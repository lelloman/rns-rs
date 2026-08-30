use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rns_tun::policy::canonicalize_routes;
use rns_tun::reticulum::{NodeEvent, PrivateNode};
use rns_tun::{
    Cidr, ClientSession, ControlMessage, PacketDirection, PacketTransport, SocketProtectorGuard,
    RNTUN_CHANNEL_MSGTYPE, RNTUN_LINK_CONTEXT,
};
use serde::{Deserialize, Serialize};

const SETUP_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Deserialize)]
pub struct AndroidConfig {
    #[serde(default = "default_schema_version")]
    pub schema_version: u8,
    #[serde(default = "default_role")]
    pub role: String,
    pub node_config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub identity_file: Option<PathBuf>,
    pub destination_hash: String,
    #[serde(default)]
    pub requested_routes: Vec<String>,
    #[serde(default)]
    pub allowed_routes: Vec<String>,
    #[serde(default)]
    pub allowed_dns: Vec<Ipv4Addr>,
    #[serde(default)]
    pub allow_default_route: bool,
    pub mtu: Option<u16>,
}

fn default_schema_version() -> u8 {
    1
}

fn default_role() -> String {
    "client".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppliedTunConfig {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub routes: Vec<String>,
    #[serde(default)]
    pub dns_servers: Vec<Ipv4Addr>,
    pub mtu: u16,
}

pub struct TunAttachment {
    pub fd: OwnedFd,
    pub applied: Option<AppliedTunConfig>,
}

#[derive(Serialize)]
struct HostEvent<'a, T: Serialize> {
    schema_version: u8,
    sequence: u64,
    event: &'a str,
    data: T,
}

#[derive(Serialize)]
pub struct AcceptedEvent {
    address: Ipv4Addr,
    prefix_len: u8,
    gateway: Ipv4Addr,
    routes: Vec<String>,
    dns_servers: Vec<Ipv4Addr>,
    mtu: u16,
    full_tunnel: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AndroidStatus {
    pub schema_version: u8,
    pub lifecycle: String,
    pub reconnecting: bool,
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub malformed: u64,
    pub queue_drops: u64,
    pub reconnect_attempts: u64,
    pub dropped_callbacks: u64,
}

pub struct AndroidRuntime {
    pub stop: Arc<AtomicBool>,
    pub tun_tx: SyncSender<TunAttachment>,
    pub events: Receiver<String>,
    pub status: Arc<Mutex<AndroidStatus>>,
    worker: Option<JoinHandle<()>>,
}

impl AndroidRuntime {
    pub fn start(config: AndroidConfig, protector: SocketProtectorGuard) -> io::Result<Self> {
        validate_config(&config)?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let (tun_tx, tun_rx) = mpsc::sync_channel(1);
        let (event_tx, events) = mpsc::sync_channel(32);
        let status = Arc::new(Mutex::new(AndroidStatus {
            schema_version: 1,
            lifecycle: "starting".into(),
            ..Default::default()
        }));
        let worker_status = Arc::clone(&status);
        let worker = std::thread::Builder::new()
            .name("rntun-android".into())
            .spawn(move || {
                let _protector = protector;
                let run_stop = Arc::clone(&worker_stop);
                if let Err(error) = run(config, run_stop, tun_rx, &event_tx, &worker_status) {
                    emit(&event_tx, "error", error.to_string());
                }
                worker_stop.store(true, Ordering::Relaxed);
                update_status(&worker_status, |value| value.lifecycle = "stopped".into());
            })?;
        Ok(Self {
            stop,
            tun_tx,
            events,
            status,
            worker: Some(worker),
        })
    }

    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        drop(self.tun_tx);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run(
    config: AndroidConfig,
    stop: Arc<AtomicBool>,
    tun_rx: Receiver<TunAttachment>,
    event_tx: &SyncSender<String>,
    status: &Arc<Mutex<AndroidStatus>>,
) -> io::Result<()> {
    update_status(status, |value| value.lifecycle = "connecting".into());
    emit(event_tx, "connecting", true);
    let destination = parse_hash(&config.destination_hash)?;
    let identity_file = config
        .identity_file
        .clone()
        .unwrap_or_else(|| config.state_dir.join("client_identity"));
    let private = PrivateNode::start(
        &config.node_config_dir,
        &config.state_dir,
        &identity_file,
        None,
    )?;
    let requested = parse_routes(&config.requested_routes)?;
    let allowed = parse_routes(&config.allowed_routes)?;
    let (mut link_id, mut session, mut accepted) =
        negotiate(&private, destination, &config, &requested, &stop)?;
    validate_accept(&config, &allowed, &requested, &accepted)?;
    emit(
        event_tx,
        "accepted",
        AcceptedEvent {
            address: accepted.address,
            prefix_len: accepted.prefix_len,
            gateway: accepted.gateway,
            routes: accepted.routes.iter().map(ToString::to_string).collect(),
            dns_servers: accepted.dns_servers.clone(),
            mtu: accepted.mtu,
            full_tunnel: accepted.routes.iter().any(|route| route.prefix_len() == 0),
        },
    );
    let fd = loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        match tun_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(attachment) => break attachment,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
    };
    validate_applied(&accepted, fd.applied.as_ref())?;
    let mut device = File::from(fd.fd);
    let mut reader = device.try_clone()?;
    set_nonblocking(reader.as_raw_fd())?;
    let reader_stop = Arc::clone(&stop);
    let ready = session
        .device_ready(accepted.dns_servers.clone())
        .map_err(io::Error::other)?;
    send_control(&private, link_id, ready)?;
    wait_ready(&private, &mut session, link_id, &stop)?;
    emit(event_tx, "ready", true);
    update_status(status, |value| {
        value.lifecycle = "ready".into();
        value.reconnecting = false;
    });

    let mut link_mdu = private
        .node
        .links()
        .map_err(node_error)?
        .into_iter()
        .find(|link| link.link_id == link_id)
        .map(|link| link.mdu)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Link disappeared"))?;
    let mut transport = PacketTransport::new(
        accepted.epoch,
        accepted.address,
        accepted.gateway,
        accepted.routes.clone(),
        accepted.mtu,
        0,
    )
    .map_err(io::Error::other)?;
    let (packet_tx, packet_rx) = mpsc::sync_channel::<io::Result<Vec<u8>>>(64);
    std::thread::spawn(move || {
        let mut buffer = vec![0; 1500];
        while !reader_stop.load(Ordering::Relaxed) {
            match reader.read(&mut buffer) {
                Ok(size) => {
                    if packet_tx.send(Ok(buffer[..size].to_vec())).is_err() {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => {
                    let _ = packet_tx.send(Err(error));
                    break;
                }
            }
        }
    });
    let started = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        while let Ok(packet) = packet_rx.try_recv() {
            let packet = packet?;
            let Ok(frames) =
                transport.packetize(&packet, PacketDirection::ClientToGateway, link_mdu)
            else {
                continue;
            };
            let mut admitted = true;
            for frame in frames {
                if private
                    .node
                    .try_send_link_datagram(
                        link_id,
                        frame,
                        RNTUN_LINK_CONTEXT,
                        Duration::from_secs(2),
                    )
                    .is_err()
                {
                    admitted = false;
                    update_status(status, |value| value.queue_drops += 1);
                    break;
                }
            }
            if admitted {
                update_status(status, |value| {
                    value.packets_out += 1;
                    value.bytes_out += packet.len() as u64;
                });
            }
        }
        match private.events.recv_timeout(Duration::from_millis(20)) {
            Ok(NodeEvent::PacketData {
                link_id: id,
                payload,
            }) if id == link_id => {
                match transport.receive(
                    &payload,
                    PacketDirection::GatewayToClient,
                    started.elapsed(),
                ) {
                    Ok(Some(packet)) => {
                        write_all_nonblocking(&mut device, &packet)?;
                        update_status(status, |value| {
                            value.packets_in += 1;
                            value.bytes_in += packet.len() as u64;
                        });
                    }
                    Ok(None) => {}
                    Err(_) => update_status(status, |value| value.malformed += 1),
                }
            }
            Ok(NodeEvent::LinkClosed { link_id: id, .. }) if id == link_id => {
                emit(event_tx, "disconnected", true);
                update_status(status, |value| {
                    value.lifecycle = "reconnecting".into();
                    value.reconnecting = true;
                });
                loop {
                    if stop.load(Ordering::Relaxed) {
                        return Ok(());
                    }
                    update_status(status, |value| value.reconnect_attempts += 1);
                    match negotiate(&private, destination, &config, &requested, &stop) {
                        Ok((new_link, mut new_session, new_accepted))
                            if same_tunnel_config(&accepted, &new_accepted)
                                && validate_accept(
                                    &config,
                                    &allowed,
                                    &requested,
                                    &new_accepted,
                                )
                                .is_ok() =>
                        {
                            let ready = new_session
                                .device_ready(new_accepted.dns_servers.clone())
                                .map_err(io::Error::other)?;
                            send_control(&private, new_link, ready)?;
                            wait_ready(&private, &mut new_session, new_link, &stop)?;
                            let new_mdu = private
                                .node
                                .links()
                                .map_err(node_error)?
                                .into_iter()
                                .find(|link| link.link_id == new_link)
                                .map(|link| link.mdu)
                                .ok_or_else(|| {
                                    io::Error::new(
                                        io::ErrorKind::NotConnected,
                                        "reconnected Link disappeared",
                                    )
                                })?;
                            transport = PacketTransport::new(
                                new_accepted.epoch,
                                new_accepted.address,
                                new_accepted.gateway,
                                new_accepted.routes.clone(),
                                new_accepted.mtu,
                                0,
                            )
                            .map_err(io::Error::other)?;
                            link_id = new_link;
                            link_mdu = new_mdu;
                            accepted = new_accepted;
                            emit(event_tx, "ready", true);
                            update_status(status, |value| {
                                value.lifecycle = "ready".into();
                                value.reconnecting = false;
                            });
                            break;
                        }
                        Ok((new_link, _, _)) => {
                            let _ = private.node.teardown_link(new_link);
                            emit(
                                event_tx,
                                "warning",
                                "gateway changed tunnel configuration during reconnect",
                            );
                        }
                        Err(error) => emit(event_tx, "warning", error.to_string()),
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
        update_status(status, |value| {
            value.dropped_callbacks = private.dropped_callbacks();
        });
    }
    emit(event_tx, "stopped", true);
    Ok(())
}

fn negotiate(
    private: &PrivateNode,
    destination: [u8; 16],
    config: &AndroidConfig,
    requested: &[Cidr],
    stop: &AtomicBool,
) -> io::Result<([u8; 16], ClientSession, rns_tun::session::AcceptedConfig)> {
    let link_id = private.connect_cancellable(destination, SETUP_TIMEOUT, stop)?;
    let mut session = ClientSession::new();
    session.link_established().map_err(io::Error::other)?;
    send_control(
        private,
        link_id,
        ControlMessage::ClientHello {
            versions: vec![1],
            capabilities: 0,
            maximum_packet_size: config.mtu.unwrap_or(1280),
            requested_routes: requested.to_vec(),
        },
    )?;
    session.hello_sent().map_err(io::Error::other)?;
    let deadline = Instant::now() + SETUP_TIMEOUT;
    loop {
        if stop.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "setup cancelled",
            ));
        }
        match private.events.recv_timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100)),
        ) {
            Ok(NodeEvent::Control {
                link_id: id,
                payload,
            }) if id == link_id => {
                let message = ControlMessage::decode(&payload).map_err(io::Error::other)?;
                match message {
                    ControlMessage::ServerAccept { .. } => {
                        session
                            .accept(&message, Duration::ZERO)
                            .map_err(io::Error::other)?;
                        let accepted = session.accepted().cloned().unwrap();
                        return Ok((link_id, session, accepted));
                    }
                    ControlMessage::ServerReject { diagnostic, .. } => {
                        return Err(io::Error::new(io::ErrorKind::PermissionDenied, diagnostic));
                    }
                    _ => {}
                }
            }
            Ok(NodeEvent::LinkClosed { link_id: id, .. }) if id == link_id => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "Link closed",
                ));
            }
            Ok(_) => {}
            Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() < deadline => {}
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "setup timed out")),
        }
    }
}

fn wait_ready(
    private: &PrivateNode,
    session: &mut ClientSession,
    link_id: [u8; 16],
    stop: &AtomicBool,
) -> io::Result<()> {
    let deadline = Instant::now() + SETUP_TIMEOUT;
    loop {
        if stop.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "readiness cancelled",
            ));
        }
        match private.events.recv_timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100)),
        ) {
            Ok(NodeEvent::Control {
                link_id: id,
                payload,
            }) if id == link_id => {
                if let ControlMessage::ServerReady { session_epoch } =
                    ControlMessage::decode(&payload).map_err(io::Error::other)?
                {
                    return session
                        .server_ready(session_epoch)
                        .map_err(io::Error::other);
                }
            }
            Ok(_) => {}
            Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() < deadline => {}
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "ready timed out")),
        }
    }
}

fn validate_config(config: &AndroidConfig) -> io::Result<()> {
    if config.schema_version != 1 || config.role != "client" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported Android configuration schema or role",
        ));
    }
    let requested = parse_routes(&config.requested_routes)?;
    let allowed = parse_routes(&config.allowed_routes)?;
    let default_requested = requested.iter().any(|route| route.prefix_len() == 0);
    let default_allowed = allowed.iter().any(|route| route.prefix_len() == 0);
    if config.allow_default_route != (default_requested && default_allowed)
        || config.allow_default_route && config.allowed_dns.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid full-tunnel policy",
        ));
    }
    parse_hash(&config.destination_hash)?;
    if config.allow_default_route {
        rns_tun::config::validate_full_tunnel_node_config(&config.node_config_dir)
            .map_err(io::Error::other)?;
    }
    Ok(())
}

fn validate_applied(
    accepted: &rns_tun::session::AcceptedConfig,
    applied: Option<&AppliedTunConfig>,
) -> io::Result<()> {
    let Some(applied) = applied else {
        return Ok(()); // Legacy C ABI: attaching the descriptor was the acknowledgement.
    };
    let routes = parse_routes(&applied.routes)?;
    if applied.address != accepted.address
        || applied.prefix_len != accepted.prefix_len
        || routes != accepted.routes
        || applied.dns_servers != accepted.dns_servers
        || applied.mtu != accepted.mtu
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "host TUN configuration does not match the negotiated tunnel",
        ));
    }
    Ok(())
}

fn validate_accept(
    config: &AndroidConfig,
    allowed: &[Cidr],
    requested: &[Cidr],
    accepted: &rns_tun::session::AcceptedConfig,
) -> io::Result<()> {
    let subnet = Cidr::new(accepted.address, accepted.prefix_len).map_err(io::Error::other)?;
    if accepted.prefix_len == 0
        || accepted.prefix_len > 30
        || !subnet.contains(accepted.gateway)
        || accepted.address == accepted.gateway
        || accepted.address == subnet.network()
        || accepted.address == subnet.broadcast()
        || accepted.gateway == subnet.network()
        || accepted.gateway == subnet.broadcast()
        || rns_tun::policy::is_forbidden_special(accepted.address)
        || rns_tun::policy::is_forbidden_special(accepted.gateway)
        || accepted.routes != canonicalize_routes(accepted.routes.clone())
        || accepted.routes.iter().any(|route| {
            !allowed.iter().any(|allowed| allowed.contains_cidr(*route))
                || !requested
                    .iter()
                    .any(|requested| requested.contains_cidr(*route))
        })
        || accepted
            .dns_servers
            .iter()
            .any(|dns| !config.allowed_dns.contains(dns))
        || accepted.routes.iter().any(|route| route.prefix_len() == 0)
            && accepted.dns_servers.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "gateway configuration exceeds Android host policy",
        ));
    }
    Ok(())
}

fn same_tunnel_config(
    left: &rns_tun::session::AcceptedConfig,
    right: &rns_tun::session::AcceptedConfig,
) -> bool {
    left.address == right.address
        && left.prefix_len == right.prefix_len
        && left.gateway == right.gateway
        && left.routes == right.routes
        && left.dns_servers == right.dns_servers
        && left.mtu == right.mtu
}

fn send_control(
    private: &PrivateNode,
    link_id: [u8; 16],
    message: ControlMessage,
) -> io::Result<()> {
    private
        .node
        .send_channel_message(
            link_id,
            RNTUN_CHANNEL_MSGTYPE,
            message.encode().map_err(io::Error::other)?,
        )
        .map_err(node_error)
}
fn emit<T: Serialize>(tx: &SyncSender<String>, event: &str, data: T) {
    use std::sync::atomic::AtomicU64;
    static SEQUENCE: AtomicU64 = AtomicU64::new(1);
    if let Ok(encoded) = serde_json::to_string(&HostEvent {
        schema_version: 1,
        sequence: SEQUENCE.fetch_add(1, Ordering::Relaxed),
        event,
        data,
    }) {
        let _ = tx.try_send(encoded);
    }
}

fn update_status(status: &Arc<Mutex<AndroidStatus>>, update: impl FnOnce(&mut AndroidStatus)) {
    let mut value = status
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    update(&mut value);
}
fn parse_routes(routes: &[String]) -> io::Result<Vec<Cidr>> {
    routes
        .iter()
        .map(|route| route.parse().map_err(io::Error::other))
        .collect()
}
fn parse_hash(value: &str) -> io::Result<[u8; 16]> {
    if value.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid destination hash",
        ));
    }
    let mut result = [0; 16];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid destination hash"))?;
    }
    Ok(result)
}
fn node_error(error: rns_tun::RnsSendError) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, error)
}

fn set_nonblocking(fd: libc::c_int) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn write_all_nonblocking(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        match file.write(&bytes[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TUN write returned zero",
                ))
            }
            Ok(written) => offset += written,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted() -> rns_tun::session::AcceptedConfig {
        rns_tun::session::AcceptedConfig {
            epoch: 7,
            address: "10.77.0.2".parse().unwrap(),
            prefix_len: 24,
            gateway: "10.77.0.1".parse().unwrap(),
            routes: vec!["10.20.0.0/16".parse().unwrap()],
            dns_servers: Vec::new(),
            mtu: 1280,
            setup_timeout: Duration::from_secs(30),
        }
    }

    #[test]
    fn exact_host_acknowledgement_is_required() {
        let applied = AppliedTunConfig {
            address: "10.77.0.2".parse().unwrap(),
            prefix_len: 24,
            routes: vec!["10.20.0.0/16".into()],
            dns_servers: Vec::new(),
            mtu: 1280,
        };
        assert!(validate_applied(&accepted(), Some(&applied)).is_ok());
        assert!(validate_applied(
            &accepted(),
            Some(&AppliedTunConfig {
                mtu: 1400,
                ..applied
            })
        )
        .is_err());
    }

    #[test]
    fn version_one_rejects_gateway_role() {
        let config = AndroidConfig {
            schema_version: 1,
            role: "gateway".into(),
            node_config_dir: "node".into(),
            state_dir: "state".into(),
            identity_file: None,
            destination_hash: "00112233445566778899aabbccddeeff".into(),
            requested_routes: Vec::new(),
            allowed_routes: Vec::new(),
            allowed_dns: Vec::new(),
            allow_default_route: false,
            mtu: Some(1280),
        };
        assert!(validate_config(&config).is_err());
    }
}
