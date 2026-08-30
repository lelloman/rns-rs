use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
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

#[derive(Serialize)]
struct HostEvent<'a, T: Serialize> {
    event: &'a str,
    data: T,
}

#[derive(Serialize)]
struct AcceptedEvent {
    address: Ipv4Addr,
    prefix_len: u8,
    gateway: Ipv4Addr,
    routes: Vec<String>,
    dns_servers: Vec<Ipv4Addr>,
    mtu: u16,
    full_tunnel: bool,
}

pub struct AndroidRuntime {
    pub stop: Arc<AtomicBool>,
    pub tun_tx: SyncSender<OwnedFd>,
    pub events: Receiver<String>,
}

impl AndroidRuntime {
    pub fn start(config: AndroidConfig, protector: SocketProtectorGuard) -> io::Result<Self> {
        validate_config(&config)?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let (tun_tx, tun_rx) = mpsc::sync_channel(1);
        let (event_tx, events) = mpsc::sync_channel(32);
        std::thread::Builder::new()
            .name("rntun-android".into())
            .spawn(move || {
                let _protector = protector;
                let run_stop = Arc::clone(&worker_stop);
                if let Err(error) = run(config, run_stop, tun_rx, &event_tx) {
                    emit(&event_tx, "error", error.to_string());
                }
                worker_stop.store(true, Ordering::Relaxed);
            })?;
        Ok(Self {
            stop,
            tun_tx,
            events,
        })
    }
}

fn run(
    config: AndroidConfig,
    stop: Arc<AtomicBool>,
    tun_rx: Receiver<OwnedFd>,
    event_tx: &SyncSender<String>,
) -> io::Result<()> {
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
        negotiate(&private, destination, &config, &requested)?;
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
            Ok(fd) => break fd,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
    };
    let mut device = File::from(fd);
    let mut reader = device.try_clone()?;
    set_nonblocking(reader.as_raw_fd())?;
    let reader_stop = Arc::clone(&stop);
    let ready = session
        .device_ready(accepted.dns_servers.clone())
        .map_err(io::Error::other)?;
    send_control(&private, link_id, ready)?;
    wait_ready(&private, &mut session, link_id)?;
    emit(event_tx, "ready", true);

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
                    break;
                }
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
                    Ok(Some(packet)) => write_all_nonblocking(&mut device, &packet)?,
                    Ok(None) | Err(_) => {}
                }
            }
            Ok(NodeEvent::LinkClosed(id)) if id == link_id => {
                emit(event_tx, "disconnected", true);
                loop {
                    if stop.load(Ordering::Relaxed) {
                        return Ok(());
                    }
                    match negotiate(&private, destination, &config, &requested) {
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
                            wait_ready(&private, &mut new_session, new_link)?;
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
    }
    emit(event_tx, "stopped", true);
    Ok(())
}

fn negotiate(
    private: &PrivateNode,
    destination: [u8; 16],
    config: &AndroidConfig,
    requested: &[Cidr],
) -> io::Result<([u8; 16], ClientSession, rns_tun::session::AcceptedConfig)> {
    let link_id = private.connect(destination, SETUP_TIMEOUT)?;
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
        match private
            .events
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
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
            Ok(NodeEvent::LinkClosed(id)) if id == link_id => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "Link closed",
                ));
            }
            Ok(_) => {}
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "setup timed out")),
        }
    }
}

fn wait_ready(
    private: &PrivateNode,
    session: &mut ClientSession,
    link_id: [u8; 16],
) -> io::Result<()> {
    let deadline = Instant::now() + SETUP_TIMEOUT;
    loop {
        match private
            .events
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
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
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "ready timed out")),
        }
    }
}

fn validate_config(config: &AndroidConfig) -> io::Result<()> {
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
    if let Ok(encoded) = serde_json::to_string(&HostEvent { event, data }) {
        let _ = tx.try_send(encoded);
    }
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
