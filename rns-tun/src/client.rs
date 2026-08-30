use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rns_crypto::{OsRng, Rng};

use crate::config::{ClientConfig, Config};
use crate::linux::LinuxConfigurator;
use crate::platform::{PacketDevice, TunnelConfig, TunnelConfigurator};
use crate::policy::{canonicalize_routes, is_forbidden_special, Cidr};
use crate::protocol::{ControlMessage, VERSION};
use crate::reticulum::{NodeEvent, PrivateNode};
use crate::runtime::SharedStatus;
use crate::session::ClientSession;
use crate::transport::{PacketDirection, PacketTransport};
use crate::{RNTUN_CHANNEL_MSGTYPE, RNTUN_LINK_CONTEXT};

const SETUP_TIMEOUT: Duration = Duration::from_secs(60);
const SEND_ADMISSION_TIMEOUT: Duration = Duration::from_secs(2);

pub fn run_linux_client(
    config: &Config,
    destination: [u8; 16],
    stop: &Arc<AtomicBool>,
    status: SharedStatus,
) -> io::Result<()> {
    status.update(|value| value.lifecycle = "starting".into());
    let client = config
        .client
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "client section is required"))?;
    if client.allow_default_route {
        crate::config::validate_full_tunnel_node_config(&config.node_config_dir)
            .map_err(io::Error::other)?;
    }
    let identity_path = client
        .identity_file
        .clone()
        .unwrap_or_else(|| config.state_dir.join("client_identity"));
    let private = PrivateNode::start(
        &config.node_config_dir,
        &config.state_dir,
        &identity_path,
        Some(config.underlay_mark),
    )?;
    status.update(|value| value.lifecycle = "negotiating".into());
    let mut link_id = private.connect(destination, SETUP_TIMEOUT)?;
    let mut session = ClientSession::new();
    session.link_established().map_err(session_error)?;
    let requested = requested_routes(client)?;
    let hello = ControlMessage::ClientHello {
        versions: vec![VERSION],
        capabilities: 0,
        maximum_packet_size: client.tun_mtu.unwrap_or(1280),
        requested_routes: requested.clone(),
    };
    send_control(&private, link_id, hello)?;
    session.hello_sent().map_err(session_error)?;

    let accept = wait_for_accept(&private, link_id, SETUP_TIMEOUT)?;
    validate_accept(client, &requested, &accept)?;
    session
        .accept(&accept, Duration::ZERO)
        .map_err(session_error)?;
    let mut accepted = session.accepted().cloned().unwrap();
    let full_tunnel = accepted.routes.iter().any(|route| route.prefix_len() == 0);
    let tunnel_config = TunnelConfig {
        interface_name: client.tun_name.clone(),
        address: accepted.address,
        prefix_len: accepted.prefix_len,
        gateway: accepted.gateway,
        mtu: accepted.mtu,
        routes: accepted.routes.clone(),
        dns_servers: accepted.dns_servers.clone(),
        full_tunnel,
    };
    let mut configurator = LinuxConfigurator::new(
        config.underlay_mark,
        client.routing_table,
        client.physical_table,
        client.underlay_rule_priority,
        client.tunnel_rule_priority,
        config.state_dir.join("linux-ownership.json"),
    )?;
    configurator.cleanup_stale()?;
    let (mut device, applied) = configurator.apply(&tunnel_config)?;
    let result = (|| {
        let ready = session
            .device_ready(applied.dns_servers.clone())
            .map_err(session_error)?;
        send_control(&private, link_id, ready)?;
        wait_for_server_ready(&private, &mut session, link_id, SETUP_TIMEOUT)?;
        status.update(|value| {
            value.lifecycle = "active".into();
            value.reconnecting = false;
            value.full_tunnel_verified = applied.full_tunnel_verified;
            value.destination_hash = Some(hex(&destination));
            value.sessions = vec![crate::status::SessionStatus {
                identity: hex(&destination),
                state: "active".into(),
                address: accepted.address,
                routes: accepted.routes.iter().map(ToString::to_string).collect(),
                dns_servers: accepted.dns_servers.clone(),
                counters: Default::default(),
            }];
        });

        let mut link_mdu = private
            .node
            .links()
            .map_err(node_error)?
            .into_iter()
            .find(|link| link.link_id == link_id)
            .map(|link| link.mdu)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "active Link disappeared")
            })?;
        let mut random_id = [0u8; 8];
        OsRng.fill_bytes(&mut random_id);
        let mut transport = PacketTransport::new(
            accepted.epoch,
            accepted.address,
            accepted.gateway,
            accepted.routes.clone(),
            accepted.mtu,
            u64::from_be_bytes(random_id) & (u64::MAX - 1),
        )
        .map_err(other)?;
        let mut reader = device.try_clone()?;
        reader.set_nonblocking(true)?;
        let reader_stop = Arc::clone(stop);
        let (packet_tx, packet_rx) = mpsc::sync_channel::<io::Result<Vec<u8>>>(64);
        std::thread::spawn(move || {
            let mut buffer = vec![0; 1500];
            while !reader_stop.load(Ordering::Relaxed) {
                match reader.read_packet(&mut buffer) {
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
            status.update(|value| {
                value.queue_depths.insert(
                    "dropped_node_callbacks".into(),
                    private.dropped_callbacks() as usize,
                );
            });
            while let Ok(packet) = packet_rx.try_recv() {
                let packet = packet?;
                let frames = match transport.packetize(
                    &packet,
                    PacketDirection::ClientToGateway,
                    link_mdu,
                ) {
                    Ok(frames) => frames,
                    Err(error) => {
                        record_transport_error(&status, &error);
                        continue;
                    }
                };
                let mut admitted = true;
                for frame in frames {
                    if private
                        .node
                        .try_send_link_datagram(
                            link_id,
                            frame,
                            RNTUN_LINK_CONTEXT,
                            SEND_ADMISSION_TIMEOUT,
                        )
                        .is_err()
                    {
                        admitted = false;
                        status.update(|value| value.counters.queue_drops += 1);
                        break;
                    }
                }
                if admitted {
                    status.update(|value| {
                        value.counters.packets_out += 1;
                        value.counters.bytes_out += packet.len() as u64;
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
                            device.write_packet(&packet)?;
                            status.update(|value| {
                                value.counters.packets_in += 1;
                                value.counters.bytes_in += packet.len() as u64;
                            });
                        }
                        Ok(None) => {}
                        Err(error) => record_transport_error(&status, &error),
                    }
                }
                Ok(NodeEvent::LinkClosed {
                    link_id: id,
                    reason,
                }) if id == link_id => loop {
                    log::warn!("rntun Link closed while active: reason={reason:?}");
                    status.update(|value| {
                        value.lifecycle = "reconnecting".into();
                        value.reconnecting = true;
                        if let Some(session) = value.sessions.first_mut() {
                            session.state = "reconnecting".into();
                        }
                    });
                    if stop.load(Ordering::Relaxed) {
                        return Ok(());
                    }
                    match reconnect(
                        &private,
                        client,
                        destination,
                        &requested,
                        &accepted,
                        &applied.dns_servers,
                    ) {
                        Ok((new_link, new_accepted, new_mdu, new_transport)) => {
                            link_id = new_link;
                            accepted = new_accepted;
                            link_mdu = new_mdu;
                            transport = new_transport;
                            status.update(|value| {
                                value.lifecycle = "active".into();
                                value.reconnecting = false;
                                if let Some(session) = value.sessions.first_mut() {
                                    session.state = "active".into();
                                }
                            });
                            break;
                        }
                        Err(error) => {
                            log::warn!("rntun reconnect failed: {error}");
                            std::thread::sleep(Duration::from_secs(1));
                        }
                    }
                },
                Ok(_) => {}
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "node callback queue closed",
                    ));
                }
            }
        }
        Ok(())
    })();
    stop.store(true, Ordering::Relaxed);
    let _ = device.close();
    let teardown = configurator.teardown(&applied);
    status.update(|value| {
        value.lifecycle = "stopped".into();
        value.full_tunnel_verified = false;
    });
    result.and(teardown)
}

fn reconnect(
    private: &PrivateNode,
    client: &ClientConfig,
    destination: [u8; 16],
    requested: &[Cidr],
    previous: &crate::session::AcceptedConfig,
    applied_dns: &[std::net::Ipv4Addr],
) -> io::Result<(
    [u8; 16],
    crate::session::AcceptedConfig,
    usize,
    PacketTransport,
)> {
    let link_id = private.connect(destination, SETUP_TIMEOUT)?;
    let mut session = ClientSession::new();
    session.link_established().map_err(session_error)?;
    send_control(
        private,
        link_id,
        ControlMessage::ClientHello {
            versions: vec![VERSION],
            capabilities: 0,
            maximum_packet_size: client.tun_mtu.unwrap_or(1280),
            requested_routes: requested.to_vec(),
        },
    )?;
    session.hello_sent().map_err(session_error)?;
    let accept = wait_for_accept(private, link_id, SETUP_TIMEOUT)?;
    validate_accept(client, requested, &accept)?;
    session
        .accept(&accept, Duration::ZERO)
        .map_err(session_error)?;
    let accepted = session.accepted().cloned().unwrap();
    if accepted.address != previous.address
        || accepted.prefix_len != previous.prefix_len
        || accepted.gateway != previous.gateway
        || accepted.routes != previous.routes
        || accepted.dns_servers != previous.dns_servers
        || accepted.mtu != previous.mtu
    {
        let _ = private.node.teardown_link(link_id);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "gateway changed active tunnel configuration during reconnect",
        ));
    }
    let ready = session
        .device_ready(applied_dns.to_vec())
        .map_err(session_error)?;
    send_control(private, link_id, ready)?;
    wait_for_server_ready(private, &mut session, link_id, SETUP_TIMEOUT)?;
    let link_mdu = private
        .node
        .links()
        .map_err(node_error)?
        .into_iter()
        .find(|link| link.link_id == link_id)
        .map(|link| link.mdu)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "reconnected Link disappeared")
        })?;
    let transport = PacketTransport::new(
        accepted.epoch,
        accepted.address,
        accepted.gateway,
        accepted.routes.clone(),
        accepted.mtu,
        random_packet_id(),
    )
    .map_err(other)?;
    Ok((link_id, accepted, link_mdu, transport))
}

fn random_packet_id() -> u64 {
    loop {
        let mut bytes = [0; 8];
        OsRng.fill_bytes(&mut bytes);
        let value = u64::from_be_bytes(bytes);
        if value != u64::MAX {
            return value;
        }
    }
}

pub fn cleanup_linux(config: &Config) -> io::Result<()> {
    let client = config
        .client
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "client section is required"))?;
    LinuxConfigurator::new(
        config.underlay_mark,
        client.routing_table,
        client.physical_table,
        client.underlay_rule_priority,
        client.tunnel_rule_priority,
        config.state_dir.join("linux-ownership.json"),
    )?
    .cleanup_stale()
}

fn wait_for_accept(
    private: &PrivateNode,
    link_id: [u8; 16],
    timeout: Duration,
) -> io::Result<ControlMessage> {
    let deadline = Instant::now() + timeout;
    loop {
        match private
            .events
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            Ok(NodeEvent::Control {
                link_id: id,
                payload,
            }) if id == link_id => {
                let message = ControlMessage::decode(&payload).map_err(other)?;
                match message {
                    ControlMessage::ServerAccept { .. } => return Ok(message),
                    ControlMessage::ServerReject { diagnostic, .. } => {
                        return Err(io::Error::new(io::ErrorKind::PermissionDenied, diagnostic));
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unexpected control message",
                        ))
                    }
                }
            }
            Ok(NodeEvent::LinkClosed { link_id: id, .. }) if id == link_id => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "Link closed",
                ));
            }
            Ok(_) => {}
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "negotiation timed out",
                ))
            }
        }
    }
}

fn wait_for_server_ready(
    private: &PrivateNode,
    session: &mut ClientSession,
    link_id: [u8; 16],
    timeout: Duration,
) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        match private
            .events
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            Ok(NodeEvent::Control {
                link_id: id,
                payload,
            }) if id == link_id => {
                let message = ControlMessage::decode(&payload).map_err(other)?;
                if let ControlMessage::ServerReady { session_epoch } = message {
                    return session.server_ready(session_epoch).map_err(session_error);
                }
            }
            Ok(NodeEvent::LinkClosed { link_id: id, .. }) if id == link_id => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "Link closed",
                ));
            }
            Ok(_) => {}
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ready acknowledgement timed out",
                ))
            }
        }
    }
}

fn requested_routes(client: &ClientConfig) -> io::Result<Vec<Cidr>> {
    client
        .requested_routes
        .iter()
        .map(|route| route.parse().map_err(other))
        .collect()
}

fn validate_accept(
    client: &ClientConfig,
    requested: &[Cidr],
    message: &ControlMessage,
) -> io::Result<()> {
    let ControlMessage::ServerAccept {
        assigned_address,
        prefix_len,
        gateway_address,
        accepted_routes,
        dns_servers,
        packet_mtu,
        ..
    } = message
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected ServerAccept",
        ));
    };
    if *prefix_len == 0 || *prefix_len > 30 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid assigned prefix",
        ));
    }
    let subnet = Cidr::new(*assigned_address, *prefix_len).map_err(other)?;
    if !subnet.contains(*gateway_address)
        || assigned_address == gateway_address
        || *assigned_address == subnet.network()
        || *assigned_address == subnet.broadcast()
        || *gateway_address == subnet.network()
        || *gateway_address == subnet.broadcast()
        || is_forbidden_special(*assigned_address)
        || is_forbidden_special(*gateway_address)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid assigned address or gateway",
        ));
    }
    let allowed: Vec<Cidr> = client
        .allowed_routes
        .iter()
        .map(|route| route.parse().map_err(other))
        .collect::<io::Result<_>>()?;
    for accepted in accepted_routes {
        if !requested.iter().any(|route| route.contains_cidr(*accepted))
            || !allowed.iter().any(|route| route.contains_cidr(*accepted))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "server accepted an unauthorized route",
            ));
        }
        if accepted.prefix_len() == 0 && !client.allow_default_route {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "default route was not authorized locally",
            ));
        }
    }
    if dns_servers
        .iter()
        .any(|dns| !client.allowed_dns.contains(dns))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "server advertised an unauthorized DNS resolver",
        ));
    }
    if accepted_routes.iter().any(|route| route.prefix_len() == 0) && dns_servers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "full tunnel requires DNS",
        ));
    }
    if !(576..=1500).contains(packet_mtu) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid negotiated MTU",
        ));
    }
    let canonical = canonicalize_routes(accepted_routes.clone());
    if canonical != *accepted_routes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "accepted routes are not canonical",
        ));
    }
    Ok(())
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
            message.encode().map_err(other)?,
        )
        .map_err(node_error)
}
fn node_error(error: rns_net::node::SendError) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, error)
}
fn session_error(error: crate::SessionError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
fn other(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(error)
}

fn record_transport_error(status: &SharedStatus, error: &crate::TransportError) {
    status.update(|value| match error {
        crate::TransportError::UnauthorizedSource(_)
        | crate::TransportError::UnauthorizedDestination(_)
        | crate::TransportError::Replay
        | crate::TransportError::WrongEpoch => value.counters.unauthorized += 1,
        _ => value.counters.malformed += 1,
    });
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
