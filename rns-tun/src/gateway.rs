use std::collections::HashMap;
use std::fs;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rns_crypto::{OsRng, Rng};

use crate::config::Config;
use crate::linux::LinuxConfigurator;
use crate::packet::validate_ipv4;
use crate::platform::{PacketDevice, TunnelConfig, TunnelConfigurator};
use crate::policy::{ClientGrant, GatewayPolicy};
use crate::protocol::{ControlMessage, VERSION};
use crate::reticulum::{NodeEvent, PrivateNode};
use crate::runtime::SharedStatus;
use crate::session::{GatewaySession, GatewayState};
use crate::transport::{PacketDirection, PacketTransport};
use crate::{RNTUN_CHANNEL_MSGTYPE, RNTUN_LINK_CONTEXT};

const IDENTIFY_TIMEOUT: Duration = Duration::from_secs(30);
const SETUP_TIMEOUT: Duration = Duration::from_secs(60);
const SEND_TIMEOUT: Duration = Duration::from_secs(2);

struct SessionEntry {
    machine: GatewaySession,
    identity: Option<[u8; 16]>,
    grant: Option<ClientGrant>,
    accepted_routes: Vec<crate::Cidr>,
    advertised_dns: Vec<std::net::Ipv4Addr>,
    transport: Option<PacketTransport>,
    link_mdu: usize,
    mtu: u16,
    last_activity: Duration,
}

pub fn run_linux_gateway(
    config: &Config,
    stop: &Arc<AtomicBool>,
    status: SharedStatus,
) -> io::Result<()> {
    status.update(|value| value.lifecycle = "starting".into());
    let gateway = config.gateway.as_ref().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "gateway section is required")
    })?;
    let mut policy = GatewayPolicy::parse_toml(&fs::read_to_string(&gateway.policy_file)?)
        .map_err(io::Error::other)?;
    let mut policy_modified = fs::metadata(&gateway.policy_file)?.modified().ok();
    let identity_path = gateway
        .identity_file
        .clone()
        .unwrap_or_else(|| config.state_dir.join("gateway_identity"));
    let private = PrivateNode::start(
        &config.node_config_dir,
        &config.state_dir,
        &identity_path,
        Some(config.underlay_mark),
    )?;
    let destination = private.register_gateway()?;
    private.announce_gateway(&destination)?;
    status.update(|value| {
        value.destination_hash = Some(hex(&destination.hash.0));
        value.lifecycle = "configuring".into();
    });

    let mut configurator = LinuxConfigurator::new(
        config.underlay_mark,
        0x5254,
        254,
        100,
        110,
        config.state_dir.join("gateway-linux-ownership.json"),
    )?;
    let tunnel = TunnelConfig {
        interface_name: gateway.tun_name.clone(),
        address: policy.gateway_address,
        prefix_len: policy.gateway.prefix_len(),
        gateway: policy.gateway_address,
        mtu: 1280,
        routes: Vec::new(),
        dns_servers: Vec::new(),
        full_tunnel: false,
    };
    let (mut device, applied) = configurator.apply(&tunnel)?;
    let result = (|| {
        status.update(|value| value.lifecycle = "active".into());
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
        let mut sessions: HashMap<[u8; 16], SessionEntry> = HashMap::new();
        let mut next_announce =
            Instant::now() + Duration::from_secs(gateway.announce_interval_seconds);
        let mut next_policy_check = Instant::now() + Duration::from_secs(2);

        while !stop.load(Ordering::Relaxed) {
            if Instant::now() >= next_announce {
                private.announce_gateway(&destination)?;
                next_announce =
                    Instant::now() + Duration::from_secs(gateway.announce_interval_seconds);
            }
            if Instant::now() >= next_policy_check {
                next_policy_check = Instant::now() + Duration::from_secs(2);
                let modified = fs::metadata(&gateway.policy_file)
                    .and_then(|metadata| metadata.modified())
                    .ok();
                if modified.is_some() && modified != policy_modified {
                    match fs::read_to_string(&gateway.policy_file)
                        .map_err(io::Error::other)
                        .and_then(|text| GatewayPolicy::parse_toml(&text).map_err(io::Error::other))
                    {
                        Ok(replacement)
                            if replacement.gateway == policy.gateway
                                && replacement.gateway_address == policy.gateway_address =>
                        {
                            sessions.retain(|link_id, entry| {
                                let unchanged = entry.identity.is_some_and(|identity| {
                                    replacement.grant(&identity) == entry.grant.as_ref()
                                });
                                if !unchanged {
                                    let _ = private.node.teardown_link(*link_id);
                                }
                                unchanged
                            });
                            policy = replacement;
                            policy_modified = modified;
                        }
                        Ok(_) => log::warn!("ignoring policy reload that changes gateway address"),
                        Err(error) => {
                            log::warn!("keeping current policy after reload failure: {error}")
                        }
                    }
                }
            }
            while let Ok(packet) = packet_rx.try_recv() {
                let packet = packet?;
                let parsed = match validate_ipv4(&packet, 1280) {
                    Ok(parsed) => parsed,
                    Err(_) => continue,
                };
                let target = sessions.iter_mut().find(|(_, entry)| {
                    entry.machine.state() == GatewayState::Active
                        && entry
                            .grant
                            .as_ref()
                            .is_some_and(|grant| grant.address == parsed.destination)
                });
                let Some((link_id, entry)) = target else {
                    continue;
                };
                entry.last_activity = started.elapsed();
                let Some(transport) = &mut entry.transport else {
                    continue;
                };
                let frames = match transport.packetize(
                    &packet,
                    PacketDirection::GatewayToClient,
                    entry.link_mdu,
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
                        .try_send_link_datagram(*link_id, frame, RNTUN_LINK_CONTEXT, SEND_TIMEOUT)
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
                Ok(NodeEvent::LinkEstablished {
                    link_id,
                    initiator: false,
                }) => {
                    if sessions.len() >= gateway.max_pending_links + gateway.max_active_sessions {
                        let _ = private.node.teardown_link(link_id);
                        continue;
                    }
                    let link_mdu = private
                        .node
                        .links()
                        .map_err(node_error)?
                        .into_iter()
                        .find(|link| link.link_id == link_id)
                        .map(|link| link.mdu)
                        .unwrap_or(384);
                    sessions.insert(
                        link_id,
                        SessionEntry {
                            machine: GatewaySession::new(started.elapsed(), IDENTIFY_TIMEOUT),
                            identity: None,
                            grant: None,
                            accepted_routes: Vec::new(),
                            advertised_dns: Vec::new(),
                            transport: None,
                            link_mdu,
                            mtu: 1280,
                            last_activity: started.elapsed(),
                        },
                    );
                }
                Ok(NodeEvent::RemoteIdentified { link_id, identity }) => {
                    let Some(entry) = sessions.get_mut(&link_id) else {
                        continue;
                    };
                    let Some(grant) = policy.grant(&identity).cloned() else {
                        reject(&private, link_id, 1, "identity is not authorized");
                        sessions.remove(&link_id);
                        continue;
                    };
                    entry.identity = Some(identity);
                    entry.grant = Some(grant);
                    if let Some(buffered) =
                        entry.machine.identified(identity).map_err(session_error)?
                    {
                        process_hello(
                            &private,
                            &policy,
                            gateway,
                            link_id,
                            entry,
                            &buffered,
                            started.elapsed(),
                        )?;
                    }
                }
                Ok(NodeEvent::Control { link_id, payload }) => {
                    let active_count = sessions
                        .values()
                        .filter(|candidate| candidate.machine.state() == GatewayState::Active)
                        .count();
                    let Some(entry) = sessions.get_mut(&link_id) else {
                        continue;
                    };
                    let message = match ControlMessage::decode(&payload) {
                        Ok(message) => message,
                        Err(_) => {
                            reject(&private, link_id, 2, "malformed control message");
                            sessions.remove(&link_id);
                            continue;
                        }
                    };
                    match message {
                        ControlMessage::ClientHello { .. } => {
                            if entry.machine.state() == GatewayState::PendingIdentity {
                                entry
                                    .machine
                                    .receive_preidentify_hello(payload)
                                    .map_err(session_error)?;
                            } else {
                                process_hello(
                                    &private,
                                    &policy,
                                    gateway,
                                    link_id,
                                    entry,
                                    &payload,
                                    started.elapsed(),
                                )?;
                            }
                        }
                        ControlMessage::ClientReady {
                            session_epoch,
                            dns_servers,
                        } => {
                            if entry.machine.state() != GatewayState::Active
                                && active_count >= gateway.max_active_sessions
                            {
                                reject(&private, link_id, 6, "gateway session capacity reached");
                                sessions.remove(&link_id);
                                continue;
                            }
                            if dns_servers != entry.advertised_dns {
                                reject(&private, link_id, 3, "DNS configuration mismatch");
                                sessions.remove(&link_id);
                                continue;
                            }
                            let ready = entry
                                .machine
                                .client_ready(session_epoch)
                                .map_err(session_error)?;
                            let grant = entry.grant.as_ref().unwrap();
                            entry.transport = Some(
                                PacketTransport::new(
                                    session_epoch,
                                    grant.address,
                                    policy.gateway_address,
                                    entry.accepted_routes.clone(),
                                    entry.mtu,
                                    random_nonzero(),
                                )
                                .map_err(io::Error::other)?,
                            );
                            send_control(&private, link_id, ready)?;
                        }
                        ControlMessage::Close { session_epoch, .. } => {
                            let _ = send_control(
                                &private,
                                link_id,
                                ControlMessage::CloseAck { session_epoch },
                            );
                            let _ = private.node.teardown_link(link_id);
                            sessions.remove(&link_id);
                        }
                        _ => {}
                    }
                }
                Ok(NodeEvent::PacketData { link_id, payload }) => {
                    let Some(entry) = sessions.get_mut(&link_id) else {
                        continue;
                    };
                    if !entry.machine.permits_packet_data() {
                        continue;
                    }
                    let Some(transport) = &mut entry.transport else {
                        continue;
                    };
                    match transport.receive(
                        &payload,
                        PacketDirection::ClientToGateway,
                        started.elapsed(),
                    ) {
                        Ok(Some(packet)) => {
                            entry.last_activity = started.elapsed();
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
                Ok(NodeEvent::LinkClosed(link_id)) => {
                    sessions.remove(&link_id);
                }
                Ok(_) => {}
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "node callback queue closed",
                    ));
                }
            }
            sessions.retain(|link_id, entry| {
                let idle_expired = entry.machine.state() == GatewayState::Active
                    && entry
                        .grant
                        .as_ref()
                        .and_then(|grant| grant.idle_timeout_secs)
                        .is_some_and(|seconds| {
                            started.elapsed().saturating_sub(entry.last_activity)
                                >= Duration::from_secs(seconds as u64)
                        });
                if idle_expired || entry.machine.check_timeout(started.elapsed()).is_err() {
                    let _ = private.node.teardown_link(*link_id);
                    false
                } else {
                    true
                }
            });
            status.update(|value| {
                value.queue_depths.insert(
                    "dropped_node_callbacks".into(),
                    private.dropped_callbacks() as usize,
                );
                value.sessions = sessions
                    .values()
                    .filter_map(|entry| {
                        Some(crate::status::SessionStatus {
                            identity: hex(&entry.identity?),
                            state: format!("{:?}", entry.machine.state()).to_lowercase(),
                            address: entry.grant.as_ref()?.address,
                            routes: entry
                                .accepted_routes
                                .iter()
                                .map(ToString::to_string)
                                .collect(),
                            dns_servers: entry.advertised_dns.clone(),
                            counters: Default::default(),
                        })
                    })
                    .collect();
            });
        }
        Ok(())
    })();
    stop.store(true, Ordering::Relaxed);
    let _ = device.close();
    let teardown = configurator.teardown(&applied);
    status.update(|value| value.lifecycle = "stopped".into());
    result.and(teardown)
}

fn process_hello(
    private: &PrivateNode,
    policy: &GatewayPolicy,
    gateway: &crate::config::GatewayConfig,
    link_id: [u8; 16],
    entry: &mut SessionEntry,
    payload: &[u8],
    now: Duration,
) -> io::Result<()> {
    if entry.machine.state() != GatewayState::Negotiating {
        return Ok(());
    }
    let ControlMessage::ClientHello {
        versions,
        maximum_packet_size,
        requested_routes,
        ..
    } = ControlMessage::decode(payload).map_err(io::Error::other)?
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected ClientHello",
        ));
    };
    if !versions.contains(&VERSION) || maximum_packet_size < 576 {
        reject(private, link_id, 4, "no compatible protocol or MTU");
        return Ok(());
    }
    let identity = entry
        .identity
        .ok_or_else(|| io::Error::other("identity missing"))?;
    let grant = entry
        .grant
        .as_ref()
        .ok_or_else(|| io::Error::other("grant missing"))?;
    let accepted_routes = policy.accepted_routes(&identity, &requested_routes);
    let dns = if accepted_routes.iter().any(|route| route.prefix_len() == 0) {
        gateway.dns_servers.clone()
    } else {
        Vec::new()
    };
    if accepted_routes.iter().any(|route| route.prefix_len() == 0) && dns.is_empty() {
        reject(
            private,
            link_id,
            5,
            "gateway has no full-tunnel DNS servers",
        );
        return Ok(());
    }
    let epoch = random_nonzero();
    let mtu = maximum_packet_size.min(1280);
    let accept = ControlMessage::ServerAccept {
        session_epoch: epoch,
        assigned_address: grant.address,
        prefix_len: policy.gateway.prefix_len(),
        gateway_address: policy.gateway_address,
        accepted_routes: accepted_routes.clone(),
        dns_servers: dns.clone(),
        packet_mtu: mtu,
        setup_timeout_secs: SETUP_TIMEOUT.as_secs() as u16,
        idle_timeout_secs: grant.idle_timeout_secs.unwrap_or(0),
    };
    send_control(private, link_id, accept)?;
    entry
        .machine
        .accepted(epoch, now, SETUP_TIMEOUT)
        .map_err(session_error)?;
    entry.accepted_routes = accepted_routes;
    entry.advertised_dns = dns;
    entry.mtu = mtu;
    Ok(())
}

fn random_nonzero() -> u64 {
    loop {
        let mut bytes = [0; 8];
        OsRng.fill_bytes(&mut bytes);
        let value = u64::from_be_bytes(bytes);
        if value != 0 && value != u64::MAX {
            return value;
        }
    }
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
fn reject(private: &PrivateNode, link_id: [u8; 16], reason: u16, diagnostic: &str) {
    let _ = send_control(
        private,
        link_id,
        ControlMessage::ServerReject {
            reason,
            diagnostic: diagnostic.into(),
        },
    );
    let _ = private.node.teardown_link(link_id);
}
fn node_error(error: rns_net::node::SendError) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, error)
}
fn session_error(error: crate::SessionError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
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
