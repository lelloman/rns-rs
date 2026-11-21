//! The Linux gateway: serves authorized clients and forwards their packets
//! through a TUN interface.

use rns_core::encoding::hex;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use rns_crypto::{OsRng, Rng};
use rns_net::Destination;

use crate::config::{Config, GatewayConfig};
use crate::linux::{LinuxConfigurator, TunDevice};
use crate::packet::validate_ipv4;
use crate::platform::{PacketDevice, TunnelConfig, TunnelConfigurator};
use crate::policy::{ClientGrant, GatewayPolicy};
use crate::protocol::{ControlMessage, ProtocolError, VERSION};
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
    advertised_dns: Vec<Ipv4Addr>,
    transport: Option<PacketTransport>,
    link_mdu: usize,
    mtu: u16,
    last_activity: Duration,
}

/// Run the gateway until `stop` is set, keeping `status` current. Blocks
/// the calling thread. Registers and periodically announces the gateway
/// destination, configures the gateway TUN interface from the policy file,
/// and reloads the policy when the file changes (a reload that changes the
/// gateway address is ignored). Needs the `[gateway]` section and root
/// privileges. The interface configuration is torn down before returning.
pub fn run_linux_gateway(
    config: &Config,
    stop: &Arc<AtomicBool>,
    status: SharedStatus,
) -> io::Result<()> {
    status.update(|value| value.lifecycle = "starting".into());
    let gateway = config.gateway.as_ref().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "gateway section is required")
    })?;
    let policy = GatewayPolicy::parse_toml(&fs::read_to_string(&gateway.policy_file)?)
        .map_err(io::Error::other)?;
    let policy_modified = fs::metadata(&gateway.policy_file)?.modified().ok();
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
    configurator.cleanup_stale()?;
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
        let packet_rx = spawn_tun_reader(&device, stop)?;
        let mut server = GatewayLoop {
            gateway,
            private: &private,
            status: &status,
            device: &mut device,
            policy,
            policy_modified,
            sessions: HashMap::new(),
            started: Instant::now(),
        };
        server.run(stop, &destination, &packet_rx)
    })();
    stop.store(true, Ordering::Relaxed);
    let _ = device.close();
    let teardown = configurator.teardown(&applied);
    status.update(|value| value.lifecycle = "stopped".into());
    result.and(teardown)
}

/// Reads packets from a non-blocking clone of the TUN `device` on a
/// background thread until `stop` is set. A read error ends the thread after
/// being passed on.
fn spawn_tun_reader(
    device: &TunDevice,
    stop: &Arc<AtomicBool>,
) -> io::Result<mpsc::Receiver<io::Result<Vec<u8>>>> {
    let mut reader = device.try_clone()?;
    reader.set_nonblocking(true)?;
    let reader_stop = Arc::clone(stop);
    let (packet_tx, packet_rx) = mpsc::sync_channel::<io::Result<Vec<u8>>>(64);
    std::thread::spawn(move || {
        let mut buffer = vec![0; 1500];
        while !reader_stop.load(Ordering::Relaxed) {
            match reader.read_packet(&mut buffer) {
                Ok(size) => {
                    if packet_tx
                        .send(Ok(buffer.get(..size).unwrap_or_default().to_vec()))
                        .is_err()
                    {
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
    Ok(packet_rx)
}

/// Whether the rest of a main-loop pass (session expiry and the status
/// update) runs after an event: a pass that ignored an event or dropped a
/// session goes straight to the next one.
type Pass = ControlFlow<()>;

const NEXT_PASS: Pass = ControlFlow::Break(());

/// The gateway's state while it serves clients.
struct GatewayLoop<'a> {
    gateway: &'a GatewayConfig,
    private: &'a PrivateNode,
    status: &'a SharedStatus,
    device: &'a mut TunDevice,
    policy: GatewayPolicy,
    policy_modified: Option<SystemTime>,
    sessions: HashMap<[u8; 16], SessionEntry>,
    started: Instant,
}

impl GatewayLoop<'_> {
    fn run(
        &mut self,
        stop: &AtomicBool,
        destination: &Destination,
        packet_rx: &mpsc::Receiver<io::Result<Vec<u8>>>,
    ) -> io::Result<()> {
        let announce_interval = Duration::from_secs(self.gateway.announce_interval_seconds);
        let mut next_announce = Instant::now() + announce_interval;
        let mut next_policy_check = Instant::now() + Duration::from_secs(2);
        while !stop.load(Ordering::Relaxed) {
            if Instant::now() >= next_announce {
                self.private.announce_gateway(destination)?;
                next_announce = Instant::now() + announce_interval;
            }
            if Instant::now() >= next_policy_check {
                next_policy_check = Instant::now() + Duration::from_secs(2);
                self.reload_policy_if_changed();
            }
            self.forward_tun_packets(packet_rx)?;

            let pass = match self.private.events.recv_timeout(Duration::from_millis(20)) {
                Ok(event) => self.handle_event(event)?,
                Err(mpsc::RecvTimeoutError::Timeout) => ControlFlow::Continue(()),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "node callback queue closed",
                    ));
                }
            };
            if pass.is_break() {
                continue;
            }
            self.expire_sessions();
            self.publish_status();
        }
        Ok(())
    }

    /// Adopts the policy file when it changed, revoking sessions whose grant
    /// changed. A policy that moves the gateway, or that fails to load, is
    /// ignored.
    fn reload_policy_if_changed(&mut self) {
        let modified = fs::metadata(&self.gateway.policy_file)
            .and_then(|metadata| metadata.modified())
            .ok();
        if modified.is_none() || modified == self.policy_modified {
            return;
        }
        match fs::read_to_string(&self.gateway.policy_file)
            .map_err(io::Error::other)
            .and_then(|text| GatewayPolicy::parse_toml(&text).map_err(io::Error::other))
        {
            Ok(replacement)
                if replacement.gateway == self.policy.gateway
                    && replacement.gateway_address == self.policy.gateway_address =>
            {
                let private = self.private;
                self.sessions.retain(|link_id, entry| {
                    let unchanged = entry.identity.is_some_and(|identity| {
                        replacement.grant(&identity) == entry.grant.as_ref()
                    });
                    if !unchanged {
                        log::warn!(
                            "rntun gateway session revoked by policy reload: link={}",
                            hex(link_id)
                        );
                        let _ = private.node.teardown_link(*link_id);
                    }
                    unchanged
                });
                self.policy = replacement;
                self.policy_modified = modified;
            }
            Ok(_) => log::warn!("ignoring policy reload that changes gateway address"),
            Err(error) => {
                log::warn!("keeping current policy after reload failure: {error}")
            }
        }
    }

    /// Sends the packets read from the TUN device to the active sessions
    /// they are addressed to. Packets for no session are dropped.
    fn forward_tun_packets(
        &mut self,
        packet_rx: &mpsc::Receiver<io::Result<Vec<u8>>>,
    ) -> io::Result<()> {
        while let Ok(packet) = packet_rx.try_recv() {
            let packet = packet?;
            self.forward_tun_packet(&packet);
        }
        Ok(())
    }

    fn forward_tun_packet(&mut self, packet: &[u8]) {
        let parsed = match validate_ipv4(packet, 1280) {
            Ok(parsed) => parsed,
            Err(_) => return,
        };
        let target = self.sessions.iter_mut().find(|(_, entry)| {
            entry.machine.state() == GatewayState::Active
                && entry
                    .grant
                    .as_ref()
                    .is_some_and(|grant| grant.address == parsed.destination)
        });
        let Some((link_id, entry)) = target else {
            return;
        };
        entry.last_activity = self.started.elapsed();
        let Some(transport) = &mut entry.transport else {
            return;
        };
        let frames =
            match transport.packetize(packet, PacketDirection::GatewayToClient, entry.link_mdu) {
                Ok(frames) => frames,
                Err(error) => {
                    record_transport_error(self.status, &error);
                    return;
                }
            };
        let mut admitted = true;
        for frame in frames {
            if self
                .private
                .node
                .try_send_link_datagram(*link_id, frame, RNTUN_LINK_CONTEXT, SEND_TIMEOUT)
                .is_err()
            {
                admitted = false;
                self.status.update(|value| value.counters.queue_drops += 1);
                break;
            }
        }
        if admitted {
            self.status.update(|value| {
                value.counters.packets_out += 1;
                value.counters.bytes_out += packet.len() as u64;
            });
        }
    }

    fn handle_event(&mut self, event: NodeEvent) -> io::Result<Pass> {
        Ok(match event {
            NodeEvent::LinkEstablished {
                link_id,
                initiator: false,
            } => self.on_link_established(link_id)?,
            NodeEvent::RemoteIdentified { link_id, identity } => {
                self.on_remote_identified(link_id, identity)
            }
            NodeEvent::Control { link_id, payload } => self.on_control(link_id, payload),
            NodeEvent::PacketData { link_id, payload } => self.on_packet_data(link_id, &payload)?,
            NodeEvent::LinkClosed { link_id, reason } => {
                log::warn!("rntun gateway Link closed: reason={reason:?}");
                self.sessions.remove(&link_id);
                ControlFlow::Continue(())
            }
            _ => ControlFlow::Continue(()),
        })
    }

    /// Opens a session for an incoming Link, unless the gateway is full.
    fn on_link_established(&mut self, link_id: [u8; 16]) -> io::Result<Pass> {
        log::info!(
            "rntun gateway Link established: link={} duplicate={}",
            hex(&link_id),
            self.sessions.contains_key(&link_id)
        );
        if self.sessions.len() >= self.gateway.max_pending_links + self.gateway.max_active_sessions
        {
            let _ = self.private.node.teardown_link(link_id);
            return Ok(NEXT_PASS);
        }
        let link_mdu = self
            .private
            .node
            .links()
            .map_err(node_error)?
            .into_iter()
            .find(|link| link.link_id == link_id)
            .map(|link| link.mdu)
            .unwrap_or(384);
        self.sessions.insert(
            link_id,
            SessionEntry {
                machine: GatewaySession::new(self.started.elapsed(), IDENTIFY_TIMEOUT),
                identity: None,
                grant: None,
                accepted_routes: Vec::new(),
                advertised_dns: Vec::new(),
                transport: None,
                link_mdu,
                mtu: 1280,
                last_activity: self.started.elapsed(),
            },
        );
        Ok(ControlFlow::Continue(()))
    }

    /// Records the peer's identity and grant, rejecting identities the
    /// policy does not authorize, and answers a hello that arrived before
    /// the identity.
    fn on_remote_identified(&mut self, link_id: [u8; 16], identity: [u8; 16]) -> Pass {
        let Some(entry) = self.sessions.get_mut(&link_id) else {
            return NEXT_PASS;
        };
        let Some(grant) = self.policy.grant(&identity).cloned() else {
            log::warn!(
                "rntun gateway rejected unauthorized identity: link={} identity={}",
                hex(&link_id),
                hex(&identity)
            );
            return self.reject_session(link_id, 1, "identity is not authorized");
        };
        entry.identity = Some(identity);
        entry.grant = Some(grant);
        let result = entry
            .machine
            .identified(identity)
            .map_err(session_error)
            .and_then(|buffered| match buffered {
                Some(buffered) => process_hello(
                    self.private,
                    &self.policy,
                    self.gateway,
                    link_id,
                    entry,
                    &buffered,
                    self.started.elapsed(),
                ),
                None => Ok(()),
            });
        self.keep_or_drop(link_id, result)
    }

    /// Handles a control message from a session's client.
    fn on_control(&mut self, link_id: [u8; 16], payload: Vec<u8>) -> Pass {
        let active_count = self
            .sessions
            .values()
            .filter(|candidate| candidate.machine.state() == GatewayState::Active)
            .count();
        if !self.sessions.contains_key(&link_id) {
            return NEXT_PASS;
        }
        let message = match ControlMessage::decode(&payload) {
            Ok(message) => message,
            Err(ProtocolError::UnsupportedVersion(version)) => {
                log::warn!(
                    "rntun gateway rejected protocol version {version} (speaks {VERSION}): link={}",
                    hex(&link_id)
                );
                return self.reject_session(link_id, 4, "unsupported protocol version");
            }
            Err(_) => {
                log::warn!(
                    "rntun gateway rejected malformed control message: link={}",
                    hex(&link_id)
                );
                return self.reject_session(link_id, 2, "malformed control message");
            }
        };
        match message {
            ControlMessage::ClientHello { .. } => self.on_client_hello(link_id, payload),
            ControlMessage::ClientReady {
                session_epoch,
                dns_servers,
            } => self.on_client_ready(link_id, session_epoch, &dns_servers, active_count),
            ControlMessage::Close { session_epoch, .. } => {
                log::info!(
                    "rntun gateway received session close: link={}",
                    hex(&link_id)
                );
                let _ = send_control(
                    self.private,
                    link_id,
                    ControlMessage::CloseAck { session_epoch },
                );
                let _ = self.private.node.teardown_link(link_id);
                self.sessions.remove(&link_id);
                ControlFlow::Continue(())
            }
            _ => ControlFlow::Continue(()),
        }
    }

    /// Answers a client hello, or buffers it until the peer has identified.
    fn on_client_hello(&mut self, link_id: [u8; 16], payload: Vec<u8>) -> Pass {
        let Some(entry) = self.sessions.get_mut(&link_id) else {
            return NEXT_PASS;
        };
        let result = if entry.machine.state() == GatewayState::PendingIdentity {
            entry
                .machine
                .receive_preidentify_hello(payload)
                .map_err(session_error)
        } else {
            process_hello(
                self.private,
                &self.policy,
                self.gateway,
                link_id,
                entry,
                &payload,
                self.started.elapsed(),
            )
        };
        self.keep_or_drop(link_id, result)
    }

    /// Activates a session whose client is ready, within the gateway's
    /// session capacity and only with the DNS servers it was offered.
    fn on_client_ready(
        &mut self,
        link_id: [u8; 16],
        session_epoch: u64,
        dns_servers: &[Ipv4Addr],
        active_count: usize,
    ) -> Pass {
        let Some(entry) = self.sessions.get_mut(&link_id) else {
            return NEXT_PASS;
        };
        if entry.machine.state() != GatewayState::Active
            && active_count >= self.gateway.max_active_sessions
        {
            log::warn!(
                "rntun gateway rejected session at capacity: link={}",
                hex(&link_id)
            );
            return self.reject_session(link_id, 6, "gateway session capacity reached");
        }
        if dns_servers != entry.advertised_dns {
            log::warn!(
                "rntun gateway rejected DNS mismatch: link={}",
                hex(&link_id)
            );
            return self.reject_session(link_id, 3, "DNS configuration mismatch");
        }
        let result = start_transport(self.private, &self.policy, link_id, entry, session_epoch);
        self.keep_or_drop(link_id, result)
    }

    /// Writes a client's packet to the TUN device.
    fn on_packet_data(&mut self, link_id: [u8; 16], payload: &[u8]) -> io::Result<Pass> {
        let Some(entry) = self.sessions.get_mut(&link_id) else {
            return Ok(NEXT_PASS);
        };
        if !entry.machine.permits_packet_data() {
            return Ok(NEXT_PASS);
        }
        let Some(transport) = &mut entry.transport else {
            return Ok(NEXT_PASS);
        };
        match transport.receive(
            payload,
            PacketDirection::ClientToGateway,
            self.started.elapsed(),
        ) {
            Ok(Some(packet)) => {
                entry.last_activity = self.started.elapsed();
                self.device.write_packet(&packet)?;
                self.status.update(|value| {
                    value.counters.packets_in += 1;
                    value.counters.bytes_in += packet.len() as u64;
                });
            }
            Ok(None) => {}
            Err(error) => record_transport_error(self.status, &error),
        }
        Ok(ControlFlow::Continue(()))
    }

    /// Rejects and forgets a session.
    fn reject_session(&mut self, link_id: [u8; 16], reason: u16, diagnostic: &str) -> Pass {
        reject(self.private, link_id, reason, diagnostic);
        self.sessions.remove(&link_id);
        NEXT_PASS
    }

    /// Keeps a session whose step succeeded. A session that breaks the
    /// protocol is rejected and dropped; the gateway keeps serving the
    /// others.
    fn keep_or_drop(&mut self, link_id: [u8; 16], result: io::Result<()>) -> Pass {
        match result {
            Ok(()) => ControlFlow::Continue(()),
            Err(error) => {
                log::warn!(
                    "rntun gateway dropped session after an error: link={} error={}",
                    hex(&link_id),
                    error
                );
                self.reject_session(link_id, 2, "protocol error")
            }
        }
    }

    /// Tears down sessions past their idle timeout or a protocol deadline.
    fn expire_sessions(&mut self) {
        let now = self.started.elapsed();
        let private = self.private;
        self.sessions.retain(|link_id, entry| {
            let idle_expired = entry.machine.state() == GatewayState::Active
                && entry
                    .grant
                    .as_ref()
                    .and_then(|grant| grant.idle_timeout_secs)
                    .is_some_and(|seconds| {
                        now.saturating_sub(entry.last_activity)
                            >= Duration::from_secs(seconds as u64)
                    });
            let protocol_expired = entry.machine.check_timeout(now).is_err();
            if idle_expired || protocol_expired {
                log::warn!(
                    "rntun gateway session expired: idle_expired={idle_expired} protocol_expired={protocol_expired} state={:?}",
                    entry.machine.state()
                );
                let _ = private.node.teardown_link(*link_id);
                false
            } else {
                true
            }
        });
    }

    fn publish_status(&self) {
        self.status.update(|value| {
            value.queue_depths.insert(
                "dropped_node_callbacks".into(),
                self.private.dropped_callbacks() as usize,
            );
            value.sessions = self
                .sessions
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
}

/// Moves a session whose client is ready to active: sets up its packet
/// transport and confirms to the client.
fn start_transport(
    private: &PrivateNode,
    policy: &GatewayPolicy,
    link_id: [u8; 16],
    entry: &mut SessionEntry,
    session_epoch: u64,
) -> io::Result<()> {
    let ready = entry
        .machine
        .client_ready(session_epoch)
        .map_err(session_error)?;
    let grant = entry
        .grant
        .as_ref()
        .ok_or_else(|| io::Error::other("grant missing"))?;
    let transport = PacketTransport::new(
        session_epoch,
        grant.address,
        policy.gateway_address,
        entry.accepted_routes.clone(),
        entry.mtu,
        random_nonzero(),
    )
    .map_err(io::Error::other)?;
    entry.transport = Some(transport);
    send_control(private, link_id, ready)
}

fn process_hello(
    private: &PrivateNode,
    policy: &GatewayPolicy,
    gateway: &GatewayConfig,
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
fn node_error(error: rns_net::SendError) -> io::Error {
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
