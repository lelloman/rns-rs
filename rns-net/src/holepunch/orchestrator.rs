//! HolePunchManager: orchestrates hole-punch sessions.
//!
//! Bridges the rns-core HolePunchEngine (pure state machine) with networking
//! (probe, punch, direct interface). Lives in the Driver, analogous to LinkManager.
//!
//! Follows the asymmetric protocol from direct-link-protocol.md:
//! - Initiator probes STUN first, then sends UPGRADE_REQUEST with facilitator + A_pub
//! - Responder accepts, probes facilitator from request, sends UPGRADE_READY with B_pub
//! - Both punch simultaneously

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Instant;

use rns_core::holepunch::types::is_holepunch_msgtype;
use rns_core::holepunch::{
    Endpoint, HolePunchAction, HolePunchEngine, HolePunchState, ProbeProtocol, REJECT_BUSY,
    REJECT_POLICY, UPGRADE_REQUEST,
};

use crate::event::{Event, EventSender};
use crate::time;

use super::admission::{
    endpoint_is_acceptable, InboundRequestLimiter, INBOUND_REQUEST_WINDOW, MAX_CONCURRENT_SESSIONS,
};
use super::probe;
use super::puncher::{self, PunchHandle};
use super::udp_direct;

pub use crate::common::event::HolePunchPolicy;

/// A single hole-punch session's networking state.
struct HolePunchSession {
    engine: HolePunchEngine,
    /// The UDP socket used for probing and punching (same NAT mapping).
    socket: Option<UdpSocket>,
    /// Handle to the running punch thread.
    punch_handle: Option<PunchHandle>,
    /// Last proposal time for rate limiting.
    last_proposal: f64,
    /// Address the punch thread sends to, once punching has started.
    punch_target: Option<SocketAddr>,
}

impl HolePunchSession {
    fn new(engine: HolePunchEngine, now: f64) -> Self {
        HolePunchSession {
            engine,
            socket: None,
            punch_handle: None,
            last_proposal: now,
            punch_target: None,
        }
    }

    /// Whether this session is a responder session still probing or punching.
    fn is_active_inbound(&self) -> bool {
        !self.engine.is_initiator()
            && matches!(
                self.engine.state(),
                HolePunchState::Discovering | HolePunchState::Punching
            )
    }

    fn is_punching(&self) -> bool {
        self.punch_handle
            .as_ref()
            .map(|h| h.is_running())
            .unwrap_or(false)
    }

    fn cancel_punch(&mut self) {
        if let Some(handle) = self.punch_handle.take() {
            handle.cancel();
        }
    }
}

/// Manages all hole-punch sessions.
pub struct HolePunchManager {
    sessions: HashMap<[u8; 16], HolePunchSession>, // session_id -> session
    link_to_session: HashMap<[u8; 16], [u8; 16]>,  // link_id -> session_id
    policy: HolePunchPolicy,
    /// Configured probe servers (tried sequentially with failover).
    probe_addrs: Vec<SocketAddr>,
    /// Protocol to use for endpoint discovery.
    probe_protocol: ProbeProtocol,
    /// Linux network interface to bind probe/punch sockets to.
    device: Option<String>,
    /// Linux mark applied to probe and direct-UDP underlay sockets.
    underlay_mark: Option<u32>,
    /// Next available interface ID counter for direct interfaces.
    next_interface_id: u64,
    /// Accept private, shared, link-local and unique-local endpoints from peers.
    allow_private_endpoints: bool,
    /// Paces inbound upgrade requests per link.
    inbound_limiter: InboundRequestLimiter,
    /// Spawn probe and punch threads (disabled by unit tests).
    spawn_workers: bool,
}

/// Actions produced by HolePunchManager for the driver to dispatch.
pub enum HolePunchManagerAction {
    /// Send a channel message on a link.
    SendChannelMessage {
        link_id: [u8; 16],
        msgtype: u16,
        payload: Vec<u8>,
    },
    /// Direct connection established — register the new interface.
    DirectConnectEstablished {
        link_id: [u8; 16],
        session_id: [u8; 16],
        interface_id: rns_core::transport::types::InterfaceId,
        /// RTT measured during punch (time from first send to first ACK).
        rtt: f64,
        /// MTU of the direct interface.
        mtu: u32,
    },
    /// Direct connection failed.
    DirectConnectFailed {
        link_id: [u8; 16],
        session_id: [u8; 16],
        reason: u8,
    },
}

impl HolePunchManager {
    pub fn new(
        probe_addrs: Vec<SocketAddr>,
        probe_protocol: ProbeProtocol,
        device: Option<String>,
    ) -> Self {
        HolePunchManager {
            sessions: HashMap::new(),
            link_to_session: HashMap::new(),
            policy: HolePunchPolicy::default(),
            probe_addrs,
            probe_protocol,
            device,
            underlay_mark: None,
            next_interface_id: 50000, // start high to avoid collision with regular interfaces
            allow_private_endpoints: false,
            inbound_limiter: InboundRequestLimiter::new(INBOUND_REQUEST_WINDOW),
            spawn_workers: true,
        }
    }

    pub fn set_policy(&mut self, policy: HolePunchPolicy) {
        self.policy = policy;
    }

    pub fn policy(&self) -> HolePunchPolicy {
        self.policy
    }

    pub fn set_underlay_mark(&mut self, underlay_mark: Option<u32>) {
        self.underlay_mark = underlay_mark;
    }

    /// Accept peer-supplied endpoints in private, shared, link-local,
    /// and unique-local ranges (for LAN-only deployments).
    pub fn set_allow_private_endpoints(&mut self, allow: bool) {
        self.allow_private_endpoints = allow;
    }

    pub fn allow_private_endpoints(&self) -> bool {
        self.allow_private_endpoints
    }

    /// Whether a peer-supplied endpoint may be probed or punched.
    fn endpoint_allowed(&self, ep: &Endpoint) -> Option<SocketAddr> {
        endpoint_to_socket_addr(ep)
            .filter(|addr| endpoint_is_acceptable(addr, self.allow_private_endpoints))
    }

    /// Propose a direct connection on a link.
    ///
    /// Per the spec, the initiator first discovers its own public endpoint
    /// (Phase 1), then sends UPGRADE_REQUEST (Phase 2).
    ///
    /// `derived_key` is the link's derived session key (from LinkEngine).
    pub fn propose(
        &mut self,
        link_id: [u8; 16],
        derived_key: &[u8],
        rng: &mut dyn rns_crypto::Rng,
        tx: &EventSender,
    ) -> Vec<HolePunchManagerAction> {
        let now = time::now();

        // Rate limit: one proposal per link per 60s
        if let Some(session_id) = self.link_to_session.get(&link_id) {
            if let Some(session) = self.sessions.get(session_id) {
                let elapsed = now - session.last_proposal;
                if elapsed < rns_core::holepunch::types::PROPOSAL_COOLDOWN {
                    log::debug!(
                        "Hole punch proposal rate limited for link {:02x?}",
                        &link_id[..4]
                    );
                    return Vec::new();
                }
            }
        }

        // Clean up any existing session for this link
        self.remove_link_session(&link_id);

        let probe_endpoint = self.probe_addrs.first().map(|addr| Endpoint {
            addr: match addr {
                SocketAddr::V4(v4) => v4.ip().octets().to_vec(),
                SocketAddr::V6(v6) => v6.ip().octets().to_vec(),
            },
            port: addr.port(),
        });

        let mut engine = HolePunchEngine::new(link_id, probe_endpoint, self.probe_protocol);
        let actions = match engine.propose(derived_key, now, rng) {
            Ok(a) => a,
            Err(e) => {
                log::warn!("Failed to propose hole punch: {}", e);
                return Vec::new();
            }
        };

        let session_id = *engine.session_id();
        self.link_to_session.insert(link_id, session_id);
        self.sessions
            .insert(session_id, HolePunchSession::new(engine, now));

        let mgr_actions = convert_engine_actions(link_id, &actions);

        // Engine emits DiscoverEndpoints — start probe worker
        self.start_endpoint_discovery_from_actions(link_id, &actions, tx);

        mgr_actions
    }

    /// Handle an incoming hole-punch signaling message.
    ///
    /// Returns true if the message was handled (caller should not forward to app).
    pub fn handle_signal(
        &mut self,
        link_id: [u8; 16],
        msgtype: u16,
        payload: Vec<u8>,
        derived_key: Option<&[u8]>,
        tx: &EventSender,
    ) -> (bool, Vec<HolePunchManagerAction>) {
        self.handle_signal_at(link_id, msgtype, payload, derived_key, tx, Instant::now())
    }

    fn handle_signal_at(
        &mut self,
        link_id: [u8; 16],
        msgtype: u16,
        payload: Vec<u8>,
        derived_key: Option<&[u8]>,
        tx: &EventSender,
        now_instant: Instant,
    ) -> (bool, Vec<HolePunchManagerAction>) {
        if !is_holepunch_msgtype(msgtype) {
            return (false, Vec::new());
        }

        // For UPGRADE_REQUEST, check policy first
        if msgtype == UPGRADE_REQUEST {
            match self.policy {
                HolePunchPolicy::Reject => {
                    log::debug!("Rejecting hole punch proposal (policy=Reject)");
                    match HolePunchEngine::build_reject(link_id, &payload, REJECT_POLICY) {
                        Ok(action) => {
                            let mgr_actions = convert_engine_actions(link_id, &[action]);
                            return (true, mgr_actions);
                        }
                        Err(e) => {
                            log::warn!("Failed to build reject for proposal: {}", e);
                            return (true, Vec::new());
                        }
                    }
                }
                HolePunchPolicy::AcceptAll => {
                    // Proceed
                }
                HolePunchPolicy::IdentifiedOnly | HolePunchPolicy::AskApp => {
                    // Identity-aware and application decisions are made by the
                    // driver. Direct manager users fail closed.
                    log::debug!("Rejecting hole punch proposal pending driver authorization");
                    match HolePunchEngine::build_reject(link_id, &payload, REJECT_POLICY) {
                        Ok(action) => {
                            let mgr_actions = convert_engine_actions(link_id, &[action]);
                            return (true, mgr_actions);
                        }
                        Err(e) => {
                            log::warn!("Failed to build reject for proposal: {}", e);
                            return (true, Vec::new());
                        }
                    }
                }
            }

            if !self.inbound_limiter.check_and_record(link_id, now_instant) {
                log::debug!(
                    "Refusing hole punch proposal on link {:02x?}: request window",
                    &link_id[..4]
                );
                return (true, refuse_request(link_id, &payload, REJECT_BUSY));
            }

            // A new request replaces any earlier session on this link.
            self.remove_link_session(&link_id);

            let active_inbound = self
                .sessions
                .values()
                .filter(|s| s.is_active_inbound())
                .count();
            if active_inbound >= MAX_CONCURRENT_SESSIONS {
                log::debug!(
                    "Refusing hole punch proposal on link {:02x?}: {} sessions active",
                    &link_id[..4],
                    active_inbound
                );
                return (true, refuse_request(link_id, &payload, REJECT_BUSY));
            }

            // Create engine for responder (no probe_addr needed — facilitator comes from request)
            // Protocol will be set from the decoded UPGRADE_REQUEST payload.
            let mut engine = HolePunchEngine::new(link_id, None, ProbeProtocol::Rnsp);
            let now = time::now();
            let actions = match engine.handle_signal(msgtype, &payload, derived_key, now) {
                Ok(a) => a,
                Err(e) => {
                    log::warn!("Error handling UPGRADE_REQUEST: {}", e);
                    return (true, Vec::new());
                }
            };

            // Both endpoints in the request are chosen by the peer: check them
            // before anything is sent to either.
            let initiator_addr = engine
                .peer_public_endpoint()
                .and_then(|ep| self.endpoint_allowed(ep));
            let facilitator_ok = actions.iter().all(|a| match a {
                HolePunchAction::DiscoverEndpoints { probe_addr, .. } => {
                    self.endpoint_allowed(probe_addr).is_some()
                }
                _ => true,
            });
            let Some(initiator_addr) = initiator_addr.filter(|_| facilitator_ok) else {
                log::debug!(
                    "Refusing hole punch proposal on link {:02x?}: endpoint outside the accepted ranges",
                    &link_id[..4]
                );
                return (true, refuse_request(link_id, &payload, REJECT_POLICY));
            };
            if self.target_in_use(initiator_addr, None) {
                log::debug!(
                    "Refusing hole punch proposal on link {:02x?}: {} already has a session",
                    &link_id[..4],
                    initiator_addr
                );
                return (true, refuse_request(link_id, &payload, REJECT_BUSY));
            }

            let session_id = *engine.session_id();
            self.link_to_session.insert(link_id, session_id);
            let mut session = HolePunchSession::new(engine, now);
            session.punch_target = Some(initiator_addr);
            self.sessions.insert(session_id, session);

            let mgr_actions = convert_engine_actions(link_id, &actions);

            // Engine emits DiscoverEndpoints with facilitator from request — start probe
            self.start_endpoint_discovery_from_actions(link_id, &actions, tx);

            return (true, mgr_actions);
        }

        // For other message types, find existing session
        let session_id = match self.link_to_session.get(&link_id) {
            Some(s) => *s,
            None => {
                log::debug!("No hole punch session for link {:02x?}", &link_id[..4]);
                return (true, Vec::new());
            }
        };

        let session = match self.sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return (true, Vec::new()),
        };

        let now = time::now();
        let actions = match session
            .engine
            .handle_signal(msgtype, &payload, derived_key, now)
        {
            Ok(a) => a,
            Err(e) => {
                log::warn!("Error handling signal 0x{:04x}: {}", msgtype, e);
                return (true, Vec::new());
            }
        };

        let mut mgr_actions = convert_engine_actions(link_id, &actions);

        // Check if engine now wants to start punching
        mgr_actions.extend(self.start_punch_from_actions(link_id, &session_id, &actions));

        (true, mgr_actions)
    }

    /// Tick all sessions for timeout checks.
    pub fn tick(&mut self, tx: &EventSender) -> Vec<HolePunchManagerAction> {
        let now = time::now();
        let mut all_actions = Vec::new();

        // Build a snapshot of session IDs and their corresponding link IDs
        let session_link_pairs: Vec<([u8; 16], Option<[u8; 16]>)> = self
            .sessions
            .keys()
            .map(|sid| {
                let link_id = self
                    .link_to_session
                    .iter()
                    .find(|(_, v)| *v == sid)
                    .map(|(k, _)| *k);
                (*sid, link_id)
            })
            .collect();

        // Collect results from punch handles
        struct PunchCompletion {
            session_id: [u8; 16],
            link_id: [u8; 16],
            succeeded: bool,
            socket: Option<std::net::UdpSocket>,
            peer_addr: Option<SocketAddr>,
            rtt: Option<f64>,
        }
        let mut completions: Vec<PunchCompletion> = Vec::new();

        for (session_id, link_id) in &session_link_pairs {
            if let Some(session) = self.sessions.get_mut(session_id) {
                let punch_done = session
                    .punch_handle
                    .as_ref()
                    .map(|h| !h.is_running())
                    .unwrap_or(false);

                if punch_done {
                    let succeeded = session
                        .punch_handle
                        .as_ref()
                        .map(|h| h.succeeded())
                        .unwrap_or(false);

                    if let Some(link_id) = link_id {
                        if succeeded {
                            if let Some(handle) = session.punch_handle.take() {
                                if let Some(result) = handle.join() {
                                    let rtt_secs = result.rtt.as_secs_f64();
                                    completions.push(PunchCompletion {
                                        session_id: *session_id,
                                        link_id: *link_id,
                                        succeeded: true,
                                        socket: Some(result.socket),
                                        peer_addr: Some(result.peer_addr),
                                        rtt: Some(rtt_secs),
                                    });
                                }
                            }
                        } else {
                            session.punch_handle.take();
                            completions.push(PunchCompletion {
                                session_id: *session_id,
                                link_id: *link_id,
                                succeeded: false,
                                socket: None,
                                peer_addr: None,
                                rtt: None,
                            });
                        }
                    }
                }
            }
        }

        // Process completions
        for completion in completions {
            if completion.succeeded {
                if let (Some(socket), Some(peer_addr)) = (completion.socket, completion.peer_addr) {
                    // Register direct interface
                    let interface_id =
                        rns_core::transport::types::InterfaceId(self.next_interface_id);
                    self.next_interface_id += 1;

                    let mut iface_ok = false;
                    if let Some(session) = self.sessions.get(&completion.session_id) {
                        let session_id = *session.engine.session_id();
                        let punch_token = *session.engine.punch_token();
                        match udp_direct::start_direct_interface(
                            socket,
                            peer_addr,
                            interface_id,
                            session_id,
                            punch_token,
                            tx.clone(),
                        ) {
                            Ok((writer, info)) => {
                                log::info!("Direct UDP interface registered: {}", info.name);
                                let _ = tx.send(Event::InterfaceUp(
                                    interface_id,
                                    Some(writer),
                                    Some(Box::new(info)),
                                ));
                                iface_ok = true;
                            }
                            Err(e) => {
                                log::warn!("Failed to start direct interface: {}", e);
                            }
                        }
                    }

                    // Notify engine of success
                    if let Some(session) = self.sessions.get_mut(&completion.session_id) {
                        let engine_actions =
                            session.engine.punch_succeeded(now).unwrap_or_default();
                        for action in engine_actions {
                            match action {
                                HolePunchAction::Succeeded { session_id } if iface_ok => {
                                    all_actions.push(
                                        HolePunchManagerAction::DirectConnectEstablished {
                                            link_id: completion.link_id,
                                            session_id,
                                            interface_id,
                                            rtt: completion.rtt.unwrap_or(0.0),
                                            mtu: 1400,
                                        },
                                    );
                                }
                                HolePunchAction::Succeeded { session_id } => {
                                    all_actions.push(HolePunchManagerAction::DirectConnectFailed {
                                        link_id: completion.link_id,
                                        session_id,
                                        reason: rns_core::holepunch::types::FAIL_TIMEOUT,
                                    });
                                }
                                _ => {
                                    let mgr = convert_engine_actions(completion.link_id, &[action]);
                                    all_actions.extend(mgr);
                                }
                            }
                        }
                    }
                }
            } else {
                // Punch failed
                if let Some(session) = self.sessions.get_mut(&completion.session_id) {
                    let engine_actions = session.engine.punch_failed(now).unwrap_or_default();
                    let mgr = convert_engine_actions(completion.link_id, engine_actions.as_slice());
                    all_actions.extend(mgr);
                }
            }
        }

        // Tick engines for timeouts
        for (session_id, link_id) in &session_link_pairs {
            if let Some(link_id) = link_id {
                if let Some(session) = self.sessions.get_mut(session_id) {
                    let timeout_actions = session.engine.tick(now);
                    if !timeout_actions.is_empty() {
                        let mgr = convert_engine_actions(*link_id, timeout_actions.as_slice());
                        all_actions.extend(mgr);
                    }
                }
            }
        }

        // Clean up Failed sessions
        let failed_sessions: Vec<[u8; 16]> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.engine.state() == HolePunchState::Failed)
            .map(|(id, _)| *id)
            .collect();

        for session_id in failed_sessions {
            if let Some(mut session) = self.sessions.remove(&session_id) {
                session.cancel_punch();
            }
            self.link_to_session.retain(|_, v| *v != session_id);
        }

        all_actions
    }

    /// Called when a link is closed — clean up any associated session.
    pub fn link_closed(&mut self, link_id: &[u8; 16]) {
        self.remove_link_session(link_id);
    }

    /// Remove the session bound to `link_id`, stopping its punch thread.
    fn remove_link_session(&mut self, link_id: &[u8; 16]) {
        if let Some(session_id) = self.link_to_session.remove(link_id) {
            if let Some(mut session) = self.sessions.remove(&session_id) {
                session.cancel_punch();
            }
        }
    }

    /// Whether another session (other than `except`) is probing or punching
    /// toward `target`.
    fn target_in_use(&self, target: SocketAddr, except: Option<&[u8; 16]>) -> bool {
        self.sessions.iter().any(|(id, s)| {
            Some(id) != except
                && s.punch_target == Some(target)
                && (s.is_punching() || s.is_active_inbound())
        })
    }

    /// Abort and remove all active hole-punch sessions.
    pub fn abort_all_sessions(&mut self) {
        for (_, mut session) in self.sessions.drain() {
            if let Some(handle) = session.punch_handle.take() {
                handle.cancel();
            }
        }
        self.link_to_session.clear();
    }

    /// Check if a message type is a hole-punch signaling message.
    pub fn is_holepunch_message(msgtype: u16) -> bool {
        is_holepunch_msgtype(msgtype)
    }

    // --- Internal helpers ---

    /// Start endpoint discovery if the engine actions contain a DiscoverEndpoints.
    fn start_endpoint_discovery_from_actions(
        &self,
        link_id: [u8; 16],
        actions: &[HolePunchAction],
        tx: &EventSender,
    ) {
        for action in actions {
            if let HolePunchAction::DiscoverEndpoints {
                probe_addr,
                protocol,
            } = action
            {
                let session_id = match self.link_to_session.get(&link_id) {
                    Some(s) => *s,
                    None => continue,
                };

                let session = match self.sessions.get(&session_id) {
                    Some(s) => s,
                    None => continue,
                };

                // Initiator: try all configured servers with failover.
                // Responder: use only the facilitator from UPGRADE_REQUEST.
                let servers: Vec<SocketAddr> = if session.engine.is_initiator() {
                    self.probe_addrs.clone()
                } else {
                    match self.endpoint_allowed(probe_addr) {
                        Some(a) => vec![a],
                        None => {
                            log::warn!("Invalid probe endpoint: {:?}", probe_addr);
                            continue;
                        }
                    }
                };

                if servers.is_empty() {
                    log::warn!(
                        "No probe servers available for session {:02x?}",
                        &session_id[..4]
                    );
                    continue;
                }

                if !self.spawn_workers {
                    continue;
                }

                let tx_clone = tx.clone();
                let session_id_copy = session_id;
                let device_clone = self.device.clone();
                let underlay_mark = self.underlay_mark;
                let protocol_copy = *protocol;

                if let Err(e) =
                    thread::Builder::new()
                        .name("probe-worker".into())
                        .spawn(move || {
                            run_probe_worker(
                                servers,
                                protocol_copy,
                                session_id_copy,
                                link_id,
                                tx_clone,
                                device_clone,
                                underlay_mark,
                            );
                        })
                {
                    log::warn!("Failed to spawn probe worker: {}", e);
                }
            }
        }
    }

    /// Start punch if the engine actions contain a StartUdpPunch.
    fn start_punch_from_actions(
        &mut self,
        link_id: [u8; 16],
        session_id: &[u8; 16],
        actions: &[HolePunchAction],
    ) -> Vec<HolePunchManagerAction> {
        let mut mgr_actions = Vec::new();
        for action in actions {
            if let HolePunchAction::StartUdpPunch {
                peer_public,
                punch_token,
                ..
            } = action
            {
                mgr_actions.extend(self.start_punch_for_session(
                    link_id,
                    session_id,
                    peer_public,
                    punch_token,
                ));
            }
        }
        mgr_actions
    }

    fn start_punch_for_session(
        &mut self,
        link_id: [u8; 16],
        session_id: &[u8; 16],
        peer_public: &Endpoint,
        punch_token: &[u8; 32],
    ) -> Vec<HolePunchManagerAction> {
        let peer_addr = self.endpoint_allowed(peer_public);
        let running = self.sessions.values().filter(|s| s.is_punching()).count();
        let target_busy = peer_addr
            .map(|addr| self.target_in_use(addr, Some(session_id)))
            .unwrap_or(false);

        let session = match self.sessions.get_mut(session_id) {
            Some(s) => s,
            None => return Vec::new(),
        };

        if session.punch_handle.is_some() {
            return Vec::new(); // Already punching
        }

        let peer_addr = match peer_addr {
            Some(a) if !target_busy && running < MAX_CONCURRENT_SESSIONS => a,
            other => {
                match other {
                    None => log::warn!(
                        "Not punching session {:02x?}: peer endpoint {:?} outside the accepted ranges",
                        &session_id[..4],
                        peer_public
                    ),
                    Some(a) => log::debug!(
                        "Not punching session {:02x?} to {}: target busy or {} punches running",
                        &session_id[..4],
                        a,
                        running
                    ),
                }
                session.socket = None;
                let actions = session.engine.punch_failed(time::now()).unwrap_or_default();
                return convert_engine_actions(link_id, &actions);
            }
        };
        session.punch_target = Some(peer_addr);

        if !self.spawn_workers {
            return Vec::new();
        }

        let socket = match session.socket.take() {
            Some(s) => s,
            None => {
                log::warn!("No socket available for punching");
                return Vec::new();
            }
        };

        let punch_token_copy = *punch_token;
        let session_id_copy = *session.engine.session_id();

        log::info!(
            "Starting UDP hole punch for session {:02x?} to {}",
            &session_id_copy[..4],
            peer_addr
        );

        match puncher::start_udp_punch(
            socket,
            vec![peer_addr],
            vec![],
            session_id_copy,
            punch_token_copy,
        ) {
            Ok(handle) => {
                session.punch_handle = Some(handle);
            }
            Err(e) => {
                log::warn!("Failed to start UDP punch: {}", e);
            }
        }
        Vec::new()
    }

    /// Called when a probe result arrives from the worker thread.
    pub fn handle_probe_result(
        &mut self,
        link_id: [u8; 16],
        session_id: [u8; 16],
        observed_addr: SocketAddr,
        socket: UdpSocket,
        probe_server: SocketAddr,
    ) -> Vec<HolePunchManagerAction> {
        let session = match self.sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return Vec::new(),
        };

        // Store the socket for reuse during punching (same NAT mapping)
        session.socket = Some(socket);

        // If a different server succeeded than the first configured one,
        // update the engine's facilitator so UPGRADE_REQUEST carries the correct address.
        if session.engine.is_initiator() {
            let first = self.probe_addrs.first().copied();
            if first != Some(probe_server) {
                let facilitator_ep = Endpoint {
                    addr: match probe_server {
                        SocketAddr::V4(v4) => v4.ip().octets().to_vec(),
                        SocketAddr::V6(v6) => v6.ip().octets().to_vec(),
                    },
                    port: probe_server.port(),
                };
                session.engine.set_facilitator(facilitator_ep);
            }
        }

        // Bump-to-top: move the successful server to index 0
        if let Some(idx) = self.probe_addrs.iter().position(|a| *a == probe_server) {
            if idx > 0 {
                self.probe_addrs[..=idx].rotate_right(1);
            }
        }

        let public_endpoint = Endpoint {
            addr: match observed_addr {
                SocketAddr::V4(v4) => v4.ip().octets().to_vec(),
                SocketAddr::V6(v6) => v6.ip().octets().to_vec(),
            },
            port: observed_addr.port(),
        };

        let now = time::now();
        let actions = match session.engine.endpoints_discovered(public_endpoint, now) {
            Ok(a) => a,
            Err(e) => {
                log::warn!("Error in endpoints_discovered: {}", e);
                return Vec::new();
            }
        };

        let mut mgr_actions = convert_engine_actions(link_id, &actions);

        // Check if engine now wants to start punching (responder after discovery)
        mgr_actions.extend(self.start_punch_from_actions(link_id, &session_id, &actions));

        mgr_actions
    }

    /// Called when a probe fails.
    pub fn handle_probe_failed(
        &mut self,
        link_id: [u8; 16],
        session_id: [u8; 16],
    ) -> Vec<HolePunchManagerAction> {
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.engine.reset();
            vec![HolePunchManagerAction::DirectConnectFailed {
                link_id,
                session_id,
                reason: rns_core::holepunch::types::FAIL_PROBE,
            }]
        } else {
            Vec::new()
        }
    }
}

fn run_probe_worker(
    servers: Vec<SocketAddr>,
    protocol: ProbeProtocol,
    session_id: [u8; 16],
    link_id: [u8; 16],
    tx: EventSender,
    device: Option<String>,
    underlay_mark: Option<u32>,
) {
    match probe::probe_endpoint_failover_with_mark(
        &servers,
        protocol,
        std::time::Duration::from_secs(3),
        device.as_deref(),
        underlay_mark,
    ) {
        Ok((observed, socket, probe_server)) => {
            log::info!(
                "Probe discovered endpoint: {} via server {} for session {:02x?}",
                observed,
                probe_server,
                &session_id[..4]
            );
            let _ = tx.send(Event::HolePunchProbeResult {
                link_id,
                session_id,
                observed_addr: observed,
                socket,
                probe_server,
            });
        }
        Err(e) => {
            log::warn!(
                "Probe failed for session {:02x?} (tried {} servers): {}",
                &session_id[..4],
                servers.len(),
                e
            );
            let _ = tx.send(Event::HolePunchProbeFailed {
                link_id,
                session_id,
            });
        }
    }
}

/// Build an `UPGRADE_REJECT` reply for a request that is not taken up.
fn refuse_request(link_id: [u8; 16], payload: &[u8], reason: u8) -> Vec<HolePunchManagerAction> {
    match HolePunchEngine::build_reject(link_id, payload, reason) {
        Ok(action) => convert_engine_actions(link_id, &[action]),
        Err(e) => {
            log::warn!("Failed to build reject for proposal: {}", e);
            Vec::new()
        }
    }
}

/// Convert engine actions to manager actions (free function to avoid borrow issues).
fn convert_engine_actions(
    link_id: [u8; 16],
    actions: &[HolePunchAction],
) -> Vec<HolePunchManagerAction> {
    let mut mgr_actions = Vec::new();
    for action in actions {
        match action {
            HolePunchAction::SendSignal {
                link_id,
                msgtype,
                payload,
            } => {
                mgr_actions.push(HolePunchManagerAction::SendChannelMessage {
                    link_id: *link_id,
                    msgtype: *msgtype,
                    payload: payload.clone(),
                });
            }
            HolePunchAction::DiscoverEndpoints { .. } => {
                // Handled separately via probe workers
            }
            HolePunchAction::StartUdpPunch { .. } => {
                // Handled separately via punch threads
            }
            HolePunchAction::Succeeded { .. } => {
                // Handled directly in tick() where the interface_id is available
            }
            HolePunchAction::Failed { session_id, reason } => {
                mgr_actions.push(HolePunchManagerAction::DirectConnectFailed {
                    link_id,
                    session_id: *session_id,
                    reason: *reason,
                });
            }
        }
    }
    mgr_actions
}

/// Convert an Endpoint (from rns-core) to a SocketAddr.
pub fn endpoint_to_socket_addr(ep: &Endpoint) -> Option<SocketAddr> {
    match ep.addr.len() {
        4 => {
            let ip = std::net::Ipv4Addr::new(ep.addr[0], ep.addr[1], ep.addr[2], ep.addr[3]);
            Some(SocketAddr::new(ip.into(), ep.port))
        }
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&ep.addr);
            let ip = std::net::Ipv6Addr::from(octets);
            Some(SocketAddr::new(ip.into(), ep.port))
        }
        _ => None,
    }
}

impl HolePunchManager {
    /// Number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
impl HolePunchManager {
    fn has_session_for_link(&self, link_id: &[u8; 16]) -> bool {
        self.link_to_session.contains_key(link_id)
    }

    fn set_spawn_workers(&mut self, spawn: bool) {
        self.spawn_workers = spawn;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_core::holepunch::{UPGRADE_ACCEPT, UPGRADE_READY, UPGRADE_REJECT};
    use rns_crypto::FixedRng;

    fn make_rng(seed: u8) -> FixedRng {
        FixedRng::new(&[seed; 128])
    }

    fn test_derived_key() -> Vec<u8> {
        vec![0xAA; 32]
    }

    fn make_probe_addr() -> SocketAddr {
        "127.0.0.1:4343".parse().unwrap()
    }

    fn make_tx() -> (EventSender, crate::event::EventReceiver) {
        crate::event::channel()
    }

    fn ep(s: &str) -> Endpoint {
        let addr: SocketAddr = s.parse().unwrap();
        Endpoint {
            addr: match addr {
                SocketAddr::V4(v4) => v4.ip().octets().to_vec(),
                SocketAddr::V6(v6) => v6.ip().octets().to_vec(),
            },
            port: addr.port(),
        }
    }

    /// Build an UPGRADE_REQUEST payload naming `facilitator` and `initiator`.
    fn make_request(link_id: [u8; 16], facilitator: &str, initiator: &str, seed: u8) -> Vec<u8> {
        let mut rng = make_rng(seed);
        let mut proposer =
            HolePunchEngine::new(link_id, Some(ep(facilitator)), ProbeProtocol::Rnsp);
        proposer
            .propose(&test_derived_key(), 100.0, &mut rng)
            .unwrap();
        let discover_actions = proposer.endpoints_discovered(ep(initiator), 101.0).unwrap();
        match &discover_actions[0] {
            HolePunchAction::SendSignal { payload, .. } => payload.clone(),
            _ => panic!("Expected SendSignal"),
        }
    }

    /// Manager accepting all proposals, with probe and punch threads disabled.
    fn accepting_manager() -> HolePunchManager {
        let mut mgr = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
        mgr.set_policy(HolePunchPolicy::AcceptAll);
        mgr.set_spawn_workers(false);
        mgr
    }

    fn is_msg(action: &HolePunchManagerAction, expected: u16) -> bool {
        matches!(action, HolePunchManagerAction::SendChannelMessage { msgtype, .. } if *msgtype == expected)
    }

    fn reject_reason(actions: &[HolePunchManagerAction]) -> Option<u8> {
        actions.iter().find_map(|a| match a {
            HolePunchManagerAction::SendChannelMessage {
                msgtype, payload, ..
            } if *msgtype == UPGRADE_REJECT => {
                let (val, _) = rns_core::msgpack::unpack(payload).ok()?;
                val.map_get("r").and_then(|v| v.as_uint()).map(|r| r as u8)
            }
            _ => None,
        })
    }

    #[test]
    fn request_with_private_initiator_endpoint_is_refused() {
        for initiator in [
            "192.168.1.10:41000",
            "127.0.0.1:41000",
            "[::ffff:10.0.0.1]:41000",
        ] {
            let mut mgr = accepting_manager();
            let (tx, _rx) = make_tx();
            let link_id = [0x51; 16];
            let payload = make_request(link_id, "1.2.3.4:4343", initiator, 0x42);
            let (handled, actions) = mgr.handle_signal(
                link_id,
                UPGRADE_REQUEST,
                payload,
                Some(&test_derived_key()),
                &tx,
            );
            assert!(handled);
            assert_eq!(actions.len(), 1, "{initiator}");
            assert_eq!(reject_reason(&actions), Some(REJECT_POLICY), "{initiator}");
            assert_eq!(mgr.session_count(), 0, "{initiator}");
        }
    }

    #[test]
    fn request_with_private_facilitator_is_refused() {
        let mut mgr = accepting_manager();
        let (tx, _rx) = make_tx();
        let link_id = [0x52; 16];
        let payload = make_request(link_id, "10.0.0.1:4343", "1.2.3.4:41000", 0x42);
        let (_, actions) = mgr.handle_signal(
            link_id,
            UPGRADE_REQUEST,
            payload,
            Some(&test_derived_key()),
            &tx,
        );
        assert_eq!(reject_reason(&actions), Some(REJECT_POLICY));
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn private_endpoints_accepted_when_allowed() {
        let mut mgr = accepting_manager();
        mgr.set_allow_private_endpoints(true);
        let (tx, _rx) = make_tx();
        let link_id = [0x53; 16];
        let payload = make_request(link_id, "192.168.1.1:4343", "192.168.1.10:41000", 0x42);
        let (_, actions) = mgr.handle_signal(
            link_id,
            UPGRADE_REQUEST,
            payload,
            Some(&test_derived_key()),
            &tx,
        );
        assert!(actions.iter().any(|a| is_msg(a, UPGRADE_ACCEPT)));
        assert_eq!(mgr.session_count(), 1);
    }

    #[test]
    fn ready_with_private_responder_endpoint_does_not_punch() {
        let mut mgr = accepting_manager();
        let (tx, _rx) = make_tx();
        let link_id = [0x54; 16];
        let mut rng = make_rng(0x42);
        mgr.propose(link_id, &test_derived_key(), &mut rng, &tx);
        let session_id = *mgr.link_to_session.get(&link_id).unwrap();
        let probe_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let request = mgr.handle_probe_result(
            link_id,
            session_id,
            "1.2.3.4:41000".parse().unwrap(),
            probe_socket,
            make_probe_addr(),
        );
        assert!(request.iter().any(|a| is_msg(a, UPGRADE_REQUEST)));

        // Responder side builds ACCEPT and READY naming a private endpoint.
        let request_payload = match &request[0] {
            HolePunchManagerAction::SendChannelMessage { payload, .. } => payload.clone(),
            _ => unreachable!(),
        };
        let mut responder = HolePunchEngine::new(link_id, None, ProbeProtocol::Rnsp);
        let r_actions = responder
            .handle_signal(
                UPGRADE_REQUEST,
                &request_payload,
                Some(&test_derived_key()),
                1.0,
            )
            .unwrap();
        let accept = match &r_actions[0] {
            HolePunchAction::SendSignal { payload, .. } => payload.clone(),
            _ => unreachable!(),
        };
        let ready_actions = responder
            .endpoints_discovered(ep("10.1.2.3:52000"), 2.0)
            .unwrap();
        let ready = match &ready_actions[0] {
            HolePunchAction::SendSignal { payload, .. } => payload.clone(),
            _ => unreachable!(),
        };

        mgr.handle_signal(link_id, UPGRADE_ACCEPT, accept, None, &tx);
        let (_, actions) = mgr.handle_signal(link_id, UPGRADE_READY, ready, None, &tx);
        assert!(actions
            .iter()
            .any(|a| matches!(a, HolePunchManagerAction::DirectConnectFailed { .. })));
        let session = mgr.sessions.get(&session_id).unwrap();
        assert!(session.punch_target.is_none());
        assert!(session.punch_handle.is_none());
        assert_eq!(session.engine.state(), HolePunchState::Failed);
    }

    #[test]
    fn second_request_on_link_inside_window_is_refused() {
        let mut mgr = accepting_manager();
        let (tx, _rx) = make_tx();
        let link_id = [0x55; 16];
        let t0 = Instant::now();

        let first = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x01);
        let (_, actions) = mgr.handle_signal_at(
            link_id,
            UPGRADE_REQUEST,
            first,
            Some(&test_derived_key()),
            &tx,
            t0,
        );
        assert!(actions.iter().any(|a| is_msg(a, UPGRADE_ACCEPT)));

        let second = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x02);
        let (_, actions) = mgr.handle_signal_at(
            link_id,
            UPGRADE_REQUEST,
            second,
            Some(&test_derived_key()),
            &tx,
            t0 + std::time::Duration::from_secs(30),
        );
        assert_eq!(reject_reason(&actions), Some(REJECT_BUSY));
        assert_eq!(mgr.session_count(), 1);

        let third = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x03);
        let (_, actions) = mgr.handle_signal_at(
            link_id,
            UPGRADE_REQUEST,
            third,
            Some(&test_derived_key()),
            &tx,
            t0 + INBOUND_REQUEST_WINDOW,
        );
        assert!(actions.iter().any(|a| is_msg(a, UPGRADE_ACCEPT)));
        // The new session replaced the earlier one on this link.
        assert_eq!(mgr.session_count(), 1);
    }

    #[test]
    fn concurrent_inbound_sessions_are_capped() {
        let mut mgr = accepting_manager();
        let (tx, _rx) = make_tx();
        for i in 0..MAX_CONCURRENT_SESSIONS as u8 {
            let link_id = [0x60 + i; 16];
            let initiator = format!("5.6.7.{}:41000", 10 + i);
            let payload = make_request(link_id, "1.2.3.4:4343", &initiator, i);
            let (_, actions) = mgr.handle_signal(
                link_id,
                UPGRADE_REQUEST,
                payload,
                Some(&test_derived_key()),
                &tx,
            );
            assert!(actions.iter().any(|a| is_msg(a, UPGRADE_ACCEPT)));
        }
        assert_eq!(mgr.session_count(), MAX_CONCURRENT_SESSIONS);

        let link_id = [0x70; 16];
        let payload = make_request(link_id, "1.2.3.4:4343", "5.6.7.99:41000", 0x70);
        let (_, actions) = mgr.handle_signal(
            link_id,
            UPGRADE_REQUEST,
            payload,
            Some(&test_derived_key()),
            &tx,
        );
        assert_eq!(reject_reason(&actions), Some(REJECT_BUSY));
        assert_eq!(mgr.session_count(), MAX_CONCURRENT_SESSIONS);

        // Closing a link frees a slot.
        mgr.link_closed(&[0x60; 16]);
        let link_id = [0x71; 16];
        let payload = make_request(link_id, "1.2.3.4:4343", "5.6.7.99:41000", 0x71);
        let (_, actions) = mgr.handle_signal(
            link_id,
            UPGRADE_REQUEST,
            payload,
            Some(&test_derived_key()),
            &tx,
        );
        assert!(actions.iter().any(|a| is_msg(a, UPGRADE_ACCEPT)));
    }

    #[test]
    fn second_session_toward_same_target_is_refused() {
        let mut mgr = accepting_manager();
        let (tx, _rx) = make_tx();
        let a = make_request([0x81; 16], "1.2.3.4:4343", "5.6.7.8:41000", 0x01);
        let (_, actions) = mgr.handle_signal(
            [0x81; 16],
            UPGRADE_REQUEST,
            a,
            Some(&test_derived_key()),
            &tx,
        );
        assert!(actions.iter().any(|a| is_msg(a, UPGRADE_ACCEPT)));

        let b = make_request([0x82; 16], "1.2.3.4:4343", "5.6.7.8:41000", 0x02);
        let (_, actions) = mgr.handle_signal(
            [0x82; 16],
            UPGRADE_REQUEST,
            b,
            Some(&test_derived_key()),
            &tx,
        );
        assert_eq!(reject_reason(&actions), Some(REJECT_BUSY));
        assert_eq!(mgr.session_count(), 1);
    }

    #[test]
    fn test_propose_creates_session_in_discovering() {
        let mut mgr = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
        let link_id = [0x11; 16];
        let mut rng = make_rng(0x42);
        let (tx, _rx) = make_tx();

        let actions = mgr.propose(link_id, &test_derived_key(), &mut rng, &tx);

        assert_eq!(mgr.session_count(), 1);
        assert!(mgr.has_session_for_link(&link_id));
        // No SendChannelMessage yet — initiator probes first
        assert!(actions.is_empty());
    }

    #[test]
    fn test_propose_rate_limited() {
        let mut mgr = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
        let link_id = [0x22; 16];
        let mut rng = make_rng(0x42);
        let (tx, _rx) = make_tx();

        mgr.propose(link_id, &test_derived_key(), &mut rng, &tx);

        // Immediate second proposal should be rate-limited
        let actions = mgr.propose(link_id, &test_derived_key(), &mut rng, &tx);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_reject_policy_sends_reject() {
        let mut mgr = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
        mgr.set_policy(HolePunchPolicy::Reject);

        let link_id = [0x33; 16];
        let mut rng = make_rng(0x42);
        let (tx, _rx) = make_tx();

        // Build a proper UPGRADE_REQUEST payload
        let mut proposer = HolePunchEngine::new(
            link_id,
            Some(Endpoint {
                addr: vec![127, 0, 0, 1],
                port: 4343,
            }),
            ProbeProtocol::Rnsp,
        );
        proposer
            .propose(&test_derived_key(), 100.0, &mut rng)
            .unwrap();
        let discover_actions = proposer
            .endpoints_discovered(
                Endpoint {
                    addr: vec![1, 2, 3, 4],
                    port: 41000,
                },
                101.0,
            )
            .unwrap();
        let request_payload = match &discover_actions[0] {
            HolePunchAction::SendSignal { payload, .. } => payload.clone(),
            _ => panic!("Expected SendSignal"),
        };

        let (handled, actions) = mgr.handle_signal(
            link_id,
            UPGRADE_REQUEST,
            request_payload,
            Some(&test_derived_key()),
            &tx,
        );

        assert!(handled);
        assert_eq!(actions.len(), 1);
        assert!(
            matches!(&actions[0], HolePunchManagerAction::SendChannelMessage { msgtype, .. } if *msgtype == UPGRADE_REJECT)
        );
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_accept_policy_creates_session() {
        // Acceptable (public) endpoints still proceed under AcceptAll.
        let mut mgr = accepting_manager();

        let link_id = [0x44; 16];
        let (tx, _rx) = make_tx();

        let request_payload = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x42);

        let (handled, actions) = mgr.handle_signal(
            link_id,
            UPGRADE_REQUEST,
            request_payload,
            Some(&test_derived_key()),
            &tx,
        );

        assert!(handled);
        // Should send UPGRADE_ACCEPT
        assert!(actions.iter().any(|a| matches!(a, HolePunchManagerAction::SendChannelMessage { msgtype, .. } if *msgtype == UPGRADE_ACCEPT)));
        assert_eq!(mgr.session_count(), 1);
        assert!(mgr.has_session_for_link(&link_id));
    }

    #[test]
    fn test_non_holepunch_message_not_handled() {
        let mut mgr = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None);
        let (tx, _rx) = make_tx();

        let (handled, actions) = mgr.handle_signal([0x55; 16], 0x0001, vec![1, 2, 3], None, &tx);

        assert!(!handled);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_link_closed_cleans_up() {
        let mut mgr = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
        let link_id = [0x66; 16];
        let mut rng = make_rng(0x42);
        let (tx, _rx) = make_tx();

        mgr.propose(link_id, &test_derived_key(), &mut rng, &tx);
        assert_eq!(mgr.session_count(), 1);

        mgr.link_closed(&link_id);
        assert_eq!(mgr.session_count(), 0);
        assert!(!mgr.has_session_for_link(&link_id));
    }

    #[test]
    fn test_abort_all_sessions_cleans_up_all_links() {
        let mut mgr = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
        let mut rng = make_rng(0x55);
        let (tx, _rx) = make_tx();
        let link_a = [0x11; 16];
        let link_b = [0x22; 16];

        mgr.propose(link_a, &test_derived_key(), &mut rng, &tx);
        mgr.propose(link_b, &[0xBB; 32], &mut rng, &tx);
        assert!(mgr.session_count() >= 1);

        mgr.abort_all_sessions();

        assert_eq!(mgr.session_count(), 0);
        assert!(!mgr.has_session_for_link(&link_a));
        assert!(!mgr.has_session_for_link(&link_b));
    }

    #[test]
    fn test_handle_probe_failed_with_session() {
        let mut mgr = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
        let link_id = [0x77; 16];
        let mut rng = make_rng(0x42);
        let (tx, _rx) = make_tx();

        mgr.propose(link_id, &test_derived_key(), &mut rng, &tx);
        let session_id = *mgr.link_to_session.get(&link_id).unwrap();

        let actions = mgr.handle_probe_failed(link_id, session_id);
        assert_eq!(actions.len(), 1);
        assert!(
            matches!(&actions[0], HolePunchManagerAction::DirectConnectFailed { reason, .. }
            if *reason == rns_core::holepunch::types::FAIL_PROBE)
        );
    }

    #[test]
    fn test_handle_probe_failed_without_session() {
        let mut mgr = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None);

        let actions = mgr.handle_probe_failed([0x88; 16], [0x99; 16]);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_handle_probe_result_initiator_sends_request() {
        let mut mgr = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
        let link_id = [0xAA; 16];
        let mut rng = make_rng(0x42);
        let (tx, _rx) = make_tx();

        // Propose creates session in Discovering state
        mgr.propose(link_id, &test_derived_key(), &mut rng, &tx);
        let session_id = *mgr.link_to_session.get(&link_id).unwrap();

        // Probe result arrives — initiator should send UPGRADE_REQUEST
        let probe_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let observed: SocketAddr = "1.2.3.4:41000".parse().unwrap();
        let actions = mgr.handle_probe_result(
            link_id,
            session_id,
            observed,
            probe_socket,
            make_probe_addr(),
        );

        // Should emit UPGRADE_REQUEST (initiator discovered endpoint -> sends request)
        assert!(actions.iter().any(|a| matches!(a,
            HolePunchManagerAction::SendChannelMessage { msgtype, .. }
            if *msgtype == UPGRADE_REQUEST
        )));
    }

    #[test]
    fn test_handle_probe_result_responder_sends_ready() {
        let mut mgr = accepting_manager();
        let link_id = [0xBB; 16];
        let (tx, _rx) = make_tx();

        // Build UPGRADE_REQUEST from an initiator
        let request_payload = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x42);

        // Responder receives UPGRADE_REQUEST (session enters Discovering)
        mgr.handle_signal(
            link_id,
            UPGRADE_REQUEST,
            request_payload,
            Some(&test_derived_key()),
            &tx,
        );
        let session_id = *mgr.link_to_session.get(&link_id).unwrap();

        // Responder's probe result arrives — should send UPGRADE_READY
        let probe_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let observed: SocketAddr = "5.6.7.8:52000".parse().unwrap();
        let actions = mgr.handle_probe_result(
            link_id,
            session_id,
            observed,
            probe_socket,
            make_probe_addr(),
        );

        assert!(actions.iter().any(|a| matches!(a,
            HolePunchManagerAction::SendChannelMessage { msgtype, .. }
            if *msgtype == UPGRADE_READY
        )));
        // The responder punches toward the initiator endpoint from the request.
        let session = mgr.sessions.get(&session_id).unwrap();
        assert_eq!(session.punch_target, Some("5.6.7.8:41000".parse().unwrap()));
    }

    #[test]
    fn test_endpoint_to_socket_addr_ipv4() {
        let ep = Endpoint {
            addr: vec![10, 0, 0, 1],
            port: 8080,
        };
        let addr = endpoint_to_socket_addr(&ep).unwrap();
        assert_eq!(addr, "10.0.0.1:8080".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_endpoint_to_socket_addr_ipv6() {
        let ep = Endpoint {
            addr: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port: 9090,
        };
        let addr = endpoint_to_socket_addr(&ep).unwrap();
        assert_eq!(addr, "[::1]:9090".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_endpoint_to_socket_addr_invalid() {
        let ep = Endpoint {
            addr: vec![1, 2, 3],
            port: 80,
        };
        assert!(endpoint_to_socket_addr(&ep).is_none());
    }

    #[test]
    fn test_policy_default_is_identified_only() {
        let mgr = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None);
        assert_eq!(mgr.policy(), HolePunchPolicy::IdentifiedOnly);
        assert_eq!(HolePunchPolicy::default(), HolePunchPolicy::IdentifiedOnly);
        assert!(!mgr.allow_private_endpoints());
    }

    #[test]
    fn test_set_policy() {
        let mut mgr = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None);
        mgr.set_policy(HolePunchPolicy::Reject);
        assert_eq!(mgr.policy(), HolePunchPolicy::Reject);
    }

    #[test]
    fn test_is_holepunch_message() {
        assert!(HolePunchManager::is_holepunch_message(0xFE00));
        assert!(HolePunchManager::is_holepunch_message(0xFE04));
        assert!(!HolePunchManager::is_holepunch_message(0x0000));
        assert!(!HolePunchManager::is_holepunch_message(0xFE05));
    }

    #[test]
    fn test_tick_empty_is_noop() {
        let mut mgr = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None);
        let (tx, _rx) = make_tx();
        let actions = mgr.tick(&tx);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_propose_without_probe_addr() {
        let mut mgr = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None); // No probe addr
        let link_id = [0xCC; 16];
        let mut rng = make_rng(0x42);
        let (tx, _rx) = make_tx();

        // Should fail — initiator needs a probe address
        let actions = mgr.propose(link_id, &test_derived_key(), &mut rng, &tx);
        assert!(actions.is_empty());
        // No session created since propose() failed
        assert_eq!(mgr.session_count(), 0);
    }
}
