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

use rns_core::holepunch::{
    HolePunchAction, HolePunchEngine, HolePunchState, Endpoint,
    UPGRADE_REQUEST, REJECT_POLICY,
};
use rns_core::holepunch::types::is_holepunch_msgtype;

use crate::event::{Event, EventSender};
use crate::time;

use super::probe;
use super::puncher::{self, PunchHandle};
use super::udp_direct;

/// Policy for handling incoming direct-connect proposals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolePunchPolicy {
    /// Reject all proposals.
    Reject,
    /// Accept all proposals automatically.
    AcceptAll,
    /// Ask the application callback.
    AskApp,
}

impl Default for HolePunchPolicy {
    fn default() -> Self {
        HolePunchPolicy::AcceptAll
    }
}

/// A single hole-punch session's networking state.
struct HolePunchSession {
    engine: HolePunchEngine,
    /// The UDP socket used for probing and punching (same NAT mapping).
    socket: Option<UdpSocket>,
    /// Handle to the running punch thread.
    punch_handle: Option<PunchHandle>,
    /// Last proposal time for rate limiting.
    last_proposal: f64,
}

/// Manages all hole-punch sessions.
pub struct HolePunchManager {
    sessions: HashMap<[u8; 16], HolePunchSession>,  // session_id -> session
    link_to_session: HashMap<[u8; 16], [u8; 16]>,   // link_id -> session_id
    policy: HolePunchPolicy,
    /// Backbone probe service address (if configured).
    probe_addr: Option<SocketAddr>,
    /// Next available interface ID counter for direct interfaces.
    next_interface_id: u64,
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
    },
    /// Direct connection failed.
    DirectConnectFailed {
        link_id: [u8; 16],
        session_id: [u8; 16],
        reason: u8,
    },
}

impl HolePunchManager {
    pub fn new(probe_addr: Option<SocketAddr>) -> Self {
        HolePunchManager {
            sessions: HashMap::new(),
            link_to_session: HashMap::new(),
            policy: HolePunchPolicy::default(),
            probe_addr,
            next_interface_id: 50000, // start high to avoid collision with regular interfaces
        }
    }

    pub fn set_policy(&mut self, policy: HolePunchPolicy) {
        self.policy = policy;
    }

    pub fn policy(&self) -> HolePunchPolicy {
        self.policy
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
                    log::debug!("Hole punch proposal rate limited for link {:02x?}", &link_id[..4]);
                    return Vec::new();
                }
            }
        }

        // Clean up any existing session for this link
        if let Some(old_session_id) = self.link_to_session.remove(&link_id) {
            self.sessions.remove(&old_session_id);
        }

        let probe_endpoint = self.probe_addr.map(|addr| Endpoint {
            addr: match addr {
                SocketAddr::V4(v4) => v4.ip().octets().to_vec(),
                SocketAddr::V6(v6) => v6.ip().octets().to_vec(),
            },
            port: addr.port(),
        });

        let mut engine = HolePunchEngine::new(link_id, probe_endpoint);
        let actions = match engine.propose(derived_key, now, rng) {
            Ok(a) => a,
            Err(e) => {
                log::warn!("Failed to propose hole punch: {}", e);
                return Vec::new();
            }
        };

        let session_id = *engine.session_id();
        self.link_to_session.insert(link_id, session_id);
        self.sessions.insert(session_id, HolePunchSession {
            engine,
            socket: None,
            punch_handle: None,
            last_proposal: now,
        });

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
                HolePunchPolicy::AskApp => {
                    // For now, accept — full callback integration is in the driver
                }
            }

            // Create engine for responder (no probe_addr needed — facilitator comes from request)
            let mut engine = HolePunchEngine::new(link_id, None);
            let now = time::now();
            let actions = match engine.handle_signal(msgtype, &payload, derived_key, now) {
                Ok(a) => a,
                Err(e) => {
                    log::warn!("Error handling UPGRADE_REQUEST: {}", e);
                    return (true, Vec::new());
                }
            };

            let session_id = *engine.session_id();
            self.link_to_session.insert(link_id, session_id);
            self.sessions.insert(session_id, HolePunchSession {
                engine,
                socket: None,
                punch_handle: None,
                last_proposal: now,
            });

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
        let actions = match session.engine.handle_signal(msgtype, &payload, derived_key, now) {
            Ok(a) => a,
            Err(e) => {
                log::warn!("Error handling signal 0x{:04x}: {}", msgtype, e);
                return (true, Vec::new());
            }
        };

        let mgr_actions = convert_engine_actions(link_id, &actions);

        // Check if engine now wants to start punching
        self.start_punch_from_actions(&session_id, &actions);

        (true, mgr_actions)
    }

    /// Tick all sessions for timeout checks.
    pub fn tick(&mut self, tx: &EventSender) -> Vec<HolePunchManagerAction> {
        let now = time::now();
        let mut all_actions = Vec::new();

        // Build a snapshot of session IDs and their corresponding link IDs
        let session_link_pairs: Vec<([u8; 16], Option<[u8; 16]>)> = self.sessions.keys()
            .map(|sid| {
                let link_id = self.link_to_session.iter()
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
        }
        let mut completions: Vec<PunchCompletion> = Vec::new();

        for (session_id, link_id) in &session_link_pairs {
            if let Some(session) = self.sessions.get_mut(session_id) {
                let punch_done = session.punch_handle.as_ref()
                    .map(|h| !h.is_running())
                    .unwrap_or(false);

                if punch_done {
                    let succeeded = session.punch_handle.as_ref()
                        .map(|h| h.succeeded())
                        .unwrap_or(false);

                    if let Some(link_id) = link_id {
                        if succeeded {
                            if let Some(handle) = session.punch_handle.take() {
                                if let Some(result) = handle.join() {
                                    completions.push(PunchCompletion {
                                        session_id: *session_id,
                                        link_id: *link_id,
                                        succeeded: true,
                                        socket: Some(result.socket),
                                        peer_addr: Some(result.peer_addr),
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
                    let interface_id = rns_core::transport::types::InterfaceId(self.next_interface_id);
                    self.next_interface_id += 1;

                    let mut iface_ok = false;
                    if let Some(session) = self.sessions.get(&completion.session_id) {
                        let session_id = *session.engine.session_id();
                        let punch_token = *session.engine.punch_token();
                        match udp_direct::start_direct_interface(
                            socket, peer_addr, interface_id, session_id, punch_token, tx.clone(),
                        ) {
                            Ok((writer, info)) => {
                                log::info!("Direct UDP interface registered: {}", info.name);
                                let _ = tx.send(Event::InterfaceUp(interface_id, Some(writer), Some(info)));
                                iface_ok = true;
                            }
                            Err(e) => {
                                log::warn!("Failed to start direct interface: {}", e);
                            }
                        }
                    }

                    // Notify engine of success
                    if let Some(session) = self.sessions.get_mut(&completion.session_id) {
                        let engine_actions = match session.engine.punch_succeeded(now) {
                            Ok(a) => a,
                            Err(_) => Vec::new(),
                        };
                        for action in engine_actions {
                            match action {
                                HolePunchAction::Succeeded { session_id } if iface_ok => {
                                    all_actions.push(HolePunchManagerAction::DirectConnectEstablished {
                                        link_id: completion.link_id,
                                        session_id,
                                        interface_id,
                                    });
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
                    let engine_actions = match session.engine.punch_failed(now) {
                        Ok(a) => a,
                        Err(_) => Vec::new(),
                    };
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
        let failed_sessions: Vec<[u8; 16]> = self.sessions.iter()
            .filter(|(_, s)| s.engine.state() == HolePunchState::Failed)
            .map(|(id, _)| *id)
            .collect();

        for session_id in failed_sessions {
            self.sessions.remove(&session_id);
            self.link_to_session.retain(|_, v| *v != session_id);
        }

        all_actions
    }

    /// Called when a link is closed — clean up any associated session.
    pub fn link_closed(&mut self, link_id: &[u8; 16]) {
        if let Some(session_id) = self.link_to_session.remove(link_id) {
            if let Some(mut session) = self.sessions.remove(&session_id) {
                if let Some(handle) = session.punch_handle.take() {
                    handle.cancel();
                }
            }
        }
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
            if let HolePunchAction::DiscoverEndpoints { probe_addr } = action {
                let session_id = match self.link_to_session.get(&link_id) {
                    Some(s) => *s,
                    None => continue,
                };

                let probe_socket_addr = match endpoint_to_socket_addr(probe_addr) {
                    Some(a) => a,
                    None => {
                        log::warn!("Invalid probe endpoint: {:?}", probe_addr);
                        continue;
                    }
                };

                let tx_clone = tx.clone();
                let session_id_copy = session_id;

                if let Err(e) = thread::Builder::new()
                    .name("probe-worker".into())
                    .spawn(move || {
                        run_probe_worker(probe_socket_addr, session_id_copy, link_id, tx_clone);
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
        session_id: &[u8; 16],
        actions: &[HolePunchAction],
    ) {
        for action in actions {
            if let HolePunchAction::StartUdpPunch { peer_public, punch_token, session_id: sid } = action {
                self.start_punch_for_session(session_id, peer_public, punch_token, sid);
            }
        }
    }

    fn start_punch_for_session(
        &mut self,
        session_id: &[u8; 16],
        peer_public: &Endpoint,
        punch_token: &[u8; 32],
        _engine_session_id: &[u8; 16],
    ) {
        let session = match self.sessions.get_mut(session_id) {
            Some(s) => s,
            None => return,
        };

        if session.punch_handle.is_some() {
            return; // Already punching
        }

        let socket = match session.socket.take() {
            Some(s) => s,
            None => {
                log::warn!("No socket available for punching");
                return;
            }
        };

        let peer_addr = match endpoint_to_socket_addr(peer_public) {
            Some(a) => a,
            None => {
                log::warn!("Invalid peer endpoint for punch: {:?}", peer_public);
                session.socket = Some(socket);
                return;
            }
        };

        let punch_token_copy = *punch_token;
        let session_id_copy = *session.engine.session_id();

        log::info!(
            "Starting UDP hole punch for session {:02x?} to {}",
            &session_id_copy[..4], peer_addr
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
    }

    /// Called when a probe result arrives from the worker thread.
    pub fn handle_probe_result(
        &mut self,
        link_id: [u8; 16],
        session_id: [u8; 16],
        observed_addr: SocketAddr,
        socket: UdpSocket,
    ) -> Vec<HolePunchManagerAction> {
        let session = match self.sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return Vec::new(),
        };

        // Store the socket for reuse during punching (same NAT mapping)
        session.socket = Some(socket);

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

        let mgr_actions = convert_engine_actions(link_id, &actions);

        // Check if engine now wants to start punching (responder after discovery)
        let should_punch = actions.iter().any(|a| matches!(a, HolePunchAction::StartUdpPunch { .. }));
        if should_punch {
            // Need to extract punch params and start
            for action in &actions {
                if let HolePunchAction::StartUdpPunch { peer_public, punch_token, session_id: sid } = action {
                    self.start_punch_for_session(&session_id, peer_public, punch_token, sid);
                }
            }
        }

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
    probe_addr: SocketAddr,
    session_id: [u8; 16],
    link_id: [u8; 16],
    tx: EventSender,
) {
    match probe::probe_endpoint(probe_addr, None, std::time::Duration::from_secs(3)) {
        Ok((observed, socket)) => {
            log::info!(
                "Probe discovered endpoint: {} for session {:02x?}",
                observed, &session_id[..4]
            );
            let _ = tx.send(Event::HolePunchProbeResult {
                link_id,
                session_id,
                observed_addr: observed,
                socket,
            });
        }
        Err(e) => {
            log::warn!("Probe failed for session {:02x?}: {}", &session_id[..4], e);
            let _ = tx.send(Event::HolePunchProbeFailed {
                link_id,
                session_id,
            });
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
            HolePunchAction::SendSignal { link_id, msgtype, payload } => {
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

/// Number of active sessions (for testing).
#[cfg(test)]
impl HolePunchManager {
    fn session_count(&self) -> usize {
        self.sessions.len()
    }

    fn has_session_for_link(&self, link_id: &[u8; 16]) -> bool {
        self.link_to_session.contains_key(link_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::FixedRng;
    use rns_core::holepunch::{UPGRADE_ACCEPT, UPGRADE_REJECT, UPGRADE_READY};

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

    #[test]
    fn test_propose_creates_session_in_discovering() {
        let mut mgr = HolePunchManager::new(Some(make_probe_addr()));
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
        let mut mgr = HolePunchManager::new(Some(make_probe_addr()));
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
        let mut mgr = HolePunchManager::new(Some(make_probe_addr()));
        mgr.set_policy(HolePunchPolicy::Reject);

        let link_id = [0x33; 16];
        let mut rng = make_rng(0x42);
        let (tx, _rx) = make_tx();

        // Build a proper UPGRADE_REQUEST payload
        let mut proposer = HolePunchEngine::new(link_id, Some(Endpoint { addr: vec![127, 0, 0, 1], port: 4343 }));
        proposer.propose(&test_derived_key(), 100.0, &mut rng).unwrap();
        let discover_actions = proposer.endpoints_discovered(
            Endpoint { addr: vec![1, 2, 3, 4], port: 41000 }, 101.0
        ).unwrap();
        let request_payload = match &discover_actions[0] {
            HolePunchAction::SendSignal { payload, .. } => payload.clone(),
            _ => panic!("Expected SendSignal"),
        };

        let (handled, actions) = mgr.handle_signal(
            link_id, UPGRADE_REQUEST, request_payload, Some(&test_derived_key()), &tx,
        );

        assert!(handled);
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], HolePunchManagerAction::SendChannelMessage { msgtype, .. } if *msgtype == UPGRADE_REJECT));
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_accept_policy_creates_session() {
        let mut mgr = HolePunchManager::new(Some(make_probe_addr()));
        mgr.set_policy(HolePunchPolicy::AcceptAll);

        let link_id = [0x44; 16];
        let mut rng = make_rng(0x42);
        let (tx, _rx) = make_tx();

        // Build UPGRADE_REQUEST
        let mut proposer = HolePunchEngine::new(link_id, Some(Endpoint { addr: vec![127, 0, 0, 1], port: 4343 }));
        proposer.propose(&test_derived_key(), 100.0, &mut rng).unwrap();
        let discover_actions = proposer.endpoints_discovered(
            Endpoint { addr: vec![1, 2, 3, 4], port: 41000 }, 101.0
        ).unwrap();
        let request_payload = match &discover_actions[0] {
            HolePunchAction::SendSignal { payload, .. } => payload.clone(),
            _ => panic!("Expected SendSignal"),
        };

        let (handled, actions) = mgr.handle_signal(
            link_id, UPGRADE_REQUEST, request_payload, Some(&test_derived_key()), &tx,
        );

        assert!(handled);
        // Should send UPGRADE_ACCEPT
        assert!(actions.iter().any(|a| matches!(a, HolePunchManagerAction::SendChannelMessage { msgtype, .. } if *msgtype == UPGRADE_ACCEPT)));
        assert_eq!(mgr.session_count(), 1);
        assert!(mgr.has_session_for_link(&link_id));
    }

    #[test]
    fn test_non_holepunch_message_not_handled() {
        let mut mgr = HolePunchManager::new(None);
        let (tx, _rx) = make_tx();

        let (handled, actions) = mgr.handle_signal(
            [0x55; 16], 0x0001, vec![1, 2, 3], None, &tx,
        );

        assert!(!handled);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_link_closed_cleans_up() {
        let mut mgr = HolePunchManager::new(Some(make_probe_addr()));
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
    fn test_handle_probe_failed_with_session() {
        let mut mgr = HolePunchManager::new(Some(make_probe_addr()));
        let link_id = [0x77; 16];
        let mut rng = make_rng(0x42);
        let (tx, _rx) = make_tx();

        mgr.propose(link_id, &test_derived_key(), &mut rng, &tx);
        let session_id = *mgr.link_to_session.get(&link_id).unwrap();

        let actions = mgr.handle_probe_failed(link_id, session_id);
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], HolePunchManagerAction::DirectConnectFailed { reason, .. }
            if *reason == rns_core::holepunch::types::FAIL_PROBE));
    }

    #[test]
    fn test_handle_probe_failed_without_session() {
        let mut mgr = HolePunchManager::new(None);

        let actions = mgr.handle_probe_failed([0x88; 16], [0x99; 16]);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_handle_probe_result_initiator_sends_request() {
        let mut mgr = HolePunchManager::new(Some(make_probe_addr()));
        let link_id = [0xAA; 16];
        let mut rng = make_rng(0x42);
        let (tx, _rx) = make_tx();

        // Propose creates session in Discovering state
        mgr.propose(link_id, &test_derived_key(), &mut rng, &tx);
        let session_id = *mgr.link_to_session.get(&link_id).unwrap();

        // Probe result arrives — initiator should send UPGRADE_REQUEST
        let probe_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let observed: SocketAddr = "1.2.3.4:41000".parse().unwrap();
        let actions = mgr.handle_probe_result(link_id, session_id, observed, probe_socket);

        // Should emit UPGRADE_REQUEST (initiator discovered endpoint -> sends request)
        assert!(actions.iter().any(|a| matches!(a,
            HolePunchManagerAction::SendChannelMessage { msgtype, .. }
            if *msgtype == UPGRADE_REQUEST
        )));
    }

    #[test]
    fn test_handle_probe_result_responder_sends_ready() {
        let mut mgr = HolePunchManager::new(Some(make_probe_addr()));
        let link_id = [0xBB; 16];
        let mut rng = make_rng(0x42);
        let (tx, _rx) = make_tx();

        // Build UPGRADE_REQUEST from an initiator
        let mut proposer = HolePunchEngine::new(link_id, Some(Endpoint { addr: vec![127, 0, 0, 1], port: 4343 }));
        proposer.propose(&test_derived_key(), 100.0, &mut rng).unwrap();
        let discover_actions = proposer.endpoints_discovered(
            Endpoint { addr: vec![1, 2, 3, 4], port: 41000 }, 101.0
        ).unwrap();
        let request_payload = match &discover_actions[0] {
            HolePunchAction::SendSignal { payload, .. } => payload.clone(),
            _ => panic!("Expected SendSignal"),
        };

        // Responder receives UPGRADE_REQUEST (session enters Discovering)
        mgr.handle_signal(link_id, UPGRADE_REQUEST, request_payload, Some(&test_derived_key()), &tx);
        let session_id = *mgr.link_to_session.get(&link_id).unwrap();

        // Responder's probe result arrives — should send UPGRADE_READY
        let probe_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let observed: SocketAddr = "5.6.7.8:52000".parse().unwrap();
        let actions = mgr.handle_probe_result(link_id, session_id, observed, probe_socket);

        assert!(actions.iter().any(|a| matches!(a,
            HolePunchManagerAction::SendChannelMessage { msgtype, .. }
            if *msgtype == UPGRADE_READY
        )));
    }

    #[test]
    fn test_endpoint_to_socket_addr_ipv4() {
        let ep = Endpoint { addr: vec![10, 0, 0, 1], port: 8080 };
        let addr = endpoint_to_socket_addr(&ep).unwrap();
        assert_eq!(addr, "10.0.0.1:8080".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_endpoint_to_socket_addr_ipv6() {
        let ep = Endpoint { addr: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], port: 9090 };
        let addr = endpoint_to_socket_addr(&ep).unwrap();
        assert_eq!(addr, "[::1]:9090".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_endpoint_to_socket_addr_invalid() {
        let ep = Endpoint { addr: vec![1, 2, 3], port: 80 };
        assert!(endpoint_to_socket_addr(&ep).is_none());
    }

    #[test]
    fn test_policy_default_is_accept_all() {
        let mgr = HolePunchManager::new(None);
        assert_eq!(mgr.policy(), HolePunchPolicy::AcceptAll);
    }

    #[test]
    fn test_set_policy() {
        let mut mgr = HolePunchManager::new(None);
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
        let mut mgr = HolePunchManager::new(None);
        let (tx, _rx) = make_tx();
        let actions = mgr.tick(&tx);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_propose_without_probe_addr() {
        let mut mgr = HolePunchManager::new(None); // No probe addr
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
