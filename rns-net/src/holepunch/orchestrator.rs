//! HolePunchManager: orchestrates hole-punch sessions.
//!
//! Bridges the rns-core HolePunchEngine (pure state machine) with networking
//! (probe, punch, direct interface). Lives in the Driver, analogous to LinkManager.
//!
//! Follows the asymmetric protocol from direct-link-protocol.md:
//! - Initiator first asks the peer whether it implements Direct Link (HELLO)
//!   and sends nothing else to a peer that does not answer
//! - Initiator probes STUN, then sends UPGRADE_REQUEST with facilitator + A_pub
//! - Responder accepts, probes facilitator from request, sends UPGRADE_READY with B_pub
//! - Both punch simultaneously

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Instant;

use rns_core::holepunch::types::{is_holepunch_msgtype, HELLO_RETRY_INTERVAL, HELLO_TIMEOUT};
use rns_core::holepunch::{
    Endpoint, HolePunchAction, HolePunchEngine, HolePunchState, ProbeProtocol, HELLO, REJECT_BUSY,
    REJECT_POLICY, REJECT_UNSUPPORTED, UPGRADE_REQUEST,
};

use crate::event::{Event, EventSender};
use crate::time;

use super::admission::{
    endpoint_is_acceptable, InboundRequestLimiter, INBOUND_REQUEST_WINDOW, MAX_CONCURRENT_SESSIONS,
};
use super::canonical;
use super::probe;
use super::puncher::{self, PunchHandle};
use super::udp_direct;

pub use crate::common::event::{DirectReupgradeConfig, HolePunchPolicy};

/// Seconds a closed link's direct interface is kept, so that the link's
/// closing packets still leave on it.
const DIRECT_INTERFACE_RETIRE_DELAY: f64 = 1.0;

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
    /// The facilitator that answered this session's probe, and the
    /// endpoint it saw for us.
    facilitator: Option<SocketAddr>,
    observed: Option<SocketAddr>,
}

impl HolePunchSession {
    fn new(engine: HolePunchEngine, now: f64) -> Self {
        HolePunchSession {
            engine,
            socket: None,
            punch_handle: None,
            last_proposal: now,
            punch_target: None,
            facilitator: None,
            observed: None,
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

/// What is known about a link peer's Direct Link support.
#[derive(Debug, Clone, Copy, PartialEq)]
enum PeerSupport {
    /// The peer answered a `HELLO` or sent signalling itself.
    Supported,
    /// A `HELLO` is out, and a proposal waits for the answer.
    Querying { since: f64, last_sent: f64 },
}

/// The direct interface a link was upgraded to.
#[derive(Debug, Clone)]
struct DirectPath {
    interface_id: rns_core::transport::types::InterfaceId,
    session_id: [u8; 16],
    /// Drops the path's traffic both ways when set (for tests).
    blackhole: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// This side proposed the upgrade.
    initiated: bool,
    /// When the path was established.
    since: f64,
}

/// A link that lost the direct path it proposed, and proposes again.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Reupgrade {
    /// Proposals scheduled since the count last started.
    attempts: u32,
    /// When the next proposal is due, if one is scheduled.
    due: Option<f64>,
    /// A proposal made for it has not had its outcome yet.
    in_flight: bool,
}

/// The delay before re-upgrade proposal number `attempt` (from 0), with
/// `jitter` in `[0, 1)` adding up to a quarter.
fn reupgrade_delay(config: &DirectReupgradeConfig, attempt: u32, jitter: f64) -> f64 {
    let initial = config
        .initial_delay
        .as_secs_f64()
        .max(rns_core::holepunch::types::PROPOSAL_COOLDOWN);
    let max = config.max_delay.as_secs_f64().max(initial);
    let base = (initial * 2f64.powi(attempt.min(32) as i32)).min(max);
    base * (1.0 + 0.25 * jitter.clamp(0.0, 1.0))
}

/// A random number in `[0, 1)`.
fn random_unit() -> f64 {
    use rns_crypto::Rng;
    let mut bytes = [0u8; 4];
    rns_crypto::OsRng.fill_bytes(&mut bytes);
    u32::from_le_bytes(bytes) as f64 / (u32::MAX as f64 + 1.0)
}

/// Manages all hole-punch sessions.
pub struct HolePunchManager {
    sessions: HashMap<[u8; 16], HolePunchSession>, // session_id -> session
    link_to_session: HashMap<[u8; 16], [u8; 16]>,  // link_id -> session_id
    /// Link peers known to implement Direct Link, or being asked.
    peer_support: HashMap<[u8; 16], PeerSupport>,
    /// Links upgraded to a direct interface, which belongs to the link and
    /// goes away with it.
    direct: HashMap<[u8; 16], DirectPath>,
    /// Direct interfaces of closed links, removed once the link's last
    /// packets (its LINKCLOSE) have left: `(link, interface, due)`.
    retiring: Vec<([u8; 16], rns_core::transport::types::InterfaceId, f64)>,
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
    /// UDP ports this node listens on (its probe server), never punched
    /// toward at its own public address.
    own_ports: Vec<u16>,
    /// Identities whose proposals are accepted whatever the policy.
    allowed_identities: Vec<[u8; 16]>,
    /// Paces inbound upgrade requests per link.
    inbound_limiter: InboundRequestLimiter,
    /// Proposing again after a lost direct path.
    reupgrade_config: DirectReupgradeConfig,
    reupgrades: HashMap<[u8; 16], Reupgrade>,
    /// Spawn probe and punch threads (disabled by unit tests).
    spawn_workers: bool,
    /// The driver's queue, for probes and punches run on its loop instead
    /// of threads (see [`crate::engine::FOLD_SERVICES`]).
    event_tx: Option<EventSender>,
}

/// Actions produced by HolePunchManager for the driver to dispatch.
pub enum HolePunchManagerAction {
    /// Send a Direct Link signalling message (kind and body) to the link
    /// peer, in a link packet with `CONTEXT_DIRECT_LINK`.
    SendSignal {
        link_id: [u8; 16],
        msgtype: u8,
        payload: Vec<u8>,
    },
    /// Direct connection established: register the new interface and
    /// route the link over it.
    DirectConnectEstablished {
        link_id: [u8; 16],
        session_id: [u8; 16],
        interface_id: rns_core::transport::types::InterfaceId,
        writer: Box<dyn crate::interface::Writer>,
        info: Box<rns_core::transport::types::InterfaceInfo>,
        /// RTT measured during punch (time from first send to first ACK).
        rtt: f64,
        /// MTU of the direct interface.
        mtu: u32,
        /// Largest link packet the peer accepts on the direct path, if it
        /// advertised one.
        peer_max_packet: Option<u32>,
    },
    /// Remove a direct interface that no longer belongs to a live upgrade
    /// (its link closed, or a newer upgrade replaced it).
    RemoveDirectInterface {
        link_id: [u8; 16],
        interface_id: rns_core::transport::types::InterfaceId,
    },
    /// Propose again on a link that lost its direct path, if it is still
    /// active (see [`DirectReupgradeConfig`]).
    Reupgrade { link_id: [u8; 16] },
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
            peer_support: HashMap::new(),
            direct: HashMap::new(),
            retiring: Vec::new(),
            policy: HolePunchPolicy::default(),
            probe_addrs,
            probe_protocol,
            device,
            underlay_mark: None,
            next_interface_id: 50000, // start high to avoid collision with regular interfaces
            allow_private_endpoints: false,
            own_ports: Vec::new(),
            allowed_identities: Vec::new(),
            inbound_limiter: InboundRequestLimiter::new(INBOUND_REQUEST_WINDOW),
            reupgrade_config: DirectReupgradeConfig::default(),
            reupgrades: HashMap::new(),
            spawn_workers: true,
            event_tx: None,
        }
    }

    /// Replace the probe servers, their protocol and the device probes and
    /// punches are bound to, keeping every other setting.
    pub fn set_probe_config(
        &mut self,
        probe_addrs: Vec<SocketAddr>,
        probe_protocol: ProbeProtocol,
        device: Option<String>,
    ) {
        self.probe_addrs = probe_addrs;
        self.probe_protocol = probe_protocol;
        self.device = device;
    }

    /// Run probes and punches on the loop of the driver that `tx` feeds,
    /// when services are folded.
    pub(crate) fn set_event_sender(&mut self, tx: EventSender) {
        self.event_tx = Some(tx);
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

    /// Identities whose proposals are accepted whatever the policy, once
    /// they have identified on the link.
    pub fn set_allowed_identities(&mut self, identities: Vec<[u8; 16]>) {
        self.allowed_identities = identities;
    }

    /// Whether `identity` is on the allowlist.
    pub fn identity_allowed(&self, identity: &[u8; 16]) -> bool {
        self.allowed_identities.contains(identity)
    }

    /// Accept peer-supplied endpoints in private, shared, link-local,
    /// and unique-local ranges (for LAN-only deployments).
    pub fn set_allow_private_endpoints(&mut self, allow: bool) {
        self.allow_private_endpoints = allow;
    }

    pub fn allow_private_endpoints(&self) -> bool {
        self.allow_private_endpoints
    }

    pub fn set_reupgrade_config(&mut self, config: DirectReupgradeConfig) {
        self.reupgrade_config = config;
        if !config.enabled {
            self.reupgrades.clear();
        }
    }

    pub fn reupgrade_config(&self) -> DirectReupgradeConfig {
        self.reupgrade_config
    }

    /// The link lost the direct path `path`: if this side proposed it,
    /// schedule a proposal again.
    fn direct_path_lost(&mut self, link_id: [u8; 16], path: &DirectPath, now: f64) {
        let config = self.reupgrade_config;
        if !config.enabled
            || config.max_attempts == 0
            || !path.initiated
            || self.probe_addrs.is_empty()
        {
            self.reupgrades.remove(&link_id);
            return;
        }
        let entry = self.reupgrades.entry(link_id).or_insert(Reupgrade {
            attempts: 0,
            due: None,
            in_flight: false,
        });
        // A path that lasted a while starts the count again.
        if now - path.since >= config.max_delay.as_secs_f64() {
            entry.attempts = 0;
        }
        self.schedule_reupgrade(link_id, now);
    }

    /// Schedule the link's next re-upgrade proposal, or give up after the
    /// last one.
    fn schedule_reupgrade(&mut self, link_id: [u8; 16], now: f64) {
        let config = self.reupgrade_config;
        let Some(entry) = self.reupgrades.get_mut(&link_id) else {
            return;
        };
        if entry.attempts >= config.max_attempts {
            log::info!(
                "Giving up re-upgrading link {:02x?} after {} attempts",
                &link_id[..4],
                entry.attempts
            );
            self.reupgrades.remove(&link_id);
            return;
        }
        let delay = reupgrade_delay(&config, entry.attempts, random_unit());
        entry.attempts += 1;
        entry.due = Some(now + delay);
        entry.in_flight = false;
        log::debug!(
            "Re-upgrading link {:02x?} in {:.0} s (attempt {} of {})",
            &link_id[..4],
            delay,
            entry.attempts,
            config.max_attempts
        );
    }

    /// A Direct Link attempt on the link failed: if it was a re-upgrade,
    /// try again later, unless the peer refused by policy or does not
    /// answer the capability check.
    pub fn reupgrade_failed(&mut self, link_id: [u8; 16], reason: u8) {
        if !self
            .reupgrades
            .get(&link_id)
            .is_some_and(|entry| entry.in_flight)
        {
            return;
        }
        if self.probe_addrs.is_empty() {
            self.reupgrades.remove(&link_id);
            return;
        }
        if matches!(reason, REJECT_POLICY | REJECT_UNSUPPORTED) {
            log::info!(
                "Not re-upgrading link {:02x?}: the peer refused (reason {})",
                &link_id[..4],
                reason
            );
            self.reupgrades.remove(&link_id);
            return;
        }
        self.schedule_reupgrade(link_id, time::now());
    }

    /// Stop re-upgrading the link (it is no longer active).
    pub fn cancel_reupgrade(&mut self, link_id: &[u8; 16]) {
        self.reupgrades.remove(link_id);
    }

    /// UDP ports this node listens on, which it never punches toward at
    /// its own public address.
    pub fn set_own_listen_ports(&mut self, ports: Vec<u16>) {
        self.own_ports = ports;
    }

    pub fn own_listen_ports(&self) -> &[u16] {
        &self.own_ports
    }

    /// Why `target`, named by the peer, may not be punched toward, or
    /// `None` if it may: it is a facilitator, this node itself (as its
    /// probe saw it, or one of its listening ports there), or of another
    /// address family than the punch socket's mapping.
    fn punch_target_refusal(
        &self,
        target: SocketAddr,
        facilitator: Option<SocketAddr>,
        observed: Option<SocketAddr>,
    ) -> Option<&'static str> {
        let target = canonical(target);
        if facilitator
            .into_iter()
            .chain(self.probe_addrs.iter().copied())
            .any(|f| canonical(f) == target)
        {
            return Some("a facilitator");
        }
        let observed = observed.map(canonical)?;
        if observed == target
            || (observed.ip() == target.ip() && self.own_ports.contains(&target.port()))
        {
            return Some("this node");
        }
        if observed.is_ipv4() != target.is_ipv4() {
            return Some("of another address family than the probed mapping");
        }
        None
    }

    /// Whether a peer-supplied endpoint may be probed or punched.
    fn endpoint_allowed(&self, ep: &Endpoint) -> Option<SocketAddr> {
        endpoint_to_socket_addr(ep)
            .filter(|addr| endpoint_is_acceptable(addr, self.allow_private_endpoints))
    }

    /// Whether this node takes part in Direct Link at all: it can propose
    /// (a probe server is configured) or may accept proposals. A node that
    /// does neither ignores all signalling, as a node without Direct Link
    /// support does.
    pub fn enabled(&self) -> bool {
        !self.probe_addrs.is_empty()
            || self.policy != HolePunchPolicy::Reject
            || !self.allowed_identities.is_empty()
    }

    /// Whether the link peer is known to implement Direct Link.
    pub fn peer_supported(&self, link_id: &[u8; 16]) -> bool {
        self.peer_support.get(link_id) == Some(&PeerSupport::Supported)
    }

    /// Propose a direct connection on a link.
    ///
    /// Signalling goes only to a peer known to implement Direct Link. For a
    /// peer not known yet, this sends a `HELLO` and the proposal starts when
    /// the peer answers; a peer that stays silent for [`HELLO_TIMEOUT`] is
    /// taken not to support it, and the proposal fails with
    /// `REJECT_UNSUPPORTED`.
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
        if self.probe_addrs.is_empty() {
            log::warn!(
                "Cannot propose direct connect on link {:02x?}: no probe_addr configured",
                &link_id[..4]
            );
            return vec![not_started(link_id)];
        }
        if self.rate_limited(&link_id, now) {
            return vec![not_started(link_id)];
        }
        match self.peer_support.get(&link_id) {
            Some(PeerSupport::Supported) => self.start_proposal(link_id, derived_key, rng, tx),
            // Already asking: the proposal starts with the answer.
            Some(PeerSupport::Querying { .. }) => Vec::new(),
            None => {
                self.peer_support.insert(
                    link_id,
                    PeerSupport::Querying {
                        since: now,
                        last_sent: now,
                    },
                );
                vec![hello(link_id, true)]
            }
        }
    }

    /// Handle a `HELLO` from a link peer: note that it implements Direct
    /// Link, answer it when it asks, and start a proposal that waited for it.
    pub fn handle_hello(
        &mut self,
        link_id: [u8; 16],
        body: &[u8],
        derived_key: Option<&[u8]>,
        rng: &mut dyn rns_crypto::Rng,
        tx: &EventSender,
    ) -> Vec<HolePunchManagerAction> {
        let hello_msg = match rns_core::holepunch::decode_hello(body) {
            Ok(h) => h,
            Err(e) => {
                log::debug!("Dropping malformed Direct Link HELLO: {}", e);
                return Vec::new();
            }
        };
        let mut actions = Vec::new();
        if hello_msg.reply_wanted {
            actions.push(hello(link_id, false));
        }
        let waiting = matches!(
            self.peer_support.insert(link_id, PeerSupport::Supported),
            Some(PeerSupport::Querying { .. })
        );
        if waiting {
            match derived_key {
                Some(key) => actions.extend(self.start_proposal(link_id, key, rng, tx)),
                None => log::warn!(
                    "Cannot propose direct connect: no derived key for link {:02x?}",
                    &link_id[..4]
                ),
            }
        }
        actions
    }

    /// One proposal per link per [`PROPOSAL_COOLDOWN`](rns_core::holepunch::types::PROPOSAL_COOLDOWN).
    fn rate_limited(&self, link_id: &[u8; 16], now: f64) -> bool {
        let limited = self
            .link_to_session
            .get(link_id)
            .and_then(|session_id| self.sessions.get(session_id))
            .is_some_and(|session| {
                now - session.last_proposal < rns_core::holepunch::types::PROPOSAL_COOLDOWN
            });
        if limited {
            log::debug!(
                "Hole punch proposal rate limited for link {:02x?}",
                &link_id[..4]
            );
        }
        limited
    }

    /// Start the upgrade on a link whose peer implements Direct Link.
    ///
    /// Per the spec, the initiator first discovers its own public endpoint
    /// (Phase 1), then sends UPGRADE_REQUEST (Phase 2).
    fn start_proposal(
        &mut self,
        link_id: [u8; 16],
        derived_key: &[u8],
        rng: &mut dyn rns_crypto::Rng,
        tx: &EventSender,
    ) -> Vec<HolePunchManagerAction> {
        let now = time::now();

        if self.rate_limited(&link_id, now) {
            return vec![not_started(link_id)];
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
                return vec![not_started(link_id)];
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
        msgtype: u8,
        payload: Vec<u8>,
        derived_key: Option<&[u8]>,
        tx: &EventSender,
    ) -> (bool, Vec<HolePunchManagerAction>) {
        self.handle_signal_at(link_id, msgtype, payload, derived_key, tx, Instant::now())
    }

    fn handle_signal_at(
        &mut self,
        link_id: [u8; 16],
        msgtype: u8,
        payload: Vec<u8>,
        derived_key: Option<&[u8]>,
        tx: &EventSender,
        now_instant: Instant,
    ) -> (bool, Vec<HolePunchManagerAction>) {
        if !is_holepunch_msgtype(msgtype) {
            return (false, Vec::new());
        }
        // Only a node implementing Direct Link sends these.
        self.peer_support.insert(link_id, PeerSupport::Supported);

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
            let facilitator = actions.iter().find_map(|a| match a {
                HolePunchAction::DiscoverEndpoints { probe_addr, .. } => {
                    endpoint_to_socket_addr(probe_addr)
                }
                _ => None,
            });
            if let Some(why) = self.punch_target_refusal(initiator_addr, facilitator, None) {
                log::debug!(
                    "Refusing hole punch proposal on link {:02x?}: initiator endpoint is {}",
                    &link_id[..4],
                    why
                );
                return (true, refuse_request(link_id, &payload, REJECT_POLICY));
            }
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
                log::debug!("Error handling signal 0x{:02x}: {}", msgtype, e);
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

        // Direct interfaces of closed links whose last packets have left.
        let mut retiring = std::mem::take(&mut self.retiring);
        retiring.retain(|(link_id, interface_id, due)| {
            if *due > now {
                return true;
            }
            all_actions.push(HolePunchManagerAction::RemoveDirectInterface {
                link_id: *link_id,
                interface_id: *interface_id,
            });
            false
        });
        self.retiring = retiring;

        // Links due to propose again after losing their direct path.
        for (link_id, entry) in self.reupgrades.iter_mut() {
            if !entry.in_flight && entry.due.is_some_and(|due| due <= now) {
                entry.due = None;
                entry.in_flight = true;
                all_actions.push(HolePunchManagerAction::Reupgrade { link_id: *link_id });
            }
        }

        // Peers asked whether they implement Direct Link: ask again, and
        // after HELLO_TIMEOUT of silence fail the waiting proposal.
        let mut unanswered = Vec::new();
        for (link_id, support) in self.peer_support.iter_mut() {
            if let PeerSupport::Querying { since, last_sent } = support {
                if now - *since >= HELLO_TIMEOUT {
                    unanswered.push(*link_id);
                } else if now - *last_sent >= HELLO_RETRY_INTERVAL {
                    *last_sent = now;
                    all_actions.push(hello(*link_id, true));
                }
            }
        }
        for link_id in unanswered {
            self.peer_support.remove(&link_id);
            log::debug!(
                "Link peer {:02x?} did not answer HELLO: Direct Link unsupported",
                &link_id[..4]
            );
            all_actions.push(HolePunchManagerAction::DirectConnectFailed {
                link_id,
                session_id: [0u8; 16],
                reason: REJECT_UNSUPPORTED,
            });
        }

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

                    let mut started = None;
                    let blackhole = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let initiated = self
                        .sessions
                        .get(&completion.session_id)
                        .is_some_and(|session| session.engine.is_initiator());
                    if let Some(session) = self.sessions.get(&completion.session_id) {
                        let params = udp_direct::DirectPathParams {
                            link_id: completion.link_id,
                            session_id: *session.engine.session_id(),
                            keepalive_key: *session.engine.keepalive_key(),
                            blackhole: blackhole.clone(),
                        };
                        match udp_direct::start_direct_interface(
                            socket,
                            peer_addr,
                            interface_id,
                            params,
                            tx.clone(),
                        ) {
                            Ok((writer, info)) => {
                                log::info!("Direct UDP interface started: {}", info.name);
                                started = Some((writer, info));
                            }
                            Err(e) => {
                                log::warn!("Failed to start direct interface: {}", e);
                            }
                        }
                    }

                    // Notify engine of success
                    if let Some(session) = self.sessions.get_mut(&completion.session_id) {
                        let peer_max_packet = session.engine.peer_max_packet();
                        let engine_actions =
                            session.engine.punch_succeeded(now).unwrap_or_default();
                        for action in engine_actions {
                            match action {
                                HolePunchAction::Succeeded { session_id } if started.is_some() => {
                                    let (writer, info) = started.take().unwrap();
                                    // One direct interface per link: a
                                    // repeated upgrade replaces the old one.
                                    if let Some(old) = self.direct.insert(
                                        completion.link_id,
                                        DirectPath {
                                            interface_id,
                                            session_id,
                                            blackhole: blackhole.clone(),
                                            initiated,
                                            since: now,
                                        },
                                    ) {
                                        all_actions.push(
                                            HolePunchManagerAction::RemoveDirectInterface {
                                                link_id: completion.link_id,
                                                interface_id: old.interface_id,
                                            },
                                        );
                                    }
                                    if let Some(entry) =
                                        self.reupgrades.get_mut(&completion.link_id)
                                    {
                                        entry.in_flight = false;
                                        entry.due = None;
                                    }
                                    all_actions.push(
                                        HolePunchManagerAction::DirectConnectEstablished {
                                            link_id: completion.link_id,
                                            session_id,
                                            interface_id,
                                            writer,
                                            info: Box::new(info),
                                            rtt: completion.rtt.unwrap_or(0.0),
                                            mtu: udp_direct::DIRECT_MTU,
                                            peer_max_packet,
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
    /// The link's direct interface is removed by a later [`tick`](Self::tick),
    /// once the link's closing packets have been sent on it.
    pub fn link_closed(&mut self, link_id: &[u8; 16]) {
        self.remove_link_session(link_id);
        self.peer_support.remove(link_id);
        self.reupgrades.remove(link_id);
        if let Some(path) = self.direct.remove(link_id) {
            self.retiring.push((
                *link_id,
                path.interface_id,
                time::now() + DIRECT_INTERFACE_RETIRE_DELAY,
            ));
        }
    }

    /// Whether `interface_id` is a direct interface, of a live upgrade or
    /// of a closed link waiting to be removed.
    pub fn is_direct_interface(
        &self,
        interface_id: rns_core::transport::types::InterfaceId,
    ) -> bool {
        self.direct
            .values()
            .any(|path| path.interface_id == interface_id)
            || self
                .retiring
                .iter()
                .any(|(_, retiring, _)| *retiring == interface_id)
    }

    /// The direct interface a link was upgraded to, if any.
    pub fn direct_interface(
        &self,
        link_id: &[u8; 16],
    ) -> Option<rns_core::transport::types::InterfaceId> {
        self.direct.get(link_id).map(|path| path.interface_id)
    }

    /// The link whose direct interface `interface_id` is, if any.
    pub fn direct_link_of(
        &self,
        interface_id: rns_core::transport::types::InterfaceId,
    ) -> Option<[u8; 16]> {
        self.direct
            .iter()
            .find(|(_, path)| path.interface_id == interface_id)
            .map(|(link_id, _)| *link_id)
    }

    /// The session of the link's direct path, if any.
    pub fn direct_session(&self, link_id: &[u8; 16]) -> Option<[u8; 16]> {
        self.direct.get(link_id).map(|path| path.session_id)
    }

    /// Stop using the link's direct path: forget it and return its
    /// interface and session. The caller removes the interface.
    pub fn take_direct(
        &mut self,
        link_id: &[u8; 16],
    ) -> Option<(rns_core::transport::types::InterfaceId, [u8; 16])> {
        let path = self.direct.remove(link_id)?;
        self.direct_path_lost(*link_id, &path, time::now());
        Some((path.interface_id, path.session_id))
    }

    /// Make the link's direct path silently drop all traffic both ways, as
    /// a network that stopped carrying it would. For tests.
    pub fn blackhole_direct(&self, link_id: &[u8; 16]) -> bool {
        match self.direct.get(link_id) {
            Some(path) => {
                path.blackhole
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    /// Called when an interface went down: if it was a link's direct
    /// interface, forget it and return the link and the path's session.
    pub fn direct_interface_down(
        &mut self,
        interface_id: rns_core::transport::types::InterfaceId,
    ) -> Option<([u8; 16], [u8; 16])> {
        self.retiring
            .retain(|(_, retiring, _)| *retiring != interface_id);
        let link_id = self
            .direct
            .iter()
            .find(|(_, path)| path.interface_id == interface_id)
            .map(|(link_id, _)| *link_id)?;
        let path = self.direct.remove(&link_id)?;
        self.direct_path_lost(link_id, &path, time::now());
        Some((link_id, path.session_id))
    }

    /// Whether this node is itself proposing on `link_id`: asking the peer
    /// about Direct Link for a proposal, or running an initiator session
    /// that has not finished.
    pub fn proposing(&self, link_id: &[u8; 16]) -> bool {
        if matches!(
            self.peer_support.get(link_id),
            Some(PeerSupport::Querying { .. })
        ) {
            return true;
        }
        self.link_to_session
            .get(link_id)
            .and_then(|session_id| self.sessions.get(session_id))
            .is_some_and(|session| {
                session.engine.is_initiator()
                    && matches!(
                        session.engine.state(),
                        HolePunchState::Discovering
                            | HolePunchState::Proposing
                            | HolePunchState::WaitingReady
                            | HolePunchState::Punching
                    )
            })
    }

    /// Both sides proposed on the same link at once, and the peer's
    /// proposal wins (the link initiator's does): drop ours without
    /// reporting a failure, since the upgrade goes ahead with us as the
    /// responder.
    pub fn yield_proposal(&mut self, link_id: &[u8; 16]) {
        if matches!(
            self.peer_support.get(link_id),
            Some(PeerSupport::Querying { .. })
        ) {
            // The peer sent a request, so it implements Direct Link.
            self.peer_support.insert(*link_id, PeerSupport::Supported);
        }
        let ours = self
            .link_to_session
            .get(link_id)
            .and_then(|session_id| self.sessions.get(session_id))
            .is_some_and(|session| session.engine.is_initiator());
        if ours {
            self.remove_link_session(link_id);
        }
    }

    /// Responder: replies to resend when `payload` repeats the request of
    /// the session running on `link_id` (its earlier replies may have been
    /// lost). `None` for a new request.
    pub fn replay_for_repeated_request(
        &self,
        link_id: [u8; 16],
        payload: &[u8],
    ) -> Option<Vec<HolePunchManagerAction>> {
        let session_id = HolePunchEngine::request_session_id(payload).ok()?;
        let current = self.link_to_session.get(&link_id)?;
        if *current != session_id {
            return None;
        }
        let session = self.sessions.get(current)?;
        if session.engine.is_initiator() {
            return None;
        }
        Some(convert_engine_actions(
            link_id,
            &session.engine.replay_replies(),
        ))
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
        self.peer_support.clear();
        self.reupgrades.clear();
    }

    /// Check if a signalling kind is an upgrade negotiation message.
    pub fn is_holepunch_message(msgtype: u8) -> bool {
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

                if crate::engine::FOLD_SERVICES {
                    super::folded_probe::start(super::folded_probe::ProbeJob {
                        servers,
                        protocol: protocol_copy,
                        session_id: session_id_copy,
                        link_id,
                        tx: tx_clone,
                        device: device_clone,
                        underlay_mark,
                        timeout: super::folded_probe::PROBE_TIMEOUT,
                    });
                    continue;
                }

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
        let refusal = self.sessions.get(session_id).and_then(|session| {
            let target = self.endpoint_allowed(peer_public)?;
            self.punch_target_refusal(target, session.facilitator, session.observed)
        });
        if let Some(why) = refusal {
            log::warn!(
                "Not punching session {:02x?}: peer endpoint {:?} is {}",
                &session_id[..4],
                peer_public,
                why
            );
        }
        let peer_addr = self
            .endpoint_allowed(peer_public)
            .filter(|_| refusal.is_none());
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
                    None if refusal.is_some() => {}
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

        let started = match &self.event_tx {
            Some(tx) if crate::engine::FOLD_SERVICES => puncher::start_udp_punch_on_loop(
                socket,
                vec![peer_addr],
                vec![],
                session_id_copy,
                punch_token_copy,
                tx,
            ),
            _ => puncher::start_udp_punch(
                socket,
                vec![peer_addr],
                vec![],
                session_id_copy,
                punch_token_copy,
            ),
        };
        match started {
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
        session.facilitator = Some(probe_server);
        session.observed = Some(observed_addr);

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
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return Vec::new();
        };
        // A responder tells the initiator instead of leaving it waiting;
        // the failed session is cleaned up on the next tick.
        match session.engine.discovery_failed(time::now()) {
            Ok(actions) => convert_engine_actions(link_id, &actions),
            Err(_) => Vec::new(),
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

/// A proposal that could not start.
fn not_started(link_id: [u8; 16]) -> HolePunchManagerAction {
    HolePunchManagerAction::DirectConnectFailed {
        link_id,
        session_id: [0u8; 16],
        reason: rns_core::holepunch::types::FAIL_NOT_STARTED,
    }
}

/// A `HELLO` to the link peer.
fn hello(link_id: [u8; 16], reply_wanted: bool) -> HolePunchManagerAction {
    HolePunchManagerAction::SendSignal {
        link_id,
        msgtype: HELLO,
        payload: rns_core::holepunch::encode_hello(reply_wanted),
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
                mgr_actions.push(HolePunchManagerAction::SendSignal {
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

    pub(crate) fn set_spawn_workers(&mut self, spawn: bool) {
        self.spawn_workers = spawn;
    }

    /// Propose on a link whose peer is already known to implement Direct
    /// Link, skipping the HELLO exchange.
    pub(crate) fn propose_to_supported(
        &mut self,
        link_id: [u8; 16],
        derived_key: &[u8],
        rng: &mut dyn rns_crypto::Rng,
        tx: &EventSender,
    ) -> Vec<HolePunchManagerAction> {
        self.peer_support.insert(link_id, PeerSupport::Supported);
        self.propose(link_id, derived_key, rng, tx)
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

    fn is_msg(action: &HolePunchManagerAction, expected: u8) -> bool {
        matches!(action, HolePunchManagerAction::SendSignal { msgtype, .. } if *msgtype == expected)
    }

    fn reject_reason(actions: &[HolePunchManagerAction]) -> Option<u8> {
        actions.iter().find_map(|a| match a {
            HolePunchManagerAction::SendSignal {
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
        mgr.propose_to_supported(link_id, &test_derived_key(), &mut rng, &tx);
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
            HolePunchManagerAction::SendSignal { payload, .. } => payload.clone(),
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
    fn request_naming_a_facilitator_as_the_initiator_is_refused() {
        // The facilitator in the request, and one of ours.
        for (facilitator, initiator) in [
            ("1.2.3.4:4343", "1.2.3.4:4343"),
            ("1.2.3.4:4343", "[::ffff:1.2.3.4]:4343"),
            ("1.2.3.4:4343", "9.9.9.9:4343"),
        ] {
            let mut mgr = HolePunchManager::new(
                vec!["9.9.9.9:4343".parse().unwrap()],
                ProbeProtocol::Rnsp,
                None,
            );
            mgr.set_policy(HolePunchPolicy::AcceptAll);
            mgr.set_spawn_workers(false);
            let (tx, _rx) = make_tx();
            let link_id = [0x58; 16];
            let payload = make_request(link_id, facilitator, initiator, 0x42);
            let (_, actions) = mgr.handle_signal(
                link_id,
                UPGRADE_REQUEST,
                payload,
                Some(&test_derived_key()),
                &tx,
            );
            assert_eq!(reject_reason(&actions), Some(REJECT_POLICY), "{initiator}");
            assert_eq!(mgr.session_count(), 0, "{initiator}");
        }
    }

    /// Run an initiator session that probed `observed` through the
    /// manager's probe server, up to the peer's READY naming `responder`.
    /// Whether the manager went on to punch.
    fn punches_toward(mgr: &mut HolePunchManager, observed: &str, responder: &str) -> bool {
        let (tx, _rx) = make_tx();
        let link_id = [0x59; 16];
        let mut rng = make_rng(0x42);
        mgr.propose_to_supported(link_id, &test_derived_key(), &mut rng, &tx);
        let session_id = *mgr.link_to_session.get(&link_id).unwrap();
        let facilitator = mgr.probe_addrs[0];
        let request = mgr.handle_probe_result(
            link_id,
            session_id,
            observed.parse().unwrap(),
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            facilitator,
        );
        let request_payload = match &request[0] {
            HolePunchManagerAction::SendSignal { payload, .. } => payload.clone(),
            _ => unreachable!(),
        };
        let mut responder_engine = HolePunchEngine::new(link_id, None, ProbeProtocol::Rnsp);
        let r_actions = responder_engine
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
        let ready_actions = responder_engine
            .endpoints_discovered(ep(responder), 2.0)
            .unwrap();
        let ready = match &ready_actions[0] {
            HolePunchAction::SendSignal { payload, .. } => payload.clone(),
            _ => unreachable!(),
        };
        mgr.handle_signal(link_id, UPGRADE_ACCEPT, accept, None, &tx);
        let (_, actions) = mgr.handle_signal(link_id, UPGRADE_READY, ready, None, &tx);
        let session = mgr.sessions.get(&session_id).unwrap();
        let punching = session.punch_target.is_some();
        assert_eq!(
            punching,
            !actions
                .iter()
                .any(|a| matches!(a, HolePunchManagerAction::DirectConnectFailed { .. }))
        );
        punching
    }

    #[test]
    fn punch_toward_this_node_or_a_facilitator_is_refused() {
        let manager = || {
            let mut mgr = HolePunchManager::new(
                vec!["9.9.9.9:4343".parse().unwrap()],
                ProbeProtocol::Rnsp,
                None,
            );
            mgr.set_own_listen_ports(vec![4242]);
            mgr.set_spawn_workers(false);
            mgr
        };
        let observed = "1.2.3.4:41000";
        // Our own mapping, our probe server at our address, the
        // facilitator, and an IPv6 peer for an IPv4 mapping.
        for responder in [
            "1.2.3.4:41000",
            "[::ffff:1.2.3.4]:41000",
            "1.2.3.4:4242",
            "9.9.9.9:4343",
            "[2001:4860::1]:52000",
        ] {
            assert!(
                !punches_toward(&mut manager(), observed, responder),
                "{responder}"
            );
        }
        // Another port at our own address is a peer behind the same NAT,
        // and any port elsewhere is fine.
        for responder in ["1.2.3.4:41001", "5.6.7.8:4242", "9.9.9.9:4344"] {
            assert!(
                punches_toward(&mut manager(), observed, responder),
                "{responder}"
            );
        }
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

        let actions = mgr.propose_to_supported(link_id, &test_derived_key(), &mut rng, &tx);

        assert_eq!(mgr.session_count(), 1);
        assert!(mgr.has_session_for_link(&link_id));
        // No SendSignal yet — initiator probes first
        assert!(actions.is_empty());
    }

    #[test]
    fn test_propose_rate_limited() {
        let mut mgr = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
        let link_id = [0x22; 16];
        let mut rng = make_rng(0x42);
        let (tx, _rx) = make_tx();

        mgr.propose_to_supported(link_id, &test_derived_key(), &mut rng, &tx);

        // Immediate second proposal is rate-limited, and says so
        let actions = mgr.propose_to_supported(link_id, &test_derived_key(), &mut rng, &tx);
        assert!(matches!(
            actions[..],
            [HolePunchManagerAction::DirectConnectFailed {
                reason: rns_core::holepunch::types::FAIL_NOT_STARTED,
                ..
            }]
        ));
        // To a peer not yet known as well, before anything is sent.
        mgr.peer_support.clear();
        let actions = mgr.propose(link_id, &test_derived_key(), &mut rng, &tx);
        assert!(matches!(
            actions[..],
            [HolePunchManagerAction::DirectConnectFailed { .. }]
        ));
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
            matches!(&actions[0], HolePunchManagerAction::SendSignal { msgtype, .. } if *msgtype == UPGRADE_REJECT)
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
        assert!(actions.iter().any(|a| matches!(a, HolePunchManagerAction::SendSignal { msgtype, .. } if *msgtype == UPGRADE_ACCEPT)));
        assert_eq!(mgr.session_count(), 1);
        assert!(mgr.has_session_for_link(&link_id));
    }

    #[test]
    fn test_non_holepunch_message_not_handled() {
        let mut mgr = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None);
        let (tx, _rx) = make_tx();

        let (handled, actions) = mgr.handle_signal([0x55; 16], 0x05, vec![1, 2, 3], None, &tx);

        assert!(!handled);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_link_closed_cleans_up() {
        let mut mgr = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
        let link_id = [0x66; 16];
        let mut rng = make_rng(0x42);
        let (tx, _rx) = make_tx();

        mgr.propose_to_supported(link_id, &test_derived_key(), &mut rng, &tx);
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

        mgr.propose_to_supported(link_a, &test_derived_key(), &mut rng, &tx);
        mgr.propose_to_supported(link_b, &[0xBB; 32], &mut rng, &tx);
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

        mgr.propose_to_supported(link_id, &test_derived_key(), &mut rng, &tx);
        let session_id = *mgr.link_to_session.get(&link_id).unwrap();

        let actions = mgr.handle_probe_failed(link_id, session_id);
        assert_eq!(actions.len(), 1);
        assert!(
            matches!(&actions[0], HolePunchManagerAction::DirectConnectFailed { reason, .. }
            if *reason == rns_core::holepunch::types::FAIL_PROBE)
        );
    }

    #[test]
    fn responder_probe_failure_rejects_the_request() {
        let mut mgr = accepting_manager();
        let (tx, _rx) = make_tx();
        let link_id = [0x78; 16];
        let payload = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x45);
        let (_, accepted) = mgr.handle_signal(
            link_id,
            UPGRADE_REQUEST,
            payload,
            Some(&test_derived_key()),
            &tx,
        );
        assert!(accepted.iter().any(|a| is_msg(a, UPGRADE_ACCEPT)));
        let session_id = mgr.link_to_session[&link_id];

        let actions = mgr.handle_probe_failed(link_id, session_id);
        assert_eq!(
            reject_reason(&actions),
            Some(rns_core::holepunch::REJECT_NO_ENDPOINT)
        );
        assert!(actions.iter().any(|a| matches!(
            a,
            HolePunchManagerAction::DirectConnectFailed { reason, .. }
                if *reason == rns_core::holepunch::types::FAIL_PROBE
        )));
        // The failed session is cleaned up.
        mgr.tick(&tx);
        assert_eq!(mgr.session_count(), 0);
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
        mgr.propose_to_supported(link_id, &test_derived_key(), &mut rng, &tx);
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
            HolePunchManagerAction::SendSignal { msgtype, .. }
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
            HolePunchManagerAction::SendSignal { msgtype, .. }
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
    fn test_policy_default_is_reject() {
        let mgr = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None);
        assert_eq!(mgr.policy(), HolePunchPolicy::Reject);
        assert_eq!(HolePunchPolicy::default(), HolePunchPolicy::Reject);
        assert!(!mgr.allow_private_endpoints());
        // Out of the box a node takes no part in Direct Link.
        assert!(!mgr.enabled());
    }

    #[test]
    fn test_set_policy() {
        let mut mgr = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None);
        mgr.set_policy(HolePunchPolicy::Reject);
        assert_eq!(mgr.policy(), HolePunchPolicy::Reject);
    }

    #[test]
    fn test_is_holepunch_message() {
        assert!(HolePunchManager::is_holepunch_message(UPGRADE_REQUEST));
        assert!(HolePunchManager::is_holepunch_message(UPGRADE_READY));
        assert!(!HolePunchManager::is_holepunch_message(HELLO));
        assert!(!HolePunchManager::is_holepunch_message(0x05));
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

        // Fails at once, and says so — an initiator needs a probe address;
        // not even HELLO goes to the peer.
        for propose in [
            HolePunchManager::propose_to_supported,
            HolePunchManager::propose,
        ] {
            let actions = propose(&mut mgr, link_id, &test_derived_key(), &mut rng, &tx);
            assert!(matches!(
                actions[..],
                [HolePunchManagerAction::DirectConnectFailed {
                    reason: rns_core::holepunch::types::FAIL_NOT_STARTED,
                    ..
                }]
            ));
        }
        // No session created since propose() failed
        assert_eq!(mgr.session_count(), 0);
    }

    fn hello_sent(actions: &[HolePunchManagerAction]) -> Vec<bool> {
        actions
            .iter()
            .filter_map(|a| match a {
                HolePunchManagerAction::SendSignal {
                    msgtype, payload, ..
                } if *msgtype == HELLO => Some(
                    rns_core::holepunch::decode_hello(payload)
                        .unwrap()
                        .reply_wanted,
                ),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn proposal_to_unknown_peer_only_asks_hello() {
        let mut mgr = accepting_manager();
        let (tx, _rx) = make_tx();
        let link_id = [0x61; 16];
        let actions = mgr.propose(link_id, &test_derived_key(), &mut make_rng(1), &tx);
        // Nothing but the capability query goes to a peer not known to
        // implement Direct Link.
        assert_eq!(actions.len(), 1);
        assert_eq!(hello_sent(&actions), vec![true]);
        assert_eq!(mgr.session_count(), 0);
        assert!(!mgr.peer_supported(&link_id));
        // Proposing again while asking sends nothing more.
        assert!(mgr
            .propose(link_id, &test_derived_key(), &mut make_rng(2), &tx)
            .is_empty());
    }

    #[test]
    fn hello_answer_starts_the_waiting_proposal() {
        let mut mgr = accepting_manager();
        let (tx, _rx) = make_tx();
        let link_id = [0x62; 16];
        mgr.propose(link_id, &test_derived_key(), &mut make_rng(1), &tx);
        let actions = mgr.handle_hello(
            link_id,
            &rns_core::holepunch::encode_hello(false),
            Some(&test_derived_key()),
            &mut make_rng(3),
            &tx,
        );
        // An answer is not answered again.
        assert!(hello_sent(&actions).is_empty());
        assert!(mgr.peer_supported(&link_id));
        assert_eq!(mgr.session_count(), 1);
        let session_id = mgr.link_to_session[&link_id];
        assert_eq!(
            mgr.sessions[&session_id].engine.state(),
            HolePunchState::Discovering
        );
    }

    #[test]
    fn hello_query_is_answered_without_proposing() {
        let mut mgr = accepting_manager();
        let (tx, _rx) = make_tx();
        let link_id = [0x63; 16];
        let actions = mgr.handle_hello(
            link_id,
            &rns_core::holepunch::encode_hello(true),
            Some(&test_derived_key()),
            &mut make_rng(3),
            &tx,
        );
        assert_eq!(hello_sent(&actions), vec![false]);
        assert_eq!(actions.len(), 1);
        assert_eq!(mgr.session_count(), 0);
        assert!(mgr.peer_supported(&link_id));
        // Malformed HELLOs are dropped.
        let other = [0x64; 16];
        assert!(mgr
            .handle_hello(other, &[0xC1], None, &mut make_rng(3), &tx)
            .is_empty());
        assert!(!mgr.peer_supported(&other));
    }

    #[test]
    fn unanswered_hello_is_repeated_then_fails_as_unsupported() {
        let mut mgr = accepting_manager();
        let (tx, _rx) = make_tx();
        let link_id = [0x65; 16];
        mgr.propose(link_id, &test_derived_key(), &mut make_rng(1), &tx);
        let now = time::now();
        mgr.peer_support.insert(
            link_id,
            PeerSupport::Querying {
                since: now - HELLO_RETRY_INTERVAL,
                last_sent: now - HELLO_RETRY_INTERVAL,
            },
        );
        assert_eq!(hello_sent(&mgr.tick(&tx)), vec![true]);
        assert!(hello_sent(&mgr.tick(&tx)).is_empty());

        mgr.peer_support.insert(
            link_id,
            PeerSupport::Querying {
                since: now - HELLO_TIMEOUT,
                last_sent: now,
            },
        );
        let actions = mgr.tick(&tx);
        assert!(hello_sent(&actions).is_empty());
        assert!(actions.iter().any(|a| matches!(
            a,
            HolePunchManagerAction::DirectConnectFailed { link_id: l, reason, .. }
                if *l == link_id && *reason == REJECT_UNSUPPORTED
        )));
        assert!(mgr.peer_support.is_empty());
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn upgrade_message_marks_the_peer_supported() {
        let mut mgr = accepting_manager();
        let (tx, _rx) = make_tx();
        let link_id = [0x66; 16];
        let payload = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x42);
        mgr.handle_signal(
            link_id,
            UPGRADE_REQUEST,
            payload,
            Some(&test_derived_key()),
            &tx,
        );
        assert!(mgr.peer_supported(&link_id));
        mgr.link_closed(&link_id);
        assert!(!mgr.peer_supported(&link_id));
    }

    #[test]
    fn repeated_request_replays_replies_instead_of_refusing() {
        let mut mgr = accepting_manager();
        let (tx, _rx) = make_tx();
        let link_id = [0x67; 16];
        let payload = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x42);
        assert!(mgr.replay_for_repeated_request(link_id, &payload).is_none());
        let (_, first) = mgr.handle_signal(
            link_id,
            UPGRADE_REQUEST,
            payload.clone(),
            Some(&test_derived_key()),
            &tx,
        );
        assert!(first.iter().any(|a| is_msg(a, UPGRADE_ACCEPT)));
        let replay = mgr.replay_for_repeated_request(link_id, &payload).unwrap();
        assert_eq!(replay.len(), 1);
        assert!(is_msg(&replay[0], UPGRADE_ACCEPT));
        // A different session is a new request.
        let other = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x43);
        assert!(mgr.replay_for_repeated_request(link_id, &other).is_none());
    }

    #[test]
    fn manager_takes_part_only_when_configured() {
        let mut mgr = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None);
        mgr.set_policy(HolePunchPolicy::Reject);
        assert!(!mgr.enabled());
        mgr.set_policy(HolePunchPolicy::AcceptAll);
        assert!(mgr.enabled());
        let mut initiator =
            HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
        initiator.set_policy(HolePunchPolicy::Reject);
        assert!(initiator.enabled());
        let mut allowlisted = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None);
        allowlisted.set_policy(HolePunchPolicy::Reject);
        allowlisted.set_allowed_identities(vec![[7; 16]]);
        assert!(allowlisted.enabled());
        assert!(allowlisted.identity_allowed(&[7; 16]));
        assert!(!allowlisted.identity_allowed(&[8; 16]));
    }

    fn upgraded(mgr: &mut HolePunchManager, link_id: [u8; 16], interface: u64) {
        upgraded_as(mgr, link_id, interface, true, time::now());
    }

    fn upgraded_as(
        mgr: &mut HolePunchManager,
        link_id: [u8; 16],
        interface: u64,
        initiated: bool,
        since: f64,
    ) {
        mgr.direct.insert(
            link_id,
            DirectPath {
                interface_id: rns_core::transport::types::InterfaceId(interface),
                session_id: [interface as u8; 16],
                blackhole: Default::default(),
                initiated,
                since,
            },
        );
    }

    fn reupgrade_due(mgr: &HolePunchManager, link_id: &[u8; 16]) -> Option<f64> {
        mgr.reupgrades.get(link_id).and_then(|entry| entry.due)
    }

    /// Make the link's scheduled re-upgrade due now, and tick.
    fn run_due_reupgrade(mgr: &mut HolePunchManager, link_id: [u8; 16]) -> bool {
        let (tx, _rx) = make_tx();
        if let Some(entry) = mgr.reupgrades.get_mut(&link_id) {
            if entry.due.is_some() {
                entry.due = Some(time::now() - 1.0);
            }
        }
        mgr.tick(&tx).iter().any(
            |a| matches!(a, HolePunchManagerAction::Reupgrade { link_id: id } if *id == link_id),
        )
    }

    #[test]
    fn reupgrade_delay_doubles_up_to_the_cap_with_bounded_jitter() {
        let config = DirectReupgradeConfig {
            enabled: true,
            max_attempts: 10,
            initial_delay: std::time::Duration::from_secs(60),
            max_delay: std::time::Duration::from_secs(300),
        };
        let delays: Vec<f64> = (0..5).map(|n| reupgrade_delay(&config, n, 0.0)).collect();
        assert_eq!(delays, vec![60.0, 120.0, 240.0, 300.0, 300.0]);
        // Jitter adds at most a quarter.
        let jittered = reupgrade_delay(&config, 1, 0.999_999);
        assert!(jittered > 149.9 && jittered < 150.0, "{jittered}");
        assert!(reupgrade_delay(&config, 1000, 0.5) <= 300.0 * 1.25);
        // Never sooner than a link may be proposed on again.
        let short = DirectReupgradeConfig {
            initial_delay: std::time::Duration::from_secs(1),
            max_delay: std::time::Duration::from_secs(2),
            ..config
        };
        assert_eq!(reupgrade_delay(&short, 0, 0.0), 60.0);
        assert_eq!(reupgrade_delay(&short, 3, 0.0), 60.0);
        for _ in 0..100 {
            let unit = random_unit();
            assert!((0.0..1.0).contains(&unit));
        }
    }

    #[test]
    fn lost_direct_path_is_proposed_again_with_backoff_until_the_limit() {
        let mut mgr = accepting_manager();
        mgr.set_reupgrade_config(DirectReupgradeConfig {
            max_attempts: 3,
            ..DirectReupgradeConfig::default()
        });
        let link_id = [0x71; 16];
        upgraded(&mut mgr, link_id, 50_100);
        let now = time::now();
        assert!(mgr.take_direct(&link_id).is_some());
        let due = reupgrade_due(&mgr, &link_id).expect("re-upgrade scheduled");
        assert!(
            due >= now + 60.0 && due <= now + 75.0 + 1.0,
            "{}",
            due - now
        );
        // Not before it is due.
        let (tx, _rx) = make_tx();
        assert!(!mgr
            .tick(&tx)
            .iter()
            .any(|a| matches!(a, HolePunchManagerAction::Reupgrade { .. })));

        // Each failed attempt schedules the next, twice as far out.
        let mut delays = Vec::new();
        for _ in 0..3 {
            assert!(run_due_reupgrade(&mut mgr, link_id));
            // Once handed out, it is not handed out again.
            assert!(!run_due_reupgrade(&mut mgr, link_id));
            let before = time::now();
            mgr.reupgrade_failed(link_id, rns_core::holepunch::types::FAIL_TIMEOUT);
            if let Some(due) = reupgrade_due(&mgr, &link_id) {
                delays.push(due - before);
            }
        }
        assert_eq!(delays.len(), 2, "{delays:?}");
        assert!(delays[0] >= 120.0 && delays[0] <= 150.0 + 1.0, "{delays:?}");
        assert!(delays[1] >= 240.0 && delays[1] <= 300.0 + 1.0, "{delays:?}");
        // The third failure was the last attempt.
        assert!(!mgr.reupgrades.contains_key(&link_id));
    }

    #[test]
    fn reupgrade_stops_on_refusal_success_or_link_close() {
        let link_id = [0x72; 16];
        let lost = |mgr: &mut HolePunchManager| {
            upgraded(mgr, link_id, 50_101);
            mgr.direct_interface_down(rns_core::transport::types::InterfaceId(50_101));
            assert!(reupgrade_due(mgr, &link_id).is_some());
        };

        // The peer refuses by policy, or stopped answering HELLO.
        for reason in [REJECT_POLICY, REJECT_UNSUPPORTED] {
            let mut mgr = accepting_manager();
            lost(&mut mgr);
            assert!(run_due_reupgrade(&mut mgr, link_id));
            mgr.reupgrade_failed(link_id, reason);
            assert!(!mgr.reupgrades.contains_key(&link_id));
        }

        // A failure while nothing is in flight (the application's own
        // proposal) does not move the schedule.
        let mut mgr = accepting_manager();
        lost(&mut mgr);
        let due = reupgrade_due(&mgr, &link_id);
        mgr.reupgrade_failed(link_id, rns_core::holepunch::types::FAIL_TIMEOUT);
        assert_eq!(reupgrade_due(&mgr, &link_id), due);

        // The link closes, or the driver finds it no longer active.
        mgr.link_closed(&link_id);
        assert!(!mgr.reupgrades.contains_key(&link_id));
        let mut mgr = accepting_manager();
        lost(&mut mgr);
        mgr.cancel_reupgrade(&link_id);
        assert!(!run_due_reupgrade(&mut mgr, link_id));
    }

    #[test]
    fn only_the_proposing_side_reupgrades_and_only_when_enabled() {
        let link_id = [0x73; 16];
        // The responder side of the lost upgrade.
        let mut mgr = accepting_manager();
        upgraded_as(&mut mgr, link_id, 50_102, false, time::now());
        mgr.take_direct(&link_id);
        assert!(!mgr.reupgrades.contains_key(&link_id));

        // Turned off.
        let mut mgr = accepting_manager();
        mgr.set_reupgrade_config(DirectReupgradeConfig {
            enabled: false,
            ..DirectReupgradeConfig::default()
        });
        upgraded(&mut mgr, link_id, 50_103);
        mgr.take_direct(&link_id);
        assert!(!mgr.reupgrades.contains_key(&link_id));

        // No facilitator to propose through any more.
        let mut mgr = accepting_manager();
        mgr.set_probe_config(vec![], ProbeProtocol::Rnsp, None);
        upgraded(&mut mgr, link_id, 50_104);
        mgr.take_direct(&link_id);
        assert!(!mgr.reupgrades.contains_key(&link_id));
    }

    #[test]
    fn a_long_lived_path_starts_the_attempt_count_again() {
        let link_id = [0x74; 16];
        let mut mgr = accepting_manager();
        mgr.set_reupgrade_config(DirectReupgradeConfig {
            max_attempts: 2,
            ..DirectReupgradeConfig::default()
        });
        upgraded(&mut mgr, link_id, 50_105);
        mgr.take_direct(&link_id);
        assert!(run_due_reupgrade(&mut mgr, link_id));
        mgr.reupgrade_failed(link_id, rns_core::holepunch::types::FAIL_TIMEOUT);
        assert_eq!(mgr.reupgrades[&link_id].attempts, 2);
        // The next attempt succeeds, and the path is lost again soon: the
        // count goes on, and that was the last attempt.
        assert!(run_due_reupgrade(&mut mgr, link_id));
        mgr.reupgrades.get_mut(&link_id).unwrap().in_flight = false;
        upgraded(&mut mgr, link_id, 50_106);
        mgr.take_direct(&link_id);
        assert!(!mgr.reupgrades.contains_key(&link_id));

        // A path that lasted past the longest delay starts over.
        upgraded(&mut mgr, link_id, 50_107);
        mgr.take_direct(&link_id);
        assert!(run_due_reupgrade(&mut mgr, link_id));
        mgr.reupgrade_failed(link_id, rns_core::holepunch::types::FAIL_TIMEOUT);
        assert_eq!(mgr.reupgrades[&link_id].attempts, 2);
        assert!(run_due_reupgrade(&mut mgr, link_id));
        mgr.reupgrades.get_mut(&link_id).unwrap().in_flight = false;
        upgraded_as(&mut mgr, link_id, 50_108, true, time::now() - 1000.0);
        mgr.take_direct(&link_id);
        assert_eq!(mgr.reupgrades[&link_id].attempts, 1);
    }

    #[test]
    fn closed_link_retires_its_direct_interface_after_a_delay() {
        use rns_core::transport::types::InterfaceId;
        let mut mgr = accepting_manager();
        let (tx, _rx) = make_tx();
        let link_id = [0x71; 16];
        upgraded(&mut mgr, link_id, 50_001);
        assert_eq!(mgr.direct_interface(&link_id), Some(InterfaceId(50_001)));
        assert!(mgr.is_direct_interface(InterfaceId(50_001)));

        mgr.link_closed(&link_id);
        assert_eq!(mgr.direct_interface(&link_id), None);
        // Still a direct interface (no broadcasts) while it is retiring.
        assert!(mgr.is_direct_interface(InterfaceId(50_001)));
        assert!(!mgr
            .tick(&tx)
            .iter()
            .any(|a| matches!(a, HolePunchManagerAction::RemoveDirectInterface { .. })));
        mgr.retiring[0].2 = time::now() - 0.1;
        let actions = mgr.tick(&tx);
        assert!(actions.iter().any(|a| matches!(
            a,
            HolePunchManagerAction::RemoveDirectInterface { link_id: l, interface_id }
                if *l == link_id && *interface_id == InterfaceId(50_001)
        )));
        assert!(mgr.retiring.is_empty());
        assert!(mgr.tick(&tx).is_empty());
    }

    #[test]
    fn direct_interface_down_forgets_it() {
        use rns_core::transport::types::InterfaceId;
        let mut mgr = accepting_manager();
        let link_id = [0x72; 16];
        upgraded(&mut mgr, link_id, 50_002);
        assert_eq!(mgr.direct_interface_down(InterfaceId(7)), None);
        assert_eq!(
            mgr.direct_interface_down(InterfaceId(50_002)),
            Some((link_id, [(50_002u64 as u8); 16]))
        );
        assert!(!mgr.is_direct_interface(InterfaceId(50_002)));
        assert_eq!(mgr.direct_interface_down(InterfaceId(50_002)), None);
        // A retiring interface that goes down is not removed twice.
        upgraded(&mut mgr, link_id, 50_003);
        mgr.link_closed(&link_id);
        assert_eq!(mgr.direct_interface_down(InterfaceId(50_003)), None);
        assert!(mgr.retiring.is_empty());
    }

    #[test]
    fn own_proposal_is_reported_and_can_be_yielded() {
        let mut mgr = accepting_manager();
        let (tx, _rx) = make_tx();
        let link_id = [0x73; 16];
        assert!(!mgr.proposing(&link_id));
        // Asking HELLO counts as proposing.
        mgr.propose(link_id, &test_derived_key(), &mut make_rng(1), &tx);
        assert!(mgr.proposing(&link_id));
        mgr.yield_proposal(&link_id);
        assert!(!mgr.proposing(&link_id));
        assert!(mgr.peer_supported(&link_id));

        // So does a running initiator session; yielding drops it quietly.
        mgr.propose(link_id, &test_derived_key(), &mut make_rng(2), &tx);
        assert!(mgr.proposing(&link_id));
        assert_eq!(mgr.session_count(), 1);
        mgr.yield_proposal(&link_id);
        assert!(!mgr.proposing(&link_id));
        assert_eq!(mgr.session_count(), 0);
        assert!(mgr
            .tick(&tx)
            .iter()
            .all(|a| !matches!(a, HolePunchManagerAction::DirectConnectFailed { .. })));

        // A responder session is not ours to yield.
        let request = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x44);
        mgr.handle_signal(
            link_id,
            UPGRADE_REQUEST,
            request,
            Some(&test_derived_key()),
            &tx,
        );
        assert!(!mgr.proposing(&link_id));
        mgr.yield_proposal(&link_id);
        assert_eq!(mgr.session_count(), 1);
    }
}
