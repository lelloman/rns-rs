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

mod direct;
mod proposals;
mod punch;
mod settings;
mod signals;
mod status;
#[cfg(test)]
mod tests;
mod tick;

use punch::*;
pub use signals::*;

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Instant;

use rns_core::holepunch::types::{is_holepunch_msgtype, HELLO_RETRY_INTERVAL, HELLO_TIMEOUT};
use rns_core::holepunch::{
    Endpoint, HolePunchAction, HolePunchEngine, HolePunchState, ProbeProtocol, HELLO, REJECT_BUSY,
    REJECT_POLICY, REJECT_UNSUPPORTED, UPGRADE_REQUEST,
};

use crate::event::{
    DirectCandidateKind, DirectLinkCounters, DirectLinkEntry, DirectLinkStatus, DirectLossCause,
    DirectPathStatus, Event, EventSender,
};
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

/// Seconds before a re-upgrade that found its link stale looks again.
const REUPGRADE_STALE_RETRY: f64 = 1.0;

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
    /// The candidates the punch sends to, with their kinds.
    candidates: Vec<(SocketAddr, DirectCandidateKind)>,
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
            candidates: Vec::new(),
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
    /// The peer's address on the path, and what kind of candidate it was.
    peer_addr: SocketAddr,
    candidate: DirectCandidateKind,
    candidates: Vec<(SocketAddr, DirectCandidateKind)>,
    /// Round trip measured by the punch, in seconds.
    rtt: f64,
    mtu: u32,
    mtu_discovered: bool,
    /// Largest link packet the peer said it accepts on the path.
    peer_max_packet: Option<u32>,
}

/// Counts of upgrades, kept node-wide and per link.
#[derive(Debug, Clone, Default)]
struct Counters {
    proposed: u64,
    accepted: u64,
    established: u64,
    failed: std::collections::BTreeMap<u8, u64>,
    lost: u64,
}

impl Counters {
    fn report(&self) -> DirectLinkCounters {
        DirectLinkCounters {
            proposed: self.proposed,
            accepted: self.accepted,
            established: self.established,
            failed: self.failed.iter().map(|(r, n)| (*r, *n)).collect(),
            lost: self.lost,
        }
    }
}

/// What is recorded about a link's upgrades, for status reports.
#[derive(Debug, Clone, Default)]
struct LinkHistory {
    counters: Counters,
    last_failure: Option<(u8, f64)>,
    last_loss: Option<(DirectLossCause, f64)>,
}

/// The name of an upgrade state in status reports.
fn state_name(state: HolePunchState) -> Option<&'static str> {
    match state {
        HolePunchState::Idle => None,
        HolePunchState::Discovering => Some("discovering"),
        HolePunchState::Proposing => Some("proposing"),
        HolePunchState::WaitingReady => Some("waiting_ready"),
        HolePunchState::Punching => Some("punching"),
        HolePunchState::Connected => Some("connected"),
        HolePunchState::Failed => Some("failed"),
    }
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
    /// Counters of this node's own probe server, when it runs one.
    probe_server_counters: Option<std::sync::Arc<super::probe::ProbeServerCounters>>,
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
    /// Upgrade counts over the node's life, and per link while it is open.
    totals: Counters,
    history: HashMap<[u8; 16], LinkHistory>,
    /// This host's networks as tests want them seen.
    #[cfg(test)]
    networks: Option<Vec<super::candidates::LocalNetwork>>,
}

/// Actions produced by HolePunchManager for the driver to dispatch.
pub enum HolePunchManagerAction {
    /// Send a Direct Link signalling message (kind and body) to the link
    /// peer, in a link packet with `CONTEXT_DIRECT_LINK`.
    SendSignal {
        /// Link to send on.
        link_id: [u8; 16],
        /// Message kind.
        msgtype: u8,
        /// Message body.
        payload: Vec<u8>,
    },
    /// Direct connection established: register the new interface and
    /// route the link over it.
    DirectConnectEstablished {
        /// Link being upgraded.
        link_id: [u8; 16],
        /// Hole punching session that made the connection.
        session_id: [u8; 16],
        /// ID of the new direct interface.
        interface_id: rns_core::transport::types::InterfaceId,
        /// Writer of the direct interface.
        writer: Box<dyn crate::interface::Writer>,
        /// Transport-level description of the direct interface.
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
        /// Link the interface belonged to.
        link_id: [u8; 16],
        /// Direct interface to remove.
        interface_id: rns_core::transport::types::InterfaceId,
    },
    /// Propose again on a link that lost its direct path, if it is still
    /// active (see [`DirectReupgradeConfig`]).
    Reupgrade {
        /// Link to propose on.
        link_id: [u8; 16],
    },
    /// Direct connection failed.
    DirectConnectFailed {
        /// Link whose upgrade failed.
        link_id: [u8; 16],
        /// Hole punching session, all zeros when none was started.
        session_id: [u8; 16],
        /// Failure reason, a `FAIL_*` or `REJECT_*` code.
        reason: u8,
    },
}

impl HolePunchManager {
    // --- Internal helpers ---
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
