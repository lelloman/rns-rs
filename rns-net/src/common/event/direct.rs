//! Direct path settings, status and counters.

/// Policy for handling incoming direct-connect proposals.
///
/// Accepting a proposal reveals this node's public IP address and port to
/// the link peer. Identities listed in
/// `NodeConfig::direct_connect_allowed_identities` are accepted whatever the
/// policy once they identify on the link.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HolePunchPolicy {
    /// Reject all proposals (the default).
    #[default]
    Reject,
    /// Accept all proposals automatically.
    AcceptAll,
    /// Accept proposals only after the Reticulum link peer has identified
    /// itself. Any peer can identify with a throwaway identity, so this
    /// discloses the endpoint to anyone who asks; prefer an allowlist.
    IdentifiedOnly,
    /// Ask the application callback.
    AskApp,
}

/// Automatic re-upgrade of a link whose direct path was lost.
///
/// After the side that proposed an upgrade loses the direct path, it
/// proposes again by itself while the link stays active: the first time
/// after `initial_delay`, then after twice the previous delay, at most
/// `max_delay`, each with up to 25% added at random, and gives up after
/// `max_attempts` proposals that do not establish a direct path, when the
/// peer refuses by policy or no longer answers the capability check, or
/// when the link closes. A direct path that then lasts at least `max_delay`
/// before it is lost starts the count again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectReupgradeConfig {
    /// Re-upgrade at all (default on).
    pub enabled: bool,
    /// Proposals after a loss before giving up (default 5).
    pub max_attempts: u32,
    /// Delay before the first proposal (default 60 seconds). A shorter one
    /// is taken as 60 seconds, the shortest spacing of two proposals on a
    /// link.
    pub initial_delay: std::time::Duration,
    /// Upper bound of the delay (default 15 minutes).
    pub max_delay: std::time::Duration,
}

impl Default for DirectReupgradeConfig {
    fn default() -> Self {
        DirectReupgradeConfig {
            enabled: true,
            max_attempts: 5,
            initial_delay: std::time::Duration::from_secs(60),
            max_delay: std::time::Duration::from_secs(900),
        }
    }
}

/// Rate limits of the probe server (the facilitator side of Direct Link).
///
/// Each source gets a token bucket: `per_source_burst` requests at once,
/// refilled at `per_source_rate` a second. A source is an IPv4 address or
/// an IPv6 /64, since a host usually holds a whole /64. Over all sources
/// the server answers at most `total_rate` requests a second. A request
/// over either limit is dropped without an answer, as a lost datagram
/// would be. A rate of 0 turns that limit off.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ProbeRateLimit {
    /// Requests a second each source may sustain (default 1).
    pub per_source_rate: f64,
    /// Requests a source may send at once (default 10).
    pub per_source_burst: u32,
    /// Requests a second answered over all sources (default 1000).
    pub total_rate: u32,
}

impl Default for ProbeRateLimit {
    fn default() -> Self {
        ProbeRateLimit {
            per_source_rate: 1.0,
            per_source_burst: 10,
            total_rate: 1000,
        }
    }
}

/// What kind of endpoint a Direct Link candidate is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectCandidateKind {
    /// The peer's public mapping, as the facilitator saw it.
    Reflexive,
    /// An address of one of the peer's own interfaces, for a peer on the
    /// same network.
    Host,
    /// An address the peer's authenticated punch packets came from that
    /// it did not signal (a NAT that maps each destination apart).
    PeerReflexive,
}

impl DirectCandidateKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            DirectCandidateKind::Reflexive => "reflexive",
            DirectCandidateKind::Host => "host",
            DirectCandidateKind::PeerReflexive => "peer_reflexive",
        }
    }
}

/// Counts of Direct Link upgrades, node-wide or for one link.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirectLinkCounters {
    /// Upgrades this node proposed (each that got as far as probing).
    pub proposed: u64,
    /// Upgrade requests from a peer this node took up as the responder.
    pub accepted: u64,
    /// Upgrades that established a direct path.
    pub established: u64,
    /// Upgrades that failed, each counted under its reason code (see
    /// `rns_core::holepunch::types`), in ascending order of the code.
    pub failed: Vec<(u8, u64)>,
    /// Direct paths lost after they were established.
    pub lost: u64,
}

impl DirectLinkCounters {
    /// All failures, whatever their reason.
    pub fn failed_total(&self) -> u64 {
        self.failed.iter().map(|(_, n)| n).sum()
    }
}

/// The direct path a link runs over.
#[derive(Debug, Clone, PartialEq)]
pub struct DirectPathStatus {
    pub interface_id: rns_core::transport::types::InterfaceId,
    pub session_id: [u8; 16],
    /// This side proposed the upgrade.
    pub initiator: bool,
    /// The peer's address on the direct path.
    pub peer_addr: std::net::SocketAddr,
    /// What kind of candidate that address was.
    pub candidate: DirectCandidateKind,
    /// The candidates the punch sent to, with their kinds.
    pub candidates: Vec<(std::net::SocketAddr, DirectCandidateKind)>,
    /// Round trip measured by the punch, in seconds.
    pub rtt: f64,
    /// MTU of the direct interface: 1200 until path MTU discovery finds a
    /// larger one.
    pub mtu: u32,
    /// Path MTU discovery has reported.
    pub mtu_discovered: bool,
    /// Largest link packet the peer accepts on the path, as it advertised
    /// during the upgrade (`m`); `None` from a peer that did not, which is
    /// sent nothing above the link's MTU.
    pub peer_max_packet: Option<u32>,
    /// When the path was established.
    pub since: f64,
}

/// Why a link left its direct path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectLossCause {
    /// The direct interface went down: no keepalive for its timeout, or a
    /// socket error.
    InterfaceDown,
    /// The link went stale, or its channel ran out of retries, on the
    /// direct path.
    LinkFailed,
    /// The peer said it fell back.
    PeerFallback,
}

impl DirectLossCause {
    pub fn as_str(&self) -> &'static str {
        match self {
            DirectLossCause::InterfaceDown => "interface_down",
            DirectLossCause::LinkFailed => "link_failed",
            DirectLossCause::PeerFallback => "peer_fallback",
        }
    }
}

/// Direct Link state of one link.
#[derive(Debug, Clone, PartialEq)]
pub struct DirectLinkEntry {
    pub link_id: [u8; 16],
    /// The direct path the link runs over, or `None` when it runs over its
    /// original (transport) path.
    pub direct: Option<DirectPathStatus>,
    /// The state of the upgrade in progress or last run on the link
    /// (`discovering`, `proposing`, `waiting_ready`, `punching`,
    /// `connected`, `failed`), if any.
    pub session_state: Option<&'static str>,
    /// The link peer implements Direct Link: `Some(true)` once it answered
    /// or signalled, `None` when not known.
    pub peer_supported: Option<bool>,
    pub counters: DirectLinkCounters,
    /// The reason code of the last failure and when it happened.
    pub last_failure: Option<(u8, f64)>,
    /// Why and when the link last lost its direct path.
    pub last_loss: Option<(DirectLossCause, f64)>,
    /// Re-upgrade proposals made since the last loss, and when the next
    /// is due, while the link proposes again by itself.
    pub reupgrade: Option<(u32, Option<f64>)>,
}

/// Counts of a node's own probe server over its life.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProbeServerReport {
    /// Probe requests answered.
    pub answered: u64,
    /// Probe requests dropped over the rate limits.
    pub rate_limited: u64,
}

/// The state of Direct Link on a node.
#[derive(Debug, Clone, PartialEq)]
pub struct DirectLinkStatus {
    /// The node takes part in Direct Link at all.
    pub enabled: bool,
    /// The facilitators this node probes, in the order it tries them.
    pub probe_servers: Vec<std::net::SocketAddr>,
    /// What this node's own probe server (`probe_port`) has answered and
    /// dropped over its rate limits, when it runs one.
    pub probe_server: Option<ProbeServerReport>,
    /// Counts over the node's life.
    pub totals: DirectLinkCounters,
    /// Links with Direct Link activity, ordered by link id.
    pub links: Vec<DirectLinkEntry>,
}

/// The name of a Direct Link failure or reject reason code.
pub fn direct_link_reason_name(reason: u8) -> &'static str {
    use rns_core::holepunch::types as t;
    match reason {
        t::REJECT_POLICY => "policy",
        t::REJECT_BUSY => "busy",
        t::REJECT_UNSUPPORTED => "unsupported",
        t::REJECT_NO_ENDPOINT => "no_endpoint",
        t::FAIL_TIMEOUT => "timeout",
        t::FAIL_PROBE => "probe",
        t::FAIL_NOT_STARTED => "not_started",
        _ => "unknown",
    }
}
