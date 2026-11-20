use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::RxMetadata;
use crate::constants;

/// Default for [`TransportConfig::max_path_destinations`].
pub const DEFAULT_MAX_PATH_DESTINATIONS: usize = 8192;

/// Shared, immutable packet bytes, cheap to clone into several actions.
pub type PacketBytes = Arc<[u8]>;

/// Opaque identifier for a network interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InterfaceId(pub u64);

/// Packet airtime model for interfaces where payload transmit time is not
/// accurately represented by payload bits divided by a raw bit rate.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AirtimeProfile {
    /// LoRa radio airtime, from the standard LoRa time-on-air formula.
    Lora {
        /// Channel bandwidth in Hz.
        bandwidth: u32,
        /// Spreading factor; 0 makes the airtime zero.
        spreading_factor: u8,
        /// Coding rate denominator, as in 4/5..4/8 (5..=8).
        coding_rate: u8,
        /// Number of preamble symbols.
        preamble_symbols: u16,
        /// Whether packets carry an explicit header.
        explicit_header: bool,
        /// Whether packets carry a payload CRC.
        crc: bool,
    },
}

impl AirtimeProfile {
    /// Time on air for a payload of `payload_len` bytes, in seconds.
    pub fn transmit_time_secs(&self, payload_len: usize) -> f64 {
        match *self {
            AirtimeProfile::Lora {
                bandwidth,
                spreading_factor,
                coding_rate,
                preamble_symbols,
                explicit_header,
                crc,
            } => lora_airtime_secs(
                payload_len,
                bandwidth,
                spreading_factor,
                coding_rate,
                preamble_symbols,
                explicit_header,
                crc,
            ),
        }
    }
}

fn lora_airtime_secs(
    payload_len: usize,
    bandwidth: u32,
    spreading_factor: u8,
    coding_rate: u8,
    preamble_symbols: u16,
    explicit_header: bool,
    crc: bool,
) -> f64 {
    if bandwidth == 0 || spreading_factor == 0 {
        return 0.0;
    }

    let sf = spreading_factor as f64;
    let symbol_time = libm::pow(2f64, (spreading_factor as i32) as f64) / bandwidth as f64;
    let low_data_rate_optimize = spreading_factor >= 11 && bandwidth <= 125_000;
    let de = if low_data_rate_optimize { 1.0 } else { 0.0 };
    let ih = if explicit_header { 0.0 } else { 1.0 };
    let crc = if crc { 1.0 } else { 0.0 };
    let denominator = 4.0 * (sf - 2.0 * de);
    if denominator <= 0.0 {
        return 0.0;
    }

    let numerator = 8.0 * payload_len as f64 - 4.0 * sf + 28.0 + 16.0 * crc - 20.0 * ih;
    let payload_symbols = 8.0 + libm::ceil(numerator / denominator).max(0.0) * coding_rate as f64;
    let preamble_time = (preamble_symbols as f64 + 4.25) * symbol_time;
    let payload_time = payload_symbols * symbol_time;
    preamble_time + payload_time
}

/// Per-interface ingress-control configuration.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IngressControlConfig {
    /// Hold announces and gate path requests during ingress bursts (upstream `ingress_control`).
    pub enabled: bool,
    /// Gate outgoing path requests by their frequency (upstream `egress_control`).
    pub egress_enabled: bool,
    /// Maximum announces held per interface during a burst.
    pub max_held_announces: usize,
    /// Announce burst threshold while the interface is younger than `new_time`, in announces per second.
    pub burst_freq_new: f64,
    /// Announce burst threshold once the interface is older than `new_time`, in announces per second.
    pub burst_freq: f64,
    /// Path request burst threshold while the interface is younger than `new_time`, in requests per second.
    pub pr_burst_freq_new: f64,
    /// Path request burst threshold once the interface is older than `new_time`, in requests per second.
    pub pr_burst_freq: f64,
    /// Outgoing path request frequency above which egress control limits, in requests per second.
    pub egress_pr_freq: f64,
    /// Age below which the interface counts as new, in seconds.
    pub new_time: f64,
    /// Minimum time a burst stays active after it starts or was last sustained, in seconds.
    pub burst_hold: f64,
    /// Delay after a burst starts before held announces may be released, in seconds.
    pub burst_penalty: f64,
    /// Delay between releasing two held announces, in seconds.
    pub held_release_interval: f64,
}

impl IngressControlConfig {
    /// Default configuration with ingress control on.
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }

    /// Default configuration with ingress control off.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }
}

impl Default for IngressControlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            egress_enabled: false,
            max_held_announces: constants::IC_MAX_HELD_ANNOUNCES,
            burst_freq_new: constants::IC_BURST_FREQ_NEW,
            burst_freq: constants::IC_BURST_FREQ,
            pr_burst_freq_new: constants::IC_PR_BURST_FREQ_NEW,
            pr_burst_freq: constants::IC_PR_BURST_FREQ,
            egress_pr_freq: constants::EC_PR_FREQ,
            new_time: constants::IC_NEW_TIME,
            burst_hold: constants::IC_BURST_HOLD,
            burst_penalty: constants::IC_BURST_PENALTY,
            held_release_interval: constants::IC_HELD_RELEASE_INTERVAL,
        }
    }
}

/// Per-interface stamp cost overrides (upstream 9b464382, the interface
/// options `destination_cost` and `pr_cost`, read with `as_float` and
/// clamped to `0..=STAMP_COST_CAP`). `None` uses the node-wide
/// `Transport.DESTINATION_COST` / `PR_COST`, as the upstream
/// `Interface.destination_cost` and `pr_cost` properties do.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceStampCosts {
    /// Announce stamp cost override for this interface (upstream `destination_cost`).
    pub destination_cost: Option<crate::stamp::StampCost>,
    /// Path request stamp cost override for this interface (upstream `pr_cost`).
    pub pr_cost: Option<crate::stamp::StampCost>,
}

impl InterfaceStampCosts {
    /// The announce cost required on this interface.
    pub fn destination_cost(&self, requirements: &StampRequirements) -> crate::stamp::StampCost {
        self.destination_cost
            .unwrap_or(requirements.destination_cost)
    }

    /// The path request cost required on this interface.
    pub fn pr_cost(&self, requirements: &StampRequirements) -> crate::stamp::StampCost {
        self.pr_cost.unwrap_or(requirements.path_request_cost)
    }
}

/// Metadata about a network interface.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// Identifier the transport uses for this interface.
    pub id: InterfaceId,
    /// Human-readable interface name.
    pub name: String,
    /// Interface mode, one of the `constants::MODE_*` values.
    pub mode: u8,
    /// Signed interface preference used by path selection.
    pub gravity: i64,
    /// Discover paths for unknown destinations on path requests from this interface, whatever its mode (upstream `recursive_prs`).
    pub recursive_prs: bool,
    /// Rebroadcast here announces whose path was learnt on an internal-mode interface (upstream `announces_from_internal`).
    pub announces_from_internal: bool,
    /// Allow announces received here to propagate to internal-mode interfaces.
    pub announces_to_internal: Option<bool>,
    /// Whether the interface can send; only such interfaces get broadcasts and path requests.
    pub out_capable: bool,
    /// Whether the interface can receive.
    pub in_capable: bool,
    /// Interface bit rate in bits per second, if known.
    pub bitrate: Option<u64>,
    /// Airtime model used instead of `bitrate` for announce bandwidth accounting.
    pub airtime_profile: Option<AirtimeProfile>,
    /// Minimum time between announces from one destination, in seconds; `None` disables announce rate limiting.
    pub announce_rate_target: Option<f64>,
    /// Number of rate violations tolerated before a destination is blocked.
    pub announce_rate_grace: u32,
    /// Extra block time added to `announce_rate_target` once a destination is blocked, in seconds.
    pub announce_rate_penalty: f64,
    /// Announce bandwidth cap (fraction of bitrate). Default 0.02 (2%).
    pub announce_cap: f64,
    /// Whether this interface is a local shared-instance client.
    pub is_local_client: bool,
    /// Whether this interface wants tunnel synthesis on connect.
    pub wants_tunnel: bool,
    /// Whether the interface shares its medium with other nodes, as radio,
    /// serial and UDP links do (upstream `Interface.shared_medium`). An
    /// announce heard again on such an interface while it waits for
    /// rebroadcast is still rebroadcast there.
    pub shared_medium: bool,
    /// The interface's own hop limiter (upstream bb63dd44
    /// `Interface.hop_limiter`): an inbound packet whose hop count is not
    /// below it is a hop limiter hit, checked before the transport-wide
    /// `[filter] hop_limiter`. `None` when unset, and for a configured 0,
    /// which upstream treats as unset.
    pub hop_limiter: Option<u8>,
    /// Tunnel ID associated with this interface, if any.
    pub tunnel_id: Option<[u8; 32]>,
    /// Maximum transmission unit for this interface in bytes.
    ///
    /// The interface selects this before registration; the transport core does
    /// not recalculate or log MTU choices while processing packets.
    pub mtu: u32,
    /// Whether links routed over this interface may negotiate an MTU above
    /// the protocol default (upstream `AUTOCONFIGURE_MTU or FIXED_MTU`).
    /// When false, a link request leaving through this interface carries no
    /// MTU signalling, so the link uses the default MTU whatever `mtu` says.
    pub mtu_upgradable: bool,
    /// Ingress control behavior for this interface.
    pub ingress_control: IngressControlConfig,
    /// Stamp costs required of announces and path requests received here.
    pub stamp_costs: InterfaceStampCosts,
    /// Current incoming announce frequency (announces/sec), synced from driver.
    pub ia_freq: f64,
    /// Current incoming announce sample count, synced from driver.
    pub ia_samples: usize,
    /// Current incoming path request frequency (requests/sec), synced from driver.
    pub ip_freq: f64,
    /// Current outgoing path request frequency (requests/sec), synced from driver.
    pub op_freq: f64,
    /// Current outgoing path request sample count, synced from driver.
    pub op_samples: usize,
    /// When this interface was started (epoch seconds).
    pub started: f64,
}

/// A received and validated announce, see [`TransportAction::AnnounceReceived`].
#[derive(Debug, Clone)]
pub struct ReceivedAnnounce {
    /// Hash of the announced destination.
    pub destination_hash: [u8; 16],
    /// Hash of the announce packet, which upstream keeps with the known
    /// destination (`Identity.remember`'s `packet_hash`).
    pub packet_hash: [u8; 32],
    /// Hash of the announcing identity.
    pub identity_hash: [u8; 16],
    /// Public key of the announcing identity (X25519 then Ed25519, 32 bytes each).
    pub public_key: [u8; 64],
    /// Name hash of the destination's full name.
    pub name_hash: [u8; 10],
    /// Random hash of the announce (5 random bytes and a 5-byte timestamp).
    pub random_hash: [u8; 10],
    /// Ratchet public key, when the announce carries one.
    pub ratchet: Option<[u8; 32]>,
    /// Application data, when the announce carries any.
    pub app_data: Option<Vec<u8>>,
    /// Detached destination stamp, when present on the announce.
    pub stamp: Option<[u8; crate::constants::STAMP_LENGTH]>,
    /// Fractional stamp value, or zero when absent or invalid.
    pub stamp_value: crate::stamp::StampValue,
    /// Announced link request stamp cost, if present.
    pub lr_cost: Option<crate::stamp::StampCost>,
    /// Hop count after counting the hop to this node.
    pub hops: u8,
    /// Interface the announce arrived on.
    pub receiving_interface: InterfaceId,
    /// Receive metadata of the frame.
    pub rx: RxMetadata,
}

/// Actions produced by TransportEngine for the caller to execute.
#[derive(Debug, Clone)]
pub enum TransportAction {
    /// Send raw bytes on a specific interface.
    SendOnInterface {
        /// Interface to send on.
        interface: InterfaceId,
        /// Packet bytes.
        raw: PacketBytes,
    },
    /// Broadcast raw bytes on all OUT-capable interfaces, optionally excluding one.
    BroadcastOnAllInterfaces {
        /// Packet bytes.
        raw: PacketBytes,
        /// Interface to skip.
        exclude: Option<InterfaceId>,
    },
    /// Deliver a packet to a local destination.
    DeliverLocal {
        /// Destination the packet is addressed to.
        destination_hash: [u8; 16],
        /// The packet as received, with its hop count as on the wire,
        /// except for a link request proof or an LRRTT packet: their hop
        /// byte holds the count after this hop, which the link learns its
        /// distance from (upstream's `packet.hops`). Rewriting it in every
        /// packet would copy each one delivered.
        raw: PacketBytes,
        /// May be zeroed for a link resource part, part request or proof,
        /// whose hash nothing on its delivery path reads (see
        /// [`RawPacket::is_unhashed_link_resource`](crate::packet::RawPacket::is_unhashed_link_resource)).
        packet_hash: [u8; 32],
        /// Interface the packet arrived on.
        receiving_interface: InterfaceId,
    },
    /// An announce was received and validated. Boxed: it is by far the
    /// largest action, and every action moves at its size.
    AnnounceReceived(Box<ReceivedAnnounce>),
    /// A path was updated in the path table.
    PathUpdated {
        /// Destination whose path changed.
        destination_hash: [u8; 16],
        /// Hop count of the new path.
        hops: u8,
        /// Transport identity hash of the next hop, or the announced destination for a direct neighbour.
        next_hop: [u8; 16],
        /// Interface the path goes through.
        interface: InterfaceId,
    },
    /// Forward raw bytes to all local client interfaces (excluding one).
    ForwardToLocalClients {
        /// Packet bytes.
        raw: PacketBytes,
        /// Interface to skip.
        exclude: Option<InterfaceId>,
    },
    /// Forward a PLAIN/GROUP broadcast between local and external interfaces.
    ForwardPlainBroadcast {
        /// Packet bytes.
        raw: PacketBytes,
        /// Send to local client interfaces when true, to the other interfaces when false.
        to_local: bool,
        /// Interface to skip.
        exclude: Option<InterfaceId>,
    },
    /// Cache an announce packet to disk.
    CacheAnnounce {
        /// Hash of the announce packet.
        packet_hash: [u8; 32],
        /// Announce packet bytes.
        raw: PacketBytes,
    },
    /// Tunnel synthesis: send synthesis data on an interface.
    TunnelSynthesize {
        /// Interface to send on.
        interface: InterfaceId,
        /// Synthesis payload.
        data: Vec<u8>,
        /// Destination hash of `rnstransport.tunnel.synthesize`.
        dest_hash: [u8; 16],
    },
    /// A tunnel was established or reattached.
    TunnelEstablished {
        /// Tunnel identifier.
        tunnel_id: [u8; 32],
        /// Interface now attached to the tunnel.
        interface: InterfaceId,
    },
    /// An announce is being retransmitted (for hook notification).
    AnnounceRetransmit {
        /// Announced destination.
        destination_hash: [u8; 16],
        /// Hop count of the announce.
        hops: u8,
        /// Interface the announce goes out on, or `None` for all.
        interface: Option<InterfaceId>,
    },
    /// A link request was received and is being forwarded (transport relay).
    LinkRequestReceived {
        /// Identifier of the link.
        link_id: [u8; 16],
        /// Destination the link request is addressed to.
        destination_hash: [u8; 16],
        /// Interface the link request arrived on.
        receiving_interface: InterfaceId,
    },
    /// A link was established via LRPROOF validation (transport relay).
    LinkEstablished {
        /// Identifier of the link.
        link_id: [u8; 16],
        /// Interface the proof is forwarded on, toward the link initiator.
        interface: InterfaceId,
    },
    /// A link entry expired and was removed from the link table.
    LinkClosed {
        /// Identifier of the link.
        link_id: [u8; 16],
    },
    /// A malformed or cryptographically invalid packet was rejected.
    ProtocolViolation {
        /// Interface the packet arrived on.
        interface: InterfaceId,
    },
    /// A path request arrived for a destination registered on this node.
    ///
    /// Python `Transport.path_request()` answers it with
    /// `destination.announce(path_response=True, tag=tag,
    /// attached_interface=...)`. The engine holds no destination keys, so the
    /// caller must build an announce with context `PATH_RESPONSE` and send it
    /// only on `interface`. Path requests without a tag are dropped earlier,
    /// so `tag` always holds 1..=16 bytes.
    AnnounceLocalPathResponse {
        /// Local destination the request asks for.
        destination_hash: [u8; 16],
        /// Request tag to echo in the path response.
        tag: Vec<u8>,
        /// Interface the request arrived on.
        interface: InterfaceId,
    },
    /// A path request must be stamped by this node before it is sent on
    /// `interface`.
    ///
    /// Produced only while path request stamping is on, for a request from a
    /// local client that carried no stamp. Python `Transport.request_path`
    /// hands such a request to the stamper queue; the caller grinds the stamp
    /// off the engine thread and then sends `destination_hash || transport_id
    /// || tag || marker | flags | stamp` on `interface`. One action is produced
    /// per egress interface, matching upstream's one queue entry per
    /// `destination_hash + interface` key. `tag` holds 1..=16 bytes.
    StampPathRequest {
        /// Destination the request asks for.
        destination_hash: [u8; 16],
        /// Request tag.
        tag: Vec<u8>,
        /// Interface the stamped request goes out on.
        interface: InterfaceId,
    },
    /// Send a path request to rediscover `destination_hash`, taken from the
    /// rediscovery queue (`Transport.handle_disovery_path_requests`).
    ///
    /// With no `skip_interface` this is a plain `Transport.request_path`, as
    /// `Event::RequestPath` sends. Otherwise one request with a new tag goes
    /// out on every interface except `skip_interface`, stamped once when
    /// path request stamping is on (upstream acb38a8a).
    RediscoverPath {
        /// Destination to rediscover.
        destination_hash: [u8; 16],
        /// Interface to leave out, if any.
        skip_interface: Option<InterfaceId>,
    },
}

/// A blackholed identity entry.
#[derive(Debug, Clone)]
pub struct BlackholeEntry {
    /// When this entry was created.
    pub created: f64,
    /// When this entry expires (0.0 = never).
    pub expires: f64,
    /// Optional reason for blackholing.
    pub reason: Option<String>,
    /// Identity hash of the blackhole list this entry came from, or `None`
    /// for an entry made on this node (upstream records its own transport
    /// identity hash as the source of local entries).
    pub source: Option<[u8; 16]>,
}

/// Stamp requirements applied to received announces and path requests.
///
/// Upstream keeps these as `Transport` class attributes that the `[stamps]`
/// config section can override (Reticulum.py, d7749b0b): `enforce_stamps`
/// sets `STAMPS_ENFORCED`, and `destination_cost` / `pr_cost` set
/// `DESTINATION_COST` / `PR_COST`, clamped to `0..=STAMP_COST_CAP`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StampRequirements {
    /// Drop announces and path requests without a sufficient stamp
    /// (`Transport.STAMPS_ENFORCED`).
    pub enforced: bool,
    /// Required announce stamp value (`Transport.DESTINATION_COST`).
    pub destination_cost: crate::stamp::StampCost,
    /// Required path request stamp value (`Transport.PR_COST`).
    pub path_request_cost: crate::stamp::StampCost,
}

impl Default for StampRequirements {
    fn default() -> Self {
        Self {
            enforced: crate::constants::STAMPS_ENFORCED,
            destination_cost: crate::constants::DESTINATION_STAMP_COST,
            path_request_cost: crate::constants::PATH_REQUEST_STAMP_COST,
        }
    }
}

/// Startup allocation policy for the packet hash list.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum PacketHashlistAllocation {
    /// Touch every payload slot during construction: the full table's
    /// memory from the start.
    Eager,
    /// Grow payload storage and its index with occupancy, up to the
    /// retention limit: a node holds memory for the packets it has seen.
    #[default]
    Lazy,
}

/// How an announce may recover a destination's path once that path is
/// marked unresponsive (`[reticulum] unresponsive_path_recovery`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum UnresponsivePathRecovery {
    /// rns-rs's own rules. An already-heard announce (same emission time)
    /// replaces an unresponsive path only through the path's own next hop,
    /// over more hops, or, unlike upstream, over the same or fewer hops;
    /// through another next hop it is rejected. A replacement accepted only
    /// because the path is unresponsive is not rebroadcast.
    #[default]
    Native,
    /// Upstream Transport.py's rules for an unresponsive path: the path is
    /// decided as upstream's single path, and an accepted announce replaces
    /// it whatever its next hop. An already-heard announce over more hops
    /// replaces it without being rebroadcast; one over the same or fewer
    /// hops does not.
    Upstream,
}

/// Configuration for [`TransportEngine`](super::TransportEngine).
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Act as a transport node: forward packets and rebroadcast announces for others.
    pub transport_enabled: bool,
    /// Hash of this node's transport identity, used as its transport id.
    pub identity_hash: Option<[u8; 16]>,
    /// Non-zero hop byte used to mask local zero-hop origination.
    pub local_hops_delta: u8,
    /// Accept an announce with strictly fewer hops even when the random_blob
    /// is a duplicate of the existing path entry.  Default `false` preserves
    /// Python-compatible anti-replay behaviour.
    pub prefer_shorter_path: bool,
    /// Maximum number of alternative paths stored per destination.
    /// When >1, failover to the next-best path happens automatically
    /// when the primary becomes unresponsive.  Default 1 (single path,
    /// backward-compatible with Python Reticulum behaviour).
    pub max_paths_per_destination: usize,
    /// How an announce may recover an unresponsive path. Default
    /// [`UnresponsivePathRecovery::Native`].
    pub unresponsive_path_recovery: UnresponsivePathRecovery,
    /// Maximum number of packet hashes retained for duplicate suppression.
    pub packet_hashlist_max_entries: usize,
    /// Startup allocation policy for packet-hash payload storage.
    pub packet_hashlist_allocation: PacketHashlistAllocation,
    /// Maximum number of discovery path-request tags remembered for duplicate suppression.
    pub max_discovery_pr_tags: usize,
    /// Maximum number of destination hashes retained in the live path table.
    pub max_path_destinations: usize,
    /// Maximum number of destination hashes retained across all tunnel entries.
    pub max_tunnel_destinations_total: usize,
    /// Retention timeout for tunnel-known destinations, in seconds.
    pub destination_timeout_secs: f64,
    /// Retention timeout for announce retransmission state, in seconds.
    pub announce_table_ttl_secs: f64,
    /// Maximum retained bytes across announce retransmission state maps.
    pub announce_table_max_bytes: usize,
    /// Whether the announce signature verification cache is enabled.
    pub announce_sig_cache_enabled: bool,
    /// Maximum entries in the announce signature verification cache.
    pub announce_sig_cache_max_entries: usize,
    /// TTL for announce signature cache entries, in seconds.
    pub announce_sig_cache_ttl_secs: f64,
    /// Maximum entries in the async announce verification queue.
    pub announce_queue_max_entries: usize,
    /// Maximum number of interface-scoped announce queues retained.
    pub announce_queue_max_interfaces: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_id_ordering() {
        let a = InterfaceId(1);
        let b = InterfaceId(2);
        assert!(a < b);
        assert_eq!(a, InterfaceId(1));
    }

    #[test]
    fn test_transport_config_defaults() {
        let cfg = TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            unresponsive_path_recovery: crate::transport::types::UnresponsivePathRecovery::Native,
            packet_hashlist_max_entries: crate::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: crate::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: crate::constants::MAX_PR_TAGS,
            max_path_destinations: DEFAULT_MAX_PATH_DESTINATIONS,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: crate::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: crate::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: crate::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: crate::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: crate::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        };
        assert!(!cfg.transport_enabled);
        assert!(cfg.identity_hash.is_none());
        assert_eq!(cfg.local_hops_delta, 0);
        assert!(!cfg.prefer_shorter_path);
        assert_eq!(cfg.max_paths_per_destination, 1);
        assert_eq!(
            cfg.unresponsive_path_recovery,
            UnresponsivePathRecovery::default()
        );
        assert_eq!(
            UnresponsivePathRecovery::default(),
            UnresponsivePathRecovery::Native
        );
        assert_eq!(
            cfg.packet_hashlist_max_entries,
            crate::constants::HASHLIST_MAXSIZE
        );
        assert_eq!(cfg.max_discovery_pr_tags, crate::constants::MAX_PR_TAGS);
        assert_eq!(cfg.max_path_destinations, DEFAULT_MAX_PATH_DESTINATIONS);
        assert_eq!(cfg.max_tunnel_destinations_total, usize::MAX);
        assert_eq!(
            cfg.destination_timeout_secs,
            crate::constants::DESTINATION_TIMEOUT
        );
        assert_eq!(
            cfg.announce_table_ttl_secs,
            crate::constants::ANNOUNCE_TABLE_TTL
        );
        assert_eq!(
            cfg.announce_table_max_bytes,
            crate::constants::ANNOUNCE_TABLE_MAX_BYTES
        );
        assert!(cfg.announce_sig_cache_enabled);
        assert_eq!(
            cfg.announce_sig_cache_max_entries,
            crate::constants::ANNOUNCE_SIG_CACHE_MAXSIZE
        );
        assert_eq!(
            cfg.announce_sig_cache_ttl_secs,
            crate::constants::ANNOUNCE_SIG_CACHE_TTL
        );
        assert_eq!(cfg.announce_queue_max_entries, 256);
        assert_eq!(cfg.announce_queue_max_interfaces, 1024);
    }

    fn lora(
        spreading_factor: u8,
        coding_rate: u8,
        explicit_header: bool,
        crc: bool,
    ) -> AirtimeProfile {
        AirtimeProfile::Lora {
            bandwidth: 125_000,
            spreading_factor,
            coding_rate,
            preamble_symbols: 8,
            explicit_header,
            crc,
        }
    }

    /// LoRa time on air: (preamble + 4.25 + 8 + ceil((8PL - 4SF + 28 +
    /// 16CRC - 20IH) / (4(SF - 2DE))) * CR) symbols of 2^SF / BW seconds,
    /// with low data rate optimisation (DE) from SF11 at 125 kHz or less.
    #[test]
    fn lora_airtime_follows_the_time_on_air_formula() {
        // SF12/BW125 with DE: (8 + 4.25 + 8 + ceil(244 / 40) * 5) symbols
        // of 32.768 ms.
        let airtime = lora(12, 5, true, true).transmit_time_secs(31);
        assert!((airtime - 55.25 * 0.032768).abs() < 1e-9, "{airtime}");

        // SF7/BW125, implicit header, no CRC: (8 + 4.25 + 8 + ceil(28 / 28)
        // * 8) symbols of 1.024 ms.
        let airtime = lora(7, 8, false, false).transmit_time_secs(6);
        assert!((airtime - 28.25 * 0.001024).abs() < 1e-9, "{airtime}");
    }

    #[test]
    fn lora_airtime_without_bandwidth_or_spreading_factor_is_zero() {
        let profile = AirtimeProfile::Lora {
            bandwidth: 0,
            spreading_factor: 7,
            coding_rate: 5,
            preamble_symbols: 8,
            explicit_header: true,
            crc: true,
        };
        assert_eq!(profile.transmit_time_secs(30), 0.0);
        assert_eq!(lora(0, 5, true, true).transmit_time_secs(30), 0.0);
    }
}
