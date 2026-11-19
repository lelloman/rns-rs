//! ConfigObj parser for RNS config files.
//!
//! Python RNS uses ConfigObj format — NOT TOML, NOT standard INI.
//! Key differences: nested `[[sections]]`, booleans `Yes`/`No`/`True`/`False`,
//! comments with `#`, unquoted string values.

mod hooks;
mod interfaces;
mod parse;
mod reticulum;
mod sections;
#[cfg(test)]
mod tests;

pub use hooks::*;
use interfaces::*;
pub use parse::*;
use reticulum::*;
use sections::*;

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::Path;

use rns_core::stamp::StampCost;

/// Parsed RNS configuration.
#[derive(Debug, Clone)]
pub struct RnsConfig {
    pub reticulum: ReticulumSection,
    pub logging: LoggingSection,
    pub stamps: StampsSection,
    pub filter: FilterSection,
    pub interfaces: Vec<ParsedInterface>,
    pub hooks: Vec<ParsedHook>,
}

/// A parsed hook from `[[subsection]]` within `[hooks]`.
#[derive(Debug, Clone)]
pub struct ParsedHook {
    pub name: String,
    pub path: String,
    pub hook_type: String,
    pub builtin_id: Option<String>,
    pub attach_point: String,
    pub priority: i32,
    pub enabled: bool,
}

/// How a node auto-connects discovered interfaces (`[reticulum]
/// autoconnect_policy`), chosen at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AutoconnectPolicy {
    /// Upstream's behaviour: up to `autoconnect_discovered_interfaces`
    /// discovered Backbone interfaces, on top of the configured ones, with
    /// `bootstrap_only` interfaces torn down while enough are online.
    #[default]
    Upstream,
    /// The rns-rs Backbone peer pool (`backbone_peer_pool_*`), which holds
    /// configured and discovered Backbone peers under one cap.
    Pool,
}

/// The `[reticulum]` section.
#[derive(Debug, Clone)]
pub struct ReticulumSection {
    pub enable_transport: bool,
    /// Inbound packets whose hop count reaches this limit are dropped and
    /// counted as `hop_limiter_hits`: `[filter] hop_limiter`, clamped to
    /// `0..=PATHFINDER_M` (upstream 01aef5bc), so 0 drops every packet.
    pub hop_limiter: u8,
    pub static_transport_identity: bool,
    pub local_hops_delta: bool,
    pub share_instance: bool,
    /// Allow local shared-instance clients to attach, detach, and reload interfaces.
    pub enable_interface_management: bool,
    pub instance_name: String,
    pub shared_instance_port: u16,
    pub instance_control_port: u16,
    pub panic_on_interface_error: bool,
    pub use_implicit_proof: bool,
    pub network_identity: Option<String>,
    pub respond_to_probes: bool,
    pub enable_remote_management: bool,
    pub remote_management_allowed: Vec<String>,
    pub publish_blackhole: bool,
    /// Transport identity hashes whose published blackhole lists this
    /// instance fetches and applies (`blackhole_sources`).
    pub blackhole_sources: Vec<[u8; 16]>,
    /// How often each blackhole source is fetched, in seconds; upstream's
    /// `blackhole_update_interval` is given in minutes, at least 2. `None`
    /// keeps upstream's default of an hour.
    pub blackhole_update_interval: Option<f64>,
    /// Network identities whose discovered interfaces are accepted
    /// (`interface_discovery_sources`); empty accepts any.
    pub interface_discovery_sources: Vec<[u8; 16]>,
    /// `shared_instance_type = tcp` keeps the shared instance and its RPC on
    /// TCP; otherwise Linux uses abstract Unix sockets, as upstream does.
    pub shared_instance_tcp: bool,
    /// The shared instance RPC key (`rpc_key`), in place of the one derived
    /// from the transport identity.
    pub rpc_key: Option<[u8; 32]>,
    /// The bitrate the shared instance interface reports
    /// (`force_shared_instance_bitrate`), in bits per second.
    pub force_shared_instance_bitrate: Option<u64>,
    pub probe_port: Option<u16>,
    pub probe_addr: Option<String>,
    /// Protocol for endpoint discovery: "rnsp" (default) or "stun".
    pub probe_protocol: Option<String>,
    /// Policy for incoming direct-connect proposals (default `reject`).
    pub direct_connect_policy: crate::event::HolePunchPolicy,
    /// Accept direct-connect endpoints in private, shared, link-local,
    /// and unique-local ranges (LAN-only deployments).
    pub direct_connect_allow_private_endpoints: bool,
    /// Identities whose direct-connect proposals are always accepted
    /// (`direct_connect_allowed_identities`).
    pub direct_connect_allowed_identities: Vec<[u8; 16]>,
    /// Automatic re-upgrade after a direct path is lost
    /// (`direct_connect_reupgrade*`).
    pub direct_connect_reupgrade: crate::event::DirectReupgradeConfig,
    /// Rate limits of the probe server (`probe_source_rate`,
    /// `probe_source_burst`, `probe_total_rate`).
    pub probe_rate_limit: crate::event::ProbeRateLimit,
    /// Network interface to bind outbound sockets to (e.g. "usb0").
    pub device: Option<String>,
    /// Linux `SO_MARK` value applied to Reticulum IP underlay sockets.
    pub underlay_mark: Option<u32>,
    /// Enable interface discovery (advertise discoverable interfaces and
    /// listen for discovery announces from the network).
    pub discover_interfaces: bool,
    /// Global gravity used by interfaces without an explicit override.
    pub default_gravity: i64,
    /// Mode assigned to auto-connected interfaces.
    pub autoconnect_interface_mode: Option<String>,
    /// Gravity assigned to auto-connected interfaces.
    pub autoconnect_interface_gravity: i64,
    /// Allow auto-connected interfaces to propagate announces to internal interfaces.
    pub autoconnect_announces_to_internal: bool,
    /// Allow auto-connecting discovered interfaces from unverified implementations.
    pub autoconnect_unverified_implementations: bool,
    /// How discovered interfaces are auto-connected (`autoconnect_policy`).
    pub autoconnect_policy: AutoconnectPolicy,
    /// Upstream's `autoconnect_discovered_interfaces`: how many discovered
    /// interfaces to auto-connect; 0 auto-connects none.
    pub autoconnect_discovered_interfaces: usize,
    /// Minimum stamp value for accepting discovered interfaces, fractional
    /// since upstream 796ef2d4. A value of 0 or less leaves the default.
    pub required_discovery_value: Option<StampCost>,
    /// Accept an announce with strictly fewer hops even when the random_blob
    /// is a duplicate of the existing path entry.
    pub prefer_shorter_path: bool,
    /// Maximum number of alternative paths stored per destination.
    /// Default 1 (single path, backward-compatible).
    pub max_paths_per_destination: usize,
    /// Maximum number of packet hashes retained for duplicate suppression.
    pub packet_hashlist_max_entries: usize,
    /// Startup allocation policy for the packet hashlist payload pages.
    pub packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation,
    /// Maximum number of discovery path-request tags remembered.
    pub max_discovery_pr_tags: usize,
    /// Maximum number of destinations retained in the live path table.
    pub max_path_destinations: usize,
    /// Maximum number of destinations retained across tunnel-known paths.
    pub max_tunnel_destinations_total: usize,
    /// TTL for recalled known destinations without an active path, in seconds.
    pub known_destinations_ttl: u64,
    /// Maximum number of recalled known destinations retained.
    pub known_destinations_max_entries: usize,
    /// TTL for received ratchets, in seconds.
    pub ratchet_expiry: u64,
    /// TTL for announce retransmission state, in seconds.
    pub announce_table_ttl: u64,
    /// Maximum retained bytes for announce retransmission state.
    pub announce_table_max_bytes: usize,
    /// Whether the announce signature verification cache is enabled.
    pub announce_sig_cache_enabled: bool,
    /// Maximum entries in the announce signature verification cache.
    pub announce_sig_cache_max_entries: usize,
    /// TTL for announce signature cache entries, in seconds.
    pub announce_sig_cache_ttl: u64,
    /// Maximum entries in the async announce verification queue.
    pub announce_queue_max_entries: usize,
    /// Maximum interface-scoped announce queues retained.
    pub announce_queue_max_interfaces: usize,
    /// Default announce-rate target for transport-node interfaces, in seconds.
    pub default_ar_target: Option<f64>,
    /// Default announce-rate penalty for transport-node interfaces, in seconds.
    pub default_ar_penalty: f64,
    /// Default announce-rate grace count for transport-node interfaces.
    pub default_ar_grace: u32,
    /// Default maximum held announces for ingress control.
    pub default_ic_max_held_announces: usize,
    /// Default announce burst hold time for ingress control.
    pub default_ic_burst_hold: f64,
    /// Default new-interface announce burst threshold.
    pub default_ic_burst_freq_new: f64,
    /// Default mature-interface announce burst threshold.
    pub default_ic_burst_freq: f64,
    /// Default new-interface path request burst threshold.
    pub default_ic_pr_burst_freq_new: f64,
    /// Default mature-interface path request burst threshold.
    pub default_ic_pr_burst_freq: f64,
    /// Default new-interface age window for ingress control.
    pub default_ic_new_time: f64,
    /// Default burst penalty before releasing held announces.
    pub default_ic_burst_penalty: f64,
    /// Default interval between released held announces.
    pub default_ic_held_release_interval: f64,
    /// Default egress path request limiting state.
    pub default_egress_control: bool,
    /// Default egress path request frequency threshold.
    pub default_ec_pr_freq: f64,
    /// Maximum retained bytes in the async announce verification queue.
    pub announce_queue_max_bytes: usize,
    /// TTL for queued async announce verification entries, in seconds.
    pub announce_queue_ttl: u64,
    /// Overflow policy for the async announce verification queue.
    pub announce_queue_overflow_policy: String,
    /// Maximum queued events awaiting driver processing.
    pub driver_event_queue_capacity: usize,
    /// Independently bounded inbound traffic-class queues.
    pub inbound_queue_capacities: crate::event::InboundQueueCapacities,
    /// Maximum queued outbound frames per interface writer worker.
    pub interface_writer_queue_capacity: usize,
    /// Maximum active outbound Backbone peer-pool connections. Zero disables pooling.
    pub backbone_peer_pool_max_connected: usize,
    /// Failures within the failure window before a discovered pooled Backbone
    /// peer enters cooldown. Configured peers never enter cooldown: they retry
    /// with the Backbone client backoff (reconnect wait doubled per failure,
    /// capped at 64x, i.e. 320 s by default, with ±25 % jitter).
    pub backbone_peer_pool_failure_threshold: usize,
    /// Failure accounting window for pooled Backbone peers, in seconds.
    pub backbone_peer_pool_failure_window: u64,
    /// Cooldown duration for failed discovered pooled Backbone peers, in seconds.
    pub backbone_peer_pool_cooldown: u64,
    #[cfg(feature = "hooks")]
    pub provider_bridge: bool,
    #[cfg(feature = "hooks")]
    pub provider_socket_path: Option<String>,
    #[cfg(feature = "hooks")]
    pub provider_queue_max_events: usize,
    #[cfg(feature = "hooks")]
    pub provider_queue_max_bytes: usize,
    #[cfg(feature = "hooks")]
    pub provider_overflow_policy: String,
}

impl Default for ReticulumSection {
    fn default() -> Self {
        ReticulumSection {
            enable_transport: false,
            hop_limiter: rns_core::constants::HOP_LIMITER,
            static_transport_identity: false,
            local_hops_delta: false,
            share_instance: true,
            enable_interface_management: true,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            instance_control_port: 37429,
            panic_on_interface_error: false,
            use_implicit_proof: true,
            network_identity: None,
            respond_to_probes: false,
            enable_remote_management: false,
            remote_management_allowed: Vec::new(),
            publish_blackhole: false,
            blackhole_sources: Vec::new(),
            blackhole_update_interval: None,
            interface_discovery_sources: Vec::new(),
            shared_instance_tcp: false,
            rpc_key: None,
            force_shared_instance_bitrate: None,
            probe_port: None,
            probe_addr: None,
            probe_protocol: None,
            direct_connect_policy: crate::event::HolePunchPolicy::Reject,
            direct_connect_allow_private_endpoints: false,
            direct_connect_allowed_identities: Vec::new(),
            direct_connect_reupgrade: Default::default(),
            probe_rate_limit: Default::default(),
            device: None,
            underlay_mark: None,
            discover_interfaces: false,
            default_gravity: 0,
            autoconnect_interface_mode: None,
            autoconnect_interface_gravity: 0,
            autoconnect_announces_to_internal: false,
            autoconnect_unverified_implementations: false,
            autoconnect_policy: AutoconnectPolicy::Upstream,
            autoconnect_discovered_interfaces: 0,
            required_discovery_value: None,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Lazy,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: rns_core::transport::types::DEFAULT_MAX_PATH_DESTINATIONS,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: 48 * 60 * 60,
            known_destinations_max_entries: 8192,
            ratchet_expiry: rns_core::constants::RATCHET_EXPIRY,
            announce_table_ttl: rns_core::constants::ANNOUNCE_TABLE_TTL as u64,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
            default_ar_target: Some(3600.0),
            default_ar_penalty: 0.0,
            default_ar_grace: 5,
            default_ic_max_held_announces: rns_core::constants::IC_MAX_HELD_ANNOUNCES,
            default_ic_burst_hold: rns_core::constants::IC_BURST_HOLD,
            default_ic_burst_freq_new: rns_core::constants::IC_BURST_FREQ_NEW,
            default_ic_burst_freq: rns_core::constants::IC_BURST_FREQ,
            default_ic_pr_burst_freq_new: rns_core::constants::IC_PR_BURST_FREQ_NEW,
            default_ic_pr_burst_freq: rns_core::constants::IC_PR_BURST_FREQ,
            default_ic_new_time: rns_core::constants::IC_NEW_TIME,
            default_ic_burst_penalty: rns_core::constants::IC_BURST_PENALTY,
            default_ic_held_release_interval: rns_core::constants::IC_HELD_RELEASE_INTERVAL,
            default_egress_control: false,
            default_ec_pr_freq: rns_core::constants::EC_PR_FREQ,
            announce_queue_max_bytes: 256 * 1024,
            announce_queue_ttl: 30,
            announce_queue_overflow_policy: "drop_worst".into(),
            driver_event_queue_capacity: crate::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            inbound_queue_capacities: crate::event::InboundQueueCapacities::default(),
            interface_writer_queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            backbone_peer_pool_max_connected: 0,
            backbone_peer_pool_failure_threshold: 3,
            backbone_peer_pool_failure_window: 600,
            backbone_peer_pool_cooldown: 900,
            #[cfg(feature = "hooks")]
            provider_bridge: false,
            #[cfg(feature = "hooks")]
            provider_socket_path: None,
            #[cfg(feature = "hooks")]
            provider_queue_max_events: 16384,
            #[cfg(feature = "hooks")]
            provider_queue_max_bytes: 8 * 1024 * 1024,
            #[cfg(feature = "hooks")]
            provider_overflow_policy: "drop_newest".into(),
        }
    }
}

/// The `[stamps]` section (upstream d7749b0b, Reticulum.py `__apply_config`).
///
/// The boolean options can only enable a feature: upstream applies them as
/// `if value == True: Transport.X = True`, so `no` leaves the built-in
/// default in place. Costs and values are read as floats (`as_float`, since
/// upstream 796ef2d4) and clamped to `0..=STAMP_COST_CAP` (`lr_cost` to
/// `0..=LINK_COST_CAP`). The timeouts are floored at 20 ms.
#[derive(Debug, Clone, PartialEq)]
pub struct StampsSection {
    /// `Transport.STAMPS_ENFORCED`, set by `enforce_stamps`.
    pub stamps_enforced: bool,
    /// `Transport.LR_STAMPS_ENFORCED`, also set by `enforce_stamps`.
    pub lr_stamps_enforced: bool,
    /// `Transport.STAMP_DESTINATIONS` (`stamp_destinations`).
    pub stamp_destinations: bool,
    /// `Transport.STAMP_PRS` (`stamp_prs`).
    pub stamp_prs: bool,
    /// `Transport.STAMP_LRS`. Upstream a8cc6cb2 turned it back on and
    /// removed its `stamp_lrs` option; it stays switchable at runtime through
    /// `global.stamp_link_requests`.
    pub stamp_lrs: bool,
    /// `Transport.ALWAYS_STAMP_LRS` (`always_stamp_lrs`).
    pub always_stamp_lrs: bool,
    /// `Transport.DESTINATION_COST` (`destination_cost`).
    pub destination_cost: StampCost,
    /// `Transport.DESTINATION_VALUE` (`destination_value`).
    pub destination_value: StampCost,
    /// `Transport.PR_COST` (`pr_cost`).
    pub pr_cost: StampCost,
    /// `Transport.PR_VALUE` (`pr_value`).
    pub pr_value: StampCost,
    /// `Transport.LR_COST` (`lr_cost`).
    pub lr_cost: StampCost,
    /// `Transport.LINK_STAMP_TIMEOUT` in seconds (`lr_stamp_timeout`).
    pub lr_stamp_timeout: f64,
    /// `Transport.PR_STAMP_TIMEOUT` in seconds (`pr_stamp_timeout`).
    pub pr_stamp_timeout: f64,
    /// `Stamps.MAX_WORKERS` (`max_workers`, at least 1): the most threads
    /// one stamp search uses. `None` keeps the default.
    pub max_workers: Option<usize>,
    /// `Stamps.NICENESS` (`worker_niceness`, 0 to 20, default 16): the
    /// scheduling niceness of stamp search threads.
    pub worker_niceness: i32,
}

/// The `[filter]` section (upstream 825c2e19): announce filtering by
/// destination type. `required_only` is read with `as_bool` and assigned,
/// and the two type lists with `as_list`, as full destination names such as
/// `lxmf.delivery` or, since upstream e96c81c3, name hashes written as
/// `<hex>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterSection {
    /// `Transport.required_destinations_only` (`required_only`).
    pub required_only: bool,
    /// Types blocked with `Transport.block_destination_type`
    /// (`ignored_types`).
    pub ignored_types: Vec<String>,
    /// Types allowed with `Transport.allow_destination_type`
    /// (`allowed_types`).
    pub allowed_types: Vec<String>,
}

impl FilterSection {
    /// The engine filter this section configures.
    pub fn destination_filter(
        &self,
    ) -> rns_core::transport::destination_filter::DestinationTypeFilter {
        use rns_core::transport::destination_filter::{
            configured_destination_type, DestinationTypeFilter,
        };
        let mut filter = DestinationTypeFilter::default();
        filter.set_required_only(self.required_only);
        for destination_type in self
            .ignored_types
            .iter()
            .filter_map(|name| configured_destination_type(name))
        {
            filter.block(destination_type);
        }
        for destination_type in self
            .allowed_types
            .iter()
            .filter_map(|name| configured_destination_type(name))
        {
            filter.allow(destination_type);
        }
        filter
    }
}

impl Default for StampsSection {
    fn default() -> Self {
        use rns_core::constants;
        StampsSection {
            stamps_enforced: constants::STAMPS_ENFORCED,
            lr_stamps_enforced: constants::LR_STAMPS_ENFORCED,
            stamp_destinations: constants::STAMP_DESTINATIONS,
            stamp_prs: constants::STAMP_PRS,
            stamp_lrs: constants::STAMP_LRS,
            always_stamp_lrs: constants::ALWAYS_STAMP_LRS,
            destination_cost: constants::DESTINATION_STAMP_COST,
            destination_value: constants::DESTINATION_STAMP_VALUE,
            pr_cost: constants::PATH_REQUEST_STAMP_COST,
            pr_value: constants::PATH_REQUEST_STAMP_VALUE,
            lr_cost: constants::LINK_REQUEST_STAMP_COST,
            lr_stamp_timeout: constants::LINK_STAMP_TIMEOUT as f64,
            pr_stamp_timeout: constants::PATH_REQUEST_STAMP_TIMEOUT as f64,
            max_workers: None,
            worker_niceness: crate::stamps::DEFAULT_WORKER_NICENESS,
        }
    }
}

impl StampsSection {
    /// The announce and path request requirements for the transport engine.
    pub fn requirements(&self) -> rns_core::transport::types::StampRequirements {
        rns_core::transport::types::StampRequirements {
            enforced: self.stamps_enforced,
            destination_cost: self.destination_cost,
            path_request_cost: self.pr_cost,
        }
    }

    /// The link request stamp timeout as a duration.
    pub fn link_stamp_timeout(&self) -> std::time::Duration {
        stamp_timeout_duration(self.lr_stamp_timeout)
    }

    /// The path request stamp timeout as a duration.
    pub fn path_request_stamp_timeout(&self) -> std::time::Duration {
        stamp_timeout_duration(self.pr_stamp_timeout)
    }
}

/// The `[logging]` section.
#[derive(Debug, Clone)]
pub struct LoggingSection {
    pub loglevel: u8,
    pub logtimestamps: bool,
}

impl Default for LoggingSection {
    fn default() -> Self {
        LoggingSection {
            loglevel: 4,
            logtimestamps: true,
        }
    }
}

/// A parsed interface from `[[subsection]]` within `[interfaces]`.
#[derive(Debug, Clone)]
pub struct ParsedInterface {
    pub name: String,
    pub interface_type: String,
    pub enabled: bool,
    pub mode: String,
    pub params: HashMap<String, String>,
    pub subinterfaces: Vec<ParsedSubinterface>,
}

/// A `[[[subinterface]]]` nested under an interface section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSubinterface {
    pub name: String,
    pub params: HashMap<String, String>,
}

/// Configuration parse error.
#[derive(Debug, Clone)]
pub enum ConfigError {
    Io(String),
    Parse(String),
    InvalidValue { key: String, value: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(msg) => write!(f, "Config I/O error: {}", msg),
            ConfigError::Parse(msg) => write!(f, "Config parse error: {}", msg),
            ConfigError::InvalidValue { key, value } => {
                write!(f, "Invalid value for '{}': '{}'", key, value)
            }
        }
    }
}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> Self {
        ConfigError::Io(e.to_string())
    }
}
