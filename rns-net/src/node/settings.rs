//! Configuration of a node and of its interfaces.

use super::*;

/// Sources and startup defaults needed to reread a named interface from disk.
pub(crate) struct InterfaceManagementConfig {
    pub(crate) config_file: std::path::PathBuf,
    pub(crate) storage_dir: std::path::PathBuf,
    pub(crate) initial_ids: HashMap<String, rns_core::transport::types::InterfaceId>,
    pub(crate) queue_capacity: usize,
    pub(crate) transport_enabled: bool,
    pub(crate) underlay_mark: Option<u32>,
}

/// How a shared instance is served, from upstream's `shared_instance_type`,
/// `rpc_key` and `force_shared_instance_bitrate`.
#[derive(Debug, Clone)]
pub struct SharedInstanceSettings {
    /// Serve the shared instance and its RPC on abstract Unix sockets on
    /// Linux, besides TCP; `false` for `shared_instance_type = tcp`.
    pub use_af_unix: bool,
    /// The RPC key (`rpc_key`), in place of the one derived from the
    /// transport identity.
    pub rpc_key: Option<[u8; 32]>,
    /// The bitrate the shared instance's local interfaces report
    /// (`force_shared_instance_bitrate`).
    pub force_bitrate: Option<u64>,
}

impl Default for SharedInstanceSettings {
    fn default() -> Self {
        Self {
            use_af_unix: true,
            rpc_key: None,
            force_bitrate: None,
        }
    }
}

/// Interface discovery settings of a node, from the `[reticulum]` keys
/// upstream reads for discovery.
#[derive(Debug, Clone, Default)]
pub struct DiscoverySettings {
    /// Network identities whose discovered interfaces are accepted
    /// (`interface_discovery_sources`); empty accepts any.
    pub interface_discovery_sources: Vec<[u8; 16]>,
    /// Upstream's `autoconnect_discovered_interfaces` under
    /// `autoconnect_policy = upstream`: how many discovered interfaces to
    /// auto-connect; 0 auto-connects none.
    pub autoconnect_discovered_interfaces: usize,
    /// Names of the `bootstrap_only` interfaces, detached while enough
    /// auto-connected interfaces are online.
    pub bootstrap_interfaces: Vec<String>,
}

/// Top-level node configuration.
pub struct NodeConfig {
    /// Act as a transport node (`enable_transport`).
    pub transport_enabled: bool,
    /// Use the node identity as transport identity even without transport
    /// enabled (`static_transport_identity`); otherwise a non-transport node
    /// gets an ephemeral one.
    pub static_transport_identity: bool,
    /// Pick a random non-zero hop delta, 2 to 7, that masks this node's
    /// locally originated zero-hop packets (`local_hops_delta`).
    pub local_hops_delta: bool,
    /// Node identity, with its private key (starting fails without one); a
    /// new one is generated when `None`.
    pub identity: Option<Identity>,
    /// The configured `network_identity`, kept apart from the transport
    /// identity as upstream's `Transport.network_identity`. It signs this
    /// node's interface discovery announces and encrypts and decrypts
    /// `discovery_encrypt` ones.
    pub network_identity: Option<Identity>,
    /// Interface configurations (parsed via registry factories).
    pub interfaces: Vec<InterfaceConfig>,
    /// Enable shared instance server for local clients (rns-ctl, etc.)
    pub share_instance: bool,
    /// Instance name for Unix socket namespace (default: "default").
    pub instance_name: String,
    /// Shared instance port for local client connections (default 37428).
    pub shared_instance_port: u16,
    /// RPC control port (default 37429). Only used when share_instance is true.
    pub rpc_port: u16,
    /// Cache directory for announce cache. If None, announce caching is disabled.
    pub cache_dir: Option<std::path::PathBuf>,
    /// Store for received ratchets. If None, received ratchets are not persisted or used.
    pub ratchet_store: Option<Arc<dyn storage::RatchetStore>>,
    /// TTL for received ratchets.
    pub ratchet_expiry: Duration,
    /// Remote management configuration.
    pub management: crate::management::ManagementConfig,
    /// Port to run the STUN probe server on (for facilitator nodes).
    pub probe_port: Option<u16>,
    /// Addresses of STUN/RNSP probe servers (tried sequentially with failover).
    pub probe_addrs: Vec<std::net::SocketAddr>,
    /// Protocol for endpoint discovery: "rnsp" (default) or "stun".
    pub probe_protocol: rns_core::holepunch::ProbeProtocol,
    /// Policy for incoming direct-connect proposals from peers not in
    /// `direct_connect_allowed_identities`. Accepting a proposal reveals
    /// this node's public IP address and port to the peer; the default,
    /// `Reject`, reveals nothing.
    pub direct_connect_policy: crate::event::HolePunchPolicy,
    /// Accept direct-connect endpoints in private, shared, link-local,
    /// and unique-local ranges (LAN-only deployments).
    pub direct_connect_allow_private_endpoints: bool,
    /// Identity hashes whose direct-connect proposals are accepted whatever
    /// the policy, once the peer has identified itself on the link
    /// (`LINKIDENTIFY`).
    pub direct_connect_allowed_identities: Vec<[u8; 16]>,
    /// Re-upgrade a link by itself after losing the direct path it
    /// proposed (see [`crate::event::DirectReupgradeConfig`]).
    pub direct_connect_reupgrade: crate::event::DirectReupgradeConfig,
    /// Rate limits of the probe server started by `probe_port`.
    pub probe_rate_limit: crate::event::ProbeRateLimit,
    /// Network interface to bind outbound sockets to (e.g. "usb0").
    pub device: Option<String>,
    /// Linux `SO_MARK` value applied to Reticulum IP underlay sockets.
    pub underlay_mark: Option<u32>,
    /// Hook configurations loaded from the config file.
    pub hooks: Vec<config::ParsedHook>,
    /// Enable interface discovery.
    pub discover_interfaces: bool,
    /// Interface discovery settings beyond turning it on.
    pub discovery: DiscoverySettings,
    /// How the shared instance is served, beyond `share_instance`.
    pub shared_instance: SharedInstanceSettings,
    /// Mode assigned to auto-connected discovered interfaces, when configured.
    pub autoconnect_interface_mode: Option<u8>,
    /// Gravity assigned to auto-connected discovered interfaces.
    pub autoconnect_interface_gravity: i64,
    /// Allow auto-connected interfaces to propagate announces to internal interfaces.
    pub autoconnect_announces_to_internal: bool,
    /// Allow auto-connecting discovered interfaces from unverified implementations.
    pub autoconnect_unverified_implementations: bool,
    /// Minimum stamp value for accepting discovered interfaces (default: 16).
    pub discovery_required_value: Option<rns_core::stamp::StampCost>,
    /// Respond to probe packets with automatic proof (like Python's respond_to_probes).
    pub respond_to_probes: bool,
    /// `use_implicit_proof`: prove received packets with the signature
    /// alone, instead of the packet hash and the signature. Link packets are
    /// always proved explicitly, as upstream does.
    pub use_implicit_proof: bool,
    /// Accept an announce with strictly fewer hops even when the random_blob
    /// is a duplicate of the existing path entry.  Default `false` preserves
    /// Python-compatible anti-replay behaviour.
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
    /// Maximum number of destination hashes retained in the live path table.
    pub max_path_destinations: usize,
    /// Maximum number of retained tunnel-known destinations.
    pub max_tunnel_destinations_total: usize,
    /// TTL for recalled known destinations without an active path.
    pub known_destinations_ttl: Duration,
    /// Maximum number of recalled known destinations retained.
    pub known_destinations_max_entries: usize,
    /// TTL for announce retransmission state.
    pub announce_table_ttl: Duration,
    /// Maximum retained bytes for announce retransmission state.
    pub announce_table_max_bytes: usize,
    /// Maximum queued events awaiting driver processing.
    pub driver_event_queue_capacity: usize,
    /// Maximum queued outbound frames per interface writer worker.
    pub interface_writer_queue_capacity: usize,
    /// Default announce-rate controls applied to interfaces when transport is enabled.
    pub announce_rate_defaults: AnnounceRateDefaults,
    /// Default ingress/egress controls applied to interfaces when transport is enabled.
    pub ingress_control_defaults: rns_core::transport::types::IngressControlConfig,
    /// Outbound Backbone peer-pool settings. Disabled when `None`.
    #[cfg(feature = "iface-backbone")]
    pub backbone_peer_pool: Option<BackbonePeerPoolSettings>,
    /// Whether the announce signature verification cache is enabled.
    pub announce_sig_cache_enabled: bool,
    /// Maximum entries in the announce signature verification cache.
    pub announce_sig_cache_max_entries: usize,
    /// TTL for announce signature cache entries.
    pub announce_sig_cache_ttl: Duration,
    /// Custom interface registry. If `None`, uses `InterfaceRegistry::with_builtins()`.
    pub registry: Option<crate::interface::registry::InterfaceRegistry>,
    /// If true, a single interface failing to start will abort the entire node.
    /// If false (default), the error is logged and remaining interfaces continue.
    pub panic_on_interface_error: bool,
    /// Threads that verify and sign link packet proofs off the driver thread
    /// (`Auto`: half the CPUs the process may use, from one to four).
    pub link_proof_verify_threads: crate::ProofVerifyThreads,
    /// Stamp generation, enforcement, costs and timeouts: the `[stamps]`
    /// section, which [`RnsNode::from_config`] reads from the config file.
    /// Upstream's `Reticulum(enable_stamping=True)` corresponds to setting
    /// `stamp_destinations`, `stamp_prs` and `stamp_lrs`, and
    /// `enforce_stamps=True` to `stamps_enforced` and `lr_stamps_enforced`.
    pub stamps: config::StampsSection,
    /// External provider bridge for hook-emitted events.
    #[cfg(feature = "hooks")]
    pub provider_bridge: Option<crate::provider_bridge::ProviderBridgeConfig>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            transport_enabled: false,
            static_transport_identity: false,
            local_hops_delta: false,
            identity: None,
            network_identity: None,
            interfaces: Vec::new(),
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            ratchet_store: None,
            ratchet_expiry: Duration::from_secs(rns_core::constants::RATCHET_EXPIRY),
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            direct_connect_policy: crate::event::HolePunchPolicy::Reject,
            direct_connect_allow_private_endpoints: false,
            direct_connect_allowed_identities: Vec::new(),
            direct_connect_reupgrade: Default::default(),
            probe_rate_limit: Default::default(),
            device: None,
            underlay_mark: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery: Default::default(),
            shared_instance: Default::default(),
            autoconnect_interface_mode: None,
            autoconnect_interface_gravity: 0,
            autoconnect_announces_to_internal: false,
            autoconnect_unverified_implementations: false,
            discovery_required_value: None,
            respond_to_probes: false,
            use_implicit_proof: true,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Lazy,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: rns_core::transport::types::DEFAULT_MAX_PATH_DESTINATIONS,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: Duration::from_secs(48 * 60 * 60),
            known_destinations_max_entries: DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: crate::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_rate_defaults: AnnounceRateDefaults::default(),
            ingress_control_defaults: rns_core::transport::types::IngressControlConfig::enabled(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: None,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            panic_on_interface_error: false,
            link_proof_verify_threads: Default::default(),
            stamps: config::StampsSection::default(),
            #[cfg(feature = "hooks")]
            provider_bridge: None,
        }
    }
}

/// IFAC configuration for an interface.
pub struct IfacConfig {
    /// Network name (`networkname` / `network_name`).
    pub netname: Option<String>,
    /// Passphrase (`passphrase` / `pass_phrase`).
    pub netkey: Option<String>,
    /// IFAC size in bytes (`ifac_size` is given in bits).
    pub size: usize,
}

/// Interface configuration, parsed via an [`InterfaceFactory`] from the registry.
pub struct InterfaceConfig {
    /// Interface name, from its config section.
    pub name: String,
    /// Interface type name, e.g. "TCPClientInterface".
    pub type_name: String,
    /// Type-specific settings parsed by the interface's factory.
    pub config_data: Box<dyn crate::interface::InterfaceConfigData>,
    /// Interface mode, one of the `constants::MODE_*` values.
    pub mode: u8,
    /// Signed interface preference used by path selection.
    pub gravity: i64,
    /// The interface's own `hop_limiter` (upstream bb63dd44).
    pub hop_limiter: Option<u8>,
    /// Upstream `recursive_prs` option.
    pub recursive_prs: bool,
    /// Upstream `announces_from_internal` option.
    pub announces_from_internal: bool,
    /// Upstream `announces_to_internal` option.
    pub announces_to_internal: Option<bool>,
    /// Ingress control settings of the interface.
    pub ingress_control: rns_core::transport::types::IngressControlConfig,
    /// Per-interface `destination_cost` and `pr_cost` (upstream 9b464382).
    pub stamp_costs: rns_core::transport::types::InterfaceStampCosts,
    /// Per-interface announce rate controls and announce cap.
    pub announce_limits: InterfaceAnnounceLimits,
    /// IFAC settings, when a network name or passphrase is set.
    pub ifac: Option<IfacConfig>,
    /// Interface discovery settings, when the interface is discoverable.
    pub discovery: Option<crate::discovery::DiscoveryConfig>,
}

/// An interface section's `announce_rate_target`, `announce_rate_grace`,
/// `announce_rate_penalty` and `announce_cap` (Reticulum.py
/// `_synthesize_interface`). Unset options leave the interface to the
/// instance-wide `default_ar_*` values and the default announce cap.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct InterfaceAnnounceLimits {
    /// Seconds between rebroadcasts of one destination's announces.
    pub rate_target: Option<f64>,
    /// Rate violations allowed before the penalty applies.
    pub rate_grace: Option<u32>,
    /// Seconds added to the target for a destination over its grace.
    pub rate_penalty: Option<f64>,
    /// Fraction of the interface bitrate allocated to announces.
    pub cap: Option<f64>,
}

impl InterfaceAnnounceLimits {
    /// Set the configured values on `info`. With a target set, an unset
    /// grace or penalty is 0 for this interface rather than the instance
    /// default, as upstream sets them.
    pub(crate) fn apply(&self, info: &mut rns_core::transport::types::InterfaceInfo) {
        if let Some(target) = self.rate_target {
            info.announce_rate_target = Some(target);
            info.announce_rate_grace = self.rate_grace.unwrap_or(0);
            info.announce_rate_penalty = self.rate_penalty.unwrap_or(0.0);
        } else {
            if let Some(grace) = self.rate_grace {
                info.announce_rate_grace = grace;
            }
            if let Some(penalty) = self.rate_penalty {
                info.announce_rate_penalty = penalty;
            }
        }
        if let Some(cap) = self.cap {
            info.announce_cap = cap;
        }
    }
}
