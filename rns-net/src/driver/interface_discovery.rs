//! The driver's interface discovery state.

use super::*;

/// Interface discovery: the interfaces discovered from other nodes'
/// announces, this node's own discovery announces, and the auto-connecting
/// of discovered interfaces.
pub(crate) struct InterfaceDiscovery {
    /// Whether interface discovery is enabled.
    pub(crate) enabled: bool,
    /// Storage for discovered interfaces.
    pub(crate) storage: crate::discovery::DiscoveredInterfaceStorage,
    /// Required stamp value for accepting discovered interfaces.
    pub(crate) required_value: rns_core::stamp::StampCost,
    /// Bounded cache of discovery payloads with previously rejected stamps.
    pub(crate) stamp_cache: crate::discovery::DiscoveryStampCache,
    /// Name hash for interface discovery announces ("rnstransport.discovery.interface").
    pub(crate) name_hash: [u8; 10],
    /// Network identities whose discovered interfaces are accepted; empty
    /// accepts any (`interface_discovery_sources`).
    pub(crate) sources: Vec<[u8; 16]>,
    /// Announcer for discoverable interfaces (None if nothing to announce).
    pub(crate) announcer: Option<crate::discovery::InterfaceAnnouncer>,
    /// Explicit mode for interfaces created from discovery announces.
    pub(crate) autoconnect_mode: Option<u8>,
    /// Gravity for interfaces created from discovery announces.
    pub(crate) autoconnect_gravity: i64,
    /// Internal announce propagation override for discovered interfaces.
    pub(crate) autoconnect_announces_to_internal: Option<bool>,
    /// Allow auto-connecting discovered interfaces from unverified implementations.
    pub(crate) autoconnect_unverified_implementations: bool,
    /// Upstream's auto-connecting of discovered interfaces, when
    /// `autoconnect_discovered_interfaces` is set under the upstream policy.
    pub(crate) upstream_autoconnect: Option<autoconnect::UpstreamAutoconnect>,
    /// Tick counter for periodic discovery cleanup (every ~3600 ticks = ~1 hour).
    pub(crate) cleanup_counter: u32,
    /// Runtime-configurable discovery cleanup interval.
    pub(crate) cleanup_interval_ticks: u32,
}

impl InterfaceDiscovery {
    pub(crate) fn new(name_hash: [u8; 10], cleanup_interval_ticks: u32) -> Self {
        Self {
            enabled: false,
            storage: crate::discovery::DiscoveredInterfaceStorage::new(
                std::env::temp_dir().join("rns-discovered-interfaces"),
            ),
            required_value: crate::discovery::DEFAULT_STAMP_VALUE,
            stamp_cache: crate::discovery::DiscoveryStampCache::default(),
            name_hash,
            sources: Vec::new(),
            announcer: None,
            autoconnect_mode: None,
            autoconnect_gravity: 0,
            autoconnect_announces_to_internal: None,
            autoconnect_unverified_implementations: false,
            upstream_autoconnect: None,
            cleanup_counter: 0,
            cleanup_interval_ticks,
        }
    }

    /// Whether interfaces discovered from the network identity
    /// `network_id` are accepted: any are without
    /// `interface_discovery_sources`.
    pub(crate) fn source_allowed(&self, network_id: &[u8; 16]) -> bool {
        self.sources.is_empty() || self.sources.contains(network_id)
    }

    /// Whether an interface was auto-connected from a discovery.
    pub(crate) fn is_autoconnected(&self, id: InterfaceId) -> bool {
        self.upstream_autoconnect
            .as_ref()
            .is_some_and(|autoconnect| autoconnect.is_member(id))
    }
}
