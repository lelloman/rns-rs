//! The backbone peer pool: its settings and candidates.

use super::*;

#[cfg(feature = "iface-backbone")]
pub(super) type BackboneCandidateOrder = (
    std::cmp::Reverse<u8>,
    u8,
    u8,
    u8,
    std::cmp::Reverse<rns_core::stamp::StampValue>,
    std::cmp::Reverse<u64>,
    [u8; 32],
);

#[cfg(feature = "iface-backbone")]
/// Limits of the backbone peer pool, from the `backbone_peer_pool_*` options.
#[derive(Debug, Clone)]
pub struct BackbonePeerPoolSettings {
    /// Most outbound pool connections active at once.
    pub max_connected: usize,
    /// Failures within `failure_window` that put a discovered peer in cooldown.
    pub failure_threshold: usize,
    /// How long a failure counts toward `failure_threshold`.
    pub failure_window: Duration,
    /// How long a discovered peer stays in cooldown before it is retried.
    pub cooldown: Duration,
}

#[cfg(feature = "iface-backbone")]
pub(crate) const BACKBONE_PEER_POOL_CONFIGURED_DEFAULT_PRIORITY: u8 = 60;

#[cfg(feature = "iface-backbone")]
pub(crate) const BACKBONE_PEER_POOL_DISCOVERED_PRIORITY: u8 = 40;

#[cfg(feature = "iface-backbone")]
#[derive(Clone)]
pub(crate) struct BackbonePeerPoolCandidateConfig {
    pub(crate) client: BackboneClientConfig,
    pub(crate) mode: u8,
    pub(crate) gravity: i64,
    pub(crate) recursive_prs: bool,
    pub(crate) announces_from_internal: bool,
    pub(crate) announces_to_internal: Option<bool>,
    pub(crate) ingress_control: rns_core::transport::types::IngressControlConfig,
    pub(crate) stamp_costs: rns_core::transport::types::InterfaceStampCosts,
    pub(crate) ifac_runtime: IfacRuntimeConfig,
    pub(crate) ifac_enabled: bool,
    pub(crate) interface_type_name: String,
    pub(crate) source: BackbonePeerPoolCandidateSource,
    pub(crate) priority: u8,
    pub(crate) discovery: Option<BackbonePeerPoolDiscoveryCandidate>,
}

#[cfg(feature = "iface-backbone")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackbonePeerPoolCandidateSource {
    Configured,
    Discovered,
}

#[cfg(feature = "iface-backbone")]
impl BackbonePeerPoolCandidateSource {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Discovered => "discovered",
        }
    }
}

#[cfg(feature = "iface-backbone")]
#[derive(Debug, Clone)]
pub(crate) struct BackbonePeerPoolDiscoveryCandidate {
    pub(crate) discovery_hash: [u8; 32],
    pub(crate) status: crate::discovery::DiscoveredStatus,
    pub(crate) hops: u8,
    pub(crate) stamp_value: rns_core::stamp::StampValue,
    pub(crate) last_heard: f64,
    /// The network that announced it (upstream's `network_id`).
    pub(crate) network_id: [u8; 16],
}

#[cfg(feature = "iface-backbone")]
pub(super) struct BackbonePeerPool {
    pub(super) settings: BackbonePeerPoolSettings,
    pub(super) candidates: Vec<BackbonePeerPoolCandidate>,
}

#[cfg(feature = "iface-backbone")]
pub(super) struct BackbonePeerPoolCandidate {
    pub(super) config: BackbonePeerPoolCandidateConfig,
    pub(super) active_id: Option<InterfaceId>,
    pub(super) failures: Vec<f64>,
    /// Failed attempts since the last successful connect; drives the
    /// reconnect backoff of configured peers.
    pub(super) consecutive_failures: u32,
    pub(super) retry_after: Option<f64>,
    pub(super) cooldown_until: Option<f64>,
    pub(super) last_error: Option<String>,
    /// Stops the active connection's reader when the pool evicts it.
    pub(super) control: Option<crate::interface::ListenerControl>,
}
