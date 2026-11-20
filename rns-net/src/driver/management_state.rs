//! Remote management state.

use super::*;

/// Remote management: who may manage this node, and when its management
/// destinations were last announced.
pub(crate) struct ManagementState {
    /// Management configuration for ACL checks.
    pub(crate) config: crate::management::ManagementConfig,
    /// Last time management announces were emitted.
    pub(crate) last_announce: f64,
    /// Whether initial management announce has been sent (delayed 5s after start).
    pub(crate) initial_announce_sent: bool,
    /// Runtime-configurable management announce interval.
    pub(crate) announce_interval_secs: f64,
}

impl ManagementState {
    pub(crate) fn new(defaults: &RuntimeConfigDefaults) -> Self {
        Self {
            config: Default::default(),
            last_announce: 0.0,
            initial_announce_sent: false,
            announce_interval_secs: defaults.management_announce_interval_secs,
        }
    }
}
