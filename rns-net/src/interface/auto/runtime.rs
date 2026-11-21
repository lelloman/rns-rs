//! Runtime settings of an AutoInterface.

use super::*;

/// AutoInterface timing settings that can be changed while it runs.
#[derive(Debug, Clone)]
pub(crate) struct AutoRuntime {
    /// Interval between multicast discovery announces, in seconds.
    pub announce_interval_secs: f64,
    /// How long a peer may stay silent before it is removed, in seconds.
    pub peer_timeout_secs: f64,
    /// Interval between peer maintenance passes, in seconds.
    pub peer_job_interval_secs: f64,
}

impl Default for AutoRuntime {
    /// Startup settings for an AutoInterface. As upstream, these timings
    /// are fixed, not configurable.
    fn default() -> Self {
        Self {
            announce_interval_secs: ANNOUNCE_INTERVAL,
            peer_timeout_secs: PEERING_TIMEOUT,
            peer_job_interval_secs: PEER_JOB_INTERVAL,
        }
    }
}

/// Driver-side handle to a running AutoInterface's runtime settings.
#[derive(Debug, Clone)]
pub(crate) struct AutoRuntimeConfigHandle {
    /// Name of the AutoInterface.
    pub interface_name: String,
    /// Live settings shared with the interface.
    pub runtime: Arc<Mutex<AutoRuntime>>,
    /// Settings at startup, reported as the defaults.
    pub startup: AutoRuntime,
}

pub(crate) fn auto_runtime_handle_from_config(config: &AutoConfig) -> AutoRuntimeConfigHandle {
    AutoRuntimeConfigHandle {
        interface_name: config.name.clone(),
        runtime: Arc::clone(&config.runtime),
        startup: AutoRuntime::default(),
    }
}
