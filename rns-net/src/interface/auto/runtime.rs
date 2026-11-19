//! Runtime settings of an AutoInterface.

use super::*;

#[derive(Debug, Clone)]
pub struct AutoRuntime {
    pub announce_interval_secs: f64,
    pub peer_timeout_secs: f64,
    pub peer_job_interval_secs: f64,
}

impl AutoRuntime {
    pub fn from_config(_config: &AutoConfig) -> Self {
        Self {
            announce_interval_secs: ANNOUNCE_INTERVAL,
            peer_timeout_secs: PEERING_TIMEOUT,
            peer_job_interval_secs: PEER_JOB_INTERVAL,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AutoRuntimeConfigHandle {
    pub interface_name: String,
    pub runtime: Arc<Mutex<AutoRuntime>>,
    pub startup: AutoRuntime,
}

pub(crate) fn auto_runtime_handle_from_config(config: &AutoConfig) -> AutoRuntimeConfigHandle {
    AutoRuntimeConfigHandle {
        interface_name: config.name.clone(),
        runtime: Arc::clone(&config.runtime),
        startup: AutoRuntime::from_config(config),
    }
}
