//! Runtime settings of an RNode interface.

use super::*;

#[derive(Debug, Clone)]
pub struct RNodeRuntime {
    pub sub: RNodeSubConfig,
    pub writer: Option<Arc<Mutex<DeviceWriter>>>,
}

impl RNodeRuntime {
    pub fn from_config(config: &RNodeConfig) -> Self {
        Self {
            sub: config
                .subinterfaces
                .first()
                .cloned()
                .unwrap_or_else(|| RNodeSubConfig {
                    name: config.name.clone(),
                    vport: 0,
                    outgoing: true,
                    frequency: 868_000_000,
                    bandwidth: 125_000,
                    txpower: 7,
                    spreading_factor: 8,
                    coding_rate: 5,
                    flow_control: false,
                    st_alock: None,
                    lt_alock: None,
                }),
            writer: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RNodeRuntimeConfigHandle {
    pub interface_name: String,
    pub runtime: Arc<Mutex<RNodeRuntime>>,
    pub startup: RNodeRuntime,
}

pub(crate) fn rnode_runtime_handle_from_config(config: &RNodeConfig) -> RNodeRuntimeConfigHandle {
    RNodeRuntimeConfigHandle {
        interface_name: config.name.clone(),
        runtime: Arc::clone(&config.runtime),
        startup: RNodeRuntime::from_config(config),
    }
}
