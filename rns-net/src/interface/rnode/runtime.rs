//! Runtime settings of an RNode interface.

use super::*;

/// Radio settings of a single RNode that can be changed while it runs.
#[derive(Debug, Clone)]
pub struct RNodeRuntime {
    /// Current radio settings.
    pub sub: RNodeSubConfig,
    /// Write side of the open device, set once connected; changes are sent through it.
    pub writer: Option<Arc<Mutex<DeviceWriter>>>,
}

impl RNodeRuntime {
    /// Settings from the first subinterface of `config`, or the defaults when it has none.
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

/// The driver's handle on an RNode's runtime settings.
#[derive(Debug, Clone)]
pub struct RNodeRuntimeConfigHandle {
    /// Name of the interface.
    pub interface_name: String,
    /// Current settings, shared with the interface.
    pub runtime: Arc<Mutex<RNodeRuntime>>,
    /// Settings at startup, used as defaults and for resets.
    pub startup: RNodeRuntime,
}

pub(crate) fn rnode_runtime_handle_from_config(config: &RNodeConfig) -> RNodeRuntimeConfigHandle {
    RNodeRuntimeConfigHandle {
        interface_name: config.name.clone(),
        runtime: Arc::clone(&config.runtime),
        startup: RNodeRuntime::from_config(config),
    }
}
