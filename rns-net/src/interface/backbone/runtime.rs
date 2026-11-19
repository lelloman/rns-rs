//! Runtime settings and peer state of servers and clients.

use super::*;

/// Live runtime state for a backbone server interface.
#[derive(Debug, Clone)]
pub struct BackboneServerRuntime {
    pub max_connections: Option<usize>,
    pub idle_timeout: Option<Duration>,
    pub write_stall_timeout: Option<Duration>,
    pub abuse: BackboneAbuseConfig,
}

impl BackboneServerRuntime {
    pub fn from_config(config: &BackboneConfig) -> Self {
        Self {
            max_connections: config.max_connections,
            idle_timeout: config.idle_timeout,
            write_stall_timeout: config.write_stall_timeout,
            abuse: config.abuse.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackboneRuntimeConfigHandle {
    pub interface_name: String,
    pub runtime: Arc<Mutex<BackboneServerRuntime>>,
    pub startup: BackboneServerRuntime,
}

#[derive(Debug, Clone)]
pub struct BackbonePeerStateHandle {
    pub interface_id: InterfaceId,
    pub interface_name: String,
    pub mode: u8,
    pub gravity: i64,
    pub announces_to_internal: Option<bool>,
    pub peer_state: Arc<Mutex<BackbonePeerMonitor>>,
    pub fast_flap: BackboneFastFlapConfig,
    pub fast_flap_state: Arc<Mutex<BackboneFastFlapMonitor>>,
}

#[derive(Debug, Clone)]
pub struct BackboneClientRuntime {
    pub reconnect_wait: Duration,
    pub max_reconnect_tries: Option<u32>,
    pub connect_timeout: Duration,
}

impl BackboneClientRuntime {
    pub fn from_config(config: &BackboneClientConfig) -> Self {
        Self {
            reconnect_wait: config.reconnect_wait,
            max_reconnect_tries: config.max_reconnect_tries,
            connect_timeout: config.connect_timeout,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackboneClientRuntimeConfigHandle {
    pub interface_name: String,
    pub runtime: Arc<Mutex<BackboneClientRuntime>>,
    pub startup: BackboneClientRuntime,
}

pub(crate) fn runtime_handle_from_mode(mode: &BackboneMode) -> Option<BackboneRuntimeConfigHandle> {
    match mode {
        BackboneMode::Server(config) => Some(BackboneRuntimeConfigHandle {
            interface_name: config.name.clone(),
            runtime: Arc::clone(&config.runtime),
            startup: BackboneServerRuntime::from_config(config),
        }),
        BackboneMode::Client(_, _) => None,
    }
}

pub(crate) fn peer_state_handle_from_mode(mode: &BackboneMode) -> Option<BackbonePeerStateHandle> {
    match mode {
        BackboneMode::Server(config) => Some(BackbonePeerStateHandle {
            interface_id: config.interface_id,
            interface_name: config.name.clone(),
            mode: config.mode,
            gravity: config.gravity,
            announces_to_internal: config.announces_to_internal,
            peer_state: Arc::clone(&config.peer_state),
            fast_flap: config.fast_flap,
            fast_flap_state: Arc::clone(&config.fast_flap_state),
        }),
        BackboneMode::Client(_, _) => None,
    }
}

pub(crate) fn client_runtime_handle_from_mode(
    mode: &BackboneMode,
) -> Option<BackboneClientRuntimeConfigHandle> {
    match mode {
        BackboneMode::Client(config, _) => Some(BackboneClientRuntimeConfigHandle {
            interface_name: config.name.clone(),
            runtime: Arc::clone(&config.runtime),
            startup: BackboneClientRuntime::from_config(config),
        }),
        BackboneMode::Server(_) => None,
    }
}

pub(crate) fn client_config_from_mode(mode: &BackboneMode) -> Option<BackboneClientConfig> {
    match mode {
        BackboneMode::Client(config, _) => Some(config.clone()),
        BackboneMode::Server(_) => None,
    }
}

pub(crate) fn client_priority_from_mode(mode: &BackboneMode) -> Option<u8> {
    match mode {
        BackboneMode::Client(_, priority) => Some(*priority),
        BackboneMode::Server(_) => None,
    }
}
