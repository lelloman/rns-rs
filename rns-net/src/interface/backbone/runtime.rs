//! Runtime settings and peer state of servers and clients.

use super::*;

/// Live runtime state for a backbone server interface.
#[derive(Debug, Clone)]
pub struct BackboneServerRuntime {
    /// Limit on concurrent clients; `None` for no limit.
    pub max_connections: Option<usize>,
    /// Disconnect a client that sends nothing this long after connecting;
    /// `None` disables it.
    pub idle_timeout: Option<Duration>,
    /// Disconnect a client whose writes stall this long; `None` uses the
    /// default egress dead time.
    pub write_stall_timeout: Option<Duration>,
    /// Abuse handling settings.
    pub abuse: BackboneAbuseConfig,
}

impl BackboneServerRuntime {
    /// The settings `config` starts with.
    pub fn from_config(config: &BackboneConfig) -> Self {
        Self {
            max_connections: config.max_connections,
            idle_timeout: config.idle_timeout,
            write_stall_timeout: config.write_stall_timeout,
            abuse: config.abuse.clone(),
        }
    }
}

/// Handle the driver keeps to read and change a listener's runtime settings.
#[derive(Debug, Clone)]
pub struct BackboneRuntimeConfigHandle {
    /// Interface name.
    pub interface_name: String,
    /// Live settings.
    pub runtime: Arc<Mutex<BackboneServerRuntime>>,
    /// Settings at start, restored on reset.
    pub startup: BackboneServerRuntime,
}

/// Handle the driver keeps to a listener's peer and fast-flap state.
#[derive(Debug, Clone)]
pub struct BackbonePeerStateHandle {
    /// ID of the listener interface.
    pub interface_id: InterfaceId,
    /// Interface name.
    pub interface_name: String,
    /// `mode` of the config the handle was made from.
    pub mode: u8,
    /// `gravity` of the config the handle was made from.
    pub gravity: i64,
    /// `announces_to_internal` of the config the handle was made from.
    pub announces_to_internal: Option<bool>,
    /// Per-address peer state.
    pub peer_state: Arc<Mutex<BackbonePeerMonitor>>,
    /// The listener's fast-flap policy.
    pub fast_flap: BackboneFastFlapConfig,
    /// Fast-flap history.
    pub fast_flap_state: Arc<Mutex<BackboneFastFlapMonitor>>,
}

/// Live runtime settings of a backbone client interface.
#[derive(Debug, Clone)]
pub struct BackboneClientRuntime {
    /// Wait between connection attempts, and the base of the backoff after a
    /// lost connection.
    pub reconnect_wait: Duration,
    /// Limit on reconnection attempts; `None` retries forever.
    pub max_reconnect_tries: Option<u32>,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
}

impl BackboneClientRuntime {
    /// The settings `config` starts with.
    pub fn from_config(config: &BackboneClientConfig) -> Self {
        Self {
            reconnect_wait: config.reconnect_wait,
            max_reconnect_tries: config.max_reconnect_tries,
            connect_timeout: config.connect_timeout,
        }
    }
}

/// Handle the driver keeps to read and change a client's runtime settings.
#[derive(Debug, Clone)]
pub struct BackboneClientRuntimeConfigHandle {
    /// Interface name.
    pub interface_name: String,
    /// Live settings.
    pub runtime: Arc<Mutex<BackboneClientRuntime>>,
    /// Settings at start, restored on reset.
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
