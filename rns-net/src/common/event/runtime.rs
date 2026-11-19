//! Runtime config values and errors, and the lifecycle and drain state.

/// Scalar runtime-config value.
#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeConfigValue {
    Int(i64),
    Float(f64),
    Bool(bool),
    String(String),
    Null,
}

/// Source of a runtime-config value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeConfigSource {
    Startup,
    RuntimeOverride,
}

/// How a runtime-config change applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeConfigApplyMode {
    Immediate,
    NewConnectionsOnly,
    NextReconnect,
    RestartRequired,
}

/// A runtime-config entry exposed by the daemon.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeConfigEntry {
    pub key: String,
    pub value: RuntimeConfigValue,
    pub default: RuntimeConfigValue,
    pub source: RuntimeConfigSource,
    pub apply_mode: RuntimeConfigApplyMode,
    pub description: Option<String>,
}

/// Runtime-config mutation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfigError {
    pub code: RuntimeConfigErrorCode,
    pub message: String,
}

/// Category of runtime-config mutation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeConfigErrorCode {
    UnknownKey,
    InvalidType,
    InvalidValue,
    Unsupported,
    NotFound,
    ApplyFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    Active,
    Draining,
    Stopping,
    Stopped,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DrainStatus {
    pub state: LifecycleState,
    pub drain_age_seconds: Option<f64>,
    pub deadline_remaining_seconds: Option<f64>,
    pub drain_complete: bool,
    pub interface_writer_queued_frames: usize,
    pub provider_backlog_events: usize,
    pub provider_consumer_queued_events: usize,
    pub detail: Option<String>,
}
