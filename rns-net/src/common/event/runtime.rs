//! Runtime config values and errors, and the lifecycle and drain state.

/// Scalar runtime-config value.
#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeConfigValue {
    /// An integer.
    Int(i64),
    /// A floating-point number.
    Float(f64),
    /// A boolean.
    Bool(bool),
    /// A string.
    String(String),
    /// No value; for an optional setting, unset.
    Null,
}

/// Source of a runtime-config value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeConfigSource {
    /// The value equals the one the node started with.
    Startup,
    /// The value was changed at runtime.
    RuntimeOverride,
}

/// How a runtime-config change applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeConfigApplyMode {
    /// Takes effect at once.
    Immediate,
    /// Applies to connections made after the change.
    NewConnectionsOnly,
    /// Applies when the interface next reconnects.
    NextReconnect,
}

/// A runtime-config entry exposed by the daemon.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeConfigEntry {
    /// The entry's key, such as `global.tick_interval_ms`.
    pub key: String,
    /// The current value.
    pub value: RuntimeConfigValue,
    /// The value the node started with, which a reset restores.
    pub default: RuntimeConfigValue,
    /// Whether the value was changed at runtime.
    pub source: RuntimeConfigSource,
    /// When a change takes effect.
    pub apply_mode: RuntimeConfigApplyMode,
    /// What the entry controls.
    pub description: Option<String>,
}

/// Runtime-config mutation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfigError {
    /// The kind of error.
    pub code: RuntimeConfigErrorCode,
    /// What went wrong.
    pub message: String,
}

/// Category of runtime-config mutation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeConfigErrorCode {
    /// No entry has this key.
    UnknownKey,
    /// The value has the wrong type for the entry.
    InvalidType,
    /// The value is out of range or otherwise not allowed.
    InvalidValue,
    /// The operation is not supported here.
    Unsupported,
    /// The interface the key names does not exist.
    NotFound,
    /// The value could not be applied or read back.
    ApplyFailed,
}

/// Where the driver is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    /// Accepting new work.
    Active,
    /// Refusing new work while existing work finishes, until the drain
    /// deadline.
    Draining,
    /// Tearing down the remaining work.
    Stopping,
    /// Stopped.
    Stopped,
}

/// The driver's lifecycle state and the work a drain still waits for.
#[derive(Debug, Clone, PartialEq)]
pub struct DrainStatus {
    /// The lifecycle state.
    pub state: LifecycleState,
    /// Seconds since draining began, once it has.
    pub drain_age_seconds: Option<f64>,
    /// Seconds left until the drain deadline, 0 once it passed; `None` before a
    /// drain.
    pub deadline_remaining_seconds: Option<f64>,
    /// No drain is in progress, or none of the work it waits for remains.
    pub drain_complete: bool,
    /// Frames waiting in interface writer queues.
    pub interface_writer_queued_frames: usize,
    /// Events in the provider bridge backlog.
    pub provider_backlog_events: usize,
    /// Events queued for provider bridge consumers.
    pub provider_consumer_queued_events: usize,
    /// A readable description of the state and what remains.
    pub detail: Option<String>,
}
