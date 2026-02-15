use std::fmt;

/// Errors that can occur in the hook system.
#[derive(Debug)]
pub enum HookError {
    /// WASM module failed to compile.
    CompileError(String),
    /// WASM module failed to instantiate.
    InstantiationError(String),
    /// WASM execution ran out of fuel.
    FuelExhausted,
    /// WASM execution trapped (panic, out-of-bounds, etc.).
    Trap(String),
    /// Hook returned invalid result data.
    InvalidResult(String),
    /// Hook was auto-disabled after too many consecutive failures.
    AutoDisabled { name: String, consecutive_traps: u32 },
    /// Hook point not found or invalid.
    InvalidHookPoint(String),
    /// I/O error loading a WASM module.
    IoError(std::io::Error),
}

impl fmt::Display for HookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HookError::CompileError(msg) => write!(f, "compile error: {}", msg),
            HookError::InstantiationError(msg) => write!(f, "instantiation error: {}", msg),
            HookError::FuelExhausted => write!(f, "fuel exhausted"),
            HookError::Trap(msg) => write!(f, "trap: {}", msg),
            HookError::InvalidResult(msg) => write!(f, "invalid result: {}", msg),
            HookError::AutoDisabled { name, consecutive_traps } => {
                write!(f, "hook '{}' auto-disabled after {} consecutive traps", name, consecutive_traps)
            }
            HookError::InvalidHookPoint(msg) => write!(f, "invalid hook point: {}", msg),
            HookError::IoError(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for HookError {}

impl From<std::io::Error> for HookError {
    fn from(e: std::io::Error) -> Self {
        HookError::IoError(e)
    }
}
