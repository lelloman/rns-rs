use std::fmt;

/// Errors that can occur in the hook system.
#[derive(Debug)]
pub enum HookError {
    /// The program could not be loaded: a WASM module that does not compile,
    /// a native library that fails to load or lacks an entry point, an
    /// unregistered built-in id, or a backend this build does not include.
    CompileError(String),
    /// WASM module failed to instantiate.
    InstantiationError(String),
    /// WASM execution ran out of fuel.
    FuelExhausted,
    /// Execution failed: a WASM trap (panic, out-of-bounds access, ...), a
    /// native hook's non-zero return code, or a built-in hook's error.
    Trap(String),
    /// Hook returned invalid result data.
    InvalidResult(String),
    /// Hook was auto-disabled after too many consecutive failures.
    AutoDisabled {
        /// Name of the program.
        name: String,
        /// Failures in a row that disabled it.
        consecutive_traps: u32,
    },
    /// Hook point not found or invalid.
    InvalidHookPoint(String),
    /// I/O error loading a WASM module.
    IoError(std::io::Error),
    /// A WASM module or native library was built against an incompatible
    /// ABI version.
    AbiVersionMismatch {
        /// Name of the program, or the library path for a native hook.
        hook_name: String,
        /// The host's ABI version.
        expected: i32,
        /// The version the hook reported; `None` if it exports no version
        /// function.
        found: Option<i32>,
    },
}

impl fmt::Display for HookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HookError::CompileError(msg) => write!(f, "compile error: {}", msg),
            HookError::InstantiationError(msg) => write!(f, "instantiation error: {}", msg),
            HookError::FuelExhausted => write!(f, "fuel exhausted"),
            HookError::Trap(msg) => write!(f, "trap: {}", msg),
            HookError::InvalidResult(msg) => write!(f, "invalid result: {}", msg),
            HookError::AutoDisabled {
                name,
                consecutive_traps,
            } => {
                write!(
                    f,
                    "hook '{}' auto-disabled after {} consecutive traps",
                    name, consecutive_traps
                )
            }
            HookError::InvalidHookPoint(msg) => write!(f, "invalid hook point: {}", msg),
            HookError::IoError(e) => write!(f, "I/O error: {}", e),
            HookError::AbiVersionMismatch {
                hook_name,
                expected,
                found,
            } => match found {
                Some(v) => write!(
                    f,
                    "hook '{}' ABI version mismatch: host expects {}, hook has {}. \
                         Recompile the hook against the current rns-hooks-sdk.",
                    hook_name, expected, v
                ),
                None => write!(
                    f,
                    "hook '{}' missing __rns_abi_version export (expected ABI version {}). \
                         Recompile the hook against the current rns-hooks-sdk.",
                    hook_name, expected
                ),
            },
        }
    }
}

impl std::error::Error for HookError {}

impl From<std::io::Error> for HookError {
    fn from(e: std::io::Error) -> Self {
        HookError::IoError(e)
    }
}
