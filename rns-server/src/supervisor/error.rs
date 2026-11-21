use std::fmt;
use std::io;
use std::path::PathBuf;

use super::Role;

/// Why the supervisor stopped with an error.
///
/// The children started so far are stopped before it is returned. Its
/// `Display` text is what `rns-server` prints and what the control plane
/// shows for a process that failed to start.
#[derive(Debug)]
#[non_exhaustive]
pub enum SupervisorError {
    /// The path of the running executable, needed to start a process from
    /// it, could not be resolved.
    ResolveSelfExec(io::Error),
    /// A process could not be started.
    Spawn {
        /// The process.
        role: Role,
        /// Why it could not.
        source: io::Error,
    },
    /// The hook run once every process has started failed.
    Started(Box<dyn std::error::Error + Send + Sync>),
    /// The supervisor's wake-up and signal handling could not be set up.
    Setup(io::Error),
    /// Checking whether a process exited failed.
    Poll {
        /// The process.
        role: Role,
        /// Why it failed.
        source: io::Error,
    },
    /// A control command named a process the supervisor does not know.
    UnknownProcess(String),
    /// A control command named a process the supervisor has no spec for.
    MissingSpec(String),
    /// A process could not be stopped for a restart or stop command.
    Terminate {
        /// The process.
        role: Role,
        /// `restart` or `stop`.
        during: &'static str,
        /// Why it could not.
        source: io::Error,
    },
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SupervisorError::ResolveSelfExec(error) => {
                write!(f, "failed to resolve current executable: {}", error)
            }
            SupervisorError::Spawn { role, source } => {
                write!(f, "failed to start {}: {}", role.display_name(), source)
            }
            SupervisorError::Started(error) => write!(f, "{}", error),
            SupervisorError::Setup(error) => write!(f, "cannot set up the supervisor: {}", error),
            SupervisorError::Poll { role, source } => {
                write!(f, "failed to poll {}: {}", role.display_name(), source)
            }
            SupervisorError::UnknownProcess(name) => write!(f, "unknown process '{}'", name),
            SupervisorError::MissingSpec(name) => {
                write!(f, "missing process spec for '{}'", name)
            }
            SupervisorError::Terminate {
                role,
                during,
                source,
            } => write!(
                f,
                "failed to terminate {} during {}: {}",
                role.display_name(),
                during,
                source
            ),
        }
    }
}

impl std::error::Error for SupervisorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SupervisorError::ResolveSelfExec(error) | SupervisorError::Setup(error) => Some(error),
            SupervisorError::Spawn { source, .. }
            | SupervisorError::Poll { source, .. }
            | SupervisorError::Terminate { source, .. } => Some(source),
            SupervisorError::Started(error) => Some(error.as_ref()),
            SupervisorError::UnknownProcess(_) | SupervisorError::MissingSpec(_) => None,
        }
    }
}

/// An RPC call the supervisor makes to `rnsd` that failed.
#[derive(Debug)]
pub(crate) enum RpcCallError {
    /// Connecting to `rnsd` failed.
    Connect(io::Error),
    /// The named call failed.
    Call {
        call: &'static str,
        source: io::Error,
    },
}

impl RpcCallError {
    /// A failure of `call`, for `map_err`.
    pub(crate) fn call(call: &'static str) -> impl FnOnce(io::Error) -> Self {
        move |source| RpcCallError::Call { call, source }
    }
}

impl fmt::Display for RpcCallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpcCallError::Connect(error) => write!(f, "rpc connect failed: {}", error),
            RpcCallError::Call { call, source } => write!(f, "{} failed: {}", call, source),
        }
    }
}

impl std::error::Error for RpcCallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RpcCallError::Connect(source) | RpcCallError::Call { source, .. } => Some(source),
        }
    }
}

/// Why a readiness file does not show its process ready.
#[derive(Debug)]
pub(crate) enum ReadyFileError {
    /// The file could not be read (usually: not written yet).
    Read { path: PathBuf, source: io::Error },
    /// The `pid` line is not a pid.
    InvalidPid {
        value: String,
        source: std::num::ParseIntError,
    },
    /// A required line is missing.
    Missing(&'static str),
    /// The file names another process.
    WrongProcess { path: PathBuf, process: String },
    /// The file was written by an earlier instance of the process.
    Stale {
        path: PathBuf,
        pid: u32,
        expected: u32,
    },
    /// The file reports a status other than `ready`.
    NotReady { path: PathBuf, status: String },
}

impl fmt::Display for ReadyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadyFileError::Read { path, source } => write!(
                f,
                "waiting for readiness file {}: {}",
                path.display(),
                source
            ),
            ReadyFileError::InvalidPid { value, source } => {
                write!(f, "invalid readiness pid '{}': {}", value, source)
            }
            ReadyFileError::Missing(field) => write!(f, "readiness file missing {}", field),
            ReadyFileError::WrongProcess { path, process } => write!(
                f,
                "readiness file {} belongs to {}",
                path.display(),
                process
            ),
            ReadyFileError::Stale {
                path,
                pid,
                expected,
            } => write!(
                f,
                "readiness file {} is stale for pid {} (expected {})",
                path.display(),
                pid,
                expected
            ),
            ReadyFileError::NotReady { path, status } => write!(
                f,
                "readiness file {} reports status={}",
                path.display(),
                status
            ),
        }
    }
}

impl std::error::Error for ReadyFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReadyFileError::Read { source, .. } => Some(source),
            ReadyFileError::InvalidPid { source, .. } => Some(source),
            _ => None,
        }
    }
}
