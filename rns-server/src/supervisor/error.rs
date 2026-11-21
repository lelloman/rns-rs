use std::fmt;
use std::io;

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
