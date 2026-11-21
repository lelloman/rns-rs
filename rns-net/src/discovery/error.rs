//! Why a discovery announce could not be prepared.

use std::io;
use std::path::PathBuf;

use super::LOCATION_CMD_MAX_STDOUT;

/// Why an interface's `location_cmd` gave no coordinates.
#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum LocationError {
    /// The command printed more than the output limit.
    OutputTooLong,
    /// The command's output is not UTF-8.
    NotUtf8(std::str::Utf8Error),
    /// The command printed more than one line.
    MultipleLines,
    /// The command printed this many comma-separated components, not 3.
    ComponentCount(usize),
    /// A component is not a number.
    InvalidNumber {
        /// Which coordinate: `latitude`, `longitude` or `height`.
        label: &'static str,
        /// The component as printed.
        value: String,
        /// Why it did not parse.
        source: std::num::ParseFloatError,
    },
    /// A component is infinite or NaN.
    NotFinite {
        /// Which coordinate.
        label: &'static str,
    },
    /// A coordinate is outside its valid range.
    OutOfRange {
        /// Which coordinate.
        label: &'static str,
        /// Its value.
        value: f64,
        /// The valid range, as shown to the operator.
        range: &'static str,
    },
    /// The command starts with `~` (given as `prefix`) and `HOME` is unset.
    HomeNotSet {
        /// `~` or `~/`.
        prefix: &'static str,
    },
    /// The command's file could not be inspected.
    Inspect {
        /// The command's path.
        path: PathBuf,
        /// Why it could not.
        source: io::Error,
    },
    /// The command's path is not a regular file.
    NotRegularFile(PathBuf),
    /// The command's file is not executable.
    NotExecutable(PathBuf),
    /// The command could not be started.
    Spawn {
        /// The command's path.
        path: PathBuf,
        /// Why it could not.
        source: io::Error,
    },
    /// The command's stdout pipe was not available.
    StdoutUnavailable,
    /// The command ran past its time limit and was killed.
    TimedOut,
    /// Waiting for the command failed.
    Wait(io::Error),
    /// The thread reading the command's stdout panicked.
    ReaderPanicked,
    /// Reading the command's stdout failed.
    ReadStdout(io::Error),
    /// The command exited unsuccessfully.
    Failed(std::process::ExitStatus),
    /// `location_cmd` is not supported on this platform.
    #[cfg(windows)]
    Unsupported,
}

impl std::fmt::Display for LocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocationError::OutputTooLong => write!(
                f,
                "location command output exceeds {} bytes",
                LOCATION_CMD_MAX_STDOUT
            ),
            LocationError::NotUtf8(error) => {
                write!(f, "location command output is not UTF-8: {error}")
            }
            LocationError::MultipleLines => {
                f.write_str("location command must output exactly one line")
            }
            LocationError::ComponentCount(count) => write!(
                f,
                "location command returned {count} components; expected 3"
            ),
            LocationError::InvalidNumber {
                label,
                value,
                source,
            } => write!(f, "invalid {label} '{value}': {source}"),
            LocationError::NotFinite { label } => write!(f, "{label} must be finite"),
            LocationError::OutOfRange {
                label,
                value,
                range,
            } => write!(f, "{label} {value} is outside {range}"),
            LocationError::HomeNotSet { prefix } => write!(
                f,
                "cannot expand location command '{prefix}' because HOME is not set"
            ),
            LocationError::Inspect { path, source } => {
                write!(f, "cannot inspect '{}': {source}", path.display())
            }
            LocationError::NotRegularFile(path) => {
                write!(f, "'{}' is not a regular file", path.display())
            }
            LocationError::NotExecutable(path) => {
                write!(f, "'{}' is not executable", path.display())
            }
            LocationError::Spawn { path, source } => {
                write!(f, "cannot execute '{}': {source}", path.display())
            }
            LocationError::StdoutUnavailable => {
                f.write_str("location command stdout was unavailable")
            }
            LocationError::TimedOut => f.write_str("location command timed out after 5 seconds"),
            LocationError::Wait(error) => {
                write!(f, "failed waiting for location command: {error}")
            }
            LocationError::ReaderPanicked => f.write_str("location command stdout reader panicked"),
            LocationError::ReadStdout(error) => {
                write!(f, "failed reading location command stdout: {error}")
            }
            LocationError::Failed(status) => write!(f, "location command exited with {status}"),
            #[cfg(windows)]
            LocationError::Unsupported => f.write_str("location_cmd is not supported on Windows"),
        }
    }
}

impl std::error::Error for LocationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LocationError::NotUtf8(error) => Some(error),
            LocationError::InvalidNumber { source, .. } => Some(source),
            LocationError::Inspect { source, .. }
            | LocationError::Spawn { source, .. }
            | LocationError::Wait(source)
            | LocationError::ReadStdout(source) => Some(source),
            _ => None,
        }
    }
}

/// Why a discovery announce was suppressed while preparing it.
#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum AnnounceError {
    /// The interface's `location_cmd` gave no coordinates.
    Location(LocationError),
    /// An interface of this type is announced only with a `reachable_on`
    /// address.
    NoReachableAddress {
        /// The interface's type.
        interface_type: String,
    },
    /// The announce is to be encrypted, but no network identity is
    /// configured.
    NoNetworkIdentity {
        /// The interface's discovery name.
        name: String,
    },
    /// Encrypting the announce failed.
    Encryption(rns_crypto::identity::CryptoError),
}

impl std::fmt::Display for AnnounceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnnounceError::Location(error) => error.fmt(f),
            AnnounceError::NoReachableAddress { interface_type } => write!(
                f,
                "{interface_type} discovery requires a reachable_on address"
            ),
            AnnounceError::NoNetworkIdentity { name } => write!(
                f,
                "Discovery encryption requested for {name}, but no network identity configured"
            ),
            AnnounceError::Encryption(error) => {
                write!(f, "Discovery encryption failed: {error:?}")
            }
        }
    }
}

impl std::error::Error for AnnounceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AnnounceError::Location(error) => Some(error),
            AnnounceError::Encryption(error) => Some(error),
            _ => None,
        }
    }
}
