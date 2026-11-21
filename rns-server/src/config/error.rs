use std::fmt;
use std::io;
use std::path::PathBuf;

/// Why an `rns-server.json` document was rejected or could not be loaded or
/// saved.
///
/// Its `Display` text is what the config API returns as the error and what
/// `rns-server` logs for a config file it cannot load.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServerConfigError {
    /// The config file could not be read.
    ReadFile {
        /// The config file.
        path: PathBuf,
        /// Why it could not be read.
        source: io::Error,
    },
    /// The document is not valid `rns-server.json` JSON.
    InvalidJson(serde_json::Error),
    /// A string field that is set is empty or only whitespace.
    Empty(&'static str),
    /// `logs.max_file_size_mb` is 0.
    LogFileSizeZero,
    /// `logs.max_file_size_mb` is above 10240.
    LogFileSizeTooLarge,
    /// `logs.max_archives` is above 100.
    LogArchivesTooMany,
    /// `stats.max_age_days` is 0.
    StatsMaxAgeZero,
    /// `stats.max_age_days` is above 3650.
    StatsMaxAgeTooLarge,
    /// `stats.max_size_mb` is below 64.
    StatsMaxSizeTooSmall,
    /// `stats.max_size_mb` is above 1048576.
    StatsMaxSizeTooLarge,
    /// `http.port` is 0 while HTTP is enabled.
    HttpPortZero,
    /// The API submission changes one of the
    /// [`API_READ_ONLY_KEYS`](super::API_READ_ONLY_KEYS).
    ReadOnlyKey {
        /// The key.
        key: &'static str,
        /// The config file where it can be changed instead.
        file: PathBuf,
    },
    /// The config directory could not be created.
    CreateConfigDir {
        /// The config directory.
        path: PathBuf,
        /// Why it could not be created.
        source: io::Error,
    },
    /// The new document could not be serialized.
    Serialize(serde_json::Error),
    /// The config file could not be written.
    WriteFile {
        /// The config file.
        path: PathBuf,
        /// Why it could not be written.
        source: io::Error,
    },
    /// A restart of the named process could not be queued, because the
    /// supervisor is gone.
    QueueRestart(String),
}

impl fmt::Display for ServerConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerConfigError::ReadFile { path, source } => {
                write!(f, "failed to read {}: {}", path.display(), source)
            }
            ServerConfigError::InvalidJson(error) => {
                write!(f, "invalid server config JSON: {}", error)
            }
            ServerConfigError::Empty(field) => write!(f, "{field} cannot be empty"),
            ServerConfigError::LogFileSizeZero => {
                f.write_str("logs.max_file_size_mb must be greater than 0")
            }
            ServerConfigError::LogFileSizeTooLarge => {
                f.write_str("logs.max_file_size_mb must not exceed 10240")
            }
            ServerConfigError::LogArchivesTooMany => {
                f.write_str("logs.max_archives must not exceed 100")
            }
            ServerConfigError::StatsMaxAgeZero => {
                f.write_str("stats.max_age_days must be greater than 0 or null")
            }
            ServerConfigError::StatsMaxAgeTooLarge => {
                f.write_str("stats.max_age_days must not exceed 3650")
            }
            ServerConfigError::StatsMaxSizeTooSmall => {
                f.write_str("stats.max_size_mb must be at least 64 or null")
            }
            ServerConfigError::StatsMaxSizeTooLarge => {
                f.write_str("stats.max_size_mb must not exceed 1048576")
            }
            ServerConfigError::HttpPortZero => {
                f.write_str("http.port must be greater than 0 when HTTP is enabled")
            }
            ServerConfigError::ReadOnlyKey { key, file } => write!(
                f,
                "read-only key: {key} can only be changed by editing {} and restarting rns-server",
                file.display()
            ),
            ServerConfigError::CreateConfigDir { path, source } => write!(
                f,
                "failed to create config dir {}: {}",
                path.display(),
                source
            ),
            ServerConfigError::Serialize(error) => {
                write!(f, "failed to serialize server config JSON: {}", error)
            }
            ServerConfigError::WriteFile { path, source } => {
                write!(f, "failed to write {}: {}", path.display(), source)
            }
            ServerConfigError::QueueRestart(process) => {
                write!(f, "failed to queue restart for process '{}'", process)
            }
        }
    }
}

impl std::error::Error for ServerConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ServerConfigError::ReadFile { source, .. }
            | ServerConfigError::CreateConfigDir { source, .. }
            | ServerConfigError::WriteFile { source, .. } => Some(source),
            ServerConfigError::InvalidJson(error) | ServerConfigError::Serialize(error) => {
                Some(error)
            }
            _ => None,
        }
    }
}

/// Why the runtime storage or node identity could not be set up.
#[derive(Debug)]
#[non_exhaustive]
pub enum BootstrapError {
    /// The storage directories could not be created.
    StorageDirs(io::Error),
    /// The node identity could not be loaded or created.
    Identity(io::Error),
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootstrapError::StorageDirs(error) => {
                write!(f, "failed to create runtime storage dirs: {}", error)
            }
            BootstrapError::Identity(error) => {
                write!(f, "failed to initialize node identity: {}", error)
            }
        }
    }
}

impl std::error::Error for BootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BootstrapError::StorageDirs(error) | BootstrapError::Identity(error) => Some(error),
        }
    }
}
