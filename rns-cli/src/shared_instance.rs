//! Reaching the local shared instance's RPC server, as the CLI tools do.

use std::fmt;
use std::io;
use std::path::Path;

use rns_net::config::{self, ConfigError, RnsConfig};
use rns_net::storage::{self, StoragePaths};
use rns_net::SharedInstanceRpc;

/// What upstream's `RNS.Reticulum(configdir)` gives a tool for the local
/// instance: the config, the storage, and the shared instance's RPC.
pub struct LocalInstance {
    /// The parsed config, or the defaults without a config file.
    pub config: RnsConfig,
    /// The storage directories, created if missing.
    pub paths: StoragePaths,
    /// The shared instance's RPC server and its key.
    pub rpc: SharedInstanceRpc,
}

/// Why [`LocalInstance::open`] failed. Its `Display` is the line the tools
/// print for it.
#[derive(Debug)]
pub enum LocalInstanceError {
    /// The config file could not be read or parsed.
    ReadConfig(ConfigError),
    /// The default config could not be parsed.
    DefaultConfig(ConfigError),
    /// The storage directories could not be created.
    Storage(io::Error),
    /// The transport identity could not be loaded, or has no private key.
    Identity(io::Error),
}

impl LocalInstanceError {
    /// The underlying error, without the tools' prefix.
    pub fn cause(&self) -> &dyn fmt::Display {
        match self {
            Self::ReadConfig(e) | Self::DefaultConfig(e) => e,
            Self::Storage(e) | Self::Identity(e) => e,
        }
    }
}

impl fmt::Display for LocalInstanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadConfig(e) => write!(f, "Error reading config: {e}"),
            Self::DefaultConfig(e) => write!(f, "Error: {e}"),
            Self::Storage(e) => write!(f, "Error: {e}"),
            Self::Identity(e) => write!(f, "Error loading identity: {e}"),
        }
    }
}

impl std::error::Error for LocalInstanceError {}

impl LocalInstance {
    /// Load the config in `config_dir`, create its storage and derive the
    /// shared instance's RPC key from its transport identity (created if
    /// the directory has none yet). The identity is loaded even with an
    /// `rpc_key` configured.
    pub fn open(config_dir: &Path) -> Result<Self, LocalInstanceError> {
        let config_file = config_dir.join("config");
        let config = if config_file.exists() {
            config::parse_file(&config_file).map_err(LocalInstanceError::ReadConfig)?
        } else {
            config::parse("").map_err(LocalInstanceError::DefaultConfig)?
        };
        let paths =
            storage::ensure_storage_dirs(config_dir).map_err(LocalInstanceError::Storage)?;
        let identity = storage::load_rpc_identity(&paths).map_err(LocalInstanceError::Identity)?;
        let rpc = SharedInstanceRpc::new(&config.reticulum, || Ok(identity))
            .map_err(LocalInstanceError::Identity)?;
        Ok(Self { config, paths, rpc })
    }
}
