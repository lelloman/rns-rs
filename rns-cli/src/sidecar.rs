//! What rns-statsd and rns-sentineld share: their hooks in the running
//! instance, managed over its RPC, the provider bridge they read the hooks'
//! events from, and their errors.

use std::fmt;
use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use rns_net::provider_bridge::{decode_provider_envelope, ProviderEnvelope};
use rns_net::storage;
use rns_net::{HookInfo, RpcClient, SharedInstanceRpc};

use crate::readiness::ReadyFileError;
use crate::shared_instance::LocalInstance;

/// Why a sidecar stopped. `Display` is the message it prints after its
/// name.
#[derive(Debug)]
pub(crate) enum SidecarError {
    /// A message of its own: bad options, configuration, a refusal from the
    /// instance.
    Message(String),
    /// The instance's RPC server could not be reached.
    RpcConnect(io::Error),
    /// An RPC call failed.
    RpcCall(io::Error),
    /// A hook could not be loaded.
    LoadHook {
        name: &'static str,
        attach_point: &'static str,
        source: Box<SidecarError>,
    },
    /// Stopped by a signal while waiting.
    Interrupted(&'static str),
    /// The provider bridge connection could not be set up.
    BridgeTimeout(io::Error),
    /// The readiness file could not be written or removed.
    ReadyFile(ReadyFileError),
    /// A database operation failed; `action` names it.
    Sqlite {
        action: &'static str,
        source: rusqlite::Error,
    },
    /// What failed, then why: `<context>: <source>`.
    Context {
        context: &'static str,
        source: Box<SidecarError>,
    },
}

impl SidecarError {
    /// This error, after `context`.
    pub(crate) fn context(self, context: &'static str) -> Self {
        Self::Context {
            context,
            source: Box::new(self),
        }
    }
}

impl fmt::Display for SidecarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(message) => f.write_str(message),
            Self::RpcConnect(e) => write!(f, "rpc connect failed: {}", e),
            Self::RpcCall(e) => write!(f, "rpc call failed: {}", e),
            Self::LoadHook {
                name,
                attach_point,
                source,
            } => write!(f, "failed to load {} at {}: {}", name, attach_point, source),
            Self::Interrupted(message) => f.write_str(message),
            Self::BridgeTimeout(e) => write!(f, "provider bridge timeout setup failed: {}", e),
            Self::ReadyFile(e) => e.fmt(f),
            Self::Sqlite { action, source } => write!(f, "sqlite {} failed: {}", action, source),
            Self::Context { context, source } => write!(f, "{}: {}", context, source),
        }
    }
}

impl std::error::Error for SidecarError {}

impl From<String> for SidecarError {
    fn from(message: String) -> Self {
        Self::Message(message)
    }
}

impl From<ReadyFileError> for SidecarError {
    fn from(e: ReadyFileError) -> Self {
        Self::ReadyFile(e)
    }
}

/// A sidecar's hooks: the name and attach point of each, and where their
/// code comes from.
pub(crate) struct Hooks {
    pub(crate) specs: &'static [(&'static str, &'static str)],
    /// The WebAssembly module, built into the sidecar.
    #[cfg(feature = "rns-hooks-wasm")]
    pub(crate) wasm: &'static [u8],
    /// The id of the hook built into rnsd.
    #[cfg(not(feature = "rns-hooks-wasm"))]
    pub(crate) builtin_id: &'static str,
}

/// The running instance, controlled over its RPC: each call on a
/// connection of its own.
#[derive(Clone)]
pub(crate) struct RpcControl {
    rpc: SharedInstanceRpc,
    hooks: &'static Hooks,
}

impl RpcControl {
    pub(crate) fn new(rpc: SharedInstanceRpc, hooks: &'static Hooks) -> Self {
        Self { rpc, hooks }
    }

    /// Run `op` on a new connection.
    pub(crate) fn with_client<T>(
        &self,
        op: impl FnOnce(&mut RpcClient) -> io::Result<T>,
    ) -> Result<T, SidecarError> {
        let mut client = self.rpc.connect().map_err(SidecarError::RpcConnect)?;
        op(&mut client).map_err(SidecarError::RpcCall)
    }

    fn load_hook(&self, name: &str, attach_point: &str, priority: i32) -> Result<(), SidecarError> {
        #[cfg(feature = "rns-hooks-wasm")]
        let loaded = self.with_client(|client| {
            client.load_hook(name, attach_point, priority, self.hooks.wasm)
        })?;
        #[cfg(not(feature = "rns-hooks-wasm"))]
        let loaded = self.with_client(|client| {
            client.load_builtin_hook(name, attach_point, priority, self.hooks.builtin_id)
        })?;
        loaded.map_err(SidecarError::Message)
    }

    pub(crate) fn unload_hook(&self, name: &str, attach_point: &str) -> Result<(), SidecarError> {
        self.with_client(|client| client.unload_hook(name, attach_point))?
            .map_err(SidecarError::Message)
    }

    fn list_hooks(&self) -> Result<Vec<HookInfo>, SidecarError> {
        self.with_client(|client| client.list_hooks())
    }

    /// Load every hook; on a failure, unload those already loaded.
    pub(crate) fn load_hooks(&self, priority: i32) -> Result<(), SidecarError> {
        let mut loaded = Vec::new();
        for &(name, attach_point) in self.hooks.specs {
            if let Err(err) = self.load_hook(name, attach_point, priority) {
                for (loaded_name, loaded_attach_point) in loaded.into_iter().rev() {
                    let _ = self.unload_hook(loaded_name, loaded_attach_point);
                }
                return Err(SidecarError::LoadHook {
                    name,
                    attach_point,
                    source: Box::new(err),
                });
            }
            loaded.push((name, attach_point));
        }
        Ok(())
    }

    /// Unload this sidecar's hooks a previous run left loaded.
    pub(crate) fn unload_stale_hooks(&self) {
        match self.list_hooks() {
            Ok(hooks) => {
                for hook in hooks {
                    if self.hooks.specs.iter().any(|(name, attach_point)| {
                        *name == hook.name && *attach_point == hook.attach_point
                    }) {
                        let _ = self.unload_hook(&hook.name, &hook.attach_point);
                    }
                }
            }
            Err(err) => {
                log::debug!("could not list hooks for stale cleanup: {}", err);
                self.unload_all_hooks();
            }
        }
    }

    fn unload_all_hooks(&self) {
        for (name, attach_point) in self.hooks.specs {
            let _ = self.unload_hook(name, attach_point);
        }
    }
}

/// Unloads the sidecar's hooks when dropped.
pub(crate) struct HookGuard(pub(crate) RpcControl);

impl Drop for HookGuard {
    fn drop(&mut self) {
        self.0.unload_all_hooks();
    }
}

/// Where a sidecar finds the instance: its RPC, and the provider bridge
/// socket.
pub(crate) struct RuntimeConfig {
    pub(crate) rpc: SharedInstanceRpc,
    pub(crate) provider_socket: PathBuf,
}

impl RuntimeConfig {
    /// From the config in `config_path`; `socket_override` replaces the
    /// configured provider bridge socket.
    pub(crate) fn load(
        config_path: Option<&Path>,
        socket_override: Option<&str>,
    ) -> Result<Self, SidecarError> {
        let config_dir = storage::resolve_config_dir(config_path);
        let LocalInstance { config, rpc, .. } = LocalInstance::open(&config_dir)
            .map_err(|e| SidecarError::Message(e.cause().to_string()))?;
        let provider_socket = socket_override
            .map(PathBuf::from)
            .or_else(|| {
                config
                    .reticulum
                    .provider_socket_path
                    .as_ref()
                    .map(PathBuf::from)
            })
            .ok_or_else(|| {
                SidecarError::Message("provider bridge socket is not configured".into())
            })?;

        Ok(Self {
            rpc,
            provider_socket,
        })
    }
}

/// The next envelope from the provider bridge, or `None` when none arrived
/// before the read timeout.
pub(crate) fn read_provider_envelope(
    stream: &mut UnixStream,
) -> io::Result<Option<ProviderEnvelope>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            return Ok(None);
        }
        Err(err) => return Err(err),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    let envelope: ProviderEnvelope = decode_provider_envelope(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(envelope))
}
