//! Android host boundary for `VpnService` integration.
//!
//! The C ABI has explicit descriptor ownership. Protocol and session logic
//! remains in `rns-tun`; Java/Kotlin can bind this directly or via thin JNI.

mod bundle;
mod jni_api;
mod session;

use std::collections::{HashMap, VecDeque};
use std::ffi::{c_char, c_void, CStr};
use std::fs;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex, OnceLock};

use rns_tun::{SocketProtector, SocketProtectorGuard};
use session::{AndroidConfig, AndroidRuntime, AppliedTunConfig, TunAttachment};

pub type ProtectCallback = unsafe extern "C" fn(fd: libc::c_int, user_data: *mut c_void) -> bool;

struct HostProtector {
    callback: ProtectCallback,
    user_data: usize,
}
impl SocketProtector for HostProtector {
    fn protect(&self, fd: RawFd) -> io::Result<()> {
        if unsafe { (self.callback)(fd, self.user_data as *mut c_void) } {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VpnService.protect rejected an underlay socket",
            ))
        }
    }
}

struct Handle {
    config: AndroidConfig,
    protector: Option<SocketProtectorGuard>,
    runtime: Option<AndroidRuntime>,
    pending_events: VecDeque<String>,
}

fn handles() -> &'static Mutex<HashMap<u64, Handle>> {
    static HANDLES: OnceLock<Mutex<HashMap<u64, Handle>>> = OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn create_handle(config_json: String) -> io::Result<u64> {
    let config: AndroidConfig = serde_json::from_str(&config_json).map_err(io::Error::other)?;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    handles().lock().unwrap_or_else(|p| p.into_inner()).insert(
        id,
        Handle {
            config,
            protector: None,
            runtime: None,
            pending_events: VecDeque::new(),
        },
    );
    Ok(id)
}

pub fn install_protector_object(
    handle: u64,
    protector: Arc<dyn SocketProtector>,
) -> io::Result<()> {
    let mut map = handles().lock().unwrap_or_else(|p| p.into_inner());
    let entry = map
        .get_mut(&handle)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown handle"))?;
    if entry.protector.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "protector already installed",
        ));
    }
    entry.protector = Some(rns_tun::install_socket_protector(protector)?);
    Ok(())
}

pub fn install_protector(
    handle: u64,
    callback: ProtectCallback,
    user_data: *mut c_void,
) -> io::Result<()> {
    install_protector_object(
        handle,
        Arc::new(HostProtector {
            callback,
            user_data: user_data as usize,
        }),
    )
}

pub fn ensure_identity(path: &std::path::Path) -> io::Result<String> {
    let identity = rns_tun::identity::load_or_create(path)?;
    Ok(hex(identity.hash()))
}

pub fn export_identity(path: &std::path::Path) -> io::Result<Vec<u8>> {
    let identity = rns_net::storage::load_identity(path)?;
    identity
        .get_private_key()
        .map(|key| key.to_vec())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "identity has no private key"))
}

pub fn import_identity(path: &std::path::Path, bytes: &[u8]) -> io::Result<String> {
    if handles()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .values()
        .any(|handle| handle.runtime.is_some())
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "identity cannot be replaced while a tunnel is running",
        ));
    }
    let key: [u8; 64] = bytes.try_into().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "identity must contain 64 bytes")
    })?;
    let identity = rns_crypto::identity::Identity::from_private_key(&key);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("import-{}", std::process::id()));
    rns_net::storage::save_identity(&identity, &temporary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&temporary, path).inspect_err(|_| {
        let _ = fs::remove_file(&temporary);
    })?;
    Ok(hex(identity.hash()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn validate_node_config_text(text: &str, full_tunnel: bool) -> io::Result<()> {
    let parsed = rns_net::config::parse(text)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let enabled: Vec<_> = parsed
        .interfaces
        .iter()
        .filter(|interface| interface.enabled)
        .collect();
    if enabled.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Reticulum configuration has no enabled interface",
        ));
    }
    for interface in enabled {
        if !matches!(
            interface.interface_type.as_str(),
            "TCPClientInterface" | "TCPServerInterface" | "UDPInterface" | "AutoInterface"
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Android does not support enabled interface type '{}'",
                    interface.interface_type
                ),
            ));
        }
    }
    if full_tunnel {
        rns_tun::config::validate_full_tunnel_node_config_text(text)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    }
    Ok(())
}

pub fn attach_owned_tun(
    handle: u64,
    fd: OwnedFd,
    applied: Option<AppliedTunConfig>,
) -> io::Result<()> {
    let mut map = handles().lock().unwrap_or_else(|p| p.into_inner());
    let entry = map
        .get_mut(&handle)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown handle"))?;
    let runtime = entry
        .runtime
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "session is not started"))?;
    runtime
        .tun_tx
        .try_send(TunAttachment { fd, applied })
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "TUN is already attached"))
}

pub fn attach_duplicated_tun(
    handle: u64,
    fd: RawFd,
    applied: Option<AppliedTunConfig>,
) -> io::Result<()> {
    let duplicate = unsafe { libc::dup(fd) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    attach_owned_tun(handle, unsafe { OwnedFd::from_raw_fd(duplicate) }, applied)
}

pub fn destroy_handle(handle: u64) -> bool {
    let removed = handles()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&handle);
    if let Some(mut entry) = removed {
        if let Some(runtime) = entry.runtime.take() {
            runtime.shutdown();
        }
        return true;
    }
    false
}

pub fn start_handle(handle: u64) -> io::Result<()> {
    let mut map = handles().lock().unwrap_or_else(|p| p.into_inner());
    let entry = map
        .get_mut(&handle)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown handle"))?;
    if entry.runtime.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "session already started",
        ));
    }
    let protector = entry.protector.take().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socket protector must be installed before start",
        )
    })?;
    match AndroidRuntime::start(entry.config.clone(), protector) {
        Ok(runtime) => entry.runtime = Some(runtime),
        Err(error) => return Err(error),
    }
    Ok(())
}

pub fn poll_event(handle: u64) -> io::Result<Option<String>> {
    let mut map = handles().lock().unwrap_or_else(|p| p.into_inner());
    let entry = map
        .get_mut(&handle)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown handle"))?;
    if let Some(event) = entry.pending_events.pop_front() {
        return Ok(Some(event));
    }
    let Some(runtime) = &entry.runtime else {
        return Ok(None);
    };
    Ok(runtime.events.try_recv().ok())
}

pub fn status_json(handle: u64) -> io::Result<String> {
    let map = handles().lock().unwrap_or_else(|p| p.into_inner());
    let entry = map
        .get(&handle)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown handle"))?;
    let status = entry
        .runtime
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "session is not started"))?
        .status
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    serde_json::to_string(&status).map_err(io::Error::other)
}

/// Create a host handle. Returns zero for null, non-UTF-8, or malformed input.
///
/// # Safety
///
/// `config_json` must be null or point to a valid NUL-terminated byte string
/// for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn rntun_android_create(config_json: *const c_char) -> u64 {
    if config_json.is_null() {
        return 0;
    }
    let Ok(config) = unsafe { CStr::from_ptr(config_json) }.to_str() else {
        return 0;
    };
    create_handle(config.to_owned()).unwrap_or(0)
}

/// Register the required `VpnService.protect(fd)` callback.
#[no_mangle]
pub extern "C" fn rntun_android_set_protector(
    handle: u64,
    callback: Option<ProtectCallback>,
    user_data: *mut c_void,
) -> libc::c_int {
    let Some(callback) = callback else {
        return libc::EINVAL;
    };
    install_protector(handle, callback, user_data).map_or_else(|_| libc::EINVAL, |_| 0)
}

/// Start Reticulum negotiation. Install the protector first, then poll until
/// an `accepted` event describes the settings to apply to `VpnService.Builder`.
#[no_mangle]
pub extern "C" fn rntun_android_start(handle: u64) -> libc::c_int {
    start_handle(handle).map_or_else(|_| libc::EINVAL, |_| 0)
}

/// Poll one UTF-8 JSON event. Returns zero when no event is ready, a positive
/// byte count including NUL on success, or the required size when `capacity`
/// is too small (the event remains queued).
///
/// # Safety
///
/// When `output` is non-null and `capacity` is large enough for the reported
/// event, it must point to writable memory spanning at least `capacity` bytes.
#[no_mangle]
pub unsafe extern "C" fn rntun_android_poll_event(
    handle: u64,
    output: *mut c_char,
    capacity: usize,
) -> isize {
    let mut map = handles().lock().unwrap_or_else(|p| p.into_inner());
    let Some(entry) = map.get_mut(&handle) else {
        return -(libc::ENOENT as isize);
    };
    if entry.pending_events.is_empty() {
        if let Some(runtime) = &entry.runtime {
            if let Ok(event) = runtime.events.try_recv() {
                entry.pending_events.push_back(event);
            }
        }
    }
    let Some(event) = entry.pending_events.front() else {
        return 0;
    };
    let required = event.len() + 1;
    if output.is_null() || capacity < required {
        return required as isize;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(event.as_ptr(), output.cast::<u8>(), event.len());
        *output.add(event.len()) = 0;
    }
    entry.pending_events.pop_front();
    required as isize
}

/// Transfer ownership of `fd` to Rust. Rust closes it with the handle.
///
/// # Safety
///
/// `fd` must be either negative or a valid, open file descriptor owned by the
/// caller. For a non-negative descriptor, ownership is transferred on entry
/// and the caller must not use or close it afterward, even if this call fails.
#[no_mangle]
pub unsafe extern "C" fn rntun_android_attach_tun_owned(
    handle: u64,
    fd: libc::c_int,
) -> libc::c_int {
    if fd < 0 {
        return libc::EBADF;
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    attach_owned_tun(handle, owned, None).map_or_else(|_| libc::EINVAL, |_| 0)
}

/// Duplicate `fd`; the host retains ownership of the original descriptor.
#[no_mangle]
pub extern "C" fn rntun_android_attach_tun_dup(handle: u64, fd: libc::c_int) -> libc::c_int {
    attach_duplicated_tun(handle, fd, None).map_or_else(|_| libc::EINVAL, |_| 0)
}

/// Duplicate `fd` and require a JSON acknowledgement of the exact TUN
/// configuration applied by the host before the protocol becomes ready.
///
/// # Safety
///
/// `applied_json` must be null or point to a valid NUL-terminated byte string
/// for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn rntun_android_attach_tun_dup_v2(
    handle: u64,
    fd: libc::c_int,
    applied_json: *const c_char,
) -> libc::c_int {
    if applied_json.is_null() {
        return libc::EINVAL;
    }
    let Ok(value) = unsafe { CStr::from_ptr(applied_json) }.to_str() else {
        return libc::EINVAL;
    };
    let Ok(applied) = serde_json::from_str::<AppliedTunConfig>(value) else {
        return libc::EINVAL;
    };
    attach_duplicated_tun(handle, fd, Some(applied)).map_or_else(|_| libc::EINVAL, |_| 0)
}

#[no_mangle]
pub extern "C" fn rntun_android_destroy(handle: u64) -> bool {
    destroy_handle(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handle_lifecycle_and_validation() {
        assert!(create_handle("[]".into()).is_err());
        let config = r#"{
            "node_config_dir":"node",
            "state_dir":"state",
            "destination_hash":"00112233445566778899aabbccddeeff"
        }"#;
        let handle = create_handle(config.into()).unwrap();
        assert!(handles()
            .lock()
            .unwrap()
            .get(&handle)
            .unwrap()
            .runtime
            .is_none());
        assert!(destroy_handle(handle));
        assert!(!destroy_handle(handle));
    }
}
