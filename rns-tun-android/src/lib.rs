//! Android host boundary for `VpnService` integration.
//!
//! The C ABI has explicit descriptor ownership. Protocol and session logic
//! remains in `rns-tun`; Java/Kotlin can bind this directly or via thin JNI.

mod session;

use std::collections::{HashMap, VecDeque};
use std::ffi::{c_char, c_void, CStr};
use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex, OnceLock};

use rns_tun::{SocketProtector, SocketProtectorGuard};
use session::{AndroidConfig, AndroidRuntime};

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

pub fn install_protector(
    handle: u64,
    callback: ProtectCallback,
    user_data: *mut c_void,
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
    let guard = rns_tun::install_socket_protector(Arc::new(HostProtector {
        callback,
        user_data: user_data as usize,
    }))?;
    entry.protector = Some(guard);
    Ok(())
}

pub fn attach_owned_tun(handle: u64, fd: OwnedFd) -> io::Result<()> {
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
        .try_send(fd)
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "TUN is already attached"))
}

pub fn attach_duplicated_tun(handle: u64, fd: RawFd) -> io::Result<()> {
    let duplicate = unsafe { libc::dup(fd) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    attach_owned_tun(handle, unsafe { OwnedFd::from_raw_fd(duplicate) })
}

pub fn destroy_handle(handle: u64) -> bool {
    let removed = handles()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&handle);
    if let Some(entry) = &removed {
        if let Some(runtime) = &entry.runtime {
            runtime
                .stop
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
    removed.is_some()
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

/// Create a host handle. Returns zero for null, non-UTF-8, or malformed input.
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
#[no_mangle]
pub unsafe extern "C" fn rntun_android_attach_tun_owned(
    handle: u64,
    fd: libc::c_int,
) -> libc::c_int {
    if fd < 0 {
        return libc::EBADF;
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    attach_owned_tun(handle, owned).map_or_else(|_| libc::EINVAL, |_| 0)
}

/// Duplicate `fd`; the host retains ownership of the original descriptor.
#[no_mangle]
pub extern "C" fn rntun_android_attach_tun_dup(handle: u64, fd: libc::c_int) -> libc::c_int {
    attach_duplicated_tun(handle, fd).map_or_else(|_| libc::EINVAL, |_| 0)
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
