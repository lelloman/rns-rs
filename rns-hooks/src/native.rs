#![allow(
    unsafe_code,
    reason = "loading native hook libraries and their C ABI callbacks"
)]

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use libloading::Library;
use rns_hooks_abi::native::{
    NativeHookAbiVersionFn, NativeHookOnCallFn, RnsNativeHostApi, NATIVE_HOOK_ABI_VERSION_SYMBOL,
    NATIVE_HOOK_ON_CALL_SYMBOL, NATIVE_HOST_API_VERSION,
};

use crate::engine_access::EngineAccess;
use crate::error::HookError;
use crate::result::{ExecuteResult, HookResult, Verdict};
use crate::runtime::RawProviderEvent;
use crate::wire::ActionWire;

pub struct NativeProgram {
    _library: Library,
    on_call: NativeHookOnCallFn,
}

/// Path handed to the dynamic loader for a native hook file.
///
/// A bare file name (no directory component) is anchored to the current
/// directory, so it is always treated as a file path and the dynamic loader's
/// library search path is never used.
fn loader_path(path: &Path) -> PathBuf {
    let has_dir = path.is_absolute()
        || path
            .parent()
            .is_some_and(|parent| !parent.as_os_str().is_empty());
    if has_dir {
        path.to_path_buf()
    } else {
        Path::new(".").join(path)
    }
}

impl NativeProgram {
    pub fn load(path: &Path) -> Result<Self, HookError> {
        let path = loader_path(path);
        let path = path.as_path();
        // SAFETY: loading runs the library's initializers; native hooks are trusted
        // code the operator configured, and `loader_path` keeps the loader from
        // resolving a bare name through its search path.
        let library = unsafe { Library::new(path) }
            .map_err(|e| HookError::CompileError(format!("failed to load native hook: {}", e)))?;

        // SAFETY: `NativeHookAbiVersionFn` is the type the native hook ABI
        // (rns-hooks-abi) defines for this symbol; the copied fn pointer is only
        // called below while `library` is still loaded.
        let abi_version = unsafe {
            let symbol = library
                .get::<NativeHookAbiVersionFn>(NATIVE_HOOK_ABI_VERSION_SYMBOL)
                .map_err(|e| {
                    HookError::CompileError(format!(
                        "native hook missing rns_hook_abi_version: {}",
                        e
                    ))
                })?;
            *symbol
        };
        // SAFETY: `abi_version` comes from `library`, which is alive in this scope,
        // and takes no arguments.
        let found = unsafe { abi_version() };
        if found != rns_hooks_abi::ABI_VERSION {
            return Err(HookError::AbiVersionMismatch {
                hook_name: path.display().to_string(),
                expected: rns_hooks_abi::ABI_VERSION,
                found: Some(found),
            });
        }

        // SAFETY: `NativeHookOnCallFn` is the ABI-defined type for this symbol (and
        // the ABI version was checked above); the fn pointer is stored next to
        // `_library` in `Self`, so the code stays mapped for as long as it is callable.
        let on_call = unsafe {
            let symbol = library
                .get::<NativeHookOnCallFn>(NATIVE_HOOK_ON_CALL_SYMBOL)
                .map_err(|e| {
                    HookError::CompileError(format!("native hook missing rns_hook_on_call: {}", e))
                })?;
            *symbol
        };

        Ok(Self {
            _library: library,
            on_call,
        })
    }

    pub fn execute(
        &self,
        ctx_bytes: &[u8],
        engine_access: &dyn EngineAccess,
        provider_events_enabled: bool,
    ) -> Result<ExecuteResult, HookError> {
        let mut state = NativeCallState {
            engine_access,
            injected_actions: Vec::new(),
            provider_events: Vec::new(),
            provider_events_enabled,
            modified_data: None,
        };
        let mut result = HookResult::continue_result();
        let api = RnsNativeHostApi {
            version: NATIVE_HOST_API_VERSION,
            user_data: (&mut state as *mut NativeCallState<'_>).cast::<c_void>(),
            log: Some(native_log),
            has_path: Some(native_has_path),
            get_hops: Some(native_get_hops),
            get_next_hop: Some(native_get_next_hop),
            is_blackholed: Some(native_is_blackholed),
            get_interface_name: Some(native_get_interface_name),
            get_interface_mode: Some(native_get_interface_mode),
            get_transport_identity: Some(native_get_transport_identity),
            get_announce_rate: Some(native_get_announce_rate),
            get_link_state: Some(native_get_link_state),
            inject_action: Some(native_inject_action),
            emit_event: Some(native_emit_event),
            set_modified_data: Some(native_set_modified_data),
        };

        // SAFETY: `self._library` keeps `on_call` loaded; `ctx_bytes` is a live slice
        // of the length passed, `api` and `result` are live locals, and
        // `api.user_data` points to `state`, alive and not otherwise accessed until
        // the call returns (the ABI contract above `NativeCallState`).
        let rc = unsafe { (self.on_call)(ctx_bytes.as_ptr(), ctx_bytes.len(), &api, &mut result) };
        if rc != 0 {
            return Err(HookError::Trap(format!(
                "native hook returned error code {}",
                rc
            )));
        }
        if Verdict::from_u32(result.verdict).is_none() {
            return Err(HookError::InvalidResult(format!(
                "invalid verdict value: {}",
                result.verdict
            )));
        }

        Ok(ExecuteResult {
            hook_result: Some(result),
            injected_actions: state.injected_actions,
            provider_events: state
                .provider_events
                .into_iter()
                .map(|event| crate::result::EmittedProviderEvent {
                    hook_name: String::new(),
                    payload_type: event.payload_type,
                    payload: event.payload,
                })
                .collect(),
            modified_data: state.modified_data,
        })
    }
}

// The host API callbacks below are called by the hook's code during
// `on_call`. The contract of the native hook ABI, which every callback
// relies on: `user_data` is the pointer `call` put in the API table, to a
// `NativeCallState` alive for the whole call; every (pointer, length) pair
// the hook passes is either null or valid for reading that many bytes;
// every output pointer is either null or valid for writing the size the
// callback documents (16 bytes for hashes, `out_len` for names).

struct NativeCallState<'a> {
    engine_access: &'a dyn EngineAccess,
    injected_actions: Vec<ActionWire>,
    provider_events: Vec<RawProviderEvent>,
    provider_events_enabled: bool,
    modified_data: Option<Vec<u8>>,
}

/// The call's state from the API table's `user_data`.
///
/// # Safety
/// `user_data` is null or the pointer `call` put in the API table, during
/// that call.
unsafe fn state<'a>(user_data: *mut c_void) -> Option<&'a mut NativeCallState<'a>> {
    // SAFETY: the caller's contract: null or a live, unaliased state.
    unsafe { user_data.cast::<NativeCallState<'a>>().as_mut() }
}

/// The `len` bytes at `ptr`, or None for a null pointer.
///
/// # Safety
/// `ptr` is null or valid for reading `len` bytes for `'a`.
unsafe fn read_bytes<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: not null, so valid for `len` bytes by the caller's contract.
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// The 16 bytes at `ptr`, or None for a null pointer.
///
/// # Safety
/// `ptr` is null or valid for reading 16 bytes.
unsafe fn read_16(ptr: *const u8) -> Option<[u8; 16]> {
    // SAFETY: the caller's contract is read_bytes' for 16 bytes.
    let bytes = unsafe { read_bytes(ptr, 16) }?;
    let mut out = [0u8; 16];
    out.copy_from_slice(bytes);
    Some(out)
}

unsafe extern "C" fn native_log(user_data: *mut c_void, ptr: *const u8, len: usize) {
    // SAFETY: user_data comes from the API table (see the ABI contract above).
    if unsafe { state(user_data) }.is_none() {
        return;
    }
    // SAFETY: a pointer the hook passed, null or readable (ABI contract).
    let Some(bytes) = (unsafe { read_bytes(ptr, len) }) else {
        return;
    };
    log::debug!("[native-hook] {}", String::from_utf8_lossy(bytes));
}

unsafe extern "C" fn native_has_path(user_data: *mut c_void, dest_ptr: *const u8) -> i32 {
    // SAFETY: user_data comes from the API table (see the ABI contract above).
    let Some(state) = (unsafe { state(user_data) }) else {
        return 0;
    };
    // SAFETY: a pointer the hook passed, null or readable (ABI contract).
    let Some(dest) = (unsafe { read_16(dest_ptr) }) else {
        return 0;
    };
    state.engine_access.has_path(&dest) as i32
}

unsafe extern "C" fn native_get_hops(user_data: *mut c_void, dest_ptr: *const u8) -> i32 {
    // SAFETY: user_data comes from the API table (see the ABI contract above).
    let Some(state) = (unsafe { state(user_data) }) else {
        return -1;
    };
    // SAFETY: a pointer the hook passed, null or readable (ABI contract).
    let Some(dest) = (unsafe { read_16(dest_ptr) }) else {
        return -1;
    };
    state
        .engine_access
        .hops_to(&dest)
        .map(i32::from)
        .unwrap_or(-1)
}

unsafe extern "C" fn native_get_next_hop(
    user_data: *mut c_void,
    dest_ptr: *const u8,
    out_ptr: *mut u8,
) -> i32 {
    // SAFETY: user_data comes from the API table (see the ABI contract above).
    let Some(state) = (unsafe { state(user_data) }) else {
        return 0;
    };
    // SAFETY: a pointer the hook passed, null or readable (ABI contract).
    let Some(dest) = (unsafe { read_16(dest_ptr) }) else {
        return 0;
    };
    let Some(next_hop) = state.engine_access.next_hop(&dest) else {
        return 0;
    };
    if out_ptr.is_null() {
        return 0;
    }
    // SAFETY: out_ptr is not null, so writable for the documented size
    // (ABI contract); the source is a distinct host-owned buffer.
    unsafe { std::ptr::copy_nonoverlapping(next_hop.as_ptr(), out_ptr, next_hop.len()) };
    1
}

unsafe extern "C" fn native_is_blackholed(user_data: *mut c_void, ptr: *const u8) -> i32 {
    // SAFETY: user_data comes from the API table (see the ABI contract above).
    let Some(state) = (unsafe { state(user_data) }) else {
        return 0;
    };
    // SAFETY: a pointer the hook passed, null or readable (ABI contract).
    let Some(identity) = (unsafe { read_16(ptr) }) else {
        return 0;
    };
    state.engine_access.is_blackholed(&identity) as i32
}

unsafe extern "C" fn native_get_interface_name(
    user_data: *mut c_void,
    id: u64,
    out_ptr: *mut u8,
    out_len: usize,
) -> isize {
    // SAFETY: user_data comes from the API table (see the ABI contract above).
    let Some(state) = (unsafe { state(user_data) }) else {
        return -1;
    };
    let Some(name) = state.engine_access.interface_name(id) else {
        return -1;
    };
    if out_ptr.is_null() {
        return -1;
    }
    let bytes = name.as_bytes();
    let write_len = bytes.len().min(out_len);
    // SAFETY: out_ptr is not null, so writable for the documented size
    // (ABI contract); the source is a distinct host-owned buffer.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr, write_len) };
    write_len as isize
}

unsafe extern "C" fn native_get_interface_mode(user_data: *mut c_void, id: u64) -> i32 {
    // SAFETY: user_data comes from the API table (see the ABI contract above).
    let Some(state) = (unsafe { state(user_data) }) else {
        return -1;
    };
    state
        .engine_access
        .interface_mode(id)
        .map(i32::from)
        .unwrap_or(-1)
}

unsafe extern "C" fn native_get_transport_identity(
    user_data: *mut c_void,
    out_ptr: *mut u8,
) -> i32 {
    // SAFETY: user_data comes from the API table (see the ABI contract above).
    let Some(state) = (unsafe { state(user_data) }) else {
        return 0;
    };
    let Some(hash) = state.engine_access.identity_hash() else {
        return 0;
    };
    if out_ptr.is_null() {
        return 0;
    }
    // SAFETY: out_ptr is not null, so writable for the documented size
    // (ABI contract); the source is a distinct host-owned buffer.
    unsafe { std::ptr::copy_nonoverlapping(hash.as_ptr(), out_ptr, hash.len()) };
    1
}

unsafe extern "C" fn native_get_announce_rate(user_data: *mut c_void, id: u64) -> i32 {
    // SAFETY: user_data comes from the API table (see the ABI contract above).
    let Some(state) = (unsafe { state(user_data) }) else {
        return -1;
    };
    state.engine_access.announce_rate(id).unwrap_or(-1)
}

unsafe extern "C" fn native_get_link_state(user_data: *mut c_void, ptr: *const u8) -> i32 {
    // SAFETY: user_data comes from the API table (see the ABI contract above).
    let Some(state) = (unsafe { state(user_data) }) else {
        return -1;
    };
    // SAFETY: a pointer the hook passed, null or readable (ABI contract).
    let Some(link_hash) = (unsafe { read_16(ptr) }) else {
        return -1;
    };
    state
        .engine_access
        .link_state(&link_hash)
        .map(i32::from)
        .unwrap_or(-1)
}

unsafe extern "C" fn native_inject_action(
    user_data: *mut c_void,
    ptr: *const u8,
    len: usize,
) -> i32 {
    // SAFETY: user_data comes from the API table (see the ABI contract above).
    let Some(state) = (unsafe { state(user_data) }) else {
        return -1;
    };
    // SAFETY: a pointer the hook passed, null or readable (ABI contract).
    let Some(bytes) = (unsafe { read_bytes(ptr, len) }) else {
        return -1;
    };
    match crate::arena::read_action_wire(bytes, 0, bytes.len()) {
        Some(action) => {
            state.injected_actions.push(action);
            0
        }
        None => -1,
    }
}

unsafe extern "C" fn native_emit_event(
    user_data: *mut c_void,
    type_ptr: *const u8,
    type_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
) -> i32 {
    // SAFETY: user_data comes from the API table (see the ABI contract above).
    let Some(state) = (unsafe { state(user_data) }) else {
        return -1;
    };
    if !state.provider_events_enabled {
        return -1;
    }
    // SAFETY: a pointer the hook passed, null or readable (ABI contract).
    let Some(payload_type) = (unsafe { read_bytes(type_ptr, type_len) }) else {
        return -1;
    };
    // SAFETY: a pointer the hook passed, null or readable (ABI contract).
    let Some(payload) = (unsafe { read_bytes(payload_ptr, payload_len) }) else {
        return -1;
    };
    state.provider_events.push(RawProviderEvent {
        payload_type: String::from_utf8_lossy(payload_type).to_string(),
        payload: payload.to_vec(),
    });
    0
}

unsafe extern "C" fn native_set_modified_data(
    user_data: *mut c_void,
    ptr: *const u8,
    len: usize,
) -> i32 {
    // SAFETY: user_data comes from the API table (see the ABI contract above).
    let Some(state) = (unsafe { state(user_data) }) else {
        return -1;
    };
    // SAFETY: a pointer the hook passed, null or readable (ABI contract).
    let Some(bytes) = (unsafe { read_bytes(ptr, len) }) else {
        return -1;
    };
    state.modified_data = Some(bytes.to_vec());
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_name_is_anchored_to_current_dir() {
        assert_eq!(
            loader_path(Path::new("libhook.so")),
            PathBuf::from("./libhook.so")
        );
    }

    #[test]
    fn paths_with_directories_are_unchanged() {
        assert_eq!(
            loader_path(Path::new("/opt/rns/hooks/libhook.so")),
            PathBuf::from("/opt/rns/hooks/libhook.so")
        );
        assert_eq!(
            loader_path(Path::new("hooks/libhook.so")),
            PathBuf::from("hooks/libhook.so")
        );
        assert_eq!(
            loader_path(Path::new("./libhook.so")),
            PathBuf::from("./libhook.so")
        );
    }
}
