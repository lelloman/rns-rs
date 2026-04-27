use std::ffi::c_void;
use std::path::Path;

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

impl NativeProgram {
    pub fn load(path: &Path) -> Result<Self, HookError> {
        let library = unsafe { Library::new(path) }
            .map_err(|e| HookError::CompileError(format!("failed to load native hook: {}", e)))?;

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
        let found = unsafe { abi_version() };
        if found != rns_hooks_abi::ABI_VERSION {
            return Err(HookError::AbiVersionMismatch {
                hook_name: path.display().to_string(),
                expected: rns_hooks_abi::ABI_VERSION,
                found: Some(found),
            });
        }

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

struct NativeCallState<'a> {
    engine_access: &'a dyn EngineAccess,
    injected_actions: Vec<ActionWire>,
    provider_events: Vec<RawProviderEvent>,
    provider_events_enabled: bool,
    modified_data: Option<Vec<u8>>,
}

unsafe fn state<'a>(user_data: *mut c_void) -> Option<&'a mut NativeCallState<'a>> {
    user_data.cast::<NativeCallState<'a>>().as_mut()
}

unsafe fn read_bytes<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    Some(std::slice::from_raw_parts(ptr, len))
}

unsafe fn read_16(ptr: *const u8) -> Option<[u8; 16]> {
    let bytes = read_bytes(ptr, 16)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(bytes);
    Some(out)
}

unsafe extern "C" fn native_log(user_data: *mut c_void, ptr: *const u8, len: usize) {
    if state(user_data).is_none() {
        return;
    }
    let Some(bytes) = read_bytes(ptr, len) else {
        return;
    };
    log::debug!("[native-hook] {}", String::from_utf8_lossy(bytes));
}

unsafe extern "C" fn native_has_path(user_data: *mut c_void, dest_ptr: *const u8) -> i32 {
    let Some(state) = state(user_data) else {
        return 0;
    };
    let Some(dest) = read_16(dest_ptr) else {
        return 0;
    };
    state.engine_access.has_path(&dest) as i32
}

unsafe extern "C" fn native_get_hops(user_data: *mut c_void, dest_ptr: *const u8) -> i32 {
    let Some(state) = state(user_data) else {
        return -1;
    };
    if !state.provider_events_enabled {
        return -1;
    }
    let Some(dest) = read_16(dest_ptr) else {
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
    let Some(state) = state(user_data) else {
        return 0;
    };
    let Some(dest) = read_16(dest_ptr) else {
        return 0;
    };
    let Some(next_hop) = state.engine_access.next_hop(&dest) else {
        return 0;
    };
    if out_ptr.is_null() {
        return 0;
    }
    std::ptr::copy_nonoverlapping(next_hop.as_ptr(), out_ptr, next_hop.len());
    1
}

unsafe extern "C" fn native_is_blackholed(user_data: *mut c_void, ptr: *const u8) -> i32 {
    let Some(state) = state(user_data) else {
        return 0;
    };
    let Some(identity) = read_16(ptr) else {
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
    let Some(state) = state(user_data) else {
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
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr, write_len);
    write_len as isize
}

unsafe extern "C" fn native_get_interface_mode(user_data: *mut c_void, id: u64) -> i32 {
    let Some(state) = state(user_data) else {
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
    let Some(state) = state(user_data) else {
        return 0;
    };
    let Some(hash) = state.engine_access.identity_hash() else {
        return 0;
    };
    if out_ptr.is_null() {
        return 0;
    }
    std::ptr::copy_nonoverlapping(hash.as_ptr(), out_ptr, hash.len());
    1
}

unsafe extern "C" fn native_get_announce_rate(user_data: *mut c_void, id: u64) -> i32 {
    let Some(state) = state(user_data) else {
        return -1;
    };
    state.engine_access.announce_rate(id).unwrap_or(-1)
}

unsafe extern "C" fn native_get_link_state(user_data: *mut c_void, ptr: *const u8) -> i32 {
    let Some(state) = state(user_data) else {
        return -1;
    };
    let Some(link_hash) = read_16(ptr) else {
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
    let Some(state) = state(user_data) else {
        return -1;
    };
    let Some(bytes) = read_bytes(ptr, len) else {
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
    let Some(state) = state(user_data) else {
        return -1;
    };
    let Some(payload_type) = read_bytes(type_ptr, type_len) else {
        return -1;
    };
    let Some(payload) = read_bytes(payload_ptr, payload_len) else {
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
    let Some(state) = state(user_data) else {
        return -1;
    };
    let Some(bytes) = read_bytes(ptr, len) else {
        return -1;
    };
    state.modified_data = Some(bytes.to_vec());
    0
}
