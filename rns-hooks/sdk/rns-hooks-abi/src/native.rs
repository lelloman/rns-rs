use core::ffi::c_void;

use crate::result::HookResult;

pub const NATIVE_HOST_API_VERSION: u32 = 1;

pub const NATIVE_HOOK_ABI_VERSION_SYMBOL: &[u8] = b"rns_hook_abi_version\0";
pub const NATIVE_HOOK_ON_CALL_SYMBOL: &[u8] = b"rns_hook_on_call\0";

pub type NativeHookAbiVersionFn = unsafe extern "C" fn() -> i32;

pub type NativeHookOnCallFn = unsafe extern "C" fn(
    ctx: *const u8,
    ctx_len: usize,
    host_api: *const RnsNativeHostApi,
    result: *mut HookResult,
) -> i32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RnsNativeHostApi {
    pub version: u32,
    pub user_data: *mut c_void,
    pub log: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize)>,
    pub has_path: Option<unsafe extern "C" fn(*mut c_void, *const u8) -> i32>,
    pub get_hops: Option<unsafe extern "C" fn(*mut c_void, *const u8) -> i32>,
    pub get_next_hop: Option<unsafe extern "C" fn(*mut c_void, *const u8, *mut u8) -> i32>,
    pub is_blackholed: Option<unsafe extern "C" fn(*mut c_void, *const u8) -> i32>,
    pub get_interface_name: Option<unsafe extern "C" fn(*mut c_void, u64, *mut u8, usize) -> isize>,
    pub get_interface_mode: Option<unsafe extern "C" fn(*mut c_void, u64) -> i32>,
    pub get_transport_identity: Option<unsafe extern "C" fn(*mut c_void, *mut u8) -> i32>,
    pub get_announce_rate: Option<unsafe extern "C" fn(*mut c_void, u64) -> i32>,
    pub get_link_state: Option<unsafe extern "C" fn(*mut c_void, *const u8) -> i32>,
    pub inject_action: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
    pub emit_event:
        Option<unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize) -> i32>,
    pub set_modified_data: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
}
