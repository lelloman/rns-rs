//! Entry points and host API of native (shared library) hooks.
//!
//! A native hook exports two C functions under the names in
//! [`NATIVE_HOOK_ABI_VERSION_SYMBOL`] and [`NATIVE_HOOK_ON_CALL_SYMBOL`].
//! The host checks the first against [`ABI_VERSION`](crate::ABI_VERSION)
//! when it loads the library, and calls the second once per hook
//! invocation, synchronously on the host's event loop thread.

use core::ffi::c_void;

use crate::result::HookResult;

/// Version of the [`RnsNativeHostApi`] table, found in its `version` field.
pub const NATIVE_HOST_API_VERSION: u32 = 1;

/// NUL-terminated name of the [`NativeHookAbiVersionFn`] a native hook exports.
pub const NATIVE_HOOK_ABI_VERSION_SYMBOL: &[u8] = b"rns_hook_abi_version\0";
/// NUL-terminated name of the [`NativeHookOnCallFn`] a native hook exports.
pub const NATIVE_HOOK_ON_CALL_SYMBOL: &[u8] = b"rns_hook_on_call\0";

/// Returns the [`ABI_VERSION`](crate::ABI_VERSION) the hook was built
/// against; the host refuses to load a hook whose version differs.
pub type NativeHookAbiVersionFn = unsafe extern "C" fn() -> i32;

/// Runs the hook once.
///
/// `ctx` points to `ctx_len` bytes holding one of the
/// [`context`](crate::context) layouts, with any packet data offsets relative
/// to `ctx`. `host_api` is valid for the duration of the call only.
/// `result` starts out as a `Continue` result; the hook overwrites it to
/// return another verdict. Replacement packet bytes for a `Modify` verdict go
/// through [`RnsNativeHostApi::set_modified_data`], not the result's offsets.
/// A non-zero return value is an error, and the host discards the result.
pub type NativeHookOnCallFn = unsafe extern "C" fn(
    ctx: *const u8,
    ctx_len: usize,
    host_api: *const RnsNativeHostApi,
    result: *mut HookResult,
) -> i32;

/// Table of host callbacks handed to [`NativeHookOnCallFn`].
///
/// Every callback takes [`user_data`](Self::user_data) as its first
/// argument. Hash arguments and outputs are 16-byte buffers; a null pointer
/// where one is expected makes the callback fail. A callback set to `None`
/// is not offered by this host.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RnsNativeHostApi {
    /// [`NATIVE_HOST_API_VERSION`] of the host that filled the table.
    pub version: u32,
    /// Opaque host state; pass it back unchanged to every callback.
    pub user_data: *mut c_void,
    /// Logs `len` bytes of text (lossily decoded as UTF-8) at debug level.
    pub log: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize)>,
    /// 1 if the host has a path to the destination hash, else 0.
    pub has_path: Option<unsafe extern "C" fn(*mut c_void, *const u8) -> i32>,
    /// Hop count of the path to the destination hash, or -1 with no path.
    pub get_hops: Option<unsafe extern "C" fn(*mut c_void, *const u8) -> i32>,
    /// Writes the next hop's 16-byte transport identity hash for the
    /// destination hash to the output buffer; returns 1 if written, 0 with
    /// no path.
    pub get_next_hop: Option<unsafe extern "C" fn(*mut c_void, *const u8, *mut u8) -> i32>,
    /// 1 if the 16-byte identity hash is blackholed, else 0.
    pub is_blackholed: Option<unsafe extern "C" fn(*mut c_void, *const u8) -> i32>,
    /// Copies the name of the interface with the given id into the output
    /// buffer of the given capacity, truncating it to fit (no NUL is
    /// added); returns the bytes written, or -1 for an unknown interface.
    pub get_interface_name: Option<unsafe extern "C" fn(*mut c_void, u64, *mut u8, usize) -> isize>,
    /// The interface's mode as its numeric constant (full, access point,
    /// roaming, ...), or -1 for an unknown interface.
    pub get_interface_mode: Option<unsafe extern "C" fn(*mut c_void, u64) -> i32>,
    /// Writes the node's 16-byte transport identity hash to the output
    /// buffer; returns 1 if written, 0 when the node has no identity.
    pub get_transport_identity: Option<unsafe extern "C" fn(*mut c_void, *mut u8) -> i32>,
    /// The interface's outgoing announce rate in millihertz, or -1 for an
    /// unknown interface.
    pub get_announce_rate: Option<unsafe extern "C" fn(*mut c_void, u64) -> i32>,
    /// State of the link with the given 16-byte id (0 pending, 1 handshake,
    /// 2 active, 3 stale, 4 closed), or -1 for an unknown link.
    pub get_link_state: Option<unsafe extern "C" fn(*mut c_void, *const u8) -> i32>,
    /// Queues an action, encoded as in [`wire`](crate::wire) with its data
    /// offsets relative to the given buffer, for the host to carry out
    /// after the call; returns 0, or -1 if the encoding is invalid.
    pub inject_action: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
    /// Emits a provider event: a payload type string, then the payload
    /// bytes. Returns 0, or -1 when the host has provider events disabled.
    pub emit_event:
        Option<unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize) -> i32>,
    /// Sets the replacement packet bytes a `Modify` verdict uses; the last
    /// call wins. Returns 0, or -1 for a null pointer.
    pub set_modified_data: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
}
