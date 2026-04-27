use rns_hooks_abi::native::RnsNativeHostApi;
use rns_hooks_abi::result::HookResult;

#[no_mangle]
pub unsafe extern "C" fn rns_hook_abi_version() -> i32 {
    rns_hooks_abi::ABI_VERSION
}

#[no_mangle]
pub unsafe extern "C" fn rns_hook_on_call(
    ctx: *const u8,
    ctx_len: usize,
    host_api: *const RnsNativeHostApi,
    result: *mut HookResult,
) -> i32 {
    let _ = (ctx, ctx_len, host_api);
    if result.is_null() {
        return -1;
    }
    *result = HookResult::continue_result();
    0
}
