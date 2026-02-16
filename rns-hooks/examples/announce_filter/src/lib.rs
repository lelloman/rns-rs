#![no_std]

use rns_hooks_sdk::context::{self, AnnounceContext};
use rns_hooks_sdk::result::HookResult;

/// Maximum allowed hops for an announce. Announces with more hops are dropped.
const MAX_HOPS: u8 = 8;

static mut RESULT: HookResult = HookResult {
    verdict: 0,
    modified_data_offset: 0,
    modified_data_len: 0,
    inject_actions_offset: 0,
    inject_actions_count: 0,
    log_offset: 0,
    log_len: 0,
};

#[no_mangle]
pub extern "C" fn on_hook(ctx_ptr: i32) -> i32 {
    let ptr = ctx_ptr as *const u8;
    let ctx_type = unsafe { context::context_type(ptr) };

    let result = if ctx_type == context::CTX_TYPE_ANNOUNCE {
        let announce = unsafe { &*(ptr as *const AnnounceContext) };
        if announce.hops > MAX_HOPS {
            HookResult::drop_result()
        } else {
            HookResult::continue_result()
        }
    } else {
        HookResult::continue_result()
    };

    unsafe {
        let rptr = &raw mut RESULT;
        rptr.write(result);
        rptr as i32
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}
