#![no_std]

use rns_hooks_sdk::context::{self, PacketContext};
use rns_hooks_sdk::host;
use rns_hooks_sdk::result::HookResult;

/// Maximum packets allowed within the sliding window.
const MAX_PACKETS: u32 = 100;
/// Window size in number of calls. Counter resets every WINDOW_SIZE calls.
const WINDOW_SIZE: u32 = 200;

static mut COUNTER: u32 = 0;
static mut WINDOW_CALLS: u32 = 0;

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

    let result = if ctx_type == context::CTX_TYPE_PACKET {
        let _pkt = unsafe { &*(ptr as *const PacketContext) };

        unsafe {
            WINDOW_CALLS += 1;
            if WINDOW_CALLS >= WINDOW_SIZE {
                WINDOW_CALLS = 0;
                COUNTER = 0;
            }

            COUNTER += 1;
            if COUNTER > MAX_PACKETS {
                host::log_str("rate_limiter: dropping excess packet");
                HookResult::drop_result()
            } else {
                HookResult::continue_result()
            }
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
