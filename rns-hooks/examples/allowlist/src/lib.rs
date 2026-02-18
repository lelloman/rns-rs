#![no_std]

use rns_hooks_sdk::context::{self, AnnounceContext, LinkContext};
use rns_hooks_sdk::host;
use rns_hooks_sdk::result::HookResult;

/// Allowed destination hash prefixes (first 2 bytes).
/// In a real deployment these would be configured; here we hardcode examples.
const ALLOWED_PREFIXES: &[[u8; 2]] = &[
    [0x00, 0x00], // allow destinations starting with 0x0000
    [0xFF, 0xFF], // allow destinations starting with 0xFFFF
];

static mut RESULT: HookResult = HookResult {
    verdict: 0,
    modified_data_offset: 0,
    modified_data_len: 0,
    inject_actions_offset: 0,
    inject_actions_count: 0,
    log_offset: 0,
    log_len: 0,
};

fn is_allowed(dest_hash: &[u8; 16]) -> bool {
    let mut i = 0;
    while i < ALLOWED_PREFIXES.len() {
        if dest_hash[0] == ALLOWED_PREFIXES[i][0] && dest_hash[1] == ALLOWED_PREFIXES[i][1] {
            return true;
        }
        i += 1;
    }
    false
}

#[no_mangle]
pub extern "C" fn on_hook(ctx_ptr: i32) -> i32 {
    let ptr = ctx_ptr as *const u8;
    let ctx_type = unsafe { context::context_type(ptr) };

    let result = match ctx_type {
        context::CTX_TYPE_ANNOUNCE => {
            let announce = unsafe { &*(ptr as *const AnnounceContext) };
            if is_allowed(&announce.destination_hash) {
                HookResult::continue_result()
            } else {
                host::log_str("allowlist: dropping announce from unknown dest");
                HookResult::drop_result()
            }
        }
        context::CTX_TYPE_LINK => {
            let link = unsafe { &*(ptr as *const LinkContext) };
            // Use link_id as the identifier to check
            if is_allowed(&link.link_id) {
                HookResult::continue_result()
            } else {
                host::log_str("allowlist: dropping link request from unknown source");
                HookResult::drop_result()
            }
        }
        _ => HookResult::continue_result(),
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
