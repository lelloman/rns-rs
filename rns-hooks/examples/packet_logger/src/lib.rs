#![no_std]

use rns_hooks_sdk::context::{self, AnnounceContext, PacketContext};
use rns_hooks_sdk::host;
use rns_hooks_sdk::result::HookResult;

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

    match ctx_type {
        context::CTX_TYPE_PACKET => {
            let pkt = unsafe { &*(ptr as *const PacketContext) };
            host::log_str("packet received");
            let hops = pkt.hops;
            let mut buf = [b'h', b'o', b'p', b's', b'=', b'0'];
            buf[5] = b'0' + (hops % 10);
            let msg = unsafe { core::str::from_utf8_unchecked(&buf) };
            host::log_str(msg);
        }
        context::CTX_TYPE_ANNOUNCE => {
            let ann = unsafe { &*(ptr as *const AnnounceContext) };
            let _ = ann.hops;
            host::log_str("announce received");
        }
        context::CTX_TYPE_TICK => {
            host::log_str("tick");
        }
        _ => {
            host::log_str("other context");
        }
    }

    unsafe {
        let rptr = &raw mut RESULT;
        rptr.write(HookResult::continue_result());
        rptr as i32
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}
