#![no_std]

use rns_hooks_sdk::action;
use rns_hooks_sdk::context::{self, PacketContext, ARENA_BASE};
use rns_hooks_sdk::host;
use rns_hooks_sdk::result::HookResult;

/// Interface ID to mirror packets to.
const MIRROR_INTERFACE: u64 = 99;

/// Buffer for encoding the SendOnInterface action.
static mut ACTION_BUF: [u8; 32] = [0u8; 32];

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

    if ctx_type == context::CTX_TYPE_PACKET {
        let pkt = unsafe { &*(ptr as *const PacketContext) };
        let data_ptr = (ARENA_BASE + pkt.data_offset as usize) as u32;
        let data_len = pkt.data_len;

        // Encode a SendOnInterface action to mirror the packet
        unsafe {
            let buf = &raw mut ACTION_BUF;
            action::encode_send_on_interface(&mut *buf, MIRROR_INTERFACE, data_ptr, data_len);
            host::inject_action_raw(&(&*buf)[..17]);
        }
    }

    // Always continue — mirroring is non-blocking
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
