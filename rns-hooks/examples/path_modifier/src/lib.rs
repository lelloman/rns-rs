#![no_std]

use rns_hooks_sdk::context::{self, PacketContext, ARENA_BASE};
use rns_hooks_sdk::result::HookResult;

/// Marker byte prepended to packet data.
const MARKER: u8 = 0xFF;

/// Static buffer for modified data (max 4096 bytes).
const BUF_SIZE: usize = 4096;
static mut MOD_BUF: [u8; BUF_SIZE] = [0u8; BUF_SIZE];

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

    let rptr = &raw mut RESULT;

    if ctx_type != context::CTX_TYPE_PACKET {
        unsafe {
            rptr.write(HookResult::continue_result());
            return rptr as i32;
        }
    }

    let pkt = unsafe { &*(ptr as *const PacketContext) };
    let data_len = pkt.data_len as usize;
    let new_len = data_len + 1;

    if new_len > BUF_SIZE {
        unsafe {
            rptr.write(HookResult::continue_result());
            return rptr as i32;
        }
    }

    unsafe {
        let buf_ptr = &raw mut MOD_BUF as *mut u8;
        // Prepend marker byte
        buf_ptr.write(MARKER);
        // Copy original data after marker
        let src = (ARENA_BASE as *const u8).add(pkt.data_offset as usize);
        core::ptr::copy_nonoverlapping(src, buf_ptr.add(1), data_len);

        rptr.write(HookResult::modify_result(buf_ptr as u32, new_len as u32));
        rptr as i32
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}
