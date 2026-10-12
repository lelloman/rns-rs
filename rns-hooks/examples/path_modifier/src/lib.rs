//! Demonstrates the `Modify` verdict.
//!
//! Attach at `PreIngress` on an interface whose paths should be less
//! preferred. For every received announce, the hook returns the packet with
//! its hop count raised by `HOP_PENALTY`, so destinations learned through that
//! interface are recorded with a longer path. The hop count is not covered by
//! the announce signature or the packet hash, so the replacement still
//! validates. Other packets, and announces whose raised hop count would reach
//! the protocol limit, pass through unchanged.

#![no_std]

use rns_hooks_sdk::context::{self, PacketContext, ARENA_BASE};
use rns_hooks_sdk::result::HookResult;

/// Hops added to every received announce.
const HOP_PENALTY: u8 = 2;

/// Packets with this many hops or more are refused by the packet decoder.
const MAX_HOPS: u8 = 128;

/// Packet type bits of the flags byte, and the announce packet type.
const PACKET_TYPE_MASK: u8 = 0x03;
const PACKET_TYPE_ANNOUNCE: u8 = 0x01;

/// Static buffer for the replacement packet.
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
    if data_len < 2 || data_len > BUF_SIZE {
        unsafe {
            rptr.write(HookResult::continue_result());
            return rptr as i32;
        }
    }

    // Read flags and hops from the packet bytes rather than the context
    // header: an earlier hook in the chain may already have replaced them.
    let src = unsafe { (ARENA_BASE as *const u8).add(pkt.data_offset as usize) };
    let (flags, hops) = unsafe { (src.read(), src.add(1).read()) };
    let is_announce = flags & PACKET_TYPE_MASK == PACKET_TYPE_ANNOUNCE;
    let raised_hops = hops.saturating_add(HOP_PENALTY);

    if !is_announce || raised_hops >= MAX_HOPS {
        unsafe {
            rptr.write(HookResult::continue_result());
            return rptr as i32;
        }
    }

    unsafe {
        let buf_ptr = &raw mut MOD_BUF as *mut u8;
        core::ptr::copy_nonoverlapping(src, buf_ptr, data_len);
        // Byte 1 of a packet is its hop count.
        buf_ptr.add(1).write(raised_hops);

        rptr.write(HookResult::modify_result(buf_ptr as u32, data_len as u32));
        rptr as i32
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}
