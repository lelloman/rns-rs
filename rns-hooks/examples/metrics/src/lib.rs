#![no_std]

use rns_hooks_sdk::context::{self, PacketContext};
use rns_hooks_sdk::host;
use rns_hooks_sdk::result::HookResult;

/// Log a summary every LOG_INTERVAL calls.
const LOG_INTERVAL: u32 = 50;

static mut PACKET_COUNT: u32 = 0;
static mut ANNOUNCE_COUNT: u32 = 0;
static mut TICK_COUNT: u32 = 0;
static mut LINK_COUNT: u32 = 0;
static mut OTHER_COUNT: u32 = 0;
static mut TOTAL_CALLS: u32 = 0;

/// Buffer for building log messages.
static mut LOG_BUF: [u8; 128] = [0u8; 128];

static mut RESULT: HookResult = HookResult {
    verdict: 0,
    modified_data_offset: 0,
    modified_data_len: 0,
    inject_actions_offset: 0,
    inject_actions_count: 0,
    log_offset: 0,
    log_len: 0,
};

/// Write a u32 as decimal into buf at offset, return new offset.
fn write_u32(buf: &mut [u8], mut off: usize, mut val: u32) -> usize {
    if val == 0 {
        buf[off] = b'0';
        return off + 1;
    }
    // Write digits in reverse
    let start = off;
    while val > 0 {
        buf[off] = b'0' + (val % 10) as u8;
        val /= 10;
        off += 1;
    }
    // Reverse
    let mut lo = start;
    let mut hi = off - 1;
    while lo < hi {
        buf.swap(lo, hi);
        lo += 1;
        hi -= 1;
    }
    off
}

fn copy_str(buf: &mut [u8], off: usize, s: &[u8]) -> usize {
    let mut i = 0;
    while i < s.len() {
        buf[off + i] = s[i];
        i += 1;
    }
    off + s.len()
}

unsafe fn log_summary() {
    let buf = &raw mut LOG_BUF;
    let b = &mut *buf;
    let mut off = copy_str(b, 0, b"metrics: pkt=");
    off = write_u32(b, off, PACKET_COUNT);
    off = copy_str(b, off, b" ann=");
    off = write_u32(b, off, ANNOUNCE_COUNT);
    off = copy_str(b, off, b" tick=");
    off = write_u32(b, off, TICK_COUNT);
    off = copy_str(b, off, b" link=");
    off = write_u32(b, off, LINK_COUNT);
    off = copy_str(b, off, b" other=");
    off = write_u32(b, off, OTHER_COUNT);

    let msg = core::str::from_utf8_unchecked(&(&*buf)[..off]);
    host::log_str(msg);
}

#[no_mangle]
pub extern "C" fn on_hook(ctx_ptr: i32) -> i32 {
    let ptr = ctx_ptr as *const u8;
    let ctx_type = unsafe { context::context_type(ptr) };

    unsafe {
        match ctx_type {
            context::CTX_TYPE_PACKET => {
                let pkt = &*(ptr as *const PacketContext);
                PACKET_COUNT += 1;
                // Enrich log with interface name if available
                if TOTAL_CALLS == 0 {
                    let mut name_buf = [0u8; 64];
                    if let Some(len) = host::get_interface_name(pkt.interface_id, &mut name_buf) {
                        let _ = len; // name available but we just count
                    }
                }
            }
            context::CTX_TYPE_ANNOUNCE => {
                ANNOUNCE_COUNT += 1;
            }
            context::CTX_TYPE_TICK => {
                TICK_COUNT += 1;
            }
            context::CTX_TYPE_LINK => {
                LINK_COUNT += 1;
            }
            _ => {
                OTHER_COUNT += 1;
            }
        }

        TOTAL_CALLS += 1;
        if TOTAL_CALLS % LOG_INTERVAL == 0 {
            log_summary();
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
