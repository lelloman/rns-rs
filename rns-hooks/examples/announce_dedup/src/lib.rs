#![no_std]

use rns_hooks_sdk::context::{self, AnnounceContext};
use rns_hooks_sdk::host;
use rns_hooks_sdk::result::HookResult;

/// Size of the circular buffer (number of destination hashes to remember).
const BUFFER_SIZE: usize = 64;
/// Maximum retransmissions of the same destination hash before suppression.
const MAX_RETRANSMITS: u32 = 3;

/// Circular buffer of recently-seen destination hashes.
static mut RING_BUF: [[u8; 16]; BUFFER_SIZE] = [[0u8; 16]; BUFFER_SIZE];
/// Write position in the circular buffer.
static mut WRITE_POS: usize = 0;
/// Number of entries written (saturates at BUFFER_SIZE).
static mut COUNT: usize = 0;

static mut RESULT: HookResult = HookResult {
    verdict: 0,
    modified_data_offset: 0,
    modified_data_len: 0,
    inject_actions_offset: 0,
    inject_actions_count: 0,
    log_offset: 0,
    log_len: 0,
};

/// Count occurrences of `dest` in the circular buffer.
unsafe fn count_occurrences(dest: &[u8; 16]) -> u32 {
    let entries = if COUNT < BUFFER_SIZE { COUNT } else { BUFFER_SIZE };
    let mut found = 0u32;
    let mut i = 0;
    while i < entries {
        if RING_BUF[i] == *dest {
            found += 1;
        }
        i += 1;
    }
    found
}

/// Record a destination hash in the circular buffer.
unsafe fn record(dest: &[u8; 16]) {
    RING_BUF[WRITE_POS] = *dest;
    WRITE_POS = (WRITE_POS + 1) % BUFFER_SIZE;
    if COUNT < BUFFER_SIZE {
        COUNT += 1;
    }
}

#[no_mangle]
pub extern "C" fn on_hook(ctx_ptr: i32) -> i32 {
    let ptr = ctx_ptr as *const u8;
    let ctx_type = unsafe { context::context_type(ptr) };

    let result = if ctx_type == context::CTX_TYPE_ANNOUNCE {
        let announce = unsafe { &*(ptr as *const AnnounceContext) };

        unsafe {
            let seen = count_occurrences(&announce.destination_hash);
            record(&announce.destination_hash);

            if seen >= MAX_RETRANSMITS {
                host::log_str("announce_dedup: suppressing retransmit");
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
