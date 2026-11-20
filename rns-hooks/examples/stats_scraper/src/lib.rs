#![no_std]

use rns_hooks_abi::stats::{
    AnnounceStatsPayload, PacketStatsPayload, ANNOUNCE_STATS_PAYLOAD_TYPE,
    PACKET_STATS_PAYLOAD_TYPE,
};
use rns_hooks_sdk::context::{self, PacketContext};
use rns_hooks_sdk::host;
use rns_hooks_sdk::result::HookResult;
use sha2::{Digest, Sha256};

static mut RESULT: HookResult = HookResult {
    verdict: 0,
    modified_data_offset: 0,
    modified_data_len: 0,
};

/// Minimum announce data length: public_key(64) + name_hash(10) + random_hash(10) + signature(64)
const MIN_ANNOUNCE_DATA_LEN: usize = 148;

/// HEADER_1: [flags:1][hops:1][dest:16][context:1] = 19 bytes before data
const HEADER_1_DATA_OFFSET: usize = 19;
/// HEADER_2: [flags:1][hops:1][transport_id:16][dest:16][context:1] = 35 bytes before data
const HEADER_2_DATA_OFFSET: usize = 35;

const PACKET_TYPE_ANNOUNCE: u8 = 0x01;

#[no_mangle]
pub extern "C" fn on_hook(ctx_ptr: i32) -> i32 {
    let ptr = ctx_ptr as *const u8;
    if unsafe { context::context_type(ptr) } == context::CTX_TYPE_PACKET {
        let ctx = unsafe { &*(ptr as *const PacketContext) };

        // Always emit packet stats
        let payload = PacketStatsPayload {
            flags: ctx.flags,
            packet_len: ctx.data_len,
            interface_id: ctx.interface_id,
        }
        .encode();
        let _ = host::emit_event(PACKET_STATS_PAYLOAD_TYPE, &payload);

        // If this is an announce, parse and emit announce details
        if (ctx.flags & 0x03) == PACKET_TYPE_ANNOUNCE {
            emit_announce_stats(ctx);
        }
    }

    unsafe {
        let rptr = &raw mut RESULT;
        rptr.write(HookResult::continue_result());
        rptr as i32
    }
}

fn emit_announce_stats(ctx: &PacketContext) {
    let raw = unsafe { context::packet_data(ctx) };

    let header_type = (ctx.flags >> 6) & 0x01;
    let data_offset = if header_type == 0 {
        HEADER_1_DATA_OFFSET
    } else {
        HEADER_2_DATA_OFFSET
    };

    if raw.len() < data_offset + MIN_ANNOUNCE_DATA_LEN {
        return;
    }

    let announce_data = &raw[data_offset..];
    let public_key = &announce_data[..64];
    let name_hash = &announce_data[64..74];
    let random_hash = &announce_data[74..84];

    // identity_hash = truncated SHA-256 of public_key (first 16 bytes)
    let full_hash = Sha256::digest(public_key);
    let mut identity_hash = [0u8; 16];
    identity_hash.copy_from_slice(&full_hash[..16]);

    let mut nh = [0u8; 10];
    nh.copy_from_slice(name_hash);
    let mut rh = [0u8; 10];
    rh.copy_from_slice(random_hash);

    let payload = AnnounceStatsPayload {
        identity_hash,
        destination_hash: ctx.destination_hash,
        name_hash: nh,
        random_hash: rh,
        hops: ctx.hops,
        interface_id: ctx.interface_id,
    }
    .encode();
    let _ = host::emit_event(ANNOUNCE_STATS_PAYLOAD_TYPE, &payload);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}
