#![cfg_attr(target_arch = "wasm32", no_std)]
// As a wasm guest the crate exports its entry point unmangled and reads the
// context the host wrote into its memory: that is the hook ABI.
#![cfg_attr(
    target_arch = "wasm32",
    allow(unsafe_code, reason = "the wasm guest side of the hook ABI")
)]

#[cfg(any(target_arch = "wasm32", feature = "builtin"))]
use rns_hooks_abi::stats::{
    AnnounceStatsPayload, LinkStatsPayload, PacketStatsPayload, ANNOUNCE_STATS_PAYLOAD_TYPE,
    LINK_STATS_PAYLOAD_TYPE, PACKET_STATS_PAYLOAD_TYPE,
};
#[cfg(target_arch = "wasm32")]
use rns_hooks_sdk::context::{self, LinkContext, PacketContext};
#[cfg(target_arch = "wasm32")]
use rns_hooks_sdk::host;
#[cfg(target_arch = "wasm32")]
use rns_hooks_sdk::result::HookResult;
#[cfg(any(target_arch = "wasm32", feature = "builtin"))]
use sha2::{Digest, Sha256};

#[cfg(feature = "builtin")]
use rns_hooks::{
    register_builtin_hook, BuiltinHookCall, BuiltinHookHost, HookContext, HookError, HookResult,
};

#[cfg(feature = "builtin")]
pub const BUILTIN_ID: &str = "rns.statsd";

#[cfg(target_arch = "wasm32")]
static mut RESULT: HookResult = HookResult {
    verdict: 0,
    modified_data_offset: 0,
    modified_data_len: 0,
};

#[cfg(any(target_arch = "wasm32", feature = "builtin"))]
const MIN_ANNOUNCE_DATA_LEN: usize = 148;
#[cfg(any(target_arch = "wasm32", feature = "builtin"))]
const HEADER_1_DATA_OFFSET: usize = 19;
#[cfg(any(target_arch = "wasm32", feature = "builtin"))]
const HEADER_2_DATA_OFFSET: usize = 35;
#[cfg(any(target_arch = "wasm32", feature = "builtin"))]
const PACKET_TYPE_ANNOUNCE: u8 = 0x01;

#[cfg(any(target_arch = "wasm32", feature = "builtin"))]
fn identity_hash(public_key: &[u8]) -> [u8; 16] {
    let full_hash = Sha256::digest(public_key);
    let mut identity_hash = [0u8; 16];
    for (out, byte) in identity_hash.iter_mut().zip(full_hash) {
        *out = byte;
    }
    identity_hash
}

/// The public key, name hash and random hash at the start of an announce's
/// data, which begins `data_offset` bytes into `raw`.
#[cfg(any(target_arch = "wasm32", feature = "builtin"))]
fn announce_fields(raw: &[u8], data_offset: usize) -> Option<(&[u8; 64], &[u8; 10], &[u8; 10])> {
    let (public_key, rest) = raw.get(data_offset..)?.split_first_chunk::<64>()?;
    let (name_hash, rest) = rest.split_first_chunk::<10>()?;
    let random_hash = rest.first_chunk::<10>()?;
    Some((public_key, name_hash, random_hash))
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn on_hook(ctx_ptr: i32) -> i32 {
    let ptr = ctx_ptr as *const u8;
    // SAFETY: the host calls on_hook with the address of the context it
    // has just written at the arena base.
    match unsafe { context::context_type(ptr) } {
        context::CTX_TYPE_PACKET => {
            // SAFETY: the context is a PacketContext, as its type says, and
            // the arena base is 4096-aligned, enough for any repr(C) context.
            let ctx = unsafe { &*(ptr as *const PacketContext) };

            let payload = PacketStatsPayload {
                flags: ctx.flags,
                packet_len: ctx.data_len,
                interface_id: ctx.interface_id,
            }
            .encode();
            let _ = host::emit_event(PACKET_STATS_PAYLOAD_TYPE, &payload);

            if (ctx.flags & 0x03) == PACKET_TYPE_ANNOUNCE {
                emit_announce_stats(ctx);
            }
        }
        context::CTX_TYPE_LINK => {
            // SAFETY: as for the packet context above, for a LinkContext.
            let ctx = unsafe { &*(ptr as *const LinkContext) };
            let payload = LinkStatsPayload {
                link_id: ctx.link_id,
                interface_id: ctx.interface_id,
            }
            .encode();
            let _ = host::emit_event(LINK_STATS_PAYLOAD_TYPE, &payload);
        }
        _ => {}
    }

    // SAFETY: a wasm guest runs one call at a time, so nothing else touches
    // RESULT while it is written and its address handed to the host.
    unsafe {
        let rptr = &raw mut RESULT;
        rptr.write(HookResult::continue_result());
        rptr as i32
    }
}

#[cfg(target_arch = "wasm32")]
fn emit_announce_stats(ctx: &PacketContext) {
    // SAFETY: the host writes the packet's data_len bytes at the arena base
    // plus data_offset together with the context that names them.
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

    let Some((public_key, name_hash, random_hash)) = announce_fields(raw, data_offset) else {
        return;
    };

    let identity_hash = identity_hash(public_key);

    let payload = AnnounceStatsPayload {
        identity_hash,
        destination_hash: ctx.destination_hash,
        name_hash: *name_hash,
        random_hash: *random_hash,
        hops: ctx.hops,
        interface_id: ctx.interface_id,
    }
    .encode();
    let _ = host::emit_event(ANNOUNCE_STATS_PAYLOAD_TYPE, &payload);
}

#[cfg(feature = "builtin")]
pub fn register_builtin_hooks() -> Result<(), HookError> {
    register_builtin_hook(BUILTIN_ID, builtin_stats_hook)
}

#[cfg(feature = "builtin")]
fn builtin_stats_hook(
    call: BuiltinHookCall<'_>,
    host: &mut BuiltinHookHost,
) -> Result<HookResult, HookError> {
    match call.ctx {
        HookContext::Packet { ctx, raw } => {
            let payload = PacketStatsPayload {
                flags: ctx.flags,
                packet_len: ctx.data_len,
                interface_id: ctx.interface_id,
            }
            .encode();
            host.emit_event(&call, PACKET_STATS_PAYLOAD_TYPE, payload)?;

            if (ctx.flags & 0x03) == PACKET_TYPE_ANNOUNCE {
                emit_builtin_announce_stats(&call, host, ctx, raw)?;
            }
        }
        HookContext::Link {
            link_id,
            interface_id,
        } => {
            let payload = LinkStatsPayload {
                link_id: *link_id,
                interface_id: *interface_id,
            }
            .encode();
            host.emit_event(&call, LINK_STATS_PAYLOAD_TYPE, payload)?;
        }
        _ => {}
    }

    Ok(HookResult::continue_result())
}

#[cfg(feature = "builtin")]
fn emit_builtin_announce_stats(
    call: &BuiltinHookCall<'_>,
    host: &mut BuiltinHookHost,
    ctx: &rns_hooks::PacketContext,
    raw: &[u8],
) -> Result<(), HookError> {
    let header_type = (ctx.flags >> 6) & 0x01;
    let data_offset = if header_type == 0 {
        HEADER_1_DATA_OFFSET
    } else {
        HEADER_2_DATA_OFFSET
    };

    if raw.len() < data_offset + MIN_ANNOUNCE_DATA_LEN {
        return Ok(());
    }

    let Some((public_key, name_hash, random_hash)) = announce_fields(raw, data_offset) else {
        return Ok(());
    };

    let identity_hash = identity_hash(public_key);

    let payload = AnnounceStatsPayload {
        identity_hash,
        destination_hash: ctx.destination_hash,
        name_hash: *name_hash,
        random_hash: *random_hash,
        hops: ctx.hops,
        interface_id: ctx.interface_id,
    }
    .encode();
    host.emit_event(call, ANNOUNCE_STATS_PAYLOAD_TYPE, payload)
}

#[cfg(all(test, feature = "builtin"))]
mod tests {
    use super::*;

    #[test]
    fn identity_hash_matches_fixed_sha256_truncation_vector() {
        let public_key: Vec<u8> = (0..64).collect();
        assert_eq!(
            identity_hash(&public_key),
            [
                0xfd, 0xea, 0xb9, 0xac, 0xf3, 0x71, 0x03, 0x62, 0xbd, 0x26, 0x58, 0xcd, 0xc9, 0xa2,
                0x9e, 0x8f,
            ]
        );
    }
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

#[cfg(not(target_arch = "wasm32"))]
pub fn build_dependency_marker() {}
