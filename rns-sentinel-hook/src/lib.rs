#![cfg_attr(target_arch = "wasm32", no_std)]

#[cfg(target_arch = "wasm32")]
use rns_hooks_abi::context::{self, BackbonePeerContext, CTX_TYPE_BACKBONE_PEER};
#[cfg(target_arch = "wasm32")]
use rns_hooks_abi::sentinel::{
    BackbonePeerPayload, BACKBONE_PEER_INTERFACE_NAME_MAX, BACKBONE_PEER_PAYLOAD_TYPE,
};
#[cfg(target_arch = "wasm32")]
use rns_hooks_sdk::host;
#[cfg(target_arch = "wasm32")]
use rns_hooks_sdk::result::HookResult;

#[cfg(target_arch = "wasm32")]
static mut RESULT: HookResult = HookResult {
    verdict: 0,
    modified_data_offset: 0,
    modified_data_len: 0,
    inject_actions_offset: 0,
    inject_actions_count: 0,
    log_offset: 0,
    log_len: 0,
};

/// Event kind byte, set by the host depending on which attach point fires.
/// The sentinel binary passes a different hook name per attach point, but all
/// hooks share this same wasm module. We derive the event kind from the
/// `penalty_level` and `blacklist_for_secs` fields in the context: if
/// `blacklist_for_secs > 0` it's a penalty event; otherwise we rely on the
/// host setting the attach point name (which the provider bridge envelope
/// carries). For simplicity we encode a sentinel-side discriminant from
/// a static that the host sets before calling us.
///
/// Actually, since all 5 attach points call the same wasm entry point and
/// we can't distinguish them from within the wasm, we store the event kind
/// in a global that is set via `__rns_sentinel_set_event_kind` export.
/// The host calls this before each `on_hook` invocation.
///
/// For now, we use a simpler approach: the sentinel binary loads 5 copies
/// of this hook with different names. The provider bridge envelope carries
/// `attach_point` which tells the consumer which event it was. The wasm
/// hook just emits the context data; the consumer classifies by attach point.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn on_hook(ctx_ptr: i32) -> i32 {
    let ptr = ctx_ptr as *const u8;
    if unsafe { context::context_type(ptr) } == CTX_TYPE_BACKBONE_PEER {
        let ctx = unsafe { core::ptr::read_unaligned(ptr as *const BackbonePeerContext) };
        let mut server_interface_name = [0u8; BACKBONE_PEER_INTERFACE_NAME_MAX];
        let server_interface_name_len =
            host::get_interface_name(ctx.server_interface_id, &mut server_interface_name)
                .map(|len| len.min(BACKBONE_PEER_INTERFACE_NAME_MAX))
                .unwrap_or(0) as u8;
        let payload = BackbonePeerPayload {
            peer_ip_family: ctx.peer_ip_family,
            peer_ip: ctx.peer_ip,
            peer_port: ctx.peer_port,
            server_interface_id: ctx.server_interface_id,
            peer_interface_id: ctx.peer_interface_id,
            connected_for_secs: ctx.connected_for_secs,
            had_received_data: ctx.had_received_data != 0,
            penalty_level: ctx.penalty_level,
            blacklist_for_secs: ctx.blacklist_for_secs,
            // Event kind is 0 here; the consumer uses attach_point from the
            // provider envelope to distinguish event types.
            event_kind: 0,
            server_interface_name_len,
            server_interface_name,
        }
        .encode();
        let _ = host::emit_event(BACKBONE_PEER_PAYLOAD_TYPE, &payload);
    }

    unsafe {
        let rptr = &raw mut RESULT;
        rptr.write(HookResult::continue_result());
        rptr as i32
    }
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

#[cfg(not(target_arch = "wasm32"))]
pub fn build_dependency_marker() {}
