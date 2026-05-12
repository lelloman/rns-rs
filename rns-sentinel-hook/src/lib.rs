#![cfg_attr(target_arch = "wasm32", no_std)]

#[cfg(target_arch = "wasm32")]
use rns_hooks_abi::context::{self, BackbonePeerContext, CTX_TYPE_BACKBONE_PEER};
#[cfg(any(target_arch = "wasm32", feature = "builtin"))]
use rns_hooks_abi::sentinel::{
    BackbonePeerPayload, BACKBONE_PEER_INTERFACE_NAME_MAX, BACKBONE_PEER_PAYLOAD_TYPE,
};
#[cfg(target_arch = "wasm32")]
use rns_hooks_sdk::host;
#[cfg(target_arch = "wasm32")]
use rns_hooks_sdk::result::HookResult;

#[cfg(feature = "builtin")]
use rns_hooks::{
    register_builtin_hook, BuiltinHookCall, BuiltinHookHost, HookContext, HookError, HookResult,
};

#[cfg(feature = "builtin")]
pub const BUILTIN_ID: &str = "rns.sentineld";

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

#[cfg(feature = "builtin")]
pub fn register_builtin_hooks() -> Result<(), HookError> {
    register_builtin_hook(BUILTIN_ID, builtin_sentinel_hook)
}

#[cfg(feature = "builtin")]
fn builtin_sentinel_hook(
    call: BuiltinHookCall<'_>,
    host: &mut BuiltinHookHost,
) -> Result<HookResult, HookError> {
    let HookContext::BackbonePeer {
        server_interface_id,
        peer_interface_id,
        peer_ip,
        peer_port,
        connected_for,
        had_received_data,
        penalty_level,
        blacklist_for,
    } = call.ctx
    else {
        return Ok(HookResult::continue_result());
    };

    let mut server_interface_name = [0u8; BACKBONE_PEER_INTERFACE_NAME_MAX];
    let server_interface_name_len = call
        .engine_access
        .interface_name(*server_interface_id)
        .map(|name| {
            let bytes = name.as_bytes();
            let len = bytes.len().min(BACKBONE_PEER_INTERFACE_NAME_MAX);
            server_interface_name[..len].copy_from_slice(&bytes[..len]);
            len as u8
        })
        .unwrap_or(0);

    let (peer_ip_family, peer_ip_bytes) = match peer_ip {
        std::net::IpAddr::V4(addr) => {
            let mut bytes = [0u8; 16];
            bytes[10] = 0xff;
            bytes[11] = 0xff;
            bytes[12..16].copy_from_slice(&addr.octets());
            (4, bytes)
        }
        std::net::IpAddr::V6(addr) => (6, addr.octets()),
    };

    let payload = BackbonePeerPayload {
        peer_ip_family,
        peer_ip: peer_ip_bytes,
        peer_port: *peer_port,
        server_interface_id: *server_interface_id,
        peer_interface_id: peer_interface_id.unwrap_or(0),
        connected_for_secs: connected_for.as_secs(),
        had_received_data: *had_received_data,
        penalty_level: *penalty_level,
        blacklist_for_secs: blacklist_for.as_secs(),
        // The provider bridge envelope carries the attach point used by
        // rns-sentineld to classify the event.
        event_kind: 0,
        server_interface_name_len,
        server_interface_name,
    }
    .encode();
    host.emit_event(&call, BACKBONE_PEER_PAYLOAD_TYPE, payload)?;

    Ok(HookResult::continue_result())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn build_dependency_marker() {}
