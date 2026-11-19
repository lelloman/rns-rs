//! Hook sections.

use super::*;

pub(super) fn build_parsed_hook(name: String, mut kvs: HashMap<String, String>) -> ParsedHook {
    let path = kvs.remove("path").unwrap_or_default();
    let hook_type = kvs
        .remove("type")
        .or_else(|| kvs.remove("backend"))
        .unwrap_or_else(|| default_hook_type().into());
    let builtin_id = kvs
        .remove("builtin")
        .or_else(|| kvs.remove("builtin_id"))
        .or_else(|| kvs.remove("id"));
    let attach_point = kvs.remove("attach_point").unwrap_or_default();
    let priority = kvs
        .remove("priority")
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0);
    let enabled = kvs
        .remove("enabled")
        .and_then(|v| parse_bool(&v))
        .unwrap_or(true);

    ParsedHook {
        name,
        path,
        hook_type,
        builtin_id,
        attach_point,
        priority,
        enabled,
    }
}

pub(super) fn default_hook_type() -> &'static str {
    if cfg!(feature = "rns-hooks-native") {
        "native"
    } else {
        "wasm"
    }
}

/// Map a hook point name string to its index. Returns None for unknown names.
pub fn parse_hook_point(s: &str) -> Option<usize> {
    match s {
        "PreIngress" => Some(0),
        "PreDispatch" => Some(1),
        "AnnounceReceived" => Some(2),
        "PathUpdated" => Some(3),
        "AnnounceRetransmit" => Some(4),
        "LinkRequestReceived" => Some(5),
        "LinkEstablished" => Some(6),
        "LinkClosed" => Some(7),
        "InterfaceUp" => Some(8),
        "InterfaceDown" => Some(9),
        "InterfaceConfigChanged" => Some(10),
        "BackbonePeerConnected" => Some(11),
        "BackbonePeerDisconnected" => Some(12),
        "BackbonePeerIdleTimeout" => Some(13),
        "BackbonePeerWriteStall" => Some(14),
        "BackbonePeerPenalty" => Some(15),
        "SendOnInterface" => Some(16),
        "BroadcastOnAllInterfaces" => Some(17),
        "DeliverLocal" => Some(18),
        "TunnelSynthesize" => Some(19),
        "Tick" => Some(20),
        _ => None,
    }
}

/// The hook backend a hook's `type` names.
#[cfg(feature = "hooks")]
pub fn parse_hook_backend(s: &str) -> Result<rns_hooks::HookBackend, String> {
    s.parse()
}
