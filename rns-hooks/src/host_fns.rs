use crate::runtime::{
    StoreData, MAX_INJECTED_ACTIONS_PER_CALL, MAX_INJECTED_ACTION_BYTES_PER_CALL,
    MAX_LOG_MESSAGES_PER_CALL, MAX_LOG_MESSAGE_BYTES, MAX_PROVIDER_EVENTS_PER_CALL,
    MAX_PROVIDER_EVENT_BYTES_PER_CALL,
};
use crate::wire::ActionWire;
use wasmtime::{Caller, Linker};

/// Register all host functions into the linker under the "env" module.
pub fn register_host_functions(linker: &mut Linker<StoreData>) -> Result<(), wasmtime::Error> {
    linker.func_wrap("env", "host_log", host_log)?;
    linker.func_wrap("env", "host_has_path", host_has_path)?;
    linker.func_wrap("env", "host_get_hops", host_get_hops)?;
    linker.func_wrap("env", "host_get_next_hop", host_get_next_hop)?;
    linker.func_wrap("env", "host_is_blackholed", host_is_blackholed)?;
    linker.func_wrap("env", "host_get_interface_name", host_get_interface_name)?;
    linker.func_wrap("env", "host_get_interface_mode", host_get_interface_mode)?;
    linker.func_wrap(
        "env",
        "host_get_transport_identity",
        host_get_transport_identity,
    )?;
    linker.func_wrap("env", "host_get_announce_rate", host_get_announce_rate)?;
    linker.func_wrap("env", "host_get_link_state", host_get_link_state)?;
    linker.func_wrap("env", "host_inject_action", host_inject_action)?;
    linker.func_wrap("env", "host_emit_event", host_emit_event)?;
    Ok(())
}

/// Return code for a call refused because a per-call limit was reached.
pub const LIMIT_REACHED: i32 = -3;

fn get_memory(caller: &mut Caller<'_, StoreData>) -> Option<wasmtime::Memory> {
    caller.get_export("memory").and_then(|e| e.into_memory())
}

/// Convert a guest pointer and length into a host range. Guest pointers are
/// unsigned 32-bit offsets into linear memory.
fn guest_range(ptr: i32, len: usize) -> Option<std::ops::Range<usize>> {
    let start = ptr as u32 as usize;
    let end = start.checked_add(len)?;
    Some(start..end)
}

fn read_bytes(data: &[u8], ptr: i32, len: i32) -> Option<&[u8]> {
    data.get(guest_range(ptr, len as u32 as usize)?)
}

fn read_16(data: &[u8], ptr: i32) -> Option<[u8; 16]> {
    data.get(guest_range(ptr, 16)?)?.try_into().ok()
}

fn write_bytes(data: &mut [u8], ptr: i32, bytes: &[u8]) -> bool {
    match guest_range(ptr, bytes.len()).and_then(|range| data.get_mut(range)) {
        Some(out) => {
            out.copy_from_slice(bytes);
            true
        }
        None => false,
    }
}

/// Charge one unit of fuel per byte copied between guest memory and the host.
/// Returns false, leaving no fuel, if the remaining budget does not cover it.
fn charge_fuel(caller: &mut Caller<'_, StoreData>, bytes: usize) -> bool {
    let Ok(fuel) = caller.get_fuel() else {
        // Fuel metering is not enabled for this store.
        return true;
    };
    let cost = u64::try_from(bytes).unwrap_or(u64::MAX);
    let enough = fuel >= cost;
    let _ = caller.set_fuel(fuel.saturating_sub(cost));
    enough
}

/// Log a message from guest memory.
///
/// Messages are forwarded to the host logger and not retained. At most
/// `MAX_LOG_MESSAGES_PER_CALL` messages are forwarded per invocation, each
/// truncated to `MAX_LOG_MESSAGE_BYTES`.
fn host_log(mut caller: Caller<'_, StoreData>, ptr: i32, len: i32) {
    if caller.data().log_messages_forwarded >= MAX_LOG_MESSAGES_PER_CALL {
        let data = caller.data_mut();
        data.log_messages_dropped += 1;
        if data.log_messages_dropped == 1 {
            log::debug!(
                "[wasm-hook {}] log limit of {} messages per call reached, dropping the rest",
                data.program_name,
                MAX_LOG_MESSAGES_PER_CALL
            );
        }
        return;
    }
    let Some(memory) = get_memory(&mut caller) else {
        return;
    };
    let data = memory.data(&caller);
    let Some(bytes) = read_bytes(data, ptr, len) else {
        return;
    };
    let bytes = &bytes[..bytes.len().min(MAX_LOG_MESSAGE_BYTES)];
    let msg = String::from_utf8_lossy(bytes).into_owned();
    if !charge_fuel(&mut caller, msg.len()) {
        return;
    }
    let data = caller.data_mut();
    data.log_messages_forwarded += 1;
    log::debug!("[wasm-hook {}] {}", data.program_name, msg);
}

/// Check if a path exists to the given destination.
fn host_has_path(mut caller: Caller<'_, StoreData>, dest_ptr: i32) -> i32 {
    let Some(memory) = get_memory(&mut caller) else {
        return 0;
    };
    let data = memory.data(&caller);
    let Some(dest) = read_16(data, dest_ptr) else {
        return 0;
    };
    let result = unsafe { caller.data().engine().has_path(&dest) };
    result as i32
}

/// Get hop count to destination. Returns -1 if no path.
fn host_get_hops(mut caller: Caller<'_, StoreData>, dest_ptr: i32) -> i32 {
    let Some(memory) = get_memory(&mut caller) else {
        return -1;
    };
    let data = memory.data(&caller);
    let Some(dest) = read_16(data, dest_ptr) else {
        return -1;
    };
    match unsafe { caller.data().engine().hops_to(&dest) } {
        Some(h) => h as i32,
        None => -1,
    }
}

/// Get next hop for a destination. Writes 16 bytes to out_ptr. Returns 1 if found, 0 otherwise.
fn host_get_next_hop(mut caller: Caller<'_, StoreData>, dest_ptr: i32, out_ptr: i32) -> i32 {
    let Some(memory) = get_memory(&mut caller) else {
        return 0;
    };
    let data = memory.data(&caller);
    let Some(dest) = read_16(data, dest_ptr) else {
        return 0;
    };
    match unsafe { caller.data().engine().next_hop(&dest) } {
        Some(hop) => write_bytes(memory.data_mut(&mut caller), out_ptr, &hop) as i32,
        None => 0,
    }
}

/// Check if an identity is blackholed.
fn host_is_blackholed(mut caller: Caller<'_, StoreData>, identity_ptr: i32) -> i32 {
    let Some(memory) = get_memory(&mut caller) else {
        return 0;
    };
    let data = memory.data(&caller);
    let Some(identity) = read_16(data, identity_ptr) else {
        return 0;
    };
    let result = unsafe { caller.data().engine().is_blackholed(&identity) };
    result as i32
}

/// Get interface name. Writes UTF-8 bytes to out_ptr (up to out_len). Returns bytes written, or -1.
fn host_get_interface_name(
    mut caller: Caller<'_, StoreData>,
    id: i64,
    out_ptr: i32,
    out_len: i32,
) -> i32 {
    if out_len < 0 {
        return -1;
    }
    let name = unsafe { caller.data().engine().interface_name(id as u64) };
    let Some(name) = name else { return -1 };
    let Some(memory) = get_memory(&mut caller) else {
        return -1;
    };
    let bytes = name.as_bytes();
    let write_len = bytes.len().min(out_len as usize);
    if !write_bytes(memory.data_mut(&mut caller), out_ptr, &bytes[..write_len]) {
        return -1;
    }
    write_len as i32
}
/// Get interface mode. Returns mode byte, or -1 if not found.
fn host_get_interface_mode(caller: Caller<'_, StoreData>, id: i64) -> i32 {
    match unsafe { caller.data().engine().interface_mode(id as u64) } {
        Some(m) => m as i32,
        None => -1,
    }
}

/// Get transport identity hash. Writes 16 bytes to out_ptr. Returns 1 if available, 0 otherwise.
fn host_get_transport_identity(mut caller: Caller<'_, StoreData>, out_ptr: i32) -> i32 {
    let hash = unsafe { caller.data().engine().identity_hash() };
    let Some(hash) = hash else { return 0 };
    let Some(memory) = get_memory(&mut caller) else {
        return 0;
    };
    write_bytes(memory.data_mut(&mut caller), out_ptr, &hash) as i32
}

/// Get the outgoing announce rate for an interface in millihertz.
/// Returns -1 if the interface is not found.
fn host_get_announce_rate(caller: Caller<'_, StoreData>, id: i64) -> i32 {
    unsafe { caller.data().engine().announce_rate(id as u64) }.unwrap_or(-1)
}

/// Get the state of a link. Returns the state as u8 (Pending=0, Handshake=1, Active=2,
/// Stale=3, Closed=4), or -1 if the link is not found.
fn host_get_link_state(mut caller: Caller<'_, StoreData>, link_hash_ptr: i32) -> i32 {
    let Some(memory) = get_memory(&mut caller) else {
        return -1;
    };
    let data = memory.data(&caller);
    let Some(hash) = read_16(data, link_hash_ptr) else {
        return -1;
    };
    match unsafe { caller.data().engine().link_state(&hash) } {
        Some(state) => state as i32,
        None => -1,
    }
}

/// Inject an action from guest memory (action_ptr, action_len).
/// Returns 0 on success, -1 on error, -3 if the per-call action limit is reached.
///
/// The guest writes a binary-encoded action into linear memory, then calls
/// this function. The host parses it into an `ActionWire` and queues it in
/// `StoreData.injected_actions` for dispatch after the hook chain completes.
/// At most `MAX_INJECTED_ACTIONS_PER_CALL` actions carrying at most
/// `MAX_INJECTED_ACTION_BYTES_PER_CALL` bytes are accepted per invocation.
fn host_inject_action(mut caller: Caller<'_, StoreData>, action_ptr: i32, action_len: i32) -> i32 {
    if action_len <= 0 {
        return -1;
    }
    if caller.data().injected_actions.len() >= MAX_INJECTED_ACTIONS_PER_CALL {
        return LIMIT_REACHED;
    }
    let Some(memory) = get_memory(&mut caller) else {
        return -1;
    };
    let data = memory.data(&caller);
    let Some(range) = guest_range(action_ptr, action_len as usize) else {
        return -1;
    };
    let Some(action) = crate::arena::read_action_wire(data, range.start, range.len()) else {
        return -1;
    };
    let size = range.len().saturating_add(action_payload_len(&action));
    if !charge_fuel(&mut caller, size) {
        return -1;
    }
    let store_data = caller.data_mut();
    let total = store_data.injected_action_bytes.saturating_add(size);
    if total > MAX_INJECTED_ACTION_BYTES_PER_CALL {
        return LIMIT_REACHED;
    }
    store_data.injected_action_bytes = total;
    store_data.injected_actions.push(action);
    0
}

/// Bytes copied out of guest memory for the variable-length fields of an action.
fn action_payload_len(action: &ActionWire) -> usize {
    match action {
        ActionWire::SendOnInterface { raw, .. }
        | ActionWire::BroadcastOnAllInterfaces { raw, .. }
        | ActionWire::DeliverLocal { raw, .. }
        | ActionWire::ForwardToLocalClients { raw, .. }
        | ActionWire::ForwardPlainBroadcast { raw, .. }
        | ActionWire::CacheAnnounce { raw, .. } => raw.len(),
        ActionWire::TunnelSynthesize { data, .. } => data.len(),
        ActionWire::AnnounceReceived { app_data, .. } => app_data.as_ref().map_or(0, Vec::len),
        ActionWire::PathUpdated { .. } | ActionWire::TunnelEstablished { .. } => 0,
    }
}

/// Queue a provider event for host-side forwarding.
/// Returns 0 on success, -1 on invalid memory, -2 if provider events are disabled,
/// -3 if the per-call event limit is reached.
///
/// At most `MAX_PROVIDER_EVENTS_PER_CALL` events carrying at most
/// `MAX_PROVIDER_EVENT_BYTES_PER_CALL` bytes (type plus payload) are accepted
/// per invocation.
fn host_emit_event(
    mut caller: Caller<'_, StoreData>,
    type_ptr: i32,
    type_len: i32,
    payload_ptr: i32,
    payload_len: i32,
) -> i32 {
    if type_len < 0 || payload_len < 0 {
        return -1;
    }
    if !caller.data().provider_events_enabled {
        return -2;
    }
    let size = type_len as usize + payload_len as usize;
    let store_data = caller.data();
    if store_data.provider_events.len() >= MAX_PROVIDER_EVENTS_PER_CALL
        || store_data.provider_event_bytes.saturating_add(size) > MAX_PROVIDER_EVENT_BYTES_PER_CALL
    {
        return LIMIT_REACHED;
    }
    let Some(memory) = get_memory(&mut caller) else {
        return -1;
    };
    let data = memory.data(&caller);
    let Some(payload_type_bytes) = read_bytes(data, type_ptr, type_len) else {
        return -1;
    };
    let Some(payload) = read_bytes(data, payload_ptr, payload_len) else {
        return -1;
    };
    let payload_type = String::from_utf8_lossy(payload_type_bytes).into_owned();
    let payload = payload.to_vec();
    if !charge_fuel(&mut caller, size) {
        return -1;
    }
    let store_data = caller.data_mut();
    store_data.provider_event_bytes += size;
    store_data
        .provider_events
        .push(crate::runtime::RawProviderEvent {
            payload_type,
            payload,
        });
    0
}
