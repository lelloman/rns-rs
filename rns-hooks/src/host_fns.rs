use crate::runtime::StoreData;
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
    linker.func_wrap("env", "host_get_transport_identity", host_get_transport_identity)?;
    linker.func_wrap("env", "host_get_announce_rate", host_get_announce_rate)?;
    linker.func_wrap("env", "host_get_link_state", host_get_link_state)?;
    linker.func_wrap("env", "host_inject_action", host_inject_action)?;
    Ok(())
}

fn get_memory(caller: &mut Caller<'_, StoreData>) -> Option<wasmtime::Memory> {
    caller.get_export("memory").and_then(|e| e.into_memory())
}

fn read_bytes<'a>(data: &'a [u8], ptr: usize, len: usize) -> Option<&'a [u8]> {
    let end = ptr.checked_add(len)?;
    data.get(ptr..end)
}

fn read_16(data: &[u8], ptr: usize) -> Option<[u8; 16]> {
    read_bytes(data, ptr, 16).map(|s| {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(s);
        arr
    })
}

/// Log a message from guest memory.
fn host_log(mut caller: Caller<'_, StoreData>, ptr: i32, len: i32) {
    if ptr < 0 || len < 0 {
        return;
    }
    let Some(memory) = get_memory(&mut caller) else { return };
    let data = memory.data(&caller);
    if let Some(bytes) = read_bytes(data, ptr as usize, len as usize) {
        let msg = String::from_utf8_lossy(bytes).to_string();
        log::debug!("[wasm-hook] {}", msg);
        caller.data_mut().log_messages.push(msg);
    }
}

/// Check if a path exists to the given destination.
fn host_has_path(mut caller: Caller<'_, StoreData>, dest_ptr: i32) -> i32 {
    let Some(memory) = get_memory(&mut caller) else { return 0 };
    let data = memory.data(&caller);
    let Some(dest) = read_16(data, dest_ptr as usize) else { return 0 };
    let result = unsafe { caller.data().engine().has_path(&dest) };
    result as i32
}

/// Get hop count to destination. Returns -1 if no path.
fn host_get_hops(mut caller: Caller<'_, StoreData>, dest_ptr: i32) -> i32 {
    let Some(memory) = get_memory(&mut caller) else { return -1 };
    let data = memory.data(&caller);
    let Some(dest) = read_16(data, dest_ptr as usize) else { return -1 };
    match unsafe { caller.data().engine().hops_to(&dest) } {
        Some(h) => h as i32,
        None => -1,
    }
}

/// Get next hop for a destination. Writes 16 bytes to out_ptr. Returns 1 if found, 0 otherwise.
fn host_get_next_hop(mut caller: Caller<'_, StoreData>, dest_ptr: i32, out_ptr: i32) -> i32 {
    let Some(memory) = get_memory(&mut caller) else { return 0 };
    let data = memory.data(&caller);
    let Some(dest) = read_16(data, dest_ptr as usize) else { return 0 };
    match unsafe { caller.data().engine().next_hop(&dest) } {
        Some(hop) => {
            let data = memory.data_mut(&mut caller);
            let out = out_ptr as usize;
            if out + 16 > data.len() {
                return 0;
            }
            data[out..out + 16].copy_from_slice(&hop);
            1
        }
        None => 0,
    }
}

/// Check if an identity is blackholed.
fn host_is_blackholed(mut caller: Caller<'_, StoreData>, identity_ptr: i32) -> i32 {
    let Some(memory) = get_memory(&mut caller) else { return 0 };
    let data = memory.data(&caller);
    let Some(identity) = read_16(data, identity_ptr as usize) else { return 0 };
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
    if out_ptr < 0 || out_len < 0 {
        return -1;
    }
    let name = unsafe { caller.data().engine().interface_name(id as u64) };
    let Some(name) = name else { return -1 };
    let Some(memory) = get_memory(&mut caller) else { return -1 };
    let bytes = name.as_bytes();
    let write_len = bytes.len().min(out_len as usize);
    let data = memory.data_mut(&mut caller);
    let out = out_ptr as usize;
    if out + write_len > data.len() {
        return -1;
    }
    data[out..out + write_len].copy_from_slice(&bytes[..write_len]);
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
    let Some(memory) = get_memory(&mut caller) else { return 0 };
    let data = memory.data_mut(&mut caller);
    let out = out_ptr as usize;
    if out + 16 > data.len() {
        return 0;
    }
    data[out..out + 16].copy_from_slice(&hash);
    1
}

/// Get the outgoing announce rate for an interface in millihertz.
/// Returns -1 if the interface is not found.
fn host_get_announce_rate(caller: Caller<'_, StoreData>, id: i64) -> i32 {
    match unsafe { caller.data().engine().announce_rate(id as u64) } {
        Some(rate) => rate,
        None => -1,
    }
}

/// Get the state of a link. Returns the state as u8 (Pending=0, Handshake=1, Active=2,
/// Stale=3, Closed=4), or -1 if the link is not found.
fn host_get_link_state(mut caller: Caller<'_, StoreData>, link_hash_ptr: i32) -> i32 {
    let Some(memory) = get_memory(&mut caller) else { return -1 };
    let data = memory.data(&caller);
    let Some(hash) = read_16(data, link_hash_ptr as usize) else { return -1 };
    match unsafe { caller.data().engine().link_state(&hash) } {
        Some(state) => state as i32,
        None => -1,
    }
}

/// Inject an action from guest memory (action_ptr, action_len).
/// Returns 0 on success, -1 on error.
///
/// The guest writes a binary-encoded action into linear memory, then calls
/// this function. The host parses it into an `ActionWire` and queues it in
/// `StoreData.injected_actions` for dispatch after the hook chain completes.
fn host_inject_action(mut caller: Caller<'_, StoreData>, action_ptr: i32, action_len: i32) -> i32 {
    if action_ptr < 0 || action_len <= 0 {
        return -1;
    }
    let Some(memory) = get_memory(&mut caller) else { return -1 };
    let data = memory.data(&caller);
    match crate::arena::read_action_wire(data, action_ptr as usize, action_len as usize) {
        Some(action) => {
            caller.data_mut().injected_actions.push(action);
            0
        }
        None => -1,
    }
}
