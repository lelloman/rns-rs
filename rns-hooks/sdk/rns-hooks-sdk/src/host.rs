extern "C" {
    fn host_log(ptr: i32, len: i32);
    fn host_has_path(dest_ptr: i32) -> i32;
    fn host_get_hops(dest_ptr: i32) -> i32;
    fn host_get_next_hop(dest_ptr: i32, out_ptr: i32) -> i32;
    fn host_is_blackholed(identity_ptr: i32) -> i32;
    fn host_get_interface_name(id: i64, out_ptr: i32, out_len: i32) -> i32;
    fn host_get_interface_mode(id: i64) -> i32;
    fn host_get_transport_identity(out_ptr: i32) -> i32;
    fn host_get_announce_rate(id: i64) -> i32;
    fn host_get_link_state(link_hash_ptr: i32) -> i32;
    fn host_inject_action(action_ptr: i32, action_len: i32) -> i32;
    fn host_emit_event(type_ptr: i32, type_len: i32, payload_ptr: i32, payload_len: i32) -> i32;
}

/// Log a string message to the host.
pub fn log_str(msg: &str) {
    // SAFETY: the host bounds-checks every guest pointer/length against linear memory
    // (rns-hooks host_fns.rs) and never retains it; `msg` is a live borrowed
    // str of `msg.len()` bytes for the duration of the call.
    unsafe {
        host_log(msg.as_ptr() as i32, msg.len() as i32);
    }
}

/// Check if a path exists to the given 16-byte destination hash.
pub fn has_path(dest: &[u8; 16]) -> bool {
    // SAFETY: the host bounds-checks every guest pointer/length against linear memory
    // (rns-hooks host_fns.rs) and never retains it; `dest` is a live 16-byte
    // array, the size the host reads.
    unsafe { host_has_path(dest.as_ptr() as i32) != 0 }
}

/// Get hop count to destination. Returns `None` if no path.
pub fn get_hops(dest: &[u8; 16]) -> Option<u8> {
    // SAFETY: the host bounds-checks every guest pointer/length against linear memory
    // (rns-hooks host_fns.rs) and never retains it; `dest` is a live 16-byte
    // array, the size the host reads.
    let r = unsafe { host_get_hops(dest.as_ptr() as i32) };
    if r < 0 {
        None
    } else {
        Some(r as u8)
    }
}

/// Get next hop for a destination. Returns `None` if no path.
pub fn get_next_hop(dest: &[u8; 16]) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    // SAFETY: the host bounds-checks every guest pointer/length against linear memory
    // (rns-hooks host_fns.rs) and never retains it; `dest` and `out` are live
    // 16-byte arrays, the sizes the host reads and writes.
    let r = unsafe { host_get_next_hop(dest.as_ptr() as i32, out.as_mut_ptr() as i32) };
    if r != 0 {
        Some(out)
    } else {
        None
    }
}

/// Check if an identity is blackholed.
pub fn is_blackholed(identity: &[u8; 16]) -> bool {
    // SAFETY: the host bounds-checks every guest pointer/length against linear memory
    // (rns-hooks host_fns.rs) and never retains it; `identity` is a live 16-byte
    // array, the size the host reads.
    unsafe { host_is_blackholed(identity.as_ptr() as i32) != 0 }
}

/// Get interface name. Writes into the provided buffer, returns the number of
/// bytes written, or `None` if the interface was not found.
pub fn get_interface_name(id: u64, buf: &mut [u8]) -> Option<usize> {
    // SAFETY: the host bounds-checks every guest pointer/length against linear memory
    // (rns-hooks host_fns.rs) and never retains it; `buf` is a live exclusive
    // borrow of `buf.len()` bytes and the host writes at most `out_len` bytes.
    let r =
        unsafe { host_get_interface_name(id as i64, buf.as_mut_ptr() as i32, buf.len() as i32) };
    if r < 0 {
        None
    } else {
        Some(r as usize)
    }
}

/// Get interface mode byte. Returns `None` if not found.
pub fn get_interface_mode(id: u64) -> Option<u8> {
    // SAFETY: the host function takes only an integer id and touches no guest
    // memory.
    let r = unsafe { host_get_interface_mode(id as i64) };
    if r < 0 {
        None
    } else {
        Some(r as u8)
    }
}

/// Get the transport identity hash. Returns `None` if not available.
pub fn get_transport_identity() -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    // SAFETY: the host bounds-checks every guest pointer/length against linear memory
    // (rns-hooks host_fns.rs) and never retains it; `out` is a live 16-byte
    // array, the size the host writes.
    let r = unsafe { host_get_transport_identity(out.as_mut_ptr() as i32) };
    if r != 0 {
        Some(out)
    } else {
        None
    }
}

/// Get the outgoing announce rate for an interface in millihertz.
/// Returns `None` if the interface is not found.
pub fn get_announce_rate(id: u64) -> Option<i32> {
    // SAFETY: the host function takes only an integer id and touches no guest
    // memory.
    let r = unsafe { host_get_announce_rate(id as i64) };
    if r < 0 {
        None
    } else {
        Some(r)
    }
}

/// Get link state. Returns `None` if the link is not found.
/// States: Pending=0, Handshake=1, Active=2, Stale=3, Closed=4.
pub fn get_link_state(link_hash: &[u8; 16]) -> Option<u8> {
    // SAFETY: the host bounds-checks every guest pointer/length against linear memory
    // (rns-hooks host_fns.rs) and never retains it; `link_hash` is a live 16-byte
    // array, the size the host reads.
    let r = unsafe { host_get_link_state(link_hash.as_ptr() as i32) };
    if r < 0 {
        None
    } else {
        Some(r as u8)
    }
}

/// Inject a raw action. `buf` must contain a binary-encoded action.
/// Returns `true` on success; `false` if the action is invalid or the
/// per-call action limit has been reached.
pub fn inject_action_raw(buf: &[u8]) -> bool {
    // SAFETY: the host bounds-checks every guest pointer/length against linear memory
    // (rns-hooks host_fns.rs) and never retains it; `buf` is a live borrowed
    // slice of `buf.len()` bytes for the duration of the call.
    unsafe { host_inject_action(buf.as_ptr() as i32, buf.len() as i32) == 0 }
}

/// Emit a provider event for host-side forwarding.
/// Returns 0 on success, -1 on invalid arguments, -2 if disabled by the host,
/// -3 if the per-call event limit has been reached.
pub fn emit_event(payload_type: &str, payload: &[u8]) -> i32 {
    // SAFETY: the host bounds-checks every guest pointer/length against linear memory
    // (rns-hooks host_fns.rs) and never retains it; `payload_type` and `payload`
    // are live borrows of exactly the lengths passed with them.
    unsafe {
        host_emit_event(
            payload_type.as_ptr() as i32,
            payload_type.len() as i32,
            payload.as_ptr() as i32,
            payload.len() as i32,
        )
    }
}
