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
}

/// Log a string message to the host.
pub fn log_str(msg: &str) {
    unsafe {
        host_log(msg.as_ptr() as i32, msg.len() as i32);
    }
}

/// Check if a path exists to the given 16-byte destination hash.
pub fn has_path(dest: &[u8; 16]) -> bool {
    unsafe { host_has_path(dest.as_ptr() as i32) != 0 }
}

/// Get hop count to destination. Returns `None` if no path.
pub fn get_hops(dest: &[u8; 16]) -> Option<u8> {
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
    let r = unsafe { host_get_next_hop(dest.as_ptr() as i32, out.as_mut_ptr() as i32) };
    if r != 0 {
        Some(out)
    } else {
        None
    }
}

/// Check if an identity is blackholed.
pub fn is_blackholed(identity: &[u8; 16]) -> bool {
    unsafe { host_is_blackholed(identity.as_ptr() as i32) != 0 }
}

/// Get interface name. Writes into the provided buffer, returns the number of
/// bytes written, or `None` if the interface was not found.
pub fn get_interface_name(id: u64, buf: &mut [u8]) -> Option<usize> {
    let r = unsafe {
        host_get_interface_name(id as i64, buf.as_mut_ptr() as i32, buf.len() as i32)
    };
    if r < 0 {
        None
    } else {
        Some(r as usize)
    }
}

/// Get interface mode byte. Returns `None` if not found.
pub fn get_interface_mode(id: u64) -> Option<u8> {
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
    let r = unsafe { host_get_link_state(link_hash.as_ptr() as i32) };
    if r < 0 {
        None
    } else {
        Some(r as u8)
    }
}

/// Inject a raw action. `buf` must contain a binary-encoded action.
/// Returns `true` on success.
pub fn inject_action_raw(buf: &[u8]) -> bool {
    unsafe { host_inject_action(buf.as_ptr() as i32, buf.len() as i32) == 0 }
}
