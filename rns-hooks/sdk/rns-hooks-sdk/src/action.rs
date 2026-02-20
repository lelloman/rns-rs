// Import tag constants from shared ABI crate.
pub use rns_hooks_abi::wire::*;

fn write_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_u64(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

/// Encode `SendOnInterface`. Returns bytes written.
/// Layout: tag(1) + interface(8) + data_offset(4) + data_len(4) = 17
pub fn encode_send_on_interface(
    buf: &mut [u8],
    interface: u64,
    data_ptr: u32,
    data_len: u32,
) -> usize {
    buf[0] = TAG_SEND_ON_INTERFACE;
    write_u64(buf, 1, interface);
    write_u32(buf, 9, data_ptr);
    write_u32(buf, 13, data_len);
    17
}

/// Encode `BroadcastOnAllInterfaces`. Returns bytes written.
/// Layout: tag(1) + data_offset(4) + data_len(4) + exclude(8) + has_exclude(1) = 18
pub fn encode_broadcast(
    buf: &mut [u8],
    data_ptr: u32,
    data_len: u32,
    exclude: u64,
    has_exclude: bool,
) -> usize {
    buf[0] = TAG_BROADCAST;
    write_u32(buf, 1, data_ptr);
    write_u32(buf, 5, data_len);
    write_u64(buf, 9, exclude);
    buf[17] = has_exclude as u8;
    18
}

/// Encode `DeliverLocal`. Returns bytes written.
/// Layout: tag(1) + dest_hash(16) + data_offset(4) + data_len(4) + packet_hash(32) + receiving_interface(8) = 65
pub fn encode_deliver_local(
    buf: &mut [u8],
    destination_hash: &[u8; 16],
    data_ptr: u32,
    data_len: u32,
    packet_hash: &[u8; 32],
    receiving_interface: u64,
) -> usize {
    buf[0] = TAG_DELIVER_LOCAL;
    buf[1..17].copy_from_slice(destination_hash);
    write_u32(buf, 17, data_ptr);
    write_u32(buf, 21, data_len);
    buf[25..57].copy_from_slice(packet_hash);
    write_u64(buf, 57, receiving_interface);
    65
}

/// Encode `AnnounceReceived` without app_data. Returns bytes written.
/// Layout: tag(1) + dest_hash(16) + identity_hash(16) + public_key(64) + name_hash(10) +
///         random_hash(10) + hops(1) + receiving_interface(8) + has_app_data(1) = 127
pub fn encode_announce_received(
    buf: &mut [u8],
    destination_hash: &[u8; 16],
    identity_hash: &[u8; 16],
    public_key: &[u8; 64],
    name_hash: &[u8; 10],
    random_hash: &[u8; 10],
    hops: u8,
    receiving_interface: u64,
) -> usize {
    buf[0] = TAG_ANNOUNCE_RECEIVED;
    buf[1..17].copy_from_slice(destination_hash);
    buf[17..33].copy_from_slice(identity_hash);
    buf[33..97].copy_from_slice(public_key);
    buf[97..107].copy_from_slice(name_hash);
    buf[107..117].copy_from_slice(random_hash);
    buf[117] = hops;
    write_u64(buf, 118, receiving_interface);
    buf[126] = 0; // has_app_data = false
    127
}

/// Encode `AnnounceReceived` with app_data. Returns bytes written.
/// Layout: 127 base + app_data_offset(4) + app_data_len(4) = 135
pub fn encode_announce_received_with_app_data(
    buf: &mut [u8],
    destination_hash: &[u8; 16],
    identity_hash: &[u8; 16],
    public_key: &[u8; 64],
    name_hash: &[u8; 10],
    random_hash: &[u8; 10],
    hops: u8,
    receiving_interface: u64,
    app_data_ptr: u32,
    app_data_len: u32,
) -> usize {
    // Write base fields
    let _ = encode_announce_received(
        buf,
        destination_hash,
        identity_hash,
        public_key,
        name_hash,
        random_hash,
        hops,
        receiving_interface,
    );
    buf[126] = 1; // has_app_data = true
    write_u32(buf, 127, app_data_ptr);
    write_u32(buf, 131, app_data_len);
    135
}

/// Encode `PathUpdated`. Returns bytes written.
/// Layout: tag(1) + dest_hash(16) + hops(1) + next_hop(16) + interface(8) = 42
pub fn encode_path_updated(
    buf: &mut [u8],
    destination_hash: &[u8; 16],
    hops: u8,
    next_hop: &[u8; 16],
    interface: u64,
) -> usize {
    buf[0] = TAG_PATH_UPDATED;
    buf[1..17].copy_from_slice(destination_hash);
    buf[17] = hops;
    buf[18..34].copy_from_slice(next_hop);
    write_u64(buf, 34, interface);
    42
}

/// Encode `ForwardToLocalClients`. Returns bytes written.
/// Layout: tag(1) + data_offset(4) + data_len(4) + exclude(8) + has_exclude(1) = 18
pub fn encode_forward_local_clients(
    buf: &mut [u8],
    data_ptr: u32,
    data_len: u32,
    exclude: u64,
    has_exclude: bool,
) -> usize {
    buf[0] = TAG_FORWARD_LOCAL_CLIENTS;
    write_u32(buf, 1, data_ptr);
    write_u32(buf, 5, data_len);
    write_u64(buf, 9, exclude);
    buf[17] = has_exclude as u8;
    18
}

/// Encode `ForwardPlainBroadcast`. Returns bytes written.
/// Layout: tag(1) + data_offset(4) + data_len(4) + to_local(1) + exclude(8) + has_exclude(1) = 19
pub fn encode_forward_plain_broadcast(
    buf: &mut [u8],
    data_ptr: u32,
    data_len: u32,
    to_local: bool,
    exclude: u64,
    has_exclude: bool,
) -> usize {
    buf[0] = TAG_FORWARD_PLAIN_BROADCAST;
    write_u32(buf, 1, data_ptr);
    write_u32(buf, 5, data_len);
    buf[9] = to_local as u8;
    write_u64(buf, 10, exclude);
    buf[18] = has_exclude as u8;
    19
}

/// Encode `CacheAnnounce`. Returns bytes written.
/// Layout: tag(1) + packet_hash(32) + data_offset(4) + data_len(4) = 41
pub fn encode_cache_announce(
    buf: &mut [u8],
    packet_hash: &[u8; 32],
    data_ptr: u32,
    data_len: u32,
) -> usize {
    buf[0] = TAG_CACHE_ANNOUNCE;
    buf[1..33].copy_from_slice(packet_hash);
    write_u32(buf, 33, data_ptr);
    write_u32(buf, 37, data_len);
    41
}

/// Encode `TunnelSynthesize`. Returns bytes written.
/// Layout: tag(1) + interface(8) + data_offset(4) + data_len(4) + dest_hash(16) = 33
pub fn encode_tunnel_synthesize(
    buf: &mut [u8],
    interface: u64,
    data_ptr: u32,
    data_len: u32,
    dest_hash: &[u8; 16],
) -> usize {
    buf[0] = TAG_TUNNEL_SYNTHESIZE;
    write_u64(buf, 1, interface);
    write_u32(buf, 9, data_ptr);
    write_u32(buf, 13, data_len);
    buf[17..33].copy_from_slice(dest_hash);
    33
}

/// Encode `TunnelEstablished`. Returns bytes written.
/// Layout: tag(1) + tunnel_id(32) + interface(8) = 41
pub fn encode_tunnel_established(
    buf: &mut [u8],
    tunnel_id: &[u8; 32],
    interface: u64,
) -> usize {
    buf[0] = TAG_TUNNEL_ESTABLISHED;
    buf[1..33].copy_from_slice(tunnel_id);
    write_u64(buf, 33, interface);
    41
}
