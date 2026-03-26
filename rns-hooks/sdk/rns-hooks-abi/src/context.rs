/// Base address in WASM linear memory where the host writes context.
pub const ARENA_BASE: usize = 0x1000;

/// Context type discriminants.
pub const CTX_TYPE_PACKET: u32 = 0;
pub const CTX_TYPE_INTERFACE: u32 = 1;
pub const CTX_TYPE_TICK: u32 = 2;
pub const CTX_TYPE_ANNOUNCE: u32 = 3;
pub const CTX_TYPE_LINK: u32 = 4;
pub const CTX_TYPE_BACKBONE_PEER: u32 = 5;

/// Read the context type discriminant from an arena pointer.
///
/// # Safety
/// `ptr` must point to a valid arena context written by the host.
pub unsafe fn context_type(ptr: *const u8) -> u32 {
    (ptr as *const u32).read()
}

/// Packet context layout — matches host `ArenaPacket` byte-for-byte.
#[repr(C)]
pub struct PacketContext {
    pub context_type: u32,
    pub flags: u8,
    pub hops: u8,
    _pad: [u8; 2],
    pub destination_hash: [u8; 16],
    pub context: u8,
    _pad2: [u8; 3],
    pub packet_hash: [u8; 32],
    _pad3: u32,
    pub interface_id: u64,
    pub data_offset: u32,
    pub data_len: u32,
}

/// Interface context layout — matches host `ArenaInterface`.
#[repr(C)]
pub struct InterfaceContext {
    pub context_type: u32,
    _pad: u32,
    pub interface_id: u64,
}

/// Tick context layout — matches host `ArenaTick`.
#[repr(C)]
pub struct TickContext {
    pub context_type: u32,
}

/// Announce context layout — matches host `ArenaAnnounce`.
#[repr(C)]
pub struct AnnounceContext {
    pub context_type: u32,
    pub hops: u8,
    _pad: [u8; 3],
    pub destination_hash: [u8; 16],
    pub interface_id: u64,
}

/// Link context layout — matches host `ArenaLink`.
#[repr(C)]
pub struct LinkContext {
    pub context_type: u32,
    _pad: u32,
    pub link_id: [u8; 16],
    pub interface_id: u64,
}

/// Backbone peer lifecycle context layout — matches host `ArenaBackbonePeer`.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BackbonePeerContext {
    pub context_type: u32,
    pub peer_ip_family: u8,
    pub peer_port: u16,
    pub had_received_data: u8,
    pub server_interface_id: u64,
    pub peer_interface_id: u64,
    pub connected_for_secs: u64,
    pub penalty_level: u8,
    _pad: [u8; 7],
    pub blacklist_for_secs: u64,
    pub peer_ip: [u8; 16],
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn backbone_peer_context_matches_host_layout() {
        assert_eq!(core::mem::size_of::<BackbonePeerContext>(), 64);
        let mut raw = [0u8; 64];
        write_u32(&mut raw, 0, CTX_TYPE_BACKBONE_PEER);
        raw[4] = 4;
        write_u16(&mut raw, 5, 4242);
        raw[7] = 1;
        write_u64(&mut raw, 8, 11);
        write_u64(&mut raw, 16, 22);
        write_u64(&mut raw, 24, 33);
        raw[32] = 4;
        write_u64(&mut raw, 40, 44);
        raw[48..64].copy_from_slice(&[172, 20, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let ctx = unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const BackbonePeerContext) };
        let context_type = ctx.context_type;
        let peer_ip_family = ctx.peer_ip_family;
        let peer_port = ctx.peer_port;
        let had_received_data = ctx.had_received_data;
        let server_interface_id = ctx.server_interface_id;
        let peer_interface_id = ctx.peer_interface_id;
        let connected_for_secs = ctx.connected_for_secs;
        let penalty_level = ctx.penalty_level;
        let blacklist_for_secs = ctx.blacklist_for_secs;
        let peer_ip = ctx.peer_ip;

        assert_eq!(context_type, CTX_TYPE_BACKBONE_PEER);
        assert_eq!(peer_ip_family, 4);
        assert_eq!(peer_port, 4242);
        assert_eq!(had_received_data, 1);
        assert_eq!(server_interface_id, 11);
        assert_eq!(peer_interface_id, 22);
        assert_eq!(connected_for_secs, 33);
        assert_eq!(penalty_level, 4);
        assert_eq!(blacklist_for_secs, 44);
        assert_eq!(peer_ip[0..4], [172, 20, 0, 3]);
    }
}
