//! Layouts of the contexts the host passes to a hook.
//!
//! A WASM hook receives a pointer to one of these at [`ARENA_BASE`] in its
//! linear memory; a native hook receives a pointer and length to a host
//! buffer with the same layout. Every context starts with a `u32`
//! `context_type` holding one of the `CTX_TYPE_*` values, which says which
//! struct to read the rest as. Interface ids are the host's numeric
//! interface identifiers, and hashes are the raw truncated hashes.

/// Base address in WASM linear memory where the host writes context.
pub const ARENA_BASE: usize = 0x1000;

/// `context_type` of a [`PacketContext`].
pub const CTX_TYPE_PACKET: u32 = 0;
/// `context_type` of an [`InterfaceContext`].
pub const CTX_TYPE_INTERFACE: u32 = 1;
/// `context_type` of a [`TickContext`].
pub const CTX_TYPE_TICK: u32 = 2;
/// `context_type` of an [`AnnounceContext`].
pub const CTX_TYPE_ANNOUNCE: u32 = 3;
/// `context_type` of a [`LinkContext`].
pub const CTX_TYPE_LINK: u32 = 4;
/// `context_type` of a [`BackbonePeerContext`].
pub const CTX_TYPE_BACKBONE_PEER: u32 = 5;

/// Read the context type discriminant from an arena pointer.
///
/// # Safety
/// `ptr` must point to a valid arena context written by the host.
pub unsafe fn context_type(ptr: *const u8) -> u32 {
    (ptr as *const u32).read()
}

/// Context of the packet hook points (ingress, dispatch, send, broadcast,
/// local delivery). 80 bytes, followed by the raw packet bytes.
#[repr(C)]
pub struct PacketContext {
    /// [`CTX_TYPE_PACKET`].
    pub context_type: u32,
    /// The packet's first header byte (header type, propagation, destination
    /// and packet type bits); 0 when the host has no raw header at hand.
    pub flags: u8,
    /// The packet's hop count as on the wire; 0 when unknown.
    pub hops: u8,
    _pad: [u8; 2],
    /// Destination the packet is addressed to; all zeroes if the packet is
    /// too short to hold one.
    pub destination_hash: [u8; 16],
    /// The packet's context byte; the host may leave it 0.
    pub context: u8,
    _pad2: [u8; 3],
    /// The packet's hash, or all zeroes where the host has not computed it
    /// (only local delivery fills it in).
    pub packet_hash: [u8; 32],
    _pad3: u32,
    /// Interface the packet arrived on or is leaving through.
    pub interface_id: u64,
    /// Byte offset from the start of this struct to the raw packet bytes.
    pub data_offset: u32,
    /// Length of the raw packet bytes, in bytes.
    pub data_len: u32,
}

/// Context of the interface lifecycle hook points (up, down, config changed).
#[repr(C)]
pub struct InterfaceContext {
    /// [`CTX_TYPE_INTERFACE`].
    pub context_type: u32,
    _pad: u32,
    /// The interface the event is about.
    pub interface_id: u64,
}

/// Context of the periodic tick hook point; it carries nothing else.
#[repr(C)]
pub struct TickContext {
    /// [`CTX_TYPE_TICK`].
    pub context_type: u32,
}

/// Context of the announce and path hook points (announce received,
/// path updated, announce retransmit).
#[repr(C)]
pub struct AnnounceContext {
    /// [`CTX_TYPE_ANNOUNCE`].
    pub context_type: u32,
    /// Hop count of the announce or of the new path.
    pub hops: u8,
    _pad: [u8; 3],
    /// The announced destination.
    pub destination_hash: [u8; 16],
    /// Interface the announce arrived on or the path goes through; 0 when
    /// the host does not know it.
    pub interface_id: u64,
}

/// Context of the link lifecycle hook points (request received,
/// established, closed).
#[repr(C)]
pub struct LinkContext {
    /// [`CTX_TYPE_LINK`].
    pub context_type: u32,
    _pad: u32,
    /// The link's id.
    pub link_id: [u8; 16],
    /// Interface the link runs over; 0 when the host does not know it.
    pub interface_id: u64,
}

/// Context of the backbone peer hook points (connected, disconnected, idle
/// timeout, write stall, penalty). 64 bytes, packed: copy it out with an
/// unaligned read rather than referencing its fields in place.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BackbonePeerContext {
    /// [`CTX_TYPE_BACKBONE_PEER`].
    pub context_type: u32,
    /// 4 for an IPv4 peer, 6 for IPv6.
    pub peer_ip_family: u8,
    /// The peer's TCP port; 0 for a penalty.
    pub peer_port: u16,
    /// 1 if the peer sent data before it disconnected, else 0.
    pub had_received_data: u8,
    /// The backbone server interface the peer connected to.
    pub server_interface_id: u64,
    /// The interface spawned for the peer; 0 for a penalty, which has none.
    pub peer_interface_id: u64,
    /// How long the connection lasted, in seconds; 0 when the event has none.
    pub connected_for_secs: u64,
    /// Penalty level of a penalty event; 0 for the other events.
    pub penalty_level: u8,
    _pad: [u8; 7],
    /// How long the peer's IP is blacklisted, in seconds, for a penalty
    /// event; 0 for the other events.
    pub blacklist_for_secs: u64,
    /// The peer's address: an IPv4 address in the first 4 bytes (the rest
    /// zero), or the 16 bytes of an IPv6 address.
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
