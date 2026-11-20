/// Packet context shared between host and WASM guest via linear memory.
///
/// Uses raw primitives (`u64` for interface IDs, `[u8; N]` for hashes) so that
/// `rns-hooks` has zero dependency on `rns-core`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PacketContext {
    /// The packet's first header byte; 0 when the host has no raw header.
    pub flags: u8,
    /// The packet's hop count as on the wire; 0 when unknown.
    pub hops: u8,
    /// Destination the packet is addressed to; all zeroes if the packet is
    /// too short to hold one.
    pub destination_hash: [u8; 16],
    /// The packet's context byte; the host may leave it 0.
    pub context: u8,
    /// The packet's hash, or all zeroes where the host has not computed it.
    pub packet_hash: [u8; 32],
    /// Interface the packet arrived on or is leaving through.
    pub interface_id: u64,
    /// Offset from the start of this struct to variable-length packet data.
    pub data_offset: u32,
    /// Length of the variable-length packet data.
    pub data_len: u32,
}
