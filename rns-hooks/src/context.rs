/// Packet context shared between host and WASM guest via linear memory.
///
/// Uses raw primitives (`u64` for interface IDs, `[u8; N]` for hashes) so that
/// `rns-hooks` has zero dependency on `rns-core`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PacketContext {
    pub flags: u8,
    pub hops: u8,
    pub destination_hash: [u8; 16],
    pub context: u8,
    pub packet_hash: [u8; 32],
    pub interface_id: u64,
    /// Offset from the start of this struct to variable-length packet data.
    pub data_offset: u32,
    /// Length of the variable-length packet data.
    pub data_len: u32,
}
