/// Base address in WASM linear memory where the host writes context.
pub const ARENA_BASE: usize = 0x1000;

/// Context type discriminants.
pub const CTX_TYPE_PACKET: u32 = 0;
pub const CTX_TYPE_INTERFACE: u32 = 1;
pub const CTX_TYPE_TICK: u32 = 2;
pub const CTX_TYPE_ANNOUNCE: u32 = 3;
pub const CTX_TYPE_LINK: u32 = 4;

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

impl PacketContext {
    /// Read the variable-length packet data that follows the header.
    ///
    /// # Safety
    /// The caller must ensure the arena memory is valid and `data_len` bytes
    /// are readable at `ARENA_BASE + data_offset`.
    pub unsafe fn data(&self) -> &[u8] {
        let base = ARENA_BASE as *const u8;
        let start = base.add(self.data_offset as usize);
        core::slice::from_raw_parts(start, self.data_len as usize)
    }
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
