use crate::error::HookError;
use crate::hooks::HookContext;
use crate::result::HookResult;
use crate::result::Verdict;
use crate::runtime::StoreData;

/// Base address in WASM linear memory where context is written.
pub const ARENA_BASE: usize = 0x1000;

/// Context type discriminants written at the start of the arena.
pub const CTX_TYPE_PACKET: u32 = 0;
pub const CTX_TYPE_INTERFACE: u32 = 1;
pub const CTX_TYPE_TICK: u32 = 2;
pub const CTX_TYPE_ANNOUNCE: u32 = 3;
pub const CTX_TYPE_LINK: u32 = 4;

/// repr(C) arena struct for Packet context.
#[repr(C)]
struct ArenaPacket {
    context_type: u32,
    flags: u8,
    hops: u8,
    _pad: [u8; 2],
    destination_hash: [u8; 16],
    context: u8,
    _pad2: [u8; 3],
    packet_hash: [u8; 32],
    interface_id: u64,
    data_offset: u32,
    data_len: u32,
}

/// repr(C) arena struct for Interface context.
#[repr(C)]
struct ArenaInterface {
    context_type: u32,
    _pad: u32,
    interface_id: u64,
}

/// repr(C) arena struct for Tick context.
#[repr(C)]
struct ArenaTick {
    context_type: u32,
}

/// repr(C) arena struct for Announce context.
#[repr(C)]
struct ArenaAnnounce {
    context_type: u32,
    hops: u8,
    _pad: [u8; 3],
    destination_hash: [u8; 16],
    interface_id: u64,
}

/// repr(C) arena struct for Link context.
#[repr(C)]
struct ArenaLink {
    context_type: u32,
    _pad: u32,
    link_id: [u8; 16],
    interface_id: u64,
}

/// Write a HookContext into WASM linear memory at ARENA_BASE.
/// Returns the number of bytes written.
pub fn write_context(
    memory: &wasmtime::Memory,
    mut store: impl wasmtime::AsContextMut<Data = StoreData>,
    ctx: &HookContext,
) -> Result<usize, HookError> {
    let mem_size = memory.data_size(&store);
    match ctx {
        HookContext::Packet(pkt) => {
            let size = std::mem::size_of::<ArenaPacket>() + pkt.data_len as usize;
            if ARENA_BASE + size > mem_size {
                return Err(HookError::InvalidResult("arena overflow for Packet context".into()));
            }
            let data = memory.data_mut(&mut store);
            let base = ARENA_BASE;
            // Write fields manually to avoid alignment issues
            write_u32(data, base, CTX_TYPE_PACKET);
            data[base + 4] = pkt.flags;
            data[base + 5] = pkt.hops;
            data[base + 6] = 0;
            data[base + 7] = 0;
            data[base + 8..base + 24].copy_from_slice(&pkt.destination_hash);
            data[base + 24] = pkt.context;
            data[base + 25] = 0;
            data[base + 26] = 0;
            data[base + 27] = 0;
            data[base + 28..base + 60].copy_from_slice(&pkt.packet_hash);
            // 4 bytes padding at offset 60 for u64 alignment
            write_u32(data, base + 60, 0);
            write_u64(data, base + 64, pkt.interface_id);
            // data_offset: offset from arena base to the variable data
            let header_size = std::mem::size_of::<ArenaPacket>();
            write_u32(data, base + 72, header_size as u32);
            write_u32(data, base + 76, pkt.data_len);
            // Note: we don't have the actual packet data bytes here (PacketContext only
            // has offset/len). The guest will see data_len=N but the data area is zeroed.
            // In a full implementation the caller would copy packet bytes after the header.
            Ok(size)
        }
        HookContext::Interface { interface_id } => {
            let size = std::mem::size_of::<ArenaInterface>();
            if ARENA_BASE + size > mem_size {
                return Err(HookError::InvalidResult("arena overflow for Interface context".into()));
            }
            let data = memory.data_mut(&mut store);
            let base = ARENA_BASE;
            write_u32(data, base, CTX_TYPE_INTERFACE);
            write_u32(data, base + 4, 0); // pad
            write_u64(data, base + 8, *interface_id);
            Ok(size)
        }
        HookContext::Tick => {
            let size = std::mem::size_of::<ArenaTick>();
            if ARENA_BASE + size > mem_size {
                return Err(HookError::InvalidResult("arena overflow for Tick context".into()));
            }
            let data = memory.data_mut(&mut store);
            write_u32(data, ARENA_BASE, CTX_TYPE_TICK);
            Ok(size)
        }
        HookContext::Announce {
            destination_hash,
            hops,
            interface_id,
        } => {
            let size = std::mem::size_of::<ArenaAnnounce>();
            if ARENA_BASE + size > mem_size {
                return Err(HookError::InvalidResult("arena overflow for Announce context".into()));
            }
            let data = memory.data_mut(&mut store);
            let base = ARENA_BASE;
            write_u32(data, base, CTX_TYPE_ANNOUNCE);
            data[base + 4] = *hops;
            data[base + 5] = 0;
            data[base + 6] = 0;
            data[base + 7] = 0;
            data[base + 8..base + 24].copy_from_slice(destination_hash);
            write_u64(data, base + 24, *interface_id);
            Ok(size)
        }
        HookContext::Link {
            link_id,
            interface_id,
        } => {
            let size = std::mem::size_of::<ArenaLink>();
            if ARENA_BASE + size > mem_size {
                return Err(HookError::InvalidResult("arena overflow for Link context".into()));
            }
            let data = memory.data_mut(&mut store);
            let base = ARENA_BASE;
            write_u32(data, base, CTX_TYPE_LINK);
            write_u32(data, base + 4, 0); // pad
            data[base + 8..base + 24].copy_from_slice(link_id);
            write_u64(data, base + 24, *interface_id);
            Ok(size)
        }
    }
}

/// Read a HookResult from WASM linear memory at the given offset.
pub fn read_result(
    memory: &wasmtime::Memory,
    store: impl wasmtime::AsContext<Data = StoreData>,
    offset: usize,
) -> Result<HookResult, HookError> {
    let size = std::mem::size_of::<HookResult>();
    let mem_size = memory.data_size(&store);
    if offset + size > mem_size {
        return Err(HookError::InvalidResult(format!(
            "result offset {} + size {} exceeds memory size {}",
            offset, size, mem_size
        )));
    }
    let data = memory.data(&store);
    let verdict = read_u32(data, offset);
    if Verdict::from_u32(verdict).is_none() {
        return Err(HookError::InvalidResult(format!(
            "invalid verdict value: {}",
            verdict
        )));
    }
    Ok(HookResult {
        verdict,
        modified_data_offset: read_u32(data, offset + 4),
        modified_data_len: read_u32(data, offset + 8),
        inject_actions_offset: read_u32(data, offset + 12),
        inject_actions_count: read_u32(data, offset + 16),
        log_offset: read_u32(data, offset + 20),
        log_len: read_u32(data, offset + 24),
    })
}

fn write_u32(data: &mut [u8], offset: usize, val: u32) {
    data[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_u64(data: &mut [u8], offset: usize, val: u64) {
    data[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}
