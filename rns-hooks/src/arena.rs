use crate::error::HookError;
use crate::hooks::HookContext;
use crate::result::HookResult;
use crate::result::Verdict;
use crate::runtime::StoreData;

pub use rns_hooks_abi::context::{
    AnnounceContext, InterfaceContext, LinkContext, PacketContext, TickContext, ARENA_BASE,
    CTX_TYPE_ANNOUNCE, CTX_TYPE_INTERFACE, CTX_TYPE_LINK, CTX_TYPE_PACKET, CTX_TYPE_TICK,
};

/// Write a HookContext into WASM linear memory at ARENA_BASE.
/// Returns the number of bytes written.
pub fn write_context(
    memory: &wasmtime::Memory,
    mut store: impl wasmtime::AsContextMut<Data = StoreData>,
    ctx: &HookContext,
) -> Result<usize, HookError> {
    let mem_size = memory.data_size(&store);
    match ctx {
        HookContext::Packet { ctx: pkt, raw } => {
            let header_size = std::mem::size_of::<PacketContext>();
            let size = header_size + raw.len();
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
            // data_offset: offset from start of struct to variable data
            write_u32(data, base + 72, header_size as u32);
            write_u32(data, base + 76, raw.len() as u32);
            // Copy raw packet bytes after the header
            if !raw.is_empty() {
                let data_start = base + header_size;
                data[data_start..data_start + raw.len()].copy_from_slice(raw);
            }
            Ok(size)
        }
        HookContext::Interface { interface_id } => {
            let size = std::mem::size_of::<InterfaceContext>();
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
            let size = std::mem::size_of::<TickContext>();
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
            let size = std::mem::size_of::<AnnounceContext>();
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
            let size = std::mem::size_of::<LinkContext>();
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

fn read_slice(data: &[u8], offset: usize, len: usize) -> Option<Vec<u8>> {
    let end = offset.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some(data[offset..end].to_vec())
}

/// Parse an ActionWire from guest linear memory at the given range.
///
/// Binary encoding:
/// - Byte 0: tag (see `wire::TAG_*` constants)
/// - Remaining bytes: variant fields, little-endian
///
/// All data referenced by offset/len pairs within the action is copied
/// from `wasm_data` (full linear memory) into owned `Vec<u8>`.
pub fn read_action_wire(
    wasm_data: &[u8],
    action_ptr: usize,
    action_len: usize,
) -> Option<crate::wire::ActionWire> {
    use crate::wire::*;
    use rns_hooks_abi::wire as tags;

    let end = action_ptr.checked_add(action_len)?;
    if end > wasm_data.len() || action_len == 0 {
        return None;
    }
    let buf = &wasm_data[action_ptr..end];
    let tag = buf[0];
    let b = &buf[1..];

    match tag {
        tags::TAG_SEND_ON_INTERFACE => {
            // interface: u64 (8) + data_offset: u32 (4) + data_len: u32 (4) = 16
            if b.len() < 16 { return None; }
            let interface = u64::from_le_bytes(b[0..8].try_into().ok()?);
            let data_offset = u32::from_le_bytes(b[8..12].try_into().ok()?) as usize;
            let data_len = u32::from_le_bytes(b[12..16].try_into().ok()?) as usize;
            let raw = read_slice(wasm_data, data_offset, data_len)?;
            Some(ActionWire::SendOnInterface { interface, raw })
        }
        tags::TAG_BROADCAST => {
            // data_offset: u32 (4) + data_len: u32 (4) + exclude: u64 (8) + has_exclude: u8 (1) = 17
            if b.len() < 17 { return None; }
            let data_offset = u32::from_le_bytes(b[0..4].try_into().ok()?) as usize;
            let data_len = u32::from_le_bytes(b[4..8].try_into().ok()?) as usize;
            let exclude = u64::from_le_bytes(b[8..16].try_into().ok()?);
            let has_exclude = b[16];
            let raw = read_slice(wasm_data, data_offset, data_len)?;
            Some(ActionWire::BroadcastOnAllInterfaces { raw, exclude, has_exclude })
        }
        tags::TAG_DELIVER_LOCAL => {
            // dest_hash: 16 + data_offset: 4 + data_len: 4 + packet_hash: 32 + receiving_interface: 8 = 64
            if b.len() < 64 { return None; }
            let destination_hash: [u8; 16] = b[0..16].try_into().ok()?;
            let data_offset = u32::from_le_bytes(b[16..20].try_into().ok()?) as usize;
            let data_len = u32::from_le_bytes(b[20..24].try_into().ok()?) as usize;
            let packet_hash: [u8; 32] = b[24..56].try_into().ok()?;
            let receiving_interface = u64::from_le_bytes(b[56..64].try_into().ok()?);
            let raw = read_slice(wasm_data, data_offset, data_len)?;
            Some(ActionWire::DeliverLocal { destination_hash, raw, packet_hash, receiving_interface })
        }
        tags::TAG_PATH_UPDATED => {
            // dest_hash: 16 + hops: 1 + next_hop: 16 + interface: 8 = 41
            if b.len() < 41 { return None; }
            let destination_hash: [u8; 16] = b[0..16].try_into().ok()?;
            let hops = b[16];
            let next_hop: [u8; 16] = b[17..33].try_into().ok()?;
            let interface = u64::from_le_bytes(b[33..41].try_into().ok()?);
            Some(ActionWire::PathUpdated { destination_hash, hops, next_hop, interface })
        }
        tags::TAG_ANNOUNCE_RECEIVED => {
            // dest_hash: 16 + identity_hash: 16 + public_key: 64 + name_hash: 10 +
            // random_hash: 10 + hops: 1 + receiving_interface: 8 + has_app_data: 1 = 126 minimum
            if b.len() < 126 { return None; }
            let destination_hash: [u8; 16] = b[0..16].try_into().ok()?;
            let identity_hash: [u8; 16] = b[16..32].try_into().ok()?;
            let public_key: [u8; 64] = b[32..96].try_into().ok()?;
            let name_hash: [u8; 10] = b[96..106].try_into().ok()?;
            let random_hash: [u8; 10] = b[106..116].try_into().ok()?;
            let hops = b[116];
            let receiving_interface = u64::from_le_bytes(b[117..125].try_into().ok()?);
            let has_app_data = b[125];
            let app_data = if has_app_data != 0 {
                // app_data_offset: u32 (4) + app_data_len: u32 (4)
                if b.len() < 134 { return None; }
                let app_data_offset = u32::from_le_bytes(b[126..130].try_into().ok()?) as usize;
                let app_data_len = u32::from_le_bytes(b[130..134].try_into().ok()?) as usize;
                Some(read_slice(wasm_data, app_data_offset, app_data_len)?)
            } else {
                None
            };
            Some(ActionWire::AnnounceReceived {
                destination_hash, identity_hash, public_key, name_hash,
                random_hash, app_data, hops, receiving_interface,
            })
        }
        tags::TAG_FORWARD_LOCAL_CLIENTS => {
            // data_offset: u32 (4) + data_len: u32 (4) + exclude: u64 (8) + has_exclude: u8 (1) = 17
            if b.len() < 17 { return None; }
            let data_offset = u32::from_le_bytes(b[0..4].try_into().ok()?) as usize;
            let data_len = u32::from_le_bytes(b[4..8].try_into().ok()?) as usize;
            let exclude = u64::from_le_bytes(b[8..16].try_into().ok()?);
            let has_exclude = b[16];
            let raw = read_slice(wasm_data, data_offset, data_len)?;
            Some(ActionWire::ForwardToLocalClients { raw, exclude, has_exclude })
        }
        tags::TAG_FORWARD_PLAIN_BROADCAST => {
            // data_offset: u32 (4) + data_len: u32 (4) + to_local: u8 (1) + exclude: u64 (8) + has_exclude: u8 (1) = 18
            if b.len() < 18 { return None; }
            let data_offset = u32::from_le_bytes(b[0..4].try_into().ok()?) as usize;
            let data_len = u32::from_le_bytes(b[4..8].try_into().ok()?) as usize;
            let to_local = b[8];
            let exclude = u64::from_le_bytes(b[9..17].try_into().ok()?);
            let has_exclude = b[17];
            let raw = read_slice(wasm_data, data_offset, data_len)?;
            Some(ActionWire::ForwardPlainBroadcast { raw, to_local, exclude, has_exclude })
        }
        tags::TAG_CACHE_ANNOUNCE => {
            // packet_hash: 32 + data_offset: 4 + data_len: 4 = 40
            if b.len() < 40 { return None; }
            let packet_hash: [u8; 32] = b[0..32].try_into().ok()?;
            let data_offset = u32::from_le_bytes(b[32..36].try_into().ok()?) as usize;
            let data_len = u32::from_le_bytes(b[36..40].try_into().ok()?) as usize;
            let raw = read_slice(wasm_data, data_offset, data_len)?;
            Some(ActionWire::CacheAnnounce { packet_hash, raw })
        }
        tags::TAG_TUNNEL_SYNTHESIZE => {
            // interface: u64 (8) + data_offset: u32 (4) + data_len: u32 (4) + dest_hash: 16 = 32
            if b.len() < 32 { return None; }
            let interface = u64::from_le_bytes(b[0..8].try_into().ok()?);
            let data_offset = u32::from_le_bytes(b[8..12].try_into().ok()?) as usize;
            let data_len = u32::from_le_bytes(b[12..16].try_into().ok()?) as usize;
            let dest_hash: [u8; 16] = b[16..32].try_into().ok()?;
            let data = read_slice(wasm_data, data_offset, data_len)?;
            Some(ActionWire::TunnelSynthesize { interface, data, dest_hash })
        }
        tags::TAG_TUNNEL_ESTABLISHED => {
            // tunnel_id: 32 + interface: 8 = 40
            if b.len() < 40 { return None; }
            let tunnel_id: [u8; 32] = b[0..32].try_into().ok()?;
            let interface = u64::from_le_bytes(b[32..40].try_into().ok()?);
            Some(ActionWire::TunnelEstablished { tunnel_id, interface })
        }
        _ => None,
    }
}

/// Read modified data bytes from WASM memory using offsets from a HookResult.
/// The offsets are relative to WASM linear memory (not arena base).
pub fn read_modified_data(
    memory: &wasmtime::Memory,
    store: impl wasmtime::AsContext<Data = StoreData>,
    result: &crate::result::HookResult,
) -> Option<Vec<u8>> {
    let offset = result.modified_data_offset as usize;
    let len = result.modified_data_len as usize;
    if len == 0 {
        return None;
    }
    let data = memory.data(&store);
    let end = offset.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some(data[offset..end].to_vec())
}

/// Overwrite the packet data region in the arena for subsequent hooks.
/// This writes `new_data` at the data offset within the Packet arena layout,
/// and updates the `data_len` field.
pub fn write_data_override(
    memory: &wasmtime::Memory,
    mut store: impl wasmtime::AsContextMut<Data = StoreData>,
    new_data: &[u8],
) -> Result<(), HookError> {
    let header_size = std::mem::size_of::<PacketContext>();
    let data_start = ARENA_BASE + header_size;
    let mem_size = memory.data_size(&store);
    if data_start + new_data.len() > mem_size {
        return Err(HookError::InvalidResult("modified data overflows arena".into()));
    }
    let mem = memory.data_mut(&mut store);
    mem[data_start..data_start + new_data.len()].copy_from_slice(new_data);
    // Update data_len field (at offset 76 from ARENA_BASE)
    write_u32(mem, ARENA_BASE + 76, new_data.len() as u32);
    Ok(())
}
