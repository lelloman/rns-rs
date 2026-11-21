use crate::error::HookError;
use crate::hooks::HookContext;
#[cfg(feature = "wasm")]
use crate::result::{HookResult, Verdict};
#[cfg(feature = "wasm")]
use crate::runtime::StoreData;

#[cfg(feature = "wasm")]
pub(crate) use rns_hooks_abi::context::ARENA_BASE;
use rns_hooks_abi::context::{
    AnnounceContext, BackbonePeerContext, InterfaceContext, LinkContext, PacketContext,
    TickContext, CTX_TYPE_ANNOUNCE, CTX_TYPE_BACKBONE_PEER, CTX_TYPE_INTERFACE, CTX_TYPE_LINK,
    CTX_TYPE_PACKET, CTX_TYPE_TICK,
};

/// Write a HookContext into WASM linear memory at ARENA_BASE.
/// Returns the number of bytes written.
#[cfg(feature = "wasm")]
pub(crate) fn write_context(
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
                return Err(HookError::InvalidResult(
                    "arena overflow for Packet context".into(),
                ));
            }
            let data = memory.data_mut(&mut store);
            let base = ARENA_BASE;
            // Write fields manually to avoid alignment issues
            write_u32(data, base, CTX_TYPE_PACKET);
            put(data, base + 4, &[pkt.flags]);
            put(data, base + 5, &[pkt.hops]);
            put(data, base + 6, &[0]);
            put(data, base + 7, &[0]);
            put(data, base + 8, &pkt.destination_hash);
            put(data, base + 24, &[pkt.context]);
            put(data, base + 25, &[0]);
            put(data, base + 26, &[0]);
            put(data, base + 27, &[0]);
            put(data, base + 28, &pkt.packet_hash);
            // 4 bytes padding at offset 60 for u64 alignment
            write_u32(data, base + 60, 0);
            write_u64(data, base + 64, pkt.interface_id);
            // data_offset: offset from start of struct to variable data
            write_u32(data, base + 72, header_size as u32);
            write_u32(data, base + 76, raw.len() as u32);
            // Copy raw packet bytes after the header
            if !raw.is_empty() {
                let data_start = base + header_size;
                put(data, data_start, raw);
            }
            Ok(size)
        }
        HookContext::Interface { interface_id } => {
            let size = std::mem::size_of::<InterfaceContext>();
            if ARENA_BASE + size > mem_size {
                return Err(HookError::InvalidResult(
                    "arena overflow for Interface context".into(),
                ));
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
                return Err(HookError::InvalidResult(
                    "arena overflow for Tick context".into(),
                ));
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
                return Err(HookError::InvalidResult(
                    "arena overflow for Announce context".into(),
                ));
            }
            let data = memory.data_mut(&mut store);
            let base = ARENA_BASE;
            write_u32(data, base, CTX_TYPE_ANNOUNCE);
            put(data, base + 4, &[*hops]);
            put(data, base + 5, &[0]);
            put(data, base + 6, &[0]);
            put(data, base + 7, &[0]);
            put(data, base + 8, destination_hash);
            write_u64(data, base + 24, *interface_id);
            Ok(size)
        }
        HookContext::Link {
            link_id,
            interface_id,
        } => {
            let size = std::mem::size_of::<LinkContext>();
            if ARENA_BASE + size > mem_size {
                return Err(HookError::InvalidResult(
                    "arena overflow for Link context".into(),
                ));
            }
            let data = memory.data_mut(&mut store);
            let base = ARENA_BASE;
            write_u32(data, base, CTX_TYPE_LINK);
            write_u32(data, base + 4, 0); // pad
            put(data, base + 8, link_id);
            write_u64(data, base + 24, *interface_id);
            Ok(size)
        }
        HookContext::BackbonePeer {
            server_interface_id,
            peer_interface_id,
            peer_ip,
            peer_port,
            connected_for,
            had_received_data,
            penalty_level,
            blacklist_for,
        } => {
            let size = std::mem::size_of::<BackbonePeerContext>();
            if ARENA_BASE + size > mem_size {
                return Err(HookError::InvalidResult(
                    "arena overflow for BackbonePeer context".into(),
                ));
            }
            let data = memory.data_mut(&mut store);
            let base = ARENA_BASE;
            write_u32(data, base, CTX_TYPE_BACKBONE_PEER);
            put(data, base + 4, &[peer_ip_family(peer_ip)]);
            write_u16(data, base + 5, *peer_port);
            put(data, base + 7, &[u8::from(*had_received_data)]);
            write_u64(data, base + 8, *server_interface_id);
            write_u64(data, base + 16, peer_interface_id.unwrap_or(0));
            write_u64(data, base + 24, connected_for.as_secs());
            put(data, base + 32, &[*penalty_level]);
            put(data, base + 33, &[0; 7]);
            write_u64(data, base + 40, blacklist_for.as_secs());
            put(data, base + 48, &peer_ip_bytes(peer_ip));
            Ok(size)
        }
    }
}

/// Encode a hook context into a host-owned byte buffer for native hooks.
///
/// Variable packet data starts at the same offset recorded in
/// `PacketContext::data_offset`, but offsets are relative to the beginning of
/// the returned buffer instead of WASM linear memory.
#[cfg(feature = "native")]
pub(crate) fn context_to_bytes(
    ctx: &HookContext,
    data_override: Option<&[u8]>,
) -> Result<Vec<u8>, HookError> {
    match ctx {
        HookContext::Packet { ctx: pkt, raw } => {
            let raw = data_override.unwrap_or(raw);
            let header_size = std::mem::size_of::<PacketContext>();
            let mut data = vec![0u8; header_size + raw.len()];
            write_u32(&mut data, 0, CTX_TYPE_PACKET);
            put(&mut data, 4, &[pkt.flags]);
            put(&mut data, 5, &[pkt.hops]);
            put(&mut data, 8, &pkt.destination_hash);
            put(&mut data, 24, &[pkt.context]);
            put(&mut data, 28, &pkt.packet_hash);
            write_u64(&mut data, 64, pkt.interface_id);
            write_u32(&mut data, 72, header_size as u32);
            write_u32(&mut data, 76, raw.len() as u32);
            if !raw.is_empty() {
                put(&mut data, header_size, raw);
            }
            Ok(data)
        }
        HookContext::Interface { interface_id } => {
            let mut data = vec![0u8; std::mem::size_of::<InterfaceContext>()];
            write_u32(&mut data, 0, CTX_TYPE_INTERFACE);
            write_u64(&mut data, 8, *interface_id);
            Ok(data)
        }
        HookContext::Tick => {
            let mut data = vec![0u8; std::mem::size_of::<TickContext>()];
            write_u32(&mut data, 0, CTX_TYPE_TICK);
            Ok(data)
        }
        HookContext::Announce {
            destination_hash,
            hops,
            interface_id,
        } => {
            let mut data = vec![0u8; std::mem::size_of::<AnnounceContext>()];
            write_u32(&mut data, 0, CTX_TYPE_ANNOUNCE);
            put(&mut data, 4, &[*hops]);
            put(&mut data, 8, destination_hash);
            write_u64(&mut data, 24, *interface_id);
            Ok(data)
        }
        HookContext::Link {
            link_id,
            interface_id,
        } => {
            let mut data = vec![0u8; std::mem::size_of::<LinkContext>()];
            write_u32(&mut data, 0, CTX_TYPE_LINK);
            put(&mut data, 8, link_id);
            write_u64(&mut data, 24, *interface_id);
            Ok(data)
        }
        HookContext::BackbonePeer {
            server_interface_id,
            peer_interface_id,
            peer_ip,
            peer_port,
            connected_for,
            had_received_data,
            penalty_level,
            blacklist_for,
        } => {
            let mut data = vec![0u8; std::mem::size_of::<BackbonePeerContext>()];
            write_u32(&mut data, 0, CTX_TYPE_BACKBONE_PEER);
            put(&mut data, 4, &[peer_ip_family(peer_ip)]);
            write_u16(&mut data, 5, *peer_port);
            put(&mut data, 7, &[u8::from(*had_received_data)]);
            write_u64(&mut data, 8, *server_interface_id);
            write_u64(&mut data, 16, peer_interface_id.unwrap_or(0));
            write_u64(&mut data, 24, connected_for.as_secs());
            put(&mut data, 32, &[*penalty_level]);
            write_u64(&mut data, 40, blacklist_for.as_secs());
            put(&mut data, 48, &peer_ip_bytes(peer_ip));
            Ok(data)
        }
    }
}

/// Read a HookResult from WASM linear memory at the given offset.
#[cfg(feature = "wasm")]
pub(crate) fn read_result(
    memory: &wasmtime::Memory,
    store: impl wasmtime::AsContext<Data = StoreData>,
    offset: usize,
) -> Result<HookResult, HookError> {
    let size = std::mem::size_of::<HookResult>();
    let mem_size = memory.data_size(&store);
    let out_of_bounds = || {
        HookError::InvalidResult(format!(
            "result offset {} + size {} exceeds memory size {}",
            offset, size, mem_size
        ))
    };
    if offset.checked_add(size).is_none_or(|end| end > mem_size) {
        return Err(out_of_bounds());
    }
    let data = memory.data(&store);
    let word = |at: usize| read_u32(data, offset + at).ok_or_else(out_of_bounds);
    let verdict = word(0)?;
    if Verdict::from_u32(verdict).is_none() {
        return Err(HookError::InvalidResult(format!(
            "invalid verdict value: {}",
            verdict
        )));
    }
    Ok(HookResult {
        verdict,
        modified_data_offset: word(4)?,
        modified_data_len: word(8)?,
    })
}

/// Write `bytes` at `offset`. Callers check the arena against the context
/// size, or allocate the buffer at that size, before writing.
#[allow(
    clippy::indexing_slicing,
    reason = "writers check or allocate the context size first; a short buffer must panic, not leave a partial context"
)]
fn put(data: &mut [u8], offset: usize, bytes: &[u8]) {
    data[offset..offset + bytes.len()].copy_from_slice(bytes);
}

fn write_u32(data: &mut [u8], offset: usize, val: u32) {
    put(data, offset, &val.to_le_bytes());
}

fn write_u16(data: &mut [u8], offset: usize, val: u16) {
    put(data, offset, &val.to_le_bytes());
}

fn write_u64(data: &mut [u8], offset: usize, val: u64) {
    put(data, offset, &val.to_le_bytes());
}

fn peer_ip_family(ip: &std::net::IpAddr) -> u8 {
    match ip {
        std::net::IpAddr::V4(_) => 4,
        std::net::IpAddr::V6(_) => 6,
    }
}

fn peer_ip_bytes(ip: &std::net::IpAddr) -> [u8; 16] {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let mut out = [0u8; 16];
            out[..4].copy_from_slice(&v4.octets());
            out
        }
        std::net::IpAddr::V6(v6) => v6.octets(),
    }
}

#[cfg(feature = "wasm")]
fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..)?.first_chunk()?;
    Some(u32::from_le_bytes(*bytes))
}

fn read_slice(data: &[u8], offset: usize, len: usize) -> Option<Vec<u8>> {
    let end = offset.checked_add(len)?;
    data.get(offset..end).map(<[u8]>::to_vec)
}

/// Parse an ActionWire from guest linear memory at the given range.
///
/// Binary encoding:
/// - Byte 0: tag (see `wire::TAG_*` constants)
/// - Remaining bytes: variant fields, little-endian
///
/// All data referenced by offset/len pairs within the action is copied
/// from `wasm_data` (full linear memory) into owned `Vec<u8>`.
pub(crate) fn read_action_wire(
    wasm_data: &[u8],
    action_ptr: usize,
    action_len: usize,
) -> Option<crate::wire::ActionWire> {
    use crate::wire::*;
    use rns_hooks_abi::wire as tags;

    let end = action_ptr.checked_add(action_len)?;
    let (&tag, b) = wasm_data.get(action_ptr..end)?.split_first()?;
    let mut b = Fields(b);

    match tag {
        tags::TAG_SEND_ON_INTERFACE => {
            // interface: u64 (8) + data_offset: u32 (4) + data_len: u32 (4) = 16
            let interface = b.u64()?;
            let data_offset = b.u32()? as usize;
            let data_len = b.u32()? as usize;
            let raw = read_slice(wasm_data, data_offset, data_len)?;
            Some(ActionWire::SendOnInterface { interface, raw })
        }
        tags::TAG_BROADCAST => {
            // data_offset: u32 (4) + data_len: u32 (4) + exclude: u64 (8) + has_exclude: u8 (1) = 17
            let data_offset = b.u32()? as usize;
            let data_len = b.u32()? as usize;
            let exclude = b.u64()?;
            let has_exclude = b.u8()?;
            let raw = read_slice(wasm_data, data_offset, data_len)?;
            Some(ActionWire::BroadcastOnAllInterfaces {
                raw,
                exclude,
                has_exclude,
            })
        }
        tags::TAG_DELIVER_LOCAL => {
            // dest_hash: 16 + data_offset: 4 + data_len: 4 + packet_hash: 32 + receiving_interface: 8 = 64
            let destination_hash = b.array::<16>()?;
            let data_offset = b.u32()? as usize;
            let data_len = b.u32()? as usize;
            let packet_hash = b.array::<32>()?;
            let receiving_interface = b.u64()?;
            let raw = read_slice(wasm_data, data_offset, data_len)?;
            Some(ActionWire::DeliverLocal {
                destination_hash,
                raw,
                packet_hash,
                receiving_interface,
            })
        }
        tags::TAG_PATH_UPDATED => {
            // dest_hash: 16 + hops: 1 + next_hop: 16 + interface: 8 = 41
            let destination_hash = b.array::<16>()?;
            let hops = b.u8()?;
            let next_hop = b.array::<16>()?;
            let interface = b.u64()?;
            Some(ActionWire::PathUpdated {
                destination_hash,
                hops,
                next_hop,
                interface,
            })
        }
        tags::TAG_ANNOUNCE_RECEIVED => {
            // dest_hash: 16 + identity_hash: 16 + public_key: 64 + name_hash: 10 +
            // random_hash: 10 + hops: 1 + receiving_interface: 8 + has_app_data: 1 = 126 minimum
            let destination_hash = b.array::<16>()?;
            let identity_hash = b.array::<16>()?;
            let public_key = b.array::<64>()?;
            let name_hash = b.array::<10>()?;
            let random_hash = b.array::<10>()?;
            let hops = b.u8()?;
            let receiving_interface = b.u64()?;
            let has_app_data = b.u8()?;
            let app_data = if has_app_data != 0 {
                // app_data_offset: u32 (4) + app_data_len: u32 (4)
                let app_data_offset = b.u32()? as usize;
                let app_data_len = b.u32()? as usize;
                Some(read_slice(wasm_data, app_data_offset, app_data_len)?)
            } else {
                None
            };
            Some(ActionWire::AnnounceReceived {
                destination_hash,
                identity_hash,
                public_key,
                name_hash,
                random_hash,
                app_data,
                hops,
                receiving_interface,
            })
        }
        tags::TAG_FORWARD_LOCAL_CLIENTS => {
            // data_offset: u32 (4) + data_len: u32 (4) + exclude: u64 (8) + has_exclude: u8 (1) = 17
            let data_offset = b.u32()? as usize;
            let data_len = b.u32()? as usize;
            let exclude = b.u64()?;
            let has_exclude = b.u8()?;
            let raw = read_slice(wasm_data, data_offset, data_len)?;
            Some(ActionWire::ForwardToLocalClients {
                raw,
                exclude,
                has_exclude,
            })
        }
        tags::TAG_FORWARD_PLAIN_BROADCAST => {
            // data_offset: u32 (4) + data_len: u32 (4) + to_local: u8 (1) + exclude: u64 (8) + has_exclude: u8 (1) = 18
            let data_offset = b.u32()? as usize;
            let data_len = b.u32()? as usize;
            let to_local = b.u8()?;
            let exclude = b.u64()?;
            let has_exclude = b.u8()?;
            let raw = read_slice(wasm_data, data_offset, data_len)?;
            Some(ActionWire::ForwardPlainBroadcast {
                raw,
                to_local,
                exclude,
                has_exclude,
            })
        }
        tags::TAG_CACHE_ANNOUNCE => {
            // packet_hash: 32 + data_offset: 4 + data_len: 4 = 40
            let packet_hash = b.array::<32>()?;
            let data_offset = b.u32()? as usize;
            let data_len = b.u32()? as usize;
            let raw = read_slice(wasm_data, data_offset, data_len)?;
            Some(ActionWire::CacheAnnounce { packet_hash, raw })
        }
        tags::TAG_TUNNEL_SYNTHESIZE => {
            // interface: u64 (8) + data_offset: u32 (4) + data_len: u32 (4) + dest_hash: 16 = 32
            let interface = b.u64()?;
            let data_offset = b.u32()? as usize;
            let data_len = b.u32()? as usize;
            let dest_hash = b.array::<16>()?;
            let data = read_slice(wasm_data, data_offset, data_len)?;
            Some(ActionWire::TunnelSynthesize {
                interface,
                data,
                dest_hash,
            })
        }
        tags::TAG_TUNNEL_ESTABLISHED => {
            // tunnel_id: 32 + interface: 8 = 40
            let tunnel_id = b.array::<32>()?;
            let interface = b.u64()?;
            Some(ActionWire::TunnelEstablished {
                tunnel_id,
                interface,
            })
        }
        _ => None,
    }
}

/// The fields of an action, read in order; each read fails once the bytes
/// run out.
struct Fields<'a>(&'a [u8]);

impl Fields<'_> {
    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (field, rest) = self.0.split_first_chunk::<N>()?;
        self.0 = rest;
        Some(*field)
    }

    fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(u8::from_le_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_le_bytes)
    }
}

/// Read modified data bytes from WASM memory using offsets from a HookResult.
/// The offsets are relative to WASM linear memory (not arena base).
#[cfg(feature = "wasm")]
pub(crate) fn read_modified_data(
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
    data.get(offset..end).map(<[u8]>::to_vec)
}

/// Overwrite the packet data region in the arena for subsequent hooks.
/// This writes `new_data` at the data offset within the Packet arena layout,
/// and updates the `data_len` field.
#[cfg(feature = "wasm")]
pub(crate) fn write_data_override(
    memory: &wasmtime::Memory,
    mut store: impl wasmtime::AsContextMut<Data = StoreData>,
    new_data: &[u8],
) -> Result<(), HookError> {
    let header_size = std::mem::size_of::<PacketContext>();
    let data_start = ARENA_BASE + header_size;
    let mem_size = memory.data_size(&store);
    if data_start + new_data.len() > mem_size {
        return Err(HookError::InvalidResult(
            "modified data overflows arena".into(),
        ));
    }
    let mem = memory.data_mut(&mut store);
    put(mem, data_start, new_data);
    // Update data_len field (at offset 76 from ARENA_BASE)
    write_u32(mem, ARENA_BASE + 76, new_data.len() as u32);
    Ok(())
}
