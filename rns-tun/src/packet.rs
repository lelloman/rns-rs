//! IPv4 packet validation and the fragmentation and reassembly of packets
//! into rntun fragments.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::policy::{is_forbidden_special, Cidr};
use crate::protocol::{PacketFragment, FRAGMENT_MAX, PACKET_MAX};

/// Why a packet or fragment was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    /// Shorter than a 20-byte IPv4 header.
    TooShort,
    /// The version field is not 4.
    WrongVersion,
    /// The header carries IP options (IHL is not 5).
    OptionsUnsupported,
    /// The total-length field disagrees with the buffer length.
    InvalidLength,
    /// Larger than the negotiated MTU or the protocol maximum.
    TooLarge,
    /// The header checksum does not verify.
    InvalidChecksum,
    /// An IP fragment (MF set, nonzero offset, or the reserved bit set);
    /// only whole packets are tunnelled.
    NativeFragment,
    /// The source or destination is a special-use address, or is not one
    /// the session may use.
    InvalidAddress,
    /// The TTL is zero.
    InvalidTtl,
    /// A fragment with impossible bounds, or one that disagrees with earlier
    /// fragments of the same packet on the total length.
    InvalidFragment,
    /// A fragment rewrites bytes already received with different contents,
    /// or partly overlaps received bytes.
    Overlap,
    /// Reassembly is out of slots or memory, or the packet needs more
    /// fragments than the protocol allows.
    ReassemblyLimit,
}
impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid IPv4 packet: {self:?}")
    }
}
impl std::error::Error for PacketError {}

/// Header fields of a packet that passed [`validate_ipv4`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedIpv4 {
    /// Source address.
    pub source: Ipv4Addr,
    /// Destination address.
    pub destination: Ipv4Addr,
    /// IP protocol number (1 ICMP, 6 TCP, 17 UDP, ...).
    pub protocol: u8,
    /// Packet length in bytes, header included.
    pub total_len: u16,
}

/// Check that `packet` is a single, whole IPv4 packet without options that
/// fits in `negotiated_mtu` bytes, with a valid header checksum, a nonzero
/// TTL and no special-use (zero, loopback, link-local, multicast or
/// reserved) source or destination.
pub fn validate_ipv4(packet: &[u8], negotiated_mtu: usize) -> Result<ValidatedIpv4, PacketError> {
    if packet.len() < 20 {
        return Err(PacketError::TooShort);
    }
    if packet[0] >> 4 != 4 {
        return Err(PacketError::WrongVersion);
    }
    if packet[0] & 0x0f != 5 {
        return Err(PacketError::OptionsUnsupported);
    }
    let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total != packet.len() || total < 20 {
        return Err(PacketError::InvalidLength);
    }
    if total > negotiated_mtu || total > PACKET_MAX {
        return Err(PacketError::TooLarge);
    }
    if checksum(&packet[..20]) != 0 {
        return Err(PacketError::InvalidChecksum);
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x8000 != 0 || fragment & 0x3fff != 0 {
        return Err(PacketError::NativeFragment);
    }
    if packet[8] == 0 {
        return Err(PacketError::InvalidTtl);
    }
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    if is_forbidden_special(source) || is_forbidden_special(destination) {
        return Err(PacketError::InvalidAddress);
    }
    Ok(ValidatedIpv4 {
        source,
        destination,
        protocol: packet[9],
        total_len: total as u16,
    })
}

/// The Internet checksum (RFC 1071) of `header`. Over a header that already
/// holds its checksum, a valid one gives 0.
pub fn checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in header.chunks(2) {
        let word = if pair.len() == 2 {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            (pair[0] as u16) << 8
        };
        sum += word as u32;
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    !(sum as u16)
}

/// Whether `packet` is an ICMP error (destination unreachable, time
/// exceeded or parameter problem) sent to the client at `assigned` about a
/// packet that client sent into one of its `accepted` routes, judged by the
/// quoted header.
pub fn valid_icmp_error_exception(packet: &[u8], assigned: Ipv4Addr, accepted: &[Cidr]) -> bool {
    let Ok(outer) = validate_ipv4(packet, PACKET_MAX) else {
        return false;
    };
    if outer.protocol != 1 || outer.destination != assigned || packet.len() < 48 {
        return false;
    }
    if !matches!(packet[20], 3 | 11 | 12) {
        return false;
    }
    let quoted = &packet[28..];
    if quoted.len() < 20 || quoted[0] != 0x45 || checksum(&quoted[..20]) != 0 {
        return false;
    }
    let source = Ipv4Addr::new(quoted[12], quoted[13], quoted[14], quoted[15]);
    let destination = Ipv4Addr::new(quoted[16], quoted[17], quoted[18], quoted[19]);
    source == assigned && accepted.iter().any(|route| route.contains(destination))
}

struct PartialPacket {
    total: usize,
    bytes: Vec<u8>,
    received: Vec<bool>,
    received_count: usize,
    fragments: usize,
    updated: Duration,
}

/// Rebuilds packets from [`PacketFragment`]s, keyed by session epoch and
/// packet id, within fixed limits on pending packets and buffered bytes.
pub struct Reassembler {
    entries: HashMap<(u64, u64), PartialPacket>,
    max_entries: usize,
    max_bytes: usize,
    used_bytes: usize,
    expiry: Duration,
}
impl Reassembler {
    /// A reassembler holding at most `max_entries` incomplete packets and
    /// `max_bytes` of their buffers. An incomplete packet that receives no
    /// fragment for longer than `expiry` is dropped.
    pub fn new(max_entries: usize, max_bytes: usize, expiry: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            max_bytes,
            used_bytes: 0,
            expiry,
        }
    }
    /// Add a fragment. `now` is the caller's monotonic clock, the same one
    /// for every call; expired entries are dropped first. Returns the whole
    /// packet once its last byte has arrived, `None` while it is incomplete
    /// or when the fragment is an exact duplicate. An error leaves the
    /// already buffered fragments in place.
    pub fn push(
        &mut self,
        fragment: PacketFragment,
        now: Duration,
    ) -> Result<Option<Vec<u8>>, PacketError> {
        self.expire(now);
        let key = (fragment.session_epoch, fragment.packet_id);
        let total = fragment.total_len as usize;
        let start = fragment.offset as usize;
        let end = start + fragment.payload.len();
        if total == 0 || total > PACKET_MAX || end > total || fragment.payload.is_empty() {
            return Err(PacketError::InvalidFragment);
        }
        let full =
            self.entries.len() >= self.max_entries || self.used_bytes + total > self.max_bytes;
        let entry = match self.entries.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(_) if full => return Err(PacketError::ReassemblyLimit),
            Entry::Vacant(entry) => {
                self.used_bytes += total;
                entry.insert(PartialPacket {
                    total,
                    bytes: vec![0; total],
                    received: vec![false; total],
                    received_count: 0,
                    fragments: 0,
                    updated: now,
                })
            }
        };
        if entry.total != total {
            return Err(PacketError::InvalidFragment);
        }
        if entry.fragments >= FRAGMENT_MAX {
            return Err(PacketError::ReassemblyLimit);
        }
        let mut all_duplicate = true;
        for (index, value) in fragment.payload.iter().enumerate() {
            let at = start + index;
            if entry.received[at] {
                if entry.bytes[at] != *value {
                    return Err(PacketError::Overlap);
                }
            } else {
                all_duplicate = false;
            }
        }
        if all_duplicate {
            entry.updated = now;
            return Ok(None);
        }
        if (start..end).any(|at| entry.received[at]) {
            return Err(PacketError::Overlap);
        }
        entry.bytes[start..end].copy_from_slice(&fragment.payload);
        for bit in &mut entry.received[start..end] {
            *bit = true;
        }
        entry.received_count += fragment.payload.len();
        entry.fragments += 1;
        entry.updated = now;
        if entry.received_count == entry.total {
            let bytes = std::mem::take(&mut entry.bytes);
            self.entries.remove(&key);
            self.used_bytes -= total;
            Ok(Some(bytes))
        } else {
            Ok(None)
        }
    }
    /// Drop incomplete packets idle for longer than the expiry and return
    /// how many were dropped.
    pub fn expire(&mut self, now: Duration) -> usize {
        let before = self.entries.len();
        let expiry = self.expiry;
        let mut removed = 0;
        self.entries.retain(|_, v| {
            let keep = now.saturating_sub(v.updated) <= expiry;
            if !keep {
                self.used_bytes -= v.total;
                removed += 1;
            }
            keep
        });
        debug_assert_eq!(before - self.entries.len(), removed);
        removed
    }
    /// Number of incomplete packets held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Whether no incomplete packet is held.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Bytes reserved by incomplete packets (their full lengths).
    pub fn used_bytes(&self) -> usize {
        self.used_bytes
    }
}

/// Split `packet` into fragments carrying at most `max_payload` bytes each,
/// all tagged with `epoch` and `packet_id`. Fails on an empty or oversized
/// packet, a zero `max_payload`, or when more fragments than the protocol
/// allows would be needed.
pub fn fragment_packet(
    packet: &[u8],
    epoch: u64,
    packet_id: u64,
    max_payload: usize,
) -> Result<Vec<PacketFragment>, PacketError> {
    if packet.is_empty() || packet.len() > PACKET_MAX || max_payload == 0 {
        return Err(PacketError::InvalidFragment);
    }
    let count = packet.len().div_ceil(max_payload);
    if count > FRAGMENT_MAX {
        return Err(PacketError::ReassemblyLimit);
    }
    Ok(packet
        .chunks(max_payload)
        .enumerate()
        .map(|(i, p)| PacketFragment {
            session_epoch: epoch,
            packet_id,
            total_len: packet.len() as u16,
            offset: (i * max_payload) as u16,
            payload: p.to_vec(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet() -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(20u16).to_be_bytes());
        p[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let c = checksum(&p);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        p
    }
    #[test]
    fn validates_plain_ipv4() {
        assert!(validate_ipv4(&packet(), 1280).is_ok());
    }
    #[test]
    fn rejects_options_and_native_fragments() {
        let mut p = packet();
        p[0] = 0x46;
        assert_eq!(
            validate_ipv4(&p, 1280),
            Err(PacketError::OptionsUnsupported)
        );
        let mut p = packet();
        p[6] = 0x20;
        p[10..12].fill(0);
        let c = checksum(&p[..20]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        assert_eq!(validate_ipv4(&p, 1280), Err(PacketError::NativeFragment));
    }
    #[test]
    fn reassembles_out_of_order() {
        let fs = fragment_packet(&packet(), 1, 2, 7).unwrap();
        let mut r = Reassembler::new(8, 12000, Duration::from_secs(10));
        let mut out = None;
        for f in fs.into_iter().rev() {
            if let Some(p) = r.push(f, Duration::ZERO).unwrap() {
                out = Some(p)
            }
        }
        assert_eq!(out.unwrap(), packet());
    }
}
