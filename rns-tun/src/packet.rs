use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::policy::{is_forbidden_special, Cidr};
use crate::protocol::{PacketFragment, FRAGMENT_MAX, PACKET_MAX};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    TooShort,
    WrongVersion,
    OptionsUnsupported,
    InvalidLength,
    TooLarge,
    InvalidChecksum,
    NativeFragment,
    InvalidAddress,
    InvalidTtl,
    InvalidFragment,
    Overlap,
    ReassemblyLimit,
}
impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid IPv4 packet: {self:?}")
    }
}
impl std::error::Error for PacketError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedIpv4 {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol: u8,
    pub total_len: u16,
}

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

pub struct Reassembler {
    entries: HashMap<(u64, u64), PartialPacket>,
    max_entries: usize,
    max_bytes: usize,
    used_bytes: usize,
    expiry: Duration,
}
impl Reassembler {
    pub fn new(max_entries: usize, max_bytes: usize, expiry: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            max_bytes,
            used_bytes: 0,
            expiry,
        }
    }
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
        if !self.entries.contains_key(&key) {
            if self.entries.len() >= self.max_entries || self.used_bytes + total > self.max_bytes {
                return Err(PacketError::ReassemblyLimit);
            }
            self.entries.insert(
                key,
                PartialPacket {
                    total,
                    bytes: vec![0; total],
                    received: vec![false; total],
                    received_count: 0,
                    fragments: 0,
                    updated: now,
                },
            );
            self.used_bytes += total;
        }
        let entry = self.entries.get_mut(&key).unwrap();
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
            let entry = self.entries.remove(&key).unwrap();
            self.used_bytes -= entry.total;
            Ok(Some(entry.bytes))
        } else {
            Ok(None)
        }
    }
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
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn used_bytes(&self) -> usize {
        self.used_bytes
    }
}

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
