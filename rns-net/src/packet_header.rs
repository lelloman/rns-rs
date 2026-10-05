//! Allocation-free fields for traffic classification, not authentication.

use rns_core::{constants, packet::PacketFlags};

pub(crate) struct PacketHeader<'a> {
    pub flags: PacketFlags,
    pub destination_hash: &'a [u8],
}

impl<'a> PacketHeader<'a> {
    /// Accept the same wire structure as `RawPacket::unpack`, without owning
    /// payload bytes or computing a packet hash. Consumers must still perform
    /// normal packet validation and authentication before processing traffic.
    pub fn unpack(raw: &'a [u8]) -> Option<Self> {
        if raw.len() < constants::HEADER_MINSIZE || raw[1] >= constants::PATHFINDER_M {
            return None;
        }
        let flags = PacketFlags::unpack(raw[0]);
        let destination_start = match flags.header_type {
            constants::HEADER_1 => 2,
            constants::HEADER_2 => 2 + constants::TRUNCATED_HASHLENGTH / 8,
            _ => return None,
        };
        let destination_end = destination_start + constants::TRUNCATED_HASHLENGTH / 8;
        // A context byte and at least one payload byte must follow the address.
        if raw.len() <= destination_end + 1 {
            return None;
        }
        Some(Self {
            flags,
            destination_hash: &raw[destination_start..destination_end],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_core::packet::RawPacket;

    #[test]
    fn header_matches_full_unpack_at_wire_boundaries() {
        // Include the IFAC bit: the full unpacker masks it out, leaving its
        // enforcement to the interface. Classification must preserve that.
        for flags in 0..=u8::MAX {
            for hops in [
                0,
                1,
                constants::PATHFINDER_M - 1,
                constants::PATHFINDER_M,
                255,
            ] {
                let mut raw: Vec<u8> = (0..80).collect();
                raw[0] = flags;
                raw[1] = hops;
                for len in (0..=40).chain([80]) {
                    let full = RawPacket::unpack(&raw[..len]);
                    let header = PacketHeader::unpack(&raw[..len]);
                    assert_eq!(
                        header.is_some(),
                        full.is_ok(),
                        "flags={flags} hops={hops} len={len}"
                    );
                    if let (Some(header), Ok(full)) = (header, full) {
                        assert_eq!(header.flags, full.flags);
                        assert_eq!(header.destination_hash, full.destination_hash);
                    }
                }
            }
        }
    }
}
