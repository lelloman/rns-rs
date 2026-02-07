use alloc::vec::Vec;
use core::fmt;

use crate::constants;
use crate::hash;

#[derive(Debug)]
pub enum PacketError {
    TooShort,
    ExceedsMtu,
    MissingTransportId,
    InvalidHeaderType,
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketError::TooShort => write!(f, "Packet too short"),
            PacketError::ExceedsMtu => write!(f, "Packet exceeds MTU"),
            PacketError::MissingTransportId => write!(f, "HEADER_2 requires transport_id"),
            PacketError::InvalidHeaderType => write!(f, "Invalid header type"),
        }
    }
}

// =============================================================================
// PacketFlags: packs 5 fields into one byte
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketFlags {
    pub header_type: u8,
    pub context_flag: u8,
    pub transport_type: u8,
    pub destination_type: u8,
    pub packet_type: u8,
}

impl PacketFlags {
    /// Pack fields into a single flags byte.
    ///
    /// Bit layout:
    /// ```text
    /// Bit 6:     header_type (1 bit)
    /// Bit 5:     context_flag (1 bit)
    /// Bit 4:     transport_type (1 bit)
    /// Bits 3-2:  destination_type (2 bits)
    /// Bits 1-0:  packet_type (2 bits)
    /// ```
    pub fn pack(&self) -> u8 {
        (self.header_type << 6)
            | (self.context_flag << 5)
            | (self.transport_type << 4)
            | (self.destination_type << 2)
            | self.packet_type
    }

    /// Unpack a flags byte into fields.
    pub fn unpack(byte: u8) -> Self {
        PacketFlags {
            header_type: (byte & 0b01000000) >> 6,
            context_flag: (byte & 0b00100000) >> 5,
            transport_type: (byte & 0b00010000) >> 4,
            destination_type: (byte & 0b00001100) >> 2,
            packet_type: byte & 0b00000011,
        }
    }
}

// =============================================================================
// RawPacket: wire-level packet representation
// =============================================================================

#[derive(Debug, Clone)]
pub struct RawPacket {
    pub flags: PacketFlags,
    pub hops: u8,
    pub transport_id: Option<[u8; 16]>,
    pub destination_hash: [u8; 16],
    pub context: u8,
    pub data: Vec<u8>,
    pub raw: Vec<u8>,
    pub packet_hash: [u8; 32],
}

impl RawPacket {
    /// Pack fields into raw bytes.
    pub fn pack(
        flags: PacketFlags,
        hops: u8,
        destination_hash: &[u8; 16],
        transport_id: Option<&[u8; 16]>,
        context: u8,
        data: &[u8],
    ) -> Result<Self, PacketError> {
        if flags.header_type == constants::HEADER_2 && transport_id.is_none() {
            return Err(PacketError::MissingTransportId);
        }

        let mut raw = Vec::new();
        raw.push(flags.pack());
        raw.push(hops);

        if flags.header_type == constants::HEADER_2 {
            raw.extend_from_slice(transport_id.unwrap());
        }

        raw.extend_from_slice(destination_hash);
        raw.push(context);
        raw.extend_from_slice(data);

        if raw.len() > constants::MTU {
            return Err(PacketError::ExceedsMtu);
        }

        let packet_hash = hash::full_hash(&Self::compute_hashable_part(
            flags.header_type,
            &raw,
        ));

        Ok(RawPacket {
            flags,
            hops,
            transport_id: transport_id.copied(),
            destination_hash: *destination_hash,
            context,
            data: data.to_vec(),
            raw,
            packet_hash,
        })
    }

    /// Unpack raw bytes into fields.
    pub fn unpack(raw: &[u8]) -> Result<Self, PacketError> {
        if raw.len() < constants::HEADER_MINSIZE {
            return Err(PacketError::TooShort);
        }

        let flags = PacketFlags::unpack(raw[0]);
        let hops = raw[1];

        let dst_len = constants::TRUNCATED_HASHLENGTH / 8; // 16

        if flags.header_type == constants::HEADER_2 {
            // HEADER_2: [flags:1][hops:1][transport_id:16][dest_hash:16][context:1][data:*]
            let min_len = 2 + dst_len * 2 + 1;
            if raw.len() < min_len {
                return Err(PacketError::TooShort);
            }

            let mut transport_id = [0u8; 16];
            transport_id.copy_from_slice(&raw[2..2 + dst_len]);

            let mut destination_hash = [0u8; 16];
            destination_hash.copy_from_slice(&raw[2 + dst_len..2 + 2 * dst_len]);

            let context = raw[2 + 2 * dst_len];
            let data = raw[2 + 2 * dst_len + 1..].to_vec();

            let packet_hash = hash::full_hash(&Self::compute_hashable_part(
                flags.header_type,
                raw,
            ));

            Ok(RawPacket {
                flags,
                hops,
                transport_id: Some(transport_id),
                destination_hash,
                context,
                data,
                raw: raw.to_vec(),
                packet_hash,
            })
        } else if flags.header_type == constants::HEADER_1 {
            // HEADER_1: [flags:1][hops:1][dest_hash:16][context:1][data:*]
            let min_len = 2 + dst_len + 1;
            if raw.len() < min_len {
                return Err(PacketError::TooShort);
            }

            let mut destination_hash = [0u8; 16];
            destination_hash.copy_from_slice(&raw[2..2 + dst_len]);

            let context = raw[2 + dst_len];
            let data = raw[2 + dst_len + 1..].to_vec();

            let packet_hash = hash::full_hash(&Self::compute_hashable_part(
                flags.header_type,
                raw,
            ));

            Ok(RawPacket {
                flags,
                hops,
                transport_id: None,
                destination_hash,
                context,
                data,
                raw: raw.to_vec(),
                packet_hash,
            })
        } else {
            Err(PacketError::InvalidHeaderType)
        }
    }

    /// Get the hashable part of the packet.
    ///
    /// From Python Packet.py:354-361:
    /// - Take raw[0] & 0x0F (mask out upper 4 bits of flags)
    /// - For HEADER_1: append raw[2:]
    /// - For HEADER_2: skip transport_id: append raw[18:]
    pub fn get_hashable_part(&self) -> Vec<u8> {
        Self::compute_hashable_part(self.flags.header_type, &self.raw)
    }

    fn compute_hashable_part(header_type: u8, raw: &[u8]) -> Vec<u8> {
        let mut hashable = Vec::new();
        hashable.push(raw[0] & 0b00001111);
        if header_type == constants::HEADER_2 {
            // Skip transport_id: raw[2..18] is transport_id (16 bytes)
            hashable.extend_from_slice(&raw[(constants::TRUNCATED_HASHLENGTH / 8 + 2)..]);
        } else {
            hashable.extend_from_slice(&raw[2..]);
        }
        hashable
    }

    /// Full SHA-256 hash of the hashable part.
    pub fn get_hash(&self) -> [u8; 32] {
        self.packet_hash
    }

    /// Truncated hash (first 16 bytes) of the hashable part.
    pub fn get_truncated_hash(&self) -> [u8; 16] {
        let mut result = [0u8; 16];
        result.copy_from_slice(&self.packet_hash[..16]);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flags_pack_header1_data_single_broadcast() {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        assert_eq!(flags.pack(), 0x00);
    }

    #[test]
    fn test_flags_pack_header2_announce_single_transport() {
        let flags = PacketFlags {
            header_type: constants::HEADER_2,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_TRANSPORT,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        };
        // 0b01010001 = 0x51
        assert_eq!(flags.pack(), 0x51);
    }

    #[test]
    fn test_flags_roundtrip() {
        for byte in 0..=0x7Fu8 {
            let flags = PacketFlags::unpack(byte);
            assert_eq!(flags.pack(), byte);
        }
    }

    #[test]
    fn test_pack_header1() {
        let dest_hash = [0xAA; 16];
        let data = b"hello";
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };

        let pkt = RawPacket::pack(flags, 0, &dest_hash, None, constants::CONTEXT_NONE, data).unwrap();

        // Verify layout: [flags:1][hops:1][dest:16][context:1][data:5] = 24 bytes
        assert_eq!(pkt.raw.len(), 24);
        assert_eq!(pkt.raw[0], 0x00); // flags
        assert_eq!(pkt.raw[1], 0x00); // hops
        assert_eq!(&pkt.raw[2..18], &dest_hash); // dest hash
        assert_eq!(pkt.raw[18], 0x00); // context
        assert_eq!(&pkt.raw[19..], b"hello"); // data
    }

    #[test]
    fn test_pack_header2() {
        let dest_hash = [0xAA; 16];
        let transport_id = [0xBB; 16];
        let data = b"world";
        let flags = PacketFlags {
            header_type: constants::HEADER_2,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_TRANSPORT,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        };

        let pkt = RawPacket::pack(flags, 3, &dest_hash, Some(&transport_id), constants::CONTEXT_NONE, data).unwrap();

        // Layout: [flags:1][hops:1][transport:16][dest:16][context:1][data:5] = 40 bytes
        assert_eq!(pkt.raw.len(), 40);
        assert_eq!(pkt.raw[0], flags.pack());
        assert_eq!(pkt.raw[1], 3);
        assert_eq!(&pkt.raw[2..18], &transport_id);
        assert_eq!(&pkt.raw[18..34], &dest_hash);
        assert_eq!(pkt.raw[34], 0x00);
        assert_eq!(&pkt.raw[35..], b"world");
    }

    #[test]
    fn test_unpack_roundtrip_header1() {
        let dest_hash = [0x11; 16];
        let data = b"test data";
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };

        let pkt = RawPacket::pack(flags, 5, &dest_hash, None, constants::CONTEXT_RESOURCE, data).unwrap();
        let unpacked = RawPacket::unpack(&pkt.raw).unwrap();

        assert_eq!(unpacked.flags, flags);
        assert_eq!(unpacked.hops, 5);
        assert!(unpacked.transport_id.is_none());
        assert_eq!(unpacked.destination_hash, dest_hash);
        assert_eq!(unpacked.context, constants::CONTEXT_RESOURCE);
        assert_eq!(unpacked.data, data);
        assert_eq!(unpacked.packet_hash, pkt.packet_hash);
    }

    #[test]
    fn test_unpack_roundtrip_header2() {
        let dest_hash = [0x22; 16];
        let transport_id = [0x33; 16];
        let data = b"transported";
        let flags = PacketFlags {
            header_type: constants::HEADER_2,
            context_flag: constants::FLAG_SET,
            transport_type: constants::TRANSPORT_TRANSPORT,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        };

        let pkt = RawPacket::pack(flags, 2, &dest_hash, Some(&transport_id), constants::CONTEXT_NONE, data).unwrap();
        let unpacked = RawPacket::unpack(&pkt.raw).unwrap();

        assert_eq!(unpacked.flags, flags);
        assert_eq!(unpacked.hops, 2);
        assert_eq!(unpacked.transport_id.unwrap(), transport_id);
        assert_eq!(unpacked.destination_hash, dest_hash);
        assert_eq!(unpacked.context, constants::CONTEXT_NONE);
        assert_eq!(unpacked.data, data);
        assert_eq!(unpacked.packet_hash, pkt.packet_hash);
    }

    #[test]
    fn test_unpack_too_short() {
        assert!(RawPacket::unpack(&[0x00; 5]).is_err());
    }

    #[test]
    fn test_pack_exceeds_mtu() {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let data = [0u8; 500]; // way too much data
        let result = RawPacket::pack(flags, 0, &[0; 16], None, 0, &data);
        assert!(result.is_err());
    }

    #[test]
    fn test_header2_missing_transport_id() {
        let flags = PacketFlags {
            header_type: constants::HEADER_2,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_TRANSPORT,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        };
        let result = RawPacket::pack(flags, 0, &[0; 16], None, 0, b"data");
        assert!(result.is_err());
    }

    #[test]
    fn test_hashable_part_header1_masks_upper_flags() {
        let dest_hash = [0xCC; 16];
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_SET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };

        let pkt = RawPacket::pack(flags, 0, &dest_hash, None, constants::CONTEXT_NONE, b"test").unwrap();
        let hashable = pkt.get_hashable_part();

        // First byte should have upper 4 bits masked out
        assert_eq!(hashable[0], pkt.raw[0] & 0x0F);
        // Rest should be raw[2:]
        assert_eq!(&hashable[1..], &pkt.raw[2..]);
    }

    #[test]
    fn test_hashable_part_header2_strips_transport_id() {
        let dest_hash = [0xDD; 16];
        let transport_id = [0xEE; 16];
        let flags = PacketFlags {
            header_type: constants::HEADER_2,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_TRANSPORT,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        };

        let pkt = RawPacket::pack(flags, 0, &dest_hash, Some(&transport_id), constants::CONTEXT_NONE, b"data").unwrap();
        let hashable = pkt.get_hashable_part();

        // First byte: flags masked
        assert_eq!(hashable[0], pkt.raw[0] & 0x0F);
        // Should skip transport_id: raw[18:] = dest_hash + context + data
        assert_eq!(&hashable[1..], &pkt.raw[18..]);
    }
}
