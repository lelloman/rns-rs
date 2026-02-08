use alloc::vec::Vec;

use crate::msgpack::{self, Value};
use crate::constants::{RESOURCE_HASHMAP_MAX_LEN, RESOURCE_MAPHASH_LEN};
use super::types::{AdvFlags, ResourceError};

/// Resource advertisement data, corresponding to Python's ResourceAdvertisement.
#[derive(Debug, Clone)]
pub struct ResourceAdvertisement {
    /// Transfer size (encrypted data size)
    pub transfer_size: u64,
    /// Total uncompressed data size (including metadata overhead)
    pub data_size: u64,
    /// Number of parts
    pub num_parts: u64,
    /// Resource hash (full 32 bytes)
    pub resource_hash: Vec<u8>,
    /// Random hash (4 bytes)
    pub random_hash: Vec<u8>,
    /// Original hash (first segment, 32 bytes)
    pub original_hash: Vec<u8>,
    /// Hashmap segment (concatenated 4-byte part hashes)
    pub hashmap: Vec<u8>,
    /// Flags byte
    pub flags: AdvFlags,
    /// Segment index (1-based)
    pub segment_index: u64,
    /// Total segments
    pub total_segments: u64,
    /// Request ID (optional)
    pub request_id: Option<Vec<u8>>,
}

impl ResourceAdvertisement {
    /// Pack the advertisement to msgpack bytes.
    /// `segment` controls which hashmap segment to include (0-based).
    pub fn pack(&self, segment: usize) -> Vec<u8> {
        let hashmap_start = segment * RESOURCE_HASHMAP_MAX_LEN * RESOURCE_MAPHASH_LEN;
        let max_end = (segment + 1) * RESOURCE_HASHMAP_MAX_LEN * RESOURCE_MAPHASH_LEN;
        let hashmap_end = core::cmp::min(max_end, self.hashmap.len());
        let hashmap_segment = if hashmap_start < self.hashmap.len() {
            &self.hashmap[hashmap_start..hashmap_end]
        } else {
            &[]
        };

        let q_value = match &self.request_id {
            Some(id) => Value::Bin(id.clone()),
            None => Value::Nil,
        };

        // Match Python's key order: t, d, n, h, r, o, i, l, q, f, m
        let entries: Vec<(&str, Value)> = vec![
            ("t", Value::UInt(self.transfer_size)),
            ("d", Value::UInt(self.data_size)),
            ("n", Value::UInt(self.num_parts)),
            ("h", Value::Bin(self.resource_hash.clone())),
            ("r", Value::Bin(self.random_hash.clone())),
            ("o", Value::Bin(self.original_hash.clone())),
            ("i", Value::UInt(self.segment_index)),
            ("l", Value::UInt(self.total_segments)),
            ("q", q_value),
            ("f", Value::UInt(self.flags.to_byte() as u64)),
            ("m", Value::Bin(hashmap_segment.to_vec())),
        ];

        msgpack::pack_str_map(&entries)
    }

    /// Unpack an advertisement from msgpack bytes.
    pub fn unpack(data: &[u8]) -> Result<Self, ResourceError> {
        let value = msgpack::unpack_exact(data).map_err(|_| ResourceError::InvalidAdvertisement)?;

        let t = value.map_get("t")
            .and_then(|v| v.as_uint())
            .ok_or(ResourceError::InvalidAdvertisement)?;
        let d = value.map_get("d")
            .and_then(|v| v.as_uint())
            .ok_or(ResourceError::InvalidAdvertisement)?;
        let n = value.map_get("n")
            .and_then(|v| v.as_uint())
            .ok_or(ResourceError::InvalidAdvertisement)?;
        let h = value.map_get("h")
            .and_then(|v| v.as_bin())
            .ok_or(ResourceError::InvalidAdvertisement)?
            .to_vec();
        let r = value.map_get("r")
            .and_then(|v| v.as_bin())
            .ok_or(ResourceError::InvalidAdvertisement)?
            .to_vec();
        let o = value.map_get("o")
            .and_then(|v| v.as_bin())
            .ok_or(ResourceError::InvalidAdvertisement)?
            .to_vec();
        let m = value.map_get("m")
            .and_then(|v| v.as_bin())
            .ok_or(ResourceError::InvalidAdvertisement)?
            .to_vec();
        let f = value.map_get("f")
            .and_then(|v| v.as_uint())
            .ok_or(ResourceError::InvalidAdvertisement)? as u8;
        let i = value.map_get("i")
            .and_then(|v| v.as_uint())
            .ok_or(ResourceError::InvalidAdvertisement)?;
        let l = value.map_get("l")
            .and_then(|v| v.as_uint())
            .ok_or(ResourceError::InvalidAdvertisement)?;

        let q_val = value.map_get("q").ok_or(ResourceError::InvalidAdvertisement)?;
        let request_id = if q_val.is_nil() {
            None
        } else {
            Some(q_val.as_bin().ok_or(ResourceError::InvalidAdvertisement)?.to_vec())
        };

        Ok(ResourceAdvertisement {
            transfer_size: t,
            data_size: d,
            num_parts: n,
            resource_hash: h,
            random_hash: r,
            original_hash: o,
            hashmap: m,
            flags: AdvFlags::from_byte(f),
            segment_index: i,
            total_segments: l,
            request_id,
        })
    }

    /// Check if this advertisement is a request.
    pub fn is_request(&self) -> bool {
        self.request_id.is_some() && self.flags.is_request
    }

    /// Check if this advertisement is a response.
    pub fn is_response(&self) -> bool {
        self.request_id.is_some() && self.flags.is_response
    }

    /// Get the number of hashmap segments needed.
    pub fn hashmap_segments(&self) -> usize {
        let total_hashes = self.num_parts as usize;
        if total_hashes == 0 {
            return 1;
        }
        (total_hashes + RESOURCE_HASHMAP_MAX_LEN - 1) / RESOURCE_HASHMAP_MAX_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_adv(flags: AdvFlags) -> ResourceAdvertisement {
        ResourceAdvertisement {
            transfer_size: 1000,
            data_size: 950,
            num_parts: 3,
            resource_hash: vec![0x11; 32],
            random_hash: vec![0xAA, 0xBB, 0xCC, 0xDD],
            original_hash: vec![0x22; 32],
            hashmap: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C],
            flags,
            segment_index: 1,
            total_segments: 1,
            request_id: None,
        }
    }

    #[test]
    fn test_pack_unpack_roundtrip() {
        let flags = AdvFlags {
            encrypted: true,
            compressed: false,
            split: false,
            is_request: false,
            is_response: false,
            has_metadata: false,
        };
        let adv = make_adv(flags);
        let packed = adv.pack(0);
        let unpacked = ResourceAdvertisement::unpack(&packed).unwrap();

        assert_eq!(unpacked.transfer_size, 1000);
        assert_eq!(unpacked.data_size, 950);
        assert_eq!(unpacked.num_parts, 3);
        assert_eq!(unpacked.resource_hash, vec![0x11; 32]);
        assert_eq!(unpacked.random_hash, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(unpacked.original_hash, vec![0x22; 32]);
        assert_eq!(unpacked.flags, flags);
        assert_eq!(unpacked.segment_index, 1);
        assert_eq!(unpacked.total_segments, 1);
        assert!(unpacked.request_id.is_none());
    }

    #[test]
    fn test_flags_encrypted_compressed() {
        let flags = AdvFlags {
            encrypted: true,
            compressed: true,
            split: false,
            is_request: false,
            is_response: false,
            has_metadata: false,
        };
        let adv = make_adv(flags);
        let packed = adv.pack(0);
        let unpacked = ResourceAdvertisement::unpack(&packed).unwrap();
        assert!(unpacked.flags.encrypted);
        assert!(unpacked.flags.compressed);
        assert!(!unpacked.flags.split);
    }

    #[test]
    fn test_flags_with_metadata() {
        let flags = AdvFlags {
            encrypted: true,
            compressed: false,
            split: false,
            is_request: false,
            is_response: false,
            has_metadata: true,
        };
        let adv = make_adv(flags);
        let packed = adv.pack(0);
        let unpacked = ResourceAdvertisement::unpack(&packed).unwrap();
        assert!(unpacked.flags.has_metadata);
    }

    #[test]
    fn test_multi_segment() {
        let flags = AdvFlags {
            encrypted: true,
            compressed: false,
            split: true,
            is_request: false,
            is_response: false,
            has_metadata: false,
        };
        let mut adv = make_adv(flags);
        adv.segment_index = 2;
        adv.total_segments = 5;
        let packed = adv.pack(0);
        let unpacked = ResourceAdvertisement::unpack(&packed).unwrap();
        assert!(unpacked.flags.split);
        assert_eq!(unpacked.segment_index, 2);
        assert_eq!(unpacked.total_segments, 5);
    }

    #[test]
    fn test_with_request_id() {
        let flags = AdvFlags {
            encrypted: true,
            compressed: false,
            split: false,
            is_request: true,
            is_response: false,
            has_metadata: false,
        };
        let mut adv = make_adv(flags);
        adv.request_id = Some(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let packed = adv.pack(0);
        let unpacked = ResourceAdvertisement::unpack(&packed).unwrap();
        assert!(unpacked.is_request());
        assert!(!unpacked.is_response());
        assert_eq!(unpacked.request_id, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn test_is_response() {
        let flags = AdvFlags {
            encrypted: true,
            compressed: false,
            split: false,
            is_request: false,
            is_response: true,
            has_metadata: false,
        };
        let mut adv = make_adv(flags);
        adv.request_id = Some(vec![0x42; 16]);
        assert!(adv.is_response());
        assert!(!adv.is_request());
    }

    #[test]
    fn test_nil_request_id() {
        let flags = AdvFlags {
            encrypted: true,
            compressed: false,
            split: false,
            is_request: false,
            is_response: false,
            has_metadata: false,
        };
        let adv = make_adv(flags);
        let packed = adv.pack(0);
        let unpacked = ResourceAdvertisement::unpack(&packed).unwrap();
        assert!(unpacked.request_id.is_none());
        assert!(!unpacked.is_request());
        assert!(!unpacked.is_response());
    }

    #[test]
    fn test_hashmap_segmentation() {
        // Create a large hashmap with > HASHMAP_MAX_LEN(74) hashes
        let num_hashes = 100;
        let hashmap: Vec<u8> = (0..num_hashes).flat_map(|i| vec![i as u8; 4]).collect();

        let flags = AdvFlags {
            encrypted: true,
            compressed: false,
            split: false,
            is_request: false,
            is_response: false,
            has_metadata: false,
        };
        let adv = ResourceAdvertisement {
            transfer_size: 50000,
            data_size: 48000,
            num_parts: num_hashes,
            resource_hash: vec![0x11; 32],
            random_hash: vec![0xAA; 4],
            original_hash: vec![0x22; 32],
            hashmap: hashmap.clone(),
            flags,
            segment_index: 1,
            total_segments: 1,
            request_id: None,
        };

        // Segment 0: first 74 hashes = 296 bytes
        let packed0 = adv.pack(0);
        let unpacked0 = ResourceAdvertisement::unpack(&packed0).unwrap();
        assert_eq!(unpacked0.hashmap.len(), 74 * 4);

        // Segment 1: remaining 26 hashes = 104 bytes
        let packed1 = adv.pack(1);
        let unpacked1 = ResourceAdvertisement::unpack(&packed1).unwrap();
        assert_eq!(unpacked1.hashmap.len(), 26 * 4);
    }

    #[test]
    fn test_hashmap_segments_count() {
        let flags = AdvFlags {
            encrypted: true, compressed: false, split: false,
            is_request: false, is_response: false, has_metadata: false,
        };
        let mut adv = make_adv(flags);

        adv.num_parts = 74; // exactly HASHMAP_MAX_LEN
        assert_eq!(adv.hashmap_segments(), 1);

        adv.num_parts = 75;
        assert_eq!(adv.hashmap_segments(), 2);

        adv.num_parts = 148;
        assert_eq!(adv.hashmap_segments(), 2);

        adv.num_parts = 149;
        assert_eq!(adv.hashmap_segments(), 3);
    }

    #[test]
    fn test_unpack_invalid_data() {
        assert!(ResourceAdvertisement::unpack(&[]).is_err());
        assert!(ResourceAdvertisement::unpack(&[0xc0]).is_err()); // nil
        assert!(ResourceAdvertisement::unpack(&[0x01, 0x02]).is_err()); // not a map
    }
}
