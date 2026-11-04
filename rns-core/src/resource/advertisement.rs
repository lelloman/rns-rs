use alloc::vec::Vec;

use super::types::{AdvFlags, ResourceError};
use crate::constants::{RESOURCE_HASHMAP_MAX_LEN, RESOURCE_MAPHASH_LEN};
use crate::msgpack;

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

        // Written directly, in Python's key order (t, d, n, h, r, o, i, l, q,
        // f, m): building a msgpack value first cloned every field. Sized for
        // the worst case so the buffer is allocated once.
        let bins = self.resource_hash.len()
            + self.random_hash.len()
            + self.original_hash.len()
            + self.request_id.as_ref().map_or(0, Vec::len)
            + hashmap_segment.len();
        let mut out = Vec::with_capacity(1 + 11 * 2 + 6 * 9 + 5 * 5 + bins);
        out.push(0x80 | 11);
        let uint = |out: &mut Vec<u8>, key: &str, value: u64| {
            msgpack::pack_str(key, out);
            msgpack::pack_uint(value, out);
        };
        uint(&mut out, "t", self.transfer_size);
        uint(&mut out, "d", self.data_size);
        uint(&mut out, "n", self.num_parts);
        for (key, value) in [
            ("h", &self.resource_hash),
            ("r", &self.random_hash),
            ("o", &self.original_hash),
        ] {
            msgpack::pack_str(key, &mut out);
            msgpack::pack_bin(value, &mut out);
        }
        uint(&mut out, "i", self.segment_index);
        uint(&mut out, "l", self.total_segments);
        msgpack::pack_str("q", &mut out);
        match &self.request_id {
            Some(id) => msgpack::pack_bin(id, &mut out),
            None => out.push(0xc0),
        }
        uint(&mut out, "f", self.flags.to_byte() as u64);
        msgpack::pack_str("m", &mut out);
        msgpack::pack_bin(hashmap_segment, &mut out);
        out
    }

    /// Pack the advertisement for a link with the given MDU.
    ///
    /// Like Python, an advertisement that would exceed the MDU is sent with
    /// an empty hashmap, and the receiver requests the first hashmap segment
    /// with `RESOURCE_HASHMAP_IS_EMPTY` before any part.
    pub fn pack_for_mdu(&self, segment: usize, mdu: usize) -> Vec<u8> {
        let packed = self.pack(segment);
        if packed.len() <= mdu {
            return packed;
        }
        let without_hashmap = ResourceAdvertisement {
            hashmap: Vec::new(),
            ..self.clone()
        };
        without_hashmap.pack(segment)
    }

    /// Unpack an advertisement from msgpack bytes.
    pub fn unpack(data: &[u8]) -> Result<Self, ResourceError> {
        // Read in place: decoding to a msgpack value first allocated every
        // key and field, and each field was then copied again.
        let invalid = ResourceError::InvalidAdvertisement;
        let value = msgpack::unpack_exact_ref(data).map_err(|_| invalid.clone())?;
        let mut fields: [Option<msgpack::ValueRef<'_>>; 11] = [None; 11];
        for (key, field) in value.map_entries().ok_or(invalid.clone())? {
            let Some(key) = key.as_str() else { continue };
            let Some(index) = ["t", "d", "n", "h", "r", "o", "i", "l", "q", "f", "m"]
                .iter()
                .position(|k| *k == key)
            else {
                continue;
            };
            // The first entry for a key wins, as in `Value::map_get`.
            fields[index].get_or_insert(field);
        }
        let [t, d, n, h, r, o, i, l, q, f, m] = fields;
        let uint =
            |v: Option<msgpack::ValueRef<'_>>| v.and_then(|v| v.as_uint()).ok_or(invalid.clone());
        let bin = |v: Option<msgpack::ValueRef<'_>>| {
            v.and_then(|v| v.as_bin())
                .map(<[u8]>::to_vec)
                .ok_or(invalid.clone())
        };
        let (t, d, n) = (uint(t)?, uint(d)?, uint(n)?);
        let (h, r, o, m) = (bin(h)?, bin(r)?, bin(o)?, bin(m)?);
        let f = uint(f)? as u8;
        let (i, l) = (uint(i)?, uint(l)?);
        let q = q.ok_or(invalid.clone())?;
        let request_id = if q.is_nil() {
            None
        } else {
            Some(q.as_bin().ok_or(invalid.clone())?.to_vec())
        };

        if t > (crate::constants::RESOURCE_MAX_EFFICIENT_SIZE * 3) as u64 {
            return Err(ResourceError::InvalidAdvertisement);
        }

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

    /// Whether the sender set the application flag (Python `app_flag_set`).
    pub fn app_flag_set(&self) -> bool {
        self.flags.app_flag
    }

    /// Get the number of hashmap segments needed.
    pub fn hashmap_segments(&self) -> usize {
        let total_hashes = self.num_parts as usize;
        if total_hashes == 0 {
            return 1;
        }
        total_hashes.div_ceil(RESOURCE_HASHMAP_MAX_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgpack::Value;
    use alloc::vec;

    /// The encoder before direct writing, kept as the reference.
    fn pack_reference(adv: &ResourceAdvertisement, segment: usize) -> Vec<u8> {
        let hashmap_start = segment * RESOURCE_HASHMAP_MAX_LEN * RESOURCE_MAPHASH_LEN;
        let max_end = (segment + 1) * RESOURCE_HASHMAP_MAX_LEN * RESOURCE_MAPHASH_LEN;
        let hashmap_end = core::cmp::min(max_end, adv.hashmap.len());
        let hashmap_segment = if hashmap_start < adv.hashmap.len() {
            &adv.hashmap[hashmap_start..hashmap_end]
        } else {
            &[]
        };
        let q_value = match &adv.request_id {
            Some(id) => Value::Bin(id.clone()),
            None => Value::Nil,
        };
        let entries: Vec<(&str, Value)> = vec![
            ("t", Value::UInt(adv.transfer_size)),
            ("d", Value::UInt(adv.data_size)),
            ("n", Value::UInt(adv.num_parts)),
            ("h", Value::Bin(adv.resource_hash.clone())),
            ("r", Value::Bin(adv.random_hash.clone())),
            ("o", Value::Bin(adv.original_hash.clone())),
            ("i", Value::UInt(adv.segment_index)),
            ("l", Value::UInt(adv.total_segments)),
            ("q", q_value),
            ("f", Value::UInt(adv.flags.to_byte() as u64)),
            ("m", Value::Bin(hashmap_segment.to_vec())),
        ];
        msgpack::pack_str_map(&entries)
    }

    /// The decoder before reading in place, kept as the reference.
    fn unpack_reference(data: &[u8]) -> Option<ResourceAdvertisement> {
        let value = msgpack::unpack_exact(data).ok()?;
        let uint = |k| value.map_get(k).and_then(|v| v.as_uint());
        let bin = |k| {
            value
                .map_get(k)
                .and_then(|v| v.as_bin())
                .map(<[u8]>::to_vec)
        };
        let (t, d, n) = (uint("t")?, uint("d")?, uint("n")?);
        let (h, r, o, m) = (bin("h")?, bin("r")?, bin("o")?, bin("m")?);
        let f = uint("f")? as u8;
        let (i, l) = (uint("i")?, uint("l")?);
        let q = value.map_get("q")?;
        let request_id = if q.is_nil() {
            None
        } else {
            Some(q.as_bin()?.to_vec())
        };
        if t > (crate::constants::RESOURCE_MAX_EFFICIENT_SIZE * 3) as u64 {
            return None;
        }
        Some(ResourceAdvertisement {
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

    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len).map(|_| self.next() as u8).collect()
        }
    }

    fn random_adv(rng: &mut XorShift) -> ResourceAdvertisement {
        // Sizes cross every msgpack integer width.
        let widths = [
            0u64,
            1,
            127,
            128,
            255,
            256,
            65_535,
            65_536,
            u32::MAX as u64,
            u64::MAX,
        ];
        let pick = |rng: &mut XorShift| {
            let w = widths[(rng.next() % widths.len() as u64) as usize];
            w.saturating_sub(rng.next() % 3)
        };
        let hashmap_len = [0usize, 4, 300, 74 * 4 * 2][(rng.next() % 4) as usize];
        let original_len = (rng.next() % 40) as usize;
        ResourceAdvertisement {
            transfer_size: pick(rng) % 1_000_000,
            data_size: pick(rng),
            num_parts: pick(rng),
            resource_hash: rng.bytes(32),
            random_hash: rng.bytes(4),
            original_hash: rng.bytes(original_len),
            hashmap: rng.bytes(hashmap_len),
            flags: AdvFlags::from_byte(rng.next() as u8),
            segment_index: pick(rng),
            total_segments: pick(rng),
            request_id: rng.next().is_multiple_of(2).then(|| rng.bytes(16)),
        }
    }

    fn same(a: &Option<ResourceAdvertisement>, b: &Option<ResourceAdvertisement>) -> bool {
        match (a, b) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                a.transfer_size == b.transfer_size
                    && a.data_size == b.data_size
                    && a.num_parts == b.num_parts
                    && a.resource_hash == b.resource_hash
                    && a.random_hash == b.random_hash
                    && a.original_hash == b.original_hash
                    && a.hashmap == b.hashmap
                    && a.flags.to_byte() == b.flags.to_byte()
                    && a.segment_index == b.segment_index
                    && a.total_segments == b.total_segments
                    && a.request_id == b.request_id
            }
            _ => false,
        }
    }

    #[test]
    fn direct_pack_matches_the_value_encoder_byte_for_byte() {
        let mut rng = XorShift(0x5EED_0001);
        for _ in 0..2_000 {
            let adv = random_adv(&mut rng);
            for segment in 0..3 {
                assert_eq!(adv.pack(segment), pack_reference(&adv, segment));
            }
        }
    }

    #[test]
    fn in_place_unpack_matches_the_value_decoder_on_valid_and_corrupt_input() {
        let mut rng = XorShift(0x5EED_0002);
        let mut cases = 0;
        for round in 0..400u32 {
            let adv = random_adv(&mut rng);
            let packed = adv.pack(0);
            let check = |data: &[u8]| {
                let new = ResourceAdvertisement::unpack(data).ok();
                assert!(
                    same(&new, &unpack_reference(data)),
                    "diverged on {data:02x?}"
                );
            };
            check(&packed);
            // Every truncation, every single-byte change at a few values, and
            // random multi-byte flips.
            for len in 0..packed.len() {
                check(&packed[..len]);
            }
            let mut extended = packed.clone();
            extended.push(0xc0);
            check(&extended);
            if round.is_multiple_of(8) {
                for at in 0..packed.len() {
                    for value in [
                        0x00, 0x7f, 0x80, 0xa1, 0xc0, 0xc1, 0xc4, 0xcc, 0xd0, 0xd9, 0xdc, 0xde,
                        0xff,
                    ] {
                        let mut mutated = packed.clone();
                        mutated[at] = value;
                        check(&mutated);
                        cases += 1;
                    }
                }
            }
            for _ in 0..20 {
                let mut mutated = packed.clone();
                for _ in 0..(1 + rng.next() % 4) {
                    let at = (rng.next() as usize) % mutated.len();
                    mutated[at] = rng.next() as u8;
                }
                check(&mutated);
                cases += 1;
            }
        }
        // Duplicate keys: the first entry wins in both decoders.
        let adv = random_adv(&mut rng);
        let mut packed = adv.pack(0);
        packed[0] = 0x80 | 12;
        msgpack::pack_str("t", &mut packed);
        msgpack::pack_uint(5, &mut packed);
        assert!(same(
            &ResourceAdvertisement::unpack(&packed).ok(),
            &unpack_reference(&packed)
        ));
        assert!(cases > 10_000);
    }

    fn make_adv(flags: AdvFlags) -> ResourceAdvertisement {
        ResourceAdvertisement {
            transfer_size: 1000,
            data_size: 950,
            num_parts: 3,
            resource_hash: vec![0x11; 32],
            random_hash: vec![0xAA, 0xBB, 0xCC, 0xDD],
            original_hash: vec![0x22; 32],
            hashmap: vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            ],
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
            app_flag: false,
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
            app_flag: false,
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
            app_flag: false,
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
            app_flag: false,
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
            app_flag: false,
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
            app_flag: false,
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
            app_flag: false,
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
            app_flag: false,
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
            encrypted: true,
            compressed: false,
            split: false,
            is_request: false,
            is_response: false,
            has_metadata: false,
            app_flag: false,
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

    #[test]
    fn test_unpack_accepts_exact_upstream_transfer_limit() {
        let flags = AdvFlags {
            encrypted: true,
            compressed: false,
            split: false,
            is_request: false,
            is_response: false,
            has_metadata: false,
            app_flag: false,
        };
        let mut adv = make_adv(flags);
        adv.transfer_size = (crate::constants::RESOURCE_MAX_EFFICIENT_SIZE * 3) as u64;

        let unpacked = ResourceAdvertisement::unpack(&adv.pack(0)).unwrap();
        assert_eq!(unpacked.transfer_size, adv.transfer_size);
    }

    #[test]
    fn test_unpack_rejects_transfer_above_upstream_limit() {
        let flags = AdvFlags {
            encrypted: true,
            compressed: false,
            split: false,
            is_request: false,
            is_response: false,
            has_metadata: false,
            app_flag: false,
        };
        let mut adv = make_adv(flags);
        adv.transfer_size = (crate::constants::RESOURCE_MAX_EFFICIENT_SIZE * 3 + 1) as u64;

        assert_eq!(
            ResourceAdvertisement::unpack(&adv.pack(0)).unwrap_err(),
            ResourceError::InvalidAdvertisement
        );
    }
}
