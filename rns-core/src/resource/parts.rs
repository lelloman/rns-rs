use alloc::vec::Vec;

use crate::constants::{RESOURCE_COLLISION_GUARD_SIZE, RESOURCE_MAPHASH_LEN};

/// Compute map hash for a part: SHA-256(part_data + random_hash)[:4]
pub fn map_hash(part_data: &[u8], random_hash: &[u8]) -> [u8; RESOURCE_MAPHASH_LEN] {
    // Hashed in two updates: no buffer joining the part and the random hash.
    let mut hasher = rns_crypto::sha256::Sha256::new();
    hasher.update(part_data);
    hasher.update(random_hash);
    let hash = hasher.digest();
    let mut result = [0u8; RESOURCE_MAPHASH_LEN];
    result.copy_from_slice(&hash[..RESOURCE_MAPHASH_LEN]);
    result
}

/// The map hashes of `encrypted` cut into `sdu`-byte parts, with `data`
/// absorbed into `data_state` alongside: each part's blocks are compressed
/// together with as many of `data`'s.
///
/// With `mac`, `encrypted` is a token whose last 32 bytes are its tag still
/// to be written: the MAC takes every byte before them alongside, and the
/// tag is written before the parts that hold it are hashed.
pub(crate) fn map_hashes_with_data(
    encrypted: &mut [u8],
    sdu: usize,
    random_hash: &[u8],
    data: &[u8],
    data_state: &mut rns_crypto::sha256::Sha256,
    mac: Option<rns_crypto::hmac::HmacSha256>,
) -> Vec<[u8; RESOURCE_MAPHASH_LEN]> {
    use rns_crypto::sha256::{update_pair, Sha256};
    let finish = |mut hasher: Sha256| {
        hasher.update(random_hash);
        let mut result = [0u8; RESOURCE_MAPHASH_LEN];
        result.copy_from_slice(&hasher.digest()[..RESOURCE_MAPHASH_LEN]);
        result
    };
    let mut rest = data;
    let mut take = |len: usize| {
        let (paired, after) = rest.split_at(len.min(rest.len()));
        rest = after;
        paired
    };
    let mut hashes = Vec::with_capacity(encrypted.len().div_ceil(sdu));
    let mut tagged_from = 0;
    if let Some(mut mac) = mac {
        let signed = encrypted.len() - 32;
        // Parts wholly before the tag: part, MAC and data together.
        tagged_from = signed / sdu * sdu;
        for part in encrypted[..tagged_from].chunks(sdu) {
            let mut hasher = Sha256::new();
            mac.update_tripled(part, &mut hasher, part, data_state, take(part.len()));
            hashes.push(finish(hasher));
        }
        let unsigned = &encrypted[tagged_from..signed];
        mac.update_paired(unsigned, data_state, take(unsigned.len()));
        let tag = mac.finalize();
        encrypted[signed..].copy_from_slice(&tag);
    }
    for part in encrypted[tagged_from..].chunks(sdu) {
        let mut hasher = Sha256::new();
        update_pair(&mut hasher, part, data_state, take(part.len()));
        hashes.push(finish(hasher));
    }
    let rest = take(usize::MAX);
    data_state.update(rest);
    hashes
}

/// Split data into SDU-sized parts and compute their map hashes.
/// Returns (parts_data, map_hashes).
pub fn split_into_parts(
    encrypted_data: &[u8],
    sdu: usize,
    random_hash: &[u8],
) -> (Vec<Vec<u8>>, Vec<[u8; RESOURCE_MAPHASH_LEN]>) {
    if encrypted_data.is_empty() || sdu == 0 {
        return (Vec::new(), Vec::new());
    }
    let num_parts = encrypted_data.len().div_ceil(sdu);
    let mut parts = Vec::with_capacity(num_parts);
    let mut hashes = Vec::with_capacity(num_parts);

    for i in 0..num_parts {
        let start = i * sdu;
        let end = core::cmp::min(start + sdu, encrypted_data.len());
        let part = encrypted_data[start..end].to_vec();
        let hash = map_hash(&part, random_hash);
        parts.push(part);
        hashes.push(hash);
    }

    (parts, hashes)
}

/// Build concatenated hashmap bytes from map hashes.
pub fn build_hashmap(hashes: &[[u8; RESOURCE_MAPHASH_LEN]]) -> Vec<u8> {
    let mut hashmap = Vec::with_capacity(hashes.len() * RESOURCE_MAPHASH_LEN);
    for h in hashes {
        hashmap.extend_from_slice(h);
    }
    hashmap
}

/// Check for collisions within COLLISION_GUARD_SIZE window.
/// Returns true if a collision exists.
pub fn has_collision(hashes: &[[u8; RESOURCE_MAPHASH_LEN]]) -> bool {
    // Use a sliding window of COLLISION_GUARD_SIZE
    for (i, hash) in hashes.iter().enumerate() {
        let guard_start = i.saturating_sub(RESOURCE_COLLISION_GUARD_SIZE);
        for prev in &hashes[guard_start..i] {
            if prev == hash {
                return true;
            }
        }
    }
    false
}

/// Find a part index by its map hash in the hashmap within a search window.
/// Returns the index within the provided hashmap slice.
pub fn find_part_by_hash(
    hashmap: &[Option<[u8; RESOURCE_MAPHASH_LEN]>],
    target: &[u8; RESOURCE_MAPHASH_LEN],
    start: usize,
    window: usize,
) -> Option<usize> {
    let end = core::cmp::min(start + window, hashmap.len());
    for (i, item) in hashmap.iter().enumerate().take(end).skip(start) {
        if let Some(h) = item {
            if h == target {
                return Some(i);
            }
        }
    }
    None
}

/// Prepend metadata to data: [3-byte BE length] + metadata + data.
pub fn prepend_metadata(data: &[u8], metadata: &[u8]) -> Vec<u8> {
    let size = metadata.len();
    let size_bytes = [
        ((size >> 16) & 0xFF) as u8,
        ((size >> 8) & 0xFF) as u8,
        (size & 0xFF) as u8,
    ];
    let mut result = Vec::with_capacity(3 + metadata.len() + data.len());
    result.extend_from_slice(&size_bytes);
    result.extend_from_slice(metadata);
    result.extend_from_slice(data);
    result
}

/// Extract metadata from assembled data.
/// Returns (metadata_bytes, remaining_data).
pub fn extract_metadata(assembled: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if assembled.len() < 3 {
        return None;
    }
    let size =
        ((assembled[0] as usize) << 16) | ((assembled[1] as usize) << 8) | (assembled[2] as usize);
    if assembled.len() < 3 + size {
        return None;
    }
    let metadata = assembled[3..3 + size].to_vec();
    let data = assembled[3 + size..].to_vec();
    Some((metadata, data))
}

/// Extract metadata while retaining the owned payload allocation.
pub(crate) fn extract_metadata_owned(mut assembled: Vec<u8>) -> Option<(Vec<u8>, Vec<u8>)> {
    let header = assembled.get(..3)?;
    let size = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
    let end = 3 + size;
    let metadata = assembled.get(3..end)?.to_vec();
    let payload_len = assembled.len() - end;
    assembled.copy_within(end.., 0);
    assembled.truncate(payload_len);
    Some((metadata, assembled))
}

#[cfg(test)]
mod tests {

    #[test]
    fn map_hashes_with_data_match_separate_hashes() {
        let encrypted: Vec<u8> = (0..5000).map(|i| (i * 7) as u8).collect();
        for data_len in [0usize, 10, 4000, 5000, 9000] {
            let data: Vec<u8> = (0..data_len).map(|i| (i * 11) as u8).collect();
            for sdu in [1usize, 31, 63, 64, 464, 5000, 9000] {
                let mut state = rns_crypto::sha256::Sha256::new();
                let mut bytes = encrypted.clone();
                let hashes =
                    map_hashes_with_data(&mut bytes, sdu, b"rand", &data, &mut state, None);
                let expected: Vec<_> = encrypted
                    .chunks(sdu)
                    .map(|p| map_hash(p, b"rand"))
                    .collect();
                assert_eq!(hashes, expected, "data {data_len} sdu {sdu}");
                assert_eq!(state.digest(), rns_crypto::sha256::sha256(&data));
                assert_eq!(bytes, encrypted);

                // With the tag written alongside.
                let token = rns_crypto::token::Token::new(&[0x33; 64]).unwrap();
                let plain = &encrypted[..data_len.min(4000)];
                let tagged = token.encrypt(plain, &mut rns_crypto::FixedRng::new(&[0x10; 16]));
                let (mut untagged, mac) =
                    token.encrypt_untagged(plain, &mut rns_crypto::FixedRng::new(&[0x10; 16]));
                let mut state = rns_crypto::sha256::Sha256::new();
                let hashes =
                    map_hashes_with_data(&mut untagged, sdu, b"rand", &data, &mut state, Some(mac));
                assert_eq!(untagged, tagged, "data {data_len} sdu {sdu}");
                let expected: Vec<_> = tagged.chunks(sdu).map(|p| map_hash(p, b"rand")).collect();
                assert_eq!(hashes, expected, "tagged data {data_len} sdu {sdu}");
                assert_eq!(state.digest(), rns_crypto::sha256::sha256(&data));
            }
        }
    }

    use super::*;

    #[test]
    fn owned_metadata_matches_borrowed_for_valid_and_malformed_inputs() {
        for input in [
            vec![],
            vec![0],
            vec![0, 0],
            vec![0, 0, 1],
            vec![255, 255, 255],
            prepend_metadata(b"payload", b"meta"),
            prepend_metadata(b"", b""),
            prepend_metadata(b"", b"meta"),
            prepend_metadata(b"payload", b""),
        ] {
            assert_eq!(
                extract_metadata_owned(input.clone()),
                extract_metadata(&input)
            );
        }
    }

    #[test]
    fn test_map_hash_basic() {
        let part_data = b"test part data";
        let random = [0xAA, 0xBB, 0xCC, 0xDD];
        let h = map_hash(part_data, &random);
        assert_eq!(h.len(), RESOURCE_MAPHASH_LEN);

        // Deterministic
        let h2 = map_hash(part_data, &random);
        assert_eq!(h, h2);
    }

    #[test]
    fn test_map_hash_different_data() {
        let random = [0x11, 0x22, 0x33, 0x44];
        let h1 = map_hash(b"part1", &random);
        let h2 = map_hash(b"part2", &random);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_map_hash_different_random() {
        let data = b"same data";
        let h1 = map_hash(data, &[0x01, 0x02, 0x03, 0x04]);
        let h2 = map_hash(data, &[0x05, 0x06, 0x07, 0x08]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_split_into_parts_basic() {
        let data = vec![0xAA; 1000];
        let random = [0x11, 0x22, 0x33, 0x44];
        let sdu = 464;
        let (parts, hashes) = split_into_parts(&data, sdu, &random);

        // 1000 bytes / 464 SDU = 3 parts (464, 464, 72)
        assert_eq!(parts.len(), 3);
        assert_eq!(hashes.len(), 3);
        assert_eq!(parts[0].len(), 464);
        assert_eq!(parts[1].len(), 464);
        assert_eq!(parts[2].len(), 72);

        // Verify map hashes match
        for (part, hash) in parts.iter().zip(hashes.iter()) {
            assert_eq!(map_hash(part, &random), *hash);
        }
    }

    #[test]
    fn test_split_into_parts_empty() {
        let (parts, hashes) = split_into_parts(&[], 464, &[0x11; 4]);
        assert!(parts.is_empty());
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_split_exact_sdu() {
        let data = vec![0xBB; 464];
        let (parts, hashes) = split_into_parts(&data, 464, &[0x11; 4]);
        assert_eq!(parts.len(), 1);
        assert_eq!(hashes.len(), 1);
        assert_eq!(parts[0].len(), 464);
    }

    #[test]
    fn test_build_hashmap() {
        let hashes = vec![[0x11, 0x22, 0x33, 0x44], [0xAA, 0xBB, 0xCC, 0xDD]];
        let hashmap = build_hashmap(&hashes);
        assert_eq!(
            hashmap,
            vec![0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD]
        );
    }

    #[test]
    fn test_has_collision_no_collision() {
        let hashes = vec![
            [0x01, 0x02, 0x03, 0x04],
            [0x05, 0x06, 0x07, 0x08],
            [0x09, 0x0A, 0x0B, 0x0C],
        ];
        assert!(!has_collision(&hashes));
    }

    #[test]
    fn test_has_collision_with_collision() {
        let hashes = vec![
            [0x01, 0x02, 0x03, 0x04],
            [0x05, 0x06, 0x07, 0x08],
            [0x01, 0x02, 0x03, 0x04], // duplicate
        ];
        assert!(has_collision(&hashes));
    }

    #[test]
    fn test_find_part_by_hash() {
        let hashmap: Vec<Option<[u8; 4]>> = vec![
            Some([0x11, 0x22, 0x33, 0x44]),
            Some([0xAA, 0xBB, 0xCC, 0xDD]),
            Some([0x55, 0x66, 0x77, 0x88]),
            None,
        ];
        assert_eq!(
            find_part_by_hash(&hashmap, &[0xAA, 0xBB, 0xCC, 0xDD], 0, 4),
            Some(1)
        );
        assert_eq!(
            find_part_by_hash(&hashmap, &[0xFF, 0xFF, 0xFF, 0xFF], 0, 4),
            None
        );
        // Outside window
        assert_eq!(
            find_part_by_hash(&hashmap, &[0x55, 0x66, 0x77, 0x88], 0, 2),
            None
        );
    }

    #[test]
    fn test_prepend_metadata() {
        let data = b"hello";
        let metadata = b"meta";
        let result = prepend_metadata(data, metadata);
        // 3-byte length (4) + "meta" + "hello"
        assert_eq!(result.len(), 3 + 4 + 5);
        assert_eq!(result[0], 0);
        assert_eq!(result[1], 0);
        assert_eq!(result[2], 4);
        assert_eq!(&result[3..7], b"meta");
        assert_eq!(&result[7..12], b"hello");
    }

    #[test]
    fn test_extract_metadata() {
        let assembled = prepend_metadata(b"data", b"metadata bytes");
        let (meta, data) = extract_metadata(&assembled).unwrap();
        assert_eq!(meta, b"metadata bytes");
        assert_eq!(data, b"data");
    }

    #[test]
    fn test_metadata_roundtrip_empty() {
        let assembled = prepend_metadata(b"data", b"");
        let (meta, data) = extract_metadata(&assembled).unwrap();
        assert!(meta.is_empty());
        assert_eq!(data, b"data");
    }

    #[test]
    fn test_extract_metadata_too_short() {
        assert!(extract_metadata(&[0, 0]).is_none());
        // Size says 5 bytes but only 3 available
        assert!(extract_metadata(&[0, 0, 5, 1, 2, 3]).is_none());
    }

    #[test]
    fn test_split_into_parts_zero_sdu() {
        // sdu==0 should not panic, returns empty
        let (parts, hashes) = split_into_parts(&[0xAA; 100], 0, &[0x11; 4]);
        assert!(parts.is_empty());
        assert!(hashes.is_empty());
    }
}
