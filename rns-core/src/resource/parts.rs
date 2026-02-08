use alloc::vec::Vec;

use crate::constants::{RESOURCE_MAPHASH_LEN, RESOURCE_COLLISION_GUARD_SIZE};
use crate::hash::full_hash;

/// Compute map hash for a part: SHA-256(part_data + random_hash)[:4]
pub fn map_hash(part_data: &[u8], random_hash: &[u8]) -> [u8; RESOURCE_MAPHASH_LEN] {
    let mut input = Vec::with_capacity(part_data.len() + random_hash.len());
    input.extend_from_slice(part_data);
    input.extend_from_slice(random_hash);
    let hash = full_hash(&input);
    let mut result = [0u8; RESOURCE_MAPHASH_LEN];
    result.copy_from_slice(&hash[..RESOURCE_MAPHASH_LEN]);
    result
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
    let num_parts = (encrypted_data.len() + sdu - 1) / sdu;
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
        let guard_start = if i >= RESOURCE_COLLISION_GUARD_SIZE {
            i - RESOURCE_COLLISION_GUARD_SIZE
        } else {
            0
        };
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
    for i in start..end {
        if let Some(ref h) = hashmap[i] {
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
    let size = ((assembled[0] as usize) << 16)
        | ((assembled[1] as usize) << 8)
        | (assembled[2] as usize);
    if assembled.len() < 3 + size {
        return None;
    }
    let metadata = assembled[3..3 + size].to_vec();
    let data = assembled[3 + size..].to_vec();
    Some((metadata, data))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(hashmap, vec![0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD]);
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
        assert_eq!(find_part_by_hash(&hashmap, &[0xAA, 0xBB, 0xCC, 0xDD], 0, 4), Some(1));
        assert_eq!(find_part_by_hash(&hashmap, &[0xFF, 0xFF, 0xFF, 0xFF], 0, 4), None);
        // Outside window
        assert_eq!(find_part_by_hash(&hashmap, &[0x55, 0x66, 0x77, 0x88], 0, 2), None);
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
