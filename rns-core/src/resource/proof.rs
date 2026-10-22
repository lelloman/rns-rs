use alloc::vec::Vec;

use rns_crypto::sha256::Sha256;

use super::types::ResourceError;

/// SHA-256 state after absorbing the resource data. The resource hash and the
/// expected proof are both SHA-256 over this data followed by a short suffix,
/// so one pass over the data serves both (and every collision retry).
pub(crate) fn data_hash_state(unencrypted_data: &[u8]) -> Sha256 {
    let mut state = Sha256::new();
    state.update(unencrypted_data);
    state
}

/// Finish a copy of `state` with `suffix`.
pub(crate) fn finish_with(state: &Sha256, suffix: &[u8]) -> [u8; 32] {
    let mut hasher = state.clone();
    hasher.update(suffix);
    hasher.digest()
}

/// Compute resource hash: SHA-256(unencrypted_data + random_hash).
/// `unencrypted_data` is the metadata-prefixed data BEFORE encryption.
/// Returns full 32-byte hash.
pub fn compute_resource_hash(unencrypted_data: &[u8], random_hash: &[u8]) -> [u8; 32] {
    finish_with(&data_hash_state(unencrypted_data), random_hash)
}

/// Compute expected proof: SHA-256(unencrypted_data + resource_hash).
/// `unencrypted_data` is the same data used in compute_resource_hash.
pub fn compute_expected_proof(unencrypted_data: &[u8], resource_hash: &[u8; 32]) -> [u8; 32] {
    finish_with(&data_hash_state(unencrypted_data), resource_hash)
}

/// Build proof data: [resource_hash: 32 bytes][proof: 32 bytes].
pub fn build_proof_data(resource_hash: &[u8; 32], proof: &[u8; 32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(resource_hash);
    data.extend_from_slice(proof);
    data
}

/// Validate proof data against expected proof.
/// proof_data = [resource_hash: 32 bytes][proof: 32 bytes]
///
/// Only checks the proof portion (bytes 32..64) against the expected proof,
/// matching Python's behavior which validates the proof hash, not the resource hash prefix.
pub fn validate_proof(
    proof_data: &[u8],
    _expected_resource_hash: &[u8; 32],
    expected_proof: &[u8; 32],
) -> Result<bool, ResourceError> {
    if proof_data.len() != 64 {
        return Err(ResourceError::InvalidProof);
    }
    let recv_proof = &proof_data[32..64];
    Ok(recv_proof == expected_proof.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::full_hash;

    fn concatenated(data: &[u8], suffix: &[u8]) -> [u8; 32] {
        let mut input = data.to_vec();
        input.extend_from_slice(suffix);
        full_hash(&input)
    }

    #[test]
    fn streamed_hash_and_proof_match_concatenation() {
        // Block boundaries of SHA-256 (64 bytes) and a multi-part size.
        for len in [0usize, 1, 55, 56, 63, 64, 65, 127, 128, 1000, 70_001] {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let random = [0x5a, 0x01, 0xfe, 0x33];
            let hash = compute_resource_hash(&data, &random);
            assert_eq!(hash, concatenated(&data, &random), "hash, len {len}");
            let proof = compute_expected_proof(&data, &hash);
            assert_eq!(proof, concatenated(&data, &hash), "proof, len {len}");
            // One state serves both suffixes, in either order, repeatedly.
            let state = data_hash_state(&data);
            assert_eq!(finish_with(&state, &hash), proof);
            assert_eq!(finish_with(&state, &random), hash);
            assert_eq!(
                finish_with(&state, &[0x5a, 0x01, 0xfe, 0x34]),
                concatenated(&data, &[0x5a, 0x01, 0xfe, 0x34])
            );
        }
    }

    #[test]
    fn test_compute_resource_hash() {
        let data = b"test resource data";
        let random = [0xAA, 0xBB, 0xCC, 0xDD];
        let hash = compute_resource_hash(data, &random);
        assert_eq!(hash.len(), 32);

        // Deterministic
        let hash2 = compute_resource_hash(data, &random);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_compute_expected_proof() {
        let data = b"test resource data";
        let random = [0xAA, 0xBB, 0xCC, 0xDD];
        let resource_hash = compute_resource_hash(data, &random);
        let proof = compute_expected_proof(data, &resource_hash);
        assert_eq!(proof.len(), 32);
        assert_ne!(proof, resource_hash); // proof != hash
    }

    #[test]
    fn test_build_proof_data() {
        let hash = [0x11u8; 32];
        let proof = [0x22u8; 32];
        let data = build_proof_data(&hash, &proof);
        assert_eq!(data.len(), 64);
        assert_eq!(&data[..32], &hash);
        assert_eq!(&data[32..], &proof);
    }

    #[test]
    fn test_validate_proof_valid() {
        let data = b"resource data here";
        let random = [0x11, 0x22, 0x33, 0x44];
        let resource_hash = compute_resource_hash(data, &random);
        let expected = compute_expected_proof(data, &resource_hash);
        let proof_data = build_proof_data(&resource_hash, &expected);
        assert_eq!(
            validate_proof(&proof_data, &resource_hash, &expected),
            Ok(true)
        );
    }

    #[test]
    fn test_validate_proof_wrong_hash_prefix_still_valid() {
        // Python only checks the proof portion, not the resource_hash prefix
        let data = b"resource data";
        let random = [0x11; 4];
        let resource_hash = compute_resource_hash(data, &random);
        let expected = compute_expected_proof(data, &resource_hash);
        let wrong_hash = [0xFF; 32];
        let proof_data = build_proof_data(&wrong_hash, &expected);
        // Proof is still valid because we only check bytes 32..64
        assert_eq!(
            validate_proof(&proof_data, &resource_hash, &expected),
            Ok(true)
        );
    }

    #[test]
    fn test_validate_proof_invalid_proof() {
        let data = b"resource data";
        let random = [0x11; 4];
        let resource_hash = compute_resource_hash(data, &random);
        let expected = compute_expected_proof(data, &resource_hash);
        let wrong_proof = [0xFF; 32];
        let proof_data = build_proof_data(&resource_hash, &wrong_proof);
        assert_eq!(
            validate_proof(&proof_data, &resource_hash, &expected),
            Ok(false)
        );
    }

    #[test]
    fn test_validate_proof_wrong_length() {
        let hash = [0x11; 32];
        let proof = [0x22; 32];
        assert!(validate_proof(&[0; 50], &hash, &proof).is_err());
        assert!(validate_proof(&[], &hash, &proof).is_err());
    }

    #[test]
    fn test_proof_uses_unencrypted_data() {
        // Verify that changing the data changes both hash and proof
        let random = [0xAA; 4];
        let hash1 = compute_resource_hash(b"data1", &random);
        let hash2 = compute_resource_hash(b"data2", &random);
        assert_ne!(hash1, hash2);

        let proof1 = compute_expected_proof(b"data1", &hash1);
        let proof2 = compute_expected_proof(b"data2", &hash2);
        assert_ne!(proof1, proof2);
    }
}
