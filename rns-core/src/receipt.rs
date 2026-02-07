use rns_crypto::identity::Identity;

use crate::constants;

/// Result of proof validation.
#[derive(Debug, PartialEq, Eq)]
pub enum ProofResult {
    Valid,
    InvalidHash,
    InvalidSignature,
    InvalidLength,
}

/// Validate an explicit or implicit proof against a packet hash.
///
/// Explicit proof (96 bytes): `[proof_hash:32][signature:64]`
/// - Verify: proof_hash == packet_hash AND identity.verify(signature, packet_hash)
///
/// Implicit proof (64 bytes): `[signature:64]`
/// - Verify: identity.verify(signature, packet_hash)
pub fn validate_proof(
    proof: &[u8],
    packet_hash: &[u8; 32],
    identity: &Identity,
) -> ProofResult {
    if proof.len() == constants::EXPL_LENGTH {
        // Explicit proof: [proof_hash:32][signature:64]
        let proof_hash = &proof[..constants::HASHLENGTH / 8];
        if proof_hash != packet_hash.as_slice() {
            return ProofResult::InvalidHash;
        }

        let signature: &[u8; 64] = proof[constants::HASHLENGTH / 8..constants::HASHLENGTH / 8 + constants::SIGLENGTH / 8]
            .try_into()
            .unwrap();

        if identity.verify(signature, packet_hash) {
            ProofResult::Valid
        } else {
            ProofResult::InvalidSignature
        }
    } else if proof.len() == constants::IMPL_LENGTH {
        // Implicit proof: [signature:64]
        let signature: &[u8; 64] = proof[..constants::SIGLENGTH / 8]
            .try_into()
            .unwrap();

        if identity.verify(signature, packet_hash) {
            ProofResult::Valid
        } else {
            ProofResult::InvalidSignature
        }
    } else {
        ProofResult::InvalidLength
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_identity() -> Identity {
        Identity::from_private_key(&[0x42; 64])
    }

    #[test]
    fn test_explicit_proof_valid() {
        let identity = make_test_identity();
        let packet_hash = crate::hash::full_hash(b"test packet data");

        let signature = identity.sign(&packet_hash).unwrap();

        let mut proof = Vec::new();
        proof.extend_from_slice(&packet_hash);
        proof.extend_from_slice(&signature);

        assert_eq!(proof.len(), constants::EXPL_LENGTH);
        assert_eq!(validate_proof(&proof, &packet_hash, &identity), ProofResult::Valid);
    }

    #[test]
    fn test_explicit_proof_wrong_hash() {
        let identity = make_test_identity();
        let packet_hash = crate::hash::full_hash(b"test packet data");
        let wrong_hash = crate::hash::full_hash(b"wrong data");

        let signature = identity.sign(&packet_hash).unwrap();

        let mut proof = Vec::new();
        proof.extend_from_slice(&wrong_hash); // wrong hash in proof
        proof.extend_from_slice(&signature);

        assert_eq!(validate_proof(&proof, &packet_hash, &identity), ProofResult::InvalidHash);
    }

    #[test]
    fn test_explicit_proof_bad_signature() {
        let identity = make_test_identity();
        let packet_hash = crate::hash::full_hash(b"test packet data");

        let mut bad_sig = [0u8; 64];
        bad_sig[0] = 0xFF;

        let mut proof = Vec::new();
        proof.extend_from_slice(&packet_hash);
        proof.extend_from_slice(&bad_sig);

        assert_eq!(validate_proof(&proof, &packet_hash, &identity), ProofResult::InvalidSignature);
    }

    #[test]
    fn test_implicit_proof_valid() {
        let identity = make_test_identity();
        let packet_hash = crate::hash::full_hash(b"test packet data");

        let signature = identity.sign(&packet_hash).unwrap();

        assert_eq!(signature.len(), constants::IMPL_LENGTH);
        assert_eq!(validate_proof(&signature, &packet_hash, &identity), ProofResult::Valid);
    }

    #[test]
    fn test_implicit_proof_bad_signature() {
        let identity = make_test_identity();
        let packet_hash = crate::hash::full_hash(b"test packet data");

        let bad_sig = [0u8; 64];
        assert_eq!(validate_proof(&bad_sig, &packet_hash, &identity), ProofResult::InvalidSignature);
    }

    #[test]
    fn test_wrong_length_proof() {
        let identity = make_test_identity();
        let packet_hash = crate::hash::full_hash(b"test packet data");

        let proof = [0u8; 50]; // wrong length
        assert_eq!(validate_proof(&proof, &packet_hash, &identity), ProofResult::InvalidLength);
    }
}
