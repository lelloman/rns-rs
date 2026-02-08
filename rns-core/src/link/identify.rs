use alloc::vec::Vec;

use rns_crypto::identity::Identity;
use rns_crypto::ed25519::Ed25519PublicKey;

use crate::constants::{KEYSIZE, SIGLENGTH};
use super::types::{LinkError, LinkId};

/// Build LINKIDENTIFY plaintext: `[public_key:64][signature:64]`.
///
/// `signed_data = link_id + public_key`
pub fn build_identify_data(identity: &Identity, link_id: &LinkId) -> Result<Vec<u8>, LinkError> {
    let public_key = identity.get_public_key()
        .ok_or(LinkError::CryptoError)?;

    let mut signed_data = Vec::with_capacity(16 + 64);
    signed_data.extend_from_slice(link_id);
    signed_data.extend_from_slice(&public_key);

    let signature = identity.sign(&signed_data)
        .map_err(|_| LinkError::CryptoError)?;

    let mut data = Vec::with_capacity(128);
    data.extend_from_slice(&public_key);
    data.extend_from_slice(&signature);

    Ok(data)
}

/// Validate LINKIDENTIFY plaintext.
///
/// Returns `(identity_hash, public_key)` on success.
pub fn validate_identify_data(
    plaintext: &[u8],
    link_id: &LinkId,
) -> Result<([u8; 16], [u8; 64]), LinkError> {
    let expected_len = KEYSIZE / 8 + SIGLENGTH / 8; // 64 + 64 = 128
    if plaintext.len() != expected_len {
        return Err(LinkError::InvalidData);
    }

    let mut public_key = [0u8; 64];
    public_key.copy_from_slice(&plaintext[..64]);

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&plaintext[64..128]);

    let mut signed_data = Vec::with_capacity(16 + 64);
    signed_data.extend_from_slice(link_id);
    signed_data.extend_from_slice(&public_key);

    // Verify using Ed25519 signing key (second half of public key)
    let sig_pub = Ed25519PublicKey::from_bytes(&{
        let mut b = [0u8; 32];
        b.copy_from_slice(&public_key[32..64]);
        b
    });

    if sig_pub.verify(&signature, &signed_data) {
        // Compute identity hash
        let identity = Identity::from_public_key(&public_key);
        let identity_hash = *identity.hash();
        Ok((identity_hash, public_key))
    } else {
        Err(LinkError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::FixedRng;

    #[test]
    fn test_identify_roundtrip() {
        let mut rng = FixedRng::new(&[0x42; 128]);
        let identity = Identity::new(&mut rng);
        let link_id: LinkId = [0xAA; 16];

        let data = build_identify_data(&identity, &link_id).unwrap();
        assert_eq!(data.len(), 128);

        let (hash, pubkey) = validate_identify_data(&data, &link_id).unwrap();
        assert_eq!(hash, *identity.hash());
        assert_eq!(pubkey, identity.get_public_key().unwrap());
    }

    #[test]
    fn test_identify_wrong_link_id() {
        let mut rng = FixedRng::new(&[0x42; 128]);
        let identity = Identity::new(&mut rng);
        let link_id: LinkId = [0xAA; 16];
        let wrong_id: LinkId = [0xBB; 16];

        let data = build_identify_data(&identity, &link_id).unwrap();
        assert_eq!(validate_identify_data(&data, &wrong_id), Err(LinkError::InvalidSignature));
    }

    #[test]
    fn test_identify_tampered() {
        let mut rng = FixedRng::new(&[0x42; 128]);
        let identity = Identity::new(&mut rng);
        let link_id: LinkId = [0xAA; 16];

        let mut data = build_identify_data(&identity, &link_id).unwrap();
        data[10] ^= 0xFF; // tamper with public key
        assert_eq!(validate_identify_data(&data, &link_id), Err(LinkError::InvalidSignature));
    }

    #[test]
    fn test_identify_invalid_length() {
        let link_id: LinkId = [0xAA; 16];
        assert_eq!(validate_identify_data(&[0u8; 64], &link_id), Err(LinkError::InvalidData));
    }

    #[test]
    fn test_identify_public_only_fails() {
        let mut rng = FixedRng::new(&[0x42; 128]);
        let identity = Identity::new(&mut rng);
        let pubkey = identity.get_public_key().unwrap();
        let public_only = Identity::from_public_key(&pubkey);
        let link_id: LinkId = [0xAA; 16];

        // Should fail because public-only identity can't sign
        assert!(build_identify_data(&public_only, &link_id).is_err());
    }
}
