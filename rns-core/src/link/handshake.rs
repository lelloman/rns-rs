use alloc::vec::Vec;

use rns_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use rns_crypto::hkdf::hkdf;
use rns_crypto::x25519::{X25519PrivateKey, X25519PublicKey};

use crate::constants::{LINK_ECPUBSIZE, LINK_MTU_BYTEMASK, LINK_MTU_SIZE, LINK_MODE_BYTEMASK};
use crate::hash::truncated_hash;
use super::types::{LinkError, LinkId, LinkMode};

/// Compute link_id from a LINKREQUEST packet's hashable part.
///
/// The signalling bytes (if present) are stripped from the end before hashing.
/// `extra_bytes_len` is `data.len() - ECPUBSIZE` (0 or MTU_SIZE).
pub fn compute_link_id(hashable_part: &[u8], extra_bytes_len: usize) -> LinkId {
    let end = if extra_bytes_len > 0 && hashable_part.len() > extra_bytes_len {
        hashable_part.len() - extra_bytes_len
    } else {
        hashable_part.len()
    };
    truncated_hash(&hashable_part[..end])
}

/// Build signalling bytes: 3 big-endian bytes encoding MTU (21 bits) + mode (3 bits).
///
/// Format: `(mtu & 0x1FFFFF) + (((mode << 5) & 0xE0) << 16)`, packed as big-endian u32,
/// then take the last 3 bytes.
pub fn build_signalling_bytes(mtu: u32, mode: LinkMode) -> [u8; 3] {
    let mode_bits = ((mode.mode_byte() << 5) & LINK_MODE_BYTEMASK) as u32;
    let signalling_value = (mtu & LINK_MTU_BYTEMASK) + (mode_bits << 16);
    let bytes = signalling_value.to_be_bytes();
    [bytes[1], bytes[2], bytes[3]]
}

/// Parse signalling bytes → (mtu, mode).
pub fn parse_signalling_bytes(bytes: &[u8; 3]) -> Result<(u32, LinkMode), LinkError> {
    let mtu = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32);
    let mode_byte = (bytes[0] & LINK_MODE_BYTEMASK) >> 5;
    let mtu_val = mtu & LINK_MTU_BYTEMASK;
    let mode = LinkMode::from_byte(mode_byte)?;
    Ok((mtu_val, mode))
}

/// Build LINKREQUEST data: `[x25519_pub:32][ed25519_pub:32][signalling:0-3]`.
pub fn build_linkrequest_data(
    pub_bytes: &[u8; 32],
    sig_pub_bytes: &[u8; 32],
    mtu: Option<u32>,
    mode: LinkMode,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(LINK_ECPUBSIZE + LINK_MTU_SIZE);
    data.extend_from_slice(pub_bytes);
    data.extend_from_slice(sig_pub_bytes);
    if let Some(mtu_val) = mtu {
        let sig_bytes = build_signalling_bytes(mtu_val, mode);
        data.extend_from_slice(&sig_bytes);
    }
    data
}

/// Parse LINKREQUEST data. Returns `(x25519_pub, ed25519_pub, mtu, mode)`.
pub fn parse_linkrequest_data(
    data: &[u8],
) -> Result<([u8; 32], [u8; 32], Option<u32>, LinkMode), LinkError> {
    if data.len() != LINK_ECPUBSIZE && data.len() != LINK_ECPUBSIZE + LINK_MTU_SIZE {
        return Err(LinkError::InvalidData);
    }

    let mut x25519_pub = [0u8; 32];
    let mut ed25519_pub = [0u8; 32];
    x25519_pub.copy_from_slice(&data[..32]);
    ed25519_pub.copy_from_slice(&data[32..64]);

    if data.len() == LINK_ECPUBSIZE + LINK_MTU_SIZE {
        let mut sig_bytes = [0u8; 3];
        sig_bytes.copy_from_slice(&data[LINK_ECPUBSIZE..LINK_ECPUBSIZE + LINK_MTU_SIZE]);
        let (mtu, mode) = parse_signalling_bytes(&sig_bytes)?;
        Ok((x25519_pub, ed25519_pub, Some(mtu), mode))
    } else {
        Ok((x25519_pub, ed25519_pub, None, LinkMode::Aes256Cbc))
    }
}

/// Build LRPROOF data: `[signature:64][x25519_pub:32][signalling:0-3]`.
///
/// Signs: `link_id + pub_bytes + sig_pub_bytes + signalling_bytes`.
pub fn build_lrproof(
    link_id: &LinkId,
    pub_bytes: &[u8; 32],
    sig_pub_bytes: &[u8; 32],
    sig_prv: &Ed25519PrivateKey,
    mtu: Option<u32>,
    mode: LinkMode,
) -> Vec<u8> {
    let signalling_bytes = if let Some(mtu_val) = mtu {
        build_signalling_bytes(mtu_val, mode).to_vec()
    } else {
        Vec::new()
    };

    let mut signed_data = Vec::with_capacity(16 + 32 + 32 + signalling_bytes.len());
    signed_data.extend_from_slice(link_id);
    signed_data.extend_from_slice(pub_bytes);
    signed_data.extend_from_slice(sig_pub_bytes);
    signed_data.extend_from_slice(&signalling_bytes);

    let signature = sig_prv.sign(&signed_data);

    let mut proof_data = Vec::with_capacity(64 + 32 + signalling_bytes.len());
    proof_data.extend_from_slice(&signature);
    proof_data.extend_from_slice(pub_bytes);
    proof_data.extend_from_slice(&signalling_bytes);

    proof_data
}

/// Validate LRPROOF. Returns peer X25519 public key bytes on success.
///
/// Expects `proof_data = [signature:64][x25519_pub:32][signalling:0-3]`.
/// Validates against `signed_data = link_id + peer_x25519_pub + peer_sig_pub + signalling`.
pub fn validate_lrproof(
    proof_data: &[u8],
    link_id: &LinkId,
    peer_sig_pub: &Ed25519PublicKey,
    peer_sig_pub_bytes: &[u8; 32],
) -> Result<([u8; 32], Option<u32>, LinkMode), LinkError> {
    let sig_len = 64;
    let pub_len = 32;

    if proof_data.len() != sig_len + pub_len && proof_data.len() != sig_len + pub_len + LINK_MTU_SIZE {
        return Err(LinkError::InvalidData);
    }

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&proof_data[..sig_len]);

    let mut peer_pub = [0u8; 32];
    peer_pub.copy_from_slice(&proof_data[sig_len..sig_len + pub_len]);

    let signalling_bytes = &proof_data[sig_len + pub_len..];

    let (mtu, mode) = if signalling_bytes.len() == LINK_MTU_SIZE {
        let mut sb = [0u8; 3];
        sb.copy_from_slice(signalling_bytes);
        let (m, md) = parse_signalling_bytes(&sb)?;
        (Some(m), md)
    } else {
        (None, LinkMode::Aes256Cbc)
    };

    let mut signed_data = Vec::with_capacity(16 + 32 + 32 + signalling_bytes.len());
    signed_data.extend_from_slice(link_id);
    signed_data.extend_from_slice(&peer_pub);
    signed_data.extend_from_slice(peer_sig_pub_bytes);
    signed_data.extend_from_slice(signalling_bytes);

    if peer_sig_pub.verify(&signature, &signed_data) {
        Ok((peer_pub, mtu, mode))
    } else {
        Err(LinkError::InvalidSignature)
    }
}

/// Derive session key using HKDF.
///
/// `shared_key` is the raw ECDH output (32 bytes).
/// Salt = link_id, context = None.
/// Output length depends on mode: 32 for AES-128, 64 for AES-256.
pub fn derive_session_key(
    shared_key: &[u8; 32],
    link_id: &LinkId,
    mode: LinkMode,
) -> Result<Vec<u8>, LinkError> {
    let length = mode.derived_key_length();
    hkdf(length, shared_key, Some(link_id), None)
        .map_err(|_| LinkError::CryptoError)
}

/// Perform ECDH key exchange and derive session key.
pub fn perform_key_exchange(
    prv: &X25519PrivateKey,
    peer_pub_bytes: &[u8; 32],
    link_id: &LinkId,
    mode: LinkMode,
) -> Result<Vec<u8>, LinkError> {
    let peer_pub = X25519PublicKey::from_bytes(peer_pub_bytes);
    let shared_key = prv.exchange(&peer_pub);
    derive_session_key(&shared_key, link_id, mode)
}

/// Pack RTT as msgpack float64: `0xcb` + 8 bytes big-endian.
pub fn pack_rtt(rtt: f64) -> Vec<u8> {
    let mut data = Vec::with_capacity(9);
    data.push(0xcb);
    data.extend_from_slice(&rtt.to_be_bytes());
    data
}

/// Unpack RTT from msgpack float64.
pub fn unpack_rtt(data: &[u8]) -> Option<f64> {
    if data.len() == 9 && data[0] == 0xcb {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[1..9]);
        Some(f64::from_be_bytes(bytes))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::FixedRng;

    #[test]
    fn test_signalling_bytes_roundtrip() {
        let mtu = 500u32;
        let mode = LinkMode::Aes256Cbc;
        let bytes = build_signalling_bytes(mtu, mode);
        let (parsed_mtu, parsed_mode) = parse_signalling_bytes(&bytes).unwrap();
        assert_eq!(parsed_mtu, mtu);
        assert_eq!(parsed_mode, mode);
    }

    #[test]
    fn test_signalling_bytes_aes128() {
        let mtu = 1234u32;
        let mode = LinkMode::Aes128Cbc;
        let bytes = build_signalling_bytes(mtu, mode);
        let (parsed_mtu, parsed_mode) = parse_signalling_bytes(&bytes).unwrap();
        assert_eq!(parsed_mtu, mtu);
        assert_eq!(parsed_mode, mode);
    }

    #[test]
    fn test_signalling_bytes_max_mtu() {
        let mtu = LINK_MTU_BYTEMASK; // maximum 21-bit value
        let mode = LinkMode::Aes256Cbc;
        let bytes = build_signalling_bytes(mtu, mode);
        let (parsed_mtu, parsed_mode) = parse_signalling_bytes(&bytes).unwrap();
        assert_eq!(parsed_mtu, mtu);
        assert_eq!(parsed_mode, mode);
    }

    #[test]
    fn test_linkrequest_data_roundtrip() {
        let pub_bytes = [0xAAu8; 32];
        let sig_pub_bytes = [0xBBu8; 32];
        let data = build_linkrequest_data(&pub_bytes, &sig_pub_bytes, Some(500), LinkMode::Aes256Cbc);
        assert_eq!(data.len(), LINK_ECPUBSIZE + LINK_MTU_SIZE);

        let (p, s, mtu, mode) = parse_linkrequest_data(&data).unwrap();
        assert_eq!(p, pub_bytes);
        assert_eq!(s, sig_pub_bytes);
        assert_eq!(mtu, Some(500));
        assert_eq!(mode, LinkMode::Aes256Cbc);
    }

    #[test]
    fn test_linkrequest_data_no_mtu() {
        let pub_bytes = [0xAAu8; 32];
        let sig_pub_bytes = [0xBBu8; 32];
        let data = build_linkrequest_data(&pub_bytes, &sig_pub_bytes, None, LinkMode::Aes256Cbc);
        assert_eq!(data.len(), LINK_ECPUBSIZE);

        let (p, s, mtu, mode) = parse_linkrequest_data(&data).unwrap();
        assert_eq!(p, pub_bytes);
        assert_eq!(s, sig_pub_bytes);
        assert_eq!(mtu, None);
        assert_eq!(mode, LinkMode::Aes256Cbc); // default when no signalling
    }

    #[test]
    fn test_linkrequest_data_invalid_size() {
        let data = [0u8; 10];
        assert_eq!(parse_linkrequest_data(&data), Err(LinkError::InvalidData));
    }

    #[test]
    fn test_compute_link_id_no_extra() {
        let hashable = [0x42u8; 40];
        let id = compute_link_id(&hashable, 0);
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn test_compute_link_id_with_extra() {
        let hashable = [0x42u8; 43]; // 40 base + 3 signalling
        let id_with_extra = compute_link_id(&hashable, 3);
        let id_base = compute_link_id(&hashable[..40], 0);
        assert_eq!(id_with_extra, id_base);
    }

    #[test]
    fn test_lrproof_sign_verify() {
        let mut rng = FixedRng::new(&[0x11; 64]);
        let sig_prv = Ed25519PrivateKey::generate(&mut rng);
        let sig_pub = sig_prv.public_key();
        let sig_pub_bytes = sig_pub.public_bytes();

        let mut rng2 = FixedRng::new(&[0x22; 64]);
        let x_prv = rns_crypto::x25519::X25519PrivateKey::generate(&mut rng2);
        let pub_bytes = x_prv.public_key().public_bytes();

        let link_id: LinkId = [0xAA; 16];
        let mtu = Some(500u32);
        let mode = LinkMode::Aes256Cbc;

        let proof = build_lrproof(&link_id, &pub_bytes, &sig_pub_bytes, &sig_prv, mtu, mode);

        let result = validate_lrproof(&proof, &link_id, &sig_pub, &sig_pub_bytes);
        assert!(result.is_ok());
        let (peer_pub, parsed_mtu, parsed_mode) = result.unwrap();
        assert_eq!(peer_pub, pub_bytes);
        assert_eq!(parsed_mtu, mtu);
        assert_eq!(parsed_mode, mode);
    }

    #[test]
    fn test_lrproof_wrong_link_id() {
        let mut rng = FixedRng::new(&[0x11; 64]);
        let sig_prv = Ed25519PrivateKey::generate(&mut rng);
        let sig_pub = sig_prv.public_key();
        let sig_pub_bytes = sig_pub.public_bytes();

        let pub_bytes = [0x33u8; 32];
        let link_id: LinkId = [0xAA; 16];
        let wrong_id: LinkId = [0xBB; 16];

        let proof = build_lrproof(&link_id, &pub_bytes, &sig_pub_bytes, &sig_prv, None, LinkMode::Aes256Cbc);
        let result = validate_lrproof(&proof, &wrong_id, &sig_pub, &sig_pub_bytes);
        assert_eq!(result, Err(LinkError::InvalidSignature));
    }

    #[test]
    fn test_derive_session_key_aes128() {
        let shared = [0x42u8; 32];
        let link_id = [0xAA; 16];
        let key = derive_session_key(&shared, &link_id, LinkMode::Aes128Cbc).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_session_key_aes256() {
        let shared = [0x42u8; 32];
        let link_id = [0xAA; 16];
        let key = derive_session_key(&shared, &link_id, LinkMode::Aes256Cbc).unwrap();
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn test_rtt_pack_unpack() {
        let rtt = 0.123456789;
        let packed = pack_rtt(rtt);
        assert_eq!(packed.len(), 9);
        assert_eq!(packed[0], 0xcb);
        let unpacked = unpack_rtt(&packed).unwrap();
        assert_eq!(unpacked, rtt);
    }

    #[test]
    fn test_rtt_unpack_invalid() {
        assert_eq!(unpack_rtt(&[0xcb, 0x00]), None);
        assert_eq!(unpack_rtt(&[0xca, 0, 0, 0, 0, 0, 0, 0, 0]), None);
    }

    #[test]
    fn test_rtt_pack_zero() {
        let packed = pack_rtt(0.0);
        let unpacked = unpack_rtt(&packed).unwrap();
        assert_eq!(unpacked, 0.0);
    }
}
