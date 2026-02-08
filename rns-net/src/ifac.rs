//! IFAC (Interface Access Codes) — per-interface cryptographic authentication.
//!
//! Matches `Transport.py:894-933` (outbound masking) and `Transport.py:1241-1303`
//! (inbound unmasking). Key derivation matches `Reticulum.py:811-829`.

use rns_crypto::hkdf;
use rns_crypto::identity::Identity;
use rns_crypto::sha256;

/// IFAC salt from `Reticulum.py:152`.
pub const IFAC_SALT: [u8; 32] = [
    0xad, 0xf5, 0x4d, 0x88, 0x2c, 0x9a, 0x9b, 0x80,
    0x77, 0x1e, 0xb4, 0x99, 0x5d, 0x70, 0x2d, 0x4a,
    0x3e, 0x73, 0x33, 0x91, 0xb2, 0xa0, 0xf5, 0x3f,
    0x41, 0x6d, 0x9f, 0x90, 0x7e, 0x55, 0xcf, 0xf8,
];

pub const IFAC_MIN_SIZE: usize = 1;

/// Pre-computed IFAC state for an interface.
pub struct IfacState {
    pub size: usize,
    pub key: [u8; 64],
    pub identity: Identity,
}

/// Derive IFAC state from network name and/or passphrase.
///
/// Matches Python `Reticulum.py:811-829`:
/// ```text
/// ifac_origin = SHA256(netname) || SHA256(netkey)
/// ifac_origin_hash = SHA256(ifac_origin)
/// ifac_key = hkdf(length=64, derive_from=ifac_origin_hash, salt=IFAC_SALT)
/// ifac_identity = Identity.from_bytes(ifac_key)
/// ```
pub fn derive_ifac(
    netname: Option<&str>,
    netkey: Option<&str>,
    size: usize,
) -> IfacState {
    let mut ifac_origin = Vec::new();

    if let Some(name) = netname {
        let hash = sha256::sha256(name.as_bytes());
        ifac_origin.extend_from_slice(&hash);
    }

    if let Some(key) = netkey {
        let hash = sha256::sha256(key.as_bytes());
        ifac_origin.extend_from_slice(&hash);
    }

    let ifac_origin_hash = sha256::sha256(&ifac_origin);
    let ifac_key_vec = hkdf::hkdf(64, &ifac_origin_hash, Some(&IFAC_SALT), None)
        .expect("HKDF should not fail with valid inputs");

    let mut ifac_key = [0u8; 64];
    ifac_key.copy_from_slice(&ifac_key_vec);

    let identity = Identity::from_private_key(&ifac_key);

    IfacState {
        size: size.max(IFAC_MIN_SIZE),
        key: ifac_key,
        identity,
    }
}

/// Mask an outbound packet. Returns new packet with IFAC inserted and masked.
///
/// Matches `Transport.py:894-930`:
/// 1. `ifac = identity.sign(raw)[-ifac_size:]`
/// 2. `mask = hkdf(length=len(raw)+ifac_size, derive_from=ifac, salt=ifac_key)`
/// 3. New packet: `[flags|0x80, hops] + ifac + raw[2:]`
/// 4. XOR mask: flags byte masked BUT 0x80 forced on; hops masked; IFAC NOT masked; payload masked
pub fn mask_outbound(raw: &[u8], state: &IfacState) -> Vec<u8> {
    if raw.len() < 2 {
        return raw.to_vec();
    }

    // Calculate IFAC: last `size` bytes of the Ed25519 signature
    let sig = state.identity.sign(raw)
        .expect("IFAC identity must have private key");
    let ifac = &sig[64 - state.size..];

    // Generate mask
    let mask = hkdf::hkdf(
        raw.len() + state.size,
        ifac,
        Some(&state.key),
        None,
    )
    .expect("HKDF should not fail");

    // Build new_raw: [flags|0x80, hops] + ifac + raw[2..]
    let mut new_raw = Vec::with_capacity(raw.len() + state.size);
    new_raw.push(raw[0] | 0x80); // Set IFAC flag
    new_raw.push(raw[1]);
    new_raw.extend_from_slice(ifac);
    new_raw.extend_from_slice(&raw[2..]);

    // Apply mask
    let mut masked = Vec::with_capacity(new_raw.len());
    for (i, &byte) in new_raw.iter().enumerate() {
        if i == 0 {
            // Mask first header byte, but force IFAC flag on
            masked.push((byte ^ mask[i]) | 0x80);
        } else if i == 1 || i > state.size + 1 {
            // Mask second header byte and payload (after IFAC)
            masked.push(byte ^ mask[i]);
        } else {
            // Don't mask the IFAC itself (positions 2..2+ifac_size)
            masked.push(byte);
        }
    }

    masked
}

/// Unmask an inbound packet. Returns original packet without IFAC, or None if invalid.
///
/// Matches `Transport.py:1241-1303`.
pub fn unmask_inbound(raw: &[u8], state: &IfacState) -> Option<Vec<u8>> {
    // Check minimum length
    if raw.len() <= 2 + state.size {
        return None;
    }

    // Check IFAC flag
    if raw[0] & 0x80 != 0x80 {
        return None;
    }

    // Extract IFAC
    let ifac = &raw[2..2 + state.size];

    // Generate mask
    let mask = hkdf::hkdf(
        raw.len(),
        ifac,
        Some(&state.key),
        None,
    )
    .expect("HKDF should not fail");

    // Unmask: header bytes and payload are unmasked, IFAC is left as-is
    let mut unmasked = Vec::with_capacity(raw.len());
    for (i, &byte) in raw.iter().enumerate() {
        if i <= 1 || i > state.size + 1 {
            // Unmask header bytes and payload
            unmasked.push(byte ^ mask[i]);
        } else {
            // Don't unmask IFAC itself
            unmasked.push(byte);
        }
    }

    // Clear IFAC flag
    let flags_cleared = unmasked[0] & 0x7F;
    let hops = unmasked[1];

    // Re-assemble packet without IFAC
    let mut new_raw = Vec::with_capacity(raw.len() - state.size);
    new_raw.push(flags_cleared);
    new_raw.push(hops);
    new_raw.extend_from_slice(&unmasked[2 + state.size..]);

    // Verify IFAC: expected = identity.sign(new_raw)[-ifac_size:]
    let expected_sig = state.identity.sign(&new_raw)
        .expect("IFAC identity must have private key");
    let expected_ifac = &expected_sig[64 - state.size..];

    if ifac == expected_ifac {
        Some(new_raw)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_ifac_netname_only() {
        let state = derive_ifac(Some("testnet"), None, 8);
        assert_eq!(state.size, 8);
        assert_eq!(state.key.len(), 64);
        // Identity should be constructable
        assert!(state.identity.get_private_key().is_some());
    }

    #[test]
    fn derive_ifac_netkey_only() {
        let state = derive_ifac(None, Some("secretpassword"), 16);
        assert_eq!(state.size, 16);
        assert!(state.identity.get_private_key().is_some());
    }

    #[test]
    fn derive_ifac_both() {
        let state = derive_ifac(Some("testnet"), Some("mypassword"), 8);
        assert_eq!(state.size, 8);
        // Verify deterministic: same inputs → same key
        let state2 = derive_ifac(Some("testnet"), Some("mypassword"), 8);
        assert_eq!(state.key, state2.key);
    }

    #[test]
    fn mask_unmask_roundtrip() {
        let state = derive_ifac(Some("testnet"), Some("password"), 8);

        // Create a fake packet (flags + hops + 32 bytes payload)
        let mut raw = vec![0x00, 0x01]; // flags=0, hops=1
        raw.extend_from_slice(&[0x42u8; 32]);

        let masked = mask_outbound(&raw, &state);
        assert_ne!(masked, raw);
        assert!(masked.len() > raw.len()); // IFAC bytes added

        let recovered = unmask_inbound(&masked, &state).expect("unmask should succeed");
        assert_eq!(recovered, raw);
    }

    #[test]
    fn mask_sets_ifac_flag() {
        let state = derive_ifac(Some("testnet"), None, 8);

        let raw = vec![0x00, 0x01, 0x42, 0x43, 0x44, 0x45];
        let masked = mask_outbound(&raw, &state);

        // First byte should have 0x80 set
        assert_eq!(masked[0] & 0x80, 0x80);
    }

    #[test]
    fn unmask_rejects_bad_ifac() {
        let state = derive_ifac(Some("testnet"), Some("password"), 8);

        let mut raw = vec![0x00, 0x01];
        raw.extend_from_slice(&[0x42u8; 32]);

        let mut masked = mask_outbound(&raw, &state);

        // Tamper with IFAC bytes (positions 2..10)
        masked[3] ^= 0xFF;

        let result = unmask_inbound(&masked, &state);
        assert!(result.is_none());
    }

    #[test]
    fn unmask_rejects_missing_flag() {
        let state = derive_ifac(Some("testnet"), None, 8);

        // Packet without 0x80 flag
        let raw = vec![0x00, 0x01, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x50];
        let result = unmask_inbound(&raw, &state);
        assert!(result.is_none());
    }

    #[test]
    fn unmask_rejects_too_short() {
        let state = derive_ifac(Some("testnet"), None, 8);

        // Packet too short: only 2 + 7 bytes (need at least 2 + ifac_size + 1)
        let raw = vec![0x80, 0x01, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48];
        let result = unmask_inbound(&raw, &state);
        assert!(result.is_none());
    }
}
