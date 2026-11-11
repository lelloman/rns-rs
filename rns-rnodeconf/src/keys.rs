//! The two signing keys upstream `rnodeconf` keeps in its firmware
//! directory: `signing.key`, a 1024-bit RSA key (PKCS#8 DER) that signs a
//! device's EEPROM checksum, and `device.key`, a Reticulum identity whose
//! Ed25519 key signs a device's hash.

use std::path::{Path, PathBuf};

use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::sha2::Sha256;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;

/// upstream's EEPROM signing key size.
const SIGNING_KEY_BITS: usize = 1024;

pub fn signing_key_path(firmware_dir: &Path) -> PathBuf {
    firmware_dir.join("signing.key")
}

pub fn device_key_path(firmware_dir: &Path) -> PathBuf {
    firmware_dir.join("device.key")
}

/// A new EEPROM signing key, as PKCS#8 DER.
pub fn generate_signing_key() -> Result<Vec<u8>, String> {
    let mut rng = getrandom::SysRng;
    let key = rsa::PrivateKey::new(&mut rng, SIGNING_KEY_BITS).map_err(|e| e.to_string())?;
    let der = key.to_pkcs8_der().map_err(|e| e.to_string())?;
    Ok(der.as_bytes().to_vec())
}

/// The DER SubjectPublicKeyInfo of a PKCS#8 signing key.
pub fn signing_public_key(private_der: &[u8]) -> Result<Vec<u8>, String> {
    let key = rsa::PrivateKey::from_pkcs8_der(private_der).map_err(|e| e.to_string())?;
    let public = key
        .to_public_key()
        .to_public_key_der()
        .map_err(|e| e.to_string())?;
    Ok(public.as_bytes().to_vec())
}

/// Sign an EEPROM checksum as upstream does: RSA-PSS with SHA-256,
/// MGF1(SHA-256) and the maximum salt length (`PSS.MAX_LENGTH`), which is
/// what upstream's verifier requires.
pub fn sign_checksum(private_der: &[u8], checksum: &[u8]) -> Result<Vec<u8>, String> {
    let key = rsa::PrivateKey::from_pkcs8_der(private_der).map_err(|e| e.to_string())?;
    let mod_bits = key.to_public_key().n().bit_width() as usize;
    let em_len = (mod_bits - 1).div_ceil(8);
    let salt_len = em_len - 32 - 2;
    let signer = rsa::pss::SigningKey::<Sha256>::new_with_salt_len(key, salt_len);
    let mut rng = getrandom::SysRng;
    let signature = signer
        .try_sign_with_rng(&mut rng, checksum)
        .map_err(|e| e.to_string())?;
    Ok(signature.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature;

    #[test]
    fn signatures_verify_as_upstream_requires() {
        let private = generate_signing_key().unwrap();
        let public = signing_public_key(&private).unwrap();
        let key = signature::parse_public_key(&public).unwrap();
        let checksum = [0x42u8; 16];
        let signed = sign_checksum(&private, &checksum).unwrap();
        assert_eq!(signed.len(), 128);
        // The stage 1 verifier requires the maximum salt length.
        assert!(signature::verify_pss(&key, &checksum, &signed));
        assert!(!signature::verify_pss(&key, &[0x43; 16], &signed));
        // The local key reader derives the same public key.
        let derived = signature::public_key_of_private(&private).unwrap();
        assert_eq!(signature::encode_public_key(&derived), public);
    }

    #[test]
    fn reads_cryptography_generated_keys() {
        let private =
            signature::unhex(include_str!("../tests/vectors/pss_private_key_pkcs8.hex")).unwrap();
        let expected =
            signature::unhex(include_str!("../tests/vectors/pss_public_key.hex")).unwrap();
        assert_eq!(signing_public_key(&private).unwrap(), expected);
    }
}
