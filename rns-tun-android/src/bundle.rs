use std::io;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const MEMORY_KIB: u32 = 32 * 1024;
const ITERATIONS: u32 = 3;
const LANES: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    format: String,
    version: u8,
    bundle_type: String,
    kdf: Kdf,
    cipher: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Kdf {
    name: String,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
}

pub fn encrypt(bundle_type: &str, plaintext: &[u8], password: &str) -> io::Result<Vec<u8>> {
    validate_bundle_type(bundle_type)?;
    if password.chars().count() < 10 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "export password must contain at least 10 characters",
        ));
    }
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let mut key = derive_key(password, &salt, MEMORY_KIB, ITERATIONS, LANES)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let aad = associated_data(bundle_type);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bundle encryption failed"))?;
    key.zeroize();
    serde_json::to_vec(&Envelope {
        format: "rntun-bundle".into(),
        version: 1,
        bundle_type: bundle_type.into(),
        kdf: Kdf {
            name: "argon2id".into(),
            memory_kib: MEMORY_KIB,
            iterations: ITERATIONS,
            lanes: LANES,
        },
        cipher: "xchacha20-poly1305".into(),
        salt: URL_SAFE_NO_PAD.encode(salt),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
    .map_err(io::Error::other)
}

pub fn decrypt(expected_type: &str, encoded: &[u8], password: &str) -> io::Result<Vec<u8>> {
    validate_bundle_type(expected_type)?;
    let envelope: Envelope = serde_json::from_slice(encoded).map_err(io::Error::other)?;
    if envelope.format != "rntun-bundle"
        || envelope.version != 1
        || envelope.bundle_type != expected_type
        || envelope.kdf.name != "argon2id"
        || envelope.cipher != "xchacha20-poly1305"
        || envelope.kdf.memory_kib != MEMORY_KIB
        || envelope.kdf.iterations != ITERATIONS
        || envelope.kdf.lanes != LANES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported or mismatched rntun bundle",
        ));
    }
    let salt = URL_SAFE_NO_PAD
        .decode(envelope.salt)
        .map_err(io::Error::other)?;
    let nonce = URL_SAFE_NO_PAD
        .decode(envelope.nonce)
        .map_err(io::Error::other)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(envelope.ciphertext)
        .map_err(io::Error::other)?;
    if salt.len() != SALT_LEN || nonce.len() != NONCE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid rntun bundle salt or nonce",
        ));
    }
    let mut key = derive_key(
        password,
        &salt,
        envelope.kdf.memory_kib,
        envelope.kdf.iterations,
        envelope.kdf.lanes,
    )?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let aad = associated_data(expected_type);
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wrong password or tampered rntun bundle",
            )
        })?;
    key.zeroize();
    Ok(plaintext)
}

fn derive_key(
    password: &str,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
) -> io::Result<[u8; KEY_LEN]> {
    let params = Params::new(memory_kib, iterations, lanes, Some(KEY_LEN))
        .map_err(|error| io::Error::other(error.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(key)
}

fn associated_data(bundle_type: &str) -> String {
    format!("rntun-bundle-v1:{bundle_type}")
}

fn validate_bundle_type(bundle_type: &str) -> io::Result<()> {
    if matches!(bundle_type, "profile" | "identity") {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bundle type must be profile or identity",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_authentication() {
        let encoded = encrypt("profile", b"secret profile", "correct horse").unwrap();
        assert_eq!(
            decrypt("profile", &encoded, "correct horse").unwrap(),
            b"secret profile"
        );
        assert!(decrypt("profile", &encoded, "wrong password").is_err());
        assert!(decrypt("identity", &encoded, "correct horse").is_err());
        let mut tampered = encoded;
        let last = tampered.len() - 2;
        tampered[last] ^= 1;
        assert!(decrypt("profile", &tampered, "correct horse").is_err());
    }

    #[test]
    fn rejects_short_passwords() {
        assert!(encrypt("profile", b"x", "short").is_err());
    }
}
