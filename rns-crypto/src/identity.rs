use alloc::vec::Vec;
use core::fmt;

use crate::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use crate::hkdf;
use crate::sha256;
use crate::token::{Token, TokenError};
use crate::x25519::{X25519PrivateKey, X25519PublicKey};
use crate::Rng;

pub const KEYSIZE: usize = 512; // bits
pub const DERIVED_KEY_LENGTH: usize = 64; // bytes
pub const TRUNCATED_HASHLENGTH: usize = 128; // bits (16 bytes)

#[derive(Debug)]
pub enum CryptoError {
    NoPrivateKey,
    NoPublicKey,
    TokenError(TokenError),
    HkdfError(hkdf::HkdfError),
    InvalidCiphertext,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::NoPrivateKey => write!(f, "No private key"),
            CryptoError::NoPublicKey => write!(f, "No public key"),
            CryptoError::TokenError(e) => write!(f, "Token error: {}", e),
            CryptoError::HkdfError(e) => write!(f, "HKDF error: {}", e),
            CryptoError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
        }
    }
}

pub struct Identity {
    prv: Option<X25519PrivateKey>,
    sig_prv: Option<Ed25519PrivateKey>,
    pub_key: Option<X25519PublicKey>,
    sig_pub: Option<Ed25519PublicKey>,
    hash: [u8; 16],
}

impl Identity {
    pub fn new(rng: &mut dyn Rng) -> Self {
        let prv = X25519PrivateKey::generate(rng);
        let sig_prv = Ed25519PrivateKey::generate(rng);

        let pub_key = prv.public_key();
        let sig_pub = sig_prv.public_key();

        let mut pub_bytes = [0u8; 64];
        pub_bytes[..32].copy_from_slice(&pub_key.public_bytes());
        pub_bytes[32..].copy_from_slice(&sig_pub.public_bytes());

        let hash = truncated_hash(&pub_bytes);

        Identity {
            prv: Some(prv),
            sig_prv: Some(sig_prv),
            pub_key: Some(pub_key),
            sig_pub: Some(sig_pub),
            hash,
        }
    }

    pub fn from_private_key(prv_bytes: &[u8; 64]) -> Self {
        let x_prv_bytes: [u8; 32] = prv_bytes[..32].try_into().unwrap();
        let ed_seed: [u8; 32] = prv_bytes[32..].try_into().unwrap();

        let prv = X25519PrivateKey::from_bytes(&x_prv_bytes);
        let sig_prv = Ed25519PrivateKey::from_bytes(&ed_seed);

        let pub_key = prv.public_key();
        let sig_pub = sig_prv.public_key();

        let mut pub_bytes = [0u8; 64];
        pub_bytes[..32].copy_from_slice(&pub_key.public_bytes());
        pub_bytes[32..].copy_from_slice(&sig_pub.public_bytes());

        let hash = truncated_hash(&pub_bytes);

        Identity {
            prv: Some(prv),
            sig_prv: Some(sig_prv),
            pub_key: Some(pub_key),
            sig_pub: Some(sig_pub),
            hash,
        }
    }

    pub fn from_public_key(pub_bytes: &[u8; 64]) -> Self {
        let x_pub_bytes: [u8; 32] = pub_bytes[..32].try_into().unwrap();
        let ed_pub_bytes: [u8; 32] = pub_bytes[32..].try_into().unwrap();

        let pub_key = X25519PublicKey::from_bytes(&x_pub_bytes);
        let sig_pub = Ed25519PublicKey::from_bytes(&ed_pub_bytes);

        let hash = truncated_hash(pub_bytes);

        Identity {
            prv: None,
            sig_prv: None,
            pub_key: Some(pub_key),
            sig_pub: Some(sig_pub),
            hash,
        }
    }

    pub fn get_private_key(&self) -> Option<[u8; 64]> {
        match (&self.prv, &self.sig_prv) {
            (Some(prv), Some(sig_prv)) => {
                let mut result = [0u8; 64];
                result[..32].copy_from_slice(&prv.private_bytes());
                result[32..].copy_from_slice(&sig_prv.private_bytes());
                Some(result)
            }
            _ => None,
        }
    }

    pub fn get_public_key(&self) -> Option<[u8; 64]> {
        match (&self.pub_key, &self.sig_pub) {
            (Some(pub_key), Some(sig_pub)) => {
                let mut result = [0u8; 64];
                result[..32].copy_from_slice(&pub_key.public_bytes());
                result[32..].copy_from_slice(&sig_pub.public_bytes());
                Some(result)
            }
            _ => None,
        }
    }

    pub fn hash(&self) -> &[u8; 16] {
        &self.hash
    }

    pub fn encrypt(&self, plaintext: &[u8], rng: &mut dyn Rng) -> Result<Vec<u8>, CryptoError> {
        let pub_key = self.pub_key.as_ref().ok_or(CryptoError::NoPublicKey)?;

        let ephemeral = X25519PrivateKey::generate(rng);
        let ephemeral_pub_bytes = ephemeral.public_key().public_bytes();
        let shared_key = ephemeral.exchange(pub_key);

        let derived_key = hkdf::hkdf(
            DERIVED_KEY_LENGTH,
            &shared_key,
            Some(&self.hash),
            None,
        )
        .map_err(CryptoError::HkdfError)?;

        let token = Token::new(&derived_key).map_err(CryptoError::TokenError)?;
        let ciphertext = token.encrypt(plaintext, rng);

        let mut result = Vec::with_capacity(32 + ciphertext.len());
        result.extend_from_slice(&ephemeral_pub_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Encrypt with a specific ephemeral key and IV for deterministic testing
    pub fn encrypt_deterministic(
        &self,
        plaintext: &[u8],
        ephemeral_prv: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Vec<u8>, CryptoError> {
        let pub_key = self.pub_key.as_ref().ok_or(CryptoError::NoPublicKey)?;

        let ephemeral = X25519PrivateKey::from_bytes(ephemeral_prv);
        let ephemeral_pub_bytes = ephemeral.public_key().public_bytes();
        let shared_key = ephemeral.exchange(pub_key);

        let derived_key = hkdf::hkdf(
            DERIVED_KEY_LENGTH,
            &shared_key,
            Some(&self.hash),
            None,
        )
        .map_err(CryptoError::HkdfError)?;

        let token = Token::new(&derived_key).map_err(CryptoError::TokenError)?;
        let ciphertext = token.encrypt_with_iv(plaintext, iv);

        let mut result = Vec::with_capacity(32 + ciphertext.len());
        result.extend_from_slice(&ephemeral_pub_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt(&self, ciphertext_token: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let prv = self.prv.as_ref().ok_or(CryptoError::NoPrivateKey)?;

        if ciphertext_token.len() <= KEYSIZE / 8 / 2 {
            return Err(CryptoError::InvalidCiphertext);
        }

        let peer_pub_bytes: [u8; 32] = ciphertext_token[..32].try_into().unwrap();
        let peer_pub = X25519PublicKey::from_bytes(&peer_pub_bytes);
        let ciphertext = &ciphertext_token[32..];

        let shared_key = prv.exchange(&peer_pub);

        let derived_key = hkdf::hkdf(
            DERIVED_KEY_LENGTH,
            &shared_key,
            Some(&self.hash),
            None,
        )
        .map_err(CryptoError::HkdfError)?;

        let token = Token::new(&derived_key).map_err(CryptoError::TokenError)?;
        token.decrypt(ciphertext).map_err(CryptoError::TokenError)
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], CryptoError> {
        let sig_prv = self.sig_prv.as_ref().ok_or(CryptoError::NoPrivateKey)?;
        Ok(sig_prv.sign(message))
    }

    pub fn verify(&self, signature: &[u8; 64], message: &[u8]) -> bool {
        match &self.sig_pub {
            Some(sig_pub) => sig_pub.verify(signature, message),
            None => false,
        }
    }
}

fn truncated_hash(data: &[u8]) -> [u8; 16] {
    let full = sha256::sha256(data);
    let mut result = [0u8; 16];
    result.copy_from_slice(&full[..16]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FixedRng;

    #[test]
    fn test_identity_key_roundtrip() {
        let mut rng = FixedRng::new(&(0..64).collect::<Vec<u8>>());
        let id = Identity::new(&mut rng);
        let prv_bytes = id.get_private_key().unwrap();
        let id2 = Identity::from_private_key(&prv_bytes);
        assert_eq!(
            id.get_public_key().unwrap(),
            id2.get_public_key().unwrap()
        );
    }

    #[test]
    fn test_identity_hash() {
        let mut rng = FixedRng::new(&(0..64).collect::<Vec<u8>>());
        let id = Identity::new(&mut rng);
        let pub_key = id.get_public_key().unwrap();
        let expected_hash = truncated_hash(&pub_key);
        assert_eq!(*id.hash(), expected_hash);
    }

    #[test]
    fn test_identity_encrypt_decrypt_roundtrip() {
        let mut rng = FixedRng::new(&(0..128).collect::<Vec<u8>>());
        let id = Identity::new(&mut rng);
        let plaintext = b"Hello, Reticulum! This is a test of the encrypt/decrypt pipeline.";
        let mut rng2 = FixedRng::new(&(128..255).collect::<Vec<u8>>());
        let ciphertext = id.encrypt(plaintext, &mut rng2).unwrap();
        let decrypted = id.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_identity_sign_verify() {
        let mut rng = FixedRng::new(&(0..64).collect::<Vec<u8>>());
        let id = Identity::new(&mut rng);
        let msg = b"Sign this message";
        let sig = id.sign(msg).unwrap();
        assert!(id.verify(&sig, msg));
        assert!(!id.verify(&sig, b"Wrong message"));
    }
}
