use alloc::vec::Vec;
use core::fmt;

use crate::aes128::Aes128;
use crate::aes256::Aes256;
use crate::hmac::hmac_sha256;
use crate::pkcs7;
use crate::Rng;

pub const TOKEN_OVERHEAD: usize = 48; // 16 IV + 32 HMAC

#[derive(Debug, PartialEq)]
pub enum TokenError {
    InvalidKeyLength,
    InvalidToken,
    HmacMismatch,
    DecryptionFailed,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::InvalidKeyLength => write!(f, "Token key must be 32 or 64 bytes"),
            TokenError::InvalidToken => write!(f, "Token too short"),
            TokenError::HmacMismatch => write!(f, "Token HMAC was invalid"),
            TokenError::DecryptionFailed => write!(f, "Could not decrypt token"),
        }
    }
}

enum AesMode {
    Aes128(Aes128),
    Aes256(Aes256),
}

pub struct Token {
    signing_key: Vec<u8>,
    mode: AesMode,
}

impl Token {
    pub fn new(key: &[u8]) -> Result<Self, TokenError> {
        match key.len() {
            32 => {
                let signing_key = key[..16].to_vec();
                let encryption_key: [u8; 16] = key[16..32].try_into().unwrap();
                Ok(Token {
                    signing_key,
                    mode: AesMode::Aes128(Aes128::new(&encryption_key)),
                })
            }
            64 => {
                let signing_key = key[..32].to_vec();
                let encryption_key: [u8; 32] = key[32..64].try_into().unwrap();
                Ok(Token {
                    signing_key,
                    mode: AesMode::Aes256(Aes256::new(&encryption_key)),
                })
            }
            _ => Err(TokenError::InvalidKeyLength),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8], rng: &mut dyn Rng) -> Vec<u8> {
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut iv);
        self.encrypt_with_iv(plaintext, &iv)
    }

    pub fn encrypt_with_iv(&self, plaintext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        let padded = pkcs7::pad(plaintext, 16);
        let ciphertext = match &self.mode {
            AesMode::Aes128(aes) => aes.encrypt_cbc(&padded, iv),
            AesMode::Aes256(aes) => aes.encrypt_cbc(&padded, iv),
        };

        let mut signed_parts = Vec::with_capacity(16 + ciphertext.len());
        signed_parts.extend_from_slice(iv);
        signed_parts.extend_from_slice(&ciphertext);

        let mac = hmac_sha256(&self.signing_key, &signed_parts);

        let mut result = Vec::with_capacity(signed_parts.len() + 32);
        result.extend_from_slice(&signed_parts);
        result.extend_from_slice(&mac);
        result
    }

    pub fn verify_hmac(&self, token: &[u8]) -> Result<bool, TokenError> {
        if token.len() <= 32 {
            return Err(TokenError::InvalidToken);
        }
        let received_hmac = &token[token.len() - 32..];
        let expected_hmac = hmac_sha256(&self.signing_key, &token[..token.len() - 32]);
        Ok(received_hmac == expected_hmac)
    }

    pub fn decrypt(&self, token: &[u8]) -> Result<Vec<u8>, TokenError> {
        if token.len() <= TOKEN_OVERHEAD {
            return Err(TokenError::InvalidToken);
        }

        if !self.verify_hmac(token).map_err(|_| TokenError::InvalidToken)? {
            return Err(TokenError::HmacMismatch);
        }

        let iv: [u8; 16] = token[..16].try_into().unwrap();
        let ciphertext = &token[16..token.len() - 32];

        let decrypted = match &self.mode {
            AesMode::Aes128(aes) => aes.decrypt_cbc(ciphertext, &iv),
            AesMode::Aes256(aes) => aes.decrypt_cbc(ciphertext, &iv),
        };

        pkcs7::unpad(&decrypted, 16)
            .map(|s| s.to_vec())
            .map_err(|_| TokenError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FixedRng;

    #[test]
    fn test_token_new_32byte_key() {
        let key = [0u8; 32];
        assert!(Token::new(&key).is_ok());
    }

    #[test]
    fn test_token_new_64byte_key() {
        let key = [0u8; 64];
        assert!(Token::new(&key).is_ok());
    }

    #[test]
    fn test_token_new_48byte_key() {
        let key = [0u8; 48];
        assert!(matches!(Token::new(&key), Err(TokenError::InvalidKeyLength)));
    }

    #[test]
    fn test_token_roundtrip_32() {
        let key = [0x42u8; 32];
        let token = Token::new(&key).unwrap();
        let mut rng = FixedRng::new(&[0xAA; 16]);
        let plaintext = b"Hello, Reticulum!";
        let encrypted = token.encrypt(plaintext, &mut rng);
        let decrypted = token.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_token_roundtrip_64() {
        let key = [0x42u8; 64];
        let token = Token::new(&key).unwrap();
        let mut rng = FixedRng::new(&[0xBB; 16]);
        let plaintext = b"Hello, Reticulum!";
        let encrypted = token.encrypt(plaintext, &mut rng);
        let decrypted = token.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_token_hmac_reject_tampered() {
        let key = [0x42u8; 64];
        let token = Token::new(&key).unwrap();
        let mut rng = FixedRng::new(&[0xCC; 16]);
        let encrypted = token.encrypt(b"test", &mut rng);
        let mut tampered = encrypted.clone();
        tampered[20] ^= 0xFF; // flip a bit in ciphertext
        assert!(token.decrypt(&tampered).is_err());
    }

    #[test]
    fn test_token_decrypt_truncated() {
        let key = [0x42u8; 64];
        let token = Token::new(&key).unwrap();
        assert!(matches!(token.decrypt(&[0u8; 10]), Err(TokenError::InvalidToken)));
    }

    #[test]
    fn test_token_overhead() {
        assert_eq!(TOKEN_OVERHEAD, 48);
    }
}
