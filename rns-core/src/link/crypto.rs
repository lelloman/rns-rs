use alloc::vec::Vec;

use rns_crypto::token::Token;
use rns_crypto::Rng;

use super::types::LinkError;

/// Create a Token from a derived session key.
///
/// 32 bytes → AES-128-CBC, 64 bytes → AES-256-CBC.
pub fn create_session_token(derived_key: &[u8]) -> Result<Token, LinkError> {
    Token::new(derived_key).map_err(|_| LinkError::CryptoError)
}

/// Encrypt plaintext for link transmission.
pub fn link_encrypt(token: &Token, plaintext: &[u8], rng: &mut dyn Rng) -> Vec<u8> {
    token.encrypt(plaintext, rng)
}

/// Decrypt ciphertext received on link.
pub fn link_decrypt(token: &Token, ciphertext: &[u8]) -> Result<Vec<u8>, LinkError> {
    token.decrypt(ciphertext).map_err(|_| LinkError::CryptoError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::FixedRng;

    #[test]
    fn test_encrypt_decrypt_roundtrip_aes128() {
        let key = [0x42u8; 32];
        let token = create_session_token(&key).unwrap();
        let mut rng = FixedRng::new(&[0xAA; 16]);
        let plaintext = b"Hello, Link!";
        let encrypted = link_encrypt(&token, plaintext, &mut rng);
        let decrypted = link_decrypt(&token, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_aes256() {
        let key = [0x42u8; 64];
        let token = create_session_token(&key).unwrap();
        let mut rng = FixedRng::new(&[0xBB; 16]);
        let plaintext = b"Hello, Link AES-256!";
        let encrypted = link_encrypt(&token, plaintext, &mut rng);
        let decrypted = link_decrypt(&token, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [0x42u8; 64];
        let key2 = [0x43u8; 64];
        let token1 = create_session_token(&key1).unwrap();
        let token2 = create_session_token(&key2).unwrap();
        let mut rng = FixedRng::new(&[0xCC; 16]);
        let encrypted = link_encrypt(&token1, b"secret", &mut rng);
        assert!(link_decrypt(&token2, &encrypted).is_err());
    }

    #[test]
    fn test_invalid_key_length() {
        let key = [0u8; 48];
        assert!(create_session_token(&key).is_err());
    }

    #[test]
    fn test_mode_detection() {
        // 32-byte key → AES-128
        assert!(create_session_token(&[0u8; 32]).is_ok());
        // 64-byte key → AES-256
        assert!(create_session_token(&[0u8; 64]).is_ok());
    }
}
