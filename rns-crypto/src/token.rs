use alloc::vec::Vec;
use core::fmt;

use crate::aes128::Aes128;
use crate::aes256::Aes256;
use aes::cipher::{array::Array, BlockModeDecrypt};

use crate::hmac::{hmac_sha256, hmac_sha256_verify, HmacSha256};
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

/// CBC chaining state carried across the pieces of one ciphertext. It lives
/// on the stack for one call, so the variants' size difference is harmless.
#[allow(clippy::large_enum_variant)]
enum CbcDecryptor {
    Aes128(cbc::Decryptor<aes::Aes128>),
    Aes256(cbc::Decryptor<aes::Aes256>),
}

impl CbcDecryptor {
    /// Decrypt whole blocks in place, continuing the chain.
    fn decrypt_blocks(&mut self, buf: &mut [u8]) {
        let (blocks, rest) = Array::slice_as_chunks_mut(buf);
        debug_assert!(rest.is_empty());
        match self {
            CbcDecryptor::Aes128(dec) => dec.decrypt_blocks(blocks),
            CbcDecryptor::Aes256(dec) => dec.decrypt_blocks(blocks),
        }
    }
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
        // Build the whole token in one buffer: the plaintext is copied once,
        // padded and encrypted in place, then signed and the tag appended.
        let padding = pkcs7::BLOCK_SIZE - plaintext.len() % pkcs7::BLOCK_SIZE;
        let mut token = Vec::with_capacity(16 + plaintext.len() + padding + 32);
        token.extend_from_slice(iv);
        token.extend_from_slice(plaintext);
        token.resize(token.len() + padding, padding as u8);
        match &self.mode {
            AesMode::Aes128(aes) => aes.encrypt_cbc_in_place(&mut token[16..], iv),
            AesMode::Aes256(aes) => aes.encrypt_cbc_in_place(&mut token[16..], iv),
        }
        .expect("PKCS7 padding always produces block-aligned plaintext");

        let mac = hmac_sha256(&self.signing_key, &token);
        token.extend_from_slice(&mac);
        token
    }

    pub fn verify_hmac(&self, token: &[u8]) -> Result<bool, TokenError> {
        if token.len() <= 32 {
            return Err(TokenError::InvalidToken);
        }
        let received_hmac = &token[token.len() - 32..];
        Ok(hmac_sha256_verify(
            &self.signing_key,
            &token[..token.len() - 32],
            received_hmac,
        ))
    }

    pub fn decrypt(&self, token: &[u8]) -> Result<Vec<u8>, TokenError> {
        if token.len() <= TOKEN_OVERHEAD {
            return Err(TokenError::InvalidToken);
        }

        if !self
            .verify_hmac(token)
            .map_err(|_| TokenError::InvalidToken)?
        {
            return Err(TokenError::HmacMismatch);
        }

        let iv: [u8; 16] = token[..16].try_into().unwrap();
        let ciphertext = &token[16..token.len() - 32];

        // CBC ciphertext must be a non-empty whole number of 16-byte blocks.
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
            return Err(TokenError::DecryptionFailed);
        }

        let mut decrypted = match &self.mode {
            AesMode::Aes128(aes) => aes.decrypt_cbc(ciphertext, &iv),
            AesMode::Aes256(aes) => aes.decrypt_cbc(ciphertext, &iv),
        }
        .map_err(|_| TokenError::DecryptionFailed)?;

        let unpadded_len = pkcs7::unpad(&decrypted, 16)
            .map_err(|_| TokenError::DecryptionFailed)?
            .len();
        decrypted.truncate(unpadded_len);
        Ok(decrypted)
    }

    /// Decrypt a token that arrives as consecutive chunks, such as the parts
    /// of a resource, without joining them first. Each chunk is authenticated
    /// and decrypted while it is still in cache; nothing is returned unless
    /// the tag matches. The result is [`Token::decrypt`] of the joined bytes
    /// with its first `skip` bytes (at most one block) dropped, and the errors
    /// are the same, except that a plaintext shorter than `skip` is
    /// [`TokenError::DecryptionFailed`].
    pub fn decrypt_chunks(&self, chunks: &[&[u8]], skip: usize) -> Result<Vec<u8>, TokenError> {
        assert!(skip <= 16, "decrypt_chunks skips at most one block");
        let total: usize = chunks.iter().map(|chunk| chunk.len()).sum();
        if total <= TOKEN_OVERHEAD {
            return Err(TokenError::InvalidToken);
        }
        let signed_len = total - 32;
        let ciphertext_len = signed_len - 16;
        // A misaligned ciphertext is rejected after the tag check, as in
        // `decrypt`; it is authenticated but not decrypted.
        let aligned = ciphertext_len.is_multiple_of(16);

        let mut mac = HmacSha256::new(&self.signing_key);
        let mut iv = [0u8; 16];
        let mut tag = [0u8; 32];
        let mut plaintext = Vec::with_capacity(if aligned { ciphertext_len - skip } else { 0 });
        let mut decryptor = None;
        // A block that straddles chunks, and always the first block, which
        // carries the skipped bytes, are decrypted here.
        let mut block = [0u8; 16];
        let mut block_len = 0;
        let mut first_block = true;
        let mut last_byte = 0u8;
        let mut pos = 0;
        for chunk in chunks {
            let end = pos + chunk.len();
            if pos < signed_len {
                mac.update(&chunk[..signed_len.min(end) - pos]);
            }
            if pos < 16 {
                let n = 16.min(end) - pos;
                iv[pos..pos + n].copy_from_slice(&chunk[..n]);
            }
            let (start, stop) = (pos.max(16), end.min(signed_len));
            if aligned && start < stop {
                let decryptor = decryptor.get_or_insert_with(|| match &self.mode {
                    AesMode::Aes128(aes) => CbcDecryptor::Aes128(aes.cbc_decryptor(&iv)),
                    AesMode::Aes256(aes) => CbcDecryptor::Aes256(aes.cbc_decryptor(&iv)),
                });
                let mut data = &chunk[start - pos..stop - pos];
                while !data.is_empty() && (block_len > 0 || first_block) {
                    let n = (16 - block_len).min(data.len());
                    block[block_len..block_len + n].copy_from_slice(&data[..n]);
                    block_len += n;
                    data = &data[n..];
                    if block_len == 16 {
                        decryptor.decrypt_blocks(&mut block);
                        let from = if first_block { skip } else { 0 };
                        plaintext.extend_from_slice(&block[from..]);
                        last_byte = block[15];
                        first_block = false;
                        block_len = 0;
                    }
                }
                if !data.is_empty() {
                    let whole = data.len() - data.len() % 16;
                    if whole > 0 {
                        let at = plaintext.len();
                        plaintext.extend_from_slice(&data[..whole]);
                        decryptor.decrypt_blocks(&mut plaintext[at..]);
                        last_byte = plaintext[plaintext.len() - 1];
                    }
                    let rest = &data[whole..];
                    block[..rest.len()].copy_from_slice(rest);
                    block_len = rest.len();
                }
            }
            if end > signed_len {
                let from = pos.max(signed_len);
                tag[from - signed_len..end - signed_len].copy_from_slice(&chunk[from - pos..]);
            }
            pos = end;
        }

        if !mac.verify(&tag) {
            return Err(TokenError::HmacMismatch);
        }
        if !aligned {
            return Err(TokenError::DecryptionFailed);
        }
        // The same padding check as `pkcs7::unpad`.
        let padding = usize::from(last_byte);
        if padding > 16 || padding > plaintext.len() {
            return Err(TokenError::DecryptionFailed);
        }
        plaintext.truncate(plaintext.len() - padding);
        Ok(plaintext)
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
        assert!(matches!(
            Token::new(&key),
            Err(TokenError::InvalidKeyLength)
        ));
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
    fn token_hmac_rejects_mismatches_across_the_entire_tag() {
        let key = [0x42u8; 64];
        let token = Token::new(&key).unwrap();
        let mut rng = FixedRng::new(&[0xCC; 16]);
        let encrypted = token.encrypt(b"timing regression", &mut rng);

        assert_eq!(token.verify_hmac(&encrypted), Ok(true));
        for tag_index in 0..32 {
            let mut corrupted = encrypted.clone();
            let index = corrupted.len() - 32 + tag_index;
            corrupted[index] ^= 0x01;
            assert_eq!(
                token.verify_hmac(&corrupted),
                Ok(false),
                "tag mismatch at byte {tag_index} must fail"
            );
        }
    }

    #[test]
    fn test_token_decrypt_truncated() {
        let key = [0x42u8; 64];
        let token = Token::new(&key).unwrap();
        assert!(matches!(
            token.decrypt(&[0u8; 10]),
            Err(TokenError::InvalidToken)
        ));
    }

    fn sign_token_parts(key: &[u8], iv_and_ciphertext: &[u8]) -> Vec<u8> {
        let signing_key = &key[..key.len() / 2];
        let mut token = iv_and_ciphertext.to_vec();
        token.extend_from_slice(&hmac_sha256(signing_key, iv_and_ciphertext));
        token
    }

    #[test]
    fn test_token_decrypt_rejects_misaligned_ciphertext_with_valid_hmac() {
        for key in [&[0x42u8; 32][..], &[0x42u8; 64][..]] {
            let token = Token::new(key).unwrap();
            for ciphertext_len in [1usize, 15, 17, 31, 33] {
                let mut parts = alloc::vec![0xAAu8; 16];
                parts.extend(core::iter::repeat_n(0x55u8, ciphertext_len));
                let signed = sign_token_parts(key, &parts);
                assert_eq!(token.verify_hmac(&signed), Ok(true));
                assert_eq!(
                    token.decrypt(&signed),
                    Err(TokenError::DecryptionFailed),
                    "ciphertext length {ciphertext_len} must be rejected"
                );
            }
        }
    }

    #[test]
    fn test_token_well_formed_roundtrip_after_alignment_check() {
        for key in [&[0x24u8; 32][..], &[0x24u8; 64][..]] {
            let token = Token::new(key).unwrap();
            for plaintext_len in [0usize, 1, 15, 16, 17, 32, 100] {
                let plaintext = alloc::vec![0x5Au8; plaintext_len];
                let encrypted = token.encrypt_with_iv(&plaintext, &[0x11; 16]);
                assert_eq!((encrypted.len() - TOKEN_OVERHEAD) % 16, 0);
                assert_eq!(token.decrypt(&encrypted).unwrap(), plaintext);
            }
        }
    }

    #[test]
    fn test_token_overhead() {
        assert_eq!(TOKEN_OVERHEAD, 48);
    }

    /// Split `bytes` at the given offsets (clamped, in order).
    fn split_at_offsets<'a>(bytes: &'a [u8], offsets: &[usize]) -> Vec<&'a [u8]> {
        let mut chunks = Vec::new();
        let mut from = 0;
        for &offset in offsets {
            let to = offset.clamp(from, bytes.len());
            chunks.push(&bytes[from..to]);
            from = to;
        }
        chunks.push(&bytes[from..]);
        chunks
    }

    fn chunked_as_joined(token: &Token, bytes: &[u8], chunks: &[&[u8]], skip: usize) {
        let joined = token.decrypt(bytes);
        let expected = match joined {
            Ok(plaintext) if plaintext.len() >= skip => Ok(plaintext[skip..].to_vec()),
            Ok(_) => Err(TokenError::DecryptionFailed),
            Err(error) => Err(error),
        };
        assert_eq!(
            token.decrypt_chunks(chunks, skip),
            expected,
            "{chunks:?} skip {skip}"
        );
    }

    #[test]
    fn chunked_decryption_matches_joined_decryption() {
        let mut rng = FixedRng::new(&[0x5D; 64]);
        for key in [[0x21u8; 32].to_vec(), [0x42u8; 64].to_vec()] {
            let token = Token::new(&key).unwrap();
            for len in [0usize, 1, 3, 4, 5, 12, 15, 16, 17, 33, 100, 1000] {
                let plaintext: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
                let bytes = token.encrypt(&plaintext, &mut rng);
                let n = bytes.len();
                let splits: Vec<Vec<usize>> = alloc::vec![
                    alloc::vec![],
                    alloc::vec![1],
                    alloc::vec![8, 16, 17],
                    alloc::vec![16, 20, 32, 47],
                    alloc::vec![n - 33, n - 32, n - 31],
                    alloc::vec![n - 40, n - 10],
                    (1..n).collect(),
                    (0..n).step_by(13).collect(),
                    alloc::vec![0, 0, 5, 5, n],
                ];
                for offsets in &splits {
                    let chunks = split_at_offsets(&bytes, offsets);
                    for skip in [0, 1, 4, 16] {
                        chunked_as_joined(&token, &bytes, &chunks, skip);
                    }
                }
                // Tampering anywhere is caught.
                for at in 0..n {
                    let mut tampered = bytes.clone();
                    tampered[at] ^= 0x01;
                    let chunks = split_at_offsets(&tampered, &[at / 2, at, at + 1]);
                    assert_eq!(
                        token.decrypt_chunks(&chunks, 4),
                        Err(TokenError::HmacMismatch)
                    );
                }
            }
            // Misaligned ciphertext under a valid tag, and short tokens.
            for ciphertext_len in [1usize, 15, 17, 31, 33] {
                let mut parts = alloc::vec![0xAAu8; 16];
                parts.extend(core::iter::repeat_n(0x55u8, ciphertext_len));
                let signed = sign_token_parts(&key, &parts);
                let chunks = split_at_offsets(&signed, &[7, 20, 40]);
                chunked_as_joined(&token, &signed, &chunks, 4);
            }
            // Signed garbage decrypts to arbitrary padding bytes.
            for fill in 0u8..64 {
                for ciphertext_len in [16usize, 32] {
                    let parts: Vec<u8> = (0..16 + ciphertext_len)
                        .map(|i| (i as u8).wrapping_mul(fill).wrapping_add(fill))
                        .collect();
                    let signed = sign_token_parts(&key, &parts);
                    for offsets in [alloc::vec![], alloc::vec![3, 19, 30]] {
                        let chunks = split_at_offsets(&signed, &offsets);
                        for skip in [0, 4, 16] {
                            chunked_as_joined(&token, &signed, &chunks, skip);
                        }
                    }
                }
            }
            for len in [0usize, 1, 48] {
                let short = alloc::vec![0u8; len];
                assert_eq!(
                    token.decrypt_chunks(&split_at_offsets(&short, &[1]), 0),
                    Err(TokenError::InvalidToken)
                );
            }
        }
    }

    #[test]
    fn single_buffer_encryption_matches_pad_encrypt_sign() {
        for key in [[0x21u8; 32].to_vec(), [0x42u8; 64].to_vec()] {
            let token = Token::new(&key).unwrap();
            let iv = [0x17u8; 16];
            for len in [0usize, 1, 15, 16, 17, 31, 32, 1000] {
                let plaintext: Vec<u8> = (0..len).map(|i| i as u8).collect();
                let padded = pkcs7::pad(&plaintext, 16);
                let ciphertext = match &token.mode {
                    AesMode::Aes128(aes) => aes.encrypt_cbc(&padded, &iv),
                    AesMode::Aes256(aes) => aes.encrypt_cbc(&padded, &iv),
                }
                .unwrap();
                let mut expected = iv.to_vec();
                expected.extend_from_slice(&ciphertext);
                let mac = hmac_sha256(&token.signing_key, &expected);
                expected.extend_from_slice(&mac);
                let encrypted = token.encrypt_with_iv(&plaintext, &iv);
                assert_eq!(encrypted, expected, "key {} len {len}", key.len());
                assert_eq!(encrypted.capacity(), encrypted.len());
                assert_eq!(token.decrypt(&encrypted).unwrap(), plaintext);
            }
        }
    }
}
