use alloc::vec::Vec;

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

const BLOCK_SIZE: usize = 16;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub struct Aes256 {
    key: [u8; 32],
}

impl Aes256 {
    pub fn new(key: &[u8; 32]) -> Self {
        Aes256 { key: *key }
    }

    pub fn encrypt_cbc(&self, plaintext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        assert_eq!(plaintext.len() % BLOCK_SIZE, 0);
        let mut buf = plaintext.to_vec();
        let mut enc = Aes256CbcEnc::new(&self.key.into(), iv.into());
        enc.encrypt_blocks_mut(bytemuck_cast_blocks_mut(&mut buf));
        buf
    }

    pub fn decrypt_cbc(&self, ciphertext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        assert_eq!(ciphertext.len() % BLOCK_SIZE, 0);
        let mut buf = ciphertext.to_vec();
        let mut dec = Aes256CbcDec::new(&self.key.into(), iv.into());
        dec.decrypt_blocks_mut(bytemuck_cast_blocks_mut(&mut buf));
        buf
    }
}

fn bytemuck_cast_blocks_mut(buf: &mut [u8]) -> &mut [aes::Block] {
    assert_eq!(buf.len() % 16, 0);
    // SAFETY: aes::Block is [u8; 16] with repr transparent via GenericArray
    unsafe {
        core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut aes::Block, buf.len() / 16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_encrypt_decrypt_block() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let cipher = Aes256::new(&key);
        let plaintext = [0u8; 16];
        let encrypted = cipher.encrypt_cbc(&plaintext, &iv);
        let decrypted = cipher.decrypt_cbc(&encrypted, &iv);
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_aes256_cbc_roundtrip() {
        let key = [0x01u8; 32];
        let iv = [0x02u8; 16];
        let cipher = Aes256::new(&key);
        let plaintext = [0x03u8; 32];
        let encrypted = cipher.encrypt_cbc(&plaintext, &iv);
        let decrypted = cipher.decrypt_cbc(&encrypted, &iv);
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_aes256_known_vector() {
        // NIST AES-256 ECB test vector, verified via single-block CBC with zero IV
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
        ];
        let plaintext: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ];
        let expected: [u8; 16] = [
            0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
            0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
        ];
        let cipher = Aes256::new(&key);
        let iv = [0u8; 16];
        let result = cipher.encrypt_cbc(&plaintext, &iv);
        assert_eq!(&result[..16], &expected);
    }
}
