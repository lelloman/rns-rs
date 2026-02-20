use alloc::vec::Vec;

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

const BLOCK_SIZE: usize = 16;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub struct Aes128 {
    key: [u8; 16],
}

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Self {
        Aes128 { key: *key }
    }

    pub fn encrypt_cbc(&self, plaintext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        assert_eq!(plaintext.len() % BLOCK_SIZE, 0);
        let mut buf = plaintext.to_vec();
        let mut enc = Aes128CbcEnc::new(&self.key.into(), iv.into());
        enc.encrypt_blocks_mut(bytemuck_cast_blocks_mut(&mut buf));
        buf
    }

    pub fn decrypt_cbc(&self, ciphertext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        assert_eq!(ciphertext.len() % BLOCK_SIZE, 0);
        let mut buf = ciphertext.to_vec();
        let mut dec = Aes128CbcDec::new(&self.key.into(), iv.into());
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
    fn test_aes128_encrypt_decrypt_block() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let cipher = Aes128::new(&key);
        let plaintext = [0u8; 16];
        let encrypted = cipher.encrypt_cbc(&plaintext, &iv);
        let decrypted = cipher.decrypt_cbc(&encrypted, &iv);
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_aes128_cbc_roundtrip() {
        let key = [0x01u8; 16];
        let iv = [0x02u8; 16];
        let cipher = Aes128::new(&key);
        let plaintext = [0x03u8; 32];
        let encrypted = cipher.encrypt_cbc(&plaintext, &iv);
        let decrypted = cipher.decrypt_cbc(&encrypted, &iv);
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_aes128_known_vector() {
        // NIST AES-128 ECB test vector, verified via single-block CBC with zero IV
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let plaintext: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ];
        let expected: [u8; 16] = [
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
            0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
        ];
        let cipher = Aes128::new(&key);
        let iv = [0u8; 16];
        let result = cipher.encrypt_cbc(&plaintext, &iv);
        assert_eq!(&result[..16], &expected);
    }
}
