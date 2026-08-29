use alloc::vec::Vec;

use aes::cipher::{block_padding::NoPadding, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};

const BLOCK_SIZE: usize = 16;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub struct Aes256 {
    key: [u8; 32],
}

impl Aes256 {
    /// Construct AES-256 with a compile-time-sized 256-bit key.
    ///
    /// The array reference deliberately makes an invalid key length
    /// unrepresentable at this API boundary.
    pub fn new(key: &[u8; 32]) -> Self {
        Aes256 { key: *key }
    }

    pub fn encrypt_cbc(&self, plaintext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        assert_eq!(plaintext.len() % BLOCK_SIZE, 0);
        let mut buf = plaintext.to_vec();
        let message_len = buf.len();
        Aes256CbcEnc::new(&self.key.into(), iv.into())
            .encrypt_padded::<NoPadding>(&mut buf, message_len)
            .expect("aligned CBC plaintext has sufficient capacity");
        buf
    }

    pub fn decrypt_cbc(&self, ciphertext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        assert_eq!(ciphertext.len() % BLOCK_SIZE, 0);
        let mut buf = ciphertext.to_vec();
        Aes256CbcDec::new(&self.key.into(), iv.into())
            .decrypt_padded::<NoPadding>(&mut buf)
            .expect("aligned CBC ciphertext has no padding to validate");
        buf
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
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let plaintext: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expected: [u8; 16] = [
            0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1,
            0x81, 0xf8,
        ];
        let cipher = Aes256::new(&key);
        let iv = [0u8; 16];
        let result = cipher.encrypt_cbc(&plaintext, &iv);
        assert_eq!(&result[..16], &expected);
    }

    #[test]
    fn test_aes256_nist_sp800_38a_cbc_four_block_vector() {
        let key: [u8; 32] = decode_hex(concat!(
            "603deb1015ca71be2b73aef0857d7781",
            "1f352c073b6108d72d9810a30914dff4"
        ))
        .try_into()
        .unwrap();
        let iv: [u8; 16] = decode_hex("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let plaintext = decode_hex(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710"
        ));
        let expected = decode_hex(concat!(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
            "9cfc4e967edb808d679f777bc6702c7d",
            "39f23369a9d9bacfa530e26304231461",
            "b2eb05e2c39be9fcda6c19078c6a9d1b"
        ));
        let cipher = Aes256::new(&key);

        assert_eq!(cipher.encrypt_cbc(&plaintext, &iv), expected);
        assert_eq!(cipher.decrypt_cbc(&expected, &iv), plaintext);
    }

    #[test]
    fn test_aes256_empty_cbc_payload_is_stable() {
        let cipher = Aes256::new(&[0x11; 32]);
        assert!(cipher.encrypt_cbc(&[], &[0x22; 16]).is_empty());
        assert!(cipher.decrypt_cbc(&[], &[0x22; 16]).is_empty());
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn test_aes256_rejects_unaligned_ciphertext() {
        Aes256::new(&[0; 32]).decrypt_cbc(&[0; 17], &[0; 16]);
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect()
    }
}
