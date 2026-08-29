use alloc::vec::Vec;

use aes::cipher::{block_padding::NoPadding, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};

const BLOCK_SIZE: usize = 16;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub struct Aes128 {
    key: [u8; 16],
}

impl Aes128 {
    /// Construct AES-128 with a compile-time-sized 128-bit key.
    ///
    /// The array reference deliberately makes an invalid key length
    /// unrepresentable at this API boundary.
    pub fn new(key: &[u8; 16]) -> Self {
        Aes128 { key: *key }
    }

    pub fn encrypt_cbc(&self, plaintext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        assert_eq!(plaintext.len() % BLOCK_SIZE, 0);
        let mut buf = plaintext.to_vec();
        let message_len = buf.len();
        Aes128CbcEnc::new(&self.key.into(), iv.into())
            .encrypt_padded::<NoPadding>(&mut buf, message_len)
            .expect("aligned CBC plaintext has sufficient capacity");
        buf
    }

    pub fn decrypt_cbc(&self, ciphertext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        assert_eq!(ciphertext.len() % BLOCK_SIZE, 0);
        let mut buf = ciphertext.to_vec();
        Aes128CbcDec::new(&self.key.into(), iv.into())
            .decrypt_padded::<NoPadding>(&mut buf)
            .expect("aligned CBC ciphertext has no padding to validate");
        buf
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
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let plaintext: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expected: [u8; 16] = [
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66,
            0xef, 0x97,
        ];
        let cipher = Aes128::new(&key);
        let iv = [0u8; 16];
        let result = cipher.encrypt_cbc(&plaintext, &iv);
        assert_eq!(&result[..16], &expected);
    }

    #[test]
    fn test_aes128_nist_sp800_38a_cbc_four_block_vector() {
        let key: [u8; 16] = decode_hex("2b7e151628aed2a6abf7158809cf4f3c")
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
            "7649abac8119b246cee98e9b12e9197d",
            "5086cb9b507219ee95db113a917678b2",
            "73bed6b8e3c1743b7116e69e22229516",
            "3ff1caa1681fac09120eca307586e1a7"
        ));
        let cipher = Aes128::new(&key);

        assert_eq!(cipher.encrypt_cbc(&plaintext, &iv), expected);
        assert_eq!(cipher.decrypt_cbc(&expected, &iv), plaintext);
    }

    #[test]
    fn test_aes128_empty_cbc_payload_is_stable() {
        let cipher = Aes128::new(&[0x11; 16]);
        assert!(cipher.encrypt_cbc(&[], &[0x22; 16]).is_empty());
        assert!(cipher.decrypt_cbc(&[], &[0x22; 16]).is_empty());
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn test_aes128_rejects_unaligned_plaintext() {
        Aes128::new(&[0; 16]).encrypt_cbc(&[0; 15], &[0; 16]);
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect()
    }
}
