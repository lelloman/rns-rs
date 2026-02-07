use alloc::vec::Vec;
use crate::aes::{
    self, bytes_to_matrix, matrix_to_bytes, xor_bytes,
    add_round_key, sub_bytes, inv_sub_bytes,
    shift_rows, inv_shift_rows, mix_columns, inv_mix_columns,
};

const ROUNDS: usize = 10;
const BLOCK_SIZE: usize = 16;

pub struct Aes128 {
    round_keys: Vec<Vec<Vec<u8>>>,
}

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Self {
        let round_keys = aes::expand_key(key, ROUNDS);
        Aes128 { round_keys }
    }

    fn encrypt_block(&self, plaintext: &[u8]) -> [u8; 16] {
        assert_eq!(plaintext.len(), BLOCK_SIZE);
        let mut state = bytes_to_matrix(plaintext);

        add_round_key(&mut state, &self.round_keys[0]);

        for i in 1..ROUNDS {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &self.round_keys[i]);
        }

        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &self.round_keys[ROUNDS]);

        matrix_to_bytes(&state)
    }

    fn decrypt_block(&self, ciphertext: &[u8]) -> [u8; 16] {
        assert_eq!(ciphertext.len(), BLOCK_SIZE);
        let mut state = bytes_to_matrix(ciphertext);

        add_round_key(&mut state, &self.round_keys[ROUNDS]);
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);

        for i in (1..ROUNDS).rev() {
            add_round_key(&mut state, &self.round_keys[i]);
            inv_mix_columns(&mut state);
            inv_shift_rows(&mut state);
            inv_sub_bytes(&mut state);
        }

        add_round_key(&mut state, &self.round_keys[0]);

        matrix_to_bytes(&state)
    }

    pub fn encrypt_cbc(&self, plaintext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        assert_eq!(plaintext.len() % BLOCK_SIZE, 0);
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut previous = iv.to_vec();

        for block in plaintext.chunks(BLOCK_SIZE) {
            let xorred = xor_bytes(block, &previous);
            let encrypted = self.encrypt_block(&xorred);
            previous = encrypted.to_vec();
            ciphertext.extend_from_slice(&encrypted);
        }

        ciphertext
    }

    pub fn decrypt_cbc(&self, ciphertext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        assert_eq!(ciphertext.len() % BLOCK_SIZE, 0);
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut previous = iv.to_vec();

        for block in ciphertext.chunks(BLOCK_SIZE) {
            let decrypted = self.decrypt_block(block);
            let xorred = xor_bytes(&previous, &decrypted);
            plaintext.extend_from_slice(&xorred);
            previous = block.to_vec();
        }

        plaintext
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_encrypt_decrypt_block() {
        let key = [0u8; 16];
        let cipher = Aes128::new(&key);
        let plaintext = [0u8; 16];
        let encrypted = cipher.encrypt_block(&plaintext);
        let decrypted = cipher.decrypt_block(&encrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_cbc_roundtrip() {
        let key = [0x01u8; 16];
        let iv = [0x02u8; 16];
        let cipher = Aes128::new(&key);
        // Two blocks
        let plaintext = [0x03u8; 32];
        let encrypted = cipher.encrypt_cbc(&plaintext, &iv);
        let decrypted = cipher.decrypt_cbc(&encrypted, &iv);
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_aes128_known_vector() {
        // NIST AES-128 test vector
        // Key:       2b7e151628aed2a6abf7158809cf4f3c
        // Plaintext: 6bc1bee22e409f96e93d7e117393172a
        // Expected:  3ad77bb40d7a3660a89ecaf32466ef97
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
        let result = cipher.encrypt_block(&plaintext);
        assert_eq!(result, expected);
    }
}
