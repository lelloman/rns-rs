//! HMAC-SHA256 over [`Sha256`], so that its message can be hashed together
//! with another (see [`HmacSha256::update_paired`]).

use crate::sha256::{update_pair, update_triple, Sha256};
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub struct HmacSha256 {
    /// The inner hash, after the key's inner pad.
    inner: Sha256,
    /// The outer hash after the key's outer pad, waiting for the inner digest.
    outer: Sha256,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut block = [0u8; 64];
        if key.len() > 64 {
            block[..32].copy_from_slice(&crate::sha256::sha256(key));
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let mut pad = [0u8; 64];
        for (p, k) in pad.iter_mut().zip(&block) {
            *p = k ^ 0x36;
        }
        let mut inner = Sha256::new();
        inner.update(&pad);
        for (p, k) in pad.iter_mut().zip(&block) {
            *p = k ^ 0x5c;
        }
        let mut outer = Sha256::new();
        outer.update(&pad);
        HmacSha256 { inner, outer }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// `self.update(data)` and `other.update(other_data)`, with their blocks
    /// compressed together where they can be.
    pub fn update_paired(&mut self, data: &[u8], other: &mut Sha256, other_data: &[u8]) {
        update_pair(&mut self.inner, data, other, other_data);
    }

    /// [`Self::update_paired`] with two other hashes.
    pub fn update_tripled(
        &mut self,
        data: &[u8],
        b: &mut Sha256,
        b_data: &[u8],
        c: &mut Sha256,
        c_data: &[u8],
    ) {
        update_triple(&mut self.inner, data, b, b_data, c, c_data);
    }

    pub fn finalize(&self) -> [u8; 32] {
        let mut outer = self.outer.clone();
        outer.update(&self.inner.digest());
        outer.digest()
    }

    /// Compare the tag in constant time.
    pub fn verify(self, tag: &[u8]) -> bool {
        tag.len() == 32 && bool::from(self.finalize().ct_eq(tag))
    }
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = HmacSha256::new(key);
    h.update(data);
    h.finalize()
}

/// Verify an HMAC-SHA256 tag with a constant-time comparison.
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let mut h = HmacSha256::new(key);
    h.update(data);
    h.verify(tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(hex: &str) -> alloc::vec::Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_hmac_rfc4231_test1() {
        let key = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected =
            hex_to_bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(hmac_sha256(&key, data).to_vec(), expected);
    }

    #[test]
    fn test_hmac_rfc4231_test2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected =
            hex_to_bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(hmac_sha256(key, data).to_vec(), expected);
    }

    #[test]
    fn test_hmac_empty_msg() {
        let key = b"secret";
        let result = hmac_sha256(key, b"");
        assert_eq!(
            result.to_vec(),
            hex_to_bytes("f9e66e179b6747ae54108f82f8ade8b3c25d76fd30afde6c395822c530196169")
        );
    }

    #[test]
    fn test_hmac_long_key() {
        let key = [0xAA; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected =
            hex_to_bytes("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
        assert_eq!(hmac_sha256(&key, data).to_vec(), expected);
    }

    #[test]
    fn test_hmac_incremental() {
        let key = b"key";
        let data = b"hello world";
        let expected = hmac_sha256(key, data);

        let mut h = HmacSha256::new(key);
        h.update(b"hello ");
        h.update(b"world");
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn test_hmac_rfc4231_test3_crosses_block_boundary() {
        let key = [0xaa; 20];
        let data = [0xdd; 50];
        assert_eq!(
            hmac_sha256(&key, &data).to_vec(),
            hex_to_bytes("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
        );
    }

    #[test]
    fn test_hmac_rfc4231_test4_nonuniform_key() {
        let key: alloc::vec::Vec<u8> = (1..=25).collect();
        let data = [0xcd; 50];
        assert_eq!(
            hmac_sha256(&key, &data).to_vec(),
            hex_to_bytes("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")
        );
    }

    #[test]
    fn test_hmac_finalize_snapshot_does_not_consume_state() {
        let mut hmac = HmacSha256::new(b"key");
        hmac.update(b"first");
        let snapshot = hmac.finalize();
        hmac.update(b"-second");

        assert_eq!(snapshot, hmac_sha256(b"key", b"first"));
        assert_eq!(hmac.finalize(), hmac_sha256(b"key", b"first-second"));
    }

    #[test]
    fn matches_the_reference_hmac_for_every_key_and_message_length() {
        use ::hmac::{KeyInit, Mac};
        for key_len in [0usize, 1, 16, 32, 63, 64, 65, 131] {
            let key: alloc::vec::Vec<u8> = (0..key_len).map(|i| (i * 13 + 1) as u8).collect();
            for len in [0usize, 1, 55, 56, 64, 65, 1000] {
                let data: alloc::vec::Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
                let mut reference = ::hmac::Hmac::<sha2::Sha256>::new_from_slice(&key).unwrap();
                reference.update(&data);
                let expected: [u8; 32] = reference.finalize().into_bytes().into();
                assert_eq!(
                    hmac_sha256(&key, &data),
                    expected,
                    "key {key_len} data {len}"
                );
            }
        }
    }

    #[test]
    fn paired_updates_match_separate_updates() {
        let data: alloc::vec::Vec<u8> = (0..3000).map(|i| (i * 7) as u8).collect();
        let other: alloc::vec::Vec<u8> = (0..2000).map(|i| (i * 3) as u8).collect();
        let mut mac = HmacSha256::new(b"key");
        let mut hash = Sha256::new();
        for (a, b) in data.chunks(500).zip(other.chunks(333)) {
            mac.update_paired(a, &mut hash, b);
        }
        assert_eq!(mac.finalize(), hmac_sha256(b"key", &data));
        assert_eq!(hash.digest(), crate::sha256::sha256(&other[..333 * 6]));
    }

    #[test]
    fn hmac_verify_checks_every_tag_position_and_length() {
        let key = b"timing-test-key";
        let data = b"authenticated payload";
        let expected = hmac_sha256(key, data);

        assert!(hmac_sha256_verify(key, data, &expected));
        assert!(!hmac_sha256_verify(key, data, &expected[..31]));
        for index in 0..expected.len() {
            let mut corrupted = expected;
            corrupted[index] ^= 0x80;
            assert!(
                !hmac_sha256_verify(key, data, &corrupted),
                "tag mismatch at byte {index} must fail"
            );
        }
    }
}
