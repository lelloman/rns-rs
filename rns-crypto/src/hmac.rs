//! HMAC-SHA256, a thin wrapper over the `hmac` crate.

use ::hmac::{KeyInit, Mac};

type Inner = ::hmac::Hmac<sha2::Sha256>;

/// An incremental HMAC-SHA256, keyed once; clone it to reuse the key.
#[derive(Clone)]
pub struct HmacSha256(Inner);

impl HmacSha256 {
    /// An HMAC keyed with `key`, of any length.
    pub fn new(key: &[u8]) -> Self {
        match Inner::new_from_slice(key) {
            Ok(mac) => HmacSha256(mac),
            // HMAC takes keys of any length: longer ones are hashed first.
            Err(_) => unreachable!("HMAC accepts keys of every length"),
        }
    }

    /// Add `data` to the message.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The tag of everything absorbed so far; the MAC stays usable.
    pub fn finalize(&self) -> [u8; 32] {
        self.0.clone().finalize().into_bytes().into()
    }

    /// Compare the tag in constant time.
    pub fn verify(self, tag: &[u8]) -> bool {
        self.0.verify_slice(tag).is_ok()
    }
}

/// The HMAC-SHA256 of `data` under `key`.
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
