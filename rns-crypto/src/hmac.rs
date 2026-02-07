use crate::sha256::{self, Sha256};

const BLOCK_SIZE: usize = 64;

#[derive(Clone)]
pub struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut key_block = [0u8; BLOCK_SIZE];

        if key.len() > BLOCK_SIZE {
            let hashed = sha256::sha256(key);
            key_block[..32].copy_from_slice(&hashed);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0u8; BLOCK_SIZE];
        let mut opad = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            ipad[i] = key_block[i] ^ 0x36;
            opad[i] = key_block[i] ^ 0x5C;
        }

        let mut inner = Sha256::new();
        inner.update(&ipad);

        let mut outer = Sha256::new();
        outer.update(&opad);

        HmacSha256 { inner, outer }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(&self) -> [u8; 32] {
        let inner_digest = self.inner.digest();
        let mut outer = self.outer.clone();
        outer.update(&inner_digest);
        outer.digest()
    }
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = HmacSha256::new(key);
    h.update(data);
    h.finalize()
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
        // RFC 4231 Test Case 1
        let key = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected = hex_to_bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(hmac_sha256(&key, data).to_vec(), expected);
    }

    #[test]
    fn test_hmac_rfc4231_test2() {
        // RFC 4231 Test Case 2 - "Jefe" key
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = hex_to_bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(hmac_sha256(key, data).to_vec(), expected);
    }

    #[test]
    fn test_hmac_empty_msg() {
        let key = b"secret";
        let result = hmac_sha256(key, b"");
        // Just verify it produces a 32-byte result without panicking
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hmac_long_key() {
        // Key > 64 bytes should be hashed first
        let key = [0xAA; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected = hex_to_bytes("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
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
}
