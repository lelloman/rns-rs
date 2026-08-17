use sha2::Digest;

#[derive(Clone)]
pub struct Sha256 {
    inner: sha2::Sha256,
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            inner: sha2::Sha256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn digest(&self) -> [u8; 32] {
        self.inner.clone().finalize().into()
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(sha256(b""), expected);
    }

    #[test]
    fn test_sha256_abc() {
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(sha256(b"abc"), expected);
    }

    #[test]
    fn test_sha256_long() {
        let data = [b'a'; 1000];
        let result = sha256(&data);
        let expected = [
            0x41, 0xed, 0xec, 0xe4, 0x2d, 0x63, 0xe8, 0xd9, 0xbf, 0x51, 0x5a, 0x9b, 0xa6, 0x93,
            0x2e, 0x1c, 0x20, 0xcb, 0xc9, 0xf5, 0xa5, 0xd1, 0x34, 0x64, 0x5a, 0xdb, 0x5d, 0xb1,
            0xb9, 0x73, 0x7e, 0xa3,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha256_incremental() {
        let mut hasher = Sha256::new();
        hasher.update(b"ab");
        hasher.update(b"c");
        assert_eq!(hasher.digest(), sha256(b"abc"));
    }

    #[test]
    fn test_sha256_million_a_known_answer() {
        let mut hasher = Sha256::new();
        for _ in 0..1000 {
            hasher.update(&[b'a'; 1000]);
        }
        assert_eq!(
            hasher.digest().to_vec(),
            hex_to_bytes("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
        );
    }

    #[test]
    fn test_sha256_incremental_matches_one_shot_across_padding_boundaries() {
        for length in [0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 255] {
            let input: alloc::vec::Vec<u8> = (0..length)
                .map(|index| ((index * 37 + 11) & 0xff) as u8)
                .collect();
            let expected = sha256(&input);
            for chunk_size in [1, 3, 7, 64] {
                let mut hasher = Sha256::new();
                for chunk in input.chunks(chunk_size) {
                    hasher.update(chunk);
                }
                assert_eq!(
                    hasher.digest(),
                    expected,
                    "length={length}, chunk={chunk_size}"
                );
            }
        }
    }

    #[test]
    fn test_sha256_digest_snapshot_does_not_consume_state() {
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        let snapshot = hasher.digest();
        hasher.update(b"def");

        assert_eq!(snapshot, sha256(b"abc"));
        assert_eq!(hasher.digest(), sha256(b"abcdef"));
    }

    fn hex_to_bytes(hex: &str) -> alloc::vec::Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect()
    }
}
