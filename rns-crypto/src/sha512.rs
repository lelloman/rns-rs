use sha2::Digest;

#[derive(Clone)]
pub struct Sha512 {
    inner: sha2::Sha512,
}

impl Sha512 {
    pub fn new() -> Self {
        Sha512 {
            inner: sha2::Sha512::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn digest(&self) -> [u8; 64] {
        self.inner.clone().finalize().into()
    }
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    sha2::Sha512::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn test_sha512_empty() {
        let expected_hex = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        let expected = hex_to_bytes(expected_hex);
        assert_eq!(sha512(b"").to_vec(), expected);
    }

    #[test]
    fn test_sha512_abc() {
        let expected_hex = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
        let expected = hex_to_bytes(expected_hex);
        assert_eq!(sha512(b"abc").to_vec(), expected);
    }

    #[test]
    fn test_sha512_incremental() {
        let mut hasher = Sha512::new();
        hasher.update(b"ab");
        hasher.update(b"c");
        assert_eq!(hasher.digest(), sha512(b"abc"));
    }

    #[test]
    fn test_sha512_million_a_known_answer() {
        let mut hasher = Sha512::new();
        for _ in 0..1000 {
            hasher.update(&[b'a'; 1000]);
        }
        assert_eq!(
            hasher.digest().to_vec(),
            hex_to_bytes(concat!(
                "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb",
                "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
            ))
        );
    }

    #[test]
    fn test_sha512_incremental_matches_one_shot_across_padding_boundaries() {
        for length in [0, 1, 111, 112, 127, 128, 129, 255, 256, 257] {
            let input: Vec<u8> = (0..length)
                .map(|index| ((index * 53 + 19) & 0xff) as u8)
                .collect();
            let expected = sha512(&input);
            for chunk_size in [1, 5, 17, 128] {
                let mut hasher = Sha512::new();
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
    fn test_sha512_digest_snapshot_does_not_consume_state() {
        let mut hasher = Sha512::new();
        hasher.update(b"abc");
        let snapshot = hasher.digest();
        hasher.update(b"def");

        assert_eq!(snapshot, sha512(b"abc"));
        assert_eq!(hasher.digest(), sha512(b"abcdef"));
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
