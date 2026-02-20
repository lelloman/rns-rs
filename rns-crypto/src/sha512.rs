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

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
