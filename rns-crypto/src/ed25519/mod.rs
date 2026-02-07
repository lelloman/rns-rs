pub(crate) mod basic;
pub(crate) mod eddsa;

use crate::Rng;

pub struct Ed25519PrivateKey {
    seed: [u8; 32],
}

pub struct Ed25519PublicKey {
    bytes: [u8; 32],
}

impl Ed25519PrivateKey {
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Ed25519PrivateKey { seed: *seed }
    }

    pub fn generate(rng: &mut dyn Rng) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_bytes(&seed)
    }

    pub fn private_bytes(&self) -> [u8; 32] {
        self.seed
    }

    pub fn public_key(&self) -> Ed25519PublicKey {
        let pk_bytes = eddsa::publickey(&self.seed);
        Ed25519PublicKey { bytes: pk_bytes }
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let pk = self.public_key();
        eddsa::signature(message, &self.seed, &pk.bytes)
    }
}

impl Ed25519PublicKey {
    pub fn from_bytes(data: &[u8; 32]) -> Self {
        Ed25519PublicKey { bytes: *data }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    pub fn verify(&self, signature: &[u8; 64], message: &[u8]) -> bool {
        eddsa::checkvalid(signature, message, &self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify_roundtrip() {
        // Use a known seed
        let seed = [42u8; 32];
        let key = Ed25519PrivateKey::from_bytes(&seed);
        let pubkey = key.public_key();
        let msg = b"Hello, Ed25519!";
        let sig = key.sign(msg);
        assert!(pubkey.verify(&sig, msg));
    }

    #[test]
    fn test_ed25519_verify_tampered() {
        let seed = [42u8; 32];
        let key = Ed25519PrivateKey::from_bytes(&seed);
        let pubkey = key.public_key();
        let msg = b"Hello, Ed25519!";
        let sig = key.sign(msg);
        // Tampered message
        assert!(!pubkey.verify(&sig, b"Hello, Ed25519?"));
    }

    #[test]
    fn test_ed25519_pubkey_deterministic() {
        let seed = [1u8; 32];
        let key1 = Ed25519PrivateKey::from_bytes(&seed);
        let key2 = Ed25519PrivateKey::from_bytes(&seed);
        assert_eq!(key1.public_key().public_bytes(), key2.public_key().public_bytes());
    }
}
