use crate::Rng;
use ed25519_dalek::Signer;
use ed25519_dalek::Verifier;

pub struct Ed25519PrivateKey {
    inner: ed25519_dalek::SigningKey,
}

pub struct Ed25519PublicKey {
    inner: ed25519_dalek::VerifyingKey,
}

impl Ed25519PrivateKey {
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Ed25519PrivateKey {
            inner: ed25519_dalek::SigningKey::from_bytes(seed),
        }
    }

    pub fn generate(rng: &mut dyn Rng) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_bytes(&seed)
    }

    pub fn private_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey {
            inner: self.inner.verifying_key(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.inner.sign(message).to_bytes()
    }
}

impl Ed25519PublicKey {
    pub fn from_bytes(data: &[u8; 32]) -> Self {
        Ed25519PublicKey {
            inner: ed25519_dalek::VerifyingKey::from_bytes(data)
                .expect("invalid Ed25519 public key bytes"),
        }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    pub fn verify(&self, signature: &[u8; 64], message: &[u8]) -> bool {
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        self.inner.verify(message, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify_roundtrip() {
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
