use alloc::vec::Vec;
use core::fmt;

use crate::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use crate::hkdf;
use crate::sha256;
use crate::token::{Token, TokenError};
use crate::x25519::{X25519PrivateKey, X25519PublicKey};
use crate::Rng;

pub const KEYSIZE: usize = 512; // bits
pub const DERIVED_KEY_LENGTH: usize = 64; // bytes
pub const TRUNCATED_HASHLENGTH: usize = 128; // bits (16 bytes)

#[derive(Debug)]
pub enum CryptoError {
    NoPrivateKey,
    NoPublicKey,
    TokenError(TokenError),
    HkdfError(hkdf::HkdfError),
    InvalidCiphertext,
    InvalidPublicKey,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::NoPrivateKey => write!(f, "No private key"),
            CryptoError::NoPublicKey => write!(f, "No public key"),
            CryptoError::TokenError(e) => write!(f, "Token error: {}", e),
            CryptoError::HkdfError(e) => write!(f, "HKDF error: {}", e),
            CryptoError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            CryptoError::InvalidPublicKey => write!(f, "Invalid public key"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}

pub use crate::stamp_value::{stamp_value, StampCost, StampValue};

/// Generate an X25519 keypair whose public key meets `stamp_cost` over
/// `material`, mirroring upstream `generate_stamped_key`.
pub fn generate_stamped_key(
    rng: &mut dyn Rng,
    material: &[u8],
    stamp_cost: StampCost,
) -> (X25519PrivateKey, X25519PublicKey, StampValue) {
    generate_stamped_key_until(rng, material, stamp_cost, &mut || false)
        .expect("stamped key generation without a stop condition always completes")
}

/// Like [`generate_stamped_key`], but gives up and returns `None` as soon as
/// `should_stop` reports true. The search is unbounded, so callers that run
/// it on a latency-sensitive path must supply a deadline or cancellation flag,
/// as upstream does with `LINK_STAMP_TIMEOUT` and `cancel_work`.
pub fn generate_stamped_key_until(
    rng: &mut dyn Rng,
    material: &[u8],
    stamp_cost: StampCost,
    should_stop: &mut dyn FnMut() -> bool,
) -> Option<(X25519PrivateKey, X25519PublicKey, StampValue)> {
    loop {
        if should_stop() {
            return None;
        }
        let prv = X25519PrivateKey::generate(rng);
        let public = prv.public_key();
        let mut input = Vec::with_capacity(material.len() + 32);
        input.extend_from_slice(material);
        input.extend_from_slice(&public.public_bytes());
        let product = crate::sha256::sha256(&input);
        if stamp_cost.admits(&product) {
            let value = crate::stamp_value::value_of_product(&product);
            return Some((prv, public, value));
        }
    }
}

pub struct Identity {
    prv: Option<X25519PrivateKey>,
    sig_prv: Option<Ed25519PrivateKey>,
    pub_key: Option<X25519PublicKey>,
    sig_pub: Option<Ed25519PublicKey>,
    hash: [u8; 16],
}

impl Identity {
    pub fn new(rng: &mut dyn Rng) -> Self {
        let prv = X25519PrivateKey::generate(rng);
        let sig_prv = Ed25519PrivateKey::generate(rng);

        let pub_key = prv.public_key();
        let sig_pub = sig_prv.public_key();

        let mut pub_bytes = [0u8; 64];
        pub_bytes[..32].copy_from_slice(&pub_key.public_bytes());
        pub_bytes[32..].copy_from_slice(&sig_pub.public_bytes());

        let hash = truncated_hash(&pub_bytes);

        Identity {
            prv: Some(prv),
            sig_prv: Some(sig_prv),
            pub_key: Some(pub_key),
            sig_pub: Some(sig_pub),
            hash,
        }
    }

    /// Create an identity whose X25519 public key carries a stamp of at least
    /// `value` over the Ed25519 public key, mirroring upstream
    /// `Identity(value=n)`.
    pub fn new_stamped(rng: &mut dyn Rng, value: StampCost) -> Self {
        let sig_prv = Ed25519PrivateKey::generate(rng);
        let sig_pub = sig_prv.public_key();
        let (prv, pub_key, _value) = generate_stamped_key(rng, &sig_pub.public_bytes(), value);

        let mut pub_bytes = [0u8; 64];
        pub_bytes[..32].copy_from_slice(&pub_key.public_bytes());
        pub_bytes[32..].copy_from_slice(&sig_pub.public_bytes());
        let hash = truncated_hash(&pub_bytes);

        Identity {
            prv: Some(prv),
            sig_prv: Some(sig_prv),
            pub_key: Some(pub_key),
            sig_pub: Some(sig_pub),
            hash,
        }
    }

    /// Stamp value carried by this identity's public key, if available.
    pub fn get_value(&self) -> Option<StampValue> {
        match (&self.sig_pub, &self.pub_key) {
            (Some(sig_pub), Some(pub_key)) => Some(stamp_value(
                &sig_pub.public_bytes(),
                &pub_key.public_bytes(),
            )),
            _ => None,
        }
    }

    /// Load a complete private identity from its fixed-width key material.
    ///
    /// Valid input is represented by the 64-byte type itself, so successful
    /// construction returns `Self` directly instead of a fall-through status.
    pub fn from_private_key(prv_bytes: &[u8; 64]) -> Self {
        let x_prv_bytes: [u8; 32] = prv_bytes[..32].try_into().unwrap();
        let ed_seed: [u8; 32] = prv_bytes[32..].try_into().unwrap();

        let prv = X25519PrivateKey::from_bytes(&x_prv_bytes);
        let sig_prv = Ed25519PrivateKey::from_bytes(&ed_seed);

        let pub_key = prv.public_key();
        let sig_pub = sig_prv.public_key();

        let mut pub_bytes = [0u8; 64];
        pub_bytes[..32].copy_from_slice(&pub_key.public_bytes());
        pub_bytes[32..].copy_from_slice(&sig_pub.public_bytes());

        let hash = truncated_hash(&pub_bytes);

        Identity {
            prv: Some(prv),
            sig_prv: Some(sig_prv),
            pub_key: Some(pub_key),
            sig_pub: Some(sig_pub),
            hash,
        }
    }

    /// Load a public-only identity from fixed-width public key material.
    ///
    /// Any 32 bytes form a valid X25519 public key, but the Ed25519 half must
    /// decode to a valid curve point; otherwise this returns
    /// `CryptoError::InvalidPublicKey`.
    pub fn from_public_key(pub_bytes: &[u8; 64]) -> Result<Self, CryptoError> {
        let x_pub_bytes: [u8; 32] = pub_bytes[..32].try_into().unwrap();
        let ed_pub_bytes: [u8; 32] = pub_bytes[32..].try_into().unwrap();

        let pub_key = X25519PublicKey::from_bytes(&x_pub_bytes);
        let sig_pub = Ed25519PublicKey::from_bytes(&ed_pub_bytes)
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        let hash = truncated_hash(pub_bytes);

        Ok(Identity {
            prv: None,
            sig_prv: None,
            pub_key: Some(pub_key),
            sig_pub: Some(sig_pub),
            hash,
        })
    }

    pub fn get_private_key(&self) -> Option<[u8; 64]> {
        match (&self.prv, &self.sig_prv) {
            (Some(prv), Some(sig_prv)) => {
                let mut result = [0u8; 64];
                result[..32].copy_from_slice(&prv.private_bytes());
                result[32..].copy_from_slice(&sig_prv.private_bytes());
                Some(result)
            }
            _ => None,
        }
    }

    pub fn get_public_key(&self) -> Option<[u8; 64]> {
        match (&self.pub_key, &self.sig_pub) {
            (Some(pub_key), Some(sig_pub)) => {
                let mut result = [0u8; 64];
                result[..32].copy_from_slice(&pub_key.public_bytes());
                result[32..].copy_from_slice(&sig_pub.public_bytes());
                Some(result)
            }
            _ => None,
        }
    }

    pub fn hash(&self) -> &[u8; 16] {
        &self.hash
    }

    pub fn encrypt(&self, plaintext: &[u8], rng: &mut dyn Rng) -> Result<Vec<u8>, CryptoError> {
        let pub_key = self.pub_key.as_ref().ok_or(CryptoError::NoPublicKey)?;
        self.encrypt_to_public_key(plaintext, pub_key, rng)
    }

    pub fn encrypt_with_ratchet(
        &self,
        plaintext: &[u8],
        ratchet: Option<&[u8; 32]>,
        rng: &mut dyn Rng,
    ) -> Result<Vec<u8>, CryptoError> {
        match ratchet {
            Some(ratchet_pub_bytes) => {
                let ratchet_pub = X25519PublicKey::from_bytes(ratchet_pub_bytes);
                self.encrypt_to_public_key(plaintext, &ratchet_pub, rng)
            }
            None => self.encrypt(plaintext, rng),
        }
    }

    fn encrypt_to_public_key(
        &self,
        plaintext: &[u8],
        target_public_key: &X25519PublicKey,
        rng: &mut dyn Rng,
    ) -> Result<Vec<u8>, CryptoError> {
        let ephemeral = X25519PrivateKey::generate(rng);
        let ephemeral_pub_bytes = ephemeral.public_key().public_bytes();
        let shared_key = ephemeral.exchange(target_public_key);

        let derived_key = hkdf::hkdf(DERIVED_KEY_LENGTH, &shared_key, Some(&self.hash), None)
            .map_err(CryptoError::HkdfError)?;

        let token = Token::new(&derived_key).map_err(CryptoError::TokenError)?;
        let ciphertext = token.encrypt(plaintext, rng);

        let mut result = Vec::with_capacity(32 + ciphertext.len());
        result.extend_from_slice(&ephemeral_pub_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Encrypt with a specific ephemeral key and IV for deterministic testing
    pub fn encrypt_deterministic(
        &self,
        plaintext: &[u8],
        ephemeral_prv: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Vec<u8>, CryptoError> {
        let pub_key = self.pub_key.as_ref().ok_or(CryptoError::NoPublicKey)?;

        let ephemeral = X25519PrivateKey::from_bytes(ephemeral_prv);
        let ephemeral_pub_bytes = ephemeral.public_key().public_bytes();
        let shared_key = ephemeral.exchange(pub_key);

        let derived_key = hkdf::hkdf(DERIVED_KEY_LENGTH, &shared_key, Some(&self.hash), None)
            .map_err(CryptoError::HkdfError)?;

        let token = Token::new(&derived_key).map_err(CryptoError::TokenError)?;
        let ciphertext = token.encrypt_with_iv(plaintext, iv);

        let mut result = Vec::with_capacity(32 + ciphertext.len());
        result.extend_from_slice(&ephemeral_pub_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt(&self, ciphertext_token: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let prv = self.prv.as_ref().ok_or(CryptoError::NoPrivateKey)?;
        self.decrypt_with_key(ciphertext_token, prv)
    }

    /// Try newest-first destination keys, optionally forbidding identity-key fallback.
    /// The identity hash remains the HKDF salt, including for ratchet encryption.
    pub fn decrypt_with_ratchets(
        &self,
        ciphertext: &[u8],
        ratchets: &crate::ratchet::RatchetRing,
        enforce: bool,
    ) -> Result<crate::ratchet::Decrypted, CryptoError> {
        // Token length is independent of the candidate key. Do not scan retained
        // secrets when no candidate can possibly decrypt this input. Keep the
        // existing enforced/fallback error paths below.
        if ciphertext.len() > 32 + crate::token::TOKEN_OVERHEAD {
            for key in ratchets.keys() {
                let private = X25519PrivateKey::from_bytes(key);
                if let Ok(plaintext) = self.decrypt_with_key(ciphertext, &private) {
                    return Ok(crate::ratchet::Decrypted {
                        plaintext,
                        ratchet_id: Some(crate::ratchet::ratchet_id(
                            &private.public_key().public_bytes(),
                        )),
                    });
                }
            }
        }
        if enforce {
            return Err(CryptoError::InvalidCiphertext);
        }
        Ok(crate::ratchet::Decrypted {
            plaintext: self.decrypt(ciphertext)?,
            ratchet_id: None,
        })
    }

    fn decrypt_with_key(
        &self,
        ciphertext_token: &[u8],
        private: &X25519PrivateKey,
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext_token.len() <= 32 {
            return Err(CryptoError::InvalidCiphertext);
        }
        if ciphertext_token.len() <= 32 + crate::token::TOKEN_OVERHEAD {
            return Err(CryptoError::TokenError(TokenError::InvalidToken));
        }
        let peer_pub_bytes: [u8; 32] = ciphertext_token[..32].try_into().unwrap();
        let peer_pub = X25519PublicKey::from_bytes(&peer_pub_bytes);
        let shared_key = zeroize::Zeroizing::new(private.exchange(&peer_pub));
        let derived_key = zeroize::Zeroizing::new(
            hkdf::hkdf(DERIVED_KEY_LENGTH, &*shared_key, Some(&self.hash), None)
                .map_err(CryptoError::HkdfError)?,
        );
        let token = Token::new(&derived_key).map_err(CryptoError::TokenError)?;
        token
            .decrypt(&ciphertext_token[32..])
            .map_err(CryptoError::TokenError)
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], CryptoError> {
        let sig_prv = self.sig_prv.as_ref().ok_or(CryptoError::NoPrivateKey)?;
        Ok(sig_prv.sign(message))
    }

    pub fn verify(&self, signature: &[u8; 64], message: &[u8]) -> bool {
        match &self.sig_pub {
            Some(sig_pub) => sig_pub.verify(signature, message),
            None => false,
        }
    }
}

fn truncated_hash(data: &[u8]) -> [u8; 16] {
    let full = sha256::sha256(data);
    let mut result = [0u8; 16];
    result.copy_from_slice(&full[..16]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FixedRng;

    #[test]
    fn from_public_key_with_invalid_signing_key_returns_error() {
        let identity = Identity::from_private_key(&[0x37; 64]);
        let mut public_key = identity.get_public_key().unwrap();
        // y = 2 is not a valid compressed Ed25519 point encoding.
        public_key[32..].copy_from_slice(&[0; 32]);
        public_key[32] = 2;
        assert!(matches!(
            Identity::from_public_key(&public_key),
            Err(CryptoError::InvalidPublicKey)
        ));
    }

    #[test]
    fn from_public_key_accepts_valid_public_key() {
        let identity = Identity::from_private_key(&[0x37; 64]);
        let public_key = identity.get_public_key().unwrap();
        let public = Identity::from_public_key(&public_key).unwrap();
        assert_eq!(public.get_public_key(), Some(public_key));
        assert_eq!(public.hash(), identity.hash());
    }

    #[test]
    fn short_ratchet_ciphertexts_preserve_error_and_fallback_policy() {
        use crate::ratchet::RatchetRing;
        let identity = Identity::from_private_key(&[0x37; 64]);
        let public = Identity::from_public_key(&identity.get_public_key().unwrap()).unwrap();
        for retained in [0, 1, 32] {
            let ring = RatchetRing::from_keys(vec![[0x42; 32]; retained]).unwrap();
            for length in [0, 1, 31, 32, 33, 48, 79, 80] {
                let ciphertext = vec![0x63; length];
                for owner in [&identity, &public] {
                    assert!(matches!(
                        owner.decrypt_with_ratchets(&ciphertext, &ring, true),
                        Err(CryptoError::InvalidCiphertext)
                    ));
                    let expected = owner.decrypt(&ciphertext).unwrap_err();
                    let actual = owner
                        .decrypt_with_ratchets(&ciphertext, &ring, false)
                        .err()
                        .unwrap();
                    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
                }
                assert!(matches!(
                    public.decrypt(&ciphertext),
                    Err(CryptoError::NoPrivateKey)
                ));
                if length <= 32 {
                    assert!(matches!(
                        identity.decrypt(&ciphertext),
                        Err(CryptoError::InvalidCiphertext)
                    ));
                } else {
                    assert!(matches!(
                        identity.decrypt(&ciphertext),
                        Err(CryptoError::TokenError(TokenError::InvalidToken))
                    ));
                }
            }
        }
    }

    #[test]
    fn minimum_valid_ratchet_ciphertext_still_authenticates() {
        use crate::ratchet::{ratchet_id, RatchetRing};
        let identity = Identity::from_private_key(&[0x37; 64]);
        let public_identity =
            Identity::from_public_key(&identity.get_public_key().unwrap()).unwrap();
        let ring = RatchetRing::from_keys(vec![[0x42; 32]]).unwrap();
        let key = ring.current_public().unwrap();
        let mut ciphertext = identity
            .encrypt_with_ratchet(b"", Some(&key), &mut crate::FixedRng::new(&[0x63; 64]))
            .unwrap();
        assert_eq!(ciphertext.len(), 96);
        let result = public_identity
            .decrypt_with_ratchets(&ciphertext, &ring, true)
            .unwrap();
        assert!(result.plaintext.is_empty());
        assert_eq!(result.ratchet_id, Some(ratchet_id(&key)));
        *ciphertext.last_mut().unwrap() ^= 1;
        assert!(public_identity
            .decrypt_with_ratchets(&ciphertext, &ring, true)
            .is_err());
    }

    #[test]
    fn test_identity_key_roundtrip() {
        let mut rng = FixedRng::new(&(0..64).collect::<Vec<u8>>());
        let id = Identity::new(&mut rng);
        let prv_bytes = id.get_private_key().unwrap();
        let id2 = Identity::from_private_key(&prv_bytes);
        assert_eq!(id.get_public_key().unwrap(), id2.get_public_key().unwrap());
    }

    #[test]
    fn test_identity_hash() {
        let mut rng = FixedRng::new(&(0..64).collect::<Vec<u8>>());
        let id = Identity::new(&mut rng);
        let pub_key = id.get_public_key().unwrap();
        let expected_hash = truncated_hash(&pub_key);
        assert_eq!(*id.hash(), expected_hash);
    }

    #[test]
    fn test_identity_encrypt_decrypt_roundtrip() {
        let mut rng = FixedRng::new(&(0..128).collect::<Vec<u8>>());
        let id = Identity::new(&mut rng);
        let plaintext = b"Hello, Reticulum! This is a test of the encrypt/decrypt pipeline.";
        let mut rng2 = FixedRng::new(&(128..255).collect::<Vec<u8>>());
        let ciphertext = id.encrypt(plaintext, &mut rng2).unwrap();
        let decrypted = id.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_identity_encrypt_with_ratchet_targets_ratchet_key() {
        let mut rng = FixedRng::new(&(0..128).collect::<Vec<u8>>());
        let remote_identity = Identity::new(&mut rng);
        let ratchet_prv = X25519PrivateKey::from_bytes(&[0x42; 32]);
        let ratchet_pub = ratchet_prv.public_key().public_bytes();
        let plaintext = b"ratcheted";

        let mut encrypt_rng = FixedRng::new(&(128..255).collect::<Vec<u8>>());
        let ciphertext = remote_identity
            .encrypt_with_ratchet(plaintext, Some(&ratchet_pub), &mut encrypt_rng)
            .unwrap();

        let peer_pub_bytes: [u8; 32] = ciphertext[..32].try_into().unwrap();
        let peer_pub = X25519PublicKey::from_bytes(&peer_pub_bytes);
        let shared_key = ratchet_prv.exchange(&peer_pub);
        let derived_key = hkdf::hkdf(
            DERIVED_KEY_LENGTH,
            &shared_key,
            Some(remote_identity.hash()),
            None,
        )
        .unwrap();
        let token = Token::new(&derived_key).unwrap();
        let decrypted = token.decrypt(&ciphertext[32..]).unwrap();

        assert_eq!(decrypted, plaintext);
        assert!(remote_identity.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_identity_sign_verify() {
        let mut rng = FixedRng::new(&(0..64).collect::<Vec<u8>>());
        let id = Identity::new(&mut rng);
        let msg = b"Sign this message";
        let sig = id.sign(msg).unwrap();
        assert!(id.verify(&sig, msg));
        assert!(!id.verify(&sig, b"Wrong message"));
    }

    #[test]
    fn stamped_key_generation_until_meets_cost_when_never_stopped() {
        let mut rng = crate::OsRng;
        let material = b"link request material";
        let (prv, public, value) =
            generate_stamped_key_until(&mut rng, material, StampCost::from_whole(4), &mut || false)
                .unwrap();
        assert!(value.meets(StampCost::from_whole(4)));
        assert_eq!(public.public_bytes(), prv.public_key().public_bytes());
        assert_eq!(stamp_value(material, &public.public_bytes()), value);
    }

    #[test]
    fn stamped_key_generation_stops_when_asked() {
        let mut rng = crate::OsRng;
        let mut polls = 0u32;
        let result = generate_stamped_key_until(
            &mut rng,
            b"material",
            StampCost::from_whole(100),
            &mut || {
                polls += 1;
                polls > 3
            },
        );
        assert!(result.is_none());
        assert_eq!(polls, 4);
    }

    #[test]
    fn stamped_identity_carries_required_value() {
        let mut rng = crate::OsRng;
        let id = Identity::new_stamped(&mut rng, StampCost::from_whole(4));
        let value = id.get_value().unwrap();
        assert!(value.meets(StampCost::from_whole(4)));

        let public = id.get_public_key().unwrap();
        assert_eq!(stamp_value(&public[32..], &public[..32]), value);
    }
}
