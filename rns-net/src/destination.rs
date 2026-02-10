//! Application-facing Destination and AnnouncedIdentity types.
//!
//! `Destination` is a pure data struct representing a network endpoint.
//! `AnnouncedIdentity` captures the result of a received announce.

use rns_core::destination::destination_hash;
use rns_core::types::{DestHash, DestinationType, Direction, IdentityHash, ProofStrategy};
use rns_crypto::token::Token;
use rns_crypto::OsRng;
use rns_crypto::Rng;

/// Errors related to GROUP destination key operations.
#[derive(Debug, PartialEq)]
pub enum GroupKeyError {
    /// No symmetric key has been loaded or generated.
    NoKey,
    /// Key must be 32 bytes (AES-128) or 64 bytes (AES-256).
    InvalidKeyLength,
    /// Encryption failed.
    EncryptionFailed,
    /// Decryption failed (wrong key, tampered data, or invalid format).
    DecryptionFailed,
}

impl core::fmt::Display for GroupKeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GroupKeyError::NoKey => write!(f, "No GROUP key loaded"),
            GroupKeyError::InvalidKeyLength => write!(f, "Key must be 32 or 64 bytes"),
            GroupKeyError::EncryptionFailed => write!(f, "Encryption failed"),
            GroupKeyError::DecryptionFailed => write!(f, "Decryption failed"),
        }
    }
}

/// A network destination (endpoint) for sending or receiving packets.
///
/// This is a pure data struct with no behavior — all operations
/// (register, announce, send) are methods on `RnsNode`.
#[derive(Debug, Clone)]
pub struct Destination {
    /// Computed destination hash.
    pub hash: DestHash,
    /// Type: Single, Group, or Plain.
    pub dest_type: DestinationType,
    /// Direction: In (receiving) or Out (sending).
    pub direction: Direction,
    /// Application name (e.g. "echo_app").
    pub app_name: String,
    /// Aspects (e.g. ["echo", "request"]).
    pub aspects: Vec<String>,
    /// Identity hash of the owner (for SINGLE destinations).
    pub identity_hash: Option<IdentityHash>,
    /// Full public key (64 bytes) of the remote peer (for OUT SINGLE destinations).
    pub public_key: Option<[u8; 64]>,
    /// Symmetric key for GROUP destinations (32 or 64 bytes).
    pub group_key: Option<Vec<u8>>,
    /// How to handle proofs for incoming packets.
    pub proof_strategy: ProofStrategy,
}

impl Destination {
    /// Create an inbound SINGLE destination (for receiving encrypted packets).
    ///
    /// `identity_hash` is the local identity that owns this destination.
    pub fn single_in(app_name: &str, aspects: &[&str], identity_hash: IdentityHash) -> Self {
        let dh = destination_hash(app_name, aspects, Some(&identity_hash.0));
        Destination {
            hash: DestHash(dh),
            dest_type: DestinationType::Single,
            direction: Direction::In,
            app_name: app_name.into(),
            aspects: aspects.iter().map(|s| s.to_string()).collect(),
            identity_hash: Some(identity_hash),
            public_key: None,
            group_key: None,
            proof_strategy: ProofStrategy::ProveNone,
        }
    }

    /// Create an outbound SINGLE destination (for sending encrypted packets).
    ///
    /// `recalled` contains the remote peer's identity data (from announce/recall).
    pub fn single_out(app_name: &str, aspects: &[&str], recalled: &AnnouncedIdentity) -> Self {
        let dh = destination_hash(app_name, aspects, Some(&recalled.identity_hash.0));
        Destination {
            hash: DestHash(dh),
            dest_type: DestinationType::Single,
            direction: Direction::Out,
            app_name: app_name.into(),
            aspects: aspects.iter().map(|s| s.to_string()).collect(),
            identity_hash: Some(recalled.identity_hash),
            public_key: Some(recalled.public_key),
            group_key: None,
            proof_strategy: ProofStrategy::ProveNone,
        }
    }

    /// Create a PLAIN destination (unencrypted, no identity).
    pub fn plain(app_name: &str, aspects: &[&str]) -> Self {
        let dh = destination_hash(app_name, aspects, None);
        Destination {
            hash: DestHash(dh),
            dest_type: DestinationType::Plain,
            direction: Direction::In,
            app_name: app_name.into(),
            aspects: aspects.iter().map(|s| s.to_string()).collect(),
            identity_hash: None,
            public_key: None,
            group_key: None,
            proof_strategy: ProofStrategy::ProveNone,
        }
    }

    /// Create a GROUP destination (symmetric encryption with pre-shared key).
    ///
    /// No identity needed — the hash is based only on app_name + aspects,
    /// same as PLAIN. All members sharing the same key can encrypt/decrypt.
    pub fn group(app_name: &str, aspects: &[&str]) -> Self {
        let dh = destination_hash(app_name, aspects, None);
        Destination {
            hash: DestHash(dh),
            dest_type: DestinationType::Group,
            direction: Direction::In,
            app_name: app_name.into(),
            aspects: aspects.iter().map(|s| s.to_string()).collect(),
            identity_hash: None,
            public_key: None,
            group_key: None,
            proof_strategy: ProofStrategy::ProveNone,
        }
    }

    /// Generate a new random 64-byte symmetric key (AES-256) for this GROUP destination.
    pub fn create_keys(&mut self) {
        let mut key = vec![0u8; 64];
        OsRng.fill_bytes(&mut key);
        self.group_key = Some(key);
    }

    /// Load an existing symmetric key for this GROUP destination.
    ///
    /// Key must be 32 bytes (AES-128) or 64 bytes (AES-256).
    pub fn load_private_key(&mut self, key: Vec<u8>) -> Result<(), GroupKeyError> {
        if key.len() != 32 && key.len() != 64 {
            return Err(GroupKeyError::InvalidKeyLength);
        }
        self.group_key = Some(key);
        Ok(())
    }

    /// Retrieve the symmetric key bytes, if set.
    pub fn get_private_key(&self) -> Option<&[u8]> {
        self.group_key.as_deref()
    }

    /// Encrypt plaintext using this destination's GROUP key.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, GroupKeyError> {
        let key = self.group_key.as_ref().ok_or(GroupKeyError::NoKey)?;
        let token = Token::new(key).map_err(|_| GroupKeyError::EncryptionFailed)?;
        Ok(token.encrypt(plaintext, &mut OsRng))
    }

    /// Decrypt ciphertext using this destination's GROUP key.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, GroupKeyError> {
        let key = self.group_key.as_ref().ok_or(GroupKeyError::NoKey)?;
        let token = Token::new(key).map_err(|_| GroupKeyError::DecryptionFailed)?;
        token.decrypt(ciphertext).map_err(|_| GroupKeyError::DecryptionFailed)
    }

    /// Set the proof strategy for this destination.
    pub fn set_proof_strategy(mut self, strategy: ProofStrategy) -> Self {
        self.proof_strategy = strategy;
        self
    }
}

/// Information about an announced identity, received via announce or recalled from cache.
#[derive(Debug, Clone)]
pub struct AnnouncedIdentity {
    /// Destination hash that was announced.
    pub dest_hash: DestHash,
    /// Identity hash (truncated SHA-256 of public key).
    pub identity_hash: IdentityHash,
    /// Full public key (X25519 32 bytes + Ed25519 32 bytes).
    pub public_key: [u8; 64],
    /// Optional application data included in the announce.
    pub app_data: Option<Vec<u8>>,
    /// Number of hops this announce has traveled.
    pub hops: u8,
    /// Timestamp when this announce was received.
    pub received_at: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity_hash() -> IdentityHash {
        IdentityHash([0x42; 16])
    }

    fn test_announced() -> AnnouncedIdentity {
        AnnouncedIdentity {
            dest_hash: DestHash([0xAA; 16]),
            identity_hash: IdentityHash([0x42; 16]),
            public_key: [0xBB; 64],
            app_data: Some(b"test_data".to_vec()),
            hops: 3,
            received_at: 1234567890.0,
        }
    }

    #[test]
    fn single_in_hash_matches_raw() {
        let ih = test_identity_hash();
        let dest = Destination::single_in("echo", &["app"], ih);

        let raw = destination_hash("echo", &["app"], Some(&ih.0));
        assert_eq!(dest.hash.0, raw);
        assert_eq!(dest.dest_type, DestinationType::Single);
        assert_eq!(dest.direction, Direction::In);
        assert_eq!(dest.app_name, "echo");
        assert_eq!(dest.aspects, vec!["app".to_string()]);
        assert_eq!(dest.identity_hash, Some(ih));
        assert!(dest.public_key.is_none());
    }

    #[test]
    fn single_out_from_recalled() {
        let recalled = test_announced();
        let dest = Destination::single_out("echo", &["app"], &recalled);

        let raw = destination_hash("echo", &["app"], Some(&recalled.identity_hash.0));
        assert_eq!(dest.hash.0, raw);
        assert_eq!(dest.dest_type, DestinationType::Single);
        assert_eq!(dest.direction, Direction::Out);
        assert_eq!(dest.public_key, Some([0xBB; 64]));
    }

    #[test]
    fn plain_destination() {
        let dest = Destination::plain("broadcast", &["test"]);

        let raw = destination_hash("broadcast", &["test"], None);
        assert_eq!(dest.hash.0, raw);
        assert_eq!(dest.dest_type, DestinationType::Plain);
        assert!(dest.identity_hash.is_none());
        assert!(dest.public_key.is_none());
    }

    #[test]
    fn destination_deterministic() {
        let ih = test_identity_hash();
        let d1 = Destination::single_in("app", &["a", "b"], ih);
        let d2 = Destination::single_in("app", &["a", "b"], ih);
        assert_eq!(d1.hash, d2.hash);
    }

    #[test]
    fn different_identity_different_hash() {
        let d1 = Destination::single_in("app", &["a"], IdentityHash([1; 16]));
        let d2 = Destination::single_in("app", &["a"], IdentityHash([2; 16]));
        assert_ne!(d1.hash, d2.hash);
    }

    #[test]
    fn proof_strategy_builder() {
        let dest = Destination::plain("app", &["a"])
            .set_proof_strategy(ProofStrategy::ProveAll);
        assert_eq!(dest.proof_strategy, ProofStrategy::ProveAll);
    }

    #[test]
    fn announced_identity_fields() {
        let ai = test_announced();
        assert_eq!(ai.dest_hash, DestHash([0xAA; 16]));
        assert_eq!(ai.identity_hash, IdentityHash([0x42; 16]));
        assert_eq!(ai.public_key, [0xBB; 64]);
        assert_eq!(ai.app_data, Some(b"test_data".to_vec()));
        assert_eq!(ai.hops, 3);
        assert_eq!(ai.received_at, 1234567890.0);
    }

    #[test]
    fn multiple_aspects() {
        let dest = Destination::plain("app", &["one", "two", "three"]);
        assert_eq!(dest.aspects, vec!["one", "two", "three"]);
    }

    // --- GROUP destination tests ---

    #[test]
    fn group_destination_hash_deterministic() {
        let d1 = Destination::group("myapp", &["chat", "room"]);
        let d2 = Destination::group("myapp", &["chat", "room"]);
        assert_eq!(d1.hash, d2.hash);
        assert_eq!(d1.dest_type, DestinationType::Group);
        assert_eq!(d1.direction, Direction::In);
        assert!(d1.identity_hash.is_none());
        assert!(d1.public_key.is_none());
        assert!(d1.group_key.is_none());
    }

    #[test]
    fn group_destination_hash_matches_plain_hash() {
        let group = Destination::group("broadcast", &["test"]);
        let plain = Destination::plain("broadcast", &["test"]);
        // GROUP and PLAIN with same name produce the same hash (no identity component)
        assert_eq!(group.hash, plain.hash);
    }

    #[test]
    fn group_create_keys() {
        let mut dest = Destination::group("app", &["g"]);
        assert!(dest.group_key.is_none());
        dest.create_keys();
        let key = dest.group_key.as_ref().unwrap();
        assert_eq!(key.len(), 64);
        // Key should not be all zeros (astronomically unlikely with real RNG)
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn group_load_private_key_64() {
        let mut dest = Destination::group("app", &["g"]);
        let key = vec![0x42u8; 64];
        assert!(dest.load_private_key(key.clone()).is_ok());
        assert_eq!(dest.get_private_key(), Some(key.as_slice()));
    }

    #[test]
    fn group_load_private_key_32() {
        let mut dest = Destination::group("app", &["g"]);
        let key = vec![0xAB; 32];
        assert!(dest.load_private_key(key.clone()).is_ok());
        assert_eq!(dest.get_private_key(), Some(key.as_slice()));
    }

    #[test]
    fn group_load_private_key_invalid_length() {
        let mut dest = Destination::group("app", &["g"]);
        assert_eq!(
            dest.load_private_key(vec![0; 48]),
            Err(GroupKeyError::InvalidKeyLength)
        );
        assert_eq!(
            dest.load_private_key(vec![0; 16]),
            Err(GroupKeyError::InvalidKeyLength)
        );
    }

    #[test]
    fn group_encrypt_decrypt_roundtrip() {
        let mut dest = Destination::group("app", &["secure"]);
        dest.load_private_key(vec![0x42u8; 64]).unwrap();

        let plaintext = b"Hello, GROUP destination!";
        let ciphertext = dest.encrypt(plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);
        assert!(ciphertext.len() > plaintext.len()); // includes IV + HMAC overhead

        let decrypted = dest.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn group_decrypt_wrong_key_fails() {
        let mut dest1 = Destination::group("app", &["a"]);
        dest1.load_private_key(vec![0x42u8; 64]).unwrap();

        let mut dest2 = Destination::group("app", &["a"]);
        dest2.load_private_key(vec![0xBBu8; 64]).unwrap();

        let ciphertext = dest1.encrypt(b"secret").unwrap();
        assert_eq!(dest2.decrypt(&ciphertext), Err(GroupKeyError::DecryptionFailed));
    }

    #[test]
    fn group_encrypt_without_key_fails() {
        let dest = Destination::group("app", &["a"]);
        assert_eq!(dest.encrypt(b"test"), Err(GroupKeyError::NoKey));
        assert_eq!(dest.decrypt(b"test"), Err(GroupKeyError::NoKey));
    }

    #[test]
    fn group_key_interop_with_token() {
        // Encrypt with Token directly, decrypt with Destination (and vice versa)
        let key = vec![0x42u8; 64];

        let token = Token::new(&key).unwrap();
        let ciphertext = token.encrypt(b"from token", &mut OsRng);

        let mut dest = Destination::group("app", &["a"]);
        dest.load_private_key(key.clone()).unwrap();
        let decrypted = dest.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, b"from token");

        // And the other direction
        let ciphertext2 = dest.encrypt(b"from dest").unwrap();
        let decrypted2 = token.decrypt(&ciphertext2).unwrap();
        assert_eq!(decrypted2, b"from dest");
    }

    #[test]
    fn group_encrypt_decrypt_32byte_key() {
        let mut dest = Destination::group("app", &["aes128"]);
        dest.load_private_key(vec![0xABu8; 32]).unwrap();

        let plaintext = b"AES-128 mode";
        let ciphertext = dest.encrypt(plaintext).unwrap();
        let decrypted = dest.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
