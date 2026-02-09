//! Application-facing Destination and AnnouncedIdentity types.
//!
//! `Destination` is a pure data struct representing a network endpoint.
//! `AnnouncedIdentity` captures the result of a received announce.

use rns_core::destination::destination_hash;
use rns_core::types::{DestHash, DestinationType, Direction, IdentityHash, ProofStrategy};

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
            proof_strategy: ProofStrategy::ProveNone,
        }
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
}
