//! The driver's packet proof bookkeeping.

use super::*;

/// Packet proofs: the sent packets awaiting proofs and the keys those
/// proofs are checked with, probe results, and how local destinations
/// prove the packets they receive.
pub(crate) struct PacketProofs {
    /// Tracked sent packets for proof matching: packet_hash → (dest_hash, sent_time).
    pub(crate) sent_packets: HashMap<[u8; 32], ([u8; 16], f64)>,
    /// The signing keys proofs of tracked sent packets are checked with,
    /// for packets sent with the identity they were encrypted for:
    /// packet_hash → Ed25519 public key bytes.
    pub(crate) sent_packet_keys: HashMap<[u8; 32], [u8; 32]>,
    /// Parsed signing keys of destinations whose packet proofs were checked.
    /// A destination's hash follows from its identity, so its key never
    /// changes.
    pub(crate) keys: HashMap<[u8; 16], rns_crypto::ed25519::Ed25519PublicKey>,
    /// Completed proofs for probe polling: packet_hash → (rtt_seconds, received_time).
    /// Only probes ([`QueryRequest::SendProbe`]) are recorded: a proof for
    /// every other packet would be kept two minutes for nobody to poll.
    pub(crate) completed: HashMap<[u8; 32], (f64, f64)>,
    /// Probes sent and not yet proved, whose proofs `completed` records.
    pub(crate) pending_probes: HashSet<[u8; 32]>,
    /// Proof strategies per local destination hash: the strategy and the
    /// optional signing identity proofs are generated with.
    pub(crate) strategies: HashMap<
        [u8; 16],
        (
            rns_core::types::ProofStrategy,
            Option<rns_crypto::identity::Identity>,
        ),
    >,
    /// Reused buffer for single-packet proofs the proof pool finished.
    pub(crate) pool_outcomes: Vec<crate::common::link_manager::ProofOutcome>,
    /// Prove received single packets implicitly, with the signature alone,
    /// as upstream's `use_implicit_proof` (on by default).
    pub(crate) implicit: bool,
}

impl PacketProofs {
    pub(crate) fn new() -> Self {
        Self {
            sent_packets: HashMap::new(),
            sent_packet_keys: HashMap::new(),
            keys: HashMap::new(),
            completed: HashMap::new(),
            pending_probes: HashSet::new(),
            strategies: HashMap::new(),
            pool_outcomes: Vec::new(),
            implicit: true,
        }
    }
}
