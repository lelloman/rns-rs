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

impl PacketProofs {
    /// Prove the packets `dest_hash` receives as `strategy` says, signing
    /// with `signing_key`.
    pub(crate) fn register_strategy(
        &mut self,
        dest_hash: [u8; 16],
        strategy: rns_core::types::ProofStrategy,
        signing_key: Option<[u8; 64]>,
    ) {
        let identity =
            signing_key.map(|key| rns_crypto::identity::Identity::from_private_key(&key));
        self.strategies.insert(dest_hash, (strategy, identity));
    }

    /// The tracked packet a received proof for `dest_hash` proves, and the
    /// proof's signature. Reticulum supports both proof formats:
    /// - explicit: [packet_hash:32][signature:64]
    /// - implicit: [signature:64], keyed by proof destination hash
    pub(crate) fn proved_packet<'a>(
        &self,
        dest_hash: &[u8; 16],
        proof_data: &'a [u8],
    ) -> Option<([u8; 32], &'a [u8])> {
        if let Some((tracked_hash, rest)) = proof_data
            .split_first_chunk::<32>()
            .filter(|_| proof_data.len() >= 96)
        {
            Some((*tracked_hash, rest.get(..64)?))
        } else if proof_data.len() == 64 {
            let mut candidates = self
                .sent_packets
                .keys()
                .filter_map(|packet_hash| {
                    if packet_hash[..16] == *dest_hash {
                        Some(*packet_hash)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            if candidates.is_empty() {
                log::debug!(
                    "Implicit proof for unknown packet prefix {:02x?} on dest {:02x?}",
                    &dest_hash[..4],
                    &dest_hash[..4]
                );
                return None;
            }

            // Multiple matches are extremely unlikely (16-byte truncated hash).
            // Use the newest tracked packet for deterministic behavior.
            if candidates.len() > 1 {
                candidates.sort_by(|a, b| {
                    let ta = self
                        .sent_packets
                        .get(a)
                        .map(|(_, t)| *t)
                        .unwrap_or_default();
                    let tb = self
                        .sent_packets
                        .get(b)
                        .map(|(_, t)| *t)
                        .unwrap_or_default();
                    tb.partial_cmp(&ta).unwrap_or(core::cmp::Ordering::Equal)
                });
                log::debug!(
                    "Implicit proof matched {} candidates for prefix {:02x?}; using newest",
                    candidates.len(),
                    &dest_hash[..4]
                );
            }

            Some((*candidates.first()?, proof_data))
        } else {
            log::debug!("Unsupported proof length: {} bytes", proof_data.len());
            None
        }
    }

    /// Whether a plain link packet on a link to `dest_hash` is proved, by
    /// that destination's proof strategy (upstream `Link.receive`): always
    /// under PROVE_ALL, when the application agrees under PROVE_APP, and
    /// never under PROVE_NONE, the default for an unregistered destination.
    pub(crate) fn link_packet_proof_wanted(
        &self,
        callbacks: &mut dyn Callbacks,
        dest_hash: [u8; 16],
        packet_hash: &[u8; 32],
    ) -> bool {
        use rns_core::types::ProofStrategy;
        match self
            .strategies
            .get(&dest_hash)
            .map(|(strategy, _)| *strategy)
        {
            Some(ProofStrategy::ProveAll) => true,
            Some(ProofStrategy::ProveApp) => callbacks.on_proof_requested(
                rns_core::types::DestHash(dest_hash),
                rns_core::types::PacketHash(*packet_hash),
            ),
            Some(ProofStrategy::ProveNone) | None => false,
        }
    }

    /// Complete the receipt of a packet sent to `destination` whose proof's
    /// signature checked out, unless another proof completed it first.
    pub(crate) fn proof_valid(
        &mut self,
        known: &mut known_destinations::KnownDestinations,
        callbacks: &mut dyn Callbacks,
        destination: [u8; 16],
        packet_hash: [u8; 32],
        rtt: f64,
        proof_packet: Option<[u8; 32]>,
    ) {
        if self.sent_packets.remove(&packet_hash).is_none() {
            return;
        }
        self.sent_packet_keys.remove(&packet_hash);
        let _ = known.mark_used(&destination);
        self.proof_accepted(callbacks, destination, packet_hash, rtt, proof_packet);
    }

    /// The peer of `link_id` proved `packet_hash`: complete its receipt if
    /// the packet was sent on that link. A proof the peer of another link
    /// signed proves nothing about this one.
    pub(crate) fn link_packet_proved(
        &mut self,
        callbacks: &mut dyn Callbacks,
        link_id: [u8; 16],
        packet_hash: [u8; 32],
    ) {
        match self.sent_packets.get(&packet_hash) {
            Some(&(destination, sent_time)) if destination == link_id => {
                self.sent_packets.remove(&packet_hash);
                self.proof_accepted(
                    callbacks,
                    link_id,
                    packet_hash,
                    time::now() - sent_time,
                    None,
                );
            }
            Some(_) => log::debug!(
                "Proof on link {:02x?} for {:02x?}, not sent on it",
                &link_id[..4],
                &packet_hash[..4],
            ),
            // Untracked, or completed by another copy of the proof.
            None => {}
        }
    }

    /// Complete the receipt of a packet sent to `destination` whose proof
    /// was accepted; `proof_packet` is the packet that carried the proof.
    fn proof_accepted(
        &mut self,
        callbacks: &mut dyn Callbacks,
        destination: [u8; 16],
        packet_hash: [u8; 32],
        rtt: f64,
        proof_packet: Option<[u8; 32]>,
    ) {
        log::debug!(
            "Proof received for {:02x?} rtt={:.3}s",
            &packet_hash[..4],
            rtt,
        );
        if self.pending_probes.remove(&packet_hash) {
            self.completed.insert(packet_hash, (rtt, time::now()));
        }
        callbacks.on_proof_packet(
            rns_core::types::DestHash(destination),
            rns_core::types::PacketHash(packet_hash),
            rtt,
            proof_packet.map(rns_core::types::PacketHash),
        );
    }

    /// The signing key a proof for a packet sent to `destination` is checked
    /// with: `None` when the destination's identity is unknown in `known`,
    /// `Some(None)` when its announced key does not parse.
    pub(crate) fn proof_key(
        &mut self,
        known: &known_destinations::KnownDestinations,
        destination: &[u8; 16],
    ) -> Option<Option<rns_crypto::ed25519::Ed25519PublicKey>> {
        let public_key = known.entries.get(destination)?.announced.public_key;
        if let Some(key) = self.keys.get(destination) {
            return Some(Some(key.clone()));
        }
        let (_, ed_bytes) = rns_crypto::identity::split_key(&public_key);
        let Ok(key) = rns_crypto::ed25519::Ed25519PublicKey::from_bytes(&ed_bytes) else {
            return Some(None);
        };
        // Bounded like a cache: refilled from the known destinations.
        if self.keys.len() >= 4096 {
            self.keys.clear();
        }
        self.keys.insert(*destination, key.clone());
        Some(Some(key))
    }
}
