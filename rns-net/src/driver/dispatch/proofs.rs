//! Packet proofs: when to send one, and checking those that arrive.

use super::*;

impl Driver {
    /// Whether a plain link packet on a link to `dest_hash` is proved, by
    /// that destination's proof strategy (upstream `Link.receive`): always
    /// under PROVE_ALL, when the application agrees under PROVE_APP, and
    /// never under PROVE_NONE, the default for an unregistered destination.
    pub(crate) fn link_packet_proof_wanted(
        &mut self,
        dest_hash: [u8; 16],
        packet_hash: &[u8; 32],
    ) -> bool {
        use rns_core::types::ProofStrategy;
        match self
            .proofs
            .strategies
            .get(&dest_hash)
            .map(|(strategy, _)| *strategy)
        {
            Some(ProofStrategy::ProveAll) => true,
            Some(ProofStrategy::ProveApp) => self.callbacks.on_proof_requested(
                rns_core::types::DestHash(dest_hash),
                rns_core::types::PacketHash(*packet_hash),
            ),
            Some(ProofStrategy::ProveNone) | None => false,
        }
    }

    /// Prove a packet received for `dest_hash` as its proof strategy says.
    /// The proof goes back on `interface`, where the packet arrived, as
    /// upstream attaches it; without one it is sent as transport routes it.
    pub(crate) fn maybe_generate_proof(
        &mut self,
        dest_hash: [u8; 16],
        packet_hash: &[u8; 32],
        interface: Option<InterfaceId>,
    ) {
        use rns_core::types::ProofStrategy;

        let (strategy, identity) = match self.proofs.strategies.get(&dest_hash) {
            Some((s, id)) => (*s, id.as_ref()),
            None => return,
        };

        let should_prove = match strategy {
            ProofStrategy::ProveAll => true,
            ProofStrategy::ProveApp => self.callbacks.on_proof_requested(
                rns_core::types::DestHash(dest_hash),
                rns_core::types::PacketHash(*packet_hash),
            ),
            ProofStrategy::ProveNone => false,
        };

        if !should_prove {
            return;
        }

        let identity = match identity {
            Some(id) => id,
            None => {
                log::warn!(
                    "Cannot generate proof for {:02x?}: no signing key",
                    &dest_hash[..4]
                );
                return;
            }
        };

        // Signed on the proof pool when there is one: the proof goes out once
        // the driver takes the signature back.
        if let Some(key) = identity.signing_key() {
            if self.link_manager.submit_packet_proof_sign(
                dest_hash,
                *packet_hash,
                interface,
                key.clone(),
            ) {
                return;
            }
        }
        let signature = match identity.sign(packet_hash) {
            Ok(sig) => sig,
            Err(e) => {
                log::warn!("Failed to sign proof for {:02x?}: {:?}", &dest_hash[..4], e);
                return;
            }
        };
        self.send_packet_proof(dest_hash, packet_hash, &signature, interface);
    }

    /// Send the proof of a packet received for `dest_hash` on `interface`,
    /// where the packet arrived.
    pub(super) fn send_packet_proof(
        &mut self,
        dest_hash: [u8; 16],
        packet_hash: &[u8; 32],
        signature: &[u8; 64],
        interface: Option<InterfaceId>,
    ) {
        // As upstream's `Identity.prove`: implicit [signature:64], or
        // explicit [packet_hash:32][signature:64].
        let mut proof_data = Vec::with_capacity(96);
        if !self.proofs.implicit {
            proof_data.extend_from_slice(packet_hash);
        }
        proof_data.extend_from_slice(signature);

        // Address the proof to the truncated packet hash (first 16 bytes),
        // matching Python's ProofDestination (Packet.py:390-394).
        // Transport nodes create reverse_table entries keyed by truncated
        // packet hash when forwarding data, so this allows proofs to be
        // routed back to the sender via the reverse path.
        let mut proof_dest = [0u8; 16];
        proof_dest.copy_from_slice(&packet_hash[..16]);

        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: rns_core::constants::FLAG_UNSET,
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: rns_core::constants::DESTINATION_SINGLE,
            packet_type: rns_core::constants::PACKET_TYPE_PROOF,
        };

        if let Ok(packet) = RawPacket::pack(
            flags,
            0,
            &proof_dest,
            None,
            rns_core::constants::CONTEXT_NONE,
            &proof_data,
        ) {
            let actions = self.engine.handle_outbound(
                &packet,
                rns_core::constants::DESTINATION_SINGLE,
                interface,
                time::now(),
            );
            self.dispatch_all(actions);
            log::debug!(
                "Generated proof for packet on dest {:02x?}",
                &dest_hash[..4]
            );
        }
    }

    /// Apply single-packet proofs the proof pool finished: deliver checked
    /// proofs, send signed ones.
    pub(crate) fn apply_packet_proofs(&mut self) {
        use crate::common::link_manager::{ProofOutcome, ProofOwner};
        let mut outcomes = core::mem::take(&mut self.proofs.pool_outcomes);
        self.link_manager.take_packet_proofs(&mut outcomes);
        for outcome in outcomes.drain(..) {
            match outcome {
                ProofOutcome::Verified {
                    owner:
                        ProofOwner::Packet {
                            destination,
                            rtt,
                            proof_packet,
                            ..
                        },
                    packet_hash,
                    valid,
                } => {
                    if valid {
                        self.packet_proof_valid(destination, packet_hash, rtt, proof_packet);
                    } else {
                        log::debug!("Proof signature invalid for {:02x?}", &packet_hash[..4]);
                    }
                }
                ProofOutcome::Signed {
                    owner:
                        ProofOwner::Packet {
                            destination,
                            interface,
                            ..
                        },
                    packet_hash,
                    signature,
                } => self.send_packet_proof(destination, &packet_hash, &signature, interface),
                ProofOutcome::Encrypted {
                    ticket,
                    destination,
                    payload,
                } => self.send_deferred(ticket, destination, payload),
                ProofOutcome::Decrypted {
                    destination,
                    packet_hash,
                    interface,
                    plaintext,
                } => self.deliver_decrypted(destination, packet_hash, interface, plaintext),
                // Link outcomes are applied by the link manager.
                ProofOutcome::Verified { .. } | ProofOutcome::Signed { .. } => {}
            }
        }
        self.proofs.pool_outcomes = outcomes;
    }

    /// Handle an inbound proof packet: validate and fire on_proof callback.
    pub(crate) fn handle_inbound_proof(
        &mut self,
        dest_hash: [u8; 16],
        proof_data: &[u8],
        proof_packet_hash: &[u8; 32],
    ) {
        // Reticulum supports both proof formats:
        // - explicit: [packet_hash:32][signature:64]
        // - implicit: [signature:64], keyed by proof destination hash
        let (tracked_hash, signature): ([u8; 32], &[u8]) = if proof_data.len() >= 96 {
            let mut tracked_hash = [0u8; 32];
            tracked_hash.copy_from_slice(&proof_data[..32]);
            (tracked_hash, &proof_data[32..96])
        } else if proof_data.len() == 64 {
            let mut candidates = self
                .proofs
                .sent_packets
                .keys()
                .filter_map(|packet_hash| {
                    if packet_hash[..16] == dest_hash {
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
                return;
            }

            // Multiple matches are extremely unlikely (16-byte truncated hash).
            // Use the newest tracked packet for deterministic behavior.
            if candidates.len() > 1 {
                candidates.sort_by(|a, b| {
                    let ta = self
                        .proofs
                        .sent_packets
                        .get(a)
                        .map(|(_, t)| *t)
                        .unwrap_or_default();
                    let tb = self
                        .proofs
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

            (candidates[0], &proof_data[..64])
        } else {
            log::debug!("Unsupported proof length: {} bytes", proof_data.len());
            return;
        };

        // The receipt stays until a proof checks out, so that a forged proof
        // cannot keep the genuine one from completing it.
        let Some(&(tracked_dest, sent_time)) = self.proofs.sent_packets.get(&tracked_hash) else {
            log::debug!(
                "Proof for unknown packet {:02x?} on dest {:02x?}",
                &tracked_hash[..4],
                &dest_hash[..4],
            );
            return;
        };
        if self.link_manager.link_state(&tracked_dest).is_some() {
            // A packet sent on a link is proved by the link's peer, on that
            // link: the link manager checks the proof against the peer's key
            // and reports it (`link_packet_proved`). As upstream's
            // `PacketReceipt.validate_proof`, refuse it arriving otherwise.
            log::debug!(
                "Proof for link packet {:02x?} outside its link {:02x?}",
                &tracked_hash[..4],
                &tracked_dest[..4],
            );
            return;
        }
        let rtt = time::now() - sent_time;
        // Checked with the destination's public key, as Python's
        // `PacketReceipt.validate_proof`: the identity the packet was
        // encrypted for, else the destination's known one. Without either
        // the proof cannot be checked and is not accepted.
        let key = match self.proofs.sent_packet_keys.get(&tracked_hash) {
            Some(bytes) => Some(rns_crypto::ed25519::Ed25519PublicKey::from_bytes(bytes).ok()),
            None => self.proof_key(&tracked_dest),
        };
        let key = match key {
            Some(Some(key)) => key,
            Some(None) => {
                log::debug!("Proof signature invalid for {:02x?}", &tracked_hash[..4]);
                return;
            }
            None => {
                log::debug!(
                    "No known identity for dest {:02x?}, cannot check proof",
                    &tracked_dest[..4],
                );
                return;
            }
        };
        let mut sig = [0u8; 64];
        sig.copy_from_slice(signature);
        // Checked on the proof pool when there is one, batched with the
        // proofs queued with it.
        if self.link_manager.submit_packet_proof_check(
            tracked_dest,
            tracked_hash,
            sig,
            key.clone(),
            rtt,
            *proof_packet_hash,
        ) {
            return;
        }
        if !key.verify(&sig, &tracked_hash) {
            log::debug!("Proof signature invalid for {:02x?}", &tracked_hash[..4]);
            return;
        }
        self.packet_proof_valid(tracked_dest, tracked_hash, rtt, Some(*proof_packet_hash));
    }

    /// Complete the receipt of a packet sent to `destination` whose proof's
    /// signature checked out, unless another proof completed it first.
    pub(super) fn packet_proof_valid(
        &mut self,
        destination: [u8; 16],
        packet_hash: [u8; 32],
        rtt: f64,
        proof_packet: Option<[u8; 32]>,
    ) {
        if self.proofs.sent_packets.remove(&packet_hash).is_none() {
            return;
        }
        self.proofs.sent_packet_keys.remove(&packet_hash);
        let _ = self.known.mark_used(&destination);
        self.packet_proof_accepted(destination, packet_hash, rtt, proof_packet);
    }

    /// The peer of `link_id` proved `packet_hash`: complete its receipt if
    /// the packet was sent on that link. A proof the peer of another link
    /// signed proves nothing about this one.
    pub(super) fn link_packet_proved(&mut self, link_id: [u8; 16], packet_hash: [u8; 32]) {
        match self.proofs.sent_packets.get(&packet_hash) {
            Some(&(destination, sent_time)) if destination == link_id => {
                self.proofs.sent_packets.remove(&packet_hash);
                self.packet_proof_accepted(link_id, packet_hash, time::now() - sent_time, None);
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
    pub(super) fn packet_proof_accepted(
        &mut self,
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
        if self.proofs.pending_probes.remove(&packet_hash) {
            self.proofs
                .completed
                .insert(packet_hash, (rtt, time::now()));
        }
        self.callbacks.on_proof_packet(
            rns_core::types::DestHash(destination),
            rns_core::types::PacketHash(packet_hash),
            rtt,
            proof_packet.map(rns_core::types::PacketHash),
        );
    }

    /// The signing key a proof for a packet sent to `destination` is checked
    /// with: `None` when the destination's identity is unknown, `Some(None)`
    /// when its announced key does not parse.
    pub(super) fn proof_key(
        &mut self,
        destination: &[u8; 16],
    ) -> Option<Option<rns_crypto::ed25519::Ed25519PublicKey>> {
        let public_key = self.known.entries.get(destination)?.announced.public_key;
        if let Some(key) = self.proofs.keys.get(destination) {
            return Some(Some(key.clone()));
        }
        let (_, ed_bytes) = rns_crypto::identity::split_key(&public_key);
        let Ok(key) = rns_crypto::ed25519::Ed25519PublicKey::from_bytes(&ed_bytes) else {
            return Some(None);
        };
        // Bounded like a cache: refilled from the known destinations.
        if self.proofs.keys.len() >= 4096 {
            self.proofs.keys.clear();
        }
        self.proofs.keys.insert(*destination, key.clone());
        Some(Some(key))
    }
}
