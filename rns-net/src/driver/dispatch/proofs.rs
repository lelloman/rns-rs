//! Packet proofs: when to send one, and checking those that arrive.

use super::*;

impl Driver {
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
                        self.proofs.proof_valid(
                            &mut self.known,
                            &mut *self.callbacks,
                            destination,
                            packet_hash,
                            rtt,
                            proof_packet,
                        );
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
        let Some((tracked_hash, signature)) = self.proofs.proved_packet(&dest_hash, proof_data)
        else {
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
            None => self.proofs.proof_key(&self.known, &tracked_dest),
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
        self.proofs.proof_valid(
            &mut self.known,
            &mut *self.callbacks,
            tracked_dest,
            tracked_hash,
            rtt,
            Some(*proof_packet_hash),
        );
    }
}
