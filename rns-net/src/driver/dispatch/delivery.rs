//! Decrypting and delivering packets to local destinations.

use super::*;

impl Driver {
    /// Encrypt a deferred send on the proof pool, or here without one.
    pub(crate) fn handle_send_deferred(
        &mut self,
        encryption: Box<crate::common::event::DeferredSend>,
    ) {
        if self.is_draining() {
            self.reject_new_work("send deferred packet");
            self.callbacks
                .on_packet_sent(crate::SendTicket(encryption.ticket), None);
            return;
        }
        if encryption.encrypted {
            let encryption = *encryption;
            self.send_deferred(
                encryption.ticket,
                encryption.destination,
                Some(encryption.data),
            );
            return;
        }
        if let Err(encryption) = self.link_manager.submit_packet_encrypt(encryption) {
            let payload = encryption.run();
            self.send_deferred(encryption.ticket, encryption.destination, payload);
        }
    }

    /// Send a deferred packet once its payload is encrypted, reporting its
    /// hash first: a proof of it cannot arrive before the report.
    pub(super) fn send_deferred(
        &mut self,
        ticket: u64,
        destination: [u8; 16],
        payload: Option<Vec<u8>>,
    ) {
        let ticket = crate::SendTicket(ticket);
        // Encrypted on the pool while a drain began: not sent.
        if self.is_draining() {
            self.reject_new_work("send deferred packet");
            self.callbacks.on_packet_sent(ticket, None);
            return;
        }
        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: rns_core::constants::FLAG_UNSET,
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: rns_core::constants::DESTINATION_SINGLE,
            packet_type: rns_core::constants::PACKET_TYPE_DATA,
        };
        let packet = payload.and_then(|payload| {
            RawPacket::pack(
                flags,
                0,
                &destination,
                None,
                rns_core::constants::CONTEXT_NONE,
                &payload,
            )
            .ok()
        });
        let Some(packet) = packet else {
            self.callbacks.on_packet_sent(ticket, None);
            return;
        };
        self.callbacks.on_packet_sent(
            ticket,
            Some(rns_core::types::PacketHash(packet.packet_hash)),
        );
        self.handle_send_outbound_event(packet.raw, rns_core::constants::DESTINATION_SINGLE, None);
    }

    /// Decrypt a packet for a destination that delivers decrypted: on the
    /// proof pool when there is one, here without.
    pub(super) fn decrypt_for_delivery(
        &mut self,
        destination: [u8; 16],
        packet_hash: [u8; 32],
        interface: InterfaceId,
        ciphertext: Vec<u8>,
        identity: Arc<rns_crypto::identity::Identity>,
    ) {
        use crate::common::link_manager::{Decryption, DecryptionKey};
        // Ratchets attached by the application decrypt as its owner does.
        let ratchets =
            crate::sync::lock_or_recover(self.event_tx.local_ratchets(), "local ratchets")
                .get(&destination)
                .cloned();
        let key = match ratchets {
            Some(owner) => DecryptionKey::Ratchets(owner),
            None => DecryptionKey::Identity(identity),
        };
        let decryption = Box::new(Decryption {
            destination,
            packet_hash,
            interface,
            ciphertext,
            key,
        });
        // On one CPU a pool thread would only share it: decrypt here.
        let submitted = if one_cpu() {
            Err(decryption)
        } else {
            self.link_manager.submit_packet_decrypt(decryption)
        };
        if let Err(decryption) = submitted {
            let plaintext = decryption.run();
            self.deliver_decrypted(destination, packet_hash, interface, plaintext);
        }
    }

    /// Prove and deliver a decrypted packet; drop one that did not decrypt.
    pub(super) fn deliver_decrypted(
        &mut self,
        destination: [u8; 16],
        packet_hash: [u8; 32],
        interface: InterfaceId,
        plaintext: Option<Vec<u8>>,
    ) {
        let Some(plaintext) = plaintext else {
            log::debug!(
                "Dropped a packet for {:02x?} that did not decrypt",
                &destination[..4]
            );
            return;
        };
        self.maybe_generate_proof(destination, &packet_hash, Some(interface));
        self.callbacks.on_packet_received(
            rns_core::types::DestHash(destination),
            plaintext,
            rns_core::types::PacketHash(packet_hash),
        );
    }

    /// Deliver a packet the engine accepted for a local destination.
    ///
    /// `packet_hash` may be zeroed for a link resource part; the link
    /// manager's resource path does not read it, and every other consumer
    /// takes it from [`delivered_packet_hash`].
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_deliver_local_action(
        &mut self,
        destination_hash: [u8; 16],
        raw: rns_core::transport::types::PacketBytes,
        packet_hash: [u8; 32],
        receiving_interface: InterfaceId,
        ingress_limited: bool,
        _hook_injected: &mut Vec<TransportAction>,
        run_hooks: bool,
    ) {
        #[cfg(not(feature = "hooks"))]
        let _ = run_hooks;
        // The engine recorded the received packet's hash; a stale-link arrival
        // must forget that entry even if a hook replaced the bytes.
        let hashlist_hash = packet_hash;
        #[cfg(feature = "hooks")]
        let (destination_hash, raw, packet_hash) =
            if run_hooks && self.hooks_attached(HookPoint::DeliverLocal) {
                let packet_hash = delivered_packet_hash(&raw, packet_hash);
                let pkt_ctx = rns_hooks::PacketContext {
                    flags: 0,
                    hops: 0,
                    destination_hash,
                    context: 0,
                    packet_hash,
                    interface_id: receiving_interface.0,
                    data_offset: 0,
                    data_len: raw.len() as u32,
                };
                let ctx = HookContext::Packet {
                    ctx: &pkt_ctx,
                    raw: &raw,
                };
                let now = time::now();
                let engine_ref = EngineRef {
                    engine: &self.engine,
                    interfaces: &self.interfaces,
                    link_manager: &self.link_manager,
                    now,
                };
                let provider_events_enabled = self.provider_events_enabled();
                let mut outcome = PacketHookOutcome::Keep;
                if let Some(ref e) = run_hook_inner(
                    &mut self.hook_slots[HookPoint::DeliverLocal as usize].programs,
                    &self.hook_manager,
                    &engine_ref,
                    &ctx,
                    now,
                    provider_events_enabled,
                ) {
                    self.collect_hook_side_effects("DeliverLocal", e, _hook_injected);
                    let max_len = self.hook_packet_limit(receiving_interface);
                    outcome = self.packet_hook_outcome(HookPoint::DeliverLocal, e, max_len);
                }
                match outcome {
                    PacketHookOutcome::Keep => (destination_hash, raw, packet_hash),
                    PacketHookOutcome::Drop => return,
                    // Deliver the replacement under its own destination and hash.
                    PacketHookOutcome::Replace(packet) => (
                        packet.destination_hash,
                        packet.raw.into(),
                        packet.packet_hash,
                    ),
                }
            } else {
                (destination_hash, raw, packet_hash)
            };

        if destination_hash == self.tunnel_synth_dest {
            self.handle_tunnel_synth_delivery(&raw, receiving_interface);
        } else if destination_hash == self.path_request_dest {
            if let Ok(packet) = RawPacket::unpack(&raw) {
                let now = time::now();
                let Some(request) =
                    self.engine
                        .accept_path_request(packet.data(), receiving_interface, now)
                else {
                    return;
                };
                if let Some(entry) = self.interfaces.get_mut(&receiving_interface) {
                    if request.stamped() {
                        entry.stats.stamped_path_requests += 1;
                    }
                    entry
                        .stats
                        .record_incoming_path_request_bytes(now, raw.len());
                    super::sync_interface_frequencies(
                        &mut self.engine,
                        receiving_interface,
                        entry.stats.frequencies(now),
                    );
                }
                let actions = self
                    .engine
                    .handle_accepted_path_request_with_ingress_limit(request, ingress_limited);
                self.dispatch_all(actions);
            }
        } else if self.link_manager.is_link_destination(&destination_hash) {
            // Only the flags are needed here; a full unpack would copy and
            // rehash the whole packet.
            if let Ok(packet) = RawPacket::view_unhashed(&raw) {
                // A link running over a direct path also takes packets on
                // its original route, where the peer may have fallen back.
                let arrived_on_stale_link_route = packet.flags.packet_type
                    == rns_core::constants::PACKET_TYPE_DATA
                    && packet.flags.destination_type == rns_core::constants::DESTINATION_LINK
                    && !self
                        .link_manager
                        .link_route_accepts(&destination_hash, receiving_interface);
                if arrived_on_stale_link_route {
                    // The active link has failed over, but an in-flight packet
                    // arrived on its former interface. Do not let this arrival
                    // suppress the copy still travelling on the current route.
                    self.engine.forget_packet_hash(&hashlist_hash);
                    return;
                }
            }
            let mut link_actions = self.link_actions.take();
            self.link_manager.handle_local_delivery_into(
                destination_hash,
                &raw,
                packet_hash,
                receiving_interface,
                &mut self.rng,
                &mut link_actions,
            );
            if link_actions.is_empty() {
                self.link_actions.give(link_actions);
                let packet_hash = delivered_packet_hash(&raw, packet_hash);
                self.deliver_to_destination(
                    destination_hash,
                    &raw,
                    packet_hash,
                    receiving_interface,
                );
            } else {
                self.dispatch_link_actions(link_actions);
            }
        } else {
            let packet_hash = delivered_packet_hash(&raw, packet_hash);
            self.deliver_to_destination(destination_hash, &raw, packet_hash, receiving_interface);
        }
    }

    /// Hand a packet for a local destination to its receipts (a proof), or
    /// prove it as configured and deliver it: decrypted for destinations
    /// that asked for it, raw otherwise.
    pub(super) fn deliver_to_destination(
        &mut self,
        destination_hash: [u8; 16],
        raw: &[u8],
        packet_hash: [u8; 32],
        receiving_interface: InterfaceId,
    ) {
        // Every transported proof is also offered to local receipts. The
        // header carries all the check needs; the packet hash is known.
        if let Ok(packet) = RawPacket::view_unhashed(raw) {
            if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_PROOF {
                self.handle_inbound_proof(destination_hash, packet.data(), &packet_hash);
                return;
            }
            if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_DATA
                && packet.flags.destination_type == rns_core::constants::DESTINATION_SINGLE
            {
                if let Some(identity) = self.decrypted_destinations.get(&destination_hash) {
                    let identity = Arc::clone(identity);
                    let ciphertext = packet.data().to_vec();
                    self.decrypt_for_delivery(
                        destination_hash,
                        packet_hash,
                        receiving_interface,
                        ciphertext,
                        identity,
                    );
                    return;
                }
            }
        }
        self.maybe_generate_proof(destination_hash, &packet_hash, Some(receiving_interface));
        self.callbacks.on_local_delivery(
            rns_core::types::DestHash(destination_hash),
            raw.to_vec(),
            rns_core::types::PacketHash(packet_hash),
        );
    }
}
