//! Establishing links: requests, proofs, and identifying on a link.

use super::*;

impl LinkManager {
    /// Create an outbound link to a destination.
    ///
    /// `dest_sig_pub_bytes` is the destination's Ed25519 signing public key
    /// (needed to verify LRPROOF). In Python this comes from the Destination's Identity.
    ///
    /// Returns `(link_id, actions)`. The first action will be a SendPacket with
    /// the LINKREQUEST.
    pub fn create_link(
        &mut self,
        dest_hash: &[u8; 16],
        dest_sig_pub_bytes: &[u8; 32],
        hops: u8,
        mtu: u32,
        rng: &mut dyn Rng,
    ) -> (LinkId, Vec<LinkManagerAction>) {
        self.create_link_with_keys(dest_hash, dest_sig_pub_bytes, hops, mtu, None, rng)
    }

    /// Create an outbound link, using pre-generated link request keys when
    /// given. A stamped link request supplies keys ground ahead of time, off
    /// the driver thread; this method never performs stamp work itself.
    pub fn create_link_with_keys(
        &mut self,
        dest_hash: &[u8; 16],
        dest_sig_pub_bytes: &[u8; 32],
        hops: u8,
        mtu: u32,
        keys: Option<(X25519PrivateKey, Ed25519PrivateKey)>,
        rng: &mut dyn Rng,
    ) -> (LinkId, Vec<LinkManagerAction>) {
        let mode = LinkMode::Aes256Cbc;
        let signalled_mtu = self.link_mtu_discovery.then_some(mtu);
        let (mut engine, request_data) = match keys {
            Some((prv, sig_prv)) => LinkEngine::new_initiator_with_keys(
                dest_hash,
                hops,
                mode,
                signalled_mtu,
                time::now(),
                prv,
                sig_prv,
            ),
            None => {
                LinkEngine::new_initiator(dest_hash, hops, mode, signalled_mtu, time::now(), rng)
            }
        };

        // Build the LINKREQUEST packet to compute link_id
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_LINKREQUEST,
        };

        let packet = match RawPacket::pack(
            flags,
            0,
            dest_hash,
            None,
            constants::CONTEXT_NONE,
            &request_data,
        ) {
            Ok(p) => p,
            Err(_) => {
                // Should not happen with valid data
                return ([0u8; 16], Vec::new());
            }
        };

        engine.set_link_id_from_hashable(&packet.get_hashable_part(), request_data.len());
        engine.add_establishment_cost(packet.raw.len());
        let link_id = *engine.link_id();

        engine.record_outbound_traffic(packet.data().len());
        let managed = ManagedLink {
            resource_generation: std::sync::Arc::new(()),
            engine,
            channel: None,
            pre_rtt_packets: Vec::new(),
            pending_channel_packets: Default::default(),
            channel_send_ok: 0,
            channel_send_not_ready: 0,
            channel_send_too_big: 0,
            channel_send_other_error: 0,
            channel_messages_received: 0,
            packet_proofs_sent: 0,
            channel_proofs_received: 0,
            dest_hash: *dest_hash,
            remote_identity: None,
            dest_sig_pub_bytes: Some(*dest_sig_pub_bytes),
            incoming_resources: Vec::new(),
            concluded_incoming: Default::default(),
            outgoing_resources: Vec::new(),
            pending_requests: Default::default(),
            incoming_splits: Default::default(),
            outgoing_splits: Default::default(),
            outgoing_streams: Default::default(),
            resource_strategy: ResourceStrategy::default(),
            resource_receive_mode: ResourceReceiveMode::default(),
            max_request_size: None,
            route_interface: None,
            route_transport_id: None,
            direct_route: None,
            direct_peer: false,
            channel_parts: Default::default(),
        };
        self.links.insert(link_id, managed);

        let actions = vec![
            // Register the link_id as a local destination so we can receive LRPROOF
            LinkManagerAction::RegisterLinkDest { link_id },
            // Send the LINKREQUEST packet
            LinkManagerAction::SendPacket {
                raw: packet.raw.into(),
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            },
        ];

        (link_id, actions)
    }

    /// Handle an incoming LINKREQUEST packet.
    pub(super) fn handle_linkrequest(
        &mut self,
        dest_hash: &[u8; 16],
        packet: &RawPacket<&[u8]>,
        receiving_interface: rns_core::transport::types::InterfaceId,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        // Look up the link destination
        let ld = match self.link_destinations.get(dest_hash) {
            Some(ld) => ld,
            None => return Vec::new(),
        };

        let hashable = packet.get_hashable_part();
        let now = time::now();

        // `Link.validate_request`: the request's X25519 public key is its
        // stamp over `destination_hash || peer_sig_pub`. With
        // `LR_STAMPS_ENFORCED`, a stamp that is not valid for the
        // destination's `get_link_cost()` drops the request without a proof:
        // `LR_STAMPS_ENFORCED and not stamp_valid(...)`. Upstream 796ef2d4
        // wrote the test without the `not`, dropping the valid requests
        // instead; this always dropped the invalid ones, and upstream
        // restored the `not` in 50e939ab.
        let stamp_value =
            rns_core::link::handshake::link_request_stamp_value(dest_hash, packet.data());
        if let Some(value) = stamp_value {
            log::trace!(
                "LINKREQUEST for {:02x?} carries stamp value {}",
                &dest_hash[..4],
                value
            );
            if self.link_request_costs.enforced()
                && rns_core::link::handshake::link_request_stamp_valid(
                    dest_hash,
                    packet.data(),
                    self.link_request_costs.get(dest_hash),
                ) == Some(false)
            {
                log::debug!(
                    "Validating incoming link request failed: Insufficient link request stamp value {}",
                    value
                );
                return Vec::new();
            }
        }

        // Create responder engine
        let (mut engine, lrproof_data) = match LinkEngine::new_responder(
            &ld.sig_prv,
            &ld.sig_pub_bytes,
            packet.data(),
            &hashable,
            dest_hash,
            packet.hops,
            now,
            rng,
        ) {
            Ok(r) => r,
            Err(e) => {
                log::debug!("LINKREQUEST rejected: {}", e);
                return vec![LinkManagerAction::ProtocolViolation {
                    receiving_interface,
                }];
            }
        };

        engine.add_establishment_cost(packet.raw.len());
        let link_id = *engine.link_id();
        log::debug!(
            "LINKREQUEST accepted: link={:02x?} iface={} header_type={} transport_id_present={} hops={}",
            &link_id[..4],
            receiving_interface.0,
            packet.flags.header_type,
            packet.transport_id.is_some(),
            packet.hops
        );

        let managed = ManagedLink {
            resource_generation: std::sync::Arc::new(()),
            engine,
            channel: None,
            pre_rtt_packets: Vec::new(),
            pending_channel_packets: Default::default(),
            channel_send_ok: 0,
            channel_send_not_ready: 0,
            channel_send_too_big: 0,
            channel_send_other_error: 0,
            channel_messages_received: 0,
            packet_proofs_sent: 0,
            channel_proofs_received: 0,
            dest_hash: *dest_hash,
            remote_identity: None,
            dest_sig_pub_bytes: None,
            incoming_resources: Vec::new(),
            concluded_incoming: Default::default(),
            outgoing_resources: Vec::new(),
            pending_requests: Default::default(),
            incoming_splits: Default::default(),
            outgoing_splits: Default::default(),
            outgoing_streams: Default::default(),
            resource_strategy: ld.resource_strategy,
            resource_receive_mode: ld.resource_receive_mode.clone(),
            max_request_size: ld.max_request_size,
            route_interface: Some(receiving_interface),
            route_transport_id: if packet.flags.header_type == constants::HEADER_2 {
                packet.transport_id
            } else {
                None
            },
            direct_route: None,
            direct_peer: false,
            channel_parts: Default::default(),
        };
        self.links.insert(link_id, managed);

        // Build LRPROOF packet: type=PROOF, context=LRPROOF, dest=link_id
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_PROOF,
        };

        let mut actions = Vec::new();

        // Register link_id as local destination so we receive link data
        actions.push(LinkManagerAction::RegisterLinkDest { link_id });

        if let Ok((raw, _packet_hash)) = RawPacket::pack_raw_with_hash(
            flags,
            0,
            &link_id,
            None,
            constants::CONTEXT_LRPROOF,
            &lrproof_data,
        ) {
            if let Some(link) = self.links.get_mut(&link_id) {
                link.engine.add_establishment_cost(raw.len());
            }
            log::debug!(
                "LRPROOF queued: link={:02x?} route_iface={} route_tid_present={} hops=0",
                &link_id[..4],
                receiving_interface.0,
                packet.transport_id.is_some()
            );
            actions.push(LinkManagerAction::SendPacket {
                raw: raw.into(),
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            });
        }

        // Notify hook system about the incoming link request
        actions.push(LinkManagerAction::LinkRequestReceived {
            link_id,
            receiving_interface,
        });

        actions
    }

    pub(super) fn handle_link_proof(
        &mut self,
        link_id: &LinkId,
        packet: &RawPacket<&[u8]>,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        if packet.data().len() != 96 {
            return Vec::new();
        }

        let mut tracked_hash = [0u8; 32];
        tracked_hash.copy_from_slice(&packet.data()[..32]);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&packet.data()[32..]);

        let Some(key) = self
            .links
            .get(link_id)
            .and_then(|link| link.engine.peer_signing_key())
            .cloned()
        else {
            return Vec::new();
        };
        if let Some(pool) = self.proof_pool() {
            if pool.submit_verify(
                proof_pool::Owner::Link(*link_id),
                tracked_hash,
                signature,
                key.clone(),
            ) {
                return Vec::new();
            }
        }
        if !key.verify(&signature, &tracked_hash) {
            return Vec::new();
        }
        self.link_proof_verified(link_id, &tracked_hash, rng)
    }

    /// Act on a link proof whose signature checked out.
    pub(super) fn link_proof_verified(
        &mut self,
        link_id: &LinkId,
        tracked_hash: &[u8; 32],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let Some(link) = self.links.get_mut(link_id) else {
            return Vec::new();
        };
        // A proof the peer signed is evidence the link is alive, whether or
        // not it answers a tracked channel packet: plain confirmed sends
        // complete on transmission and leave nothing to match here.
        link.engine.record_proof(time::now());
        let mut actions = vec![LinkManagerAction::PacketProved {
            link_id: *link_id,
            packet_hash: *tracked_hash,
        }];
        let Some(sequence) = link.pending_channel_packets.remove(tracked_hash) else {
            return actions;
        };
        link.channel_proofs_received += 1;
        let Some(channel) = link.channel.as_mut() else {
            return actions;
        };

        let chan_actions = channel.packet_delivered(sequence);
        actions.extend(self.process_channel_actions(link_id, chan_actions, rng));
        actions
    }

    /// The proof packet of a packet received on `link_id`.
    pub(super) fn link_proof_packet(
        link_id: &LinkId,
        packet_hash: &[u8; 32],
        signature: &[u8; 64],
    ) -> Vec<LinkManagerAction> {
        let mut proof_data = Vec::with_capacity(96);
        proof_data.extend_from_slice(packet_hash);
        proof_data.extend_from_slice(signature);

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        if let Ok((raw, _packet_hash)) = RawPacket::pack_raw_with_hash(
            flags,
            0,
            link_id,
            None,
            constants::CONTEXT_NONE,
            &proof_data,
        ) {
            vec![LinkManagerAction::SendPacket {
                raw: raw.into(),
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            }]
        } else {
            Vec::new()
        }
    }

    /// Handle an incoming LRPROOF packet (initiator side).
    pub(super) fn handle_lrproof(
        &mut self,
        link_id_bytes: &[u8; 16],
        packet: &RawPacket<&[u8]>,
        receiving_interface: rns_core::transport::types::InterfaceId,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id_bytes) {
            Some(l) => l,
            None => return Vec::new(),
        };

        link.route_interface = Some(receiving_interface);
        if packet.flags.header_type == constants::HEADER_2 {
            if let Some(transport_id) = packet.transport_id {
                link.route_transport_id = Some(transport_id);
            }
        }
        log::debug!(
            "LRPROOF received: link={:02x?} iface={} header_type={} transport_id_present={}",
            &link_id_bytes[..4],
            receiving_interface.0,
            packet.flags.header_type,
            packet.transport_id.is_some()
        );

        if link.engine.state() != LinkState::Pending || !link.engine.is_initiator() {
            return Vec::new();
        }

        // The destination's signing pub key was stored when create_link was called
        let dest_sig_pub_bytes = match link.dest_sig_pub_bytes {
            Some(b) => b,
            None => {
                log::debug!("LRPROOF: no destination signing key available");
                return Vec::new();
            }
        };

        let now = time::now();
        link.engine.add_establishment_cost(packet.raw.len());
        let (lrrtt_encrypted, link_actions) = match link.engine.handle_lrproof_with_hops(
            packet.data(),
            &dest_sig_pub_bytes,
            Some(packet.hops),
            now,
            rng,
        ) {
            Ok(r) => r,
            Err(e) => {
                log::debug!("LRPROOF validation failed: {}", e);
                return Vec::new();
            }
        };

        let link_id = *link.engine.link_id();
        let mut actions = Vec::new();

        // Process link actions (StateChanged, LinkEstablished)
        actions.extend(self.process_link_actions(&link_id, &link_actions));

        // Send LRRTT: type=DATA, context=LRRTT, dest=link_id
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        };

        if let Ok((raw, _packet_hash)) = RawPacket::pack_raw_with_hash(
            flags,
            0,
            &link_id,
            None,
            constants::CONTEXT_LRRTT,
            &lrrtt_encrypted,
        ) {
            actions.push(LinkManagerAction::SendPacket {
                raw: raw.into(),
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            });
        }

        // Initialize channel now that link is active
        if let Some(link) = self.links.get_mut(&link_id) {
            if link.engine.state() == LinkState::Active {
                let rtt = link.engine.rtt().unwrap_or(1.0);
                link.channel = Some(Channel::new(rtt));
            }
        }

        actions
    }

    /// Send an identify message on a link (initiator reveals identity to responder).
    pub fn identify(
        &self,
        link_id: &LinkId,
        identity: &rns_crypto::identity::Identity,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let encrypted = match link.engine.build_identify(identity, rng) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        };

        let mut actions = Vec::new();
        if let Ok((raw, _packet_hash)) = RawPacket::pack_raw_with_hash(
            flags,
            0,
            link_id,
            None,
            constants::CONTEXT_LINKIDENTIFY,
            &encrypted,
        ) {
            actions.push(LinkManagerAction::SendPacket {
                raw: raw.into(),
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            });
        }
        actions
    }
}
