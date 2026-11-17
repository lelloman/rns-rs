use super::*;

pub(super) fn extra_link_proof_timeout(interface: Option<&InterfaceInfo>) -> f64 {
    interface
        .and_then(|interface| interface.bitrate)
        .filter(|bitrate| *bitrate > 0)
        .map_or(0.0, |bitrate| {
            (constants::MTU as f64 * 8.0) / bitrate as f64
        })
}

/// How the destination type filter treats an inbound announce.
enum DestinationFilterVerdict {
    Admit,
    /// A blocked destination type.
    Blocked,
    /// With `required_destinations_only`, a type nobody allowed or wants.
    NotAllowed,
}

/// The ingress limiting outcome for an inbound announce.
enum HoldDecision {
    /// Not limited; processing continues.
    Pass,
    /// Held for later release.
    Held,
    /// Dropped or replacing a held announce: a filtered announce.
    Filtered,
}

impl TransportEngine {
    fn record_invalid_announce(
        &self,
        announce: &AnnounceData,
        interface: InterfaceId,
        now: f64,
        actions: &mut Vec<TransportAction>,
    ) {
        let identity_hash = crate::hash::truncated_hash(&announce.public_key);
        if !self.is_blackholed(&identity_hash, now) {
            actions.push(TransportAction::ProtocolViolation { interface });
        }
    }

    /// Return whether an inbound frame passes parsing, hop, and packet filtering.
    /// This does not mutate deduplication or routing state.
    pub fn accepts_inbound_frame(&self, frame: InboundFrame<'_>) -> bool {
        self.prepare_inbound_packet(frame).is_some()
    }

    /// Process an inbound raw packet from a network interface.
    ///
    /// Returns a list of actions for the caller to execute.
    pub fn handle_inbound(
        &mut self,
        frame: InboundFrame<'_>,
        rng: &mut dyn Rng,
    ) -> Vec<TransportAction> {
        self.handle_inbound_with_announce_queue(frame, rng, None)
    }

    pub fn handle_inbound_with_announce_queue(
        &mut self,
        frame: InboundFrame<'_>,
        rng: &mut dyn Rng,
        announce_queue: Option<&mut AnnounceVerifyQueue>,
    ) -> Vec<TransportAction> {
        let Ok(decoded) = self.decode_inbound(PacketBytes::from(frame.raw)) else {
            return Vec::new();
        };
        self.handle_decoded_inbound_with_announce_queue(
            DecodedInboundFrame {
                decoded,
                iface: frame.iface,
                now: frame.now,
                rx: frame.rx,
            },
            rng,
            announce_queue,
        )
    }

    /// Decode an inbound frame for [`handle_decoded_inbound_with_announce_queue`].
    ///
    /// Link traffic that this node only forwards, in a context the packet
    /// filter admits without consulting deduplication, is not hashed: no
    /// step that handles it reads the hash. Its hash cannot reject any later
    /// packet either, since a packet with the same hash has the same context.
    /// Nor is a resource part, part request or resource proof for a local
    /// link (see [`RawPacket::is_unhashed_link_resource`]); its delivery
    /// carries a zeroed hash. [`DecodedPacket::packet_hash`] reports whether hashing was
    /// deferred.
    ///
    /// [`handle_decoded_inbound_with_announce_queue`]: Self::handle_decoded_inbound_with_announce_queue
    /// It takes ownership of the wire bytes, which the decoded packet keeps.
    pub fn decode_inbound(
        &self,
        raw: PacketBytes,
    ) -> Result<DecodedPacket, crate::packet::PacketError> {
        // Only link data and proofs qualify; decode everything else directly.
        let flags = raw
            .first()
            .map(|flags| crate::packet::PacketFlags::unpack(*flags));
        if !flags.is_some_and(|flags| {
            matches!(
                flags.packet_type,
                constants::PACKET_TYPE_DATA | constants::PACKET_TYPE_PROOF
            ) && flags.destination_type == constants::DESTINATION_LINK
        }) {
            return DecodedPacket::unpack_shared(raw);
        }
        let mut packet = RawPacket::unpack_shared_unhashed(raw)?;
        let hash_deferred = self.link_packet_hash_unread(&packet);
        if !hash_deferred {
            packet.hash_in_place();
        }
        Ok(DecodedPacket {
            packet,
            hash_deferred,
        })
    }

    /// Whether every inbound step that handles `packet` leaves its hash unread.
    fn link_packet_hash_unread<B: AsRef<[u8]>>(&self, packet: &RawPacket<B>) -> bool {
        self.forwards_link_packet_unhashed(packet) || self.delivers_link_resource_unhashed(packet)
    }

    /// A resource part, part request or resource proof for a local link is
    /// only delivered, and its delivery hands the payload to the resource
    /// code. Path-table routing would key a reverse entry on the hash, so a
    /// destination with a path is excluded.
    fn delivers_link_resource_unhashed<B: AsRef<[u8]>>(&self, packet: &RawPacket<B>) -> bool {
        packet.is_unhashed_link_resource()
            && self
                .local_destinations
                .contains_key(&packet.destination_hash)
            && !self.path_table.contains_key(&packet.destination_hash)
    }

    /// Whether `packet` is only relayed and leaves its hash unread: it is
    /// link data for a validated link this node relays, in a context
    /// that [`packet_filter_at_hops`](Self::packet_filter_at_hops) admits
    /// before deduplication, and it is neither delivered locally nor routed
    /// through the path table.
    fn forwards_link_packet_unhashed<B: AsRef<[u8]>>(&self, packet: &RawPacket<B>) -> bool {
        packet.flags.packet_type == constants::PACKET_TYPE_DATA
            && packet.flags.destination_type == constants::DESTINATION_LINK
            && matches!(
                packet.context,
                constants::CONTEXT_KEEPALIVE
                    | constants::CONTEXT_RESOURCE_REQ
                    | constants::CONTEXT_RESOURCE
                    | constants::CONTEXT_CACHE_REQUEST
                    | constants::CONTEXT_CHANNEL
            )
            && (self.config.transport_enabled || self.config.identity_hash.is_some())
            && self
                .link_table
                .get(&packet.destination_hash)
                .is_some_and(|entry| entry.validated)
            && !self
                .local_destinations
                .contains_key(&packet.destination_hash)
            && !self.path_table.contains_key(&packet.destination_hash)
    }

    /// Recheck current routing/filter state and consume a previously decoded frame.
    pub fn handle_decoded_inbound_with_announce_queue(
        &mut self,
        frame: DecodedInboundFrame,
        rng: &mut dyn Rng,
        announce_queue: Option<&mut AnnounceVerifyQueue>,
    ) -> Vec<TransportAction> {
        let mut actions = Vec::new();
        self.handle_decoded_inbound_into(frame, rng, announce_queue, &mut actions);
        actions
    }

    /// [`Self::handle_decoded_inbound_with_announce_queue`], appending the
    /// actions to `actions` so a caller can reuse one buffer across packets.
    pub fn handle_decoded_inbound_into(
        &mut self,
        frame: DecodedInboundFrame,
        rng: &mut dyn Rng,
        announce_queue: Option<&mut AnnounceVerifyQueue>,
        actions: &mut Vec<TransportAction>,
    ) {
        self.inbound_filtered = false;
        self.inbound_filtered_announce = false;
        let Some(mut ctx) = self.prepare_decoded_packet(frame) else {
            self.inbound_filtered = true;
            return;
        };
        match self.destination_filter_verdict(&ctx) {
            DestinationFilterVerdict::Admit => {}
            DestinationFilterVerdict::Blocked => {
                self.inbound_filtered = true;
                return;
            }
            // Upstream 819076c3 counts this one as a filtered announce.
            DestinationFilterVerdict::NotAllowed => {
                self.filter_announce();
                return;
            }
        }
        // Routing state may have changed since decoding. Any packet whose hash
        // a step could now read is hashed first.
        if ctx.hash_deferred && !self.link_packet_hash_unread(&ctx.packet) {
            ctx.packet.hash_in_place();
            ctx.hash_deferred = false;
        }

        // A deferred packet's context bypasses deduplication.
        if !ctx.hash_deferred {
            self.remember_inbound_packet_hash(&ctx.packet);
        }
        self.bridge_plain_broadcast(&ctx, actions);
        self.handle_transport_forwarding(&ctx, actions);
        self.handle_link_table_routing(&ctx, actions);
        self.handle_inbound_announce(&ctx, rng, announce_queue, actions);

        if ctx.packet.flags.packet_type == constants::PACKET_TYPE_PROOF {
            self.process_inbound_proof(&ctx, actions);
        }

        self.handle_inbound_local_delivery(&ctx, actions);
    }

    /// The announce ingress filter of `Transport.inbound` (825c2e19), which
    /// runs before anything else sees the packet. Python's `hops == 1` after
    /// its increment means the announce was sent with zero hops; local
    /// client hops are not incremented here.
    fn destination_filter_verdict(&self, ctx: &InboundPacketCtx) -> DestinationFilterVerdict {
        if ctx.packet.flags.packet_type != constants::PACKET_TYPE_ANNOUNCE {
            return DestinationFilterVerdict::Admit;
        }
        let start = constants::KEYSIZE / 8;
        let Some(name_hash) = ctx
            .packet
            .data()
            .get(start..start + constants::NAME_HASH_LENGTH / 8)
        else {
            // Malformed. The driver rejects a payload this short as a
            // protocol violation (upstream 096e6726); otherwise announce
            // unpacking reports it.
            return DestinationFilterVerdict::Admit;
        };
        let mut destination_type = [0u8; constants::NAME_HASH_LENGTH / 8];
        destination_type.copy_from_slice(name_hash);
        let own_local_announce = ctx.from_local_client && ctx.packet.hops == 0;
        if self.destination_filter.blocks(&destination_type) {
            DestinationFilterVerdict::Blocked
        } else if self
            .destination_filter
            .allows(&destination_type, own_local_announce)
        {
            DestinationFilterVerdict::Admit
        } else {
            DestinationFilterVerdict::NotAllowed
        }
    }

    /// Mark the inbound packet as a filtered announce: its bytes count as
    /// filtered and the interface's `afrxc` grows (upstream 819076c3).
    fn filter_announce(&mut self) {
        self.inbound_filtered = true;
        self.inbound_filtered_announce = true;
    }

    pub(super) fn prepare_inbound_packet(
        &self,
        frame: InboundFrame<'_>,
    ) -> Option<InboundPacketCtx> {
        let decoded = DecodedPacket::unpack(frame.raw).ok()?;
        self.prepare_decoded_packet(DecodedInboundFrame {
            decoded,
            iface: frame.iface,
            now: frame.now,
            rx: frame.rx,
        })
    }

    pub(super) fn filtered_inbound_hops<B: AsRef<[u8]>>(
        &self,
        packet: &RawPacket<B>,
        iface: InterfaceId,
    ) -> Option<(u8, bool)> {
        let from_local_client = self
            .interfaces
            .get(&iface)
            .is_some_and(|i| i.is_local_client);
        let mut hops = packet.hops.checked_add(1)?;
        if from_local_client {
            hops = hops.saturating_sub(1);
        }
        self.packet_filter_at_hops(packet, hops)
            .then_some((hops, from_local_client))
    }

    pub fn accepts_decoded_packet(&self, decoded: &DecodedPacket, iface: InterfaceId) -> bool {
        self.filtered_inbound_hops(&decoded.packet, iface).is_some()
    }

    pub(super) fn prepare_decoded_packet(
        &self,
        frame: DecodedInboundFrame,
    ) -> Option<InboundPacketCtx> {
        let hash_deferred = frame.decoded.hash_deferred;
        let mut packet = frame.decoded.packet;
        let (hops, from_local_client) = self.filtered_inbound_hops(&packet, frame.iface)?;
        packet.hops = hops;
        packet.rssi = frame.rx.rssi;
        packet.snr = frame.rx.snr;
        let retain_original_raw = packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE;
        let original_raw = retain_original_raw.then(|| packet.raw.clone());
        Some(InboundPacketCtx {
            packet,
            hash_deferred,
            original_raw,
            iface: frame.iface,
            now: frame.now,
            from_local_client,
        })
    }

    fn remember_inbound_packet_hash<B: AsRef<[u8]>>(&mut self, packet: &RawPacket<B>) {
        let remember_hash = !(self.link_table.contains_key(&packet.destination_hash)
            || (packet.flags.packet_type == constants::PACKET_TYPE_PROOF
                && packet.context == constants::CONTEXT_LRPROOF));
        if remember_hash {
            self.packet_hashlist.add(packet.packet_hash);
        }
    }

    fn bridge_plain_broadcast(&self, ctx: &InboundPacketCtx, actions: &mut Vec<TransportAction>) {
        // Transport.py:2227: control destinations (path requests and tunnel
        // synthesis) are handled by the engine, which re-emits path requests
        // itself, and are never bridged raw. Bridging them as well would send
        // a local client's path request twice, once raw and once rebuilt
        // (and stamped, when STAMP_PRS is on), with the rebuilt copy then
        // dropped downstream as a duplicate tag.
        if ctx.packet.flags.destination_type != constants::DESTINATION_PLAIN
            || ctx.packet.flags.transport_type != constants::TRANSPORT_BROADCAST
            || !self.has_local_clients()
            || self
                .control_destinations
                .contains(&ctx.packet.destination_hash)
        {
            return;
        }

        if ctx.from_local_client {
            actions.push(TransportAction::ForwardPlainBroadcast {
                raw: PacketBytes::from(ctx.packet.raw.clone()),
                to_local: false,
                exclude: Some(ctx.iface),
            });
        } else {
            actions.push(TransportAction::ForwardPlainBroadcast {
                raw: PacketBytes::from(ctx.packet.raw.clone()),
                to_local: true,
                exclude: None,
            });
        }
    }

    fn handle_transport_forwarding(
        &mut self,
        ctx: &InboundPacketCtx,
        actions: &mut Vec<TransportAction>,
    ) {
        if !(self.config.transport_enabled || self.config.identity_hash.is_some()) {
            return;
        }
        // Transport.py: clients behind a shared instance are announced with a
        // "spoofed" hop count of 0, so they look directly reachable and
        // senders strip the transport header. Treat a packet for such a
        // client as addressed to us so normal forwarding handles it (#183).
        let for_local_client = ctx.packet.flags.packet_type != constants::PACKET_TYPE_ANNOUNCE
            && self
                .path_table
                .get(&ctx.packet.destination_hash)
                .and_then(|ps| ps.primary())
                .is_some_and(|entry| {
                    entry.hops == 0 && self.interface_is_local_client(entry.receiving_interface)
                });
        let transport_id = match ctx.packet.transport_id {
            None if for_local_client => self.config.identity_hash,
            transport_id => transport_id,
        };
        if transport_id.is_none() || ctx.packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE
        {
            if ctx.packet.flags.packet_type == constants::PACKET_TYPE_DATA {
                log::debug!(
                    "TransportForward: DATA dest={:02x}{:02x}{:02x}{:02x}.. not transport-addressed header={} iface={}",
                    ctx.packet.destination_hash[0],
                    ctx.packet.destination_hash[1],
                    ctx.packet.destination_hash[2],
                    ctx.packet.destination_hash[3],
                    ctx.packet.flags.header_type,
                    ctx.iface.0
                );
            }
            return;
        }

        let Some(identity_hash) = self.config.identity_hash else {
            return;
        };
        if transport_id != Some(identity_hash) {
            if ctx.packet.flags.packet_type == constants::PACKET_TYPE_DATA {
                log::debug!(
                    "TransportForward: DATA dest={:02x}{:02x}{:02x}{:02x}.. transport mismatch got={:02x?} own={:02x?} iface={}",
                    ctx.packet.destination_hash[0],
                    ctx.packet.destination_hash[1],
                    ctx.packet.destination_hash[2],
                    ctx.packet.destination_hash[3],
                    ctx.packet.transport_id.as_ref().map(|id| &id[..4]),
                    &identity_hash[..4],
                    ctx.iface.0
                );
            }
            return;
        }

        let Some(path_entry) = self
            .path_table
            .get(&ctx.packet.destination_hash)
            .and_then(|ps| ps.primary())
        else {
            if ctx.packet.flags.packet_type == constants::PACKET_TYPE_DATA {
                log::debug!(
                    "TransportForward: DATA dest={:02x}{:02x}{:02x}{:02x}.. addressed to us but no path iface={}",
                    ctx.packet.destination_hash[0],
                    ctx.packet.destination_hash[1],
                    ctx.packet.destination_hash[2],
                    ctx.packet.destination_hash[3],
                    ctx.iface.0
                );
            }
            return;
        };

        let next_hop = path_entry.next_hop;
        let remaining_hops = path_entry.hops;
        let outbound_interface = path_entry.receiving_interface;
        let outbound_is_local_client = self
            .interfaces
            .get(&outbound_interface)
            .map(|info| info.is_local_client)
            .unwrap_or(false);
        let forwarded_remaining_hops = if outbound_is_local_client {
            0
        } else {
            remaining_hops
        };
        if ctx.packet.flags.packet_type == constants::PACKET_TYPE_DATA {
            log::debug!(
                "TransportForward: DATA dest={:02x}{:02x}{:02x}{:02x}.. remaining_hops={} out_iface={} next_hop={:02x?}",
                ctx.packet.destination_hash[0],
                ctx.packet.destination_hash[1],
                ctx.packet.destination_hash[2],
                ctx.packet.destination_hash[3],
                remaining_hops,
                outbound_interface.0,
                &next_hop[..4]
            );
        }
        let mut new_raw = forward_transport_packet(
            &ctx.packet,
            next_hop,
            forwarded_remaining_hops,
            outbound_interface,
        );
        if self.config.local_hops_delta != 0
            && ctx.from_local_client
            && !outbound_is_local_client
            && ctx.packet.hops == 0
            && ctx.packet.flags.destination_type != constants::DESTINATION_PLAIN
            && ctx.packet.flags.destination_type != constants::DESTINATION_GROUP
            && new_raw.len() > 1
        {
            new_raw[1] = self.config.local_hops_delta;
        }

        if ctx.packet.flags.packet_type == constants::PACKET_TYPE_LINKREQUEST {
            clamp_forwarded_link_request_mtu(
                &mut new_raw,
                ctx.packet.data().len() == constants::LINK_ECPUBSIZE + constants::LINK_MTU_SIZE,
                self.interfaces.get(&ctx.iface).map(|info| info.mtu),
                self.interfaces
                    .get(&outbound_interface)
                    .filter(|info| info.mtu_upgradable)
                    .map(|info| info.mtu),
            );
            let extra_proof_timeout =
                extra_link_proof_timeout(self.interfaces.get(&outbound_interface));
            let proof_timeout = ctx.now
                + constants::LINK_ESTABLISHMENT_TIMEOUT_PER_HOP * (remaining_hops.max(1) as f64)
                + extra_proof_timeout;
            let (link_id, link_entry) = create_link_entry(
                &ctx.packet,
                next_hop,
                outbound_interface,
                remaining_hops,
                ctx.iface,
                ctx.now,
                proof_timeout,
            );
            self.link_table.insert(link_id, link_entry);
            actions.push(TransportAction::LinkRequestReceived {
                link_id,
                destination_hash: ctx.packet.destination_hash,
                receiving_interface: ctx.iface,
            });
        } else {
            let (trunc_hash, reverse_entry) =
                create_reverse_entry(&ctx.packet, outbound_interface, ctx.iface, ctx.now);
            self.reverse_table.insert(trunc_hash, reverse_entry);
        }

        actions.push(TransportAction::SendOnInterface {
            interface: outbound_interface,
            raw: new_raw.into(),
        });

        // Transport.py (1.6.0) marks the path used, so the unused path pool
        // culling keeps paths that carry traffic through this node.
        if let Some(entry) = self
            .path_table
            .get_mut(&ctx.packet.destination_hash)
            .and_then(|ps| ps.primary_mut())
        {
            entry.used = ctx.now;
        }
    }

    fn handle_link_table_routing(
        &mut self,
        ctx: &InboundPacketCtx,
        actions: &mut Vec<TransportAction>,
    ) {
        if !self.config.transport_enabled && self.config.identity_hash.is_none() {
            return;
        }
        if ctx.packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE
            || ctx.packet.flags.packet_type == constants::PACKET_TYPE_LINKREQUEST
            || ctx.packet.context == constants::CONTEXT_LRPROOF
        {
            return;
        }

        // This single keyed lookup is the native link fast path. The engine is
        // already exclusively borrowed, and the typed entry contains every
        // routing and hop-rewrite field, so a second denormalized cache would
        // add invalidation risk without avoiding locks or linear searches.
        // Keep this authoritative-table path even when profiling suggests a
        // cache: upstream's corresponding denormalized experiment was removed.
        let Some(link_entry) = self.link_table.get(&ctx.packet.destination_hash).cloned() else {
            return;
        };
        if !link_entry.validated {
            return;
        }
        let instance_local_link = self.interface_is_local_client(link_entry.next_hop_interface)
            && self.interface_is_local_client(link_entry.received_interface);
        let Some((outbound_iface, new_raw)) = super::inbound::route_via_link_table_shared(
            &ctx.packet,
            &link_entry,
            ctx.iface,
            LocalHopRewrite {
                local_hops_delta: self.config.local_hops_delta,
                from_local_client: ctx.from_local_client,
                skip_local_hops_delta: instance_local_link,
            },
        ) else {
            // A link entry with no route from this receiving interface is an
            // expected fast-path miss, not an operator-facing warning.
            return;
        };

        // A deferred packet's context bypasses deduplication, so its hash
        // could never mark a later packet as a duplicate.
        if !ctx.hash_deferred {
            self.packet_hashlist.add(ctx.packet.packet_hash);
        }
        actions.push(TransportAction::SendOnInterface {
            interface: outbound_iface,
            raw: new_raw,
        });

        if let Some(entry) = self.link_table.get_mut(&ctx.packet.destination_hash) {
            entry.timestamp = ctx.now;
        }
        // As in Transport.py, traffic on a relayed link uses the path to the
        // link's destination.
        if let Some(entry) = self
            .path_table
            .get_mut(&link_entry.destination_hash)
            .and_then(|ps| ps.primary_mut())
        {
            entry.used = ctx.now;
        }
    }

    fn handle_inbound_announce(
        &mut self,
        ctx: &InboundPacketCtx,
        rng: &mut dyn Rng,
        announce_queue: Option<&mut AnnounceVerifyQueue>,
        actions: &mut Vec<TransportAction>,
    ) {
        if ctx.packet.flags.packet_type != constants::PACKET_TYPE_ANNOUNCE {
            return;
        }

        if let Some(queue) = announce_queue {
            self.try_enqueue_announce(ctx, rng, queue, actions);
        } else {
            let original_raw = ctx
                .original_raw
                .as_deref()
                .expect("announce packets retain original raw bytes");
            self.process_inbound_announce(
                &ctx.packet,
                original_raw,
                ctx.iface,
                ctx.now,
                rng,
                actions,
            );
        }
    }

    fn handle_inbound_local_delivery(
        &self,
        ctx: &InboundPacketCtx,
        actions: &mut Vec<TransportAction>,
    ) {
        if (ctx.packet.flags.packet_type == constants::PACKET_TYPE_LINKREQUEST
            || ctx.packet.flags.packet_type == constants::PACKET_TYPE_DATA)
            // The engine's exclusive borrow makes this a direct, lock-free
            // destination lookup for data and link requests alike; delivery
            // reuses the same keyed registry.
            && self
                .local_destinations
                .contains_key(&ctx.packet.destination_hash)
        {
            // Link responders learn the post-ingress hop metric from the
            // authenticated LRRTT packet. Preserve that field when crossing
            // the action boundary without changing ordinary callback bytes.
            let delivery_raw = if ctx.packet.context == constants::CONTEXT_LRRTT
                && ctx.packet.raw.len() >= 2
            {
                let mut raw = ctx.packet.raw.to_vec();
                raw[1] = ctx.packet.hops;
                PacketBytes::from(raw)
            } else if ctx.packet.flags.packet_type == constants::PACKET_TYPE_LINKREQUEST
                && ctx.packet.data().len() == constants::LINK_ECPUBSIZE + constants::LINK_MTU_SIZE
            {
                let receiving = self.interfaces.get(&ctx.iface);
                let mut raw = ctx.packet.raw.to_vec();
                super::inbound::clamp_local_link_request_mtu(
                    &mut raw,
                    true,
                    receiving.map(|info| info.mtu),
                    receiving.is_some_and(|info| info.mtu_upgradable),
                );
                PacketBytes::from(raw)
            } else {
                // The received bytes themselves, shared.
                ctx.packet.raw.clone()
            };
            actions.push(TransportAction::DeliverLocal {
                destination_hash: ctx.packet.destination_hash,
                raw: delivery_raw,
                packet_hash: ctx.packet.packet_hash,
                receiving_interface: ctx.iface,
            });
        }
    }

    // =========================================================================
    // Inbound announce processing
    // =========================================================================

    fn process_inbound_announce(
        &mut self,
        packet: &RawPacket<PacketBytes>,
        original_raw: &[u8],
        iface: InterfaceId,
        now: f64,
        rng: &mut dyn Rng,
        actions: &mut Vec<TransportAction>,
    ) {
        if packet.flags.destination_type != constants::DESTINATION_SINGLE {
            return;
        }

        let has_ratchet = packet.flags.context_flag == constants::FLAG_SET;

        // Unpack and validate announce
        let announce = match AnnounceData::unpack(packet.data(), has_ratchet) {
            Ok(a) => a,
            Err(_) => {
                actions.push(TransportAction::ProtocolViolation { interface: iface });
                self.inbound_filtered = true;
                return;
            }
        };

        if self.prefilter_announce(packet, iface, now) {
            return;
        }

        let sig_cache_key = Self::announce_sig_cache_key(&packet.destination_hash, &announce);

        let validated = if self.announce_sig_cache.contains(&sig_cache_key) {
            announce.to_validated_with_cached_signature(&packet.destination_hash)
        } else {
            announce.validate(&packet.destination_hash).inspect(|_| {
                self.announce_sig_cache.insert(sig_cache_key, now);
            })
        };
        let validated = match validated {
            Ok(v) => v,
            Err(_) => {
                self.record_invalid_announce(&announce, iface, now, actions);
                self.inbound_filtered = true;
                return;
            }
        };

        let received_from = self.announce_received_from(packet, now);
        let random_blob = match extract_random_blob(packet.data()) {
            Some(b) => b,
            None => {
                actions.push(TransportAction::ProtocolViolation { interface: iface });
                self.inbound_filtered = true;
                return;
            }
        };
        let announce_emitted = timebase_from_random_blob(&random_blob);

        self.process_verified_announce(
            VerifiedAnnounceCtx {
                packet,
                original_raw,
                iface,
                now,
                validated,
                received_from,
                random_blob,
                announce_emitted,
            },
            rng,
            actions,
        );
    }

    fn announce_raw_for_local_clients(&self, packet: &RawPacket<PacketBytes>) -> PacketBytes {
        let Some(identity_hash) = self.config.identity_hash else {
            return packet.raw.clone();
        };

        if packet.raw.len() < 2 {
            return packet.raw.clone();
        }

        let payload_start = if packet.flags.header_type == constants::HEADER_2 {
            18usize
        } else {
            2usize
        };
        if packet.raw.len() < payload_start {
            return packet.raw.clone();
        }

        // As upstream, the context flag is kept: it tells the client the
        // announce carries a ratchet.
        let flags = (constants::HEADER_2 << 6)
            | (packet.flags.context_flag << 5)
            | (constants::TRANSPORT_TRANSPORT << 4)
            | (packet.raw[0] & 0x0F);
        let mut raw = Vec::with_capacity(18 + packet.raw.len() - payload_start);
        raw.push(flags);
        raw.push(packet.hops);
        raw.extend_from_slice(&identity_hash);
        raw.extend_from_slice(&packet.raw[payload_start..]);
        PacketBytes::from(raw)
    }

    /// Signature cache key for an announce: covers the full signed data
    /// (see [`AnnounceData::signature_cache_key`]) plus the signature.
    pub(super) fn announce_sig_cache_key(
        destination_hash: &[u8; 16],
        announce: &AnnounceData,
    ) -> [u8; 32] {
        announce.signature_cache_key(destination_hash)
    }

    fn announce_received_from<B: AsRef<[u8]>>(
        &mut self,
        packet: &RawPacket<B>,
        now: f64,
    ) -> [u8; 16] {
        if let Some(transport_id) = packet.transport_id {
            if self.config.transport_enabled {
                if let Some(announce_entry) = self.announce_table.get_mut(&packet.destination_hash)
                {
                    if packet.hops.checked_sub(1) == Some(announce_entry.hops) {
                        announce_entry.local_rebroadcasts += 1;
                        if announce_entry.retries > 0
                            && announce_entry.local_rebroadcasts
                                >= constants::LOCAL_REBROADCASTS_MAX
                        {
                            self.announce_table.remove(&packet.destination_hash);
                        }
                    }
                    if let Some(announce_entry) = self.announce_table.get(&packet.destination_hash)
                    {
                        if packet.hops.checked_sub(1) == Some(announce_entry.hops + 1)
                            && announce_entry.retries > 0
                            && now < announce_entry.retransmit_timeout
                        {
                            self.announce_table.remove(&packet.destination_hash);
                        }
                    }
                }
            }
            transport_id
        } else {
            packet.destination_hash
        }
    }

    /// Upstream 096e6726 prefilters an announce for a destination that
    /// already has a path, before validating its signature: unless it is a
    /// path response, a local or discovery path request waits for the
    /// destination, or the destination is in the announce table, an announce
    /// that could not update the path (`Transport.announce_prefilter`) counts
    /// as a received announce without bytes and as a filtered announce, and
    /// is dropped. Returns whether it was dropped.
    fn prefilter_announce<B: AsRef<[u8]>>(
        &mut self,
        packet: &RawPacket<B>,
        iface: InterfaceId,
        now: f64,
    ) -> bool {
        let destination_hash = &packet.destination_hash;
        if packet.context == constants::CONTEXT_PATH_RESPONSE
            || !self.path_table.contains_key(destination_hash)
            || self.path_requests.contains_key(destination_hash)
            || self.discovery_path_requests.contains_key(destination_hash)
            || self.announce_table.contains_key(destination_hash)
        {
            return false;
        }
        if super::maintenance::announce_passes_prefilter(
            &self.config,
            &self.path_table,
            &self.path_states,
            &self.interfaces,
            destination_hash,
            packet.data(),
            iface,
            now,
        ) {
            return false;
        }
        self.announce_receipts.push((iface, 0));
        self.filter_announce();
        true
    }

    /// Whether a waiting path request or a known path exempts an announce
    /// from ingress limiting.
    fn ingress_exempt(&self, destination_hash: &[u8; 16]) -> bool {
        if self.has_path(destination_hash) {
            return true;
        }
        // Waiting path requests, local or for discovery, skip ingress
        // limiting (upstream logs this at pathing level since daec67a1).
        if self.path_requests.contains_key(destination_hash)
            || self.discovery_path_requests.contains_key(destination_hash)
        {
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Skipping ingress limit check for {:02x?} due to waiting path requests",
                &destination_hash[..4],
            );
            return true;
        }
        false
    }

    /// Whether ingress control limits a valid announce: one for an unknown
    /// destination, on an interface in an announce burst. Asking may start
    /// or end the burst.
    fn ingress_limited<B: AsRef<[u8]>>(
        &mut self,
        packet: &RawPacket<B>,
        iface: InterfaceId,
        now: f64,
    ) -> bool {
        if packet.context == constants::CONTEXT_PATH_RESPONSE
            || self.ingress_exempt(&packet.destination_hash)
        {
            return false;
        }
        let Some(info) = self.interfaces.get(&iface) else {
            return false;
        };
        self.ingress_control.should_ingress_limit(
            iface,
            &info.ingress_control,
            info.ia_freq,
            info.ia_samples,
            info.started,
            now,
        )
    }

    /// Hold a verified announce that arrived while its interface was
    /// limiting.
    /// An announce ingress control takes up counts as received without
    /// bytes (upstream c850cdac). Since upstream 29dc449a
    /// `preprocess_inbound` returns false after holding, so the held frame's
    /// bytes are filtered; its release counts them again. One ingress
    /// control drops or uses to replace a held one is also a filtered
    /// announce (819076c3).
    fn hold_decision<B: AsRef<[u8]>>(
        &mut self,
        packet: &RawPacket<B>,
        original_raw: &[u8],
        iface: InterfaceId,
        now: f64,
    ) -> HoldDecision {
        let Some(info) = self.interfaces.get(&iface) else {
            return HoldDecision::Pass;
        };
        // Upstream c850cdac: an announce ingress control takes up counts as
        // received, without bytes, whether it is held or dropped.
        self.announce_receipts.push((iface, 0));
        let held = self.ingress_control.hold_announce(
            iface,
            &info.ingress_control,
            packet.destination_hash,
            ingress_control::HeldAnnounce {
                raw: original_raw.to_vec(),
                hops: packet.hops,
                receiving_interface: iface,
                rx: RxMetadata {
                    rssi: packet.rssi,
                    snr: packet.snr,
                },
                timestamp: now,
            },
        );
        if held {
            self.inbound_filtered = true;
            HoldDecision::Held
        } else {
            HoldDecision::Filtered
        }
    }

    fn try_enqueue_announce(
        &mut self,
        ctx: &InboundPacketCtx,
        rng: &mut dyn Rng,
        announce_queue: &mut AnnounceVerifyQueue,
        actions: &mut Vec<TransportAction>,
    ) {
        if ctx.packet.flags.destination_type != constants::DESTINATION_SINGLE {
            return;
        }

        let has_ratchet = ctx.packet.flags.context_flag == constants::FLAG_SET;
        let announce = match AnnounceData::unpack(ctx.packet.data(), has_ratchet) {
            Ok(a) => a,
            Err(_) => {
                actions.push(TransportAction::ProtocolViolation {
                    interface: ctx.iface,
                });
                self.inbound_filtered = true;
                return;
            }
        };

        if self.prefilter_announce(&ctx.packet, ctx.iface, ctx.now) {
            return;
        }
        let received_from = self.announce_received_from(&ctx.packet, ctx.now);

        // Announce verification and this registry read share the engine's
        // exclusive processing turn, so no destinations-map lock is needed.
        if self
            .local_destinations
            .contains_key(&ctx.packet.destination_hash)
        {
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Announce:skipping local destination {:02x}{:02x}{:02x}{:02x}..",
                ctx.packet.destination_hash[0],
                ctx.packet.destination_hash[1],
                ctx.packet.destination_hash[2],
                ctx.packet.destination_hash[3],
            );
            return;
        }

        let original_raw = ctx
            .original_raw
            .as_deref()
            .expect("announce packets retain original raw bytes");

        // Upstream processes inbound announces one at a time, in the order
        // they arrive. An announce that would be processed at once, without
        // waiting for verification, waits behind an earlier one for the same
        // destination still being verified: processed first, a shared
        // client's registration path response would have the announce it
        // emitted just before rejected as not newer, and not rebroadcast.
        let behind_queued = announce_queue.has_destination(&ctx.packet.destination_hash);
        let sig_cache_key = Self::announce_sig_cache_key(&ctx.packet.destination_hash, &announce);
        if !behind_queued && self.announce_sig_cache.contains(&sig_cache_key) {
            let Ok(validated) =
                announce.to_validated_with_cached_signature(&ctx.packet.destination_hash)
            else {
                self.record_invalid_announce(&announce, ctx.iface, ctx.now, actions);
                self.inbound_filtered = true;
                return;
            };
            let random_blob = match extract_random_blob(ctx.packet.data()) {
                Some(b) => b,
                None => {
                    self.inbound_filtered = true;
                    return;
                }
            };
            let announce_emitted = timebase_from_random_blob(&random_blob);
            self.process_verified_announce(
                VerifiedAnnounceCtx {
                    packet: &ctx.packet,
                    original_raw,
                    iface: ctx.iface,
                    now: ctx.now,
                    validated,
                    received_from,
                    random_blob,
                    announce_emitted,
                },
                rng,
                actions,
            );
            return;
        }

        if !behind_queued && ctx.packet.context == constants::CONTEXT_PATH_RESPONSE {
            let Ok(validated) = announce.validate(&ctx.packet.destination_hash) else {
                self.record_invalid_announce(&announce, ctx.iface, ctx.now, actions);
                self.inbound_filtered = true;
                return;
            };
            self.announce_sig_cache.insert(sig_cache_key, ctx.now);
            let random_blob = match extract_random_blob(ctx.packet.data()) {
                Some(b) => b,
                None => {
                    self.inbound_filtered = true;
                    return;
                }
            };
            let announce_emitted = timebase_from_random_blob(&random_blob);
            self.process_verified_announce(
                VerifiedAnnounceCtx {
                    packet: &ctx.packet,
                    original_raw,
                    iface: ctx.iface,
                    now: ctx.now,
                    validated,
                    received_from,
                    random_blob,
                    announce_emitted,
                },
                rng,
                actions,
            );
            return;
        }

        let random_blob = match extract_random_blob(ctx.packet.data()) {
            Some(b) => b,
            None => {
                actions.push(TransportAction::ProtocolViolation {
                    interface: ctx.iface,
                });
                self.inbound_filtered = true;
                return;
            }
        };
        let announce_emitted = timebase_from_random_blob(&random_blob);
        let key = AnnounceVerifyKey {
            destination_hash: ctx.packet.destination_hash,
            random_blob,
            received_from,
        };
        let pending = PendingAnnounce {
            original_raw: original_raw.to_vec(),
            packet: ctx.packet.clone(),
            interface: ctx.iface,
            received_from,
            queued_at: ctx.now,
            best_hops: ctx.packet.hops,
            emission_ts: announce_emitted,
            random_blob,
        };
        let _ = announce_queue.enqueue(key, pending);
    }

    pub fn complete_verified_announce(
        &mut self,
        pending: PendingAnnounce,
        validated: crate::announce::ValidatedAnnounce,
        sig_cache_key: [u8; 32],
        now: f64,
        rng: &mut dyn Rng,
    ) -> Vec<TransportAction> {
        self.inbound_filtered = false;
        self.inbound_filtered_announce = false;
        self.announce_sig_cache.insert(sig_cache_key, now);
        let mut actions = Vec::new();
        self.process_verified_announce(
            VerifiedAnnounceCtx {
                packet: &pending.packet,
                original_raw: &pending.original_raw,
                iface: pending.interface,
                now,
                validated,
                received_from: pending.received_from,
                random_blob: pending.random_blob,
                announce_emitted: pending.emission_ts,
            },
            rng,
            &mut actions,
        );
        actions
    }

    pub fn clear_failed_verified_announce(&mut self, _sig_cache_key: [u8; 32], _now: f64) {}

    fn process_verified_announce(
        &mut self,
        mut ctx: VerifiedAnnounceCtx<'_>,
        rng: &mut dyn Rng,
        actions: &mut Vec<TransportAction>,
    ) {
        if self.is_blackholed(&ctx.validated.identity_hash, ctx.now) {
            self.filter_announce();
            return;
        }

        // Identity.validate_announce since 9b464382: the receiving
        // interface's `destination_cost`, else `Transport.DESTINATION_COST`.
        let required_value = self
            .interfaces
            .get(&ctx.iface)
            .map(|info| info.stamp_costs.destination_cost(&self.stamp_requirements))
            .unwrap_or(self.stamp_requirements.destination_cost);
        let stamp_status = ctx
            .validated
            .apply_stamp(&ctx.packet.destination_hash, required_value);
        if self.stamp_requirements.enforced
            && stamp_status != crate::announce::AnnounceStampStatus::Valid
        {
            self.filter_announce();
            return;
        }

        // As upstream's `preprocess_inbound`, ingress control judges an
        // announce only once its signature, identity and stamp have passed,
        // so an invalid or blackholed one neither starts nor ends a burst,
        // and judges it by the announces received before it.
        let hold = if self.ingress_limited(ctx.packet, ctx.iface, ctx.now) {
            self.hold_decision(ctx.packet, ctx.original_raw, ctx.iface, ctx.now)
        } else {
            HoldDecision::Pass
        };
        match hold {
            HoldDecision::Pass => {}
            HoldDecision::Held => return,
            HoldDecision::Filtered => {
                self.filter_announce();
                return;
            }
        }
        // Upstream's `received_announce(size)`: a valid announce that was
        // not held counts as received, with its bytes, whatever the path
        // table then makes of it.
        self.announce_receipts
            .push((ctx.iface, ctx.original_raw.len()));

        if ctx.packet.hops > constants::PATHFINDER_M {
            return;
        }

        let existing_set = self.path_table.get(&ctx.packet.destination_hash);
        let was_unknown_destination = existing_set.is_none_or(|ps| ps.is_empty());

        // Reset stale path state before first-path installation so path-state handling
        // cannot race ahead of the path table for previously unknown destinations.
        if was_unknown_destination {
            self.path_states.remove(&ctx.packet.destination_hash);
        }

        // Multi-path aware decision
        let is_unresponsive = self.path_is_unresponsive(&ctx.packet.destination_hash);

        let current_gravity = existing_set
            .and_then(|path_set| path_set.primary())
            .and_then(|path| self.interfaces.get(&path.receiving_interface))
            .map(|interface| interface.gravity);
        let announce_gravity = self
            .interfaces
            .get(&ctx.iface)
            .map(|interface| interface.gravity);
        let higher_gravity_replacement = existing_set.is_some_and(|path_set| {
            pathfinder::is_higher_gravity_replacement(
                path_set,
                ctx.packet.hops,
                ctx.announce_emitted,
                ctx.now,
                current_gravity,
                announce_gravity,
            )
        });
        let mp_decision = pathfinder::decide_announce_multipath_with_gravity(
            existing_set,
            ctx.packet.hops,
            ctx.announce_emitted,
            &ctx.random_blob,
            &ctx.received_from,
            is_unresponsive,
            ctx.now,
            self.config.prefer_shorter_path,
            current_gravity,
            announce_gravity,
        );

        if mp_decision == MultiPathDecision::Reject {
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Announce:path decision REJECT for dest={:02x}{:02x}{:02x}{:02x}..",
                ctx.packet.destination_hash[0],
                ctx.packet.destination_hash[1],
                ctx.packet.destination_hash[2],
                ctx.packet.destination_hash[3],
            );
            return;
        }
        if higher_gravity_replacement {
            log::log!(
                target: crate::logging::PATHING_LOG_TARGET,
                crate::logging::GRAVITY_UPDATE_LOG_LEVEL,
                "Replacing path table entry for {:02x}{:02x}{:02x}{:02x}.. due to higher gravity ({:?}->{:?})",
                ctx.packet.destination_hash[0],
                ctx.packet.destination_hash[1],
                ctx.packet.destination_hash[2],
                ctx.packet.destination_hash[3],
                current_gravity,
                announce_gravity,
            );
        }

        // Rate limiting
        let rate_blocked = if ctx.packet.context != constants::CONTEXT_PATH_RESPONSE {
            if let Some(iface_info) = self.interfaces.get(&ctx.iface) {
                self.rate_limiter.check_and_update(
                    &ctx.packet.destination_hash,
                    ctx.now,
                    iface_info.announce_rate_target,
                    iface_info.announce_rate_grace,
                    iface_info.announce_rate_penalty,
                )
            } else {
                false
            }
        } else {
            false
        };

        // Get interface mode for expiry calculation
        let interface_mode = self
            .interfaces
            .get(&ctx.iface)
            .map(|i| i.mode)
            .unwrap_or(constants::MODE_FULL);

        let expires = compute_path_expires(ctx.now, interface_mode);

        // Get existing random blobs from the matching path (same next_hop) or empty
        let existing_blobs = self
            .path_table
            .get(&ctx.packet.destination_hash)
            .and_then(|ps| ps.find_by_next_hop(&ctx.received_from))
            .map(|e| e.random_blobs.clone())
            .unwrap_or_default();

        // Generate RNG value for retransmit timeout
        let mut rng_bytes = [0u8; 8];
        rng.fill_bytes(&mut rng_bytes);
        let rng_value = (u64::from_le_bytes(rng_bytes) as f64) / (u64::MAX as f64);

        let is_path_response = ctx.packet.context == constants::CONTEXT_PATH_RESPONSE;

        let (mut path_entry, announce_entry) = announce_proc::process_validated_announce(
            ctx.packet.destination_hash,
            ctx.packet.hops,
            ctx.packet.data(),
            &ctx.packet.raw,
            ctx.packet.packet_hash,
            ctx.packet.flags.context_flag,
            ctx.received_from,
            ctx.iface,
            ctx.now,
            existing_blobs,
            ctx.random_blob,
            expires,
            rng_value,
            self.config.transport_enabled,
            self.serves_local_client(ctx.iface),
            is_path_response,
            rate_blocked,
            Some(ctx.original_raw.to_vec()),
        );

        // Emit CacheAnnounce for disk caching (pre-hop-increment raw)
        actions.push(TransportAction::CacheAnnounce {
            packet_hash: ctx.packet.packet_hash,
            raw: ctx.original_raw.to_vec().into(),
        });

        // As upstream, the new path keeps when the destination's path was
        // last used.
        path_entry.used = self
            .path_table
            .get(&ctx.packet.destination_hash)
            .and_then(|ps| ps.primary())
            .map_or(0.0, |path| path.used);

        // Store path via upsert into PathSet
        match mp_decision {
            MultiPathDecision::ReplacePrimary => self.upsert_primary_path_destination(
                ctx.packet.destination_hash,
                path_entry,
                ctx.now,
            ),
            MultiPathDecision::AddAlternative => {
                self.upsert_path_destination(ctx.packet.destination_hash, path_entry, ctx.now)
            }
            MultiPathDecision::Reject => unreachable!("rejected decisions returned above"),
        }

        // If receiving interface has a tunnel_id, store path in tunnel table too
        if let Some(tunnel_id) = self.interfaces.get(&ctx.iface).and_then(|i| i.tunnel_id) {
            // As upstream, the tunnel keeps the path's random blobs and
            // when it was last used.
            let (blobs, used) = self
                .path_table
                .get(&ctx.packet.destination_hash)
                .and_then(|ps| ps.find_by_next_hop(&ctx.received_from))
                .map(|e| (e.random_blobs.clone(), e.used))
                .unwrap_or_default();
            self.tunnel_table.store_tunnel_path(
                &tunnel_id,
                ctx.packet.destination_hash,
                tunnel::TunnelPath {
                    timestamp: ctx.now,
                    received_from: ctx.received_from,
                    hops: ctx.packet.hops,
                    expires,
                    random_blobs: blobs,
                    packet_hash: ctx.packet.packet_hash,
                    used,
                },
                ctx.now,
                self.config.destination_timeout_secs,
                self.config.max_tunnel_destinations_total,
            );
        }

        // Re-apply the path-state reset after storing the path entry so any transient
        // stale state is also cleared once the destination exists in the path table.
        self.path_states.remove(&ctx.packet.destination_hash);

        // Store announce for retransmission
        if let Some(ann) = announce_entry {
            self.insert_announce_entry(ctx.packet.destination_hash, ann, ctx.now);
        } else if is_path_response && self.serves_local_client(ctx.iface) {
            // Transport.py:2375-2395: relay a local client's path response,
            // immediately and once, to an interface that asked for it.
            if let Some((requesting_interface, _)) = self
                .pending_local_path_requests
                .remove(&ctx.packet.destination_hash)
            {
                let entry = AnnounceEntry {
                    timestamp: ctx.now,
                    retransmit_timeout: ctx.now,
                    retries: constants::PATHFINDER_R,
                    received_from: ctx.received_from,
                    hops: ctx.packet.hops,
                    packet_raw: ctx.packet.raw.to_vec(),
                    packet_data: ctx.packet.data().to_vec(),
                    destination_hash: ctx.packet.destination_hash,
                    context_flag: ctx.packet.flags.context_flag,
                    local_rebroadcasts: 0,
                    block_rebroadcasts: true,
                    attached_interface: Some(requesting_interface),
                };
                self.insert_announce_entry(ctx.packet.destination_hash, entry, ctx.now);
            }
        }

        // Emit actions
        actions.push(TransportAction::AnnounceReceived(alloc::boxed::Box::new(
            types::ReceivedAnnounce {
                destination_hash: ctx.packet.destination_hash,
                identity_hash: ctx.validated.identity_hash,
                public_key: ctx.validated.public_key,
                name_hash: ctx.validated.name_hash,
                random_hash: ctx.validated.random_hash,
                ratchet: ctx.validated.ratchet,
                app_data: ctx.validated.app_data,
                stamp: ctx.validated.stamp,
                stamp_value: ctx.validated.stamp_value,
                lr_cost: ctx.validated.lr_cost,
                hops: ctx.packet.hops,
                receiving_interface: ctx.iface,
                rx: RxMetadata {
                    rssi: ctx.packet.rssi,
                    snr: ctx.packet.snr,
                },
            },
        )));

        actions.push(TransportAction::PathUpdated {
            destination_hash: ctx.packet.destination_hash,
            hops: ctx.packet.hops,
            next_hop: ctx.received_from,
            interface: ctx.iface,
        });

        // An announce arriving with PATHFINDER_M - 1 hops now carries
        // PATHFINDER_M, which no node decodes: it updates the path table but
        // is not sent on (upstream's `Packet.send` refuses it).
        let sendable = ctx.packet.hops < constants::PATHFINDER_M;

        // Forward announce to local clients if any are connected
        if sendable && self.has_local_clients() {
            actions.push(TransportAction::ForwardToLocalClients {
                raw: self.announce_raw_for_local_clients(ctx.packet),
                exclude: Some(ctx.iface),
            });
        }

        // Check for discovery path requests waiting for this announce
        if let Some(requesting_interfaces) =
            self.discovery_path_requests_waiting(&ctx.packet.destination_hash)
        {
            // Build a path response announce and queue it
            let entry = AnnounceEntry {
                timestamp: ctx.now,
                retransmit_timeout: ctx.now,
                retries: constants::PATHFINDER_R,
                received_from: ctx.received_from,
                hops: ctx.packet.hops,
                packet_raw: ctx.packet.raw.to_vec(),
                packet_data: ctx.packet.data().to_vec(),
                destination_hash: ctx.packet.destination_hash,
                context_flag: ctx.packet.flags.context_flag,
                local_rebroadcasts: 0,
                block_rebroadcasts: true,
                attached_interface: requesting_interfaces.first().copied(),
            };
            if let Some(identity_hash) = self.config.identity_hash.filter(|_| sendable) {
                let raw = announce_proc::build_retransmit_announce(&entry, &identity_hash);
                for interface in requesting_interfaces.iter().skip(1) {
                    actions.push(TransportAction::SendOnInterface {
                        interface: *interface,
                        raw: raw.clone().into(),
                    });
                }
            }
            self.insert_announce_entry(ctx.packet.destination_hash, entry, ctx.now);
        }
    }

    pub fn announce_sig_cache_contains(&self, sig_cache_key: &[u8; 32]) -> bool {
        self.announce_sig_cache.contains(sig_cache_key)
    }

    /// Check if there's a waiting discovery path request for a destination.
    /// Consumes the request if found (one-shot: the caller queues the announce response).
    pub(super) fn discovery_path_requests_waiting(
        &mut self,
        dest_hash: &[u8; 16],
    ) -> Option<Vec<InterfaceId>> {
        let request = self
            .discovery_path_requests
            .remove(dest_hash)
            .map(|req| req.requesting_interfaces);
        self.discovery_path_request_deadlines.remove(dest_hash);
        request
    }

    // =========================================================================
    // Inbound proof processing
    // =========================================================================

    fn process_inbound_proof(
        &mut self,
        ctx: &InboundPacketCtx,
        actions: &mut Vec<TransportAction>,
    ) {
        let packet = &ctx.packet;
        if packet.context == constants::CONTEXT_LRPROOF {
            // Link request proof routing. As in Transport.py, a shared
            // instance without transport also routes proofs for links to or
            // from its local clients (#183).
            let for_local_client_link =
                self.link_table
                    .get(&packet.destination_hash)
                    .is_some_and(|entry| {
                        self.interface_is_local_client(entry.next_hop_interface)
                            || self.interface_is_local_client(entry.received_interface)
                    });
            let verdict = self
                .lrproof_verdict
                .take()
                .filter(|(link_id, _)| *link_id == packet.destination_hash)
                .map(|(_, valid)| valid);
            if (self.config.transport_enabled || ctx.from_local_client || for_local_client_link)
                && self.link_table.contains_key(&packet.destination_hash)
            {
                let link_entry = self.link_table.get(&packet.destination_hash).cloned();
                if verdict == Some(false) {
                    // Transport.py drops a transported proof whose signature
                    // does not verify, as a protocol violation.
                    log::debug!(
                        "Invalid link request proof in transport for link {:02x?}, dropping proof",
                        &packet.destination_hash[..4]
                    );
                    actions.push(TransportAction::ProtocolViolation {
                        interface: ctx.iface,
                    });
                    return;
                }
                if let Some(entry) = link_entry {
                    let instance_local_link = self
                        .interface_is_local_client(entry.next_hop_interface)
                        && self.interface_is_local_client(entry.received_interface);
                    if let Some((outbound_interface, new_raw)) = route_via_link_table(
                        packet,
                        &entry,
                        ctx.iface,
                        LocalHopRewrite {
                            local_hops_delta: self.config.local_hops_delta,
                            from_local_client: ctx.from_local_client,
                            skip_local_hops_delta: instance_local_link,
                        },
                    ) {
                        // The caller checked the signature when it could recall
                        // the destination's identity (`verdict`); a proof from
                        // the destination proves it alive.
                        if let Some(le) = self.link_table.get_mut(&packet.destination_hash) {
                            le.validated = true;
                        }
                        if verdict == Some(true) {
                            self.mark_path_responsive(&entry.destination_hash, ctx.now);
                        }

                        actions.push(TransportAction::LinkEstablished {
                            link_id: packet.destination_hash,
                            interface: outbound_interface,
                        });

                        actions.push(TransportAction::SendOnInterface {
                            interface: outbound_interface,
                            raw: new_raw.into(),
                        });
                    } else if link_route_hops_match(packet.hops, &entry, ctx.iface) {
                        log::debug!(
                            "Link request proof received on wrong interface {}, not transporting it (expected {} or {})",
                            ctx.iface.0,
                            entry.next_hop_interface.0,
                            entry.received_interface.0,
                        );
                    } else {
                        log::debug!("{}", lrproof_hop_mismatch_diagnostic(packet.hops, &entry));
                    }
                }
            } else {
                // Could be for a local pending link - deliver locally
                let mut delivery_raw = packet.raw.to_vec();
                // LinkManager must see the same post-ingress hop metric that
                // was authenticated and considered by transport.
                if delivery_raw.len() >= 2 {
                    delivery_raw[1] = packet.hops;
                }
                actions.push(TransportAction::DeliverLocal {
                    destination_hash: packet.destination_hash,
                    raw: PacketBytes::from(delivery_raw),
                    packet_hash: packet.packet_hash,
                    receiving_interface: ctx.iface,
                });
            }
        } else {
            // Regular proof: check reverse table. As in Transport.py, a shared
            // instance without transport also routes proofs to or from its
            // local clients (#183).
            let proof_for_local_client = self
                .reverse_table
                .get(&packet.destination_hash)
                .is_some_and(|entry| self.interface_is_local_client(entry.receiving_interface));
            if self.config.transport_enabled || ctx.from_local_client || proof_for_local_client {
                if let Some(reverse_entry) = self.reverse_table.remove(&packet.destination_hash) {
                    if let Some(action) = route_proof_via_reverse(
                        packet,
                        &reverse_entry,
                        ctx.iface,
                        LocalHopRewrite {
                            local_hops_delta: self.config.local_hops_delta,
                            from_local_client: ctx.from_local_client,
                            skip_local_hops_delta: proof_for_local_client,
                        },
                    ) {
                        actions.push(action);
                    }
                }
            }

            // Deliver to local receipts
            actions.push(TransportAction::DeliverLocal {
                destination_hash: packet.destination_hash,
                raw: packet.raw.clone(),
                packet_hash: packet.packet_hash,
                receiving_interface: ctx.iface,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PacketFlags;
    use crate::transport::tables::ReverseEntry;
    use crate::transport::tests::{
        make_config, make_interface, make_local_client_interface, make_path_entry,
    };

    const OUR_ID: [u8; 16] = [0x42; 16];

    fn flags(header_type: u8, destination_type: u8, packet_type: u8) -> PacketFlags {
        PacketFlags {
            header_type,
            context_flag: constants::FLAG_UNSET,
            transport_type: if header_type == constants::HEADER_2 {
                constants::TRANSPORT_TRANSPORT
            } else {
                constants::TRANSPORT_BROADCAST
            },
            destination_type,
            packet_type,
        }
    }

    fn packet(
        flags: PacketFlags,
        hops: u8,
        destination: &[u8; 16],
        transport_id: Option<&[u8; 16]>,
        context: u8,
    ) -> RawPacket {
        RawPacket::pack(flags, hops, destination, transport_id, context, b"payload").unwrap()
    }

    fn receive(
        engine: &mut TransportEngine,
        packet: &RawPacket,
        iface: u64,
    ) -> Vec<TransportAction> {
        let mut rng = rns_crypto::FixedRng::new(&[0x44; 32]);
        engine.handle_inbound(
            InboundFrame::new(&packet.raw, InterfaceId(iface), 1001.0),
            &mut rng,
        )
    }

    fn sent_on(actions: &[TransportAction], iface: u64) -> Option<&PacketBytes> {
        actions.iter().find_map(|action| match action {
            TransportAction::SendOnInterface { interface, raw }
                if *interface == InterfaceId(iface) =>
            {
                Some(raw)
            }
            _ => None,
        })
    }

    #[test]
    fn accepts_inbound_frame_applies_the_packet_filter() {
        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        let data = packet(
            flags(
                constants::HEADER_1,
                constants::DESTINATION_SINGLE,
                constants::PACKET_TYPE_DATA,
            ),
            0,
            &[0x51; 16],
            None,
            constants::CONTEXT_NONE,
        );
        let frame = InboundFrame::new(&data.raw, InterfaceId(1), 1000.0);
        assert!(engine.accepts_inbound_frame(frame));
        assert!(!engine.accepts_inbound_frame(InboundFrame::new(&[0x00], InterfaceId(1), 1000.0)));
        receive(&mut engine, &data, 1);
        assert!(
            !engine.accepts_inbound_frame(frame),
            "a duplicate is filtered"
        );
    }

    /// As upstream's Transport.inbound, a packet's hash is remembered for
    /// deduplication unless it belongs to a link this node relays or is a
    /// link request proof.
    #[test]
    fn inbound_packet_hashes_are_remembered_as_upstream() {
        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        let relayed_link = [0x4C; 16];
        engine.register_link(
            relayed_link,
            LinkEntry {
                timestamp: 1000.0,
                next_hop_transport_id: [0x33; 16],
                next_hop_interface: InterfaceId(2),
                remaining_hops: 1,
                received_interface: InterfaceId(1),
                taken_hops: 1,
                destination_hash: [0xD0; 16],
                validated: true,
                proof_timeout: 2000.0,
            },
        );
        let link_flags = |packet_type| {
            flags(
                constants::HEADER_1,
                constants::DESTINATION_LINK,
                packet_type,
            )
        };
        let single_flags = |packet_type| {
            flags(
                constants::HEADER_1,
                constants::DESTINATION_SINGLE,
                packet_type,
            )
        };
        let cases = [
            (
                packet(
                    single_flags(constants::PACKET_TYPE_DATA),
                    0,
                    &[0x51; 16],
                    None,
                    0,
                ),
                true,
            ),
            (
                packet(
                    single_flags(constants::PACKET_TYPE_PROOF),
                    0,
                    &[0x52; 16],
                    None,
                    0,
                ),
                true,
            ),
            (
                packet(
                    link_flags(constants::PACKET_TYPE_PROOF),
                    0,
                    &[0x53; 16],
                    None,
                    constants::CONTEXT_LRPROOF,
                ),
                false,
            ),
            (
                packet(
                    link_flags(constants::PACKET_TYPE_DATA),
                    0,
                    &relayed_link,
                    None,
                    0,
                ),
                false,
            ),
        ];
        for (n, (packet, remembered)) in cases.iter().enumerate() {
            receive(&mut engine, packet, 1);
            assert_eq!(
                engine.packet_hashlist.is_duplicate(&packet.packet_hash),
                *remembered,
                "case {n}"
            );
        }
    }

    /// Only plain broadcasts are bridged between a shared instance's local
    /// clients and the network.
    #[test]
    fn only_plain_broadcasts_are_bridged_to_local_clients() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_local_client_interface(1));
        engine.register_interface(make_interface(2, constants::MODE_FULL));
        let bridged = |actions: &[TransportAction]| {
            actions
                .iter()
                .any(|action| matches!(action, TransportAction::ForwardPlainBroadcast { .. }))
        };
        for (destination_type, expected) in [
            (constants::DESTINATION_PLAIN, true),
            (constants::DESTINATION_SINGLE, false),
        ] {
            let broadcast = packet(
                flags(
                    constants::HEADER_1,
                    destination_type,
                    constants::PACKET_TYPE_DATA,
                ),
                0,
                &[0x60 + destination_type; 16],
                None,
                constants::CONTEXT_NONE,
            );
            assert_eq!(bridged(&receive(&mut engine, &broadcast, 2)), expected);
        }
    }

    /// As upstream, an announce is never forwarded as transport traffic,
    /// even when it carries this node's transport id.
    #[test]
    fn announce_addressed_to_this_transport_is_not_forwarded() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        engine.register_interface(make_interface(2, constants::MODE_FULL));
        let dest = [0xA7; 16];
        engine.upsert_path_destination(
            dest,
            make_path_entry(1000.0, 2, InterfaceId(2), [0x29; 16]),
            1000.0,
        );
        let announce = packet(
            flags(
                constants::HEADER_2,
                constants::DESTINATION_SINGLE,
                constants::PACKET_TYPE_ANNOUNCE,
            ),
            0,
            &dest,
            Some(&OUR_ID),
            constants::CONTEXT_NONE,
        );
        let actions = receive(&mut engine, &announce, 1);
        assert!(sent_on(&actions, 2).is_none());
        assert!(engine.reverse_table.is_empty());
    }

    /// The local hop delta masks only a local client's own zero-hop
    /// packets as they leave for the network.
    #[test]
    fn local_hops_delta_masks_only_local_zero_hop_packets_leaving_the_instance() {
        let mut config = make_config(true);
        config.local_hops_delta = 5;
        let mut engine = TransportEngine::new(config);
        engine.register_interface(make_local_client_interface(1));
        engine.register_interface(make_interface(2, constants::MODE_FULL));
        engine.register_interface(make_local_client_interface(3));
        engine.register_interface(make_interface(4, constants::MODE_FULL));
        let to_network = [0xB1; 16];
        let to_local_client = [0xB3; 16];
        engine.upsert_path_destination(
            to_network,
            make_path_entry(1000.0, 2, InterfaceId(2), [0x29; 16]),
            1000.0,
        );
        engine.upsert_path_destination(
            to_local_client,
            make_path_entry(1000.0, 1, InterfaceId(3), to_local_client),
            1000.0,
        );
        let data = |hops: u8, destination: &[u8; 16], payload_tag: u8| {
            RawPacket::pack(
                flags(
                    constants::HEADER_2,
                    constants::DESTINATION_SINGLE,
                    constants::PACKET_TYPE_DATA,
                ),
                hops,
                destination,
                Some(&OUR_ID),
                constants::CONTEXT_NONE,
                &[payload_tag; 8],
            )
            .unwrap()
        };
        // (packet, receiving interface, outbound interface, forwarded hops)
        let cases = [
            (data(0, &to_network, 1), 1, 2, 5),
            (data(0, &to_network, 2), 4, 2, 1),
            (data(0, &to_local_client, 3), 1, 3, 0),
            (data(1, &to_network, 4), 1, 2, 1),
        ];
        for (n, (packet, from, to, hops)) in cases.iter().enumerate() {
            let actions = receive(&mut engine, packet, *from);
            let raw = sent_on(&actions, *to).unwrap_or_else(|| panic!("case {n} forwarded"));
            assert_eq!(raw[1], *hops, "case {n}");
        }
    }

    fn relayed_link(next_hop_interface: u64, received_interface: u64) -> LinkEntry {
        LinkEntry {
            timestamp: 1000.0,
            next_hop_transport_id: [0x33; 16],
            next_hop_interface: InterfaceId(next_hop_interface),
            remaining_hops: 1,
            received_interface: InterfaceId(received_interface),
            taken_hops: 0,
            destination_hash: [0xD0; 16],
            validated: true,
            proof_timeout: 2000.0,
        }
    }

    /// Link traffic is relayed by a transport node or a shared instance,
    /// which has a transport identity, but not by a plain client.
    #[test]
    fn link_traffic_is_relayed_only_by_nodes_with_a_transport_identity() {
        let link_id = [0x4C; 16];
        let link_data = packet(
            flags(
                constants::HEADER_1,
                constants::DESTINATION_LINK,
                constants::PACKET_TYPE_DATA,
            ),
            0,
            &link_id,
            None,
            constants::CONTEXT_NONE,
        );
        let mut shared = make_config(false);
        shared.identity_hash = Some(OUR_ID);
        for (config, relays) in [
            (make_config(true), true),
            (shared, true),
            (make_config(false), false),
        ] {
            let mut engine = TransportEngine::new(config);
            engine.register_interface(make_local_client_interface(1));
            engine.register_interface(make_interface(2, constants::MODE_FULL));
            engine.register_link(link_id, relayed_link(2, 1));
            let actions = receive(&mut engine, &link_data, 1);
            assert_eq!(sent_on(&actions, 2).is_some(), relays);
        }
    }

    /// As upstream, announces, link requests and link request proofs are
    /// never relayed through the link table, even when addressed to a link
    /// it holds.
    #[test]
    fn link_table_does_not_relay_announces_link_requests_or_their_proofs() {
        let link_id = [0x4C; 16];
        for (packet_type, context, sends) in [
            (constants::PACKET_TYPE_ANNOUNCE, constants::CONTEXT_NONE, 0),
            (
                constants::PACKET_TYPE_LINKREQUEST,
                constants::CONTEXT_NONE,
                0,
            ),
            // The proof is relayed once, as a proof.
            (constants::PACKET_TYPE_PROOF, constants::CONTEXT_LRPROOF, 1),
        ] {
            let mut engine = TransportEngine::new(make_config(true));
            engine.register_interface(make_interface(1, constants::MODE_FULL));
            engine.register_interface(make_interface(2, constants::MODE_FULL));
            engine.register_link(link_id, relayed_link(2, 1));
            let packet = packet(
                flags(
                    constants::HEADER_1,
                    constants::DESTINATION_LINK,
                    packet_type,
                ),
                0,
                &link_id,
                None,
                context,
            );
            let actions = receive(&mut engine, &packet, 2);
            let sent = actions
                .iter()
                .filter(|action| matches!(action, TransportAction::SendOnInterface { .. }))
                .count();
            assert_eq!(sent, sends, "packet type {packet_type}");
        }
    }

    /// Only a link request's MTU signalling is clamped on delivery; data of
    /// the same length is delivered as received.
    #[test]
    fn local_delivery_clamps_only_link_request_signalling() {
        let mut engine = TransportEngine::new(make_config(false));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        let dest = [0xE1; 16];
        engine.register_destination(dest, constants::DESTINATION_SINGLE);
        let mut payload = vec![0x5A; constants::LINK_ECPUBSIZE];
        payload.extend_from_slice(&[0x1F, 0xFF, 0xFF]);
        let data = RawPacket::pack(
            flags(
                constants::HEADER_1,
                constants::DESTINATION_SINGLE,
                constants::PACKET_TYPE_DATA,
            ),
            0,
            &dest,
            None,
            constants::CONTEXT_NONE,
            &payload,
        )
        .unwrap();
        let actions = receive(&mut engine, &data, 1);
        let delivered = actions
            .iter()
            .find_map(|action| match action {
                TransportAction::DeliverLocal { raw, .. } => Some(raw),
                _ => None,
            })
            .expect("delivered");
        assert_eq!(&delivered[2..], &data.raw[2..]);
    }

    fn announced(actions: &[TransportAction]) -> bool {
        actions
            .iter()
            .any(|action| matches!(action, TransportAction::AnnounceReceived(_)))
    }

    /// Ingress control holds an announce for an unknown destination during
    /// a burst, but never a path response, and nothing outside a burst.
    #[test]
    fn ingress_control_holds_only_unrequested_announces_during_a_burst() {
        use super::local_client_announce_tests::announce_in_context;
        for (ia_freq, context, held) in [
            (100.0, constants::CONTEXT_NONE, true),
            (100.0, constants::CONTEXT_PATH_RESPONSE, false),
            (0.0, constants::CONTEXT_NONE, false),
        ] {
            let mut engine = TransportEngine::new(make_config(true));
            engine.register_interface(InterfaceInfo {
                ingress_control: crate::transport::types::IngressControlConfig::enabled(),
                ia_freq,
                ..make_interface(1, constants::MODE_FULL)
            });
            let announce = announce_in_context(7, false, constants::HEADER_1, 0, context);
            let actions = receive(&mut engine, &announce, 1);
            assert_eq!(
                announced(&actions),
                !held,
                "freq {ia_freq} context {context}"
            );
            assert_eq!(
                engine.held_announce_count(&InterfaceId(1)),
                usize::from(held)
            );
        }
    }

    /// As upstream, announce rate limiting does not apply to path
    /// responses: their rate is not even tracked.
    #[test]
    fn announce_rate_limit_spares_path_responses() {
        use super::local_client_announce_tests::announce_in_context;
        for (context, tracked) in [
            (constants::CONTEXT_NONE, true),
            (constants::CONTEXT_PATH_RESPONSE, false),
        ] {
            let mut engine = TransportEngine::new(make_config(true));
            engine.register_interface(InterfaceInfo {
                announce_rate_target: Some(3600.0),
                ..make_interface(1, constants::MODE_FULL)
            });
            let announce = announce_in_context(8, false, constants::HEADER_1, 0, context);
            let actions = receive(&mut engine, &announce, 1);
            assert!(announced(&actions));
            assert_eq!(
                engine.rate_limiter_count(),
                usize::from(tracked),
                "context {context}"
            );
        }
    }

    /// As upstream, a path response is passed on to a network interface
    /// that asked for it only when it comes from a local client; one from
    /// the network is not retransmitted.
    #[test]
    fn only_a_local_clients_path_response_answers_a_pending_request() {
        use super::local_client_announce_tests::announce_in_context;
        for (from, answered) in [(2, true), (1, false)] {
            let mut engine = TransportEngine::new(make_config(true));
            engine.register_interface(make_interface(1, constants::MODE_FULL));
            engine.register_interface(make_local_client_interface(2));
            engine.register_interface(make_interface(3, constants::MODE_FULL));
            let response = announce_in_context(
                9,
                false,
                constants::HEADER_1,
                0,
                constants::CONTEXT_PATH_RESPONSE,
            );
            let dest = response.destination_hash;
            engine
                .pending_local_path_requests
                .insert(dest, (InterfaceId(3), 1000.0));
            let actions = receive(&mut engine, &response, from);
            assert!(announced(&actions));
            assert_eq!(
                engine
                    .announce_table
                    .get(&dest)
                    .map(|entry| entry.attached_interface),
                answered.then_some(Some(InterfaceId(3))),
                "from {from}"
            );
        }
    }

    fn table_entry(hops: u8, retries: u8, retransmit_timeout: f64) -> AnnounceEntry {
        AnnounceEntry {
            timestamp: 1000.0,
            retransmit_timeout,
            retries,
            received_from: [0xAA; 16],
            hops,
            packet_raw: Vec::new(),
            packet_data: Vec::new(),
            destination_hash: [0xAD; 16],
            context_flag: 0,
            local_rebroadcasts: 0,
            block_rebroadcasts: false,
            attached_interface: None,
        }
    }

    fn rebroadcast(hops: u8) -> RawPacket {
        packet(
            flags(
                constants::HEADER_2,
                constants::DESTINATION_SINGLE,
                constants::PACKET_TYPE_ANNOUNCE,
            ),
            hops,
            &[0xAD; 16],
            Some(&[0x29; 16]),
            constants::CONTEXT_NONE,
        )
    }

    /// As upstream: hearing a neighbour rebroadcast an announce this node
    /// is retransmitting, at the hops this node would, counts a local
    /// rebroadcast, and after LOCAL_REBROADCASTS_MAX of them, once this
    /// node has retried, it stops retransmitting.
    #[test]
    fn local_rebroadcasts_end_retransmission_after_a_retry() {
        let dest = [0xAD; 16];
        for (retries, removed_after) in [(1, Some(2)), (0, None)] {
            let mut engine = TransportEngine::new(make_config(true));
            engine
                .announce_table
                .insert(dest, table_entry(2, retries, 2000.0));
            for heard in 1..=3u8 {
                let from = engine.announce_received_from(&rebroadcast(3), 1500.0);
                assert_eq!(from, [0x29; 16]);
                let entry = engine.announce_table.get(&dest);
                if removed_after.is_some_and(|after| heard >= after) {
                    assert!(entry.is_none(), "retries {retries} heard {heard}");
                } else {
                    assert_eq!(entry.unwrap().local_rebroadcasts, heard);
                }
            }
        }

        // A rebroadcast at other hops is not a local one.
        let mut engine = TransportEngine::new(make_config(true));
        engine
            .announce_table
            .insert(dest, table_entry(2, 1, 2000.0));
        engine.announce_received_from(&rebroadcast(5), 1500.0);
        assert_eq!(engine.announce_table[&dest].local_rebroadcasts, 0);
    }

    /// As upstream: hearing the announce one hop further on, after this
    /// node has retried it and before its next retry is due, means another
    /// node passed it on, so it is not retransmitted again.
    #[test]
    fn announce_passed_on_by_another_node_ends_retransmission() {
        let dest = [0xAD; 16];
        for (retries, now, removed) in [(1, 1500.0, true), (0, 1500.0, false), (1, 2000.0, false)] {
            let mut engine = TransportEngine::new(make_config(true));
            engine
                .announce_table
                .insert(dest, table_entry(2, retries, 2000.0));
            engine.announce_received_from(&rebroadcast(4), now);
            assert_eq!(
                !engine.announce_table.contains_key(&dest),
                removed,
                "retries {retries} at {now}"
            );
        }

        // An announce without a transport id is received from its
        // destination and leaves the table alone.
        let mut engine = TransportEngine::new(make_config(true));
        engine
            .announce_table
            .insert(dest, table_entry(2, 1, 2000.0));
        let direct = packet(
            flags(
                constants::HEADER_1,
                constants::DESTINATION_SINGLE,
                constants::PACKET_TYPE_ANNOUNCE,
            ),
            3,
            &dest,
            None,
            constants::CONTEXT_NONE,
        );
        assert_eq!(engine.announce_received_from(&direct, 1500.0), dest);
        assert_eq!(engine.announce_table[&dest].local_rebroadcasts, 0);
    }

    /// A path response is never prefiltered, even when an ordinary
    /// announce with the same emission time would be.
    #[test]
    fn prefilter_spares_path_responses() {
        use crate::transport::tests::make_random_blob;
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        let dest = [0xAE; 16];
        engine.upsert_path_destination(
            dest,
            PathEntry {
                random_blobs: vec![make_random_blob(200)],
                ..make_path_entry(1000.0, 1, InterfaceId(1), [0x29; 16])
            },
            1000.0,
        );
        let mut data = vec![0u8; constants::KEYSIZE / 8 + constants::NAME_HASH_LENGTH / 8];
        data.extend_from_slice(&make_random_blob(100));
        data.extend_from_slice(&[0u8; 64]);
        for (context, dropped) in [
            (constants::CONTEXT_NONE, true),
            (constants::CONTEXT_PATH_RESPONSE, false),
        ] {
            let announce = RawPacket::pack(
                flags(
                    constants::HEADER_1,
                    constants::DESTINATION_SINGLE,
                    constants::PACKET_TYPE_ANNOUNCE,
                ),
                1,
                &dest,
                None,
                context,
                &data,
            )
            .unwrap();
            assert_eq!(
                engine.prefilter_announce(&announce, InterfaceId(1), 1000.0),
                dropped,
                "context {context}"
            );
        }

        // Nor is an announce for a destination a discovery path request
        // waits for, or one being retransmitted.
        let announce = RawPacket::pack(
            flags(
                constants::HEADER_1,
                constants::DESTINATION_SINGLE,
                constants::PACKET_TYPE_ANNOUNCE,
            ),
            1,
            &dest,
            None,
            constants::CONTEXT_NONE,
            &data,
        )
        .unwrap();
        engine.discovery_path_requests.insert(
            dest,
            DiscoveryPathRequest {
                timestamp: 1000.0,
                requesting_interfaces: Vec::new(),
                engaged: false,
            },
        );
        assert!(!engine.prefilter_announce(&announce, InterfaceId(1), 1000.0));
        engine.discovery_path_requests.remove(&dest);
        engine
            .announce_table
            .insert(dest, table_entry(1, 0, 2000.0));
        assert!(!engine.prefilter_announce(&announce, InterfaceId(1), 1000.0));
    }

    fn lrproof(link_id: &[u8; 16], hops: u8) -> RawPacket {
        packet(
            flags(
                constants::HEADER_1,
                constants::DESTINATION_LINK,
                constants::PACKET_TYPE_PROOF,
            ),
            hops,
            link_id,
            None,
            constants::CONTEXT_LRPROOF,
        )
    }

    /// As upstream, a shared instance without transport still relays a
    /// link request proof for a link to or from one of its local clients.
    #[test]
    fn shared_instance_relays_link_proofs_for_its_local_clients() {
        let mut config = make_config(false);
        config.identity_hash = Some(OUR_ID);
        let mut engine = TransportEngine::new(config);
        engine.register_interface(make_local_client_interface(1));
        engine.register_interface(make_interface(2, constants::MODE_FULL));
        let link_id = [0x4D; 16];
        // The local client on 1 asked for a link to a destination over 2.
        engine.register_link(
            link_id,
            LinkEntry {
                validated: false,
                ..relayed_link(2, 1)
            },
        );
        let actions = receive(&mut engine, &lrproof(&link_id, 0), 2);
        assert!(sent_on(&actions, 1).is_some());
        assert!(!actions
            .iter()
            .any(|action| matches!(action, TransportAction::DeliverLocal { .. })));
    }

    /// A transport node delivers a link request proof for a link it holds
    /// no relay entry for: one it requested itself.
    #[test]
    fn link_proof_without_relay_entry_is_delivered_locally() {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        let actions = receive(&mut engine, &lrproof(&[0x4E; 16], 0), 1);
        assert!(actions
            .iter()
            .any(|action| matches!(action, TransportAction::DeliverLocal { .. })));
    }

    /// A link proof from a local client toward the network carries the
    /// local hop delta; only a link between two local clients skips it.
    #[test]
    fn link_proof_from_local_client_to_network_carries_local_hops_delta() {
        let mut config = make_config(true);
        config.local_hops_delta = 5;
        let mut engine = TransportEngine::new(config);
        engine.register_interface(make_local_client_interface(1));
        engine.register_interface(make_interface(2, constants::MODE_FULL));
        let link_id = [0x4F; 16];
        // A network node on 2 asked for a link to the local client on 1.
        engine.register_link(
            link_id,
            LinkEntry {
                validated: false,
                remaining_hops: 0,
                taken_hops: 1,
                ..relayed_link(1, 2)
            },
        );
        let actions = receive(&mut engine, &lrproof(&link_id, 0), 1);
        let raw = sent_on(&actions, 2).expect("proof relayed");
        assert_eq!(raw[1], 5);
    }

    /// As upstream, a shared instance without transport routes a proof
    /// back over its reverse table when the proven packet came from or goes
    /// to one of its local clients.
    #[test]
    fn shared_instance_routes_proofs_for_its_local_clients() {
        let proof = packet(
            flags(
                constants::HEADER_1,
                constants::DESTINATION_SINGLE,
                constants::PACKET_TYPE_PROOF,
            ),
            0,
            &[0x50; 16],
            None,
            constants::CONTEXT_NONE,
        );
        // (reverse entry receiving, outbound, proof arrives on, relayed to)
        for (receiving, outbound, arrives, relayed) in [(1, 2, 2, 1), (2, 1, 1, 2)] {
            let mut config = make_config(false);
            config.identity_hash = Some(OUR_ID);
            let mut engine = TransportEngine::new(config);
            engine.register_interface(make_local_client_interface(1));
            engine.register_interface(make_interface(2, constants::MODE_FULL));
            engine.reverse_table.insert(
                [0x50; 16],
                ReverseEntry {
                    receiving_interface: InterfaceId(receiving),
                    outbound_interface: InterfaceId(outbound),
                    timestamp: 1000.0,
                },
            );
            let actions = receive(&mut engine, &proof, arrives);
            assert!(sent_on(&actions, relayed).is_some(), "arrives on {arrives}");
        }
    }
}

#[cfg(test)]
mod local_client_announce_tests {
    use super::*;
    use crate::announce::AnnounceData;
    use crate::destination::{destination_hash, name_hash};
    use crate::packet::PacketFlags;
    use crate::transport::tests::{make_config, make_interface, make_local_client_interface};

    /// A signed announce, ratcheted or not, sent as `header_type` with
    /// `hops`, for `identity_seed`'s destination.
    fn announce(identity_seed: u8, ratchet: bool, header_type: u8, hops: u8) -> RawPacket {
        announce_in_context(
            identity_seed,
            ratchet,
            header_type,
            hops,
            constants::CONTEXT_NONE,
        )
    }

    /// [`announce`] in `context`.
    pub(super) fn announce_in_context(
        identity_seed: u8,
        ratchet: bool,
        header_type: u8,
        hops: u8,
        context: u8,
    ) -> RawPacket {
        let identity = rns_crypto::identity::Identity::from_private_key(&[identity_seed; 64]);
        let dest_hash = destination_hash("forward", &["test"], Some(identity.hash()));
        let ratchet_key = [0x3C; 32];
        let (data, _) = AnnounceData::pack(
            &identity,
            &dest_hash,
            &name_hash("forward", &["test"]),
            &[0x5C; 10],
            ratchet.then_some(&ratchet_key),
            None,
        )
        .unwrap();
        let h2 = header_type == constants::HEADER_2;
        RawPacket::pack(
            PacketFlags {
                header_type,
                context_flag: if ratchet {
                    constants::FLAG_SET
                } else {
                    constants::FLAG_UNSET
                },
                transport_type: if h2 {
                    constants::TRANSPORT_TRANSPORT
                } else {
                    constants::TRANSPORT_BROADCAST
                },
                destination_type: constants::DESTINATION_SINGLE,
                packet_type: constants::PACKET_TYPE_ANNOUNCE,
            },
            hops,
            &dest_hash,
            h2.then_some(&[0x29; 16]),
            context,
            &data,
        )
        .unwrap()
    }

    /// As upstream, an announce passed on to local clients is rebuilt as a
    /// HEADER_2 transport packet from this node, with the hops it arrived
    /// with and its context flag, which marks a ratchet.
    #[test]
    fn announce_for_local_clients_is_sent_on_from_this_transport() {
        for (seed, ratchet, header_type) in [
            (1, false, constants::HEADER_1),
            (2, true, constants::HEADER_1),
            (3, true, constants::HEADER_2),
        ] {
            let mut engine = TransportEngine::new(make_config(true));
            engine.register_interface(make_interface(1, constants::MODE_FULL));
            engine.register_interface(make_local_client_interface(2));
            let announce = announce(seed, ratchet, header_type, 2);
            let mut rng = rns_crypto::FixedRng::new(&[0x77; 32]);
            let actions = engine.handle_inbound(
                InboundFrame::new(&announce.raw, InterfaceId(1), 1000.0),
                &mut rng,
            );
            let raw = actions
                .iter()
                .find_map(|action| match action {
                    TransportAction::ForwardToLocalClients { raw, .. } => Some(raw),
                    _ => None,
                })
                .expect("announce passed on to local clients");
            let forwarded = RawPacket::unpack(raw).unwrap();
            assert_eq!(forwarded.flags.header_type, constants::HEADER_2);
            assert_eq!(
                forwarded.flags.transport_type,
                constants::TRANSPORT_TRANSPORT
            );
            assert_eq!(forwarded.flags.context_flag, announce.flags.context_flag);
            assert_eq!(
                forwarded.flags.destination_type,
                constants::DESTINATION_SINGLE
            );
            assert_eq!(forwarded.flags.packet_type, constants::PACKET_TYPE_ANNOUNCE);
            assert_eq!(forwarded.hops, 3);
            assert_eq!(forwarded.transport_id, Some([0x42; 16]));
            assert_eq!(forwarded.destination_hash, announce.destination_hash);
            assert_eq!(forwarded.data(), announce.data());
        }
    }
}
