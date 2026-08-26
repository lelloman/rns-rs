use super::*;

pub(super) fn extra_link_proof_timeout(interface: Option<&InterfaceInfo>) -> f64 {
    interface
        .and_then(|interface| interface.bitrate)
        .filter(|bitrate| *bitrate > 0)
        .map_or(0.0, |bitrate| {
            (constants::MTU as f64 * 8.0) / bitrate as f64
        })
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
        let Some(ctx) = self.prepare_inbound_packet(frame) else {
            return Vec::new();
        };
        let mut actions = Vec::new();

        self.remember_inbound_packet_hash(&ctx.packet);
        self.bridge_plain_broadcast(&ctx, &mut actions);
        self.handle_transport_forwarding(&ctx, &mut actions);
        self.handle_link_table_routing(&ctx, &mut actions);
        self.handle_inbound_announce(&ctx, rng, announce_queue, &mut actions);

        if ctx.packet.flags.packet_type == constants::PACKET_TYPE_PROOF {
            self.process_inbound_proof(&ctx, &mut actions);
        }

        self.handle_inbound_local_delivery(&ctx, &mut actions);
        actions
    }

    pub(super) fn prepare_inbound_packet(
        &self,
        frame: InboundFrame<'_>,
    ) -> Option<InboundPacketCtx> {
        let mut packet = RawPacket::unpack(frame.raw).ok()?;
        let from_local_client = self
            .interfaces
            .get(&frame.iface)
            .map(|i| i.is_local_client)
            .unwrap_or(false);
        packet.hops = packet.hops.checked_add(1)?;
        packet.rssi = frame.rx.rssi;
        packet.snr = frame.rx.snr;
        if from_local_client {
            packet.hops = packet.hops.saturating_sub(1);
        }
        if !self.packet_filter(&packet) {
            return None;
        }
        let retain_original_raw = packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE;
        Some(InboundPacketCtx {
            packet,
            original_raw: if retain_original_raw {
                Some(frame.raw.to_vec())
            } else {
                None
            },
            iface: frame.iface,
            now: frame.now,
            from_local_client,
        })
    }

    fn remember_inbound_packet_hash(&mut self, packet: &RawPacket) {
        let remember_hash = !(self.link_table.contains_key(&packet.destination_hash)
            || (packet.flags.packet_type == constants::PACKET_TYPE_PROOF
                && packet.context == constants::CONTEXT_LRPROOF));
        if remember_hash {
            self.packet_hashlist.add(packet.packet_hash);
        }
    }

    fn bridge_plain_broadcast(&self, ctx: &InboundPacketCtx, actions: &mut Vec<TransportAction>) {
        if ctx.packet.flags.destination_type != constants::DESTINATION_PLAIN
            || ctx.packet.flags.transport_type != constants::TRANSPORT_BROADCAST
            || !self.has_local_clients()
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
        if ctx.packet.transport_id.is_none()
            || ctx.packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE
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
        if ctx.packet.transport_id != Some(identity_hash) {
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

        if let Some(entry) = self
            .path_table
            .get_mut(&ctx.packet.destination_hash)
            .and_then(|ps| ps.primary_mut())
        {
            entry.timestamp = ctx.now;
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
        let Some((outbound_iface, new_raw)) = route_via_link_table(
            &ctx.packet,
            &link_entry,
            ctx.iface,
            LocalHopRewrite {
                local_hops_delta: self.config.local_hops_delta,
                from_local_client: ctx.from_local_client,
                skip_local_hops_delta: instance_local_link,
            },
        ) else {
            return;
        };

        self.packet_hashlist.add(ctx.packet.packet_hash);
        actions.push(TransportAction::SendOnInterface {
            interface: outbound_iface,
            raw: new_raw.into(),
        });

        if let Some(entry) = self.link_table.get_mut(&ctx.packet.destination_hash) {
            entry.timestamp = ctx.now;
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
            && self
                .local_destinations
                .contains_key(&ctx.packet.destination_hash)
        {
            let mut delivery_raw = ctx.packet.raw.clone();
            // Link responders learn the post-ingress hop metric from the
            // authenticated LRRTT packet. Preserve that field when crossing
            // the action boundary without changing ordinary callback bytes.
            if ctx.packet.context == constants::CONTEXT_LRRTT && delivery_raw.len() >= 2 {
                delivery_raw[1] = ctx.packet.hops;
            }
            actions.push(TransportAction::DeliverLocal {
                destination_hash: ctx.packet.destination_hash,
                raw: PacketBytes::from(delivery_raw),
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
        packet: &RawPacket,
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
        let announce = match AnnounceData::unpack(&packet.data, has_ratchet) {
            Ok(a) => a,
            Err(_) => {
                actions.push(TransportAction::ProtocolViolation { interface: iface });
                return;
            }
        };

        if self.should_hold_announce(packet, original_raw, iface, now) {
            return;
        }

        let sig_cache_key =
            Self::announce_sig_cache_key(packet.destination_hash, &announce.signature);

        let validated = if self.announce_sig_cache.contains(&sig_cache_key) {
            announce.to_validated_unchecked()
        } else {
            match announce.validate(&packet.destination_hash) {
                Ok(v) => {
                    self.announce_sig_cache.insert(sig_cache_key, now);
                    v
                }
                Err(_) => {
                    self.record_invalid_announce(&announce, iface, now, actions);
                    return;
                }
            }
        };

        let received_from = self.announce_received_from(packet, now);
        let random_blob = match extract_random_blob(&packet.data) {
            Some(b) => b,
            None => {
                actions.push(TransportAction::ProtocolViolation { interface: iface });
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

    fn announce_raw_for_local_clients(&self, packet: &RawPacket) -> PacketBytes {
        let Some(identity_hash) = self.config.identity_hash else {
            return PacketBytes::from(packet.raw.clone());
        };

        if packet.raw.len() < 2 {
            return PacketBytes::from(packet.raw.clone());
        }

        let payload_start = if packet.flags.header_type == constants::HEADER_2 {
            18usize
        } else {
            2usize
        };
        if packet.raw.len() < payload_start {
            return PacketBytes::from(packet.raw.clone());
        }

        let flags = (constants::HEADER_2 << 6)
            | (constants::TRANSPORT_TRANSPORT << 4)
            | (packet.raw[0] & 0x0F);
        let mut raw = Vec::with_capacity(18 + packet.raw.len() - payload_start);
        raw.push(flags);
        raw.push(packet.hops);
        raw.extend_from_slice(&identity_hash);
        raw.extend_from_slice(&packet.raw[payload_start..]);
        PacketBytes::from(raw)
    }

    pub(super) fn announce_sig_cache_key(
        destination_hash: [u8; 16],
        signature: &[u8; 64],
    ) -> [u8; 32] {
        let mut material = [0u8; 80];
        material[..16].copy_from_slice(&destination_hash);
        material[16..].copy_from_slice(signature);
        hash::full_hash(&material)
    }

    fn announce_received_from(&mut self, packet: &RawPacket, now: f64) -> [u8; 16] {
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

    fn should_hold_announce(
        &mut self,
        packet: &RawPacket,
        original_raw: &[u8],
        iface: InterfaceId,
        now: f64,
    ) -> bool {
        if self.has_path(&packet.destination_hash) {
            return false;
        }
        if self
            .discovery_path_requests
            .contains_key(&packet.destination_hash)
        {
            return false;
        }
        let Some(info) = self.interfaces.get(&iface) else {
            return false;
        };
        if packet.context == constants::CONTEXT_PATH_RESPONSE
            || !self.ingress_control.should_ingress_limit(
                iface,
                &info.ingress_control,
                info.ia_freq,
                info.started,
                now,
            )
        {
            return false;
        }
        self.ingress_control.hold_announce(
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
        true
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
        let announce = match AnnounceData::unpack(&ctx.packet.data, has_ratchet) {
            Ok(a) => a,
            Err(_) => {
                actions.push(TransportAction::ProtocolViolation {
                    interface: ctx.iface,
                });
                return;
            }
        };

        let received_from = self.announce_received_from(&ctx.packet, ctx.now);

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
        if self.should_hold_announce(&ctx.packet, original_raw, ctx.iface, ctx.now) {
            return;
        }

        let sig_cache_key =
            Self::announce_sig_cache_key(ctx.packet.destination_hash, &announce.signature);
        if self.announce_sig_cache.contains(&sig_cache_key) {
            let validated = announce.to_validated_unchecked();
            let random_blob = match extract_random_blob(&ctx.packet.data) {
                Some(b) => b,
                None => return,
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

        if ctx.packet.context == constants::CONTEXT_PATH_RESPONSE {
            let Ok(validated) = announce.validate(&ctx.packet.destination_hash) else {
                self.record_invalid_announce(&announce, ctx.iface, ctx.now, actions);
                return;
            };
            self.announce_sig_cache.insert(sig_cache_key, ctx.now);
            let random_blob = match extract_random_blob(&ctx.packet.data) {
                Some(b) => b,
                None => return,
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

        let random_blob = match extract_random_blob(&ctx.packet.data) {
            Some(b) => b,
            None => {
                actions.push(TransportAction::ProtocolViolation {
                    interface: ctx.iface,
                });
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
        ctx: VerifiedAnnounceCtx<'_>,
        rng: &mut dyn Rng,
        actions: &mut Vec<TransportAction>,
    ) {
        if self.is_blackholed(&ctx.validated.identity_hash, ctx.now) {
            return;
        }
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

        let (path_entry, announce_entry) = announce_proc::process_validated_announce(
            ctx.packet.destination_hash,
            ctx.packet.hops,
            &ctx.packet.data,
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
            is_path_response,
            rate_blocked,
            Some(ctx.original_raw.to_vec()),
        );

        // Emit CacheAnnounce for disk caching (pre-hop-increment raw)
        actions.push(TransportAction::CacheAnnounce {
            packet_hash: ctx.packet.packet_hash,
            raw: ctx.original_raw.to_vec().into(),
        });

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
            let blobs = self
                .path_table
                .get(&ctx.packet.destination_hash)
                .and_then(|ps| ps.find_by_next_hop(&ctx.received_from))
                .map(|e| e.random_blobs.clone())
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
        }

        // Emit actions
        actions.push(TransportAction::AnnounceReceived {
            destination_hash: ctx.packet.destination_hash,
            identity_hash: ctx.validated.identity_hash,
            public_key: ctx.validated.public_key,
            name_hash: ctx.validated.name_hash,
            random_hash: ctx.validated.random_hash,
            ratchet: ctx.validated.ratchet,
            app_data: ctx.validated.app_data,
            hops: ctx.packet.hops,
            receiving_interface: ctx.iface,
            rx: RxMetadata {
                rssi: ctx.packet.rssi,
                snr: ctx.packet.snr,
            },
        });

        actions.push(TransportAction::PathUpdated {
            destination_hash: ctx.packet.destination_hash,
            hops: ctx.packet.hops,
            next_hop: ctx.received_from,
            interface: ctx.iface,
        });

        // Forward announce to local clients if any are connected
        if self.has_local_clients() {
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
                packet_raw: ctx.packet.raw.clone(),
                packet_data: ctx.packet.data.clone(),
                destination_hash: ctx.packet.destination_hash,
                context_flag: ctx.packet.flags.context_flag,
                local_rebroadcasts: 0,
                block_rebroadcasts: true,
                attached_interface: requesting_interfaces.first().copied(),
            };
            if let Some(identity_hash) = self.config.identity_hash {
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
            // Link request proof routing
            if (self.config.transport_enabled)
                && self.link_table.contains_key(&packet.destination_hash)
            {
                let link_entry = self.link_table.get(&packet.destination_hash).cloned();
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
                        // Forward the proof (simplified: skip signature validation
                        // which requires Identity recall)

                        // Mark link as validated
                        if let Some(le) = self.link_table.get_mut(&packet.destination_hash) {
                            le.validated = true;
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
                let mut delivery_raw = packet.raw.clone();
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
            // Regular proof: check reverse table
            if self.config.transport_enabled {
                if let Some(reverse_entry) = self.reverse_table.remove(&packet.destination_hash) {
                    let proof_for_local_client =
                        self.interface_is_local_client(reverse_entry.receiving_interface);
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
                raw: PacketBytes::from(packet.raw.clone()),
                packet_hash: packet.packet_hash,
                receiving_interface: ctx.iface,
            });
        }
    }
}
