//! Inbound announces: filtering, rate limiting and queueing them for
//! verification.

use super::*;

impl TransportEngine {
    pub(super) fn handle_inbound_announce(
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
            // The wire bytes are never rewritten inbound: hops change only
            // in the decoded header, so `raw` is the announce as received.
            self.process_inbound_announce(
                &ctx.packet,
                &ctx.packet.raw,
                ctx.iface,
                ctx.now,
                rng,
                actions,
            );
        }
    }

    pub(super) fn process_inbound_announce(
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
                self.accounting.inbound_filtered = true;
                return;
            }
        };

        if self.prefilter_announce(packet, iface, now) {
            return;
        }

        let sig_cache_key = Self::announce_sig_cache_key(&packet.destination_hash, &announce);

        let validated = if self.announces.sig_cache.contains(&sig_cache_key) {
            announce.to_validated_with_cached_signature(&packet.destination_hash)
        } else {
            announce.validate(&packet.destination_hash).inspect(|_| {
                self.announces.sig_cache.insert(sig_cache_key, now);
            })
        };
        let validated = match validated {
            Ok(v) => v,
            Err(_) => {
                self.record_invalid_announce(&announce, iface, now, actions);
                self.accounting.inbound_filtered = true;
                return;
            }
        };

        let received_from = self.announce_received_from(packet, now);
        let random_blob = match extract_random_blob(packet.data()) {
            Some(b) => b,
            None => {
                actions.push(TransportAction::ProtocolViolation { interface: iface });
                self.accounting.inbound_filtered = true;
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

    pub(super) fn announce_raw_for_local_clients(
        &self,
        packet: &RawPacket<PacketBytes>,
    ) -> PacketBytes {
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
        let Some(payload) = packet.raw.get(payload_start..) else {
            return packet.raw.clone();
        };

        // As upstream, the context flag is kept: it tells the client the
        // announce carries a ratchet.
        let flags = (constants::HEADER_2 << 6)
            | (packet.flags.context_flag << 5)
            | (constants::TRANSPORT_TRANSPORT << 4)
            | (packet.raw_flags() & 0x0F);
        let mut raw = Vec::with_capacity(18 + payload.len());
        raw.push(flags);
        raw.push(packet.hops);
        raw.extend_from_slice(&identity_hash);
        raw.extend_from_slice(payload);
        PacketBytes::from(raw)
    }

    /// Signature cache key for an announce: covers the full signed data
    /// (see [`AnnounceData::signature_cache_key`]) plus the signature.
    pub(in crate::transport) fn announce_sig_cache_key(
        destination_hash: &[u8; 16],
        announce: &AnnounceData,
    ) -> [u8; 32] {
        announce.signature_cache_key(destination_hash)
    }

    pub(super) fn announce_received_from<B: AsRef<[u8]>>(
        &mut self,
        packet: &RawPacket<B>,
        now: f64,
    ) -> [u8; 16] {
        if let Some(transport_id) = packet.transport_id {
            if self.config.transport_enabled {
                if let Some(announce_entry) = self.announces.table.get_mut(&packet.destination_hash)
                {
                    if packet.hops.checked_sub(1) == Some(announce_entry.hops) {
                        announce_entry.local_rebroadcasts += 1;
                        if announce_entry.retries > 0
                            && announce_entry.local_rebroadcasts
                                >= constants::LOCAL_REBROADCASTS_MAX
                        {
                            self.announces.table.remove(&packet.destination_hash);
                        }
                    }
                    if let Some(announce_entry) = self.announces.table.get(&packet.destination_hash)
                    {
                        if packet.hops.checked_sub(1) == Some(announce_entry.hops + 1)
                            && announce_entry.retries > 0
                            && now < announce_entry.retransmit_timeout
                        {
                            self.announces.table.remove(&packet.destination_hash);
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
    pub(super) fn prefilter_announce<B: AsRef<[u8]>>(
        &mut self,
        packet: &RawPacket<B>,
        iface: InterfaceId,
        now: f64,
    ) -> bool {
        let destination_hash = &packet.destination_hash;
        if packet.context == constants::CONTEXT_PATH_RESPONSE
            || !self.paths.table.contains_key(destination_hash)
            || self.path_requests.gates.contains_key(destination_hash)
            || self.path_requests.discovery.contains_key(destination_hash)
            || self.announces.table.contains_key(destination_hash)
        {
            return false;
        }
        if crate::transport::maintenance::announce_passes_prefilter(
            &self.config,
            &self.paths,
            &self.interfaces,
            destination_hash,
            packet.data(),
            iface,
            now,
        ) {
            return false;
        }
        self.accounting.announce_receipts.push((iface, 0));
        self.filter_announce();
        true
    }

    /// Whether a waiting path request or a known path exempts an announce
    /// from ingress limiting.
    pub(super) fn ingress_exempt(&self, destination_hash: &[u8; 16]) -> bool {
        if self.has_path(destination_hash) {
            return true;
        }
        // Waiting path requests, local or for discovery, skip ingress
        // limiting (upstream logs this at pathing level since daec67a1).
        if self.path_requests.gates.contains_key(destination_hash)
            || self.path_requests.discovery.contains_key(destination_hash)
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
    pub(super) fn ingress_limited<B: AsRef<[u8]>>(
        &mut self,
        packet: &RawPacket<B>,
        iface: InterfaceId,
        now: f64,
    ) -> bool {
        if self.ingress_exempt(&packet.destination_hash) {
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
    pub(super) fn hold_decision<B: AsRef<[u8]>>(
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
        self.accounting.announce_receipts.push((iface, 0));
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
            self.accounting.inbound_filtered = true;
            HoldDecision::Held
        } else {
            HoldDecision::Filtered
        }
    }

    pub(super) fn try_enqueue_announce(
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
                self.accounting.inbound_filtered = true;
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

        // The announce as received: inbound handling never rewrites `raw`.
        let original_raw: &[u8] = &ctx.packet.raw;

        // Upstream processes inbound announces one at a time, in the order
        // they arrive. An announce that would be processed at once, without
        // waiting for verification, waits behind an earlier one for the same
        // destination still being verified: processed first, a shared
        // client's registration path response would have the announce it
        // emitted just before rejected as not newer, and not rebroadcast.
        let behind_queued = announce_queue.has_destination(&ctx.packet.destination_hash);
        let sig_cache_key = Self::announce_sig_cache_key(&ctx.packet.destination_hash, &announce);
        if !behind_queued && self.announces.sig_cache.contains(&sig_cache_key) {
            let Ok(validated) =
                announce.to_validated_with_cached_signature(&ctx.packet.destination_hash)
            else {
                self.record_invalid_announce(&announce, ctx.iface, ctx.now, actions);
                self.accounting.inbound_filtered = true;
                return;
            };
            let random_blob = match extract_random_blob(ctx.packet.data()) {
                Some(b) => b,
                None => {
                    self.accounting.inbound_filtered = true;
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
                self.accounting.inbound_filtered = true;
                return;
            };
            self.announces.sig_cache.insert(sig_cache_key, ctx.now);
            let random_blob = match extract_random_blob(ctx.packet.data()) {
                Some(b) => b,
                None => {
                    self.accounting.inbound_filtered = true;
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
                self.accounting.inbound_filtered = true;
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

    /// Process an announce taken from an [`AnnounceVerifyQueue`] whose signature
    /// verified, caching `sig_cache_key` as verified.
    pub fn complete_verified_announce(
        &mut self,
        pending: PendingAnnounce,
        validated: crate::announce::ValidatedAnnounce,
        sig_cache_key: [u8; 32],
        now: f64,
        rng: &mut dyn Rng,
    ) -> Vec<TransportAction> {
        self.accounting.inbound_filtered = false;
        self.accounting.inbound_filtered_announce = false;
        self.announces.sig_cache.insert(sig_cache_key, now);
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

    /// Whether an announce with this signature cache key was verified recently.
    pub fn announce_sig_cache_contains(&self, sig_cache_key: &[u8; 32]) -> bool {
        self.announces.sig_cache.contains(sig_cache_key)
    }

    /// Check if there's a waiting discovery path request for a destination.
    /// Consumes the request if found (one-shot: the caller queues the announce response).
    pub(in crate::transport) fn discovery_path_requests_waiting(
        &mut self,
        dest_hash: &[u8; 16],
    ) -> Option<Vec<InterfaceId>> {
        let request = self
            .path_requests
            .discovery
            .remove(dest_hash)
            .map(|req| req.requesting_interfaces);
        self.path_requests.discovery_deadlines.remove(dest_hash);
        request
    }
}
