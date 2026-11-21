//! Frames from interfaces: admitting, classifying and handing them to
//! the transport engine, and verified announces.

use super::*;

impl Driver {
    #[cfg(test)]
    pub(crate) fn handle_frame_event(
        &mut self,
        interface_id: InterfaceId,
        data: Vec<u8>,
        rssi: Option<i16>,
        snr: Option<f32>,
    ) {
        self.handle_classified_frame_event(interface_id, data.into(), rssi, snr, false);
    }

    /// Reclassify a received frame as filtered: one dropped where upstream's
    /// `preprocess_inbound` drops it (134dc677). Since upstream 01e7ed84,
    /// `Transport.inbound` charges each frame once, to `rxb` through
    /// `accepted_inbound` or to `frxb` through `filtered_inbound`. rns-rs
    /// counts the frame as received on arrival and moves it here, which gives
    /// the same split. Upstream counts a packet in `rx_packets` only once it
    /// passes, so it leaves that count too.
    pub(crate) fn record_filtered_inbound(&mut self, interface_id: InterfaceId, size: usize) {
        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
            let size = size as u64;
            entry.stats.rxb = entry.stats.rxb.saturating_sub(size);
            entry.stats.frxb = entry.stats.frxb.saturating_add(size);
            entry.stats.rx_packets = entry.stats.rx_packets.saturating_sub(1);
        }
    }

    /// Count the announces the engine received, as upstream's
    /// `received_announce` does: in `arxc` and `arxb`, and as a sample of
    /// the incoming announce frequency. The engine reports a valid announce
    /// with its bytes, and one ingress control or the prefilter took up
    /// without (upstream c850cdac).
    pub(crate) fn record_announce_receipts(&mut self) {
        let now = time::now();
        for (interface_id, size) in self.engine.take_announce_receipts() {
            if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                entry.stats.record_incoming_announce_bytes(now, size);
            }
        }
    }

    /// Charge the frames of held announces that ingress control released
    /// during a tick. Since upstream 29dc449a a release goes through
    /// `Transport.inbound` with accounting: its bytes count again, in `rxb`
    /// and as a received packet when preprocessing accepts it, and in `frxb`
    /// when it drops it, and a filtered announce counts in `afrxc`.
    pub(crate) fn record_released_traffic(&mut self) {
        for released in self.engine.take_released_traffic() {
            if let Some(entry) = self.interfaces.get_mut(&released.interface) {
                let size = released.size as u64;
                if released.filtered {
                    entry.stats.frxb = entry.stats.frxb.saturating_add(size);
                } else {
                    entry.stats.rxb = entry.stats.rxb.saturating_add(size);
                    entry.stats.rx_packets = entry.stats.rx_packets.saturating_add(1);
                }
                if released.filtered_announce {
                    entry.stats.afrxc = entry.stats.afrxc.saturating_add(1);
                }
            }
        }
    }

    /// Count a filtered announce on the receiving interface (upstream
    /// 819076c3 `Interface.filtered_announce`). Upstream also adds it to a
    /// spawned interface's parent; a listener's row sums its children.
    pub(crate) fn record_filtered_announce(&mut self, interface_id: InterfaceId) {
        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
            entry.stats.afrxc = entry.stats.afrxc.saturating_add(1);
        }
    }

    /// Inbound admission checks that run on a decoded packet before the
    /// `PreIngress` hook. They count protocol violations and packet filter hits
    /// on the receiving interface and return whether the packet may proceed.
    pub(super) fn admit_decoded_inbound(
        &mut self,
        interface_id: InterfaceId,
        packet_len: usize,
        decoded: &DecodedPacket,
    ) -> bool {
        let parsed_packet = decoded.packet();
        let is_announce =
            parsed_packet.flags.packet_type == rns_core::constants::PACKET_TYPE_ANNOUNCE;
        if is_announce && packet_len > rns_core::constants::MTU {
            if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                entry.stats.protocol_violations += 1;
            }
            return false;
        }
        // Upstream 715707b1: a HEADER_1 announce without room for the
        // transport id a transport node would insert is a protocol
        // violation (an announce built since d077d1ab always has it).
        if is_announce
            && parsed_packet.flags.header_type == rns_core::constants::HEADER_1
            && packet_len + rns_core::constants::TRUNCATED_HASHLENGTH / 8 > rns_core::constants::MTU
        {
            if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                entry.stats.protocol_violations += 1;
            }
            log::debug!(
                "Protocol violation on interface {}: Excessive announce payload of {} bytes",
                interface_id.0,
                parsed_packet.data().len()
            );
            return false;
        }
        // Upstream 096e6726: an announce payload shorter than a public key,
        // a name hash and a random hash is a protocol violation, checked
        // before the destination type filter reads the name hash.
        let announce_min =
            rns_core::constants::KEYSIZE / 8 + rns_core::constants::NAME_HASH_LENGTH / 8 + 10;
        if is_announce && parsed_packet.data().len() < announce_min {
            if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                entry.stats.protocol_violations += 1;
            }
            log::debug!(
                "Protocol violation on interface {}: Insufficient announce payload of {} bytes",
                interface_id.0,
                parsed_packet.data().len()
            );
            return false;
        }
        let is_path_request = parsed_packet.destination_hash == self.builtin.path_request;
        // Upstream drops a path request shorter than a destination hash
        // without counting a protocol violation.
        if is_path_request
            && parsed_packet.data().len() < rns_core::constants::TRUNCATED_HASHLENGTH / 8
        {
            return false;
        }
        let tagless_path_request = is_path_request && parsed_packet.data().len() <= 16;
        if tagless_path_request || self.engine.is_unvalidated_link_packet(parsed_packet) {
            if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                entry.stats.protocol_violations += 1;
            }
            if tagless_path_request {
                // Logged on the pathing target since upstream ecd677ba.
                log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                    "Protocol violation on interface {}: Tagless path request",
                    interface_id.0
                );
            }
            return false;
        }
        // Upstream cda4d72b: a tagged path request of any length other than
        // the legacy, unstamped or stamped one is a protocol violation and is
        // dropped (before, only a 49 to 63 byte one counted, and it was still
        // processed).
        let path_request_len = parsed_packet.data().len();
        if is_path_request && !rns_core::constants::is_valid_path_request_length(path_request_len) {
            if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                entry.stats.protocol_violations += 1;
            }
            if path_request_len > rns_core::constants::PATH_REQUEST_STAMPED_LENGTH {
                log::debug!(
                    "Protocol violation on interface {}: Excessive path request size of {} bytes",
                    interface_id.0,
                    path_request_len
                );
            } else {
                // Logged on the pathing target since upstream ecd677ba.
                log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                    "Protocol violation on interface {}: Invalid path request size {}",
                    interface_id.0,
                    path_request_len
                );
            }
            return false;
        }
        if !self.engine.accepts_decoded_packet(decoded, interface_id) {
            if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                if self
                    .engine
                    .is_packet_filter_protocol_violation(parsed_packet, interface_id)
                {
                    entry.stats.protocol_violations += 1;
                } else {
                    entry.stats.packet_filter_hits += 1;
                }
            }
            return false;
        }
        // Upstream 819076c3 dropped f96cef7e's early held-announces-full
        // drop: the limit now applies only while ingress control holds
        // announces, in the engine.
        true
    }

    pub(super) fn handle_classified_frame_event(
        &mut self,
        interface_id: InterfaceId,
        data: PacketBytes,
        rssi: Option<i16>,
        snr: Option<f32>,
        ingress_limited: bool,
    ) {
        let received_size = data.len();
        if data.len() > 2 && (data[0] & 0x03) == 0x01 {
            log::debug!(
                "Announce:frame from iface {} (len={}, flags=0x{:02x})",
                interface_id.0,
                data.len(),
                data[0]
            );
        }
        let Some(entry) = self.interfaces.get(&interface_id) else {
            log::warn!("[{}] dropping frame from unknown interface", interface_id.0);
            return;
        };
        if !entry.enabled || !entry.online {
            return;
        }
        // Where a received frame is counted. Only frames read from an
        // interface arrive here: rns-rs keeps no packet cache to replay into
        // inbound, which upstream d1837919 exempts from accounting. The one
        // frame counted twice is a held announce, filtered when held and
        // counted again on release (`record_released_traffic`, 29dc449a).
        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
            entry.stats.rxb += data.len() as u64;
            entry.stats.rx_packets += 1;
        }

        let packet = if let Some(entry) = self.interfaces.get(&interface_id) {
            if let Some(ref ifac_state) = entry.ifac {
                match ifac::unmask_inbound(&data, ifac_state) {
                    Some(unmasked) => PacketBytes::from(unmasked),
                    None => {
                        log::debug!("[{}] IFAC rejected packet", interface_id.0);
                        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                            entry.stats.ifac_violations += 1;
                        }
                        self.record_filtered_inbound(interface_id, received_size);
                        return;
                    }
                }
            } else {
                if data.len() > 2 && data[0] & 0x80 == 0x80 {
                    log::debug!(
                        "[{}] dropping packet with IFAC flag on non-IFAC interface",
                        interface_id.0
                    );
                    if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                        entry.stats.ifac_violations += 1;
                    }
                    self.record_filtered_inbound(interface_id, received_size);
                    return;
                }
                data
            }
        } else {
            data
        };

        // The decoded packet keeps the frame's bytes as its `raw`.
        let decoded_packet = match self.engine.decode_inbound(packet) {
            Ok(packet) => packet,
            Err(error) => {
                // A malformed packet, including a hop count at or above
                // PATHFINDER_M, which upstream `Packet.unpack` rejects
                // before the hop limiter is consulted (Packet.py:250,
                // Transport.py:2008).
                log::trace!("[{}] malformed packet: {error}", interface_id.0);
                if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                    entry.stats.protocol_violations += 1;
                }
                self.record_filtered_inbound(interface_id, received_size);
                return;
            }
        };
        // `if not packet.hops < Transport.HOP_LIMITER: return
        // interface.hop_limiter_hit()` (Transport.py:2009), before the packet
        // filter, and since upstream bb63dd44 first the same against the
        // interface's own `hop_limiter`. `hop_limiter_hit` returns `None`, so
        // `Transport.inbound` charges the frame to filtered bytes.
        let hops = decoded_packet.packet().hops;
        let interface_limit = self
            .interfaces
            .get(&interface_id)
            .and_then(|entry| entry.info.hop_limiter);
        if interface_limit.is_some_and(|limit| hops >= limit) || hops >= self.hop_limiter {
            if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                entry.stats.hop_limiter_hits += 1;
            }
            self.record_filtered_inbound(interface_id, received_size);
            return;
        }
        if let Some(packet_hash) = decoded_packet.packet_hash() {
            self.engine.prefetch_packet_hash(packet_hash);
            // Transport._inbound: remember the readings of a packet from an
            // interface that reports them, for get_packet_rssi/snr/q.
            if rssi.is_some() || snr.is_some() {
                let q = self
                    .interfaces
                    .get(&interface_id)
                    .and_then(|entry| entry.stats.signal_quality);
                self.record_packet_signal(
                    *packet_hash,
                    crate::event::PacketSignal { rssi, snr, q },
                );
            }
        }
        let packet_len = decoded_packet.packet().raw.len();
        if !self.admit_decoded_inbound(interface_id, packet_len, &decoded_packet) {
            self.record_filtered_inbound(interface_id, received_size);
            return;
        }

        let decoded_packet = if !self.hooks.attached(HookPoint::PreIngress) {
            decoded_packet
        } else {
            let outcome = self.run_packet_hooks(
                HookPoint::PreIngress,
                &HookEvent::wire_packet(&decoded_packet.packet().raw, interface_id.0),
                InjectedActions::Dispatch,
                |driver| driver.hook_packet_limit(interface_id),
            );
            // A packet the hook drops is filtered inbound, as any other
            // packet dropped before transport processes it.
            match outcome {
                PacketHookOutcome::Keep => decoded_packet,
                PacketHookOutcome::Drop => {
                    self.record_filtered_inbound(interface_id, received_size);
                    return;
                }
                PacketHookOutcome::Replace(replacement) => {
                    // Decode the replacement afresh and hold it to the same
                    // admission checks as a received packet.
                    let replacement_len = replacement.raw.len();
                    let Ok(decoded) = DecodedPacket::unpack_owned(replacement.raw) else {
                        self.record_filtered_inbound(interface_id, received_size);
                        return;
                    };
                    if !self.admit_decoded_inbound(interface_id, replacement_len, &decoded) {
                        self.record_filtered_inbound(interface_id, received_size);
                        return;
                    }
                    decoded
                }
            }
        };

        if let Some(entry) = self.interfaces.get(&interface_id) {
            let now = time::now();
            super::sync_interface_frequencies(
                &mut self.engine,
                interface_id,
                entry.stats.frequencies(now),
            );
        }

        // A relay can only accept a hop-count change after validating the
        // LRPROOF against the announced destination identity. Supplying the
        // key here keeps identity lifecycle state in the driver while the
        // transport engine owns the route mutation.
        if let Some((link_id, destination_hash, packet_hops, proof_data)) = self
            .engine
            .decoded_lrproof_rebalance_candidate(&decoded_packet, interface_id)
        {
            if let Some(announced) = self.known.announced(&destination_hash) {
                let mut sig_pub = [0u8; 32];
                sig_pub.copy_from_slice(&announced.public_key[32..64]);
                if self.engine.rebalance_link_path_from_lrproof(
                    &link_id,
                    packet_hops,
                    interface_id,
                    &proof_data,
                    &sig_pub,
                ) {
                    log::log!(
                        target: crate::logging::PATHING_LOG_TARGET,
                        crate::logging::REBALANCE_LOG_LEVEL,
                        "Re-balanced path to {:02x?} from link-request proof",
                        &destination_hash[..4],
                    );
                }
            }
        }

        // Transport.py transports a link request proof only once it verifies
        // against the destination's identity, and drops it when the identity
        // cannot be recalled; a valid one proves the destination alive.
        if let Some((link_id, destination_hash, _, proof_data)) = self
            .engine
            .decoded_transported_lrproof(&decoded_packet, interface_id)
        {
            let valid = self
                .known
                .announced(&destination_hash)
                .is_some_and(|announced| {
                    let mut sig_pub = [0u8; 32];
                    sig_pub.copy_from_slice(&announced.public_key[32..64]);
                    rns_core::transport::TransportEngine::lrproof_is_valid(
                        &link_id,
                        &proof_data,
                        &sig_pub,
                    )
                });
            self.engine.set_lrproof_verdict(link_id, valid);
            if valid && !self.connected_to_shared_instance {
                self.known.mark_used(&destination_hash);
            }
        }

        // The engine consumes the packet; the hooks after it need the bytes.
        let dispatch_hook_packet = self
            .hooks
            .attached(HookPoint::PreDispatch)
            .then(|| decoded_packet.packet().raw.clone());
        let inbound_frame = DecodedInboundFrame {
            decoded: decoded_packet,
            iface: interface_id,
            now: time::now(),
            rx: RxMetadata { rssi, snr },
        };

        let mut actions = self.transport_actions.take();
        if self.announce_verify.async_enabled {
            let mut announce_queue = crate::sync::lock_or_recover(
                &self.announce_verify.queue,
                "inbound announce verify queue",
            );
            let queued = announce_queue.len();
            self.engine.handle_decoded_inbound_into(
                inbound_frame,
                &mut self.rng,
                Some(&mut announce_queue),
                &mut actions,
            );
            if announce_queue.len() > queued {
                if crate::engine::FOLD_WORK {
                    self.folded.announces_queued = true;
                } else {
                    self.announce_verify.signal.notify();
                }
            }
        } else {
            self.engine.handle_decoded_inbound_into(
                inbound_frame,
                &mut self.rng,
                None,
                &mut actions,
            );
        }

        if let Some(packet) = dispatch_hook_packet {
            // The engine has already handled this packet, so neither `Drop`
            // nor `Modify` can change it any more: both act as `Continue` here
            // and the replacement bytes of a `Modify` verdict are ignored.
            self.run_hooks_with_effects(
                HookPoint::PreDispatch,
                &HookEvent::wire_packet(&packet, interface_id.0),
                InjectedActions::Dispatch,
            );
        }

        self.dispatch_all_with_ingress_class(actions, ingress_limited);
        // The engine drops, and the path request its actions delivered.
        if self.engine.take_inbound_filtered() {
            self.record_filtered_inbound(interface_id, received_size);
        }
        if self.engine.take_inbound_filtered_announce() {
            self.record_filtered_announce(interface_id);
        }
        self.record_announce_receipts();
        let bursts = (
            self.engine
                .burst_active(&interface_id)
                .then(|| self.engine.burst_activated(&interface_id)),
            self.engine
                .pr_burst_active(&interface_id)
                .then(|| self.engine.pr_burst_activated(&interface_id)),
        );
        // Publishing takes the shared event-queue lock that every interface
        // reader also needs, so only publish when the burst state changed.
        if self.published_ingress_bursts.get(&interface_id) != Some(&bursts) {
            self.event_tx
                .set_ingress_bursts(interface_id, bursts.0, bursts.1);
            self.published_ingress_bursts.insert(interface_id, bursts);
        }
    }

    pub(crate) fn handle_announce_verify_failed(
        &mut self,
        key: rns_core::transport::announce_verify_queue::AnnounceVerifyKey,
    ) {
        let mut announce_queue = crate::sync::lock_or_recover(
            &self.announce_verify.queue,
            "inbound announce verify queue",
        );
        let interface = announce_queue.pending_interface(&key);
        let size = announce_queue.pending_size(&key).unwrap_or(0);
        let blackholed = announce_queue
            .pending_identity_hash(&key)
            .is_some_and(|hash| self.engine.is_blackholed(&hash, time::now()));
        if announce_queue.complete_failure(&key) {
            drop(announce_queue);
            if let Some(id) = interface {
                if let Some(entry) = self.interfaces.get_mut(&id) {
                    if !blackholed {
                        entry.stats.protocol_violations += 1;
                    }
                }
                // Upstream checks the signature before the packet passes
                // `preprocess_inbound`, so a failed one is filtered (134dc677).
                self.record_filtered_inbound(id, size);
            }
        }
    }

    pub(crate) fn handle_announce_verified_event(
        &mut self,
        key: rns_core::transport::announce_verify_queue::AnnounceVerifyKey,
        validated: rns_core::announce::ValidatedAnnounce,
        sig_cache_key: [u8; 32],
    ) {
        let pending = {
            let mut announce_queue = crate::sync::lock_or_recover(
                &self.announce_verify.queue,
                "inbound announce verify queue",
            );
            announce_queue.complete_success(&key)
        };
        if let Some(pending) = pending {
            let interface = pending.interface;
            let received_size = pending.original_raw.len();
            // Ingress control judges the announce by the ones received
            // before it.
            let now = time::now();
            if let Some(entry) = self.interfaces.get(&interface) {
                super::sync_interface_frequencies(
                    &mut self.engine,
                    interface,
                    entry.stats.frequencies(now),
                );
            }
            let actions = self.engine.complete_verified_announce(
                pending,
                validated,
                sig_cache_key,
                time::now(),
                &mut self.rng,
            );
            self.record_announce_receipts();
            // A blackholed identity or a failed stamp (134dc677).
            if self.engine.take_inbound_filtered() {
                self.record_filtered_inbound(interface, received_size);
            }
            if self.engine.take_inbound_filtered_announce() {
                self.record_filtered_announce(interface);
            }
            self.dispatch_all(actions);
        }
    }
}
