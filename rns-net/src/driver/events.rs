use super::*;
use rns_core::transport::{DecodedInboundFrame, DecodedPacket, RxMetadata};

/// Events the driver handles before flushing driver-run writers and polling
/// its sockets even though its queue has not emptied yet.
const WRITER_FLUSH_EVENTS: usize = 1024;

impl Driver {
    #[cfg(test)]
    pub(crate) fn handle_frame_event(
        &mut self,
        interface_id: InterfaceId,
        data: Vec<u8>,
        rssi: Option<i16>,
        snr: Option<f32>,
    ) {
        self.handle_classified_frame_event(interface_id, data, rssi, snr, false);
    }

    /// Inbound admission checks that run on a decoded packet before the
    /// `PreIngress` hook. They count protocol violations and packet filter hits
    /// on the receiving interface and return whether the packet may proceed.
    fn admit_decoded_inbound(
        &mut self,
        interface_id: InterfaceId,
        packet_len: usize,
        decoded: &DecodedPacket,
    ) -> bool {
        let parsed_packet = decoded.packet();
        if parsed_packet.flags.packet_type == rns_core::constants::PACKET_TYPE_ANNOUNCE
            && packet_len > rns_core::constants::MTU
        {
            if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                entry.stats.protocol_violations += 1;
            }
            return false;
        }
        let is_path_request = parsed_packet.destination_hash == self.path_request_dest;
        let tagless_path_request = is_path_request && parsed_packet.data().len() <= 16;
        if tagless_path_request || self.engine.is_unvalidated_link_packet(parsed_packet) {
            if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                entry.stats.protocol_violations += 1;
            }
            return false;
        }
        if is_path_request
            && parsed_packet.data().len() > rns_core::constants::PATH_REQUEST_LENGTH
            && parsed_packet.data().len() != rns_core::constants::PATH_REQUEST_STAMPED_LENGTH
        {
            if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                entry.stats.protocol_violations += 1;
            }
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
        true
    }

    fn handle_classified_frame_event(
        &mut self,
        interface_id: InterfaceId,
        data: Vec<u8>,
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
        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
            entry.stats.rxb += data.len() as u64;
            entry.stats.rx_packets += 1;
        }

        let packet = if let Some(entry) = self.interfaces.get(&interface_id) {
            if let Some(ref ifac_state) = entry.ifac {
                match ifac::unmask_inbound(&data, ifac_state) {
                    Some(unmasked) => unmasked,
                    None => {
                        log::debug!("[{}] IFAC rejected packet", interface_id.0);
                        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                            entry.stats.ifac_violations += 1;
                        }
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
                return;
            }
        };
        // `if not packet.hops < Transport.HOP_LIMITER: return
        // interface.hop_limiter_hit()` (Transport.py:2009), before the packet
        // filter.
        if decoded_packet.packet().hops >= self.hop_limiter {
            if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                entry.stats.hop_limiter_hits += 1;
            }
            return;
        }
        if let Some(packet_hash) = decoded_packet.packet_hash() {
            self.engine.prefetch_packet_hash(packet_hash);
        }
        let packet_len = decoded_packet.packet().raw.len();
        if !self.admit_decoded_inbound(interface_id, packet_len, &decoded_packet) {
            return;
        }

        #[cfg(feature = "hooks")]
        let decoded_packet = if !self.hooks_attached(HookPoint::PreIngress) {
            decoded_packet
        } else {
            let packet = &decoded_packet.packet().raw;
            let pkt_ctx = rns_hooks::PacketContext {
                flags: if packet.is_empty() { 0 } else { packet[0] },
                hops: if packet.len() > 1 { packet[1] } else { 0 },
                destination_hash: extract_dest_hash(packet),
                context: 0,
                packet_hash: [0; 32],
                interface_id: interface_id.0,
                data_offset: 0,
                data_len: packet.len() as u32,
            };
            let ctx = HookContext::Packet {
                ctx: &pkt_ctx,
                raw: packet,
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
                &mut self.hook_slots[HookPoint::PreIngress as usize].programs,
                &self.hook_manager,
                &engine_ref,
                &ctx,
                now,
                provider_events_enabled,
            ) {
                self.forward_hook_side_effects("PreIngress", e);
                let max_len = self.hook_packet_limit(interface_id);
                outcome = self.packet_hook_outcome(HookPoint::PreIngress, e, max_len);
            }
            match outcome {
                PacketHookOutcome::Keep => decoded_packet,
                PacketHookOutcome::Drop => return,
                PacketHookOutcome::Replace(replacement) => {
                    // Decode the replacement afresh and hold it to the same
                    // admission checks as a received packet.
                    let replacement_len = replacement.raw.len();
                    let Ok(decoded) = DecodedPacket::unpack_owned(replacement.raw) else {
                        return;
                    };
                    if !self.admit_decoded_inbound(interface_id, replacement_len, &decoded) {
                        return;
                    }
                    decoded
                }
            }
        };

        let packet = &decoded_packet.packet().raw;
        if packet.len() > 2 && (packet[0] & 0x03) == 0x01 {
            let now = time::now();
            if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                entry.stats.record_incoming_announce(now);
            }
        }

        if let Some(entry) = self.interfaces.get(&interface_id) {
            self.engine.update_interface_freqs(
                interface_id,
                entry.stats.incoming_announce_freq(),
                entry.stats.incoming_path_request_freq(),
                entry.stats.outgoing_path_request_freq(),
                entry.stats.outgoing_path_request_samples(),
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
            if let Some(announced) = self.known_destination_announced(&destination_hash) {
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

        // The engine consumes the packet; the hooks after it need the bytes.
        #[cfg(feature = "hooks")]
        let dispatch_hook_packet = self
            .hooks_attached(HookPoint::PreDispatch)
            .then(|| decoded_packet.packet().raw.clone());
        let inbound_frame = DecodedInboundFrame {
            decoded: decoded_packet,
            iface: interface_id,
            now: time::now(),
            rx: RxMetadata { rssi, snr },
        };

        let actions = if self.async_announce_verification {
            let mut announce_queue = self
                .announce_verify_queue
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.engine.handle_decoded_inbound_with_announce_queue(
                inbound_frame,
                &mut self.rng,
                Some(&mut announce_queue),
            )
        } else {
            self.engine.handle_decoded_inbound_with_announce_queue(
                inbound_frame,
                &mut self.rng,
                None,
            )
        };
        if actions.iter().any(|action| {
            matches!(
                action,
                TransportAction::AnnounceReceived(announce)
                    if announce.receiving_interface == interface_id
            )
        }) {
            if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                entry.stats.arxc = entry.stats.arxc.saturating_add(1);
                entry.stats.arxb = entry.stats.arxb.saturating_add(received_size as u64);
            }
        }

        #[cfg(feature = "hooks")]
        if let Some(packet) = dispatch_hook_packet {
            let pkt_ctx = rns_hooks::PacketContext {
                flags: if packet.is_empty() { 0 } else { packet[0] },
                hops: if packet.len() > 1 { packet[1] } else { 0 },
                destination_hash: extract_dest_hash(&packet),
                context: 0,
                packet_hash: [0; 32],
                interface_id: interface_id.0,
                data_offset: 0,
                data_len: packet.len() as u32,
            };
            let ctx = HookContext::Packet {
                ctx: &pkt_ctx,
                raw: &packet,
            };
            let now = time::now();
            let engine_ref = EngineRef {
                engine: &self.engine,
                interfaces: &self.interfaces,
                link_manager: &self.link_manager,
                now,
            };
            let provider_events_enabled = self.provider_events_enabled();
            // The engine has already handled this packet, so neither `Drop`
            // nor `Modify` can change it any more: both act as `Continue` here
            // and the replacement bytes of a `Modify` verdict are ignored.
            if let Some(ref e) = run_hook_inner(
                &mut self.hook_slots[HookPoint::PreDispatch as usize].programs,
                &self.hook_manager,
                &engine_ref,
                &ctx,
                now,
                provider_events_enabled,
            ) {
                self.forward_hook_side_effects("PreDispatch", e);
            }
        }

        self.dispatch_all_with_ingress_class(actions, ingress_limited);
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

    pub(crate) fn handle_announce_verified_event(
        &mut self,
        key: rns_core::transport::announce_verify_queue::AnnounceVerifyKey,
        validated: rns_core::announce::ValidatedAnnounce,
        sig_cache_key: [u8; 32],
    ) {
        let pending = {
            let mut announce_queue = self
                .announce_verify_queue
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            announce_queue.complete_success(&key)
        };
        if let Some(pending) = pending {
            let interface = pending.interface;
            let received_size = pending.original_raw.len();
            let actions = self.engine.complete_verified_announce(
                pending,
                validated,
                sig_cache_key,
                time::now(),
                &mut self.rng,
            );
            if actions
                .iter()
                .any(|action| matches!(action, TransportAction::AnnounceReceived(_)))
            {
                if let Some(entry) = self.interfaces.get_mut(&interface) {
                    entry.stats.arxc = entry.stats.arxc.saturating_add(1);
                    entry.stats.arxb = entry.stats.arxb.saturating_add(received_size as u64);
                }
            }
            self.dispatch_all(actions);
        }
    }

    pub(crate) fn handle_tick_event(&mut self) {
        // Close sockets of detached interfaces served on this thread.
        self.rx.sweep_stopped_sources();
        // Re-arm sources that backed off after an error, e.g. a listener
        // whose accept failed.
        self.rx.resume_paused_sources();
        // Let driver-run writers notice peers that stopped reading.
        for entry in self.interfaces.values_mut() {
            entry.writer.tick();
        }
        #[cfg(feature = "hooks")]
        {
            let ctx = HookContext::Tick;
            let now = time::now();
            let engine_ref = EngineRef {
                engine: &self.engine,
                interfaces: &self.interfaces,
                link_manager: &self.link_manager,
                now,
            };
            let provider_events_enabled = self.provider_events_enabled();
            // Tick carries no packet: `Modify` acts as `Continue`.
            if let Some(ref e) = run_hook_inner(
                &mut self.hook_slots[HookPoint::Tick as usize].programs,
                &self.hook_manager,
                &engine_ref,
                &ctx,
                now,
                provider_events_enabled,
            ) {
                self.forward_hook_side_effects("Tick", e);
            }
        }

        let now = time::now();
        self.sample_interface_traffic(now);
        for (id, entry) in &self.interfaces {
            self.engine.update_interface_freqs(
                *id,
                entry.stats.incoming_announce_freq(),
                entry.stats.incoming_path_request_freq(),
                entry.stats.outgoing_path_request_freq(),
                entry.stats.outgoing_path_request_samples(),
            );
        }
        let actions = self.engine.tick(now, &mut self.rng);
        self.dispatch_all(actions);
        let link_actions = self.link_manager.tick(&mut self.rng);
        self.dispatch_link_actions(link_actions);
        self.enforce_drain_deadline();
        {
            let tx = self.get_event_sender();
            let hp_actions = self.holepunch_manager.tick(&tx);
            self.dispatch_holepunch_actions(hp_actions);
        }
        self.tick_management_announces(now);
        self.sent_packets
            .retain(|_, (_, sent_time)| now - *sent_time < 60.0);
        self.completed_proofs
            .retain(|_, (_, received)| now - *received < 120.0);
        self.expire_local_path_responses(now);

        self.tick_discovery_announcer(now);
        #[cfg(feature = "iface-backbone")]
        self.maintain_backbone_peer_pool();

        self.memory_stats_counter += 1;
        if self.memory_stats_counter >= 300 {
            self.memory_stats_counter = 0;
            self.log_memory_stats();
        }

        if self.discover_interfaces {
            self.discovery_cleanup_counter += 1;
            if self.discovery_cleanup_counter >= self.discovery_cleanup_interval_ticks {
                self.discovery_cleanup_counter = 0;
                if let Ok(removed) = self
                    .discovered_interfaces
                    .cleanup_with_blackholes(|identity| self.engine.is_blackholed(identity, now))
                {
                    if removed > 0 {
                        log::info!("Discovery cleanup: removed {} stale entries", removed);
                    }
                    #[cfg(feature = "iface-backbone")]
                    self.cull_stale_discovered_backbone_peer_pool_candidates();
                }
            }
        }

        self.finish_ratchet_cleanup_if_ready();
        if self.known_destination_cleanup.is_none() {
            self.cache_cleanup_counter += 1;
            if self.cache_cleanup_counter >= self.known_destinations_cleanup_interval_ticks {
                self.cache_cleanup_counter = 0;
                self.known_destination_cleanup = Some(KnownDestinationCleanup {
                    candidates: self.known_destinations.keys().copied().collect(),
                    cursor: 0,
                    started_at: Instant::now(),
                    removed: 0,
                });
                log::debug!("Cleaning known destinations at background priority...");
            }
        }
        self.continue_known_destination_cleanup(now);

        self.announce_cache_cleanup_counter += 1;
        if self.announce_cache_cleanup_counter >= self.announce_cache_cleanup_interval_ticks {
            self.announce_cache_cleanup_counter = 0;
            if let Some(cache) = self.announce_cache.as_ref() {
                let active_hashes = self.engine.active_packet_hashes();
                match cache.clean(&active_hashes) {
                    Ok(removed) if removed > 0 => {
                        log::info!(
                            "Announce cache cleanup complete: removed {} stale entries",
                            removed
                        );
                    }
                    Ok(_) => {}
                    Err(e) => log::warn!("Announce cache cleanup failed: {}", e),
                }
            }
        }
        self.publish_state_snapshot();
    }

    pub(super) fn sample_interface_traffic(&mut self, now: f64) {
        self.traffic_samples
            .retain(|id, _| self.interfaces.contains_key(id));
        for (id, entry) in &mut self.interfaces {
            let Some(previous) = self.traffic_samples.get(id).copied() else {
                self.traffic_samples
                    .insert(*id, TrafficSample::from_stats(now, &entry.stats));
                entry.stats.traffic_rates = Default::default();
                continue;
            };
            let elapsed = now - previous.sampled_at;
            if elapsed < 1.0 {
                continue;
            }
            let bps =
                |current: u64, prior: u64| current.saturating_sub(prior) as f64 * 8.0 / elapsed;
            let pps = |current: u64, prior: u64| current.saturating_sub(prior) as f64 / elapsed;
            entry.stats.traffic_rates = crate::interface::TrafficRates {
                rxs: bps(entry.stats.rxb, previous.rxb),
                txs: bps(entry.stats.txb, previous.txb),
                rxpps: pps(entry.stats.rx_packets, previous.rx_packets),
                txpps: pps(entry.stats.tx_packets, previous.tx_packets),
                arxs: bps(entry.stats.arxb, previous.arxb),
                atxs: bps(entry.stats.atxb, previous.atxb),
                prxs: bps(entry.stats.prxb, previous.prxb),
                ptxs: bps(entry.stats.ptxb, previous.ptxb),
            };
            self.traffic_samples
                .insert(*id, TrafficSample::from_stats(now, &entry.stats));
        }
    }

    fn continue_known_destination_cleanup(&mut self, now: f64) {
        let Some(mut cleanup) = self.known_destination_cleanup.take() else {
            return;
        };
        let end =
            (cleanup.cursor + KNOWN_DESTINATION_CLEANUP_BATCH_SIZE).min(cleanup.candidates.len());
        for destination_hash in &cleanup.candidates[cleanup.cursor..end] {
            let remove = self
                .known_destinations
                .get(destination_hash)
                .is_some_and(|state| {
                    !self.engine.has_path(destination_hash)
                        && !self.local_destinations.contains_key(destination_hash)
                        && !state.retained
                        && now - Self::known_destination_relevance_time(state)
                            >= self.known_destinations_ttl
                });
            if remove && self.known_destinations.remove(destination_hash).is_some() {
                cleanup.removed += 1;
            }
        }
        cleanup.cursor = end;
        if cleanup.cursor < cleanup.candidates.len() {
            self.known_destination_cleanup = Some(cleanup);
            return;
        }

        let evicted = self.enforce_known_destination_cap(false);
        let active_destinations = self.engine.active_destination_hashes();
        let rate_limiters =
            self.engine
                .cull_rate_limiter(&active_destinations, now, self.rate_limiter_ttl_secs);
        log::debug!(
            "Cleaned known destinations in {:?}",
            cleanup.started_at.elapsed()
        );
        if cleanup.removed > 0 || evicted > 0 || rate_limiters > 0 {
            log::info!(
                "Memory cleanup: removed {} known_destinations, evicted {} known_destinations, {} rate_limiter entries",
                cleanup.removed,
                evicted,
                rate_limiters,
            );
        }
        self.start_ratchet_cleanup(now);
    }

    fn finish_ratchet_cleanup_if_ready(&mut self) {
        let finished = self
            .ratchet_cleanup_handle
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished);
        if finished {
            if let Some(handle) = self.ratchet_cleanup_handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn start_ratchet_cleanup(&mut self, now: f64) {
        if self.ratchet_cleanup_handle.is_some() {
            return;
        }
        let Some(store) = self.ratchet_store.clone() else {
            return;
        };
        let known_destinations = self.known_destinations.keys().copied().collect();
        let expiry = self.ratchet_expiry_secs;
        match std::thread::Builder::new()
            .name("rns-destination-cleanup".into())
            .spawn(move || {
                #[cfg(target_family = "unix")]
                unsafe {
                    libc::nice(5);
                }
                match store.cleanup(&known_destinations, now, expiry) {
                    Ok(stats) if stats.removed > 0 => log::info!(
                        "Known-destination cleanup removed {} stale ratchets",
                        stats.removed
                    ),
                    Ok(_) => {}
                    Err(err) => log::warn!("failed to clean ratchets: {}", err),
                }
            }) {
            Ok(handle) => self.ratchet_cleanup_handle = Some(handle),
            Err(err) => log::warn!("failed to start ratchet cleanup worker: {}", err),
        }
    }

    pub(crate) fn handle_interface_up_event(
        &mut self,
        id: InterfaceId,
        new_writer: Option<Box<dyn crate::interface::Writer>>,
        info: Option<rns_core::transport::types::InterfaceInfo>,
    ) {
        self.state_snapshot_schedule.mark_dirty();
        let wants_tunnel;
        let mut replay_shared_announces = false;
        if let Some(mut info) = info {
            log::info!("[{}] dynamic interface registered", id.0);
            self.apply_announce_rate_defaults(&mut info);
            self.apply_ingress_control_defaults(&mut info);
            wants_tunnel = info.wants_tunnel;
            let iface_type = infer_interface_type(&info.name);
            info.started = time::now();
            self.register_interface_runtime_defaults(&info);
            self.engine.register_interface(info.clone());
            if let Some(writer) = new_writer {
                let (writer, async_writer_metrics) =
                    self.wrap_interface_writer(id, &info.name, writer);
                self.interfaces.insert(
                    id,
                    InterfaceEntry {
                        id,
                        info,
                        writer,
                        async_writer_metrics: Some(async_writer_metrics),
                        enabled: true,
                        online: true,
                        dynamic: true,
                        ifac: None,
                        stats: InterfaceStats {
                            started: time::now(),
                            ..Default::default()
                        },
                        interface_type: iface_type,
                        send_retry_at: None,
                        send_retry_backoff: Duration::ZERO,
                    },
                );
            }
            self.callbacks.on_interface_up(id);
            #[cfg(feature = "hooks")]
            {
                let ctx = HookContext::Interface { interface_id: id.0 };
                let now = time::now();
                let engine_ref = EngineRef {
                    engine: &self.engine,
                    interfaces: &self.interfaces,
                    link_manager: &self.link_manager,
                    now,
                };
                let provider_events_enabled = self.provider_events_enabled();
                if let Some(ref e) = run_hook_inner(
                    &mut self.hook_slots[HookPoint::InterfaceUp as usize].programs,
                    &self.hook_manager,
                    &engine_ref,
                    &ctx,
                    now,
                    provider_events_enabled,
                ) {
                    self.forward_hook_side_effects("InterfaceUp", e);
                }
            }
        } else {
            let is_local_client = self
                .interfaces
                .get(&id)
                .map(|entry| entry.info.is_local_client)
                .unwrap_or(false);
            replay_shared_announces =
                is_local_client && self.shared_reconnect_pending.remove(&id).unwrap_or(false);
            let interface_name = self
                .interfaces
                .get(&id)
                .map(|entry| entry.info.name.clone())
                .unwrap_or_else(|| format!("iface-{}", id.0));
            let wrapped_writer =
                new_writer.map(|writer| self.wrap_interface_writer(id, &interface_name, writer));
            if let Some(entry) = self.interfaces.get_mut(&id) {
                log::info!("[{}] interface online", id.0);
                wants_tunnel = entry.info.wants_tunnel;
                entry.online = true;
                if let Some((writer, async_writer_metrics)) = wrapped_writer {
                    log::info!("[{}] writer refreshed after reconnect", id.0);
                    entry.writer = writer;
                    entry.async_writer_metrics = Some(async_writer_metrics);
                }
                self.callbacks.on_interface_up(id);
                #[cfg(feature = "hooks")]
                {
                    let ctx = HookContext::Interface { interface_id: id.0 };
                    let now = time::now();
                    let engine_ref = EngineRef {
                        engine: &self.engine,
                        interfaces: &self.interfaces,
                        link_manager: &self.link_manager,
                        now,
                    };
                    let provider_events_enabled = self.provider_events_enabled();
                    if let Some(ref e) = run_hook_inner(
                        &mut self.hook_slots[HookPoint::InterfaceUp as usize].programs,
                        &self.hook_manager,
                        &engine_ref,
                        &ctx,
                        now,
                        provider_events_enabled,
                    ) {
                        self.forward_hook_side_effects("InterfaceUp", e);
                    }
                }
            } else {
                wants_tunnel = false;
            }
        }

        if wants_tunnel {
            self.synthesize_tunnel_for_interface(id);
        }
        if replay_shared_announces {
            self.replay_shared_announces();
        }
    }

    pub(crate) fn handle_dynamic_interface_up_event(
        &mut self,
        id: InterfaceId,
        writer: Box<dyn crate::interface::Writer>,
        mut registration: crate::event::DynamicInterfaceRegistration,
    ) {
        self.state_snapshot_schedule.mark_dirty();
        let parent_id = registration.parent_id;
        if self.retired_interface_parents.contains(&parent_id) {
            return;
        }
        let parent_ifac = self.interfaces.get(&parent_id).and_then(|parent| {
            registration.info.mode = parent.info.mode;
            registration.info.gravity = parent.info.gravity;
            registration.info.recursive_prs = parent.info.recursive_prs;
            registration.info.announces_from_internal = parent.info.announces_from_internal;
            registration.info.announces_to_internal = parent.info.announces_to_internal;
            registration.info.announce_rate_target = parent.info.announce_rate_target;
            registration.info.announce_rate_grace = parent.info.announce_rate_grace;
            registration.info.announce_rate_penalty = parent.info.announce_rate_penalty;
            registration.info.announce_cap = parent.info.announce_cap;
            registration.info.ingress_control = parent.info.ingress_control;
            registration.info.stamp_costs = parent.info.stamp_costs;
            parent.ifac.clone()
        });
        let inherited_ifac = registration.ifac.take().or(parent_ifac);

        let interface_type = registration.interface_type;
        let telemetry = registration.telemetry;
        self.handle_interface_up_event(id, Some(writer), Some(registration.info));
        if let Some(entry) = self.interfaces.get_mut(&id) {
            self.dynamic_interface_parents.insert(id, parent_id);
            self.event_tx.register_dynamic_parent(id, parent_id);
            entry.interface_type = interface_type;
            entry.ifac = inherited_ifac;
            Self::apply_interface_telemetry(entry, telemetry);
        }
    }

    fn apply_interface_telemetry(
        entry: &mut crate::interface::InterfaceEntry,
        telemetry: crate::event::InterfaceTelemetry,
    ) {
        entry.stats.cpu_load = telemetry.cpu_load;
        entry.stats.mem_load = telemetry.mem_load;
        entry.stats.switch_id = telemetry.switch_id;
        entry.stats.endpoint_id = telemetry.endpoint_id;
        entry.stats.via_switch_id = telemetry.via_switch_id;
        entry.stats.peers = telemetry.peers;
        if telemetry.rssi.is_some() {
            entry.stats.rssi = telemetry.rssi;
        }
        if telemetry.snr.is_some() {
            entry.stats.snr = telemetry.snr;
        }
        if telemetry.signal_quality.is_some() {
            entry.stats.signal_quality = telemetry.signal_quality;
        }
        if telemetry.frequency.is_some() {
            entry.stats.frequency = telemetry.frequency;
        }
        if telemetry.bandwidth.is_some() {
            entry.stats.bandwidth = telemetry.bandwidth;
        }
        if telemetry.txpower.is_some() {
            entry.stats.txpower = telemetry.txpower;
        }
        if telemetry.spreading_factor.is_some() {
            entry.stats.spreading_factor = telemetry.spreading_factor;
        }
        if telemetry.coding_rate.is_some() {
            entry.stats.coding_rate = telemetry.coding_rate;
        }
        if telemetry.channel.is_some() {
            entry.stats.channel = telemetry.channel;
        }
        if telemetry.modulation.is_some() {
            entry.stats.modulation = telemetry.modulation;
        }
    }

    pub(crate) fn handle_interface_telemetry_event(
        &mut self,
        interface_id: InterfaceId,
        telemetry: crate::event::InterfaceTelemetry,
    ) {
        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
            Self::apply_interface_telemetry(entry, telemetry);
        }
    }

    pub(crate) fn handle_interface_down_event(&mut self, id: InterfaceId) {
        self.state_snapshot_schedule.mark_dirty();
        self.event_tx.remove_interface(id);
        if let Some(entry) = self.interfaces.get(&id) {
            if let Some(tunnel_id) = entry.info.tunnel_id {
                self.engine.void_tunnel_interface(&tunnel_id);
            }
        }

        if let Some(entry) = self.interfaces.get(&id) {
            let is_dynamic = entry.dynamic;
            let is_local_client = entry.info.is_local_client;
            let interface_name = entry.info.name.clone();
            if is_dynamic {
                log::info!("[{}] dynamic interface removed", id.0);
                self.interface_runtime_defaults.remove(&interface_name);
                self.engine.deregister_interface(id);
                self.interfaces.remove(&id);
                self.dynamic_interface_parents.remove(&id);
            } else {
                log::info!("[{}] interface offline", id.0);
                if let Some(entry) = self.interfaces.get_mut(&id) {
                    entry.online = false;
                } else {
                    log::warn!(
                        "interface {} disappeared while handling interface-down",
                        id.0
                    );
                    return;
                }
                if is_local_client {
                    self.handle_shared_interface_down(id);
                }
            }
            self.callbacks.on_interface_down(id);
            #[cfg(feature = "hooks")]
            {
                let ctx = HookContext::Interface { interface_id: id.0 };
                let now = time::now();
                let engine_ref = EngineRef {
                    engine: &self.engine,
                    interfaces: &self.interfaces,
                    link_manager: &self.link_manager,
                    now,
                };
                let provider_events_enabled = self.provider_events_enabled();
                if let Some(ref e) = run_hook_inner(
                    &mut self.hook_slots[HookPoint::InterfaceDown as usize].programs,
                    &self.hook_manager,
                    &engine_ref,
                    &ctx,
                    now,
                    provider_events_enabled,
                ) {
                    self.forward_hook_side_effects("InterfaceDown", e);
                }
            }
        }
        #[cfg(feature = "iface-backbone")]
        self.handle_backbone_peer_pool_down(id);
    }

    pub(crate) fn known_destination_route_hint(
        &self,
        dest_hash: &[u8; 16],
    ) -> Option<(InterfaceId, u8)> {
        let announced = &self.known_destinations.get(dest_hash)?.announced;
        let iface = announced.receiving_interface;
        if iface.0 == 0 {
            return None;
        }

        self.interfaces
            .get(&iface)
            .filter(|entry| entry.online)
            .map(|_| (iface, announced.hops))
    }

    pub(crate) fn handle_send_outbound_event(
        &mut self,
        raw: Vec<u8>,
        dest_type: u8,
        attached_interface: Option<InterfaceId>,
    ) {
        if self.is_draining() {
            self.reject_new_work("send outbound packet");
            return;
        }
        match RawPacket::unpack(&raw) {
            Ok(packet) => {
                let is_announce =
                    packet.flags.packet_type == rns_core::constants::PACKET_TYPE_ANNOUNCE;
                if is_announce {
                    log::debug!(
                        "SendOutbound: ANNOUNCE for {:02x?} (len={}, dest_type={}, attached={:?})",
                        &packet.destination_hash[..4],
                        raw.len(),
                        dest_type,
                        attached_interface
                    );
                }
                if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_DATA {
                    log::debug!(
                        "SendOutbound: DATA dest={:02x}{:02x}{:02x}{:02x}.. header={} transport={:02x?} attached={:?}",
                        packet.destination_hash[0],
                        packet.destination_hash[1],
                        packet.destination_hash[2],
                        packet.destination_hash[3],
                        packet.flags.header_type,
                        packet.transport_id.as_ref().map(|id| &id[..4]),
                        attached_interface
                    );
                    self.sent_packets
                        .insert(packet.packet_hash, (packet.destination_hash, time::now()));
                }
                let actions = self.engine.handle_outbound(
                    &packet,
                    dest_type,
                    attached_interface,
                    time::now(),
                );
                if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_DATA {
                    log::debug!(
                        "SendOutbound: DATA routed to {} actions: {:?}",
                        actions.len(),
                        actions
                            .iter()
                            .map(|a| match a {
                                TransportAction::SendOnInterface { interface, raw } =>
                                    format!("SendOn({};{}b)", interface.0, raw.len()),
                                TransportAction::BroadcastOnAllInterfaces { raw, .. } =>
                                    format!("BroadcastAll({}b)", raw.len()),
                                _ => "other".to_string(),
                            })
                            .collect::<Vec<_>>()
                    );
                }
                if is_announce {
                    log::debug!(
                        "SendOutbound: announce routed to {} actions: {:?}",
                        actions.len(),
                        actions
                            .iter()
                            .map(|a| match a {
                                TransportAction::SendOnInterface { interface, .. } =>
                                    format!("SendOn({})", interface.0),
                                TransportAction::BroadcastOnAllInterfaces { .. } =>
                                    "BroadcastAll".to_string(),
                                _ => "other".to_string(),
                            })
                            .collect::<Vec<_>>()
                    );
                }
                self.dispatch_all(actions);
            }
            Err(e) => {
                log::warn!("SendOutbound: failed to unpack packet: {:?}", e);
            }
        }
    }

    /// Run the event loop. Blocks until Shutdown or all senders are dropped.
    pub fn run(&mut self) {
        self.link_manager
            .set_receive_worker_wake(self.event_tx.clone());
        let mut ready = polling::Events::new();
        // Events handled since driver-run writers were last flushed.
        let mut unflushed = 0usize;
        loop {
            self.poll_resource_preparations();
            let actions = self.link_manager.poll_receive_worker(&mut self.rng);
            self.dispatch_link_actions(actions);
            self.flush_pending_link_frames();
            if self
                .state_snapshot_schedule
                .needs_publish(self.link_manager.link_count())
            {
                self.publish_state_snapshot();
            }
            if !self.rx.has_prefetched() {
                self.wake_writers();
            }
            let received = match self.rx.try_recv_classified() {
                Ok(Some(e)) => e,
                Ok(None) => {
                    // Everything the last poll delivered has been handled:
                    // send this pass's output before waiting for more.
                    self.flush_writers();
                    unflushed = 0;
                    ready.clear();
                    if let Err(error) = self.rx.wait(&mut ready, None) {
                        log::warn!("driver wait failed: {error}");
                    }
                    self.handle_ready_sources(&ready);
                    continue;
                }
                Err(_) => break, // all senders dropped
            };
            // Bound output latency, and keep serving sockets, while other
            // threads keep the queue from emptying.
            unflushed += 1;
            // A tick queued behind a long backlog would leave the snapshot
            // stale for as long as the backlog takes to drain.
            let tick_interval =
                Duration::from_millis(self.tick_interval_ms.load(Ordering::Relaxed));
            if self.state_snapshot_schedule.event_handled(tick_interval) {
                self.publish_state_snapshot();
            }
            if unflushed >= WRITER_FLUSH_EVENTS {
                self.flush_writers();
                unflushed = 0;
                ready.clear();
                match self.rx.poll_ready(&mut ready) {
                    Ok(()) => self.handle_ready_sources(&ready),
                    Err(error) => log::warn!("driver poll failed: {error}"),
                }
            }

            match received.event {
                Event::Frame {
                    interface_id,
                    data,
                    rssi,
                    snr,
                } => {
                    self.handle_classified_frame_event(
                        interface_id,
                        data,
                        rssi,
                        snr,
                        received.ingress_limited,
                    );
                }
                Event::AnnounceVerified {
                    key,
                    validated,
                    sig_cache_key,
                } => {
                    self.handle_announce_verified_event(key, *validated, sig_cache_key);
                }
                Event::AnnounceVerifyFailed { key, .. } => {
                    let mut announce_queue = self
                        .announce_verify_queue
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let interface = announce_queue.pending_interface(&key);
                    let blackholed = announce_queue
                        .pending_identity_hash(&key)
                        .is_some_and(|hash| self.engine.is_blackholed(&hash, time::now()));
                    if announce_queue.complete_failure(&key) {
                        if let Some(entry) = interface.and_then(|id| self.interfaces.get_mut(&id)) {
                            if !blackholed {
                                entry.stats.protocol_violations += 1;
                            }
                        }
                    }
                }
                Event::Tick => self.handle_tick_event(),
                Event::BeginDrain { timeout } => {
                    self.begin_drain(timeout);
                }
                Event::InterfaceUp(id, new_writer, info) => {
                    self.handle_interface_up_event(id, new_writer, info.map(|info| *info));
                }
                Event::DynamicInterfaceUp {
                    id,
                    writer,
                    registration,
                } => self.handle_dynamic_interface_up_event(id, writer, *registration),
                Event::InterfaceTelemetry {
                    interface_id,
                    telemetry,
                } => self.handle_interface_telemetry_event(interface_id, *telemetry),
                Event::InterfaceDown(id) => self.handle_interface_down_event(id),
                Event::SendOutbound {
                    raw,
                    dest_type,
                    attached_interface,
                } => self.handle_send_outbound_event(raw, dest_type, attached_interface),
                Event::SendOutboundTracked {
                    raw,
                    dest_type,
                    replay,
                    completion,
                } => {
                    self.handle_confirmed_outbound(raw, dest_type, replay, completion);
                }
                Event::RegisterDestination {
                    dest_hash,
                    dest_type,
                } => {
                    self.engine.register_destination(dest_hash, dest_type);
                    self.local_destinations.insert(dest_hash, dest_type);
                }
                Event::StoreSharedAnnounce {
                    dest_hash,
                    name_hash,
                    identity_prv_key,
                    app_data,
                } => {
                    self.shared_announces.insert(
                        dest_hash,
                        SharedAnnounceRecord {
                            name_hash,
                            identity_prv_key,
                            app_data,
                        },
                    );
                }
                Event::DeregisterDestination { dest_hash } => {
                    self.engine.deregister_destination(&dest_hash);
                    self.local_destinations.remove(&dest_hash);
                    self.shared_announces.remove(&dest_hash);
                }
                Event::Query(request, response_tx) => {
                    let response = self.handle_query_mut(*request);
                    let _ = response_tx.send(response);
                }
                Event::DeregisterLinkDestination { dest_hash } => {
                    self.link_manager.deregister_link_destination(&dest_hash);
                }
                Event::RegisterLinkDestination {
                    dest_hash,
                    sig_prv_bytes,
                    sig_pub_bytes,
                    resource_strategy,
                    max_request_size,
                } => {
                    let sig_prv =
                        rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&sig_prv_bytes);
                    let strat = match resource_strategy {
                        1 => crate::link_manager::ResourceStrategy::AcceptAll,
                        2 => crate::link_manager::ResourceStrategy::AcceptApp,
                        _ => crate::link_manager::ResourceStrategy::AcceptNone,
                    };
                    self.link_manager.register_link_destination(
                        dest_hash,
                        sig_prv,
                        sig_pub_bytes,
                        strat,
                    );
                    self.link_manager
                        .set_link_destination_max_request_size(&dest_hash, max_request_size);
                    // Also register in transport engine so inbound packets are delivered locally
                    self.engine
                        .register_destination(dest_hash, rns_core::constants::DESTINATION_SINGLE);
                    self.local_destinations
                        .insert(dest_hash, rns_core::constants::DESTINATION_SINGLE);
                }
                Event::RegisterRequestHandler {
                    path,
                    allowed_list,
                    handler,
                } => {
                    self.link_manager.register_request_handler(
                        &path,
                        allowed_list,
                        move |link_id, p, data, remote| handler(link_id, p, data, remote),
                    );
                }
                Event::RegisterRequestHandlerResponse {
                    path,
                    allowed_list,
                    handler,
                } => {
                    self.link_manager.register_request_handler_response(
                        &path,
                        allowed_list,
                        move |link_id, p, data, remote| handler(link_id, p, data, remote),
                    );
                }
                Event::RegisterDeferredRequestHandler {
                    path,
                    allowed_list,
                    handler,
                } => {
                    self.link_manager.register_deferred_request_handler(
                        &path,
                        allowed_list,
                        move |link_id, path, request_id, data, remote| {
                            handler(link_id, path, request_id, data, remote)
                        },
                    );
                }
                Event::CreateLink {
                    dest_hash,
                    dest_sig_pub_bytes,
                    response_tx,
                } => {
                    if self.is_draining() {
                        self.reject_new_work("create link");
                        let _ = (dest_hash, dest_sig_pub_bytes);
                        let _ = response_tx.send([0u8; 16]);
                        continue;
                    }
                    self.handle_create_link(dest_hash, dest_sig_pub_bytes, response_tx);
                }
                Event::SendStampedPathRequest(request) => {
                    if self.is_draining() {
                        self.reject_new_work("send stamped path request");
                        continue;
                    }
                    let crate::stamper::StampedPathRequest {
                        destination_hash,
                        tag,
                        ext_payload,
                        interface,
                    } = *request;
                    self.send_path_request(destination_hash, &tag, Some(&ext_payload), interface);
                }
                Event::CompleteStampedLink(keys) => {
                    let crate::common::event::StampedLinkKeys {
                        dest_hash,
                        dest_sig_pub_bytes,
                        prv_bytes,
                        sig_prv_bytes,
                        stamp_value,
                        response_tx,
                    } = *keys;
                    if self.is_draining() {
                        self.reject_new_work("complete stamped link");
                        let _ = response_tx.send([0u8; 16]);
                        continue;
                    }
                    log::trace!(
                        "Completing stamped link request to {:02x?} with value {}",
                        &dest_hash[..4],
                        stamp_value
                    );
                    let keys = (
                        rns_crypto::x25519::X25519PrivateKey::from_bytes(&prv_bytes),
                        rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&sig_prv_bytes),
                    );
                    self.complete_create_link(
                        dest_hash,
                        dest_sig_pub_bytes,
                        Some(keys),
                        response_tx,
                    );
                }
                Event::SendRequest {
                    link_id,
                    path,
                    data,
                    max_response_size,
                } => {
                    if self.is_draining() {
                        self.reject_new_work("send link request");
                        let _ = (link_id, path, data, max_response_size);
                        continue;
                    }
                    self.finish_resource_preparations_for(&link_id);
                    let link_actions = self.link_manager.send_request_with_max_response_size(
                        &link_id,
                        &path,
                        &data,
                        max_response_size,
                        &mut self.rng,
                    );
                    self.dispatch_link_actions(link_actions);
                }
                Event::SendDeferredResponse {
                    link_id,
                    request_id,
                    data,
                } => {
                    self.finish_resource_preparations_for(&link_id);
                    let link_actions = self.link_manager.send_deferred_response(
                        &link_id,
                        &request_id,
                        &data,
                        &mut self.rng,
                    );
                    self.dispatch_link_actions(link_actions);
                }
                Event::IdentifyOnLink {
                    link_id,
                    identity_prv_key,
                } => {
                    if self.is_draining() {
                        self.reject_new_work("identify on link");
                        let _ = (link_id, identity_prv_key);
                        continue;
                    }
                    let identity =
                        rns_crypto::identity::Identity::from_private_key(&identity_prv_key);
                    let link_actions =
                        self.link_manager
                            .identify(&link_id, &identity, &mut self.rng);
                    self.dispatch_link_actions(link_actions);
                }
                Event::TeardownLink { link_id } => {
                    let link_actions = self.link_manager.teardown_link(&link_id);
                    self.dispatch_link_actions(link_actions);
                }
                Event::ResourcePreparationReady | Event::ResourceAssemblyReady => {}
                Event::SendResource {
                    link_id,
                    data,
                    metadata,
                    options,
                } => {
                    if self.is_draining() {
                        self.reject_new_work("send resource");
                        let _ = (link_id, data, metadata, options);
                        continue;
                    }
                    self.prepare_resource_with_options(link_id, data, metadata, options);
                }
                Event::SendResourceStream {
                    link_id,
                    transfer_id,
                    reader,
                    declared_length,
                    metadata,
                    options,
                } => {
                    if self.is_draining() {
                        self.callbacks.on_resource_stream_failed(
                            rns_core::types::LinkId(link_id),
                            transfer_id,
                            crate::resource::ResourceTransferError::Cancelled,
                        );
                        continue;
                    }
                    self.finish_resource_preparations_for(&link_id);
                    let link_actions = self.link_manager.send_resource_stream_with_options(
                        &link_id,
                        transfer_id,
                        reader,
                        declared_length,
                        metadata,
                        options,
                        &mut self.rng,
                    );
                    self.dispatch_link_actions(link_actions);
                }
                Event::SetResourceStrategy { link_id, strategy } => {
                    use crate::link_manager::ResourceStrategy;
                    let strat = match strategy {
                        0 => ResourceStrategy::AcceptNone,
                        1 => ResourceStrategy::AcceptAll,
                        2 => ResourceStrategy::AcceptApp,
                        _ => ResourceStrategy::AcceptNone,
                    };
                    self.link_manager.set_resource_strategy(&link_id, strat);
                }
                Event::SetResourceReceiveMode { link_id, mode } => {
                    self.link_manager.set_resource_receive_mode(&link_id, mode);
                }
                Event::AcceptResource {
                    link_id,
                    resource_hash,
                    accept,
                } => {
                    if self.is_draining() && accept {
                        self.reject_new_work("accept resource");
                        let _ = (link_id, resource_hash, accept);
                        continue;
                    }
                    let link_actions = self.link_manager.accept_resource(
                        &link_id,
                        &resource_hash,
                        accept,
                        &mut self.rng,
                    );
                    self.dispatch_link_actions(link_actions);
                }
                Event::SendChannelMessage {
                    link_id,
                    msgtype,
                    payload,
                    response_tx,
                } => {
                    if self.is_draining() {
                        self.reject_new_work("send channel message");
                        let _ = response_tx.send(Err(self.drain_error("send channel message")));
                        continue;
                    }
                    match self.link_manager.send_channel_message(
                        &link_id,
                        msgtype,
                        &payload,
                        &mut self.rng,
                    ) {
                        Ok(link_actions) => {
                            self.dispatch_link_actions(link_actions);
                            let _ = response_tx.send(Ok(()));
                        }
                        Err(err) => {
                            let _ = response_tx.send(Err(err));
                        }
                    }
                }
                Event::LinkWriterReady => {}
                Event::SendLinkTracked {
                    link_id,
                    data,
                    context,
                    completion,
                } => {
                    use crate::link_send::LinkSendError;
                    if self.is_draining() {
                        completion.finish(Err(LinkSendError::Draining));
                        continue;
                    }
                    match self.link_manager.try_send_on_link(
                        &link_id,
                        &data,
                        context,
                        &mut self.rng,
                    ) {
                        Ok(actions) => {
                            if self.link_manager.get_link_route_hint(&link_id).is_none() {
                                completion.finish(Err(LinkSendError::NoRoute));
                                continue;
                            }
                            let hash = actions.iter().find_map(|action| match action {
                                LinkManagerAction::SendPacket { raw, .. } => {
                                    RawPacket::unpack(raw).ok().map(|p| p.packet_hash)
                                }
                                _ => None,
                            });
                            if let Some(hash) = hash {
                                self.tracked_link_send = Some((hash, completion));
                                self.dispatch_link_actions(actions);
                                if let Some((_, completion)) = self.tracked_link_send.take() {
                                    completion.finish(Err(LinkSendError::Rejected));
                                }
                            } else {
                                completion.finish(Err(LinkSendError::Rejected));
                            }
                        }
                        Err(error) => completion.finish(Err(LinkSendError::InvalidPacket(error))),
                    }
                }
                Event::SendOnLink {
                    link_id,
                    data,
                    context,
                    response_tx,
                } => {
                    if self.is_draining() {
                        self.reject_new_work("send link payload");
                        if let Some(tx) = response_tx {
                            let _ = tx.send(Err(crate::event::LinkDatagramError::DriverStopped));
                        }
                        continue;
                    }
                    let result =
                        self.link_manager
                            .try_send_on_link(&link_id, &data, context, &mut self.rng);
                    match result {
                        Ok(link_actions) => {
                            self.dispatch_link_actions(link_actions);
                            if let Some(tx) = response_tx {
                                let _ = tx.send(Ok(()));
                            }
                        }
                        Err(error) => {
                            if let Some(tx) = response_tx {
                                let _ = tx.send(Err(error));
                            }
                        }
                    }
                }
                Event::RequestPath { dest_hash } => {
                    if self.is_draining() {
                        self.reject_new_work("request path");
                        let _ = dest_hash;
                        continue;
                    }
                    self.handle_request_path(dest_hash);
                }
                Event::RegisterProofStrategy {
                    dest_hash,
                    strategy,
                    signing_key,
                } => {
                    let identity = signing_key
                        .map(|key| rns_crypto::identity::Identity::from_private_key(&key));
                    self.proof_strategies
                        .insert(dest_hash, (strategy, identity));
                }
                Event::ProposeDirectConnect { link_id } => {
                    if self.is_draining() {
                        self.reject_new_work("propose direct connect");
                        let _ = link_id;
                        continue;
                    }
                    let derived_key = self.link_manager.get_derived_key(&link_id);
                    if let Some(dk) = derived_key {
                        let tx = self.get_event_sender();
                        let hp_actions =
                            self.holepunch_manager
                                .propose(link_id, &dk, &mut self.rng, &tx);
                        self.dispatch_holepunch_actions(hp_actions);
                    } else {
                        log::warn!(
                            "Cannot propose direct connect: no derived key for link {:02x?}",
                            &link_id[..4]
                        );
                    }
                }
                Event::SetDirectConnectPolicy { policy } => {
                    self.holepunch_manager.set_policy(policy);
                }
                Event::HolePunchProbeResult {
                    link_id,
                    session_id,
                    observed_addr,
                    socket,
                    probe_server,
                } => {
                    let hp_actions = self.holepunch_manager.handle_probe_result(
                        link_id,
                        session_id,
                        observed_addr,
                        socket,
                        probe_server,
                    );
                    self.dispatch_holepunch_actions(hp_actions);
                }
                Event::HolePunchProbeFailed {
                    link_id,
                    session_id,
                } => {
                    let hp_actions = self
                        .holepunch_manager
                        .handle_probe_failed(link_id, session_id);
                    self.dispatch_holepunch_actions(hp_actions);
                }
                Event::LoadHook {
                    name,
                    wasm_bytes,
                    attach_point,
                    priority,
                    response_tx,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let result = (|| -> Result<(), String> {
                            let point_idx = crate::config::parse_hook_point(&attach_point)
                                .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                            let mgr = self
                                .hook_manager
                                .as_ref()
                                .ok_or_else(|| "hook manager not available".to_string())?;
                            let program = mgr
                                .compile(name.clone(), &wasm_bytes, priority)
                                .map_err(|e| format!("compile error: {}", e))?;
                            self.hook_slots[point_idx].attach(program);
                            log::info!(
                                "Loaded hook '{}' at point {} (priority {})",
                                name,
                                attach_point,
                                priority
                            );
                            Ok(())
                        })();
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (name, wasm_bytes, attach_point, priority);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::LoadHookFile {
                    name,
                    path,
                    hook_type,
                    attach_point,
                    priority,
                    response_tx,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let result = (|| -> Result<(), String> {
                            let point_idx = crate::config::parse_hook_point(&attach_point)
                                .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                            let backend = crate::config::parse_hook_backend(&hook_type)?;
                            let mgr = self
                                .hook_manager
                                .as_ref()
                                .ok_or_else(|| "hook manager not available".to_string())?;
                            let program = mgr
                                .load_file_backend(
                                    name.clone(),
                                    std::path::Path::new(&path),
                                    priority,
                                    backend,
                                )
                                .map_err(|e| format!("load error: {}", e))?;
                            self.hook_slots[point_idx].attach(program);
                            log::info!(
                                "Loaded {} hook '{}' at point {} (priority {})",
                                backend.as_str(),
                                name,
                                attach_point,
                                priority
                            );
                            Ok(())
                        })();
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (name, path, hook_type, attach_point, priority);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::LoadBuiltinHook {
                    name,
                    builtin_id,
                    attach_point,
                    priority,
                    response_tx,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let result = (|| -> Result<(), String> {
                            let point_idx = crate::config::parse_hook_point(&attach_point)
                                .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                            let mgr = self
                                .hook_manager
                                .as_ref()
                                .ok_or_else(|| "hook manager not available".to_string())?;
                            let program = mgr
                                .load_builtin(name.clone(), builtin_id.as_str(), priority)
                                .map_err(|e| format!("load error: {}", e))?;
                            self.hook_slots[point_idx].attach(program);
                            log::info!(
                                "Loaded built-in hook '{}' ({}) at point {} (priority {})",
                                name,
                                builtin_id,
                                attach_point,
                                priority
                            );
                            Ok(())
                        })();
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (name, builtin_id, attach_point, priority);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::UnloadHook {
                    name,
                    attach_point,
                    response_tx,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let result = (|| -> Result<(), String> {
                            let point_idx = crate::config::parse_hook_point(&attach_point)
                                .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                            match self.hook_slots[point_idx].detach(&name) {
                                Some(_) => {
                                    log::info!(
                                        "Unloaded hook '{}' from point {}",
                                        name,
                                        attach_point
                                    );
                                    Ok(())
                                }
                                None => Err(format!(
                                    "hook '{}' not found at point '{}'",
                                    name, attach_point
                                )),
                            }
                        })();
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (name, attach_point);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::ReloadHook {
                    name,
                    attach_point,
                    wasm_bytes,
                    response_tx,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let result = (|| -> Result<(), String> {
                            let point_idx = crate::config::parse_hook_point(&attach_point)
                                .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                            let old =
                                self.hook_slots[point_idx].detach(&name).ok_or_else(|| {
                                    format!("hook '{}' not found at point '{}'", name, attach_point)
                                })?;
                            let priority = old.priority;
                            let mgr = match self.hook_manager.as_ref() {
                                Some(m) => m,
                                None => {
                                    self.hook_slots[point_idx].attach(old);
                                    return Err("hook manager not available".to_string());
                                }
                            };
                            match mgr.compile(name.clone(), &wasm_bytes, priority) {
                                Ok(program) => {
                                    self.hook_slots[point_idx].attach(program);
                                    log::info!(
                                        "Reloaded hook '{}' at point {} (priority {})",
                                        name,
                                        attach_point,
                                        priority
                                    );
                                    Ok(())
                                }
                                Err(e) => {
                                    self.hook_slots[point_idx].attach(old);
                                    Err(format!("compile error: {}", e))
                                }
                            }
                        })();
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (name, attach_point, wasm_bytes);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::ReloadHookFile {
                    name,
                    attach_point,
                    path,
                    hook_type,
                    response_tx,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let result = (|| -> Result<(), String> {
                            let point_idx = crate::config::parse_hook_point(&attach_point)
                                .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                            let old =
                                self.hook_slots[point_idx].detach(&name).ok_or_else(|| {
                                    format!("hook '{}' not found at point '{}'", name, attach_point)
                                })?;
                            let priority = old.priority;
                            let backend = match crate::config::parse_hook_backend(&hook_type) {
                                Ok(backend) => backend,
                                Err(e) => {
                                    self.hook_slots[point_idx].attach(old);
                                    return Err(e);
                                }
                            };
                            let mgr = match self.hook_manager.as_ref() {
                                Some(m) => m,
                                None => {
                                    self.hook_slots[point_idx].attach(old);
                                    return Err("hook manager not available".to_string());
                                }
                            };
                            match mgr.load_file_backend(
                                name.clone(),
                                std::path::Path::new(&path),
                                priority,
                                backend,
                            ) {
                                Ok(program) => {
                                    self.hook_slots[point_idx].attach(program);
                                    log::info!(
                                        "Reloaded {} hook '{}' at point {} (priority {})",
                                        backend.as_str(),
                                        name,
                                        attach_point,
                                        priority
                                    );
                                    Ok(())
                                }
                                Err(e) => {
                                    self.hook_slots[point_idx].attach(old);
                                    Err(format!("load error: {}", e))
                                }
                            }
                        })();
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (name, attach_point, path, hook_type);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::ReloadBuiltinHook {
                    name,
                    attach_point,
                    builtin_id,
                    response_tx,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let result = (|| -> Result<(), String> {
                            let point_idx = crate::config::parse_hook_point(&attach_point)
                                .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                            let old =
                                self.hook_slots[point_idx].detach(&name).ok_or_else(|| {
                                    format!("hook '{}' not found at point '{}'", name, attach_point)
                                })?;
                            let priority = old.priority;
                            let mgr = match self.hook_manager.as_ref() {
                                Some(m) => m,
                                None => {
                                    self.hook_slots[point_idx].attach(old);
                                    return Err("hook manager not available".to_string());
                                }
                            };
                            match mgr.load_builtin(name.clone(), builtin_id.as_str(), priority) {
                                Ok(program) => {
                                    self.hook_slots[point_idx].attach(program);
                                    log::info!(
                                        "Reloaded built-in hook '{}' ({}) at point {} (priority {})",
                                        name,
                                        builtin_id,
                                        attach_point,
                                        priority
                                    );
                                    Ok(())
                                }
                                Err(e) => {
                                    self.hook_slots[point_idx].attach(old);
                                    Err(format!("load error: {}", e))
                                }
                            }
                        })();
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (name, attach_point, builtin_id);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::SetHookEnabled {
                    name,
                    attach_point,
                    enabled,
                    response_tx,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let result = self.update_hook_program(&name, &attach_point, |program| {
                            program.enabled = enabled;
                        });
                        if result.is_ok() {
                            log::info!(
                                "{} hook '{}' at point {}",
                                if enabled { "Enabled" } else { "Disabled" },
                                name,
                                attach_point,
                            );
                        }
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (name, attach_point, enabled);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::SetHookPriority {
                    name,
                    attach_point,
                    priority,
                    response_tx,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let result = self.update_hook_program(&name, &attach_point, |program| {
                            program.priority = priority;
                        });
                        if result.is_ok() {
                            if let Some(point_idx) = crate::config::parse_hook_point(&attach_point)
                            {
                                self.hook_slots[point_idx]
                                    .programs
                                    .sort_by_key(|program| std::cmp::Reverse(program.priority));
                                log::info!(
                                    "Updated hook '{}' at point {} to priority {}",
                                    name,
                                    attach_point,
                                    priority,
                                );
                            } else {
                                log::error!(
                                    "hook point '{}' became invalid during priority update",
                                    attach_point
                                );
                            }
                        }
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (name, attach_point, priority);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::ListHooks { response_tx } => {
                    #[cfg(feature = "hooks")]
                    {
                        let hook_point_names = [
                            "PreIngress",
                            "PreDispatch",
                            "AnnounceReceived",
                            "PathUpdated",
                            "AnnounceRetransmit",
                            "LinkRequestReceived",
                            "LinkEstablished",
                            "LinkClosed",
                            "InterfaceUp",
                            "InterfaceDown",
                            "InterfaceConfigChanged",
                            "BackbonePeerConnected",
                            "BackbonePeerDisconnected",
                            "BackbonePeerIdleTimeout",
                            "BackbonePeerWriteStall",
                            "BackbonePeerPenalty",
                            "SendOnInterface",
                            "BroadcastOnAllInterfaces",
                            "DeliverLocal",
                            "TunnelSynthesize",
                            "Tick",
                        ];
                        let mut infos = Vec::new();
                        for (idx, slot) in self.hook_slots.iter().enumerate() {
                            let point_name = hook_point_names.get(idx).unwrap_or(&"Unknown");
                            for prog in &slot.programs {
                                infos.push(crate::event::HookInfo {
                                    name: prog.name.clone(),
                                    hook_type: prog.backend_name().to_string(),
                                    attach_point: point_name.to_string(),
                                    priority: prog.priority,
                                    enabled: prog.enabled,
                                    consecutive_traps: prog.consecutive_traps,
                                });
                            }
                        }
                        let _ = response_tx.send(infos);
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = response_tx.send(Vec::new());
                    }
                }
                Event::InterfaceConfigChanged(id) => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Interface { interface_id: id.0 };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::InterfaceConfigChanged as usize]
                                .programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.forward_hook_side_effects("InterfaceConfigChanged", e);
                        }
                    }
                    #[cfg(not(feature = "hooks"))]
                    let _ = id;
                }
                Event::BackbonePeerConnected {
                    server_interface_id,
                    peer_interface_id,
                    peer_ip,
                    peer_port,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        self.run_backbone_peer_hook(
                            "BackbonePeerConnected",
                            HookPoint::BackbonePeerConnected,
                            &BackbonePeerHookEvent {
                                server_interface_id,
                                peer_interface_id: Some(peer_interface_id),
                                peer_ip,
                                peer_port,
                                connected_for: Duration::ZERO,
                                had_received_data: false,
                                penalty_level: 0,
                                blacklist_for: Duration::ZERO,
                            },
                        );
                    }
                    #[cfg(not(feature = "hooks"))]
                    let _ = (server_interface_id, peer_interface_id, peer_ip, peer_port);
                }
                Event::BackbonePeerDisconnected {
                    server_interface_id,
                    peer_interface_id,
                    peer_ip,
                    peer_port,
                    connected_for,
                    had_received_data,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        self.run_backbone_peer_hook(
                            "BackbonePeerDisconnected",
                            HookPoint::BackbonePeerDisconnected,
                            &BackbonePeerHookEvent {
                                server_interface_id,
                                peer_interface_id: Some(peer_interface_id),
                                peer_ip,
                                peer_port,
                                connected_for,
                                had_received_data,
                                penalty_level: 0,
                                blacklist_for: Duration::ZERO,
                            },
                        );
                    }
                    #[cfg(not(feature = "hooks"))]
                    let _ = (
                        server_interface_id,
                        peer_interface_id,
                        peer_ip,
                        peer_port,
                        connected_for,
                        had_received_data,
                    );
                }
                Event::BackbonePeerIdleTimeout {
                    server_interface_id,
                    peer_interface_id,
                    peer_ip,
                    peer_port,
                    connected_for,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        self.run_backbone_peer_hook(
                            "BackbonePeerIdleTimeout",
                            HookPoint::BackbonePeerIdleTimeout,
                            &BackbonePeerHookEvent {
                                server_interface_id,
                                peer_interface_id: Some(peer_interface_id),
                                peer_ip,
                                peer_port,
                                connected_for,
                                had_received_data: false,
                                penalty_level: 0,
                                blacklist_for: Duration::ZERO,
                            },
                        );
                    }
                    #[cfg(not(feature = "hooks"))]
                    let _ = (
                        server_interface_id,
                        peer_interface_id,
                        peer_ip,
                        peer_port,
                        connected_for,
                    );
                }
                Event::BackbonePeerWriteStall {
                    server_interface_id,
                    peer_interface_id,
                    peer_ip,
                    peer_port,
                    connected_for,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        self.run_backbone_peer_hook(
                            "BackbonePeerWriteStall",
                            HookPoint::BackbonePeerWriteStall,
                            &BackbonePeerHookEvent {
                                server_interface_id,
                                peer_interface_id: Some(peer_interface_id),
                                peer_ip,
                                peer_port,
                                connected_for,
                                had_received_data: false,
                                penalty_level: 0,
                                blacklist_for: Duration::ZERO,
                            },
                        );
                    }
                    #[cfg(not(feature = "hooks"))]
                    let _ = (
                        server_interface_id,
                        peer_interface_id,
                        peer_ip,
                        peer_port,
                        connected_for,
                    );
                }
                Event::BackbonePeerPenalty {
                    server_interface_id,
                    peer_ip,
                    penalty_level,
                    blacklist_for,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        self.run_backbone_peer_hook(
                            "BackbonePeerPenalty",
                            HookPoint::BackbonePeerPenalty,
                            &BackbonePeerHookEvent {
                                server_interface_id,
                                peer_interface_id: None,
                                peer_ip,
                                peer_port: 0,
                                connected_for: Duration::ZERO,
                                had_received_data: false,
                                penalty_level,
                                blacklist_for,
                            },
                        );
                    }
                    #[cfg(not(feature = "hooks"))]
                    let _ = (server_interface_id, peer_ip, penalty_level, blacklist_for);
                }
                Event::Shutdown => {
                    self.event_tx.link_send_pool().close();
                    self.pending_link_frames.clear();
                    self.graceful_shutdown();
                    break;
                }
            }
        }
        self.link_manager.stop_receive_worker();
        self.stop_resource_preparations();
        self.event_tx.link_send_pool().close();
        self.pending_link_frames.clear();
    }
    pub(crate) fn handle_tunnel_synth_delivery(
        &mut self,
        raw: &[u8],
        receiving_interface: InterfaceId,
    ) {
        // Extract the data payload from the raw packet
        let packet = match RawPacket::unpack(raw) {
            Ok(p) => p,
            Err(_) => return,
        };

        match rns_core::transport::tunnel::validate_tunnel_synthesize_data(packet.data()) {
            Ok(validated) => {
                // Find the interface this tunnel belongs to by computing the expected
                // tunnel_id for each interface with wants_tunnel
                let iface_id = self
                    .interfaces
                    .iter()
                    .find(|(_, entry)| entry.info.wants_tunnel && entry.online && entry.enabled)
                    .map(|(id, _)| *id);

                if let Some(iface) = iface_id {
                    let now = time::now();
                    let tunnel_actions = self.engine.handle_tunnel(validated.tunnel_id, iface, now);
                    self.dispatch_all(tunnel_actions);
                }
            }
            Err(e) => {
                log::debug!("Tunnel synthesis validation failed: {}", e);
                if let Some(entry) = self.interfaces.get_mut(&receiving_interface) {
                    entry.stats.protocol_violations += 1;
                }
            }
        }
    }

    /// Synthesize a tunnel on an interface that wants it.
    ///
    /// Called when an interface with `wants_tunnel` comes up.
    pub(crate) fn synthesize_tunnel_for_interface(&mut self, interface: InterfaceId) {
        if let Some(ref identity) = self.transport_identity {
            let actions = self
                .engine
                .synthesize_tunnel(identity, interface, &mut self.rng);
            self.dispatch_all(actions);
        }
    }

    /// Emit a path request for a destination, as `Transport.request_path`
    /// without an interface.
    ///
    /// The request is `dest_hash || transport_id || random_tag`; since
    /// Reticulum 1.6.0 (upstream 156c7323) it always carries the transport
    /// identity. With `STAMP_PRS` the request also needs a stamp over the
    /// destination hash and tag: a cached one is appended at once, otherwise
    /// the request is recorded as pending and handed to the stamper, which
    /// posts it back as `Event::SendStampedPathRequest`.
    pub(crate) fn handle_request_path(&mut self, dest_hash: [u8; 16]) {
        let mut tag = [0u8; 16];
        self.rng.fill_bytes(&mut tag);

        if self.engine.stamp_prs() {
            match self.stamper.cached_path_request_stamp(&dest_hash, &tag) {
                Some(stamp) => {
                    let payload = crate::stamps::path_request_ext_payload(&stamp, 0);
                    let mut ext_payload = [0u8; rns_core::constants::PR_EXT_PAYLOAD_LENGTH];
                    ext_payload.copy_from_slice(&payload);
                    self.send_path_request(dest_hash, &tag, Some(&ext_payload), None);
                }
                None => {
                    self.engine
                        .record_outbound_path_request(dest_hash, time::now());
                    self.enqueue_path_request_stamp(dest_hash, tag.to_vec(), None);
                }
            }
            return;
        }
        self.send_path_request(dest_hash, &tag, None, None);
    }

    /// `Transport.enqueue_stamped_pr`: a full queue drops the request.
    pub(crate) fn enqueue_path_request_stamp(
        &mut self,
        dest_hash: [u8; 16],
        tag: Vec<u8>,
        interface: Option<InterfaceId>,
    ) {
        let job = crate::stamper::PathRequestStampJob {
            destination_hash: dest_hash,
            tag,
            interface,
        };
        if self.stamper.enqueue_path_request(job).is_err() {
            log::debug!(
                "Stamp queue full, dropping path request for {:02x?}",
                &dest_hash[..4]
            );
        }
    }

    /// Build and send a path request frame, broadcast when `interface` is
    /// `None` or on that interface alone when forwarding a local client's
    /// request.
    pub(crate) fn send_path_request(
        &mut self,
        dest_hash: [u8; 16],
        tag: &[u8],
        ext_payload: Option<&[u8; rns_core::constants::PR_EXT_PAYLOAD_LENGTH]>,
        interface: Option<InterfaceId>,
    ) {
        let Some(raw) = self.engine.build_path_request(&dest_hash, tag, ext_payload) else {
            return;
        };
        let now = time::now();
        match interface {
            Some(interface) => {
                self.dispatch_all(vec![TransportAction::SendOnInterface {
                    interface,
                    raw: raw.into(),
                }]);
            }
            None => {
                let Ok(packet) = RawPacket::unpack(&raw) else {
                    return;
                };
                self.engine.record_outbound_path_request(dest_hash, now);
                let actions = self.engine.handle_outbound(
                    &packet,
                    rns_core::constants::DESTINATION_PLAIN,
                    None,
                    now,
                );
                self.dispatch_all(actions);
            }
        }
    }

    /// Check if we should generate a proof for a delivered packet,
    /// and if so, sign and send it.
    pub(crate) fn get_event_sender(&self) -> crate::event::EventSender {
        // The driver doesn't directly have a sender, but node.rs creates the channel
        // and passes rx to the driver. We need to store a sender clone.
        // For now we use an internal sender that was set during construction.
        self.event_tx.clone()
    }

    /// Delay before first management announce after startup.
    const MANAGEMENT_ANNOUNCE_DELAY: f64 = 5.0;

    /// Tick the discovery announcer: start stamp generation if due, send announce if ready.
    pub(crate) fn tick_discovery_announcer(&mut self, now: f64) {
        let announcer = match self.interface_announcer.as_mut() {
            Some(a) => a,
            None => return,
        };

        announcer.set_stamp_requirements(self.engine.stamp_requirements());
        announcer.maybe_start(now);

        let stamp_result = match announcer.poll_ready() {
            Some(r) => r,
            None => return,
        };

        if !announcer.contains_interface(&stamp_result.interface_name) {
            log::debug!(
                "Discovery: dropping completed stamp for removed interface '{}'",
                stamp_result.interface_name
            );
            return;
        }

        let app_data = match stamp_result.app_data {
            Ok(app_data) => app_data,
            Err(error) => {
                log::error!(
                    "Discovery: suppressing announce for '{}': {}",
                    stamp_result.interface_name,
                    error
                );
                return;
            }
        };

        let identity = match self.transport_identity.as_ref() {
            Some(id) => id,
            None => {
                log::warn!("Discovery: stamp ready but no transport identity");
                return;
            }
        };

        // Discovery is a SINGLE destination — the dest hash includes the transport identity
        let identity_hash = identity.hash();
        let disc_dest = rns_core::destination::destination_hash(
            crate::discovery::APP_NAME,
            &["discovery", "interface"],
            Some(identity_hash),
        );
        let name_hash = self.discovery_name_hash;
        let random_hash = crate::common::management::announce_random_blob(&mut self.rng, now);

        let (announce_data, _) = match rns_core::announce::AnnounceData::pack(
            identity,
            &disc_dest,
            &name_hash,
            &random_hash,
            None,
            Some(&app_data),
        ) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("Discovery: failed to pack announce: {}", e);
                return;
            }
        };

        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: rns_core::constants::FLAG_UNSET,
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: rns_core::constants::DESTINATION_SINGLE,
            packet_type: rns_core::constants::PACKET_TYPE_ANNOUNCE,
        };

        let packet = match RawPacket::pack(
            flags,
            0,
            &disc_dest,
            None,
            rns_core::constants::CONTEXT_NONE,
            &announce_data,
        ) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("Discovery: failed to pack packet: {}", e);
                return;
            }
        };

        self.engine.register_destination(
            packet.destination_hash,
            rns_core::constants::DESTINATION_SINGLE,
        );
        let outbound_actions = self.engine.handle_outbound(
            &packet,
            rns_core::constants::DESTINATION_SINGLE,
            None,
            now,
        );
        log::debug!(
            "Discovery announce sent for interface '{}' ({} actions, dest={:02x?})",
            stamp_result.interface_name,
            outbound_actions.len(),
            &disc_dest[..4],
        );
        self.dispatch_all(outbound_actions);
    }

    /// Read RSS from /proc/self/statm (Linux only).
    pub(crate) fn rss_mb() -> Option<f64> {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let rss_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        Some(rss_pages as f64 * 4096.0 / (1024.0 * 1024.0))
    }

    pub(crate) fn parse_proc_kib(contents: &str, key: &str) -> Option<u64> {
        contents.lines().find_map(|line| {
            let value = line.strip_prefix(key)?;
            value.split_whitespace().next()?.parse().ok()
        })
    }

    pub(crate) fn proc_status_mb() -> Option<(f64, f64, f64, f64)> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let vm_rss = Self::parse_proc_kib(&status, "VmRSS:")? as f64 / 1024.0;
        let vm_hwm = Self::parse_proc_kib(&status, "VmHWM:")? as f64 / 1024.0;
        let vm_data = Self::parse_proc_kib(&status, "VmData:")? as f64 / 1024.0;
        let vm_swap = Self::parse_proc_kib(&status, "VmSwap:").unwrap_or(0) as f64 / 1024.0;
        Some((vm_rss, vm_hwm, vm_data, vm_swap))
    }

    pub(crate) fn smaps_rollup_mb() -> Option<MemoryRollup> {
        let smaps = std::fs::read_to_string("/proc/self/smaps_rollup").ok()?;
        let rss_kib = Self::parse_proc_kib(&smaps, "Rss:")?;
        let anon_kib = Self::parse_proc_kib(&smaps, "Anonymous:")?;
        let shared_clean_kib = Self::parse_proc_kib(&smaps, "Shared_Clean:").unwrap_or(0);
        let shared_dirty_kib = Self::parse_proc_kib(&smaps, "Shared_Dirty:").unwrap_or(0);
        let private_clean_kib = Self::parse_proc_kib(&smaps, "Private_Clean:").unwrap_or(0);
        let private_dirty_kib = Self::parse_proc_kib(&smaps, "Private_Dirty:").unwrap_or(0);
        let swap_kib = Self::parse_proc_kib(&smaps, "Swap:").unwrap_or(0);
        let file_est_kib = rss_kib.saturating_sub(anon_kib);
        Some((
            rss_kib as f64 / 1024.0,
            anon_kib as f64 / 1024.0,
            file_est_kib as f64 / 1024.0,
            shared_clean_kib as f64 / 1024.0,
            shared_dirty_kib as f64 / 1024.0,
            private_clean_kib as f64 / 1024.0,
            private_dirty_kib as f64 / 1024.0,
            swap_kib as f64 / 1024.0,
        ))
    }

    /// Log sizes of all major collections for memory growth diagnostics.
    pub(crate) fn log_memory_stats(&self) {
        let rss = Self::rss_mb()
            .map(|v| format!("{:.1}", v))
            .unwrap_or_else(|| "N/A".into());
        let (vm_rss, vm_hwm, vm_data, vm_swap) = Self::proc_status_mb()
            .map(|(rss, hwm, data, swap)| {
                (
                    format!("{rss:.1}"),
                    format!("{hwm:.1}"),
                    format!("{data:.1}"),
                    format!("{swap:.1}"),
                )
            })
            .unwrap_or_else(|| ("N/A".into(), "N/A".into(), "N/A".into(), "N/A".into()));
        let (
            smaps_rss,
            smaps_anon,
            smaps_file_est,
            smaps_shared_clean,
            smaps_shared_dirty,
            smaps_private_clean,
            smaps_private_dirty,
            smaps_swap,
        ) = Self::smaps_rollup_mb()
            .map(
                |(
                    rss,
                    anon,
                    file_est,
                    shared_clean,
                    shared_dirty,
                    private_clean,
                    private_dirty,
                    swap,
                )| {
                    (
                        format!("{rss:.1}"),
                        format!("{anon:.1}"),
                        format!("{file_est:.1}"),
                        format!("{shared_clean:.1}"),
                        format!("{shared_dirty:.1}"),
                        format!("{private_clean:.1}"),
                        format!("{private_dirty:.1}"),
                        format!("{swap:.1}"),
                    )
                },
            )
            .unwrap_or_else(|| {
                (
                    "N/A".into(),
                    "N/A".into(),
                    "N/A".into(),
                    "N/A".into(),
                    "N/A".into(),
                    "N/A".into(),
                    "N/A".into(),
                    "N/A".into(),
                )
            });
        log::info!(
            "MEMSTATS rss_mb={} vmrss_mb={} vmhwm_mb={} vmdata_mb={} vmswap_mb={} smaps_rss_mb={} smaps_anon_mb={} smaps_file_est_mb={} smaps_shared_clean_mb={} smaps_shared_dirty_mb={} smaps_private_clean_mb={} smaps_private_dirty_mb={} smaps_swap_mb={} known_dest={} known_dest_cap_evict={} path={} path_cap_evict={} announce={} reverse={}              link={} held_ann={} hashlist={} sig_cache={} ann_verify_q={} rate_lim={} blackhole={} tunnel={} ann_q_ifaces={} ann_q_nonempty={} ann_q_entries={} ann_q_bytes={} ann_q_iface_drop={}              pr_tags={} disc_pr={} sent_pkt={} completed={} local_dest={}              shared_ann={} lm_links={} hp_sessions={} proof_strat={}",
            rss,
            vm_rss,
            vm_hwm,
            vm_data,
            vm_swap,
            smaps_rss,
            smaps_anon,
            smaps_file_est,
            smaps_shared_clean,
            smaps_shared_dirty,
            smaps_private_clean,
            smaps_private_dirty,
            smaps_swap,
            self.known_destinations.len(),
            self.known_destinations_cap_evict_count,
            self.engine.path_table_count(),
            self.engine.path_destination_cap_evict_count(),
            self.engine.announce_table_count(),
            self.engine.reverse_table_count(),
            self.engine.link_table_count(),
            self.engine.held_announces_count(),
            self.engine.packet_hashlist_len(),
            self.engine.announce_sig_cache_len(),
            self.announce_verify_queue
                .lock()
                .map(|queue| queue.len())
                .unwrap_or(0),
            self.engine.rate_limiter_count(),
            self.engine.blackholed_count(),
            self.engine.tunnel_count(),
            self.engine.announce_queue_count(),
            self.engine.nonempty_announce_queue_count(),
            self.engine.queued_announce_count(),
            self.engine.queued_announce_bytes(),
            self.engine.announce_queue_interface_cap_drop_count(),
            self.engine.discovery_pr_tags_count(),
            self.engine.discovery_path_requests_count(),
            self.sent_packets.len(),
            self.completed_proofs.len(),
            self.local_destinations.len(),
            self.shared_announces.len(),
            self.link_manager.link_count(),
            self.holepunch_manager.session_count(),
            self.proof_strategies.len(),
        );
    }

    /// Emit management and/or blackhole announces if enabled and due.
    pub(crate) fn tick_management_announces(&mut self, now: f64) {
        if self.transport_identity.is_none() {
            return;
        }

        let uptime = now - self.started;

        // Wait for initial delay
        if !self.initial_announce_sent {
            if uptime < Self::MANAGEMENT_ANNOUNCE_DELAY {
                return;
            }
            self.initial_announce_sent = true;
            self.emit_management_announces(now);
            return;
        }

        // Periodic re-announce
        if now - self.last_management_announce >= self.management_announce_interval_secs {
            self.emit_management_announces(now);
        }
    }

    /// Emit management/blackhole announce packets through the engine outbound path.
    pub(crate) fn emit_management_announces(&mut self, now: f64) {
        use crate::management;

        self.last_management_announce = now;

        let identity = match self.transport_identity {
            Some(ref id) => id,
            None => return,
        };

        // Build announce packets first (immutable borrow of identity), then dispatch
        let mgmt_raw = if self.management_config.enable_remote_management {
            management::build_management_announce(identity, &mut self.rng, now, false)
        } else {
            None
        };

        let bh_raw = if self.management_config.publish_blackhole {
            management::build_blackhole_announce(identity, &mut self.rng, now, false)
        } else {
            None
        };

        let probe_raw = if self.probe_responder_hash.is_some() {
            management::build_probe_announce(identity, &mut self.rng, now, false)
        } else {
            None
        };

        self.emit_local_management_announce(mgmt_raw, now, "management destination");
        self.emit_local_management_announce(bh_raw, now, "blackhole info");
        self.emit_local_management_announce(probe_raw, now, "probe responder");
    }

    fn emit_local_management_announce(&mut self, raw: Option<Vec<u8>>, now: f64, label: &str) {
        if let Some(raw) = raw {
            if let Ok(packet) = RawPacket::unpack(&raw) {
                self.engine.register_destination(
                    packet.destination_hash,
                    rns_core::constants::DESTINATION_SINGLE,
                );
                let actions = self.engine.handle_outbound(
                    &packet,
                    rns_core::constants::DESTINATION_SINGLE,
                    None,
                    now,
                );
                self.dispatch_all(actions);
                log::debug!("Emitted {} announce", label);
            }
        }
    }

    /// How long a path-response announce is replayed for a repeated tag
    /// (Python `Destination.PR_TAG_WINDOW`).
    pub(crate) const LOCAL_PATH_RESPONSE_WINDOW: f64 = 30.0;
    /// Upper bound on cached path-response announces.
    pub(crate) const LOCAL_PATH_RESPONSE_MAX_ENTRIES: usize = 1024;

    /// Answer a path request for a destination hosted on this node, as Python
    /// `Transport.path_request()` does with
    /// `destination.announce(path_response=True, tag=tag, attached_interface=...)`.
    ///
    /// The announce has context `PATH_RESPONSE` and goes out only on the
    /// interface the request arrived on. A repeated tag within
    /// `LOCAL_PATH_RESPONSE_WINDOW` replays the same bytes, like
    /// `Destination.path_responses`.
    pub(crate) fn answer_local_path_request(
        &mut self,
        dest_hash: [u8; 16],
        tag: Vec<u8>,
        interface: InterfaceId,
    ) {
        let now = time::now();
        self.expire_local_path_responses(now);

        let key = (dest_hash, tag);
        let raw = if let Some((_, raw)) = self.local_path_responses.get(&key) {
            raw.clone()
        } else {
            let Some(raw) = self.build_local_path_response(&dest_hash, now) else {
                return;
            };
            if self.local_path_responses.len() >= Self::LOCAL_PATH_RESPONSE_MAX_ENTRIES {
                if let Some(oldest) = self
                    .local_path_responses
                    .iter()
                    .min_by(|a, b| a.1 .0.total_cmp(&b.1 .0))
                    .map(|(key, _)| key.clone())
                {
                    self.local_path_responses.remove(&oldest);
                }
            }
            self.local_path_responses.insert(key, (now, raw.clone()));
            raw
        };

        let Ok(packet) = RawPacket::unpack(&raw) else {
            return;
        };
        // Locally originated (hops 0), so the engine applies no announce
        // bandwidth queue, and an attached interface skips mode filtering.
        let actions = self.engine.handle_outbound(
            &packet,
            rns_core::constants::DESTINATION_SINGLE,
            Some(interface),
            now,
        );
        self.dispatch_all(actions);
        log::debug!(
            "Answered path request for local destination {:02x?} on interface {}",
            &dest_hash[..4],
            interface.0,
        );
    }

    /// Drop path-response announces older than the replay window.
    pub(crate) fn expire_local_path_responses(&mut self, now: f64) {
        self.local_path_responses
            .retain(|_, (created, _)| now - *created <= Self::LOCAL_PATH_RESPONSE_WINDOW);
    }

    /// Build a fresh `PATH_RESPONSE` announce for a local destination.
    fn build_local_path_response(&mut self, dest_hash: &[u8; 16], now: f64) -> Option<Vec<u8>> {
        use crate::management;

        if let Some(identity) = self.transport_identity.as_ref() {
            let identity_hash = *identity.hash();
            if self.probe_responder_hash == Some(*dest_hash) {
                return management::build_probe_announce(identity, &mut self.rng, now, true);
            }
            if self.management_config.enable_remote_management
                && *dest_hash == management::management_dest_hash(&identity_hash)
            {
                return management::build_management_announce(identity, &mut self.rng, now, true);
            }
            if self.management_config.publish_blackhole
                && *dest_hash == management::blackhole_dest_hash(&identity_hash)
            {
                return management::build_blackhole_announce(identity, &mut self.rng, now, true);
            }
        }

        if let Some(record) = self.shared_announces.get(dest_hash).cloned() {
            return self.build_shared_announce_raw(dest_hash, &record, true);
        }

        // Known gap: the driver only holds announce keys for SINGLE
        // destinations that were announced through the node API at least
        // once (`shared_announces`). A destination that is registered but
        // never announced cannot be answered here, whereas Python announces
        // it on demand from the Destination object.
        log::debug!(
            "Cannot answer path request for local destination {:02x?}: no announce record",
            &dest_hash[..4],
        );
        None
    }

    /// Handle a management request by querying engine state and sending a response.
    pub(crate) fn handle_management_request(
        &mut self,
        link_id: [u8; 16],
        path_hash: [u8; 16],
        data: Vec<u8>,
        request_id: [u8; 16],
        remote_identity: Option<([u8; 16], [u8; 64])>,
    ) {
        use crate::management;

        // ACL check for /status and /path (ALLOW_LIST), /list is ALLOW_ALL
        let is_restricted = path_hash == management::status_path_hash()
            || path_hash == management::path_path_hash();

        if is_restricted && !self.management_config.remote_management_allowed.is_empty() {
            match remote_identity {
                Some((identity_hash, _)) => {
                    if !self
                        .management_config
                        .remote_management_allowed
                        .contains(&identity_hash)
                    {
                        log::debug!("Management request denied: identity not in allowed list");
                        return;
                    }
                }
                None => {
                    log::debug!("Management request denied: peer not identified");
                    return;
                }
            }
        }

        let response_data = if path_hash == management::status_path_hash() {
            {
                let views: Vec<&dyn management::InterfaceStatusView> = self
                    .interfaces
                    .values()
                    .map(|e| e as &dyn management::InterfaceStatusView)
                    .collect();
                management::handle_status_request(
                    &data,
                    &self.engine,
                    &views,
                    self.started,
                    self.probe_responder_hash,
                )
            }
        } else if path_hash == management::path_path_hash() {
            management::handle_path_request(&data, &self.engine)
        } else if path_hash == management::list_path_hash() {
            management::handle_blackhole_list_request(&self.engine)
        } else {
            log::warn!("Unknown management path_hash: {:02x?}", &path_hash[..4]);
            None
        };

        if let Some(response) = response_data {
            let actions = self.link_manager.send_management_response(
                &link_id,
                &request_id,
                &response,
                &mut self.rng,
            );
            self.dispatch_link_actions(actions);
        }
    }
}
