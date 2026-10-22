use super::*;

/// Maximum nesting depth for re-dispatching actions injected by hooks.
#[cfg(feature = "hooks")]
const MAX_HOOK_INJECTION_DEPTH: usize = 4;

impl Driver {
    pub(crate) fn handle_confirmed_outbound(
        &mut self,
        raw: Vec<u8>,
        dest_type: u8,
        replay: Option<Box<crate::common::event::AnnounceReplay>>,
        completion: crate::link_send::Completion,
    ) {
        use crate::link_send::LinkSendError;
        if self.is_draining() {
            completion.finish(Err(LinkSendError::Draining));
            return;
        }
        let Ok(packet) = RawPacket::unpack(&raw) else {
            completion.finish(Err(LinkSendError::PacketBuildFailed));
            return;
        };
        if let Some(replay) = replay {
            let crate::common::event::AnnounceReplay {
                dest_hash,
                name_hash,
                identity_prv_key,
                app_data,
            } = *replay;
            self.shared_announces.insert(
                dest_hash,
                SharedAnnounceRecord {
                    name_hash,
                    identity_prv_key,
                    app_data,
                },
            );
        }
        let now = time::now();
        if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_DATA {
            self.sent_packets
                .insert(packet.packet_hash, (packet.destination_hash, now));
        }
        // These APIs originate hops=0 packets, so announcement relay bandwidth
        // queues do not apply. Retain the normal routing and per-send hooks.
        let actions = self.engine.handle_outbound(&packet, dest_type, None, now);
        let mut selected = 0;
        for action in actions {
            match action {
                TransportAction::SendOnInterface { interface, raw } => {
                    selected += 1;
                    self.tracked_link_send = Some((packet.packet_hash, completion.branch()));
                    self.dispatch_all(vec![TransportAction::SendOnInterface { interface, raw }]);
                    if let Some((_, branch)) = self.tracked_link_send.take() {
                        branch.finish(Err(LinkSendError::Rejected));
                    }
                }
                TransportAction::BroadcastOnAllInterfaces { raw, exclude } => {
                    // Broadcast hooks still run in dispatch_broadcast_action.
                    self.tracked_link_send = Some((packet.packet_hash, completion.branch()));
                    self.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
                        raw,
                        exclude,
                    }]);
                    if let Some((_, branch)) = self.tracked_link_send.take() {
                        branch.finish(Err(LinkSendError::Rejected));
                    }
                    selected += 1;
                }
                other => self.dispatch_all(vec![other]),
            }
        }
        completion.finish(if selected == 0 {
            Err(LinkSendError::NoRoute)
        } else {
            Ok(())
        });
    }
    /// Pending frames own admission permits until actual writer completion,
    /// bounding this queue together with driver events and in-flight writes.
    pub(crate) fn flush_pending_link_frames(&mut self) {
        use crate::link_send::LinkSendError;
        // Called on every driver iteration; avoid seeding a hasher when idle.
        if self.pending_link_frames.is_empty() {
            return;
        }
        let mut blocked = std::collections::HashSet::new();
        for _ in 0..self.pending_link_frames.len() {
            let mut frame = self.pending_link_frames.pop_front().unwrap();
            if blocked.contains(&frame.interface) {
                self.pending_link_frames.push_back(frame);
                continue;
            }
            let Some(entry) = self
                .interfaces
                .get_mut(&frame.interface)
                .filter(|e| e.online && e.enabled)
            else {
                if let Some(completion) = frame.completion.take() {
                    completion.finish(Err(LinkSendError::InterfaceUnavailable));
                }
                continue;
            };
            match entry
                .writer
                .enqueue_confirmed(&frame.data, &mut frame.completion)
            {
                Ok(()) => {
                    entry.stats.txb += frame.data.len() as u64;
                    entry.stats.tx_packets += 1;
                    if frame.is_announce {
                        entry
                            .stats
                            .record_outgoing_announce_bytes(time::now(), frame.data.len());
                    }
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && frame.completion.is_some() =>
                {
                    blocked.insert(frame.interface);
                    self.pending_link_frames.push_back(frame);
                }
                Err(error) => {
                    if let Some(completion) = frame.completion.take() {
                        completion.finish(Err(LinkSendError::WriteFailed(error.to_string())));
                    }
                }
            }
        }
    }
    pub(crate) fn authorize_direct_connect_proposal(
        &mut self,
        policy: crate::event::HolePunchPolicy,
        link_id: [u8; 16],
        peer_identity: Option<[u8; 16]>,
        payload: &[u8],
    ) -> Option<bool> {
        if let Err(error) = rns_core::holepunch::HolePunchEngine::validate_upgrade_request(payload)
        {
            log::warn!("Dropping malformed direct-connect proposal: {}", error);
            return None;
        }
        Some(self.authorize_direct_connect(policy, link_id, peer_identity))
    }

    pub(crate) fn authorize_direct_connect(
        &mut self,
        policy: crate::event::HolePunchPolicy,
        link_id: [u8; 16],
        peer_identity: Option<[u8; 16]>,
    ) -> bool {
        match policy {
            crate::event::HolePunchPolicy::Reject => false,
            crate::event::HolePunchPolicy::AcceptAll => true,
            crate::event::HolePunchPolicy::IdentifiedOnly => peer_identity.is_some(),
            crate::event::HolePunchPolicy::AskApp => self.callbacks.on_direct_connect_proposed(
                rns_core::types::LinkId(link_id),
                peer_identity.map(rns_core::types::IdentityHash),
            ),
        }
    }

    pub(crate) fn maybe_generate_proof(&mut self, dest_hash: [u8; 16], packet_hash: &[u8; 32]) {
        use rns_core::types::ProofStrategy;

        let (strategy, identity) = match self.proof_strategies.get(&dest_hash) {
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

        // Sign the packet hash to create the proof
        let signature = match identity.sign(packet_hash) {
            Ok(sig) => sig,
            Err(e) => {
                log::warn!("Failed to sign proof for {:02x?}: {:?}", &dest_hash[..4], e);
                return;
            }
        };

        // Build explicit proof: [packet_hash:32][signature:64]
        let mut proof_data = Vec::with_capacity(96);
        proof_data.extend_from_slice(packet_hash);
        proof_data.extend_from_slice(&signature);

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
                None,
                time::now(),
            );
            self.dispatch_all(actions);
            log::debug!(
                "Generated proof for packet on dest {:02x?}",
                &dest_hash[..4]
            );
        }
    }

    /// Handle an inbound proof packet: validate and fire on_proof callback.
    pub(crate) fn handle_inbound_proof(
        &mut self,
        dest_hash: [u8; 16],
        proof_data: &[u8],
        _raw_packet_hash: &[u8; 32],
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

            (candidates[0], &proof_data[..64])
        } else {
            log::debug!("Unsupported proof length: {} bytes", proof_data.len());
            return;
        };

        // Look up the tracked sent packet
        if let Some((tracked_dest, sent_time)) = self.sent_packets.remove(&tracked_hash) {
            // Validate the proof signature using the destination's public key
            // (matches Python's PacketReceipt.validate_proof behavior)
            if let Some(announced) = self.known_destination_announced(&tracked_dest) {
                let identity =
                    rns_crypto::identity::Identity::from_public_key(&announced.public_key).ok();
                let mut sig = [0u8; 64];
                sig.copy_from_slice(signature);
                if !identity.is_some_and(|identity| identity.verify(&sig, &tracked_hash)) {
                    log::debug!("Proof signature invalid for {:02x?}", &tracked_hash[..4],);
                    return;
                }
                let _ = self.mark_known_destination_used(&tracked_dest);
            } else {
                log::debug!(
                    "No known identity for dest {:02x?}, accepting proof without signature check",
                    &tracked_dest[..4],
                );
            }

            let now = time::now();
            let rtt = now - sent_time;
            log::debug!(
                "Proof received for {:02x?} rtt={:.3}s",
                &tracked_hash[..4],
                rtt,
            );
            self.completed_proofs.insert(tracked_hash, (rtt, now));
            self.callbacks.on_proof(
                rns_core::types::DestHash(tracked_dest),
                rns_core::types::PacketHash(tracked_hash),
                rtt,
            );
        } else {
            log::debug!(
                "Proof for unknown packet {:02x?} on dest {:02x?}",
                &tracked_hash[..4],
                &dest_hash[..4],
            );
        }
    }

    /// Serve sockets the driver poller reported ready: loop sources read
    /// (queueing what they decode), and writers that had bytes left over
    /// continue writing.
    pub(crate) fn handle_ready_sources(&mut self, ready: &polling::Events) {
        self.rx.serve_sources(ready);
        for event in ready.iter() {
            let (interface, is_write) = crate::interface::loop_writer::key_target(event.key);
            if is_write && event.writable {
                if let Some(entry) = self.interfaces.get_mut(&interface) {
                    entry.writer.flush_pending();
                }
            }
        }
    }

    /// Write out every driver-run writer's buffered frames.
    pub(crate) fn flush_writers(&mut self) {
        for entry in self.interfaces.values_mut() {
            entry.writer.flush_pending();
        }
    }

    /// Wake writers left asleep by deferred forwarding sends.
    pub(crate) fn wake_writers(&mut self) {
        for id in std::mem::take(&mut self.writers_to_wake) {
            if let Some(entry) = self.interfaces.get_mut(&id) {
                entry.writer.wake();
            }
        }
    }

    /// [`Self::interface_send_deferred`] at the current time, reading the
    /// clock only while a send retry is pending.
    pub(crate) fn interface_send_deferred_now(entry: &InterfaceEntry) -> bool {
        entry.send_retry_at.is_some() && Self::interface_send_deferred(entry, Instant::now())
    }

    pub(crate) fn interface_send_deferred(entry: &InterfaceEntry, now: Instant) -> bool {
        // Async writers bound their own waiting and stop waiting on a stalled
        // peer, refusing only frames that do not fit. Skipping sends to them
        // for the whole retry window would discard traffic that the drained
        // queue could have accepted.
        if entry.async_writer_metrics.is_some() {
            return false;
        }
        matches!(entry.send_retry_at, Some(retry_at) if now < retry_at)
    }

    pub(crate) fn record_send_result(
        entry: &mut InterfaceEntry,
        result: &std::io::Result<()>,
        context: &str,
        interface_id: InterfaceId,
    ) {
        match result {
            Ok(()) => {
                entry.send_retry_at = None;
                entry.send_retry_backoff = Duration::ZERO;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let next_backoff = if entry.send_retry_backoff.is_zero() {
                    SEND_RETRY_BACKOFF_MIN
                } else {
                    (entry.send_retry_backoff * 2).min(SEND_RETRY_BACKOFF_MAX)
                };
                entry.send_retry_backoff = next_backoff;
                entry.send_retry_at = Some(Instant::now() + next_backoff);
                log::debug!(
                    "[{}] {} deferred after WouldBlock; retry in {:?}",
                    interface_id.0,
                    context,
                    next_backoff
                );
            }
            Err(e) => {
                entry.send_retry_at = None;
                entry.send_retry_backoff = Duration::ZERO;
                log::warn!("[{}] {} failed: {}", interface_id.0, context, e);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn dispatch_send_on_interface_action(
        &mut self,
        interface: InterfaceId,
        raw: rns_core::transport::types::PacketBytes,
        hook_injected: &mut Vec<TransportAction>,
    ) {
        self.dispatch_send_on_interface_action_with_hooks(interface, raw, hook_injected, true);
    }

    /// Apply an outbound packet hook outcome. Returns the bytes to send and the
    /// ratchet lease that covers them, or `None` when the packet must not be
    /// sent. A replacement takes its own ratchet lease and becomes the packet
    /// a pending confirmed link send waits for.
    #[cfg(feature = "hooks")]
    fn apply_outbound_hook_outcome(
        &mut self,
        outcome: PacketHookOutcome,
        raw: rns_core::transport::types::PacketBytes,
        ratchet_lease: Option<crate::local_ratchet::AnnouncementLease>,
    ) -> Option<(
        rns_core::transport::types::PacketBytes,
        Option<crate::local_ratchet::AnnouncementLease>,
    )> {
        match outcome {
            PacketHookOutcome::Keep => Some((raw, ratchet_lease)),
            PacketHookOutcome::Drop => None,
            PacketHookOutcome::Replace(packet) => {
                let lease = match crate::local_ratchet::AnnouncementLease::acquire(
                    self.event_tx.local_ratchets(),
                    &packet.raw,
                ) {
                    Ok(lease) => lease,
                    Err(error) => {
                        log::warn!("suppressing local announcement: {error}");
                        return None;
                    }
                };
                drop(ratchet_lease);
                self.retarget_tracked_link_send(&raw, &packet);
                Some((packet.raw.into(), lease))
            }
        }
    }

    /// Send `raw` on `interface`. When `run_hooks` is false the
    /// `SendOnInterface` hook point is skipped; this is used for actions that
    /// hooks injected themselves, so a hook cannot re-trigger itself.
    fn dispatch_send_on_interface_action_with_hooks(
        &mut self,
        interface: InterfaceId,
        raw: rns_core::transport::types::PacketBytes,
        _hook_injected: &mut Vec<TransportAction>,
        run_hooks: bool,
    ) {
        #[cfg(not(feature = "hooks"))]
        let _ = run_hooks;
        let ratchet_lease = match crate::local_ratchet::AnnouncementLease::acquire(
            self.event_tx.local_ratchets(),
            &raw,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                log::warn!("suppressing local announcement: {error}");
                return;
            }
        };

        #[cfg(feature = "hooks")]
        let (raw, ratchet_lease) = if run_hooks && self.hooks_attached(HookPoint::SendOnInterface) {
            let pkt_ctx = rns_hooks::PacketContext {
                flags: if raw.is_empty() { 0 } else { raw[0] },
                hops: if raw.len() > 1 { raw[1] } else { 0 },
                destination_hash: extract_dest_hash(&raw),
                context: 0,
                packet_hash: [0; 32],
                interface_id: interface.0,
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
                &mut self.hook_slots[HookPoint::SendOnInterface as usize].programs,
                &self.hook_manager,
                &engine_ref,
                &ctx,
                now,
                provider_events_enabled,
            ) {
                self.collect_hook_side_effects("SendOnInterface", e, _hook_injected);
                let max_len = self.hook_packet_limit(interface);
                outcome = self.packet_hook_outcome(HookPoint::SendOnInterface, e, max_len);
            }
            let Some(applied) = self.apply_outbound_hook_outcome(outcome, raw, ratchet_lease)
            else {
                return;
            };
            applied
        } else {
            (raw, ratchet_lease)
        };

        let is_announce = raw.len() > 2 && (raw[0] & 0x03) == 0x01;
        let is_path_request = is_outbound_path_request(&raw, &self.path_request_dest);
        if is_path_request {
            let live_rate = self.interfaces.get(&interface).map(|entry| {
                (
                    entry.stats.outgoing_path_request_freq(),
                    entry.stats.outgoing_path_request_samples(),
                )
            });
            if live_rate.is_some_and(|(freq, samples)| {
                self.engine
                    .should_egress_limit_path_request(interface, freq, samples)
            }) {
                log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                    "Blocking recursive path request on interface {} due to active egress limiting",
                    interface.0,
                );
                return;
            }
        }
        if is_announce {
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Announce:dispatching to iface {} (len={}, online={})",
                interface.0,
                raw.len(),
                self.interfaces
                    .get(&interface)
                    .map(|e| e.online && e.enabled)
                    .unwrap_or(false)
            );
        }
        // Keep targeted-send failures interface-specific. In particular, an
        // attached interface that disappeared must not fall back to broadcast
        // or be reported as a generic inability of every interface to send.
        let Some(entry) = self.interfaces.get_mut(&interface) else {
            log::warn!("[{}] cannot send on missing interface", interface.0);
            return;
        };
        if !entry.online || !entry.enabled {
            log::debug!(
                "[{}] cannot send on unavailable interface (online={}, enabled={})",
                interface.0,
                entry.online,
                entry.enabled
            );
            return;
        }
        if ratchet_lease.is_some() && self.tracked_link_send.is_none() {
            let Ok(permit) = self.event_tx.link_send_pool().try_acquire() else {
                return;
            };
            let (completion, _receipt) = crate::link_send::Completion::new(permit);
            self.tracked_link_send =
                Some((RawPacket::unpack(&raw).unwrap().packet_hash, completion));
        }
        let tracked = self.tracked_link_send.as_ref().is_some_and(|(hash, _)| {
            RawPacket::unpack(&raw).is_ok_and(|packet| packet.packet_hash == *hash)
        });
        if tracked {
            let data = if let Some(ref state) = entry.ifac {
                ifac::mask_outbound(&raw, state)
            } else {
                raw.to_vec()
            };
            let (_, mut completion) = self.tracked_link_send.take().unwrap();
            completion.retain_ratchet(ratchet_lease.clone());
            self.pending_link_frames.push_back(PendingLinkFrame {
                interface,
                data,
                is_announce,
                completion: Some(completion),
            });
            return;
        }
        if Self::interface_send_deferred_now(entry) {
            return;
        }
        let data = if let Some(ref ifac_state) = entry.ifac {
            ifac::mask_outbound(&raw, ifac_state)
        } else {
            Vec::new()
        };
        let send_len = if entry.ifac.is_some() {
            data.len()
        } else {
            raw.len()
        };
        entry.stats.txb += send_len as u64;
        entry.stats.tx_packets += 1;
        if is_announce {
            entry
                .stats
                .record_outgoing_announce_bytes(time::now(), send_len);
        }
        if is_path_request {
            let now = time::now();
            entry
                .stats
                .record_outgoing_path_request_bytes(now, send_len);
            self.engine.update_interface_freqs(
                interface,
                entry.stats.incoming_announce_freq(),
                entry.stats.incoming_path_request_freq(),
                entry.stats.outgoing_path_request_freq(),
                entry.stats.outgoing_path_request_samples(),
            );
        }
        // Forwarded frames postpone the writer wakeup; the driver wakes each
        // touched writer once before it next waits for events.
        let send_result = if entry.ifac.is_some() {
            entry.writer.send_frame_deferred(&data)
        } else {
            entry.writer.send_shared_deferred(&raw)
        };
        if self.writers_to_wake.last() != Some(&interface) {
            self.writers_to_wake.push(interface);
        }
        let sent_ok = send_result.is_ok();
        Self::record_send_result(entry, &send_result, "send", interface);
        if sent_ok && is_announce {
            let sent_slice: &[u8] = if entry.ifac.is_some() { &data } else { &raw };
            let header_type = (sent_slice[0] >> 6) & 0x03;
            let dest_start = if header_type == 1 { 18usize } else { 2usize };
            let dest_preview = if sent_slice.len() >= dest_start + 4 {
                format!("{:02x?}", &sent_slice[dest_start..dest_start + 4])
            } else {
                "??".into()
            };
            log::debug!(
                "Announce:SENT on iface {} (len={}, h={}, dest=[{}])",
                interface.0,
                sent_slice.len(),
                header_type,
                dest_preview
            );
        }
    }

    pub(crate) fn dispatch_broadcast_action(
        &mut self,
        raw: rns_core::transport::types::PacketBytes,
        exclude: Option<InterfaceId>,
        _hook_injected: &mut Vec<TransportAction>,
        run_hooks: bool,
    ) {
        #[cfg(not(feature = "hooks"))]
        let _ = run_hooks;
        let ratchet_lease = match crate::local_ratchet::AnnouncementLease::acquire(
            self.event_tx.local_ratchets(),
            &raw,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                log::warn!("suppressing local announcement: {error}");
                return;
            }
        };

        #[cfg(feature = "hooks")]
        let (raw, ratchet_lease) = if run_hooks
            && self.hooks_attached(HookPoint::BroadcastOnAllInterfaces)
        {
            let pkt_ctx = rns_hooks::PacketContext {
                flags: if raw.is_empty() { 0 } else { raw[0] },
                hops: if raw.len() > 1 { raw[1] } else { 0 },
                destination_hash: extract_dest_hash(&raw),
                context: 0,
                packet_hash: [0; 32],
                interface_id: 0,
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
                &mut self.hook_slots[HookPoint::BroadcastOnAllInterfaces as usize].programs,
                &self.hook_manager,
                &engine_ref,
                &ctx,
                now,
                provider_events_enabled,
            ) {
                self.collect_hook_side_effects("BroadcastOnAllInterfaces", e, _hook_injected);
                // The replacement goes out on every selected interface, so it
                // must fit the smallest of them.
                let max_len = self
                    .interfaces
                    .values()
                    .filter(|entry| entry.online && entry.enabled && Some(entry.id) != exclude)
                    .map(|entry| self.hook_packet_limit(entry.id))
                    .min()
                    .unwrap_or(rns_core::constants::MTU);
                outcome = self.packet_hook_outcome(HookPoint::BroadcastOnAllInterfaces, e, max_len);
            }
            let Some(applied) = self.apply_outbound_hook_outcome(outcome, raw, ratchet_lease)
            else {
                return;
            };
            applied
        } else {
            (raw, ratchet_lease)
        };

        let is_announce = raw.len() > 2 && (raw[0] & 0x03) == 0x01;
        let is_path_request = is_outbound_path_request(&raw, &self.path_request_dest);
        if ratchet_lease.is_some() && self.tracked_link_send.is_none() {
            let Ok(permit) = self.event_tx.link_send_pool().try_acquire() else {
                return;
            };
            let (completion, _receipt) = crate::link_send::Completion::new(permit);
            self.tracked_link_send =
                Some((RawPacket::unpack(&raw).unwrap().packet_hash, completion));
        }
        if self.tracked_link_send.as_ref().is_some_and(|(hash, _)| {
            RawPacket::unpack(&raw).is_ok_and(|packet| packet.packet_hash == *hash)
        }) {
            let (_, mut completion) = self.tracked_link_send.take().unwrap();
            completion.retain_ratchet(ratchet_lease.clone());
            let mut selected = 0;
            for entry in self.interfaces.values() {
                if entry.online && entry.enabled && Some(entry.id) != exclude {
                    selected += 1;
                    let data = entry
                        .ifac
                        .as_ref()
                        .map_or_else(|| raw.to_vec(), |state| ifac::mask_outbound(&raw, state));
                    self.pending_link_frames.push_back(PendingLinkFrame {
                        interface: entry.id,
                        data,
                        is_announce,
                        completion: Some(completion.branch()),
                    });
                }
            }
            completion.finish(if selected == 0 {
                Err(crate::link_send::LinkSendError::NoRoute)
            } else {
                Ok(())
            });
            return;
        }
        for entry in self.interfaces.values_mut() {
            if entry.online && entry.enabled && Some(entry.id) != exclude {
                if Self::interface_send_deferred_now(entry) {
                    continue;
                }
                let data = if let Some(ref ifac_state) = entry.ifac {
                    ifac::mask_outbound(&raw, ifac_state)
                } else {
                    Vec::new()
                };
                let send_len = if entry.ifac.is_some() {
                    data.len()
                } else {
                    raw.len()
                };
                entry.stats.txb += send_len as u64;
                entry.stats.tx_packets += 1;
                if is_announce {
                    entry
                        .stats
                        .record_outgoing_announce_bytes(time::now(), send_len);
                }
                if is_path_request {
                    let now = time::now();
                    entry
                        .stats
                        .record_outgoing_path_request_bytes(now, send_len);
                    self.engine.update_interface_freqs(
                        entry.id,
                        entry.stats.incoming_announce_freq(),
                        entry.stats.incoming_path_request_freq(),
                        entry.stats.outgoing_path_request_freq(),
                        entry.stats.outgoing_path_request_samples(),
                    );
                }
                let send_result = if entry.ifac.is_some() {
                    entry.writer.send_frame(&data)
                } else {
                    entry.writer.send_frame(&raw)
                };
                Self::record_send_result(entry, &send_result, "broadcast", entry.id);
            }
        }
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
                    entry
                        .stats
                        .record_incoming_path_request_bytes(now, raw.len());
                    self.engine.update_interface_freqs(
                        receiving_interface,
                        entry.stats.incoming_announce_freq(),
                        entry.stats.incoming_path_request_freq(),
                        entry.stats.outgoing_path_request_freq(),
                        entry.stats.outgoing_path_request_samples(),
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
            if let Some(packet) = crate::packet_header::PacketHeader::unpack(&raw) {
                let arrived_on_stale_link_route = packet.flags.packet_type
                    == rns_core::constants::PACKET_TYPE_DATA
                    && packet.flags.destination_type == rns_core::constants::DESTINATION_LINK
                    && self
                        .link_manager
                        .get_link_route_hint(&destination_hash)
                        .is_some_and(|route| route.interface != receiving_interface);
                if arrived_on_stale_link_route {
                    // The active link has failed over, but an in-flight packet
                    // arrived on its former interface. Do not let this arrival
                    // suppress the copy still travelling on the current route.
                    self.engine.forget_packet_hash(&hashlist_hash);
                    return;
                }
            }
            let link_actions = self.link_manager.handle_local_delivery(
                destination_hash,
                &raw,
                packet_hash,
                receiving_interface,
                &mut self.rng,
            );
            if link_actions.is_empty() {
                let packet_hash = delivered_packet_hash(&raw, packet_hash);
                if let Some(packet) = crate::packet_header::PacketHeader::unpack(&raw) {
                    if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_PROOF {
                        self.handle_inbound_proof(destination_hash, packet.data, &packet_hash);
                        return;
                    }
                }
                self.maybe_generate_proof(destination_hash, &packet_hash);
                self.callbacks.on_local_delivery(
                    rns_core::types::DestHash(destination_hash),
                    raw.to_vec(),
                    rns_core::types::PacketHash(packet_hash),
                );
            } else {
                self.dispatch_link_actions(link_actions);
            }
        } else {
            let packet_hash = delivered_packet_hash(&raw, packet_hash);
            // Every transported proof is also offered to local receipts. The
            // header carries all the check needs; the packet hash is known.
            if let Some(packet) = crate::packet_header::PacketHeader::unpack(&raw) {
                if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_PROOF {
                    self.handle_inbound_proof(destination_hash, packet.data, &packet_hash);
                    return;
                }
            }
            self.maybe_generate_proof(destination_hash, &packet_hash);
            self.callbacks.on_local_delivery(
                rns_core::types::DestHash(destination_hash),
                raw.to_vec(),
                rns_core::types::PacketHash(packet_hash),
            );
        }
    }

    /// Dispatch a list of transport actions.
    pub(crate) fn dispatch_all(&mut self, actions: Vec<TransportAction>) {
        self.dispatch_all_with_ingress_class(actions, false);
    }

    pub(crate) fn dispatch_all_with_ingress_class(
        &mut self,
        actions: Vec<TransportAction>,
        ingress_limited: bool,
    ) {
        self.dispatch_actions_at_depth(actions, ingress_limited, 0);
    }

    /// Re-dispatch actions injected by hooks one nesting level below
    /// `depth`. Injected actions skip the per-action packet hooks
    /// (`SendOnInterface`, `BroadcastOnAllInterfaces`, `DeliverLocal`), and
    /// nesting through other hook points is capped at
    /// `MAX_HOOK_INJECTION_DEPTH`; anything beyond that is logged and dropped.
    #[cfg(feature = "hooks")]
    fn dispatch_hook_injected(&mut self, injected: Vec<TransportAction>, depth: usize) {
        if injected.is_empty() {
            return;
        }
        if depth >= MAX_HOOK_INJECTION_DEPTH {
            log::warn!(
                "dropping {} hook-injected action(s): nesting depth limit {} reached",
                injected.len(),
                MAX_HOOK_INJECTION_DEPTH
            );
            return;
        }
        self.dispatch_actions_at_depth(injected, false, depth + 1);
    }

    /// Dispatch `actions`. `depth` is 0 for top-level actions and counts how
    /// many hook-injection levels deep the batch is otherwise; per-action
    /// packet hooks run only at depth 0.
    fn dispatch_actions_at_depth(
        &mut self,
        actions: Vec<TransportAction>,
        ingress_limited: bool,
        depth: usize,
    ) {
        let run_packet_hooks = depth == 0;
        #[cfg(feature = "hooks")]
        let mut hook_injected: Vec<TransportAction> = Vec::new();
        #[cfg(not(feature = "hooks"))]
        let mut hook_injected: Vec<TransportAction> = Vec::new();

        for action in actions {
            match action {
                TransportAction::SendOnInterface { interface, raw } => {
                    self.dispatch_send_on_interface_action_with_hooks(
                        interface,
                        raw,
                        &mut hook_injected,
                        run_packet_hooks,
                    );
                }
                TransportAction::BroadcastOnAllInterfaces { raw, exclude } => {
                    self.dispatch_broadcast_action(
                        raw,
                        exclude,
                        &mut hook_injected,
                        run_packet_hooks,
                    );
                }
                TransportAction::DeliverLocal {
                    destination_hash,
                    raw,
                    packet_hash,
                    receiving_interface,
                } => {
                    self.dispatch_deliver_local_action(
                        destination_hash,
                        raw,
                        packet_hash,
                        receiving_interface,
                        ingress_limited,
                        &mut hook_injected,
                        run_packet_hooks,
                    );
                }
                TransportAction::AnnounceReceived(announce) => {
                    let ReceivedAnnounce {
                        destination_hash,
                        identity_hash,
                        public_key,
                        name_hash,
                        ratchet,
                        app_data,
                        hops,
                        receiving_interface,
                        rx,
                        ..
                    } = *announce;
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Announce {
                            destination_hash,
                            hops,
                            interface_id: receiving_interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        {
                            let exec = run_hook_inner(
                                &mut self.hook_slots[HookPoint::AnnounceReceived as usize].programs,
                                &self.hook_manager,
                                &engine_ref,
                                &ctx,
                                now,
                                provider_events_enabled,
                            );
                            if let Some(ref e) = exec {
                                self.collect_hook_side_effects(
                                    "AnnounceReceived",
                                    e,
                                    &mut hook_injected,
                                );
                                if e.hook_result.as_ref().is_some_and(|r| r.is_drop()) {
                                    continue;
                                }
                            }
                        }
                    }

                    // Check if this is a discovery announce (matched by name_hash
                    // since discovery is a SINGLE destination — its dest hash varies
                    // with the sender's identity).
                    if name_hash == self.discovery_name_hash && self.discover_interfaces {
                        if let Some(ref app_data) = app_data {
                            if let Some(mut discovered) =
                                crate::discovery::parse_interface_announce_with_cache(
                                    app_data,
                                    &identity_hash,
                                    hops,
                                    self.discovery_required_value,
                                    &mut self.discovery_stamp_cache,
                                )
                            {
                                crate::discovery::apply_transport_autoconnect_mode(
                                    &mut discovered,
                                    self.engine.transport_enabled(),
                                    self.autoconnect_interface_mode,
                                );
                                if let Err(e) =
                                    self.discovered_interfaces.store_received(&mut discovered)
                                {
                                    log::warn!("Failed to store discovered interface: {}", e);
                                } else {
                                    let stack = match (
                                        discovered.impl_name.as_deref(),
                                        discovered.impl_version.as_deref(),
                                    ) {
                                        (Some(name), Some(version))
                                            if !name.is_empty() && !version.is_empty() =>
                                        {
                                            format!("{name} {version}")
                                        }
                                        _ => "unknown implementation".into(),
                                    };
                                    log::debug!(
                                        "Discovered interface '{}' ({}; {}) at {}:{} [stamp={}]",
                                        discovered.name,
                                        discovered.interface_type,
                                        stack,
                                        discovered.reachable_on.as_deref().unwrap_or("?"),
                                        discovered
                                            .port
                                            .map(|p| p.to_string())
                                            .unwrap_or_else(|| "?".into()),
                                        discovered.stamp_value,
                                    );
                                }
                                #[cfg(feature = "iface-backbone")]
                                self.upsert_discovered_backbone_peer_pool_candidate(discovered);
                            }
                        }
                    }
                    // Still cache the identity and notify callbacks

                    if let (Some(store), Some(ratchet)) = (&self.ratchet_store, ratchet) {
                        let entry = crate::storage::RatchetEntry {
                            ratchet,
                            received_at: time::now(),
                        };
                        if let Err(err) = store.remember(destination_hash, entry) {
                            log::warn!(
                                "failed to persist ratchet for {:02x}{:02x}{:02x}{:02x}..: {}",
                                destination_hash[0],
                                destination_hash[1],
                                destination_hash[2],
                                destination_hash[3],
                                err
                            );
                        }
                    }

                    // Cache the announced identity
                    let announced = crate::destination::AnnouncedIdentity {
                        dest_hash: rns_core::types::DestHash(destination_hash),
                        identity_hash: rns_core::types::IdentityHash(identity_hash),
                        public_key,
                        app_data: app_data.clone(),
                        hops,
                        received_at: time::now(),
                        receiving_interface,
                        rssi: rx.rssi,
                        snr: rx.snr,
                    };
                    self.upsert_known_destination(destination_hash, announced.clone());
                    log::debug!(
                        "Announce:validated dest={:02x}{:02x}{:02x}{:02x}.. hops={}",
                        destination_hash[0],
                        destination_hash[1],
                        destination_hash[2],
                        destination_hash[3],
                        hops,
                    );
                    self.callbacks.on_announce(announced);
                }
                TransportAction::PathUpdated {
                    destination_hash,
                    hops,
                    next_hop,
                    interface,
                } => {
                    log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                        "Destination {:02x?} is now {} hops away via {:02x?} on interface {}",
                        &destination_hash[..4],
                        hops,
                        &next_hop[..4],
                        interface.0,
                    );
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Announce {
                            destination_hash,
                            hops,
                            interface_id: interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::PathUpdated as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects("PathUpdated", e, &mut hook_injected);
                        }
                    }
                    #[cfg(not(feature = "hooks"))]
                    let _ = interface;

                    let _ = self.mark_known_destination_used(&destination_hash);
                    self.callbacks
                        .on_path_updated(rns_core::types::DestHash(destination_hash), hops);
                }
                TransportAction::ForwardToLocalClients { raw, exclude } => {
                    for entry in self.interfaces.values_mut() {
                        if entry.online
                            && entry.enabled
                            && entry.info.is_local_client
                            && Some(entry.id) != exclude
                        {
                            if Self::interface_send_deferred_now(entry) {
                                continue;
                            }
                            let data = if let Some(ref ifac_state) = entry.ifac {
                                ifac::mask_outbound(&raw, ifac_state)
                            } else {
                                raw.to_vec()
                            };
                            entry.stats.txb += data.len() as u64;
                            entry.stats.tx_packets += 1;
                            let send_result = entry.writer.send_frame(&data);
                            Self::record_send_result(
                                entry,
                                &send_result,
                                "forward to local client",
                                entry.id,
                            );
                        }
                    }
                }
                TransportAction::ForwardPlainBroadcast {
                    raw,
                    to_local,
                    exclude,
                } => {
                    for entry in self.interfaces.values_mut() {
                        if entry.online
                            && entry.enabled
                            && entry.info.is_local_client == to_local
                            && Some(entry.id) != exclude
                        {
                            if Self::interface_send_deferred_now(entry) {
                                continue;
                            }
                            let data = if let Some(ref ifac_state) = entry.ifac {
                                ifac::mask_outbound(&raw, ifac_state)
                            } else {
                                raw.to_vec()
                            };
                            entry.stats.txb += data.len() as u64;
                            entry.stats.tx_packets += 1;
                            let send_result = entry.writer.send_frame(&data);
                            Self::record_send_result(
                                entry,
                                &send_result,
                                "forward plain broadcast",
                                entry.id,
                            );
                        }
                    }
                }
                TransportAction::CacheAnnounce { packet_hash, raw } => {
                    if let Some(ref cache) = self.announce_cache {
                        if let Err(e) = cache.store(&packet_hash, &raw, None) {
                            log::warn!("Failed to cache announce: {}", e);
                        }
                    }
                }
                TransportAction::TunnelSynthesize {
                    interface,
                    data,
                    dest_hash,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let pkt_ctx = rns_hooks::PacketContext {
                            flags: 0,
                            hops: 0,
                            destination_hash: dest_hash,
                            context: 0,
                            packet_hash: [0; 32],
                            interface_id: interface.0,
                            data_offset: 0,
                            data_len: data.len() as u32,
                        };
                        let ctx = HookContext::Packet {
                            ctx: &pkt_ctx,
                            raw: &data,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        // The hook sees the synthesis payload, not a packet, so
                        // `Modify` acts as `Continue` and its bytes are ignored.
                        {
                            let exec = run_hook_inner(
                                &mut self.hook_slots[HookPoint::TunnelSynthesize as usize].programs,
                                &self.hook_manager,
                                &engine_ref,
                                &ctx,
                                now,
                                provider_events_enabled,
                            );
                            if let Some(ref e) = exec {
                                self.collect_hook_side_effects(
                                    "TunnelSynthesize",
                                    e,
                                    &mut hook_injected,
                                );
                                if e.hook_result.as_ref().is_some_and(|r| r.is_drop()) {
                                    continue;
                                }
                            }
                        }
                    }
                    // Pack as BROADCAST DATA PLAIN packet and send on interface
                    let flags = rns_core::packet::PacketFlags {
                        header_type: rns_core::constants::HEADER_1,
                        context_flag: rns_core::constants::FLAG_UNSET,
                        transport_type: rns_core::constants::TRANSPORT_BROADCAST,
                        destination_type: rns_core::constants::DESTINATION_PLAIN,
                        packet_type: rns_core::constants::PACKET_TYPE_DATA,
                    };
                    if let Ok(packet) = rns_core::packet::RawPacket::pack(
                        flags,
                        0,
                        &dest_hash,
                        None,
                        rns_core::constants::CONTEXT_NONE,
                        &data,
                    ) {
                        if let Some(entry) = self.interfaces.get_mut(&interface) {
                            if entry.online && entry.enabled {
                                let raw = if let Some(ref ifac_state) = entry.ifac {
                                    ifac::mask_outbound(&packet.raw, ifac_state)
                                } else {
                                    packet.raw
                                };
                                entry.stats.txb += raw.len() as u64;
                                entry.stats.tx_packets += 1;
                                if let Err(e) = entry.writer.send_frame(&raw) {
                                    log::warn!(
                                        "[{}] tunnel synthesize send failed: {}",
                                        entry.info.id.0,
                                        e
                                    );
                                }
                            }
                        }
                    }
                }
                TransportAction::TunnelEstablished {
                    tunnel_id,
                    interface,
                } => {
                    log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                        "Tunnel established: {:02x?} on interface {}",
                        &tunnel_id[..4],
                        interface.0
                    );
                }
                TransportAction::AnnounceRetransmit {
                    destination_hash,
                    hops,
                    interface,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Announce {
                            destination_hash,
                            hops,
                            interface_id: interface.map(|i| i.0).unwrap_or(0),
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::AnnounceRetransmit as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects(
                                "AnnounceRetransmit",
                                e,
                                &mut hook_injected,
                            );
                        }
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (destination_hash, hops, interface);
                    }
                }
                TransportAction::LinkRequestReceived {
                    link_id,
                    destination_hash: _,
                    receiving_interface,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: receiving_interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkRequestReceived as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects(
                                "LinkRequestReceived",
                                e,
                                &mut hook_injected,
                            );
                        }
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (link_id, receiving_interface);
                    }
                }
                TransportAction::LinkEstablished { link_id, interface } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkEstablished as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects(
                                "LinkEstablished",
                                e,
                                &mut hook_injected,
                            );
                        }
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (link_id, interface);
                    }
                }
                TransportAction::LinkClosed { link_id } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: 0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkClosed as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects("LinkClosed", e, &mut hook_injected);
                        }
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = link_id;
                    }
                }
                TransportAction::ProtocolViolation { interface } => {
                    if let Some(entry) = self.interfaces.get_mut(&interface) {
                        entry.stats.protocol_violations += 1;
                    }
                }
                TransportAction::AnnounceLocalPathResponse {
                    destination_hash,
                    tag,
                    interface,
                } => {
                    self.answer_local_path_request(destination_hash, tag, interface);
                }
            }
        }

        // Dispatch any actions injected by hooks during action processing
        #[cfg(feature = "hooks")]
        self.dispatch_hook_injected(hook_injected, depth);
        #[cfg(not(feature = "hooks"))]
        let _ = depth;
    }

    /// Dispatch link manager actions.
    pub(crate) fn dispatch_link_actions(&mut self, actions: Vec<LinkManagerAction>) {
        #[cfg(feature = "hooks")]
        let mut hook_injected: Vec<TransportAction> = Vec::new();

        for action in actions {
            match action {
                LinkManagerAction::SendPacket {
                    raw,
                    dest_type,
                    mut attached_interface,
                } => {
                    // Take the bytes instead of copying them; a resource part
                    // is not hashed, since nothing reads its hash.
                    let mut decoded = RawPacket::unpack_outbound(raw);
                    if dest_type == rns_core::constants::DESTINATION_LINK
                        && attached_interface.is_none()
                    {
                        if let Ok(packet) = &decoded {
                            let link_id = packet.destination_hash;
                            if let Some(route_hint) =
                                self.link_manager.get_link_route_hint(&link_id)
                            {
                                attached_interface = Some(route_hint.interface);
                                if packet.flags.header_type == rns_core::constants::HEADER_1 {
                                    if let Some(next_hop) = route_hint.transport_id {
                                        let raw = inject_transport_header(&packet.raw, &next_hop);
                                        // Reparse only when routing changed the wire header,
                                        // releasing the old payload copies first.
                                        drop(decoded);
                                        decoded = RawPacket::unpack_outbound(raw);
                                        log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                                            "Link SendPacket rewrite: link={:02x?} iface={} header=1->2 tid={:02x?}",
                                            &link_id[..4],
                                            route_hint.interface.0,
                                            &next_hop[..4]
                                        );
                                    } else {
                                        log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                                            "Link SendPacket route: link={:02x?} iface={} header=1 (no transport_id)",
                                            &link_id[..4],
                                            route_hint.interface.0
                                        );
                                    }
                                }
                            } else {
                                log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                                    "Link SendPacket no route hint: link={:02x?}",
                                    &link_id[..4]
                                );
                            }
                        }
                    }

                    // Route through the transport engine's outbound path
                    match decoded {
                        Ok(packet) => {
                            self.link_manager.record_outbound_packet(&packet);
                            // Track only packets a proof can answer. Kept until
                            // expiry, the others filled the table under load.
                            if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_DATA
                                && !packet.is_unproven_link_data()
                            {
                                self.sent_packets.insert(
                                    packet.packet_hash,
                                    (packet.destination_hash, time::now()),
                                );
                            }
                            let transport_actions = self.engine.handle_outbound(
                                &packet,
                                dest_type,
                                attached_interface,
                                time::now(),
                            );
                            self.dispatch_all(transport_actions);
                        }
                        Err(e) => {
                            log::warn!("LinkManager SendPacket: failed to unpack: {:?}", e);
                        }
                    }
                }
                LinkManagerAction::LinkEstablished {
                    link_id,
                    dest_hash,
                    hops,
                    rebalanced_at,
                    rtt,
                    is_initiator,
                } => {
                    if is_initiator && rebalanced_at.is_some() {
                        self.engine
                            .rebalance_destination_path_hops(&dest_hash, hops);
                    }
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: 0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkEstablished as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects(
                                "LinkEstablished",
                                e,
                                &mut hook_injected,
                            );
                        }
                    }
                    log::info!(
                        "Link established: {:02x?} rtt={:.3}s initiator={}",
                        &link_id[..4],
                        rtt,
                        is_initiator,
                    );
                    self.callbacks.on_link_established(
                        rns_core::types::LinkId(link_id),
                        rns_core::types::DestHash(dest_hash),
                        rtt,
                        is_initiator,
                    );
                }
                LinkManagerAction::LinkClosed { link_id, reason } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: 0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkClosed as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects("LinkClosed", e, &mut hook_injected);
                        }
                    }
                    log::info!("Link closed: {:02x?} reason={:?}", &link_id[..4], reason);
                    self.holepunch_manager.link_closed(&link_id);
                    self.callbacks
                        .on_link_closed(rns_core::types::LinkId(link_id), reason);
                }
                LinkManagerAction::RemoteIdentified {
                    link_id,
                    identity_hash,
                    public_key,
                } => {
                    if self.engine.is_blackholed(&identity_hash, time::now()) {
                        log::debug!(
                            "Terminating link {:02x?} from blackholed identity {:02x?}",
                            &link_id[..4],
                            &identity_hash[..4],
                        );
                        let teardown_actions = self.link_manager.teardown_link(&link_id);
                        self.dispatch_link_actions(teardown_actions);
                        continue;
                    }
                    log::debug!(
                        "Remote identified on link {:02x?}: {:02x?}",
                        &link_id[..4],
                        &identity_hash[..4],
                    );
                    self.callbacks.on_remote_identified(
                        rns_core::types::LinkId(link_id),
                        rns_core::types::IdentityHash(identity_hash),
                        public_key,
                    );
                }
                LinkManagerAction::RegisterLinkDest { link_id } => {
                    // Register the link_id as a LINK destination in the transport engine
                    self.engine
                        .register_destination(link_id, rns_core::constants::DESTINATION_LINK);
                }
                LinkManagerAction::DeregisterLinkDest { link_id } => {
                    self.engine.deregister_destination(&link_id);
                }
                LinkManagerAction::ManagementRequest {
                    link_id,
                    path_hash,
                    data,
                    request_id,
                    remote_identity,
                } => {
                    self.handle_management_request(
                        link_id,
                        path_hash,
                        data,
                        request_id,
                        remote_identity,
                    );
                }
                LinkManagerAction::ResourceReceived {
                    link_id,
                    data,
                    metadata,
                } => {
                    self.callbacks.on_resource_received(
                        rns_core::types::LinkId(link_id),
                        data,
                        metadata,
                    );
                }
                LinkManagerAction::ResourceFileReceived { link_id, resource } => {
                    self.callbacks
                        .on_resource_file_received(rns_core::types::LinkId(link_id), resource);
                }
                LinkManagerAction::ResourceCompleted { link_id } => {
                    self.callbacks
                        .on_resource_completed(rns_core::types::LinkId(link_id));
                }
                LinkManagerAction::ResourceFailed { link_id, error } => {
                    log::debug!("Resource failed on link {:02x?}: {}", &link_id[..4], error);
                    self.callbacks
                        .on_resource_failed(rns_core::types::LinkId(link_id), error);
                }
                LinkManagerAction::ResourceProgress {
                    link_id,
                    received,
                    total,
                } => {
                    self.callbacks.on_resource_progress(
                        rns_core::types::LinkId(link_id),
                        received,
                        total,
                    );
                }
                LinkManagerAction::ResourceStreamCompleted {
                    link_id,
                    transfer_id,
                } => {
                    self.callbacks.on_resource_stream_completed(
                        rns_core::types::LinkId(link_id),
                        transfer_id,
                    );
                }
                LinkManagerAction::ResourceStreamFailed {
                    link_id,
                    transfer_id,
                    error,
                } => {
                    self.callbacks.on_resource_stream_failed(
                        rns_core::types::LinkId(link_id),
                        transfer_id,
                        error,
                    );
                }
                LinkManagerAction::ResourceStreamProgress {
                    link_id,
                    transfer_id,
                    transferred,
                    total,
                } => {
                    self.callbacks.on_resource_stream_progress(
                        rns_core::types::LinkId(link_id),
                        transfer_id,
                        transferred,
                        total,
                    );
                }
                LinkManagerAction::ResourceAcceptQuery {
                    link_id,
                    resource_hash,
                    transfer_size,
                    has_metadata,
                } => {
                    let accept = self.callbacks.on_resource_accept_query(
                        rns_core::types::LinkId(link_id),
                        resource_hash.clone(),
                        transfer_size,
                        has_metadata,
                    );
                    let accept_actions = self.link_manager.accept_resource(
                        &link_id,
                        &resource_hash,
                        accept,
                        &mut self.rng,
                    );
                    // Re-dispatch (recursive but bounded: accept_resource won't produce more AcceptQuery)
                    self.dispatch_link_actions(accept_actions);
                }
                LinkManagerAction::ChannelMessageReceived {
                    link_id,
                    msgtype,
                    payload,
                } => {
                    // Intercept hole-punch signaling messages (0xFE00..=0xFE04)
                    if HolePunchManager::is_holepunch_message(msgtype) {
                        let configured_policy = self.holepunch_manager.policy();
                        if msgtype == rns_core::holepunch::UPGRADE_REQUEST {
                            let peer_identity = self.link_manager.remote_identity_hash(&link_id);
                            let Some(accept) = self.authorize_direct_connect_proposal(
                                configured_policy,
                                link_id,
                                peer_identity,
                                &payload,
                            ) else {
                                continue;
                            };
                            self.holepunch_manager.set_policy(if accept {
                                crate::event::HolePunchPolicy::AcceptAll
                            } else {
                                crate::event::HolePunchPolicy::Reject
                            });
                        }
                        let derived_key = self.link_manager.get_derived_key(&link_id);
                        let tx = self.get_event_sender();
                        let (handled, hp_actions) = self.holepunch_manager.handle_signal(
                            link_id,
                            msgtype,
                            payload,
                            derived_key.as_deref(),
                            &tx,
                        );
                        self.holepunch_manager.set_policy(configured_policy);
                        if handled {
                            self.dispatch_holepunch_actions(hp_actions);
                        }
                    } else {
                        self.callbacks.on_channel_message(
                            rns_core::types::LinkId(link_id),
                            msgtype,
                            payload,
                        );
                    }
                }
                LinkManagerAction::LinkDataReceived {
                    link_id,
                    context,
                    data,
                } => {
                    self.callbacks
                        .on_link_data(rns_core::types::LinkId(link_id), context, data);
                }
                LinkManagerAction::ResponseReceived {
                    link_id,
                    request_id,
                    data,
                    metadata,
                } => {
                    self.callbacks.on_response_with_metadata(
                        rns_core::types::LinkId(link_id),
                        request_id,
                        data,
                        metadata,
                    );
                }
                LinkManagerAction::RequestFailed {
                    link_id,
                    request_id,
                    reason,
                } => {
                    self.callbacks.on_request_failed(
                        rns_core::types::LinkId(link_id),
                        request_id,
                        reason,
                    );
                }
                LinkManagerAction::LinkRequestReceived {
                    link_id,
                    receiving_interface,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: receiving_interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkRequestReceived as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects(
                                "LinkRequestReceived",
                                e,
                                &mut hook_injected,
                            );
                        }
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (link_id, receiving_interface);
                    }
                }
                LinkManagerAction::ProtocolViolation {
                    receiving_interface,
                } => {
                    if let Some(entry) = self.interfaces.get_mut(&receiving_interface) {
                        entry.stats.protocol_violations += 1;
                    }
                }
            }
        }

        // Dispatch any actions injected by hooks during action processing
        #[cfg(feature = "hooks")]
        self.dispatch_hook_injected(hook_injected, 0);
    }

    /// Dispatch hole-punch manager actions.
    pub(crate) fn dispatch_holepunch_actions(&mut self, actions: Vec<HolePunchManagerAction>) {
        for action in actions {
            match action {
                HolePunchManagerAction::SendChannelMessage {
                    link_id,
                    msgtype,
                    payload,
                } => {
                    if let Ok(link_actions) = self.link_manager.send_channel_message(
                        &link_id,
                        msgtype,
                        &payload,
                        &mut self.rng,
                    ) {
                        self.dispatch_link_actions(link_actions);
                    }
                }
                HolePunchManagerAction::DirectConnectEstablished {
                    link_id,
                    session_id,
                    interface_id,
                    rtt,
                    mtu,
                } => {
                    log::info!(
                        "Direct connection established for link {:02x?} session {:02x?} iface {} rtt={:.1}ms mtu={}",
                        &link_id[..4], &session_id[..4], interface_id.0, rtt * 1000.0, mtu
                    );
                    // Redirect the link's path to use the direct interface
                    self.engine
                        .redirect_path(&link_id, interface_id, time::now());
                    self.link_manager
                        .set_link_route_hint(&link_id, interface_id, None);
                    // Update the link's RTT and MTU to reflect the direct path
                    self.link_manager.set_link_rtt(&link_id, rtt);
                    self.link_manager.set_link_mtu(&link_id, mtu);
                    // Reset inbound timer — set_rtt shortens the keepalive/stale
                    // intervals, so without this the link goes stale immediately
                    self.link_manager.record_link_inbound(&link_id);
                    // Flush holepunch signaling messages from the channel window
                    self.link_manager.flush_channel_tx(&link_id);
                    self.callbacks.on_direct_connect_established(
                        rns_core::types::LinkId(link_id),
                        interface_id,
                    );
                }
                HolePunchManagerAction::DirectConnectFailed {
                    link_id,
                    session_id,
                    reason,
                } => {
                    log::debug!(
                        "Direct connection failed for link {:02x?} session {:02x?} reason={}",
                        &link_id[..4],
                        &session_id[..4],
                        reason
                    );
                    self.callbacks
                        .on_direct_connect_failed(rns_core::types::LinkId(link_id), reason);
                }
            }
        }
    }
}

fn is_outbound_path_request(raw: &[u8], path_request_dest: &[u8; 16]) -> bool {
    crate::packet_header::PacketHeader::unpack(raw).is_some_and(|packet| {
        packet.destination_hash == path_request_dest
            && packet.flags.destination_type == rns_core::constants::DESTINATION_PLAIN
            && packet.flags.packet_type == rns_core::constants::PACKET_TYPE_DATA
    })
}

/// The hash of a delivered packet. The engine leaves a link resource part
/// unhashed, so hash it here for the consumers that read the hash.
fn delivered_packet_hash(raw: &[u8], packet_hash: [u8; 32]) -> [u8; 32] {
    if RawPacket::is_link_resource_part_wire(raw) {
        if let Ok(packet) = RawPacket::unpack(raw) {
            return packet.packet_hash;
        }
    }
    packet_hash
}

#[cfg(test)]
mod classification_tests {
    use super::*;

    #[test]
    fn outbound_path_request_matches_full_unpack() {
        let destination = [0x53; 16];
        for flags in 0..=u8::MAX {
            for hops in [
                0,
                rns_core::constants::PATHFINDER_M - 1,
                rns_core::constants::PATHFINDER_M,
                255,
            ] {
                for matching in [false, true] {
                    let mut raw = [0x31; 80];
                    raw[0] = flags;
                    raw[1] = hops;
                    let start = if flags & 0x40 == 0 { 2 } else { 18 };
                    if matching {
                        raw[start..start + 16].copy_from_slice(&destination);
                    }
                    for len in (0..=40).chain([80]) {
                        let raw = &raw[..len];
                        let expected = RawPacket::unpack(raw).is_ok_and(|packet| {
                            packet.destination_hash == destination
                                && packet.flags.destination_type
                                    == rns_core::constants::DESTINATION_PLAIN
                                && packet.flags.packet_type == rns_core::constants::PACKET_TYPE_DATA
                        });
                        assert_eq!(
                            is_outbound_path_request(raw, &destination),
                            expected,
                            "flags={flags} hops={hops} len={len} matching={matching}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn delivered_resource_parts_are_hashed_on_demand() {
        let packet = |context| {
            RawPacket::pack(
                rns_core::packet::PacketFlags {
                    header_type: rns_core::constants::HEADER_1,
                    context_flag: rns_core::constants::FLAG_UNSET,
                    transport_type: rns_core::constants::TRANSPORT_BROADCAST,
                    destination_type: rns_core::constants::DESTINATION_LINK,
                    packet_type: rns_core::constants::PACKET_TYPE_DATA,
                },
                0,
                &[0x42; 16],
                None,
                context,
                b"payload",
            )
            .unwrap()
        };
        let part = packet(rns_core::constants::CONTEXT_RESOURCE);
        assert_eq!(delivered_packet_hash(&part.raw, [0; 32]), part.packet_hash);
        // Any other packet keeps the hash the engine computed.
        let channel = packet(rns_core::constants::CONTEXT_CHANNEL);
        assert_eq!(delivered_packet_hash(&channel.raw, [7; 32]), [7; 32]);
    }
}

#[cfg(all(test, feature = "rns-hooks-builtin"))]
mod hook_injection_tests {
    use super::*;
    use crate::interface::Writer;
    use rns_core::transport::types::InterfaceInfo;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    struct NoopCallbacks;

    impl Callbacks for NoopCallbacks {
        fn on_announce(&mut self, _: crate::common::destination::AnnouncedIdentity) {}
        fn on_path_updated(&mut self, _: rns_core::types::DestHash, _: u8) {}
        fn on_local_delivery(
            &mut self,
            _: rns_core::types::DestHash,
            _: Vec<u8>,
            _: rns_core::types::PacketHash,
        ) {
        }
    }

    struct RecordingWriter(Arc<Mutex<Vec<Vec<u8>>>>);

    impl Writer for RecordingWriter {
        fn send_frame(&mut self, data: &[u8]) -> std::io::Result<()> {
            self.0.lock().unwrap().push(data.to_vec());
            Ok(())
        }
    }

    fn interface_info(id: u64) -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId(id),
            name: format!("test-{}", id),
            mode: rns_core::constants::MODE_FULL,
            gravity: 0,
            recursive_prs: false,
            announces_from_internal: true,
            announces_to_internal: None,
            out_capable: true,
            in_capable: true,
            bitrate: None,
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: rns_core::constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: rns_core::constants::MTU as u32,
            ia_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: 0.0,
            ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
        }
    }

    fn driver_with_interface(id: u64) -> (Driver, Arc<Mutex<Vec<Vec<u8>>>>) {
        let (tx, rx) = crate::event::channel();
        let mut driver = Driver::new(
            super::super::tests::make_transport_config(false),
            rx,
            tx,
            Box::new(NoopCallbacks),
        );
        driver.set_tick_interval_handle(Arc::new(AtomicU64::new(1000)));
        let sent = Arc::new(Mutex::new(Vec::new()));
        driver.interfaces.insert(
            InterfaceId(id),
            InterfaceEntry {
                id: InterfaceId(id),
                info: interface_info(id),
                writer: Box::new(RecordingWriter(sent.clone())),
                async_writer_metrics: None,
                enabled: true,
                online: true,
                dynamic: false,
                ifac: None,
                stats: InterfaceStats::default(),
                interface_type: String::new(),
                send_retry_at: None,
                send_retry_backoff: Duration::ZERO,
            },
        );
        (driver, sent)
    }

    static HOOK_ID_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn attach_builtin(
        driver: &mut Driver,
        point: HookPoint,
        hook: impl rns_hooks::BuiltinHook,
    ) -> String {
        let id = format!(
            "test.dispatch.hook_injection.{}.{}",
            std::process::id(),
            HOOK_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        rns_hooks::register_builtin_hook(id.clone(), hook).unwrap();
        let program = driver
            .hook_manager
            .as_ref()
            .expect("hook manager")
            .load_builtin(id.clone(), id.as_str(), 0)
            .unwrap();
        driver.hook_slots[point as usize].attach(program);
        id
    }

    #[test]
    fn send_hook_injecting_a_send_runs_once_and_sends_the_injected_frame() {
        let (mut driver, sent) = driver_with_interface(1);
        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = calls.clone();
        attach_builtin(
            &mut driver,
            HookPoint::SendOnInterface,
            move |_call: rns_hooks::BuiltinHookCall<'_>, host: &mut rns_hooks::BuiltinHookHost| {
                hook_calls.fetch_add(1, Ordering::SeqCst);
                host.inject_action(rns_hooks::ActionWire::SendOnInterface {
                    interface: 1,
                    raw: vec![0x00, 0x00, 0x42],
                });
                Ok(rns_hooks::HookResult::continue_result())
            },
        );

        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(1),
            raw: vec![0x00, 0x00, 0x01].into(),
        }]);

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let sent = sent.lock().unwrap();
        assert_eq!(
            sent.as_slice(),
            &[vec![0x00, 0x00, 0x01], vec![0x00, 0x00, 0x42]]
        );
    }

    #[test]
    fn self_injecting_path_updated_hook_stops_at_nesting_limit() {
        let (mut driver, _sent) = driver_with_interface(1);
        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = calls.clone();
        attach_builtin(
            &mut driver,
            HookPoint::PathUpdated,
            move |_call: rns_hooks::BuiltinHookCall<'_>, host: &mut rns_hooks::BuiltinHookHost| {
                hook_calls.fetch_add(1, Ordering::SeqCst);
                host.inject_action(rns_hooks::ActionWire::PathUpdated {
                    destination_hash: [0x11; 16],
                    hops: 1,
                    next_hop: [0x22; 16],
                    interface: 1,
                });
                Ok(rns_hooks::HookResult::continue_result())
            },
        );

        driver.dispatch_all(vec![TransportAction::PathUpdated {
            destination_hash: [0x11; 16],
            hops: 1,
            next_hop: [0x22; 16],
            interface: InterfaceId(1),
        }]);

        assert_eq!(calls.load(Ordering::SeqCst), MAX_HOOK_INJECTION_DEPTH + 1);
    }
}
