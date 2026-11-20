use super::*;

impl Driver {
    pub(crate) fn upsert_known_destination(
        &mut self,
        dest_hash: [u8; 16],
        announced: crate::destination::AnnouncedIdentity,
    ) {
        if let Some(existing) = self.known.entries.get_mut(&dest_hash) {
            existing.announced = announced;
            return;
        }

        self.enforce_known_destination_cap(true);
        self.known.entries.insert(
            dest_hash,
            KnownDestinationState {
                announced,
                was_used: false,
                last_used_at: None,
                retained: false,
                stamp: None,
                stamp_value: rns_core::stamp::StampValue::ZERO,
                lr_cost: None,
            },
        );
    }

    pub(crate) fn record_known_destination_stamp(
        &mut self,
        dest_hash: [u8; 16],
        stamp: Option<[u8; rns_core::constants::STAMP_LENGTH]>,
        stamp_value: rns_core::stamp::StampValue,
        lr_cost: Option<rns_core::stamp::StampCost>,
    ) {
        if let Some(state) = self.known.entries.get_mut(&dest_hash) {
            state.stamp = stamp;
            state.stamp_value = stamp_value;
            state.lr_cost = lr_cost;
        }
    }

    /// Recall the link request stamp cost announced by a destination.
    pub fn recall_link_cost(&self, dest_hash: &[u8; 16]) -> Option<rns_core::stamp::StampCost> {
        self.known
            .entries
            .get(dest_hash)
            .and_then(|state| state.lr_cost)
    }

    pub(crate) fn recall_stamp_value(
        &self,
        dest_hash: &[u8; 16],
    ) -> Option<rns_core::stamp::StampValue> {
        self.known
            .entries
            .get(dest_hash)
            .map(|state| state.stamp_value)
    }

    pub(crate) fn known_destination_entry(
        dest_hash: [u8; 16],
        state: &KnownDestinationState,
    ) -> KnownDestinationEntry {
        KnownDestinationEntry {
            dest_hash,
            identity_hash: state.announced.identity_hash.0,
            public_key: state.announced.public_key,
            app_data: state.announced.app_data.clone(),
            hops: state.announced.hops,
            received_at: state.announced.received_at,
            receiving_interface: state.announced.receiving_interface,
            was_used: state.was_used,
            last_used_at: state.last_used_at,
            retained: state.retained,
            stamp: state.stamp,
            stamp_value: state.stamp_value,
            lr_cost: state.lr_cost,
        }
    }

    /// Fingerprint of a known destination as storage persists it.
    pub(crate) fn known_destination_fingerprint(state: &KnownDestinationState) -> u64 {
        crate::storage::known_destination_fingerprint(
            &state.announced.identity_hash.0,
            &state.announced.public_key,
            state.announced.app_data.as_deref(),
            state.announced.hops,
            state.announced.received_at,
            state.announced.receiving_interface.0,
            state.was_used,
            state.last_used_at,
            state.retained,
            state.stamp.as_ref().map(|stamp| &stamp[..]),
            state.stamp_value,
            state.lr_cost,
        )
    }

    /// The known destinations that differ from their last flushed
    /// fingerprint, and the flushed ones that are gone. Only those are
    /// copied: the flush runs every ten seconds, and copying the whole table
    /// each time made a busy transport node's memory grow.
    pub(crate) fn known_destination_changes(
        &self,
    ) -> (Vec<(KnownDestinationEntry, u64)>, Vec<[u8; 16]>) {
        let changed = self
            .known
            .entries
            .iter()
            .filter_map(|(dest_hash, state)| {
                let fingerprint = Self::known_destination_fingerprint(state);
                (self.known.flushed.get(dest_hash) != Some(&fingerprint)).then(|| {
                    (
                        Self::known_destination_entry(*dest_hash, state),
                        fingerprint,
                    )
                })
            })
            .collect();
        let removed = self
            .known
            .flushed
            .keys()
            .filter(|dest_hash| !self.known.entries.contains_key(*dest_hash))
            .copied()
            .collect();
        (changed, removed)
    }

    pub(crate) fn known_destination_entries(&self) -> Vec<KnownDestinationEntry> {
        let mut entries: Vec<_> = self
            .known
            .entries
            .iter()
            .map(|(dest_hash, state)| Self::known_destination_entry(*dest_hash, state))
            .collect();
        entries.sort_by_key(|a| a.dest_hash);
        entries
    }

    /// `Identity._used_destination_data`: record that a destination was
    /// used now. A retained destination is left as it is, and like upstream
    /// this then returns `false`.
    pub(crate) fn mark_known_destination_used(&mut self, dest_hash: &[u8; 16]) -> bool {
        let Some(state) = self.known.entries.get_mut(dest_hash) else {
            return false;
        };
        if state.retained {
            return false;
        }
        state.was_used = true;
        state.last_used_at = Some(time::now());
        true
    }

    pub(crate) fn retain_known_destination(&mut self, dest_hash: &[u8; 16]) -> bool {
        let Some(state) = self.known.entries.get_mut(dest_hash) else {
            return false;
        };
        state.retained = true;
        true
    }

    pub(crate) fn retain_identity(&mut self, identity_hash: &[u8; 16]) -> bool {
        let mut retained = false;
        for state in self.known.entries.values_mut() {
            if &state.announced.identity_hash.0 == identity_hash {
                state.retained = true;
                retained = true;
            }
        }
        retained
    }

    /// `Identity._unretain_destination_data`: stop retaining a destination.
    /// Like upstream, it counts as used now, so it is not cleaned up before
    /// it has gone unused for the usual time.
    pub(crate) fn unretain_known_destination(&mut self, dest_hash: &[u8; 16]) -> bool {
        let Some(state) = self.known.entries.get_mut(dest_hash) else {
            return false;
        };
        state.retained = false;
        state.was_used = true;
        state.last_used_at = Some(time::now());
        true
    }

    pub(crate) fn known_destination_announced(
        &self,
        dest_hash: &[u8; 16],
    ) -> Option<crate::destination::AnnouncedIdentity> {
        self.known
            .entries
            .get(dest_hash)
            .map(|state| state.announced.clone())
    }

    pub(crate) fn known_destination_relevance_time(state: &KnownDestinationState) -> f64 {
        state.last_used_at.unwrap_or(state.announced.received_at)
    }

    pub(crate) fn begin_drain(&mut self, timeout: Duration) {
        // Frames deferred in this pass count as queued: get them moving.
        self.wake_writers();
        let now = Instant::now();
        let deadline = now + timeout;
        match self.lifecycle_state {
            LifecycleState::Active => {
                self.lifecycle_state = LifecycleState::Draining;
                self.accepting_work.store(false, Ordering::Release);
                self.drain_started_at = Some(now);
                self.drain_deadline = Some(deadline);
                log::info!(
                    "driver entering drain mode with {:.3}s timeout",
                    timeout.as_secs_f64()
                );
                self.stop_listener_accepts();
            }
            LifecycleState::Draining => {
                self.drain_deadline = Some(deadline);
                log::info!(
                    "driver drain deadline updated to {:.3}s from now",
                    timeout.as_secs_f64()
                );
                self.stop_listener_accepts();
            }
            LifecycleState::Stopping | LifecycleState::Stopped => {
                log::debug!(
                    "ignoring BeginDrain while lifecycle state is {:?}",
                    self.lifecycle_state
                );
            }
        }
    }

    pub(crate) fn is_draining(&self) -> bool {
        matches!(self.lifecycle_state, LifecycleState::Draining)
    }

    /// Keep `control` so the driver stops the listener when it shuts down.
    pub fn register_listener_control(&mut self, control: crate::interface::ListenerControl) {
        self.listener_controls.push(control);
    }

    /// Report the shared instance's local server, serving on `endpoint`,
    /// in interface statistics as upstream's `LocalServerInterface`.
    #[cfg(feature = "iface-local")]
    pub(crate) fn register_shared_instance_listener(
        &mut self,
        id: InterfaceId,
        endpoint: crate::interface::display::LocalEndpoint,
    ) {
        self.listener_stats.retain(|listener| listener.id != id);
        self.listener_stats.push(super::ListenerStat {
            id,
            // Upstream's `LocalServerInterface.name`.
            name: "Reticulum".into(),
            display_name: crate::interface::display::shared_instance(&endpoint),
            interface_type: "LocalServerInterface".into(),
            mode: rns_core::constants::MODE_FULL,
            gravity: 0,
            announces_to_internal: None,
            bitrate: Some(crate::interface::local::BITRATE),
            mtu: crate::interface::local::HW_MTU,
            ifac: None,
            clients: super::ListenerClients::Local(endpoint),
        });
    }

    pub(crate) fn stop_listener_accepts(&mut self) {
        for control in &self.listener_controls {
            control.request_stop();
        }
        #[cfg(feature = "hooks")]
        if let Some(bridge) = self.provider_bridge.as_ref() {
            bridge.stop_accepting();
        }
    }

    pub(crate) fn reject_new_work(&self, op: &str) {
        log::info!("rejecting {} while node is draining", op);
    }

    fn interface_writer_queued_frames(&self) -> usize {
        self.interfaces
            .values()
            .map(|entry| {
                entry
                    .async_writer_metrics
                    .as_ref()
                    .map(|metrics| metrics.queued_frames())
                    .unwrap_or(0)
            })
            .sum()
    }

    fn wait_for_writer_flush(&mut self, timeout: Duration) {
        // Writers owed a wake for deferred frames would never flush.
        self.wake_writers();
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    pub(crate) fn graceful_shutdown(&mut self) {
        if matches!(self.lifecycle_state, LifecycleState::Stopped) {
            return;
        }

        self.lifecycle_state = LifecycleState::Stopping;

        // Upstream detaches its interfaces on exit, and each TCP connection
        // logs its teardown.
        let mut ids: Vec<_> = self.interfaces.keys().copied().collect();
        ids.sort_by_key(|id| id.0);
        for id in ids {
            if let Some(entry) = self.interfaces.get(&id) {
                if matches!(
                    entry.interface_type.as_str(),
                    "TCPClientInterface" | "TCPServerClientInterface"
                ) {
                    log::info!(
                        "The interface {} is being torn down.",
                        self.interface_display_name(entry)
                    );
                }
            }
        }

        self.accepting_work.store(false, Ordering::Release);
        self.stop_resource_preparations();
        self.stop_listener_accepts();

        let resource_actions = self.link_manager.cancel_all_resources(&mut self.rng);
        let resource_flush = resource_actions
            .iter()
            .any(|action| matches!(action, LinkManagerAction::SendPacket { .. }));
        self.dispatch_link_actions(resource_actions);

        let link_actions = self.link_manager.teardown_all_links();
        let link_flush = link_actions
            .iter()
            .any(|action| matches!(action, LinkManagerAction::SendPacket { .. }));
        self.dispatch_link_actions(link_actions);

        let cleanup_actions = self.link_manager.tick(&mut self.rng);
        let cleanup_flush = cleanup_actions
            .iter()
            .any(|action| matches!(action, LinkManagerAction::SendPacket { .. }));
        self.dispatch_link_actions(cleanup_actions);
        self.holepunch_manager.abort_all_sessions();

        if resource_flush
            || link_flush
            || cleanup_flush
            || self.interface_writer_queued_frames() > 0
        {
            self.wait_for_writer_flush(DEFAULT_LINK_TEARDOWN_FLUSH);
        }

        self.engine.void_queues();
        crate::sync::lock_or_recover(
            &self.announce_verify_queue,
            "lifecycle announce verify queue",
        )
        .clear();
        self.sent_packets.clear();
        self.sent_packet_keys.clear();
        self.completed_proofs.clear();
        for control in &self.listener_controls {
            control.finish();
        }
        self.pending_probes.clear();
        if let Some(handle) = self.ratchet_cleanup_handle.take() {
            let _ = handle.join();
        }
        // Folded housekeeping still queued completes, as a helper thread's
        // work is joined above.
        while let Some(job) = self.folded.jobs.pop_front() {
            self.run_folded_job(job);
        }

        self.link_manager.stop_receive_worker();
        self.lifecycle_state = LifecycleState::Stopped;
        self.accepting_work.store(false, Ordering::Release);
    }

    pub(crate) fn drain_status(&self) -> DrainStatus {
        let now = Instant::now();
        let active_links = self.link_manager.link_count();
        let active_resource_transfers = self.link_manager.resource_transfer_count()
            + self
                .resource_preparation
                .as_ref()
                .map_or(0, |worker| worker.len());
        let active_holepunch_sessions = self.holepunch_manager.session_count();
        let interface_writer_queued_frames = self.interface_writer_queued_frames();
        let link_transmissions = self.event_tx.link_send_pool().in_flight();
        #[cfg(feature = "hooks")]
        let (provider_backlog_events, provider_consumer_queued_events) = self
            .provider_bridge
            .as_ref()
            .map(|bridge| {
                let stats = bridge.stats();
                (
                    stats.backlog_len,
                    stats
                        .consumers
                        .iter()
                        .map(|consumer| consumer.queue_len)
                        .sum(),
                )
            })
            .unwrap_or((0, 0));
        #[cfg(not(feature = "hooks"))]
        let (provider_backlog_events, provider_consumer_queued_events) = (0, 0);
        let drain_age_seconds = self
            .drain_started_at
            .map(|started| started.elapsed().as_secs_f64());
        let deadline_remaining_seconds = self.drain_deadline.map(|deadline| {
            deadline
                .checked_duration_since(now)
                .map(|remaining| remaining.as_secs_f64())
                .unwrap_or(0.0)
        });
        let detail = match self.lifecycle_state {
            LifecycleState::Active => Some("node is accepting normal work".into()),
            LifecycleState::Draining => {
                let mut remaining = Vec::new();
                if active_links > 0 {
                    remaining.push(format!("{active_links} link(s)"));
                }
                if active_resource_transfers > 0 {
                    remaining.push(format!("{active_resource_transfers} resource transfer(s)"));
                }
                if active_holepunch_sessions > 0 {
                    remaining.push(format!("{active_holepunch_sessions} hole-punch session(s)"));
                }
                if interface_writer_queued_frames > 0 {
                    remaining.push(format!(
                        "{interface_writer_queued_frames} queued interface writer frame(s)"
                    ));
                }
                if link_transmissions > 0 {
                    remaining.push(format!("{link_transmissions} pending Link transmission(s)"));
                }
                if provider_backlog_events > 0 {
                    remaining.push(format!(
                        "{provider_backlog_events} provider backlog event(s)"
                    ));
                }
                if provider_consumer_queued_events > 0 {
                    remaining.push(format!(
                        "{provider_consumer_queued_events} queued provider consumer event(s)"
                    ));
                }
                Some(if remaining.is_empty() {
                    "node is draining existing work; no active links, resource transfers, hole-punch sessions, or queued writer/provider work remain".into()
                } else {
                    format!(
                        "node is draining existing work; {} still active",
                        remaining.join(", ")
                    )
                })
            }
            LifecycleState::Stopping => Some("node is tearing down remaining work".into()),
            LifecycleState::Stopped => Some("node is stopped".into()),
        };

        DrainStatus {
            state: self.lifecycle_state,
            drain_age_seconds,
            deadline_remaining_seconds,
            drain_complete: !matches!(self.lifecycle_state, LifecycleState::Draining)
                || (active_links == 0
                    && active_resource_transfers == 0
                    && active_holepunch_sessions == 0
                    && interface_writer_queued_frames == 0
                    && link_transmissions == 0
                    && provider_backlog_events == 0
                    && provider_consumer_queued_events == 0),
            interface_writer_queued_frames,
            provider_backlog_events,
            provider_consumer_queued_events,
            detail,
        }
    }

    pub(crate) fn enforce_drain_deadline(&mut self) {
        if !matches!(self.lifecycle_state, LifecycleState::Draining) {
            return;
        }
        let Some(deadline) = self.drain_deadline else {
            return;
        };
        if Instant::now() < deadline {
            return;
        }

        log::info!("driver drain deadline reached; tearing down remaining links");
        self.event_tx.link_send_pool().close();
        self.pending_link_frames.clear();
        self.lifecycle_state = LifecycleState::Stopping;
        self.accepting_work.store(false, Ordering::Release);
        self.stop_resource_preparations();
        let resource_actions = self.link_manager.cancel_all_resources(&mut self.rng);
        self.dispatch_link_actions(resource_actions);
        let link_actions = self.link_manager.teardown_all_links();
        self.dispatch_link_actions(link_actions);
        let cleanup_actions = self.link_manager.tick(&mut self.rng);
        self.dispatch_link_actions(cleanup_actions);
        self.link_manager.stop_receive_worker();
        self.holepunch_manager.abort_all_sessions();
    }

    pub(crate) fn enforce_known_destination_cap(&mut self, for_insert: bool) -> usize {
        if self.known.max_entries == usize::MAX {
            return 0;
        }

        let mut evicted = 0usize;
        while if for_insert {
            self.known.entries.len() >= self.known.max_entries
        } else {
            self.known.entries.len() > self.known.max_entries
        } {
            let active_dests = self.engine.active_destination_hashes();
            let candidate = self
                .oldest_known_destination(false, &active_dests)
                .or_else(|| self.oldest_known_destination(true, &active_dests));
            let Some(dest_hash) = candidate else {
                break;
            };
            if self.known.entries.remove(&dest_hash).is_some() {
                evicted += 1;
                self.known.cap_evict_count += 1;
            } else {
                break;
            }
        }
        evicted
    }

    pub(crate) fn oldest_known_destination(
        &self,
        include_protected: bool,
        active_dests: &std::collections::BTreeSet<[u8; 16]>,
    ) -> Option<[u8; 16]> {
        self.known
            .entries
            .iter()
            .filter(|(dest_hash, state)| {
                include_protected
                    || (!active_dests.contains(*dest_hash)
                        && !self.local_destinations.contains_key(*dest_hash)
                        && !state.retained)
            })
            .min_by(|a, b| {
                Self::known_destination_relevance_time(a.1)
                    .partial_cmp(&Self::known_destination_relevance_time(b.1))
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.0.cmp(b.0))
            })
            .map(|(dest_hash, _)| *dest_hash)
    }

    pub(super) fn build_shared_announce_raw(
        &mut self,
        dest_hash: &[u8; 16],
        record: &SharedAnnounceRecord,
        path_response: bool,
    ) -> Option<Vec<u8>> {
        let identity = rns_crypto::identity::Identity::from_private_key(&record.identity_prv_key);

        let mut random_hash = [0u8; 10];
        self.rng.fill_bytes(&mut random_hash[..5]);
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        random_hash[5..10].copy_from_slice(&now_secs.to_be_bytes()[3..8]);

        let owner = crate::sync::lock_or_recover(self.event_tx.local_ratchets(), "local ratchets")
            .get(dest_hash)
            .cloned();
        let ratchet = match owner {
            Some(owner) => match owner.public_for_announce(now_secs) {
                Ok(public) => Some(public),
                Err(error) => {
                    log::error!("cannot replay ratcheted announce: {error}");
                    return None;
                }
            },
            None => None,
        };
        let (announce_data, has_ratchet) = rns_core::announce::AnnounceData::pack(
            &identity,
            dest_hash,
            &record.name_hash,
            &random_hash,
            ratchet.as_ref(),
            record.app_data.as_deref(),
        )
        .ok()?;

        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: if has_ratchet {
                rns_core::constants::FLAG_SET
            } else {
                rns_core::constants::FLAG_UNSET
            },
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: rns_core::constants::DESTINATION_SINGLE,
            packet_type: rns_core::constants::PACKET_TYPE_ANNOUNCE,
        };
        let context = if path_response {
            rns_core::constants::CONTEXT_PATH_RESPONSE
        } else {
            rns_core::constants::CONTEXT_NONE
        };

        rns_core::packet::RawPacket::pack(flags, 0, dest_hash, None, context, &announce_data)
            .ok()
            .map(|packet| packet.raw)
    }

    /// `Transport.shared_connection_reappeared`: once the connection to the
    /// shared instance is back, every SINGLE IN destination this client can
    /// announce is announced again as a path response, so the instance
    /// knows where it is. One that announced is replayed with its latest
    /// app data; one only registered with its identity is announced
    /// without any.
    pub(crate) fn replay_shared_announces(&mut self) {
        let records: Vec<([u8; 16], SharedAnnounceRecord)> = self
            .shared_announces
            .iter()
            .map(|(dest_hash, record)| (*dest_hash, record.clone()))
            .collect();
        let responders: Vec<[u8; 16]> = self
            .path_responders
            .keys()
            .filter(|dest_hash| !self.shared_announces.contains_key(*dest_hash))
            .copied()
            .collect();
        for (dest_hash, record) in records {
            if let Some(raw) = self.build_shared_announce_raw(&dest_hash, &record, true) {
                self.send_shared_path_response_raw(&dest_hash, &raw);
            }
        }
        for dest_hash in responders {
            self.send_path_responder_announce(dest_hash);
        }
    }

    /// Send a path-response announce for a destination of this shared
    /// instance client on every interface.
    pub(super) fn send_shared_path_response_raw(&mut self, dest_hash: &[u8; 16], raw: &[u8]) {
        match RawPacket::unpack(raw) {
            Ok(packet) => {
                let actions = self.engine.handle_outbound(
                    &packet,
                    rns_core::constants::DESTINATION_SINGLE,
                    None,
                    time::now(),
                );
                self.dispatch_all(actions);
            }
            Err(e) => {
                log::warn!(
                    "Shared announce replay failed for {:02x?}: {:?}",
                    &dest_hash[..4],
                    e
                );
            }
        }
    }

    pub(crate) fn handle_shared_interface_down(&mut self, id: InterfaceId) {
        let dropped_paths = self.engine.drop_paths_for_interface(id);
        let dropped_reverse = self.engine.drop_reverse_for_interface(id);
        let dropped_links = self.engine.drop_links_for_interface(id);
        self.engine.drop_announce_queues();
        let link_actions = self.link_manager.teardown_all_links();
        self.dispatch_link_actions(link_actions);
        self.shared_reconnect_pending.insert(id, true);
        log::info!(
            "[{}] cleared shared state: {} paths, {} reverse entries, {} transport links",
            id.0,
            dropped_paths,
            dropped_reverse,
            dropped_links
        );
    }
}
