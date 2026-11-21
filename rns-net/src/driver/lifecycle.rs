//! The node's lifecycle (draining, shutdown) and the shared-instance
//! announces.

use super::*;

/// Where the node is in its lifecycle, and the progress of a drain.
pub(crate) struct Lifecycle {
    pub(crate) state: LifecycleState,
    /// Whether `state` is still `Active`, shared with the node handle so
    /// that each API call can check it without a driver query.
    pub(crate) accepting_work: Arc<AtomicBool>,
    pub(crate) drain_started_at: Option<Instant>,
    pub(crate) drain_deadline: Option<Instant>,
}

impl Lifecycle {
    pub(crate) fn new() -> Self {
        Self {
            state: LifecycleState::Active,
            accepting_work: Arc::new(AtomicBool::new(true)),
            drain_started_at: None,
            drain_deadline: None,
        }
    }
}

impl Driver {
    /// Remember the identity a destination announced, evicting the least
    /// relevant known destination first when the cache is full.
    pub(crate) fn upsert_known_destination(
        &mut self,
        dest_hash: [u8; 16],
        announced: crate::destination::AnnouncedIdentity,
    ) {
        self.known
            .upsert(dest_hash, announced, &self.engine, &self.local_destinations);
    }

    pub(crate) fn begin_drain(&mut self, timeout: Duration) {
        // Frames deferred in this pass count as queued: get them moving.
        self.wake_writers();
        let now = Instant::now();
        // A timeout too long to represent as an instant means no deadline.
        let deadline = now.checked_add(timeout);
        match self.lifecycle.state {
            LifecycleState::Active => {
                self.lifecycle.state = LifecycleState::Draining;
                self.lifecycle
                    .accepting_work
                    .store(false, Ordering::Release);
                self.lifecycle.drain_started_at = Some(now);
                self.lifecycle.drain_deadline = deadline;
                log::info!(
                    "driver entering drain mode with {:.3}s timeout",
                    timeout.as_secs_f64()
                );
                self.stop_listener_accepts();
            }
            LifecycleState::Draining => {
                self.lifecycle.drain_deadline = deadline;
                log::info!(
                    "driver drain deadline updated to {:.3}s from now",
                    timeout.as_secs_f64()
                );
                self.stop_listener_accepts();
            }
            LifecycleState::Stopping | LifecycleState::Stopped => {
                log::debug!(
                    "ignoring BeginDrain while lifecycle state is {:?}",
                    self.lifecycle.state
                );
            }
        }
    }

    pub(crate) fn is_draining(&self) -> bool {
        matches!(self.lifecycle.state, LifecycleState::Draining)
    }

    /// Keep `control` so the driver stops the listener when it shuts down.
    pub fn register_listener_control(&mut self, control: crate::interface::ListenerControl) {
        self.registry.listener_controls.push(control);
    }

    /// Report the shared instance's local server, serving on `endpoint`,
    /// in interface statistics as upstream's `LocalServerInterface`.
    #[cfg(feature = "iface-local")]
    pub(crate) fn register_shared_instance_listener(
        &mut self,
        id: InterfaceId,
        endpoint: crate::interface::display::LocalEndpoint,
    ) {
        self.registry
            .listener_stats
            .retain(|listener| listener.id != id);
        self.registry.listener_stats.push(super::ListenerStat {
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
        for control in &self.registry.listener_controls {
            control.request_stop();
        }
        self.hooks.stop_provider_bridge();
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
        if matches!(self.lifecycle.state, LifecycleState::Stopped) {
            return;
        }

        self.lifecycle.state = LifecycleState::Stopping;

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

        self.lifecycle
            .accepting_work
            .store(false, Ordering::Release);
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
            &self.announce_verify.queue,
            "lifecycle announce verify queue",
        )
        .clear();
        self.proofs.sent_packets.clear();
        self.proofs.sent_packet_keys.clear();
        self.proofs.completed.clear();
        for control in &self.registry.listener_controls {
            control.finish();
        }
        self.proofs.pending_probes.clear();
        if let Some(handle) = self.housekeeping.ratchet_cleanup_handle.take() {
            let _ = handle.join();
        }
        // Folded housekeeping still queued completes, as a helper thread's
        // work is joined above.
        while let Some(job) = self.folded.jobs.pop_front() {
            self.run_folded_job(job);
        }

        self.link_manager.stop_receive_worker();
        self.lifecycle.state = LifecycleState::Stopped;
        self.lifecycle
            .accepting_work
            .store(false, Ordering::Release);
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
        let (provider_backlog_events, provider_consumer_queued_events) =
            self.hooks.provider_queued_events();
        let drain_age_seconds = self
            .lifecycle
            .drain_started_at
            .map(|started| started.elapsed().as_secs_f64());
        let deadline_remaining_seconds = self.lifecycle.drain_deadline.map(|deadline| {
            deadline
                .checked_duration_since(now)
                .map(|remaining| remaining.as_secs_f64())
                .unwrap_or(0.0)
        });
        let detail = match self.lifecycle.state {
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
            state: self.lifecycle.state,
            drain_age_seconds,
            deadline_remaining_seconds,
            drain_complete: !matches!(self.lifecycle.state, LifecycleState::Draining)
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
        if !matches!(self.lifecycle.state, LifecycleState::Draining) {
            return;
        }
        let Some(deadline) = self.lifecycle.drain_deadline else {
            return;
        };
        if Instant::now() < deadline {
            return;
        }

        log::info!("driver drain deadline reached; tearing down remaining links");
        self.event_tx.link_send_pool().close();
        self.pending_link_frames.clear();
        self.lifecycle.state = LifecycleState::Stopping;
        self.lifecycle
            .accepting_work
            .store(false, Ordering::Release);
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
            .path_responses
            .shared_announces
            .iter()
            .map(|(dest_hash, record)| (*dest_hash, record.clone()))
            .collect();
        let responders: Vec<[u8; 16]> = self
            .path_responses
            .responders
            .keys()
            .filter(|dest_hash| {
                !self
                    .path_responses
                    .shared_announces
                    .contains_key(*dest_hash)
            })
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
        self.path_responses
            .shared_reconnect_pending
            .insert(id, true);
        log::info!(
            "[{}] cleared shared state: {} paths, {} reverse entries, {} transport links",
            id.0,
            dropped_paths,
            dropped_reverse,
            dropped_links
        );
    }
}
