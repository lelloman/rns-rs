use super::*;

impl Driver {
    pub(crate) fn upsert_known_destination(
        &mut self,
        dest_hash: [u8; 16],
        announced: crate::destination::AnnouncedIdentity,
    ) {
        if let Some(existing) = self.known_destinations.get_mut(&dest_hash) {
            existing.announced = announced;
            return;
        }

        self.enforce_known_destination_cap(true);
        self.known_destinations.insert(
            dest_hash,
            KnownDestinationState {
                announced,
                was_used: false,
                last_used_at: None,
                retained: false,
            },
        );
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
        }
    }

    pub(crate) fn known_destination_entries(&self) -> Vec<KnownDestinationEntry> {
        let mut entries: Vec<_> = self
            .known_destinations
            .iter()
            .map(|(dest_hash, state)| Self::known_destination_entry(*dest_hash, state))
            .collect();
        entries.sort_by(|a, b| a.dest_hash.cmp(&b.dest_hash));
        entries
    }

    pub(crate) fn mark_known_destination_used(&mut self, dest_hash: &[u8; 16]) -> bool {
        let Some(state) = self.known_destinations.get_mut(dest_hash) else {
            return false;
        };
        state.was_used = true;
        state.last_used_at = Some(time::now());
        true
    }

    pub(crate) fn retain_known_destination(&mut self, dest_hash: &[u8; 16]) -> bool {
        let Some(state) = self.known_destinations.get_mut(dest_hash) else {
            return false;
        };
        state.retained = true;
        true
    }

    pub(crate) fn unretain_known_destination(&mut self, dest_hash: &[u8; 16]) -> bool {
        let Some(state) = self.known_destinations.get_mut(dest_hash) else {
            return false;
        };
        state.retained = false;
        true
    }

    pub(crate) fn known_destination_announced(
        &self,
        dest_hash: &[u8; 16],
    ) -> Option<crate::destination::AnnouncedIdentity> {
        self.known_destinations
            .get(dest_hash)
            .map(|state| state.announced.clone())
    }

    pub(crate) fn known_destination_relevance_time(state: &KnownDestinationState) -> f64 {
        state.last_used_at.unwrap_or(state.announced.received_at)
    }

    pub(crate) fn begin_drain(&mut self, timeout: Duration) {
        let now = Instant::now();
        let deadline = now + timeout;
        match self.lifecycle_state {
            LifecycleState::Active => {
                self.lifecycle_state = LifecycleState::Draining;
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

    pub fn register_listener_control(&mut self, control: crate::interface::ListenerControl) {
        self.listener_controls.push(control);
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

    pub(crate) fn drain_error(&self, op: &str) -> String {
        format!("cannot {} while node is draining", op)
    }

    pub(crate) fn drain_status(&self) -> DrainStatus {
        let now = Instant::now();
        let active_links = self.link_manager.link_count();
        let active_resource_transfers = self.link_manager.resource_transfer_count();
        let active_holepunch_sessions = self.holepunch_manager.session_count();
        let interface_writer_queued_frames = self
            .interfaces
            .values()
            .map(|entry| {
                entry
                    .async_writer_metrics
                    .as_ref()
                    .map(|metrics| metrics.queued_frames())
                    .unwrap_or(0)
            })
            .sum();
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
        self.lifecycle_state = LifecycleState::Stopping;
        let resource_actions = self.link_manager.cancel_all_resources(&mut self.rng);
        self.dispatch_link_actions(resource_actions);
        let link_actions = self.link_manager.teardown_all_links();
        self.dispatch_link_actions(link_actions);
        let cleanup_actions = self.link_manager.tick(&mut self.rng);
        self.dispatch_link_actions(cleanup_actions);
        self.holepunch_manager.abort_all_sessions();
    }

    pub(crate) fn enforce_known_destination_cap(&mut self, for_insert: bool) -> usize {
        if self.known_destinations_max_entries == usize::MAX {
            return 0;
        }

        let mut evicted = 0usize;
        while if for_insert {
            self.known_destinations.len() >= self.known_destinations_max_entries
        } else {
            self.known_destinations.len() > self.known_destinations_max_entries
        } {
            let active_dests = self.engine.active_destination_hashes();
            let candidate = self
                .oldest_known_destination(false, &active_dests)
                .or_else(|| self.oldest_known_destination(true, &active_dests));
            let Some(dest_hash) = candidate else {
                break;
            };
            if self.known_destinations.remove(&dest_hash).is_some() {
                evicted += 1;
                self.known_destinations_cap_evict_count += 1;
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
        self.known_destinations
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

    fn build_shared_announce_raw(
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

        let (announce_data, _has_ratchet) = rns_core::announce::AnnounceData::pack(
            &identity,
            dest_hash,
            &record.name_hash,
            &random_hash,
            None,
            record.app_data.as_deref(),
        )
        .ok()?;

        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: rns_core::constants::FLAG_UNSET,
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

    pub(crate) fn replay_shared_announces(&mut self) {
        let records: Vec<([u8; 16], SharedAnnounceRecord)> = self
            .shared_announces
            .iter()
            .map(|(dest_hash, record)| (*dest_hash, record.clone()))
            .collect();
        for (dest_hash, record) in records {
            if let Some(raw) = self.build_shared_announce_raw(&dest_hash, &record, true) {
                let event = Event::SendOutbound {
                    raw,
                    dest_type: rns_core::constants::DESTINATION_SINGLE,
                    attached_interface: None,
                };
                match event {
                    Event::SendOutbound {
                        raw,
                        dest_type,
                        attached_interface,
                    } => match RawPacket::unpack(&raw) {
                        Ok(packet) => {
                            let actions = self.engine.handle_outbound(
                                &packet,
                                dest_type,
                                attached_interface,
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
                    },
                    other => {
                        log::warn!(
                            "shared announce replay returned unexpected response: {:?}",
                            other
                        );
                    }
                }
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
