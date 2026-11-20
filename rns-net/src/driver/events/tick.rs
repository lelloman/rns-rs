//! The periodic tick and the traffic and frequency samples it takes.

use super::*;

impl Driver {
    /// Upstream's I2P peer watchdog: track each peer's tunnel state, keep
    /// idle tunnels alive with empty frames, and restart those that stopped
    /// answering (see [`crate::interface::i2p::tunnel`]).
    #[cfg(feature = "iface-i2p")]
    pub(crate) fn watch_i2p_tunnels(&mut self) {
        for listener in &self.registry.listener_stats {
            let ListenerClients::I2pPeers(i2p) = &listener.clients else {
                continue;
            };
            let tunnels: Vec<_> = crate::interface::lock_or_recover(&i2p.endpoint, "i2p endpoint")
                .tunnels
                .iter()
                .map(|(id, tunnel)| (*id, std::sync::Arc::clone(tunnel)))
                .collect();
            for (id, tunnel) in tunnels {
                // Upstream's watchdog runs only while the peer is connected.
                let Some(entry) = self.interfaces.get_mut(&id).filter(|entry| entry.online) else {
                    continue;
                };
                let Some(found) = tunnel.watch(entry.stats.txb) else {
                    continue;
                };
                if found.keepalive && !found.restart {
                    if let Err(e) = entry.writer.send_frame(&[]) {
                        log::error!(
                            "An error ocurred while sending I2P keepalive. The contained exception was: {}",
                            e
                        );
                        tunnel.shutdown();
                    }
                }
            }
        }
    }

    /// As upstream's once-a-second traffic count, read every interface's
    /// frequencies, decaying their stale samples, and give them to the
    /// engine.
    pub(crate) fn sample_interface_frequencies(&mut self, now: f64) {
        for (id, entry) in &mut self.interfaces {
            super::sync_interface_frequencies(
                &mut self.engine,
                *id,
                entry.stats.sample_frequencies(now),
            );
        }
    }

    pub(crate) fn handle_tick_event(&mut self) {
        if crate::engine::FOLD_TIMERS {
            self.queue_folded_persistence();
        }
        // Close sockets of detached interfaces served on this thread.
        self.rx.sweep_stopped_sources();
        // Re-arm sources that backed off after an error, e.g. a listener
        // whose accept failed.
        self.rx.resume_paused_sources();
        self.expire_rpc_connections();
        // Let driver-run writers notice peers that stopped reading.
        for entry in self.interfaces.values_mut() {
            entry.writer.tick();
        }
        #[cfg(feature = "iface-i2p")]
        self.watch_i2p_tunnels();
        self.prioritize_interfaces();
        // Tick carries no packet: `Modify` acts as `Continue`.
        self.run_hooks_with_effects(HookPoint::Tick, &HookEvent::Tick, InjectedActions::Dispatch);

        let now = time::now();
        self.sample_interface_traffic(now);
        self.sample_link_traffic(now);
        self.sample_interface_frequencies(now);
        let actions = self.engine.tick(now, &mut self.rng);
        // Released held announces (upstream c850cdac, 29dc449a).
        self.record_released_traffic();
        self.record_announce_receipts();
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
        self.tick_blackhole_updater(now);
        self.tick_upstream_autoconnect(now);
        self.proofs
            .sent_packets
            .retain(|_, (_, sent_time)| now - *sent_time < 60.0);
        let sent_packets = &self.proofs.sent_packets;
        self.proofs
            .sent_packet_keys
            .retain(|hash, _| sent_packets.contains_key(hash));
        self.proofs
            .pending_probes
            .retain(|hash| sent_packets.contains_key(hash));
        self.proofs
            .completed
            .retain(|_, (_, received)| now - *received < 120.0);
        self.expire_local_path_responses(now);

        self.tick_discovery_announcer(now);
        #[cfg(feature = "iface-backbone")]
        self.maintain_backbone_peer_pool();

        self.housekeeping.memory_stats_counter += 1;
        if self.housekeeping.memory_stats_counter >= 300 {
            self.housekeeping.memory_stats_counter = 0;
            self.log_memory_stats();
        }

        if self.discovery.enabled {
            self.discovery.cleanup_counter += 1;
            if self.discovery.cleanup_counter >= self.discovery.cleanup_interval_ticks {
                self.discovery.cleanup_counter = 0;
                let sources = &self.discovery.sources;
                if let Ok(removed) = self.discovery.storage.cleanup_with_filters(
                    |identity| self.engine.is_blackholed(identity, now),
                    |network_id| sources.is_empty() || sources.contains(network_id),
                ) {
                    if removed > 0 {
                        log::info!("Discovery cleanup: removed {} stale entries", removed);
                    }
                    #[cfg(feature = "iface-backbone")]
                    self.cull_stale_discovered_backbone_peer_pool_candidates();
                }
            }
        }

        self.finish_ratchet_cleanup_if_ready();
        if self.known.cleanup.is_none() {
            self.housekeeping.cache_cleanup_counter += 1;
            if self.housekeeping.cache_cleanup_counter >= self.known.cleanup_interval_ticks {
                self.housekeeping.cache_cleanup_counter = 0;
                self.known.cleanup = Some(KnownDestinationCleanup {
                    candidates: self.known.entries.keys().copied().collect(),
                    cursor: 0,
                    started_at: Instant::now(),
                    removed: 0,
                });
                log::debug!("Cleaning known destinations at background priority...");
            }
        }
        self.continue_known_destination_cleanup(now);

        self.housekeeping.announce_cache_cleanup_counter += 1;
        if self.housekeeping.announce_cache_cleanup_counter
            >= self.housekeeping.announce_cache_cleanup_interval_ticks
        {
            self.housekeeping.announce_cache_cleanup_counter = 0;
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

    /// Upstream's `Transport.link_rxb` and `link_txb`: the link traffic the
    /// transport engine relays (ef3e8086) and that this node's own link
    /// endpoints receive and send (01ffb98e), in the same two totals.
    pub(in crate::driver) fn link_traffic(&self) -> (u64, u64) {
        let (relayed_rx, relayed_tx) = self.engine.link_traffic();
        let (local_rx, local_tx) = self.link_manager.local_link_traffic();
        (relayed_rx + local_rx, relayed_tx + local_tx)
    }

    /// Upstream's traffic loop's link speeds (ef3e8086): a pass about once
    /// a second, the first a second after start.
    pub(in crate::driver) fn sample_link_traffic(&mut self, now: f64) {
        let monotonic = time::monotonic();
        let due = match self.registry.link_traffic.sampled_at() {
            None => now - self.started >= 1.0,
            Some(at) => monotonic - at >= 1.0,
        };
        if due {
            self.registry
                .link_traffic
                .sample(monotonic, self.started, self.link_traffic());
        }
    }

    pub(in crate::driver) fn sample_interface_traffic(&mut self, now: f64) {
        self.registry
            .traffic_samples
            .retain(|id, _| self.interfaces.contains_key(id));
        for (id, entry) in &mut self.interfaces {
            let Some(previous) = self.registry.traffic_samples.get(id).copied() else {
                self.registry
                    .traffic_samples
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
                frxs: bps(entry.stats.frxb, previous.frxb),
                ftxs: bps(entry.stats.ftxb, previous.ftxb),
            };
            self.registry
                .traffic_samples
                .insert(*id, TrafficSample::from_stats(now, &entry.stats));
        }
    }
}
