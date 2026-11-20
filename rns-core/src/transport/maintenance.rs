use super::*;

/// Whether an announce for `destination_hash`, received on `announce_iface`
/// with announce payload `data`, passes upstream's
/// `Transport.announce_prefilter`: true when the destination has no path, or
/// when the announce could still update its path. A free function over the
/// engine's tables so ingress control can call it while it holds its own
/// state mutably.
///
/// The test assumes upstream's single path per destination. With
/// `max_paths_per_destination` above 1 an older announce can still add an
/// alternative path (except under `unresponsive_path_recovery = upstream`,
/// where announces only replace the primary path as upstream does), and
/// with `prefer_shorter_path` a shorter one can replace the path regardless
/// of emission time, so both keep every announce.
pub(super) fn announce_passes_prefilter(
    config: &TransportConfig,
    paths: &PathTables,
    interfaces: &BTreeMap<InterfaceId, InterfaceInfo>,
    destination_hash: &[u8; 16],
    data: &[u8],
    announce_iface: InterfaceId,
    now: f64,
) -> bool {
    let keeps_alternatives = config.max_paths_per_destination > 1
        && config.unresponsive_path_recovery == types::UnresponsivePathRecovery::Native;
    if keeps_alternatives || config.prefer_shorter_path {
        return true;
    }
    let Some(existing) = paths.table.get(destination_hash).and_then(PathSet::primary) else {
        return true;
    };
    let Some(random_blob) = extract_random_blob(data) else {
        return true;
    };
    let gravity = |iface: &InterfaceId| interfaces.get(iface).map(|info| info.gravity);
    pathfinder::announce_prefilter(
        existing,
        timebase_from_random_blob(&random_blob),
        gravity(&announce_iface).unwrap_or(0),
        gravity(&existing.receiving_interface),
        paths.states.get(destination_hash) == Some(&constants::STATE_UNRESPONSIVE),
        now,
        config.unresponsive_path_recovery,
    )
}

impl TransportEngine {
    /// Periodic maintenance. Call regularly (e.g., every 250ms).
    pub fn tick(&mut self, now: f64, rng: &mut dyn Rng) -> Vec<TransportAction> {
        let mut ctx = TickCtx {
            now,
            rng,
            actions: Vec::new(),
        };
        self.process_tick_pending_announces(&mut ctx);

        let mut queue_actions = self.announces.queues.process_queues(now, &self.interfaces);
        ctx.actions.append(&mut queue_actions);

        self.process_tick_ingress_release(&mut ctx);
        self.cull_tick_tables(&mut ctx);
        self.process_tick_rediscovery(&mut ctx);
        ctx.actions
    }

    /// Queue a path rediscovery request for `destination_hash`, skipping
    /// `skip_interface`, unless one is already queued or the queue is full.
    pub fn queue_path_rediscovery(
        &mut self,
        destination_hash: [u8; 16],
        skip_interface: Option<InterfaceId>,
        now: f64,
    ) {
        if self
            .path_requests
            .pending_discovery
            .iter()
            .any(|(queued, _)| *queued == destination_hash)
            || self.path_requests.pending_discovery.len() >= constants::MAX_QUEUED_DISCOVERY_PRS
        {
            return;
        }
        // Upstream's sender thread sleeps one throttle interval before each
        // request, the first included.
        if self.path_requests.pending_discovery.is_empty() {
            self.path_requests.discovery_next_tx = self
                .path_requests
                .discovery_next_tx
                .max(now + constants::DISCOVERY_PR_TX_THROTTLE);
        }
        self.path_requests
            .pending_discovery
            .push_back((destination_hash, skip_interface));
    }

    /// When this node last sent or accepted a path request for
    /// `destination_hash`, if within `PATH_REQUEST_GATE_TIMEOUT`.
    pub fn last_path_request(&self, destination_hash: &[u8; 16]) -> Option<f64> {
        self.path_requests.gates.get(destination_hash).copied()
    }

    /// `Transport.handle_disovery_path_requests`: send the oldest queued
    /// rediscovery request once its throttle interval has passed.
    fn process_tick_rediscovery(&mut self, ctx: &mut TickCtx<'_>) {
        if ctx.now < self.path_requests.discovery_next_tx {
            return;
        }
        if let Some((destination_hash, skip_interface)) =
            self.path_requests.pending_discovery.pop_front()
        {
            ctx.actions.push(TransportAction::RediscoverPath {
                destination_hash,
                skip_interface,
            });
            self.path_requests.discovery_next_tx = ctx.now + constants::DISCOVERY_PR_TX_THROTTLE;
        }
    }

    /// The path rediscovery half of the link table job (Transport.py
    /// 1041-1115): a forwarded link request that was never proven may mean
    /// the path to its destination went stale.
    fn rediscover_unproven_link_paths(&mut self, now: f64) {
        let mut requests: Vec<([u8; 16], Option<InterfaceId>)> = Vec::new();
        let unproven: Vec<LinkEntry> = self
            .routes
            .links
            .values()
            .filter(|entry| !entry.validated && now > entry.proof_timeout)
            .cloned()
            .collect();
        for entry in unproven {
            let destination_hash = entry.destination_hash;
            let throttled = self
                .last_path_request(&destination_hash)
                .is_some_and(|requested_at| now - requested_at < constants::PATH_REQUEST_MI);
            let mut skip_interface = None;
            let mut mark_unresponsive = false;
            let rediscover = if !self.has_path(&destination_hash) {
                // The path was dropped after the link request went out.
                log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                    "Trying to rediscover path for {:02x?} since an attempted link was never established, and path is now missing",
                    &destination_hash[..4],
                );
                true
            } else if throttled {
                false
            } else if entry.taken_hops == 0 {
                // Upstream 5bd93ad9: not for an instance-local (hops-0)
                // destination, and as upstream's elif chain, such a link
                // request triggers none of the cases below either.
                if self.hops_to(&destination_hash) == Some(0) {
                    false
                } else {
                    log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                        "Trying to rediscover path for {:02x?} since an attempted local client link was never established",
                        &destination_hash[..4],
                    );
                    true
                }
            } else if self.hops_to(&destination_hash) == Some(1) {
                // The destination was local to one of our interfaces and
                // probably roamed.
                log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                    "Trying to rediscover path for {:02x?} since an attempted link was never established, and destination was previously local to an interface on this instance",
                    &destination_hash[..4],
                );
                skip_interface = Some(entry.received_interface);
                mark_unresponsive = true;
                true
            } else if entry.taken_hops == 1 {
                // The initiator is local, so the topology probably changed.
                log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                    "Trying to rediscover path for {:02x?} since an attempted link was never established, and link initiator is local to an interface on this instance",
                    &destination_hash[..4],
                );
                skip_interface = Some(entry.received_interface);
                mark_unresponsive = true;
                true
            } else {
                false
            };
            if !rediscover {
                continue;
            }
            if mark_unresponsive && self.config.transport_enabled {
                // Skipped when the request came in on a boundary interface.
                self.mark_path_unresponsive(&destination_hash, Some(entry.received_interface));
            }
            if !requests
                .iter()
                .any(|(queued, _)| *queued == destination_hash)
            {
                requests.push((destination_hash, skip_interface));
            }
            if !self.config.transport_enabled {
                // Let a non-transport node take a longer path or a path from
                // a newly adjacent transport instance.
                self.expire_path(&destination_hash);
            }
        }
        for (destination_hash, skip_interface) in requests {
            self.queue_path_rediscovery(destination_hash, skip_interface, now);
        }
    }

    fn process_tick_pending_announces(&mut self, ctx: &mut TickCtx<'_>) {
        if ctx.now <= self.timers.announces_last_checked + constants::ANNOUNCES_CHECK_INTERVAL {
            return;
        }

        self.cull_expired_announce_entries(ctx.now);
        self.enforce_announce_retention_cap(ctx.now);
        if let Some(identity_hash) = self.config.identity_hash {
            let mut blocked_broadcasts = BTreeMap::new();
            let announce_actions = jobs::process_pending_announces(
                &mut self.announces.table,
                &mut self.announces.held,
                &identity_hash,
                ctx.now,
                &mut blocked_broadcasts,
            );
            let gated =
                self.gate_retransmit_actions(announce_actions, &blocked_broadcasts, ctx.now);
            ctx.actions.extend(gated);
        }
        self.cull_expired_announce_entries(ctx.now);
        self.enforce_announce_retention_cap(ctx.now);
        self.timers.announces_last_checked = ctx.now;
    }

    fn process_tick_ingress_release(&mut self, ctx: &mut TickCtx<'_>) {
        let ic_interfaces = self.ingress_control.interfaces_with_held();
        for iface_id in ic_interfaces {
            let (ia_freq, started, ingress_config) = match self.interfaces.get(&iface_id) {
                Some(info) => (info.ia_freq, info.started, info.ingress_control),
                None => continue,
            };
            if !ingress_config.enabled {
                continue;
            }
            // Upstream 85d36979: held announces that can no longer update
            // their destination's path are culled before one is released.
            let (config, paths, interfaces) = (&self.config, &self.paths, &self.interfaces);
            let now = ctx.now;
            let keep = |destination_hash: &[u8; 16], held: &ingress_control::HeldAnnounce| {
                let Ok(packet) = RawPacket::unpack(&held.raw) else {
                    return true;
                };
                announce_passes_prefilter(
                    config,
                    paths,
                    interfaces,
                    destination_hash,
                    packet.data(),
                    held.receiving_interface,
                    now,
                )
            };
            if let Some(held) = self.ingress_control.process_held_announces(
                iface_id,
                &ingress_config,
                ia_freq,
                started,
                ctx.now,
                keep,
            ) {
                let released_actions = self.handle_inbound(
                    InboundFrame {
                        raw: &held.raw,
                        iface: held.receiving_interface,
                        now: ctx.now,
                        rx: held.rx,
                    },
                    ctx.rng,
                );
                // Since upstream 29dc449a a release goes through
                // `Transport.inbound` with accounting, so its frame is charged
                // again, to received or filtered bytes, and a filtered
                // announce counts in afrxc. Inbound processing records it as
                // a received announce (c850cdac).
                self.accounting.released_traffic.push(ReleasedTraffic {
                    interface: held.receiving_interface,
                    size: held.raw.len(),
                    filtered: core::mem::take(&mut self.accounting.inbound_filtered),
                    filtered_announce: core::mem::take(
                        &mut self.accounting.inbound_filtered_announce,
                    ),
                });
                ctx.actions.extend(released_actions);
            }
        }
    }

    fn cull_tick_tables(&mut self, ctx: &mut TickCtx<'_>) {
        if ctx.now <= self.timers.tables_last_culled + constants::TABLES_CULL_INTERVAL {
            return;
        }

        let unused_path_linger = self.unused_path_linger();
        jobs::cull_path_table(
            &mut self.paths.table,
            &self.interfaces,
            ctx.now,
            unused_path_linger,
            jobs::UnusedPoolLimits::UPSTREAM,
            self.policy.hop_limiter,
        );
        jobs::cull_reverse_table(&mut self.routes.reverse, &self.interfaces, ctx.now);
        self.rediscover_unproven_link_paths(ctx.now);
        let (_culled, link_closed_actions) =
            jobs::cull_link_table(&mut self.routes.links, &self.interfaces, ctx.now);
        ctx.actions.extend(link_closed_actions);
        jobs::cull_path_states(&mut self.paths.states, &self.paths.table);
        self.cull_blackholed(ctx.now);
        // Upstream drops a path request gate, and a discovery path request,
        // only once its timeout has passed.
        self.path_requests.gates.retain(|_, requested_at| {
            ctx.now <= *requested_at + constants::PATH_REQUEST_GATE_TIMEOUT
        });
        self.path_requests.discovery.retain(|destination, req| {
            let deadline = self
                .path_requests
                .discovery_deadlines
                .get(destination)
                .copied()
                .unwrap_or(req.timestamp + constants::DISCOVERY_PATH_REQUEST_TIMEOUT);
            ctx.now <= deadline
        });
        self.path_requests
            .discovery_deadlines
            .retain(|destination, _| self.path_requests.discovery.contains_key(destination));
        // Transport.py culls these only when the requesting interface is
        // gone; also expire them, as a local client answers right away.
        self.path_requests
            .pending_local
            .retain(|_, (interface, requested_at)| {
                self.interfaces.contains_key(interface)
                    && ctx.now < *requested_at + constants::PATH_REQUEST_TIMEOUT
            });
        self.tunnels
            .table
            .void_missing_interfaces(ctx.now, |id| self.interfaces.contains_key(id));
        self.tunnels.table.cull(ctx.now);
        self.announces.sig_cache.cull(ctx.now);
        self.timers.tables_last_culled = ctx.now;
    }

    /// Gate retransmitted announce actions through per-interface bandwidth queues.
    ///
    /// Retransmitted announces always have hops > 0.
    /// `BroadcastOnAllInterfaces` is expanded to per-interface sends gated through queues.
    pub(super) fn gate_retransmit_actions(
        &mut self,
        actions: Vec<TransportAction>,
        blocked_broadcasts: &BTreeMap<[u8; 16], BTreeSet<InterfaceId>>,
        now: f64,
    ) -> Vec<TransportAction> {
        let mut result = Vec::new();
        for action in actions {
            match action {
                TransportAction::SendOnInterface { interface, raw } => {
                    // Extract dest_hash from raw (bytes 2..18 for H1, 18..34 for H2)
                    let (dest_hash, hops) = Self::extract_announce_info(&raw);
                    let (bitrate, airtime_profile, announce_cap) =
                        if let Some(info) = self.interfaces.get(&interface) {
                            (info.bitrate, info.airtime_profile, info.announce_cap)
                        } else {
                            (None, None, constants::ANNOUNCE_CAP)
                        };
                    let emitted = announce_queue::announce_emitted(&raw).unwrap_or(now);
                    if let Some(send_action) = self.announces.queues.gate_announce(
                        interface,
                        raw,
                        dest_hash,
                        hops,
                        emitted,
                        now,
                        bitrate,
                        airtime_profile,
                        announce_cap,
                    ) {
                        result.push(send_action);
                    }
                }
                TransportAction::BroadcastOnAllInterfaces { raw, exclude } => {
                    let (dest_hash, hops) = Self::extract_announce_info(&raw);
                    // Upstream da368e05: interfaces the announce was heard
                    // on again while it waited are left out.
                    let blocked = blocked_broadcasts.get(&dest_hash);
                    // Expand to per-interface sends gated through queues,
                    // applying mode filtering (AP blocks non-local announces, etc.)
                    let iface_ids: Vec<(
                        InterfaceId,
                        Option<u64>,
                        Option<types::AirtimeProfile>,
                        f64,
                    )> = self
                        .interfaces
                        .iter()
                        .filter(|(_, info)| info.out_capable)
                        // Without transport, the only rebroadcasts are local
                        // client announces, which the local client relay has
                        // already delivered to the other local clients.
                        .filter(|(_, info)| self.config.transport_enabled || !info.is_local_client)
                        .filter(|(id, _)| {
                            if let Some(ref ex) = exclude {
                                **id != *ex
                            } else {
                                true
                            }
                        })
                        .filter(|(id, _)| !blocked.is_some_and(|blocked| blocked.contains(id)))
                        .filter(|(_, info)| {
                            should_transmit_announce(
                                info,
                                &dest_hash,
                                hops,
                                &self.local_destinations,
                                &self.paths.table,
                                &self.interfaces,
                            )
                        })
                        .map(|(id, info)| {
                            (*id, info.bitrate, info.airtime_profile, info.announce_cap)
                        })
                        .collect();

                    for (iface_id, bitrate, airtime_profile, announce_cap) in iface_ids {
                        let emitted = announce_queue::announce_emitted(&raw).unwrap_or(now);
                        if let Some(send_action) = self.announces.queues.gate_announce(
                            iface_id,
                            raw.clone(),
                            dest_hash,
                            hops,
                            emitted,
                            now,
                            bitrate,
                            airtime_profile,
                            announce_cap,
                        ) {
                            result.push(send_action);
                        }
                    }
                }
                other => result.push(other),
            }
        }
        result
    }

    /// Extract destination hash and hops from raw announce bytes.
    fn extract_announce_info(raw: &[u8]) -> ([u8; 16], u8) {
        if raw.len() < 18 {
            return ([0; 16], 0);
        }
        let header_type = (raw[0] >> 6) & 0x03;
        let hops = raw[1];
        if header_type == constants::HEADER_2 && raw.len() >= 34 {
            // H2: transport_id at [2..18], dest_hash at [18..34]
            let mut dest = [0u8; 16];
            dest.copy_from_slice(&raw[18..34]);
            (dest, hops)
        } else {
            // H1: dest_hash at [2..18]
            let mut dest = [0u8; 16];
            dest.copy_from_slice(&raw[2..18]);
            (dest, hops)
        }
    }

    #[cfg(test)]
    pub(crate) fn link_table_ref(&self) -> &super::tables::LinkTable {
        &self.routes.links
    }
}

#[cfg(test)]
#[path = "maintenance_tests.rs"]
mod tests;
