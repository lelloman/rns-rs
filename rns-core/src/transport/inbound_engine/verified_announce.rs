//! What a verified announce does to the path table, the announce
//! table and local clients.

use super::*;

impl TransportEngine {
    /// Upstream da368e05: a copy of the announce waiting in the announce
    /// table (same packet hash, so any hop count and relaying node), heard
    /// on an interface that is not a shared medium, means the neighbour
    /// there already has it, so the rebroadcast skips that interface.
    fn record_announce_heard_while_waiting(
        &mut self,
        packet: &RawPacket<PacketBytes>,
        iface: InterfaceId,
    ) {
        let shared_medium = self
            .interfaces
            .get(&iface)
            .is_some_and(|info| info.shared_medium);
        if shared_medium {
            return;
        }
        if let Some(waiting) = self.announces.table.get_mut(&packet.destination_hash) {
            if waiting.packet_hash == packet.packet_hash {
                waiting.blocked_interfaces.insert(iface);
            }
        }
    }

    pub(super) fn process_verified_announce(
        &mut self,
        mut ctx: VerifiedAnnounceCtx<'_>,
        rng: &mut dyn Rng,
        actions: &mut Vec<TransportAction>,
    ) {
        if !self.admit_verified_announce(&mut ctx) {
            return;
        }
        // Upstream's `received_announce(size)`: a valid announce that was
        // not held counts as received, with its bytes, whatever the path
        // table then makes of it.
        self.accounting
            .announce_receipts
            .push((ctx.iface, ctx.original_raw.len()));

        if ctx.packet.hops > constants::PATHFINDER_M {
            return;
        }

        let Some(mp_decision) = self.decide_announced_path(&ctx) else {
            return;
        };
        let rate_blocked = self.announce_rate_blocked(&ctx);
        let (expires, announce_entry) =
            self.store_announced_path(&ctx, &mp_decision, rate_blocked, rng, actions);
        self.store_announced_tunnel_path(&ctx, expires);

        // Re-apply the path-state reset after storing the path entry so any transient
        // stale state is also cleared once the destination exists in the path table.
        self.paths.states.remove(&ctx.packet.destination_hash);
        // Upstream 833f6cf2: an announce from a local client this instance
        // serves proves its destination alive, so its path is marked
        // responsive (timestamp, expiry and use refreshed) instead of
        // unknown.
        if self.serves_local_client(ctx.iface) {
            self.mark_path_responsive(&ctx.packet.destination_hash, ctx.now);
        }

        self.store_announce_for_retransmission(&ctx, &mp_decision, announce_entry);

        let VerifiedAnnounceCtx {
            packet,
            iface,
            now,
            validated,
            received_from,
            ..
        } = ctx;
        actions.push(received_announce_action(packet, iface, validated));
        actions.push(TransportAction::PathUpdated {
            destination_hash: packet.destination_hash,
            hops: packet.hops,
            next_hop: received_from,
            interface: iface,
        });

        // An announce arriving with PATHFINDER_M - 1 hops now carries
        // PATHFINDER_M, which no node decodes: it updates the path table but
        // is not sent on (upstream's `Packet.send` refuses it).
        let sendable = packet.hops < constants::PATHFINDER_M;

        // Forward announce to local clients if any are connected
        if sendable && self.has_local_clients() {
            actions.push(TransportAction::ForwardToLocalClients {
                raw: self.announce_raw_for_local_clients(packet),
                exclude: Some(iface),
            });
        }

        self.answer_discovery_path_requests(packet, received_from, now, sendable, actions);
    }

    /// Whether a verified announce passes the blackhole, its stamp and
    /// ingress control; one that does not is filtered, or held.
    fn admit_verified_announce(&mut self, ctx: &mut VerifiedAnnounceCtx<'_>) -> bool {
        if self.is_blackholed(&ctx.validated.identity_hash, ctx.now) {
            self.filter_announce();
            return false;
        }

        // Identity.validate_announce since 9b464382: the receiving
        // interface's `destination_cost`, else `Transport.DESTINATION_COST`.
        let required_value = self
            .interfaces
            .get(&ctx.iface)
            .map(|info| {
                info.stamp_costs
                    .destination_cost(&self.policy.stamp_requirements)
            })
            .unwrap_or(self.policy.stamp_requirements.destination_cost);
        let stamp_status = ctx
            .validated
            .apply_stamp(&ctx.packet.destination_hash, required_value);
        if self.policy.stamp_requirements.enforced
            && stamp_status != crate::announce::AnnounceStampStatus::Valid
        {
            self.filter_announce();
            return false;
        }

        // As upstream's `preprocess_inbound`, ingress control judges an
        // announce only once its signature, identity and stamp have passed,
        // so an invalid or blackholed one neither starts nor ends a burst,
        // and judges it by the announces received before it.
        let hold = if self.ingress_limited(ctx.packet, ctx.iface, ctx.now) {
            self.hold_decision(ctx.packet, ctx.original_raw, ctx.iface, ctx.now)
        } else {
            HoldDecision::Pass
        };
        match hold {
            HoldDecision::Pass => true,
            HoldDecision::Held => false,
            HoldDecision::Filtered => {
                self.filter_announce();
                false
            }
        }
    }

    /// How the announce changes its destination's paths, or `None` when it
    /// is rejected.
    fn decide_announced_path(
        &mut self,
        ctx: &VerifiedAnnounceCtx<'_>,
    ) -> Option<MultiPathDecision> {
        let existing_set = self.paths.table.get(&ctx.packet.destination_hash);
        let was_unknown_destination = existing_set.is_none_or(|ps| ps.is_empty());

        // Reset stale path state before first-path installation so path-state handling
        // cannot race ahead of the path table for previously unknown destinations.
        if was_unknown_destination {
            self.paths.states.remove(&ctx.packet.destination_hash);
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
                ctx.now,
                current_gravity,
                announce_gravity,
                self.config.unresponsive_path_recovery,
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
            self.config.unresponsive_path_recovery,
        );

        if mp_decision == MultiPathDecision::Reject {
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Announce:path decision REJECT for dest={:02x}{:02x}{:02x}{:02x}..",
                ctx.packet.destination_hash[0],
                ctx.packet.destination_hash[1],
                ctx.packet.destination_hash[2],
                ctx.packet.destination_hash[3],
            );
            self.record_announce_heard_while_waiting(ctx.packet, ctx.iface);
            return None;
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
        Some(mp_decision)
    }

    /// Whether the announce rate limit of the receiving interface blocks
    /// the announce's rebroadcast. Path responses are not rate limited.
    fn announce_rate_blocked(&mut self, ctx: &VerifiedAnnounceCtx<'_>) -> bool {
        if ctx.packet.context == constants::CONTEXT_PATH_RESPONSE {
            return false;
        }
        let Some(iface_info) = self.interfaces.get(&ctx.iface) else {
            return false;
        };
        self.announces.rate_limiter.check_and_update(
            &ctx.packet.destination_hash,
            ctx.now,
            iface_info.announce_rate_target,
            iface_info.announce_rate_grace,
            iface_info.announce_rate_penalty,
        )
    }

    /// Install the announced path as `mp_decision` says and ask for the
    /// announce to be cached. Returns the path's expiry and the announce
    /// table entry to retransmit it with, if any.
    fn store_announced_path(
        &mut self,
        ctx: &VerifiedAnnounceCtx<'_>,
        mp_decision: &MultiPathDecision,
        rate_blocked: bool,
        rng: &mut dyn Rng,
        actions: &mut Vec<TransportAction>,
    ) -> (f64, Option<AnnounceEntry>) {
        // Get interface mode for expiry calculation
        let interface_mode = self
            .interfaces
            .get(&ctx.iface)
            .map(|i| i.mode)
            .unwrap_or(constants::MODE_FULL);

        let expires = compute_path_expires(ctx.now, interface_mode);

        // Get existing random blobs from the matching path (same next_hop)
        // or empty; the replaced path's when the primary path is replaced
        // as upstream does.
        let replaces_as_upstream =
            matches!(mp_decision, MultiPathDecision::ReplaceAsUpstream { .. });
        let existing_blobs = self
            .paths
            .table
            .get(&ctx.packet.destination_hash)
            .and_then(|ps| {
                if replaces_as_upstream {
                    ps.primary()
                } else {
                    ps.find_by_next_hop(&ctx.received_from)
                }
            })
            .map(|e| e.random_blobs.clone())
            .unwrap_or_default();

        // Generate RNG value for retransmit timeout
        let mut rng_bytes = [0u8; 8];
        rng.fill_bytes(&mut rng_bytes);
        let rng_value = (u64::from_le_bytes(rng_bytes) as f64) / (u64::MAX as f64);

        let is_path_response = ctx.packet.context == constants::CONTEXT_PATH_RESPONSE;

        let (mut path_entry, announce_entry) = announce_proc::process_validated_announce(
            ctx.packet.destination_hash,
            ctx.packet.hops,
            ctx.packet.data(),
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
            self.serves_local_client(ctx.iface),
            is_path_response,
            rate_blocked,
            Some(ctx.original_raw.to_vec()),
        );

        // Emit CacheAnnounce for disk caching (pre-hop-increment raw)
        actions.push(TransportAction::CacheAnnounce {
            packet_hash: ctx.packet.packet_hash,
            raw: ctx.original_raw.to_vec().into(),
        });

        // As upstream, the new path keeps when the destination's path was
        // last used.
        path_entry.used = self
            .paths
            .table
            .get(&ctx.packet.destination_hash)
            .and_then(|ps| ps.primary())
            .map_or(0.0, |path| path.used);

        // Store path via upsert into PathSet
        match mp_decision {
            MultiPathDecision::ReplacePrimary | MultiPathDecision::RecoverUnresponsive => self
                .upsert_primary_path_destination(ctx.packet.destination_hash, path_entry, ctx.now),
            MultiPathDecision::ReplaceAsUpstream { .. } => self.replace_primary_path_destination(
                ctx.packet.destination_hash,
                path_entry,
                ctx.now,
            ),
            MultiPathDecision::AddAlternative => {
                self.upsert_path_destination(ctx.packet.destination_hash, path_entry, ctx.now)
            }
            // Rejected announces return before this; none is stored.
            MultiPathDecision::Reject => {}
        }
        (expires, announce_entry)
    }

    /// If the receiving interface has a tunnel, store the announced path in
    /// the tunnel table too.
    fn store_announced_tunnel_path(&mut self, ctx: &VerifiedAnnounceCtx<'_>, expires: f64) {
        let Some(tunnel_id) = self.interfaces.get(&ctx.iface).and_then(|i| i.tunnel_id) else {
            return;
        };
        // As upstream, the tunnel keeps the path's random blobs and
        // when it was last used.
        let (blobs, used) = self
            .paths
            .table
            .get(&ctx.packet.destination_hash)
            .and_then(|ps| ps.find_by_next_hop(&ctx.received_from))
            .map(|e| (e.random_blobs.clone(), e.used))
            .unwrap_or_default();
        self.tunnels.table.store_tunnel_path(
            &tunnel_id,
            ctx.packet.destination_hash,
            tunnel::TunnelPath {
                timestamp: ctx.now,
                received_from: ctx.received_from,
                hops: ctx.packet.hops,
                expires,
                random_blobs: blobs,
                packet_hash: ctx.packet.packet_hash,
                used,
            },
            ctx.now,
            self.config.destination_timeout_secs,
            self.config.max_tunnel_destinations_total,
        );
    }

    /// Put the announce in the announce table for retransmission: its own
    /// entry, or for a local client's path response, one that answers the
    /// pending request.
    fn store_announce_for_retransmission(
        &mut self,
        ctx: &VerifiedAnnounceCtx<'_>,
        mp_decision: &MultiPathDecision,
        announce_entry: Option<AnnounceEntry>,
    ) {
        // Upstream 8c73e203: an announce accepted only because the path
        // is unresponsive updates the path table but is not rebroadcast.
        let table_insertion_only = matches!(
            mp_decision,
            MultiPathDecision::RecoverUnresponsive
                | MultiPathDecision::ReplaceAsUpstream { rebroadcast: false }
        );
        let is_path_response = ctx.packet.context == constants::CONTEXT_PATH_RESPONSE;

        if let Some(ann) = announce_entry {
            if !table_insertion_only {
                self.insert_announce_entry(ctx.packet.destination_hash, ann, ctx.now);
            }
        } else if is_path_response && self.serves_local_client(ctx.iface) {
            // As upstream, a local client's path response that answers a
            // pending request is retransmitted at once and once only. Since
            // upstream 70eb417d it goes only to the requesting interface, as
            // a path response (attached interface, blocked rebroadcast).
            if let Some((requesting_interface, _)) = self
                .path_requests
                .pending_local
                .remove(&ctx.packet.destination_hash)
            {
                let entry = path_response_entry(
                    ctx.packet,
                    ctx.received_from,
                    ctx.now,
                    Some(requesting_interface),
                );
                self.insert_announce_entry(ctx.packet.destination_hash, entry, ctx.now);
            }
        }
    }

    /// Answer the discovery path requests waiting for this announce's
    /// destination with a path response.
    fn answer_discovery_path_requests(
        &mut self,
        packet: &RawPacket<PacketBytes>,
        received_from: [u8; 16],
        now: f64,
        sendable: bool,
        actions: &mut Vec<TransportAction>,
    ) {
        let Some(requesting_interfaces) =
            self.discovery_path_requests_waiting(&packet.destination_hash)
        else {
            return;
        };
        // Build a path response announce and queue it
        let entry = path_response_entry(
            packet,
            received_from,
            now,
            requesting_interfaces.first().copied(),
        );
        if let Some(identity_hash) = self.config.identity_hash.filter(|_| sendable) {
            let raw = announce_proc::build_retransmit_announce(&entry, &identity_hash);
            for interface in requesting_interfaces.iter().skip(1) {
                actions.push(TransportAction::SendOnInterface {
                    interface: *interface,
                    raw: raw.clone().into(),
                });
            }
        }
        self.insert_announce_entry(packet.destination_hash, entry, now);
    }
}

/// An announce table entry that sends `packet` once, at once, as a path
/// response on `attached_interface`, with rebroadcasts blocked.
fn path_response_entry(
    packet: &RawPacket<PacketBytes>,
    received_from: [u8; 16],
    now: f64,
    attached_interface: Option<InterfaceId>,
) -> AnnounceEntry {
    AnnounceEntry {
        timestamp: now,
        retransmit_timeout: now,
        retries: constants::PATHFINDER_R,
        received_from,
        hops: packet.hops,
        packet_raw: packet.raw.to_vec(),
        packet_data: packet.data().to_vec(),
        destination_hash: packet.destination_hash,
        context_flag: packet.flags.context_flag,
        local_rebroadcasts: 0,
        block_rebroadcasts: true,
        attached_interface,
        packet_hash: packet.packet_hash,
        blocked_interfaces: Default::default(),
    }
}

/// The action reporting a received announce to the caller.
fn received_announce_action(
    packet: &RawPacket<PacketBytes>,
    iface: InterfaceId,
    validated: crate::announce::ValidatedAnnounce,
) -> TransportAction {
    TransportAction::AnnounceReceived(alloc::boxed::Box::new(types::ReceivedAnnounce {
        destination_hash: packet.destination_hash,
        packet_hash: packet.packet_hash,
        identity_hash: validated.identity_hash,
        public_key: validated.public_key,
        name_hash: validated.name_hash,
        random_hash: validated.random_hash,
        ratchet: validated.ratchet,
        app_data: validated.app_data,
        stamp: validated.stamp,
        stamp_value: validated.stamp_value,
        lr_cost: validated.lr_cost,
        hops: packet.hops,
        receiving_interface: iface,
        rx: RxMetadata {
            rssi: packet.rssi,
            snr: packet.snr,
        },
    }))
}
