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
        if let Some(waiting) = self.announce_table.get_mut(&packet.destination_hash) {
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
        if self.is_blackholed(&ctx.validated.identity_hash, ctx.now) {
            self.filter_announce();
            return;
        }

        // Identity.validate_announce since 9b464382: the receiving
        // interface's `destination_cost`, else `Transport.DESTINATION_COST`.
        let required_value = self
            .interfaces
            .get(&ctx.iface)
            .map(|info| info.stamp_costs.destination_cost(&self.stamp_requirements))
            .unwrap_or(self.stamp_requirements.destination_cost);
        let stamp_status = ctx
            .validated
            .apply_stamp(&ctx.packet.destination_hash, required_value);
        if self.stamp_requirements.enforced
            && stamp_status != crate::announce::AnnounceStampStatus::Valid
        {
            self.filter_announce();
            return;
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
            HoldDecision::Pass => {}
            HoldDecision::Held => return,
            HoldDecision::Filtered => {
                self.filter_announce();
                return;
            }
        }
        // Upstream's `received_announce(size)`: a valid announce that was
        // not held counts as received, with its bytes, whatever the path
        // table then makes of it.
        self.announce_receipts
            .push((ctx.iface, ctx.original_raw.len()));

        if ctx.packet.hops > constants::PATHFINDER_M {
            return;
        }

        let existing_set = self.path_table.get(&ctx.packet.destination_hash);
        let was_unknown_destination = existing_set.is_none_or(|ps| ps.is_empty());

        // Reset stale path state before first-path installation so path-state handling
        // cannot race ahead of the path table for previously unknown destinations.
        if was_unknown_destination {
            self.path_states.remove(&ctx.packet.destination_hash);
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
            return;
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

        // Rate limiting
        let rate_blocked = if ctx.packet.context != constants::CONTEXT_PATH_RESPONSE {
            if let Some(iface_info) = self.interfaces.get(&ctx.iface) {
                self.rate_limiter.check_and_update(
                    &ctx.packet.destination_hash,
                    ctx.now,
                    iface_info.announce_rate_target,
                    iface_info.announce_rate_grace,
                    iface_info.announce_rate_penalty,
                )
            } else {
                false
            }
        } else {
            false
        };

        // Get interface mode for expiry calculation
        let interface_mode = self
            .interfaces
            .get(&ctx.iface)
            .map(|i| i.mode)
            .unwrap_or(constants::MODE_FULL);

        let expires = compute_path_expires(ctx.now, interface_mode);

        // Get existing random blobs from the matching path (same next_hop) or empty
        let existing_blobs = self
            .path_table
            .get(&ctx.packet.destination_hash)
            .and_then(|ps| ps.find_by_next_hop(&ctx.received_from))
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
            .path_table
            .get(&ctx.packet.destination_hash)
            .and_then(|ps| ps.primary())
            .map_or(0.0, |path| path.used);

        // Store path via upsert into PathSet
        match mp_decision {
            MultiPathDecision::ReplacePrimary => self.upsert_primary_path_destination(
                ctx.packet.destination_hash,
                path_entry,
                ctx.now,
            ),
            MultiPathDecision::AddAlternative => {
                self.upsert_path_destination(ctx.packet.destination_hash, path_entry, ctx.now)
            }
            MultiPathDecision::Reject => unreachable!("rejected decisions returned above"),
        }

        // If receiving interface has a tunnel_id, store path in tunnel table too
        if let Some(tunnel_id) = self.interfaces.get(&ctx.iface).and_then(|i| i.tunnel_id) {
            // As upstream, the tunnel keeps the path's random blobs and
            // when it was last used.
            let (blobs, used) = self
                .path_table
                .get(&ctx.packet.destination_hash)
                .and_then(|ps| ps.find_by_next_hop(&ctx.received_from))
                .map(|e| (e.random_blobs.clone(), e.used))
                .unwrap_or_default();
            self.tunnel_table.store_tunnel_path(
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

        // Re-apply the path-state reset after storing the path entry so any transient
        // stale state is also cleared once the destination exists in the path table.
        self.path_states.remove(&ctx.packet.destination_hash);
        // Upstream 833f6cf2: an announce from a local client this instance
        // serves proves its destination alive, so its path is marked
        // responsive (timestamp, expiry and use refreshed) instead of
        // unknown.
        if self.serves_local_client(ctx.iface) {
            self.mark_path_responsive(&ctx.packet.destination_hash, ctx.now);
        }

        // Store announce for retransmission
        if let Some(ann) = announce_entry {
            self.insert_announce_entry(ctx.packet.destination_hash, ann, ctx.now);
        } else if is_path_response && self.serves_local_client(ctx.iface) {
            // As upstream, a local client's path response that answers a
            // pending request is retransmitted at once and once only. Since
            // upstream 70eb417d it goes only to the requesting interface, as
            // a path response (attached interface, blocked rebroadcast).
            if let Some((requesting_interface, _)) = self
                .pending_local_path_requests
                .remove(&ctx.packet.destination_hash)
            {
                let entry = AnnounceEntry {
                    timestamp: ctx.now,
                    retransmit_timeout: ctx.now,
                    retries: constants::PATHFINDER_R,
                    received_from: ctx.received_from,
                    hops: ctx.packet.hops,
                    packet_raw: ctx.packet.raw.to_vec(),
                    packet_data: ctx.packet.data().to_vec(),
                    destination_hash: ctx.packet.destination_hash,
                    context_flag: ctx.packet.flags.context_flag,
                    local_rebroadcasts: 0,
                    block_rebroadcasts: true,
                    attached_interface: Some(requesting_interface),
                    packet_hash: ctx.packet.packet_hash,
                    blocked_interfaces: Default::default(),
                };
                self.insert_announce_entry(ctx.packet.destination_hash, entry, ctx.now);
            }
        }

        // Emit actions
        actions.push(TransportAction::AnnounceReceived(alloc::boxed::Box::new(
            types::ReceivedAnnounce {
                destination_hash: ctx.packet.destination_hash,
                packet_hash: ctx.packet.packet_hash,
                identity_hash: ctx.validated.identity_hash,
                public_key: ctx.validated.public_key,
                name_hash: ctx.validated.name_hash,
                random_hash: ctx.validated.random_hash,
                ratchet: ctx.validated.ratchet,
                app_data: ctx.validated.app_data,
                stamp: ctx.validated.stamp,
                stamp_value: ctx.validated.stamp_value,
                lr_cost: ctx.validated.lr_cost,
                hops: ctx.packet.hops,
                receiving_interface: ctx.iface,
                rx: RxMetadata {
                    rssi: ctx.packet.rssi,
                    snr: ctx.packet.snr,
                },
            },
        )));

        actions.push(TransportAction::PathUpdated {
            destination_hash: ctx.packet.destination_hash,
            hops: ctx.packet.hops,
            next_hop: ctx.received_from,
            interface: ctx.iface,
        });

        // An announce arriving with PATHFINDER_M - 1 hops now carries
        // PATHFINDER_M, which no node decodes: it updates the path table but
        // is not sent on (upstream's `Packet.send` refuses it).
        let sendable = ctx.packet.hops < constants::PATHFINDER_M;

        // Forward announce to local clients if any are connected
        if sendable && self.has_local_clients() {
            actions.push(TransportAction::ForwardToLocalClients {
                raw: self.announce_raw_for_local_clients(ctx.packet),
                exclude: Some(ctx.iface),
            });
        }

        // Check for discovery path requests waiting for this announce
        if let Some(requesting_interfaces) =
            self.discovery_path_requests_waiting(&ctx.packet.destination_hash)
        {
            // Build a path response announce and queue it
            let entry = AnnounceEntry {
                timestamp: ctx.now,
                retransmit_timeout: ctx.now,
                retries: constants::PATHFINDER_R,
                received_from: ctx.received_from,
                hops: ctx.packet.hops,
                packet_raw: ctx.packet.raw.to_vec(),
                packet_data: ctx.packet.data().to_vec(),
                destination_hash: ctx.packet.destination_hash,
                context_flag: ctx.packet.flags.context_flag,
                local_rebroadcasts: 0,
                block_rebroadcasts: true,
                attached_interface: requesting_interfaces.first().copied(),
                packet_hash: ctx.packet.packet_hash,
                blocked_interfaces: Default::default(),
            };
            if let Some(identity_hash) = self.config.identity_hash.filter(|_| sendable) {
                let raw = announce_proc::build_retransmit_announce(&entry, &identity_hash);
                for interface in requesting_interfaces.iter().skip(1) {
                    actions.push(TransportAction::SendOnInterface {
                        interface: *interface,
                        raw: raw.clone().into(),
                    });
                }
            }
            self.insert_announce_entry(ctx.packet.destination_hash, entry, ctx.now);
        }
    }
}
