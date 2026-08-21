use super::*;

pub(super) fn discovery_path_request_timeout(
    interfaces: &BTreeMap<InterfaceId, InterfaceInfo>,
) -> f64 {
    let Some(lowest_bitrate) = interfaces
        .values()
        .filter_map(|interface| interface.bitrate)
        .filter(|bitrate| *bitrate > 0)
        .min()
    else {
        return constants::PATH_REQUEST_TIMEOUT;
    };
    let effective_bitrate = lowest_bitrate.max(constants::MINIMUM_BITRATE);
    let medium_timeout = 2.0 * (constants::MTU as f64 * 8.0 / effective_bitrate as f64)
        + constants::LINK_ESTABLISHMENT_TIMEOUT_PER_HOP;
    constants::PATH_REQUEST_TIMEOUT.max(medium_timeout)
}

impl TransportEngine {
    pub fn handle_path_request(
        &mut self,
        data: &[u8],
        interface_id: InterfaceId,
        now: f64,
    ) -> Vec<TransportAction> {
        self.handle_path_request_with_ingress_limit(data, interface_id, now, false)
    }

    /// Handle a path request while preserving an earlier ingress-limiter
    /// classification made by an external prioritized queue.
    #[doc(hidden)]
    pub fn handle_path_request_with_ingress_limit(
        &mut self,
        data: &[u8],
        interface_id: InterfaceId,
        now: f64,
        ingress_limited: bool,
    ) -> Vec<TransportAction> {
        let Some(request) = self.accept_path_request(data, interface_id, now) else {
            return Vec::new();
        };
        self.handle_accepted_path_request_with_ingress_limit(request, ingress_limited)
    }

    /// Validate and deduplicate a path request before recording ingress stats.
    #[doc(hidden)]
    pub fn accept_path_request(
        &mut self,
        data: &[u8],
        interface_id: InterfaceId,
        now: f64,
    ) -> Option<AcceptedPathRequest> {
        self.parse_path_request(data, interface_id, now)
    }

    /// Process a request returned by [`Self::accept_path_request`].
    #[doc(hidden)]
    pub fn handle_accepted_path_request_with_ingress_limit(
        &mut self,
        ctx: AcceptedPathRequest,
        ingress_limited: bool,
    ) -> Vec<TransportAction> {
        log::trace!(target: crate::logging::PATHING_LOG_TARGET,
            "Path request for {:02x?} on interface {}",
            &ctx.destination_hash[..4],
            ctx.interface_id.0,
        );
        if ctx.already_in_flight {
            self.batch_inflight_path_request(&ctx, ingress_limited);
            return Vec::new();
        }
        if self.local_destinations.contains_key(&ctx.destination_hash) {
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Ignoring path request for {:02x?}: destination is local",
                &ctx.destination_hash[..4],
            );
            return Vec::new();
        }
        if self.config.transport_enabled && self.handle_known_path_request(&ctx) {
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Answering path request for {:02x?}: path is known",
                &ctx.destination_hash[..4],
            );
            return Vec::new();
        }
        if self.config.transport_enabled {
            return self.handle_discovery_path_request(&ctx, ingress_limited);
        }
        log::trace!(target: crate::logging::PATHING_LOG_TARGET,
            "Ignoring path request for {:02x?}: transport is disabled",
            &ctx.destination_hash[..4],
        );
        Vec::new()
    }

    fn parse_path_request(
        &mut self,
        data: &[u8],
        interface_id: InterfaceId,
        now: f64,
    ) -> Option<AcceptedPathRequest> {
        if data.len() < 16 {
            return None;
        }

        let mut destination_hash = [0u8; 16];
        destination_hash.copy_from_slice(&data[..16]);

        let tag_bytes = if data.len() > 32 {
            Some(&data[32..])
        } else if data.len() > 16 {
            Some(&data[16..])
        } else {
            None
        };
        let Some(tag_bytes) = tag_bytes else {
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Ignoring tagless path request for {:02x?}",
                &destination_hash[..4],
            );
            return None;
        };

        let tag_len = tag_bytes.len().min(16);
        let mut unique_tag = [0u8; 32];
        unique_tag[..16].copy_from_slice(&destination_hash);
        unique_tag[16..16 + tag_len].copy_from_slice(&tag_bytes[..tag_len]);
        if !self.insert_discovery_pr_tag(unique_tag) {
            return None;
        }

        let already_in_flight = self.path_requests.contains_key(&destination_hash)
            && !self.path_table.contains_key(&destination_hash)
            && !self.local_destinations.contains_key(&destination_hash);
        self.path_requests.entry(destination_hash).or_insert(now);

        let mut tag = [0u8; 16];
        tag[..tag_len].copy_from_slice(&tag_bytes[..tag_len]);
        Some(AcceptedPathRequest {
            tag,
            tag_len,
            interface_id,
            now,
            destination_hash,
            already_in_flight,
        })
    }

    fn batch_inflight_path_request(&mut self, ctx: &AcceptedPathRequest, ingress_limited: bool) {
        let Some((ingress_control, ip_freq, started)) = self
            .interfaces
            .get(&ctx.interface_id)
            .map(|info| (info.ingress_control, info.ip_freq, info.started))
        else {
            return;
        };
        if ingress_limited
            || self.ingress_control.should_ingress_limit_pr(
                ctx.interface_id,
                &ingress_control,
                ip_freq,
                started,
                ctx.now,
            )
        {
            return;
        }

        let timeout = discovery_path_request_timeout(&self.interfaces);
        let request = self
            .discovery_path_requests
            .entry(ctx.destination_hash)
            .or_insert_with(|| DiscoveryPathRequest {
                timestamp: ctx.now,
                requesting_interfaces: Vec::new(),
                engaged: false,
            });
        if !request.requesting_interfaces.contains(&ctx.interface_id) {
            request.requesting_interfaces.push(ctx.interface_id);
        }
        self.discovery_path_request_deadlines
            .entry(ctx.destination_hash)
            .or_insert(ctx.now + timeout);
    }

    /// Record a locally generated path request, refreshing its gate timeout.
    #[doc(hidden)]
    pub fn record_outbound_path_request(&mut self, destination_hash: [u8; 16], now: f64) {
        self.path_requests.insert(destination_hash, now);
    }

    fn handle_known_path_request(&mut self, ctx: &AcceptedPathRequest) -> bool {
        let Some(path) = self
            .path_table
            .get(&ctx.destination_hash)
            .and_then(|ps| ps.primary())
            .cloned()
        else {
            return false;
        };

        if let Some(recv_info) = self.interfaces.get(&ctx.interface_id) {
            if recv_info.mode == constants::MODE_ROAMING
                && path.receiving_interface == ctx.interface_id
            {
                return true;
            }
        }

        let Some(raw) = path.announce_raw.as_ref() else {
            return false;
        };
        if let Some(existing) = self.announce_table.remove(&ctx.destination_hash) {
            self.insert_held_announce(ctx.destination_hash, existing, ctx.now);
        }
        let retransmit_timeout = if let Some(iface_info) = self.interfaces.get(&ctx.interface_id) {
            let base = ctx.now + constants::PATH_REQUEST_GRACE;
            if iface_info.mode == constants::MODE_ROAMING {
                base + constants::PATH_REQUEST_RG
            } else {
                base
            }
        } else {
            ctx.now + constants::PATH_REQUEST_GRACE
        };

        let Ok(parsed) = RawPacket::unpack(raw) else {
            return false;
        };

        let entry = AnnounceEntry {
            timestamp: ctx.now,
            retransmit_timeout,
            retries: constants::PATHFINDER_R,
            received_from: path.next_hop,
            hops: path.hops,
            packet_raw: raw.clone(),
            packet_data: parsed.data,
            destination_hash: ctx.destination_hash,
            context_flag: parsed.flags.context_flag,
            local_rebroadcasts: 0,
            block_rebroadcasts: true,
            attached_interface: Some(ctx.interface_id),
        };

        self.insert_announce_entry(ctx.destination_hash, entry, ctx.now);
        true
    }

    fn handle_discovery_path_request(
        &mut self,
        ctx: &AcceptedPathRequest,
        ingress_limited: bool,
    ) -> Vec<TransportAction> {
        let Some((mode, recursive_prs, ingress_control, ip_freq, started)) =
            self.interfaces.get(&ctx.interface_id).map(|info| {
                (
                    info.mode,
                    info.recursive_prs,
                    info.ingress_control,
                    info.ip_freq,
                    info.started,
                )
            })
        else {
            return Vec::new();
        };

        let search_mode_filter: Option<&[u8]> = if recursive_prs
            || constants::DISCOVER_PATHS_FOR.contains(&mode)
        {
            None
        } else if mode == constants::MODE_BOUNDARY {
            Some(&constants::BOUNDARY_SEARCH_MODES)
        } else {
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Not discovering path to {:02x?}: recursive path discovery is disabled on interface {}",
                &ctx.destination_hash[..4],
                ctx.interface_id.0,
            );
            return Vec::new();
        };

        if ingress_limited
            || self.ingress_control.should_ingress_limit_pr(
                ctx.interface_id,
                &ingress_control,
                ip_freq,
                started,
                ctx.now,
            )
        {
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Not discovering path to {:02x?}: ingress path-request limiting is active on interface {}",
                &ctx.destination_hash[..4],
                ctx.interface_id.0,
            );
            return Vec::new();
        }

        let egress_candidates: Vec<_> = self
            .interfaces
            .values()
            .filter(|info| info.id != ctx.interface_id && info.out_capable)
            .filter(|info| search_mode_filter.is_none_or(|modes| modes.contains(&info.mode)))
            .map(|info| {
                (
                    info.id,
                    info.ingress_control,
                    info.op_freq,
                    info.op_samples,
                    info.bitrate,
                    info.airtime_profile,
                    info.announce_cap,
                )
            })
            .collect();

        let Some((path_request_raw, path_request_len)) = build_path_request_packet(
            &ctx.destination_hash,
            self.config.identity_hash.as_ref(),
            &ctx.tag[..ctx.tag_len],
        ) else {
            return Vec::new();
        };

        let mut actions = Vec::new();
        for (id, ingress_control, op_freq, op_samples, bitrate, airtime_profile, announce_cap) in
            egress_candidates
        {
            if self.ingress_control.should_egress_limit_pr(
                id,
                &ingress_control,
                op_freq,
                op_samples,
            ) || self
                .announce_queues
                .blocks_recursive_path_request(id, ctx.now)
            {
                continue;
            }

            self.announce_queues.reserve_recursive_path_request(
                id,
                path_request_len + constants::HEADER_MINSIZE,
                ctx.now,
                bitrate,
                airtime_profile,
                announce_cap,
            );
            actions.push(TransportAction::SendOnInterface {
                interface: id,
                raw: path_request_raw.clone().into(),
            });
        }

        if !actions.is_empty() {
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Discovering unknown path to {:02x?} on behalf of interface {} via {} interfaces",
                &ctx.destination_hash[..4],
                ctx.interface_id.0,
                actions.len(),
            );
            let request = self
                .discovery_path_requests
                .entry(ctx.destination_hash)
                .or_insert_with(|| DiscoveryPathRequest {
                    timestamp: ctx.now,
                    requesting_interfaces: Vec::new(),
                    engaged: false,
                });
            if !request.requesting_interfaces.contains(&ctx.interface_id) {
                request.requesting_interfaces.push(ctx.interface_id);
            }
            request.engaged = true;
            let timeout = discovery_path_request_timeout(&self.interfaces);
            self.discovery_path_request_deadlines
                .insert(ctx.destination_hash, ctx.now + timeout);
        } else {
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Not discovering path to {:02x?}: no eligible egress interface",
                &ctx.destination_hash[..4],
            );
        }

        actions
    }
}

fn build_path_request_packet(
    destination_hash: &[u8; 16],
    transport_identity_hash: Option<&[u8; 16]>,
    tag: &[u8],
) -> Option<(Vec<u8>, usize)> {
    let mut data = Vec::with_capacity(16 + transport_identity_hash.map_or(0, |_| 16) + tag.len());
    data.extend_from_slice(destination_hash);
    if let Some(identity_hash) = transport_identity_hash {
        data.extend_from_slice(identity_hash);
    }
    data.extend_from_slice(tag);

    let flags = crate::packet::PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_PLAIN,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let path_request_dest =
        crate::destination::destination_hash("rnstransport", &["path", "request"], None);

    let data_len = data.len();
    RawPacket::pack(
        flags,
        0,
        &path_request_dest,
        None,
        constants::CONTEXT_NONE,
        &data,
    )
    .ok()
    .map(|packet| (packet.raw, data_len))
}
