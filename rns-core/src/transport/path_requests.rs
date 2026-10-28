use super::*;

pub fn lowest_interface_bitrate(interfaces: &BTreeMap<InterfaceId, InterfaceInfo>) -> Option<u64> {
    // Having no usable bitrate is a normal state, not a diagnostic condition.
    // Callers fall back to the fixed path-request timeout without logging.
    interfaces
        .values()
        .filter_map(|interface| interface.bitrate)
        .filter(|bitrate| *bitrate > 0)
        .min()
}

pub fn medium_path_timeout(interfaces: &BTreeMap<InterfaceId, InterfaceInfo>) -> f64 {
    let Some(lowest_bitrate) = lowest_interface_bitrate(interfaces) else {
        return 0.0;
    };
    let effective_bitrate = lowest_bitrate.max(constants::MINIMUM_BITRATE);
    2.0 * (constants::MTU as f64 * 8.0 / effective_bitrate as f64)
        + constants::LINK_ESTABLISHMENT_TIMEOUT_PER_HOP
}

pub(super) fn discovery_path_request_timeout(
    interfaces: &BTreeMap<InterfaceId, InterfaceInfo>,
) -> f64 {
    constants::PATH_REQUEST_TIMEOUT.max(medium_path_timeout(interfaces))
}

impl TransportEngine {
    /// Re-check live path-request egress state immediately before dispatch.
    #[doc(hidden)]
    pub fn should_egress_limit_path_request(
        &mut self,
        interface_id: InterfaceId,
        pr_freq: f64,
        sample_count: usize,
    ) -> bool {
        let Some(config) = self
            .interfaces
            .get(&interface_id)
            .map(|info| info.ingress_control)
        else {
            return false;
        };
        self.ingress_control
            .should_egress_limit_pr(interface_id, &config, pr_freq, sample_count)
    }

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
        let from_local_client = self.serves_local_client(ctx.interface_id);
        // Transport.py:3439-3448: remember who asked for a destination behind
        // a local client, so the client's path response can be relayed back.
        if self
            .next_hop_interface(&ctx.destination_hash)
            .is_some_and(|iface| self.serves_local_client(iface))
        {
            self.pending_local_path_requests
                .insert(ctx.destination_hash, (ctx.interface_id, ctx.now));
        }
        // Transport.py:3450-3457: a destination local to this system answers
        // with a path-response announce on the requesting interface, whether
        // or not transport is enabled. The caller holds the keys to build it.
        if self.local_destinations.contains_key(&ctx.destination_hash) {
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Answering path request for {:02x?}: destination is local",
                &ctx.destination_hash[..4],
            );
            return alloc::vec![TransportAction::AnnounceLocalPathResponse {
                destination_hash: ctx.destination_hash,
                tag: ctx.tag[..ctx.tag_len].to_vec(),
                interface: ctx.interface_id,
            }];
        }
        // Transport.py:3459: a shared instance answers its local clients from
        // the path table even without transport.
        if (self.config.transport_enabled || from_local_client)
            && self.handle_known_path_request(&ctx, from_local_client)
        {
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Answering path request for {:02x?}: path is known",
                &ctx.destination_hash[..4],
            );
            return Vec::new();
        }
        if from_local_client {
            // Transport.py:3523-3530: forward on all other interfaces.
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Forwarding path request from local client for {:02x?} to all other interfaces",
                &ctx.destination_hash[..4],
            );
            return self.forward_path_request(&ctx, |info| info.id != ctx.interface_id, false);
        }
        if self.config.transport_enabled && self.discovery_search_mode(ctx.interface_id).is_some() {
            return self.handle_discovery_path_request(&ctx, ingress_limited);
        }
        if self.serves_local_clients() {
            // Transport.py:3585-3590: forward on all local client interfaces;
            // a client's path response is relayed back to the requester.
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Forwarding path request for {:02x?} to local clients",
                &ctx.destination_hash[..4],
            );
            return self.forward_path_request(&ctx, |info| info.is_local_client, true);
        }
        log::trace!(target: crate::logging::PATHING_LOG_TARGET,
            "Ignoring path request for {:02x?}: no path known",
            &ctx.destination_hash[..4],
        );
        Vec::new()
    }

    /// Send a new path request for `ctx`'s destination on the interfaces
    /// selected by `select`, as `Transport.request_path` does without a tag.
    fn forward_path_request(
        &mut self,
        ctx: &AcceptedPathRequest,
        select: impl Fn(&InterfaceInfo) -> bool,
        relay_to_local_clients: bool,
    ) -> Vec<TransportAction> {
        // A stamped request is relayed with its original tag and extension:
        // the stamp covers the tag, so deriving a new one would invalidate it.
        // During the transition, a stamping node marks an unstamped request
        // relayed to local clients with the 0xFF sentinel flags byte.
        let ext_payload = ctx.ext_payload.or_else(|| {
            (relay_to_local_clients && constants::STAMP_PRS && !constants::STAMPS_ENFORCED)
                .then(unstamped_relay_payload)
        });
        let tag: Vec<u8> = if ext_payload.is_some() {
            ctx.tag[..ctx.tag_len].to_vec()
        } else {
            // Python uses a fresh random tag. The engine has no RNG here, so
            // derive one from the request that was answered; it differs from
            // the incoming tag and is recorded so echoes of it are dropped.
            let mut seed = Vec::with_capacity(16 + 16 + 8 + 8);
            seed.extend_from_slice(&ctx.destination_hash);
            seed.extend_from_slice(&ctx.tag[..ctx.tag_len]);
            seed.extend_from_slice(&ctx.interface_id.0.to_be_bytes());
            seed.extend_from_slice(&ctx.now.to_bits().to_be_bytes());
            let derived = hash::truncated_hash(&seed);
            let mut unique_tag = [0u8; 32];
            unique_tag[..16].copy_from_slice(&ctx.destination_hash);
            unique_tag[16..].copy_from_slice(&derived);
            self.insert_discovery_pr_tag(unique_tag);
            derived.to_vec()
        };

        let transport_identity_hash = if self.config.transport_enabled {
            self.config.identity_hash.as_ref()
        } else {
            None
        };
        let Some((raw, _)) = build_path_request_packet(
            &ctx.destination_hash,
            transport_identity_hash,
            &tag,
            ext_payload.as_ref(),
        ) else {
            return Vec::new();
        };
        self.interfaces
            .values()
            .filter(|info| info.out_capable && select(info))
            .map(|info| TransportAction::SendOnInterface {
                interface: info.id,
                raw: raw.clone().into(),
            })
            .collect()
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

        // Stamped 1.6.0+ requests carry a 16-byte extension payload after the
        // destination hash, transport id and tag.
        let (request_len, ext_payload) = if data.len() == constants::PATH_REQUEST_STAMPED_LENGTH {
            let mut ext = [0u8; constants::EXT_PAYLOAD_LENGTH];
            ext.copy_from_slice(&data[constants::PATH_REQUEST_LENGTH..]);
            (constants::PATH_REQUEST_LENGTH, Some(ext))
        } else {
            if data.len() > constants::PATH_REQUEST_LENGTH {
                return None;
            }
            (data.len(), None)
        };
        let request_data = &data[..request_len];

        let tag_bytes = if request_data.len() > 32 {
            Some(&request_data[32..])
        } else if request_data.len() > 16 {
            Some(&request_data[16..])
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

        if constants::STAMPS_ENABLED {
            let valid = ext_payload.is_some_and(|ext| {
                if ext[0] != constants::EXT_PAYLOAD_MARKER {
                    return false;
                }
                let mut material = Vec::with_capacity(16 + tag_len);
                material.extend_from_slice(&destination_hash);
                material.extend_from_slice(&tag_bytes[..tag_len]);
                let workblock = crate::stamp::stamp_workblock(&material, 0);
                crate::stamp::stamp_valid(
                    &ext[constants::EXT_HEADER_LENGTH..],
                    constants::PATH_REQUEST_STAMP_COST,
                    &workblock,
                )
            });
            if constants::STAMPS_ENFORCED && !valid {
                return None;
            }
        }

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
            ext_payload,
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

    fn handle_known_path_request(
        &mut self,
        ctx: &AcceptedPathRequest,
        from_local_client: bool,
    ) -> bool {
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
        // Leave the active entry in place until replacement so insertion can
        // preserve its pending send deadline under repeated path requests.
        if let Some(existing) = self.announce_table.get(&ctx.destination_hash).cloned() {
            self.insert_held_announce(ctx.destination_hash, existing, ctx.now);
        }
        // Transport.py:3492-3506: answer local clients, and requests for
        // destinations behind a local client, immediately.
        let retransmit_timeout =
            if from_local_client || self.interface_is_local_client(path.receiving_interface) {
                ctx.now
            } else if let Some(iface_info) = self.interfaces.get(&ctx.interface_id) {
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
            packet_data: parsed.data().to_vec(),
            destination_hash: ctx.destination_hash,
            context_flag: parsed.flags.context_flag,
            local_rebroadcasts: 0,
            block_rebroadcasts: true,
            attached_interface: Some(ctx.interface_id),
        };

        self.insert_announce_entry(ctx.destination_hash, entry, ctx.now);
        true
    }

    /// Whether a path request on `interface_id` searches for unknown paths
    /// (`should_search_for_unknown` in Transport.py), and in which modes.
    fn discovery_search_mode(&self, interface_id: InterfaceId) -> Option<Option<&'static [u8]>> {
        self.interfaces
            .get(&interface_id)
            .and_then(|info| search_mode_filter(info.mode, info.recursive_prs))
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

        let Some(search_mode_filter) = search_mode_filter(mode, recursive_prs) else {
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
            ctx.ext_payload.as_ref(),
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

/// Interface modes to search for an unknown path requested on an interface
/// in `mode`: `None` if it does not search, `Some(None)` for all modes.
fn search_mode_filter(mode: u8, recursive_prs: bool) -> Option<Option<&'static [u8]>> {
    if recursive_prs || constants::DISCOVER_PATHS_FOR.contains(&mode) {
        Some(None)
    } else if mode == constants::MODE_BOUNDARY {
        Some(Some(&constants::BOUNDARY_SEARCH_MODES))
    } else {
        None
    }
}

/// Transitional extension payload marking an unstamped request relayed by a
/// stamp-aware node to its local clients.
pub(crate) fn unstamped_relay_payload() -> [u8; constants::EXT_PAYLOAD_LENGTH] {
    let mut ext = [0u8; constants::EXT_PAYLOAD_LENGTH];
    ext[0] = constants::EXT_PAYLOAD_MARKER;
    ext[1] = 0xFF;
    ext
}

/// Build a path request frame, optionally appending a stamp extension.
///
/// The extension is opaque here: the caller supplies the verified payload so
/// a relayed request keeps the exact `marker | flags | stamp` bytes that the
/// original sender signed the stamp for.
fn build_path_request_packet(
    destination_hash: &[u8; 16],
    transport_identity_hash: Option<&[u8; 16]>,
    tag: &[u8],
    ext_payload: Option<&[u8; constants::EXT_PAYLOAD_LENGTH]>,
) -> Option<(Vec<u8>, usize)> {
    let mut data = Vec::with_capacity(
        16 + transport_identity_hash.map_or(0, |_| 16)
            + tag.len()
            + ext_payload.map_or(0, |_| constants::EXT_PAYLOAD_LENGTH),
    );
    data.extend_from_slice(destination_hash);
    if let Some(identity_hash) = transport_identity_hash {
        data.extend_from_slice(identity_hash);
    }
    data.extend_from_slice(tag);
    if let Some(ext) = ext_payload {
        data.extend_from_slice(ext);
    }

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
