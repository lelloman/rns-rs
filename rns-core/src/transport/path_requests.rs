use super::*;

impl TransportEngine {
    pub fn handle_path_request(
        &mut self,
        data: &[u8],
        interface_id: InterfaceId,
        now: f64,
    ) -> Vec<TransportAction> {
        let Some(ctx) = self.parse_path_request(data, interface_id, now) else {
            return Vec::new();
        };
        if self.local_destinations.contains_key(&ctx.destination_hash) {
            return Vec::new();
        }
        if self.config.transport_enabled && self.handle_known_path_request(&ctx) {
            return Vec::new();
        }
        if self.config.transport_enabled {
            return self.handle_discovery_path_request(&ctx);
        }
        Vec::new()
    }

    fn parse_path_request<'a>(
        &mut self,
        data: &'a [u8],
        interface_id: InterfaceId,
        now: f64,
    ) -> Option<PathRequestCtx<'a>> {
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
        }?;

        let tag_len = tag_bytes.len().min(16);
        let mut unique_tag = [0u8; 32];
        unique_tag[..16].copy_from_slice(&destination_hash);
        unique_tag[16..16 + tag_len].copy_from_slice(&tag_bytes[..tag_len]);
        if !self.insert_discovery_pr_tag(unique_tag) {
            return None;
        }

        Some(PathRequestCtx {
            data,
            interface_id,
            now,
            destination_hash,
        })
    }

    fn handle_known_path_request(&mut self, ctx: &PathRequestCtx<'_>) -> bool {
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

    fn handle_discovery_path_request(&mut self, ctx: &PathRequestCtx<'_>) -> Vec<TransportAction> {
        let Some((mode, ingress_control, ip_freq, started)) = self
            .interfaces
            .get(&ctx.interface_id)
            .map(|info| (info.mode, info.ingress_control, info.ip_freq, info.started))
        else {
            return Vec::new();
        };

        let should_discover = constants::DISCOVER_PATHS_FOR.contains(&mode);
        if !should_discover {
            return Vec::new();
        }

        if self.ingress_control.should_ingress_limit_pr(
            ctx.interface_id,
            &ingress_control,
            ip_freq,
            started,
            ctx.now,
        ) {
            return Vec::new();
        }

        let egress_candidates: Vec<_> = self
            .interfaces
            .values()
            .filter(|info| info.id != ctx.interface_id && info.out_capable)
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
                ctx.data.len() + constants::HEADER_MINSIZE,
                ctx.now,
                bitrate,
                airtime_profile,
                announce_cap,
            );
            actions.push(TransportAction::SendOnInterface {
                interface: id,
                raw: ctx.data.to_vec().into(),
            });
        }

        if !actions.is_empty() {
            self.discovery_path_requests.insert(
                ctx.destination_hash,
                DiscoveryPathRequest {
                    timestamp: ctx.now,
                    requesting_interface: ctx.interface_id,
                },
            );
        }

        actions
    }
}
