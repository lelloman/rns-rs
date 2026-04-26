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
        if self.config.transport_enabled && self.has_path(&ctx.destination_hash) {
            self.handle_known_path_request(&ctx);
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

    fn handle_known_path_request(&mut self, ctx: &PathRequestCtx<'_>) {
        let Some(path) = self
            .path_table
            .get(&ctx.destination_hash)
            .and_then(|ps| ps.primary())
            .cloned()
        else {
            return;
        };

        if let Some(recv_info) = self.interfaces.get(&ctx.interface_id) {
            if recv_info.mode == constants::MODE_ROAMING
                && path.receiving_interface == ctx.interface_id
            {
                return;
            }
        }

        let Some(raw) = path.announce_raw.as_ref() else {
            return;
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
            return;
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
    }

    fn handle_discovery_path_request(&mut self, ctx: &PathRequestCtx<'_>) -> Vec<TransportAction> {
        let should_discover = self
            .interfaces
            .get(&ctx.interface_id)
            .map(|info| constants::DISCOVER_PATHS_FOR.contains(&info.mode))
            .unwrap_or(false);
        if !should_discover {
            return Vec::new();
        }

        self.discovery_path_requests.insert(
            ctx.destination_hash,
            DiscoveryPathRequest {
                timestamp: ctx.now,
                requesting_interface: ctx.interface_id,
            },
        );

        self.interfaces
            .values()
            .filter(|iface_info| iface_info.id != ctx.interface_id && iface_info.out_capable)
            .map(|iface_info| TransportAction::SendOnInterface {
                interface: iface_info.id,
                raw: ctx.data.to_vec(),
            })
            .collect()
    }
}
