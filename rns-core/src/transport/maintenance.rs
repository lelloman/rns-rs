use super::*;

impl TransportEngine {
    /// Periodic maintenance. Call regularly (e.g., every 250ms).
    pub fn tick(&mut self, now: f64, rng: &mut dyn Rng) -> Vec<TransportAction> {
        let mut ctx = TickCtx {
            now,
            rng,
            actions: Vec::new(),
        };
        self.process_tick_pending_announces(&mut ctx);

        let mut queue_actions = self.announce_queues.process_queues(now, &self.interfaces);
        ctx.actions.append(&mut queue_actions);

        self.process_tick_ingress_release(&mut ctx);
        self.cull_tick_tables(&mut ctx);
        ctx.actions
    }

    fn process_tick_pending_announces(&mut self, ctx: &mut TickCtx<'_>) {
        if ctx.now <= self.announces_last_checked + constants::ANNOUNCES_CHECK_INTERVAL {
            return;
        }

        self.cull_expired_announce_entries(ctx.now);
        self.enforce_announce_retention_cap(ctx.now);
        if let Some(identity_hash) = self.config.identity_hash {
            let announce_actions = jobs::process_pending_announces(
                &mut self.announce_table,
                &mut self.held_announces,
                &identity_hash,
                ctx.now,
            );
            let gated = self.gate_retransmit_actions(announce_actions, ctx.now);
            ctx.actions.extend(gated);
        }
        self.cull_expired_announce_entries(ctx.now);
        self.enforce_announce_retention_cap(ctx.now);
        self.announces_last_checked = ctx.now;
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
            if let Some(held) = self.ingress_control.process_held_announces(
                iface_id,
                &ingress_config,
                ia_freq,
                started,
                ctx.now,
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
                ctx.actions.extend(released_actions);
            }
        }
    }

    fn cull_tick_tables(&mut self, ctx: &mut TickCtx<'_>) {
        if ctx.now <= self.tables_last_culled + constants::TABLES_CULL_INTERVAL {
            return;
        }

        jobs::cull_path_table(&mut self.path_table, &self.interfaces, ctx.now);
        jobs::cull_reverse_table(&mut self.reverse_table, &self.interfaces, ctx.now);
        let (_culled, link_closed_actions) =
            jobs::cull_link_table(&mut self.link_table, &self.interfaces, ctx.now);
        ctx.actions.extend(link_closed_actions);
        jobs::cull_path_states(&mut self.path_states, &self.path_table);
        self.cull_blackholed(ctx.now);
        self.path_requests.retain(|_, requested_at| {
            ctx.now < *requested_at + constants::PATH_REQUEST_GATE_TIMEOUT
        });
        self.discovery_path_requests.retain(|destination, req| {
            let deadline = self
                .discovery_path_request_deadlines
                .get(destination)
                .copied()
                .unwrap_or(req.timestamp + constants::DISCOVERY_PATH_REQUEST_TIMEOUT);
            ctx.now < deadline
        });
        self.discovery_path_request_deadlines
            .retain(|destination, _| self.discovery_path_requests.contains_key(destination));
        self.tunnel_table
            .void_missing_interfaces(|id| self.interfaces.contains_key(id));
        self.tunnel_table.cull(ctx.now);
        self.announce_sig_cache.cull(ctx.now);
        self.tables_last_culled = ctx.now;
    }

    /// Gate retransmitted announce actions through per-interface bandwidth queues.
    ///
    /// Retransmitted announces always have hops > 0.
    /// `BroadcastOnAllInterfaces` is expanded to per-interface sends gated through queues.
    pub(super) fn gate_retransmit_actions(
        &mut self,
        actions: Vec<TransportAction>,
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
                    if let Some(send_action) = self.announce_queues.gate_announce(
                        interface,
                        raw,
                        dest_hash,
                        hops,
                        now,
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
                        .filter(|(id, _)| {
                            if let Some(ref ex) = exclude {
                                **id != *ex
                            } else {
                                true
                            }
                        })
                        .filter(|(_, info)| {
                            should_transmit_announce(
                                info,
                                &dest_hash,
                                hops,
                                &self.local_destinations,
                                &self.path_table,
                                &self.interfaces,
                            )
                        })
                        .map(|(id, info)| {
                            (*id, info.bitrate, info.airtime_profile, info.announce_cap)
                        })
                        .collect();

                    for (iface_id, bitrate, airtime_profile, announce_cap) in iface_ids {
                        if let Some(send_action) = self.announce_queues.gate_announce(
                            iface_id,
                            raw.clone(),
                            dest_hash,
                            hops,
                            now,
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
    #[allow(dead_code)]
    pub(crate) fn link_table_ref(&self) -> &BTreeMap<[u8; 16], LinkEntry> {
        &self.link_table
    }
}
