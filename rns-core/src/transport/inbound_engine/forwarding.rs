//! Forwarding packets for others, routing link traffic, and delivering
//! to local destinations.

use super::*;

impl TransportEngine {
    pub(super) fn bridge_plain_broadcast(
        &self,
        ctx: &InboundPacketCtx,
        actions: &mut Vec<TransportAction>,
    ) {
        // Transport.py:2227: control destinations (path requests and tunnel
        // synthesis) are handled by the engine, which re-emits path requests
        // itself, and are never bridged raw. Bridging them as well would send
        // a local client's path request twice, once raw and once rebuilt
        // (and stamped, when STAMP_PRS is on), with the rebuilt copy then
        // dropped downstream as a duplicate tag.
        if ctx.packet.flags.destination_type != constants::DESTINATION_PLAIN
            || ctx.packet.flags.transport_type != constants::TRANSPORT_BROADCAST
            || !self.has_local_clients()
            || self
                .control_destinations
                .contains(&ctx.packet.destination_hash)
        {
            return;
        }

        if ctx.from_local_client {
            actions.push(TransportAction::ForwardPlainBroadcast {
                raw: PacketBytes::from(ctx.packet.raw.clone()),
                to_local: false,
                exclude: Some(ctx.iface),
            });
        } else {
            actions.push(TransportAction::ForwardPlainBroadcast {
                raw: PacketBytes::from(ctx.packet.raw.clone()),
                to_local: true,
                exclude: None,
            });
        }
    }

    pub(super) fn handle_transport_forwarding(
        &mut self,
        ctx: &InboundPacketCtx,
        actions: &mut Vec<TransportAction>,
    ) {
        if !(self.config.transport_enabled || self.config.identity_hash.is_some()) {
            return;
        }
        // Transport.py: clients behind a shared instance are announced with a
        // "spoofed" hop count of 0, so they look directly reachable and
        // senders strip the transport header. Treat a packet for such a
        // client as addressed to us so normal forwarding handles it (#183).
        let for_local_client = ctx.packet.flags.packet_type != constants::PACKET_TYPE_ANNOUNCE
            && self
                .path_table
                .get(&ctx.packet.destination_hash)
                .and_then(|ps| ps.primary())
                .is_some_and(|entry| {
                    entry.hops == 0 && self.interface_is_local_client(entry.receiving_interface)
                });
        let transport_id = match ctx.packet.transport_id {
            None if for_local_client => self.config.identity_hash,
            transport_id => transport_id,
        };
        if transport_id.is_none() || ctx.packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE
        {
            if ctx.packet.flags.packet_type == constants::PACKET_TYPE_DATA {
                log::debug!(
                    "TransportForward: DATA dest={:02x}{:02x}{:02x}{:02x}.. not transport-addressed header={} iface={}",
                    ctx.packet.destination_hash[0],
                    ctx.packet.destination_hash[1],
                    ctx.packet.destination_hash[2],
                    ctx.packet.destination_hash[3],
                    ctx.packet.flags.header_type,
                    ctx.iface.0
                );
            }
            return;
        }

        let Some(identity_hash) = self.config.identity_hash else {
            return;
        };
        if transport_id != Some(identity_hash) {
            if ctx.packet.flags.packet_type == constants::PACKET_TYPE_DATA {
                log::debug!(
                    "TransportForward: DATA dest={:02x}{:02x}{:02x}{:02x}.. transport mismatch got={:02x?} own={:02x?} iface={}",
                    ctx.packet.destination_hash[0],
                    ctx.packet.destination_hash[1],
                    ctx.packet.destination_hash[2],
                    ctx.packet.destination_hash[3],
                    ctx.packet.transport_id.as_ref().map(|id| &id[..4]),
                    &identity_hash[..4],
                    ctx.iface.0
                );
            }
            return;
        }

        let Some(path_entry) = self
            .path_table
            .get(&ctx.packet.destination_hash)
            .and_then(|ps| ps.primary())
        else {
            if ctx.packet.flags.packet_type == constants::PACKET_TYPE_DATA {
                log::debug!(
                    "TransportForward: DATA dest={:02x}{:02x}{:02x}{:02x}.. addressed to us but no path iface={}",
                    ctx.packet.destination_hash[0],
                    ctx.packet.destination_hash[1],
                    ctx.packet.destination_hash[2],
                    ctx.packet.destination_hash[3],
                    ctx.iface.0
                );
            }
            return;
        };

        let next_hop = path_entry.next_hop;
        let remaining_hops = path_entry.hops;
        let outbound_interface = path_entry.receiving_interface;
        let outbound_is_local_client = self
            .interfaces
            .get(&outbound_interface)
            .map(|info| info.is_local_client)
            .unwrap_or(false);
        let forwarded_remaining_hops = if outbound_is_local_client {
            0
        } else {
            remaining_hops
        };
        if ctx.packet.flags.packet_type == constants::PACKET_TYPE_DATA {
            log::debug!(
                "TransportForward: DATA dest={:02x}{:02x}{:02x}{:02x}.. remaining_hops={} out_iface={} next_hop={:02x?}",
                ctx.packet.destination_hash[0],
                ctx.packet.destination_hash[1],
                ctx.packet.destination_hash[2],
                ctx.packet.destination_hash[3],
                remaining_hops,
                outbound_interface.0,
                &next_hop[..4]
            );
        }
        let mut new_raw = forward_transport_packet(
            &ctx.packet,
            next_hop,
            forwarded_remaining_hops,
            outbound_interface,
        );
        if self.config.local_hops_delta != 0
            && ctx.from_local_client
            && !outbound_is_local_client
            && ctx.packet.hops == 0
            && ctx.packet.flags.destination_type != constants::DESTINATION_PLAIN
            && ctx.packet.flags.destination_type != constants::DESTINATION_GROUP
            && new_raw.len() > 1
        {
            new_raw[1] = self.config.local_hops_delta;
        }

        if ctx.packet.flags.packet_type == constants::PACKET_TYPE_LINKREQUEST {
            if let Err(mode) = clamp_forwarded_link_request_mtu(
                &mut new_raw,
                ctx.packet.data().len() == constants::LINK_ECPUBSIZE + constants::LINK_MTU_SIZE,
                self.interfaces.get(&ctx.iface).map(|info| info.mtu),
                self.interfaces
                    .get(&outbound_interface)
                    .filter(|info| info.mtu_upgradable)
                    .map(|info| info.mtu),
            ) {
                // Transport.py: `Link.signalling_bytes` raises for a mode
                // outside `ENABLED_MODES`, and the request is dropped before
                // any link table entry, transmission or path use.
                log::debug!(
                    "Dropping link request packet. The contained exception was: Requested link mode {} not enabled",
                    crate::link::types::mode_description(mode)
                );
                self.undecodable_mtu_signalling(ctx.iface, actions);
                return;
            }
            let extra_proof_timeout =
                extra_link_proof_timeout(self.interfaces.get(&outbound_interface));
            let proof_timeout = ctx.now
                + constants::LINK_ESTABLISHMENT_TIMEOUT_PER_HOP * (remaining_hops.max(1) as f64)
                + extra_proof_timeout;
            let (link_id, link_entry) = create_link_entry(
                &ctx.packet,
                next_hop,
                outbound_interface,
                remaining_hops,
                ctx.iface,
                ctx.now,
                proof_timeout,
            );
            self.link_table.insert(link_id, link_entry);
            actions.push(TransportAction::LinkRequestReceived {
                link_id,
                destination_hash: ctx.packet.destination_hash,
                receiving_interface: ctx.iface,
            });
        } else {
            let (trunc_hash, reverse_entry) =
                create_reverse_entry(&ctx.packet, outbound_interface, ctx.iface, ctx.now);
            self.reverse_table.insert(trunc_hash, reverse_entry);
        }

        actions.push(TransportAction::SendOnInterface {
            interface: outbound_interface,
            raw: new_raw.into(),
        });

        // Transport.py (1.6.0) marks the path used, so the unused path pool
        // culling keeps paths that carry traffic through this node.
        if let Some(entry) = self
            .path_table
            .get_mut(&ctx.packet.destination_hash)
            .and_then(|ps| ps.primary_mut())
        {
            entry.used = ctx.now;
        }
    }

    pub(super) fn handle_link_table_routing(
        &mut self,
        ctx: &InboundPacketCtx,
        actions: &mut Vec<TransportAction>,
    ) {
        if !self.config.transport_enabled && self.config.identity_hash.is_none() {
            return;
        }
        if ctx.packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE
            || ctx.packet.flags.packet_type == constants::PACKET_TYPE_LINKREQUEST
            || ctx.packet.context == constants::CONTEXT_LRPROOF
        {
            return;
        }

        // This single keyed lookup is the native link fast path. The engine is
        // already exclusively borrowed, and the typed entry contains every
        // routing and hop-rewrite field, so a second denormalized cache would
        // add invalidation risk without avoiding locks or linear searches.
        // Keep this authoritative-table path even when profiling suggests a
        // cache: upstream's corresponding denormalized experiment was removed.
        let Some(link_entry) = self.link_table.get(&ctx.packet.destination_hash).cloned() else {
            return;
        };
        if !link_entry.validated {
            return;
        }
        let instance_local_link = self.interface_is_local_client(link_entry.next_hop_interface)
            && self.interface_is_local_client(link_entry.received_interface);
        let Some((outbound_iface, new_raw)) =
            crate::transport::inbound::route_via_link_table_shared(
                &ctx.packet,
                &link_entry,
                ctx.iface,
                LocalHopRewrite {
                    local_hops_delta: self.config.local_hops_delta,
                    from_local_client: ctx.from_local_client,
                    skip_local_hops_delta: instance_local_link,
                },
            )
        else {
            // A link entry with no route from this receiving interface is an
            // expected fast-path miss, not an operator-facing warning.
            return;
        };

        // A deferred packet's context bypasses deduplication, so its hash
        // could never mark a later packet as a duplicate.
        if !ctx.hash_deferred {
            self.packet_hashlist.add(ctx.packet.packet_hash);
        }
        actions.push(TransportAction::SendOnInterface {
            interface: outbound_iface,
            raw: new_raw,
        });

        if let Some(entry) = self.link_table.get_mut(&ctx.packet.destination_hash) {
            entry.timestamp = ctx.now;
        }
        // As in Transport.py, traffic on a relayed link uses the path to the
        // link's destination.
        if let Some(entry) = self
            .path_table
            .get_mut(&link_entry.destination_hash)
            .and_then(|ps| ps.primary_mut())
        {
            entry.used = ctx.now;
        }
    }

    /// Upstream's `protocol_violation("Undecodable path MTU signalling
    /// bytes")` on the interface a dropped link request came in on.
    fn undecodable_mtu_signalling(&self, iface: InterfaceId, actions: &mut Vec<TransportAction>) {
        if let Some(info) = self.interfaces.get(&iface) {
            log::debug!(
                "Protocol violation on {}: Undecodable path MTU signalling bytes",
                info.name
            );
        }
        actions.push(TransportAction::ProtocolViolation { interface: iface });
    }

    pub(super) fn handle_inbound_local_delivery(
        &self,
        ctx: &InboundPacketCtx,
        actions: &mut Vec<TransportAction>,
    ) {
        if (ctx.packet.flags.packet_type == constants::PACKET_TYPE_LINKREQUEST
            || ctx.packet.flags.packet_type == constants::PACKET_TYPE_DATA)
            // The engine's exclusive borrow makes this a direct, lock-free
            // destination lookup for data and link requests alike; delivery
            // reuses the same keyed registry.
            && self
                .local_destinations
                .contains_key(&ctx.packet.destination_hash)
        {
            // Link responders learn the post-ingress hop metric from the
            // authenticated LRRTT packet. Preserve that field when crossing
            // the action boundary without changing ordinary callback bytes.
            let delivery_raw = if ctx.packet.context == constants::CONTEXT_LRRTT
                && ctx.packet.raw.len() >= 2
            {
                let mut raw = ctx.packet.raw.to_vec();
                raw[1] = ctx.packet.hops;
                PacketBytes::from(raw)
            } else if ctx.packet.flags.packet_type == constants::PACKET_TYPE_LINKREQUEST
                && ctx.packet.data().len() == constants::LINK_ECPUBSIZE + constants::LINK_MTU_SIZE
            {
                let receiving = self.interfaces.get(&ctx.iface);
                let mut raw = ctx.packet.raw.to_vec();
                if let Err(mode) = crate::transport::inbound::clamp_local_link_request_mtu(
                    &mut raw,
                    true,
                    receiving.map(|info| info.mtu),
                    receiving.is_some_and(|info| info.mtu_upgradable),
                ) {
                    // Transport.py, as for a forwarded request, but logged
                    // as a warning.
                    log::warn!(
                        "Dropping link request packet to local destination. The contained exception was: Requested link mode {} not enabled",
                        crate::link::types::mode_description(mode)
                    );
                    self.undecodable_mtu_signalling(ctx.iface, actions);
                    return;
                }
                PacketBytes::from(raw)
            } else {
                // The received bytes themselves, shared.
                ctx.packet.raw.clone()
            };
            actions.push(TransportAction::DeliverLocal {
                destination_hash: ctx.packet.destination_hash,
                raw: delivery_raw,
                packet_hash: ctx.packet.packet_hash,
                receiving_interface: ctx.iface,
            });
        }
    }
}
