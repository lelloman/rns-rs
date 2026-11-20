//! Inbound proofs: for links and for packets we sent or forwarded.

use super::*;

impl TransportEngine {
    pub(super) fn process_inbound_proof(
        &mut self,
        ctx: &InboundPacketCtx,
        actions: &mut Vec<TransportAction>,
    ) {
        let packet = &ctx.packet;
        if packet.context == constants::CONTEXT_LRPROOF {
            // Link request proof routing. As in Transport.py, a shared
            // instance without transport also routes proofs for links to or
            // from its local clients (#183).
            let for_local_client_link = self
                .routes
                .links
                .get(&packet.destination_hash)
                .is_some_and(|entry| {
                    self.interface_is_local_client(entry.next_hop_interface)
                        || self.interface_is_local_client(entry.received_interface)
                });
            let verdict = self
                .routes
                .lrproof_verdict
                .take()
                .filter(|(link_id, _)| *link_id == packet.destination_hash)
                .map(|(_, valid)| valid);
            if (self.config.transport_enabled || ctx.from_local_client || for_local_client_link)
                && self.routes.links.contains_key(&packet.destination_hash)
            {
                let link_entry = self.routes.links.get(&packet.destination_hash).cloned();
                if verdict == Some(false) {
                    // Transport.py drops a transported proof whose signature
                    // does not verify, as a protocol violation.
                    log::debug!(
                        "Invalid link request proof in transport for link {:02x?}, dropping proof",
                        &packet.destination_hash[..4]
                    );
                    actions.push(TransportAction::ProtocolViolation {
                        interface: ctx.iface,
                    });
                    return;
                }
                if let Some(entry) = link_entry {
                    let instance_local_link = self
                        .interface_is_local_client(entry.next_hop_interface)
                        && self.interface_is_local_client(entry.received_interface);
                    if let Some((outbound_interface, new_raw)) = route_via_link_table(
                        packet,
                        &entry,
                        ctx.iface,
                        LocalHopRewrite {
                            local_hops_delta: self.config.local_hops_delta,
                            from_local_client: ctx.from_local_client,
                            skip_local_hops_delta: instance_local_link,
                        },
                    ) {
                        // The caller checked the signature when it could recall
                        // the destination's identity (`verdict`); a proof from
                        // the destination proves it alive.
                        if let Some(le) = self.routes.links.get_mut(&packet.destination_hash) {
                            le.validated = true;
                        }
                        if verdict == Some(true) {
                            self.mark_path_responsive(&entry.destination_hash, ctx.now);
                        }

                        actions.push(TransportAction::LinkEstablished {
                            link_id: packet.destination_hash,
                            interface: outbound_interface,
                        });

                        actions.push(TransportAction::SendOnInterface {
                            interface: outbound_interface,
                            raw: new_raw.into(),
                        });
                    } else if link_route_hops_match(packet.hops, &entry, ctx.iface) {
                        log::debug!(
                            "Link request proof received on wrong interface {}, not transporting it (expected {} or {})",
                            ctx.iface.0,
                            entry.next_hop_interface.0,
                            entry.received_interface.0,
                        );
                    } else {
                        log::debug!("{}", lrproof_hop_mismatch_diagnostic(packet.hops, &entry));
                    }
                }
            } else {
                // Could be for a local pending link - deliver locally
                let mut delivery_raw = packet.raw.to_vec();
                // LinkManager must see the same post-ingress hop metric that
                // was authenticated and considered by transport.
                if delivery_raw.len() >= 2 {
                    delivery_raw[1] = packet.hops;
                }
                actions.push(TransportAction::DeliverLocal {
                    destination_hash: packet.destination_hash,
                    raw: PacketBytes::from(delivery_raw),
                    packet_hash: packet.packet_hash,
                    receiving_interface: ctx.iface,
                });
            }
        } else {
            // Regular proof: check reverse table. As in Transport.py, a shared
            // instance without transport also routes proofs to or from its
            // local clients (#183).
            let proof_for_local_client = self
                .routes
                .reverse
                .get(&packet.destination_hash)
                .is_some_and(|entry| self.interface_is_local_client(entry.receiving_interface));
            if self.config.transport_enabled || ctx.from_local_client || proof_for_local_client {
                if let Some(reverse_entry) = self.routes.reverse.remove(&packet.destination_hash) {
                    if let Some(action) = route_proof_via_reverse(
                        packet,
                        &reverse_entry,
                        ctx.iface,
                        LocalHopRewrite {
                            local_hops_delta: self.config.local_hops_delta,
                            from_local_client: ctx.from_local_client,
                            skip_local_hops_delta: proof_for_local_client,
                        },
                    ) {
                        actions.push(action);
                    }
                }
            }

            // Deliver to local receipts
            actions.push(TransportAction::DeliverLocal {
                destination_hash: packet.destination_hash,
                raw: packet.raw.clone(),
                packet_hash: packet.packet_hash,
                receiving_interface: ctx.iface,
            });
        }
    }
}
