use super::*;

impl TransportEngine {
    /// Route an outbound packet.
    pub fn handle_outbound(
        &mut self,
        packet: &RawPacket,
        dest_type: u8,
        attached_interface: Option<InterfaceId>,
        now: f64,
    ) -> Vec<TransportAction> {
        if packet.hops >= constants::PATHFINDER_M {
            return Vec::new();
        }

        let actions = route_outbound_with_options(
            &self.path_table,
            &self.interfaces,
            &self.local_destinations,
            packet,
            dest_type,
            attached_interface,
            OutboundRouteOptions {
                identity_hash: self.config.identity_hash,
                local_hops_delta: self.config.local_hops_delta,
            },
        );

        // Add to packet hashlist for outbound packets
        self.packet_hashlist.add(packet.packet_hash);

        // Gate announces with hops > 0 through the bandwidth queue
        if packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE && packet.hops > 0 {
            self.gate_announce_actions(actions, &packet.destination_hash, packet.hops, now)
        } else {
            actions
        }
    }

    /// Gate announce SendOnInterface actions through per-interface bandwidth queues.
    fn gate_announce_actions(
        &mut self,
        actions: Vec<TransportAction>,
        dest_hash: &[u8; 16],
        hops: u8,
        now: f64,
    ) -> Vec<TransportAction> {
        let mut result = Vec::new();
        for action in actions {
            match action {
                TransportAction::SendOnInterface { interface, raw } => {
                    let (bitrate, airtime_profile, announce_cap) =
                        if let Some(info) = self.interfaces.get(&interface) {
                            (info.bitrate, info.airtime_profile, info.announce_cap)
                        } else {
                            (None, None, constants::ANNOUNCE_CAP)
                        };
                    if let Some(send_action) = self.announce_queues.gate_announce(
                        interface,
                        raw,
                        *dest_hash,
                        hops,
                        now,
                        now,
                        bitrate,
                        airtime_profile,
                        announce_cap,
                    ) {
                        result.push(send_action);
                    }
                    // If None, it was queued — no action emitted now
                }
                other => result.push(other),
            }
        }
        result
    }
}
