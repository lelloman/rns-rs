//! Packets the application sends.

use super::*;

impl Driver {
    /// The ratchet to encrypt a SINGLE packet for `dest_hash` with: the
    /// application's own for destinations it attached ratchets to, else the
    /// latest one the destination announced.
    pub(crate) fn single_ratchet_for(&self, dest_hash: &[u8; 16]) -> Option<[u8; 32]> {
        let local = crate::sync::lock_or_recover(self.event_tx.local_ratchets(), "local ratchets")
            .get(dest_hash)
            .and_then(|owner| owner.current_public());
        local.or_else(|| {
            let store = self.ratchet_store.as_ref()?;
            match store.current(dest_hash, time::now(), self.ratchet_expiry_secs) {
                Ok(entry) => entry.map(|entry| entry.ratchet),
                Err(err) => {
                    log::warn!(
                        "failed to load ratchet for {:02x}{:02x}{:02x}{:02x}..: {}",
                        dest_hash[0],
                        dest_hash[1],
                        dest_hash[2],
                        dest_hash[3],
                        err
                    );
                    None
                }
            }
        })
    }

    pub(crate) fn known_destination_route_hint(
        &self,
        dest_hash: &[u8; 16],
    ) -> Option<(InterfaceId, u8)> {
        let announced = &self.known.entries.get(dest_hash)?.announced;
        let iface = announced.receiving_interface;
        if iface.0 == 0 {
            return None;
        }

        self.interfaces
            .get(&iface)
            .filter(|entry| entry.online)
            .map(|_| (iface, announced.hops))
    }

    pub(crate) fn handle_send_outbound_event(
        &mut self,
        raw: Vec<u8>,
        dest_type: u8,
        attached_interface: Option<InterfaceId>,
    ) {
        if self.is_draining() {
            self.reject_new_work("send outbound packet");
            return;
        }
        match RawPacket::unpack(&raw) {
            Ok(packet) => {
                let is_announce =
                    packet.flags.packet_type == rns_core::constants::PACKET_TYPE_ANNOUNCE;
                if is_announce {
                    log::debug!(
                        "SendOutbound: ANNOUNCE for {:02x?} (len={}, dest_type={}, attached={:?})",
                        &packet.destination_hash[..4],
                        raw.len(),
                        dest_type,
                        attached_interface
                    );
                }
                if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_DATA {
                    log::debug!(
                        "SendOutbound: DATA dest={:02x}{:02x}{:02x}{:02x}.. header={} transport={:02x?} attached={:?}",
                        packet.destination_hash[0],
                        packet.destination_hash[1],
                        packet.destination_hash[2],
                        packet.destination_hash[3],
                        packet.flags.header_type,
                        packet.transport_id.as_ref().map(|id| &id[..4]),
                        attached_interface
                    );
                    self.proofs
                        .sent_packets
                        .insert(packet.packet_hash, (packet.destination_hash, time::now()));
                }
                let actions = self.engine.handle_outbound(
                    &packet,
                    dest_type,
                    attached_interface,
                    time::now(),
                );
                if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_DATA {
                    log::debug!(
                        "SendOutbound: DATA routed to {} actions: {:?}",
                        actions.len(),
                        actions
                            .iter()
                            .map(|a| match a {
                                TransportAction::SendOnInterface { interface, raw } =>
                                    format!("SendOn({};{}b)", interface.0, raw.len()),
                                TransportAction::BroadcastOnAllInterfaces { raw, .. } =>
                                    format!("BroadcastAll({}b)", raw.len()),
                                _ => "other".to_string(),
                            })
                            .collect::<Vec<_>>()
                    );
                }
                if is_announce {
                    log::debug!(
                        "SendOutbound: announce routed to {} actions: {:?}",
                        actions.len(),
                        actions
                            .iter()
                            .map(|a| match a {
                                TransportAction::SendOnInterface { interface, .. } =>
                                    format!("SendOn({})", interface.0),
                                TransportAction::BroadcastOnAllInterfaces { .. } =>
                                    "BroadcastAll".to_string(),
                                _ => "other".to_string(),
                            })
                            .collect::<Vec<_>>()
                    );
                }
                self.dispatch_all(actions);
            }
            Err(e) => {
                log::warn!("SendOutbound: failed to unpack packet: {:?}", e);
            }
        }
    }
}
