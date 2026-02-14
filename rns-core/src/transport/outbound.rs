use alloc::vec::Vec;

use super::types::{InterfaceId, InterfaceInfo, TransportAction};
use super::tables::PathEntry;
use crate::constants;
use crate::packet::RawPacket;

/// Route an outbound packet through the transport system.
///
/// Follows Transport.py:939-1179:
/// 1. If path known and hops > 1 → rewrite HEADER_1 to HEADER_2 with next_hop, send on path interface
/// 2. If path known and hops == 1 → send as-is on path interface
/// 3. No path → broadcast on all OUT interfaces (with mode filtering for announces)
pub fn route_outbound(
    path_table: &alloc::collections::BTreeMap<[u8; 16], PathEntry>,
    interfaces: &alloc::collections::BTreeMap<InterfaceId, InterfaceInfo>,
    local_destinations: &alloc::collections::BTreeMap<[u8; 16], u8>,
    packet: &RawPacket,
    dest_type: u8,
    attached_interface: Option<InterfaceId>,
    _now: f64,
) -> Vec<TransportAction> {
    let mut actions = Vec::new();

    // Don't route announces or PLAIN/GROUP via path table
    let use_path_table = packet.flags.packet_type != constants::PACKET_TYPE_ANNOUNCE
        && dest_type != constants::DESTINATION_PLAIN
        && dest_type != constants::DESTINATION_GROUP;

    if use_path_table {
        if let Some(path_entry) = path_table.get(&packet.destination_hash) {
            if path_entry.hops > 1 {
                if packet.flags.header_type == constants::HEADER_1 {
                    // Rewrite H1 → H2 with transport
                    let new_flags = (constants::HEADER_2 << 6)
                        | (constants::TRANSPORT_TRANSPORT << 4)
                        | (packet.raw[0] & 0x0F);

                    let mut new_raw = Vec::new();
                    new_raw.push(new_flags);
                    new_raw.push(packet.raw[1]); // hops
                    new_raw.extend_from_slice(&path_entry.next_hop); // transport_id = next hop
                    new_raw.extend_from_slice(&packet.raw[2..]); // dest_hash + context + data

                    actions.push(TransportAction::SendOnInterface {
                        interface: path_entry.receiving_interface,
                        raw: new_raw,
                    });
                }
                // If already HEADER_2, just forward (shouldn't normally happen for outbound)
            } else {
                // Direct: hops <= 1, send as-is on path interface
                actions.push(TransportAction::SendOnInterface {
                    interface: path_entry.receiving_interface,
                    raw: packet.raw.clone(),
                });
            }
            return actions;
        }
    }

    // No known path (or announce/plain/group): broadcast on all OUT interfaces
    // For LINK destinations, send on attached interface if specified,
    // otherwise broadcast (needed for LRPROOF and other link responses
    // where the responder doesn't know the originating interface).
    if dest_type == constants::DESTINATION_LINK {
        if let Some(iface) = attached_interface {
            actions.push(TransportAction::SendOnInterface {
                interface: iface,
                raw: packet.raw.clone(),
            });
            return actions;
        }
        // No attached interface — fall through to broadcast
    }

    // For announces, apply mode filtering
    if packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE {
        for (_, iface_info) in interfaces.iter() {
            if !iface_info.out_capable {
                continue;
            }

            if let Some(attached) = attached_interface {
                if iface_info.id != attached {
                    continue;
                }
            }

            let should_transmit = should_transmit_announce(
                iface_info,
                &packet.destination_hash,
                packet.hops,
                local_destinations,
                path_table,
                interfaces,
            );

            if should_transmit {
                actions.push(TransportAction::SendOnInterface {
                    interface: iface_info.id,
                    raw: packet.raw.clone(),
                });
            }
        }
    } else {
        // Regular broadcast
        // Python Transport.py:1037-1038: if attached_interface is set,
        // only send on that specific interface, not broadcast on all.
        if let Some(iface) = attached_interface {
            actions.push(TransportAction::SendOnInterface {
                interface: iface,
                raw: packet.raw.clone(),
            });
        } else {
            actions.push(TransportAction::BroadcastOnAllInterfaces {
                raw: packet.raw.clone(),
                exclude: None,
            });
        }
    }

    actions
}

/// Determine whether an announce should be transmitted on a given interface.
///
/// Applies mode-based filtering from Transport.py:1040-1165.
///
/// - ACCESS_POINT: never re-broadcast announces (AP is a sink)
/// - ROAMING: allow local announces; allow non-local unless source interface is ROAMING or BOUNDARY
/// - BOUNDARY: allow local announces; allow non-local unless source interface is ROAMING
/// - Others (FULL, PTP, GATEWAY): always allow
pub(crate) fn should_transmit_announce(
    iface: &InterfaceInfo,
    dest_hash: &[u8; 16],
    hops: u8,
    local_destinations: &alloc::collections::BTreeMap<[u8; 16], u8>,
    path_table: &alloc::collections::BTreeMap<[u8; 16], PathEntry>,
    interfaces: &alloc::collections::BTreeMap<InterfaceId, InterfaceInfo>,
) -> bool {
    let _ = hops;
    match iface.mode {
        constants::MODE_ACCESS_POINT => {
            // Block announce broadcast on AP mode interfaces
            false
        }
        constants::MODE_ROAMING => {
            // Allow if destination is local
            if local_destinations.contains_key(dest_hash) {
                return true;
            }
            // Non-local: allow unless source interface is ROAMING or BOUNDARY
            if let Some(path) = path_table.get(dest_hash) {
                if let Some(from_iface) = interfaces.get(&path.receiving_interface) {
                    if from_iface.mode == constants::MODE_ROAMING
                        || from_iface.mode == constants::MODE_BOUNDARY
                    {
                        return false;
                    }
                }
                return true;
            }
            // No path known — allow (might be our own announce)
            true
        }
        constants::MODE_BOUNDARY => {
            // Allow if destination is local
            if local_destinations.contains_key(dest_hash) {
                return true;
            }
            // Non-local: allow unless source interface is ROAMING
            if let Some(path) = path_table.get(dest_hash) {
                if let Some(from_iface) = interfaces.get(&path.receiving_interface) {
                    if from_iface.mode == constants::MODE_ROAMING {
                        return false;
                    }
                }
                return true;
            }
            // No path known — allow
            true
        }
        _ => {
            // FULL, POINT_TO_POINT, GATEWAY — always allow
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use crate::packet::PacketFlags;

    fn make_interface(id: u64, mode: u8) -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId(id),
            name: String::from("test"),
            mode,
            out_capable: true,
            in_capable: true,
            bitrate: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: constants::MTU as u32,
            ingress_control: false,
            ia_freq: 0.0,
            started: 0.0,
        }
    }

    fn make_path(hops: u8, iface: u64) -> PathEntry {
        PathEntry {
            timestamp: 1000.0,
            next_hop: [0xAA; 16],
            hops,
            expires: 9999.0,
            random_blobs: Vec::new(),
            receiving_interface: InterfaceId(iface),
            packet_hash: [0; 32],
            announce_raw: None,
        }
    }

    fn make_data_packet(dest_hash: &[u8; 16]) -> RawPacket {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        RawPacket::pack(flags, 0, dest_hash, None, constants::CONTEXT_NONE, b"hello").unwrap()
    }

    #[test]
    fn test_outbound_multi_hop_rewrite() {
        let dest = [0x11; 16];
        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path(3, 1));

        let interfaces = BTreeMap::new();
        let local_dests = BTreeMap::new();
        let packet = make_data_packet(&dest);

        let actions = route_outbound(
            &paths,
            &interfaces,
            &local_dests,
            &packet,
            constants::DESTINATION_SINGLE,
            None,
            1000.0,
        );

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::SendOnInterface { interface, raw } => {
                assert_eq!(*interface, InterfaceId(1));
                // Should be HEADER_2 now
                let flags = PacketFlags::unpack(raw[0]);
                assert_eq!(flags.header_type, constants::HEADER_2);
                assert_eq!(flags.transport_type, constants::TRANSPORT_TRANSPORT);
                // Transport ID should be next_hop
                assert_eq!(&raw[2..18], &[0xAA; 16]);
            }
            _ => panic!("Expected SendOnInterface"),
        }
    }

    #[test]
    fn test_outbound_direct_hop() {
        let dest = [0x22; 16];
        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path(1, 2));

        let interfaces = BTreeMap::new();
        let local_dests = BTreeMap::new();
        let packet = make_data_packet(&dest);

        let actions = route_outbound(
            &paths,
            &interfaces,
            &local_dests,
            &packet,
            constants::DESTINATION_SINGLE,
            None,
            1000.0,
        );

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::SendOnInterface { interface, raw } => {
                assert_eq!(*interface, InterfaceId(2));
                // Should remain HEADER_1
                let flags = PacketFlags::unpack(raw[0]);
                assert_eq!(flags.header_type, constants::HEADER_1);
            }
            _ => panic!("Expected SendOnInterface"),
        }
    }

    #[test]
    fn test_outbound_no_path_broadcast() {
        let dest = [0x33; 16];
        let paths = BTreeMap::new();
        let interfaces = BTreeMap::new();
        let local_dests = BTreeMap::new();
        let packet = make_data_packet(&dest);

        let actions = route_outbound(
            &paths,
            &interfaces,
            &local_dests,
            &packet,
            constants::DESTINATION_SINGLE,
            None,
            1000.0,
        );

        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], TransportAction::BroadcastOnAllInterfaces { .. }));
    }

    #[test]
    fn test_outbound_link_dest_uses_attached_interface() {
        let dest = [0x44; 16];
        let paths = BTreeMap::new();
        let interfaces = BTreeMap::new();
        let local_dests = BTreeMap::new();
        let packet = make_data_packet(&dest);

        let actions = route_outbound(
            &paths,
            &interfaces,
            &local_dests,
            &packet,
            constants::DESTINATION_LINK,
            Some(InterfaceId(5)),
            1000.0,
        );

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::SendOnInterface { interface, .. } => {
                assert_eq!(*interface, InterfaceId(5));
            }
            _ => panic!("Expected SendOnInterface"),
        }
    }

    #[test]
    fn test_outbound_announce_mode_filtering() {
        let dest = [0x55; 16];
        let paths = BTreeMap::new();
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_FULL));
        interfaces.insert(InterfaceId(2), make_interface(2, constants::MODE_ACCESS_POINT));

        let local_dests = BTreeMap::new();

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        };
        let packet = RawPacket::pack(flags, 1, &dest, None, constants::CONTEXT_NONE, &[0xAA; 64]).unwrap();

        let actions = route_outbound(
            &paths,
            &interfaces,
            &local_dests,
            &packet,
            constants::DESTINATION_SINGLE,
            None,
            1000.0,
        );

        // Only FULL interface should transmit, AP should be blocked
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::SendOnInterface { interface, .. } => {
                assert_eq!(*interface, InterfaceId(1));
            }
            _ => panic!("Expected SendOnInterface"),
        }
    }

    #[test]
    fn test_outbound_attached_interface_sends_only_on_that_interface() {
        let dest = [0x77; 16];
        let paths = BTreeMap::new();
        let interfaces = BTreeMap::new();
        let local_dests = BTreeMap::new();
        let packet = make_data_packet(&dest);

        let actions = route_outbound(
            &paths,
            &interfaces,
            &local_dests,
            &packet,
            constants::DESTINATION_SINGLE,
            Some(InterfaceId(5)),
            1000.0,
        );

        // With attached_interface, should send only on that interface (not broadcast)
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::SendOnInterface { interface, .. } => {
                assert_eq!(*interface, InterfaceId(5));
            }
            _ => panic!("Expected SendOnInterface for attached_interface, got broadcast"),
        }
    }

    #[test]
    fn test_outbound_plain_dest_not_routed() {
        let dest = [0x66; 16];
        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path(3, 1)); // path exists but shouldn't be used for PLAIN

        let interfaces = BTreeMap::new();
        let local_dests = BTreeMap::new();
        let packet = make_data_packet(&dest);

        let actions = route_outbound(
            &paths,
            &interfaces,
            &local_dests,
            &packet,
            constants::DESTINATION_PLAIN,
            None,
            1000.0,
        );

        // Should broadcast, not use path table
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], TransportAction::BroadcastOnAllInterfaces { .. }));
    }

    // =========================================================================
    // ROAMING/BOUNDARY mode announce filtering tests
    // =========================================================================

    #[test]
    fn test_roaming_allows_announce_from_full() {
        let dest = [0xA1; 16];
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_FULL));
        interfaces.insert(InterfaceId(2), make_interface(2, constants::MODE_ROAMING));

        // Path arrived via FULL interface (id=1)
        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path(2, 1));

        let local_dests = BTreeMap::new();
        let roaming_iface = &interfaces[&InterfaceId(2)];

        assert!(should_transmit_announce(
            roaming_iface,
            &dest,
            2,
            &local_dests,
            &paths,
            &interfaces,
        ));
    }

    #[test]
    fn test_roaming_blocks_announce_from_roaming() {
        let dest = [0xA2; 16];
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_ROAMING));
        interfaces.insert(InterfaceId(2), make_interface(2, constants::MODE_ROAMING));

        // Path arrived via ROAMING interface (id=1)
        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path(2, 1));

        let local_dests = BTreeMap::new();
        let roaming_iface = &interfaces[&InterfaceId(2)];

        assert!(!should_transmit_announce(
            roaming_iface,
            &dest,
            2,
            &local_dests,
            &paths,
            &interfaces,
        ));
    }

    #[test]
    fn test_roaming_blocks_announce_from_boundary() {
        let dest = [0xA3; 16];
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_BOUNDARY));
        interfaces.insert(InterfaceId(2), make_interface(2, constants::MODE_ROAMING));

        // Path arrived via BOUNDARY interface (id=1)
        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path(2, 1));

        let local_dests = BTreeMap::new();
        let roaming_iface = &interfaces[&InterfaceId(2)];

        assert!(!should_transmit_announce(
            roaming_iface,
            &dest,
            2,
            &local_dests,
            &paths,
            &interfaces,
        ));
    }

    #[test]
    fn test_boundary_allows_announce_from_full() {
        let dest = [0xA4; 16];
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_FULL));
        interfaces.insert(InterfaceId(2), make_interface(2, constants::MODE_BOUNDARY));

        // Path arrived via FULL interface (id=1)
        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path(2, 1));

        let local_dests = BTreeMap::new();
        let boundary_iface = &interfaces[&InterfaceId(2)];

        assert!(should_transmit_announce(
            boundary_iface,
            &dest,
            2,
            &local_dests,
            &paths,
            &interfaces,
        ));
    }

    #[test]
    fn test_boundary_allows_announce_from_boundary() {
        let dest = [0xA5; 16];
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_BOUNDARY));
        interfaces.insert(InterfaceId(2), make_interface(2, constants::MODE_BOUNDARY));

        // Path arrived via BOUNDARY interface (id=1)
        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path(2, 1));

        let local_dests = BTreeMap::new();
        let boundary_iface = &interfaces[&InterfaceId(2)];

        assert!(should_transmit_announce(
            boundary_iface,
            &dest,
            2,
            &local_dests,
            &paths,
            &interfaces,
        ));
    }

    #[test]
    fn test_boundary_blocks_announce_from_roaming() {
        let dest = [0xA6; 16];
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_ROAMING));
        interfaces.insert(InterfaceId(2), make_interface(2, constants::MODE_BOUNDARY));

        // Path arrived via ROAMING interface (id=1)
        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path(2, 1));

        let local_dests = BTreeMap::new();
        let boundary_iface = &interfaces[&InterfaceId(2)];

        assert!(!should_transmit_announce(
            boundary_iface,
            &dest,
            2,
            &local_dests,
            &paths,
            &interfaces,
        ));
    }
}
