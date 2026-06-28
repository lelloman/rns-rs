use alloc::vec::Vec;

use super::tables::PathSet;
use super::types::{InterfaceId, InterfaceInfo, PacketBytes, TransportAction};
use crate::constants;
use crate::packet::RawPacket;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct OutboundRouteOptions {
    pub identity_hash: Option<[u8; 16]>,
    pub local_hops_delta: u8,
}

/// Route an outbound packet through the transport system.
///
/// Follows Transport.py:939-1179:
/// 1. If path known and hops > 1 → rewrite HEADER_1 to HEADER_2 with next_hop, send on path interface
/// 2. If path known and hops == 1 but next hop is another transport → rewrite HEADER_1 to HEADER_2
/// 3. If path known and hops == 1 on a shared client → rewrite HEADER_1 to HEADER_2
/// 4. If path known and hops <= 1 otherwise → send as-is on path interface
/// 5. No path → broadcast on all OUT interfaces (with mode filtering for announces)
pub fn route_outbound(
    path_table: &alloc::collections::BTreeMap<[u8; 16], PathSet>,
    interfaces: &alloc::collections::BTreeMap<InterfaceId, InterfaceInfo>,
    local_destinations: &alloc::collections::BTreeMap<[u8; 16], u8>,
    packet: &RawPacket,
    dest_type: u8,
    attached_interface: Option<InterfaceId>,
    now: f64,
) -> Vec<TransportAction> {
    route_outbound_with_options(
        path_table,
        interfaces,
        local_destinations,
        packet,
        dest_type,
        attached_interface,
        now,
        OutboundRouteOptions::default(),
    )
}

pub(crate) fn route_outbound_with_options(
    path_table: &alloc::collections::BTreeMap<[u8; 16], PathSet>,
    interfaces: &alloc::collections::BTreeMap<InterfaceId, InterfaceInfo>,
    local_destinations: &alloc::collections::BTreeMap<[u8; 16], u8>,
    packet: &RawPacket,
    dest_type: u8,
    attached_interface: Option<InterfaceId>,
    _now: f64,
    options: OutboundRouteOptions,
) -> Vec<TransportAction> {
    let mut actions = Vec::new();
    let shared_raw: PacketBytes = packet.raw.clone().into();

    // Don't route announces or PLAIN/GROUP via path table
    let use_path_table = packet.flags.packet_type != constants::PACKET_TYPE_ANNOUNCE
        && dest_type != constants::DESTINATION_PLAIN
        && dest_type != constants::DESTINATION_GROUP;

    if use_path_table {
        if let Some(path_entry) = path_table
            .get(&packet.destination_hash)
            .and_then(|ps| ps.primary())
        {
            let outbound_info = interfaces.get(&path_entry.receiving_interface);
            let is_shared_client = outbound_info
                .map(|iface| iface.is_local_client)
                .unwrap_or(false);

            let one_hop_via_transport =
                path_entry.hops == 1 && path_entry.next_hop != packet.destination_hash;

            if path_entry.hops > 1
                || one_hop_via_transport
                || (path_entry.hops == 1 && is_shared_client)
            {
                if packet.flags.header_type == constants::HEADER_1 {
                    let hops = outbound_info
                        .and_then(|iface| local_hops_delta(packet, dest_type, iface, options))
                        .unwrap_or(packet.raw[1]);
                    actions.push(TransportAction::SendOnInterface {
                        interface: path_entry.receiving_interface,
                        raw: inject_transport_header_with_hops(packet, &path_entry.next_hop, hops)
                            .into(),
                    });
                }
                // If already HEADER_2, just forward (shouldn't normally happen for outbound)
            } else {
                // Direct: hops <= 1, send on path interface.
                let raw = outbound_info
                    .map(|iface| raw_for_interface(packet, dest_type, iface, options))
                    .unwrap_or_else(|| shared_raw.clone());
                actions.push(TransportAction::SendOnInterface {
                    interface: path_entry.receiving_interface,
                    raw,
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
            let raw = interfaces
                .get(&iface)
                .map(|iface_info| raw_for_interface(packet, dest_type, iface_info, options))
                .unwrap_or_else(|| shared_raw.clone());
            actions.push(TransportAction::SendOnInterface {
                interface: iface,
                raw,
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
                    raw: raw_for_interface(packet, dest_type, iface_info, options),
                });
            }
        }
    } else {
        // Regular broadcast
        // Python Transport.py:1037-1038: if attached_interface is set,
        // only send on that specific interface, not broadcast on all.
        if let Some(iface) = attached_interface {
            let raw = interfaces
                .get(&iface)
                .map(|iface_info| raw_for_interface(packet, dest_type, iface_info, options))
                .unwrap_or_else(|| shared_raw.clone());
            actions.push(TransportAction::SendOnInterface {
                interface: iface,
                raw,
            });
        } else {
            actions.push(TransportAction::BroadcastOnAllInterfaces {
                raw: shared_raw,
                exclude: None,
            });
        }
    }

    actions
}

fn inject_transport_header_with_hops(packet: &RawPacket, next_hop: &[u8; 16], hops: u8) -> Vec<u8> {
    let new_flags =
        (constants::HEADER_2 << 6) | (constants::TRANSPORT_TRANSPORT << 4) | (packet.raw[0] & 0x0F);

    let mut new_raw = Vec::new();
    new_raw.push(new_flags);
    new_raw.push(hops);
    new_raw.extend_from_slice(next_hop); // transport_id = next hop
    new_raw.extend_from_slice(&packet.raw[2..]); // dest_hash + context + data
    new_raw
}

fn mangle_hops(raw: &[u8], hops: u8) -> PacketBytes {
    let mut new_raw = raw.to_vec();
    if new_raw.len() > 1 {
        new_raw[1] = hops;
    }
    new_raw.into()
}

fn local_hops_delta(
    packet: &RawPacket,
    dest_type: u8,
    iface: &InterfaceInfo,
    options: OutboundRouteOptions,
) -> Option<u8> {
    if options.local_hops_delta == 0
        || packet.hops != 0
        || dest_type == constants::DESTINATION_PLAIN
        || dest_type == constants::DESTINATION_GROUP
        || iface.is_local_client
    {
        None
    } else {
        Some(options.local_hops_delta)
    }
}

fn raw_for_interface(
    packet: &RawPacket,
    dest_type: u8,
    iface: &InterfaceInfo,
    options: OutboundRouteOptions,
) -> PacketBytes {
    let Some(hops) = local_hops_delta(packet, dest_type, iface, options) else {
        return packet.raw.clone().into();
    };

    if packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE
        && packet.flags.header_type == constants::HEADER_1
    {
        if let Some(identity_hash) = options.identity_hash {
            return inject_transport_header_with_hops(packet, &identity_hash, hops).into();
        }
    }

    mangle_hops(&packet.raw, hops)
}

/// Determine whether an announce should be transmitted on a given interface.
///
/// Applies mode-based filtering from Transport.py:1040-1165.
///
/// - ACCESS_POINT: never re-broadcast announces (AP is a sink)
/// - ROAMING: allow local announces; allow non-local unless source interface is ROAMING or BOUNDARY
/// - BOUNDARY: allow local announces; allow non-local unless source interface is ROAMING
/// - INTERNAL: allow local announces; allow non-local unless source interface is BOUNDARY
/// - Others (FULL, PTP, GATEWAY): allow local and known-source announces
pub(crate) fn should_transmit_announce(
    iface: &InterfaceInfo,
    dest_hash: &[u8; 16],
    hops: u8,
    local_destinations: &alloc::collections::BTreeMap<[u8; 16], u8>,
    path_table: &alloc::collections::BTreeMap<[u8; 16], PathSet>,
    interfaces: &alloc::collections::BTreeMap<InterfaceId, InterfaceInfo>,
) -> bool {
    let _ = hops;
    let local_destination = local_destinations.contains_key(dest_hash);
    let from_interface = path_table
        .get(dest_hash)
        .and_then(|ps| ps.primary())
        .and_then(|path| interfaces.get(&path.receiving_interface));

    if !local_destination && from_interface.is_none() {
        return false;
    }

    if !local_destination
        && !iface.announces_from_internal
        && from_interface.is_some_and(|from_iface| from_iface.mode == constants::MODE_INTERNAL)
    {
        return false;
    }

    match iface.mode {
        constants::MODE_ACCESS_POINT => {
            // Block announce broadcast on AP mode interfaces
            false
        }
        constants::MODE_ROAMING => {
            if local_destination {
                return true;
            }
            !from_interface.is_some_and(|from_iface| {
                from_iface.mode == constants::MODE_ROAMING
                    || from_iface.mode == constants::MODE_BOUNDARY
            })
        }
        constants::MODE_BOUNDARY => {
            if local_destination {
                return true;
            }
            !from_interface.is_some_and(|from_iface| from_iface.mode == constants::MODE_ROAMING)
        }
        constants::MODE_INTERNAL => {
            if local_destination {
                return true;
            }
            !from_interface.is_some_and(|from_iface| from_iface.mode == constants::MODE_BOUNDARY)
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
    use crate::packet::PacketFlags;
    use alloc::collections::BTreeMap;

    fn make_interface(id: u64, mode: u8) -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId(id),
            name: String::from("test"),
            mode,
            recursive_prs: false,
            announces_from_internal: true,
            out_capable: true,
            in_capable: true,
            bitrate: None,
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: constants::MTU as u32,
            ingress_control: crate::transport::types::IngressControlConfig::disabled(),
            ia_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: 0.0,
        }
    }

    fn make_local_client_interface(id: u64, mode: u8) -> InterfaceInfo {
        let mut iface = make_interface(id, mode);
        iface.is_local_client = true;
        iface
    }

    use super::super::tables::PathEntry;

    fn make_path(hops: u8, iface: u64) -> PathSet {
        make_path_with_next_hop(hops, iface, [0xAA; 16])
    }

    fn make_path_with_next_hop(hops: u8, iface: u64, next_hop: [u8; 16]) -> PathSet {
        PathSet::from_single(
            PathEntry {
                timestamp: 1000.0,
                next_hop,
                hops,
                expires: 9999.0,
                random_blobs: Vec::new(),
                receiving_interface: InterfaceId(iface),
                packet_hash: [0; 32],
                announce_raw: None,
            },
            1,
        )
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

    fn make_packet_with_dest_type(dest_hash: &[u8; 16], dest_type: u8) -> RawPacket {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: dest_type,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        RawPacket::pack(flags, 0, dest_hash, None, constants::CONTEXT_NONE, b"hello").unwrap()
    }

    fn make_announce_packet(dest_hash: &[u8; 16], hops: u8) -> RawPacket {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        };
        RawPacket::pack(
            flags,
            hops,
            dest_hash,
            None,
            constants::CONTEXT_NONE,
            &[0xAA; 64],
        )
        .unwrap()
    }

    #[test]
    fn test_local_hops_delta_rewrites_direct_outbound_hop_byte() {
        let dest = [0xD1; 16];
        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path_with_next_hop(1, 2, dest));

        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(2), make_interface(2, constants::MODE_FULL));
        let local_dests = BTreeMap::new();
        let packet = make_data_packet(&dest);

        let actions = route_outbound_with_options(
            &paths,
            &interfaces,
            &local_dests,
            &packet,
            constants::DESTINATION_SINGLE,
            None,
            1000.0,
            OutboundRouteOptions {
                identity_hash: Some([0x42; 16]),
                local_hops_delta: 5,
            },
        );

        match &actions[..] {
            [TransportAction::SendOnInterface { interface, raw }] => {
                assert_eq!(*interface, InterfaceId(2));
                let flags = PacketFlags::unpack(raw[0]);
                assert_eq!(flags.header_type, constants::HEADER_1);
                assert_eq!(raw[1], 5);
            }
            other => panic!("expected one direct send, got {other:?}"),
        }
    }

    #[test]
    fn test_local_hops_delta_injects_transport_header_for_announce() {
        let dest = [0xD2; 16];
        let paths = BTreeMap::new();
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_FULL));
        let mut local_dests = BTreeMap::new();
        local_dests.insert(dest, constants::DESTINATION_SINGLE);
        let packet = make_announce_packet(&dest, 0);
        let identity_hash = [0x42; 16];

        let actions = route_outbound_with_options(
            &paths,
            &interfaces,
            &local_dests,
            &packet,
            constants::DESTINATION_SINGLE,
            None,
            1000.0,
            OutboundRouteOptions {
                identity_hash: Some(identity_hash),
                local_hops_delta: 4,
            },
        );

        match &actions[..] {
            [TransportAction::SendOnInterface { interface, raw }] => {
                assert_eq!(*interface, InterfaceId(1));
                let flags = PacketFlags::unpack(raw[0]);
                assert_eq!(flags.header_type, constants::HEADER_2);
                assert_eq!(flags.transport_type, constants::TRANSPORT_TRANSPORT);
                assert_eq!(raw[1], 4);
                assert_eq!(&raw[2..18], &identity_hash);
                assert_eq!(&raw[18..], &packet.raw[2..]);
            }
            other => panic!("expected one announce send, got {other:?}"),
        }
    }

    #[test]
    fn test_local_hops_delta_skips_plain_and_group_destinations() {
        for dest_type in [constants::DESTINATION_PLAIN, constants::DESTINATION_GROUP] {
            let dest = [dest_type; 16];
            let mut interfaces = BTreeMap::new();
            interfaces.insert(InterfaceId(9), make_interface(9, constants::MODE_FULL));
            let paths = BTreeMap::new();
            let local_dests = BTreeMap::new();
            let packet = make_packet_with_dest_type(&dest, dest_type);

            let actions = route_outbound_with_options(
                &paths,
                &interfaces,
                &local_dests,
                &packet,
                dest_type,
                Some(InterfaceId(9)),
                1000.0,
                OutboundRouteOptions {
                    identity_hash: Some([0x42; 16]),
                    local_hops_delta: 6,
                },
            );

            match &actions[..] {
                [TransportAction::SendOnInterface { raw, .. }] => assert_eq!(raw[1], 0),
                other => panic!("expected attached-interface send, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_local_hops_delta_skips_local_client_interface() {
        let dest = [0xD3; 16];
        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path_with_next_hop(1, 7, dest));
        let mut interfaces = BTreeMap::new();
        interfaces.insert(
            InterfaceId(7),
            make_local_client_interface(7, constants::MODE_FULL),
        );
        let local_dests = BTreeMap::new();
        let packet = make_data_packet(&dest);

        let actions = route_outbound_with_options(
            &paths,
            &interfaces,
            &local_dests,
            &packet,
            constants::DESTINATION_SINGLE,
            None,
            1000.0,
            OutboundRouteOptions {
                identity_hash: Some([0x42; 16]),
                local_hops_delta: 5,
            },
        );

        match &actions[..] {
            [TransportAction::SendOnInterface { raw, .. }] => assert_eq!(raw[1], 0),
            other => panic!("expected one local-client send, got {other:?}"),
        }
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
        paths.insert(dest, make_path_with_next_hop(1, 2, dest));

        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(2), make_interface(2, constants::MODE_FULL));
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
    fn test_outbound_one_hop_via_transport_injects_transport() {
        let dest = [0x24; 16];
        let next_hop = [0xAA; 16];
        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path_with_next_hop(1, 2, next_hop));

        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(2), make_interface(2, constants::MODE_FULL));
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
                let flags = PacketFlags::unpack(raw[0]);
                assert_eq!(flags.header_type, constants::HEADER_2);
                assert_eq!(flags.transport_type, constants::TRANSPORT_TRANSPORT);
                assert_eq!(&raw[2..18], &next_hop);
                assert_eq!(&raw[18..], &packet.raw[2..]);
            }
            _ => panic!("Expected SendOnInterface"),
        }
    }

    #[test]
    fn test_outbound_direct_hop_shared_client_injects_transport() {
        let dest = [0x23; 16];
        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path(1, 2));

        let mut interfaces = BTreeMap::new();
        interfaces.insert(
            InterfaceId(2),
            make_local_client_interface(2, constants::MODE_FULL),
        );
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
                let flags = PacketFlags::unpack(raw[0]);
                assert_eq!(flags.header_type, constants::HEADER_2);
                assert_eq!(flags.transport_type, constants::TRANSPORT_TRANSPORT);
                assert_eq!(raw[1], packet.raw[1]);
                assert_eq!(&raw[2..18], &[0xAA; 16]);
                assert_eq!(&raw[18..], &packet.raw[2..]);
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
        assert!(matches!(
            &actions[0],
            TransportAction::BroadcastOnAllInterfaces { .. }
        ));
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
        interfaces.insert(
            InterfaceId(2),
            make_interface(2, constants::MODE_ACCESS_POINT),
        );

        let mut local_dests = BTreeMap::new();
        local_dests.insert(dest, constants::DESTINATION_SINGLE);

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        };
        let packet =
            RawPacket::pack(flags, 1, &dest, None, constants::CONTEXT_NONE, &[0xAA; 64]).unwrap();

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
    fn test_outbound_announce_fanout_clones_for_each_allowed_interface() {
        let dest = [0x56; 16];
        let paths = BTreeMap::new();
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_FULL));
        interfaces.insert(InterfaceId(2), make_interface(2, constants::MODE_FULL));
        interfaces.insert(
            InterfaceId(3),
            make_interface(3, constants::MODE_ACCESS_POINT),
        );

        let mut local_dests = BTreeMap::new();
        local_dests.insert(dest, constants::DESTINATION_SINGLE);
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        };
        let packet =
            RawPacket::pack(flags, 1, &dest, None, constants::CONTEXT_NONE, &[0xAA; 64]).unwrap();

        let actions = route_outbound(
            &paths,
            &interfaces,
            &local_dests,
            &packet,
            constants::DESTINATION_SINGLE,
            None,
            1000.0,
        );

        assert_eq!(actions.len(), 2);
        for action in &actions {
            match action {
                TransportAction::SendOnInterface { interface, raw } => {
                    assert!(*interface == InterfaceId(1) || *interface == InterfaceId(2));
                    assert_eq!(&**raw, packet.raw.as_slice());
                }
                other => panic!("Expected SendOnInterface, got {:?}", other),
            }
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
        assert!(matches!(
            &actions[0],
            TransportAction::BroadcastOnAllInterfaces { .. }
        ));
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
    fn test_full_blocks_unknown_nonlocal_announce_without_source_path() {
        let dest = [0xA7; 16];
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_FULL));

        let paths = BTreeMap::new();
        let local_dests = BTreeMap::new();
        let full_iface = &interfaces[&InterfaceId(1)];

        assert!(!should_transmit_announce(
            full_iface,
            &dest,
            0,
            &local_dests,
            &paths,
            &interfaces,
        ));
    }

    #[test]
    fn test_full_allows_local_announce_without_source_path() {
        let dest = [0xA8; 16];
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_FULL));

        let paths = BTreeMap::new();
        let mut local_dests = BTreeMap::new();
        local_dests.insert(dest, constants::DESTINATION_SINGLE);
        let full_iface = &interfaces[&InterfaceId(1)];

        assert!(should_transmit_announce(
            full_iface,
            &dest,
            0,
            &local_dests,
            &paths,
            &interfaces,
        ));
    }

    #[test]
    fn test_announces_from_internal_filter_allows_local_destination() {
        let dest = [0xA9; 16];
        let mut interfaces = BTreeMap::new();
        let mut outbound = make_interface(1, constants::MODE_FULL);
        outbound.announces_from_internal = false;
        interfaces.insert(InterfaceId(1), outbound);

        let paths = BTreeMap::new();
        let mut local_dests = BTreeMap::new();
        local_dests.insert(dest, constants::DESTINATION_SINGLE);
        let full_iface = &interfaces[&InterfaceId(1)];

        assert!(should_transmit_announce(
            full_iface,
            &dest,
            0,
            &local_dests,
            &paths,
            &interfaces,
        ));
    }

    #[test]
    fn test_internal_allows_announce_from_full() {
        let dest = [0xB1; 16];
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_FULL));
        interfaces.insert(InterfaceId(2), make_interface(2, constants::MODE_INTERNAL));

        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path(2, 1));

        let local_dests = BTreeMap::new();
        let internal_iface = &interfaces[&InterfaceId(2)];

        assert!(should_transmit_announce(
            internal_iface,
            &dest,
            2,
            &local_dests,
            &paths,
            &interfaces,
        ));
    }

    #[test]
    fn test_internal_allows_announce_from_internal() {
        let dest = [0xB2; 16];
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_INTERNAL));
        interfaces.insert(InterfaceId(2), make_interface(2, constants::MODE_INTERNAL));

        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path(2, 1));

        let local_dests = BTreeMap::new();
        let internal_iface = &interfaces[&InterfaceId(2)];

        assert!(should_transmit_announce(
            internal_iface,
            &dest,
            2,
            &local_dests,
            &paths,
            &interfaces,
        ));
    }

    #[test]
    fn test_full_allows_announce_from_internal_by_default() {
        let dest = [0xB6; 16];
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_INTERNAL));
        interfaces.insert(InterfaceId(2), make_interface(2, constants::MODE_FULL));

        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path(2, 1));

        let local_dests = BTreeMap::new();
        let full_iface = &interfaces[&InterfaceId(2)];

        assert!(should_transmit_announce(
            full_iface,
            &dest,
            2,
            &local_dests,
            &paths,
            &interfaces,
        ));
    }

    #[test]
    fn test_full_blocks_announce_from_internal_when_disabled() {
        let dest = [0xB7; 16];
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_INTERNAL));
        let mut outbound = make_interface(2, constants::MODE_FULL);
        outbound.announces_from_internal = false;
        interfaces.insert(InterfaceId(2), outbound);

        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path(2, 1));

        let local_dests = BTreeMap::new();
        let full_iface = &interfaces[&InterfaceId(2)];

        assert!(!should_transmit_announce(
            full_iface,
            &dest,
            2,
            &local_dests,
            &paths,
            &interfaces,
        ));
    }

    #[test]
    fn test_gateway_blocks_announce_from_internal_when_disabled() {
        let dest = [0xB8; 16];
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_INTERNAL));
        let mut outbound = make_interface(2, constants::MODE_GATEWAY);
        outbound.announces_from_internal = false;
        interfaces.insert(InterfaceId(2), outbound);

        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path(2, 1));

        let local_dests = BTreeMap::new();
        let gateway_iface = &interfaces[&InterfaceId(2)];

        assert!(!should_transmit_announce(
            gateway_iface,
            &dest,
            2,
            &local_dests,
            &paths,
            &interfaces,
        ));
    }

    #[test]
    fn test_internal_blocks_announce_from_boundary() {
        let dest = [0xB3; 16];
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_BOUNDARY));
        interfaces.insert(InterfaceId(2), make_interface(2, constants::MODE_INTERNAL));

        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path(2, 1));

        let local_dests = BTreeMap::new();
        let internal_iface = &interfaces[&InterfaceId(2)];

        assert!(!should_transmit_announce(
            internal_iface,
            &dest,
            2,
            &local_dests,
            &paths,
            &interfaces,
        ));
    }

    #[test]
    fn test_internal_allows_announce_from_roaming() {
        let dest = [0xB4; 16];
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_ROAMING));
        interfaces.insert(InterfaceId(2), make_interface(2, constants::MODE_INTERNAL));

        let mut paths = BTreeMap::new();
        paths.insert(dest, make_path(2, 1));

        let local_dests = BTreeMap::new();
        let internal_iface = &interfaces[&InterfaceId(2)];

        assert!(should_transmit_announce(
            internal_iface,
            &dest,
            2,
            &local_dests,
            &paths,
            &interfaces,
        ));
    }

    #[test]
    fn test_boundary_allows_announce_from_internal() {
        let dest = [0xB5; 16];
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface(1, constants::MODE_INTERNAL));
        interfaces.insert(InterfaceId(2), make_interface(2, constants::MODE_BOUNDARY));

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
