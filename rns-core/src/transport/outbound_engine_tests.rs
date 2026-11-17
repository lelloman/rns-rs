use super::super::engine_fixtures::{engine, interface, path_entry};
use crate::packet::PacketFlags;

use super::*;

fn packet(packet_type: u8, destination_type: u8, hops: u8, destination: [u8; 16]) -> RawPacket {
    RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type,
            packet_type,
        },
        hops,
        &destination,
        None,
        constants::CONTEXT_NONE,
        &[0x5A; 100],
    )
    .unwrap()
}

/// Transport.py:1663-1670: an outbound packet that goes by the path table
/// marks the path used; announces and plain or group packets do not, nor
/// does a link packet sent on its link's attached interface.
#[test]
fn only_packets_routed_by_path_mark_it_used() {
    let destination = [0xA1; 16];
    for (packet_type, destination_type, attached, marks) in [
        (
            constants::PACKET_TYPE_DATA,
            constants::DESTINATION_SINGLE,
            None,
            true,
        ),
        (
            constants::PACKET_TYPE_DATA,
            constants::DESTINATION_LINK,
            None,
            true,
        ),
        (
            constants::PACKET_TYPE_DATA,
            constants::DESTINATION_LINK,
            Some(InterfaceId(1)),
            false,
        ),
        (
            constants::PACKET_TYPE_ANNOUNCE,
            constants::DESTINATION_SINGLE,
            None,
            false,
        ),
        (
            constants::PACKET_TYPE_DATA,
            constants::DESTINATION_PLAIN,
            None,
            false,
        ),
        (
            constants::PACKET_TYPE_DATA,
            constants::DESTINATION_GROUP,
            None,
            false,
        ),
    ] {
        let mut engine = engine(true);
        engine.register_interface(interface(1, constants::MODE_FULL));
        engine.path_table.insert(
            destination,
            PathSet::from_single(
                path_entry(&destination, 900.0, 2, InterfaceId(1), [0x77; 16]),
                1,
            ),
        );
        let packet = packet(packet_type, destination_type, 0, destination);
        engine.handle_outbound(&packet, destination_type, attached, 1000.0);
        let used = engine.path_table[&destination].primary().unwrap().used;
        assert_eq!(
            used == 1000.0,
            marks,
            "type {packet_type}, destination type {destination_type}, attached {attached:?}"
        );
    }
}

fn sends(actions: &[TransportAction]) -> usize {
    actions
        .iter()
        .filter(|action| matches!(action, TransportAction::SendOnInterface { .. }))
        .count()
}

/// Only forwarded announces, with hops above zero, are held to the
/// interface's announce cap; local announces and other packets are not.
#[test]
fn only_forwarded_announces_are_gated_by_the_announce_cap() {
    for (packet_type, hops, second_sent) in [
        (constants::PACKET_TYPE_ANNOUNCE, 1, false),
        (constants::PACKET_TYPE_ANNOUNCE, 0, true),
        (constants::PACKET_TYPE_DATA, 1, true),
    ] {
        let mut engine = engine(true);
        let mut slow = interface(1, constants::MODE_FULL);
        slow.bitrate = Some(1_000);
        engine.register_interface(slow);
        engine.register_destination([0xB1; 16], constants::DESTINATION_SINGLE);
        engine.register_destination([0xB2; 16], constants::DESTINATION_SINGLE);
        for destination in [[0xB1; 16], [0xB2; 16]] {
            engine.path_table.insert(
                destination,
                PathSet::from_single(
                    path_entry(&destination, 900.0, 1, InterfaceId(1), [0x77; 16]),
                    1,
                ),
            );
        }
        let destination_type = constants::DESTINATION_SINGLE;
        let first = packet(packet_type, destination_type, hops, [0xB1; 16]);
        let second = packet(packet_type, destination_type, hops, [0xB2; 16]);
        let actions = engine.handle_outbound(&first, destination_type, None, 1000.0);
        assert_eq!(sends(&actions), 1, "type {packet_type} hops {hops}");
        let actions = engine.handle_outbound(&second, destination_type, None, 1000.0);
        assert_eq!(
            sends(&actions) == 1,
            second_sent,
            "type {packet_type} hops {hops}"
        );
    }
}
