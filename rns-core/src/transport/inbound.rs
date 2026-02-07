use alloc::vec::Vec;

use super::tables::{LinkEntry, ReverseEntry};
use super::types::{InterfaceId, TransportAction};
use crate::constants;
use crate::packet::RawPacket;

/// Forward a packet that is addressed to us as a transport node.
///
/// Transport.py:1427-1504: When we receive a HEADER_2 packet with our
/// transport_id, we forward it toward the destination using our path table.
pub fn forward_transport_packet(
    packet: &RawPacket,
    next_hop: [u8; 16],
    remaining_hops: u8,
    _outbound_interface: InterfaceId,
) -> Vec<u8> {
    if remaining_hops > 1 {
        // Replace transport_id with next_hop, update hops
        let mut new_raw = Vec::new();
        new_raw.push(packet.raw[0]); // flags unchanged
        new_raw.push(packet.hops); // updated hop count
        new_raw.extend_from_slice(&next_hop); // new transport_id
        // Skip old transport_id (bytes 2..18), keep dest_hash + context + data
        new_raw.extend_from_slice(&packet.raw[(constants::TRUNCATED_HASHLENGTH / 8 + 2)..]);
        new_raw
    } else if remaining_hops == 1 {
        // Strip transport headers: convert H2→H1
        let new_flags = (constants::HEADER_1 << 6)
            | (constants::TRANSPORT_BROADCAST << 4)
            | (packet.raw[0] & 0x0F);
        let mut new_raw = Vec::new();
        new_raw.push(new_flags);
        new_raw.push(packet.hops);
        // Skip transport_id, keep dest_hash + context + data
        new_raw.extend_from_slice(&packet.raw[(constants::TRUNCATED_HASHLENGTH / 8 + 2)..]);
        new_raw
    } else {
        // remaining_hops == 0: just update hop count
        let mut new_raw = Vec::new();
        new_raw.push(packet.raw[0]);
        new_raw.push(packet.hops);
        new_raw.extend_from_slice(&packet.raw[2..]);
        new_raw
    }
}

/// Create a link table entry for a forwarded LINKREQUEST.
pub fn create_link_entry(
    packet: &RawPacket,
    next_hop: [u8; 16],
    outbound_interface: InterfaceId,
    remaining_hops: u8,
    receiving_interface: InterfaceId,
    now: f64,
    proof_timeout: f64,
) -> ([u8; 16], LinkEntry) {
    // Link ID is derived from packet data (first 32 bytes of LINKREQUEST data
    // form the ephemeral public key; link_id = truncated_hash of public_key))
    // In Python: RNS.Link.link_id_from_lr_packet uses packet.data[:32+10]
    // For simplicity, we use the destination_hash as the link_id key since
    // link requests are targeted at a specific destination.
    // Actually in Python, link_id = SHA256(packet.data[:32+10])[:16]
    // But the link_table is keyed by this link_id. For us, we'll compute it.
    let link_id = crate::hash::truncated_hash(
        if packet.data.len() >= 42 {
            &packet.data[..42]
        } else {
            &packet.data
        },
    );

    let entry = LinkEntry {
        timestamp: now,
        next_hop_transport_id: next_hop,
        next_hop_interface: outbound_interface,
        remaining_hops,
        received_interface: receiving_interface,
        taken_hops: packet.hops,
        destination_hash: packet.destination_hash,
        validated: false,
        proof_timeout,
    };

    (link_id, entry)
}

/// Create a reverse table entry for proof routing.
pub fn create_reverse_entry(
    packet: &RawPacket,
    outbound_interface: InterfaceId,
    receiving_interface: InterfaceId,
    now: f64,
) -> ([u8; 16], ReverseEntry) {
    let truncated_hash = packet.get_truncated_hash();
    let entry = ReverseEntry {
        receiving_interface,
        outbound_interface,
        timestamp: now,
    };
    (truncated_hash, entry)
}

/// Route a proof packet via the reverse table.
///
/// Transport.py:2090-2100: Pop the reverse entry, check that the proof
/// arrived on the correct interface (outbound_interface), then forward
/// it to the receiving_interface.
pub fn route_proof_via_reverse(
    packet: &RawPacket,
    reverse_entry: &ReverseEntry,
    receiving_interface: InterfaceId,
) -> Option<TransportAction> {
    if receiving_interface == reverse_entry.outbound_interface {
        let mut new_raw = Vec::new();
        new_raw.push(packet.raw[0]);
        new_raw.push(packet.hops);
        new_raw.extend_from_slice(&packet.raw[2..]);

        Some(TransportAction::SendOnInterface {
            interface: reverse_entry.receiving_interface,
            raw: new_raw,
        })
    } else {
        None
    }
}

/// Route link traffic bidirectionally through the link table.
///
/// Transport.py:1514-1549.
pub fn route_via_link_table(
    packet: &RawPacket,
    link_entry: &LinkEntry,
    receiving_interface: InterfaceId,
) -> Option<(InterfaceId, Vec<u8>)> {
    let outbound_interface;

    if link_entry.next_hop_interface == link_entry.received_interface {
        // Same interface: check hop counts match
        if packet.hops == link_entry.remaining_hops || packet.hops == link_entry.taken_hops {
            outbound_interface = link_entry.next_hop_interface;
        } else {
            return None;
        }
    } else {
        // Different interfaces: forward to opposite side
        if receiving_interface == link_entry.next_hop_interface {
            if packet.hops == link_entry.remaining_hops {
                outbound_interface = link_entry.received_interface;
            } else {
                return None;
            }
        } else if receiving_interface == link_entry.received_interface {
            if packet.hops == link_entry.taken_hops {
                outbound_interface = link_entry.next_hop_interface;
            } else {
                return None;
            }
        } else {
            return None;
        }
    }

    let mut new_raw = Vec::new();
    new_raw.push(packet.raw[0]);
    new_raw.push(packet.hops);
    new_raw.extend_from_slice(&packet.raw[2..]);

    Some((outbound_interface, new_raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PacketFlags;

    fn make_h2_packet(dest: &[u8; 16], transport_id: &[u8; 16], hops: u8) -> RawPacket {
        let flags = PacketFlags {
            header_type: constants::HEADER_2,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_TRANSPORT,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        RawPacket::pack(flags, hops, dest, Some(transport_id), constants::CONTEXT_NONE, b"payload").unwrap()
    }

    #[test]
    fn test_forward_transport_multi_hop() {
        let dest = [0x11; 16];
        let transport_id = [0x22; 16];
        let next_hop = [0x33; 16];
        let packet = make_h2_packet(&dest, &transport_id, 2);

        let new_raw = forward_transport_packet(&packet, next_hop, 3, InterfaceId(1));

        // Should still be HEADER_2
        let flags = crate::packet::PacketFlags::unpack(new_raw[0]);
        assert_eq!(flags.header_type, constants::HEADER_2);
        // Hops should be updated
        assert_eq!(new_raw[1], 2);
        // New transport_id should be next_hop
        assert_eq!(&new_raw[2..18], &next_hop);
        // dest_hash preserved
        assert_eq!(&new_raw[18..34], &dest);
    }

    #[test]
    fn test_forward_transport_last_hop_strips_header() {
        let dest = [0x11; 16];
        let transport_id = [0x22; 16];
        let packet = make_h2_packet(&dest, &transport_id, 3);

        let new_raw = forward_transport_packet(&packet, [0; 16], 1, InterfaceId(1));

        // Should be HEADER_1 now
        let flags = crate::packet::PacketFlags::unpack(new_raw[0]);
        assert_eq!(flags.header_type, constants::HEADER_1);
        assert_eq!(flags.transport_type, constants::TRANSPORT_BROADCAST);
        // No transport_id in HEADER_1
        // dest_hash starts at byte 2
        assert_eq!(&new_raw[2..18], &dest);
    }

    #[test]
    fn test_route_proof_correct_interface() {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        let packet = RawPacket::pack(flags, 2, &[0xAA; 16], None, constants::CONTEXT_NONE, &[0xBB; 32]).unwrap();

        let reverse = ReverseEntry {
            receiving_interface: InterfaceId(1),
            outbound_interface: InterfaceId(2),
            timestamp: 100.0,
        };

        let action = route_proof_via_reverse(&packet, &reverse, InterfaceId(2));
        assert!(action.is_some());
        match action.unwrap() {
            TransportAction::SendOnInterface { interface, .. } => {
                assert_eq!(interface, InterfaceId(1));
            }
            _ => panic!("Expected SendOnInterface"),
        }
    }

    #[test]
    fn test_route_proof_wrong_interface() {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        let packet = RawPacket::pack(flags, 2, &[0xAA; 16], None, constants::CONTEXT_NONE, &[0xBB; 32]).unwrap();

        let reverse = ReverseEntry {
            receiving_interface: InterfaceId(1),
            outbound_interface: InterfaceId(2),
            timestamp: 100.0,
        };

        // Received on wrong interface (3 instead of 2)
        let action = route_proof_via_reverse(&packet, &reverse, InterfaceId(3));
        assert!(action.is_none());
    }

    #[test]
    fn test_route_via_link_table_different_interfaces() {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet = RawPacket::pack(flags, 3, &[0xAA; 16], None, constants::CONTEXT_NONE, b"data").unwrap();

        let link = LinkEntry {
            timestamp: 100.0,
            next_hop_transport_id: [0; 16],
            next_hop_interface: InterfaceId(1),
            remaining_hops: 3,
            received_interface: InterfaceId(2),
            taken_hops: 5,
            destination_hash: [0xAA; 16],
            validated: true,
            proof_timeout: 200.0,
        };

        // Received on next_hop_interface (1), should forward to received_interface (2)
        let result = route_via_link_table(&packet, &link, InterfaceId(1));
        assert!(result.is_some());
        let (iface, _) = result.unwrap();
        assert_eq!(iface, InterfaceId(2));

        // Received on received_interface (2), should forward to next_hop_interface (1)
        let packet2 = RawPacket::pack(flags, 5, &[0xAA; 16], None, constants::CONTEXT_NONE, b"data").unwrap();
        let result2 = route_via_link_table(&packet2, &link, InterfaceId(2));
        assert!(result2.is_some());
        let (iface2, _) = result2.unwrap();
        assert_eq!(iface2, InterfaceId(1));
    }

    #[test]
    fn test_route_via_link_table_wrong_hops() {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        // Wrong hop count
        let packet = RawPacket::pack(flags, 99, &[0xAA; 16], None, constants::CONTEXT_NONE, b"data").unwrap();

        let link = LinkEntry {
            timestamp: 100.0,
            next_hop_transport_id: [0; 16],
            next_hop_interface: InterfaceId(1),
            remaining_hops: 3,
            received_interface: InterfaceId(2),
            taken_hops: 5,
            destination_hash: [0xAA; 16],
            validated: true,
            proof_timeout: 200.0,
        };

        let result = route_via_link_table(&packet, &link, InterfaceId(1));
        assert!(result.is_none());
    }
}
