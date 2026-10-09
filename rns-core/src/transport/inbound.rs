use alloc::sync::Arc;
use alloc::vec::Vec;

use super::tables::{LinkEntry, ReverseEntry};
use super::types::{InterfaceId, PacketBytes, TransportAction};
use crate::constants;
use crate::link::handshake::compute_link_id;
use crate::packet::RawPacket;

#[derive(Debug, Clone, Copy, Default)]
pub struct LocalHopRewrite {
    pub local_hops_delta: u8,
    pub from_local_client: bool,
    pub skip_local_hops_delta: bool,
}

impl LocalHopRewrite {
    fn hop_byte(self, packet: &RawPacket) -> u8 {
        if self.local_hops_delta != 0 && self.from_local_client && !self.skip_local_hops_delta {
            self.local_hops_delta
        } else {
            packet.hops
        }
    }
}

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
    if remaining_hops > 1 || (remaining_hops == 1 && next_hop != packet.destination_hash) {
        // Replace transport_id with next_hop, update hops. A one-hop path can
        // still point at a final transport node for destinations behind it.
        let mut new_raw = Vec::new();
        new_raw.push(packet.raw[0]); // flags unchanged
        new_raw.push(packet.hops); // updated hop count
        new_raw.extend_from_slice(&next_hop); // transport_id = next hop
                                              // Skip old transport_id (bytes 2..18), keep dest_hash + context + data
        new_raw.extend_from_slice(&packet.raw[(constants::TRUNCATED_HASHLENGTH / 8 + 2)..]);
        new_raw
    } else if remaining_hops == 1 {
        // Direct final hop: strip transport headers and deliver as H1.
        let new_flags = (constants::HEADER_1 << 6)
            | (constants::TRANSPORT_BROADCAST << 4)
            | (packet.raw[0] & 0x0F);
        let mut new_raw = Vec::new();
        new_raw.push(new_flags);
        new_raw.push(packet.hops);
        new_raw.extend_from_slice(&packet.raw[(constants::TRUNCATED_HASHLENGTH / 8 + 2)..]);
        new_raw
    } else {
        // remaining_hops == 0: final local delivery, strip transport header.
        let new_flags = (constants::HEADER_1 << 6)
            | (constants::TRANSPORT_BROADCAST << 4)
            | (packet.raw[0] & 0x0F);
        let mut new_raw = Vec::new();
        new_raw.push(new_flags);
        new_raw.push(packet.hops);
        new_raw.extend_from_slice(&packet.raw[(constants::TRUNCATED_HASHLENGTH / 8 + 2)..]);
        new_raw
    }
}

/// Clamp the link MTU signalled by a forwarded LINKREQUEST to the smaller of
/// the receiving and next-hop interface MTUs.
///
/// Transport.py (forwarding a LINKREQUEST): when the request carries MTU
/// signalling and either hop's hardware MTU is smaller than the signalled
/// path MTU, the signalled MTU is lowered so both endpoints negotiate a frame
/// size every hop can carry. A next-hop interface without a usable MTU strips
/// the signalling, disabling the upgrade. The three mode bits are preserved.
/// Link IDs exclude the signalling bytes, so rewriting them does not change
/// the link table key.
pub fn clamp_forwarded_link_request_mtu(
    new_raw: &mut Vec<u8>,
    signalled: bool,
    receiving_mtu: Option<u32>,
    next_hop_mtu: Option<u32>,
) {
    if !signalled || new_raw.len() < constants::LINK_MTU_SIZE {
        return;
    }
    let start = new_raw.len() - constants::LINK_MTU_SIZE;
    let Some(next_hop_mtu) = next_hop_mtu.filter(|mtu| *mtu > 0) else {
        new_raw.truncate(start);
        return;
    };
    let value = ((new_raw[start] as u32) << 16)
        | ((new_raw[start + 1] as u32) << 8)
        | (new_raw[start + 2] as u32);
    let path_mtu = value & constants::LINK_MTU_BYTEMASK;
    let mut limit = next_hop_mtu;
    if let Some(receiving_mtu) = receiving_mtu.filter(|mtu| *mtu > 0) {
        limit = limit.min(receiving_mtu);
    }
    if limit < path_mtu {
        let clamped =
            (value & !constants::LINK_MTU_BYTEMASK) | (limit & constants::LINK_MTU_BYTEMASK);
        new_raw[start] = (clamped >> 16) as u8;
        new_raw[start + 1] = (clamped >> 8) as u8;
        new_raw[start + 2] = clamped as u8;
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
    // Link ID must be computed the same way as in the link engine:
    // compute_link_id(hashable_part, extra) where extra = data_len - ECPUBSIZE
    // This ensures the transport's link table key matches the link_id in LRPROOF packets.
    let hashable = packet.get_hashable_part();
    let extra = if packet.data.len() > constants::LINK_ECPUBSIZE {
        packet.data.len() - constants::LINK_ECPUBSIZE
    } else {
        0
    };
    let link_id = compute_link_id(&hashable, extra);

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
    hop_rewrite: LocalHopRewrite,
) -> Option<TransportAction> {
    if receiving_interface == reverse_entry.outbound_interface {
        let mut new_raw = Vec::new();
        new_raw.push(packet.raw[0]);
        new_raw.push(hop_rewrite.hop_byte(packet));
        new_raw.extend_from_slice(&packet.raw[2..]);

        Some(TransportAction::SendOnInterface {
            interface: reverse_entry.receiving_interface,
            raw: new_raw.into(),
        })
    } else {
        None
    }
}

/// Route link traffic bidirectionally through the link table.
///
/// Transport.py:1514-1549.
fn link_table_outbound_interface(
    packet: &RawPacket,
    link_entry: &LinkEntry,
    receiving_interface: InterfaceId,
) -> Option<InterfaceId> {
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

    Some(outbound_interface)
}

pub fn route_via_link_table(
    packet: &RawPacket,
    link_entry: &LinkEntry,
    receiving_interface: InterfaceId,
    hop_rewrite: LocalHopRewrite,
) -> Option<(InterfaceId, Vec<u8>)> {
    let outbound_interface =
        link_table_outbound_interface(packet, link_entry, receiving_interface)?;
    let mut new_raw = Vec::new();
    new_raw.push(packet.raw[0]);
    new_raw.push(hop_rewrite.hop_byte(packet));
    new_raw.extend_from_slice(&packet.raw[2..]);

    Some((outbound_interface, new_raw))
}

/// Build the final shared forwarding buffer directly, avoiding a temporary Vec
/// and its subsequent conversion copy. The source packet remains unchanged.
pub(super) fn route_via_link_table_shared(
    packet: &RawPacket,
    link_entry: &LinkEntry,
    receiving_interface: InterfaceId,
    hop_rewrite: LocalHopRewrite,
) -> Option<(InterfaceId, PacketBytes)> {
    let outbound_interface =
        link_table_outbound_interface(packet, link_entry, receiving_interface)?;
    let mut raw: PacketBytes = packet.raw.as_slice().into();
    Arc::get_mut(&mut raw).expect("fresh forwarding buffer is uniquely owned")[1] =
        hop_rewrite.hop_byte(packet);
    Some((outbound_interface, raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_link_forwarding_matches_vec_bytes_and_keeps_packet_immutable() {
        for header_type in [constants::HEADER_1, constants::HEADER_2] {
            for payload_len in [0, 1, 128, 480, 8157] {
                let flags = PacketFlags {
                    header_type,
                    context_flag: constants::FLAG_UNSET,
                    transport_type: constants::TRANSPORT_BROADCAST,
                    destination_type: constants::DESTINATION_LINK,
                    packet_type: constants::PACKET_TYPE_DATA,
                };
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
                let payload = alloc::vec![0x7e; payload_len];
                for hops in [0, 3, 5, 255] {
                    let packet = RawPacket::pack_with_max_mtu(
                        flags,
                        hops,
                        &[0xAA; 16],
                        Some(&[0xBB; 16]),
                        constants::CONTEXT_RESOURCE,
                        &payload,
                        8192,
                    )
                    .unwrap();
                    let original = packet.raw.clone();
                    for same_interface in [false, true] {
                        let mut link = link.clone();
                        if same_interface {
                            link.received_interface = link.next_hop_interface;
                        }
                        for receiving in [InterfaceId(1), InterfaceId(2), InterfaceId(3)] {
                            for from_local_client in [false, true] {
                                for skip_local_hops_delta in [false, true] {
                                    let rewrite = LocalHopRewrite {
                                        local_hops_delta: 7,
                                        from_local_client,
                                        skip_local_hops_delta,
                                    };
                                    let old =
                                        route_via_link_table(&packet, &link, receiving, rewrite);
                                    let shared = route_via_link_table_shared(
                                        &packet, &link, receiving, rewrite,
                                    );
                                    assert_eq!(
                                        old.as_ref().map(|(i, b)| (*i, b.as_slice())),
                                        shared.as_ref().map(|(i, b)| (*i, b.as_ref()))
                                    );
                                    if let Some((_, bytes)) = shared {
                                        let clone = bytes.clone();
                                        assert!(Arc::ptr_eq(&bytes, &clone));
                                        drop(bytes);
                                        assert_eq!(clone.as_ref(), old.unwrap().1.as_slice());
                                    }
                                    assert_eq!(packet.raw, original);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    use crate::packet::PacketFlags;

    fn make_h2_packet(dest: &[u8; 16], transport_id: &[u8; 16], hops: u8) -> RawPacket {
        let flags = PacketFlags {
            header_type: constants::HEADER_2,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_TRANSPORT,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        RawPacket::pack(
            flags,
            hops,
            dest,
            Some(transport_id),
            constants::CONTEXT_NONE,
            b"payload",
        )
        .unwrap()
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

        let new_raw = forward_transport_packet(&packet, dest, 1, InterfaceId(1));

        // Should be HEADER_1 now
        let flags = crate::packet::PacketFlags::unpack(new_raw[0]);
        assert_eq!(flags.header_type, constants::HEADER_1);
        assert_eq!(flags.transport_type, constants::TRANSPORT_BROADCAST);
        // No transport_id in HEADER_1
        // dest_hash starts at byte 2
        assert_eq!(&new_raw[2..18], &dest);
    }

    #[test]
    fn test_forward_transport_one_hop_to_transport_keeps_header() {
        let dest = [0x11; 16];
        let transport_id = [0x22; 16];
        let next_transport = [0x33; 16];
        let packet = make_h2_packet(&dest, &transport_id, 3);

        let new_raw = forward_transport_packet(&packet, next_transport, 1, InterfaceId(1));

        let flags = crate::packet::PacketFlags::unpack(new_raw[0]);
        assert_eq!(flags.header_type, constants::HEADER_2);
        assert_eq!(flags.transport_type, constants::TRANSPORT_TRANSPORT);
        assert_eq!(&new_raw[2..18], &next_transport);
        assert_eq!(&new_raw[18..34], &dest);
    }

    #[test]
    fn forward_transport_packet_strips_header_for_final_local_hop() {
        let flags = PacketFlags {
            header_type: constants::HEADER_2,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_TRANSPORT,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let daemon_id = [0x42; 16];
        let dest_hash = [0x99; 16];
        let mut raw = Vec::new();
        raw.push(flags.pack());
        raw.push(0);
        raw.extend_from_slice(&daemon_id);
        raw.extend_from_slice(&dest_hash);
        raw.push(constants::CONTEXT_NONE);
        raw.extend_from_slice(b"hello");
        let packet = RawPacket::unpack(&raw).unwrap();

        let forwarded = forward_transport_packet(&packet, dest_hash, 0, InterfaceId(2));
        let forwarded_flags = PacketFlags::unpack(forwarded[0]);
        assert_eq!(forwarded_flags.header_type, constants::HEADER_1);
        assert_eq!(
            forwarded_flags.transport_type,
            constants::TRANSPORT_BROADCAST
        );
        assert_eq!(&forwarded[2..18], &dest_hash);
        assert_eq!(&forwarded[19..], b"hello");
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
        let packet = RawPacket::pack(
            flags,
            2,
            &[0xAA; 16],
            None,
            constants::CONTEXT_NONE,
            &[0xBB; 32],
        )
        .unwrap();

        let reverse = ReverseEntry {
            receiving_interface: InterfaceId(1),
            outbound_interface: InterfaceId(2),
            timestamp: 100.0,
        };

        let action = route_proof_via_reverse(
            &packet,
            &reverse,
            InterfaceId(2),
            LocalHopRewrite::default(),
        );
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
        let packet = RawPacket::pack(
            flags,
            2,
            &[0xAA; 16],
            None,
            constants::CONTEXT_NONE,
            &[0xBB; 32],
        )
        .unwrap();

        let reverse = ReverseEntry {
            receiving_interface: InterfaceId(1),
            outbound_interface: InterfaceId(2),
            timestamp: 100.0,
        };

        // Received on wrong interface (3 instead of 2)
        let action = route_proof_via_reverse(
            &packet,
            &reverse,
            InterfaceId(3),
            LocalHopRewrite::default(),
        );
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
        let packet = RawPacket::pack(
            flags,
            3,
            &[0xAA; 16],
            None,
            constants::CONTEXT_NONE,
            b"data",
        )
        .unwrap();

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
        let result =
            route_via_link_table(&packet, &link, InterfaceId(1), LocalHopRewrite::default());
        assert!(result.is_some());
        let (iface, _) = result.unwrap();
        assert_eq!(iface, InterfaceId(2));

        // Received on received_interface (2), should forward to next_hop_interface (1)
        let packet2 = RawPacket::pack(
            flags,
            5,
            &[0xAA; 16],
            None,
            constants::CONTEXT_NONE,
            b"data",
        )
        .unwrap();
        let result2 =
            route_via_link_table(&packet2, &link, InterfaceId(2), LocalHopRewrite::default());
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
        let packet = RawPacket::pack(
            flags,
            99,
            &[0xAA; 16],
            None,
            constants::CONTEXT_NONE,
            b"data",
        )
        .unwrap();

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

        let result =
            route_via_link_table(&packet, &link, InterfaceId(1), LocalHopRewrite::default());
        assert!(result.is_none());
    }
}

#[cfg(test)]
mod link_request_mtu_tests {
    use super::clamp_forwarded_link_request_mtu;
    use crate::link::handshake::build_signalling_bytes;
    use crate::link::types::LinkMode;

    fn request(mtu: u32, mode: LinkMode) -> Vec<u8> {
        let mut raw = vec![0xAA; 19 + 64];
        raw.extend_from_slice(&build_signalling_bytes(mtu, mode));
        raw
    }

    #[test]
    fn clamps_to_smaller_next_hop_and_preserves_mode() {
        let mut raw = request(524_288, LinkMode::Aes256Cbc);
        clamp_forwarded_link_request_mtu(&mut raw, true, Some(262_144), Some(16_384));
        assert_eq!(raw, request(16_384, LinkMode::Aes256Cbc));
    }

    #[test]
    fn clamps_to_smaller_receiving_interface() {
        let mut raw = request(524_288, LinkMode::Aes128Cbc);
        clamp_forwarded_link_request_mtu(&mut raw, true, Some(8_192), Some(65_535));
        assert_eq!(raw, request(8_192, LinkMode::Aes128Cbc));
    }

    #[test]
    fn leaves_fitting_signalling_untouched() {
        let mut raw = request(16_384, LinkMode::Aes256Cbc);
        clamp_forwarded_link_request_mtu(&mut raw, true, Some(65_535), Some(65_535));
        assert_eq!(raw, request(16_384, LinkMode::Aes256Cbc));
    }

    #[test]
    fn strips_signalling_without_next_hop_mtu() {
        let mut raw = request(16_384, LinkMode::Aes256Cbc);
        clamp_forwarded_link_request_mtu(&mut raw, true, Some(65_535), Some(0));
        assert_eq!(raw.len(), 19 + 64);
    }

    #[test]
    fn ignores_requests_without_signalling() {
        let mut raw = vec![0xAA; 19 + 64];
        clamp_forwarded_link_request_mtu(&mut raw, false, Some(500), Some(500));
        assert_eq!(raw, vec![0xAA; 19 + 64]);
    }
}
