use super::*;
use crate::packet::PacketFlags;
use crate::transport::tables::ReverseEntry;
use crate::transport::tests::{
    make_config, make_interface, make_local_client_interface, make_path_entry,
};

const OUR_ID: [u8; 16] = [0x42; 16];

fn flags(header_type: u8, destination_type: u8, packet_type: u8) -> PacketFlags {
    PacketFlags {
        header_type,
        context_flag: constants::FLAG_UNSET,
        transport_type: if header_type == constants::HEADER_2 {
            constants::TRANSPORT_TRANSPORT
        } else {
            constants::TRANSPORT_BROADCAST
        },
        destination_type,
        packet_type,
    }
}

fn packet(
    flags: PacketFlags,
    hops: u8,
    destination: &[u8; 16],
    transport_id: Option<&[u8; 16]>,
    context: u8,
) -> RawPacket {
    RawPacket::pack(flags, hops, destination, transport_id, context, b"payload").unwrap()
}

fn receive(engine: &mut TransportEngine, packet: &RawPacket, iface: u64) -> Vec<TransportAction> {
    let mut rng = rns_crypto::FixedRng::new(&[0x44; 32]);
    engine.handle_inbound(
        InboundFrame::new(&packet.raw, InterfaceId(iface), 1001.0),
        &mut rng,
    )
}

fn sent_on(actions: &[TransportAction], iface: u64) -> Option<&PacketBytes> {
    actions.iter().find_map(|action| match action {
        TransportAction::SendOnInterface { interface, raw } if *interface == InterfaceId(iface) => {
            Some(raw)
        }
        _ => None,
    })
}

#[test]
fn accepts_inbound_frame_applies_the_packet_filter() {
    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    let data = packet(
        flags(
            constants::HEADER_1,
            constants::DESTINATION_SINGLE,
            constants::PACKET_TYPE_DATA,
        ),
        0,
        &[0x51; 16],
        None,
        constants::CONTEXT_NONE,
    );
    let frame = InboundFrame::new(&data.raw, InterfaceId(1), 1000.0);
    assert!(engine.accepts_inbound_frame(frame));
    assert!(!engine.accepts_inbound_frame(InboundFrame::new(&[0x00], InterfaceId(1), 1000.0)));
    receive(&mut engine, &data, 1);
    assert!(
        !engine.accepts_inbound_frame(frame),
        "a duplicate is filtered"
    );
}

/// As upstream's Transport.inbound, a packet's hash is remembered for
/// deduplication unless it belongs to a link this node relays or is a
/// link request proof.
#[test]
fn inbound_packet_hashes_are_remembered_as_upstream() {
    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    let relayed_link = [0x4C; 16];
    engine.register_link(
        relayed_link,
        LinkEntry {
            timestamp: 1000.0,
            next_hop_transport_id: [0x33; 16],
            next_hop_interface: InterfaceId(2),
            remaining_hops: 1,
            received_interface: InterfaceId(1),
            taken_hops: 1,
            destination_hash: [0xD0; 16],
            validated: true,
            proof_timeout: 2000.0,
        },
    );
    let link_flags = |packet_type| {
        flags(
            constants::HEADER_1,
            constants::DESTINATION_LINK,
            packet_type,
        )
    };
    let single_flags = |packet_type| {
        flags(
            constants::HEADER_1,
            constants::DESTINATION_SINGLE,
            packet_type,
        )
    };
    let cases = [
        (
            packet(
                single_flags(constants::PACKET_TYPE_DATA),
                0,
                &[0x51; 16],
                None,
                0,
            ),
            true,
        ),
        (
            packet(
                single_flags(constants::PACKET_TYPE_PROOF),
                0,
                &[0x52; 16],
                None,
                0,
            ),
            true,
        ),
        (
            packet(
                link_flags(constants::PACKET_TYPE_PROOF),
                0,
                &[0x53; 16],
                None,
                constants::CONTEXT_LRPROOF,
            ),
            false,
        ),
        (
            packet(
                link_flags(constants::PACKET_TYPE_DATA),
                0,
                &relayed_link,
                None,
                0,
            ),
            false,
        ),
    ];
    for (n, (packet, remembered)) in cases.iter().enumerate() {
        receive(&mut engine, packet, 1);
        assert_eq!(
            engine.packet_hashlist.is_duplicate(&packet.packet_hash),
            *remembered,
            "case {n}"
        );
    }
}

/// Only plain broadcasts are bridged between a shared instance's local
/// clients and the network.
#[test]
fn only_plain_broadcasts_are_bridged_to_local_clients() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_local_client_interface(1));
    engine.register_interface(make_interface(2, constants::MODE_FULL));
    let bridged = |actions: &[TransportAction]| {
        actions
            .iter()
            .any(|action| matches!(action, TransportAction::ForwardPlainBroadcast { .. }))
    };
    for (destination_type, expected) in [
        (constants::DESTINATION_PLAIN, true),
        (constants::DESTINATION_SINGLE, false),
    ] {
        let broadcast = packet(
            flags(
                constants::HEADER_1,
                destination_type,
                constants::PACKET_TYPE_DATA,
            ),
            0,
            &[0x60 + destination_type; 16],
            None,
            constants::CONTEXT_NONE,
        );
        assert_eq!(bridged(&receive(&mut engine, &broadcast, 2)), expected);
    }
}

/// As upstream, an announce is never forwarded as transport traffic,
/// even when it carries this node's transport id.
#[test]
fn announce_addressed_to_this_transport_is_not_forwarded() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    engine.register_interface(make_interface(2, constants::MODE_FULL));
    let dest = [0xA7; 16];
    engine.upsert_path_destination(
        dest,
        make_path_entry(1000.0, 2, InterfaceId(2), [0x29; 16]),
        1000.0,
    );
    let announce = packet(
        flags(
            constants::HEADER_2,
            constants::DESTINATION_SINGLE,
            constants::PACKET_TYPE_ANNOUNCE,
        ),
        0,
        &dest,
        Some(&OUR_ID),
        constants::CONTEXT_NONE,
    );
    let actions = receive(&mut engine, &announce, 1);
    assert!(sent_on(&actions, 2).is_none());
    assert!(engine.reverse_table.is_empty());
}

/// The local hop delta masks only a local client's own zero-hop
/// packets as they leave for the network.
#[test]
fn local_hops_delta_masks_only_local_zero_hop_packets_leaving_the_instance() {
    let mut config = make_config(true);
    config.local_hops_delta = 5;
    let mut engine = TransportEngine::new(config);
    engine.register_interface(make_local_client_interface(1));
    engine.register_interface(make_interface(2, constants::MODE_FULL));
    engine.register_interface(make_local_client_interface(3));
    engine.register_interface(make_interface(4, constants::MODE_FULL));
    let to_network = [0xB1; 16];
    let to_local_client = [0xB3; 16];
    engine.upsert_path_destination(
        to_network,
        make_path_entry(1000.0, 2, InterfaceId(2), [0x29; 16]),
        1000.0,
    );
    engine.upsert_path_destination(
        to_local_client,
        make_path_entry(1000.0, 1, InterfaceId(3), to_local_client),
        1000.0,
    );
    let data = |hops: u8, destination: &[u8; 16], payload_tag: u8| {
        RawPacket::pack(
            flags(
                constants::HEADER_2,
                constants::DESTINATION_SINGLE,
                constants::PACKET_TYPE_DATA,
            ),
            hops,
            destination,
            Some(&OUR_ID),
            constants::CONTEXT_NONE,
            &[payload_tag; 8],
        )
        .unwrap()
    };
    // (packet, receiving interface, outbound interface, forwarded hops)
    let cases = [
        (data(0, &to_network, 1), 1, 2, 5),
        (data(0, &to_network, 2), 4, 2, 1),
        (data(0, &to_local_client, 3), 1, 3, 0),
        (data(1, &to_network, 4), 1, 2, 1),
    ];
    for (n, (packet, from, to, hops)) in cases.iter().enumerate() {
        let actions = receive(&mut engine, packet, *from);
        let raw = sent_on(&actions, *to).unwrap_or_else(|| panic!("case {n} forwarded"));
        assert_eq!(raw[1], *hops, "case {n}");
    }
}

fn relayed_link(next_hop_interface: u64, received_interface: u64) -> LinkEntry {
    LinkEntry {
        timestamp: 1000.0,
        next_hop_transport_id: [0x33; 16],
        next_hop_interface: InterfaceId(next_hop_interface),
        remaining_hops: 1,
        received_interface: InterfaceId(received_interface),
        taken_hops: 0,
        destination_hash: [0xD0; 16],
        validated: true,
        proof_timeout: 2000.0,
    }
}

/// Link traffic is relayed by a transport node or a shared instance,
/// which has a transport identity, but not by a plain client.
#[test]
fn link_traffic_is_relayed_only_by_nodes_with_a_transport_identity() {
    let link_id = [0x4C; 16];
    let link_data = packet(
        flags(
            constants::HEADER_1,
            constants::DESTINATION_LINK,
            constants::PACKET_TYPE_DATA,
        ),
        0,
        &link_id,
        None,
        constants::CONTEXT_NONE,
    );
    let mut shared = make_config(false);
    shared.identity_hash = Some(OUR_ID);
    for (config, relays) in [
        (make_config(true), true),
        (shared, true),
        (make_config(false), false),
    ] {
        let mut engine = TransportEngine::new(config);
        engine.register_interface(make_local_client_interface(1));
        engine.register_interface(make_interface(2, constants::MODE_FULL));
        engine.register_link(link_id, relayed_link(2, 1));
        let actions = receive(&mut engine, &link_data, 1);
        assert_eq!(sent_on(&actions, 2).is_some(), relays);
    }
}

/// As upstream, announces, link requests and link request proofs are
/// never relayed through the link table, even when addressed to a link
/// it holds.
#[test]
fn link_table_does_not_relay_announces_link_requests_or_their_proofs() {
    let link_id = [0x4C; 16];
    for (packet_type, context, sends) in [
        (constants::PACKET_TYPE_ANNOUNCE, constants::CONTEXT_NONE, 0),
        (
            constants::PACKET_TYPE_LINKREQUEST,
            constants::CONTEXT_NONE,
            0,
        ),
        // The proof is relayed once, as a proof.
        (constants::PACKET_TYPE_PROOF, constants::CONTEXT_LRPROOF, 1),
    ] {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        engine.register_interface(make_interface(2, constants::MODE_FULL));
        engine.register_link(link_id, relayed_link(2, 1));
        let packet = packet(
            flags(
                constants::HEADER_1,
                constants::DESTINATION_LINK,
                packet_type,
            ),
            0,
            &link_id,
            None,
            context,
        );
        let actions = receive(&mut engine, &packet, 2);
        let sent = actions
            .iter()
            .filter(|action| matches!(action, TransportAction::SendOnInterface { .. }))
            .count();
        assert_eq!(sent, sends, "packet type {packet_type}");
    }
}

/// Only a link request's MTU signalling is clamped on delivery; data of
/// the same length is delivered as received.
#[test]
fn local_delivery_clamps_only_link_request_signalling() {
    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    let dest = [0xE1; 16];
    engine.register_destination(dest, constants::DESTINATION_SINGLE);
    let mut payload = vec![0x5A; constants::LINK_ECPUBSIZE];
    payload.extend_from_slice(&[0x1F, 0xFF, 0xFF]);
    let data = RawPacket::pack(
        flags(
            constants::HEADER_1,
            constants::DESTINATION_SINGLE,
            constants::PACKET_TYPE_DATA,
        ),
        0,
        &dest,
        None,
        constants::CONTEXT_NONE,
        &payload,
    )
    .unwrap();
    let actions = receive(&mut engine, &data, 1);
    let delivered = actions
        .iter()
        .find_map(|action| match action {
            TransportAction::DeliverLocal { raw, .. } => Some(raw),
            _ => None,
        })
        .expect("delivered");
    assert_eq!(&delivered[2..], &data.raw[2..]);
}

fn announced(actions: &[TransportAction]) -> bool {
    actions
        .iter()
        .any(|action| matches!(action, TransportAction::AnnounceReceived(_)))
}

/// Ingress control holds an announce for an unknown destination during
/// a burst, a path response too, unless a path request for it is
/// waiting (upstream `Transport.inbound`); nothing outside a burst.
#[test]
fn ingress_control_holds_only_unrequested_announces_during_a_burst() {
    use super::local_client_announce_tests::announce_in_context;
    for (ia_freq, context, requested, held) in [
        (100.0, constants::CONTEXT_NONE, false, true),
        (100.0, constants::CONTEXT_PATH_RESPONSE, false, true),
        (100.0, constants::CONTEXT_PATH_RESPONSE, true, false),
        (100.0, constants::CONTEXT_NONE, true, false),
        (0.0, constants::CONTEXT_NONE, false, false),
    ] {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(InterfaceInfo {
            ingress_control: crate::transport::types::IngressControlConfig::enabled(),
            ia_freq,
            ..make_interface(1, constants::MODE_FULL)
        });
        let announce = announce_in_context(7, false, constants::HEADER_1, 0, context);
        if requested {
            engine.path_requests.insert(announce.destination_hash, 0.0);
        }
        let actions = receive(&mut engine, &announce, 1);
        assert_eq!(
            announced(&actions),
            !held,
            "freq {ia_freq} context {context} requested {requested}"
        );
        assert_eq!(
            engine.held_announce_count(&InterfaceId(1)),
            usize::from(held)
        );
    }
}

/// As upstream, announce rate limiting does not apply to path
/// responses: their rate is not even tracked.
#[test]
fn announce_rate_limit_spares_path_responses() {
    use super::local_client_announce_tests::announce_in_context;
    for (context, tracked) in [
        (constants::CONTEXT_NONE, true),
        (constants::CONTEXT_PATH_RESPONSE, false),
    ] {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(InterfaceInfo {
            announce_rate_target: Some(3600.0),
            ..make_interface(1, constants::MODE_FULL)
        });
        let announce = announce_in_context(8, false, constants::HEADER_1, 0, context);
        let actions = receive(&mut engine, &announce, 1);
        assert!(announced(&actions));
        assert_eq!(
            engine.rate_limiter_count(),
            usize::from(tracked),
            "context {context}"
        );
    }
}

/// As upstream, a path response that answers a pending request is
/// retransmitted only when it comes from a local client, and then as a
/// plain announce on every interface; one from the network is not
/// retransmitted.
#[test]
fn only_a_local_clients_path_response_answers_a_pending_request() {
    use super::local_client_announce_tests::announce_in_context;
    for (from, answered) in [(2, true), (1, false)] {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        engine.register_interface(make_local_client_interface(2));
        engine.register_interface(make_interface(3, constants::MODE_FULL));
        let response = announce_in_context(
            9,
            false,
            constants::HEADER_1,
            0,
            constants::CONTEXT_PATH_RESPONSE,
        );
        let dest = response.destination_hash;
        engine
            .pending_local_path_requests
            .insert(dest, (InterfaceId(3), 1000.0));
        let actions = receive(&mut engine, &response, from);
        assert!(announced(&actions));
        assert_eq!(
            engine
                .announce_table
                .get(&dest)
                .map(|entry| (entry.attached_interface, entry.block_rebroadcasts)),
            answered.then_some((None, false)),
            "from {from}"
        );
    }
}

/// Upstream 833f6cf2: an announce from a local client this instance
/// serves marks its path responsive, refreshing its timestamp, expiry and
/// use. One from the network, or heard by a shared instance client on its
/// connection to the instance, leaves the path state unknown and the path
/// unused.
#[test]
fn a_local_clients_announce_marks_its_path_responsive() {
    use super::local_client_announce_tests::announce_in_context;
    for (serves, from, responsive) in [(true, 2, true), (true, 1, false), (false, 2, false)] {
        let mut engine = TransportEngine::new(make_config(serves));
        engine.register_interface(make_interface(1, constants::MODE_FULL));
        engine.register_interface(make_local_client_interface(2));
        let announce =
            announce_in_context(10, false, constants::HEADER_1, 0, constants::CONTEXT_NONE);
        let dest = announce.destination_hash;
        receive(&mut engine, &announce, from);
        let path = engine.path_table.get(&dest).unwrap().primary().unwrap();
        let case = format!("serves {serves} from {from}");
        assert_eq!(
            engine.path_states.get(&dest).copied(),
            responsive.then_some(constants::STATE_RESPONSIVE),
            "{case}"
        );
        assert_eq!(path.used, if responsive { 1001.0 } else { 0.0 }, "{case}");
        assert_eq!(path.timestamp, 1001.0, "{case}");
        assert_eq!(path.expires, 1001.0 + constants::PATHFINDER_E, "{case}");
    }
}

fn table_entry(hops: u8, retries: u8, retransmit_timeout: f64) -> AnnounceEntry {
    AnnounceEntry {
        timestamp: 1000.0,
        retransmit_timeout,
        retries,
        received_from: [0xAA; 16],
        hops,
        packet_raw: Vec::new(),
        packet_data: Vec::new(),
        destination_hash: [0xAD; 16],
        context_flag: 0,
        local_rebroadcasts: 0,
        block_rebroadcasts: false,
        attached_interface: None,
        packet_hash: [0; 32],
        blocked_interfaces: Default::default(),
    }
}

fn rebroadcast(hops: u8) -> RawPacket {
    packet(
        flags(
            constants::HEADER_2,
            constants::DESTINATION_SINGLE,
            constants::PACKET_TYPE_ANNOUNCE,
        ),
        hops,
        &[0xAD; 16],
        Some(&[0x29; 16]),
        constants::CONTEXT_NONE,
    )
}

/// As upstream: hearing a neighbour rebroadcast an announce this node
/// is retransmitting, at the hops this node would, counts a local
/// rebroadcast, and after LOCAL_REBROADCASTS_MAX of them, once this
/// node has retried, it stops retransmitting.
#[test]
fn local_rebroadcasts_end_retransmission_after_a_retry() {
    let dest = [0xAD; 16];
    for (retries, removed_after) in [(1, Some(2)), (0, None)] {
        let mut engine = TransportEngine::new(make_config(true));
        engine
            .announce_table
            .insert(dest, table_entry(2, retries, 2000.0));
        for heard in 1..=3u8 {
            let from = engine.announce_received_from(&rebroadcast(3), 1500.0);
            assert_eq!(from, [0x29; 16]);
            let entry = engine.announce_table.get(&dest);
            if removed_after.is_some_and(|after| heard >= after) {
                assert!(entry.is_none(), "retries {retries} heard {heard}");
            } else {
                assert_eq!(entry.unwrap().local_rebroadcasts, heard);
            }
        }
    }

    // A rebroadcast at other hops is not a local one.
    let mut engine = TransportEngine::new(make_config(true));
    engine
        .announce_table
        .insert(dest, table_entry(2, 1, 2000.0));
    engine.announce_received_from(&rebroadcast(5), 1500.0);
    assert_eq!(engine.announce_table[&dest].local_rebroadcasts, 0);
}

/// As upstream: hearing the announce one hop further on, after this
/// node has retried it and before its next retry is due, means another
/// node passed it on, so it is not retransmitted again.
#[test]
fn announce_passed_on_by_another_node_ends_retransmission() {
    let dest = [0xAD; 16];
    for (retries, now, removed) in [(1, 1500.0, true), (0, 1500.0, false), (1, 2000.0, false)] {
        let mut engine = TransportEngine::new(make_config(true));
        engine
            .announce_table
            .insert(dest, table_entry(2, retries, 2000.0));
        engine.announce_received_from(&rebroadcast(4), now);
        assert_eq!(
            !engine.announce_table.contains_key(&dest),
            removed,
            "retries {retries} at {now}"
        );
    }

    // An announce without a transport id is received from its
    // destination and leaves the table alone.
    let mut engine = TransportEngine::new(make_config(true));
    engine
        .announce_table
        .insert(dest, table_entry(2, 1, 2000.0));
    let direct = packet(
        flags(
            constants::HEADER_1,
            constants::DESTINATION_SINGLE,
            constants::PACKET_TYPE_ANNOUNCE,
        ),
        3,
        &dest,
        None,
        constants::CONTEXT_NONE,
    );
    assert_eq!(engine.announce_received_from(&direct, 1500.0), dest);
    assert_eq!(engine.announce_table[&dest].local_rebroadcasts, 0);
}

/// A path response is never prefiltered, even when an ordinary
/// announce with the same emission time would be.
#[test]
fn prefilter_spares_path_responses() {
    use crate::transport::tests::make_random_blob;
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    let dest = [0xAE; 16];
    engine.upsert_path_destination(
        dest,
        PathEntry {
            random_blobs: vec![make_random_blob(200)],
            ..make_path_entry(1000.0, 1, InterfaceId(1), [0x29; 16])
        },
        1000.0,
    );
    let mut data = vec![0u8; constants::KEYSIZE / 8 + constants::NAME_HASH_LENGTH / 8];
    data.extend_from_slice(&make_random_blob(100));
    data.extend_from_slice(&[0u8; 64]);
    for (context, dropped) in [
        (constants::CONTEXT_NONE, true),
        (constants::CONTEXT_PATH_RESPONSE, false),
    ] {
        let announce = RawPacket::pack(
            flags(
                constants::HEADER_1,
                constants::DESTINATION_SINGLE,
                constants::PACKET_TYPE_ANNOUNCE,
            ),
            1,
            &dest,
            None,
            context,
            &data,
        )
        .unwrap();
        assert_eq!(
            engine.prefilter_announce(&announce, InterfaceId(1), 1000.0),
            dropped,
            "context {context}"
        );
    }

    // Nor is an announce for a destination a discovery path request
    // waits for, or one being retransmitted.
    let announce = RawPacket::pack(
        flags(
            constants::HEADER_1,
            constants::DESTINATION_SINGLE,
            constants::PACKET_TYPE_ANNOUNCE,
        ),
        1,
        &dest,
        None,
        constants::CONTEXT_NONE,
        &data,
    )
    .unwrap();
    engine.discovery_path_requests.insert(
        dest,
        DiscoveryPathRequest {
            timestamp: 1000.0,
            requesting_interfaces: Vec::new(),
            engaged: false,
        },
    );
    assert!(!engine.prefilter_announce(&announce, InterfaceId(1), 1000.0));
    engine.discovery_path_requests.remove(&dest);
    engine
        .announce_table
        .insert(dest, table_entry(1, 0, 2000.0));
    assert!(!engine.prefilter_announce(&announce, InterfaceId(1), 1000.0));
}

fn lrproof(link_id: &[u8; 16], hops: u8) -> RawPacket {
    packet(
        flags(
            constants::HEADER_1,
            constants::DESTINATION_LINK,
            constants::PACKET_TYPE_PROOF,
        ),
        hops,
        link_id,
        None,
        constants::CONTEXT_LRPROOF,
    )
}

/// As upstream, a shared instance without transport still relays a
/// link request proof for a link to or from one of its local clients.
#[test]
fn shared_instance_relays_link_proofs_for_its_local_clients() {
    let mut config = make_config(false);
    config.identity_hash = Some(OUR_ID);
    let mut engine = TransportEngine::new(config);
    engine.register_interface(make_local_client_interface(1));
    engine.register_interface(make_interface(2, constants::MODE_FULL));
    let link_id = [0x4D; 16];
    // The local client on 1 asked for a link to a destination over 2.
    engine.register_link(
        link_id,
        LinkEntry {
            validated: false,
            ..relayed_link(2, 1)
        },
    );
    let actions = receive(&mut engine, &lrproof(&link_id, 0), 2);
    assert!(sent_on(&actions, 1).is_some());
    assert!(!actions
        .iter()
        .any(|action| matches!(action, TransportAction::DeliverLocal { .. })));
}

/// A transport node delivers a link request proof for a link it holds
/// no relay entry for: one it requested itself.
#[test]
fn link_proof_without_relay_entry_is_delivered_locally() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    let actions = receive(&mut engine, &lrproof(&[0x4E; 16], 0), 1);
    assert!(actions
        .iter()
        .any(|action| matches!(action, TransportAction::DeliverLocal { .. })));
}

/// A link proof from a local client toward the network carries the
/// local hop delta; only a link between two local clients skips it.
#[test]
fn link_proof_from_local_client_to_network_carries_local_hops_delta() {
    let mut config = make_config(true);
    config.local_hops_delta = 5;
    let mut engine = TransportEngine::new(config);
    engine.register_interface(make_local_client_interface(1));
    engine.register_interface(make_interface(2, constants::MODE_FULL));
    let link_id = [0x4F; 16];
    // A network node on 2 asked for a link to the local client on 1.
    engine.register_link(
        link_id,
        LinkEntry {
            validated: false,
            remaining_hops: 0,
            taken_hops: 1,
            ..relayed_link(1, 2)
        },
    );
    let actions = receive(&mut engine, &lrproof(&link_id, 0), 1);
    let raw = sent_on(&actions, 2).expect("proof relayed");
    assert_eq!(raw[1], 5);
}

/// As upstream, a shared instance without transport routes a proof
/// back over its reverse table when the proven packet came from or goes
/// to one of its local clients.
#[test]
fn shared_instance_routes_proofs_for_its_local_clients() {
    let proof = packet(
        flags(
            constants::HEADER_1,
            constants::DESTINATION_SINGLE,
            constants::PACKET_TYPE_PROOF,
        ),
        0,
        &[0x50; 16],
        None,
        constants::CONTEXT_NONE,
    );
    // (reverse entry receiving, outbound, proof arrives on, relayed to)
    for (receiving, outbound, arrives, relayed) in [(1, 2, 2, 1), (2, 1, 1, 2)] {
        let mut config = make_config(false);
        config.identity_hash = Some(OUR_ID);
        let mut engine = TransportEngine::new(config);
        engine.register_interface(make_local_client_interface(1));
        engine.register_interface(make_interface(2, constants::MODE_FULL));
        engine.reverse_table.insert(
            [0x50; 16],
            ReverseEntry {
                receiving_interface: InterfaceId(receiving),
                outbound_interface: InterfaceId(outbound),
                timestamp: 1000.0,
            },
        );
        let actions = receive(&mut engine, &proof, arrives);
        assert!(sent_on(&actions, relayed).is_some(), "arrives on {arrives}");
    }
}

/// A LINKREQUEST with signalling for `mode` (any three-bit value) and
/// `mtu`, after a 64-byte key pair.
fn link_request_payload(mtu: u32, mode: u8) -> Vec<u8> {
    let mut payload = vec![0x5C; constants::LINK_ECPUBSIZE];
    let value = (mtu & constants::LINK_MTU_BYTEMASK) | ((mode as u32) << 21);
    payload.extend_from_slice(&value.to_be_bytes()[1..]);
    payload
}

fn protocol_violation_on(actions: &[TransportAction], iface: u64) -> bool {
    actions.iter().any(|action| {
        matches!(action, TransportAction::ProtocolViolation { interface } if *interface == InterfaceId(iface))
    })
}

/// Transport.py rebuilds the signalling of a forwarded LINKREQUEST whose
/// MTU it lowers with `Link.signalling_bytes`, which raises for a mode
/// outside `ENABLED_MODES`: the request is dropped as undecodable, with a
/// protocol violation on the receiving interface and no link table entry.
#[test]
fn forwarded_link_request_needing_a_clamp_in_a_mode_not_enabled_is_dropped() {
    for mode in 0u8..=7 {
        let mut engine = TransportEngine::new(make_config(true));
        engine.register_interface(InterfaceInfo {
            mtu: 262_144,
            mtu_upgradable: true,
            ..make_interface(1, constants::MODE_FULL)
        });
        engine.register_interface(InterfaceInfo {
            mtu: 8_192,
            mtu_upgradable: true,
            ..make_interface(2, constants::MODE_FULL)
        });
        let dest = [0xC4; 16];
        engine.upsert_path_destination(
            dest,
            make_path_entry(1000.0, 2, InterfaceId(2), [0x29; 16]),
            1000.0,
        );
        let request = RawPacket::pack(
            flags(
                constants::HEADER_2,
                constants::DESTINATION_SINGLE,
                constants::PACKET_TYPE_LINKREQUEST,
            ),
            0,
            &dest,
            Some(&OUR_ID),
            constants::CONTEXT_NONE,
            &link_request_payload(262_144, mode),
        )
        .unwrap();
        let actions = receive(&mut engine, &request, 1);
        if mode == 0x01 {
            assert!(sent_on(&actions, 2).is_some());
            assert_eq!(engine.link_table.len(), 1);
            assert!(!protocol_violation_on(&actions, 1));
        } else {
            assert!(sent_on(&actions, 2).is_none(), "mode {mode}");
            assert!(engine.link_table.is_empty(), "mode {mode}");
            assert!(protocol_violation_on(&actions, 1), "mode {mode}");
        }
    }
}

/// The same for a LINKREQUEST to a local destination: its MTU is lowered
/// to what the receiving interface carries, and for a mode that is not
/// enabled the request is dropped as undecodable instead of delivered.
/// Signalling that needs no clamp is delivered whatever its mode.
#[test]
fn local_link_request_needing_a_clamp_in_a_mode_not_enabled_is_dropped() {
    for mode in 0u8..=7 {
        for (mtu, clamped) in [(262_144, true), (500, false)] {
            let mut engine = TransportEngine::new(make_config(false));
            engine.register_interface(make_interface(1, constants::MODE_FULL));
            let dest = [0xC5; 16];
            engine.register_destination(dest, constants::DESTINATION_SINGLE);
            let request = RawPacket::pack(
                flags(
                    constants::HEADER_1,
                    constants::DESTINATION_SINGLE,
                    constants::PACKET_TYPE_LINKREQUEST,
                ),
                0,
                &dest,
                None,
                constants::CONTEXT_NONE,
                &link_request_payload(mtu, mode),
            )
            .unwrap();
            let actions = receive(&mut engine, &request, 1);
            let delivered = actions
                .iter()
                .any(|action| matches!(action, TransportAction::DeliverLocal { .. }));
            let dropped = clamped && mode != 0x01;
            assert_eq!(delivered, !dropped, "mode {mode} mtu {mtu}");
            assert_eq!(
                protocol_violation_on(&actions, 1),
                dropped,
                "mode {mode} mtu {mtu}"
            );
        }
    }
}
