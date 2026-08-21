use super::*;
use crate::packet::PacketFlags;

fn make_config(transport_enabled: bool) -> TransportConfig {
    TransportConfig {
        transport_enabled,
        identity_hash: if transport_enabled {
            Some([0x42; 16])
        } else {
            None
        },
        local_hops_delta: 0,
        prefer_shorter_path: false,
        max_paths_per_destination: 1,
        packet_hashlist_max_entries: constants::HASHLIST_MAXSIZE,
        packet_hashlist_allocation: crate::transport::types::PacketHashlistAllocation::Eager,
        max_discovery_pr_tags: constants::MAX_PR_TAGS,
        max_path_destinations: usize::MAX,
        max_tunnel_destinations_total: usize::MAX,
        destination_timeout_secs: constants::DESTINATION_TIMEOUT,
        announce_table_ttl_secs: constants::ANNOUNCE_TABLE_TTL,
        announce_table_max_bytes: constants::ANNOUNCE_TABLE_MAX_BYTES,
        announce_sig_cache_enabled: true,
        announce_sig_cache_max_entries: constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
        announce_sig_cache_ttl_secs: constants::ANNOUNCE_SIG_CACHE_TTL,
        announce_queue_max_entries: 256,
        announce_queue_max_interfaces: 1024,
    }
}

fn make_interface(id: u64, mode: u8) -> InterfaceInfo {
    InterfaceInfo {
        id: InterfaceId(id),
        name: String::from("test"),
        mode,
        gravity: 0,
        recursive_prs: false,
        announces_from_internal: true,
        announces_to_internal: None,
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

fn make_announce_entry(dest_hash: [u8; 16], timestamp: f64, fill_len: usize) -> AnnounceEntry {
    AnnounceEntry {
        timestamp,
        retransmit_timeout: timestamp,
        retries: 0,
        received_from: [0xAA; 16],
        hops: 2,
        packet_raw: vec![0x01; fill_len],
        packet_data: vec![0x02; fill_len],
        destination_hash: dest_hash,
        context_flag: 0,
        local_rebroadcasts: 0,
        block_rebroadcasts: false,
        attached_interface: None,
    }
}

fn make_path_entry(
    timestamp: f64,
    hops: u8,
    receiving_interface: InterfaceId,
    next_hop: [u8; 16],
) -> PathEntry {
    PathEntry {
        timestamp,
        next_hop,
        hops,
        expires: timestamp + 10_000.0,
        random_blobs: Vec::new(),
        receiving_interface,
        packet_hash: [0; 32],
        announce_raw: None,
    }
}

fn make_unique_tag(dest_hash: [u8; 16], tag: &[u8]) -> [u8; 32] {
    let mut unique_tag = [0u8; 32];
    let tag_len = tag.len().min(16);
    unique_tag[..16].copy_from_slice(&dest_hash);
    unique_tag[16..16 + tag_len].copy_from_slice(&tag[..tag_len]);
    unique_tag
}

fn make_random_blob(timebase: u64) -> [u8; 10] {
    let mut blob = [0u8; 10];
    let bytes = timebase.to_be_bytes();
    blob[5..10].copy_from_slice(&bytes[3..8]);
    blob
}

#[test]
fn test_empty_engine() {
    let engine = TransportEngine::new(make_config(false));
    assert!(!engine.has_path(&[0; 16]));
    assert!(engine.hops_to(&[0; 16]).is_none());
    assert!(engine.next_hop(&[0; 16]).is_none());
}

#[test]
fn test_register_deregister_interface() {
    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    assert!(engine.interfaces.contains_key(&InterfaceId(1)));

    engine.deregister_interface(InterfaceId(1));
    assert!(!engine.interfaces.contains_key(&InterfaceId(1)));
}

#[test]
fn test_deregister_interface_removes_announce_queue_state() {
    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_FULL));

    let _ = engine.announce_queues.gate_announce(
        InterfaceId(1),
        vec![0x01; 100].into(),
        [0xAA; 16],
        2,
        0.0,
        0.0,
        Some(1000),
        None,
        constants::ANNOUNCE_CAP,
    );
    let _ = engine.announce_queues.gate_announce(
        InterfaceId(1),
        vec![0x02; 100].into(),
        [0xBB; 16],
        3,
        0.0,
        0.0,
        Some(1000),
        None,
        constants::ANNOUNCE_CAP,
    );
    assert_eq!(engine.announce_queue_count(), 1);

    engine.deregister_interface(InterfaceId(1));
    assert_eq!(engine.announce_queue_count(), 0);
}

#[test]
fn test_deregister_interface_removes_transport_state() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let destination_hash = [0x11; 16];
    engine.inject_path(
        destination_hash,
        PathEntry {
            timestamp: 1000.0,
            next_hop: [0x22; 16],
            hops: 2,
            expires: 2000.0,
            random_blobs: Vec::new(),
            receiving_interface: InterfaceId(1),
            packet_hash: [0x33; 32],
            announce_raw: None,
        },
    );
    engine.reverse_table.insert(
        [0x44; 16],
        tables::ReverseEntry {
            receiving_interface: InterfaceId(2),
            outbound_interface: InterfaceId(1),
            timestamp: 1000.0,
        },
    );
    engine.register_link(
        [0x55; 16],
        LinkEntry {
            timestamp: 1000.0,
            next_hop_transport_id: [0x66; 16],
            next_hop_interface: InterfaceId(1),
            remaining_hops: 1,
            received_interface: InterfaceId(2),
            taken_hops: 1,
            destination_hash,
            validated: true,
            proof_timeout: 1100.0,
        },
    );

    assert_eq!(engine.path_table_count(), 1);
    assert_eq!(engine.reverse_table_count(), 1);
    assert_eq!(engine.link_table_count(), 1);

    engine.deregister_interface(InterfaceId(1));

    assert_eq!(engine.path_table_count(), 0);
    assert_eq!(engine.reverse_table_count(), 0);
    assert_eq!(engine.link_table_count(), 0);
}

#[test]
fn test_deregister_interface_preserves_other_announce_queues() {
    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let _ = engine.announce_queues.gate_announce(
        InterfaceId(1),
        vec![0x01; 100].into(),
        [0xAA; 16],
        2,
        0.0,
        0.0,
        Some(1000),
        None,
        constants::ANNOUNCE_CAP,
    );
    let _ = engine.announce_queues.gate_announce(
        InterfaceId(1),
        vec![0x02; 100].into(),
        [0xAB; 16],
        3,
        0.0,
        0.0,
        Some(1000),
        None,
        constants::ANNOUNCE_CAP,
    );
    let _ = engine.announce_queues.gate_announce(
        InterfaceId(2),
        vec![0x03; 100].into(),
        [0xBA; 16],
        2,
        0.0,
        0.0,
        Some(1000),
        None,
        constants::ANNOUNCE_CAP,
    );
    let _ = engine.announce_queues.gate_announce(
        InterfaceId(2),
        vec![0x04; 100].into(),
        [0xBB; 16],
        3,
        0.0,
        0.0,
        Some(1000),
        None,
        constants::ANNOUNCE_CAP,
    );

    engine.deregister_interface(InterfaceId(1));
    assert_eq!(engine.announce_queue_count(), 1);
    assert_eq!(engine.nonempty_announce_queue_count(), 1);
}

#[test]
fn test_register_deregister_destination() {
    let mut engine = TransportEngine::new(make_config(false));
    let dest = [0x11; 16];
    engine.register_destination(dest, constants::DESTINATION_SINGLE);
    assert!(engine.local_destinations.contains_key(&dest));

    engine.deregister_destination(&dest);
    assert!(!engine.local_destinations.contains_key(&dest));
}

#[test]
fn test_path_state() {
    let mut engine = TransportEngine::new(make_config(false));
    let dest = [0x22; 16];

    assert!(!engine.path_is_unresponsive(&dest));

    engine.mark_path_unresponsive(&dest, None);
    assert!(engine.path_is_unresponsive(&dest));

    engine.mark_path_responsive(&dest);
    assert!(!engine.path_is_unresponsive(&dest));
}

#[test]
fn test_announce_clears_stale_path_state_for_unknown_destination() {
    use crate::announce::AnnounceData;
    use crate::destination::{destination_hash, name_hash};

    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_FULL));

    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x61; 32]));
    let dest_hash = destination_hash("pathfix", &["announce"], Some(identity.hash()));
    let name_h = name_hash("pathfix", &["announce"]);
    let random_hash = [0x24u8; 10];

    let (announce_data, _) =
        AnnounceData::pack(&identity, &dest_hash, &name_h, &random_hash, None, None).unwrap();

    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        },
        0,
        &dest_hash,
        None,
        constants::CONTEXT_NONE,
        &announce_data,
    )
    .unwrap();

    engine.mark_path_unresponsive(&dest_hash, None);
    assert!(engine.path_is_unresponsive(&dest_hash));
    assert!(!engine.has_path(&dest_hash));

    let mut rng = rns_crypto::FixedRng::new(&[0x62; 32]);
    let actions = engine.handle_inbound(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(1),
            now: 1000.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
    );

    assert!(engine.has_path(&dest_hash));
    assert!(
        !engine.path_is_unresponsive(&dest_hash),
        "stale path state should be cleared for newly installed paths"
    );
    assert!(actions.iter().any(|action| matches!(
        action,
        TransportAction::PathUpdated {
            destination_hash,
            interface,
            ..
        } if *destination_hash == dest_hash && *interface == InterfaceId(1)
    )));
}

#[test]
fn test_duplicate_announce_from_second_interface_uses_existing_path() {
    use crate::announce::AnnounceData;
    use crate::destination::{destination_hash, name_hash};

    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x63; 32]));
    let dest_hash = destination_hash("dedup", &["announce"], Some(identity.hash()));
    let name_h = name_hash("dedup", &["announce"]);
    let random_hash = [0x25u8; 10];

    let (announce_data, _) =
        AnnounceData::pack(&identity, &dest_hash, &name_h, &random_hash, None, None).unwrap();
    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        },
        0,
        &dest_hash,
        None,
        constants::CONTEXT_NONE,
        &announce_data,
    )
    .unwrap();

    let mut rng = rns_crypto::FixedRng::new(&[0x64; 32]);
    let first_actions = engine.handle_inbound(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(1),
            now: 1000.0,
            rx: RxMetadata::default(),
        },
        &mut rng,
    );
    assert!(first_actions.iter().any(|action| matches!(
        action,
        TransportAction::PathUpdated {
            destination_hash,
            interface,
            ..
        } if *destination_hash == dest_hash && *interface == InterfaceId(1)
    )));

    let second_actions = engine.handle_inbound(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(2),
            now: 1000.1,
            rx: RxMetadata::default(),
        },
        &mut rng,
    );

    assert!(!second_actions.iter().any(|action| matches!(
        action,
        TransportAction::PathUpdated {
            destination_hash,
            interface,
            ..
        } if *destination_hash == dest_hash && *interface == InterfaceId(2)
    )));
    let path = engine
        .path_table
        .get(&dest_hash)
        .and_then(|set| set.primary())
        .expect("first announce should install a path");
    assert_eq!(path.receiving_interface, InterfaceId(1));

    let mut higher_gravity = make_interface(2, constants::MODE_FULL);
    higher_gravity.gravity = 1;
    engine.register_interface(higher_gravity);
    let third_actions = engine.handle_inbound(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(2),
            now: 1000.2,
            rx: RxMetadata::default(),
        },
        &mut rng,
    );

    assert!(third_actions.iter().any(|action| matches!(
        action,
        TransportAction::PathUpdated {
            destination_hash,
            interface,
            ..
        } if *destination_hash == dest_hash && *interface == InterfaceId(2)
    )));
    let path = engine
        .path_table
        .get(&dest_hash)
        .and_then(|set| set.primary())
        .expect("higher-gravity reception should become primary");
    assert_eq!(path.receiving_interface, InterfaceId(2));
}

#[test]
fn test_boundary_exempts_unresponsive() {
    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_BOUNDARY));
    let dest = [0xB1; 16];

    // Marking via a boundary interface should be skipped
    engine.mark_path_unresponsive(&dest, Some(InterfaceId(1)));
    assert!(!engine.path_is_unresponsive(&dest));
}

#[test]
fn test_non_boundary_marks_unresponsive() {
    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    let dest = [0xB2; 16];

    // Marking via a non-boundary interface should work
    engine.mark_path_unresponsive(&dest, Some(InterfaceId(1)));
    assert!(engine.path_is_unresponsive(&dest));
}

#[test]
fn test_expire_path() {
    let mut engine = TransportEngine::new(make_config(false));
    let dest = [0x33; 16];

    engine.path_table.insert(
        dest,
        PathSet::from_single(
            PathEntry {
                timestamp: 1000.0,
                next_hop: [0; 16],
                hops: 2,
                expires: 9999.0,
                random_blobs: Vec::new(),
                receiving_interface: InterfaceId(1),
                packet_hash: [0; 32],
                announce_raw: None,
            },
            1,
        ),
    );

    assert!(engine.has_path(&dest));
    engine.expire_path(&dest);
    // Path still exists but expires = 0
    assert!(engine.has_path(&dest));
    assert_eq!(engine.path_table[&dest].primary().unwrap().expires, 0.0);
}

#[test]
fn test_link_table_operations() {
    let mut engine = TransportEngine::new(make_config(false));
    let link_id = [0x44; 16];

    engine.register_link(
        link_id,
        LinkEntry {
            timestamp: 100.0,
            next_hop_transport_id: [0; 16],
            next_hop_interface: InterfaceId(1),
            remaining_hops: 3,
            received_interface: InterfaceId(2),
            taken_hops: 2,
            destination_hash: [0xAA; 16],
            validated: false,
            proof_timeout: 200.0,
        },
    );

    assert!(engine.link_table.contains_key(&link_id));
    assert!(!engine.link_table[&link_id].validated);

    engine.validate_link(&link_id);
    assert!(engine.link_table[&link_id].validated);

    engine.remove_link(&link_id);
    assert!(!engine.link_table.contains_key(&link_id));
}

#[test]
fn test_lrproof_routes_from_originating_side_via_link_table() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let link_id = [0x44; 16];
    engine.register_link(
        link_id,
        LinkEntry {
            timestamp: 100.0,
            next_hop_transport_id: [0xAA; 16],
            next_hop_interface: InterfaceId(2),
            remaining_hops: 3,
            received_interface: InterfaceId(1),
            taken_hops: 1,
            destination_hash: [0xBB; 16],
            validated: false,
            proof_timeout: 200.0,
        },
    );

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_LINK,
        packet_type: constants::PACKET_TYPE_PROOF,
    };
    let packet = RawPacket::pack(
        flags,
        0,
        &link_id,
        None,
        constants::CONTEXT_LRPROOF,
        &[0xCC; 64],
    )
    .unwrap();
    let mut rng = rns_crypto::FixedRng::new(&[0x33; 32]);

    let actions = engine.handle_inbound(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(1),
            now: 101.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
    );

    assert!(matches!(
        engine
            .link_table_ref()
            .get(&link_id)
            .map(|entry| entry.validated),
        Some(true)
    ));
    assert!(actions.iter().any(|action| matches!(
        action,
        TransportAction::LinkEstablished {
            link_id: established,
            interface: InterfaceId(2),
        } if *established == link_id
    )));
    assert!(actions.iter().any(|action| matches!(
        action,
        TransportAction::SendOnInterface {
            interface: InterfaceId(2),
            ..
        }
    )));
}

fn lrproof_rebalance_fixture() -> (TransportEngine, [u8; 16], [u8; 16], [u8; 32], Vec<u8>) {
    use rns_crypto::ed25519::Ed25519PrivateKey;

    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    engine.register_interface(make_interface(2, constants::MODE_FULL));
    let link_id = [0x44; 16];
    let destination_hash = [0xBB; 16];
    engine.register_link(
        link_id,
        LinkEntry {
            timestamp: 100.0,
            next_hop_transport_id: [0xAA; 16],
            next_hop_interface: InterfaceId(2),
            remaining_hops: 3,
            received_interface: InterfaceId(1),
            taken_hops: 1,
            destination_hash,
            validated: false,
            proof_timeout: 200.0,
        },
    );
    engine.inject_path(
        destination_hash,
        PathEntry {
            timestamp: 99.0,
            next_hop: [0xAA; 16],
            hops: 3,
            expires: 999.0,
            random_blobs: Vec::new(),
            receiving_interface: InterfaceId(2),
            packet_hash: [0xCC; 32],
            announce_raw: None,
        },
    );

    let mut key_rng = rns_crypto::FixedRng::new(&[0x51; 128]);
    let signing_key = Ed25519PrivateKey::generate(&mut key_rng);
    let signing_public = signing_key.public_key().public_bytes();
    let proof = crate::link::handshake::build_lrproof(
        &link_id,
        &[0x22; 32],
        &signing_public,
        &signing_key,
        None,
        crate::link::LinkMode::Aes256Cbc,
    );
    (engine, link_id, destination_hash, signing_public, proof)
}

#[test]
fn valid_lrproof_rebalances_relay_link_and_destination_path() {
    let (mut engine, link_id, destination_hash, signing_public, proof) =
        lrproof_rebalance_fixture();

    assert!(engine.rebalance_link_path_from_lrproof(
        &link_id,
        5,
        InterfaceId(2),
        &proof,
        &signing_public,
    ));

    assert_eq!(engine.link_table[&link_id].remaining_hops, 5);
    assert_eq!(engine.hops_to(&destination_hash), Some(5));

    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_PROOF,
        },
        4,
        &link_id,
        None,
        constants::CONTEXT_LRPROOF,
        &proof,
    )
    .unwrap();
    let mut inbound_rng = rns_crypto::FixedRng::new(&[0x61; 32]);
    let actions = engine.handle_inbound(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(2),
            now: 101.0,
            rx: RxMetadata::default(),
        },
        &mut inbound_rng,
    );
    assert!(engine.link_table[&link_id].validated);
    assert!(actions.iter().any(|action| matches!(
        action,
        TransportAction::SendOnInterface {
            interface: InterfaceId(1),
            ..
        }
    )));
}

#[test]
fn relay_rebalance_rejects_invalid_signature_wrong_interface_and_validated_link() {
    let (mut engine, link_id, destination_hash, signing_public, mut proof) =
        lrproof_rebalance_fixture();
    proof[0] ^= 0x01;
    assert!(!engine.rebalance_link_path_from_lrproof(
        &link_id,
        5,
        InterfaceId(2),
        &proof,
        &signing_public,
    ));
    assert_eq!(engine.link_table[&link_id].remaining_hops, 3);
    assert_eq!(engine.hops_to(&destination_hash), Some(3));

    let (_, _, _, _, valid_proof) = lrproof_rebalance_fixture();
    assert!(!engine.rebalance_link_path_from_lrproof(
        &link_id,
        5,
        InterfaceId(1),
        &valid_proof,
        &signing_public,
    ));
    engine.validate_link(&link_id);
    assert!(!engine.rebalance_link_path_from_lrproof(
        &link_id,
        5,
        InterfaceId(2),
        &valid_proof,
        &signing_public,
    ));
}

#[test]
fn relay_rebalance_candidate_rejects_proof_addressed_to_another_transport() {
    let (engine, link_id, _, _, proof) = lrproof_rebalance_fixture();
    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_2,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_TRANSPORT,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_PROOF,
        },
        4,
        &link_id,
        Some(&[0x43; 16]),
        constants::CONTEXT_LRPROOF,
        &proof,
    )
    .unwrap();

    assert!(engine
        .inbound_lrproof_rebalance_candidate(&packet.raw, InterfaceId(2))
        .is_none());
}

#[test]
fn lrproof_hop_mismatch_diagnostic_contains_complete_route_context() {
    let entry = LinkEntry {
        timestamp: 100.0,
        next_hop_transport_id: [0; 16],
        next_hop_interface: InterfaceId(17),
        remaining_hops: 3,
        received_interface: InterfaceId(29),
        taken_hops: 5,
        destination_hash: [0xAA; 16],
        validated: false,
        proof_timeout: 200.0,
    };

    assert_eq!(
        lrproof_hop_mismatch_diagnostic(9, &entry),
        "Received link request proof with hop mismatch (9/3:17->29), not transporting it"
    );
}

#[test]
fn lrproof_hop_mismatch_diagnostic_does_not_confuse_hops_with_interface_ids() {
    let entry = LinkEntry {
        timestamp: 100.0,
        next_hop_transport_id: [0; 16],
        next_hop_interface: InterfaceId(u64::MAX - 1),
        remaining_hops: u8::MAX,
        received_interface: InterfaceId(u64::MAX),
        taken_hops: 0,
        destination_hash: [0xAA; 16],
        validated: false,
        proof_timeout: 200.0,
    };

    assert_eq!(
        lrproof_hop_mismatch_diagnostic(0, &entry),
        alloc::format!(
            "Received link request proof with hop mismatch (0/255:{}->{}), not transporting it",
            u64::MAX - 1,
            u64::MAX
        )
    );
}

#[test]
fn test_packet_filter_drops_plain_announce() {
    let engine = TransportEngine::new(make_config(false));
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_PLAIN,
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
    };
    let packet =
        RawPacket::pack(flags, 0, &[0; 16], None, constants::CONTEXT_NONE, b"test").unwrap();
    assert!(!engine.packet_filter(&packet));
}

#[test]
fn test_packet_filter_allows_keepalive() {
    let engine = TransportEngine::new(make_config(false));
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet = RawPacket::pack(
        flags,
        0,
        &[0; 16],
        None,
        constants::CONTEXT_KEEPALIVE,
        b"test",
    )
    .unwrap();
    assert!(engine.packet_filter(&packet));
}

#[test]
fn test_packet_filter_drops_high_hop_plain() {
    let engine = TransportEngine::new(make_config(false));
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_PLAIN,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let mut packet =
        RawPacket::pack(flags, 0, &[0; 16], None, constants::CONTEXT_NONE, b"test").unwrap();
    packet.hops = 2;
    assert!(!engine.packet_filter(&packet));
}

#[test]
fn test_packet_filter_allows_duplicate_single_announce() {
    let mut engine = TransportEngine::new(make_config(false));
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
    };
    let packet = RawPacket::pack(
        flags,
        0,
        &[0; 16],
        None,
        constants::CONTEXT_NONE,
        &[0xAA; 64],
    )
    .unwrap();

    // Add to hashlist
    engine.packet_hashlist.add(packet.packet_hash);

    // Should still pass filter (duplicate announce for SINGLE allowed)
    assert!(engine.packet_filter(&packet));
}

#[test]
fn test_packet_filter_fifo_eviction_allows_oldest_hash_again() {
    let mut engine = TransportEngine::new(make_config(false));
    engine.packet_hashlist = PacketHashlist::new(2);

    let make_packet = |seed: u8| {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        RawPacket::pack(
            flags,
            0,
            &[seed; 16],
            None,
            constants::CONTEXT_NONE,
            &[seed; 4],
        )
        .unwrap()
    };

    let packet1 = make_packet(1);
    let packet2 = make_packet(2);
    let packet3 = make_packet(3);

    engine.packet_hashlist.add(packet1.packet_hash);
    engine.packet_hashlist.add(packet2.packet_hash);
    assert!(!engine.packet_filter(&packet1));

    engine.packet_hashlist.add(packet3.packet_hash);

    assert!(engine.packet_filter(&packet1));
    assert!(!engine.packet_filter(&packet2));
    assert!(!engine.packet_filter(&packet3));
}

#[test]
fn test_packet_filter_duplicate_does_not_refresh_recency() {
    let mut engine = TransportEngine::new(make_config(false));
    engine.packet_hashlist = PacketHashlist::new(2);

    let make_packet = |seed: u8| {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        RawPacket::pack(
            flags,
            0,
            &[seed; 16],
            None,
            constants::CONTEXT_NONE,
            &[seed; 4],
        )
        .unwrap()
    };

    let packet1 = make_packet(1);
    let packet2 = make_packet(2);
    let packet3 = make_packet(3);

    engine.packet_hashlist.add(packet1.packet_hash);
    engine.packet_hashlist.add(packet2.packet_hash);
    engine.packet_hashlist.add(packet2.packet_hash);
    engine.packet_hashlist.add(packet3.packet_hash);

    assert!(engine.packet_filter(&packet1));
    assert!(!engine.packet_filter(&packet2));
    assert!(!engine.packet_filter(&packet3));
}

#[test]
fn test_tick_retransmits_announce() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_FULL));

    let dest = [0x55; 16];
    engine.register_destination(dest, constants::DESTINATION_SINGLE);
    engine.insert_announce_entry(
        dest,
        AnnounceEntry {
            timestamp: 190.0,
            retransmit_timeout: 100.0, // ready to retransmit
            retries: 0,
            received_from: [0xAA; 16],
            hops: 2,
            packet_raw: vec![0x01, 0x02],
            packet_data: vec![0xCC; 10],
            destination_hash: dest,
            context_flag: 0,
            local_rebroadcasts: 0,
            block_rebroadcasts: false,
            attached_interface: None,
        },
        190.0,
    );

    let mut rng = rns_crypto::FixedRng::new(&[0x42; 32]);
    let actions = engine.tick(200.0, &mut rng);

    // Should have a send action for the retransmit (gated through announce queue,
    // expanded from BroadcastOnAllInterfaces to per-interface SendOnInterface)
    assert!(!actions.is_empty());
    assert!(matches!(
        &actions[0],
        TransportAction::SendOnInterface { .. }
    ));

    // Retries should have increased
    assert_eq!(engine.announce_table[&dest].retries, 1);
}

#[test]
fn test_gate_retransmit_actions_expands_broadcast_to_matching_interfaces() {
    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    engine.register_interface(make_interface(2, constants::MODE_FULL));
    engine.register_interface(make_interface(3, constants::MODE_ACCESS_POINT));

    let dest = [0x56; 16];
    engine.register_destination(dest, constants::DESTINATION_SINGLE);
    let raw = make_announce_raw(&dest, &[0xAB; 32]);
    let actions = engine.gate_retransmit_actions(
        vec![TransportAction::BroadcastOnAllInterfaces {
            raw: raw.clone().into(),
            exclude: None,
        }],
        1000.0,
    );

    assert_eq!(actions.len(), 2);
    for action in &actions {
        match action {
            TransportAction::SendOnInterface {
                interface,
                raw: sent,
            } => {
                assert!(*interface == InterfaceId(1) || *interface == InterfaceId(2));
                assert_eq!(&**sent, raw.as_slice());
            }
            other => panic!("expected SendOnInterface, got {:?}", other),
        }
    }
}

#[test]
fn test_tick_culls_expired_announce_entries() {
    let mut config = make_config(true);
    config.announce_table_ttl_secs = 10.0;
    let mut engine = TransportEngine::new(config);

    let dest1 = [0x61; 16];
    let dest2 = [0x62; 16];
    assert!(engine.insert_announce_entry(dest1, make_announce_entry(dest1, 100.0, 8), 100.0));
    assert!(engine.insert_held_announce(dest2, make_announce_entry(dest2, 100.0, 8), 100.0));

    let mut rng = rns_crypto::FixedRng::new(&[0x11; 32]);
    let _ = engine.tick(111.0, &mut rng);

    assert!(!engine.announce_table().contains_key(&dest1));
    assert!(!engine.held_announces().contains_key(&dest2));
}

#[test]
fn test_announce_retention_cap_evicts_oldest_and_prefers_held_on_tie() {
    let sample_entry = make_announce_entry([0x70; 16], 100.0, 32);
    let mut config = make_config(true);
    config.announce_table_max_bytes = TransportEngine::announce_entry_size_bytes(&sample_entry) * 2
        + TransportEngine::announce_entry_size_bytes(&sample_entry) / 2;
    let max_bytes = config.announce_table_max_bytes;
    let mut engine = TransportEngine::new(config);

    let held_dest = [0x71; 16];
    let active_dest = [0x72; 16];
    let newest_dest = [0x73; 16];

    assert!(engine.insert_held_announce(
        held_dest,
        make_announce_entry(held_dest, 100.0, 32),
        100.0,
    ));
    assert!(engine.insert_announce_entry(
        active_dest,
        make_announce_entry(active_dest, 100.0, 32),
        100.0,
    ));
    assert!(engine.insert_announce_entry(
        newest_dest,
        make_announce_entry(newest_dest, 101.0, 32),
        101.0,
    ));

    assert!(!engine.held_announces().contains_key(&held_dest));
    assert!(engine.announce_table().contains_key(&active_dest));
    assert!(engine.announce_table().contains_key(&newest_dest));
    assert!(engine.announce_retained_bytes() <= max_bytes);
}

#[test]
fn test_oversized_announce_entry_is_not_retained() {
    let mut config = make_config(true);
    config.announce_table_max_bytes = 200;
    let mut engine = TransportEngine::new(config);
    let dest = [0x81; 16];

    assert!(!engine.insert_announce_entry(dest, make_announce_entry(dest, 100.0, 256), 100.0));
    assert!(!engine.announce_table().contains_key(&dest));
    assert_eq!(engine.announce_retained_bytes(), 0);
}

#[test]
fn test_void_queues_clears_shutdown_transients() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_FULL));

    let active_dest = [0x91; 16];
    let held_dest = [0x92; 16];
    assert!(engine.insert_announce_entry(
        active_dest,
        make_announce_entry(active_dest, 100.0, 16),
        100.0,
    ));
    assert!(engine.insert_held_announce(
        held_dest,
        make_announce_entry(held_dest, 100.0, 16),
        100.0,
    ));
    engine.reverse_table.insert(
        [0x93; 16],
        tables::ReverseEntry {
            receiving_interface: InterfaceId(1),
            outbound_interface: InterfaceId(2),
            timestamp: 100.0,
        },
    );
    let _ = engine.announce_queues.gate_announce(
        InterfaceId(1),
        vec![0xAA; 32].into(),
        [0x94; 16],
        2,
        100.0,
        100.0,
        Some(1000),
        None,
        constants::ANNOUNCE_CAP,
    );
    let _ = engine.announce_queues.gate_announce(
        InterfaceId(1),
        vec![0xBB; 32].into(),
        [0x95; 16],
        3,
        100.0,
        100.0,
        Some(1000),
        None,
        constants::ANNOUNCE_CAP,
    );

    assert_eq!(engine.announce_table_count(), 1);
    assert_eq!(engine.held_announces_count(), 1);
    assert_eq!(engine.reverse_table_count(), 1);
    assert_eq!(engine.queued_announce_count(), 1);

    engine.void_queues();

    assert_eq!(engine.announce_table_count(), 0);
    assert_eq!(engine.held_announces_count(), 0);
    assert_eq!(engine.reverse_table_count(), 0);
    assert_eq!(engine.queued_announce_count(), 0);
    assert_eq!(engine.nonempty_announce_queue_count(), 0);
    assert_eq!(engine.announce_retained_bytes(), 0);
}

#[test]
fn test_blackhole_identity() {
    let mut engine = TransportEngine::new(make_config(false));
    let hash = [0xAA; 16];
    let now = 1000.0;

    assert!(!engine.is_blackholed(&hash, now));

    engine.blackhole_identity(hash, now, None, Some(String::from("test")));
    assert!(engine.is_blackholed(&hash, now));
    assert!(engine.is_blackholed(&hash, now + 999999.0)); // never expires

    assert!(engine.unblackhole_identity(&hash));
    assert!(!engine.is_blackholed(&hash, now));
    assert!(!engine.unblackhole_identity(&hash)); // already removed
}

#[test]
fn test_blackhole_with_duration() {
    let mut engine = TransportEngine::new(make_config(false));
    let hash = [0xBB; 16];
    let now = 1000.0;

    engine.blackhole_identity(hash, now, Some(1.0), None); // 1 hour
    assert!(engine.is_blackholed(&hash, now));
    assert!(engine.is_blackholed(&hash, now + 3599.0)); // just before expiry
    assert!(!engine.is_blackholed(&hash, now + 3601.0)); // after expiry
}

#[test]
fn test_cull_blackholed() {
    let mut engine = TransportEngine::new(make_config(false));
    let hash1 = [0xCC; 16];
    let hash2 = [0xDD; 16];
    let now = 1000.0;

    engine.blackhole_identity(hash1, now, Some(1.0), None); // 1 hour
    engine.blackhole_identity(hash2, now, None, None); // never expires

    engine.cull_blackholed(now + 4000.0); // past hash1 expiry

    assert!(!engine.blackholed_identities.contains_key(&hash1));
    assert!(engine.blackholed_identities.contains_key(&hash2));
}

#[test]
fn test_blackhole_blocks_announce() {
    use crate::announce::AnnounceData;
    use crate::destination::{destination_hash, name_hash};

    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_FULL));

    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x55; 32]));
    let dest_hash = destination_hash("test", &["app"], Some(identity.hash()));
    let name_h = name_hash("test", &["app"]);
    let random_hash = [0x42u8; 10];

    let (announce_data, _) =
        AnnounceData::pack(&identity, &dest_hash, &name_h, &random_hash, None, None).unwrap();

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
    };
    let packet = RawPacket::pack(
        flags,
        0,
        &dest_hash,
        None,
        constants::CONTEXT_NONE,
        &announce_data,
    )
    .unwrap();

    // Blackhole the identity
    let now = 1000.0;
    engine.blackhole_identity(*identity.hash(), now, None, None);

    let mut rng = rns_crypto::FixedRng::new(&[0x11; 32]);
    let actions = engine.handle_inbound(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(1),
            now,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
    );

    // Should produce no AnnounceReceived or PathUpdated actions
    assert!(actions
        .iter()
        .all(|a| !matches!(a, TransportAction::AnnounceReceived { .. })));
    assert!(actions
        .iter()
        .all(|a| !matches!(a, TransportAction::PathUpdated { .. })));
}

#[test]
fn test_async_announce_retransmit_cleanup_happens_before_queueing() {
    use crate::announce::AnnounceData;
    use crate::destination::{destination_hash, name_hash};
    use crate::transport::announce_verify_queue::AnnounceVerifyQueue;

    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_FULL));

    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x31; 32]));
    let dest_hash = destination_hash("async", &["announce"], Some(identity.hash()));
    let name_h = name_hash("async", &["announce"]);
    let random_hash = [0x44u8; 10];
    let (announce_data, _) =
        AnnounceData::pack(&identity, &dest_hash, &name_h, &random_hash, None, None).unwrap();

    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_2,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_TRANSPORT,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        },
        3,
        &dest_hash,
        Some(&[0xBB; 16]),
        constants::CONTEXT_NONE,
        &announce_data,
    )
    .unwrap();

    engine.announce_table.insert(
        dest_hash,
        AnnounceEntry {
            timestamp: 1000.0,
            retransmit_timeout: 2000.0,
            retries: constants::PATHFINDER_R,
            received_from: [0xBB; 16],
            hops: 2,
            packet_raw: packet.raw.clone(),
            packet_data: packet.data.clone(),
            destination_hash: dest_hash,
            context_flag: constants::FLAG_UNSET,
            local_rebroadcasts: 0,
            block_rebroadcasts: false,
            attached_interface: None,
        },
    );

    let mut queue = AnnounceVerifyQueue::new(8);
    let mut rng = rns_crypto::FixedRng::new(&[0x11; 32]);
    let actions = engine.handle_inbound_with_announce_queue(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(1),
            now: 1000.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
        Some(&mut queue),
    );

    assert!(actions.is_empty());
    assert_eq!(queue.len(), 1);
    assert!(
        !engine.announce_table.contains_key(&dest_hash),
        "retransmit completion should clear announce_table before queueing"
    );
}

#[test]
fn test_async_announce_completion_inserts_sig_cache_and_prevents_requeue() {
    use crate::announce::AnnounceData;
    use crate::destination::{destination_hash, name_hash};
    use crate::transport::announce_verify_queue::AnnounceVerifyQueue;

    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_FULL));

    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x52; 32]));
    let dest_hash = destination_hash("async", &["cache"], Some(identity.hash()));
    let name_h = name_hash("async", &["cache"]);
    let random_hash = [0x55u8; 10];
    let (announce_data, _) =
        AnnounceData::pack(&identity, &dest_hash, &name_h, &random_hash, None, None).unwrap();

    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        },
        0,
        &dest_hash,
        None,
        constants::CONTEXT_NONE,
        &announce_data,
    )
    .unwrap();

    let mut queue = AnnounceVerifyQueue::new(8);
    let mut rng = rns_crypto::FixedRng::new(&[0x77; 32]);
    let actions = engine.handle_inbound_with_announce_queue(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(1),
            now: 1000.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
        Some(&mut queue),
    );
    assert!(actions.is_empty());
    assert_eq!(queue.len(), 1);

    let mut batch = queue.take_pending(1000.0);
    assert_eq!(batch.len(), 1);
    let (key, pending) = batch.pop().unwrap();

    let announce = AnnounceData::unpack(&pending.packet.data, false).unwrap();
    let validated = announce.validate(&pending.packet.destination_hash).unwrap();
    let mut material = [0u8; 80];
    material[..16].copy_from_slice(&pending.packet.destination_hash);
    material[16..].copy_from_slice(&announce.signature);
    let sig_cache_key = hash::full_hash(&material);

    let pending = queue.complete_success(&key).unwrap();
    let actions =
        engine.complete_verified_announce(pending, validated, sig_cache_key, 1000.0, &mut rng);
    assert!(actions
        .iter()
        .any(|action| matches!(action, TransportAction::AnnounceReceived { .. })));
    assert!(engine.announce_sig_cache_contains(&sig_cache_key));

    let actions = engine.handle_inbound_with_announce_queue(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(1),
            now: 1001.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
        Some(&mut queue),
    );
    assert!(actions.is_empty());
    assert_eq!(queue.len(), 0);
}

#[test]
fn test_tick_culls_expired_path() {
    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_FULL));

    let dest = [0x66; 16];
    engine.path_table.insert(
        dest,
        PathSet::from_single(
            PathEntry {
                timestamp: 100.0,
                next_hop: [0; 16],
                hops: 2,
                expires: 200.0,
                random_blobs: Vec::new(),
                receiving_interface: InterfaceId(1),
                packet_hash: [0; 32],
                announce_raw: None,
            },
            1,
        ),
    );

    assert!(engine.has_path(&dest));

    let mut rng = rns_crypto::FixedRng::new(&[0; 32]);
    // Advance past cull interval and path expiry
    engine.tick(300.0, &mut rng);

    assert!(!engine.has_path(&dest));
}

// =========================================================================
// Phase 7b: Local client transport tests
// =========================================================================

fn make_local_client_interface(id: u64) -> InterfaceInfo {
    InterfaceInfo {
        id: InterfaceId(id),
        name: String::from("local_client"),
        mode: constants::MODE_FULL,
        gravity: 0,
        recursive_prs: false,
        announces_from_internal: true,
        announces_to_internal: None,
        out_capable: true,
        in_capable: true,
        bitrate: None,
        airtime_profile: None,
        announce_rate_target: None,
        announce_rate_grace: 0,
        announce_rate_penalty: 0.0,
        announce_cap: constants::ANNOUNCE_CAP,
        is_local_client: true,
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

#[test]
fn test_has_local_clients() {
    let mut engine = TransportEngine::new(make_config(false));
    assert!(!engine.has_local_clients());

    engine.register_interface(make_interface(1, constants::MODE_FULL));
    assert!(!engine.has_local_clients());

    engine.register_interface(make_local_client_interface(2));
    assert!(engine.has_local_clients());

    engine.deregister_interface(InterfaceId(2));
    assert!(!engine.has_local_clients());
}

#[test]
fn test_local_client_hop_decrement() {
    // Packets from local clients should have their hops decremented
    // to cancel the standard +1 (net zero change)
    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_local_client_interface(1));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    // Register destination so we get a DeliverLocal action
    let dest = [0xAA; 16];
    engine.register_destination(dest, constants::DESTINATION_PLAIN);

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_PLAIN,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    // Pack with hops=0
    let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

    let mut rng = rns_crypto::FixedRng::new(&[0; 32]);
    let actions = engine.handle_inbound(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(1),
            now: 1000.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
    );

    // Should have local delivery; hops should still be 0 (not 1)
    // because the local client decrement cancels the increment
    let deliver = actions
        .iter()
        .find(|a| matches!(a, TransportAction::DeliverLocal { .. }));
    assert!(deliver.is_some(), "Should deliver locally");
}

#[test]
fn lrrtt_local_delivery_preserves_post_ingress_hops() {
    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    let link_id = [0x4c; 16];
    engine.register_destination(link_id, constants::DESTINATION_LINK);
    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        },
        0,
        &link_id,
        None,
        constants::CONTEXT_LRRTT,
        b"authenticated ciphertext",
    )
    .unwrap();
    let actions = engine.handle_inbound(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(1),
            now: 1.0,
            rx: RxMetadata::default(),
        },
        &mut rns_crypto::FixedRng::new(&[0; 32]),
    );
    let raw = actions
        .iter()
        .find_map(|action| match action {
            TransportAction::DeliverLocal { raw, .. } => Some(raw),
            _ => None,
        })
        .expect("LRRTT should be delivered locally");
    assert_eq!(RawPacket::unpack(raw).unwrap().hops, 1);
}

#[test]
fn test_prepare_inbound_packet_only_retains_original_raw_for_announces() {
    let engine = TransportEngine::new(make_config(false));
    let dest = [0xAB; 16];
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

    let ctx = engine
        .prepare_inbound_packet(InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(9),
            now: 1000.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        })
        .expect("packet should parse and pass filter");

    assert!(ctx.original_raw.is_none());
    assert_eq!(ctx.packet.raw, packet.raw);
    assert_eq!(ctx.packet.hops, 1);
    assert_eq!(ctx.iface, InterfaceId(9));

    let announce_flags = PacketFlags {
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
        ..flags
    };
    let announce = RawPacket::pack(
        announce_flags,
        0,
        &dest,
        None,
        constants::CONTEXT_NONE,
        &[0u8; 91],
    )
    .unwrap();
    let announce_ctx = engine
        .prepare_inbound_packet(InboundFrame {
            raw: &announce.raw,
            iface: InterfaceId(9),
            now: 1000.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        })
        .expect("announce should parse and pass filter");
    assert_eq!(
        announce_ctx.original_raw.as_deref(),
        Some(announce.raw.as_slice())
    );
}

#[test]
fn test_deliver_local_preserves_original_raw_and_metadata() {
    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_FULL));

    let dest = [0xAC; 16];
    engine.register_destination(dest, constants::DESTINATION_SINGLE);

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet =
        RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"deliver").unwrap();

    let mut rng = rns_crypto::FixedRng::new(&[0; 32]);
    let actions = engine.handle_inbound(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(1),
            now: 1000.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
    );

    let deliver = actions
        .iter()
        .find_map(|action| match action {
            TransportAction::DeliverLocal {
                destination_hash,
                raw,
                packet_hash,
                receiving_interface,
            } => Some((destination_hash, raw, packet_hash, receiving_interface)),
            _ => None,
        })
        .expect("should produce DeliverLocal");

    assert_eq!(*deliver.0, dest);
    assert_eq!(&**deliver.1, packet.raw.as_slice());
    assert_eq!(*deliver.2, packet.packet_hash);
    assert_eq!(*deliver.3, InterfaceId(1));
}

#[test]
fn local_lrproof_delivery_carries_post_ingress_hops() {
    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    let link_id = [0x4C; 16];
    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_PROOF,
        },
        4,
        &link_id,
        None,
        constants::CONTEXT_LRPROOF,
        &[0xAA; 96],
    )
    .unwrap();
    let mut rng = rns_crypto::FixedRng::new(&[0x11; 32]);

    let actions = engine.handle_inbound(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(1),
            now: 1000.0,
            rx: RxMetadata::default(),
        },
        &mut rng,
    );
    let delivered_raw = actions
        .iter()
        .find_map(|action| match action {
            TransportAction::DeliverLocal { raw, .. } => Some(&**raw),
            _ => None,
        })
        .expect("LRPROOF should be delivered to the pending link manager");
    assert_eq!(RawPacket::unpack(delivered_raw).unwrap().hops, 5);
}

#[test]
fn test_plain_broadcast_from_local_client() {
    // PLAIN broadcast from local client should forward to external interfaces
    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_local_client_interface(1));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let dest = [0xBB; 16];
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_PLAIN,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"test").unwrap();

    let mut rng = rns_crypto::FixedRng::new(&[0; 32]);
    let actions = engine.handle_inbound(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(1),
            now: 1000.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
    );

    // Should have ForwardPlainBroadcast to external (to_local=false)
    let forward = actions.iter().find(|a| {
        matches!(
            a,
            TransportAction::ForwardPlainBroadcast {
                to_local: false,
                ..
            }
        )
    });
    assert!(forward.is_some(), "Should forward to external interfaces");
}

#[test]
fn test_plain_broadcast_from_external() {
    // PLAIN broadcast from external should forward to local clients
    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_local_client_interface(1));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let dest = [0xCC; 16];
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_PLAIN,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"test").unwrap();

    let mut rng = rns_crypto::FixedRng::new(&[0; 32]);
    let actions = engine.handle_inbound(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(2),
            now: 1000.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
    );

    // Should have ForwardPlainBroadcast to local clients (to_local=true)
    let forward = actions.iter().find(|a| {
        matches!(
            a,
            TransportAction::ForwardPlainBroadcast { to_local: true, .. }
        )
    });
    assert!(forward.is_some(), "Should forward to local clients");
}

#[test]
fn test_no_plain_broadcast_bridging_without_local_clients() {
    // Without local clients, no bridging should happen
    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let dest = [0xDD; 16];
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_PLAIN,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"test").unwrap();

    let mut rng = rns_crypto::FixedRng::new(&[0; 32]);
    let actions = engine.handle_inbound(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(1),
            now: 1000.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
    );

    // No ForwardPlainBroadcast should be emitted
    let has_forward = actions
        .iter()
        .any(|a| matches!(a, TransportAction::ForwardPlainBroadcast { .. }));
    assert!(!has_forward, "No bridging without local clients");
}

#[test]
fn test_announce_forwarded_to_local_clients() {
    use crate::announce::AnnounceData;
    use crate::destination::{destination_hash, name_hash};

    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    engine.register_interface(make_local_client_interface(2));

    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x77; 32]));
    let dest_hash = destination_hash("test", &["fwd"], Some(identity.hash()));
    let name_h = name_hash("test", &["fwd"]);
    let random_hash = [0x42u8; 10];

    let (announce_data, _) =
        AnnounceData::pack(&identity, &dest_hash, &name_h, &random_hash, None, None).unwrap();

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
    };
    let packet = RawPacket::pack(
        flags,
        0,
        &dest_hash,
        None,
        constants::CONTEXT_NONE,
        &announce_data,
    )
    .unwrap();

    let mut rng = rns_crypto::FixedRng::new(&[0x11; 32]);
    let actions = engine.handle_inbound(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(1),
            now: 1000.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
    );

    // Should have ForwardToLocalClients since we have local clients
    let forward = actions
        .iter()
        .find(|a| matches!(a, TransportAction::ForwardToLocalClients { .. }));
    assert!(
        forward.is_some(),
        "Should forward announce to local clients"
    );

    // The exclude should be the receiving interface
    match forward.unwrap() {
        TransportAction::ForwardToLocalClients { exclude, raw } => {
            assert_eq!(*exclude, Some(InterfaceId(1)));
            let flags = PacketFlags::unpack(raw[0]);
            assert_eq!(flags.header_type, constants::HEADER_2);
            assert_eq!(flags.transport_type, constants::TRANSPORT_TRANSPORT);
            assert_eq!(&raw[2..18], &[0x42; 16]);
        }
        _ => unreachable!(),
    }
}

#[test]
fn test_no_announce_forward_without_local_clients() {
    use crate::announce::AnnounceData;
    use crate::destination::{destination_hash, name_hash};

    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_interface(1, constants::MODE_FULL));

    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x88; 32]));
    let dest_hash = destination_hash("test", &["nofwd"], Some(identity.hash()));
    let name_h = name_hash("test", &["nofwd"]);
    let random_hash = [0x42u8; 10];

    let (announce_data, _) =
        AnnounceData::pack(&identity, &dest_hash, &name_h, &random_hash, None, None).unwrap();

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
    };
    let packet = RawPacket::pack(
        flags,
        0,
        &dest_hash,
        None,
        constants::CONTEXT_NONE,
        &announce_data,
    )
    .unwrap();

    let mut rng = rns_crypto::FixedRng::new(&[0x22; 32]);
    let actions = engine.handle_inbound(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(1),
            now: 1000.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
    );

    // No ForwardToLocalClients should be emitted
    let has_forward = actions
        .iter()
        .any(|a| matches!(a, TransportAction::ForwardToLocalClients { .. }));
    assert!(!has_forward, "No forward without local clients");
}

#[test]
fn test_local_client_exclude_from_forward() {
    use crate::announce::AnnounceData;
    use crate::destination::{destination_hash, name_hash};

    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_local_client_interface(1));
    engine.register_interface(make_local_client_interface(2));

    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x99; 32]));
    let dest_hash = destination_hash("test", &["excl"], Some(identity.hash()));
    let name_h = name_hash("test", &["excl"]);
    let random_hash = [0x42u8; 10];

    let (announce_data, _) =
        AnnounceData::pack(&identity, &dest_hash, &name_h, &random_hash, None, None).unwrap();

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
    };
    let packet = RawPacket::pack(
        flags,
        0,
        &dest_hash,
        None,
        constants::CONTEXT_NONE,
        &announce_data,
    )
    .unwrap();

    let mut rng = rns_crypto::FixedRng::new(&[0x33; 32]);
    // Feed announce from local client 1
    let actions = engine.handle_inbound(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(1),
            now: 1000.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
    );

    // Should forward to local clients, excluding interface 1 (the sender)
    let forward = actions
        .iter()
        .find(|a| matches!(a, TransportAction::ForwardToLocalClients { .. }));
    assert!(forward.is_some());
    match forward.unwrap() {
        TransportAction::ForwardToLocalClients { exclude, .. } => {
            assert_eq!(*exclude, Some(InterfaceId(1)));
        }
        _ => unreachable!(),
    }
}

// =========================================================================
// Phase 7d: Tunnel tests
// =========================================================================

fn make_tunnel_interface(id: u64) -> InterfaceInfo {
    InterfaceInfo {
        id: InterfaceId(id),
        name: String::from("tunnel_iface"),
        mode: constants::MODE_FULL,
        gravity: 0,
        recursive_prs: false,
        announces_from_internal: true,
        announces_to_internal: None,
        out_capable: true,
        in_capable: true,
        bitrate: None,
        airtime_profile: None,
        announce_rate_target: None,
        announce_rate_grace: 0,
        announce_rate_penalty: 0.0,
        announce_cap: constants::ANNOUNCE_CAP,
        is_local_client: false,
        wants_tunnel: true,
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

#[test]
fn test_handle_tunnel_new() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_tunnel_interface(1));

    let tunnel_id = [0xAA; 32];
    let actions = engine.handle_tunnel(tunnel_id, InterfaceId(1), 1000.0);

    // Should emit TunnelEstablished
    assert!(actions
        .iter()
        .any(|a| matches!(a, TransportAction::TunnelEstablished { .. })));

    // Interface should now have tunnel_id set
    let info = engine.interface_info(&InterfaceId(1)).unwrap();
    assert_eq!(info.tunnel_id, Some(tunnel_id));

    // Tunnel table should have the entry
    assert_eq!(engine.tunnel_table().len(), 1);
}

#[test]
fn test_announce_stores_tunnel_path() {
    use crate::announce::AnnounceData;
    use crate::destination::{destination_hash, name_hash};

    let mut engine = TransportEngine::new(make_config(false));
    let mut iface = make_tunnel_interface(1);
    let tunnel_id = [0xBB; 32];
    iface.tunnel_id = Some(tunnel_id);
    engine.register_interface(iface);

    // Create tunnel entry
    engine.handle_tunnel(tunnel_id, InterfaceId(1), 1000.0);

    // Create and send an announce
    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0xCC; 32]));
    let dest_hash = destination_hash("test", &["tunnel"], Some(identity.hash()));
    let name_h = name_hash("test", &["tunnel"]);
    let random_hash = [0x42u8; 10];

    let (announce_data, _) =
        AnnounceData::pack(&identity, &dest_hash, &name_h, &random_hash, None, None).unwrap();

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
    };
    let packet = RawPacket::pack(
        flags,
        0,
        &dest_hash,
        None,
        constants::CONTEXT_NONE,
        &announce_data,
    )
    .unwrap();

    let mut rng = rns_crypto::FixedRng::new(&[0xDD; 32]);
    engine.handle_inbound(
        InboundFrame {
            raw: &packet.raw,
            iface: InterfaceId(1),
            now: 1000.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
    );

    // Path should be in path table
    assert!(engine.has_path(&dest_hash));

    // Path should also be in tunnel table
    let tunnel = engine.tunnel_table().get(&tunnel_id).unwrap();
    assert_eq!(tunnel.paths.len(), 1);
    assert!(tunnel.paths.contains_key(&dest_hash));
}

#[test]
fn test_tunnel_reattach_restores_paths() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_tunnel_interface(1));

    let tunnel_id = [0xCC; 32];
    engine.handle_tunnel(tunnel_id, InterfaceId(1), 1000.0);

    // Manually add a path to the tunnel
    let dest = [0xDD; 16];
    engine.tunnel_table.store_tunnel_path(
        &tunnel_id,
        dest,
        tunnel::TunnelPath {
            timestamp: 1000.0,
            received_from: [0xEE; 16],
            hops: 3,
            expires: 1000.0 + constants::DESTINATION_TIMEOUT,
            random_blobs: Vec::new(),
            packet_hash: [0xFF; 32],
        },
        1000.0,
        constants::DESTINATION_TIMEOUT,
        usize::MAX,
    );

    // Void the tunnel interface (disconnect)
    engine.void_tunnel_interface(&tunnel_id);

    // Remove path from path table to simulate it expiring
    engine.path_table.remove(&dest);
    assert!(!engine.has_path(&dest));

    // Reattach tunnel on new interface
    engine.register_interface(make_interface(2, constants::MODE_FULL));
    let actions = engine.handle_tunnel(tunnel_id, InterfaceId(2), 2000.0);

    // Should restore the path
    assert!(engine.has_path(&dest));
    let path = engine.path_table.get(&dest).unwrap().primary().unwrap();
    assert_eq!(path.hops, 3);
    assert_eq!(path.receiving_interface, InterfaceId(2));

    // Should emit TunnelEstablished
    assert!(actions
        .iter()
        .any(|a| matches!(a, TransportAction::TunnelEstablished { .. })));
}

#[test]
fn test_active_packet_hashes_include_detached_tunnel_paths() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_tunnel_interface(1));

    let tunnel_id = [0xCA; 32];
    let destination_hash = [0xDB; 16];
    let packet_hash = [0xEC; 32];
    engine.handle_tunnel(tunnel_id, InterfaceId(1), 1000.0);
    engine.tunnel_table.store_tunnel_path(
        &tunnel_id,
        destination_hash,
        tunnel::TunnelPath {
            timestamp: 1000.0,
            received_from: [0xFE; 16],
            hops: 2,
            expires: 1000.0 + constants::DESTINATION_TIMEOUT,
            random_blobs: Vec::new(),
            packet_hash,
        },
        1000.0,
        constants::DESTINATION_TIMEOUT,
        usize::MAX,
    );
    engine.void_tunnel_interface(&tunnel_id);
    engine.path_table.remove(&destination_hash);

    let active_hashes = engine.active_packet_hashes();
    assert_eq!(active_hashes, vec![packet_hash]);
}

#[test]
fn test_tunnel_reattach_does_not_overwrite_newer_path() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_tunnel_interface(1));

    let tunnel_id = [0xCD; 32];
    let dest = [0xDE; 16];
    let older_blob = make_random_blob(100);
    let newer_blob = make_random_blob(200);

    engine.handle_tunnel(tunnel_id, InterfaceId(1), 1000.0);
    engine.tunnel_table.store_tunnel_path(
        &tunnel_id,
        dest,
        tunnel::TunnelPath {
            timestamp: 1000.0,
            received_from: [0xEE; 16],
            hops: 2,
            expires: 1000.0 + constants::DESTINATION_TIMEOUT,
            random_blobs: vec![older_blob],
            packet_hash: [0x11; 32],
        },
        1000.0,
        constants::DESTINATION_TIMEOUT,
        usize::MAX,
    );
    engine.void_tunnel_interface(&tunnel_id);

    engine.path_table.insert(
        dest,
        PathSet::from_single(
            PathEntry {
                timestamp: 1500.0,
                next_hop: [0xAB; 16],
                hops: 3,
                expires: 1500.0 + constants::DESTINATION_TIMEOUT,
                random_blobs: vec![newer_blob],
                receiving_interface: InterfaceId(3),
                packet_hash: [0x22; 32],
                announce_raw: None,
            },
            1,
        ),
    );

    engine.register_interface(make_interface(2, constants::MODE_FULL));
    engine.handle_tunnel(tunnel_id, InterfaceId(2), 2000.0);

    let path = engine.path_table.get(&dest).unwrap().primary().unwrap();
    assert_eq!(path.next_hop, [0xAB; 16]);
    assert_eq!(path.hops, 3);
    assert_eq!(path.receiving_interface, InterfaceId(3));
    assert_eq!(path.random_blobs, vec![newer_blob]);
}

#[test]
fn test_void_tunnel_interface() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_tunnel_interface(1));

    let tunnel_id = [0xDD; 32];
    engine.handle_tunnel(tunnel_id, InterfaceId(1), 1000.0);

    // Verify tunnel has interface
    assert_eq!(
        engine.tunnel_table().get(&tunnel_id).unwrap().interface,
        Some(InterfaceId(1))
    );

    engine.void_tunnel_interface(&tunnel_id);

    // Interface voided, but tunnel still exists
    assert_eq!(engine.tunnel_table().len(), 1);
    assert_eq!(
        engine.tunnel_table().get(&tunnel_id).unwrap().interface,
        None
    );
}

#[test]
fn test_tick_culls_tunnels() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_tunnel_interface(1));

    let tunnel_id = [0xEE; 32];
    engine.handle_tunnel(tunnel_id, InterfaceId(1), 1000.0);
    assert_eq!(engine.tunnel_table().len(), 1);

    let mut rng = rns_crypto::FixedRng::new(&[0; 32]);

    // Tick past DESTINATION_TIMEOUT + TABLES_CULL_INTERVAL
    engine.tick(
        1000.0 + constants::DESTINATION_TIMEOUT + constants::TABLES_CULL_INTERVAL + 1.0,
        &mut rng,
    );

    assert_eq!(engine.tunnel_table().len(), 0);
}

#[test]
fn test_synthesize_tunnel() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_tunnel_interface(1));

    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0xFF; 32]));
    let mut rng = rns_crypto::FixedRng::new(&[0x11; 32]);

    let actions = engine.synthesize_tunnel(&identity, InterfaceId(1), &mut rng);

    // Should produce a TunnelSynthesize action
    assert_eq!(actions.len(), 1);
    match &actions[0] {
        TransportAction::TunnelSynthesize {
            interface,
            data,
            dest_hash,
        } => {
            assert_eq!(*interface, InterfaceId(1));
            assert_eq!(data.len(), tunnel::TUNNEL_SYNTH_LENGTH);
            // dest_hash should be the tunnel.synthesize plain destination
            let expected_dest = crate::destination::destination_hash(
                "rnstransport",
                &["tunnel", "synthesize"],
                None,
            );
            assert_eq!(*dest_hash, expected_dest);
        }
        _ => panic!("Expected TunnelSynthesize"),
    }
}

fn synthesized_interface_hash(actions: &[TransportAction]) -> [u8; 32] {
    let data = actions
        .iter()
        .find_map(|action| match action {
            TransportAction::TunnelSynthesize { data, .. } => Some(data),
            _ => None,
        })
        .expect("tunnel synthesis action");
    let mut interface_hash = [0u8; 32];
    interface_hash.copy_from_slice(&data[64..96]);
    interface_hash
}

#[test]
fn tunnel_synthesis_uses_hash_cached_at_interface_registration() {
    let mut engine = TransportEngine::new(make_config(true));
    let mut interface = make_tunnel_interface(1);
    interface.name = String::from("registered-name");
    engine.register_interface(interface);

    // Interface display names are immutable in normal operation. Mutating
    // the stored metadata here distinguishes a registration-time cache
    // from a hash recalculated by every synthesis.
    engine.interfaces.get_mut(&InterfaceId(1)).unwrap().name = String::from("later-name");

    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0xFF; 32]));
    let actions = engine.synthesize_tunnel(
        &identity,
        InterfaceId(1),
        &mut rns_crypto::FixedRng::new(&[0x11; 32]),
    );

    assert_eq!(
        synthesized_interface_hash(&actions),
        hash::full_hash(b"registered-name")
    );
}

#[test]
fn replacing_interface_id_refreshes_cached_tunnel_hash() {
    let mut engine = TransportEngine::new(make_config(true));
    let mut first = make_tunnel_interface(1);
    first.name = String::from("first-name");
    engine.register_interface(first);
    let mut replacement = make_tunnel_interface(1);
    replacement.name = String::from("replacement-name");
    engine.register_interface(replacement);

    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0xFF; 32]));
    let actions = engine.synthesize_tunnel(
        &identity,
        InterfaceId(1),
        &mut rns_crypto::FixedRng::new(&[0x11; 32]),
    );

    assert_eq!(
        synthesized_interface_hash(&actions),
        hash::full_hash(b"replacement-name")
    );
    assert_ne!(
        synthesized_interface_hash(&actions),
        hash::full_hash(b"first-name")
    );
}

#[test]
fn test_synthesize_tunnel_missing_interface_is_dropped() {
    let engine = TransportEngine::new(make_config(true));

    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0xFF; 32]));
    let mut rng = rns_crypto::FixedRng::new(&[0x11; 32]);

    let actions = engine.synthesize_tunnel(&identity, InterfaceId(99), &mut rng);

    assert!(actions.is_empty());
}

#[test]
fn test_synthesize_tunnel_public_only_identity_is_dropped() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_tunnel_interface(1));

    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0xFF; 32]));
    let public_key = identity.get_public_key().unwrap();
    let public_only_identity = rns_crypto::identity::Identity::from_public_key(&public_key);
    let mut rng = rns_crypto::FixedRng::new(&[0x11; 32]);

    let actions = engine.synthesize_tunnel(&public_only_identity, InterfaceId(1), &mut rng);

    assert!(actions.is_empty());
}

// =========================================================================
// DISCOVER_PATHS_FOR tests
// =========================================================================

fn make_path_request_data(dest_hash: &[u8; 16], tag: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(dest_hash);
    data.extend_from_slice(tag);
    data
}

fn make_transport_path_request_data(
    dest_hash: &[u8; 16],
    requestor_transport_id: &[u8; 16],
    tag: &[u8],
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(dest_hash);
    data.extend_from_slice(requestor_transport_id);
    data.extend_from_slice(tag);
    data
}

fn assert_recursive_path_request_packet(raw: &[u8], dest: &[u8; 16], tag: &[u8]) {
    let packet = RawPacket::unpack(raw).expect("recursive path request packet");
    let path_request_dest =
        crate::destination::destination_hash("rnstransport", &["path", "request"], None);

    assert_eq!(packet.flags.header_type, constants::HEADER_1);
    assert_eq!(packet.flags.transport_type, constants::TRANSPORT_BROADCAST);
    assert_eq!(packet.flags.destination_type, constants::DESTINATION_PLAIN);
    assert_eq!(packet.flags.packet_type, constants::PACKET_TYPE_DATA);
    assert_eq!(packet.hops, 0);
    assert_eq!(packet.context, constants::CONTEXT_NONE);
    assert_eq!(packet.destination_hash, path_request_dest);

    let mut expected_data = Vec::new();
    expected_data.extend_from_slice(dest);
    expected_data.extend_from_slice(&[0x42; 16]);
    expected_data.extend_from_slice(tag);
    assert_eq!(packet.data, expected_data);
}

#[test]
fn test_path_request_forwarded_on_ap() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let dest = [0xD1; 16];
    let tag = [0x01; 16];
    let data = make_path_request_data(&dest, &tag);

    let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

    // Should forward the path request on interface 2 (the other OUT interface)
    assert_eq!(actions.len(), 1);
    match &actions[0] {
        TransportAction::SendOnInterface { interface, .. } => {
            assert_eq!(*interface, InterfaceId(2));
        }
        _ => panic!("Expected SendOnInterface for forwarded path request"),
    }
    // Should have stored a discovery path request
    assert!(engine.discovery_path_requests.contains_key(&dest));
}

#[test]
fn test_recursive_path_request_rebuilds_transport_payload() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let dest = [0xD8; 16];
    let original_requestor_transport_id = [0x99; 16];
    let tag = [0x08; 16];
    let data = make_transport_path_request_data(&dest, &original_requestor_transport_id, &tag);

    let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

    assert_eq!(actions.len(), 1);
    match &actions[0] {
        TransportAction::SendOnInterface { interface, raw } => {
            assert_eq!(*interface, InterfaceId(2));
            assert_recursive_path_request_packet(raw.as_ref(), &dest, &tag);
        }
        _ => panic!("expected SendOnInterface for recursive path request"),
    }
    assert!(engine.discovery_path_requests.contains_key(&dest));
}

#[test]
fn test_path_request_forwarded_on_internal() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_INTERNAL));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let dest = [0xDB; 16];
    let tag = [0x0B; 16];
    let data = make_path_request_data(&dest, &tag);

    let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

    assert_eq!(actions.len(), 1);
    match &actions[0] {
        TransportAction::SendOnInterface { interface, raw } => {
            assert_eq!(*interface, InterfaceId(2));
            assert_recursive_path_request_packet(raw.as_ref(), &dest, &tag);
        }
        _ => panic!("expected SendOnInterface for recursive path request"),
    }
    assert!(engine.discovery_path_requests.contains_key(&dest));
}

#[test]
fn boundary_path_request_searches_only_boundary_and_gateway_interfaces() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_BOUNDARY));
    engine.register_interface(make_interface(2, constants::MODE_BOUNDARY));
    engine.register_interface(make_interface(3, constants::MODE_GATEWAY));
    engine.register_interface(make_interface(4, constants::MODE_FULL));
    engine.register_interface(make_interface(5, constants::MODE_ACCESS_POINT));
    engine.register_interface(make_interface(6, constants::MODE_INTERNAL));

    let dest = [0xBC; 16];
    let tag = [0x21; 16];
    let data = make_path_request_data(&dest, &tag);

    let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

    let interfaces: Vec<_> = actions
        .iter()
        .filter_map(|action| match action {
            TransportAction::SendOnInterface { interface, raw } => {
                assert_recursive_path_request_packet(raw.as_ref(), &dest, &tag);
                Some(*interface)
            }
            _ => None,
        })
        .collect();
    assert_eq!(interfaces, vec![InterfaceId(2), InterfaceId(3)]);
    assert!(engine.discovery_path_requests.contains_key(&dest));
}

#[test]
fn recursive_prs_on_boundary_keeps_unfiltered_egress_behavior() {
    let mut engine = TransportEngine::new(make_config(true));
    let mut ingress = make_interface(1, constants::MODE_BOUNDARY);
    ingress.recursive_prs = true;
    engine.register_interface(ingress);
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let dest = [0xBD; 16];
    let tag = [0x22; 16];
    let data = make_path_request_data(&dest, &tag);

    let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

    assert_eq!(actions.len(), 1);
    match &actions[0] {
        TransportAction::SendOnInterface { interface, raw } => {
            assert_eq!(*interface, InterfaceId(2));
            assert_recursive_path_request_packet(raw.as_ref(), &dest, &tag);
        }
        _ => panic!("expected SendOnInterface for recursive path request"),
    }
    assert!(engine.discovery_path_requests.contains_key(&dest));
}

#[test]
fn test_path_request_not_forwarded_on_full() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let dest = [0xD2; 16];
    let tag = [0x02; 16];
    let data = make_path_request_data(&dest, &tag);

    let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

    // MODE_FULL is not in DISCOVER_PATHS_FOR, so no forwarding
    assert!(actions.is_empty());
    assert!(!engine.discovery_path_requests.contains_key(&dest));
}

#[test]
fn test_path_request_forwarded_on_full_with_recursive_prs() {
    let mut engine = TransportEngine::new(make_config(true));
    let mut ingress = make_interface(1, constants::MODE_FULL);
    ingress.recursive_prs = true;
    engine.register_interface(ingress);
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let dest = [0xD9; 16];
    let tag = [0x09; 16];
    let data = make_path_request_data(&dest, &tag);

    let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

    assert_eq!(actions.len(), 1);
    match &actions[0] {
        TransportAction::SendOnInterface { interface, raw } => {
            assert_eq!(*interface, InterfaceId(2));
            assert_recursive_path_request_packet(raw.as_ref(), &dest, &tag);
        }
        _ => panic!("expected SendOnInterface for recursive path request"),
    }
    assert!(engine.discovery_path_requests.contains_key(&dest));
}

#[test]
fn test_recursive_prs_still_obeys_ingress_control() {
    let mut engine = TransportEngine::new(make_config(true));
    let mut ingress = make_interface(1, constants::MODE_FULL);
    ingress.recursive_prs = true;
    let ingress_config = crate::transport::types::IngressControlConfig::enabled();
    ingress.ip_freq = ingress_config.pr_burst_freq_new + 1.0;
    ingress.ingress_control = ingress_config;
    ingress.started = 1000.0;
    engine.register_interface(ingress);
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let dest = [0xDA; 16];
    let tag = [0x0A; 16];
    let data = make_path_request_data(&dest, &tag);

    let actions = engine.handle_path_request(&data, InterfaceId(1), 1001.0);

    assert!(actions.is_empty());
    assert!(!engine.discovery_path_requests.contains_key(&dest));
}

#[test]
fn test_queued_ingress_limited_path_request_cannot_escape_after_burst_clears() {
    let mut engine = TransportEngine::new(make_config(true));
    let mut ingress = make_interface(1, constants::MODE_FULL);
    ingress.recursive_prs = true;
    ingress.ingress_control = crate::transport::types::IngressControlConfig::enabled();
    ingress.ip_freq = 0.0;
    ingress.started = 0.0;
    engine.register_interface(ingress);
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let dest = [0xDB; 16];
    let tag = [0x0B; 16];
    let data = make_path_request_data(&dest, &tag);
    let actions =
        engine.handle_path_request_with_ingress_limit(&data, InterfaceId(1), 1000.0, true);

    assert!(actions.is_empty());
    assert!(!engine.discovery_path_requests.contains_key(&dest));
    assert!(!engine.pr_burst_active(&InterfaceId(1)));
}

#[test]
fn test_duplicate_discovery_path_request_is_suppressed() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let dest = [0xD7; 16];
    let tag = [0x07; 16];
    let data = make_path_request_data(&dest, &tag);

    let first = engine.handle_path_request(&data, InterfaceId(1), 1000.0);
    let second = engine.handle_path_request(&data, InterfaceId(1), 1001.0);

    assert_eq!(first.len(), 1);
    assert!(
        second.is_empty(),
        "duplicate discovery request should be dropped"
    );
    assert_eq!(engine.discovery_pr_tags_count(), 1);
}

#[test]
fn discovery_path_request_timeout_covers_slowest_interface_round_trip() {
    let mut engine = TransportEngine::new(make_config(true));
    let mut ingress = make_interface(1, constants::MODE_ACCESS_POINT);
    ingress.bitrate = Some(4_000);
    let mut slow_egress = make_interface(2, constants::MODE_FULL);
    slow_egress.bitrate = Some(400);
    engine.register_interface(ingress);
    engine.register_interface(slow_egress);

    assert_eq!(
        super::path_requests::discovery_path_request_timeout(&engine.interfaces),
        26.0
    );

    let destination = [0xd0; 16];
    let data = make_path_request_data(&destination, &[0x10; 16]);
    assert_eq!(
        engine
            .handle_path_request(&data, InterfaceId(1), 1000.0)
            .len(),
        1
    );
    assert_eq!(
        engine.discovery_path_request_deadlines.get(&destination),
        Some(&1026.0)
    );

    let mut rng = rns_crypto::FixedRng::new(&[0x20; 32]);
    engine.tick(1016.0, &mut rng);
    assert!(engine.discovery_path_requests.contains_key(&destination));
    engine.tick(1027.0, &mut rng);
    assert!(!engine.discovery_path_requests.contains_key(&destination));
    assert!(!engine
        .discovery_path_request_deadlines
        .contains_key(&destination));
}

#[test]
fn discovery_path_request_timeout_defaults_and_clamps_safely() {
    let mut interfaces = BTreeMap::new();
    assert_eq!(
        super::path_requests::discovery_path_request_timeout(&interfaces),
        constants::PATH_REQUEST_TIMEOUT
    );

    let mut fast = make_interface(1, constants::MODE_FULL);
    fast.bitrate = Some(1_000);
    interfaces.insert(fast.id, fast);
    assert_eq!(
        super::path_requests::discovery_path_request_timeout(&interfaces),
        constants::PATH_REQUEST_TIMEOUT
    );

    let mut zero = make_interface(2, constants::MODE_FULL);
    zero.bitrate = Some(0);
    interfaces.insert(zero.id, zero);
    assert_eq!(
        super::path_requests::discovery_path_request_timeout(&interfaces),
        constants::PATH_REQUEST_TIMEOUT
    );

    let mut below_minimum = make_interface(3, constants::MODE_FULL);
    below_minimum.bitrate = Some(1);
    interfaces.insert(below_minimum.id, below_minimum);
    assert_eq!(
        super::path_requests::discovery_path_request_timeout(&interfaces),
        1606.0
    );
}

#[test]
fn discovery_path_request_without_bitrate_uses_fixed_deadline() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let destination = [0xd1; 16];
    let data = make_path_request_data(&destination, &[0x11; 16]);
    assert_eq!(
        engine
            .handle_path_request(&data, InterfaceId(1), 2000.0)
            .len(),
        1
    );
    assert_eq!(
        engine.discovery_path_request_deadlines.get(&destination),
        Some(&2015.0)
    );
}

#[test]
fn test_path_request_ingress_burst_suppresses_recursive_discovery() {
    let mut engine = TransportEngine::new(make_config(true));
    let mut ingress = make_interface(1, constants::MODE_ACCESS_POINT);
    ingress.ingress_control.enabled = true;
    ingress.ip_freq = constants::IC_PR_BURST_FREQ + 1.0;
    engine.register_interface(ingress);
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let dest = [0xE1; 16];
    let tag = [0x11; 16];
    let data = make_path_request_data(&dest, &tag);

    let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

    assert!(actions.is_empty());
    assert!(!engine.discovery_path_requests.contains_key(&dest));
}

#[test]
fn test_path_request_egress_limit_skips_only_limited_interface() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));

    let mut limited = make_interface(2, constants::MODE_FULL);
    limited.ingress_control.egress_enabled = true;
    limited.op_freq = constants::EC_PR_FREQ + 1.0;
    limited.op_samples = constants::IC_BURST_MIN_SAMPLES;
    engine.register_interface(limited);

    let mut allowed = make_interface(3, constants::MODE_FULL);
    allowed.ingress_control.egress_enabled = true;
    allowed.op_freq = constants::EC_PR_FREQ - 1.0;
    allowed.op_samples = constants::IC_BURST_MIN_SAMPLES;
    engine.register_interface(allowed);

    let dest = [0xE2; 16];
    let tag = [0x12; 16];
    let data = make_path_request_data(&dest, &tag);

    let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

    assert_eq!(actions.len(), 1);
    match &actions[0] {
        TransportAction::SendOnInterface { interface, .. } => {
            assert_eq!(*interface, InterfaceId(3))
        }
        _ => panic!("expected SendOnInterface for the unlimited egress interface"),
    }
    assert!(engine.discovery_path_requests.contains_key(&dest));
}

#[test]
fn test_recursive_path_request_skips_interface_with_queued_announces() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));
    let mut blocked = make_interface(2, constants::MODE_FULL);
    blocked.bitrate = Some(1_000);
    engine.register_interface(blocked);
    engine.register_interface(make_interface(3, constants::MODE_FULL));

    let _ = engine.announce_queues.gate_announce(
        InterfaceId(2),
        vec![0xAA; 100].into(),
        [0xA0; 16],
        1,
        900.0,
        900.0,
        Some(1_000),
        None,
        constants::ANNOUNCE_CAP,
    );
    let _ = engine.announce_queues.gate_announce(
        InterfaceId(2),
        vec![0xBB; 100].into(),
        [0xB0; 16],
        1,
        901.0,
        901.0,
        Some(1_000),
        None,
        constants::ANNOUNCE_CAP,
    );

    let dest = [0xE3; 16];
    let tag = [0x13; 16];
    let data = make_path_request_data(&dest, &tag);
    let actions = engine.handle_path_request(&data, InterfaceId(1), 902.0);

    assert_eq!(actions.len(), 1);
    match &actions[0] {
        TransportAction::SendOnInterface { interface, .. } => {
            assert_eq!(*interface, InterfaceId(3));
        }
        _ => panic!("expected SendOnInterface for the unqueued egress interface"),
    }
    assert!(engine.discovery_path_requests.contains_key(&dest));
}

#[test]
fn test_recursive_path_request_skips_interface_with_active_announce_cap() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));
    let mut blocked = make_interface(2, constants::MODE_FULL);
    blocked.bitrate = Some(1_000);
    engine.register_interface(blocked);

    let _ = engine.announce_queues.gate_announce(
        InterfaceId(2),
        vec![0xAA; 100].into(),
        [0xA0; 16],
        1,
        900.0,
        900.0,
        Some(1_000),
        None,
        constants::ANNOUNCE_CAP,
    );

    let dest = [0xE4; 16];
    let tag = [0x14; 16];
    let data = make_path_request_data(&dest, &tag);
    let actions = engine.handle_path_request(&data, InterfaceId(1), 901.0);

    assert!(actions.is_empty());
    assert!(!engine.discovery_path_requests.contains_key(&dest));
}

#[test]
fn test_recursive_path_request_reserves_announce_cap_on_sent_interface() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));
    let mut egress = make_interface(2, constants::MODE_FULL);
    egress.bitrate = Some(1_000);
    engine.register_interface(egress);

    let dest = [0xE5; 16];
    let tag = [0x15; 16];
    let data = make_path_request_data(&dest, &tag);
    let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

    assert_eq!(actions.len(), 1);
    let queue = engine
        .announce_queues
        .queue_for(&InterfaceId(2))
        .expect("sent recursive PR should create announce-cap state");
    assert!(
        queue.announce_allowed_at > 1000.0,
        "recursive PR should reserve announce-cap airtime"
    );
    assert!(queue.entries.is_empty());
}

#[test]
fn test_discovery_pr_tags_fifo_eviction() {
    let mut config = make_config(true);
    config.max_discovery_pr_tags = 2;
    let mut engine = TransportEngine::new(config);

    let dest1 = [0xA1; 16];
    let dest2 = [0xA2; 16];
    let dest3 = [0xA3; 16];
    let tag1 = [0x01; 16];
    let tag2 = [0x02; 16];
    let tag3 = [0x03; 16];

    engine.handle_path_request(
        &make_path_request_data(&dest1, &tag1),
        InterfaceId(1),
        1000.0,
    );
    engine.handle_path_request(
        &make_path_request_data(&dest2, &tag2),
        InterfaceId(1),
        1001.0,
    );
    assert_eq!(engine.discovery_pr_tags_count(), 2);

    let unique1 = make_unique_tag(dest1, &tag1);
    let unique2 = make_unique_tag(dest2, &tag2);
    let unique3 = make_unique_tag(dest3, &tag3);
    assert!(engine.has_discovery_pr_tag(&unique1));
    assert!(engine.has_discovery_pr_tag(&unique2));

    engine.handle_path_request(
        &make_path_request_data(&dest1, &tag1),
        InterfaceId(1),
        1001.5,
    );
    assert_eq!(engine.discovery_pr_tags_count(), 2);

    engine.handle_path_request(
        &make_path_request_data(&dest3, &tag3),
        InterfaceId(1),
        1002.0,
    );
    assert_eq!(engine.discovery_pr_tags_count(), 2);
    assert!(!engine.has_discovery_pr_tag(&unique1));
    assert!(engine.has_discovery_pr_tag(&unique2));
    assert!(engine.has_discovery_pr_tag(&unique3));

    engine.handle_path_request(
        &make_path_request_data(&dest1, &tag1),
        InterfaceId(1),
        1003.0,
    );
    assert_eq!(engine.discovery_pr_tags_count(), 2);
    assert!(engine.has_discovery_pr_tag(&unique1));
    assert!(!engine.has_discovery_pr_tag(&unique2));
    assert!(engine.has_discovery_pr_tag(&unique3));
}

#[test]
fn test_path_destination_cap_evicts_oldest_and_clears_state() {
    let mut config = make_config(false);
    config.max_path_destinations = 2;
    let mut engine = TransportEngine::new(config);
    engine.register_interface(make_interface(1, constants::MODE_FULL));

    let dest1 = [0xB1; 16];
    let dest2 = [0xB2; 16];
    let dest3 = [0xB3; 16];

    engine.upsert_path_destination(
        dest1,
        make_path_entry(1000.0, 1, InterfaceId(1), [0x11; 16]),
        1000.0,
    );
    engine.upsert_path_destination(
        dest2,
        make_path_entry(1001.0, 1, InterfaceId(1), [0x22; 16]),
        1001.0,
    );
    engine
        .path_states
        .insert(dest1, constants::STATE_UNRESPONSIVE);

    engine.upsert_path_destination(
        dest3,
        make_path_entry(1002.0, 1, InterfaceId(1), [0x33; 16]),
        1002.0,
    );

    assert_eq!(engine.path_table_count(), 2);
    assert!(!engine.has_path(&dest1));
    assert!(engine.has_path(&dest2));
    assert!(engine.has_path(&dest3));
    assert!(!engine.path_states.contains_key(&dest1));
    assert_eq!(engine.path_destination_cap_evict_count(), 1);
}

#[test]
fn test_existing_path_destination_update_does_not_trigger_cap_eviction() {
    let mut config = make_config(false);
    config.max_path_destinations = 2;
    config.max_paths_per_destination = 2;
    let mut engine = TransportEngine::new(config);
    engine.register_interface(make_interface(1, constants::MODE_FULL));

    let dest1 = [0xC1; 16];
    let dest2 = [0xC2; 16];

    engine.upsert_path_destination(
        dest1,
        make_path_entry(1000.0, 2, InterfaceId(1), [0x11; 16]),
        1000.0,
    );
    engine.upsert_path_destination(
        dest2,
        make_path_entry(1001.0, 2, InterfaceId(1), [0x22; 16]),
        1001.0,
    );

    engine.upsert_path_destination(
        dest2,
        make_path_entry(1002.0, 1, InterfaceId(1), [0x23; 16]),
        1002.0,
    );

    assert_eq!(engine.path_table_count(), 2);
    assert!(engine.has_path(&dest1));
    assert!(engine.has_path(&dest2));
}

#[test]
fn test_redirect_path_replaces_stale_transport_next_hop() {
    let mut engine = TransportEngine::new(make_config(true));
    let original_interface = InterfaceId(1);
    let direct_interface = InterfaceId(2);
    engine.register_interface(make_interface(original_interface.0, constants::MODE_FULL));
    engine.register_interface(make_interface(direct_interface.0, constants::MODE_FULL));

    let link_id = [0xD1; 16];
    let facilitator = [0xFA; 16];
    engine.inject_path(
        link_id,
        make_path_entry(1000.0, 2, original_interface, facilitator),
    );

    engine.redirect_path(&link_id, direct_interface, 1001.0);

    let path = engine.path_table[&link_id].primary().unwrap();
    assert_eq!(path.receiving_interface, direct_interface);
    assert_eq!(path.next_hop, link_id);
    assert_eq!(path.hops, 1);
    assert_eq!(path.timestamp, 1001.0);
    assert_eq!(path.expires, 4601.0);

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_LINK,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet = RawPacket::pack(
        flags,
        0,
        &link_id,
        None,
        constants::CONTEXT_CHANNEL,
        b"direct payload",
    )
    .unwrap();

    let actions = engine.handle_outbound(
        &packet,
        constants::DESTINATION_LINK,
        Some(direct_interface),
        1002.0,
    );
    assert_eq!(actions.len(), 1);
    match &actions[0] {
        TransportAction::SendOnInterface { interface, raw } => {
            assert_eq!(*interface, direct_interface);
            assert_eq!(&**raw, packet.raw.as_slice());
            assert_eq!(raw[0] >> 6, constants::HEADER_1);
        }
        other => panic!("expected direct interface send, got {other:?}"),
    }
}

#[test]
fn test_redirect_path_creates_direct_next_hop() {
    let mut engine = TransportEngine::new(make_config(true));
    let link_id = [0xD2; 16];
    let direct_interface = InterfaceId(7);

    engine.redirect_path(&link_id, direct_interface, 2000.0);

    let path = engine.path_table[&link_id].primary().unwrap();
    assert_eq!(path.receiving_interface, direct_interface);
    assert_eq!(path.next_hop, link_id);
    assert_eq!(path.hops, 1);
}

#[test]
fn test_roaming_loop_prevention() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_ROAMING));

    let dest = [0xD3; 16];
    // Path is known and routes through the same interface (1)
    engine.path_table.insert(
        dest,
        PathSet::from_single(
            PathEntry {
                timestamp: 900.0,
                next_hop: [0xAA; 16],
                hops: 2,
                expires: 9999.0,
                random_blobs: Vec::new(),
                receiving_interface: InterfaceId(1),
                packet_hash: [0; 32],
                announce_raw: None,
            },
            1,
        ),
    );

    let tag = [0x03; 16];
    let data = make_path_request_data(&dest, &tag);

    let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

    // ROAMING interface, path next-hop on same interface → loop prevention, no action
    assert!(actions.is_empty());
    assert!(!engine.announce_table.contains_key(&dest));
}

/// Build a minimal HEADER_1 announce raw packet for testing.
fn make_announce_raw(dest_hash: &[u8; 16], payload: &[u8]) -> Vec<u8> {
    // HEADER_1: [flags:1][hops:1][dest:16][context:1][data:*]
    // flags: HEADER_1(0) << 6 | context_flag(0) << 5 | TRANSPORT_BROADCAST(0) << 4 | SINGLE(0) << 2 | ANNOUNCE(1)
    let flags: u8 = 0x01; // HEADER_1, no context, broadcast, single, announce
    let mut raw = Vec::new();
    raw.push(flags);
    raw.push(0x02); // hops
    raw.extend_from_slice(dest_hash);
    raw.push(constants::CONTEXT_NONE);
    raw.extend_from_slice(payload);
    raw
}

#[test]
fn test_path_request_populates_announce_entry_from_raw() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let dest = [0xD5; 16];
    let payload = vec![0xAB; 32]; // simulated announce data (pubkey, sig, etc.)
    let announce_raw = make_announce_raw(&dest, &payload);

    engine.path_table.insert(
        dest,
        PathSet::from_single(
            PathEntry {
                timestamp: 900.0,
                next_hop: [0xBB; 16],
                hops: 2,
                expires: 9999.0,
                random_blobs: Vec::new(),
                receiving_interface: InterfaceId(2),
                packet_hash: [0; 32],
                announce_raw: Some(announce_raw.clone()),
            },
            1,
        ),
    );

    let tag = [0x05; 16];
    let data = make_path_request_data(&dest, &tag);
    let _actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

    // The announce table should now have an entry with populated packet_raw/packet_data
    let entry = engine
        .announce_table
        .get(&dest)
        .expect("announce entry must exist");
    assert_eq!(entry.packet_raw, announce_raw);
    assert_eq!(entry.packet_data, payload);
    assert!(entry.block_rebroadcasts);
}

#[test]
fn test_path_request_discovers_when_known_path_has_no_announce_raw() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let dest = [0xD6; 16];

    engine.path_table.insert(
        dest,
        PathSet::from_single(
            PathEntry {
                timestamp: 900.0,
                next_hop: [0xCC; 16],
                hops: 1,
                expires: 9999.0,
                random_blobs: Vec::new(),
                receiving_interface: InterfaceId(2),
                packet_hash: [0; 32],
                announce_raw: None, // no raw data available
            },
            1,
        ),
    );

    let tag = [0x06; 16];
    let data = make_path_request_data(&dest, &tag);
    let actions = engine.handle_path_request(&data, InterfaceId(1), 1000.0);

    assert!(!engine.announce_table.contains_key(&dest));
    assert_eq!(actions.len(), 1);
    match &actions[0] {
        TransportAction::SendOnInterface { interface, raw } => {
            assert_eq!(*interface, InterfaceId(2));
            assert_recursive_path_request_packet(raw.as_ref(), &dest, &tag);
        }
        _ => panic!("expected SendOnInterface for recursive path request"),
    }
    assert!(engine.discovery_path_requests.contains_key(&dest));
}

#[test]
fn test_discovery_request_consumed_on_announce() {
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_ACCESS_POINT));

    let dest = [0xD4; 16];

    // Simulate a waiting discovery request
    engine.discovery_path_requests.insert(
        dest,
        DiscoveryPathRequest {
            timestamp: 900.0,
            requesting_interface: InterfaceId(1),
        },
    );

    // Consume it
    let iface = engine.discovery_path_requests_waiting(&dest);
    assert_eq!(iface, Some(InterfaceId(1)));

    // Should be gone now
    assert!(!engine.discovery_path_requests.contains_key(&dest));
    assert_eq!(engine.discovery_path_requests_waiting(&dest), None);
}

#[test]
fn test_pending_path_request_announce_bypasses_ingress_control() {
    let mut engine = TransportEngine::new(make_config(true));
    let mut inbound = make_interface(1, constants::MODE_FULL);
    inbound.ingress_control = crate::transport::types::IngressControlConfig::enabled();
    inbound.ia_freq = 10_000.0;
    inbound.started = 0.0;
    engine.register_interface(inbound);
    engine.register_interface(make_interface(2, constants::MODE_ACCESS_POINT));

    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x99; 32]));
    let dest_hash =
        crate::destination::destination_hash("ingress", &["path-request"], Some(identity.hash()));
    let name_hash = crate::destination::name_hash("ingress", &["path-request"]);
    let announce_raw = build_announce_for_issue4(&dest_hash, &name_hash);

    engine.discovery_path_requests.insert(
        dest_hash,
        DiscoveryPathRequest {
            timestamp: 999.0,
            requesting_interface: InterfaceId(2),
        },
    );

    let mut rng = rns_crypto::FixedRng::new(&[0x88; 32]);
    let actions = engine.handle_inbound(
        InboundFrame {
            raw: &announce_raw,
            iface: InterfaceId(1),
            now: 1000.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
    );

    assert_eq!(engine.held_announce_count(&InterfaceId(1)), 0);
    assert!(engine.has_path(&dest_hash));
    assert!(!engine.discovery_path_requests.contains_key(&dest_hash));
    assert!(actions.iter().any(|a| {
        matches!(
            a,
            TransportAction::AnnounceReceived {
                destination_hash,
                receiving_interface: InterfaceId(1),
                ..
            } if *destination_hash == dest_hash
        )
    }));

    let entry = engine
        .announce_table
        .get(&dest_hash)
        .expect("path response announce should be queued");
    assert!(entry.block_rebroadcasts);
    assert_eq!(entry.attached_interface, Some(InterfaceId(2)));
}

// =========================================================================
// Issue #4: Shared instance client 1-hop transport injection
// =========================================================================

/// Helper: build a valid announce packet for use in issue #4 tests.
fn build_announce_for_issue4(dest_hash: &[u8; 16], name_hash: &[u8; 10]) -> Vec<u8> {
    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x99; 32]));
    let random_hash = [0x42u8; 10];
    let (announce_data, _) = crate::announce::AnnounceData::pack(
        &identity,
        dest_hash,
        name_hash,
        &random_hash,
        None,
        None,
    )
    .unwrap();
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
    };
    RawPacket::pack(
        flags,
        0,
        dest_hash,
        None,
        constants::CONTEXT_NONE,
        &announce_data,
    )
    .unwrap()
    .raw
}

#[test]
fn test_ingress_held_announce_preserves_rx_metadata_on_release() {
    let mut engine = TransportEngine::new(make_config(true));
    let mut inbound = make_interface(1, constants::MODE_FULL);
    inbound.ingress_control = crate::transport::types::IngressControlConfig::enabled();
    inbound.ia_freq = constants::IC_BURST_FREQ + 1.0;
    inbound.started = 0.0;
    engine.register_interface(inbound);

    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x99; 32]));
    let dest_hash = crate::destination::destination_hash("ingress", &["rx"], Some(identity.hash()));
    let name_hash = crate::destination::name_hash("ingress", &["rx"]);
    let announce_raw = build_announce_for_issue4(&dest_hash, &name_hash);
    let rx = RxMetadata {
        rssi: Some(-91),
        snr: Some(5.5),
    };

    let mut rng = rns_crypto::FixedRng::new(&[0x88; 32]);
    let held_actions = engine.handle_inbound(
        InboundFrame::new(&announce_raw, InterfaceId(1), 10000.0).with_rx(rx),
        &mut rng,
    );

    assert!(held_actions.is_empty());
    assert_eq!(engine.held_announce_count(&InterfaceId(1)), 1);
    assert!(!engine.has_path(&dest_hash));

    engine
        .interfaces
        .get_mut(&InterfaceId(1))
        .expect("interface must exist")
        .ia_freq = 0.0;

    let released_actions = engine.tick(10000.0 + constants::IC_BURST_PENALTY + 1.0, &mut rng);

    let released_rx = released_actions.iter().find_map(|action| match action {
        TransportAction::AnnounceReceived {
            destination_hash,
            rx: action_rx,
            ..
        } if *destination_hash == dest_hash => Some(*action_rx),
        _ => None,
    });

    assert_eq!(released_rx, Some(rx));
    assert_eq!(engine.held_announce_count(&InterfaceId(1)), 0);
    assert!(engine.has_path(&dest_hash));
}

#[test]
fn test_issue4_local_client_single_data_to_1hop_rewrites_on_outbound() {
    // Shared clients learn remote paths via their local shared-instance
    // interface and must inject transport headers on outbound when the
    // destination is exactly 1 hop away behind the daemon.

    let mut engine = TransportEngine::new(make_config(false));
    engine.register_interface(make_local_client_interface(1));

    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x99; 32]));
    let dest_hash =
        crate::destination::destination_hash("issue4", &["test"], Some(identity.hash()));
    let name_hash = crate::destination::name_hash("issue4", &["test"]);
    let announce_raw = build_announce_for_issue4(&dest_hash, &name_hash);

    // Model the announce as already forwarded by the shared daemon to
    // the local client. The raw hop count is 1 so that after the local
    // client hop compensation the learned path remains 1 hop away.
    let mut announce_packet = RawPacket::unpack(&announce_raw).unwrap();
    announce_packet.raw[1] = 1;
    let mut rng = rns_crypto::FixedRng::new(&[0; 32]);
    engine.handle_inbound(
        InboundFrame {
            raw: &announce_packet.raw,
            iface: InterfaceId(1),
            now: 1000.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
    );
    assert!(engine.has_path(&dest_hash));
    assert_eq!(engine.hops_to(&dest_hash), Some(1));

    // Build DATA from the shared client to the 1-hop destination.
    let data_flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let data_packet = RawPacket::pack(
        data_flags,
        0,
        &dest_hash,
        None,
        constants::CONTEXT_NONE,
        b"hello",
    )
    .unwrap();

    let actions = engine.handle_outbound(&data_packet, constants::DESTINATION_SINGLE, None, 1001.0);

    let send = actions.iter().find_map(|a| match a {
        TransportAction::SendOnInterface { interface, raw } => Some((interface, raw)),
        _ => None,
    });
    let (interface, raw) = send.expect("shared client should emit a transport-injected packet");
    assert_eq!(*interface, InterfaceId(1));
    let flags = PacketFlags::unpack(raw[0]);
    assert_eq!(flags.header_type, constants::HEADER_2);
    assert_eq!(flags.transport_type, constants::TRANSPORT_TRANSPORT);
}

#[test]
fn test_local_client_forward_to_external_applies_local_hops_delta() {
    let daemon_id = [0x42; 16];
    let mut config = make_config(true);
    config.local_hops_delta = 5;
    let mut engine = TransportEngine::new(config);
    engine.register_interface(make_local_client_interface(1));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let dest_hash = [0xB7; 16];
    engine.upsert_path_destination(
        dest_hash,
        make_path_entry(1000.0, 1, InterfaceId(2), dest_hash),
        1000.0,
    );

    let flags = PacketFlags {
        header_type: constants::HEADER_2,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_TRANSPORT,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet = RawPacket::pack(
        flags,
        0,
        &dest_hash,
        Some(&daemon_id),
        constants::CONTEXT_NONE,
        b"from local client",
    )
    .unwrap();

    let mut rng = rns_crypto::FixedRng::new(&[0x44; 32]);
    let actions = engine.handle_inbound(
        InboundFrame::new(&packet.raw, InterfaceId(1), 1001.0),
        &mut rng,
    );

    let raw = actions.iter().find_map(|action| match action {
        TransportAction::SendOnInterface { interface, raw } if *interface == InterfaceId(2) => {
            Some(raw)
        }
        _ => None,
    });
    let raw = raw.expect("local-client DATA should be forwarded externally");
    assert_eq!(raw[1], 5);
    let forwarded_flags = PacketFlags::unpack(raw[0]);
    assert_eq!(forwarded_flags.header_type, constants::HEADER_1);
    assert_eq!(&raw[2..18], &dest_hash);
}

#[test]
fn transported_link_proof_timeout_uses_outbound_interface_bitrate() {
    let mut engine = TransportEngine::new(make_config(true));
    let mut inbound = make_interface(1, constants::MODE_FULL);
    inbound.bitrate = Some(4_000);
    let mut outbound = make_interface(2, constants::MODE_FULL);
    outbound.bitrate = Some(400);
    engine.register_interface(inbound);
    engine.register_interface(outbound);

    let destination_hash = [0xb8; 16];
    engine.inject_path(
        destination_hash,
        PathEntry {
            timestamp: 900.0,
            next_hop: [0x29; 16],
            hops: 2,
            expires: 2000.0,
            random_blobs: Vec::new(),
            receiving_interface: InterfaceId(2),
            packet_hash: [0x39; 32],
            announce_raw: None,
        },
    );
    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_2,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_TRANSPORT,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_LINKREQUEST,
        },
        0,
        &destination_hash,
        Some(&[0x42; 16]),
        constants::CONTEXT_NONE,
        &[0x49; 64],
    )
    .unwrap();

    let mut rng = rns_crypto::FixedRng::new(&[0x59; 32]);
    engine.handle_inbound(
        InboundFrame::new(&packet.raw, InterfaceId(1), 1000.0),
        &mut rng,
    );

    let entry = engine
        .link_table
        .values()
        .next()
        .expect("transported link request should create tracking state");
    assert_eq!(entry.next_hop_interface, InterfaceId(2));
    assert_eq!(entry.received_interface, InterfaceId(1));
    assert_eq!(entry.proof_timeout, 1022.0);
}

#[test]
fn extra_link_proof_timeout_requires_positive_interface_bitrate() {
    let mut interface = make_interface(1, constants::MODE_FULL);
    assert_eq!(super::inbound_engine::extra_link_proof_timeout(None), 0.0);
    assert_eq!(
        super::inbound_engine::extra_link_proof_timeout(Some(&interface)),
        0.0
    );

    interface.bitrate = Some(0);
    assert_eq!(
        super::inbound_engine::extra_link_proof_timeout(Some(&interface)),
        0.0
    );

    interface.bitrate = Some(400);
    assert_eq!(
        super::inbound_engine::extra_link_proof_timeout(Some(&interface)),
        10.0
    );
}

#[test]
fn test_local_client_link_routing_to_external_applies_local_hops_delta() {
    let mut config = make_config(true);
    config.local_hops_delta = 5;
    let mut engine = TransportEngine::new(config);
    engine.register_interface(make_local_client_interface(1));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let link_id = [0x4C; 16];
    engine.register_link(
        link_id,
        LinkEntry {
            timestamp: 1000.0,
            next_hop_transport_id: [0xAA; 16],
            next_hop_interface: InterfaceId(2),
            remaining_hops: 3,
            received_interface: InterfaceId(1),
            taken_hops: 0,
            destination_hash: [0xBB; 16],
            validated: true,
            proof_timeout: 1100.0,
        },
    );

    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        },
        0,
        &link_id,
        None,
        constants::CONTEXT_CHANNEL,
        b"link data",
    )
    .unwrap();

    let mut rng = rns_crypto::FixedRng::new(&[0x45; 32]);
    let actions = engine.handle_inbound(
        InboundFrame::new(&packet.raw, InterfaceId(1), 1001.0),
        &mut rng,
    );

    let raw = actions.iter().find_map(|action| match action {
        TransportAction::SendOnInterface { interface, raw } if *interface == InterfaceId(2) => {
            Some(raw)
        }
        _ => None,
    });
    let raw = raw.expect("local-client link packet should be forwarded externally");
    assert_eq!(raw[1], 5);
}

#[test]
fn test_instance_local_link_routing_preserves_hops() {
    let mut config = make_config(true);
    config.local_hops_delta = 5;
    let mut engine = TransportEngine::new(config);
    engine.register_interface(make_local_client_interface(1));
    engine.register_interface(make_local_client_interface(2));

    let link_id = [0x4D; 16];
    engine.register_link(
        link_id,
        LinkEntry {
            timestamp: 1000.0,
            next_hop_transport_id: [0xAA; 16],
            next_hop_interface: InterfaceId(2),
            remaining_hops: 0,
            received_interface: InterfaceId(1),
            taken_hops: 0,
            destination_hash: [0xBB; 16],
            validated: true,
            proof_timeout: 1100.0,
        },
    );

    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        },
        0,
        &link_id,
        None,
        constants::CONTEXT_CHANNEL,
        b"local link data",
    )
    .unwrap();

    let mut rng = rns_crypto::FixedRng::new(&[0x46; 32]);
    let actions = engine.handle_inbound(
        InboundFrame::new(&packet.raw, InterfaceId(1), 1001.0),
        &mut rng,
    );

    let raw = actions.iter().find_map(|action| match action {
        TransportAction::SendOnInterface { interface, raw } if *interface == InterfaceId(2) => {
            Some(raw)
        }
        _ => None,
    });
    let raw = raw.expect("instance-local link packet should be forwarded");
    assert_eq!(raw[1], 0);
}

#[test]
fn test_local_client_proof_to_external_applies_local_hops_delta() {
    let mut config = make_config(true);
    config.local_hops_delta = 5;
    let mut engine = TransportEngine::new(config);
    engine.register_interface(make_local_client_interface(1));
    engine.register_interface(make_interface(2, constants::MODE_FULL));

    let proof_dest = [0xA5; 16];
    engine.reverse_table.insert(
        proof_dest,
        tables::ReverseEntry {
            receiving_interface: InterfaceId(2),
            outbound_interface: InterfaceId(1),
            timestamp: 1000.0,
        },
    );

    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_PROOF,
        },
        0,
        &proof_dest,
        None,
        constants::CONTEXT_NONE,
        &[0xCC; 32],
    )
    .unwrap();

    let mut rng = rns_crypto::FixedRng::new(&[0x47; 32]);
    let actions = engine.handle_inbound(
        InboundFrame::new(&packet.raw, InterfaceId(1), 1001.0),
        &mut rng,
    );

    let raw = actions.iter().find_map(|action| match action {
        TransportAction::SendOnInterface { interface, raw } if *interface == InterfaceId(2) => {
            Some(raw)
        }
        _ => None,
    });
    let raw = raw.expect("local-client proof should be forwarded externally");
    assert_eq!(raw[1], 5);
}

#[test]
fn test_proof_for_local_client_preserves_hops() {
    let mut config = make_config(true);
    config.local_hops_delta = 5;
    let mut engine = TransportEngine::new(config);
    engine.register_interface(make_local_client_interface(1));
    engine.register_interface(make_local_client_interface(2));

    let proof_dest = [0xA6; 16];
    engine.reverse_table.insert(
        proof_dest,
        tables::ReverseEntry {
            receiving_interface: InterfaceId(2),
            outbound_interface: InterfaceId(1),
            timestamp: 1000.0,
        },
    );

    let packet = RawPacket::pack(
        PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_PROOF,
        },
        0,
        &proof_dest,
        None,
        constants::CONTEXT_NONE,
        &[0xCD; 32],
    )
    .unwrap();

    let mut rng = rns_crypto::FixedRng::new(&[0x48; 32]);
    let actions = engine.handle_inbound(
        InboundFrame::new(&packet.raw, InterfaceId(1), 1001.0),
        &mut rng,
    );

    let raw = actions.iter().find_map(|action| match action {
        TransportAction::SendOnInterface { interface, raw } if *interface == InterfaceId(2) => {
            Some(raw)
        }
        _ => None,
    });
    let raw = raw.expect("proof for local client should be forwarded");
    assert_eq!(raw[1], 0);
}

#[test]
fn test_issue4_external_data_to_shared_client_strips_transport_header() {
    let daemon_id = [0x42; 16];
    let mut engine = TransportEngine::new(make_config(true));
    engine.register_interface(make_interface(1, constants::MODE_FULL));
    engine.register_interface(make_local_client_interface(2));

    let dest_hash = [0x99; 16];
    engine.upsert_path_destination(
        dest_hash,
        make_path_entry(1000.0, 1, InterfaceId(2), daemon_id),
        1000.0,
    );

    let h2_flags = PacketFlags {
        header_type: constants::HEADER_2,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_TRANSPORT,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let mut h2_raw = Vec::new();
    h2_raw.push(h2_flags.pack());
    h2_raw.push(0);
    h2_raw.extend_from_slice(&daemon_id);
    h2_raw.extend_from_slice(&dest_hash);
    h2_raw.push(constants::CONTEXT_NONE);
    h2_raw.extend_from_slice(b"hello shared client");

    let mut rng = rns_crypto::FixedRng::new(&[0x22; 32]);
    let actions = engine.handle_inbound(
        InboundFrame {
            raw: &h2_raw,
            iface: InterfaceId(1),
            now: 1001.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
    );

    let raw = actions.iter().find_map(|a| match a {
        TransportAction::SendOnInterface { interface, raw } if *interface == InterfaceId(2) => {
            Some(raw)
        }
        _ => None,
    });
    let raw = raw.expect("daemon should forward external DATA to shared client");
    let flags = PacketFlags::unpack(raw[0]);
    assert_eq!(flags.header_type, constants::HEADER_1);
    assert_eq!(flags.transport_type, constants::TRANSPORT_BROADCAST);
    assert_eq!(&raw[2..18], &dest_hash);
    assert_eq!(&raw[19..], b"hello shared client");
}

#[test]
fn test_issue4_external_data_to_1hop_via_transport_works() {
    // Control test: when a DATA packet arrives from an external interface
    // with HEADER_2 and the daemon's transport_id, the daemon correctly
    // forwards it via step 5.  This proves the multi-hop path works;
    // it's only the 1-hop shared-client case that's broken.

    let daemon_id = [0x42; 16];
    let mut engine = TransportEngine::new(TransportConfig {
        transport_enabled: true,
        identity_hash: Some(daemon_id),
        local_hops_delta: 0,
        prefer_shorter_path: false,
        max_paths_per_destination: 1,
        packet_hashlist_max_entries: constants::HASHLIST_MAXSIZE,
        packet_hashlist_allocation: crate::transport::types::PacketHashlistAllocation::Eager,
        max_discovery_pr_tags: constants::MAX_PR_TAGS,
        max_path_destinations: usize::MAX,
        max_tunnel_destinations_total: usize::MAX,
        destination_timeout_secs: constants::DESTINATION_TIMEOUT,
        announce_table_ttl_secs: constants::ANNOUNCE_TABLE_TTL,
        announce_table_max_bytes: constants::ANNOUNCE_TABLE_MAX_BYTES,
        announce_sig_cache_enabled: true,
        announce_sig_cache_max_entries: constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
        announce_sig_cache_ttl_secs: constants::ANNOUNCE_SIG_CACHE_TTL,
        announce_queue_max_entries: 256,
        announce_queue_max_interfaces: 1024,
    });
    engine.register_interface(make_interface(1, constants::MODE_FULL)); // inbound
    engine.register_interface(make_interface(2, constants::MODE_FULL)); // outbound to Bob

    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::FixedRng::new(&[0x99; 32]));
    let dest_hash =
        crate::destination::destination_hash("issue4", &["ctrl"], Some(identity.hash()));
    let name_hash = crate::destination::name_hash("issue4", &["ctrl"]);
    let announce_raw = build_announce_for_issue4(&dest_hash, &name_hash);

    // Feed announce from interface 2 (Bob's side), hops=0 → stored as hops=1
    let mut rng = rns_crypto::FixedRng::new(&[0; 32]);
    engine.handle_inbound(
        InboundFrame {
            raw: &announce_raw,
            iface: InterfaceId(2),
            now: 1000.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng,
    );
    assert_eq!(engine.hops_to(&dest_hash), Some(1));

    // Now send a HEADER_2 transport packet addressed to the daemon
    // (simulating what Alice would send in a multi-hop scenario)
    let h2_flags = PacketFlags {
        header_type: constants::HEADER_2,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_TRANSPORT,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    // Build HEADER_2 manually: [flags, hops, transport_id(16), dest_hash(16), context, data...]
    let mut h2_raw = Vec::new();
    h2_raw.push(h2_flags.pack());
    h2_raw.push(0); // hops
    h2_raw.extend_from_slice(&daemon_id); // transport_id = daemon
    h2_raw.extend_from_slice(&dest_hash);
    h2_raw.push(constants::CONTEXT_NONE);
    h2_raw.extend_from_slice(b"hello via transport");

    let mut rng2 = rns_crypto::FixedRng::new(&[0x22; 32]);
    let actions = engine.handle_inbound(
        InboundFrame {
            raw: &h2_raw,
            iface: InterfaceId(1),
            now: 1001.0,
            rx: RxMetadata {
                rssi: None,
                snr: None,
            },
        },
        &mut rng2,
    );

    // This SHOULD forward via step 5 (transport forwarding)
    let has_send = actions.iter().any(|a| {
        matches!(
            a,
            TransportAction::SendOnInterface { interface, .. } if *interface == InterfaceId(2)
        )
    });
    assert!(
        has_send,
        "HEADER_2 transport packet should be forwarded (control test)"
    );
}
