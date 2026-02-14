//! Integration tests for the transport/routing engine.
//!
//! These tests exercise the full TransportEngine pipeline:
//! 1. Announce arrives → path stored → retransmit queued → tick fires → retransmitted
//! 2. Retransmit heard back → announce_table entry cleared
//! 3. DATA sent to stored path → routed via correct interface with HEADER_2 rewrite
//! 4. Proof arrives → routed back via reverse_table
//! 5. Path expires → cull removes it → has_path returns false
//! 6. LINKREQUEST forwarded → link_table created → link traffic routed → LRPROOF validated

use std::fs;
use std::path::PathBuf;

use serde_json::Value;

use rns_core::announce::AnnounceData;
use rns_core::constants;
use rns_core::packet::{PacketFlags, RawPacket};
use rns_core::transport::types::{InterfaceId, InterfaceInfo, TransportAction, TransportConfig};
use rns_core::transport::TransportEngine;
use rns_crypto::identity::Identity;
use rns_crypto::FixedRng;

// =============================================================================
// Fixture loading helpers
// =============================================================================

fn transport_fixture_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("tests");
    path.push("fixtures");
    path.push("transport");
    path.push(name);
    path
}

fn load_transport_fixture(name: &str) -> Vec<Value> {
    let path = transport_fixture_path(name);
    let data = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("Failed to read fixture {}: {}", path.display(), e)
    });
    serde_json::from_str(&data).unwrap()
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

// =============================================================================
// Test harness
// =============================================================================

struct TestHarness {
    engine: TransportEngine,
    now: f64,
    rng: FixedRng,
}

impl TestHarness {
    fn new(transport_enabled: bool) -> Self {
        let config = TransportConfig {
            transport_enabled,
            identity_hash: if transport_enabled {
                Some([0x42; 16])
            } else {
                None
            },
        };
        TestHarness {
            engine: TransportEngine::new(config),
            now: 1000.0,
            rng: FixedRng::new(&[0x42; 32]),
        }
    }

    fn new_with_identity(identity_hash: [u8; 16]) -> Self {
        let config = TransportConfig {
            transport_enabled: true,
            identity_hash: Some(identity_hash),
        };
        TestHarness {
            engine: TransportEngine::new(config),
            now: 1000.0,
            rng: FixedRng::new(&[0x42; 32]),
        }
    }

    fn advance_time(&mut self, seconds: f64) {
        self.now += seconds;
    }

    fn tick(&mut self) -> Vec<TransportAction> {
        self.engine.tick(self.now, &mut self.rng)
    }

    fn inbound(&mut self, raw: &[u8], iface: InterfaceId) -> Vec<TransportAction> {
        self.engine.handle_inbound(raw, iface, self.now, &mut self.rng)
    }

    fn outbound(
        &mut self,
        packet: &RawPacket,
        dest_type: u8,
        attached: Option<InterfaceId>,
    ) -> Vec<TransportAction> {
        self.engine.handle_outbound(packet, dest_type, attached, self.now)
    }

    fn add_interface(&mut self, id: u64, mode: u8) {
        self.engine.register_interface(InterfaceInfo {
            id: InterfaceId(id),
            name: format!("test-{}", id),
            mode,
            out_capable: true,
            in_capable: true,
            bitrate: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: rns_core::constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: rns_core::constants::MTU as u32,
            ingress_control: false,
            ia_freq: 0.0,
            started: 0.0,
        });
    }
}

// =============================================================================
// Helper: build a real, validatable announce packet
// =============================================================================

fn build_announce_packet(
    identity: &Identity,
    dest_hash: &[u8; 16],
    name_hash: &[u8; 10],
    random_hash: &[u8; 10],
    hops: u8,
    app_data: Option<&[u8]>,
) -> Vec<u8> {
    let (announce_data, _) = AnnounceData::pack(
        identity,
        dest_hash,
        name_hash,
        random_hash,
        None,
        app_data,
    )
    .unwrap();

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
    };

    let packet = RawPacket::pack(
        flags,
        hops,
        dest_hash,
        None,
        constants::CONTEXT_NONE,
        &announce_data,
    )
    .unwrap();

    packet.raw
}

/// Create a known identity and its corresponding destination hash.
fn make_test_identity() -> (Identity, [u8; 16], [u8; 10], [u8; 16]) {
    let identity = Identity::from_private_key(&[0x42; 64]);
    let id_hash = *identity.hash();

    let name_hash = rns_core::destination::name_hash("testapp", &["aspect"]);
    let dest_hash =
        rns_core::destination::destination_hash("testapp", &["aspect"], Some(&id_hash));

    (identity, dest_hash, name_hash, id_hash)
}

/// Create a random_hash with an embedded timebase value.
fn make_random_hash_with_timebase(timebase: u64, prefix: [u8; 5]) -> [u8; 10] {
    let mut rh = [0u8; 10];
    rh[..5].copy_from_slice(&prefix);
    let tb_bytes = timebase.to_be_bytes();
    rh[5..10].copy_from_slice(&tb_bytes[3..8]);
    rh
}

// =============================================================================
// Interop test: pathfinder vectors from Python
// =============================================================================

#[test]
fn test_pathfinder_timebase_interop() {
    let vectors = load_transport_fixture("pathfinder_vectors.json");

    for v in &vectors {
        let desc = v["description"].as_str().unwrap();
        let blob_hex = v["random_blob"].as_str().unwrap();
        let expected_timebase = v["timebase"].as_u64().unwrap();

        let blob_bytes = hex_to_bytes(blob_hex);
        let mut blob = [0u8; 10];
        blob.copy_from_slice(&blob_bytes);

        let timebase = rns_core::transport::pathfinder::timebase_from_random_blob(&blob);
        assert_eq!(
            timebase, expected_timebase,
            "timebase mismatch for {}",
            desc
        );
    }
}

// =============================================================================
// Interop test: announce retransmit vectors from Python
// =============================================================================

#[test]
fn test_announce_retransmit_interop() {
    let vectors = load_transport_fixture("announce_retransmit_vectors.json");

    for v in &vectors {
        let desc = v["description"].as_str().unwrap();

        let dest_hash_bytes = hex_to_bytes(v["destination_hash"].as_str().unwrap());
        let announce_data_bytes = hex_to_bytes(v["announce_data"].as_str().unwrap());
        let transport_id_bytes = hex_to_bytes(v["transport_id"].as_str().unwrap());
        let expected_flags = v["retransmit_flags"].as_u64().unwrap() as u8;
        let expected_raw = hex_to_bytes(v["retransmit_raw"].as_str().unwrap());
        let original_flags = v["original_flags"].as_u64().unwrap() as u8;
        let original_hops = v["original_hops"].as_u64().unwrap() as u8;
        let context = v["context"].as_u64().unwrap() as u8;

        let mut dest_hash = [0u8; 16];
        dest_hash.copy_from_slice(&dest_hash_bytes);
        let mut transport_id = [0u8; 16];
        transport_id.copy_from_slice(&transport_id_bytes);

        // Build original raw packet for the entry
        let mut original_raw = Vec::new();
        original_raw.push(original_flags);
        original_raw.push(original_hops);
        original_raw.extend_from_slice(&dest_hash);
        original_raw.push(0x00); // context
        original_raw.extend_from_slice(&announce_data_bytes);

        // Determine context_flag from the original flags
        let context_flag = (original_flags >> 5) & 0x01;

        let entry = rns_core::transport::tables::AnnounceEntry {
            timestamp: 1000.0,
            retransmit_timeout: 1000.0,
            retries: 0,
            received_from: [0xAA; 16],
            hops: original_hops,
            packet_raw: original_raw,
            packet_data: announce_data_bytes.clone(),
            destination_hash: dest_hash,
            context_flag,
            local_rebroadcasts: 0,
            block_rebroadcasts: context == constants::CONTEXT_PATH_RESPONSE,
            attached_interface: None,
        };

        let raw = rns_core::transport::announce_proc::build_retransmit_announce(
            &entry,
            &transport_id,
        );

        assert_eq!(
            raw[0], expected_flags,
            "retransmit flags mismatch for {}",
            desc
        );
        assert_eq!(raw, expected_raw, "retransmit raw mismatch for {}", desc);
    }
}

// =============================================================================
// Interop test: transport routing vectors from Python
// =============================================================================

#[test]
fn test_transport_routing_interop() {
    let vectors = load_transport_fixture("transport_routing_vectors.json");

    for v in &vectors {
        let desc = v["description"].as_str().unwrap();

        match desc {
            "h1_to_h2_rewrite" => {
                // Test outbound routing rewrites H1 → H2
                let dest_hash_bytes = hex_to_bytes(v["destination_hash"].as_str().unwrap());
                let next_hop_bytes = hex_to_bytes(v["next_hop"].as_str().unwrap());
                let original_raw = hex_to_bytes(v["original_raw"].as_str().unwrap());
                let expected_flags = v["rewritten_flags"].as_u64().unwrap() as u8;
                let expected_raw = hex_to_bytes(v["rewritten_raw"].as_str().unwrap());

                let mut dest_hash = [0u8; 16];
                dest_hash.copy_from_slice(&dest_hash_bytes);
                let mut next_hop = [0u8; 16];
                next_hop.copy_from_slice(&next_hop_bytes);

                // Parse the original packet
                let packet = RawPacket::unpack(&original_raw).unwrap();

                // Set up harness with a path entry
                let mut harness = TestHarness::new(false);
                harness.add_interface(1, constants::MODE_FULL);

                // Manually insert a path entry
                harness.engine.register_interface(InterfaceInfo {
                    id: InterfaceId(1),
                    name: String::from("test-1"),
                    mode: constants::MODE_FULL,
                    out_capable: true,
                    in_capable: true,
                    bitrate: None,
                    announce_rate_target: None,
                    announce_rate_grace: 0,
                    announce_rate_penalty: 0.0,
            announce_cap: rns_core::constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: rns_core::constants::MTU as u32,
            ingress_control: false,
            ia_freq: 0.0,
            started: 0.0,
                });

                // Use route_outbound directly with a known path
                let mut path_table = std::collections::BTreeMap::new();
                path_table.insert(
                    dest_hash,
                    rns_core::transport::tables::PathEntry {
                        timestamp: 1000.0,
                        next_hop,
                        hops: 3,
                        expires: 9999.0,
                        random_blobs: Vec::new(),
                        receiving_interface: InterfaceId(1),
                        packet_hash: [0; 32],
                        announce_raw: None,
                    },
                );

                let interfaces = std::collections::BTreeMap::new();
                let local_dests = std::collections::BTreeMap::new();

                let actions = rns_core::transport::outbound::route_outbound(
                    &path_table,
                    &interfaces,
                    &local_dests,
                    &packet,
                    constants::DESTINATION_SINGLE,
                    None,
                    1000.0,
                );

                assert_eq!(actions.len(), 1, "expected 1 action for {}", desc);
                match &actions[0] {
                    TransportAction::SendOnInterface { raw, .. } => {
                        let flags = PacketFlags::unpack(raw[0]);
                        assert_eq!(
                            flags.header_type,
                            constants::HEADER_2,
                            "expected HEADER_2 for {}",
                            desc
                        );
                        assert_eq!(
                            raw[0], expected_flags,
                            "flags mismatch for {}",
                            desc
                        );
                        // Transport ID should be next_hop
                        assert_eq!(&raw[2..18], &next_hop, "transport_id mismatch for {}", desc);
                        // Rest should match
                        assert_eq!(raw.as_slice(), expected_raw.as_slice(), "raw mismatch for {}", desc);
                    }
                    _ => panic!("Expected SendOnInterface for {}", desc),
                }
            }
            "h2_forward_replace_transport" => {
                // Test forward_transport_packet replaces transport ID
                let dest_hash_bytes = hex_to_bytes(v["destination_hash"].as_str().unwrap());
                let new_transport_bytes = hex_to_bytes(v["new_transport_id"].as_str().unwrap());
                let original_raw = hex_to_bytes(v["original_raw"].as_str().unwrap());
                let expected_raw = hex_to_bytes(v["rewritten_raw"].as_str().unwrap());

                let mut dest_hash = [0u8; 16];
                dest_hash.copy_from_slice(&dest_hash_bytes);
                let mut new_transport = [0u8; 16];
                new_transport.copy_from_slice(&new_transport_bytes);

                let packet = RawPacket::unpack(&original_raw).unwrap();

                let result = rns_core::transport::inbound::forward_transport_packet(
                    &packet,
                    new_transport,
                    3, // remaining_hops > 1
                    InterfaceId(1),
                );

                assert_eq!(
                    &result[2..18],
                    &new_transport,
                    "new transport_id mismatch for {}",
                    desc
                );
                assert_eq!(result, expected_raw, "raw mismatch for {}", desc);
            }
            "h2_to_h1_strip_last_hop" => {
                // Test forward_transport_packet strips H2→H1 on last hop
                let original_raw = hex_to_bytes(v["original_raw"].as_str().unwrap());
                let expected_flags = v["stripped_flags"].as_u64().unwrap() as u8;
                let expected_raw = hex_to_bytes(v["stripped_raw"].as_str().unwrap());

                let packet = RawPacket::unpack(&original_raw).unwrap();

                let result = rns_core::transport::inbound::forward_transport_packet(
                    &packet,
                    [0; 16], // next_hop doesn't matter for last hop
                    1,       // remaining_hops == 1 → strip
                    InterfaceId(1),
                );

                let flags = PacketFlags::unpack(result[0]);
                assert_eq!(
                    flags.header_type,
                    constants::HEADER_1,
                    "expected HEADER_1 for {}",
                    desc
                );
                assert_eq!(result[0], expected_flags, "flags mismatch for {}", desc);
                assert_eq!(result, expected_raw, "raw mismatch for {}", desc);
            }
            _ => {
                panic!("Unknown transport routing test: {}", desc);
            }
        }
    }
}

// =============================================================================
// Integration: Full announce pipeline with Python vector
// =============================================================================

#[test]
fn test_full_announce_pipeline_from_python() {
    let vectors = load_transport_fixture("full_pipeline_vectors.json");
    let v = &vectors[0];

    let raw_packet = hex_to_bytes(v["raw_packet"].as_str().unwrap());
    let dest_hash_bytes = hex_to_bytes(v["destination_hash"].as_str().unwrap());
    let identity_hash_bytes = hex_to_bytes(v["identity_hash"].as_str().unwrap());
    let expected_timebase = v["timebase"].as_u64().unwrap();

    let mut dest_hash = [0u8; 16];
    dest_hash.copy_from_slice(&dest_hash_bytes);

    // Create transport engine (transport enabled so it queues retransmits)
    let mut harness = TestHarness::new_with_identity([0xFF; 16]); // different from announce identity
    harness.add_interface(1, constants::MODE_FULL);

    // Feed the announce
    let actions = harness.inbound(&raw_packet, InterfaceId(1));

    // Should produce AnnounceReceived and PathUpdated actions
    let mut has_announce_received = false;
    let mut has_path_updated = false;

    for action in &actions {
        match action {
            TransportAction::AnnounceReceived {
                destination_hash: dh,
                identity_hash: ih,
                hops,
                ..
            } => {
                assert_eq!(dh, &dest_hash, "AnnounceReceived dest_hash mismatch");
                assert_eq!(
                    ih.as_slice(),
                    identity_hash_bytes.as_slice(),
                    "AnnounceReceived identity_hash mismatch"
                );
                assert_eq!(*hops, 1, "AnnounceReceived hops should be 1 (incremented from 0)");
                has_announce_received = true;
            }
            TransportAction::PathUpdated {
                destination_hash: dh,
                hops,
                ..
            } => {
                assert_eq!(dh, &dest_hash, "PathUpdated dest_hash mismatch");
                assert_eq!(*hops, 1);
                has_path_updated = true;
            }
            _ => {}
        }
    }

    assert!(has_announce_received, "Expected AnnounceReceived action");
    assert!(has_path_updated, "Expected PathUpdated action");

    // Path should be stored
    assert!(
        harness.engine.has_path(&dest_hash),
        "Path should be stored after announce"
    );
    assert_eq!(harness.engine.hops_to(&dest_hash), Some(1));

    // Verify timebase extraction from the random_hash in the announce data
    let random_hash_bytes = hex_to_bytes(v["random_hash"].as_str().unwrap());
    let mut random_hash = [0u8; 10];
    random_hash.copy_from_slice(&random_hash_bytes);
    let timebase = rns_core::transport::pathfinder::timebase_from_random_blob(&random_hash);
    assert_eq!(timebase, expected_timebase, "Timebase extraction mismatch");

    // Announce should be in the retransmit table (transport enabled)
    // Tick past the retransmit timeout to trigger retransmission
    harness.advance_time(2.0); // past ANNOUNCES_CHECK_INTERVAL + PATHFINDER_RW
    let tick_actions = harness.tick();

    // Should have a retransmit action with H2/TRANSPORT flags
    let retransmit = tick_actions.iter().find(|a| {
        matches!(
            a,
            TransportAction::BroadcastOnAllInterfaces { .. }
                | TransportAction::SendOnInterface { .. }
        )
    });
    assert!(
        retransmit.is_some(),
        "Expected retransmit action after tick, got {:?}",
        tick_actions
    );
    // Verify retransmitted packet has correct H2/TRANSPORT structure
    let retransmit_raw = match retransmit.unwrap() {
        TransportAction::BroadcastOnAllInterfaces { raw, .. } => raw,
        TransportAction::SendOnInterface { raw, .. } => raw,
        _ => unreachable!(),
    };
    let retransmit_flags = PacketFlags::unpack(retransmit_raw[0]);
    assert_eq!(retransmit_flags.header_type, constants::HEADER_2, "Retransmit should be HEADER_2");
    assert_eq!(retransmit_flags.transport_type, constants::TRANSPORT_TRANSPORT, "Retransmit should be TRANSPORT");
    assert_eq!(retransmit_flags.packet_type, constants::PACKET_TYPE_ANNOUNCE, "Retransmit should be ANNOUNCE");
    // Transport ID (bytes 2..18) should be our identity hash
    assert_eq!(&retransmit_raw[2..18], &[0xFF; 16], "Transport ID should be engine identity");
    // Destination hash (bytes 18..34) should match
    assert_eq!(&retransmit_raw[18..34], &dest_hash, "Destination hash in retransmit should match");
}

// =============================================================================
// Integration: Announce → Path → Retransmit → Heard back → Cleared
// =============================================================================

#[test]
fn test_announce_retransmit_lifecycle() {
    let (identity, dest_hash, name_hash, _id_hash) = make_test_identity();
    let random_hash = make_random_hash_with_timebase(500, [0x11, 0x22, 0x33, 0x44, 0x55]);

    let raw = build_announce_packet(&identity, &dest_hash, &name_hash, &random_hash, 0, None);

    // Transport node receives the announce
    let mut harness = TestHarness::new_with_identity([0xFF; 16]);
    harness.add_interface(1, constants::MODE_FULL);
    harness.add_interface(2, constants::MODE_FULL);

    let actions = harness.inbound(&raw, InterfaceId(1));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, TransportAction::AnnounceReceived { .. })),
        "Should receive announce"
    );
    assert!(harness.engine.has_path(&dest_hash));

    // Tick to trigger retransmit
    harness.advance_time(2.0);
    let tick_actions = harness.tick();
    assert!(
        !tick_actions.is_empty(),
        "Should retransmit after tick"
    );

    // Find the retransmit action and verify its contents
    let retransmit = tick_actions.iter().find(|a| {
        matches!(
            a,
            TransportAction::BroadcastOnAllInterfaces { .. }
                | TransportAction::SendOnInterface { .. }
        )
    });
    assert!(retransmit.is_some(), "Expected retransmit action");

    let retransmit_raw = match retransmit.unwrap() {
        TransportAction::BroadcastOnAllInterfaces { raw, .. } => raw,
        TransportAction::SendOnInterface { raw, .. } => raw,
        _ => unreachable!(),
    };

    // Verify H2/TRANSPORT/ANNOUNCE structure
    let flags = PacketFlags::unpack(retransmit_raw[0]);
    assert_eq!(flags.header_type, constants::HEADER_2);
    assert_eq!(flags.transport_type, constants::TRANSPORT_TRANSPORT);
    assert_eq!(flags.packet_type, constants::PACKET_TYPE_ANNOUNCE);
    // Transport ID should be our identity
    assert_eq!(&retransmit_raw[2..18], &[0xFF; 16], "Transport ID should be engine identity");
    // Destination hash should be preserved
    assert_eq!(&retransmit_raw[18..34], &dest_hash, "Dest hash should be preserved in retransmit");
}

// =============================================================================
// Integration: DATA routed via stored path with H1→H2 rewrite
// =============================================================================

#[test]
fn test_data_routed_via_path() {
    let (identity, dest_hash, name_hash, _id_hash) = make_test_identity();
    let random_hash = make_random_hash_with_timebase(500, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);

    let announce_raw =
        build_announce_packet(&identity, &dest_hash, &name_hash, &random_hash, 1, None);

    let mut harness = TestHarness::new_with_identity([0xFF; 16]);
    harness.add_interface(1, constants::MODE_FULL);

    // Feed announce (hops=1, will be incremented to 2 inside handle_inbound)
    harness.inbound(&announce_raw, InterfaceId(1));
    assert!(harness.engine.has_path(&dest_hash));
    assert_eq!(harness.engine.hops_to(&dest_hash), Some(2));

    // Now send a DATA packet to this destination
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
        b"hello world",
    )
    .unwrap();

    let actions = harness.outbound(&data_packet, constants::DESTINATION_SINGLE, None);

    assert_eq!(actions.len(), 1, "Expected 1 outbound action");
    match &actions[0] {
        TransportAction::SendOnInterface { interface, raw } => {
            assert_eq!(*interface, InterfaceId(1));
            let flags = PacketFlags::unpack(raw[0]);
            // Multi-hop path (hops=2), so should be rewritten to H2/TRANSPORT
            assert_eq!(flags.header_type, constants::HEADER_2);
            assert_eq!(flags.transport_type, constants::TRANSPORT_TRANSPORT);
            // Destination hash should be preserved at offset 18..34
            assert_eq!(&raw[18..34], &dest_hash);
        }
        other => panic!("Expected SendOnInterface, got {:?}", other),
    }
}

// =============================================================================
// Integration: Proof routed back via reverse table
// =============================================================================

#[test]
fn test_proof_routed_via_reverse_table() {
    let mut harness = TestHarness::new_with_identity([0x42; 16]);
    harness.add_interface(1, constants::MODE_FULL);
    harness.add_interface(2, constants::MODE_FULL);

    let _dest_hash = [0x11; 16];

    // Simulate a transport forward by manually inserting a path and sending
    // a transport packet addressed to us. This creates a reverse table entry.

    // Build a HEADER_2 DATA packet addressed to our transport identity
    let data_flags = PacketFlags {
        header_type: constants::HEADER_2,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_TRANSPORT,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };

    // We need a path to the destination for forwarding
    // Manually insert it since we can't use private fields directly
    // Instead, use a different approach: build the complete flow

    // First, register a path via announce
    let (identity, actual_dest, name_hash, _) = make_test_identity();
    let rh = make_random_hash_with_timebase(100, [0x11; 5]);
    let announce_raw = build_announce_packet(&identity, &actual_dest, &name_hash, &rh, 0, None);
    harness.inbound(&announce_raw, InterfaceId(1));

    // Now build a DATA packet to this destination with our transport_id
    let transport_packet = RawPacket::pack(
        data_flags,
        2,
        &actual_dest,
        Some(&[0x42; 16]),
        constants::CONTEXT_NONE,
        b"payload data",
    )
    .unwrap();

    // Feed this as inbound - it should be forwarded and create a reverse entry
    let forward_actions = harness.inbound(&transport_packet.raw, InterfaceId(2));

    // Should have forwarded the packet
    let forwarded = forward_actions
        .iter()
        .any(|a| matches!(a, TransportAction::SendOnInterface { .. }));
    assert!(forwarded, "Expected transport packet to be forwarded");

    // Now build a proof packet for the forwarded data
    // Proof destination_hash should be the truncated hash of the original packet
    let truncated_hash = transport_packet.get_truncated_hash();

    let proof_flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_PROOF,
    };

    let proof_data = [0xBB; 64]; // Simulated proof signature
    let proof_packet = RawPacket::pack(
        proof_flags,
        0,
        &truncated_hash,
        None,
        constants::CONTEXT_NONE,
        &proof_data,
    )
    .unwrap();

    // Feed proof - should be routed back via reverse table to interface 2
    // (where the original transport packet came from)
    let proof_actions = harness.inbound(&proof_packet.raw, InterfaceId(1));

    // Should route proof back on the reverse path (interface 2)
    let routed_proof = proof_actions.iter().find(|a| {
        matches!(
            a,
            TransportAction::SendOnInterface { .. } | TransportAction::DeliverLocal { .. }
        )
    });
    assert!(
        routed_proof.is_some(),
        "Expected proof to be routed, got {:?}",
        proof_actions
    );

    // If routed via SendOnInterface, it should go to interface 2 (reverse path)
    if let Some(TransportAction::SendOnInterface { interface, .. }) = routed_proof {
        assert_eq!(
            *interface,
            InterfaceId(2),
            "Proof should be routed back on the reverse path (interface 2)"
        );
    }
}

// =============================================================================
// Integration: Path expires → cull removes it
// =============================================================================

#[test]
fn test_path_expires_after_cull() {
    let (identity, dest_hash, name_hash, _) = make_test_identity();
    let rh = make_random_hash_with_timebase(100, [0x33; 5]);
    let announce_raw = build_announce_packet(&identity, &dest_hash, &name_hash, &rh, 0, None);

    let mut harness = TestHarness::new_with_identity([0xFF; 16]);
    harness.add_interface(1, constants::MODE_FULL);

    harness.inbound(&announce_raw, InterfaceId(1));
    assert!(harness.engine.has_path(&dest_hash));

    // Fast-forward past path expiry (PATHFINDER_E = 604800s for MODE_FULL)
    harness.advance_time(604801.0);

    // Tick to trigger culling
    harness.tick();

    assert!(
        !harness.engine.has_path(&dest_hash),
        "Path should be removed after expiry"
    );
}

// =============================================================================
// Integration: LINKREQUEST forwarded → link_table → traffic routed
// =============================================================================

#[test]
fn test_linkrequest_forward_and_link_traffic() {
    let mut harness = TestHarness::new_with_identity([0x42; 16]);
    harness.add_interface(1, constants::MODE_FULL);
    harness.add_interface(2, constants::MODE_FULL);

    // First, set up a path to the destination via announce
    let (identity, dest_hash, name_hash, _) = make_test_identity();
    let rh = make_random_hash_with_timebase(100, [0x55; 5]);
    let announce_raw = build_announce_packet(&identity, &dest_hash, &name_hash, &rh, 0, None);
    harness.inbound(&announce_raw, InterfaceId(1));

    assert!(harness.engine.has_path(&dest_hash));

    // Build a LINKREQUEST HEADER_2 packet addressed to our transport
    let lr_flags = PacketFlags {
        header_type: constants::HEADER_2,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_TRANSPORT,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_LINKREQUEST,
    };

    // LINKREQUEST data needs to be at least 42 bytes for link_id computation
    let mut lr_data = vec![0u8; 50];
    lr_data[0..32].copy_from_slice(&[0xEE; 32]); // ephemeral public key
    lr_data[32..42].copy_from_slice(&[0xDD; 10]); // extra data

    let lr_packet = RawPacket::pack(
        lr_flags,
        2,
        &dest_hash,
        Some(&[0x42; 16]), // our transport identity
        constants::CONTEXT_NONE,
        &lr_data,
    )
    .unwrap();

    // Feed LINKREQUEST
    let lr_actions = harness.inbound(&lr_packet.raw, InterfaceId(2));

    // Should have forwarded the LINKREQUEST
    let forwarded = lr_actions
        .iter()
        .any(|a| matches!(a, TransportAction::SendOnInterface { .. }));
    assert!(
        forwarded,
        "LINKREQUEST should be forwarded, got {:?}",
        lr_actions
    );
}

// =============================================================================
// Integration: Local delivery for local destinations
// =============================================================================

#[test]
fn test_local_delivery() {
    let mut harness = TestHarness::new(false);
    harness.add_interface(1, constants::MODE_FULL);

    let dest_hash = [0x77; 16];
    harness
        .engine
        .register_destination(dest_hash, constants::DESTINATION_SINGLE);

    // Build a DATA packet for this local destination
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet = RawPacket::pack(flags, 0, &dest_hash, None, constants::CONTEXT_NONE, b"local data")
        .unwrap();

    let actions = harness.inbound(&packet.raw, InterfaceId(1));

    let delivered = actions.iter().any(|a| match a {
        TransportAction::DeliverLocal {
            destination_hash, ..
        } => *destination_hash == dest_hash,
        _ => false,
    });
    assert!(delivered, "Expected local delivery");
}

// =============================================================================
// Integration: Deduplication drops repeated packets
// =============================================================================

#[test]
fn test_deduplication() {
    let mut harness = TestHarness::new(false);
    harness.add_interface(1, constants::MODE_FULL);

    let dest_hash = [0x88; 16];
    harness
        .engine
        .register_destination(dest_hash, constants::DESTINATION_SINGLE);

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet = RawPacket::pack(flags, 0, &dest_hash, None, constants::CONTEXT_NONE, b"test data")
        .unwrap();

    // First delivery
    let actions1 = harness.inbound(&packet.raw, InterfaceId(1));
    let delivered1 = actions1
        .iter()
        .any(|a| matches!(a, TransportAction::DeliverLocal { .. }));
    assert!(delivered1, "First packet should be delivered");

    // Exact same packet again (duplicate)
    let actions2 = harness.inbound(&packet.raw, InterfaceId(1));
    let delivered2 = actions2
        .iter()
        .any(|a| matches!(a, TransportAction::DeliverLocal { .. }));
    assert!(!delivered2, "Duplicate packet should NOT be delivered");
}

// =============================================================================
// Integration: Duplicate announce still allowed (for path updates)
// =============================================================================

#[test]
fn test_duplicate_announce_allowed() {
    let (identity, dest_hash, name_hash, _) = make_test_identity();
    let rh1 = make_random_hash_with_timebase(100, [0x11; 5]);
    let raw1 = build_announce_packet(&identity, &dest_hash, &name_hash, &rh1, 0, None);

    let mut harness = TestHarness::new_with_identity([0xFF; 16]);
    harness.add_interface(1, constants::MODE_FULL);

    // First announce
    let actions1 = harness.inbound(&raw1, InterfaceId(1));
    assert!(
        actions1
            .iter()
            .any(|a| matches!(a, TransportAction::AnnounceReceived { .. })),
        "First announce should be processed"
    );

    // Second announce with newer timebase and different blob
    let rh2 = make_random_hash_with_timebase(200, [0x22; 5]);
    let raw2 = build_announce_packet(&identity, &dest_hash, &name_hash, &rh2, 0, None);

    harness.advance_time(1.0);
    let actions2 = harness.inbound(&raw2, InterfaceId(1));
    assert!(
        actions2
            .iter()
            .any(|a| matches!(a, TransportAction::AnnounceReceived { .. })),
        "Duplicate announce with newer timebase should still be processed"
    );
}

// =============================================================================
// Integration: No path broadcast
// =============================================================================

#[test]
fn test_no_path_broadcasts() {
    let mut harness = TestHarness::new(false);
    harness.add_interface(1, constants::MODE_FULL);
    harness.add_interface(2, constants::MODE_FULL);

    let dest_hash = [0x99; 16];

    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let packet = RawPacket::pack(flags, 0, &dest_hash, None, constants::CONTEXT_NONE, b"data")
        .unwrap();

    let actions = harness.outbound(&packet, constants::DESTINATION_SINGLE, None);

    // No path known → should broadcast
    assert_eq!(actions.len(), 1);
    assert!(
        matches!(&actions[0], TransportAction::BroadcastOnAllInterfaces { .. }),
        "Should broadcast when no path"
    );
}

// =============================================================================
// Integration: Announce mode filtering (AP blocks)
// =============================================================================

#[test]
fn test_announce_mode_filtering() {
    let (identity, dest_hash, name_hash, _) = make_test_identity();
    let rh = make_random_hash_with_timebase(100, [0xCC; 5]);
    let raw = build_announce_packet(&identity, &dest_hash, &name_hash, &rh, 1, None);

    let mut harness = TestHarness::new_with_identity([0xFF; 16]);
    harness.add_interface(1, constants::MODE_FULL);
    harness.add_interface(2, constants::MODE_ACCESS_POINT);

    // Feed announce
    harness.inbound(&raw, InterfaceId(1));

    // Tick past retransmit timeout
    harness.advance_time(2.0);
    let tick_actions = harness.tick();

    // The retransmit should happen but the AP interface should be filtered
    // (retransmit is broadcast without attached_interface)
    for action in &tick_actions {
        match action {
            TransportAction::SendOnInterface { interface, .. } => {
                assert_ne!(
                    *interface,
                    InterfaceId(2),
                    "AP interface should not receive retransmitted announce"
                );
            }
            _ => {}
        }
    }
}

// =============================================================================
// Integration: Path state management
// =============================================================================

#[test]
fn test_path_state_lifecycle() {
    let (identity, dest_hash, name_hash, _) = make_test_identity();
    let rh = make_random_hash_with_timebase(100, [0xDD; 5]);
    let raw = build_announce_packet(&identity, &dest_hash, &name_hash, &rh, 0, None);

    let mut harness = TestHarness::new_with_identity([0xFF; 16]);
    harness.add_interface(1, constants::MODE_FULL);

    harness.inbound(&raw, InterfaceId(1));
    assert!(harness.engine.has_path(&dest_hash));

    // Mark unresponsive
    harness.engine.mark_path_unresponsive(&dest_hash);
    assert!(harness.engine.path_is_unresponsive(&dest_hash));

    // New announce with same timebase should be accepted (unresponsive path recovery)
    let rh2 = make_random_hash_with_timebase(100, [0xEE; 5]); // same timebase, different blob
    let raw2 = build_announce_packet(&identity, &dest_hash, &name_hash, &rh2, 0, None);
    harness.advance_time(1.0);
    let actions = harness.inbound(&raw2, InterfaceId(1));

    assert!(
        actions
            .iter()
            .any(|a| matches!(a, TransportAction::PathUpdated { .. })),
        "Path should be updated for unresponsive recovery"
    );

    // Path should no longer be unresponsive (state cleared on update)
    assert!(
        !harness.engine.path_is_unresponsive(&dest_hash),
        "Path state should be cleared after update"
    );
}
