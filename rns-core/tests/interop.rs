use std::fs;
use std::path::PathBuf;

use serde_json::Value;

use rns_core::announce::AnnounceData;
use rns_core::constants;
use rns_core::destination;
use rns_core::hash;
use rns_core::packet::{PacketFlags, RawPacket};
use rns_core::receipt::{self, ProofResult};
use rns_crypto::identity::Identity;

fn fixture_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("tests");
    path.push("fixtures");
    path.push("protocol");
    path.push(name);
    path
}

fn load_fixture(name: &str) -> Vec<Value> {
    let path = fixture_path(name);
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
// Hash interop tests
// =============================================================================

#[test]
fn test_hash_interop() {
    let vectors = load_fixture("hash_vectors.json");

    for v in &vectors {
        let desc = v["description"].as_str().unwrap();

        if desc.starts_with("name_hash_") {
            // Name hash test
            let app_name = v["app_name"].as_str().unwrap();
            let aspects: Vec<&str> = v["aspects"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap())
                .collect();
            let expected = hex_to_bytes(v["name_hash"].as_str().unwrap());

            let result = hash::name_hash(app_name, &aspects);
            assert_eq!(
                result.as_slice(),
                expected.as_slice(),
                "name_hash mismatch for {}",
                desc
            );
        } else {
            // Full/truncated hash test
            let input = hex_to_bytes(v["input"].as_str().unwrap());
            let expected_full = hex_to_bytes(v["full_hash"].as_str().unwrap());
            let expected_trunc = hex_to_bytes(v["truncated_hash"].as_str().unwrap());

            let full = hash::full_hash(&input);
            assert_eq!(
                full.as_slice(),
                expected_full.as_slice(),
                "full_hash mismatch for {}",
                desc
            );

            let trunc = hash::truncated_hash(&input);
            assert_eq!(
                trunc.as_slice(),
                expected_trunc.as_slice(),
                "truncated_hash mismatch for {}",
                desc
            );
        }
    }
}

// =============================================================================
// Flags interop tests
// =============================================================================

#[test]
fn test_flags_interop() {
    let vectors = load_fixture("flags_vectors.json");

    for v in &vectors {
        let desc = v["description"].as_str().unwrap();
        let expected_packed = v["packed"].as_u64().unwrap() as u8;

        let flags = PacketFlags {
            header_type: v["header_type"].as_u64().unwrap() as u8,
            context_flag: v["context_flag"].as_u64().unwrap() as u8,
            transport_type: v["transport_type"].as_u64().unwrap() as u8,
            destination_type: v["destination_type"].as_u64().unwrap() as u8,
            packet_type: v["packet_type"].as_u64().unwrap() as u8,
        };

        let packed = flags.pack();
        assert_eq!(packed, expected_packed, "flags pack mismatch for {}", desc);

        let unpacked = PacketFlags::unpack(expected_packed);
        assert_eq!(unpacked, flags, "flags unpack mismatch for {}", desc);
    }
}

// =============================================================================
// Packet interop tests
// =============================================================================

#[test]
fn test_packet_interop() {
    let vectors = load_fixture("packet_vectors.json");

    for v in &vectors {
        let desc = v["description"].as_str().unwrap();

        let header_type = v["header_type"].as_u64().unwrap() as u8;
        let context_flag = v["context_flag"].as_u64().unwrap() as u8;
        let transport_type = v["transport_type"].as_u64().unwrap() as u8;
        let destination_type = v["destination_type"].as_u64().unwrap() as u8;
        let packet_type = v["packet_type"].as_u64().unwrap() as u8;
        let hops = v["hops"].as_u64().unwrap() as u8;
        let context = v["context"].as_u64().unwrap() as u8;

        let dest_hash_bytes = hex_to_bytes(v["destination_hash"].as_str().unwrap());
        let mut dest_hash = [0u8; 16];
        dest_hash.copy_from_slice(&dest_hash_bytes);

        let transport_id = if v["transport_id"].is_null() {
            None
        } else {
            let bytes = hex_to_bytes(v["transport_id"].as_str().unwrap());
            let mut tid = [0u8; 16];
            tid.copy_from_slice(&bytes);
            Some(tid)
        };

        let data = hex_to_bytes(v["data"].as_str().unwrap());
        let expected_raw = hex_to_bytes(v["raw"].as_str().unwrap());
        let expected_hashable = hex_to_bytes(v["hashable_part"].as_str().unwrap());
        let expected_hash = hex_to_bytes(v["packet_hash"].as_str().unwrap());
        let expected_trunc = hex_to_bytes(v["truncated_hash"].as_str().unwrap());

        let flags = PacketFlags {
            header_type,
            context_flag,
            transport_type,
            destination_type,
            packet_type,
        };

        // Test pack
        let pkt = RawPacket::pack(
            flags,
            hops,
            &dest_hash,
            transport_id.as_ref(),
            context,
            &data,
        )
        .unwrap();

        assert_eq!(
            pkt.raw, expected_raw,
            "pack raw mismatch for {}",
            desc
        );

        assert_eq!(
            pkt.get_hashable_part(),
            expected_hashable,
            "hashable_part mismatch for {}",
            desc
        );

        assert_eq!(
            pkt.get_hash().as_slice(),
            expected_hash.as_slice(),
            "packet_hash mismatch for {}",
            desc
        );

        assert_eq!(
            pkt.get_truncated_hash().as_slice(),
            expected_trunc.as_slice(),
            "truncated_hash mismatch for {}",
            desc
        );

        // Test unpack
        let unpacked = RawPacket::unpack(&expected_raw).unwrap();
        assert_eq!(unpacked.flags, flags, "unpack flags mismatch for {}", desc);
        assert_eq!(unpacked.hops, hops, "unpack hops mismatch for {}", desc);
        assert_eq!(
            unpacked.destination_hash, dest_hash,
            "unpack dest_hash mismatch for {}",
            desc
        );
        assert_eq!(
            unpacked.context, context,
            "unpack context mismatch for {}",
            desc
        );
        assert_eq!(
            unpacked.data, data,
            "unpack data mismatch for {}",
            desc
        );

        if let Some(ref tid) = transport_id {
            assert_eq!(
                unpacked.transport_id.unwrap(),
                *tid,
                "unpack transport_id mismatch for {}",
                desc
            );
        } else {
            assert!(
                unpacked.transport_id.is_none(),
                "expected no transport_id for {}",
                desc
            );
        }

        assert_eq!(
            unpacked.get_hash().as_slice(),
            expected_hash.as_slice(),
            "unpack packet_hash mismatch for {}",
            desc
        );
    }
}

// =============================================================================
// Destination interop tests
// =============================================================================

#[test]
fn test_destination_interop() {
    let vectors = load_fixture("destination_vectors.json");

    for v in &vectors {
        let desc = v["description"].as_str().unwrap();
        let app_name = v["app_name"].as_str().unwrap();
        let aspects: Vec<&str> = v["aspects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();

        let identity_hash = if v["identity_hash"].is_null() {
            None
        } else {
            let bytes = hex_to_bytes(v["identity_hash"].as_str().unwrap());
            let mut h = [0u8; 16];
            h.copy_from_slice(&bytes);
            Some(h)
        };

        let expected_name = v["expanded_name"].as_str().unwrap();
        let expected_name_hash = hex_to_bytes(v["name_hash"].as_str().unwrap());
        let expected_dest_hash = hex_to_bytes(v["destination_hash"].as_str().unwrap());

        // Test expand_name
        let name = destination::expand_name(app_name, &aspects, identity_hash.as_ref()).unwrap();
        assert_eq!(name, expected_name, "expand_name mismatch for {}", desc);

        // Test name_hash
        let nh = destination::name_hash(app_name, &aspects);
        assert_eq!(
            nh.as_slice(),
            expected_name_hash.as_slice(),
            "name_hash mismatch for {}",
            desc
        );

        // Test destination_hash
        let dh = destination::destination_hash(app_name, &aspects, identity_hash.as_ref());
        assert_eq!(
            dh.as_slice(),
            expected_dest_hash.as_slice(),
            "destination_hash mismatch for {}",
            desc
        );
    }
}

// =============================================================================
// Announce interop tests
// =============================================================================

#[test]
fn test_announce_interop() {
    let vectors = load_fixture("announce_vectors.json");

    for v in &vectors {
        let desc = v["description"].as_str().unwrap();

        let prv_key_bytes = hex_to_bytes(v["private_key"].as_str().unwrap());
        let mut prv_key = [0u8; 64];
        prv_key.copy_from_slice(&prv_key_bytes);
        let identity = Identity::from_private_key(&prv_key);

        let pub_key_bytes = hex_to_bytes(v["public_key"].as_str().unwrap());
        let identity_hash_bytes = hex_to_bytes(v["identity_hash"].as_str().unwrap());
        let name_hash_bytes = hex_to_bytes(v["name_hash"].as_str().unwrap());
        let dest_hash_bytes = hex_to_bytes(v["destination_hash"].as_str().unwrap());
        let random_hash_bytes = hex_to_bytes(v["random_hash"].as_str().unwrap());
        let expected_announce = hex_to_bytes(v["announce_data"].as_str().unwrap());
        let has_ratchet = v["has_ratchet"].as_bool().unwrap();

        let mut dest_hash = [0u8; 16];
        dest_hash.copy_from_slice(&dest_hash_bytes);
        let mut name_hash = [0u8; 10];
        name_hash.copy_from_slice(&name_hash_bytes);
        let mut random_hash = [0u8; 10];
        random_hash.copy_from_slice(&random_hash_bytes);

        let ratchet = if v["ratchet"].is_null() {
            None
        } else {
            let bytes = hex_to_bytes(v["ratchet"].as_str().unwrap());
            let mut r = [0u8; 32];
            r.copy_from_slice(&bytes);
            Some(r)
        };

        let app_data = if v["app_data"].is_null() {
            None
        } else {
            Some(hex_to_bytes(v["app_data"].as_str().unwrap()))
        };

        // Test pack
        let (packed, got_ratchet) = AnnounceData::pack(
            &identity,
            &dest_hash,
            &name_hash,
            &random_hash,
            ratchet.as_ref(),
            app_data.as_deref(),
        )
        .unwrap();

        assert_eq!(
            got_ratchet, has_ratchet,
            "has_ratchet mismatch for {}",
            desc
        );
        assert_eq!(
            packed, expected_announce,
            "pack mismatch for {}",
            desc
        );

        // Test unpack
        let parsed = AnnounceData::unpack(&expected_announce, has_ratchet).unwrap();
        assert_eq!(
            parsed.public_key.as_slice(),
            pub_key_bytes.as_slice(),
            "unpack public_key mismatch for {}",
            desc
        );
        assert_eq!(
            parsed.name_hash.as_slice(),
            name_hash_bytes.as_slice(),
            "unpack name_hash mismatch for {}",
            desc
        );
        assert_eq!(
            parsed.random_hash.as_slice(),
            random_hash_bytes.as_slice(),
            "unpack random_hash mismatch for {}",
            desc
        );

        if has_ratchet {
            assert!(parsed.ratchet.is_some(), "expected ratchet for {}", desc);
        } else {
            assert!(parsed.ratchet.is_none(), "unexpected ratchet for {}", desc);
        }

        // Test validate
        let validated = parsed.validate(&dest_hash).unwrap();
        assert_eq!(
            validated.identity_hash.as_slice(),
            identity_hash_bytes.as_slice(),
            "validate identity_hash mismatch for {}",
            desc
        );
    }
}

// =============================================================================
// Proof interop tests
// =============================================================================

#[test]
fn test_proof_interop() {
    let vectors = load_fixture("proof_vectors.json");

    for v in &vectors {
        let desc = v["description"].as_str().unwrap();

        let pub_key_bytes = hex_to_bytes(v["public_key"].as_str().unwrap());
        let mut pub_key = [0u8; 64];
        pub_key.copy_from_slice(&pub_key_bytes);
        let identity = Identity::from_public_key(&pub_key);

        let packet_hash_bytes = hex_to_bytes(v["packet_hash"].as_str().unwrap());
        let mut packet_hash = [0u8; 32];
        packet_hash.copy_from_slice(&packet_hash_bytes);

        let proof = hex_to_bytes(v["proof"].as_str().unwrap());
        let expected_result = v["result"].as_str().unwrap();

        let result = receipt::validate_proof(&proof, &packet_hash, &identity);

        let expected = match expected_result {
            "valid" => ProofResult::Valid,
            "invalid_hash" => ProofResult::InvalidHash,
            "invalid_signature" => ProofResult::InvalidSignature,
            "invalid_length" => ProofResult::InvalidLength,
            other => panic!("Unknown result type: {}", other),
        };

        assert_eq!(result, expected, "proof result mismatch for {}", desc);
    }
}

// =============================================================================
// Milestone: Full announce pipeline
// =============================================================================

#[test]
fn test_milestone_announce_pipeline() {
    // This test verifies the full pipeline:
    // 1. Python generates an announce with known identity
    // 2. Rust unpacks it from raw bytes
    // 3. Rust validates the signature
    // 4. Rust verifies the destination hash
    // 5. Rust extracts the correct identity hash
    //
    // Using the first announce vector as the milestone test.
    let vectors = load_fixture("announce_vectors.json");
    let v = &vectors[0];

    let announce_bytes = hex_to_bytes(v["announce_data"].as_str().unwrap());
    let dest_hash_bytes = hex_to_bytes(v["destination_hash"].as_str().unwrap());
    let identity_hash_bytes = hex_to_bytes(v["identity_hash"].as_str().unwrap());
    let has_ratchet = v["has_ratchet"].as_bool().unwrap();

    let mut dest_hash = [0u8; 16];
    dest_hash.copy_from_slice(&dest_hash_bytes);

    // Step 1: Unpack the Python-generated announce
    let parsed = AnnounceData::unpack(&announce_bytes, has_ratchet).unwrap();

    // Step 2-4: Validate (signature + destination hash)
    let validated = parsed
        .validate(&dest_hash)
        .expect("Milestone: announce validation failed");

    // Step 5: Verify identity hash matches
    assert_eq!(
        validated.identity_hash.as_slice(),
        identity_hash_bytes.as_slice(),
        "Milestone: identity hash mismatch"
    );

    // Also verify we can build a packet wrapping this announce and unpack it
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
    };

    let pkt = RawPacket::pack(
        flags,
        0,
        &dest_hash,
        None,
        constants::CONTEXT_NONE,
        &announce_bytes,
    )
    .unwrap();

    let unpacked = RawPacket::unpack(&pkt.raw).unwrap();
    assert_eq!(unpacked.destination_hash, dest_hash);
    assert_eq!(unpacked.data, announce_bytes);

    // Re-validate from unpacked packet data
    let reparsed = AnnounceData::unpack(&unpacked.data, has_ratchet).unwrap();
    let revalidated = reparsed.validate(&dest_hash).unwrap();
    assert_eq!(revalidated.identity_hash, validated.identity_hash);
}
