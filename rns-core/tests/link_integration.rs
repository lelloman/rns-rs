//! Integration tests for Phase 4a: Link, Channel, Buffer
//!
//! Tests full handshake between two LinkEngines, channel messaging,
//! buffer streaming, and interop with Python-generated test vectors.

use rns_core::buffer::{BufferReader, BufferWriter, NoopCompressor, StreamDataMessage};
use rns_core::channel::envelope::{pack_envelope, unpack_envelope};
use rns_core::channel::Channel;
use rns_core::link::handshake::{
    build_signalling_bytes, derive_session_key, pack_rtt, parse_signalling_bytes, unpack_rtt,
};
use rns_core::link::crypto::create_session_token;
use rns_core::link::{LinkEngine, LinkMode, LinkState};

use rns_crypto::ed25519::Ed25519PrivateKey;
use rns_crypto::x25519::X25519PrivateKey;
use rns_crypto::FixedRng;

use std::fs;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("tests");
    path.push("fixtures");
    path.push("link");
    path.push(name);
    path
}

fn load_fixture(name: &str) -> serde_json::Value {
    let path = fixture_path(name);
    let data = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", path.display(), e));
    serde_json::from_str(&data).unwrap()
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

// ============================================================================
// Link Handshake Interop Tests
// ============================================================================

#[test]
fn test_link_handshake_interop() {
    let vectors = load_fixture("link_handshake_vectors.json");

    for v in vectors.as_array().unwrap() {
        let desc = v["description"].as_str().unwrap();
        let mode_val = v["mode"].as_u64().unwrap() as u8;
        let mode = if mode_val == 0 {
            LinkMode::Aes128Cbc
        } else {
            LinkMode::Aes256Cbc
        };

        // Load keys
        let init_x25519_prv_bytes: [u8; 32] =
            hex_to_bytes(v["initiator_x25519_prv"].as_str().unwrap())
                .try_into()
                .unwrap();
        let resp_x25519_prv_bytes: [u8; 32] =
            hex_to_bytes(v["responder_x25519_prv"].as_str().unwrap())
                .try_into()
                .unwrap();

        // Load expected values
        let expected_link_id = hex_to_bytes(v["link_id"].as_str().unwrap());
        let expected_shared_key = hex_to_bytes(v["shared_key"].as_str().unwrap());
        let expected_derived_key = hex_to_bytes(v["derived_key"].as_str().unwrap());
        let expected_signalling = hex_to_bytes(v["signalling_bytes"].as_str().unwrap());

        // Test signalling bytes
        let mtu = v["mtu"].as_u64().unwrap() as u32;
        let sig_bytes = build_signalling_bytes(mtu, mode);
        assert_eq!(
            sig_bytes.to_vec(),
            expected_signalling,
            "{desc}: signalling bytes mismatch"
        );

        // Parse signalling roundtrip
        let (parsed_mtu, parsed_mode) = parse_signalling_bytes(&sig_bytes).unwrap();
        assert_eq!(parsed_mtu, mtu, "{desc}: parsed MTU mismatch");
        assert_eq!(parsed_mode, mode, "{desc}: parsed mode mismatch");

        // Test link_id computation
        let hashable_for_linkid = hex_to_bytes(v["hashable_for_linkid"].as_str().unwrap());
        let link_id = rns_core::hash::truncated_hash(&hashable_for_linkid);
        assert_eq!(
            link_id.to_vec(),
            expected_link_id,
            "{desc}: link_id mismatch"
        );

        // Test ECDH
        let init_prv = X25519PrivateKey::from_bytes(&init_x25519_prv_bytes);
        let resp_prv = X25519PrivateKey::from_bytes(&resp_x25519_prv_bytes);
        let init_pub = init_prv.public_key();

        let shared_key = resp_prv.exchange(&init_pub);
        assert_eq!(
            shared_key.to_vec(),
            expected_shared_key,
            "{desc}: shared key mismatch"
        );

        // Test HKDF key derivation
        let link_id_arr: [u8; 16] = link_id;
        let derived = derive_session_key(&shared_key, &link_id_arr, mode).unwrap();
        assert_eq!(derived, expected_derived_key, "{desc}: derived key mismatch");

        // Test RTT pack/unpack
        let rtt_value = v["rtt_value"].as_f64().unwrap();
        let expected_rtt_msgpack = hex_to_bytes(v["rtt_data_msgpack"].as_str().unwrap());
        let packed_rtt = pack_rtt(rtt_value);
        assert_eq!(
            packed_rtt, expected_rtt_msgpack,
            "{desc}: RTT msgpack mismatch"
        );
        let unpacked_rtt = unpack_rtt(&packed_rtt).unwrap();
        assert_eq!(unpacked_rtt, rtt_value, "{desc}: RTT unpack mismatch");

        // Test session encryption
        let token = create_session_token(&derived).unwrap();
        let expected_encrypted_rtt = hex_to_bytes(v["encrypted_rtt"].as_str().unwrap());
        let fixed_iv: [u8; 16] = hex_to_bytes(v["fixed_iv"].as_str().unwrap())
            .try_into()
            .unwrap();
        let encrypted = token.encrypt_with_iv(&expected_rtt_msgpack, &fixed_iv);
        assert_eq!(
            encrypted, expected_encrypted_rtt,
            "{desc}: encrypted RTT mismatch"
        );

        // Decrypt and verify
        let decrypted = token.decrypt(&encrypted).unwrap();
        assert_eq!(
            decrypted, expected_rtt_msgpack,
            "{desc}: decrypted RTT mismatch"
        );

        eprintln!("  PASS: {desc}");
    }
}

// ============================================================================
// Link Crypto Interop Tests
// ============================================================================

#[test]
fn test_link_crypto_interop() {
    let vectors = load_fixture("link_crypto_vectors.json");

    for v in vectors.as_array().unwrap() {
        let desc = v["description"].as_str().unwrap();
        let key = hex_to_bytes(v["derived_key"].as_str().unwrap());
        let iv: [u8; 16] = hex_to_bytes(v["fixed_iv"].as_str().unwrap())
            .try_into()
            .unwrap();
        let plaintext = hex_to_bytes(v["plaintext"].as_str().unwrap());
        let expected_ct = hex_to_bytes(v["ciphertext"].as_str().unwrap());

        let token = create_session_token(&key).unwrap();
        let encrypted = token.encrypt_with_iv(&plaintext, &iv);
        assert_eq!(encrypted, expected_ct, "{desc}: ciphertext mismatch");

        let decrypted = token.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext, "{desc}: decrypt mismatch");

        eprintln!("  PASS: {desc}");
    }
}

// ============================================================================
// Link Identify Interop Tests
// ============================================================================

#[test]
fn test_link_identify_interop() {
    let vectors = load_fixture("link_identify_vectors.json");

    for v in vectors.as_array().unwrap() {
        let desc = v["description"].as_str().unwrap();
        let link_id: [u8; 16] = hex_to_bytes(v["link_id"].as_str().unwrap())
            .try_into()
            .unwrap();
        let key = hex_to_bytes(v["derived_key"].as_str().unwrap());
        let iv: [u8; 16] = hex_to_bytes(v["fixed_iv"].as_str().unwrap())
            .try_into()
            .unwrap();
        let expected_plaintext = hex_to_bytes(v["proof_data_plaintext"].as_str().unwrap());
        let expected_encrypted = hex_to_bytes(v["proof_data_encrypted"].as_str().unwrap());

        // Verify identify plaintext structure
        let pub_key = hex_to_bytes(v["public_key"].as_str().unwrap());
        let signature = hex_to_bytes(v["signature"].as_str().unwrap());
        let mut expected_proof = Vec::new();
        expected_proof.extend_from_slice(&pub_key);
        expected_proof.extend_from_slice(&signature);
        assert_eq!(
            expected_proof, expected_plaintext,
            "{desc}: proof plaintext structure"
        );

        // Verify encryption
        let token = create_session_token(&key).unwrap();
        let encrypted = token.encrypt_with_iv(&expected_plaintext, &iv);
        assert_eq!(encrypted, expected_encrypted, "{desc}: encryption mismatch");

        // Verify decryption + identify validation
        let decrypted = token.decrypt(&encrypted).unwrap();
        let result =
            rns_core::link::identify::validate_identify_data(&decrypted, &link_id);
        assert!(result.is_ok(), "{desc}: identify validation failed");

        eprintln!("  PASS: {desc}");
    }
}

// ============================================================================
// Channel Envelope Interop Tests
// ============================================================================

#[test]
fn test_channel_envelope_interop() {
    let vectors = load_fixture("channel_envelope_vectors.json");

    for v in vectors.as_array().unwrap() {
        let desc = v["description"].as_str().unwrap();
        let msgtype = v["msgtype"].as_u64().unwrap() as u16;
        let sequence = v["sequence"].as_u64().unwrap() as u16;
        let data = hex_to_bytes(v["data"].as_str().unwrap());
        let expected_packed = hex_to_bytes(v["packed"].as_str().unwrap());

        let packed = pack_envelope(msgtype, sequence, &data);
        assert_eq!(packed, expected_packed, "{desc}: pack mismatch");

        let (mt, seq, pl) = unpack_envelope(&packed).unwrap();
        assert_eq!(mt, msgtype, "{desc}: msgtype mismatch");
        assert_eq!(seq, sequence, "{desc}: sequence mismatch");
        assert_eq!(pl, &data[..], "{desc}: payload mismatch");

        eprintln!("  PASS: {desc}");
    }
}

// ============================================================================
// Stream Data Interop Tests
// ============================================================================

#[test]
fn test_stream_data_interop() {
    let vectors = load_fixture("stream_data_vectors.json");

    for v in vectors.as_array().unwrap() {
        let desc = v["description"].as_str().unwrap();
        let stream_id = v["stream_id"].as_u64().unwrap() as u16;
        let eof = v["eof"].as_bool().unwrap();
        let compressed = v["compressed"].as_bool().unwrap();
        let data = hex_to_bytes(v["data"].as_str().unwrap());
        let expected_packed = hex_to_bytes(v["packed"].as_str().unwrap());

        let msg = StreamDataMessage::new(stream_id, data.clone(), eof, compressed);
        let packed = msg.pack();
        assert_eq!(packed, expected_packed, "{desc}: pack mismatch");

        // Only unpack non-compressed messages (NoopCompressor can't decompress)
        if !compressed {
            let unpacked = StreamDataMessage::unpack(&packed, &NoopCompressor).unwrap();
            assert_eq!(unpacked.stream_id, stream_id, "{desc}: stream_id mismatch");
            assert_eq!(unpacked.eof, eof, "{desc}: eof mismatch");
            assert_eq!(unpacked.data, data, "{desc}: data mismatch");
        }

        eprintln!("  PASS: {desc}");
    }
}

// ============================================================================
// Full Handshake Integration Test
// ============================================================================

#[test]
fn test_full_handshake_two_engines() {
    let mut rng_id = FixedRng::new(&[0x01; 128]);
    let dest_sig_prv = Ed25519PrivateKey::generate(&mut rng_id);
    let dest_sig_pub_bytes = dest_sig_prv.public_key().public_bytes();
    let dest_hash = [0xDD; 16];

    // Initiator creates link
    let mut rng_init = FixedRng::new(&[0x10; 128]);
    let (mut initiator, request_data) = LinkEngine::new_initiator(
        &dest_hash,
        2,
        LinkMode::Aes256Cbc,
        Some(500),
        100.0,
        &mut rng_init,
    );
    assert_eq!(initiator.state(), LinkState::Pending);

    // Build fake hashable part
    let mut hashable = Vec::new();
    hashable.push(0x02); // LINKREQUEST flags lower nibble
    hashable.push(0x00); // hops
    hashable.extend_from_slice(&dest_hash);
    hashable.push(0x00);
    hashable.extend_from_slice(&request_data);
    initiator.set_link_id_from_hashable(&hashable, request_data.len());

    // Responder receives
    let mut rng_resp = FixedRng::new(&[0x20; 128]);
    let (mut responder, lrproof_data) = LinkEngine::new_responder(
        &dest_sig_prv,
        &dest_sig_pub_bytes,
        &request_data,
        &hashable,
        &dest_hash,
        2,
        100.5,
        &mut rng_resp,
    )
    .unwrap();
    assert_eq!(responder.state(), LinkState::Handshake);
    assert_eq!(responder.link_id(), initiator.link_id());

    // Initiator validates proof
    let mut rng_rtt = FixedRng::new(&[0x30; 128]);
    let (lrrtt_enc, actions) = initiator
        .handle_lrproof(&lrproof_data, &dest_sig_pub_bytes, 101.0, &mut rng_rtt)
        .unwrap();
    assert_eq!(initiator.state(), LinkState::Active);
    assert_eq!(actions.len(), 2);

    // Responder handles RTT
    let actions = responder.handle_lrrtt(&lrrtt_enc, 101.5).unwrap();
    assert_eq!(responder.state(), LinkState::Active);
    assert_eq!(actions.len(), 2);

    // Both can encrypt/decrypt
    let mut rng_enc = FixedRng::new(&[0x40; 128]);
    let ct = initiator.encrypt(b"ping", &mut rng_enc).unwrap();
    let pt = responder.decrypt(&ct).unwrap();
    assert_eq!(pt, b"ping");

    let mut rng_enc2 = FixedRng::new(&[0x50; 128]);
    let ct2 = responder.encrypt(b"pong", &mut rng_enc2).unwrap();
    let pt2 = initiator.decrypt(&ct2).unwrap();
    assert_eq!(pt2, b"pong");
}

// ============================================================================
// Channel over Link Integration Test
// ============================================================================

#[test]
fn test_channel_messaging_over_link() {
    // Set up link (abbreviated)
    let mut rng_id = FixedRng::new(&[0x01; 128]);
    let dest_sig_prv = Ed25519PrivateKey::generate(&mut rng_id);
    let dest_sig_pub_bytes = dest_sig_prv.public_key().public_bytes();
    let dest_hash = [0xDD; 16];

    let mut rng_init = FixedRng::new(&[0x10; 128]);
    let (mut initiator, request_data) = LinkEngine::new_initiator(
        &dest_hash,
        1,
        LinkMode::Aes256Cbc,
        Some(500),
        100.0,
        &mut rng_init,
    );
    let mut hashable = Vec::new();
    hashable.push(0x02);
    hashable.push(0x00);
    hashable.extend_from_slice(&dest_hash);
    hashable.push(0x00);
    hashable.extend_from_slice(&request_data);
    initiator.set_link_id_from_hashable(&hashable, request_data.len());

    let mut rng_resp = FixedRng::new(&[0x20; 128]);
    let (mut responder, lrproof_data) = LinkEngine::new_responder(
        &dest_sig_prv,
        &dest_sig_pub_bytes,
        &request_data,
        &hashable,
        &dest_hash,
        1,
        100.5,
        &mut rng_resp,
    )
    .unwrap();

    let mut rng_rtt = FixedRng::new(&[0x30; 128]);
    let (lrrtt_enc, _) = initiator
        .handle_lrproof(&lrproof_data, &dest_sig_pub_bytes, 101.0, &mut rng_rtt)
        .unwrap();
    responder.handle_lrrtt(&lrrtt_enc, 101.5).unwrap();

    // Create channels on both sides
    let rtt = initiator.rtt().unwrap();
    let mut ch_init = Channel::new(rtt);
    let mut ch_resp = Channel::new(rtt);

    // Send message from initiator to responder via channel
    let link_mdu = initiator.mdu();
    let actions = ch_init.send(0x01, b"Hello Channel!", 102.0, link_mdu).unwrap();
    assert_eq!(actions.len(), 1);

    let raw_envelope = match &actions[0] {
        rns_core::channel::ChannelAction::SendOnLink { raw } => raw.clone(),
        _ => panic!("Expected SendOnLink"),
    };

    // Encrypt for link transport
    let mut rng_ch = FixedRng::new(&[0x60; 128]);
    let encrypted = initiator.encrypt(&raw_envelope, &mut rng_ch).unwrap();

    // Responder decrypts and passes to channel
    let decrypted = responder.decrypt(&encrypted).unwrap();
    let recv_actions = ch_resp.receive(&decrypted, 102.1);
    assert_eq!(recv_actions.len(), 1);

    match &recv_actions[0] {
        rns_core::channel::ChannelAction::MessageReceived {
            msgtype, payload, ..
        } => {
            assert_eq!(*msgtype, 0x01);
            assert_eq!(payload, b"Hello Channel!");
        }
        _ => panic!("Expected MessageReceived"),
    }
}

// ============================================================================
// Buffer Streaming Integration Test
// ============================================================================

#[test]
fn test_buffer_streaming() {
    let mut writer = BufferWriter::new(1);
    let mut reader = BufferReader::new(1);

    let data = b"Hello buffer streaming! This is a test of chunked data transfer.";
    let msgs = writer.write(data, 30, &NoopCompressor);
    assert!(msgs.len() > 1); // Should chunk since MDU is small

    for msg in &msgs {
        reader.receive(msg);
    }

    let eof = writer.close();
    reader.receive(&eof);

    assert!(reader.is_eof());
    let result = reader.read(1000);
    assert_eq!(result, data);
    assert!(reader.is_done());
}

// ============================================================================
// Establishment Timeout Test
// ============================================================================

#[test]
fn test_establishment_timeout_integration() {
    let mut rng = FixedRng::new(&[0x42; 128]);
    let dest_hash = [0xDD; 16];
    let (mut engine, _) =
        LinkEngine::new_initiator(&dest_hash, 1, LinkMode::Aes256Cbc, None, 0.0, &mut rng);

    // Timeout = 6.0 + 6.0 * 1 = 12.0s → expires at 12.0
    // Should not timeout before 12.0s
    let actions = engine.tick(10.0);
    assert!(actions.is_empty());

    // Should timeout after 12.0s
    let actions = engine.tick(15.0);
    assert_eq!(engine.state(), LinkState::Closed);
    assert_eq!(actions.len(), 1);
}
