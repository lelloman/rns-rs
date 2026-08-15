use super::*;
use rns_crypto::identity::Identity;
use rns_crypto::{FixedRng, OsRng};

fn make_rng(seed: u8) -> FixedRng {
    FixedRng::new(&[seed; 128])
}

fn make_dest_keys(rng: &mut dyn Rng) -> (Ed25519PrivateKey, [u8; 32]) {
    let sig_prv = Ed25519PrivateKey::generate(rng);
    let sig_pub_bytes = sig_prv.public_key().public_bytes();
    (sig_prv, sig_pub_bytes)
}

#[test]
fn test_register_link_destination() {
    let mut mgr = LinkManager::new();
    let mut rng = make_rng(0x01);
    let (sig_prv, sig_pub_bytes) = make_dest_keys(&mut rng);
    let dest_hash = [0xDD; 16];

    mgr.register_link_destination(
        dest_hash,
        sig_prv,
        sig_pub_bytes,
        ResourceStrategy::AcceptNone,
    );
    assert!(mgr.is_link_destination(&dest_hash));

    mgr.deregister_link_destination(&dest_hash);
    assert!(!mgr.is_link_destination(&dest_hash));
}

#[test]
fn test_create_link() {
    let mut mgr = LinkManager::new();
    let mut rng = OsRng;
    let dest_hash = [0xDD; 16];

    let sig_pub_bytes = [0xAA; 32]; // dummy sig pub for test
    let (link_id, actions) = mgr.create_link(
        &dest_hash,
        &sig_pub_bytes,
        1,
        constants::MTU as u32,
        &mut rng,
    );
    assert_ne!(link_id, [0u8; 16]);
    // Should have RegisterLinkDest + SendPacket
    assert_eq!(actions.len(), 2);
    assert!(matches!(
        actions[0],
        LinkManagerAction::RegisterLinkDest { .. }
    ));
    assert!(matches!(actions[1], LinkManagerAction::SendPacket { .. }));

    // Link should be in Pending state
    assert_eq!(mgr.link_state(&link_id), Some(LinkState::Pending));
}

#[test]
fn test_full_handshake_via_manager() {
    let mut rng = OsRng;
    let dest_hash = [0xDD; 16];

    // Setup responder
    let mut responder_mgr = LinkManager::new();
    let (sig_prv, sig_pub_bytes) = make_dest_keys(&mut rng);
    responder_mgr.register_link_destination(
        dest_hash,
        sig_prv,
        sig_pub_bytes,
        ResourceStrategy::AcceptNone,
    );

    // Setup initiator
    let mut initiator_mgr = LinkManager::new();

    // Step 1: Initiator creates link (needs dest signing pub key for LRPROOF verification)
    let (link_id, init_actions) = initiator_mgr.create_link(
        &dest_hash,
        &sig_pub_bytes,
        1,
        constants::MTU as u32,
        &mut rng,
    );
    assert_eq!(init_actions.len(), 2);

    // Extract the LINKREQUEST packet raw bytes
    let linkrequest_raw = match &init_actions[1] {
        LinkManagerAction::SendPacket { raw, .. } => raw.clone(),
        _ => panic!("Expected SendPacket"),
    };

    // Parse to get packet_hash and dest_hash
    let lr_packet = RawPacket::unpack(&linkrequest_raw).unwrap();

    // Step 2: Responder handles LINKREQUEST
    let resp_actions = responder_mgr.handle_local_delivery(
        lr_packet.destination_hash,
        &linkrequest_raw,
        lr_packet.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    // Should have RegisterLinkDest + SendPacket(LRPROOF)
    assert!(resp_actions.len() >= 2);
    assert!(matches!(
        resp_actions[0],
        LinkManagerAction::RegisterLinkDest { .. }
    ));

    // Extract LRPROOF packet
    let lrproof_raw = match &resp_actions[1] {
        LinkManagerAction::SendPacket { raw, .. } => raw.clone(),
        _ => panic!("Expected SendPacket for LRPROOF"),
    };

    // Step 3: Initiator handles LRPROOF
    let lrproof_packet = RawPacket::unpack(&lrproof_raw).unwrap();
    let init_actions2 = initiator_mgr.handle_local_delivery(
        lrproof_packet.destination_hash,
        &lrproof_raw,
        lrproof_packet.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    // Should have LinkEstablished + SendPacket(LRRTT)
    let has_established = init_actions2
        .iter()
        .any(|a| matches!(a, LinkManagerAction::LinkEstablished { .. }));
    assert!(has_established, "Initiator should emit LinkEstablished");

    // Extract LRRTT
    let lrrtt_raw = init_actions2
        .iter()
        .find_map(|a| match a {
            LinkManagerAction::SendPacket { raw, .. } => Some(raw.clone()),
            _ => None,
        })
        .expect("Should have LRRTT SendPacket");

    // Step 4: Responder handles LRRTT
    let lrrtt_packet = RawPacket::unpack(&lrrtt_raw).unwrap();
    let resp_link_id = lrrtt_packet.destination_hash;
    let resp_actions2 = responder_mgr.handle_local_delivery(
        resp_link_id,
        &lrrtt_raw,
        lrrtt_packet.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    let has_established = resp_actions2
        .iter()
        .any(|a| matches!(a, LinkManagerAction::LinkEstablished { .. }));
    assert!(has_established, "Responder should emit LinkEstablished");

    // Both sides should be Active
    assert_eq!(initiator_mgr.link_state(&link_id), Some(LinkState::Active));
    assert_eq!(responder_mgr.link_state(&link_id), Some(LinkState::Active));

    // Both should have RTT
    assert!(initiator_mgr.link_rtt(&link_id).is_some());
    assert!(responder_mgr.link_rtt(&link_id).is_some());
}

#[test]
fn test_encrypted_data_exchange() {
    let mut rng = OsRng;
    let dest_hash = [0xDD; 16];
    let mut resp_mgr = LinkManager::new();
    let (sig_prv, sig_pub_bytes) = make_dest_keys(&mut rng);
    resp_mgr.register_link_destination(
        dest_hash,
        sig_prv,
        sig_pub_bytes,
        ResourceStrategy::AcceptNone,
    );
    let mut init_mgr = LinkManager::new();

    // Handshake
    let (link_id, init_actions) = init_mgr.create_link(
        &dest_hash,
        &sig_pub_bytes,
        1,
        constants::MTU as u32,
        &mut rng,
    );
    let lr_raw = extract_send_packet(&init_actions);
    let lr_pkt = RawPacket::unpack(&lr_raw).unwrap();
    let resp_actions = resp_mgr.handle_local_delivery(
        lr_pkt.destination_hash,
        &lr_raw,
        lr_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    let lrproof_raw = extract_send_packet_at(&resp_actions, 1);
    let lrproof_pkt = RawPacket::unpack(&lrproof_raw).unwrap();
    let init_actions2 = init_mgr.handle_local_delivery(
        lrproof_pkt.destination_hash,
        &lrproof_raw,
        lrproof_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    let lrrtt_raw = extract_any_send_packet(&init_actions2);
    let lrrtt_pkt = RawPacket::unpack(&lrrtt_raw).unwrap();
    resp_mgr.handle_local_delivery(
        lrrtt_pkt.destination_hash,
        &lrrtt_raw,
        lrrtt_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    // Send data from initiator to responder
    let actions =
        init_mgr.send_on_link(&link_id, b"hello link!", constants::CONTEXT_NONE, &mut rng);
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], LinkManagerAction::SendPacket { .. }));
}

#[test]
fn test_request_response() {
    let mut rng = OsRng;
    let dest_hash = [0xDD; 16];
    let mut resp_mgr = LinkManager::new();
    let (sig_prv, sig_pub_bytes) = make_dest_keys(&mut rng);
    resp_mgr.register_link_destination(
        dest_hash,
        sig_prv,
        sig_pub_bytes,
        ResourceStrategy::AcceptNone,
    );

    // Register a request handler
    resp_mgr.register_request_handler("/status", None, |_link_id, _path, _data, _remote| {
        Some(b"OK".to_vec())
    });

    let mut init_mgr = LinkManager::new();

    // Complete handshake
    let (link_id, init_actions) = init_mgr.create_link(
        &dest_hash,
        &sig_pub_bytes,
        1,
        constants::MTU as u32,
        &mut rng,
    );
    let lr_raw = extract_send_packet(&init_actions);
    let lr_pkt = RawPacket::unpack(&lr_raw).unwrap();
    let resp_actions = resp_mgr.handle_local_delivery(
        lr_pkt.destination_hash,
        &lr_raw,
        lr_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    let lrproof_raw = extract_send_packet_at(&resp_actions, 1);
    let lrproof_pkt = RawPacket::unpack(&lrproof_raw).unwrap();
    let init_actions2 = init_mgr.handle_local_delivery(
        lrproof_pkt.destination_hash,
        &lrproof_raw,
        lrproof_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    let lrrtt_raw = extract_any_send_packet(&init_actions2);
    let lrrtt_pkt = RawPacket::unpack(&lrrtt_raw).unwrap();
    resp_mgr.handle_local_delivery(
        lrrtt_pkt.destination_hash,
        &lrrtt_raw,
        lrrtt_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    // Send request from initiator
    let req_actions = init_mgr.send_request(&link_id, "/status", b"query", &mut rng);
    assert_eq!(req_actions.len(), 1);

    // Deliver request to responder
    let req_raw = extract_send_packet_from(&req_actions);
    let req_pkt = RawPacket::unpack(&req_raw).unwrap();
    let resp_actions = resp_mgr.handle_local_delivery(
        req_pkt.destination_hash,
        &req_raw,
        req_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    // Should have a response SendPacket
    let has_response = resp_actions
        .iter()
        .any(|a| matches!(a, LinkManagerAction::SendPacket { .. }));
    assert!(has_response, "Handler should produce a response packet");
}

#[test]
fn packet_request_at_exact_size_limit_is_dispatched() {
    use std::sync::{Arc, Mutex};

    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let observed = Arc::new(Mutex::new(false));
    resp_mgr.register_request_handler("/bounded", None, {
        let observed = Arc::clone(&observed);
        move |_link_id, _path, _data, _remote| {
            *observed.lock().unwrap() = true;
            None
        }
    });

    let request_actions = init_mgr.send_request(&link_id, "/bounded", b"\xc0", &mut rng);
    let raw = extract_any_send_packet(&request_actions);
    let packet = RawPacket::unpack(&raw).unwrap();
    let packed_size = resp_mgr.links[&link_id]
        .engine
        .decrypt(&packet.data)
        .unwrap()
        .len();
    resp_mgr.links.get_mut(&link_id).unwrap().max_request_size = Some(packed_size);

    resp_mgr.handle_local_delivery(
        packet.destination_hash,
        &raw,
        packet.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    assert!(*observed.lock().unwrap());
}

#[test]
fn packet_request_one_byte_over_size_limit_is_ignored_before_dispatch() {
    use std::sync::{Arc, Mutex};

    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let observed = Arc::new(Mutex::new(false));
    resp_mgr.register_request_handler("/bounded", None, {
        let observed = Arc::clone(&observed);
        move |_link_id, _path, _data, _remote| {
            *observed.lock().unwrap() = true;
            None
        }
    });

    let request_actions = init_mgr.send_request(&link_id, "/bounded", b"\xc0", &mut rng);
    let raw = extract_any_send_packet(&request_actions);
    let packet = RawPacket::unpack(&raw).unwrap();
    let packed_size = resp_mgr.links[&link_id]
        .engine
        .decrypt(&packet.data)
        .unwrap()
        .len();
    resp_mgr.links.get_mut(&link_id).unwrap().max_request_size = Some(packed_size - 1);

    let actions = resp_mgr.handle_local_delivery(
        packet.destination_hash,
        &raw,
        packet.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    assert!(actions.is_empty());
    assert!(!*observed.lock().unwrap());
}

#[test]
fn test_send_request_wraps_invalid_msgpack_data_as_bin() {
    use std::sync::{Arc, Mutex};

    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    let invalid = vec![0xC1];
    let expected = rns_core::msgpack::pack(&rns_core::msgpack::Value::Bin(invalid.clone()));
    let captured = Arc::new(Mutex::new(None::<Vec<u8>>));
    let captured_for_handler = Arc::clone(&captured);

    resp_mgr.register_request_handler("/bin", None, move |_link_id, _path, data, _remote| {
        *captured_for_handler.lock().unwrap() = Some(data.to_vec());
        Some(rns_core::msgpack::pack(&rns_core::msgpack::Value::Bool(
            true,
        )))
    });

    let req_actions = init_mgr.send_request(&link_id, "/bin", &invalid, &mut rng);
    let req_raw = extract_send_packet_from(&req_actions);
    let req_pkt = RawPacket::unpack(&req_raw).unwrap();
    let resp_actions = resp_mgr.handle_local_delivery(
        req_pkt.destination_hash,
        &req_raw,
        req_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    assert!(
        resp_actions
            .iter()
            .any(|a| matches!(a, LinkManagerAction::SendPacket { .. })),
        "handler should still produce a response"
    );
    assert_eq!(*captured.lock().unwrap(), Some(expected));
}

#[test]
fn test_invalid_response_bytes_are_returned_as_msgpack_bin() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let invalid_response = vec![0xC1];
    let expected =
        rns_core::msgpack::pack(&rns_core::msgpack::Value::Bin(invalid_response.clone()));

    resp_mgr.register_request_handler("/invalid-response", None, {
        let invalid_response = invalid_response.clone();
        move |_link_id, _path, _data, _remote| Some(invalid_response.clone())
    });

    let req_actions = init_mgr.send_request(&link_id, "/invalid-response", b"\xc0", &mut rng);
    let req_raw = extract_send_packet_from(&req_actions);
    let req_pkt = RawPacket::unpack(&req_raw).unwrap();
    let resp_actions = resp_mgr.handle_local_delivery(
        req_pkt.destination_hash,
        &req_raw,
        req_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    let resp_raw = extract_any_send_packet(&resp_actions);
    let resp_pkt = RawPacket::unpack(&resp_raw).unwrap();
    let init_actions = init_mgr.handle_local_delivery(
        resp_pkt.destination_hash,
        &resp_raw,
        resp_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    let response_data = init_actions
        .iter()
        .find_map(|action| match action {
            LinkManagerAction::ResponseReceived { data, .. } => Some(data.clone()),
            _ => None,
        })
        .expect("initiator should receive a response");
    assert_eq!(response_data, expected);
}

#[test]
fn packet_response_at_exact_size_limit_is_accepted() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let payload = vec![0xA5; 64];
    let response_value = rns_core::msgpack::pack(&rns_core::msgpack::Value::Bin(payload.clone()));
    resp_mgr.register_request_handler("/bounded-response", None, {
        let response_value = response_value.clone();
        move |_, _, _, _| Some(response_value.clone())
    });

    let request_actions = init_mgr.send_request_with_max_response_size(
        &link_id,
        "/bounded-response",
        b"\xc0",
        Some(payload.len()),
        &mut rng,
    );
    let request_raw = extract_any_send_packet(&request_actions);
    let request = RawPacket::unpack(&request_raw).unwrap();
    let response_actions = resp_mgr.handle_local_delivery(
        request.destination_hash,
        &request_raw,
        request.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    let response_raw = extract_any_send_packet(&response_actions);
    let response = RawPacket::unpack(&response_raw).unwrap();
    let actions = init_mgr.handle_local_delivery(
        response.destination_hash,
        &response_raw,
        response.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    assert!(actions.iter().any(|action| matches!(
        action,
        LinkManagerAction::ResponseReceived { data, .. } if data == &response_value
    )));
    assert!(!actions
        .iter()
        .any(|action| matches!(action, LinkManagerAction::RequestFailed { .. })));
}

#[test]
fn packet_response_one_byte_over_size_limit_fails_request() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let payload = vec![0xA5; 64];
    let response_value = rns_core::msgpack::pack(&rns_core::msgpack::Value::Bin(payload.clone()));
    resp_mgr.register_request_handler("/bounded-response", None, {
        let response_value = response_value.clone();
        move |_, _, _, _| Some(response_value.clone())
    });

    let request_actions = init_mgr.send_request_with_max_response_size(
        &link_id,
        "/bounded-response",
        b"\xc0",
        Some(payload.len() - 1),
        &mut rng,
    );
    let request_raw = extract_any_send_packet(&request_actions);
    let request = RawPacket::unpack(&request_raw).unwrap();
    let request_id = request.get_truncated_hash();
    let response_actions = resp_mgr.handle_local_delivery(
        request.destination_hash,
        &request_raw,
        request.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    let response_raw = extract_any_send_packet(&response_actions);
    let response = RawPacket::unpack(&response_raw).unwrap();
    let actions = init_mgr.handle_local_delivery(
        response.destination_hash,
        &response_raw,
        response.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    assert!(actions.iter().any(|action| matches!(
        action,
        LinkManagerAction::RequestFailed {
            request_id: failed_id,
            reason: RequestFailure::ResponseTooLarge { size: 64, maximum: 63 },
            ..
        } if failed_id == &request_id
    )));
    assert!(!actions
        .iter()
        .any(|action| matches!(action, LinkManagerAction::ResponseReceived { .. })));
    assert!(!init_mgr.links[&link_id]
        .pending_requests
        .contains_key(&request_id));
    assert!(init_mgr
        .handle_local_delivery(
            response.destination_hash,
            &response_raw,
            response.packet_hash,
            rns_core::transport::types::InterfaceId(0),
            &mut rng,
        )
        .is_empty());
}

#[test]
fn test_request_acl_deny_unidentified() {
    let mut rng = OsRng;
    let dest_hash = [0xDD; 16];
    let mut resp_mgr = LinkManager::new();
    let (sig_prv, sig_pub_bytes) = make_dest_keys(&mut rng);
    resp_mgr.register_link_destination(
        dest_hash,
        sig_prv,
        sig_pub_bytes,
        ResourceStrategy::AcceptNone,
    );

    // Register handler with ACL (only allow specific identity)
    resp_mgr.register_request_handler(
        "/restricted",
        Some(vec![[0xAA; 16]]),
        |_link_id, _path, _data, _remote| Some(b"secret".to_vec()),
    );

    let mut init_mgr = LinkManager::new();

    // Complete handshake (without identification)
    let (link_id, init_actions) = init_mgr.create_link(
        &dest_hash,
        &sig_pub_bytes,
        1,
        constants::MTU as u32,
        &mut rng,
    );
    let lr_raw = extract_send_packet(&init_actions);
    let lr_pkt = RawPacket::unpack(&lr_raw).unwrap();
    let resp_actions = resp_mgr.handle_local_delivery(
        lr_pkt.destination_hash,
        &lr_raw,
        lr_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    let lrproof_raw = extract_send_packet_at(&resp_actions, 1);
    let lrproof_pkt = RawPacket::unpack(&lrproof_raw).unwrap();
    let init_actions2 = init_mgr.handle_local_delivery(
        lrproof_pkt.destination_hash,
        &lrproof_raw,
        lrproof_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    let lrrtt_raw = extract_any_send_packet(&init_actions2);
    let lrrtt_pkt = RawPacket::unpack(&lrrtt_raw).unwrap();
    resp_mgr.handle_local_delivery(
        lrrtt_pkt.destination_hash,
        &lrrtt_raw,
        lrrtt_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    // Send request without identifying first
    let req_actions = init_mgr.send_request(&link_id, "/restricted", b"query", &mut rng);
    let req_raw = extract_send_packet_from(&req_actions);
    let req_pkt = RawPacket::unpack(&req_raw).unwrap();
    let resp_actions = resp_mgr.handle_local_delivery(
        req_pkt.destination_hash,
        &req_raw,
        req_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    // Should be denied — no response packet
    let has_response = resp_actions
        .iter()
        .any(|a| matches!(a, LinkManagerAction::SendPacket { .. }));
    assert!(!has_response, "Unidentified peer should be denied");
}

#[test]
fn test_teardown_link() {
    let mut rng = OsRng;
    let dest_hash = [0xDD; 16];
    let mut mgr = LinkManager::new();

    let dummy_sig = [0xAA; 32];
    let (link_id, _) = mgr.create_link(&dest_hash, &dummy_sig, 1, constants::MTU as u32, &mut rng);
    assert_eq!(mgr.link_count(), 1);

    let actions = mgr.teardown_link(&link_id);
    let has_close = actions
        .iter()
        .any(|a| matches!(a, LinkManagerAction::LinkClosed { .. }));
    assert!(has_close);
    assert!(!actions
        .iter()
        .any(|a| matches!(a, LinkManagerAction::SendPacket { .. })));
    assert!(mgr.teardown_link(&link_id).is_empty());

    // After tick, closed links should be cleaned up
    let tick_actions = mgr.tick(&mut rng);
    let has_deregister = tick_actions
        .iter()
        .any(|a| matches!(a, LinkManagerAction::DeregisterLinkDest { .. }));
    assert!(has_deregister);
    assert_eq!(mgr.link_count(), 0);
}

#[test]
fn active_teardown_sends_linkclose_and_remote_closed_teardown_is_noop() {
    let (mut initiator, mut responder, link_id) = setup_active_link();
    let actions = initiator.teardown_link(&link_id);
    let close_packet = actions
        .iter()
        .find_map(|action| match action {
            LinkManagerAction::SendPacket { raw, .. } => RawPacket::unpack(raw)
                .ok()
                .filter(|packet| packet.context == constants::CONTEXT_LINKCLOSE),
            _ => None,
        })
        .expect("active teardown must emit LINKCLOSE");
    assert!(close_packet.raw.len() > constants::HEADER_MINSIZE);
    let plaintext = responder
        .links
        .get(&link_id)
        .unwrap()
        .engine
        .decrypt(&close_packet.data)
        .expect("LINKCLOSE payload must authenticate");
    assert_eq!(plaintext, link_id);
    assert!(initiator.teardown_link(&link_id).is_empty());

    responder
        .links
        .get_mut(&link_id)
        .unwrap()
        .engine
        .handle_teardown();
    assert!(responder.teardown_link(&link_id).is_empty());
}

#[test]
fn forged_or_empty_linkclose_does_not_close_an_active_link() {
    let (_initiator, mut responder, link_id) = setup_active_link();
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_LINK,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let mut rng = OsRng;

    for forged_payload in [Vec::new(), vec![0x55; 48]] {
        let packet = RawPacket::pack(
            flags,
            0,
            &link_id,
            None,
            constants::CONTEXT_LINKCLOSE,
            &forged_payload,
        )
        .unwrap();
        let actions = responder.handle_local_delivery(
            link_id,
            &packet.raw,
            [0u8; 32],
            rns_core::transport::types::InterfaceId(1),
            &mut rng,
        );

        assert_eq!(responder.link_state(&link_id), Some(LinkState::Active));
        assert!(!actions
            .iter()
            .any(|action| matches!(action, LinkManagerAction::LinkClosed { .. })));
    }
}

#[test]
fn test_identify_on_link() {
    let mut rng = OsRng;
    let dest_hash = [0xDD; 16];
    let mut resp_mgr = LinkManager::new();
    let (sig_prv, sig_pub_bytes) = make_dest_keys(&mut rng);
    resp_mgr.register_link_destination(
        dest_hash,
        sig_prv,
        sig_pub_bytes,
        ResourceStrategy::AcceptNone,
    );
    let mut init_mgr = LinkManager::new();

    // Complete handshake
    let (link_id, init_actions) = init_mgr.create_link(
        &dest_hash,
        &sig_pub_bytes,
        1,
        constants::MTU as u32,
        &mut rng,
    );
    let lr_raw = extract_send_packet(&init_actions);
    let lr_pkt = RawPacket::unpack(&lr_raw).unwrap();
    let resp_actions = resp_mgr.handle_local_delivery(
        lr_pkt.destination_hash,
        &lr_raw,
        lr_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    let lrproof_raw = extract_send_packet_at(&resp_actions, 1);
    let lrproof_pkt = RawPacket::unpack(&lrproof_raw).unwrap();
    let init_actions2 = init_mgr.handle_local_delivery(
        lrproof_pkt.destination_hash,
        &lrproof_raw,
        lrproof_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    let lrrtt_raw = extract_any_send_packet(&init_actions2);
    let lrrtt_pkt = RawPacket::unpack(&lrrtt_raw).unwrap();
    resp_mgr.handle_local_delivery(
        lrrtt_pkt.destination_hash,
        &lrrtt_raw,
        lrrtt_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    // Identify initiator to responder
    let identity = Identity::new(&mut rng);
    let id_actions = init_mgr.identify(&link_id, &identity, &mut rng);
    assert_eq!(id_actions.len(), 1);

    // Deliver identify to responder
    let id_raw = extract_send_packet_from(&id_actions);
    let id_pkt = RawPacket::unpack(&id_raw).unwrap();
    let resp_actions = resp_mgr.handle_local_delivery(
        id_pkt.destination_hash,
        &id_raw,
        id_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    let has_identified = resp_actions
        .iter()
        .any(|a| matches!(a, LinkManagerAction::RemoteIdentified { .. }));
    assert!(has_identified, "Responder should emit RemoteIdentified");
}

#[test]
fn test_path_hash_computation() {
    let h1 = compute_path_hash("/status");
    let h2 = compute_path_hash("/path");
    assert_ne!(h1, h2);

    // Deterministic
    assert_eq!(h1, compute_path_hash("/status"));
}

#[test]
fn test_link_count() {
    let mut mgr = LinkManager::new();
    let mut rng = OsRng;

    assert_eq!(mgr.link_count(), 0);

    let dummy_sig = [0xAA; 32];
    mgr.create_link(&[0x11; 16], &dummy_sig, 1, constants::MTU as u32, &mut rng);
    assert_eq!(mgr.link_count(), 1);

    mgr.create_link(&[0x22; 16], &dummy_sig, 1, constants::MTU as u32, &mut rng);
    assert_eq!(mgr.link_count(), 2);
}

// --- Test helpers ---

fn extract_send_packet(actions: &[LinkManagerAction]) -> Vec<u8> {
    extract_send_packet_at(actions, actions.len() - 1)
}

fn extract_send_packet_at(actions: &[LinkManagerAction], idx: usize) -> Vec<u8> {
    match &actions[idx] {
        LinkManagerAction::SendPacket { raw, .. } => raw.clone(),
        other => panic!("Expected SendPacket at index {}, got {:?}", idx, other),
    }
}

fn extract_any_send_packet(actions: &[LinkManagerAction]) -> Vec<u8> {
    actions
        .iter()
        .find_map(|a| match a {
            LinkManagerAction::SendPacket { raw, .. } => Some(raw.clone()),
            _ => None,
        })
        .expect("Expected at least one SendPacket action")
}

fn extract_send_packet_from(actions: &[LinkManagerAction]) -> Vec<u8> {
    extract_any_send_packet(actions)
}

/// Set up two linked managers with an active link.
/// Returns (initiator_mgr, responder_mgr, link_id).
fn setup_active_link() -> (LinkManager, LinkManager, LinkId) {
    setup_active_link_with_max_request_size(None)
}

fn setup_active_link_with_max_request_size(
    max_request_size: Option<usize>,
) -> (LinkManager, LinkManager, LinkId) {
    let mut rng = OsRng;
    let dest_hash = [0xDD; 16];
    let mut resp_mgr = LinkManager::new();
    let (sig_prv, sig_pub_bytes) = make_dest_keys(&mut rng);
    resp_mgr.register_link_destination(
        dest_hash,
        sig_prv,
        sig_pub_bytes,
        ResourceStrategy::AcceptNone,
    );
    assert!(resp_mgr.set_link_destination_max_request_size(&dest_hash, max_request_size));
    let mut init_mgr = LinkManager::new();

    let (link_id, init_actions) = init_mgr.create_link(
        &dest_hash,
        &sig_pub_bytes,
        1,
        constants::MTU as u32,
        &mut rng,
    );
    let lr_raw = extract_send_packet(&init_actions);
    let lr_pkt = RawPacket::unpack(&lr_raw).unwrap();
    let resp_actions = resp_mgr.handle_local_delivery(
        lr_pkt.destination_hash,
        &lr_raw,
        lr_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    let lrproof_raw = extract_send_packet_at(&resp_actions, 1);
    let lrproof_pkt = RawPacket::unpack(&lrproof_raw).unwrap();
    let init_actions2 = init_mgr.handle_local_delivery(
        lrproof_pkt.destination_hash,
        &lrproof_raw,
        lrproof_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    let lrrtt_raw = extract_any_send_packet(&init_actions2);
    let lrrtt_pkt = RawPacket::unpack(&lrrtt_raw).unwrap();
    resp_mgr.handle_local_delivery(
        lrrtt_pkt.destination_hash,
        &lrrtt_raw,
        lrrtt_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    assert_eq!(init_mgr.link_state(&link_id), Some(LinkState::Active));
    assert_eq!(resp_mgr.link_state(&link_id), Some(LinkState::Active));

    (init_mgr, resp_mgr, link_id)
}

#[test]
fn request_size_limit_is_inherited_when_link_is_accepted() {
    let (_init_mgr, resp_mgr, link_id) = setup_active_link_with_max_request_size(Some(321));
    assert_eq!(resp_mgr.links[&link_id].max_request_size, Some(321));
}

#[test]
fn request_size_limit_updates_existing_responder_links() {
    let (_init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let dest_hash = resp_mgr.links[&link_id].dest_hash;
    assert!(resp_mgr.set_link_destination_max_request_size(&dest_hash, Some(654)));
    assert_eq!(resp_mgr.links[&link_id].max_request_size, Some(654));
}

#[test]
fn setting_request_size_limit_for_unknown_destination_fails() {
    let mut mgr = LinkManager::new();
    assert!(!mgr.set_link_destination_max_request_size(&[0xEE; 16], Some(1)));
}

fn packed_keepalive(link_id: &LinkId, payload: &[u8]) -> (Vec<u8>, RawPacket) {
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_LINK,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let (raw, _) = RawPacket::pack_raw_with_hash(
        flags,
        0,
        link_id,
        None,
        constants::CONTEXT_KEEPALIVE,
        payload,
    )
    .unwrap();
    let packet = RawPacket::unpack(&raw).unwrap();
    (raw, packet)
}

fn keepalive_packets(actions: &[LinkManagerAction]) -> Vec<RawPacket> {
    actions
        .iter()
        .filter_map(|action| match action {
            LinkManagerAction::SendPacket { raw, .. } => RawPacket::unpack(raw).ok(),
            _ => None,
        })
        .filter(|packet| packet.context == constants::CONTEXT_KEEPALIVE)
        .collect()
}

#[test]
fn initiator_tick_emits_ff_keepalive_probe_when_outbound_is_quiet() {
    let (mut initiator, _, link_id) = setup_active_link();
    let now = time::now();
    let keepalive = initiator.links[&link_id].engine.keepalive_interval();
    let engine = &mut initiator.links.get_mut(&link_id).unwrap().engine;
    engine.record_inbound(now);
    engine.record_outbound(now - keepalive - 1.0, true);

    let packets = keepalive_packets(&initiator.tick(&mut OsRng));
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].data, [0xff]);
}

#[test]
fn responder_tick_never_originates_keepalive_probe() {
    let (_, mut responder, link_id) = setup_active_link();
    let now = time::now();
    let keepalive = responder.links[&link_id].engine.keepalive_interval();
    let engine = &mut responder.links.get_mut(&link_id).unwrap().engine;
    engine.record_inbound(now - keepalive - 1.0);
    engine.record_outbound(now - keepalive - 1.0, false);

    assert!(keepalive_packets(&responder.tick(&mut OsRng)).is_empty());
}

#[test]
fn responder_acknowledges_ff_probe_after_outbound_silence() {
    let (_, mut responder, link_id) = setup_active_link();
    let now = time::now();
    let keepalive = responder.links[&link_id].engine.keepalive_interval();
    responder
        .links
        .get_mut(&link_id)
        .unwrap()
        .engine
        .record_outbound(now - keepalive - 1.0, false);
    let (raw, packet) = packed_keepalive(&link_id, &[0xff]);

    let actions = responder.handle_local_delivery(
        packet.destination_hash,
        &raw,
        packet.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut OsRng,
    );
    let packets = keepalive_packets(&actions);
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].data, [0xfe]);
}

#[test]
fn recent_responder_traffic_suppresses_keepalive_ack() {
    let (_, mut responder, link_id) = setup_active_link();
    responder
        .links
        .get_mut(&link_id)
        .unwrap()
        .engine
        .record_outbound(time::now(), false);
    let (raw, packet) = packed_keepalive(&link_id, &[0xff]);

    let actions = responder.handle_local_delivery(
        packet.destination_hash,
        &raw,
        packet.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut OsRng,
    );
    assert!(keepalive_packets(&actions).is_empty());
}

#[test]
fn keepalive_ack_does_not_create_ping_pong_reply() {
    let (mut initiator, _, link_id) = setup_active_link();
    let (raw, packet) = packed_keepalive(&link_id, &[0xfe]);

    let actions = initiator.handle_local_delivery(
        packet.destination_hash,
        &raw,
        packet.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut OsRng,
    );
    assert!(keepalive_packets(&actions).is_empty());
}

// ====================================================================
// Phase 8a: Resource wiring tests
// ====================================================================

#[test]
fn test_resource_strategy_default() {
    let mut mgr = LinkManager::new();
    let mut rng = OsRng;
    let dummy_sig = [0xAA; 32];
    let (link_id, _) = mgr.create_link(&[0x11; 16], &dummy_sig, 1, constants::MTU as u32, &mut rng);

    // Default strategy is AcceptNone
    let link = mgr.links.get(&link_id).unwrap();
    assert_eq!(link.resource_strategy, ResourceStrategy::AcceptNone);
}

#[test]
fn test_set_resource_strategy() {
    let mut mgr = LinkManager::new();
    let mut rng = OsRng;
    let dummy_sig = [0xAA; 32];
    let (link_id, _) = mgr.create_link(&[0x11; 16], &dummy_sig, 1, constants::MTU as u32, &mut rng);

    mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);
    assert_eq!(
        mgr.links.get(&link_id).unwrap().resource_strategy,
        ResourceStrategy::AcceptAll
    );

    mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptApp);
    assert_eq!(
        mgr.links.get(&link_id).unwrap().resource_strategy,
        ResourceStrategy::AcceptApp
    );
}

#[test]
fn test_send_resource_on_active_link() {
    let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    // Send resource data
    let data = vec![0xAB; 100]; // small enough for a single part
    let actions = init_mgr.send_resource(&link_id, &data, None, &mut rng);

    // Should produce at least a SendPacket (advertisement)
    let has_send = actions
        .iter()
        .any(|a| matches!(a, LinkManagerAction::SendPacket { .. }));
    assert!(
        has_send,
        "send_resource should emit advertisement SendPacket"
    );
}

#[test]
fn test_large_send_request_uses_request_resource() {
    let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    let data = vec![0xAB; 2048];
    let actions = init_mgr.send_request(&link_id, "/large", &data, &mut rng);

    let adv = first_resource_advertisement(&init_mgr, &link_id, &actions);
    assert!(adv.is_request());
    assert!(!adv.is_response());
    assert_eq!(adv.request_id.as_ref().map(Vec::len), Some(16));
    let request_id = LinkManager::response_request_id(&adv.request_id).unwrap();
    assert_eq!(
        init_mgr.links[&link_id]
            .pending_requests
            .get(&request_id)
            .and_then(|request| request.deadline),
        None,
        "resource request timeout must wait for delivery proof"
    );
    assert!(init_mgr.links[&link_id]
        .pending_requests
        .contains_key(&request_id));

    let has_request_packet = actions.iter().any(|action| match action {
        LinkManagerAction::SendPacket { raw, .. } => RawPacket::unpack(raw)
            .map(|pkt| pkt.context == constants::CONTEXT_REQUEST)
            .unwrap_or(false),
        _ => false,
    });
    assert!(!has_request_packet);
}

#[test]
fn unanswered_packet_request_expires_from_pending_set() {
    let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let actions = init_mgr.send_request(&link_id, "/no-response", b"\xc0", &mut rng);
    let raw = extract_any_send_packet(&actions);
    let request_id = RawPacket::unpack(&raw).unwrap().get_truncated_hash();
    assert!(init_mgr.links[&link_id]
        .pending_requests
        .get(&request_id)
        .is_some_and(|request| request.deadline.is_some()));

    init_mgr
        .links
        .get_mut(&link_id)
        .unwrap()
        .pending_requests
        .get_mut(&request_id)
        .unwrap()
        .deadline = Some(time::now() - 1.0);
    init_mgr.tick(&mut rng);

    assert!(!init_mgr.links[&link_id]
        .pending_requests
        .contains_key(&request_id));
}

#[test]
fn invalid_resource_advertisement_tears_down_link_once() {
    let (_init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    let actions = resp_mgr.handle_resource_adv(&link_id, &[0xc1], &mut rng);

    assert_eq!(resp_mgr.link_state(&link_id), Some(LinkState::Closed));
    assert_eq!(
        actions
            .iter()
            .filter(|action| matches!(action, LinkManagerAction::LinkClosed { .. }))
            .count(),
        1
    );
    assert!(resp_mgr
        .handle_resource_adv(&link_id, &[0xc1], &mut rng)
        .is_empty());
}

#[test]
fn oversized_resource_advertisement_tears_down_link() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let adv_actions = init_mgr.send_resource_with_auto_compress(
        &link_id,
        &deterministic_bytes(1024),
        None,
        false,
        &mut rng,
    );
    let mut adv = first_resource_advertisement(&init_mgr, &link_id, &adv_actions);
    adv.transfer_size = (constants::RESOURCE_MAX_EFFICIENT_SIZE * 3 + 1) as u64;

    let actions = resp_mgr.handle_resource_adv(&link_id, &adv.pack(0), &mut rng);

    assert_eq!(resp_mgr.link_state(&link_id), Some(LinkState::Closed));
    assert!(actions
        .iter()
        .any(|action| matches!(action, LinkManagerAction::LinkClosed { .. })));
}

#[test]
fn request_resource_without_any_handler_is_ignored() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let data = deterministic_bytes(4096);

    let adv_actions = init_mgr.send_request(&link_id, "/missing", &data, &mut rng);
    let adv_raw = extract_any_send_packet(&adv_actions);
    let adv_pkt = RawPacket::unpack(&adv_raw).unwrap();
    assert_eq!(adv_pkt.context, constants::CONTEXT_RESOURCE_ADV);

    let actions = resp_mgr.handle_local_delivery(
        adv_pkt.destination_hash,
        &adv_raw,
        adv_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    assert!(
        actions.is_empty(),
        "unhandled request resource must be ignored"
    );
    assert!(resp_mgr.links[&link_id].incoming_resources.is_empty());
}

#[test]
fn request_resource_at_exact_declared_size_limit_is_accepted() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    resp_mgr.register_request_handler("/bounded", None, |_, _, _, _| None);
    let request = deterministic_bytes(4096);
    let adv_actions = init_mgr.send_request(&link_id, "/bounded", &request, &mut rng);
    let adv = first_resource_advertisement(&init_mgr, &link_id, &adv_actions);
    resp_mgr.links.get_mut(&link_id).unwrap().max_request_size = Some(adv.data_size as usize);
    let raw = extract_any_send_packet(&adv_actions);
    let packet = RawPacket::unpack(&raw).unwrap();

    let actions = resp_mgr.handle_local_delivery(
        packet.destination_hash,
        &raw,
        packet.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    assert!(
        !actions.is_empty(),
        "accepted resource should request parts"
    );
    assert_eq!(resp_mgr.links[&link_id].incoming_resources.len(), 1);
}

#[test]
fn request_resource_one_byte_over_declared_size_limit_is_rejected() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    resp_mgr.register_request_handler("/bounded", None, |_, _, _, _| None);
    let adv_actions =
        init_mgr.send_request(&link_id, "/bounded", &deterministic_bytes(4096), &mut rng);
    let adv = first_resource_advertisement(&init_mgr, &link_id, &adv_actions);
    resp_mgr.links.get_mut(&link_id).unwrap().max_request_size = Some(adv.data_size as usize - 1);
    let raw = extract_any_send_packet(&adv_actions);
    let packet = RawPacket::unpack(&raw).unwrap();

    let actions = resp_mgr.handle_local_delivery(
        packet.destination_hash,
        &raw,
        packet.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    assert!(!actions.is_empty(), "rejected resource should send an RCL");
    assert!(resp_mgr.links[&link_id].incoming_resources.is_empty());
}

#[test]
fn request_size_limit_does_not_reject_ordinary_resources() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let link = resp_mgr.links.get_mut(&link_id).unwrap();
    link.max_request_size = Some(0);
    link.resource_strategy = ResourceStrategy::AcceptAll;
    let adv_actions = init_mgr.send_resource_with_auto_compress(
        &link_id,
        &deterministic_bytes(4096),
        None,
        false,
        &mut rng,
    );
    let raw = extract_any_send_packet(&adv_actions);
    let packet = RawPacket::unpack(&raw).unwrap();

    let actions = resp_mgr.handle_local_delivery(
        packet.destination_hash,
        &raw,
        packet.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    assert!(!actions.is_empty(), "ordinary resource should be accepted");
    assert_eq!(resp_mgr.links[&link_id].incoming_resources.len(), 1);
}

#[test]
fn unsolicited_response_resource_is_ignored() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let unsolicited_id = [0xEF; 16];

    let adv_actions = resp_mgr.send_response_resource(
        &link_id,
        &unsolicited_id,
        &deterministic_bytes(4096),
        None,
        false,
        &mut rng,
    );
    let adv_raw = extract_any_send_packet(&adv_actions);
    let adv_pkt = RawPacket::unpack(&adv_raw).unwrap();
    let actions = init_mgr.handle_local_delivery(
        adv_pkt.destination_hash,
        &adv_raw,
        adv_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    assert!(
        actions.is_empty(),
        "unsolicited response resource must be ignored"
    );
    assert!(init_mgr.links[&link_id].incoming_resources.is_empty());
}

#[test]
fn resource_packets_are_suppressed_after_link_closes() {
    let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    init_mgr.send_resource_with_auto_compress(
        &link_id,
        &deterministic_bytes(4096),
        None,
        false,
        &mut rng,
    );
    init_mgr
        .links
        .get_mut(&link_id)
        .unwrap()
        .engine
        .handle_teardown();

    for action in [
        ResourceAction::SendAdvertisement(vec![1]),
        ResourceAction::SendPart(vec![2]),
        ResourceAction::SendRequest(vec![3]),
        ResourceAction::SendHmu(vec![4]),
        ResourceAction::SendProof(vec![5; 64]),
    ] {
        let emitted = init_mgr.process_resource_actions(&link_id, vec![action], &mut rng);
        assert!(
            !emitted
                .iter()
                .any(|item| matches!(item, LinkManagerAction::SendPacket { .. })),
            "closed link emitted a resource packet"
        );
    }
    assert!(init_mgr.links[&link_id]
        .outgoing_resources
        .iter()
        .all(|sender| sender.status == rns_core::resource::ResourceStatus::Failed));
}

#[test]
fn large_request_resource_reaches_registered_handler_and_returns_response() {
    use std::sync::{Arc, Mutex};

    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let request_value =
        rns_core::msgpack::pack(&rns_core::msgpack::Value::Bin(deterministic_bytes(4096)));
    let observed = Arc::new(Mutex::new(None));
    resp_mgr.register_request_handler("/large-request", None, {
        let observed = Arc::clone(&observed);
        move |_link_id, _path, data, _remote| {
            *observed.lock().unwrap() = Some(data.to_vec());
            Some(rns_core::msgpack::pack(&rns_core::msgpack::Value::Bool(
                true,
            )))
        }
    });

    let initial = init_mgr.send_request(&link_id, "/large-request", &request_value, &mut rng);
    let mut pending: Vec<(char, LinkManagerAction)> =
        initial.into_iter().map(|action| ('i', action)).collect();
    let mut response = None;

    for _ in 0..300 {
        if pending.is_empty() || response.is_some() {
            break;
        }
        let mut next = Vec::new();
        for (source, action) in pending.drain(..) {
            let LinkManagerAction::SendPacket { raw, .. } = action else {
                continue;
            };
            let packet = RawPacket::unpack(&raw).unwrap();
            let actions = if source == 'i' {
                resp_mgr.handle_local_delivery(
                    packet.destination_hash,
                    &raw,
                    packet.packet_hash,
                    rns_core::transport::types::InterfaceId(0),
                    &mut rng,
                )
            } else {
                init_mgr.handle_local_delivery(
                    packet.destination_hash,
                    &raw,
                    packet.packet_hash,
                    rns_core::transport::types::InterfaceId(0),
                    &mut rng,
                )
            };
            for action in &actions {
                if let LinkManagerAction::ResponseReceived { data, .. } = action {
                    response = Some(data.clone());
                }
                assert!(!matches!(
                    action,
                    LinkManagerAction::ResourceAcceptQuery { .. }
                ));
            }
            let next_source = if source == 'i' { 'r' } else { 'i' };
            next.extend(actions.into_iter().map(|action| (next_source, action)));
        }
        pending = next;
    }

    assert_eq!(*observed.lock().unwrap(), Some(request_value));
    assert_eq!(
        response,
        Some(rns_core::msgpack::pack(&rns_core::msgpack::Value::Bool(
            true
        )))
    );
    assert!(init_mgr.links[&link_id].pending_requests.is_empty());
}

fn first_resource_advertisement(
    mgr: &LinkManager,
    link_id: &LinkId,
    actions: &[LinkManagerAction],
) -> rns_core::resource::ResourceAdvertisement {
    let adv_raw = actions
        .iter()
        .find_map(|action| match action {
            LinkManagerAction::SendPacket { raw, .. } => {
                let pkt = RawPacket::unpack(raw).ok()?;
                (pkt.context == constants::CONTEXT_RESOURCE_ADV).then_some(raw)
            }
            _ => None,
        })
        .expect("sender should emit a resource advertisement");
    let adv_pkt = RawPacket::unpack(adv_raw).unwrap();
    let plaintext = mgr
        .links
        .get(link_id)
        .unwrap()
        .engine
        .decrypt(&adv_pkt.data)
        .unwrap();
    rns_core::resource::ResourceAdvertisement::unpack(&plaintext).unwrap()
}

fn deterministic_bytes(len: usize) -> Vec<u8> {
    let mut state = 0x1234_5678u32;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            (state >> 16) as u8
        })
        .collect()
}

struct CountingReader {
    inner: std::io::Cursor<Vec<u8>>,
    bytes_read: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Read for CountingReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.bytes_read
            .fetch_add(count, std::sync::atomic::Ordering::Relaxed);
        Ok(count)
    }
}

#[test]
fn streaming_resource_reads_one_segment_at_a_time_and_receives_to_disk() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let directory = tempfile::tempdir().unwrap();
    resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);
    resp_mgr.set_resource_receive_mode(
        &link_id,
        ResourceReceiveMode::TemporaryFile {
            directory: directory.path().to_path_buf(),
            max_bytes: None,
        },
    );

    let data = deterministic_bytes(constants::RESOURCE_MAX_EFFICIENT_SIZE * 2 + 12345);
    let bytes_read = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reader = CountingReader {
        inner: std::io::Cursor::new(data.clone()),
        bytes_read: bytes_read.clone(),
    };
    let initial = init_mgr.send_resource_stream(
        &link_id,
        ResourceTransferId(42),
        Box::new(reader),
        data.len() as u64,
        None,
        false,
        &mut rng,
    );

    assert_eq!(
        bytes_read.load(std::sync::atomic::Ordering::Relaxed),
        constants::RESOURCE_MAX_EFFICIENT_SIZE,
        "starting a stream must not consume later segments"
    );
    assert_eq!(init_mgr.links[&link_id].outgoing_resources.len(), 1);

    let (received, completed, _progress, failures, _rounds) =
        drive_link_manager_packets(&mut init_mgr, &mut resp_mgr, initial, 'i', &mut rng, 30_000);
    assert_eq!(received, Some(data));
    assert!(completed);
    assert!(
        failures.is_empty(),
        "streaming transfer failed: {failures:?}"
    );
    assert_eq!(
        bytes_read.load(std::sync::atomic::Ordering::Relaxed),
        constants::RESOURCE_MAX_EFFICIENT_SIZE * 2 + 12345
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

type DrivenPackets = (
    Option<Vec<u8>>,
    bool,
    Vec<(char, usize, usize)>,
    Vec<(char, String)>,
    usize,
);

fn drive_link_manager_packets(
    init_mgr: &mut LinkManager,
    resp_mgr: &mut LinkManager,
    initial_actions: Vec<LinkManagerAction>,
    initial_source: char,
    rng: &mut dyn Rng,
    max_rounds: usize,
) -> DrivenPackets {
    let mut pending: Vec<(char, LinkManagerAction)> = initial_actions
        .into_iter()
        .map(|a| (initial_source, a))
        .collect();
    let mut rounds = 0;
    let mut received_data = None;
    let mut sender_completed = false;
    let mut progress = Vec::new();
    let mut failures = Vec::new();

    while !pending.is_empty() && rounds < max_rounds {
        rounds += 1;
        let mut next = Vec::new();
        for (source, action) in pending.drain(..) {
            let LinkManagerAction::SendPacket { raw, .. } = action else {
                continue;
            };
            let pkt = RawPacket::unpack(&raw).unwrap();
            let target_actions = if source == 'i' {
                resp_mgr.handle_local_delivery(
                    pkt.destination_hash,
                    &raw,
                    pkt.packet_hash,
                    rns_core::transport::types::InterfaceId(0),
                    rng,
                )
            } else {
                init_mgr.handle_local_delivery(
                    pkt.destination_hash,
                    &raw,
                    pkt.packet_hash,
                    rns_core::transport::types::InterfaceId(0),
                    rng,
                )
            };
            let target_source = if source == 'i' { 'r' } else { 'i' };
            for action in &target_actions {
                match action {
                    LinkManagerAction::ResourceReceived { data, .. } => {
                        received_data = Some(data.clone());
                    }
                    LinkManagerAction::ResourceFileReceived { resource, .. } => {
                        received_data = Some(std::fs::read(resource.path()).unwrap());
                    }
                    LinkManagerAction::ResourceCompleted { .. } => {
                        sender_completed = true;
                    }
                    LinkManagerAction::ResourceStreamCompleted { .. } => {
                        sender_completed = true;
                    }
                    LinkManagerAction::ResourceProgress {
                        received, total, ..
                    } => {
                        progress.push((target_source, *received, *total));
                    }
                    LinkManagerAction::ResourceFailed { error, .. } => {
                        failures.push((target_source, error.clone()));
                    }
                    LinkManagerAction::ResourceStreamFailed { error, .. } => {
                        failures.push((target_source, format!("{error:?}")));
                    }
                    _ => {}
                }
            }
            next.extend(target_actions.into_iter().map(|a| (target_source, a)));
        }
        pending = next;
    }

    (received_data, sender_completed, progress, failures, rounds)
}

#[test]
fn test_send_resource_auto_compress_option_controls_adv_flag() {
    let data = vec![0x41; 2048];

    let (mut compressed_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let actions =
        compressed_mgr.send_resource_with_auto_compress(&link_id, &data, None, true, &mut rng);
    let adv = first_resource_advertisement(&compressed_mgr, &link_id, &actions);
    assert!(
        adv.flags.compressed,
        "compressible resource should compress"
    );

    let (mut plain_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let actions =
        plain_mgr.send_resource_with_auto_compress(&link_id, &data, None, false, &mut rng);
    let adv = first_resource_advertisement(&plain_mgr, &link_id, &actions);
    assert!(
        !adv.flags.compressed,
        "auto_compress=false should keep resource uncompressed"
    );
}

#[test]
fn test_send_resource_on_inactive_link() {
    let mut mgr = LinkManager::new();
    let mut rng = OsRng;
    let dummy_sig = [0xAA; 32];
    let (link_id, _) = mgr.create_link(&[0x11; 16], &dummy_sig, 1, constants::MTU as u32, &mut rng);

    // Link is Pending, not Active
    let actions = mgr.send_resource(&link_id, b"data", None, &mut rng);
    assert!(actions.is_empty(), "Cannot send resource on inactive link");
}

#[test]
fn test_send_resource_without_session_key_uses_encrypt_fallback_path() {
    let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    init_mgr
        .links
        .get_mut(&link_id)
        .unwrap()
        .engine
        .clear_session_for_testing();

    let actions = init_mgr.send_resource(&link_id, b"data", None, &mut rng);

    assert!(
        actions.is_empty(),
        "without a session key, no advertisement should be emitted"
    );
    assert_eq!(
        init_mgr
            .links
            .get(&link_id)
            .map(|managed| managed.outgoing_resources.len()),
        Some(1)
    );
}

#[test]
fn test_resource_adv_rejected_by_accept_none() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    // Responder uses default AcceptNone strategy
    // Send resource from initiator
    let data = vec![0xCD; 100];
    let adv_actions = init_mgr.send_resource(&link_id, &data, None, &mut rng);

    // Deliver advertisement to responder
    for action in &adv_actions {
        if let LinkManagerAction::SendPacket { raw, .. } = action {
            let pkt = RawPacket::unpack(raw).unwrap();
            let resp_actions = resp_mgr.handle_local_delivery(
                pkt.destination_hash,
                raw,
                pkt.packet_hash,
                rns_core::transport::types::InterfaceId(0),
                &mut rng,
            );
            // AcceptNone: should not produce ResourceReceived, may produce SendPacket (RCL)
            let has_resource_received = resp_actions
                .iter()
                .any(|a| matches!(a, LinkManagerAction::ResourceReceived { .. }));
            assert!(
                !has_resource_received,
                "AcceptNone should not accept resource"
            );
        }
    }
}

#[test]
fn test_resource_adv_accepted_by_accept_all() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    // Set responder to AcceptAll
    resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);

    // Send resource from initiator
    let data = vec![0xCD; 100];
    let adv_actions = init_mgr.send_resource(&link_id, &data, None, &mut rng);

    // Deliver advertisement to responder
    for action in &adv_actions {
        if let LinkManagerAction::SendPacket { raw, .. } = action {
            let pkt = RawPacket::unpack(raw).unwrap();
            let resp_actions = resp_mgr.handle_local_delivery(
                pkt.destination_hash,
                raw,
                pkt.packet_hash,
                rns_core::transport::types::InterfaceId(0),
                &mut rng,
            );
            // AcceptAll: should accept and produce a SendPacket (request for parts)
            let has_send = resp_actions
                .iter()
                .any(|a| matches!(a, LinkManagerAction::SendPacket { .. }));
            assert!(has_send, "AcceptAll should accept and request parts");
        }
    }
}

#[test]
fn test_resource_accept_app_query() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    // Set responder to AcceptApp
    resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptApp);

    // Send resource from initiator
    let data = vec![0xCD; 100];
    let adv_actions = init_mgr.send_resource(&link_id, &data, None, &mut rng);

    // Deliver advertisement to responder
    let mut got_query = false;
    for action in &adv_actions {
        if let LinkManagerAction::SendPacket { raw, .. } = action {
            let pkt = RawPacket::unpack(raw).unwrap();
            let resp_actions = resp_mgr.handle_local_delivery(
                pkt.destination_hash,
                raw,
                pkt.packet_hash,
                rns_core::transport::types::InterfaceId(0),
                &mut rng,
            );
            for a in &resp_actions {
                if matches!(a, LinkManagerAction::ResourceAcceptQuery { .. }) {
                    got_query = true;
                }
            }
        }
    }
    assert!(got_query, "AcceptApp should emit ResourceAcceptQuery");
}

#[test]
fn test_resource_accept_app_accept() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptApp);

    let data = vec![0xCD; 100];
    let adv_actions = init_mgr.send_resource(&link_id, &data, None, &mut rng);

    for action in &adv_actions {
        if let LinkManagerAction::SendPacket { raw, .. } = action {
            let pkt = RawPacket::unpack(raw).unwrap();
            let resp_actions = resp_mgr.handle_local_delivery(
                pkt.destination_hash,
                raw,
                pkt.packet_hash,
                rns_core::transport::types::InterfaceId(0),
                &mut rng,
            );
            for a in &resp_actions {
                if let LinkManagerAction::ResourceAcceptQuery {
                    link_id: lid,
                    resource_hash,
                    ..
                } = a
                {
                    // Accept the resource
                    let accept_actions =
                        resp_mgr.accept_resource(lid, resource_hash, true, &mut rng);
                    // Should produce a SendPacket (request for parts)
                    let has_send = accept_actions
                        .iter()
                        .any(|a| matches!(a, LinkManagerAction::SendPacket { .. }));
                    assert!(
                        has_send,
                        "Accepting resource should produce request for parts"
                    );
                }
            }
        }
    }
}

#[test]
fn test_resource_accept_app_reject() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptApp);

    let data = vec![0xCD; 100];
    let adv_actions = init_mgr.send_resource(&link_id, &data, None, &mut rng);

    for action in &adv_actions {
        if let LinkManagerAction::SendPacket { raw, .. } = action {
            let pkt = RawPacket::unpack(raw).unwrap();
            let resp_actions = resp_mgr.handle_local_delivery(
                pkt.destination_hash,
                raw,
                pkt.packet_hash,
                rns_core::transport::types::InterfaceId(0),
                &mut rng,
            );
            for a in &resp_actions {
                if let LinkManagerAction::ResourceAcceptQuery {
                    link_id: lid,
                    resource_hash,
                    ..
                } = a
                {
                    // Reject the resource
                    let reject_actions =
                        resp_mgr.accept_resource(lid, resource_hash, false, &mut rng);
                    // Rejecting should send a cancel and not request parts
                    // No ResourceReceived should appear
                    let has_resource_received = reject_actions
                        .iter()
                        .any(|a| matches!(a, LinkManagerAction::ResourceReceived { .. }));
                    assert!(!has_resource_received);
                }
            }
        }
    }
}

#[test]
fn test_resource_full_transfer() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    // Set responder to AcceptAll
    resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);

    // Small data (fits in single SDU)
    let original_data = b"Hello, Resource Transfer!".to_vec();
    let adv_actions = init_mgr.send_resource(&link_id, &original_data, None, &mut rng);

    // Drive the full transfer protocol between the two managers.
    // Tag each SendPacket with its source ('i' = initiator, 'r' = responder).
    let mut pending: Vec<(char, LinkManagerAction)> =
        adv_actions.into_iter().map(|a| ('i', a)).collect();
    let mut rounds = 0;
    let max_rounds = 50;
    let mut resource_received = false;
    let mut sender_completed = false;

    while !pending.is_empty() && rounds < max_rounds {
        rounds += 1;
        let mut next: Vec<(char, LinkManagerAction)> = Vec::new();

        for (source, action) in pending.drain(..) {
            if let LinkManagerAction::SendPacket { raw, .. } = action {
                let pkt = RawPacket::unpack(&raw).unwrap();

                // Deliver only to the OTHER side
                let target_actions = if source == 'i' {
                    resp_mgr.handle_local_delivery(
                        pkt.destination_hash,
                        &raw,
                        pkt.packet_hash,
                        rns_core::transport::types::InterfaceId(0),
                        &mut rng,
                    )
                } else {
                    init_mgr.handle_local_delivery(
                        pkt.destination_hash,
                        &raw,
                        pkt.packet_hash,
                        rns_core::transport::types::InterfaceId(0),
                        &mut rng,
                    )
                };

                let target_source = if source == 'i' { 'r' } else { 'i' };
                for a in &target_actions {
                    match a {
                        LinkManagerAction::ResourceReceived { data, .. } => {
                            assert_eq!(*data, original_data);
                            resource_received = true;
                        }
                        LinkManagerAction::ResourceCompleted { .. } => {
                            sender_completed = true;
                        }
                        _ => {}
                    }
                }
                next.extend(target_actions.into_iter().map(|a| (target_source, a)));
            }
        }
        pending = next;
    }

    assert!(
        resource_received,
        "Responder should receive resource data (rounds={})",
        rounds
    );
    assert!(
        sender_completed,
        "Sender should get completion proof (rounds={})",
        rounds
    );
}

#[test]
fn test_split_resource_advertisement_and_progress_entries() {
    let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let data = deterministic_bytes(constants::RESOURCE_MAX_EFFICIENT_SIZE + 1024);

    let actions = init_mgr.send_resource_with_auto_compress(&link_id, &data, None, false, &mut rng);
    let adv = first_resource_advertisement(&init_mgr, &link_id, &actions);

    assert!(adv.flags.split);
    assert_eq!(adv.segment_index, 1);
    assert_eq!(adv.total_segments, 2);
    assert_eq!(adv.data_size, data.len() as u64);

    let managed = init_mgr.links.get(&link_id).unwrap();
    assert_eq!(managed.outgoing_splits.len(), 1);
    assert_eq!(
        managed
            .outgoing_resources
            .iter()
            .filter(|sender| sender.flags.split)
            .count(),
        2
    );

    let entries = init_mgr.resource_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].direction, "outgoing");
    assert!(entries[0].total_parts > managed.outgoing_resources[0].total_parts());
    assert_eq!(entries[0].transferred_parts, 0);
}

#[test]
fn test_split_resource_full_transfer_and_monotonic_progress() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);

    let original_data = deterministic_bytes(constants::RESOURCE_MAX_EFFICIENT_SIZE + 2048);
    let initial_actions =
        init_mgr.send_resource_with_auto_compress(&link_id, &original_data, None, false, &mut rng);

    let (received_data, sender_completed, progress, failures, rounds) = drive_link_manager_packets(
        &mut init_mgr,
        &mut resp_mgr,
        initial_actions,
        'i',
        &mut rng,
        10_000,
    );

    assert!(
            received_data.as_ref().is_some_and(|data| data == &original_data),
            "split transfer did not deliver payload in {rounds} rounds; sender_completed={sender_completed}; failures={failures:?}; last_progress={:?}; init_entries={:?}; resp_entries={:?}",
            progress.last(),
            init_mgr.resource_entries(),
            resp_mgr.resource_entries()
        );
    assert!(
        sender_completed,
        "sender did not complete in {rounds} rounds"
    );
    assert!(
        progress
            .iter()
            .any(|(_, received, total)| received == total),
        "expected final progress update"
    );

    let mut init_last = 0;
    let mut resp_last = 0;
    for (side, received, total) in progress {
        assert!(received <= total);
        match side {
            'i' => {
                assert!(
                    received >= init_last,
                    "initiator progress regressed from {init_last} to {received}"
                );
                init_last = received;
            }
            'r' => {
                assert!(
                    received >= resp_last,
                    "responder progress regressed from {resp_last} to {received}"
                );
                resp_last = received;
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn test_split_resource_accept_app_queries_only_first_segment() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptApp);

    let original_data = deterministic_bytes(constants::RESOURCE_MAX_EFFICIENT_SIZE + 1024);
    let adv_actions =
        init_mgr.send_resource_with_auto_compress(&link_id, &original_data, None, false, &mut rng);
    let adv_raw = extract_any_send_packet(&adv_actions);
    let adv_pkt = RawPacket::unpack(&adv_raw).unwrap();
    let query_actions = resp_mgr.handle_local_delivery(
        adv_pkt.destination_hash,
        &adv_raw,
        adv_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    let queries: Vec<_> = query_actions
        .iter()
        .filter_map(|action| match action {
            LinkManagerAction::ResourceAcceptQuery { resource_hash, .. } => {
                Some(resource_hash.clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(queries.len(), 1);

    let accept_actions = resp_mgr.accept_resource(&link_id, &queries[0], true, &mut rng);
    let (received_data, sender_completed, _progress, failures, rounds) = drive_link_manager_packets(
        &mut init_mgr,
        &mut resp_mgr,
        accept_actions,
        'r',
        &mut rng,
        10_000,
    );

    assert!(
        failures.is_empty(),
        "split AcceptApp transfer failed: {failures:?}"
    );
    assert!(
        received_data
            .as_ref()
            .is_some_and(|data| data == &original_data),
        "split AcceptApp transfer did not deliver in {rounds} rounds"
    );
    assert!(sender_completed);
}

#[test]
fn test_resource_cancel_icl() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);

    // Use large data so transfer is multi-part
    let data = vec![0xAB; 2000];
    let adv_actions = init_mgr.send_resource(&link_id, &data, None, &mut rng);

    // Deliver advertisement — responder accepts and sends request
    for action in &adv_actions {
        if let LinkManagerAction::SendPacket { raw, .. } = action {
            let pkt = RawPacket::unpack(raw).unwrap();
            resp_mgr.handle_local_delivery(
                pkt.destination_hash,
                raw,
                pkt.packet_hash,
                rns_core::transport::types::InterfaceId(0),
                &mut rng,
            );
        }
    }

    // Verify there are incoming resources on the responder
    assert!(!resp_mgr
        .links
        .get(&link_id)
        .unwrap()
        .incoming_resources
        .is_empty());

    // Simulate ICL (cancel from initiator side) by calling handle_resource_icl
    let icl_actions = resp_mgr.handle_resource_icl(&link_id);

    // Should have resource failed
    let has_failed = icl_actions
        .iter()
        .any(|a| matches!(a, LinkManagerAction::ResourceFailed { .. }));
    assert!(has_failed, "ICL should produce ResourceFailed");
}

#[test]
fn test_resource_cancel_rcl() {
    let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    // Create a resource sender
    let data = vec![0xAB; 2000];
    init_mgr.send_resource(&link_id, &data, None, &mut rng);

    // Verify there are outgoing resources
    assert!(!init_mgr
        .links
        .get(&link_id)
        .unwrap()
        .outgoing_resources
        .is_empty());

    // Simulate RCL (cancel from receiver side)
    let rcl_actions = init_mgr.handle_resource_rcl(&link_id);

    let has_failed = rcl_actions
        .iter()
        .any(|a| matches!(a, LinkManagerAction::ResourceFailed { .. }));
    assert!(has_failed, "RCL should produce ResourceFailed");
}

#[test]
fn test_cancel_all_resources_clears_active_transfers() {
    let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    let actions = init_mgr.send_resource(&link_id, b"resource body", None, &mut rng);
    assert!(!actions.is_empty());
    assert_eq!(init_mgr.resource_transfer_count(), 1);

    let cancel_actions = init_mgr.cancel_all_resources(&mut rng);

    assert_eq!(init_mgr.resource_transfer_count(), 0);
    assert!(cancel_actions.iter().any(|action| match action {
        LinkManagerAction::SendPacket { raw, .. } => RawPacket::unpack(raw)
            .map(|packet| packet.context == constants::CONTEXT_RESOURCE_ICL)
            .unwrap_or(false),
        _ => false,
    }));
}

#[test]
fn cancelling_stream_reports_one_terminal_failure() {
    let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let transfer_id = ResourceTransferId(42);
    let length = constants::RESOURCE_MAX_EFFICIENT_SIZE as u64 + 1;
    init_mgr.send_resource_stream(
        &link_id,
        transfer_id,
        Box::new(std::io::Cursor::new(vec![0x5a; length as usize])),
        length,
        None,
        false,
        &mut rng,
    );

    let actions = init_mgr.cancel_all_resources(&mut rng);
    assert_eq!(
        actions
            .iter()
            .filter(|action| matches!(
                action,
                LinkManagerAction::ResourceStreamFailed {
                    transfer_id: failed,
                    error: ResourceTransferError::Cancelled,
                    ..
                } if *failed == transfer_id
            ))
            .count(),
        1
    );
    assert_eq!(init_mgr.resource_transfer_count(), 0);
}

#[test]
fn receiver_cancel_sends_rcl_while_active_and_closed_cleanup_is_local_only() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptApp);

    let advertisement = init_mgr.send_resource(&link_id, b"incoming body", None, &mut rng);
    let raw = extract_any_send_packet(&advertisement);
    let packet = RawPacket::unpack(&raw).unwrap();
    resp_mgr.handle_local_delivery(
        packet.destination_hash,
        &raw,
        packet.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    assert_eq!(resp_mgr.resource_transfer_count(), 1);
    let active_cancel = resp_mgr.cancel_all_resources(&mut rng);
    assert_eq!(resp_mgr.resource_transfer_count(), 0);
    assert!(active_cancel.iter().any(|action| match action {
        LinkManagerAction::SendPacket { raw, .. } => RawPacket::unpack(raw)
            .map(|packet| packet.context == constants::CONTEXT_RESOURCE_RCL)
            .unwrap_or(false),
        _ => false,
    }));

    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptApp);
    let advertisement = init_mgr.send_resource(&link_id, b"second body", None, &mut rng);
    let raw = extract_any_send_packet(&advertisement);
    let packet = RawPacket::unpack(&raw).unwrap();
    resp_mgr.handle_local_delivery(
        packet.destination_hash,
        &raw,
        packet.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    resp_mgr
        .links
        .get_mut(&link_id)
        .unwrap()
        .engine
        .handle_teardown();
    let closed_cancel = resp_mgr.cancel_all_resources(&mut rng);
    assert_eq!(resp_mgr.resource_transfer_count(), 0);
    assert!(!closed_cancel
        .iter()
        .any(|action| matches!(action, LinkManagerAction::SendPacket { .. })));
}

#[test]
fn stale_sender_cancel_cleans_up_without_icl() {
    let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    init_mgr.send_resource(&link_id, b"stale transfer", None, &mut rng);
    init_mgr
        .links
        .get_mut(&link_id)
        .unwrap()
        .engine
        .tick(time::now() + 100_000.0);
    assert_eq!(init_mgr.link_state(&link_id), Some(LinkState::Stale));

    let actions = init_mgr.cancel_all_resources(&mut rng);
    assert_eq!(init_mgr.resource_transfer_count(), 0);
    assert!(!actions
        .iter()
        .any(|action| matches!(action, LinkManagerAction::SendPacket { .. })));
}

#[test]
fn test_resource_tick_cleans_up() {
    let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    let data = vec![0xAB; 100];
    init_mgr.send_resource(&link_id, &data, None, &mut rng);

    assert!(!init_mgr
        .links
        .get(&link_id)
        .unwrap()
        .outgoing_resources
        .is_empty());

    // Cancel the sender to make it Complete
    init_mgr.handle_resource_rcl(&link_id);

    // Tick should clean up completed resources
    init_mgr.tick(&mut rng);

    assert!(
        init_mgr
            .links
            .get(&link_id)
            .unwrap()
            .outgoing_resources
            .is_empty(),
        "Tick should clean up completed/failed outgoing resources"
    );
}

#[test]
fn test_build_link_packet() {
    let (init_mgr, _resp_mgr, link_id) = setup_active_link();

    let actions = init_mgr.build_link_packet(&link_id, constants::CONTEXT_RESOURCE, b"test data");
    assert_eq!(actions.len(), 1);
    if let LinkManagerAction::SendPacket { raw, dest_type, .. } = &actions[0] {
        let pkt = RawPacket::unpack(raw).unwrap();
        assert_eq!(pkt.context, constants::CONTEXT_RESOURCE);
        assert_eq!(*dest_type, constants::DESTINATION_LINK);
    } else {
        panic!("Expected SendPacket");
    }
}

#[test]
fn link_traffic_accounting_uses_ciphertext_data_once() {
    let (mut initiator, mut responder, link_id) = setup_active_link();
    let before_tx = initiator.links[&link_id].engine.tx_packets();
    let before_tx_bytes = initiator.links[&link_id].engine.tx_bytes();
    let before_rx = responder.links[&link_id].engine.rx_packets();
    let before_rx_bytes = responder.links[&link_id].engine.rx_bytes();
    let actions = initiator.send_on_link(
        &link_id,
        b"short plaintext",
        constants::CONTEXT_NONE,
        &mut OsRng,
    );
    let raw = actions
        .iter()
        .find_map(|action| match action {
            LinkManagerAction::SendPacket { raw, .. } => Some(raw.clone()),
            _ => None,
        })
        .unwrap();
    let packet = RawPacket::unpack(&raw).unwrap();
    assert!(packet.data.len() > b"short plaintext".len());

    initiator.record_outbound_packet(&packet);
    assert_eq!(initiator.links[&link_id].engine.tx_packets(), before_tx + 1);
    assert_eq!(
        initiator.links[&link_id].engine.tx_bytes(),
        before_tx_bytes + packet.data.len() as u64
    );

    responder.handle_local_delivery(
        link_id,
        &raw,
        packet.packet_hash,
        rns_core::transport::types::InterfaceId(1),
        &mut OsRng,
    );
    assert_eq!(responder.links[&link_id].engine.rx_packets(), before_rx + 1);
    assert_eq!(
        responder.links[&link_id].engine.rx_bytes(),
        before_rx_bytes + packet.data.len() as u64
    );
}

#[test]
fn test_build_link_packet_returns_empty_when_mtu_too_small() {
    let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
    init_mgr.set_link_mtu(&link_id, 84);

    let actions = init_mgr.build_link_packet(&link_id, constants::CONTEXT_RESOURCE, &[0xAA; 200]);
    assert!(actions.is_empty(), "oversized packet should not be built");
}

#[test]
fn test_process_resource_actions_encrypted_variants_drop_on_encrypt_failure() {
    let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    init_mgr
        .links
        .get_mut(&link_id)
        .unwrap()
        .engine
        .clear_session_for_testing();

    let cases = vec![
        ResourceAction::SendAdvertisement(vec![1, 2, 3]),
        ResourceAction::SendRequest(vec![4, 5, 6]),
        ResourceAction::SendHmu(vec![7, 8, 9]),
        ResourceAction::SendCancelInitiator(vec![13, 14, 15]),
        ResourceAction::SendCancelReceiver(vec![16, 17, 18]),
    ];

    for action in cases {
        let out = init_mgr.process_resource_actions(&link_id, vec![action], &mut rng);
        assert!(
            out.is_empty(),
            "encrypt failure should suppress packet emission"
        );
    }
}

#[test]
fn test_resource_proof_is_raw_proof_packet() {
    let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let proof = vec![0x22; 64];

    let out = init_mgr.process_resource_actions(
        &link_id,
        vec![ResourceAction::SendProof(proof.clone())],
        &mut rng,
    );
    let raw = extract_any_send_packet(&out);
    let pkt = RawPacket::unpack(&raw).unwrap();

    assert_eq!(pkt.flags.packet_type, constants::PACKET_TYPE_PROOF);
    assert_eq!(pkt.context, constants::CONTEXT_RESOURCE_PRF);
    assert_eq!(pkt.data, proof);
}

// ====================================================================
// Phase 8b: Channel message & data callback tests
// ====================================================================

#[test]
fn test_channel_message_delivery() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    // Send channel message from initiator
    let chan_actions = init_mgr
        .send_channel_message(&link_id, 42, b"channel data", &mut rng)
        .expect("active link channel send should succeed");
    assert!(!chan_actions.is_empty());

    // Deliver to responder
    let mut got_channel_msg = false;
    for action in &chan_actions {
        if let LinkManagerAction::SendPacket { raw, .. } = action {
            let pkt = RawPacket::unpack(raw).unwrap();
            let resp_actions = resp_mgr.handle_local_delivery(
                pkt.destination_hash,
                raw,
                pkt.packet_hash,
                rns_core::transport::types::InterfaceId(0),
                &mut rng,
            );
            for a in &resp_actions {
                if let LinkManagerAction::ChannelMessageReceived {
                    msgtype, payload, ..
                } = a
                {
                    assert_eq!(*msgtype, 42);
                    assert_eq!(*payload, b"channel data");
                    got_channel_msg = true;
                }
            }
        }
    }
    assert!(got_channel_msg, "Responder should receive channel message");
}

#[test]
fn test_channel_send_drops_packet_when_encrypt_fails() {
    let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    init_mgr
        .links
        .get_mut(&link_id)
        .unwrap()
        .engine
        .clear_session_for_testing();

    let actions = init_mgr
        .send_channel_message(&link_id, 42, b"channel data", &mut rng)
        .expect("channel should still accept the message locally");

    assert!(
        actions.is_empty(),
        "encrypt failure should suppress channel packet"
    );
    assert!(
        init_mgr
            .links
            .get(&link_id)
            .unwrap()
            .pending_channel_packets
            .is_empty(),
        "failed packet encryption must not track a pending channel proof"
    );
}

#[test]
fn test_channel_proof_reopens_send_window() {
    let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    init_mgr
        .send_channel_message(&link_id, 42, b"first", &mut rng)
        .expect("first send should succeed");
    init_mgr
        .send_channel_message(&link_id, 42, b"second", &mut rng)
        .expect("second send should succeed");

    let err = init_mgr
        .send_channel_message(&link_id, 42, b"third", &mut rng)
        .expect_err("third send should hit the initial channel window");
    assert_eq!(err, "Channel is not ready to send");

    let queued_packets = init_mgr
        .links
        .get(&link_id)
        .unwrap()
        .pending_channel_packets
        .clone();
    assert_eq!(queued_packets.len(), 2);
    for tracked_hash in queued_packets.keys().take(1) {
        let mut proof_data = Vec::with_capacity(96);
        proof_data.extend_from_slice(tracked_hash);
        proof_data.extend_from_slice(&[0x11; 64]);
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        let proof = RawPacket::pack(
            flags,
            0,
            &link_id,
            None,
            constants::CONTEXT_NONE,
            &proof_data,
        )
        .expect("proof packet should pack");
        let ack_actions = init_mgr.handle_local_delivery(
            link_id,
            &proof.raw,
            proof.packet_hash,
            rns_core::transport::types::InterfaceId(0),
            &mut rng,
        );
        assert!(
            ack_actions.is_empty(),
            "proof delivery should only update channel state"
        );
    }

    init_mgr
        .send_channel_message(&link_id, 42, b"third", &mut rng)
        .expect("proof should free one channel slot");
}

#[test]
fn test_generic_link_data_delivery() {
    let (init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    // Send generic data with a custom context
    let actions = init_mgr.send_on_link(&link_id, b"raw stuff", 0x42, &mut rng);
    assert_eq!(actions.len(), 1);

    // Deliver to responder
    let raw = extract_any_send_packet(&actions);
    let pkt = RawPacket::unpack(&raw).unwrap();
    let resp_actions = resp_mgr.handle_local_delivery(
        pkt.destination_hash,
        &raw,
        pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    let has_data = resp_actions
        .iter()
        .any(|a| matches!(a, LinkManagerAction::LinkDataReceived { context: 0x42, .. }));
    assert!(
        has_data,
        "Responder should receive LinkDataReceived for unknown context"
    );
}

#[test]
fn test_invalid_encrypted_contexts_are_ignored() {
    let (_init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let contexts = [
        constants::CONTEXT_CHANNEL,
        constants::CONTEXT_REQUEST,
        constants::CONTEXT_RESPONSE,
        constants::CONTEXT_RESOURCE_ADV,
        constants::CONTEXT_RESOURCE_REQ,
        constants::CONTEXT_RESOURCE_HMU,
        constants::CONTEXT_RESOURCE_PRF,
        0x42,
    ];

    for context in contexts {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let pkt = RawPacket::pack(flags, 0, &link_id, None, context, b"invalid-ciphertext")
            .expect("test packet should pack");
        let actions = resp_mgr.handle_local_delivery(
            pkt.destination_hash,
            &pkt.raw,
            pkt.packet_hash,
            rns_core::transport::types::InterfaceId(0),
            &mut rng,
        );
        assert!(
            actions.is_empty(),
            "invalid ciphertext for context {context:#x} should be ignored"
        );
    }
}

#[test]
fn test_resource_part_without_matching_receiver_is_ignored() {
    let (_init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_LINK,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let pkt = RawPacket::pack(
        flags,
        0,
        &link_id,
        None,
        constants::CONTEXT_RESOURCE,
        b"orphan-part",
    )
    .expect("test packet should pack");

    let actions = resp_mgr.handle_local_delivery(
        pkt.destination_hash,
        &pkt.raw,
        pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    assert!(actions.is_empty(), "orphan resource part should be ignored");
}

#[test]
fn test_response_delivery() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    // Register handler on responder
    resp_mgr.register_request_handler("/echo", None, |_link_id, _path, data, _remote| {
        Some(data.to_vec())
    });

    // Send request from initiator
    let req_actions = init_mgr.send_request(&link_id, "/echo", b"\xc0", &mut rng); // msgpack nil
    assert!(!req_actions.is_empty());

    // Deliver request to responder — should produce response
    let req_raw = extract_any_send_packet(&req_actions);
    let req_pkt = RawPacket::unpack(&req_raw).unwrap();
    let resp_actions = resp_mgr.handle_local_delivery(
        req_pkt.destination_hash,
        &req_raw,
        req_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    let has_resp_send = resp_actions
        .iter()
        .any(|a| matches!(a, LinkManagerAction::SendPacket { .. }));
    assert!(has_resp_send, "Handler should produce response");

    // Deliver response back to initiator
    let resp_raw = extract_any_send_packet(&resp_actions);
    let resp_pkt = RawPacket::unpack(&resp_raw).unwrap();
    let init_actions = init_mgr.handle_local_delivery(
        resp_pkt.destination_hash,
        &resp_raw,
        resp_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    let has_response_received = init_actions
        .iter()
        .any(|a| matches!(a, LinkManagerAction::ResponseReceived { .. }));
    assert!(
        has_response_received,
        "Initiator should receive ResponseReceived"
    );
}

#[test]
fn deferred_request_response_round_trip() {
    use std::sync::{Arc, Mutex};

    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let deferred = Arc::new(Mutex::new(None));
    resp_mgr.register_deferred_request_handler("/deferred", None, {
        let deferred = Arc::clone(&deferred);
        move |received_link, _, request_id, data, _| {
            *deferred.lock().unwrap() = Some((received_link, request_id, data.to_vec()));
        }
    });

    let request_actions = init_mgr.send_request(&link_id, "/deferred", b"\xa5hello", &mut rng);
    let request_raw = extract_any_send_packet(&request_actions);
    let request_packet = RawPacket::unpack(&request_raw).unwrap();
    let immediate = resp_mgr.handle_local_delivery(
        request_packet.destination_hash,
        &request_raw,
        request_packet.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    assert!(
        immediate
            .iter()
            .all(|action| !matches!(action, LinkManagerAction::SendPacket { .. })),
        "deferred handlers must not send an immediate response"
    );

    let (received_link, request_id, data) = deferred.lock().unwrap().take().unwrap();
    assert_eq!(received_link, link_id);
    assert_eq!(data, b"\xa5hello");
    let response_actions =
        resp_mgr.send_deferred_response(&link_id, &request_id, b"\xa2OK", &mut rng);
    let response_raw = extract_any_send_packet(&response_actions);
    let response_packet = RawPacket::unpack(&response_raw).unwrap();
    let delivered = init_mgr.handle_local_delivery(
        response_packet.destination_hash,
        &response_raw,
        response_packet.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    assert!(delivered.iter().any(|action| matches!(
        action,
        LinkManagerAction::ResponseReceived { data, .. } if data == b"\xa2OK"
    )));
}

#[test]
fn test_large_response_uses_resource_fallback() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    // Register handler on responder with payload that cannot fit a direct
    // CONTEXT_RESPONSE packet.
    let large_payload: Vec<u8> = (0..5000u32).map(|i| (i & 0xFF) as u8).collect();
    resp_mgr.register_request_handler("/large", None, {
        let large_payload = large_payload.clone();
        move |_link_id, _path, _data, _remote| Some(large_payload.clone())
    });

    // Send request from initiator.
    let req_actions = init_mgr.send_request(&link_id, "/large", b"\xc0", &mut rng);
    assert!(!req_actions.is_empty());

    // Deliver request to responder and inspect responder outbound packets.
    let req_raw = extract_any_send_packet(&req_actions);
    let req_pkt = RawPacket::unpack(&req_raw).unwrap();
    let resp_actions = resp_mgr.handle_local_delivery(
        req_pkt.destination_hash,
        &req_raw,
        req_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    let mut has_resource_adv = false;
    let mut has_direct_response = false;
    for action in &resp_actions {
        if let LinkManagerAction::SendPacket { raw, .. } = action {
            let pkt = RawPacket::unpack(raw).unwrap();
            if pkt.context == constants::CONTEXT_RESOURCE_ADV {
                has_resource_adv = true;
            }
            if pkt.context == constants::CONTEXT_RESPONSE {
                has_direct_response = true;
            }
        }
    }

    assert!(
        has_resource_adv,
        "Large response should advertise a response resource"
    );
    assert!(
        !has_direct_response,
        "Large response should not use direct CONTEXT_RESPONSE packet"
    );
}

#[test]
fn test_send_management_response_without_session_key_uses_resource_fallback_path() {
    let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    init_mgr
        .links
        .get_mut(&link_id)
        .unwrap()
        .engine
        .clear_session_for_testing();

    let large_response: Vec<u8> = (0..5000u32).map(|i| (i & 0xFF) as u8).collect();
    let actions =
        init_mgr.send_management_response(&link_id, &[0x11; 16], &large_response, &mut rng);

    assert!(
        actions.is_empty(),
        "without a session key, no response packets should be emitted"
    );
    assert_eq!(
        init_mgr
            .links
            .get(&link_id)
            .map(|managed| managed.outgoing_resources.len()),
        Some(1)
    );
}

#[test]
fn test_send_channel_message_on_no_channel() {
    let mut mgr = LinkManager::new();
    let mut rng = OsRng;
    let dummy_sig = [0xAA; 32];
    let (link_id, _) = mgr.create_link(&[0x11; 16], &dummy_sig, 1, constants::MTU as u32, &mut rng);

    // Link is Pending (no channel), should return empty
    let err = mgr
        .send_channel_message(&link_id, 1, b"test", &mut rng)
        .expect_err("pending link should reject channel send");
    assert_eq!(err, "link has no active channel");
}

#[test]
fn test_send_on_link_requires_active() {
    let mut mgr = LinkManager::new();
    let mut rng = OsRng;
    let dummy_sig = [0xAA; 32];
    let (link_id, _) = mgr.create_link(&[0x11; 16], &dummy_sig, 1, constants::MTU as u32, &mut rng);

    let actions = mgr.send_on_link(&link_id, b"test", constants::CONTEXT_NONE, &mut rng);
    assert!(actions.is_empty(), "Cannot send on pending link");
}

#[test]
fn test_send_on_link_unknown_link() {
    let mgr = LinkManager::new();
    let mut rng = OsRng;

    let actions = mgr.send_on_link(&[0xFF; 16], b"test", constants::CONTEXT_NONE, &mut rng);
    assert!(actions.is_empty());
}

#[test]
fn test_resource_full_transfer_large() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);

    // Multi-part data (larger than a single SDU of 464 bytes)
    let original_data: Vec<u8> = (0..2000u32)
        .map(|i| {
            let pos = i as usize;
            (pos ^ (pos >> 8) ^ (pos >> 16)) as u8
        })
        .collect();

    let adv_actions = init_mgr.send_resource(&link_id, &original_data, None, &mut rng);

    let mut pending: Vec<(char, LinkManagerAction)> =
        adv_actions.into_iter().map(|a| ('i', a)).collect();
    let mut rounds = 0;
    let max_rounds = 200;
    let mut resource_received = false;
    let mut sender_completed = false;

    while !pending.is_empty() && rounds < max_rounds {
        rounds += 1;
        let mut next: Vec<(char, LinkManagerAction)> = Vec::new();

        for (source, action) in pending.drain(..) {
            if let LinkManagerAction::SendPacket { raw, .. } = action {
                let pkt = match RawPacket::unpack(&raw) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                let target_actions = if source == 'i' {
                    resp_mgr.handle_local_delivery(
                        pkt.destination_hash,
                        &raw,
                        pkt.packet_hash,
                        rns_core::transport::types::InterfaceId(0),
                        &mut rng,
                    )
                } else {
                    init_mgr.handle_local_delivery(
                        pkt.destination_hash,
                        &raw,
                        pkt.packet_hash,
                        rns_core::transport::types::InterfaceId(0),
                        &mut rng,
                    )
                };

                let target_source = if source == 'i' { 'r' } else { 'i' };
                for a in &target_actions {
                    match a {
                        LinkManagerAction::ResourceReceived { data, .. } => {
                            assert_eq!(*data, original_data);
                            resource_received = true;
                        }
                        LinkManagerAction::ResourceCompleted { .. } => {
                            sender_completed = true;
                        }
                        _ => {}
                    }
                }
                next.extend(target_actions.into_iter().map(|a| (target_source, a)));
            }
        }
        pending = next;
    }

    assert!(
        resource_received,
        "Should receive large resource (rounds={})",
        rounds
    );
    assert!(
        sender_completed,
        "Sender should complete (rounds={})",
        rounds
    );
}

#[test]
fn test_resource_receiver_stores_original_advertisement_plaintext() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);

    let data = vec![0x41; 256];
    let adv_actions = init_mgr.send_resource(&link_id, &data, None, &mut rng);

    let adv_raw = adv_actions
        .iter()
        .find_map(|action| match action {
            LinkManagerAction::SendPacket { raw, .. } => {
                let pkt = RawPacket::unpack(raw).ok()?;
                (pkt.context == constants::CONTEXT_RESOURCE_ADV).then_some(raw.clone())
            }
            _ => None,
        })
        .expect("sender should emit a resource advertisement");

    let adv_pkt = RawPacket::unpack(&adv_raw).unwrap();
    let adv_plaintext = resp_mgr
        .links
        .get(&link_id)
        .unwrap()
        .engine
        .decrypt(&adv_pkt.data)
        .unwrap();

    let _resp_actions = resp_mgr.handle_local_delivery(
        adv_pkt.destination_hash,
        &adv_raw,
        adv_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    let receiver = resp_mgr
        .links
        .get(&link_id)
        .and_then(|managed| managed.incoming_resources.first())
        .expect("advertisement should create an incoming receiver");
    assert_eq!(receiver.advertisement_packet, adv_plaintext);
    assert_eq!(
        receiver.max_decompressed_size,
        constants::RESOURCE_AUTO_COMPRESS_MAX_SIZE
    );
}

#[test]
fn test_corrupt_compressed_resource_rejects_and_tears_down_link() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);

    let data = vec![b'A'; 4096];
    let adv_actions = init_mgr.send_resource(&link_id, &data, None, &mut rng);

    let mut request_actions = Vec::new();
    for action in &adv_actions {
        let LinkManagerAction::SendPacket { raw, .. } = action else {
            continue;
        };
        let pkt = RawPacket::unpack(raw).unwrap();
        let actions = resp_mgr.handle_local_delivery(
            pkt.destination_hash,
            raw,
            pkt.packet_hash,
            rns_core::transport::types::InterfaceId(0),
            &mut rng,
        );
        request_actions.extend(actions);
    }

    {
        let receiver = resp_mgr
            .links
            .get_mut(&link_id)
            .and_then(|managed| managed.incoming_resources.first_mut())
            .expect("receiver should exist after advertisement");
        assert!(receiver.flags.compressed, "test data should be compressed");
        receiver.max_decompressed_size = 64;
    }

    let mut responder_actions = Vec::new();
    for action in request_actions {
        let LinkManagerAction::SendPacket { raw, .. } = action else {
            continue;
        };
        let pkt = RawPacket::unpack(&raw).unwrap();
        let actions = init_mgr.handle_local_delivery(
            pkt.destination_hash,
            &raw,
            pkt.packet_hash,
            rns_core::transport::types::InterfaceId(0),
            &mut rng,
        );

        for action in actions {
            let LinkManagerAction::SendPacket { raw, .. } = &action else {
                continue;
            };
            let pkt = RawPacket::unpack(raw).unwrap();
            let delivered = resp_mgr.handle_local_delivery(
                pkt.destination_hash,
                raw,
                pkt.packet_hash,
                rns_core::transport::types::InterfaceId(0),
                &mut rng,
            );
            responder_actions.extend(delivered);
        }
    }

    assert!(
        responder_actions.iter().any(|action| matches!(
            action,
            LinkManagerAction::ResourceFailed { error, .. }
                if error == "Resource too large"
        )),
        "corrupt oversized resource should fail with TooLarge"
    );
    assert!(
        responder_actions.iter().any(|action| matches!(
            action,
            LinkManagerAction::LinkClosed { link_id: closed_id, .. } if *closed_id == link_id
        )),
        "corrupt oversized resource should tear down the link"
    );
    assert!(
        responder_actions.iter().any(|action| match action {
            LinkManagerAction::SendPacket { raw, .. } => RawPacket::unpack(raw)
                .map(|pkt| pkt.context == constants::CONTEXT_RESOURCE_RCL)
                .unwrap_or(false),
            _ => false,
        }),
        "corrupt oversized resource should send a receiver cancel/reject packet"
    );
    assert_eq!(
        resp_mgr
            .links
            .get(&link_id)
            .map(|managed| managed.engine.state()),
        Some(LinkState::Closed)
    );
}

#[test]
fn test_resource_hmu_timeout_extension_in_link_manager_flow() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);

    // Large and incompressible enough to require multiple hashmap segments
    // even with the live Bzip2Compressor in the LinkManager path.
    let mut state = 0x1234_5678u32;
    let data: Vec<u8> = (0..50000)
        .map(|_| {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            (state >> 16) as u8
        })
        .collect();
    let adv_actions = init_mgr.send_resource(&link_id, &data, None, &mut rng);
    let mut pending: Vec<(char, LinkManagerAction)> =
        adv_actions.into_iter().map(|a| ('i', a)).collect();

    let mut rounds = 0;

    // Drive the real link-manager exchange until the receiver is genuinely
    // waiting for an HMU after exhausting the advertised hashmap segment.
    while rounds < 300 {
        rounds += 1;
        let mut next: Vec<(char, LinkManagerAction)> = Vec::new();

        for (source, action) in pending.drain(..) {
            let LinkManagerAction::SendPacket { raw, .. } = action else {
                continue;
            };

            let pkt = match RawPacket::unpack(&raw) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let target_actions = if source == 'i' {
                resp_mgr.handle_local_delivery(
                    pkt.destination_hash,
                    &raw,
                    pkt.packet_hash,
                    rns_core::transport::types::InterfaceId(0),
                    &mut rng,
                )
            } else {
                init_mgr.handle_local_delivery(
                    pkt.destination_hash,
                    &raw,
                    pkt.packet_hash,
                    rns_core::transport::types::InterfaceId(0),
                    &mut rng,
                )
            };

            let target_source = if source == 'i' { 'r' } else { 'i' };
            next.extend(target_actions.into_iter().map(|a| (target_source, a)));
        }

        if resp_mgr
            .links
            .get(&link_id)
            .and_then(|managed| managed.incoming_resources.first())
            .is_some_and(|receiver| receiver.waiting_for_hmu)
        {
            break;
        }

        pending = next;
    }

    assert!(
        resp_mgr
            .links
            .get(&link_id)
            .and_then(|managed| managed.incoming_resources.first())
            .is_some_and(|receiver| receiver.waiting_for_hmu),
        "expected receiver to reach a live HMU wait state"
    );

    // Prime the live receiver once so it computes the same EIFR it will use
    // for timeout decisions in this HMU-wait state.
    let prime_actions = {
        let managed = resp_mgr.links.get_mut(&link_id).unwrap();
        let receiver = managed.incoming_resources.first_mut().unwrap();
        let decrypt_fn = |ciphertext: &[u8]| -> Result<Vec<u8>, ()> {
            managed.engine.decrypt(ciphertext).map_err(|_| ())
        };
        receiver.tick(
            receiver.last_activity + 0.0001,
            &decrypt_fn,
            &Bzip2Compressor,
        )
    };
    assert!(
        !prime_actions
            .iter()
            .any(|a| matches!(a, ResourceAction::SendRequest(_))),
        "fresh HMU wait state should not immediately emit a retry request"
    );

    let (late_delta, retries_before) = {
        let managed = resp_mgr
            .links
            .get_mut(&link_id)
            .expect("receiver link should still exist");
        let receiver = managed
            .incoming_resources
            .first_mut()
            .expect("receiver should have an active incoming resource");

        assert!(
            receiver.waiting_for_hmu,
            "receiver should be waiting for HMU"
        );

        let eifr = receiver.eifr.unwrap_or_else(|| {
            (constants::RESOURCE_SDU as f64 * 8.0) / receiver.rtt.unwrap_or(0.5)
        });
        let expected_tof = if receiver.outstanding_parts > 0 {
            (receiver.outstanding_parts as f64 * constants::RESOURCE_SDU as f64 * 8.0) / eifr
        } else {
            (3.0 * constants::RESOURCE_SDU as f64) / eifr
        };
        let expected_hmu_wait =
            (constants::RESOURCE_SDU as f64 * 8.0 * constants::RESOURCE_HMU_WAIT_FACTOR) / eifr;
        let old_delta = constants::RESOURCE_PART_TIMEOUT_FACTOR_AFTER_RTT * expected_tof
            + constants::RESOURCE_RETRY_GRACE_TIME;
        (
            old_delta + expected_hmu_wait + expected_hmu_wait.max(1.0),
            receiver.retries_left,
        )
    };
    {
        let managed = resp_mgr.links.get(&link_id).unwrap();
        let receiver = managed.incoming_resources.first().unwrap();
        assert_eq!(receiver.retries_left, retries_before);
        assert!(
            receiver.eifr.is_some(),
            "receiver tick should have populated EIFR"
        );
    }

    let late_resource_actions = {
        let managed = resp_mgr.links.get_mut(&link_id).unwrap();
        let receiver = managed.incoming_resources.first_mut().unwrap();
        let decrypt_fn = |ciphertext: &[u8]| -> Result<Vec<u8>, ()> {
            managed.engine.decrypt(ciphertext).map_err(|_| ())
        };
        receiver.tick(
            receiver.last_activity + late_delta,
            &decrypt_fn,
            &Bzip2Compressor,
        )
    };
    let late_actions = resp_mgr.process_resource_actions(&link_id, late_resource_actions, &mut rng);
    let retry_raw = late_actions
        .iter()
        .find_map(|a| match a {
            LinkManagerAction::SendPacket { raw, .. } => {
                let pkt = RawPacket::unpack(raw).ok()?;
                (pkt.context == constants::CONTEXT_RESOURCE_REQ).then_some(raw.clone())
            }
            _ => None,
        })
        .expect("receiver should emit a resource retry request after extended timeout");

    {
        let managed = resp_mgr.links.get(&link_id).unwrap();
        let receiver = managed.incoming_resources.first().unwrap();
        assert_eq!(receiver.retries_left, retries_before - 1);
    }

    let retry_pkt = RawPacket::unpack(&retry_raw).unwrap();
    let retry_plaintext = resp_mgr
        .links
        .get(&link_id)
        .unwrap()
        .engine
        .decrypt(&retry_pkt.data)
        .expect("retry request should decrypt");
    assert_eq!(retry_plaintext[0], constants::RESOURCE_HASHMAP_IS_EXHAUSTED);

    // Deliver the retry request to the sender and verify it turns into a
    // real HMU packet in the live LinkManager flow.
    let retry_to_sender = init_mgr.handle_local_delivery(
        retry_pkt.destination_hash,
        &retry_raw,
        retry_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    assert!(
        retry_to_sender.iter().any(|a| match a {
            LinkManagerAction::SendPacket { raw, .. } => RawPacket::unpack(raw)
                .map(|pkt| pkt.context == constants::CONTEXT_RESOURCE_HMU)
                .unwrap_or(false),
            _ => false,
        }),
        "sender should answer the exhausted retry request with a live HMU packet"
    );
}

#[test]
fn test_process_resource_actions_mapping() {
    let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    // Test that various ResourceActions map to correct LinkManagerActions
    let actions = vec![
        ResourceAction::DataReceived {
            data: vec![1, 2, 3],
            metadata: Some(vec![4, 5]),
        },
        ResourceAction::Completed,
        ResourceAction::Failed(rns_core::resource::ResourceError::Timeout),
        ResourceAction::ProgressUpdate {
            received: 10,
            total: 20,
        },
        ResourceAction::TeardownLink,
    ];

    let result = init_mgr.process_resource_actions(&link_id, actions, &mut rng);

    assert!(matches!(
        result[0],
        LinkManagerAction::ResourceReceived { .. }
    ));
    assert!(matches!(
        result[1],
        LinkManagerAction::ResourceCompleted { .. }
    ));
    assert!(matches!(
        result[2],
        LinkManagerAction::ResourceFailed { .. }
    ));
    assert!(matches!(
        result[3],
        LinkManagerAction::ResourceProgress {
            received: 10,
            total: 20,
            ..
        }
    ));
    assert!(result
        .iter()
        .any(|action| matches!(action, LinkManagerAction::LinkClosed { .. })));
}

#[test]
fn test_link_state_empty() {
    let mgr = LinkManager::new();
    let fake_id = [0xAA; 16];
    assert!(mgr.link_state(&fake_id).is_none());
}

#[test]
fn test_large_response_resource_completes_as_response() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    let large_payload: Vec<u8> = (0..5000u32).map(|i| (i & 0xFF) as u8).collect();
    let response_value = rns_core::msgpack::pack(&rns_core::msgpack::Value::Bin(large_payload));
    resp_mgr.register_request_handler("/large", None, {
        let response_value = response_value.clone();
        move |_link_id, _path, _data, _remote| Some(response_value.clone())
    });

    let req_actions = init_mgr.send_request(&link_id, "/large", b"\xc0", &mut rng);
    let req_raw = extract_any_send_packet(&req_actions);
    let req_pkt = RawPacket::unpack(&req_raw).unwrap();
    let request_id = req_pkt.get_truncated_hash();
    let resp_actions = resp_mgr.handle_local_delivery(
        req_pkt.destination_hash,
        &req_raw,
        req_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    let mut pending: Vec<(char, LinkManagerAction)> =
        resp_actions.into_iter().map(|a| ('r', a)).collect();
    let mut rounds = 0;
    let mut received_response = None;

    while !pending.is_empty() && rounds < 200 {
        rounds += 1;
        let mut next = Vec::new();

        for (source, action) in pending.drain(..) {
            let LinkManagerAction::SendPacket { raw, .. } = action else {
                continue;
            };
            let pkt = RawPacket::unpack(&raw).unwrap();
            let target_actions = if source == 'r' {
                init_mgr.handle_local_delivery(
                    pkt.destination_hash,
                    &raw,
                    pkt.packet_hash,
                    rns_core::transport::types::InterfaceId(0),
                    &mut rng,
                )
            } else {
                resp_mgr.handle_local_delivery(
                    pkt.destination_hash,
                    &raw,
                    pkt.packet_hash,
                    rns_core::transport::types::InterfaceId(0),
                    &mut rng,
                )
            };

            let target_source = if source == 'r' { 'i' } else { 'r' };
            for target_action in &target_actions {
                match target_action {
                    LinkManagerAction::ResponseReceived {
                        request_id: rid,
                        data,
                        ..
                    } => {
                        received_response = Some((*rid, data.clone()));
                    }
                    LinkManagerAction::ResourceReceived { .. } => {
                        panic!("response resources must complete as ResponseReceived")
                    }
                    LinkManagerAction::ResourceAcceptQuery { .. } => {
                        panic!("response resources must bypass application acceptance")
                    }
                    _ => {}
                }
            }
            next.extend(target_actions.into_iter().map(|a| (target_source, a)));
        }

        pending = next;
    }

    let (received_request_id, received_data) = received_response.unwrap_or_else(|| {
        panic!(
            "large response resource did not complete as ResponseReceived after {} rounds",
            rounds
        )
    });
    assert_eq!(received_request_id, request_id);
    assert_eq!(received_data, response_value);
}

#[test]
fn response_resource_at_exact_declared_size_limit_is_accepted() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let payload = deterministic_bytes(4096);
    let response_value = rns_core::msgpack::pack(&rns_core::msgpack::Value::Bin(payload.clone()));
    let expected_size = rns_core::msgpack::pack(&rns_core::msgpack::Value::Array(vec![
        rns_core::msgpack::Value::Bin(vec![0; 16]),
        rns_core::msgpack::Value::Bin(payload),
    ]))
    .len();
    resp_mgr.register_request_handler_response("/bounded-resource", None, {
        let response_value = response_value.clone();
        move |_, _, _, _| {
            Some(RequestResponse::Resource {
                data: response_value.clone(),
                metadata: None,
                auto_compress: false,
            })
        }
    });

    let request_actions = init_mgr.send_request_with_max_response_size(
        &link_id,
        "/bounded-resource",
        b"\xc0",
        Some(expected_size),
        &mut rng,
    );
    let request_raw = extract_any_send_packet(&request_actions);
    let request = RawPacket::unpack(&request_raw).unwrap();
    let response_actions = resp_mgr.handle_local_delivery(
        request.destination_hash,
        &request_raw,
        request.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    let adv = first_resource_advertisement(&resp_mgr, &link_id, &response_actions);
    assert_eq!(adv.data_size as usize, expected_size);
    let adv_raw = extract_any_send_packet(&response_actions);
    let adv_packet = RawPacket::unpack(&adv_raw).unwrap();
    let actions = init_mgr.handle_local_delivery(
        adv_packet.destination_hash,
        &adv_raw,
        adv_packet.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    assert!(!actions
        .iter()
        .any(|action| matches!(action, LinkManagerAction::RequestFailed { .. })));
    assert_eq!(init_mgr.links[&link_id].incoming_resources.len(), 1);
}

#[test]
fn response_resource_one_byte_over_declared_size_limit_is_rejected() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;
    let payload = deterministic_bytes(4096);
    let response_value = rns_core::msgpack::pack(&rns_core::msgpack::Value::Bin(payload.clone()));
    let expected_size = rns_core::msgpack::pack(&rns_core::msgpack::Value::Array(vec![
        rns_core::msgpack::Value::Bin(vec![0; 16]),
        rns_core::msgpack::Value::Bin(payload),
    ]))
    .len();
    resp_mgr.register_request_handler_response("/bounded-resource", None, {
        let response_value = response_value.clone();
        move |_, _, _, _| {
            Some(RequestResponse::Resource {
                data: response_value.clone(),
                metadata: None,
                auto_compress: false,
            })
        }
    });

    let request_actions = init_mgr.send_request_with_max_response_size(
        &link_id,
        "/bounded-resource",
        b"\xc0",
        Some(expected_size - 1),
        &mut rng,
    );
    let request_raw = extract_any_send_packet(&request_actions);
    let request = RawPacket::unpack(&request_raw).unwrap();
    let request_id = request.get_truncated_hash();
    let response_actions = resp_mgr.handle_local_delivery(
        request.destination_hash,
        &request_raw,
        request.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );
    let adv_raw = extract_any_send_packet(&response_actions);
    let adv_packet = RawPacket::unpack(&adv_raw).unwrap();
    let actions = init_mgr.handle_local_delivery(
        adv_packet.destination_hash,
        &adv_raw,
        adv_packet.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    assert!(actions.iter().any(|action| matches!(
        action,
        LinkManagerAction::RequestFailed {
            request_id: failed_id,
            reason: RequestFailure::ResponseTooLarge { size, maximum },
            ..
        } if failed_id == &request_id
            && *size == expected_size as u64
            && *maximum == expected_size - 1
    )));
    assert!(init_mgr.links[&link_id].incoming_resources.is_empty());
    assert!(!init_mgr.links[&link_id]
        .pending_requests
        .contains_key(&request_id));
}

#[test]
fn test_response_resource_preserves_metadata() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    let payload = b"bundle-data".to_vec();
    let metadata = b"git-status-ok".to_vec();
    let response_value = rns_core::msgpack::pack(&rns_core::msgpack::Value::Bin(payload));
    resp_mgr.register_request_handler_response("/fetch", None, {
        let response_value = response_value.clone();
        let metadata = metadata.clone();
        move |_link_id, _path, _data, _remote| {
            Some(RequestResponse::Resource {
                data: response_value.clone(),
                metadata: Some(metadata.clone()),
                auto_compress: false,
            })
        }
    });

    let req_actions = init_mgr.send_request(&link_id, "/fetch", b"\xc0", &mut rng);
    let req_raw = extract_any_send_packet(&req_actions);
    let req_pkt = RawPacket::unpack(&req_raw).unwrap();
    let request_id = req_pkt.get_truncated_hash();
    let resp_actions = resp_mgr.handle_local_delivery(
        req_pkt.destination_hash,
        &req_raw,
        req_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    let mut pending: Vec<(char, LinkManagerAction)> =
        resp_actions.into_iter().map(|a| ('r', a)).collect();
    let mut received_response = None;

    for _ in 0..200 {
        if pending.is_empty() || received_response.is_some() {
            break;
        }

        let mut next = Vec::new();
        for (source, action) in pending.drain(..) {
            let LinkManagerAction::SendPacket { raw, .. } = action else {
                continue;
            };
            let pkt = RawPacket::unpack(&raw).unwrap();
            let target_actions = if source == 'r' {
                init_mgr.handle_local_delivery(
                    pkt.destination_hash,
                    &raw,
                    pkt.packet_hash,
                    rns_core::transport::types::InterfaceId(0),
                    &mut rng,
                )
            } else {
                resp_mgr.handle_local_delivery(
                    pkt.destination_hash,
                    &raw,
                    pkt.packet_hash,
                    rns_core::transport::types::InterfaceId(0),
                    &mut rng,
                )
            };

            let target_source = if source == 'r' { 'i' } else { 'r' };
            for target_action in &target_actions {
                match target_action {
                    LinkManagerAction::ResponseReceived {
                        request_id: rid,
                        data,
                        metadata: response_metadata,
                        ..
                    } => {
                        received_response = Some((*rid, data.clone(), response_metadata.clone()));
                    }
                    LinkManagerAction::ResourceReceived { .. } => {
                        panic!("response resources must complete as ResponseReceived")
                    }
                    _ => {}
                }
            }
            next.extend(target_actions.into_iter().map(|a| (target_source, a)));
        }
        pending = next;
    }

    let (received_request_id, received_data, received_metadata) = received_response
        .expect("resource response with metadata should complete as ResponseReceived");
    assert_eq!(received_request_id, request_id);
    assert_eq!(received_data, response_value);
    assert_eq!(received_metadata, Some(metadata));
}

#[test]
fn test_negotiated_mtu_response_uses_resource_before_global_mtu() {
    let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    init_mgr.set_link_mtu(&link_id, 300);
    resp_mgr.set_link_mtu(&link_id, 300);

    let payload = vec![0xAB; 350];
    let response_value = rns_core::msgpack::pack(&rns_core::msgpack::Value::Bin(payload));
    resp_mgr.register_request_handler("/mtu", None, {
        let response_value = response_value.clone();
        move |_link_id, _path, _data, _remote| Some(response_value.clone())
    });

    let req_actions = init_mgr.send_request(&link_id, "/mtu", b"\xc0", &mut rng);
    let req_raw = extract_any_send_packet(&req_actions);
    let req_pkt = RawPacket::unpack(&req_raw).unwrap();
    let resp_actions = resp_mgr.handle_local_delivery(
        req_pkt.destination_hash,
        &req_raw,
        req_pkt.packet_hash,
        rns_core::transport::types::InterfaceId(0),
        &mut rng,
    );

    let mut has_resource_adv = false;
    let mut direct_response_len = None;
    for action in &resp_actions {
        if let LinkManagerAction::SendPacket { raw, .. } = action {
            let pkt = RawPacket::unpack(raw).unwrap();
            has_resource_adv |= pkt.context == constants::CONTEXT_RESOURCE_ADV;
            if pkt.context == constants::CONTEXT_RESPONSE {
                direct_response_len = Some(raw.len());
            }
        }
    }

    assert!(
        has_resource_adv,
        "responses larger than the negotiated link MTU should use resource fallback"
    );
    assert!(
        direct_response_len.is_none(),
        "sent direct response of {} bytes on a 300 byte negotiated MTU",
        direct_response_len.unwrap_or_default()
    );
}

#[test]
fn test_large_management_response_uses_resource_fallback() {
    let (_init_mgr, mut resp_mgr, link_id) = setup_active_link();
    let mut rng = OsRng;

    let payload = vec![0xBC; 5000];
    let response_value = rns_core::msgpack::pack(&rns_core::msgpack::Value::Bin(payload));
    let actions =
        resp_mgr.send_management_response(&link_id, &[0x55; 16], &response_value, &mut rng);

    let mut has_resource_adv = false;
    let mut has_direct_response = false;
    for action in &actions {
        if let LinkManagerAction::SendPacket { raw, .. } = action {
            let pkt = RawPacket::unpack(raw).unwrap();
            has_resource_adv |= pkt.context == constants::CONTEXT_RESOURCE_ADV;
            has_direct_response |= pkt.context == constants::CONTEXT_RESPONSE;
        }
    }

    assert!(
        has_resource_adv,
        "large management responses should advertise a response resource"
    );
    assert!(
        !has_direct_response,
        "large management responses should not use a direct CONTEXT_RESPONSE packet"
    );
}
