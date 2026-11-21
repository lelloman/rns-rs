use super::*;
use rns_core::holepunch::{UPGRADE_ACCEPT, UPGRADE_READY, UPGRADE_REJECT};
use rns_crypto::FixedRng;

fn make_rng(seed: u8) -> FixedRng {
    FixedRng::new(&[seed; 128])
}

fn test_derived_key() -> Vec<u8> {
    vec![0xAA; 32]
}

fn make_probe_addr() -> SocketAddr {
    "127.0.0.1:4343".parse().unwrap()
}

fn make_tx() -> (EventSender, crate::event::EventReceiver) {
    crate::event::channel()
}

fn ep(s: &str) -> Endpoint {
    let addr: SocketAddr = s.parse().unwrap();
    Endpoint {
        addr: match addr {
            SocketAddr::V4(v4) => v4.ip().octets().to_vec(),
            SocketAddr::V6(v6) => v6.ip().octets().to_vec(),
        },
        port: addr.port(),
    }
}

/// Build an UPGRADE_REQUEST payload naming `facilitator` and `initiator`.
fn make_request(link_id: [u8; 16], facilitator: &str, initiator: &str, seed: u8) -> Vec<u8> {
    let mut rng = make_rng(seed);
    let mut proposer = HolePunchEngine::new(link_id, Some(ep(facilitator)), ProbeProtocol::Rnsp);
    proposer
        .propose(&test_derived_key(), 100.0, &mut rng)
        .unwrap();
    let discover_actions = proposer.endpoints_discovered(ep(initiator), 101.0).unwrap();
    match &discover_actions[0] {
        HolePunchAction::SendSignal { payload, .. } => payload.clone(),
        _ => panic!("Expected SendSignal"),
    }
}

/// Manager accepting all proposals, with probe and punch threads disabled.
fn accepting_manager() -> HolePunchManager {
    let mut mgr = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
    mgr.set_policy(HolePunchPolicy::AcceptAll);
    mgr.set_spawn_workers(false);
    mgr
}

fn is_msg(action: &HolePunchManagerAction, expected: u8) -> bool {
    matches!(action, HolePunchManagerAction::SendSignal { msgtype, .. } if *msgtype == expected)
}

fn reject_reason(actions: &[HolePunchManagerAction]) -> Option<u8> {
    actions.iter().find_map(|a| match a {
        HolePunchManagerAction::SendSignal {
            msgtype, payload, ..
        } if *msgtype == UPGRADE_REJECT => {
            let (val, _) = rns_core::msgpack::unpack(payload).ok()?;
            val.map_get("r").and_then(|v| v.as_uint()).map(|r| r as u8)
        }
        _ => None,
    })
}

#[test]
fn request_with_private_initiator_endpoint_is_refused() {
    for initiator in [
        "192.168.1.10:41000",
        "127.0.0.1:41000",
        "[::ffff:10.0.0.1]:41000",
    ] {
        let mut mgr = accepting_manager();
        let (tx, _rx) = make_tx();
        let link_id = [0x51; 16];
        let payload = make_request(link_id, "1.2.3.4:4343", initiator, 0x42);
        let (handled, actions) = mgr.handle_signal(
            link_id,
            UPGRADE_REQUEST,
            payload,
            Some(&test_derived_key()),
            &tx,
        );
        assert!(handled);
        assert_eq!(actions.len(), 1, "{initiator}");
        assert_eq!(reject_reason(&actions), Some(REJECT_POLICY), "{initiator}");
        assert_eq!(mgr.session_count(), 0, "{initiator}");
    }
}

#[test]
fn nat64_endpoints_are_never_used() {
    // In a request, even with private endpoints allowed.
    for (facilitator, initiator) in [
        ("[64:ff9b::909:909]:4343", "[2a00:1450::1]:41000"),
        ("[2a00:1450::9]:4343", "[64:ff9b::102:304]:41000"),
        ("[2a00:1450::9]:4343", "[64:ff9b:1::a00:1]:41000"),
    ] {
        let mut mgr = accepting_manager();
        mgr.set_allow_private_endpoints(true);
        let (tx, _rx) = make_tx();
        let link_id = [0x53; 16];
        let payload = make_request(link_id, facilitator, initiator, 0x42);
        let (_, actions) = mgr.handle_signal(
            link_id,
            UPGRADE_REQUEST,
            payload,
            Some(&test_derived_key()),
            &tx,
        );
        assert_eq!(reject_reason(&actions), Some(REJECT_POLICY), "{initiator}");
    }
    // As a configured facilitator.
    let mgr = HolePunchManager::new(
        vec![
            "[64:ff9b::909:909]:4343".parse().unwrap(),
            "[2a00:1450::9]:4343".parse().unwrap(),
        ],
        ProbeProtocol::Rnsp,
        None,
    );
    assert_eq!(
        mgr.probe_addrs,
        vec!["[2a00:1450::9]:4343".parse::<SocketAddr>().unwrap()]
    );
    // As the peer's endpoint in READY it is outside the accepted
    // ranges like any other (admission), and the punch never sends to
    // it (puncher).
}

#[test]
fn a_mapping_of_another_family_or_synthesized_fails_the_probe() {
    for observed in ["1.2.3.4:41000", "[64:ff9b::102:304]:41000"] {
        let mut mgr = HolePunchManager::new(
            vec!["[2a00:1450::9]:4343".parse().unwrap()],
            ProbeProtocol::Rnsp,
            None,
        );
        mgr.set_spawn_workers(false);
        let (tx, _rx) = make_tx();
        let link_id = [0x54; 16];
        let mut rng = make_rng(0x42);
        mgr.propose_to_supported(link_id, &test_derived_key(), &mut rng, &tx);
        let session_id = *mgr.link_to_session.get(&link_id).unwrap();
        let Ok(socket) = UdpSocket::bind("[::1]:0") else {
            return; // no IPv6 on this host
        };
        let actions = mgr.handle_probe_result(
            link_id,
            session_id,
            observed.parse().unwrap(),
            socket,
            "[2a00:1450::9]:4343".parse().unwrap(),
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, HolePunchManagerAction::SendSignal { .. })),
            "{observed}"
        );
    }
}

#[test]
fn request_with_private_facilitator_is_refused() {
    let mut mgr = accepting_manager();
    let (tx, _rx) = make_tx();
    let link_id = [0x52; 16];
    let payload = make_request(link_id, "10.0.0.1:4343", "1.2.3.4:41000", 0x42);
    let (_, actions) = mgr.handle_signal(
        link_id,
        UPGRADE_REQUEST,
        payload,
        Some(&test_derived_key()),
        &tx,
    );
    assert_eq!(reject_reason(&actions), Some(REJECT_POLICY));
    assert_eq!(mgr.session_count(), 0);
}

#[test]
fn private_endpoints_accepted_when_allowed() {
    let mut mgr = accepting_manager();
    mgr.set_allow_private_endpoints(true);
    let (tx, _rx) = make_tx();
    let link_id = [0x53; 16];
    let payload = make_request(link_id, "192.168.1.1:4343", "192.168.1.10:41000", 0x42);
    let (_, actions) = mgr.handle_signal(
        link_id,
        UPGRADE_REQUEST,
        payload,
        Some(&test_derived_key()),
        &tx,
    );
    assert!(actions.iter().any(|a| is_msg(a, UPGRADE_ACCEPT)));
    assert_eq!(mgr.session_count(), 1);
}

#[test]
fn ready_with_private_responder_endpoint_does_not_punch() {
    let mut mgr = accepting_manager();
    let (tx, _rx) = make_tx();
    let link_id = [0x54; 16];
    let mut rng = make_rng(0x42);
    mgr.propose_to_supported(link_id, &test_derived_key(), &mut rng, &tx);
    let session_id = *mgr.link_to_session.get(&link_id).unwrap();
    let probe_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let request = mgr.handle_probe_result(
        link_id,
        session_id,
        "1.2.3.4:41000".parse().unwrap(),
        probe_socket,
        make_probe_addr(),
    );
    assert!(request.iter().any(|a| is_msg(a, UPGRADE_REQUEST)));

    // Responder side builds ACCEPT and READY naming a private endpoint.
    let request_payload = match &request[0] {
        HolePunchManagerAction::SendSignal { payload, .. } => payload.clone(),
        _ => unreachable!(),
    };
    let mut responder = HolePunchEngine::new(link_id, None, ProbeProtocol::Rnsp);
    let r_actions = responder
        .handle_signal(
            UPGRADE_REQUEST,
            &request_payload,
            Some(&test_derived_key()),
            1.0,
        )
        .unwrap();
    let accept = match &r_actions[0] {
        HolePunchAction::SendSignal { payload, .. } => payload.clone(),
        _ => unreachable!(),
    };
    let ready_actions = responder
        .endpoints_discovered(ep("10.1.2.3:52000"), 2.0)
        .unwrap();
    let ready = match &ready_actions[0] {
        HolePunchAction::SendSignal { payload, .. } => payload.clone(),
        _ => unreachable!(),
    };

    mgr.handle_signal(link_id, UPGRADE_ACCEPT, accept, None, &tx);
    let (_, actions) = mgr.handle_signal(link_id, UPGRADE_READY, ready, None, &tx);
    assert!(actions
        .iter()
        .any(|a| matches!(a, HolePunchManagerAction::DirectConnectFailed { .. })));
    let session = mgr.sessions.get(&session_id).unwrap();
    assert!(session.punch_target.is_none());
    assert!(session.punch_handle.is_none());
    assert_eq!(session.engine.state(), HolePunchState::Failed);
}

#[test]
fn request_naming_a_facilitator_as_the_initiator_is_refused() {
    // The facilitator in the request, and one of ours.
    for (facilitator, initiator) in [
        ("1.2.3.4:4343", "1.2.3.4:4343"),
        ("1.2.3.4:4343", "[::ffff:1.2.3.4]:4343"),
        ("1.2.3.4:4343", "9.9.9.9:4343"),
    ] {
        let mut mgr = HolePunchManager::new(
            vec!["9.9.9.9:4343".parse().unwrap()],
            ProbeProtocol::Rnsp,
            None,
        );
        mgr.set_policy(HolePunchPolicy::AcceptAll);
        mgr.set_spawn_workers(false);
        let (tx, _rx) = make_tx();
        let link_id = [0x58; 16];
        let payload = make_request(link_id, facilitator, initiator, 0x42);
        let (_, actions) = mgr.handle_signal(
            link_id,
            UPGRADE_REQUEST,
            payload,
            Some(&test_derived_key()),
            &tx,
        );
        assert_eq!(reject_reason(&actions), Some(REJECT_POLICY), "{initiator}");
        assert_eq!(mgr.session_count(), 0, "{initiator}");
    }
}

/// Run an initiator session that probed `observed` through the
/// manager's probe server, up to the peer's READY naming `responder`.
/// Whether the manager went on to punch.
fn punches_toward(mgr: &mut HolePunchManager, observed: &str, responder: &str) -> bool {
    let (tx, _rx) = make_tx();
    let link_id = [0x59; 16];
    let mut rng = make_rng(0x42);
    mgr.propose_to_supported(link_id, &test_derived_key(), &mut rng, &tx);
    let session_id = *mgr.link_to_session.get(&link_id).unwrap();
    let facilitator = mgr.probe_addrs[0];
    let request = mgr.handle_probe_result(
        link_id,
        session_id,
        observed.parse().unwrap(),
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        facilitator,
    );
    let request_payload = match &request[0] {
        HolePunchManagerAction::SendSignal { payload, .. } => payload.clone(),
        _ => unreachable!(),
    };
    let mut responder_engine = HolePunchEngine::new(link_id, None, ProbeProtocol::Rnsp);
    let r_actions = responder_engine
        .handle_signal(
            UPGRADE_REQUEST,
            &request_payload,
            Some(&test_derived_key()),
            1.0,
        )
        .unwrap();
    let accept = match &r_actions[0] {
        HolePunchAction::SendSignal { payload, .. } => payload.clone(),
        _ => unreachable!(),
    };
    let ready_actions = responder_engine
        .endpoints_discovered(ep(responder), 2.0)
        .unwrap();
    let ready = match &ready_actions[0] {
        HolePunchAction::SendSignal { payload, .. } => payload.clone(),
        _ => unreachable!(),
    };
    mgr.handle_signal(link_id, UPGRADE_ACCEPT, accept, None, &tx);
    let (_, actions) = mgr.handle_signal(link_id, UPGRADE_READY, ready, None, &tx);
    let session = mgr.sessions.get(&session_id).unwrap();
    let punching = session.punch_target.is_some();
    assert_eq!(
        punching,
        !actions
            .iter()
            .any(|a| matches!(a, HolePunchManagerAction::DirectConnectFailed { .. }))
    );
    punching
}

/// Run a proposal to the point of punching, the responder offering
/// `hosts`: the candidates punched, and the host candidates the request
/// carried.
fn punch_candidates_with_hosts(
    observed: &str,
    responder: &str,
    hosts: &[&str],
) -> (Vec<(SocketAddr, DirectCandidateKind)>, Vec<Endpoint>) {
    let mut mgr = HolePunchManager::new(
        vec!["9.9.9.9:4343".parse().unwrap()],
        ProbeProtocol::Rnsp,
        None,
    );
    mgr.set_spawn_workers(false);
    mgr.networks = Some(vec![super::super::candidates::LocalNetwork {
        interface: "eth0".into(),
        addr: "192.168.1.20".parse().unwrap(),
        prefix: 24,
    }]);
    let (tx, _rx) = make_tx();
    let link_id = [0x5a; 16];
    let mut rng = make_rng(0x42);
    mgr.propose_to_supported(link_id, &test_derived_key(), &mut rng, &tx);
    let session_id = *mgr.link_to_session.get(&link_id).unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let request = mgr.handle_probe_result(
        link_id,
        session_id,
        observed.parse().unwrap(),
        socket,
        "9.9.9.9:4343".parse().unwrap(),
    );
    let request_payload = match &request[0] {
        HolePunchManagerAction::SendSignal { payload, .. } => payload.clone(),
        _ => unreachable!(),
    };
    let mut responder_engine = HolePunchEngine::new(link_id, None, ProbeProtocol::Rnsp);
    let r_actions = responder_engine
        .handle_signal(
            UPGRADE_REQUEST,
            &request_payload,
            Some(&test_derived_key()),
            1.0,
        )
        .unwrap();
    let offered = responder_engine.peer_host_endpoints().to_vec();
    let accept = match &r_actions[0] {
        HolePunchAction::SendSignal { payload, .. } => payload.clone(),
        _ => unreachable!(),
    };
    responder_engine.set_host_endpoints(hosts.iter().map(|h| ep(h)).collect());
    let ready_actions = responder_engine
        .endpoints_discovered(ep(responder), 2.0)
        .unwrap();
    let ready = match &ready_actions[0] {
        HolePunchAction::SendSignal { payload, .. } => payload.clone(),
        _ => unreachable!(),
    };
    mgr.handle_signal(link_id, UPGRADE_ACCEPT, accept, None, &tx);
    mgr.handle_signal(link_id, UPGRADE_READY, ready, None, &tx);
    let candidates = mgr.sessions.get(&session_id).unwrap().candidates.clone();
    (candidates, offered)
}

#[test]
fn host_candidates_are_offered_and_punched_only_for_a_neighbour() {
    // Our LAN address goes out with the request.
    let (_, offered) = punch_candidates_with_hosts("1.2.3.4:41000", "5.6.7.8:41001", &[]);
    assert_eq!(offered.len(), 1);
    assert_eq!(offered[0].addr, vec![192, 168, 1, 20]);

    // Behind the same NAT: the peer's host candidate on our network is
    // punched after its public endpoint; one elsewhere is not.
    let (candidates, _) = punch_candidates_with_hosts(
        "1.2.3.4:41000",
        "1.2.3.4:41001",
        &["192.168.1.30:5000", "192.168.9.9:5000"],
    );
    assert_eq!(
        candidates,
        vec![
            (
                "1.2.3.4:41001".parse().unwrap(),
                DirectCandidateKind::Reflexive
            ),
            (
                "192.168.1.30:5000".parse().unwrap(),
                DirectCandidateKind::Host
            ),
        ]
    );

    // Behind another NAT, the same candidate is not punched.
    let (candidates, _) =
        punch_candidates_with_hosts("1.2.3.4:41000", "5.6.7.8:41001", &["192.168.1.30:5000"]);
    assert_eq!(candidates.len(), 1);
}

#[test]
fn punch_toward_this_node_or_a_facilitator_is_refused() {
    let manager = || {
        let mut mgr = HolePunchManager::new(
            vec!["9.9.9.9:4343".parse().unwrap()],
            ProbeProtocol::Rnsp,
            None,
        );
        mgr.set_own_listen_ports(vec![4242]);
        mgr.set_spawn_workers(false);
        mgr
    };
    let observed = "1.2.3.4:41000";
    // Our own mapping, our probe server at our address, the
    // facilitator, and an IPv6 peer for an IPv4 mapping.
    for responder in [
        "1.2.3.4:41000",
        "[::ffff:1.2.3.4]:41000",
        "1.2.3.4:4242",
        "9.9.9.9:4343",
        "[2001:4860::1]:52000",
    ] {
        assert!(
            !punches_toward(&mut manager(), observed, responder),
            "{responder}"
        );
    }
    // Another port at our own address is a peer behind the same NAT,
    // and any port elsewhere is fine.
    for responder in ["1.2.3.4:41001", "5.6.7.8:4242", "9.9.9.9:4344"] {
        assert!(
            punches_toward(&mut manager(), observed, responder),
            "{responder}"
        );
    }
}

#[test]
fn second_request_on_link_inside_window_is_refused() {
    let mut mgr = accepting_manager();
    let (tx, _rx) = make_tx();
    let link_id = [0x55; 16];
    let t0 = Instant::now();

    let first = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x01);
    let (_, actions) = mgr.handle_signal_at(
        link_id,
        UPGRADE_REQUEST,
        first,
        Some(&test_derived_key()),
        &tx,
        t0,
    );
    assert!(actions.iter().any(|a| is_msg(a, UPGRADE_ACCEPT)));

    let second = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x02);
    let (_, actions) = mgr.handle_signal_at(
        link_id,
        UPGRADE_REQUEST,
        second,
        Some(&test_derived_key()),
        &tx,
        t0 + std::time::Duration::from_secs(30),
    );
    assert_eq!(reject_reason(&actions), Some(REJECT_BUSY));
    assert_eq!(mgr.session_count(), 1);

    let third = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x03);
    let (_, actions) = mgr.handle_signal_at(
        link_id,
        UPGRADE_REQUEST,
        third,
        Some(&test_derived_key()),
        &tx,
        t0 + INBOUND_REQUEST_WINDOW,
    );
    assert!(actions.iter().any(|a| is_msg(a, UPGRADE_ACCEPT)));
    // The new session replaced the earlier one on this link.
    assert_eq!(mgr.session_count(), 1);
}

#[test]
fn concurrent_inbound_sessions_are_capped() {
    let mut mgr = accepting_manager();
    let (tx, _rx) = make_tx();
    for i in 0..MAX_CONCURRENT_SESSIONS as u8 {
        let link_id = [0x60 + i; 16];
        let initiator = format!("5.6.7.{}:41000", 10 + i);
        let payload = make_request(link_id, "1.2.3.4:4343", &initiator, i);
        let (_, actions) = mgr.handle_signal(
            link_id,
            UPGRADE_REQUEST,
            payload,
            Some(&test_derived_key()),
            &tx,
        );
        assert!(actions.iter().any(|a| is_msg(a, UPGRADE_ACCEPT)));
    }
    assert_eq!(mgr.session_count(), MAX_CONCURRENT_SESSIONS);

    let link_id = [0x70; 16];
    let payload = make_request(link_id, "1.2.3.4:4343", "5.6.7.99:41000", 0x70);
    let (_, actions) = mgr.handle_signal(
        link_id,
        UPGRADE_REQUEST,
        payload,
        Some(&test_derived_key()),
        &tx,
    );
    assert_eq!(reject_reason(&actions), Some(REJECT_BUSY));
    assert_eq!(mgr.session_count(), MAX_CONCURRENT_SESSIONS);

    // Closing a link frees a slot.
    mgr.link_closed(&[0x60; 16]);
    let link_id = [0x71; 16];
    let payload = make_request(link_id, "1.2.3.4:4343", "5.6.7.99:41000", 0x71);
    let (_, actions) = mgr.handle_signal(
        link_id,
        UPGRADE_REQUEST,
        payload,
        Some(&test_derived_key()),
        &tx,
    );
    assert!(actions.iter().any(|a| is_msg(a, UPGRADE_ACCEPT)));
}

#[test]
fn second_session_toward_same_target_is_refused() {
    let mut mgr = accepting_manager();
    let (tx, _rx) = make_tx();
    let a = make_request([0x81; 16], "1.2.3.4:4343", "5.6.7.8:41000", 0x01);
    let (_, actions) = mgr.handle_signal(
        [0x81; 16],
        UPGRADE_REQUEST,
        a,
        Some(&test_derived_key()),
        &tx,
    );
    assert!(actions.iter().any(|a| is_msg(a, UPGRADE_ACCEPT)));

    let b = make_request([0x82; 16], "1.2.3.4:4343", "5.6.7.8:41000", 0x02);
    let (_, actions) = mgr.handle_signal(
        [0x82; 16],
        UPGRADE_REQUEST,
        b,
        Some(&test_derived_key()),
        &tx,
    );
    assert_eq!(reject_reason(&actions), Some(REJECT_BUSY));
    assert_eq!(mgr.session_count(), 1);
}

#[test]
fn test_propose_creates_session_in_discovering() {
    let mut mgr = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
    let link_id = [0x11; 16];
    let mut rng = make_rng(0x42);
    let (tx, _rx) = make_tx();

    let actions = mgr.propose_to_supported(link_id, &test_derived_key(), &mut rng, &tx);

    assert_eq!(mgr.session_count(), 1);
    assert!(mgr.has_session_for_link(&link_id));
    // No SendSignal yet — initiator probes first
    assert!(actions.is_empty());
}

#[test]
fn test_propose_rate_limited() {
    let mut mgr = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
    let link_id = [0x22; 16];
    let mut rng = make_rng(0x42);
    let (tx, _rx) = make_tx();

    mgr.propose_to_supported(link_id, &test_derived_key(), &mut rng, &tx);

    // Immediate second proposal is rate-limited, and says so
    let actions = mgr.propose_to_supported(link_id, &test_derived_key(), &mut rng, &tx);
    assert!(matches!(
        actions[..],
        [HolePunchManagerAction::DirectConnectFailed {
            reason: rns_core::holepunch::FAIL_NOT_STARTED,
            ..
        }]
    ));
    // To a peer not yet known as well, before anything is sent.
    mgr.peer_support.clear();
    let actions = mgr.propose(link_id, &test_derived_key(), &mut rng, &tx);
    assert!(matches!(
        actions[..],
        [HolePunchManagerAction::DirectConnectFailed { .. }]
    ));
}

#[test]
fn test_reject_policy_sends_reject() {
    let mut mgr = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
    mgr.set_policy(HolePunchPolicy::Reject);

    let link_id = [0x33; 16];
    let mut rng = make_rng(0x42);
    let (tx, _rx) = make_tx();

    // Build a proper UPGRADE_REQUEST payload
    let mut proposer = HolePunchEngine::new(
        link_id,
        Some(Endpoint {
            addr: vec![127, 0, 0, 1],
            port: 4343,
        }),
        ProbeProtocol::Rnsp,
    );
    proposer
        .propose(&test_derived_key(), 100.0, &mut rng)
        .unwrap();
    let discover_actions = proposer
        .endpoints_discovered(
            Endpoint {
                addr: vec![1, 2, 3, 4],
                port: 41000,
            },
            101.0,
        )
        .unwrap();
    let request_payload = match &discover_actions[0] {
        HolePunchAction::SendSignal { payload, .. } => payload.clone(),
        _ => panic!("Expected SendSignal"),
    };

    let (handled, actions) = mgr.handle_signal(
        link_id,
        UPGRADE_REQUEST,
        request_payload,
        Some(&test_derived_key()),
        &tx,
    );

    assert!(handled);
    assert_eq!(actions.len(), 1);
    assert!(
        matches!(&actions[0], HolePunchManagerAction::SendSignal { msgtype, .. } if *msgtype == UPGRADE_REJECT)
    );
    assert_eq!(mgr.session_count(), 0);
}

#[test]
fn test_accept_policy_creates_session() {
    // Acceptable (public) endpoints still proceed under AcceptAll.
    let mut mgr = accepting_manager();

    let link_id = [0x44; 16];
    let (tx, _rx) = make_tx();

    let request_payload = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x42);

    let (handled, actions) = mgr.handle_signal(
        link_id,
        UPGRADE_REQUEST,
        request_payload,
        Some(&test_derived_key()),
        &tx,
    );

    assert!(handled);
    // Should send UPGRADE_ACCEPT
    assert!(actions.iter().any(|a| matches!(a, HolePunchManagerAction::SendSignal { msgtype, .. } if *msgtype == UPGRADE_ACCEPT)));
    assert_eq!(mgr.session_count(), 1);
    assert!(mgr.has_session_for_link(&link_id));
}

#[test]
fn test_non_holepunch_message_not_handled() {
    let mut mgr = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None);
    let (tx, _rx) = make_tx();

    let (handled, actions) = mgr.handle_signal([0x55; 16], 0x05, vec![1, 2, 3], None, &tx);

    assert!(!handled);
    assert!(actions.is_empty());
}

#[test]
fn test_link_closed_cleans_up() {
    let mut mgr = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
    let link_id = [0x66; 16];
    let mut rng = make_rng(0x42);
    let (tx, _rx) = make_tx();

    mgr.propose_to_supported(link_id, &test_derived_key(), &mut rng, &tx);
    assert_eq!(mgr.session_count(), 1);

    mgr.link_closed(&link_id);
    assert_eq!(mgr.session_count(), 0);
    assert!(!mgr.has_session_for_link(&link_id));
}

#[test]
fn test_abort_all_sessions_cleans_up_all_links() {
    let mut mgr = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
    let mut rng = make_rng(0x55);
    let (tx, _rx) = make_tx();
    let link_a = [0x11; 16];
    let link_b = [0x22; 16];

    mgr.propose_to_supported(link_a, &test_derived_key(), &mut rng, &tx);
    mgr.propose_to_supported(link_b, &[0xBB; 32], &mut rng, &tx);
    assert!(mgr.session_count() >= 1);

    mgr.abort_all_sessions();

    assert_eq!(mgr.session_count(), 0);
    assert!(!mgr.has_session_for_link(&link_a));
    assert!(!mgr.has_session_for_link(&link_b));
}

#[test]
fn test_handle_probe_failed_with_session() {
    let mut mgr = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
    let link_id = [0x77; 16];
    let mut rng = make_rng(0x42);
    let (tx, _rx) = make_tx();

    mgr.propose_to_supported(link_id, &test_derived_key(), &mut rng, &tx);
    let session_id = *mgr.link_to_session.get(&link_id).unwrap();

    let actions = mgr.handle_probe_failed(link_id, session_id);
    assert_eq!(actions.len(), 1);
    assert!(
        matches!(&actions[0], HolePunchManagerAction::DirectConnectFailed { reason, .. }
            if *reason == rns_core::holepunch::FAIL_PROBE)
    );
}

#[test]
fn responder_probe_failure_rejects_the_request() {
    let mut mgr = accepting_manager();
    let (tx, _rx) = make_tx();
    let link_id = [0x78; 16];
    let payload = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x45);
    let (_, accepted) = mgr.handle_signal(
        link_id,
        UPGRADE_REQUEST,
        payload,
        Some(&test_derived_key()),
        &tx,
    );
    assert!(accepted.iter().any(|a| is_msg(a, UPGRADE_ACCEPT)));
    let session_id = mgr.link_to_session[&link_id];

    let actions = mgr.handle_probe_failed(link_id, session_id);
    assert_eq!(
        reject_reason(&actions),
        Some(rns_core::holepunch::REJECT_NO_ENDPOINT)
    );
    assert!(actions.iter().any(|a| matches!(
        a,
        HolePunchManagerAction::DirectConnectFailed { reason, .. }
            if *reason == rns_core::holepunch::FAIL_PROBE
    )));
    // The failed session is cleaned up.
    mgr.tick(&tx);
    assert_eq!(mgr.session_count(), 0);
}

#[test]
fn test_handle_probe_failed_without_session() {
    let mut mgr = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None);

    let actions = mgr.handle_probe_failed([0x88; 16], [0x99; 16]);
    assert!(actions.is_empty());
}

#[test]
fn test_handle_probe_result_initiator_sends_request() {
    let mut mgr = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
    let link_id = [0xAA; 16];
    let mut rng = make_rng(0x42);
    let (tx, _rx) = make_tx();

    // Propose creates session in Discovering state
    mgr.propose_to_supported(link_id, &test_derived_key(), &mut rng, &tx);
    let session_id = *mgr.link_to_session.get(&link_id).unwrap();

    // Probe result arrives — initiator should send UPGRADE_REQUEST
    let probe_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let observed: SocketAddr = "1.2.3.4:41000".parse().unwrap();
    let actions = mgr.handle_probe_result(
        link_id,
        session_id,
        observed,
        probe_socket,
        make_probe_addr(),
    );

    // Should emit UPGRADE_REQUEST (initiator discovered endpoint -> sends request)
    assert!(actions.iter().any(|a| matches!(a,
        HolePunchManagerAction::SendSignal { msgtype, .. }
        if *msgtype == UPGRADE_REQUEST
    )));
}

#[test]
fn test_handle_probe_result_responder_sends_ready() {
    let mut mgr = accepting_manager();
    let link_id = [0xBB; 16];
    let (tx, _rx) = make_tx();

    // Build UPGRADE_REQUEST from an initiator
    let request_payload = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x42);

    // Responder receives UPGRADE_REQUEST (session enters Discovering)
    mgr.handle_signal(
        link_id,
        UPGRADE_REQUEST,
        request_payload,
        Some(&test_derived_key()),
        &tx,
    );
    let session_id = *mgr.link_to_session.get(&link_id).unwrap();

    // Responder's probe result arrives — should send UPGRADE_READY
    let probe_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let observed: SocketAddr = "5.6.7.8:52000".parse().unwrap();
    let actions = mgr.handle_probe_result(
        link_id,
        session_id,
        observed,
        probe_socket,
        make_probe_addr(),
    );

    assert!(actions.iter().any(|a| matches!(a,
        HolePunchManagerAction::SendSignal { msgtype, .. }
        if *msgtype == UPGRADE_READY
    )));
    // The responder punches toward the initiator endpoint from the request.
    let session = mgr.sessions.get(&session_id).unwrap();
    assert_eq!(session.punch_target, Some("5.6.7.8:41000".parse().unwrap()));
}

#[test]
fn test_endpoint_to_socket_addr_ipv4() {
    let ep = Endpoint {
        addr: vec![10, 0, 0, 1],
        port: 8080,
    };
    let addr = endpoint_to_socket_addr(&ep).unwrap();
    assert_eq!(addr, "10.0.0.1:8080".parse::<SocketAddr>().unwrap());
}

#[test]
fn test_endpoint_to_socket_addr_ipv6() {
    let ep = Endpoint {
        addr: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        port: 9090,
    };
    let addr = endpoint_to_socket_addr(&ep).unwrap();
    assert_eq!(addr, "[::1]:9090".parse::<SocketAddr>().unwrap());
}

#[test]
fn test_endpoint_to_socket_addr_invalid() {
    let ep = Endpoint {
        addr: vec![1, 2, 3],
        port: 80,
    };
    assert!(endpoint_to_socket_addr(&ep).is_none());
}

#[test]
fn test_policy_default_is_reject() {
    let mgr = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None);
    assert_eq!(mgr.policy(), HolePunchPolicy::Reject);
    assert_eq!(HolePunchPolicy::default(), HolePunchPolicy::Reject);
    assert!(!mgr.allow_private_endpoints());
    // Out of the box a node takes no part in Direct Link.
    assert!(!mgr.enabled());
}

#[test]
fn test_set_policy() {
    let mut mgr = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None);
    mgr.set_policy(HolePunchPolicy::Reject);
    assert_eq!(mgr.policy(), HolePunchPolicy::Reject);
}

#[test]
fn test_is_holepunch_message() {
    assert!(HolePunchManager::is_holepunch_message(UPGRADE_REQUEST));
    assert!(HolePunchManager::is_holepunch_message(UPGRADE_READY));
    assert!(!HolePunchManager::is_holepunch_message(HELLO));
    assert!(!HolePunchManager::is_holepunch_message(0x05));
}

#[test]
fn test_tick_empty_is_noop() {
    let mut mgr = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None);
    let (tx, _rx) = make_tx();
    let actions = mgr.tick(&tx);
    assert!(actions.is_empty());
}

#[test]
fn test_propose_without_probe_addr() {
    let mut mgr = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None); // No probe addr
    let link_id = [0xCC; 16];
    let mut rng = make_rng(0x42);
    let (tx, _rx) = make_tx();

    // Fails at once, and says so — an initiator needs a probe address;
    // not even HELLO goes to the peer.
    for propose in [
        HolePunchManager::propose_to_supported,
        HolePunchManager::propose,
    ] {
        let actions = propose(&mut mgr, link_id, &test_derived_key(), &mut rng, &tx);
        assert!(matches!(
            actions[..],
            [HolePunchManagerAction::DirectConnectFailed {
                reason: rns_core::holepunch::FAIL_NOT_STARTED,
                ..
            }]
        ));
    }
    // No session created since propose() failed
    assert_eq!(mgr.session_count(), 0);
}

fn hello_sent(actions: &[HolePunchManagerAction]) -> Vec<bool> {
    actions
        .iter()
        .filter_map(|a| match a {
            HolePunchManagerAction::SendSignal {
                msgtype, payload, ..
            } if *msgtype == HELLO => Some(
                rns_core::holepunch::decode_hello(payload)
                    .unwrap()
                    .reply_wanted,
            ),
            _ => None,
        })
        .collect()
}

#[test]
fn proposal_to_unknown_peer_only_asks_hello() {
    let mut mgr = accepting_manager();
    let (tx, _rx) = make_tx();
    let link_id = [0x61; 16];
    let actions = mgr.propose(link_id, &test_derived_key(), &mut make_rng(1), &tx);
    // Nothing but the capability query goes to a peer not known to
    // implement Direct Link.
    assert_eq!(actions.len(), 1);
    assert_eq!(hello_sent(&actions), vec![true]);
    assert_eq!(mgr.session_count(), 0);
    assert!(!mgr.peer_supported(&link_id));
    // Proposing again while asking sends nothing more.
    assert!(mgr
        .propose(link_id, &test_derived_key(), &mut make_rng(2), &tx)
        .is_empty());
}

#[test]
fn hello_answer_starts_the_waiting_proposal() {
    let mut mgr = accepting_manager();
    let (tx, _rx) = make_tx();
    let link_id = [0x62; 16];
    mgr.propose(link_id, &test_derived_key(), &mut make_rng(1), &tx);
    let actions = mgr.handle_hello(
        link_id,
        &rns_core::holepunch::encode_hello(false),
        Some(&test_derived_key()),
        &mut make_rng(3),
        &tx,
    );
    // An answer is not answered again.
    assert!(hello_sent(&actions).is_empty());
    assert!(mgr.peer_supported(&link_id));
    assert_eq!(mgr.session_count(), 1);
    let session_id = mgr.link_to_session[&link_id];
    assert_eq!(
        mgr.sessions[&session_id].engine.state(),
        HolePunchState::Discovering
    );
}

#[test]
fn hello_query_is_answered_without_proposing() {
    let mut mgr = accepting_manager();
    let (tx, _rx) = make_tx();
    let link_id = [0x63; 16];
    let actions = mgr.handle_hello(
        link_id,
        &rns_core::holepunch::encode_hello(true),
        Some(&test_derived_key()),
        &mut make_rng(3),
        &tx,
    );
    assert_eq!(hello_sent(&actions), vec![false]);
    assert_eq!(actions.len(), 1);
    assert_eq!(mgr.session_count(), 0);
    assert!(mgr.peer_supported(&link_id));
    // Malformed HELLOs are dropped.
    let other = [0x64; 16];
    assert!(mgr
        .handle_hello(other, &[0xC1], None, &mut make_rng(3), &tx)
        .is_empty());
    assert!(!mgr.peer_supported(&other));
}

#[test]
fn unanswered_hello_is_repeated_then_fails_as_unsupported() {
    let mut mgr = accepting_manager();
    let (tx, _rx) = make_tx();
    let link_id = [0x65; 16];
    mgr.propose(link_id, &test_derived_key(), &mut make_rng(1), &tx);
    let now = time::now();
    mgr.peer_support.insert(
        link_id,
        PeerSupport::Querying {
            since: now - HELLO_RETRY_INTERVAL,
            last_sent: now - HELLO_RETRY_INTERVAL,
        },
    );
    assert_eq!(hello_sent(&mgr.tick(&tx)), vec![true]);
    assert!(hello_sent(&mgr.tick(&tx)).is_empty());

    mgr.peer_support.insert(
        link_id,
        PeerSupport::Querying {
            since: now - HELLO_TIMEOUT,
            last_sent: now,
        },
    );
    let actions = mgr.tick(&tx);
    assert!(hello_sent(&actions).is_empty());
    assert!(actions.iter().any(|a| matches!(
        a,
        HolePunchManagerAction::DirectConnectFailed { link_id: l, reason, .. }
            if *l == link_id && *reason == REJECT_UNSUPPORTED
    )));
    assert!(mgr.peer_support.is_empty());
    assert_eq!(mgr.session_count(), 0);
}

#[test]
fn upgrade_message_marks_the_peer_supported() {
    let mut mgr = accepting_manager();
    let (tx, _rx) = make_tx();
    let link_id = [0x66; 16];
    let payload = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x42);
    mgr.handle_signal(
        link_id,
        UPGRADE_REQUEST,
        payload,
        Some(&test_derived_key()),
        &tx,
    );
    assert!(mgr.peer_supported(&link_id));
    mgr.link_closed(&link_id);
    assert!(!mgr.peer_supported(&link_id));
}

#[test]
fn repeated_request_replays_replies_instead_of_refusing() {
    let mut mgr = accepting_manager();
    let (tx, _rx) = make_tx();
    let link_id = [0x67; 16];
    let payload = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x42);
    assert!(mgr.replay_for_repeated_request(link_id, &payload).is_none());
    let (_, first) = mgr.handle_signal(
        link_id,
        UPGRADE_REQUEST,
        payload.clone(),
        Some(&test_derived_key()),
        &tx,
    );
    assert!(first.iter().any(|a| is_msg(a, UPGRADE_ACCEPT)));
    let replay = mgr.replay_for_repeated_request(link_id, &payload).unwrap();
    assert_eq!(replay.len(), 1);
    assert!(is_msg(&replay[0], UPGRADE_ACCEPT));
    // A different session is a new request.
    let other = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x43);
    assert!(mgr.replay_for_repeated_request(link_id, &other).is_none());
}

#[test]
fn manager_takes_part_only_when_configured() {
    let mut mgr = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None);
    mgr.set_policy(HolePunchPolicy::Reject);
    assert!(!mgr.enabled());
    mgr.set_policy(HolePunchPolicy::AcceptAll);
    assert!(mgr.enabled());
    let mut initiator = HolePunchManager::new(vec![make_probe_addr()], ProbeProtocol::Rnsp, None);
    initiator.set_policy(HolePunchPolicy::Reject);
    assert!(initiator.enabled());
    let mut allowlisted = HolePunchManager::new(vec![], ProbeProtocol::Rnsp, None);
    allowlisted.set_policy(HolePunchPolicy::Reject);
    allowlisted.set_allowed_identities(vec![[7; 16]]);
    assert!(allowlisted.enabled());
    assert!(allowlisted.identity_allowed(&[7; 16]));
    assert!(!allowlisted.identity_allowed(&[8; 16]));
}

fn upgraded(mgr: &mut HolePunchManager, link_id: [u8; 16], interface: u64) {
    upgraded_as(mgr, link_id, interface, true, time::now());
}

fn upgraded_as(
    mgr: &mut HolePunchManager,
    link_id: [u8; 16],
    interface: u64,
    initiated: bool,
    since: f64,
) {
    mgr.direct.insert(
        link_id,
        DirectPath {
            interface_id: rns_core::transport::types::InterfaceId(interface),
            session_id: [interface as u8; 16],
            blackhole: Default::default(),
            initiated,
            since,
            peer_addr: "203.0.113.9:4000".parse().unwrap(),
            candidate: DirectCandidateKind::Reflexive,
            candidates: vec![(
                "203.0.113.9:4000".parse().unwrap(),
                DirectCandidateKind::Reflexive,
            )],
            rtt: 0.02,
            mtu: udp_direct::DIRECT_MTU,
            mtu_discovered: false,
            peer_max_packet: Some(rns_core::holepunch::DIRECT_MAX_PACKET),
        },
    );
}

fn reupgrade_due(mgr: &HolePunchManager, link_id: &[u8; 16]) -> Option<f64> {
    mgr.reupgrades.get(link_id).and_then(|entry| entry.due)
}

/// Make the link's scheduled re-upgrade due now, and tick.
fn run_due_reupgrade(mgr: &mut HolePunchManager, link_id: [u8; 16]) -> bool {
    let (tx, _rx) = make_tx();
    if let Some(entry) = mgr.reupgrades.get_mut(&link_id) {
        if entry.due.is_some() {
            entry.due = Some(time::now() - 1.0);
        }
    }
    mgr.tick(&tx)
        .iter()
        .any(|a| matches!(a, HolePunchManagerAction::Reupgrade { link_id: id } if *id == link_id))
}

#[test]
fn reupgrade_delay_doubles_up_to_the_cap_with_bounded_jitter() {
    let config = DirectReupgradeConfig {
        enabled: true,
        max_attempts: 10,
        initial_delay: std::time::Duration::from_secs(60),
        max_delay: std::time::Duration::from_secs(300),
    };
    let delays: Vec<f64> = (0..5).map(|n| reupgrade_delay(&config, n, 0.0)).collect();
    assert_eq!(delays, vec![60.0, 120.0, 240.0, 300.0, 300.0]);
    // Jitter adds at most a quarter.
    let jittered = reupgrade_delay(&config, 1, 0.999_999);
    assert!(jittered > 149.9 && jittered < 150.0, "{jittered}");
    assert!(reupgrade_delay(&config, 1000, 0.5) <= 300.0 * 1.25);
    // Never sooner than a link may be proposed on again.
    let short = DirectReupgradeConfig {
        initial_delay: std::time::Duration::from_secs(1),
        max_delay: std::time::Duration::from_secs(2),
        ..config
    };
    assert_eq!(reupgrade_delay(&short, 0, 0.0), 60.0);
    assert_eq!(reupgrade_delay(&short, 3, 0.0), 60.0);
    for _ in 0..100 {
        let unit = random_unit();
        assert!((0.0..1.0).contains(&unit));
    }
}

#[test]
fn lost_direct_path_is_proposed_again_with_backoff_until_the_limit() {
    let mut mgr = accepting_manager();
    mgr.set_reupgrade_config(DirectReupgradeConfig {
        max_attempts: 3,
        ..DirectReupgradeConfig::default()
    });
    let link_id = [0x71; 16];
    upgraded(&mut mgr, link_id, 50_100);
    let now = time::now();
    assert!(mgr
        .take_direct(&link_id, DirectLossCause::LinkFailed)
        .is_some());
    let due = reupgrade_due(&mgr, &link_id).expect("re-upgrade scheduled");
    assert!(
        due >= now + 60.0 && due <= now + 75.0 + 1.0,
        "{}",
        due - now
    );
    // Not before it is due.
    let (tx, _rx) = make_tx();
    assert!(!mgr
        .tick(&tx)
        .iter()
        .any(|a| matches!(a, HolePunchManagerAction::Reupgrade { .. })));

    // Each failed attempt schedules the next, twice as far out.
    let mut delays = Vec::new();
    for _ in 0..3 {
        assert!(run_due_reupgrade(&mut mgr, link_id));
        // Once handed out, it is not handed out again.
        assert!(!run_due_reupgrade(&mut mgr, link_id));
        let before = time::now();
        mgr.reupgrade_failed(link_id, rns_core::holepunch::FAIL_TIMEOUT);
        if let Some(due) = reupgrade_due(&mgr, &link_id) {
            delays.push(due - before);
        }
    }
    assert_eq!(delays.len(), 2, "{delays:?}");
    assert!(delays[0] >= 120.0 && delays[0] <= 150.0 + 1.0, "{delays:?}");
    assert!(delays[1] >= 240.0 && delays[1] <= 300.0 + 1.0, "{delays:?}");
    // The third failure was the last attempt.
    assert!(!mgr.reupgrades.contains_key(&link_id));
}

#[test]
fn reupgrade_stops_on_refusal_success_or_link_close() {
    let link_id = [0x72; 16];
    let lost = |mgr: &mut HolePunchManager| {
        upgraded(mgr, link_id, 50_101);
        mgr.direct_interface_down(rns_core::transport::types::InterfaceId(50_101));
        assert!(reupgrade_due(mgr, &link_id).is_some());
    };

    // The peer refuses by policy, or stopped answering HELLO.
    for reason in [REJECT_POLICY, REJECT_UNSUPPORTED] {
        let mut mgr = accepting_manager();
        lost(&mut mgr);
        assert!(run_due_reupgrade(&mut mgr, link_id));
        mgr.reupgrade_failed(link_id, reason);
        assert!(!mgr.reupgrades.contains_key(&link_id));
    }

    // A failure while nothing is in flight (the application's own
    // proposal) does not move the schedule.
    let mut mgr = accepting_manager();
    lost(&mut mgr);
    let due = reupgrade_due(&mgr, &link_id);
    mgr.reupgrade_failed(link_id, rns_core::holepunch::FAIL_TIMEOUT);
    assert_eq!(reupgrade_due(&mgr, &link_id), due);

    // The link closes, or the driver finds it no longer active.
    mgr.link_closed(&link_id);
    assert!(!mgr.reupgrades.contains_key(&link_id));
    let mut mgr = accepting_manager();
    lost(&mut mgr);
    mgr.cancel_reupgrade(&link_id);
    assert!(!run_due_reupgrade(&mut mgr, link_id));
}

#[test]
fn reupgrade_postponed_by_a_stale_link_keeps_its_attempt() {
    let link_id = [0x75; 16];
    let mut mgr = accepting_manager();
    upgraded(&mut mgr, link_id, 50_109);
    mgr.take_direct(&link_id, DirectLossCause::LinkFailed);
    assert!(run_due_reupgrade(&mut mgr, link_id));
    // The link was stale for the moment: it is looked at again shortly,
    // and that does not count as an attempt.
    let before = time::now();
    mgr.postpone_reupgrade(link_id);
    assert_eq!(mgr.reupgrades[&link_id].attempts, 1);
    let due = reupgrade_due(&mgr, &link_id).expect("re-upgrade still scheduled");
    assert!(
        due >= before + REUPGRADE_STALE_RETRY && due <= time::now() + REUPGRADE_STALE_RETRY,
        "{}",
        due - before
    );
    assert!(run_due_reupgrade(&mut mgr, link_id));
    assert_eq!(mgr.reupgrades[&link_id].attempts, 1);

    // Nothing in flight: the schedule stays.
    mgr.reupgrade_failed(link_id, rns_core::holepunch::FAIL_TIMEOUT);
    let due = reupgrade_due(&mgr, &link_id);
    mgr.postpone_reupgrade(link_id);
    assert_eq!(reupgrade_due(&mgr, &link_id), due);
    assert_eq!(mgr.reupgrades[&link_id].attempts, 2);
}

#[test]
fn only_the_proposing_side_reupgrades_and_only_when_enabled() {
    let link_id = [0x73; 16];
    // The responder side of the lost upgrade.
    let mut mgr = accepting_manager();
    upgraded_as(&mut mgr, link_id, 50_102, false, time::now());
    mgr.take_direct(&link_id, DirectLossCause::LinkFailed);
    assert!(!mgr.reupgrades.contains_key(&link_id));

    // Turned off.
    let mut mgr = accepting_manager();
    mgr.set_reupgrade_config(DirectReupgradeConfig {
        enabled: false,
        ..DirectReupgradeConfig::default()
    });
    upgraded(&mut mgr, link_id, 50_103);
    mgr.take_direct(&link_id, DirectLossCause::LinkFailed);
    assert!(!mgr.reupgrades.contains_key(&link_id));

    // No facilitator to propose through any more.
    let mut mgr = accepting_manager();
    mgr.set_probe_config(vec![], ProbeProtocol::Rnsp, None);
    upgraded(&mut mgr, link_id, 50_104);
    mgr.take_direct(&link_id, DirectLossCause::LinkFailed);
    assert!(!mgr.reupgrades.contains_key(&link_id));
}

#[test]
fn a_long_lived_path_starts_the_attempt_count_again() {
    let link_id = [0x74; 16];
    let mut mgr = accepting_manager();
    mgr.set_reupgrade_config(DirectReupgradeConfig {
        max_attempts: 2,
        ..DirectReupgradeConfig::default()
    });
    upgraded(&mut mgr, link_id, 50_105);
    mgr.take_direct(&link_id, DirectLossCause::LinkFailed);
    assert!(run_due_reupgrade(&mut mgr, link_id));
    mgr.reupgrade_failed(link_id, rns_core::holepunch::FAIL_TIMEOUT);
    assert_eq!(mgr.reupgrades[&link_id].attempts, 2);
    // The next attempt succeeds, and the path is lost again soon: the
    // count goes on, and that was the last attempt.
    assert!(run_due_reupgrade(&mut mgr, link_id));
    mgr.reupgrades.get_mut(&link_id).unwrap().in_flight = false;
    upgraded(&mut mgr, link_id, 50_106);
    mgr.take_direct(&link_id, DirectLossCause::LinkFailed);
    assert!(!mgr.reupgrades.contains_key(&link_id));

    // A path that lasted past the longest delay starts over.
    upgraded(&mut mgr, link_id, 50_107);
    mgr.take_direct(&link_id, DirectLossCause::LinkFailed);
    assert!(run_due_reupgrade(&mut mgr, link_id));
    mgr.reupgrade_failed(link_id, rns_core::holepunch::FAIL_TIMEOUT);
    assert_eq!(mgr.reupgrades[&link_id].attempts, 2);
    assert!(run_due_reupgrade(&mut mgr, link_id));
    mgr.reupgrades.get_mut(&link_id).unwrap().in_flight = false;
    upgraded_as(&mut mgr, link_id, 50_108, true, time::now() - 1000.0);
    mgr.take_direct(&link_id, DirectLossCause::LinkFailed);
    assert_eq!(mgr.reupgrades[&link_id].attempts, 1);
}

#[test]
fn status_reports_paths_counts_failures_and_losses() {
    let mut mgr = accepting_manager();
    let link_id = [0x51; 16];
    let other = [0x52; 16];
    assert!(mgr.status().links.is_empty());

    upgraded(&mut mgr, link_id, 50_201);
    mgr.count(link_id, |c| c.established += 1);
    mgr.note_direct_mtu(rns_core::transport::types::InterfaceId(50_201), 1400);
    mgr.note_failed(other, rns_core::holepunch::FAIL_TIMEOUT);
    mgr.note_failed(other, rns_core::holepunch::FAIL_TIMEOUT);
    mgr.note_failed(other, REJECT_BUSY);

    let status = mgr.status();
    assert_eq!(
        status.links.iter().map(|l| l.link_id).collect::<Vec<_>>(),
        vec![link_id, other]
    );
    let direct = status.links[0].direct.as_ref().unwrap();
    assert_eq!(direct.mtu, 1400);
    assert!(direct.mtu_discovered);
    assert_eq!(direct.candidate, DirectCandidateKind::Reflexive);
    assert_eq!(
        status.totals.failed,
        vec![(REJECT_BUSY, 1), (rns_core::holepunch::FAIL_TIMEOUT, 2)]
    );
    assert_eq!(status.totals.failed_total(), 3);
    assert_eq!(status.totals.established, 1);
    assert_eq!(status.links[1].last_failure.map(|f| f.0), Some(REJECT_BUSY));

    mgr.take_direct(&link_id, DirectLossCause::PeerFallback);
    let status = mgr.status();
    assert!(status.links[0].direct.is_none());
    assert_eq!(
        status.links[0].last_loss.map(|l| l.0),
        Some(DirectLossCause::PeerFallback)
    );
    assert_eq!(status.totals.lost, 1);

    // A closed link leaves the report; the totals stay.
    mgr.link_closed(&link_id);
    mgr.link_closed(&other);
    let status = mgr.status();
    assert!(status.links.is_empty());
    assert_eq!(status.totals.failed_total(), 3);
}

#[test]
fn closed_link_retires_its_direct_interface_after_a_delay() {
    use rns_core::transport::types::InterfaceId;
    let mut mgr = accepting_manager();
    let (tx, _rx) = make_tx();
    let link_id = [0x71; 16];
    upgraded(&mut mgr, link_id, 50_001);
    assert_eq!(mgr.direct_interface(&link_id), Some(InterfaceId(50_001)));
    assert!(mgr.is_direct_interface(InterfaceId(50_001)));

    mgr.link_closed(&link_id);
    assert_eq!(mgr.direct_interface(&link_id), None);
    // Still a direct interface (no broadcasts) while it is retiring.
    assert!(mgr.is_direct_interface(InterfaceId(50_001)));
    assert!(!mgr
        .tick(&tx)
        .iter()
        .any(|a| matches!(a, HolePunchManagerAction::RemoveDirectInterface { .. })));
    mgr.retiring[0].2 = time::now() - 0.1;
    let actions = mgr.tick(&tx);
    assert!(actions.iter().any(|a| matches!(
        a,
        HolePunchManagerAction::RemoveDirectInterface { link_id: l, interface_id }
            if *l == link_id && *interface_id == InterfaceId(50_001)
    )));
    assert!(mgr.retiring.is_empty());
    assert!(mgr.tick(&tx).is_empty());
}

#[test]
fn direct_interface_down_forgets_it() {
    use rns_core::transport::types::InterfaceId;
    let mut mgr = accepting_manager();
    let link_id = [0x72; 16];
    upgraded(&mut mgr, link_id, 50_002);
    assert_eq!(mgr.direct_interface_down(InterfaceId(7)), None);
    assert_eq!(
        mgr.direct_interface_down(InterfaceId(50_002)),
        Some((link_id, [(50_002u64 as u8); 16]))
    );
    assert!(!mgr.is_direct_interface(InterfaceId(50_002)));
    assert_eq!(mgr.direct_interface_down(InterfaceId(50_002)), None);
    // A retiring interface that goes down is not removed twice.
    upgraded(&mut mgr, link_id, 50_003);
    mgr.link_closed(&link_id);
    assert_eq!(mgr.direct_interface_down(InterfaceId(50_003)), None);
    assert!(mgr.retiring.is_empty());
}

#[test]
fn own_proposal_is_reported_and_can_be_yielded() {
    let mut mgr = accepting_manager();
    let (tx, _rx) = make_tx();
    let link_id = [0x73; 16];
    assert!(!mgr.proposing(&link_id));
    // Asking HELLO counts as proposing.
    mgr.propose(link_id, &test_derived_key(), &mut make_rng(1), &tx);
    assert!(mgr.proposing(&link_id));
    mgr.yield_proposal(&link_id);
    assert!(!mgr.proposing(&link_id));
    assert!(mgr.peer_supported(&link_id));

    // So does a running initiator session; yielding drops it quietly.
    mgr.propose(link_id, &test_derived_key(), &mut make_rng(2), &tx);
    assert!(mgr.proposing(&link_id));
    assert_eq!(mgr.session_count(), 1);
    mgr.yield_proposal(&link_id);
    assert!(!mgr.proposing(&link_id));
    assert_eq!(mgr.session_count(), 0);
    assert!(mgr
        .tick(&tx)
        .iter()
        .all(|a| !matches!(a, HolePunchManagerAction::DirectConnectFailed { .. })));

    // A responder session is not ours to yield.
    let request = make_request(link_id, "1.2.3.4:4343", "5.6.7.8:41000", 0x44);
    mgr.handle_signal(
        link_id,
        UPGRADE_REQUEST,
        request,
        Some(&test_derived_key()),
        &tx,
    );
    assert!(!mgr.proposing(&link_id));
    mgr.yield_proposal(&link_id);
    assert_eq!(mgr.session_count(), 1);
}
