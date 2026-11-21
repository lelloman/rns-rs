use super::*;

/// One message as [`send_bytes`] frames it.
fn framed(message: &[u8]) -> Vec<u8> {
    let mut out = (message.len() as i32).to_be_bytes().to_vec();
    out.extend_from_slice(message);
    out
}

/// Take the session's output as messages.
fn sent_messages(session: &mut ServerSession) -> Vec<Vec<u8>> {
    let mut pending = session.pending().to_vec();
    session.sent(pending.len());
    let mut messages = Vec::new();
    while let Some(message) = take_message(&mut pending, MAX_MESSAGE).unwrap() {
        messages.push(message);
    }
    messages
}

#[test]
fn server_session_runs_the_exchange_a_server_thread_runs() {
    let key = derive_auth_key(b"session");
    let mut session = ServerSession::new(key, [3; CHALLENGE_LEN]);
    let challenge = sent_messages(&mut session).remove(0);
    let challenged = challenge.strip_prefix(CHALLENGE_PREFIX).unwrap();
    assert!(session
        .receive(&framed(&create_response(&key, challenged)))
        .unwrap()
        .is_none());
    assert_eq!(sent_messages(&mut session), vec![WELCOME.to_vec()]);

    // The client challenges back; the session answers it.
    let mut client_challenge = CHALLENGE_PREFIX.to_vec();
    client_challenge.extend_from_slice(b"{sha256}");
    client_challenge.extend_from_slice(&[9; CHALLENGE_LEN]);
    session.receive(&framed(&client_challenge)).unwrap();
    let answer = sent_messages(&mut session).remove(0);
    assert!(verify_response(
        &key,
        &client_challenge[CHALLENGE_PREFIX.len()..],
        &answer
    ));
    session.receive(&framed(WELCOME)).unwrap();

    // The request may arrive a byte at a time.
    let request = framed(b"request");
    let (last, head) = request.split_last().unwrap();
    for byte in head {
        assert!(session.receive(&[*byte]).unwrap().is_none());
    }
    assert_eq!(
        session.receive(&[*last]).unwrap(),
        Some(b"request".to_vec())
    );
    assert!(!session.wants_input());
    session.answer(b"answer");
    assert!(!session.finished());
    assert_eq!(sent_messages(&mut session), vec![b"answer".to_vec()]);
    assert!(session.finished());
}

#[test]
fn server_session_refuses_a_wrong_answer() {
    let mut session = ServerSession::new(derive_auth_key(b"right"), [3; CHALLENGE_LEN]);
    let challenge = sent_messages(&mut session).remove(0);
    let wrong = create_response(
        &derive_auth_key(b"wrong"),
        &challenge[CHALLENGE_PREFIX.len()..],
    );
    let refused = session.receive(&framed(&wrong)).unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(sent_messages(&mut session), vec![FAILURE.to_vec()]);
    assert!(session.finished());
}

#[test]
fn server_session_bounds_messages_before_the_request() {
    let mut session = ServerSession::new(derive_auth_key(b"bound"), [3; CHALLENGE_LEN]);
    let huge = ((MAX_HANDSHAKE_MESSAGE + 1) as i32).to_be_bytes();
    assert_eq!(
        session.receive(&huge).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    // The session is over: the connection closes, as a server thread's
    // does when its read fails.
    sent_messages(&mut session);
    assert!(session.finished());
}

#[test]
fn discovered_interface_rpc_includes_operator_lxmf_address() {
    let interface = crate::discovery::DiscoveredInterface {
        dst_cost: None,
        pr_cost: None,
        interface_type: "BackboneInterface".into(),
        impl_name: Some("Reticulum".into()),
        impl_version: Some("1.5.5".into()),
        transport: true,
        name: "Operator Test".into(),
        discovered: 1.0,
        last_heard: 2.0,
        heard_count: 1,
        status: crate::discovery::DiscoveredStatus::Available,
        stamp: vec![0; crate::discovery::STAMP_SIZE],
        stamp_value: rns_core::stamp::StampValue::from_whole(16),
        transport_id: [0x11; 16],
        network_id: [0x22; 16],
        hops: 1,
        latitude: None,
        longitude: None,
        height: None,
        operator_lxmf_address: Some([0xa5; 16]),
        reachable_on: Some("example.com".into()),
        port: Some(4242),
        frequency: None,
        bandwidth: None,
        spreading_factor: None,
        coding_rate: None,
        modulation: None,
        channel: None,
        ifac_netname: None,
        ifac_netkey: None,
        config_entry: None,
        discovery_hash: [0x33; 32],
    };

    let encoded = discovered_interfaces_to_pickle(&[interface]);
    let first = &encoded.as_list().unwrap()[0];

    assert_eq!(
        first.get("impl_name").and_then(PickleValue::as_str),
        Some("Reticulum")
    );
    assert_eq!(
        first.get("version").and_then(PickleValue::as_str),
        Some("1.5.5")
    );

    assert_eq!(
        first
            .get("operator_lxmf_address")
            .and_then(PickleValue::as_str),
        Some("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5")
    );
}

#[test]
fn send_recv_bytes_roundtrip() {
    let (mut c1, mut c2) = tcp_pair();
    let data = b"hello world";
    send_bytes(&mut c1, data).unwrap();
    let received = recv_bytes(&mut c2).unwrap();
    assert_eq!(&received, data);
}

#[test]
fn send_recv_empty() {
    let (mut c1, mut c2) = tcp_pair();
    send_bytes(&mut c1, b"").unwrap();
    let received = recv_bytes(&mut c2).unwrap();
    assert!(received.is_empty());
}

#[test]
fn auth_success() {
    let key = derive_auth_key(b"test-private-key");
    let (mut server, mut client) = tcp_pair();

    let key2 = key;
    let t = thread::spawn(move || {
        client_auth(&mut client, &key2).unwrap();
    });

    server_auth(&mut server, &key).unwrap();
    answer_challenge(&mut server, &key).unwrap();
    t.join().unwrap();
}

#[test]
fn auth_failure_wrong_key() {
    let server_key = derive_auth_key(b"server-key");
    let client_key = derive_auth_key(b"wrong-key");
    let (mut server, mut client) = tcp_pair();

    let t = thread::spawn(move || {
        let result = client_auth(&mut client, &client_key);
        assert!(result.is_err());
    });

    let result = server_auth(&mut server, &server_key);
    assert!(result.is_err());
    t.join().unwrap();
}

#[test]
fn rpc_connection_closes_after_a_failed_request() {
    // Upstream closes the RPC connection in a `finally` block; here the
    // stream is owned by `handle_connection` and dropped on every return.
    let key = derive_auth_key(b"test-private-key");
    let (server, mut client) = tcp_pair();
    let (event_tx, event_rx) = crate::event::channel();
    drop(event_rx);

    let handler = thread::spawn(move || handle_connection(server, &key, &event_tx));

    client_auth(&mut client, &key).unwrap();
    let request = PickleValue::Dict(vec![(
        PickleValue::String("get".into()),
        PickleValue::String("path_table".into()),
    )]);
    send_bytes(&mut client, &pickle::encode(&request)).unwrap();

    let error = handler.join().unwrap().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    let mut buf = [0u8; 1];
    assert_eq!(client.read(&mut buf).unwrap(), 0);
}

#[test]
fn destination_type_rpc_calls_reach_the_driver() {
    // The calls Python `Reticulum.wants_destination_type` and friends
    // send to the shared instance (upstream 825c2e19).
    let (event_tx, event_rx) = crate::event::channel();
    let driver = thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..3 {
            let Ok(Event::Query(request, resp_tx)) =
                event_rx.recv_timeout(std::time::Duration::from_secs(5))
            else {
                panic!("expected a query");
            };
            let response = match &*request {
                QueryRequest::WantsDestinationType { .. } => true,
                QueryRequest::UnwantsDestinationType { .. } => false,
                QueryRequest::UnwantsAllDestinationTypes { .. } => true,
                other => panic!("unexpected query {other:?}"),
            };
            seen.push(*request);
            let _ = resp_tx.send(QueryResponse::DestinationTypeRegistration(response));
        }
        seen
    });

    let call = |entries: Vec<(&str, PickleValue)>| {
        let request = PickleValue::Dict(
            entries
                .into_iter()
                .map(|(key, value)| (PickleValue::String(key.into()), value))
                .collect(),
        );
        handle_rpc_request(&request, &mut event_tx.clone()).unwrap()
    };
    let requester = PickleValue::Bytes(vec![0x11; 16]);
    assert_eq!(
        call(vec![
            (
                "wants_destination_type",
                PickleValue::String("rncp.receive".into())
            ),
            ("requester", requester.clone()),
            ("signature", PickleValue::None),
        ]),
        PickleValue::Bool(true)
    );
    assert_eq!(
        call(vec![
            (
                "unwants_destination_type",
                PickleValue::String("rnx.execute".into())
            ),
            ("requester", requester.clone()),
            ("signature", PickleValue::None),
        ]),
        PickleValue::Bool(false)
    );
    assert_eq!(
        call(vec![
            ("unwants_all_destination_types", PickleValue::Bool(true)),
            ("requester", requester),
            ("signature", PickleValue::None),
        ]),
        PickleValue::Bool(true)
    );

    let seen = driver.join().unwrap();
    assert!(matches!(
        &seen[0],
        QueryRequest::WantsDestinationType { full_name, requester }
            if full_name == "rncp.receive" && requester == &vec![0x11; 16]
    ));
    assert!(matches!(
        &seen[1],
        QueryRequest::UnwantsDestinationType { full_name, .. } if full_name == "rnx.execute"
    ));
    assert!(matches!(
        &seen[2],
        QueryRequest::UnwantsAllDestinationTypes { requester } if requester == &vec![0x11; 16]
    ));
}

#[test]
fn verify_sha256_response() {
    let key = derive_auth_key(b"mykey");
    let message = b"{sha256}abcdefghijklmnopqrstuvwxyz0123456789ABCD";
    let response = create_response(&key, message);
    assert!(response.starts_with(b"{sha256}"));
    assert!(verify_response(&key, message, &response));
}

#[test]
fn verify_legacy_md5_response() {
    let key = derive_auth_key(b"mykey");
    // Legacy message: 20 bytes, no prefix
    let message = b"01234567890123456789";
    // Create legacy response (raw HMAC-MD5)
    let digest = hmac_md5(&key, message);
    assert!(verify_response(&key, message, &digest));
}

#[test]
fn constant_time_eq_works() {
    assert!(constant_time_eq(b"hello", b"hello"));
    assert!(!constant_time_eq(b"hello", b"world"));
    assert!(!constant_time_eq(b"hello", b"hell"));
}

#[test]
fn rpc_payload_accepts_msgpack_and_legacy_pickle() {
    let request = PickleValue::Dict(vec![
        (
            PickleValue::String("get".into()),
            PickleValue::String("link_count".into()),
        ),
        (PickleValue::String("max_hops".into()), PickleValue::Int(3)),
    ]);

    let msgpack_bytes = encode_rpc_payload(&request, RpcCodec::Msgpack);
    let (decoded_msgpack, msgpack_codec) = decode_rpc_payload(&msgpack_bytes).unwrap();
    assert_eq!(decoded_msgpack, request);
    assert_eq!(msgpack_codec, RpcCodec::Msgpack);

    let pickle_bytes = encode_rpc_payload(&request, RpcCodec::Pickle);
    let (decoded_pickle, pickle_codec) = decode_rpc_payload(&pickle_bytes).unwrap();
    assert_eq!(decoded_pickle, request);
    assert_eq!(pickle_codec, RpcCodec::Pickle);
}

#[test]
fn rpc_roundtrip() {
    let key = derive_auth_key(b"test-key");
    let (event_tx, event_rx) = crate::event::channel();

    // Start server
    // Bind manually to get the actual port
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown2 = shutdown.clone();

    // Driver thread that handles queries
    let driver_thread = thread::spawn(move || loop {
        match event_rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Event::Query(request, resp_tx)) if matches!(*request, QueryRequest::LinkCount) => {
                let _ = resp_tx.send(QueryResponse::LinkCount(42));
            }
            Ok(Event::Query(request, resp_tx))
                if matches!(*request, QueryRequest::ActiveLinkCount) =>
            {
                let _ = resp_tx.send(QueryResponse::ActiveLinkCount(7));
            }
            Ok(Event::Query(request, resp_tx))
                if matches!(*request, QueryRequest::LowestInterfaceBitrate) =>
            {
                let _ = resp_tx.send(QueryResponse::LowestInterfaceBitrate(Some(400)));
            }
            Ok(Event::Query(request, resp_tx))
                if matches!(*request, QueryRequest::MediumPathTimeout) =>
            {
                let _ = resp_tx.send(QueryResponse::MediumPathTimeout(26.0));
            }
            Ok(Event::Query(request, resp_tx))
                if matches!(*request, QueryRequest::FirstHopTimeout { .. }) =>
            {
                let QueryRequest::FirstHopTimeout { dest_hash } = *request else {
                    unreachable!()
                };
                assert_eq!(dest_hash, [0x77; 16]);
                let _ = resp_tx.send(QueryResponse::FirstHopTimeout(6.4));
            }
            Ok(Event::Query(request, resp_tx))
                if matches!(*request, QueryRequest::InterfaceStats) =>
            {
                let _ = resp_tx.send(QueryResponse::InterfaceStats(InterfaceStatsResponse {
                    network_id: None,
                    interfaces: vec![SingleInterfaceStat {
                        id: 7,
                        name: "TestInterface".into(),
                        display_name: "TestInterface[TestInterface]".into(),
                        parent_display_name: None,
                        tunnel_id: None,
                        remote_transport_id: None,
                        remote_transport_info: None,
                        status: true,
                        mode: 1,
                        gravity: -2,
                        announces_to_internal: Some(true),
                        rxb: 1000,
                        txb: 2000,
                        tx_drops: 0,
                        tx_dropped_bytes: 0,
                        tx_stalled: false,
                        tx_buffered: 0,
                        traffic: TrafficDetail::default(),
                        protocol_violations: 0,
                        ifac_violations: 0,
                        packet_filter_hits: 0,
                        hop_limiter_hits: 0,
                        stamped_path_requests: 0,
                        rx_packets: 10,
                        tx_packets: 20,
                        cpu_load: None,
                        mem_load: None,
                        switch_id: None,
                        endpoint_id: None,
                        via_switch_id: None,
                        peers: None,
                        rssi: None,
                        snr: None,
                        signal_quality: None,
                        frequency: None,
                        bandwidth: None,
                        txpower: None,
                        spreading_factor: None,
                        coding_rate: None,
                        channel: None,
                        modulation: None,
                        radio: None,
                        bitrate: Some(10_000_000),
                        bitrate_is_float: false,
                        mtu: Some(262_144),
                        ifac_size: None,
                        started: 1000.0,
                        ia_freq: 0.0,
                        ip_freq: 0.0,
                        op_freq: 0.0,
                        op_samples: 0,
                        burst_active: false,
                        burst_activated: 0.0,
                        pr_burst_active: false,
                        pr_burst_activated: 0.0,
                        oa_freq: 0.0,
                        clients: Some(2),
                        blocked_ips: None,
                        blocked_ip_list: None,
                        i2p: None,
                        i2p_tunnel_state: None,
                        autoconnect_source: None,
                        announce_rate_target: Some(3600.0),
                        announce_rate_grace: 5,
                        announce_rate_penalty: 0.0,
                        interface_type: "TestInterface".into(),
                        held_announces: 0,
                        announce_queue: 0,
                        ifac_netname: None,
                        ifac_signature: None,
                    }],
                    transport_id: None,
                    transport_enabled: true,
                    transport_uptime: 3600.0,
                    total_rxb: 1000,
                    total_txb: 2000,
                    rx_pps: 3.0,
                    tx_pps: 4.0,
                    traffic: TrafficDetail::default(),
                    probe_responder: None,
                    backbone_peer_pool: None,
                    ..Default::default()
                }));
            }
            _ => break,
        }
    });

    let key2 = key;
    let shutdown3 = shutdown2.clone();
    let (listener, wake) = Listener::new(listener).unwrap();
    let server_thread = thread::spawn(move || {
        rpc_server_loop(listener, key2, event_tx, shutdown3);
    });

    // Give server time to start
    thread::sleep(std::time::Duration::from_millis(50));

    // Client: connect and query link count
    let server_addr = RpcAddr::Tcp("127.0.0.1".into(), port);
    let mut client = RpcClient::connect(&server_addr, &key).unwrap();
    let response = client
        .call(&PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("link_count".into()),
        )]))
        .unwrap();
    assert_eq!(response.as_int().unwrap(), 42);
    drop(client);

    let mut active_client = RpcClient::connect(&server_addr, &key).unwrap();
    let active_response = active_client
        .call(&PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("active_link_count".into()),
        )]))
        .unwrap();
    assert_eq!(active_response.as_int().unwrap(), 7);
    drop(active_client);

    let mut timeout_client = RpcClient::connect(&server_addr, &key).unwrap();
    let bitrate = timeout_client
        .call(&PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("lowest_interface_bitrate".into()),
        )]))
        .unwrap();
    assert_eq!(bitrate.as_int(), Some(400));
    drop(timeout_client);
    let mut timeout_client = RpcClient::connect(&server_addr, &key).unwrap();
    let timeout = timeout_client
        .call(&PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("medium_path_timeout".into()),
        )]))
        .unwrap();
    assert_eq!(timeout.as_float(), Some(26.0));
    drop(timeout_client);
    let mut timeout_client = RpcClient::connect(&server_addr, &key).unwrap();
    let first_hop = timeout_client
        .call(&PickleValue::Dict(vec![
            (
                PickleValue::String("get".into()),
                PickleValue::String("first_hop_timeout".into()),
            ),
            (
                PickleValue::String("destination_hash".into()),
                PickleValue::Bytes(vec![0x77; 16]),
            ),
        ]))
        .unwrap();
    assert_eq!(first_hop.as_float(), Some(6.4));
    drop(timeout_client);

    // Client: query interface stats
    let mut client2 = RpcClient::connect(&server_addr, &key).unwrap();
    let response2 = client2
        .call(&PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("interface_stats".into()),
        )]))
        .unwrap();
    let ifaces = response2.get("interfaces").unwrap().as_list().unwrap();
    assert_eq!(ifaces.len(), 1);
    let iface = &ifaces[0];
    assert_eq!(
        iface.get("name").unwrap().as_str().unwrap(),
        "TestInterface[TestInterface]"
    );
    assert_eq!(
        iface.get("short_name").unwrap().as_str().unwrap(),
        "TestInterface"
    );
    assert_eq!(iface.get("rxb").unwrap().as_int().unwrap(), 1000);
    // Upstream's rnstatus compares a present `blocked_ips` with 0.
    assert!(iface.get("blocked_ips").is_none());
    assert!(iface.get("blocked_ip_list").is_none());
    assert_eq!(iface.get("mtu").unwrap().as_int(), Some(262_144));
    drop(client2);

    // Shutdown
    shutdown2.store(true, Ordering::Relaxed);
    wake.wake();
    server_thread.join().unwrap();
    driver_thread.join().unwrap();
}

#[test]
fn full_event_queue_fails_rpc_query_without_blocking() {
    let (event_tx, event_rx) = crate::event::channel_with_capacity(1);
    event_tx.send(Event::Tick).unwrap();

    let (result_tx, result_rx) = mpsc::channel();
    let query_thread = thread::spawn(move || {
        let _ = result_tx.send(send_query(&mut event_tx.clone(), query::LinkCount));
    });

    let completed_promptly = match result_rx.recv_timeout(Duration::from_millis(250)) {
        Ok(result) => {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
            true
        }
        Err(mpsc::RecvTimeoutError::Timeout) => false,
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("RPC query thread disconnected without a result")
        }
    };

    // Let the old blocking implementation finish so a regression failure does
    // not leak a thread into the rest of the test process.
    assert!(matches!(event_rx.recv().unwrap(), Event::Tick));
    if !completed_promptly {
        match event_rx.recv_timeout(Duration::from_secs(1)).unwrap() {
            Event::Query(request, response_tx) if matches!(*request, QueryRequest::LinkCount) => {
                response_tx.send(QueryResponse::LinkCount(1)).unwrap();
            }
            other => panic!("unexpected event after releasing queue: {other:?}"),
        }
        let _ = result_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    query_thread.join().unwrap();

    assert!(
        completed_promptly,
        "RPC query blocked while the driver event queue was full"
    );
}

#[test]
fn stalled_rpc_request_does_not_block_later_clients() {
    let key = derive_auth_key(b"concurrent-rpc-test");
    let (event_tx, event_rx) = crate::event::channel();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();

    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = shutdown.clone();
    let (listener, wake) = Listener::new(listener).unwrap();
    let server_thread = thread::spawn(move || {
        rpc_server_loop(listener, key, event_tx, server_shutdown);
    });

    let (first_seen_tx, first_seen_rx) = mpsc::channel();
    let (concurrent_tx, concurrent_rx) = mpsc::channel();
    let driver_thread = thread::spawn(move || {
        let first_response = match event_rx.recv_timeout(Duration::from_secs(1)).unwrap() {
            Event::Query(request, response_tx) if matches!(*request, QueryRequest::LinkCount) => {
                response_tx
            }
            other => panic!("unexpected first RPC event: {other:?}"),
        };
        first_seen_tx.send(()).unwrap();

        let second = event_rx.recv_timeout(Duration::from_millis(500));
        let handled_concurrently = match second {
            Ok(Event::Query(request, response_tx))
                if matches!(*request, QueryRequest::TransportIdentity) =>
            {
                response_tx
                    .send(QueryResponse::TransportIdentity(Some([7; 16])))
                    .unwrap();
                true
            }
            Ok(other) => panic!("unexpected second RPC event: {other:?}"),
            Err(mpsc::RecvTimeoutError::Timeout) => false,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("RPC event channel disconnected")
            }
        };

        first_response.send(QueryResponse::LinkCount(1)).unwrap();

        if !handled_concurrently {
            match event_rx.recv_timeout(Duration::from_secs(1)).unwrap() {
                Event::Query(request, response_tx)
                    if matches!(*request, QueryRequest::TransportIdentity) =>
                {
                    response_tx
                        .send(QueryResponse::TransportIdentity(Some([7; 16])))
                        .unwrap();
                }
                other => panic!("unexpected delayed RPC event: {other:?}"),
            }
        }
        concurrent_tx.send(handled_concurrently).unwrap();
    });

    let first_addr = RpcAddr::Tcp("127.0.0.1".into(), port);
    let first_client = thread::spawn(move || {
        let mut client = RpcClient::connect(&first_addr, &key).unwrap();
        client
            .call(&PickleValue::Dict(vec![(
                PickleValue::String("get".into()),
                PickleValue::String("link_count".into()),
            )]))
            .unwrap()
    });

    first_seen_rx.recv_timeout(Duration::from_secs(1)).unwrap();

    let second_addr = RpcAddr::Tcp("127.0.0.1".into(), port);
    let second_client = thread::spawn(move || {
        let mut client = RpcClient::connect(&second_addr, &key).unwrap();
        client
            .call(&PickleValue::Dict(vec![(
                PickleValue::String("get".into()),
                PickleValue::String("transport_identity".into()),
            )]))
            .unwrap()
    });

    let handled_concurrently = concurrent_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(first_client.join().unwrap().as_int(), Some(1));
    assert_eq!(
        second_client.join().unwrap().as_bytes(),
        Some([7; 16].as_slice())
    );

    shutdown.store(true, Ordering::Relaxed);
    wake.wake();
    server_thread.join().unwrap();
    driver_thread.join().unwrap();

    assert!(
        handled_concurrently,
        "a stalled RPC request prevented the server from handling a later client"
    );
}

#[test]
fn derive_auth_key_deterministic() {
    let key1 = derive_auth_key(b"test");
    let key2 = derive_auth_key(b"test");
    assert_eq!(key1, key2);
    // Different input → different key
    let key3 = derive_auth_key(b"other");
    assert_ne!(key1, key3);
}

#[test]
fn pickle_request_handling() {
    // Test the request → query translation without networking
    let (event_tx, event_rx) = crate::event::channel();

    let driver = thread::spawn(move || {
        if let Some((QueryRequest::DropPath { dest_hash }, resp_tx)) = event_rx
            .recv()
            .ok()
            .and_then(|event| event.into_query().ok())
        {
            assert_eq!(dest_hash, [1u8; 16]);
            let _ = resp_tx.send(QueryResponse::DropPath(true));
        }
    });

    let request = PickleValue::Dict(vec![
        (
            PickleValue::String("drop".into()),
            PickleValue::String("path".into()),
        ),
        (
            PickleValue::String("destination_hash".into()),
            PickleValue::Bytes(vec![1u8; 16]),
        ),
    ]);

    let response = handle_rpc_request(&request, &mut event_tx.clone()).unwrap();
    assert_eq!(response, PickleValue::Bool(true));
    driver.join().unwrap();
}

#[test]
fn packet_signal_requests_return_upstream_values() {
    let (event_tx, event_rx) = crate::event::channel();
    let driver = thread::spawn(move || {
        for _ in 0..3 {
            if let Ok(Event::Query(request, resp_tx)) = event_rx.recv() {
                let QueryRequest::PacketSignal { packet_hash } = *request else {
                    panic!("unexpected query");
                };
                assert_eq!(packet_hash, [7u8; 32]);
                let _ = resp_tx.send(QueryResponse::PacketSignal(Some(
                    crate::event::PacketSignal {
                        rssi: Some(-97),
                        snr: Some(6.5),
                        q: None,
                    },
                )));
            }
        }
    });

    let request = |path: &str| {
        PickleValue::Dict(vec![
            (
                PickleValue::String("get".into()),
                PickleValue::String(path.into()),
            ),
            (
                PickleValue::String("packet_hash".into()),
                PickleValue::Bytes(vec![7u8; 32]),
            ),
        ])
    };
    let get = |path: &str| handle_rpc_request(&request(path), &mut event_tx.clone()).unwrap();
    assert_eq!(get("packet_rssi"), PickleValue::Int(-97));
    assert_eq!(get("packet_snr"), PickleValue::Float(6.5));
    assert_eq!(get("packet_q"), PickleValue::None);
    driver.join().unwrap();
}

/// A driver stand-in answering `count` link-count queries with 42.
fn answer_link_counts(
    event_rx: crate::event::EventReceiver,
    count: usize,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for _ in 0..count {
            match event_rx.recv() {
                Ok(Event::Query(request, resp_tx)) => {
                    assert!(matches!(*request, QueryRequest::LinkCount));
                    let _ = resp_tx.send(QueryResponse::LinkCount(42));
                }
                _ => break,
            }
        }
    })
}

fn link_count(client: &mut RpcClient) -> Option<i64> {
    client
        .call(&PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("link_count".into()),
        )]))
        .unwrap()
        .as_int()
}

#[cfg(target_os = "linux")]
#[test]
fn local_rpc_client_uses_the_abstract_socket() {
    let key = derive_auth_key(b"local-rpc-unix");
    let instance = crate::test_support::instance_name("local-rpc-unix");
    let (event_tx, event_rx) = crate::event::channel();
    let driver = answer_link_counts(event_rx, 1);
    let mut server = RpcServer::start_abstract_unix(&instance, key, event_tx).unwrap();

    // Nothing listens on the TCP port, so this only works over the socket.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut client = RpcClient::connect(&RpcAddr::local(instance, port), &key).unwrap();
    assert!(matches!(client.stream, ClientStream::Unix(_)));
    assert_eq!(link_count(&mut client), Some(42));
    drop(client);
    server.stop();
    driver.join().unwrap();
}

#[test]
fn local_rpc_client_falls_back_to_tcp() {
    let key = derive_auth_key(b"local-rpc-tcp");
    let instance = crate::test_support::instance_name("local-rpc-tcp");
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr = RpcAddr::local(instance, port);
    let (event_tx, event_rx) = crate::event::channel();
    let driver = answer_link_counts(event_rx, 1);
    let mut server = RpcServer::start(&addr, key, event_tx).unwrap();

    let mut client = RpcClient::connect(&addr, &key).unwrap();
    assert!(matches!(client.stream, ClientStream::Tcp(_)));
    assert_eq!(link_count(&mut client), Some(42));
    drop(client);
    server.stop();
    driver.join().unwrap();
}

#[test]
fn hook_list_request_handling() {
    let (event_tx, event_rx) = crate::event::channel();

    let driver = thread::spawn(move || {
        if let Ok(Event::ListHooks { response_tx }) = event_rx.recv() {
            let _ = response_tx.send(vec![HookInfo {
                name: "stats".into(),
                hook_type: "wasm".into(),
                attach_point: "PreIngress".into(),
                priority: 7,
                enabled: true,
                consecutive_traps: 0,
            }]);
        }
    });

    let request = PickleValue::Dict(vec![(
        PickleValue::String("get".into()),
        PickleValue::String("hooks".into()),
    )]);
    let response = handle_rpc_request(&request, &mut event_tx.clone()).unwrap();
    let hooks = parse_hook_list(&response).unwrap();
    assert_eq!(hooks.len(), 1);
    assert_eq!(hooks[0].name, "stats");
    driver.join().unwrap();
}

#[test]
fn hook_load_request_handling() {
    let (event_tx, event_rx) = crate::event::channel();

    let driver = thread::spawn(move || {
        if let Ok(Event::LoadHook {
            name,
            wasm_bytes,
            attach_point,
            priority,
            response_tx,
        }) = event_rx.recv()
        {
            assert_eq!(name, "stats");
            assert_eq!(attach_point, "PreIngress");
            assert_eq!(priority, 11);
            assert_eq!(wasm_bytes, vec![1, 2, 3]);
            let _ = response_tx.send(Ok(()));
        }
    });

    let request = PickleValue::Dict(vec![
        (
            PickleValue::String("hook".into()),
            PickleValue::String("load".into()),
        ),
        (
            PickleValue::String("name".into()),
            PickleValue::String("stats".into()),
        ),
        (
            PickleValue::String("attach_point".into()),
            PickleValue::String("PreIngress".into()),
        ),
        (PickleValue::String("priority".into()), PickleValue::Int(11)),
        (
            PickleValue::String("wasm".into()),
            PickleValue::Bytes(vec![1, 2, 3]),
        ),
    ]);
    let response = handle_rpc_request(&request, &mut event_tx.clone()).unwrap();
    assert_eq!(parse_hook_result(&response).unwrap(), Ok(()));
    driver.join().unwrap();
}

#[test]
fn path_table_pickle_carries_stamp_value_and_lr_cost() {
    // Upstream 21170877: rnpath formats `value` and `lr_cost` of every
    // entry, so both keys are present, as None when unknown.
    let entry = |stamp_value, lr_cost| PathTableEntry {
        hash: [0x11; 16],
        timestamp: 1.0,
        via: [0x22; 16],
        hops: 2,
        expires: 3.0,
        used: 0.0,
        interface: crate::InterfaceId(1),
        interface_name: "iface".into(),
        interface_display_name: "TCPInterface[test/127.0.0.1:4242]".into(),
        stamp_value,
        lr_cost,
        state: rns_core::constants::STATE_UNKNOWN,
    };
    let pickle = path_table_to_pickle(&[
        entry(
            Some(rns_core::stamp::StampValue::from_fp(25 * 256 + 64)),
            Some(rns_core::stamp::StampCost::from_fp(4915)),
        ),
        entry(None, None),
    ]);
    let entries = pickle.as_list().unwrap();
    assert_eq!(
        entries[0].get("value").and_then(|v| v.as_float()),
        Some(25.25)
    );
    assert_eq!(
        entries[0].get("lr_cost").and_then(|v| v.as_float()),
        Some(4915.0 / 256.0)
    );
    // Upstream reports the receiving interface as str(interface).
    assert_eq!(
        entries[0].get("interface").and_then(|v| v.as_str()),
        Some("TCPInterface[test/127.0.0.1:4242]")
    );
    assert_eq!(entries[1].get("value"), Some(&PickleValue::None));
    assert_eq!(entries[1].get("lr_cost"), Some(&PickleValue::None));
}

#[test]
fn path_and_rate_tables_follow_upstreams_keys_and_types() {
    // Reticulum.get_path_table()'s dict, in its order; a destination
    // remembered without a stamp has the int value 0, a path never used
    // the int 0.
    let entry = PathTableEntry {
        hash: [0x11; 16],
        timestamp: 1.5,
        via: [0x22; 16],
        hops: 2,
        expires: 3.5,
        used: 0.0,
        interface: crate::InterfaceId(1),
        interface_name: "iface".into(),
        interface_display_name: "iface".into(),
        stamp_value: Some(rns_core::stamp::StampValue::ZERO),
        lr_cost: None,
        state: rns_core::constants::STATE_RESPONSIVE,
    };
    let table = path_table_msgpack(&[entry]);
    let MsgpackValue::Map(fields) = &table[0] else {
        panic!("expected a map");
    };
    let keys: Vec<&str> = fields.iter().filter_map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        keys,
        [
            "hash",
            "timestamp",
            "via",
            "hops",
            "expires",
            "value",
            "used",
            "lr_cost",
            "interface",
            "interface_hash",
            "state"
        ]
    );
    assert_eq!(fields[5].1, MsgpackValue::UInt(0));
    assert_eq!(fields[6].1, MsgpackValue::UInt(0));
    assert_eq!(fields[7].1, MsgpackValue::Nil);
    // Upstream c90a5d58: `interface.get_hash()`, the full hash of the
    // interface's str().
    assert_eq!(
        fields[9].1,
        MsgpackValue::Bin(rns_core::hash::full_hash(b"iface").to_vec())
    );
    // Upstream 41260ea1: `Transport.get_path_state()`, an int.
    assert_eq!(fields[10].1, MsgpackValue::UInt(2));

    // AnnounceRateTable.items()'s dict, with `hash` added last.
    let rates = rate_table_msgpack(&[RateTableEntry {
        hash: [0x33; 16],
        last: 1.0,
        rate_violations: 1,
        blocked_until: 0.0,
        timestamps: vec![1.0],
    }]);
    let MsgpackValue::Map(fields) = &rates[0] else {
        panic!("expected a map");
    };
    let keys: Vec<&str> = fields.iter().filter_map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        keys,
        [
            "last",
            "rate_violations",
            "blocked_until",
            "timestamps",
            "hash"
        ]
    );
    assert_eq!(fields[2].1, MsgpackValue::Float(0.0));
}

#[test]
fn idle_stats_keep_upstreams_integer_zeros() {
    // Upstream starts its traffic totals, frequencies, queue pressures
    // and the speeds of interfaces its counter skips at the integer 0;
    // its packet rates are always ints.
    let stats = InterfaceStatsResponse {
        rx_pps: 2.6,
        ..Default::default()
    };
    let pickle = interface_stats_to_pickle(&stats);
    for key in ["rxs", "txs", "frxs", "arxs", "prxs", "arxf", "ptxf"] {
        assert!(
            matches!(pickle.get(key), Some(PickleValue::Int(0))),
            "{key}: {:?}",
            pickle.get(key)
        );
    }
    assert!(matches!(pickle.get("rxpps"), Some(PickleValue::Int(3))));
    assert!(matches!(pickle.get("txpps"), Some(PickleValue::Int(0))));
}

/// Upstream ef3e8086's link traffic keys: right after `txs`, the byte
/// totals ints, the speeds the integer 0 until its traffic loop first
/// measures them and floats from then on, a measured 0 too.
#[test]
fn link_traffic_keys_follow_upstreams_position_and_types() {
    let mut stats = InterfaceStatsResponse {
        link_traffic: crate::event::LinkTraffic {
            rxb: 1500,
            txb: 700,
            speeds: None,
        },
        ..Default::default()
    };
    let pickle = interface_stats_to_pickle(&stats);
    let PickleValue::Dict(entries) = &pickle else {
        panic!("expected a dict");
    };
    let keys: Vec<&str> = entries.iter().filter_map(|(k, _)| k.as_str()).collect();
    let txs = keys.iter().position(|k| *k == "txs").unwrap();
    assert_eq!(
        keys[txs - 1..txs + 6],
        ["rxs", "txs", "lrxb", "ltxb", "lrxs", "ltxs", "frxb"]
    );
    assert_eq!(pickle.get("lrxb"), Some(&PickleValue::Int(1500)));
    assert_eq!(pickle.get("ltxb"), Some(&PickleValue::Int(700)));
    assert_eq!(pickle.get("lrxs"), Some(&PickleValue::Int(0)));
    assert_eq!(pickle.get("ltxs"), Some(&PickleValue::Int(0)));

    stats.link_traffic.speeds = Some((0.0, 4096.5));
    let pickle = interface_stats_to_pickle(&stats);
    assert_eq!(pickle.get("lrxs"), Some(&PickleValue::Float(0.0)));
    assert_eq!(pickle.get("ltxs"), Some(&PickleValue::Float(4096.5)));
}

#[test]
fn interface_stats_pickle_format() {
    let traffic = TrafficDetail {
        rxs: 800.0,
        txs: 1600.0,
        frxb: 55,
        ftxb: 0,
        frxs: 440.0,
        ftxs: 0.0,
        arxb: 11,
        atxb: 22,
        arxc: 1,
        atxc: 2,
        afrxc: 6,
        arxs: 88.0,
        atxs: 176.0,
        prxb: 33,
        ptxb: 44,
        prxc: 3,
        ptxc: 4,
        prxs: 264.0,
        ptxs: 352.0,
        arxf: 1.0,
        atxf: 2.0,
        prxf: 3.0,
        ptxf: 4.0,
    };
    let mut stats = InterfaceStatsResponse {
        network_id: None,
        interfaces: vec![SingleInterfaceStat {
            id: 1,
            name: "TCP".into(),
            display_name: "TCPInterface[TCP/10.0.0.1:4242]".into(),
            parent_display_name: None,
            tunnel_id: Some([0x5A; 32]),
            remote_transport_id: Some([0x6B; 16]),
            remote_transport_info: Some(rns_core::transport::tunnel::RemoteTransportInfo {
                implementation: "RNS".into(),
                version: vec![1, 6, 1],
                is_transport: true,
                destination_cost: rns_core::stamp::StampCost::from_f64(23.5),
                pr_cost: rns_core::stamp::StampCost::from_f64(15.8),
            }),
            status: true,
            mode: 1,
            gravity: -2,
            announces_to_internal: Some(true),
            rxb: 100,
            txb: 200,
            tx_drops: 3,
            tx_dropped_bytes: 4096,
            tx_stalled: true,
            tx_buffered: 8192,
            traffic,
            protocol_violations: 11,
            ifac_violations: 12,
            packet_filter_hits: 13,
            hop_limiter_hits: 14,
            stamped_path_requests: 0,
            rx_packets: 5,
            tx_packets: 10,
            cpu_load: Some(12.0),
            mem_load: Some(34.5),
            switch_id: Some([1, 2, 3, 4]),
            endpoint_id: Some([5; 8]),
            via_switch_id: Some([6; 4]),
            peers: Some(2),
            rssi: Some(-101),
            snr: Some(7.25),
            signal_quality: Some(88.5),
            frequency: Some(868_000_000),
            bandwidth: Some(125_000),
            txpower: Some(14),
            spreading_factor: Some(8),
            coding_rate: Some(5),
            channel: Some(3),
            modulation: Some("LoRa".into()),
            radio: None,
            bitrate: Some(1000000),
            bitrate_is_float: false,
            mtu: Some(131_072),
            ifac_size: Some(16),
            started: 1000.0,
            ia_freq: 1.0,
            ip_freq: 2.0,
            op_freq: 3.0,
            op_samples: 0,
            burst_active: true,
            burst_activated: 1200.0,
            pr_burst_active: true,
            pr_burst_activated: 1300.0,
            oa_freq: 4.0,
            clients: Some(3),
            blocked_ips: Some(2),
            blocked_ip_list: Some(vec!["192.0.2.1".into(), "203.0.113.2".into()]),
            i2p: None,
            i2p_tunnel_state: None,
            autoconnect_source: None,
            announce_rate_target: Some(3600.0),
            announce_rate_grace: 5,
            announce_rate_penalty: 0.0,
            interface_type: "TCPClientInterface".into(),
            held_announces: 0,
            announce_queue: 0,
            ifac_netname: None,
            ifac_signature: None,
        }],
        transport_id: Some([0xAB; 16]),
        transport_enabled: true,
        transport_uptime: 3600.0,
        total_rxb: 100,
        total_txb: 200,
        rx_pps: 3.0,
        tx_pps: 4.0,
        traffic,
        probe_responder: None,
        backbone_peer_pool: None,
        ..Default::default()
    };

    let pickle = interface_stats_to_pickle(&stats);

    // Verify it round-trips through encode/decode
    let encoded = pickle::encode(&pickle);
    let decoded = pickle::decode(&encoded).unwrap();
    assert!(decoded.get("transport_enabled").unwrap().as_bool().unwrap());
    let ifaces = decoded.get("interfaces").unwrap().as_list().unwrap();
    assert_eq!(decoded.get("arxf").unwrap().as_float(), Some(1.0));
    assert_eq!(decoded.get("atxf").unwrap().as_float(), Some(2.0));
    assert_eq!(decoded.get("prxf").unwrap().as_float(), Some(3.0));
    assert_eq!(decoded.get("ptxf").unwrap().as_float(), Some(4.0));
    // `int(round(pps))`, as upstream.
    assert_eq!(decoded.get("rxpps").unwrap().as_int(), Some(3));
    assert_eq!(decoded.get("txpps").unwrap().as_int(), Some(4));
    assert_eq!(ifaces[0].get("id").unwrap().as_int().unwrap(), 1);
    // Upstream's `str(interface)`, its config name, and `get_hash()`,
    // the full hash of the former.
    assert_eq!(
        ifaces[0].get("name").unwrap().as_str().unwrap(),
        "TCPInterface[TCP/10.0.0.1:4242]"
    );
    assert_eq!(ifaces[0].get("short_name").unwrap().as_str(), Some("TCP"));
    assert_eq!(
        ifaces[0].get("hash").unwrap().as_bytes().unwrap(),
        rns_core::hash::full_hash(b"TCPInterface[TCP/10.0.0.1:4242]").as_slice()
    );
    // Upstream's own keys and number types, which its rnstatus reads.
    assert_eq!(
        ifaces[0].get("type").unwrap().as_str(),
        Some("TCPClientInterface")
    );
    for (upstream, ours) in [
        ("incoming_announce_frequency", "ia_freq"),
        ("outgoing_announce_frequency", "oa_freq"),
        ("incoming_pr_frequency", "ip_freq"),
        ("outgoing_pr_frequency", "op_freq"),
    ] {
        assert_eq!(
            ifaces[0].get(upstream).unwrap().as_number(),
            ifaces[0].get(ours).unwrap().as_float(),
            "{upstream}"
        );
    }
    assert_eq!(ifaces[0].get("held_announces").unwrap().as_int(), Some(0));
    assert_eq!(ifaces[0].get("announce_queue").unwrap().as_int(), Some(0));
    assert!(ifaces[0].get("ifac_netname").is_some());
    assert!(ifaces[0].get("ifac_signature").is_some());
    assert!(decoded.get("network_id").is_some());
    #[cfg(target_os = "linux")]
    assert!(decoded.get("rss").unwrap().as_int().unwrap() > 0);
    let mut spawned = stats.interfaces[0].clone();
    spawned.interface_type = "TCPServerClientInterface".into();
    spawned.burst_activated = 0.0;
    spawned.announce_rate_penalty = 7.0;
    spawned.announce_rate_target = Some(3600.0);
    spawned.ifac_netname = Some("mesh".into());
    spawned.ifac_signature = Some([9; 64]);
    let spawned = pickle::decode(&pickle::encode(&single_iface_to_pickle(&spawned))).unwrap();
    assert_eq!(
        spawned.get("type").unwrap().as_str(),
        Some("TCPClientInterface")
    );
    assert_eq!(spawned.get("burst_activated").unwrap().as_int(), Some(0));
    assert_eq!(
        spawned.get("announce_rate_penalty").unwrap().as_int(),
        Some(7)
    );
    assert_eq!(
        spawned.get("announce_rate_target").unwrap().as_int(),
        Some(3600)
    );
    assert_eq!(spawned.get("ifac_netname").unwrap().as_str(), Some("mesh"));
    assert_eq!(
        spawned.get("ifac_signature").unwrap().as_bytes(),
        Some(&[9u8; 64][..])
    );
    assert_eq!(
        ifaces[0].get("autoconnect_source"),
        Some(&PickleValue::None)
    );
    let mut discovered = stats.interfaces[0].clone();
    discovered.autoconnect_source = Some("ab".repeat(16));
    let discovered = pickle::decode(&pickle::encode(&single_iface_to_pickle(&discovered))).unwrap();
    assert_eq!(
        discovered.get("autoconnect_source").unwrap().as_str(),
        Some("ab".repeat(16).as_str())
    );
    // Only an I2P interface reports its endpoint, its address None
    // until known.
    assert!(ifaces[0].get("i2p_connectable").is_none());
    assert!(ifaces[0].get("i2p_b32").is_none());
    let mut i2p = stats.interfaces[0].clone();
    i2p.i2p = Some(crate::event::I2pEndpointStat {
        connectable: false,
        b32: None,
    });
    let i2p = pickle::decode(&pickle::encode(&single_iface_to_pickle(&i2p))).unwrap();
    assert_eq!(i2p.get("i2p_connectable").unwrap().as_bool(), Some(false));
    assert_eq!(i2p.get("i2p_b32"), Some(&PickleValue::None));
    // The bitrate is an int, unless upstream holds it as a float, as
    // it does an auto-connected interface's.
    assert_eq!(ifaces[0].get("bitrate"), Some(&PickleValue::Int(1000000)));
    let mut autoconnected = stats.interfaces[0].clone();
    autoconnected.bitrate = Some(5_000_000);
    autoconnected.bitrate_is_float = true;
    let autoconnected =
        pickle::decode(&pickle::encode(&single_iface_to_pickle(&autoconnected))).unwrap();
    assert_eq!(
        autoconnected.get("bitrate"),
        Some(&PickleValue::Float(5_000_000.0))
    );
    // Only I2P peers report their tunnel state.
    assert!(ifaces[0].get("tunnelstate").is_none());
    let mut peer = stats.interfaces[0].clone();
    peer.i2p_tunnel_state = Some(Some("Tunnel Active".into()));
    let peer = pickle::decode(&pickle::encode(&single_iface_to_pickle(&peer))).unwrap();
    assert_eq!(
        peer.get("tunnelstate").unwrap().as_str(),
        Some("Tunnel Active")
    );
    let mut peer = stats.interfaces[0].clone();
    peer.i2p_tunnel_state = Some(None);
    let peer = pickle::decode(&pickle::encode(&single_iface_to_pickle(&peer))).unwrap();
    assert_eq!(peer.get("tunnelstate"), Some(&PickleValue::None));
    // Weave statistics only on Weave interfaces: upstream's rnstatus
    // prints "Unknown" lines for a key that is there without a value.
    for key in [
        "cpu_load",
        "mem_load",
        "switch_id",
        "endpoint_id",
        "via_switch_id",
    ] {
        assert!(ifaces[0].get(key).is_none(), "{key} on a TCP interface");
    }
    let weave = |interface_type: &str| {
        let mut stat = stats.interfaces[0].clone();
        stat.interface_type = interface_type.into();
        pickle::decode(&pickle::encode(&single_iface_to_pickle(&stat))).unwrap()
    };
    let device = weave("WeaveInterface");
    assert_eq!(device.get("cpu_load").unwrap().as_int(), Some(12));
    assert_eq!(device.get("mem_load").unwrap().as_float(), Some(34.5));
    assert_eq!(
        device.get("switch_id").unwrap().as_str(),
        Some("01:02:03:04")
    );
    assert_eq!(
        device.get("endpoint_id").unwrap().as_str(),
        Some("05:05:05:05:05:05:05:05")
    );
    assert!(device.get("via_switch_id").is_none());
    let peer = weave("WeaveInterfacePeer");
    assert_eq!(
        peer.get("via_switch_id").unwrap().as_str(),
        Some("06:06:06:06")
    );
    assert!(peer.get("cpu_load").is_none());
    // Upstream 134dc677: filtered traffic, per interface and in total.
    for stats in [&decoded, &ifaces[0]] {
        assert_eq!(stats.get("frxb").unwrap().as_int(), Some(55));
        assert_eq!(stats.get("ftxb").unwrap().as_int(), Some(0));
        assert_eq!(stats.get("frxs").unwrap().as_float(), Some(440.0));
        assert_eq!(stats.get("ftxs").unwrap().as_float(), Some(0.0));
    }
    // Upstream 819076c3: filtered announces, per interface only.
    assert_eq!(ifaces[0].get("afrxc").unwrap().as_int(), Some(6));
    assert!(decoded.get("afrxc").is_none());
    // Upstream 464e7598: the remote transport identity hash.
    assert_eq!(
        ifaces[0].get("remote_transport_id").unwrap().as_bytes(),
        Some(&[0x6B; 16][..])
    );
    // Upstream b7a93b9b: what the remote transport reported.
    assert_eq!(ifaces[0].get("rem_impl").unwrap().as_str(), Some("RNS"));
    assert_eq!(
        ifaces[0].get("rem_vers"),
        Some(&PickleValue::List(vec![
            PickleValue::Int(1),
            PickleValue::Int(6),
            PickleValue::Int(1)
        ]))
    );
    assert_eq!(ifaces[0].get("rem_is_tn"), Some(&PickleValue::Bool(true)));
    assert_eq!(
        ifaces[0].get("rem_dst_cost"),
        Some(&PickleValue::Float(23.5))
    );
    assert_eq!(
        ifaces[0].get("rem_pr_cost"),
        Some(&PickleValue::Float(4045.0 / 256.0))
    );
    // Upstream 9b6b724b: the tunnel id, bytes or None.
    assert_eq!(
        ifaces[0].get("tunnel_id").unwrap().as_bytes(),
        Some(&[0x5A; 32][..])
    );
    assert_eq!(ifaces[0].get("mtu").unwrap().as_int(), Some(131_072));
    assert_eq!(ifaces[0].get("gravity").unwrap().as_int().unwrap(), -2);
    assert_eq!(ifaces[0].get("txdrp").unwrap().as_int(), Some(3));
    assert_eq!(ifaces[0].get("txdrb").unwrap().as_int(), Some(4096));
    assert_eq!(ifaces[0].get("txstalled").unwrap().as_bool(), Some(true));
    assert_eq!(ifaces[0].get("txbuffered").unwrap().as_int(), Some(8192));
    assert!(ifaces[0]
        .get("announces_to_internal")
        .unwrap()
        .as_bool()
        .unwrap());
    assert_eq!(ifaces[0].get("ia_freq").unwrap().as_float().unwrap(), 1.0);
    assert_eq!(ifaces[0].get("ip_freq").unwrap().as_float().unwrap(), 2.0);
    assert_eq!(ifaces[0].get("op_freq").unwrap().as_float().unwrap(), 3.0);
    assert_eq!(ifaces[0].get("oa_freq").unwrap().as_float().unwrap(), 4.0);
    assert_eq!(ifaces[0].get("arxb").unwrap().as_int().unwrap(), 11);
    assert_eq!(ifaces[0].get("atxb").unwrap().as_int().unwrap(), 22);
    assert_eq!(ifaces[0].get("prxb").unwrap().as_int().unwrap(), 33);
    assert_eq!(ifaces[0].get("ptxb").unwrap().as_int().unwrap(), 44);
    assert_eq!(ifaces[0].get("arxs").unwrap().as_float().unwrap(), 88.0);
    assert_eq!(ifaces[0].get("ptxs").unwrap().as_float().unwrap(), 352.0);
    assert_eq!(
        ifaces[0]
            .get("protocol_violations")
            .unwrap()
            .as_int()
            .unwrap(),
        11
    );
    assert_eq!(ifaces[0].get("ifac_violations").unwrap().as_int(), Some(12));
    assert_eq!(
        ifaces[0].get("packet_filter_hits").unwrap().as_int(),
        Some(13)
    );
    assert_eq!(
        ifaces[0].get("hop_limiter_hits").unwrap().as_int(),
        Some(14)
    );
    assert_eq!(decoded.get("arxb").unwrap().as_int().unwrap(), 11);
    assert_eq!(decoded.get("prxb").unwrap().as_int().unwrap(), 33);
    assert_eq!(ifaces[0].get("rssi").unwrap().as_int(), Some(-101));
    assert_eq!(ifaces[0].get("snr").unwrap().as_float(), Some(7.25));
    assert_eq!(
        ifaces[0].get("signal_quality").unwrap().as_float(),
        Some(88.5)
    );
    assert_eq!(
        ifaces[0].get("frequency").unwrap().as_int(),
        Some(868_000_000)
    );
    assert_eq!(ifaces[0].get("bandwidth").unwrap().as_int(), Some(125_000));
    assert_eq!(ifaces[0].get("txpower").unwrap().as_int(), Some(14));
    assert_eq!(ifaces[0].get("sf").unwrap().as_int(), Some(8));
    assert_eq!(ifaces[0].get("cr").unwrap().as_int(), Some(5));
    assert_eq!(ifaces[0].get("channel").unwrap().as_int(), Some(3));
    assert_eq!(ifaces[0].get("modulation").unwrap().as_str(), Some("LoRa"));
    assert!(ifaces[0].get("burst_active").unwrap().as_bool().unwrap());
    assert_eq!(
        ifaces[0]
            .get("burst_activated")
            .unwrap()
            .as_number()
            .unwrap(),
        1200.0
    );
    assert!(ifaces[0].get("pr_burst_active").unwrap().as_bool().unwrap());
    assert_eq!(
        ifaces[0]
            .get("pr_burst_activated")
            .unwrap()
            .as_number()
            .unwrap(),
        1300.0
    );
    assert_eq!(
        ifaces[0]
            .get("announce_rate_target")
            .unwrap()
            .as_number()
            .unwrap(),
        3600.0
    );
    assert_eq!(
        ifaces[0]
            .get("announce_rate_grace")
            .unwrap()
            .as_int()
            .unwrap(),
        5
    );
    assert_eq!(
        ifaces[0]
            .get("announce_rate_penalty")
            .unwrap()
            .as_number()
            .unwrap(),
        0.0
    );
    assert_eq!(ifaces[0].get("clients").unwrap().as_int().unwrap(), 3);
    assert_eq!(ifaces[0].get("blocked_ips").unwrap().as_int().unwrap(), 2);
    assert_eq!(
        ifaces[0]
            .get("blocked_ip_list")
            .unwrap()
            .as_list()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["192.0.2.1", "203.0.113.2"]
    );

    stats.interfaces[0].interface_type = "BackboneInterface".into();
    let (event_tx, _event_rx) = crate::event::channel_with_capacity(1);
    event_tx.register_dynamic_parent(InterfaceId(2), InterfaceId(1));
    event_tx.set_ingress_bursts(InterfaceId(2), Some(10.0), Some(20.0));
    event_tx
        .try_send(Event::Frame {
            interface_id: InterfaceId(2),
            data: vec![0].into(),
            rssi: None,
            snr: None,
        })
        .unwrap();
    assert!(event_tx
        .try_send(Event::Frame {
            interface_id: InterfaceId(2),
            data: vec![0].into(),
            rssi: None,
            snr: None,
        })
        .is_err());
    // Reader `send` now waits for space in the data class instead of
    // dropping, so a second refused `try_send` provides the second drop.
    assert!(event_tx
        .try_send(Event::Frame {
            interface_id: InterfaceId(2),
            data: vec![0].into(),
            rssi: None,
            snr: None,
        })
        .is_err());
    let mut runtime_pickle = interface_stats_to_pickle(&stats);
    add_inbound_runtime_stats(&mut runtime_pickle, &stats, &event_tx);
    let runtime_ifaces = runtime_pickle.get("interfaces").unwrap().as_list().unwrap();
    assert_eq!(
        runtime_ifaces[0]
            .get("burst_count")
            .unwrap()
            .as_int()
            .unwrap(),
        1
    );
    assert_eq!(
        runtime_ifaces[0]
            .get("pr_burst_count")
            .unwrap()
            .as_int()
            .unwrap(),
        1
    );
    assert!(runtime_ifaces[0]
        .get("burst_active")
        .unwrap()
        .as_bool()
        .unwrap());
    assert_eq!(
        runtime_ifaces[0]
            .get("burst_activated")
            .unwrap()
            .as_number()
            .unwrap(),
        10.0
    );
    assert!(runtime_ifaces[0]
        .get("pr_burst_active")
        .unwrap()
        .as_bool()
        .unwrap());
    assert_eq!(
        runtime_ifaces[0]
            .get("pr_burst_activated")
            .unwrap()
            .as_number()
            .unwrap(),
        20.0
    );
    assert_eq!(runtime_pickle.get("rxqt").unwrap().as_int().unwrap(), 1);
    assert_eq!(runtime_pickle.get("rxqd").unwrap().as_int().unwrap(), 1);
    assert_eq!(runtime_pickle.get("rxqtd").unwrap().as_int().unwrap(), 2);
    assert_eq!(runtime_pickle.get("rxqdd").unwrap().as_int().unwrap(), 2);
    assert_eq!(runtime_pickle.get("rxqad").unwrap().as_int().unwrap(), 0);
    assert_eq!(runtime_pickle.get("rxqpd").unwrap().as_int().unwrap(), 0);
    assert_eq!(runtime_pickle.get("rxqild").unwrap().as_int().unwrap(), 0);
    assert_eq!(
        runtime_pickle
            .get("dqpressure")
            .unwrap()
            .as_float()
            .unwrap(),
        1.0
    );
    assert_eq!(
        runtime_pickle
            .get("tqpressure")
            .unwrap()
            .as_float()
            .unwrap(),
        0.25
    );

    // Only RNode interfaces carry upstream's channel and device keys.
    assert!(ifaces[0].get("noise_floor").is_none());
    let mut rnode = stats.interfaces[0].clone();
    rnode.radio = Some(crate::common::interface_stats::RadioStats {
        airtime_short: 6.97,
        airtime_long: 0.02,
        channel_load_short: 11.13,
        channel_load_long: 0.04,
        current_rssi: Some(-110),
        noise_floor: Some(-99),
        interference: None,
        interference_last: Some((1_700_000_000.5, -80)),
        battery_state: 0x01,
        battery_percent: 91,
        temperature: Some(58),
    });
    let rnode = pickle::decode(&pickle::encode(&single_iface_to_pickle(&rnode))).unwrap();
    for (key, value) in [
        ("airtime_short", 6.97),
        ("airtime_long", 0.02),
        ("channel_load_short", 11.13),
        ("channel_load_long", 0.04),
        ("interference_last_ts", 1_700_000_000.5),
    ] {
        assert_eq!(rnode.get(key).unwrap().as_float(), Some(value), "{key}");
    }
    assert_eq!(rnode.get("noise_floor").unwrap().as_int(), Some(-99));
    assert!(matches!(rnode.get("interference"), Some(PickleValue::None)));
    assert_eq!(
        rnode.get("interference_last_dbm").unwrap().as_int(),
        Some(-80)
    );
    assert_eq!(rnode.get("cpu_temp").unwrap().as_int(), Some(58));
    assert_eq!(
        rnode.get("battery_state").unwrap().as_str(),
        Some("discharging")
    );
    assert_eq!(rnode.get("battery_percent").unwrap().as_int(), Some(91));
    // Upstream sends the battery state only once the device reports one.
    let mut unknown = stats.interfaces[0].clone();
    unknown.radio = Some(Default::default());
    let unknown = pickle::decode(&pickle::encode(&single_iface_to_pickle(&unknown))).unwrap();
    assert!(unknown.get("battery_state").is_none());
    assert!(unknown.get("interference_last_ts").is_none());
    assert!(matches!(
        unknown.get("noise_floor"),
        Some(PickleValue::None)
    ));
    assert_eq!(unknown.get("battery_percent").unwrap().as_int(), Some(0));
}

#[test]
fn profiling_results_rpc_exposes_completed_samples() {
    {
        let _sample = crate::profiling::profile("entry110.rpc");
    }
    let (event_tx, _event_rx) = crate::event::channel();
    let request = PickleValue::Dict(vec![(
        PickleValue::String("get".into()),
        PickleValue::String("profiling_results".into()),
    )]);
    let response = handle_rpc_request(&request, &mut event_tx.clone()).unwrap();
    let sample = response.get("entry110.rpc").unwrap();
    assert_eq!(
        sample.get("name").and_then(PickleValue::as_str),
        Some("entry110.rpc")
    );
    assert_eq!(
        sample
            .get("stats_all")
            .and_then(|stats| stats.get("count"))
            .and_then(PickleValue::as_int),
        Some(1)
    );
}

#[test]
fn interface_stats_pickle_includes_backbone_peer_pool_priority() {
    let stats = InterfaceStatsResponse {
        network_id: None,
        interfaces: vec![],
        transport_id: None,
        transport_enabled: true,
        transport_uptime: 1.0,
        total_rxb: 0,
        total_txb: 0,
        rx_pps: 0.0,
        tx_pps: 0.0,
        traffic: TrafficDetail::default(),
        probe_responder: None,
        backbone_peer_pool: Some(crate::event::BackbonePeerPoolStatus {
            max_connected: 1,
            active_count: 1,
            standby_count: 0,
            cooldown_count: 0,
            members: vec![crate::event::BackbonePeerPoolMemberStatus {
                name: "peer".into(),
                remote: "127.0.0.1:4242".into(),
                source: "configured".into(),
                priority: 77,
                state: "active".into(),
                interface_id: Some(42),
                failure_count: 0,
                last_error: None,
                cooldown_remaining_seconds: None,
            }],
        }),
        ..Default::default()
    };

    let pickle = interface_stats_to_pickle(&stats);
    let encoded = pickle::encode(&pickle);
    let decoded = pickle::decode(&encoded).unwrap();
    let pool = decoded.get("backbone_peer_pool").unwrap();
    let members = pool.get("members").unwrap().as_list().unwrap();
    assert_eq!(members[0].get("priority").unwrap().as_int().unwrap(), 77);
}

#[test]
fn send_probe_rpc_unknown_dest() {
    let (event_tx, event_rx) = crate::event::channel();

    let driver = thread::spawn(move || {
        if let Some((
            QueryRequest::SendProbe {
                dest_hash,
                payload_size,
            },
            resp_tx,
        )) = event_rx
            .recv()
            .ok()
            .and_then(|event| event.into_query().ok())
        {
            assert_eq!(dest_hash, [0xAA; 16]);
            assert_eq!(payload_size, 16); // default
            let _ = resp_tx.send(QueryResponse::SendProbe(Err(
                crate::event::SendProbeError::UnknownIdentity,
            )));
        }
    });

    let request = PickleValue::Dict(vec![(
        PickleValue::String("send_probe".into()),
        PickleValue::Bytes(vec![0xAA; 16]),
    )]);

    let response = handle_rpc_request(&request, &mut event_tx.clone()).unwrap();
    assert_eq!(response, PickleValue::None);
    driver.join().unwrap();
}

#[test]
fn send_probe_rpc_with_result() {
    let (event_tx, event_rx) = crate::event::channel();

    let packet_hash = [0xBB; 32];
    let driver = thread::spawn(move || {
        if let Some((
            QueryRequest::SendProbe {
                dest_hash,
                payload_size,
            },
            resp_tx,
        )) = event_rx
            .recv()
            .ok()
            .and_then(|event| event.into_query().ok())
        {
            assert_eq!(dest_hash, [0xCC; 16]);
            assert_eq!(payload_size, 32);
            let _ = resp_tx.send(QueryResponse::SendProbe(Ok((packet_hash, 3))));
        }
    });

    let request = PickleValue::Dict(vec![
        (
            PickleValue::String("send_probe".into()),
            PickleValue::Bytes(vec![0xCC; 16]),
        ),
        (PickleValue::String("size".into()), PickleValue::Int(32)),
    ]);

    let response = handle_rpc_request(&request, &mut event_tx.clone()).unwrap();
    let ph = response.get("packet_hash").unwrap().as_bytes().unwrap();
    assert_eq!(ph, &[0xBB; 32]);
    assert_eq!(response.get("hops").unwrap().as_int().unwrap(), 3);
    driver.join().unwrap();
}

#[test]
fn retain_identity_rpc_sends_identity_hash_query() {
    let (event_tx, event_rx) = crate::event::channel();
    let identity_hash = [0x44; 16];

    let driver = thread::spawn(move || {
        if let Some((
            QueryRequest::RetainIdentity {
                identity_hash: hash,
            },
            resp_tx,
        )) = event_rx
            .recv()
            .ok()
            .and_then(|event| event.into_query().ok())
        {
            assert_eq!(hash, identity_hash);
            let _ = resp_tx.send(QueryResponse::RetainIdentity(true));
        }
    });

    let request = PickleValue::Dict(vec![
        (
            PickleValue::String("set".into()),
            PickleValue::String("identity_retained".into()),
        ),
        (
            PickleValue::String("identity_hash".into()),
            PickleValue::Bytes(identity_hash.to_vec()),
        ),
    ]);

    let response = handle_rpc_request(&request, &mut event_tx.clone()).unwrap();
    assert_eq!(response, PickleValue::Bool(true));
    driver.join().unwrap();
}

#[test]
fn send_probe_rpc_size_validation() {
    let (event_tx, event_rx) = crate::event::channel();

    // Negative size should be clamped to default (16)
    let driver = thread::spawn(move || {
        if let Some((QueryRequest::SendProbe { payload_size, .. }, resp_tx)) = event_rx
            .recv()
            .ok()
            .and_then(|event| event.into_query().ok())
        {
            assert_eq!(payload_size, 16); // default, not negative
            let _ = resp_tx.send(QueryResponse::SendProbe(Err(
                crate::event::SendProbeError::UnknownIdentity,
            )));
        }
    });

    let request = PickleValue::Dict(vec![
        (
            PickleValue::String("send_probe".into()),
            PickleValue::Bytes(vec![0xDD; 16]),
        ),
        (PickleValue::String("size".into()), PickleValue::Int(-1)),
    ]);

    let response = handle_rpc_request(&request, &mut event_tx.clone()).unwrap();
    assert_eq!(response, PickleValue::None);
    driver.join().unwrap();
}

#[test]
fn send_probe_rpc_size_too_large() {
    let (event_tx, _event_rx) = crate::event::channel();

    // Oversize requests are rejected before reaching the driver instead
    // of being silently replaced by the default size.
    let request = PickleValue::Dict(vec![
        (
            PickleValue::String("send_probe".into()),
            PickleValue::Bytes(vec![0xDD; 16]),
        ),
        (
            PickleValue::String("size".into()),
            PickleValue::Int(crate::event::MAX_PROBE_PAYLOAD_SIZE as i64 + 1),
        ),
    ]);

    let response = handle_rpc_request(&request, &mut event_tx.clone()).unwrap();
    assert_eq!(
        response.get("error").and_then(|v| v.as_str()),
        Some("payload_too_large")
    );
    assert_eq!(
        response.get("max_size").and_then(|v| v.as_int()),
        Some(crate::event::MAX_PROBE_PAYLOAD_SIZE as i64)
    );
}

#[test]
fn send_probe_rpc_max_size_reaches_driver() {
    let (event_tx, event_rx) = crate::event::channel();

    let driver = thread::spawn(move || {
        if let Some((QueryRequest::SendProbe { payload_size, .. }, resp_tx)) = event_rx
            .recv()
            .ok()
            .and_then(|event| event.into_query().ok())
        {
            assert_eq!(payload_size, crate::event::MAX_PROBE_PAYLOAD_SIZE);
            let _ = resp_tx.send(QueryResponse::SendProbe(Ok(([0xEE; 32], 2))));
        }
    });

    let request = PickleValue::Dict(vec![
        (
            PickleValue::String("send_probe".into()),
            PickleValue::Bytes(vec![0xDD; 16]),
        ),
        (
            PickleValue::String("size".into()),
            PickleValue::Int(crate::event::MAX_PROBE_PAYLOAD_SIZE as i64),
        ),
    ]);

    let response = handle_rpc_request(&request, &mut event_tx.clone()).unwrap();
    assert_eq!(response.get("hops").unwrap().as_int().unwrap(), 2);
    driver.join().unwrap();
}

#[test]
fn send_probe_rpc_driver_payload_too_large_is_reported() {
    let (event_tx, event_rx) = crate::event::channel();

    let driver = thread::spawn(move || {
        if let Some((QueryRequest::SendProbe { .. }, resp_tx)) = event_rx
            .recv()
            .ok()
            .and_then(|event| event.into_query().ok())
        {
            let _ = resp_tx.send(QueryResponse::SendProbe(Err(
                crate::event::SendProbeError::PayloadTooLarge { max: 123 },
            )));
        }
    });

    let request = PickleValue::Dict(vec![(
        PickleValue::String("send_probe".into()),
        PickleValue::Bytes(vec![0xDD; 16]),
    )]);

    let response = handle_rpc_request(&request, &mut event_tx.clone()).unwrap();
    assert_eq!(
        response.get("error").and_then(|v| v.as_str()),
        Some("payload_too_large")
    );
    assert_eq!(response.get("max_size").and_then(|v| v.as_int()), Some(123));
    driver.join().unwrap();
}

#[test]
fn check_proof_rpc_not_found() {
    let (event_tx, event_rx) = crate::event::channel();

    let driver = thread::spawn(move || {
        if let Some((QueryRequest::CheckProof { packet_hash }, resp_tx)) = event_rx
            .recv()
            .ok()
            .and_then(|event| event.into_query().ok())
        {
            assert_eq!(packet_hash, [0xEE; 32]);
            let _ = resp_tx.send(QueryResponse::CheckProof(None));
        }
    });

    let request = PickleValue::Dict(vec![(
        PickleValue::String("check_proof".into()),
        PickleValue::Bytes(vec![0xEE; 32]),
    )]);

    let response = handle_rpc_request(&request, &mut event_tx.clone()).unwrap();
    assert_eq!(response, PickleValue::None);
    driver.join().unwrap();
}

#[test]
fn check_proof_rpc_found() {
    let (event_tx, event_rx) = crate::event::channel();

    let driver = thread::spawn(move || {
        if let Some((QueryRequest::CheckProof { packet_hash }, resp_tx)) = event_rx
            .recv()
            .ok()
            .and_then(|event| event.into_query().ok())
        {
            assert_eq!(packet_hash, [0xFF; 32]);
            let _ = resp_tx.send(QueryResponse::CheckProof(Some(0.352)));
        }
    });

    let request = PickleValue::Dict(vec![(
        PickleValue::String("check_proof".into()),
        PickleValue::Bytes(vec![0xFF; 32]),
    )]);

    let response = handle_rpc_request(&request, &mut event_tx.clone()).unwrap();
    if let PickleValue::Float(rtt) = response {
        assert!((rtt - 0.352).abs() < 0.001);
    } else {
        panic!("Expected Float, got {:?}", response);
    }
    driver.join().unwrap();
}

#[test]
fn request_path_rpc() {
    let (event_tx, event_rx) = crate::event::channel();

    let driver =
        thread::spawn(
            move || match event_rx.recv_timeout(std::time::Duration::from_secs(5)) {
                Ok(Event::RequestPath { dest_hash }) => {
                    assert_eq!(dest_hash, [0x11; 16]);
                }
                other => panic!("Expected RequestPath event, got {:?}", other),
            },
        );

    let request = PickleValue::Dict(vec![(
        PickleValue::String("request_path".into()),
        PickleValue::Bytes(vec![0x11; 16]),
    )]);

    let response = handle_rpc_request(&request, &mut event_tx.clone()).unwrap();
    assert_eq!(response, PickleValue::Bool(true));
    driver.join().unwrap();
}

#[test]
fn begin_drain_rpc_emits_event() {
    let (event_tx, event_rx) = crate::event::channel();

    let driver = thread::spawn(
        move || match event_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Event::BeginDrain { timeout }) => {
                assert!((timeout.as_secs_f64() - 1.5).abs() < 0.001);
            }
            other => panic!("Expected BeginDrain event, got {:?}", other),
        },
    );

    let request = PickleValue::Dict(vec![(
        PickleValue::String("begin_drain".into()),
        PickleValue::Float(1.5),
    )]);

    let response = handle_rpc_request(&request, &mut event_tx.clone()).unwrap();
    assert_eq!(response, PickleValue::Bool(true));
    driver.join().unwrap();
}

#[test]
fn begin_drain_rpc_with_an_unrepresentable_timeout_drains_without_a_deadline() {
    for value in [f64::INFINITY, 1e30] {
        let (event_tx, event_rx) = crate::event::channel();
        let request = PickleValue::Dict(vec![(
            PickleValue::String("begin_drain".into()),
            PickleValue::Float(value),
        )]);
        let response = handle_rpc_request(&request, &mut event_tx.clone()).unwrap();
        assert_eq!(response, PickleValue::Bool(true));
        match event_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Event::BeginDrain { timeout }) => assert_eq!(timeout, Duration::MAX),
            other => panic!("Expected BeginDrain event, got {:?}", other),
        }
    }
}

#[test]
fn drain_status_rpc_roundtrips_fields() {
    let (event_tx, event_rx) = crate::event::channel();

    let driver = thread::spawn(move || {
        if let Some((QueryRequest::DrainStatus, resp_tx)) = event_rx
            .recv()
            .ok()
            .and_then(|event| event.into_query().ok())
        {
            let _ = resp_tx.send(QueryResponse::DrainStatus(DrainStatus {
                state: LifecycleState::Draining,
                drain_age_seconds: Some(0.75),
                deadline_remaining_seconds: Some(2.25),
                drain_complete: false,
                interface_writer_queued_frames: 3,
                provider_backlog_events: 4,
                provider_consumer_queued_events: 5,
                detail: Some("node is draining existing work".into()),
            }));
        }
    });

    let request = PickleValue::Dict(vec![(
        PickleValue::String("get".into()),
        PickleValue::String("drain_status".into()),
    )]);

    let response = handle_rpc_request(&request, &mut event_tx.clone()).unwrap();
    assert_eq!(response.get("state").unwrap().as_str(), Some("draining"));
    assert_eq!(
        response.get("drain_complete").unwrap().as_bool(),
        Some(false)
    );
    assert_eq!(
        response
            .get("deadline_remaining_seconds")
            .unwrap()
            .as_float(),
        Some(2.25)
    );
    assert_eq!(
        response
            .get("interface_writer_queued_frames")
            .unwrap()
            .as_int(),
        Some(3)
    );
    assert_eq!(
        response.get("provider_backlog_events").unwrap().as_int(),
        Some(4)
    );
    assert_eq!(
        response
            .get("provider_consumer_queued_events")
            .unwrap()
            .as_int(),
        Some(5)
    );
    assert_eq!(
        response.get("detail").unwrap().as_str(),
        Some("node is draining existing work")
    );
    driver.join().unwrap();
}

#[test]
fn interface_stats_with_probe_responder() {
    let probe_hash = [0x42; 16];
    let stats = InterfaceStatsResponse {
        network_id: None,
        interfaces: vec![],
        transport_id: None,
        transport_enabled: true,
        transport_uptime: 100.0,
        total_rxb: 0,
        total_txb: 0,
        rx_pps: 0.0,
        tx_pps: 0.0,
        traffic: TrafficDetail::default(),
        probe_responder: Some(probe_hash),
        backbone_peer_pool: None,
        ..Default::default()
    };

    let pickle = interface_stats_to_pickle(&stats);
    let encoded = pickle::encode(&pickle);
    let decoded = pickle::decode(&encoded).unwrap();

    let pr = decoded.get("probe_responder").unwrap().as_bytes().unwrap();
    assert_eq!(pr, &probe_hash);
}

#[test]
fn runtime_config_get_and_set_rpc() {
    let (event_tx, event_rx) = crate::event::channel();

    let driver = thread::spawn(move || {
        if let Some((QueryRequest::GetRuntimeConfig { key }, resp_tx)) = event_rx
            .recv()
            .ok()
            .and_then(|event| event.into_query().ok())
        {
            assert_eq!(key, "global.tick_interval_ms");
            let _ = resp_tx.send(QueryResponse::RuntimeConfigEntry(Some(
                RuntimeConfigEntry {
                    key,
                    value: RuntimeConfigValue::Int(1000),
                    default: RuntimeConfigValue::Int(1000),
                    source: RuntimeConfigSource::Startup,
                    apply_mode: RuntimeConfigApplyMode::Immediate,
                    description: Some("tick".into()),
                },
            )));
        } else {
            panic!("expected GetRuntimeConfig query");
        }

        if let Some((QueryRequest::SetRuntimeConfig { key, value }, resp_tx)) = event_rx
            .recv()
            .ok()
            .and_then(|event| event.into_query().ok())
        {
            assert_eq!(key, "global.tick_interval_ms");
            assert_eq!(value, RuntimeConfigValue::Int(250));
            let _ = resp_tx.send(QueryResponse::RuntimeConfigSet(Ok(RuntimeConfigEntry {
                key,
                value: RuntimeConfigValue::Int(250),
                default: RuntimeConfigValue::Int(1000),
                source: RuntimeConfigSource::RuntimeOverride,
                apply_mode: RuntimeConfigApplyMode::Immediate,
                description: Some("tick".into()),
            })));
        } else {
            panic!("expected SetRuntimeConfig query");
        }
    });

    let get_request = PickleValue::Dict(vec![
        (
            PickleValue::String("get".into()),
            PickleValue::String("runtime_config_entry".into()),
        ),
        (
            PickleValue::String("key".into()),
            PickleValue::String("global.tick_interval_ms".into()),
        ),
    ]);
    let get_response = handle_rpc_request(&get_request, &mut event_tx.clone()).unwrap();
    assert_eq!(
        get_response.get("key").and_then(|v| v.as_str()),
        Some("global.tick_interval_ms")
    );

    let set_request = PickleValue::Dict(vec![
        (
            PickleValue::String("set".into()),
            PickleValue::String("runtime_config".into()),
        ),
        (
            PickleValue::String("key".into()),
            PickleValue::String("global.tick_interval_ms".into()),
        ),
        (PickleValue::String("value".into()), PickleValue::Int(250)),
    ]);
    let set_response = handle_rpc_request(&set_request, &mut event_tx.clone()).unwrap();
    assert_eq!(
        set_response.get("value").and_then(|v| v.as_int()),
        Some(250)
    );

    driver.join().unwrap();
}

// Helper: create a connected TCP pair
fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let (server, _) = listener.accept().unwrap();
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    server
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    (server, client)
}

/// Three known destinations as the driver reports them: never used and
/// unstamped, used and stamped with a link cost, and retained.
fn known_destination_fixtures() -> Vec<KnownDestinationEntry> {
    let entry = |n: u8| KnownDestinationEntry {
        dest_hash: [n; 16],
        identity_hash: crate::storage::full_hash_prefix(&[n; 64]),
        public_key: [n; 64],
        packet_hash: Some([n; 32]),
        app_data: None,
        hops: 2,
        received_at: 1_700_000_000.25,
        receiving_interface: InterfaceId(3),
        was_used: false,
        last_used_at: None,
        retained: false,
        stamp: None,
        stamp_value: rns_core::stamp::StampValue::ZERO,
        lr_cost: None,
    };
    let never = entry(0x11);
    let used = KnownDestinationEntry {
        app_data: Some(b"app".to_vec()),
        was_used: true,
        last_used_at: Some(1_700_000_100.5),
        stamp: Some([0x5a; rns_core::constants::STAMP_LENGTH]),
        stamp_value: rns_core::stamp::StampValue::from_f64(9.5),
        lr_cost: Some(rns_core::stamp::StampCost::from_f64(12.5)),
        ..entry(0x22)
    };
    let retained = KnownDestinationEntry {
        packet_hash: None,
        was_used: true,
        retained: true,
        ..entry(0x33)
    };
    vec![never, used, retained]
}

/// Answer one `get` with a driver that reports the fixtures.
fn known_destinations_answer(path: &str) -> PickleValue {
    let (event_tx, event_rx) = crate::event::channel();
    let driver = thread::spawn(move || {
        let Ok(Event::Query(request, resp_tx)) =
            event_rx.recv_timeout(std::time::Duration::from_secs(5))
        else {
            panic!("expected a query");
        };
        assert!(matches!(*request, QueryRequest::KnownDestinations));
        let _ = resp_tx.send(QueryResponse::KnownDestinations(
            known_destination_fixtures(),
        ));
    });
    let request = PickleValue::Dict(vec![(
        PickleValue::String("get".into()),
        PickleValue::String(path.into()),
    )]);
    let answer = handle_rpc_request(&request, &mut event_tx.clone()).unwrap();
    driver.join().unwrap();
    answer
}

#[test]
fn known_destinations_rpc_answers_upstreams_dict() {
    // Upstream 48c77061's `get_known_destinations()`: a copy of
    // `Identity.known_destinations`, `{destination_hash: [last_heard,
    // packet_hash, public_key, app_data, used, stamp, stamp_value,
    // lr_cost]}`, sent as msgpack.
    let answer = known_destinations_answer("known_destinations");
    let packed = encode_rpc_payload(&answer, RpcCodec::Msgpack);
    use rns_core::msgpack::Value as V;
    let entry = |n: u8, rest: [V; 6]| {
        let [app_data, used, stamp, stamp_value, lr_cost, packet_hash] = rest;
        (
            V::Bin(vec![n; 16]),
            V::Array(vec![
                V::Float(1_700_000_000.25),
                packet_hash,
                V::Bin(vec![n; 64]),
                app_data,
                used,
                stamp,
                stamp_value,
                lr_cost,
            ]),
        )
    };
    let expected = V::Map(vec![
        // `Identity.remember`: `used` 0 and `stamp_value` 0, both ints.
        entry(
            0x11,
            [
                V::Nil,
                V::UInt(0),
                V::Nil,
                V::UInt(0),
                V::Nil,
                V::Bin(vec![0x11; 32]),
            ],
        ),
        entry(
            0x22,
            [
                V::Bin(b"app".to_vec()),
                V::Float(1_700_000_100.5),
                V::Bin(vec![0x5a; rns_core::constants::STAMP_LENGTH]),
                V::Float(9.5),
                V::Float(12.5),
                V::Bin(vec![0x22; 32]),
            ],
        ),
        // `_retain_destination_data` sets `used` to -1; a packet hash this
        // node does not know is all zeros, as its database holds it.
        entry(
            0x33,
            [
                V::Nil,
                V::Int(-1),
                V::Nil,
                V::UInt(0),
                V::Nil,
                V::Bin(vec![0; 32]),
            ],
        ),
    ]);
    assert_eq!(rns_core::msgpack::unpack_exact(&packed).unwrap(), expected);
    // Floats go out as float64, as Python packs them.
    assert_eq!(
        packed
            .windows(9)
            .filter(|w| w[0] == 0xcb && w[1..] == 1_700_000_000.25f64.to_be_bytes())
            .count(),
        3
    );

    // A client reads the same table back.
    let parsed = parse_upstream_known_destinations(&answer).unwrap();
    assert_eq!(parsed.len(), 3);
    let (hash, used) = &parsed[1];
    assert_eq!(*hash, [0x22; 16]);
    assert_eq!(used.packet_hash, Some([0x22; 32]));
    assert_eq!(
        used.identity_hash,
        crate::storage::full_hash_prefix(&[0x22; 64])
    );
    assert_eq!(used.app_data.as_deref(), Some(&b"app"[..]));
    assert_eq!(used.last_used_at, Some(1_700_000_100.5));
    assert!(used.was_used && !used.retained);
    assert_eq!(used.stamp_value.as_f64(), 9.5);
    assert_eq!(used.lr_cost.map(|cost| cost.as_f64()), Some(12.5));
    assert!(parsed[2].1.retained);
    assert_eq!(parsed[2].1.packet_hash, None);
    assert!(!parsed[0].1.was_used);
}

#[test]
fn known_destination_entries_rpc_keeps_the_native_list() {
    let answer = known_destinations_answer("known_destination_entries");
    assert_eq!(
        parse_known_destination_list(&answer).unwrap(),
        known_destination_fixtures()
            .into_iter()
            .map(|entry| KnownDestinationEntry {
                packet_hash: None,
                ..entry
            })
            .collect::<Vec<_>>()
    );
}

// Upstream 1f7cd145: `link_distribution`'s `from_ifs` is a list, so the
// answer encodes and the client gets it (at 3f55e9eb a set made upstream's
// `rpc_loop` close the connection unanswered). An empty table answers an
// empty dict.
#[test]
fn link_distribution_rpc_answers_with_from_ifs_lists() {
    let key = derive_auth_key(b"link-distribution");
    let request = rns_core::msgpack::pack(&MsgpackValue::Map(vec![(
        MsgpackValue::Str("get".into()),
        MsgpackValue::Str("link_distribution".into()),
    )]));
    for links in [0usize, 1] {
        let (server, mut client) = tcp_pair();
        let (event_tx, event_rx) = crate::event::channel();
        let driver = thread::spawn(move || {
            let Ok(Event::Query(query, resp_tx)) =
                event_rx.recv_timeout(std::time::Duration::from_secs(5))
            else {
                panic!("expected a query");
            };
            assert!(matches!(*query, QueryRequest::LinkDistribution));
            let entries = (0..links)
                .map(|_| LinkDistributionEntry {
                    destination_hash: [0xD5; 16],
                    active: 1,
                    pending: 0,
                    traffic: 42,
                    from_interface_hashes: vec![[0x11; 32], [0x22; 32]],
                })
                .collect();
            let _ = resp_tx.send(QueryResponse::LinkDistribution(entries));
        });
        let handler = thread::spawn(move || handle_connection(server, &key, &event_tx));
        client_auth(&mut client, &key).unwrap();
        send_bytes(&mut client, &request).unwrap();
        handler.join().unwrap().unwrap();
        driver.join().unwrap();
        let answer = recv_bytes(&mut client).unwrap();
        let expected = if links == 0 {
            MsgpackValue::Map(Vec::new())
        } else {
            let key = |k: &str| MsgpackValue::Str(k.into());
            MsgpackValue::Map(vec![(
                MsgpackValue::Bin(vec![0xD5; 16]),
                MsgpackValue::Map(vec![
                    (key("active"), MsgpackValue::UInt(1)),
                    (key("pending"), MsgpackValue::UInt(0)),
                    (key("traffic"), MsgpackValue::UInt(42)),
                    (
                        key("from_ifs"),
                        MsgpackValue::Array(vec![
                            MsgpackValue::Bin(vec![0x11; 32]),
                            MsgpackValue::Bin(vec![0x22; 32]),
                        ]),
                    ),
                ]),
            )])
        };
        assert_eq!(rns_core::msgpack::unpack_exact(&answer).unwrap(), expected);
    }
}

// upstream 52898683: the shared instance RPC listener takes a backlog of
// 128 (it had 1). The abstract socket rns-rs listens on queues as many
// connections nobody has accepted yet.
#[cfg(target_os = "linux")]
#[test]
fn abstract_rpc_listener_queues_upstreams_backlog() {
    let instance = crate::test_support::instance_name("rpc-backlog");
    let listener = bind_abstract_unix(&instance).unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let connector = thread::spawn(move || {
        let addr =
            std::os::unix::net::SocketAddr::from_abstract_name(format!("rns/{instance}/rpc"))
                .unwrap();
        let streams: Vec<_> = (0..128)
            .map(|_| std::os::unix::net::UnixStream::connect_addr(&addr).unwrap())
            .collect();
        let _ = done_tx.send(streams.len());
        streams
    });
    // A connection beyond the backlog would wait for an accept.
    assert_eq!(
        done_rx.recv_timeout(std::time::Duration::from_secs(10)),
        Ok(128)
    );
    drop(connector.join().unwrap());
    drop(listener);
}
