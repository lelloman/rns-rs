use super::*;
use std::io::Read;
use std::sync::mpsc;
use std::time::Duration;

fn find_free_port() -> u16 {
    crate::test_support::port()
}

/// Serve the receiver's sockets and timers for `duration` without
/// taking any event, as a driver busy with other work would.
fn serve_for(rx: &crate::event::EventReceiver, duration: Duration) {
    let deadline = Instant::now() + duration;
    let mut ready = crate::poll::Events::new();
    while Instant::now() < deadline {
        ready.clear();
        rx.poll_ready(&mut ready).unwrap();
        rx.serve_sources(&ready);
        thread::sleep(Duration::from_millis(2));
    }
}

fn test_fast_flap_config() -> BackboneFastFlapConfig {
    BackboneFastFlapConfig {
        enabled: true,
        connection_threshold: Duration::from_secs(20),
        grace: 5,
        block_duration: Duration::from_secs(12 * 60 * 60),
    }
}

#[test]
fn blocked_ips_file_parses_addresses_and_skips_comments_and_garbage() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("blocked_ips"),
        "\n# a comment\n 203.0.113.7 \n2001:DB8::1\n\n198.51.100.0/24\nexample.com\n\
             192.0.2.1 # trailing comment\n010.0.0.1\n::ffff:192.0.2.9\n",
    )
    .unwrap();
    let ips = read_blocked_ips_file(dir.path());
    let expected: Vec<IpAddr> = ["203.0.113.7", "2001:db8::1", "::ffff:192.0.2.9"]
        .iter()
        .map(|ip| ip.parse().unwrap())
        .collect();
    assert_eq!(ips, expected);
}

#[test]
fn missing_or_unreadable_blocked_ips_file_blocks_nothing() {
    let dir = tempfile::tempdir().unwrap();
    assert!(read_blocked_ips_file(dir.path()).is_empty());
    std::fs::write(dir.path().join("blocked_ips"), [0xFF, 0xFE, b'\n']).unwrap();
    assert!(read_blocked_ips_file(dir.path()).is_empty());
}

#[test]
fn file_blocked_ip_never_expires_and_is_listed() {
    let mut monitor = BackboneFastFlapMonitor::new();
    let ip: IpAddr = "203.0.113.7".parse().unwrap();
    monitor.load_static_blocked([ip]);
    let config = BackboneFastFlapConfig {
        block_duration: Duration::from_secs(1),
        ..test_fast_flap_config()
    };
    let later = Instant::now() + Duration::from_secs(1_000_000);
    assert!(monitor.is_blocked(ip, &config, later));
    assert_eq!(monitor.blocked_ip_list(&config, later), vec![ip]);
    assert_eq!(monitor.blocked_ip_count(&config, later), 1);
    // Clearing forgets it until the file is read again.
    assert!(monitor.clear(ip));
    assert!(!monitor.is_blocked(ip, &config, later));
}

#[test]
fn file_blocked_ip_follows_the_listener_fast_flap_policy() {
    let mut monitor = BackboneFastFlapMonitor::new();
    let ip: IpAddr = "203.0.113.8".parse().unwrap();
    monitor.load_static_blocked([ip]);
    let disabled = BackboneFastFlapConfig {
        enabled: false,
        ..test_fast_flap_config()
    };
    assert!(!monitor.is_statically_blocked(ip, &disabled));
    assert!(monitor
        .blocked_ip_list(&disabled, Instant::now())
        .is_empty());
    // Upstream gives these addresses a flap count of 0xFFFF.
    let just_below = BackboneFastFlapConfig {
        grace: STATIC_BLOCK_FLAP_COUNT - 1,
        ..test_fast_flap_config()
    };
    assert!(monitor.is_statically_blocked(ip, &just_below));
    let at = BackboneFastFlapConfig {
        grace: STATIC_BLOCK_FLAP_COUNT,
        ..test_fast_flap_config()
    };
    assert!(!monitor.is_statically_blocked(ip, &at));
}

#[test]
fn file_blocked_ipv4_matches_its_ipv4_mapped_form() {
    let mut monitor = BackboneFastFlapMonitor::new();
    monitor.load_static_blocked(["192.0.2.10".parse::<IpAddr>().unwrap()]);
    let mapped: IpAddr = "::ffff:192.0.2.10".parse().unwrap();
    assert!(monitor.is_statically_blocked(mapped, &test_fast_flap_config()));
}

#[test]
fn backbone_blocked_ips_file_rejects_before_allocating_interface() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(9950));
    let mut config = make_server_config(port, 98, None, None, None, BackboneAbuseConfig::default());
    config.fast_flap = test_fast_flap_config();
    lock_or_recover(&config.fast_flap_state, "test fast-flap state")
        .load_static_blocked(["127.0.0.1".parse::<IpAddr>().unwrap()]);
    let peer_state = Arc::clone(&config.peer_state);

    start(config, tx, Arc::clone(&next_id)).unwrap();
    thread::sleep(Duration::from_millis(50));

    let _rejected = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    serve_for(&rx, Duration::from_millis(200));
    assert_eq!(
        next_id.load(Ordering::Relaxed),
        9950,
        "rejection must happen before dynamic interface allocation"
    );
    while let Ok(event) = rx.try_recv() {
        assert!(!matches!(event, Event::InterfaceUp(_, _, _)));
    }
    let entries = lock_or_recover(&peer_state, "test peer state").list("test-backbone");
    let entry = entries
        .iter()
        .find(|entry| entry.peer_ip == "127.0.0.1".parse::<IpAddr>().unwrap())
        .expect("blocked peer state");
    assert_eq!(entry.blacklist_reason.as_deref(), Some("blocked_ips file"));
    assert_eq!(entry.reject_count, 1);
}

fn limit_params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn client_limit_defaults_to_upstream_500() {
    assert_eq!(BACKBONE_CLIENT_LIMIT, 500);
    assert_eq!(parse_client_limit(&limit_params(&[])).unwrap(), Some(500));
    // Upstream reads `client_limit or CLIENT_LIMIT`.
    assert_eq!(
        parse_client_limit(&limit_params(&[("client_limit", "0")])).unwrap(),
        Some(500)
    );
    assert_eq!(
        parse_client_limit(&limit_params(&[("client_limit", "7")])).unwrap(),
        Some(7)
    );
}

#[test]
fn client_limit_rejects_invalid_values() {
    for raw in ["abc", "-1", "1.5"] {
        let err = parse_client_limit(&limit_params(&[("client_limit", raw)])).unwrap_err();
        assert!(err.contains("client_limit"), "{err}");
    }
}

#[test]
fn max_connections_takes_precedence_over_client_limit() {
    assert_eq!(
        parse_client_limit(&limit_params(&[
            ("client_limit", "7"),
            ("max_connections", "512"),
        ]))
        .unwrap(),
        Some(512)
    );
    // max_connections = 0 keeps its meaning: no limit.
    assert_eq!(
        parse_client_limit(&limit_params(&[("max_connections", "0")])).unwrap(),
        None
    );
}

#[test]
fn fast_flap_defaults_match_upstream() {
    assert_eq!(BackboneFastFlapConfig::default(), test_fast_flap_config());
}

#[test]
fn sixth_short_connection_blocks_but_fifth_does_not() {
    let config = test_fast_flap_config();
    let mut monitor = BackboneFastFlapMonitor::new();
    let peer: IpAddr = "192.0.2.10".parse().unwrap();
    let start = Instant::now();

    for flap in 1..=5 {
        let record = monitor
            .record_disconnect(
                peer,
                Duration::from_secs(19),
                &config,
                start + Duration::from_secs(flap),
            )
            .unwrap();
        assert_eq!(record.flap_count, flap);
        assert!(!record.blocked);
        assert!(!monitor.is_blocked(peer, &config, start + Duration::from_secs(flap)));
    }

    let sixth = monitor
        .record_disconnect(
            peer,
            Duration::from_secs(1),
            &config,
            start + Duration::from_secs(6),
        )
        .unwrap();
    assert_eq!(sixth.flap_count, 6);
    assert!(sixth.blocked);
    assert!(sixth.newly_blocked);
    assert!(monitor.is_blocked(peer, &config, start + Duration::from_secs(6)));
}

#[test]
fn every_short_connection_counts_even_after_receiving_data() {
    let config = test_fast_flap_config();
    let mut monitor = BackboneFastFlapMonitor::new();
    let peer: IpAddr = "192.0.2.11".parse().unwrap();
    let now = Instant::now();

    let record = monitor
        .record_disconnect(peer, Duration::from_secs(2), &config, now)
        .unwrap();
    assert_eq!(record.flap_count, 1);
    assert_eq!(monitor.flap_count(peer), 1);
}

#[test]
fn threshold_boundary_and_long_connections_are_not_counted() {
    let config = test_fast_flap_config();
    let mut monitor = BackboneFastFlapMonitor::new();
    let peer: IpAddr = "192.0.2.12".parse().unwrap();
    let now = Instant::now();

    assert!(monitor
        .record_disconnect(peer, Duration::from_secs(20), &config, now)
        .is_none());
    assert!(monitor
        .record_disconnect(peer, Duration::from_secs(21), &config, now)
        .is_none());
    assert_eq!(monitor.flap_count(peer), 0);
}

#[test]
fn disabled_fast_flapping_neither_tracks_nor_blocks() {
    let mut config = test_fast_flap_config();
    config.enabled = false;
    let mut monitor = BackboneFastFlapMonitor::new();
    let peer: IpAddr = "192.0.2.13".parse().unwrap();
    let now = Instant::now();

    for offset in 0..10 {
        assert!(monitor
            .record_disconnect(
                peer,
                Duration::from_secs(1),
                &config,
                now + Duration::from_secs(offset),
            )
            .is_none());
    }
    assert_eq!(monitor.flap_count(peer), 0);
    assert!(!monitor.is_blocked(peer, &config, now + Duration::from_secs(10)));
    assert_eq!(monitor.blocked_ip_count(&config, now), 0);
}

#[test]
fn flap_blocks_expire_strictly_after_configured_duration() {
    let mut config = test_fast_flap_config();
    config.grace = 0;
    config.block_duration = Duration::from_secs(60);
    let mut monitor = BackboneFastFlapMonitor::new();
    let peer: IpAddr = "192.0.2.14".parse().unwrap();
    let now = Instant::now();

    monitor
        .record_disconnect(peer, Duration::from_secs(1), &config, now)
        .unwrap();
    assert!(monitor.is_blocked(peer, &config, now + Duration::from_secs(60)));
    assert!(!monitor.is_blocked(
        peer,
        &config,
        now + Duration::from_secs(60) + Duration::from_nanos(1)
    ));
    assert_eq!(monitor.flap_count(peer), 0);
}

#[test]
fn fast_flap_history_is_isolated_by_ip() {
    let mut config = test_fast_flap_config();
    config.grace = 1;
    let mut monitor = BackboneFastFlapMonitor::new();
    let first: IpAddr = "192.0.2.15".parse().unwrap();
    let second: IpAddr = "192.0.2.16".parse().unwrap();
    let now = Instant::now();

    for offset in 0..2 {
        monitor
            .record_disconnect(
                first,
                Duration::from_secs(1),
                &config,
                now + Duration::from_secs(offset),
            )
            .unwrap();
    }
    monitor
        .record_disconnect(second, Duration::from_secs(1), &config, now)
        .unwrap();

    assert!(monitor.is_blocked(first, &config, now + Duration::from_secs(2)));
    assert!(!monitor.is_blocked(second, &config, now + Duration::from_secs(2)));
    assert_eq!(
        monitor.blocked_ip_count(&config, now + Duration::from_secs(2)),
        1
    );
    assert_eq!(
        monitor.blocked_ip_list(&config, now + Duration::from_secs(2)),
        vec![first],
        "tracked peers within the grace allowance must not appear as blocked"
    );
}

#[test]
fn blocked_ip_list_is_sorted_current_and_empty_when_disabled() {
    let mut config = test_fast_flap_config();
    config.grace = 0;
    config.block_duration = Duration::from_secs(60);
    let mut monitor = BackboneFastFlapMonitor::new();
    let first: IpAddr = "203.0.113.20".parse().unwrap();
    let second: IpAddr = "192.0.2.10".parse().unwrap();
    let now = Instant::now();
    monitor
        .record_disconnect(first, Duration::from_secs(1), &config, now)
        .unwrap();
    monitor
        .record_disconnect(second, Duration::from_secs(1), &config, now)
        .unwrap();

    assert_eq!(monitor.blocked_ip_list(&config, now), vec![second, first]);
    assert!(monitor
        .blocked_ip_list(&config, now + Duration::from_secs(61))
        .is_empty());
    config.enabled = false;
    assert!(monitor.blocked_ip_list(&config, now).is_empty());
}

#[test]
fn peer_monitor_snapshot_clears_expired_blacklist_state() {
    let peer: IpAddr = "192.0.2.17".parse().unwrap();
    let mut monitor = BackbonePeerMonitor::new();
    monitor.blacklist(peer, Duration::from_secs(60), "temporary".into());
    let mut peers = HashMap::new();
    monitor.sync_into(&mut peers);
    let state = peers.get_mut(&peer).unwrap();
    state.blacklisted_until = None;
    state.blacklist_reason = None;

    monitor.upsert_snapshot(&peers);

    let entry = monitor.list("test").into_iter().next().unwrap();
    assert!(entry.blacklisted_remaining_secs.is_none());
    assert!(entry.blacklist_reason.is_none());
}

fn recv_non_peer_event(
    rx: &crate::event::EventReceiver,
    timeout: Duration,
) -> Result<Event, mpsc::RecvTimeoutError> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(mpsc::RecvTimeoutError::Timeout);
        }
        let event = rx.recv_timeout(remaining)?;
        match event {
            Event::BackbonePeerConnected { .. }
            | Event::BackbonePeerDisconnected { .. }
            | Event::BackbonePeerIdleTimeout { .. }
            | Event::BackbonePeerWriteStall { .. }
            | Event::BackbonePeerPenalty { .. } => continue,
            other => return Ok(other),
        }
    }
}

fn make_server_config(
    port: u16,
    interface_id: u64,
    max_connections: Option<usize>,
    idle_timeout: Option<Duration>,
    write_stall_timeout: Option<Duration>,
    abuse: BackboneAbuseConfig,
) -> BackboneConfig {
    let mut config = BackboneConfig {
        name: "test-backbone".into(),
        listen_ip: "127.0.0.1".into(),
        listen_port: port,
        interface_id: InterfaceId(interface_id),
        mode: constants::MODE_FULL,
        gravity: 0,
        recursive_prs: false,
        announces_from_internal: true,
        announces_to_internal: None,
        max_connections,
        idle_timeout,
        write_stall_timeout,
        abuse,
        fast_flap: BackboneFastFlapConfig::default(),
        fast_flap_state: Arc::new(Mutex::new(BackboneFastFlapMonitor::new())),
        ingress_control: IngressControlConfig::enabled(),
        runtime: Arc::new(Mutex::new(BackboneServerRuntime {
            max_connections: None,
            idle_timeout: None,
            write_stall_timeout: None,
            abuse: BackboneAbuseConfig::default(),
        })),
        peer_state: Arc::new(Mutex::new(BackbonePeerMonitor::new())),
    };
    let startup = BackboneServerRuntime::from_config(&config);
    config.runtime = Arc::new(Mutex::new(startup));
    config
}

#[test]
fn backbone_accept_connection() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(8000));

    let config = make_server_config(port, 80, None, None, None, BackboneAbuseConfig::default());

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));

    let _client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    match event {
        Event::InterfaceUp(id, writer, info) => {
            assert_eq!(id, InterfaceId(8000));
            assert!(writer.is_some());
            assert!(info.is_some());
            let info = info.unwrap();
            assert!(info.out_capable);
            assert!(info.in_capable);
            assert_eq!(info.bitrate, Some(SERVER_BITRATE_GUESS));
            assert_eq!(info.mtu, SERVER_PEER_MTU);
        }
        other => panic!("expected InterfaceUp, got {:?}", other),
    }
}

#[test]
fn backbone_class_defaults_preserve_server_and_client_distinction() {
    assert_eq!(SERVER_BITRATE_GUESS, 100_000_000);
    assert_eq!(SERVER_PEER_MTU, 32_768);
    assert_eq!(CLIENT_BITRATE_GUESS, 100_000_000);
    assert_eq!(HW_MTU, 32_768);
}

#[test]
fn client_hw_mtu_follows_its_bitrate() {
    let mut config = BackboneClientConfig::default();
    assert_eq!(config.hw_mtu(), HW_MTU);
    // An auto-connected client, configured at 5 Mbps.
    config.bitrate = 5_000_000;
    assert_eq!(config.hw_mtu(), 8192);
}

#[test]
fn auto_mtu_thresholds_include_exact_bitrate_boundaries() {
    for (bitrate, mtu) in [
        (1_000_000_000, Some(524_288)),
        (750_000_000, Some(262_144)),
        (400_000_000, Some(131_072)),
        (200_000_000, Some(65_536)),
        (100_000_000, Some(32_768)),
        (10_000_000, Some(16_384)),
        (5_000_000, Some(8_192)),
        (2_000_000, Some(4_096)),
        (1_000_000, Some(2_048)),
        (62_500, Some(1_024)),
        (62_499, None),
    ] {
        assert_eq!(auto_mtu_for_bitrate(bitrate), mtu, "bitrate {bitrate}");
    }
}

#[test]
fn backbone_accepted_connection_inherits_server_mode() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(8050));

    let mut config = make_server_config(port, 85, None, None, None, BackboneAbuseConfig::default());
    config.mode = constants::MODE_GATEWAY;

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));

    let _client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    match event {
        Event::InterfaceUp(_, _, Some(info)) => {
            assert_eq!(info.mode, constants::MODE_GATEWAY);
        }
        other => panic!("expected InterfaceUp with info, got {:?}", other),
    }
}

#[test]
fn dataplane_ingress_thresholds_match_upstream_defaults() {
    assert_eq!(
        ingress_thresholds(1024),
        IngressThresholds {
            high: 921,
            immediate: 921,
            mid: 696,
            low: 102,
        }
    );
    assert_eq!(
        ingress_thresholds(8),
        IngressThresholds {
            high: 7,
            immediate: 128,
            mid: 5,
            low: 0,
        }
    );
}

#[test]
fn dataplane_ingress_selects_the_largest_packet_producer() {
    assert_eq!(
        busiest_ingress_key([(7, 12), (8, 41), (9, 3)].into_iter()),
        Some(8)
    );
    assert_eq!(busiest_ingress_key([(7, 0), (8, 0)].into_iter()), None);
}

#[test]
fn backbone_gates_the_largest_producer_before_data_queue_overflow() {
    let port = find_free_port();
    let capacities = crate::event::InboundQueueCapacities {
        data: 200,
        announce: 8,
        path_request: 8,
        ingress_limited: 8,
    };
    let (tx, rx) = crate::event::channel_with_queue_capacities(16, capacities);
    let observer = tx.clone();
    let next_id = Arc::new(AtomicU64::new(8075));
    let config = make_server_config(port, 80, None, None, None, BackboneAbuseConfig::default());

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));
    let mut client = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let _ = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();

    let payload = vec![0u8; 32];
    let framed = hdlc::frame(&payload);
    let mut burst = Vec::with_capacity(framed.len() * 180);
    for _ in 0..180 {
        burst.extend_from_slice(&framed);
    }
    client.write_all(&burst).unwrap();

    let deadline = Instant::now() + Duration::from_secs(2);
    while observer.inbound_queue_snapshot().heights[0] < 180 && Instant::now() < deadline {
        serve_for(&rx, Duration::from_millis(5));
    }
    serve_for(&rx, Duration::from_millis(100));
    let gated = observer.inbound_queue_snapshot();
    assert!(
        gated.heights[0] >= 180,
        "DATA queue never reached the high watermark"
    );
    assert_eq!(gated.dropped[0], 0);

    client.write_all(&hdlc::frame(&[1u8; 32])).unwrap();
    serve_for(&rx, Duration::from_millis(300));
    let after_marker = observer.inbound_queue_snapshot();
    assert_eq!(after_marker.heights[0], gated.heights[0]);
    assert_eq!(
        after_marker.dropped[0], gated.dropped[0],
        "the producer remained readable and overflowed the DATA queue"
    );

    for _ in 0..gated.heights[0] {
        let event = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();
        assert!(matches!(event, Event::Frame { .. }));
    }
    let released = recv_non_peer_event(&rx, Duration::from_secs(5)).unwrap();
    assert!(
        matches!(released, Event::Frame { data, .. } if data == vec![1u8; 32].into()),
        "held producer was not released after DATA pressure recovered"
    );
}

#[test]
fn a_gated_peer_that_hangs_up_is_disconnected_while_gated() {
    let port = find_free_port();
    let capacities = crate::event::InboundQueueCapacities {
        data: 200,
        announce: 8,
        path_request: 8,
        ingress_limited: 8,
    };
    let (tx, rx) = crate::event::channel_with_queue_capacities(16, capacities);
    let observer = tx.clone();
    let next_id = Arc::new(AtomicU64::new(8076));
    let config = make_server_config(port, 80, None, None, None, BackboneAbuseConfig::default());

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));
    let mut client = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let _ = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();

    let framed = hdlc::frame(&[0u8; 32]);
    let mut burst = Vec::with_capacity(framed.len() * 180);
    for _ in 0..180 {
        burst.extend_from_slice(&framed);
    }
    client.write_all(&burst).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while observer.inbound_queue_snapshot().heights[0] < 180 && Instant::now() < deadline {
        serve_for(&rx, Duration::from_millis(5));
    }
    serve_for(&rx, Duration::from_millis(100));
    assert!(observer.inbound_queue_snapshot().heights[0] >= 180);

    // Gated, with the queue still full: a reset (reported even while the
    // peer is unwatched) must be noticed now, not once the hold ends.
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: valid socket and option buffer for the call.
    unsafe {
        libc::setsockopt(
            std::os::fd::AsRawFd::as_raw_fd(&client),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&linger as *const libc::linger).cast(),
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        );
    }
    drop(client);
    serve_for(&rx, Duration::from_millis(200));
    let mut down = false;
    while let Some(received) = rx.try_recv_classified().unwrap() {
        if matches!(received.event, Event::InterfaceDown(InterfaceId(8076))) {
            down = true;
        }
    }
    assert!(down, "the hung-up gated peer was not disconnected");
}

#[cfg(target_os = "linux")]
#[test]
fn backbone_sockets_get_upstreams_user_timeout() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    for stream in [&client, &accepted] {
        set_tcp_keepalive(stream).unwrap();
        let sock = SockRef::from(stream);
        assert_eq!(
            sock.tcp_user_timeout().unwrap(),
            Some(Duration::from_secs(24))
        );
        assert!(sock.keepalive().unwrap());
    }
}

#[test]
fn backbone_receive_frame() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(8100));

    let config = make_server_config(port, 81, None, None, None, BackboneAbuseConfig::default());

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));

    let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

    // Drain InterfaceUp
    let _ = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();

    // The exact Reticulum header minimum must be dropped without
    // preventing recovery of the next valid frame.
    client
        .write_all(&hdlc::frame(&[0x11; rns_core::constants::HEADER_MINSIZE]))
        .unwrap();
    let payload: Vec<u8> = (0..32).collect();
    client.write_all(&hdlc::frame(&payload)).unwrap();

    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    match event {
        Event::Frame {
            interface_id,
            data,
            rssi: _,
            snr: _,
        } => {
            assert_eq!(interface_id, InterfaceId(8100));
            assert_eq!(data, payload.into());
        }
        other => panic!("expected Frame, got {:?}", other),
    }
}

#[test]
fn backbone_send_to_client() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(8200));

    let config = make_server_config(port, 82, None, None, None, BackboneAbuseConfig::default());

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));

    let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    // Get writer from InterfaceUp
    let event = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();
    let mut writer = match event {
        Event::InterfaceUp(_, Some(w), _) => w,
        other => panic!("expected InterfaceUp with writer, got {:?}", other),
    };

    // Send frame via writer
    let payload: Vec<u8> = (0..24).collect();
    writer.send_frame(&payload).unwrap();

    // Read from client
    let mut buf = [0u8; 256];
    let n = client.read(&mut buf).unwrap();
    let expected = hdlc::frame(&payload);
    assert_eq!(&buf[..n], &expected[..]);
}

#[test]
fn backbone_write_backpressure_does_not_starve_reads() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(8250));
    let config = make_server_config(port, 82, None, None, None, BackboneAbuseConfig::default());

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));

    let mut client = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    SockRef::from(&client).set_recv_buffer_size(4096).unwrap();
    let event = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();
    let mut writer = match event {
        Event::InterfaceUp(_, Some(writer), _) => writer,
        other => panic!("expected InterfaceUp with writer, got {other:?}"),
    };

    let outbound = vec![0x55; 60 * 1024];
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut backpressured = false;
    while Instant::now() < deadline {
        match writer.send_frame(&outbound) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                backpressured = true;
                break;
            }
            Err(error) => panic!("unexpected backbone write error: {error}"),
        }
    }
    assert!(
        backpressured,
        "failed to create outbound write backpressure"
    );

    let inbound: Vec<u8> = (0..32).collect();
    client.write_all(&hdlc::frame(&inbound)).unwrap();
    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    match event {
        Event::Frame { data, .. } => assert_eq!(data, inbound.into()),
        other => panic!("inbound frame was starved by outbound backpressure: {other:?}"),
    }
}

#[test]
fn backbone_multiple_clients() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(8300));

    let config = make_server_config(port, 83, None, None, None, BackboneAbuseConfig::default());

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));

    let _client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    let _client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

    let mut ids = Vec::new();
    for _ in 0..2 {
        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        match event {
            Event::InterfaceUp(id, _, _) => ids.push(id),
            other => panic!("expected InterfaceUp, got {:?}", other),
        }
    }

    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
}

#[test]
fn backbone_client_disconnect() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(8400));

    let config = make_server_config(port, 84, None, None, None, BackboneAbuseConfig::default());

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));

    let client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

    // Drain InterfaceUp
    let _ = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();

    // Disconnect
    drop(client);

    // Should receive InterfaceDown
    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    assert!(
        matches!(event, Event::InterfaceDown(InterfaceId(8400))),
        "expected InterfaceDown(8400), got {:?}",
        event
    );
}

#[test]
fn backbone_epoll_multiplexing() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(8500));

    let config = make_server_config(port, 85, None, None, None, BackboneAbuseConfig::default());

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));

    let mut client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    let mut client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

    // Drain both InterfaceUp events
    let _ = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();
    let _ = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();

    // Both clients send data simultaneously
    let payload1: Vec<u8> = (0..24).collect();
    let payload2: Vec<u8> = (100..130).collect();
    client1.write_all(&hdlc::frame(&payload1)).unwrap();
    client2.write_all(&hdlc::frame(&payload2)).unwrap();

    // Should receive both Frame events
    let mut received = Vec::new();
    for _ in 0..2 {
        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { data, .. } => received.push(data),
            other => panic!("expected Frame, got {:?}", other),
        }
    }
    assert!(received.iter().any(|d| **d == payload1[..]));
    assert!(received.iter().any(|d| **d == payload2[..]));
}

#[test]
fn backbone_bind_port() {
    let port = find_free_port();
    let (tx, _rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(8600));

    let config = make_server_config(port, 86, None, None, None, BackboneAbuseConfig::default());

    // Should not error
    start(config, tx, next_id).unwrap();
}

#[test]
fn backbone_hdlc_fragmented() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(8700));

    let config = make_server_config(port, 87, None, None, None, BackboneAbuseConfig::default());

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));

    let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    client.set_nodelay(true).unwrap();

    // Drain InterfaceUp
    let _ = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();

    // Send HDLC frame in two fragments
    let payload: Vec<u8> = (0..32).collect();
    let framed = hdlc::frame(&payload);
    let mid = framed.len() / 2;

    client.write_all(&framed[..mid]).unwrap();
    thread::sleep(Duration::from_millis(50));
    client.write_all(&framed[mid..]).unwrap();

    // Should receive reassembled frame
    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    match event {
        Event::Frame { data, .. } => {
            assert_eq!(data, payload.into());
        }
        other => panic!("expected Frame, got {:?}", other),
    }
}

// -----------------------------------------------------------------------
// Client mode tests
// -----------------------------------------------------------------------

fn make_client_config(port: u16, id: u64) -> BackboneClientConfig {
    BackboneClientConfig {
        name: format!("test-bb-client-{}", port),
        target_host: "127.0.0.1".into(),
        target_port: port,
        interface_id: InterfaceId(id),
        reconnect_wait: Duration::from_millis(100),
        max_reconnect_tries: Some(2),
        connect_timeout: Duration::from_secs(2),
        transport_identity: None,
        bitrate: CLIENT_BITRATE_GUESS,
        runtime: Arc::new(Mutex::new(BackboneClientRuntime {
            reconnect_wait: Duration::from_millis(100),
            max_reconnect_tries: Some(2),
            connect_timeout: Duration::from_secs(2),
        })),
    }
}

#[test]
fn backbone_client_connect() {
    let port = find_free_port();
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
    let (tx, rx) = crate::event::channel();

    let config = make_client_config(port, 9000);
    let _writer = start_client(config, tx).unwrap();

    let _server_stream = listener.accept().unwrap();

    let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(matches!(event, Event::InterfaceUp(InterfaceId(9000), _, _)));
}

#[test]
fn backbone_client_receive_frame() {
    let port = find_free_port();
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
    let (tx, rx) = crate::event::channel();

    let config = make_client_config(port, 9100);
    let _writer = start_client(config, tx).unwrap();

    let (mut server_stream, _) = listener.accept().unwrap();

    // Drain InterfaceUp
    let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

    // Client mode applies the same strict lower bound and recovers.
    server_stream
        .write_all(&hdlc::frame(&[0x11; rns_core::constants::HEADER_MINSIZE]))
        .unwrap();
    let payload: Vec<u8> = (0..32).collect();
    server_stream.write_all(&hdlc::frame(&payload)).unwrap();

    let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    match event {
        Event::Frame {
            interface_id,
            data,
            rssi: _,
            snr: _,
        } => {
            assert_eq!(interface_id, InterfaceId(9100));
            assert_eq!(data, payload.into());
        }
        other => panic!("expected Frame, got {:?}", other),
    }
}

#[test]
fn backbone_client_send_frame() {
    let port = find_free_port();
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
    let (tx, _rx) = crate::event::channel();

    let config = make_client_config(port, 9200);
    let mut writer = start_client(config, tx).unwrap();

    let (mut server_stream, _) = listener.accept().unwrap();
    server_stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let payload: Vec<u8> = (0..24).collect();
    writer.send_frame(&payload).unwrap();

    let mut buf = [0u8; 256];
    let n = server_stream.read(&mut buf).unwrap();
    let expected = hdlc::frame(&payload);
    assert_eq!(&buf[..n], &expected[..]);
}

#[test]
fn backbone_max_connections_rejects_excess() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(8800));

    let config = make_server_config(
        port,
        88,
        Some(2),
        None,
        None,
        BackboneAbuseConfig::default(),
    );

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));

    // Connect two clients (at limit)
    let _client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    let _client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

    // Drain both InterfaceUp events
    for _ in 0..2 {
        let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceUp(_, _, _)));
    }

    // Third connection should be accepted at TCP level but immediately dropped
    let client3 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    client3
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    // Give server time to reject
    thread::sleep(Duration::from_millis(100));

    // Should NOT receive a third InterfaceUp
    let result = recv_non_peer_event(&rx, Duration::from_millis(500));
    assert!(
        result.is_err(),
        "expected no InterfaceUp for rejected connection, got {:?}",
        result
    );
}

#[test]
fn backbone_max_connections_allows_after_disconnect() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(8900));

    let config = make_server_config(
        port,
        89,
        Some(1),
        None,
        None,
        BackboneAbuseConfig::default(),
    );

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));

    // Connect first client
    let client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    assert!(matches!(event, Event::InterfaceUp(_, _, _)));

    // Disconnect first client
    drop(client1);

    // Wait for InterfaceDown
    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    assert!(matches!(event, Event::InterfaceDown(_)));

    // Now a new connection should be accepted
    let _client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    assert!(
        matches!(event, Event::InterfaceUp(_, _, _)),
        "expected InterfaceUp after slot freed, got {:?}",
        event
    );
}

#[test]
fn backbone_client_reconnect() {
    let port = find_free_port();
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
    listener.set_nonblocking(false).unwrap();
    let (tx, rx) = crate::event::channel();

    let config = make_client_config(port, 9300);
    let _writer = start_client(config, tx).unwrap();

    // Accept first connection and immediately close it
    let (server_stream, _) = listener.accept().unwrap();

    // Drain InterfaceUp
    let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

    drop(server_stream);

    // Should get InterfaceDown
    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    assert!(matches!(event, Event::InterfaceDown(InterfaceId(9300))));

    // Accept the reconnection
    let _server_stream2 = listener.accept().unwrap();

    // Should get InterfaceUp again
    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    assert!(matches!(event, Event::InterfaceUp(InterfaceId(9300), _, _)));
}

#[test]
fn a_reconnected_backbone_client_is_read_on_the_receiving_thread() {
    let port = find_free_port();
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
    let (tx, rx) = crate::event::channel();
    let _writer = start_client(make_client_config(port, 9310), tx).unwrap();
    let (first, _) = listener.accept().unwrap();
    assert!(matches!(
        rx.recv_timeout(Duration::from_secs(1)).unwrap(),
        Event::InterfaceUp(InterfaceId(9310), None, _)
    ));
    drop(first);
    assert!(matches!(
        recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap(),
        Event::InterfaceDown(InterfaceId(9310))
    ));
    let (mut second, _) = listener.accept().unwrap();
    assert!(matches!(
        recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap(),
        Event::InterfaceUp(InterfaceId(9310), Some(_), _)
    ));
    let payload: Vec<u8> = (0..32).collect();
    second.write_all(&hdlc::frame(&payload)).unwrap();
    match recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap() {
        Event::Frame { data, .. } => assert_eq!(data, payload.into()),
        other => panic!("expected Frame, got {:?}", other),
    }
    // The reconnect thread exits once the new socket is served here.
    let reconnecting = || {
        std::fs::read_dir("/proc/self/task")
            .unwrap()
            .filter_map(|task| std::fs::read_to_string(task.ok()?.path().join("comm")).ok())
            .any(|name| name.trim_end() == "bb-reconn-9310")
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    while reconnecting() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(!reconnecting());
}

#[test]
fn backbone_client_keeps_reconnecting_until_server_returns() {
    // The remote node restarts: its listener disappears for several
    // reconnect attempts, then comes back on the same port. Without
    // max_reconnect_tries the client must not give up.
    let port = find_free_port();
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let (tx, rx) = crate::event::channel();

    let mut config = make_client_config(port, 9360);
    config.reconnect_wait = Duration::from_millis(20);
    config.max_reconnect_tries = None;
    config.connect_timeout = Duration::from_millis(200);
    config.runtime = Arc::new(Mutex::new(BackboneClientRuntime::from_config(&config)));
    let _writer = start_client(config, tx).unwrap();

    let (server_stream, _) = listener.accept().unwrap();
    let event = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();
    assert!(matches!(
        event,
        Event::InterfaceUp(InterfaceId(9360), None, _)
    ));

    // Server goes away: connection and listener both close.
    drop(server_stream);
    drop(listener);
    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    assert!(matches!(event, Event::InterfaceDown(InterfaceId(9360))));

    // Several attempts (backoff 20, 40, 80, 160 ms ...) fail meanwhile.
    thread::sleep(Duration::from_millis(400));
    if let Ok(event) = recv_non_peer_event(&rx, Duration::from_millis(10)) {
        panic!("unexpected event while the server is down: {:?}", event);
    }

    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let (_server_stream, _) = listener.accept().unwrap();
    let event = recv_non_peer_event(&rx, Duration::from_secs(5)).unwrap();
    assert!(
        matches!(event, Event::InterfaceUp(InterfaceId(9360), Some(_), _)),
        "expected reconnect InterfaceUp, got {:?}",
        event
    );
}

#[test]
fn configured_client_with_unreachable_target_retries_until_it_connects() {
    // Upstream leaves a BackboneClientInterface whose target cannot be
    // reached unconnected, and tries again every RECONNECT_WAIT, forever.
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let mut config = make_client_config(port, 9380);
    config.reconnect_wait = Duration::from_millis(100);
    config.max_reconnect_tries = None;
    config.runtime = Arc::new(Mutex::new(BackboneClientRuntime::from_config(&config)));
    let control = ListenerControl::new();
    let mut writer = start_retrying_client(config, tx, 0, None, control.clone()).unwrap();
    assert_eq!(
        writer.send_frame(b"x").unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );

    // Many attempts fail meanwhile, and nothing is reported.
    thread::sleep(Duration::from_millis(1000));
    if let Ok(event) = recv_non_peer_event(&rx, Duration::from_millis(10)) {
        panic!("unexpected event while the target is down: {:?}", event);
    }

    // The target appears: the next attempt, at most one wait later,
    // brings the client up with its writer.
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let appeared = Instant::now();
    let (mut server, _) = listener.accept().unwrap();
    assert!(appeared.elapsed() < Duration::from_millis(500));
    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    let Event::InterfaceUp(InterfaceId(9380), Some(mut writer), None) = event else {
        panic!("expected the client's InterfaceUp, got {:?}", event);
    };
    writer.send_frame(b"hello").unwrap();
    let mut sent = vec![0u8; hdlc::frame(b"hello").len()];
    server.read_exact(&mut sent).unwrap();
    assert_eq!(sent, hdlc::frame(b"hello"));
    control.request_stop();
}

#[test]
fn steady_retry_waits_the_same_before_every_attempt() {
    let base = Duration::from_secs(5);
    for attempt in 0..10 {
        assert_eq!(Retry::Steady.wait(base, attempt), base);
    }
    assert!(Retry::Backoff.wait(base, 3) > base);
}

#[test]
fn backbone_client_without_reconnect_tries_leaves_reconnecting_to_owner() {
    let port = find_free_port();
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let (tx, rx) = crate::event::channel();

    let mut config = make_client_config(port, 9370);
    config.reconnect_wait = Duration::from_millis(20);
    config.max_reconnect_tries = Some(0);
    config.runtime = Arc::new(Mutex::new(BackboneClientRuntime::from_config(&config)));
    let _writer = start_client(config, tx).unwrap();

    let (server_stream, _) = listener.accept().unwrap();
    let _ = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();
    drop(server_stream);

    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    assert!(matches!(event, Event::InterfaceDown(InterfaceId(9370))));
    // No reconnect attempt and no second, late InterfaceDown that could
    // tear down a connection the owner has since re-established.
    listener.set_nonblocking(true).unwrap();
    if let Ok(event) = recv_non_peer_event(&rx, Duration::from_millis(300)) {
        panic!("unexpected event after the connection closed: {:?}", event);
    }
    assert!(listener.accept().is_err());
}

#[test]
fn backbone_client_stop_prevents_reconnect() {
    let port = find_free_port();
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let (tx, rx) = crate::event::channel();

    let config = make_client_config(port, 9350);
    let control = ListenerControl::new();
    let _writer = start_client_with_ifac(config, tx, 0, None, control.clone()).unwrap();

    let (server_stream, _) = listener.accept().unwrap();
    // Drain the initial InterfaceUp from the successful connect.
    let _ = recv_non_peer_event(&rx, Duration::from_secs(1)).unwrap();

    control.request_stop();
    drop(server_stream);

    // A detached client must not emit InterfaceDown or reconnect.
    if let Ok(event) = recv_non_peer_event(&rx, Duration::from_millis(700)) {
        panic!("unexpected event after stop: {:?}", event);
    }
}

#[test]
fn backbone_idle_timeout_disconnects_silent_client() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(9400));

    let config = make_server_config(
        port,
        94,
        None,
        Some(Duration::from_millis(150)),
        None,
        BackboneAbuseConfig::default(),
    );

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));

    let _client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    let client_id = match event {
        Event::InterfaceUp(id, _, _) => id,
        other => panic!("expected InterfaceUp, got {:?}", other),
    };

    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    assert!(matches!(event, Event::InterfaceDown(id) if id == client_id));
}

#[test]
fn backbone_idle_timeout_ignores_client_after_data() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(9500));

    let config = make_server_config(
        port,
        95,
        None,
        Some(Duration::from_millis(200)),
        None,
        BackboneAbuseConfig::default(),
    );

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));

    let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    let client_id = match event {
        Event::InterfaceUp(id, _, _) => id,
        other => panic!("expected InterfaceUp, got {:?}", other),
    };

    client.write_all(&hdlc::frame(&[1u8; 24])).unwrap();

    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    match event {
        Event::Frame {
            interface_id,
            data,
            rssi: _,
            snr: _,
        } => {
            assert_eq!(interface_id, client_id);
            assert_eq!(data, vec![1u8; 24].into());
        }
        other => panic!("expected Frame, got {:?}", other),
    }

    let result = recv_non_peer_event(&rx, Duration::from_millis(500));
    assert!(
        result.is_err(),
        "expected no InterfaceDown after client sent data, got {:?}",
        result
    );
}

#[test]
fn backbone_runtime_idle_timeout_updates_live() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(9650));

    let config = make_server_config(port, 97, None, None, None, BackboneAbuseConfig::default());
    let runtime = Arc::clone(&config.runtime);

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));

    let _client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    let client_id = match event {
        Event::InterfaceUp(id, _, _) => id,
        other => panic!("expected InterfaceUp, got {:?}", other),
    };

    {
        let mut runtime = runtime.lock().unwrap();
        runtime.idle_timeout = Some(Duration::from_millis(150));
    }

    let event = recv_non_peer_event(&rx, Duration::from_secs(4)).unwrap();
    assert!(matches!(event, Event::InterfaceDown(id) if id == client_id));
}

#[test]
fn backbone_write_stall_timeout_disconnects_unwritable_client() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(9660));

    let config = make_server_config(
        port,
        98,
        None,
        None,
        Some(Duration::from_millis(50)),
        BackboneAbuseConfig::default(),
    );

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));

    let client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let sock = SockRef::from(&client);
    sock.set_recv_buffer_size(4096).ok();

    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    let (client_id, mut writer) = match event {
        Event::InterfaceUp(id, Some(writer), _) => (id, writer),
        other => panic!("expected InterfaceUp with writer, got {:?}", other),
    };

    let payload = vec![0x55; 512 * 1024];
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut stalled = false;
    while Instant::now() < deadline {
        match writer.send_frame(&payload) {
            Ok(()) => {}
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
                stalled = true;
                break;
            }
            Err(e) => panic!("unexpected send error: {}", e),
        }
    }

    assert!(stalled, "expected writer to time out on persistent stall");
    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    assert!(matches!(event, Event::InterfaceDown(id) if id == client_id));
}

#[test]
fn shutting_down_backbone_writer_closes_the_client_socket() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(9670));
    let config = make_server_config(port, 99, None, None, None, BackboneAbuseConfig::default());

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));

    let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    let mut writer = match event {
        Event::InterfaceUp(_, Some(writer), _) => writer,
        other => panic!("expected InterfaceUp with writer, got {:?}", other),
    };

    writer.shutdown();

    let mut byte = [0u8; 1];
    assert_eq!(client.read(&mut byte).unwrap(), 0);
}

/// Drain events matching a predicate, return the first match.
fn wait_for<F>(rx: &crate::event::EventReceiver, timeout: Duration, mut pred: F) -> Option<Event>
where
    F: FnMut(&Event) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match rx.recv_timeout(remaining) {
            Ok(event) if pred(&event) => return Some(event),
            Ok(_) => continue,
            Err(_) => return None,
        }
    }
}

#[test]
fn backbone_write_stall_emits_peer_events() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(9700));

    let config = make_server_config(
        port,
        97,
        None,
        None,
        Some(Duration::from_millis(50)), // 50ms stall timeout
        BackboneAbuseConfig::default(),
    );

    start(config, tx, next_id).unwrap();
    thread::sleep(Duration::from_millis(50));

    // Connect a client that won't read (will cause write stall)
    let client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let sock = SockRef::from(&client);
    sock.set_recv_buffer_size(4096).ok();

    // Wait for InterfaceUp and grab writer
    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    let mut writer = match event {
        Event::InterfaceUp(_, Some(w), _) => w,
        other => panic!("expected InterfaceUp with writer, got {:?}", other),
    };

    // Flood until stall
    let payload = vec![0x55; 512 * 1024];
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        match writer.send_frame(&payload) {
            Ok(()) | Err(_) => {
                if Instant::now() + Duration::from_millis(10) > deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    // Should see BackbonePeerWriteStall event
    let stall_event = wait_for(&rx, Duration::from_secs(3), |e| {
        matches!(e, Event::BackbonePeerWriteStall { .. })
    });
    assert!(
        stall_event.is_some(),
        "expected BackbonePeerWriteStall event"
    );
}

#[test]
fn backbone_blacklisted_peer_rejected_on_connect() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(9800));

    let config = make_server_config(port, 98, None, None, None, BackboneAbuseConfig::default());
    let peer_state = config.peer_state.clone();

    start(config, tx.clone(), next_id).unwrap();
    thread::sleep(Duration::from_millis(50));

    // First connection should succeed
    let client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    let event = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
    assert!(
        matches!(event, Event::InterfaceUp(_, _, _)),
        "first connection should succeed"
    );
    drop(client1);

    // Drain disconnect events
    thread::sleep(Duration::from_millis(100));
    while rx.try_recv().is_ok() {}

    // Blacklist 127.0.0.1 via the peer monitor
    peer_state.lock().unwrap().blacklist(
        "127.0.0.1".parse().unwrap(),
        Duration::from_secs(60),
        "test blacklist".into(),
    );

    // Second connection from same IP should be rejected (no InterfaceUp)
    let _client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    // Give poll loop time to reject
    thread::sleep(Duration::from_millis(200));

    // Should NOT get an InterfaceUp — connection should have been rejected
    let event = rx.try_recv();
    if let Ok(Event::InterfaceUp(_, _, _)) = event {
        panic!("blacklisted peer should not get InterfaceUp")
    }
}

#[test]
fn backbone_six_fast_flaps_reject_before_allocating_seventh_interface() {
    let port = find_free_port();
    let (tx, rx) = crate::event::channel();
    let next_id = Arc::new(AtomicU64::new(9900));
    let mut config = make_server_config(port, 99, None, None, None, BackboneAbuseConfig::default());
    config.fast_flap = test_fast_flap_config();
    let fast_flap_state = Arc::clone(&config.fast_flap_state);
    let peer_state = Arc::clone(&config.peer_state);

    start(config, tx, Arc::clone(&next_id)).unwrap();
    thread::sleep(Duration::from_millis(50));

    for flap in 0..6 {
        let mut client = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        let up = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        assert!(matches!(up, Event::InterfaceUp(_, _, _)));

        // Receiving traffic must not exempt a short-lived connection.
        if flap == 0 {
            let payload = vec![0x41; 32];
            client.write_all(&hdlc::frame(&payload)).unwrap();
            let frame = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
            assert!(matches!(frame, Event::Frame { data, .. } if data == payload.into()));
        }

        drop(client);
        let down = recv_non_peer_event(&rx, Duration::from_secs(2)).unwrap();
        assert!(matches!(down, Event::InterfaceDown(_)));
    }

    let peer_ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(
        lock_or_recover(&fast_flap_state, "test fast-flap state").is_blocked(
            peer_ip,
            &test_fast_flap_config(),
            Instant::now(),
        )
    );
    assert_eq!(next_id.load(Ordering::Relaxed), 9906);
    let entries = lock_or_recover(&peer_state, "test peer state").list("test-backbone");
    let entry = entries
        .iter()
        .find(|entry| entry.peer_ip == peer_ip)
        .expect("fast-flapping peer state");
    assert_eq!(entry.blacklist_reason.as_deref(), Some("fast flapping"));
    assert!(entry.blacklisted_remaining_secs.is_some());

    let _rejected = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    serve_for(&rx, Duration::from_millis(200));
    assert_eq!(
        next_id.load(Ordering::Relaxed),
        9906,
        "rejection must happen before dynamic interface allocation"
    );
    while let Ok(event) = rx.try_recv() {
        assert!(
            !matches!(event, Event::InterfaceUp(_, _, _)),
            "blocked peer must not register a dynamic interface"
        );
    }
    let entries = lock_or_recover(&peer_state, "test peer state").list("test-backbone");
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry.peer_ip == peer_ip)
            .unwrap()
            .reject_count,
        1
    );
}

#[test]
fn backbone_listen_on_replaces_listen_ip() {
    let factory = BackboneInterfaceFactory;
    let listen_ip = |pairs: &[(&str, &str)]| {
        let params: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let config = factory
            .parse_config("test-backbone", InterfaceId(96), &params)
            .unwrap();
        match *config.into_any().downcast::<BackboneMode>().unwrap() {
            BackboneMode::Server(config) => config.listen_ip,
            BackboneMode::Client(_, _) => panic!("expected server config"),
        }
    };
    assert_eq!(listen_ip(&[("listen_on", "10.0.0.1")]), "10.0.0.1");
    assert_eq!(
        listen_ip(&[("listen_on", "10.0.0.1"), ("listen_ip", "10.0.0.2")]),
        "10.0.0.1"
    );
    assert_eq!(listen_ip(&[("listen_ip", "10.0.0.2")]), "10.0.0.2");
}

#[test]
fn backbone_parse_config_reads_abuse_settings() {
    let factory = BackboneInterfaceFactory;
    let mut params = HashMap::new();
    params.insert("listen_ip".into(), "127.0.0.1".into());
    params.insert("listen_port".into(), "4242".into());
    params.insert("idle_timeout".into(), "15".into());
    params.insert("write_stall_timeout".into(), "45".into());
    params.insert("max_penalty_duration".into(), "3600".into());

    let config = factory
        .parse_config("test-backbone", InterfaceId(97), &params)
        .unwrap();
    let mode = *config.into_any().downcast::<BackboneMode>().unwrap();

    match mode {
        BackboneMode::Server(config) => {
            assert_eq!(config.listen_ip, "127.0.0.1");
            assert_eq!(config.listen_port, 4242);
            assert_eq!(config.idle_timeout, Some(Duration::from_secs(15)));
            assert_eq!(config.write_stall_timeout, Some(Duration::from_secs(45)));
            assert_eq!(
                config.abuse.max_penalty_duration,
                Some(Duration::from_secs(3600))
            );
        }
        BackboneMode::Client(_, _) => panic!("expected server config"),
    }
}

#[test]
fn backbone_parse_config_reads_fast_flapping_settings() {
    let factory = BackboneInterfaceFactory;
    let mut params = HashMap::new();
    params.insert("listen_ip".into(), "127.0.0.1".into());
    params.insert("listen_port".into(), "4242".into());
    params.insert("block_fast_flapping".into(), "no".into());
    params.insert("fast_flapping_threshold".into(), "2.5".into());
    params.insert("fast_flapping_grace".into(), "9".into());
    params.insert("fast_flapping_block_time".into(), "1.5".into());

    let config = factory
        .parse_config("test-backbone", InterfaceId(93), &params)
        .unwrap();
    let mode = *config.into_any().downcast::<BackboneMode>().unwrap();
    let BackboneMode::Server(config) = mode else {
        panic!("expected server config");
    };

    assert!(!config.fast_flap.enabled);
    assert_eq!(
        config.fast_flap.connection_threshold,
        Duration::from_secs_f64(2.5)
    );
    assert_eq!(config.fast_flap.grace, 9);
    assert_eq!(config.fast_flap.block_duration, Duration::from_secs(90));
}

#[test]
fn backbone_parse_config_rejects_invalid_fast_flapping_settings() {
    let factory = BackboneInterfaceFactory;
    for (key, value) in [
        ("block_fast_flapping", "perhaps"),
        ("fast_flapping_threshold", "-1"),
        ("fast_flapping_threshold", "NaN"),
        ("fast_flapping_grace", "-1"),
        ("fast_flapping_block_time", "infinite"),
    ] {
        let mut params = HashMap::new();
        params.insert("listen_port".into(), "4242".into());
        params.insert(key.into(), value.into());

        let err = match factory.parse_config("test-backbone", InterfaceId(92), &params) {
            Ok(_) => panic!("{key}={value} should be rejected"),
            Err(err) => err,
        };
        assert!(err.contains(key), "unexpected error: {err}");
    }
}

#[test]
fn parsed_backbone_listeners_share_fast_flap_history() {
    let factory = BackboneInterfaceFactory;
    let mut params = HashMap::new();
    params.insert("listen_port".into(), "4242".into());

    let first = factory
        .parse_config("first", InterfaceId(90), &params)
        .unwrap();
    let second = factory
        .parse_config("second", InterfaceId(91), &params)
        .unwrap();
    let BackboneMode::Server(first) = *first.into_any().downcast::<BackboneMode>().unwrap() else {
        panic!("expected server config");
    };
    let BackboneMode::Server(second) = *second.into_any().downcast::<BackboneMode>().unwrap()
    else {
        panic!("expected server config");
    };

    assert!(Arc::ptr_eq(&first.fast_flap_state, &second.fast_flap_state));
}

#[test]
fn backbone_parse_config_reads_client_priority() {
    let factory = BackboneInterfaceFactory;
    let mut params = HashMap::new();
    params.insert("remote".into(), "example.com".into());
    params.insert("target_port".into(), "4242".into());
    params.insert("priority".into(), "87".into());

    let config = factory
        .parse_config("test-backbone-client", InterfaceId(96), &params)
        .unwrap();
    let mode = *config.into_any().downcast::<BackboneMode>().unwrap();

    match mode {
        BackboneMode::Client(_, priority) => assert_eq!(priority, 87),
        BackboneMode::Server(_) => panic!("expected client config"),
    }
}

#[test]
fn backbone_parse_config_reads_client_max_reconnect_tries() {
    let parse = |value: Option<&str>| {
        let mut params = HashMap::new();
        params.insert("remote".into(), "127.0.0.1".into());
        if let Some(value) = value {
            params.insert("max_reconnect_tries".into(), value.into());
        }
        BackboneInterfaceFactory
            .parse_config("peer", InterfaceId(1), &params)
            .map(|config| {
                let mode = config.into_any().downcast::<BackboneMode>().unwrap();
                match *mode {
                    BackboneMode::Client(client, _) => client,
                    BackboneMode::Server(_) => panic!("expected client mode"),
                }
            })
    };

    let client = parse(None).unwrap();
    assert_eq!(client.max_reconnect_tries, None);
    assert_eq!(client.runtime.lock().unwrap().max_reconnect_tries, None);

    let client = parse(Some("7")).unwrap();
    assert_eq!(client.max_reconnect_tries, Some(7));
    assert_eq!(client.runtime.lock().unwrap().max_reconnect_tries, Some(7));

    assert!(parse(Some("-1")).is_err());
    assert!(parse(Some("forever")).is_err());
}

#[test]
fn backbone_parse_config_defaults_client_priority() {
    let factory = BackboneInterfaceFactory;
    let mut params = HashMap::new();
    params.insert("remote".into(), "example.com".into());

    let config = factory
        .parse_config("test-backbone-client", InterfaceId(95), &params)
        .unwrap();
    let mode = *config.into_any().downcast::<BackboneMode>().unwrap();

    match mode {
        BackboneMode::Client(_, priority) => assert_eq!(priority, 60),
        BackboneMode::Server(_) => panic!("expected client config"),
    }
}

#[test]
fn backbone_parse_config_rejects_invalid_client_priority() {
    let factory = BackboneInterfaceFactory;
    for value in ["-1", "101", "fast"] {
        let mut params = HashMap::new();
        params.insert("remote".into(), "example.com".into());
        params.insert("priority".into(), value.into());

        let err = match factory.parse_config("test-backbone-client", InterfaceId(94), &params) {
            Ok(_) => panic!("priority {value} should be rejected"),
            Err(err) => err,
        };
        assert!(
            err.contains("priority"),
            "unexpected error for {value}: {err}"
        );
    }
}

#[test]
fn positive_duration_param_rejects_values_that_are_not_durations() {
    for raw in ["inf", "-inf", "NaN", "1e300", "-1", "0"] {
        let params = HashMap::from([("idle_timeout".to_string(), raw.to_string())]);
        assert_eq!(
            parse_positive_duration_secs(&params, "idle_timeout"),
            None,
            "value {raw} should be ignored"
        );
    }
    let params = HashMap::from([("idle_timeout".to_string(), "2.5".to_string())]);
    assert_eq!(
        parse_positive_duration_secs(&params, "idle_timeout"),
        Some(Duration::from_millis(2500))
    );
}

#[test]
fn backbone_client_wants_a_tunnel() {
    // Upstream's BackboneClientInterface synthesizes a tunnel on each
    // connect; accepted peers do not.
    let port = find_free_port();
    let _listener = std::net::TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
    let (tx, _rx) = crate::event::channel();
    let mut params = HashMap::new();
    params.insert("remote".into(), "127.0.0.1".into());
    params.insert("target_port".into(), port.to_string());
    let config = BackboneInterfaceFactory
        .parse_config("backbone-dialer", InterfaceId(78), &params)
        .unwrap();
    let result = BackboneInterfaceFactory
        .start(config, crate::interface::test_start_context(tx))
        .unwrap();
    let StartResult::Simple { info, control, .. } = result else {
        panic!("expected a simple interface");
    };
    assert!(info.wants_tunnel);
    if let Some(control) = control {
        control.request_stop();
    }
}

#[test]
fn configured_backbone_clients_are_backbone_client_interfaces() {
    // Upstream starts a BackboneClientInterface both for a
    // BackboneClientInterface section and for a BackboneInterface one
    // with a target host, and statistics report that class.
    let port = find_free_port();
    let _listener = std::net::TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
    let factories: [&dyn InterfaceFactory; 2] =
        [&BackboneInterfaceFactory, &BackboneClientInterfaceFactory];
    for (n, factory) in factories.into_iter().enumerate() {
        let (tx, _rx) = crate::event::channel();
        let mut params = HashMap::new();
        params.insert("target_host".into(), "127.0.0.1".into());
        params.insert("target_port".into(), port.to_string());
        let config = factory
            .parse_config("client", InterfaceId(80 + n as u64), &params)
            .unwrap();
        let result = factory
            .start(config, crate::interface::test_start_context(tx))
            .unwrap();
        let StartResult::Simple {
            interface_type_name,
            info,
            control,
            ..
        } = result
        else {
            panic!("expected a simple interface");
        };
        assert_eq!(interface_type_name, "BackboneClientInterface");
        // Upstream's BITRATE_GUESS, an int.
        assert_eq!(info.bitrate, Some(100_000_000));
        if let Some(control) = control {
            control.request_stop();
        }
    }
}
