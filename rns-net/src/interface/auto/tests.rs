use super::*;

#[test]
fn listener_control_stops_auto_supervisor() {
    let running = Arc::new(AtomicBool::new(true));
    let control = super::super::ListenerControl::with_running_flag(Arc::clone(&running));

    control.request_stop();

    assert!(!running.load(Ordering::Relaxed));
    assert!(control.should_stop());
}

// ── Multicast address derivation ──────────────────────────────────

#[test]
fn multicast_address_default_group() {
    // Python vector: ff12:0:d70b:fb1c:16e4:5e39:485e:31e1
    let addr = derive_multicast_address(
        DEFAULT_GROUP_ID,
        MULTICAST_TEMPORARY_ADDRESS_TYPE,
        SCOPE_LINK,
    );
    assert_eq!(addr, "ff12:0:d70b:fb1c:16e4:5e39:485e:31e1");
}

#[test]
fn multicast_address_custom_group() {
    let addr = derive_multicast_address(b"testgroup", MULTICAST_TEMPORARY_ADDRESS_TYPE, SCOPE_LINK);
    // Just verify format
    assert!(addr.starts_with("ff12:0:"));
    // Must be different from default
    assert_ne!(addr, "ff12:0:d70b:fb1c:16e4:5e39:485e:31e1");
}

#[test]
fn multicast_address_scope_admin() {
    let addr = derive_multicast_address(
        DEFAULT_GROUP_ID,
        MULTICAST_TEMPORARY_ADDRESS_TYPE,
        SCOPE_ADMIN,
    );
    assert!(addr.starts_with("ff14:0:"));
}

#[test]
fn multicast_address_permanent_type() {
    let addr = derive_multicast_address(
        DEFAULT_GROUP_ID,
        MULTICAST_PERMANENT_ADDRESS_TYPE,
        SCOPE_LINK,
    );
    assert!(addr.starts_with("ff02:0:"));
}

#[test]
fn multicast_address_parseable() {
    let addr = derive_multicast_address(
        DEFAULT_GROUP_ID,
        MULTICAST_TEMPORARY_ADDRESS_TYPE,
        SCOPE_LINK,
    );
    let ip = parse_multicast_addr(&addr);
    assert!(ip.is_some());
    assert!(ip.unwrap().is_multicast());
}

// ── Discovery token ──────────────────────────────────────────────

#[test]
fn discovery_token_interop() {
    // Python vector: fe80::1 → 97b25576749ea936b0d8a8536ffaf442d157cf47d460dcf13c48b7bd18b6c163
    let token = compute_discovery_token(DEFAULT_GROUP_ID, "fe80::1");
    let expected = "97b25576749ea936b0d8a8536ffaf442d157cf47d460dcf13c48b7bd18b6c163";
    let got = token
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    assert_eq!(got, expected);
}

#[test]
fn discovery_token_interop_2() {
    // Python vector: fe80::dead:beef:1234:5678
    let token = compute_discovery_token(DEFAULT_GROUP_ID, "fe80::dead:beef:1234:5678");
    let expected = "46b6ec7595504b6a35f06bd4bfff71567fb82fcf2706cd361bab20409c42d072";
    let got = token
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    assert_eq!(got, expected);
}

#[test]
fn discovery_token_different_groups() {
    let t1 = compute_discovery_token(b"reticulum", "fe80::1");
    let t2 = compute_discovery_token(b"othergroup", "fe80::1");
    assert_ne!(t1, t2);
}

#[test]
fn discovery_token_different_addrs() {
    let t1 = compute_discovery_token(DEFAULT_GROUP_ID, "fe80::1");
    let t2 = compute_discovery_token(DEFAULT_GROUP_ID, "fe80::2");
    assert_ne!(t1, t2);
}

// ── Deduplication ────────────────────────────────────────────────

#[test]
fn dedup_basic() {
    let next_id = Arc::new(AtomicU64::new(1));
    let mut state = SharedState::new(next_id);

    let hash = [0xAA; 32];
    let now = 1000.0;

    assert!(!state.is_duplicate(&hash, now));
    state.add_dedup(hash, now);
    assert!(state.is_duplicate(&hash, now));
}

#[test]
fn dedup_expired() {
    let next_id = Arc::new(AtomicU64::new(1));
    let mut state = SharedState::new(next_id);

    let hash = [0xBB; 32];
    state.add_dedup(hash, 1000.0);

    // Within TTL
    assert!(state.is_duplicate(&hash, 1000.5));
    // Expired
    assert!(!state.is_duplicate(&hash, 1001.0));
}

#[test]
fn dedup_max_length() {
    let next_id = Arc::new(AtomicU64::new(1));
    let mut state = SharedState::new(next_id);

    // Fill beyond max
    for i in 0..MULTI_IF_DEQUE_LEN + 10 {
        let mut hash = [0u8; 32];
        hash[0] = (i & 0xFF) as u8;
        hash[1] = ((i >> 8) & 0xFF) as u8;
        state.add_dedup(hash, 1000.0);
    }

    assert_eq!(state.dedup_deque.len(), MULTI_IF_DEQUE_LEN);
}

// ── Peer tracking ────────────────────────────────────────────────

#[test]
fn peer_refresh() {
    let next_id = Arc::new(AtomicU64::new(100));
    let mut state = SharedState::new(next_id);
    let key = peer_key("fe80::1", 2);

    state.peers.insert(
        key.clone(),
        AutoPeer {
            interface_id: InterfaceId(100),
            link_local_addr: key.link_local_addr.clone(),
            ifname: "eth0".to_string(),
            if_index: key.if_index,
            last_heard: 1000.0,
        },
    );

    state.refresh_peer(&key, 2000.0);
    assert_eq!(state.peers[&key].last_heard, 2000.0);
}

#[test]
fn peer_not_found_refresh() {
    let next_id = Arc::new(AtomicU64::new(100));
    let mut state = SharedState::new(next_id);
    // Should not panic
    state.refresh_peer(&peer_key("fe80::999", 4), 1000.0);
}

fn peer_key(addr: &str, if_index: u32) -> PeerKey {
    PeerKey {
        link_local_addr: addr.to_string(),
        if_index,
    }
}

#[test]
fn peer_key_distinguishes_same_link_local_on_different_interfaces() {
    let next_id = Arc::new(AtomicU64::new(100));
    let mut state = SharedState::new(next_id);
    let eth = peer_key("fe80::1", 2);
    let wlan = peer_key("fe80::1", 4);

    state.peers.insert(
        eth.clone(),
        AutoPeer {
            interface_id: InterfaceId(100),
            link_local_addr: eth.link_local_addr.clone(),
            ifname: "eth0".to_string(),
            if_index: eth.if_index,
            last_heard: 1000.0,
        },
    );
    state.peers.insert(
        wlan.clone(),
        AutoPeer {
            interface_id: InterfaceId(101),
            link_local_addr: wlan.link_local_addr.clone(),
            ifname: "wlan0".to_string(),
            if_index: wlan.if_index,
            last_heard: 1000.0,
        },
    );

    assert_eq!(state.peers.len(), 2);
    assert_eq!(state.peers[&eth].interface_id, InterfaceId(100));
    assert_eq!(state.peers[&wlan].interface_id, InterfaceId(101));
}

#[test]
fn peer_target_addr_uses_scope_id() {
    let target = peer_target_addr(&peer_key("fe80::1", 7), 42671).unwrap();

    assert_eq!(target.port(), 42671);
    assert_eq!(target.scope_id(), 7);
}

#[test]
fn remove_peers_for_worker_emits_interface_down() {
    let next_id = Arc::new(AtomicU64::new(100));
    let shared = Arc::new(Mutex::new(SharedState::new(next_id)));
    let worker = worker_key("wlan0", 4, "fe80::abcd");
    let removed = peer_key("fe80::1", 4);
    let kept = peer_key("fe80::1", 5);
    let (tx, rx) = crate::event::channel_with_capacity(4);

    {
        let mut state = lock_or_recover(&shared, "test auto shared state");
        state.peers.insert(
            removed.clone(),
            AutoPeer {
                interface_id: InterfaceId(100),
                link_local_addr: removed.link_local_addr.clone(),
                ifname: "wlan0".to_string(),
                if_index: removed.if_index,
                last_heard: 1000.0,
            },
        );
        state.peers.insert(
            kept.clone(),
            AutoPeer {
                interface_id: InterfaceId(101),
                link_local_addr: kept.link_local_addr.clone(),
                ifname: "wlan1".to_string(),
                if_index: kept.if_index,
                last_heard: 1000.0,
            },
        );
    }

    remove_peers_for_worker(&shared, &tx, &worker);

    let state = lock_or_recover(&shared, "test auto shared state");
    assert!(!state.peers.contains_key(&removed));
    assert!(state.peers.contains_key(&kept));
    drop(state);

    assert!(matches!(
        rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap(),
        Event::InterfaceDown(InterfaceId(100))
    ));
    assert!(rx.try_recv().is_err());
}

// ── Network interface enumeration ────────────────────────────────

#[test]
fn enumerate_returns_vec() {
    // This test just verifies the function runs without crashing.
    // Results depend on the system's network configuration.
    let interfaces = enumerate_interfaces(&[], &[]);
    // On CI/test machines, we may or may not have IPv6 link-local
    for iface in &interfaces {
        assert!(!iface.name.is_empty());
        assert!(iface.link_local_addr.starts_with("fe80"));
        assert!(iface.index > 0);
    }
}

#[test]
fn enumerate_with_ignored() {
    // Ignore everything
    let interfaces = enumerate_interfaces(
        &[],
        &[
            "lo".to_string(),
            "eth0".to_string(),
            "wlan0".to_string(),
            "enp0s3".to_string(),
            "docker0".to_string(),
        ],
    );
    // May still have some interfaces, but known ones should be filtered
    for iface in &interfaces {
        assert_ne!(iface.name, "lo");
        assert_ne!(iface.name, "eth0");
        assert_ne!(iface.name, "wlan0");
    }
}

#[test]
fn enumerate_with_allowed_nonexistent() {
    // Only allow an interface that doesn't exist
    let interfaces = enumerate_interfaces(&["nonexistent_if_12345".to_string()], &[]);
    assert!(interfaces.is_empty());
}

fn worker_key(name: &str, index: u32, addr: &str) -> AutoWorkerKey {
    AutoWorkerKey {
        ifname: name.to_string(),
        if_index: index,
        link_local_addr: addr.to_string(),
    }
}

#[test]
fn reconcile_worker_keys_adds_new_interface() {
    let desired = vec![worker_key("wlan0", 4, "fe80::1")];

    assert_eq!(
        reconcile_worker_keys(Vec::new(), desired.clone()),
        vec![WorkerReconcileAction::Add(desired[0].clone())]
    );
}

#[test]
fn reconcile_worker_keys_keeps_unchanged_interface() {
    let key = worker_key("wlan0", 4, "fe80::1");

    assert!(reconcile_worker_keys(vec![key.clone()], vec![key]).is_empty());
}

#[test]
fn reconcile_worker_keys_removes_missing_interface() {
    let active = vec![worker_key("wlan0", 4, "fe80::1")];

    assert_eq!(
        reconcile_worker_keys(active.clone(), Vec::new()),
        vec![WorkerReconcileAction::Remove(active[0].clone())]
    );
}

#[test]
fn reconcile_worker_keys_replaces_changed_interface_identity() {
    let old = worker_key("wlan0", 4, "fe80::1");
    let new = worker_key("wlan0", 9, "fe80::2");
    let actions = reconcile_worker_keys(vec![old.clone()], vec![new.clone()]);

    assert!(actions.contains(&WorkerReconcileAction::Remove(old)));
    assert!(actions.contains(&WorkerReconcileAction::Add(new)));
    assert_eq!(actions.len(), 2);
}

#[test]
fn reconcile_auto_workers_starts_new_worker() {
    let key = worker_key("wlan0", 4, "fe80::1");
    let mut workers = HashMap::new();
    let mut starts = Vec::new();

    reconcile_auto_workers(&mut workers, vec![key.clone()], |key| {
        starts.push(key.clone());
        Ok(RunningAutoWorker {
            running: Arc::new(AtomicBool::new(true)),
        })
    });

    assert_eq!(starts, vec![key.clone()]);
    assert!(matches!(
        workers.get(&key),
        Some(AutoWorkerEntry::Running(_))
    ));
}

#[test]
fn reconcile_auto_workers_stops_removed_worker() {
    let key = worker_key("wlan0", 4, "fe80::1");
    let running = Arc::new(AtomicBool::new(true));
    let mut workers = HashMap::from([(
        key.clone(),
        AutoWorkerEntry::Running(RunningAutoWorker {
            running: running.clone(),
        }),
    )]);

    reconcile_auto_workers(&mut workers, Vec::new(), |_| unreachable!());

    assert!(!running.load(Ordering::Relaxed));
    assert!(!workers.contains_key(&key));
}

#[test]
fn reconcile_auto_workers_leaves_unchanged_worker_running() {
    let key = worker_key("wlan0", 4, "fe80::1");
    let running = Arc::new(AtomicBool::new(true));
    let mut workers = HashMap::from([(
        key.clone(),
        AutoWorkerEntry::Running(RunningAutoWorker {
            running: running.clone(),
        }),
    )]);
    let mut starts = 0;

    reconcile_auto_workers(&mut workers, vec![key.clone()], |_| {
        starts += 1;
        unreachable!()
    });

    assert_eq!(starts, 0);
    assert!(running.load(Ordering::Relaxed));
    assert!(workers.contains_key(&key));
}

#[test]
fn reconcile_auto_workers_records_pending_start_failure() {
    let key = worker_key("wlan0", 4, "fe80::1");
    let mut workers = HashMap::new();

    reconcile_auto_workers(&mut workers, vec![key.clone()], |_| {
        Err(io::Error::new(io::ErrorKind::AddrInUse, "busy"))
    });

    assert!(matches!(workers.get(&key), Some(AutoWorkerEntry::Pending)));
}

#[test]
fn reconcile_auto_workers_retries_pending_worker() {
    let key = worker_key("wlan0", 4, "fe80::1");
    let running = Arc::new(AtomicBool::new(true));
    let mut workers = HashMap::from([(key.clone(), AutoWorkerEntry::Pending)]);
    let mut starts = 0;

    reconcile_auto_workers(&mut workers, vec![key.clone()], |_| {
        starts += 1;
        Ok(RunningAutoWorker {
            running: running.clone(),
        })
    });

    assert_eq!(starts, 1);
    assert!(matches!(
        workers.get(&key),
        Some(AutoWorkerEntry::Running(_))
    ));
}

#[test]
fn reconcile_auto_workers_keeps_pending_worker_on_retry_failure() {
    let key = worker_key("wlan0", 4, "fe80::1");
    let mut workers = HashMap::from([(key.clone(), AutoWorkerEntry::Pending)]);
    let mut starts = 0;

    reconcile_auto_workers(&mut workers, vec![key.clone()], |_| {
        starts += 1;
        Err(io::Error::new(io::ErrorKind::AddrInUse, "busy"))
    });

    assert_eq!(starts, 1);
    assert!(matches!(workers.get(&key), Some(AutoWorkerEntry::Pending)));
}

#[test]
fn reconcile_auto_workers_removes_pending_worker() {
    let key = worker_key("wlan0", 4, "fe80::1");
    let mut workers = HashMap::from([(key.clone(), AutoWorkerEntry::Pending)]);

    reconcile_auto_workers(&mut workers, Vec::new(), |_| unreachable!());

    assert!(!workers.contains_key(&key));
}

#[test]
fn filter_skips_android_system_interfaces() {
    let allowed = Vec::new();
    let ignored = Vec::new();

    for name in ["dummy0", "lo", "tun0", "rmnet0", "rmnet7"] {
        assert!(
            !should_adopt_interface_name(name, &allowed, &ignored, ANDROID_IGNORE_IFS),
            "{name} should be skipped by Android AutoInterface defaults"
        );
    }
}

#[test]
fn filter_does_not_skip_rmnet8_by_android_defaults() {
    assert!(should_adopt_interface_name(
        "rmnet8",
        &[],
        &[],
        ANDROID_IGNORE_IFS
    ));
}

#[test]
fn filter_allowed_overrides_system_ignored_interface() {
    assert!(should_adopt_interface_name(
        "rmnet0",
        &["rmnet0".to_string()],
        &[],
        ANDROID_IGNORE_IFS
    ));

    assert!(should_adopt_interface_name(
        "lo0",
        &["lo0".to_string()],
        &[],
        &[]
    ));
}

#[test]
fn filter_ignored_wins_over_allowed_interface() {
    assert!(!should_adopt_interface_name(
        "rmnet0",
        &["rmnet0".to_string()],
        &["rmnet0".to_string()],
        ANDROID_IGNORE_IFS
    ));
}

#[test]
fn filter_allowed_list_excludes_unlisted_interfaces() {
    assert!(!should_adopt_interface_name(
        "wlan0",
        &["eth0".to_string()],
        &[],
        ANDROID_IGNORE_IFS
    ));

    assert!(should_adopt_interface_name(
        "wlan0",
        &["wlan0".to_string()],
        &[],
        ANDROID_IGNORE_IFS
    ));
}

// ── Config defaults ──────────────────────────────────────────────

#[test]
fn config_defaults() {
    let config = AutoConfig::default();
    assert_eq!(config.group_id, DEFAULT_GROUP_ID);
    assert_eq!(config.discovery_scope, SCOPE_LINK);
    assert_eq!(config.discovery_port, DEFAULT_DISCOVERY_PORT);
    assert_eq!(config.data_port, DEFAULT_DATA_PORT);
    assert_eq!(
        config.multicast_address_type,
        MULTICAST_TEMPORARY_ADDRESS_TYPE
    );
    assert_eq!(config.configured_bitrate, BITRATE_GUESS);
    assert!(config.allowed_interfaces.is_empty());
    assert!(config.ignored_interfaces.is_empty());
    assert_eq!(config.max_peers, DEFAULT_MAX_PEERS);
}

fn parse_auto_config(params: &[(&str, &str)]) -> AutoConfig {
    let params = params
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect::<HashMap<_, _>>();
    let config = AutoFactory
        .parse_config("auto", InterfaceId(1), &params)
        .unwrap();
    *config.into_any().downcast::<AutoConfig>().unwrap()
}

#[test]
fn parse_config_reads_max_peers() {
    assert_eq!(parse_auto_config(&[]).max_peers, DEFAULT_MAX_PEERS);
    assert_eq!(parse_auto_config(&[("max_peers", "16")]).max_peers, 16);
    assert_eq!(
        parse_auto_config(&[("max_peers", "0")]).max_peers,
        DEFAULT_MAX_PEERS
    );
    assert_eq!(
        parse_auto_config(&[("max_peers", "many")]).max_peers,
        DEFAULT_MAX_PEERS
    );
}

// ── Peer admission ───────────────────────────────────────────────

fn insert_peer(state: &mut SharedState, addr: &str, ifname: &str, last_heard: f64) {
    let key = peer_key(addr, 2);
    let id = InterfaceId(state.next_id.fetch_add(1, Ordering::Relaxed));
    state.peers.insert(
        key.clone(),
        AutoPeer {
            interface_id: id,
            link_local_addr: key.link_local_addr.clone(),
            ifname: ifname.to_string(),
            if_index: key.if_index,
            last_heard,
        },
    );
}

#[test]
fn peer_cap_refuses_peer_beyond_limit_and_admits_after_timeout() {
    let mut state = SharedState::new(Arc::new(AtomicU64::new(100)));
    state.max_peers = 3;
    let now = Instant::now();

    for (i, addr) in ["fe80::1", "fe80::2", "fe80::3"].iter().enumerate() {
        assert_eq!(
            state.admit_new_peer("eth0", now),
            PeerAdmissionDecision::Admit
        );
        insert_peer(&mut state, addr, "eth0", 1000.0 + i as f64);
    }
    assert_eq!(
        state.admit_new_peer("eth0", now),
        PeerAdmissionDecision::AtCapacity
    );
    // Another adopted interface has its own cap.
    assert_eq!(
        state.admit_new_peer("wlan0", now),
        PeerAdmissionDecision::Admit
    );

    // fe80::1 was last heard at 1000.0 and times out first.
    let removed = state.remove_timed_out_peers(1000.0 + PEERING_TIMEOUT + 0.5, PEERING_TIMEOUT);
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].0, peer_key("fe80::1", 2));
    assert_eq!(state.active_peers_on("eth0"), 2);

    assert_eq!(
        state.admit_new_peer("eth0", now),
        PeerAdmissionDecision::Admit
    );
}

#[test]
fn peer_admission_rate_limit_refuses_within_window_and_admits_after() {
    let mut admission = PeerAdmission::default();
    let start = Instant::now();

    for _ in 0..MAX_NEW_PEERS_PER_WINDOW {
        assert_eq!(
            admission.decide(0, usize::MAX, start),
            PeerAdmissionDecision::Admit
        );
    }
    assert_eq!(
        admission.decide(0, usize::MAX, start),
        PeerAdmissionDecision::RateLimited
    );
    let almost = start + PEER_ADMISSION_WINDOW - Duration::from_millis(1);
    assert_eq!(
        admission.decide(0, usize::MAX, almost),
        PeerAdmissionDecision::RateLimited
    );

    let next_window = start + PEER_ADMISSION_WINDOW;
    assert_eq!(
        admission.decide(0, usize::MAX, next_window),
        PeerAdmissionDecision::Admit
    );
}

#[test]
fn peer_admission_cap_takes_precedence_and_does_not_use_window() {
    let mut admission = PeerAdmission::default();
    let now = Instant::now();
    for _ in 0..MAX_NEW_PEERS_PER_WINDOW * 2 {
        assert_eq!(
            admission.decide(4, 4, now),
            PeerAdmissionDecision::AtCapacity
        );
    }
    assert_eq!(admission.decide(3, 4, now), PeerAdmissionDecision::Admit);
}

#[test]
fn peer_refusal_warnings_are_spaced_out() {
    let mut admission = PeerAdmission::default();
    let start = Instant::now();
    assert_eq!(admission.note_refusal(start), Some(1));
    assert_eq!(admission.note_refusal(start), None);
    assert_eq!(admission.note_refusal(start + Duration::from_secs(1)), None);
    assert_eq!(
        admission.note_refusal(start + PEER_REFUSAL_LOG_INTERVAL),
        Some(3)
    );
}

#[test]
fn peers_advertise_no_more_than_the_receive_buffer_takes() {
    let shared = Arc::new(Mutex::new(SharedState::new(Arc::new(AtomicU64::new(900)))));
    let runtime = Arc::new(Mutex::new(AutoRuntime::from_config(&AutoConfig::default())));
    let event = add_peer(AddPeerContext {
        shared: &shared,
        peer_key: &PeerKey {
            link_local_addr: "fe80::1".into(),
            if_index: 1,
        },
        data_port: DEFAULT_DATA_PORT,
        name: "auto-test",
        ifname: "test0",
        configured_bitrate: BITRATE_GUESS,
        ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
        runtime: &runtime,
        dynamic_template: None,
        underlay_mark: None,
        inline: false,
    });
    let Some(Event::InterfaceUp(_, Some(_), Some(info))) = event else {
        panic!("expected the new peer's InterfaceUp");
    };
    // Packets up to the MTU must fit the data receivers' buffer, or
    // link traffic above it is truncated and lost.
    assert_eq!(info.mtu as usize, HW_MTU);
}

#[test]
fn remove_peers_for_worker_resets_peer_admission() {
    let next_id = Arc::new(AtomicU64::new(100));
    let shared = Arc::new(Mutex::new(SharedState::new(next_id)));
    let now = Instant::now();
    {
        let mut state = lock_or_recover(&shared, "auto shared state");
        for _ in 0..MAX_NEW_PEERS_PER_WINDOW {
            state.admit_new_peer("eth0", now);
        }
        assert_eq!(
            state.admit_new_peer("eth0", now),
            PeerAdmissionDecision::RateLimited
        );
    }
    let (tx, _rx) = crate::event::channel();
    let key = AutoWorkerKey {
        ifname: "eth0".to_string(),
        if_index: 2,
        link_local_addr: "fe80::10".to_string(),
    };
    remove_peers_for_worker(&shared, &tx, &key);
    assert_eq!(
        lock_or_recover(&shared, "auto shared state").admit_new_peer("eth0", now),
        PeerAdmissionDecision::Admit
    );
}

// ── Constants ────────────────────────────────────────────────────

#[test]
fn constants_match_python() {
    assert_eq!(DEFAULT_DISCOVERY_PORT, 29716);
    assert_eq!(DEFAULT_DATA_PORT, 42671);
    assert_eq!(HW_MTU, 1196);
    assert_eq!(MULTI_IF_DEQUE_LEN, 48);
    assert!((MULTI_IF_DEQUE_TTL - 0.75).abs() < f64::EPSILON);
    assert!((PEERING_TIMEOUT - 22.0).abs() < f64::EPSILON);
    assert!((ANNOUNCE_INTERVAL - 1.6).abs() < f64::EPSILON);
    assert!((PEER_JOB_INTERVAL - 4.0).abs() < f64::EPSILON);
    assert!((MCAST_ECHO_TIMEOUT - 6.5).abs() < f64::EPSILON);
    assert_eq!(BITRATE_GUESS, 10_000_000);
}

#[test]
fn unicast_discovery_port() {
    // Python: unicast_discovery_port = discovery_port + 1
    let unicast_port = DEFAULT_DISCOVERY_PORT + 1;
    assert_eq!(unicast_port, 29717);
}

#[test]
fn reverse_peering_interval() {
    let interval = ANNOUNCE_INTERVAL * REVERSE_PEERING_MULTIPLIER;
    assert!((interval - 5.2).abs() < 0.01);
}
