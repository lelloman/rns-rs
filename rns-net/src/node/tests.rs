use super::*;
use crate::driver::IfacRuntimeConfig;
use crate::storage::RatchetStore;
use rns_core::stamp::StampCost;
use std::fs;
use tempfile::tempdir;

#[test]
fn local_ratchet_announcements_and_self_send() {
    let node = RnsNode::start(NodeConfig::default(), Box::new(NoopCallbacks)).unwrap();
    let identity = Identity::from_private_key(&[42; 64]);
    let dest = crate::Destination::single_in(
        "test",
        &["ratchet"],
        rns_core::types::IdentityHash(*identity.hash()),
    );
    let owner = crate::LocalRatchets::with_store(
        &dest,
        Identity::from_private_key(&[42; 64]),
        Arc::new(crate::MemoryRatchetStore::default()),
    )
    .unwrap();
    owner.enforce();
    node.attach_local_ratchets(owner.clone()).unwrap();
    node.attach_local_ratchets(owner.clone()).unwrap();
    let conflicting = crate::LocalRatchets::with_store(
        &dest,
        Identity::from_private_key(&[42; 64]),
        Arc::new(crate::MemoryRatchetStore::default()),
    )
    .unwrap();
    assert!(node.attach_local_ratchets(conflicting).is_err());
    let (packet, _) = node.build_announce(&dest, &identity, Some(b"app")).unwrap();
    assert_eq!(packet.flags.context_flag, rns_core::constants::FLAG_SET);
    let announce = rns_core::announce::AnnounceData::unpack(packet.data(), true).unwrap();
    announce.validate(&dest.hash.0).unwrap();
    assert_eq!(announce.ratchet, owner.current_public());
    assert!(node
        .build_announce(&dest, &Identity::from_private_key(&[43; 64]), None)
        .is_err());
    assert!(node
        .build_announce(&dest, &identity, Some(&vec![0; 500]))
        .is_err());
    let mut outgoing = dest.clone();
    outgoing.direction = rns_core::types::Direction::Out;
    outgoing.public_key = identity.get_public_key();
    let encrypted = node.encrypt_single_payload(&outgoing, b"self").unwrap();
    assert_eq!(owner.decrypt(&encrypted).unwrap().plaintext, b"self");
    assert!(identity.decrypt(&encrypted).is_err());
}

struct NoopCallbacks;

impl Callbacks for NoopCallbacks {}

#[test]
#[cfg(feature = "iface-udp")]
fn managed_interface_attaches_disabled_section_and_reloads_from_disk() {
    use crate::event::InterfaceManagementOperation as Operation;

    let dir = tempdir().unwrap();
    let config_file = dir.path().join("config");
    let write_config = |port| {
        fs::write(&config_file, format!("[reticulum]\nshare_instance = no\n\n[interfaces]\n  [[Managed UDP]]\n    type = UDPInterface\n    enabled = no\n    forward_ip = 127.0.0.1\n    forward_port = {port}\n"))
            .unwrap();
    };
    write_config(9);
    let node = RnsNode::from_config(Some(dir.path()), Box::new(NoopCallbacks)).unwrap();
    let manage = |operation| {
        node.query(QueryRequest::ManageInterface {
            operation,
            name: "Managed UDP".into(),
        })
        .unwrap()
    };
    assert!(matches!(
        manage(Operation::Detach),
        QueryResponse::InterfaceManagement(None)
    ));
    assert!(matches!(
        manage(Operation::Attach),
        QueryResponse::InterfaceManagement(Some(true))
    ));
    assert!(matches!(
        manage(Operation::Attach),
        QueryResponse::InterfaceManagement(Some(false))
    ));
    write_config(10);
    assert!(matches!(
        manage(Operation::Reload),
        QueryResponse::InterfaceManagement(Some(true))
    ));
    assert!(matches!(
        manage(Operation::Detach),
        QueryResponse::InterfaceManagement(Some(true))
    ));
    assert!(matches!(
        manage(Operation::Detach),
        QueryResponse::InterfaceManagement(None)
    ));
    node.shutdown();
}

/// An RNodeMultiInterface takes an id for itself and one per
/// subinterface; interfaces configured after it get ids of their own,
/// in the order they are added.
#[cfg(all(feature = "iface-rnode", feature = "iface-udp"))]
#[test]
fn interface_ids_stay_unique_after_a_multi_interface() {
    let dir = tempdir().unwrap();
    let missing = dir.path().join("missing-rnode-port");
    let sub = |name: &str, vport: u8| {
        format!(
                "    [[[{name}]]]\n      interface_enabled = yes\n      vport = {vport}\n      frequency = 868000000\n      bandwidth = 125000\n      txpower = 7\n      spreadingfactor = 8\n      codingrate = 5\n"
            )
    };
    let udp = |name: &str, port: u16| {
        format!(
                "  [[{name}]]\n    type = UDPInterface\n    enabled = yes\n    listen_ip = 127.0.0.1\n    listen_port = {port}\n    forward_ip = 127.0.0.1\n    forward_port = {port}\n"
            )
    };
    fs::write(
            dir.path().join("config"),
            format!(
                "[reticulum]\nshare_instance = no\n\n[interfaces]\n{}  [[Multi]]\n    type = RNodeMultiInterface\n    enabled = yes\n    port = {}\n{}{}{}",
                udp("Before", crate::test_support::port()),
                missing.display(),
                sub("A", 0),
                sub("B", 1),
                udp("After", crate::test_support::port()),
            ),
        )
        .unwrap();
    let node = RnsNode::from_config(Some(dir.path()), Box::new(NoopCallbacks)).unwrap();
    let QueryResponse::InterfaceStats(stats) = node.query(QueryRequest::InterfaceStats).unwrap()
    else {
        panic!("expected interface stats");
    };
    node.shutdown();
    let after_stat = stats
        .interfaces
        .iter()
        .find(|stat| stat.name == "After")
        .unwrap();
    // Not taken for a subinterface of the RNodeMultiInterface.
    assert_eq!(after_stat.parent_display_name, None);
    let ids: HashMap<String, u64> = stats
        .interfaces
        .iter()
        .map(|stat| (stat.name.clone(), stat.id))
        .collect();
    // The subinterfaces are not listed without their device; the driver
    // still knows them by their ids.
    assert_eq!(ids.len(), 3, "{ids:?}");
    let before = ids["Before"];
    let multi = ids["Multi"];
    let after = ids["After"];
    // Before, the RNodeMultiInterface, its two subinterfaces, After.
    assert!(before < multi, "{ids:?}");
    assert_eq!(after, multi + 3, "{ids:?}");
}

#[test]
fn interface_management_can_be_disabled() {
    use crate::event::InterfaceManagementOperation as Operation;

    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("config"),
        "[reticulum]\nshare_instance = no\nenable_interface_management = no\n",
    )
    .unwrap();
    let node = RnsNode::from_config(Some(dir.path()), Box::new(NoopCallbacks)).unwrap();
    assert!(matches!(
        node.query(QueryRequest::ManageInterface {
            operation: Operation::Attach,
            name: "missing".into(),
        })
        .unwrap(),
        QueryResponse::InterfaceManagement(Some(false))
    ));
    node.shutdown();
}

#[cfg(feature = "iface-tcp")]
#[test]
fn managed_tcp_listener_releases_port_on_detach() {
    use crate::event::InterfaceManagementOperation as Operation;
    use std::io::Read;

    let dir = tempdir().unwrap();
    let port = crate::test_support::port();
    fs::write(dir.path().join("config"), format!(
            "[reticulum]\nshare_instance = no\n\n[interfaces]\n  [[Managed TCP]]\n    type = TCPServerInterface\n    enabled = no\n    listen_ip = 127.0.0.1\n    listen_port = {port}\n"
        )).unwrap();
    let node = RnsNode::from_config(Some(dir.path()), Box::new(NoopCallbacks)).unwrap();
    let manage = |operation| {
        node.query(QueryRequest::ManageInterface {
            operation,
            name: "Managed TCP".into(),
        })
        .unwrap()
    };
    assert!(matches!(
        manage(Operation::Attach),
        QueryResponse::InterfaceManagement(Some(true))
    ));
    let mut client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    thread::sleep(Duration::from_millis(100));
    assert!(matches!(
        manage(Operation::Detach),
        QueryResponse::InterfaceManagement(Some(true))
    ));
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
        && std::time::Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(25));
    }
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    assert_eq!(client.read(&mut [0u8; 1]).unwrap(), 0);
    assert!(matches!(
        manage(Operation::Attach),
        QueryResponse::InterfaceManagement(Some(true))
    ));
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
    node.shutdown();
}

#[test]
#[cfg(feature = "iface-udp")]
fn shared_instance_rpc_manages_interface_by_name() {
    use crate::pickle::PickleValue;
    use crate::rpc::{derive_auth_key, RpcAddr, RpcClient};

    let dir = tempdir().unwrap();
    let rpc_port = crate::test_support::port();
    let shared_port = crate::test_support::port();
    let instance = crate::test_support::instance_name("test-rpc-manage");
    fs::write(dir.path().join("config"), format!(
            "[reticulum]\nshare_instance = yes\ninstance_name = {instance}\ninstance_control_port = {rpc_port}\nshared_instance_port = {shared_port}\n\n[interfaces]\n  [[Managed UDP]]\n    type = UDPInterface\n    enabled = no\n    forward_ip = 127.0.0.1\n    forward_port = 9\n"
        )).unwrap();
    let node = RnsNode::from_config(Some(dir.path()), Box::new(NoopCallbacks)).unwrap();
    let paths = storage::ensure_storage_dirs(dir.path()).unwrap();
    let identity = storage::load_or_create_identity(&paths.identities).unwrap();
    let key = derive_auth_key(&identity.get_private_key().unwrap());
    let call = |action: &str| {
        let mut client =
            RpcClient::connect(&RpcAddr::local(instance.clone(), rpc_port), &key).unwrap();
        client
            .call(&PickleValue::Dict(vec![
                (
                    PickleValue::String("manage".into()),
                    PickleValue::String(action.into()),
                ),
                (
                    PickleValue::String("name".into()),
                    PickleValue::String("Managed UDP".into()),
                ),
            ]))
            .unwrap()
    };
    assert_eq!(call("attach_interface"), PickleValue::Bool(true));
    assert_eq!(call("reload_interface"), PickleValue::Bool(true));
    assert_eq!(call("detach_interface"), PickleValue::Bool(true));
    assert_eq!(call("detach_interface"), PickleValue::None);
    node.shutdown();
}

/// Upstream `Reticulum.__start_local_interface`: a second process with
/// the same shared instance attaches to the running one as a client,
/// instead of serving a second instance (once on TCP, after the Unix
/// bind failed) that opened every interface again.
#[test]
#[cfg(feature = "iface-local")]
fn second_node_with_same_shared_instance_attaches_as_client() {
    for instance_type in ["", "shared_instance_type = tcp\n"] {
        let dir = tempdir().unwrap();
        let rpc_port = crate::test_support::port();
        let shared_port = crate::test_support::port();
        let instance = crate::test_support::instance_name("test-second-node");
        fs::write(dir.path().join("config"), format!(
                "[reticulum]\nshare_instance = yes\n{instance_type}instance_name = {instance}\ninstance_control_port = {rpc_port}\nshared_instance_port = {shared_port}\n"
            )).unwrap();
        let first = RnsNode::from_config(Some(dir.path()), Box::new(NoopCallbacks)).unwrap();
        assert!(!first.is_connected_to_shared_instance());
        let second = RnsNode::from_config(Some(dir.path()), Box::new(NoopCallbacks)).unwrap();
        assert!(
            second.is_connected_to_shared_instance(),
            "second node must attach to the running instance ({instance_type:?})"
        );
        second.shutdown();
        first.shutdown();
    }
}

struct TestWriter;

impl crate::interface::Writer for TestWriter {
    fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
        Ok(())
    }
}

fn test_transport_config(transport_enabled: bool) -> TransportConfig {
    TransportConfig {
        transport_enabled,
        identity_hash: None,
        local_hops_delta: 0,
        prefer_shorter_path: false,
        max_paths_per_destination: 1,
        packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
        packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
        max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
        max_path_destinations: usize::MAX,
        max_tunnel_destinations_total: usize::MAX,
        destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
        announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
        announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
        announce_sig_cache_enabled: true,
        announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
        announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
        announce_queue_max_entries: 256,
        announce_queue_max_interfaces: 1024,
    }
}

fn test_interface_info(id: u64) -> rns_core::transport::types::InterfaceInfo {
    rns_core::transport::types::InterfaceInfo {
        stamp_costs: Default::default(),
        id: rns_core::transport::types::InterfaceId(id),
        name: format!("test-{id}"),
        mode: rns_core::constants::MODE_FULL,
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
        announce_cap: rns_core::constants::ANNOUNCE_CAP,
        is_local_client: false,
        wants_tunnel: false,
        hop_limiter: None,
        tunnel_id: None,
        mtu: rns_core::constants::MTU as u32,
        mtu_upgradable: false,
        ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
        ia_freq: 0.0,
        ia_samples: 0,
        ip_freq: 0.0,
        op_freq: 0.0,
        op_samples: 0,
        started: 0.0,
    }
}

#[test]
fn static_interface_registration_applies_transport_announce_rate_defaults() {
    let (tx, rx) = crate::event::channel();
    let mut driver = Driver::new(
        test_transport_config(true),
        rx,
        tx.clone(),
        Box::new(NoopCallbacks),
    );
    driver.set_announce_rate_defaults(AnnounceRateDefaults {
        target: Some(7200.0),
        penalty: 15.0,
        grace: 7,
    });

    let id = rns_core::transport::types::InterfaceId(7);
    register_started_interface(StartedInterface {
        driver: &mut driver,
        tx: &tx,
        queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
        id,
        info: test_interface_info(id.0),
        writer: Box::new(TestWriter),
        interface_type_name: "TestInterface".to_string(),
        ifac_state: None,
        ifac_runtime: &IfacRuntimeConfig {
            netname: None,
            netkey: None,
            size: 16,
        },
        stamp_costs: Default::default(),
        hop_limiter: None,
        display_name: None,
    });

    let info = &driver.interfaces[&id].info;
    assert_eq!(info.announce_rate_target, Some(7200.0));
    assert_eq!(info.announce_rate_penalty, 15.0);
    assert_eq!(info.announce_rate_grace, 7);
}

#[test]
fn interface_announce_limits_parse_like_upstream() {
    // Reticulum.py `_synthesize_interface`: target `as_int` > 0, grace
    // and penalty `as_int` >= 0, cap `as_float` in (0, 100] as a fraction.
    let mut params = std::collections::HashMap::new();
    assert_eq!(
        super::parse_interface_announce_limits(&params).unwrap(),
        Default::default()
    );
    for (key, value) in [
        ("announce_rate_target", "600"),
        ("announce_rate_grace", "3"),
        ("announce_rate_penalty", "120"),
        ("announce_cap", "5"),
    ] {
        params.insert(key.to_string(), value.to_string());
    }
    let limits = super::parse_interface_announce_limits(&params).unwrap();
    assert_eq!(limits.rate_target, Some(600.0));
    assert_eq!(limits.rate_grace, Some(3));
    assert_eq!(limits.rate_penalty, Some(120.0));
    assert_eq!(limits.cap, Some(0.05));

    // Out-of-range values are dropped, as upstream leaves them unset.
    for (key, value) in [
        ("announce_rate_target", "0"),
        ("announce_rate_grace", "-1"),
        ("announce_rate_penalty", "-5"),
        ("announce_cap", "150"),
    ] {
        params.insert(key.to_string(), value.to_string());
    }
    assert_eq!(
        super::parse_interface_announce_limits(&params).unwrap(),
        Default::default()
    );

    params.insert("announce_rate_target".to_string(), "4.5".to_string());
    let err = super::parse_interface_announce_limits(&params).unwrap_err();
    assert!(err.contains("announce_rate_target"));
}

#[test]
fn configured_interface_announce_limits_override_the_defaults() {
    let (tx, rx) = crate::event::channel();
    let mut driver = Driver::new(
        test_transport_config(true),
        rx,
        tx.clone(),
        Box::new(NoopCallbacks),
    );
    driver.set_announce_rate_defaults(AnnounceRateDefaults {
        target: Some(7200.0),
        penalty: 15.0,
        grace: 7,
    });
    let register = |driver: &mut Driver, id: u64| {
        let id = rns_core::transport::types::InterfaceId(id);
        register_started_interface(StartedInterface {
            driver,
            tx: &tx,
            queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            id,
            info: test_interface_info(id.0),
            writer: Box::new(TestWriter),
            interface_type_name: "TestInterface".to_string(),
            ifac_state: None,
            ifac_runtime: &IfacRuntimeConfig {
                netname: None,
                netkey: None,
                size: 16,
            },
            stamp_costs: Default::default(),
            hop_limiter: None,
            display_name: None,
        });
        driver.interfaces[&id].info.clone()
    };

    // A target of its own: grace and penalty default to 0, not to the
    // instance defaults (upstream sets them when only a target is set).
    let name = test_interface_info(8).name;
    driver.set_interface_announce_limits(
        &name,
        InterfaceAnnounceLimits {
            rate_target: Some(600.0),
            cap: Some(0.05),
            ..Default::default()
        },
    );
    let info = register(&mut driver, 8);
    assert_eq!(info.announce_rate_target, Some(600.0));
    assert_eq!(info.announce_rate_grace, 0);
    assert_eq!(info.announce_rate_penalty, 0.0);
    assert_eq!(info.announce_cap, 0.05);

    // Only a grace: the instance default target still applies.
    let name = test_interface_info(9).name;
    driver.set_interface_announce_limits(
        &name,
        InterfaceAnnounceLimits {
            rate_grace: Some(2),
            ..Default::default()
        },
    );
    let info = register(&mut driver, 9);
    assert_eq!(info.announce_rate_target, Some(7200.0));
    assert_eq!(info.announce_rate_grace, 2);
    assert_eq!(info.announce_rate_penalty, 15.0);

    // No options: the defaults, as before.
    let info = register(&mut driver, 10);
    assert_eq!(info.announce_rate_target, Some(7200.0));
    assert_eq!(info.announce_rate_grace, 7);
    assert_eq!(info.announce_cap, rns_core::constants::ANNOUNCE_CAP);
}

#[test]
fn static_interface_registration_applies_transport_ingress_control_defaults() {
    let (tx, rx) = crate::event::channel();
    let mut driver = Driver::new(
        test_transport_config(true),
        rx,
        tx.clone(),
        Box::new(NoopCallbacks),
    );
    let mut defaults = rns_core::transport::types::IngressControlConfig::enabled();
    defaults.burst_hold = 1.5;
    defaults.pr_burst_freq = 5.5;
    defaults.egress_enabled = true;
    defaults.egress_pr_freq = 9.5;
    driver.set_ingress_control_defaults(defaults);

    let id = rns_core::transport::types::InterfaceId(8);
    register_started_interface(StartedInterface {
        driver: &mut driver,
        tx: &tx,
        queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
        id,
        info: test_interface_info(id.0),
        writer: Box::new(TestWriter),
        interface_type_name: "TestInterface".to_string(),
        ifac_state: None,
        ifac_runtime: &IfacRuntimeConfig {
            netname: None,
            netkey: None,
            size: 16,
        },
        stamp_costs: rns_core::transport::types::InterfaceStampCosts {
            destination_cost: None,
            pr_cost: Some(rns_core::stamp::StampCost::from_f64(12.25)),
        },
        hop_limiter: None,
        display_name: None,
    });

    let ic = driver.interfaces[&id].info.ingress_control;
    assert_eq!(ic.burst_hold, 1.5);
    assert_eq!(ic.pr_burst_freq, 5.5);
    assert!(ic.egress_enabled);
    assert_eq!(ic.egress_pr_freq, 9.5);
    // The configured per-interface costs reach the engine (9b464382).
    assert_eq!(
        driver
            .engine
            .interface_info(&id)
            .unwrap()
            .stamp_costs
            .pr_cost,
        Some(rns_core::stamp::StampCost::from_f64(12.25))
    );
}

struct TestNodeRatchetStore {
    entry: storage::RatchetEntry,
    current_calls: std::sync::Mutex<Vec<[u8; 16]>>,
}

impl storage::RatchetStore for TestNodeRatchetStore {
    fn remember(&self, _dest_hash: [u8; 16], _entry: storage::RatchetEntry) -> io::Result<()> {
        Ok(())
    }

    fn current(
        &self,
        dest_hash: &[u8; 16],
        _now: f64,
        _expiry_secs: f64,
    ) -> io::Result<Option<storage::RatchetEntry>> {
        self.current_calls.lock().unwrap().push(*dest_hash);
        Ok(Some(self.entry))
    }

    fn cleanup(
        &self,
        _known_destinations: &HashSet<[u8; 16]>,
        _now: f64,
        _expiry_secs: f64,
    ) -> io::Result<storage::RatchetCleanupStats> {
        Ok(Default::default())
    }
}

#[test]
fn send_packet_checks_ratchet_store_for_single_destinations() {
    let store = Arc::new(TestNodeRatchetStore {
        entry: storage::RatchetEntry {
            ratchet: [0x55; 32],
            received_at: time::now(),
        },
        current_calls: std::sync::Mutex::new(Vec::new()),
    });
    let ratchet_store: Arc<dyn storage::RatchetStore> = store.clone();
    let node = RnsNode::start(
        NodeConfig {
            ratchet_store: Some(ratchet_store),
            ..Default::default()
        },
        Box::new(NoopCallbacks),
    )
    .unwrap();

    let mut rng = OsRng;
    let remote_identity = Identity::new(&mut rng);
    let public_key = remote_identity.get_public_key().unwrap();
    let announced = crate::destination::AnnouncedIdentity {
        dest_hash: rns_core::types::DestHash([0x22; 16]),
        identity_hash: rns_core::types::IdentityHash(*remote_identity.hash()),
        public_key,
        app_data: None,
        hops: 1,
        received_at: time::now(),
        receiving_interface: rns_core::transport::types::InterfaceId(0),
        rssi: Some(-100),
        snr: Some(10.5),
    };
    let dest = crate::destination::Destination::single_out("test", &["ratchet"], &announced);

    node.send_packet_queued(&dest, b"hello").unwrap();
    assert_eq!(
        store.current_calls.lock().unwrap().as_slice(),
        &[dest.hash.0]
    );

    node.shutdown();
}

#[test]
fn single_payload_uses_stored_ratchet_key_material() {
    let ratchet_prv = rns_crypto::x25519::X25519PrivateKey::from_bytes(&[0x42; 32]);
    let ratchet_pub = ratchet_prv.public_key().public_bytes();
    let store = Arc::new(TestNodeRatchetStore {
        entry: storage::RatchetEntry {
            ratchet: ratchet_pub,
            received_at: time::now(),
        },
        current_calls: std::sync::Mutex::new(Vec::new()),
    });
    let ratchet_store: Arc<dyn storage::RatchetStore> = store.clone();
    let (tx, _rx) = crate::event::channel();
    let node = RnsNode {
        tx,
        driver_handle: None,
        verify_handle: None,
        verify_shutdown: Arc::default(),
        persist_handle: None,
        persist_stop: None,
        kd_flush_handle: None,
        kd_flush_stop: None,
        rpc_server: None,
        #[cfg(target_os = "linux")]
        rpc_unix_server: None,
        tick_interval_ms: Arc::new(AtomicU64::new(1000)),
        next_send_ticket: AtomicU64::new(0),
        encrypt_deferred_inline: std::thread::available_parallelism()
            .map_or(true, |cpus| cpus.get() == 1),
        accepting_work: Arc::new(AtomicBool::new(true)),
        _probe_server: None,
        known_destinations_path: None,
        known_destinations_store: None,
        stamp_store: None,
        stamp_destinations: Arc::new(AtomicBool::new(rns_core::constants::STAMP_DESTINATIONS)),
        stamp_targets: crate::stamper::StampTargets::default(),
        stamper: None,
        transport_state_dir: None,
        ratchet_store: Some(ratchet_store),
        ratchet_expiry: Duration::from_secs(rns_core::constants::RATCHET_EXPIRY),
        #[cfg(feature = "iface-local")]
        destination_types: Default::default(),
    };

    let mut rng = OsRng;
    let remote_identity = Identity::new(&mut rng);
    let public_key = remote_identity.get_public_key().unwrap();
    let announced = crate::destination::AnnouncedIdentity {
        dest_hash: rns_core::types::DestHash([0x33; 16]),
        identity_hash: rns_core::types::IdentityHash(*remote_identity.hash()),
        public_key,
        app_data: None,
        hops: 1,
        received_at: time::now(),
        receiving_interface: rns_core::transport::types::InterfaceId(0),
        rssi: Some(-100),
        snr: Some(10.5),
    };
    let dest = crate::destination::Destination::single_out("test", &["ratchet"], &announced);
    let payload = node
        .encrypt_single_payload(&dest, b"ratchet message")
        .unwrap();

    assert_eq!(
        store.current_calls.lock().unwrap().as_slice(),
        &[dest.hash.0]
    );
    assert!(remote_identity.decrypt(&payload).is_err());

    let peer_pub_bytes: [u8; 32] = payload[..32].try_into().unwrap();
    let peer_pub = rns_crypto::x25519::X25519PublicKey::from_bytes(&peer_pub_bytes);
    let shared_key = ratchet_prv.exchange(&peer_pub);
    let derived_key = rns_crypto::hkdf::hkdf(
        rns_crypto::identity::DERIVED_KEY_LENGTH,
        &shared_key,
        Some(remote_identity.hash()),
        None,
    )
    .unwrap();
    let token = rns_crypto::token::Token::new(&derived_key).unwrap();
    let plaintext = token.decrypt(&payload[32..]).unwrap();
    assert_eq!(plaintext, b"ratchet message");
}

#[test]
fn tcp_client_interface_is_not_discoverable_without_kiss_framing() {
    let mut params = std::collections::HashMap::new();
    params.insert("discoverable".to_string(), "yes".to_string());
    params.insert(
        "discovery_name".to_string(),
        "invalid-tcp-client".to_string(),
    );
    params.insert("reachable_on".to_string(), "example.com".to_string());
    params.insert("target_port".to_string(), "4242".to_string());

    let discovery = super::extract_discovery_config("tcp-client", "TCPClientInterface", &params);

    assert!(
        discovery.is_none(),
        "TCPClientInterface discovery must be rejected unless KISS framing is supported"
    );
}

#[test]
fn discovery_config_parses_ifac_encryption_and_radio_keys() {
    let params = |pairs: &[(&str, &str)]| {
        let mut params: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        params.insert("discoverable".into(), "yes".into());
        params
    };

    let backbone =
        super::extract_discovery_config("public", "BackboneInterface", &params(&[])).unwrap();
    assert!(!backbone.publish_ifac);
    assert!(!backbone.encrypt);
    assert_eq!(backbone.radio, crate::discovery::DiscoveryRadio::default());

    let backbone = super::extract_discovery_config(
        "public",
        "BackboneInterface",
        &params(&[("publish_ifac", "yes"), ("discovery_encrypt", "yes")]),
    )
    .unwrap();
    assert!(backbone.publish_ifac);
    assert!(backbone.encrypt);

    // An RNode announces its own radio settings.
    let rnode = super::extract_discovery_config(
        "lora",
        "RNodeInterface",
        &params(&[
            ("frequency", "868000000"),
            ("bandwidth", "125000"),
            ("spreadingfactor", "8"),
            ("codingrate", "5"),
            ("discovery_frequency", "1"),
        ]),
    )
    .unwrap();
    assert_eq!(rnode.radio.frequency, Some(868_000_000));
    assert_eq!(rnode.radio.bandwidth, Some(125_000));
    assert_eq!(rnode.radio.spreading_factor, Some(8));
    assert_eq!(rnode.radio.coding_rate, Some(5));

    // A KISS interface announces the ones given for discovery.
    let kiss = super::extract_discovery_config(
        "kiss",
        "KISSInterface",
        &params(&[
            ("frequency", "1"),
            ("discovery_frequency", "433500000"),
            ("discovery_bandwidth", "12500"),
            ("discovery_modulation", "4"),
        ]),
    )
    .unwrap();
    assert_eq!(kiss.radio.frequency, Some(433_500_000));
    assert_eq!(kiss.radio.bandwidth, Some(12_500));
    assert_eq!(kiss.radio.modulation.as_deref(), Some("4"));
    assert_eq!(kiss.radio.spreading_factor, None);
}

#[test]
fn discovery_config_parses_location_command() {
    let mut params = std::collections::HashMap::new();
    params.insert("discoverable".into(), "yes".into());
    params.insert("location_cmd".into(), "~/bin/reticulum-location".into());

    let discovery =
        super::extract_discovery_config("public", "BackboneInterface", &params).unwrap();
    assert_eq!(
        discovery.location_cmd.as_deref(),
        Some("~/bin/reticulum-location")
    );
}

#[test]
fn discovery_config_parses_valid_operator_lxmf_address() {
    let mut params = std::collections::HashMap::new();
    params.insert("discoverable".into(), "yes".into());
    params.insert("discovery_lxmf_address".into(), "ab".repeat(16));

    let discovery =
        super::extract_discovery_config("public", "BackboneInterface", &params).unwrap();

    assert_eq!(discovery.operator_lxmf_address, Some([0xab; 16]));
}

#[test]
fn discovery_config_ignores_invalid_operator_lxmf_addresses() {
    for address in ["ab".repeat(15), "zz".repeat(16)] {
        let mut params = std::collections::HashMap::new();
        params.insert("discoverable".into(), "yes".into());
        params.insert("discovery_lxmf_address".into(), address);

        let discovery =
            super::extract_discovery_config("public", "BackboneInterface", &params).unwrap();

        assert_eq!(discovery.operator_lxmf_address, None);
    }
}

#[test]
fn ingress_control_config_defaults_by_interface_type() {
    let params = std::collections::HashMap::new();

    let tcp = super::parse_ingress_control_config("TCPServerInterface", &params).unwrap();
    assert!(tcp.enabled);
    assert_eq!(
        tcp.max_held_announces,
        rns_core::constants::IC_MAX_HELD_ANNOUNCES
    );
    assert_eq!(tcp.burst_hold, rns_core::constants::IC_BURST_HOLD);

    let pipe = super::parse_ingress_control_config("PipeInterface", &params).unwrap();
    assert!(!pipe.enabled);
    assert_eq!(
        pipe.held_release_interval,
        rns_core::constants::IC_HELD_RELEASE_INTERVAL
    );
}

#[test]
fn ingress_control_config_parses_python_ic_keys() {
    let mut params = std::collections::HashMap::new();
    params.insert("ingress_control".to_string(), "No".to_string());
    params.insert("ic_max_held_announces".to_string(), "17".to_string());
    params.insert("ic_burst_hold".to_string(), "1.5".to_string());
    params.insert("ic_burst_freq_new".to_string(), "2.5".to_string());
    params.insert("ic_burst_freq".to_string(), "3.5".to_string());
    params.insert("ic_pr_burst_freq_new".to_string(), "3.25".to_string());
    params.insert("ic_pr_burst_freq".to_string(), "8.25".to_string());
    params.insert("egress_control".to_string(), "Yes".to_string());
    params.insert("ec_pr_freq".to_string(), "5.25".to_string());
    params.insert("ic_new_time".to_string(), "4.5".to_string());
    params.insert("ic_burst_penalty".to_string(), "5.5".to_string());
    params.insert("ic_held_release_interval".to_string(), "6.5".to_string());

    let config = super::parse_ingress_control_config("TCPServerInterface", &params).unwrap();

    assert!(!config.enabled);
    assert_eq!(config.max_held_announces, 17);
    assert_eq!(config.burst_hold, 1.5);
    assert_eq!(config.burst_freq_new, 2.5);
    assert_eq!(config.burst_freq, 3.5);
    assert_eq!(config.pr_burst_freq_new, 3.25);
    assert_eq!(config.pr_burst_freq, 8.25);
    assert!(config.egress_enabled);
    assert_eq!(config.egress_pr_freq, 5.25);
    assert_eq!(config.new_time, 4.5);
    assert_eq!(config.burst_penalty, 5.5);
    assert_eq!(config.held_release_interval, 6.5);
}

#[test]
fn ingress_control_config_rejects_invalid_values() {
    let mut params = std::collections::HashMap::new();
    params.insert("ic_burst_hold".to_string(), "-1".to_string());

    let err = super::parse_ingress_control_config("TCPServerInterface", &params).unwrap_err();

    assert!(err.contains("ic_burst_hold"));
}

#[test]
fn interface_stamp_costs_are_fractional_and_clamped() {
    // Reticulum.py since 9b464382: `as_float`, `max(0, min(v, cap))`.
    use rns_core::stamp::StampCost;
    let mut params = std::collections::HashMap::new();
    let none = super::parse_interface_stamp_costs(&params).unwrap();
    assert_eq!(none, Default::default());

    params.insert("destination_cost".to_string(), "17.5".to_string());
    params.insert("pr_cost".to_string(), "250".to_string());
    let costs = super::parse_interface_stamp_costs(&params).unwrap();
    assert_eq!(costs.destination_cost, Some(StampCost::from_f64(17.5)));
    assert_eq!(costs.pr_cost, Some(StampCost::from_whole(100)));

    params.insert("pr_cost".to_string(), "-3".to_string());
    let costs = super::parse_interface_stamp_costs(&params).unwrap();
    assert_eq!(costs.pr_cost, Some(StampCost::ZERO));

    params.insert("destination_cost".to_string(), "steep".to_string());
    let err = super::parse_interface_stamp_costs(&params).unwrap_err();
    assert!(err.contains("destination_cost"));
}

#[test]
fn discovery_announce_interval_is_read_in_minutes() {
    // Upstream: `as_int("announce_interval")*60`, at least 5 minutes,
    // 6 hours without the option.
    let interval = |value: Option<&str>| {
        let mut params = std::collections::HashMap::new();
        params.insert("discoverable".to_string(), "yes".to_string());
        if let Some(value) = value {
            params.insert("announce_interval".to_string(), value.to_string());
        }
        super::extract_discovery_config("Discovery Test", "BackboneInterface", &params)
            .unwrap()
            .announce_interval
    };
    assert_eq!(interval(None), 6 * 60 * 60);
    assert_eq!(interval(Some("720")), 12 * 60 * 60);
    assert_eq!(interval(Some("1")), 5 * 60);
}

#[test]
fn discovery_stamp_default_is_16_but_explicit_override_is_preserved() {
    let mut params = std::collections::HashMap::new();
    params.insert("discoverable".to_string(), "yes".to_string());
    let defaults =
        super::extract_discovery_config("Discovery Test", "BackboneInterface", &params).unwrap();
    assert_eq!(
        defaults.stamp_value,
        rns_core::stamp::StampCost::from_whole(16)
    );

    params.insert("discovery_stamp_value".to_string(), "14".to_string());
    let overridden =
        super::extract_discovery_config("Discovery Test", "BackboneInterface", &params).unwrap();
    assert_eq!(
        overridden.stamp_value,
        rns_core::stamp::StampCost::from_whole(14)
    );
}

#[test]
fn start_and_shutdown() {
    let node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            link_proof_verify_threads: Default::default(),
            stamps: Default::default(),
            transport_enabled: false,
            static_transport_identity: false,
            local_hops_delta: false,
            identity: None,
            network_identity: None,
            interfaces: vec![],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            ratchet_store: None,
            ratchet_expiry: Duration::from_secs(rns_core::constants::RATCHET_EXPIRY),
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            direct_connect_policy: Default::default(),
            direct_connect_allow_private_endpoints: false,
            direct_connect_allowed_identities: Vec::new(),
            direct_connect_reupgrade: Default::default(),
            probe_rate_limit: Default::default(),
            device: None,
            underlay_mark: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery: Default::default(),
            shared_instance: Default::default(),
            autoconnect_interface_mode: None,
            autoconnect_interface_gravity: 0,
            autoconnect_announces_to_internal: false,
            autoconnect_unverified_implementations: false,
            discovery_required_value: None,
            respond_to_probes: false,
            use_implicit_proof: true,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: crate::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_rate_defaults: AnnounceRateDefaults::default(),
            ingress_control_defaults: rns_core::transport::types::IngressControlConfig::enabled(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: None,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "hooks")]
            provider_bridge: None,
        },
        Box::new(NoopCallbacks),
    )
    .unwrap();
    node.shutdown();
}

#[test]
fn known_destinations_persist_across_restart() {
    let dir = tempdir().unwrap();
    let dest_hash = [0x91; 16];
    let identity = Identity::new(&mut OsRng);
    let last_used_at = 77.0;
    let receiving_interface = rns_core::transport::types::InterfaceId(42);

    let node = RnsNode::from_config(Some(dir.path()), Box::new(NoopCallbacks)).unwrap();
    let (response_tx, response_rx) = std::sync::mpsc::channel();
    node.event_sender()
        .send(crate::event::Event::query(
            QueryRequest::RestoreKnownDestination(crate::event::KnownDestinationEntry {
                dest_hash,
                identity_hash: *identity.hash(),
                public_key: identity.get_public_key().unwrap(),
                app_data: Some(b"persisted".to_vec()),
                hops: 2,
                received_at: 55.0,
                receiving_interface,
                was_used: true,
                last_used_at: Some(last_used_at),
                retained: true,
                stamp: None,
                stamp_value: rns_core::stamp::StampValue::ZERO,
                lr_cost: None,
            }),
            response_tx,
        ))
        .unwrap();
    assert!(matches!(
        response_rx.recv().unwrap(),
        QueryResponse::RestoreKnownDestination(true)
    ));
    node.shutdown();

    let restarted = RnsNode::from_config(Some(dir.path()), Box::new(NoopCallbacks)).unwrap();
    let entries = restarted.known_destinations().unwrap();
    let entry = entries
        .iter()
        .find(|entry| entry.dest_hash == dest_hash)
        .expect("reloaded destination should appear in lifecycle listing");
    assert!(entry.retained);
    assert!(entry.was_used);
    assert_eq!(entry.hops, 2);
    assert_eq!(entry.receiving_interface, receiving_interface);
    assert_eq!(entry.last_used_at, Some(last_used_at));

    let recalled = restarted
        .recall_identity(&rns_core::types::DestHash(dest_hash))
        .unwrap()
        .expect("known destination should reload from storage");
    assert_eq!(recalled.identity_hash.0, *identity.hash());
    assert_eq!(recalled.app_data, Some(b"persisted".to_vec()));
    restarted.shutdown();
}

#[test]
#[cfg(feature = "iface-udp")]
fn transport_paths_hashes_and_detached_tunnels_restore_from_upstream_files() {
    use rns_core::packet::{PacketFlags, RawPacket};
    use rns_core::transport::persistence::{
        PersistedPath, PersistedTunnel, TransportStateSnapshot,
    };

    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("config"),
        r#"[reticulum]
enable_transport = True
share_instance = False

[interfaces]
  [[Persistence Test]]
    type = UDPInterface
    enabled = yes
    forward_ip = 127.0.0.1
    forward_port = 9
    interface_mode = full
"#,
    )
    .unwrap();
    let paths = storage::ensure_storage_dirs(dir.path()).unwrap();
    let destination_hash = [0x31; 16];
    let packet = RawPacket::pack(
        PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: rns_core::constants::FLAG_UNSET,
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: rns_core::constants::DESTINATION_SINGLE,
            packet_type: rns_core::constants::PACKET_TYPE_ANNOUNCE,
        },
        0,
        &destination_hash,
        None,
        rns_core::constants::CONTEXT_NONE,
        &[0xA5; 32],
    )
    .unwrap();
    crate::announce_cache::AnnounceCache::new(paths.cache.join("announces"))
        .store(&packet.packet_hash, &packet.raw, None)
        .unwrap();
    let now = time::now();
    let route = PersistedPath {
        destination_hash,
        timestamp: now,
        received_from: [0x41; 16],
        hops: 2,
        expires: now + 600.0,
        random_blobs: vec![[0x51; 10]],
        interface_hash: Some(rns_core::hash::full_hash(b"Persistence Test")),
        packet_hash: packet.packet_hash,
        used: 0.0,
    };
    storage::save_transport_state(
        &TransportStateSnapshot {
            packet_hashes: vec![[0x61; 32], [0x62; 32]],
            paths: vec![route.clone()],
            tunnels: vec![PersistedTunnel {
                tunnel_id: [0x71; 32],
                interface_hash: None,
                paths: vec![PersistedPath {
                    interface_hash: None,
                    ..route
                }],
                expires: now + 1_200.0,
            }],
            announce_rates: Vec::new(),
        },
        &paths.storage,
        false,
    )
    .unwrap();

    let node = RnsNode::from_config(Some(dir.path()), Box::new(NoopCallbacks)).unwrap();
    let QueryResponse::TransportStateSnapshot(restored) =
        node.query(QueryRequest::TransportStateSnapshot).unwrap()
    else {
        panic!("unexpected transport snapshot response");
    };
    // Upstream's full hashes load; the table keeps their first 16 bytes.
    let stored = |byte: u8| {
        let mut hash = [0u8; 32];
        hash[..16].fill(byte);
        hash
    };
    assert_eq!(restored.packet_hashes, vec![stored(0x61), stored(0x62)]);
    assert_eq!(restored.paths.len(), 1);
    assert_eq!(restored.paths[0].destination_hash, destination_hash);
    assert_eq!(restored.paths[0].received_from, [0x41; 16]);
    assert_eq!(restored.tunnels.len(), 1);
    assert_eq!(restored.tunnels[0].tunnel_id, [0x71; 32]);
    assert_eq!(restored.tunnels[0].interface_hash, None);
    node.shutdown();
}

#[test]
fn from_config_cleans_persistent_ratchets_after_loading_known_destinations() {
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
    }

    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("config"),
        "[reticulum]\nenable_transport = False\nshare_instance = False\nratchet_expiry = 300\n",
    )
    .unwrap();
    let paths = storage::ensure_storage_dirs(dir.path()).unwrap();
    let known_live = [0x01; 16];
    let known_expired = [0x02; 16];
    let unknown = [0x03; 16];
    let known_corrupt = [0x04; 16];
    let now = time::now();

    let identity = Identity::new(&mut OsRng);
    let known = std::collections::HashMap::from([
        (
            known_live,
            storage::KnownDestination {
                identity_hash: *identity.hash(),
                public_key: identity.get_public_key().unwrap(),
                app_data: None,
                hops: 1,
                received_at: now,
                receiving_interface: 0,
                was_used: false,
                last_used_at: None,
                retained: false,
                stamp: None,
                stamp_value: rns_core::stamp::StampValue::ZERO,
                lr_cost: None,
            },
        ),
        (
            known_expired,
            storage::KnownDestination {
                identity_hash: *identity.hash(),
                public_key: identity.get_public_key().unwrap(),
                app_data: None,
                hops: 1,
                received_at: now,
                receiving_interface: 0,
                was_used: false,
                last_used_at: None,
                retained: false,
                stamp: None,
                stamp_value: rns_core::stamp::StampValue::ZERO,
                lr_cost: None,
            },
        ),
        (
            known_corrupt,
            storage::KnownDestination {
                identity_hash: *identity.hash(),
                public_key: identity.get_public_key().unwrap(),
                app_data: None,
                hops: 1,
                received_at: now,
                receiving_interface: 0,
                was_used: false,
                last_used_at: None,
                retained: false,
                stamp: None,
                stamp_value: rns_core::stamp::StampValue::ZERO,
                lr_cost: None,
            },
        ),
    ]);
    storage::save_known_destinations(&known, &paths.storage.join("known_destinations")).unwrap();

    let store = storage::FsRatchetStore::new(paths.ratchets.clone());
    store
        .remember(
            known_live,
            storage::RatchetEntry {
                ratchet: [0x11; 32],
                received_at: now,
            },
        )
        .unwrap();
    store
        .remember(
            known_expired,
            storage::RatchetEntry {
                ratchet: [0x22; 32],
                received_at: now - 1000.0,
            },
        )
        .unwrap();
    store
        .remember(
            unknown,
            storage::RatchetEntry {
                ratchet: [0x33; 32],
                received_at: now,
            },
        )
        .unwrap();
    fs::write(paths.ratchets.join(hex(&known_corrupt)), b"not msgpack").unwrap();
    fs::write(paths.ratchets.join("0102.out"), b"temp").unwrap();

    let node = RnsNode::from_config(Some(dir.path()), Box::new(NoopCallbacks)).unwrap();

    assert!(!paths.ratchets.join(hex(&known_live)).exists());
    assert!(!paths.ratchets.join(hex(&known_expired)).exists());
    assert!(!paths.ratchets.join(hex(&unknown)).exists());
    assert!(!paths.ratchets.join(hex(&known_corrupt)).exists());
    assert!(!paths.ratchets.join("0102.out").exists());
    assert!(paths.storage.join("known_destinations.imported").exists());

    let store = crate::storage_sqlite::KnownDestinationsStore::open_read_only(
        &crate::storage_sqlite::default_path(&paths.storage),
    )
    .unwrap();
    assert_eq!(store.load_all().unwrap().len(), 3);
    assert!(store.current(&known_live, now, 300.0).unwrap().is_some());
    assert!(store.current(&known_expired, now, 300.0).unwrap().is_none());
    assert!(store.current(&unknown, now, 300.0).unwrap().is_none());
    assert!(store.current(&known_corrupt, now, 300.0).unwrap().is_none());

    node.shutdown();
}

#[test]
fn start_with_identity() {
    let identity = Identity::new(&mut OsRng);
    let hash = *identity.hash();
    let node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            link_proof_verify_threads: Default::default(),
            stamps: Default::default(),
            transport_enabled: true,
            static_transport_identity: false,
            local_hops_delta: false,
            identity: Some(identity),
            network_identity: None,
            interfaces: vec![],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            ratchet_store: None,
            ratchet_expiry: Duration::from_secs(rns_core::constants::RATCHET_EXPIRY),
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            direct_connect_policy: Default::default(),
            direct_connect_allow_private_endpoints: false,
            direct_connect_allowed_identities: Vec::new(),
            direct_connect_reupgrade: Default::default(),
            probe_rate_limit: Default::default(),
            device: None,
            underlay_mark: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery: Default::default(),
            shared_instance: Default::default(),
            autoconnect_interface_mode: None,
            autoconnect_interface_gravity: 0,
            autoconnect_announces_to_internal: false,
            autoconnect_unverified_implementations: false,
            discovery_required_value: None,
            respond_to_probes: false,
            use_implicit_proof: true,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: crate::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_rate_defaults: AnnounceRateDefaults::default(),
            ingress_control_defaults: rns_core::transport::types::IngressControlConfig::enabled(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: None,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "hooks")]
            provider_bridge: None,
        },
        Box::new(NoopCallbacks),
    )
    .unwrap();
    // The identity hash should have been used
    let _ = hash;
    node.shutdown();
}

#[test]
fn start_generates_identity() {
    let node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            link_proof_verify_threads: Default::default(),
            stamps: Default::default(),
            transport_enabled: false,
            static_transport_identity: false,
            local_hops_delta: false,
            identity: None,
            network_identity: None,
            interfaces: vec![],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            ratchet_store: None,
            ratchet_expiry: Duration::from_secs(rns_core::constants::RATCHET_EXPIRY),
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            direct_connect_policy: Default::default(),
            direct_connect_allow_private_endpoints: false,
            direct_connect_allowed_identities: Vec::new(),
            direct_connect_reupgrade: Default::default(),
            probe_rate_limit: Default::default(),
            device: None,
            underlay_mark: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery: Default::default(),
            shared_instance: Default::default(),
            autoconnect_interface_mode: None,
            autoconnect_interface_gravity: 0,
            autoconnect_announces_to_internal: false,
            autoconnect_unverified_implementations: false,
            discovery_required_value: None,
            respond_to_probes: false,
            use_implicit_proof: true,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: crate::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_rate_defaults: AnnounceRateDefaults::default(),
            ingress_control_defaults: rns_core::transport::types::IngressControlConfig::enabled(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: None,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "hooks")]
            provider_bridge: None,
        },
        Box::new(NoopCallbacks),
    )
    .unwrap();
    // Should not panic - identity was auto-generated
    node.shutdown();
}

#[test]
fn from_config_creates_identity() {
    let dir = std::env::temp_dir().join(format!("rns-test-fc-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    // Write a minimal config file
    fs::write(
        dir.join("config"),
        "[reticulum]\nshare_instance = No\nenable_transport = False\n",
    )
    .unwrap();

    let node = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks)).unwrap();

    // Identity file should have been created
    assert!(dir.join("storage/identities/identity").exists());

    node.shutdown();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn startup_creates_state_directories_or_fails() {
    let dir = tempfile::tempdir().unwrap();
    let config = "[reticulum]\nshare_instance = No\nenable_transport = False\n";
    fs::write(dir.path().join("config"), config).unwrap();
    let node = RnsNode::from_config(Some(dir.path()), Box::new(NoopCallbacks)).unwrap();
    node.shutdown();
    for made in [
        "cache/announces",
        "storage/discovery/interfaces",
        "storage/blackhole",
    ] {
        assert!(dir.path().join(made).is_dir(), "{made}");
    }

    let blocked = tempfile::tempdir().unwrap();
    fs::write(blocked.path().join("config"), config).unwrap();
    fs::create_dir_all(blocked.path().join("storage")).unwrap();
    fs::write(blocked.path().join("storage/blackhole"), b"").unwrap();
    let err = RnsNode::from_config(Some(blocked.path()), Box::new(NoopCallbacks))
        .err()
        .expect("startup fails");
    assert!(err.to_string().contains("storage/blackhole"), "{err}");
}

#[test]
fn private_config_keeps_state_out_of_config_directory() {
    let root = tempfile::tempdir().unwrap();
    let config_dir = root.path().join("config");
    let state_dir = root.path().join("state");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(
        config_dir.join("config"),
        "[reticulum]\nenable_transport = False\nshare_instance = Yes\n",
    )
    .unwrap();
    let node = RnsNode::from_private_config(&config_dir, &state_dir, None, Box::new(NoopCallbacks))
        .unwrap();
    assert!(state_dir.join("storage/identities/identity").exists());
    assert!(!config_dir.join("storage").exists());
    node.shutdown();
}

#[test]
fn from_config_loads_identity() {
    let dir = std::env::temp_dir().join(format!("rns-test-fl-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("storage/identities")).unwrap();

    // Pre-create an identity
    let identity = Identity::new(&mut OsRng);
    let hash = *identity.hash();
    storage::save_identity(&identity, &dir.join("storage/identities/identity")).unwrap();

    fs::write(
        dir.join("config"),
        "[reticulum]\nshare_instance = No\nenable_transport = False\n",
    )
    .unwrap();

    let node = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks)).unwrap();

    // Verify the same identity was loaded (hash matches)
    let loaded = storage::load_identity(&dir.join("storage/identities/identity")).unwrap();
    assert_eq!(*loaded.hash(), hash);

    node.shutdown();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
#[cfg(feature = "iface-tcp")]
fn from_config_tcp_server() {
    let dir = std::env::temp_dir().join(format!("rns-test-fts-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let port = crate::test_support::port();

    let config = format!(
        r#"
[reticulum]
share_instance = No
enable_transport = False

[interfaces]
  [[Test TCP Server]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {}
"#,
        port
    );

    fs::write(dir.join("config"), config).unwrap();

    let node = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks)).unwrap();

    // Give server time to start
    thread::sleep(Duration::from_millis(100));

    // Should be able to connect
    let _client = std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

    node.shutdown();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn from_config_starts_rpc_when_share_instance_enabled() {
    // As upstream: RPC on the abstract socket where the shared instance
    // uses one (Linux), on TCP with `shared_instance_type = tcp`, never
    // both.
    for tcp_only in [false, true] {
        let dir = tempdir().unwrap();
        let rpc_port = crate::test_support::port();
        let instance = crate::test_support::instance_name("test-rpc-start");
        let instance_type = if tcp_only {
            "shared_instance_type = tcp\n"
        } else {
            ""
        };
        fs::write(
            dir.path().join("config"),
            format!(
                "[reticulum]\nenable_transport = False\nshare_instance = Yes\n\
                     instance_name = {instance}\ninstance_control_port = {rpc_port}\n\
                     shared_instance_port = {}\n{instance_type}\n[interfaces]\n",
                crate::test_support::port()
            ),
        )
        .unwrap();

        let node = RnsNode::from_config(Some(dir.path()), Box::new(NoopCallbacks)).unwrap();
        thread::sleep(Duration::from_millis(100));

        let tcp = std::net::TcpStream::connect(("127.0.0.1", rpc_port)).is_ok();
        if tcp_only || !cfg!(target_os = "linux") {
            assert!(tcp, "RPC must be served on TCP");
        } else {
            assert!(!tcp, "RPC must not also be served on TCP");
            crate::rpc::RpcAddr::local(instance.clone(), rpc_port)
                .accepts_connections()
                .expect("RPC on the abstract socket");
        }
        node.shutdown();
    }
}

#[test]
fn from_config_starts_rpc_when_transport_enabled() {
    let dir = std::env::temp_dir().join(format!("rns-test-rpc-transport-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let rpc_port = crate::test_support::port();
    let instance = crate::test_support::instance_name("test-rpc-transport");

    let config = format!(
        r#"
[reticulum]
enable_transport = True
share_instance = Yes
instance_name = {instance}
instance_control_port = {}

[interfaces]
"#,
        rpc_port
    );

    fs::write(dir.join("config"), config).unwrap();

    let node = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks)).unwrap();

    thread::sleep(Duration::from_millis(100));

    crate::rpc::RpcAddr::local(instance, rpc_port)
        .accepts_connections()
        .unwrap();

    node.shutdown();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn from_config_starts_rpc_when_tcp_client_is_unreachable() {
    let dir = std::env::temp_dir().join(format!("rns-test-rpc-unreachable-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let rpc_port = crate::test_support::port();
    let unreachable_port = crate::test_support::port();
    let instance = crate::test_support::instance_name("test-rpc-unreachable");

    let config = format!(
        r#"
[reticulum]
enable_transport = True
share_instance = Yes
instance_name = {instance}
instance_control_port = {}

[interfaces]
  [[Unreachable Upstream]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {}
"#,
        rpc_port, unreachable_port
    );

    fs::write(dir.join("config"), config).unwrap();

    let node = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks)).unwrap();

    thread::sleep(Duration::from_millis(100));

    crate::rpc::RpcAddr::local(instance, rpc_port)
        .accepts_connections()
        .unwrap();

    node.shutdown();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_parse_interface_mode() {
    use rns_core::constants::*;

    assert_eq!(parse_interface_mode("full"), MODE_FULL);
    assert_eq!(parse_interface_mode("Full"), MODE_FULL);
    assert_eq!(parse_interface_mode("access_point"), MODE_ACCESS_POINT);
    assert_eq!(parse_interface_mode("accesspoint"), MODE_ACCESS_POINT);
    assert_eq!(parse_interface_mode("ap"), MODE_ACCESS_POINT);
    assert_eq!(parse_interface_mode("AP"), MODE_ACCESS_POINT);
    assert_eq!(parse_interface_mode("pointtopoint"), MODE_POINT_TO_POINT);
    assert_eq!(parse_interface_mode("ptp"), MODE_POINT_TO_POINT);
    assert_eq!(parse_interface_mode("roaming"), MODE_ROAMING);
    assert_eq!(parse_interface_mode("boundary"), MODE_BOUNDARY);
    assert_eq!(parse_interface_mode("gateway"), MODE_GATEWAY);
    assert_eq!(parse_interface_mode("gw"), MODE_GATEWAY);
    assert_eq!(parse_interface_mode("internal"), MODE_INTERNAL);
    assert_eq!(parse_interface_mode("Internal"), MODE_INTERNAL);
    // Unknown defaults to FULL
    assert_eq!(parse_interface_mode("invalid"), MODE_FULL);
}

#[test]
fn discovery_mode_normalization_matrix() {
    use rns_core::constants::*;

    let interface_types = [
        "RNodeInterface",
        "RNodeMultiInterface",
        "BackboneInterface",
        "TCPServerInterface",
        "AutoInterface",
    ];
    let modes = [
        MODE_FULL,
        MODE_ACCESS_POINT,
        MODE_POINT_TO_POINT,
        MODE_ROAMING,
        MODE_BOUNDARY,
        MODE_GATEWAY,
        MODE_INTERNAL,
    ];

    for interface_type in interface_types {
        for configured_mode in modes {
            for discoverable in [false, true] {
                for ignore_warnings in [false, true] {
                    let expected = if !discoverable
                        || ignore_warnings
                        || matches!(
                            configured_mode,
                            MODE_ACCESS_POINT | MODE_GATEWAY | MODE_INTERNAL
                        ) {
                        configured_mode
                    } else if matches!(interface_type, "RNodeInterface" | "RNodeMultiInterface") {
                        MODE_ACCESS_POINT
                    } else {
                        MODE_GATEWAY
                    };
                    assert_eq!(
                            normalize_discovery_mode(
                                interface_type,
                                configured_mode,
                                discoverable,
                                ignore_warnings,
                            ),
                            expected,
                            "type={interface_type}, mode={configured_mode}, discoverable={discoverable}, ignore={ignore_warnings}",
                        );
                }
            }
        }
    }
}

#[test]
fn to_node_config_serial() {
    // Verify from_config parses SerialInterface correctly.
    // The serial port won't exist, so start() will fail, but the config
    // parsing path is exercised. We verify via the error (not a config error).
    let dir = std::env::temp_dir().join(format!("rns-test-serial-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let config = r#"
[reticulum]
share_instance = No
enable_transport = False

[interfaces]
  [[Test Serial Port]]
    type = SerialInterface
    enabled = yes
    port = /dev/nonexistent_rns_test_serial
    speed = 115200
    databits = 8
    parity = E
    stopbits = 1
    interface_mode = ptp
    networkname = testnet
"#;
    fs::write(dir.join("config"), config).unwrap();

    // Interface error is non-fatal: the node starts but logs the error.
    let node = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks))
        .expect("Config should parse; interface failure is non-fatal");
    node.shutdown();

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn to_node_config_kiss() {
    // Verify from_config parses KISSInterface correctly.
    let dir = std::env::temp_dir().join(format!("rns-test-kiss-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let config = r#"
[reticulum]
share_instance = No
enable_transport = False

[interfaces]
  [[Test KISS TNC]]
    type = KISSInterface
    enabled = yes
    port = /dev/nonexistent_rns_test_kiss
    speed = 9600
    preamble = 500
    txtail = 30
    persistence = 128
    slottime = 40
    flow_control = True
    id_interval = 600
    id_callsign = TEST0
    interface_mode = full
    passphrase = secretkey
"#;
    fs::write(dir.join("config"), config).unwrap();

    // Interface error is non-fatal: the node starts but logs the error.
    let node = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks))
        .expect("Config should parse; interface failure is non-fatal");
    node.shutdown();

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn config_parser_accepts_recursive_prs_interface_option() {
    let config = r#"
[reticulum]
enable_transport = True

[interfaces]
  [[Recursive Client]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = 4242
    interface_mode = full
    recursive_prs = yes

  [[Default Client]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = 4243
    interface_mode = gateway
"#;

    let parsed = config::parse(config).unwrap();

    assert_eq!(parsed.interfaces.len(), 2);
    assert_eq!(parsed.interfaces[0].name, "Recursive Client");
    assert_eq!(parsed.interfaces[0].mode, "full");
    assert_eq!(
        parsed.interfaces[0]
            .params
            .get("recursive_prs")
            .map(String::as_str),
        Some("yes")
    );
    assert_eq!(parsed.interfaces[1].name, "Default Client");
    assert_eq!(parsed.interfaces[1].mode, "gateway");
    assert!(!parsed.interfaces[1].params.contains_key("recursive_prs"));
}

#[test]
fn config_parser_accepts_announces_from_internal_interface_option() {
    let config = r#"
[reticulum]
enable_transport = True

[interfaces]
  [[Filtered Client]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = 4242
    interface_mode = gateway
    announces_from_internal = no

  [[Default Client]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = 4243
    interface_mode = full
"#;

    let parsed = config::parse(config).unwrap();

    assert_eq!(parsed.interfaces.len(), 2);
    assert_eq!(parsed.interfaces[0].name, "Filtered Client");
    assert_eq!(parsed.interfaces[0].mode, "gateway");
    assert_eq!(
        parsed.interfaces[0]
            .params
            .get("announces_from_internal")
            .map(String::as_str),
        Some("no")
    );
    assert_eq!(parsed.interfaces[1].name, "Default Client");
    assert_eq!(parsed.interfaces[1].mode, "full");
    assert!(!parsed.interfaces[1]
        .params
        .contains_key("announces_from_internal"));
}

#[test]
fn config_parser_preserves_announces_to_internal_tristate() {
    let config = r#"
[interfaces]
  [[Allowed Boundary]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = 4242
    announces_to_internal = yes

  [[Blocked Boundary]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = 4243
    announces_to_internal = no

  [[Default Boundary]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = 4244
"#;

    let parsed = config::parse(config).unwrap();
    let parsed_value = |index: usize| {
        parsed.interfaces[index]
            .params
            .get("announces_to_internal")
            .and_then(|value| config::parse_bool_pub(value))
    };

    assert_eq!(parsed_value(0), Some(true));
    assert_eq!(parsed_value(1), Some(false));
    assert_eq!(parsed_value(2), None);
}

#[test]
fn interface_hop_limiter_parser_clamps_and_treats_zero_as_unset() {
    // Upstream bb63dd44: `as_int`, clamped to 0..=PATHFINDER_M, and 0 is
    // falsy where it is checked.
    assert_eq!(parse_interface_hop_limiter(Some("5")), Some(5));
    assert_eq!(parse_interface_hop_limiter(Some(" 12 ")), Some(12));
    assert_eq!(
        parse_interface_hop_limiter(Some("500")),
        Some(rns_core::constants::PATHFINDER_M)
    );
    assert_eq!(parse_interface_hop_limiter(Some("0")), None);
    assert_eq!(parse_interface_hop_limiter(Some("-3")), None);
    assert_eq!(parse_interface_hop_limiter(Some("many")), None);
    assert_eq!(parse_interface_hop_limiter(None), None);
}

#[test]
fn interface_gravity_parser_accepts_signed_values_and_uses_global_default() {
    assert_eq!(parse_interface_gravity(Some("7"), -2), 7);
    assert_eq!(parse_interface_gravity(Some("-4"), 2), -4);
    assert_eq!(parse_interface_gravity(None, -6), -6);
}

#[test]
fn config_parser_accepts_local_hops_delta_option() {
    let cfg = r#"
[reticulum]
local_hops_delta = yes
"#;
    let parsed = config::parse(cfg).unwrap();
    assert!(parsed.reticulum.local_hops_delta);
}

#[test]
fn config_parser_accepts_static_transport_identity_option() {
    let config = r#"
[reticulum]
enable_transport = false
static_transport_identity = yes
"#;

    let parsed = config::parse(config).unwrap();

    assert!(!parsed.reticulum.enable_transport);
    assert!(parsed.reticulum.static_transport_identity);
}

#[test]
fn non_transport_node_uses_ephemeral_transport_identity_by_default() {
    let identity = Identity::new(&mut rns_crypto::FixedRng::new(&[0x41; 32]));
    let stored_hash = *identity.hash();
    let node = RnsNode::start(
        NodeConfig {
            transport_enabled: false,
            static_transport_identity: false,
            local_hops_delta: false,
            identity: Some(identity),
            share_instance: false,
            ..Default::default()
        },
        Box::new(NoopCallbacks),
    )
    .unwrap();

    let response = node.query(QueryRequest::TransportIdentity).unwrap();
    let QueryResponse::TransportIdentity(Some(hash)) = response else {
        panic!("transport identity query returned {response:?}");
    };
    assert_ne!(hash, stored_hash);

    node.shutdown();
}

#[test]
fn non_transport_node_can_use_static_transport_identity() {
    let identity = Identity::new(&mut rns_crypto::FixedRng::new(&[0x42; 32]));
    let stored_hash = *identity.hash();
    let node = RnsNode::start(
        NodeConfig {
            transport_enabled: false,
            static_transport_identity: true,
            local_hops_delta: false,
            identity: Some(identity),
            share_instance: false,
            ..Default::default()
        },
        Box::new(NoopCallbacks),
    )
    .unwrap();

    let response = node.query(QueryRequest::TransportIdentity).unwrap();
    let QueryResponse::TransportIdentity(Some(hash)) = response else {
        panic!("transport identity query returned {response:?}");
    };
    assert_eq!(hash, stored_hash);

    node.shutdown();
}

#[test]
fn discoverable_interface_forces_static_transport_identity_on_non_transport() {
    assert!(!effective_static_transport_identity(false, false, false));
    assert!(effective_static_transport_identity(true, false, false));
    assert!(!effective_static_transport_identity(false, true, false));
    assert!(effective_static_transport_identity(false, false, true));
    assert!(effective_static_transport_identity(true, false, true));
}

#[test]
fn test_extract_ifac_config() {
    use std::collections::HashMap;

    // No IFAC params → None
    let params: HashMap<String, String> = HashMap::new();
    assert!(extract_ifac_config(&params, 16).is_none());

    // networkname only
    let mut params = HashMap::new();
    params.insert("networkname".into(), "testnet".into());
    let ifac = extract_ifac_config(&params, 16).unwrap();
    assert_eq!(ifac.netname.as_deref(), Some("testnet"));
    assert!(ifac.netkey.is_none());
    assert_eq!(ifac.size, 16);

    // passphrase only with custom size (in bits)
    let mut params = HashMap::new();
    params.insert("passphrase".into(), "secret".into());
    params.insert("ifac_size".into(), "64".into()); // 64 bits = 8 bytes
    let ifac = extract_ifac_config(&params, 16).unwrap();
    assert!(ifac.netname.is_none());
    assert_eq!(ifac.netkey.as_deref(), Some("secret"));
    assert_eq!(ifac.size, 8);

    // Both with alternate key names
    let mut params = HashMap::new();
    params.insert("network_name".into(), "mynet".into());
    params.insert("pass_phrase".into(), "mykey".into());
    let ifac = extract_ifac_config(&params, 8).unwrap();
    assert_eq!(ifac.netname.as_deref(), Some("mynet"));
    assert_eq!(ifac.netkey.as_deref(), Some("mykey"));
    assert_eq!(ifac.size, 8);

    // Nonsensical "None" network name and passphrase are ignored.
    let mut params = HashMap::new();
    params.insert("networkname".into(), "None".into());
    params.insert("passphrase".into(), "None".into());
    assert!(extract_ifac_config(&params, 16).is_none());

    // Empty values are ignored, but a valid sibling value still applies.
    let mut params = HashMap::new();
    params.insert("networkname".into(), String::new());
    params.insert("passphrase".into(), "secret".into());
    let ifac = extract_ifac_config(&params, 16).unwrap();
    assert!(ifac.netname.is_none());
    assert_eq!(ifac.netkey.as_deref(), Some("secret"));
}

#[test]
fn to_node_config_rnode() {
    // Verify from_config parses RNodeInterface correctly.
    // The serial port won't exist, so start() will fail at open time.
    let dir = std::env::temp_dir().join(format!("rns-test-rnode-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let config = r#"
[reticulum]
share_instance = No
enable_transport = False

[interfaces]
  [[Test RNode]]
    type = RNodeInterface
    enabled = yes
    port = /dev/nonexistent_rns_test_rnode
    frequency = 867200000
    bandwidth = 125000
    txpower = 7
    spreadingfactor = 8
    codingrate = 5
    flow_control = True
    st_alock = 5.0
    lt_alock = 2.5
    interface_mode = full
    networkname = testnet
"#;
    fs::write(dir.join("config"), config).unwrap();

    // Interface error is non-fatal: the node starts but logs the error.
    let node = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks))
        .expect("Config should parse; interface failure is non-fatal");
    node.shutdown();

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn to_node_config_pipe() {
    // Verify from_config parses PipeInterface correctly.
    // Use `cat` as a real command so it actually starts.
    let dir = std::env::temp_dir().join(format!("rns-test-pipe-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let config = r#"
[reticulum]
share_instance = No
enable_transport = False

[interfaces]
  [[Test Pipe]]
    type = PipeInterface
    enabled = yes
    command = cat
    respawn_delay = 2.5
    interface_mode = full
"#;
    fs::write(dir.join("config"), config).unwrap();

    let node = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks)).unwrap();
    // If we got here, config parsing and start() succeeded
    node.shutdown();

    let _ = fs::remove_dir_all(&dir);
}

#[test]
#[cfg(feature = "iface-backbone")]
fn to_node_config_backbone() {
    // Verify from_config parses BackboneInterface correctly.
    let dir = std::env::temp_dir().join(format!("rns-test-backbone-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let port = crate::test_support::port();

    let config = format!(
        r#"
[reticulum]
share_instance = No
enable_transport = False

[interfaces]
  [[Test Backbone]]
    type = BackboneInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {}
    interface_mode = full
"#,
        port
    );

    fs::write(dir.join("config"), config).unwrap();

    let node = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks)).unwrap();

    // Give server time to start
    thread::sleep(Duration::from_millis(100));

    // Should be able to connect
    {
        let _client = std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        // client drops here, closing the connection cleanly
    }

    // Small delay to let epoll process the disconnect
    thread::sleep(Duration::from_millis(50));

    node.shutdown();
    let _ = fs::remove_dir_all(&dir);
}

/// A Backbone listener's status row shows its configured mode and
/// gravity, not the defaults its parsed config holds until it starts.
#[test]
#[cfg(feature = "iface-backbone")]
fn backbone_listener_reports_its_configured_mode() {
    let dir = std::env::temp_dir().join(format!("rns-test-backbone-mode-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let port = crate::test_support::port();
    let config = format!(
        r#"
[reticulum]
share_instance = No
enable_transport = False

[interfaces]
  [[Mode Backbone]]
    type = BackboneInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {port}
    interface_mode = gateway
"#
    );
    fs::write(dir.join("config"), config).unwrap();
    let node = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks)).unwrap();
    let Ok(crate::event::QueryResponse::InterfaceStats(stats)) =
        node.query(crate::event::QueryRequest::InterfaceStats)
    else {
        panic!("no interface stats");
    };
    let row = stats
        .interfaces
        .iter()
        .find(|i| i.name.contains("Mode Backbone"))
        .expect("listener row");
    assert_eq!(row.mode, rns_core::constants::MODE_GATEWAY);
    node.shutdown();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
#[cfg(feature = "iface-rnode")]
fn rnode_config_defaults() {
    use crate::interface::rnode::{RNodeConfig, RNodeSubConfig};

    let config = RNodeConfig::default();
    assert_eq!(config.speed, 115200);
    assert!(config.subinterfaces.is_empty());
    assert!(config.id_interval.is_none());
    assert!(config.id_callsign.is_none());

    let sub = RNodeSubConfig {
        name: "test".into(),
        vport: 0,
        outgoing: true,
        frequency: 868_000_000,
        bandwidth: 125_000,
        txpower: 7,
        spreading_factor: 8,
        coding_rate: 5,
        flow_control: false,
        st_alock: None,
        lt_alock: None,
    };
    assert_eq!(sub.frequency, 868_000_000);
    assert_eq!(sub.bandwidth, 125_000);
    assert!(!sub.flow_control);
}

// =========================================================================
// Phase 9c: Announce + Discovery node-level tests
// =========================================================================

#[test]
fn announce_without_persisted_stamp_is_deferred_to_the_stamper() {
    let dir = tempdir().unwrap();
    let store = crate::stamps::DestinationStampStore::new(dir.path());
    let targets = crate::stamper::StampTargets {
        destination_value: StampCost::from_whole(6),
        path_request_value: StampCost::from_whole(6),
    };
    let mut node = RnsNode::start(NodeConfig::default(), Box::new(NoopCallbacks)).unwrap();
    node.set_stamp_store(store.clone());
    node.set_destination_stamping(true, targets);
    let stamper = Arc::clone(node.stamper().expect("started nodes share a stamper"));
    assert_eq!(
        stamper.targets(),
        targets,
        "the stamper grinds at the node's targets"
    );

    let identity = Identity::from_private_key(&[0x51; 64]);
    let dest = crate::Destination::single_in(
        "stamper",
        &["node"],
        rns_core::types::IdentityHash(*identity.hash()),
    );
    node.register_destination(dest.hash.0, dest.dest_type.to_wire_constant())
        .unwrap();
    assert!(node.announce_needs_stamp(&dest, &identity));

    // Destination.announce with STAMP_DESTINATIONS and no stamp: the call
    // returns at once and the worker grinds, persists and emits.
    let started = std::time::Instant::now();
    node.announce_queued(&dest, &identity, Some(b"first"))
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));

    let name_hash = rns_core::destination::name_hash("stamper", &["node"]);
    let material = rns_core::stamp::destination_stamp_material(
        &dest.hash.0,
        &identity.get_public_key().unwrap(),
        &name_hash,
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while store
        .load(&dest.hash.0, &material, targets.destination_value)
        .is_none()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "stamp was never persisted"
        );
        thread::sleep(Duration::from_millis(20));
    }

    // From now on announces are synchronous: the persisted stamp is reused.
    assert!(!node.announce_needs_stamp(&dest, &identity));
    node.announce_queued(&dest, &identity, Some(b"second"))
        .unwrap();
    assert_eq!(stamper.queued(), 0);
    let receipt = node
        .try_announce(&dest, &identity, None)
        .expect("synchronous stamped announce is admitted");
    // No interfaces: the receipt settles either way, it must not hang.
    let _ = futures::executor::block_on(receipt);

    // A confirmed-transmission announce for a destination still without a
    // stamp also defers, and its receipt settles once the worker emitted.
    let other_identity = Identity::from_private_key(&[0x52; 64]);
    let other = crate::Destination::single_in(
        "stamper",
        &["node", "other"],
        rns_core::types::IdentityHash(*other_identity.hash()),
    );
    node.register_destination(other.hash.0, other.dest_type.to_wire_constant())
        .unwrap();
    let started = std::time::Instant::now();
    let receipt = node
        .try_announce(&other, &other_identity, Some(b"deferred"))
        .expect("deferred announce is admitted");
    assert!(started.elapsed() < Duration::from_secs(1));
    let _ = futures::executor::block_on(receipt);
    assert!(!node.announce_needs_stamp(&other, &other_identity));

    node.shutdown();
}

#[test]
fn announce_builds_valid_packet() {
    let identity = Identity::new(&mut OsRng);
    let identity_hash = rns_core::types::IdentityHash(*identity.hash());

    let node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            link_proof_verify_threads: Default::default(),
            stamps: Default::default(),
            transport_enabled: false,
            static_transport_identity: false,
            local_hops_delta: false,
            identity: None,
            network_identity: None,
            interfaces: vec![],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            ratchet_store: None,
            ratchet_expiry: Duration::from_secs(rns_core::constants::RATCHET_EXPIRY),
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            direct_connect_policy: Default::default(),
            direct_connect_allow_private_endpoints: false,
            direct_connect_allowed_identities: Vec::new(),
            direct_connect_reupgrade: Default::default(),
            probe_rate_limit: Default::default(),
            device: None,
            underlay_mark: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery: Default::default(),
            shared_instance: Default::default(),
            autoconnect_interface_mode: None,
            autoconnect_interface_gravity: 0,
            autoconnect_announces_to_internal: false,
            autoconnect_unverified_implementations: false,
            discovery_required_value: None,
            respond_to_probes: false,
            use_implicit_proof: true,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: crate::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_rate_defaults: AnnounceRateDefaults::default(),
            ingress_control_defaults: rns_core::transport::types::IngressControlConfig::enabled(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: None,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "hooks")]
            provider_bridge: None,
        },
        Box::new(NoopCallbacks),
    )
    .unwrap();

    let dest = crate::destination::Destination::single_in("test", &["echo"], identity_hash);

    // Register destination first
    node.register_destination(dest.hash.0, dest.dest_type.to_wire_constant())
        .unwrap();

    // Announce should succeed (though no interfaces to send on)
    let result = node.announce_queued(&dest, &identity, Some(b"hello"));
    assert!(result.is_ok());

    node.shutdown();
}

#[test]
fn has_path_and_hops_to() {
    let node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            link_proof_verify_threads: Default::default(),
            stamps: Default::default(),
            transport_enabled: false,
            static_transport_identity: false,
            local_hops_delta: false,
            identity: None,
            network_identity: None,
            interfaces: vec![],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            ratchet_store: None,
            ratchet_expiry: Duration::from_secs(rns_core::constants::RATCHET_EXPIRY),
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            direct_connect_policy: Default::default(),
            direct_connect_allow_private_endpoints: false,
            direct_connect_allowed_identities: Vec::new(),
            direct_connect_reupgrade: Default::default(),
            probe_rate_limit: Default::default(),
            device: None,
            underlay_mark: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery: Default::default(),
            shared_instance: Default::default(),
            autoconnect_interface_mode: None,
            autoconnect_interface_gravity: 0,
            autoconnect_announces_to_internal: false,
            autoconnect_unverified_implementations: false,
            discovery_required_value: None,
            respond_to_probes: false,
            use_implicit_proof: true,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: crate::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_rate_defaults: AnnounceRateDefaults::default(),
            ingress_control_defaults: rns_core::transport::types::IngressControlConfig::enabled(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: None,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "hooks")]
            provider_bridge: None,
        },
        Box::new(NoopCallbacks),
    )
    .unwrap();

    let dh = rns_core::types::DestHash([0xAA; 16]);

    // No path should exist
    assert!(!node.has_path(&dh).unwrap());
    assert_eq!(node.hops_to(&dh).unwrap(), None);

    node.shutdown();
}

#[test]
fn recall_identity_none_when_unknown() {
    let node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            link_proof_verify_threads: Default::default(),
            stamps: Default::default(),
            transport_enabled: false,
            static_transport_identity: false,
            local_hops_delta: false,
            identity: None,
            network_identity: None,
            interfaces: vec![],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            ratchet_store: None,
            ratchet_expiry: Duration::from_secs(rns_core::constants::RATCHET_EXPIRY),
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            direct_connect_policy: Default::default(),
            direct_connect_allow_private_endpoints: false,
            direct_connect_allowed_identities: Vec::new(),
            direct_connect_reupgrade: Default::default(),
            probe_rate_limit: Default::default(),
            device: None,
            underlay_mark: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery: Default::default(),
            shared_instance: Default::default(),
            autoconnect_interface_mode: None,
            autoconnect_interface_gravity: 0,
            autoconnect_announces_to_internal: false,
            autoconnect_unverified_implementations: false,
            discovery_required_value: None,
            respond_to_probes: false,
            use_implicit_proof: true,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: crate::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_rate_defaults: AnnounceRateDefaults::default(),
            ingress_control_defaults: rns_core::transport::types::IngressControlConfig::enabled(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: None,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "hooks")]
            provider_bridge: None,
        },
        Box::new(NoopCallbacks),
    )
    .unwrap();

    let dh = rns_core::types::DestHash([0xBB; 16]);
    assert!(node.recall_identity(&dh).unwrap().is_none());

    node.shutdown();
}

#[test]
fn request_path_does_not_crash() {
    let node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            link_proof_verify_threads: Default::default(),
            stamps: Default::default(),
            transport_enabled: false,
            static_transport_identity: false,
            local_hops_delta: false,
            identity: None,
            network_identity: None,
            interfaces: vec![],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            ratchet_store: None,
            ratchet_expiry: Duration::from_secs(rns_core::constants::RATCHET_EXPIRY),
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            direct_connect_policy: Default::default(),
            direct_connect_allow_private_endpoints: false,
            direct_connect_allowed_identities: Vec::new(),
            direct_connect_reupgrade: Default::default(),
            probe_rate_limit: Default::default(),
            device: None,
            underlay_mark: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery: Default::default(),
            shared_instance: Default::default(),
            autoconnect_interface_mode: None,
            autoconnect_interface_gravity: 0,
            autoconnect_announces_to_internal: false,
            autoconnect_unverified_implementations: false,
            discovery_required_value: None,
            respond_to_probes: false,
            use_implicit_proof: true,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: crate::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_rate_defaults: AnnounceRateDefaults::default(),
            ingress_control_defaults: rns_core::transport::types::IngressControlConfig::enabled(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: None,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "hooks")]
            provider_bridge: None,
        },
        Box::new(NoopCallbacks),
    )
    .unwrap();

    let dh = rns_core::types::DestHash([0xCC; 16]);
    assert!(node.request_path(&dh).is_ok());

    // Small wait for the event to be processed
    thread::sleep(Duration::from_millis(50));

    node.shutdown();
}

#[test]
fn create_link_returns_error_while_draining() {
    let node = RnsNode::start(NodeConfig::default(), Box::new(NoopCallbacks)).unwrap();

    node.begin_drain(Duration::from_secs(1)).unwrap();
    assert!(node.create_link([0xAB; 16], [0xCD; 32]).is_err());

    node.shutdown();
}

#[test]
fn request_path_returns_error_while_draining() {
    let node = RnsNode::start(NodeConfig::default(), Box::new(NoopCallbacks)).unwrap();

    node.begin_drain(Duration::from_secs(1)).unwrap();
    assert!(node
        .request_path(&rns_core::types::DestHash([0xAB; 16]))
        .is_err());

    node.shutdown();
}

// =========================================================================
// Phase 9d: send_packet + register_destination_with_proof tests
// =========================================================================

#[test]
fn send_packet_returns_error_while_draining() {
    let node = RnsNode::start(NodeConfig::default(), Box::new(NoopCallbacks)).unwrap();
    let dest = crate::destination::Destination::plain("drain-test", &["send"]);

    node.begin_drain(Duration::from_secs(1)).unwrap();
    assert!(node.send_packet_queued(&dest, b"hello").is_err());

    node.shutdown();
}

#[test]
fn send_packet_plain() {
    let node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            link_proof_verify_threads: Default::default(),
            stamps: Default::default(),
            transport_enabled: false,
            static_transport_identity: false,
            local_hops_delta: false,
            identity: None,
            network_identity: None,
            interfaces: vec![],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            ratchet_store: None,
            ratchet_expiry: Duration::from_secs(rns_core::constants::RATCHET_EXPIRY),
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            direct_connect_policy: Default::default(),
            direct_connect_allow_private_endpoints: false,
            direct_connect_allowed_identities: Vec::new(),
            direct_connect_reupgrade: Default::default(),
            probe_rate_limit: Default::default(),
            device: None,
            underlay_mark: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery: Default::default(),
            shared_instance: Default::default(),
            autoconnect_interface_mode: None,
            autoconnect_interface_gravity: 0,
            autoconnect_announces_to_internal: false,
            autoconnect_unverified_implementations: false,
            discovery_required_value: None,
            respond_to_probes: false,
            use_implicit_proof: true,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: crate::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_rate_defaults: AnnounceRateDefaults::default(),
            ingress_control_defaults: rns_core::transport::types::IngressControlConfig::enabled(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: None,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "hooks")]
            provider_bridge: None,
        },
        Box::new(NoopCallbacks),
    )
    .unwrap();

    let dest = crate::destination::Destination::plain("test", &["echo"]);
    let result = node.send_packet_queued(&dest, b"hello world");
    assert!(result.is_ok());

    let packet_hash = result.unwrap();
    // Packet hash should be non-zero
    assert_ne!(packet_hash.0, [0u8; 32]);

    // Small wait for the event to be processed
    thread::sleep(Duration::from_millis(50));

    node.shutdown();
}

#[test]
fn send_packet_single_requires_public_key() {
    let node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            link_proof_verify_threads: Default::default(),
            stamps: Default::default(),
            transport_enabled: false,
            static_transport_identity: false,
            local_hops_delta: false,
            identity: None,
            network_identity: None,
            interfaces: vec![],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            ratchet_store: None,
            ratchet_expiry: Duration::from_secs(rns_core::constants::RATCHET_EXPIRY),
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            direct_connect_policy: Default::default(),
            direct_connect_allow_private_endpoints: false,
            direct_connect_allowed_identities: Vec::new(),
            direct_connect_reupgrade: Default::default(),
            probe_rate_limit: Default::default(),
            device: None,
            underlay_mark: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery: Default::default(),
            shared_instance: Default::default(),
            autoconnect_interface_mode: None,
            autoconnect_interface_gravity: 0,
            autoconnect_announces_to_internal: false,
            autoconnect_unverified_implementations: false,
            discovery_required_value: None,
            respond_to_probes: false,
            use_implicit_proof: true,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: crate::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_rate_defaults: AnnounceRateDefaults::default(),
            ingress_control_defaults: rns_core::transport::types::IngressControlConfig::enabled(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: None,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "hooks")]
            provider_bridge: None,
        },
        Box::new(NoopCallbacks),
    )
    .unwrap();

    // single_in has no public_key — sending should fail
    let dest = crate::destination::Destination::single_in(
        "test",
        &["echo"],
        rns_core::types::IdentityHash([0x42; 16]),
    );
    let result = node.send_packet_queued(&dest, b"hello");
    assert!(result.is_err(), "single_in has no public_key, should fail");

    node.shutdown();
}

#[test]
fn send_packet_single_encrypts() {
    let node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            link_proof_verify_threads: Default::default(),
            stamps: Default::default(),
            transport_enabled: false,
            static_transport_identity: false,
            local_hops_delta: false,
            identity: None,
            network_identity: None,
            interfaces: vec![],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            ratchet_store: None,
            ratchet_expiry: Duration::from_secs(rns_core::constants::RATCHET_EXPIRY),
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            direct_connect_policy: Default::default(),
            direct_connect_allow_private_endpoints: false,
            direct_connect_allowed_identities: Vec::new(),
            direct_connect_reupgrade: Default::default(),
            probe_rate_limit: Default::default(),
            device: None,
            underlay_mark: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery: Default::default(),
            shared_instance: Default::default(),
            autoconnect_interface_mode: None,
            autoconnect_interface_gravity: 0,
            autoconnect_announces_to_internal: false,
            autoconnect_unverified_implementations: false,
            discovery_required_value: None,
            respond_to_probes: false,
            use_implicit_proof: true,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: crate::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_rate_defaults: AnnounceRateDefaults::default(),
            ingress_control_defaults: rns_core::transport::types::IngressControlConfig::enabled(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: None,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "hooks")]
            provider_bridge: None,
        },
        Box::new(NoopCallbacks),
    )
    .unwrap();

    // Create a proper OUT SINGLE destination with a real identity's public key
    let remote_identity = Identity::new(&mut OsRng);
    let recalled = crate::destination::AnnouncedIdentity {
        dest_hash: rns_core::types::DestHash([0xAA; 16]),
        identity_hash: rns_core::types::IdentityHash(*remote_identity.hash()),
        public_key: remote_identity.get_public_key().unwrap(),
        app_data: None,
        hops: 1,
        received_at: 0.0,
        receiving_interface: rns_core::transport::types::InterfaceId(0),
        rssi: Some(-100),
        snr: Some(10.5),
    };
    let dest = crate::destination::Destination::single_out("test", &["echo"], &recalled);

    let result = node.send_packet_queued(&dest, b"secret message");
    assert!(result.is_ok());

    let packet_hash = result.unwrap();
    assert_ne!(packet_hash.0, [0u8; 32]);

    thread::sleep(Duration::from_millis(50));
    node.shutdown();
}

#[test]
fn register_destination_with_proof_prove_all() {
    let node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            link_proof_verify_threads: Default::default(),
            stamps: Default::default(),
            transport_enabled: false,
            static_transport_identity: false,
            local_hops_delta: false,
            identity: None,
            network_identity: None,
            interfaces: vec![],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            ratchet_store: None,
            ratchet_expiry: Duration::from_secs(rns_core::constants::RATCHET_EXPIRY),
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            direct_connect_policy: Default::default(),
            direct_connect_allow_private_endpoints: false,
            direct_connect_allowed_identities: Vec::new(),
            direct_connect_reupgrade: Default::default(),
            probe_rate_limit: Default::default(),
            device: None,
            underlay_mark: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery: Default::default(),
            shared_instance: Default::default(),
            autoconnect_interface_mode: None,
            autoconnect_interface_gravity: 0,
            autoconnect_announces_to_internal: false,
            autoconnect_unverified_implementations: false,
            discovery_required_value: None,
            respond_to_probes: false,
            use_implicit_proof: true,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: crate::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_rate_defaults: AnnounceRateDefaults::default(),
            ingress_control_defaults: rns_core::transport::types::IngressControlConfig::enabled(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: None,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "hooks")]
            provider_bridge: None,
        },
        Box::new(NoopCallbacks),
    )
    .unwrap();

    let identity = Identity::new(&mut OsRng);
    let ih = rns_core::types::IdentityHash(*identity.hash());
    let dest = crate::destination::Destination::single_in("echo", &["request"], ih)
        .set_proof_strategy(rns_core::types::ProofStrategy::ProveAll);
    let prv_key = identity.get_private_key().unwrap();

    let result = node.register_destination_with_proof(&dest, Some(prv_key));
    assert!(result.is_ok());

    // Small wait for the events to be processed
    thread::sleep(Duration::from_millis(50));

    node.shutdown();
}

#[test]
fn register_destination_with_proof_prove_none() {
    let node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            link_proof_verify_threads: Default::default(),
            stamps: Default::default(),
            transport_enabled: false,
            static_transport_identity: false,
            local_hops_delta: false,
            identity: None,
            network_identity: None,
            interfaces: vec![],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            ratchet_store: None,
            ratchet_expiry: Duration::from_secs(rns_core::constants::RATCHET_EXPIRY),
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            direct_connect_policy: Default::default(),
            direct_connect_allow_private_endpoints: false,
            direct_connect_allowed_identities: Vec::new(),
            direct_connect_reupgrade: Default::default(),
            probe_rate_limit: Default::default(),
            device: None,
            underlay_mark: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery: Default::default(),
            shared_instance: Default::default(),
            autoconnect_interface_mode: None,
            autoconnect_interface_gravity: 0,
            autoconnect_announces_to_internal: false,
            autoconnect_unverified_implementations: false,
            discovery_required_value: None,
            respond_to_probes: false,
            use_implicit_proof: true,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: crate::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_rate_defaults: AnnounceRateDefaults::default(),
            ingress_control_defaults: rns_core::transport::types::IngressControlConfig::enabled(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: None,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "hooks")]
            provider_bridge: None,
        },
        Box::new(NoopCallbacks),
    )
    .unwrap();

    // ProveNone should not send RegisterProofStrategy event
    let dest = crate::destination::Destination::plain("test", &["data"])
        .set_proof_strategy(rns_core::types::ProofStrategy::ProveNone);

    let result = node.register_destination_with_proof(&dest, None);
    assert!(result.is_ok());

    thread::sleep(Duration::from_millis(50));
    node.shutdown();
}

#[test]
fn destination_stamp_below_target_value_is_regenerated() {
    // Destination._announce (d7749b0b): the held stamp is reloaded or
    // regenerated when its value is below `target_value`, and both the
    // lookup and the grind use the target (Destination.py:319-323).
    let dir = tempdir().unwrap();
    let store = crate::stamps::DestinationStampStore::new(dir.path());
    let targets = crate::stamper::StampTargets {
        destination_value: StampCost::from_whole(4),
        path_request_value: StampCost::from_whole(4),
    };
    let identity = Identity::from_private_key(&[0x52; 64]);
    let mut dest = crate::Destination::single_in(
        "stamper",
        &["target"],
        rns_core::types::IdentityHash(*identity.hash()),
    );
    let name_hash = rns_core::destination::name_hash("stamper", &["target"]);
    let material = rns_core::stamp::destination_stamp_material(
        &dest.hash.0,
        &identity.get_public_key().unwrap(),
        &name_hash,
    );

    ensure_destination_stamp(&store, targets, &dest, &identity).unwrap();
    let (first, first_value) = store
        .load(&dest.hash.0, &material, StampCost::ZERO)
        .expect("stamp persisted at the default target");
    assert!(first_value.meets(StampCost::from_whole(4)));

    // A target the held stamp already meets reuses it.
    dest.set_value(f64::from(first_value.whole()));
    ensure_destination_stamp(&store, targets, &dest, &identity).unwrap();
    assert_eq!(
        store
            .load(&dest.hash.0, &material, StampCost::ZERO)
            .unwrap()
            .0,
        first
    );

    // A target above the held value regenerates and persists a stamp
    // that reaches it.
    let raised = first_value.whole() as u8 + 1;
    dest.set_value(f64::from(raised));
    ensure_destination_stamp(&store, targets, &dest, &identity).unwrap();
    let (second, second_value) = store
        .load(&dest.hash.0, &material, StampCost::ZERO)
        .unwrap();
    assert_ne!(second, first);
    assert!(second_value.meets(StampCost::from_whole(u32::from(raised))));

    // The announce builder reloads at the same target and carries the
    // regenerated stamp and the configured default link cost.
    let (tx, _rx) = crate::event::channel();
    tx.link_request_costs()
        .set_default_cost(StampCost::from_whole(7));
    let (packet, _) =
        build_announce_packet(&tx, Some(&store), true, targets, &dest, &identity, None).unwrap();
    let announce = rns_core::announce::AnnounceData::unpack(packet.data(), false).unwrap();
    let app_data = announce
        .app_data
        .expect("stamped announce carries app data");
    let ext = &app_data[app_data.len() - rns_core::constants::EXT_PAYLOAD_LENGTH..];
    assert_eq!(ext[0], rns_core::constants::EXT_PAYLOAD_MARKER);
    assert_eq!(
        &ext[rns_core::constants::EXT_HEADER_LENGTH
            ..rns_core::constants::EXT_HEADER_LENGTH + rns_core::constants::STAMP_LENGTH],
        &second[..]
    );
    assert_eq!(ext[rns_core::constants::EXT_PAYLOAD_LENGTH - 1], 7);

    // Without a stamp store, as a shared instance client has, the
    // announce goes out unstamped instead of failing.
    let (packet, _) =
        build_announce_packet(&tx, None, true, targets, &dest, &identity, Some(b"app")).unwrap();
    let announce = rns_core::announce::AnnounceData::unpack(packet.data(), false).unwrap();
    assert_eq!(announce.app_data.as_deref(), Some(&b"app"[..]));
}

#[cfg(feature = "iface-local")]
#[test]
fn a_node_discovering_interfaces_wants_their_announces() {
    // Upstream 884f109b: InterfaceDiscovery registers the type, so a
    // node with `required_only` still receives discovery announces.
    let discovery_type = "rnstransport.discovery.interface";
    let node = RnsNode::start(
        NodeConfig {
            discover_interfaces: true,
            ..NodeConfig::default()
        },
        Box::new(NoopCallbacks),
    )
    .unwrap();
    assert!(node.unwants_destination_type(discovery_type));
    node.shutdown();

    let node = RnsNode::start(NodeConfig::default(), Box::new(NoopCallbacks)).unwrap();
    assert!(!node.unwants_destination_type(discovery_type));
    node.shutdown();
}

#[test]
fn from_config_applies_the_stamps_section_and_hop_limiter() {
    let dir = tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "[reticulum]\nshare_instance = No\n\
             hop_limiter = 12\n\
             [stamps]\n\
             enforce_stamps = yes\n\
             stamp_destinations = yes\n\
             stamp_prs = yes\n\
             always_stamp_lrs = yes\n\
             destination_cost = 18\n\
             destination_value = 27\n\
             pr_cost = 11\n\
             pr_value = 13\n\
             lr_cost = 9\n\
             pr_stamp_timeout = 3\n",
    )
    .unwrap();
    let node = RnsNode::from_private_config(dir.path(), dir.path(), None, Box::new(NoopCallbacks))
        .unwrap();

    assert!(node.stamp_destinations.load(Ordering::Relaxed));
    assert_eq!(
        node.stamp_targets,
        crate::stamper::StampTargets {
            destination_value: StampCost::from_whole(27),
            path_request_value: StampCost::from_whole(13),
        }
    );
    // `lr_cost` and `enforce_stamps` reach the shared link cost table.
    assert_eq!(node.link_cost(&[0u8; 16]), 9.0);
    assert!(node.link_request_stamps_enforced());
    let stamper = node.stamper().unwrap();
    assert_eq!(stamper.targets(), node.stamp_targets);
    assert_eq!(stamper.path_request_timeout(), Duration::from_secs(3));

    // The runtime keys report the configured values as their startup
    // defaults, so a reset returns to the config file and not to the
    // compile-time constants.
    for key in [
        "global.stamp_destinations",
        "global.stamp_path_requests",
        "global.stamps_enforced",
        "global.stamp_link_requests",
        "global.always_stamp_link_requests",
    ] {
        let QueryResponse::RuntimeConfigEntry(Some(entry)) = node
            .query(QueryRequest::GetRuntimeConfig { key: key.into() })
            .unwrap()
        else {
            panic!("expected runtime config entry for {key}");
        };
        assert_eq!(
            entry.value,
            crate::event::RuntimeConfigValue::Bool(true),
            "{key}"
        );
        assert_eq!(
            entry.default,
            crate::event::RuntimeConfigValue::Bool(true),
            "{key}"
        );
    }
    node.shutdown();
}

#[test]
fn start_applies_the_node_config_stamps() {
    // Upstream eb826cde: `Reticulum(enable_stamping=True,
    // enforce_stamps=True)` for a node configured in code.
    let node = RnsNode::start(
        NodeConfig {
            stamps: config::StampsSection {
                stamp_destinations: true,
                stamp_prs: true,
                stamps_enforced: true,
                lr_stamps_enforced: true,
                lr_cost: StampCost::from_whole(9),
                ..Default::default()
            },
            ..NodeConfig::default()
        },
        Box::new(NoopCallbacks),
    )
    .unwrap();

    assert!(node.stamp_destinations.load(Ordering::Relaxed));
    assert_eq!(node.link_cost(&[0u8; 16]), 9.0);
    assert!(node.link_request_stamps_enforced());
    for key in [
        "global.stamp_destinations",
        "global.stamp_path_requests",
        "global.stamps_enforced",
        "global.lr_stamps_enforced",
    ] {
        let QueryResponse::RuntimeConfigEntry(Some(entry)) = node
            .query(QueryRequest::GetRuntimeConfig { key: key.into() })
            .unwrap()
        else {
            panic!("expected runtime config entry for {key}");
        };
        assert_eq!(
            entry.value,
            crate::event::RuntimeConfigValue::Bool(true),
            "{key}"
        );
        assert_eq!(
            entry.default,
            crate::event::RuntimeConfigValue::Bool(true),
            "{key}"
        );
    }
    node.shutdown();
}

#[test]
fn published_blackhole_destination_requires_its_link_cost() {
    let identity = Identity::new(&mut OsRng);
    let blackhole = crate::management::blackhole_dest_hash(identity.hash());
    let node = RnsNode::start(
        NodeConfig {
            identity: Some(Identity::from_private_key(
                &identity.get_private_key().unwrap(),
            )),
            // On a transport instance the blackhole destination
            // belongs to this identity, not an ephemeral one.
            transport_enabled: true,
            management: crate::ManagementConfig {
                publish_blackhole: true,
                ..Default::default()
            },
            ..NodeConfig::default()
        },
        Box::new(NoopCallbacks),
    )
    .unwrap();

    assert_eq!(node.link_cost(&blackhole), 5.25);
    // Other destinations keep the `LR_COST` default.
    assert_eq!(node.link_cost(&[0u8; 16]), 12.5);
    node.shutdown();
}

#[test]
fn single_packets_carry_the_signing_key_their_proof_is_checked_with() {
    let identity = Identity::new(&mut OsRng);
    let public_key = identity.get_public_key().unwrap();
    let announced = crate::destination::AnnouncedIdentity {
        dest_hash: rns_core::types::DestHash([0x23; 16]),
        identity_hash: rns_core::types::IdentityHash(*identity.hash()),
        public_key,
        app_data: None,
        hops: 1,
        received_at: time::now(),
        receiving_interface: rns_core::transport::types::InterfaceId(0),
        rssi: None,
        snr: None,
    };
    let single = crate::destination::Destination::single_out("test", &["proof"], &announced);
    assert_eq!(
        single_proof_key(&single),
        Some(public_key[32..].try_into().unwrap())
    );
    let plain = crate::destination::Destination::plain("test", &["proof"]);
    assert_eq!(single_proof_key(&plain), None);
}

/// The display names a configured interface gets, as
/// `configured_*_interfaces_get_upstream_display_names` check them.
#[cfg(any(
    feature = "iface-tcp",
    feature = "iface-udp",
    feature = "iface-backbone",
    feature = "iface-kiss"
))]
fn configured_display(name: &str, id: u64) -> ConfiguredDisplay {
    let parsed = config::parse(
            "[interfaces]\n\
             [[TCP Peer]]\n  type = TCPClientInterface\n  target_host = 10.0.0.1\n  target_port = 4242\n\
             [[TCP Server]]\n  type = TCPServerInterface\n  listen_ip = ::\n  listen_port = 4243\n  mode = gateway\n\
             [[UDP]]\n  type = UDPInterface\n  listen_ip = 0.0.0.0\n  listen_port = 4244\n  forward_ip = 255.255.255.255\n  forward_port = 4244\n\
             [[Backbone]]\n  type = BackboneInterface\n  listen_on = 0.0.0.0\n  port = 4245\n\
             [[Backbone Peer]]\n  type = BackboneInterface\n  remote = example.org\n  target_port = 4246\n\
             [[Radio]]\n  type = KISSInterface\n  port = /dev/null\n",
        )
        .unwrap();
    let registry = crate::interface::registry::InterfaceRegistry::with_builtins();
    let iface = parsed
        .interfaces
        .iter()
        .find(|iface| iface.name == name)
        .unwrap();
    let config = parse_managed_interface(
        iface,
        &parsed,
        Path::new("/tmp"),
        rns_core::transport::types::InterfaceId(id),
        &registry,
    )
    .unwrap();
    ConfiguredDisplay::of(&config, None)
}

#[test]
#[cfg(feature = "iface-tcp")]
fn configured_tcp_interfaces_get_upstream_display_names() {
    let tcp = configured_display("TCP Peer", 1);
    assert_eq!(
        tcp.interface.as_deref(),
        Some("TCPInterface[TCP Peer/10.0.0.1:4242]")
    );
    assert!(tcp.listener.is_none() && tcp.listener_stat.is_none());

    let server = configured_display("TCP Server", 2);
    assert!(server.interface.is_none());
    assert_eq!(
        server.listener,
        Some((
            rns_core::transport::types::InterfaceId(2),
            "TCPServerInterface[TCP Server/[::]:4243]".to_string()
        ))
    );
    let stat = server.listener_stat.unwrap();
    assert_eq!(stat.name, "TCP Server");
    assert_eq!(stat.interface_type, "TCPServerInterface");
    assert_eq!(stat.mode, rns_core::constants::MODE_GATEWAY);
    assert!(matches!(
        stat.clients,
        crate::driver::ListenerClients::Spawned
    ));
}

#[test]
#[cfg(feature = "iface-udp")]
fn configured_udp_interfaces_get_upstream_display_names() {
    assert_eq!(
        configured_display("UDP", 3).interface.as_deref(),
        Some("UDPInterface[UDP/0.0.0.0:4244]")
    );
}

#[test]
#[cfg(feature = "iface-backbone")]
fn configured_backbone_interfaces_get_upstream_display_names() {
    assert_eq!(
        configured_display("Backbone", 4)
            .listener
            .map(|(_, name)| name)
            .as_deref(),
        Some("BackboneInterface[Backbone/0.0.0.0:4245]")
    );
    assert_eq!(
        configured_display("Backbone Peer", 5).interface.as_deref(),
        Some("BackboneInterface[Backbone Peer/example.org:4246]")
    );
}

#[test]
#[cfg(feature = "iface-kiss")]
fn configured_kiss_interfaces_get_named_by_the_driver() {
    // Named `{type}[{name}]` by the driver.
    let radio = configured_display("Radio", 6);
    assert!(radio.interface.is_none() && radio.listener.is_none());
}

/// A node identity without its private key is refused at start, not a
/// panic.
#[test]
fn start_refuses_an_identity_without_private_key() {
    let full = Identity::new(&mut OsRng);
    let public = Identity::from_public_key(&full.get_public_key().unwrap()).unwrap();
    let config = NodeConfig {
        identity: Some(public),
        ..NodeConfig::default()
    };
    let error = RnsNode::start(config, Box::new(NoopCallbacks))
        .err()
        .expect("a node needs a private key");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}
