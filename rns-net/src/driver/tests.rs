use super::*;
    use crate::event;
    use crate::interface::Writer;
    use rns_core::announce::AnnounceData;
    use rns_core::constants;
    use rns_core::packet::PacketFlags;
    use rns_core::transport::types::InterfaceInfo;
    use rns_crypto::identity::Identity;
    use std::io;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    struct MockWriter {
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl MockWriter {
        fn new() -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
            let sent = Arc::new(Mutex::new(Vec::new()));
            (MockWriter { sent: sent.clone() }, sent)
        }
    }

    impl Writer for MockWriter {
        fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
            self.sent.lock().unwrap().push(data.to_vec());
            Ok(())
        }
    }

    struct BlockingWriter {
        entered_tx: std::sync::mpsc::Sender<()>,
        release_rx: std::sync::mpsc::Receiver<()>,
    }

    impl Writer for BlockingWriter {
        fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
            let _ = self.entered_tx.send(());
            let _ = self.release_rx.recv();
            Ok(())
        }
    }

    struct WouldBlockWriter {
        attempts: Arc<Mutex<usize>>,
    }

    impl WouldBlockWriter {
        fn new() -> (Self, Arc<Mutex<usize>>) {
            let attempts = Arc::new(Mutex::new(0));
            (
                WouldBlockWriter {
                    attempts: attempts.clone(),
                },
                attempts,
            )
        }
    }

    impl Writer for WouldBlockWriter {
        fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
            *self.attempts.lock().unwrap() += 1;
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "intentional stall",
            ))
        }
    }

    fn wait_for_sent_len(sent: &Arc<Mutex<Vec<Vec<u8>>>>, expected: usize) {
        let deadline = Instant::now() + Duration::from_millis(200);
        while Instant::now() < deadline {
            if sent.lock().unwrap().len() == expected {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(sent.lock().unwrap().len(), expected);
    }

    use rns_core::types::{DestHash, IdentityHash, LinkId as TypedLinkId, PacketHash};

    struct MockCallbacks {
        announces: Arc<Mutex<Vec<(DestHash, u8)>>>,
        paths: Arc<Mutex<Vec<(DestHash, u8)>>>,
        deliveries: Arc<Mutex<Vec<DestHash>>>,
        iface_ups: Arc<Mutex<Vec<InterfaceId>>>,
        iface_downs: Arc<Mutex<Vec<InterfaceId>>>,
        link_established: Arc<Mutex<Vec<(TypedLinkId, f64, bool)>>>,
        link_closed: Arc<Mutex<Vec<TypedLinkId>>>,
        remote_identified: Arc<Mutex<Vec<(TypedLinkId, IdentityHash)>>>,
        resources_received: Arc<Mutex<Vec<(TypedLinkId, Vec<u8>)>>>,
        resource_completed: Arc<Mutex<Vec<TypedLinkId>>>,
        resource_failed: Arc<Mutex<Vec<(TypedLinkId, String)>>>,
        channel_messages: Arc<Mutex<Vec<(TypedLinkId, u16, Vec<u8>)>>>,
        link_data: Arc<Mutex<Vec<(TypedLinkId, u8, Vec<u8>)>>>,
        responses: Arc<Mutex<Vec<(TypedLinkId, [u8; 16], Vec<u8>)>>>,
        proofs: Arc<Mutex<Vec<(DestHash, PacketHash, f64)>>>,
        proof_requested: Arc<Mutex<Vec<(DestHash, PacketHash)>>>,
    }

    impl MockCallbacks {
        fn new() -> (
            Self,
            Arc<Mutex<Vec<(DestHash, u8)>>>,
            Arc<Mutex<Vec<(DestHash, u8)>>>,
            Arc<Mutex<Vec<DestHash>>>,
            Arc<Mutex<Vec<InterfaceId>>>,
            Arc<Mutex<Vec<InterfaceId>>>,
        ) {
            let announces = Arc::new(Mutex::new(Vec::new()));
            let paths = Arc::new(Mutex::new(Vec::new()));
            let deliveries = Arc::new(Mutex::new(Vec::new()));
            let iface_ups = Arc::new(Mutex::new(Vec::new()));
            let iface_downs = Arc::new(Mutex::new(Vec::new()));
            (
                MockCallbacks {
                    announces: announces.clone(),
                    paths: paths.clone(),
                    deliveries: deliveries.clone(),
                    iface_ups: iface_ups.clone(),
                    iface_downs: iface_downs.clone(),
                    link_established: Arc::new(Mutex::new(Vec::new())),
                    link_closed: Arc::new(Mutex::new(Vec::new())),
                    remote_identified: Arc::new(Mutex::new(Vec::new())),
                    resources_received: Arc::new(Mutex::new(Vec::new())),
                    resource_completed: Arc::new(Mutex::new(Vec::new())),
                    resource_failed: Arc::new(Mutex::new(Vec::new())),
                    channel_messages: Arc::new(Mutex::new(Vec::new())),
                    link_data: Arc::new(Mutex::new(Vec::new())),
                    responses: Arc::new(Mutex::new(Vec::new())),
                    proofs: Arc::new(Mutex::new(Vec::new())),
                    proof_requested: Arc::new(Mutex::new(Vec::new())),
                },
                announces,
                paths,
                deliveries,
                iface_ups,
                iface_downs,
            )
        }

        fn with_link_tracking() -> (
            Self,
            Arc<Mutex<Vec<(TypedLinkId, f64, bool)>>>,
            Arc<Mutex<Vec<TypedLinkId>>>,
            Arc<Mutex<Vec<(TypedLinkId, IdentityHash)>>>,
        ) {
            let link_established = Arc::new(Mutex::new(Vec::new()));
            let link_closed = Arc::new(Mutex::new(Vec::new()));
            let remote_identified = Arc::new(Mutex::new(Vec::new()));
            (
                MockCallbacks {
                    announces: Arc::new(Mutex::new(Vec::new())),
                    paths: Arc::new(Mutex::new(Vec::new())),
                    deliveries: Arc::new(Mutex::new(Vec::new())),
                    iface_ups: Arc::new(Mutex::new(Vec::new())),
                    iface_downs: Arc::new(Mutex::new(Vec::new())),
                    link_established: link_established.clone(),
                    link_closed: link_closed.clone(),
                    remote_identified: remote_identified.clone(),
                    resources_received: Arc::new(Mutex::new(Vec::new())),
                    resource_completed: Arc::new(Mutex::new(Vec::new())),
                    resource_failed: Arc::new(Mutex::new(Vec::new())),
                    channel_messages: Arc::new(Mutex::new(Vec::new())),
                    link_data: Arc::new(Mutex::new(Vec::new())),
                    responses: Arc::new(Mutex::new(Vec::new())),
                    proofs: Arc::new(Mutex::new(Vec::new())),
                    proof_requested: Arc::new(Mutex::new(Vec::new())),
                },
                link_established,
                link_closed,
                remote_identified,
            )
        }
    }

    fn new_test_driver() -> Driver {
        let transport_config = TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
        };
        let (callbacks, _, _, _, _, _) = MockCallbacks::new();
        let (tx, rx) = event::channel();
        let mut driver = Driver::new(transport_config, rx, tx, Box::new(callbacks));
        driver.set_tick_interval_handle(Arc::new(AtomicU64::new(1000)));
        driver
    }

    fn make_announced_identity(
        dest_hash: [u8; 16],
        received_at: f64,
        receiving_interface: InterfaceId,
    ) -> crate::destination::AnnouncedIdentity {
        crate::destination::AnnouncedIdentity {
            dest_hash: rns_core::types::DestHash(dest_hash),
            identity_hash: rns_core::types::IdentityHash([dest_hash[0]; 16]),
            public_key: [dest_hash[0]; 64],
            app_data: None,
            hops: 1,
            received_at,
            receiving_interface,
        }
    }

    fn make_known_destination_state(
        dest_hash: [u8; 16],
        received_at: f64,
        receiving_interface: InterfaceId,
    ) -> KnownDestinationState {
        KnownDestinationState {
            announced: make_announced_identity(dest_hash, received_at, receiving_interface),
            was_used: false,
            last_used_at: None,
            retained: false,
        }
    }

    #[cfg(feature = "iface-backbone")]
    fn make_pool_candidate(name: &str, port: u16, id: u64) -> BackbonePeerPoolCandidateConfig {
        let mut client = BackboneClientConfig {
            name: name.to_string(),
            target_host: "127.0.0.1".to_string(),
            target_port: port,
            interface_id: InterfaceId(id),
            reconnect_wait: Duration::from_millis(10),
            max_reconnect_tries: Some(0),
            connect_timeout: Duration::from_millis(50),
            transport_identity: None,
            ..BackboneClientConfig::default()
        };
        client.runtime = Arc::new(Mutex::new(BackboneClientRuntime::from_config(&client)));
        BackbonePeerPoolCandidateConfig {
            client,
            mode: constants::MODE_FULL,
            ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
            ifac_runtime: IfacRuntimeConfig {
                netname: None,
                netkey: None,
                size: 16,
            },
            ifac_enabled: false,
            interface_type_name: "BackboneInterface".to_string(),
        }
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn backbone_peer_pool_respects_max_connected_order() {
        let listener_a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listener_b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port_a = listener_a.local_addr().unwrap().port();
        let port_b = listener_b.local_addr().unwrap().port();
        let mut driver = new_test_driver();

        driver.configure_backbone_peer_pool(
            BackbonePeerPoolSettings {
                max_connected: 1,
                failure_threshold: 3,
                failure_window: Duration::from_secs(60),
                cooldown: Duration::from_secs(60),
            },
            vec![
                make_pool_candidate("first", port_a, 7001),
                make_pool_candidate("second", port_b, 7002),
            ],
        );

        let status = driver.backbone_peer_pool_status().unwrap();
        assert_eq!(status.max_connected, 1);
        assert_eq!(status.active_count, 1);
        assert_eq!(status.standby_count, 1);
        assert_eq!(status.members[0].name, "first");
        assert_eq!(status.members[0].interface_id, Some(7001));
        assert_eq!(status.members[1].name, "second");
        assert_eq!(status.members[1].state, "standby");
        drop(listener_a);
        drop(listener_b);
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn backbone_peer_pool_cools_down_failed_peer_and_tries_next() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let reachable_port = listener.local_addr().unwrap().port();
        let mut driver = new_test_driver();

        driver.configure_backbone_peer_pool(
            BackbonePeerPoolSettings {
                max_connected: 1,
                failure_threshold: 1,
                failure_window: Duration::from_secs(60),
                cooldown: Duration::from_secs(60),
            },
            vec![
                make_pool_candidate("failed", 1, 7011),
                make_pool_candidate("replacement", reachable_port, 7012),
            ],
        );

        let status = driver.backbone_peer_pool_status().unwrap();
        assert_eq!(status.active_count, 1);
        assert_eq!(status.cooldown_count, 1);
        assert_eq!(status.members[0].name, "failed");
        assert_eq!(status.members[0].state, "cooldown");
        assert_eq!(status.members[0].failure_count, 1);
        assert_eq!(status.members[1].name, "replacement");
        assert_eq!(status.members[1].interface_id, Some(7012));
        drop(listener);
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn backbone_peer_pool_rotates_after_runtime_disconnect() {
        let listener_a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listener_b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port_a = listener_a.local_addr().unwrap().port();
        let port_b = listener_b.local_addr().unwrap().port();
        let mut driver = new_test_driver();

        driver.configure_backbone_peer_pool(
            BackbonePeerPoolSettings {
                max_connected: 1,
                failure_threshold: 1,
                failure_window: Duration::from_secs(60),
                cooldown: Duration::from_secs(60),
            },
            vec![
                make_pool_candidate("first", port_a, 7021),
                make_pool_candidate("second", port_b, 7022),
            ],
        );
        driver.handle_backbone_peer_pool_down(InterfaceId(7021));

        let status = driver.backbone_peer_pool_status().unwrap();
        assert_eq!(status.active_count, 1);
        assert_eq!(status.cooldown_count, 1);
        assert_eq!(status.members[0].state, "cooldown");
        assert_eq!(status.members[1].interface_id, Some(7022));
        drop(listener_a);
        drop(listener_b);
    }

    #[cfg(feature = "iface-backbone")]
    fn register_test_backbone(driver: &mut Driver, name: &str) {
        let startup = BackboneServerRuntime {
            max_connections: Some(8),
            idle_timeout: Some(Duration::from_secs(10)),
            write_stall_timeout: Some(Duration::from_secs(30)),
            abuse: BackboneAbuseConfig {
                max_penalty_duration: Some(Duration::from_secs(3600)),
            },
        };
        let peer_state = Arc::new(std::sync::Mutex::new(
            crate::interface::backbone::BackbonePeerMonitor::new(),
        ));
        driver.register_backbone_runtime(BackboneRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
            startup,
        });
        driver.register_backbone_peer_state(BackbonePeerStateHandle {
            interface_id: InterfaceId(1),
            interface_name: name.to_string(),
            peer_state,
        });
    }

    #[cfg(feature = "iface-backbone")]
    fn register_test_backbone_client(driver: &mut Driver, name: &str) {
        let startup = BackboneClientRuntime {
            reconnect_wait: Duration::from_secs(5),
            max_reconnect_tries: Some(3),
            connect_timeout: Duration::from_secs(5),
        };
        driver.register_backbone_client_runtime(BackboneClientRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
            startup,
        });
    }

    #[cfg(feature = "iface-backbone")]
    fn register_test_backbone_discovery(driver: &mut Driver, name: &str, discoverable: bool) {
        let startup = BackboneDiscoveryRuntime {
            discoverable,
            config: crate::discovery::DiscoveryConfig {
                discovery_name: name.to_string(),
                announce_interval: 3600,
                stamp_value: crate::discovery::DEFAULT_STAMP_VALUE,
                reachable_on: None,
                interface_type: "BackboneInterface".to_string(),
                listen_port: Some(4242),
                latitude: None,
                longitude: None,
                height: None,
            },
            transport_enabled: true,
            ifac_netname: None,
            ifac_netkey: None,
        };
        driver.register_backbone_discovery_runtime(BackboneDiscoveryRuntimeHandle {
            interface_name: name.to_string(),
            current: startup.clone(),
            startup,
        });
    }

    #[cfg(feature = "iface-tcp")]
    fn register_test_tcp_server(driver: &mut Driver, name: &str) {
        let startup = TcpServerRuntime {
            max_connections: Some(4),
        };
        driver.register_tcp_server_runtime(TcpServerRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
            startup,
        });
    }

    #[cfg(feature = "iface-tcp")]
    fn register_test_tcp_server_discovery(driver: &mut Driver, name: &str, discoverable: bool) {
        let startup = TcpServerDiscoveryRuntime {
            discoverable,
            config: crate::discovery::DiscoveryConfig {
                discovery_name: name.to_string(),
                announce_interval: 3600,
                stamp_value: crate::discovery::DEFAULT_STAMP_VALUE,
                reachable_on: None,
                interface_type: "TCPServerInterface".to_string(),
                listen_port: Some(4242),
                latitude: None,
                longitude: None,
                height: None,
            },
            transport_enabled: true,
            ifac_netname: None,
            ifac_netkey: None,
        };
        driver.register_tcp_server_discovery_runtime(TcpServerDiscoveryRuntimeHandle {
            interface_name: name.to_string(),
            current: startup.clone(),
            startup,
        });
    }

    #[cfg(feature = "iface-tcp")]
    fn register_test_tcp_client(driver: &mut Driver, name: &str) {
        let startup = crate::interface::tcp::TcpClientRuntime {
            target_host: "127.0.0.1".into(),
            target_port: 4242,
            reconnect_wait: Duration::from_secs(5),
            max_reconnect_tries: Some(3),
            connect_timeout: Duration::from_secs(5),
        };
        driver.register_tcp_client_runtime(crate::interface::tcp::TcpClientRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
            startup,
        });
    }

    #[cfg(feature = "iface-udp")]
    fn register_test_udp(driver: &mut Driver, name: &str) {
        let startup = UdpRuntime {
            forward_ip: Some("127.0.0.1".into()),
            forward_port: Some(4242),
        };
        driver.register_udp_runtime(UdpRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
            startup,
        });
    }

    fn register_test_generic_interface(driver: &mut Driver, id: u64, name: &str) {
        let mut info = make_interface_info(id);
        info.name = name.to_string();
        info.mode = rns_core::constants::MODE_FULL;
        info.announce_rate_target = Some(1.5);
        info.announce_rate_grace = 2;
        info.announce_rate_penalty = 0.25;
        info.announce_cap = 0.05;
        info.ingress_control.enabled = true;
        driver.register_interface_runtime_defaults(&info);
        driver.register_interface_ifac_runtime(
            &info.name,
            IfacRuntimeConfig {
                netname: None,
                netkey: None,
                size: 16,
            },
        );
        driver.engine.register_interface(info.clone());
        let (writer, _) = MockWriter::new();
        driver.interfaces.insert(
            InterfaceId(id),
            InterfaceEntry {
                id: InterfaceId(id),
                info,
                writer: Box::new(writer),
                async_writer_metrics: None,
                enabled: true,
                online: true,
                dynamic: false,
                ifac: None,
                stats: InterfaceStats {
                    started: time::now(),
                    ..Default::default()
                },
                interface_type: "TestInterface".to_string(),
                send_retry_at: None,
                send_retry_backoff: Duration::ZERO,
            },
        );
    }

    #[cfg(feature = "iface-auto")]
    fn register_test_auto(driver: &mut Driver, name: &str) {
        let startup = AutoRuntime {
            announce_interval_secs: 1.6,
            peer_timeout_secs: 22.0,
            peer_job_interval_secs: 4.0,
        };
        driver.register_auto_runtime(AutoRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
            startup,
        });
    }

    #[cfg(feature = "iface-i2p")]
    fn register_test_i2p(driver: &mut Driver, name: &str) {
        let startup = I2pRuntime {
            reconnect_wait: Duration::from_secs(15),
        };
        driver.register_i2p_runtime(I2pRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
            startup,
        });
    }

    #[cfg(feature = "iface-pipe")]
    fn register_test_pipe(driver: &mut Driver, name: &str) {
        let startup = PipeRuntime {
            respawn_delay: Duration::from_secs(5),
        };
        driver.register_pipe_runtime(PipeRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
            startup,
        });
    }

    #[cfg(feature = "iface-rnode")]
    fn register_test_rnode(driver: &mut Driver, name: &str) {
        let startup = RNodeRuntime {
            sub: RNodeSubConfig {
                name: name.to_string(),
                frequency: 868_000_000,
                bandwidth: 125_000,
                txpower: 7,
                spreading_factor: 8,
                coding_rate: 5,
                flow_control: false,
                st_alock: None,
                lt_alock: None,
            },
            writer: None,
        };
        driver.register_rnode_runtime(RNodeRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: Arc::new(std::sync::Mutex::new(startup.clone())),
            startup,
        });
    }

    impl Callbacks for MockCallbacks {
        fn on_announce(&mut self, announced: crate::destination::AnnouncedIdentity) {
            self.announces
                .lock()
                .unwrap()
                .push((announced.dest_hash, announced.hops));
        }

        fn on_path_updated(&mut self, dest_hash: DestHash, hops: u8) {
            self.paths.lock().unwrap().push((dest_hash, hops));
        }

        fn on_local_delivery(
            &mut self,
            dest_hash: DestHash,
            _raw: Vec<u8>,
            _packet_hash: PacketHash,
        ) {
            self.deliveries.lock().unwrap().push(dest_hash);
        }

        fn on_interface_up(&mut self, id: InterfaceId) {
            self.iface_ups.lock().unwrap().push(id);
        }

        fn on_interface_down(&mut self, id: InterfaceId) {
            self.iface_downs.lock().unwrap().push(id);
        }

        fn on_link_established(
            &mut self,
            link_id: TypedLinkId,
            _dest_hash: DestHash,
            rtt: f64,
            is_initiator: bool,
        ) {
            self.link_established
                .lock()
                .unwrap()
                .push((link_id, rtt, is_initiator));
        }

        fn on_link_closed(
            &mut self,
            link_id: TypedLinkId,
            _reason: Option<rns_core::link::TeardownReason>,
        ) {
            self.link_closed.lock().unwrap().push(link_id);
        }

        fn on_remote_identified(
            &mut self,
            link_id: TypedLinkId,
            identity_hash: IdentityHash,
            _public_key: [u8; 64],
        ) {
            self.remote_identified
                .lock()
                .unwrap()
                .push((link_id, identity_hash));
        }

        fn on_resource_received(
            &mut self,
            link_id: TypedLinkId,
            data: Vec<u8>,
            _metadata: Option<Vec<u8>>,
        ) {
            self.resources_received
                .lock()
                .unwrap()
                .push((link_id, data));
        }

        fn on_resource_completed(&mut self, link_id: TypedLinkId) {
            self.resource_completed.lock().unwrap().push(link_id);
        }

        fn on_resource_failed(&mut self, link_id: TypedLinkId, error: String) {
            self.resource_failed.lock().unwrap().push((link_id, error));
        }

        fn on_channel_message(&mut self, link_id: TypedLinkId, msgtype: u16, payload: Vec<u8>) {
            self.channel_messages
                .lock()
                .unwrap()
                .push((link_id, msgtype, payload));
        }

        fn on_link_data(&mut self, link_id: TypedLinkId, context: u8, data: Vec<u8>) {
            self.link_data
                .lock()
                .unwrap()
                .push((link_id, context, data));
        }

        fn on_response(&mut self, link_id: TypedLinkId, request_id: [u8; 16], data: Vec<u8>) {
            self.responses
                .lock()
                .unwrap()
                .push((link_id, request_id, data));
        }

        fn on_proof(&mut self, dest_hash: DestHash, packet_hash: PacketHash, rtt: f64) {
            self.proofs
                .lock()
                .unwrap()
                .push((dest_hash, packet_hash, rtt));
        }

        fn on_proof_requested(&mut self, dest_hash: DestHash, packet_hash: PacketHash) -> bool {
            self.proof_requested
                .lock()
                .unwrap()
                .push((dest_hash, packet_hash));
            true
        }
    }

    fn make_interface_info(id: u64) -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId(id),
            name: format!("test-{}", id),
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
            mtu: constants::MTU as u32,
            ia_freq: 0.0,
            started: 0.0,
            ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
        }
    }

    fn make_entry(id: u64, writer: Box<dyn Writer>, online: bool) -> InterfaceEntry {
        InterfaceEntry {
            id: InterfaceId(id),
            info: make_interface_info(id),
            writer,
            async_writer_metrics: None,
            enabled: true,
            online,
            dynamic: false,
            ifac: None,
            stats: InterfaceStats::default(),
            interface_type: String::new(),
            send_retry_at: None,
            send_retry_backoff: Duration::ZERO,
        }
    }

    /// Build a valid announce packet that the engine will accept.
    fn build_announce_packet(identity: &Identity) -> Vec<u8> {
        let dest_hash =
            rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));
        let name_hash = rns_core::destination::name_hash("test", &["app"]);
        let random_hash = [0x42u8; 10];

        let (announce_data, _has_ratchet) =
            AnnounceData::pack(identity, &dest_hash, &name_hash, &random_hash, None, None).unwrap();

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
        packet.raw
    }

    #[test]
    fn process_inbound_frame() {
        let (tx, rx) = event::channel();
        let (cbs, announces, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);

        // Send frame then shutdown
        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert_eq!(announces.lock().unwrap().len(), 1);
    }

    #[test]
    fn dispatch_send() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(1),
            raw: vec![0x01, 0x02, 0x03],
        }]);

        assert_eq!(sent.lock().unwrap().len(), 1);
        assert_eq!(sent.lock().unwrap()[0], vec![0x01, 0x02, 0x03]);

        drop(tx);
    }

    #[test]
    fn dispatch_broadcast() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let (w1, sent1) = MockWriter::new();
        let (w2, sent2) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(w1), true));
        driver
            .interfaces
            .insert(InterfaceId(2), make_entry(2, Box::new(w2), true));

        driver.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
            raw: vec![0xAA],
            exclude: None,
        }]);

        assert_eq!(sent1.lock().unwrap().len(), 1);
        assert_eq!(sent2.lock().unwrap().len(), 1);

        drop(tx);
    }

    #[test]
    fn dispatch_broadcast_exclude() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let (w1, sent1) = MockWriter::new();
        let (w2, sent2) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(w1), true));
        driver
            .interfaces
            .insert(InterfaceId(2), make_entry(2, Box::new(w2), true));

        driver.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
            raw: vec![0xBB],
            exclude: Some(InterfaceId(1)),
        }]);

        assert_eq!(sent1.lock().unwrap().len(), 0); // excluded
        assert_eq!(sent2.lock().unwrap().len(), 1);

        drop(tx);
    }

    #[test]
    fn tick_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: true,
                identity_hash: Some([0x42; 16]),
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Send Tick then Shutdown
        tx.send(Event::Tick).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();
        // No crash = tick was processed successfully
    }

    #[test]
    fn shutdown_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        tx.send(Event::Shutdown).unwrap();
        driver.run(); // Should return immediately
    }

    #[test]
    fn begin_drain_updates_driver_status() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx,
            Box::new(cbs),
        );

        driver.begin_drain(Duration::from_secs(3));

        let QueryResponse::DrainStatus(status) = driver.handle_query(QueryRequest::DrainStatus)
        else {
            panic!("expected drain status response");
        };
        assert_eq!(status.state, LifecycleState::Draining);
        assert!(status.drain_complete);
        assert!(status.drain_age_seconds.is_some());
        assert!(status.deadline_remaining_seconds.is_some());
        assert_eq!(
            status.detail.as_deref(),
            Some("node is draining existing work; no active links, resource transfers, hole-punch sessions, or queued writer/provider work remain")
        );
    }

    #[test]
    fn begin_drain_with_pending_link_reports_incomplete_status() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx,
            Box::new(cbs),
        );

        let _ = driver.link_manager.create_link(
            &[0xDD; 16],
            &[0x11; 32],
            1,
            rns_core::constants::MTU as u32,
            &mut OsRng,
        );

        driver.begin_drain(Duration::from_secs(3));

        let QueryResponse::DrainStatus(status) = driver.handle_query(QueryRequest::DrainStatus)
        else {
            panic!("expected drain status response");
        };
        assert_eq!(status.state, LifecycleState::Draining);
        assert!(!status.drain_complete);
        assert!(status
            .detail
            .unwrap_or_default()
            .contains("1 link(s) still active"));
    }

    #[test]
    fn begin_drain_with_queued_writer_frames_reports_incomplete_status() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx,
            Box::new(cbs),
        );

        let info = make_interface_info(77);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (writer, async_writer_metrics) = crate::interface::wrap_async_writer(
            Box::new(BlockingWriter {
                entered_tx,
                release_rx,
            }),
            InterfaceId(77),
            &info.name,
            driver.event_tx.clone(),
            1,
        );

        driver.interfaces.insert(
            InterfaceId(77),
            InterfaceEntry {
                id: InterfaceId(77),
                info,
                writer,
                async_writer_metrics: Some(async_writer_metrics),
                enabled: true,
                online: true,
                dynamic: false,
                ifac: None,
                stats: InterfaceStats::default(),
                interface_type: "TestInterface".to_string(),
                send_retry_at: None,
                send_retry_backoff: Duration::ZERO,
            },
        );

        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(77),
            raw: vec![0x01],
        }]);
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(77),
            raw: vec![0x02],
        }]);

        driver.begin_drain(Duration::from_secs(3));

        let QueryResponse::DrainStatus(status) = driver.handle_query(QueryRequest::DrainStatus)
        else {
            panic!("expected drain status response");
        };
        assert_eq!(status.state, LifecycleState::Draining);
        assert!(!status.drain_complete);
        assert_eq!(status.interface_writer_queued_frames, 1);
        assert!(status
            .detail
            .unwrap_or_default()
            .contains("queued interface writer frame"));

        let _ = release_tx.send(());
    }

    #[test]
    fn enforce_drain_deadline_tears_down_remaining_links() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx,
            Box::new(cbs),
        );

        let _ = driver.link_manager.create_link(
            &[0xDD; 16],
            &[0x11; 32],
            1,
            rns_core::constants::MTU as u32,
            &mut OsRng,
        );
        driver.begin_drain(Duration::ZERO);

        driver.enforce_drain_deadline();

        assert_eq!(driver.lifecycle_state, LifecycleState::Stopping);
        assert_eq!(driver.link_manager.link_count(), 0);
        let QueryResponse::DrainStatus(status) = driver.handle_query(QueryRequest::DrainStatus)
        else {
            panic!("expected drain status response");
        };
        assert!(status.drain_complete);
        assert_eq!(status.state, LifecycleState::Stopping);
    }

    #[test]
    fn begin_drain_with_holepunch_session_reports_incomplete_status_and_deadline_aborts_it() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx,
            Box::new(cbs),
        );
        driver.holepunch_manager = crate::holepunch::orchestrator::HolePunchManager::new(
            vec!["127.0.0.1:4343".parse().unwrap()],
            rns_core::holepunch::ProbeProtocol::Rnsp,
            None,
        );

        let _ = driver.holepunch_manager.propose(
            [0x44; 16],
            &[0xAA; 32],
            &mut OsRng,
            &driver.get_event_sender(),
        );
        assert_eq!(driver.holepunch_manager.session_count(), 1);

        driver.begin_drain(Duration::from_secs(3));

        let QueryResponse::DrainStatus(status) = driver.handle_query(QueryRequest::DrainStatus)
        else {
            panic!("expected drain status response");
        };
        assert_eq!(status.state, LifecycleState::Draining);
        assert!(!status.drain_complete);
        assert!(status
            .detail
            .unwrap_or_default()
            .contains("1 hole-punch session(s) still active"));

        driver.begin_drain(Duration::ZERO);
        driver.enforce_drain_deadline();

        assert_eq!(driver.holepunch_manager.session_count(), 0);
        let QueryResponse::DrainStatus(status) = driver.handle_query(QueryRequest::DrainStatus)
        else {
            panic!("expected drain status response");
        };
        assert!(status.drain_complete);
        assert_eq!(status.state, LifecycleState::Stopping);
    }

    #[test]
    fn begin_drain_event_is_processed_by_run_loop() {
        let (tx, rx) = event::channel();
        let tx_query = tx.clone();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let handle = std::thread::spawn(move || driver.run());
        tx.send(Event::BeginDrain {
            timeout: Duration::from_secs(2),
        })
        .unwrap();
        let (resp_tx, resp_rx) = std::sync::mpsc::channel();
        tx_query
            .send(Event::Query(QueryRequest::DrainStatus, resp_tx))
            .unwrap();
        let status = match resp_rx.recv().unwrap() {
            QueryResponse::DrainStatus(status) => status,
            other => panic!("expected drain status response, got {:?}", other),
        };
        assert_eq!(status.state, LifecycleState::Draining);
        tx_query.send(Event::Shutdown).unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn send_channel_message_returns_error_while_draining() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        tx.send(Event::BeginDrain {
            timeout: Duration::from_secs(2),
        })
        .unwrap();
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::SendChannelMessage {
            link_id: [0xAA; 16],
            msgtype: 7,
            payload: b"drain".to_vec(),
            response_tx: resp_tx,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let response = resp_rx.recv().unwrap();
        assert_eq!(
            response,
            Err("cannot send channel message while node is draining".into())
        );
    }

    #[test]
    fn send_outbound_is_ignored_while_draining() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let identity = Identity::new(&mut OsRng);
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        tx.send(Event::BeginDrain {
            timeout: Duration::from_secs(2),
        })
        .unwrap();
        tx.send(Event::SendOutbound {
            raw: build_announce_packet(&identity),
            dest_type: constants::DESTINATION_SINGLE,
            attached_interface: None,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert!(sent.lock().unwrap().is_empty());
        assert!(driver.sent_packets.is_empty());
    }

    #[test]
    fn request_path_is_ignored_while_draining() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        tx.send(Event::BeginDrain {
            timeout: Duration::from_secs(2),
        })
        .unwrap();
        tx.send(Event::RequestPath {
            dest_hash: [0xAA; 16],
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert!(sent.lock().unwrap().is_empty());
    }

    #[test]
    fn create_link_returns_zero_link_id_while_draining() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        tx.send(Event::BeginDrain {
            timeout: Duration::from_secs(2),
        })
        .unwrap();
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::CreateLink {
            dest_hash: [0xAB; 16],
            dest_sig_pub_bytes: [0xCD; 32],
            response_tx: resp_tx,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert_eq!(resp_rx.recv().unwrap(), [0u8; 16]);
    }

    #[test]
    fn announce_callback() {
        let (tx, rx) = event::channel();
        let (cbs, announces, paths, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let ann = announces.lock().unwrap();
        assert_eq!(ann.len(), 1);
        // Hops should be 1 (incremented from 0 by handle_inbound)
        assert_eq!(ann[0].1, 1);

        let p = paths.lock().unwrap();
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn dispatch_skips_offline_interface() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let (w1, sent1) = MockWriter::new();
        let (w2, sent2) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(w1), false)); // offline
        driver
            .interfaces
            .insert(InterfaceId(2), make_entry(2, Box::new(w2), true));

        // Direct send to offline interface: should be skipped
        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(1),
            raw: vec![0x01],
        }]);
        assert_eq!(sent1.lock().unwrap().len(), 0);

        // Broadcast: only online interface should receive
        driver.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
            raw: vec![0x02],
            exclude: None,
        }]);
        assert_eq!(sent1.lock().unwrap().len(), 0); // still offline
        assert_eq!(sent2.lock().unwrap().len(), 1);

        drop(tx);
    }

    #[test]
    fn interface_up_refreshes_writer() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let (w_old, sent_old) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(w_old), false));

        // Simulate reconnect: InterfaceUp with new writer
        let (w_new, sent_new) = MockWriter::new();
        tx.send(Event::InterfaceUp(
            InterfaceId(1),
            Some(Box::new(w_new)),
            None,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Interface should be online now
        assert!(driver.interfaces[&InterfaceId(1)].online);

        // Send via the (now-refreshed) interface
        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(1),
            raw: vec![0xFF],
        }]);

        // Old writer should not have received anything
        assert_eq!(sent_old.lock().unwrap().len(), 0);
        // New writer should have received the data
        wait_for_sent_len(&sent_new, 1);
        assert_eq!(sent_new.lock().unwrap()[0], vec![0xFF]);

        drop(tx);
    }

    #[test]
    fn dynamic_interface_register() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, iface_ups, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let info = make_interface_info(100);
        let (writer, sent) = MockWriter::new();

        // InterfaceUp with InterfaceInfo = new dynamic interface
        tx.send(Event::InterfaceUp(
            InterfaceId(100),
            Some(Box::new(writer)),
            Some(info),
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should be registered and online
        assert!(driver.interfaces.contains_key(&InterfaceId(100)));
        assert!(driver.interfaces[&InterfaceId(100)].online);
        assert!(driver.interfaces[&InterfaceId(100)].dynamic);

        // Callback should have fired
        assert_eq!(iface_ups.lock().unwrap().len(), 1);
        assert_eq!(iface_ups.lock().unwrap()[0], InterfaceId(100));

        // Can send to it
        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(100),
            raw: vec![0x42],
        }]);
        wait_for_sent_len(&sent, 1);

        drop(tx);
    }

    #[test]
    fn dynamic_interface_deregister() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, iface_downs) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        // Register a dynamic interface
        let info = make_interface_info(200);
        driver.engine.register_interface(info.clone());
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(
            InterfaceId(200),
            InterfaceEntry {
                id: InterfaceId(200),
                info,
                writer: Box::new(writer),
                async_writer_metrics: None,
                enabled: true,
                online: true,
                dynamic: true,
                ifac: None,
                stats: InterfaceStats::default(),
                interface_type: String::new(),
                send_retry_at: None,
                send_retry_backoff: Duration::ZERO,
            },
        );

        // InterfaceDown for dynamic → should be removed entirely
        tx.send(Event::InterfaceDown(InterfaceId(200))).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert!(!driver.interfaces.contains_key(&InterfaceId(200)));
        assert_eq!(iface_downs.lock().unwrap().len(), 1);
        assert_eq!(iface_downs.lock().unwrap()[0], InterfaceId(200));
    }

    #[test]
    fn send_wouldblock_is_backed_off_between_dispatches() {
        let (tx, rx) = event::channel();
        let (cbs, ..) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx,
            Box::new(cbs),
        );
        let (writer, attempts) = WouldBlockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(7), make_entry(7, Box::new(writer), true));

        let action = TransportAction::SendOnInterface {
            interface: InterfaceId(7),
            raw: vec![0x01, 0x00, 0x42],
        };
        driver.dispatch_all(vec![action.clone()]);
        assert_eq!(*attempts.lock().unwrap(), 1);

        driver.dispatch_all(vec![action.clone()]);
        assert_eq!(
            *attempts.lock().unwrap(),
            1,
            "second dispatch should be deferred during backoff"
        );

        let entry = driver.interfaces.get_mut(&InterfaceId(7)).unwrap();
        entry.send_retry_at = Some(Instant::now() - Duration::from_millis(1));
        driver.dispatch_all(vec![action]);
        assert_eq!(*attempts.lock().unwrap(), 2);
    }

    #[test]
    fn interface_callbacks_fire() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, iface_ups, iface_downs) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        // Static interface
        let (writer, _) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), false));

        tx.send(Event::InterfaceUp(InterfaceId(1), None, None))
            .unwrap();
        tx.send(Event::InterfaceDown(InterfaceId(1))).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert_eq!(iface_ups.lock().unwrap().len(), 1);
        assert_eq!(iface_downs.lock().unwrap().len(), 1);
        // Static interface should still exist but be offline
        assert!(driver.interfaces.contains_key(&InterfaceId(1)));
        assert!(!driver.interfaces[&InterfaceId(1)].online);
    }

    // =========================================================================
    // New tests for Phase 6a
    // =========================================================================

    #[test]
    fn frame_updates_rx_stats() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);
        let announce_len = announce_raw.len() as u64;

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let stats = &driver.interfaces[&InterfaceId(1)].stats;
        assert_eq!(stats.rxb, announce_len);
        assert_eq!(stats.rx_packets, 1);
    }

    #[test]
    fn send_updates_tx_stats() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(1),
            raw: vec![0x01, 0x02, 0x03],
        }]);

        let stats = &driver.interfaces[&InterfaceId(1)].stats;
        assert_eq!(stats.txb, 3);
        assert_eq!(stats.tx_packets, 1);

        drop(tx);
    }

    #[test]
    fn broadcast_updates_tx_stats() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let (w1, _s1) = MockWriter::new();
        let (w2, _s2) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(w1), true));
        driver
            .interfaces
            .insert(InterfaceId(2), make_entry(2, Box::new(w2), true));

        driver.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
            raw: vec![0xAA, 0xBB],
            exclude: None,
        }]);

        // Both interfaces should have tx stats updated
        assert_eq!(driver.interfaces[&InterfaceId(1)].stats.txb, 2);
        assert_eq!(driver.interfaces[&InterfaceId(1)].stats.tx_packets, 1);
        assert_eq!(driver.interfaces[&InterfaceId(2)].stats.txb, 2);
        assert_eq!(driver.interfaces[&InterfaceId(2)].stats.tx_packets, 1);

        drop(tx);
    }

    #[test]
    fn query_interface_stats() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: true,
                identity_hash: Some([0x42; 16]),
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::InterfaceStats, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let resp = resp_rx.recv().unwrap();
        match resp {
            QueryResponse::InterfaceStats(stats) => {
                assert_eq!(stats.interfaces.len(), 1);
                assert_eq!(stats.interfaces[0].name, "test-1");
                assert!(stats.interfaces[0].status);
                assert_eq!(stats.transport_id, Some([0x42; 16]));
                assert!(stats.transport_enabled);
            }
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_path_table() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Feed an announce to create a path entry
        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);
        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::PathTable { max_hops: None },
            resp_tx,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let resp = resp_rx.recv().unwrap();
        match resp {
            QueryResponse::PathTable(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].hops, 1);
            }
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_drop_path() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Feed an announce to create a path entry
        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);
        let dest_hash =
            rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::DropPath { dest_hash }, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let resp = resp_rx.recv().unwrap();
        match resp {
            QueryResponse::DropPath(dropped) => {
                assert!(dropped);
            }
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn send_outbound_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let (writer, sent) = MockWriter::new();
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Build a DATA packet to a destination
        let dest = [0xAA; 16];
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

        tx.send(Event::SendOutbound {
            raw: packet.raw,
            dest_type: constants::DESTINATION_PLAIN,
            attached_interface: None,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // PLAIN packet should be broadcast on all interfaces
        assert_eq!(sent.lock().unwrap().len(), 1);
    }

    #[test]
    fn register_destination_and_deliver() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, deliveries, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let dest = [0xBB; 16];

        // Register destination then send a data packet to it
        tx.send(Event::RegisterDestination {
            dest_hash: dest,
            dest_type: constants::DESTINATION_SINGLE,
        })
        .unwrap();

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"data").unwrap();
        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert_eq!(deliveries.lock().unwrap().len(), 1);
        assert_eq!(deliveries.lock().unwrap()[0], DestHash(dest));
    }

    #[test]
    fn query_transport_identity() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: true,
                identity_hash: Some([0xAA; 16]),
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::TransportIdentity, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::TransportIdentity(Some(hash)) => {
                assert_eq!(hash, [0xAA; 16]);
            }
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_link_count() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::LinkCount, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::LinkCount(count) => assert_eq!(count, 0),
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_rate_table() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::RateTable, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::RateTable(entries) => assert!(entries.is_empty()),
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_next_hop() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let dest = [0xBB; 16];
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::NextHop { dest_hash: dest },
            resp_tx,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::NextHop(None) => {}
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_next_hop_if_name() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let dest = [0xCC; 16];
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::NextHopIfName { dest_hash: dest },
            resp_tx,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::NextHopIfName(None) => {}
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_drop_all_via() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let transport = [0xDD; 16];
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::DropAllVia {
                transport_hash: transport,
            },
            resp_tx,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::DropAllVia(count) => assert_eq!(count, 0),
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_drop_announce_queues() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::DropAnnounceQueues, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::DropAnnounceQueues => {}
            _ => panic!("unexpected response"),
        }
    }

    // =========================================================================
    // Phase 7e: Link wiring integration tests
    // =========================================================================

    #[test]
    fn register_link_dest_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let mut rng = OsRng;
        let sig_prv = rns_crypto::ed25519::Ed25519PrivateKey::generate(&mut rng);
        let sig_pub_bytes = sig_prv.public_key().public_bytes();
        let sig_prv_bytes = sig_prv.private_bytes();
        let dest_hash = [0xDD; 16];

        tx.send(Event::RegisterLinkDestination {
            dest_hash,
            sig_prv_bytes,
            sig_pub_bytes,
            resource_strategy: 0,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Link manager should know about the destination
        assert!(driver.link_manager.is_link_destination(&dest_hash));
    }

    #[test]
    fn create_link_event() {
        let (tx, rx) = event::channel();
        let (cbs, _link_established, _, _) = MockCallbacks::with_link_tracking();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let dest_hash = [0xDD; 16];
        let dummy_sig_pub = [0xAA; 32];

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::CreateLink {
            dest_hash,
            dest_sig_pub_bytes: dummy_sig_pub,
            response_tx: resp_tx,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should have received a link_id
        let link_id = resp_rx.recv().unwrap();
        assert_ne!(link_id, [0u8; 16]);

        // Link should be in pending state in the manager
        assert_eq!(driver.link_manager.link_count(), 1);

        // The LINKREQUEST packet won't be sent on the wire without a path
        // to the destination (DESTINATION_LINK requires a known path or
        // attached_interface). In a real scenario, the path would exist from
        // an announce received earlier.
    }

    #[test]
    fn create_link_uses_known_destination_interface_without_path() {
        let (tx, rx) = event::channel();
        let (cbs, _link_established, _, _) = MockCallbacks::with_link_tracking();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        for id in [1, 2] {
            driver.engine.register_interface(make_interface_info(id));
        }
        let (writer, sent) = MockWriter::new();
        let (writer2, sent2) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
        driver
            .interfaces
            .insert(InterfaceId(2), make_entry(2, Box::new(writer2), true));

        let dest_hash = [0xD1; 16];
        driver.known_destinations.insert(
            dest_hash,
            make_known_destination_state(dest_hash, 10.0, InterfaceId(2)),
        );

        let dummy_sig_pub = [0xA1; 32];
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::CreateLink {
            dest_hash,
            dest_sig_pub_bytes: dummy_sig_pub,
            response_tx: resp_tx,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let link_id = resp_rx.recv().unwrap();
        assert_ne!(link_id, [0u8; 16]);
        assert_eq!(driver.link_manager.link_count(), 1);

        let sent_packets = sent.lock().unwrap();
        let sent_packets2 = sent2.lock().unwrap();
        assert!(
            sent_packets.is_empty(),
            "LINKREQUEST should not broadcast to unrelated interfaces when a known destination interface exists"
        );
        assert_eq!(sent_packets2.len(), 1);
        let flags = PacketFlags::unpack(sent_packets2[0][0] & 0x7F);
        assert_eq!(flags.packet_type, constants::PACKET_TYPE_LINKREQUEST);
        assert_eq!(extract_dest_hash(&sent_packets2[0]), dest_hash);
    }

    #[test]
    fn create_link_ignores_sentinel_known_destination_interface() {
        let (tx, rx) = event::channel();
        let (cbs, _link_established, _, _) = MockCallbacks::with_link_tracking();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        for id in [1, 2] {
            driver.engine.register_interface(make_interface_info(id));
        }
        let (writer, sent) = MockWriter::new();
        let (writer2, sent2) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));
        driver
            .interfaces
            .insert(InterfaceId(2), make_entry(2, Box::new(writer2), true));

        let dest_hash = [0xD2; 16];
        driver.known_destinations.insert(
            dest_hash,
            make_known_destination_state(dest_hash, 10.0, InterfaceId(0)),
        );

        let dummy_sig_pub = [0xA2; 32];
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::CreateLink {
            dest_hash,
            dest_sig_pub_bytes: dummy_sig_pub,
            response_tx: resp_tx,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let link_id = resp_rx.recv().unwrap();
        assert_ne!(link_id, [0u8; 16]);
        assert_eq!(driver.link_manager.link_count(), 1);

        let sent_packets = sent.lock().unwrap();
        let sent_packets2 = sent2.lock().unwrap();
        assert!(
            sent_packets.len() == 1 && sent_packets2.len() == 1,
            "sentinel InterfaceId(0) must not suppress the default broadcast behavior"
        );
        let flags = PacketFlags::unpack(sent_packets[0][0] & 0x7F);
        assert_eq!(flags.packet_type, constants::PACKET_TYPE_LINKREQUEST);
    }

    #[test]
    fn deliver_local_routes_to_link_manager() {
        // Verify that DeliverLocal for a registered link destination goes to
        // the link manager instead of the callbacks.
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register a link destination
        let mut rng = OsRng;
        let sig_prv = rns_crypto::ed25519::Ed25519PrivateKey::generate(&mut rng);
        let sig_pub_bytes = sig_prv.public_key().public_bytes();
        let dest_hash = [0xEE; 16];
        driver.link_manager.register_link_destination(
            dest_hash,
            sig_prv,
            sig_pub_bytes,
            crate::link_manager::ResourceStrategy::AcceptNone,
        );

        // dispatch_all with a DeliverLocal for that dest should route to link_manager
        // (not to callbacks). We can't easily test this via run() since we need
        // a valid LINKREQUEST, but we can check is_link_destination works.
        assert!(driver.link_manager.is_link_destination(&dest_hash));

        // Non-link destination should go to callbacks
        assert!(!driver.link_manager.is_link_destination(&[0xFF; 16]));

        drop(tx);
    }

    #[test]
    fn teardown_link_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, link_closed, _) = MockCallbacks::with_link_tracking();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Create a link first
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::CreateLink {
            dest_hash: [0xDD; 16],
            dest_sig_pub_bytes: [0xAA; 32],
            response_tx: resp_tx,
        })
        .unwrap();
        // Then tear it down
        // We can't receive resp_rx yet since driver.run() hasn't started,
        // but we know the link_id will be created. Send teardown after CreateLink.
        // Actually, we need to get the link_id first. Let's use a two-phase approach.
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let link_id = resp_rx.recv().unwrap();
        assert_ne!(link_id, [0u8; 16]);
        assert_eq!(driver.link_manager.link_count(), 1);

        // Now restart with same driver (just use events directly since driver loop exited)
        let teardown_actions = driver.link_manager.teardown_link(&link_id);
        driver.dispatch_link_actions(teardown_actions);

        // Callback should have been called
        assert_eq!(link_closed.lock().unwrap().len(), 1);
        assert_eq!(link_closed.lock().unwrap()[0], TypedLinkId(link_id));
    }

    #[test]
    fn link_count_includes_link_manager() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Create a link via link_manager directly
        let mut rng = OsRng;
        let dummy_sig = [0xAA; 32];
        driver.link_manager.create_link(
            &[0xDD; 16],
            &dummy_sig,
            1,
            constants::MTU as u32,
            &mut rng,
        );

        // Query link count — should include link_manager links
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::LinkCount, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::LinkCount(count) => assert_eq!(count, 1),
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn register_request_handler_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        tx.send(Event::RegisterRequestHandler {
            path: "/status".to_string(),
            allowed_list: None,
            handler: Box::new(|_link_id, _path, _data, _remote| Some(b"OK".to_vec())),
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Handler should be registered (we can't directly query the count,
        // but at least verify no crash)
    }

    // Phase 8c: Management announce timing tests

    #[test]
    fn management_announces_emitted_after_delay() {
        let (tx, rx) = event::channel();
        let (cbs, _announces, _, _, _, _) = MockCallbacks::new();
        let identity = Identity::new(&mut OsRng);
        let identity_hash = *identity.hash();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: true,
                identity_hash: Some(identity_hash),
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        // Register interface so announces can be sent
        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Enable management announces
        driver.management_config.enable_remote_management = true;
        driver.transport_identity = Some(identity);

        // Set started time to 10 seconds ago so the 5s delay has passed
        driver.started = time::now() - 10.0;

        // Send Tick then Shutdown
        tx.send(Event::Tick).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should have sent at least one packet (the management announce)
        let sent_packets = sent.lock().unwrap();
        assert!(
            !sent_packets.is_empty(),
            "Management announce should be sent after startup delay"
        );
    }

    #[test]
    fn runtime_config_list_contains_global_keys() {
        let driver = new_test_driver();
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"global.tick_interval_ms".to_string()));
        assert!(keys.contains(&"global.known_destinations_ttl_secs".to_string()));
        assert!(keys.contains(&"global.rate_limiter_ttl_secs".to_string()));
        assert!(keys.contains(&"global.direct_connect_policy".to_string()));
    }

    #[test]
    fn runtime_config_set_and_reset_tick_interval() {
        let mut driver = new_test_driver();

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "global.tick_interval_ms".into(),
            value: RuntimeConfigValue::Int(250),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.key, "global.tick_interval_ms");
        assert_eq!(entry.value, RuntimeConfigValue::Int(250));
        assert_eq!(driver.tick_interval_ms.load(Ordering::Relaxed), 250);

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "global.tick_interval_ms".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(1000));
        assert_eq!(driver.tick_interval_ms.load(Ordering::Relaxed), 1000);
    }

    #[test]
    fn runtime_config_rejects_invalid_policy() {
        let mut driver = new_test_driver();
        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "global.direct_connect_policy".into(),
            value: RuntimeConfigValue::String("bogus".into()),
        });
        let QueryResponse::RuntimeConfigSet(Err(err)) = response else {
            panic!("expected runtime config set failure");
        };
        assert_eq!(err.code, RuntimeConfigErrorCode::InvalidValue);
    }

    #[test]
    fn runtime_config_set_and_reset_rate_limiter_ttl() {
        let mut driver = new_test_driver();

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "global.rate_limiter_ttl_secs".into(),
            value: RuntimeConfigValue::Float(600.0),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(600.0));
        assert_eq!(driver.rate_limiter_ttl_secs, 600.0);

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "global.rate_limiter_ttl_secs".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(
            entry.value,
            RuntimeConfigValue::Float(DEFAULT_RATE_LIMITER_TTL_SECS)
        );
        assert_eq!(driver.rate_limiter_ttl_secs, DEFAULT_RATE_LIMITER_TTL_SECS);
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn runtime_config_lists_backbone_keys() {
        let mut driver = new_test_driver();
        register_test_backbone(&mut driver, "public");
        register_test_backbone_client(&mut driver, "uplink");
        register_test_backbone_discovery(&mut driver, "public", false);
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"backbone.public.idle_timeout_secs".to_string()));
        assert!(keys.contains(&"backbone.public.write_stall_timeout_secs".to_string()));
        assert!(keys.contains(&"backbone.public.max_connections".to_string()));
        assert!(keys.contains(&"backbone.public.discoverable".to_string()));
        assert!(keys.contains(&"backbone.public.discovery_name".to_string()));
        assert!(keys.contains(&"backbone.public.latitude".to_string()));
        assert!(keys.contains(&"backbone.public.longitude".to_string()));
        assert!(keys.contains(&"backbone.public.height".to_string()));
        assert!(keys.contains(&"backbone_client.uplink.connect_timeout_secs".to_string()));
        assert!(keys.contains(&"backbone_client.uplink.reconnect_wait_secs".to_string()));
        assert!(keys.contains(&"backbone_client.uplink.max_reconnect_tries".to_string()));
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn runtime_config_sets_backbone_values() {
        let mut driver = new_test_driver();
        register_test_backbone(&mut driver, "public");
        register_test_backbone_discovery(&mut driver, "public", false);
        driver.transport_identity = Some(rns_crypto::identity::Identity::new(&mut OsRng));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone.public.idle_timeout_secs".into(),
            value: RuntimeConfigValue::Float(2.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(2.5));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone.public.write_stall_timeout_secs".into(),
            value: RuntimeConfigValue::Float(15.0),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(15.0));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone.public.max_connections".into(),
            value: RuntimeConfigValue::Int(0),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(0));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "backbone.public.max_connections".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(8));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "backbone.public.write_stall_timeout_secs".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(30.0));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone.public.discoverable".into(),
            value: RuntimeConfigValue::Bool(true),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Bool(true));
        assert!(driver
            .interface_announcer
            .as_ref()
            .map(|announcer| announcer.contains_interface("public"))
            .unwrap_or(false));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone.public.discovery_name".into(),
            value: RuntimeConfigValue::String("Public Backbone".into()),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(
            entry.value,
            RuntimeConfigValue::String("Public Backbone".into())
        );

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone.public.latitude".into(),
            value: RuntimeConfigValue::Float(45.4642),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(45.4642));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone.public.longitude".into(),
            value: RuntimeConfigValue::Float(9.19),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(9.19));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone.public.height".into(),
            value: RuntimeConfigValue::Int(120),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(120.0));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "backbone.public.discoverable".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Bool(false));
        assert!(driver.interface_announcer.is_none());

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "backbone.public.latitude".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Null);
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn runtime_config_sets_backbone_client_values() {
        let mut driver = new_test_driver();
        register_test_backbone_client(&mut driver, "uplink");

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone_client.uplink.connect_timeout_secs".into(),
            value: RuntimeConfigValue::Float(2.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(2.5));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone_client.uplink.max_reconnect_tries".into(),
            value: RuntimeConfigValue::Int(0),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(0));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "backbone_client.uplink.connect_timeout_secs".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(5.0));
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn backbone_peer_state_query_lists_entries() {
        let mut driver = new_test_driver();
        register_test_backbone(&mut driver, "public");
        driver
            .backbone_peer_state
            .get("public")
            .unwrap()
            .peer_state
            .lock()
            .unwrap()
            .seed_entry(BackbonePeerStateEntry {
                interface_name: "public".into(),
                peer_ip: "203.0.113.10".parse().unwrap(),
                connected_count: 1,
                blacklisted_remaining_secs: Some(120.0),
                blacklist_reason: Some("repeated idle timeouts".into()),
                reject_count: 7,
            });

        let response = driver.handle_query(QueryRequest::BackbonePeerState {
            interface_name: Some("public".into()),
        });
        let QueryResponse::BackbonePeerState(entries) = response else {
            panic!("expected backbone peer state list");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].peer_ip.to_string(), "203.0.113.10");
        assert_eq!(entries[0].connected_count, 1);
        assert_eq!(entries[0].reject_count, 7);
        assert_eq!(
            entries[0].blacklist_reason.as_deref(),
            Some("repeated idle timeouts")
        );
        assert!(entries[0].blacklisted_remaining_secs.unwrap() > 0.0);
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn backbone_peer_state_clear_removes_entry() {
        let mut driver = new_test_driver();
        register_test_backbone(&mut driver, "public");
        driver
            .backbone_peer_state
            .get("public")
            .unwrap()
            .peer_state
            .lock()
            .unwrap()
            .seed_entry(BackbonePeerStateEntry {
                interface_name: "public".into(),
                peer_ip: "203.0.113.11".parse().unwrap(),
                connected_count: 0,
                blacklisted_remaining_secs: None,
                blacklist_reason: None,
                reject_count: 0,
            });

        let response = driver.handle_query_mut(QueryRequest::ClearBackbonePeerState {
            interface_name: "public".into(),
            peer_ip: "203.0.113.11".parse().unwrap(),
        });
        let QueryResponse::ClearBackbonePeerState(true) = response else {
            panic!("expected successful peer-state clear");
        };

        let response = driver.handle_query(QueryRequest::BackbonePeerState {
            interface_name: Some("public".into()),
        });
        let QueryResponse::BackbonePeerState(entries) = response else {
            panic!("expected backbone peer state list");
        };
        assert!(entries.is_empty());
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn backbone_peer_blacklist_sets_blacklist() {
        let mut driver = new_test_driver();
        register_test_backbone(&mut driver, "public");
        driver
            .backbone_peer_state
            .get("public")
            .unwrap()
            .peer_state
            .lock()
            .unwrap()
            .seed_entry(BackbonePeerStateEntry {
                interface_name: "public".into(),
                peer_ip: "203.0.113.50".parse().unwrap(),
                connected_count: 1,
                blacklisted_remaining_secs: None,
                blacklist_reason: None,
                reject_count: 0,
            });

        let response = driver.handle_query_mut(QueryRequest::BlacklistBackbonePeer {
            interface_name: "public".into(),
            peer_ip: "203.0.113.50".parse().unwrap(),
            duration: Duration::from_secs(300),
            reason: "sentinel blacklist".into(),
            penalty_level: 2,
        });
        let QueryResponse::BlacklistBackbonePeer(true) = response else {
            panic!("expected successful blacklist");
        };

        // Verify the peer is now blacklisted
        let response = driver.handle_query(QueryRequest::BackbonePeerState {
            interface_name: Some("public".into()),
        });
        let QueryResponse::BackbonePeerState(entries) = response else {
            panic!("expected backbone peer state list");
        };
        let entry = entries
            .iter()
            .find(|e| e.peer_ip == "203.0.113.50".parse::<std::net::IpAddr>().unwrap())
            .expect("expected entry for blacklisted peer");
        assert!(entry.blacklisted_remaining_secs.is_some());
        let remaining = entry.blacklisted_remaining_secs.unwrap();
        assert!(remaining > 290.0 && remaining <= 300.0);
        assert_eq!(
            entry.blacklist_reason.as_deref(),
            Some("sentinel blacklist")
        );
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn backbone_peer_blacklist_unknown_interface_returns_false() {
        let mut driver = new_test_driver();
        let response = driver.handle_query_mut(QueryRequest::BlacklistBackbonePeer {
            interface_name: "nonexistent".into(),
            peer_ip: "203.0.113.50".parse().unwrap(),
            duration: Duration::from_secs(60),
            reason: "sentinel blacklist".into(),
            penalty_level: 1,
        });
        let QueryResponse::BlacklistBackbonePeer(false) = response else {
            panic!("expected false for unknown interface");
        };
    }

    #[cfg(feature = "iface-backbone")]
    #[test]
    fn backbone_peer_blacklist_creates_entry_for_unknown_ip() {
        let mut driver = new_test_driver();
        register_test_backbone(&mut driver, "public");

        // Blacklist an IP that has no existing peer state
        let response = driver.handle_query_mut(QueryRequest::BlacklistBackbonePeer {
            interface_name: "public".into(),
            peer_ip: "198.51.100.1".parse().unwrap(),
            duration: Duration::from_secs(120),
            reason: "sentinel blacklist".into(),
            penalty_level: 1,
        });
        let QueryResponse::BlacklistBackbonePeer(true) = response else {
            panic!("expected successful blacklist for new IP");
        };

        let response = driver.handle_query(QueryRequest::BackbonePeerState {
            interface_name: Some("public".into()),
        });
        let QueryResponse::BackbonePeerState(entries) = response else {
            panic!("expected backbone peer state list");
        };
        let entry = entries
            .iter()
            .find(|e| e.peer_ip == "198.51.100.1".parse::<std::net::IpAddr>().unwrap())
            .expect("expected entry for newly blacklisted IP");
        assert!(entry.blacklisted_remaining_secs.is_some());
    }

    #[cfg(feature = "iface-tcp")]
    #[test]
    fn runtime_config_lists_tcp_server_keys() {
        let mut driver = new_test_driver();
        register_test_tcp_server(&mut driver, "public");
        register_test_tcp_server_discovery(&mut driver, "public", false);
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"tcp_server.public.max_connections".to_string()));
        assert!(keys.contains(&"tcp_server.public.discoverable".to_string()));
        assert!(keys.contains(&"tcp_server.public.discovery_name".to_string()));
    }

    #[cfg(feature = "iface-tcp")]
    #[test]
    fn runtime_config_sets_tcp_server_values() {
        let mut driver = new_test_driver();
        register_test_tcp_server(&mut driver, "public");
        register_test_tcp_server_discovery(&mut driver, "public", false);
        driver.transport_identity = Some(rns_crypto::identity::Identity::new(&mut OsRng));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "tcp_server.public.max_connections".into(),
            value: RuntimeConfigValue::Int(0),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(0));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "tcp_server.public.max_connections".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(4));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "tcp_server.public.discoverable".into(),
            value: RuntimeConfigValue::Bool(true),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Bool(true));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "tcp_server.public.latitude".into(),
            value: RuntimeConfigValue::Float(41.9028),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(41.9028));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "tcp_server.public.latitude".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Null);
    }

    #[cfg(feature = "iface-tcp")]
    #[test]
    fn runtime_config_lists_tcp_client_keys() {
        let mut driver = new_test_driver();
        register_test_tcp_client(&mut driver, "uplink");
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"tcp_client.uplink.connect_timeout_secs".to_string()));
        assert!(keys.contains(&"tcp_client.uplink.reconnect_wait_secs".to_string()));
        assert!(keys.contains(&"tcp_client.uplink.max_reconnect_tries".to_string()));
    }

    #[cfg(feature = "iface-tcp")]
    #[test]
    fn runtime_config_sets_tcp_client_values() {
        let mut driver = new_test_driver();
        register_test_tcp_client(&mut driver, "uplink");

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "tcp_client.uplink.connect_timeout_secs".into(),
            value: RuntimeConfigValue::Float(2.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(2.5));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "tcp_client.uplink.max_reconnect_tries".into(),
            value: RuntimeConfigValue::Int(0),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(0));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "tcp_client.uplink.connect_timeout_secs".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected runtime config reset success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(5.0));
    }

    #[cfg(feature = "iface-udp")]
    #[test]
    fn runtime_config_lists_udp_keys() {
        let mut driver = new_test_driver();
        register_test_udp(&mut driver, "lan");
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"udp.lan.forward_ip".to_string()));
        assert!(keys.contains(&"udp.lan.forward_port".to_string()));
    }

    #[cfg(feature = "iface-udp")]
    #[test]
    fn runtime_config_sets_udp_values() {
        let mut driver = new_test_driver();
        register_test_udp(&mut driver, "lan");

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "udp.lan.forward_ip".into(),
            value: RuntimeConfigValue::String("192.168.1.10".into()),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(
            entry.value,
            RuntimeConfigValue::String("192.168.1.10".into())
        );

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "udp.lan.forward_port".into(),
            value: RuntimeConfigValue::Null,
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Null);

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "udp.lan.forward_port".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(4242));
    }

    #[cfg(feature = "iface-auto")]
    #[test]
    fn runtime_config_lists_auto_keys() {
        let mut driver = new_test_driver();
        register_test_auto(&mut driver, "lan");
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"auto.lan.announce_interval_secs".to_string()));
        assert!(keys.contains(&"auto.lan.peer_timeout_secs".to_string()));
        assert!(keys.contains(&"auto.lan.peer_job_interval_secs".to_string()));
    }

    #[cfg(feature = "iface-auto")]
    #[test]
    fn runtime_config_sets_auto_values() {
        let mut driver = new_test_driver();
        register_test_auto(&mut driver, "lan");

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "auto.lan.announce_interval_secs".into(),
            value: RuntimeConfigValue::Float(2.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(2.5));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "auto.lan.peer_timeout_secs".into(),
            value: RuntimeConfigValue::Float(30.0),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(30.0));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "auto.lan.peer_job_interval_secs".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(4.0));
    }

    #[cfg(feature = "iface-i2p")]
    #[test]
    fn runtime_config_lists_i2p_keys() {
        let mut driver = new_test_driver();
        register_test_i2p(&mut driver, "anon");
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"i2p.anon.reconnect_wait_secs".to_string()));
    }

    #[cfg(feature = "iface-i2p")]
    #[test]
    fn runtime_config_sets_i2p_values() {
        let mut driver = new_test_driver();
        register_test_i2p(&mut driver, "anon");

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "i2p.anon.reconnect_wait_secs".into(),
            value: RuntimeConfigValue::Float(3.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(3.5));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "i2p.anon.reconnect_wait_secs".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(15.0));
    }

    #[cfg(feature = "iface-pipe")]
    #[test]
    fn runtime_config_lists_pipe_keys() {
        let mut driver = new_test_driver();
        register_test_pipe(&mut driver, "worker");
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"pipe.worker.respawn_delay_secs".to_string()));
    }

    #[cfg(feature = "iface-pipe")]
    #[test]
    fn runtime_config_sets_pipe_values() {
        let mut driver = new_test_driver();
        register_test_pipe(&mut driver, "worker");

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "pipe.worker.respawn_delay_secs".into(),
            value: RuntimeConfigValue::Float(2.0),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(2.0));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "pipe.worker.respawn_delay_secs".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(5.0));
    }

    #[cfg(feature = "iface-rnode")]
    #[test]
    fn runtime_config_lists_rnode_keys() {
        let mut driver = new_test_driver();
        register_test_rnode(&mut driver, "radio");
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"rnode.radio.frequency_hz".to_string()));
        assert!(keys.contains(&"rnode.radio.bandwidth_hz".to_string()));
        assert!(keys.contains(&"rnode.radio.txpower_dbm".to_string()));
        assert!(keys.contains(&"rnode.radio.spreading_factor".to_string()));
        assert!(keys.contains(&"rnode.radio.coding_rate".to_string()));
        assert!(keys.contains(&"rnode.radio.st_alock_pct".to_string()));
        assert!(keys.contains(&"rnode.radio.lt_alock_pct".to_string()));
    }

    #[cfg(feature = "iface-rnode")]
    #[test]
    fn runtime_config_sets_rnode_values() {
        let mut driver = new_test_driver();
        register_test_rnode(&mut driver, "radio");

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "rnode.radio.frequency_hz".into(),
            value: RuntimeConfigValue::Int(915_000_000),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(915_000_000));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "rnode.radio.st_alock_pct".into(),
            value: RuntimeConfigValue::Float(12.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(12.5));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "rnode.radio.frequency_hz".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(868_000_000));
    }

    #[test]
    fn runtime_config_lists_generic_interface_keys() {
        let mut driver = new_test_driver();
        register_test_generic_interface(&mut driver, 1, "public");
        let response = driver.handle_query(QueryRequest::ListRuntimeConfig);
        let QueryResponse::RuntimeConfigList(entries) = response else {
            panic!("expected runtime config list");
        };
        let keys: Vec<String> = entries.into_iter().map(|entry| entry.key).collect();
        assert!(keys.contains(&"interface.public.enabled".to_string()));
        assert!(keys.contains(&"interface.public.mode".to_string()));
        assert!(keys.contains(&"interface.public.announce_rate_target".to_string()));
        assert!(keys.contains(&"interface.public.announce_rate_grace".to_string()));
        assert!(keys.contains(&"interface.public.announce_rate_penalty".to_string()));
        assert!(keys.contains(&"interface.public.announce_cap".to_string()));
        assert!(keys.contains(&"interface.public.ingress_control".to_string()));
        assert!(keys.contains(&"interface.public.ic_max_held_announces".to_string()));
        assert!(keys.contains(&"interface.public.ic_burst_hold".to_string()));
        assert!(keys.contains(&"interface.public.ic_burst_freq_new".to_string()));
        assert!(keys.contains(&"interface.public.ic_burst_freq".to_string()));
        assert!(keys.contains(&"interface.public.ic_new_time".to_string()));
        assert!(keys.contains(&"interface.public.ic_burst_penalty".to_string()));
        assert!(keys.contains(&"interface.public.ic_held_release_interval".to_string()));
        assert!(keys.contains(&"interface.public.ifac_netname".to_string()));
        assert!(keys.contains(&"interface.public.ifac_passphrase".to_string()));
        assert!(keys.contains(&"interface.public.ifac_size_bytes".to_string()));
    }

    #[test]
    fn runtime_config_sets_generic_interface_values() {
        let mut driver = new_test_driver();
        register_test_generic_interface(&mut driver, 1, "public");

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.enabled".into(),
            value: RuntimeConfigValue::Bool(false),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Bool(false));
        assert!(!driver.interfaces.get(&InterfaceId(1)).unwrap().enabled);

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.announce_cap".into(),
            value: RuntimeConfigValue::Float(0.15),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(0.15));
        assert_eq!(
            driver
                .engine
                .interface_info(&InterfaceId(1))
                .unwrap()
                .announce_cap,
            0.15
        );

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.mode".into(),
            value: RuntimeConfigValue::String("gateway".into()),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::String("gateway".into()));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "interface.public.mode".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::String("full".into()));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.ic_max_held_announces".into(),
            value: RuntimeConfigValue::Int(17),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(17));
        assert_eq!(
            driver
                .engine
                .interface_info(&InterfaceId(1))
                .unwrap()
                .ingress_control
                .max_held_announces,
            17
        );

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.ic_burst_hold".into(),
            value: RuntimeConfigValue::Float(1.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(1.5));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.ic_burst_freq_new".into(),
            value: RuntimeConfigValue::Float(2.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(2.5));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.ic_burst_freq".into(),
            value: RuntimeConfigValue::Float(3.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(3.5));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.ic_new_time".into(),
            value: RuntimeConfigValue::Float(4.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(4.5));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.ic_burst_penalty".into(),
            value: RuntimeConfigValue::Float(5.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(5.5));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.ic_held_release_interval".into(),
            value: RuntimeConfigValue::Float(6.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(6.5));

        let ingress_control = driver
            .engine
            .interface_info(&InterfaceId(1))
            .unwrap()
            .ingress_control;
        assert_eq!(ingress_control.burst_hold, 1.5);
        assert_eq!(ingress_control.burst_freq_new, 2.5);
        assert_eq!(ingress_control.burst_freq, 3.5);
        assert_eq!(ingress_control.new_time, 4.5);
        assert_eq!(ingress_control.burst_penalty, 5.5);
        assert_eq!(ingress_control.held_release_interval, 6.5);

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "interface.public.ic_max_held_announces".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(
            entry.value,
            RuntimeConfigValue::Int(rns_core::constants::IC_MAX_HELD_ANNOUNCES as i64)
        );

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "interface.public.enabled".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Bool(true));
        assert!(driver.interfaces.get(&InterfaceId(1)).unwrap().enabled);

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.ifac_netname".into(),
            value: RuntimeConfigValue::String("mesh".into()),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::String("mesh".into()));
        assert_eq!(
            driver
                .interfaces
                .get(&InterfaceId(1))
                .unwrap()
                .ifac
                .as_ref()
                .unwrap()
                .size,
            16
        );

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.ifac_passphrase".into(),
            value: RuntimeConfigValue::String("secret".into()),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::String("<redacted>".into()));

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "interface.public.ifac_size_bytes".into(),
            value: RuntimeConfigValue::Int(24),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(24));
        let ifac = driver
            .interfaces
            .get(&InterfaceId(1))
            .unwrap()
            .ifac
            .as_ref()
            .unwrap();
        assert_eq!(ifac.size, 24);

        let response = driver.handle_query(QueryRequest::GetRuntimeConfig {
            key: "interface.public.ifac_passphrase".into(),
        });
        let QueryResponse::RuntimeConfigEntry(Some(entry)) = response else {
            panic!("expected runtime config entry");
        };
        assert_eq!(entry.value, RuntimeConfigValue::String("<redacted>".into()));

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "interface.public.ifac_netname".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Null);
        assert!(driver
            .interfaces
            .get(&InterfaceId(1))
            .unwrap()
            .ifac
            .is_some());

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "interface.public.ifac_passphrase".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Null);
        assert!(driver
            .interfaces
            .get(&InterfaceId(1))
            .unwrap()
            .ifac
            .is_none());
    }

    #[cfg(feature = "rns-hooks")]
    #[test]
    fn runtime_config_sets_provider_bridge_values() {
        let mut driver = new_test_driver();

        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("provider.sock");
        let bridge = crate::provider_bridge::ProviderBridge::start(
            crate::provider_bridge::ProviderBridgeConfig {
                enabled: true,
                socket_path,
                queue_max_events: 1024,
                queue_max_bytes: 1024 * 1024,
                ..Default::default()
            },
        )
        .unwrap();
        driver.runtime_config_defaults.provider_queue_max_events = 1024;
        driver.runtime_config_defaults.provider_queue_max_bytes = 1024 * 1024;
        driver.provider_bridge = Some(bridge);

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "provider.queue_max_events".into(),
            value: RuntimeConfigValue::Int(4096),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(4096));
        assert_eq!(entry.source, RuntimeConfigSource::RuntimeOverride,);

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "provider.queue_max_bytes".into(),
            value: RuntimeConfigValue::Int(2 * 1024 * 1024),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected set ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(2 * 1024 * 1024));

        // Reject zero values
        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "provider.queue_max_events".into(),
            value: RuntimeConfigValue::Int(0),
        });
        assert!(matches!(response, QueryResponse::RuntimeConfigSet(Err(_))));

        // Reset
        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "provider.queue_max_events".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(1024));
        assert_eq!(entry.source, RuntimeConfigSource::Startup);

        let response = driver.handle_query_mut(QueryRequest::ResetRuntimeConfig {
            key: "provider.queue_max_bytes".into(),
        });
        let QueryResponse::RuntimeConfigReset(Ok(entry)) = response else {
            panic!("expected reset ok");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Int(1024 * 1024));
    }

    #[test]
    fn disabled_interface_drops_ingress_and_egress() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.register_interface_runtime_defaults(&info);
        driver.engine.register_interface(info.clone());
        let (writer, sent) = MockWriter::new();
        driver.interfaces.insert(
            InterfaceId(1),
            InterfaceEntry {
                id: InterfaceId(1),
                info,
                writer: Box::new(writer),
                async_writer_metrics: None,
                enabled: false,
                online: true,
                dynamic: false,
                ifac: None,
                stats: InterfaceStats::default(),
                interface_type: String::new(),
                send_retry_at: None,
                send_retry_backoff: Duration::ZERO,
            },
        );

        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(1),
            raw: vec![0x00, 0x01, 0x42],
        }]);
        assert!(sent.lock().unwrap().is_empty());

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: vec![0x00, 0x01, 0x42],
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let entry = driver.interfaces.get(&InterfaceId(1)).unwrap();
        assert_eq!(entry.stats.rxb, 0);
        assert_eq!(entry.stats.rx_packets, 0);
    }

    #[test]
    fn management_announces_not_emitted_when_disabled() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let identity = Identity::new(&mut OsRng);
        let identity_hash = *identity.hash();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: true,
                identity_hash: Some(identity_hash),
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Management announces disabled (default)
        driver.transport_identity = Some(identity);
        driver.started = time::now() - 10.0;

        tx.send(Event::Tick).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should NOT have sent any packets
        let sent_packets = sent.lock().unwrap();
        assert!(
            sent_packets.is_empty(),
            "No announces should be sent when management is disabled"
        );
    }

    #[test]
    fn management_announces_not_emitted_before_delay() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let identity = Identity::new(&mut OsRng);
        let identity_hash = *identity.hash();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: true,
                identity_hash: Some(identity_hash),
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        driver.management_config.enable_remote_management = true;
        driver.transport_identity = Some(identity);
        // Started just now - delay hasn't passed
        driver.started = time::now();

        tx.send(Event::Tick).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let sent_packets = sent.lock().unwrap();
        assert!(sent_packets.is_empty(), "No announces before startup delay");
    }

    // =========================================================================
    // Phase 9c: Announce + Discovery tests
    // =========================================================================

    #[test]
    fn announce_received_populates_known_destinations() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);

        let dest_hash =
            rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // known_destinations should be populated
        assert!(driver.known_destinations.contains_key(&dest_hash));
        let recalled = &driver.known_destinations[&dest_hash];
        assert_eq!(recalled.announced.dest_hash.0, dest_hash);
        assert_eq!(recalled.announced.identity_hash.0, *identity.hash());
        assert_eq!(
            &recalled.announced.public_key,
            &identity.get_public_key().unwrap()
        );
        assert_eq!(recalled.announced.hops, 1);
    }

    #[test]
    fn known_destinations_cleanup_respects_ttl() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        driver.known_destinations_ttl = 10.0;
        driver.cache_cleanup_counter = 3599;

        let stale_dest = [0x11; 16];
        let fresh_dest = [0x22; 16];
        driver.known_destinations.insert(
            stale_dest,
            KnownDestinationState {
                announced: crate::destination::AnnouncedIdentity {
                    dest_hash: rns_core::types::DestHash(stale_dest),
                    identity_hash: rns_core::types::IdentityHash([0x33; 16]),
                    public_key: [0x44; 64],
                    app_data: None,
                    hops: 1,
                    received_at: time::now() - 20.0,
                    receiving_interface: InterfaceId(1),
                },
                was_used: false,
                last_used_at: None,
                retained: false,
            },
        );
        driver.known_destinations.insert(
            fresh_dest,
            KnownDestinationState {
                announced: crate::destination::AnnouncedIdentity {
                    dest_hash: rns_core::types::DestHash(fresh_dest),
                    identity_hash: rns_core::types::IdentityHash([0x55; 16]),
                    public_key: [0x66; 64],
                    app_data: None,
                    hops: 1,
                    received_at: time::now() - 5.0,
                    receiving_interface: InterfaceId(1),
                },
                was_used: false,
                last_used_at: None,
                retained: false,
            },
        );

        tx.send(Event::Tick).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert!(!driver.known_destinations.contains_key(&stale_dest));
        assert!(driver.known_destinations.contains_key(&fresh_dest));
    }

    #[test]
    fn known_destinations_cap_prefers_evicting_oldest_non_active_non_local() {
        let mut driver = new_test_driver();
        driver.known_destinations_max_entries = 2;
        driver.engine.register_interface(make_interface_info(1));

        let active_dest = [0x11; 16];
        let evictable_dest = [0x22; 16];
        let new_dest = [0x33; 16];

        driver.engine.inject_path(
            active_dest,
            PathEntry {
                timestamp: 100.0,
                next_hop: [0x44; 16],
                hops: 1,
                expires: 1000.0,
                random_blobs: Vec::new(),
                receiving_interface: InterfaceId(1),
                packet_hash: [0x55; 32],
                announce_raw: None,
            },
        );

        driver.upsert_known_destination(
            active_dest,
            make_announced_identity(active_dest, 10.0, InterfaceId(1)),
        );
        driver.upsert_known_destination(
            evictable_dest,
            make_announced_identity(evictable_dest, 20.0, InterfaceId(1)),
        );
        driver.upsert_known_destination(
            new_dest,
            make_announced_identity(new_dest, 30.0, InterfaceId(1)),
        );

        assert!(driver.known_destinations.contains_key(&active_dest));
        assert!(!driver.known_destinations.contains_key(&evictable_dest));
        assert!(driver.known_destinations.contains_key(&new_dest));
        assert_eq!(driver.known_destinations_cap_evict_count, 1);
    }

    #[test]
    fn known_destinations_cap_falls_back_to_oldest_overall_when_all_protected() {
        let mut driver = new_test_driver();
        driver.known_destinations_max_entries = 2;

        let local_oldest = [0x41; 16];
        let local_newer = [0x42; 16];
        let new_dest = [0x43; 16];
        driver
            .local_destinations
            .insert(local_oldest, rns_core::constants::DESTINATION_SINGLE);
        driver
            .local_destinations
            .insert(local_newer, rns_core::constants::DESTINATION_SINGLE);

        driver.upsert_known_destination(
            local_oldest,
            make_announced_identity(local_oldest, 10.0, InterfaceId(1)),
        );
        driver.upsert_known_destination(
            local_newer,
            make_announced_identity(local_newer, 20.0, InterfaceId(1)),
        );
        driver.upsert_known_destination(
            new_dest,
            make_announced_identity(new_dest, 30.0, InterfaceId(1)),
        );

        assert!(!driver.known_destinations.contains_key(&local_oldest));
        assert!(driver.known_destinations.contains_key(&local_newer));
        assert!(driver.known_destinations.contains_key(&new_dest));
        assert_eq!(driver.known_destinations_cap_evict_count, 1);
    }

    #[test]
    fn known_destinations_cap_update_existing_entry_does_not_evict() {
        let mut driver = new_test_driver();
        driver.known_destinations_max_entries = 1;

        let dest = [0x61; 16];
        driver.upsert_known_destination(dest, make_announced_identity(dest, 10.0, InterfaceId(1)));
        driver.upsert_known_destination(dest, make_announced_identity(dest, 20.0, InterfaceId(2)));

        assert_eq!(driver.known_destinations.len(), 1);
        assert_eq!(
            driver.known_destinations[&dest]
                .announced
                .receiving_interface,
            InterfaceId(2)
        );
        assert_eq!(driver.known_destinations_cap_evict_count, 0);
    }

    #[test]
    fn known_destinations_cleanup_enforces_cap() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        driver.known_destinations_ttl = 1000.0;
        driver.known_destinations_max_entries = 2;
        driver.cache_cleanup_counter = 3599;
        let now = time::now();
        driver.known_destinations.insert(
            [0x71; 16],
            make_known_destination_state([0x71; 16], now - 30.0, InterfaceId(1)),
        );
        driver.known_destinations.insert(
            [0x72; 16],
            make_known_destination_state([0x72; 16], now - 20.0, InterfaceId(1)),
        );
        driver.known_destinations.insert(
            [0x73; 16],
            make_known_destination_state([0x73; 16], now - 10.0, InterfaceId(1)),
        );

        tx.send(Event::Tick).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert_eq!(driver.known_destinations.len(), 2);
        assert!(!driver.known_destinations.contains_key(&[0x71; 16]));
        assert_eq!(driver.known_destinations_cap_evict_count, 1);
    }

    #[test]
    fn recall_identity_marks_known_destination_used() {
        let mut driver = new_test_driver();
        let dest = [0x81; 16];
        driver.upsert_known_destination(dest, make_announced_identity(dest, 10.0, InterfaceId(1)));

        let response = driver.handle_query_mut(QueryRequest::RecallIdentity { dest_hash: dest });
        assert!(matches!(response, QueryResponse::RecallIdentity(Some(_))));

        let entry = driver.known_destinations.get(&dest).unwrap();
        assert!(entry.was_used);
        assert!(entry.last_used_at.is_some());
    }

    #[test]
    fn retained_known_destination_survives_cleanup() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        driver.known_destinations_ttl = 10.0;
        driver.cache_cleanup_counter = 3599;

        let dest = [0x82; 16];
        driver.upsert_known_destination(
            dest,
            make_announced_identity(dest, time::now() - 30.0, InterfaceId(1)),
        );
        assert!(driver.retain_known_destination(&dest));

        tx.send(Event::Tick).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert!(driver.known_destinations.contains_key(&dest));
    }

    #[test]
    fn used_known_destination_cleanup_uses_last_used_time() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        driver.known_destinations_ttl = 10.0;
        driver.cache_cleanup_counter = 3599;

        let dest = [0x83; 16];
        driver.known_destinations.insert(
            dest,
            KnownDestinationState {
                announced: make_announced_identity(dest, time::now() - 50.0, InterfaceId(1)),
                was_used: true,
                last_used_at: Some(time::now() - 5.0),
                retained: false,
            },
        );

        tx.send(Event::Tick).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert!(driver.known_destinations.contains_key(&dest));
    }

    #[test]
    fn query_has_path() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // No path yet
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::HasPath {
                dest_hash: [0xAA; 16],
            },
            resp_tx,
        ))
        .unwrap();

        // Feed an announce to create a path
        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);
        let dest_hash =
            rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));
        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();

        let (resp_tx2, resp_rx2) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::HasPath { dest_hash }, resp_tx2))
            .unwrap();

        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // First query — no path
        match resp_rx.recv().unwrap() {
            QueryResponse::HasPath(false) => {}
            other => panic!("expected HasPath(false), got {:?}", other),
        }

        // Second query — path exists
        match resp_rx2.recv().unwrap() {
            QueryResponse::HasPath(true) => {}
            other => panic!("expected HasPath(true), got {:?}", other),
        }
    }

    #[test]
    fn query_hops_to() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Feed an announce
        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);
        let dest_hash =
            rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::HopsTo { dest_hash }, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::HopsTo(Some(1)) => {}
            other => panic!("expected HopsTo(Some(1)), got {:?}", other),
        }
    }

    #[test]
    fn query_recall_identity() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);
        let dest_hash =
            rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();

        // Recall identity
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::RecallIdentity { dest_hash },
            resp_tx,
        ))
        .unwrap();

        // Also recall unknown destination
        let (resp_tx2, resp_rx2) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::RecallIdentity {
                dest_hash: [0xFF; 16],
            },
            resp_tx2,
        ))
        .unwrap();

        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::RecallIdentity(Some(recalled)) => {
                assert_eq!(recalled.dest_hash.0, dest_hash);
                assert_eq!(recalled.identity_hash.0, *identity.hash());
                assert_eq!(recalled.public_key, identity.get_public_key().unwrap());
                assert_eq!(recalled.hops, 1);
            }
            other => panic!("expected RecallIdentity(Some(..)), got {:?}", other),
        }

        match resp_rx2.recv().unwrap() {
            QueryResponse::RecallIdentity(None) => {}
            other => panic!("expected RecallIdentity(None), got {:?}", other),
        }
    }

    #[test]
    fn request_path_sends_packet() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Send path request
        tx.send(Event::RequestPath {
            dest_hash: [0xAA; 16],
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should have sent a packet on the wire (broadcast)
        let sent_packets = sent.lock().unwrap();
        assert!(
            !sent_packets.is_empty(),
            "Path request should be sent on wire"
        );

        // Verify the sent packet is a DATA PLAIN BROADCAST packet
        let raw = &sent_packets[0];
        let flags = rns_core::packet::PacketFlags::unpack(raw[0] & 0x7F);
        assert_eq!(flags.packet_type, constants::PACKET_TYPE_DATA);
        assert_eq!(flags.destination_type, constants::DESTINATION_PLAIN);
        assert_eq!(flags.transport_type, constants::TRANSPORT_BROADCAST);
    }

    #[test]
    fn request_path_includes_transport_id() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: true,
                identity_hash: Some([0xBB; 16]),
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        tx.send(Event::RequestPath {
            dest_hash: [0xAA; 16],
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let sent_packets = sent.lock().unwrap();
        assert!(!sent_packets.is_empty());

        // Unpack the packet to check data length includes transport_id
        let raw = &sent_packets[0];
        if let Ok(packet) = RawPacket::unpack(raw) {
            // Data: dest_hash(16) + transport_id(16) + random_tag(16) = 48 bytes
            assert_eq!(
                packet.data.len(),
                48,
                "Path request data should be 48 bytes with transport_id"
            );
            assert_eq!(
                &packet.data[..16],
                &[0xAA; 16],
                "First 16 bytes should be dest_hash"
            );
            assert_eq!(
                &packet.data[16..32],
                &[0xBB; 16],
                "Next 16 bytes should be transport_id"
            );
        } else {
            panic!("Could not unpack sent packet");
        }
    }

    #[test]
    fn path_request_dest_registered() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        // The path request dest should be registered as a local PLAIN destination
        let expected_dest =
            rns_core::destination::destination_hash("rnstransport", &["path", "request"], None);
        assert_eq!(driver.path_request_dest, expected_dest);

        drop(tx);
    }

    // =========================================================================
    // Phase 9d: send_packet + proofs tests
    // =========================================================================

    #[test]
    fn register_proof_strategy_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let dest = [0xAA; 16];
        let identity = Identity::new(&mut OsRng);
        let prv_key = identity.get_private_key().unwrap();

        tx.send(Event::RegisterProofStrategy {
            dest_hash: dest,
            strategy: rns_core::types::ProofStrategy::ProveAll,
            signing_key: Some(prv_key),
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert!(driver.proof_strategies.contains_key(&dest));
        let (strategy, ref id_opt) = driver.proof_strategies[&dest];
        assert_eq!(strategy, rns_core::types::ProofStrategy::ProveAll);
        assert!(id_opt.is_some());
    }

    #[test]
    fn register_proof_strategy_prove_none_no_identity() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let dest = [0xBB; 16];
        tx.send(Event::RegisterProofStrategy {
            dest_hash: dest,
            strategy: rns_core::types::ProofStrategy::ProveNone,
            signing_key: None,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert!(driver.proof_strategies.contains_key(&dest));
        let (strategy, ref id_opt) = driver.proof_strategies[&dest];
        assert_eq!(strategy, rns_core::types::ProofStrategy::ProveNone);
        assert!(id_opt.is_none());
    }

    #[test]
    fn send_outbound_tracks_sent_packets() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Build a DATA packet
        let dest = [0xCC; 16];
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"test data").unwrap();
        let expected_hash = packet.packet_hash;

        tx.send(Event::SendOutbound {
            raw: packet.raw,
            dest_type: constants::DESTINATION_PLAIN,
            attached_interface: None,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should be tracking the sent packet
        assert!(driver.sent_packets.contains_key(&expected_hash));
        let (tracked_dest, _sent_time) = &driver.sent_packets[&expected_hash];
        assert_eq!(tracked_dest, &dest);
    }

    #[test]
    fn prove_all_generates_proof_on_delivery() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, deliveries, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register a destination with ProveAll
        let dest = [0xDD; 16];
        let identity = Identity::new(&mut OsRng);
        let prv_key = identity.get_private_key().unwrap();
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);
        driver.proof_strategies.insert(
            dest,
            (
                rns_core::types::ProofStrategy::ProveAll,
                Some(Identity::from_private_key(&prv_key)),
            ),
        );

        // Send a DATA packet to that destination
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should have delivered the packet
        assert_eq!(deliveries.lock().unwrap().len(), 1);

        // Should have sent at least one proof packet on the wire
        let sent_packets = sent.lock().unwrap();
        // The original DATA is not sent out (it was delivered locally), but a PROOF should be
        let has_proof = sent_packets.iter().any(|raw| {
            let flags = PacketFlags::unpack(raw[0] & 0x7F);
            flags.packet_type == constants::PACKET_TYPE_PROOF
        });
        assert!(
            has_proof,
            "ProveAll should generate a proof packet: sent {} packets",
            sent_packets.len()
        );
    }

    #[test]
    fn prove_none_does_not_generate_proof() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, deliveries, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register a destination with ProveNone
        let dest = [0xDD; 16];
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);
        driver
            .proof_strategies
            .insert(dest, (rns_core::types::ProofStrategy::ProveNone, None));

        // Send a DATA packet to that destination
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should have delivered the packet
        assert_eq!(deliveries.lock().unwrap().len(), 1);

        // Should NOT have sent any proof
        let sent_packets = sent.lock().unwrap();
        let has_proof = sent_packets.iter().any(|raw| {
            let flags = PacketFlags::unpack(raw[0] & 0x7F);
            flags.packet_type == constants::PACKET_TYPE_PROOF
        });
        assert!(!has_proof, "ProveNone should not generate a proof packet");
    }

    #[test]
    fn no_proof_strategy_does_not_generate_proof() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, deliveries, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register destination but NO proof strategy
        let dest = [0xDD; 16];
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert_eq!(deliveries.lock().unwrap().len(), 1);

        let sent_packets = sent.lock().unwrap();
        let has_proof = sent_packets.iter().any(|raw| {
            let flags = PacketFlags::unpack(raw[0] & 0x7F);
            flags.packet_type == constants::PACKET_TYPE_PROOF
        });
        assert!(!has_proof, "No proof strategy means no proof generated");
    }

    #[test]
    fn prove_app_calls_callback() {
        let (tx, rx) = event::channel();
        let proof_requested = Arc::new(Mutex::new(Vec::new()));
        let deliveries = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: deliveries.clone(),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: Arc::new(Mutex::new(Vec::new())),
            proof_requested: proof_requested.clone(),
        };

        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register dest with ProveApp
        let dest = [0xDD; 16];
        let identity = Identity::new(&mut OsRng);
        let prv_key = identity.get_private_key().unwrap();
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);
        driver.proof_strategies.insert(
            dest,
            (
                rns_core::types::ProofStrategy::ProveApp,
                Some(Identity::from_private_key(&prv_key)),
            ),
        );

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"app test").unwrap();

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // on_proof_requested should have been called
        let prs = proof_requested.lock().unwrap();
        assert_eq!(prs.len(), 1);
        assert_eq!(prs[0].0, DestHash(dest));

        // Since our mock returns true, a proof should also have been sent
        let sent_packets = sent.lock().unwrap();
        let has_proof = sent_packets.iter().any(|raw| {
            let flags = PacketFlags::unpack(raw[0] & 0x7F);
            flags.packet_type == constants::PACKET_TYPE_PROOF
        });
        assert!(
            has_proof,
            "ProveApp (callback returns true) should generate a proof"
        );
    }

    #[test]
    fn inbound_proof_fires_callback() {
        let (tx, rx) = event::channel();
        let proofs = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: proofs.clone(),
            proof_requested: Arc::new(Mutex::new(Vec::new())),
        };

        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register a destination so proof packets can be delivered locally
        let dest = [0xEE; 16];
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);

        // Simulate a sent packet that we're tracking
        let tracked_hash = [0x42u8; 32];
        let sent_time = time::now() - 0.5; // 500ms ago
        driver.sent_packets.insert(tracked_hash, (dest, sent_time));

        // Build a PROOF packet with the tracked hash + dummy signature
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&tracked_hash);
        proof_data.extend_from_slice(&[0xAA; 64]); // dummy signature

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, &proof_data).unwrap();

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // on_proof callback should have been fired
        let proof_list = proofs.lock().unwrap();
        assert_eq!(proof_list.len(), 1);
        assert_eq!(proof_list[0].0, DestHash(dest));
        assert_eq!(proof_list[0].1, PacketHash(tracked_hash));
        assert!(
            proof_list[0].2 >= 0.4,
            "RTT should be approximately 0.5s, got {}",
            proof_list[0].2
        );

        // Tracked packet should be removed
        assert!(!driver.sent_packets.contains_key(&tracked_hash));
    }

    #[test]
    fn inbound_proof_for_unknown_packet_is_ignored() {
        let (tx, rx) = event::channel();
        let proofs = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: proofs.clone(),
            proof_requested: Arc::new(Mutex::new(Vec::new())),
        };

        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let dest = [0xEE; 16];
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);

        // Build a PROOF packet for an untracked hash
        let unknown_hash = [0xFF; 32];
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&unknown_hash);
        proof_data.extend_from_slice(&[0xAA; 64]);

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, &proof_data).unwrap();

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // on_proof should NOT have been called
        assert!(proofs.lock().unwrap().is_empty());
    }

    #[test]
    fn inbound_implicit_proof_matches_truncated_destination() {
        let (tx, rx) = event::channel();
        let proofs = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: proofs.clone(),
            proof_requested: Arc::new(Mutex::new(Vec::new())),
        };

        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let tracked_hash = [0x3Cu8; 32];
        let sent_time = time::now() - 0.25;
        driver
            .sent_packets
            .insert(tracked_hash, ([0xEE; 16], sent_time));

        let mut proof_dest = [0u8; 16];
        proof_dest.copy_from_slice(&tracked_hash[..16]);
        driver
            .engine
            .register_destination(proof_dest, constants::DESTINATION_SINGLE);

        // Implicit proof is signature-only (64 bytes)
        let proof_data = vec![0xAA; 64];
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        let packet = RawPacket::pack(
            flags,
            0,
            &proof_dest,
            None,
            constants::CONTEXT_NONE,
            &proof_data,
        )
        .unwrap();

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let proof_list = proofs.lock().unwrap();
        assert_eq!(proof_list.len(), 1);
        assert_eq!(proof_list[0].0, DestHash([0xEE; 16]));
        assert_eq!(proof_list[0].1, PacketHash(tracked_hash));
        assert!(!driver.sent_packets.contains_key(&tracked_hash));
    }

    #[test]
    fn link_manager_data_send_is_tracked_for_proofs() {
        let mut driver = new_test_driver();
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

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
            &[0x77; 16],
            None,
            constants::CONTEXT_NONE,
            b"track me",
        )
        .unwrap();
        let packet_hash = packet.packet_hash;
        let destination_hash = packet.destination_hash;

        driver.dispatch_link_actions(vec![LinkManagerAction::SendPacket {
            raw: packet.raw,
            dest_type: constants::DESTINATION_LINK,
            attached_interface: Some(InterfaceId(1)),
        }]);

        assert_eq!(
            driver.sent_packets.get(&packet_hash).map(|(dest, _)| *dest),
            Some(destination_hash)
        );
    }

    #[test]
    fn inbound_proof_with_valid_signature_fires_callback() {
        // When the destination IS in known_destinations, the proof signature is verified
        let (tx, rx) = event::channel();
        let proofs = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: proofs.clone(),
            proof_requested: Arc::new(Mutex::new(Vec::new())),
        };

        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let dest = [0xEE; 16];
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);

        // Create real identity and add to known_destinations
        let identity = Identity::new(&mut OsRng);
        let pub_key = identity.get_public_key();
        driver.known_destinations.insert(
            dest,
            KnownDestinationState {
                announced: crate::destination::AnnouncedIdentity {
                    dest_hash: DestHash(dest),
                    identity_hash: IdentityHash(*identity.hash()),
                    public_key: pub_key.unwrap(),
                    app_data: None,
                    hops: 0,
                    received_at: time::now(),
                    receiving_interface: InterfaceId(0),
                },
                was_used: false,
                last_used_at: None,
                retained: false,
            },
        );

        // Sign a packet hash with the identity
        let tracked_hash = [0x42u8; 32];
        let sent_time = time::now() - 0.5;
        driver.sent_packets.insert(tracked_hash, (dest, sent_time));

        let signature = identity.sign(&tracked_hash).unwrap();
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&tracked_hash);
        proof_data.extend_from_slice(&signature);

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, &proof_data).unwrap();

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Valid signature: on_proof should fire
        let proof_list = proofs.lock().unwrap();
        assert_eq!(proof_list.len(), 1);
        assert_eq!(proof_list[0].0, DestHash(dest));
        assert_eq!(proof_list[0].1, PacketHash(tracked_hash));
    }

    #[test]
    fn inbound_proof_with_invalid_signature_rejected() {
        // When known_destinations has the public key, bad signatures are rejected
        let (tx, rx) = event::channel();
        let proofs = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: proofs.clone(),
            proof_requested: Arc::new(Mutex::new(Vec::new())),
        };

        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let dest = [0xEE; 16];
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);

        // Create identity and add to known_destinations
        let identity = Identity::new(&mut OsRng);
        let pub_key = identity.get_public_key();
        driver.known_destinations.insert(
            dest,
            KnownDestinationState {
                announced: crate::destination::AnnouncedIdentity {
                    dest_hash: DestHash(dest),
                    identity_hash: IdentityHash(*identity.hash()),
                    public_key: pub_key.unwrap(),
                    app_data: None,
                    hops: 0,
                    received_at: time::now(),
                    receiving_interface: InterfaceId(0),
                },
                was_used: false,
                last_used_at: None,
                retained: false,
            },
        );

        // Track a sent packet
        let tracked_hash = [0x42u8; 32];
        let sent_time = time::now() - 0.5;
        driver.sent_packets.insert(tracked_hash, (dest, sent_time));

        // Use WRONG signature (all 0xAA — invalid for this identity)
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&tracked_hash);
        proof_data.extend_from_slice(&[0xAA; 64]);

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        let packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, &proof_data).unwrap();

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Invalid signature: on_proof should NOT fire
        assert!(proofs.lock().unwrap().is_empty());
    }

    #[test]
    fn proof_data_is_valid_explicit_proof() {
        // Verify that the proof generated by ProveAll is a valid explicit proof
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let dest = [0xDD; 16];
        let identity = Identity::new(&mut OsRng);
        let prv_key = identity.get_private_key().unwrap();
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);
        driver.proof_strategies.insert(
            dest,
            (
                rns_core::types::ProofStrategy::ProveAll,
                Some(Identity::from_private_key(&prv_key)),
            ),
        );

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let data_packet =
            RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"verify me").unwrap();
        let data_packet_hash = data_packet.packet_hash;

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: data_packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Find the proof packet in sent
        let sent_packets = sent.lock().unwrap();
        let proof_raw = sent_packets.iter().find(|raw| {
            let f = PacketFlags::unpack(raw[0] & 0x7F);
            f.packet_type == constants::PACKET_TYPE_PROOF
        });
        assert!(proof_raw.is_some(), "Should have sent a proof");

        let proof_packet = RawPacket::unpack(proof_raw.unwrap()).unwrap();
        // Proof data should be 96 bytes: packet_hash(32) + signature(64)
        assert_eq!(
            proof_packet.data.len(),
            96,
            "Explicit proof should be 96 bytes"
        );

        // Validate using rns-core's receipt module
        let result = rns_core::receipt::validate_proof(
            &proof_packet.data,
            &data_packet_hash,
            &Identity::from_private_key(&prv_key), // same identity
        );
        assert_eq!(result, rns_core::receipt::ProofResult::Valid);
    }

    #[test]
    fn query_local_destinations_empty() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let driver_config = TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
        };
        let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::LocalDestinations, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::LocalDestinations(entries) => {
                // Should contain the two internal destinations (tunnel_synth + path_request)
                assert_eq!(entries.len(), 2);
                for entry in &entries {
                    assert_eq!(entry.dest_type, rns_core::constants::DESTINATION_PLAIN);
                }
            }
            other => panic!("expected LocalDestinations, got {:?}", other),
        }
    }

    #[test]
    fn query_local_destinations_with_registered() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let driver_config = TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
        };
        let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

        let dest_hash = [0xAA; 16];
        tx.send(Event::RegisterDestination {
            dest_hash,
            dest_type: rns_core::constants::DESTINATION_SINGLE,
        })
        .unwrap();

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::LocalDestinations, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::LocalDestinations(entries) => {
                // 2 internal + 1 registered
                assert_eq!(entries.len(), 3);
                assert!(entries.iter().any(|e| e.hash == dest_hash
                    && e.dest_type == rns_core::constants::DESTINATION_SINGLE));
            }
            other => panic!("expected LocalDestinations, got {:?}", other),
        }
    }

    #[test]
    fn query_local_destinations_tracks_link_dest() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let driver_config = TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
        };
        let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

        let dest_hash = [0xBB; 16];
        tx.send(Event::RegisterLinkDestination {
            dest_hash,
            sig_prv_bytes: [0x11; 32],
            sig_pub_bytes: [0x22; 32],
            resource_strategy: 0,
        })
        .unwrap();

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::LocalDestinations, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::LocalDestinations(entries) => {
                // 2 internal + 1 link destination
                assert_eq!(entries.len(), 3);
                assert!(entries.iter().any(|e| e.hash == dest_hash
                    && e.dest_type == rns_core::constants::DESTINATION_SINGLE));
            }
            other => panic!("expected LocalDestinations, got {:?}", other),
        }
    }

    #[test]
    fn query_links_empty() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let driver_config = TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
        };
        let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::Links, resp_tx)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::Links(entries) => {
                assert!(entries.is_empty());
            }
            other => panic!("expected Links, got {:?}", other),
        }
    }

    #[test]
    fn query_resources_empty() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let driver_config = TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
        };
        let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::Resources, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::Resources(entries) => {
                assert!(entries.is_empty());
            }
            other => panic!("expected Resources, got {:?}", other),
        }
    }

    #[test]
    fn infer_interface_type_from_name() {
        assert_eq!(
            super::infer_interface_type("TCPServerInterface/Client-1234"),
            "TCPServerClientInterface"
        );
        assert_eq!(
            super::infer_interface_type("BackboneInterface/5"),
            "BackboneInterface"
        );
        assert_eq!(
            super::infer_interface_type("LocalInterface"),
            "LocalServerClientInterface"
        );
        assert_eq!(
            super::infer_interface_type("MyAutoGroup:fe80::1"),
            "AutoInterface"
        );
    }

    // ---- extract_dest_hash tests ----

    #[test]
    fn test_extract_dest_hash_empty() {
        assert_eq!(super::extract_dest_hash(&[]), [0u8; 16]);
    }

    // =========================================================================
    // Probe tests: SendProbe, CheckProof, completed_proofs, probe_responder
    // =========================================================================

    #[test]
    fn send_probe_unknown_dest_returns_none() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // SendProbe for a dest_hash with no known identity should return None
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::SendProbe {
                dest_hash: [0xAA; 16],
                payload_size: 16,
            },
            resp_tx,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::SendProbe(None) => {}
            other => panic!("expected SendProbe(None), got {:?}", other),
        }
    }

    #[test]
    fn send_probe_known_dest_returns_packet_hash() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Inject a known identity so SendProbe can encrypt to it
        let remote_identity = Identity::new(&mut OsRng);
        let dest_hash = rns_core::destination::destination_hash(
            "rnstransport",
            &["probe"],
            Some(remote_identity.hash()),
        );

        // First inject the identity via announce
        let (inject_tx, inject_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::InjectIdentity {
                dest_hash,
                identity_hash: *remote_identity.hash(),
                public_key: remote_identity.get_public_key().unwrap(),
                app_data: None,
                hops: 1,
                received_at: 0.0,
            },
            inject_tx,
        ))
        .unwrap();

        // Now send the probe
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::SendProbe {
                dest_hash,
                payload_size: 16,
            },
            resp_tx,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Verify injection succeeded
        match inject_rx.recv().unwrap() {
            QueryResponse::InjectIdentity(true) => {}
            other => panic!("expected InjectIdentity(true), got {:?}", other),
        }

        // Verify probe sent
        match resp_rx.recv().unwrap() {
            QueryResponse::SendProbe(Some((packet_hash, _hops))) => {
                // Packet hash should be non-zero
                assert_ne!(packet_hash, [0u8; 32]);
                // Should be tracked in sent_packets
                assert!(driver.sent_packets.contains_key(&packet_hash));
                // Should have sent a DATA packet on the wire
                let sent_data = sent.lock().unwrap();
                assert!(!sent_data.is_empty(), "Probe packet should be sent on wire");
                // Verify it's a DATA SINGLE packet
                let raw = &sent_data[0];
                let flags = PacketFlags::unpack(raw[0] & 0x7F);
                assert_eq!(flags.packet_type, constants::PACKET_TYPE_DATA);
                assert_eq!(flags.destination_type, constants::DESTINATION_SINGLE);
            }
            other => panic!("expected SendProbe(Some(..)), got {:?}", other),
        }
    }

    #[test]
    fn check_proof_not_found_returns_none() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::CheckProof {
                packet_hash: [0xBB; 32],
            },
            resp_tx,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::CheckProof(None) => {}
            other => panic!("expected CheckProof(None), got {:?}", other),
        }
    }

    #[test]
    fn check_proof_found_returns_rtt() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        // Pre-populate completed_proofs
        let packet_hash = [0xCC; 32];
        driver
            .completed_proofs
            .insert(packet_hash, (0.123, time::now()));

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::CheckProof { packet_hash },
            resp_tx,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::CheckProof(Some(rtt)) => {
                assert!(
                    (rtt - 0.123).abs() < 0.001,
                    "RTT should be ~0.123, got {}",
                    rtt
                );
            }
            other => panic!("expected CheckProof(Some(..)), got {:?}", other),
        }
        // Should be consumed (removed) after checking
        assert!(!driver.completed_proofs.contains_key(&packet_hash));
    }

    #[test]
    fn inbound_proof_populates_completed_proofs() {
        let (tx, rx) = event::channel();
        let proofs = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: proofs.clone(),
            proof_requested: Arc::new(Mutex::new(Vec::new())),
        };

        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register a destination with ProveAll so we can get a proof back
        let dest = [0xDD; 16];
        let identity = Identity::new(&mut OsRng);
        let prv_key = identity.get_private_key().unwrap();
        driver
            .engine
            .register_destination(dest, constants::DESTINATION_SINGLE);
        driver.proof_strategies.insert(
            dest,
            (
                rns_core::types::ProofStrategy::ProveAll,
                Some(Identity::from_private_key(&prv_key)),
            ),
        );

        // Build and send a DATA packet to the dest (this creates a sent_packet + proof)
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let data_packet = RawPacket::pack(
            flags,
            0,
            &dest,
            None,
            constants::CONTEXT_NONE,
            b"probe data",
        )
        .unwrap();
        let data_packet_hash = data_packet.packet_hash;

        // Track it as a sent packet so the proof handler recognizes it
        driver
            .sent_packets
            .insert(data_packet_hash, (dest, time::now()));

        // Deliver the frame — this generates a proof which gets sent on wire
        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: data_packet.raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // The proof was generated and sent on the wire
        let sent_packets = sent.lock().unwrap();
        let proof_packets: Vec<_> = sent_packets
            .iter()
            .filter(|raw| {
                let flags = PacketFlags::unpack(raw[0] & 0x7F);
                flags.packet_type == constants::PACKET_TYPE_PROOF
            })
            .collect();
        assert!(!proof_packets.is_empty(), "Should have sent a proof packet");

        // Now feed the proof packet back to the driver so handle_inbound_proof fires.
        // We need a fresh driver run since the previous one shut down.
        // Instead, verify the data flow: the proof was sent on wire, and when
        // handle_inbound_proof processes a matching proof, completed_proofs gets populated.
        // Since our DATA packet was both delivered locally AND tracked in sent_packets,
        // the proof was generated on delivery. But the proof is for the *sender* to verify --
        // the proof gets sent back to the sender. So in this test (same driver = both sides),
        // the proof was sent on wire but not yet received back.
        //
        // Let's verify handle_inbound_proof directly by feeding the proof frame back.
        let proof_raw = proof_packets[0].clone();
        drop(sent_packets); // release lock

        // Create a new event loop to handle the proof frame
        let (tx2, rx2) = event::channel();
        let proofs2 = Arc::new(Mutex::new(Vec::new()));
        let cbs2 = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: proofs2.clone(),
            proof_requested: Arc::new(Mutex::new(Vec::new())),
        };
        let mut driver2 = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx2,
            tx2.clone(),
            Box::new(cbs2),
        );
        let info2 = make_interface_info(1);
        driver2.engine.register_interface(info2);
        let (writer2, _sent2) = MockWriter::new();
        driver2
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer2), true));

        // Track the original sent packet in driver2 so it recognizes the proof
        driver2
            .sent_packets
            .insert(data_packet_hash, (dest, time::now()));

        // Feed the proof frame
        tx2.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: proof_raw,
        })
        .unwrap();
        tx2.send(Event::Shutdown).unwrap();
        driver2.run();

        // The on_proof callback should have fired
        let proof_events = proofs2.lock().unwrap();
        assert_eq!(proof_events.len(), 1, "on_proof callback should fire once");
        assert_eq!(
            proof_events[0].1 .0, data_packet_hash,
            "proof should match original packet hash"
        );
        assert!(proof_events[0].2 >= 0.0, "RTT should be non-negative");

        // completed_proofs should contain the entry
        assert!(
            driver2.completed_proofs.contains_key(&data_packet_hash),
            "completed_proofs should contain the packet hash"
        );
        let (rtt, _received) = driver2.completed_proofs[&data_packet_hash];
        assert!(rtt >= 0.0, "RTT should be non-negative");
    }

    #[test]
    fn interface_stats_includes_probe_responder() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: true,
                identity_hash: Some([0x42; 16]),
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Set probe_responder_hash
        driver.probe_responder_hash = Some([0xEE; 16]);

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::InterfaceStats, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::InterfaceStats(stats) => {
                assert_eq!(stats.probe_responder, Some([0xEE; 16]));
            }
            other => panic!("expected InterfaceStats, got {:?}", other),
        }
    }

    #[test]
    fn interface_stats_probe_responder_none_when_disabled() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::InterfaceStats, resp_tx))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::InterfaceStats(stats) => {
                assert_eq!(stats.probe_responder, None);
            }
            other => panic!("expected InterfaceStats, got {:?}", other),
        }
    }

    #[test]
    fn test_extract_dest_hash_too_short() {
        // Packet too short to contain a full dest hash
        assert_eq!(super::extract_dest_hash(&[0x00, 0x00, 0xAA]), [0u8; 16]);
    }

    #[test]
    fn test_extract_dest_hash_header1() {
        // HEADER_1: bit 6 = 0, dest at bytes 2..18
        let mut raw = vec![0x00, 0x00]; // flags (header_type=0), hops
        let dest = [0x11; 16];
        raw.extend_from_slice(&dest);
        raw.extend_from_slice(&[0xFF; 10]); // trailing data
        assert_eq!(super::extract_dest_hash(&raw), dest);
    }

    #[test]
    fn test_extract_dest_hash_header2() {
        // HEADER_2: bit 6 = 1, transport_id at 2..18, dest at 18..34
        let mut raw = vec![0x40, 0x00]; // flags (header_type=1), hops
        raw.extend_from_slice(&[0xAA; 16]); // transport_id (bytes 2..18)
        let dest = [0x22; 16];
        raw.extend_from_slice(&dest); // dest (bytes 18..34)
        raw.extend_from_slice(&[0xFF; 10]); // trailing data
        assert_eq!(super::extract_dest_hash(&raw), dest);
    }

    #[test]
    fn test_extract_dest_hash_header2_too_short() {
        // HEADER_2 packet that's too short for the dest portion
        let mut raw = vec![0x40, 0x00];
        raw.extend_from_slice(&[0xAA; 16]); // transport_id only, no dest
        assert_eq!(super::extract_dest_hash(&raw), [0u8; 16]);
    }

    #[test]
    fn announce_stores_receiving_interface_in_known_destinations() {
        // When an announce arrives on interface 1, the AnnouncedIdentity
        // stored in known_destinations must have receiving_interface == InterfaceId(1).
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver
            .interfaces
            .insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);

        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // The identity should be cached with the correct receiving interface
        assert_eq!(driver.known_destinations.len(), 1);
        let (_, announced) = driver.known_destinations.iter().next().unwrap();
        assert_eq!(
            announced.announced.receiving_interface,
            InterfaceId(1),
            "receiving_interface should match the interface the announce arrived on"
        );
    }

    #[test]
    fn announce_on_different_interfaces_stores_correct_id() {
        // Announces arriving on interface 2 should store InterfaceId(2).
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        // Register two interfaces
        for id in [1, 2] {
            driver.engine.register_interface(make_interface_info(id));
            let (writer, _) = MockWriter::new();
            driver
                .interfaces
                .insert(InterfaceId(id), make_entry(id, Box::new(writer), true));
        }

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);

        // Send on interface 2
        tx.send(Event::Frame {
            interface_id: InterfaceId(2),
            data: announce_raw,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert_eq!(driver.known_destinations.len(), 1);
        let (_, announced) = driver.known_destinations.iter().next().unwrap();
        assert_eq!(announced.announced.receiving_interface, InterfaceId(2));
    }

    #[test]
    fn inject_identity_stores_sentinel_interface() {
        // InjectIdentity (used for persistence restore) should store InterfaceId(0)
        // because the identity wasn't received from a real interface.
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let identity = Identity::new(&mut OsRng);
        let dest_hash =
            rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::InjectIdentity {
                dest_hash,
                identity_hash: *identity.hash(),
                public_key: identity.get_public_key().unwrap(),
                app_data: Some(b"restored".to_vec()),
                hops: 2,
                received_at: 99.0,
            },
            resp_tx,
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::InjectIdentity(true) => {}
            other => panic!("expected InjectIdentity(true), got {:?}", other),
        }

        let announced = driver
            .known_destinations
            .get(&dest_hash)
            .expect("identity should be cached");
        assert_eq!(
            announced.announced.receiving_interface,
            InterfaceId(0),
            "injected identity should have sentinel InterfaceId(0)"
        );
        assert_eq!(announced.announced.dest_hash.0, dest_hash);
        assert_eq!(announced.announced.identity_hash.0, *identity.hash());
        assert_eq!(
            announced.announced.public_key,
            identity.get_public_key().unwrap()
        );
        assert_eq!(announced.announced.app_data, Some(b"restored".to_vec()));
        assert_eq!(announced.announced.hops, 2);
        assert_eq!(announced.announced.received_at, 99.0);
    }

    #[test]
    fn inject_identity_overwrites_previous_entry() {
        // A second InjectIdentity for the same dest_hash should overwrite the first.
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let identity = Identity::new(&mut OsRng);
        let dest_hash =
            rns_core::destination::destination_hash("test", &["app"], Some(identity.hash()));

        // First injection
        let (resp_tx1, resp_rx1) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::InjectIdentity {
                dest_hash,
                identity_hash: *identity.hash(),
                public_key: identity.get_public_key().unwrap(),
                app_data: Some(b"first".to_vec()),
                hops: 1,
                received_at: 10.0,
            },
            resp_tx1,
        ))
        .unwrap();

        // Second injection with different app_data
        let (resp_tx2, resp_rx2) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::InjectIdentity {
                dest_hash,
                identity_hash: *identity.hash(),
                public_key: identity.get_public_key().unwrap(),
                app_data: Some(b"second".to_vec()),
                hops: 3,
                received_at: 20.0,
            },
            resp_tx2,
        ))
        .unwrap();

        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert!(matches!(
            resp_rx1.recv().unwrap(),
            QueryResponse::InjectIdentity(true)
        ));
        assert!(matches!(
            resp_rx2.recv().unwrap(),
            QueryResponse::InjectIdentity(true)
        ));

        // Should have the second injection's data
        let announced = driver.known_destinations.get(&dest_hash).unwrap();
        assert_eq!(announced.announced.app_data, Some(b"second".to_vec()));
        assert_eq!(announced.announced.hops, 3);
        assert_eq!(announced.announced.received_at, 20.0);
    }

    #[test]
    fn re_announce_updates_receiving_interface() {
        // If we get two announces for the same dest from different interfaces,
        // the latest should win (known_destinations is a HashMap keyed by dest_hash).
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig {
                transport_enabled: false,
                identity_hash: None,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
                packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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
            },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        for id in [1, 2] {
            driver.engine.register_interface(make_interface_info(id));
            let (writer, _) = MockWriter::new();
            driver
                .interfaces
                .insert(InterfaceId(id), make_entry(id, Box::new(writer), true));
        }

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);

        // Same announce on interface 1, then interface 2
        tx.send(Event::Frame {
            interface_id: InterfaceId(1),
            data: announce_raw.clone(),
        })
        .unwrap();
        // The second announce of the same identity will be dropped by the transport
        // engine's deduplication (same random_hash). Build a second identity instead
        // to verify the field is correctly set per-announce.
        let identity2 = Identity::new(&mut OsRng);
        let announce_raw2 = build_announce_packet(&identity2);
        tx.send(Event::Frame {
            interface_id: InterfaceId(2),
            data: announce_raw2,
        })
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Both should be cached with their respective interface IDs
        assert_eq!(driver.known_destinations.len(), 2);
        for (_, announced) in &driver.known_destinations {
            // We can't predict ordering, but each should have a valid non-zero interface
            assert!(
                announced.announced.receiving_interface == InterfaceId(1)
                    || announced.announced.receiving_interface == InterfaceId(2)
            );
        }
        // Verify we actually got both interfaces represented
        let ifaces: Vec<_> = driver
            .known_destinations
            .values()
            .map(|a| a.announced.receiving_interface)
            .collect();
        assert!(ifaces.contains(&InterfaceId(1)));
        assert!(ifaces.contains(&InterfaceId(2)));
    }

    #[test]
    fn test_extract_dest_hash_other_flags_preserved() {
        // Ensure other flag bits don't affect header type detection
        // 0x3F = all bits set except bit 6 -> still HEADER_1
        let mut raw = vec![0x3F, 0x00];
        let dest = [0x33; 16];
        raw.extend_from_slice(&dest);
        raw.extend_from_slice(&[0xFF; 10]);
        assert_eq!(super::extract_dest_hash(&raw), dest);

        // 0xFF = all bits set including bit 6 -> HEADER_2
        let mut raw2 = vec![0xFF, 0x00];
        raw2.extend_from_slice(&[0xBB; 16]); // transport_id
        let dest2 = [0x44; 16];
        raw2.extend_from_slice(&dest2);
        raw2.extend_from_slice(&[0xFF; 10]);
        assert_eq!(super::extract_dest_hash(&raw2), dest2);
    }
