//! Creating a driver.

use super::*;

impl Driver {
    /// Create a new driver.
    pub fn new(
        config: TransportConfig,
        rx: EventReceiver,
        tx: crate::event::EventSender,
        callbacks: Box<dyn Callbacks>,
    ) -> Self {
        let announce_queue_max_entries = config.announce_queue_max_entries;
        let tunnel_synth_dest = rns_core::destination::destination_hash(
            "rnstransport",
            &["tunnel", "synthesize"],
            None,
        );
        let path_request_dest =
            rns_core::destination::destination_hash("rnstransport", &["path", "request"], None);
        let discovery_name_hash = crate::discovery::discovery_name_hash();
        let mut engine = TransportEngine::new(config);
        engine.seed_table_hashing(&mut OsRng);
        engine.register_destination(tunnel_synth_dest, rns_core::constants::DESTINATION_PLAIN);
        // Register path request destination so inbound path requests are delivered locally
        engine.register_destination(path_request_dest, rns_core::constants::DESTINATION_PLAIN);
        // Note: discovery destination is NOT registered as local — it's a SINGLE destination
        // whose hash depends on the sender's identity. We match it by name_hash instead.
        let mut local_destinations = HashMap::new();
        local_destinations.insert(tunnel_synth_dest, rns_core::constants::DESTINATION_PLAIN);
        local_destinations.insert(path_request_dest, rns_core::constants::DESTINATION_PLAIN);
        let runtime_config_defaults = RuntimeConfigDefaults {
            tick_interval_ms: DEFAULT_TICK_INTERVAL_MS,
            known_destinations_ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
            rate_limiter_ttl_secs: DEFAULT_RATE_LIMITER_TTL_SECS,
            known_destinations_cleanup_interval_ticks:
                DEFAULT_KNOWN_DESTINATIONS_CLEANUP_INTERVAL_TICKS,
            announce_cache_cleanup_interval_ticks: DEFAULT_ANNOUNCE_CACHE_CLEANUP_INTERVAL_TICKS,
            announce_cache_cleanup_batch_size: DEFAULT_ANNOUNCE_CACHE_CLEANUP_BATCH_SIZE,
            discovery_cleanup_interval_ticks: DEFAULT_DISCOVERY_CLEANUP_INTERVAL_TICKS,
            management_announce_interval_secs: DEFAULT_MANAGEMENT_ANNOUNCE_INTERVAL_SECS,
            direct_connect_policy: crate::event::HolePunchPolicy::default(),
            stamp_destinations: rns_core::constants::STAMP_DESTINATIONS,
            stamp_path_requests: rns_core::constants::STAMP_PRS,
            stamps_enforced: rns_core::constants::STAMPS_ENFORCED,
            lr_stamps_enforced: rns_core::constants::LR_STAMPS_ENFORCED,
            stamp_link_requests: rns_core::constants::STAMP_LRS,
            always_stamp_link_requests: rns_core::constants::ALWAYS_STAMP_LRS,
            #[cfg(feature = "hooks")]
            provider_queue_max_events: crate::provider_bridge::ProviderBridgeConfig::default()
                .queue_max_events,
            #[cfg(feature = "hooks")]
            provider_queue_max_bytes: crate::provider_bridge::ProviderBridgeConfig::default()
                .queue_max_bytes,
        };
        Driver {
            tracked_link_send: None,
            pending_link_frames: std::collections::VecDeque::new(),
            engine,
            interfaces: Default::default(),
            dynamic_interface_parents: HashMap::new(),
            interface_display_names: HashMap::new(),
            interface_short_names: HashMap::new(),
            listener_stats: Vec::new(),
            interface_priority: Vec::new(),
            interface_priority_at: 0.0,
            traffic_samples: HashMap::new(),
            rng: OsRng,
            rx,
            callbacks,
            started: time::now(),
            lifecycle_state: LifecycleState::Active,
            accepting_work: Arc::new(AtomicBool::new(true)),
            connected_to_shared_instance: false,
            drain_started_at: None,
            drain_deadline: None,
            listener_controls: Vec::new(),
            interface_management: None,
            managed_interfaces: HashMap::new(),
            unmanaged_static_interfaces: HashMap::new(),
            retired_interface_parents: HashSet::new(),
            published_ingress_bursts: Default::default(),
            writers_to_wake: Vec::new(),
            announce_cache: None,
            tunnel_synth_dest,
            transport_identity: None,
            link_manager: {
                let mut link_manager = LinkManager::new();
                link_manager.set_link_request_costs(tx.link_request_costs().clone());
                link_manager
            },
            management_config: Default::default(),
            last_management_announce: 0.0,
            initial_announce_sent: false,
            known_destinations: HashMap::new(),
            known_destinations_flushed: HashMap::new(),
            packet_signals: std::collections::VecDeque::new(),
            blackhole_dir: None,
            blackhole_sources: Vec::new(),
            blackhole_updater: None,
            interface_discovery_sources: Vec::new(),
            network_identity: None,
            forced_local_bitrate: None,
            upstream_autoconnect: None,
            ratchet_store: None,
            ratchet_expiry_secs: rns_core::constants::RATCHET_EXPIRY as f64,
            known_destinations_ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES,
            rate_limiter_ttl_secs: DEFAULT_RATE_LIMITER_TTL_SECS,
            path_request_dest,
            proof_strategies: HashMap::new(),
            sent_packets: HashMap::new(),
            sent_packet_keys: HashMap::new(),
            packet_proofs: Vec::new(),
            decrypted_destinations: HashMap::new(),
            transport_actions: crate::action_pool::ActionPool::new(),
            link_actions: crate::action_pool::ActionPool::new(),
            completed_proofs: HashMap::new(),
            pending_probes: std::collections::HashSet::new(),
            proof_keys: HashMap::new(),
            local_destinations,
            builtin_link_destinations: HashSet::new(),
            builtin_links: HashSet::new(),
            shared_announces: HashMap::new(),
            path_responders: HashMap::new(),
            stamp_waiting_path_responses: HashMap::new(),
            shared_reconnect_pending: HashMap::new(),
            local_path_responses: HashMap::new(),
            holepunch_manager: {
                let mut manager =
                    HolePunchManager::new(vec![], rns_core::holepunch::ProbeProtocol::Rnsp, None);
                manager.set_event_sender(tx.clone());
                manager
            },
            stamper: Arc::new(crate::stamper::Stamper::new(tx.clone(), None)),
            stamp_destinations: Arc::new(AtomicBool::new(rns_core::constants::STAMP_DESTINATIONS)),
            stamp_settings: crate::config::StampsSection::default(),
            hop_limiter: rns_core::constants::HOP_LIMITER,
            event_tx: tx,
            interface_writer_queue_capacity: crate::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            underlay_mark: None,
            announce_rate_defaults: AnnounceRateDefaults::default(),
            interface_announce_limits: HashMap::new(),
            ingress_control_defaults: rns_core::transport::types::IngressControlConfig::enabled(),
            tick_interval_ms: Arc::new(AtomicU64::new(DEFAULT_TICK_INTERVAL_MS)),
            #[cfg(feature = "iface-backbone")]
            backbone_runtime: HashMap::new(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_state: HashMap::new(),
            #[cfg(feature = "iface-backbone")]
            backbone_client_runtime: HashMap::new(),
            #[cfg(feature = "iface-backbone")]
            backbone_discovery_runtime: HashMap::new(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: None,
            next_dynamic_interface_id: Arc::new(AtomicU64::new(10000)),
            #[cfg(feature = "iface-tcp")]
            tcp_server_runtime: HashMap::new(),
            #[cfg(feature = "iface-tcp")]
            tcp_client_runtime: HashMap::new(),
            #[cfg(feature = "iface-tcp")]
            tcp_server_discovery_runtime: HashMap::new(),
            #[cfg(feature = "iface-udp")]
            udp_runtime: HashMap::new(),
            #[cfg(feature = "iface-auto")]
            auto_runtime: HashMap::new(),
            #[cfg(feature = "iface-i2p")]
            i2p_runtime: HashMap::new(),
            #[cfg(feature = "iface-pipe")]
            pipe_runtime: HashMap::new(),
            #[cfg(feature = "iface-rnode")]
            rnode_runtime: HashMap::new(),
            interface_runtime_defaults: HashMap::new(),
            interface_ifac_runtime: HashMap::new(),
            interface_ifac_runtime_defaults: HashMap::new(),
            discovered_interfaces: crate::discovery::DiscoveredInterfaceStorage::new(
                std::env::temp_dir().join("rns-discovered-interfaces"),
            ),
            discovery_required_value: crate::discovery::DEFAULT_STAMP_VALUE,
            discovery_stamp_cache: crate::discovery::DiscoveryStampCache::default(),
            discovery_name_hash,
            probe_responder_hash: None,
            discover_interfaces: false,
            autoconnect_interface_mode: None,
            autoconnect_interface_gravity: 0,
            autoconnect_announces_to_internal: None,
            autoconnect_unverified_implementations: false,
            interface_announcer: None,
            announce_verify_queue: Arc::new(Mutex::new(AnnounceVerifyQueue::new(
                announce_queue_max_entries,
            ))),
            announce_verify_signal: Arc::default(),
            async_announce_verification: false,
            discovery_cleanup_counter: 0,
            discovery_cleanup_interval_ticks: runtime_config_defaults
                .discovery_cleanup_interval_ticks,
            memory_stats_counter: 0,
            state_snapshot_schedule: Default::default(),
            cache_cleanup_counter: 0,
            announce_cache_cleanup_counter: 0,
            known_destinations_cleanup_interval_ticks: runtime_config_defaults
                .known_destinations_cleanup_interval_ticks,
            known_destination_cleanup: None,
            ratchet_cleanup_handle: None,
            folded: FoldedTimers::new(),
            rpc_service: None,
            probe_server: None,
            resource_preparation: None,
            known_destinations_cap_evict_count: 0,
            announce_cache_cleanup_interval_ticks: runtime_config_defaults
                .announce_cache_cleanup_interval_ticks,
            announce_cache_cleanup_batch_size: runtime_config_defaults
                .announce_cache_cleanup_batch_size,
            management_announce_interval_secs: runtime_config_defaults
                .management_announce_interval_secs,
            runtime_config_defaults,
            #[cfg(feature = "hooks")]
            hook_slots: create_hook_slots(),
            #[cfg(feature = "hooks")]
            hook_manager: HookManager::new().ok(),
            #[cfg(feature = "hooks")]
            provider_bridge: None,
            #[cfg(feature = "hooks")]
            hook_rejected_modifications: [0; HookPoint::COUNT],
        }
    }
}
