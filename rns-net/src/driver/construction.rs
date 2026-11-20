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
            registry: interface_registry::InterfaceRegistry::new(),
            rng: OsRng,
            rx,
            callbacks,
            started: time::now(),
            lifecycle: lifecycle::Lifecycle::new(),
            connected_to_shared_instance: false,
            destination_type_names: Default::default(),
            published_ingress_bursts: Default::default(),
            writers_to_wake: Vec::new(),
            announce_cache: None,
            builtin: builtin_destinations::BuiltinDestinations::new(
                tunnel_synth_dest,
                path_request_dest,
            ),
            transport_identity: None,
            link_manager: {
                let mut link_manager = LinkManager::new();
                link_manager.set_link_request_costs(tx.link_request_costs().clone());
                link_manager
            },
            management: management_state::ManagementState::new(&runtime_config_defaults),
            known: known_destinations::KnownDestinations::new(
                runtime_config_defaults.known_destinations_cleanup_interval_ticks,
            ),
            packet_signals: std::collections::VecDeque::new(),
            blackhole: blackhole::BlackholeState::new(),
            discovery: interface_discovery::InterfaceDiscovery::new(
                discovery_name_hash,
                runtime_config_defaults.discovery_cleanup_interval_ticks,
            ),
            network_identity: None,
            interface_settings: InterfaceSettings::new(),
            ratchet_store: None,
            ratchet_expiry_secs: rns_core::constants::RATCHET_EXPIRY as f64,
            rate_limiter_ttl_secs: DEFAULT_RATE_LIMITER_TTL_SECS,
            proofs: packet_proofs::PacketProofs::new(),
            decrypted_destinations: HashMap::new(),
            transport_actions: crate::action_pool::ActionPool::new(),
            link_actions: crate::action_pool::ActionPool::new(),
            local_destinations,
            path_responses: PathResponses::new(),
            holepunch_manager: {
                let mut manager =
                    HolePunchManager::new(vec![], rns_core::holepunch::ProbeProtocol::Rnsp, None);
                manager.set_event_sender(tx.clone());
                manager
            },
            stamps: stamps::Stamps::new(tx.clone()),
            hop_limiter: rns_core::constants::HOP_LIMITER,
            event_tx: tx,
            tick_interval_ms: Arc::new(AtomicU64::new(DEFAULT_TICK_INTERVAL_MS)),
            runtime_config: runtime_config::RuntimeConfigHandles::new(runtime_config_defaults),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: None,
            announce_verify: announce_verification::AnnounceVerification::new(
                announce_queue_max_entries,
            ),
            housekeeping: housekeeping::Housekeeping::new(&runtime_config_defaults),
            folded: FoldedTimers::new(),
            rpc_service: None,
            probe_server: None,
            resource_preparation: None,
            #[cfg(feature = "hooks")]
            hooks: Hooks::new(),
        }
    }
}
