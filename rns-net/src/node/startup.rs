//! Starting a node: reading its config and bringing up its driver,
//! interfaces and services.

#![allow(unsafe_code, reason = "OS calls through libc")]

use super::*;

pub(super) struct NodeQueueConfig {
    rpc_auth_key: Option<[u8; 32]>,
    announce_max_entries: usize,
    announce_max_interfaces: usize,
    announce_max_bytes: usize,
    announce_ttl_secs: f64,
    announce_overflow_policy: AnnounceQueueOverflowPolicy,
    inbound_capacities: crate::event::InboundQueueCapacities,
    link_mtu_discovery: bool,
    /// The `[filter]` config section.
    filter: config::FilterSection,
    /// `[filter] hop_limiter`.
    hop_limiter: u8,
}

impl Default for NodeQueueConfig {
    fn default() -> Self {
        Self {
            rpc_auth_key: None,
            announce_max_entries: 256,
            announce_max_interfaces: 1024,
            announce_max_bytes: 256 * 1024,
            announce_ttl_secs: 30.0,
            announce_overflow_policy: AnnounceQueueOverflowPolicy::DropWorst,
            inbound_capacities: crate::event::InboundQueueCapacities::default(),
            link_mtu_discovery: true,
            filter: config::FilterSection::default(),
            hop_limiter: rns_core::constants::HOP_LIMITER,
        }
    }
}

impl RnsNode {
    /// Start the node from a config file path.
    /// If `config_path` is None, uses `~/.reticulum/`.
    pub fn from_config(
        config_path: Option<&Path>,
        callbacks: Box<dyn Callbacks>,
    ) -> io::Result<Self> {
        let config_dir = storage::resolve_config_dir(config_path);
        Self::from_config_dirs(&config_dir, &config_dir, None, false, callbacks)
    }

    /// Start an application-private node from a dedicated configuration and
    /// state root.
    ///
    /// Private nodes never expose the shared-instance or management servers,
    /// never load hooks, fail on unsupported/malformed enabled interfaces, and
    /// force runtime interface failures to stop startup. `underlay_mark`
    /// overrides the value in the Reticulum configuration.
    pub fn from_private_config(
        config_dir: &Path,
        state_dir: &Path,
        underlay_mark: Option<u32>,
        callbacks: Box<dyn Callbacks>,
    ) -> io::Result<Self> {
        Self::from_config_dirs(config_dir, state_dir, underlay_mark, true, callbacks)
    }

    pub(super) fn from_config_dirs(
        config_dir: &Path,
        state_dir: &Path,
        underlay_mark: Option<u32>,
        private: bool,
        callbacks: Box<dyn Callbacks>,
    ) -> io::Result<Self> {
        let paths = storage::ensure_storage_dirs(state_dir)?;
        let known_destinations_path = paths.storage.join("known_destinations");

        // Parse config file, upstream's default one when there is none
        // (private nodes run on what they were given).
        if !private {
            storage::ensure_config_file(config_dir)?;
        }
        let config_file = config_dir.join("config");
        let config_content = if config_file.exists() {
            std::fs::read_to_string(&config_file)?
        } else {
            String::new()
        };
        let rns_config = config::parse(&config_content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?;
        let link_mtu_discovery = config::parse_link_mtu_discovery(&config_content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?;
        // Upstream `Reticulum.__start_local_interface`: when another process
        // already serves this shared instance, attach to it as a client
        // instead of starting a second instance on the same interfaces.
        #[cfg(feature = "iface-local")]
        if !private && rns_config.reticulum.share_instance {
            let shared =
                crate::shared_client::SharedClientConfig::from_reticulum(&rns_config.reticulum);
            if crate::interface::local::shared_instance_running(
                &shared.instance_name,
                shared.port,
                shared.use_af_unix,
            ) {
                log::info!(
                    "Shared instance {} is already running, connecting to it as a client",
                    shared.instance_name
                );
                return Self::connect_shared_from_config(Some(config_dir), callbacks);
            }
        }
        // Addresses Backbone listeners refuse, from <config dir>/blocked_ips
        // (upstream 5f2dbc16).
        #[cfg(feature = "iface-backbone")]
        crate::interface::backbone::load_blocked_ips_file(config_dir);

        // Upstream loads the configured network identity while it reads the
        // config, creating it when the file is missing. It is kept apart
        // from the transport identity.
        let network_identity = match rns_config.reticulum.network_identity {
            Some(ref path) => Some(load_network_identity(path)?),
            None => None,
        };
        // Upstream brings up the configured interfaces while it reads the
        // config; here they start with the node, from the configs built
        // below.
        log::info!("Bringing up system interfaces...");
        log::info!("System interfaces are ready");
        log::info!("Configuration loaded from {}", config_file.display());
        // Upstream loads the known destinations next, before Transport.start.
        let KnownDestinationsStorage {
            destinations: known_destinations,
            ratchet_store,
            database: known_destinations_store,
        } = open_known_destinations(
            &paths,
            &known_destinations_path,
            rns_config.reticulum.ratchet_expiry,
        );
        let identity = load_transport_identity(&paths)?;
        // Python clients derive their RPC key from the persisted transport
        // identity, even when their non-transport instance uses an
        // ephemeral one.
        let rpc_auth_key = if !private && rns_config.reticulum.share_instance {
            Some(crate::rpc::derive_auth_key(
                &identity
                    .get_private_key()
                    .expect("transport identity has private key"),
            ))
        } else {
            None
        };

        let (interface_configs, initial_ids) =
            build_interface_configs(&rns_config, &paths, private)?;

        let mgmt_allowed =
            parse_management_allowed(&rns_config.reticulum.remote_management_allowed);
        let probe_addrs = parse_probe_addrs(rns_config.reticulum.probe_addr.as_deref());
        let probe_protocol = parse_probe_protocol(rns_config.reticulum.probe_protocol.as_deref());
        clean_ratchets(
            ratchet_store.as_ref(),
            &known_destinations,
            rns_config.reticulum.ratchet_expiry,
        );

        let interface_management = if private || !rns_config.reticulum.enable_interface_management {
            None
        } else {
            Some(InterfaceManagementConfig {
                config_file: config_file.clone(),
                storage_dir: paths.storage.clone(),
                initial_ids,
                queue_capacity: rns_config.reticulum.interface_writer_queue_capacity,
                transport_enabled: rns_config.reticulum.enable_transport,
                underlay_mark: underlay_mark.or(rns_config.reticulum.underlay_mark),
            })
        };
        let (upstream_policy, bootstrap_interfaces) = autoconnect_policy(&rns_config);
        let node_config = NodeConfig {
            transport_enabled: rns_config.reticulum.enable_transport,
            static_transport_identity: rns_config.reticulum.static_transport_identity,
            local_hops_delta: rns_config.reticulum.local_hops_delta,
            identity: Some(identity),
            network_identity,
            share_instance: !private && rns_config.reticulum.share_instance,
            instance_name: rns_config.reticulum.instance_name.clone(),
            shared_instance_port: rns_config.reticulum.shared_instance_port,
            rpc_port: rns_config.reticulum.instance_control_port,
            cache_dir: Some(paths.cache),
            ratchet_store: Some(Arc::clone(&ratchet_store)),
            ratchet_expiry: Duration::from_secs(rns_config.reticulum.ratchet_expiry),
            management: if private {
                crate::management::ManagementConfig::default()
            } else {
                crate::management::ManagementConfig {
                    enable_remote_management: rns_config.reticulum.enable_remote_management,
                    remote_management_allowed: mgmt_allowed,
                    publish_blackhole: rns_config.reticulum.publish_blackhole,
                    blackhole_sources: rns_config.reticulum.blackhole_sources.clone(),
                    blackhole_update_interval: rns_config.reticulum.blackhole_update_interval,
                }
            },
            probe_port: rns_config.reticulum.probe_port,
            probe_addrs,
            probe_protocol,
            direct_connect_policy: rns_config.reticulum.direct_connect_policy,
            direct_connect_allow_private_endpoints: rns_config
                .reticulum
                .direct_connect_allow_private_endpoints,
            direct_connect_allowed_identities: rns_config
                .reticulum
                .direct_connect_allowed_identities
                .clone(),
            direct_connect_reupgrade: rns_config.reticulum.direct_connect_reupgrade,
            probe_rate_limit: rns_config.reticulum.probe_rate_limit,
            device: rns_config.reticulum.device.clone(),
            underlay_mark: underlay_mark.or(rns_config.reticulum.underlay_mark),
            hooks: if private {
                Vec::new()
            } else {
                rns_config.hooks.clone()
            },
            discover_interfaces: rns_config.reticulum.discover_interfaces,
            discovery: DiscoverySettings {
                interface_discovery_sources: rns_config
                    .reticulum
                    .interface_discovery_sources
                    .clone(),
                autoconnect_discovered_interfaces: if upstream_policy {
                    rns_config.reticulum.autoconnect_discovered_interfaces
                } else {
                    0
                },
                bootstrap_interfaces: if upstream_policy {
                    bootstrap_interfaces
                } else {
                    Vec::new()
                },
            },
            shared_instance: SharedInstanceSettings {
                use_af_unix: !rns_config.reticulum.shared_instance_tcp,
                rpc_key: rns_config.reticulum.rpc_key,
                force_bitrate: rns_config.reticulum.force_shared_instance_bitrate,
            },
            autoconnect_interface_mode: rns_config
                .reticulum
                .autoconnect_interface_mode
                .as_deref()
                .and_then(parse_optional_interface_mode),
            autoconnect_interface_gravity: rns_config.reticulum.autoconnect_interface_gravity,
            autoconnect_announces_to_internal: rns_config
                .reticulum
                .autoconnect_announces_to_internal,
            autoconnect_unverified_implementations: rns_config
                .reticulum
                .autoconnect_unverified_implementations,
            discovery_required_value: rns_config.reticulum.required_discovery_value,
            respond_to_probes: rns_config.reticulum.respond_to_probes,
            prefer_shorter_path: rns_config.reticulum.prefer_shorter_path,
            max_paths_per_destination: rns_config.reticulum.max_paths_per_destination,
            packet_hashlist_max_entries: rns_config.reticulum.packet_hashlist_max_entries,
            packet_hashlist_allocation: rns_config.reticulum.packet_hashlist_allocation,
            max_discovery_pr_tags: rns_config.reticulum.max_discovery_pr_tags,
            max_path_destinations: rns_config.reticulum.max_path_destinations,
            max_tunnel_destinations_total: rns_config.reticulum.max_tunnel_destinations_total,
            known_destinations_ttl: Duration::from_secs(
                rns_config.reticulum.known_destinations_ttl,
            ),
            known_destinations_max_entries: rns_config.reticulum.known_destinations_max_entries,
            announce_table_ttl: Duration::from_secs(rns_config.reticulum.announce_table_ttl),
            announce_table_max_bytes: rns_config.reticulum.announce_table_max_bytes,
            driver_event_queue_capacity: rns_config.reticulum.driver_event_queue_capacity,
            interface_writer_queue_capacity: rns_config.reticulum.interface_writer_queue_capacity,
            announce_rate_defaults: AnnounceRateDefaults {
                target: rns_config.reticulum.default_ar_target,
                penalty: rns_config.reticulum.default_ar_penalty,
                grace: rns_config.reticulum.default_ar_grace,
            },
            ingress_control_defaults: rns_core::transport::types::IngressControlConfig {
                enabled: true,
                egress_enabled: rns_config.reticulum.default_egress_control,
                max_held_announces: rns_config.reticulum.default_ic_max_held_announces,
                burst_freq_new: rns_config.reticulum.default_ic_burst_freq_new,
                burst_freq: rns_config.reticulum.default_ic_burst_freq,
                pr_burst_freq_new: rns_config.reticulum.default_ic_pr_burst_freq_new,
                pr_burst_freq: rns_config.reticulum.default_ic_pr_burst_freq,
                egress_pr_freq: rns_config.reticulum.default_ec_pr_freq,
                new_time: rns_config.reticulum.default_ic_new_time,
                burst_hold: rns_config.reticulum.default_ic_burst_hold,
                burst_penalty: rns_config.reticulum.default_ic_burst_penalty,
                held_release_interval: rns_config.reticulum.default_ic_held_release_interval,
            },
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: if !upstream_policy
                && rns_config.reticulum.backbone_peer_pool_max_connected > 0
            {
                Some(BackbonePeerPoolSettings {
                    max_connected: rns_config.reticulum.backbone_peer_pool_max_connected,
                    failure_threshold: rns_config.reticulum.backbone_peer_pool_failure_threshold,
                    failure_window: Duration::from_secs(
                        rns_config.reticulum.backbone_peer_pool_failure_window,
                    ),
                    cooldown: Duration::from_secs(rns_config.reticulum.backbone_peer_pool_cooldown),
                })
            } else {
                None
            },
            announce_sig_cache_enabled: rns_config.reticulum.announce_sig_cache_enabled,
            announce_sig_cache_max_entries: rns_config.reticulum.announce_sig_cache_max_entries,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_config.reticulum.announce_sig_cache_ttl,
            ),
            interfaces: interface_configs,
            registry: None,
            panic_on_interface_error: private || rns_config.reticulum.panic_on_interface_error,
            link_proof_verify_threads: Default::default(),
            stamps: rns_config.stamps.clone(),
            #[cfg(feature = "hooks")]
            provider_bridge: if !private && rns_config.reticulum.provider_bridge {
                Some(crate::provider_bridge::ProviderBridgeConfig {
                    enabled: true,
                    socket_path: rns_config
                        .reticulum
                        .provider_socket_path
                        .as_ref()
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|| config_dir.join("provider.sock")),
                    queue_max_events: rns_config.reticulum.provider_queue_max_events,
                    queue_max_bytes: rns_config.reticulum.provider_queue_max_bytes,
                    overflow_policy: match rns_config.reticulum.provider_overflow_policy.as_str() {
                        "drop_oldest" => crate::provider_bridge::OverflowPolicy::DropOldest,
                        _ => crate::provider_bridge::OverflowPolicy::DropNewest,
                    },
                    node_instance: rns_config.reticulum.instance_name.clone(),
                })
            } else {
                None
            },
        };

        let mut node = Self::start_with_queue_config(
            node_config,
            callbacks,
            NodeQueueConfig {
                rpc_auth_key,
                announce_max_entries: rns_config.reticulum.announce_queue_max_entries,
                announce_max_interfaces: rns_config.reticulum.announce_queue_max_interfaces,
                announce_max_bytes: rns_config.reticulum.announce_queue_max_bytes,
                announce_ttl_secs: rns_config.reticulum.announce_queue_ttl as f64,
                announce_overflow_policy: match rns_config
                    .reticulum
                    .announce_queue_overflow_policy
                    .as_str()
                {
                    "drop_newest" => AnnounceQueueOverflowPolicy::DropNewest,
                    "drop_oldest" => AnnounceQueueOverflowPolicy::DropOldest,
                    _ => AnnounceQueueOverflowPolicy::DropWorst,
                },
                inbound_capacities: rns_config.reticulum.inbound_queue_capacities,
                link_mtu_discovery,
                filter: rns_config.filter.clone(),
                hop_limiter: rns_config.reticulum.hop_limiter,
            },
            interface_management,
        )?;

        node.known_destinations_path = Some(known_destinations_path.clone());
        node.known_destinations_store = known_destinations_store;
        let flushed: std::collections::HashMap<[u8; 16], storage::KnownDestination> =
            known_destinations.clone().into_iter().collect();
        node.set_stamp_store(crate::stamps::DestinationStampStore::new(&paths.storage));
        node.restore_known_destinations(known_destinations);
        node.start_known_destinations_flush(flushed);

        Ok(node)
    }

    /// Start the node. Connects all interfaces, starts driver and timer threads.
    pub fn start(config: NodeConfig, callbacks: Box<dyn Callbacks>) -> io::Result<Self> {
        crate::interface::validate_underlay_mark(config.underlay_mark)?;
        let inbound_queue_capacities = crate::event::InboundQueueCapacities::from_shared_capacity(
            config.driver_event_queue_capacity,
        );
        Self::start_with_queue_config(
            config,
            callbacks,
            NodeQueueConfig {
                inbound_capacities: inbound_queue_capacities,
                ..NodeQueueConfig::default()
            },
            None,
        )
    }

    pub(super) fn start_with_queue_config(
        config: NodeConfig,
        callbacks: Box<dyn Callbacks>,
        queue_config: NodeQueueConfig,
        interface_management: Option<InterfaceManagementConfig>,
    ) -> io::Result<Self> {
        let storage_dir = config.cache_dir.as_ref().map(|cache_dir| {
            cache_dir
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("storage")
        });
        // The directories the node keeps state in, created before anything
        // starts; as upstream does, failing to create one fails startup.
        if let (Some(cache_dir), Some(storage_dir)) = (&config.cache_dir, &storage_dir) {
            for dir in [
                cache_dir.join("announces"),
                storage_dir.join("discovery").join("interfaces"),
                storage_dir.join("blackhole"),
            ] {
                std::fs::create_dir_all(&dir).map_err(|e| {
                    io::Error::new(e.kind(), format!("could not create {}: {e}", dir.display()))
                })?;
            }
        }
        let transport_state_dir = if config.transport_enabled {
            storage_dir.clone()
        } else {
            None
        };
        let identity = config.identity.unwrap_or_else(|| Identity::new(&mut OsRng));
        let rpc_auth_key = config
            .shared_instance
            .rpc_key
            .or(queue_config.rpc_auth_key)
            .unwrap_or_else(|| {
                crate::rpc::derive_auth_key(
                    &identity
                        .get_private_key()
                        .expect("node identity has private key"),
                )
            });
        let has_discoverable_interface = config
            .interfaces
            .iter()
            .any(|iface| iface.discovery.is_some());
        let static_transport_identity = effective_static_transport_identity(
            config.static_transport_identity,
            config.transport_enabled,
            has_discoverable_interface,
        );
        if static_transport_identity && !config.static_transport_identity {
            log::warn!(
                "Discoverable interface was configured, enabling static transport identity on non-transport instance"
            );
        }
        let transport_identity = if config.transport_enabled || static_transport_identity {
            Identity::from_private_key(
                &identity
                    .get_private_key()
                    .expect("node identity must expose a private key"),
            )
        } else {
            let identity = create_identity();
            log::info!(
                "Initialized ephemeral transport identity <{}>",
                hex_string(identity.hash())
            );
            identity
        };
        // `Transport.application_identity`, which names this application's
        // registrations with a shared instance.
        let application_identity = create_identity();

        let local_hops_delta = if config.local_hops_delta {
            let mut byte = [0u8; 1];
            OsRng.fill_bytes(&mut byte);
            byte[0] % 6 + 2
        } else {
            0
        };

        let transport_config = TransportConfig {
            transport_enabled: config.transport_enabled,
            identity_hash: Some(*transport_identity.hash()),
            local_hops_delta,
            prefer_shorter_path: config.prefer_shorter_path,
            max_paths_per_destination: config.max_paths_per_destination,
            packet_hashlist_max_entries: config.packet_hashlist_max_entries,
            packet_hashlist_allocation: config.packet_hashlist_allocation,
            max_discovery_pr_tags: config.max_discovery_pr_tags,
            max_path_destinations: config.max_path_destinations,
            max_tunnel_destinations_total: config.max_tunnel_destinations_total,
            destination_timeout_secs: config.known_destinations_ttl.as_secs_f64(),
            announce_table_ttl_secs: config.announce_table_ttl.as_secs_f64(),
            announce_table_max_bytes: config.announce_table_max_bytes,
            announce_sig_cache_enabled: config.announce_sig_cache_enabled,
            announce_sig_cache_max_entries: config.announce_sig_cache_max_entries,
            announce_sig_cache_ttl_secs: config.announce_sig_cache_ttl.as_secs_f64(),
            announce_queue_max_entries: queue_config.announce_max_entries,
            announce_queue_max_interfaces: queue_config.announce_max_interfaces,
        };

        let (tx, rx) = event::channel_with_queue_capacities(
            config.driver_event_queue_capacity,
            queue_config.inbound_capacities,
        );
        let tick_interval_ms = Arc::new(AtomicU64::new(1000));
        let mut driver = Driver::new(transport_config, rx, tx.clone(), callbacks);
        let stamper = Arc::new(crate::stamper::Stamper::new(tx.clone(), None));
        driver.set_stamper(Arc::clone(&stamper));
        let stamp_destinations = Arc::new(AtomicBool::new(rns_core::constants::STAMP_DESTINATIONS));
        driver.set_stamp_destinations_flag(Arc::clone(&stamp_destinations));
        driver.apply_stamp_config(&config.stamps, queue_config.hop_limiter);
        crate::stamps::set_worker_limits(config.stamps.max_workers, config.stamps.worker_niceness);
        *driver.engine.destination_filter_mut() = queue_config.filter.destination_filter();
        let stamp_targets = crate::stamper::StampTargets::from(&config.stamps);
        driver.underlay_mark = config.underlay_mark;
        driver
            .link_manager
            .set_link_mtu_discovery(queue_config.link_mtu_discovery);
        driver
            .link_manager
            .set_proof_verify_threads(config.link_proof_verify_threads);
        driver.set_announce_verify_queue_config(
            queue_config.announce_max_entries,
            queue_config.announce_max_bytes,
            queue_config.announce_ttl_secs,
            queue_config.announce_overflow_policy,
        );
        driver.async_announce_verification = true;
        driver.set_tick_interval_handle(Arc::clone(&tick_interval_ms));
        let accepting_work = driver.accepting_work_handle();
        driver.known_destinations_ttl = config.known_destinations_ttl.as_secs_f64();
        driver.known_destinations_max_entries = config.known_destinations_max_entries;
        driver.ratchet_store = config.ratchet_store.clone();
        driver.ratchet_expiry_secs = config.ratchet_expiry.as_secs_f64();
        driver.interface_writer_queue_capacity = config.interface_writer_queue_capacity;
        driver.set_announce_rate_defaults(config.announce_rate_defaults);
        driver.set_ingress_control_defaults(config.ingress_control_defaults);
        driver.runtime_config_defaults.known_destinations_ttl =
            config.known_destinations_ttl.as_secs_f64();
        driver
            .holepunch_manager
            .set_policy(config.direct_connect_policy);
        driver
            .holepunch_manager
            .set_allow_private_endpoints(config.direct_connect_allow_private_endpoints);
        driver
            .holepunch_manager
            .set_allowed_identities(config.direct_connect_allowed_identities.clone());
        driver
            .holepunch_manager
            .set_reupgrade_config(config.direct_connect_reupgrade);
        driver.runtime_config_defaults.direct_connect_policy = config.direct_connect_policy;
        #[cfg(feature = "hooks")]
        if let Some(provider_config) = config.provider_bridge.clone() {
            driver.runtime_config_defaults.provider_queue_max_events =
                provider_config.queue_max_events;
            driver.runtime_config_defaults.provider_queue_max_bytes =
                provider_config.queue_max_bytes;
            if provider_config.enabled {
                let started = if crate::engine::FOLD_SERVICES {
                    crate::provider_bridge::ProviderBridge::start_folded(
                        provider_config,
                        Arc::clone(tx.poller()),
                    )
                } else {
                    crate::provider_bridge::ProviderBridge::start(provider_config)
                };
                match started {
                    Ok(bridge) => driver.provider_bridge = Some(bridge),
                    Err(err) => log::warn!("failed to start provider bridge: {}", err),
                }
            }
        }

        // Set up announce cache if cache directory is configured
        if let Some(ref cache_dir) = config.cache_dir {
            let announces_dir = cache_dir.join("announces");
            driver.announce_cache = Some(crate::announce_cache::AnnounceCache::new(announces_dir));
        }

        // Configure probe addresses and device for hole punching
        if !config.probe_addrs.is_empty()
            || config.device.is_some()
            || config.underlay_mark.is_some()
        {
            driver.set_probe_config(
                config.probe_addrs.clone(),
                config.probe_protocol,
                config.device.clone(),
            );
        }

        // Start probe server if configured. A peer never gets this node
        // to punch toward it.
        if let Some(port) = config.probe_port {
            driver.holepunch_manager.set_own_listen_ports(vec![port]);
        }
        let probe_server = if let Some(port) = config.probe_port {
            // Dual stack where the host has IPv6, else IPv4 alone.
            let mut started = None;
            let mut last_error = None;
            for listen_addr in crate::holepunch::probe::probe_server_listen_addrs(port) {
                let result = if crate::engine::FOLD_SERVICES {
                    crate::holepunch::probe::FoldedProbeServer::bind(
                        listen_addr,
                        config.underlay_mark,
                        config.probe_rate_limit,
                        Arc::clone(tx.poller()),
                    )
                    .map(|server| {
                        driver
                            .holepunch_manager
                            .set_probe_server_counters(server.counters());
                        driver.probe_server = Some(server);
                        None
                    })
                } else {
                    crate::holepunch::probe::start_probe_server_with_mark(
                        listen_addr,
                        config.underlay_mark,
                        config.probe_rate_limit,
                    )
                    .map(|server| {
                        driver
                            .holepunch_manager
                            .set_probe_server_counters(server.counters());
                        Some(server)
                    })
                };
                match result {
                    Ok(handle) => {
                        log::info!("Probe server started on {}", listen_addr);
                        started = Some(handle);
                        break;
                    }
                    Err(e) => last_error = Some(e),
                }
            }
            if started.is_none() {
                if let Some(e) = last_error {
                    log::error!("Failed to start probe server on port {}: {}", port, e);
                }
            }
            started.flatten()
        } else {
            None
        };

        // Store management config on driver for ACL enforcement
        driver.management_config = config.management.clone();

        // Store transport identity for tunnel synthesis and management announces.
        driver.transport_identity = Some(transport_identity);

        #[cfg(feature = "hooks")]
        load_configured_hooks(&mut driver, &config.hooks);

        // Configure discovery
        driver.discover_interfaces = config.discover_interfaces;
        let discover_interfaces = config.discover_interfaces;
        driver.interface_discovery_sources = config.discovery.interface_discovery_sources.clone();
        driver.forced_local_bitrate = config.shared_instance.force_bitrate;
        driver.network_identity = config.network_identity;
        driver.register_network_destinations();
        driver.autoconnect_interface_mode = config.autoconnect_interface_mode;
        driver.autoconnect_interface_gravity = config.autoconnect_interface_gravity;
        driver.autoconnect_announces_to_internal =
            config.autoconnect_announces_to_internal.then_some(true);
        driver.autoconnect_unverified_implementations =
            config.autoconnect_unverified_implementations;
        if let Some(val) = config.discovery_required_value {
            driver.discovery_required_value = val;
        }

        // Shared counter for dynamic interface IDs
        let next_dynamic_id = Arc::new(AtomicU64::new(10000));
        driver.next_dynamic_interface_id = Arc::clone(&next_dynamic_id);

        // Collect discoverable interface configs for the announcer
        let mut discoverable_interfaces = Vec::new();
        #[cfg(feature = "iface-backbone")]
        let mut backbone_peer_pool_candidates = Vec::new();
        let mut configured_client_targets: Vec<(String, u16)> = Vec::new();

        let initial_managed_ids = interface_management
            .as_ref()
            .map(|management| management.initial_ids.clone())
            .unwrap_or_default();
        driver.interface_management = interface_management;

        // --- Registry-based startup for interfaces ---
        let registry = config
            .registry
            .unwrap_or_else(crate::interface::registry::InterfaceRegistry::with_builtins);
        for iface_config in config.interfaces {
            driver.set_interface_announce_limits(&iface_config.name, iface_config.announce_limits);
            let managed_id = initial_managed_ids.get(&iface_config.name).copied();
            #[cfg(feature = "iface-backbone")]
            if iface_config.type_name == "BackboneInterface" {
                if let Some(mode) = iface_config
                    .config_data
                    .as_any()
                    .downcast_ref::<BackboneMode>()
                {
                    if let Some(handle) = runtime_handle_from_mode(mode) {
                        driver.register_backbone_runtime(handle);
                    }
                    if let Some(handle) = peer_state_handle_from_mode(mode) {
                        driver.register_backbone_peer_state(handle);
                    }
                    if let Some(handle) = client_runtime_handle_from_mode(mode) {
                        driver.register_backbone_client_runtime(handle);
                    }
                    if let Some(handle) = backbone_discovery_runtime_from_interface(
                        &iface_config.name,
                        mode,
                        iface_config.discovery.as_ref(),
                        config.transport_enabled,
                        iface_config.ifac.as_ref(),
                    ) {
                        driver.register_backbone_discovery_runtime(handle);
                    }
                }
            }
            #[cfg(feature = "iface-tcp")]
            if iface_config.type_name == "TCPClientInterface" {
                if let Some(tcp_config) = iface_config
                    .config_data
                    .as_any()
                    .downcast_ref::<TcpClientConfig>()
                {
                    driver.register_tcp_client_runtime(tcp_client_runtime_handle_from_config(
                        tcp_config,
                    ));
                }
            }
            #[cfg(feature = "iface-tcp")]
            if iface_config.type_name == "TCPServerInterface" {
                if let Some(tcp_config) = iface_config
                    .config_data
                    .as_any()
                    .downcast_ref::<TcpServerConfig>()
                {
                    driver.register_tcp_server_runtime(tcp_runtime_handle_from_config(tcp_config));
                    driver.register_tcp_server_discovery_runtime(
                        tcp_server_discovery_runtime_from_interface(
                            &iface_config.name,
                            tcp_config,
                            iface_config.discovery.as_ref(),
                            config.transport_enabled,
                            iface_config.ifac.as_ref(),
                        ),
                    );
                }
            }
            #[cfg(feature = "iface-udp")]
            if iface_config.type_name == "UDPInterface" {
                if let Some(udp_config) = iface_config
                    .config_data
                    .as_any()
                    .downcast_ref::<UdpConfig>()
                {
                    driver.register_udp_runtime(udp_runtime_handle_from_config(udp_config));
                }
            }
            #[cfg(feature = "iface-auto")]
            if iface_config.type_name == "AutoInterface" {
                if let Some(auto_config) = iface_config
                    .config_data
                    .as_any()
                    .downcast_ref::<AutoConfig>()
                {
                    driver.register_auto_runtime(auto_runtime_handle_from_config(auto_config));
                }
            }
            #[cfg(feature = "iface-i2p")]
            if iface_config.type_name == "I2PInterface" {
                if let Some(i2p_config) = iface_config
                    .config_data
                    .as_any()
                    .downcast_ref::<I2pConfig>()
                {
                    driver.register_i2p_runtime(i2p_runtime_handle_from_config(i2p_config));
                }
            }
            #[cfg(feature = "iface-pipe")]
            if iface_config.type_name == "PipeInterface" {
                if let Some(pipe_config) = iface_config
                    .config_data
                    .as_any()
                    .downcast_ref::<PipeConfig>()
                {
                    driver.register_pipe_runtime(pipe_runtime_handle_from_config(pipe_config));
                }
            }
            #[cfg(feature = "iface-rnode")]
            if iface_config.type_name == "RNodeInterface" {
                if let Some(rnode_config) = iface_config
                    .config_data
                    .as_any()
                    .downcast_ref::<RNodeConfig>()
                {
                    driver.register_rnode_runtime(rnode_runtime_handle_from_config(rnode_config));
                }
            }
            // An auto-connect must not duplicate a configured client.
            #[cfg(feature = "iface-tcp")]
            if let Some(tcp) = iface_config
                .config_data
                .as_any()
                .downcast_ref::<crate::interface::tcp::TcpClientConfig>()
            {
                configured_client_targets.push((tcp.target_host.clone(), tcp.target_port));
            }
            #[cfg(feature = "iface-backbone")]
            if let Some(BackboneMode::Client(client, _)) = iface_config
                .config_data
                .as_any()
                .downcast_ref::<BackboneMode>()
            {
                configured_client_targets.push((client.target_host.clone(), client.target_port));
            }

            let factory = match registry.get(&iface_config.type_name) {
                Some(f) => f,
                None => {
                    log::warn!(
                        "No factory registered for interface type '{}'",
                        iface_config.type_name
                    );
                    continue;
                }
            };

            let mut ifac_state = derive_ifac_state(iface_config.ifac.as_ref(), &iface_config.name)?;
            let ifac_runtime =
                ifac_runtime_from_config(iface_config.ifac.as_ref(), factory.default_ifac_size());

            #[cfg(feature = "iface-backbone")]
            if config.backbone_peer_pool.is_some() && iface_config.type_name == "BackboneInterface"
            {
                if let Some(mode) = iface_config
                    .config_data
                    .as_any()
                    .downcast_ref::<BackboneMode>()
                {
                    if let Some(client) = client_config_from_mode(mode) {
                        let priority = client_priority_from_mode(mode).unwrap_or(
                            crate::driver::BACKBONE_PEER_POOL_CONFIGURED_DEFAULT_PRIORITY,
                        );
                        backbone_peer_pool_candidates.push(BackbonePeerPoolCandidateConfig {
                            client,
                            mode: iface_config.mode,
                            gravity: iface_config.gravity,
                            recursive_prs: iface_config.recursive_prs,
                            announces_from_internal: iface_config.announces_from_internal,
                            announces_to_internal: iface_config.announces_to_internal,
                            ingress_control: iface_config.ingress_control,
                            stamp_costs: iface_config.stamp_costs,
                            ifac_runtime: ifac_runtime.clone(),
                            ifac_enabled: ifac_state.is_some(),
                            // Upstream starts a BackboneClientInterface for
                            // a Backbone interface with a target host.
                            interface_type_name: "BackboneClientInterface".to_string(),
                            source: crate::driver::BackbonePeerPoolCandidateSource::Configured,
                            priority,
                            discovery: None,
                        });
                        if let Some(ref disc) = iface_config.discovery {
                            discoverable_interfaces.push(discoverable_interface_from_config(
                                &iface_config.name,
                                disc,
                                config.transport_enabled,
                                iface_config.ifac.as_ref(),
                            ));
                        }
                        continue;
                    }
                }
            }

            let ctx = crate::interface::StartContext {
                tx: tx.clone(),
                next_dynamic_id: next_dynamic_id.clone(),
                mode: iface_config.mode,
                gravity: iface_config.gravity,
                hop_limiter: iface_config.hop_limiter,
                recursive_prs: iface_config.recursive_prs,
                announces_from_internal: iface_config.announces_from_internal,
                announces_to_internal: iface_config.announces_to_internal,
                ingress_control: iface_config.ingress_control,
                stamp_costs: iface_config.stamp_costs,
                announce_limits: iface_config.announce_limits,
                ifac: ifac_state.clone(),
                underlay_mark: config.underlay_mark,
            };

            let mut display = ConfiguredDisplay::of(&iface_config, ifac_state.as_ref());
            let result = match factory.start(iface_config.config_data, ctx) {
                Ok(r) => r,
                Err(e) => {
                    if config.panic_on_interface_error {
                        return Err(e);
                    }
                    log::error!(
                        "Interface '{}' ({}) failed to start: {}",
                        iface_config.name,
                        iface_config.type_name,
                        e
                    );
                    continue;
                }
            };

            if let Some(ref disc) = iface_config.discovery {
                discoverable_interfaces.push(discoverable_interface_from_config(
                    &iface_config.name,
                    disc,
                    config.transport_enabled,
                    iface_config.ifac.as_ref(),
                ));
            }

            match result {
                crate::interface::StartResult::Simple {
                    id,
                    info,
                    writer,
                    interface_type_name,
                    control,
                } => {
                    let managed_control = control.clone();
                    if let Some(control) = control {
                        driver.register_listener_control(control);
                    }
                    if let Some(parent_id) = managed_id {
                        driver.managed_interfaces.insert(
                            iface_config.name.clone(),
                            crate::driver::ManagedInterface {
                                parent_id,
                                type_name: iface_config.type_name.clone(),
                                control: managed_control,
                                static_ids: vec![id],
                            },
                        );
                    } else {
                        driver
                            .unmanaged_static_interfaces
                            .insert(id, managed_control);
                    }
                    register_started_interface(StartedInterface {
                        driver: &mut driver,
                        tx: &tx,
                        queue_capacity: config.interface_writer_queue_capacity,
                        id,
                        info,
                        writer,
                        interface_type_name,
                        ifac_state,
                        ifac_runtime: &ifac_runtime,
                        stamp_costs: iface_config.stamp_costs,
                        hop_limiter: iface_config.hop_limiter,
                        display_name: display.interface.take(),
                    });
                }
                crate::interface::StartResult::Listener { control } => {
                    // Listener-type interface (TcpServer, Auto, I2P, etc.)
                    // registers dynamic interfaces via InterfaceUp events.
                    display.register_listener(&mut driver);
                    let managed_control = control.clone();
                    if let Some(control) = control {
                        driver.register_listener_control(control);
                    }
                    if let Some(parent_id) = managed_id {
                        driver.managed_interfaces.insert(
                            iface_config.name.clone(),
                            crate::driver::ManagedInterface {
                                parent_id,
                                type_name: iface_config.type_name.clone(),
                                control: managed_control,
                                static_ids: Vec::new(),
                            },
                        );
                    }
                }
                crate::interface::StartResult::Multi {
                    subinterfaces: subs,
                    control,
                } => {
                    let managed_control = control.clone();
                    if let Some(control) = control {
                        driver.register_listener_control(control);
                    }
                    let static_ids: Vec<_> = subs.iter().map(|sub| sub.id).collect();
                    display.register_subinterfaces(&mut driver, static_ids.clone());
                    if let Some(parent_id) = managed_id {
                        driver.managed_interfaces.insert(
                            iface_config.name.clone(),
                            crate::driver::ManagedInterface {
                                parent_id,
                                type_name: iface_config.type_name.clone(),
                                control: managed_control,
                                static_ids,
                            },
                        );
                    }
                    let ifac_cfg = &iface_config.ifac;
                    let mut first = true;
                    for sub in subs {
                        let sub_ifac = if first {
                            first = false;
                            ifac_state.take()
                        } else {
                            derive_ifac_state(ifac_cfg.as_ref(), &sub.info.name)?
                        };
                        let display_name = subinterface_display_name(&iface_config.name, &sub);
                        register_started_interface(StartedInterface {
                            driver: &mut driver,
                            tx: &tx,
                            queue_capacity: config.interface_writer_queue_capacity,
                            id: sub.id,
                            info: sub.info,
                            writer: sub.writer,
                            interface_type_name: sub.interface_type_name,
                            ifac_state: sub_ifac,
                            ifac_runtime: &ifac_runtime,
                            stamp_costs: iface_config.stamp_costs,
                            hop_limiter: iface_config.hop_limiter,
                            display_name,
                        });
                    }
                }
            }
        }

        // Set up interface announcer if we have discoverable interfaces
        if !discoverable_interfaces.is_empty() {
            let transport_id = *identity.hash();
            let announcer = driver.new_interface_announcer(transport_id, discoverable_interfaces);
            log::info!("Interface discovery announcer initialized");
            driver.interface_announcer = Some(announcer);
        }

        // Set up discovered interfaces storage path
        if let Some(ref cache_dir) = config.cache_dir {
            let disc_path = std::path::PathBuf::from(cache_dir)
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .join("storage")
                .join("discovery")
                .join("interfaces");
            driver.discovered_interfaces =
                crate::discovery::DiscoveredInterfaceStorage::new(disc_path);
            // Upstream's `storage/blackhole`, beside the discovery storage.
            let blackhole_path = std::path::PathBuf::from(cache_dir)
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .join("storage")
                .join("blackhole");
            driver.blackhole_sources = config.management.blackhole_sources.clone();
            driver.load_blackhole(blackhole_path);
            driver.enable_blackhole_updater(config.management.blackhole_update_interval);
        }

        // Restore after static interfaces and the announce cache are available,
        // but before the driver can process inbound traffic. Upstream logs
        // the tables it loaded after its management destinations' notices,
        // so the lines follow those below.
        let mut restored_tables = None;
        if let Some(ref storage_dir) = transport_state_dir {
            match storage::load_transport_state(storage_dir) {
                Ok(snapshot) => {
                    let announce_cache = driver.announce_cache.as_ref();
                    let stats = driver.engine.restore_persistence_snapshot(
                        snapshot,
                        time::now(),
                        |packet_hash| {
                            announce_cache
                                .and_then(|cache| cache.get(packet_hash).ok().flatten())
                                .map(|(raw, _)| raw)
                        },
                    );
                    restored_tables = Some(stats);
                    log::debug!(
                        "restored transport state: {} packet hashes, {} paths, {} tunnels, {} announce rates ({} paths skipped, {} filtered, {} blackholed)",
                        stats.packet_hashes,
                        stats.paths,
                        stats.tunnels,
                        stats.announce_rates,
                        stats.skipped_paths,
                        stats.filtered_paths,
                        stats.blackholed_paths,
                    );
                }
                Err(err) => log::warn!("failed to restore transport state: {}", err),
            }
        }

        #[cfg(feature = "iface-backbone")]
        if let Some(settings) = config.backbone_peer_pool.clone() {
            driver.configure_backbone_peer_pool(settings, backbone_peer_pool_candidates);
            driver.seed_backbone_peer_pool_from_discovery_cache();
        }
        // Upstream's auto-connecting of discovered interfaces.
        if config.discover_interfaces && config.discovery.autoconnect_discovered_interfaces > 0 {
            driver.enable_upstream_autoconnect(
                config.discovery.autoconnect_discovered_interfaces,
                config.discovery.bootstrap_interfaces.clone(),
                configured_client_targets,
            );
            driver.autoconnect_stored_discoveries();
        } else if !config.discovery.bootstrap_interfaces.is_empty() {
            log::warn!(
                "bootstrap_only interfaces stay up: they are only torn down while autoconnect_discovered_interfaces are connected"
            );
        }

        // The management destinations belong to the transport identity,
        // `Transport.identity`: on an instance without transport and
        // without static_transport_identity, the ephemeral one.
        let transport_id = Identity::from_private_key(
            &driver
                .transport_identity
                .as_ref()
                .and_then(|identity| identity.get_private_key())
                .expect("the node has a transport identity"),
        );
        if config.management.enable_remote_management {
            enable_remote_management(&mut driver, &transport_id, &config.management);
        }
        if config.management.publish_blackhole {
            enable_blackhole_publishing(&mut driver, &transport_id);
        }
        if let (Some(stats), Some(storage_dir)) = (restored_tables, transport_state_dir.as_ref()) {
            log_restored_tables(&stats, storage_dir);
        }
        if config.respond_to_probes && config.transport_enabled {
            enable_probe_responder(&mut driver, &transport_id);
        }
        if config.transport_enabled {
            log::info!(
                "Transport instance <{}> started",
                hex_string(transport_id.hash())
            );
        }

        // Spawn timer thread with configurable tick interval, unless the
        // driver keeps the tick itself (compact engine).
        if !crate::engine::FOLD_TIMERS {
            let timer_tx = tx.clone();
            let timer_interval = Arc::clone(&tick_interval_ms);
            thread::Builder::new()
                .name("rns-timer".into())
                .spawn(move || loop {
                    let ms = timer_interval.load(Ordering::Relaxed);
                    thread::sleep(Duration::from_millis(ms));
                    if timer_tx.send(Event::Tick).is_err() {
                        break; // receiver dropped
                    }
                })?;
        }

        // Start LocalServer for shared instance clients if share_instance is enabled
        #[cfg(feature = "iface-local")]
        if config.share_instance {
            let local_server_config = LocalServerConfig {
                instance_name: config.instance_name.clone(),
                port: config.shared_instance_port,
                // Keys the listener on the driver loop when interface I/O is
                // folded; clients get ids of their own.
                interface_id: rns_core::transport::types::InterfaceId(
                    next_dynamic_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                ),
                use_af_unix: config.shared_instance.use_af_unix,
            };
            let listener_id = local_server_config.interface_id;
            match crate::interface::local::start_shared_instance_server(
                local_server_config,
                tx.clone(),
                next_dynamic_id.clone(),
            ) {
                Ok((control, endpoint)) => {
                    driver.register_listener_control(control);
                    driver.register_shared_instance_listener(listener_id, endpoint);
                    log::debug!(
                        "Local shared instance server started (instance={}, port={})",
                        config.instance_name,
                        config.shared_instance_port
                    );
                }
                Err(e) => {
                    log::error!("Failed to start local shared instance server: {}", e);
                }
            }
        }

        // Start the RPC servers if share_instance is enabled: on threads, or
        // on the driver loop when the compact engine folds services.
        //
        // As upstream, the RPC server listens on the abstract Unix socket
        // where the shared instance uses one, and on TCP only otherwise
        // (`shared_instance_type = tcp`, other platforms, or when the socket
        // cannot be bound): two instances on the default control port then
        // do not collide.
        let serve_rpc_threads = config.share_instance && !crate::engine::FOLD_SERVICES;
        let rpc_on_unix = |bound: io::Result<()>| -> bool {
            match bound {
                Ok(()) => {
                    log::debug!(
                        "RPC server started on abstract Unix socket for {}",
                        config.instance_name
                    );
                    true
                }
                Err(e) => {
                    log::warn!("Abstract Unix RPC socket unavailable ({e}), serving RPC over TCP");
                    false
                }
            }
        };
        if config.share_instance && crate::engine::FOLD_SERVICES {
            let mut service = crate::driver::RpcService::new(rpc_auth_key, Arc::clone(tx.poller()));
            #[cfg(target_os = "linux")]
            let on_unix = config.shared_instance.use_af_unix
                && rpc_on_unix(
                    crate::rpc::bind_abstract_unix(&config.instance_name).and_then(|listener| {
                        service.add_listener(crate::driver::RpcListener::Unix(listener))
                    }),
                );
            #[cfg(not(target_os = "linux"))]
            let on_unix = false;
            if !on_unix {
                match std::net::TcpListener::bind(("127.0.0.1", config.rpc_port)).and_then(
                    |listener| service.add_listener(crate::driver::RpcListener::Tcp(listener)),
                ) {
                    Ok(()) => log::debug!("RPC server started on 127.0.0.1:{}", config.rpc_port),
                    Err(e) => log::error!("Failed to start RPC server: {}", e),
                }
            }
            driver.rpc_service = Some(service);
        }
        #[cfg(target_os = "linux")]
        let rpc_unix_server = if serve_rpc_threads && config.shared_instance.use_af_unix {
            let started = crate::rpc::RpcServer::start_abstract_unix(
                &config.instance_name,
                rpc_auth_key,
                tx.clone(),
            );
            match started {
                Ok(server) => rpc_on_unix(Ok(())).then_some(server),
                Err(e) => {
                    rpc_on_unix(Err(e));
                    None
                }
            }
        } else {
            None
        };
        #[cfg(target_os = "linux")]
        let on_unix = rpc_unix_server.is_some();
        #[cfg(not(target_os = "linux"))]
        let on_unix = {
            let _ = rpc_on_unix;
            false
        };
        let rpc_server = if serve_rpc_threads && !on_unix {
            let rpc_addr = crate::rpc::RpcAddr::Tcp("127.0.0.1".into(), config.rpc_port);
            match crate::rpc::RpcServer::start(&rpc_addr, rpc_auth_key, tx.clone()) {
                Ok(server) => {
                    log::debug!("RPC server started on 127.0.0.1:{}", config.rpc_port);
                    Some(server)
                }
                Err(e) => {
                    log::error!("Failed to start RPC server: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let verify_shutdown = Arc::clone(&driver.announce_verify_signal);
        let verify_handle =
            spawn_announce_verifier(&driver.announce_verify_queue, &verify_shutdown, tx.clone())?;

        // Spawn the driver after startup has registered local destinations and static interfaces.
        // Interface readers can enqueue frames before this point; the bounded event queue preserves
        // ordering and backpressures instead of dropping startup traffic.
        log::debug!("rns-net {} engine", crate::engine::ENGINE);
        // The compact engine persists transport state on the driver loop.
        if crate::engine::FOLD_TIMERS {
            driver.folded.persist_dir = transport_state_dir.clone();
        }
        let driver_handle = thread::Builder::new()
            .name("rns-driver".into())
            .spawn(move || {
                driver.run();
            })?;

        let (persist_handle, persist_stop) =
            spawn_transport_state_persister(transport_state_dir.clone(), tx.clone())?.unzip();

        let mut node = RnsNode {
            tx,
            driver_handle: Some(driver_handle),
            verify_handle,
            verify_shutdown,
            persist_handle,
            persist_stop,
            kd_flush_handle: None,
            kd_flush_stop: None,
            rpc_server,
            #[cfg(target_os = "linux")]
            rpc_unix_server,
            tick_interval_ms,
            next_send_ticket: AtomicU64::new(0),
            encrypt_deferred_inline: std::thread::available_parallelism()
                .map_or(true, |cpus| cpus.get() == 1),
            accepting_work,
            probe_server,
            known_destinations_path: None,
            known_destinations_store: None,
            stamp_store: None,
            stamp_destinations,
            stamp_targets,
            stamper: Some(stamper),
            transport_state_dir,
            ratchet_store: config.ratchet_store,
            ratchet_expiry: config.ratchet_expiry,
            #[cfg(feature = "iface-local")]
            destination_types: crate::shared_client::DestinationTypeRequester::new(
                *application_identity.hash(),
            ),
        };
        #[cfg(not(feature = "iface-local"))]
        let _ = application_identity;
        // Destination stamps live under `storage/stamps` next to the cache
        // directory, the layout `from_config_dirs` uses; a node without a
        // cache directory cannot stamp its announces.
        if let Some(storage_dir) = storage_dir {
            node.set_stamp_store(crate::stamps::DestinationStampStore::new(&storage_dir));
        }
        // InterfaceDiscovery (upstream 884f109b): an instance discovering
        // interfaces wants their announces, so `required_only` keeps them.
        #[cfg(feature = "iface-local")]
        if discover_interfaces {
            node.wants_destination_type(&format!(
                "{}.discovery.interface",
                crate::discovery::APP_NAME
            ));
        }
        #[cfg(not(feature = "iface-local"))]
        let _ = discover_interfaces;
        Ok(node)
    }
}

/// What the node's known destination storage holds when it starts.
struct KnownDestinationsStorage {
    destinations: HashMap<[u8; 16], storage::KnownDestination>,
    ratchet_store: Arc<dyn storage::RatchetStore>,
    /// The known destinations database, when it could be opened.
    database: Option<Arc<crate::storage_sqlite::KnownDestinationsStore>>,
}

/// The known destinations and the ratchet store: from the known
/// destinations database, into which legacy storage is imported once, or
/// from legacy storage when the database cannot be opened.
fn open_known_destinations(
    paths: &storage::StoragePaths,
    known_destinations_path: &Path,
    ratchet_expiry: u64,
) -> KnownDestinationsStorage {
    let known_destinations_db = crate::storage_sqlite::default_path(&paths.storage);
    match crate::storage_sqlite::KnownDestinationsStore::open(&known_destinations_db, 16) {
        Ok(store) => {
            let store = Arc::new(store);
            let started = std::time::Instant::now();
            let mut destinations: std::collections::HashMap<[u8; 16], storage::KnownDestination> =
                store
                    .load_all()
                    .map(|entries| entries.into_iter().collect())
                    .unwrap_or_else(|err| {
                        log::warn!("failed to load known destinations from database: {}", err);
                        Default::default()
                    });
            if destinations.is_empty() && known_destinations_path.is_file() {
                match store.import_legacy(known_destinations_path) {
                    Ok(imported) if imported > 0 => {
                        log::info!(
                            "Imported {} known destinations from legacy storage into the known destinations database",
                            imported
                        );
                        let _ = std::fs::rename(
                            known_destinations_path,
                            known_destinations_path.with_extension("imported"),
                        );
                        destinations = store
                            .load_all()
                            .map(|entries| entries.into_iter().collect())
                            .unwrap_or_default();
                    }
                    Ok(_) => {}
                    Err(err) => {
                        log::warn!("could not import legacy known destinations: {}", err)
                    }
                }
            }
            log::info!(
                "Loaded {} known destinations from storage in {}",
                destinations.len(),
                crate::logging::prettyshorttime(started.elapsed().as_secs_f64())
            );
            let known_destination_hashes: HashSet<[u8; 16]> =
                destinations.keys().copied().collect();
            if let Err(err) = store.import_legacy_ratchets(
                &paths.ratchets,
                time::now() - ratchet_expiry as f64,
                &known_destination_hashes,
            ) {
                log::warn!("could not import legacy ratchets: {}", err);
            }
            KnownDestinationsStorage {
                destinations,
                ratchet_store: store.clone(),
                database: Some(store),
            }
        }
        Err(err) => {
            log::warn!(
                "could not initialise known destinations database, falling back to legacy storage: {}",
                err
            );
            let destinations = match storage::load_known_destinations(known_destinations_path) {
                Ok(destinations) => destinations,
                Err(err) if err.kind() == io::ErrorKind::NotFound => Default::default(),
                Err(err) => {
                    log::warn!("failed to load known destinations: {}", err);
                    Default::default()
                }
            };
            KnownDestinationsStorage {
                destinations,
                ratchet_store: Arc::new(storage::FsRatchetStore::new(paths.ratchets.clone())),
                database: None,
            }
        }
    }
}

/// The transport identity. It lives in storage/transport_identity, as
/// upstream keeps it, so a config directory keeps its transport identity
/// whichever implementation runs it. Directories written before only hold
/// storage/identities/identity: carry that over, or create one when
/// neither exists.
fn load_transport_identity(paths: &storage::StoragePaths) -> io::Result<Identity> {
    let transport_identity_path = storage::transport_identity_path(paths);
    if transport_identity_path.exists() {
        let identity = storage::load_identity(&transport_identity_path)?;
        log::info!("Loaded Transport Identity from storage");
        return Ok(identity);
    }
    let node_identity_path = paths.identities.join("identity");
    let identity = if node_identity_path.exists() {
        let identity = storage::load_identity(&node_identity_path)?;
        log::info!("Loaded Transport Identity from storage");
        identity
    } else {
        log::info!("No valid Transport Identity in storage, creating...");
        let identity = create_identity();
        storage::save_identity(&identity, &node_identity_path)?;
        identity
    };
    storage::save_identity(&identity, &transport_identity_path)?;
    Ok(identity)
}

/// The configs of the enabled interfaces in `rns_config`, and the ids they
/// start with. An interface whose config is wrong is skipped with a warning,
/// or fails the start on a private node, which runs only what it was given.
fn build_interface_configs(
    rns_config: &config::RnsConfig,
    paths: &storage::StoragePaths,
    private: bool,
) -> io::Result<(
    Vec<InterfaceConfig>,
    HashMap<String, rns_core::transport::types::InterfaceId>,
)> {
    let registry = crate::interface::registry::InterfaceRegistry::with_builtins();
    let mut interface_configs = Vec::new();
    let mut initial_ids = HashMap::new();
    let mut next_id_val = 1u64;

    for iface in &rns_config.interfaces {
        if !iface.enabled {
            continue;
        }

        let iface_id = rns_core::transport::types::InterfaceId(next_id_val);
        next_id_val += 1;

        let factory = match registry.get(&iface.interface_type) {
            Some(f) => f,
            None => {
                if private {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "unsupported enabled interface type '{}' for '{}'",
                            iface.interface_type, iface.name
                        ),
                    ));
                }
                log::warn!(
                    "Unsupported interface type '{}' for '{}'",
                    iface.interface_type,
                    iface.name,
                );
                continue;
            }
        };

        let mut iface_mode = parse_interface_mode(&iface.mode);

        let discoverable = iface
            .params
            .get("discoverable")
            .and_then(|value| config::parse_bool_pub(value))
            .unwrap_or(false);
        let ignore_config_warnings = iface
            .params
            .get("ignore_config_warnings")
            .and_then(|value| config::parse_bool_pub(value))
            .unwrap_or(false);
        let normalized_mode = normalize_discovery_mode(
            &iface.interface_type,
            iface_mode,
            discoverable,
            ignore_config_warnings,
        );
        if normalized_mode != iface_mode {
            log::info!(
                "Interface '{}' has discovery enabled, auto-configuring mode to {}",
                iface.name,
                if normalized_mode == rns_core::constants::MODE_ACCESS_POINT {
                    "ACCESS_POINT"
                } else {
                    "GATEWAY"
                }
            );
            iface_mode = normalized_mode;
        }

        let default_ifac_size = factory.default_ifac_size();
        let ifac_config = extract_ifac_config(&iface.params, default_ifac_size);
        let discovery_config =
            extract_discovery_config(&iface.name, &iface.interface_type, &iface.params);
        let ingress_control =
            match parse_ingress_control_config(&iface.interface_type, &iface.params) {
                Ok(config) => config,
                Err(e) => {
                    if private {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid ingress control for '{}': {e}", iface.name),
                        ));
                    }
                    log::warn!(
                        "Failed to parse ingress control config for '{}': {}",
                        iface.name,
                        e
                    );
                    continue;
                }
            };
        let stamp_costs = match parse_interface_stamp_costs(&iface.params) {
            Ok(costs) => costs,
            Err(e) => {
                if private {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid stamp cost for '{}': {e}", iface.name),
                    ));
                }
                log::warn!("Failed to parse stamp costs for '{}': {}", iface.name, e);
                continue;
            }
        };
        let announce_limits = match parse_interface_announce_limits(&iface.params) {
            Ok(limits) => limits,
            Err(e) => {
                if private {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid announce limits for '{}': {e}", iface.name),
                    ));
                }
                log::warn!(
                    "Failed to parse announce limits for '{}': {}",
                    iface.name,
                    e
                );
                continue;
            }
        };
        let recursive_prs = iface
            .params
            .get("recursive_prs")
            .and_then(|v| config::parse_bool_pub(v))
            .unwrap_or(false);
        let announces_from_internal = iface
            .params
            .get("announces_from_internal")
            .and_then(|v| config::parse_bool_pub(v))
            .unwrap_or(true);
        let gravity = parse_interface_gravity(
            iface.params.get("gravity").map(String::as_str),
            rns_config.reticulum.default_gravity,
        );
        let announces_to_internal = iface
            .params
            .get("announces_to_internal")
            .and_then(|v| config::parse_bool_pub(v));

        // Inject storage_dir for I2P (and any future factories that need it)
        let mut params = iface.params.clone();
        if !params.contains_key("storage_dir") {
            params.insert(
                "storage_dir".to_string(),
                paths.storage.to_string_lossy().to_string(),
            );
        }
        // Inject device for TCP client
        if let Some(ref device) = rns_config.reticulum.device {
            if !params.contains_key("device") {
                params.insert("device".to_string(), device.clone());
            }
        }

        let config_data = match factory.parse_config_section(
            &iface.name,
            iface_id,
            crate::interface::ConfigSection {
                params: &params,
                children: &iface.subinterfaces,
            },
        ) {
            Ok(data) => data,
            Err(e) => {
                if private {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid interface '{}': {e}", iface.name),
                    ));
                }
                log::warn!("Failed to parse config for '{}': {}", iface.name, e);
                continue;
            }
        };
        // Ids are handed out in the order interfaces are added; an
        // RNodeMultiInterface's subinterfaces take the ones after its
        // own.
        next_id_val = iface_id.0 + reserved_interface_ids(config_data.as_ref());

        interface_configs.push(InterfaceConfig {
            name: iface.name.clone(),
            type_name: iface.interface_type.clone(),
            config_data,
            mode: iface_mode,
            gravity,
            hop_limiter: parse_interface_hop_limiter(
                iface.params.get("hop_limiter").map(String::as_str),
            ),
            recursive_prs,
            announces_from_internal,
            announces_to_internal,
            ingress_control,
            stamp_costs,
            announce_limits,
            ifac: ifac_config,
            discovery: discovery_config,
        });
        initial_ids.insert(iface.name.clone(), iface_id);
    }
    Ok((interface_configs, initial_ids))
}

/// The identity hashes `remote_management_allowed` lists, skipping and
/// logging entries that are not 32 hex digits.
fn parse_management_allowed(entries: &[String]) -> Vec<[u8; 16]> {
    let mut mgmt_allowed = Vec::new();
    for hex_hash in entries {
        if hex_hash.len() == 32 {
            if let Ok(bytes) = (0..hex_hash.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex_hash[i..i + 2], 16))
                .collect::<Result<Vec<u8>, _>>()
            {
                if bytes.len() == 16 {
                    let mut h = [0u8; 16];
                    h.copy_from_slice(&bytes);
                    mgmt_allowed.push(h);
                }
            } else {
                log::warn!("Invalid hex in remote_management_allowed: {}", hex_hash);
            }
        } else {
            log::warn!(
                "Invalid entry in remote_management_allowed (expected 32 hex chars, got {}): {}",
                hex_hash.len(),
                hex_hash,
            );
        }
    }
    mgmt_allowed
}

/// The probe servers `probe_addr` lists, comma separated, skipping and
/// logging entries that do not parse.
fn parse_probe_addrs(probe_addr: Option<&str>) -> Vec<std::net::SocketAddr> {
    probe_addr
        .map(|s| {
            s.split(',')
                .filter_map(|entry| {
                    let trimmed = entry.trim();
                    if trimmed.is_empty() {
                        return None;
                    }
                    trimmed
                        .parse::<std::net::SocketAddr>()
                        .map_err(|e| {
                            log::warn!("Invalid probe_addr entry '{}': {}", trimmed, e);
                            e
                        })
                        .ok()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `probe_protocol`: STUN when it says so, else RNSP.
fn parse_probe_protocol(probe_protocol: Option<&str>) -> rns_core::holepunch::ProbeProtocol {
    match probe_protocol.map(|s| s.to_lowercase()) {
        Some(ref s) if s == "stun" => rns_core::holepunch::ProbeProtocol::Stun,
        _ => rns_core::holepunch::ProbeProtocol::Rnsp,
    }
}

/// Remove ratchets of destinations no longer known, and expired ones.
fn clean_ratchets(
    ratchet_store: &dyn storage::RatchetStore,
    known_destinations: &HashMap<[u8; 16], storage::KnownDestination>,
    ratchet_expiry: u64,
) {
    let known_destination_hashes: HashSet<[u8; 16]> = known_destinations.keys().copied().collect();
    match ratchet_store.cleanup(
        &known_destination_hashes,
        time::now(),
        ratchet_expiry as f64,
    ) {
        Ok(stats) if stats.processed > 0 => log::debug!(
            "Processed {} ratchets, not in use {}, removed {}",
            stats.processed,
            stats.not_known,
            stats.removed
        ),
        Ok(_) => {}
        Err(err) => log::warn!("failed to clean ratchets: {}", err),
    }
}

/// Whether `autoconnect_policy` is upstream's, and the bootstrap-only
/// interfaces. The settings of the policy not chosen are read but ignored,
/// with a warning.
fn autoconnect_policy(rns_config: &config::RnsConfig) -> (bool, Vec<String>) {
    let upstream_policy =
        rns_config.reticulum.autoconnect_policy == config::AutoconnectPolicy::Upstream;
    let bootstrap_interfaces: Vec<String> = rns_config
        .interfaces
        .iter()
        .filter(|iface| {
            iface
                .params
                .get("bootstrap_only")
                .and_then(|v| config::parse_bool_pub(v))
                .unwrap_or(false)
        })
        .map(|iface| iface.name.clone())
        .collect();
    if upstream_policy && rns_config.reticulum.backbone_peer_pool_max_connected > 0 {
        log::warn!(
            "backbone_peer_pool_max_connected applies only with autoconnect_policy = pool; ignoring it"
        );
    }
    if !upstream_policy
        && (rns_config.reticulum.autoconnect_discovered_interfaces > 0
            || !bootstrap_interfaces.is_empty())
    {
        log::warn!(
            "autoconnect_discovered_interfaces and bootstrap_only apply only with autoconnect_policy = upstream; ignoring them"
        );
    }
    (upstream_policy, bootstrap_interfaces)
}

/// Register `dest` as a built-in SINGLE destination taking links, signed
/// with the Ed25519 half of `prv_key`, as the management destinations are.
fn register_builtin_link_destination(driver: &mut Driver, dest: [u8; 16], prv_key: &[u8; 64]) {
    let (_, sig_seed) = rns_crypto::identity::split_key(prv_key);
    let sig_prv = rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&sig_seed);
    let sig_pub_bytes = sig_prv.public_key().public_bytes();
    driver
        .engine
        .register_destination(dest, rns_core::constants::DESTINATION_SINGLE);
    driver
        .local_destinations
        .insert(dest, rns_core::constants::DESTINATION_SINGLE);
    driver.builtin_link_destinations.insert(dest);
    driver.link_manager.register_link_destination(
        dest,
        sig_prv,
        sig_pub_bytes,
        crate::link_manager::ResourceStrategy::AcceptNone,
    );
}

/// The remote management destination of the transport identity
/// `transport_id`, answering status and path requests.
fn enable_remote_management(
    driver: &mut Driver,
    transport_id: &Identity,
    management: &crate::management::ManagementConfig,
) {
    let Some(prv_key) = transport_id.get_private_key() else {
        return;
    };
    let identity_hash = *transport_id.hash();
    let mgmt_dest = crate::management::management_dest_hash(&identity_hash);
    register_builtin_link_destination(driver, mgmt_dest, &prv_key);
    driver
        .link_manager
        .register_management_path(crate::management::status_path_hash());
    driver
        .link_manager
        .register_management_path(crate::management::path_path_hash());
    log::info!(
        target: crate::logging::NOTICE_TARGET,
        "Enabled remote management on <rnstransport.remote.management.{}:{}>",
        hex_string(&identity_hash),
        hex_string(&mgmt_dest),
    );
    if !management.remote_management_allowed.is_empty() {
        log::info!(
            "Remote management allowed for {} identities",
            management.remote_management_allowed.len(),
        );
    }
}

/// The blackhole list destination of the transport identity
/// `transport_id`.
fn enable_blackhole_publishing(driver: &mut Driver, transport_id: &Identity) {
    let Some(prv_key) = transport_id.get_private_key() else {
        return;
    };
    let identity_hash = *transport_id.hash();
    let bh_dest = crate::management::blackhole_dest_hash(&identity_hash);
    register_builtin_link_destination(driver, bh_dest, &prv_key);
    driver
        .link_manager
        .register_management_path(crate::management::list_path_hash());
    // Upstream 426673e9: requesting the list costs a 5.25 stamp, below the
    // `LR_COST` default.
    driver
        .link_manager
        .link_request_costs()
        .set(bh_dest, rns_core::constants::BLACKHOLE_LINK_COST.as_f64());
    log::info!(
        target: crate::logging::NOTICE_TARGET,
        "Enabled blackhole list publishing for transport identity <{}>",
        hex_string(&identity_hash),
    );
}

/// Upstream's lines for the path and tunnel tables found in storage.
fn log_restored_tables(stats: &rns_core::transport::persistence::RestoreStats, storage_dir: &Path) {
    // Upstream's lines, for the tables it found in storage.
    let entries = |n: usize| if n == 1 { "entry" } else { "entries" };
    if storage_dir.join("destination_table").is_file() {
        let filtered = if stats.filtered_paths > 0 {
            format!(", {} filtered", stats.filtered_paths)
        } else {
            String::new()
        };
        log::info!(
            "Loaded {} path table {} from storage{}",
            stats.paths,
            entries(stats.paths),
            filtered
        );
    }
    if storage_dir.join("tunnels").is_file() {
        log::info!(
            "Loaded {} tunnel table {} from storage",
            stats.tunnels,
            entries(stats.tunnels)
        );
    }
}

/// The probe destination of the transport identity `transport_id`, which
/// proves every packet it receives.
fn enable_probe_responder(driver: &mut Driver, transport_id: &Identity) {
    let identity_hash = *transport_id.hash();
    let probe_dest = crate::management::probe_dest_hash(&identity_hash);

    // Register as SINGLE destination in transport engine
    driver
        .engine
        .register_destination(probe_dest, rns_core::constants::DESTINATION_SINGLE);
    driver
        .local_destinations
        .insert(probe_dest, rns_core::constants::DESTINATION_SINGLE);

    // Register PROVE_ALL proof strategy with transport identity
    let probe_identity = rns_crypto::identity::Identity::from_private_key(
        &transport_id
            .get_private_key()
            .expect("the transport identity was built from its private key"),
    );
    driver.proof_strategies.insert(
        probe_dest,
        (
            rns_core::types::ProofStrategy::ProveAll,
            Some(probe_identity),
        ),
    );

    driver.probe_responder_hash = Some(probe_dest);

    log::info!(
        target: crate::logging::NOTICE_TARGET,
        "Transport Instance will respond to probe requests on <rnstransport.probe.{}:{}>",
        hex_string(&identity_hash),
        hex_string(&probe_dest),
    );
}

/// Load the enabled hooks of the config into `driver`'s hook slots,
/// skipping, with a warning or an error, those that cannot be loaded.
#[cfg(feature = "hooks")]
fn load_configured_hooks(driver: &mut Driver, hooks: &[config::ParsedHook]) {
    for hook_cfg in hooks {
        if !hook_cfg.enabled {
            continue;
        }
        let point_idx = match config::parse_hook_point(&hook_cfg.attach_point) {
            Some(idx) => idx,
            None => {
                log::warn!(
                    "Unknown hook point '{}' for hook '{}'",
                    hook_cfg.attach_point,
                    hook_cfg.name,
                );
                continue;
            }
        };
        let mgr = match driver.hook_manager.as_ref() {
            Some(m) => m,
            None => {
                log::warn!(
                    "Hook manager not available, skipping hook '{}'",
                    hook_cfg.name
                );
                continue;
            }
        };
        let hook_backend = match config::parse_hook_backend(&hook_cfg.hook_type) {
            Ok(backend) => backend,
            Err(e) => {
                log::warn!(
                    "Invalid hook type '{}' for hook '{}': {}",
                    hook_cfg.hook_type,
                    hook_cfg.name,
                    e,
                );
                continue;
            }
        };
        let load_result = if hook_backend == rns_hooks::HookBackend::Builtin {
            let builtin_id = hook_cfg
                .builtin_id
                .as_deref()
                .filter(|id| !id.is_empty())
                .or_else(|| (!hook_cfg.path.is_empty()).then_some(hook_cfg.path.as_str()));
            match builtin_id {
                Some(id) => mgr.load_builtin(hook_cfg.name.clone(), id, hook_cfg.priority),
                None => Err(rns_hooks::HookError::CompileError(
                    "built-in hook requires builtin/id or path".to_string(),
                )),
            }
        } else {
            mgr.load_file_backend(
                hook_cfg.name.clone(),
                std::path::Path::new(&hook_cfg.path),
                hook_cfg.priority,
                hook_backend,
            )
        };
        match load_result {
            Ok(program) => {
                driver.hook_slots[point_idx].attach(program);
                log::info!(
                    "Loaded hook '{}' at point {} (priority {})",
                    hook_cfg.name,
                    hook_cfg.attach_point,
                    hook_cfg.priority,
                );
            }
            Err(e) => {
                log::error!(
                    "Failed to load hook '{}' from '{}': {}",
                    hook_cfg.name,
                    hook_cfg.path,
                    e,
                );
            }
        }
    }
}

/// The thread that verifies announces, unless the compact engine verifies
/// them on its driver loop.
fn spawn_announce_verifier(
    queue: &Arc<std::sync::Mutex<rns_core::transport::announce_verify_queue::AnnounceVerifyQueue>>,
    signal: &Arc<crate::driver::WorkSignal>,
    verify_tx: EventSender,
) -> io::Result<Option<JoinHandle<()>>> {
    let announce_verify_queue = Arc::clone(queue);
    let verify_shutdown_thread = Arc::clone(signal);
    let handle = if crate::engine::FOLD_WORK {
        None
    } else {
        Some(
            thread::Builder::new()
                .name("rns-verify".into())
                .spawn(move || {
                    #[cfg(target_family = "unix")]
                    {
                        // SAFETY: `nice` takes a plain integer and only lowers scheduling
                        // priority (per thread on Linux); no memory is involved.
                        unsafe {
                            libc::nice(5);
                        }
                    }

                    while !verify_shutdown_thread.stopped() {
                        let batch = {
                            let mut queue = announce_verify_queue
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            queue.take_pending(time::now())
                        };

                        if batch.is_empty() {
                            // Until the driver queues an announce.
                            verify_shutdown_thread.wait();
                            continue;
                        }

                        for (key, pending) in batch {
                            if verify_shutdown_thread.stopped() {
                                break;
                            }
                            let event = match crate::driver::check_pending_announce(&pending) {
                                crate::driver::AnnounceCheck::Valid {
                                    validated,
                                    sig_cache_key,
                                } => Event::AnnounceVerified {
                                    key,
                                    validated,
                                    sig_cache_key,
                                },
                                crate::driver::AnnounceCheck::Invalid { sig_cache_key } => {
                                    Event::AnnounceVerifyFailed { key, sig_cache_key }
                                }
                            };
                            if verify_tx.send(event).is_err() {
                                return;
                            }
                        }
                    }
                })?,
        )
    };
    Ok(handle)
}

/// The thread that persists the transport state every 12 hours, as
/// upstream's background persistence does, and the sender that stops it;
/// none when the compact engine persists on its driver loop. It writes at
/// low priority and reads engine state only through the driver's snapshot.
fn spawn_transport_state_persister(
    transport_state_dir: Option<std::path::PathBuf>,
    persist_tx: EventSender,
) -> io::Result<Option<(JoinHandle<()>, std::sync::mpsc::Sender<()>)>> {
    let threads = if let Some(storage_dir) =
        transport_state_dir.filter(|_| !crate::engine::FOLD_TIMERS)
    {
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let handle = thread::Builder::new()
            .name("rns-persist".into())
            .spawn(move || {
                #[cfg(target_family = "unix")]
                // SAFETY: `nice` takes a plain integer and only lowers scheduling
                // priority (per thread on Linux); no memory is involved.
                unsafe {
                    libc::nice(5);
                }

                loop {
                    match stop_rx.recv_timeout(Duration::from_secs(12 * 60 * 60)) {
                        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    }
                    let (response_tx, response_rx) = std::sync::mpsc::channel();
                    if persist_tx
                        .send(Event::query(
                            QueryRequest::TransportStateSnapshot,
                            response_tx,
                        ))
                        .is_err()
                    {
                        break;
                    }
                    let Ok(QueryResponse::TransportStateSnapshot(snapshot)) = response_rx.recv()
                    else {
                        continue;
                    };
                    if let Err(err) = storage::save_transport_state(&snapshot, &storage_dir, true) {
                        log::warn!("failed to persist transport state: {}", err);
                    }
                }
            })?;
        Some((handle, stop_tx))
    } else {
        None
    };
    Ok(threads)
}
