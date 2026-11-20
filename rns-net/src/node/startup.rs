//! Starting a node: reading its config and bringing up its driver,
//! interfaces and services.

mod builtin_destinations;
mod config_steps;
mod services;
mod threads;

use builtin_destinations::*;
use config_steps::*;
use services::*;
use threads::*;

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
        // The node signs and decrypts with its identity: one without a
        // private key cannot run a node.
        let private_key = identity.get_private_key().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the node identity has no private key",
            )
        })?;
        let rpc_auth_key = config
            .shared_instance
            .rpc_key
            .or(queue_config.rpc_auth_key)
            .unwrap_or_else(|| crate::rpc::derive_auth_key(&private_key));
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
            Identity::from_private_key(&private_key)
        } else {
            let identity = create_identity();
            log::info!(
                "Initialized ephemeral transport identity <{}>",
                hex(identity.hash())
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

        let (tx, rx) = event::try_channel_with_queue_capacities(
            config.driver_event_queue_capacity,
            queue_config.inbound_capacities,
        )?;
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
        #[cfg(feature = "iface-backbone")]
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
            #[cfg(runtime_config_ifaces)]
            register_interface_runtime(
                &mut driver,
                &iface_config,
                #[cfg(any(feature = "iface-tcp", feature = "iface-backbone"))]
                config.transport_enabled,
            );
            #[cfg(feature = "iface-backbone")]
            configured_client_targets.extend(configured_client_target(&iface_config));

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
                #[cfg(feature = "iface-backbone")]
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
            log::info!("Transport instance <{}> started", hex(transport_id.hash()));
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

        #[cfg(feature = "iface-local")]
        if config.share_instance {
            start_local_server(
                &mut driver,
                &config.instance_name,
                config.shared_instance_port,
                config.shared_instance.use_af_unix,
                tx.clone(),
                next_dynamic_id.clone(),
            );
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
