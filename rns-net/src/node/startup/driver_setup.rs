//! The steps of building and configuring the driver as the node starts:
//! its identities, transport settings, probing, discovery and restored
//! state.

use super::*;

/// The directory the node keeps its state in: `storage` beside the cache
/// directory, when the node has one.
pub(super) fn node_storage_dir(cache_dir: Option<&Path>) -> Option<std::path::PathBuf> {
    cache_dir.map(|cache_dir| {
        cache_dir
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("storage")
    })
}

/// Create the directories the node keeps state in before anything starts;
/// as upstream does, failing to create one fails startup.
pub(super) fn create_state_dirs(
    cache_dir: Option<&Path>,
    storage_dir: Option<&Path>,
) -> io::Result<()> {
    if let (Some(_), Some(storage_dir)) = (cache_dir, storage_dir) {
        for dir in [
            crate::announce_cache::announce_cache_base(storage_dir),
            storage_dir.join("discovery").join("interfaces"),
            storage_dir.join("blackhole"),
        ] {
            std::fs::create_dir_all(&dir).map_err(|e| {
                io::Error::new(e.kind(), format!("could not create {}: {e}", dir.display()))
            })?;
        }
    }
    Ok(())
}

/// The identities a node starts with, and the key of its RPC server.
pub(super) struct NodeIdentities {
    /// The node identity.
    pub(super) identity: Identity,
    /// `Transport.identity`: the node identity, or an ephemeral one on an
    /// instance without transport and without a static transport identity.
    pub(super) transport_identity: Identity,
    /// `Transport.application_identity`, which names this application's
    /// registrations with a shared instance.
    pub(super) application_identity: Identity,
    pub(super) rpc_auth_key: [u8; 32],
}

impl NodeIdentities {
    /// Take the node identity, or a new one, and derive the transport
    /// identity, the application identity and the RPC key from the config.
    pub(super) fn new(
        identity: Option<Identity>,
        config: &NodeConfig,
        queue_config: &NodeQueueConfig,
    ) -> io::Result<Self> {
        let identity = identity.unwrap_or_else(|| Identity::new(&mut OsRng));
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
        // Since upstream 606a1691 a discoverable interface no longer
        // implies `static_transport_identity`: such an interface is not made
        // discoverable on an instance without either, see
        // `discoverable_on_instance`.
        let transport_identity = if config.transport_enabled || config.static_transport_identity {
            Identity::from_private_key(&private_key)
        } else {
            let identity = create_identity();
            log::info!(
                "Initialized ephemeral transport identity <{}>",
                hex(identity.hash())
            );
            identity
        };
        let application_identity = create_identity();
        Ok(Self {
            identity,
            transport_identity,
            application_identity,
            rpc_auth_key,
        })
    }
}

/// The transport engine's settings, with a random local hop delta when the
/// config asks for one.
pub(super) fn transport_config(
    config: &NodeConfig,
    queue_config: &NodeQueueConfig,
    transport_identity_hash: &[u8; 16],
) -> TransportConfig {
    let local_hops_delta = if config.local_hops_delta {
        let mut byte = [0u8; 1];
        OsRng.fill_bytes(&mut byte);
        byte[0] % 6 + 2
    } else {
        0
    };

    TransportConfig {
        transport_enabled: config.transport_enabled,
        identity_hash: Some(*transport_identity_hash),
        local_hops_delta,
        prefer_shorter_path: config.prefer_shorter_path,
        max_paths_per_destination: config.max_paths_per_destination,
        unresponsive_path_recovery: config.unresponsive_path_recovery,
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
    }
}

/// What the node keeps of the driver it builds: handles shared with it.
pub(super) struct DriverHandles {
    pub(super) tick_interval_ms: Arc<AtomicU64>,
    pub(super) stamper: Arc<crate::stamper::Stamper>,
    pub(super) stamp_destinations: Arc<AtomicBool>,
    pub(super) stamp_targets: crate::stamper::StampTargets,
    pub(super) accepting_work: Arc<AtomicBool>,
}

/// Build the driver and apply the config's stamp, queue, ratchet, announce
/// rate, ingress control and direct connect settings to it.
pub(super) fn new_driver(
    config: &NodeConfig,
    queue_config: &NodeQueueConfig,
    transport_config: TransportConfig,
    rx: event::EventReceiver,
    tx: &EventSender,
    callbacks: Box<dyn Callbacks>,
) -> (Driver, DriverHandles) {
    let tick_interval_ms = Arc::new(AtomicU64::new(1000));
    let mut driver = Driver::new(transport_config, rx, tx.clone(), callbacks);
    let stamper = Arc::new(crate::stamper::Stamper::new(tx.clone(), None));
    driver.set_stamper(Arc::clone(&stamper));
    let stamp_destinations = Arc::new(AtomicBool::new(rns_core::constants::STAMP_DESTINATIONS));
    driver.set_stamp_destinations_flag(Arc::clone(&stamp_destinations));
    driver.apply_stamp_config(&config.stamps, queue_config.hop_limiter);
    crate::stamps::set_worker_limits(config.stamps.max_workers, config.stamps.worker_niceness);
    *driver.engine.destination_filter_mut() = queue_config.filter.destination_filter();
    driver.destination_type_names = queue_config.destination_type_names.clone();
    let stamp_targets = crate::stamper::StampTargets::from(&config.stamps);
    driver.interface_settings.underlay_mark = config.underlay_mark;
    driver.proofs.implicit = config.use_implicit_proof;
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
    driver.announce_verify.async_enabled = true;
    driver.set_tick_interval_handle(Arc::clone(&tick_interval_ms));
    let accepting_work = driver.accepting_work_handle();
    driver.known.ttl = config.known_destinations_ttl.as_secs_f64();
    driver.known.max_entries = config.known_destinations_max_entries;
    driver.ratchet_store = config.ratchet_store.clone();
    driver.ratchet_expiry_secs = config.ratchet_expiry.as_secs_f64();
    driver.interface_settings.writer_queue_capacity = config.interface_writer_queue_capacity;
    driver.set_announce_rate_defaults(config.announce_rate_defaults);
    driver.set_ingress_control_defaults(config.ingress_control_defaults);
    driver.runtime_config.defaults.known_destinations_ttl =
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
    driver.runtime_config.defaults.direct_connect_policy = config.direct_connect_policy;
    (
        driver,
        DriverHandles {
            tick_interval_ms,
            stamper,
            stamp_destinations,
            stamp_targets,
            accepting_work,
        },
    )
}

/// Start the driver's provider bridge, announce cache and probe server,
/// hand it the transport and network identities, and apply the
/// management, hook and discovery settings. The probe server's handle is
/// returned when it runs on a thread of its own.
pub(super) fn configure_driver_services(
    driver: &mut Driver,
    config: &NodeConfig,
    tx: &EventSender,
    transport_identity: Identity,
    network_identity: Option<Identity>,
) -> Option<crate::holepunch::probe::ProbeServerHandle> {
    #[cfg(feature = "hooks")]
    start_provider_bridge(driver, config.provider_bridge.clone(), tx);

    // Set up the announce cache if a cache directory is configured, in
    // upstream's `storage/cache`, moving one rns-rs kept in the cache
    // directory itself.
    if let Some(ref cache_dir) = config.cache_dir {
        if let Some(storage_dir) = node_storage_dir(Some(cache_dir)) {
            let announces_dir = crate::announce_cache::announce_cache_base(&storage_dir);
            crate::announce_cache::migrate_announce_cache(
                &cache_dir.join("announces"),
                &announces_dir,
            );
            driver.announce_cache = Some(crate::announce_cache::AnnounceCache::new(announces_dir));
        }
    }
    let probe_server = start_probe_server(driver, config, tx);

    // Store management config on driver for ACL enforcement
    driver.management.config = config.management.clone();
    // Store transport identity for tunnel synthesis and management announces.
    driver.transport_identity = Some(transport_identity);
    driver.hooks.load_configured(&config.hooks);
    configure_discovery(driver, config, network_identity);
    probe_server
}

/// Apply the provider bridge's queue settings and start the bridge when it
/// is enabled; a bridge that fails to start is logged and left out.
#[cfg(feature = "hooks")]
fn start_provider_bridge(
    driver: &mut Driver,
    provider_config: Option<crate::provider_bridge::ProviderBridgeConfig>,
    tx: &EventSender,
) {
    if let Some(provider_config) = provider_config {
        driver.runtime_config.defaults.provider_queue_max_events = provider_config.queue_max_events;
        driver.runtime_config.defaults.provider_queue_max_bytes = provider_config.queue_max_bytes;
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
                Ok(bridge) => driver.hooks.provider_bridge = Some(bridge),
                Err(err) => log::warn!("failed to start provider bridge: {}", err),
            }
        }
    }
}

/// Configure the probe addresses and device for hole punching, and start
/// the probe server if configured: on its own thread, whose handle is
/// returned, or on the driver loop when the compact engine folds services.
fn start_probe_server(
    driver: &mut Driver,
    config: &NodeConfig,
    tx: &EventSender,
) -> Option<crate::holepunch::probe::ProbeServerHandle> {
    if !config.probe_addrs.is_empty() || config.device.is_some() || config.underlay_mark.is_some() {
        driver.set_probe_config(
            config.probe_addrs.clone(),
            config.probe_protocol,
            config.device.clone(),
        );
    }

    // A peer never gets this node to punch toward its probe server.
    if let Some(port) = config.probe_port {
        driver.holepunch_manager.set_own_listen_ports(vec![port]);
    }
    let port = config.probe_port?;
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
}

/// Apply the interface discovery and autoconnect settings, and register
/// the network identity's destinations.
fn configure_discovery(
    driver: &mut Driver,
    config: &NodeConfig,
    network_identity: Option<Identity>,
) {
    driver.discovery.enabled = config.discover_interfaces;
    driver.discovery.sources = config.discovery.interface_discovery_sources.clone();
    driver.interface_settings.forced_local_bitrate = config.shared_instance.force_bitrate;
    driver.network_identity = network_identity;
    driver.register_network_destinations();
    driver.discovery.autoconnect_mode = config.autoconnect_interface_mode;
    driver.discovery.autoconnect_gravity = config.autoconnect_interface_gravity;
    driver.discovery.autoconnect_announces_to_internal =
        config.autoconnect_announces_to_internal.then_some(true);
    driver.discovery.autoconnect_unverified_implementations =
        config.autoconnect_unverified_implementations;
    if let Some(val) = config.discovery_required_value {
        driver.discovery.required_value = val;
    }
}

/// Start the interface discovery announcer, if any interface is
/// discoverable.
pub(super) fn start_interface_announcer(
    driver: &mut Driver,
    identity: &Identity,
    discoverable_interfaces: Vec<crate::discovery::DiscoverableInterface>,
) {
    if !discoverable_interfaces.is_empty() {
        let transport_id = *identity.hash();
        let announcer = driver.new_interface_announcer(transport_id, discoverable_interfaces);
        log::info!("Interface discovery announcer initialized");
        driver.discovery.announcer = Some(announcer);
    }
}

/// Point the driver at the discovered interfaces storage and upstream's
/// `storage/blackhole` beside it, loading the blackhole and starting its
/// updater, when the node has a cache directory.
pub(super) fn open_discovery_storage(driver: &mut Driver, config: &NodeConfig) {
    if let Some(ref cache_dir) = config.cache_dir {
        let disc_path = std::path::PathBuf::from(cache_dir)
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("storage")
            .join("discovery")
            .join("interfaces");
        driver.discovery.storage = crate::discovery::DiscoveredInterfaceStorage::new(disc_path);
        let blackhole_path = std::path::PathBuf::from(cache_dir)
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("storage")
            .join("blackhole");
        driver.blackhole.sources = config.management.blackhole_sources.clone();
        driver.load_blackhole(blackhole_path);
        driver.enable_blackhole_updater(config.management.blackhole_update_interval);
    }
}

/// Restore the transport state persisted in `transport_state_dir`, with
/// the announces it refers to from the announce cache, and return what was
/// restored. A state that cannot be loaded is logged and skipped.
pub(super) fn restore_transport_state(
    driver: &mut Driver,
    transport_state_dir: Option<&Path>,
) -> Option<rns_core::transport::persistence::RestoreStats> {
    let storage_dir = transport_state_dir?;
    match storage::load_transport_state(storage_dir) {
        Ok(snapshot) => {
            let announce_cache = driver.announce_cache.as_ref();
            let stats =
                driver
                    .engine
                    .restore_persistence_snapshot(snapshot, time::now(), |packet_hash| {
                        announce_cache
                            .and_then(|cache| cache.get(packet_hash).ok().flatten())
                            .map(|(raw, _)| raw)
                    });
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
            Some(stats)
        }
        Err(err) => {
            log::warn!("failed to restore transport state: {}", err);
            None
        }
    }
}

/// Configure the Backbone peer pool, seeded from the discovery cache, and
/// upstream's auto-connecting of discovered interfaces.
pub(super) fn configure_autoconnect(
    driver: &mut Driver,
    config: &NodeConfig,
    #[cfg(feature = "iface-backbone")] started: StartedInterfaces,
) {
    #[cfg(feature = "iface-backbone")]
    if let Some(settings) = config.backbone_peer_pool.clone() {
        driver.configure_backbone_peer_pool(settings, started.backbone_peer_pool_candidates);
        driver.seed_backbone_peer_pool_from_discovery_cache();
    }
    if config.discover_interfaces && config.discovery.autoconnect_discovered_interfaces > 0 {
        driver.enable_upstream_autoconnect(
            config.discovery.autoconnect_discovered_interfaces,
            config.discovery.bootstrap_interfaces.clone(),
            #[cfg(feature = "iface-backbone")]
            started.configured_client_targets,
        );
        driver.autoconnect_stored_discoveries();
    } else if !config.discovery.bootstrap_interfaces.is_empty() {
        log::warn!(
            "bootstrap_only interfaces stay up: they are only torn down while autoconnect_discovered_interfaces are connected"
        );
    }
}
