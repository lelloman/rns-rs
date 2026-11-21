//! Starting a node: reading its config and bringing up its driver,
//! interfaces and services.

mod builtin_destinations;
mod config_steps;
mod driver_setup;
mod interfaces;
mod node_config;
mod services;
mod threads;

use builtin_destinations::*;
use config_steps::*;
use driver_setup::*;
use interfaces::*;
use node_config::*;
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
    /// Names of destination types read with the config.
    destination_type_names: crate::destination_types::DestinationTypeNames,
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
            destination_type_names: Default::default(),
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
        let ReadConfig {
            config_file,
            rns_config,
            link_mtu_discovery,
        } = read_config(config_dir, private)?;
        // Upstream `Reticulum.__start_local_interface`: when another process
        // already serves this shared instance, attach to it as a client
        // instead of starting a second instance on the same interfaces.
        #[cfg(feature = "iface-local")]
        if !private && shared_instance_already_running(&rns_config) {
            return Self::connect_shared_from_config(Some(config_dir), callbacks);
        }
        // Addresses Backbone listeners refuse, from <config dir>/blocked_ips
        // (upstream 5f2dbc16).
        #[cfg(feature = "iface-backbone")]
        crate::interface::backbone::load_blocked_ips_file(config_dir);
        // Upstream c90a5d58: the names of destination types, from the
        // `[filter]` section and <config dir>/known_destination_types.
        let destination_type_names = crate::destination_types::DestinationTypeNames::from_config(
            config_dir,
            &rns_config.filter,
        );

        // Upstream loads the configured network identity while it reads the
        // config, creating it when the file is missing. It is kept apart
        // from the transport identity.
        let network_identity = match rns_config.reticulum.network_identity {
            Some(ref path) => Some(load_network_identity(path)?),
            None => None,
        };
        // Upstream 1.6.1 (25cce0a8) runs `Transport.ensure_identity()`
        // before it brings up the interfaces: the transport identity, the
        // ephemeral one used instead on an instance without transport, and
        // the application identity.
        let identity = load_transport_identity(&paths)?;
        let rpc_auth_key = shared_rpc_auth_key(&rns_config, &identity, private);
        let identities = NodeIdentities::new(
            Some(identity),
            rns_config.reticulum.enable_transport,
            rns_config.reticulum.static_transport_identity,
        )?;
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

        let interface_management = interface_management_config(
            &rns_config,
            &config_file,
            &paths,
            initial_ids,
            private,
            underlay_mark,
        );
        let (upstream_policy, bootstrap_interfaces) = autoconnect_policy(&rns_config);
        let node_config = node_config_from(
            &rns_config,
            NodeConfigParts {
                config_dir,
                private,
                underlay_mark,
                network_identity,
                cache_dir: paths.cache,
                ratchet_store: Arc::clone(&ratchet_store),
                interfaces: interface_configs,
                mgmt_allowed,
                probe_addrs,
                probe_protocol,
                upstream_policy,
                bootstrap_interfaces,
            },
        );

        let queue_config = NodeQueueConfig {
            destination_type_names,
            ..queue_config_from(&rns_config, rpc_auth_key, link_mtu_discovery)
        };
        let mut node = Self::start_with_queue_config(
            node_config,
            callbacks,
            queue_config,
            interface_management,
            Some(identities),
        )?;
        node.adopt_known_destinations(
            &known_destinations_path,
            known_destinations_store,
            known_destinations,
            &paths.storage,
        );
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
            None,
        )
    }

    /// Start the node from `config`, with `identities` when startup created
    /// them already, else with ones made from `config`.
    fn start_with_queue_config(
        mut config: NodeConfig,
        callbacks: Box<dyn Callbacks>,
        queue_config: NodeQueueConfig,
        interface_management: Option<InterfaceManagementConfig>,
        identities: Option<NodeIdentities>,
    ) -> io::Result<Self> {
        let storage_dir = node_storage_dir(config.cache_dir.as_deref());
        create_state_dirs(config.cache_dir.as_deref(), storage_dir.as_deref())?;
        let transport_state_dir = if config.transport_enabled {
            storage_dir.clone()
        } else {
            None
        };
        let identities = match identities {
            Some(identities) => identities,
            None => NodeIdentities::new(
                config.identity.take(),
                config.transport_enabled,
                config.static_transport_identity,
            )?,
        };
        let rpc_auth_key = identities.rpc_auth_key(&config, &queue_config)?;
        let NodeIdentities {
            identity,
            transport_identity,
            application_identity,
        } = identities;
        let transport_config = transport_config(&config, &queue_config, transport_identity.hash());

        let (tx, rx) = event::try_channel_with_queue_capacities(
            config.driver_event_queue_capacity,
            queue_config.inbound_capacities,
        )?;
        let (mut driver, handles) =
            new_driver(&config, &queue_config, transport_config, rx, &tx, callbacks);
        let network_identity = config.network_identity.take();
        // The transport identity is the driver's before any interface
        // starts (upstream 25cce0a8 `Transport.ensure_identity()` before the
        // interfaces): a client that connects during startup sends its
        // tunnel synthesis, signed by it, from its first connect event, and
        // the driver handles no interface event before the node's threads
        // are spawned below.
        let probe_server = configure_driver_services(
            &mut driver,
            &config,
            &tx,
            transport_identity,
            network_identity,
        );

        // Shared counter for dynamic interface IDs
        let next_dynamic_id = Arc::new(AtomicU64::new(10000));
        driver.registry.next_dynamic_id = Arc::clone(&next_dynamic_id);
        let interfaces = std::mem::take(&mut config.interfaces);
        let registry = config.registry.take();
        let mut started = start_interfaces(
            &mut driver,
            &tx,
            &next_dynamic_id,
            &config,
            interfaces,
            registry,
            interface_management,
        )?;
        start_interface_announcer(
            &mut driver,
            &identity,
            std::mem::take(&mut started.discoverable),
        );
        open_discovery_storage(&mut driver, &config);

        // Restore after static interfaces and the announce cache are available,
        // but before the driver can process inbound traffic. Upstream logs
        // the tables it loaded after its management destinations' notices,
        // so the lines follow those below.
        let restored_tables = restore_transport_state(&mut driver, transport_state_dir.as_deref());
        configure_autoconnect(
            &mut driver,
            &config,
            #[cfg(feature = "iface-backbone")]
            started,
        );
        enable_builtin_destinations(
            &mut driver,
            &config,
            restored_tables,
            transport_state_dir.as_deref(),
        );

        spawn_timer(&tx, &handles.tick_interval_ms)?;
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
        let rpc_servers = start_rpc_servers(&mut driver, &config, rpc_auth_key, &tx);

        let threads = spawn_node_threads(driver, &tx, transport_state_dir.clone())?;

        let mut node = RnsNode {
            tx,
            driver_handle: Some(threads.driver),
            verify_handle: threads.verify,
            verify_shutdown: threads.verify_shutdown,
            persist_handle: threads.persist,
            persist_stop: threads.persist_stop,
            kd_flush_handle: None,
            kd_flush_stop: None,
            rpc_server: rpc_servers.tcp,
            #[cfg(target_os = "linux")]
            rpc_unix_server: rpc_servers.unix,
            tick_interval_ms: handles.tick_interval_ms,
            next_send_ticket: AtomicU64::new(0),
            encrypt_deferred_inline: std::thread::available_parallelism()
                .map_or(true, |cpus| cpus.get() == 1),
            accepting_work: handles.accepting_work,
            _probe_server: probe_server,
            known_destinations_path: None,
            known_destinations_store: None,
            stamp_store: None,
            stamp_destinations: handles.stamp_destinations,
            stamp_targets: handles.stamp_targets,
            stamper: Some(handles.stamper),
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
        node.finish_start(storage_dir, config.discover_interfaces);
        Ok(node)
    }
}
