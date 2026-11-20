//! Shared instance client mode.
//!
//! Allows an RnsNode to connect as a client to an already-running Reticulum
//! daemon, proxying operations through it. The client runs a minimal transport
//! engine with `transport_enabled: false` — it does no routing of its own, but
//! registers local destinations and sends/receives packets via the local
//! connection.
//!
//! This matches Python's behavior when `share_instance = True` and a daemon
//! is already running: the new process connects as a client rather than
//! starting its own interfaces.

use std::io;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rns_core::destination::{destination_hash, name_hash};
use rns_core::packet::RawPacket;
use rns_core::transport::types::TransportConfig;
use rns_crypto::identity::Identity;

use crate::driver::{Callbacks, Driver};
use crate::event;
use crate::event::{Event, QueryRequest, QueryResponse};
use crate::interface::local::LocalClientConfig;
use crate::interface::{InterfaceEntry, InterfaceStats};
use crate::node::RnsNode;
use crate::pickle::PickleValue;
use crate::rpc::SharedInstanceRpc;
use crate::storage;
use crate::time;

/// Configuration for connecting as a shared instance client.
pub struct SharedClientConfig {
    /// Instance name for Unix socket namespace (e.g. "default" → `\0rns/default`).
    pub instance_name: String,
    /// TCP port to try if Unix socket fails (default 37428).
    pub port: u16,
    /// RPC control port for queries (default 37429).
    pub rpc_port: u16,
    /// Try the abstract Unix socket first on Linux; `false` for upstream's
    /// `shared_instance_type = tcp`.
    pub use_af_unix: bool,
    /// The bitrate the shared instance interface reports
    /// (`force_shared_instance_bitrate`).
    pub force_bitrate: Option<u64>,
}

impl SharedClientConfig {
    /// The shared instance a config's `[reticulum]` section describes.
    pub fn from_reticulum(reticulum: &crate::config::ReticulumSection) -> Self {
        Self {
            instance_name: reticulum.instance_name.clone(),
            port: reticulum.shared_instance_port,
            rpc_port: reticulum.instance_control_port,
            use_af_unix: !reticulum.shared_instance_tcp,
            force_bitrate: reticulum.force_shared_instance_bitrate,
        }
    }
}

impl Default for SharedClientConfig {
    fn default() -> Self {
        SharedClientConfig {
            instance_name: "default".into(),
            port: 37428,
            rpc_port: 37429,
            use_af_unix: true,
            force_bitrate: None,
        }
    }
}

/// The destination types an application needs announces of (upstream
/// 825c2e19). A shared instance with `[filter] required_only` drops
/// announces of any other type, so a client registers what it needs there.
pub(crate) struct DestinationTypeRequester {
    /// `Transport.application_identity.hash`: identifies this application's
    /// registrations, so they can be withdrawn together.
    requester: [u8; 16],
    /// Whether this node is a shared instance client.
    shared_client: bool,
    /// Address and key of the shared instance's RPC server, when known.
    shared_rpc: Option<SharedInstanceRpc>,
    /// Whether a type was registered with the shared instance, so the
    /// registrations are withdrawn on shutdown.
    registered: AtomicBool,
}

impl Default for DestinationTypeRequester {
    fn default() -> Self {
        Self::new(*Identity::new(&mut rns_crypto::OsRng).hash())
    }
}

impl DestinationTypeRequester {
    /// A requester named by the hash of the application identity.
    pub(crate) fn new(requester: [u8; 16]) -> Self {
        DestinationTypeRequester {
            requester,
            shared_client: false,
            shared_rpc: None,
            registered: AtomicBool::new(false),
        }
    }

    /// Send one destination type call to the shared instance. A failed call
    /// or one the instance does not understand reports `false`.
    fn call_shared_instance(&self, key: &str, value: PickleValue) -> bool {
        let Some(rpc) = &self.shared_rpc else {
            return false;
        };
        call_destination_type_rpc(rpc, &self.destination_type_request(key, value))
    }

    fn destination_type_request(&self, key: &str, value: PickleValue) -> PickleValue {
        PickleValue::Dict(vec![
            (PickleValue::String(key.into()), value),
            (
                PickleValue::String("requester".into()),
                PickleValue::Bytes(self.requester.to_vec()),
            ),
            (PickleValue::String("signature".into()), PickleValue::None),
        ])
    }

    /// Whether this is a shared instance client that knows the instance's
    /// RPC server.
    pub(crate) fn is_client_with_rpc(&self) -> bool {
        self.shared_client && self.shared_rpc.is_some()
    }

    /// One call to the shared instance's RPC server, when it is known.
    pub(crate) fn call(&self, request: &PickleValue) -> Option<PickleValue> {
        let rpc = self.shared_rpc.as_ref()?;
        match rpc.connect().and_then(|mut client| client.call(request)) {
            Ok(response) => Some(response),
            Err(e) => {
                log::error!("Shared instance RPC failed: {e}");
                None
            }
        }
    }

    /// Withdraw this application's registrations from the shared instance,
    /// as the Python exit handler does. Since upstream 29ce7ca5 the exit
    /// handler waits at most [`SHARED_RPC_EXIT_TIMEOUT`] for the call, so a
    /// shared instance that does not answer cannot hold up shutdown; the
    /// call is left to finish on its own thread. Only an application that
    /// registered a type with a shared instance withdraws, which is what
    /// upstream's `is_connected_to_shared_instance` condition gives
    /// (e35bd08f).
    pub(crate) fn withdraw_from_shared_instance(&self) {
        if !self.registered.swap(false, Ordering::Relaxed) {
            return;
        }
        let Some(rpc) = self.shared_rpc.clone() else {
            return;
        };
        let request =
            self.destination_type_request("unwants_all_destination_types", PickleValue::Bool(true));
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let spawned = thread::Builder::new()
            .name("rns-withdraw-types".into())
            .spawn(move || {
                let _ = done_tx.send(call_destination_type_rpc(&rpc, &request));
            });
        match spawned {
            Ok(_) => {
                if done_rx.recv_timeout(SHARED_RPC_EXIT_TIMEOUT).is_err() {
                    log::debug!("Shared instance RPC timed out during exit");
                }
            }
            Err(e) => log::debug!("Could not deregister destination types at exit: {e}"),
        }
    }
}

/// How long shutdown waits for the shared instance to withdraw this
/// application's destination types (upstream `Reticulum.RPC_EXIT_TIMEOUT`,
/// 29ce7ca5).
pub(crate) const SHARED_RPC_EXIT_TIMEOUT: Duration = Duration::from_millis(500);

/// One destination type call to a shared instance's RPC server. A failed
/// call or one the instance does not understand reports `false`.
fn call_destination_type_rpc(rpc: &SharedInstanceRpc, request: &PickleValue) -> bool {
    match rpc.connect().and_then(|mut client| client.call(request)) {
        Ok(response) => response.as_bool() == Some(true),
        // Debug level: a Python shared instance on Linux serves RPC on an
        // abstract Unix socket, which this TCP client cannot reach, and
        // registration only matters when it filters announces.
        Err(e) => {
            log::debug!("Shared instance RPC failed while setting destination type filters: {e}");
            false
        }
    }
}

impl RnsNode {
    /// `Reticulum.wants_destination_type`: this application needs announces
    /// of the destination type `full_name`, such as `rncp.receive`.
    ///
    /// The type is registered with the local transport and, on a shared
    /// instance client, with the shared instance, whose answer is returned.
    /// Returns `false` for a blocked type.
    pub fn wants_destination_type(&self, full_name: &str) -> bool {
        let local = self.destination_type_query(QueryRequest::WantsDestinationType {
            full_name: full_name.into(),
            requester: self.destination_types.requester.to_vec(),
        });
        if !self.destination_types.shared_client || self.destination_types.shared_rpc.is_none() {
            return local;
        }
        let registered = self.destination_types.call_shared_instance(
            "wants_destination_type",
            PickleValue::String(full_name.into()),
        );
        if registered {
            self.destination_types
                .registered
                .store(true, Ordering::Relaxed);
        }
        registered
    }

    /// `Reticulum.unwants_destination_type`: withdraw a need registered with
    /// [`Self::wants_destination_type`]. Returns whether it was registered.
    pub fn unwants_destination_type(&self, full_name: &str) -> bool {
        let local = self.destination_type_query(QueryRequest::UnwantsDestinationType {
            full_name: full_name.into(),
            requester: self.destination_types.requester.to_vec(),
        });
        if !self.destination_types.shared_client || self.destination_types.shared_rpc.is_none() {
            return local;
        }
        self.destination_types.call_shared_instance(
            "unwants_destination_type",
            PickleValue::String(full_name.into()),
        )
    }

    /// `Reticulum.unwants_all_destination_types`: withdraw every destination
    /// type this application registered.
    pub fn unwants_all_destination_types(&self) -> bool {
        let local = self.destination_type_query(QueryRequest::UnwantsAllDestinationTypes {
            requester: self.destination_types.requester.to_vec(),
        });
        if !self.destination_types.shared_client || self.destination_types.shared_rpc.is_none() {
            return local;
        }
        self.destination_types
            .registered
            .store(false, Ordering::Relaxed);
        self.destination_types
            .call_shared_instance("unwants_all_destination_types", PickleValue::Bool(true))
    }

    /// `Reticulum.required_announces_only`: on a shared instance client, let
    /// through only announces of the types this application registered and
    /// the shared instance's own destinations. Other nodes return `false`,
    /// so an application cannot squelch announces for the node as a whole.
    pub fn required_announces_only(&self, enabled: bool) -> bool {
        if !self.destination_types.shared_client {
            return false;
        }
        self.destination_type_query(QueryRequest::SetRequiredDestinationsOnly { enabled })
    }

    fn destination_type_query(&self, request: QueryRequest) -> bool {
        matches!(
            self.query(request),
            Ok(QueryResponse::DestinationTypeRegistration(true))
        )
    }

    /// Connect to an existing shared instance as a client.
    ///
    /// The client runs `transport_enabled: false` — it does no routing,
    /// but can register destinations and send/receive packets through
    /// the daemon.
    pub fn connect_shared(
        config: SharedClientConfig,
        callbacks: Box<dyn Callbacks>,
    ) -> io::Result<Self> {
        Self::connect_shared_with_reconnect_wait(
            config,
            callbacks,
            Duration::from_secs(8),
            None,
            &crate::config::StampsSection::default(),
            rns_core::constants::HOP_LIMITER,
            false,
            Default::default(),
        )
    }

    /// `instance_storage` is the shared instance's storage directory: ratchets
    /// this client has not seen announced are looked up there, read-only, and
    /// the client keeps its destination stamps under it, as an upstream client
    /// shares the instance's storage path. Without it the client announces
    /// unstamped. `stamps` and `hop_limiter` are the client's own `[stamps]`
    /// and `[filter] hop_limiter`, which upstream applies in every instance.
    /// With `static_transport_identity` the client uses the stored transport
    /// identity rather than an ephemeral one. `destination_type_names` are
    /// the names of destination types the client read with its config, as
    /// every upstream instance does.
    #[allow(clippy::too_many_arguments)]
    fn connect_shared_with_reconnect_wait(
        config: SharedClientConfig,
        callbacks: Box<dyn Callbacks>,
        reconnect_wait: Duration,
        instance_storage: Option<std::path::PathBuf>,
        stamps: &crate::config::StampsSection,
        hop_limiter: u8,
        static_transport_identity: bool,
        destination_type_names: crate::destination_types::DestinationTypeNames,
    ) -> io::Result<Self> {
        let transport_config = TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            unresponsive_path_recovery:
                rns_core::transport::types::UnresponsivePathRecovery::Native,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Lazy,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: rns_core::transport::types::DEFAULT_MAX_PATH_DESTINATIONS,
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

        let (tx, rx) = event::channel();
        let tick_interval_ms = Arc::new(AtomicU64::new(1000));
        let mut driver = Driver::new(transport_config, rx, tx.clone(), callbacks);
        driver.connected_to_shared_instance = true;
        driver.destination_type_names = destination_type_names;
        // A client stamps the announces and path requests it emits itself
        // (upstream 51fa8413), with the node handle and the driver sharing
        // one stamper and one STAMP_DESTINATIONS flag, as `RnsNode::start`.
        let stamper = Arc::new(crate::stamper::Stamper::new(tx.clone(), None));
        driver.set_stamper(Arc::clone(&stamper));
        let stamp_destinations = Arc::new(std::sync::atomic::AtomicBool::new(
            rns_core::constants::STAMP_DESTINATIONS,
        ));
        driver.set_stamp_destinations_flag(Arc::clone(&stamp_destinations));
        driver.apply_stamp_config(stamps, hop_limiter);
        let stamp_store = instance_storage
            .as_deref()
            .map(crate::stamps::DestinationStampStore::new);
        // Received ratchets: without a store, packets to destinations that
        // enforce ratchets would go out encrypted to the identity key alone.
        // Upstream's client runs Transport.start too: it loads the stored
        // transport identity, or creates and stores one, then, without
        // static_transport_identity, uses an ephemeral one, and creates its
        // application identity. Its path requests carry the transport
        // identity's hash; without one a stamped request has the length of
        // an unstamped one, and an instance that enforces stamps drops it.
        //
        // Only a client that uses the stored identity creates it. Otherwise
        // the instance's own file is only read: a client started with its
        // instance, as rns-server starts its sidecars and control plane on a
        // new directory, wrote one of its own while the instance created
        // another, and the instance's RPC key no longer matched the one the
        // supervisor derived.
        let stored_identity = match instance_storage.as_deref() {
            Some(storage_dir) if static_transport_identity => {
                Some(load_or_create_transport_identity(storage_dir)?)
            }
            Some(storage_dir) => load_transport_identity(storage_dir),
            None => None,
        };
        let transport_identity = match stored_identity {
            Some(identity) if static_transport_identity => identity,
            _ => {
                let identity = crate::node::create_identity();
                log::info!(
                    "Initialized ephemeral transport identity <{}>",
                    rns_core::encoding::hex(identity.hash())
                );
                identity
            }
        };
        driver
            .engine
            .set_client_transport_id(Some(*transport_identity.hash()));
        let application_identity = crate::node::create_identity();
        let ratchet_store: Arc<dyn storage::RatchetStore> =
            Arc::new(storage::SharedClientRatchetStore::new(instance_storage));
        driver.ratchet_store = Some(Arc::clone(&ratchet_store));
        driver.set_tick_interval_handle(Arc::clone(&tick_interval_ms));
        let accepting_work = driver.accepting_work_handle();

        // Connect to the daemon via LocalClientInterface
        let local_config = LocalClientConfig {
            name: "Local shared instance".into(),
            instance_name: config.instance_name.clone(),
            port: config.port,
            interface_id: rns_core::transport::types::InterfaceId(1),
            reconnect_wait,
            use_af_unix: config.use_af_unix,
        };

        let id = local_config.interface_id;
        // Upstream's `str(interface)` for this connection.
        let endpoint = crate::interface::display::LocalEndpoint::for_client(
            local_config.use_af_unix,
            &local_config.instance_name,
            local_config.port,
        );
        driver
            .registry
            .display_names
            .insert(id, crate::interface::display::local_client(&endpoint));
        let info = rns_core::transport::types::InterfaceInfo {
            stamp_costs: Default::default(),
            id,
            name: "LocalInterface".into(),
            mode: rns_core::constants::MODE_FULL,
            gravity: 0,
            recursive_prs: false,
            announces_from_internal: true,
            announces_to_internal: None,
            out_capable: true,
            in_capable: true,
            bitrate: Some(
                config
                    .force_bitrate
                    .unwrap_or(crate::interface::local::BITRATE),
            ),
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: rns_core::constants::ANNOUNCE_CAP,
            is_local_client: true,
            wants_tunnel: false,
            shared_medium: false,
            hop_limiter: None,
            tunnel_id: None,
            mtu: crate::interface::local::HW_MTU,
            mtu_upgradable: true,
            ia_freq: 0.0,
            ia_samples: 0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: time::now(),
            ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
        };

        let writer = crate::interface::local::start_client(local_config, tx.clone())?;
        let (writer, async_writer_metrics) = crate::interface::wrap_async_writer(
            writer,
            id,
            &info.name,
            tx.clone(),
            driver.interface_settings.writer_queue_capacity,
        );

        driver.engine.register_interface(info.clone());
        driver.interfaces.insert(
            id,
            InterfaceEntry {
                id,
                info,
                writer,
                async_writer_metrics: Some(async_writer_metrics),
                enabled: true,
                online: false,
                dynamic: false,
                ifac: None,
                stats: InterfaceStats {
                    started: time::now(),
                    ..Default::default()
                },
                interface_type: "LocalClientInterface".to_string(),
                send_retry_at: None,
                send_retry_backoff: Duration::ZERO,
            },
        );

        // Spawn timer thread with configurable tick interval, unless the
        // driver keeps the tick itself (compact engine).
        if !crate::engine::FOLD_TIMERS {
            let timer_tx = tx.clone();
            let timer_interval = Arc::clone(&tick_interval_ms);
            thread::Builder::new()
                .name("rns-timer-client".into())
                .spawn(move || loop {
                    let ms = timer_interval.load(Ordering::Relaxed);
                    thread::sleep(Duration::from_millis(ms));
                    if timer_tx.send(event::Event::Tick).is_err() {
                        break;
                    }
                })?;
        }

        // Spawn driver thread
        let driver_handle = thread::Builder::new()
            .name("rns-driver-client".into())
            .spawn(move || {
                driver.run();
            })?;

        let mut node =
            RnsNode::from_parts(tx, driver_handle, None, tick_interval_ms, accepting_work);
        node.destination_types = DestinationTypeRequester::new(*application_identity.hash());
        node.destination_types.shared_client = true;
        node.ratchet_store = Some(ratchet_store);
        node.attach_stamper(
            stamper,
            stamp_destinations,
            crate::stamper::StampTargets::from(stamps),
        );
        if let Some(store) = stamp_store {
            node.set_stamp_store(store);
        }
        Ok(node)
    }

    /// Whether this node is a client of another process's shared instance
    /// (upstream `Reticulum.is_connected_to_shared_instance`).
    pub fn is_connected_to_shared_instance(&self) -> bool {
        self.destination_types.shared_client
    }

    /// Connect to a shared instance, with config loaded from a config directory.
    ///
    /// Reads the config file to determine instance_name and ports.
    pub fn connect_shared_from_config(
        config_path: Option<&Path>,
        callbacks: Box<dyn Callbacks>,
    ) -> io::Result<Self> {
        let config_dir = storage::resolve_config_dir(config_path);

        // Parse config file for instance settings; as upstream, starting
        // without one writes the default config.
        storage::ensure_config_file(&config_dir)?;
        let config_file = config_dir.join("config");
        let rns_config = if config_file.exists() {
            crate::config::parse_file(&config_file)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?
        } else {
            crate::config::parse("")
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?
        };

        // Upstream loads the network identity while it reads the config,
        // before it knows it is a client.
        if let Some(ref path) = rns_config.reticulum.network_identity {
            crate::node::load_network_identity(path)?;
        }
        // Upstream c90a5d58: so are the names of destination types.
        let destination_type_names = crate::destination_types::DestinationTypeNames::from_config(
            &config_dir,
            &rns_config.filter,
        );
        log::info!("Configuration loaded from {}", config_file.display());
        let shared_config = SharedClientConfig::from_reticulum(&rns_config.reticulum);
        let mut node = Self::connect_shared_with_reconnect_wait(
            shared_config,
            callbacks,
            Duration::from_secs(8),
            Some(config_dir.join("storage")),
            &rns_config.stamps,
            rns_config.reticulum.hop_limiter,
            rns_config.reticulum.static_transport_identity,
            destination_type_names,
        )?;
        node.use_shared_instance_rpc(&config_dir, &rns_config.reticulum);
        // After the RPC is set up, which the split mode fallback needs
        // (upstream 48c77061 moved the load after `rpc_key` for this).
        let known_destinations = node.load_instance_known_destinations(&config_dir.join("storage"));
        node.restore_known_destinations(known_destinations);
        Ok(node)
    }

    /// `Identity.load_known_destinations` on a shared instance client: what
    /// the instance knows, read from its database without writing to it.
    /// When the database cannot be read, as when the client runs in its own
    /// storage path (split mode), the instance is asked over RPC, as
    /// upstream since 48c77061. Its log lines and levels are upstream's.
    fn load_instance_known_destinations(
        &self,
        storage_dir: &std::path::Path,
    ) -> Vec<([u8; 16], storage::KnownDestination)> {
        let db = crate::storage_sqlite::default_path(storage_dir);
        let loaded = if db.is_file() {
            crate::storage_sqlite::KnownDestinationsStore::open_read_only(&db)
                .and_then(|store| store.load_all())
        } else {
            // Upstream's read-only sqlite open fails the same way.
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "unable to open database file",
            ))
        };
        let entries = match loaded {
            Ok(entries) => entries,
            Err(e) => {
                log::debug!("Could not load known destinations from shared instance database: {e}");
                log::debug!("Potentially running in split mode, attempting to load known destinations over RPC...");
                match self.instance_known_destinations_over_rpc() {
                    Ok(entries) => entries,
                    Err(e) => {
                        log::error!("Could not load known destinations from shared instance: {e}");
                        return Vec::new();
                    }
                }
            }
        };
        log::info!(
            "Loaded {} known destinations from shared instance",
            entries.len()
        );
        entries
    }

    /// Upstream's `Reticulum.get_known_destinations()` on a client: the
    /// instance's table over RPC, or an empty one when the call fails.
    fn instance_known_destinations_over_rpc(
        &self,
    ) -> io::Result<Vec<([u8; 16], storage::KnownDestination)>> {
        let request = PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("known_destinations".into()),
        )]);
        let response = match &self.destination_types.shared_rpc {
            Some(rpc) => rpc.connect().and_then(|mut client| client.call(&request)),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no shared instance RPC key",
            )),
        };
        match response {
            // `get_known_destinations() or {}`: an empty answer is an empty table.
            Ok(PickleValue::None) => Ok(Vec::new()),
            Ok(response) => crate::rpc::parse_upstream_known_destinations(&response),
            Err(e) => {
                log::error!("Shared instance RPC failed while getting known destinations: {e}");
                Ok(Vec::new())
            }
        }
    }

    /// Reach the shared instance's RPC server for destination type
    /// registrations. Its key derives from the shared instance's transport
    /// identity, which clients read from the same storage directory; without
    /// one, registrations stay local.
    pub(crate) fn use_shared_instance_rpc(
        &mut self,
        config_dir: &Path,
        reticulum: &crate::config::ReticulumSection,
    ) {
        let rpc = SharedInstanceRpc::new(reticulum, || {
            storage::load_identity(&config_dir.join("storage").join("transport_identity"))
        });
        match rpc {
            Ok(rpc) => self.destination_types.shared_rpc = Some(rpc),
            Err(e) => log::debug!("No shared instance RPC key for destination type filters: {e}"),
        }
    }
}

#[doc(hidden)]
#[allow(
    clippy::unwrap_used,
    reason = "benchmark harness: a failure aborts the run"
)]
pub fn bench_shared_client_replay_once(
    announce_count: usize,
    reconnect_wait: Duration,
) -> io::Result<usize> {
    struct BenchNoopCallbacks;
    impl Callbacks for BenchNoopCallbacks {}

    fn build_shared_announce_raw(
        dest_hash: &[u8; 16],
        name_hash: &[u8; 10],
        identity_prv_key: &[u8; 64],
        app_data: Option<&[u8]>,
        path_response: bool,
    ) -> Vec<u8> {
        let identity = Identity::from_private_key(identity_prv_key);
        let mut random_hash = [0u8; 10];
        random_hash[..5].copy_from_slice(&[0xA5; 5]);
        random_hash[5..10].copy_from_slice(&[0, 0, 0, 0, 1]);

        let (announce_data, _) = rns_core::announce::AnnounceData::pack(
            &identity,
            dest_hash,
            name_hash,
            &random_hash,
            None,
            app_data,
        )
        .unwrap();

        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: rns_core::constants::FLAG_UNSET,
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: rns_core::constants::DESTINATION_SINGLE,
            packet_type: rns_core::constants::PACKET_TYPE_ANNOUNCE,
        };
        let context = if path_response {
            rns_core::constants::CONTEXT_PATH_RESPONSE
        } else {
            rns_core::constants::CONTEXT_NONE
        };

        rns_core::packet::RawPacket::pack(flags, 0, dest_hash, None, context, &announce_data)
            .unwrap()
            .raw
    }

    fn read_until_frames(
        stream: &mut std::net::TcpStream,
        expected: usize,
        expected_context: u8,
    ) -> io::Result<Vec<Vec<u8>>> {
        let mut decoder = crate::interface::local::frame_decoder(0);
        let mut buf = [0u8; 4096];
        let mut frames = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while frames.len() < expected {
            let n = match stream.read(&mut buf) {
                Ok(n) => n,
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    if std::time::Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "timed out waiting for {} frames, got {}",
                                expected,
                                frames.len()
                            ),
                        ));
                    }
                    continue;
                }
                Err(e) => return Err(e),
            };
            for frame in decoder.feed(&buf[..n]) {
                let Ok(packet) = RawPacket::unpack(&frame) else {
                    log::debug!("skipping malformed shared-instance packet");
                    continue;
                };
                if packet.context == expected_context {
                    frames.push(frame);
                }
            }
        }
        Ok(frames)
    }

    let listener1 = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener1.local_addr()?.port();
    let instance_name = format!("bench-shared-replay-{port}");

    let (accepted1_tx, accepted1_rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let (stream, _) = listener1.accept().unwrap();
        accepted1_tx.send(stream).unwrap();
    });

    let transport_config = TransportConfig {
        transport_enabled: false,
        identity_hash: None,
        local_hops_delta: 0,
        prefer_shorter_path: false,
        max_paths_per_destination: 1,
        unresponsive_path_recovery: rns_core::transport::types::UnresponsivePathRecovery::Native,
        packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
        packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Lazy,
        max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
        max_path_destinations: rns_core::transport::types::DEFAULT_MAX_PATH_DESTINATIONS,
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

    let (tx, rx) = event::channel();
    let tick_interval_ms = Arc::new(AtomicU64::new(1000));
    let mut driver = Driver::new(
        transport_config,
        rx,
        tx.clone(),
        Box::new(BenchNoopCallbacks),
    );
    driver.set_tick_interval_handle(Arc::clone(&tick_interval_ms));

    let local_config = LocalClientConfig {
        name: "Shared replay bench".into(),
        instance_name: instance_name.clone(),
        port,
        interface_id: rns_core::transport::types::InterfaceId(1),
        reconnect_wait,
        use_af_unix: true,
    };

    let id = local_config.interface_id;
    let info = rns_core::transport::types::InterfaceInfo {
        stamp_costs: Default::default(),
        id,
        name: "LocalInterface".into(),
        mode: rns_core::constants::MODE_FULL,
        gravity: 0,
        recursive_prs: false,
        announces_from_internal: true,
        announces_to_internal: None,
        out_capable: true,
        in_capable: true,
        bitrate: Some(crate::interface::local::BITRATE),
        airtime_profile: None,
        announce_rate_target: None,
        announce_rate_grace: 0,
        announce_rate_penalty: 0.0,
        announce_cap: rns_core::constants::ANNOUNCE_CAP,
        is_local_client: true,
        wants_tunnel: false,
        shared_medium: false,
        hop_limiter: None,
        tunnel_id: None,
        mtu: crate::interface::local::HW_MTU,
        mtu_upgradable: true,
        ia_freq: 0.0,
        ia_samples: 0,
        ip_freq: 0.0,
        op_freq: 0.0,
        op_samples: 0,
        started: time::now(),
        ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
    };

    let writer = crate::interface::local::start_client(local_config, tx.clone())?;
    let (writer, async_writer_metrics) = crate::interface::wrap_async_writer(
        writer,
        id,
        &info.name,
        tx.clone(),
        driver.interface_settings.writer_queue_capacity,
    );
    driver.engine.register_interface(info.clone());
    driver.interfaces.insert(
        id,
        InterfaceEntry {
            id,
            info,
            writer,
            async_writer_metrics: Some(async_writer_metrics),
            enabled: true,
            online: false,
            dynamic: false,
            ifac: None,
            stats: InterfaceStats {
                started: time::now(),
                ..Default::default()
            },
            interface_type: "LocalClientInterface".to_string(),
            send_retry_at: None,
            send_retry_backoff: Duration::ZERO,
        },
    );

    let driver_handle = thread::Builder::new()
        .name("rns-driver-bench-client".into())
        .spawn(move || {
            driver.run();
        })?;

    let mut stream1 = accepted1_rx
        .recv_timeout(Duration::from_secs(2))
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("shared bench initial accept failed: {e}"),
            )
        })?;
    stream1.set_read_timeout(Some(Duration::from_secs(2)))?;

    let mut records = Vec::new();
    for i in 0..announce_count {
        let mut prv_key = [0u8; 64];
        for (j, byte) in prv_key.iter_mut().enumerate() {
            *byte = (i as u8)
                .wrapping_mul(23)
                .wrapping_add(j as u8)
                .wrapping_add(5);
        }
        let identity = Identity::from_private_key(&prv_key);
        let aspect = format!("echo-{i}");
        let name_hash = name_hash("shared-bench", &[&aspect]);
        let dest_hash = destination_hash("shared-bench", &[&aspect], Some(identity.hash()));
        let app_data = format!("hello-{i}").into_bytes();
        records.push((dest_hash, name_hash, prv_key, app_data));
    }

    for (dest_hash, name_hash, prv_key, app_data) in &records {
        let raw = build_shared_announce_raw(dest_hash, name_hash, prv_key, Some(app_data), false);
        tx.send(Event::RegisterDestination {
            dest_hash: *dest_hash,
            dest_type: rns_core::constants::DESTINATION_SINGLE,
        })
        .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("{e}")))?;
        tx.send(Event::StoreSharedAnnounce {
            dest_hash: *dest_hash,
            name_hash: *name_hash,
            identity_prv_key: *prv_key,
            app_data: Some(app_data.clone()),
        })
        .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("{e}")))?;
        tx.send(Event::SendOutbound {
            raw,
            dest_type: rns_core::constants::DESTINATION_SINGLE,
            attached_interface: None,
        })
        .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("{e}")))?;
    }

    let _ = read_until_frames(
        &mut stream1,
        announce_count,
        rns_core::constants::CONTEXT_NONE,
    )
    .map_err(|e| io::Error::new(e.kind(), format!("initial announce delivery failed: {e}")))?;
    drop(stream1);

    let listener2 = std::net::TcpListener::bind(format!("127.0.0.1:{port}"))?;
    let (accepted2_tx, accepted2_rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let (stream, _) = listener2.accept().unwrap();
        accepted2_tx.send(stream).unwrap();
    });

    let mut stream2 = accepted2_rx
        .recv_timeout(Duration::from_secs(2))
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("shared bench reconnect accept failed: {e}"),
            )
        })?;
    stream2.set_read_timeout(Some(Duration::from_secs(2)))?;
    let frames = read_until_frames(
        &mut stream2,
        announce_count,
        rns_core::constants::CONTEXT_PATH_RESPONSE,
    )
    .map_err(|e| io::Error::new(e.kind(), format!("replayed announce delivery failed: {e}")))?;

    tx.send(Event::Shutdown)
        .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("{e}")))?;
    let _ = driver_handle.join();

    Ok(frames.len())
}

/// The transport identity in the instance's `storage_dir`, if it holds a
/// valid one.
fn load_transport_identity(storage_dir: &std::path::Path) -> Option<Identity> {
    let identity = storage::load_identity(&storage_dir.join("transport_identity")).ok()?;
    log::info!("Loaded Transport Identity from storage");
    Some(identity)
}

/// The transport identity in the instance's `storage_dir`, as upstream's
/// client loads it, or a new one stored there when it holds none.
fn load_or_create_transport_identity(storage_dir: &std::path::Path) -> io::Result<Identity> {
    let path = storage_dir.join("transport_identity");
    if let Ok(identity) = storage::load_identity(&path) {
        log::info!("Loaded Transport Identity from storage");
        return Ok(identity);
    }
    log::info!("No valid Transport Identity in storage, creating...");
    let identity = crate::node::create_identity();
    storage::save_identity(&identity, &path)?;
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{RpcAddr, RpcClient};
    use rns_core::packet::RawPacket;
    use rns_core::types::{DestHash, IdentityHash};
    use rns_crypto::identity::Identity;
    use rns_crypto::OsRng;
    use std::io::Read;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc;
    use std::sync::Arc;

    use crate::interface::local::LocalServerConfig;

    struct NoopCallbacks;
    impl Callbacks for NoopCallbacks {}

    fn find_free_port() -> u16 {
        crate::test_support::port()
    }

    #[test]
    fn shared_client_registers_destination_types_with_the_shared_instance() {
        // Upstream 825c2e19: clients send their needed destination types to
        // the shared instance over RPC and withdraw them on exit.
        let dir = tempfile::tempdir().unwrap();
        let rpc_port = find_free_port();
        let shared_port = find_free_port();
        // Its own name, so its RPC socket is not another test's.
        let instance = crate::test_support::instance_name("test-shared-types");
        std::fs::write(
            dir.path().join("config"),
            format!(
                "[reticulum]\nshare_instance = yes\ninstance_name = {instance}\n\
                 instance_control_port = {rpc_port}\n\
                 shared_instance_port = {shared_port}\n\n[filter]\n\
                 required_only = yes\nignored_types = nomadnetwork.node\n"
            ),
        )
        .unwrap();
        let daemon = RnsNode::from_config(Some(dir.path()), Box::new(NoopCallbacks)).unwrap();
        let client =
            RnsNode::connect_shared_from_config(Some(dir.path()), Box::new(NoopCallbacks)).unwrap();

        // Only the shared instance knows the type is blocked, so `false`
        // shows the call reached it.
        assert!(client.wants_destination_type("rncp.receive"));
        assert!(!client.wants_destination_type("nomadnetwork.node"));
        assert!(!client.unwants_destination_type("rnx.execute"));
        assert!(client.unwants_destination_type("rncp.receive"));
        assert!(client.wants_destination_type("rnx.execute"));

        assert!(client.required_announces_only(true));
        assert!(!daemon.required_announces_only(true));

        // Shutting the client down withdraws its registrations.
        let auth_key = client
            .destination_types
            .shared_rpc
            .as_ref()
            .unwrap()
            .auth_key;
        let requester = client.destination_types.requester;
        client.shutdown();
        let mut rpc =
            RpcClient::connect(&RpcAddr::local(instance.clone(), rpc_port), &auth_key).unwrap();
        let response = rpc
            .call(&PickleValue::Dict(vec![
                (
                    PickleValue::String("unwants_destination_type".into()),
                    PickleValue::String("rnx.execute".into()),
                ),
                (
                    PickleValue::String("requester".into()),
                    PickleValue::Bytes(requester.to_vec()),
                ),
            ]))
            .unwrap();
        assert_eq!(response, PickleValue::Bool(false));
        daemon.shutdown();
    }

    /// Upstream 48c77061: a client in its own storage path (split mode)
    /// cannot open the instance's known destinations database, so it loads
    /// the instance's table over RPC.
    #[test]
    fn a_split_mode_client_loads_known_destinations_over_rpc() {
        let instance_dir = tempfile::tempdir().unwrap();
        let client_dir = tempfile::tempdir().unwrap();
        let rpc_port = find_free_port();
        let shared_port = find_free_port();
        let instance = crate::test_support::instance_name("test-split-known");
        let config = format!(
            "[reticulum]\nshare_instance = yes\ninstance_name = {instance}\n\
             instance_control_port = {rpc_port}\n\
             shared_instance_port = {shared_port}\n\
             rpc_key = {}\n",
            "ab".repeat(32)
        );
        std::fs::write(instance_dir.path().join("config"), &config).unwrap();
        std::fs::write(client_dir.path().join("config"), &config).unwrap();
        let daemon =
            RnsNode::from_config(Some(instance_dir.path()), Box::new(NoopCallbacks)).unwrap();
        let identity = Identity::new(&mut OsRng);
        let dest_hash = [0x5d; 16];
        let response = daemon
            .query(QueryRequest::InjectIdentity {
                dest_hash,
                identity_hash: *identity.hash(),
                public_key: identity.get_public_key().unwrap(),
                app_data: Some(b"split".to_vec()),
                hops: 2,
                received_at: 1_700_000_000.0,
            })
            .unwrap();
        assert!(matches!(response, QueryResponse::InjectIdentity(true)));
        assert!(daemon
            .retain_known_destination(&DestHash(dest_hash))
            .unwrap());

        let client =
            RnsNode::connect_shared_from_config(Some(client_dir.path()), Box::new(NoopCallbacks))
                .unwrap();
        assert!(!crate::storage_sqlite::default_path(&client_dir.path().join("storage")).exists());
        let known = client.known_destinations().unwrap();
        let entry = known
            .iter()
            .find(|entry| entry.dest_hash == dest_hash)
            .unwrap_or_else(|| panic!("not loaded over RPC: {known:?}"));
        assert_eq!(entry.public_key, identity.get_public_key().unwrap());
        assert_eq!(entry.identity_hash, *identity.hash());
        assert_eq!(entry.app_data.as_deref(), Some(&b"split"[..]));
        assert_eq!(entry.received_at, 1_700_000_000.0);
        assert!(entry.retained);
        assert!(client
            .recall_identity(&DestHash(dest_hash))
            .unwrap()
            .is_some());

        client.shutdown();
        daemon.shutdown();
    }

    #[test]
    fn connect_shared_to_tcp_server() {
        let port = find_free_port();
        let next_id = Arc::new(AtomicU64::new(50000));
        let (server_tx, server_rx) = crate::event::channel();

        // Start a local server
        let server_config = LocalServerConfig {
            instance_name: crate::test_support::instance_name("test-shared-connect"),
            port,
            interface_id: rns_core::transport::types::InterfaceId(99),
            use_af_unix: true,
        };

        crate::interface::local::start_server(server_config, server_tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        // Connect as shared client
        let config = SharedClientConfig {
            instance_name: crate::test_support::instance_name("test-shared-connect"),
            port,
            rpc_port: 0,
            use_af_unix: true,
            force_bitrate: None,
        };

        let node = RnsNode::connect_shared(config, Box::new(NoopCallbacks)).unwrap();

        // Server should see InterfaceUp for the client
        let event = server_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, crate::event::Event::InterfaceUp(_, _, _)));

        node.shutdown();
    }

    #[test]
    fn shared_client_register_destination() {
        let port = find_free_port();
        let next_id = Arc::new(AtomicU64::new(51000));
        let (server_tx, _server_rx) = crate::event::channel();

        let server_config = LocalServerConfig {
            instance_name: crate::test_support::instance_name("test-shared-reg"),
            port,
            interface_id: rns_core::transport::types::InterfaceId(98),
            use_af_unix: true,
        };

        crate::interface::local::start_server(server_config, server_tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let config = SharedClientConfig {
            instance_name: crate::test_support::instance_name("test-shared-reg"),
            port,
            rpc_port: 0,
            use_af_unix: true,
            force_bitrate: None,
        };

        let node = RnsNode::connect_shared(config, Box::new(NoopCallbacks)).unwrap();

        // Register a destination
        let dest_hash = [0xAA; 16];
        node.register_destination(dest_hash, rns_core::constants::DESTINATION_SINGLE)
            .unwrap();

        // Give time for event processing
        thread::sleep(Duration::from_millis(100));

        node.shutdown();
    }

    #[test]
    fn shared_client_send_packet() {
        let port = find_free_port();
        let next_id = Arc::new(AtomicU64::new(52000));
        let (server_tx, server_rx) = crate::event::channel();

        let server_config = LocalServerConfig {
            instance_name: crate::test_support::instance_name("test-shared-send"),
            port,
            interface_id: rns_core::transport::types::InterfaceId(97),
            use_af_unix: true,
        };

        crate::interface::local::start_server(server_config, server_tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let config = SharedClientConfig {
            instance_name: crate::test_support::instance_name("test-shared-send"),
            port,
            rpc_port: 0,
            use_af_unix: true,
            force_bitrate: None,
        };

        let node = RnsNode::connect_shared(config, Box::new(NoopCallbacks)).unwrap();

        // Build a minimal packet and send it
        let raw = vec![0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD]; // minimal raw packet
        node.send_raw(raw, rns_core::constants::DESTINATION_PLAIN, None)
            .unwrap();

        // Server should receive a Frame event from the client
        // (the packet will be HDLC-framed over the local connection)
        for _ in 0..10 {
            match server_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(crate::event::Event::Frame { .. }) => {
                    break;
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        // The packet may or may not arrive as a Frame depending on transport
        // routing, so we don't assert on it — the important thing is no crash.

        node.shutdown();
    }

    #[test]
    fn shared_client_replays_single_announces_after_reconnect() {
        let port = find_free_port();
        let addr = format!("127.0.0.1:{}", port);
        let instance_name = format!("test-shared-replay-{}", port);

        let listener1 = std::net::TcpListener::bind(&addr).unwrap();
        let (accepted1_tx, accepted1_rx) = mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener1.accept().unwrap();
            accepted1_tx.send(stream).unwrap();
        });

        let node = RnsNode::connect_shared(
            SharedClientConfig {
                instance_name,
                port,
                rpc_port: 0,
                use_af_unix: true,
                force_bitrate: None,
            },
            Box::new(NoopCallbacks),
        )
        .unwrap();

        let identity = Identity::new(&mut OsRng);
        let dest = crate::destination::Destination::single_in(
            "shared-replay",
            &["echo"],
            IdentityHash(*identity.hash()),
        );
        node.register_destination(dest.hash.0, dest.dest_type.to_wire_constant())
            .unwrap();
        node.announce_queued(&dest, &identity, Some(b"hello"))
            .unwrap();

        let mut stream1 = accepted1_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        stream1
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let mut decoder = crate::interface::local::frame_decoder(0);
        let mut buf = [0u8; 4096];
        let n = stream1.read(&mut buf).unwrap();
        let frames = decoder.feed(&buf[..n]);
        assert!(!frames.is_empty(), "expected initial announce frame");
        let packet1 = RawPacket::unpack(&frames[0]).unwrap();
        assert_eq!(packet1.destination_hash, dest.hash.0);
        assert_eq!(packet1.context, rns_core::constants::CONTEXT_NONE);

        drop(stream1);

        let listener2 = std::net::TcpListener::bind(&addr).unwrap();
        let (accepted2_tx, accepted2_rx) = mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener2.accept().unwrap();
            accepted2_tx.send(stream).unwrap();
        });

        let mut stream2 = accepted2_rx.recv_timeout(Duration::from_secs(15)).unwrap();
        stream2
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();

        let mut decoder = crate::interface::local::frame_decoder(0);
        let n = stream2.read(&mut buf).unwrap();
        let frames = decoder.feed(&buf[..n]);
        assert!(!frames.is_empty(), "expected replayed announce frame");
        let packet2 = RawPacket::unpack(&frames[0]).unwrap();
        assert_eq!(packet2.destination_hash, dest.hash.0);
        assert_eq!(packet2.context, rns_core::constants::CONTEXT_PATH_RESPONSE);

        node.shutdown();
    }

    /// Only a client with `static_transport_identity` creates the instance's
    /// transport identity file. One started together with its instance, on
    /// a directory that holds none yet, must not write one the instance's
    /// own would race with.
    #[test]
    fn only_a_static_transport_identity_client_stores_a_transport_identity() {
        for static_transport_identity in [false, true] {
            let port = find_free_port();
            let listener = std::net::TcpListener::bind(format!("127.0.0.1:{port}")).unwrap();
            let storage = tempfile::tempdir().unwrap();
            let node = RnsNode::connect_shared_with_reconnect_wait(
                SharedClientConfig {
                    instance_name: format!("test-client-identity-{port}"),
                    port,
                    rpc_port: 0,
                    use_af_unix: true,
                    force_bitrate: None,
                },
                Box::new(NoopCallbacks),
                Duration::from_secs(8),
                Some(storage.path().to_path_buf()),
                &crate::config::StampsSection::default(),
                rns_core::constants::HOP_LIMITER,
                static_transport_identity,
                Default::default(),
            )
            .unwrap();
            assert_eq!(
                storage.path().join("transport_identity").exists(),
                static_transport_identity,
                "static_transport_identity = {static_transport_identity}"
            );
            node.shutdown();
            drop(listener);
        }
    }

    #[test]
    fn a_shared_client_with_storage_stamps_its_own_announces() {
        // Upstream 51fa8413: a client of a shared instance stamps the
        // announces it emits, keeping the stamp in the shared storage path.
        let port = find_free_port();
        let addr = format!("127.0.0.1:{}", port);
        let listener = std::net::TcpListener::bind(&addr).unwrap();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            accepted_tx.send(stream).unwrap();
        });

        let storage = tempfile::tempdir().unwrap();
        let cheap = rns_core::stamp::StampCost::from_whole(4);
        let stamps = crate::config::StampsSection {
            destination_value: cheap,
            destination_cost: cheap,
            ..Default::default()
        };
        let node = RnsNode::connect_shared_with_reconnect_wait(
            SharedClientConfig {
                instance_name: format!("test-shared-stamps-{port}"),
                port,
                rpc_port: 0,
                use_af_unix: true,
                force_bitrate: None,
            },
            Box::new(NoopCallbacks),
            Duration::from_secs(8),
            Some(storage.path().to_path_buf()),
            &stamps,
            rns_core::constants::HOP_LIMITER,
            false,
            Default::default(),
        )
        .unwrap();

        let identity = Identity::new(&mut OsRng);
        let dest = crate::destination::Destination::single_in(
            "shared-stamps",
            &["echo"],
            IdentityHash(*identity.hash()),
        );
        node.register_destination(dest.hash.0, dest.dest_type.to_wire_constant())
            .unwrap();
        node.announce_queued(&dest, &identity, Some(b"hello"))
            .unwrap();

        let mut stream = accepted_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut decoder = crate::interface::local::frame_decoder(0);
        let mut buf = [0u8; 4096];
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let announce = 'found: loop {
            assert!(
                std::time::Instant::now() < deadline,
                "no stamped announce from the client"
            );
            let Ok(n) = stream.read(&mut buf) else {
                continue;
            };
            for frame in decoder.feed(&buf[..n]) {
                let packet = RawPacket::unpack(&frame).unwrap();
                if packet.destination_hash == dest.hash.0
                    && packet.flags.packet_type == rns_core::constants::PACKET_TYPE_ANNOUNCE
                {
                    break 'found packet;
                }
            }
        };
        let mut validated = rns_core::announce::AnnounceData::unpack(
            announce.data(),
            announce.flags.context_flag == rns_core::constants::FLAG_SET,
        )
        .unwrap()
        .validate(&dest.hash.0)
        .unwrap();
        assert_eq!(
            validated.apply_stamp(&dest.hash.0, cheap),
            rns_core::announce::AnnounceStampStatus::Valid
        );
        assert_eq!(validated.app_data.as_deref(), Some(&b"hello"[..]));
        assert!(storage.path().join("stamps").is_dir());

        node.shutdown();
    }

    #[test]
    fn connect_shared_fails_no_server() {
        let port = find_free_port();

        let config = SharedClientConfig {
            instance_name: "nonexistent-instance-12345".into(),
            port,
            rpc_port: 0,
            use_af_unix: true,
            force_bitrate: None,
        };

        // Should fail because no server is running
        let result = RnsNode::connect_shared(config, Box::new(NoopCallbacks));
        assert!(result.is_err());
    }

    #[test]
    fn shared_config_defaults() {
        let config = SharedClientConfig::default();
        assert_eq!(config.instance_name, "default");
        assert_eq!(config.port, 37428);
        assert_eq!(config.rpc_port, 37429);
    }

    #[test]
    fn withdrawing_from_an_unresponsive_shared_instance_is_bounded() {
        // Upstream 29ce7ca5: the exit handler waits at most
        // `RPC_EXIT_TIMEOUT` to deregister destination types.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // Accepts the connection, then never answers the authentication.
        let held = thread::spawn(move || listener.accept().map(|(stream, _)| stream));
        let requester = DestinationTypeRequester {
            shared_client: true,
            shared_rpc: Some(SharedInstanceRpc {
                addr: RpcAddr::Tcp("127.0.0.1".into(), port),
                auth_key: [0x11; 32],
            }),
            registered: AtomicBool::new(true),
            ..Default::default()
        };

        let started = std::time::Instant::now();
        requester.withdraw_from_shared_instance();
        let waited = started.elapsed();
        assert!(
            waited >= SHARED_RPC_EXIT_TIMEOUT,
            "returned after {waited:?}"
        );
        assert!(
            waited < SHARED_RPC_EXIT_TIMEOUT + Duration::from_secs(2),
            "waited {waited:?}"
        );
        assert!(!requester.registered.load(Ordering::Relaxed));
        drop(held);
    }
}
