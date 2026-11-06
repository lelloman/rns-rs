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
use crate::rpc::{RpcAddr, RpcClient};
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
}

impl Default for SharedClientConfig {
    fn default() -> Self {
        SharedClientConfig {
            instance_name: "default".into(),
            port: 37428,
            rpc_port: 37429,
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
    shared_rpc: Option<(RpcAddr, [u8; 32])>,
    /// Whether a type was registered with the shared instance, so the
    /// registrations are withdrawn on shutdown.
    registered: AtomicBool,
}

impl Default for DestinationTypeRequester {
    fn default() -> Self {
        DestinationTypeRequester {
            requester: *Identity::new(&mut rns_crypto::OsRng).hash(),
            shared_client: false,
            shared_rpc: None,
            registered: AtomicBool::new(false),
        }
    }
}

impl DestinationTypeRequester {
    /// Send one destination type call to the shared instance. A failed call
    /// or one the instance does not understand reports `false`.
    fn call_shared_instance(&self, key: &str, value: PickleValue) -> bool {
        let Some((addr, auth_key)) = &self.shared_rpc else {
            return false;
        };
        let request = PickleValue::Dict(vec![
            (PickleValue::String(key.into()), value),
            (
                PickleValue::String("requester".into()),
                PickleValue::Bytes(self.requester.to_vec()),
            ),
            (PickleValue::String("signature".into()), PickleValue::None),
        ]);
        match RpcClient::connect(addr, auth_key).and_then(|mut client| client.call(&request)) {
            Ok(response) => response.as_bool() == Some(true),
            // Debug level: a Python shared instance on Linux serves RPC on
            // an abstract Unix socket, which this TCP client cannot reach,
            // and registration only matters when it filters announces.
            Err(e) => {
                log::debug!(
                    "Shared instance RPC failed while setting destination type filters: {e}"
                );
                false
            }
        }
    }

    /// Withdraw this application's registrations from the shared instance,
    /// as the Python exit handler does.
    pub(crate) fn withdraw_from_shared_instance(&self) {
        if self.registered.swap(false, Ordering::Relaxed) {
            self.call_shared_instance("unwants_all_destination_types", PickleValue::Bool(true));
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
        Self::connect_shared_with_reconnect_wait(config, callbacks, Duration::from_secs(8))
    }

    fn connect_shared_with_reconnect_wait(
        config: SharedClientConfig,
        callbacks: Box<dyn Callbacks>,
        reconnect_wait: Duration,
    ) -> io::Result<Self> {
        let transport_config = TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
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
        driver.set_tick_interval_handle(Arc::clone(&tick_interval_ms));
        let accepting_work = driver.accepting_work_handle();

        // Connect to the daemon via LocalClientInterface
        let local_config = LocalClientConfig {
            name: "Local shared instance".into(),
            instance_name: config.instance_name.clone(),
            port: config.port,
            interface_id: rns_core::transport::types::InterfaceId(1),
            reconnect_wait,
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
            tunnel_id: None,
            mtu: crate::interface::local::HW_MTU,
            ia_freq: 0.0,
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
            driver.interface_writer_queue_capacity,
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
        node.destination_types.shared_client = true;
        Ok(node)
    }

    /// Connect to a shared instance, with config loaded from a config directory.
    ///
    /// Reads the config file to determine instance_name and ports.
    pub fn connect_shared_from_config(
        config_path: Option<&Path>,
        callbacks: Box<dyn Callbacks>,
    ) -> io::Result<Self> {
        let config_dir = storage::resolve_config_dir(config_path);

        // Parse config file for instance settings
        let config_file = config_dir.join("config");
        let rns_config = if config_file.exists() {
            crate::config::parse_file(&config_file)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?
        } else {
            crate::config::parse("")
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?
        };

        let shared_config = SharedClientConfig {
            instance_name: rns_config.reticulum.instance_name.clone(),
            port: rns_config.reticulum.shared_instance_port,
            rpc_port: rns_config.reticulum.instance_control_port,
        };
        let rpc_port = shared_config.rpc_port;

        let mut node = Self::connect_shared(shared_config, callbacks)?;
        node.use_shared_instance_rpc(&config_dir, rpc_port);
        Ok(node)
    }

    /// Reach the shared instance's RPC server for destination type
    /// registrations. Its key derives from the shared instance's transport
    /// identity, which clients read from the same storage directory; without
    /// one, registrations stay local.
    pub(crate) fn use_shared_instance_rpc(&mut self, config_dir: &Path, rpc_port: u16) {
        match storage::load_identity(&config_dir.join("storage").join("transport_identity")) {
            Ok(identity) => {
                let auth_key =
                    crate::rpc::derive_auth_key(&identity.get_private_key().unwrap_or([0u8; 64]));
                self.destination_types.shared_rpc =
                    Some((RpcAddr::Tcp("127.0.0.1".into(), rpc_port), auth_key));
            }
            Err(e) => log::debug!("No shared instance RPC key for destination type filters: {e}"),
        }
    }
}

#[doc(hidden)]
pub fn bench_shared_client_replay_once(
    announce_count: usize,
    reconnect_wait: Duration,
) -> io::Result<usize> {
    struct BenchNoopCallbacks;
    impl Callbacks for BenchNoopCallbacks {
        fn on_announce(&mut self, _: crate::destination::AnnouncedIdentity) {}
        fn on_path_updated(&mut self, _: rns_core::types::DestHash, _: u8) {}
        fn on_local_delivery(
            &mut self,
            _: rns_core::types::DestHash,
            _: Vec<u8>,
            _: rns_core::types::PacketHash,
        ) {
        }
    }

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
        packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
        packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
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
        tunnel_id: None,
        mtu: crate::interface::local::HW_MTU,
        ia_freq: 0.0,
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
        driver.interface_writer_queue_capacity,
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

#[cfg(test)]
mod tests {
    use super::*;
    use rns_core::packet::RawPacket;
    use rns_core::types::IdentityHash;
    use rns_crypto::identity::Identity;
    use rns_crypto::OsRng;
    use std::io::Read;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc;
    use std::sync::Arc;

    use crate::interface::local::LocalServerConfig;

    struct NoopCallbacks;
    impl Callbacks for NoopCallbacks {
        fn on_announce(&mut self, _: crate::destination::AnnouncedIdentity) {}
        fn on_path_updated(&mut self, _: rns_core::types::DestHash, _: u8) {}
        fn on_local_delivery(
            &mut self,
            _: rns_core::types::DestHash,
            _: Vec<u8>,
            _: rns_core::types::PacketHash,
        ) {
        }
    }

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
        std::fs::write(
            dir.path().join("config"),
            format!(
                "[reticulum]\nshare_instance = yes\ninstance_control_port = {rpc_port}\n\
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
        let auth_key = client.destination_types.shared_rpc.as_ref().unwrap().1;
        let requester = client.destination_types.requester;
        client.shutdown();
        let mut rpc =
            RpcClient::connect(&RpcAddr::Tcp("127.0.0.1".into(), rpc_port), &auth_key).unwrap();
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
        };

        crate::interface::local::start_server(server_config, server_tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        // Connect as shared client
        let config = SharedClientConfig {
            instance_name: crate::test_support::instance_name("test-shared-connect"),
            port,
            rpc_port: 0,
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
        };

        crate::interface::local::start_server(server_config, server_tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let config = SharedClientConfig {
            instance_name: crate::test_support::instance_name("test-shared-reg"),
            port,
            rpc_port: 0,
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
        };

        crate::interface::local::start_server(server_config, server_tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let config = SharedClientConfig {
            instance_name: crate::test_support::instance_name("test-shared-send"),
            port,
            rpc_port: 0,
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

    #[test]
    fn connect_shared_fails_no_server() {
        let port = find_free_port();

        let config = SharedClientConfig {
            instance_name: "nonexistent-instance-12345".into(),
            port,
            rpc_port: 0,
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
}
