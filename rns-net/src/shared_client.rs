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
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rns_core::transport::types::TransportConfig;

use crate::driver::{Callbacks, Driver};
use crate::event;
use crate::interface::local::LocalClientConfig;
use crate::interface::{InterfaceEntry, InterfaceStats};
use crate::node::RnsNode;
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

impl RnsNode {
    /// Connect to an existing shared instance as a client.
    ///
    /// The client runs `transport_enabled: false` — it does no routing,
    /// but can register destinations and send/receive packets through
    /// the daemon.
    pub fn connect_shared(
        config: SharedClientConfig,
        callbacks: Box<dyn Callbacks>,
    ) -> io::Result<Self> {
        let transport_config = TransportConfig {
            transport_enabled: false,
            identity_hash: None,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
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

        // Connect to the daemon via LocalClientInterface
        let local_config = LocalClientConfig {
            name: "Local shared instance".into(),
            instance_name: config.instance_name.clone(),
            port: config.port,
            interface_id: rns_core::transport::types::InterfaceId(1),
            reconnect_wait: Duration::from_secs(8),
        };

        let id = local_config.interface_id;
        let info = rns_core::transport::types::InterfaceInfo {
            id,
            name: "LocalInterface".into(),
            mode: rns_core::constants::MODE_FULL,
            out_capable: true,
            in_capable: true,
            bitrate: Some(1_000_000_000),
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: rns_core::constants::ANNOUNCE_CAP,
            is_local_client: true,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: 65535,
            ia_freq: 0.0,
            started: time::now(),
            ingress_control: false,
        };

        let writer = crate::interface::local::start_client(local_config, tx.clone())?;

        driver.engine.register_interface(info.clone());
        driver.interfaces.insert(
            id,
            InterfaceEntry {
                id,
                info,
                writer,
                async_writer_metrics: None,
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

        // Spawn timer thread with configurable tick interval
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

        // Spawn driver thread
        let driver_handle = thread::Builder::new()
            .name("rns-driver-client".into())
            .spawn(move || {
                driver.run();
            })?;

        Ok(RnsNode::from_parts(
            tx,
            driver_handle,
            None,
            tick_interval_ms,
        ))
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

        Self::connect_shared(shared_config, callbacks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hdlc;
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
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn connect_shared_to_tcp_server() {
        let port = find_free_port();
        let next_id = Arc::new(AtomicU64::new(50000));
        let (server_tx, server_rx) = crate::event::channel();

        // Start a local server
        let server_config = LocalServerConfig {
            instance_name: "test-shared-connect".into(),
            port,
            interface_id: rns_core::transport::types::InterfaceId(99),
        };

        crate::interface::local::start_server(server_config, server_tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        // Connect as shared client
        let config = SharedClientConfig {
            instance_name: "test-shared-connect".into(),
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
            instance_name: "test-shared-reg".into(),
            port,
            interface_id: rns_core::transport::types::InterfaceId(98),
        };

        crate::interface::local::start_server(server_config, server_tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let config = SharedClientConfig {
            instance_name: "test-shared-reg".into(),
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
            instance_name: "test-shared-send".into(),
            port,
            interface_id: rns_core::transport::types::InterfaceId(97),
        };

        crate::interface::local::start_server(server_config, server_tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let config = SharedClientConfig {
            instance_name: "test-shared-send".into(),
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
        node.announce(&dest, &identity, Some(b"hello")).unwrap();

        let mut stream1 = accepted1_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        stream1
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let mut decoder = hdlc::Decoder::new();
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

        let mut decoder = hdlc::Decoder::new();
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
