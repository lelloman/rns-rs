//! RnsNode: high-level lifecycle management.
//!
//! Wires together the driver, interfaces, and timer thread.

use std::io;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rns_core::transport::types::{InterfaceInfo, TransportConfig};
use rns_crypto::identity::Identity;
use rns_crypto::OsRng;

use crate::config;
use crate::driver::{Callbacks, Driver};
use crate::event::{self, Event, EventSender};
use crate::interface::tcp::TcpClientConfig;
use crate::interface::tcp_server::TcpServerConfig;
use crate::interface::udp::UdpConfig;
use crate::interface::local::{LocalServerConfig, LocalClientConfig};
use crate::interface::InterfaceEntry;
use crate::storage;

/// Parse an interface mode string to the corresponding constant.
/// Matches Python's `_synthesize_interface()` in `RNS/Reticulum.py`.
fn parse_interface_mode(mode: &str) -> u8 {
    match mode.to_lowercase().as_str() {
        "full" => rns_core::constants::MODE_FULL,
        "access_point" | "accesspoint" | "ap" => rns_core::constants::MODE_ACCESS_POINT,
        "pointtopoint" | "ptp" => rns_core::constants::MODE_POINT_TO_POINT,
        "roaming" => rns_core::constants::MODE_ROAMING,
        "boundary" => rns_core::constants::MODE_BOUNDARY,
        "gateway" | "gw" => rns_core::constants::MODE_GATEWAY,
        _ => rns_core::constants::MODE_FULL,
    }
}

/// Top-level node configuration.
pub struct NodeConfig {
    pub transport_enabled: bool,
    pub identity: Option<Identity>,
    pub interfaces: Vec<InterfaceConfig>,
}

/// Interface configuration variant with its mode.
pub struct InterfaceConfig {
    pub variant: InterfaceVariant,
    /// Interface mode (MODE_FULL, MODE_ACCESS_POINT, etc.)
    pub mode: u8,
}

/// The specific interface type and its parameters.
pub enum InterfaceVariant {
    TcpClient(TcpClientConfig),
    TcpServer(TcpServerConfig),
    Udp(UdpConfig),
    LocalServer(LocalServerConfig),
    LocalClient(LocalClientConfig),
}

/// A running RNS node.
pub struct RnsNode {
    tx: EventSender,
    driver_handle: Option<JoinHandle<()>>,
}

impl RnsNode {
    /// Start the node from a config file path.
    /// If `config_path` is None, uses `~/.reticulum/`.
    pub fn from_config(
        config_path: Option<&Path>,
        callbacks: Box<dyn Callbacks>,
    ) -> io::Result<Self> {
        let config_dir = storage::resolve_config_dir(config_path);
        let paths = storage::ensure_storage_dirs(&config_dir)?;

        // Parse config file
        let config_file = config_dir.join("config");
        let rns_config = if config_file.exists() {
            config::parse_file(&config_file).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("{}", e))
            })?
        } else {
            // No config file, use defaults
            config::parse("").map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("{}", e))
            })?
        };

        // Load or create identity
        let identity = if let Some(ref id_path_str) = rns_config.reticulum.network_identity {
            let id_path = std::path::PathBuf::from(id_path_str);
            if id_path.exists() {
                storage::load_identity(&id_path)?
            } else {
                let id = Identity::new(&mut OsRng);
                storage::save_identity(&id, &id_path)?;
                id
            }
        } else {
            storage::load_or_create_identity(&paths.identities)?
        };

        // Build interface configs from parsed config
        let mut interface_configs = Vec::new();
        let mut next_id_val = 1u64;

        for iface in &rns_config.interfaces {
            if !iface.enabled {
                continue;
            }

            let iface_id = rns_core::transport::types::InterfaceId(next_id_val);
            next_id_val += 1;

            let iface_mode = parse_interface_mode(&iface.mode);

            match iface.interface_type.as_str() {
                "TCPClientInterface" => {
                    let target_host = iface
                        .params
                        .get("target_host")
                        .cloned()
                        .unwrap_or_else(|| "127.0.0.1".into());
                    let target_port = iface
                        .params
                        .get("target_port")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(4242);

                    interface_configs.push(InterfaceConfig {
                        variant: InterfaceVariant::TcpClient(TcpClientConfig {
                            name: iface.name.clone(),
                            target_host,
                            target_port,
                            interface_id: iface_id,
                            ..TcpClientConfig::default()
                        }),
                        mode: iface_mode,
                    });
                }
                "TCPServerInterface" => {
                    let listen_ip = iface
                        .params
                        .get("listen_ip")
                        .cloned()
                        .unwrap_or_else(|| "0.0.0.0".into());
                    let listen_port = iface
                        .params
                        .get("listen_port")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(4242);

                    interface_configs.push(InterfaceConfig {
                        variant: InterfaceVariant::TcpServer(TcpServerConfig {
                            name: iface.name.clone(),
                            listen_ip,
                            listen_port,
                            interface_id: iface_id,
                        }),
                        mode: iface_mode,
                    });
                }
                "UDPInterface" => {
                    let listen_ip = iface.params.get("listen_ip").cloned();
                    let listen_port = iface
                        .params
                        .get("listen_port")
                        .and_then(|v| v.parse().ok());
                    let forward_ip = iface.params.get("forward_ip").cloned();
                    let forward_port = iface
                        .params
                        .get("forward_port")
                        .and_then(|v| v.parse().ok());

                    // Handle 'port' shorthand (sets both listen_port and forward_port)
                    let port = iface.params.get("port").and_then(|v| v.parse::<u16>().ok());
                    let listen_port = listen_port.or(port);
                    let forward_port = forward_port.or(port);

                    interface_configs.push(InterfaceConfig {
                        variant: InterfaceVariant::Udp(UdpConfig {
                            name: iface.name.clone(),
                            listen_ip,
                            listen_port,
                            forward_ip,
                            forward_port,
                            interface_id: iface_id,
                        }),
                        mode: iface_mode,
                    });
                }
                _ => {
                    log::warn!(
                        "Unsupported interface type '{}' for '{}'",
                        iface.interface_type,
                        iface.name
                    );
                }
            }
        }

        let node_config = NodeConfig {
            transport_enabled: rns_config.reticulum.enable_transport,
            identity: Some(identity),
            interfaces: interface_configs,
        };

        Self::start(node_config, callbacks)
    }

    /// Start the node. Connects all interfaces, starts driver and timer threads.
    pub fn start(config: NodeConfig, callbacks: Box<dyn Callbacks>) -> io::Result<Self> {
        let identity = config
            .identity
            .unwrap_or_else(|| Identity::new(&mut OsRng));

        let transport_config = TransportConfig {
            transport_enabled: config.transport_enabled,
            identity_hash: Some(*identity.hash()),
        };

        let (tx, rx) = event::channel();
        let mut driver = Driver::new(transport_config, rx, callbacks);

        // Shared counter for dynamic interface IDs
        let next_dynamic_id = Arc::new(AtomicU64::new(10000));

        // Start each interface
        for iface_config in config.interfaces {
            let iface_mode = iface_config.mode;
            match iface_config.variant {
                InterfaceVariant::TcpClient(tcp_config) => {
                    let id = tcp_config.interface_id;
                    let info = InterfaceInfo {
                        id,
                        mode: iface_mode,
                        out_capable: true,
                        in_capable: true,
                        bitrate: None,
                        announce_rate_target: None,
                        announce_rate_grace: 0,
                        announce_rate_penalty: 0.0,
                    };

                    let writer =
                        crate::interface::tcp::start(tcp_config, tx.clone())?;

                    driver.engine.register_interface(info.clone());
                    driver.interfaces.insert(
                        id,
                        InterfaceEntry {
                            id,
                            info,
                            writer,
                            online: false, // InterfaceUp event will set this
                            dynamic: false,
                        },
                    );
                }
                InterfaceVariant::TcpServer(server_config) => {
                    crate::interface::tcp_server::start(
                        server_config,
                        tx.clone(),
                        next_dynamic_id.clone(),
                    )?;
                    // Server itself doesn't register as an interface;
                    // per-client interfaces are registered dynamically via InterfaceUp
                }
                InterfaceVariant::Udp(udp_config) => {
                    let id = udp_config.interface_id;
                    let out_capable = udp_config.forward_ip.is_some();
                    let in_capable = udp_config.listen_ip.is_some();

                    let writer = crate::interface::udp::start(udp_config, tx.clone())?;

                    let info = InterfaceInfo {
                        id,
                        mode: iface_mode,
                        out_capable,
                        in_capable,
                        bitrate: Some(10_000_000), // 10 Mbps guess (matches Python)
                        announce_rate_target: None,
                        announce_rate_grace: 0,
                        announce_rate_penalty: 0.0,
                    };

                    driver.engine.register_interface(info.clone());

                    if let Some(w) = writer {
                        driver.interfaces.insert(
                            id,
                            InterfaceEntry {
                                id,
                                info,
                                writer: w,
                                online: in_capable || out_capable, // Online if it can send or receive
                                dynamic: false,
                            },
                        );
                    }
                }
                InterfaceVariant::LocalServer(local_config) => {
                    crate::interface::local::start_server(
                        local_config,
                        tx.clone(),
                        next_dynamic_id.clone(),
                    )?;
                    // Per-client interfaces registered dynamically
                }
                InterfaceVariant::LocalClient(local_config) => {
                    let id = local_config.interface_id;
                    let info = InterfaceInfo {
                        id,
                        mode: iface_mode,
                        out_capable: true,
                        in_capable: true,
                        bitrate: Some(1_000_000_000), // 1 Gbps
                        announce_rate_target: None,
                        announce_rate_grace: 0,
                        announce_rate_penalty: 0.0,
                    };

                    let writer =
                        crate::interface::local::start_client(local_config, tx.clone())?;

                    driver.engine.register_interface(info.clone());
                    driver.interfaces.insert(
                        id,
                        InterfaceEntry {
                            id,
                            info,
                            writer,
                            online: false,
                            dynamic: false,
                        },
                    );
                }
            }
        }

        // Spawn timer thread
        let timer_tx = tx.clone();
        thread::Builder::new()
            .name("rns-timer".into())
            .spawn(move || {
                loop {
                    thread::sleep(Duration::from_secs(1));
                    if timer_tx.send(Event::Tick).is_err() {
                        break; // receiver dropped
                    }
                }
            })?;

        // Spawn driver thread
        let driver_handle = thread::Builder::new()
            .name("rns-driver".into())
            .spawn(move || {
                driver.run();
            })?;

        Ok(RnsNode {
            tx,
            driver_handle: Some(driver_handle),
        })
    }

    /// Shut down the node. Blocks until the driver thread exits.
    pub fn shutdown(mut self) {
        let _ = self.tx.send(Event::Shutdown);
        if let Some(handle) = self.driver_handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct NoopCallbacks;

    impl Callbacks for NoopCallbacks {
        fn on_announce(&mut self, _: [u8; 16], _: [u8; 16], _: [u8; 64], _: Option<Vec<u8>>, _: u8) {}
        fn on_path_updated(&mut self, _: [u8; 16], _: u8) {}
        fn on_local_delivery(&mut self, _: [u8; 16], _: Vec<u8>, _: [u8; 32]) {}
    }

    #[test]
    fn start_and_shutdown() {
        let node = RnsNode::start(
            NodeConfig {
                transport_enabled: false,
                identity: None,
                interfaces: vec![],
            },
            Box::new(NoopCallbacks),
        )
        .unwrap();
        node.shutdown();
    }

    #[test]
    fn start_with_identity() {
        let identity = Identity::new(&mut OsRng);
        let hash = *identity.hash();
        let node = RnsNode::start(
            NodeConfig {
                transport_enabled: true,
                identity: Some(identity),
                interfaces: vec![],
            },
            Box::new(NoopCallbacks),
        )
        .unwrap();
        // The identity hash should have been used
        let _ = hash;
        node.shutdown();
    }

    #[test]
    fn start_generates_identity() {
        let node = RnsNode::start(
            NodeConfig {
                transport_enabled: false,
                identity: None,
                interfaces: vec![],
            },
            Box::new(NoopCallbacks),
        )
        .unwrap();
        // Should not panic - identity was auto-generated
        node.shutdown();
    }

    #[test]
    fn from_config_creates_identity() {
        let dir = std::env::temp_dir().join(format!("rns-test-fc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Write a minimal config file
        fs::write(
            dir.join("config"),
            "[reticulum]\nenable_transport = False\n",
        )
        .unwrap();

        let node = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks)).unwrap();

        // Identity file should have been created
        assert!(dir.join("storage/identities/identity").exists());

        node.shutdown();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_config_loads_identity() {
        let dir = std::env::temp_dir().join(format!("rns-test-fl-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("storage/identities")).unwrap();

        // Pre-create an identity
        let identity = Identity::new(&mut OsRng);
        let hash = *identity.hash();
        storage::save_identity(&identity, &dir.join("storage/identities/identity")).unwrap();

        fs::write(
            dir.join("config"),
            "[reticulum]\nenable_transport = False\n",
        )
        .unwrap();

        let node = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks)).unwrap();

        // Verify the same identity was loaded (hash matches)
        let loaded = storage::load_identity(&dir.join("storage/identities/identity")).unwrap();
        assert_eq!(*loaded.hash(), hash);

        node.shutdown();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_config_tcp_server() {
        let dir = std::env::temp_dir().join(format!("rns-test-fts-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Find a free port
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let config = format!(
            r#"
[reticulum]
enable_transport = False

[interfaces]
  [[Test TCP Server]]
    type = TCPServerInterface
    listen_ip = 127.0.0.1
    listen_port = {}
"#,
            port
        );

        fs::write(dir.join("config"), config).unwrap();

        let node = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks)).unwrap();

        // Give server time to start
        thread::sleep(Duration::from_millis(100));

        // Should be able to connect
        let _client = std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        node.shutdown();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_parse_interface_mode() {
        use rns_core::constants::*;

        assert_eq!(parse_interface_mode("full"), MODE_FULL);
        assert_eq!(parse_interface_mode("Full"), MODE_FULL);
        assert_eq!(parse_interface_mode("access_point"), MODE_ACCESS_POINT);
        assert_eq!(parse_interface_mode("accesspoint"), MODE_ACCESS_POINT);
        assert_eq!(parse_interface_mode("ap"), MODE_ACCESS_POINT);
        assert_eq!(parse_interface_mode("AP"), MODE_ACCESS_POINT);
        assert_eq!(parse_interface_mode("pointtopoint"), MODE_POINT_TO_POINT);
        assert_eq!(parse_interface_mode("ptp"), MODE_POINT_TO_POINT);
        assert_eq!(parse_interface_mode("roaming"), MODE_ROAMING);
        assert_eq!(parse_interface_mode("boundary"), MODE_BOUNDARY);
        assert_eq!(parse_interface_mode("gateway"), MODE_GATEWAY);
        assert_eq!(parse_interface_mode("gw"), MODE_GATEWAY);
        // Unknown defaults to FULL
        assert_eq!(parse_interface_mode("invalid"), MODE_FULL);
    }
}
