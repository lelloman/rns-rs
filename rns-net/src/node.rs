//! RnsNode: high-level lifecycle management.
//!
//! Wires together the driver, interfaces, and timer thread.

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rns_core::transport::types::{InterfaceInfo, TransportConfig};
use rns_crypto::identity::Identity;
use rns_crypto::{OsRng, Rng};

use crate::config;
use crate::driver::{Callbacks, Driver};
use crate::event::{self, Event, EventSender};
use crate::ifac;
use crate::interface::tcp::TcpClientConfig;
use crate::interface::tcp_server::TcpServerConfig;
use crate::interface::udp::UdpConfig;
use crate::interface::local::{LocalServerConfig, LocalClientConfig};
use crate::interface::serial_iface::SerialIfaceConfig;
use crate::interface::kiss_iface::KissIfaceConfig;
use crate::interface::pipe::PipeConfig;
use crate::interface::rnode::{RNodeConfig, RNodeSubConfig};
use crate::interface::backbone::{BackboneConfig, BackboneClientConfig};
use crate::interface::auto::AutoConfig;
use crate::interface::i2p::I2pConfig;
use crate::interface::{InterfaceEntry, InterfaceStats};
use crate::time;
use crate::serial::Parity;
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

/// Parse a parity string from config. Matches Python's serial.PARITY_*.
fn parse_parity(s: &str) -> Parity {
    match s.to_lowercase().as_str() {
        "e" | "even" => Parity::Even,
        "o" | "odd" => Parity::Odd,
        _ => Parity::None,
    }
}

/// Extract IFAC configuration from interface params, if present.
/// Returns None if neither networkname/network_name nor passphrase/pass_phrase is set.
fn extract_ifac_config(params: &std::collections::HashMap<String, String>, default_size: usize) -> Option<IfacConfig> {
    let netname = params.get("networkname")
        .or_else(|| params.get("network_name"))
        .cloned();
    let netkey = params.get("passphrase")
        .or_else(|| params.get("pass_phrase"))
        .cloned();

    if netname.is_none() && netkey.is_none() {
        return None;
    }

    // ifac_size is specified in bits in config, divide by 8 for bytes
    let size = params.get("ifac_size")
        .and_then(|v| v.parse::<usize>().ok())
        .map(|bits| (bits / 8).max(1))
        .unwrap_or(default_size);

    Some(IfacConfig { netname, netkey, size })
}

/// Extract discovery configuration from interface params, if `discoverable` is set.
fn extract_discovery_config(
    iface_name: &str,
    iface_type: &str,
    params: &std::collections::HashMap<String, String>,
) -> Option<crate::discovery::DiscoveryConfig> {
    let discoverable = params.get("discoverable")
        .and_then(|v| config::parse_bool_pub(v))
        .unwrap_or(false);
    if !discoverable {
        return None;
    }

    let discovery_name = params.get("discovery_name")
        .cloned()
        .unwrap_or_else(|| iface_name.to_string());

    // Config value is in seconds. Min 300s (5min), default 21600s (6h).
    let announce_interval = params.get("announce_interval")
        .and_then(|v| v.parse::<u64>().ok())
        .map(|secs| secs.max(300))
        .unwrap_or(21600);

    let stamp_value = params.get("discovery_stamp_value")
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(crate::discovery::DEFAULT_STAMP_VALUE);

    let reachable_on = params.get("reachable_on").cloned();

    let listen_port = params.get("listen_port")
        .or_else(|| params.get("port"))
        .and_then(|v| v.parse().ok());

    let latitude = params.get("latitude")
        .or_else(|| params.get("lat"))
        .and_then(|v| v.parse().ok());
    let longitude = params.get("longitude")
        .or_else(|| params.get("lon"))
        .and_then(|v| v.parse().ok());
    let height = params.get("height")
        .and_then(|v| v.parse().ok());

    Some(crate::discovery::DiscoveryConfig {
        discovery_name,
        announce_interval,
        stamp_value,
        reachable_on,
        interface_type: iface_type.to_string(),
        listen_port,
        latitude,
        longitude,
        height,
    })
}

/// Top-level node configuration.
pub struct NodeConfig {
    pub transport_enabled: bool,
    pub identity: Option<Identity>,
    pub interfaces: Vec<InterfaceConfig>,
    /// Enable shared instance server for local clients (rns-ctl, etc.)
    pub share_instance: bool,
    /// Instance name for Unix socket namespace (default: "default").
    pub instance_name: String,
    /// Shared instance port for local client connections (default 37428).
    pub shared_instance_port: u16,
    /// RPC control port (default 37429). Only used when share_instance is true.
    pub rpc_port: u16,
    /// Cache directory for announce cache. If None, announce caching is disabled.
    pub cache_dir: Option<std::path::PathBuf>,
    /// Remote management configuration.
    pub management: crate::management::ManagementConfig,
    /// Port to run the STUN probe server on (for facilitator nodes).
    pub probe_port: Option<u16>,
    /// Address of the STUN probe server (for client nodes behind NAT).
    pub probe_addr: Option<std::net::SocketAddr>,
    /// Network interface to bind outbound sockets to (e.g. "usb0").
    pub device: Option<String>,
    /// Hook configurations loaded from the config file.
    pub hooks: Vec<config::ParsedHook>,
    /// Enable interface discovery.
    pub discover_interfaces: bool,
    /// Minimum stamp value for accepting discovered interfaces (default: 14).
    pub discovery_required_value: Option<u8>,
    /// Respond to probe packets with automatic proof (like Python's respond_to_probes).
    pub respond_to_probes: bool,
    /// Accept an announce with strictly fewer hops even when the random_blob
    /// is a duplicate of the existing path entry.  Default `false` preserves
    /// Python-compatible anti-replay behaviour.
    pub prefer_shorter_path: bool,
    /// Maximum number of alternative paths stored per destination.
    /// Default 1 (single path, backward-compatible).
    pub max_paths_per_destination: usize,
}

/// Interface configuration variant with its mode.
pub struct InterfaceConfig {
    pub variant: InterfaceVariant,
    /// Interface mode (MODE_FULL, MODE_ACCESS_POINT, etc.)
    pub mode: u8,
    /// IFAC (Interface Access Code) configuration, if enabled.
    pub ifac: Option<IfacConfig>,
    /// Discovery configuration, if this interface is discoverable.
    pub discovery: Option<crate::discovery::DiscoveryConfig>,
}

/// IFAC configuration for an interface.
pub struct IfacConfig {
    pub netname: Option<String>,
    pub netkey: Option<String>,
    pub size: usize,
}

/// The specific interface type and its parameters.
pub enum InterfaceVariant {
    TcpClient(TcpClientConfig),
    TcpServer(TcpServerConfig),
    Udp(UdpConfig),
    LocalServer(LocalServerConfig),
    LocalClient(LocalClientConfig),
    Serial(SerialIfaceConfig),
    Kiss(KissIfaceConfig),
    Pipe(PipeConfig),
    RNode(RNodeConfig),
    Backbone(BackboneConfig),
    BackboneClient(BackboneClientConfig),
    Auto(AutoConfig),
    I2p(I2pConfig),
}

use crate::event::{QueryRequest, QueryResponse};

/// Error returned when the driver thread has shut down.
#[derive(Debug)]
pub struct SendError;

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "driver shut down")
    }
}

impl std::error::Error for SendError {}

/// A running RNS node.
pub struct RnsNode {
    tx: EventSender,
    driver_handle: Option<JoinHandle<()>>,
    rpc_server: Option<crate::rpc::RpcServer>,
    tick_interval_ms: Arc<AtomicU64>,
    #[allow(dead_code)]
    probe_server: Option<crate::holepunch::probe::ProbeServerHandle>,
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

            let mut iface_mode = parse_interface_mode(&iface.mode);

            // Auto-configure mode when discovery is enabled (Python Reticulum.py).
            // AutoInterface inherently uses discovery; RNodeInterface may have discoverable=true.
            let has_discovery = match iface.interface_type.as_str() {
                "AutoInterface" => true,
                "RNodeInterface" => iface.params.get("discoverable")
                    .and_then(|v| config::parse_bool_pub(v))
                    .unwrap_or(false),
                _ => false,
            };
            if has_discovery
                && iface_mode != rns_core::constants::MODE_ACCESS_POINT
                && iface_mode != rns_core::constants::MODE_GATEWAY
            {
                let new_mode = if iface.interface_type == "RNodeInterface" {
                    rns_core::constants::MODE_ACCESS_POINT
                } else {
                    rns_core::constants::MODE_GATEWAY
                };
                log::info!(
                    "Interface '{}' has discovery enabled, auto-configuring mode to {}",
                    iface.name,
                    if new_mode == rns_core::constants::MODE_ACCESS_POINT {
                        "ACCESS_POINT"
                    } else {
                        "GATEWAY"
                    }
                );
                iface_mode = new_mode;
            }

            // Default IFAC size depends on interface type:
            // 8 bytes for Serial/KISS/RNode, 16 for TCP/UDP/Auto/Local
            let default_ifac_size = match iface.interface_type.as_str() {
                "SerialInterface" | "KISSInterface" | "RNodeInterface" => 8,
                _ => 16,
            };
            let ifac_config = extract_ifac_config(&iface.params, default_ifac_size);
            let discovery_config = extract_discovery_config(
                &iface.name, &iface.interface_type, &iface.params,
            );

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
                            device: rns_config.reticulum.device.clone(),
                            ..TcpClientConfig::default()
                        }),
                        mode: iface_mode,
                        ifac: ifac_config,
                        discovery: discovery_config.clone(),
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
                        ifac: ifac_config,
                        discovery: discovery_config.clone(),
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
                        ifac: ifac_config,
                        discovery: discovery_config.clone(),
                    });
                }
                "SerialInterface" => {
                    let port = match iface.params.get("port") {
                        Some(p) => p.clone(),
                        None => {
                            log::warn!("No port specified for SerialInterface '{}'", iface.name);
                            continue;
                        }
                    };
                    let speed = iface.params.get("speed")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(9600);
                    let databits = iface.params.get("databits")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(8);
                    let parity = iface.params.get("parity")
                        .map(|v| parse_parity(v))
                        .unwrap_or(Parity::None);
                    let stopbits = iface.params.get("stopbits")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(1);

                    interface_configs.push(InterfaceConfig {
                        variant: InterfaceVariant::Serial(SerialIfaceConfig {
                            name: iface.name.clone(),
                            port,
                            speed,
                            data_bits: databits,
                            parity,
                            stop_bits: stopbits,
                            interface_id: iface_id,
                        }),
                        mode: iface_mode,
                        ifac: ifac_config,
                        discovery: discovery_config.clone(),
                    });
                }
                "KISSInterface" => {
                    let port = match iface.params.get("port") {
                        Some(p) => p.clone(),
                        None => {
                            log::warn!("No port specified for KISSInterface '{}'", iface.name);
                            continue;
                        }
                    };
                    let speed = iface.params.get("speed")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(9600);
                    let databits = iface.params.get("databits")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(8);
                    let parity = iface.params.get("parity")
                        .map(|v| parse_parity(v))
                        .unwrap_or(Parity::None);
                    let stopbits = iface.params.get("stopbits")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(1);
                    let preamble = iface.params.get("preamble")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(350);
                    let txtail = iface.params.get("txtail")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(20);
                    let persistence = iface.params.get("persistence")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(64);
                    let slottime = iface.params.get("slottime")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(20);
                    let flow_control = iface.params.get("flow_control")
                        .and_then(|v| config::parse_bool_pub(v))
                        .unwrap_or(false);
                    let beacon_interval = iface.params.get("id_interval")
                        .and_then(|v| v.parse().ok());
                    let beacon_data = iface.params.get("id_callsign")
                        .map(|v| v.as_bytes().to_vec());

                    interface_configs.push(InterfaceConfig {
                        variant: InterfaceVariant::Kiss(KissIfaceConfig {
                            name: iface.name.clone(),
                            port,
                            speed,
                            data_bits: databits,
                            parity,
                            stop_bits: stopbits,
                            preamble,
                            txtail,
                            persistence,
                            slottime,
                            flow_control,
                            beacon_interval,
                            beacon_data,
                            interface_id: iface_id,
                        }),
                        mode: iface_mode,
                        ifac: ifac_config,
                        discovery: discovery_config.clone(),
                    });
                }
                "RNodeInterface" => {
                    let port = match iface.params.get("port") {
                        Some(p) => p.clone(),
                        None => {
                            log::warn!("No port specified for RNodeInterface '{}'", iface.name);
                            continue;
                        }
                    };
                    let speed = iface.params.get("speed")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(115200);
                    let frequency = iface.params.get("frequency")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(868_000_000);
                    let bandwidth = iface.params.get("bandwidth")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(125_000);
                    let txpower = iface.params.get("txpower")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(7);
                    let spreading_factor = iface.params.get("spreadingfactor")
                        .or_else(|| iface.params.get("spreading_factor"))
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(8);
                    let coding_rate = iface.params.get("codingrate")
                        .or_else(|| iface.params.get("coding_rate"))
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(5);
                    let flow_control = iface.params.get("flow_control")
                        .and_then(|v| config::parse_bool_pub(v))
                        .unwrap_or(false);
                    let st_alock = iface.params.get("st_alock")
                        .and_then(|v| v.parse().ok());
                    let lt_alock = iface.params.get("lt_alock")
                        .and_then(|v| v.parse().ok());
                    let id_interval = iface.params.get("id_interval")
                        .and_then(|v| v.parse().ok());
                    let id_callsign = iface.params.get("id_callsign")
                        .map(|v| v.as_bytes().to_vec());

                    let sub = RNodeSubConfig {
                        name: iface.name.clone(),
                        frequency,
                        bandwidth,
                        txpower,
                        spreading_factor,
                        coding_rate,
                        flow_control,
                        st_alock,
                        lt_alock,
                    };

                    interface_configs.push(InterfaceConfig {
                        variant: InterfaceVariant::RNode(RNodeConfig {
                            name: iface.name.clone(),
                            port,
                            speed,
                            subinterfaces: vec![sub],
                            id_interval,
                            id_callsign,
                            base_interface_id: iface_id,
                        }),
                        mode: iface_mode,
                        ifac: ifac_config,
                        discovery: discovery_config.clone(),
                    });
                }
                "PipeInterface" => {
                    let command = match iface.params.get("command") {
                        Some(c) => c.clone(),
                        None => {
                            log::warn!("No command specified for PipeInterface '{}'", iface.name);
                            continue;
                        }
                    };
                    let respawn_delay = iface.params.get("respawn_delay")
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_millis)
                        .unwrap_or(Duration::from_secs(5));

                    interface_configs.push(InterfaceConfig {
                        variant: InterfaceVariant::Pipe(PipeConfig {
                            name: iface.name.clone(),
                            command,
                            respawn_delay,
                            interface_id: iface_id,
                        }),
                        mode: iface_mode,
                        ifac: ifac_config,
                        discovery: discovery_config.clone(),
                    });
                }
                "BackboneInterface" => {
                    if let Some(target_host) = iface.params.get("remote")
                        .or_else(|| iface.params.get("target_host"))
                    {
                        // Client mode
                        let target_host = target_host.clone();
                        let target_port = iface.params.get("target_port")
                            .or_else(|| iface.params.get("port"))
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(4242);
                        let transport_identity = iface.params.get("transport_identity").cloned();

                        interface_configs.push(InterfaceConfig {
                            variant: InterfaceVariant::BackboneClient(BackboneClientConfig {
                                name: iface.name.clone(),
                                target_host,
                                target_port,
                                interface_id: iface_id,
                                transport_identity,
                                ..BackboneClientConfig::default()
                            }),
                            mode: iface_mode,
                            ifac: ifac_config,
                            discovery: discovery_config.clone(),
                        });
                    } else {
                        // Server mode
                        let listen_ip = iface.params.get("listen_ip")
                            .or_else(|| iface.params.get("device"))
                            .cloned()
                            .unwrap_or_else(|| "0.0.0.0".into());
                        let listen_port = iface.params.get("listen_port")
                            .or_else(|| iface.params.get("port"))
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(4242);

                        interface_configs.push(InterfaceConfig {
                            variant: InterfaceVariant::Backbone(BackboneConfig {
                                name: iface.name.clone(),
                                listen_ip,
                                listen_port,
                                interface_id: iface_id,
                            }),
                            mode: iface_mode,
                            ifac: ifac_config,
                            discovery: discovery_config.clone(),
                        });
                    }
                }
                "AutoInterface" => {
                    let group_id = iface
                        .params
                        .get("group_id")
                        .map(|s| s.as_bytes().to_vec())
                        .unwrap_or_else(|| crate::interface::auto::DEFAULT_GROUP_ID.to_vec());

                    let discovery_scope = iface
                        .params
                        .get("discovery_scope")
                        .map(|s| match s.to_lowercase().as_str() {
                            "link" => crate::interface::auto::SCOPE_LINK.to_string(),
                            "admin" => crate::interface::auto::SCOPE_ADMIN.to_string(),
                            "site" => crate::interface::auto::SCOPE_SITE.to_string(),
                            "organisation" | "organization" => crate::interface::auto::SCOPE_ORGANISATION.to_string(),
                            "global" => crate::interface::auto::SCOPE_GLOBAL.to_string(),
                            other => other.to_string(),
                        })
                        .unwrap_or_else(|| crate::interface::auto::SCOPE_LINK.to_string());

                    let discovery_port = iface
                        .params
                        .get("discovery_port")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(crate::interface::auto::DEFAULT_DISCOVERY_PORT);

                    let data_port = iface
                        .params
                        .get("data_port")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(crate::interface::auto::DEFAULT_DATA_PORT);

                    let multicast_address_type = iface
                        .params
                        .get("multicast_address_type")
                        .map(|s| match s.to_lowercase().as_str() {
                            "permanent" => crate::interface::auto::MULTICAST_PERMANENT_ADDRESS_TYPE.to_string(),
                            "temporary" => crate::interface::auto::MULTICAST_TEMPORARY_ADDRESS_TYPE.to_string(),
                            other => other.to_string(),
                        })
                        .unwrap_or_else(|| crate::interface::auto::MULTICAST_TEMPORARY_ADDRESS_TYPE.to_string());

                    let configured_bitrate = iface
                        .params
                        .get("configured_bitrate")
                        .or_else(|| iface.params.get("bitrate"))
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(crate::interface::auto::BITRATE_GUESS);

                    // Parse device lists (comma-separated)
                    let allowed_interfaces = iface
                        .params
                        .get("devices")
                        .or_else(|| iface.params.get("allowed_interfaces"))
                        .map(|s| s.split(',').map(|d| d.trim().to_string()).filter(|d| !d.is_empty()).collect())
                        .unwrap_or_default();

                    let ignored_interfaces = iface
                        .params
                        .get("ignored_devices")
                        .or_else(|| iface.params.get("ignored_interfaces"))
                        .map(|s| s.split(',').map(|d| d.trim().to_string()).filter(|d| !d.is_empty()).collect())
                        .unwrap_or_default();

                    interface_configs.push(InterfaceConfig {
                        variant: InterfaceVariant::Auto(AutoConfig {
                            name: iface.name.clone(),
                            group_id,
                            discovery_scope,
                            discovery_port,
                            data_port,
                            multicast_address_type,
                            allowed_interfaces,
                            ignored_interfaces,
                            configured_bitrate,
                            interface_id: iface_id,
                        }),
                        mode: iface_mode,
                        ifac: ifac_config,
                        discovery: discovery_config.clone(),
                    });
                }
                "I2PInterface" => {
                    let sam_host = iface
                        .params
                        .get("sam_host")
                        .cloned()
                        .unwrap_or_else(|| "127.0.0.1".into());
                    let sam_port = iface
                        .params
                        .get("sam_port")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(7656);
                    let connectable = iface
                        .params
                        .get("connectable")
                        .and_then(|v| config::parse_bool_pub(v))
                        .unwrap_or(false);
                    let peers: Vec<String> = iface
                        .params
                        .get("peers")
                        .map(|s| {
                            s.split(',')
                                .map(|p| p.trim().to_string())
                                .filter(|p| !p.is_empty())
                                .collect()
                        })
                        .unwrap_or_default();

                    interface_configs.push(InterfaceConfig {
                        variant: InterfaceVariant::I2p(I2pConfig {
                            name: iface.name.clone(),
                            interface_id: iface_id,
                            sam_host,
                            sam_port,
                            peers,
                            connectable,
                            storage_dir: paths.storage.clone(),
                        }),
                        mode: iface_mode,
                        ifac: ifac_config,
                        discovery: discovery_config.clone(),
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

        // Parse management config
        let mut mgmt_allowed = Vec::new();
        for hex_hash in &rns_config.reticulum.remote_management_allowed {
            if hex_hash.len() == 32 {
                if let Ok(bytes) = (0..hex_hash.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex_hash[i..i+2], 16))
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
                    hex_hash.len(), hex_hash,
                );
            }
        }

        // Parse probe_addr string to SocketAddr
        let probe_addr = rns_config.reticulum.probe_addr.as_ref().and_then(|s| {
            s.parse::<std::net::SocketAddr>().map_err(|e| {
                log::warn!("Invalid probe_addr '{}': {}", s, e);
                e
            }).ok()
        });

        let node_config = NodeConfig {
            transport_enabled: rns_config.reticulum.enable_transport,
            identity: Some(identity),
            interfaces: interface_configs,
            share_instance: rns_config.reticulum.share_instance,
            instance_name: rns_config.reticulum.instance_name.clone(),
            shared_instance_port: rns_config.reticulum.shared_instance_port,
            rpc_port: rns_config.reticulum.instance_control_port,
            cache_dir: Some(paths.cache),
            management: crate::management::ManagementConfig {
                enable_remote_management: rns_config.reticulum.enable_remote_management,
                remote_management_allowed: mgmt_allowed,
                publish_blackhole: rns_config.reticulum.publish_blackhole,
            },
            probe_port: rns_config.reticulum.probe_port,
            probe_addr,
            device: rns_config.reticulum.device.clone(),
            hooks: rns_config.hooks.clone(),
            discover_interfaces: rns_config.reticulum.discover_interfaces,
            discovery_required_value: rns_config.reticulum.required_discovery_value,
            respond_to_probes: rns_config.reticulum.respond_to_probes,
            prefer_shorter_path: rns_config.reticulum.prefer_shorter_path,
            max_paths_per_destination: rns_config.reticulum.max_paths_per_destination,
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
            prefer_shorter_path: config.prefer_shorter_path,
            max_paths_per_destination: config.max_paths_per_destination,
        };

        let (tx, rx) = event::channel();
        let mut driver = Driver::new(transport_config, rx, tx.clone(), callbacks);

        // Set up announce cache if cache directory is configured
        if let Some(ref cache_dir) = config.cache_dir {
            let announces_dir = cache_dir.join("announces");
            let _ = std::fs::create_dir_all(&announces_dir);
            driver.announce_cache = Some(crate::announce_cache::AnnounceCache::new(announces_dir));
        }

        // Configure probe address and device for hole punching
        if config.probe_addr.is_some() || config.device.is_some() {
            driver.set_probe_config(config.probe_addr, config.device.clone());
        }

        // Start probe server if configured
        let probe_server = if let Some(port) = config.probe_port {
            let listen_addr: std::net::SocketAddr = ([0, 0, 0, 0], port).into();
            match crate::holepunch::probe::start_probe_server(listen_addr) {
                Ok(handle) => {
                    log::info!("Probe server started on 0.0.0.0:{}", port);
                    Some(handle)
                }
                Err(e) => {
                    log::error!("Failed to start probe server on port {}: {}", port, e);
                    None
                }
            }
        } else {
            None
        };

        // Store management config on driver for ACL enforcement
        driver.management_config = config.management.clone();

        // Store transport identity for tunnel synthesis
        if let Some(prv_key) = identity.get_private_key() {
            driver.transport_identity = Some(Identity::from_private_key(&prv_key));
        }

        // Load hooks from config
        #[cfg(feature = "rns-hooks")]
        {
            for hook_cfg in &config.hooks {
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
                        log::warn!("Hook manager not available, skipping hook '{}'", hook_cfg.name);
                        continue;
                    }
                };
                match mgr.load_file(
                    hook_cfg.name.clone(),
                    std::path::Path::new(&hook_cfg.path),
                    hook_cfg.priority,
                ) {
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

        // Configure discovery
        driver.discover_interfaces = config.discover_interfaces;
        if let Some(val) = config.discovery_required_value {
            driver.discovery_required_value = val;
        }

        // Shared counter for dynamic interface IDs
        let next_dynamic_id = Arc::new(AtomicU64::new(10000));

        // Collect discoverable interface configs for the announcer
        let mut discoverable_interfaces = Vec::new();

        // Start each interface
        for iface_config in config.interfaces {
            let iface_mode = iface_config.mode;
            let ifac_cfg = iface_config.ifac;

            // Collect discovery config before consuming ifac_cfg
            if let Some(ref disc) = iface_config.discovery {
                discoverable_interfaces.push(crate::discovery::DiscoverableInterface {
                    config: disc.clone(),
                    transport_enabled: config.transport_enabled,
                    ifac_netname: ifac_cfg.as_ref().and_then(|ic| ic.netname.clone()),
                    ifac_netkey: ifac_cfg.as_ref().and_then(|ic| ic.netkey.clone()),
                });
            }

            // Derive IFAC state if configured
            let mut ifac_state = ifac_cfg.as_ref().and_then(|ic| {
                if ic.netname.is_some() || ic.netkey.is_some() {
                    Some(ifac::derive_ifac(
                        ic.netname.as_deref(),
                        ic.netkey.as_deref(),
                        ic.size,
                    ))
                } else {
                    None
                }
            });

            match iface_config.variant {
                InterfaceVariant::TcpClient(tcp_config) => {
                    let id = tcp_config.interface_id;
                    let name = tcp_config.name.clone();
                    let info = InterfaceInfo {
                        id,
                        name,
                        mode: iface_mode,
                        out_capable: true,
                        in_capable: true,
                        bitrate: None,
                        announce_rate_target: None,
                        announce_rate_grace: 0,
                        announce_rate_penalty: 0.0,
                        announce_cap: rns_core::constants::ANNOUNCE_CAP,
                        is_local_client: false,
                        wants_tunnel: false,
                        tunnel_id: None,
                        mtu: 65535,
                        ingress_control: true,
                        ia_freq: 0.0,
                        started: time::now(),
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
                            online: false,
                            dynamic: false,
                            ifac: ifac_state,
                            stats: InterfaceStats {
                                started: time::now(),
                                ..Default::default()
                            },
                            interface_type: "TCPClientInterface".to_string(),
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
                    let name = udp_config.name.clone();
                    let out_capable = udp_config.forward_ip.is_some();
                    let in_capable = udp_config.listen_ip.is_some();

                    let writer = crate::interface::udp::start(udp_config, tx.clone())?;

                    let info = InterfaceInfo {
                        id,
                        name,
                        mode: iface_mode,
                        out_capable,
                        in_capable,
                        bitrate: Some(10_000_000), // 10 Mbps guess (matches Python)
                        announce_rate_target: None,
                        announce_rate_grace: 0,
                        announce_rate_penalty: 0.0,
                        announce_cap: rns_core::constants::ANNOUNCE_CAP,
                        is_local_client: false,
                        wants_tunnel: false,
                        tunnel_id: None,
                        mtu: 1400,
                        ingress_control: true,
                        ia_freq: 0.0,
                        started: time::now(),
                    };

                    driver.engine.register_interface(info.clone());

                    if let Some(w) = writer {
                        driver.interfaces.insert(
                            id,
                            InterfaceEntry {
                                id,
                                info,
                                writer: w,
                                online: in_capable || out_capable,
                                dynamic: false,
                                ifac: ifac_state,
                                stats: InterfaceStats {
                                    started: time::now(),
                                    ..Default::default()
                                },
                                interface_type: "UDPInterface".to_string(),
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
                }
                InterfaceVariant::LocalClient(local_config) => {
                    let id = local_config.interface_id;
                    let name = local_config.name.clone();
                    let info = InterfaceInfo {
                        id,
                        name,
                        mode: iface_mode,
                        out_capable: true,
                        in_capable: true,
                        bitrate: Some(1_000_000_000),
                        announce_rate_target: None,
                        announce_rate_grace: 0,
                        announce_rate_penalty: 0.0,
                        announce_cap: rns_core::constants::ANNOUNCE_CAP,
                        is_local_client: false,
                        wants_tunnel: false,
                        tunnel_id: None,
                        mtu: 65535,
                        ingress_control: false,
                        ia_freq: 0.0,
                        started: time::now(),
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
                            ifac: ifac_state,
                            stats: InterfaceStats {
                                started: time::now(),
                                ..Default::default()
                            },
                            interface_type: "LocalInterface".to_string(),
                        },
                    );
                }
                InterfaceVariant::Serial(serial_config) => {
                    let id = serial_config.interface_id;
                    let name = serial_config.name.clone();
                    let bitrate = serial_config.speed;
                    let info = InterfaceInfo {
                        id,
                        name,
                        mode: iface_mode,
                        out_capable: true,
                        in_capable: true,
                        bitrate: Some(bitrate as u64),
                        announce_rate_target: None,
                        announce_rate_grace: 0,
                        announce_rate_penalty: 0.0,
                        announce_cap: rns_core::constants::ANNOUNCE_CAP,
                        is_local_client: false,
                        wants_tunnel: false,
                        tunnel_id: None,
                        mtu: rns_core::constants::MTU as u32,
                        ingress_control: false,
                        ia_freq: 0.0,
                        started: time::now(),
                    };

                    let writer =
                        crate::interface::serial_iface::start(serial_config, tx.clone())?;

                    driver.engine.register_interface(info.clone());
                    driver.interfaces.insert(
                        id,
                        InterfaceEntry {
                            id,
                            info,
                            writer,
                            online: false,
                            dynamic: false,
                            ifac: ifac_state,
                            stats: InterfaceStats {
                                started: time::now(),
                                ..Default::default()
                            },
                            interface_type: "SerialInterface".to_string(),
                        },
                    );
                }
                InterfaceVariant::Kiss(kiss_config) => {
                    let id = kiss_config.interface_id;
                    let name = kiss_config.name.clone();
                    let info = InterfaceInfo {
                        id,
                        name,
                        mode: iface_mode,
                        out_capable: true,
                        in_capable: true,
                        bitrate: Some(1200), // BITRATE_GUESS from Python
                        announce_rate_target: None,
                        announce_rate_grace: 0,
                        announce_rate_penalty: 0.0,
                        announce_cap: rns_core::constants::ANNOUNCE_CAP,
                        is_local_client: false,
                        wants_tunnel: false,
                        tunnel_id: None,
                        mtu: rns_core::constants::MTU as u32,
                        ingress_control: false,
                        ia_freq: 0.0,
                        started: time::now(),
                    };

                    let writer =
                        crate::interface::kiss_iface::start(kiss_config, tx.clone())?;

                    driver.engine.register_interface(info.clone());
                    driver.interfaces.insert(
                        id,
                        InterfaceEntry {
                            id,
                            info,
                            writer,
                            online: false,
                            dynamic: false,
                            ifac: ifac_state,
                            stats: InterfaceStats {
                                started: time::now(),
                                ..Default::default()
                            },
                            interface_type: "KISSInterface".to_string(),
                        },
                    );
                }
                InterfaceVariant::Pipe(pipe_config) => {
                    let id = pipe_config.interface_id;
                    let name = pipe_config.name.clone();
                    let info = InterfaceInfo {
                        id,
                        name,
                        mode: iface_mode,
                        out_capable: true,
                        in_capable: true,
                        bitrate: Some(1_000_000), // 1 Mbps guess
                        announce_rate_target: None,
                        announce_rate_grace: 0,
                        announce_rate_penalty: 0.0,
                        announce_cap: rns_core::constants::ANNOUNCE_CAP,
                        is_local_client: false,
                        wants_tunnel: false,
                        tunnel_id: None,
                        mtu: rns_core::constants::MTU as u32,
                        ingress_control: false,
                        ia_freq: 0.0,
                        started: time::now(),
                    };

                    let writer =
                        crate::interface::pipe::start(pipe_config, tx.clone())?;

                    driver.engine.register_interface(info.clone());
                    driver.interfaces.insert(
                        id,
                        InterfaceEntry {
                            id,
                            info,
                            writer,
                            online: false,
                            dynamic: false,
                            ifac: ifac_state,
                            stats: InterfaceStats {
                                started: time::now(),
                                ..Default::default()
                            },
                            interface_type: "PipeInterface".to_string(),
                        },
                    );
                }
                InterfaceVariant::RNode(rnode_config) => {
                    let name = rnode_config.name.clone();
                    let sub_writers =
                        crate::interface::rnode::start(rnode_config, tx.clone())?;

                    // For multi-subinterface RNodes, we need an IfacState per sub.
                    // Re-derive from the original config for each beyond the first.
                    let mut first = true;
                    let mut sub_index = 0u32;
                    for (sub_id, writer) in sub_writers {
                        let sub_name = if sub_index == 0 {
                            name.clone()
                        } else {
                            format!("{}/{}", name, sub_index)
                        };
                        sub_index += 1;

                        let info = InterfaceInfo {
                            id: sub_id,
                            name: sub_name,
                            mode: iface_mode,
                            out_capable: true,
                            in_capable: true,
                            bitrate: None, // LoRa bitrate depends on SF/BW, set dynamically
                            announce_rate_target: None,
                            announce_rate_grace: 0,
                            announce_rate_penalty: 0.0,
                        announce_cap: rns_core::constants::ANNOUNCE_CAP,
                        is_local_client: false,
                        wants_tunnel: false,
                        tunnel_id: None,
                        mtu: rns_core::constants::MTU as u32,
                        ingress_control: false,
                        ia_freq: 0.0,
                        started: time::now(),
                        };

                        let sub_ifac = if first {
                            first = false;
                            ifac_state.take()
                        } else if let Some(ref ic) = ifac_cfg {
                            Some(ifac::derive_ifac(
                                ic.netname.as_deref(),
                                ic.netkey.as_deref(),
                                ic.size,
                            ))
                        } else {
                            None
                        };

                        driver.engine.register_interface(info.clone());
                        driver.interfaces.insert(
                            sub_id,
                            InterfaceEntry {
                                id: sub_id,
                                info,
                                writer,
                                online: false,
                                dynamic: false,
                                ifac: sub_ifac,
                                stats: InterfaceStats {
                                    started: time::now(),
                                    ..Default::default()
                                },
                                interface_type: "RNodeInterface".to_string(),
                            },
                        );
                    }

                }
                InterfaceVariant::Backbone(backbone_config) => {
                    crate::interface::backbone::start(
                        backbone_config,
                        tx.clone(),
                        next_dynamic_id.clone(),
                    )?;
                    // Like TcpServer/LocalServer, backbone itself doesn't register
                    // as an interface; per-client interfaces are registered via InterfaceUp
                }
                InterfaceVariant::BackboneClient(config) => {
                    let id = config.interface_id;
                    let name = config.name.clone();
                    let info = InterfaceInfo {
                        id,
                        name,
                        mode: iface_mode,
                        out_capable: true,
                        in_capable: true,
                        bitrate: Some(1_000_000_000),
                        announce_rate_target: None,
                        announce_rate_grace: 0,
                        announce_rate_penalty: 0.0,
                        announce_cap: rns_core::constants::ANNOUNCE_CAP,
                        is_local_client: false,
                        wants_tunnel: false,
                        tunnel_id: None,
                        mtu: 65535,
                        ingress_control: true,
                        ia_freq: 0.0,
                        started: time::now(),
                    };

                    let writer =
                        crate::interface::backbone::start_client(config, tx.clone())?;

                    driver.engine.register_interface(info.clone());
                    driver.interfaces.insert(
                        id,
                        InterfaceEntry {
                            id,
                            info,
                            writer,
                            online: false,
                            dynamic: false,
                            ifac: ifac_state,
                            stats: InterfaceStats {
                                started: time::now(),
                                ..Default::default()
                            },
                            interface_type: "BackboneInterface".to_string(),
                        },
                    );
                }
                InterfaceVariant::Auto(auto_config) => {
                    crate::interface::auto::start(
                        auto_config,
                        tx.clone(),
                        next_dynamic_id.clone(),
                    )?;
                    // Like TcpServer, AutoInterface doesn't register itself;
                    // per-peer interfaces are registered dynamically via InterfaceUp
                }
                InterfaceVariant::I2p(i2p_config) => {
                    crate::interface::i2p::start(
                        i2p_config,
                        tx.clone(),
                        next_dynamic_id.clone(),
                    )?;
                    // Like TcpServer, I2P doesn't register itself;
                    // per-peer interfaces are registered dynamically via InterfaceUp
                }
            }
        }

        // Set up interface announcer if we have discoverable interfaces
        if !discoverable_interfaces.is_empty() {
            let transport_id = *identity.hash();
            let announcer = crate::discovery::InterfaceAnnouncer::new(
                transport_id,
                discoverable_interfaces,
            );
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
            let _ = std::fs::create_dir_all(&disc_path);
            driver.discovered_interfaces = crate::discovery::DiscoveredInterfaceStorage::new(disc_path);
        }

        // Set up management destinations if enabled
        if config.management.enable_remote_management {
            if let Some(prv_key) = identity.get_private_key() {
                let identity_hash = *identity.hash();
                let mgmt_dest = crate::management::management_dest_hash(&identity_hash);

                // Extract Ed25519 signing keys from the identity
                let sig_prv = rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(
                    &prv_key[32..64].try_into().unwrap(),
                );
                let sig_pub_bytes: [u8; 32] = identity
                    .get_public_key()
                    .unwrap()[32..64]
                    .try_into()
                    .unwrap();

                // Register as SINGLE destination in transport engine
                driver.engine.register_destination(
                    mgmt_dest,
                    rns_core::constants::DESTINATION_SINGLE,
                );
                driver.local_destinations.insert(
                    mgmt_dest,
                    rns_core::constants::DESTINATION_SINGLE,
                );

                // Register as link destination in link manager
                driver.link_manager.register_link_destination(
                    mgmt_dest,
                    sig_prv,
                    sig_pub_bytes,
                    crate::link_manager::ResourceStrategy::AcceptNone,
                );

                // Register management path hashes
                driver.link_manager.register_management_path(
                    crate::management::status_path_hash(),
                );
                driver.link_manager.register_management_path(
                    crate::management::path_path_hash(),
                );

                log::info!(
                    "Remote management enabled on {:02x?}",
                    &mgmt_dest[..4],
                );

                // Set up allowed list
                if !config.management.remote_management_allowed.is_empty() {
                    log::info!(
                        "Remote management allowed for {} identities",
                        config.management.remote_management_allowed.len(),
                    );
                }
            }
        }

        if config.management.publish_blackhole {
            if let Some(prv_key) = identity.get_private_key() {
                let identity_hash = *identity.hash();
                let bh_dest = crate::management::blackhole_dest_hash(&identity_hash);

                let sig_prv = rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(
                    &prv_key[32..64].try_into().unwrap(),
                );
                let sig_pub_bytes: [u8; 32] = identity
                    .get_public_key()
                    .unwrap()[32..64]
                    .try_into()
                    .unwrap();

                driver.engine.register_destination(
                    bh_dest,
                    rns_core::constants::DESTINATION_SINGLE,
                );
                driver.link_manager.register_link_destination(
                    bh_dest,
                    sig_prv,
                    sig_pub_bytes,
                    crate::link_manager::ResourceStrategy::AcceptNone,
                );
                driver.link_manager.register_management_path(
                    crate::management::list_path_hash(),
                );

                log::info!(
                    "Blackhole list publishing enabled on {:02x?}",
                    &bh_dest[..4],
                );
            }
        }

        // Set up probe responder if enabled
        if config.respond_to_probes && config.transport_enabled {
            let identity_hash = *identity.hash();
            let probe_dest = crate::management::probe_dest_hash(&identity_hash);

            // Register as SINGLE destination in transport engine
            driver.engine.register_destination(
                probe_dest,
                rns_core::constants::DESTINATION_SINGLE,
            );
            driver.local_destinations.insert(
                probe_dest,
                rns_core::constants::DESTINATION_SINGLE,
            );

            // Register PROVE_ALL proof strategy with transport identity
            let probe_identity = rns_crypto::identity::Identity::from_private_key(
                &identity.get_private_key().unwrap(),
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
                "Probe responder enabled on {:02x?}",
                &probe_dest[..4],
            );
        }

        // Spawn timer thread with configurable tick interval
        let tick_interval_ms = Arc::new(AtomicU64::new(1000));
        let timer_tx = tx.clone();
        let timer_interval = Arc::clone(&tick_interval_ms);
        thread::Builder::new()
            .name("rns-timer".into())
            .spawn(move || {
                loop {
                    let ms = timer_interval.load(Ordering::Relaxed);
                    thread::sleep(Duration::from_millis(ms));
                    if timer_tx.send(Event::Tick).is_err() {
                        break; // receiver dropped
                    }
                }
            })?;

        // Start LocalServer for shared instance clients if share_instance is enabled
        if config.share_instance {
            let local_server_config = LocalServerConfig {
                instance_name: config.instance_name.clone(),
                port: config.shared_instance_port,
                interface_id: rns_core::transport::types::InterfaceId(0), // Not used for server
            };
            match crate::interface::local::start_server(
                local_server_config,
                tx.clone(),
                next_dynamic_id.clone(),
            ) {
                Ok(()) => {
                    log::info!(
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

        // Start RPC server if share_instance is enabled
        let rpc_server = if config.share_instance {
            let auth_key = crate::rpc::derive_auth_key(
                &identity.get_private_key().unwrap_or([0u8; 64]),
            );
            let rpc_addr = crate::rpc::RpcAddr::Tcp("127.0.0.1".into(), config.rpc_port);
            match crate::rpc::RpcServer::start(&rpc_addr, auth_key, tx.clone()) {
                Ok(server) => {
                    log::info!("RPC server started on 127.0.0.1:{}", config.rpc_port);
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

        // Spawn driver thread
        let driver_handle = thread::Builder::new()
            .name("rns-driver".into())
            .spawn(move || {
                driver.run();
            })?;

        Ok(RnsNode {
            tx,
            driver_handle: Some(driver_handle),
            rpc_server,
            tick_interval_ms,
            probe_server,
        })
    }

    /// Query the driver for state information.
    pub fn query(&self, request: QueryRequest) -> Result<QueryResponse, SendError> {
        let (resp_tx, resp_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::Query(request, resp_tx))
            .map_err(|_| SendError)?;
        resp_rx.recv().map_err(|_| SendError)
    }

    /// Send a raw outbound packet.
    pub fn send_raw(
        &self,
        raw: Vec<u8>,
        dest_type: u8,
        attached_interface: Option<rns_core::transport::types::InterfaceId>,
    ) -> Result<(), SendError> {
        self.tx
            .send(Event::SendOutbound {
                raw,
                dest_type,
                attached_interface,
            })
            .map_err(|_| SendError)
    }

    /// Register a local destination with the transport engine.
    pub fn register_destination(
        &self,
        dest_hash: [u8; 16],
        dest_type: u8,
    ) -> Result<(), SendError> {
        self.tx
            .send(Event::RegisterDestination { dest_hash, dest_type })
            .map_err(|_| SendError)
    }

    /// Deregister a local destination.
    pub fn deregister_destination(&self, dest_hash: [u8; 16]) -> Result<(), SendError> {
        self.tx
            .send(Event::DeregisterDestination { dest_hash })
            .map_err(|_| SendError)
    }

    /// Deregister a link destination (stop accepting incoming links).
    pub fn deregister_link_destination(&self, dest_hash: [u8; 16]) -> Result<(), SendError> {
        self.tx
            .send(Event::DeregisterLinkDestination { dest_hash })
            .map_err(|_| SendError)
    }

    /// Register a link destination that can accept incoming links.
    ///
    /// `dest_hash`: the destination hash
    /// `sig_prv_bytes`: Ed25519 private signing key (32 bytes)
    /// `sig_pub_bytes`: Ed25519 public signing key (32 bytes)
    pub fn register_link_destination(
        &self,
        dest_hash: [u8; 16],
        sig_prv_bytes: [u8; 32],
        sig_pub_bytes: [u8; 32],
        resource_strategy: u8,
    ) -> Result<(), SendError> {
        self.tx
            .send(Event::RegisterLinkDestination {
                dest_hash,
                sig_prv_bytes,
                sig_pub_bytes,
                resource_strategy,
            })
            .map_err(|_| SendError)
    }

    /// Register a request handler for a given path on established links.
    pub fn register_request_handler<F>(
        &self,
        path: &str,
        allowed_list: Option<Vec<[u8; 16]>>,
        handler: F,
    ) -> Result<(), SendError>
    where
        F: Fn([u8; 16], &str, &[u8], Option<&([u8; 16], [u8; 64])>) -> Option<Vec<u8>> + Send + 'static,
    {
        self.tx
            .send(Event::RegisterRequestHandler {
                path: path.to_string(),
                allowed_list,
                handler: Box::new(handler),
            })
            .map_err(|_| SendError)
    }

    /// Create an outbound link to a destination.
    ///
    /// Returns the link_id on success.
    pub fn create_link(
        &self,
        dest_hash: [u8; 16],
        dest_sig_pub_bytes: [u8; 32],
    ) -> Result<[u8; 16], SendError> {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::CreateLink {
                dest_hash,
                dest_sig_pub_bytes,
                response_tx,
            })
            .map_err(|_| SendError)?;
        response_rx.recv().map_err(|_| SendError)
    }

    /// Send a request on an established link.
    pub fn send_request(
        &self,
        link_id: [u8; 16],
        path: &str,
        data: &[u8],
    ) -> Result<(), SendError> {
        self.tx
            .send(Event::SendRequest {
                link_id,
                path: path.to_string(),
                data: data.to_vec(),
            })
            .map_err(|_| SendError)
    }

    /// Identify on a link (reveal identity to remote peer).
    pub fn identify_on_link(
        &self,
        link_id: [u8; 16],
        identity_prv_key: [u8; 64],
    ) -> Result<(), SendError> {
        self.tx
            .send(Event::IdentifyOnLink {
                link_id,
                identity_prv_key,
            })
            .map_err(|_| SendError)
    }

    /// Tear down a link.
    pub fn teardown_link(&self, link_id: [u8; 16]) -> Result<(), SendError> {
        self.tx
            .send(Event::TeardownLink { link_id })
            .map_err(|_| SendError)
    }

    /// Send a resource on an established link.
    pub fn send_resource(
        &self,
        link_id: [u8; 16],
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
    ) -> Result<(), SendError> {
        self.tx
            .send(Event::SendResource { link_id, data, metadata })
            .map_err(|_| SendError)
    }

    /// Set the resource acceptance strategy for a link.
    ///
    /// 0 = AcceptNone, 1 = AcceptAll, 2 = AcceptApp
    pub fn set_resource_strategy(
        &self,
        link_id: [u8; 16],
        strategy: u8,
    ) -> Result<(), SendError> {
        self.tx
            .send(Event::SetResourceStrategy { link_id, strategy })
            .map_err(|_| SendError)
    }

    /// Accept or reject a pending resource (for AcceptApp strategy).
    pub fn accept_resource(
        &self,
        link_id: [u8; 16],
        resource_hash: Vec<u8>,
        accept: bool,
    ) -> Result<(), SendError> {
        self.tx
            .send(Event::AcceptResource { link_id, resource_hash, accept })
            .map_err(|_| SendError)
    }

    /// Send a channel message on a link.
    pub fn send_channel_message(
        &self,
        link_id: [u8; 16],
        msgtype: u16,
        payload: Vec<u8>,
    ) -> Result<(), SendError> {
        self.tx
            .send(Event::SendChannelMessage { link_id, msgtype, payload })
            .map_err(|_| SendError)
    }

    /// Propose a direct P2P connection to a peer via NAT hole punching.
    ///
    /// The link must be active and connected through a backbone node.
    /// If successful, a direct UDP connection will be established, bypassing the backbone.
    pub fn propose_direct_connect(&self, link_id: [u8; 16]) -> Result<(), SendError> {
        self.tx
            .send(Event::ProposeDirectConnect { link_id })
            .map_err(|_| SendError)
    }

    /// Set the policy for handling incoming direct-connect proposals.
    pub fn set_direct_connect_policy(
        &self,
        policy: crate::holepunch::orchestrator::HolePunchPolicy,
    ) -> Result<(), SendError> {
        self.tx
            .send(Event::SetDirectConnectPolicy { policy })
            .map_err(|_| SendError)
    }

    /// Send data on a link with a given context.
    pub fn send_on_link(
        &self,
        link_id: [u8; 16],
        data: Vec<u8>,
        context: u8,
    ) -> Result<(), SendError> {
        self.tx
            .send(Event::SendOnLink { link_id, data, context })
            .map_err(|_| SendError)
    }

    /// Build and broadcast an announce for a destination.
    ///
    /// The identity is used to sign the announce. Must be the identity that
    /// owns the destination (i.e. `identity.hash()` matches `dest.identity_hash`).
    pub fn announce(
        &self,
        dest: &crate::destination::Destination,
        identity: &Identity,
        app_data: Option<&[u8]>,
    ) -> Result<(), SendError> {
        let name_hash = rns_core::destination::name_hash(
            &dest.app_name,
            &dest.aspects.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        );

        let mut random_hash = [0u8; 10];
        OsRng.fill_bytes(&mut random_hash[..5]);
        // Bytes [5:10] must be the emission timestamp (seconds since epoch,
        // big-endian, truncated to 5 bytes) so that path table dedup can
        // compare announce freshness.  Matches Python: int(time.time()).to_bytes(5, "big")
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        random_hash[5..10].copy_from_slice(&now_secs.to_be_bytes()[3..8]);

        let (announce_data, _has_ratchet) = rns_core::announce::AnnounceData::pack(
            identity,
            &dest.hash.0,
            &name_hash,
            &random_hash,
            None, // no ratchet
            app_data,
        ).map_err(|_| SendError)?;

        let context_flag = rns_core::constants::FLAG_UNSET;

        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag,
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: rns_core::constants::DESTINATION_SINGLE,
            packet_type: rns_core::constants::PACKET_TYPE_ANNOUNCE,
        };

        let packet = rns_core::packet::RawPacket::pack(
            flags, 0, &dest.hash.0, None,
            rns_core::constants::CONTEXT_NONE, &announce_data,
        ).map_err(|_| SendError)?;

        self.send_raw(
            packet.raw,
            dest.dest_type.to_wire_constant(),
            None,
        )
    }

    /// Send an encrypted (SINGLE) or plaintext (PLAIN) packet to a destination.
    ///
    /// For SINGLE destinations, `dest.public_key` must be set (OUT direction).
    /// Returns the packet hash for proof tracking.
    pub fn send_packet(
        &self,
        dest: &crate::destination::Destination,
        data: &[u8],
    ) -> Result<rns_core::types::PacketHash, SendError> {
        use rns_core::types::DestinationType;

        let payload = match dest.dest_type {
            DestinationType::Single => {
                let pub_key = dest.public_key.ok_or(SendError)?;
                let remote_id = rns_crypto::identity::Identity::from_public_key(&pub_key);
                remote_id.encrypt(data, &mut OsRng).map_err(|_| SendError)?
            }
            DestinationType::Plain => data.to_vec(),
            DestinationType::Group => {
                dest.encrypt(data).map_err(|_| SendError)?
            }
        };

        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: rns_core::constants::FLAG_UNSET,
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: dest.dest_type.to_wire_constant(),
            packet_type: rns_core::constants::PACKET_TYPE_DATA,
        };

        let packet = rns_core::packet::RawPacket::pack(
            flags, 0, &dest.hash.0, None,
            rns_core::constants::CONTEXT_NONE, &payload,
        ).map_err(|_| SendError)?;

        let packet_hash = rns_core::types::PacketHash(packet.packet_hash);

        self.tx
            .send(Event::SendOutbound {
                raw: packet.raw,
                dest_type: dest.dest_type.to_wire_constant(),
                attached_interface: None,
            })
            .map_err(|_| SendError)?;

        Ok(packet_hash)
    }

    /// Register a destination with the transport engine and set its proof strategy.
    ///
    /// `signing_key` is the full 64-byte identity private key (X25519 32 bytes +
    /// Ed25519 32 bytes), needed for ProveAll/ProveApp to sign proof packets.
    pub fn register_destination_with_proof(
        &self,
        dest: &crate::destination::Destination,
        signing_key: Option<[u8; 64]>,
    ) -> Result<(), SendError> {
        // Register with transport engine
        self.register_destination(dest.hash.0, dest.dest_type.to_wire_constant())?;

        // Register proof strategy if not ProveNone
        if dest.proof_strategy != rns_core::types::ProofStrategy::ProveNone {
            self.tx
                .send(Event::RegisterProofStrategy {
                    dest_hash: dest.hash.0,
                    strategy: dest.proof_strategy,
                    signing_key,
                })
                .map_err(|_| SendError)?;
        }

        Ok(())
    }

    /// Request a path to a destination from the network.
    pub fn request_path(&self, dest_hash: &rns_core::types::DestHash) -> Result<(), SendError> {
        self.tx
            .send(Event::RequestPath { dest_hash: dest_hash.0 })
            .map_err(|_| SendError)
    }

    /// Check if a path exists to a destination (synchronous query).
    pub fn has_path(&self, dest_hash: &rns_core::types::DestHash) -> Result<bool, SendError> {
        match self.query(QueryRequest::HasPath { dest_hash: dest_hash.0 })? {
            QueryResponse::HasPath(v) => Ok(v),
            _ => Ok(false),
        }
    }

    /// Get hop count to a destination (synchronous query).
    pub fn hops_to(&self, dest_hash: &rns_core::types::DestHash) -> Result<Option<u8>, SendError> {
        match self.query(QueryRequest::HopsTo { dest_hash: dest_hash.0 })? {
            QueryResponse::HopsTo(v) => Ok(v),
            _ => Ok(None),
        }
    }

    /// Recall the identity information for a previously announced destination.
    pub fn recall_identity(
        &self,
        dest_hash: &rns_core::types::DestHash,
    ) -> Result<Option<crate::destination::AnnouncedIdentity>, SendError> {
        match self.query(QueryRequest::RecallIdentity { dest_hash: dest_hash.0 })? {
            QueryResponse::RecallIdentity(v) => Ok(v),
            _ => Ok(None),
        }
    }

    /// Load a WASM hook at runtime.
    pub fn load_hook(
        &self,
        name: String,
        wasm_bytes: Vec<u8>,
        attach_point: String,
        priority: i32,
    ) -> Result<Result<(), String>, SendError> {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::LoadHook {
                name,
                wasm_bytes,
                attach_point,
                priority,
                response_tx,
            })
            .map_err(|_| SendError)?;
        response_rx.recv().map_err(|_| SendError)
    }

    /// Unload a WASM hook at runtime.
    pub fn unload_hook(
        &self,
        name: String,
        attach_point: String,
    ) -> Result<Result<(), String>, SendError> {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::UnloadHook {
                name,
                attach_point,
                response_tx,
            })
            .map_err(|_| SendError)?;
        response_rx.recv().map_err(|_| SendError)
    }

    /// Reload a WASM hook at runtime (detach + recompile + reattach with same priority).
    pub fn reload_hook(
        &self,
        name: String,
        attach_point: String,
        wasm_bytes: Vec<u8>,
    ) -> Result<Result<(), String>, SendError> {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::ReloadHook {
                name,
                attach_point,
                wasm_bytes,
                response_tx,
            })
            .map_err(|_| SendError)?;
        response_rx.recv().map_err(|_| SendError)
    }

    /// List all loaded hooks.
    pub fn list_hooks(&self) -> Result<Vec<crate::event::HookInfo>, SendError> {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::ListHooks { response_tx })
            .map_err(|_| SendError)?;
        response_rx.recv().map_err(|_| SendError)
    }

    /// Construct an RnsNode from its constituent parts.
    /// Used by `shared_client` to build a client-mode node.
    pub(crate) fn from_parts(
        tx: EventSender,
        driver_handle: thread::JoinHandle<()>,
        rpc_server: Option<crate::rpc::RpcServer>,
        tick_interval_ms: Arc<AtomicU64>,
    ) -> Self {
        RnsNode {
            tx,
            driver_handle: Some(driver_handle),
            rpc_server,
            tick_interval_ms,
            probe_server: None,
        }
    }

    /// Get the event sender for direct event injection.
    pub fn event_sender(&self) -> &EventSender {
        &self.tx
    }

    /// Set the tick interval in milliseconds.
    /// Default is 1000 (1 second). Changes take effect on the next tick cycle.
    /// Values are clamped to the range 100..=10000.
    /// Returns the actual stored value (which may differ from `ms` if clamped).
    pub fn set_tick_interval(&self, ms: u64) -> u64 {
        let clamped = ms.clamp(100, 10_000);
        if clamped != ms {
            log::warn!(
                "tick interval {}ms out of range, clamped to {}ms",
                ms,
                clamped
            );
        }
        self.tick_interval_ms.store(clamped, Ordering::Relaxed);
        clamped
    }

    /// Get the current tick interval in milliseconds.
    pub fn tick_interval(&self) -> u64 {
        self.tick_interval_ms.load(Ordering::Relaxed)
    }

    /// Shut down the node. Blocks until the driver thread exits.
    pub fn shutdown(mut self) {
        // Stop RPC server first
        if let Some(mut rpc) = self.rpc_server.take() {
            rpc.stop();
        }
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
        fn on_announce(&mut self, _: crate::destination::AnnouncedIdentity) {}
        fn on_path_updated(&mut self, _: rns_core::types::DestHash, _: u8) {}
        fn on_local_delivery(&mut self, _: rns_core::types::DestHash, _: Vec<u8>, _: rns_core::types::PacketHash) {}
    }

    #[test]
    fn start_and_shutdown() {
        let node = RnsNode::start(
            NodeConfig {
                transport_enabled: false,
                identity: None,
                interfaces: vec![],
                share_instance: false,
                instance_name: "default".into(),
                shared_instance_port: 37428,
                rpc_port: 0,
                cache_dir: None,
                management: Default::default(),
                probe_port: None,
                probe_addr: None,
                device: None,
                hooks: Vec::new(),
                discover_interfaces: false,
                discovery_required_value: None,
            respond_to_probes: false,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
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
                share_instance: false,
                instance_name: "default".into(),
                shared_instance_port: 37428,
                rpc_port: 0,
                cache_dir: None,
                management: Default::default(),
                probe_port: None,
                probe_addr: None,
                device: None,
                hooks: Vec::new(),
                discover_interfaces: false,
                discovery_required_value: None,
            respond_to_probes: false,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
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
                share_instance: false,
                instance_name: "default".into(),
                shared_instance_port: 37428,
                rpc_port: 0,
                cache_dir: None,
                management: Default::default(),
                probe_port: None,
                probe_addr: None,
                device: None,
                hooks: Vec::new(),
                discover_interfaces: false,
                discovery_required_value: None,
            respond_to_probes: false,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
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

    #[test]
    fn to_node_config_serial() {
        // Verify from_config parses SerialInterface correctly.
        // The serial port won't exist, so start() will fail, but the config
        // parsing path is exercised. We verify via the error (not a config error).
        let dir = std::env::temp_dir().join(format!("rns-test-serial-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let config = r#"
[reticulum]
enable_transport = False

[interfaces]
  [[Test Serial Port]]
    type = SerialInterface
    port = /dev/nonexistent_rns_test_serial
    speed = 115200
    databits = 8
    parity = E
    stopbits = 1
    interface_mode = ptp
    networkname = testnet
"#;
        fs::write(dir.join("config"), config).unwrap();

        let result = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks));
        // Should fail because the serial port doesn't exist, not because of config parsing
        match result {
            Ok(node) => {
                node.shutdown();
                panic!("Expected error from non-existent serial port");
            }
            Err(err) => {
                let msg = format!("{}", err);
                assert!(
                    !msg.contains("Unsupported") && !msg.contains("parse"),
                    "Error should be from serial open, got: {}",
                    msg
                );
            }
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn to_node_config_kiss() {
        // Verify from_config parses KISSInterface correctly.
        let dir = std::env::temp_dir().join(format!("rns-test-kiss-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let config = r#"
[reticulum]
enable_transport = False

[interfaces]
  [[Test KISS TNC]]
    type = KISSInterface
    port = /dev/nonexistent_rns_test_kiss
    speed = 9600
    preamble = 500
    txtail = 30
    persistence = 128
    slottime = 40
    flow_control = True
    id_interval = 600
    id_callsign = TEST0
    interface_mode = full
    passphrase = secretkey
"#;
        fs::write(dir.join("config"), config).unwrap();

        let result = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks));
        // Should fail because the serial port doesn't exist
        match result {
            Ok(node) => {
                node.shutdown();
                panic!("Expected error from non-existent serial port");
            }
            Err(err) => {
                let msg = format!("{}", err);
                assert!(
                    !msg.contains("Unsupported") && !msg.contains("parse"),
                    "Error should be from serial open, got: {}",
                    msg
                );
            }
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_extract_ifac_config() {
        use std::collections::HashMap;

        // No IFAC params → None
        let params: HashMap<String, String> = HashMap::new();
        assert!(extract_ifac_config(&params, 16).is_none());

        // networkname only
        let mut params = HashMap::new();
        params.insert("networkname".into(), "testnet".into());
        let ifac = extract_ifac_config(&params, 16).unwrap();
        assert_eq!(ifac.netname.as_deref(), Some("testnet"));
        assert!(ifac.netkey.is_none());
        assert_eq!(ifac.size, 16);

        // passphrase only with custom size (in bits)
        let mut params = HashMap::new();
        params.insert("passphrase".into(), "secret".into());
        params.insert("ifac_size".into(), "64".into()); // 64 bits = 8 bytes
        let ifac = extract_ifac_config(&params, 16).unwrap();
        assert!(ifac.netname.is_none());
        assert_eq!(ifac.netkey.as_deref(), Some("secret"));
        assert_eq!(ifac.size, 8);

        // Both with alternate key names
        let mut params = HashMap::new();
        params.insert("network_name".into(), "mynet".into());
        params.insert("pass_phrase".into(), "mykey".into());
        let ifac = extract_ifac_config(&params, 8).unwrap();
        assert_eq!(ifac.netname.as_deref(), Some("mynet"));
        assert_eq!(ifac.netkey.as_deref(), Some("mykey"));
        assert_eq!(ifac.size, 8);
    }

    #[test]
    fn test_parse_parity() {
        assert_eq!(parse_parity("E"), Parity::Even);
        assert_eq!(parse_parity("even"), Parity::Even);
        assert_eq!(parse_parity("O"), Parity::Odd);
        assert_eq!(parse_parity("odd"), Parity::Odd);
        assert_eq!(parse_parity("N"), Parity::None);
        assert_eq!(parse_parity("none"), Parity::None);
        assert_eq!(parse_parity("unknown"), Parity::None);
    }

    #[test]
    fn to_node_config_rnode() {
        // Verify from_config parses RNodeInterface correctly.
        // The serial port won't exist, so start() will fail at open time.
        let dir = std::env::temp_dir().join(format!("rns-test-rnode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let config = r#"
[reticulum]
enable_transport = False

[interfaces]
  [[Test RNode]]
    type = RNodeInterface
    port = /dev/nonexistent_rns_test_rnode
    frequency = 867200000
    bandwidth = 125000
    txpower = 7
    spreadingfactor = 8
    codingrate = 5
    flow_control = True
    st_alock = 5.0
    lt_alock = 2.5
    interface_mode = full
    networkname = testnet
"#;
        fs::write(dir.join("config"), config).unwrap();

        let result = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks));
        // Should fail because the serial port doesn't exist, not because of config parsing
        match result {
            Ok(node) => {
                node.shutdown();
                panic!("Expected error from non-existent serial port");
            }
            Err(err) => {
                let msg = format!("{}", err);
                assert!(
                    !msg.contains("Unsupported") && !msg.contains("parse"),
                    "Error should be from serial open, got: {}",
                    msg
                );
            }
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn to_node_config_pipe() {
        // Verify from_config parses PipeInterface correctly.
        // Use `cat` as a real command so it actually starts.
        let dir = std::env::temp_dir().join(format!("rns-test-pipe-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let config = r#"
[reticulum]
enable_transport = False

[interfaces]
  [[Test Pipe]]
    type = PipeInterface
    command = cat
    respawn_delay = 5000
    interface_mode = full
"#;
        fs::write(dir.join("config"), config).unwrap();

        let node = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks)).unwrap();
        // If we got here, config parsing and start() succeeded
        node.shutdown();

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn to_node_config_backbone() {
        // Verify from_config parses BackboneInterface correctly.
        let dir = std::env::temp_dir().join(format!("rns-test-backbone-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

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
  [[Test Backbone]]
    type = BackboneInterface
    listen_ip = 127.0.0.1
    listen_port = {}
    interface_mode = full
"#,
            port
        );

        fs::write(dir.join("config"), config).unwrap();

        let node = RnsNode::from_config(Some(&dir), Box::new(NoopCallbacks)).unwrap();

        // Give server time to start
        thread::sleep(Duration::from_millis(100));

        // Should be able to connect
        {
            let _client = std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
            // client drops here, closing the connection cleanly
        }

        // Small delay to let epoll process the disconnect
        thread::sleep(Duration::from_millis(50));

        node.shutdown();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rnode_config_defaults() {
        use crate::interface::rnode::{RNodeConfig, RNodeSubConfig};

        let config = RNodeConfig::default();
        assert_eq!(config.speed, 115200);
        assert!(config.subinterfaces.is_empty());
        assert!(config.id_interval.is_none());
        assert!(config.id_callsign.is_none());

        let sub = RNodeSubConfig {
            name: "test".into(),
            frequency: 868_000_000,
            bandwidth: 125_000,
            txpower: 7,
            spreading_factor: 8,
            coding_rate: 5,
            flow_control: false,
            st_alock: None,
            lt_alock: None,
        };
        assert_eq!(sub.frequency, 868_000_000);
        assert_eq!(sub.bandwidth, 125_000);
        assert!(!sub.flow_control);
    }

    // =========================================================================
    // Phase 9c: Announce + Discovery node-level tests
    // =========================================================================

    #[test]
    fn announce_builds_valid_packet() {
        let identity = Identity::new(&mut OsRng);
        let identity_hash = rns_core::types::IdentityHash(*identity.hash());

        let node = RnsNode::start(
            NodeConfig {
                transport_enabled: false,
                identity: None,
                interfaces: vec![],
                share_instance: false,
                instance_name: "default".into(),
                shared_instance_port: 37428,
                rpc_port: 0,
                cache_dir: None,
                management: Default::default(),
                probe_port: None,
                probe_addr: None,
                device: None,
                hooks: Vec::new(),
                discover_interfaces: false,
                discovery_required_value: None,
            respond_to_probes: false,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
            },
            Box::new(NoopCallbacks),
        ).unwrap();

        let dest = crate::destination::Destination::single_in(
            "test", &["echo"], identity_hash,
        );

        // Register destination first
        node.register_destination(dest.hash.0, dest.dest_type.to_wire_constant()).unwrap();

        // Announce should succeed (though no interfaces to send on)
        let result = node.announce(&dest, &identity, Some(b"hello"));
        assert!(result.is_ok());

        node.shutdown();
    }

    #[test]
    fn has_path_and_hops_to() {
        let node = RnsNode::start(
            NodeConfig {
                transport_enabled: false,
                identity: None,
                interfaces: vec![],
                share_instance: false,
                instance_name: "default".into(),
                shared_instance_port: 37428,
                rpc_port: 0,
                cache_dir: None,
                management: Default::default(),
                probe_port: None,
                probe_addr: None,
                device: None,
                hooks: Vec::new(),
                discover_interfaces: false,
                discovery_required_value: None,
            respond_to_probes: false,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
            },
            Box::new(NoopCallbacks),
        ).unwrap();

        let dh = rns_core::types::DestHash([0xAA; 16]);

        // No path should exist
        assert_eq!(node.has_path(&dh).unwrap(), false);
        assert_eq!(node.hops_to(&dh).unwrap(), None);

        node.shutdown();
    }

    #[test]
    fn recall_identity_none_when_unknown() {
        let node = RnsNode::start(
            NodeConfig {
                transport_enabled: false,
                identity: None,
                interfaces: vec![],
                share_instance: false,
                instance_name: "default".into(),
                shared_instance_port: 37428,
                rpc_port: 0,
                cache_dir: None,
                management: Default::default(),
                probe_port: None,
                probe_addr: None,
                device: None,
                hooks: Vec::new(),
                discover_interfaces: false,
                discovery_required_value: None,
            respond_to_probes: false,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
            },
            Box::new(NoopCallbacks),
        ).unwrap();

        let dh = rns_core::types::DestHash([0xBB; 16]);
        assert!(node.recall_identity(&dh).unwrap().is_none());

        node.shutdown();
    }

    #[test]
    fn request_path_does_not_crash() {
        let node = RnsNode::start(
            NodeConfig {
                transport_enabled: false,
                identity: None,
                interfaces: vec![],
                share_instance: false,
                instance_name: "default".into(),
                shared_instance_port: 37428,
                rpc_port: 0,
                cache_dir: None,
                management: Default::default(),
                probe_port: None,
                probe_addr: None,
                device: None,
                hooks: Vec::new(),
                discover_interfaces: false,
                discovery_required_value: None,
            respond_to_probes: false,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
            },
            Box::new(NoopCallbacks),
        ).unwrap();

        let dh = rns_core::types::DestHash([0xCC; 16]);
        assert!(node.request_path(&dh).is_ok());

        // Small wait for the event to be processed
        thread::sleep(Duration::from_millis(50));

        node.shutdown();
    }

    // =========================================================================
    // Phase 9d: send_packet + register_destination_with_proof tests
    // =========================================================================

    #[test]
    fn send_packet_plain() {
        let node = RnsNode::start(
            NodeConfig {
                transport_enabled: false,
                identity: None,
                interfaces: vec![],
                share_instance: false,
                instance_name: "default".into(),
                shared_instance_port: 37428,
                rpc_port: 0,
                cache_dir: None,
                management: Default::default(),
                probe_port: None,
                probe_addr: None,
                device: None,
                hooks: Vec::new(),
                discover_interfaces: false,
                discovery_required_value: None,
            respond_to_probes: false,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
            },
            Box::new(NoopCallbacks),
        ).unwrap();

        let dest = crate::destination::Destination::plain("test", &["echo"]);
        let result = node.send_packet(&dest, b"hello world");
        assert!(result.is_ok());

        let packet_hash = result.unwrap();
        // Packet hash should be non-zero
        assert_ne!(packet_hash.0, [0u8; 32]);

        // Small wait for the event to be processed
        thread::sleep(Duration::from_millis(50));

        node.shutdown();
    }

    #[test]
    fn send_packet_single_requires_public_key() {
        let node = RnsNode::start(
            NodeConfig {
                transport_enabled: false,
                identity: None,
                interfaces: vec![],
                share_instance: false,
                instance_name: "default".into(),
                shared_instance_port: 37428,
                rpc_port: 0,
                cache_dir: None,
                management: Default::default(),
                probe_port: None,
                probe_addr: None,
                device: None,
                hooks: Vec::new(),
                discover_interfaces: false,
                discovery_required_value: None,
            respond_to_probes: false,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
            },
            Box::new(NoopCallbacks),
        ).unwrap();

        // single_in has no public_key — sending should fail
        let dest = crate::destination::Destination::single_in(
            "test", &["echo"],
            rns_core::types::IdentityHash([0x42; 16]),
        );
        let result = node.send_packet(&dest, b"hello");
        assert!(result.is_err(), "single_in has no public_key, should fail");

        node.shutdown();
    }

    #[test]
    fn send_packet_single_encrypts() {
        let node = RnsNode::start(
            NodeConfig {
                transport_enabled: false,
                identity: None,
                interfaces: vec![],
                share_instance: false,
                instance_name: "default".into(),
                shared_instance_port: 37428,
                rpc_port: 0,
                cache_dir: None,
                management: Default::default(),
                probe_port: None,
                probe_addr: None,
                device: None,
                hooks: Vec::new(),
                discover_interfaces: false,
                discovery_required_value: None,
            respond_to_probes: false,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
            },
            Box::new(NoopCallbacks),
        ).unwrap();

        // Create a proper OUT SINGLE destination with a real identity's public key
        let remote_identity = Identity::new(&mut OsRng);
        let recalled = crate::destination::AnnouncedIdentity {
            dest_hash: rns_core::types::DestHash([0xAA; 16]),
            identity_hash: rns_core::types::IdentityHash(*remote_identity.hash()),
            public_key: remote_identity.get_public_key().unwrap(),
            app_data: None,
            hops: 1,
            received_at: 0.0,
        };
        let dest = crate::destination::Destination::single_out("test", &["echo"], &recalled);

        let result = node.send_packet(&dest, b"secret message");
        assert!(result.is_ok());

        let packet_hash = result.unwrap();
        assert_ne!(packet_hash.0, [0u8; 32]);

        thread::sleep(Duration::from_millis(50));
        node.shutdown();
    }

    #[test]
    fn register_destination_with_proof_prove_all() {
        let node = RnsNode::start(
            NodeConfig {
                transport_enabled: false,
                identity: None,
                interfaces: vec![],
                share_instance: false,
                instance_name: "default".into(),
                shared_instance_port: 37428,
                rpc_port: 0,
                cache_dir: None,
                management: Default::default(),
                probe_port: None,
                probe_addr: None,
                device: None,
                hooks: Vec::new(),
                discover_interfaces: false,
                discovery_required_value: None,
            respond_to_probes: false,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
            },
            Box::new(NoopCallbacks),
        ).unwrap();

        let identity = Identity::new(&mut OsRng);
        let ih = rns_core::types::IdentityHash(*identity.hash());
        let dest = crate::destination::Destination::single_in("echo", &["request"], ih)
            .set_proof_strategy(rns_core::types::ProofStrategy::ProveAll);
        let prv_key = identity.get_private_key().unwrap();

        let result = node.register_destination_with_proof(&dest, Some(prv_key));
        assert!(result.is_ok());

        // Small wait for the events to be processed
        thread::sleep(Duration::from_millis(50));

        node.shutdown();
    }

    #[test]
    fn register_destination_with_proof_prove_none() {
        let node = RnsNode::start(
            NodeConfig {
                transport_enabled: false,
                identity: None,
                interfaces: vec![],
                share_instance: false,
                instance_name: "default".into(),
                shared_instance_port: 37428,
                rpc_port: 0,
                cache_dir: None,
                management: Default::default(),
                probe_port: None,
                probe_addr: None,
                device: None,
                hooks: Vec::new(),
                discover_interfaces: false,
                discovery_required_value: None,
            respond_to_probes: false,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
            },
            Box::new(NoopCallbacks),
        ).unwrap();

        // ProveNone should not send RegisterProofStrategy event
        let dest = crate::destination::Destination::plain("test", &["data"])
            .set_proof_strategy(rns_core::types::ProofStrategy::ProveNone);

        let result = node.register_destination_with_proof(&dest, None);
        assert!(result.is_ok());

        thread::sleep(Duration::from_millis(50));
        node.shutdown();
    }
}
