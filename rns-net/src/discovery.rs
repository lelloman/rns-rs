//! Interface Discovery protocol implementation.
//!
//! Handles receiving, validating, and storing discovered interface announcements
//! from other Reticulum nodes on the network.
//!
//! Python reference: RNS/Discovery.py

use std::fs;
use std::io;
use std::path::PathBuf;

use rns_core::msgpack::{self, Value};
use rns_core::stamp::{stamp_valid, stamp_value, stamp_workblock};
use rns_crypto::sha256::sha256;

use crate::time;

// ============================================================================
// Constants (matching Python Discovery.py)
// ============================================================================

/// Discovery field IDs for msgpack encoding
pub const NAME: u8 = 0xFF;
pub const TRANSPORT_ID: u8 = 0xFE;
pub const INTERFACE_TYPE: u8 = 0x00;
pub const TRANSPORT: u8 = 0x01;
pub const REACHABLE_ON: u8 = 0x02;
pub const LATITUDE: u8 = 0x03;
pub const LONGITUDE: u8 = 0x04;
pub const HEIGHT: u8 = 0x05;
pub const PORT: u8 = 0x06;
pub const IFAC_NETNAME: u8 = 0x07;
pub const IFAC_NETKEY: u8 = 0x08;
pub const FREQUENCY: u8 = 0x09;
pub const BANDWIDTH: u8 = 0x0A;
pub const SPREADINGFACTOR: u8 = 0x0B;
pub const CODINGRATE: u8 = 0x0C;
pub const MODULATION: u8 = 0x0D;
pub const CHANNEL: u8 = 0x0E;

/// App name for discovery destination
pub const APP_NAME: &str = "rnstransport";

/// Default stamp value for interface discovery
pub const DEFAULT_STAMP_VALUE: u8 = 14;

/// Workblock expand rounds for interface discovery
pub const WORKBLOCK_EXPAND_ROUNDS: u32 = 20;

/// Stamp size in bytes
pub const STAMP_SIZE: usize = 32;

// Status thresholds (in seconds)
/// 24 hours - status becomes "unknown"
pub const THRESHOLD_UNKNOWN: f64 = 24.0 * 60.0 * 60.0;
/// 3 days - status becomes "stale"
pub const THRESHOLD_STALE: f64 = 3.0 * 24.0 * 60.0 * 60.0;
/// 7 days - interface is removed
pub const THRESHOLD_REMOVE: f64 = 7.0 * 24.0 * 60.0 * 60.0;

// Status codes for sorting
const STATUS_STALE: i32 = 0;
const STATUS_UNKNOWN: i32 = 100;
const STATUS_AVAILABLE: i32 = 1000;

// ============================================================================
// Per-interface discovery configuration
// ============================================================================

/// Per-interface discovery configuration parsed from config file.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Human-readable name to advertise (defaults to interface name).
    pub discovery_name: String,
    /// Announce interval in seconds (default 21600 = 6h, min 300 = 5min).
    pub announce_interval: u64,
    /// Stamp cost for discovery PoW (default 14).
    pub stamp_value: u8,
    /// IP/hostname this interface is reachable on.
    pub reachable_on: Option<String>,
    /// Interface type string (e.g. "BackboneInterface").
    pub interface_type: String,
    /// Listen port of the discoverable interface.
    pub listen_port: Option<u16>,
    /// Geographic latitude in decimal degrees.
    pub latitude: Option<f64>,
    /// Geographic longitude in decimal degrees.
    pub longitude: Option<f64>,
    /// Height/altitude in meters.
    pub height: Option<f64>,
}

// ============================================================================
// Data Structures
// ============================================================================

/// Status of a discovered interface
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveredStatus {
    Available,
    Unknown,
    Stale,
}

impl DiscoveredStatus {
    /// Get numeric code for sorting (higher = better)
    pub fn code(&self) -> i32 {
        match self {
            DiscoveredStatus::Available => STATUS_AVAILABLE,
            DiscoveredStatus::Unknown => STATUS_UNKNOWN,
            DiscoveredStatus::Stale => STATUS_STALE,
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            DiscoveredStatus::Available => "available",
            DiscoveredStatus::Unknown => "unknown",
            DiscoveredStatus::Stale => "stale",
        }
    }
}

/// Information about a discovered interface
#[derive(Debug, Clone)]
pub struct DiscoveredInterface {
    /// Interface type (e.g., "BackboneInterface", "TCPServerInterface", "RNodeInterface")
    pub interface_type: String,
    /// Whether the announcing node has transport enabled
    pub transport: bool,
    /// Human-readable name of the interface
    pub name: String,
    /// Timestamp when first discovered
    pub discovered: f64,
    /// Timestamp of last announcement
    pub last_heard: f64,
    /// Number of times heard
    pub heard_count: u32,
    /// Current status based on last_heard
    pub status: DiscoveredStatus,
    /// Raw stamp bytes
    pub stamp: Vec<u8>,
    /// Calculated stamp value (leading zeros)
    pub stamp_value: u32,
    /// Transport identity hash (truncated)
    pub transport_id: [u8; 16],
    /// Network identity hash (announcer)
    pub network_id: [u8; 16],
    /// Number of hops to reach this interface
    pub hops: u8,

    // Optional location info
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub height: Option<f64>,

    // Connection info
    pub reachable_on: Option<String>,
    pub port: Option<u16>,

    // RNode/RF specific
    pub frequency: Option<u32>,
    pub bandwidth: Option<u32>,
    pub spreading_factor: Option<u8>,
    pub coding_rate: Option<u8>,
    pub modulation: Option<String>,
    pub channel: Option<u8>,

    // IFAC info
    pub ifac_netname: Option<String>,
    pub ifac_netkey: Option<String>,

    // Auto-generated config entry
    pub config_entry: Option<String>,

    /// Hash for storage key (SHA256 of transport_id + name)
    pub discovery_hash: [u8; 32],
}

impl DiscoveredInterface {
    /// Compute the current status based on last_heard timestamp
    pub fn compute_status(&self) -> DiscoveredStatus {
        let delta = time::now() - self.last_heard;
        if delta > THRESHOLD_STALE {
            DiscoveredStatus::Stale
        } else if delta > THRESHOLD_UNKNOWN {
            DiscoveredStatus::Unknown
        } else {
            DiscoveredStatus::Available
        }
    }
}

// ============================================================================
// Storage
// ============================================================================

/// Persistent storage for discovered interfaces
pub struct DiscoveredInterfaceStorage {
    base_path: PathBuf,
}

impl DiscoveredInterfaceStorage {
    /// Create a new storage instance
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    /// Store a discovered interface
    pub fn store(&self, iface: &DiscoveredInterface) -> io::Result<()> {
        let filename = hex_encode(&iface.discovery_hash);
        let filepath = self.base_path.join(filename);

        let data = self.serialize_interface(iface)?;
        fs::write(&filepath, &data)
    }

    /// Load a discovered interface by its discovery hash
    pub fn load(&self, discovery_hash: &[u8; 32]) -> io::Result<Option<DiscoveredInterface>> {
        let filename = hex_encode(discovery_hash);
        let filepath = self.base_path.join(filename);

        if !filepath.exists() {
            return Ok(None);
        }

        let data = fs::read(&filepath)?;
        self.deserialize_interface(&data).map(Some)
    }

    /// List all discovered interfaces
    pub fn list(&self) -> io::Result<Vec<DiscoveredInterface>> {
        let mut interfaces = Vec::new();

        let entries = match fs::read_dir(&self.base_path) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(interfaces),
            Err(e) => return Err(e),
        };

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            match fs::read(&path) {
                Ok(data) => {
                    if let Ok(iface) = self.deserialize_interface(&data) {
                        interfaces.push(iface);
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(interfaces)
    }

    /// Remove a discovered interface by its discovery hash
    pub fn remove(&self, discovery_hash: &[u8; 32]) -> io::Result<()> {
        let filename = hex_encode(discovery_hash);
        let filepath = self.base_path.join(filename);

        if filepath.exists() {
            fs::remove_file(&filepath)?;
        }
        Ok(())
    }

    /// Clean up stale entries (older than THRESHOLD_REMOVE)
    /// Returns the number of entries removed
    pub fn cleanup(&self) -> io::Result<usize> {
        let mut removed = 0;
        let now = time::now();

        let interfaces = self.list()?;
        for iface in interfaces {
            if now - iface.last_heard > THRESHOLD_REMOVE {
                self.remove(&iface.discovery_hash)?;
                removed += 1;
            }
        }

        Ok(removed)
    }

    /// Serialize an interface to msgpack
    fn serialize_interface(&self, iface: &DiscoveredInterface) -> io::Result<Vec<u8>> {
        let mut entries: Vec<(Value, Value)> = Vec::new();

        entries.push((Value::Str("type".into()), Value::Str(iface.interface_type.clone())));
        entries.push((Value::Str("transport".into()), Value::Bool(iface.transport)));
        entries.push((Value::Str("name".into()), Value::Str(iface.name.clone())));
        entries.push((Value::Str("discovered".into()), Value::Float(iface.discovered)));
        entries.push((Value::Str("last_heard".into()), Value::Float(iface.last_heard)));
        entries.push((Value::Str("heard_count".into()), Value::UInt(iface.heard_count as u64)));
        entries.push((Value::Str("status".into()), Value::Str(iface.status.as_str().into())));
        entries.push((Value::Str("stamp".into()), Value::Bin(iface.stamp.clone())));
        entries.push((Value::Str("value".into()), Value::UInt(iface.stamp_value as u64)));
        entries.push((Value::Str("transport_id".into()), Value::Bin(iface.transport_id.to_vec())));
        entries.push((Value::Str("network_id".into()), Value::Bin(iface.network_id.to_vec())));
        entries.push((Value::Str("hops".into()), Value::UInt(iface.hops as u64)));

        if let Some(v) = iface.latitude {
            entries.push((Value::Str("latitude".into()), Value::Float(v)));
        }
        if let Some(v) = iface.longitude {
            entries.push((Value::Str("longitude".into()), Value::Float(v)));
        }
        if let Some(v) = iface.height {
            entries.push((Value::Str("height".into()), Value::Float(v)));
        }
        if let Some(ref v) = iface.reachable_on {
            entries.push((Value::Str("reachable_on".into()), Value::Str(v.clone())));
        }
        if let Some(v) = iface.port {
            entries.push((Value::Str("port".into()), Value::UInt(v as u64)));
        }
        if let Some(v) = iface.frequency {
            entries.push((Value::Str("frequency".into()), Value::UInt(v as u64)));
        }
        if let Some(v) = iface.bandwidth {
            entries.push((Value::Str("bandwidth".into()), Value::UInt(v as u64)));
        }
        if let Some(v) = iface.spreading_factor {
            entries.push((Value::Str("sf".into()), Value::UInt(v as u64)));
        }
        if let Some(v) = iface.coding_rate {
            entries.push((Value::Str("cr".into()), Value::UInt(v as u64)));
        }
        if let Some(ref v) = iface.modulation {
            entries.push((Value::Str("modulation".into()), Value::Str(v.clone())));
        }
        if let Some(v) = iface.channel {
            entries.push((Value::Str("channel".into()), Value::UInt(v as u64)));
        }
        if let Some(ref v) = iface.ifac_netname {
            entries.push((Value::Str("ifac_netname".into()), Value::Str(v.clone())));
        }
        if let Some(ref v) = iface.ifac_netkey {
            entries.push((Value::Str("ifac_netkey".into()), Value::Str(v.clone())));
        }
        if let Some(ref v) = iface.config_entry {
            entries.push((Value::Str("config_entry".into()), Value::Str(v.clone())));
        }

        entries.push((Value::Str("discovery_hash".into()), Value::Bin(iface.discovery_hash.to_vec())));

        Ok(msgpack::pack(&Value::Map(entries)))
    }

    /// Deserialize an interface from msgpack
    fn deserialize_interface(&self, data: &[u8]) -> io::Result<DiscoveredInterface> {
        let (value, _) = msgpack::unpack(data).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("msgpack error: {}", e))
        })?;

        // Helper functions using map_get
        let get_str = |v: &Value, key: &str| -> io::Result<String> {
            v.map_get(key)
                .and_then(|val| val.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{} not a string", key)))
        };

        let get_opt_str = |v: &Value, key: &str| -> Option<String> {
            v.map_get(key).and_then(|val| val.as_str().map(|s| s.to_string()))
        };

        let get_bool = |v: &Value, key: &str| -> io::Result<bool> {
            v.map_get(key)
                .and_then(|val| val.as_bool())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{} not a bool", key)))
        };

        let get_float = |v: &Value, key: &str| -> io::Result<f64> {
            v.map_get(key)
                .and_then(|val| val.as_float())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{} not a float", key)))
        };

        let get_opt_float = |v: &Value, key: &str| -> Option<f64> {
            v.map_get(key).and_then(|val| val.as_float())
        };

        let get_uint = |v: &Value, key: &str| -> io::Result<u64> {
            v.map_get(key)
                .and_then(|val| val.as_uint())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{} not a uint", key)))
        };

        let get_opt_uint = |v: &Value, key: &str| -> Option<u64> {
            v.map_get(key).and_then(|val| val.as_uint())
        };

        let get_bytes = |v: &Value, key: &str| -> io::Result<Vec<u8>> {
            v.map_get(key)
                .and_then(|val| val.as_bin())
                .map(|b| b.to_vec())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{} not bytes", key)))
        };

        let transport_id_bytes = get_bytes(&value, "transport_id")?;
        let mut transport_id = [0u8; 16];
        if transport_id_bytes.len() == 16 {
            transport_id.copy_from_slice(&transport_id_bytes);
        }

        let network_id_bytes = get_bytes(&value, "network_id")?;
        let mut network_id = [0u8; 16];
        if network_id_bytes.len() == 16 {
            network_id.copy_from_slice(&network_id_bytes);
        }

        let discovery_hash_bytes = get_bytes(&value, "discovery_hash")?;
        let mut discovery_hash = [0u8; 32];
        if discovery_hash_bytes.len() == 32 {
            discovery_hash.copy_from_slice(&discovery_hash_bytes);
        }

        let status_str = get_str(&value, "status")?;
        let status = match status_str.as_str() {
            "available" => DiscoveredStatus::Available,
            "unknown" => DiscoveredStatus::Unknown,
            "stale" => DiscoveredStatus::Stale,
            _ => DiscoveredStatus::Unknown,
        };

        Ok(DiscoveredInterface {
            interface_type: get_str(&value, "type")?,
            transport: get_bool(&value, "transport")?,
            name: get_str(&value, "name")?,
            discovered: get_float(&value, "discovered")?,
            last_heard: get_float(&value, "last_heard")?,
            heard_count: get_uint(&value, "heard_count")? as u32,
            status,
            stamp: get_bytes(&value, "stamp")?,
            stamp_value: get_uint(&value, "value")? as u32,
            transport_id,
            network_id,
            hops: get_uint(&value, "hops")? as u8,
            latitude: get_opt_float(&value, "latitude"),
            longitude: get_opt_float(&value, "longitude"),
            height: get_opt_float(&value, "height"),
            reachable_on: get_opt_str(&value, "reachable_on"),
            port: get_opt_uint(&value, "port").map(|v| v as u16),
            frequency: get_opt_uint(&value, "frequency").map(|v| v as u32),
            bandwidth: get_opt_uint(&value, "bandwidth").map(|v| v as u32),
            spreading_factor: get_opt_uint(&value, "sf").map(|v| v as u8),
            coding_rate: get_opt_uint(&value, "cr").map(|v| v as u8),
            modulation: get_opt_str(&value, "modulation"),
            channel: get_opt_uint(&value, "channel").map(|v| v as u8),
            ifac_netname: get_opt_str(&value, "ifac_netname"),
            ifac_netkey: get_opt_str(&value, "ifac_netkey"),
            config_entry: get_opt_str(&value, "config_entry"),
            discovery_hash,
        })
    }
}

// ============================================================================
// Parsing and Validation
// ============================================================================

/// Parse an interface discovery announcement from app_data.
///
/// Returns None if:
/// - Data is too short
/// - Stamp is invalid
/// - Required fields are missing
pub fn parse_interface_announce(
    app_data: &[u8],
    announced_identity_hash: &[u8; 16],
    hops: u8,
    required_stamp_value: u8,
) -> Option<DiscoveredInterface> {
    // Need at least: 1 byte flags + some data + STAMP_SIZE
    if app_data.len() <= STAMP_SIZE + 1 {
        return None;
    }

    // Extract flags and payload
    let flags = app_data[0];
    let payload = &app_data[1..];

    // Check encryption flag (we don't support encrypted discovery yet)
    let encrypted = (flags & 0x02) != 0;
    if encrypted {
        log::debug!("Ignoring encrypted discovered interface (not supported)");
        return None;
    }

    // Split stamp and packed info
    let stamp = &payload[payload.len() - STAMP_SIZE..];
    let packed = &payload[..payload.len() - STAMP_SIZE];

    // Compute infohash and workblock
    let infohash = sha256(packed);
    let workblock = stamp_workblock(&infohash, WORKBLOCK_EXPAND_ROUNDS);

    // Validate stamp
    if !stamp_valid(stamp, required_stamp_value, &workblock) {
        log::debug!("Ignoring discovered interface with invalid stamp");
        return None;
    }

    // Calculate stamp value
    let stamp_value = stamp_value(&workblock, stamp);

    // Unpack the interface info
    let (value, _) = msgpack::unpack(packed).ok()?;
    let map = value.as_map()?;

    // Helper to get a value from the map by integer key
    let get_u8_val = |key: u8| -> Option<Value> {
        for (k, v) in map {
            if k.as_uint()? as u8 == key {
                return Some(v.clone());
            }
        }
        None
    };

    // Extract required fields
    let interface_type = get_u8_val(INTERFACE_TYPE)?.as_str()?.to_string();
    let transport = get_u8_val(TRANSPORT)?.as_bool()?;
    let name = get_u8_val(NAME)?
        .as_str()
        .unwrap_or(&format!("Discovered {}", interface_type))
        .to_string();

    let transport_id_val = get_u8_val(TRANSPORT_ID)?;
    let transport_id_bytes = transport_id_val.as_bin()?;
    let mut transport_id = [0u8; 16];
    if transport_id_bytes.len() >= 16 {
        transport_id.copy_from_slice(&transport_id_bytes[..16]);
    }

    // Extract optional fields
    let latitude = get_u8_val(LATITUDE).and_then(|v| v.as_float());
    let longitude = get_u8_val(LONGITUDE).and_then(|v| v.as_float());
    let height = get_u8_val(HEIGHT).and_then(|v| v.as_float());
    let reachable_on = get_u8_val(REACHABLE_ON).and_then(|v| v.as_str().map(|s| s.to_string()));
    let port = get_u8_val(PORT).and_then(|v| v.as_uint().map(|n| n as u16));
    let frequency = get_u8_val(FREQUENCY).and_then(|v| v.as_uint().map(|n| n as u32));
    let bandwidth = get_u8_val(BANDWIDTH).and_then(|v| v.as_uint().map(|n| n as u32));
    let spreading_factor = get_u8_val(SPREADINGFACTOR).and_then(|v| v.as_uint().map(|n| n as u8));
    let coding_rate = get_u8_val(CODINGRATE).and_then(|v| v.as_uint().map(|n| n as u8));
    let modulation = get_u8_val(MODULATION).and_then(|v| v.as_str().map(|s| s.to_string()));
    let channel = get_u8_val(CHANNEL).and_then(|v| v.as_uint().map(|n| n as u8));
    let ifac_netname = get_u8_val(IFAC_NETNAME).and_then(|v| v.as_str().map(|s| s.to_string()));
    let ifac_netkey = get_u8_val(IFAC_NETKEY).and_then(|v| v.as_str().map(|s| s.to_string()));

    // Compute discovery hash
    let discovery_hash = compute_discovery_hash(&transport_id, &name);

    // Generate config entry
    let config_entry = generate_config_entry(
        &interface_type,
        &name,
        &transport_id,
        reachable_on.as_deref(),
        port,
        frequency,
        bandwidth,
        spreading_factor,
        coding_rate,
        modulation.as_deref(),
        ifac_netname.as_deref(),
        ifac_netkey.as_deref(),
    );

    let now = time::now();

    Some(DiscoveredInterface {
        interface_type,
        transport,
        name,
        discovered: now,
        last_heard: now,
        heard_count: 0,
        status: DiscoveredStatus::Available,
        stamp: stamp.to_vec(),
        stamp_value,
        transport_id,
        network_id: *announced_identity_hash,
        hops,
        latitude,
        longitude,
        height,
        reachable_on,
        port,
        frequency,
        bandwidth,
        spreading_factor,
        coding_rate,
        modulation,
        channel,
        ifac_netname,
        ifac_netkey,
        config_entry,
        discovery_hash,
    })
}

/// Compute the discovery hash for storage
pub fn compute_discovery_hash(transport_id: &[u8; 16], name: &str) -> [u8; 32] {
    let mut material = Vec::with_capacity(16 + name.len());
    material.extend_from_slice(transport_id);
    material.extend_from_slice(name.as_bytes());
    sha256(&material)
}

/// Generate a config entry for auto-connecting to a discovered interface
fn generate_config_entry(
    interface_type: &str,
    name: &str,
    transport_id: &[u8; 16],
    reachable_on: Option<&str>,
    port: Option<u16>,
    frequency: Option<u32>,
    bandwidth: Option<u32>,
    spreading_factor: Option<u8>,
    coding_rate: Option<u8>,
    modulation: Option<&str>,
    ifac_netname: Option<&str>,
    ifac_netkey: Option<&str>,
) -> Option<String> {
    let transport_id_hex = hex_encode(transport_id);
    let netname_str = ifac_netname.map(|n| format!("\n  network_name = {}", n)).unwrap_or_default();
    let netkey_str = ifac_netkey.map(|k| format!("\n  passphrase = {}", k)).unwrap_or_default();
    let identity_str = format!("\n  transport_identity = {}", transport_id_hex);

    match interface_type {
        "BackboneInterface" | "TCPServerInterface" => {
            let reachable = reachable_on.unwrap_or("unknown");
            let port_val = port.unwrap_or(4242);
            Some(format!(
                "[[{}]]\n  type = BackboneInterface\n  enabled = yes\n  remote = {}\n  target_port = {}{}{}{}",
                name, reachable, port_val, identity_str, netname_str, netkey_str
            ))
        }
        "I2PInterface" => {
            let reachable = reachable_on.unwrap_or("unknown");
            Some(format!(
                "[[{}]]\n  type = I2PInterface\n  enabled = yes\n  peers = {}{}{}{}",
                name, reachable, identity_str, netname_str, netkey_str
            ))
        }
        "RNodeInterface" => {
            let freq_str = frequency.map(|f| format!("\n  frequency = {}", f)).unwrap_or_default();
            let bw_str = bandwidth.map(|b| format!("\n  bandwidth = {}", b)).unwrap_or_default();
            let sf_str = spreading_factor.map(|s| format!("\n  spreadingfactor = {}", s)).unwrap_or_default();
            let cr_str = coding_rate.map(|c| format!("\n  codingrate = {}", c)).unwrap_or_default();
            Some(format!(
                "[[{}]]\n  type = RNodeInterface\n  enabled = yes\n  port = {}{}{}{}{}{}{}{}",
                name, "", freq_str, bw_str, sf_str, cr_str, identity_str, netname_str, netkey_str
            ))
        }
        "KISSInterface" => {
            let freq_str = frequency.map(|f| format!("\n  # Frequency: {}", f)).unwrap_or_default();
            let bw_str = bandwidth.map(|b| format!("\n  # Bandwidth: {}", b)).unwrap_or_default();
            let mod_str = modulation.map(|m| format!("\n  # Modulation: {}", m)).unwrap_or_default();
            Some(format!(
                "[[{}]]\n  type = KISSInterface\n  enabled = yes\n  port = {}{}{}{}{}{}{}",
                name, "", freq_str, bw_str, mod_str, identity_str, netname_str, netkey_str
            ))
        }
        "WeaveInterface" => {
            Some(format!(
                "[[{}]]\n  type = WeaveInterface\n  enabled = yes\n  port = {}{}{}{}",
                name, "", identity_str, netname_str, netkey_str
            ))
        }
        _ => None,
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Encode bytes as hex string (no delimiters)
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Check if a string is a valid IP address
pub fn is_ip_address(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// Check if a string is a valid hostname
pub fn is_hostname(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.len() > 253 {
        return false;
    }
    let components: Vec<&str> = s.split('.').collect();
    if components.is_empty() {
        return false;
    }
    // Last component should not be all numeric
    if components.last().map(|c| c.chars().all(|ch| ch.is_ascii_digit())).unwrap_or(false) {
        return false;
    }
    components.iter().all(|c| {
        !c.is_empty()
            && c.len() <= 63
            && !c.starts_with('-')
            && !c.ends_with('-')
            && c.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    })
}

/// Filter and sort discovered interfaces
pub fn filter_and_sort_interfaces(
    interfaces: &mut Vec<DiscoveredInterface>,
    only_available: bool,
    only_transport: bool,
) {
    let now = time::now();

    // Update status and filter
    interfaces.retain(|iface| {
        let delta = now - iface.last_heard;

        // Check for removal threshold
        if delta > THRESHOLD_REMOVE {
            return false;
        }

        // Update status
        let status = iface.compute_status();

        // Apply filters
        if only_available && status != DiscoveredStatus::Available {
            return false;
        }
        if only_transport && !iface.transport {
            return false;
        }

        true
    });

    // Sort by (status_code desc, value desc, last_heard desc)
    interfaces.sort_by(|a, b| {
        let status_cmp = b.compute_status().code().cmp(&a.compute_status().code());
        if status_cmp != std::cmp::Ordering::Equal {
            return status_cmp;
        }
        let value_cmp = b.stamp_value.cmp(&a.stamp_value);
        if value_cmp != std::cmp::Ordering::Equal {
            return value_cmp;
        }
        b.last_heard.partial_cmp(&a.last_heard).unwrap_or(std::cmp::Ordering::Equal)
    });
}

// ============================================================================
// Stamp Generation (parallel PoW search)
// ============================================================================

/// Generate a discovery stamp with the given cost using rayon parallel iterators.
///
/// Returns `(stamp, value)` on success. This is a blocking, CPU-intensive operation.
pub fn generate_discovery_stamp(
    packed_data: &[u8],
    stamp_cost: u8,
) -> ([u8; STAMP_SIZE], u32) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use rns_crypto::{OsRng, Rng};

    let infohash = sha256(packed_data);
    let workblock = stamp_workblock(&infohash, WORKBLOCK_EXPAND_ROUNDS);

    let found: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let result: Arc<Mutex<Option<[u8; STAMP_SIZE]>>> = Arc::new(Mutex::new(None));

    let num_threads = rayon::current_num_threads();

    rayon::scope(|s| {
        for _ in 0..num_threads {
            let found = found.clone();
            let result = result.clone();
            let workblock = &workblock;
            s.spawn(move |_| {
                let mut rng = OsRng;
                let mut nonce = [0u8; STAMP_SIZE];
                loop {
                    if found.load(Ordering::Relaxed) {
                        return;
                    }
                    rng.fill_bytes(&mut nonce);
                    if stamp_valid(&nonce, stamp_cost, workblock) {
                        let mut r = result.lock().unwrap();
                        if r.is_none() {
                            *r = Some(nonce);
                        }
                        found.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            });
        }
    });

    let stamp = result.lock().unwrap().take().expect("stamp search must find result");
    let value = stamp_value(&workblock, &stamp);
    (stamp, value)
}

// ============================================================================
// Interface Announcer
// ============================================================================

/// Info about a single discoverable interface, ready for announcing.
#[derive(Debug, Clone)]
pub struct DiscoverableInterface {
    pub config: DiscoveryConfig,
    /// Whether the node has transport enabled.
    pub transport_enabled: bool,
    /// IFAC network name, if configured.
    pub ifac_netname: Option<String>,
    /// IFAC passphrase, if configured.
    pub ifac_netkey: Option<String>,
}

/// Result of a completed background stamp generation.
pub struct StampResult {
    /// Index of the interface this stamp is for.
    pub index: usize,
    /// The complete app_data: [flags][packed][stamp].
    pub app_data: Vec<u8>,
}

/// Manages periodic announcing of discoverable interfaces.
///
/// Stamp generation (PoW) runs on a background thread so it never blocks the
/// driver event loop.  The driver calls `poll_ready()` each tick to collect
/// finished results.
pub struct InterfaceAnnouncer {
    /// Transport identity hash (16 bytes).
    transport_id: [u8; 16],
    /// Discoverable interfaces with their configs.
    interfaces: Vec<DiscoverableInterface>,
    /// Last announce time per interface (indexed same as `interfaces`).
    last_announced: Vec<f64>,
    /// Receiver for completed stamp results from background threads.
    stamp_rx: std::sync::mpsc::Receiver<StampResult>,
    /// Sender cloned into background threads.
    stamp_tx: std::sync::mpsc::Sender<StampResult>,
    /// Whether a background stamp job is currently running.
    stamp_pending: bool,
}

impl InterfaceAnnouncer {
    /// Create a new announcer.
    pub fn new(transport_id: [u8; 16], interfaces: Vec<DiscoverableInterface>) -> Self {
        let n = interfaces.len();
        let (stamp_tx, stamp_rx) = std::sync::mpsc::channel();
        InterfaceAnnouncer {
            transport_id,
            interfaces,
            last_announced: vec![0.0; n],
            stamp_rx,
            stamp_tx,
            stamp_pending: false,
        }
    }

    /// If any interface is due for an announce and no stamp job is already
    /// running, spawns a background thread for PoW.  The result will be
    /// available via `poll_ready()`.
    pub fn maybe_start(&mut self, now: f64) {
        if self.stamp_pending {
            return;
        }
        let due_index = self.interfaces.iter().enumerate().find_map(|(i, iface)| {
            let elapsed = now - self.last_announced[i];
            if elapsed >= iface.config.announce_interval as f64 {
                Some(i)
            } else {
                None
            }
        });

        if let Some(idx) = due_index {
            let packed = self.pack_interface_info(idx);
            let stamp_cost = self.interfaces[idx].config.stamp_value;
            let name = self.interfaces[idx].config.discovery_name.clone();
            let tx = self.stamp_tx.clone();

            log::info!(
                "Spawning discovery stamp generation (cost={}) for '{}'...",
                stamp_cost,
                name,
            );

            self.stamp_pending = true;
            self.last_announced[idx] = now;

            std::thread::spawn(move || {
                let (stamp, value) = generate_discovery_stamp(&packed, stamp_cost);
                log::info!(
                    "Discovery stamp generated (value={}) for '{}'",
                    value,
                    name,
                );

                let flags: u8 = 0x00; // no encryption
                let mut app_data = Vec::with_capacity(1 + packed.len() + STAMP_SIZE);
                app_data.push(flags);
                app_data.extend_from_slice(&packed);
                app_data.extend_from_slice(&stamp);

                let _ = tx.send(StampResult {
                    index: idx,
                    app_data,
                });
            });
        }
    }

    /// Non-blocking poll: returns completed app_data if a background stamp
    /// job has finished.
    pub fn poll_ready(&mut self) -> Option<StampResult> {
        match self.stamp_rx.try_recv() {
            Ok(result) => {
                self.stamp_pending = false;
                Some(result)
            }
            Err(_) => None,
        }
    }

    /// Pack interface metadata as msgpack map with integer keys.
    fn pack_interface_info(&self, index: usize) -> Vec<u8> {
        let iface = &self.interfaces[index];
        let mut entries: Vec<(msgpack::Value, msgpack::Value)> = Vec::new();

        entries.push((
            msgpack::Value::UInt(INTERFACE_TYPE as u64),
            msgpack::Value::Str(iface.config.interface_type.clone()),
        ));
        entries.push((
            msgpack::Value::UInt(TRANSPORT as u64),
            msgpack::Value::Bool(iface.transport_enabled),
        ));
        entries.push((
            msgpack::Value::UInt(NAME as u64),
            msgpack::Value::Str(iface.config.discovery_name.clone()),
        ));
        entries.push((
            msgpack::Value::UInt(TRANSPORT_ID as u64),
            msgpack::Value::Bin(self.transport_id.to_vec()),
        ));
        if let Some(ref reachable) = iface.config.reachable_on {
            entries.push((
                msgpack::Value::UInt(REACHABLE_ON as u64),
                msgpack::Value::Str(reachable.clone()),
            ));
        }
        if let Some(port) = iface.config.listen_port {
            entries.push((
                msgpack::Value::UInt(PORT as u64),
                msgpack::Value::UInt(port as u64),
            ));
        }
        if let Some(lat) = iface.config.latitude {
            entries.push((
                msgpack::Value::UInt(LATITUDE as u64),
                msgpack::Value::Float(lat),
            ));
        }
        if let Some(lon) = iface.config.longitude {
            entries.push((
                msgpack::Value::UInt(LONGITUDE as u64),
                msgpack::Value::Float(lon),
            ));
        }
        if let Some(h) = iface.config.height {
            entries.push((
                msgpack::Value::UInt(HEIGHT as u64),
                msgpack::Value::Float(h),
            ));
        }
        if let Some(ref netname) = iface.ifac_netname {
            entries.push((
                msgpack::Value::UInt(IFAC_NETNAME as u64),
                msgpack::Value::Str(netname.clone()),
            ));
        }
        if let Some(ref netkey) = iface.ifac_netkey {
            entries.push((
                msgpack::Value::UInt(IFAC_NETKEY as u64),
                msgpack::Value::Str(netkey.clone()),
            ));
        }

        msgpack::pack(&msgpack::Value::Map(entries))
    }

}

/// Compute the name hash for the discovery destination: `rnstransport.discovery.interface`.
///
/// Discovery is a SINGLE destination — its dest hash varies with the sender's identity.
/// We match incoming announces by comparing their name_hash to this constant.
pub fn discovery_name_hash() -> [u8; 10] {
    rns_core::destination::name_hash(APP_NAME, &["discovery", "interface"])
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0x12]), "00ff12");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn test_compute_discovery_hash() {
        let transport_id = [0x42u8; 16];
        let name = "TestInterface";
        let hash = compute_discovery_hash(&transport_id, name);

        // Should be deterministic
        let hash2 = compute_discovery_hash(&transport_id, name);
        assert_eq!(hash, hash2);

        // Different name should give different hash
        let hash3 = compute_discovery_hash(&transport_id, "OtherInterface");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_is_ip_address() {
        assert!(is_ip_address("192.168.1.1"));
        assert!(is_ip_address("::1"));
        assert!(is_ip_address("2001:db8::1"));
        assert!(!is_ip_address("not-an-ip"));
        assert!(!is_ip_address("hostname.example.com"));
    }

    #[test]
    fn test_is_hostname() {
        assert!(is_hostname("example.com"));
        assert!(is_hostname("sub.example.com"));
        assert!(is_hostname("my-node"));
        assert!(is_hostname("my-node.example.com"));
        assert!(!is_hostname(""));
        assert!(!is_hostname("-invalid"));
        assert!(!is_hostname("invalid-"));
        assert!(!is_hostname("a".repeat(300).as_str()));
    }

    #[test]
    fn test_discovered_status() {
        let now = time::now();

        let mut iface = DiscoveredInterface {
            interface_type: "TestInterface".into(),
            transport: true,
            name: "Test".into(),
            discovered: now,
            last_heard: now,
            heard_count: 0,
            status: DiscoveredStatus::Available,
            stamp: vec![],
            stamp_value: 14,
            transport_id: [0u8; 16],
            network_id: [0u8; 16],
            hops: 0,
            latitude: None,
            longitude: None,
            height: None,
            reachable_on: None,
            port: None,
            frequency: None,
            bandwidth: None,
            spreading_factor: None,
            coding_rate: None,
            modulation: None,
            channel: None,
            ifac_netname: None,
            ifac_netkey: None,
            config_entry: None,
            discovery_hash: [0u8; 32],
        };

        // Fresh interface should be available
        assert_eq!(iface.compute_status(), DiscoveredStatus::Available);

        // 25 hours old should be unknown
        iface.last_heard = now - THRESHOLD_UNKNOWN - 3600.0;
        assert_eq!(iface.compute_status(), DiscoveredStatus::Unknown);

        // 4 days old should be stale
        iface.last_heard = now - THRESHOLD_STALE - 3600.0;
        assert_eq!(iface.compute_status(), DiscoveredStatus::Stale);
    }

    #[test]
    fn test_storage_roundtrip() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rns-discovery-test-{}-{}", std::process::id(), id));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let storage = DiscoveredInterfaceStorage::new(dir.clone());

        let mut iface = DiscoveredInterface {
            interface_type: "BackboneInterface".into(),
            transport: true,
            name: "TestNode".into(),
            discovered: 1700000000.0,
            last_heard: 1700001000.0,
            heard_count: 5,
            status: DiscoveredStatus::Available,
            stamp: vec![0x42u8; 64],
            stamp_value: 18,
            transport_id: [0x01u8; 16],
            network_id: [0x02u8; 16],
            hops: 2,
            latitude: Some(45.0),
            longitude: Some(9.0),
            height: Some(100.0),
            reachable_on: Some("example.com".into()),
            port: Some(4242),
            frequency: None,
            bandwidth: None,
            spreading_factor: None,
            coding_rate: None,
            modulation: None,
            channel: None,
            ifac_netname: Some("mynetwork".into()),
            ifac_netkey: Some("secretkey".into()),
            config_entry: Some("test config".into()),
            discovery_hash: compute_discovery_hash(&[0x01u8; 16], "TestNode"),
        };

        // Store
        storage.store(&iface).unwrap();

        // Load
        let loaded = storage.load(&iface.discovery_hash).unwrap().unwrap();

        assert_eq!(loaded.interface_type, iface.interface_type);
        assert_eq!(loaded.name, iface.name);
        assert_eq!(loaded.stamp_value, iface.stamp_value);
        assert_eq!(loaded.transport_id, iface.transport_id);
        assert_eq!(loaded.hops, iface.hops);
        assert_eq!(loaded.latitude, iface.latitude);
        assert_eq!(loaded.reachable_on, iface.reachable_on);
        assert_eq!(loaded.port, iface.port);

        // List
        let list = storage.list().unwrap();
        assert_eq!(list.len(), 1);

        // Remove
        storage.remove(&iface.discovery_hash).unwrap();
        let list = storage.list().unwrap();
        assert!(list.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_filter_and_sort() {
        let now = time::now();

        let ifaces = vec![
            DiscoveredInterface {
                interface_type: "A".into(),
                transport: true,
                name: "high-value-stale".into(),
                discovered: now,
                last_heard: now - THRESHOLD_STALE - 100.0, // Stale
                heard_count: 0,
                status: DiscoveredStatus::Stale,
                stamp: vec![],
                stamp_value: 20,
                transport_id: [0u8; 16],
                network_id: [0u8; 16],
                hops: 0,
                latitude: None,
                longitude: None,
                height: None,
                reachable_on: None,
                port: None,
                frequency: None,
                bandwidth: None,
                spreading_factor: None,
                coding_rate: None,
                modulation: None,
                channel: None,
                ifac_netname: None,
                ifac_netkey: None,
                config_entry: None,
                discovery_hash: [0u8; 32],
            },
            DiscoveredInterface {
                interface_type: "B".into(),
                transport: true,
                name: "low-value-available".into(),
                discovered: now,
                last_heard: now,
                heard_count: 0,
                status: DiscoveredStatus::Available,
                stamp: vec![],
                stamp_value: 10,
                transport_id: [0u8; 16],
                network_id: [0u8; 16],
                hops: 0,
                latitude: None,
                longitude: None,
                height: None,
                reachable_on: None,
                port: None,
                frequency: None,
                bandwidth: None,
                spreading_factor: None,
                coding_rate: None,
                modulation: None,
                channel: None,
                ifac_netname: None,
                ifac_netkey: None,
                config_entry: None,
                discovery_hash: [0u8; 32],
            },
            DiscoveredInterface {
                interface_type: "C".into(),
                transport: false,
                name: "no-transport".into(),
                discovered: now,
                last_heard: now,
                heard_count: 0,
                status: DiscoveredStatus::Available,
                stamp: vec![],
                stamp_value: 15,
                transport_id: [0u8; 16],
                network_id: [0u8; 16],
                hops: 0,
                latitude: None,
                longitude: None,
                height: None,
                reachable_on: None,
                port: None,
                frequency: None,
                bandwidth: None,
                spreading_factor: None,
                coding_rate: None,
                modulation: None,
                channel: None,
                ifac_netname: None,
                ifac_netkey: None,
                config_entry: None,
                discovery_hash: [0u8; 32],
            },
        ];

        // Test only_available filter
        let mut filtered = ifaces.clone();
        filter_and_sort_interfaces(&mut filtered, true, false);
        // Should exclude stale
        assert_eq!(filtered.len(), 2);

        // Test only_transport filter
        let mut filtered = ifaces.clone();
        filter_and_sort_interfaces(&mut filtered, false, true);
        // Should exclude no-transport
        assert_eq!(filtered.len(), 2);

        // Test both filters
        let mut filtered = ifaces.clone();
        filter_and_sort_interfaces(&mut filtered, true, true);
        // Should have only low-value-available
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "low-value-available");
    }

    #[test]
    fn test_discovery_name_hash_is_deterministic() {
        let h1 = discovery_name_hash();
        let h2 = discovery_name_hash();
        assert_eq!(h1, h2);
        // Must be 10 bytes (name hash length)
        assert_eq!(h1.len(), 10);
        // Verify it matches the name hash for "rnstransport.discovery.interface"
        let expected = rns_core::destination::name_hash(
            APP_NAME,
            &["discovery", "interface"],
        );
        assert_eq!(h1, expected);
    }

    #[test]
    fn test_announcer_next_due_and_maybe_start() {
        let transport_id = [0xABu8; 16];
        let iface = DiscoverableInterface {
            config: DiscoveryConfig {
                discovery_name: "TestBB".into(),
                announce_interval: 600, // 10 minutes
                stamp_value: 8,         // low cost for fast test
                reachable_on: Some("10.0.0.1".into()),
                interface_type: "BackboneInterface".into(),
                listen_port: Some(4242),
                latitude: None,
                longitude: None,
                height: None,
            },
            transport_enabled: true,
            ifac_netname: None,
            ifac_netkey: None,
        };
        let mut announcer = InterfaceAnnouncer::new(transport_id, vec![iface]);

        // At t=0 all interfaces are due (last_announced = 0.0, interval = 600)
        // maybe_start should kick off a background thread
        announcer.maybe_start(1000.0);
        assert!(announcer.stamp_pending);

        // Calling again while pending should be a no-op
        announcer.maybe_start(1000.0);
        assert!(announcer.stamp_pending);

        // Wait for the stamp to complete (low cost = fast)
        let result = announcer.stamp_rx.recv_timeout(std::time::Duration::from_secs(30))
            .expect("stamp generation timed out");
        assert_eq!(result.index, 0);
        assert!(!result.app_data.is_empty());
        // First byte is flags
        assert_eq!(result.app_data[0], 0x00);
        // Last 64 bytes are stamp
        assert!(result.app_data.len() > STAMP_SIZE + 1);

        // Clear the pending flag via poll_ready
        announcer.stamp_pending = false;

        // After announcing at t=1000, should not be due until t=1600
        assert!(announcer.poll_ready().is_none()); // channel already drained
    }

    #[test]
    fn test_pack_parse_roundtrip() {
        // Build announce data via the announcer, then parse it back
        let transport_id = [0x42u8; 16];
        let identity_hash = [0xFFu8; 16];
        let iface = DiscoverableInterface {
            config: DiscoveryConfig {
                discovery_name: "RoundtripNode".into(),
                announce_interval: 300,
                stamp_value: 8, // low for fast test
                reachable_on: Some("192.168.1.100".into()),
                interface_type: "TCPServerInterface".into(),
                listen_port: Some(5555),
                latitude: Some(45.464),
                longitude: Some(9.190),
                height: Some(120.0),
            },
            transport_enabled: true,
            ifac_netname: Some("testnet".into()),
            ifac_netkey: Some("secretkey".into()),
        };
        let mut announcer = InterfaceAnnouncer::new(transport_id, vec![iface]);

        // Kick off stamp generation
        announcer.maybe_start(1000.0);
        let result = announcer.stamp_rx.recv_timeout(std::time::Duration::from_secs(30))
            .expect("stamp generation timed out");

        // Parse the app_data back through parse_interface_announce
        let discovered = parse_interface_announce(
            &result.app_data,
            &identity_hash,
            0, // hops
            8, // required stamp value matches what we generated
        ).expect("parse_interface_announce should succeed on our own data");

        assert_eq!(discovered.interface_type, "TCPServerInterface");
        assert_eq!(discovered.name, "RoundtripNode");
        assert_eq!(discovered.transport, true);
        assert_eq!(discovered.transport_id, transport_id);
        assert_eq!(discovered.network_id, identity_hash);
        assert_eq!(discovered.reachable_on.as_deref(), Some("192.168.1.100"));
        assert_eq!(discovered.port, Some(5555));
        assert_eq!(discovered.ifac_netname.as_deref(), Some("testnet"));
        assert_eq!(discovered.ifac_netkey.as_deref(), Some("secretkey"));
        assert!(discovered.stamp_value >= 8);
        assert_eq!(discovered.hops, 0);
        assert!((discovered.latitude.unwrap() - 45.464).abs() < 0.001);
        assert!((discovered.longitude.unwrap() - 9.190).abs() < 0.001);
        assert!((discovered.height.unwrap() - 120.0).abs() < 0.1);
    }
}
