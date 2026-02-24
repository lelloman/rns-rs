//! Interface Discovery protocol — pure types and parsing logic.
//!
//! Contains constants, data structures, parsing, and validation functions
//! for the interface discovery protocol. No filesystem or threading I/O.
//!
//! Python reference: RNS/Discovery.py

use rns_core::msgpack::{self, Value};
use rns_core::stamp::{stamp_valid, stamp_value, stamp_workblock};
use rns_crypto::sha256::sha256;

use super::time;

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
pub fn hex_encode(bytes: &[u8]) -> String {
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

/// Compute the name hash for the discovery destination: `rnstransport.discovery.interface`.
///
/// Discovery is a SINGLE destination — its dest hash varies with the sender's identity.
/// We match incoming announces by comparing their name_hash to this constant.
pub fn discovery_name_hash() -> [u8; 10] {
    rns_core::destination::name_hash(APP_NAME, &["discovery", "interface"])
}
