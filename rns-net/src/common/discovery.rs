//! Interface Discovery protocol — pure types and parsing logic.
//!
//! Contains constants, data structures, parsing, and validation functions
//! for the interface discovery protocol. No filesystem or threading I/O.
//!
//! Python reference: RNS/Discovery.py

use std::collections::{BTreeMap, BTreeSet, VecDeque};

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
pub const DEFAULT_STAMP_VALUE: u8 = 16;

/// Workblock expand rounds for interface discovery
pub const WORKBLOCK_EXPAND_ROUNDS: u32 = 20;

/// Stamp size in bytes
pub const STAMP_SIZE: usize = 32;

/// Maximum number of known-invalid discovery payloads retained by default.
pub const DISCOVERY_STAMP_CACHE_MAX_ENTRIES: usize = 2048;

/// Interface types accepted from discovery announces.
pub const DISCOVERABLE_TYPES: [&str; 6] = [
    "BackboneInterface",
    "TCPServerInterface",
    "I2PInterface",
    "RNodeInterface",
    "WeaveInterface",
    "KISSInterface",
];

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
    /// Stamp cost for discovery PoW (default 16).
    pub stamp_value: u8,
    /// IP/hostname this interface is reachable on.
    pub reachable_on: Option<String>,
    /// Interface type string (e.g. "BackboneInterface").
    pub interface_type: String,
    /// Listen port of the discoverable interface.
    pub listen_port: Option<u16>,
    /// Executable that resolves `latitude,longitude,height` for each announce.
    pub location_cmd: Option<String>,
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

fn insufficient_stamp_diagnostic(value: u32) -> String {
    format!("Ignored discovered interface with insufficient stamp value {value}")
}

/// Bounded FIFO cache for discovery payloads with invalid proof-of-work stamps.
///
/// The key is the full SHA-256 hash of the discovery payload after its flags
/// byte, matching upstream Reticulum. It therefore includes the stamp itself,
/// while harmless changes to the flags byte do not bypass the cache.
#[derive(Debug, Clone)]
pub struct DiscoveryStampCache {
    capacity: usize,
    valid_order: VecDeque<[u8; 32]>,
    valid_entries: BTreeMap<[u8; 32], ValidStampEntry>,
    invalid_order: VecDeque<[u8; 32]>,
    invalid_entries: BTreeSet<[u8; 32]>,
}

#[derive(Debug, Clone)]
struct ValidStampEntry {
    stamp: Vec<u8>,
    packed: Vec<u8>,
    value: u32,
}

impl Default for DiscoveryStampCache {
    fn default() -> Self {
        Self::with_capacity(DISCOVERY_STAMP_CACHE_MAX_ENTRIES)
    }
}

impl DiscoveryStampCache {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            valid_order: VecDeque::with_capacity(capacity),
            valid_entries: BTreeMap::new(),
            invalid_order: VecDeque::with_capacity(capacity),
            invalid_entries: BTreeSet::new(),
        }
    }

    fn payload_hash(app_data: &[u8]) -> Option<[u8; 32]> {
        app_data
            .get(1..)
            .filter(|payload| !payload.is_empty())
            .map(sha256)
    }

    fn contains_invalid_hash(&self, payload_hash: &[u8; 32]) -> bool {
        self.invalid_entries.contains(payload_hash)
    }

    fn valid_entry(&self, payload_hash: &[u8; 32]) -> Option<&ValidStampEntry> {
        self.valid_entries.get(payload_hash)
    }

    fn insert_valid_hash(&mut self, payload_hash: [u8; 32], entry: ValidStampEntry) {
        if self.capacity == 0 || self.valid_entries.contains_key(&payload_hash) {
            return;
        }
        if self.valid_order.len() == self.capacity {
            if let Some(evicted) = self.valid_order.pop_front() {
                self.valid_entries.remove(&evicted);
            }
        }
        self.valid_order.push_back(payload_hash);
        self.valid_entries.insert(payload_hash, entry);
    }

    fn insert_invalid_hash(&mut self, payload_hash: [u8; 32]) {
        if self.capacity == 0 || self.invalid_entries.contains(&payload_hash) {
            return;
        }
        if self.invalid_order.len() == self.capacity {
            if let Some(evicted) = self.invalid_order.pop_front() {
                self.invalid_entries.remove(&evicted);
            }
        }
        self.invalid_order.push_back(payload_hash);
        self.invalid_entries.insert(payload_hash);
    }

    pub fn invalid_len(&self) -> usize {
        self.invalid_order.len()
    }

    pub fn valid_len(&self) -> usize {
        self.valid_order.len()
    }

    pub fn contains_invalid_app_data(&self, app_data: &[u8]) -> bool {
        Self::payload_hash(app_data)
            .is_some_and(|payload_hash| self.contains_invalid_hash(&payload_hash))
    }

    pub fn contains_valid_app_data(&self, app_data: &[u8]) -> bool {
        Self::payload_hash(app_data)
            .is_some_and(|payload_hash| self.valid_entries.contains_key(&payload_hash))
    }
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
    let mut cache = DiscoveryStampCache::with_capacity(0);
    parse_interface_announce_with_cache(
        app_data,
        announced_identity_hash,
        hops,
        required_stamp_value,
        &mut cache,
    )
}

/// Parse an interface discovery announcement while retaining invalid stamp
/// results across calls.
pub fn parse_interface_announce_with_cache(
    app_data: &[u8],
    announced_identity_hash: &[u8; 16],
    hops: u8,
    required_stamp_value: u8,
    cache: &mut DiscoveryStampCache,
) -> Option<DiscoveredInterface> {
    // Need at least: 1 byte flags + some data + STAMP_SIZE
    if app_data.len() <= STAMP_SIZE + 1 {
        return None;
    }

    // Extract flags and payload
    let flags = app_data[0];
    let payload = &app_data[1..];
    let payload_hash = sha256(payload);

    if cache.contains_invalid_hash(&payload_hash) {
        log::trace!(
            target: rns_core::logging::PATHING_LOG_TARGET,
            "Ignored previously discovered interface with insufficient stamp value"
        );
        return None;
    }

    // Check encryption flag (we don't support encrypted discovery yet)
    let encrypted = (flags & 0x02) != 0;
    if encrypted {
        log::debug!("Ignoring encrypted discovered interface (not supported)");
        return None;
    }

    let (stamp, packed, stamp_value) =
        if let Some(entry) = cache.valid_entry(&payload_hash).cloned() {
            log::trace!(
                target: rns_core::logging::PATHING_LOG_TARGET,
                "Discovery announce cache hit"
            );
            if entry.value < required_stamp_value as u32 {
                log::debug!("{}", insufficient_stamp_diagnostic(entry.value));
                return None;
            }
            (entry.stamp, entry.packed, entry.value)
        } else {
            // The driver owns this cache and processes events sequentially, so the
            // upstream validation lock is implicit in Rust's ownership model.
            let stamp = payload[payload.len() - STAMP_SIZE..].to_vec();
            let packed = payload[..payload.len() - STAMP_SIZE].to_vec();
            let infohash = sha256(&packed);
            let workblock = stamp_workblock(&infohash, WORKBLOCK_EXPAND_ROUNDS);
            let value = stamp_value(&workblock, &stamp);

            if !stamp_valid(&stamp, required_stamp_value, &workblock) {
                log::debug!("{}", insufficient_stamp_diagnostic(value));
                cache.insert_invalid_hash(payload_hash);
                return None;
            }
            cache.insert_valid_hash(
                payload_hash,
                ValidStampEntry {
                    stamp: stamp.clone(),
                    packed: packed.clone(),
                    value,
                },
            );
            (stamp, packed, value)
        };

    // Unpack the interface info
    let (value, _) = msgpack::unpack(&packed).ok()?;
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
    let interface_type = match get_u8_val(INTERFACE_TYPE)? {
        Value::Str(value) => value,
        _ => return None,
    };
    if !is_discoverable_type(&interface_type) {
        log::debug!(
            "Ignoring discovered interface with unsupported type '{}'",
            interface_type
        );
        return None;
    }

    let transport = match get_u8_val(TRANSPORT)? {
        Value::Bool(value) => value,
        _ => return None,
    };
    let raw_name = match get_u8_val(NAME) {
        Some(Value::Str(value)) => value,
        Some(_) | None => String::new(),
    };
    let name = sanitize_discovered_name(&raw_name)
        .unwrap_or_else(|| format!("Discovered {}", interface_type));

    let transport_id_val = get_u8_val(TRANSPORT_ID)?;
    let transport_id_bytes = transport_id_val.as_bin()?;
    if transport_id_bytes.len() != 16 {
        log::debug!("Ignoring discovered interface with invalid transport_id length");
        return None;
    }
    let mut transport_id = [0u8; 16];
    transport_id.copy_from_slice(transport_id_bytes);

    // Extract optional fields
    let latitude = optional_f64_field(get_u8_val(LATITUDE))?;
    let longitude = optional_f64_field(get_u8_val(LONGITUDE))?;
    let height = optional_f64_field(get_u8_val(HEIGHT))?;
    let reachable_on = match get_u8_val(REACHABLE_ON) {
        None | Some(Value::Nil) => None,
        Some(Value::Str(value)) => Some(value),
        Some(_) => return None,
    };
    if let Some(ref reachable_on) = reachable_on {
        if !(is_ip_address(reachable_on) || is_hostname(reachable_on)) {
            log::debug!(
                "Ignoring discovered interface with invalid reachable_on '{}'",
                reachable_on
            );
            return None;
        }
    }

    let port = get_u8_val(PORT).and_then(|v| v.as_uint().map(|n| n as u16));
    let frequency = get_u8_val(FREQUENCY).and_then(|v| v.as_uint().map(|n| n as u32));
    let bandwidth = get_u8_val(BANDWIDTH).and_then(|v| v.as_uint().map(|n| n as u32));
    let spreading_factor = get_u8_val(SPREADINGFACTOR).and_then(|v| v.as_uint().map(|n| n as u8));
    let coding_rate = get_u8_val(CODINGRATE).and_then(|v| v.as_uint().map(|n| n as u8));
    let modulation = get_u8_val(MODULATION).and_then(|v| v.as_str().map(|s| s.to_string()));
    let channel = get_u8_val(CHANNEL).and_then(|v| v.as_uint().map(|n| n as u8));
    let ifac_netname = get_u8_val(IFAC_NETNAME).map(|v| discovery_value_to_string(&v));
    let ifac_netkey = get_u8_val(IFAC_NETKEY).map(|v| discovery_value_to_string(&v));

    // Compute discovery hash
    let discovery_hash = compute_discovery_hash(&transport_id, &name);

    // Generate config entry
    let config_entry = generate_config_entry(ConfigEntryParams {
        interface_type: &interface_type,
        name: &name,
        transport_id: &transport_id,
        reachable_on: reachable_on.as_deref(),
        port,
        frequency,
        bandwidth,
        spreading_factor,
        coding_rate,
        modulation: modulation.as_deref(),
        ifac_netname: ifac_netname.as_deref(),
        ifac_netkey: ifac_netkey.as_deref(),
    });

    let now = time::now();

    Some(DiscoveredInterface {
        interface_type,
        transport,
        name,
        discovered: now,
        last_heard: now,
        heard_count: 0,
        status: DiscoveredStatus::Available,
        stamp,
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

/// Mark a discovered transport interface config entry for gateway mode.
pub fn apply_transport_autoconnect_mode(
    iface: &mut DiscoveredInterface,
    local_transport_enabled: bool,
    configured_mode: Option<u8>,
) {
    let mode = configured_mode.or_else(|| {
        (local_transport_enabled && iface.transport).then_some(rns_core::constants::MODE_GATEWAY)
    });
    let Some(mode) = mode else {
        return;
    };
    let Some(config_entry) = iface.config_entry.as_mut() else {
        return;
    };
    if config_entry
        .lines()
        .any(|line| line.trim_start().starts_with("interface_mode"))
    {
        return;
    }
    if let Some(pos) = config_entry.find("  enabled = yes\n") {
        let insert_at = pos + "  enabled = yes\n".len();
        config_entry.insert_str(
            insert_at,
            &format!("  interface_mode = {}\n", interface_mode_name(mode)),
        );
    } else {
        config_entry.push_str(&format!(
            "\n  interface_mode = {}",
            interface_mode_name(mode)
        ));
    }
}

fn interface_mode_name(mode: u8) -> &'static str {
    match mode {
        rns_core::constants::MODE_ACCESS_POINT => "access_point",
        rns_core::constants::MODE_POINT_TO_POINT => "pointtopoint",
        rns_core::constants::MODE_ROAMING => "roaming",
        rns_core::constants::MODE_BOUNDARY => "boundary",
        rns_core::constants::MODE_GATEWAY => "gateway",
        rns_core::constants::MODE_INTERNAL => "internal",
        _ => "full",
    }
}

/// Generate a config entry for auto-connecting to a discovered interface
struct ConfigEntryParams<'a> {
    interface_type: &'a str,
    name: &'a str,
    transport_id: &'a [u8; 16],
    reachable_on: Option<&'a str>,
    port: Option<u16>,
    frequency: Option<u32>,
    bandwidth: Option<u32>,
    spreading_factor: Option<u8>,
    coding_rate: Option<u8>,
    modulation: Option<&'a str>,
    ifac_netname: Option<&'a str>,
    ifac_netkey: Option<&'a str>,
}

fn generate_config_entry(params: ConfigEntryParams<'_>) -> Option<String> {
    let ConfigEntryParams {
        interface_type,
        name,
        transport_id,
        reachable_on,
        port,
        frequency,
        bandwidth,
        spreading_factor,
        coding_rate,
        modulation,
        ifac_netname,
        ifac_netkey,
    } = params;
    if reachable_on.is_some_and(is_ygg_ipv6) {
        return None;
    }

    let transport_id_hex = hex_encode(transport_id);
    let netname_str = ifac_netname
        .map(|n| format!("\n  network_name = {}", n))
        .unwrap_or_default();
    let netkey_str = ifac_netkey
        .map(|k| format!("\n  passphrase = {}", k))
        .unwrap_or_default();
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
            let freq_str = frequency
                .map(|f| format!("\n  frequency = {}", f))
                .unwrap_or_default();
            let bw_str = bandwidth
                .map(|b| format!("\n  bandwidth = {}", b))
                .unwrap_or_default();
            let sf_str = spreading_factor
                .map(|s| format!("\n  spreadingfactor = {}", s))
                .unwrap_or_default();
            let cr_str = coding_rate
                .map(|c| format!("\n  codingrate = {}", c))
                .unwrap_or_default();
            Some(format!(
                "[[{}]]\n  type = RNodeInterface\n  enabled = yes\n  port = {}{}{}{}{}{}{}{}",
                name, "", freq_str, bw_str, sf_str, cr_str, identity_str, netname_str, netkey_str
            ))
        }
        "KISSInterface" => {
            let freq_str = frequency
                .map(|f| format!("\n  # Frequency: {}", f))
                .unwrap_or_default();
            let bw_str = bandwidth
                .map(|b| format!("\n  # Bandwidth: {}", b))
                .unwrap_or_default();
            let mod_str = modulation
                .map(|m| format!("\n  # Modulation: {}", m))
                .unwrap_or_default();
            Some(format!(
                "[[{}]]\n  type = KISSInterface\n  enabled = yes\n  port = {}{}{}{}{}{}{}",
                name, "", freq_str, bw_str, mod_str, identity_str, netname_str, netkey_str
            ))
        }
        "WeaveInterface" => Some(format!(
            "[[{}]]\n  type = WeaveInterface\n  enabled = yes\n  port = {}{}{}{}",
            name, "", identity_str, netname_str, netkey_str
        )),
        _ => None,
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn optional_f64_field(value: Option<Value>) -> Option<Option<f64>> {
    match value {
        None | Some(Value::Nil) => Some(None),
        Some(Value::Float(value)) if value.is_finite() => Some(Some(value)),
        Some(_) => None,
    }
}

fn discovery_value_to_string(value: &Value) -> String {
    match value {
        Value::Nil => "None".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::UInt(value) => value.to_string(),
        Value::Int(value) => value.to_string(),
        Value::Float(value) => value.to_string(),
        Value::Bin(value) => hex_encode(value),
        Value::Str(value) => value.clone(),
        Value::Array(_) => "[]".to_string(),
        Value::Map(_) => "{}".to_string(),
    }
}

/// Sanitize a discovered interface name like upstream Reticulum.
pub fn sanitize_discovered_name(name: &str) -> Option<String> {
    let ascii: String = name.chars().filter(|ch| ch.is_ascii()).collect();
    let mut sanitized = ascii.trim().to_string();
    while sanitized.contains("  ") {
        sanitized = sanitized.replace("  ", " ");
    }

    let start = sanitized
        .char_indices()
        .find(|(_, ch)| ch.is_ascii_alphanumeric())
        .map(|(idx, _)| idx)?;
    let end = sanitized
        .char_indices()
        .rev()
        .find(|(_, ch)| ch.is_ascii_alphanumeric() || *ch == ')')
        .map(|(idx, ch)| idx + ch.len_utf8())?;

    if start >= end {
        return None;
    }

    let sanitized = sanitized[start..end].to_string();
    (!sanitized.is_empty()).then_some(sanitized)
}

/// Encode bytes as hex string (no delimiters)
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Check if a string is a valid IP address
pub fn is_ip_address(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// Check if an address belongs to Yggdrasil's `200::/7` IPv6 range.
pub fn is_ygg_ipv6(s: &str) -> bool {
    match s.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(addr)) => {
            let segments = addr.segments();
            (segments[0] & 0xfe00) == 0x0200
        }
        _ => false,
    }
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
    if components
        .last()
        .map(|c| c.chars().all(|ch| ch.is_ascii_digit()))
        .unwrap_or(false)
    {
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

/// Check whether an interface type can be accepted from discovery.
pub fn is_discoverable_type(interface_type: &str) -> bool {
    DISCOVERABLE_TYPES.contains(&interface_type)
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
        if !is_discoverable_type(&iface.interface_type) {
            return false;
        }
        if let Some(ref reachable_on) = iface.reachable_on {
            if !(is_ip_address(reachable_on) || is_hostname(reachable_on)) {
                return false;
            }
        }

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
        b.last_heard
            .partial_cmp(&a.last_heard)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
}

/// Compute the name hash for the discovery destination: `rnstransport.discovery.interface`.
///
/// Discovery is a SINGLE destination — its dest hash varies with the sender's identity.
/// We match incoming announces by comparing their name_hash to this constant.
pub fn discovery_name_hash() -> [u8; 10] {
    rns_core::destination::name_hash(APP_NAME, &["discovery", "interface"])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack_discovery_entries(entries: Vec<(Value, Value)>) -> Vec<u8> {
        let packed = msgpack::pack(&Value::Map(entries));
        let mut app_data = Vec::with_capacity(1 + packed.len() + STAMP_SIZE);
        app_data.push(0x00);
        app_data.extend_from_slice(&packed);
        app_data.extend_from_slice(&[0u8; STAMP_SIZE]);
        app_data
    }

    fn discovery_entries(interface_type: &str, reachable_on: Option<&str>) -> Vec<(Value, Value)> {
        let mut entries = vec![
            (
                Value::UInt(INTERFACE_TYPE as u64),
                Value::Str(interface_type.to_string()),
            ),
            (Value::UInt(TRANSPORT as u64), Value::Bool(true)),
            (
                Value::UInt(NAME as u64),
                Value::Str(format!("test-{interface_type}")),
            ),
            (Value::UInt(TRANSPORT_ID as u64), Value::Bin(vec![0x42; 16])),
        ];

        if let Some(reachable_on) = reachable_on {
            entries.push((
                Value::UInt(REACHABLE_ON as u64),
                Value::Str(reachable_on.to_string()),
            ));
        }

        entries
    }

    fn build_discovery_app_data(interface_type: &str, reachable_on: Option<&str>) -> Vec<u8> {
        pack_discovery_entries(discovery_entries(interface_type, reachable_on))
    }

    #[test]
    fn insufficient_stamp_diagnostic_includes_calculated_value() {
        assert_eq!(
            insufficient_stamp_diagnostic(7),
            "Ignored discovered interface with insufficient stamp value 7"
        );
    }

    #[test]
    fn default_discovery_stamp_value_matches_upstream_1_4_0() {
        assert_eq!(DEFAULT_STAMP_VALUE, 16);
    }

    #[test]
    fn invalid_stamp_cache_short_circuits_repeat_validation() {
        let app_data = build_discovery_app_data("BackboneInterface", Some("example.com"));
        let mut cache = DiscoveryStampCache::with_capacity(8);

        assert!(parse_interface_announce_with_cache(
            &app_data,
            &[0x11; 16],
            1,
            u8::MAX,
            &mut cache,
        )
        .is_none());
        assert_eq!(cache.invalid_len(), 1);

        // A zero requirement would accept this stamp if validation ran again.
        // The cached invalid payload must be rejected before that work occurs.
        assert!(
            parse_interface_announce_with_cache(&app_data, &[0x11; 16], 1, 0, &mut cache,)
                .is_none()
        );
        assert!(parse_interface_announce(&app_data, &[0x11; 16], 1, 0).is_some());
        assert_eq!(
            cache.invalid_len(),
            1,
            "cache hits must not duplicate entries"
        );
    }

    #[test]
    fn invalid_stamp_cache_is_bounded_fifo() {
        let first = build_discovery_app_data("BackboneInterface", Some("first.example"));
        let second = build_discovery_app_data("BackboneInterface", Some("second.example"));
        let third = build_discovery_app_data("BackboneInterface", Some("third.example"));
        let mut cache = DiscoveryStampCache::with_capacity(2);

        for app_data in [&first, &second, &third] {
            assert!(parse_interface_announce_with_cache(
                app_data,
                &[0x11; 16],
                1,
                u8::MAX,
                &mut cache,
            )
            .is_none());
        }

        assert_eq!(cache.invalid_len(), 2);
        assert!(!cache.contains_invalid_app_data(&first));
        assert!(cache.contains_invalid_app_data(&second));
        assert!(cache.contains_invalid_app_data(&third));
    }

    #[test]
    fn valid_stamp_cache_short_circuits_repeat_work_and_preserves_dynamic_metadata() {
        let app_data = build_discovery_app_data("BackboneInterface", Some("example.com"));
        let mut cache = DiscoveryStampCache::with_capacity(8);
        let first =
            parse_interface_announce_with_cache(&app_data, &[0x11; 16], 1, 0, &mut cache).unwrap();
        assert_eq!(cache.valid_len(), 1);

        let second =
            parse_interface_announce_with_cache(&app_data, &[0x22; 16], 7, 0, &mut cache).unwrap();
        assert_eq!(cache.valid_len(), 1);
        assert_eq!(second.stamp, first.stamp);
        assert_eq!(second.stamp_value, first.stamp_value);
        assert_eq!(second.network_id, [0x22; 16]);
        assert_eq!(second.hops, 7);
    }

    #[test]
    fn valid_stamp_cache_is_bounded_fifo_and_keys_payload_like_invalid_cache() {
        let first = build_discovery_app_data("BackboneInterface", Some("first.example"));
        let second = build_discovery_app_data("BackboneInterface", Some("second.example"));
        let third = build_discovery_app_data("BackboneInterface", Some("third.example"));
        let mut cache = DiscoveryStampCache::with_capacity(2);

        for app_data in [&first, &second, &third] {
            assert!(
                parse_interface_announce_with_cache(app_data, &[0x11; 16], 1, 0, &mut cache,)
                    .is_some()
            );
        }
        assert_eq!(cache.valid_len(), 2);
        assert!(!cache.contains_valid_app_data(&first));
        assert!(cache.contains_valid_app_data(&second));
        assert!(cache.contains_valid_app_data(&third));

        let mut different_flags = second.clone();
        different_flags[0] ^= 0x01;
        assert!(cache.contains_valid_app_data(&different_flags));
        let mut different_stamp = second.clone();
        *different_stamp.last_mut().unwrap() ^= 0x01;
        assert!(!cache.contains_valid_app_data(&different_stamp));
    }

    #[test]
    fn cached_stamp_value_is_rechecked_if_requirement_increases() {
        let app_data = build_discovery_app_data("BackboneInterface", Some("example.com"));
        let mut cache = DiscoveryStampCache::with_capacity(8);
        assert!(
            parse_interface_announce_with_cache(&app_data, &[0x11; 16], 1, 0, &mut cache,)
                .is_some()
        );
        assert!(parse_interface_announce_with_cache(
            &app_data,
            &[0x11; 16],
            1,
            u8::MAX,
            &mut cache,
        )
        .is_none());
        assert_eq!(cache.valid_len(), 1);
        assert_eq!(cache.invalid_len(), 0);
    }

    #[test]
    fn invalid_stamp_cache_keys_payload_including_stamp_but_excluding_flags() {
        let original = build_discovery_app_data("BackboneInterface", Some("example.com"));
        let mut cache = DiscoveryStampCache::with_capacity(8);
        assert!(parse_interface_announce_with_cache(
            &original,
            &[0x11; 16],
            1,
            u8::MAX,
            &mut cache,
        )
        .is_none());

        let mut different_flags = original.clone();
        different_flags[0] ^= 0x01;
        assert!(cache.contains_invalid_app_data(&different_flags));

        let mut different_stamp = original.clone();
        *different_stamp.last_mut().unwrap() ^= 0x01;
        assert!(!cache.contains_invalid_app_data(&different_stamp));
    }

    #[test]
    fn malformed_discovery_payload_is_not_added_to_invalid_stamp_cache() {
        let mut cache = DiscoveryStampCache::with_capacity(8);
        assert!(parse_interface_announce_with_cache(
            &[0x00, 0x01, 0x02],
            &[0x11; 16],
            1,
            u8::MAX,
            &mut cache,
        )
        .is_none());
        assert_eq!(cache.invalid_len(), 0);
    }

    #[test]
    fn parse_rejects_unsupported_discovered_interface_type() {
        let app_data = build_discovery_app_data("BogusInterface", None);

        let parsed = parse_interface_announce(&app_data, &[0x11; 16], 1, 0);

        assert!(
            parsed.is_none(),
            "unsupported discovered interface types must be ignored"
        );
    }

    #[test]
    fn parse_rejects_invalid_reachable_on_address() {
        let app_data = build_discovery_app_data("BackboneInterface", Some("-not a host-"));

        let parsed = parse_interface_announce(&app_data, &[0x11; 16], 1, 0);

        assert!(
            parsed.is_none(),
            "discovered interfaces with invalid reachable_on values must be ignored"
        );
    }

    #[test]
    fn parse_sanitizes_discovered_interface_name() {
        let mut entries = discovery_entries("BackboneInterface", Some("example.com"));
        entries.retain(|(key, _)| key.as_uint() != Some(NAME as u64));
        entries.push((
            Value::UInt(NAME as u64),
            Value::Str("\t**Alpha     Beta!!!\n".to_string()),
        ));
        let app_data = pack_discovery_entries(entries);

        let parsed = parse_interface_announce(&app_data, &[0x11; 16], 1, 0).unwrap();

        assert_eq!(parsed.name, "Alpha Beta");
        assert!(parsed.config_entry.unwrap().starts_with("[[Alpha Beta]]"));
    }

    #[test]
    fn parse_falls_back_when_discovered_interface_name_sanitizes_empty() {
        let mut entries = discovery_entries("BackboneInterface", Some("example.com"));
        entries.retain(|(key, _)| key.as_uint() != Some(NAME as u64));
        entries.push((Value::UInt(NAME as u64), Value::Str("!!!".to_string())));
        let app_data = pack_discovery_entries(entries);

        let parsed = parse_interface_announce(&app_data, &[0x11; 16], 1, 0).unwrap();

        assert_eq!(parsed.name, "Discovered BackboneInterface");
    }

    #[test]
    fn parse_falls_back_when_discovered_interface_name_is_nil() {
        let mut entries = discovery_entries("BackboneInterface", Some("example.com"));
        entries.retain(|(key, _)| key.as_uint() != Some(NAME as u64));
        entries.push((Value::UInt(NAME as u64), Value::Nil));
        let app_data = pack_discovery_entries(entries);

        let parsed = parse_interface_announce(&app_data, &[0x11; 16], 1, 0).unwrap();

        assert_eq!(parsed.name, "Discovered BackboneInterface");
    }

    #[test]
    fn parse_rejects_invalid_discovered_interface_field_types() {
        for (field, replacement) in [
            (TRANSPORT, Value::Str("yes".to_string())),
            (LATITUDE, Value::Str("45.0".to_string())),
            (LONGITUDE, Value::Str("9.0".to_string())),
            (HEIGHT, Value::Str("100".to_string())),
            (INTERFACE_TYPE, Value::UInt(123)),
            (REACHABLE_ON, Value::UInt(123)),
        ] {
            let mut entries = discovery_entries("BackboneInterface", Some("example.com"));
            entries.retain(|(key, _)| key.as_uint() != Some(field as u64));
            entries.push((Value::UInt(field as u64), replacement));
            let app_data = pack_discovery_entries(entries);

            let parsed = parse_interface_announce(&app_data, &[0x11; 16], 1, 0);

            assert!(parsed.is_none(), "field {field} should reject invalid type");
        }
    }

    #[test]
    fn parse_rejects_invalid_transport_id_length() {
        let mut entries = discovery_entries("BackboneInterface", Some("example.com"));
        entries.retain(|(key, _)| key.as_uint() != Some(TRANSPORT_ID as u64));
        entries.push((Value::UInt(TRANSPORT_ID as u64), Value::Bin(vec![0x42; 15])));
        let app_data = pack_discovery_entries(entries);

        let parsed = parse_interface_announce(&app_data, &[0x11; 16], 1, 0);

        assert!(parsed.is_none());
    }

    #[test]
    fn parse_converts_ifac_fields_to_strings() {
        let mut entries = discovery_entries("BackboneInterface", Some("example.com"));
        entries.push((Value::UInt(IFAC_NETNAME as u64), Value::UInt(123)));
        entries.push((Value::UInt(IFAC_NETKEY as u64), Value::Bool(true)));
        let app_data = pack_discovery_entries(entries);

        let parsed = parse_interface_announce(&app_data, &[0x11; 16], 1, 0).unwrap();

        assert_eq!(parsed.ifac_netname.as_deref(), Some("123"));
        assert_eq!(parsed.ifac_netkey.as_deref(), Some("true"));
    }

    #[test]
    fn transport_autoconnect_mode_marks_transport_discovery_config_as_gateway() {
        let app_data = build_discovery_app_data("BackboneInterface", Some("example.com"));
        let mut parsed = parse_interface_announce(&app_data, &[0x11; 16], 1, 0).unwrap();

        apply_transport_autoconnect_mode(&mut parsed, true, None);

        let config_entry = parsed.config_entry.unwrap();
        assert!(config_entry.contains("  enabled = yes\n  interface_mode = gateway\n"));
    }

    #[test]
    fn configured_autoconnect_mode_overrides_transport_fallback() {
        let app_data = build_discovery_app_data("BackboneInterface", Some("example.com"));
        let mut parsed = parse_interface_announce(&app_data, &[0x11; 16], 1, 0).unwrap();

        apply_transport_autoconnect_mode(
            &mut parsed,
            true,
            Some(rns_core::constants::MODE_BOUNDARY),
        );

        let config_entry = parsed.config_entry.unwrap();
        assert!(config_entry.contains("  enabled = yes\n  interface_mode = boundary\n"));
    }

    #[test]
    fn transport_autoconnect_mode_does_not_modify_non_transport_contexts() {
        let app_data = build_discovery_app_data("BackboneInterface", Some("example.com"));
        let mut parsed = parse_interface_announce(&app_data, &[0x11; 16], 1, 0).unwrap();
        let original = parsed.config_entry.clone();

        apply_transport_autoconnect_mode(&mut parsed, false, None);

        assert_eq!(parsed.config_entry, original);
    }

    #[test]
    fn transport_autoconnect_mode_does_not_modify_non_transport_announces() {
        let mut entries = discovery_entries("BackboneInterface", Some("example.com"));
        entries.retain(|(key, _)| key.as_uint() != Some(TRANSPORT as u64));
        entries.push((Value::UInt(TRANSPORT as u64), Value::Bool(false)));
        let app_data = pack_discovery_entries(entries);
        let mut parsed = parse_interface_announce(&app_data, &[0x11; 16], 1, 0).unwrap();
        let original = parsed.config_entry.clone();

        apply_transport_autoconnect_mode(&mut parsed, true, None);

        assert_eq!(parsed.config_entry, original);
    }

    #[test]
    fn transport_autoconnect_mode_preserves_existing_interface_mode() {
        let app_data = build_discovery_app_data("BackboneInterface", Some("example.com"));
        let mut parsed = parse_interface_announce(&app_data, &[0x11; 16], 1, 0).unwrap();
        let config_entry = parsed.config_entry.as_mut().unwrap();
        config_entry.push_str("\n  interface_mode = access_point");
        let original = parsed.config_entry.clone();

        apply_transport_autoconnect_mode(&mut parsed, true, None);

        assert_eq!(parsed.config_entry, original);
    }

    #[test]
    fn parse_yggdrasil_reachable_on_keeps_record_without_config_entry() {
        let app_data = build_discovery_app_data("BackboneInterface", Some("200:1234::1"));

        let parsed = parse_interface_announce(&app_data, &[0x11; 16], 1, 0).unwrap();

        assert_eq!(parsed.reachable_on.as_deref(), Some("200:1234::1"));
        assert!(parsed.config_entry.is_none());
    }

    #[test]
    fn parse_accepts_supported_discovered_interface_types() {
        for interface_type in [
            "BackboneInterface",
            "TCPServerInterface",
            "I2PInterface",
            "RNodeInterface",
            "WeaveInterface",
            "KISSInterface",
        ] {
            let app_data = build_discovery_app_data(interface_type, Some("example.com"));

            let parsed = parse_interface_announce(&app_data, &[0x11; 16], 1, 0);

            assert!(
                parsed.is_some(),
                "{interface_type} should be accepted as a discoverable interface type"
            );
        }
    }
}
