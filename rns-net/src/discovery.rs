//! Interface Discovery protocol implementation.
//!
//! Handles receiving, validating, and storing discovered interface announcements
//! from other Reticulum nodes on the network.
//!
//! The protocol lives in `rns_core::discovery`; this module contains
//! I/O storage and background-threaded stamp generation / announcing.
//!
//! Python reference: RNS/Discovery.py

// Re-export common::discovery (and through it rns_core::discovery) so
// `crate::discovery::X` paths work.
pub use crate::common::discovery::*;

use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rns_core::encoding::{hex, hex_decode};
use rns_core::msgpack::{self, Value};
use rns_core::stamp::{stamp_valid, stamp_workblock, StampCost, StampValue};
use rns_crypto::sha256::sha256;

use crate::time;

mod error;
pub use error::{AnnounceError, LocationError};

// ============================================================================
// Storage
// ============================================================================

static DISCOVERY_STORAGE_LOCK: Mutex<()> = Mutex::new(());

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
        let _guard = discovery_storage_guard();
        self.store_unlocked(iface)
    }

    fn store_unlocked(&self, iface: &DiscoveredInterface) -> io::Result<()> {
        let filename = hex(&iface.discovery_hash);
        let filepath = self.base_path.join(filename);

        let data = self.serialize_interface(iface)?;
        fs::write(&filepath, &data)
    }

    /// Store a newly received interface announce, preserving persistent counters.
    pub fn store_received(&self, iface: &mut DiscoveredInterface) -> io::Result<()> {
        let _guard = discovery_storage_guard();
        match self.load_unlocked(&iface.discovery_hash) {
            Ok(Some(existing)) => {
                iface.discovered = existing.discovered;
                iface.heard_count = existing.heard_count.saturating_add(1);
            }
            Ok(None) => {
                // Upstream starts a new record at 0.
                iface.discovered = iface.last_heard;
                iface.heard_count = 0;
            }
            Err(err) => {
                log::error!(
                    "Error while reading existing data for discovered interface, re-creating data: {}",
                    err
                );
                // As upstream: an unreadable record counts from 0 and this
                // receipt adds one.
                iface.discovered = iface.last_heard;
                iface.heard_count = 1;
            }
        }

        self.store_unlocked(iface)
    }

    /// Load a discovered interface by its discovery hash
    pub fn load(&self, discovery_hash: &[u8; 32]) -> io::Result<Option<DiscoveredInterface>> {
        let _guard = discovery_storage_guard();
        self.load_unlocked(discovery_hash)
    }

    fn load_unlocked(&self, discovery_hash: &[u8; 32]) -> io::Result<Option<DiscoveredInterface>> {
        let filename = hex(discovery_hash);
        let filepath = self.base_path.join(filename);

        if !filepath.exists() {
            return Ok(None);
        }

        let data = fs::read(&filepath)?;
        self.deserialize_interface(&data).map(Some)
    }

    /// List all discovered interfaces
    pub fn list(&self) -> io::Result<Vec<DiscoveredInterface>> {
        let _guard = discovery_storage_guard();
        self.list_unlocked()
    }

    fn list_unlocked(&self) -> io::Result<Vec<DiscoveredInterface>> {
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
                        if let Some(iface) = self.migrate_discovery_hash(&path, iface) {
                            interfaces.push(iface);
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(interfaces)
    }

    /// Remove a discovered interface by its discovery hash
    /// Earlier releases hashed the raw transport id instead of its hex
    /// string, as upstream does. Move such a record to upstream's file name,
    /// or drop it when the interface has been heard since under that name.
    fn migrate_discovery_hash(
        &self,
        path: &std::path::Path,
        mut iface: DiscoveredInterface,
    ) -> Option<DiscoveredInterface> {
        let expected = compute_discovery_hash(&iface.transport_id, &iface.name);
        if iface.discovery_hash == expected {
            return Some(iface);
        }
        let _ = fs::remove_file(path);
        if self.base_path.join(hex(&expected)).exists() {
            return None;
        }
        iface.discovery_hash = expected;
        if let Err(error) = self.store_unlocked(&iface) {
            log::warn!("could not migrate discovered interface record: {error}");
        }
        Some(iface)
    }

    /// Delete the stored record for `discovery_hash`, if there is one.
    pub fn remove(&self, discovery_hash: &[u8; 32]) -> io::Result<()> {
        let _guard = discovery_storage_guard();
        self.remove_unlocked(discovery_hash)
    }

    fn remove_unlocked(&self, discovery_hash: &[u8; 32]) -> io::Result<()> {
        let filename = hex(discovery_hash);
        let filepath = self.base_path.join(filename);

        if filepath.exists() {
            fs::remove_file(&filepath)?;
        }
        Ok(())
    }

    /// Clean up stale entries (older than THRESHOLD_REMOVE)
    /// Returns the number of entries removed
    pub fn cleanup(&self) -> io::Result<usize> {
        self.cleanup_with_blackholes(|_| false)
    }

    /// Clean up stale, invalid, or blackholed discovery records.
    pub fn cleanup_with_blackholes<F>(&self, is_blackholed: F) -> io::Result<usize>
    where
        F: FnMut(&[u8; 16]) -> bool,
    {
        self.cleanup_with_filters(is_blackholed, |_| true)
    }

    /// Clean up stale, invalid or blackholed discovery records, and those of
    /// networks `allowed_network` rejects (upstream's
    /// `interface_discovery_sources`).
    pub fn cleanup_with_filters<F, A>(
        &self,
        mut is_blackholed: F,
        mut allowed_network: A,
    ) -> io::Result<usize>
    where
        F: FnMut(&[u8; 16]) -> bool,
        A: FnMut(&[u8; 16]) -> bool,
    {
        let _guard = discovery_storage_guard();
        let mut removed = 0;
        let now = time::now();

        let entries = match fs::read_dir(&self.base_path) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(err) => return Err(err),
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let iface = match fs::read(&path).and_then(|data| self.deserialize_interface(&data)) {
                Ok(iface) => iface,
                Err(err) => {
                    log::debug!(
                        "Removing invalid cached interface discovery {}: {}",
                        path.display(),
                        err
                    );
                    fs::remove_file(&path)?;
                    removed += 1;
                    continue;
                }
            };
            let invalid_reachable_on = iface
                .reachable_on
                .as_ref()
                .map(|reachable_on| !(is_ip_address(reachable_on) || is_hostname(reachable_on)))
                .unwrap_or(false);

            if !is_discoverable_type(&iface.interface_type)
                || invalid_reachable_on
                || now - iface.last_heard > THRESHOLD_REMOVE
                || is_blackholed(&iface.network_id)
                || is_blackholed(&iface.transport_id)
                || !allowed_network(&iface.network_id)
            {
                fs::remove_file(&path)?;
                removed += 1;
            }
        }

        Ok(removed)
    }

    /// Serialize an interface to msgpack as upstream persists it: its keys
    /// in its order, ids and the operator address as hex strings, absent
    /// optional fields as nil, and the type's own fields only.
    fn serialize_interface(&self, iface: &DiscoveredInterface) -> io::Result<Vec<u8>> {
        fn opt<T>(value: Option<T>, f: impl FnOnce(T) -> Value) -> Value {
            value.map(f).unwrap_or(Value::Nil)
        }
        let key = |name: &str| Value::Str(name.into());
        let mut entries: Vec<(Value, Value)> = vec![
            (key("type"), Value::Str(iface.interface_type.clone())),
            (key("impl_name"), opt(iface.impl_name.clone(), Value::Str)),
            (key("version"), opt(iface.impl_version.clone(), Value::Str)),
            (key("transport"), Value::Bool(iface.transport)),
            (key("name"), Value::Str(iface.name.clone())),
            (key("received"), Value::Float(iface.last_heard)),
            (key("stamp"), Value::Bin(iface.stamp.clone())),
            (key("value"), Value::Float(iface.stamp_value.as_f64())),
            (key("transport_id"), Value::Str(hex(&iface.transport_id))),
            (key("network_id"), Value::Str(hex(&iface.network_id))),
            (
                key("dst_cost"),
                opt(iface.dst_cost, |c| Value::Float(c.as_f64())),
            ),
            (
                key("pr_cost"),
                opt(iface.pr_cost, |c| Value::Float(c.as_f64())),
            ),
            (key("hops"), Value::UInt(iface.hops as u64)),
            (key("latitude"), opt(iface.latitude, Value::Float)),
            (key("longitude"), opt(iface.longitude, Value::Float)),
            (key("height"), opt(iface.height, Value::Float)),
        ];
        for (name, value) in [
            ("ifac_netname", &iface.ifac_netname),
            ("ifac_netkey", &iface.ifac_netkey),
        ] {
            if let Some(value) = value.as_ref().filter(|v| !v.is_empty()) {
                entries.push((key(name), Value::Str(value.clone())));
            }
        }
        let uint = |v: Option<u64>| opt(v, Value::UInt);
        let text = |v: &Option<String>| opt(v.clone(), Value::Str);
        let type_fields: Vec<(&str, Value)> = match iface.interface_type.as_str() {
            "BackboneInterface" | "TCPServerInterface" => vec![
                ("reachable_on", text(&iface.reachable_on)),
                ("port", uint(iface.port.map(u64::from))),
            ],
            "I2PInterface" => vec![("reachable_on", text(&iface.reachable_on))],
            "RNodeInterface" => vec![
                ("frequency", uint(iface.frequency.map(u64::from))),
                ("bandwidth", uint(iface.bandwidth.map(u64::from))),
                ("sf", uint(iface.spreading_factor.map(u64::from))),
                ("cr", uint(iface.coding_rate.map(u64::from))),
            ],
            "WeaveInterface" => vec![
                ("frequency", uint(iface.frequency.map(u64::from))),
                ("bandwidth", uint(iface.bandwidth.map(u64::from))),
                ("channel", uint(iface.channel.map(u64::from))),
                ("modulation", text(&iface.modulation)),
            ],
            "KISSInterface" => vec![
                ("frequency", uint(iface.frequency.map(u64::from))),
                ("bandwidth", uint(iface.bandwidth.map(u64::from))),
                ("modulation", text(&iface.modulation)),
            ],
            _ => Vec::new(),
        };
        for (name, value) in type_fields {
            entries.push((key(name), value));
        }
        if let Some(ref entry) = iface.config_entry {
            entries.push((key("config_entry"), Value::Str(entry.clone())));
        }
        entries.push((
            key("discovery_hash"),
            Value::Bin(iface.discovery_hash.to_vec()),
        ));
        if let Some(address) = iface.operator_lxmf_address {
            entries.push((key("operator_lxmf_address"), Value::Str(hex(&address))));
        }
        entries.push((key("discovered"), Value::Float(iface.discovered)));
        entries.push((key("last_heard"), Value::Float(iface.last_heard)));
        entries.push((key("heard_count"), Value::UInt(iface.heard_count as u64)));

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
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{} not a string", key))
                })
        };

        let get_opt_str = |v: &Value, key: &str| -> Option<String> {
            v.map_get(key)
                .and_then(|val| val.as_str().map(|s| s.to_string()))
        };

        let get_bool = |v: &Value, key: &str| -> io::Result<bool> {
            v.map_get(key).and_then(|val| val.as_bool()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("{} not a bool", key))
            })
        };

        let get_float = |v: &Value, key: &str| -> io::Result<f64> {
            v.map_get(key)
                .and_then(|val| val.as_float())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{} not a float", key))
                })
        };

        let get_opt_float =
            |v: &Value, key: &str| -> Option<f64> { v.map_get(key).and_then(|val| val.as_float()) };

        let get_uint = |v: &Value, key: &str| -> io::Result<u64> {
            v.map_get(key).and_then(|val| val.as_uint()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("{} not a uint", key))
            })
        };

        let get_opt_uint =
            |v: &Value, key: &str| -> Option<u64> { v.map_get(key).and_then(|val| val.as_uint()) };

        let get_bytes = |v: &Value, key: &str| -> io::Result<Vec<u8>> {
            v.map_get(key)
                .and_then(|val| val.as_bin())
                .map(|b| b.to_vec())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{} not bytes", key))
                })
        };

        // Upstream stores the ids as hex strings; earlier releases of this
        // implementation stored raw bytes.
        let id_bytes = |key: &str| -> io::Result<Vec<u8>> {
            match value.map_get(key) {
                Some(Value::Str(text)) => hex_decode(text).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{} not hex", key))
                }),
                _ => get_bytes(&value, key),
            }
        };
        let fixed_bytes = |key: &str, expected_len: usize| -> io::Result<Vec<u8>> {
            let bytes = id_bytes(key)?;
            if bytes.len() != expected_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} must be {} bytes", key, expected_len),
                ));
            }
            Ok(bytes)
        };

        let transport_id_bytes = fixed_bytes("transport_id", 16)?;
        let mut transport_id = [0u8; 16];
        transport_id.copy_from_slice(&transport_id_bytes);

        let network_id_bytes = fixed_bytes("network_id", 16)?;
        let mut network_id = [0u8; 16];
        network_id.copy_from_slice(&network_id_bytes);

        let discovery_hash_bytes = fixed_bytes("discovery_hash", 32)?;
        let mut discovery_hash = [0u8; 32];
        discovery_hash.copy_from_slice(&discovery_hash_bytes);

        // Upstream does not persist the status; it follows from last_heard
        // when listed.
        let status = match get_opt_str(&value, "status").as_deref() {
            Some("available") => DiscoveredStatus::Available,
            Some("stale") => DiscoveredStatus::Stale,
            _ => DiscoveredStatus::Unknown,
        };

        let interface_type = get_str(&value, "type")?;
        let raw_name = get_str(&value, "name")?;
        let name = sanitize_discovered_name(&raw_name)
            .unwrap_or_else(|| format!("Discovered {}", interface_type));

        Ok(DiscoveredInterface {
            interface_type,
            impl_name: get_opt_str(&value, "impl_name"),
            impl_version: get_opt_str(&value, "version"),
            dst_cost: value
                .map_get("dst_cost")
                .and_then(|cost| cost.as_number())
                .map(StampCost::from_f64),
            pr_cost: value
                .map_get("pr_cost")
                .and_then(|cost| cost.as_number())
                .map(StampCost::from_f64),
            transport: get_bool(&value, "transport")?,
            name,
            discovered: get_float(&value, "discovered")?,
            last_heard: get_float(&value, "last_heard")?,
            heard_count: get_uint(&value, "heard_count")? as u32,
            status,
            stamp: get_bytes(&value, "stamp")?,
            // Integer values from before fractional stamp values read as
            // whole bits.
            stamp_value: value
                .map_get("value")
                .and_then(|val| val.as_number())
                .map(StampValue::from_f64)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "value not a number"))?,
            transport_id,
            network_id,
            hops: get_uint(&value, "hops")? as u8,
            latitude: get_opt_float(&value, "latitude"),
            longitude: get_opt_float(&value, "longitude"),
            height: get_opt_float(&value, "height"),
            operator_lxmf_address: id_bytes("operator_lxmf_address")
                .ok()
                .filter(|bytes| bytes.len() == 16)
                .map(|bytes| {
                    let mut address = [0u8; 16];
                    address.copy_from_slice(&bytes);
                    address
                }),
            reachable_on: get_opt_str(&value, "reachable_on"),
            port: get_opt_uint(&value, "port").map(|v| v as u16),
            frequency: get_opt_uint(&value, "frequency").map(|v| v as u32),
            bandwidth: get_opt_uint(&value, "bandwidth").map(|v| v as u32),
            spreading_factor: get_opt_uint(&value, "sf").map(|v| v as u8),
            coding_rate: get_opt_uint(&value, "cr").map(|v| v as u8),
            modulation: get_opt_str(&value, "modulation"),
            channel: get_opt_uint(&value, "channel").map(|v| v as u8),
            ifac_netname: sanitize_persisted_ifac(get_opt_str(&value, "ifac_netname")),
            ifac_netkey: sanitize_persisted_ifac(get_opt_str(&value, "ifac_netkey")),
            config_entry: get_opt_str(&value, "config_entry"),
            discovery_hash,
        })
    }
}

fn discovery_storage_guard() -> MutexGuard<'static, ()> {
    match DISCOVERY_STORAGE_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::error!("recovering from poisoned discovery storage lock");
            poisoned.into_inner()
        }
    }
}

// ============================================================================
// Stamp Generation (parallel PoW search)
// ============================================================================

/// Generate a discovery stamp with the given cost: on threads of its own on
/// the parallel engine, on the calling thread on the compact one
/// (see [`crate::stamps::search`]). A discovery stamp is the costliest grind
/// a node runs: on the rayon pool it held up the short searches there, and
/// on a two-core host path requests were cancelled when their stamp missed
/// its deadline behind it.
///
/// Returns `(stamp, value)` on success. This is a blocking, CPU-intensive operation.
pub fn generate_discovery_stamp(
    packed_data: &[u8],
    stamp_cost: StampCost,
) -> ([u8; STAMP_SIZE], StampValue) {
    use crate::stamps::{search, SearchPool};
    use rns_crypto::{OsRng, Rng};
    use std::sync::atomic::Ordering;

    let infohash = sha256(packed_data);
    let workblock = stamp_workblock(&infohash, WORKBLOCK_EXPAND_ROUNDS);

    let stamp = search(SearchPool::Dedicated, |stop| {
        let mut rng = OsRng;
        let mut nonce = [0u8; STAMP_SIZE];
        loop {
            if stop.load(Ordering::Relaxed) {
                return None;
            }
            rng.fill_bytes(&mut nonce);
            if stamp_valid(&nonce, stamp_cost, &workblock) {
                return Some(nonce);
            }
        }
    })
    .unwrap_or_else(|| {
        log::error!("parallel discovery stamp search returned no result; retrying synchronously");
        let mut rng = OsRng;
        let mut nonce = [0u8; STAMP_SIZE];
        loop {
            rng.fill_bytes(&mut nonce);
            if stamp_valid(&nonce, stamp_cost, &workblock) {
                return nonce;
            }
        }
    });
    let value = rns_core::stamp::stamp_value(&workblock, &stamp);
    (stamp, value)
}

// ============================================================================
// Interface Announcer
// ============================================================================

/// Info about a single discoverable interface, ready for announcing.
#[derive(Debug, Clone)]
pub struct DiscoverableInterface {
    /// Configured interface name used for runtime targeting.
    pub interface_name: String,
    /// The interface's discovery settings.
    pub config: DiscoveryConfig,
    /// Whether the node has transport enabled.
    pub transport_enabled: bool,
    /// IFAC network name, if configured.
    pub ifac_netname: Option<String>,
    /// IFAC passphrase, if configured.
    pub ifac_netkey: Option<String>,
}

/// Result of a completed background announce generation.
pub struct AnnounceResult {
    /// Configured interface name this stamp was generated for.
    pub interface_name: String,
    /// The complete app_data (`[flags][packed][stamp]`), or the reason this
    /// announce was suppressed while preparing its metadata.
    pub app_data: Result<Vec<u8>, AnnounceError>,
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
    stamp_rx: std::sync::mpsc::Receiver<AnnounceResult>,
    /// Sender cloned into background threads.
    stamp_tx: std::sync::mpsc::Sender<AnnounceResult>,
    /// Whether a background stamp job is currently running.
    stamp_pending: bool,
    /// Node-wide stamp costs, behind the per-interface costs announced as
    /// `DST_COST` / `PR_COST`.
    stamp_requirements: rns_core::transport::types::StampRequirements,
    /// Public key of the network identity, for `discovery_encrypt`.
    network_public_key: Option<[u8; 64]>,
}

const LOCATION_CMD_TIMEOUT: Duration = Duration::from_secs(5);
const LOCATION_CMD_MAX_STDOUT: usize = 4096;

fn parse_location_output(output: &[u8]) -> Result<(f64, f64, f64), LocationError> {
    if output.len() > LOCATION_CMD_MAX_STDOUT {
        return Err(LocationError::OutputTooLong);
    }
    let line = std::str::from_utf8(output).map_err(LocationError::NotUtf8)?;
    let line = line.strip_suffix('\n').unwrap_or(line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.contains(['\n', '\r']) {
        return Err(LocationError::MultipleLines);
    }
    let values: Vec<&str> = line.split(',').map(str::trim).collect();
    if values.len() != 3 {
        return Err(LocationError::ComponentCount(values.len()));
    }
    let parse = |value: &str, label: &'static str| {
        value
            .parse::<f64>()
            .map_err(|source| LocationError::InvalidNumber {
                label,
                value: value.to_string(),
                source,
            })
            .and_then(|number| {
                number
                    .is_finite()
                    .then_some(number)
                    .ok_or(LocationError::NotFinite { label })
            })
    };
    let latitude = parse(values[0], "latitude")?;
    let longitude = parse(values[1], "longitude")?;
    let height = parse(values[2], "height")?;
    let check = |label: &'static str, value: f64, valid: std::ops::RangeInclusive<f64>, range| {
        if valid.contains(&value) {
            Ok(())
        } else {
            Err(LocationError::OutOfRange {
                label,
                value,
                range,
            })
        }
    };
    check("latitude", latitude, -90.0..=90.0, "-90..=90")?;
    check("longitude", longitude, -180.0..=180.0, "-180..=180")?;
    check("height", height, -4000.0..=1_000_000.0, "-4000..=1000000")?;
    Ok((latitude, longitude, height))
}

#[cfg(unix)]
fn expand_location_path(
    command: &str,
    home: Option<std::ffi::OsString>,
) -> Result<PathBuf, LocationError> {
    let path = if command == "~" {
        home.map(PathBuf::from)
            .ok_or(LocationError::HomeNotSet { prefix: "~" })?
    } else if let Some(suffix) = command.strip_prefix("~/") {
        let home = home
            .map(PathBuf::from)
            .ok_or(LocationError::HomeNotSet { prefix: "~/" })?;
        home.join(suffix)
    } else {
        PathBuf::from(command)
    };
    Ok(path)
}

#[cfg(unix)]
fn resolve_location(command: &str) -> Result<(f64, f64, f64), LocationError> {
    use std::os::unix::fs::PermissionsExt;

    let path = expand_location_path(command, std::env::var_os("HOME"))?;
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(source) => return Err(LocationError::Inspect { path, source }),
    };
    if !metadata.is_file() {
        return Err(LocationError::NotRegularFile(path));
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(LocationError::NotExecutable(path));
    }

    let child = Command::new(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(source) => return Err(LocationError::Spawn { path, source }),
    };
    let stdout = child
        .stdout
        .take()
        .ok_or(LocationError::StdoutUnavailable)?;
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        stdout
            .take((LOCATION_CMD_MAX_STDOUT + 1) as u64)
            .read_to_end(&mut output)
            .map(|_| output)
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < LOCATION_CMD_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(LocationError::TimedOut);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(LocationError::Wait(error));
            }
        }
    };
    let output = reader
        .join()
        .map_err(|_| LocationError::ReaderPanicked)?
        .map_err(LocationError::ReadStdout)?;
    if !status.success() {
        return Err(LocationError::Failed(status));
    }
    parse_location_output(&output)
}

#[cfg(windows)]
fn resolve_location(_command: &str) -> Result<(f64, f64, f64), LocationError> {
    Err(LocationError::Unsupported)
}

fn prepare_interface_info(
    transport_id: &[u8; 16],
    iface: &DiscoverableInterface,
    requirements: &rns_core::transport::types::StampRequirements,
) -> Result<Vec<u8>, AnnounceError> {
    let mut resolved = iface.clone();
    if let Some(command) = &resolved.config.location_cmd {
        let (latitude, longitude, height) =
            resolve_location(command).map_err(AnnounceError::Location)?;
        resolved.config.latitude = Some(latitude);
        resolved.config.longitude = Some(longitude);
        resolved.config.height = Some(height);
    }
    InterfaceAnnouncer::pack_interface_info(transport_id, &resolved, requirements)
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
            stamp_requirements: Default::default(),
            network_public_key: None,
        }
    }

    /// Encrypt the announces of interfaces with `discovery_encrypt` to the
    /// network identity with this public key.
    pub fn set_network_public_key(&mut self, public_key: Option<[u8; 64]>) {
        self.network_public_key = public_key;
    }

    /// Track the node-wide stamp costs (`[stamps] destination_cost` and
    /// `pr_cost`) that interfaces without their own announce.
    pub fn set_stamp_requirements(
        &mut self,
        requirements: rns_core::transport::types::StampRequirements,
    ) {
        self.stamp_requirements = requirements;
    }

    /// If any interface is due for an announce and no stamp job is already
    /// running, spawns a background thread for PoW.  The result will be
    /// available via `poll_ready()`.
    pub fn maybe_start(&mut self, now: f64) {
        if self.stamp_pending {
            return;
        }
        let due_index = self
            .interfaces
            .iter()
            .enumerate()
            .filter(|(i, iface)| {
                now - self.last_announced[*i] >= iface.config.announce_interval as f64
            })
            .min_by(|(left, _), (right, _)| {
                self.last_announced[*left].total_cmp(&self.last_announced[*right])
            })
            .map(|(i, _)| i);

        if let Some(idx) = due_index {
            let iface = self.interfaces[idx].clone();
            let transport_id = self.transport_id;
            let stamp_cost = iface.config.stamp_value;
            let name = iface.config.discovery_name.clone();
            let interface_name = iface.interface_name.clone();
            let tx = self.stamp_tx.clone();
            let requirements = self.stamp_requirements;
            let network_public_key = self.network_public_key;

            log::info!(
                "Spawning discovery stamp generation (cost={}) for '{}'...",
                stamp_cost,
                name,
            );

            self.stamp_pending = true;
            self.last_announced[idx] = now;

            std::thread::spawn(move || {
                let packed = match prepare_interface_info(&transport_id, &iface, &requirements) {
                    Ok(packed) => packed,
                    Err(error) => {
                        let _ = tx.send(AnnounceResult {
                            interface_name,
                            app_data: Err(error),
                        });
                        return;
                    }
                };
                let (stamp, value) = generate_discovery_stamp(&packed, stamp_cost);
                log::info!("Discovery stamp generated (value={}) for '{}'", value, name,);

                let mut payload = Vec::with_capacity(packed.len() + STAMP_SIZE);
                payload.extend_from_slice(&packed);
                payload.extend_from_slice(&stamp);
                let mut flags: u8 = 0x00;
                if iface.config.encrypt {
                    // Upstream encrypts to the network identity, which
                    // every node of the network holds.
                    let Some(public_key) = network_public_key else {
                        let _ = tx.send(AnnounceResult {
                            interface_name,
                            app_data: Err(AnnounceError::NoNetworkIdentity { name }),
                        });
                        return;
                    };
                    let encrypted = rns_crypto::identity::Identity::from_public_key(&public_key)
                        .and_then(|identity| identity.encrypt(&payload, &mut rns_crypto::OsRng));
                    match encrypted {
                        Ok(ciphertext) => payload = ciphertext,
                        Err(error) => {
                            let _ = tx.send(AnnounceResult {
                                interface_name,
                                app_data: Err(AnnounceError::Encryption(error)),
                            });
                            return;
                        }
                    }
                    flags |= FLAG_ENCRYPTED;
                }
                let mut app_data = Vec::with_capacity(1 + payload.len());
                app_data.push(flags);
                app_data.extend_from_slice(&payload);

                let _ = tx.send(AnnounceResult {
                    interface_name,
                    app_data: Ok(app_data),
                });
            });
        }
    }

    /// Non-blocking poll: returns completed app_data if a background stamp
    /// job has finished.
    pub fn poll_ready(&mut self) -> Option<AnnounceResult> {
        match self.stamp_rx.try_recv() {
            Ok(result) => {
                self.stamp_pending = false;
                Some(result)
            }
            Err(_) => None,
        }
    }

    /// Returns true if the announcer currently tracks a discoverable interface by name.
    pub fn contains_interface(&self, interface_name: &str) -> bool {
        self.interfaces
            .iter()
            .any(|iface| iface.interface_name == interface_name)
    }

    /// Insert or update a discoverable interface by configured name.
    pub fn upsert_interface(&mut self, iface: DiscoverableInterface) {
        if let Some(index) = self
            .interfaces
            .iter()
            .position(|existing| existing.interface_name == iface.interface_name)
        {
            self.interfaces[index] = iface;
            return;
        }
        self.interfaces.push(iface);
        self.last_announced.push(0.0);
    }

    /// Remove a discoverable interface by configured name.
    pub fn remove_interface(&mut self, interface_name: &str) -> bool {
        if let Some(index) = self
            .interfaces
            .iter()
            .position(|iface| iface.interface_name == interface_name)
        {
            self.interfaces.remove(index);
            self.last_announced.remove(index);
            true
        } else {
            false
        }
    }

    /// Returns true if no discoverable interfaces remain.
    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
    }

    /// Pack interface metadata as msgpack map with integer keys.
    fn pack_interface_info(
        transport_id: &[u8; 16],
        iface: &DiscoverableInterface,
        requirements: &rns_core::transport::types::StampRequirements,
    ) -> Result<Vec<u8>, AnnounceError> {
        if matches!(
            iface.config.interface_type.as_str(),
            "BackboneInterface" | "TCPServerInterface"
        ) && iface.config.reachable_on.is_none()
        {
            return Err(AnnounceError::NoReachableAddress {
                interface_type: iface.config.interface_type.clone(),
            });
        }
        let mut entries: Vec<(msgpack::Value, msgpack::Value)> = vec![
            (
                msgpack::Value::UInt(INTERFACE_TYPE as u64),
                msgpack::Value::Str(iface.config.interface_type.clone()),
            ),
            (
                msgpack::Value::UInt(TRANSPORT as u64),
                msgpack::Value::Bool(iface.transport_enabled),
            ),
            (
                msgpack::Value::UInt(NAME as u64),
                msgpack::Value::Str(iface.config.discovery_name.clone()),
            ),
            (
                msgpack::Value::UInt(TRANSPORT_ID as u64),
                msgpack::Value::Bin(transport_id.to_vec()),
            ),
            (
                msgpack::Value::UInt(TRANSPORT_IMPL as u64),
                msgpack::Value::Str(TRANSPORT_IMPLEMENTATION_NAME.into()),
            ),
            (
                msgpack::Value::UInt(TRANSPORT_VERS as u64),
                msgpack::Value::Str(TRANSPORT_IMPLEMENTATION_VERSION.into()),
            ),
            // The interface's required costs, quantized (9b464382).
            (
                msgpack::Value::UInt(DST_COST as u64),
                msgpack::Value::Float(
                    iface
                        .config
                        .stamp_costs
                        .destination_cost(requirements)
                        .as_f64(),
                ),
            ),
            (
                msgpack::Value::UInt(PR_COST as u64),
                msgpack::Value::Float(iface.config.stamp_costs.pr_cost(requirements).as_f64()),
            ),
        ];
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
        // Upstream always sends the location, nil when unknown, and its
        // receivers reject an announce without these keys.
        for (key, value) in [
            (LATITUDE, iface.config.latitude),
            (LONGITUDE, iface.config.longitude),
            (HEIGHT, iface.config.height),
        ] {
            entries.push((
                msgpack::Value::UInt(key as u64),
                value.map_or(msgpack::Value::Nil, msgpack::Value::Float),
            ));
        }
        if let Some(address) = iface.config.operator_lxmf_address {
            entries.push((
                msgpack::Value::UInt(OP_ADDR as u64),
                msgpack::Value::Bin(address.to_vec()),
            ));
        }
        let radio = &iface.config.radio;
        for (key, value) in [
            (FREQUENCY, radio.frequency),
            (BANDWIDTH, radio.bandwidth),
            (SPREADINGFACTOR, radio.spreading_factor),
            (CODINGRATE, radio.coding_rate),
        ] {
            if let Some(value) = value {
                entries.push((
                    msgpack::Value::UInt(key as u64),
                    msgpack::Value::UInt(value),
                ));
            }
        }
        if let Some(modulation) = radio.modulation.as_deref().filter(|m| !m.is_empty()) {
            entries.push((
                msgpack::Value::UInt(MODULATION as u64),
                msgpack::Value::Str(modulation.to_string()),
            ));
        }
        // Upstream announces IFAC credentials only with `publish_ifac`.
        let publish_ifac = iface.config.publish_ifac;
        if let Some(netname) = iface
            .ifac_netname
            .as_deref()
            .filter(|v| publish_ifac && !v.is_empty() && *v != "None")
        {
            entries.push((
                msgpack::Value::UInt(IFAC_NETNAME as u64),
                msgpack::Value::Str(netname.to_string()),
            ));
        }
        if let Some(netkey) = iface
            .ifac_netkey
            .as_deref()
            .filter(|v| publish_ifac && !v.is_empty() && *v != "None")
        {
            entries.push((
                msgpack::Value::UInt(IFAC_NETKEY as u64),
                msgpack::Value::Str(netkey.to_string()),
            ));
        }

        Ok(msgpack::pack(&msgpack::Value::Map(entries)))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn discovery_test_dir(label: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "rns-discovery-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn test_announce_interface(name: &str, interval: u64) -> DiscoverableInterface {
        DiscoverableInterface {
            interface_name: name.to_string(),
            config: DiscoveryConfig {
                stamp_costs: Default::default(),
                publish_ifac: true,
                encrypt: false,
                radio: Default::default(),
                discovery_name: format!("Discovery {name}"),
                announce_interval: interval,
                stamp_value: rns_core::stamp::StampCost::ZERO,
                reachable_on: Some("example.test".into()),
                interface_type: "BackboneInterface".into(),
                listen_port: Some(4242),
                location_cmd: None,
                latitude: Some(45.0),
                longitude: Some(9.0),
                height: Some(100.0),
                operator_lxmf_address: None,
            },
            transport_enabled: true,
            ifac_netname: Some("testnet".into()),
            ifac_netkey: Some("secret".into()),
        }
    }

    fn wait_for_announce(announcer: &mut InterfaceAnnouncer) -> AnnounceResult {
        for _ in 0..10_000 {
            if let Some(result) = announcer.poll_ready() {
                return result;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("background discovery job did not complete");
    }

    fn packed_keys(iface: &DiscoverableInterface) -> Vec<(u8, msgpack::Value)> {
        let packed =
            InterfaceAnnouncer::pack_interface_info(&[0x77; 16], iface, &Default::default())
                .unwrap();
        msgpack::unpack_exact(&packed)
            .unwrap()
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.as_uint().unwrap() as u8, v.clone()))
            .collect()
    }

    #[test]
    fn ifac_credentials_are_announced_only_with_publish_ifac() {
        let mut iface = test_announce_interface("ifac", 10);
        iface.config.publish_ifac = false;
        let keys = packed_keys(&iface);
        assert!(!keys
            .iter()
            .any(|(k, _)| *k == IFAC_NETNAME || *k == IFAC_NETKEY));

        iface.config.publish_ifac = true;
        let keys = packed_keys(&iface);
        let value = |key| keys.iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone());
        assert_eq!(
            value(IFAC_NETNAME),
            Some(msgpack::Value::Str("testnet".into()))
        );
        assert_eq!(
            value(IFAC_NETKEY),
            Some(msgpack::Value::Str("secret".into()))
        );
    }

    #[test]
    fn location_is_always_announced_as_upstream_requires() {
        let mut iface = test_announce_interface("nowhere", 10);
        iface.config.latitude = None;
        iface.config.longitude = None;
        iface.config.height = None;
        let keys = packed_keys(&iface);
        for key in [LATITUDE, LONGITUDE, HEIGHT] {
            assert_eq!(
                keys.iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone()),
                Some(msgpack::Value::Nil),
                "key {key}"
            );
        }
    }

    #[test]
    fn radio_parameters_are_announced() {
        let mut iface = test_announce_interface("radio", 10);
        iface.config.interface_type = "RNodeInterface".into();
        iface.config.radio = DiscoveryRadio {
            frequency: Some(868_000_000),
            bandwidth: Some(125_000),
            spreading_factor: Some(8),
            coding_rate: Some(5),
            modulation: Some("lora".into()),
        };
        let keys = packed_keys(&iface);
        let value = |key| keys.iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone());
        assert_eq!(value(FREQUENCY), Some(msgpack::Value::UInt(868_000_000)));
        assert_eq!(value(BANDWIDTH), Some(msgpack::Value::UInt(125_000)));
        assert_eq!(value(SPREADINGFACTOR), Some(msgpack::Value::UInt(8)));
        assert_eq!(value(CODINGRATE), Some(msgpack::Value::UInt(5)));
        assert_eq!(value(MODULATION), Some(msgpack::Value::Str("lora".into())));
    }

    #[test]
    fn encrypted_announces_are_read_only_with_the_network_identity() {
        let network = rns_crypto::identity::Identity::new(&mut rns_crypto::OsRng);
        let mut iface = test_announce_interface("encrypted", 10);
        iface.config.encrypt = true;

        // Without a network identity the announce is not sent.
        let mut announcer = InterfaceAnnouncer::new([0x77; 16], vec![iface.clone()]);
        announcer.maybe_start(10.0);
        let error = wait_for_announce(&mut announcer)
            .app_data
            .unwrap_err()
            .to_string();
        assert!(error.contains("no network identity"), "{error}");

        let mut announcer = InterfaceAnnouncer::new([0x77; 16], vec![iface]);
        announcer.set_network_public_key(network.get_public_key());
        announcer.maybe_start(10.0);
        let app_data = wait_for_announce(&mut announcer).app_data.unwrap();
        assert_ne!(app_data[0] & FLAG_ENCRYPTED, 0);

        let parse = |identity: Option<&rns_crypto::identity::Identity>| {
            parse_interface_announce_with_identity(
                &app_data,
                &[0x77; 16],
                1,
                rns_core::stamp::StampCost::ZERO,
                &mut DiscoveryStampCache::with_capacity(8),
                identity,
                time::now(),
            )
        };
        let discovered = parse(Some(&network)).expect("the network identity reads it");
        assert_eq!(discovered.name, "Discovery encrypted");
        assert!(parse(None).is_none());
        let other = rns_crypto::identity::Identity::new(&mut rns_crypto::OsRng);
        assert!(parse(Some(&other)).is_none());
    }

    #[test]
    fn location_errors_keep_their_messages() {
        let message = |output: &[u8]| parse_location_output(output).unwrap_err().to_string();
        assert_eq!(
            message(&vec![b'0'; LOCATION_CMD_MAX_STDOUT + 1]),
            "location command output exceeds 4096 bytes"
        );
        assert!(message(&[0xff]).starts_with("location command output is not UTF-8: "));
        assert_eq!(
            message(b"1,2,3\n4,5,6\n"),
            "location command must output exactly one line"
        );
        assert_eq!(
            message(b"1,2"),
            "location command returned 2 components; expected 3"
        );
        assert_eq!(
            message(b"one,2,3"),
            "invalid latitude 'one': invalid float literal"
        );
        assert_eq!(message(b"1,inf,3"), "longitude must be finite");
        assert_eq!(message(b"91.5,2,3"), "latitude 91.5 is outside -90..=90");
        assert_eq!(message(b"1,181,3"), "longitude 181 is outside -180..=180");
        assert_eq!(
            message(b"1,2,-4001"),
            "height -4001 is outside -4000..=1000000"
        );
        #[cfg(unix)]
        assert_eq!(
            expand_location_path("~", None).unwrap_err().to_string(),
            "cannot expand location command '~' because HOME is not set"
        );
        assert_eq!(
            LocationError::TimedOut.to_string(),
            "location command timed out after 5 seconds"
        );
    }

    #[test]
    fn location_output_parser_enforces_shape_finiteness_and_ranges() {
        for valid in [
            "-90,-180,-4000",
            "90,180,1000000\n",
            " 45.5, 9.25, 123.0\r\n",
        ] {
            assert!(parse_location_output(valid.as_bytes()).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "1,2",
            "1,2,3,4",
            "one,2,3",
            "NaN,2,3",
            "inf,2,3",
            "91,2,3",
            "1,181,3",
            "1,2,-4001",
            "1,2,1000001",
            "1,2,3\n4,5,6\n",
        ] {
            assert!(
                parse_location_output(invalid.as_bytes()).is_err(),
                "{invalid}"
            );
        }
        assert!(parse_location_output(&[0xff, 0xfe]).is_err());
        assert!(parse_location_output(&vec![b'0'; LOCATION_CMD_MAX_STDOUT + 1]).is_err());
    }

    #[cfg(unix)]
    fn executable_script(body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rns-location-command-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        // Some overlay filesystems briefly report ETXTBSY immediately after
        // replacing an executable inode.
        std::thread::sleep(Duration::from_millis(10));
        path
    }

    #[cfg(unix)]
    #[test]
    fn location_command_is_direct_bounded_and_overrides_static_coordinates() {
        use std::os::unix::fs::PermissionsExt;

        let home = std::ffi::OsString::from("/tmp/rns-home");
        assert_eq!(
            expand_location_path("~/bin/location", Some(home)).unwrap(),
            PathBuf::from("/tmp/rns-home/bin/location")
        );
        assert!(expand_location_path("~/bin/location", None).is_err());

        let success = executable_script("printf '12.5,-44.25,321\\n'");
        assert_eq!(
            resolve_location(success.to_str().unwrap()).unwrap(),
            (12.5, -44.25, 321.0)
        );

        let mut iface = test_announce_interface("dynamic", 1);
        iface.config.location_cmd = Some(success.to_string_lossy().into_owned());
        let packed = prepare_interface_info(&[0x55; 16], &iface, &Default::default()).unwrap();
        let (value, consumed) = msgpack::unpack(&packed).unwrap();
        assert_eq!(consumed, packed.len());
        let Value::Map(entries) = value else {
            panic!("discovery metadata was not a map")
        };
        let coordinate = |key: u8| {
            entries.iter().find_map(|(candidate, value)| {
                (*candidate == Value::UInt(key as u64)).then_some(value)
            })
        };
        assert_eq!(coordinate(LATITUDE), Some(&Value::Float(12.5)));
        assert_eq!(coordinate(LONGITUDE), Some(&Value::Float(-44.25)));
        assert_eq!(coordinate(HEIGHT), Some(&Value::Float(321.0)));
        assert_eq!(iface.config.latitude, Some(45.0));
        assert_eq!(iface.config.longitude, Some(9.0));
        assert_eq!(iface.config.height, Some(100.0));

        let nonzero = executable_script("exit 7");
        assert!(resolve_location(nonzero.to_str().unwrap()).is_err());
        let oversized = executable_script("head -c 4097 /dev/zero");
        assert!(resolve_location(oversized.to_str().unwrap()).is_err());
        let missing = success.with_extension("missing");
        assert!(resolve_location(missing.to_str().unwrap()).is_err());

        let non_executable = executable_script("printf '1,2,3'");
        let mut permissions = fs::metadata(&non_executable).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&non_executable, permissions).unwrap();
        assert!(resolve_location(non_executable.to_str().unwrap()).is_err());

        for path in [success, nonzero, oversized, non_executable] {
            let _ = fs::remove_file(path);
        }
    }

    #[cfg(unix)]
    #[test]
    fn failed_dynamic_location_is_suppressed_then_retried_at_normal_interval() {
        let failure = executable_script("exit 1");
        let success = executable_script("printf '1,2,3\\n'");
        let mut iface = test_announce_interface("recovering", 10);
        iface.config.location_cmd = Some(failure.to_string_lossy().into_owned());
        let mut announcer = InterfaceAnnouncer::new([0x77; 16], vec![iface.clone()]);

        announcer.maybe_start(10.0);
        assert!(wait_for_announce(&mut announcer).app_data.is_err());
        announcer.maybe_start(19.0);
        assert!(!announcer.stamp_pending);

        iface.config.location_cmd = Some(success.to_string_lossy().into_owned());
        announcer.upsert_interface(iface);
        announcer.maybe_start(20.0);
        assert!(wait_for_announce(&mut announcer).app_data.is_ok());

        let _ = fs::remove_file(failure);
        let _ = fs::remove_file(success);
    }

    #[cfg(unix)]
    #[test]
    fn location_command_timeout_kills_and_reaps_child() {
        let command = executable_script("exec sleep 30");
        let started = Instant::now();
        let error = resolve_location(command.to_str().unwrap()).unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(7));
        let _ = fs::remove_file(command);
    }

    #[cfg(unix)]
    #[test]
    fn documented_location_stanza_parses_and_example_output_resolves() {
        use std::os::unix::fs::PermissionsExt;

        const STANZA: &str = r#"[interfaces]
  [[Mobile Backbone]]
    type = BackboneInterface
    enabled = yes
    interface_mode = internal
    listen_ip = 0.0.0.0
    listen_port = 4242
    discoverable = yes
    discovery_name = Mobile Backbone
    discovery_lxmf_address = 0123456789abcdef0123456789abcdef
    reachable_on = backbone.example.net
    location_cmd = ~/bin/reticulum-location"#;
        const OUTPUT: &str = "45.4642,9.1900,122.5\n";
        let documentation = include_str!("../../docs/interface-discovery.md");
        assert!(documentation.contains(STANZA));
        assert!(documentation.contains(OUTPUT.trim_end()));

        let parsed = crate::config::parse(STANZA).unwrap();
        assert_eq!(
            parsed.interfaces[0]
                .params
                .get("discovery_lxmf_address")
                .map(String::as_str),
            Some("0123456789abcdef0123456789abcdef")
        );
        let command = parsed.interfaces[0].params.get("location_cmd").unwrap();
        let home = std::env::temp_dir().join(format!(
            "rns-documented-location-home-{}",
            std::process::id()
        ));
        let bin = home.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let path = expand_location_path(command, Some(home.clone().into_os_string())).unwrap();
        fs::write(&path, format!("#!/bin/sh\nprintf '{OUTPUT}'\n")).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        std::thread::sleep(Duration::from_millis(10));

        assert_eq!(
            resolve_location(path.to_str().unwrap()).unwrap(),
            (45.4642, 9.19, 122.5)
        );
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn announcer_selects_due_interfaces_one_job_at_a_time_and_accounts_interval() {
        let mut announcer = InterfaceAnnouncer::new(
            [0x42; 16],
            vec![
                test_announce_interface("first", 10),
                test_announce_interface("second", 10),
            ],
        );

        announcer.maybe_start(10.0);
        assert!(announcer.stamp_pending);
        assert_eq!(announcer.last_announced, vec![10.0, 0.0]);
        announcer.maybe_start(20.0);
        assert_eq!(announcer.last_announced, vec![10.0, 0.0]);

        let first = wait_for_announce(&mut announcer);
        assert_eq!(first.interface_name, "first");
        assert!(first.app_data.is_ok());
        assert!(!announcer.stamp_pending);

        announcer.maybe_start(20.0);
        let second = wait_for_announce(&mut announcer);
        assert_eq!(second.interface_name, "second");
        assert_eq!(announcer.last_announced, vec![10.0, 20.0]);
    }

    #[test]
    fn poll_ready_clears_pending_for_failed_generation() {
        let mut announcer = InterfaceAnnouncer::new([0; 16], vec![]);
        announcer.stamp_pending = true;
        announcer
            .stamp_tx
            .send(AnnounceResult {
                interface_name: "failed".into(),
                app_data: Err(AnnounceError::Location(LocationError::TimedOut)),
            })
            .unwrap();

        let result = announcer.poll_ready().unwrap();
        assert!(matches!(
            result.app_data,
            Err(AnnounceError::Location(LocationError::TimedOut))
        ));
        assert!(!announcer.stamp_pending);
    }

    #[test]
    fn background_packing_preserves_static_metadata_bytes() {
        let iface = test_announce_interface("static", 1);
        let expected =
            InterfaceAnnouncer::pack_interface_info(&[0x24; 16], &iface, &Default::default())
                .unwrap();
        let mut announcer = InterfaceAnnouncer::new([0x24; 16], vec![iface]);

        announcer.maybe_start(1.0);
        let result = wait_for_announce(&mut announcer).app_data.unwrap();
        assert_eq!(&result[1..result.len() - STAMP_SIZE], expected.as_slice());
    }

    #[test]
    fn announcer_packs_operator_lxmf_address() {
        let mut iface = test_announce_interface("operator", 1);
        iface.config.operator_lxmf_address = Some([0xa5; 16]);

        let packed =
            InterfaceAnnouncer::pack_interface_info(&[0x24; 16], &iface, &Default::default())
                .unwrap();
        let (Value::Map(entries), consumed) = msgpack::unpack(&packed).unwrap() else {
            panic!("discovery metadata was not a map")
        };

        assert_eq!(consumed, packed.len());
        assert!(entries.contains(&(Value::UInt(OP_ADDR as u64), Value::Bin(vec![0xa5; 16]),)));
    }

    #[test]
    fn announcer_identifies_native_transport_implementation_and_version() {
        let iface = test_announce_interface("implementation", 1);
        let packed =
            InterfaceAnnouncer::pack_interface_info(&[0x24; 16], &iface, &Default::default())
                .unwrap();
        let (Value::Map(entries), consumed) = msgpack::unpack(&packed).unwrap() else {
            panic!("discovery metadata was not a map")
        };

        assert_eq!(consumed, packed.len());
        assert!(entries.contains(&(
            Value::UInt(TRANSPORT_IMPL as u64),
            Value::Str("rns-rs".into()),
        )));
        assert!(entries.contains(&(
            Value::UInt(TRANSPORT_VERS as u64),
            Value::Str(env!("CARGO_PKG_VERSION").into()),
        )));
    }

    #[test]
    fn announcer_packs_the_interface_stamp_costs() {
        // 9b464382: DST_COST / PR_COST carry the quantized interface costs,
        // the node-wide ones where the interface sets none.
        let requirements = rns_core::transport::types::StampRequirements {
            enforced: false,
            destination_cost: StampCost::from_f64(23.5),
            path_request_cost: StampCost::from_f64(15.8),
        };
        let mut iface = test_announce_interface("costs", 1);
        let cost_of = |iface: &DiscoverableInterface, key: u8| {
            let packed =
                InterfaceAnnouncer::pack_interface_info(&[0x24; 16], iface, &requirements).unwrap();
            let (Value::Map(entries), _) = msgpack::unpack(&packed).unwrap() else {
                panic!("discovery metadata was not a map")
            };
            entries
                .into_iter()
                .find(|(k, _)| *k == Value::UInt(key as u64))
                .map(|(_, v)| v)
        };
        assert_eq!(cost_of(&iface, DST_COST), Some(Value::Float(23.5)));
        // quantize_cost(15.8)
        assert_eq!(cost_of(&iface, PR_COST), Some(Value::Float(15.80078125)));

        iface.config.stamp_costs.destination_cost = Some(StampCost::from_f64(12.2));
        assert_eq!(
            cost_of(&iface, DST_COST),
            Some(Value::Float(StampCost::from_f64(12.2).as_f64()))
        );
        assert_eq!(cost_of(&iface, PR_COST), Some(Value::Float(15.80078125)));
    }

    #[test]
    fn announcer_suppresses_network_discovery_without_reachable_address() {
        for interface_type in ["BackboneInterface", "TCPServerInterface"] {
            let mut iface = test_announce_interface("missing-address", 1);
            iface.config.interface_type = interface_type.into();
            iface.config.reachable_on = None;

            assert_eq!(
                InterfaceAnnouncer::pack_interface_info(&[0x24; 16], &iface, &Default::default())
                    .map_err(|error| error.to_string()),
                Err(format!(
                    "{interface_type} discovery requires a reachable_on address"
                ))
            );
        }
    }

    fn test_discovered_interface(name: &str) -> DiscoveredInterface {
        DiscoveredInterface {
            dst_cost: None,
            pr_cost: None,
            interface_type: "BackboneInterface".into(),
            impl_name: None,
            impl_version: None,
            transport: true,
            name: name.into(),
            discovered: 1700000000.0,
            last_heard: 1700001000.0,
            heard_count: 5,
            status: DiscoveredStatus::Available,
            stamp: vec![0x42u8; 64],
            stamp_value: rns_core::stamp::StampValue::from_whole(18),
            transport_id: [0x01u8; 16],
            network_id: [0x02u8; 16],
            hops: 2,
            latitude: Some(45.0),
            longitude: Some(9.0),
            height: Some(100.0),
            operator_lxmf_address: Some([0xa5; 16]),
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
            discovery_hash: compute_discovery_hash(&[0x01u8; 16], name),
        }
    }

    fn upstream_record(name: &str) -> Vec<u8> {
        fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/fixtures/discovery")
                .join(format!("{name}.msgpack")),
        )
        .unwrap()
    }

    /// Records written by upstream (tests/generate_discovery_record_fixtures.py)
    /// load, and serialize back to the very same bytes.
    #[test]
    fn upstream_records_load_and_serialize_byte_for_byte() {
        let storage = DiscoveredInterfaceStorage::new(std::env::temp_dir());
        for name in ["upstream_backbone_record", "upstream_rnode_record"] {
            let bytes = upstream_record(name);
            let iface = storage.deserialize_interface(&bytes).unwrap();
            assert_eq!(
                storage.serialize_interface(&iface).unwrap(),
                bytes,
                "{name}"
            );
        }

        let backbone = storage
            .deserialize_interface(&upstream_record("upstream_backbone_record"))
            .unwrap();
        assert_eq!(backbone.name, "Backbone North");
        assert_eq!(backbone.transport_id, [0x01; 16]);
        assert_eq!(backbone.network_id, [0x02; 16]);
        assert_eq!(backbone.operator_lxmf_address, Some([0xa5; 16]));
        assert_eq!(backbone.reachable_on.as_deref(), Some("example.com"));
        assert_eq!(backbone.port, Some(4242));
        assert_eq!(backbone.heard_count, 5);
        assert_eq!(backbone.impl_name.as_deref(), Some("RNS"));
        assert_eq!(
            backbone.discovery_hash,
            compute_discovery_hash(&[0x01; 16], "Backbone North")
        );
        let rnode = storage
            .deserialize_interface(&upstream_record("upstream_rnode_record"))
            .unwrap();
        assert_eq!(rnode.frequency, Some(868_000_000));
        assert_eq!(rnode.spreading_factor, Some(8));
        assert_eq!(rnode.impl_name, None);
        assert_eq!(rnode.latitude, None);
    }

    /// A record stored under the earlier, raw-byte discovery hash moves to
    /// upstream's file name when listed, or goes when that name exists.
    #[test]
    fn records_under_the_earlier_discovery_hash_are_migrated() {
        let dir = std::env::temp_dir().join(format!(
            "rns-discovery-hash-migration-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let storage = DiscoveredInterfaceStorage::new(dir.clone());
        let old_hash = |iface: &DiscoveredInterface| {
            let mut material = iface.transport_id.to_vec();
            material.extend_from_slice(iface.name.as_bytes());
            sha256(&material)
        };

        let mut moved = test_discovered_interface("Moved");
        moved.discovery_hash = old_hash(&moved);
        storage.store(&moved).unwrap();
        let mut stale_copy = test_discovered_interface("Twice");
        storage.store(&stale_copy).unwrap();
        stale_copy.discovery_hash = old_hash(&stale_copy);
        storage.store(&stale_copy).unwrap();

        let mut listed: Vec<String> = storage
            .list()
            .unwrap()
            .into_iter()
            .map(|i| i.name)
            .collect();
        listed.sort();
        assert_eq!(listed, ["Moved", "Twice"]);
        let mut files: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        files.sort();
        let mut expected = vec![
            hex(&compute_discovery_hash(&moved.transport_id, "Moved")),
            hex(&compute_discovery_hash(&stale_copy.transport_id, "Twice")),
        ];
        expected.sort();
        assert_eq!(files, expected);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Records this implementation wrote before it used upstream's format
    /// (raw-byte ids, a stored status) still load.
    #[test]
    fn records_in_the_earlier_format_still_load() {
        let iface = test_discovered_interface("Legacy");
        let key = |name: &str| Value::Str(name.into());
        let legacy = msgpack::pack(&Value::Map(vec![
            (key("type"), Value::Str(iface.interface_type.clone())),
            (key("transport"), Value::Bool(true)),
            (key("name"), Value::Str("Legacy".into())),
            (key("discovered"), Value::Float(1.0)),
            (key("last_heard"), Value::Float(2.0)),
            (key("heard_count"), Value::UInt(3)),
            (key("status"), Value::Str("stale".into())),
            (key("stamp"), Value::Bin(vec![0x42; 64])),
            (key("value"), Value::Float(18.0)),
            (key("transport_id"), Value::Bin(vec![0x01; 16])),
            (key("network_id"), Value::Bin(vec![0x02; 16])),
            (key("hops"), Value::UInt(2)),
            (key("operator_lxmf_address"), Value::Bin(vec![0xa5; 16])),
            (
                key("discovery_hash"),
                Value::Bin(iface.discovery_hash.to_vec()),
            ),
        ]));
        let storage = DiscoveredInterfaceStorage::new(std::env::temp_dir());
        let loaded = storage.deserialize_interface(&legacy).unwrap();
        assert_eq!(loaded.transport_id, [0x01; 16]);
        assert_eq!(loaded.network_id, [0x02; 16]);
        assert_eq!(loaded.operator_lxmf_address, Some([0xa5; 16]));
        assert_eq!(loaded.status, DiscoveredStatus::Stale);
        assert_eq!(loaded.heard_count, 3);
    }

    #[test]
    fn test_storage_roundtrip() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("rns-discovery-test-{}-{}", std::process::id(), id));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let storage = DiscoveredInterfaceStorage::new(dir.clone());

        let mut iface = test_discovered_interface("TestNode");
        iface.impl_name = Some("Reticulum".into());
        iface.impl_version = Some("1.5.5".into());
        iface.dst_cost = Some(StampCost::from_f64(23.5));
        iface.pr_cost = Some(StampCost::from_f64(15.8));

        // Store
        storage.store(&iface).unwrap();

        // Load
        let loaded = storage.load(&iface.discovery_hash).unwrap().unwrap();

        assert_eq!(loaded.interface_type, iface.interface_type);
        assert_eq!(loaded.impl_name, iface.impl_name);
        assert_eq!(loaded.impl_version, iface.impl_version);
        assert_eq!(loaded.dst_cost, iface.dst_cost);
        assert_eq!(loaded.pr_cost, iface.pr_cost);
        assert_eq!(loaded.name, iface.name);
        assert_eq!(loaded.stamp_value, iface.stamp_value);
        assert_eq!(loaded.transport_id, iface.transport_id);
        assert_eq!(loaded.hops, iface.hops);
        assert_eq!(loaded.latitude, iface.latitude);
        assert_eq!(loaded.operator_lxmf_address, iface.operator_lxmf_address);
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
    fn storage_load_sanitizes_cached_interface_names() {
        let dir = std::env::temp_dir().join(format!(
            "rns-discovery-sanitize-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let storage = DiscoveredInterfaceStorage::new(dir.clone());
        let iface = test_discovered_interface("\t**Cached     Name!!!\n");

        storage.store(&iface).unwrap();

        let loaded = storage.load(&iface.discovery_hash).unwrap().unwrap();
        let listed = storage.list().unwrap();

        assert_eq!(loaded.name, "Cached Name");
        assert_eq!(listed[0].name, "Cached Name");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn storage_rejects_cached_transport_id_with_invalid_length() {
        let storage = DiscoveredInterfaceStorage::new(std::env::temp_dir());
        let iface = test_discovered_interface("BadTransportId");
        let mut data = storage.serialize_interface(&iface).unwrap();
        let (mut value, _) = msgpack::unpack(&data).unwrap();
        if let Value::Map(ref mut entries) = value {
            for (key, val) in entries {
                if key.as_str() == Some("transport_id") {
                    *val = Value::Bin(vec![0x01; 15]);
                }
            }
        }
        data = msgpack::pack(&value);

        let err = storage.deserialize_interface(&data).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("transport_id"));
    }

    #[test]
    fn store_received_preserves_existing_first_seen_and_increments_heard_count() {
        let dir = std::env::temp_dir().join(format!(
            "rns-discovery-received-preserve-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let storage = DiscoveredInterfaceStorage::new(dir.clone());

        let mut existing = test_discovered_interface("ExistingDiscovery");
        existing.discovered = 1000.0;
        existing.last_heard = 1100.0;
        existing.heard_count = 7;
        storage.store(&existing).unwrap();

        let mut received = existing.clone();
        received.discovered = 2000.0;
        received.last_heard = 3000.0;
        received.heard_count = 0;
        storage.store_received(&mut received).unwrap();

        let loaded = storage.load(&received.discovery_hash).unwrap().unwrap();
        assert_eq!(received.discovered, 1000.0);
        assert_eq!(received.last_heard, 3000.0);
        assert_eq!(received.heard_count, 8);
        assert_eq!(loaded.discovered, 1000.0);
        assert_eq!(loaded.last_heard, 3000.0);
        assert_eq!(loaded.heard_count, 8);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_received_serializes_concurrent_counter_updates() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let dir = std::env::temp_dir().join(format!(
            "rns-discovery-concurrent-received-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let storage = Arc::new(DiscoveredInterfaceStorage::new(dir.clone()));

        let mut existing = test_discovered_interface("ConcurrentDiscovery");
        existing.discovered = 1000.0;
        existing.last_heard = 1000.0;
        existing.heard_count = 0;
        storage.store(&existing).unwrap();

        let threads = 16;
        let updates_per_thread = 25;
        let barrier = Arc::new(Barrier::new(threads));
        let mut handles = Vec::new();
        for thread_id in 0..threads {
            let storage = Arc::clone(&storage);
            let barrier = Arc::clone(&barrier);
            let template = existing.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                for update in 0..updates_per_thread {
                    let mut received = template.clone();
                    received.last_heard = 2000.0 + (thread_id * updates_per_thread + update) as f64;
                    storage.store_received(&mut received).unwrap();
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let loaded = storage.load(&existing.discovery_hash).unwrap().unwrap();
        assert_eq!(loaded.discovered, 1000.0);
        assert_eq!(loaded.heard_count as usize, threads * updates_per_thread);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_received_recreates_corrupt_cache_with_received_time_as_first_seen() {
        let dir = std::env::temp_dir().join(format!(
            "rns-discovery-corrupt-recreate-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let storage = DiscoveredInterfaceStorage::new(dir.clone());

        let mut received = test_discovered_interface("CorruptDiscovery");
        received.discovered = 1234.0;
        received.last_heard = 5678.0;
        received.heard_count = 0;
        let filepath = dir.join(hex(&received.discovery_hash));
        fs::write(&filepath, b"not msgpack").unwrap();

        storage.store_received(&mut received).unwrap();

        let loaded = storage.load(&received.discovery_hash).unwrap().unwrap();
        assert_eq!(received.discovered, 5678.0);
        assert_eq!(received.heard_count, 1);
        assert_eq!(loaded.discovered, 5678.0);
        assert_eq!(loaded.last_heard, 5678.0);
        assert_eq!(loaded.heard_count, 1);
        assert_eq!(loaded.name, "CorruptDiscovery");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_removes_discoveries_for_blackholed_network_and_transport_identities() {
        let dir = discovery_test_dir("blackholed-cleanup");
        fs::create_dir_all(&dir).unwrap();
        let storage = DiscoveredInterfaceStorage::new(dir.clone());
        let now = time::now();

        let mut network_blocked = test_discovered_interface("NetworkBlocked");
        network_blocked.last_heard = now;
        network_blocked.network_id = [0x31; 16];
        let mut transport_blocked = test_discovered_interface("TransportBlocked");
        transport_blocked.last_heard = now;
        transport_blocked.transport_id = [0x42; 16];
        let mut retained = test_discovered_interface("Retained");
        retained.last_heard = now;
        retained.network_id = [0x53; 16];
        retained.transport_id = [0x64; 16];
        storage.store(&network_blocked).unwrap();
        storage.store(&transport_blocked).unwrap();
        storage.store(&retained).unwrap();

        let removed = storage
            .cleanup_with_blackholes(|identity| identity == &[0x31; 16] || identity == &[0x42; 16])
            .unwrap();

        assert_eq!(removed, 2);
        let listed = storage.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "Retained");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_removes_discoveries_of_networks_that_are_not_sources() {
        let dir = discovery_test_dir("sources-cleanup");
        fs::create_dir_all(&dir).unwrap();
        let storage = DiscoveredInterfaceStorage::new(dir.clone());
        let now = time::now();
        for (name, network_id) in [("FromSource", [0x31; 16]), ("FromOther", [0x42; 16])] {
            let mut iface = test_discovered_interface(name);
            iface.last_heard = now;
            iface.network_id = network_id;
            storage.store(&iface).unwrap();
        }

        let removed = storage
            .cleanup_with_filters(|_| false, |network_id| network_id == &[0x31; 16])
            .unwrap();

        assert_eq!(removed, 1);
        let listed = storage.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "FromSource");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_removes_cached_discoveries_with_missing_or_empty_identities() {
        let dir = discovery_test_dir("invalid-identity-cleanup");
        fs::create_dir_all(&dir).unwrap();
        let storage = DiscoveredInterfaceStorage::new(dir.clone());
        let iface = test_discovered_interface("InvalidIdentity");
        let valid = storage.serialize_interface(&iface).unwrap();

        let (mut missing_transport, _) = msgpack::unpack(&valid).unwrap();
        if let Value::Map(entries) = &mut missing_transport {
            entries.retain(|(key, _)| key.as_str() != Some("transport_id"));
        }
        fs::write(
            dir.join("missing-transport"),
            msgpack::pack(&missing_transport),
        )
        .unwrap();

        let (mut empty_network, _) = msgpack::unpack(&valid).unwrap();
        if let Value::Map(entries) = &mut empty_network {
            for (key, value) in entries {
                if key.as_str() == Some("network_id") {
                    *value = Value::Bin(Vec::new());
                }
            }
        }
        fs::write(dir.join("empty-network"), msgpack::pack(&empty_network)).unwrap();
        fs::write(dir.join("corrupt-msgpack"), b"not msgpack").unwrap();

        assert_eq!(storage.cleanup().unwrap(), 3);
        assert!(storage.list().unwrap().is_empty());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_filter_and_sort() {
        let now = time::now();

        let ifaces = vec![
            DiscoveredInterface {
                dst_cost: None,
                pr_cost: None,
                interface_type: "BackboneInterface".into(),
                impl_name: None,
                impl_version: None,
                transport: true,
                name: "high-value-stale".into(),
                discovered: now,
                last_heard: now - THRESHOLD_STALE - 100.0, // Stale
                heard_count: 0,
                status: DiscoveredStatus::Stale,
                stamp: vec![],
                stamp_value: rns_core::stamp::StampValue::from_whole(20),
                transport_id: [0u8; 16],
                network_id: [0u8; 16],
                hops: 0,
                latitude: None,
                longitude: None,
                height: None,
                operator_lxmf_address: None,
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
                dst_cost: None,
                pr_cost: None,
                interface_type: "TCPServerInterface".into(),
                impl_name: None,
                impl_version: None,
                transport: true,
                name: "low-value-available".into(),
                discovered: now,
                last_heard: now - 10.0, // Available
                heard_count: 0,
                status: DiscoveredStatus::Available,
                stamp: vec![],
                stamp_value: rns_core::stamp::StampValue::from_whole(10),
                transport_id: [0u8; 16],
                network_id: [0u8; 16],
                hops: 0,
                latitude: None,
                longitude: None,
                height: None,
                operator_lxmf_address: None,
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
                discovery_hash: [1u8; 32],
            },
            DiscoveredInterface {
                dst_cost: None,
                pr_cost: None,
                interface_type: "I2PInterface".into(),
                impl_name: None,
                impl_version: None,
                transport: false,
                name: "high-value-available".into(),
                discovered: now,
                last_heard: now - 10.0, // Available
                heard_count: 0,
                status: DiscoveredStatus::Available,
                stamp: vec![],
                stamp_value: rns_core::stamp::StampValue::from_whole(20),
                transport_id: [0u8; 16],
                network_id: [0u8; 16],
                hops: 0,
                latitude: None,
                longitude: None,
                height: None,
                operator_lxmf_address: None,
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
                discovery_hash: [2u8; 32],
            },
        ];

        // Test no filter — all included, sorted by status then value
        let mut result = ifaces.clone();
        filter_and_sort_interfaces(&mut result, false, false);
        assert_eq!(result.len(), 3);
        // Available ones should come first (higher status code)
        assert_eq!(result[0].name, "high-value-available");
        assert_eq!(result[1].name, "low-value-available");
        assert_eq!(result[2].name, "high-value-stale");

        // Test only_available filter
        let mut result = ifaces.clone();
        filter_and_sort_interfaces(&mut result, true, false);
        assert_eq!(result.len(), 2); // stale one filtered out

        // Test only_transport filter
        let mut result = ifaces.clone();
        filter_and_sort_interfaces(&mut result, false, true);
        assert_eq!(result.len(), 2); // non-transport one filtered out
    }

    #[test]
    fn generated_discovery_stamp_is_accepted_without_external_stamper() {
        let packed = b"internal stamps module";
        // Fractional since upstream 796ef2d4.
        let cost = StampCost::from_f64(8.5);
        let (stamp, value) = generate_discovery_stamp(packed, cost);
        assert!(value.meets(cost));
        let infohash = sha256(packed);
        let workblock = stamp_workblock(&infohash, WORKBLOCK_EXPAND_ROUNDS);
        assert!(stamp_valid(&stamp, cost, &workblock));
    }

    #[cfg(feature = "engine-parallel")]
    #[test]
    fn a_discovery_stamp_search_leaves_the_rayon_pool_free() {
        // An expensive discovery grind must not hold up the short searches
        // that run on the rayon pool, such as a path request stamp with its
        // deadline (vps-us cancelled path requests while one ran). The grind
        // fills the pool only when it has no more threads than the search
        // uses, as on a two-core host: run with RAYON_NUM_THREADS=2 to see
        // the difference on a larger machine.
        let grind = std::thread::spawn(|| {
            let started = std::time::Instant::now();
            generate_discovery_stamp(b"busy discovery grind", StampCost::from_whole(20));
            started.elapsed()
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        let asked = std::time::Instant::now();
        let ran = std::sync::Mutex::new(Vec::new());
        rayon::scope(|scope| {
            for _ in 0..rayon::current_num_threads() {
                scope.spawn(|_| ran.lock().unwrap().push(asked.elapsed()));
            }
        });
        let waited = ran.into_inner().unwrap().into_iter().max().unwrap();
        let grind_took = grind.join().unwrap();
        assert!(
            waited < std::time::Duration::from_millis(500) || grind_took < waited,
            "rayon work waited {waited:?} behind a discovery grind of {grind_took:?}"
        );
    }

    #[test]
    fn test_discovery_name_hash_deterministic() {
        let h1 = discovery_name_hash();
        let h2 = discovery_name_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 10]); // not all zeros
    }
}
