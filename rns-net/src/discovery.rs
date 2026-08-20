//! Interface Discovery protocol implementation.
//!
//! Handles receiving, validating, and storing discovered interface announcements
//! from other Reticulum nodes on the network.
//!
//! Pure types and parsing live in `common::discovery`; this module contains
//! I/O storage and background-threaded stamp generation / announcing.
//!
//! Python reference: RNS/Discovery.py

// Re-export everything from common::discovery so existing `crate::discovery::X` paths work.
pub use crate::common::discovery::*;

use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rns_core::msgpack::{self, Value};
use rns_core::stamp::{stamp_valid, stamp_workblock};
use rns_crypto::sha256::sha256;

use crate::time;

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
        let filename = hex_encode(&iface.discovery_hash);
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
                iface.discovered = iface.last_heard;
                iface.heard_count = 1;
            }
            Err(err) => {
                log::error!(
                    "Error while reading existing data for discovered interface, re-creating data: {}",
                    err
                );
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
        let _guard = discovery_storage_guard();
        self.remove_unlocked(discovery_hash)
    }

    fn remove_unlocked(&self, discovery_hash: &[u8; 32]) -> io::Result<()> {
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
        self.cleanup_with_blackholes(|_| false)
    }

    /// Clean up stale, invalid, or blackholed discovery records.
    pub fn cleanup_with_blackholes<F>(&self, mut is_blackholed: F) -> io::Result<usize>
    where
        F: FnMut(&[u8; 16]) -> bool,
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
            {
                fs::remove_file(&path)?;
                removed += 1;
            }
        }

        Ok(removed)
    }

    /// Serialize an interface to msgpack
    fn serialize_interface(&self, iface: &DiscoveredInterface) -> io::Result<Vec<u8>> {
        let mut entries: Vec<(Value, Value)> = vec![
            (
                Value::Str("type".into()),
                Value::Str(iface.interface_type.clone()),
            ),
            (Value::Str("transport".into()), Value::Bool(iface.transport)),
            (Value::Str("name".into()), Value::Str(iface.name.clone())),
            (
                Value::Str("discovered".into()),
                Value::Float(iface.discovered),
            ),
            (
                Value::Str("last_heard".into()),
                Value::Float(iface.last_heard),
            ),
            (
                Value::Str("heard_count".into()),
                Value::UInt(iface.heard_count as u64),
            ),
            (
                Value::Str("status".into()),
                Value::Str(iface.status.as_str().into()),
            ),
            (Value::Str("stamp".into()), Value::Bin(iface.stamp.clone())),
            (
                Value::Str("value".into()),
                Value::UInt(iface.stamp_value as u64),
            ),
            (
                Value::Str("transport_id".into()),
                Value::Bin(iface.transport_id.to_vec()),
            ),
            (
                Value::Str("network_id".into()),
                Value::Bin(iface.network_id.to_vec()),
            ),
            (Value::Str("hops".into()), Value::UInt(iface.hops as u64)),
        ];

        if let Some(v) = iface.latitude {
            entries.push((Value::Str("latitude".into()), Value::Float(v)));
        }
        if let Some(v) = iface.longitude {
            entries.push((Value::Str("longitude".into()), Value::Float(v)));
        }
        if let Some(v) = iface.height {
            entries.push((Value::Str("height".into()), Value::Float(v)));
        }
        if let Some(v) = iface.operator_lxmf_address {
            entries.push((
                Value::Str("operator_lxmf_address".into()),
                Value::Bin(v.to_vec()),
            ));
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

        entries.push((
            Value::Str("discovery_hash".into()),
            Value::Bin(iface.discovery_hash.to_vec()),
        ));

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

        let fixed_bytes = |key: &str, expected_len: usize| -> io::Result<Vec<u8>> {
            let bytes = get_bytes(&value, key)?;
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

        let status_str = get_str(&value, "status")?;
        let status = match status_str.as_str() {
            "available" => DiscoveredStatus::Available,
            "unknown" => DiscoveredStatus::Unknown,
            "stale" => DiscoveredStatus::Stale,
            _ => DiscoveredStatus::Unknown,
        };

        let interface_type = get_str(&value, "type")?;
        let raw_name = get_str(&value, "name")?;
        let name = sanitize_discovered_name(&raw_name)
            .unwrap_or_else(|| format!("Discovered {}", interface_type));

        Ok(DiscoveredInterface {
            interface_type,
            transport: get_bool(&value, "transport")?,
            name,
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
            operator_lxmf_address: value
                .map_get("operator_lxmf_address")
                .and_then(Value::as_bin)
                .filter(|bytes| bytes.len() == 16)
                .map(|bytes| {
                    let mut address = [0u8; 16];
                    address.copy_from_slice(bytes);
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
            ifac_netname: get_opt_str(&value, "ifac_netname"),
            ifac_netkey: get_opt_str(&value, "ifac_netkey"),
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

/// Generate a discovery stamp with the given cost using rayon parallel iterators.
///
/// Returns `(stamp, value)` on success. This is a blocking, CPU-intensive operation.
pub fn generate_discovery_stamp(packed_data: &[u8], stamp_cost: u8) -> ([u8; STAMP_SIZE], u32) {
    use rns_crypto::{OsRng, Rng};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

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
                        let mut r = match result.lock() {
                            Ok(guard) => guard,
                            Err(poisoned) => {
                                log::error!(
                                    "recovering from poisoned discovery stamp result buffer"
                                );
                                poisoned.into_inner()
                            }
                        };
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

    let stamp = match result.lock() {
        Ok(mut guard) => guard.take(),
        Err(poisoned) => {
            log::error!("recovering from poisoned discovery stamp result buffer");
            poisoned.into_inner().take()
        }
    }
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
    pub app_data: Result<Vec<u8>, String>,
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
}

const LOCATION_CMD_TIMEOUT: Duration = Duration::from_secs(5);
const LOCATION_CMD_MAX_STDOUT: usize = 4096;

fn parse_location_output(output: &[u8]) -> Result<(f64, f64, f64), String> {
    if output.len() > LOCATION_CMD_MAX_STDOUT {
        return Err(format!(
            "location command output exceeds {} bytes",
            LOCATION_CMD_MAX_STDOUT
        ));
    }
    let line = std::str::from_utf8(output)
        .map_err(|error| format!("location command output is not UTF-8: {error}"))?;
    let line = line.strip_suffix('\n').unwrap_or(line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.contains(['\n', '\r']) {
        return Err("location command must output exactly one line".into());
    }
    let values: Vec<&str> = line.split(',').map(str::trim).collect();
    if values.len() != 3 {
        return Err(format!(
            "location command returned {} components; expected 3",
            values.len()
        ));
    }
    let parse = |value: &str, label: &str| {
        value
            .parse::<f64>()
            .map_err(|error| format!("invalid {label} '{value}': {error}"))
            .and_then(|number| {
                number
                    .is_finite()
                    .then_some(number)
                    .ok_or_else(|| format!("{label} must be finite"))
            })
    };
    let latitude = parse(values[0], "latitude")?;
    let longitude = parse(values[1], "longitude")?;
    let height = parse(values[2], "height")?;
    if !(-90.0..=90.0).contains(&latitude) {
        return Err(format!("latitude {latitude} is outside -90..=90"));
    }
    if !(-180.0..=180.0).contains(&longitude) {
        return Err(format!("longitude {longitude} is outside -180..=180"));
    }
    if !(-4000.0..=1_000_000.0).contains(&height) {
        return Err(format!("height {height} is outside -4000..=1000000"));
    }
    Ok((latitude, longitude, height))
}

#[cfg(unix)]
fn expand_location_path(
    command: &str,
    home: Option<std::ffi::OsString>,
) -> Result<PathBuf, String> {
    let path = if command == "~" {
        home.map(PathBuf::from).ok_or_else(|| {
            "cannot expand location command '~' because HOME is not set".to_string()
        })?
    } else if let Some(suffix) = command.strip_prefix("~/") {
        let home = home.map(PathBuf::from).ok_or_else(|| {
            "cannot expand location command '~/' because HOME is not set".to_string()
        })?;
        home.join(suffix)
    } else {
        PathBuf::from(command)
    };
    Ok(path)
}

#[cfg(unix)]
fn resolve_location(command: &str) -> Result<(f64, f64, f64), String> {
    use std::os::unix::fs::PermissionsExt;

    let path = expand_location_path(command, std::env::var_os("HOME"))?;
    let metadata = fs::metadata(&path)
        .map_err(|error| format!("cannot inspect '{}': {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("'{}' is not a regular file", path.display()));
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!("'{}' is not executable", path.display()));
    }

    let mut child = Command::new(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("cannot execute '{}': {error}", path.display()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "location command stdout was unavailable".to_string())?;
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
                return Err("location command timed out after 5 seconds".into());
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("failed waiting for location command: {error}"));
            }
        }
    };
    let output = reader
        .join()
        .map_err(|_| "location command stdout reader panicked".to_string())?
        .map_err(|error| format!("failed reading location command stdout: {error}"))?;
    if !status.success() {
        return Err(format!("location command exited with {status}"));
    }
    parse_location_output(&output)
}

#[cfg(windows)]
fn resolve_location(_command: &str) -> Result<(f64, f64, f64), String> {
    Err("location_cmd is not supported on Windows".into())
}

fn prepare_interface_info(
    transport_id: &[u8; 16],
    iface: &DiscoverableInterface,
) -> Result<Vec<u8>, String> {
    let mut resolved = iface.clone();
    if let Some(command) = &resolved.config.location_cmd {
        let (latitude, longitude, height) = resolve_location(command)?;
        resolved.config.latitude = Some(latitude);
        resolved.config.longitude = Some(longitude);
        resolved.config.height = Some(height);
    }
    InterfaceAnnouncer::pack_interface_info(transport_id, &resolved)
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

            log::info!(
                "Spawning discovery stamp generation (cost={}) for '{}'...",
                stamp_cost,
                name,
            );

            self.stamp_pending = true;
            self.last_announced[idx] = now;

            std::thread::spawn(move || {
                let packed = match prepare_interface_info(&transport_id, &iface) {
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

                let flags: u8 = 0x00; // no encryption
                let mut app_data = Vec::with_capacity(1 + packed.len() + STAMP_SIZE);
                app_data.push(flags);
                app_data.extend_from_slice(&packed);
                app_data.extend_from_slice(&stamp);

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
    ) -> Result<Vec<u8>, String> {
        if matches!(
            iface.config.interface_type.as_str(),
            "BackboneInterface" | "TCPServerInterface"
        ) && iface.config.reachable_on.is_none()
        {
            return Err(format!(
                "{} discovery requires a reachable_on address",
                iface.config.interface_type
            ));
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
        if let Some(address) = iface.config.operator_lxmf_address {
            entries.push((
                msgpack::Value::UInt(OP_ADDR as u64),
                msgpack::Value::Bin(address.to_vec()),
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
                discovery_name: format!("Discovery {name}"),
                announce_interval: interval,
                stamp_value: 0,
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
        let packed = prepare_interface_info(&[0x55; 16], &iface).unwrap();
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
        assert!(error.contains("timed out"));
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
    reachable_on = backbone.example.net
    location_cmd = ~/bin/reticulum-location"#;
        const OUTPUT: &str = "45.4642,9.1900,122.5\n";
        let documentation = include_str!("../../docs/interface-discovery.md");
        assert!(documentation.contains(STANZA));
        assert!(documentation.contains(OUTPUT.trim_end()));

        let parsed = crate::config::parse(STANZA).unwrap();
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
                app_data: Err("metadata failed".into()),
            })
            .unwrap();

        let result = announcer.poll_ready().unwrap();
        assert_eq!(result.app_data.unwrap_err(), "metadata failed");
        assert!(!announcer.stamp_pending);
    }

    #[test]
    fn background_packing_preserves_static_metadata_bytes() {
        let iface = test_announce_interface("static", 1);
        let expected = InterfaceAnnouncer::pack_interface_info(&[0x24; 16], &iface).unwrap();
        let mut announcer = InterfaceAnnouncer::new([0x24; 16], vec![iface]);

        announcer.maybe_start(1.0);
        let result = wait_for_announce(&mut announcer).app_data.unwrap();
        assert_eq!(&result[1..result.len() - STAMP_SIZE], expected.as_slice());
    }

    #[test]
    fn announcer_packs_operator_lxmf_address() {
        let mut iface = test_announce_interface("operator", 1);
        iface.config.operator_lxmf_address = Some([0xa5; 16]);

        let packed = InterfaceAnnouncer::pack_interface_info(&[0x24; 16], &iface).unwrap();
        let (Value::Map(entries), consumed) = msgpack::unpack(&packed).unwrap() else {
            panic!("discovery metadata was not a map")
        };

        assert_eq!(consumed, packed.len());
        assert!(entries.contains(&(Value::UInt(OP_ADDR as u64), Value::Bin(vec![0xa5; 16]),)));
    }

    #[test]
    fn announcer_suppresses_network_discovery_without_reachable_address() {
        for interface_type in ["BackboneInterface", "TCPServerInterface"] {
            let mut iface = test_announce_interface("missing-address", 1);
            iface.config.interface_type = interface_type.into();
            iface.config.reachable_on = None;

            assert_eq!(
                InterfaceAnnouncer::pack_interface_info(&[0x24; 16], &iface),
                Err(format!(
                    "{interface_type} discovery requires a reachable_on address"
                ))
            );
        }
    }

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

    fn test_discovered_interface(name: &str) -> DiscoveredInterface {
        DiscoveredInterface {
            interface_type: "BackboneInterface".into(),
            transport: true,
            name: name.into(),
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

        let iface = test_discovered_interface("TestNode");

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
        let filepath = dir.join(hex_encode(&received.discovery_hash));
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
                interface_type: "BackboneInterface".into(),
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
                interface_type: "TCPServerInterface".into(),
                transport: true,
                name: "low-value-available".into(),
                discovered: now,
                last_heard: now - 10.0, // Available
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
                interface_type: "I2PInterface".into(),
                transport: false,
                name: "high-value-available".into(),
                discovered: now,
                last_heard: now - 10.0, // Available
                heard_count: 0,
                status: DiscoveredStatus::Available,
                stamp: vec![],
                stamp_value: 20,
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
    fn test_discovery_name_hash_deterministic() {
        let h1 = discovery_name_hash();
        let h2 = discovery_name_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 10]); // not all zeros
    }
}
