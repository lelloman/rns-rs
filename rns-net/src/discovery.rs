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
use std::io;
use std::path::PathBuf;

use rns_core::msgpack::{self, Value};
use rns_core::stamp::{stamp_valid, stamp_workblock};
use rns_crypto::sha256::sha256;

use crate::time;

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
    let value = rns_core::stamp::stamp_value(&workblock, &stamp);
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

        let iface = DiscoveredInterface {
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
                interface_type: "C".into(),
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
