//! Identity, known destinations, and received ratchet persistence.
//!
//! Identity file format: 64 bytes = 32-byte X25519 private key + 32-byte Ed25519 private key.
//! Same as Python's `Identity.to_file()` / `Identity.from_file()`.
//!
//! Known destinations: msgpack binary with 16-byte keys and tuple values.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rns_crypto::identity::Identity;
use rns_crypto::OsRng;

/// Paths for storage directories.
#[derive(Debug, Clone)]
pub struct StoragePaths {
    pub config_dir: PathBuf,
    pub storage: PathBuf,
    pub cache: PathBuf,
    pub identities: PathBuf,
    pub ratchets: PathBuf,
    /// Directory for discovered interface data: storage/discovery/interfaces
    pub discovered_interfaces: PathBuf,
}

/// A known destination entry.
#[derive(Debug, Clone)]
pub struct KnownDestination {
    pub identity_hash: [u8; 16],
    pub public_key: [u8; 64],
    pub app_data: Option<Vec<u8>>,
    pub hops: u8,
    pub received_at: f64,
    pub receiving_interface: u64,
    pub was_used: bool,
    pub last_used_at: Option<f64>,
    pub retained: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RatchetEntry {
    pub ratchet: [u8; 32],
    pub received_at: f64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RatchetCleanupStats {
    pub processed: usize,
    pub not_known: usize,
    pub removed: usize,
}

pub trait RatchetStore: Send + Sync {
    fn remember(&self, dest_hash: [u8; 16], entry: RatchetEntry) -> io::Result<()>;
    fn current(
        &self,
        dest_hash: &[u8; 16],
        now: f64,
        expiry_secs: f64,
    ) -> io::Result<Option<RatchetEntry>>;
    fn cleanup(
        &self,
        known_destinations: &HashSet<[u8; 16]>,
        now: f64,
        expiry_secs: f64,
    ) -> io::Result<RatchetCleanupStats>;
}

#[derive(Debug)]
pub struct FsRatchetStore {
    dir: PathBuf,
    cache: Mutex<HashMap<[u8; 16], RatchetEntry>>,
}

impl FsRatchetStore {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn path_for(&self, dest_hash: &[u8; 16]) -> PathBuf {
        self.dir.join(hex_lower(dest_hash))
    }

    fn read_entry(path: &Path) -> io::Result<RatchetEntry> {
        use rns_core::msgpack;

        let data = fs::read(path)?;
        let (value, _) = msgpack::unpack(&data).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("msgpack error: {}", e))
        })?;
        let ratchet = value
            .map_get("ratchet")
            .and_then(|v| v.as_bin())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing ratchet"))?;
        if ratchet.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("ratchet must be 32 bytes, got {}", ratchet.len()),
            ));
        }
        let mut ratchet_bytes = [0u8; 32];
        ratchet_bytes.copy_from_slice(ratchet);
        let received_at = value
            .map_get("received")
            .and_then(|v| v.as_number())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing received"))?;

        Ok(RatchetEntry {
            ratchet: ratchet_bytes,
            received_at,
        })
    }

    fn write_entry(&self, path: &Path, entry: RatchetEntry) -> io::Result<()> {
        use rns_core::msgpack::{self, Value};

        fs::create_dir_all(&self.dir)?;
        let value = Value::Map(vec![
            (
                Value::Str("ratchet".into()),
                Value::Bin(entry.ratchet.to_vec()),
            ),
            (
                Value::Str("received".into()),
                Value::Float(entry.received_at),
            ),
        ]);
        let packed = msgpack::pack(&value);
        let tmp = path.with_extension("out");
        fs::write(&tmp, packed)?;
        fs::rename(tmp, path)
    }
}

impl RatchetStore for FsRatchetStore {
    fn remember(&self, dest_hash: [u8; 16], entry: RatchetEntry) -> io::Result<()> {
        if self
            .cache
            .lock()
            .map(|cache| cache.get(&dest_hash).copied() == Some(entry))
            .unwrap_or(false)
        {
            return Ok(());
        }

        let path = self.path_for(&dest_hash);
        self.write_entry(&path, entry)?;
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(dest_hash, entry);
        }
        Ok(())
    }

    fn current(
        &self,
        dest_hash: &[u8; 16],
        now: f64,
        expiry_secs: f64,
    ) -> io::Result<Option<RatchetEntry>> {
        if let Ok(cache) = self.cache.lock() {
            if let Some(entry) = cache.get(dest_hash).copied() {
                if now <= entry.received_at + expiry_secs {
                    return Ok(Some(entry));
                }
            }
        }

        let path = self.path_for(dest_hash);
        if !path.is_file() {
            return Ok(None);
        }

        let entry = Self::read_entry(&path)?;
        if now > entry.received_at + expiry_secs {
            let _ = fs::remove_file(path);
            if let Ok(mut cache) = self.cache.lock() {
                cache.remove(dest_hash);
            }
            return Ok(None);
        }

        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(*dest_hash, entry);
        }
        Ok(Some(entry))
    }

    fn cleanup(
        &self,
        known_destinations: &HashSet<[u8; 16]>,
        now: f64,
        expiry_secs: f64,
    ) -> io::Result<RatchetCleanupStats> {
        let mut stats = RatchetCleanupStats::default();
        if !self.dir.is_dir() {
            return Ok(stats);
        }

        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            stats.processed += 1;
            let path = entry.path();
            let Some(filename) = path.file_name().and_then(|name| name.to_str()) else {
                let _ = fs::remove_file(&path);
                stats.removed += 1;
                continue;
            };

            let Some(dest_hash) = parse_dest_hash_hex(filename) else {
                let _ = fs::remove_file(&path);
                stats.removed += 1;
                continue;
            };

            let unknown = !known_destinations.contains(&dest_hash);
            if unknown {
                stats.not_known += 1;
            }

            let expired_or_corrupt = match Self::read_entry(&path) {
                Ok(entry) => now > entry.received_at + expiry_secs,
                Err(_) => true,
            };

            if unknown || expired_or_corrupt {
                let _ = fs::remove_file(&path);
                stats.removed += 1;
                if let Ok(mut cache) = self.cache.lock() {
                    cache.remove(&dest_hash);
                }
            }
        }

        Ok(stats)
    }
}

/// Ensure all storage directories exist. Creates them if missing.
pub fn ensure_storage_dirs(config_dir: &Path) -> io::Result<StoragePaths> {
    let storage = config_dir.join("storage");
    let cache = config_dir.join("cache");
    let identities = storage.join("identities");
    let ratchets = storage.join("ratchets");
    let announces = cache.join("announces");
    let discovered_interfaces = storage.join("discovery").join("interfaces");

    fs::create_dir_all(&storage)?;
    fs::create_dir_all(&cache)?;
    fs::create_dir_all(&identities)?;
    fs::create_dir_all(&ratchets)?;
    fs::create_dir_all(&announces)?;
    fs::create_dir_all(&discovered_interfaces)?;

    Ok(StoragePaths {
        config_dir: config_dir.to_path_buf(),
        storage,
        cache,
        identities,
        ratchets,
        discovered_interfaces,
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

fn parse_dest_hash_hex(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Save an identity's private key to a file (64 bytes).
pub fn save_identity(identity: &Identity, path: &Path) -> io::Result<()> {
    let private_key = identity
        .get_private_key()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Identity has no private key"))?;
    fs::write(path, &private_key)
}

/// Load an identity from a private key file (64 bytes).
pub fn load_identity(path: &Path) -> io::Result<Identity> {
    let data = fs::read(path)?;
    if data.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Identity file must be 64 bytes, got {}", data.len()),
        ));
    }
    let mut key = [0u8; 64];
    key.copy_from_slice(&data);
    Ok(Identity::from_private_key(&key))
}

/// Save known destinations to a msgpack file.
///
/// Format: `{bytes(16): [received_at, public_key, app_data, identity_hash, hops,
/// receiving_interface, was_used, last_used_at, retained], ...}`
///
/// Legacy 4-element arrays are still accepted on load.
pub fn save_known_destinations(
    destinations: &HashMap<[u8; 16], KnownDestination>,
    path: &Path,
) -> io::Result<()> {
    use rns_core::msgpack::{self, Value};

    let entries: Vec<(Value, Value)> = destinations
        .iter()
        .map(|(hash, dest)| {
            let key = Value::Bin(hash.to_vec());
            let app_data = match &dest.app_data {
                Some(d) => Value::Bin(d.clone()),
                None => Value::Nil,
            };
            let value = Value::Array(vec![
                Value::UInt(dest.received_at as u64),
                Value::Bin(dest.public_key.to_vec()),
                app_data,
                Value::Bin(dest.identity_hash.to_vec()),
                Value::UInt(dest.hops as u64),
                Value::UInt(dest.receiving_interface),
                Value::Bool(dest.was_used),
                match dest.last_used_at {
                    Some(last_used_at) => Value::UInt(last_used_at as u64),
                    None => Value::Nil,
                },
                Value::Bool(dest.retained),
            ]);
            (key, value)
        })
        .collect();

    let packed = msgpack::pack(&Value::Map(entries));
    atomic_write(path, &packed)
}

fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("known_destinations");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temp_path = parent.join(format!(".{file_name}.tmp.{}.{}", std::process::id(), nonce));
    match fs::write(&temp_path, data).and_then(|_| replace_file(&temp_path, path)) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = fs::remove_file(&temp_path);
            Err(err)
        }
    }
}

fn replace_file(temp_path: &Path, path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(temp_path, path)
}

/// Load known destinations from a msgpack file.
pub fn load_known_destinations(path: &Path) -> io::Result<HashMap<[u8; 16], KnownDestination>> {
    use rns_core::msgpack;

    let data = fs::read(path)?;
    if data.is_empty() {
        return Ok(HashMap::new());
    }

    let (value, _) = msgpack::unpack(&data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("msgpack error: {}", e)))?;

    let map = value
        .as_map()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Expected msgpack map"))?;

    let mut result = HashMap::new();

    for (k, v) in map {
        let hash_bytes = k
            .as_bin()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Expected bin key"))?;

        if hash_bytes.len() != 16 {
            continue; // Skip invalid entries like Python does
        }

        let mut dest_hash = [0u8; 16];
        dest_hash.copy_from_slice(hash_bytes);

        let arr = v
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Expected array value"))?;

        if arr.len() < 3 {
            continue;
        }

        let received_at = arr[0].as_uint().unwrap_or(0) as f64;

        let pub_key_bytes = arr[1]
            .as_bin()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Expected bin public_key"))?;
        if pub_key_bytes.len() != 64 {
            continue;
        }
        let mut public_key = [0u8; 64];
        public_key.copy_from_slice(pub_key_bytes);

        let app_data = if arr.len() > 2 {
            arr[2].as_bin().map(|b| b.to_vec())
        } else {
            None
        };

        let identity_hash = if arr.len() > 3 {
            let hash_bytes = arr[3]
                .as_bin()
                .filter(|bytes| bytes.len() == 16)
                .map(|bytes| {
                    let mut hash = [0u8; 16];
                    hash.copy_from_slice(bytes);
                    hash
                });
            hash_bytes.unwrap_or_else(|| {
                let identity = Identity::from_public_key(&public_key);
                *identity.hash()
            })
        } else {
            let identity = Identity::from_public_key(&public_key);
            *identity.hash()
        };
        let hops = arr.get(4).and_then(|value| value.as_uint()).unwrap_or(0) as u8;
        let receiving_interface = arr.get(5).and_then(|value| value.as_uint()).unwrap_or(0);
        let was_used = arr
            .get(6)
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let last_used_at = arr
            .get(7)
            .and_then(|value| value.as_uint())
            .map(|value| value as f64);
        let retained = arr
            .get(8)
            .and_then(|value| value.as_bool())
            .unwrap_or(false);

        result.insert(
            dest_hash,
            KnownDestination {
                identity_hash,
                public_key,
                app_data,
                hops,
                received_at,
                receiving_interface,
                was_used,
                last_used_at,
                retained,
            },
        );
    }

    Ok(result)
}

/// Resolve the config directory path.
/// Priority: explicit path > `~/.reticulum/`
pub fn resolve_config_dir(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        p.to_path_buf()
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(home).join(".reticulum")
    }
}

/// Load or create an identity at the standard location.
pub fn load_or_create_identity(identities_dir: &Path) -> io::Result<Identity> {
    let id_path = identities_dir.join("identity");
    if id_path.exists() {
        load_identity(&id_path)
    } else {
        let identity = Identity::new(&mut OsRng);
        save_identity(&identity, &id_path)?;
        Ok(identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rns-test-{}-{}", std::process::id(), id));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn save_load_identity_roundtrip() {
        let dir = temp_dir();
        let path = dir.join("test_identity");

        let identity = Identity::new(&mut OsRng);
        let original_hash = *identity.hash();

        save_identity(&identity, &path).unwrap();
        let loaded = load_identity(&path).unwrap();

        assert_eq!(*loaded.hash(), original_hash);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_file_format() {
        let dir = temp_dir();
        let path = dir.join("test_identity_fmt");

        let identity = Identity::new(&mut OsRng);
        save_identity(&identity, &path).unwrap();

        let data = fs::read(&path).unwrap();
        assert_eq!(data.len(), 64, "Identity file must be exactly 64 bytes");

        // First 32 bytes: X25519 private key
        // Next 32 bytes: Ed25519 private key (seed)
        let private_key = identity.get_private_key();
        let private_key = private_key.unwrap();
        assert_eq!(&data[..], &private_key[..]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_load_known_destinations_empty() {
        let dir = temp_dir();
        let path = dir.join("known_destinations");

        let empty: HashMap<[u8; 16], KnownDestination> = HashMap::new();
        save_known_destinations(&empty, &path).unwrap();

        let loaded = load_known_destinations(&path).unwrap();
        assert!(loaded.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_load_known_destinations_roundtrip() {
        let dir = temp_dir();
        let path = dir.join("known_destinations");

        let mut dests = HashMap::new();
        dests.insert(
            [0x01u8; 16],
            KnownDestination {
                identity_hash: [0x11u8; 16],
                public_key: [0xABu8; 64],
                app_data: Some(vec![0x01, 0x02, 0x03]),
                hops: 2,
                received_at: 1700000000.0,
                receiving_interface: 7,
                was_used: true,
                last_used_at: Some(1700000010.0),
                retained: true,
            },
        );
        dests.insert(
            [0x02u8; 16],
            KnownDestination {
                identity_hash: [0x22u8; 16],
                public_key: [0xCDu8; 64],
                app_data: None,
                hops: 1,
                received_at: 1700000001.0,
                receiving_interface: 0,
                was_used: false,
                last_used_at: None,
                retained: false,
            },
        );

        save_known_destinations(&dests, &path).unwrap();
        let loaded = load_known_destinations(&path).unwrap();

        assert_eq!(loaded.len(), 2);

        let d1 = &loaded[&[0x01u8; 16]];
        assert_eq!(d1.identity_hash, [0x11u8; 16]);
        assert_eq!(d1.public_key, [0xABu8; 64]);
        assert_eq!(d1.app_data, Some(vec![0x01, 0x02, 0x03]));
        assert_eq!(d1.hops, 2);
        assert_eq!(d1.received_at as u64, 1700000000);
        assert_eq!(d1.receiving_interface, 7);
        assert!(d1.was_used);
        assert_eq!(d1.last_used_at, Some(1700000010.0));
        assert!(d1.retained);

        let d2 = &loaded[&[0x02u8; 16]];
        assert_eq!(d2.app_data, None);
        assert!(!d2.was_used);
        assert_eq!(d2.last_used_at, None);
        assert!(!d2.retained);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_known_destinations_replaces_existing_file_atomically() {
        let dir = temp_dir();
        let path = dir.join("known_destinations");
        fs::write(&path, b"old").unwrap();

        let mut dests = HashMap::new();
        dests.insert(
            [0x03u8; 16],
            KnownDestination {
                identity_hash: [0x33u8; 16],
                public_key: [0xEFu8; 64],
                app_data: None,
                hops: 3,
                received_at: 1700000002.0,
                receiving_interface: 9,
                was_used: false,
                last_used_at: None,
                retained: false,
            },
        );

        save_known_destinations(&dests, &path).unwrap();

        let loaded = load_known_destinations(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains_key(&[0x03u8; 16]));
        let leftover_temp = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().contains(".tmp."));
        assert!(!leftover_temp);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ratchet_store_roundtrip() {
        let dir = temp_dir();
        let store = FsRatchetStore::new(dir.join("ratchets"));
        let dest = [0xAA; 16];
        let entry = RatchetEntry {
            ratchet: [0xBB; 32],
            received_at: 1700000000.25,
        };

        store.remember(dest, entry).unwrap();
        let loaded = store.current(&dest, 1700000001.0, 60.0).unwrap();

        assert_eq!(loaded, Some(entry));
        assert!(dir.join("ratchets").join(hex_lower(&dest)).exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ratchet_cleanup_removes_expired_corrupt_unknown_and_temp() {
        let dir = temp_dir();
        let ratchets = dir.join("ratchets");
        fs::create_dir_all(&ratchets).unwrap();
        let store = FsRatchetStore::new(ratchets.clone());

        let known_live = [0x01; 16];
        let known_expired = [0x02; 16];
        let unknown = [0x03; 16];
        store
            .remember(
                known_live,
                RatchetEntry {
                    ratchet: [0x11; 32],
                    received_at: 1000.0,
                },
            )
            .unwrap();
        store
            .remember(
                known_expired,
                RatchetEntry {
                    ratchet: [0x22; 32],
                    received_at: 100.0,
                },
            )
            .unwrap();
        store
            .remember(
                unknown,
                RatchetEntry {
                    ratchet: [0x33; 32],
                    received_at: 1000.0,
                },
            )
            .unwrap();
        fs::write(ratchets.join(hex_lower(&[0x04; 16])), b"not msgpack").unwrap();
        fs::write(ratchets.join("0102.out"), b"temp").unwrap();

        let known = HashSet::from([known_live, known_expired, [0x04; 16]]);
        let stats = store.cleanup(&known, 1000.0, 300.0).unwrap();

        assert_eq!(stats.processed, 5);
        assert_eq!(stats.not_known, 1);
        assert_eq!(stats.removed, 4);
        assert!(ratchets.join(hex_lower(&known_live)).exists());
        assert!(!ratchets.join(hex_lower(&known_expired)).exists());
        assert!(!ratchets.join(hex_lower(&unknown)).exists());
        assert!(!ratchets.join(hex_lower(&[0x04; 16])).exists());
        assert!(!ratchets.join("0102.out").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_dirs_creates() {
        let dir = temp_dir().join("new_config");
        let _ = fs::remove_dir_all(&dir);

        let paths = ensure_storage_dirs(&dir).unwrap();

        assert!(paths.storage.exists());
        assert!(paths.cache.exists());
        assert!(paths.identities.exists());
        assert!(paths.ratchets.exists());
        assert!(paths.discovered_interfaces.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_dirs_existing() {
        let dir = temp_dir().join("existing_config");
        fs::create_dir_all(dir.join("storage")).unwrap();
        fs::create_dir_all(dir.join("cache")).unwrap();

        let paths = ensure_storage_dirs(&dir).unwrap();
        assert!(paths.storage.exists());
        assert!(paths.identities.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_create_identity_new() {
        let dir = temp_dir().join("load_or_create");
        fs::create_dir_all(&dir).unwrap();

        let identity = load_or_create_identity(&dir).unwrap();
        let id_path = dir.join("identity");
        assert!(id_path.exists());

        // Loading again should give same identity
        let loaded = load_or_create_identity(&dir).unwrap();
        assert_eq!(*identity.hash(), *loaded.hash());

        let _ = fs::remove_dir_all(&dir);
    }
}
