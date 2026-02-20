//! Identity and known destinations persistence.
//!
//! Identity file format: 64 bytes = 32-byte X25519 private key + 32-byte Ed25519 private key.
//! Same as Python's `Identity.to_file()` / `Identity.from_file()`.
//!
//! Known destinations: msgpack binary with 16-byte keys and tuple values.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rns_crypto::identity::Identity;
use rns_crypto::OsRng;

/// Paths for storage directories.
#[derive(Debug, Clone)]
pub struct StoragePaths {
    pub config_dir: PathBuf,
    pub storage: PathBuf,
    pub cache: PathBuf,
    pub identities: PathBuf,
    /// Directory for discovered interface data: storage/discovery/interfaces
    pub discovered_interfaces: PathBuf,
}

/// A known destination entry.
#[derive(Debug, Clone)]
pub struct KnownDestination {
    pub timestamp: f64,
    pub packet_hash: [u8; 32],
    pub public_key: [u8; 64],
    pub app_data: Option<Vec<u8>>,
}

/// Ensure all storage directories exist. Creates them if missing.
pub fn ensure_storage_dirs(config_dir: &Path) -> io::Result<StoragePaths> {
    let storage = config_dir.join("storage");
    let cache = config_dir.join("cache");
    let identities = storage.join("identities");
    let announces = cache.join("announces");
    let discovered_interfaces = storage.join("discovery").join("interfaces");

    fs::create_dir_all(&storage)?;
    fs::create_dir_all(&cache)?;
    fs::create_dir_all(&identities)?;
    fs::create_dir_all(&announces)?;
    fs::create_dir_all(&discovered_interfaces)?;

    Ok(StoragePaths {
        config_dir: config_dir.to_path_buf(),
        storage,
        cache,
        identities,
        discovered_interfaces,
    })
}

/// Save an identity's private key to a file (64 bytes).
pub fn save_identity(identity: &Identity, path: &Path) -> io::Result<()> {
    let private_key = identity.get_private_key().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "Identity has no private key")
    })?;
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
/// Format matches Python: `{bytes(16): [timestamp, packet_hash, public_key, app_data], ...}`
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
                // Python uses float for timestamp
                // msgpack doesn't have native float in our codec, use uint (seconds)
                // Actually Python stores as float via umsgpack. We'll store the integer
                // part as uint for now (lossy but functional for interop basics).
                Value::UInt(dest.timestamp as u64),
                Value::Bin(dest.packet_hash.to_vec()),
                Value::Bin(dest.public_key.to_vec()),
                app_data,
            ]);
            (key, value)
        })
        .collect();

    let packed = msgpack::pack(&Value::Map(entries));
    fs::write(path, packed)
}

/// Load known destinations from a msgpack file.
pub fn load_known_destinations(
    path: &Path,
) -> io::Result<HashMap<[u8; 16], KnownDestination>> {
    use rns_core::msgpack;

    let data = fs::read(path)?;
    if data.is_empty() {
        return Ok(HashMap::new());
    }

    let (value, _) = msgpack::unpack(&data).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("msgpack error: {}", e))
    })?;

    let map = value.as_map().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "Expected msgpack map")
    })?;

    let mut result = HashMap::new();

    for (k, v) in map {
        let hash_bytes = k.as_bin().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Expected bin key")
        })?;

        if hash_bytes.len() != 16 {
            continue; // Skip invalid entries like Python does
        }

        let mut dest_hash = [0u8; 16];
        dest_hash.copy_from_slice(hash_bytes);

        let arr = v.as_array().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Expected array value")
        })?;

        if arr.len() < 3 {
            continue;
        }

        let timestamp = arr[0].as_uint().unwrap_or(0) as f64;

        let pkt_hash_bytes = arr[1].as_bin().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Expected bin packet_hash")
        })?;
        if pkt_hash_bytes.len() != 32 {
            continue;
        }
        let mut packet_hash = [0u8; 32];
        packet_hash.copy_from_slice(pkt_hash_bytes);

        let pub_key_bytes = arr[2].as_bin().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Expected bin public_key")
        })?;
        if pub_key_bytes.len() != 64 {
            continue;
        }
        let mut public_key = [0u8; 64];
        public_key.copy_from_slice(pub_key_bytes);

        let app_data = if arr.len() > 3 {
            arr[3].as_bin().map(|b| b.to_vec())
        } else {
            None
        };

        result.insert(
            dest_hash,
            KnownDestination {
                timestamp,
                packet_hash,
                public_key,
                app_data,
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
        let dir = std::env::temp_dir().join(format!(
            "rns-test-{}-{}",
            std::process::id(),
            id
        ));
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
                timestamp: 1700000000.0,
                packet_hash: [0x42u8; 32],
                public_key: [0xABu8; 64],
                app_data: Some(vec![0x01, 0x02, 0x03]),
            },
        );
        dests.insert(
            [0x02u8; 16],
            KnownDestination {
                timestamp: 1700000001.0,
                packet_hash: [0x43u8; 32],
                public_key: [0xCDu8; 64],
                app_data: None,
            },
        );

        save_known_destinations(&dests, &path).unwrap();
        let loaded = load_known_destinations(&path).unwrap();

        assert_eq!(loaded.len(), 2);

        let d1 = &loaded[&[0x01u8; 16]];
        assert_eq!(d1.timestamp as u64, 1700000000);
        assert_eq!(d1.packet_hash, [0x42u8; 32]);
        assert_eq!(d1.public_key, [0xABu8; 64]);
        assert_eq!(d1.app_data, Some(vec![0x01, 0x02, 0x03]));

        let d2 = &loaded[&[0x02u8; 16]];
        assert_eq!(d2.app_data, None);

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
