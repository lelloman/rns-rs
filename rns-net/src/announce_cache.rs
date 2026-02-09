//! Announce cache for disk persistence.
//!
//! Caches announce packets to disk for path request responses.
//! File format matches Python: msgpack `[raw_bytes, interface_name_or_nil]`.
//! Filename: hex-encoded packet_hash (64 chars).
//!
//! Python reference: Transport.py:2334-2402

use std::fs;
use std::io;
use std::path::PathBuf;

use rns_core::msgpack::{self, Value};

/// Announce cache backed by filesystem.
pub struct AnnounceCache {
    base_path: PathBuf,
}

impl AnnounceCache {
    /// Create an announce cache at the given directory.
    /// The directory must already exist (created by `ensure_storage_dirs`).
    pub fn new(base_path: PathBuf) -> Self {
        AnnounceCache { base_path }
    }

    /// Store a cached announce to disk.
    ///
    /// `packet_hash`: 32-byte packet hash (used as filename)
    /// `raw`: raw announce bytes (pre-hop-increment)
    /// `interface_name`: optional interface name string
    pub fn store(
        &self,
        packet_hash: &[u8; 32],
        raw: &[u8],
        interface_name: Option<&str>,
    ) -> io::Result<()> {
        let filename = hex_encode(packet_hash);
        let path = self.base_path.join(&filename);

        let iface_val = match interface_name {
            Some(name) => Value::Str(name.into()),
            None => Value::Nil,
        };
        let data = msgpack::pack(&Value::Array(vec![
            Value::Bin(raw.to_vec()),
            iface_val,
        ]));

        fs::write(path, data)
    }

    /// Retrieve a cached announce from disk.
    ///
    /// Returns `(raw_bytes, interface_name_or_none)`.
    pub fn get(&self, packet_hash: &[u8; 32]) -> io::Result<Option<(Vec<u8>, Option<String>)>> {
        let filename = hex_encode(packet_hash);
        let path = self.base_path.join(&filename);

        if !path.is_file() {
            return Ok(None);
        }

        let data = fs::read(&path)?;
        let (value, _) = msgpack::unpack(&data).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("msgpack error: {}", e))
        })?;

        let arr = value.as_array().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Expected msgpack array")
        })?;

        if arr.is_empty() {
            return Ok(None);
        }

        let raw = arr[0].as_bin().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Expected bin raw bytes")
        })?;

        let iface_name = if arr.len() > 1 {
            arr[1].as_str().map(|s| s.to_string())
        } else {
            None
        };

        Ok(Some((raw.to_vec(), iface_name)))
    }

    /// Remove cached announces whose packet hashes are not in the active set.
    ///
    /// `active_hashes`: set of packet hashes that should be kept.
    /// Returns the number of removed entries.
    pub fn clean(&self, active_hashes: &[[u8; 32]]) -> io::Result<usize> {
        let entries = match fs::read_dir(&self.base_path) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };

        let mut removed = 0;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let filename = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };

            // Parse hex filename back to hash
            match hex_decode(filename) {
                Some(hash) => {
                    if !active_hashes.contains(&hash) {
                        let _ = fs::remove_file(&path);
                        removed += 1;
                    }
                }
                None => {
                    // Invalid filename — remove
                    let _ = fs::remove_file(&path);
                    removed += 1;
                }
            }
        }

        Ok(removed)
    }

    /// Get the base path for testing.
    #[cfg(test)]
    pub fn base_path(&self) -> &std::path::Path {
        &self.base_path
    }
}

/// Encode 32 bytes as 64-char lowercase hex string.
fn hex_encode(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize]);
        s.push(HEX_CHARS[(b & 0x0f) as usize]);
    }
    s
}

const HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// Decode a 64-char hex string back to 32 bytes.
fn hex_decode(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut result = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        result[i] = (high << 4) | low;
    }
    Some(result)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
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
            "rns-announce-cache-{}-{}",
            std::process::id(),
            id,
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_hex_encode_decode_roundtrip() {
        let hash = [0xAB; 32];
        let encoded = hex_encode(&hash);
        assert_eq!(encoded.len(), 64);
        assert_eq!(encoded.len(), 64);
        // All bytes are 0xAB so hex is "ab" repeated 32 times
        assert!(encoded.chars().all(|c| c == 'a' || c == 'b'));
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, hash);
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert!(hex_decode("too_short").is_none());
        assert!(hex_decode(&"zz".repeat(32)).is_none());
    }

    #[test]
    fn test_store_and_get_roundtrip() {
        let dir = temp_dir();
        let cache = AnnounceCache::new(dir.clone());

        let hash = [0x42; 32];
        let raw = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        cache.store(&hash, &raw, Some("TestInterface")).unwrap();

        let result = cache.get(&hash).unwrap();
        assert!(result.is_some());
        let (got_raw, got_name) = result.unwrap();
        assert_eq!(got_raw, raw);
        assert_eq!(got_name, Some("TestInterface".to_string()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_store_with_nil_interface() {
        let dir = temp_dir();
        let cache = AnnounceCache::new(dir.clone());

        let hash = [0x55; 32];
        let raw = vec![0xAA, 0xBB];
        cache.store(&hash, &raw, None).unwrap();

        let result = cache.get(&hash).unwrap();
        assert!(result.is_some());
        let (got_raw, got_name) = result.unwrap();
        assert_eq!(got_raw, raw);
        assert_eq!(got_name, None);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_get_nonexistent() {
        let dir = temp_dir();
        let cache = AnnounceCache::new(dir.clone());

        let hash = [0xFF; 32];
        let result = cache.get(&hash).unwrap();
        assert!(result.is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_clean_removes_stale() {
        let dir = temp_dir();
        let cache = AnnounceCache::new(dir.clone());

        let hash1 = [0x11; 32];
        let hash2 = [0x22; 32];
        let hash3 = [0x33; 32];

        cache.store(&hash1, &[0x01], None).unwrap();
        cache.store(&hash2, &[0x02], None).unwrap();
        cache.store(&hash3, &[0x03], None).unwrap();

        // Keep only hash2
        let removed = cache.clean(&[hash2]).unwrap();
        assert_eq!(removed, 2);

        // hash2 should still be there
        assert!(cache.get(&hash2).unwrap().is_some());
        // hash1 and hash3 should be gone
        assert!(cache.get(&hash1).unwrap().is_none());
        assert!(cache.get(&hash3).unwrap().is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_clean_empty_dir() {
        let dir = temp_dir();
        let cache = AnnounceCache::new(dir.clone());

        let removed = cache.clean(&[]).unwrap();
        assert_eq!(removed, 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_store_overwrite() {
        let dir = temp_dir();
        let cache = AnnounceCache::new(dir.clone());

        let hash = [0x77; 32];
        cache.store(&hash, &[0x01], Some("iface1")).unwrap();
        cache.store(&hash, &[0x02, 0x03], Some("iface2")).unwrap();

        let result = cache.get(&hash).unwrap().unwrap();
        assert_eq!(result.0, vec![0x02, 0x03]);
        assert_eq!(result.1, Some("iface2".to_string()));

        let _ = fs::remove_dir_all(&dir);
    }
}
