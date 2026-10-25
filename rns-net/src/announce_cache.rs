//! Announce cache for persistence.
//!
//! Uses SQLite (`announces.db`) by default, mirroring Python Reticulum's
//! `cached_announces` table. Legacy per-file caches are imported on first use.
//! If SQLite cannot be opened, the legacy filesystem backend is retained.
//!
//! Python reference: Transport.py:3087-3099 and Storage.py AnnounceCache.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use rns_core::msgpack::{self, Value};
use rusqlite::{params, Connection, OptionalExtension};

enum Backend {
    Sqlite(SqliteAnnounceCache),
    Files(FileAnnounceCache),
}

/// Announce cache with a SQLite backend and a filesystem fallback.
pub struct AnnounceCache {
    backend: Backend,
}

impl AnnounceCache {
    /// Create an announce cache rooted at `base_path`.
    ///
    /// The database is written next to the legacy directory as
    /// `<base_path>.db` (for example `cache/announces.db` for
    /// `cache/announces`). Legacy files already in `base_path` are imported
    /// and removed.
    pub fn new(base_path: PathBuf) -> Self {
        match SqliteAnnounceCache::open(&base_path) {
            Ok(cache) => {
                if let Err(error) = cache.import_legacy(&base_path) {
                    log::warn!("Could not import legacy announce cache: {}", error);
                }
                Self {
                    backend: Backend::Sqlite(cache),
                }
            }
            Err(error) => {
                log::warn!(
                    "Could not initialise announce cache database, falling back to file storage: {}",
                    error
                );
                Self {
                    backend: Backend::Files(FileAnnounceCache::new(base_path)),
                }
            }
        }
    }

    pub fn store(
        &self,
        packet_hash: &[u8; 32],
        raw: &[u8],
        interface_name: Option<&str>,
    ) -> io::Result<()> {
        match &self.backend {
            Backend::Sqlite(cache) => cache.store(packet_hash, raw, interface_name),
            Backend::Files(cache) => cache.store(packet_hash, raw, interface_name),
        }
    }

    pub fn get(&self, packet_hash: &[u8; 32]) -> io::Result<Option<(Vec<u8>, Option<String>)>> {
        match &self.backend {
            Backend::Sqlite(cache) => cache.get(packet_hash),
            Backend::Files(cache) => cache.get(packet_hash),
        }
    }

    /// Remove cached announces whose packet hashes are not in the active set.
    pub fn clean(&self, active_hashes: &[[u8; 32]]) -> io::Result<usize> {
        match &self.backend {
            Backend::Sqlite(cache) => cache.clean(active_hashes),
            Backend::Files(cache) => {
                let (removed, _) = cache.clean(active_hashes, 0)?;
                Ok(removed)
            }
        }
    }
}

struct SqliteAnnounceCache {
    conn: Mutex<Connection>,
}

impl SqliteAnnounceCache {
    fn open(base_path: &Path) -> io::Result<Self> {
        let db_path = base_path.with_extension("db");
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(&db_path).map_err(sql_error)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(sql_error)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA journal_size_limit=8388608;
             PRAGMA auto_vacuum=INCREMENTAL;
             CREATE TABLE IF NOT EXISTS cached_announces (
                packet_hash         BLOB PRIMARY KEY,
                received            REAL NOT NULL,
                raw                 BLOB NOT NULL,
                interface_reference TEXT);
             PRAGMA user_version = 1;",
        )
        .map_err(sql_error)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn store(
        &self,
        packet_hash: &[u8; 32],
        raw: &[u8],
        interface_name: Option<&str>,
    ) -> io::Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO cached_announces VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(packet_hash) DO UPDATE SET
               received=excluded.received,
               raw=excluded.raw,
               interface_reference=excluded.interface_reference",
            params![
                packet_hash.to_vec(),
                now(),
                raw.to_vec(),
                interface_name.map(str::to_string)
            ],
        )
        .map_err(sql_error)?;
        Ok(())
    }

    fn get(&self, packet_hash: &[u8; 32]) -> io::Result<Option<(Vec<u8>, Option<String>)>> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT raw, interface_reference FROM cached_announces WHERE packet_hash = ?1",
                params![packet_hash.to_vec()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()
            .map_err(sql_error)?;
        Ok(row)
    }

    fn clean(&self, active_hashes: &[[u8; 32]]) -> io::Result<usize> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(sql_error)?;
        tx.execute("DROP TABLE IF EXISTS temp.active_announces", [])
            .map_err(sql_error)?;
        tx.execute(
            "CREATE TEMP TABLE active_announces (packet_hash BLOB PRIMARY KEY)",
            [],
        )
        .map_err(sql_error)?;
        {
            let mut statement = tx
                .prepare("INSERT OR IGNORE INTO active_announces VALUES (?1)")
                .map_err(sql_error)?;
            for hash in active_hashes {
                statement
                    .execute(params![hash.to_vec()])
                    .map_err(sql_error)?;
            }
        }
        let removed = tx
            .execute(
                "DELETE FROM cached_announces
                 WHERE packet_hash NOT IN (SELECT packet_hash FROM active_announces)",
                [],
            )
            .map_err(sql_error)?;
        tx.commit().map_err(sql_error)?;
        if removed > 0 {
            conn.execute("PRAGMA incremental_vacuum", [])
                .map_err(sql_error)?;
        }
        Ok(removed)
    }

    fn import_legacy(&self, dir_path: &Path) -> io::Result<usize> {
        if !dir_path.is_dir() {
            return Ok(0);
        }
        let mut imported = 0;
        for entry in fs::read_dir(dir_path)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();
            let Some(packet_hash) = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(hex_decode)
            else {
                let _ = fs::remove_file(&path);
                continue;
            };
            let parsed = fs::read(&path)
                .ok()
                .and_then(|data| parse_legacy_announce(&data));
            if let Some((raw, interface_name)) = parsed {
                self.store(&packet_hash, &raw, interface_name.as_deref())?;
                imported += 1;
            }
            let _ = fs::remove_file(&path);
        }
        Ok(imported)
    }
}

fn parse_legacy_announce(data: &[u8]) -> Option<(Vec<u8>, Option<String>)> {
    let (value, _) = msgpack::unpack(data).ok()?;
    let arr = value.as_array()?;
    if arr.is_empty() {
        return None;
    }
    let raw = arr[0].as_bin()?.to_vec();
    let interface_name = arr
        .get(1)
        .and_then(|value| value.as_str())
        .map(str::to_string);
    Some((raw, interface_name))
}

struct FileAnnounceCache {
    base_path: PathBuf,
}

impl FileAnnounceCache {
    fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    fn store(
        &self,
        packet_hash: &[u8; 32],
        raw: &[u8],
        interface_name: Option<&str>,
    ) -> io::Result<()> {
        let path = self.base_path.join(hex_encode(packet_hash));
        let iface_val = match interface_name {
            Some(name) => Value::Str(name.into()),
            None => Value::Nil,
        };
        let data = msgpack::pack(&Value::Array(vec![Value::Bin(raw.to_vec()), iface_val]));
        fs::write(path, data)
    }

    fn get(&self, packet_hash: &[u8; 32]) -> io::Result<Option<(Vec<u8>, Option<String>)>> {
        let path = self.base_path.join(hex_encode(packet_hash));
        if !path.is_file() {
            return Ok(None);
        }
        let data = fs::read(&path)?;
        let (value, _) = msgpack::unpack(&data).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("msgpack error: {}", e))
        })?;
        let arr = value
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Expected msgpack array"))?;
        if arr.is_empty() {
            return Ok(None);
        }
        let raw = arr[0]
            .as_bin()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Expected bin raw bytes"))?;
        let iface_name = arr
            .get(1)
            .and_then(|value| value.as_str())
            .map(str::to_string);
        Ok(Some((raw.to_vec(), iface_name)))
    }

    #[cfg(test)]
    fn entries(&self) -> io::Result<fs::ReadDir> {
        fs::read_dir(&self.base_path)
    }

    fn clean(&self, active_hashes: &[[u8; 32]], batch_limit: usize) -> io::Result<(usize, bool)> {
        let mut entries = match fs::read_dir(&self.base_path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((0, true)),
            Err(e) => return Err(e),
        };
        self.clean_batch(active_hashes, &mut entries, batch_limit)
    }

    fn clean_batch(
        &self,
        active_hashes: &[[u8; 32]],
        entries: &mut fs::ReadDir,
        batch_limit: usize,
    ) -> io::Result<(usize, bool)> {
        use std::collections::HashSet;

        let active_set: HashSet<[u8; 32]> = active_hashes.iter().copied().collect();
        let mut removed = 0;
        let mut processed = 0;

        loop {
            if batch_limit > 0 && processed >= batch_limit {
                return Ok((removed, false));
            }
            let Some(entry) = entries.next() else {
                return Ok((removed, true));
            };
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            processed += 1;
            let filename = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };
            match hex_decode(filename) {
                Some(hash) if active_set.contains(&hash) => {}
                _ => {
                    let _ = fs::remove_file(&path);
                    removed += 1;
                }
            }
        }
    }

    #[cfg(test)]
    fn base_path(&self) -> &Path {
        &self.base_path
    }
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

fn sql_error(error: rusqlite::Error) -> io::Error {
    io::Error::other(error.to_string())
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
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
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
        let dir =
            std::env::temp_dir().join(format!("rns-announce-cache-{}-{}", std::process::id(), id,));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_hex_encode_decode_roundtrip() {
        let hash = [0xAB; 32];
        let encoded = hex_encode(&hash);
        assert_eq!(encoded.len(), 64);
        assert!(encoded.chars().all(|c| c == 'a' || c == 'b'));
        assert_eq!(hex_decode(&encoded), Some(hash));
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert!(hex_decode("too_short").is_none());
        assert!(hex_decode(&"zz".repeat(32)).is_none());
    }

    fn sqlite_cache_dir() -> (PathBuf, PathBuf) {
        let root = temp_dir();
        let legacy = root.join("announces");
        fs::create_dir_all(&legacy).unwrap();
        (root, legacy)
    }

    #[test]
    fn sqlite_store_get_and_reopen() {
        let (root, dir) = sqlite_cache_dir();
        {
            let cache = AnnounceCache::new(dir.clone());
            cache
                .store(&[0x42; 32], &[1, 2, 3], Some("TestInterface"))
                .unwrap();
        }
        let reopened = AnnounceCache::new(dir.clone());
        let (raw, interface) = reopened.get(&[0x42; 32]).unwrap().unwrap();
        assert_eq!(raw, vec![1, 2, 3]);
        assert_eq!(interface.as_deref(), Some("TestInterface"));
        assert!(root.join("announces.db").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sqlite_store_overwrite_and_nil_interface() {
        let (root, dir) = sqlite_cache_dir();
        let cache = AnnounceCache::new(dir.clone());
        let hash = [0x77; 32];
        cache.store(&hash, &[0x01], Some("iface1")).unwrap();
        cache.store(&hash, &[0x02, 0x03], None).unwrap();
        let (raw, interface) = cache.get(&hash).unwrap().unwrap();
        assert_eq!(raw, vec![0x02, 0x03]);
        assert_eq!(interface, None);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sqlite_clean_removes_inactive() {
        let (root, dir) = sqlite_cache_dir();
        let cache = AnnounceCache::new(dir.clone());
        let keep = [0x10; 32];
        let stale1 = [0x20; 32];
        let stale2 = [0x30; 32];
        cache.store(&keep, &[0x01], None).unwrap();
        cache.store(&stale1, &[0x02], None).unwrap();
        cache.store(&stale2, &[0x03], None).unwrap();

        assert_eq!(cache.clean(&[keep]).unwrap(), 2);
        assert!(cache.get(&keep).unwrap().is_some());
        assert!(cache.get(&stale1).unwrap().is_none());
        assert!(cache.get(&stale2).unwrap().is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sqlite_imports_legacy_files() {
        let (root, dir) = sqlite_cache_dir();
        let legacy = FileAnnounceCache::new(dir.clone());
        legacy
            .store(&[0x55; 32], &[0xAA, 0xBB], Some("legacy"))
            .unwrap();

        let cache = AnnounceCache::new(dir.clone());
        let (raw, interface) = cache.get(&[0x55; 32]).unwrap().unwrap();
        assert_eq!(raw, vec![0xAA, 0xBB]);
        assert_eq!(interface.as_deref(), Some("legacy"));
        assert!(!dir.join(hex_encode(&[0x55; 32])).exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn file_backend_get_and_clean() {
        let dir = temp_dir();
        let cache = FileAnnounceCache::new(dir.clone());
        let hash = [0x42; 32];
        cache
            .store(&hash, &[1, 2, 3], Some("TestInterface"))
            .unwrap();
        let (raw, interface) = cache.get(&hash).unwrap().unwrap();
        assert_eq!(raw, vec![1, 2, 3]);
        assert_eq!(interface.as_deref(), Some("TestInterface"));
        assert_eq!(cache.base_path(), dir.as_path());

        let (removed, finished) = cache.clean(&[], 0).unwrap();
        assert_eq!(removed, 1);
        assert!(finished);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_backend_clean_batch_progresses() {
        let dir = temp_dir();
        let cache = FileAnnounceCache::new(dir.clone());
        let keep = [0x10; 32];
        let stale1 = [0x20; 32];
        let stale2 = [0x30; 32];
        cache.store(&keep, &[0x01], None).unwrap();
        cache.store(&stale1, &[0x02], None).unwrap();
        cache.store(&stale2, &[0x03], None).unwrap();
        let mut entries = cache.entries().unwrap();
        let mut removed_total = 0;
        let mut finished = false;
        for _ in 0..4 {
            let (removed, done) = cache.clean_batch(&[keep], &mut entries, 1).unwrap();
            removed_total += removed;
            if done {
                finished = true;
                break;
            }
        }
        assert!(finished);
        assert_eq!(removed_total, 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrapper_falls_back_to_files_when_database_path_is_a_directory() {
        let (root, dir) = sqlite_cache_dir();
        // Force `announces.db` to be a directory so SQLite cannot open it.
        fs::create_dir_all(root.join("announces.db")).unwrap();
        let cache = AnnounceCache::new(dir.clone());
        let hash = [0x88; 32];
        cache.store(&hash, &[0x01], None).unwrap();
        assert!(dir.join(hex_encode(&hash)).exists());
        let _ = fs::remove_dir_all(&root);
    }
}
