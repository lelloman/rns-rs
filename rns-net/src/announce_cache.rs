//! Announce cache for persistence.
//!
//! Uses SQLite (`announces.db`) by default, mirroring Python Reticulum's
//! `cached_announces` table. Legacy per-file caches are imported on first use.
//! If SQLite cannot be opened, the legacy filesystem backend is retained.
//!
//! Python reference: Transport.py:3087-3099 and Storage.py AnnounceCache.

use rns_core::encoding::{hex, hex_decode_array};
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
pub(crate) struct AnnounceCache {
    backend: Backend,
}

/// Where a node whose state directory is `storage_dir` keeps its announce
/// cache: upstream's `<storagepath>/cache/announces`
/// (`Reticulum.cachepath` is `<configdir>/storage/cache`), so the database
/// is `storage/cache/announces.db`, as `Transport.init_announce_cache`
/// opens it.
pub(crate) fn announce_cache_base(storage_dir: &Path) -> PathBuf {
    storage_dir.join("cache").join("announces")
}

/// SQLite files that belong with a database: the write-ahead log and its
/// shared-memory index, and a rollback journal.
const SQLITE_SIDECARS: [&str; 3] = ["-wal", "-shm", "-journal"];

/// `path` with `suffix` appended to its file name.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Move an announce cache kept at `old_base` (rns-rs before this release
/// kept it in `<configdir>/cache/announces`) to `new_base`, once, before it
/// is opened.
///
/// When `<old_base>.db` exists and `<new_base>.db` does not, the database
/// and its SQLite sidecar files are renamed, all or none: if one rename
/// fails the moved files are put back and the old cache stays where it is.
/// Legacy per-file announces in the `old_base` directory move into
/// `new_base` unless one of the same name is there, to be imported when the
/// cache opens. The old directory, and its parent, are then removed when
/// empty. Every step is logged; a failure is logged and leaves the cache to
/// start empty at the new location.
pub(crate) fn migrate_announce_cache(old_base: &Path, new_base: &Path) {
    if old_base == new_base {
        return;
    }
    let old_db = old_base.with_extension("db");
    let new_db = new_base.with_extension("db");
    if old_db.exists() {
        if new_db.exists() {
            log::warn!(
                "Announce cache {} is no longer used: {} already exists",
                old_db.display(),
                new_db.display()
            );
        } else {
            match move_database(&old_db, &new_db) {
                Ok(()) => log::info!(
                    "Moved announce cache {} to {}",
                    old_db.display(),
                    new_db.display()
                ),
                Err(error) => log::warn!(
                    "Could not move announce cache {} to {}, leaving it in place: {}",
                    old_db.display(),
                    new_db.display(),
                    error
                ),
            }
        }
    }
    if old_base.is_dir() {
        match move_legacy_files(old_base, new_base) {
            Ok(0) => {}
            Ok(moved) => log::info!(
                "Moved {} legacy cached announces from {} to {}",
                moved,
                old_base.display(),
                new_base.display()
            ),
            Err(error) => log::warn!(
                "Could not move legacy cached announces from {} to {}: {}",
                old_base.display(),
                new_base.display(),
                error
            ),
        }
        if fs::remove_dir(old_base).is_ok() {
            log::info!("Removed empty directory {}", old_base.display());
            if let Some(parent) = old_base.parent() {
                if fs::remove_dir(parent).is_ok() {
                    log::info!("Removed empty directory {}", parent.display());
                }
            }
        }
    }
}

/// Rename the database `old_db` and its sidecars to `new_db`, rolling back
/// on failure.
fn move_database(old_db: &Path, new_db: &Path) -> io::Result<()> {
    if let Some(parent) = new_db.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut files = vec![(old_db.to_path_buf(), new_db.to_path_buf())];
    for suffix in SQLITE_SIDECARS {
        let (from, to) = (with_suffix(old_db, suffix), with_suffix(new_db, suffix));
        if from.exists() {
            if to.exists() {
                fs::remove_file(&to)?;
            }
            files.push((from, to));
        }
    }
    let mut moved: Vec<&(PathBuf, PathBuf)> = Vec::new();
    for pair in &files {
        if let Err(error) = fs::rename(&pair.0, &pair.1) {
            for (from, to) in moved.into_iter().rev() {
                if let Err(rollback) = fs::rename(to, from) {
                    log::warn!(
                        "Could not move {} back to {}: {}",
                        to.display(),
                        from.display(),
                        rollback
                    );
                }
            }
            return Err(error);
        }
        moved.push(pair);
    }
    Ok(())
}

/// Move the files in `old_dir` into `new_dir`, keeping any already there.
/// Returns how many moved.
fn move_legacy_files(old_dir: &Path, new_dir: &Path) -> io::Result<usize> {
    let mut moved = 0;
    for entry in fs::read_dir(old_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let target = new_dir.join(entry.file_name());
        if target.exists() {
            continue;
        }
        fs::create_dir_all(new_dir)?;
        fs::rename(entry.path(), target)?;
        moved += 1;
    }
    Ok(moved)
}

impl AnnounceCache {
    /// Create an announce cache rooted at `base_path`.
    ///
    /// The database is written next to the legacy directory as
    /// `<base_path>.db` (for example `storage/cache/announces.db` for
    /// `storage/cache/announces`, see [`announce_cache_base`]). Legacy files
    /// already in `base_path` are imported and removed.
    pub(crate) fn new(base_path: PathBuf) -> Self {
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

    /// Store the raw announce `raw` under its packet hash, with the name of
    /// the interface it was received on, if any.
    pub(crate) fn store(
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

    /// The raw announce stored under `packet_hash` and its interface name.
    pub(crate) fn get(
        &self,
        packet_hash: &[u8; 32],
    ) -> io::Result<Option<(Vec<u8>, Option<String>)>> {
        match &self.backend {
            Backend::Sqlite(cache) => cache.get(packet_hash),
            Backend::Files(cache) => cache.get(packet_hash),
        }
    }

    /// Remove cached announces whose packet hashes are not in the active set.
    pub(crate) fn clean(&self, active_hashes: &[[u8; 32]]) -> io::Result<usize> {
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
        // Upstream 8a09c9b5: `auto_vacuum` only takes effect before the
        // database header is written, which switching to WAL does, so it
        // must come first.
        conn.execute_batch(
            "PRAGMA auto_vacuum=INCREMENTAL;
             PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA journal_size_limit=8388608;
             CREATE TABLE IF NOT EXISTS cached_announces (
                packet_hash         BLOB PRIMARY KEY,
                received            REAL NOT NULL,
                raw                 BLOB NOT NULL,
                interface_reference TEXT);
             PRAGMA user_version = 1;",
        )
        .map_err(sql_error)?;
        convert_to_incremental_vacuum(&conn, &db_path);
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        crate::sync::lock_or_recover(&self.conn, "announce cache conn")
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
            // `incremental_vacuum` returns a row per freed page and frees
            // them as it is stepped, so it is read to completion.
            let mut statement = conn
                .prepare("PRAGMA incremental_vacuum")
                .map_err(sql_error)?;
            let mut rows = statement.query([]).map_err(sql_error)?;
            while rows.next().map_err(sql_error)?.is_some() {}
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
                .and_then(hex_decode_array::<32>)
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
    let raw = arr.first()?.as_bin()?.to_vec();
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
        let path = self.base_path.join(hex(packet_hash));
        let iface_val = match interface_name {
            Some(name) => Value::Str(name.into()),
            None => Value::Nil,
        };
        let data = msgpack::pack(&Value::Array(vec![Value::Bin(raw.to_vec()), iface_val]));
        fs::write(path, data)
    }

    fn get(&self, packet_hash: &[u8; 32]) -> io::Result<Option<(Vec<u8>, Option<String>)>> {
        let path = self.base_path.join(hex(packet_hash));
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
        let Some(raw) = arr.first() else {
            return Ok(None);
        };
        let raw = raw
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
            match hex_decode_array::<32>(filename) {
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

/// A cache created with the old pragma order has `auto_vacuum=NONE`, so its
/// `incremental_vacuum` after a clean reclaims nothing. Upstream leaves such a
/// file as it is; here a one-time `VACUUM` applies the incremental mode set
/// on this connection. A failure (for example too little disk space for the
/// copy) is logged and the cache keeps working without it.
fn convert_to_incremental_vacuum(conn: &Connection, db_path: &Path) {
    const AUTO_VACUUM_INCREMENTAL: i64 = 2;
    let mode = match conn.query_row("PRAGMA auto_vacuum", [], |row| row.get::<_, i64>(0)) {
        Ok(mode) => mode,
        Err(error) => {
            log::warn!("Could not read announce cache auto_vacuum mode: {}", error);
            return;
        }
    };
    if mode == AUTO_VACUUM_INCREMENTAL {
        return;
    }
    log::info!(
        "Converting announce cache {} to incremental auto-vacuum",
        db_path.display()
    );
    if let Err(error) = conn.execute_batch("VACUUM") {
        log::warn!(
            "Could not convert announce cache to incremental auto-vacuum: {}",
            error
        );
    }
}

fn sql_error(error: rusqlite::Error) -> io::Error {
    io::Error::other(error.to_string())
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

    /// rns-rs kept the announce cache in `<config>/cache/announces.db`;
    /// it moves, with its WAL sidecars and legacy files, to upstream's
    /// `<config>/storage/cache/announces.db` and stays readable there.
    #[test]
    fn migrates_the_announce_cache_to_upstreams_location() {
        let root = temp_dir();
        let old_base = root.join("cache").join("announces");
        let new_base = announce_cache_base(&root.join("storage"));
        assert_eq!(new_base, root.join("storage/cache/announces"));
        fs::create_dir_all(&old_base).unwrap();
        AnnounceCache::new(old_base.clone())
            .store(&[0x42; 32], &[1, 2, 3], Some("If"))
            .unwrap();
        // Closing folds the WAL into the database; a node that stopped
        // without closing it leaves `-wal` and `-shm` beside it. Empty ones
        // are valid for SQLite.
        let old_db = root.join("cache/announces.db");
        for suffix in ["-wal", "-shm"] {
            fs::write(with_suffix(&old_db, suffix), b"").unwrap();
        }
        fs::write(old_base.join(hex(&[0x55; 32])), b"legacy").unwrap();

        migrate_announce_cache(&old_base, &new_base);

        let new_db = root.join("storage/cache/announces.db");
        assert!(new_db.exists());
        assert!(with_suffix(&new_db, "-wal").exists());
        assert!(with_suffix(&new_db, "-shm").exists());
        assert!(!old_db.exists());
        assert!(!with_suffix(&old_db, "-wal").exists());
        assert!(!with_suffix(&old_db, "-shm").exists());
        assert!(new_base.join(hex(&[0x55; 32])).exists());
        // The emptied old directory and its parent are gone.
        assert!(!root.join("cache").exists());
        let cache = AnnounceCache::new(new_base.clone());
        let (raw, interface) = cache.get(&[0x42; 32]).unwrap().unwrap();
        assert_eq!(raw, vec![1, 2, 3]);
        assert_eq!(interface.as_deref(), Some("If"));
        drop(cache);

        // Once moved, migrating again changes nothing.
        migrate_announce_cache(&old_base, &new_base);
        assert!(new_db.exists());
        let _ = fs::remove_dir_all(&root);
    }

    /// An existing database at the new location is kept, and the old one
    /// is left where it is.
    #[test]
    fn migration_keeps_an_existing_announce_cache() {
        let root = temp_dir();
        let old_base = root.join("cache").join("announces");
        let new_base = announce_cache_base(&root.join("storage"));
        fs::create_dir_all(&old_base).unwrap();
        fs::create_dir_all(&new_base).unwrap();
        AnnounceCache::new(old_base.clone())
            .store(&[0x01; 32], &[1], None)
            .unwrap();
        AnnounceCache::new(new_base.clone())
            .store(&[0x02; 32], &[2], None)
            .unwrap();

        migrate_announce_cache(&old_base, &new_base);

        assert!(root.join("cache/announces.db").exists());
        let cache = AnnounceCache::new(new_base);
        assert!(cache.get(&[0x01; 32]).unwrap().is_none());
        assert!(cache.get(&[0x02; 32]).unwrap().is_some());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_hex_encode_decode_roundtrip() {
        let hash = [0xAB; 32];
        let encoded = hex(&hash);
        assert_eq!(encoded.len(), 64);
        assert!(encoded.chars().all(|c| c == 'a' || c == 'b'));
        assert_eq!(hex_decode_array(&encoded), Some(hash));
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert!(hex_decode_array::<32>("too_short").is_none());
        assert!(hex_decode_array::<32>(&"zz".repeat(32)).is_none());
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

    fn pragma(db_path: &Path, name: &str) -> i64 {
        let conn = Connection::open(db_path).unwrap();
        conn.query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn sqlite_cache_uses_incremental_vacuum_and_reclaims_cleaned_pages() {
        let (root, dir) = sqlite_cache_dir();
        let db_path = root.join("announces.db");
        let cache = AnnounceCache::new(dir.clone());
        assert_eq!(pragma(&db_path, "auto_vacuum"), 2);

        let hashes: Vec<[u8; 32]> = (0..64u8).map(|i| [i; 32]).collect();
        for hash in &hashes {
            cache.store(hash, &[0x5A; 4096], None).unwrap();
        }
        assert_eq!(cache.clean(&hashes[..1]).unwrap(), 63);
        assert_eq!(pragma(&db_path, "freelist_count"), 0);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sqlite_cache_created_with_the_old_pragma_order_is_converted_once() {
        let (root, dir) = sqlite_cache_dir();
        let db_path = root.join("announces.db");
        {
            // The order rns-rs used before upstream 8a09c9b5.
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA auto_vacuum=INCREMENTAL;
                 CREATE TABLE cached_announces (
                    packet_hash         BLOB PRIMARY KEY,
                    received            REAL NOT NULL,
                    raw                 BLOB NOT NULL,
                    interface_reference TEXT);
                 PRAGMA user_version = 1;",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO cached_announces VALUES (?1, 0, ?2, 'kept')",
                params![vec![0x42u8; 32], vec![1u8, 2, 3]],
            )
            .unwrap();
        }
        assert_eq!(pragma(&db_path, "auto_vacuum"), 0);

        let cache = AnnounceCache::new(dir.clone());
        assert_eq!(pragma(&db_path, "auto_vacuum"), 2);
        let (raw, interface) = cache.get(&[0x42; 32]).unwrap().unwrap();
        assert_eq!(raw, vec![1, 2, 3]);
        assert_eq!(interface.as_deref(), Some("kept"));
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
        assert!(!dir.join(hex(&[0x55; 32])).exists());
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
        assert!(dir.join(hex(&hash)).exists());
        let _ = fs::remove_dir_all(&root);
    }
}
