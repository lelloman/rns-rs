//! SQLite-backed identity persistence.
//!
//! Mirrors Python Reticulum's `known_destinations.db` layout while keeping a
//! small native metadata table for fields Python does not persist.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use crate::storage::{KnownDestination, RatchetCleanupStats, RatchetEntry, RatchetStore};

/// Default database filename inside the Reticulum storage directory.
pub const KNOWN_DESTINATIONS_DB: &str = "known_destinations.db";

pub fn default_path(storage_dir: &Path) -> PathBuf {
    storage_dir.join(KNOWN_DESTINATIONS_DB)
}

/// Write-behind SQLite store for known destinations and received ratchets.
///
/// The in-memory tables remain authoritative for transport operations; this
/// store is only used to load and persist them.
pub struct KnownDestinationsStore {
    conn: Mutex<Connection>,
    #[allow(dead_code)]
    hash_width: usize,
    read_only: bool,
}

impl KnownDestinationsStore {
    pub fn open(path: &Path, hash_width: usize) -> io::Result<Self> {
        Self::open_inner(path, hash_width, false)
    }

    pub fn open_read_only(path: &Path, hash_width: usize) -> io::Result<Self> {
        Self::open_inner(path, hash_width, true)
    }

    fn open_inner(path: &Path, hash_width: usize, read_only: bool) -> io::Result<Self> {
        if !read_only {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
        }
        let flags = if read_only {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
        };
        let conn = Connection::open_with_flags(path, flags).map_err(sql_error)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(sql_error)?;
        if !read_only {
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=NORMAL;
                 PRAGMA journal_size_limit=8388608;",
            )
            .map_err(sql_error)?;
            create_schema(&conn)?;
        }
        Ok(Self {
            conn: Mutex::new(conn),
            hash_width,
            read_only,
        })
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn load_all(&self) -> io::Result<Vec<([u8; 16], KnownDestination)>> {
        let conn = self.lock();
        let mut statement = conn
            .prepare(
                "SELECT k.destination_hash, k.last_heard, k.public_key, k.app_data,
                        k.used, k.identity_hash, COALESCE(m.hops, 0),
                        COALESCE(m.receiving_interface, 0), COALESCE(m.retained, 0),
                        k.stamp, COALESCE(k.stamp_value, 0)
                 FROM known_destinations k
                 LEFT JOIN known_destination_meta m
                   ON m.destination_hash = k.destination_hash",
            )
            .map_err(sql_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, f64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, f64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                    row.get::<_, i64>(10)?,
                ))
            })
            .map_err(sql_error)?;

        let mut destinations = Vec::new();
        for row in rows {
            let (
                destination_hash,
                received_at,
                public_key,
                app_data,
                used,
                identity_hash,
                hops,
                receiving_interface,
                retained,
                stamp,
                stamp_value,
            ) = row.map_err(sql_error)?;
            let Ok(destination_hash) = fixed_16(&destination_hash) else {
                continue;
            };
            let Ok(public_key) = fixed_64(&public_key) else {
                continue;
            };
            let identity_hash = fixed_16(&identity_hash).unwrap_or_else(|_| {
                let mut hash = [0u8; 16];
                hash.copy_from_slice(&crate::storage::full_hash_prefix(&public_key));
                hash
            });
            destinations.push((
                destination_hash,
                KnownDestination {
                    identity_hash,
                    public_key,
                    app_data,
                    hops: hops.clamp(0, u8::MAX as i64) as u8,
                    received_at,
                    receiving_interface: receiving_interface.max(0) as u64,
                    was_used: used != 0.0,
                    last_used_at: (used > 0.0).then_some(used),
                    retained: retained != 0,
                    stamp,
                    stamp_value: stamp_value.clamp(0, u32::MAX as i64) as u32,
                },
            ));
        }
        Ok(destinations)
    }

    /// Replace the persisted snapshot with `destinations`.
    pub fn save_all(
        &self,
        destinations: &HashMap<[u8; 16], KnownDestination>,
    ) -> io::Result<usize> {
        if self.read_only {
            return Ok(0);
        }
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(sql_error)?;
        tx.execute("DELETE FROM known_destinations", [])
            .map_err(sql_error)?;
        tx.execute("DELETE FROM known_destination_meta", [])
            .map_err(sql_error)?;
        for (destination_hash, destination) in destinations {
            upsert_destination(&tx, *destination_hash, destination)?;
        }
        tx.commit().map_err(sql_error)?;
        Ok(destinations.len())
    }

    /// Import a legacy msgpack known-destinations file from Python or older
    /// rns-rs releases. Existing rows are replaced.
    pub fn import_legacy(&self, path: &Path) -> io::Result<usize> {
        if self.read_only {
            return Ok(0);
        }
        let legacy = match crate::storage::load_known_destinations(path) {
            Ok(legacy) => legacy,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(err) => return Err(err),
        };
        if legacy.is_empty() {
            return Ok(0);
        }
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(sql_error)?;
        for (destination_hash, destination) in &legacy {
            upsert_destination(&tx, *destination_hash, destination)?;
        }
        tx.commit().map_err(sql_error)?;
        Ok(legacy.len())
    }

    /// Import legacy ratchet files, skipping expired or unknown destinations.
    pub fn import_legacy_ratchets(
        &self,
        dir_path: &Path,
        expiry_cutoff: f64,
        known_destinations: &HashSet<[u8; 16]>,
    ) -> io::Result<usize> {
        if self.read_only || !dir_path.is_dir() {
            return Ok(0);
        }
        let mut imported = 0usize;
        let mut rows: Vec<([u8; 16], RatchetEntry)> = Vec::new();
        for entry in fs::read_dir(dir_path)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();
            let Some(filename) = path.file_name().and_then(|name| name.to_str()) else {
                let _ = fs::remove_file(&path);
                continue;
            };
            let Some(destination_hash) = parse_hex_16(filename) else {
                let _ = fs::remove_file(&path);
                continue;
            };
            let parsed = fs::read(&path)
                .ok()
                .and_then(|data| parse_legacy_ratchet(&data));
            let Some(ratchet) = parsed else {
                let _ = fs::remove_file(&path);
                continue;
            };
            if ratchet.received_at < expiry_cutoff
                || !known_destinations.contains(&destination_hash)
            {
                let _ = fs::remove_file(&path);
                continue;
            }
            rows.push((destination_hash, ratchet));
            imported += 1;
            let _ = fs::remove_file(&path);
        }

        let mut conn = self.lock();
        let tx = conn.transaction().map_err(sql_error)?;
        for (destination_hash, ratchet) in rows {
            tx.execute(
                "INSERT INTO ratchets VALUES (?1, ?2, ?3)
                 ON CONFLICT(destination_hash) DO UPDATE SET
                   ratchet=excluded.ratchet, received=excluded.received",
                params![
                    destination_hash.to_vec(),
                    ratchet.ratchet.to_vec(),
                    ratchet.received_at
                ],
            )
            .map_err(sql_error)?;
        }
        tx.commit().map_err(sql_error)?;
        Ok(imported)
    }

    /// Delete ratchets older than `cutoff` and return their destinations.
    pub fn expire_ratchets(&self, cutoff: f64) -> io::Result<Vec<[u8; 16]>> {
        if self.read_only {
            return Ok(Vec::new());
        }
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(sql_error)?;
        let mut expired = Vec::new();
        {
            let mut statement = tx
                .prepare("SELECT destination_hash FROM ratchets WHERE received < ?1")
                .map_err(sql_error)?;
            let rows = statement
                .query_map(params![cutoff], |row| row.get::<_, Vec<u8>>(0))
                .map_err(sql_error)?;
            for row in rows {
                if let Ok(hash) = fixed_16(&row.map_err(sql_error)?) {
                    expired.push(hash);
                }
            }
        }
        for destination_hash in &expired {
            tx.execute(
                "DELETE FROM ratchets WHERE destination_hash = ?1",
                params![destination_hash.to_vec()],
            )
            .map_err(sql_error)?;
        }
        tx.commit().map_err(sql_error)?;
        Ok(expired)
    }
}

impl RatchetStore for KnownDestinationsStore {
    fn remember(&self, dest_hash: [u8; 16], entry: RatchetEntry) -> io::Result<()> {
        if self.read_only {
            return Ok(());
        }
        let conn = self.lock();
        let existing = conn
            .query_row(
                "SELECT ratchet FROM ratchets WHERE destination_hash = ?1",
                params![dest_hash.to_vec()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(sql_error)?;
        if existing.as_deref() == Some(entry.ratchet.as_slice()) {
            return Ok(());
        }
        conn.execute(
            "INSERT INTO ratchets VALUES (?1, ?2, ?3)
             ON CONFLICT(destination_hash) DO UPDATE SET
               ratchet=excluded.ratchet, received=excluded.received",
            params![
                dest_hash.to_vec(),
                entry.ratchet.to_vec(),
                entry.received_at
            ],
        )
        .map_err(sql_error)?;
        Ok(())
    }

    fn current(
        &self,
        dest_hash: &[u8; 16],
        now: f64,
        expiry_secs: f64,
    ) -> io::Result<Option<RatchetEntry>> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT ratchet, received FROM ratchets WHERE destination_hash = ?1",
                params![dest_hash.to_vec()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, f64>(1)?)),
            )
            .optional()
            .map_err(sql_error)?;
        let Some((ratchet, received_at)) = row else {
            return Ok(None);
        };
        let Ok(ratchet) = fixed_32(&ratchet) else {
            if !self.read_only {
                conn.execute(
                    "DELETE FROM ratchets WHERE destination_hash = ?1",
                    params![dest_hash.to_vec()],
                )
                .map_err(sql_error)?;
            }
            return Ok(None);
        };
        if now > received_at + expiry_secs {
            if !self.read_only {
                conn.execute(
                    "DELETE FROM ratchets WHERE destination_hash = ?1",
                    params![dest_hash.to_vec()],
                )
                .map_err(sql_error)?;
            }
            return Ok(None);
        }
        Ok(Some(RatchetEntry {
            ratchet,
            received_at,
        }))
    }

    fn cleanup(
        &self,
        known_destinations: &HashSet<[u8; 16]>,
        now: f64,
        expiry_secs: f64,
    ) -> io::Result<RatchetCleanupStats> {
        if self.read_only {
            return Ok(RatchetCleanupStats::default());
        }
        let conn = self.lock();
        let mut statement = conn
            .prepare("SELECT destination_hash, received FROM ratchets")
            .map_err(sql_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, f64>(1)?))
            })
            .map_err(sql_error)?;
        let mut stale = Vec::new();
        let mut stats = RatchetCleanupStats::default();
        for row in rows {
            let (destination_hash, received_at) = row.map_err(sql_error)?;
            stats.processed += 1;
            let Ok(parsed_hash) = fixed_16(&destination_hash) else {
                stale.push(destination_hash);
                stats.removed += 1;
                continue;
            };
            let unknown = !known_destinations.contains(&parsed_hash);
            if unknown {
                stats.not_known += 1;
            }
            if unknown || now > received_at + expiry_secs {
                stale.push(parsed_hash.to_vec());
                stats.removed += 1;
            }
        }
        drop(statement);
        for destination_hash in stale {
            conn.execute(
                "DELETE FROM ratchets WHERE destination_hash = ?1",
                params![destination_hash],
            )
            .map_err(sql_error)?;
        }
        Ok(stats)
    }
}

fn create_schema(conn: &Connection) -> io::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS known_destinations (
            destination_hash BLOB PRIMARY KEY,
            last_heard       REAL NOT NULL,
            packet_hash      BLOB NOT NULL,
            public_key       BLOB NOT NULL,
            app_data         BLOB,
            used             REAL NOT NULL DEFAULT 0,
            stamp            BLOB,
            stamp_value      INTEGER,
            identity_hash    BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS ratchets (
            destination_hash BLOB PRIMARY KEY,
            ratchet          BLOB NOT NULL,
            received         REAL NOT NULL);
         CREATE TABLE IF NOT EXISTS known_destination_meta (
            destination_hash    BLOB PRIMARY KEY,
            hops                INTEGER NOT NULL DEFAULT 0,
            receiving_interface INTEGER NOT NULL DEFAULT 0,
            retained            INTEGER NOT NULL DEFAULT 0);
         PRAGMA user_version = 1;",
    )
    .map_err(sql_error)
}

fn upsert_destination(
    conn: &Connection,
    destination_hash: [u8; 16],
    destination: &KnownDestination,
) -> io::Result<()> {
    let used = match (destination.was_used, destination.last_used_at) {
        (_, Some(last_used_at)) => last_used_at,
        (true, None) => -1.0,
        (false, None) => 0.0,
    };
    conn.execute(
        "INSERT INTO known_destinations VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
         ON CONFLICT(destination_hash) DO UPDATE SET
           last_heard=excluded.last_heard,
           packet_hash=excluded.packet_hash,
           public_key=excluded.public_key,
           app_data=excluded.app_data,
           used=excluded.used,
           stamp=excluded.stamp,
           stamp_value=excluded.stamp_value,
           identity_hash=excluded.identity_hash",
        params![
            destination_hash.to_vec(),
            destination.received_at,
            vec![0u8; 32],
            destination.public_key.to_vec(),
            destination.app_data.clone(),
            used,
            destination.stamp.clone(),
            i64::from(destination.stamp_value),
            destination.identity_hash.to_vec(),
        ],
    )
    .map_err(sql_error)?;
    conn.execute(
        "INSERT INTO known_destination_meta VALUES (?1,?2,?3,?4)
         ON CONFLICT(destination_hash) DO UPDATE SET
           hops=excluded.hops,
           receiving_interface=excluded.receiving_interface,
           retained=excluded.retained",
        params![
            destination_hash.to_vec(),
            i64::from(destination.hops),
            destination.receiving_interface as i64,
            i64::from(destination.retained),
        ],
    )
    .map_err(sql_error)?;
    Ok(())
}

fn parse_legacy_ratchet(data: &[u8]) -> Option<RatchetEntry> {
    use rns_core::msgpack;

    let (value, _) = msgpack::unpack(data).ok()?;
    let ratchet = value.map_get("ratchet")?.as_bin()?;
    let ratchet = fixed_32(ratchet).ok()?;
    let received_at = value.map_get("received")?.as_number()?;
    Some(RatchetEntry {
        ratchet,
        received_at,
    })
}

fn fixed_16(bytes: &[u8]) -> io::Result<[u8; 16]> {
    bytes.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected 16 bytes, got {}", bytes.len()),
        )
    })
}

fn fixed_32(bytes: &[u8]) -> io::Result<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected 32 bytes, got {}", bytes.len()),
        )
    })
}

fn fixed_64(bytes: &[u8]) -> io::Result<[u8; 64]> {
    bytes.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected 64 bytes, got {}", bytes.len()),
        )
    })
}

fn parse_hex_16(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (index, chunk) in text.as_bytes().chunks(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        bytes[index] = (high << 4) | low;
    }
    Some(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn sql_error(error: rusqlite::Error) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rns-sqlite-storage-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn destination(hash: u8, used: Option<f64>, retained: bool) -> KnownDestination {
        KnownDestination {
            identity_hash: [hash.wrapping_add(1); 16],
            public_key: [hash; 64],
            app_data: Some(vec![hash]),
            hops: 3,
            received_at: 1_000.0 + f64::from(hash),
            receiving_interface: 7,
            was_used: used.is_some(),
            last_used_at: used,
            retained,
            stamp: Some(vec![hash; 14]),
            stamp_value: u32::from(hash),
        }
    }

    #[test]
    fn sqlite_known_destinations_roundtrip() {
        let dir = temp_dir();
        let store = KnownDestinationsStore::open(&default_path(&dir), 16).unwrap();
        let destinations = HashMap::from([
            ([0x11; 16], destination(0x11, Some(2_000.0), true)),
            ([0x22; 16], destination(0x22, None, false)),
        ]);
        assert_eq!(store.save_all(&destinations).unwrap(), 2);

        let loaded: HashMap<_, _> = store.load_all().unwrap().into_iter().collect();
        assert_eq!(loaded.len(), 2);
        let used = &loaded[&[0x11; 16]];
        assert_eq!(used.public_key, [0x11; 64]);
        assert_eq!(used.app_data.as_deref(), Some([0x11].as_slice()));
        assert_eq!(used.hops, 3);
        assert_eq!(used.receiving_interface, 7);
        assert!(used.was_used);
        assert_eq!(used.last_used_at, Some(2_000.0));
        assert!(used.retained);
        assert_eq!(used.stamp.as_deref(), Some(&[0x11; 14][..]));
        assert_eq!(used.stamp_value, 0x11);
        let never = &loaded[&[0x22; 16]];
        assert!(!never.was_used);
        assert_eq!(never.last_used_at, None);
        assert!(!never.retained);
    }

    #[test]
    fn sqlite_imports_legacy_known_destinations() {
        let dir = temp_dir();
        let legacy_path = dir.join("known_destinations");
        let legacy = HashMap::from([([0x33; 16], destination(0x33, Some(3_000.0), true))]);
        crate::storage::save_known_destinations(&legacy, &legacy_path).unwrap();

        let store = KnownDestinationsStore::open(&default_path(&dir), 16).unwrap();
        assert_eq!(store.import_legacy(&legacy_path).unwrap(), 1);
        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, [0x33; 16]);
        assert_eq!(loaded[0].1.last_used_at, Some(3_000.0));
        assert!(loaded[0].1.retained);
    }

    #[test]
    fn sqlite_ratchet_store_roundtrip_and_cleanup() {
        let dir = temp_dir();
        let store = KnownDestinationsStore::open(&default_path(&dir), 16).unwrap();
        store
            .remember(
                [0x44; 16],
                RatchetEntry {
                    ratchet: [0xAA; 32],
                    received_at: 1_000.0,
                },
            )
            .unwrap();
        let current = store.current(&[0x44; 16], 1_100.0, 500.0).unwrap();
        assert_eq!(
            current,
            Some(RatchetEntry {
                ratchet: [0xAA; 32],
                received_at: 1_000.0,
            })
        );
        assert!(store
            .current(&[0x44; 16], 1_600.0, 500.0)
            .unwrap()
            .is_none());

        store
            .remember(
                [0x45; 16],
                RatchetEntry {
                    ratchet: [0xBB; 32],
                    received_at: 1_000.0,
                },
            )
            .unwrap();
        store
            .remember(
                [0x46; 16],
                RatchetEntry {
                    ratchet: [0xCC; 32],
                    received_at: 500.0,
                },
            )
            .unwrap();
        let known = HashSet::from([[0x44; 16], [0x45; 16]]);
        let stats = store.cleanup(&known, 1_200.0, 500.0).unwrap();
        assert_eq!(stats.processed, 2);
        assert_eq!(stats.not_known, 1);
        assert_eq!(stats.removed, 1);
        let stats = store.cleanup(&known, 1_600.0, 500.0).unwrap();
        assert_eq!(stats.processed, 1);
        assert_eq!(stats.removed, 1);
    }

    #[test]
    fn sqlite_imports_legacy_ratchets() {
        let dir = temp_dir();
        let legacy_dir = dir.join("ratchets");
        fs::create_dir_all(&legacy_dir).unwrap();
        let legacy = crate::storage::FsRatchetStore::new(legacy_dir.clone());
        legacy
            .remember(
                [0x55; 16],
                RatchetEntry {
                    ratchet: [0xDD; 32],
                    received_at: 2_000.0,
                },
            )
            .unwrap();
        legacy
            .remember(
                [0x56; 16],
                RatchetEntry {
                    ratchet: [0xEE; 32],
                    received_at: 100.0,
                },
            )
            .unwrap();

        let store = KnownDestinationsStore::open(&default_path(&dir), 16).unwrap();
        let known = HashSet::from([[0x55; 16], [0x56; 16]]);
        assert_eq!(
            store
                .import_legacy_ratchets(&legacy_dir, 1_000.0, &known)
                .unwrap(),
            1
        );
        assert!(store
            .current(&[0x55; 16], 2_000.0, 5_000.0)
            .unwrap()
            .is_some());
        assert!(store
            .current(&[0x56; 16], 2_000.0, 5_000.0)
            .unwrap()
            .is_none());
    }

    #[test]
    fn sqlite_read_only_does_not_write() {
        let dir = temp_dir();
        let path = default_path(&dir);
        let store = KnownDestinationsStore::open(&path, 16).unwrap();
        store
            .save_all(&HashMap::from([(
                [0x66; 16],
                destination(0x66, Some(1_500.0), false),
            )]))
            .unwrap();
        drop(store);

        let read_only = KnownDestinationsStore::open_read_only(&path, 16).unwrap();
        assert_eq!(read_only.load_all().unwrap().len(), 1);
        assert_eq!(read_only.save_all(&HashMap::new()).unwrap(), 0);
        assert!(read_only
            .remember(
                [0x67; 16],
                RatchetEntry {
                    ratchet: [0xFF; 32],
                    received_at: 1.0,
                },
            )
            .is_ok());
        drop(read_only);
        let writable = KnownDestinationsStore::open(&path, 16).unwrap();
        assert_eq!(writable.load_all().unwrap().len(), 1);
        assert!(writable.current(&[0x67; 16], 2.0, 5.0).unwrap().is_none());
    }
}
