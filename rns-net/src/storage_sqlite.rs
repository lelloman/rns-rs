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
    /// Destinations whose last save was rejected by a constraint or data
    /// error, so each rejection is logged once (upstream's quarantine).
    rejected: Mutex<HashSet<[u8; 16]>>,
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
            rejected: Mutex::new(HashSet::new()),
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
                        k.stamp, COALESCE(k.stamp_value, 0), k.lr_cost
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
                    // REAL since fractional stamp values; older rows hold
                    // INTEGER whole bits, which read the same way.
                    row.get::<_, f64>(10)?,
                    // REAL since fractional link costs (upstream 796ef2d4).
                    row.get::<_, Option<f64>>(11)?,
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
                lr_cost,
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
                    stamp_value: rns_core::stamp::StampValue::from_f64(stamp_value),
                    lr_cost: lr_cost.and_then(crate::storage::stored_link_cost),
                },
            ));
        }
        Ok(destinations)
    }

    /// Replace the persisted snapshot with `destinations` and return how
    /// many were written.
    ///
    /// Each destination is written in its own savepoint. One that a
    /// constraint or data error rejects is left out and logged once, and the
    /// rest of the snapshot is still saved; the next save retries it, so a
    /// later valid update heals it (upstream `1d9067c3`). Other errors abort
    /// the whole save.
    pub fn save_all(
        &self,
        destinations: &HashMap<[u8; 16], KnownDestination>,
    ) -> io::Result<usize> {
        if self.read_only {
            return Ok(0);
        }
        let mut conn = self.lock();
        let mut tx = conn.transaction().map_err(sql_error)?;
        tx.execute("DELETE FROM known_destinations", [])
            .map_err(sql_error)?;
        tx.execute("DELETE FROM known_destination_meta", [])
            .map_err(sql_error)?;
        let mut rejects = Vec::new();
        for (destination_hash, destination) in destinations {
            let row = tx.savepoint().map_err(sql_error)?;
            match upsert_destination(&row, *destination_hash, destination) {
                Ok(()) => row.commit().map_err(sql_error)?,
                Err(error) if is_rejected_row(&error) => {
                    drop(row);
                    rejects.push((*destination_hash, error));
                }
                Err(error) => return Err(sql_error(error)),
            }
        }
        tx.commit().map_err(sql_error)?;
        drop(conn);

        let mut rejected = self
            .rejected
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::mem::take(&mut *rejected);
        for (destination_hash, error) in &rejects {
            if !previous.contains(destination_hash) {
                log::error!(
                    "invalid known destination data for {} at persist: {}",
                    hex_16(destination_hash),
                    error
                );
            }
            rejected.insert(*destination_hash);
        }
        Ok(destinations.len() - rejects.len())
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
            upsert_destination(&tx, *destination_hash, destination).map_err(sql_error)?;
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

/// Schema version of Python's released `known_destinations.db` (upstream
/// `c4ed59be`): the 1.6.0 release format is version 0, with no migrations.
const SCHEMA_VERSION: i64 = 0;

/// Highest pre-release version (`fe2fe94d`). Versions 1 to 3 were written by
/// pre-release Python or by rns-rs before the release format settled.
const LAST_PRE_RELEASE_VERSION: i64 = 3;

/// Columns of `known_destinations`, in Python's order.
const KNOWN_DESTINATION_COLUMNS: &str = "destination_hash, last_heard, packet_hash, public_key, \
     app_data, used, stamp, stamp_value, lr_cost, identity_hash";

fn known_destinations_table(name: &str) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {name} (
            destination_hash BLOB PRIMARY KEY,
            last_heard       REAL NOT NULL,
            packet_hash      BLOB,
            public_key       BLOB NOT NULL,
            app_data         BLOB,
            used             REAL NOT NULL DEFAULT 0,
            stamp            BLOB,
            stamp_value      REAL,
            lr_cost          REAL,
            identity_hash    BLOB NOT NULL);"
    )
}

fn create_schema(conn: &Connection) -> io::Result<()> {
    // One immediate transaction: the version read, the migration and the
    // version write are atomic against another process opening the file.
    conn.execute_batch("BEGIN IMMEDIATE").map_err(sql_error)?;
    match migrate_schema(conn) {
        Ok(()) => conn.execute_batch("COMMIT").map_err(sql_error),
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

fn migrate_schema(conn: &Connection) -> io::Result<()> {
    let db_version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap_or(0);

    conn.execute_batch(&known_destinations_table("known_destinations"))
        .map_err(sql_error)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS ratchets (
            destination_hash BLOB PRIMARY KEY,
            ratchet          BLOB NOT NULL,
            received         REAL NOT NULL);
         CREATE TABLE IF NOT EXISTS known_destination_meta (
            destination_hash    BLOB PRIMARY KEY,
            hops                INTEGER NOT NULL DEFAULT 0,
            receiving_interface INTEGER NOT NULL DEFAULT 0,
            retained            INTEGER NOT NULL DEFAULT 0);",
    )
    .map_err(sql_error)?;

    // Pre-release databases (versions 1 to 3) are brought to the release
    // format. Upstream drops their `known_destinations` table and relearns it
    // from announces; rns-rs rebuilds it with the rows kept. Version 1 lacks
    // `lr_cost`; version 2 has `packet_hash NOT NULL`, which SQLite can only
    // drop by rebuilding the table, and the rebuild also restores Python's
    // column order after the `ADD COLUMN`. Version 3 already has the release
    // columns and is rebuilt the same way. A version above 3 comes from a
    // newer release and is left as it is.
    if (1..=LAST_PRE_RELEASE_VERSION).contains(&db_version) {
        if db_version < 2 {
            conn.execute("ALTER TABLE known_destinations ADD COLUMN lr_cost REAL", [])
                .map_err(sql_error)?;
        }
        conn.execute_batch(&format!(
            "{}
             INSERT INTO known_destinations_release ({KNOWN_DESTINATION_COLUMNS})
               SELECT {KNOWN_DESTINATION_COLUMNS} FROM known_destinations;
             DROP TABLE known_destinations;
             ALTER TABLE known_destinations_release RENAME TO known_destinations;
             PRAGMA user_version = {SCHEMA_VERSION};",
            known_destinations_table("known_destinations_release")
        ))
        .map_err(sql_error)?;
    }
    Ok(())
}

fn upsert_destination(
    conn: &Connection,
    destination_hash: [u8; 16],
    destination: &KnownDestination,
) -> rusqlite::Result<()> {
    let used = match (destination.was_used, destination.last_used_at) {
        (_, Some(last_used_at)) => last_used_at,
        (true, None) => -1.0,
        (false, None) => 0.0,
    };
    conn.execute(
        "INSERT INTO known_destinations
           (destination_hash, last_heard, packet_hash, public_key, app_data,
            used, stamp, stamp_value, lr_cost, identity_hash)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
         ON CONFLICT(destination_hash) DO UPDATE SET
           last_heard=excluded.last_heard,
           packet_hash=excluded.packet_hash,
           public_key=excluded.public_key,
           app_data=excluded.app_data,
           used=excluded.used,
           stamp=excluded.stamp,
           stamp_value=excluded.stamp_value,
           lr_cost=excluded.lr_cost,
           identity_hash=excluded.identity_hash",
        params![
            destination_hash.to_vec(),
            destination.received_at,
            vec![0u8; 32],
            destination.public_key.to_vec(),
            destination.app_data.clone(),
            used,
            destination.stamp.clone(),
            destination.stamp_value.as_f64(),
            destination.lr_cost.map(|cost| cost.as_f64()),
            destination.identity_hash.to_vec(),
        ],
    )?;
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
    )?;
    Ok(())
}

/// Whether a write failed on the row's data rather than the database: a
/// constraint violation, type mismatch or oversized value, the errors
/// Python maps to `IntegrityError` and `DataError`.
fn is_rejected_row(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(
            rusqlite::ErrorCode::ConstraintViolation
                | rusqlite::ErrorCode::TypeMismatch
                | rusqlite::ErrorCode::TooBig
        )
    )
}

fn hex_16(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
            // Fractional, so the REAL column round trip is exercised.
            stamp_value: rns_core::stamp::StampValue::from_fp(u32::from(hash) * 256 + 77),
            // Fractional too (upstream 796ef2d4).
            lr_cost: Some(rns_core::stamp::StampCost::from_fp(
                u32::from(hash) * 64 + 3,
            )),
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
        assert_eq!(
            used.stamp_value,
            rns_core::stamp::StampValue::from_fp(0x11 * 256 + 77)
        );
        assert_eq!(
            used.lr_cost,
            Some(rns_core::stamp::StampCost::from_fp(0x11 * 64 + 3))
        );
        let never = &loaded[&[0x22; 16]];
        assert!(!never.was_used);
        assert_eq!(never.last_used_at, None);
        assert!(!never.retained);
    }

    #[test]
    fn sqlite_save_skips_a_rejected_destination_and_saves_the_rest() {
        let dir = temp_dir();
        let store = KnownDestinationsStore::open(&default_path(&dir), 16).unwrap();
        // SQLite binds NaN as NULL, which `last_heard NOT NULL` rejects.
        let mut invalid = destination(0x22, None, false);
        invalid.received_at = f64::NAN;
        let mut destinations = HashMap::from([
            ([0x11; 16], destination(0x11, None, false)),
            ([0x22; 16], invalid),
            ([0x33; 16], destination(0x33, None, false)),
        ]);

        assert_eq!(store.save_all(&destinations).unwrap(), 2);
        let loaded: HashMap<_, _> = store.load_all().unwrap().into_iter().collect();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains_key(&[0x11; 16]) && loaded.contains_key(&[0x33; 16]));
        assert!(store.rejected.lock().unwrap().contains(&[0x22; 16]));

        // Still rejected on the next save, without failing it.
        assert_eq!(store.save_all(&destinations).unwrap(), 2);

        // A valid update heals the destination.
        destinations.insert([0x22; 16], destination(0x22, None, false));
        assert_eq!(store.save_all(&destinations).unwrap(), 3);
        assert_eq!(store.load_all().unwrap().len(), 3);
        assert!(store.rejected.lock().unwrap().is_empty());
    }

    fn packet_hash_not_null(path: &Path) -> bool {
        let conn = Connection::open(path).unwrap();
        conn.query_row(
            "SELECT \"notnull\" FROM pragma_table_info('known_destinations')
             WHERE name = 'packet_hash'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
            != 0
    }

    #[test]
    fn sqlite_new_schema_allows_a_missing_packet_hash() {
        // Upstream eab2983b: Python stores entries without a packet hash
        // (for example from legacy imports) as NULL.
        let dir = temp_dir();
        let path = default_path(&dir);
        let store = KnownDestinationsStore::open(&path, 16).unwrap();
        assert!(!packet_hash_not_null(&path));
        // The release format is version 0 (upstream c4ed59be).
        assert_eq!(user_version(&path), 0);

        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO known_destinations
               (destination_hash, last_heard, packet_hash, public_key, app_data,
                used, stamp, stamp_value, lr_cost, identity_hash)
             VALUES (?1,?2,NULL,?3,NULL,0,NULL,NULL,NULL,?4)",
            params![
                [0x66u8; 16].to_vec(),
                1_200.0f64,
                [0x66u8; 64].to_vec(),
                [0x66u8; 16].to_vec(),
            ],
        )
        .unwrap();
        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, [0x66; 16]);
        assert_eq!(loaded[0].1.public_key, [0x66; 64]);
    }

    fn user_version(path: &Path) -> i64 {
        Connection::open(path)
            .unwrap()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap()
    }

    fn column_names(path: &Path) -> Vec<String> {
        let conn = Connection::open(path).unwrap();
        let mut statement = conn
            .prepare("SELECT name FROM pragma_table_info('known_destinations') ORDER BY cid")
            .unwrap();
        let names = statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        names
    }

    #[test]
    fn sqlite_rebuilds_a_v2_database_into_the_release_format() {
        // Upstream c4ed59be drops pre-release tables and settles on version
        // 0; the rebuild keeps every row and drops the constraint.
        let dir = temp_dir();
        let path = default_path(&dir);
        {
            // A version 1 table migrated to version 2 by ADD COLUMN, as
            // Python leaves it: lr_cost trails identity_hash.
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE known_destinations (
                    destination_hash BLOB PRIMARY KEY,
                    last_heard       REAL NOT NULL,
                    packet_hash      BLOB NOT NULL,
                    public_key       BLOB NOT NULL,
                    app_data         BLOB,
                    used             REAL NOT NULL DEFAULT 0,
                    stamp            BLOB,
                    stamp_value      REAL,
                    identity_hash    BLOB NOT NULL);
                 ALTER TABLE known_destinations ADD COLUMN lr_cost REAL;
                 PRAGMA user_version = 2;",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO known_destinations
                   (destination_hash, last_heard, packet_hash, public_key, app_data,
                    used, stamp, stamp_value, lr_cost, identity_hash)
                 VALUES (?1,?2,?3,?4,?5,0,NULL,12.5,19.19921875,?6)",
                params![
                    [0x88u8; 16].to_vec(),
                    1_700.0f64,
                    [0x88u8; 32].to_vec(),
                    [0x88u8; 64].to_vec(),
                    Some(b"app".to_vec()),
                    [0x88u8; 16].to_vec(),
                ],
            )
            .unwrap();
        }
        assert!(packet_hash_not_null(&path));

        let store = KnownDestinationsStore::open(&path, 16).unwrap();
        assert_eq!(user_version(&path), 0);
        assert!(!packet_hash_not_null(&path));
        assert_eq!(
            column_names(&path),
            [
                "destination_hash",
                "last_heard",
                "packet_hash",
                "public_key",
                "app_data",
                "used",
                "stamp",
                "stamp_value",
                "lr_cost",
                "identity_hash"
            ]
        );
        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        let entry = &loaded[0].1;
        assert_eq!(loaded[0].0, [0x88; 16]);
        assert_eq!(entry.public_key, [0x88; 64]);
        assert_eq!(entry.app_data.as_deref(), Some(&b"app"[..]));
        assert_eq!(entry.stamp_value.as_f64(), 12.5);
        assert_eq!(
            entry.lr_cost,
            Some(rns_core::stamp::StampCost::from_fp(4915))
        );
        let packet_hash: Vec<u8> = Connection::open(&path)
            .unwrap()
            .query_row("SELECT packet_hash FROM known_destinations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(packet_hash, [0x88; 32]);

        // Reopening a release database changes nothing.
        drop(store);
        KnownDestinationsStore::open(&path, 16).unwrap();
        assert_eq!(user_version(&path), 0);
        assert_eq!(
            KnownDestinationsStore::open(&path, 16)
                .unwrap()
                .load_all()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn sqlite_rebuilds_a_v3_database_into_the_release_format() {
        // Version 3, written by rns-rs or Python at fe2fe94d, already has the
        // release columns; it keeps its rows and moves to version 0.
        let dir = temp_dir();
        let path = default_path(&dir);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(&format!(
                "{}
                 PRAGMA user_version = 3;",
                known_destinations_table("known_destinations")
            ))
            .unwrap();
            conn.execute(
                "INSERT INTO known_destinations
                   (destination_hash, last_heard, packet_hash, public_key, app_data,
                    used, stamp, stamp_value, lr_cost, identity_hash)
                 VALUES (?1,?2,NULL,?3,NULL,0,NULL,25.0,NULL,?4)",
                params![
                    [0x99u8; 16].to_vec(),
                    1_900.0f64,
                    [0x99u8; 64].to_vec(),
                    [0x99u8; 16].to_vec(),
                ],
            )
            .unwrap();
        }

        let store = KnownDestinationsStore::open(&path, 16).unwrap();
        assert_eq!(user_version(&path), 0);
        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, [0x99; 16]);
        assert_eq!(loaded[0].1.stamp_value.as_f64(), 25.0);
    }

    #[test]
    fn sqlite_keeps_a_version_above_the_pre_release_range() {
        let dir = temp_dir();
        let path = default_path(&dir);
        KnownDestinationsStore::open(&path, 16).unwrap();
        assert_eq!(user_version(&path), 0);
        Connection::open(&path)
            .unwrap()
            .execute_batch("PRAGMA user_version = 4;")
            .unwrap();
        KnownDestinationsStore::open(&path, 16).unwrap();
        assert_eq!(user_version(&path), 4);
    }

    #[test]
    fn sqlite_migrates_v1_schema_and_adds_lr_cost() {
        let dir = temp_dir();
        let path = default_path(&dir);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE known_destinations (
                    destination_hash BLOB PRIMARY KEY,
                    last_heard       REAL NOT NULL,
                    packet_hash      BLOB NOT NULL,
                    public_key       BLOB NOT NULL,
                    app_data         BLOB,
                    used             REAL NOT NULL DEFAULT 0,
                    stamp            BLOB,
                    stamp_value      INTEGER,
                    identity_hash    BLOB NOT NULL);
                 PRAGMA user_version = 1;",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO known_destinations VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    [0x77u8; 16].to_vec(),
                    1_500.0f64,
                    vec![0u8; 32],
                    [0x77u8; 64].to_vec(),
                    Option::<Vec<u8>>::None,
                    0.0f64,
                    Some(vec![0x77u8; 14]),
                    20i64,
                    [0x77u8; 16].to_vec(),
                ],
            )
            .unwrap();
        }

        let store = KnownDestinationsStore::open(&path, 16).unwrap();
        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, [0x77; 16]);
        assert_eq!(loaded[0].1.stamp.as_deref(), Some(&[0x77; 14][..]));
        assert_eq!(
            loaded[0].1.stamp_value,
            rns_core::stamp::StampValue::from_whole(20)
        );
        assert_eq!(loaded[0].1.lr_cost, None);

        let conn = Connection::open(&path).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 0);
        assert!(!packet_hash_not_null(&path));

        // An integer cost written before fractional link costs reads as whole
        // bits; one above STAMP_COST_CAP is dropped.
        conn.execute("UPDATE known_destinations SET lr_cost = 19", [])
            .unwrap();
        let loaded = store.load_all().unwrap();
        assert_eq!(
            loaded[0].1.lr_cost,
            Some(rns_core::stamp::StampCost::from_whole(19))
        );
        conn.execute("UPDATE known_destinations SET lr_cost = 101", [])
            .unwrap();
        assert_eq!(store.load_all().unwrap()[0].1.lr_cost, None);
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
