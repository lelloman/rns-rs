//! Persisted blackhole lists, in upstream's on-disk format.
//!
//! `Transport.persist_blackhole` writes the entries made on this node to
//! `storage/blackhole/local`, and the blackhole updater writes each source's
//! list to `storage/blackhole/<source identity hash>`. Every file is a msgpack
//! map from a 16-byte identity hash to `{"source", "until", "reason"}`, where
//! `until` is an absolute Unix time or nil for an entry that never expires.
//! Using the same files lets a node move between implementations without
//! losing its blackhole list.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use rns_core::msgpack::{self, Value};
use rns_core::transport::types::BlackholeEntry;

/// Name of the file holding the entries made on this node.
pub(crate) const LOCAL_FILE: &str = "local";

/// The entries a blackhole directory holds, as `Transport.reload_blackhole`
/// reads them: the local file, then the file of every source in
/// `enabled_sources`. An entry from the local file is kept over a source's,
/// and entries whose `until` has passed are skipped.
pub(crate) fn load(
    dir: &Path,
    enabled_sources: &[[u8; 16]],
    now: f64,
) -> Vec<([u8; 16], BlackholeEntry)> {
    let mut entries: BTreeMap<[u8; 16], BlackholeEntry> = BTreeMap::new();
    let read_dir = match std::fs::read_dir(dir) {
        Ok(read_dir) => read_dir,
        Err(_) => return Vec::new(),
    };
    let mut files: Vec<(Option<[u8; 16]>, std::path::PathBuf)> = Vec::new();
    for item in read_dir.flatten() {
        let name = item.file_name().to_string_lossy().into_owned();
        if name == LOCAL_FILE {
            files.push((None, item.path()));
            continue;
        }
        let Some(source) = parse_hash_hex(&name) else {
            log::debug!("Ignoring blackhole file {name}: not an identity hash");
            continue;
        };
        if !enabled_sources.contains(&source) {
            log::debug!("Skipping disabled blackhole source {name}");
            continue;
        }
        files.push((Some(source), item.path()));
    }
    // The local file first, so its entries win over a source's.
    files.sort_by_key(|(source, _)| source.is_some());
    for (source, path) in files {
        let list = match std::fs::read(&path)
            .map_err(|e| e.to_string())
            .and_then(|data| msgpack::unpack_exact(&data).map_err(|e| format!("{e:?}")))
        {
            Ok(list) => list,
            Err(error) => {
                log::error!(
                    "Could not load blackholed identities from {}: {error}",
                    path.display()
                );
                continue;
            }
        };
        let Some(map) = list.as_map() else {
            log::error!(
                "Could not load blackholed identities from {}: not a map",
                path.display()
            );
            continue;
        };
        for (key, value) in map {
            let Some(identity_hash) = key.as_bin().and_then(|b| <[u8; 16]>::try_from(b).ok())
            else {
                continue;
            };
            if entries.contains_key(&identity_hash) {
                continue;
            }
            let until = value.get_field("until").and_then(time_value);
            if until.is_some_and(|until| now >= until) {
                continue;
            }
            let reason = value
                .get_field("reason")
                .and_then(|reason| reason.as_str())
                .map(str::to_string);
            entries.insert(
                identity_hash,
                BlackholeEntry {
                    created: now,
                    expires: until.unwrap_or(0.0),
                    reason,
                    source,
                },
            );
        }
    }
    entries.into_iter().collect()
}

/// Write the entries made on this node to the local file, as
/// `Transport.persist_blackhole` does: write a temporary file, then rename
/// it over the old one. `local_source` is the transport identity hash
/// recorded as the source of each entry, or nil without one.
pub(crate) fn save_local<'a>(
    dir: &Path,
    entries: impl Iterator<Item = (&'a [u8; 16], &'a BlackholeEntry)>,
    local_source: Option<&[u8; 16]>,
) -> io::Result<()> {
    let map: Vec<(Value, Value)> = entries
        .filter(|(_, entry)| entry.source.is_none())
        .map(|(identity_hash, entry)| {
            (
                Value::Bin(identity_hash.to_vec()),
                entry_value(entry, local_source),
            )
        })
        .collect();
    std::fs::create_dir_all(dir)?;
    let path = dir.join(LOCAL_FILE);
    let tmp = dir.join(format!("{LOCAL_FILE}.tmp"));
    std::fs::write(&tmp, msgpack::pack(&Value::Map(map)))?;
    std::fs::rename(&tmp, &path)
}

/// An entry as upstream stores and publishes it: `{"source", "until",
/// "reason"}`, with the local transport identity hash (or nil) as the
/// source of an entry made on this node.
pub(crate) fn entry_value(entry: &BlackholeEntry, local_source: Option<&[u8; 16]>) -> Value {
    let source = match (entry.source, local_source) {
        (Some(source), _) => Value::Bin(source.to_vec()),
        (None, Some(local)) => Value::Bin(local.to_vec()),
        (None, None) => Value::Nil,
    };
    Value::Map(vec![
        (Value::Str("source".into()), source),
        (
            Value::Str("until".into()),
            if entry.expires == 0.0 {
                Value::Nil
            } else {
                Value::Float(entry.expires)
            },
        ),
        (
            Value::Str("reason".into()),
            entry
                .reason
                .as_ref()
                .map_or(Value::Nil, |reason| Value::Str(reason.clone())),
        ),
    ])
}

fn time_value(value: &Value) -> Option<f64> {
    value
        .as_float()
        .or_else(|| value.as_integer().map(|v| v as f64))
}

fn parse_hash_hex(name: &str) -> Option<[u8; 16]> {
    if name.len() != 32 {
        return None;
    }
    let mut hash = [0u8; 16];
    for (i, byte) in hash.iter_mut().enumerate() {
        *byte = u8::from_str_radix(name.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(hash)
}

trait MapField {
    fn get_field(&self, key: &str) -> Option<&Value>;
}

impl MapField for Value {
    fn get_field(&self, key: &str) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(expires: f64, reason: Option<&str>, source: Option<[u8; 16]>) -> BlackholeEntry {
        BlackholeEntry {
            created: 1.0,
            expires,
            reason: reason.map(str::to_string),
            source,
        }
    }

    #[test]
    fn local_entries_round_trip_in_upstream_format() {
        let dir = tempfile::tempdir().unwrap();
        let local = [0x10; 16];
        let mut entries = BTreeMap::new();
        entries.insert([0x01; 16], entry(0.0, Some("spam"), None));
        entries.insert([0x02; 16], entry(5000.0, None, None));
        // A source's entry is not written to the local file.
        entries.insert([0x03; 16], entry(0.0, None, Some([0x33; 16])));
        save_local(dir.path(), entries.iter(), Some(&local)).unwrap();

        // The file is what upstream writes: hash -> {source, until, reason}.
        let data = std::fs::read(dir.path().join(LOCAL_FILE)).unwrap();
        let map = msgpack::unpack_exact(&data).unwrap();
        let map = map.as_map().unwrap();
        assert_eq!(map.len(), 2);
        let first = &map
            .iter()
            .find(|(k, _)| k.as_bin() == Some(&[0x01; 16][..]))
            .unwrap()
            .1;
        assert_eq!(
            first.get_field("source").unwrap().as_bin(),
            Some(&local[..])
        );
        assert!(first.get_field("until").unwrap().is_nil());
        assert_eq!(first.get_field("reason").unwrap().as_str(), Some("spam"));

        let loaded = load(dir.path(), &[], 1000.0);
        assert_eq!(loaded.len(), 2);
        let (_, kept) = loaded.iter().find(|(h, _)| *h == [0x02; 16]).unwrap();
        assert_eq!(kept.expires, 5000.0);
        assert_eq!(kept.source, None);
    }

    #[test]
    fn load_skips_expired_disabled_and_shadowed_entries() {
        let dir = tempfile::tempdir().unwrap();
        let source = [0x44; 16];
        let file = |name: &str, entries: Vec<([u8; 16], Value)>| {
            let map = entries
                .into_iter()
                .map(|(h, v)| (Value::Bin(h.to_vec()), v))
                .collect();
            std::fs::write(dir.path().join(name), msgpack::pack(&Value::Map(map))).unwrap();
        };
        let fields = |until: Value| {
            Value::Map(vec![
                (Value::Str("until".into()), until),
                (Value::Str("reason".into()), Value::Nil),
            ])
        };
        file(LOCAL_FILE, vec![([0x01; 16], fields(Value::Nil))]);
        file(
            &"44".repeat(16),
            vec![
                // Shadowed by the local entry.
                ([0x01; 16], fields(Value::Float(9e9))),
                // Expired.
                ([0x02; 16], fields(Value::UInt(10))),
                ([0x03; 16], fields(Value::Nil)),
            ],
        );
        file(&"55".repeat(16), vec![([0x05; 16], fields(Value::Nil))]);

        let disabled = load(dir.path(), &[], 100.0);
        assert_eq!(disabled.len(), 1, "only the local file without sources");

        let loaded = load(dir.path(), &[source], 100.0);
        let hashes: Vec<[u8; 16]> = loaded.iter().map(|(h, _)| *h).collect();
        assert_eq!(hashes, vec![[0x01; 16], [0x03; 16]]);
        assert_eq!(loaded[0].1.source, None);
        assert_eq!(loaded[1].1.source, Some(source));
    }
}
