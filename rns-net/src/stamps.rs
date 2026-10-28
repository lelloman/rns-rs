//! Destination announce stamp generation and persistence.
//!
//! Follows upstream `RNS/Stamps.py`: destination stamps are 14-byte detached
//! proof-of-work stamps over `destination_hash || public_key || name_hash`,
//! persisted per destination under `storage/stamps/<hash>.dstamp`.

use std::io;
use std::path::{Path, PathBuf};

use rns_core::constants;
use rns_core::stamp::{stamp_valid, stamp_value, stamp_workblock};

/// Per-destination stamp files.
#[derive(Debug, Clone)]
pub struct DestinationStampStore {
    dir: PathBuf,
}

impl DestinationStampStore {
    pub fn new(storage_dir: &Path) -> Self {
        Self {
            dir: storage_dir.join("stamps"),
        }
    }

    fn path_for(&self, destination_hash: &[u8; 16]) -> PathBuf {
        let mut name = String::with_capacity(32 + 6);
        for byte in destination_hash {
            use std::fmt::Write;
            let _ = write!(name, "{:02x}", byte);
        }
        name.push_str(".dstamp");
        self.dir.join(name)
    }

    /// Load a persisted stamp when it still meets `required_value`.
    pub fn load(
        &self,
        destination_hash: &[u8; 16],
        material: &[u8],
        required_value: u8,
    ) -> Option<(Vec<u8>, u32)> {
        use rns_core::msgpack;

        let data = std::fs::read(self.path_for(destination_hash)).ok()?;
        let (value, _) = msgpack::unpack(&data).ok()?;
        if value.map_get("v").and_then(|v| v.as_uint()) != Some(1) {
            return None;
        }
        let stamp = value.map_get("stamp")?.as_bin()?;
        if stamp.len() != constants::STAMP_LENGTH {
            return None;
        }
        let stamp = stamp.to_vec();
        let workblock = stamp_workblock(material, 0);
        if !stamp_valid(&stamp, required_value, &workblock) {
            log::debug!(
                "stored stamp for {:02x?} is below required value {}; regenerating",
                &destination_hash[..4],
                required_value
            );
            return None;
        }
        let value = stamp_value(&workblock, &stamp);
        Some((stamp, value))
    }

    /// Persist a destination stamp atomically.
    pub fn store(
        &self,
        destination_hash: &[u8; 16],
        stamp: &[u8],
        stamp_value: u32,
    ) -> io::Result<()> {
        use rns_core::msgpack::{self, Value};

        std::fs::create_dir_all(&self.dir)?;
        let value = Value::Map(vec![
            (Value::Str("v".into()), Value::UInt(1)),
            (Value::Str("stamp".into()), Value::Bin(stamp.to_vec())),
            (
                Value::Str("value".into()),
                Value::UInt(u64::from(stamp_value)),
            ),
            (
                Value::Str("generated".into()),
                Value::Float(crate::time::now()),
            ),
        ]);
        let packed = msgpack::pack(&value);
        let path = self.path_for(destination_hash);
        let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
        std::fs::write(&tmp, packed)?;
        std::fs::rename(tmp, path)
    }
}

/// Material covered by a destination announce stamp.
pub fn destination_stamp_material(
    destination_hash: &[u8; 16],
    public_key: &[u8; 64],
    name_hash: &[u8; 10],
) -> Vec<u8> {
    let mut material = Vec::with_capacity(16 + 64 + 10);
    material.extend_from_slice(destination_hash);
    material.extend_from_slice(public_key);
    material.extend_from_slice(name_hash);
    material
}

/// Build the announce extension payload: marker, flags, stamp, link cost.
pub fn announce_ext_payload(stamp: &[u8], flags: u8, lr_cost: u8) -> Vec<u8> {
    let mut payload = Vec::with_capacity(constants::EXT_PAYLOAD_LENGTH);
    payload.push(constants::EXT_PAYLOAD_MARKER);
    payload.push(flags);
    payload.extend_from_slice(stamp);
    payload.push(lr_cost & 0x7F);
    payload
}

/// Build the path request extension payload: marker, flags, stamp.
pub fn path_request_ext_payload(stamp: &[u8], flags: u8) -> Vec<u8> {
    let mut payload = Vec::with_capacity(constants::PR_EXT_PAYLOAD_LENGTH);
    payload.push(constants::EXT_PAYLOAD_MARKER);
    payload.push(flags);
    payload.extend_from_slice(stamp);
    payload
}

/// Generate an internally stamped X25519 keypair.
///
/// Returns `(private_key, public_key, value)`. The public key itself is the
/// stamp, validated as `stamp_valid(public_key, cost, material)`.
pub fn generate_stamped_key(material: &[u8], stamp_cost: u8) -> Option<(Vec<u8>, Vec<u8>, u32)> {
    use rns_crypto::OsRng;

    if stamp_cost > constants::STAMP_COST_CAP {
        return None;
    }
    let mut rng = OsRng;
    let (private, public, value) =
        rns_crypto::identity::generate_stamped_key(&mut rng, material, stamp_cost);
    Some((
        private.private_bytes().to_vec(),
        public.public_bytes().to_vec(),
        value,
    ))
}

/// Generate a detached stamp with the given cost using rayon workers.
///
/// Returns `(stamp, value)`, or `None` when the cost is above the protocol cap.
pub fn generate_stamp(
    material: &[u8],
    stamp_cost: u8,
    size: usize,
    expand_rounds: u32,
) -> Option<(Vec<u8>, u32)> {
    use rns_crypto::{OsRng, Rng};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    if stamp_cost > constants::STAMP_COST_CAP || size == 0 {
        return None;
    }

    let workblock = stamp_workblock(material, expand_rounds);
    let found = Arc::new(AtomicBool::new(false));
    let result: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));

    rayon::scope(|scope| {
        for _ in 0..rayon::current_num_threads() {
            let found = Arc::clone(&found);
            let result = Arc::clone(&result);
            let workblock = &workblock;
            scope.spawn(move |_| {
                let mut rng = OsRng;
                let mut nonce = vec![0u8; size];
                loop {
                    if found.load(Ordering::Relaxed) {
                        return;
                    }
                    rng.fill_bytes(&mut nonce);
                    if stamp_valid(&nonce, stamp_cost, workblock) {
                        let mut slot = result
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        if slot.is_none() {
                            *slot = Some(nonce.clone());
                        }
                        found.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            });
        }
    });

    let stamp = result
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()?;
    let value = stamp_value(&workblock, &stamp);
    Some((stamp, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_stamp_material_matches_upstream_layout() {
        let material = destination_stamp_material(&[0x11; 16], &[0x22; 64], &[0x33; 10]);
        assert_eq!(material.len(), 90);
        assert_eq!(&material[..16], &[0x11; 16]);
        assert_eq!(&material[16..80], &[0x22; 64]);
        assert_eq!(&material[80..], &[0x33; 10]);
    }

    #[test]
    fn generated_destination_stamp_validates_and_roundtrips() {
        let material = b"destination stamp test material";
        let (stamp, value) = generate_stamp(material, 8, constants::STAMP_LENGTH, 0).unwrap();
        assert_eq!(stamp.len(), constants::STAMP_LENGTH);
        let workblock = stamp_workblock(material, 0);
        assert!(stamp_valid(&stamp, 8, &workblock));
        assert!(value >= 8);

        let dir =
            std::env::temp_dir().join(format!("rns-dstamp-test-{}-{}", std::process::id(), value));
        let store = DestinationStampStore::new(&dir);
        store.store(&[0x44; 16], &stamp, value).unwrap();
        let loaded = store.load(&[0x44; 16], material, 8).unwrap();
        assert_eq!(loaded.0, stamp);
        assert_eq!(loaded.1, value);
        assert!(store.load(&[0x44; 16], material, 200).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn stamped_key_public_half_validates_against_material() {
        let material = b"identity stamp material";
        let (private, public, value) = generate_stamped_key(material, 4).unwrap();
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 32);
        assert!(value >= 4);
        assert!(stamp_valid(&public, 4, material));
    }

    #[test]
    fn announce_ext_payload_has_marker_flags_stamp_and_link_cost() {
        let payload = announce_ext_payload(&[0x55; constants::STAMP_LENGTH], 0, 19);
        assert_eq!(payload.len(), constants::EXT_PAYLOAD_LENGTH);
        assert_eq!(payload[0], constants::EXT_PAYLOAD_MARKER);
        assert_eq!(payload[1], 0);
        assert_eq!(
            &payload[2..2 + constants::STAMP_LENGTH],
            &[0x55; constants::STAMP_LENGTH]
        );
        assert_eq!(payload[constants::EXT_PAYLOAD_LENGTH - 1], 19);
    }

    #[test]
    fn path_request_ext_payload_has_marker_flags_and_stamp() {
        let payload = path_request_ext_payload(&[0x55; constants::STAMP_LENGTH], 0);
        assert_eq!(payload.len(), constants::PR_EXT_PAYLOAD_LENGTH);
        assert_eq!(payload[0], constants::EXT_PAYLOAD_MARKER);
        assert_eq!(payload[1], 0);
        assert_eq!(&payload[2..], &[0x55; constants::STAMP_LENGTH]);
    }
}
