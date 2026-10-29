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

/// Per-destination link request costs and the responder enforcement flag.
///
/// Mirrors `Destination.link_cost` (set with `set_link_cost`, read with
/// `get_link_cost`), the `Transport.LR_COST` default behind it (`[stamps]
/// lr_cost`) and `Transport.LR_STAMPS_ENFORCED`. The handle is shared between
/// the node API, the announce builder and the link manager, so the cost a
/// destination announces is the cost its responder requires.
#[derive(Debug, Clone, Default)]
pub struct LinkRequestCosts {
    inner: std::sync::Arc<LinkRequestCostsInner>,
}

#[derive(Debug)]
struct LinkRequestCostsInner {
    costs: std::sync::Mutex<std::collections::HashMap<[u8; 16], u8>>,
    default_cost: std::sync::atomic::AtomicU8,
    enforced: std::sync::atomic::AtomicBool,
}

impl Default for LinkRequestCostsInner {
    fn default() -> Self {
        Self {
            costs: Default::default(),
            default_cost: std::sync::atomic::AtomicU8::new(constants::LINK_REQUEST_STAMP_COST),
            enforced: std::sync::atomic::AtomicBool::new(constants::LR_STAMPS_ENFORCED),
        }
    }
}

impl LinkRequestCosts {
    /// `Destination.set_link_cost`: store the clamped cost and return it.
    pub fn set(&self, destination_hash: [u8; 16], cost: i64) -> u8 {
        let cost = rns_core::stamp::clamp_link_cost(cost);
        self.inner
            .costs
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(destination_hash, cost);
        cost
    }

    /// `Destination.get_link_cost`: the announced and required cost.
    pub fn get(&self, destination_hash: &[u8; 16]) -> u8 {
        let configured = self
            .inner
            .costs
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(destination_hash)
            .copied();
        rns_core::stamp::announced_link_cost(configured, self.default_cost())
    }

    /// `Transport.LR_COST`: the cost of destinations that set none.
    pub fn default_cost(&self) -> u8 {
        self.inner
            .default_cost
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Apply `[stamps] lr_cost`, already clamped by the config parser.
    pub fn set_default_cost(&self, cost: u8) {
        self.inner
            .default_cost
            .store(cost, std::sync::atomic::Ordering::Relaxed);
    }

    /// Forget the configured cost, reverting to the default.
    pub fn remove(&self, destination_hash: &[u8; 16]) {
        self.inner
            .costs
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(destination_hash);
    }

    /// `Transport.LR_STAMPS_ENFORCED`.
    pub fn enforced(&self) -> bool {
        self.inner
            .enforced
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Override `Transport.LR_STAMPS_ENFORCED`.
    pub fn set_enforced(&self, enforced: bool) {
        self.inner
            .enforced
            .store(enforced, std::sync::atomic::Ordering::Relaxed);
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

/// Material covered by a link request stamp: `destination_hash || ed25519_pub`.
pub fn link_request_stamp_material(
    destination_hash: &[u8; 16],
    sig_pub_bytes: &[u8; 32],
) -> [u8; 48] {
    let mut material = [0u8; 48];
    material[..16].copy_from_slice(destination_hash);
    material[16..].copy_from_slice(sig_pub_bytes);
    material
}

/// Generate the keys for a stamped link request to `destination_hash`.
///
/// The Ed25519 signing key is generated first because it is part of the stamp
/// material; the X25519 key is then ground until its public half carries at
/// least `stamp_cost`. Gives up and returns `None` once `deadline` passes,
/// mirroring upstream's `LINK_STAMP_TIMEOUT` watchdog. This is unbounded
/// work and must not run on the driver thread.
pub fn generate_stamped_link_keys(
    destination_hash: &[u8; 16],
    stamp_cost: u8,
    deadline: std::time::Instant,
) -> Option<(
    rns_crypto::x25519::X25519PrivateKey,
    rns_crypto::ed25519::Ed25519PrivateKey,
    u32,
)> {
    use rns_crypto::OsRng;

    if stamp_cost > constants::STAMP_COST_CAP {
        return None;
    }
    let mut rng = OsRng;
    let sig_prv = rns_crypto::ed25519::Ed25519PrivateKey::generate(&mut rng);
    let material =
        link_request_stamp_material(destination_hash, &sig_prv.public_key().public_bytes());
    let (prv, _public, value) = rns_crypto::identity::generate_stamped_key_until(
        &mut rng,
        &material,
        stamp_cost,
        &mut || std::time::Instant::now() >= deadline,
    )?;
    Some((prv, sig_prv, value))
}

/// Generate a detached stamp with the given cost using rayon workers.
///
/// This is the native counterpart of every upstream `Stamps` job runner
/// (`job_simple`, `job_linux`, `job_linux_managed`, `job_android` and the
/// persistent Android runner added in `4867e889`): those pick a worker
/// strategy per platform because of Python's process model, whereas the
/// rayon pool covers all targets here. The stamp format and the value
/// computation are identical.
///
/// Returns `(stamp, value)`, or `None` when the cost is above the protocol cap.
pub fn generate_stamp(
    material: &[u8],
    stamp_cost: u8,
    size: usize,
    expand_rounds: u32,
) -> Option<(Vec<u8>, u32)> {
    generate_stamp_until(material, stamp_cost, size, expand_rounds, None)
}

/// How many candidate nonces a worker tries between deadline checks.
const DEADLINE_CHECK_INTERVAL: u32 = 1024;

/// How many nonces a worker draws from the OS per `fill_bytes` call.
const NONCES_PER_FILL: usize = 256;

/// As [`generate_stamp`], giving up once `deadline` passes.
///
/// This is upstream's `cancel_work` on a stamp job (`RNS/Stamps.py`), which
/// the path request watchdog in `Transport.stamp_path_request` calls after
/// `PR_STAMP_TIMEOUT` (Transport.py:3977-3986, d7749b0b). Returns `None`
/// when cancelled, as the cancelled upstream job yields no stamp.
pub fn generate_stamp_until(
    material: &[u8],
    stamp_cost: u8,
    size: usize,
    expand_rounds: u32,
    deadline: Option<std::time::Instant>,
) -> Option<(Vec<u8>, u32)> {
    use rns_crypto::{OsRng, Rng};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    if stamp_cost > constants::STAMP_COST_CAP || size == 0 {
        return None;
    }
    if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
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
                // Draw OS randomness in batches: one getrandom(2) call per
                // attempt dominated the grind, well ahead of the hash.
                let mut pool = vec![0u8; size * NONCES_PER_FILL];
                let mut next_nonce = pool.len();
                let mut nonce = vec![0u8; size];
                let mut until_check = DEADLINE_CHECK_INTERVAL;
                loop {
                    if found.load(Ordering::Relaxed) {
                        return;
                    }
                    if let Some(deadline) = deadline {
                        until_check -= 1;
                        if until_check == 0 {
                            until_check = DEADLINE_CHECK_INTERVAL;
                            if std::time::Instant::now() >= deadline {
                                // Stop the other workers too; no stamp was found.
                                found.store(true, Ordering::Relaxed);
                                return;
                            }
                        }
                    }
                    if next_nonce + size > pool.len() {
                        rng.fill_bytes(&mut pool);
                        next_nonce = 0;
                    }
                    nonce.copy_from_slice(&pool[next_nonce..next_nonce + size]);
                    next_nonce += size;
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
    fn stamp_generation_gives_up_at_the_deadline() {
        use std::time::{Duration, Instant};
        // A cost at the protocol cap is never found in time.
        let started = Instant::now();
        let deadline = started + Duration::from_millis(50);
        assert_eq!(
            generate_stamp_until(
                b"material",
                constants::STAMP_COST_CAP,
                14,
                0,
                Some(deadline)
            ),
            None
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        // An expired deadline does no work at all.
        assert_eq!(
            generate_stamp_until(b"material", 0, 14, 0, Some(Instant::now())),
            None
        );
        // A reachable cost before the deadline yields a valid stamp.
        let (stamp, value) = generate_stamp_until(
            b"material",
            4,
            14,
            0,
            Some(Instant::now() + Duration::from_secs(60)),
        )
        .expect("cost 4 is found quickly");
        assert!(value >= 4);
        assert!(stamp_valid(&stamp, 4, &stamp_workblock(b"material", 0)));
    }

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
    fn stamped_link_keys_meet_cost_and_bind_destination() {
        let dest_hash = [0x5A; 16];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let (prv, sig_prv, value) = generate_stamped_link_keys(&dest_hash, 4, deadline).unwrap();
        let material =
            link_request_stamp_material(&dest_hash, &sig_prv.public_key().public_bytes());
        let recomputed =
            rns_crypto::identity::stamp_value(&material, &prv.public_key().public_bytes());
        assert_eq!(recomputed, value);
        assert!(value >= 4);
    }

    #[test]
    fn stamped_link_keys_give_up_at_deadline() {
        let deadline = std::time::Instant::now();
        let started = std::time::Instant::now();
        assert!(generate_stamped_link_keys(&[0x5B; 16], 100, deadline).is_none());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn stamped_link_keys_honour_a_future_deadline() {
        // Cost 100 is unattainable, so the only way out is the deadline.
        let timeout = std::time::Duration::from_millis(200);
        let started = std::time::Instant::now();
        let result = generate_stamped_link_keys(&[0x5B; 16], 100, started + timeout);
        assert!(result.is_none());
        assert!(started.elapsed() >= timeout);
        assert!(started.elapsed() < timeout + std::time::Duration::from_secs(2));
    }

    #[test]
    fn stamped_link_keys_reject_cost_above_protocol_cap() {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let started = std::time::Instant::now();
        assert!(
            generate_stamped_link_keys(&[0x5C; 16], constants::STAMP_COST_CAP + 1, deadline)
                .is_none()
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn stamped_link_keys_are_fresh_per_call() {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let (prv_a, sig_a, _) = generate_stamped_link_keys(&[0x5D; 16], 1, deadline).unwrap();
        let (prv_b, sig_b, _) = generate_stamped_link_keys(&[0x5D; 16], 1, deadline).unwrap();
        assert_ne!(prv_a.private_bytes(), prv_b.private_bytes());
        assert_ne!(sig_a.private_bytes(), sig_b.private_bytes());
    }

    #[test]
    fn link_request_stamp_material_is_destination_then_signing_key() {
        let material = link_request_stamp_material(&[0x11; 16], &[0x22; 32]);
        assert_eq!(&material[..16], &[0x11; 16]);
        assert_eq!(&material[16..], &[0x22; 32]);
        // Must agree with the responder-side parser in rns-core.
        let dest_hash = [0x5E; 16];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let (prv, sig_prv, value) = generate_stamped_link_keys(&dest_hash, 3, deadline).unwrap();
        let mut request = Vec::with_capacity(64);
        request.extend_from_slice(&prv.public_key().public_bytes());
        request.extend_from_slice(&sig_prv.public_key().public_bytes());
        assert_eq!(
            rns_core::link::handshake::link_request_stamp_value(&dest_hash, &request),
            Some(value)
        );
    }

    #[test]
    fn link_request_costs_default_clamp_and_share() {
        let costs = LinkRequestCosts::default();
        let other = costs.clone();
        let dest = [0x42; 16];
        assert_eq!(costs.get(&dest), constants::LINK_REQUEST_STAMP_COST);
        assert_eq!(costs.enforced(), constants::LR_STAMPS_ENFORCED);
        assert_eq!(costs.set(dest, 99), constants::LINK_COST_CAP);
        assert_eq!(other.get(&dest), constants::LINK_COST_CAP);
        assert_eq!(costs.set(dest, -1), 0);
        assert_eq!(other.get(&dest), 0);
        costs.remove(&dest);
        assert_eq!(other.get(&dest), constants::LINK_REQUEST_STAMP_COST);
        other.set_enforced(true);
        assert!(costs.enforced());
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
