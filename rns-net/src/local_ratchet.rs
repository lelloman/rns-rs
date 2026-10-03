//! Application-owned destination ratchets, separate from received public keys.
//!
//! Use one owner per destination and share its `Arc` with the node and receiver.
//! Files are compatible with Python's signed ratchet list. Additional signed
//! destination binding is checked when present; legacy imports must be assigned
//! to the correct destination by the caller. Keys are not encrypted at rest.
use rns_core::{
    msgpack::{self, Value},
    types::Direction,
};
use rns_crypto::{
    identity::Identity,
    ratchet::{Decrypted, RatchetRing, DEFAULT_INTERVAL, DEFAULT_RETAINED, MAX_RETAINED},
    OsRng,
};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

pub(crate) type Registry = Arc<Mutex<HashMap<[u8; 16], Arc<LocalRatchets>>>>;

/// Implementations must atomically replace a complete signed snapshot. An error
/// leaves the owner blocked until recovery or reopening succeeds. Assign a store
/// exclusively to one owner; share that owner's Arc for concurrent users.
pub trait LocalRatchetStore: Send + Sync {
    fn load(&self) -> io::Result<Option<Vec<u8>>>;
    fn save(&self, data: &[u8]) -> io::Result<()>;
}

/// Explicitly volatile storage, useful in tests and applications that accept key
/// loss on restart. Never selected implicitly by the persistent constructor.
#[derive(Default)]
pub struct MemoryRatchetStore(Mutex<Option<Zeroizing<Vec<u8>>>>);
impl LocalRatchetStore for MemoryRatchetStore {
    fn load(&self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().as_ref().map(|v| v.to_vec()))
    }
    fn save(&self, data: &[u8]) -> io::Result<()> {
        *self.0.lock().unwrap() = Some(Zeroizing::new(data.to_vec()));
        Ok(())
    }
}

/// A single-writer private-key file, with a stable advisory lock on Unix.
/// All writers must honor this contract, including when migrating Python files.
pub struct FileRatchetStore {
    path: PathBuf,
    _lock: File,
}
impl FileRatchetStore {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        // Sync new directory entries too: syncing only the key file's parent
        // would not make a newly created application-state tree durable.
        let mut missing = Vec::new();
        let mut ancestor = parent;
        while !ancestor.is_dir() {
            missing.push(ancestor.to_path_buf());
            ancestor = ancestor
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
        }
        fs::create_dir_all(parent)?;
        if !missing.is_empty() {
            for directory in &missing {
                File::open(directory)?.sync_all()?;
            }
            File::open(ancestor)?.sync_all()?;
        }
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let lock = private_options()
            .create(true)
            .truncate(false)
            .open(PathBuf::from(lock_path))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "ratchet file already owned",
                ));
            }
        }
        #[cfg(not(unix))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private ratchet file locking requires Unix; supply a store",
        ));
        #[allow(unreachable_code)]
        Ok(Self { path, _lock: lock })
    }
}
fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options
}
const MAX_FILE: u64 = (MAX_RETAINED * 34 + 1024) as u64;
impl LocalRatchetStore for FileRatchetStore {
    fn load(&self) -> io::Result<Option<Vec<u8>>> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let file = match options.open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut data = Zeroizing::new(Vec::new());
        file.take(MAX_FILE + 1).read_to_end(&mut data)?;
        if data.len() as u64 > MAX_FILE {
            return Err(invalid("ratchet file too large"));
        }
        Ok(Some(std::mem::take(&mut *data)))
    }
    fn save(&self, data: &[u8]) -> io::Result<()> {
        let mut temporary = self.path.as_os_str().to_os_string();
        temporary.push(".tmp");
        let temporary = PathBuf::from(temporary);
        // The lock excludes our other writers. Remove crash residue without
        // following it; create_new also refuses pre-existing symlinks.
        match fs::remove_file(&temporary) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        let mut file = private_options().create_new(true).open(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&temporary, &self.path)?;
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct State {
    ring: RatchetRing,
    interval: u64,
    retained: usize,
    enforce: bool,
    blocked: bool,
    pins: HashMap<[u8; 32], usize>,
}
/// Shared secret owner. Debug deliberately omits identity and private history.
pub struct LocalRatchets {
    destination: [u8; 16],
    identity: Identity,
    store: Arc<dyn LocalRatchetStore>,
    state: Mutex<State>,
}
impl std::fmt::Debug for LocalRatchets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalRatchets")
            .field("destination", &self.destination)
            .finish_non_exhaustive()
    }
}
impl LocalRatchets {
    pub fn persistent(
        destination: &crate::Destination,
        identity: Identity,
        path: impl AsRef<Path>,
    ) -> io::Result<Arc<Self>> {
        Self::with_store(
            destination,
            identity,
            Arc::new(FileRatchetStore::open(path)?),
        )
    }
    pub fn with_store(
        destination: &crate::Destination,
        identity: Identity,
        store: Arc<dyn LocalRatchetStore>,
    ) -> io::Result<Arc<Self>> {
        if destination.direction != Direction::In
            || destination.dest_type != rns_core::types::DestinationType::Single
            || destination.identity_hash.map(|h| h.0) != Some(*identity.hash())
            || identity.get_private_key().is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ratchets require an IN SINGLE destination and its private identity",
            ));
        }
        let expected = rns_core::destination::destination_hash(
            &destination.app_name,
            &destination
                .aspects
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            Some(identity.hash()),
        );
        if expected != destination.hash.0 {
            return Err(invalid("destination hash mismatch"));
        }
        let ring = match store.load()? {
            Some(bytes) => decode(&Zeroizing::new(bytes), &identity, &destination.hash.0)?,
            None => RatchetRing::new(),
        };
        let owner = Arc::new(Self {
            destination: destination.hash.0,
            identity,
            store,
            state: Mutex::new(State {
                ring,
                interval: DEFAULT_INTERVAL,
                retained: DEFAULT_RETAINED,
                enforce: false,
                blocked: false,
                pins: HashMap::new(),
            }),
        });
        // Also commits binding for legacy files. Never discard imported history
        // before the first rotation; that allows decryption immediately on load.
        {
            let state = owner.state.lock().unwrap();
            owner
                .store
                .save(&encode(&state.ring, &owner.identity, &owner.destination)?)?;
        }
        Ok(owner)
    }
    pub fn destination_hash(&self) -> [u8; 16] {
        self.destination
    }
    pub fn identity_hash(&self) -> [u8; 16] {
        *self.identity.hash()
    }
    pub fn set_interval(&self, seconds: u64) -> io::Result<()> {
        if seconds == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interval must be positive",
            ));
        }
        self.state.lock().unwrap().interval = seconds;
        Ok(())
    }
    pub fn set_retained(&self, count: usize) -> io::Result<()> {
        if !(1..=MAX_RETAINED).contains(&count) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "retention must be 1..=4096",
            ));
        }
        let mut state = self.state.lock().unwrap();
        let mut next = state.ring.clone();
        next.prune(count);
        self.commit(&mut state, next)?;
        state.retained = count;
        Ok(())
    }
    /// Reconcile storage after an I/O failure without clearing enforcement or
    /// swapping the owner attached to a running node. Missing/corrupt files fail.
    pub fn recover(&self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        state.blocked = true;
        let bytes = Zeroizing::new(
            self.store
                .load()?
                .ok_or_else(|| invalid("missing private ratchet history"))?,
        );
        let ring = decode(&bytes, &self.identity, &self.destination)?;
        if state.pins.keys().any(|key| !ring.retains(key)) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "recovery waits for queued announcements",
            ));
        }
        // Recommit to establish durability after an ambiguous rename/sync error.
        self.store
            .save(&encode(&ring, &self.identity, &self.destination)?)?;
        state.ring = ring;
        state.blocked = false;
        Ok(())
    }
    pub fn enforce(&self) {
        self.state.lock().unwrap().enforce = true;
    }
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
    ) -> Result<Decrypted, rns_crypto::identity::CryptoError> {
        let state = self.state.lock().unwrap();
        self.identity
            .decrypt_with_ratchets(ciphertext, &state.ring, state.enforce)
    }
    /// Generates and commits a key if due. Restart rotates on the first call;
    /// clock rollback postpones rotation until the previous interval elapses.
    pub fn public_for_announce(&self, now: u64) -> io::Result<[u8; 32]> {
        let mut state = self.state.lock().unwrap();
        if state.blocked {
            return Err(invalid(
                "ratchet storage failed; recover or reopen owner before announcing",
            ));
        }
        if let Some(next) = state
            .ring
            .rotated(now, state.interval, state.retained, &mut OsRng)
        {
            self.commit(&mut state, next)?;
        }
        state
            .ring
            .current_public()
            .ok_or_else(|| invalid("missing ratchet"))
    }
    pub fn current_public(&self) -> Option<[u8; 32]> {
        self.state.lock().unwrap().ring.current_public()
    }
    pub fn retains(&self, public: &[u8; 32]) -> bool {
        self.state.lock().unwrap().ring.retains(public)
    }
    fn commit(&self, state: &mut State, next: RatchetRing) -> io::Result<()> {
        if state.blocked {
            return Err(invalid("ratchet storage failed; recover or reopen owner"));
        }
        if state.pins.keys().any(|key| !next.retains(key)) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "ratchet retirement waits for queued announcements",
            ));
        }
        if let Err(error) = self
            .store
            .save(&encode(&next, &self.identity, &self.destination)?)
        {
            state.blocked = true;
            return Err(error);
        }
        state.ring = next;
        Ok(())
    }
}

fn encode(
    ring: &RatchetRing,
    identity: &Identity,
    destination: &[u8; 16],
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut values = Value::Array(ring.keys().iter().map(|k| Value::Bin(k.to_vec())).collect());
    let packed = Zeroizing::new(msgpack::pack(&values));
    wipe(&mut values);
    let signature = identity
        .sign(&packed)
        .map_err(|_| invalid("missing signing key"))?;
    let mut binding = Zeroizing::new(destination.to_vec());
    binding.extend_from_slice(&packed);
    let bound_signature = identity
        .sign(&binding)
        .map_err(|_| invalid("missing signing key"))?;
    let mut record = Value::Map(vec![
        (
            Value::Str("signature".into()),
            Value::Bin(signature.to_vec()),
        ),
        (Value::Str("ratchets".into()), Value::Bin(packed.to_vec())),
        (
            Value::Str("destination".into()),
            Value::Bin(destination.to_vec()),
        ),
        (
            Value::Str("binding".into()),
            Value::Bin(bound_signature.to_vec()),
        ),
    ]);
    let encoded = Zeroizing::new(msgpack::pack(&record));
    wipe(&mut record);
    Ok(encoded)
}
fn wipe(value: &mut Value) {
    use zeroize::Zeroize;
    match value {
        Value::Bin(bytes) => bytes.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Map(items) => items.iter_mut().for_each(|(_, value)| wipe(value)),
        _ => (),
    }
}

// Parse only the flat signed-file grammar, bounding lengths before allocation.
// Using the general MessagePack tree decoder here would accept recursive input.
struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> io::Result<&'a [u8]> {
        if count > self.0.len() {
            return Err(invalid("truncated ratchet file"));
        }
        let (v, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(v)
    }
    fn byte(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn number(&mut self, bytes: usize) -> io::Result<usize> {
        Ok(self
            .take(bytes)?
            .iter()
            .fold(0, |n, b| (n << 8) | *b as usize))
    }
    fn bin(&mut self) -> io::Result<&'a [u8]> {
        let n = match self.byte()? {
            0xc4 => self.number(1)?,
            0xc5 => self.number(2)?,
            0xc6 => self.number(4)?,
            _ => return Err(invalid("expected binary")),
        };
        self.take(n)
    }
    fn string(&mut self) -> io::Result<&'a [u8]> {
        let n = match self.byte()? {
            t @ 0xa0..=0xbf => (t & 31) as usize,
            0xd9 => self.number(1)?,
            _ => return Err(invalid("expected field name")),
        };
        self.take(n)
    }
}
fn decode(bytes: &[u8], identity: &Identity, destination: &[u8; 16]) -> io::Result<RatchetRing> {
    if bytes.len() as u64 > MAX_FILE {
        return Err(invalid("ratchet file too large"));
    }
    let mut cursor = Cursor(bytes);
    let count = match cursor.byte()? {
        t @ 0x80..=0x8f => (t & 15) as usize,
        0xde => cursor.number(2)?,
        _ => return Err(invalid("expected ratchet map")),
    };
    if count != 2 && count != 4 {
        return Err(invalid("unexpected ratchet fields"));
    }
    let mut fields = HashMap::new();
    for _ in 0..count {
        let name = cursor.string()?;
        let value = cursor.bin()?;
        if fields.insert(name, value).is_some() {
            return Err(invalid("duplicate field"));
        }
    }
    if !cursor.0.is_empty() {
        return Err(invalid("trailing bytes"));
    }
    let packed = *fields
        .get(b"ratchets".as_slice())
        .ok_or_else(|| invalid("missing ratchets"))?;
    let signature: [u8; 64] = fields
        .get(b"signature".as_slice())
        .copied()
        .ok_or_else(|| invalid("missing signature"))?
        .try_into()
        .map_err(|_| invalid("signature length"))?;
    if !identity.verify(&signature, packed) {
        return Err(invalid("invalid ratchet signature"));
    }
    if count == 4 {
        if fields.get(b"destination".as_slice()).copied() != Some(destination.as_slice()) {
            return Err(invalid("ratchet destination mismatch"));
        }
        let signature: [u8; 64] = fields
            .get(b"binding".as_slice())
            .copied()
            .ok_or_else(|| invalid("missing binding"))?
            .try_into()
            .map_err(|_| invalid("binding length"))?;
        let mut bound = Zeroizing::new(destination.to_vec());
        bound.extend_from_slice(packed);
        if !identity.verify(&signature, &bound) {
            return Err(invalid("invalid destination binding"));
        }
    }
    let mut cursor = Cursor(packed);
    let count = match cursor.byte()? {
        t @ 0x90..=0x9f => (t & 15) as usize,
        0xdc => cursor.number(2)?,
        0xdd => cursor.number(4)?,
        _ => return Err(invalid("expected key array")),
    };
    if count > MAX_RETAINED {
        return Err(invalid("too many retained keys"));
    }
    let mut keys = Zeroizing::new(Vec::with_capacity(count));
    for _ in 0..count {
        keys.push(
            cursor
                .bin()?
                .try_into()
                .map_err(|_| invalid("ratchet key length"))?,
        );
    }
    if !cursor.0.is_empty() {
        return Err(invalid("trailing key data"));
    }
    RatchetRing::from_keys(std::mem::take(&mut *keys)).ok_or_else(|| invalid("too many keys"))
}

/// Keeps an advertised key retained until a queued frame reaches its writer.
#[derive(Clone)]
pub(crate) struct AnnouncementLease {
    _inner: Arc<LeaseInner>,
}
struct LeaseInner {
    owner: Arc<LocalRatchets>,
    public: [u8; 32],
}
impl Drop for LeaseInner {
    fn drop(&mut self) {
        let mut state = self.owner.state.lock().unwrap();
        if let Some(count) = state.pins.get_mut(&self.public) {
            *count -= 1;
            if *count == 0 {
                state.pins.remove(&self.public);
            }
        }
    }
}
impl AnnouncementLease {
    pub(crate) fn acquire(registry: &Registry, raw: &[u8]) -> io::Result<Option<Self>> {
        use rns_core::{
            constants::{FLAG_SET, PACKET_TYPE_ANNOUNCE},
            packet::RawPacket,
        };
        if raw
            .first()
            .is_none_or(|flags| flags & 3 != PACKET_TYPE_ANNOUNCE)
        {
            return Ok(None);
        }
        let packet = match RawPacket::unpack(raw) {
            Ok(p) if p.flags.packet_type == PACKET_TYPE_ANNOUNCE => p,
            _ => return Ok(None),
        };
        let owner = registry
            .lock()
            .unwrap()
            .get(&packet.destination_hash)
            .cloned();
        let Some(owner) = owner else {
            return Ok(None);
        };
        let announce = rns_core::announce::AnnounceData::unpack(
            &packet.data,
            packet.flags.context_flag == FLAG_SET,
        )
        .map_err(|_| invalid("invalid local announce"))?;
        let public = announce
            .ratchet
            .ok_or_else(|| invalid("local ratchet announce cannot downgrade"))?;
        {
            let mut state = owner.state.lock().unwrap();
            if state.blocked || !state.ring.retains(&public) {
                return Err(invalid("stale or blocked local ratchet announce"));
            }
            *state.pins.entry(public).or_default() += 1;
        }
        Ok(Some(Self {
            _inner: Arc::new(LeaseInner { owner, public }),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    fn fixture(aspect: &str) -> (crate::Destination, Identity) {
        let identity = Identity::from_private_key(&[31; 64]);
        (
            crate::Destination::single_in(
                "test",
                &[aspect],
                rns_core::types::IdentityHash(*identity.hash()),
            ),
            identity,
        )
    }
    #[test]
    fn concurrent_announces_and_same_identity_destinations_are_isolated() {
        let (destination, identity) = fixture("first");
        let owner = LocalRatchets::with_store(
            &destination,
            identity,
            Arc::new(MemoryRatchetStore::default()),
        )
        .unwrap();
        assert!(owner.set_interval(0).is_err());
        assert!(owner.set_retained(0).is_err());
        assert!(owner.set_retained(MAX_RETAINED + 1).is_err());
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let owner = owner.clone();
                std::thread::spawn(move || owner.public_for_announce(100).unwrap())
            })
            .collect();
        let keys: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(keys.iter().all(|key| key == &keys[0]));
        let (other_destination, identity) = fixture("second");
        let other = LocalRatchets::with_store(
            &other_destination,
            identity,
            Arc::new(MemoryRatchetStore::default()),
        )
        .unwrap();
        other.enforce();
        other.public_for_announce(100).unwrap();
        let ciphertext = Identity::from_private_key(&[31; 64])
            .encrypt_with_ratchet(b"private", Some(&keys[0]), &mut OsRng)
            .unwrap();
        assert_eq!(owner.decrypt(&ciphertext).unwrap().plaintext, b"private");
        assert!(other.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn corrupt_recovery_blocks_announcing_without_clearing_enforcement() {
        let (dest, identity) = fixture("recover");
        let store = Arc::new(MemoryRatchetStore::default());
        let owner = LocalRatchets::with_store(&dest, identity, store.clone()).unwrap();
        owner.enforce();
        owner.public_for_announce(100).unwrap();
        let good = store.load().unwrap().unwrap();
        store.save(b"corrupt").unwrap();
        assert!(owner.recover().is_err());
        assert!(owner.public_for_announce(100).is_err());
        let legacy = Identity::from_private_key(&[31; 64])
            .encrypt(b"legacy", &mut OsRng)
            .unwrap();
        assert!(owner.decrypt(&legacy).is_err());
        store.save(&good).unwrap();
        owner.recover().unwrap();
        assert!(owner.public_for_announce(101).is_ok());
        assert!(owner.decrypt(&legacy).is_err());
    }

    #[test]
    fn persistent_restart_retention_binding_and_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("new/app/private");
        let (dest, identity) = fixture("ratchet");
        let owner = LocalRatchets::persistent(&dest, identity, &path).unwrap();
        owner.set_interval(1).unwrap();
        owner.set_retained(2).unwrap();
        owner.enforce();
        let first = owner.public_for_announce(100).unwrap();
        let cipher = Identity::from_private_key(&[31; 64])
            .encrypt_with_ratchet(b"delayed", Some(&first), &mut OsRng)
            .unwrap();
        assert_eq!(owner.public_for_announce(101).unwrap(), first);
        assert_ne!(owner.public_for_announce(102).unwrap(), first);
        assert_eq!(owner.decrypt(&cipher).unwrap().plaintext, b"delayed");
        assert!(FileRatchetStore::open(&path).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(owner);
        let (_, identity) = fixture("ratchet");
        let reopened = LocalRatchets::persistent(&dest, identity, &path).unwrap();
        reopened.enforce();
        assert_eq!(reopened.decrypt(&cipher).unwrap().plaintext, b"delayed");
        reopened.set_retained(2).unwrap();
        reopened.public_for_announce(103).unwrap();
        assert!(reopened.decrypt(&cipher).is_err());
        drop(reopened);
        let original = fs::read(&path).unwrap();
        let (other, identity) = fixture("other");
        assert!(LocalRatchets::persistent(&other, identity, &path).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        fs::write(&path, b"broken").unwrap();
        let (_, identity) = fixture("ratchet");
        assert!(LocalRatchets::persistent(&dest, identity, &path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"broken");
    }
    struct FailingStore {
        memory: MemoryRatchetStore,
        fail: AtomicBool,
        after_write: bool,
    }
    impl LocalRatchetStore for FailingStore {
        fn load(&self) -> io::Result<Option<Vec<u8>>> {
            self.memory.load()
        }
        fn save(&self, bytes: &[u8]) -> io::Result<()> {
            let failed = self.fail.load(Ordering::Relaxed);
            if !failed || self.after_write {
                self.memory.save(bytes)?;
            }
            if failed {
                Err(io::Error::other("injected persistence failure"))
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn failed_commit_never_advertises_or_downgrades() {
        for after_write in [false, true] {
            let store = Arc::new(FailingStore {
                memory: Default::default(),
                fail: AtomicBool::new(false),
                after_write,
            });
            let (dest, identity) = fixture("failure");
            let owner = LocalRatchets::with_store(&dest, identity, store.clone()).unwrap();
            owner.set_interval(1).unwrap();
            owner.enforce();
            let public = owner.public_for_announce(100).unwrap();
            let identity = Identity::from_private_key(&[31; 64]);
            let ciphertext = identity
                .encrypt_with_ratchet(b"before failure", Some(&public), &mut OsRng)
                .unwrap();
            store.fail.store(true, Ordering::Relaxed);
            assert!(owner.public_for_announce(102).is_err());
            assert!(owner.public_for_announce(100).is_err());
            assert_eq!(
                owner.decrypt(&ciphertext).unwrap().plaintext,
                b"before failure"
            );
            assert!(owner
                .decrypt(&identity.encrypt(b"base", &mut OsRng).unwrap())
                .is_err());
            store.fail.store(false, Ordering::Relaxed);
            assert!(owner.public_for_announce(104).is_err());
            owner.recover().unwrap();
            assert!(owner
                .decrypt(&identity.encrypt(b"base", &mut OsRng).unwrap())
                .is_err());
            drop(owner);
            let recovered = LocalRatchets::with_store(&dest, identity, store).unwrap();
            assert_eq!(
                recovered.decrypt(&ciphertext).unwrap().plaintext,
                b"before failure"
            );
            assert!(recovered.public_for_announce(104).is_ok());
        }
    }
    #[test]
    fn bounded_decoder_rejects_tampering_and_recursive_input() {
        let (destination, identity) = fixture("parser");
        let ring = RatchetRing::new().rotated(1, 1, 2, &mut OsRng).unwrap();
        let encoded = encode(&ring, &identity, &destination.hash.0).unwrap();
        assert!(decode(&encoded, &identity, &destination.hash.0).is_ok());
        for index in 0..encoded.len() {
            let mut broken = encoded.to_vec();
            broken[index] ^= 0x80;
            assert!(
                decode(&broken, &identity, &destination.hash.0).is_err(),
                "byte {index}"
            );
        }
        assert!(decode(&vec![0x91; 10000], &identity, &destination.hash.0).is_err());
    }
    #[test]
    fn queued_key_lease_defers_retirement_and_stale_announces_are_rejected() {
        let (dest, identity) = fixture("queued");
        let signer = Identity::from_private_key(&[31; 64]);
        let owner =
            LocalRatchets::with_store(&dest, identity, Arc::new(MemoryRatchetStore::default()))
                .unwrap();
        owner.set_interval(1).unwrap();
        owner.set_retained(1).unwrap();
        let public = owner.public_for_announce(100).unwrap();
        let (data, _) = rns_core::announce::AnnounceData::pack(
            &signer,
            &dest.hash.0,
            &rns_core::destination::name_hash("test", &["queued"]),
            &[0; 10],
            Some(&public),
            None,
        )
        .unwrap();
        let flags = rns_core::packet::PacketFlags {
            header_type: 0,
            context_flag: 1,
            transport_type: 0,
            destination_type: 0,
            packet_type: 1,
        };
        let packet =
            rns_core::packet::RawPacket::pack(flags, 0, &dest.hash.0, None, 0, &data).unwrap();
        let registry: Registry = Default::default();
        registry.lock().unwrap().insert(dest.hash.0, owner.clone());
        let lease = AnnouncementLease::acquire(&registry, &packet.raw)
            .unwrap()
            .unwrap();
        let clone = lease.clone();
        drop(lease);
        assert_eq!(
            owner.public_for_announce(102).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(owner.public_for_announce(100).unwrap(), public);
        drop(clone);
        assert_ne!(owner.public_for_announce(102).unwrap(), public);
        assert!(AnnouncementLease::acquire(&registry, &packet.raw).is_err());
    }
}
