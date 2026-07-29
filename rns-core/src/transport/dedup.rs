use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::MaybeUninit;

use super::types::PacketHashlistAllocation;

/// Bounded FIFO packet-hash deduplication.
///
/// Retains at most `max_size` unique packet hashes. New unique hashes are
/// appended in insertion order; when full, the oldest retained hash is evicted.
/// Re-inserting a retained hash is a no-op and does not refresh its recency.
pub struct PacketHashlist {
    queue: PacketHashQueue,
    set: PacketHashSet,
}

impl PacketHashlist {
    pub fn new(max_size: usize) -> Self {
        Self::with_allocation(max_size, PacketHashlistAllocation::Eager)
    }

    pub fn with_allocation(max_size: usize, allocation: PacketHashlistAllocation) -> Self {
        Self {
            queue: PacketHashQueue::new(max_size, allocation),
            set: PacketHashSet::new(max_size, allocation),
        }
    }

    /// Check if a hash is currently retained.
    pub fn is_duplicate(&self, hash: &[u8; 32]) -> bool {
        self.set.contains(hash)
    }

    /// Retain a hash. If the dedup table is full, evict the oldest unique hash.
    pub fn add(&mut self, hash: [u8; 32]) {
        if self.queue.capacity() == 0 || self.set.contains(&hash) {
            return;
        }

        if self.queue.len() == self.queue.capacity() {
            let Some(evicted) = self.queue.pop_front() else {
                return;
            };
            let removed = self.set.remove(&evicted);
            debug_assert!(removed, "evicted hash must exist in dedup set");
        }

        let inserted = self.set.insert(hash);
        debug_assert!(inserted, "new hash must insert into dedup set");
        self.queue.push_back(hash);
    }

    /// Total number of retained packet hashes.
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.queue.len(), self.set.len());
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate retained hashes from oldest to newest.
    pub fn iter(&self) -> impl Iterator<Item = &[u8; 32]> {
        (0..self.queue.len).map(|offset| {
            let index = (self.queue.head + offset) % self.queue.capacity();
            self.queue.entries.get(index)
        })
    }
}

/// Fixed-capacity hash payload slots whose initialization is tracked by their owner.
///
/// Queue owners may read only slots in their logical FIFO range. Set owners may
/// read only slots whose corresponding control byte is occupied. Keeping reads
/// here confines the unsafe code required for lazy payload initialization.
struct RawHashSlots {
    slots: Box<[MaybeUninit<[u8; 32]>]>,
}

impl RawHashSlots {
    fn new(capacity: usize, allocation: PacketHashlistAllocation) -> Self {
        let mut slots = Box::<[[u8; 32]]>::new_uninit_slice(capacity);
        if allocation == PacketHashlistAllocation::Eager {
            for slot in &mut slots {
                // Volatile writes make eager page prefaulting an observable side
                // effect that release-mode optimization cannot remove.
                unsafe { core::ptr::write_volatile(slot.as_mut_ptr(), [0; 32]) };
            }
        }
        Self { slots }
    }

    fn len(&self) -> usize {
        self.slots.len()
    }

    fn write(&mut self, index: usize, hash: [u8; 32]) {
        self.slots[index].write(hash);
    }

    fn read(&self, index: usize) -> [u8; 32] {
        // SAFETY: callers establish initialization through the queue's logical
        // range or the set's occupied control byte before calling this method.
        unsafe { self.slots[index].assume_init_read() }
    }

    fn get(&self, index: usize) -> &[u8; 32] {
        // SAFETY: callers establish initialization through the queue's logical
        // range or the set's occupied control byte before calling this method.
        unsafe { self.slots[index].assume_init_ref() }
    }
}

/// Bounded TTL cache for announce signature verification results.
///
/// Stores hashes of recently verified (destination_hash, signature) pairs so
/// that duplicate announces from multiple peers skip redundant Ed25519
/// verification. Entries expire after `ttl_secs` and are culled periodically.
/// When `max_entries` is 0 the cache is disabled and all methods are no-ops.
pub struct AnnounceSignatureCache {
    entries: BTreeMap<[u8; 32], f64>,
    insertion_order: Vec<[u8; 32]>,
    max_entries: usize,
    ttl_secs: f64,
}

impl AnnounceSignatureCache {
    pub fn new(max_entries: usize, ttl_secs: f64) -> Self {
        Self {
            entries: BTreeMap::new(),
            insertion_order: Vec::new(),
            max_entries,
            ttl_secs,
        }
    }

    /// Check if a cache key is present (i.e., already verified).
    pub fn contains(&self, key: &[u8; 32]) -> bool {
        if self.max_entries == 0 {
            return false;
        }
        self.entries.contains_key(key)
    }

    /// Insert a verified cache key with the current timestamp.
    pub fn insert(&mut self, key: [u8; 32], now: f64) {
        if self.max_entries == 0 {
            return;
        }
        if self.entries.contains_key(&key) {
            return;
        }
        // FIFO eviction if at capacity
        while self.entries.len() >= self.max_entries {
            if let Some(oldest) = self.insertion_order.first().copied() {
                self.entries.remove(&oldest);
                self.insertion_order.remove(0);
            } else {
                break;
            }
        }
        self.entries.insert(key, now);
        self.insertion_order.push(key);
    }

    /// Remove entries older than TTL. Returns the number of entries removed.
    pub fn cull(&mut self, now: f64) -> usize {
        if self.max_entries == 0 {
            return 0;
        }
        let cutoff = now - self.ttl_secs;
        let before = self.entries.len();
        self.entries.retain(|_, ts| *ts > cutoff);
        self.insertion_order
            .retain(|key| self.entries.contains_key(key));
        before - self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

struct PacketHashQueue {
    entries: RawHashSlots,
    head: usize,
    len: usize,
}

impl PacketHashQueue {
    fn new(capacity: usize, allocation: PacketHashlistAllocation) -> Self {
        Self {
            entries: RawHashSlots::new(capacity, allocation),
            head: 0,
            len: 0,
        }
    }

    fn capacity(&self) -> usize {
        self.entries.len()
    }

    fn len(&self) -> usize {
        self.len
    }

    fn push_back(&mut self, hash: [u8; 32]) {
        debug_assert!(self.len < self.capacity());
        if self.capacity() == 0 {
            return;
        }
        let tail = (self.head + self.len) % self.capacity();
        self.entries.write(tail, hash);
        self.len += 1;
    }

    fn pop_front(&mut self) -> Option<[u8; 32]> {
        if self.len == 0 || self.capacity() == 0 {
            return None;
        }
        let hash = self.entries.read(self.head);
        self.head = (self.head + 1) % self.capacity();
        self.len -= 1;
        if self.len == 0 {
            self.head = 0;
        }
        Some(hash)
    }
}

struct PacketHashSet {
    entries: RawHashSlots,
    controls: Box<[u8]>,
    len: usize,
}

impl PacketHashSet {
    fn new(max_entries: usize, allocation: PacketHashlistAllocation) -> Self {
        let capacity = bucket_capacity(max_entries);
        Self {
            entries: RawHashSlots::new(capacity, allocation),
            controls: vec![0; capacity].into_boxed_slice(),
            len: 0,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn contains(&self, hash: &[u8; 32]) -> bool {
        if self.controls.is_empty() {
            return false;
        }

        let mut idx = self.bucket_index(hash);
        loop {
            if self.controls[idx] == 0 {
                return false;
            }
            if self.entries.get(idx) == hash {
                return true;
            }
            idx = (idx + 1) & (self.controls.len() - 1);
        }
    }

    fn insert(&mut self, hash: [u8; 32]) -> bool {
        if self.controls.is_empty() {
            return false;
        }

        let mut idx = self.bucket_index(&hash);
        loop {
            if self.controls[idx] == 0 {
                // Publish occupancy only after the payload is initialized.
                self.entries.write(idx, hash);
                self.controls[idx] = 1;
                self.len += 1;
                return true;
            }
            if self.entries.get(idx) == &hash {
                return false;
            }
            idx = (idx + 1) & (self.controls.len() - 1);
        }
    }

    fn remove(&mut self, hash: &[u8; 32]) -> bool {
        if self.controls.is_empty() {
            return false;
        }

        let mut idx = self.bucket_index(hash);
        loop {
            if self.controls[idx] == 0 {
                return false;
            }
            if self.entries.get(idx) == hash {
                break;
            }
            idx = (idx + 1) & (self.controls.len() - 1);
        }

        self.controls[idx] = 0;
        self.len -= 1;

        let mut next = (idx + 1) & (self.controls.len() - 1);
        while self.controls[next] != 0 {
            let entry = self.entries.read(next);
            self.controls[next] = 0;
            self.len -= 1;
            let inserted = self.insert(entry);
            debug_assert!(inserted, "cluster reinsert after removal must succeed");
            next = (next + 1) & (self.controls.len() - 1);
        }

        true
    }

    fn bucket_index(&self, hash: &[u8; 32]) -> usize {
        debug_assert!(!self.controls.is_empty());
        (hash_bytes(hash) as usize) & (self.controls.len() - 1)
    }
}

fn bucket_capacity(max_entries: usize) -> usize {
    if max_entries == 0 {
        return 0;
    }

    let min_capacity = max_entries.saturating_mul(2).max(1);
    min_capacity.next_power_of_two()
}

fn hash_bytes(hash: &[u8; 32]) -> u64 {
    let mut state = 0xcbf29ce484222325u64;
    for byte in hash {
        state ^= u64::from(*byte);
        state = state.wrapping_mul(0x100000001b3);
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(seed: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = seed;
        h
    }

    fn policies() -> [PacketHashlistAllocation; 2] {
        [
            PacketHashlistAllocation::Eager,
            PacketHashlistAllocation::Lazy,
        ]
    }

    #[test]
    fn test_new_hash_not_duplicate() {
        for policy in policies() {
            let hl = PacketHashlist::with_allocation(100, policy);
            assert!(!hl.is_duplicate(&make_hash(1)));
        }
    }

    #[test]
    fn test_added_hash_is_duplicate() {
        for policy in policies() {
            let mut hl = PacketHashlist::with_allocation(100, policy);
            let h = make_hash(1);
            hl.add(h);
            assert!(hl.is_duplicate(&h));
        }
    }

    #[test]
    fn test_duplicate_insert_does_not_increase_len() {
        for policy in policies() {
            let mut hl = PacketHashlist::with_allocation(2, policy);
            let h = make_hash(1);
            hl.add(h);
            hl.add(h);
            assert_eq!(hl.len(), 1);
            assert!(hl.is_duplicate(&h));
        }
    }

    #[test]
    fn test_full_hashlist_evicts_oldest_unique_hash() {
        for policy in policies() {
            let mut hl = PacketHashlist::with_allocation(3, policy);
            let hashes = [make_hash(1), make_hash(2), make_hash(3), make_hash(4)];
            for hash in hashes {
                hl.add(hash);
            }
            assert!(!hl.is_duplicate(&hashes[0]));
            assert!(hashes[1..].iter().all(|hash| hl.is_duplicate(hash)));
            assert_eq!(hl.len(), 3);
        }
    }

    #[test]
    fn test_duplicate_does_not_refresh_recency() {
        for policy in policies() {
            let mut hl = PacketHashlist::with_allocation(2, policy);
            let h1 = make_hash(1);
            let h2 = make_hash(2);
            let h3 = make_hash(3);
            hl.add(h1);
            hl.add(h2);
            hl.add(h2);
            hl.add(h3);
            assert!(!hl.is_duplicate(&h1));
            assert!(hl.is_duplicate(&h2));
            assert!(hl.is_duplicate(&h3));
        }
    }

    #[test]
    fn test_fifo_eviction_order_is_exact_across_multiple_inserts() {
        for policy in policies() {
            let mut hl = PacketHashlist::with_allocation(3, policy);
            for seed in 1..=9 {
                hl.add(make_hash(seed));
            }
            assert_eq!(
                hl.iter().copied().collect::<Vec<_>>(),
                vec![make_hash(7), make_hash(8), make_hash(9)]
            );
        }
    }

    #[test]
    fn test_zero_capacity_hashlist_is_noop() {
        for policy in policies() {
            let mut hl = PacketHashlist::with_allocation(0, policy);
            let h = make_hash(1);
            hl.add(h);
            assert_eq!(hl.len(), 0);
            assert!(!hl.is_duplicate(&h));
            assert_eq!(hl.iter().count(), 0);
        }
    }

    #[test]
    fn collision_cluster_removal_preserves_remaining_entries() {
        for policy in policies() {
            let mut set = PacketHashSet::new(3, policy);
            let mut colliding = Vec::new();
            for seed in 0..=u8::MAX {
                let hash = make_hash(seed);
                if hash_bytes(&hash) & 7 == 0 {
                    colliding.push(hash);
                    if colliding.len() == 3 {
                        break;
                    }
                }
            }
            assert_eq!(colliding.len(), 3);
            for hash in &colliding {
                assert!(set.insert(*hash));
            }
            assert!(set.remove(&colliding[0]));
            assert!(set.contains(&colliding[1]));
            assert!(set.contains(&colliding[2]));
        }
    }

    #[test]
    fn raw_slots_read_only_after_write() {
        for policy in policies() {
            let mut slots = RawHashSlots::new(2, policy);
            slots.write(1, make_hash(42));
            assert_eq!(slots.read(1), make_hash(42));
        }
    }

    // --- AnnounceSignatureCache tests ---

    #[test]
    fn test_sig_cache_insert_and_contains() {
        let mut cache = AnnounceSignatureCache::new(100, 60.0);
        let k = make_hash(1);
        assert!(!cache.contains(&k));
        cache.insert(k, 100.0);
        assert!(cache.contains(&k));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_sig_cache_duplicate_insert_is_noop() {
        let mut cache = AnnounceSignatureCache::new(100, 60.0);
        let k = make_hash(1);
        cache.insert(k, 100.0);
        cache.insert(k, 200.0);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_sig_cache_ttl_expiry() {
        let mut cache = AnnounceSignatureCache::new(100, 60.0);
        cache.insert(make_hash(1), 100.0);
        cache.insert(make_hash(2), 150.0);

        // At t=155, entry 1 (age=55) is still within TTL, entry 2 (age=5) too
        assert_eq!(cache.cull(155.0), 0);
        assert_eq!(cache.len(), 2);

        // At t=161, entry 1 (age=61) expired, entry 2 (age=11) still valid
        assert_eq!(cache.cull(161.0), 1);
        assert_eq!(cache.len(), 1);
        assert!(!cache.contains(&make_hash(1)));
        assert!(cache.contains(&make_hash(2)));
    }

    #[test]
    fn test_sig_cache_capacity_eviction() {
        let mut cache = AnnounceSignatureCache::new(2, 600.0);
        cache.insert(make_hash(1), 100.0);
        cache.insert(make_hash(2), 101.0);
        cache.insert(make_hash(3), 102.0); // should evict hash(1)

        assert_eq!(cache.len(), 2);
        assert!(!cache.contains(&make_hash(1)));
        assert!(cache.contains(&make_hash(2)));
        assert!(cache.contains(&make_hash(3)));
    }

    #[test]
    fn test_sig_cache_disabled_when_zero_capacity() {
        let mut cache = AnnounceSignatureCache::new(0, 60.0);
        let k = make_hash(1);
        cache.insert(k, 100.0);
        assert!(!cache.contains(&k));
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.cull(200.0), 0);
    }
}
