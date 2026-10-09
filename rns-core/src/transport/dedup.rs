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
    max_size: usize,
}

impl PacketHashlist {
    pub fn new(max_size: usize) -> Self {
        Self::with_allocation(max_size, PacketHashlistAllocation::Eager)
    }

    pub fn with_allocation(max_size: usize, allocation: PacketHashlistAllocation) -> Self {
        // Index buckets store a 32-bit slot number.
        let max_size = max_size.min(MAX_ENTRIES);
        let initial = if allocation == PacketHashlistAllocation::Eager {
            max_size
        } else {
            max_size.min(64)
        };
        Self {
            queue: PacketHashQueue::new(initial, allocation),
            set: PacketHashSet::new(initial),
            max_size,
        }
    }

    /// Check if a hash is currently retained.
    pub fn is_duplicate(&self, hash: &[u8; 32]) -> bool {
        self.set.contains(hash, &self.queue)
    }

    /// Retain a hash. If the dedup table is full, evict the oldest unique hash.
    pub fn add(&mut self, hash: [u8; 32]) {
        if self.max_size == 0 || self.set.contains(&hash, &self.queue) {
            return;
        }
        if self.queue.len() == self.max_size {
            let oldest = *self.queue.entries.get(self.queue.head);
            let removed = self.set.remove(&oldest, &self.queue);
            debug_assert!(removed, "oldest hash must exist in index");
            self.queue.pop_front();
        }
        if self.queue.len() == self.queue.capacity() {
            let capacity = self
                .queue
                .capacity()
                .saturating_mul(2)
                .max(1)
                .min(self.max_size);
            self.queue.grow(capacity);
            self.set = PacketHashSet::new(capacity);
            self.set.rebuild(&self.queue);
        }
        let slot = (self.queue.head + self.queue.len) % self.queue.capacity();
        self.queue.push_back(hash);
        self.set.insert(slot, &self.queue);
    }

    /// Stop retaining a hash, preserving the FIFO order of all other entries.
    pub fn remove(&mut self, hash: &[u8; 32]) -> bool {
        if !self.set.contains(hash, &self.queue) {
            return false;
        }
        let removed = self.queue.remove(hash);
        debug_assert!(removed, "indexed hash must exist in FIFO queue");
        // Queue compaction moves slots. Rebuild their index without allocation.
        self.set.rebuild(&self.queue);
        true
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

/// Hash payload slots initialized only within the queue's logical FIFO range.
/// The index stores queue offsets, never a second copy of a full hash.
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
        // range before calling this method.
        unsafe { self.slots[index].assume_init_read() }
    }

    fn get(&self, index: usize) -> &[u8; 32] {
        // SAFETY: callers establish initialization through the queue's logical
        // range before calling this method.
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

    fn grow(&mut self, capacity: usize) {
        debug_assert!(capacity > self.capacity());
        let mut entries = RawHashSlots::new(capacity, PacketHashlistAllocation::Lazy);
        for offset in 0..self.len {
            let old = (self.head + offset) % self.capacity();
            entries.write(offset, self.entries.read(old));
        }
        self.entries = entries;
        self.head = 0;
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

    fn remove(&mut self, hash: &[u8; 32]) -> bool {
        let Some(offset) = (0..self.len).find(|offset| {
            let index = (self.head + offset) % self.capacity();
            self.entries.get(index) == hash
        }) else {
            return false;
        };

        for current in offset..self.len - 1 {
            let next_index = (self.head + current + 1) % self.capacity();
            let current_index = (self.head + current) % self.capacity();
            let next = self.entries.read(next_index);
            self.entries.write(current_index, next);
        }
        self.len -= 1;
        if self.len == 0 {
            self.head = 0;
        }
        true
    }
}

/// Open-addressed lookup of queue slots. Zero is empty; other values are
/// physical queue slot + 1. At most half the buckets are occupied.
struct PacketHashSet {
    buckets: Box<[u32]>,
    len: usize,
}

impl PacketHashSet {
    fn new(max_entries: usize) -> Self {
        Self {
            buckets: vec![0; bucket_capacity(max_entries)].into_boxed_slice(),
            len: 0,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn position(&self, hash: &[u8; 32], queue: &PacketHashQueue) -> Option<usize> {
        if self.buckets.is_empty() {
            return None;
        }
        let mut idx = self.bucket_index(hash);
        loop {
            let entry = self.buckets[idx];
            if entry == 0 {
                return None;
            }
            if queue.entries.get(entry as usize - 1) == hash {
                return Some(idx);
            }
            idx = (idx + 1) & (self.buckets.len() - 1);
        }
    }

    fn contains(&self, hash: &[u8; 32], queue: &PacketHashQueue) -> bool {
        self.position(hash, queue).is_some()
    }

    fn insert(&mut self, slot: usize, queue: &PacketHashQueue) {
        let hash = queue.entries.get(slot);
        let mut idx = self.bucket_index(hash);
        while self.buckets[idx] != 0 {
            idx = (idx + 1) & (self.buckets.len() - 1);
        }
        self.buckets[idx] = (slot + 1) as u32;
        self.len += 1;
    }

    fn remove(&mut self, hash: &[u8; 32], queue: &PacketHashQueue) -> bool {
        let Some(idx) = self.position(hash, queue) else {
            return false;
        };
        self.buckets[idx] = 0;
        self.len -= 1;
        // Repair the probe cluster before the evicted queue slot is reused,
        // by backward-shift deletion: walk the cluster after the hole and move
        // each entry whose home bucket does not lie cyclically in
        // (hole, current] back into the hole. Every remaining entry stays
        // reachable from its home bucket, and each moves at most once.
        let mask = self.buckets.len() - 1;
        let mut hole = idx;
        let mut next = (idx + 1) & mask;
        while self.buckets[next] != 0 {
            let home = self.bucket_index(queue.entries.get(self.buckets[next] as usize - 1));
            let reachable_without_hole = if hole <= next {
                hole < home && home <= next
            } else {
                hole < home || home <= next
            };
            if !reachable_without_hole {
                self.buckets[hole] = self.buckets[next];
                self.buckets[next] = 0;
                hole = next;
            }
            next = (next + 1) & mask;
        }
        true
    }

    fn rebuild(&mut self, queue: &PacketHashQueue) {
        self.buckets.fill(0);
        self.len = 0;
        for offset in 0..queue.len {
            self.insert((queue.head + offset) % queue.capacity(), queue);
        }
    }

    fn bucket_index(&self, hash: &[u8; 32]) -> usize {
        debug_assert!(!self.buckets.is_empty());
        (hash_bytes(hash) as usize) & (self.buckets.len() - 1)
    }
}

/// Largest retention the 32-bit index buckets can address.
const MAX_ENTRIES: usize = u32::MAX as usize - 1;

fn bucket_capacity(max_entries: usize) -> usize {
    if max_entries == 0 {
        return 0;
    }

    let min_capacity = max_entries.saturating_mul(2).max(1);
    min_capacity.next_power_of_two()
}

/// Bucket key for a packet hash. Packet hashes are SHA-256 digests, already
/// uniformly distributed, so their leading 64 bits index the table directly;
/// a byte-wise mixing function added a dependent multiply per byte on every
/// lookup, insertion and eviction without improving the distribution.
fn hash_bytes(hash: &[u8; 32]) -> u64 {
    let mut leading = [0u8; 8];
    leading.copy_from_slice(&hash[..8]);
    u64::from_le_bytes(leading)
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
    fn removal_preserves_fifo_order_after_queue_wraps() {
        for policy in policies() {
            let mut hl = PacketHashlist::with_allocation(3, policy);
            for seed in 1..=4 {
                hl.add(make_hash(seed));
            }

            assert!(hl.remove(&make_hash(3)));
            assert!(!hl.remove(&make_hash(1)));
            assert_eq!(
                hl.iter().copied().collect::<Vec<_>>(),
                vec![make_hash(2), make_hash(4)]
            );

            hl.add(make_hash(5));
            assert_eq!(
                hl.iter().copied().collect::<Vec<_>>(),
                vec![make_hash(2), make_hash(4), make_hash(5)]
            );
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

    /// Random adds, duplicates and removals against a FIFO-plus-set model,
    /// with keys confined to a few buckets so probe clusters, wraparound and
    /// backward-shift deletion are exercised heavily.
    #[test]
    fn hashlist_matches_fifo_model_under_collisions() {
        use alloc::collections::VecDeque;
        for policy in policies() {
            for capacity in [1usize, 2, 3, 7, 16, 33] {
                let mut list = PacketHashlist::with_allocation(capacity, policy);
                let mut model: VecDeque<[u8; 32]> = VecDeque::new();
                let mut rng = 0x2545_f491_4f6c_dd1du64 ^ capacity as u64;
                for _ in 0..20_000 {
                    rng ^= rng << 13;
                    rng ^= rng >> 7;
                    rng ^= rng << 17;
                    let mut key = [0u8; 32];
                    // Few distinct leading bytes: many keys share a home bucket.
                    key[0] = (rng % 5) as u8;
                    key[8] = (rng >> 8) as u8 % (capacity as u8 * 3 + 1);
                    match (rng >> 20) % 4 {
                        0 | 1 => {
                            list.add(key);
                            if !model.contains(&key) {
                                if model.len() == capacity {
                                    model.pop_front();
                                }
                                model.push_back(key);
                            }
                        }
                        2 => {
                            let removed = list.remove(&key);
                            let position = model.iter().position(|k| *k == key);
                            assert_eq!(removed, position.is_some());
                            if let Some(position) = position {
                                model.remove(position);
                            }
                        }
                        _ => {}
                    }
                    assert_eq!(list.len(), model.len());
                    assert_eq!(list.is_duplicate(&key), model.contains(&key));
                    if rng % 97 == 0 {
                        for retained in &model {
                            assert!(list.is_duplicate(retained));
                        }
                        assert!(list.iter().eq(model.iter()));
                    }
                }
            }
        }
    }

    #[test]
    fn collision_cluster_removal_preserves_remaining_entries() {
        for policy in policies() {
            let mut set = PacketHashSet::new(3);
            let mut queue = PacketHashQueue::new(3, policy);
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
                queue.push_back(*hash);
                set.insert(queue.len - 1, &queue);
            }
            assert!(set.remove(&colliding[0], &queue));
            assert!(set.contains(&colliding[1], &queue));
            assert!(set.contains(&colliding[2], &queue));
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
    fn lazy_storage_grows_with_occupancy_not_retention_limit() {
        let mut table = PacketHashlist::with_allocation(250_000, PacketHashlistAllocation::Lazy);
        assert_eq!(table.queue.capacity(), 64);
        assert_eq!(table.set.buckets.len(), 128);
        for n in 0u64..1000 {
            let mut hash = [0; 32];
            hash[..8].copy_from_slice(&n.to_le_bytes());
            table.add(hash);
        }
        assert_eq!(table.len(), 1000);
        assert_eq!(table.queue.capacity(), 1024);
        assert_eq!(table.set.buckets.len(), 2048);
        assert_eq!(table.max_size, 250_000);
    }

    #[test]
    fn mixed_operations_match_fifo_model_through_growth_and_wraparound() {
        use alloc::collections::VecDeque;
        for policy in policies() {
            for limit in [0, 1, 3, 63, 64, 65, 127, 129, 257] {
                let mut table = PacketHashlist::with_allocation(limit, policy);
                let mut model = VecDeque::new();
                let mut random = 0x123456789abcdefu64;
                for step in 0..10_000 {
                    random ^= random << 13;
                    random ^= random >> 7;
                    random ^= random << 17;
                    let id = random % 400;
                    let mut hash = [0; 32];
                    hash[..8].copy_from_slice(&id.to_le_bytes());
                    if step % 5 == 0 {
                        let position = model.iter().position(|h| h == &hash);
                        assert_eq!(table.remove(&hash), position.is_some());
                        if let Some(position) = position {
                            model.remove(position);
                        }
                    } else {
                        table.add(hash);
                        if limit > 0 && !model.contains(&hash) {
                            if model.len() == limit {
                                model.pop_front();
                            }
                            model.push_back(hash);
                        }
                    }
                    assert_eq!(table.len(), model.len());
                    assert_eq!(table.is_duplicate(&hash), model.contains(&hash));
                    assert!(table.iter().eq(model.iter()));
                    if step % 100 == 0 {
                        for id in 0u64..400 {
                            let mut hash = [0; 32];
                            hash[..8].copy_from_slice(&id.to_le_bytes());
                            assert_eq!(table.is_duplicate(&hash), model.contains(&hash));
                        }
                    }
                }
            }
        }
    }

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
