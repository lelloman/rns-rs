use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::MaybeUninit;

use super::types::PacketHashlistAllocation;

/// What the table stores of a packet hash: its first 16 bytes. Two distinct
/// packets share a prefix with probability 2^-128, so a prefix decides
/// duplicates as the full hash would, in half the memory.
type Key = [u8; 16];

fn key_of(hash: &[u8; 32]) -> Key {
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash[..16]);
    key
}

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

    /// A table retaining up to `max_size` hashes. Its storage is allocated
    /// once, at full size, and never moved or freed while the table lives,
    /// so growth leaves no freed blocks behind for the allocator to keep.
    /// `Eager` touches every slot up front; `Lazy` leaves the slots to be
    /// touched as hashes are written, in order, and uses a prefix of the
    /// index that doubles with occupancy, so a table's resident memory
    /// follows the hashes it holds.
    pub fn with_allocation(max_size: usize, allocation: PacketHashlistAllocation) -> Self {
        // Index buckets store a 32-bit slot number.
        let max_size = max_size.min(MAX_ENTRIES);
        Self {
            queue: PacketHashQueue::new(max_size, allocation),
            set: PacketHashSet::new(max_size, None, allocation),
            max_size,
        }
    }

    /// Key bucket placement with a secret `seed`, so that senders cannot
    /// grind packets whose hashes share a probe sequence. Unseeded tables
    /// index buckets by the hashes' leading bits.
    pub fn seed_hashing(&mut self, seed: u64) {
        self.set.key_seed = Some(seed);
        // An empty table's buckets are already clear; rewriting them would
        // fault in every page of a table allocated up front.
        if self.set.len > 0 {
            self.set.rebuild(&self.queue);
        }
    }

    pub(crate) fn hashing_seed(&self) -> Option<u64> {
        self.set.key_seed
    }

    /// Check if a hash is currently retained.
    pub fn is_duplicate(&self, hash: &[u8; 32]) -> bool {
        self.set.contains(&key_of(hash), &self.queue)
    }

    /// Start loading the bucket a lookup of `hash` probes first, so a later
    /// [`is_duplicate`](Self::is_duplicate) or [`add`](Self::add) for it can
    /// overlap that cache miss with other work.
    pub fn prefetch(&self, hash: &[u8; 32]) {
        self.set.prefetch(self.set.key(&key_of(hash)));
    }

    /// Retain a hash. If the dedup table is full, evict the oldest unique hash.
    pub fn add(&mut self, hash: [u8; 32]) {
        let hash = key_of(&hash);
        if self.max_size == 0 || self.set.contains(&hash, &self.queue) {
            return;
        }
        if self.queue.len() == self.max_size {
            let oldest = *self.queue.entries.get(self.queue.head);
            let removed = self.set.remove(&oldest, &self.queue);
            debug_assert!(removed, "oldest hash must exist in index");
            self.queue.pop_front();
        }
        self.set.make_room(&self.queue);
        let slot = (self.queue.head + self.queue.len) % self.queue.capacity();
        self.queue.push_back(hash);
        self.set.insert(slot, &self.queue);
        if self.queue.len() == self.max_size {
            // The next new hash evicts the current oldest; start loading its
            // bucket now instead of stalling on it then.
            let oldest = self.queue.entries.get(self.queue.head);
            self.set.prefetch(self.set.key(oldest));
        }
    }

    /// Stop retaining a hash, preserving the FIFO order of all other entries.
    pub fn remove(&mut self, hash: &[u8; 32]) -> bool {
        let hash = &key_of(hash);
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

    /// Iterate retained hashes from oldest to newest, as stored: the first
    /// 16 bytes of each, the rest zero. [`add`](Self::add) takes them back
    /// unchanged.
    pub fn iter(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        (0..self.queue.len).map(|offset| {
            let index = (self.queue.head + offset) % self.queue.capacity();
            let mut hash = [0u8; 32];
            hash[..16].copy_from_slice(self.queue.entries.get(index));
            hash
        })
    }
}

/// Hash payload slots initialized only within the queue's logical FIFO range.
/// The index stores queue offsets, never a second copy of a full hash.
struct RawHashSlots {
    slots: Box<[MaybeUninit<Key>]>,
}

impl RawHashSlots {
    fn new(capacity: usize, allocation: PacketHashlistAllocation) -> Self {
        let mut slots = Box::<[Key]>::new_uninit_slice(capacity);
        if allocation == PacketHashlistAllocation::Eager {
            for slot in &mut slots {
                // Volatile writes make eager page prefaulting an observable side
                // effect that release-mode optimization cannot remove.
                unsafe { core::ptr::write_volatile(slot.as_mut_ptr(), [0; 16]) };
            }
        }
        Self { slots }
    }

    fn len(&self) -> usize {
        self.slots.len()
    }

    fn write(&mut self, index: usize, hash: Key) {
        self.slots[index].write(hash);
    }

    fn read(&self, index: usize) -> Key {
        // SAFETY: callers establish initialization through the queue's logical
        // range before calling this method.
        unsafe { self.slots[index].assume_init_read() }
    }

    fn get(&self, index: usize) -> &Key {
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

    fn capacity(&self) -> usize {
        self.entries.len()
    }

    fn len(&self) -> usize {
        self.len
    }

    fn push_back(&mut self, hash: Key) {
        debug_assert!(self.len < self.capacity());
        if self.capacity() == 0 {
            return;
        }
        let tail = (self.head + self.len) % self.capacity();
        self.entries.write(tail, hash);
        self.len += 1;
    }

    fn pop_front(&mut self) -> Option<Key> {
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

    fn remove(&mut self, hash: &Key) -> bool {
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

/// Open-addressed lookup of queue slots, in 32-bit buckets at most half
/// full. Zero is empty. Otherwise an entry holds, from its low bits: the
/// queue slot + 1, its distance from its home bucket (saturating), and in
/// the remaining high bits a tag, the same bits of the bucket key's high
/// half. Placement uses the key's low bits.
///
/// The tag lets lookups skip the queue entry of nearly every bucket whose
/// key differs, so a miss usually touches only buckets; the displacement
/// lets deletion find an entry's home bucket without reading its hash.
struct PacketHashSet {
    /// Every bucket the table may use; probing uses the first `active`.
    buckets: Box<[u32]>,
    /// Buckets in use: a power of two, at least twice the entries.
    active: usize,
    len: usize,
    /// Seed of the keyed bucket hash; `None` uses the hashes' leading bits.
    key_seed: Option<u64>,
    /// Entry bits holding the queue slot + 1.
    slot_mask: u32,
    /// Where the displacement starts, and its largest value, which means
    /// "at least this far": the home is then found from the queued hash.
    displacement_shift: u32,
    max_displacement: u32,
    /// Entry bits holding the tag; zero when the slot and displacement
    /// leave none.
    tag_mask: u32,
}

/// Displacement bits an entry carries when the slot leaves room. At half
/// load nearly every entry sits within 15 buckets of its home.
const DISPLACEMENT_BITS: u32 = 4;

impl PacketHashSet {
    fn new(
        max_entries: usize,
        key_seed: Option<u64>,
        allocation: PacketHashlistAllocation,
    ) -> Self {
        let slot_bits = usize::BITS - max_entries.leading_zeros();
        let displacement_bits = DISPLACEMENT_BITS.min(32 - slot_bits.min(32));
        let low_bits = slot_bits + displacement_bits;
        let buckets = bucket_capacity(max_entries);
        let active = match allocation {
            PacketHashlistAllocation::Eager => buckets,
            PacketHashlistAllocation::Lazy => buckets.min(INITIAL_BUCKETS),
        };
        Self {
            // Zeroed and untouched until used: only the active prefix is
            // faulted in.
            buckets: vec![0; buckets].into_boxed_slice(),
            active,
            len: 0,
            key_seed,
            slot_mask: low_mask(slot_bits),
            displacement_shift: slot_bits.min(31),
            max_displacement: low_mask(displacement_bits),
            tag_mask: !low_mask(low_bits),
        }
    }

    /// Bucket key of a packet hash.
    fn key(&self, hash: &Key) -> u64 {
        let leading = leading_bits(hash);
        match self.key_seed {
            None => leading,
            Some(seed) => {
                use core::hash::BuildHasher;
                foldhash::fast::FixedState::with_seed(seed).hash_one(leading)
            }
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    fn tag(&self, key: u64) -> u32 {
        (key >> 32) as u32 & self.tag_mask
    }

    #[inline]
    fn entry_slot(&self, entry: u32) -> usize {
        (entry & self.slot_mask) as usize - 1
    }

    #[inline]
    fn entry(&self, tag: u32, displacement: usize, slot_plus_one: u32) -> u32 {
        let displacement = displacement.min(self.max_displacement as usize) as u32;
        tag | (displacement << self.displacement_shift) | slot_plus_one
    }

    #[inline]
    fn mask(&self) -> usize {
        self.active - 1
    }

    /// Double the active buckets before one more entry would fill more than
    /// half of them.
    fn make_room(&mut self, queue: &PacketHashQueue) {
        if self.active < self.buckets.len() && (self.len + 1) * 2 > self.active {
            self.active *= 2;
            self.rebuild(queue);
        }
    }

    fn position(&self, hash: &Key, queue: &PacketHashQueue) -> Option<usize> {
        if self.buckets.is_empty() {
            return None;
        }
        let key = self.key(hash);
        let tag = self.tag(key);
        let mut idx = self.bucket_index(key);
        loop {
            let entry = self.buckets[idx];
            if entry == 0 {
                return None;
            }
            if entry & self.tag_mask == tag && queue.entries.get(self.entry_slot(entry)) == hash {
                return Some(idx);
            }
            idx = (idx + 1) & self.mask();
        }
    }

    fn contains(&self, hash: &Key, queue: &PacketHashQueue) -> bool {
        self.position(hash, queue).is_some()
    }

    fn insert(&mut self, slot: usize, queue: &PacketHashQueue) {
        let key = self.key(queue.entries.get(slot));
        let home = self.bucket_index(key);
        let mut idx = home;
        while self.buckets[idx] != 0 {
            idx = (idx + 1) & self.mask();
        }
        let displacement = idx.wrapping_sub(home) & self.mask();
        self.buckets[idx] = self.entry(self.tag(key), displacement, slot as u32 + 1);
        self.len += 1;
    }

    fn remove(&mut self, hash: &Key, queue: &PacketHashQueue) -> bool {
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
        let mask = self.mask();
        let mut hole = idx;
        let mut next = (idx + 1) & mask;
        while self.buckets[next] != 0 {
            let entry = self.buckets[next];
            let home = self.home(entry, next, queue);
            let reachable_without_hole = if hole <= next {
                hole < home && home <= next
            } else {
                hole < home || home <= next
            };
            if !reachable_without_hole {
                let displacement = hole.wrapping_sub(home) & mask;
                self.buckets[hole] =
                    self.entry(entry & self.tag_mask, displacement, entry & self.slot_mask);
                self.buckets[next] = 0;
                hole = next;
            }
            next = (next + 1) & mask;
        }
        true
    }

    fn rebuild(&mut self, queue: &PacketHashQueue) {
        self.buckets[..self.active].fill(0);
        self.len = 0;
        for offset in 0..queue.len {
            self.insert((queue.head + offset) % queue.capacity(), queue);
        }
    }

    fn prefetch(&self, key: u64) {
        if !self.buckets.is_empty() {
            prefetch_read(&self.buckets[self.bucket_index(key)]);
        }
    }

    #[inline]
    fn bucket_index(&self, key: u64) -> usize {
        debug_assert!(!self.buckets.is_empty());
        (key as usize) & self.mask()
    }

    /// Home bucket of the entry at `index`: from its displacement, or from
    /// its queued hash when the displacement saturated.
    fn home(&self, entry: u32, index: usize, queue: &PacketHashQueue) -> usize {
        let displacement = (entry >> self.displacement_shift) & self.max_displacement;
        if displacement < self.max_displacement {
            index.wrapping_sub(displacement as usize) & self.mask()
        } else {
            self.bucket_index(self.key(queue.entries.get(self.entry_slot(entry))))
        }
    }
}

/// Hint the CPU to load the cache line holding `value`. It has no effect on
/// program state, and is a no-op on architectures without a stable hint.
#[inline(always)]
fn prefetch_read(value: &u32) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: SSE is part of the x86_64 baseline, and a prefetch never faults
    // or changes memory.
    unsafe {
        core::arch::x86_64::_mm_prefetch::<{ core::arch::x86_64::_MM_HINT_T0 }>(
            (value as *const u32).cast(),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: PRFM is a hint that never faults or changes memory or flags.
    unsafe {
        core::arch::asm!(
            "prfm pldl1keep, [{0}]",
            in(reg) value as *const u32,
            options(nostack, readonly, preserves_flags)
        );
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let _ = value;
}

/// The low `bits` bits set.
fn low_mask(bits: u32) -> u32 {
    if bits >= 32 {
        u32::MAX
    } else {
        (1u32 << bits) - 1
    }
}

/// Largest retention the 32-bit index buckets can address.
const MAX_ENTRIES: usize = u32::MAX as usize - 1;

/// Active buckets of a table that grows with occupancy, at first.
const INITIAL_BUCKETS: usize = 128;

/// Buckets for `max_entries`: a power of two, at most half full.
fn bucket_capacity(max_entries: usize) -> usize {
    if max_entries == 0 {
        return 0;
    }
    max_entries.saturating_mul(2).max(1).next_power_of_two()
}

/// Leading 64 bits of a packet hash. Packet hashes are SHA-256 digests,
/// already uniformly distributed for packets nobody chose, so an unseeded
/// table indexes buckets with these bits directly.
fn leading_bits(hash: &Key) -> u64 {
    let mut leading = [0u8; 8];
    leading.copy_from_slice(&hash[..8]);
    u64::from_le_bytes(leading)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hash as the table stores and iterates it.
    fn stored(hash: [u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&hash[..16]);
        out
    }

    fn make_hash(seed: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = seed;
        h
    }

    /// Every allocation policy, unseeded and with a keyed bucket hash.
    fn seeded_policies() -> impl Iterator<Item = (PacketHashlistAllocation, Option<u64>)> {
        policies()
            .into_iter()
            .flat_map(|policy| [(policy, None), (policy, Some(0x9e37_79b9_7f4a_7c15))])
    }

    #[test]
    fn seeding_keeps_retained_hashes_and_fifo_order() {
        for policy in policies() {
            let mut list = PacketHashlist::with_allocation(16, policy);
            let hashes: Vec<[u8; 32]> = (0..12).map(make_hash).collect();
            for hash in &hashes {
                list.add(*hash);
            }
            list.seed_hashing(0x0123_4567_89ab_cdef);
            assert!(hashes.iter().all(|hash| list.is_duplicate(hash)));
            assert!(list.iter().eq(hashes.iter().copied().map(stored)));
            assert!(!list.is_duplicate(&make_hash(200)));
        }
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
                hl.iter().collect::<Vec<_>>(),
                [make_hash(2), make_hash(4)].map(stored).to_vec()
            );

            hl.add(make_hash(5));
            assert_eq!(
                hl.iter().collect::<Vec<_>>(),
                [make_hash(2), make_hash(4), make_hash(5)]
                    .map(stored)
                    .to_vec()
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
                hl.iter().collect::<Vec<_>>(),
                [make_hash(7), make_hash(8), make_hash(9)]
                    .map(stored)
                    .to_vec()
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
        for (policy, seed) in seeded_policies() {
            for capacity in [1usize, 2, 3, 7, 16, 33] {
                let mut list = PacketHashlist::with_allocation(capacity, policy);
                if let Some(seed) = seed {
                    list.seed_hashing(seed);
                }
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
                    if rng.is_multiple_of(97) {
                        for retained in &model {
                            assert!(list.is_duplicate(retained));
                        }
                        assert!(list.iter().eq(model.iter().copied().map(stored)));
                    }
                }
            }
        }
    }

    #[test]
    fn collision_cluster_removal_preserves_remaining_entries() {
        for policy in policies() {
            let mut set = PacketHashSet::new(3, None, PacketHashlistAllocation::Eager);
            let mut queue = PacketHashQueue::new(3, policy);
            let mut colliding = Vec::new();
            for seed in 0..=u8::MAX {
                let hash = key_of(&make_hash(seed));
                if leading_bits(&hash) & 7 == 0 {
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
            slots.write(1, key_of(&make_hash(42)));
            assert_eq!(slots.read(1), key_of(&make_hash(42)));
        }
    }

    // --- AnnounceSignatureCache tests ---

    #[test]
    fn lazy_storage_grows_with_occupancy_not_retention_limit() {
        let mut table = PacketHashlist::with_allocation(250_000, PacketHashlistAllocation::Lazy);
        assert_eq!(table.set.active, 128);
        for n in 0u64..1000 {
            let mut hash = [0; 32];
            hash[..8].copy_from_slice(&n.to_le_bytes());
            table.add(hash);
        }
        assert_eq!(table.len(), 1000);
        assert_eq!(table.set.active, 2048);
        assert_eq!(table.max_size, 250_000);
    }

    #[test]
    fn mixed_operations_match_fifo_model_through_growth_and_wraparound() {
        use alloc::collections::VecDeque;
        for (policy, seed) in seeded_policies() {
            for limit in [0, 1, 3, 63, 64, 65, 127, 129, 257] {
                let mut table = PacketHashlist::with_allocation(limit, policy);
                if let Some(seed) = seed {
                    table.seed_hashing(seed);
                }
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
                    assert!(table.iter().eq(model.iter().copied().map(stored)));
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
