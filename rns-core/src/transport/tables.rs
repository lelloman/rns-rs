use alloc::vec::Vec;

use super::types::InterfaceId;

/// Entry in the path table, keyed by destination_hash.
#[derive(Debug, Clone)]
pub struct PathEntry {
    pub timestamp: f64,
    pub next_hop: [u8; 16],
    pub hops: u8,
    pub expires: f64,
    pub random_blobs: Vec<[u8; 10]>,
    pub receiving_interface: InterfaceId,
    pub packet_hash: [u8; 32],
    /// Original announce raw bytes (pre-hop-increment) for cache/retransmission.
    pub announce_raw: Option<Vec<u8>>,
}

/// Entry in the announce table, keyed by destination_hash.
#[derive(Debug, Clone)]
pub struct AnnounceEntry {
    pub timestamp: f64,
    pub retransmit_timeout: f64,
    pub retries: u8,
    pub received_from: [u8; 16],
    pub hops: u8,
    pub packet_raw: Vec<u8>,
    pub packet_data: Vec<u8>,
    pub destination_hash: [u8; 16],
    pub context_flag: u8,
    pub local_rebroadcasts: u8,
    pub block_rebroadcasts: bool,
    pub attached_interface: Option<InterfaceId>,
}

/// Entry in the reverse table, keyed by truncated packet hash.
#[derive(Debug, Clone)]
pub struct ReverseEntry {
    pub receiving_interface: InterfaceId,
    pub outbound_interface: InterfaceId,
    pub timestamp: f64,
}

/// Entry in the link table, keyed by link_id.
#[derive(Debug, Clone)]
pub struct LinkEntry {
    pub timestamp: f64,
    pub next_hop_transport_id: [u8; 16],
    pub next_hop_interface: InterfaceId,
    pub remaining_hops: u8,
    pub received_interface: InterfaceId,
    pub taken_hops: u8,
    pub destination_hash: [u8; 16],
    pub validated: bool,
    pub proof_timeout: f64,
}

/// A pending discovery path request — stored when a path request arrives
/// on a DISCOVER_PATHS_FOR interface for an unknown destination.
#[derive(Debug, Clone)]
pub struct DiscoveryPathRequest {
    pub timestamp: f64,
    pub requesting_interface: InterfaceId,
}

/// Entry in the announce rate table, keyed by destination_hash.
#[derive(Debug, Clone)]
pub struct RateEntry {
    pub last: f64,
    pub rate_violations: u32,
    pub blocked_until: f64,
    pub timestamps: Vec<f64>,
}

/// A bounded set of alternative paths for a single destination.
///
/// `paths[0]` is always the *primary* (best) path.  Ranking: lowest hops
/// first, then most-recent timestamp.
#[derive(Debug, Clone)]
pub struct PathSet {
    paths: Vec<PathEntry>,
    capacity: usize,
}

impl PathSet {
    /// Create a new PathSet containing a single path.
    pub fn from_single(entry: PathEntry, capacity: usize) -> Self {
        PathSet {
            paths: alloc::vec![entry],
            capacity: capacity.max(1),
        }
    }

    /// Access the primary (best) path, if any.
    pub fn primary(&self) -> Option<&PathEntry> {
        self.paths.first()
    }

    /// Mutable access to the primary path.
    pub fn primary_mut(&mut self) -> Option<&mut PathEntry> {
        self.paths.first_mut()
    }

    /// Whether the set contains any paths.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// Number of stored paths.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Iterator over all paths (primary first).
    pub fn iter(&self) -> impl Iterator<Item = &PathEntry> {
        self.paths.iter()
    }

    /// Insert or update a path entry.
    ///
    /// - If a path with the same `next_hop` already exists, it is replaced in-place.
    /// - Otherwise the entry is added as an alternative.  If at capacity the
    ///   worst path (highest hops, then oldest) is evicted.
    ///
    /// After mutation the vector is re-sorted so `paths[0]` remains the best.
    pub fn upsert(&mut self, entry: PathEntry) {
        // Check for existing same-next_hop path
        if let Some(pos) = self.paths.iter().position(|p| p.next_hop == entry.next_hop) {
            self.paths[pos] = entry;
        } else if self.paths.len() < self.capacity {
            self.paths.push(entry);
        } else {
            // At capacity — evict worst (last after sort, but we haven't sorted
            // the new entry yet).  Replace worst if new entry is better.
            // We push then sort then truncate, which is simple and correct.
            self.paths.push(entry);
        }
        self.sort();
        self.paths.truncate(self.capacity);
    }

    /// Promote the next-best path after the current primary becomes
    /// unresponsive.
    ///
    /// If `remove` is true the old primary is discarded; otherwise it is
    /// moved to the back of the list (it may recover later).
    pub fn failover(&mut self, remove: bool) {
        if self.paths.len() <= 1 {
            return;
        }
        if remove {
            self.paths.remove(0);
        } else {
            let old_primary = self.paths.remove(0);
            self.paths.push(old_primary);
        }
    }

    /// Remove expired or orphaned paths.
    ///
    /// `interface_exists` is a predicate that checks whether an interface is
    /// still registered.
    pub fn cull(&mut self, now: f64, interface_exists: impl Fn(&InterfaceId) -> bool) {
        self.paths.retain(|p| {
            now <= p.expires && interface_exists(&p.receiving_interface)
        });
    }

    /// Filter paths by a predicate, keeping only those that match.
    pub fn retain(&mut self, predicate: impl Fn(&PathEntry) -> bool) {
        self.paths.retain(predicate);
    }

    /// Expire all paths in this set (set timestamp/expires to 0).
    pub fn expire_all(&mut self) {
        for p in &mut self.paths {
            p.timestamp = 0.0;
            p.expires = 0.0;
        }
    }

    /// Collect all random_blobs across every path in this set.
    pub fn all_random_blobs(&self) -> Vec<[u8; 10]> {
        let mut blobs = Vec::new();
        for p in &self.paths {
            blobs.extend_from_slice(&p.random_blobs);
        }
        blobs
    }

    /// Find the path entry that matches a given `next_hop`, if any.
    pub fn find_by_next_hop(&self, next_hop: &[u8; 16]) -> Option<&PathEntry> {
        self.paths.iter().find(|p| &p.next_hop == next_hop)
    }

    /// Sort: lowest hops first, then most-recent timestamp first.
    fn sort(&mut self) {
        self.paths.sort_by(|a, b| {
            a.hops.cmp(&b.hops)
                .then_with(|| b.timestamp.partial_cmp(&a.timestamp).unwrap_or(core::cmp::Ordering::Equal))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_entry_creation() {
        let entry = PathEntry {
            timestamp: 1000.0,
            next_hop: [0xAA; 16],
            hops: 3,
            expires: 2000.0,
            random_blobs: Vec::new(),
            receiving_interface: InterfaceId(1),
            packet_hash: [0xBB; 32],
            announce_raw: None,
        };
        assert_eq!(entry.hops, 3);
        assert_eq!(entry.receiving_interface, InterfaceId(1));
    }

    #[test]
    fn test_link_entry_creation() {
        let entry = LinkEntry {
            timestamp: 100.0,
            next_hop_transport_id: [0x11; 16],
            next_hop_interface: InterfaceId(2),
            remaining_hops: 5,
            received_interface: InterfaceId(3),
            taken_hops: 2,
            destination_hash: [0x22; 16],
            validated: false,
            proof_timeout: 200.0,
        };
        assert!(!entry.validated);
        assert_eq!(entry.remaining_hops, 5);
    }

    #[test]
    fn test_rate_entry_creation() {
        let entry = RateEntry {
            last: 50.0,
            rate_violations: 0,
            blocked_until: 0.0,
            timestamps: Vec::new(),
        };
        assert_eq!(entry.rate_violations, 0);
    }

    // =========================================================================
    // PathSet tests
    // =========================================================================

    fn make_path(next_hop: [u8; 16], hops: u8, timestamp: f64, expires: f64) -> PathEntry {
        PathEntry {
            timestamp,
            next_hop,
            hops,
            expires,
            random_blobs: Vec::new(),
            receiving_interface: InterfaceId(1),
            packet_hash: [0; 32],
            announce_raw: None,
        }
    }

    #[test]
    fn test_pathset_from_single() {
        let ps = PathSet::from_single(make_path([1; 16], 3, 100.0, 9999.0), 3);
        assert_eq!(ps.len(), 1);
        assert_eq!(ps.primary().unwrap().hops, 3);
    }

    #[test]
    fn test_pathset_upsert_same_nexthop_replaces() {
        let mut ps = PathSet::from_single(make_path([1; 16], 3, 100.0, 9999.0), 3);
        ps.upsert(make_path([1; 16], 2, 200.0, 9999.0));
        assert_eq!(ps.len(), 1);
        assert_eq!(ps.primary().unwrap().hops, 2);
        assert_eq!(ps.primary().unwrap().timestamp, 200.0);
    }

    #[test]
    fn test_pathset_upsert_new_nexthop_adds_alternative() {
        let mut ps = PathSet::from_single(make_path([1; 16], 3, 100.0, 9999.0), 3);
        ps.upsert(make_path([2; 16], 2, 200.0, 9999.0));
        assert_eq!(ps.len(), 2);
        // Best path (fewer hops) should be primary
        assert_eq!(ps.primary().unwrap().next_hop, [2; 16]);
    }

    #[test]
    fn test_pathset_capacity_eviction() {
        let mut ps = PathSet::from_single(make_path([1; 16], 1, 100.0, 9999.0), 2);
        ps.upsert(make_path([2; 16], 2, 200.0, 9999.0));
        ps.upsert(make_path([3; 16], 3, 300.0, 9999.0));
        // Capacity is 2, worst (3 hops) should be evicted
        assert_eq!(ps.len(), 2);
        assert_eq!(ps.primary().unwrap().next_hop, [1; 16]);
        assert!(ps.find_by_next_hop(&[3; 16]).is_none());
    }

    #[test]
    fn test_pathset_failover_promotes_second() {
        let mut ps = PathSet::from_single(make_path([1; 16], 1, 100.0, 9999.0), 3);
        ps.upsert(make_path([2; 16], 2, 200.0, 9999.0));

        ps.failover(false); // demote, don't remove
        assert_eq!(ps.primary().unwrap().next_hop, [2; 16]);
        assert_eq!(ps.len(), 2); // old primary moved to back
    }

    #[test]
    fn test_pathset_failover_with_remove() {
        let mut ps = PathSet::from_single(make_path([1; 16], 1, 100.0, 9999.0), 3);
        ps.upsert(make_path([2; 16], 2, 200.0, 9999.0));

        ps.failover(true); // remove old primary
        assert_eq!(ps.primary().unwrap().next_hop, [2; 16]);
        assert_eq!(ps.len(), 1);
    }

    #[test]
    fn test_pathset_sort_ordering() {
        let mut ps = PathSet::from_single(make_path([1; 16], 5, 300.0, 9999.0), 4);
        ps.upsert(make_path([2; 16], 2, 100.0, 9999.0));
        ps.upsert(make_path([3; 16], 2, 200.0, 9999.0));
        ps.upsert(make_path([4; 16], 3, 400.0, 9999.0));

        let hops: Vec<u8> = ps.iter().map(|p| p.hops).collect();
        // Sorted by hops asc, then timestamp desc within same hops
        assert_eq!(hops, vec![2, 2, 3, 5]);
        // Among the 2-hop paths, newer timestamp first
        assert_eq!(ps.paths[0].next_hop, [3; 16]); // timestamp 200
        assert_eq!(ps.paths[1].next_hop, [2; 16]); // timestamp 100
    }

    #[test]
    fn test_pathset_cull_removes_expired() {
        let mut ps = PathSet::from_single(make_path([1; 16], 1, 100.0, 500.0), 3);
        ps.upsert(make_path([2; 16], 2, 200.0, 9999.0));

        ps.cull(600.0, |_| true); // now > 500 for first path
        assert_eq!(ps.len(), 1);
        assert_eq!(ps.primary().unwrap().next_hop, [2; 16]);
    }

    #[test]
    fn test_pathset_cull_removes_orphaned_interface() {
        let mut ps = PathSet::from_single(make_path([1; 16], 1, 100.0, 9999.0), 3);
        ps.cull(200.0, |id| id.0 != 1); // interface 1 doesn't exist
        assert!(ps.is_empty());
    }

    #[test]
    fn test_pathset_retain_filters() {
        let mut ps = PathSet::from_single(make_path([1; 16], 1, 100.0, 9999.0), 3);
        ps.upsert(make_path([2; 16], 2, 200.0, 9999.0));

        ps.retain(|p| p.next_hop != [1; 16]);
        assert_eq!(ps.len(), 1);
        assert_eq!(ps.primary().unwrap().next_hop, [2; 16]);
    }

    #[test]
    fn test_pathset_expire_all() {
        let mut ps = PathSet::from_single(make_path([1; 16], 1, 100.0, 9999.0), 3);
        ps.upsert(make_path([2; 16], 2, 200.0, 9999.0));

        ps.expire_all();
        for p in ps.iter() {
            assert_eq!(p.timestamp, 0.0);
            assert_eq!(p.expires, 0.0);
        }
    }

    #[test]
    fn test_pathset_all_random_blobs() {
        let mut e1 = make_path([1; 16], 1, 100.0, 9999.0);
        e1.random_blobs = alloc::vec![[0xAA; 10]];
        let mut e2 = make_path([2; 16], 2, 200.0, 9999.0);
        e2.random_blobs = alloc::vec![[0xBB; 10], [0xCC; 10]];

        let mut ps = PathSet::from_single(e1, 3);
        ps.upsert(e2);

        let blobs = ps.all_random_blobs();
        assert_eq!(blobs.len(), 3);
    }

    #[test]
    fn test_pathset_failover_single_path_noop() {
        let mut ps = PathSet::from_single(make_path([1; 16], 1, 100.0, 9999.0), 3);
        ps.failover(false);
        assert_eq!(ps.len(), 1);
        assert_eq!(ps.primary().unwrap().next_hop, [1; 16]);
    }
}
