use alloc::collections::BTreeSet;

/// Double-buffered packet hash deduplication.
///
/// Uses two BTreeSets: `current` and `previous`. When the current set
/// grows past `max_size / 2`, it rotates: current becomes previous,
/// and a new empty set becomes current. This means the oldest hashes
/// are forgotten after two rotations.
pub struct PacketHashlist {
    current: BTreeSet<[u8; 32]>,
    previous: BTreeSet<[u8; 32]>,
    max_size: usize,
}

impl PacketHashlist {
    pub fn new(max_size: usize) -> Self {
        PacketHashlist {
            current: BTreeSet::new(),
            previous: BTreeSet::new(),
            max_size,
        }
    }

    /// Check if a hash is a duplicate (exists in current or previous set).
    pub fn is_duplicate(&self, hash: &[u8; 32]) -> bool {
        self.current.contains(hash) || self.previous.contains(hash)
    }

    /// Add a hash to the current set.
    pub fn add(&mut self, hash: [u8; 32]) {
        self.current.insert(hash);
    }

    /// Rotate if current set exceeds max_size / 2.
    /// Returns true if rotation occurred.
    pub fn maybe_rotate(&mut self) -> bool {
        if self.current.len() > self.max_size / 2 {
            let old_current = core::mem::take(&mut self.current);
            self.previous = old_current;
            true
        } else {
            false
        }
    }

    /// Total number of tracked hashes (current + previous).
    pub fn len(&self) -> usize {
        self.current.len() + self.previous.len()
    }

    /// Number of hashes in the current set only.
    pub fn current_len(&self) -> usize {
        self.current.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(seed: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = seed;
        h
    }

    #[test]
    fn test_new_hash_not_duplicate() {
        let hl = PacketHashlist::new(100);
        assert!(!hl.is_duplicate(&make_hash(1)));
    }

    #[test]
    fn test_added_hash_is_duplicate() {
        let mut hl = PacketHashlist::new(100);
        let h = make_hash(1);
        hl.add(h);
        assert!(hl.is_duplicate(&h));
    }

    #[test]
    fn test_after_rotation_old_hashes_still_detected() {
        let mut hl = PacketHashlist::new(4); // rotate at > 2
        let h1 = make_hash(1);
        let h2 = make_hash(2);
        let h3 = make_hash(3);
        hl.add(h1);
        hl.add(h2);
        hl.add(h3);

        // Force rotation
        assert!(hl.maybe_rotate());

        // Old hashes should still be found in previous
        assert!(hl.is_duplicate(&h1));
        assert!(hl.is_duplicate(&h2));
        assert!(hl.is_duplicate(&h3));
    }

    #[test]
    fn test_after_second_rotation_oldest_forgotten() {
        let mut hl = PacketHashlist::new(4); // rotate at > 2
        let h1 = make_hash(1);
        let h2 = make_hash(2);
        let h3 = make_hash(3);

        // Add to first generation
        hl.add(h1);
        hl.add(h2);
        hl.add(h3);
        hl.maybe_rotate(); // h1,h2,h3 now in previous

        // Add to second generation
        let h4 = make_hash(4);
        let h5 = make_hash(5);
        let h6 = make_hash(6);
        hl.add(h4);
        hl.add(h5);
        hl.add(h6);
        hl.maybe_rotate(); // h4,h5,h6 now in previous; h1,h2,h3 forgotten

        // First generation should be forgotten
        assert!(!hl.is_duplicate(&h1));
        assert!(!hl.is_duplicate(&h2));
        assert!(!hl.is_duplicate(&h3));

        // Second generation should still be detected
        assert!(hl.is_duplicate(&h4));
        assert!(hl.is_duplicate(&h5));
        assert!(hl.is_duplicate(&h6));
    }

    #[test]
    fn test_rotation_triggers_at_threshold() {
        let mut hl = PacketHashlist::new(6); // rotate at > 3
        hl.add(make_hash(1));
        hl.add(make_hash(2));
        hl.add(make_hash(3));
        assert!(!hl.maybe_rotate()); // 3 is not > 3

        hl.add(make_hash(4));
        assert!(hl.maybe_rotate()); // 4 > 3
    }

    #[test]
    fn test_len() {
        let mut hl = PacketHashlist::new(100);
        assert_eq!(hl.len(), 0);

        hl.add(make_hash(1));
        hl.add(make_hash(2));
        assert_eq!(hl.len(), 2);
    }
}
