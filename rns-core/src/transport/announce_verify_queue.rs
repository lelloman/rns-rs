use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::types::PacketBytes;
use crate::packet::RawPacket;

use super::types::InterfaceId;

/// What a full [`AnnounceVerifyQueue`] does with a new announce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    /// Reject the new announce.
    DropNewest,
    /// Evict the entry queued longest ago.
    DropOldest,
    /// Evict the entry with the most hops (the oldest among ties), unless the new announce has as many hops or more.
    DropWorst,
}

/// Identifies one announce copy awaiting verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AnnounceVerifyKey {
    /// Announced destination.
    pub destination_hash: [u8; 16],
    /// Random blob of the announce.
    pub random_blob: [u8; 10],
    /// Node the announce was received from.
    pub received_from: [u8; 16],
}

/// An announce queued for signature verification.
#[derive(Debug, Clone)]
pub struct PendingAnnounce {
    /// Frame bytes as received, before the hop count rewrite.
    pub original_raw: Vec<u8>,
    /// Parsed packet, with the hop count after this hop.
    pub packet: RawPacket<PacketBytes>,
    /// Interface the announce arrived on.
    pub interface: InterfaceId,
    /// Transport id of the sender for a HEADER_2 announce, else the destination hash.
    pub received_from: [u8; 16],
    /// When the announce was queued, in seconds.
    pub queued_at: f64,
    /// Hop count of the queued copy; a copy with fewer hops replaces it.
    pub best_hops: u8,
    /// Emission time read from the random blob, in seconds.
    pub emission_ts: u64,
    /// Random blob of the announce.
    pub random_blob: [u8; 10],
}

/// State of a queued announce.
#[derive(Debug, Clone)]
pub enum QueueEntry {
    /// Waiting to be taken for verification.
    Pending(PendingAnnounce),
    /// Taken by [`AnnounceVerifyQueue::take_pending`] and being verified.
    InFlight(PendingAnnounce),
}

/// Bounded queue of announces awaiting signature verification, one per [`AnnounceVerifyKey`].
#[derive(Debug, Clone)]
pub struct AnnounceVerifyQueue {
    /// Each entry with the arrival sequence number of its announce.
    pending: BTreeMap<AnnounceVerifyKey, (u64, QueueEntry)>,
    next_sequence: u64,
    max_entries: usize,
    max_bytes: usize,
    max_stale_secs: f64,
    overflow_policy: OverflowPolicy,
    queued_bytes: usize,
}

impl AnnounceVerifyQueue {
    /// Queue of at most `max_entries` announces, 256 KiB, entries stale after 30 seconds, evicting with [`OverflowPolicy::DropWorst`].
    pub fn new(max_entries: usize) -> Self {
        Self::with_limits(max_entries, 256 * 1024, 30.0, OverflowPolicy::DropWorst)
    }

    /// Queue with explicit limits: entry count, bytes, staleness in seconds and overflow policy.
    /// Each limit is raised to at least 1 (0.001 seconds for staleness).
    pub fn with_limits(
        max_entries: usize,
        max_bytes: usize,
        max_stale_secs: f64,
        overflow_policy: OverflowPolicy,
    ) -> Self {
        Self {
            pending: BTreeMap::new(),
            next_sequence: 0,
            max_entries: max_entries.max(1),
            max_bytes: max_bytes.max(1),
            max_stale_secs: max_stale_secs.max(0.001),
            overflow_policy,
            queued_bytes: 0,
        }
    }

    /// Queue an announce. Returns whether it was queued.
    ///
    /// A second copy under the same key replaces the first only with fewer hops.
    /// A full queue evicts according to its [`OverflowPolicy`] or rejects the
    /// announce.
    pub fn enqueue(&mut self, key: AnnounceVerifyKey, entry: PendingAnnounce) -> bool {
        if let Some((_, existing)) = self.pending.get_mut(&key) {
            return match existing {
                QueueEntry::Pending(current) | QueueEntry::InFlight(current) => {
                    if entry.best_hops < current.best_hops {
                        let current_bytes = pending_bytes(current);
                        let replacement_bytes = pending_bytes(&entry);
                        self.queued_bytes = self
                            .queued_bytes
                            .saturating_sub(current_bytes)
                            .saturating_add(replacement_bytes);
                        *current = entry;
                        true
                    } else {
                        false
                    }
                }
            };
        }

        let entry_bytes = pending_bytes(&entry);
        if entry_bytes > self.max_bytes {
            return false;
        }

        while self.pending.len() >= self.max_entries
            || self.queued_bytes.saturating_add(entry_bytes) > self.max_bytes
        {
            let Some(evict_key) = self.select_eviction_candidate(&entry) else {
                return false;
            };
            self.remove_entry(&evict_key);
        }

        self.queued_bytes = self.queued_bytes.saturating_add(entry_bytes);
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.pending
            .insert(key, (sequence, QueueEntry::Pending(entry)));
        true
    }

    /// Whether an announce for `destination_hash` is queued or being
    /// verified. A later announce for it must not be processed before it.
    pub fn has_destination(&self, destination_hash: &[u8; 16]) -> bool {
        let first = AnnounceVerifyKey {
            destination_hash: *destination_hash,
            random_blob: [0; 10],
            received_from: [0; 16],
        };
        let last = AnnounceVerifyKey {
            destination_hash: *destination_hash,
            random_blob: [0xFF; 10],
            received_from: [0xFF; 16],
        };
        self.pending.range(first..=last).next().is_some()
    }

    /// Take the pending announces for verification, in the order they
    /// arrived, as upstream processes inbound announces one at a time.
    pub fn take_pending(&mut self, now: f64) -> Vec<(AnnounceVerifyKey, PendingAnnounce)> {
        let stale_before = now - self.max_stale_secs;
        let stale_keys: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(key, (_, entry))| match entry {
                QueueEntry::Pending(current) | QueueEntry::InFlight(current)
                    if current.queued_at < stale_before =>
                {
                    Some(*key)
                }
                _ => None,
            })
            .collect();
        for key in stale_keys {
            self.remove_entry(&key);
        }

        let mut keys: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(key, (sequence, entry))| match entry {
                QueueEntry::Pending(_) => Some((*sequence, *key)),
                QueueEntry::InFlight(_) => None,
            })
            .collect();
        keys.sort_unstable_by_key(|(sequence, _)| *sequence);

        let mut drained = Vec::with_capacity(keys.len());
        for (_, key) in keys {
            if let Some((_, entry)) = self.pending.get_mut(&key) {
                if let QueueEntry::Pending(current) = entry {
                    let cloned = current.clone();
                    *entry = QueueEntry::InFlight(cloned.clone());
                    drained.push((key, cloned));
                }
            }
        }

        drained
    }

    /// Remove a verified announce and return it.
    pub fn complete_success(&mut self, key: &AnnounceVerifyKey) -> Option<PendingAnnounce> {
        match self.remove_entry(key) {
            Some(QueueEntry::InFlight(entry)) => Some(entry),
            Some(QueueEntry::Pending(entry)) => Some(entry),
            None => None,
        }
    }

    /// Remove an announce that failed verification. Returns whether it was queued.
    pub fn complete_failure(&mut self, key: &AnnounceVerifyKey) -> bool {
        self.remove_entry(key).is_some()
    }

    /// Interface the announce under `key` arrived on.
    pub fn pending_interface(&self, key: &AnnounceVerifyKey) -> Option<InterfaceId> {
        self.pending
            .get(key)
            .map(|(_, entry)| pending_of(entry).interface)
    }

    /// The size of a pending announce as received.
    pub fn pending_size(&self, key: &AnnounceVerifyKey) -> Option<usize> {
        self.pending
            .get(key)
            .map(|(_, entry)| pending_of(entry).original_raw.len())
    }

    /// Identity hash of the public key in the announce under `key`.
    pub fn pending_identity_hash(&self, key: &AnnounceVerifyKey) -> Option<[u8; 16]> {
        let packet = &pending_of(&self.pending.get(key)?.1).packet;
        Some(crate::hash::truncated_hash(packet.data().get(..64)?))
    }

    /// Number of queued announces, pending or in flight.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether no announce is queued.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Bytes counted against the byte limit: raw frame, packet data and transport id of each entry.
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Remove every entry.
    pub fn clear(&mut self) {
        self.pending.clear();
        self.queued_bytes = 0;
    }

    fn select_eviction_candidate(
        &self,
        incoming_entry: &PendingAnnounce,
    ) -> Option<AnnounceVerifyKey> {
        match self.overflow_policy {
            OverflowPolicy::DropNewest => None,
            OverflowPolicy::DropOldest => self
                .pending
                .iter()
                .min_by(|a, b| {
                    queued_at_of(&a.1 .1)
                        .partial_cmp(&queued_at_of(&b.1 .1))
                        .unwrap_or(core::cmp::Ordering::Equal)
                })
                .map(|(key, _)| *key),
            OverflowPolicy::DropWorst => {
                let candidate = self
                    .pending
                    .iter()
                    .map(|(existing_key, (_, existing_entry))| {
                        (*existing_key, pending_of(existing_entry))
                    })
                    .max_by(|a, b| {
                        a.1.best_hops.cmp(&b.1.best_hops).then_with(|| {
                            a.1.queued_at
                                .partial_cmp(&b.1.queued_at)
                                .unwrap_or(core::cmp::Ordering::Equal)
                        })
                    })?;
                if incoming_entry.best_hops >= candidate.1.best_hops {
                    None
                } else {
                    Some(candidate.0)
                }
            }
        }
    }

    fn remove_entry(&mut self, key: &AnnounceVerifyKey) -> Option<QueueEntry> {
        let (_, removed) = self.pending.remove(key)?;
        self.queued_bytes = self
            .queued_bytes
            .saturating_sub(pending_bytes(pending_of(&removed)));
        Some(removed)
    }
}

fn pending_of(entry: &QueueEntry) -> &PendingAnnounce {
    match entry {
        QueueEntry::Pending(current) | QueueEntry::InFlight(current) => current,
    }
}

fn queued_at_of(entry: &QueueEntry) -> f64 {
    pending_of(entry).queued_at
}

fn pending_bytes(entry: &PendingAnnounce) -> usize {
    entry.original_raw.len()
        + entry.packet.data().len()
        + entry.packet.transport_id.as_ref().map_or(0, |id| id.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants;
    use crate::packet::{PacketFlags, RawPacket};

    fn make_packet(dest: [u8; 16], hops: u8, fill: u8) -> RawPacket {
        RawPacket::pack(
            PacketFlags {
                header_type: constants::HEADER_1,
                context_flag: constants::FLAG_UNSET,
                transport_type: constants::TRANSPORT_BROADCAST,
                destination_type: constants::DESTINATION_SINGLE,
                packet_type: constants::PACKET_TYPE_ANNOUNCE,
            },
            hops,
            &dest,
            None,
            constants::CONTEXT_NONE,
            &[fill; 8],
        )
        .unwrap()
    }

    fn make_pending(
        dest: [u8; 16],
        random_blob: [u8; 10],
        received_from: [u8; 16],
        hops: u8,
    ) -> (AnnounceVerifyKey, PendingAnnounce) {
        (
            AnnounceVerifyKey {
                destination_hash: dest,
                random_blob,
                received_from,
            },
            PendingAnnounce {
                original_raw: vec![hops],
                packet: make_packet(dest, hops, hops).map_raw(PacketBytes::from),
                interface: InterfaceId(1),
                received_from,
                queued_at: 10.0,
                best_hops: hops,
                emission_ts: 42,
                random_blob,
            },
        )
    }

    #[test]
    fn announces_are_taken_in_arrival_order() {
        let mut queue = AnnounceVerifyQueue::new(8);
        let arrivals = [
            make_pending([3; 16], [9; 10], [1; 16], 1),
            make_pending([1; 16], [5; 10], [1; 16], 1),
            make_pending([1; 16], [2; 10], [1; 16], 1),
        ];
        for (key, entry) in arrivals.clone() {
            assert!(queue.enqueue(key, entry));
        }
        assert!(queue.has_destination(&[1; 16]));
        assert!(!queue.has_destination(&[2; 16]));

        let taken: Vec<_> = queue
            .take_pending(10.0)
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        let expected: Vec<_> = arrivals.iter().map(|(key, _)| *key).collect();
        assert_eq!(taken, expected);
        // An announce being verified still holds its destination.
        assert!(queue.has_destination(&[1; 16]));
        queue.complete_success(&expected[1]);
        queue.complete_success(&expected[2]);
        assert!(!queue.has_destination(&[1; 16]));
    }

    #[test]
    fn enqueue_replaces_lower_hops_and_preserves_distinct_paths() {
        let mut queue = AnnounceVerifyQueue::new(8);
        let dest = [1; 16];
        let random = [2; 10];
        let rx_a = [3; 16];
        let rx_b = [4; 16];

        let (key_a, entry_a) = make_pending(dest, random, rx_a, 5);
        assert!(queue.enqueue(key_a, entry_a));

        let (_, better_a) = make_pending(dest, random, rx_a, 3);
        assert!(queue.enqueue(key_a, better_a));
        assert_eq!(queue.len(), 1);

        let (key_b, entry_b) = make_pending(dest, random, rx_b, 4);
        assert!(queue.enqueue(key_b, entry_b));
        assert_eq!(queue.len(), 2);

        let taken = queue.take_pending(10.0);
        assert_eq!(taken.len(), 2);
        assert!(taken
            .iter()
            .any(|(key, entry)| *key == key_a && entry.best_hops == 3));
        assert!(taken
            .iter()
            .any(|(key, entry)| *key == key_b && entry.best_hops == 4));
    }

    #[test]
    fn enqueue_updates_inflight_and_cleans_stale_entries() {
        let mut queue = AnnounceVerifyQueue::new(2);
        let dest = [8; 16];
        let random = [9; 10];
        let recv = [10; 16];

        let (key, entry) = make_pending(dest, random, recv, 6);
        assert!(queue.enqueue(key, entry));
        let _ = queue.take_pending(20.0);

        let (_, better) = make_pending(dest, random, recv, 2);
        assert!(queue.enqueue(key, better));
        let completed = queue.complete_success(&key).unwrap();
        assert_eq!(completed.best_hops, 2);

        let (stale_key, mut stale) = make_pending([11; 16], [12; 10], [13; 16], 7);
        stale.queued_at = 1.0;
        assert!(queue.enqueue(stale_key, stale));
        assert!(queue.take_pending(40.0).is_empty());
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn enqueue_evicts_worst_entry_when_full() {
        let mut queue = AnnounceVerifyQueue::with_limits(2, 1024, 30.0, OverflowPolicy::DropWorst);
        let (k1, e1) = make_pending([1; 16], [1; 10], [1; 16], 8);
        let (k2, e2) = make_pending([2; 16], [2; 10], [2; 16], 5);
        let (k3, e3) = make_pending([3; 16], [3; 10], [3; 16], 4);
        let (_, e4) = make_pending([4; 16], [4; 10], [4; 16], 9);

        assert!(queue.enqueue(k1, e1));
        assert!(queue.enqueue(k2, e2));
        assert!(queue.enqueue(k3, e3));
        assert_eq!(queue.len(), 2);
        assert!(!queue.enqueue(
            AnnounceVerifyKey {
                destination_hash: [4; 16],
                random_blob: [4; 10],
                received_from: [4; 16],
            },
            e4
        ));

        let taken = queue.take_pending(10.0);
        assert_eq!(taken.len(), 2);
        assert!(taken.iter().all(|(key, _)| *key != k1));
    }

    #[test]
    fn drop_newest_policy_rejects_when_full() {
        let mut queue = AnnounceVerifyQueue::with_limits(1, 1024, 30.0, OverflowPolicy::DropNewest);
        let (k1, e1) = make_pending([1; 16], [1; 10], [1; 16], 4);
        let (k2, e2) = make_pending([2; 16], [2; 10], [2; 16], 1);
        assert!(queue.enqueue(k1, e1));
        assert!(!queue.enqueue(k2, e2));
        let taken = queue.take_pending(10.0);
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].0, k1);
    }

    #[test]
    fn drop_oldest_policy_evicts_oldest_for_byte_cap() {
        let mut queue = AnnounceVerifyQueue::with_limits(4, 24, 30.0, OverflowPolicy::DropOldest);
        let (k1, mut e1) = make_pending([1; 16], [1; 10], [1; 16], 4);
        let (k2, mut e2) = make_pending([2; 16], [2; 10], [2; 16], 3);
        e1.original_raw = vec![1; 12];
        e2.original_raw = vec![2; 12];
        e1.queued_at = 1.0;
        e2.queued_at = 2.0;
        assert!(queue.enqueue(k1, e1));
        assert!(queue.enqueue(k2, e2));
        assert_eq!(queue.len(), 1);
        let taken = queue.take_pending(10.0);
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].0, k2);
    }

    #[test]
    fn clear_removes_pending_and_inflight_entries_and_resets_bytes() {
        let mut queue = AnnounceVerifyQueue::new(4);
        let (pending_key, pending) = make_pending([1; 16], [1; 10], [1; 16], 4);
        let (inflight_key, inflight) = make_pending([2; 16], [2; 10], [2; 16], 3);
        assert!(queue.enqueue(pending_key, pending));
        assert!(queue.enqueue(inflight_key, inflight));
        let _ = queue.take_pending(10.0);

        assert_eq!(queue.len(), 2);
        assert!(queue.queued_bytes() > 0);

        queue.clear();

        assert!(queue.is_empty());
        assert_eq!(queue.queued_bytes(), 0);
        assert!(queue.take_pending(10.0).is_empty());
    }

    fn key_of(dest: u8) -> AnnounceVerifyKey {
        AnnounceVerifyKey {
            destination_hash: [dest; 16],
            random_blob: [dest; 10],
            received_from: [dest; 16],
        }
    }

    #[test]
    fn enqueue_keeps_the_queued_entry_against_equal_hops() {
        let mut queue = AnnounceVerifyQueue::new(8);
        let (key, mut first) = make_pending([1; 16], [2; 10], [3; 16], 4);
        first.interface = InterfaceId(1);
        assert!(queue.enqueue(key, first));
        let (_, mut second) = make_pending([1; 16], [2; 10], [3; 16], 4);
        second.interface = InterfaceId(2);
        assert!(!queue.enqueue(key, second));
        assert_eq!(queue.pending_interface(&key), Some(InterfaceId(1)));
    }

    #[test]
    fn enqueue_admits_an_entry_that_exactly_fills_the_byte_cap() {
        let (key, entry) = make_pending([1; 16], [1; 10], [1; 16], 4);
        let size = pending_bytes(&entry);
        let mut queue = AnnounceVerifyQueue::with_limits(4, size, 30.0, OverflowPolicy::DropNewest);
        assert!(queue.enqueue(key, entry));
        assert_eq!(queue.queued_bytes(), size);

        // A second entry that exactly fills the remaining room needs no
        // eviction either.
        let (first_key, first) = make_pending([2; 16], [2; 10], [2; 16], 4);
        let (second_key, second) = make_pending([3; 16], [3; 10], [3; 16], 4);
        let mut queue =
            AnnounceVerifyQueue::with_limits(4, 2 * size, 30.0, OverflowPolicy::DropNewest);
        assert!(queue.enqueue(first_key, first));
        assert!(queue.enqueue(second_key, second));
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn oversized_entry_is_refused_without_evicting_anything() {
        let (key, entry) = make_pending([1; 16], [1; 10], [1; 16], 4);
        let size = pending_bytes(&entry);
        let mut queue =
            AnnounceVerifyQueue::with_limits(4, size + 1, 30.0, OverflowPolicy::DropWorst);
        assert!(queue.enqueue(key, entry));

        let (big_key, mut big) = make_pending([2; 16], [2; 10], [2; 16], 1);
        big.original_raw = vec![0; size + 2];
        assert!(!queue.enqueue(big_key, big));
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.pending_size(&key), Some(1));
    }

    #[test]
    fn entries_go_stale_only_after_max_stale_secs() {
        let mut queue = AnnounceVerifyQueue::with_limits(4, 1024, 30.0, OverflowPolicy::DropWorst);
        let (key, mut entry) = make_pending([1; 16], [1; 10], [1; 16], 4);
        entry.queued_at = 20.0;
        assert!(queue.enqueue(key, entry));

        // Exactly max_stale_secs after queueing it is still taken.
        assert_eq!(queue.take_pending(50.0).len(), 1);
        assert_eq!(queue.len(), 1);
        // Past that it is dropped, in flight or not.
        assert!(queue.take_pending(50.5).is_empty());
        assert!(queue.is_empty());
        assert_eq!(queue.queued_bytes(), 0);
    }

    #[test]
    fn completion_reports_whether_the_entry_was_queued() {
        let mut queue = AnnounceVerifyQueue::new(4);
        let (key, entry) = make_pending([1; 16], [1; 10], [1; 16], 4);
        assert!(queue.enqueue(key, entry));
        assert!(!queue.is_empty());
        assert!(queue.complete_failure(&key));
        assert!(!queue.complete_failure(&key));
        assert!(queue.is_empty());
    }

    #[test]
    fn pending_lookups_describe_the_queued_announce() {
        let mut queue = AnnounceVerifyQueue::new(4);
        let (key, mut entry) = make_pending([1; 16], [1; 10], [1; 16], 4);
        entry.interface = InterfaceId(7);
        entry.original_raw = vec![0; 5];
        let mut data = [0u8; 70];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = i as u8;
        }
        entry.packet = RawPacket::pack(
            entry.packet.flags,
            4,
            &[1; 16],
            None,
            constants::CONTEXT_NONE,
            &data,
        )
        .unwrap()
        .map_raw(PacketBytes::from);
        assert!(queue.enqueue(key, entry));

        assert_eq!(queue.pending_interface(&key), Some(InterfaceId(7)));
        assert_eq!(queue.pending_size(&key), Some(5));
        assert_eq!(
            queue.pending_identity_hash(&key),
            Some(crate::hash::truncated_hash(&data[..64]))
        );

        let missing = key_of(9);
        assert_eq!(queue.pending_interface(&missing), None);
        assert_eq!(queue.pending_size(&missing), None);
        assert_eq!(queue.pending_identity_hash(&missing), None);
    }

    #[test]
    fn drop_oldest_evicts_by_queue_time_not_key_order() {
        let mut queue = AnnounceVerifyQueue::with_limits(2, 1024, 30.0, OverflowPolicy::DropOldest);
        let (newer_key, mut newer) = make_pending([1; 16], [1; 10], [1; 16], 4);
        newer.queued_at = 12.0;
        let (older_key, mut older) = make_pending([2; 16], [2; 10], [2; 16], 4);
        older.queued_at = 11.0;
        let (key, entry) = make_pending([3; 16], [3; 10], [3; 16], 4);
        assert!(queue.enqueue(newer_key, newer));
        assert!(queue.enqueue(older_key, older));
        assert!(queue.enqueue(key, entry));
        assert!(queue.pending_size(&older_key).is_none());
        assert!(queue.pending_size(&newer_key).is_some());
    }

    #[test]
    fn queued_bytes_count_the_transport_id() {
        let mut queue = AnnounceVerifyQueue::new(4);
        let (key, mut entry) = make_pending([1; 16], [1; 10], [1; 16], 4);
        let flags = PacketFlags {
            header_type: constants::HEADER_2,
            ..entry.packet.flags
        };
        entry.packet = RawPacket::pack(
            flags,
            4,
            &[1; 16],
            Some(&[5; 16]),
            constants::CONTEXT_NONE,
            &[4; 8],
        )
        .unwrap()
        .map_raw(PacketBytes::from);
        assert!(queue.enqueue(key, entry));
        assert_eq!(queue.queued_bytes(), 1 + 8 + 16);
    }
}
