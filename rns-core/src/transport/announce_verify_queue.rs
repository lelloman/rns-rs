use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::packet::RawPacket;

use super::types::InterfaceId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    DropNewest,
    DropOldest,
    DropWorst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AnnounceVerifyKey {
    pub destination_hash: [u8; 16],
    pub random_blob: [u8; 10],
    pub received_from: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct PendingAnnounce {
    pub original_raw: Vec<u8>,
    pub packet: RawPacket,
    pub interface: InterfaceId,
    pub received_from: [u8; 16],
    pub queued_at: f64,
    pub best_hops: u8,
    pub emission_ts: u64,
    pub random_blob: [u8; 10],
}

#[derive(Debug, Clone)]
pub enum QueueEntry {
    Pending(PendingAnnounce),
    InFlight(PendingAnnounce),
}

#[derive(Debug, Clone)]
pub struct AnnounceVerifyQueue {
    pending: BTreeMap<AnnounceVerifyKey, QueueEntry>,
    max_entries: usize,
    max_bytes: usize,
    max_stale_secs: f64,
    overflow_policy: OverflowPolicy,
    queued_bytes: usize,
}

impl AnnounceVerifyQueue {
    pub fn new(max_entries: usize) -> Self {
        Self::with_limits(max_entries, 256 * 1024, 30.0, OverflowPolicy::DropWorst)
    }

    pub fn with_limits(
        max_entries: usize,
        max_bytes: usize,
        max_stale_secs: f64,
        overflow_policy: OverflowPolicy,
    ) -> Self {
        Self {
            pending: BTreeMap::new(),
            max_entries: max_entries.max(1),
            max_bytes: max_bytes.max(1),
            max_stale_secs: max_stale_secs.max(0.001),
            overflow_policy,
            queued_bytes: 0,
        }
    }

    pub fn enqueue(&mut self, key: AnnounceVerifyKey, entry: PendingAnnounce) -> bool {
        if let Some(existing) = self.pending.get_mut(&key) {
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
        self.pending.insert(key, QueueEntry::Pending(entry));
        true
    }

    pub fn take_pending(&mut self, now: f64) -> Vec<(AnnounceVerifyKey, PendingAnnounce)> {
        let stale_before = now - self.max_stale_secs;
        let stale_keys: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(key, entry)| match entry {
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

        let keys: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(key, entry)| match entry {
                QueueEntry::Pending(_) => Some(*key),
                QueueEntry::InFlight(_) => None,
            })
            .collect();

        let mut drained = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(entry) = self.pending.get_mut(&key) {
                if let QueueEntry::Pending(current) = entry {
                    let cloned = current.clone();
                    *entry = QueueEntry::InFlight(cloned.clone());
                    drained.push((key, cloned));
                }
            }
        }

        drained
    }

    pub fn complete_success(&mut self, key: &AnnounceVerifyKey) -> Option<PendingAnnounce> {
        match self.remove_entry(key) {
            Some(QueueEntry::InFlight(entry)) => Some(entry),
            Some(QueueEntry::Pending(entry)) => Some(entry),
            None => None,
        }
    }

    pub fn complete_failure(&mut self, key: &AnnounceVerifyKey) -> bool {
        self.remove_entry(key).is_some()
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
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
                    queued_at_of(a.1)
                        .partial_cmp(&queued_at_of(b.1))
                        .unwrap_or(core::cmp::Ordering::Equal)
                })
                .map(|(key, _)| *key),
            OverflowPolicy::DropWorst => {
                let candidate = self
                    .pending
                    .iter()
                    .map(|(existing_key, existing_entry)| {
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
        let removed = self.pending.remove(key)?;
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
        + entry.packet.data.len()
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
                packet: make_packet(dest, hops, hops),
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
}
