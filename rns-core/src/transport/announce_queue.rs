//! Per-interface announce bandwidth queuing.
//!
//! Announces with hops > 0 (propagation, not locally-originated) are gated
//! by a per-interface bandwidth cap (default 2%). When bandwidth is exhausted,
//! announces are queued and released when bandwidth becomes available.
//!
//! Python reference: Transport.py:1085-1165, Interface.py:246-286

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::types::{InterfaceId, TransportAction};
use crate::constants;

/// A queued announce entry waiting for bandwidth availability.
#[derive(Debug, Clone)]
pub struct AnnounceQueueEntry {
    /// Destination hash of the announce.
    pub destination_hash: [u8; 16],
    /// Time the announce was queued.
    pub time: f64,
    /// Hops from the announce.
    pub hops: u8,
    /// Time the announce was originally emitted (from random blob).
    pub emitted: f64,
    /// Raw announce bytes (ready to send).
    pub raw: Vec<u8>,
}

/// Per-interface announce queue with bandwidth tracking.
#[derive(Debug, Clone)]
pub struct InterfaceAnnounceQueue {
    /// Queued announce entries.
    pub entries: Vec<AnnounceQueueEntry>,
    /// Earliest time another announce is allowed on this interface.
    pub announce_allowed_at: f64,
}

impl InterfaceAnnounceQueue {
    pub fn new() -> Self {
        InterfaceAnnounceQueue {
            entries: Vec::new(),
            announce_allowed_at: 0.0,
        }
    }

    /// Insert an announce into the queue.
    /// If an entry for the same destination already exists, update it if the new one
    /// has fewer hops or is newer.
    pub fn insert(&mut self, entry: AnnounceQueueEntry) {
        // Check for existing entry with same destination
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| e.destination_hash == entry.destination_hash)
        {
            let existing = &self.entries[pos];
            // Update if new entry has fewer hops, or same hops and newer
            if entry.hops < existing.hops
                || (entry.hops == existing.hops && entry.emitted > existing.emitted)
            {
                self.entries[pos] = entry;
            }
            // Otherwise discard the new entry
        } else {
            // Enforce max queue size
            if self.entries.len() >= constants::MAX_QUEUED_ANNOUNCES {
                // Drop oldest entry
                self.entries.remove(0);
            }
            self.entries.push(entry);
        }
    }

    /// Remove stale entries (older than QUEUED_ANNOUNCE_LIFE).
    pub fn remove_stale(&mut self, now: f64) {
        self.entries
            .retain(|e| now - e.time < constants::QUEUED_ANNOUNCE_LIFE);
    }

    /// Select the next announce to send: minimum hops, then oldest (FIFO).
    /// Returns the index of the selected entry, or None if empty.
    pub fn select_next(&self) -> Option<usize> {
        if self.entries.is_empty() {
            return None;
        }
        let mut best_idx = 0;
        let mut best_hops = self.entries[0].hops;
        let mut best_time = self.entries[0].time;

        for (i, entry) in self.entries.iter().enumerate().skip(1) {
            if entry.hops < best_hops
                || (entry.hops == best_hops && entry.time < best_time)
            {
                best_idx = i;
                best_hops = entry.hops;
                best_time = entry.time;
            }
        }
        Some(best_idx)
    }

    /// Check if an announce is allowed now based on bandwidth.
    pub fn is_allowed(&self, now: f64) -> bool {
        now >= self.announce_allowed_at
    }

    /// Calculate the next allowed time after sending an announce.
    /// `raw_len`: size of the announce in bytes
    /// `bitrate`: interface bitrate in bits/second
    /// `announce_cap`: fraction of bitrate reserved for announces
    pub fn calculate_next_allowed(now: f64, raw_len: usize, bitrate: u64, announce_cap: f64) -> f64 {
        if bitrate == 0 || announce_cap <= 0.0 {
            return now; // no cap
        }
        let bits = (raw_len * 8) as f64;
        let time_to_send = bits / (bitrate as f64);
        let delay = time_to_send / announce_cap;
        now + delay
    }
}

/// Manage announce queues for all interfaces.
#[derive(Debug, Clone)]
pub struct AnnounceQueues {
    queues: BTreeMap<InterfaceId, InterfaceAnnounceQueue>,
}

impl AnnounceQueues {
    pub fn new() -> Self {
        AnnounceQueues {
            queues: BTreeMap::new(),
        }
    }

    /// Try to send an announce on an interface. If bandwidth is available,
    /// returns the action immediately. Otherwise, queues it.
    ///
    /// Returns Some(action) if the announce should be sent now, None if queued.
    pub fn gate_announce(
        &mut self,
        interface: InterfaceId,
        raw: Vec<u8>,
        dest_hash: [u8; 16],
        hops: u8,
        emitted: f64,
        now: f64,
        bitrate: Option<u64>,
        announce_cap: f64,
    ) -> Option<TransportAction> {
        let queue = self
            .queues
            .entry(interface)
            .or_insert_with(InterfaceAnnounceQueue::new);

        // If no bitrate, no cap applies — send immediately
        let bitrate = match bitrate {
            Some(br) if br > 0 => br,
            _ => {
                return Some(TransportAction::SendOnInterface {
                    interface,
                    raw,
                });
            }
        };

        if queue.is_allowed(now) {
            // Bandwidth available — send now and update allowed_at
            queue.announce_allowed_at =
                InterfaceAnnounceQueue::calculate_next_allowed(now, raw.len(), bitrate, announce_cap);
            Some(TransportAction::SendOnInterface { interface, raw })
        } else {
            // Queue the announce
            queue.insert(AnnounceQueueEntry {
                destination_hash: dest_hash,
                time: now,
                hops,
                emitted,
                raw,
            });
            None
        }
    }

    /// Process all announce queues: dequeue and send when bandwidth is available.
    /// Called from tick().
    pub fn process_queues(
        &mut self,
        now: f64,
        interfaces: &BTreeMap<InterfaceId, super::types::InterfaceInfo>,
    ) -> Vec<TransportAction> {
        let mut actions = Vec::new();

        for (iface_id, queue) in self.queues.iter_mut() {
            // Remove stale entries
            queue.remove_stale(now);

            // Process as many announces as bandwidth allows
            while queue.is_allowed(now) {
                if let Some(idx) = queue.select_next() {
                    let entry = queue.entries.remove(idx);

                    // Look up bitrate for this interface
                    let (bitrate, announce_cap) =
                        if let Some(info) = interfaces.get(iface_id) {
                            (info.bitrate.unwrap_or(0), info.announce_cap)
                        } else {
                            (0, constants::ANNOUNCE_CAP)
                        };

                    if bitrate > 0 {
                        queue.announce_allowed_at =
                            InterfaceAnnounceQueue::calculate_next_allowed(
                                now,
                                entry.raw.len(),
                                bitrate,
                                announce_cap,
                            );
                    }

                    actions.push(TransportAction::SendOnInterface {
                        interface: *iface_id,
                        raw: entry.raw,
                    });
                } else {
                    break;
                }
            }
        }

        actions
    }

    /// Get the queue for a specific interface (for testing).
    #[cfg(test)]
    pub fn queue_for(&self, id: &InterfaceId) -> Option<&InterfaceAnnounceQueue> {
        self.queues.get(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    fn make_entry(dest: u8, hops: u8, time: f64) -> AnnounceQueueEntry {
        AnnounceQueueEntry {
            destination_hash: [dest; 16],
            time,
            hops,
            emitted: time,
            raw: vec![0x01, 0x02, 0x03],
        }
    }

    fn make_interface_info(id: u64, bitrate: Option<u64>) -> super::super::types::InterfaceInfo {
        super::super::types::InterfaceInfo {
            id: InterfaceId(id),
            name: String::from("test"),
            mode: crate::constants::MODE_FULL,
            out_capable: true,
            in_capable: true,
            bitrate,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
        }
    }

    // --- InterfaceAnnounceQueue tests ---

    #[test]
    fn test_queue_entry_creation() {
        let entry = make_entry(0xAA, 3, 1000.0);
        assert_eq!(entry.hops, 3);
        assert_eq!(entry.destination_hash, [0xAA; 16]);
    }

    #[test]
    fn test_queue_insert_and_select() {
        let mut queue = InterfaceAnnounceQueue::new();
        queue.insert(make_entry(0x01, 3, 100.0));
        queue.insert(make_entry(0x02, 1, 200.0));
        queue.insert(make_entry(0x03, 2, 150.0));

        // Should select min hops first (0x02 with hops=1)
        let idx = queue.select_next().unwrap();
        assert_eq!(queue.entries[idx].destination_hash, [0x02; 16]);
    }

    #[test]
    fn test_queue_select_fifo_on_same_hops() {
        let mut queue = InterfaceAnnounceQueue::new();
        queue.insert(make_entry(0x01, 2, 200.0)); // newer
        queue.insert(make_entry(0x02, 2, 100.0)); // older

        // Same hops — should pick oldest (0x02 at time 100)
        let idx = queue.select_next().unwrap();
        assert_eq!(queue.entries[idx].destination_hash, [0x02; 16]);
    }

    #[test]
    fn test_queue_dedup_update() {
        let mut queue = InterfaceAnnounceQueue::new();
        queue.insert(make_entry(0x01, 3, 100.0));
        assert_eq!(queue.entries.len(), 1);

        // Insert same dest with fewer hops — should update
        queue.insert(make_entry(0x01, 1, 200.0));
        assert_eq!(queue.entries.len(), 1);
        assert_eq!(queue.entries[0].hops, 1);

        // Insert same dest with more hops — should NOT update
        queue.insert(make_entry(0x01, 5, 300.0));
        assert_eq!(queue.entries.len(), 1);
        assert_eq!(queue.entries[0].hops, 1);
    }

    #[test]
    fn test_queue_stale_removal() {
        let mut queue = InterfaceAnnounceQueue::new();
        queue.insert(make_entry(0x01, 1, 100.0));
        queue.insert(make_entry(0x02, 2, 200.0));

        // At time 100 + 86400 + 1 = 86501, entry 0x01 should be stale
        queue.remove_stale(86501.0);
        assert_eq!(queue.entries.len(), 1);
        assert_eq!(queue.entries[0].destination_hash, [0x02; 16]);
    }

    #[test]
    fn test_queue_max_size() {
        let mut queue = InterfaceAnnounceQueue::new();
        for i in 0..constants::MAX_QUEUED_ANNOUNCES {
            queue.insert(AnnounceQueueEntry {
                destination_hash: {
                    let mut d = [0u8; 16];
                    d[0] = (i >> 8) as u8;
                    d[1] = i as u8;
                    d
                },
                time: i as f64,
                hops: 1,
                emitted: i as f64,
                raw: vec![0x01],
            });
        }
        assert_eq!(queue.entries.len(), constants::MAX_QUEUED_ANNOUNCES);

        // Add one more — oldest should be dropped
        queue.insert(make_entry(0xFF, 1, 99999.0));
        assert_eq!(queue.entries.len(), constants::MAX_QUEUED_ANNOUNCES);
    }

    #[test]
    fn test_queue_empty_select() {
        let queue = InterfaceAnnounceQueue::new();
        assert!(queue.select_next().is_none());
    }

    #[test]
    fn test_bandwidth_allowed() {
        let mut queue = InterfaceAnnounceQueue::new();
        assert!(queue.is_allowed(0.0));
        assert!(queue.is_allowed(100.0));

        queue.announce_allowed_at = 200.0;
        assert!(!queue.is_allowed(100.0));
        assert!(!queue.is_allowed(199.9));
        assert!(queue.is_allowed(200.0));
        assert!(queue.is_allowed(300.0));
    }

    #[test]
    fn test_calculate_next_allowed() {
        // 100 bytes = 800 bits, bitrate = 1000 bps, cap = 0.02
        // time_to_send = 800/1000 = 0.8s
        // delay = 0.8 / 0.02 = 40.0s
        let next = InterfaceAnnounceQueue::calculate_next_allowed(1000.0, 100, 1000, 0.02);
        assert!((next - 1040.0).abs() < 0.001);
    }

    #[test]
    fn test_calculate_next_allowed_zero_bitrate() {
        let next = InterfaceAnnounceQueue::calculate_next_allowed(1000.0, 100, 0, 0.02);
        assert_eq!(next, 1000.0); // no cap
    }

    // --- AnnounceQueues tests ---

    #[test]
    fn test_gate_announce_no_bitrate_immediate() {
        let mut queues = AnnounceQueues::new();
        let result = queues.gate_announce(
            InterfaceId(1),
            vec![0x01, 0x02, 0x03],
            [0xAA; 16],
            2,
            1000.0,
            1000.0,
            None, // no bitrate
            0.02,
        );
        assert!(result.is_some());
        assert!(matches!(
            result.unwrap(),
            TransportAction::SendOnInterface { .. }
        ));
    }

    #[test]
    fn test_gate_announce_bandwidth_available() {
        let mut queues = AnnounceQueues::new();
        let result = queues.gate_announce(
            InterfaceId(1),
            vec![0x01; 100],
            [0xBB; 16],
            2,
            1000.0,
            1000.0,
            Some(10000), // 10 kbps
            0.02,
        );
        // First announce should go through
        assert!(result.is_some());

        // Check that allowed_at was updated
        let queue = queues.queue_for(&InterfaceId(1)).unwrap();
        assert!(queue.announce_allowed_at > 1000.0);
    }

    #[test]
    fn test_gate_announce_bandwidth_exhausted_queues() {
        let mut queues = AnnounceQueues::new();

        // First announce goes through
        let r1 = queues.gate_announce(
            InterfaceId(1),
            vec![0x01; 100],
            [0xAA; 16],
            2,
            1000.0,
            1000.0,
            Some(1000), // 1 kbps — very slow
            0.02,
        );
        assert!(r1.is_some());

        // Second announce at same time should be queued
        let r2 = queues.gate_announce(
            InterfaceId(1),
            vec![0x02; 100],
            [0xBB; 16],
            3,
            1000.0,
            1000.0,
            Some(1000),
            0.02,
        );
        assert!(r2.is_none()); // queued

        let queue = queues.queue_for(&InterfaceId(1)).unwrap();
        assert_eq!(queue.entries.len(), 1);
    }

    #[test]
    fn test_process_queues_dequeues_when_allowed() {
        let mut queues = AnnounceQueues::new();

        // Queue an announce by exhausting bandwidth first
        let _ = queues.gate_announce(
            InterfaceId(1),
            vec![0x01; 10],
            [0xAA; 16],
            2,
            0.0,
            0.0,
            Some(1000),
            0.02,
        );
        let _ = queues.gate_announce(
            InterfaceId(1),
            vec![0x02; 10],
            [0xBB; 16],
            3,
            0.0,
            0.0,
            Some(1000),
            0.02,
        );

        // Queue should have one entry
        assert_eq!(queues.queue_for(&InterfaceId(1)).unwrap().entries.len(), 1);

        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface_info(1, Some(1000)));

        // Process at a future time when bandwidth is available
        let allowed_at = queues.queue_for(&InterfaceId(1)).unwrap().announce_allowed_at;
        let actions = queues.process_queues(allowed_at + 1.0, &interfaces);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            TransportAction::SendOnInterface { interface, .. } if *interface == InterfaceId(1)
        ));

        // Queue should be empty now
        assert_eq!(queues.queue_for(&InterfaceId(1)).unwrap().entries.len(), 0);
    }

    #[test]
    fn test_local_announce_bypasses_cap() {
        // hops == 0 means locally-originated, should not be queued
        // The caller (TransportEngine) is responsible for only calling gate_announce
        // for hops > 0. We verify the gate_announce works for hops=0 too.
        let mut queues = AnnounceQueues::new();

        // Exhaust bandwidth
        let _ = queues.gate_announce(
            InterfaceId(1),
            vec![0x01; 100],
            [0xAA; 16],
            2,
            0.0,
            0.0,
            Some(1000),
            0.02,
        );

        // hops=0 should still be queued by gate_announce since hops filtering
        // is the caller's responsibility. gate_announce is agnostic.
        let r = queues.gate_announce(
            InterfaceId(1),
            vec![0x02; 100],
            [0xBB; 16],
            0,
            0.0,
            0.0,
            Some(1000),
            0.02,
        );
        assert!(r.is_none()); // queued — caller must bypass for hops==0
    }
}
