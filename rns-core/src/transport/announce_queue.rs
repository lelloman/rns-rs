//! Per-interface announce bandwidth queuing.
//!
//! Announces with hops > 0 (propagation, not locally-originated) are gated
//! by a per-interface bandwidth cap (default 2%). When bandwidth is exhausted,
//! announces are queued and released when bandwidth becomes available.
//!
//! Python reference: Transport.py:1085-1165, Interface.py:246-286

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::types::{AirtimeProfile, InterfaceId, PacketBytes, TransportAction};
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
    pub raw: PacketBytes,
}

/// When the announce in `raw` was emitted, from its random blob, as
/// upstream's `Transport.announce_emitted` reads it.
pub fn announce_emitted(raw: &[u8]) -> Option<f64> {
    let header_type = (*raw.first()? >> 6) & 0x03;
    let data_start = if header_type == constants::HEADER_2 {
        2 + 2 * (constants::TRUNCATED_HASHLENGTH / 8) + 1
    } else {
        2 + constants::TRUNCATED_HASHLENGTH / 8 + 1
    };
    let blob = super::pathfinder::extract_random_blob(raw.get(data_start..)?)?;
    Some(super::pathfinder::timebase_from_random_blob(&blob) as f64)
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
    ///
    /// As upstream's `Transport.outbound` does, a full queue takes nothing
    /// more, and an announce for a destination already queued replaces the
    /// queued one only when it was emitted later.
    pub fn insert(&mut self, entry: AnnounceQueueEntry) {
        if self.entries.len() >= constants::MAX_QUEUED_ANNOUNCES {
            return;
        }
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.destination_hash == entry.destination_hash)
        {
            if entry.emitted > existing.emitted {
                *existing = entry;
            }
        } else {
            self.entries.push(entry);
        }
    }

    /// Remove stale entries, those queued more than QUEUED_ANNOUNCE_LIFE ago.
    pub fn remove_stale(&mut self, now: f64) {
        self.entries
            .retain(|e| now - e.time <= constants::QUEUED_ANNOUNCE_LIFE);
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
            if entry.hops < best_hops || (entry.hops == best_hops && entry.time < best_time) {
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
    pub fn calculate_next_allowed(
        now: f64,
        raw_len: usize,
        bitrate: u64,
        airtime_profile: Option<AirtimeProfile>,
        announce_cap: f64,
    ) -> f64 {
        if announce_cap <= 0.0 {
            return now; // no cap
        }

        let time_to_send = airtime_profile
            .map(|profile| profile.transmit_time_secs(raw_len))
            .unwrap_or_else(|| {
                if bitrate == 0 {
                    0.0
                } else {
                    let bits = (raw_len * 8) as f64;
                    bits / (bitrate as f64)
                }
            });
        if time_to_send <= 0.0 {
            return now;
        }
        let delay = time_to_send / announce_cap;
        now + delay
    }
}

impl Default for InterfaceAnnounceQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Manage announce queues for all interfaces.
#[derive(Debug, Clone)]
pub struct AnnounceQueues {
    queues: BTreeMap<InterfaceId, InterfaceAnnounceQueue>,
    max_interfaces: usize,
    interface_cap_drops: u64,
}

impl AnnounceQueues {
    pub fn new(max_interfaces: usize) -> Self {
        AnnounceQueues {
            queues: BTreeMap::new(),
            max_interfaces,
            interface_cap_drops: 0,
        }
    }

    /// Try to send an announce on an interface. If bandwidth is available,
    /// returns the action immediately. Otherwise, queues it.
    ///
    /// Returns Some(action) if the announce should be sent now, None if queued.
    #[allow(clippy::too_many_arguments)]
    pub fn gate_announce(
        &mut self,
        interface: InterfaceId,
        raw: PacketBytes,
        dest_hash: [u8; 16],
        hops: u8,
        emitted: f64,
        now: f64,
        bitrate: Option<u64>,
        airtime_profile: Option<AirtimeProfile>,
        announce_cap: f64,
    ) -> Option<TransportAction> {
        // If no timing model is available, no cap applies — send immediately
        let bitrate = match bitrate {
            Some(br) if br > 0 => br,
            _ if airtime_profile.is_none() => {
                return Some(TransportAction::SendOnInterface { interface, raw });
            }
            _ => 0,
        };

        if !self.queues.contains_key(&interface) && self.queues.len() >= self.max_interfaces {
            self.interface_cap_drops = self.interface_cap_drops.saturating_add(1);
            return None;
        }

        let queue = self.queues.entry(interface).or_default();

        // Announces already waiting go first, as upstream queues behind them
        // even once the cap has cleared.
        if queue.entries.is_empty() && queue.is_allowed(now) {
            // Bandwidth available — send now and update allowed_at
            queue.announce_allowed_at = InterfaceAnnounceQueue::calculate_next_allowed(
                now,
                raw.len(),
                bitrate,
                airtime_profile,
                announce_cap,
            );
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
        let mut empty_queues = Vec::new();

        for (iface_id, queue) in self.queues.iter_mut() {
            // Remove stale entries
            queue.remove_stale(now);

            // Process as many announces as bandwidth allows
            while queue.is_allowed(now) {
                if let Some(idx) = queue.select_next() {
                    let entry = queue.entries.remove(idx);

                    // Look up bitrate for this interface
                    let (bitrate, airtime_profile, announce_cap) =
                        if let Some(info) = interfaces.get(iface_id) {
                            (
                                info.bitrate.unwrap_or(0),
                                info.airtime_profile,
                                info.announce_cap,
                            )
                        } else {
                            (0, None, constants::ANNOUNCE_CAP)
                        };

                    if bitrate > 0 || airtime_profile.is_some() {
                        queue.announce_allowed_at = InterfaceAnnounceQueue::calculate_next_allowed(
                            now,
                            entry.raw.len(),
                            bitrate,
                            airtime_profile,
                            announce_cap,
                        );
                    } else {
                        queue.announce_allowed_at = now;
                    }

                    actions.push(TransportAction::SendOnInterface {
                        interface: *iface_id,
                        raw: entry.raw,
                    });
                } else {
                    break;
                }
            }

            // An empty queue still holds the interface's bandwidth budget
            // until `announce_allowed_at`: dropping it earlier would let the
            // next announce out at once, however recently the last one left.
            if queue.entries.is_empty() && queue.is_allowed(now) {
                empty_queues.push(*iface_id);
            }
        }

        for iface_id in empty_queues {
            self.queues.remove(&iface_id);
        }

        actions
    }

    /// Return true when recursive path requests should wait for this interface.
    pub fn blocks_recursive_path_request(&self, interface: InterfaceId, now: f64) -> bool {
        self.queues
            .get(&interface)
            .is_some_and(|queue| !queue.entries.is_empty() || !queue.is_allowed(now))
    }

    /// Reserve announce-cap airtime after sending a recursive path request.
    pub fn reserve_recursive_path_request(
        &mut self,
        interface: InterfaceId,
        raw_len: usize,
        now: f64,
        bitrate: Option<u64>,
        airtime_profile: Option<AirtimeProfile>,
        announce_cap: f64,
    ) {
        let bitrate = match bitrate {
            Some(br) if br > 0 => br,
            _ if airtime_profile.is_none() => return,
            _ => 0,
        };

        if !self.queues.contains_key(&interface) && self.queues.len() >= self.max_interfaces {
            self.interface_cap_drops = self.interface_cap_drops.saturating_add(1);
            return;
        }

        let queue = self.queues.entry(interface).or_default();
        queue.announce_allowed_at = InterfaceAnnounceQueue::calculate_next_allowed(
            now,
            raw_len,
            bitrate,
            airtime_profile,
            announce_cap,
        );
    }

    /// Remove all announce queue state for an interface.
    pub fn remove_interface(&mut self, interface: InterfaceId) -> bool {
        self.queues.remove(&interface).is_some()
    }

    /// Number of interface queues currently tracked.
    pub fn queue_count(&self) -> usize {
        self.queues.len()
    }

    /// Number of interface queues that currently hold buffered announces.
    pub fn nonempty_queue_count(&self) -> usize {
        self.queues
            .values()
            .filter(|queue| !queue.entries.is_empty())
            .count()
    }

    /// Total number of buffered announce entries across all interfaces.
    pub fn total_queued_announces(&self) -> usize {
        self.queues.values().map(|queue| queue.entries.len()).sum()
    }

    /// Total retained raw-byte payload across all buffered announces.
    pub fn total_queued_bytes(&self) -> usize {
        self.queues
            .values()
            .flat_map(|queue| queue.entries.iter())
            .map(|entry| entry.raw.len())
            .sum()
    }

    /// Number of announces dropped because the interface queue cap was reached.
    pub fn interface_cap_drop_count(&self) -> u64 {
        self.interface_cap_drops
    }

    /// Announces waiting in `id`'s queue.
    pub fn queued_for(&self, id: &InterfaceId) -> usize {
        self.queues.get(id).map_or(0, |queue| queue.entries.len())
    }

    /// Get the queue for a specific interface (for testing).
    #[cfg(test)]
    pub fn queue_for(&self, id: &InterfaceId) -> Option<&InterfaceAnnounceQueue> {
        self.queues.get(id)
    }
}

impl Default for AnnounceQueues {
    fn default() -> Self {
        Self::new(1024)
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
            raw: vec![0x01, 0x02, 0x03].into(),
        }
    }

    fn make_interface_info(id: u64, bitrate: Option<u64>) -> super::super::types::InterfaceInfo {
        super::super::types::InterfaceInfo {
            stamp_costs: Default::default(),
            id: InterfaceId(id),
            name: String::from("test"),
            mode: crate::constants::MODE_FULL,
            gravity: 0,
            recursive_prs: false,
            announces_from_internal: true,
            announces_to_internal: None,
            out_capable: true,
            in_capable: true,
            bitrate,
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            hop_limiter: None,
            tunnel_id: None,
            mtu: constants::MTU as u32,
            mtu_upgradable: false,
            ingress_control: crate::transport::types::IngressControlConfig::disabled(),
            ia_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: 0.0,
        }
    }

    // --- InterfaceAnnounceQueue tests ---

    /// Upstream 7852f53a initialises every interface's announce queue in
    /// `Interface.__init__` instead of lazily in `Transport.outbound` and
    /// `request_path`. Here queues are typed and created on demand, so an
    /// interface without one is simply one with nothing queued: processing
    /// yields nothing and recursive path requests are not held back.
    #[test]
    fn interface_without_a_queue_has_nothing_queued() {
        let mut queues = AnnounceQueues::new(8);
        let unseen = InterfaceId(42);
        assert!(queues.queue_for(&unseen).is_none());
        assert!(!queues.blocks_recursive_path_request(unseen, 0.0));
        assert!(queues.process_queues(0.0, &BTreeMap::new()).is_empty());
        assert_eq!(queues.queue_count(), 0);
    }

    /// Upstream 70b9d58f sets `announce_allowed_at = 0` in
    /// `Interface.__init__` instead of defaulting it in `Transport`. A new
    /// queue here starts at 0 too, so the first announce goes out at once.
    #[test]
    fn new_interface_queue_allows_its_first_announce_at_once() {
        let queue = InterfaceAnnounceQueue::new();
        assert_eq!(queue.announce_allowed_at, 0.0);
        assert!(queue.is_allowed(0.0));
    }

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

        // A later emission replaces the queued announce, whatever its hops.
        queue.insert(make_entry(0x01, 5, 200.0));
        assert_eq!(queue.entries.len(), 1);
        assert_eq!(queue.entries[0].hops, 5);

        // An earlier emission never does, even with fewer hops.
        queue.insert(make_entry(0x01, 1, 150.0));
        assert_eq!(queue.entries.len(), 1);
        assert_eq!(queue.entries[0].hops, 5);

        // Nor does the same emission seen again.
        queue.insert(make_entry(0x01, 2, 200.0));
        assert_eq!(queue.entries[0].hops, 5);
    }

    #[test]
    fn newer_duplicate_updates_matched_entry_not_trailing_entry() {
        let mut queue = InterfaceAnnounceQueue::new();
        queue.insert(make_entry(0x01, 3, 100.0));
        queue.insert(make_entry(0x02, 4, 150.0));

        let mut replacement = make_entry(0x01, 3, 200.0);
        replacement.raw = vec![0x09, 0x08].into();
        queue.insert(replacement);

        assert_eq!(queue.entries.len(), 2);
        assert_eq!(queue.entries[0].destination_hash, [0x01; 16]);
        assert_eq!(queue.entries[0].time, 200.0);
        assert_eq!(queue.entries[0].hops, 3);
        assert_eq!(queue.entries[0].emitted, 200.0);
        assert_eq!(&*queue.entries[0].raw, &[0x09, 0x08]);

        assert_eq!(queue.entries[1].destination_hash, [0x02; 16]);
        assert_eq!(queue.entries[1].time, 150.0);
        assert_eq!(queue.entries[1].hops, 4);
        assert_eq!(queue.entries[1].emitted, 150.0);
        assert_eq!(&*queue.entries[1].raw, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn duplicate_lookup_updates_only_first_preexisting_match() {
        let mut queue = InterfaceAnnounceQueue::new();
        queue.entries.push(make_entry(0x01, 3, 100.0));
        queue.entries.push(make_entry(0x01, 3, 150.0));

        let mut replacement = make_entry(0x01, 3, 200.0);
        replacement.raw = vec![0x09].into();
        queue.insert(replacement);

        assert_eq!(queue.entries.len(), 2);
        assert_eq!(queue.entries[0].time, 200.0);
        assert_eq!(queue.entries[0].emitted, 200.0);
        assert_eq!(&*queue.entries[0].raw, &[0x09]);
        assert_eq!(queue.entries[1].time, 150.0);
        assert_eq!(queue.entries[1].emitted, 150.0);
        assert_eq!(&*queue.entries[1].raw, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_queue_stale_removal() {
        let mut queue = InterfaceAnnounceQueue::new();
        queue.insert(make_entry(0x01, 1, 100.0));
        queue.insert(make_entry(0x02, 2, 200.0));

        // At exactly its lifetime an entry is kept, as upstream only drops
        // one queued more than QUEUED_ANNOUNCE_LIFE ago.
        queue.remove_stale(100.0 + constants::QUEUED_ANNOUNCE_LIFE);
        assert_eq!(queue.entries.len(), 2);

        // One second beyond the lifetime, only the newer entry remains.
        queue.remove_stale(100.0 + constants::QUEUED_ANNOUNCE_LIFE + 1.0);
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
                raw: vec![0x01].into(),
            });
        }
        assert_eq!(queue.entries.len(), constants::MAX_QUEUED_ANNOUNCES);

        // A full queue takes nothing more and keeps what it holds.
        queue.insert(make_entry(0xFF, 1, 99999.0));
        assert_eq!(queue.entries.len(), constants::MAX_QUEUED_ANNOUNCES);
        assert_eq!(queue.entries[0].time, 0.0);
        assert!(queue
            .entries
            .iter()
            .all(|entry| entry.destination_hash != [0xFF; 16]));
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
        let next = InterfaceAnnounceQueue::calculate_next_allowed(1000.0, 100, 1000, None, 0.02);
        assert!((next - 1040.0).abs() < 0.001);
    }

    #[test]
    fn test_calculate_next_allowed_zero_bitrate() {
        let next = InterfaceAnnounceQueue::calculate_next_allowed(1000.0, 100, 0, None, 0.02);
        assert_eq!(next, 1000.0); // no cap
    }

    #[test]
    fn test_calculate_next_allowed_uses_lora_airtime() {
        let profile = AirtimeProfile::Lora {
            bandwidth: 125_000,
            spreading_factor: 8,
            coding_rate: 5,
            preamble_symbols: 8,
            explicit_header: true,
            crc: true,
        };

        let next =
            InterfaceAnnounceQueue::calculate_next_allowed(1000.0, 100, 0, Some(profile), 0.02);

        // 100-byte explicit-header LoRa packet at BW125/SF8/CR4/5:
        // (8 + ceil((800 - 32 + 28 + 16) / 32) * 5 + 12.25) symbols
        // * 2.048 ms/symbol = 307.712 ms airtime.
        assert!((next - 1015.3856).abs() < 0.0001);
    }

    // --- AnnounceQueues tests ---

    #[test]
    fn test_gate_announce_no_bitrate_immediate() {
        let mut queues = AnnounceQueues::new(1024);
        let result = queues.gate_announce(
            InterfaceId(1),
            vec![0x01, 0x02, 0x03].into(),
            [0xAA; 16],
            2,
            1000.0,
            1000.0,
            None, // no bitrate
            None,
            0.02,
        );
        assert!(result.is_some());
        assert!(matches!(
            result.unwrap(),
            TransportAction::SendOnInterface { .. }
        ));
    }

    #[test]
    fn test_gate_announce_uses_airtime_profile_without_bitrate() {
        let mut queues = AnnounceQueues::new(1024);
        let profile = AirtimeProfile::Lora {
            bandwidth: 125_000,
            spreading_factor: 8,
            coding_rate: 5,
            preamble_symbols: 8,
            explicit_header: true,
            crc: true,
        };

        let first = queues.gate_announce(
            InterfaceId(1),
            vec![0x01; 100].into(),
            [0xAA; 16],
            2,
            1000.0,
            1000.0,
            None,
            Some(profile),
            0.02,
        );
        assert!(first.is_some());

        let queue = queues.queue_for(&InterfaceId(1)).unwrap();
        assert!((queue.announce_allowed_at - 1015.3856).abs() < 0.0001);

        let second = queues.gate_announce(
            InterfaceId(1),
            vec![0x02; 100].into(),
            [0xBB; 16],
            2,
            1000.0,
            1000.0,
            None,
            Some(profile),
            0.02,
        );
        assert!(second.is_none());
        assert_eq!(queues.queue_for(&InterfaceId(1)).unwrap().entries.len(), 1);
    }

    #[test]
    fn test_gate_announce_bandwidth_available() {
        let mut queues = AnnounceQueues::new(1024);
        let result = queues.gate_announce(
            InterfaceId(1),
            vec![0x01; 100].into(),
            [0xBB; 16],
            2,
            1000.0,
            1000.0,
            Some(10000), // 10 kbps
            None,
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
        let mut queues = AnnounceQueues::new(1024);

        // First announce goes through
        let r1 = queues.gate_announce(
            InterfaceId(1),
            vec![0x01; 100].into(),
            [0xAA; 16],
            2,
            1000.0,
            1000.0,
            Some(1000), // 1 kbps — very slow
            None,
            0.02,
        );
        assert!(r1.is_some());

        // Second announce at same time should be queued
        let r2 = queues.gate_announce(
            InterfaceId(1),
            vec![0x02; 100].into(),
            [0xBB; 16],
            3,
            1000.0,
            1000.0,
            Some(1000),
            None,
            0.02,
        );
        assert!(r2.is_none()); // queued

        let queue = queues.queue_for(&InterfaceId(1)).unwrap();
        assert_eq!(queue.entries.len(), 1);
    }

    #[test]
    fn announce_emitted_reads_the_random_blob_timebase() {
        let mut data = vec![0u8; constants::KEYSIZE / 8 + constants::NAME_HASH_LENGTH / 8];
        data.extend_from_slice(&[0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0, 0, 0, 0x12, 0x34]);
        data.extend_from_slice(&[0x55; 64]);
        let mut h1 = vec![constants::PACKET_TYPE_ANNOUNCE, 3];
        h1.extend_from_slice(&[0xAA; 16]);
        h1.push(constants::CONTEXT_NONE);
        h1.extend_from_slice(&data);
        assert_eq!(announce_emitted(&h1), Some(f64::from(0x1234)));

        let mut h2 = vec![
            (constants::HEADER_2 << 6) | constants::PACKET_TYPE_ANNOUNCE,
            3,
        ];
        h2.extend_from_slice(&[0xBB; 16]);
        h2.extend_from_slice(&[0xAA; 16]);
        h2.push(constants::CONTEXT_NONE);
        h2.extend_from_slice(&data);
        assert_eq!(announce_emitted(&h2), Some(f64::from(0x1234)));

        assert_eq!(announce_emitted(&h1[..40]), None);
        assert_eq!(announce_emitted(&[]), None);
    }

    /// Upstream's `Transport.outbound` sends a forwarded announce at once
    /// only when nothing is queued on the interface: one arriving after the
    /// cap has cleared, but before the queue is processed, waits its turn.
    #[test]
    fn announce_waits_behind_queued_announces_after_the_cap_clears() {
        let mut queues = AnnounceQueues::new(1024);
        let gate = |queues: &mut AnnounceQueues, dest: u8, hops: u8, now: f64| {
            queues.gate_announce(
                InterfaceId(1),
                vec![dest; 100].into(),
                [dest; 16],
                hops,
                now,
                now,
                Some(1000),
                None,
                0.02,
            )
        };
        assert!(gate(&mut queues, 0xAA, 2, 1000.0).is_some());
        assert!(gate(&mut queues, 0xBB, 1, 1000.0).is_none());

        let allowed_at = queues
            .queue_for(&InterfaceId(1))
            .unwrap()
            .announce_allowed_at;
        assert!(gate(&mut queues, 0xCC, 3, allowed_at + 1.0).is_none());
        assert_eq!(queues.queued_for(&InterfaceId(1)), 2);

        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface_info(1, Some(1000)));
        let actions = queues.process_queues(allowed_at + 1.0, &interfaces);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TransportAction::SendOnInterface { raw, .. } => assert_eq!(raw[0], 0xBB),
            other => panic!("unexpected action {other:?}"),
        }
    }

    #[test]
    fn test_process_queues_dequeues_when_allowed() {
        let mut queues = AnnounceQueues::new(1024);

        // Queue an announce by exhausting bandwidth first
        let _ = queues.gate_announce(
            InterfaceId(1),
            vec![0x01; 10].into(),
            [0xAA; 16],
            2,
            0.0,
            0.0,
            Some(1000),
            None,
            0.02,
        );
        let _ = queues.gate_announce(
            InterfaceId(1),
            vec![0x02; 10].into(),
            [0xBB; 16],
            3,
            0.0,
            0.0,
            Some(1000),
            None,
            0.02,
        );

        // Queue should have one entry
        assert_eq!(queues.queue_for(&InterfaceId(1)).unwrap().entries.len(), 1);

        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface_info(1, Some(1000)));

        // Process at a future time when bandwidth is available
        let allowed_at = queues
            .queue_for(&InterfaceId(1))
            .unwrap()
            .announce_allowed_at;
        let actions = queues.process_queues(allowed_at + 1.0, &interfaces);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            TransportAction::SendOnInterface { interface, .. } if *interface == InterfaceId(1)
        ));

        // The emptied queue still holds the bandwidth budget of the
        // announce just released, and is pruned once that has elapsed.
        let queue = queues.queue_for(&InterfaceId(1)).unwrap();
        assert!(queue.entries.is_empty());
        assert!(queue.announce_allowed_at > allowed_at + 1.0);
        let released_until = queue.announce_allowed_at;
        assert!(queues
            .process_queues(released_until, &interfaces)
            .is_empty());
        assert!(queues.queue_for(&InterfaceId(1)).is_none());
    }

    #[test]
    fn test_local_announce_bypasses_cap() {
        // hops == 0 means locally-originated, should not be queued
        // The caller (TransportEngine) is responsible for only calling gate_announce
        // for hops > 0. We verify the gate_announce works for hops=0 too.
        let mut queues = AnnounceQueues::new(1024);

        // Exhaust bandwidth
        let _ = queues.gate_announce(
            InterfaceId(1),
            vec![0x01; 100].into(),
            [0xAA; 16],
            2,
            0.0,
            0.0,
            Some(1000),
            None,
            0.02,
        );

        // hops=0 should still be queued by gate_announce since hops filtering
        // is the caller's responsibility. gate_announce is agnostic.
        let r = queues.gate_announce(
            InterfaceId(1),
            vec![0x02; 100].into(),
            [0xBB; 16],
            0,
            0.0,
            0.0,
            Some(1000),
            None,
            0.02,
        );
        assert!(r.is_none()); // queued — caller must bypass for hops==0
    }

    #[test]
    fn test_remove_interface_queue() {
        let mut queues = AnnounceQueues::new(1024);
        let _ = queues.gate_announce(
            InterfaceId(1),
            vec![0x01; 100].into(),
            [0xAA; 16],
            2,
            0.0,
            0.0,
            Some(1000),
            None,
            0.02,
        );
        let _ = queues.gate_announce(
            InterfaceId(1),
            vec![0x02; 100].into(),
            [0xBB; 16],
            3,
            0.0,
            0.0,
            Some(1000),
            None,
            0.02,
        );

        assert!(queues.queue_for(&InterfaceId(1)).is_some());
        assert!(queues.remove_interface(InterfaceId(1)));
        assert!(queues.queue_for(&InterfaceId(1)).is_none());
        assert!(!queues.remove_interface(InterfaceId(1)));
    }

    #[test]
    fn test_process_queues_prunes_empty_queue() {
        let mut queues = AnnounceQueues::new(1024);

        let _ = queues.gate_announce(
            InterfaceId(1),
            vec![0x01; 10].into(),
            [0xAA; 16],
            2,
            0.0,
            0.0,
            Some(1000),
            None,
            0.02,
        );
        let _ = queues.gate_announce(
            InterfaceId(1),
            vec![0x02; 10].into(),
            [0xBB; 16],
            3,
            0.0,
            0.0,
            Some(1000),
            None,
            0.02,
        );

        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface_info(1, Some(1000)));
        let allowed_at = queues
            .queue_for(&InterfaceId(1))
            .unwrap()
            .announce_allowed_at;

        let actions = queues.process_queues(allowed_at + 1.0, &interfaces);
        assert_eq!(actions.len(), 1);
        let released_until = queues
            .queue_for(&InterfaceId(1))
            .unwrap()
            .announce_allowed_at;
        assert_eq!(queues.queue_count(), 1);

        assert!(queues
            .process_queues(released_until, &interfaces)
            .is_empty());
        assert!(queues.queue_for(&InterfaceId(1)).is_none());
        assert_eq!(queues.queue_count(), 0);
    }

    /// Regression: emptying a queue dropped it together with its
    /// `announce_allowed_at`, so the next announce left at once although the
    /// one just released had used up the interface's announce cap. Every
    /// tick empties and drops such queues, so the cap only held for
    /// announces arriving between two ticks.
    #[test]
    fn released_announce_holds_the_cap_after_its_queue_empties() {
        let mut queues = AnnounceQueues::new(1024);
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface_info(1, Some(1000)));
        let gate = |queues: &mut AnnounceQueues, dest: u8, now: f64| {
            queues.gate_announce(
                InterfaceId(1),
                vec![dest; 100].into(),
                [dest; 16],
                2,
                now,
                now,
                Some(1000),
                None,
                constants::ANNOUNCE_CAP,
            )
        };

        // 100 bytes at 1000 bit/s under a 2% cap: 40 s per announce.
        assert!(gate(&mut queues, 1, 0.0).is_some());
        assert!(gate(&mut queues, 2, 1.0).is_none());
        // The tick that releases the queued announce empties the queue.
        assert_eq!(queues.process_queues(40.0, &interfaces).len(), 1);
        assert!(queues.process_queues(41.0, &interfaces).is_empty());

        // The next announce waits out the released one's 40 s.
        assert!(gate(&mut queues, 3, 41.0).is_none());
        assert!(queues.process_queues(79.0, &interfaces).is_empty());
        assert_eq!(queues.process_queues(80.0, &interfaces).len(), 1);
    }

    #[test]
    fn test_process_queues_keeps_nonempty_queue() {
        let mut queues = AnnounceQueues::new(1024);
        let _ = queues.gate_announce(
            InterfaceId(1),
            vec![0x01; 100].into(),
            [0xAA; 16],
            2,
            0.0,
            0.0,
            Some(1000),
            None,
            0.02,
        );
        let _ = queues.gate_announce(
            InterfaceId(1),
            vec![0x02; 100].into(),
            [0xBB; 16],
            3,
            0.0,
            0.0,
            Some(1000),
            None,
            0.02,
        );
        let _ = queues.gate_announce(
            InterfaceId(1),
            vec![0x03; 100].into(),
            [0xCC; 16],
            4,
            0.0,
            0.0,
            Some(1000),
            None,
            0.02,
        );

        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface_info(1, Some(1000)));
        let allowed_at = queues
            .queue_for(&InterfaceId(1))
            .unwrap()
            .announce_allowed_at;

        let actions = queues.process_queues(allowed_at + 1.0, &interfaces);
        assert_eq!(actions.len(), 1);
        assert!(queues.queue_for(&InterfaceId(1)).is_some());
        assert_eq!(queues.queue_for(&InterfaceId(1)).unwrap().entries.len(), 1);
    }

    #[test]
    fn test_gate_announce_refuses_new_interface_when_at_capacity() {
        let mut queues = AnnounceQueues::new(1);

        let _ = queues.gate_announce(
            InterfaceId(1),
            vec![0x01; 100].into(),
            [0xAA; 16],
            2,
            0.0,
            0.0,
            Some(1000),
            None,
            0.02,
        );
        let second = queues.gate_announce(
            InterfaceId(1),
            vec![0x02; 100].into(),
            [0xBB; 16],
            3,
            0.0,
            0.0,
            Some(1000),
            None,
            0.02,
        );
        assert!(second.is_none());
        assert_eq!(queues.queue_count(), 1);

        let rejected = queues.gate_announce(
            InterfaceId(2),
            vec![0x03; 100].into(),
            [0xCC; 16],
            4,
            0.0,
            0.0,
            Some(1000),
            None,
            0.02,
        );
        assert!(rejected.is_none());
        assert_eq!(queues.queue_count(), 1);
        assert!(queues.queue_for(&InterfaceId(2)).is_none());
        assert_eq!(queues.interface_cap_drop_count(), 1);
    }

    #[test]
    fn test_gate_announce_allows_existing_queue_when_at_capacity() {
        let mut queues = AnnounceQueues::new(1);

        let _ = queues.gate_announce(
            InterfaceId(1),
            vec![0x01; 100].into(),
            [0xAA; 16],
            2,
            0.0,
            0.0,
            Some(1000),
            None,
            0.02,
        );
        let queued = queues.gate_announce(
            InterfaceId(1),
            vec![0x02; 100].into(),
            [0xBB; 16],
            3,
            0.0,
            0.0,
            Some(1000),
            None,
            0.02,
        );
        assert!(queued.is_none());
        assert_eq!(queues.queue_count(), 1);
        assert_eq!(queues.queue_for(&InterfaceId(1)).unwrap().entries.len(), 1);
        assert_eq!(queues.interface_cap_drop_count(), 0);
    }

    fn lora_profile() -> AirtimeProfile {
        AirtimeProfile::Lora {
            bandwidth: 125_000,
            spreading_factor: 8,
            coding_rate: 5,
            preamble_symbols: 8,
            explicit_header: true,
            crc: true,
        }
    }

    /// Among announces with the fewest hops, upstream sends the one queued
    /// first, and on a tie in queue time the one earlier in the queue.
    #[test]
    fn select_next_keeps_queue_order_among_equal_announces() {
        let mut queue = InterfaceAnnounceQueue::new();
        queue.insert(make_entry(0x01, 2, 100.0));
        queue.insert(make_entry(0x02, 2, 200.0));
        assert_eq!(queue.select_next(), Some(0));

        let mut queue = InterfaceAnnounceQueue::new();
        queue.insert(make_entry(0x01, 2, 100.0));
        queue.insert(make_entry(0x02, 2, 100.0));
        assert_eq!(queue.select_next(), Some(0));
    }

    /// An interface with no bitrate, or a zero one, and no airtime model has
    /// no announce cap: announces and recursive path requests pass without
    /// any queue state being kept for it.
    #[test]
    fn interface_without_timing_model_keeps_no_queue_state() {
        let mut queues = AnnounceQueues::new(8);
        for (id, bitrate) in [(1, None), (2, Some(0))] {
            let sent = queues.gate_announce(
                InterfaceId(id),
                vec![0x01; 100].into(),
                [0xAA; 16],
                2,
                1000.0,
                1000.0,
                bitrate,
                None,
                0.02,
            );
            assert!(sent.is_some());
            queues.reserve_recursive_path_request(
                InterfaceId(id),
                100,
                1000.0,
                bitrate,
                None,
                0.02,
            );
            assert!(!queues.blocks_recursive_path_request(InterfaceId(id), 1000.0));
        }
        assert_eq!(queues.queue_count(), 0);
    }

    /// Upstream holds a recursive path request back while announces are
    /// queued on the interface, even once its announce cap has cleared.
    #[test]
    fn queued_announces_block_recursive_path_requests_after_the_cap_clears() {
        let mut queues = AnnounceQueues::new(8);
        for dest in [0xAA, 0xBB] {
            let _ = queues.gate_announce(
                InterfaceId(1),
                vec![dest; 100].into(),
                [dest; 16],
                2,
                1000.0,
                1000.0,
                Some(1000),
                None,
                0.02,
            );
        }
        let allowed_at = queues
            .queue_for(&InterfaceId(1))
            .unwrap()
            .announce_allowed_at;
        assert!(queues.blocks_recursive_path_request(InterfaceId(1), allowed_at + 1.0));
    }

    /// A recursive path request on an interface with only an airtime model
    /// reserves its airtime, and one on an interface already tracked does
    /// so even when no new interface queue may be added.
    #[test]
    fn recursive_path_request_reserves_airtime_on_a_tracked_interface_at_capacity() {
        let mut queues = AnnounceQueues::new(1);
        queues.reserve_recursive_path_request(
            InterfaceId(1),
            100,
            1000.0,
            None,
            Some(lora_profile()),
            0.02,
        );
        let first = queues
            .queue_for(&InterfaceId(1))
            .unwrap()
            .announce_allowed_at;
        assert!((first - 1015.3856).abs() < 0.0001);
        assert!(queues.blocks_recursive_path_request(InterfaceId(1), 1010.0));

        queues.reserve_recursive_path_request(
            InterfaceId(1),
            100,
            2000.0,
            None,
            Some(lora_profile()),
            0.02,
        );
        let second = queues
            .queue_for(&InterfaceId(1))
            .unwrap()
            .announce_allowed_at;
        assert!((second - 2015.3856).abs() < 0.0001);
        assert_eq!(queues.interface_cap_drop_count(), 0);
    }

    #[test]
    fn queued_counts_report_entries_and_bytes_per_interface() {
        let mut queues = AnnounceQueues::new(8);
        for (dest, len) in [(0xAA, 100), (0xBB, 40), (0xCC, 60)] {
            let _ = queues.gate_announce(
                InterfaceId(1),
                vec![dest; len].into(),
                [dest; 16],
                2,
                1000.0,
                1000.0,
                Some(1000),
                None,
                0.02,
            );
        }
        assert_eq!(queues.queued_for(&InterfaceId(1)), 2);
        assert_eq!(queues.queued_for(&InterfaceId(2)), 0);
        assert_eq!(queues.total_queued_bytes(), 100);
    }
}
