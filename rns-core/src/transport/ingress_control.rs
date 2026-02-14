use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::constants;
use super::types::InterfaceId;

/// A held announce waiting for release after burst conditions subside.
#[derive(Debug, Clone)]
pub struct HeldAnnounce {
    /// Original raw bytes (pre-hop-increment).
    pub raw: Vec<u8>,
    /// Hop count (post-increment, for priority selection).
    pub hops: u8,
    /// Interface the announce was received on.
    pub receiving_interface: InterfaceId,
    /// When the announce was held.
    pub timestamp: f64,
}

/// Per-interface ingress control state.
#[derive(Debug)]
struct IngressControlState {
    burst_active: bool,
    burst_activated: f64,
    held_release: f64,
    held_announces: BTreeMap<[u8; 16], HeldAnnounce>,
}

impl IngressControlState {
    fn new() -> Self {
        IngressControlState {
            burst_active: false,
            burst_activated: 0.0,
            held_release: 0.0,
            held_announces: BTreeMap::new(),
        }
    }
}

/// Ingress control system: detects announce bursts per-interface
/// and holds announces from unknown destinations during bursts.
#[derive(Debug)]
pub struct IngressControl {
    states: BTreeMap<InterfaceId, IngressControlState>,
}

impl IngressControl {
    pub fn new() -> Self {
        IngressControl {
            states: BTreeMap::new(),
        }
    }

    /// Determine whether to ingress-limit an announce on this interface.
    ///
    /// Returns true if the announce should be held (burst is active or just activated).
    pub fn should_ingress_limit(
        &mut self,
        interface: InterfaceId,
        ia_freq: f64,
        interface_started: f64,
        now: f64,
    ) -> bool {
        let state = self.states.entry(interface).or_insert_with(IngressControlState::new);
        let interface_age = now - interface_started;
        let threshold = if interface_age < constants::IC_NEW_TIME {
            constants::IC_BURST_FREQ_NEW
        } else {
            constants::IC_BURST_FREQ
        };

        if state.burst_active {
            // Check if burst can deactivate
            if ia_freq < threshold && now > state.burst_activated + constants::IC_BURST_HOLD {
                state.burst_active = false;
                state.held_release = now + constants::IC_BURST_PENALTY;
                return false;
            }
            true
        } else if ia_freq > threshold {
            // Activate burst
            state.burst_active = true;
            state.burst_activated = now;
            true
        } else {
            false
        }
    }

    /// Store a held announce for later release.
    ///
    /// If the destination already has a held announce, it is updated.
    /// If the max is reached, the announce is dropped.
    pub fn hold_announce(
        &mut self,
        interface: InterfaceId,
        dest_hash: [u8; 16],
        held: HeldAnnounce,
    ) {
        let state = self.states.entry(interface).or_insert_with(IngressControlState::new);
        if state.held_announces.contains_key(&dest_hash) {
            // Update existing
            state.held_announces.insert(dest_hash, held);
        } else if state.held_announces.len() < constants::IC_MAX_HELD_ANNOUNCES {
            state.held_announces.insert(dest_hash, held);
        }
        // else: at max, silently drop
    }

    /// Try to release one held announce from this interface.
    ///
    /// Conditions: not currently limiting, held announces exist,
    /// now >= held_release, freq < threshold.
    /// Selects the announce with the lowest hop count (closest source).
    pub fn process_held_announces(
        &mut self,
        interface: InterfaceId,
        ia_freq: f64,
        interface_started: f64,
        now: f64,
    ) -> Option<HeldAnnounce> {
        let state = self.states.get_mut(&interface)?;

        // Don't release during active burst
        if state.burst_active {
            return None;
        }

        if state.held_announces.is_empty() {
            return None;
        }

        // Wait for penalty period
        if now < state.held_release {
            return None;
        }

        // Check frequency is below threshold
        let interface_age = now - interface_started;
        let threshold = if interface_age < constants::IC_NEW_TIME {
            constants::IC_BURST_FREQ_NEW
        } else {
            constants::IC_BURST_FREQ
        };
        if ia_freq >= threshold {
            return None;
        }

        // Find announce with lowest hops
        let best_key = state
            .held_announces
            .iter()
            .min_by_key(|(_, h)| h.hops)
            .map(|(k, _)| *k)?;

        let held = state.held_announces.remove(&best_key)?;
        state.held_release = now + constants::IC_HELD_RELEASE_INTERVAL;
        Some(held)
    }

    /// Return interface IDs that have held announces.
    pub fn interfaces_with_held(&self) -> Vec<InterfaceId> {
        self.states
            .iter()
            .filter(|(_, s)| !s.held_announces.is_empty())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Remove all state for an interface.
    pub fn remove_interface(&mut self, id: &InterfaceId) {
        self.states.remove(id);
    }

    /// Clear all ingress control state.
    pub fn clear(&mut self) {
        self.states.clear();
    }

    /// Count of held announces for a specific interface.
    pub fn held_count(&self, interface: &InterfaceId) -> usize {
        self.states
            .get(interface)
            .map(|s| s.held_announces.len())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(n: u64) -> InterfaceId {
        InterfaceId(n)
    }

    #[test]
    fn test_no_limiting_below_threshold() {
        let mut ic = IngressControl::new();
        // Mature interface, freq below threshold
        let started = 0.0;
        let now = 10000.0;
        assert!(!ic.should_ingress_limit(iface(1), 5.0, started, now));
    }

    #[test]
    fn test_burst_activates_above_threshold() {
        let mut ic = IngressControl::new();
        let started = 0.0;
        let now = 10000.0;
        // Exceed mature threshold (12.0)
        assert!(ic.should_ingress_limit(iface(1), 13.0, started, now));
    }

    #[test]
    fn test_new_interface_lower_threshold() {
        let mut ic = IngressControl::new();
        let started = 9000.0;
        let now = 9500.0; // interface_age = 500s < IC_NEW_TIME (7200s)
        // Below mature threshold but above new threshold (3.5)
        assert!(ic.should_ingress_limit(iface(1), 4.0, started, now));
    }

    #[test]
    fn test_burst_stays_active_during_hold_period() {
        let mut ic = IngressControl::new();
        let started = 0.0;
        let now = 10000.0;

        // Activate burst
        assert!(ic.should_ingress_limit(iface(1), 13.0, started, now));

        // Freq drops but within hold period
        let now2 = now + 30.0; // < IC_BURST_HOLD (60s)
        assert!(ic.should_ingress_limit(iface(1), 1.0, started, now2));
    }

    #[test]
    fn test_burst_deactivates_after_hold_period() {
        let mut ic = IngressControl::new();
        let started = 0.0;
        let now = 10000.0;

        // Activate burst
        assert!(ic.should_ingress_limit(iface(1), 13.0, started, now));

        // After hold period with low freq
        let now2 = now + constants::IC_BURST_HOLD + 1.0;
        assert!(!ic.should_ingress_limit(iface(1), 1.0, started, now2));
    }

    #[test]
    fn test_penalty_period_prevents_release() {
        let mut ic = IngressControl::new();
        let started = 0.0;
        let now = 10000.0;

        // Activate burst
        ic.should_ingress_limit(iface(1), 13.0, started, now);

        // Hold an announce
        ic.hold_announce(iface(1), [1u8; 16], HeldAnnounce {
            raw: vec![0; 10],
            hops: 3,
            receiving_interface: iface(1),
            timestamp: now,
        });

        // Deactivate burst
        let now2 = now + constants::IC_BURST_HOLD + 1.0;
        ic.should_ingress_limit(iface(1), 1.0, started, now2);

        // During penalty period, no release
        let now3 = now2 + 10.0; // < IC_BURST_PENALTY (300s)
        assert!(ic.process_held_announces(iface(1), 1.0, started, now3).is_none());

        // After penalty period, release
        let now4 = now2 + constants::IC_BURST_PENALTY + 1.0;
        let released = ic.process_held_announces(iface(1), 1.0, started, now4);
        assert!(released.is_some());
        assert_eq!(released.unwrap().hops, 3);
    }

    #[test]
    fn test_released_lowest_hops_first() {
        let mut ic = IngressControl::new();
        let started = 0.0;
        let now = 10000.0;

        ic.hold_announce(iface(1), [1u8; 16], HeldAnnounce {
            raw: vec![0; 10],
            hops: 5,
            receiving_interface: iface(1),
            timestamp: now,
        });
        ic.hold_announce(iface(1), [2u8; 16], HeldAnnounce {
            raw: vec![0; 10],
            hops: 2,
            receiving_interface: iface(1),
            timestamp: now,
        });
        ic.hold_announce(iface(1), [3u8; 16], HeldAnnounce {
            raw: vec![0; 10],
            hops: 8,
            receiving_interface: iface(1),
            timestamp: now,
        });

        // Release (no burst active, past penalty)
        let release_time = now + 1.0;
        let released = ic.process_held_announces(iface(1), 1.0, started, release_time);
        assert!(released.is_some());
        assert_eq!(released.unwrap().hops, 2);

        let release_time2 = release_time + constants::IC_HELD_RELEASE_INTERVAL + 1.0;
        let released2 = ic.process_held_announces(iface(1), 1.0, started, release_time2);
        assert!(released2.is_some());
        assert_eq!(released2.unwrap().hops, 5);
    }

    #[test]
    fn test_max_held_announces() {
        let mut ic = IngressControl::new();

        for i in 0..constants::IC_MAX_HELD_ANNOUNCES {
            let mut hash = [0u8; 16];
            hash[0] = (i >> 8) as u8;
            hash[1] = (i & 0xff) as u8;
            ic.hold_announce(iface(1), hash, HeldAnnounce {
                raw: vec![0; 10],
                hops: 1,
                receiving_interface: iface(1),
                timestamp: 0.0,
            });
        }

        assert_eq!(ic.held_count(&iface(1)), constants::IC_MAX_HELD_ANNOUNCES);

        // One more should be dropped
        ic.hold_announce(iface(1), [0xff; 16], HeldAnnounce {
            raw: vec![0; 10],
            hops: 1,
            receiving_interface: iface(1),
            timestamp: 0.0,
        });
        assert_eq!(ic.held_count(&iface(1)), constants::IC_MAX_HELD_ANNOUNCES);
    }

    #[test]
    fn test_duplicate_destination_updates() {
        let mut ic = IngressControl::new();
        let hash = [1u8; 16];

        ic.hold_announce(iface(1), hash, HeldAnnounce {
            raw: vec![1; 10],
            hops: 5,
            receiving_interface: iface(1),
            timestamp: 0.0,
        });
        assert_eq!(ic.held_count(&iface(1)), 1);

        // Update with better hops
        ic.hold_announce(iface(1), hash, HeldAnnounce {
            raw: vec![2; 10],
            hops: 2,
            receiving_interface: iface(1),
            timestamp: 1.0,
        });
        assert_eq!(ic.held_count(&iface(1)), 1);
    }

    #[test]
    fn test_interfaces_with_held() {
        let mut ic = IngressControl::new();
        assert!(ic.interfaces_with_held().is_empty());

        ic.hold_announce(iface(1), [1u8; 16], HeldAnnounce {
            raw: vec![0; 10],
            hops: 1,
            receiving_interface: iface(1),
            timestamp: 0.0,
        });

        let ifaces = ic.interfaces_with_held();
        assert_eq!(ifaces.len(), 1);
        assert_eq!(ifaces[0], iface(1));
    }

    #[test]
    fn test_remove_interface() {
        let mut ic = IngressControl::new();
        ic.hold_announce(iface(1), [1u8; 16], HeldAnnounce {
            raw: vec![0; 10],
            hops: 1,
            receiving_interface: iface(1),
            timestamp: 0.0,
        });
        assert_eq!(ic.held_count(&iface(1)), 1);

        ic.remove_interface(&iface(1));
        assert_eq!(ic.held_count(&iface(1)), 0);
        assert!(ic.interfaces_with_held().is_empty());
    }

    #[test]
    fn test_release_interval() {
        let mut ic = IngressControl::new();
        let started = 0.0;
        let now = 10000.0;

        ic.hold_announce(iface(1), [1u8; 16], HeldAnnounce {
            raw: vec![0; 10],
            hops: 1,
            receiving_interface: iface(1),
            timestamp: now,
        });
        ic.hold_announce(iface(1), [2u8; 16], HeldAnnounce {
            raw: vec![0; 10],
            hops: 2,
            receiving_interface: iface(1),
            timestamp: now,
        });

        // First release
        let released = ic.process_held_announces(iface(1), 1.0, started, now);
        assert!(released.is_some());

        // Too soon for second release
        let too_soon = now + 10.0; // < IC_HELD_RELEASE_INTERVAL (30s)
        assert!(ic.process_held_announces(iface(1), 1.0, started, too_soon).is_none());

        // After interval, second release works
        let ok_time = now + constants::IC_HELD_RELEASE_INTERVAL + 1.0;
        assert!(ic.process_held_announces(iface(1), 1.0, started, ok_time).is_some());
    }
}
