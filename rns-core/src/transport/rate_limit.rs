use alloc::collections::BTreeMap;

use super::tables::RateEntry;
use crate::constants;

/// Per-destination announce rate limiter.
pub struct AnnounceRateLimiter {
    table: BTreeMap<[u8; 16], RateEntry>,
}

impl AnnounceRateLimiter {
    pub fn new() -> Self {
        AnnounceRateLimiter {
            table: BTreeMap::new(),
        }
    }

    /// Iterate over all rate table entries.
    pub fn entries(&self) -> impl Iterator<Item = (&[u8; 16], &RateEntry)> {
        self.table.iter()
    }

    /// Check if an announce should be blocked due to rate limiting.
    ///
    /// Returns `true` if the announce should be BLOCKED.
    /// If `rate_target` is None, announces are never blocked.
    pub fn check_and_update(
        &mut self,
        dest_hash: &[u8; 16],
        now: f64,
        rate_target: Option<f64>,
        rate_grace: u32,
        rate_penalty: f64,
    ) -> bool {
        let rate_target = match rate_target {
            Some(t) => t,
            None => return false,
        };

        // In Python, the first announce for a destination just creates
        // the entry and is never blocked. Only subsequent announces
        // go through the rate check logic.
        if !self.table.contains_key(dest_hash) {
            let entry = RateEntry {
                last: now,
                rate_violations: 0,
                blocked_until: 0.0,
                timestamps: alloc::vec![now],
            };
            self.table.insert(*dest_hash, entry);
            return false;
        }

        let entry = self.table.get_mut(dest_hash).unwrap();

        entry.timestamps.push(now);
        while entry.timestamps.len() > constants::MAX_RATE_TIMESTAMPS {
            entry.timestamps.remove(0);
        }

        if now > entry.blocked_until {
            let current_rate = now - entry.last;

            if current_rate < rate_target {
                entry.rate_violations += 1;
            } else {
                entry.rate_violations = entry.rate_violations.saturating_sub(1);
            }

            if entry.rate_violations > rate_grace {
                entry.blocked_until = entry.last + rate_target + rate_penalty;
                true
            } else {
                entry.last = now;
                false
            }
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest(seed: u8) -> [u8; 16] {
        [seed; 16]
    }

    #[test]
    fn test_first_announce_not_blocked() {
        let mut limiter = AnnounceRateLimiter::new();
        assert!(!limiter.check_and_update(&dest(1), 100.0, Some(10.0), 3, 30.0));
    }

    #[test]
    fn test_no_target_never_blocked() {
        let mut limiter = AnnounceRateLimiter::new();
        // Even with rapid announces, no target means no blocking
        assert!(!limiter.check_and_update(&dest(1), 100.0, None, 0, 0.0));
        assert!(!limiter.check_and_update(&dest(1), 100.1, None, 0, 0.0));
    }

    #[test]
    fn test_slow_announces_not_blocked() {
        let mut limiter = AnnounceRateLimiter::new();
        let target = 10.0;
        // Each announce is 15s apart (> target of 10s)
        assert!(!limiter.check_and_update(&dest(1), 100.0, Some(target), 3, 30.0));
        assert!(!limiter.check_and_update(&dest(1), 115.0, Some(target), 3, 30.0));
        assert!(!limiter.check_and_update(&dest(1), 130.0, Some(target), 3, 30.0));
    }

    #[test]
    fn test_fast_announces_accumulate_violations() {
        let mut limiter = AnnounceRateLimiter::new();
        let target = 10.0;
        let grace = 2;
        let penalty = 30.0;

        // First announce: OK (initializes entry)
        assert!(!limiter.check_and_update(&dest(1), 100.0, Some(target), grace, penalty));
        // 2nd: too fast (1s < 10s target) → violation 1
        assert!(!limiter.check_and_update(&dest(1), 101.0, Some(target), grace, penalty));
        // 3rd: too fast → violation 2
        assert!(!limiter.check_and_update(&dest(1), 102.0, Some(target), grace, penalty));
        // 4th: too fast → violation 3 > grace(2) → BLOCKED
        assert!(limiter.check_and_update(&dest(1), 103.0, Some(target), grace, penalty));
    }

    #[test]
    fn test_blocked_stays_blocked() {
        let mut limiter = AnnounceRateLimiter::new();
        let target = 10.0;
        let grace = 0;
        let penalty = 30.0;

        // First announce
        assert!(!limiter.check_and_update(&dest(1), 100.0, Some(target), grace, penalty));
        // Too fast → violation 1 > grace(0) → BLOCKED
        // blocked_until = 100.0 + 10.0 + 30.0 = 140.0
        assert!(limiter.check_and_update(&dest(1), 101.0, Some(target), grace, penalty));
        // Still blocked at 120.0 < 140.0
        assert!(limiter.check_and_update(&dest(1), 120.0, Some(target), grace, penalty));
    }

    #[test]
    fn test_unblocked_after_penalty() {
        let mut limiter = AnnounceRateLimiter::new();
        let target = 10.0;
        let grace = 0;
        let penalty = 30.0;

        assert!(!limiter.check_and_update(&dest(1), 100.0, Some(target), grace, penalty));
        // blocked_until = 100.0 + 10.0 + 30.0 = 140.0
        assert!(limiter.check_and_update(&dest(1), 101.0, Some(target), grace, penalty));
        // After penalty expires (now = 150 > 140)
        assert!(!limiter.check_and_update(&dest(1), 150.0, Some(target), grace, penalty));
    }

    #[test]
    fn test_different_destinations_independent() {
        let mut limiter = AnnounceRateLimiter::new();
        assert!(!limiter.check_and_update(&dest(1), 100.0, Some(10.0), 0, 30.0));
        assert!(limiter.check_and_update(&dest(1), 101.0, Some(10.0), 0, 30.0));
        // Different destination is not affected
        assert!(!limiter.check_and_update(&dest(2), 101.0, Some(10.0), 0, 30.0));
    }
}
