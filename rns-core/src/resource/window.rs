use crate::constants::*;

/// Window adaptation state for resource transfers.
///
/// Tracks window size, min/max bounds, and rate detection for
/// fast/very-slow link adaptation.
#[derive(Debug, Clone)]
pub struct WindowState {
    pub window: usize,
    pub window_max: usize,
    pub window_min: usize,
    pub window_flexibility: usize,
    pub fast_rate_rounds: usize,
    pub very_slow_rate_rounds: usize,
}

impl WindowState {
    pub fn new() -> Self {
        WindowState {
            window: RESOURCE_WINDOW,
            window_max: RESOURCE_WINDOW_MAX_SLOW,
            window_min: RESOURCE_WINDOW_MIN,
            window_flexibility: RESOURCE_WINDOW_FLEXIBILITY,
            fast_rate_rounds: 0,
            very_slow_rate_rounds: 0,
        }
    }

    /// Restore window state from a previous transfer on the same link.
    pub fn restore(&mut self, previous_window: usize) {
        self.window = previous_window;
    }

    /// Called when all outstanding parts in the window are received.
    /// Grows window and ratchets window_min.
    pub fn on_window_complete(&mut self) {
        if self.window < self.window_max {
            self.window += 1;
            if (self.window as isize - self.window_min as isize)
                > (self.window_flexibility as isize - 1)
            {
                self.window_min += 1;
            }
        }
    }

    /// Called on timeout waiting for parts.
    /// Shrinks window, shrinks window_max (can decrease by 2).
    pub fn on_timeout(&mut self) {
        if self.window > self.window_min {
            self.window -= 1;
            if self.window_max > self.window_min {
                self.window_max -= 1;
                if (self.window_max as isize - self.window as isize)
                    > (self.window_flexibility as isize - 1)
                {
                    self.window_max -= 1;
                }
            }
        }
    }

    /// Update rate tracking based on measured req_resp_rtt_rate.
    /// Called after first part of a window is received.
    pub fn update_req_resp_rate(&mut self, rate: f64) {
        if rate > RESOURCE_RATE_FAST && self.fast_rate_rounds < RESOURCE_FAST_RATE_THRESHOLD {
            self.fast_rate_rounds += 1;
            if self.fast_rate_rounds == RESOURCE_FAST_RATE_THRESHOLD {
                self.window_max = RESOURCE_WINDOW_MAX_FAST;
            }
        }
    }

    /// Update rate tracking based on measured data RTT rate.
    /// Called after a full window of parts is received.
    pub fn update_data_rate(&mut self, rate: f64) {
        if rate > RESOURCE_RATE_FAST && self.fast_rate_rounds < RESOURCE_FAST_RATE_THRESHOLD {
            self.fast_rate_rounds += 1;
            if self.fast_rate_rounds == RESOURCE_FAST_RATE_THRESHOLD {
                self.window_max = RESOURCE_WINDOW_MAX_FAST;
            }
        }

        // Very slow detection only when fast_rate_rounds == 0
        if self.fast_rate_rounds == 0
            && rate < RESOURCE_RATE_VERY_SLOW
            && self.very_slow_rate_rounds < RESOURCE_VERY_SLOW_RATE_THRESHOLD
        {
            self.very_slow_rate_rounds += 1;
            if self.very_slow_rate_rounds == RESOURCE_VERY_SLOW_RATE_THRESHOLD {
                self.window_max = RESOURCE_WINDOW_MAX_VERY_SLOW;
            }
        }
    }
}

impl Default for WindowState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let ws = WindowState::new();
        assert_eq!(ws.window, RESOURCE_WINDOW); // 4
        assert_eq!(ws.window_max, RESOURCE_WINDOW_MAX_SLOW); // 10
        assert_eq!(ws.window_min, RESOURCE_WINDOW_MIN); // 2
        assert_eq!(ws.window_flexibility, RESOURCE_WINDOW_FLEXIBILITY); // 4
        assert_eq!(ws.fast_rate_rounds, 0);
        assert_eq!(ws.very_slow_rate_rounds, 0);
    }

    #[test]
    fn test_window_increase_on_complete() {
        let mut ws = WindowState::new();
        // window=4, window_max=10, window_min=2, flexibility=4
        ws.on_window_complete();
        // window -> 5; (5-2)=3, not > (4-1)=3, so window_min stays 2
        assert_eq!(ws.window, 5);
        assert_eq!(ws.window_min, 2);

        ws.on_window_complete();
        // window -> 6; (6-2)=4 > 3, so window_min -> 3
        assert_eq!(ws.window, 6);
        assert_eq!(ws.window_min, 3);
    }

    #[test]
    fn test_window_capped_at_max() {
        let mut ws = WindowState::new();
        ws.window = 10;
        ws.window_max = 10;
        ws.on_window_complete();
        assert_eq!(ws.window, 10); // didn't increase
    }

    #[test]
    fn test_window_decrease_on_timeout() {
        let mut ws = WindowState::new();
        // window=4, window_max=10, window_min=2
        ws.on_timeout();
        // window -> 3, window_max -> 9
        // (9-3)=6 > (4-1)=3, so window_max -> 8
        assert_eq!(ws.window, 3);
        assert_eq!(ws.window_max, 8);
    }

    #[test]
    fn test_window_min_floor() {
        let mut ws = WindowState::new();
        ws.window = RESOURCE_WINDOW_MIN;
        ws.on_timeout();
        assert_eq!(ws.window, RESOURCE_WINDOW_MIN); // can't go below min
    }

    #[test]
    fn test_fast_rate_detection() {
        let mut ws = WindowState::new();
        // Need FAST_RATE_THRESHOLD(4) rounds of fast rate
        for _ in 0..3 {
            ws.update_req_resp_rate(RESOURCE_RATE_FAST + 1.0);
        }
        assert_eq!(ws.fast_rate_rounds, 3);
        assert_eq!(ws.window_max, RESOURCE_WINDOW_MAX_SLOW); // not yet

        ws.update_req_resp_rate(RESOURCE_RATE_FAST + 1.0);
        assert_eq!(ws.fast_rate_rounds, 4);
        assert_eq!(ws.window_max, RESOURCE_WINDOW_MAX_FAST); // now!
    }

    #[test]
    fn test_fast_rate_rounds_never_reset() {
        let mut ws = WindowState::new();
        ws.update_req_resp_rate(RESOURCE_RATE_FAST + 1.0);
        assert_eq!(ws.fast_rate_rounds, 1);

        // Slow rate doesn't reset fast_rate_rounds
        ws.update_req_resp_rate(1.0);
        assert_eq!(ws.fast_rate_rounds, 1);
    }

    #[test]
    fn test_fast_rate_rounds_cap() {
        let mut ws = WindowState::new();
        for _ in 0..10 {
            ws.update_req_resp_rate(RESOURCE_RATE_FAST + 1.0);
        }
        // Capped at threshold
        assert_eq!(ws.fast_rate_rounds, RESOURCE_FAST_RATE_THRESHOLD);
    }

    #[test]
    fn test_very_slow_detection() {
        let mut ws = WindowState::new();
        // fast_rate_rounds must be 0
        assert_eq!(ws.fast_rate_rounds, 0);

        ws.update_data_rate(RESOURCE_RATE_VERY_SLOW - 1.0);
        assert_eq!(ws.very_slow_rate_rounds, 1);
        assert_eq!(ws.window_max, RESOURCE_WINDOW_MAX_SLOW); // not yet

        ws.update_data_rate(RESOURCE_RATE_VERY_SLOW - 1.0);
        assert_eq!(ws.very_slow_rate_rounds, 2);
        assert_eq!(ws.window_max, RESOURCE_WINDOW_MAX_VERY_SLOW); // capped!
    }

    #[test]
    fn test_very_slow_blocked_by_fast() {
        let mut ws = WindowState::new();
        // Set fast_rate_rounds > 0
        ws.update_data_rate(RESOURCE_RATE_FAST + 1.0);
        assert_eq!(ws.fast_rate_rounds, 1);

        // Very slow should not trigger
        ws.update_data_rate(RESOURCE_RATE_VERY_SLOW - 1.0);
        assert_eq!(ws.very_slow_rate_rounds, 0);
    }

    #[test]
    fn test_restore_window() {
        let mut ws = WindowState::new();
        ws.restore(8);
        assert_eq!(ws.window, 8);
    }

    #[test]
    fn test_window_never_below_min() {
        let mut ws = WindowState::new();
        ws.window = 2;
        ws.window_min = 2;
        ws.on_timeout();
        assert_eq!(ws.window, 2);
    }

    #[test]
    fn test_window_never_above_max() {
        let mut ws = WindowState::new();
        ws.window = 10;
        ws.window_max = 10;
        ws.on_window_complete();
        assert_eq!(ws.window, 10);
    }

    #[test]
    fn timeout_keeps_the_window_at_its_minimum() {
        let mut ws = WindowState::new();
        ws.window = ws.window_min;
        let max = ws.window_max;
        ws.on_timeout();
        assert_eq!(ws.window, ws.window_min);
        assert_eq!(ws.window_max, max);
    }

    #[test]
    fn timeout_shrinks_the_maximum_twice_only_beyond_the_flexibility() {
        // window 5 -> 4, max 8 -> 7: 7 - 4 is within the flexibility.
        let mut ws = WindowState::new();
        ws.window = 5;
        ws.window_max = 8;
        ws.on_timeout();
        assert_eq!((ws.window, ws.window_max), (4, 7));

        // window 5 -> 4, max 9 -> 8: 8 - 4 is beyond it, so max -> 7.
        let mut ws = WindowState::new();
        ws.window = 5;
        ws.window_max = 9;
        ws.on_timeout();
        assert_eq!((ws.window, ws.window_max), (4, 7));
    }

    #[test]
    fn rates_at_the_thresholds_do_not_count() {
        let mut ws = WindowState::new();
        ws.update_req_resp_rate(RESOURCE_RATE_FAST);
        ws.update_data_rate(RESOURCE_RATE_FAST);
        assert_eq!(ws.fast_rate_rounds, 0);
        ws.update_data_rate(RESOURCE_RATE_VERY_SLOW);
        assert_eq!(ws.very_slow_rate_rounds, 0);
    }

    #[test]
    fn fast_rounds_raise_the_maximum_only_at_the_threshold() {
        let mut ws = WindowState::new();
        for round in 1..RESOURCE_FAST_RATE_THRESHOLD {
            ws.update_data_rate(RESOURCE_RATE_FAST * 2.0);
            assert_eq!(ws.fast_rate_rounds, round);
            assert_eq!(ws.window_max, RESOURCE_WINDOW_MAX_SLOW);
        }
        ws.update_data_rate(RESOURCE_RATE_FAST * 2.0);
        assert_eq!(ws.window_max, RESOURCE_WINDOW_MAX_FAST);
        // Counting stops at the threshold.
        ws.update_data_rate(RESOURCE_RATE_FAST * 2.0);
        assert_eq!(ws.fast_rate_rounds, RESOURCE_FAST_RATE_THRESHOLD);
    }

    #[test]
    fn very_slow_rounds_stop_at_the_threshold() {
        let mut ws = WindowState::new();
        for _ in 0..RESOURCE_VERY_SLOW_RATE_THRESHOLD + 1 {
            ws.update_data_rate(RESOURCE_RATE_VERY_SLOW / 2.0);
        }
        assert_eq!(ws.very_slow_rate_rounds, RESOURCE_VERY_SLOW_RATE_THRESHOLD);
        assert_eq!(ws.window_max, RESOURCE_WINDOW_MAX_VERY_SLOW);
    }

    #[test]
    fn timeout_keeps_the_maximum_at_the_minimum() {
        // A window restored above the maximum still shrinks; the maximum,
        // already at the minimum, does not.
        let mut ws = WindowState::new();
        ws.restore(3);
        ws.window_max = ws.window_min;
        ws.on_timeout();
        assert_eq!(ws.window, 2);
        assert_eq!(ws.window_max, ws.window_min);
    }
}
