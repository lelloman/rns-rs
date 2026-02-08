//! Time utilities.

use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current time as seconds since the Unix epoch.
pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_returns_reasonable_epoch() {
        let t = now();
        // Should be after 2024-01-01 (1704067200)
        assert!(t > 1_704_067_200.0);
        // Should be before 2050-01-01 (2524608000)
        assert!(t < 2_524_608_000.0);
    }

    #[test]
    fn now_is_monotonic() {
        let t1 = now();
        let t2 = now();
        assert!(t2 >= t1);
    }
}
