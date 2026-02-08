use crate::constants::{
    LINK_KEEPALIVE_MAX, LINK_KEEPALIVE_MAX_RTT, LINK_KEEPALIVE_MIN,
    LINK_KEEPALIVE_TIMEOUT_FACTOR, LINK_STALE_FACTOR, LINK_STALE_GRACE,
    LINK_ESTABLISHMENT_TIMEOUT_PER_HOP,
};

/// Compute keepalive interval from RTT.
///
/// `keepalive = clamp(rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT), KEEPALIVE_MIN, KEEPALIVE_MAX)`
pub fn compute_keepalive(rtt: f64) -> f64 {
    let ka = rtt * (LINK_KEEPALIVE_MAX / LINK_KEEPALIVE_MAX_RTT);
    if ka > LINK_KEEPALIVE_MAX {
        LINK_KEEPALIVE_MAX
    } else if ka < LINK_KEEPALIVE_MIN {
        LINK_KEEPALIVE_MIN
    } else {
        ka
    }
}

/// Compute stale_time from keepalive interval.
pub fn compute_stale_time(keepalive: f64) -> f64 {
    keepalive * LINK_STALE_FACTOR
}

/// Compute establishment timeout.
///
/// `first_hop_timeout + per_hop * max(1, hops)`
///
/// Matches Python's initiator formula (Link.py:280-284).
pub fn compute_establishment_timeout(first_hop_timeout: f64, hops: u8) -> f64 {
    first_hop_timeout + LINK_ESTABLISHMENT_TIMEOUT_PER_HOP * (hops.max(1) as f64)
}

/// Check if link should transition to STALE.
///
/// Returns true if no inbound for `stale_time` seconds.
pub fn should_go_stale(last_inbound: f64, stale_time: f64, now: f64) -> bool {
    now >= last_inbound + stale_time
}

/// Check if link should send keepalive.
///
/// Returns true if no outbound keepalive for `keepalive` seconds.
pub fn should_send_keepalive(last_keepalive: f64, keepalive: f64, now: f64) -> bool {
    now >= last_keepalive + keepalive
}

/// Check if STALE link should close.
///
/// Returns true when `now >= stale_entered_at + rtt * KEEPALIVE_TIMEOUT_FACTOR + STALE_GRACE`.
/// In Python, STALE immediately sends a teardown packet and transitions to CLOSED on the next
/// watchdog iteration. We model this simply: once STALE is entered, it closes.
pub fn stale_close_timeout(rtt: f64) -> f64 {
    rtt * LINK_KEEPALIVE_TIMEOUT_FACTOR + LINK_STALE_GRACE
}

/// Check if PENDING/HANDSHAKE link timed out.
pub fn is_establishment_timeout(request_time: f64, timeout: f64, now: f64) -> bool {
    now >= request_time + timeout
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keepalive_fast_rtt() {
        // Very fast RTT should clamp to KEEPALIVE_MIN
        let ka = compute_keepalive(0.001);
        assert_eq!(ka, LINK_KEEPALIVE_MIN);
    }

    #[test]
    fn test_keepalive_max_rtt() {
        // RTT at max boundary
        let ka = compute_keepalive(LINK_KEEPALIVE_MAX_RTT);
        assert!((ka - LINK_KEEPALIVE_MAX).abs() < 0.001);
    }

    #[test]
    fn test_keepalive_slow_rtt() {
        // Very slow RTT should clamp to KEEPALIVE_MAX
        let ka = compute_keepalive(10.0);
        assert_eq!(ka, LINK_KEEPALIVE_MAX);
    }

    #[test]
    fn test_keepalive_mid_rtt() {
        let ka = compute_keepalive(0.5);
        let expected = 0.5 * (LINK_KEEPALIVE_MAX / LINK_KEEPALIVE_MAX_RTT);
        assert!((ka - expected).abs() < 0.001);
        assert!(ka > LINK_KEEPALIVE_MIN);
        assert!(ka < LINK_KEEPALIVE_MAX);
    }

    #[test]
    fn test_stale_time() {
        let ka = compute_keepalive(0.5);
        let st = compute_stale_time(ka);
        assert_eq!(st, ka * LINK_STALE_FACTOR);
    }

    #[test]
    fn test_establishment_timeout() {
        let timeout = compute_establishment_timeout(6.0, 3);
        // 6.0 + 6.0 * 3 = 24.0
        assert!((timeout - 24.0).abs() < 0.001);
    }

    #[test]
    fn test_establishment_timeout_zero_hops() {
        let timeout = compute_establishment_timeout(6.0, 0);
        // 6.0 + 6.0 * 1 = 12.0
        assert!((timeout - 12.0).abs() < 0.001);
    }

    #[test]
    fn test_should_go_stale() {
        assert!(!should_go_stale(100.0, 10.0, 105.0));
        assert!(should_go_stale(100.0, 10.0, 110.0));
        assert!(should_go_stale(100.0, 10.0, 115.0));
    }

    #[test]
    fn test_should_send_keepalive() {
        assert!(!should_send_keepalive(100.0, 10.0, 105.0));
        assert!(should_send_keepalive(100.0, 10.0, 110.0));
    }

    #[test]
    fn test_is_establishment_timeout() {
        assert!(!is_establishment_timeout(100.0, 30.0, 120.0));
        assert!(is_establishment_timeout(100.0, 30.0, 130.0));
        assert!(is_establishment_timeout(100.0, 30.0, 135.0));
    }
}
