//! Admission checks for inbound direct-connect requests.
//!
//! An `UPGRADE_REQUEST` names two endpoints chosen by the link peer: the
//! facilitator the responder probes and the initiator endpoint the responder
//! sends punch packets to. Before any packet is sent, both endpoints must name
//! a globally routable unicast address (unless the operator opts in to private
//! endpoints for LAN-only deployments), and inbound requests are paced per
//! link with a node-wide cap on concurrent sessions.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

/// Minimum spacing between two inbound upgrade requests on the same link.
pub const INBOUND_REQUEST_WINDOW: Duration = Duration::from_secs(60);

/// Maximum number of inbound (responder) sessions, and of running punch
/// threads, active at once node-wide.
pub const MAX_CONCURRENT_SESSIONS: usize = 4;

/// Upper bound on the number of links tracked by the inbound request limiter.
const MAX_TRACKED_LINKS: usize = 1024;

/// Returns true if `addr` may be used as a probe or punch target named by a
/// link peer.
///
/// Always rejected: port 0, unspecified, loopback, multicast, broadcast,
/// documentation and benchmarking ranges, and the IPv4 "this network" and
/// reserved (240.0.0.0/4) ranges. Rejected unless `allow_private` is set:
/// IPv4 private (10/8, 172.16/12, 192.168/16), shared address space
/// (100.64/10), link-local (169.254/16, fe80::/10) and IPv6 unique-local
/// (fc00::/7). IPv4-mapped IPv6 addresses are checked as their IPv4 form.
pub fn endpoint_is_acceptable(addr: &SocketAddr, allow_private: bool) -> bool {
    if addr.port() == 0 {
        return false;
    }
    match addr.ip() {
        IpAddr::V4(v4) => ipv4_is_acceptable(v4, allow_private),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => ipv4_is_acceptable(v4, allow_private),
            None => ipv6_is_acceptable(v6, allow_private),
        },
    }
}

fn ipv4_is_acceptable(ip: Ipv4Addr, allow_private: bool) -> bool {
    let o = ip.octets();
    let this_network = o[0] == 0;
    let reserved = o[0] >= 240; // includes 255.255.255.255
    let benchmarking = o[0] == 198 && (o[1] & 0xfe) == 18; // 198.18.0.0/15
    if ip.is_unspecified()
        || this_network
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.is_broadcast()
        || reserved
        || ip.is_documentation()
        || benchmarking
    {
        return false;
    }
    let shared = o[0] == 100 && (o[1] & 0xc0) == 64; // 100.64.0.0/10
    let local = ip.is_private() || ip.is_link_local() || shared;
    allow_private || !local
}

fn ipv6_is_acceptable(ip: Ipv6Addr, allow_private: bool) -> bool {
    let s = ip.segments();
    let documentation = s[0] == 0x2001 && s[1] == 0x0db8; // 2001:db8::/32
    let documentation_3fff = s[0] == 0x3fff && (s[1] & 0xf000) == 0; // 3fff::/20
    let benchmarking = s[0] == 0x2001 && s[1] == 0x0002 && s[2] == 0; // 2001:2::/48
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || documentation
        || documentation_3fff
        || benchmarking
    {
        return false;
    }
    let local = ip.is_unique_local() || ip.is_unicast_link_local();
    allow_private || !local
}

/// Paces inbound upgrade requests per link.
///
/// The decision function takes `now` so callers and tests control the clock.
#[derive(Debug)]
pub(crate) struct InboundRequestLimiter {
    window: Duration,
    last_request: HashMap<[u8; 16], Instant>,
}

impl InboundRequestLimiter {
    pub(crate) fn new(window: Duration) -> Self {
        InboundRequestLimiter {
            window,
            last_request: HashMap::new(),
        }
    }

    /// Returns true (and records the request) when a request on `link_id` is
    /// allowed at `now`; false when one was already accepted inside the window
    /// or the tracking table is full.
    pub(crate) fn check_and_record(&mut self, link_id: [u8; 16], now: Instant) -> bool {
        let window = self.window;
        self.last_request
            .retain(|_, at| now.saturating_duration_since(*at) < window);
        if self.last_request.contains_key(&link_id) {
            return false;
        }
        if self.last_request.len() >= MAX_TRACKED_LINKS {
            return false;
        }
        self.last_request.insert(link_id, now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acceptable(s: &str, allow_private: bool) -> bool {
        endpoint_is_acceptable(&s.parse::<SocketAddr>().unwrap(), allow_private)
    }

    #[test]
    fn endpoint_validator_table() {
        // (address, accepted by default, accepted with allow_private)
        let cases: &[(&str, bool, bool)] = &[
            // Globally routable
            ("1.2.3.4:4343", true, true),
            ("8.8.8.8:41000", true, true),
            ("[2a00:1450::1]:4343", true, true),
            ("[::ffff:1.2.3.4]:4343", true, true),
            // Port 0
            ("1.2.3.4:0", false, false),
            ("[2a00:1450::1]:0", false, false),
            // Unspecified / this network
            ("0.0.0.0:4343", false, false),
            ("0.1.2.3:4343", false, false),
            ("[::]:4343", false, false),
            // Loopback
            ("127.0.0.1:4343", false, false),
            ("127.1.2.3:4343", false, false),
            ("[::1]:4343", false, false),
            ("[::ffff:127.0.0.1]:4343", false, false),
            // Multicast
            ("224.0.0.1:4343", false, false),
            ("239.255.255.250:1900", false, false),
            ("[ff02::1]:4343", false, false),
            ("[::ffff:224.0.0.1]:4343", false, false),
            // Broadcast / reserved
            ("255.255.255.255:4343", false, false),
            ("240.0.0.1:4343", false, false),
            // Documentation / benchmarking
            ("192.0.2.1:4343", false, false),
            ("198.51.100.7:4343", false, false),
            ("203.0.113.9:4343", false, false),
            ("198.18.0.1:4343", false, false),
            ("198.19.255.254:4343", false, false),
            ("[2001:db8::1]:4343", false, false),
            ("[3fff::1]:4343", false, false),
            ("[2001:2::1]:4343", false, false),
            ("[::ffff:192.0.2.1]:4343", false, false),
            // Private ranges: only with allow_private
            ("10.0.0.1:4343", false, true),
            ("172.16.0.1:4343", false, true),
            ("172.31.255.254:4343", false, true),
            ("192.168.1.10:4343", false, true),
            ("100.64.0.1:4343", false, true),
            ("100.127.255.254:4343", false, true),
            ("169.254.1.1:4343", false, true),
            ("[fe80::1]:4343", false, true),
            ("[fc00::1]:4343", false, true),
            ("[fd12:3456::1]:4343", false, true),
            ("[::ffff:10.0.0.1]:4343", false, true),
            ("[::ffff:192.168.1.10]:4343", false, true),
            ("[::ffff:169.254.1.1]:4343", false, true),
            // Neighbours of the private ranges stay public
            ("172.32.0.1:4343", true, true),
            ("100.128.0.1:4343", true, true),
            ("192.169.0.1:4343", true, true),
        ];
        for (addr, default_ok, private_ok) in cases {
            assert_eq!(acceptable(addr, false), *default_ok, "{addr} (default)");
            assert_eq!(
                acceptable(addr, true),
                *private_ok,
                "{addr} (allow_private)"
            );
        }
    }

    #[test]
    fn limiter_refuses_second_request_inside_window_and_allows_after() {
        let mut limiter = InboundRequestLimiter::new(INBOUND_REQUEST_WINDOW);
        let t0 = Instant::now();
        let link = [0x11; 16];
        assert!(limiter.check_and_record(link, t0));
        assert!(!limiter.check_and_record(link, t0 + Duration::from_secs(1)));
        assert!(!limiter.check_and_record(link, t0 + Duration::from_secs(59)));
        // Another link is paced independently.
        assert!(limiter.check_and_record([0x22; 16], t0 + Duration::from_secs(59)));
        assert!(limiter.check_and_record(link, t0 + INBOUND_REQUEST_WINDOW));
    }

    #[test]
    fn limiter_bounds_tracked_links() {
        let mut limiter = InboundRequestLimiter::new(INBOUND_REQUEST_WINDOW);
        let t0 = Instant::now();
        for i in 0..MAX_TRACKED_LINKS {
            let mut link = [0u8; 16];
            link[..8].copy_from_slice(&(i as u64).to_be_bytes());
            assert!(limiter.check_and_record(link, t0));
        }
        assert!(!limiter.check_and_record([0xFF; 16], t0));
        // Entries expire with the window and free the table again.
        assert!(limiter.check_and_record([0xFF; 16], t0 + INBOUND_REQUEST_WINDOW));
    }
}
