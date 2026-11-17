pub mod admission;
mod candidates;
mod folded_probe;
pub mod orchestrator;
pub mod path_mtu;
pub mod probe;
pub mod puncher;
pub mod udp_direct;

/// A poller key for a hole-punch probe or punch served on the driver loop
/// (see [`crate::engine::FOLD_SERVICES`]).
pub(crate) fn next_loop_key() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let keys = crate::engine::service_keys::HOLEPUNCH;
    keys.start + NEXT.fetch_add(1, Ordering::Relaxed) % keys.len()
}

/// `addr` with an IPv4-mapped IPv6 address as its IPv4 form.
pub(crate) fn canonical(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    match addr {
        std::net::SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => std::net::SocketAddr::new(v4.into(), v6.port()),
            None => addr,
        },
        v4 => v4,
    }
}

/// Whether `a` and `b` are equal, in time that does not depend on where
/// they differ.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Entry points for the fuzz targets in `fuzz/`: the decoders of every
/// datagram Direct Link reads from the network. Not a stable API.
#[doc(hidden)]
pub mod fuzz {
    /// A datagram at a punch socket.
    pub fn punch_datagram(data: &[u8]) {
        super::puncher::fuzz_datagram(data);
    }

    /// A datagram at a probe server.
    pub fn probe_request(data: &[u8]) {
        super::probe::fuzz_request(data);
    }

    /// A datagram at a probing socket.
    pub fn probe_reply(data: &[u8]) {
        super::probe::fuzz_reply(data);
    }

    /// A datagram at a direct path, as a keepalive.
    pub fn keepalive(data: &[u8]) {
        super::udp_direct::fuzz_keepalive(data);
    }

    /// A datagram at a direct path, as a path MTU probe or acknowledgement.
    pub fn path_mtu_datagram(data: &[u8]) {
        super::path_mtu::fuzz_datagram(data);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn fuzz_entry_points_take_any_bytes() {
        let inputs: [&[u8]; 6] = [b"", b"RNSH", b"RNSA", b"RNSK", &[0xff; 52], &[0x52; 1500]];
        for data in inputs {
            super::fuzz::punch_datagram(data);
            super::fuzz::probe_request(data);
            super::fuzz::probe_reply(data);
            super::fuzz::keepalive(data);
            super::fuzz::path_mtu_datagram(data);
        }
    }
}
