//! Host candidates: addresses of this node's own interfaces, offered to a
//! link peer on the same network so that the two can punch to each other
//! across their LAN instead of through their NAT.
//!
//! Only LAN addresses are offered (IPv4 private ranges and IPv6
//! unique-local addresses): a global address of an interface is what the
//! facilitator sees anyway. A peer's host candidate is only punched when
//! the peer is behind the same NAT (its public address is this node's) and
//! the candidate is on a network one of this node's interfaces is on, so a
//! peer cannot point a punch at an arbitrary private address.

use std::net::{IpAddr, SocketAddr};

use rns_core::holepunch::MAX_HOST_CANDIDATES;

/// An address of one of this node's interfaces, with its prefix length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalNetwork {
    pub(crate) interface: String,
    pub(crate) addr: IpAddr,
    pub(crate) prefix: u8,
}

impl LocalNetwork {
    /// Whether `ip` is on this network.
    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let bits = u32::from(self.prefix.min(32));
                let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let bits = u32::from(self.prefix.min(128));
                let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// The addresses of this node's interfaces that are up, other than
/// loopback, with their prefix lengths.
pub(crate) fn local_networks() -> Vec<LocalNetwork> {
    crate::sys::interface_addresses()
        .into_iter()
        .filter(|ifa| {
            ifa.flags & libc::IFF_UP as u32 != 0 && ifa.flags & libc::IFF_LOOPBACK as u32 == 0
        })
        .filter_map(|ifa| {
            let (addr, mask) = (ifa.addr?, ifa.netmask?);
            let prefix = match mask {
                IpAddr::V4(m) => u32::from(m).count_ones() as u8,
                IpAddr::V6(m) => u128::from(m).count_ones() as u8,
            };
            Some(LocalNetwork {
                interface: ifa.name.to_string_lossy().into_owned(),
                addr,
                prefix,
            })
        })
        .collect()
}

/// Whether `ip` is a LAN address: IPv4 private (10/8, 172.16/12,
/// 192.168/16) or IPv6 unique-local (fc00::/7). IPv4-mapped addresses are
/// taken as their IPv4 form.
pub(crate) fn is_lan_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.is_private(),
            None => v6.is_unique_local(),
        },
    }
}

/// This node's host candidates for a punch socket bound to `port` whose
/// public mapping is `observed`: its LAN addresses of `observed`'s family
/// (on `device` only, when one is set), at most [`MAX_HOST_CANDIDATES`].
/// None when the mapping is an address of this node, which is then not
/// behind a NAT.
pub(crate) fn host_candidates(
    networks: &[LocalNetwork],
    device: Option<&str>,
    port: u16,
    observed: SocketAddr,
) -> Vec<SocketAddr> {
    let observed = super::canonical(observed);
    // Not behind a NAT: the peer reaches this node at its mapping.
    if networks.iter().any(|network| network.addr == observed.ip()) {
        return Vec::new();
    }
    let mut hosts: Vec<SocketAddr> = Vec::new();
    for network in networks {
        if device.is_some_and(|device| device != network.interface)
            || network.addr.is_ipv4() != observed.is_ipv4()
            || !is_lan_address(network.addr)
        {
            continue;
        }
        let candidate = SocketAddr::new(network.addr, port);
        if !hosts.contains(&candidate) {
            hosts.push(candidate);
        }
        if hosts.len() == MAX_HOST_CANDIDATES {
            break;
        }
    }
    hosts
}

/// Why the peer's host candidate `candidate` may not be punched, or
/// `None` if it may: it must be a LAN address of the family of this
/// node's mapping `observed`, the peer's public endpoint `peer_public`
/// must be at this node's public address (behind the same NAT), and the
/// candidate must be on one of `networks` but not this node's own.
pub(crate) fn host_candidate_refusal(
    candidate: SocketAddr,
    networks: &[LocalNetwork],
    observed: SocketAddr,
    peer_public: SocketAddr,
) -> Option<&'static str> {
    let candidate = super::canonical(candidate);
    let observed = super::canonical(observed);
    if candidate.port() == 0 || !is_lan_address(candidate.ip()) {
        return Some("not a LAN address");
    }
    if candidate.is_ipv4() != observed.is_ipv4() {
        return Some("of another address family than the probed mapping");
    }
    if super::canonical(peer_public).ip() != observed.ip() {
        return Some("of a peer behind another NAT");
    }
    if networks
        .iter()
        .any(|network| network.addr == candidate.ip())
    {
        return Some("this node");
    }
    if !networks
        .iter()
        .any(|network| network.contains(candidate.ip()))
    {
        return Some("not on a network of this node");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(addr: &str, prefix: u8) -> LocalNetwork {
        LocalNetwork {
            interface: "eth0".into(),
            addr: addr.parse().unwrap(),
            prefix,
        }
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn networks_contain_their_prefix() {
        let lan = net("192.168.1.20", 24);
        assert!(lan.contains("192.168.1.200".parse().unwrap()));
        assert!(!lan.contains("192.168.2.1".parse().unwrap()));
        assert!(!lan.contains("fd00::1".parse().unwrap()));
        assert!(net("10.0.0.1", 0).contains("10.9.9.9".parse().unwrap()));
        let ula = net("fd12:3456:789a:1::5", 64);
        assert!(ula.contains("fd12:3456:789a:1::9".parse().unwrap()));
        assert!(!ula.contains("fd12:3456:789a:2::9".parse().unwrap()));
    }

    #[test]
    fn only_lan_addresses_of_the_mapping_family_are_offered() {
        let networks = vec![
            net("192.168.1.20", 24),
            net("203.0.113.7", 24),
            net("100.64.0.9", 10),
            net("169.254.3.3", 16),
            net("10.8.0.2", 24),
            net("172.16.5.5", 16),
            net("fd00::5", 64),
        ];
        assert_eq!(
            host_candidates(&networks, None, 4000, sa("198.51.100.1:62000")),
            vec![sa("192.168.1.20:4000"), sa("10.8.0.2:4000")]
        );
        assert_eq!(
            host_candidates(&networks, None, 4000, sa("[2001:db8::1]:62000")),
            vec![sa("[fd00::5]:4000")]
        );
        // On the configured device only.
        let mut tun = net("10.9.0.2", 24);
        tun.interface = "tun0".into();
        assert_eq!(
            host_candidates(&[tun], Some("eth0"), 4000, sa("198.51.100.1:62000")),
            Vec::<SocketAddr>::new()
        );
        // Not behind a NAT: the address is the mapping itself.
        assert!(host_candidates(&networks, None, 4000, sa("192.168.1.20:4000")).is_empty());
    }

    #[test]
    fn a_peer_host_candidate_must_be_a_neighbour_behind_the_same_nat() {
        let networks = vec![net("192.168.1.20", 24)];
        let observed = sa("198.51.100.1:62000");
        let peer_public = sa("198.51.100.1:62001");
        let ok = sa("192.168.1.30:5000");
        assert_eq!(
            host_candidate_refusal(ok, &networks, observed, peer_public),
            None
        );
        for (candidate, peer_public) in [
            // A public address is not a host candidate.
            (sa("203.0.113.9:5000"), peer_public),
            // Port 0, loopback, link-local, shared.
            (sa("192.168.1.30:0"), peer_public),
            (sa("127.0.0.1:5000"), peer_public),
            (sa("169.254.1.1:5000"), peer_public),
            (sa("100.64.1.1:5000"), peer_public),
            // Another network than ours.
            (sa("192.168.2.30:5000"), peer_public),
            (sa("10.0.0.1:5000"), peer_public),
            // This node's own address.
            (sa("192.168.1.20:5000"), peer_public),
            // A peer behind another NAT.
            (ok, sa("203.0.113.50:62001")),
            // Another family.
            (sa("[fd00::30]:5000"), peer_public),
        ] {
            assert!(
                host_candidate_refusal(candidate, &networks, observed, peer_public).is_some(),
                "{candidate} from {peer_public}"
            );
        }
    }

    #[test]
    fn local_networks_leave_out_loopback() {
        let networks = local_networks();
        assert!(networks.iter().all(|n| !n.addr.is_loopback()));
        assert!(networks
            .iter()
            .all(|n| n.prefix <= if n.addr.is_ipv4() { 32 } else { 128 }));
    }
}
