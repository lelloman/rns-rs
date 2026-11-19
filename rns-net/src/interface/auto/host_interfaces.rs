//! The host's network interfaces: which ones to adopt.

use super::*;

/// Information about a local network interface with an IPv6 link-local address.
#[derive(Debug, Clone)]
pub struct LocalInterface {
    /// OS interface name, e.g. `eth0`.
    pub name: String,
    /// IPv6 link-local address, without scope ID.
    pub link_local_addr: String,
    /// OS interface index.
    pub index: u32,
}

#[cfg(target_os = "android")]
pub(super) fn platform_ignored_interfaces() -> &'static [&'static str] {
    ANDROID_IGNORE_IFS
}

#[cfg(not(target_os = "android"))]
pub(super) fn platform_ignored_interfaces() -> &'static [&'static str] {
    &[]
}

pub(super) fn should_adopt_interface_name(
    name: &str,
    allowed: &[String],
    ignored: &[String],
    platform_ignored: &[&str],
) -> bool {
    let is_allowed = allowed.iter().any(|a| a == name);
    let is_system_ignored = ALL_IGNORE_IFS.contains(&name) || platform_ignored.contains(&name);

    if is_system_ignored && !is_allowed {
        return false;
    }

    if ignored.iter().any(|ig| ig == name) {
        return false;
    }

    if !allowed.is_empty() && !is_allowed {
        return false;
    }

    true
}

/// Enumerate network interfaces that have IPv6 link-local addresses (fe80::/10).
///
/// Uses `libc::getifaddrs()`. Filters by allowed/ignored interface lists.
pub fn enumerate_interfaces(allowed: &[String], ignored: &[String]) -> Vec<LocalInterface> {
    let mut result: Vec<LocalInterface> = Vec::new();
    let platform_ignored = platform_ignored_interfaces();
    for ifa in crate::sys::interface_addresses() {
        // Must have an IPv6 address
        let Some(std::net::IpAddr::V6(ipv6)) = ifa.addr else {
            continue;
        };
        let Ok(name) = ifa.name.to_str() else {
            continue;
        };
        if !should_adopt_interface_name(name, allowed, ignored, platform_ignored) {
            continue;
        }
        // Must be link-local (fe80::/10)
        let octets = ipv6.octets();
        if octets[0] != 0xfe || (octets[1] & 0xc0) != 0x80 {
            continue;
        }
        // Format the address (drop scope ID, matching Python's descope_linklocal)
        let addr_str = format!("{}", ipv6);
        let index = crate::sys::interface_index(&ifa.name);
        if index == 0 {
            continue;
        }
        // Avoid duplicates (same interface may appear multiple times)
        if result.iter().any(|li| li.name == name) {
            continue;
        }
        result.push(LocalInterface {
            name: name.to_string(),
            link_local_addr: addr_str,
            index,
        });
    }
    result
}
