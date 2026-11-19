//! The host's network interfaces: which ones to adopt.

use super::*;

/// Information about a local network interface with an IPv6 link-local address.
#[derive(Debug, Clone)]
pub struct LocalInterface {
    pub name: String,
    pub link_local_addr: String,
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
#[allow(unsafe_code, reason = "getifaddrs/freeifaddrs")]
pub fn enumerate_interfaces(allowed: &[String], ignored: &[String]) -> Vec<LocalInterface> {
    let mut result = Vec::new();
    let platform_ignored = platform_ignored_interfaces();

    // SAFETY: `getifaddrs` fills `ifaddrs` with a list that stays valid until the
    // single `freeifaddrs` at the end (the early return happens before anything
    // was allocated). Each node is non-null when dereferenced, `ifa_addr` is
    // checked for null before reading `sa_family`, it is cast to `sockaddr_in6`
    // only when the family is AF_INET6, and `ifa_name` is the NUL-terminated name
    // the kernel sets on every entry.
    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            return result;
        }

        let mut current = ifaddrs;
        while !current.is_null() {
            let ifa = &*current;
            current = ifa.ifa_next;

            // Must have an address
            if ifa.ifa_addr.is_null() {
                continue;
            }

            // Must be AF_INET6
            if (*ifa.ifa_addr).sa_family as i32 != libc::AF_INET6 {
                continue;
            }

            // Get interface name
            let name = match std::ffi::CStr::from_ptr(ifa.ifa_name).to_str() {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };

            if !should_adopt_interface_name(&name, allowed, ignored, platform_ignored) {
                continue;
            }

            // Extract IPv6 address
            let sa6 = ifa.ifa_addr as *const libc::sockaddr_in6;
            let addr_bytes = (*sa6).sin6_addr.s6_addr;
            let ipv6 = Ipv6Addr::from(addr_bytes);

            // Must be link-local (fe80::/10)
            let octets = ipv6.octets();
            if octets[0] != 0xfe || (octets[1] & 0xc0) != 0x80 {
                continue;
            }

            // Format the address (drop scope ID, matching Python's descope_linklocal)
            let addr_str = format!("{}", ipv6);

            // Get interface index
            let index = libc::if_nametoindex(ifa.ifa_name);
            if index == 0 {
                continue;
            }

            // Avoid duplicates (same interface may appear multiple times)
            if result.iter().any(|li: &LocalInterface| li.name == name) {
                continue;
            }

            result.push(LocalInterface {
                name,
                link_local_addr: addr_str,
                index,
            });
        }

        libc::freeifaddrs(ifaddrs);
    }

    result
}
