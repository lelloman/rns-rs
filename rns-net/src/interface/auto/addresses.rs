//! The multicast address and discovery token derived from the group id.

use super::*;

/// Derive the IPv6 multicast discovery address from group_id, scope, and address type.
///
/// Algorithm (matching Python):
///   1. group_hash = SHA-256(group_id)
///   2. Build suffix from hash bytes 2..14 as 6 little-endian 16-bit words
///   3. First word is hardcoded "0"
///   4. Prefix = "ff" + address_type + scope
pub(crate) fn derive_multicast_address(group_id: &[u8], address_type: &str, scope: &str) -> String {
    let group_hash = rns_crypto::sha256::sha256(group_id);
    let g = &group_hash;

    // Build 6 LE 16-bit words from bytes 2..14
    let w1 = (g[2] as u16) << 8 | g[3] as u16;
    let w2 = (g[4] as u16) << 8 | g[5] as u16;
    let w3 = (g[6] as u16) << 8 | g[7] as u16;
    let w4 = (g[8] as u16) << 8 | g[9] as u16;
    let w5 = (g[10] as u16) << 8 | g[11] as u16;
    let w6 = (g[12] as u16) << 8 | g[13] as u16;

    format!(
        "ff{}{}:0:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        address_type, scope, w1, w2, w3, w4, w5, w6
    )
}

/// Parse a multicast address string into an Ipv6Addr.
pub(crate) fn parse_multicast_addr(addr: &str) -> Option<Ipv6Addr> {
    addr.parse::<Ipv6Addr>().ok()
}

/// Compute the discovery token: SHA-256(group_id + link_local_address_string).
pub(crate) fn compute_discovery_token(group_id: &[u8], link_local_addr: &str) -> [u8; 32] {
    let mut input = group_id.to_vec();
    input.extend_from_slice(link_local_addr.as_bytes());
    rns_crypto::sha256::sha256(&input)
}
