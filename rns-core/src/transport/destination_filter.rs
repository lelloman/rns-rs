//! Announce filtering by destination type (upstream 825c2e19).
//!
//! A destination type is the name hash of its full name, such as
//! `lxmf.delivery`. Announces of a blocked type are dropped at ingress. With
//! `required_only`, only announces of an allowed type, a type some local
//! application asked for, or a local client's or the shared instance's own
//! destinations get through.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use crate::constants;
use crate::hash;

/// Name hash of a destination type.
pub type DestinationType = [u8; constants::NAME_HASH_LENGTH / 8];

/// `Destination.name_hash(full_name)`: the name hash of a full destination
/// name. Python splits the name at the dots and joins it back unchanged, so
/// this hashes the name as given.
pub fn destination_type(full_name: &str) -> DestinationType {
    let full = hash::full_hash(full_name.as_bytes());
    let mut name_hash = [0u8; constants::NAME_HASH_LENGTH / 8];
    name_hash.copy_from_slice(&full[..constants::NAME_HASH_LENGTH / 8]);
    name_hash
}

/// A destination type as `Transport.block_destination_type` and
/// `allow_destination_type` read it (upstream e96c81c3): a full name such as
/// `lxmf.delivery`, or a name hash written as `<hex>`.
///
/// For the bracketed form upstream keeps the 20 characters after the `<`
/// (a name hash's length in hex) and decodes them. If they are not hex,
/// which includes shorter hex that keeps the closing `>`, it hashes those
/// characters as a name instead. Upstream's `bytes.fromhex` also skips
/// whitespace between bytes, which this does not; such an entry is hashed
/// as a name here and gives upstream a short key that matches nothing. An
/// empty name, which upstream ignores, yields `None`.
pub fn configured_destination_type(full_name: &str) -> Option<DestinationType> {
    if full_name.is_empty() {
        return None;
    }
    let hex_len = constants::NAME_HASH_LENGTH / 8 * 2;
    let Some(inner) = full_name
        .strip_prefix('<')
        .filter(|_| full_name.ends_with('>'))
    else {
        return Some(destination_type(full_name));
    };
    let kept: String = inner.chars().take(hex_len).collect();
    match decode_hex(&kept) {
        Some(bytes) => DestinationType::try_from(bytes.as_slice()).ok(),
        None => Some(destination_type(&kept)),
    }
}

/// `bytes.fromhex` for ASCII hex without separators.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// The `Transport` destination type tables: `blocked_destination_types`,
/// `allowed_destination_types`, `client_destination_types` and
/// `required_destinations_only`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DestinationTypeFilter {
    required_only: bool,
    blocked: BTreeSet<DestinationType>,
    allowed: BTreeSet<DestinationType>,
    /// Types local applications asked for, with the requesters asking.
    wanted: BTreeMap<DestinationType, BTreeSet<Vec<u8>>>,
}

impl DestinationTypeFilter {
    /// Whether only allowed and wanted destination types are let through.
    pub fn required_only(&self) -> bool {
        self.required_only
    }

    /// `[filter] required_only`.
    pub fn set_required_only(&mut self, required_only: bool) {
        self.required_only = required_only;
    }

    /// `Transport.block_destination_type`: drop announces of this type. A
    /// blocked type is no longer wanted by anyone.
    pub fn block(&mut self, destination_type: DestinationType) {
        self.blocked.insert(destination_type);
        self.wanted.remove(&destination_type);
    }

    /// `Transport.allow_destination_type`: let this type through when
    /// `required_only` is set.
    pub fn allow(&mut self, destination_type: DestinationType) {
        self.allowed.insert(destination_type);
    }

    /// `Transport._wants_destination_type`: record that `requester` needs
    /// announces of this type. Returns `false` for a blocked type.
    pub fn want(&mut self, destination_type: DestinationType, requester: &[u8]) -> bool {
        if self.blocked.contains(&destination_type) {
            return false;
        }
        self.wanted
            .entry(destination_type)
            .or_default()
            .insert(requester.to_vec());
        true
    }

    /// `Transport._unwants_destination_type`: withdraw one requester's need
    /// for this type. Returns whether that requester had registered it.
    pub fn unwant(&mut self, destination_type: DestinationType, requester: &[u8]) -> bool {
        let Some(requesters) = self.wanted.get_mut(&destination_type) else {
            return false;
        };
        let was_registered = requesters.remove(requester);
        if requesters.is_empty() {
            self.wanted.remove(&destination_type);
        }
        was_registered
    }

    /// `Transport._unwants_all_destination_types`: withdraw every type this
    /// requester registered.
    pub fn unwant_all(&mut self, requester: &[u8]) {
        self.wanted.retain(|_, requesters| {
            requesters.remove(requester);
            !requesters.is_empty()
        });
    }

    /// Whether some requester registered this type.
    pub fn is_wanted(&self, destination_type: &DestinationType) -> bool {
        self.wanted.contains_key(destination_type)
    }

    /// The ingress check of `Transport.inbound`. `own_local_announce` is
    /// true for an announce sent with zero hops over a local client
    /// connection, in either direction: a client's own destination at the
    /// shared instance, or the shared instance's own destination at a client.
    /// The check upstream applies to paths loaded from storage (rgit
    /// `20e25a9f`): a blocked type, or with `required_only` a type that is
    /// not allowed, is not restored. Types local applications ask for are
    /// not considered; none have asked yet when the path table is loaded.
    pub fn admits_restored(&self, destination_type: &DestinationType) -> bool {
        !self.blocked.contains(destination_type)
            && (!self.required_only || self.allowed.contains(destination_type))
    }

    /// Whether announces of this type are blocked outright.
    pub fn blocks(&self, destination_type: &DestinationType) -> bool {
        self.blocked.contains(destination_type)
    }

    /// Whether an announce of this type passes the filter (upstream `Transport.inbound`).
    ///
    /// A blocked type never passes. With `required_only`, a type passes when
    /// allowed, wanted by a local application, or when `own_local_announce` is set,
    /// which the inbound path does for a zero-hop announce from a local client
    /// interface.
    pub fn allows(&self, destination_type: &DestinationType, own_local_announce: bool) -> bool {
        if self.blocked.contains(destination_type) {
            return false;
        }
        !self.required_only
            || self.allowed.contains(destination_type)
            || self.wanted.contains_key(destination_type)
            || own_local_announce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_destination_types_take_names_or_bracketed_hashes() {
        // Upstream e96c81c3.
        let lxmf = destination_type("lxmf.delivery");
        let hex: String = lxmf.iter().map(|b| alloc::format!("{b:02x}")).collect();
        assert_eq!(configured_destination_type("lxmf.delivery"), Some(lxmf));
        assert_eq!(
            configured_destination_type(&alloc::format!("<{hex}>")),
            Some(lxmf)
        );
        assert_eq!(
            configured_destination_type(&alloc::format!("<{}>", hex.to_uppercase())),
            Some(lxmf)
        );
        // Only the first 20 characters count, so a full 32-character hash
        // gives its first ten bytes.
        assert_eq!(
            configured_destination_type(&alloc::format!("<{hex}00112233445566>")),
            Some(lxmf)
        );
        // Not hex: upstream hashes the 20 kept characters as a name.
        assert_eq!(
            configured_destination_type("<lxmf.delivery>"),
            Some(destination_type("lxmf.delivery>"))
        );
        // Shorter hex keeps the closing bracket, so it is hashed as a name.
        assert_eq!(
            configured_destination_type("<abcd>"),
            Some(destination_type("abcd>"))
        );
        assert_eq!(configured_destination_type(""), None);
        // Unbalanced brackets are an ordinary name.
        assert_eq!(
            configured_destination_type("<lxmf.delivery"),
            Some(destination_type("<lxmf.delivery"))
        );
    }

    #[test]
    fn destination_type_matches_the_destination_name_hash() {
        assert_eq!(
            destination_type("rnstransport.remote.management"),
            crate::destination::name_hash("rnstransport", &["remote", "management"])
        );
        assert_eq!(
            destination_type("rnsh"),
            crate::destination::name_hash("rnsh", &[])
        );
    }

    #[test]
    fn restored_paths_are_filtered_by_blocked_and_allowed_types_only() {
        let lxmf = destination_type("lxmf.delivery");
        let nomad = destination_type("nomadnetwork.node");
        let mut filter = DestinationTypeFilter::default();
        assert!(filter.admits_restored(&lxmf));

        filter.block(nomad);
        assert!(filter.admits_restored(&lxmf));
        assert!(!filter.admits_restored(&nomad));

        filter.set_required_only(true);
        filter.allow(lxmf);
        let other = destination_type("rnsh");
        filter.want(other, b"app");
        assert!(filter.admits_restored(&lxmf));
        // A wanted type is let through at ingress but not at load time.
        assert!(filter.allows(&other, false));
        assert!(!filter.admits_restored(&other));
    }

    #[test]
    fn filter_lets_everything_through_by_default() {
        let filter = DestinationTypeFilter::default();
        assert!(filter.allows(&destination_type("lxmf.delivery"), false));
    }

    #[test]
    fn blocked_types_are_dropped_even_from_local_clients() {
        let mut filter = DestinationTypeFilter::default();
        let lxmf = destination_type("lxmf.delivery");
        filter.block(lxmf);
        assert!(!filter.allows(&lxmf, true));
        assert!(filter.allows(&destination_type("nomadnetwork.node"), false));
    }

    #[test]
    fn required_only_admits_allowed_wanted_and_own_local_types() {
        let mut filter = DestinationTypeFilter::default();
        filter.set_required_only(true);
        let allowed = destination_type("lxmf.delivery");
        let wanted = destination_type("rncp.receive");
        let other = destination_type("nomadnetwork.node");
        filter.allow(allowed);
        assert!(filter.want(wanted, b"client"));

        assert!(filter.allows(&allowed, false));
        assert!(filter.allows(&wanted, false));
        assert!(!filter.allows(&other, false));
        assert!(filter.allows(&other, true));
    }

    #[test]
    fn a_blocked_type_cannot_be_wanted_and_blocking_drops_requesters() {
        let mut filter = DestinationTypeFilter::default();
        let lxmf = destination_type("lxmf.delivery");
        assert!(filter.want(lxmf, b"client"));
        filter.block(lxmf);
        assert!(!filter.is_wanted(&lxmf));
        assert!(!filter.want(lxmf, b"client"));
    }

    #[test]
    fn a_type_stays_wanted_until_its_last_requester_withdraws() {
        let mut filter = DestinationTypeFilter::default();
        let rncp = destination_type("rncp.receive");
        assert!(filter.want(rncp, b"first"));
        assert!(filter.want(rncp, b"second"));

        assert!(filter.unwant(rncp, b"first"));
        assert!(!filter.unwant(rncp, b"first"));
        assert!(filter.is_wanted(&rncp));
        assert!(filter.unwant(rncp, b"second"));
        assert!(!filter.is_wanted(&rncp));
        assert!(!filter.unwant(rncp, b"second"));
    }

    #[test]
    fn unwant_all_withdraws_only_that_requester() {
        let mut filter = DestinationTypeFilter::default();
        let rncp = destination_type("rncp.receive");
        let rnx = destination_type("rnx.execute");
        filter.want(rncp, b"first");
        filter.want(rnx, b"first");
        filter.want(rnx, b"second");

        filter.unwant_all(b"first");
        assert!(!filter.is_wanted(&rncp));
        assert!(filter.is_wanted(&rnx));
    }

    #[test]
    fn required_only_and_blocks_read_back_the_settings() {
        let mut filter = DestinationTypeFilter::default();
        let node = destination_type("rnstransport.discovery.interface");
        assert!(!filter.required_only());
        assert!(!filter.blocks(&node));
        filter.set_required_only(true);
        assert!(filter.required_only());
        filter.block(node);
        assert!(filter.blocks(&node));
    }
}
