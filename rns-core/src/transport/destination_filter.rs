//! Announce filtering by destination type (upstream 825c2e19).
//!
//! A destination type is the name hash of its full name, such as
//! `lxmf.delivery`. Announces of a blocked type are dropped at ingress. With
//! `required_only`, only announces of an allowed type, a type some local
//! application asked for, or a local client's or the shared instance's own
//! destinations get through.

use alloc::collections::{BTreeMap, BTreeSet};
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
}
