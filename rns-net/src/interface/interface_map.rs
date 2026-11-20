//! Maps keyed by interface ID.

use std::collections::HashMap;

use rns_core::transport::types::InterfaceId;

/// Hasher for maps keyed by [`InterfaceId`], looked up several times per
/// forwarded packet. IDs are small trusted integers, so a multiplicative mix
/// replaces SipHash, whose per-lookup cost showed up in forwarding profiles.
#[derive(Default, Clone, Copy)]
pub struct InterfaceIdHasher(u64);

impl std::hash::Hasher for InterfaceIdHasher {
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.write_u64(u64::from(*byte));
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = (self.0 ^ value).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }

    fn finish(&self) -> u64 {
        self.0 ^ (self.0 >> 29)
    }
}

/// Map keyed by interface ID using [`InterfaceIdHasher`].
pub type InterfaceMap<V> =
    HashMap<InterfaceId, V, std::hash::BuildHasherDefault<InterfaceIdHasher>>;
