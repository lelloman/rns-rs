//! Typed wrappers for common identifiers and enums.
//!
//! These newtypes prevent mixing up destination hashes, identity hashes,
//! link IDs, and packet hashes — all of which are raw byte arrays.

use core::fmt;

/// A destination hash (truncated, 16 bytes).
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct DestHash(pub [u8; 16]);

/// An identity hash (truncated SHA-256 of public key, 16 bytes).
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct IdentityHash(pub [u8; 16]);

/// A link identifier (16 bytes).
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct LinkId(pub [u8; 16]);

/// A full packet hash (SHA-256, 32 bytes).
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct PacketHash(pub [u8; 32]);

// --- Display (hex) ---

impl fmt::Display for DestHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl fmt::Debug for DestHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DestHash({})", self)
    }
}

impl fmt::Display for IdentityHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl fmt::Debug for IdentityHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdentityHash({})", self)
    }
}

impl fmt::Display for LinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl fmt::Debug for LinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LinkId({})", self)
    }
}

impl fmt::Display for PacketHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl fmt::Debug for PacketHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PacketHash({})", self)
    }
}

// --- From conversions ---

impl From<[u8; 16]> for DestHash {
    fn from(bytes: [u8; 16]) -> Self {
        DestHash(bytes)
    }
}

impl From<[u8; 16]> for IdentityHash {
    fn from(bytes: [u8; 16]) -> Self {
        IdentityHash(bytes)
    }
}

impl From<[u8; 16]> for LinkId {
    fn from(bytes: [u8; 16]) -> Self {
        LinkId(bytes)
    }
}

impl From<[u8; 32]> for PacketHash {
    fn from(bytes: [u8; 32]) -> Self {
        PacketHash(bytes)
    }
}

// --- Into raw bytes ---

impl From<DestHash> for [u8; 16] {
    fn from(h: DestHash) -> Self {
        h.0
    }
}

impl From<IdentityHash> for [u8; 16] {
    fn from(h: IdentityHash) -> Self {
        h.0
    }
}

impl From<LinkId> for [u8; 16] {
    fn from(h: LinkId) -> Self {
        h.0
    }
}

impl From<PacketHash> for [u8; 32] {
    fn from(h: PacketHash) -> Self {
        h.0
    }
}

// --- AsRef for ergonomic access ---

impl AsRef<[u8; 16]> for DestHash {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl AsRef<[u8; 16]> for IdentityHash {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl AsRef<[u8; 16]> for LinkId {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl AsRef<[u8; 32]> for PacketHash {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

// --- Enums ---

/// Destination type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationType {
    /// Point-to-point, encrypted to recipient's key.
    Single,
    /// Multicast with pre-shared key.
    Group,
    /// Unencrypted.
    Plain,
}

impl DestinationType {
    /// Convert to the wire constant used in rns-core.
    pub fn to_wire_constant(self) -> u8 {
        match self {
            DestinationType::Single => crate::constants::DESTINATION_SINGLE,
            DestinationType::Group => crate::constants::DESTINATION_GROUP,
            DestinationType::Plain => crate::constants::DESTINATION_PLAIN,
        }
    }

    /// Convert from the wire constant.
    pub fn from_wire_constant(val: u8) -> Option<Self> {
        match val {
            x if x == crate::constants::DESTINATION_SINGLE => Some(DestinationType::Single),
            x if x == crate::constants::DESTINATION_GROUP => Some(DestinationType::Group),
            x if x == crate::constants::DESTINATION_PLAIN => Some(DestinationType::Plain),
            _ => None,
        }
    }
}

/// Destination direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Inbound — for receiving packets.
    In,
    /// Outbound — for sending to a remote node.
    Out,
}

/// Proof strategy for a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofStrategy {
    /// Automatically prove all incoming packets.
    ProveAll,
    /// Ask the application whether to prove each packet.
    ProveApp,
    /// Never prove incoming packets.
    ProveNone,
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::format;

    #[test]
    fn dest_hash_construct_and_access() {
        let bytes = [1u8; 16];
        let dh = DestHash(bytes);
        assert_eq!(dh.0, bytes);
        assert_eq!(*dh.as_ref(), bytes);
    }

    #[test]
    fn identity_hash_construct_and_access() {
        let bytes = [2u8; 16];
        let ih = IdentityHash(bytes);
        assert_eq!(ih.0, bytes);
    }

    #[test]
    fn link_id_construct_and_access() {
        let bytes = [3u8; 16];
        let lid = LinkId(bytes);
        assert_eq!(lid.0, bytes);
    }

    #[test]
    fn packet_hash_construct_and_access() {
        let bytes = [4u8; 32];
        let ph = PacketHash(bytes);
        assert_eq!(ph.0, bytes);
    }

    #[test]
    fn display_hex() {
        let dh = DestHash([0xAB, 0xCD, 0x01, 0x23, 0x45, 0x67, 0x89, 0xEF,
                           0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        assert_eq!(format!("{}", dh), "abcd0123456789ef0011223344556677");

        let ph = PacketHash([0xFF; 32]);
        let hex = format!("{}", ph);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c == 'f'));
    }

    #[test]
    fn from_bytes() {
        let bytes16 = [0x42u8; 16];
        let dh: DestHash = bytes16.into();
        assert_eq!(dh.0, bytes16);

        let ih: IdentityHash = bytes16.into();
        assert_eq!(ih.0, bytes16);

        let lid: LinkId = bytes16.into();
        assert_eq!(lid.0, bytes16);

        let bytes32 = [0x42u8; 32];
        let ph: PacketHash = bytes32.into();
        assert_eq!(ph.0, bytes32);
    }

    #[test]
    fn into_bytes() {
        let dh = DestHash([0xAA; 16]);
        let raw: [u8; 16] = dh.into();
        assert_eq!(raw, [0xAA; 16]);

        let ph = PacketHash([0xBB; 32]);
        let raw32: [u8; 32] = ph.into();
        assert_eq!(raw32, [0xBB; 32]);
    }

    #[test]
    fn equality() {
        let a = DestHash([1; 16]);
        let b = DestHash([1; 16]);
        let c = DestHash([2; 16]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn hash_impl() {
        use core::hash::{Hash, Hasher};
        struct DummyHasher(u64);
        impl Hasher for DummyHasher {
            fn finish(&self) -> u64 { self.0 }
            fn write(&mut self, bytes: &[u8]) {
                for b in bytes { self.0 = self.0.wrapping_mul(31).wrapping_add(*b as u64); }
            }
        }

        let a = DestHash([0xAA; 16]);
        let b = DestHash([0xAA; 16]);
        let mut ha = DummyHasher(0);
        let mut hb = DummyHasher(0);
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn destination_type_wire_roundtrip() {
        for dt in [DestinationType::Single, DestinationType::Group, DestinationType::Plain] {
            let wire = dt.to_wire_constant();
            let back = DestinationType::from_wire_constant(wire).unwrap();
            assert_eq!(dt, back);
        }
        assert!(DestinationType::from_wire_constant(0xFF).is_none());
    }

    #[test]
    fn debug_format() {
        let dh = DestHash([0; 16]);
        let s = format!("{:?}", dh);
        assert!(s.starts_with("DestHash("));

        let ih = IdentityHash([0; 16]);
        let s = format!("{:?}", ih);
        assert!(s.starts_with("IdentityHash("));

        let lid = LinkId([0; 16]);
        let s = format!("{:?}", lid);
        assert!(s.starts_with("LinkId("));

        let ph = PacketHash([0; 32]);
        let s = format!("{:?}", ph);
        assert!(s.starts_with("PacketHash("));
    }
}
