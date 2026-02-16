/// Trait for querying engine state from within WASM host functions.
///
/// `rns-hooks` cannot depend on `rns-core`, so this trait defines the
/// interface in neutral terms. `rns-net` provides the concrete implementation
/// via a thin wrapper around `TransportEngine`.
pub trait EngineAccess {
    fn has_path(&self, dest: &[u8; 16]) -> bool;
    fn hops_to(&self, dest: &[u8; 16]) -> Option<u8>;
    fn next_hop(&self, dest: &[u8; 16]) -> Option<[u8; 16]>;
    fn is_blackholed(&self, identity: &[u8; 16]) -> bool;
    fn interface_name(&self, id: u64) -> Option<String>;
    fn interface_mode(&self, id: u64) -> Option<u8>;
    fn identity_hash(&self) -> Option<[u8; 16]>;
    /// Outgoing announce rate for an interface, in millihertz (Hz * 1000).
    /// Returns None if the interface is not found.
    fn announce_rate(&self, id: u64) -> Option<i32>;
    /// Link state as a raw u8: Pending=0, Handshake=1, Active=2, Stale=3, Closed=4.
    /// Returns None if the link is not found.
    fn link_state(&self, link_hash: &[u8; 16]) -> Option<u8>;
}

/// No-op implementation that returns false/None for everything.
/// Useful for testing hooks in isolation.
pub struct NullEngine;

impl EngineAccess for NullEngine {
    fn has_path(&self, _dest: &[u8; 16]) -> bool {
        false
    }
    fn hops_to(&self, _dest: &[u8; 16]) -> Option<u8> {
        None
    }
    fn next_hop(&self, _dest: &[u8; 16]) -> Option<[u8; 16]> {
        None
    }
    fn is_blackholed(&self, _identity: &[u8; 16]) -> bool {
        false
    }
    fn interface_name(&self, _id: u64) -> Option<String> {
        None
    }
    fn interface_mode(&self, _id: u64) -> Option<u8> {
        None
    }
    fn identity_hash(&self) -> Option<[u8; 16]> {
        None
    }
    fn announce_rate(&self, _id: u64) -> Option<i32> {
        None
    }
    fn link_state(&self, _link_hash: &[u8; 16]) -> Option<u8> {
        None
    }
}
