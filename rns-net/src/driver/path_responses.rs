//! Path responses held for a local client's destinations.

use super::*;

#[derive(Clone)]
pub(super) struct SharedAnnounceRecord {
    pub(super) name_hash: [u8; 10],
    pub(super) identity_prv_key: [u8; 64],
    pub(super) app_data: Option<Vec<u8>>,
}

/// A SINGLE IN destination registered with its identity, which this node
/// announces on demand as a path response.
pub(super) struct PathResponder {
    pub(super) record: SharedAnnounceRecord,
    /// For its stamp target and the stamper job that grinds its stamp.
    pub(super) destination: crate::destination::Destination,
}

/// A path response that waits for its destination's stamp.
pub(crate) enum WaitingPathResponse {
    /// A shared client's announce to its instance, on every interface.
    Broadcast,
    /// The answer to a path request with `tag` received on `interface`.
    Answer {
        tag: Vec<u8>,
        interface: InterfaceId,
    },
}

/// Cache of path-response announces for local destinations:
/// (destination, path-request tag) → (created, raw announce).
pub(super) type LocalPathResponseCache = HashMap<([u8; 16], Vec<u8>), (f64, Vec<u8>)>;
