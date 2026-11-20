//! Path responses held for a local client's destinations, and the
//! announces a shared client replays to its instance.

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

/// Path responses for local destinations, and the announces a shared
/// client replays to its instance.
pub(crate) struct PathResponses {
    /// Latest explicit SINGLE announces to replay after shared-client reconnect.
    pub(super) shared_announces: HashMap<[u8; 16], SharedAnnounceRecord>,
    /// Shared local interfaces that went down and should replay announces on reconnect.
    pub(super) shared_reconnect_pending: HashMap<InterfaceId, bool>,
    /// Keys of SINGLE IN destinations registered with their identity, to
    /// answer path requests for them before they announce. A shared client
    /// announces one as a path response when it is registered and again on
    /// reconnect, unless `shared_announces` holds a newer record for it.
    pub(super) responders: HashMap<[u8; 16], PathResponder>,
    /// Path responses of `responders` waiting for the stamper to grind
    /// their destination's stamp, sent on `Event::DestinationStampReady`.
    pub(super) waiting_for_stamp: HashMap<[u8; 16], Vec<WaitingPathResponse>>,
    /// Path-response announces recently sent for local destinations, keyed by
    /// (destination, path-request tag), replayed byte-for-byte for a repeated
    /// tag within `LOCAL_PATH_RESPONSE_WINDOW`: (created, raw announce).
    pub(crate) local_cache: LocalPathResponseCache,
}

impl PathResponses {
    pub(crate) fn new() -> Self {
        Self {
            shared_announces: HashMap::new(),
            shared_reconnect_pending: HashMap::new(),
            responders: HashMap::new(),
            waiting_for_stamp: HashMap::new(),
            local_cache: HashMap::new(),
        }
    }
}
