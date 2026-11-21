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
    /// How long a path-response announce is replayed for a repeated tag
    /// (Python `Destination.PR_TAG_WINDOW`).
    pub(crate) const LOCAL_PATH_RESPONSE_WINDOW: f64 = 30.0;

    /// Upper bound on cached path-response announces.
    pub(crate) const LOCAL_PATH_RESPONSE_MAX_ENTRIES: usize = 1024;

    pub(crate) fn new() -> Self {
        Self {
            shared_announces: HashMap::new(),
            shared_reconnect_pending: HashMap::new(),
            responders: HashMap::new(),
            waiting_for_stamp: HashMap::new(),
            local_cache: HashMap::new(),
        }
    }

    /// Drop path-response announces older than the replay window.
    pub(crate) fn expire_local_responses(&mut self, now: f64) {
        self.local_cache
            .retain(|_, (created, _)| now - *created <= Self::LOCAL_PATH_RESPONSE_WINDOW);
    }

    /// Keep a path-response announce sent for `key` to replay, making room
    /// by dropping the oldest when the cache is full.
    pub(crate) fn cache_local_response(
        &mut self,
        key: ([u8; 16], Vec<u8>),
        now: f64,
        raw: Vec<u8>,
    ) {
        if self.local_cache.len() >= Self::LOCAL_PATH_RESPONSE_MAX_ENTRIES {
            if let Some(oldest) = self
                .local_cache
                .iter()
                .min_by(|a, b| a.1 .0.total_cmp(&b.1 .0))
                .map(|(key, _)| key.clone())
            {
                self.local_cache.remove(&oldest);
            }
        }
        self.local_cache.insert(key, (now, raw));
    }

    /// Forget a local destination's path responses and announce records.
    pub(crate) fn forget(&mut self, dest_hash: &[u8; 16]) {
        self.responders.remove(dest_hash);
        self.waiting_for_stamp.remove(dest_hash);
        self.shared_announces.remove(dest_hash);
    }
}
