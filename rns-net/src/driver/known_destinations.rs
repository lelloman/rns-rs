//! The driver's cache of known destinations.

use super::*;

/// Known destinations: the identities learned from announces, keyed by
/// destination hash, with their retention limits and cleanup progress.
pub(crate) struct KnownDestinations {
    /// Cache of known announced identities and lifecycle state.
    pub(crate) entries: HashMap<[u8; 16], KnownDestinationState>,
    /// Fingerprints of the known destinations as last flushed to storage.
    pub(crate) flushed: HashMap<[u8; 16], u64>,
    /// TTL for known destinations without an active path, in seconds.
    pub(crate) ttl: f64,
    /// Maximum number of retained known destinations.
    pub(crate) max_entries: usize,
    /// Count of cap evictions since start.
    pub(crate) cap_evict_count: usize,
    /// Runtime-configurable cleanup interval.
    pub(crate) cleanup_interval_ticks: u32,
    /// Incremental cleanup pass, if one is active.
    pub(super) cleanup: Option<KnownDestinationCleanup>,
}

impl KnownDestinations {
    pub(crate) fn new(cleanup_interval_ticks: u32) -> Self {
        Self {
            entries: HashMap::new(),
            flushed: HashMap::new(),
            ttl: DEFAULT_KNOWN_DESTINATIONS_TTL,
            max_entries: DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES,
            cap_evict_count: 0,
            cleanup_interval_ticks,
            cleanup: None,
        }
    }
}
