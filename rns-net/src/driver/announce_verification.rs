//! The queue that verifies inbound announces off the driver thread.

use super::*;

/// Verification of inbound announce signatures off the driver thread.
pub(crate) struct AnnounceVerification {
    /// Whether inbound announces are verified off the driver thread.
    pub(crate) async_enabled: bool,
    /// Shared async announce verification queue.
    pub(crate) queue: Arc<Mutex<AnnounceVerifyQueue>>,
    /// Wakes the verification thread when announces are queued.
    pub(crate) signal: Arc<WorkSignal>,
}

impl AnnounceVerification {
    pub(crate) fn new(queue_max_entries: usize) -> Self {
        Self {
            async_enabled: false,
            queue: Arc::new(Mutex::new(AnnounceVerifyQueue::new(queue_max_entries))),
            signal: Arc::default(),
        }
    }
}
