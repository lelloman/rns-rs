//! The compact engine's folded timers and jobs.

use super::*;

/// Deadlines and pending jobs of the timer and housekeeping work the driver
/// runs itself when [`crate::engine::FOLD_TIMERS`] is set.
pub(crate) struct FoldedTimers {
    pub(crate) next_tick: Instant,
    pub(crate) next_persist: Instant,
    /// Where transport state is persisted, on transport nodes.
    pub(crate) persist_dir: Option<std::path::PathBuf>,
    pub(crate) jobs: std::collections::VecDeque<FoldedJob>,
    /// Whether a timerfd loop source delivers the tick.
    pub(crate) ticks_from_source: bool,
    /// Announces taken from the verification queue, checked one per idle
    /// turn when CPU work is folded.
    pub(crate) announces: std::collections::VecDeque<(
        rns_core::transport::announce_verify_queue::AnnounceVerifyKey,
        rns_core::transport::announce_verify_queue::PendingAnnounce,
    )>,
    /// Whether the verification queue may hold announces not yet taken.
    pub(crate) announces_queued: bool,
    /// Outgoing resources compressed on the driver loop, oldest first.
    pub(crate) compressions: std::collections::VecDeque<resource_preparation::FoldedCompression>,
    pub(crate) next_compression_id: u64,
}

pub(crate) enum FoldedJob {
    PersistTransportState,
    CleanRatchets {
        known_destinations: HashSet<[u8; 16]>,
        now: f64,
        expiry: f64,
    },
}

impl FoldedTimers {
    pub(super) fn new() -> Self {
        let now = Instant::now();
        FoldedTimers {
            next_tick: now + Duration::from_millis(DEFAULT_TICK_INTERVAL_MS),
            next_persist: now + TRANSPORT_STATE_PERSIST_INTERVAL,
            persist_dir: None,
            jobs: std::collections::VecDeque::new(),
            ticks_from_source: false,
            announces: std::collections::VecDeque::new(),
            announces_queued: false,
            compressions: std::collections::VecDeque::new(),
            next_compression_id: 0,
        }
    }
}
