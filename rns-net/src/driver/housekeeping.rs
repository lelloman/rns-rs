//! Schedules of the driver's periodic housekeeping.

use super::*;

/// Counters and schedules of the periodic housekeeping jobs run from the
/// tick: memory statistics, cache cleanup and statistics snapshots.
pub(crate) struct Housekeeping {
    /// Tick counter for periodic MEMSTATS logging (every 300 ticks = ~5 min).
    pub(crate) memory_stats_counter: u32,
    /// Tick counter for periodic memory/cache cleanup (every ~3600 ticks = ~1 hour).
    pub(crate) cache_cleanup_counter: u32,
    /// Tick counter for incremental announce-cache cleanup scheduling.
    pub(crate) announce_cache_cleanup_counter: u32,
    /// Runtime-configurable interval for starting announce cache cleanup.
    pub(crate) announce_cache_cleanup_interval_ticks: u32,
    /// Runtime-configurable announce cache cleanup batch size.
    pub(crate) announce_cache_cleanup_batch_size: usize,
    /// Low-priority ratchet filesystem cleanup associated with the last pass.
    pub(crate) ratchet_cleanup_handle: Option<std::thread::JoinHandle<()>>,
    /// When to republish the link/interface statistics snapshot.
    pub(crate) state_snapshot_schedule: crate::state_snapshot::PublishSchedule,
}

impl Housekeeping {
    pub(crate) fn new(defaults: &RuntimeConfigDefaults) -> Self {
        Self {
            memory_stats_counter: 0,
            cache_cleanup_counter: 0,
            announce_cache_cleanup_counter: 0,
            announce_cache_cleanup_interval_ticks: defaults.announce_cache_cleanup_interval_ticks,
            announce_cache_cleanup_batch_size: defaults.announce_cache_cleanup_batch_size,
            ratchet_cleanup_handle: None,
            state_snapshot_schedule: Default::default(),
        }
    }
}
