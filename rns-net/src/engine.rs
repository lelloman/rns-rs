//! Which engine this build of `rns-net` runs, and which helper threads the
//! compact engine folds into the driver loop. See `docs/engines.md`.

/// `"parallel"` with the `engine-parallel` feature, `"compact"` otherwise.
pub const ENGINE: &str = if cfg!(feature = "engine-parallel") {
    "parallel"
} else {
    "compact"
};

/// Whether timers and housekeeping (the tick, transport-state persistence,
/// ratchet cleanup) run on the driver loop instead of their own threads: in
/// the compact engine unless `compact-threads-timers` keeps the threads.
pub(crate) const FOLD_TIMERS: bool =
    !cfg!(feature = "engine-parallel") && !cfg!(feature = "compact-threads-timers");

/// Whether CPU work (announce verification, so far) runs on the driver loop
/// instead of its own threads: in the compact engine unless
/// `compact-threads-work` keeps the threads.
pub(crate) const FOLD_WORK: bool =
    !cfg!(feature = "engine-parallel") && !cfg!(feature = "compact-threads-work");

/// Whether services (the RPC servers, so far) run on the driver loop
/// instead of their own threads: in the compact engine unless
/// `compact-threads-services` keeps the threads.
pub(crate) const FOLD_SERVICES: bool =
    !cfg!(feature = "engine-parallel") && !cfg!(feature = "compact-threads-services");
