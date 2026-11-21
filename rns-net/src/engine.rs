//! Which engine this build of `rns-net` runs, and which helper threads the
//! compact engine folds into the driver loop. See `docs/engines.md`.

/// `"parallel"` with the `engine-parallel` feature, `"compact"` otherwise.
pub(crate) const ENGINE: &str = if cfg!(feature = "engine-parallel") {
    "parallel"
} else {
    "compact"
};

/// Whether the compact engine folds its helper threads into the driver
/// loop: always, unless the `compact-threads` feature keeps the threads.
/// The parallel engine keeps them.
const FOLDED: bool = !cfg!(feature = "engine-parallel") && !cfg!(feature = "compact-threads");

/// Whether timers and housekeeping (the tick, transport-state persistence,
/// ratchet cleanup) run on the driver loop instead of their own threads.
pub(crate) const FOLD_TIMERS: bool = FOLDED;

/// Whether CPU work (announce verification, resource compression and
/// assembly) runs on the driver loop instead of its own threads.
pub(crate) const FOLD_WORK: bool = FOLDED;

/// Whether services (the RPC servers, the provider bridge and the probe
/// server) run on the driver loop instead of their own threads.
pub(crate) const FOLD_SERVICES: bool = FOLDED;

/// Whether interface I/O runs on the driver loop instead of reader and
/// writer threads. TCP runs on the driver loop in both engines.
pub(crate) const FOLD_IO: bool = FOLDED;

/// The driver poller's keys for folded services' sockets: above every
/// interface's keys (an interface id shifted left by one) and below the
/// tick source's.
pub(crate) mod service_keys {
    use std::ops::Range;

    const BASE: usize = 1 << (usize::BITS - 2);

    /// RPC listeners and connections.
    pub(crate) const RPC: Range<usize> = BASE..BASE + (1 << 30);
    /// The provider bridge's socket and consumers.
    pub(crate) const PROVIDER_BRIDGE: Range<usize> = RPC.end..RPC.end + (1 << 20);
    /// The probe server's socket.
    pub(crate) const PROBE_SERVER: usize = PROVIDER_BRIDGE.end;
    /// Hole-punch probes and punches in progress.
    pub(crate) const HOLEPUNCH: Range<usize> = PROBE_SERVER + 1..PROBE_SERVER + 1 + (1 << 20);
}
