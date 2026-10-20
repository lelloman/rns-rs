//! Shared process-local allocation for component-owned test listeners.

use std::sync::atomic::{AtomicU16, Ordering};

static NEXT_PORT: AtomicU16 = AtomicU16::new(0);

pub(crate) fn port() -> u16 {
    let pid = std::process::id() as u16;
    // Stay below Linux's default ephemeral range so client connections created by
    // parallel network tests cannot consume a component-owned listener port.
    let base = 10_000 + (pid % 200) * 100;
    let _ = NEXT_PORT.compare_exchange(0, base, Ordering::SeqCst, Ordering::SeqCst);
    NEXT_PORT.fetch_add(1, Ordering::SeqCst)
}

/// A shared-instance name that is unique to this test process.
///
/// Local-interface tests bind abstract Unix sockets by instance name. Each
/// test in a process uses its own prefix, and the process id keeps parallel
/// test processes (nextest, concurrent CI jobs, a developer's running daemon)
/// from binding or connecting to each other's sockets. The same prefix yields
/// the same name within a process, so a test's server and client agree.
pub(crate) fn instance_name(prefix: &str) -> String {
    format!("{prefix}-{}", std::process::id())
}
