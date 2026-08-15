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
