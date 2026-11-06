pub mod admission;
mod folded_probe;
pub mod orchestrator;
pub mod probe;
pub mod puncher;
pub mod udp_direct;

/// A poller key for a hole-punch probe or punch served on the driver loop
/// (see [`crate::engine::FOLD_SERVICES`]).
pub(crate) fn next_loop_key() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let keys = crate::engine::service_keys::HOLEPUNCH;
    keys.start + NEXT.fetch_add(1, Ordering::Relaxed) % keys.len()
}
