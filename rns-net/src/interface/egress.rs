//! Byte-budget egress control shared by a writer and its producer.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Clone)]
#[doc(hidden)]
pub struct EgressControl {
    pub(super) byte_limit: usize,
    pub(super) reserved_bytes: Arc<AtomicUsize>,
    pub(super) stalled: Arc<AtomicBool>,
    pub(super) dropped_frames: Arc<AtomicU64>,
    pub(super) dropped_bytes: Arc<AtomicU64>,
}

impl EgressControl {
    #[cfg(feature = "iface-backbone")]
    pub(crate) fn new(byte_limit: usize) -> Self {
        Self {
            byte_limit,
            reserved_bytes: Arc::new(AtomicUsize::new(0)),
            stalled: Arc::new(AtomicBool::new(false)),
            dropped_frames: Arc::new(AtomicU64::new(0)),
            dropped_bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(super) fn try_reserve(&self, bytes: usize) -> bool {
        if self.stalled.load(Ordering::Relaxed) {
            return false;
        }
        let mut current = self.reserved_bytes.load(Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(bytes) else {
                return false;
            };
            if next > self.byte_limit {
                return false;
            }
            match self.reserved_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    pub(super) fn release(&self, bytes: usize) {
        self.reserved_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }

    pub(crate) fn stalled(&self) -> bool {
        self.stalled.load(Ordering::Relaxed)
    }

    pub(crate) fn set_stalled(&self, stalled: bool) {
        self.stalled.store(stalled, Ordering::Relaxed);
    }

    pub(crate) fn record_drop(&self, bytes: usize) {
        self.dropped_frames.fetch_add(1, Ordering::Relaxed);
        self.dropped_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }
}
