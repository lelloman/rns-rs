//! Common utility functions.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Locking a mutex whatever a thread that panicked holding it left: the
/// data it guards (counters, radio state) stays usable.
pub trait LockExt<T> {
    /// The guard of `self`, recovered from poisoning.
    fn locked(&self) -> MutexGuard<'_, T>;
}

impl<T> LockExt<T> for Mutex<T> {
    fn locked(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Format bytes as a lowercase hex string.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
