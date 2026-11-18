//! Locking that outlives a panic elsewhere.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Lock `mutex`, taking it over if a thread panicked while holding it.
///
/// The panic was a bug and has been reported already. Continuing with the
/// state that thread left keeps the rest of the node running, where
/// refusing the lock would turn one panic into a panic in every later
/// caller. `label` names the mutex in the warning that records it.
#[inline]
pub(crate) fn lock_or_recover<'a, T>(mutex: &'a Mutex<T>, label: &str) -> MutexGuard<'a, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| recover(poisoned, label))
}

#[cold]
fn recover<'a, T>(poisoned: PoisonError<MutexGuard<'a, T>>, label: &str) -> MutexGuard<'a, T> {
    log::warn!("recovering poisoned mutex: {}", label);
    poisoned.into_inner()
}
