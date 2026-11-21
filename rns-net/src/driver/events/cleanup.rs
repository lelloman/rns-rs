//! Background cleanup of stale known destinations and ratchets.

use super::*;

impl Driver {
    pub(super) fn continue_known_destination_cleanup(&mut self, now: f64) {
        let Some(mut cleanup) = self.known.cleanup.take() else {
            return;
        };
        let end =
            (cleanup.cursor + KNOWN_DESTINATION_CLEANUP_BATCH_SIZE).min(cleanup.candidates.len());
        for destination_hash in &cleanup.candidates[cleanup.cursor..end] {
            let remove = self
                .known
                .entries
                .get(destination_hash)
                .is_some_and(|state| {
                    !self.engine.has_path(destination_hash)
                        && !self.local_destinations.contains_key(destination_hash)
                        && !state.retained
                        && now - state.relevance_time() >= self.known.ttl
                });
            if remove && self.known.entries.remove(destination_hash).is_some() {
                cleanup.removed += 1;
            }
        }
        cleanup.cursor = end;
        if cleanup.cursor < cleanup.candidates.len() {
            self.known.cleanup = Some(cleanup);
            return;
        }

        let evicted = self
            .known
            .enforce_cap(false, &self.engine, &self.local_destinations);
        let active_destinations = self.engine.active_destination_hashes();
        let rate_limiters =
            self.engine
                .cull_rate_limiter(&active_destinations, now, self.rate_limiter_ttl_secs);
        log::debug!(
            "Cleaned known destinations in {:?}",
            cleanup.started_at.elapsed()
        );
        if cleanup.removed > 0 || evicted > 0 || rate_limiters > 0 {
            log::info!(
                "Memory cleanup: removed {} known_destinations, evicted {} known_destinations, {} rate_limiter entries",
                cleanup.removed,
                evicted,
                rate_limiters,
            );
        }
        self.start_ratchet_cleanup(now);
    }

    pub(super) fn finish_ratchet_cleanup_if_ready(&mut self) {
        let finished = self
            .housekeeping
            .ratchet_cleanup_handle
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished);
        if finished {
            if let Some(handle) = self.housekeeping.ratchet_cleanup_handle.take() {
                let _ = handle.join();
            }
        }
    }

    pub(super) fn start_ratchet_cleanup(&mut self, now: f64) {
        if self.housekeeping.ratchet_cleanup_handle.is_some() {
            return;
        }
        let Some(store) = self.ratchet_store.clone() else {
            return;
        };
        let known_destinations = self.known.entries.keys().copied().collect();
        let expiry = self.ratchet_expiry_secs;
        if crate::engine::FOLD_TIMERS {
            let queued = self
                .folded
                .jobs
                .iter()
                .any(|job| matches!(job, crate::driver::FoldedJob::CleanRatchets { .. }));
            if !queued {
                self.folded
                    .jobs
                    .push_back(crate::driver::FoldedJob::CleanRatchets {
                        known_destinations,
                        now,
                        expiry,
                    });
            }
            return;
        }
        match std::thread::Builder::new()
            .name("rns-destination-cleanup".into())
            .spawn(move || {
                #[cfg(target_family = "unix")]
                crate::sys::nice(5);
                match store.cleanup(&known_destinations, now, expiry) {
                    Ok(stats) if stats.removed > 0 => log::info!(
                        "Known-destination cleanup removed {} stale ratchets",
                        stats.removed
                    ),
                    Ok(_) => {}
                    Err(err) => log::warn!("failed to clean ratchets: {}", err),
                }
            }) {
            Ok(handle) => self.housekeeping.ratchet_cleanup_handle = Some(handle),
            Err(err) => log::warn!("failed to start ratchet cleanup worker: {}", err),
        }
    }
}
