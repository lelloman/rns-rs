//! The compact engine's folded work: timers, announce checks and jobs
//! run on the driver's own thread.

use super::*;

impl Driver {
    /// Whether the folded CPU work has an announce to check.
    pub(super) fn has_folded_announce_work(&self) -> bool {
        crate::engine::FOLD_WORK
            && (self.folded.announces_queued || !self.folded.announces.is_empty())
    }

    /// Whether folded work of any kind is waiting.
    pub(super) fn has_folded_work(&self) -> bool {
        !self.folded.jobs.is_empty()
            || !self.folded.compressions.is_empty()
            || self.link_manager.has_folded_assembly()
            || self.has_folded_announce_work()
    }

    /// Run one unit of folded work: a queued job, a compression slice, or
    /// one announce check.
    pub(super) fn run_folded_unit(&mut self) {
        if let Some(job) = self.folded.jobs.pop_front() {
            self.run_folded_job(job);
        } else if !self.folded.compressions.is_empty() {
            self.step_folded_compression();
        } else if self.link_manager.has_folded_assembly() {
            let actions = self.link_manager.step_folded_assembly(&mut self.rng);
            self.dispatch_link_actions(actions);
        } else if self.has_folded_announce_work() {
            self.check_folded_announce();
        }
    }

    /// Check one announce from the verification queue, taking the queued
    /// ones first if needed, and complete it as the verification thread's
    /// event would.
    pub(super) fn check_folded_announce(&mut self) {
        if self.folded.announces.is_empty() && self.folded.announces_queued {
            self.folded.announces_queued = false;
            let taken = crate::sync::lock_or_recover(
                &self.announce_verify.queue,
                "folded announce verify queue",
            )
            .take_pending(time::now());
            self.folded.announces.extend(taken);
        }
        let Some((key, pending)) = self.folded.announces.pop_front() else {
            return;
        };
        match crate::driver::check_pending_announce(&pending) {
            crate::driver::AnnounceCheck::Valid {
                validated,
                sig_cache_key,
            } => self.handle_announce_verified_event(key, *validated, sig_cache_key),
            crate::driver::AnnounceCheck::Invalid { .. } => self.handle_announce_verify_failed(key),
        }
    }

    /// Fire the folded tick if its deadline has passed, when no timerfd
    /// delivers it.
    pub(super) fn run_folded_timers(&mut self) {
        let now = Instant::now();
        if now >= self.folded.next_tick {
            let interval = Duration::from_millis(self.tick_interval_ms.load(Ordering::Relaxed));
            self.folded.next_tick = now + interval;
            self.handle_tick_event();
        }
    }

    /// Queue the transport-state snapshot as idle work once it is due. The
    /// tick drives it, about once a second.
    pub(super) fn queue_folded_persistence(&mut self) {
        if self.folded.persist_dir.is_some() && Instant::now() >= self.folded.next_persist {
            self.folded.next_persist =
                Instant::now() + crate::driver::TRANSPORT_STATE_PERSIST_INTERVAL;
            self.folded
                .jobs
                .push_back(crate::driver::FoldedJob::PersistTransportState);
        }
    }

    /// How long the driver may block waiting for events: until the folded
    /// tick's deadline, unless a timerfd delivers the tick (Linux, Android).
    /// There the driver waits without a timeout: the epoll poller hands a
    /// wait's timeout to the kernel, which would arm and cancel a timer on
    /// every wait.
    pub(super) fn folded_wait(&self) -> Option<Duration> {
        if !crate::engine::FOLD_TIMERS || self.folded.ticks_from_source {
            return None;
        }
        Some(
            self.folded
                .next_tick
                .saturating_duration_since(Instant::now()),
        )
    }

    /// Register the timerfd that ticks a compact driver, where there is one.
    /// Without it the driver falls back to its tick deadline.
    pub(super) fn start_folded_tick(&mut self) {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if crate::engine::FOLD_TIMERS {
            let source = super::tick_source::TickSource::new(
                self.event_tx.clone(),
                Arc::clone(&self.tick_interval_ms),
            );
            match source.and_then(|source| {
                self.event_tx
                    .register_source(super::tick_source::TICK_SOURCE_KEY, Box::new(source))
            }) {
                Ok(()) => self.folded.ticks_from_source = true,
                Err(error) => log::warn!("driver tick timer unavailable: {error}"),
            }
        }
    }

    pub(crate) fn run_folded_job(&mut self, job: crate::driver::FoldedJob) {
        match job {
            crate::driver::FoldedJob::PersistTransportState => {
                let Some(dir) = self.folded.persist_dir.clone() else {
                    return;
                };
                let snapshot = self.engine.persistence_snapshot();
                if let Err(err) = crate::storage::save_transport_state(&snapshot, &dir, true) {
                    log::warn!("failed to persist transport state: {}", err);
                }
            }
            crate::driver::FoldedJob::CleanRatchets {
                known_destinations,
                now,
                expiry,
            } => {
                let Some(store) = self.ratchet_store.clone() else {
                    return;
                };
                match store.cleanup(&known_destinations, now, expiry) {
                    Ok(stats) if stats.removed > 0 => log::info!(
                        "Known-destination cleanup removed {} stale ratchets",
                        stats.removed
                    ),
                    Ok(_) => {}
                    Err(err) => log::warn!("failed to clean ratchets: {}", err),
                }
            }
        }
    }
}
