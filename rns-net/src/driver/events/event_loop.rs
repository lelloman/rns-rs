//! The driver's event loop.

use super::*;

impl Driver {
    /// Run the event loop. Blocks until Shutdown or all senders are dropped.
    pub fn run(&mut self) {
        self.link_manager
            .set_receive_worker_wake(self.event_tx.clone());
        self.start_folded_tick();
        let mut ready = crate::poll::Events::new();
        // Events handled since driver-run writers were last flushed.
        let mut unflushed = 0usize;
        // Turns since folded timers were last checked: a busy loop checks
        // them every so many turns, an idle one before it waits.
        let mut unchecked_turns = 0u32;
        // Events handled since folded work last ran on a busy driver.
        let mut busy_events = 0u32;
        loop {
            // Each turn handles at most one event and reads the clock at most
            // once (see `time::hold`). The scope ends before the loop waits.
            let clock = time::hold();
            if crate::engine::FOLD_TIMERS && !self.folded.ticks_from_source {
                unchecked_turns += 1;
                if unchecked_turns >= FOLDED_TIMER_CHECK_TURNS {
                    unchecked_turns = 0;
                    self.run_folded_timers();
                }
            }
            self.poll_resource_preparations();
            let actions = self.link_manager.poll_receive_worker(&mut self.rng);
            self.dispatch_link_actions(actions);
            if let Some(actions) = self.link_manager.poll_proof_pool(&mut self.rng) {
                self.dispatch_link_actions(actions);
                self.apply_packet_proofs();
            }
            self.flush_pending_link_frames();
            if self
                .housekeeping
                .state_snapshot_schedule
                .needs_publish(self.link_manager.link_count())
            {
                self.publish_state_snapshot();
            }
            if !self.rx.has_prefetched() {
                self.wake_writers();
            }
            let received = match self.rx.try_recv_classified() {
                Ok(Some(e)) => e,
                Ok(None) => {
                    // Everything the last poll delivered has been handled:
                    // send this pass's output before waiting for more.
                    self.flush_writers();
                    if self.link_manager.has_idle_work() || self.has_folded_work() {
                        // Sources that are ready go before idle work: what
                        // they hold, such as the rest of a window, may be
                        // what a peer waits on.
                        ready.clear();
                        if let Err(error) = self.rx.wait(&mut ready, Some(Duration::ZERO)) {
                            log::warn!("driver poll failed: {error}");
                        }
                        if ready.iter().next().is_some() {
                            self.handle_ready_sources(&ready);
                            continue;
                        }
                        // One job per turn: events that arrive meanwhile go first.
                        if self.has_folded_work() {
                            self.run_folded_unit();
                        } else {
                            let actions = self.link_manager.run_idle_work(&mut self.rng);
                            self.dispatch_link_actions(actions);
                        }
                        continue;
                    }
                    if crate::engine::FOLD_TIMERS && !self.folded.ticks_from_source {
                        unchecked_turns = 0;
                        self.run_folded_timers();
                        if !self.folded.jobs.is_empty() {
                            continue;
                        }
                    }
                    drop(clock);
                    unflushed = 0;
                    ready.clear();
                    if let Err(error) = self.rx.wait(&mut ready, self.folded_wait()) {
                        log::warn!("driver wait failed: {error}");
                    }
                    self.handle_ready_sources(&ready);
                    continue;
                }
                Err(_) => break, // all senders dropped
            };
            // Bound output latency, and keep serving sockets, while other
            // threads keep the queue from emptying.
            unflushed += 1;
            if crate::engine::FOLD_TIMERS || crate::engine::FOLD_WORK {
                busy_events += 1;
                if busy_events >= FOLDED_WORK_BUSY_EVENTS {
                    busy_events = 0;
                    self.run_folded_unit();
                }
            }
            // A tick queued behind a long backlog would leave the snapshot
            // stale for as long as the backlog takes to drain.
            let tick_interval =
                Duration::from_millis(self.tick_interval_ms.load(Ordering::Relaxed));
            if self
                .housekeeping
                .state_snapshot_schedule
                .event_handled(tick_interval)
            {
                self.publish_state_snapshot();
            }
            if unflushed >= WRITER_FLUSH_EVENTS {
                self.flush_writers();
                unflushed = 0;
                ready.clear();
                match self.rx.poll_ready(&mut ready) {
                    Ok(()) => self.handle_ready_sources(&ready),
                    Err(error) => log::warn!("driver poll failed: {error}"),
                }
            }

            if !self.handle_event(received) {
                break;
            }
        }
        self.link_manager.stop_receive_worker();
        self.stop_resource_preparations();
        self.event_tx.link_send_pool().close();
        self.pending_link_frames.clear();
    }

    /// Check if we should generate a proof for a delivered packet,
    /// and if so, sign and send it.
    pub(crate) fn get_event_sender(&self) -> crate::event::EventSender {
        // The driver doesn't directly have a sender, but node.rs creates the channel
        // and passes rx to the driver. We need to store a sender clone.
        // For now we use an internal sender that was set during construction.
        self.event_tx.clone()
    }
}
