//! Interface writers: flushing them and recording what they sent.

use super::*;

impl Driver {
    /// Serve sockets the driver poller reported ready: loop sources read
    /// (queueing what they decode), and writers that had bytes left over
    /// continue writing.
    pub(crate) fn handle_ready_sources(&mut self, ready: &crate::poll::Events) {
        self.rx.serve_sources(ready);
        if self.rpc_service.is_some() {
            self.serve_rpc(ready);
        }
        #[cfg(feature = "hooks")]
        if let Some(bridge) = &self.hooks.provider_bridge {
            bridge.serve(ready);
        }
        if let Some(probe_server) = &mut self.probe_server {
            probe_server.serve(ready);
        }
        for event in ready.iter() {
            let (interface, is_write) = crate::interface::loop_writer::key_target(event.key);
            if is_write && event.writable {
                if let Some(entry) = self.interfaces.get_mut(&interface) {
                    entry.writer.flush_pending();
                }
            }
        }
    }

    /// Write out every driver-run writer's buffered frames.
    pub(crate) fn flush_writers(&mut self) {
        for entry in self.interfaces.values_mut() {
            entry.writer.flush_pending();
        }
    }

    /// Wake writers left asleep by deferred forwarding sends.
    pub(crate) fn wake_writers(&mut self) {
        for id in std::mem::take(&mut self.writers_to_wake) {
            if let Some(entry) = self.interfaces.get_mut(&id) {
                entry.writer.wake();
            }
        }
    }

    /// [`Self::interface_send_deferred`] at the current time, reading the
    /// clock only while a send retry is pending.
    pub(crate) fn interface_send_deferred_now(entry: &InterfaceEntry) -> bool {
        entry.send_retry_at.is_some() && Self::interface_send_deferred(entry, Instant::now())
    }

    pub(crate) fn interface_send_deferred(entry: &InterfaceEntry, now: Instant) -> bool {
        // Async writers bound their own waiting and stop waiting on a stalled
        // peer, refusing only frames that do not fit. Skipping sends to them
        // for the whole retry window would discard traffic that the drained
        // queue could have accepted.
        if entry.async_writer_metrics.is_some() {
            return false;
        }
        matches!(entry.send_retry_at, Some(retry_at) if now < retry_at)
    }

    pub(crate) fn record_send_result(
        entry: &mut InterfaceEntry,
        result: &std::io::Result<()>,
        context: &str,
        interface_id: InterfaceId,
    ) {
        match result {
            Ok(()) => {
                entry.send_retry_at = None;
                entry.send_retry_backoff = Duration::ZERO;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let next_backoff = if entry.send_retry_backoff.is_zero() {
                    SEND_RETRY_BACKOFF_MIN
                } else {
                    (entry.send_retry_backoff * 2).min(SEND_RETRY_BACKOFF_MAX)
                };
                entry.send_retry_backoff = next_backoff;
                entry.send_retry_at = Some(Instant::now() + next_backoff);
                log::debug!(
                    "[{}] {} deferred after WouldBlock; retry in {:?}",
                    interface_id.0,
                    context,
                    next_backoff
                );
            }
            Err(e) => {
                entry.send_retry_at = None;
                entry.send_retry_backoff = Duration::ZERO;
                log::warn!("[{}] {} failed: {}", interface_id.0, context, e);
            }
        }
    }
}
