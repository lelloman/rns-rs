//! Direct paths: their lifecycle on the manager's side, losing them and
//! upgrading again.

use super::*;

impl HolePunchManager {
    /// The link lost the direct path `path`: if this side proposed it,
    /// schedule a proposal again.
    pub(super) fn direct_path_lost(
        &mut self,
        link_id: [u8; 16],
        path: &DirectPath,
        cause: DirectLossCause,
        now: f64,
    ) {
        self.count(link_id, |c| c.lost += 1);
        if let Some(history) = self.history.get_mut(&link_id) {
            history.last_loss = Some((cause, now));
        }
        let config = self.reupgrade_config;
        if !config.enabled
            || config.max_attempts == 0
            || !path.initiated
            || self.probe_addrs.is_empty()
        {
            self.reupgrades.remove(&link_id);
            return;
        }
        let entry = self.reupgrades.entry(link_id).or_insert(Reupgrade {
            attempts: 0,
            due: None,
            in_flight: false,
        });
        // A path that lasted a while starts the count again.
        if now - path.since >= config.max_delay.as_secs_f64() {
            entry.attempts = 0;
        }
        self.schedule_reupgrade(link_id, now);
    }

    /// Schedule the link's next re-upgrade proposal, or give up after the
    /// last one.
    pub(super) fn schedule_reupgrade(&mut self, link_id: [u8; 16], now: f64) {
        let config = self.reupgrade_config;
        let Some(entry) = self.reupgrades.get_mut(&link_id) else {
            return;
        };
        if entry.attempts >= config.max_attempts {
            log::info!(
                "Giving up re-upgrading link {:02x?} after {} attempts",
                &link_id[..4],
                entry.attempts
            );
            self.reupgrades.remove(&link_id);
            return;
        }
        let delay = reupgrade_delay(&config, entry.attempts, random_unit());
        entry.attempts += 1;
        entry.due = Some(now + delay);
        entry.in_flight = false;
        log::debug!(
            "Re-upgrading link {:02x?} in {:.0} s (attempt {} of {})",
            &link_id[..4],
            delay,
            entry.attempts,
            config.max_attempts
        );
    }

    /// A Direct Link attempt on the link failed: if it was a re-upgrade,
    /// try again later, unless the peer refused by policy or does not
    /// answer the capability check.
    pub(crate) fn reupgrade_failed(&mut self, link_id: [u8; 16], reason: u8) {
        if !self
            .reupgrades
            .get(&link_id)
            .is_some_and(|entry| entry.in_flight)
        {
            return;
        }
        if self.probe_addrs.is_empty() {
            self.reupgrades.remove(&link_id);
            return;
        }
        if matches!(reason, REJECT_POLICY | REJECT_UNSUPPORTED) {
            log::info!(
                "Not re-upgrading link {:02x?}: the peer refused (reason {})",
                &link_id[..4],
                reason
            );
            self.reupgrades.remove(&link_id);
            return;
        }
        self.schedule_reupgrade(link_id, time::now());
    }

    /// The link's due re-upgrade could not start because the link is
    /// stale for the moment: try again shortly, without counting an
    /// attempt. A link's watchdog marks it stale in the same run that
    /// sends the keepalive whose answer reactivates it, so a link that is
    /// fine is stale for a moment every so often; one that is not closes
    /// soon after, which cancels the re-upgrade.
    pub(crate) fn postpone_reupgrade(&mut self, link_id: [u8; 16]) {
        if let Some(entry) = self.reupgrades.get_mut(&link_id) {
            if entry.in_flight {
                log::debug!(
                    "Link {:02x?} is stale for now: re-upgrading it shortly",
                    &link_id[..4]
                );
                entry.in_flight = false;
                entry.due = Some(time::now() + REUPGRADE_STALE_RETRY);
            }
        }
    }

    /// Stop re-upgrading the link (it is no longer active).
    pub(crate) fn cancel_reupgrade(&mut self, link_id: &[u8; 16]) {
        self.reupgrades.remove(link_id);
    }

    /// Called when a link is closed — clean up any associated session.
    /// The link's direct interface is removed by a later [`tick`](Self::tick),
    /// once the link's closing packets have been sent on it.
    pub(crate) fn link_closed(&mut self, link_id: &[u8; 16]) {
        self.remove_link_session(link_id);
        self.history.remove(link_id);
        self.peer_support.remove(link_id);
        self.reupgrades.remove(link_id);
        if let Some(path) = self.direct.remove(link_id) {
            self.retiring.push((
                *link_id,
                path.interface_id,
                time::now() + DIRECT_INTERFACE_RETIRE_DELAY,
            ));
        }
    }

    /// Whether `interface_id` is a direct interface, of a live upgrade or
    /// of a closed link waiting to be removed.
    pub(crate) fn is_direct_interface(
        &self,
        interface_id: rns_core::transport::types::InterfaceId,
    ) -> bool {
        self.direct
            .values()
            .any(|path| path.interface_id == interface_id)
            || self
                .retiring
                .iter()
                .any(|(_, retiring, _)| *retiring == interface_id)
    }

    /// The direct interface a link was upgraded to, if any.
    #[cfg(test)]
    pub(crate) fn direct_interface(
        &self,
        link_id: &[u8; 16],
    ) -> Option<rns_core::transport::types::InterfaceId> {
        self.direct.get(link_id).map(|path| path.interface_id)
    }

    /// The link whose direct interface `interface_id` is, if any.
    pub(crate) fn direct_link_of(
        &self,
        interface_id: rns_core::transport::types::InterfaceId,
    ) -> Option<[u8; 16]> {
        self.direct
            .iter()
            .find(|(_, path)| path.interface_id == interface_id)
            .map(|(link_id, _)| *link_id)
    }

    /// The session of the link's direct path, if any.
    pub(crate) fn direct_session(&self, link_id: &[u8; 16]) -> Option<[u8; 16]> {
        self.direct.get(link_id).map(|path| path.session_id)
    }

    /// Stop using the link's direct path: forget it and return its
    /// interface and session. The caller removes the interface.
    pub(crate) fn take_direct(
        &mut self,
        link_id: &[u8; 16],
        cause: DirectLossCause,
    ) -> Option<(rns_core::transport::types::InterfaceId, [u8; 16])> {
        let path = self.direct.remove(link_id)?;
        self.direct_path_lost(*link_id, &path, cause, time::now());
        Some((path.interface_id, path.session_id))
    }

    /// Make the link's direct path silently drop all traffic both ways, as
    /// a network that stopped carrying it would. For tests.
    pub(crate) fn blackhole_direct(&self, link_id: &[u8; 16]) -> bool {
        match self.direct.get(link_id) {
            Some(path) => {
                path.blackhole
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    /// Called when an interface went down: if it was a link's direct
    /// interface, forget it and return the link and the path's session.
    pub(crate) fn direct_interface_down(
        &mut self,
        interface_id: rns_core::transport::types::InterfaceId,
    ) -> Option<([u8; 16], [u8; 16])> {
        self.retiring
            .retain(|(_, retiring, _)| *retiring != interface_id);
        let link_id = self
            .direct
            .iter()
            .find(|(_, path)| path.interface_id == interface_id)
            .map(|(link_id, _)| *link_id)?;
        let path = self.direct.remove(&link_id)?;
        self.direct_path_lost(link_id, &path, DirectLossCause::InterfaceDown, time::now());
        Some((link_id, path.session_id))
    }
}
