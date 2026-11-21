//! Counters and the status the manager reports.

use super::*;

impl HolePunchManager {
    /// Count something about `link_id`'s upgrades, node-wide and for the
    /// link.
    pub(super) fn count(&mut self, link_id: [u8; 16], update: impl Fn(&mut Counters)) {
        update(&mut self.totals);
        update(&mut self.history.entry(link_id).or_default().counters);
    }

    /// An upgrade on `link_id` failed with `reason` (reported to the
    /// application as `on_direct_connect_failed`).
    pub(crate) fn note_failed(&mut self, link_id: [u8; 16], reason: u8) {
        self.count(link_id, |c| *c.failed.entry(reason).or_default() += 1);
        if let Some(history) = self.history.get_mut(&link_id) {
            history.last_failure = Some((reason, time::now()));
        }
    }

    /// The direct interface `interface_id` found its path MTU.
    pub(crate) fn note_direct_mtu(
        &mut self,
        interface_id: rns_core::transport::types::InterfaceId,
        mtu: u32,
    ) {
        if let Some(path) = self
            .direct
            .values_mut()
            .find(|path| path.interface_id == interface_id)
        {
            path.mtu = mtu;
            path.mtu_discovered = true;
        }
    }

    /// The state of Direct Link on this node, for status reports.
    pub(crate) fn status(&self) -> DirectLinkStatus {
        let mut link_ids: Vec<[u8; 16]> = self
            .history
            .keys()
            .chain(self.direct.keys())
            .chain(self.link_to_session.keys())
            .chain(self.peer_support.keys())
            .chain(self.reupgrades.keys())
            .copied()
            .collect();
        link_ids.sort_unstable();
        link_ids.dedup();
        let links = link_ids
            .into_iter()
            .map(|link_id| {
                let history = self.history.get(&link_id);
                DirectLinkEntry {
                    link_id,
                    direct: self.direct.get(&link_id).map(|path| DirectPathStatus {
                        interface_id: path.interface_id,
                        session_id: path.session_id,
                        initiator: path.initiated,
                        peer_addr: path.peer_addr,
                        candidate: path.candidate,
                        candidates: path.candidates.clone(),
                        rtt: path.rtt,
                        mtu: path.mtu,
                        mtu_discovered: path.mtu_discovered,
                        peer_max_packet: path.peer_max_packet,
                        since: path.since,
                    }),
                    session_state: self
                        .link_to_session
                        .get(&link_id)
                        .and_then(|session_id| self.sessions.get(session_id))
                        .and_then(|session| state_name(session.engine.state())),
                    peer_supported: match self.peer_support.get(&link_id) {
                        Some(PeerSupport::Supported) => Some(true),
                        _ => None,
                    },
                    counters: history.map(|h| h.counters.report()).unwrap_or_default(),
                    last_failure: history.and_then(|h| h.last_failure),
                    last_loss: history.and_then(|h| h.last_loss),
                    reupgrade: self
                        .reupgrades
                        .get(&link_id)
                        .map(|entry| (entry.attempts, entry.due)),
                }
            })
            .collect();
        DirectLinkStatus {
            enabled: self.enabled(),
            probe_servers: self.probe_addrs.clone(),
            probe_server: self.probe_server_counters.as_ref().map(|counters| {
                crate::event::ProbeServerReport {
                    answered: counters.answered(),
                    rate_limited: counters.rate_limited(),
                }
            }),
            totals: self.totals.report(),
            links,
        }
    }
}
