//! Small pieces of state queries and events share: wanted destination
//! types, packet signals, burst counts, the state snapshot.

use super::*;

impl Driver {
    /// An interface announcer that encrypts `discovery_encrypt` announces
    /// to the network identity.
    pub(crate) fn new_interface_announcer(
        &self,
        transport_id: [u8; 16],
        interfaces: Vec<crate::discovery::DiscoverableInterface>,
    ) -> crate::discovery::InterfaceAnnouncer {
        let mut announcer = crate::discovery::InterfaceAnnouncer::new(transport_id, interfaces);
        announcer.set_network_public_key(
            self.network_identity
                .as_ref()
                .and_then(|identity| identity.get_public_key()),
        );
        announcer
    }

    /// Whether interfaces discovered from the network identity
    /// `network_id` are accepted: any are without
    /// `interface_discovery_sources`.
    pub(crate) fn discovery_source_allowed(&self, network_id: &[u8; 16]) -> bool {
        self.interface_discovery_sources.is_empty()
            || self.interface_discovery_sources.contains(network_id)
    }

    /// Remember a received packet's readings, keeping the newest
    /// `PACKET_SIGNAL_CACHE_MAXSIZE`.
    pub(crate) fn record_packet_signal(
        &mut self,
        packet_hash: [u8; 32],
        signal: crate::event::PacketSignal,
    ) {
        self.packet_signals.push_back((packet_hash, signal));
        while self.packet_signals.len() > crate::driver::PACKET_SIGNAL_CACHE_MAXSIZE {
            self.packet_signals.pop_front();
        }
    }

    /// `Transport._wants_destination_type`: returns `false` for a blocked
    /// type.
    pub(crate) fn wants_destination_type(&mut self, full_name: &str, requester: &[u8]) -> bool {
        use rns_core::transport::destination_filter::destination_type;
        let registered = self
            .engine
            .destination_filter_mut()
            .want(destination_type(full_name), requester);
        if registered {
            log::debug!(
                "Registered <{full_name}> destinations requirement for <{}>",
                hex(requester)
            );
        }
        registered
    }

    /// `Transport._unwants_destination_type`: returns whether the requester
    /// had registered the type.
    pub(crate) fn unwants_destination_type(&mut self, full_name: &str, requester: &[u8]) -> bool {
        use rns_core::transport::destination_filter::destination_type;
        let destination_type = destination_type(full_name);
        let filter = self.engine.destination_filter_mut();
        let was_registered = filter.unwant(destination_type, requester);
        if was_registered {
            log::debug!(
                "Deregistered <{full_name}> destinations requirement for <{}>",
                hex(requester)
            );
            if !filter.is_wanted(&destination_type) {
                log::debug!(
                    "No remaining requesters for <{full_name}> destinations, type deregistered"
                );
            }
        }
        was_registered
    }

    #[cfg(feature = "iface-backbone")]
    pub(in crate::driver) fn dynamic_burst_counts(&self, parent_id: InterfaceId) -> (usize, usize) {
        self.dynamic_interface_parents
            .iter()
            .filter(|(_, candidate_parent)| **candidate_parent == parent_id)
            .fold((0, 0), |(announce_count, path_request_count), (id, _)| {
                (
                    announce_count + usize::from(self.engine.burst_active(id)),
                    path_request_count + usize::from(self.engine.pr_burst_active(id)),
                )
            })
    }

    /// Return active announce and path-request burst counts for a Backbone listener.
    #[cfg(feature = "iface-backbone")]
    pub fn backbone_burst_counts(&self, parent_id: InterfaceId) -> Option<(usize, usize)> {
        self.backbone_peer_state
            .values()
            .any(|handle| handle.interface_id == parent_id)
            .then(|| self.dynamic_burst_counts(parent_id))
    }

    /// Whether this node hosts `dest_hash` itself (upstream's
    /// `Transport.destinations_map`), with no path to it in the table.
    pub(super) fn hosts_destination(&self, dest_hash: &[u8; 16]) -> bool {
        self.local_destinations.contains_key(dest_hash)
    }

    /// Replace the shared link and interface statistics snapshot that
    /// `RnsNode::state_snapshot` reads without a driver round trip.
    pub(crate) fn publish_state_snapshot(&mut self) {
        let links = self.link_info_entries();
        let interfaces = self.interface_stats();
        let sequence = self.state_snapshot_schedule.published(links.len());
        self.event_tx
            .state_snapshot()
            .store(crate::state_snapshot::StateSnapshot {
                sequence,
                published_at: time::now(),
                links,
                interfaces,
            });
    }
}
