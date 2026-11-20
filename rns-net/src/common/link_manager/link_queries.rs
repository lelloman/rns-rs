//! What the manager reports about its links.

use super::*;

impl LinkManager {
    pub(crate) fn resource_generation(&self, id: &LinkId) -> Option<std::sync::Arc<()>> {
        self.links
            .get(id)
            .filter(|link| link.engine.state() == LinkState::Active)
            .map(|link| link.resource_generation.clone())
    }

    /// Get the derived session key for a link (needed for hole-punch token derivation).
    pub fn get_derived_key(&self, link_id: &LinkId) -> Option<Vec<u8>> {
        self.links
            .get(link_id)
            .and_then(|link| link.engine.derived_key().map(|dk| dk.to_vec()))
    }

    /// Return the identity hash learned from a successful LINKIDENTIFY exchange.
    pub fn remote_identity_hash(&self, link_id: &LinkId) -> Option<[u8; 16]> {
        self.links
            .get(link_id)
            .and_then(|link| link.remote_identity.as_ref().map(|(hash, _)| *hash))
    }

    /// Get the state of a link.
    pub fn link_state(&self, link_id: &LinkId) -> Option<LinkState> {
        self.links.get(link_id).map(|l| l.engine.state())
    }

    /// Get the RTT of a link.
    pub fn link_rtt(&self, link_id: &LinkId) -> Option<f64> {
        self.links.get(link_id).and_then(|l| l.engine.rtt())
    }

    /// Update the RTT of a link (e.g., after path redirect to a direct connection).
    pub fn set_link_rtt(&mut self, link_id: &LinkId, rtt: f64) {
        if let Some(link) = self.links.get_mut(link_id) {
            link.engine.set_rtt(rtt);
        }
    }

    /// Reset the inbound timer for a link (e.g., after path redirect).
    pub fn record_link_inbound(&mut self, link_id: &LinkId) {
        if let Some(link) = self.links.get_mut(link_id) {
            link.engine.record_inbound(time::now());
        }
    }

    /// Update the MTU of a link (e.g., after path redirect to a different interface).
    pub fn set_link_mtu(&mut self, link_id: &LinkId, mtu: u32) {
        if let Some(link) = self.links.get_mut(link_id) {
            link.engine.set_mtu(mtu);
        }
    }

    /// Get the number of tracked links in any state.
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Get the number of established, active links.
    pub fn active_link_count(&self) -> usize {
        self.links
            .values()
            .filter(|link| link.engine.state() == LinkState::Active)
            .count()
    }

    /// Get information about all active links.
    pub fn link_entries(&self) -> Vec<crate::event::LinkInfoEntry> {
        self.links
            .iter()
            .map(|(link_id, managed)| {
                let state = match managed.engine.state() {
                    LinkState::Pending => "pending",
                    LinkState::Handshake => "handshake",
                    LinkState::Active => "active",
                    LinkState::Stale => "stale",
                    LinkState::Closed => "closed",
                };
                crate::event::LinkInfoEntry {
                    link_id: *link_id,
                    pending_send_packets: 0,
                    waiting_send_packets: 0,
                    state: state.to_string(),
                    is_initiator: managed.engine.is_initiator(),
                    dest_hash: managed.dest_hash,
                    remote_identity: managed.remote_identity.as_ref().map(|(h, _)| *h),
                    rtt: managed.engine.rtt(),
                    expected_hops: managed.engine.expected_hops(),
                    mdu: managed.engine.mdu(),
                    tx_packets: managed.engine.tx_packets(),
                    rx_packets: managed.engine.rx_packets(),
                    tx_bytes: managed.engine.tx_bytes(),
                    rx_bytes: managed.engine.rx_bytes(),
                    channel_window: managed.channel.as_ref().map(|c| c.window()),
                    channel_outstanding: managed.channel.as_ref().map(|c| c.outstanding()),
                    pending_channel_packets: managed.pending_channel_packets.len(),
                    channel_send_ok: managed.channel_send_ok,
                    channel_send_not_ready: managed.channel_send_not_ready,
                    channel_send_too_big: managed.channel_send_too_big,
                    channel_send_other_error: managed.channel_send_other_error,
                    channel_messages_received: managed.channel_messages_received,
                    packet_proofs_sent: managed.packet_proofs_sent,
                    channel_proofs_received: managed.channel_proofs_received,
                }
            })
            .collect()
    }
}
