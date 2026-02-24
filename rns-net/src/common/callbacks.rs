//! Application callback trait for driver events.

use rns_core::transport::types::InterfaceId;

pub trait Callbacks: Send {
    fn on_announce(
        &mut self,
        announced: crate::common::destination::AnnouncedIdentity,
    );

    fn on_path_updated(&mut self, dest_hash: rns_core::types::DestHash, hops: u8);

    fn on_local_delivery(&mut self, dest_hash: rns_core::types::DestHash, raw: Vec<u8>, packet_hash: rns_core::types::PacketHash);

    /// Called when an interface comes online.
    fn on_interface_up(&mut self, _id: InterfaceId) {}

    /// Called when an interface goes offline.
    fn on_interface_down(&mut self, _id: InterfaceId) {}

    /// Called when a link is fully established.
    fn on_link_established(&mut self, _link_id: rns_core::types::LinkId, _dest_hash: rns_core::types::DestHash, _rtt: f64, _is_initiator: bool) {}

    /// Called when a link is closed.
    fn on_link_closed(&mut self, _link_id: rns_core::types::LinkId, _reason: Option<rns_core::link::TeardownReason>) {}

    /// Called when a remote peer identifies on a link.
    fn on_remote_identified(&mut self, _link_id: rns_core::types::LinkId, _identity_hash: rns_core::types::IdentityHash, _public_key: [u8; 64]) {}

    /// Called when a resource transfer delivers data.
    fn on_resource_received(&mut self, _link_id: rns_core::types::LinkId, _data: Vec<u8>, _metadata: Option<Vec<u8>>) {}

    /// Called when a resource transfer completes (sender-side proof validated).
    fn on_resource_completed(&mut self, _link_id: rns_core::types::LinkId) {}

    /// Called when a resource transfer fails.
    fn on_resource_failed(&mut self, _link_id: rns_core::types::LinkId, _error: String) {}

    /// Called with resource transfer progress updates.
    fn on_resource_progress(&mut self, _link_id: rns_core::types::LinkId, _received: usize, _total: usize) {}

    /// Called to ask whether to accept an incoming resource (for AcceptApp strategy).
    /// Return true to accept, false to reject.
    fn on_resource_accept_query(&mut self, _link_id: rns_core::types::LinkId, _resource_hash: Vec<u8>, _transfer_size: u64, _has_metadata: bool) -> bool {
        false
    }

    /// Called when a channel message is received on a link.
    fn on_channel_message(&mut self, _link_id: rns_core::types::LinkId, _msgtype: u16, _payload: Vec<u8>) {}

    /// Called when generic link data is received.
    fn on_link_data(&mut self, _link_id: rns_core::types::LinkId, _context: u8, _data: Vec<u8>) {}

    /// Called when a response is received on a link.
    fn on_response(&mut self, _link_id: rns_core::types::LinkId, _request_id: [u8; 16], _data: Vec<u8>) {}

    /// Called when a delivery proof is received for a packet we sent.
    /// `rtt` is the round-trip time in seconds.
    fn on_proof(&mut self, _dest_hash: rns_core::types::DestHash, _packet_hash: rns_core::types::PacketHash, _rtt: f64) {}

    /// Called for ProveApp strategy: should we prove this incoming packet?
    /// Return true to generate and send a proof, false to skip.
    fn on_proof_requested(&mut self, _dest_hash: rns_core::types::DestHash, _packet_hash: rns_core::types::PacketHash) -> bool {
        true
    }

    /// Called when a direct connection is proposed by a peer (for AskApp policy).
    /// Return true to accept, false to reject.
    fn on_direct_connect_proposed(&mut self, _link_id: rns_core::types::LinkId, _peer_identity: Option<rns_core::types::IdentityHash>) -> bool {
        false
    }

    /// Called when a direct P2P connection is established via hole punching.
    fn on_direct_connect_established(&mut self, _link_id: rns_core::types::LinkId, _interface_id: InterfaceId) {}

    /// Called when a direct connection attempt fails.
    fn on_direct_connect_failed(&mut self, _link_id: rns_core::types::LinkId, _reason: u8) {}
}
