use rns_core::transport::types::InterfaceId;
use rns_core::types::{DestHash, IdentityHash, LinkId, PacketHash};
use rns_net::destination::AnnouncedIdentity;
use rns_net::Callbacks;

use crate::encode::{to_base64, to_hex};
use crate::state::*;

/// Callbacks implementation that bridges rns-net events into shared state + WebSocket broadcast.
pub struct CtlCallbacks {
    state: SharedState,
    ws_broadcast: WsBroadcast,
}

impl CtlCallbacks {
    pub fn new(state: SharedState, ws_broadcast: WsBroadcast) -> Self {
        CtlCallbacks {
            state,
            ws_broadcast,
        }
    }
}

impl Callbacks for CtlCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        let record = make_announce_record(&announced);
        let event = WsEvent::announce(&record);
        push_announce(&self.state, record);
        broadcast(&self.ws_broadcast, event);
    }

    fn on_path_updated(&mut self, _dest_hash: DestHash, _hops: u8) {
        // Path updates are queryable via GET /api/paths; no event record needed.
    }

    fn on_local_delivery(&mut self, dest_hash: DestHash, raw: Vec<u8>, packet_hash: PacketHash) {
        let record = PacketRecord {
            dest_hash: to_hex(&dest_hash.0),
            packet_hash: to_hex(&packet_hash.0),
            data_base64: to_base64(&raw),
            received_at: rns_net::time::now(),
        };
        let event = WsEvent::packet(&record);
        push_packet(&self.state, record);
        broadcast(&self.ws_broadcast, event);
    }

    fn on_proof(&mut self, dest_hash: DestHash, packet_hash: PacketHash, rtt: f64) {
        let record = ProofRecord {
            dest_hash: to_hex(&dest_hash.0),
            packet_hash: to_hex(&packet_hash.0),
            rtt,
        };
        let event = WsEvent::proof(&record);
        push_proof(&self.state, record);
        broadcast(&self.ws_broadcast, event);
    }

    fn on_proof_requested(&mut self, _dest_hash: DestHash, _packet_hash: PacketHash) -> bool {
        true
    }

    fn on_link_established(
        &mut self,
        link_id: LinkId,
        _dest_hash: DestHash,
        rtt: f64,
        is_initiator: bool,
    ) {
        // Callbacks run on the node's driver thread. HTTP handlers hold the
        // node handle lock while they wait for the driver to answer, so taking
        // that lock here deadlocks the whole control plane whenever a request
        // is in flight as a link comes up. The resource strategy for links is
        // therefore set where they are created or registered (api.rs), never
        // from a callback.
        let record = LinkEventRecord {
            link_id: to_hex(&link_id.0),
            event_type: "established".into(),
            is_initiator: Some(is_initiator),
            rtt: Some(rtt),
            identity_hash: None,
            reason: None,
        };
        let event = WsEvent::link(&record);
        push_link_event(&self.state, record);
        broadcast(&self.ws_broadcast, event);
    }

    fn on_link_closed(&mut self, link_id: LinkId, reason: Option<rns_core::link::TeardownReason>) {
        let record = LinkEventRecord {
            link_id: to_hex(&link_id.0),
            event_type: "closed".into(),
            is_initiator: None,
            rtt: None,
            identity_hash: None,
            reason: reason.map(|r| format!("{:?}", r)),
        };
        let event = WsEvent::link(&record);
        push_link_event(&self.state, record);
        broadcast(&self.ws_broadcast, event);
    }

    fn on_remote_identified(
        &mut self,
        link_id: LinkId,
        identity_hash: IdentityHash,
        _public_key: [u8; 64],
    ) {
        let record = LinkEventRecord {
            link_id: to_hex(&link_id.0),
            event_type: "identified".into(),
            is_initiator: None,
            rtt: None,
            identity_hash: Some(to_hex(&identity_hash.0)),
            reason: None,
        };
        let event = WsEvent::link(&record);
        push_link_event(&self.state, record);
        broadcast(&self.ws_broadcast, event);
    }

    fn on_resource_received(&mut self, link_id: LinkId, data: Vec<u8>, metadata: Option<Vec<u8>>) {
        let record = ResourceEventRecord {
            link_id: to_hex(&link_id.0),
            event_type: "received".into(),
            data_base64: Some(to_base64(&data)),
            metadata_base64: metadata.as_ref().map(|m| to_base64(m)),
            error: None,
            received: None,
            total: None,
        };
        let event = WsEvent::resource(&record);
        push_resource_event(&self.state, record);
        broadcast(&self.ws_broadcast, event);
    }

    fn on_resource_completed(&mut self, link_id: LinkId) {
        let record = ResourceEventRecord {
            link_id: to_hex(&link_id.0),
            event_type: "completed".into(),
            data_base64: None,
            metadata_base64: None,
            error: None,
            received: None,
            total: None,
        };
        let event = WsEvent::resource(&record);
        push_resource_event(&self.state, record);
        broadcast(&self.ws_broadcast, event);
    }

    fn on_resource_failed(&mut self, link_id: LinkId, error: String) {
        let record = ResourceEventRecord {
            link_id: to_hex(&link_id.0),
            event_type: "failed".into(),
            data_base64: None,
            metadata_base64: None,
            error: Some(error),
            received: None,
            total: None,
        };
        let event = WsEvent::resource(&record);
        push_resource_event(&self.state, record);
        broadcast(&self.ws_broadcast, event);
    }

    fn on_resource_progress(&mut self, link_id: LinkId, received: usize, total: usize) {
        let record = ResourceEventRecord {
            link_id: to_hex(&link_id.0),
            event_type: "progress".into(),
            data_base64: None,
            metadata_base64: None,
            error: None,
            received: Some(received),
            total: Some(total),
        };
        let event = WsEvent::resource(&record);
        push_resource_event(&self.state, record);
        broadcast(&self.ws_broadcast, event);
    }

    fn on_resource_accept_query(
        &mut self,
        _link_id: LinkId,
        _resource_hash: Vec<u8>,
        _transfer_size: u64,
        _has_metadata: bool,
    ) -> bool {
        true
    }

    fn on_channel_message(&mut self, link_id: LinkId, msgtype: u16, payload: Vec<u8>) {
        let record = PacketRecord {
            dest_hash: format!("channel:{}:{}", to_hex(&link_id.0), msgtype),
            packet_hash: String::new(),
            data_base64: to_base64(&payload),
            received_at: rns_net::time::now(),
        };
        let event = WsEvent::packet(&record);
        push_packet(&self.state, record);
        broadcast(&self.ws_broadcast, event);
    }

    fn on_response(&mut self, link_id: LinkId, request_id: [u8; 16], data: Vec<u8>) {
        let record = PacketRecord {
            dest_hash: format!("response:{}:{}", to_hex(&link_id.0), to_hex(&request_id)),
            packet_hash: String::new(),
            data_base64: to_base64(&data),
            received_at: rns_net::time::now(),
        };
        let event = WsEvent::packet(&record);
        push_packet(&self.state, record);
        broadcast(&self.ws_broadcast, event);
    }

    fn on_direct_connect_established(&mut self, link_id: LinkId, interface_id: InterfaceId) {
        let record = LinkEventRecord {
            link_id: to_hex(&link_id.0),
            event_type: "direct_established".into(),
            is_initiator: None,
            rtt: None,
            identity_hash: None,
            reason: Some(format!("interface_id={}", interface_id.0)),
        };
        let event = WsEvent::link(&record);
        push_link_event(&self.state, record);
        broadcast(&self.ws_broadcast, event);
    }

    fn on_direct_connect_failed(&mut self, link_id: LinkId, reason: u8) {
        let record = LinkEventRecord {
            link_id: to_hex(&link_id.0),
            event_type: "direct_failed".into(),
            is_initiator: None,
            rtt: None,
            identity_hash: None,
            reason: Some(format!("reason_code={}", reason)),
        };
        let event = WsEvent::link(&record);
        push_link_event(&self.state, record);
        broadcast(&self.ws_broadcast, event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex, RwLock};
    use std::time::Duration;

    /// Callbacks run on the node's driver thread, and HTTP handlers hold the
    /// node handle lock while they wait for the driver to answer. A callback
    /// that takes that lock therefore deadlocks the control plane as soon as
    /// a request is in flight when a link comes up, which happened live
    /// during concurrent link setup through the backbone. This test holds
    /// the lock the way a waiting handler does and requires the callback to
    /// finish anyway.
    #[test]
    fn link_established_callback_does_not_take_the_node_lock() {
        let node_handle: Arc<Mutex<Option<rns_net::RnsNode>>> = Arc::new(Mutex::new(None));
        let state: SharedState = Arc::new(RwLock::new(CtlState::default()));
        write_state(&state).node_handle = Some(node_handle.clone());
        let ws: WsBroadcast = Arc::new(Mutex::new(Vec::new()));
        let mut callbacks = CtlCallbacks::new(state.clone(), ws);

        let held_by_request_handler = lock_node_handle(&node_handle);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            callbacks.on_link_established(LinkId([7u8; 16]), DestHash([1u8; 16]), 0.5, true);
            let _ = done_tx.send(());
        });
        assert!(
            done_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "on_link_established blocked on the node handle lock"
        );
        drop(held_by_request_handler);

        let events = &read_state(&state).link_events;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "established");
    }
}
