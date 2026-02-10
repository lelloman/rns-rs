use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use serde::Serialize;

use rns_net::Destination;
use rns_crypto::identity::Identity;

use crate::encode::to_hex;

const MAX_RECORDS: usize = 1000;

/// Shared state accessible from HTTP handlers and Callbacks.
pub type SharedState = Arc<RwLock<CtlState>>;

/// Registry of WebSocket broadcast senders.
pub type WsBroadcast = Arc<Mutex<Vec<std::sync::mpsc::Sender<WsEvent>>>>;

pub struct CtlState {
    pub started_at: Instant,
    pub identity_hash: Option<[u8; 16]>,
    pub identity: Option<Identity>,
    pub announces: VecDeque<AnnounceRecord>,
    pub packets: VecDeque<PacketRecord>,
    pub proofs: VecDeque<ProofRecord>,
    pub link_events: VecDeque<LinkEventRecord>,
    pub resource_events: VecDeque<ResourceEventRecord>,
    pub destinations: HashMap<[u8; 16], DestinationEntry>,
}

/// A registered destination plus metadata for the API.
pub struct DestinationEntry {
    pub destination: Destination,
    /// Full name: "app_name.aspect1.aspect2"
    pub full_name: String,
}

impl CtlState {
    pub fn new() -> Self {
        CtlState {
            started_at: Instant::now(),
            identity_hash: None,
            identity: None,
            announces: VecDeque::new(),
            packets: VecDeque::new(),
            proofs: VecDeque::new(),
            link_events: VecDeque::new(),
            resource_events: VecDeque::new(),
            destinations: HashMap::new(),
        }
    }

    pub fn uptime_seconds(&self) -> f64 {
        self.started_at.elapsed().as_secs_f64()
    }
}

fn push_capped<T>(deque: &mut VecDeque<T>, item: T) {
    if deque.len() >= MAX_RECORDS {
        deque.pop_front();
    }
    deque.push_back(item);
}

pub fn push_announce(state: &SharedState, record: AnnounceRecord) {
    let mut s = state.write().unwrap();
    push_capped(&mut s.announces, record);
}

pub fn push_packet(state: &SharedState, record: PacketRecord) {
    let mut s = state.write().unwrap();
    push_capped(&mut s.packets, record);
}

pub fn push_proof(state: &SharedState, record: ProofRecord) {
    let mut s = state.write().unwrap();
    push_capped(&mut s.proofs, record);
}

pub fn push_link_event(state: &SharedState, record: LinkEventRecord) {
    let mut s = state.write().unwrap();
    push_capped(&mut s.link_events, record);
}

pub fn push_resource_event(state: &SharedState, record: ResourceEventRecord) {
    let mut s = state.write().unwrap();
    push_capped(&mut s.resource_events, record);
}

/// Broadcast a WsEvent to all connected WebSocket clients.
pub fn broadcast(ws: &WsBroadcast, event: WsEvent) {
    let mut senders = ws.lock().unwrap();
    senders.retain(|tx| tx.send(event.clone()).is_ok());
}

// --- Record types ---

#[derive(Debug, Clone, Serialize)]
pub struct AnnounceRecord {
    pub dest_hash: String,
    pub identity_hash: String,
    pub hops: u8,
    pub app_data: Option<String>,
    pub received_at: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketRecord {
    pub dest_hash: String,
    pub packet_hash: String,
    pub data_base64: String,
    pub received_at: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProofRecord {
    pub dest_hash: String,
    pub packet_hash: String,
    pub rtt: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinkEventRecord {
    pub link_id: String,
    pub event_type: String,
    pub is_initiator: Option<bool>,
    pub rtt: Option<f64>,
    pub identity_hash: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceEventRecord {
    pub link_id: String,
    pub event_type: String,
    pub data_base64: Option<String>,
    pub metadata_base64: Option<String>,
    pub error: Option<String>,
    pub received: Option<usize>,
    pub total: Option<usize>,
}

// --- WebSocket events ---

#[derive(Debug, Clone)]
pub struct WsEvent {
    pub topic: &'static str,
    pub payload: serde_json::Value,
}

impl WsEvent {
    pub fn announce(record: &AnnounceRecord) -> Self {
        WsEvent {
            topic: "announces",
            payload: serde_json::to_value(record).unwrap_or_default(),
        }
    }

    pub fn packet(record: &PacketRecord) -> Self {
        WsEvent {
            topic: "packets",
            payload: serde_json::to_value(record).unwrap_or_default(),
        }
    }

    pub fn proof(record: &ProofRecord) -> Self {
        WsEvent {
            topic: "proofs",
            payload: serde_json::to_value(record).unwrap_or_default(),
        }
    }

    pub fn link(record: &LinkEventRecord) -> Self {
        WsEvent {
            topic: "links",
            payload: serde_json::to_value(record).unwrap_or_default(),
        }
    }

    pub fn resource(record: &ResourceEventRecord) -> Self {
        WsEvent {
            topic: "resources",
            payload: serde_json::to_value(record).unwrap_or_default(),
        }
    }

    pub fn to_json(&self) -> String {
        let obj = serde_json::json!({
            "type": self.topic.trim_end_matches('s'),
            "data": self.payload,
        });
        serde_json::to_string(&obj).unwrap_or_default()
    }
}

/// Helper to create an AnnounceRecord from callback data.
pub fn make_announce_record(announced: &rns_net::AnnouncedIdentity) -> AnnounceRecord {
    AnnounceRecord {
        dest_hash: to_hex(&announced.dest_hash.0),
        identity_hash: to_hex(&announced.identity_hash.0),
        hops: announced.hops,
        app_data: announced.app_data.as_ref().map(|d| crate::encode::to_base64(d)),
        received_at: announced.received_at,
    }
}
