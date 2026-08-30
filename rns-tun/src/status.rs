use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusRequest {
    pub schema_version: u8,
    pub command: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Counters {
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub malformed: u64,
    pub unauthorized: u64,
    pub queue_drops: u64,
    pub reassembly_expired: u64,
    pub early_drops: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatus {
    pub identity: String,
    pub state: String,
    pub address: Ipv4Addr,
    pub routes: Vec<String>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub counters: Counters,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeStatus {
    pub schema_version: u8,
    pub mode: String,
    pub lifecycle: String,
    pub destination_hash: Option<String>,
    pub reconnecting: bool,
    pub full_tunnel_verified: bool,
    pub sessions: Vec<SessionStatus>,
    pub queue_depths: BTreeMap<String, usize>,
    pub counters: Counters,
}

impl Default for RuntimeStatus {
    fn default() -> Self {
        Self {
            schema_version: 1,
            mode: "unknown".into(),
            lifecycle: "starting".into(),
            destination_hash: None,
            reconnecting: false,
            full_tunnel_verified: false,
            sessions: Vec::new(),
            queue_depths: BTreeMap::new(),
            counters: Counters::default(),
        }
    }
}
