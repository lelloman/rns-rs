//! The JSON documents exchanged over the status socket (one per line).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// A status query. The server answers only `schema_version` 1 with
/// `command` `"status"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusRequest {
    /// Request schema version; 1.
    pub schema_version: u8,
    /// The query; `"status"` is the only one.
    pub command: String,
}
/// Traffic and drop counters. "In" is traffic received from the tunnel peer
/// and written to the TUN device, "out" is traffic read from the device and
/// sent to the peer. Packets are whole IPv4 packets; bytes count IPv4 bytes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Counters {
    /// Packets received from the peer.
    pub packets_in: u64,
    /// Packets sent to the peer.
    pub packets_out: u64,
    /// Bytes received from the peer.
    pub bytes_in: u64,
    /// Bytes sent to the peer.
    pub bytes_out: u64,
    /// Packets or fragments dropped as invalid.
    pub malformed: u64,
    /// Packets dropped for a disallowed address or a wrong session epoch.
    pub unauthorized: u64,
    /// Packets dropped because the node did not take them in time.
    pub queue_drops: u64,
}
/// One tunnel session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatus {
    /// Hex hash of the peer: the gateway destination on a client, the
    /// client identity on a gateway.
    pub identity: String,
    /// Lowercase session state, such as `active` or `reconnecting`.
    pub state: String,
    /// The client's tunnel address.
    pub address: Ipv4Addr,
    /// Routes granted to the session, as CIDR strings.
    pub routes: Vec<String>,
    /// Resolvers advertised to the session.
    pub dns_servers: Vec<Ipv4Addr>,
    /// Per-session counters. Not filled in yet; all 0.
    pub counters: Counters,
}
/// The whole status document the status socket returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeStatus {
    /// Response schema version; 1.
    pub schema_version: u8,
    /// `client`, `gateway`, or `unknown` before one is set.
    pub mode: String,
    /// Lifecycle phase: `starting`, `negotiating` (client), `configuring`
    /// (gateway), `active`, `reconnecting` (client) or `stopped`.
    pub lifecycle: String,
    /// Hex hash of the gateway destination: the one connected to on a
    /// client, the one served on a gateway.
    pub destination_hash: Option<String>,
    /// Whether a client is re-establishing a lost Link.
    pub reconnecting: bool,
    /// Whether a full-tunnel client's routes and DNS were checked in place.
    pub full_tunnel_verified: bool,
    /// Current sessions; at most one on a client.
    pub sessions: Vec<SessionStatus>,
    /// Named queue depths and drop counts, such as
    /// `dropped_node_callbacks`.
    pub queue_depths: BTreeMap<String, usize>,
    /// Totals over all sessions.
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
