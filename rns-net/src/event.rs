//! Event types for the driver loop.

use std::fmt;
use std::sync::mpsc;

use rns_core::transport::types::{InterfaceId, InterfaceInfo};

use crate::interface::Writer;

/// Events sent to the driver thread.
pub enum Event {
    /// A decoded frame arrived from an interface.
    Frame { interface_id: InterfaceId, data: Vec<u8> },
    /// An interface came online after (re)connecting.
    /// Carries a new writer if the connection was re-established.
    /// Carries InterfaceInfo if this is a new dynamic interface (e.g. TCP server client).
    InterfaceUp(InterfaceId, Option<Box<dyn Writer>>, Option<InterfaceInfo>),
    /// An interface went offline (socket closed, error).
    InterfaceDown(InterfaceId),
    /// Periodic maintenance tick (1s interval).
    Tick,
    /// Shut down the driver loop.
    Shutdown,
    /// Send an outbound packet.
    SendOutbound {
        raw: Vec<u8>,
        dest_type: u8,
        attached_interface: Option<InterfaceId>,
    },
    /// Register a local destination.
    RegisterDestination {
        dest_hash: [u8; 16],
        dest_type: u8,
    },
    /// Deregister a local destination.
    DeregisterDestination {
        dest_hash: [u8; 16],
    },
    /// Query driver state. Response is sent via the provided channel.
    Query(QueryRequest, mpsc::Sender<QueryResponse>),
    /// Register a link destination (accepts incoming LINKREQUEST).
    RegisterLinkDestination {
        dest_hash: [u8; 16],
        sig_prv_bytes: [u8; 32],
        sig_pub_bytes: [u8; 32],
    },
    /// Register a request handler for a path on established links.
    RegisterRequestHandler {
        path: String,
        allowed_list: Option<Vec<[u8; 16]>>,
        handler: Box<dyn Fn([u8; 16], &str, &[u8], Option<&([u8; 16], [u8; 64])>) -> Option<Vec<u8>> + Send>,
    },
    /// Create an outbound link. Response sends (link_id) back.
    CreateLink {
        dest_hash: [u8; 16],
        dest_sig_pub_bytes: [u8; 32],
        response_tx: mpsc::Sender<[u8; 16]>,
    },
    /// Send a request on an established link.
    SendRequest {
        link_id: [u8; 16],
        path: String,
        data: Vec<u8>,
    },
    /// Identify on a link (send identity to remote peer).
    IdentifyOnLink {
        link_id: [u8; 16],
        identity_prv_key: [u8; 64],
    },
    /// Tear down a link.
    TeardownLink {
        link_id: [u8; 16],
    },
    /// Send a resource on a link.
    SendResource {
        link_id: [u8; 16],
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
    },
    /// Set the resource acceptance strategy for a link.
    SetResourceStrategy {
        link_id: [u8; 16],
        strategy: u8,
    },
    /// Accept or reject a pending resource (for AcceptApp strategy).
    AcceptResource {
        link_id: [u8; 16],
        resource_hash: Vec<u8>,
        accept: bool,
    },
    /// Send a channel message on a link.
    SendChannelMessage {
        link_id: [u8; 16],
        msgtype: u16,
        payload: Vec<u8>,
    },
    /// Send generic data on a link with a given context.
    SendOnLink {
        link_id: [u8; 16],
        data: Vec<u8>,
        context: u8,
    },
    /// Request a path to a destination from the network.
    RequestPath {
        dest_hash: [u8; 16],
    },
    /// Register a proof strategy for a destination.
    RegisterProofStrategy {
        dest_hash: [u8; 16],
        strategy: rns_core::types::ProofStrategy,
        /// Full identity private key (64 bytes) for signing proofs.
        signing_key: Option<[u8; 64]>,
    },
}

/// Queries that can be sent to the driver.
#[derive(Debug)]
pub enum QueryRequest {
    /// Get interface statistics and transport info.
    InterfaceStats,
    /// Get path table entries, optionally filtered by max hops.
    PathTable { max_hops: Option<u8> },
    /// Get rate table entries.
    RateTable,
    /// Look up the next hop for a destination.
    NextHop { dest_hash: [u8; 16] },
    /// Look up the next hop interface name for a destination.
    NextHopIfName { dest_hash: [u8; 16] },
    /// Get link table entry count.
    LinkCount,
    /// Drop a specific path.
    DropPath { dest_hash: [u8; 16] },
    /// Drop all paths that route via a given transport hash.
    DropAllVia { transport_hash: [u8; 16] },
    /// Drop all announce queues.
    DropAnnounceQueues,
    /// Get the transport identity hash.
    TransportIdentity,
    /// Get all blackholed identities.
    GetBlackholed,
    /// Add an identity to the blackhole list.
    BlackholeIdentity {
        identity_hash: [u8; 16],
        duration_hours: Option<f64>,
        reason: Option<String>,
    },
    /// Remove an identity from the blackhole list.
    UnblackholeIdentity {
        identity_hash: [u8; 16],
    },
    /// Check if a path exists to a destination.
    HasPath { dest_hash: [u8; 16] },
    /// Get hop count to a destination.
    HopsTo { dest_hash: [u8; 16] },
    /// Recall identity info for a destination.
    RecallIdentity { dest_hash: [u8; 16] },
    /// Get locally registered destinations.
    LocalDestinations,
    /// Get active links.
    Links,
    /// Get active resource transfers.
    Resources,
}

/// Responses to queries.
#[derive(Debug)]
pub enum QueryResponse {
    InterfaceStats(InterfaceStatsResponse),
    PathTable(Vec<PathTableEntry>),
    RateTable(Vec<RateTableEntry>),
    NextHop(Option<NextHopResponse>),
    NextHopIfName(Option<String>),
    LinkCount(usize),
    DropPath(bool),
    DropAllVia(usize),
    DropAnnounceQueues,
    TransportIdentity(Option<[u8; 16]>),
    Blackholed(Vec<BlackholeInfo>),
    BlackholeResult(bool),
    UnblackholeResult(bool),
    HasPath(bool),
    HopsTo(Option<u8>),
    RecallIdentity(Option<crate::destination::AnnouncedIdentity>),
    LocalDestinations(Vec<LocalDestinationEntry>),
    Links(Vec<LinkInfoEntry>),
    Resources(Vec<ResourceInfoEntry>),
}

/// Interface statistics response.
#[derive(Debug, Clone)]
pub struct InterfaceStatsResponse {
    pub interfaces: Vec<SingleInterfaceStat>,
    pub transport_id: Option<[u8; 16]>,
    pub transport_enabled: bool,
    pub transport_uptime: f64,
    /// Total received bytes across all interfaces.
    pub total_rxb: u64,
    /// Total transmitted bytes across all interfaces.
    pub total_txb: u64,
}

/// Statistics for a single interface.
#[derive(Debug, Clone)]
pub struct SingleInterfaceStat {
    pub name: String,
    pub status: bool,
    pub mode: u8,
    pub rxb: u64,
    pub txb: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub bitrate: Option<u64>,
    pub ifac_size: Option<usize>,
    pub started: f64,
    /// Incoming announce frequency (per second).
    pub ia_freq: f64,
    /// Outgoing announce frequency (per second).
    pub oa_freq: f64,
    /// Human-readable interface type string (e.g. "TCPClientInterface").
    pub interface_type: String,
}

/// A locally registered destination.
#[derive(Debug, Clone)]
pub struct LocalDestinationEntry {
    pub hash: [u8; 16],
    pub dest_type: u8,
}

/// Information about an active link.
#[derive(Debug, Clone)]
pub struct LinkInfoEntry {
    pub link_id: [u8; 16],
    pub state: String,
    pub is_initiator: bool,
    pub dest_hash: [u8; 16],
    pub remote_identity: Option<[u8; 16]>,
    pub rtt: Option<f64>,
}

/// Information about an active resource transfer.
#[derive(Debug, Clone)]
pub struct ResourceInfoEntry {
    pub link_id: [u8; 16],
    pub direction: String,
    pub total_parts: usize,
    pub transferred_parts: usize,
    pub complete: bool,
}

/// A single path table entry for query responses.
#[derive(Debug, Clone)]
pub struct PathTableEntry {
    pub hash: [u8; 16],
    pub timestamp: f64,
    pub via: [u8; 16],
    pub hops: u8,
    pub expires: f64,
    pub interface: InterfaceId,
    pub interface_name: String,
}

/// A single rate table entry for query responses.
#[derive(Debug, Clone)]
pub struct RateTableEntry {
    pub hash: [u8; 16],
    pub last: f64,
    pub rate_violations: u32,
    pub blocked_until: f64,
    pub timestamps: Vec<f64>,
}

/// A blackholed identity for query responses.
#[derive(Debug, Clone)]
pub struct BlackholeInfo {
    pub identity_hash: [u8; 16],
    pub created: f64,
    pub expires: f64,
    pub reason: Option<String>,
}

/// Next hop lookup result.
#[derive(Debug, Clone)]
pub struct NextHopResponse {
    pub next_hop: [u8; 16],
    pub hops: u8,
    pub interface: InterfaceId,
}

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Frame { interface_id, data } => {
                f.debug_struct("Frame")
                    .field("interface_id", interface_id)
                    .field("data_len", &data.len())
                    .finish()
            }
            Event::InterfaceUp(id, writer, info) => {
                f.debug_tuple("InterfaceUp")
                    .field(id)
                    .field(&writer.is_some())
                    .field(&info.is_some())
                    .finish()
            }
            Event::InterfaceDown(id) => f.debug_tuple("InterfaceDown").field(id).finish(),
            Event::Tick => write!(f, "Tick"),
            Event::Shutdown => write!(f, "Shutdown"),
            Event::SendOutbound { raw, dest_type, .. } => {
                f.debug_struct("SendOutbound")
                    .field("raw_len", &raw.len())
                    .field("dest_type", dest_type)
                    .finish()
            }
            Event::RegisterDestination { dest_hash, dest_type } => {
                f.debug_struct("RegisterDestination")
                    .field("dest_hash", dest_hash)
                    .field("dest_type", dest_type)
                    .finish()
            }
            Event::DeregisterDestination { dest_hash } => {
                f.debug_struct("DeregisterDestination")
                    .field("dest_hash", dest_hash)
                    .finish()
            }
            Event::Query(req, _) => {
                f.debug_tuple("Query")
                    .field(req)
                    .finish()
            }
            Event::RegisterLinkDestination { dest_hash, .. } => {
                f.debug_struct("RegisterLinkDestination")
                    .field("dest_hash", dest_hash)
                    .finish()
            }
            Event::RegisterRequestHandler { path, .. } => {
                f.debug_struct("RegisterRequestHandler")
                    .field("path", path)
                    .finish()
            }
            Event::CreateLink { dest_hash, .. } => {
                f.debug_struct("CreateLink")
                    .field("dest_hash", dest_hash)
                    .finish()
            }
            Event::SendRequest { link_id, path, .. } => {
                f.debug_struct("SendRequest")
                    .field("link_id", link_id)
                    .field("path", path)
                    .finish()
            }
            Event::IdentifyOnLink { link_id, .. } => {
                f.debug_struct("IdentifyOnLink")
                    .field("link_id", link_id)
                    .finish()
            }
            Event::TeardownLink { link_id } => {
                f.debug_struct("TeardownLink")
                    .field("link_id", link_id)
                    .finish()
            }
            Event::SendResource { link_id, data, .. } => {
                f.debug_struct("SendResource")
                    .field("link_id", link_id)
                    .field("data_len", &data.len())
                    .finish()
            }
            Event::SetResourceStrategy { link_id, strategy } => {
                f.debug_struct("SetResourceStrategy")
                    .field("link_id", link_id)
                    .field("strategy", strategy)
                    .finish()
            }
            Event::AcceptResource { link_id, accept, .. } => {
                f.debug_struct("AcceptResource")
                    .field("link_id", link_id)
                    .field("accept", accept)
                    .finish()
            }
            Event::SendChannelMessage { link_id, msgtype, payload } => {
                f.debug_struct("SendChannelMessage")
                    .field("link_id", link_id)
                    .field("msgtype", msgtype)
                    .field("payload_len", &payload.len())
                    .finish()
            }
            Event::SendOnLink { link_id, data, context } => {
                f.debug_struct("SendOnLink")
                    .field("link_id", link_id)
                    .field("data_len", &data.len())
                    .field("context", context)
                    .finish()
            }
            Event::RequestPath { dest_hash } => {
                f.debug_struct("RequestPath")
                    .field("dest_hash", dest_hash)
                    .finish()
            }
            Event::RegisterProofStrategy { dest_hash, strategy, .. } => {
                f.debug_struct("RegisterProofStrategy")
                    .field("dest_hash", dest_hash)
                    .field("strategy", strategy)
                    .finish()
            }
        }
    }
}

pub type EventSender = mpsc::Sender<Event>;
pub type EventReceiver = mpsc::Receiver<Event>;

pub fn channel() -> (EventSender, EventReceiver) {
    mpsc::channel()
}
