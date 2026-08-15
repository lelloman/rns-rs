use super::*;

/// A managed link wrapping LinkEngine + optional Channel + resources.
pub(super) struct ManagedLink {
    pub(super) engine: LinkEngine,
    pub(super) channel: Option<Channel>,
    pub(super) pending_channel_packets: HashMap<[u8; 32], Sequence>,
    pub(super) channel_send_ok: u64,
    pub(super) channel_send_not_ready: u64,
    pub(super) channel_send_too_big: u64,
    pub(super) channel_send_other_error: u64,
    pub(super) channel_messages_received: u64,
    pub(super) channel_proofs_sent: u64,
    pub(super) channel_proofs_received: u64,
    /// Destination hash this link belongs to.
    pub(super) dest_hash: [u8; 16],
    /// Remote identity (hash, public_key) once identified.
    pub(super) remote_identity: Option<([u8; 16], [u8; 64])>,
    /// Destination's Ed25519 signing public key (for initiator to verify LRPROOF).
    pub(super) dest_sig_pub_bytes: Option<[u8; 32]>,
    /// Active incoming resource transfers.
    pub(super) incoming_resources: Vec<ResourceReceiver>,
    /// Active outgoing resource transfers.
    pub(super) outgoing_resources: Vec<ResourceSender>,
    /// Request IDs awaiting a packet or resource response.
    pub(super) pending_requests: HashMap<[u8; 16], PendingRequest>,
    /// Logical incoming split transfers, keyed by original resource hash.
    pub(super) incoming_splits: HashMap<[u8; 32], IncomingSplitTransfer>,
    /// Logical outgoing split transfers, keyed by original resource hash.
    pub(super) outgoing_splits: HashMap<[u8; 32], OutgoingSplitTransfer>,
    /// Reader state for bounded-memory outgoing transfers.
    pub(super) outgoing_streams: HashMap<[u8; 32], OutgoingStreamTransfer>,
    /// Resource acceptance strategy.
    pub(super) resource_strategy: ResourceStrategy,
    /// Delivery policy for independent incoming Resources.
    pub(super) resource_receive_mode: ResourceReceiveMode,
    /// Maximum accepted request size inherited from the local destination.
    pub(super) max_request_size: Option<usize>,
    /// Interface this link's packets should be sent on when known.
    pub(super) route_interface: Option<rns_core::transport::types::InterfaceId>,
    /// Next-hop transport ID seen on inbound HEADER_2 link traffic.
    ///
    /// When present, outbound link packets can be rewritten to HEADER_2 using
    /// this transport ID to preserve multi-hop routing.
    pub(super) route_transport_id: Option<[u8; 16]>,
}
pub(super) struct PendingRequest {
    pub(super) deadline: Option<f64>,
    pub(super) max_response_size: Option<usize>,
}

/// A registered link destination that can accept incoming LINKREQUEST.
pub(super) struct LinkDestination {
    pub(super) sig_prv: Ed25519PrivateKey,
    pub(super) sig_pub_bytes: [u8; 32],
    pub(super) resource_strategy: ResourceStrategy,
    pub(super) max_request_size: Option<usize>,
}

/// A registered request handler for a path.
pub(super) struct RequestHandlerEntry {
    /// The path this handler serves (e.g. "/status").
    pub(super) path: String,
    /// The truncated hash of the path (first 16 bytes of SHA-256).
    pub(super) path_hash: [u8; 16],
    /// Access control: None means allow all, Some(list) means allow only listed identities.
    pub(super) allowed_list: Option<Vec<[u8; 16]>>,
    /// Handler function: (link_id, path, request_id, data, remote_identity) -> Option<response>.
    pub(super) handler: Box<
        dyn Fn(LinkId, &str, &[u8], Option<&([u8; 16], [u8; 64])>) -> Option<RequestResponse>
            + Send,
    >,
}

pub(super) struct DeferredRequestHandlerEntry {
    pub(super) path: String,
    pub(super) path_hash: [u8; 16],
    pub(super) allowed_list: Option<Vec<[u8; 16]>>,
    pub(super) handler:
        Box<dyn Fn(LinkId, &str, [u8; 16], &[u8], Option<&([u8; 16], [u8; 64])>) + Send>,
}
