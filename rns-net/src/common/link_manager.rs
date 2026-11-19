//! Link manager: wires rns-core LinkEngine + Channel + Resource into the driver.
//!
//! Manages multiple concurrent links, link destination registration,
//! request/response handling, resource transfers, and full lifecycle
//! (handshake → active → teardown).
//!
//! Python reference: Link.py, RequestReceipt.py, Resource.py

mod establishment;
mod inbound;
mod lifecycle;
mod link_destinations;
mod link_queries;
mod outbound;
mod packet_crypto;
mod resource_state;
mod routes;
mod setup;

use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

use super::compressor::Bzip2Compressor;
use rns_core::channel::{Channel, Sequence};
use rns_core::constants;
use rns_core::link::types::{LinkId, LinkState, TeardownReason};
use rns_core::link::{LinkAction, LinkEngine, LinkMode};
use rns_core::packet::{PacketFlags, RawPacket};
use rns_core::resource::{ResourceAction, ResourceReceiver, ResourceSender};
use rns_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use rns_crypto::x25519::X25519PrivateKey;
use rns_crypto::{OsRng, Rng};

use super::time;

mod channel_handling;
mod decrypt_feeder;
mod folded_assembly;
mod proof_pool;
pub use proof_pool::ProofVerifyThreads;
pub(crate) use proof_pool::{
    one_cpu, Decryption, DecryptionKey, Outcome as ProofOutcome, Owner as ProofOwner,
};
mod receive_worker;
mod request_handling;
mod resource_handling;
mod segment_builder;
mod state;

use crate::resource::{
    ReceivedResourceFile, ResourceReceiveMode, ResourceSendOptions, ResourceTransferError,
    ResourceTransferId,
};
use resource_handling::ResourceSendParams;
use state::*;

// Bound deferred handshake traffic even when an initiator never sends LRRTT.
const MAX_PRE_RTT_PACKETS: usize = 8;
const MAX_PRE_RTT_BYTES: usize = 64 * 1024;

/// Resource acceptance strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResourceStrategy {
    /// Reject all incoming resources.
    #[default]
    AcceptNone,
    /// Accept all incoming resources automatically.
    AcceptAll,
    /// Query the application callback for each resource.
    AcceptApp,
}

struct IncomingSplitTransfer {
    total_segments: u64,
    completed_segments: u64,
    current_segment_index: u64,
    current_received_parts: usize,
    current_total_parts: usize,
    storage: IncomingSplitStorage,
    metadata: Option<Vec<u8>>,
    is_request: bool,
    is_response: bool,
    /// The window and rate estimate the last completed segment ended with;
    /// the next segment continues from them.
    window: Option<(rns_core::resource::WindowState, Option<f64>)>,
}

enum IncomingSplitStorage {
    Memory(Vec<u8>),
    /// Segments are handed to the application as they arrive; only the
    /// count of bytes delivered so far is kept.
    Stream {
        size: u64,
    },
    File {
        file: File,
        path: PathBuf,
        size: u64,
    },
}

struct OutgoingSplitTransfer {
    total_segments: u64,
    completed_segments: u64,
    current_segment_index: u64,
    current_sent_parts: usize,
    current_total_parts: usize,
}

struct OutgoingStreamTransfer {
    transfer_id: ResourceTransferId,
    reader: Box<dyn Read + Send>,
    remaining: u64,
    declared_length: u64,
    metadata_overhead: u64,
    auto_compress: bool,
    app_flag: bool,
}

/// Response produced by an application request handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestResponse {
    /// Send the response as the normal request response value.
    Bytes(Vec<u8>),
    /// Send the response as a resource response with optional metadata.
    Resource {
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        auto_compress: bool,
    },
    /// Send raw file bytes with MessagePack metadata, matching Python's
    /// `[file_handle, metadata]` response. No response-value envelope is added.
    File {
        data: Vec<u8>,
        metadata: Vec<u8>,
        auto_compress: bool,
    },
}

/// Reason an outbound request failed before receiving an accepted response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestFailure {
    /// The peer advertised or sent a response larger than the configured limit.
    ResponseTooLarge { size: u64, maximum: usize },
    /// No response arrived before the request's timeout.
    TimedOut,
}

impl From<Vec<u8>> for RequestResponse {
    fn from(data: Vec<u8>) -> Self {
        RequestResponse::Bytes(data)
    }
}

/// Actions produced by LinkManager for the driver to dispatch.
#[derive(Debug)]
pub enum LinkManagerAction {
    /// Send a packet via the transport engine outbound path. The wire bytes
    /// are shared, so routing hands them to the interface without a copy.
    SendPacket {
        raw: rns_core::transport::types::PacketBytes,
        dest_type: u8,
        attached_interface: Option<rns_core::transport::types::InterfaceId>,
    },
    /// A plain link packet arrived on a link to `dest_hash`. As in upstream
    /// `Link.receive`, the destination's proof strategy decides whether it
    /// is proved; the driver holds the strategies and answers through
    /// [`LinkManager::prove_link_packet`].
    ProofRequired {
        link_id: LinkId,
        dest_hash: [u8; 16],
        packet_hash: [u8; 32],
    },
    /// The peer of `link_id` proved `packet_hash`: the proof's signature
    /// checked out against the peer's link key. The driver completes the
    /// receipt of that packet if it was sent on this link.
    PacketProved {
        link_id: LinkId,
        packet_hash: [u8; 32],
    },
    /// Link established — notify callbacks.
    LinkEstablished {
        link_id: LinkId,
        dest_hash: [u8; 16],
        hops: u8,
        rebalanced_at: Option<f64>,
        rtt: f64,
        is_initiator: bool,
    },
    /// Link closed — notify callbacks.
    LinkClosed {
        link_id: LinkId,
        reason: Option<TeardownReason>,
    },
    /// A link this node initiated closed without ever becoming active
    /// (a closed entry in `Transport.pending_links`).
    PendingLinkFailed { dest_hash: [u8; 16] },
    /// Remote peer identified — notify callbacks.
    RemoteIdentified {
        link_id: LinkId,
        identity_hash: [u8; 16],
        public_key: [u8; 64],
    },
    /// Register a link_id as local destination in transport (for receiving link data).
    RegisterLinkDest { link_id: LinkId },
    /// Deregister a link_id from transport local destinations.
    DeregisterLinkDest { link_id: LinkId },
    /// A management request that needs to be handled by the driver.
    /// The driver has access to engine state needed to build the response.
    ManagementRequest {
        link_id: LinkId,
        path_hash: [u8; 16],
        /// The request data (msgpack-encoded Value from the request array).
        data: Vec<u8>,
        /// The request_id (truncated hash of the packed request).
        request_id: [u8; 16],
        remote_identity: Option<([u8; 16], [u8; 64])>,
    },
    /// Resource data fully received and assembled.
    ResourceReceived {
        link_id: LinkId,
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        /// The application flag the sender set in the advertisement.
        app_flag: bool,
    },
    /// A disk-backed Resource is ready for application ownership.
    ResourceFileReceived {
        link_id: LinkId,
        resource: ReceivedResourceFile,
    },
    /// A verified segment of a streamed incoming Resource.
    ResourceSegmentReceived {
        link_id: LinkId,
        original_hash: [u8; 32],
        offset: u64,
        data: Vec<u8>,
    },
    /// Every segment of a streamed incoming Resource has been delivered.
    ResourceStreamReceived {
        link_id: LinkId,
        resource: crate::resource::ReceivedResourceStream,
    },
    /// Resource transfer completed (proof validated on sender side).
    ResourceCompleted { link_id: LinkId },
    /// Resource transfer failed.
    ResourceFailed { link_id: LinkId, error: String },
    /// An incoming resource was accepted and its transfer starts
    /// (upstream's `resource_started` callback): its hash and the
    /// uncompressed data size it advertised.
    ResourceStarted {
        link_id: LinkId,
        resource_hash: Vec<u8>,
        data_size: u64,
    },
    /// Resource transfer progress update.
    ResourceProgress {
        link_id: LinkId,
        received: usize,
        total: usize,
    },
    ResourceStreamCompleted {
        link_id: LinkId,
        transfer_id: ResourceTransferId,
    },
    ResourceStreamFailed {
        link_id: LinkId,
        transfer_id: ResourceTransferId,
        error: ResourceTransferError,
    },
    ResourceStreamProgress {
        link_id: LinkId,
        transfer_id: ResourceTransferId,
        transferred: u64,
        total: u64,
    },
    /// Progress of the segment being transferred, sent or received, ahead
    /// of the matching `ResourceProgress` or `ResourceStreamProgress`:
    /// upstream's `get_segment_progress()` and `get_transfer_size()`.
    ResourceSegmentProgress {
        link_id: LinkId,
        segment_progress: f64,
        transfer_size: u64,
    },
    /// Query application whether to accept an incoming resource (for AcceptApp strategy).
    ResourceAcceptQuery {
        link_id: LinkId,
        resource_hash: Vec<u8>,
        transfer_size: u64,
        has_metadata: bool,
        /// The application flag set in the advertisement.
        app_flag: bool,
    },
    /// Channel message received on a link.
    ChannelMessageReceived {
        link_id: LinkId,
        msgtype: u16,
        payload: Vec<u8>,
    },
    /// Direct Link signalling received on a link (decrypted, still framed;
    /// see `rns_core::holepunch::decode_signal`). Never proven and never
    /// shown to the application.
    DirectLinkSignal { link_id: LinkId, data: Vec<u8> },
    /// A link running over a direct path shows that the path failed (it
    /// went stale, or its channel ran out of retries): fall back to the
    /// original route.
    DirectPathFailed { link_id: LinkId },
    /// Generic link data received (CONTEXT_NONE).
    LinkDataReceived {
        link_id: LinkId,
        context: u8,
        data: Vec<u8>,
    },
    /// Response received on a link.
    ResponseReceived {
        link_id: LinkId,
        request_id: [u8; 16],
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
    },
    /// An outbound request failed.
    RequestFailed {
        link_id: LinkId,
        request_id: [u8; 16],
        reason: RequestFailure,
    },
    /// A link request was received (for hook notification).
    LinkRequestReceived {
        link_id: LinkId,
        receiving_interface: rns_core::transport::types::InterfaceId,
    },
    /// A malformed link request was rejected on an interface.
    ProtocolViolation {
        receiving_interface: rns_core::transport::types::InterfaceId,
    },
}

/// Manages multiple links, link destinations, and request/response.
pub struct LinkManager {
    receive_worker: Option<receive_worker::Worker>,
    /// Decrypts incoming resource parts as they arrive in order (parallel
    /// engine), started with the first.
    decrypt_feeder: Option<decrypt_feeder::DecryptFeeder>,
    /// Whether starting the feeder failed; assembly then decrypts.
    decrypt_feeder_failed: bool,
    /// Builds streams' next segments while their current one is transferred
    /// (parallel engine), started with the first.
    segment_builder: Option<segment_builder::SegmentBuilder>,
    /// Whether the builder failed; segments are then built on the driver.
    segment_builder_failed: bool,
    receive_worker_wake: Option<crate::event::EventSender>,
    /// Incoming compressed resources assembled on the driver loop, oldest
    /// first, when CPU work is folded.
    folded_assemblies: std::collections::VecDeque<folded_assembly::FoldedAssembly>,
    /// Threads to verify and sign link proofs on, started with the first proof.
    proof_verify_threads: ProofVerifyThreads,
    proof_pool: Option<proof_pool::ProofPool>,
    /// Whether starting the pool was settled, either way.
    proof_pool_settled: bool,
    /// Reused buffer for the pool's verdicts.
    proof_outcomes: Vec<proof_pool::Outcome>,
    /// Outcomes for single packets, for the driver to apply.
    packet_proof_outcomes: Vec<proof_pool::Outcome>,
    /// The authoritative O(1) link-id index for pending, active, and closing
    /// links. Link state lives in each `ManagedLink`, so lifecycle transitions
    /// cannot desynchronise separate list and lookup-map representations.
    links: crate::common::FastHashMap<LinkId, ManagedLink>,
    link_destinations: crate::common::FastHashMap<[u8; 16], LinkDestination>,
    /// Per-destination link request costs and `LR_STAMPS_ENFORCED`, shared
    /// with the node API and the announce builder.
    link_request_costs: crate::stamps::LinkRequestCosts,
    request_handlers: Vec<RequestHandlerEntry>,
    deferred_request_handlers: Vec<DeferredRequestHandlerEntry>,
    /// Path hashes that should be handled externally (by the driver) rather than
    /// by registered handler closures. Used for management destinations.
    management_paths: Vec<[u8; 16]>,
    link_mtu_discovery: bool,
    /// Reused buffer for the resource actions of one packet.
    resource_scratch: Vec<rns_core::resource::ResourceAction>,
    /// Reused list of requested part indices a sender answers with.
    resource_part_scratch: Vec<usize>,
    /// Reused buffer for the plaintext of a received link packet.
    plaintext_scratch: Vec<u8>,
    /// Streams whose segment (link, original hash, index) is fully sent and
    /// awaits its proof: the next segment can be prepared meanwhile.
    stream_prebuilds: Vec<(LinkId, [u8; 32], u64)>,
    /// Incoming resources (link, resource hash) holding parts that can be
    /// decrypted ahead of assembly.
    receive_decrypts: std::collections::VecDeque<(LinkId, [u8; 32])>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkRouteHint {
    pub interface: rns_core::transport::types::InterfaceId,
    pub transport_id: Option<[u8; 16]>,
    /// The link's current MTU: no packet of the link larger than this may
    /// take the route.
    pub mtu: u32,
}

impl Default for LinkManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a path hash from a path string.
/// Uses truncated SHA-256 (first 16 bytes).
fn compute_path_hash(path: &str) -> [u8; 16] {
    let full = rns_core::hash::full_hash(path.as_bytes());
    let mut result = [0u8; 16];
    result.copy_from_slice(&full[..16]);
    result
}

#[cfg(test)]
mod tests;
