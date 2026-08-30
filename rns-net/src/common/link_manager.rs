//! Link manager: wires rns-core LinkEngine + Channel + Resource into the driver.
//!
//! Manages multiple concurrent links, link destination registration,
//! request/response handling, resource transfers, and full lifecycle
//! (handshake → active → teardown).
//!
//! Python reference: Link.py, RequestReceipt.py, Resource.py

use std::collections::HashMap;
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
use rns_crypto::ed25519::Ed25519PrivateKey;
use rns_crypto::{OsRng, Rng};

use super::time;

mod channel_handling;
mod request_handling;
mod resource_handling;
mod state;

use crate::resource::{
    ReceivedResourceFile, ResourceReceiveMode, ResourceTransferError, ResourceTransferId,
};
use resource_handling::ResourceSendParams;
use state::*;

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
}

enum IncomingSplitStorage {
    Memory(Vec<u8>),
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
}

/// Reason an outbound request failed before receiving an accepted response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestFailure {
    /// The peer advertised or sent a response larger than the configured limit.
    ResponseTooLarge { size: u64, maximum: usize },
}

impl From<Vec<u8>> for RequestResponse {
    fn from(data: Vec<u8>) -> Self {
        RequestResponse::Bytes(data)
    }
}

/// Actions produced by LinkManager for the driver to dispatch.
#[derive(Debug)]
pub enum LinkManagerAction {
    /// Send a packet via the transport engine outbound path.
    SendPacket {
        raw: Vec<u8>,
        dest_type: u8,
        attached_interface: Option<rns_core::transport::types::InterfaceId>,
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
    },
    /// A disk-backed Resource is ready for application ownership.
    ResourceFileReceived {
        link_id: LinkId,
        resource: ReceivedResourceFile,
    },
    /// Resource transfer completed (proof validated on sender side).
    ResourceCompleted { link_id: LinkId },
    /// Resource transfer failed.
    ResourceFailed { link_id: LinkId, error: String },
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
    /// Query application whether to accept an incoming resource (for AcceptApp strategy).
    ResourceAcceptQuery {
        link_id: LinkId,
        resource_hash: Vec<u8>,
        transfer_size: u64,
        has_metadata: bool,
    },
    /// Channel message received on a link.
    ChannelMessageReceived {
        link_id: LinkId,
        msgtype: u16,
        payload: Vec<u8>,
    },
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
    /// The authoritative O(1) link-id index for pending, active, and closing
    /// links. Link state lives in each `ManagedLink`, so lifecycle transitions
    /// cannot desynchronise separate list and lookup-map representations.
    links: HashMap<LinkId, ManagedLink>,
    link_destinations: HashMap<[u8; 16], LinkDestination>,
    request_handlers: Vec<RequestHandlerEntry>,
    deferred_request_handlers: Vec<DeferredRequestHandlerEntry>,
    /// Path hashes that should be handled externally (by the driver) rather than
    /// by registered handler closures. Used for management destinations.
    management_paths: Vec<[u8; 16]>,
    link_mtu_discovery: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkRouteHint {
    pub interface: rns_core::transport::types::InterfaceId,
    pub transport_id: Option<[u8; 16]>,
}

impl LinkManager {
    fn resource_sdu_for_link(link: &ManagedLink) -> usize {
        // Python parity: Resource.sdu = link.mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE
        // when MTU signalling is available on the link.
        let mtu = link.engine.mtu() as usize;
        let derived = mtu.saturating_sub(constants::HEADER_MAXSIZE + constants::IFAC_MIN_SIZE);
        if derived > 0 {
            derived
        } else {
            constants::RESOURCE_SDU
        }
    }

    fn split_progress_parts(
        segment_index: u64,
        total_segments: u64,
        current_done: usize,
        current_total: usize,
        sdu: usize,
    ) -> (usize, usize) {
        let max_parts_per_segment = constants::RESOURCE_MAX_EFFICIENT_SIZE.div_ceil(sdu.max(1));
        let total = (total_segments as usize).saturating_mul(max_parts_per_segment);
        let completed_segments = segment_index.saturating_sub(1) as usize;
        let completed = completed_segments.saturating_mul(max_parts_per_segment);
        let current = if current_total == 0 {
            0
        } else if current_total < max_parts_per_segment {
            let scaled =
                (current_done as f64) * (max_parts_per_segment as f64 / current_total as f64);
            scaled.floor() as usize
        } else {
            current_done
        };
        (completed.saturating_add(current).min(total), total)
    }

    fn resource_hash_key(hash: &[u8]) -> Option<[u8; 32]> {
        let mut key = [0u8; 32];
        if hash.len() != key.len() {
            return None;
        }
        key.copy_from_slice(hash);
        Some(key)
    }

    fn incoming_storage(
        mode: &ResourceReceiveMode,
        original_hash: &[u8; 32],
    ) -> std::io::Result<IncomingSplitStorage> {
        match mode {
            ResourceReceiveMode::Memory { .. } => Ok(IncomingSplitStorage::Memory(Vec::new())),
            ResourceReceiveMode::TemporaryFile { directory, .. } => {
                let (file, path) = crate::resource::create_receive_file(directory, original_hash)?;
                Ok(IncomingSplitStorage::File {
                    file,
                    path,
                    size: 0,
                })
            }
        }
    }

    fn incoming_split_progress(split: &IncomingSplitTransfer, sdu: usize) -> (usize, usize) {
        Self::split_progress_parts(
            split.current_segment_index,
            split.total_segments,
            split.current_received_parts,
            split.current_total_parts,
            sdu,
        )
    }

    fn outgoing_split_progress(split: &OutgoingSplitTransfer, sdu: usize) -> (usize, usize) {
        Self::split_progress_parts(
            split.current_segment_index,
            split.total_segments,
            split.current_sent_parts,
            split.current_total_parts,
            sdu,
        )
    }

    /// Create a new empty link manager.
    pub fn new() -> Self {
        LinkManager {
            links: HashMap::new(),
            link_destinations: HashMap::new(),
            request_handlers: Vec::new(),
            deferred_request_handlers: Vec::new(),
            management_paths: Vec::new(),
            link_mtu_discovery: true,
        }
    }

    pub(crate) fn set_link_mtu_discovery(&mut self, enabled: bool) {
        self.link_mtu_discovery = enabled;
    }

    /// Register a path hash as a management path.
    /// Management requests are returned as ManagementRequest actions
    /// for the driver to handle (since they need access to engine state).
    pub fn register_management_path(&mut self, path_hash: [u8; 16]) {
        if !self.management_paths.contains(&path_hash) {
            self.management_paths.push(path_hash);
        }
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

    /// Return best-known routing hint for link packets.
    pub fn get_link_route_hint(&self, link_id: &LinkId) -> Option<LinkRouteHint> {
        self.links.get(link_id).and_then(|link| {
            link.route_interface.map(|interface| LinkRouteHint {
                interface,
                transport_id: link.route_transport_id,
            })
        })
    }

    /// Set the best-known outbound route for a link.
    pub fn set_link_route_hint(
        &mut self,
        link_id: &LinkId,
        interface: rns_core::transport::types::InterfaceId,
        transport_id: Option<[u8; 16]>,
    ) -> bool {
        let Some(link) = self.links.get_mut(link_id) else {
            return false;
        };
        link.route_interface = Some(interface);
        link.route_transport_id = transport_id;
        true
    }

    /// Register a destination that can accept incoming links.
    pub fn register_link_destination(
        &mut self,
        dest_hash: [u8; 16],
        sig_prv: Ed25519PrivateKey,
        sig_pub_bytes: [u8; 32],
        resource_strategy: ResourceStrategy,
    ) {
        self.link_destinations.insert(
            dest_hash,
            LinkDestination {
                sig_prv,
                sig_pub_bytes,
                resource_strategy,
                max_request_size: None,
            },
        );
    }

    /// Configure the maximum request size for this destination.
    ///
    /// The new limit also applies to responder links that are already active.
    /// Returns false when the destination is not registered.
    pub fn set_link_destination_max_request_size(
        &mut self,
        dest_hash: &[u8; 16],
        max_request_size: Option<usize>,
    ) -> bool {
        let Some(destination) = self.link_destinations.get_mut(dest_hash) else {
            return false;
        };
        destination.max_request_size = max_request_size;
        for link in self.links.values_mut() {
            if link.dest_hash == *dest_hash && link.dest_sig_pub_bytes.is_none() {
                link.max_request_size = max_request_size;
            }
        }
        true
    }

    /// Deregister a link destination.
    pub fn deregister_link_destination(&mut self, dest_hash: &[u8; 16]) {
        self.link_destinations.remove(dest_hash);
    }

    /// Register a request handler for a given path.
    ///
    /// `path`: the request path string (e.g. "/status")
    /// `allowed_list`: None = allow all, Some(list) = restrict to these identity hashes
    /// `handler`: called with (link_id, path, request_data, remote_identity) -> Option<response>
    pub fn register_request_handler<F>(
        &mut self,
        path: &str,
        allowed_list: Option<Vec<[u8; 16]>>,
        handler: F,
    ) where
        F: Fn(LinkId, &str, &[u8], Option<&([u8; 16], [u8; 64])>) -> Option<Vec<u8>>
            + Send
            + 'static,
    {
        let path_hash = compute_path_hash(path);
        self.request_handlers.push(RequestHandlerEntry {
            path: path.to_string(),
            path_hash,
            allowed_list,
            handler: Box::new(move |link_id, p, data, remote| {
                handler(link_id, p, data, remote).map(RequestResponse::Bytes)
            }),
        });
    }

    /// Register a request handler that can return resource responses with metadata.
    pub fn register_request_handler_response<F>(
        &mut self,
        path: &str,
        allowed_list: Option<Vec<[u8; 16]>>,
        handler: F,
    ) where
        F: Fn(LinkId, &str, &[u8], Option<&([u8; 16], [u8; 64])>) -> Option<RequestResponse>
            + Send
            + 'static,
    {
        let path_hash = compute_path_hash(path);
        self.request_handlers.push(RequestHandlerEntry {
            path: path.to_string(),
            path_hash,
            allowed_list,
            handler: Box::new(handler),
        });
    }

    /// Register a request handler that produces its response asynchronously.
    pub fn register_deferred_request_handler<F>(
        &mut self,
        path: &str,
        allowed_list: Option<Vec<[u8; 16]>>,
        handler: F,
    ) where
        F: Fn(LinkId, &str, [u8; 16], &[u8], Option<&([u8; 16], [u8; 64])>) + Send + 'static,
    {
        self.deferred_request_handlers
            .push(DeferredRequestHandlerEntry {
                path: path.to_string(),
                path_hash: compute_path_hash(path),
                allowed_list,
                handler: Box::new(handler),
            });
    }

    /// Create an outbound link to a destination.
    ///
    /// `dest_sig_pub_bytes` is the destination's Ed25519 signing public key
    /// (needed to verify LRPROOF). In Python this comes from the Destination's Identity.
    ///
    /// Returns `(link_id, actions)`. The first action will be a SendPacket with
    /// the LINKREQUEST.
    pub fn create_link(
        &mut self,
        dest_hash: &[u8; 16],
        dest_sig_pub_bytes: &[u8; 32],
        hops: u8,
        mtu: u32,
        rng: &mut dyn Rng,
    ) -> (LinkId, Vec<LinkManagerAction>) {
        let mode = LinkMode::Aes256Cbc;
        let signalled_mtu = self.link_mtu_discovery.then_some(mtu);
        let (mut engine, request_data) =
            LinkEngine::new_initiator(dest_hash, hops, mode, signalled_mtu, time::now(), rng);

        // Build the LINKREQUEST packet to compute link_id
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_LINKREQUEST,
        };

        let packet = match RawPacket::pack(
            flags,
            0,
            dest_hash,
            None,
            constants::CONTEXT_NONE,
            &request_data,
        ) {
            Ok(p) => p,
            Err(_) => {
                // Should not happen with valid data
                return ([0u8; 16], Vec::new());
            }
        };

        engine.set_link_id_from_hashable(&packet.get_hashable_part(), request_data.len());
        let link_id = *engine.link_id();

        engine.record_outbound_traffic(packet.data.len());
        let managed = ManagedLink {
            engine,
            channel: None,
            pending_channel_packets: HashMap::new(),
            channel_send_ok: 0,
            channel_send_not_ready: 0,
            channel_send_too_big: 0,
            channel_send_other_error: 0,
            channel_messages_received: 0,
            channel_proofs_sent: 0,
            channel_proofs_received: 0,
            dest_hash: *dest_hash,
            remote_identity: None,
            dest_sig_pub_bytes: Some(*dest_sig_pub_bytes),
            incoming_resources: Vec::new(),
            outgoing_resources: Vec::new(),
            pending_requests: HashMap::new(),
            incoming_splits: HashMap::new(),
            outgoing_splits: HashMap::new(),
            outgoing_streams: HashMap::new(),
            resource_strategy: ResourceStrategy::default(),
            resource_receive_mode: ResourceReceiveMode::default(),
            max_request_size: None,
            route_interface: None,
            route_transport_id: None,
        };
        self.links.insert(link_id, managed);

        let actions = vec![
            // Register the link_id as a local destination so we can receive LRPROOF
            LinkManagerAction::RegisterLinkDest { link_id },
            // Send the LINKREQUEST packet
            LinkManagerAction::SendPacket {
                raw: packet.raw,
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            },
        ];

        (link_id, actions)
    }

    /// Handle a packet delivered locally (via DeliverLocal).
    ///
    /// Returns actions for the driver to dispatch. The `dest_hash` is the
    /// packet's destination_hash field. `raw` is the full packet bytes.
    /// `packet_hash` is the SHA-256 hash.
    pub fn handle_local_delivery(
        &mut self,
        dest_hash: [u8; 16],
        raw: &[u8],
        packet_hash: [u8; 32],
        receiving_interface: rns_core::transport::types::InterfaceId,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let packet = match RawPacket::unpack(raw) {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };

        // Python accounts link traffic once the packet is accepted on its
        // attached interface, before dispatch/decryption of its context.
        if packet.flags.packet_type != constants::PACKET_TYPE_LINKREQUEST {
            if let Some(link) = self.links.get_mut(&dest_hash) {
                link.engine.record_inbound_traffic(packet.data.len());
            }
        }

        match packet.flags.packet_type {
            constants::PACKET_TYPE_LINKREQUEST => {
                self.handle_linkrequest(&dest_hash, &packet, receiving_interface, rng)
            }
            constants::PACKET_TYPE_PROOF if packet.context == constants::CONTEXT_LRPROOF => {
                // LRPROOF: dest_hash is the link_id
                self.handle_lrproof(&dest_hash, &packet, receiving_interface, rng)
            }
            constants::PACKET_TYPE_PROOF if packet.context == constants::CONTEXT_RESOURCE_PRF => {
                // Resource proofs are PROOF packets with raw proof data, not
                // encrypted DATA packets.
                self.handle_resource_prf(&dest_hash, &packet.data, rng)
            }
            constants::PACKET_TYPE_PROOF => self.handle_link_proof(&dest_hash, &packet, rng),
            constants::PACKET_TYPE_DATA => {
                self.handle_link_data(&dest_hash, &packet, packet_hash, receiving_interface, rng)
            }
            _ => Vec::new(),
        }
    }

    /// Handle an incoming LINKREQUEST packet.
    fn handle_linkrequest(
        &mut self,
        dest_hash: &[u8; 16],
        packet: &RawPacket,
        receiving_interface: rns_core::transport::types::InterfaceId,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        // Look up the link destination
        let ld = match self.link_destinations.get(dest_hash) {
            Some(ld) => ld,
            None => return Vec::new(),
        };

        let hashable = packet.get_hashable_part();
        let now = time::now();

        // Create responder engine
        let (engine, lrproof_data) = match LinkEngine::new_responder(
            &ld.sig_prv,
            &ld.sig_pub_bytes,
            &packet.data,
            &hashable,
            dest_hash,
            packet.hops,
            now,
            rng,
        ) {
            Ok(r) => r,
            Err(e) => {
                log::debug!("LINKREQUEST rejected: {}", e);
                return vec![LinkManagerAction::ProtocolViolation {
                    receiving_interface,
                }];
            }
        };

        let link_id = *engine.link_id();
        log::debug!(
            "LINKREQUEST accepted: link={:02x?} iface={} header_type={} transport_id_present={} hops={}",
            &link_id[..4],
            receiving_interface.0,
            packet.flags.header_type,
            packet.transport_id.is_some(),
            packet.hops
        );

        let managed = ManagedLink {
            engine,
            channel: None,
            pending_channel_packets: HashMap::new(),
            channel_send_ok: 0,
            channel_send_not_ready: 0,
            channel_send_too_big: 0,
            channel_send_other_error: 0,
            channel_messages_received: 0,
            channel_proofs_sent: 0,
            channel_proofs_received: 0,
            dest_hash: *dest_hash,
            remote_identity: None,
            dest_sig_pub_bytes: None,
            incoming_resources: Vec::new(),
            outgoing_resources: Vec::new(),
            pending_requests: HashMap::new(),
            incoming_splits: HashMap::new(),
            outgoing_splits: HashMap::new(),
            outgoing_streams: HashMap::new(),
            resource_strategy: ld.resource_strategy,
            resource_receive_mode: ResourceReceiveMode::default(),
            max_request_size: ld.max_request_size,
            route_interface: Some(receiving_interface),
            route_transport_id: if packet.flags.header_type == constants::HEADER_2 {
                packet.transport_id
            } else {
                None
            },
        };
        self.links.insert(link_id, managed);

        // Build LRPROOF packet: type=PROOF, context=LRPROOF, dest=link_id
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_PROOF,
        };

        let mut actions = Vec::new();

        // Register link_id as local destination so we receive link data
        actions.push(LinkManagerAction::RegisterLinkDest { link_id });

        if let Ok((raw, _packet_hash)) = RawPacket::pack_raw_with_hash(
            flags,
            0,
            &link_id,
            None,
            constants::CONTEXT_LRPROOF,
            &lrproof_data,
        ) {
            log::debug!(
                "LRPROOF queued: link={:02x?} route_iface={} route_tid_present={} hops=0",
                &link_id[..4],
                receiving_interface.0,
                packet.transport_id.is_some()
            );
            actions.push(LinkManagerAction::SendPacket {
                raw,
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            });
        }

        // Notify hook system about the incoming link request
        actions.push(LinkManagerAction::LinkRequestReceived {
            link_id,
            receiving_interface,
        });

        actions
    }

    fn handle_link_proof(
        &mut self,
        link_id: &LinkId,
        packet: &RawPacket,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        if packet.data.len() != 96 {
            return Vec::new();
        }

        let mut tracked_hash = [0u8; 32];
        tracked_hash.copy_from_slice(&packet.data[..32]);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&packet.data[32..]);

        let Some(link) = self.links.get_mut(link_id) else {
            return Vec::new();
        };
        if !link.engine.validate_packet_proof(&tracked_hash, &signature) {
            return Vec::new();
        }
        let Some(sequence) = link.pending_channel_packets.remove(&tracked_hash) else {
            return Vec::new();
        };
        link.channel_proofs_received += 1;
        let Some(channel) = link.channel.as_mut() else {
            return Vec::new();
        };

        let chan_actions = channel.packet_delivered(sequence);
        let _ = channel;
        let _ = link;
        self.process_channel_actions(link_id, chan_actions, rng)
    }

    fn build_link_packet_proof(
        &mut self,
        link_id: &LinkId,
        packet_hash: &[u8; 32],
    ) -> Vec<LinkManagerAction> {
        let signature = match self.links.get_mut(link_id) {
            Some(link) => {
                link.channel_proofs_sent += 1;
                link.engine.sign_packet_hash(packet_hash)
            }
            None => return Vec::new(),
        };
        let mut proof_data = Vec::with_capacity(96);
        proof_data.extend_from_slice(packet_hash);
        proof_data.extend_from_slice(&signature);

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        if let Ok((raw, _packet_hash)) = RawPacket::pack_raw_with_hash(
            flags,
            0,
            link_id,
            None,
            constants::CONTEXT_NONE,
            &proof_data,
        ) {
            vec![LinkManagerAction::SendPacket {
                raw,
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            }]
        } else {
            Vec::new()
        }
    }

    /// Handle an incoming LRPROOF packet (initiator side).
    fn handle_lrproof(
        &mut self,
        link_id_bytes: &[u8; 16],
        packet: &RawPacket,
        receiving_interface: rns_core::transport::types::InterfaceId,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id_bytes) {
            Some(l) => l,
            None => return Vec::new(),
        };

        link.route_interface = Some(receiving_interface);
        if packet.flags.header_type == constants::HEADER_2 {
            if let Some(transport_id) = packet.transport_id {
                link.route_transport_id = Some(transport_id);
            }
        }
        log::debug!(
            "LRPROOF received: link={:02x?} iface={} header_type={} transport_id_present={}",
            &link_id_bytes[..4],
            receiving_interface.0,
            packet.flags.header_type,
            packet.transport_id.is_some()
        );

        if link.engine.state() != LinkState::Pending || !link.engine.is_initiator() {
            return Vec::new();
        }

        // The destination's signing pub key was stored when create_link was called
        let dest_sig_pub_bytes = match link.dest_sig_pub_bytes {
            Some(b) => b,
            None => {
                log::debug!("LRPROOF: no destination signing key available");
                return Vec::new();
            }
        };

        let now = time::now();
        let (lrrtt_encrypted, link_actions) = match link.engine.handle_lrproof_with_hops(
            &packet.data,
            &dest_sig_pub_bytes,
            Some(packet.hops),
            now,
            rng,
        ) {
            Ok(r) => r,
            Err(e) => {
                log::debug!("LRPROOF validation failed: {}", e);
                return Vec::new();
            }
        };

        let link_id = *link.engine.link_id();
        let mut actions = Vec::new();

        // Process link actions (StateChanged, LinkEstablished)
        actions.extend(self.process_link_actions(&link_id, &link_actions));

        // Send LRRTT: type=DATA, context=LRRTT, dest=link_id
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        };

        if let Ok((raw, _packet_hash)) = RawPacket::pack_raw_with_hash(
            flags,
            0,
            &link_id,
            None,
            constants::CONTEXT_LRRTT,
            &lrrtt_encrypted,
        ) {
            actions.push(LinkManagerAction::SendPacket {
                raw,
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            });
        }

        // Initialize channel now that link is active
        if let Some(link) = self.links.get_mut(&link_id) {
            if link.engine.state() == LinkState::Active {
                let rtt = link.engine.rtt().unwrap_or(1.0);
                link.channel = Some(Channel::new(rtt));
            }
        }

        actions
    }

    /// Handle DATA packets on an established link.
    ///
    /// Structured to avoid borrow checker issues: we perform engine operations
    /// on the link, collect intermediate results, drop the mutable borrow, then
    /// call self methods that need immutable access.
    fn handle_link_data(
        &mut self,
        link_id_bytes: &[u8; 16],
        packet: &RawPacket,
        packet_hash: [u8; 32],
        receiving_interface: rns_core::transport::types::InterfaceId,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        // First pass: perform engine operations, collect results
        enum LinkDataResult<'a> {
            Lrrtt {
                link_id: LinkId,
                link_actions: Vec<LinkAction>,
            },
            Identify {
                link_id: LinkId,
                link_actions: Vec<LinkAction>,
            },
            Keepalive {
                link_id: LinkId,
                inbound_actions: Vec<LinkAction>,
                reply: bool,
                received_at: f64,
            },
            LinkClose {
                link_id: LinkId,
                teardown_actions: Vec<LinkAction>,
            },
            Channel {
                link_id: LinkId,
                inbound_actions: Vec<LinkAction>,
                plaintext: Vec<u8>,
                packet_hash: [u8; 32],
            },
            Request {
                link_id: LinkId,
                inbound_actions: Vec<LinkAction>,
                plaintext: Vec<u8>,
                request_id: [u8; 16],
            },
            Response {
                link_id: LinkId,
                inbound_actions: Vec<LinkAction>,
                plaintext: Vec<u8>,
            },
            Generic {
                link_id: LinkId,
                inbound_actions: Vec<LinkAction>,
                plaintext: Vec<u8>,
                context: u8,
                packet_hash: [u8; 32],
            },
            /// Resource advertisement (link-decrypted).
            ResourceAdv {
                link_id: LinkId,
                inbound_actions: Vec<LinkAction>,
                plaintext: Vec<u8>,
            },
            /// Resource part request (link-decrypted).
            ResourceReq {
                link_id: LinkId,
                inbound_actions: Vec<LinkAction>,
                plaintext: Vec<u8>,
            },
            /// Resource hashmap update (link-decrypted).
            ResourceHmu {
                link_id: LinkId,
                inbound_actions: Vec<LinkAction>,
                plaintext: Vec<u8>,
            },
            /// Resource part data (NOT link-decrypted; parts are pre-encrypted by ResourceSender).
            ResourcePart {
                link_id: LinkId,
                inbound_actions: Vec<LinkAction>,
                raw_data: &'a [u8],
            },
            /// Resource proof (feed to sender).
            ResourcePrf {
                link_id: LinkId,
                inbound_actions: Vec<LinkAction>,
                plaintext: Vec<u8>,
            },
            /// Resource cancel from initiator (link-decrypted).
            ResourceIcl {
                link_id: LinkId,
                inbound_actions: Vec<LinkAction>,
            },
            /// Resource cancel from receiver (link-decrypted).
            ResourceRcl {
                link_id: LinkId,
                inbound_actions: Vec<LinkAction>,
            },
            Error,
        }

        let result = {
            let link = match self.links.get_mut(link_id_bytes) {
                Some(l) => l,
                None => return Vec::new(),
            };

            link.route_interface = Some(receiving_interface);
            if packet.flags.header_type == constants::HEADER_2 {
                if let Some(transport_id) = packet.transport_id {
                    link.route_transport_id = Some(transport_id);
                }
            } else {
                link.route_transport_id = None;
            }

            match packet.context {
                constants::CONTEXT_LRRTT => {
                    match link.engine.handle_lrrtt_with_hops(
                        &packet.data,
                        Some(packet.hops),
                        time::now(),
                    ) {
                        Ok(link_actions) => {
                            let link_id = *link.engine.link_id();
                            LinkDataResult::Lrrtt {
                                link_id,
                                link_actions,
                            }
                        }
                        Err(e) => {
                            log::debug!("LRRTT handling failed: {}", e);
                            LinkDataResult::Error
                        }
                    }
                }
                constants::CONTEXT_LINKIDENTIFY => {
                    match link.engine.handle_identify(&packet.data) {
                        Ok(link_actions) => {
                            let link_id = *link.engine.link_id();
                            link.remote_identity = link.engine.remote_identity().cloned();
                            LinkDataResult::Identify {
                                link_id,
                                link_actions,
                            }
                        }
                        Err(e) => {
                            log::debug!("LINKIDENTIFY failed: {}", e);
                            LinkDataResult::Error
                        }
                    }
                }
                constants::CONTEXT_KEEPALIVE => {
                    let received_at = time::now();
                    let reply = link
                        .engine
                        .should_reply_keepalive(&packet.data, received_at);
                    let inbound_actions = link.engine.record_inbound(received_at);
                    let link_id = *link.engine.link_id();
                    LinkDataResult::Keepalive {
                        link_id,
                        inbound_actions,
                        reply,
                        received_at,
                    }
                }
                constants::CONTEXT_LINKCLOSE => match link.engine.decrypt(&packet.data) {
                    Ok(plaintext) if plaintext.as_slice() == link_id_bytes => {
                        let teardown_actions = link.engine.handle_teardown();
                        let link_id = *link.engine.link_id();
                        LinkDataResult::LinkClose {
                            link_id,
                            teardown_actions,
                        }
                    }
                    _ => LinkDataResult::Error,
                },
                constants::CONTEXT_CHANNEL => match link.engine.decrypt(&packet.data) {
                    Ok(plaintext) => {
                        let inbound_actions = link.engine.record_inbound(time::now());
                        let link_id = *link.engine.link_id();
                        LinkDataResult::Channel {
                            link_id,
                            inbound_actions,
                            plaintext,
                            packet_hash,
                        }
                    }
                    Err(_) => LinkDataResult::Error,
                },
                constants::CONTEXT_REQUEST => match link.engine.decrypt(&packet.data) {
                    Ok(plaintext) => {
                        let inbound_actions = link.engine.record_inbound(time::now());
                        let link_id = *link.engine.link_id();
                        let request_id = packet.get_truncated_hash();
                        LinkDataResult::Request {
                            link_id,
                            inbound_actions,
                            plaintext,
                            request_id,
                        }
                    }
                    Err(_) => LinkDataResult::Error,
                },
                constants::CONTEXT_RESPONSE => match link.engine.decrypt(&packet.data) {
                    Ok(plaintext) => {
                        let inbound_actions = link.engine.record_inbound(time::now());
                        let link_id = *link.engine.link_id();
                        LinkDataResult::Response {
                            link_id,
                            inbound_actions,
                            plaintext,
                        }
                    }
                    Err(_) => LinkDataResult::Error,
                },
                // --- Resource contexts ---
                constants::CONTEXT_RESOURCE_ADV => match link.engine.decrypt(&packet.data) {
                    Ok(plaintext) => {
                        let inbound_actions = link.engine.record_inbound(time::now());
                        let link_id = *link.engine.link_id();
                        LinkDataResult::ResourceAdv {
                            link_id,
                            inbound_actions,
                            plaintext,
                        }
                    }
                    Err(_) => LinkDataResult::Error,
                },
                constants::CONTEXT_RESOURCE_REQ => match link.engine.decrypt(&packet.data) {
                    Ok(plaintext) => {
                        let inbound_actions = link.engine.record_inbound(time::now());
                        let link_id = *link.engine.link_id();
                        LinkDataResult::ResourceReq {
                            link_id,
                            inbound_actions,
                            plaintext,
                        }
                    }
                    Err(_) => LinkDataResult::Error,
                },
                constants::CONTEXT_RESOURCE_HMU => match link.engine.decrypt(&packet.data) {
                    Ok(plaintext) => {
                        let inbound_actions = link.engine.record_inbound(time::now());
                        let link_id = *link.engine.link_id();
                        LinkDataResult::ResourceHmu {
                            link_id,
                            inbound_actions,
                            plaintext,
                        }
                    }
                    Err(_) => LinkDataResult::Error,
                },
                constants::CONTEXT_RESOURCE => {
                    // Resource parts are NOT link-decrypted — they're pre-encrypted by ResourceSender
                    let inbound_actions = link.engine.record_inbound(time::now());
                    let link_id = *link.engine.link_id();
                    LinkDataResult::ResourcePart {
                        link_id,
                        inbound_actions,
                        raw_data: &packet.data,
                    }
                }
                constants::CONTEXT_RESOURCE_PRF => match link.engine.decrypt(&packet.data) {
                    Ok(plaintext) => {
                        let inbound_actions = link.engine.record_inbound(time::now());
                        let link_id = *link.engine.link_id();
                        LinkDataResult::ResourcePrf {
                            link_id,
                            inbound_actions,
                            plaintext,
                        }
                    }
                    Err(_) => LinkDataResult::Error,
                },
                constants::CONTEXT_RESOURCE_ICL => {
                    let _ = link.engine.decrypt(&packet.data); // decrypt to validate
                    let inbound_actions = link.engine.record_inbound(time::now());
                    let link_id = *link.engine.link_id();
                    LinkDataResult::ResourceIcl {
                        link_id,
                        inbound_actions,
                    }
                }
                constants::CONTEXT_RESOURCE_RCL => {
                    let _ = link.engine.decrypt(&packet.data); // decrypt to validate
                    let inbound_actions = link.engine.record_inbound(time::now());
                    let link_id = *link.engine.link_id();
                    LinkDataResult::ResourceRcl {
                        link_id,
                        inbound_actions,
                    }
                }
                _ => match link.engine.decrypt(&packet.data) {
                    Ok(plaintext) => {
                        let inbound_actions = link.engine.record_inbound(time::now());
                        let link_id = *link.engine.link_id();
                        LinkDataResult::Generic {
                            link_id,
                            inbound_actions,
                            plaintext,
                            context: packet.context,
                            packet_hash,
                        }
                    }
                    Err(_) => LinkDataResult::Error,
                },
            }
        }; // mutable borrow of self.links dropped here

        // Second pass: process results using self methods
        let mut actions = Vec::new();
        match result {
            LinkDataResult::Lrrtt {
                link_id,
                link_actions,
            } => {
                actions.extend(self.process_link_actions(&link_id, &link_actions));
                // Initialize channel
                if let Some(link) = self.links.get_mut(&link_id) {
                    if link.engine.state() == LinkState::Active {
                        let rtt = link.engine.rtt().unwrap_or(1.0);
                        link.channel = Some(Channel::new(rtt));
                    }
                }
            }
            LinkDataResult::Identify {
                link_id,
                link_actions,
            } => {
                actions.extend(self.process_link_actions(&link_id, &link_actions));
            }
            LinkDataResult::Keepalive {
                link_id,
                inbound_actions,
                reply,
                received_at,
            } => {
                log::debug!(
                    "Link keepalive received: link={:02x?} reply={reply}",
                    &link_id[..4]
                );
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                if reply {
                    let flags = PacketFlags {
                        header_type: constants::HEADER_1,
                        context_flag: constants::FLAG_UNSET,
                        transport_type: constants::TRANSPORT_BROADCAST,
                        destination_type: constants::DESTINATION_LINK,
                        packet_type: constants::PACKET_TYPE_DATA,
                    };
                    if let Ok((raw, _)) = RawPacket::pack_raw_with_hash(
                        flags,
                        0,
                        &link_id,
                        None,
                        constants::CONTEXT_KEEPALIVE,
                        &[0xfe],
                    ) {
                        actions.push(LinkManagerAction::SendPacket {
                            raw,
                            dest_type: constants::DESTINATION_LINK,
                            attached_interface: None,
                        });
                        if let Some(link) = self.links.get_mut(&link_id) {
                            link.engine.record_outbound(received_at, true);
                        }
                    }
                }
            }
            LinkDataResult::LinkClose {
                link_id,
                teardown_actions,
            } => {
                actions.extend(self.process_link_actions(&link_id, &teardown_actions));
            }
            LinkDataResult::Channel {
                link_id,
                inbound_actions,
                plaintext,
                packet_hash,
            } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                // Feed plaintext to channel
                if let Some(link) = self.links.get_mut(&link_id) {
                    if let Some(ref mut channel) = link.channel {
                        let chan_actions = channel.receive(&plaintext, time::now());
                        link.channel_messages_received += chan_actions
                            .iter()
                            .filter(|action| {
                                matches!(
                                    action,
                                    rns_core::channel::ChannelAction::MessageReceived { .. }
                                )
                            })
                            .count()
                            as u64;
                        // process_channel_actions needs immutable self, so collect first
                        let _ = link;
                        actions.extend(self.process_channel_actions(&link_id, chan_actions, rng));
                    }
                }
                actions.extend(self.build_link_packet_proof(&link_id, &packet_hash));
            }
            LinkDataResult::Request {
                link_id,
                inbound_actions,
                plaintext,
                request_id,
            } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                let size_ok = self
                    .links
                    .get(&link_id)
                    .and_then(|link| link.max_request_size)
                    .is_none_or(|limit| plaintext.len() <= limit);
                if size_ok {
                    actions.extend(self.handle_request(&link_id, &plaintext, request_id, rng));
                } else {
                    log::debug!(
                        "ignored request with excessive size {} bytes on link {:02x?}",
                        plaintext.len(),
                        &link_id[..4]
                    );
                }
            }
            LinkDataResult::Response {
                link_id,
                inbound_actions,
                plaintext,
            } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                // Unpack msgpack response: [Bin(request_id), response_value]
                actions.extend(self.handle_response(&link_id, &plaintext, None, None));
            }
            LinkDataResult::Generic {
                link_id,
                inbound_actions,
                plaintext,
                context,
                packet_hash,
            } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                actions.push(LinkManagerAction::LinkDataReceived {
                    link_id,
                    context,
                    data: plaintext,
                });

                actions.extend(self.build_link_packet_proof(&link_id, &packet_hash));
            }
            LinkDataResult::ResourceAdv {
                link_id,
                inbound_actions,
                plaintext,
            } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                actions.extend(self.handle_resource_adv(&link_id, &plaintext, rng));
            }
            LinkDataResult::ResourceReq {
                link_id,
                inbound_actions,
                plaintext,
            } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                actions.extend(self.handle_resource_req(&link_id, &plaintext, rng));
            }
            LinkDataResult::ResourceHmu {
                link_id,
                inbound_actions,
                plaintext,
            } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                actions.extend(self.handle_resource_hmu(&link_id, &plaintext, rng));
            }
            LinkDataResult::ResourcePart {
                link_id,
                inbound_actions,
                raw_data,
            } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                actions.extend(self.handle_resource_part(&link_id, raw_data, rng));
            }
            LinkDataResult::ResourcePrf {
                link_id,
                inbound_actions,
                plaintext,
            } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                actions.extend(self.handle_resource_prf(&link_id, &plaintext, rng));
            }
            LinkDataResult::ResourceIcl {
                link_id,
                inbound_actions,
            } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                actions.extend(self.handle_resource_icl(&link_id));
            }
            LinkDataResult::ResourceRcl {
                link_id,
                inbound_actions,
            } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                actions.extend(self.handle_resource_rcl(&link_id));
            }
            LinkDataResult::Error => {}
        }

        actions
    }

    pub fn send_on_link(
        &self,
        link_id: &LinkId,
        plaintext: &[u8],
        context: u8,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        self.try_send_on_link(link_id, plaintext, context, rng)
            .unwrap_or_default()
    }

    /// Prepare a best-effort direct Link packet and report admission failures.
    pub fn try_send_on_link(
        &self,
        link_id: &LinkId,
        plaintext: &[u8],
        context: u8,
        rng: &mut dyn Rng,
    ) -> Result<Vec<LinkManagerAction>, crate::event::LinkDatagramError> {
        use crate::event::LinkDatagramError;
        let link = match self.links.get(link_id) {
            Some(l) => l,
            None => return Err(LinkDatagramError::LinkNotFound),
        };

        if link.engine.state() != LinkState::Active {
            return Err(LinkDatagramError::LinkNotActive);
        }
        let maximum = link.engine.mdu();
        if plaintext.len() > maximum {
            return Err(LinkDatagramError::PayloadTooLarge {
                maximum,
                actual: plaintext.len(),
            });
        }

        let encrypted = match link.engine.encrypt(plaintext, rng) {
            Ok(e) => e,
            Err(_) => return Err(LinkDatagramError::EncryptionFailed),
        };

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        };

        let mut actions = Vec::new();
        let (raw, _packet_hash) =
            RawPacket::pack_raw_with_hash(flags, 0, link_id, None, context, &encrypted)
                .map_err(|_| LinkDatagramError::PacketEncodingFailed)?;
        actions.push(LinkManagerAction::SendPacket {
            raw,
            dest_type: constants::DESTINATION_LINK,
            attached_interface: None,
        });
        Ok(actions)
    }

    /// Send an identify message on a link (initiator reveals identity to responder).
    pub fn identify(
        &self,
        link_id: &LinkId,
        identity: &rns_crypto::identity::Identity,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let encrypted = match link.engine.build_identify(identity, rng) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        };

        let mut actions = Vec::new();
        if let Ok((raw, _packet_hash)) = RawPacket::pack_raw_with_hash(
            flags,
            0,
            link_id,
            None,
            constants::CONTEXT_LINKIDENTIFY,
            &encrypted,
        ) {
            actions.push(LinkManagerAction::SendPacket {
                raw,
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            });
        }
        actions
    }

    /// Tear down a link.
    pub fn teardown_link(&mut self, link_id: &LinkId) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let previous_state = link.engine.state();
        if previous_state == LinkState::Closed {
            return Vec::new();
        }

        let encrypted_close = if previous_state == LinkState::Pending {
            None
        } else {
            let mut rng = OsRng;
            link.engine.encrypt(link_id, &mut rng).ok()
        };
        let teardown_actions = link.engine.teardown();
        if let Some(ref mut channel) = link.channel {
            channel.shutdown();
        }

        let mut actions = self.process_link_actions(link_id, &teardown_actions);

        // Pending links have not established link encryption and are closed
        // locally without transmitting LINKCLOSE.
        if previous_state == LinkState::Pending {
            return actions;
        }

        // Send LINKCLOSE packet
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        if let Some(encrypted_close) = encrypted_close {
            if let Ok((raw, _packet_hash)) = RawPacket::pack_raw_with_hash(
                flags,
                0,
                link_id,
                None,
                constants::CONTEXT_LINKCLOSE,
                &encrypted_close,
            ) {
                actions.push(LinkManagerAction::SendPacket {
                    raw,
                    dest_type: constants::DESTINATION_LINK,
                    attached_interface: None,
                });
            }
        }

        actions
    }

    /// Tear down all managed links.
    pub fn teardown_all_links(&mut self) -> Vec<LinkManagerAction> {
        let link_ids: Vec<LinkId> = self.links.keys().copied().collect();
        let mut actions = Vec::new();
        for link_id in link_ids {
            actions.extend(self.teardown_link(&link_id));
        }
        actions
    }

    /// Periodic tick: check keepalive, stale, timeouts for all links.
    pub fn tick(&mut self, rng: &mut dyn Rng) -> Vec<LinkManagerAction> {
        let now = time::now();
        let mut all_actions = Vec::new();

        // Collect link_ids to avoid borrow issues
        let link_ids: Vec<LinkId> = self.links.keys().copied().collect();

        for link_id in &link_ids {
            let link = match self.links.get_mut(link_id) {
                Some(l) => l,
                None => continue,
            };

            // Tick the engine
            let tick_actions = link.engine.tick(now);
            all_actions.extend(self.process_link_actions(link_id, &tick_actions));

            // Check if keepalive is needed
            let link = match self.links.get_mut(link_id) {
                Some(l) => l,
                None => continue,
            };
            if link.engine.needs_keepalive(now) {
                log::debug!("Link keepalive probe queued: link={:02x?}", &link_id[..4]);
                // Only initiators reach this branch. Send the upstream 0xff
                // probe; responders conditionally return 0xfe on receipt.
                let flags = PacketFlags {
                    header_type: constants::HEADER_1,
                    context_flag: constants::FLAG_UNSET,
                    transport_type: constants::TRANSPORT_BROADCAST,
                    destination_type: constants::DESTINATION_LINK,
                    packet_type: constants::PACKET_TYPE_DATA,
                };
                if let Ok((raw, _packet_hash)) = RawPacket::pack_raw_with_hash(
                    flags,
                    0,
                    link_id,
                    None,
                    constants::CONTEXT_KEEPALIVE,
                    &[0xff],
                ) {
                    all_actions.push(LinkManagerAction::SendPacket {
                        raw,
                        dest_type: constants::DESTINATION_LINK,
                        attached_interface: None,
                    });
                    link.engine.record_outbound(now, true);
                }
            }

            if let Some(channel) = link.channel.as_mut() {
                let chan_actions = channel.tick(now);
                let _ = channel;
                let _ = link;
                all_actions.extend(self.process_channel_actions(link_id, chan_actions, rng));
            }
        }

        // Tick resource senders and receivers
        for link_id in &link_ids {
            let link = match self.links.get_mut(link_id) {
                Some(l) => l,
                None => continue,
            };

            // Tick outgoing resources (senders)
            let mut sender_actions = Vec::new();
            for sender in &mut link.outgoing_resources {
                sender_actions.extend(sender.tick(now));
            }

            // Tick incoming resources (receivers)
            let mut receiver_actions = Vec::new();
            for receiver in &mut link.incoming_resources {
                let decrypt_fn = |ciphertext: &[u8]| -> Result<Vec<u8>, ()> {
                    link.engine.decrypt(ciphertext).map_err(|_| ())
                };
                receiver_actions.extend(receiver.tick(now, &decrypt_fn, &Bzip2Compressor));
            }

            let failed_request_ids: Vec<[u8; 16]> = link
                .outgoing_resources
                .iter()
                .filter(|sender| {
                    sender.flags.is_request
                        && sender.status >= rns_core::resource::ResourceStatus::Failed
                })
                .filter_map(|sender| Self::response_request_id(&sender.request_id))
                .collect();
            for request_id in failed_request_ids {
                link.pending_requests.remove(&request_id);
            }
            link.pending_requests
                .retain(|_, request| request.deadline.is_none_or(|expires_at| now <= expires_at));

            // Clean up completed/failed resources
            link.outgoing_resources
                .retain(|s| s.status < rns_core::resource::ResourceStatus::Complete);
            link.incoming_resources
                .retain(|r| r.status < rns_core::resource::ResourceStatus::Assembling);
            let active_split_hashes: Vec<[u8; 32]> = link
                .outgoing_resources
                .iter()
                .filter(|s| s.flags.split)
                .map(|s| s.original_hash)
                .collect();
            link.outgoing_splits.retain(|original_hash, split| {
                split.completed_segments < split.total_segments
                    && active_split_hashes.contains(original_hash)
            });

            let _ = link;
            all_actions.extend(self.process_resource_actions(link_id, sender_actions, rng));
            all_actions.extend(self.process_resource_actions(link_id, receiver_actions, rng));
        }

        // Clean up closed links
        let closed: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(_, l)| l.engine.state() == LinkState::Closed)
            .map(|(id, _)| *id)
            .collect();
        for id in closed {
            self.links.remove(&id);
            all_actions.push(LinkManagerAction::DeregisterLinkDest { link_id: id });
        }

        all_actions
    }

    /// Check if a destination hash is a known link_id managed by this manager.
    pub fn is_link_destination(&self, dest_hash: &[u8; 16]) -> bool {
        self.links.contains_key(dest_hash) || self.link_destinations.contains_key(dest_hash)
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

    /// Get the number of active resource transfers across all links.
    pub fn resource_transfer_count(&self) -> usize {
        self.links
            .values()
            .map(|managed| {
                managed
                    .incoming_resources
                    .iter()
                    .filter(|resource| !resource.flags.split)
                    .count()
                    + managed.incoming_splits.len()
                    + managed
                        .outgoing_resources
                        .iter()
                        .filter(|resource| !resource.flags.split)
                        .count()
                    + managed.outgoing_splits.len()
            })
            .sum()
    }

    /// Cancel all active resource transfers and return the generated actions.
    pub fn cancel_all_resources(&mut self, rng: &mut dyn Rng) -> Vec<LinkManagerAction> {
        let link_ids: Vec<LinkId> = self.links.keys().copied().collect();
        let mut all_actions = Vec::new();

        for link_id in &link_ids {
            let link = match self.links.get_mut(link_id) {
                Some(l) => l,
                None => continue,
            };

            let mut sender_actions = Vec::new();
            for sender in &mut link.outgoing_resources {
                sender_actions.extend(sender.cancel());
            }

            let mut receiver_actions = Vec::new();
            for receiver in &mut link.incoming_resources {
                receiver_actions.extend(receiver.cancel());
            }

            link.outgoing_resources
                .retain(|s| s.status < rns_core::resource::ResourceStatus::Complete);
            link.incoming_resources
                .retain(|r| r.status < rns_core::resource::ResourceStatus::Assembling);
            link.outgoing_splits.clear();
            all_actions.extend(link.outgoing_streams.drain().map(|(_, stream)| {
                LinkManagerAction::ResourceStreamFailed {
                    link_id: *link_id,
                    transfer_id: stream.transfer_id,
                    error: ResourceTransferError::Cancelled,
                }
            }));
            link.incoming_splits.clear();

            let _ = link;
            all_actions.extend(self.process_resource_actions(link_id, sender_actions, rng));
            all_actions.extend(self.process_resource_actions(link_id, receiver_actions, rng));
        }

        all_actions
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
                    channel_proofs_sent: managed.channel_proofs_sent,
                    channel_proofs_received: managed.channel_proofs_received,
                }
            })
            .collect()
    }

    /// Account a packed outbound action at the single driver dispatch point.
    /// LINKREQUEST is accounted when its engine is created since its wire
    /// destination is not the resulting link ID.
    pub fn record_outbound_packet(&mut self, packet: &RawPacket) {
        if packet.flags.destination_type == constants::DESTINATION_LINK {
            if let Some(link) = self.links.get_mut(&packet.destination_hash) {
                link.engine.record_outbound_traffic(packet.data.len());
            }
        }
    }

    /// Get information about all active resource transfers.
    pub fn resource_entries(&self) -> Vec<crate::event::ResourceInfoEntry> {
        let mut entries = Vec::new();
        for (link_id, managed) in &self.links {
            let resource_sdu = Self::resource_sdu_for_link(managed);
            for split in managed.incoming_splits.values() {
                let (received, total) = Self::incoming_split_progress(split, resource_sdu);
                entries.push(crate::event::ResourceInfoEntry {
                    link_id: *link_id,
                    direction: "incoming".to_string(),
                    total_parts: total,
                    transferred_parts: received,
                    complete: received >= total && total > 0,
                });
            }
            for recv in &managed.incoming_resources {
                if recv.flags.split {
                    continue;
                }
                let (received, total) = recv.progress();
                entries.push(crate::event::ResourceInfoEntry {
                    link_id: *link_id,
                    direction: "incoming".to_string(),
                    total_parts: total,
                    transferred_parts: received,
                    complete: received >= total && total > 0,
                });
            }
            for split in managed.outgoing_splits.values() {
                let (sent, total) = Self::outgoing_split_progress(split, resource_sdu);
                entries.push(crate::event::ResourceInfoEntry {
                    link_id: *link_id,
                    direction: "outgoing".to_string(),
                    total_parts: total,
                    transferred_parts: sent,
                    complete: sent >= total && total > 0,
                });
            }
            for send in &managed.outgoing_resources {
                if send.flags.split {
                    continue;
                }
                let total = send.total_parts();
                let sent = send.sent_parts;
                entries.push(crate::event::ResourceInfoEntry {
                    link_id: *link_id,
                    direction: "outgoing".to_string(),
                    total_parts: total,
                    transferred_parts: sent,
                    complete: sent >= total && total > 0,
                });
            }
        }
        entries
    }

    /// Convert LinkActions to LinkManagerActions.
    fn process_link_actions(
        &self,
        link_id: &LinkId,
        actions: &[LinkAction],
    ) -> Vec<LinkManagerAction> {
        let mut result = Vec::new();
        for action in actions {
            match action {
                LinkAction::StateChanged {
                    new_state, reason, ..
                } => {
                    log::debug!(
                        "Link state changed: link={:02x?} state={new_state:?} reason={reason:?}",
                        &link_id[..4]
                    );
                    if new_state == &LinkState::Closed {
                        result.push(LinkManagerAction::LinkClosed {
                            link_id: *link_id,
                            reason: *reason,
                        });
                    }
                }
                LinkAction::LinkEstablished {
                    rtt, is_initiator, ..
                } => {
                    let keepalive = self
                        .links
                        .get(link_id)
                        .map(|link| link.engine.keepalive_interval())
                        .unwrap_or_default();
                    log::debug!(
                        "Link timers established: link={:02x?} rtt={rtt:.6} keepalive={keepalive:.6} stale={:.6} initiator={is_initiator}",
                        &link_id[..4],
                        keepalive * rns_core::constants::LINK_STALE_FACTOR
                    );
                    let dest_hash = self
                        .links
                        .get(link_id)
                        .map(|l| l.dest_hash)
                        .unwrap_or([0u8; 16]);
                    let hops = self
                        .links
                        .get(link_id)
                        .map(|link| link.engine.expected_hops())
                        .unwrap_or(rns_core::constants::PATHFINDER_M);
                    let rebalanced_at = self
                        .links
                        .get(link_id)
                        .and_then(|link| link.engine.rebalanced_at());
                    result.push(LinkManagerAction::LinkEstablished {
                        link_id: *link_id,
                        dest_hash,
                        hops,
                        rebalanced_at,
                        rtt: *rtt,
                        is_initiator: *is_initiator,
                    });
                }
                LinkAction::RemoteIdentified {
                    identity_hash,
                    public_key,
                    ..
                } => {
                    result.push(LinkManagerAction::RemoteIdentified {
                        link_id: *link_id,
                        identity_hash: *identity_hash,
                        public_key: *public_key,
                    });
                }
                LinkAction::DataReceived { .. } => {
                    // Data delivery is handled at a higher level
                }
            }
        }
        result
    }
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
