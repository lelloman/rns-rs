//! Link manager: wires rns-core LinkEngine + Channel + Resource into the driver.
//!
//! Manages multiple concurrent links, link destination registration,
//! request/response handling, resource transfers, and full lifecycle
//! (handshake → active → teardown).
//!
//! Python reference: Link.py, RequestReceipt.py, Resource.py

use std::collections::HashMap;

use rns_core::buffer::types::NoopCompressor;
use rns_core::channel::Channel;
use rns_core::constants;
use rns_core::link::types::{LinkId, LinkState, TeardownReason};
use rns_core::link::{LinkAction, LinkEngine, LinkMode};
use rns_core::packet::{PacketFlags, RawPacket};
use rns_core::resource::{ResourceAction, ResourceReceiver, ResourceSender};
use rns_crypto::ed25519::Ed25519PrivateKey;
use rns_crypto::Rng;

use crate::time;

/// Resource acceptance strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceStrategy {
    /// Reject all incoming resources.
    AcceptNone,
    /// Accept all incoming resources automatically.
    AcceptAll,
    /// Query the application callback for each resource.
    AcceptApp,
}

impl Default for ResourceStrategy {
    fn default() -> Self {
        ResourceStrategy::AcceptNone
    }
}

/// A managed link wrapping LinkEngine + optional Channel + resources.
struct ManagedLink {
    engine: LinkEngine,
    channel: Option<Channel>,
    /// Destination hash this link belongs to.
    dest_hash: [u8; 16],
    /// Remote identity (hash, public_key) once identified.
    remote_identity: Option<([u8; 16], [u8; 64])>,
    /// Destination's Ed25519 signing public key (for initiator to verify LRPROOF).
    dest_sig_pub_bytes: Option<[u8; 32]>,
    /// Active incoming resource transfers.
    incoming_resources: Vec<ResourceReceiver>,
    /// Active outgoing resource transfers.
    outgoing_resources: Vec<ResourceSender>,
    /// Resource acceptance strategy.
    resource_strategy: ResourceStrategy,
}

/// A registered link destination that can accept incoming LINKREQUEST.
struct LinkDestination {
    sig_prv: Ed25519PrivateKey,
    sig_pub_bytes: [u8; 32],
}

/// A registered request handler for a path.
struct RequestHandlerEntry {
    /// The path this handler serves (e.g. "/status").
    path: String,
    /// The truncated hash of the path (first 16 bytes of SHA-256).
    path_hash: [u8; 16],
    /// Access control: None means allow all, Some(list) means allow only listed identities.
    allowed_list: Option<Vec<[u8; 16]>>,
    /// Handler function: (link_id, path, request_id, data, remote_identity) -> Option<response_data>.
    handler: Box<dyn Fn(LinkId, &str, &[u8], Option<&([u8; 16], [u8; 64])>) -> Option<Vec<u8>> + Send>,
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
    RegisterLinkDest {
        link_id: LinkId,
    },
    /// Deregister a link_id from transport local destinations.
    DeregisterLinkDest {
        link_id: LinkId,
    },
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
    /// Resource transfer completed (proof validated on sender side).
    ResourceCompleted {
        link_id: LinkId,
    },
    /// Resource transfer failed.
    ResourceFailed {
        link_id: LinkId,
        error: String,
    },
    /// Resource transfer progress update.
    ResourceProgress {
        link_id: LinkId,
        received: usize,
        total: usize,
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
    },
}

/// Manages multiple links, link destinations, and request/response.
pub struct LinkManager {
    links: HashMap<LinkId, ManagedLink>,
    link_destinations: HashMap<[u8; 16], LinkDestination>,
    request_handlers: Vec<RequestHandlerEntry>,
    /// Path hashes that should be handled externally (by the driver) rather than
    /// by registered handler closures. Used for management destinations.
    management_paths: Vec<[u8; 16]>,
}

impl LinkManager {
    /// Create a new empty link manager.
    pub fn new() -> Self {
        LinkManager {
            links: HashMap::new(),
            link_destinations: HashMap::new(),
            request_handlers: Vec::new(),
            management_paths: Vec::new(),
        }
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
        self.links.get(link_id)
            .and_then(|link| link.engine.derived_key().map(|dk| dk.to_vec()))
    }

    /// Register a destination that can accept incoming links.
    pub fn register_link_destination(
        &mut self,
        dest_hash: [u8; 16],
        sig_prv: Ed25519PrivateKey,
        sig_pub_bytes: [u8; 32],
    ) {
        self.link_destinations.insert(dest_hash, LinkDestination {
            sig_prv,
            sig_pub_bytes,
        });
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
        F: Fn(LinkId, &str, &[u8], Option<&([u8; 16], [u8; 64])>) -> Option<Vec<u8>> + Send + 'static,
    {
        let path_hash = compute_path_hash(path);
        self.request_handlers.push(RequestHandlerEntry {
            path: path.to_string(),
            path_hash,
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
        let (mut engine, request_data) =
            LinkEngine::new_initiator(dest_hash, hops, mode, Some(mtu), time::now(), rng);

        // Build the LINKREQUEST packet to compute link_id
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_LINKREQUEST,
        };

        let packet = match RawPacket::pack(
            flags, 0, dest_hash, None, constants::CONTEXT_NONE, &request_data,
        ) {
            Ok(p) => p,
            Err(_) => {
                // Should not happen with valid data
                return ([0u8; 16], Vec::new());
            }
        };

        engine.set_link_id_from_hashable(&packet.get_hashable_part(), request_data.len());
        let link_id = *engine.link_id();

        let managed = ManagedLink {
            engine,
            channel: None,
            dest_hash: *dest_hash,
            remote_identity: None,
            dest_sig_pub_bytes: Some(*dest_sig_pub_bytes),
            incoming_resources: Vec::new(),
            outgoing_resources: Vec::new(),
            resource_strategy: ResourceStrategy::default(),
        };
        self.links.insert(link_id, managed);

        let mut actions = Vec::new();
        // Register the link_id as a local destination so we can receive LRPROOF
        actions.push(LinkManagerAction::RegisterLinkDest { link_id });
        // Send the LINKREQUEST packet
        actions.push(LinkManagerAction::SendPacket {
            raw: packet.raw,
            dest_type: constants::DESTINATION_LINK,
            attached_interface: None,
        });

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
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let packet = match RawPacket::unpack(raw) {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };

        match packet.flags.packet_type {
            constants::PACKET_TYPE_LINKREQUEST => {
                self.handle_linkrequest(&dest_hash, &packet, rng)
            }
            constants::PACKET_TYPE_PROOF if packet.context == constants::CONTEXT_LRPROOF => {
                // LRPROOF: dest_hash is the link_id
                self.handle_lrproof(&dest_hash, &packet, rng)
            }
            constants::PACKET_TYPE_DATA => {
                self.handle_link_data(&dest_hash, &packet, packet_hash, rng)
            }
            _ => Vec::new(),
        }
    }

    /// Handle an incoming LINKREQUEST packet.
    fn handle_linkrequest(
        &mut self,
        dest_hash: &[u8; 16],
        packet: &RawPacket,
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
                return Vec::new();
            }
        };

        let link_id = *engine.link_id();

        let managed = ManagedLink {
            engine,
            channel: None,
            dest_hash: *dest_hash,
            remote_identity: None,
            dest_sig_pub_bytes: None,
            incoming_resources: Vec::new(),
            outgoing_resources: Vec::new(),
            resource_strategy: ResourceStrategy::default(),
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

        if let Ok(pkt) = RawPacket::pack(
            flags, 0, &link_id, None, constants::CONTEXT_LRPROOF, &lrproof_data,
        ) {
            actions.push(LinkManagerAction::SendPacket {
                raw: pkt.raw,
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            });
        }

        actions
    }

    /// Handle an incoming LRPROOF packet (initiator side).
    fn handle_lrproof(
        &mut self,
        link_id_bytes: &[u8; 16],
        packet: &RawPacket,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id_bytes) {
            Some(l) => l,
            None => return Vec::new(),
        };

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
        let (lrrtt_encrypted, link_actions) = match link.engine.handle_lrproof(
            &packet.data,
            &dest_sig_pub_bytes,
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

        if let Ok(pkt) = RawPacket::pack(
            flags, 0, &link_id, None, constants::CONTEXT_LRRTT, &lrrtt_encrypted,
        ) {
            actions.push(LinkManagerAction::SendPacket {
                raw: pkt.raw,
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
        _packet_hash: [u8; 32],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        // First pass: perform engine operations, collect results
        enum LinkDataResult {
            Lrrtt { link_id: LinkId, link_actions: Vec<LinkAction> },
            Identify { link_id: LinkId, link_actions: Vec<LinkAction> },
            Keepalive { link_id: LinkId, inbound_actions: Vec<LinkAction> },
            LinkClose { link_id: LinkId, teardown_actions: Vec<LinkAction> },
            Channel { link_id: LinkId, inbound_actions: Vec<LinkAction>, plaintext: Vec<u8> },
            Request { link_id: LinkId, inbound_actions: Vec<LinkAction>, plaintext: Vec<u8> },
            Response { link_id: LinkId, inbound_actions: Vec<LinkAction>, plaintext: Vec<u8> },
            Generic { link_id: LinkId, inbound_actions: Vec<LinkAction>, plaintext: Vec<u8>, context: u8 },
            /// Resource advertisement (link-decrypted).
            ResourceAdv { link_id: LinkId, inbound_actions: Vec<LinkAction>, plaintext: Vec<u8> },
            /// Resource part request (link-decrypted).
            ResourceReq { link_id: LinkId, inbound_actions: Vec<LinkAction>, plaintext: Vec<u8> },
            /// Resource hashmap update (link-decrypted).
            ResourceHmu { link_id: LinkId, inbound_actions: Vec<LinkAction>, plaintext: Vec<u8> },
            /// Resource part data (NOT link-decrypted; parts are pre-encrypted by ResourceSender).
            ResourcePart { link_id: LinkId, inbound_actions: Vec<LinkAction>, raw_data: Vec<u8> },
            /// Resource proof (feed to sender).
            ResourcePrf { link_id: LinkId, inbound_actions: Vec<LinkAction>, plaintext: Vec<u8> },
            /// Resource cancel from initiator (link-decrypted).
            ResourceIcl { link_id: LinkId, inbound_actions: Vec<LinkAction> },
            /// Resource cancel from receiver (link-decrypted).
            ResourceRcl { link_id: LinkId, inbound_actions: Vec<LinkAction> },
            Error,
        }

        let result = {
            let link = match self.links.get_mut(link_id_bytes) {
                Some(l) => l,
                None => return Vec::new(),
            };

            match packet.context {
                constants::CONTEXT_LRRTT => {
                    match link.engine.handle_lrrtt(&packet.data, time::now()) {
                        Ok(link_actions) => {
                            let link_id = *link.engine.link_id();
                            LinkDataResult::Lrrtt { link_id, link_actions }
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
                            LinkDataResult::Identify { link_id, link_actions }
                        }
                        Err(e) => {
                            log::debug!("LINKIDENTIFY failed: {}", e);
                            LinkDataResult::Error
                        }
                    }
                }
                constants::CONTEXT_KEEPALIVE => {
                    let inbound_actions = link.engine.record_inbound(time::now());
                    let link_id = *link.engine.link_id();
                    LinkDataResult::Keepalive { link_id, inbound_actions }
                }
                constants::CONTEXT_LINKCLOSE => {
                    let teardown_actions = link.engine.handle_teardown();
                    let link_id = *link.engine.link_id();
                    LinkDataResult::LinkClose { link_id, teardown_actions }
                }
                constants::CONTEXT_CHANNEL => {
                    match link.engine.decrypt(&packet.data) {
                        Ok(plaintext) => {
                            let inbound_actions = link.engine.record_inbound(time::now());
                            let link_id = *link.engine.link_id();
                            LinkDataResult::Channel { link_id, inbound_actions, plaintext }
                        }
                        Err(_) => LinkDataResult::Error,
                    }
                }
                constants::CONTEXT_REQUEST => {
                    match link.engine.decrypt(&packet.data) {
                        Ok(plaintext) => {
                            let inbound_actions = link.engine.record_inbound(time::now());
                            let link_id = *link.engine.link_id();
                            LinkDataResult::Request { link_id, inbound_actions, plaintext }
                        }
                        Err(_) => LinkDataResult::Error,
                    }
                }
                constants::CONTEXT_RESPONSE => {
                    match link.engine.decrypt(&packet.data) {
                        Ok(plaintext) => {
                            let inbound_actions = link.engine.record_inbound(time::now());
                            let link_id = *link.engine.link_id();
                            LinkDataResult::Response { link_id, inbound_actions, plaintext }
                        }
                        Err(_) => LinkDataResult::Error,
                    }
                }
                // --- Resource contexts ---
                constants::CONTEXT_RESOURCE_ADV => {
                    match link.engine.decrypt(&packet.data) {
                        Ok(plaintext) => {
                            let inbound_actions = link.engine.record_inbound(time::now());
                            let link_id = *link.engine.link_id();
                            LinkDataResult::ResourceAdv { link_id, inbound_actions, plaintext }
                        }
                        Err(_) => LinkDataResult::Error,
                    }
                }
                constants::CONTEXT_RESOURCE_REQ => {
                    match link.engine.decrypt(&packet.data) {
                        Ok(plaintext) => {
                            let inbound_actions = link.engine.record_inbound(time::now());
                            let link_id = *link.engine.link_id();
                            LinkDataResult::ResourceReq { link_id, inbound_actions, plaintext }
                        }
                        Err(_) => LinkDataResult::Error,
                    }
                }
                constants::CONTEXT_RESOURCE_HMU => {
                    match link.engine.decrypt(&packet.data) {
                        Ok(plaintext) => {
                            let inbound_actions = link.engine.record_inbound(time::now());
                            let link_id = *link.engine.link_id();
                            LinkDataResult::ResourceHmu { link_id, inbound_actions, plaintext }
                        }
                        Err(_) => LinkDataResult::Error,
                    }
                }
                constants::CONTEXT_RESOURCE => {
                    // Resource parts are NOT link-decrypted — they're pre-encrypted by ResourceSender
                    let inbound_actions = link.engine.record_inbound(time::now());
                    let link_id = *link.engine.link_id();
                    LinkDataResult::ResourcePart { link_id, inbound_actions, raw_data: packet.data.clone() }
                }
                constants::CONTEXT_RESOURCE_PRF => {
                    match link.engine.decrypt(&packet.data) {
                        Ok(plaintext) => {
                            let inbound_actions = link.engine.record_inbound(time::now());
                            let link_id = *link.engine.link_id();
                            LinkDataResult::ResourcePrf { link_id, inbound_actions, plaintext }
                        }
                        Err(_) => LinkDataResult::Error,
                    }
                }
                constants::CONTEXT_RESOURCE_ICL => {
                    let _ = link.engine.decrypt(&packet.data); // decrypt to validate
                    let inbound_actions = link.engine.record_inbound(time::now());
                    let link_id = *link.engine.link_id();
                    LinkDataResult::ResourceIcl { link_id, inbound_actions }
                }
                constants::CONTEXT_RESOURCE_RCL => {
                    let _ = link.engine.decrypt(&packet.data); // decrypt to validate
                    let inbound_actions = link.engine.record_inbound(time::now());
                    let link_id = *link.engine.link_id();
                    LinkDataResult::ResourceRcl { link_id, inbound_actions }
                }
                _ => {
                    match link.engine.decrypt(&packet.data) {
                        Ok(plaintext) => {
                            let inbound_actions = link.engine.record_inbound(time::now());
                            let link_id = *link.engine.link_id();
                            LinkDataResult::Generic { link_id, inbound_actions, plaintext, context: packet.context }
                        }
                        Err(_) => LinkDataResult::Error,
                    }
                }
            }
        }; // mutable borrow of self.links dropped here

        // Second pass: process results using self methods
        let mut actions = Vec::new();
        match result {
            LinkDataResult::Lrrtt { link_id, link_actions } => {
                actions.extend(self.process_link_actions(&link_id, &link_actions));
                // Initialize channel
                if let Some(link) = self.links.get_mut(&link_id) {
                    if link.engine.state() == LinkState::Active {
                        let rtt = link.engine.rtt().unwrap_or(1.0);
                        link.channel = Some(Channel::new(rtt));
                    }
                }
            }
            LinkDataResult::Identify { link_id, link_actions } => {
                actions.extend(self.process_link_actions(&link_id, &link_actions));
            }
            LinkDataResult::Keepalive { link_id, inbound_actions } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                // Reply with a keepalive so the other side's last_inbound is updated.
                // This handles asymmetric keepalive intervals (different RTTs per side).
                if let Some(link) = self.links.get_mut(&link_id) {
                    let now = time::now();
                    let flags = PacketFlags {
                        header_type: constants::HEADER_1,
                        context_flag: constants::FLAG_UNSET,
                        transport_type: constants::TRANSPORT_BROADCAST,
                        destination_type: constants::DESTINATION_LINK,
                        packet_type: constants::PACKET_TYPE_DATA,
                    };
                    if let Ok(pkt) = RawPacket::pack(
                        flags, 0, &link_id, None, constants::CONTEXT_KEEPALIVE, &[],
                    ) {
                        actions.push(LinkManagerAction::SendPacket {
                            raw: pkt.raw,
                            dest_type: constants::DESTINATION_LINK,
                            attached_interface: None,
                        });
                        link.engine.record_outbound(now, true);
                    }
                }
            }
            LinkDataResult::LinkClose { link_id, teardown_actions } => {
                actions.extend(self.process_link_actions(&link_id, &teardown_actions));
            }
            LinkDataResult::Channel { link_id, inbound_actions, plaintext } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                // Feed plaintext to channel
                if let Some(link) = self.links.get_mut(&link_id) {
                    if let Some(ref mut channel) = link.channel {
                        let chan_actions = channel.receive(&plaintext, time::now());
                        // process_channel_actions needs immutable self, so collect first
                        let _ = link;
                        actions.extend(self.process_channel_actions(&link_id, chan_actions, rng));
                    }
                }
            }
            LinkDataResult::Request { link_id, inbound_actions, plaintext } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                actions.extend(self.handle_request(&link_id, &plaintext, rng));
            }
            LinkDataResult::Response { link_id, inbound_actions, plaintext } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                // Unpack msgpack response: [Bin(request_id), response_value]
                actions.extend(self.handle_response(&link_id, &plaintext));
            }
            LinkDataResult::Generic { link_id, inbound_actions, plaintext, context } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                actions.push(LinkManagerAction::LinkDataReceived {
                    link_id,
                    context,
                    data: plaintext,
                });
            }
            LinkDataResult::ResourceAdv { link_id, inbound_actions, plaintext } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                actions.extend(self.handle_resource_adv(&link_id, &plaintext, rng));
            }
            LinkDataResult::ResourceReq { link_id, inbound_actions, plaintext } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                actions.extend(self.handle_resource_req(&link_id, &plaintext, rng));
            }
            LinkDataResult::ResourceHmu { link_id, inbound_actions, plaintext } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                actions.extend(self.handle_resource_hmu(&link_id, &plaintext, rng));
            }
            LinkDataResult::ResourcePart { link_id, inbound_actions, raw_data } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                actions.extend(self.handle_resource_part(&link_id, &raw_data, rng));
            }
            LinkDataResult::ResourcePrf { link_id, inbound_actions, plaintext } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                actions.extend(self.handle_resource_prf(&link_id, &plaintext));
            }
            LinkDataResult::ResourceIcl { link_id, inbound_actions } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                actions.extend(self.handle_resource_icl(&link_id));
            }
            LinkDataResult::ResourceRcl { link_id, inbound_actions } => {
                actions.extend(self.process_link_actions(&link_id, &inbound_actions));
                actions.extend(self.handle_resource_rcl(&link_id));
            }
            LinkDataResult::Error => {}
        }

        actions
    }

    /// Handle a request on a link.
    fn handle_request(
        &mut self,
        link_id: &LinkId,
        plaintext: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        use rns_core::msgpack::{self, Value};

        // Python-compatible format: msgpack([timestamp, Bin(path_hash), data_value])
        let arr = match msgpack::unpack_exact(plaintext) {
            Ok(Value::Array(arr)) if arr.len() >= 3 => arr,
            _ => return Vec::new(),
        };

        let path_hash_bytes = match &arr[1] {
            Value::Bin(b) if b.len() == 16 => b,
            _ => return Vec::new(),
        };
        let mut path_hash = [0u8; 16];
        path_hash.copy_from_slice(path_hash_bytes);

        // Compute request_id = truncated_hash(packed_request_bytes)
        let request_id = rns_core::hash::truncated_hash(plaintext);

        // Re-encode the data element for the handler
        let request_data = msgpack::pack(&arr[2]);

        // Check if this is a management path (handled by the driver)
        if self.management_paths.contains(&path_hash) {
            let remote_identity = self.links.get(link_id)
                .and_then(|l| l.remote_identity)
                .map(|(h, k)| (h, k));
            return vec![LinkManagerAction::ManagementRequest {
                link_id: *link_id,
                path_hash,
                data: request_data,
                request_id,
                remote_identity,
            }];
        }

        // Look up handler by path_hash
        let handler_idx = self.request_handlers.iter().position(|h| h.path_hash == path_hash);
        let handler_idx = match handler_idx {
            Some(i) => i,
            None => return Vec::new(),
        };

        // Check ACL
        let remote_identity = self.links.get(link_id).and_then(|l| l.remote_identity.as_ref());
        let handler = &self.request_handlers[handler_idx];
        if let Some(ref allowed) = handler.allowed_list {
            match remote_identity {
                Some((identity_hash, _)) => {
                    if !allowed.contains(identity_hash) {
                        log::debug!("Request denied: identity not in allowed list");
                        return Vec::new();
                    }
                }
                None => {
                    log::debug!("Request denied: peer not identified");
                    return Vec::new();
                }
            }
        }

        // Call handler
        let path = handler.path.clone();
        let response = (handler.handler)(*link_id, &path, &request_data, remote_identity);

        let mut actions = Vec::new();
        if let Some(response_data) = response {
            actions.extend(self.build_response_packet(link_id, &request_id, &response_data, rng));
        }

        actions
    }

    /// Build a response packet for a request.
    /// `response_data` is the msgpack-encoded response value.
    fn build_response_packet(
        &self,
        link_id: &LinkId,
        request_id: &[u8; 16],
        response_data: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        use rns_core::msgpack::{self, Value};

        // Python-compatible response: msgpack([Bin(request_id), response_value])
        let response_value = msgpack::unpack_exact(response_data)
            .unwrap_or_else(|_| Value::Bin(response_data.to_vec()));

        let response_array = Value::Array(vec![
            Value::Bin(request_id.to_vec()),
            response_value,
        ]);
        let response_plaintext = msgpack::pack(&response_array);

        let mut actions = Vec::new();
        if let Some(link) = self.links.get(link_id) {
            if let Ok(encrypted) = link.engine.encrypt(&response_plaintext, rng) {
                let flags = PacketFlags {
                    header_type: constants::HEADER_1,
                    context_flag: constants::FLAG_UNSET,
                    transport_type: constants::TRANSPORT_BROADCAST,
                    destination_type: constants::DESTINATION_LINK,
                    packet_type: constants::PACKET_TYPE_DATA,
                };
                if let Ok(pkt) = RawPacket::pack(
                    flags, 0, link_id, None, constants::CONTEXT_RESPONSE, &encrypted,
                ) {
                    actions.push(LinkManagerAction::SendPacket {
                        raw: pkt.raw,
                        dest_type: constants::DESTINATION_LINK,
                        attached_interface: None,
                    });
                }
            }
        }
        actions
    }

    /// Send a management response on a link.
    /// Called by the driver after building the response for a ManagementRequest.
    pub fn send_management_response(
        &self,
        link_id: &LinkId,
        request_id: &[u8; 16],
        response_data: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        self.build_response_packet(link_id, request_id, response_data, rng)
    }

    /// Send a request on a link.
    ///
    /// `data` is the msgpack-encoded request data value (e.g. msgpack([True]) for /status).
    ///
    /// Uses Python-compatible format: plaintext = msgpack([timestamp, path_hash_bytes, data_value]).
    /// Returns actions (the encrypted request packet). The response will arrive
    /// later via handle_local_delivery with CONTEXT_RESPONSE.
    pub fn send_request(
        &self,
        link_id: &LinkId,
        path: &str,
        data: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        use rns_core::msgpack::{self, Value};

        let link = match self.links.get(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        if link.engine.state() != LinkState::Active {
            return Vec::new();
        }

        let path_hash = compute_path_hash(path);

        // Decode data bytes to msgpack Value (or use Bin if can't decode)
        let data_value = msgpack::unpack_exact(data)
            .unwrap_or_else(|_| Value::Bin(data.to_vec()));

        // Python-compatible format: msgpack([timestamp, Bin(path_hash), data_value])
        let request_array = Value::Array(vec![
            Value::Float(time::now()),
            Value::Bin(path_hash.to_vec()),
            data_value,
        ]);
        let plaintext = msgpack::pack(&request_array);

        let encrypted = match link.engine.encrypt(&plaintext, rng) {
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
        if let Ok(pkt) = RawPacket::pack(
            flags, 0, link_id, None, constants::CONTEXT_REQUEST, &encrypted,
        ) {
            actions.push(LinkManagerAction::SendPacket {
                raw: pkt.raw,
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            });
        }
        actions
    }

    /// Send encrypted data on a link with a given context.
    pub fn send_on_link(
        &self,
        link_id: &LinkId,
        plaintext: &[u8],
        context: u8,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        if link.engine.state() != LinkState::Active {
            return Vec::new();
        }

        let encrypted = match link.engine.encrypt(plaintext, rng) {
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
        if let Ok(pkt) = RawPacket::pack(
            flags, 0, link_id, None, context, &encrypted,
        ) {
            actions.push(LinkManagerAction::SendPacket {
                raw: pkt.raw,
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            });
        }
        actions
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
        if let Ok(pkt) = RawPacket::pack(
            flags, 0, link_id, None, constants::CONTEXT_LINKIDENTIFY, &encrypted,
        ) {
            actions.push(LinkManagerAction::SendPacket {
                raw: pkt.raw,
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

        let teardown_actions = link.engine.teardown();
        if let Some(ref mut channel) = link.channel {
            channel.shutdown();
        }

        let mut actions = self.process_link_actions(link_id, &teardown_actions);

        // Send LINKCLOSE packet
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        if let Ok(pkt) = RawPacket::pack(
            flags, 0, link_id, None, constants::CONTEXT_LINKCLOSE, &[],
        ) {
            actions.push(LinkManagerAction::SendPacket {
                raw: pkt.raw,
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            });
        }

        actions
    }

    /// Handle a response on a link.
    fn handle_response(
        &self,
        link_id: &LinkId,
        plaintext: &[u8],
    ) -> Vec<LinkManagerAction> {
        use rns_core::msgpack;

        // Python-compatible response: msgpack([Bin(request_id), response_value])
        let arr = match msgpack::unpack_exact(plaintext) {
            Ok(msgpack::Value::Array(arr)) if arr.len() >= 2 => arr,
            _ => return Vec::new(),
        };

        let request_id_bytes = match &arr[0] {
            msgpack::Value::Bin(b) if b.len() == 16 => b,
            _ => return Vec::new(),
        };
        let mut request_id = [0u8; 16];
        request_id.copy_from_slice(request_id_bytes);

        let response_data = msgpack::pack(&arr[1]);

        vec![LinkManagerAction::ResponseReceived {
            link_id: *link_id,
            request_id,
            data: response_data,
        }]
    }

    /// Handle resource advertisement (CONTEXT_RESOURCE_ADV).
    fn handle_resource_adv(
        &mut self,
        link_id: &LinkId,
        adv_plaintext: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let link_rtt = link.engine.rtt().unwrap_or(1.0);
        let now = time::now();

        let receiver = match ResourceReceiver::from_advertisement(
            adv_plaintext,
            constants::RESOURCE_SDU,
            link_rtt,
            now,
            None,
            None,
        ) {
            Ok(r) => r,
            Err(e) => {
                log::debug!("Resource ADV rejected: {}", e);
                return Vec::new();
            }
        };

        let strategy = link.resource_strategy;
        let resource_hash = receiver.resource_hash.clone();
        let transfer_size = receiver.transfer_size;
        let has_metadata = receiver.has_metadata;

        match strategy {
            ResourceStrategy::AcceptNone => {
                // Reject: send RCL
                let reject_actions = {
                    let mut r = receiver;
                    r.reject()
                };
                self.process_resource_actions(link_id, reject_actions, rng)
            }
            ResourceStrategy::AcceptAll => {
                link.incoming_resources.push(receiver);
                let idx = link.incoming_resources.len() - 1;
                let resource_actions = link.incoming_resources[idx].accept(now);
                let _ = link;
                self.process_resource_actions(link_id, resource_actions, rng)
            }
            ResourceStrategy::AcceptApp => {
                link.incoming_resources.push(receiver);
                // Query application callback
                vec![LinkManagerAction::ResourceAcceptQuery {
                    link_id: *link_id,
                    resource_hash,
                    transfer_size,
                    has_metadata,
                }]
            }
        }
    }

    /// Accept or reject a pending resource (for AcceptApp strategy).
    pub fn accept_resource(
        &mut self,
        link_id: &LinkId,
        resource_hash: &[u8],
        accept: bool,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let now = time::now();
        let idx = link.incoming_resources.iter().position(|r| r.resource_hash == resource_hash);
        let idx = match idx {
            Some(i) => i,
            None => return Vec::new(),
        };

        let resource_actions = if accept {
            link.incoming_resources[idx].accept(now)
        } else {
            link.incoming_resources[idx].reject()
        };

        let _ = link;
        self.process_resource_actions(link_id, resource_actions, rng)
    }

    /// Handle resource request (CONTEXT_RESOURCE_REQ) — feed to sender.
    fn handle_resource_req(
        &mut self,
        link_id: &LinkId,
        plaintext: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let now = time::now();
        let mut all_actions = Vec::new();
        for sender in &mut link.outgoing_resources {
            let resource_actions = sender.handle_request(plaintext, now);
            if !resource_actions.is_empty() {
                all_actions.extend(resource_actions);
                break;
            }
        }

        let _ = link;
        self.process_resource_actions(link_id, all_actions, rng)
    }

    /// Handle resource HMU (CONTEXT_RESOURCE_HMU) — feed to receiver.
    fn handle_resource_hmu(
        &mut self,
        link_id: &LinkId,
        plaintext: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let now = time::now();
        let mut all_actions = Vec::new();
        for receiver in &mut link.incoming_resources {
            let resource_actions = receiver.handle_hashmap_update(plaintext, now);
            if !resource_actions.is_empty() {
                all_actions.extend(resource_actions);
                break;
            }
        }

        let _ = link;
        self.process_resource_actions(link_id, all_actions, rng)
    }

    /// Handle resource part (CONTEXT_RESOURCE) — feed raw to receiver.
    fn handle_resource_part(
        &mut self,
        link_id: &LinkId,
        raw_data: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let now = time::now();
        let mut all_actions = Vec::new();
        let mut assemble_idx = None;

        for (idx, receiver) in link.incoming_resources.iter_mut().enumerate() {
            let resource_actions = receiver.receive_part(raw_data, now);
            if !resource_actions.is_empty() {
                // Check if all parts received (triggers assembly)
                if receiver.received_count == receiver.total_parts {
                    assemble_idx = Some(idx);
                }
                all_actions.extend(resource_actions);
                break;
            }
        }

        // Assemble if all parts received
        if let Some(idx) = assemble_idx {
            let decrypt_fn = |ciphertext: &[u8]| -> Result<Vec<u8>, ()> {
                link.engine.decrypt(ciphertext).map_err(|_| ())
            };
            let assemble_actions = link.incoming_resources[idx].assemble(&decrypt_fn, &NoopCompressor);
            all_actions.extend(assemble_actions);
        }

        let _ = link;
        self.process_resource_actions(link_id, all_actions, rng)
    }

    /// Handle resource proof (CONTEXT_RESOURCE_PRF) — feed to sender.
    fn handle_resource_prf(
        &mut self,
        link_id: &LinkId,
        plaintext: &[u8],
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let now = time::now();
        let mut result_actions = Vec::new();
        for sender in &mut link.outgoing_resources {
            let resource_actions = sender.handle_proof(plaintext, now);
            if !resource_actions.is_empty() {
                result_actions.extend(resource_actions);
                break;
            }
        }

        // Convert to LinkManagerActions
        let mut actions = Vec::new();
        for ra in result_actions {
            match ra {
                ResourceAction::Completed => {
                    actions.push(LinkManagerAction::ResourceCompleted { link_id: *link_id });
                }
                ResourceAction::Failed(e) => {
                    actions.push(LinkManagerAction::ResourceFailed {
                        link_id: *link_id,
                        error: format!("{}", e),
                    });
                }
                _ => {}
            }
        }

        // Clean up completed/failed senders
        link.outgoing_resources.retain(|s| {
            s.status < rns_core::resource::ResourceStatus::Complete
        });

        actions
    }

    /// Handle cancel from initiator (CONTEXT_RESOURCE_ICL).
    fn handle_resource_icl(
        &mut self,
        link_id: &LinkId,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let mut actions = Vec::new();
        for receiver in &mut link.incoming_resources {
            let ra = receiver.handle_cancel();
            for a in ra {
                if let ResourceAction::Failed(ref e) = a {
                    actions.push(LinkManagerAction::ResourceFailed {
                        link_id: *link_id,
                        error: format!("{}", e),
                    });
                }
            }
        }
        link.incoming_resources.retain(|r| {
            r.status < rns_core::resource::ResourceStatus::Complete
        });
        actions
    }

    /// Handle cancel from receiver (CONTEXT_RESOURCE_RCL).
    fn handle_resource_rcl(
        &mut self,
        link_id: &LinkId,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let mut actions = Vec::new();
        for sender in &mut link.outgoing_resources {
            let ra = sender.handle_reject();
            for a in ra {
                if let ResourceAction::Failed(ref e) = a {
                    actions.push(LinkManagerAction::ResourceFailed {
                        link_id: *link_id,
                        error: format!("{}", e),
                    });
                }
            }
        }
        link.outgoing_resources.retain(|s| {
            s.status < rns_core::resource::ResourceStatus::Complete
        });
        actions
    }

    /// Convert ResourceActions to LinkManagerActions.
    fn process_resource_actions(
        &self,
        link_id: &LinkId,
        actions: Vec<ResourceAction>,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let mut result = Vec::new();
        for action in actions {
            match action {
                ResourceAction::SendAdvertisement(data) => {
                    // Link-encrypt and send as CONTEXT_RESOURCE_ADV
                    if let Ok(encrypted) = link.engine.encrypt(&data, rng) {
                        result.extend(self.build_link_packet(
                            link_id, constants::CONTEXT_RESOURCE_ADV, &encrypted,
                        ));
                    }
                }
                ResourceAction::SendPart(data) => {
                    // Parts are NOT link-encrypted — send raw as CONTEXT_RESOURCE
                    result.extend(self.build_link_packet(
                        link_id, constants::CONTEXT_RESOURCE, &data,
                    ));
                }
                ResourceAction::SendRequest(data) => {
                    if let Ok(encrypted) = link.engine.encrypt(&data, rng) {
                        result.extend(self.build_link_packet(
                            link_id, constants::CONTEXT_RESOURCE_REQ, &encrypted,
                        ));
                    }
                }
                ResourceAction::SendHmu(data) => {
                    if let Ok(encrypted) = link.engine.encrypt(&data, rng) {
                        result.extend(self.build_link_packet(
                            link_id, constants::CONTEXT_RESOURCE_HMU, &encrypted,
                        ));
                    }
                }
                ResourceAction::SendProof(data) => {
                    if let Ok(encrypted) = link.engine.encrypt(&data, rng) {
                        result.extend(self.build_link_packet(
                            link_id, constants::CONTEXT_RESOURCE_PRF, &encrypted,
                        ));
                    }
                }
                ResourceAction::SendCancelInitiator(data) => {
                    if let Ok(encrypted) = link.engine.encrypt(&data, rng) {
                        result.extend(self.build_link_packet(
                            link_id, constants::CONTEXT_RESOURCE_ICL, &encrypted,
                        ));
                    }
                }
                ResourceAction::SendCancelReceiver(data) => {
                    if let Ok(encrypted) = link.engine.encrypt(&data, rng) {
                        result.extend(self.build_link_packet(
                            link_id, constants::CONTEXT_RESOURCE_RCL, &encrypted,
                        ));
                    }
                }
                ResourceAction::DataReceived { data, metadata } => {
                    result.push(LinkManagerAction::ResourceReceived {
                        link_id: *link_id,
                        data,
                        metadata,
                    });
                }
                ResourceAction::Completed => {
                    result.push(LinkManagerAction::ResourceCompleted { link_id: *link_id });
                }
                ResourceAction::Failed(e) => {
                    result.push(LinkManagerAction::ResourceFailed {
                        link_id: *link_id,
                        error: format!("{}", e),
                    });
                }
                ResourceAction::ProgressUpdate { received, total } => {
                    result.push(LinkManagerAction::ResourceProgress {
                        link_id: *link_id,
                        received,
                        total,
                    });
                }
            }
        }
        result
    }

    /// Build a link DATA packet with a given context and data.
    fn build_link_packet(
        &self,
        link_id: &LinkId,
        context: u8,
        data: &[u8],
    ) -> Vec<LinkManagerAction> {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let mut actions = Vec::new();
        if let Ok(pkt) = RawPacket::pack(flags, 0, link_id, None, context, data) {
            actions.push(LinkManagerAction::SendPacket {
                raw: pkt.raw,
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            });
        }
        actions
    }

    /// Start sending a resource on a link.
    pub fn send_resource(
        &mut self,
        link_id: &LinkId,
        data: &[u8],
        metadata: Option<&[u8]>,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        if link.engine.state() != LinkState::Active {
            return Vec::new();
        }

        let link_rtt = link.engine.rtt().unwrap_or(1.0);
        let now = time::now();

        // Use RefCell for interior mutability since ResourceSender::new expects &dyn Fn (not FnMut)
        // but link.engine.encrypt needs &mut dyn Rng
        let enc_rng = std::cell::RefCell::new(rns_crypto::OsRng);
        let encrypt_fn = |plaintext: &[u8]| -> Vec<u8> {
            link.engine.encrypt(plaintext, &mut *enc_rng.borrow_mut()).unwrap_or_else(|_| plaintext.to_vec())
        };

        let sender = match ResourceSender::new(
            data,
            metadata,
            constants::RESOURCE_SDU,
            &encrypt_fn,
            &NoopCompressor,
            rng,
            now,
            false, // auto_compress (we use NoopCompressor)
            false, // is_response
            None,  // request_id
            1,     // segment_index
            1,     // total_segments
            None,  // original_hash
            link_rtt,
            6.0,   // traffic_timeout_factor
        ) {
            Ok(s) => s,
            Err(e) => {
                log::debug!("Failed to create ResourceSender: {}", e);
                return Vec::new();
            }
        };

        let mut sender = sender;
        let adv_actions = sender.advertise(now);
        link.outgoing_resources.push(sender);

        let _ = link;
        self.process_resource_actions(link_id, adv_actions, rng)
    }

    /// Set the resource acceptance strategy for a link.
    pub fn set_resource_strategy(&mut self, link_id: &LinkId, strategy: ResourceStrategy) {
        if let Some(link) = self.links.get_mut(link_id) {
            link.resource_strategy = strategy;
        }
    }

    /// Flush the channel TX ring for a link, clearing outstanding messages.
    /// Called after holepunch completion where signaling messages are fire-and-forget.
    pub fn flush_channel_tx(&mut self, link_id: &LinkId) {
        if let Some(link) = self.links.get_mut(link_id) {
            if let Some(ref mut channel) = link.channel {
                channel.flush_tx();
            }
        }
    }

    /// Send a channel message on a link.
    pub fn send_channel_message(
        &mut self,
        link_id: &LinkId,
        msgtype: u16,
        payload: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let channel = match link.channel {
            Some(ref mut ch) => ch,
            None => return Vec::new(),
        };

        let link_mdu = constants::MDU; // Use MDU as approximate link MDU
        let now = time::now();
        let chan_actions = match channel.send(msgtype, payload, now, link_mdu) {
            Ok(a) => a,
            Err(e) => {
                log::debug!("Channel send failed: {:?}", e);
                return Vec::new();
            }
        };

        let _ = link;
        self.process_channel_actions(link_id, chan_actions, rng)
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
                // Send keepalive packet (empty data with CONTEXT_KEEPALIVE)
                let flags = PacketFlags {
                    header_type: constants::HEADER_1,
                    context_flag: constants::FLAG_UNSET,
                    transport_type: constants::TRANSPORT_BROADCAST,
                    destination_type: constants::DESTINATION_LINK,
                    packet_type: constants::PACKET_TYPE_DATA,
                };
                if let Ok(pkt) = RawPacket::pack(
                    flags, 0, link_id, None, constants::CONTEXT_KEEPALIVE, &[],
                ) {
                    all_actions.push(LinkManagerAction::SendPacket {
                        raw: pkt.raw,
                        dest_type: constants::DESTINATION_LINK,
                        attached_interface: None,
                    });
                    link.engine.record_outbound(now, true);
                }
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
                receiver_actions.extend(receiver.tick(now, &decrypt_fn, &NoopCompressor));
            }

            // Clean up completed/failed resources
            link.outgoing_resources.retain(|s| {
                s.status < rns_core::resource::ResourceStatus::Complete
            });
            link.incoming_resources.retain(|r| {
                r.status < rns_core::resource::ResourceStatus::Assembling
            });

            let _ = link;
            all_actions.extend(self.process_resource_actions(link_id, sender_actions, rng));
            all_actions.extend(self.process_resource_actions(link_id, receiver_actions, rng));
        }

        // Clean up closed links
        let closed: Vec<LinkId> = self.links.iter()
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

    /// Get the number of active links.
    pub fn link_count(&self) -> usize {
        self.links.len()
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
                }
            })
            .collect()
    }

    /// Get information about all active resource transfers.
    pub fn resource_entries(&self) -> Vec<crate::event::ResourceInfoEntry> {
        let mut entries = Vec::new();
        for (link_id, managed) in &self.links {
            for recv in &managed.incoming_resources {
                let (received, total) = recv.progress();
                entries.push(crate::event::ResourceInfoEntry {
                    link_id: *link_id,
                    direction: "incoming".to_string(),
                    total_parts: total,
                    transferred_parts: received,
                    complete: received >= total && total > 0,
                });
            }
            for send in &managed.outgoing_resources {
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
    fn process_link_actions(&self, link_id: &LinkId, actions: &[LinkAction]) -> Vec<LinkManagerAction> {
        let mut result = Vec::new();
        for action in actions {
            match action {
                LinkAction::StateChanged { new_state, reason, .. } => {
                    match new_state {
                        LinkState::Closed => {
                            result.push(LinkManagerAction::LinkClosed {
                                link_id: *link_id,
                                reason: *reason,
                            });
                        }
                        _ => {}
                    }
                }
                LinkAction::LinkEstablished { rtt, is_initiator, .. } => {
                    let dest_hash = self.links.get(link_id)
                        .map(|l| l.dest_hash)
                        .unwrap_or([0u8; 16]);
                    result.push(LinkManagerAction::LinkEstablished {
                        link_id: *link_id,
                        dest_hash,
                        rtt: *rtt,
                        is_initiator: *is_initiator,
                    });
                }
                LinkAction::RemoteIdentified { identity_hash, public_key, .. } => {
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

    /// Convert ChannelActions to LinkManagerActions.
    fn process_channel_actions(
        &self,
        link_id: &LinkId,
        actions: Vec<rns_core::channel::ChannelAction>,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let mut result = Vec::new();
        for action in actions {
            match action {
                rns_core::channel::ChannelAction::SendOnLink { raw } => {
                    // Encrypt and send as CHANNEL context
                    if let Some(link) = self.links.get(link_id) {
                        if let Ok(encrypted) = link.engine.encrypt(&raw, rng) {
                            let flags = PacketFlags {
                                header_type: constants::HEADER_1,
                                context_flag: constants::FLAG_UNSET,
                                transport_type: constants::TRANSPORT_BROADCAST,
                                destination_type: constants::DESTINATION_LINK,
                                packet_type: constants::PACKET_TYPE_DATA,
                            };
                            if let Ok(pkt) = RawPacket::pack(
                                flags, 0, link_id, None, constants::CONTEXT_CHANNEL, &encrypted,
                            ) {
                                result.push(LinkManagerAction::SendPacket {
                                    raw: pkt.raw,
                                    dest_type: constants::DESTINATION_LINK,
                                    attached_interface: None,
                                });
                            }
                        }
                    }
                }
                rns_core::channel::ChannelAction::MessageReceived { msgtype, payload, .. } => {
                    result.push(LinkManagerAction::ChannelMessageReceived {
                        link_id: *link_id,
                        msgtype,
                        payload,
                    });
                }
                rns_core::channel::ChannelAction::TeardownLink => {
                    result.push(LinkManagerAction::LinkClosed {
                        link_id: *link_id,
                        reason: Some(TeardownReason::Timeout),
                    });
                }
            }
        }
        result
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
mod tests {
    use super::*;
    use rns_crypto::identity::Identity;
    use rns_crypto::{FixedRng, OsRng};

    fn make_rng(seed: u8) -> FixedRng {
        FixedRng::new(&[seed; 128])
    }

    fn make_dest_keys(rng: &mut dyn Rng) -> (Ed25519PrivateKey, [u8; 32]) {
        let sig_prv = Ed25519PrivateKey::generate(rng);
        let sig_pub_bytes = sig_prv.public_key().public_bytes();
        (sig_prv, sig_pub_bytes)
    }

    #[test]
    fn test_register_link_destination() {
        let mut mgr = LinkManager::new();
        let mut rng = make_rng(0x01);
        let (sig_prv, sig_pub_bytes) = make_dest_keys(&mut rng);
        let dest_hash = [0xDD; 16];

        mgr.register_link_destination(dest_hash, sig_prv, sig_pub_bytes);
        assert!(mgr.is_link_destination(&dest_hash));

        mgr.deregister_link_destination(&dest_hash);
        assert!(!mgr.is_link_destination(&dest_hash));
    }

    #[test]
    fn test_create_link() {
        let mut mgr = LinkManager::new();
        let mut rng = OsRng;
        let dest_hash = [0xDD; 16];

        let sig_pub_bytes = [0xAA; 32]; // dummy sig pub for test
        let (link_id, actions) = mgr.create_link(&dest_hash, &sig_pub_bytes, 1, constants::MTU as u32, &mut rng);
        assert_ne!(link_id, [0u8; 16]);
        // Should have RegisterLinkDest + SendPacket
        assert_eq!(actions.len(), 2);
        assert!(matches!(actions[0], LinkManagerAction::RegisterLinkDest { .. }));
        assert!(matches!(actions[1], LinkManagerAction::SendPacket { .. }));

        // Link should be in Pending state
        assert_eq!(mgr.link_state(&link_id), Some(LinkState::Pending));
    }

    #[test]
    fn test_full_handshake_via_manager() {
        let mut rng = OsRng;
        let dest_hash = [0xDD; 16];

        // Setup responder
        let mut responder_mgr = LinkManager::new();
        let (sig_prv, sig_pub_bytes) = make_dest_keys(&mut rng);
        responder_mgr.register_link_destination(dest_hash, sig_prv, sig_pub_bytes);

        // Setup initiator
        let mut initiator_mgr = LinkManager::new();

        // Step 1: Initiator creates link (needs dest signing pub key for LRPROOF verification)
        let (link_id, init_actions) = initiator_mgr.create_link(&dest_hash, &sig_pub_bytes, 1, constants::MTU as u32, &mut rng);
        assert_eq!(init_actions.len(), 2);

        // Extract the LINKREQUEST packet raw bytes
        let linkrequest_raw = match &init_actions[1] {
            LinkManagerAction::SendPacket { raw, .. } => raw.clone(),
            _ => panic!("Expected SendPacket"),
        };

        // Parse to get packet_hash and dest_hash
        let lr_packet = RawPacket::unpack(&linkrequest_raw).unwrap();

        // Step 2: Responder handles LINKREQUEST
        let resp_actions = responder_mgr.handle_local_delivery(
            lr_packet.destination_hash,
            &linkrequest_raw,
            lr_packet.packet_hash,
            &mut rng,
        );
        // Should have RegisterLinkDest + SendPacket(LRPROOF)
        assert!(resp_actions.len() >= 2);
        assert!(matches!(resp_actions[0], LinkManagerAction::RegisterLinkDest { .. }));

        // Extract LRPROOF packet
        let lrproof_raw = match &resp_actions[1] {
            LinkManagerAction::SendPacket { raw, .. } => raw.clone(),
            _ => panic!("Expected SendPacket for LRPROOF"),
        };

        // Step 3: Initiator handles LRPROOF
        let lrproof_packet = RawPacket::unpack(&lrproof_raw).unwrap();
        let init_actions2 = initiator_mgr.handle_local_delivery(
            lrproof_packet.destination_hash,
            &lrproof_raw,
            lrproof_packet.packet_hash,
            &mut rng,
        );

        // Should have LinkEstablished + SendPacket(LRRTT)
        let has_established = init_actions2.iter().any(|a| matches!(a, LinkManagerAction::LinkEstablished { .. }));
        assert!(has_established, "Initiator should emit LinkEstablished");

        // Extract LRRTT
        let lrrtt_raw = init_actions2.iter().find_map(|a| match a {
            LinkManagerAction::SendPacket { raw, .. } => Some(raw.clone()),
            _ => None,
        }).expect("Should have LRRTT SendPacket");

        // Step 4: Responder handles LRRTT
        let lrrtt_packet = RawPacket::unpack(&lrrtt_raw).unwrap();
        let resp_link_id = lrrtt_packet.destination_hash;
        let resp_actions2 = responder_mgr.handle_local_delivery(
            resp_link_id,
            &lrrtt_raw,
            lrrtt_packet.packet_hash,
            &mut rng,
        );

        let has_established = resp_actions2.iter().any(|a| matches!(a, LinkManagerAction::LinkEstablished { .. }));
        assert!(has_established, "Responder should emit LinkEstablished");

        // Both sides should be Active
        assert_eq!(initiator_mgr.link_state(&link_id), Some(LinkState::Active));
        assert_eq!(responder_mgr.link_state(&link_id), Some(LinkState::Active));

        // Both should have RTT
        assert!(initiator_mgr.link_rtt(&link_id).is_some());
        assert!(responder_mgr.link_rtt(&link_id).is_some());
    }

    #[test]
    fn test_encrypted_data_exchange() {
        let mut rng = OsRng;
        let dest_hash = [0xDD; 16];
        let mut resp_mgr = LinkManager::new();
        let (sig_prv, sig_pub_bytes) = make_dest_keys(&mut rng);
        resp_mgr.register_link_destination(dest_hash, sig_prv, sig_pub_bytes);
        let mut init_mgr = LinkManager::new();

        // Handshake
        let (link_id, init_actions) = init_mgr.create_link(&dest_hash, &sig_pub_bytes, 1, constants::MTU as u32, &mut rng);
        let lr_raw = extract_send_packet(&init_actions);
        let lr_pkt = RawPacket::unpack(&lr_raw).unwrap();
        let resp_actions = resp_mgr.handle_local_delivery(lr_pkt.destination_hash, &lr_raw, lr_pkt.packet_hash, &mut rng);
        let lrproof_raw = extract_send_packet_at(&resp_actions, 1);
        let lrproof_pkt = RawPacket::unpack(&lrproof_raw).unwrap();
        let init_actions2 = init_mgr.handle_local_delivery(lrproof_pkt.destination_hash, &lrproof_raw, lrproof_pkt.packet_hash, &mut rng);
        let lrrtt_raw = extract_any_send_packet(&init_actions2);
        let lrrtt_pkt = RawPacket::unpack(&lrrtt_raw).unwrap();
        resp_mgr.handle_local_delivery(lrrtt_pkt.destination_hash, &lrrtt_raw, lrrtt_pkt.packet_hash, &mut rng);

        // Send data from initiator to responder
        let actions = init_mgr.send_on_link(&link_id, b"hello link!", constants::CONTEXT_NONE, &mut rng);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], LinkManagerAction::SendPacket { .. }));
    }

    #[test]
    fn test_request_response() {
        let mut rng = OsRng;
        let dest_hash = [0xDD; 16];
        let mut resp_mgr = LinkManager::new();
        let (sig_prv, sig_pub_bytes) = make_dest_keys(&mut rng);
        resp_mgr.register_link_destination(dest_hash, sig_prv, sig_pub_bytes);

        // Register a request handler
        resp_mgr.register_request_handler("/status", None, |_link_id, _path, _data, _remote| {
            Some(b"OK".to_vec())
        });

        let mut init_mgr = LinkManager::new();

        // Complete handshake
        let (link_id, init_actions) = init_mgr.create_link(&dest_hash, &sig_pub_bytes, 1, constants::MTU as u32, &mut rng);
        let lr_raw = extract_send_packet(&init_actions);
        let lr_pkt = RawPacket::unpack(&lr_raw).unwrap();
        let resp_actions = resp_mgr.handle_local_delivery(lr_pkt.destination_hash, &lr_raw, lr_pkt.packet_hash, &mut rng);
        let lrproof_raw = extract_send_packet_at(&resp_actions, 1);
        let lrproof_pkt = RawPacket::unpack(&lrproof_raw).unwrap();
        let init_actions2 = init_mgr.handle_local_delivery(lrproof_pkt.destination_hash, &lrproof_raw, lrproof_pkt.packet_hash, &mut rng);
        let lrrtt_raw = extract_any_send_packet(&init_actions2);
        let lrrtt_pkt = RawPacket::unpack(&lrrtt_raw).unwrap();
        resp_mgr.handle_local_delivery(lrrtt_pkt.destination_hash, &lrrtt_raw, lrrtt_pkt.packet_hash, &mut rng);

        // Send request from initiator
        let req_actions = init_mgr.send_request(&link_id, "/status", b"query", &mut rng);
        assert_eq!(req_actions.len(), 1);

        // Deliver request to responder
        let req_raw = extract_send_packet_from(&req_actions);
        let req_pkt = RawPacket::unpack(&req_raw).unwrap();
        let resp_actions = resp_mgr.handle_local_delivery(
            req_pkt.destination_hash, &req_raw, req_pkt.packet_hash, &mut rng,
        );

        // Should have a response SendPacket
        let has_response = resp_actions.iter().any(|a| matches!(a, LinkManagerAction::SendPacket { .. }));
        assert!(has_response, "Handler should produce a response packet");
    }

    #[test]
    fn test_request_acl_deny_unidentified() {
        let mut rng = OsRng;
        let dest_hash = [0xDD; 16];
        let mut resp_mgr = LinkManager::new();
        let (sig_prv, sig_pub_bytes) = make_dest_keys(&mut rng);
        resp_mgr.register_link_destination(dest_hash, sig_prv, sig_pub_bytes);

        // Register handler with ACL (only allow specific identity)
        resp_mgr.register_request_handler(
            "/restricted",
            Some(vec![[0xAA; 16]]),
            |_link_id, _path, _data, _remote| Some(b"secret".to_vec()),
        );

        let mut init_mgr = LinkManager::new();

        // Complete handshake (without identification)
        let (link_id, init_actions) = init_mgr.create_link(&dest_hash, &sig_pub_bytes, 1, constants::MTU as u32, &mut rng);
        let lr_raw = extract_send_packet(&init_actions);
        let lr_pkt = RawPacket::unpack(&lr_raw).unwrap();
        let resp_actions = resp_mgr.handle_local_delivery(lr_pkt.destination_hash, &lr_raw, lr_pkt.packet_hash, &mut rng);
        let lrproof_raw = extract_send_packet_at(&resp_actions, 1);
        let lrproof_pkt = RawPacket::unpack(&lrproof_raw).unwrap();
        let init_actions2 = init_mgr.handle_local_delivery(lrproof_pkt.destination_hash, &lrproof_raw, lrproof_pkt.packet_hash, &mut rng);
        let lrrtt_raw = extract_any_send_packet(&init_actions2);
        let lrrtt_pkt = RawPacket::unpack(&lrrtt_raw).unwrap();
        resp_mgr.handle_local_delivery(lrrtt_pkt.destination_hash, &lrrtt_raw, lrrtt_pkt.packet_hash, &mut rng);

        // Send request without identifying first
        let req_actions = init_mgr.send_request(&link_id, "/restricted", b"query", &mut rng);
        let req_raw = extract_send_packet_from(&req_actions);
        let req_pkt = RawPacket::unpack(&req_raw).unwrap();
        let resp_actions = resp_mgr.handle_local_delivery(
            req_pkt.destination_hash, &req_raw, req_pkt.packet_hash, &mut rng,
        );

        // Should be denied — no response packet
        let has_response = resp_actions.iter().any(|a| matches!(a, LinkManagerAction::SendPacket { .. }));
        assert!(!has_response, "Unidentified peer should be denied");
    }

    #[test]
    fn test_teardown_link() {
        let mut rng = OsRng;
        let dest_hash = [0xDD; 16];
        let mut mgr = LinkManager::new();

        let dummy_sig = [0xAA; 32];
        let (link_id, _) = mgr.create_link(&dest_hash, &dummy_sig, 1, constants::MTU as u32, &mut rng);
        assert_eq!(mgr.link_count(), 1);

        let actions = mgr.teardown_link(&link_id);
        let has_close = actions.iter().any(|a| matches!(a, LinkManagerAction::LinkClosed { .. }));
        assert!(has_close);

        // After tick, closed links should be cleaned up
        let tick_actions = mgr.tick(&mut rng);
        let has_deregister = tick_actions.iter().any(|a| matches!(a, LinkManagerAction::DeregisterLinkDest { .. }));
        assert!(has_deregister);
        assert_eq!(mgr.link_count(), 0);
    }

    #[test]
    fn test_identify_on_link() {
        let mut rng = OsRng;
        let dest_hash = [0xDD; 16];
        let mut resp_mgr = LinkManager::new();
        let (sig_prv, sig_pub_bytes) = make_dest_keys(&mut rng);
        resp_mgr.register_link_destination(dest_hash, sig_prv, sig_pub_bytes);
        let mut init_mgr = LinkManager::new();

        // Complete handshake
        let (link_id, init_actions) = init_mgr.create_link(&dest_hash, &sig_pub_bytes, 1, constants::MTU as u32, &mut rng);
        let lr_raw = extract_send_packet(&init_actions);
        let lr_pkt = RawPacket::unpack(&lr_raw).unwrap();
        let resp_actions = resp_mgr.handle_local_delivery(lr_pkt.destination_hash, &lr_raw, lr_pkt.packet_hash, &mut rng);
        let lrproof_raw = extract_send_packet_at(&resp_actions, 1);
        let lrproof_pkt = RawPacket::unpack(&lrproof_raw).unwrap();
        let init_actions2 = init_mgr.handle_local_delivery(lrproof_pkt.destination_hash, &lrproof_raw, lrproof_pkt.packet_hash, &mut rng);
        let lrrtt_raw = extract_any_send_packet(&init_actions2);
        let lrrtt_pkt = RawPacket::unpack(&lrrtt_raw).unwrap();
        resp_mgr.handle_local_delivery(lrrtt_pkt.destination_hash, &lrrtt_raw, lrrtt_pkt.packet_hash, &mut rng);

        // Identify initiator to responder
        let identity = Identity::new(&mut rng);
        let id_actions = init_mgr.identify(&link_id, &identity, &mut rng);
        assert_eq!(id_actions.len(), 1);

        // Deliver identify to responder
        let id_raw = extract_send_packet_from(&id_actions);
        let id_pkt = RawPacket::unpack(&id_raw).unwrap();
        let resp_actions = resp_mgr.handle_local_delivery(
            id_pkt.destination_hash, &id_raw, id_pkt.packet_hash, &mut rng,
        );

        let has_identified = resp_actions.iter().any(|a| matches!(a, LinkManagerAction::RemoteIdentified { .. }));
        assert!(has_identified, "Responder should emit RemoteIdentified");
    }

    #[test]
    fn test_path_hash_computation() {
        let h1 = compute_path_hash("/status");
        let h2 = compute_path_hash("/path");
        assert_ne!(h1, h2);

        // Deterministic
        assert_eq!(h1, compute_path_hash("/status"));
    }

    #[test]
    fn test_link_count() {
        let mut mgr = LinkManager::new();
        let mut rng = OsRng;

        assert_eq!(mgr.link_count(), 0);

        let dummy_sig = [0xAA; 32];
        mgr.create_link(&[0x11; 16], &dummy_sig, 1, constants::MTU as u32, &mut rng);
        assert_eq!(mgr.link_count(), 1);

        mgr.create_link(&[0x22; 16], &dummy_sig, 1, constants::MTU as u32, &mut rng);
        assert_eq!(mgr.link_count(), 2);
    }

    // --- Test helpers ---

    fn extract_send_packet(actions: &[LinkManagerAction]) -> Vec<u8> {
        extract_send_packet_at(actions, actions.len() - 1)
    }

    fn extract_send_packet_at(actions: &[LinkManagerAction], idx: usize) -> Vec<u8> {
        match &actions[idx] {
            LinkManagerAction::SendPacket { raw, .. } => raw.clone(),
            other => panic!("Expected SendPacket at index {}, got {:?}", idx, other),
        }
    }

    fn extract_any_send_packet(actions: &[LinkManagerAction]) -> Vec<u8> {
        actions.iter().find_map(|a| match a {
            LinkManagerAction::SendPacket { raw, .. } => Some(raw.clone()),
            _ => None,
        }).expect("Expected at least one SendPacket action")
    }

    fn extract_send_packet_from(actions: &[LinkManagerAction]) -> Vec<u8> {
        extract_any_send_packet(actions)
    }

    /// Set up two linked managers with an active link.
    /// Returns (initiator_mgr, responder_mgr, link_id).
    fn setup_active_link() -> (LinkManager, LinkManager, LinkId) {
        let mut rng = OsRng;
        let dest_hash = [0xDD; 16];
        let mut resp_mgr = LinkManager::new();
        let (sig_prv, sig_pub_bytes) = make_dest_keys(&mut rng);
        resp_mgr.register_link_destination(dest_hash, sig_prv, sig_pub_bytes);
        let mut init_mgr = LinkManager::new();

        let (link_id, init_actions) = init_mgr.create_link(&dest_hash, &sig_pub_bytes, 1, constants::MTU as u32, &mut rng);
        let lr_raw = extract_send_packet(&init_actions);
        let lr_pkt = RawPacket::unpack(&lr_raw).unwrap();
        let resp_actions = resp_mgr.handle_local_delivery(
            lr_pkt.destination_hash, &lr_raw, lr_pkt.packet_hash, &mut rng,
        );
        let lrproof_raw = extract_send_packet_at(&resp_actions, 1);
        let lrproof_pkt = RawPacket::unpack(&lrproof_raw).unwrap();
        let init_actions2 = init_mgr.handle_local_delivery(
            lrproof_pkt.destination_hash, &lrproof_raw, lrproof_pkt.packet_hash, &mut rng,
        );
        let lrrtt_raw = extract_any_send_packet(&init_actions2);
        let lrrtt_pkt = RawPacket::unpack(&lrrtt_raw).unwrap();
        resp_mgr.handle_local_delivery(
            lrrtt_pkt.destination_hash, &lrrtt_raw, lrrtt_pkt.packet_hash, &mut rng,
        );

        assert_eq!(init_mgr.link_state(&link_id), Some(LinkState::Active));
        assert_eq!(resp_mgr.link_state(&link_id), Some(LinkState::Active));

        (init_mgr, resp_mgr, link_id)
    }

    // ====================================================================
    // Phase 8a: Resource wiring tests
    // ====================================================================

    #[test]
    fn test_resource_strategy_default() {
        let mut mgr = LinkManager::new();
        let mut rng = OsRng;
        let dummy_sig = [0xAA; 32];
        let (link_id, _) = mgr.create_link(&[0x11; 16], &dummy_sig, 1, constants::MTU as u32, &mut rng);

        // Default strategy is AcceptNone
        let link = mgr.links.get(&link_id).unwrap();
        assert_eq!(link.resource_strategy, ResourceStrategy::AcceptNone);
    }

    #[test]
    fn test_set_resource_strategy() {
        let mut mgr = LinkManager::new();
        let mut rng = OsRng;
        let dummy_sig = [0xAA; 32];
        let (link_id, _) = mgr.create_link(&[0x11; 16], &dummy_sig, 1, constants::MTU as u32, &mut rng);

        mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);
        assert_eq!(mgr.links.get(&link_id).unwrap().resource_strategy, ResourceStrategy::AcceptAll);

        mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptApp);
        assert_eq!(mgr.links.get(&link_id).unwrap().resource_strategy, ResourceStrategy::AcceptApp);
    }

    #[test]
    fn test_send_resource_on_active_link() {
        let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
        let mut rng = OsRng;

        // Send resource data
        let data = vec![0xAB; 100]; // small enough for a single part
        let actions = init_mgr.send_resource(&link_id, &data, None, &mut rng);

        // Should produce at least a SendPacket (advertisement)
        let has_send = actions.iter().any(|a| matches!(a, LinkManagerAction::SendPacket { .. }));
        assert!(has_send, "send_resource should emit advertisement SendPacket");
    }

    #[test]
    fn test_send_resource_on_inactive_link() {
        let mut mgr = LinkManager::new();
        let mut rng = OsRng;
        let dummy_sig = [0xAA; 32];
        let (link_id, _) = mgr.create_link(&[0x11; 16], &dummy_sig, 1, constants::MTU as u32, &mut rng);

        // Link is Pending, not Active
        let actions = mgr.send_resource(&link_id, b"data", None, &mut rng);
        assert!(actions.is_empty(), "Cannot send resource on inactive link");
    }

    #[test]
    fn test_resource_adv_rejected_by_accept_none() {
        let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
        let mut rng = OsRng;

        // Responder uses default AcceptNone strategy
        // Send resource from initiator
        let data = vec![0xCD; 100];
        let adv_actions = init_mgr.send_resource(&link_id, &data, None, &mut rng);

        // Deliver advertisement to responder
        for action in &adv_actions {
            if let LinkManagerAction::SendPacket { raw, .. } = action {
                let pkt = RawPacket::unpack(raw).unwrap();
                let resp_actions = resp_mgr.handle_local_delivery(
                    pkt.destination_hash, raw, pkt.packet_hash, &mut rng,
                );
                // AcceptNone: should not produce ResourceReceived, may produce SendPacket (RCL)
                let has_resource_received = resp_actions.iter().any(|a|
                    matches!(a, LinkManagerAction::ResourceReceived { .. })
                );
                assert!(!has_resource_received, "AcceptNone should not accept resource");
            }
        }
    }

    #[test]
    fn test_resource_adv_accepted_by_accept_all() {
        let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
        let mut rng = OsRng;

        // Set responder to AcceptAll
        resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);

        // Send resource from initiator
        let data = vec![0xCD; 100];
        let adv_actions = init_mgr.send_resource(&link_id, &data, None, &mut rng);

        // Deliver advertisement to responder
        for action in &adv_actions {
            if let LinkManagerAction::SendPacket { raw, .. } = action {
                let pkt = RawPacket::unpack(raw).unwrap();
                let resp_actions = resp_mgr.handle_local_delivery(
                    pkt.destination_hash, raw, pkt.packet_hash, &mut rng,
                );
                // AcceptAll: should accept and produce a SendPacket (request for parts)
                let has_send = resp_actions.iter().any(|a|
                    matches!(a, LinkManagerAction::SendPacket { .. })
                );
                assert!(has_send, "AcceptAll should accept and request parts");
            }
        }
    }

    #[test]
    fn test_resource_accept_app_query() {
        let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
        let mut rng = OsRng;

        // Set responder to AcceptApp
        resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptApp);

        // Send resource from initiator
        let data = vec![0xCD; 100];
        let adv_actions = init_mgr.send_resource(&link_id, &data, None, &mut rng);

        // Deliver advertisement to responder
        let mut got_query = false;
        for action in &adv_actions {
            if let LinkManagerAction::SendPacket { raw, .. } = action {
                let pkt = RawPacket::unpack(raw).unwrap();
                let resp_actions = resp_mgr.handle_local_delivery(
                    pkt.destination_hash, raw, pkt.packet_hash, &mut rng,
                );
                for a in &resp_actions {
                    if matches!(a, LinkManagerAction::ResourceAcceptQuery { .. }) {
                        got_query = true;
                    }
                }
            }
        }
        assert!(got_query, "AcceptApp should emit ResourceAcceptQuery");
    }

    #[test]
    fn test_resource_accept_app_accept() {
        let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
        let mut rng = OsRng;

        resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptApp);

        let data = vec![0xCD; 100];
        let adv_actions = init_mgr.send_resource(&link_id, &data, None, &mut rng);

        for action in &adv_actions {
            if let LinkManagerAction::SendPacket { raw, .. } = action {
                let pkt = RawPacket::unpack(raw).unwrap();
                let resp_actions = resp_mgr.handle_local_delivery(
                    pkt.destination_hash, raw, pkt.packet_hash, &mut rng,
                );
                for a in &resp_actions {
                    if let LinkManagerAction::ResourceAcceptQuery { link_id: lid, resource_hash, .. } = a {
                        // Accept the resource
                        let accept_actions = resp_mgr.accept_resource(lid, resource_hash, true, &mut rng);
                        // Should produce a SendPacket (request for parts)
                        let has_send = accept_actions.iter().any(|a|
                            matches!(a, LinkManagerAction::SendPacket { .. })
                        );
                        assert!(has_send, "Accepting resource should produce request for parts");
                    }
                }
            }
        }
    }

    #[test]
    fn test_resource_accept_app_reject() {
        let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
        let mut rng = OsRng;

        resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptApp);

        let data = vec![0xCD; 100];
        let adv_actions = init_mgr.send_resource(&link_id, &data, None, &mut rng);

        for action in &adv_actions {
            if let LinkManagerAction::SendPacket { raw, .. } = action {
                let pkt = RawPacket::unpack(raw).unwrap();
                let resp_actions = resp_mgr.handle_local_delivery(
                    pkt.destination_hash, raw, pkt.packet_hash, &mut rng,
                );
                for a in &resp_actions {
                    if let LinkManagerAction::ResourceAcceptQuery { link_id: lid, resource_hash, .. } = a {
                        // Reject the resource
                        let reject_actions = resp_mgr.accept_resource(lid, resource_hash, false, &mut rng);
                        // Rejecting should send a cancel and not request parts
                        // No ResourceReceived should appear
                        let has_resource_received = reject_actions.iter().any(|a|
                            matches!(a, LinkManagerAction::ResourceReceived { .. })
                        );
                        assert!(!has_resource_received);
                    }
                }
            }
        }
    }

    #[test]
    fn test_resource_full_transfer() {
        let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
        let mut rng = OsRng;

        // Set responder to AcceptAll
        resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);

        // Small data (fits in single SDU)
        let original_data = b"Hello, Resource Transfer!".to_vec();
        let adv_actions = init_mgr.send_resource(&link_id, &original_data, None, &mut rng);

        // Drive the full transfer protocol between the two managers.
        // Tag each SendPacket with its source ('i' = initiator, 'r' = responder).
        let mut pending: Vec<(char, LinkManagerAction)> = adv_actions.into_iter()
            .map(|a| ('i', a))
            .collect();
        let mut rounds = 0;
        let max_rounds = 50;
        let mut resource_received = false;
        let mut sender_completed = false;

        while !pending.is_empty() && rounds < max_rounds {
            rounds += 1;
            let mut next: Vec<(char, LinkManagerAction)> = Vec::new();

            for (source, action) in pending.drain(..) {
                if let LinkManagerAction::SendPacket { raw, .. } = action {
                    let pkt = RawPacket::unpack(&raw).unwrap();

                    // Deliver only to the OTHER side
                    let target_actions = if source == 'i' {
                        resp_mgr.handle_local_delivery(
                            pkt.destination_hash, &raw, pkt.packet_hash, &mut rng,
                        )
                    } else {
                        init_mgr.handle_local_delivery(
                            pkt.destination_hash, &raw, pkt.packet_hash, &mut rng,
                        )
                    };

                    let target_source = if source == 'i' { 'r' } else { 'i' };
                    for a in &target_actions {
                        match a {
                            LinkManagerAction::ResourceReceived { data, .. } => {
                                assert_eq!(*data, original_data);
                                resource_received = true;
                            }
                            LinkManagerAction::ResourceCompleted { .. } => {
                                sender_completed = true;
                            }
                            _ => {}
                        }
                    }
                    next.extend(target_actions.into_iter().map(|a| (target_source, a)));
                }
            }
            pending = next;
        }

        assert!(resource_received, "Responder should receive resource data (rounds={})", rounds);
        assert!(sender_completed, "Sender should get completion proof (rounds={})", rounds);
    }

    #[test]
    fn test_resource_cancel_icl() {
        let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
        let mut rng = OsRng;

        resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);

        // Use large data so transfer is multi-part
        let data = vec![0xAB; 2000];
        let adv_actions = init_mgr.send_resource(&link_id, &data, None, &mut rng);

        // Deliver advertisement — responder accepts and sends request
        for action in &adv_actions {
            if let LinkManagerAction::SendPacket { raw, .. } = action {
                let pkt = RawPacket::unpack(raw).unwrap();
                resp_mgr.handle_local_delivery(
                    pkt.destination_hash, raw, pkt.packet_hash, &mut rng,
                );
            }
        }

        // Verify there are incoming resources on the responder
        assert!(!resp_mgr.links.get(&link_id).unwrap().incoming_resources.is_empty());

        // Simulate ICL (cancel from initiator side) by calling handle_resource_icl
        let icl_actions = resp_mgr.handle_resource_icl(&link_id);

        // Should have resource failed
        let has_failed = icl_actions.iter().any(|a| matches!(a, LinkManagerAction::ResourceFailed { .. }));
        assert!(has_failed, "ICL should produce ResourceFailed");
    }

    #[test]
    fn test_resource_cancel_rcl() {
        let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
        let mut rng = OsRng;

        // Create a resource sender
        let data = vec![0xAB; 2000];
        init_mgr.send_resource(&link_id, &data, None, &mut rng);

        // Verify there are outgoing resources
        assert!(!init_mgr.links.get(&link_id).unwrap().outgoing_resources.is_empty());

        // Simulate RCL (cancel from receiver side)
        let rcl_actions = init_mgr.handle_resource_rcl(&link_id);

        let has_failed = rcl_actions.iter().any(|a| matches!(a, LinkManagerAction::ResourceFailed { .. }));
        assert!(has_failed, "RCL should produce ResourceFailed");
    }

    #[test]
    fn test_resource_tick_cleans_up() {
        let (mut init_mgr, _resp_mgr, link_id) = setup_active_link();
        let mut rng = OsRng;

        let data = vec![0xAB; 100];
        init_mgr.send_resource(&link_id, &data, None, &mut rng);

        assert!(!init_mgr.links.get(&link_id).unwrap().outgoing_resources.is_empty());

        // Cancel the sender to make it Complete
        init_mgr.handle_resource_rcl(&link_id);

        // Tick should clean up completed resources
        init_mgr.tick(&mut rng);

        assert!(init_mgr.links.get(&link_id).unwrap().outgoing_resources.is_empty(),
            "Tick should clean up completed/failed outgoing resources");
    }

    #[test]
    fn test_build_link_packet() {
        let (init_mgr, _resp_mgr, link_id) = setup_active_link();

        let actions = init_mgr.build_link_packet(&link_id, constants::CONTEXT_RESOURCE, b"test data");
        assert_eq!(actions.len(), 1);
        if let LinkManagerAction::SendPacket { raw, dest_type, .. } = &actions[0] {
            let pkt = RawPacket::unpack(raw).unwrap();
            assert_eq!(pkt.context, constants::CONTEXT_RESOURCE);
            assert_eq!(*dest_type, constants::DESTINATION_LINK);
        } else {
            panic!("Expected SendPacket");
        }
    }

    // ====================================================================
    // Phase 8b: Channel message & data callback tests
    // ====================================================================

    #[test]
    fn test_channel_message_delivery() {
        let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
        let mut rng = OsRng;

        // Send channel message from initiator
        let chan_actions = init_mgr.send_channel_message(&link_id, 42, b"channel data", &mut rng);
        assert!(!chan_actions.is_empty());

        // Deliver to responder
        let mut got_channel_msg = false;
        for action in &chan_actions {
            if let LinkManagerAction::SendPacket { raw, .. } = action {
                let pkt = RawPacket::unpack(raw).unwrap();
                let resp_actions = resp_mgr.handle_local_delivery(
                    pkt.destination_hash, raw, pkt.packet_hash, &mut rng,
                );
                for a in &resp_actions {
                    if let LinkManagerAction::ChannelMessageReceived { msgtype, payload, .. } = a {
                        assert_eq!(*msgtype, 42);
                        assert_eq!(*payload, b"channel data");
                        got_channel_msg = true;
                    }
                }
            }
        }
        assert!(got_channel_msg, "Responder should receive channel message");
    }

    #[test]
    fn test_generic_link_data_delivery() {
        let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
        let mut rng = OsRng;

        // Send generic data with a custom context
        let actions = init_mgr.send_on_link(&link_id, b"raw stuff", 0x42, &mut rng);
        assert_eq!(actions.len(), 1);

        // Deliver to responder
        let raw = extract_any_send_packet(&actions);
        let pkt = RawPacket::unpack(&raw).unwrap();
        let resp_actions = resp_mgr.handle_local_delivery(
            pkt.destination_hash, &raw, pkt.packet_hash, &mut rng,
        );

        let has_data = resp_actions.iter().any(|a|
            matches!(a, LinkManagerAction::LinkDataReceived { context: 0x42, .. })
        );
        assert!(has_data, "Responder should receive LinkDataReceived for unknown context");
    }

    #[test]
    fn test_response_delivery() {
        let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
        let mut rng = OsRng;

        // Register handler on responder
        resp_mgr.register_request_handler("/echo", None, |_link_id, _path, data, _remote| {
            Some(data.to_vec())
        });

        // Send request from initiator
        let req_actions = init_mgr.send_request(&link_id, "/echo", b"\xc0", &mut rng);  // msgpack nil
        assert!(!req_actions.is_empty());

        // Deliver request to responder — should produce response
        let req_raw = extract_any_send_packet(&req_actions);
        let req_pkt = RawPacket::unpack(&req_raw).unwrap();
        let resp_actions = resp_mgr.handle_local_delivery(
            req_pkt.destination_hash, &req_raw, req_pkt.packet_hash, &mut rng,
        );
        let has_resp_send = resp_actions.iter().any(|a| matches!(a, LinkManagerAction::SendPacket { .. }));
        assert!(has_resp_send, "Handler should produce response");

        // Deliver response back to initiator
        let resp_raw = extract_any_send_packet(&resp_actions);
        let resp_pkt = RawPacket::unpack(&resp_raw).unwrap();
        let init_actions = init_mgr.handle_local_delivery(
            resp_pkt.destination_hash, &resp_raw, resp_pkt.packet_hash, &mut rng,
        );

        let has_response_received = init_actions.iter().any(|a|
            matches!(a, LinkManagerAction::ResponseReceived { .. })
        );
        assert!(has_response_received, "Initiator should receive ResponseReceived");
    }

    #[test]
    fn test_send_channel_message_on_no_channel() {
        let mut mgr = LinkManager::new();
        let mut rng = OsRng;
        let dummy_sig = [0xAA; 32];
        let (link_id, _) = mgr.create_link(&[0x11; 16], &dummy_sig, 1, constants::MTU as u32, &mut rng);

        // Link is Pending (no channel), should return empty
        let actions = mgr.send_channel_message(&link_id, 1, b"test", &mut rng);
        assert!(actions.is_empty(), "No channel on pending link");
    }

    #[test]
    fn test_send_on_link_requires_active() {
        let mut mgr = LinkManager::new();
        let mut rng = OsRng;
        let dummy_sig = [0xAA; 32];
        let (link_id, _) = mgr.create_link(&[0x11; 16], &dummy_sig, 1, constants::MTU as u32, &mut rng);

        let actions = mgr.send_on_link(&link_id, b"test", constants::CONTEXT_NONE, &mut rng);
        assert!(actions.is_empty(), "Cannot send on pending link");
    }

    #[test]
    fn test_send_on_link_unknown_link() {
        let mgr = LinkManager::new();
        let mut rng = OsRng;

        let actions = mgr.send_on_link(&[0xFF; 16], b"test", constants::CONTEXT_NONE, &mut rng);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_resource_full_transfer_large() {
        let (mut init_mgr, mut resp_mgr, link_id) = setup_active_link();
        let mut rng = OsRng;

        resp_mgr.set_resource_strategy(&link_id, ResourceStrategy::AcceptAll);

        // Multi-part data (larger than a single SDU of 464 bytes)
        let original_data: Vec<u8> = (0..2000u32).map(|i| {
            let pos = i as usize;
            (pos ^ (pos >> 8) ^ (pos >> 16)) as u8
        }).collect();

        let adv_actions = init_mgr.send_resource(&link_id, &original_data, None, &mut rng);

        let mut pending: Vec<(char, LinkManagerAction)> = adv_actions.into_iter()
            .map(|a| ('i', a))
            .collect();
        let mut rounds = 0;
        let max_rounds = 200;
        let mut resource_received = false;
        let mut sender_completed = false;

        while !pending.is_empty() && rounds < max_rounds {
            rounds += 1;
            let mut next: Vec<(char, LinkManagerAction)> = Vec::new();

            for (source, action) in pending.drain(..) {
                if let LinkManagerAction::SendPacket { raw, .. } = action {
                    let pkt = match RawPacket::unpack(&raw) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };

                    let target_actions = if source == 'i' {
                        resp_mgr.handle_local_delivery(
                            pkt.destination_hash, &raw, pkt.packet_hash, &mut rng,
                        )
                    } else {
                        init_mgr.handle_local_delivery(
                            pkt.destination_hash, &raw, pkt.packet_hash, &mut rng,
                        )
                    };

                    let target_source = if source == 'i' { 'r' } else { 'i' };
                    for a in &target_actions {
                        match a {
                            LinkManagerAction::ResourceReceived { data, .. } => {
                                assert_eq!(*data, original_data);
                                resource_received = true;
                            }
                            LinkManagerAction::ResourceCompleted { .. } => {
                                sender_completed = true;
                            }
                            _ => {}
                        }
                    }
                    next.extend(target_actions.into_iter().map(|a| (target_source, a)));
                }
            }
            pending = next;
        }

        assert!(resource_received, "Should receive large resource (rounds={})", rounds);
        assert!(sender_completed, "Sender should complete (rounds={})", rounds);
    }

    #[test]
    fn test_process_resource_actions_mapping() {
        let (init_mgr, _resp_mgr, link_id) = setup_active_link();
        let mut rng = OsRng;

        // Test that various ResourceActions map to correct LinkManagerActions
        let actions = vec![
            ResourceAction::DataReceived { data: vec![1, 2, 3], metadata: Some(vec![4, 5]) },
            ResourceAction::Completed,
            ResourceAction::Failed(rns_core::resource::ResourceError::Timeout),
            ResourceAction::ProgressUpdate { received: 10, total: 20 },
        ];

        let result = init_mgr.process_resource_actions(&link_id, actions, &mut rng);

        assert!(matches!(result[0], LinkManagerAction::ResourceReceived { .. }));
        assert!(matches!(result[1], LinkManagerAction::ResourceCompleted { .. }));
        assert!(matches!(result[2], LinkManagerAction::ResourceFailed { .. }));
        assert!(matches!(result[3], LinkManagerAction::ResourceProgress { received: 10, total: 20, .. }));
    }
}
