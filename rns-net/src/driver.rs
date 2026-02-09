//! Driver loop: receives events, drives the TransportEngine, dispatches actions.

use std::collections::HashMap;

use rns_core::packet::RawPacket;
use rns_core::transport::types::{InterfaceId, TransportAction, TransportConfig};
use rns_core::transport::TransportEngine;
use rns_crypto::OsRng;

use crate::event::{
    BlackholeInfo, Event, EventReceiver, InterfaceStatsResponse, NextHopResponse,
    PathTableEntry, QueryRequest, QueryResponse, RateTableEntry, SingleInterfaceStat,
};
use crate::ifac;
use crate::interface::{InterfaceEntry, InterfaceStats};
use crate::link_manager::{LinkManager, LinkManagerAction};
use crate::time;

/// Callbacks for events the driver produces.
pub trait Callbacks: Send {
    fn on_announce(
        &mut self,
        dest_hash: [u8; 16],
        identity_hash: [u8; 16],
        public_key: [u8; 64],
        app_data: Option<Vec<u8>>,
        hops: u8,
    );

    fn on_path_updated(&mut self, dest_hash: [u8; 16], hops: u8);

    fn on_local_delivery(&mut self, dest_hash: [u8; 16], raw: Vec<u8>, packet_hash: [u8; 32]);

    /// Called when an interface comes online.
    fn on_interface_up(&mut self, _id: InterfaceId) {}

    /// Called when an interface goes offline.
    fn on_interface_down(&mut self, _id: InterfaceId) {}

    /// Called when a link is fully established.
    fn on_link_established(&mut self, _link_id: [u8; 16], _rtt: f64, _is_initiator: bool) {}

    /// Called when a link is closed.
    fn on_link_closed(&mut self, _link_id: [u8; 16], _reason: Option<rns_core::link::TeardownReason>) {}

    /// Called when a remote peer identifies on a link.
    fn on_remote_identified(&mut self, _link_id: [u8; 16], _identity_hash: [u8; 16], _public_key: [u8; 64]) {}

    /// Called when a resource transfer delivers data.
    fn on_resource_received(&mut self, _link_id: [u8; 16], _data: Vec<u8>, _metadata: Option<Vec<u8>>) {}

    /// Called when a resource transfer completes (sender-side proof validated).
    fn on_resource_completed(&mut self, _link_id: [u8; 16]) {}

    /// Called when a resource transfer fails.
    fn on_resource_failed(&mut self, _link_id: [u8; 16], _error: String) {}

    /// Called with resource transfer progress updates.
    fn on_resource_progress(&mut self, _link_id: [u8; 16], _received: usize, _total: usize) {}

    /// Called to ask whether to accept an incoming resource (for AcceptApp strategy).
    /// Return true to accept, false to reject.
    fn on_resource_accept_query(&mut self, _link_id: [u8; 16], _resource_hash: Vec<u8>, _transfer_size: u64, _has_metadata: bool) -> bool {
        false
    }

    /// Called when a channel message is received on a link.
    fn on_channel_message(&mut self, _link_id: [u8; 16], _msgtype: u16, _payload: Vec<u8>) {}

    /// Called when generic link data is received.
    fn on_link_data(&mut self, _link_id: [u8; 16], _context: u8, _data: Vec<u8>) {}

    /// Called when a response is received on a link.
    fn on_response(&mut self, _link_id: [u8; 16], _request_id: [u8; 16], _data: Vec<u8>) {}
}

/// The driver loop. Owns the engine and all interface entries.
pub struct Driver {
    pub(crate) engine: TransportEngine,
    pub(crate) interfaces: HashMap<InterfaceId, InterfaceEntry>,
    pub(crate) rng: OsRng,
    pub(crate) rx: EventReceiver,
    pub(crate) callbacks: Box<dyn Callbacks>,
    pub(crate) started: f64,
    pub(crate) announce_cache: Option<crate::announce_cache::AnnounceCache>,
    /// Destination hash for rnstransport.tunnel.synthesize (PLAIN).
    pub(crate) tunnel_synth_dest: [u8; 16],
    /// Transport identity (optional, needed for tunnel synthesis).
    pub(crate) transport_identity: Option<rns_crypto::identity::Identity>,
    /// Link manager: handles link lifecycle, request/response.
    pub(crate) link_manager: LinkManager,
    /// Management configuration for ACL checks.
    pub(crate) management_config: crate::management::ManagementConfig,
    /// Last time management announces were emitted.
    pub(crate) last_management_announce: f64,
    /// Whether initial management announce has been sent (delayed 5s after start).
    pub(crate) initial_announce_sent: bool,
}

impl Driver {
    /// Create a new driver.
    pub fn new(
        config: TransportConfig,
        rx: EventReceiver,
        callbacks: Box<dyn Callbacks>,
    ) -> Self {
        let tunnel_synth_dest = rns_core::destination::destination_hash(
            "rnstransport",
            &["tunnel", "synthesize"],
            None,
        );
        let mut engine = TransportEngine::new(config);
        engine.register_destination(tunnel_synth_dest, rns_core::constants::DESTINATION_PLAIN);
        Driver {
            engine,
            interfaces: HashMap::new(),
            rng: OsRng,
            rx,
            callbacks,
            started: time::now(),
            announce_cache: None,
            tunnel_synth_dest,
            transport_identity: None,
            link_manager: LinkManager::new(),
            management_config: Default::default(),
            last_management_announce: 0.0,
            initial_announce_sent: false,
        }
    }

    /// Run the event loop. Blocks until Shutdown or all senders are dropped.
    pub fn run(&mut self) {
        loop {
            let event = match self.rx.recv() {
                Ok(e) => e,
                Err(_) => break, // all senders dropped
            };

            match event {
                Event::Frame { interface_id, data } => {
                    // Update rx stats
                    if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                        entry.stats.rxb += data.len() as u64;
                        entry.stats.rx_packets += 1;
                    }

                    // IFAC inbound processing
                    let packet = if let Some(entry) = self.interfaces.get(&interface_id) {
                        if let Some(ref ifac_state) = entry.ifac {
                            // Interface has IFAC enabled — unmask
                            match ifac::unmask_inbound(&data, ifac_state) {
                                Some(unmasked) => unmasked,
                                None => {
                                    log::debug!("[{}] IFAC rejected packet", interface_id.0);
                                    continue;
                                }
                            }
                        } else {
                            // No IFAC — drop if IFAC flag is set
                            if data.len() > 2 && data[0] & 0x80 == 0x80 {
                                log::debug!("[{}] dropping packet with IFAC flag on non-IFAC interface", interface_id.0);
                                continue;
                            }
                            data
                        }
                    } else {
                        data
                    };

                    let actions = self.engine.handle_inbound(
                        &packet,
                        interface_id,
                        time::now(),
                        &mut self.rng,
                    );
                    self.dispatch_all(actions);
                }
                Event::Tick => {
                    let now = time::now();
                    let actions = self.engine.tick(now, &mut self.rng);
                    self.dispatch_all(actions);
                    // Tick link manager (keepalive, stale, timeout)
                    let link_actions = self.link_manager.tick(&mut self.rng);
                    self.dispatch_link_actions(link_actions);
                    // Emit management announces
                    self.tick_management_announces(now);
                }
                Event::InterfaceUp(id, new_writer, info) => {
                    let wants_tunnel;
                    if let Some(info) = info {
                        // New dynamic interface (e.g., TCP server client connection)
                        log::info!("[{}] dynamic interface registered", id.0);
                        wants_tunnel = info.wants_tunnel;
                        self.engine.register_interface(info.clone());
                        if let Some(writer) = new_writer {
                            self.interfaces.insert(
                                id,
                                InterfaceEntry {
                                    id,
                                    info,
                                    writer,
                                    online: true,
                                    dynamic: true,
                                    ifac: None,
                                    stats: InterfaceStats {
                                        started: time::now(),
                                        ..Default::default()
                                    },
                                },
                            );
                        }
                        self.callbacks.on_interface_up(id);
                    } else if let Some(entry) = self.interfaces.get_mut(&id) {
                        // Existing interface reconnected
                        log::info!("[{}] interface online", id.0);
                        wants_tunnel = entry.info.wants_tunnel;
                        entry.online = true;
                        if let Some(writer) = new_writer {
                            log::info!("[{}] writer refreshed after reconnect", id.0);
                            entry.writer = writer;
                        }
                        self.callbacks.on_interface_up(id);
                    } else {
                        wants_tunnel = false;
                    }

                    // Trigger tunnel synthesis if the interface wants it
                    if wants_tunnel {
                        self.synthesize_tunnel_for_interface(id);
                    }
                }
                Event::InterfaceDown(id) => {
                    // Void tunnel if interface had one
                    if let Some(entry) = self.interfaces.get(&id) {
                        if let Some(tunnel_id) = entry.info.tunnel_id {
                            self.engine.void_tunnel_interface(&tunnel_id);
                        }
                    }

                    if let Some(entry) = self.interfaces.get(&id) {
                        if entry.dynamic {
                            // Dynamic interfaces are removed entirely
                            log::info!("[{}] dynamic interface removed", id.0);
                            self.engine.deregister_interface(id);
                            self.interfaces.remove(&id);
                        } else {
                            // Static interfaces are just marked offline
                            log::info!("[{}] interface offline", id.0);
                            self.interfaces.get_mut(&id).unwrap().online = false;
                        }
                        self.callbacks.on_interface_down(id);
                    }
                }
                Event::SendOutbound { raw, dest_type, attached_interface } => {
                    match RawPacket::unpack(&raw) {
                        Ok(packet) => {
                            let actions = self.engine.handle_outbound(
                                &packet,
                                dest_type,
                                attached_interface,
                                time::now(),
                            );
                            self.dispatch_all(actions);
                        }
                        Err(e) => {
                            log::warn!("SendOutbound: failed to unpack packet: {:?}", e);
                        }
                    }
                }
                Event::RegisterDestination { dest_hash, dest_type } => {
                    self.engine.register_destination(dest_hash, dest_type);
                }
                Event::DeregisterDestination { dest_hash } => {
                    self.engine.deregister_destination(&dest_hash);
                }
                Event::Query(request, response_tx) => {
                    let response = self.handle_query_mut(request);
                    let _ = response_tx.send(response);
                }
                Event::RegisterLinkDestination { dest_hash, sig_prv_bytes, sig_pub_bytes } => {
                    let sig_prv = rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&sig_prv_bytes);
                    self.link_manager.register_link_destination(dest_hash, sig_prv, sig_pub_bytes);
                    // Also register in transport engine so inbound packets are delivered locally
                    self.engine.register_destination(dest_hash, rns_core::constants::DESTINATION_SINGLE);
                }
                Event::RegisterRequestHandler { path, allowed_list, handler } => {
                    self.link_manager.register_request_handler(&path, allowed_list, move |link_id, p, data, remote| {
                        handler(link_id, p, data, remote)
                    });
                }
                Event::CreateLink { dest_hash, dest_sig_pub_bytes, response_tx } => {
                    let hops = self.engine.hops_to(&dest_hash).unwrap_or(0);
                    let (link_id, link_actions) = self.link_manager.create_link(
                        &dest_hash, &dest_sig_pub_bytes, hops, &mut self.rng,
                    );
                    let _ = response_tx.send(link_id);
                    self.dispatch_link_actions(link_actions);
                }
                Event::SendRequest { link_id, path, data } => {
                    let link_actions = self.link_manager.send_request(
                        &link_id, &path, &data, &mut self.rng,
                    );
                    self.dispatch_link_actions(link_actions);
                }
                Event::IdentifyOnLink { link_id, identity_prv_key } => {
                    let identity = rns_crypto::identity::Identity::from_private_key(&identity_prv_key);
                    let link_actions = self.link_manager.identify(&link_id, &identity, &mut self.rng);
                    self.dispatch_link_actions(link_actions);
                }
                Event::TeardownLink { link_id } => {
                    let link_actions = self.link_manager.teardown_link(&link_id);
                    self.dispatch_link_actions(link_actions);
                }
                Event::SendResource { link_id, data, metadata } => {
                    let link_actions = self.link_manager.send_resource(
                        &link_id, &data, metadata.as_deref(), &mut self.rng,
                    );
                    self.dispatch_link_actions(link_actions);
                }
                Event::SetResourceStrategy { link_id, strategy } => {
                    use crate::link_manager::ResourceStrategy;
                    let strat = match strategy {
                        0 => ResourceStrategy::AcceptNone,
                        1 => ResourceStrategy::AcceptAll,
                        2 => ResourceStrategy::AcceptApp,
                        _ => ResourceStrategy::AcceptNone,
                    };
                    self.link_manager.set_resource_strategy(&link_id, strat);
                }
                Event::AcceptResource { link_id, resource_hash, accept } => {
                    let link_actions = self.link_manager.accept_resource(
                        &link_id, &resource_hash, accept, &mut self.rng,
                    );
                    self.dispatch_link_actions(link_actions);
                }
                Event::SendChannelMessage { link_id, msgtype, payload } => {
                    let link_actions = self.link_manager.send_channel_message(
                        &link_id, msgtype, &payload, &mut self.rng,
                    );
                    self.dispatch_link_actions(link_actions);
                }
                Event::SendOnLink { link_id, data, context } => {
                    let link_actions = self.link_manager.send_on_link(
                        &link_id, &data, context, &mut self.rng,
                    );
                    self.dispatch_link_actions(link_actions);
                }
                Event::Shutdown => break,
            }
        }
    }

    /// Handle a query request and produce a response.
    fn handle_query(&self, request: QueryRequest) -> QueryResponse {
        match request {
            QueryRequest::InterfaceStats => {
                let mut interfaces = Vec::new();
                let mut total_rxb: u64 = 0;
                let mut total_txb: u64 = 0;
                for entry in self.interfaces.values() {
                    total_rxb += entry.stats.rxb;
                    total_txb += entry.stats.txb;
                    interfaces.push(SingleInterfaceStat {
                        name: entry.info.name.clone(),
                        status: entry.online,
                        mode: entry.info.mode,
                        rxb: entry.stats.rxb,
                        txb: entry.stats.txb,
                        rx_packets: entry.stats.rx_packets,
                        tx_packets: entry.stats.tx_packets,
                        bitrate: entry.info.bitrate,
                        ifac_size: entry.ifac.as_ref().map(|s| s.size),
                        started: entry.stats.started,
                        ia_freq: entry.stats.incoming_announce_freq(),
                        oa_freq: entry.stats.outgoing_announce_freq(),
                    });
                }
                // Sort by name for consistent output
                interfaces.sort_by(|a, b| a.name.cmp(&b.name));
                QueryResponse::InterfaceStats(InterfaceStatsResponse {
                    interfaces,
                    transport_id: self.engine.identity_hash().copied(),
                    transport_enabled: self.engine.transport_enabled(),
                    transport_uptime: time::now() - self.started,
                    total_rxb,
                    total_txb,
                })
            }
            QueryRequest::PathTable { max_hops } => {
                let entries: Vec<PathTableEntry> = self
                    .engine
                    .path_table_entries()
                    .filter(|(_, entry)| {
                        max_hops.map_or(true, |max| entry.hops <= max)
                    })
                    .map(|(hash, entry)| {
                        let iface_name = self.interfaces.get(&entry.receiving_interface)
                            .map(|e| e.info.name.clone())
                            .or_else(|| self.engine.interface_info(&entry.receiving_interface)
                                .map(|i| i.name.clone()))
                            .unwrap_or_default();
                        PathTableEntry {
                            hash: *hash,
                            timestamp: entry.timestamp,
                            via: entry.next_hop,
                            hops: entry.hops,
                            expires: entry.expires,
                            interface: entry.receiving_interface,
                            interface_name: iface_name,
                        }
                    })
                    .collect();
                QueryResponse::PathTable(entries)
            }
            QueryRequest::RateTable => {
                let entries: Vec<RateTableEntry> = self
                    .engine
                    .rate_limiter()
                    .entries()
                    .map(|(hash, entry)| RateTableEntry {
                        hash: *hash,
                        last: entry.last,
                        rate_violations: entry.rate_violations,
                        blocked_until: entry.blocked_until,
                        timestamps: entry.timestamps.clone(),
                    })
                    .collect();
                QueryResponse::RateTable(entries)
            }
            QueryRequest::NextHop { dest_hash } => {
                let resp = self.engine.next_hop(&dest_hash).map(|next_hop| {
                    NextHopResponse {
                        next_hop,
                        hops: self.engine.hops_to(&dest_hash).unwrap_or(0),
                        interface: self.engine.next_hop_interface(&dest_hash).unwrap_or(InterfaceId(0)),
                    }
                });
                QueryResponse::NextHop(resp)
            }
            QueryRequest::NextHopIfName { dest_hash } => {
                let name = self
                    .engine
                    .next_hop_interface(&dest_hash)
                    .and_then(|id| self.interfaces.get(&id))
                    .map(|entry| entry.info.name.clone());
                QueryResponse::NextHopIfName(name)
            }
            QueryRequest::LinkCount => {
                QueryResponse::LinkCount(self.engine.link_table_count() + self.link_manager.link_count())
            }
            QueryRequest::DropPath { .. } => {
                // Mutating queries are handled by handle_query_mut
                QueryResponse::DropPath(false)
            }
            QueryRequest::DropAllVia { .. } => {
                QueryResponse::DropAllVia(0)
            }
            QueryRequest::DropAnnounceQueues => {
                QueryResponse::DropAnnounceQueues
            }
            QueryRequest::TransportIdentity => {
                QueryResponse::TransportIdentity(self.engine.identity_hash().copied())
            }
            QueryRequest::GetBlackholed => {
                let now = time::now();
                let entries: Vec<BlackholeInfo> = self.engine.blackholed_entries()
                    .filter(|(_, e)| e.expires == 0.0 || e.expires > now)
                    .map(|(hash, entry)| BlackholeInfo {
                        identity_hash: *hash,
                        created: entry.created,
                        expires: entry.expires,
                        reason: entry.reason.clone(),
                    })
                    .collect();
                QueryResponse::Blackholed(entries)
            }
            QueryRequest::BlackholeIdentity { .. }
            | QueryRequest::UnblackholeIdentity { .. } => {
                // Mutating queries handled by handle_query_mut
                QueryResponse::BlackholeResult(false)
            }
        }
    }

    /// Handle a mutating query request.
    fn handle_query_mut(&mut self, request: QueryRequest) -> QueryResponse {
        match request {
            QueryRequest::BlackholeIdentity { identity_hash, duration_hours, reason } => {
                let now = time::now();
                self.engine.blackhole_identity(identity_hash, now, duration_hours, reason);
                QueryResponse::BlackholeResult(true)
            }
            QueryRequest::UnblackholeIdentity { identity_hash } => {
                let result = self.engine.unblackhole_identity(&identity_hash);
                QueryResponse::UnblackholeResult(result)
            }
            QueryRequest::DropPath { dest_hash } => {
                QueryResponse::DropPath(self.engine.drop_path(&dest_hash))
            }
            QueryRequest::DropAllVia { transport_hash } => {
                QueryResponse::DropAllVia(self.engine.drop_all_via(&transport_hash))
            }
            QueryRequest::DropAnnounceQueues => {
                self.engine.drop_announce_queues();
                QueryResponse::DropAnnounceQueues
            }
            other => self.handle_query(other),
        }
    }

    /// Handle a tunnel synthesis packet delivered locally.
    fn handle_tunnel_synth_delivery(&mut self, raw: &[u8]) {
        // Extract the data payload from the raw packet
        let packet = match RawPacket::unpack(raw) {
            Ok(p) => p,
            Err(_) => return,
        };

        match rns_core::transport::tunnel::validate_tunnel_synthesize_data(&packet.data) {
            Ok(validated) => {
                // Find the interface this tunnel belongs to by computing the expected
                // tunnel_id for each interface with wants_tunnel
                let iface_id = self
                    .interfaces
                    .iter()
                    .find(|(_, entry)| entry.info.wants_tunnel && entry.online)
                    .map(|(id, _)| *id);

                if let Some(iface) = iface_id {
                    let now = time::now();
                    let tunnel_actions =
                        self.engine.handle_tunnel(validated.tunnel_id, iface, now);
                    self.dispatch_all(tunnel_actions);
                }
            }
            Err(e) => {
                log::debug!("Tunnel synthesis validation failed: {}", e);
            }
        }
    }

    /// Synthesize a tunnel on an interface that wants it.
    ///
    /// Called when an interface with `wants_tunnel` comes up.
    fn synthesize_tunnel_for_interface(&mut self, interface: InterfaceId) {
        if let Some(ref identity) = self.transport_identity {
            let actions = self.engine.synthesize_tunnel(identity, interface, &mut self.rng);
            self.dispatch_all(actions);
        }
    }

    /// Dispatch a list of transport actions.
    fn dispatch_all(&mut self, actions: Vec<TransportAction>) {
        for action in actions {
            match action {
                TransportAction::SendOnInterface { interface, raw } => {
                    let is_announce = raw.len() > 2 && (raw[0] & 0x03) == 0x01;
                    if let Some(entry) = self.interfaces.get_mut(&interface) {
                        if entry.online {
                            let data = if let Some(ref ifac_state) = entry.ifac {
                                ifac::mask_outbound(&raw, ifac_state)
                            } else {
                                raw
                            };
                            // Update tx stats
                            entry.stats.txb += data.len() as u64;
                            entry.stats.tx_packets += 1;
                            if is_announce {
                                entry.stats.record_outgoing_announce(time::now());
                            }
                            if let Err(e) = entry.writer.send_frame(&data) {
                                log::warn!("[{}] send failed: {}", entry.info.id.0, e);
                            }
                        }
                    }
                }
                TransportAction::BroadcastOnAllInterfaces { raw, exclude } => {
                    let is_announce = raw.len() > 2 && (raw[0] & 0x03) == 0x01;
                    for entry in self.interfaces.values_mut() {
                        if entry.online && Some(entry.id) != exclude {
                            let data = if let Some(ref ifac_state) = entry.ifac {
                                ifac::mask_outbound(&raw, ifac_state)
                            } else {
                                raw.clone()
                            };
                            // Update tx stats
                            entry.stats.txb += data.len() as u64;
                            entry.stats.tx_packets += 1;
                            if is_announce {
                                entry.stats.record_outgoing_announce(time::now());
                            }
                            if let Err(e) = entry.writer.send_frame(&data) {
                                log::warn!("[{}] broadcast failed: {}", entry.info.id.0, e);
                            }
                        }
                    }
                }
                TransportAction::DeliverLocal {
                    destination_hash,
                    raw,
                    packet_hash,
                } => {
                    if destination_hash == self.tunnel_synth_dest {
                        // Tunnel synthesis packet — validate and handle
                        self.handle_tunnel_synth_delivery(&raw);
                    } else if self.link_manager.is_link_destination(&destination_hash) {
                        // Link-related packet — route to link manager
                        let link_actions = self.link_manager.handle_local_delivery(
                            destination_hash, &raw, packet_hash, &mut self.rng,
                        );
                        self.dispatch_link_actions(link_actions);
                    } else {
                        self.callbacks
                            .on_local_delivery(destination_hash, raw, packet_hash);
                    }
                }
                TransportAction::AnnounceReceived {
                    destination_hash,
                    identity_hash,
                    public_key,
                    app_data,
                    hops,
                    receiving_interface,
                    ..
                } => {
                    if let Some(entry) = self.interfaces.get_mut(&receiving_interface) {
                        entry.stats.record_incoming_announce(time::now());
                    }
                    self.callbacks
                        .on_announce(destination_hash, identity_hash, public_key, app_data, hops);
                }
                TransportAction::PathUpdated {
                    destination_hash,
                    hops,
                    ..
                } => {
                    self.callbacks.on_path_updated(destination_hash, hops);
                }
                TransportAction::ForwardToLocalClients { raw, exclude } => {
                    for entry in self.interfaces.values_mut() {
                        if entry.online
                            && entry.info.is_local_client
                            && Some(entry.id) != exclude
                        {
                            let data = if let Some(ref ifac_state) = entry.ifac {
                                ifac::mask_outbound(&raw, ifac_state)
                            } else {
                                raw.clone()
                            };
                            entry.stats.txb += data.len() as u64;
                            entry.stats.tx_packets += 1;
                            if let Err(e) = entry.writer.send_frame(&data) {
                                log::warn!("[{}] forward to local client failed: {}", entry.info.id.0, e);
                            }
                        }
                    }
                }
                TransportAction::ForwardPlainBroadcast { raw, to_local, exclude } => {
                    for entry in self.interfaces.values_mut() {
                        if entry.online
                            && entry.info.is_local_client == to_local
                            && Some(entry.id) != exclude
                        {
                            let data = if let Some(ref ifac_state) = entry.ifac {
                                ifac::mask_outbound(&raw, ifac_state)
                            } else {
                                raw.clone()
                            };
                            entry.stats.txb += data.len() as u64;
                            entry.stats.tx_packets += 1;
                            if let Err(e) = entry.writer.send_frame(&data) {
                                log::warn!("[{}] forward plain broadcast failed: {}", entry.info.id.0, e);
                            }
                        }
                    }
                }
                TransportAction::CacheAnnounce { packet_hash, raw } => {
                    if let Some(ref cache) = self.announce_cache {
                        if let Err(e) = cache.store(&packet_hash, &raw, None) {
                            log::warn!("Failed to cache announce: {}", e);
                        }
                    }
                }
                TransportAction::TunnelSynthesize { interface, data, dest_hash } => {
                    // Pack as BROADCAST DATA PLAIN packet and send on interface
                    let flags = rns_core::packet::PacketFlags {
                        header_type: rns_core::constants::HEADER_1,
                        context_flag: rns_core::constants::FLAG_UNSET,
                        transport_type: rns_core::constants::TRANSPORT_BROADCAST,
                        destination_type: rns_core::constants::DESTINATION_PLAIN,
                        packet_type: rns_core::constants::PACKET_TYPE_DATA,
                    };
                    if let Ok(packet) = rns_core::packet::RawPacket::pack(
                        flags, 0, &dest_hash, None,
                        rns_core::constants::CONTEXT_NONE, &data,
                    ) {
                        if let Some(entry) = self.interfaces.get_mut(&interface) {
                            if entry.online {
                                let raw = if let Some(ref ifac_state) = entry.ifac {
                                    ifac::mask_outbound(&packet.raw, ifac_state)
                                } else {
                                    packet.raw
                                };
                                entry.stats.txb += raw.len() as u64;
                                entry.stats.tx_packets += 1;
                                if let Err(e) = entry.writer.send_frame(&raw) {
                                    log::warn!("[{}] tunnel synthesize send failed: {}", entry.info.id.0, e);
                                }
                            }
                        }
                    }
                }
                TransportAction::TunnelEstablished { tunnel_id, interface } => {
                    log::info!("Tunnel established: {:02x?} on interface {}", &tunnel_id[..4], interface.0);
                }
            }
        }
    }

    /// Dispatch link manager actions.
    fn dispatch_link_actions(&mut self, actions: Vec<LinkManagerAction>) {
        for action in actions {
            match action {
                LinkManagerAction::SendPacket { raw, dest_type, attached_interface } => {
                    // Route through the transport engine's outbound path
                    match RawPacket::unpack(&raw) {
                        Ok(packet) => {
                            let transport_actions = self.engine.handle_outbound(
                                &packet,
                                dest_type,
                                attached_interface,
                                time::now(),
                            );
                            self.dispatch_all(transport_actions);
                        }
                        Err(e) => {
                            log::warn!("LinkManager SendPacket: failed to unpack: {:?}", e);
                        }
                    }
                }
                LinkManagerAction::LinkEstablished { link_id, rtt, is_initiator } => {
                    log::info!(
                        "Link established: {:02x?} rtt={:.3}s initiator={}",
                        &link_id[..4], rtt, is_initiator,
                    );
                    self.callbacks.on_link_established(link_id, rtt, is_initiator);
                }
                LinkManagerAction::LinkClosed { link_id, reason } => {
                    log::info!("Link closed: {:02x?} reason={:?}", &link_id[..4], reason);
                    self.callbacks.on_link_closed(link_id, reason);
                }
                LinkManagerAction::RemoteIdentified { link_id, identity_hash, public_key } => {
                    log::debug!(
                        "Remote identified on link {:02x?}: {:02x?}",
                        &link_id[..4], &identity_hash[..4],
                    );
                    self.callbacks.on_remote_identified(link_id, identity_hash, public_key);
                }
                LinkManagerAction::RegisterLinkDest { link_id } => {
                    // Register the link_id as a LINK destination in the transport engine
                    self.engine.register_destination(link_id, rns_core::constants::DESTINATION_LINK);
                }
                LinkManagerAction::DeregisterLinkDest { link_id } => {
                    self.engine.deregister_destination(&link_id);
                }
                LinkManagerAction::ManagementRequest {
                    link_id, path_hash, data, request_id, remote_identity,
                } => {
                    self.handle_management_request(
                        link_id, path_hash, data, request_id, remote_identity,
                    );
                }
                LinkManagerAction::ResourceReceived { link_id, data, metadata } => {
                    self.callbacks.on_resource_received(link_id, data, metadata);
                }
                LinkManagerAction::ResourceCompleted { link_id } => {
                    self.callbacks.on_resource_completed(link_id);
                }
                LinkManagerAction::ResourceFailed { link_id, error } => {
                    log::debug!("Resource failed on link {:02x?}: {}", &link_id[..4], error);
                    self.callbacks.on_resource_failed(link_id, error);
                }
                LinkManagerAction::ResourceProgress { link_id, received, total } => {
                    self.callbacks.on_resource_progress(link_id, received, total);
                }
                LinkManagerAction::ResourceAcceptQuery { link_id, resource_hash, transfer_size, has_metadata } => {
                    let accept = self.callbacks.on_resource_accept_query(
                        link_id, resource_hash.clone(), transfer_size, has_metadata,
                    );
                    let accept_actions = self.link_manager.accept_resource(
                        &link_id, &resource_hash, accept, &mut self.rng,
                    );
                    // Re-dispatch (recursive but bounded: accept_resource won't produce more AcceptQuery)
                    self.dispatch_link_actions(accept_actions);
                }
                LinkManagerAction::ChannelMessageReceived { link_id, msgtype, payload } => {
                    self.callbacks.on_channel_message(link_id, msgtype, payload);
                }
                LinkManagerAction::LinkDataReceived { link_id, context, data } => {
                    self.callbacks.on_link_data(link_id, context, data);
                }
                LinkManagerAction::ResponseReceived { link_id, request_id, data } => {
                    self.callbacks.on_response(link_id, request_id, data);
                }
            }
        }
    }

    /// Management announce interval in seconds.
    const MANAGEMENT_ANNOUNCE_INTERVAL: f64 = 300.0;

    /// Delay before first management announce after startup.
    const MANAGEMENT_ANNOUNCE_DELAY: f64 = 5.0;

    /// Emit management and/or blackhole announces if enabled and due.
    fn tick_management_announces(&mut self, now: f64) {
        if self.transport_identity.is_none() {
            return;
        }

        let uptime = now - self.started;

        // Wait for initial delay
        if !self.initial_announce_sent {
            if uptime < Self::MANAGEMENT_ANNOUNCE_DELAY {
                return;
            }
            self.initial_announce_sent = true;
            self.emit_management_announces(now);
            return;
        }

        // Periodic re-announce
        if now - self.last_management_announce >= Self::MANAGEMENT_ANNOUNCE_INTERVAL {
            self.emit_management_announces(now);
        }
    }

    /// Emit management/blackhole announce packets through the engine outbound path.
    fn emit_management_announces(&mut self, now: f64) {
        use crate::management;

        self.last_management_announce = now;

        let identity = match self.transport_identity {
            Some(ref id) => id,
            None => return,
        };

        // Build announce packets first (immutable borrow of identity), then dispatch
        let mgmt_raw = if self.management_config.enable_remote_management {
            management::build_management_announce(identity, &mut self.rng)
        } else {
            None
        };

        let bh_raw = if self.management_config.publish_blackhole {
            management::build_blackhole_announce(identity, &mut self.rng)
        } else {
            None
        };

        if let Some(raw) = mgmt_raw {
            if let Ok(packet) = RawPacket::unpack(&raw) {
                let actions = self.engine.handle_outbound(
                    &packet,
                    rns_core::constants::DESTINATION_SINGLE,
                    None,
                    now,
                );
                self.dispatch_all(actions);
                log::debug!("Emitted management destination announce");
            }
        }

        if let Some(raw) = bh_raw {
            if let Ok(packet) = RawPacket::unpack(&raw) {
                let actions = self.engine.handle_outbound(
                    &packet,
                    rns_core::constants::DESTINATION_SINGLE,
                    None,
                    now,
                );
                self.dispatch_all(actions);
                log::debug!("Emitted blackhole info announce");
            }
        }
    }

    /// Handle a management request by querying engine state and sending a response.
    fn handle_management_request(
        &mut self,
        link_id: [u8; 16],
        path_hash: [u8; 16],
        data: Vec<u8>,
        request_id: [u8; 16],
        remote_identity: Option<([u8; 16], [u8; 64])>,
    ) {
        use crate::management;

        // ACL check for /status and /path (ALLOW_LIST), /list is ALLOW_ALL
        let is_restricted = path_hash == management::status_path_hash()
            || path_hash == management::path_path_hash();

        if is_restricted && !self.management_config.remote_management_allowed.is_empty() {
            match remote_identity {
                Some((identity_hash, _)) => {
                    if !self.management_config.remote_management_allowed.contains(&identity_hash) {
                        log::debug!("Management request denied: identity not in allowed list");
                        return;
                    }
                }
                None => {
                    log::debug!("Management request denied: peer not identified");
                    return;
                }
            }
        }

        let response_data = if path_hash == management::status_path_hash() {
            management::handle_status_request(&data, &self.engine, &self.interfaces, self.started)
        } else if path_hash == management::path_path_hash() {
            management::handle_path_request(&data, &self.engine)
        } else if path_hash == management::list_path_hash() {
            management::handle_blackhole_list_request(&self.engine)
        } else {
            log::warn!("Unknown management path_hash: {:02x?}", &path_hash[..4]);
            None
        };

        if let Some(response) = response_data {
            let actions = self.link_manager.send_management_response(
                &link_id, &request_id, &response, &mut self.rng,
            );
            self.dispatch_link_actions(actions);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event;
    use crate::interface::Writer;
    use rns_core::announce::AnnounceData;
    use rns_core::constants;
    use rns_core::packet::PacketFlags;
    use rns_core::transport::types::InterfaceInfo;
    use rns_crypto::identity::Identity;
    use std::io;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};

    struct MockWriter {
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl MockWriter {
        fn new() -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
            let sent = Arc::new(Mutex::new(Vec::new()));
            (MockWriter { sent: sent.clone() }, sent)
        }
    }

    impl Writer for MockWriter {
        fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
            self.sent.lock().unwrap().push(data.to_vec());
            Ok(())
        }
    }

    struct MockCallbacks {
        announces: Arc<Mutex<Vec<([u8; 16], u8)>>>,
        paths: Arc<Mutex<Vec<([u8; 16], u8)>>>,
        deliveries: Arc<Mutex<Vec<[u8; 16]>>>,
        iface_ups: Arc<Mutex<Vec<InterfaceId>>>,
        iface_downs: Arc<Mutex<Vec<InterfaceId>>>,
        link_established: Arc<Mutex<Vec<([u8; 16], f64, bool)>>>,
        link_closed: Arc<Mutex<Vec<[u8; 16]>>>,
        remote_identified: Arc<Mutex<Vec<([u8; 16], [u8; 16])>>>,
        resources_received: Arc<Mutex<Vec<([u8; 16], Vec<u8>)>>>,
        resource_completed: Arc<Mutex<Vec<[u8; 16]>>>,
        resource_failed: Arc<Mutex<Vec<([u8; 16], String)>>>,
        channel_messages: Arc<Mutex<Vec<([u8; 16], u16, Vec<u8>)>>>,
        link_data: Arc<Mutex<Vec<([u8; 16], u8, Vec<u8>)>>>,
        responses: Arc<Mutex<Vec<([u8; 16], [u8; 16], Vec<u8>)>>>,
    }

    impl MockCallbacks {
        fn new() -> (
            Self,
            Arc<Mutex<Vec<([u8; 16], u8)>>>,
            Arc<Mutex<Vec<([u8; 16], u8)>>>,
            Arc<Mutex<Vec<[u8; 16]>>>,
            Arc<Mutex<Vec<InterfaceId>>>,
            Arc<Mutex<Vec<InterfaceId>>>,
        ) {
            let announces = Arc::new(Mutex::new(Vec::new()));
            let paths = Arc::new(Mutex::new(Vec::new()));
            let deliveries = Arc::new(Mutex::new(Vec::new()));
            let iface_ups = Arc::new(Mutex::new(Vec::new()));
            let iface_downs = Arc::new(Mutex::new(Vec::new()));
            (
                MockCallbacks {
                    announces: announces.clone(),
                    paths: paths.clone(),
                    deliveries: deliveries.clone(),
                    iface_ups: iface_ups.clone(),
                    iface_downs: iface_downs.clone(),
                    link_established: Arc::new(Mutex::new(Vec::new())),
                    link_closed: Arc::new(Mutex::new(Vec::new())),
                    remote_identified: Arc::new(Mutex::new(Vec::new())),
                    resources_received: Arc::new(Mutex::new(Vec::new())),
                    resource_completed: Arc::new(Mutex::new(Vec::new())),
                    resource_failed: Arc::new(Mutex::new(Vec::new())),
                    channel_messages: Arc::new(Mutex::new(Vec::new())),
                    link_data: Arc::new(Mutex::new(Vec::new())),
                    responses: Arc::new(Mutex::new(Vec::new())),
                },
                announces,
                paths,
                deliveries,
                iface_ups,
                iface_downs,
            )
        }

        fn with_link_tracking() -> (
            Self,
            Arc<Mutex<Vec<([u8; 16], f64, bool)>>>,
            Arc<Mutex<Vec<[u8; 16]>>>,
            Arc<Mutex<Vec<([u8; 16], [u8; 16])>>>,
        ) {
            let link_established = Arc::new(Mutex::new(Vec::new()));
            let link_closed = Arc::new(Mutex::new(Vec::new()));
            let remote_identified = Arc::new(Mutex::new(Vec::new()));
            (
                MockCallbacks {
                    announces: Arc::new(Mutex::new(Vec::new())),
                    paths: Arc::new(Mutex::new(Vec::new())),
                    deliveries: Arc::new(Mutex::new(Vec::new())),
                    iface_ups: Arc::new(Mutex::new(Vec::new())),
                    iface_downs: Arc::new(Mutex::new(Vec::new())),
                    link_established: link_established.clone(),
                    link_closed: link_closed.clone(),
                    remote_identified: remote_identified.clone(),
                    resources_received: Arc::new(Mutex::new(Vec::new())),
                    resource_completed: Arc::new(Mutex::new(Vec::new())),
                    resource_failed: Arc::new(Mutex::new(Vec::new())),
                    channel_messages: Arc::new(Mutex::new(Vec::new())),
                    link_data: Arc::new(Mutex::new(Vec::new())),
                    responses: Arc::new(Mutex::new(Vec::new())),
                },
                link_established,
                link_closed,
                remote_identified,
            )
        }
    }

    impl Callbacks for MockCallbacks {
        fn on_announce(
            &mut self,
            dest_hash: [u8; 16],
            _identity_hash: [u8; 16],
            _public_key: [u8; 64],
            _app_data: Option<Vec<u8>>,
            hops: u8,
        ) {
            self.announces.lock().unwrap().push((dest_hash, hops));
        }

        fn on_path_updated(&mut self, dest_hash: [u8; 16], hops: u8) {
            self.paths.lock().unwrap().push((dest_hash, hops));
        }

        fn on_local_delivery(&mut self, dest_hash: [u8; 16], _raw: Vec<u8>, _packet_hash: [u8; 32]) {
            self.deliveries.lock().unwrap().push(dest_hash);
        }

        fn on_interface_up(&mut self, id: InterfaceId) {
            self.iface_ups.lock().unwrap().push(id);
        }

        fn on_interface_down(&mut self, id: InterfaceId) {
            self.iface_downs.lock().unwrap().push(id);
        }

        fn on_link_established(&mut self, link_id: [u8; 16], rtt: f64, is_initiator: bool) {
            self.link_established.lock().unwrap().push((link_id, rtt, is_initiator));
        }

        fn on_link_closed(&mut self, link_id: [u8; 16], _reason: Option<rns_core::link::TeardownReason>) {
            self.link_closed.lock().unwrap().push(link_id);
        }

        fn on_remote_identified(&mut self, link_id: [u8; 16], identity_hash: [u8; 16], _public_key: [u8; 64]) {
            self.remote_identified.lock().unwrap().push((link_id, identity_hash));
        }

        fn on_resource_received(&mut self, link_id: [u8; 16], data: Vec<u8>, _metadata: Option<Vec<u8>>) {
            self.resources_received.lock().unwrap().push((link_id, data));
        }

        fn on_resource_completed(&mut self, link_id: [u8; 16]) {
            self.resource_completed.lock().unwrap().push(link_id);
        }

        fn on_resource_failed(&mut self, link_id: [u8; 16], error: String) {
            self.resource_failed.lock().unwrap().push((link_id, error));
        }

        fn on_channel_message(&mut self, link_id: [u8; 16], msgtype: u16, payload: Vec<u8>) {
            self.channel_messages.lock().unwrap().push((link_id, msgtype, payload));
        }

        fn on_link_data(&mut self, link_id: [u8; 16], context: u8, data: Vec<u8>) {
            self.link_data.lock().unwrap().push((link_id, context, data));
        }

        fn on_response(&mut self, link_id: [u8; 16], request_id: [u8; 16], data: Vec<u8>) {
            self.responses.lock().unwrap().push((link_id, request_id, data));
        }
    }

    fn make_interface_info(id: u64) -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId(id),
            name: format!("test-{}", id),
            mode: constants::MODE_FULL,
            out_capable: true,
            in_capable: true,
            bitrate: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: rns_core::constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
        }
    }

    fn make_entry(id: u64, writer: Box<dyn Writer>, online: bool) -> InterfaceEntry {
        InterfaceEntry {
            id: InterfaceId(id),
            info: make_interface_info(id),
            writer,
            online,
            dynamic: false,
            ifac: None,
            stats: InterfaceStats::default(),
        }
    }

    /// Build a valid announce packet that the engine will accept.
    fn build_announce_packet(identity: &Identity) -> Vec<u8> {
        let dest_hash = rns_core::destination::destination_hash(
            "test",
            &["app"],
            Some(identity.hash()),
        );
        let name_hash = rns_core::destination::name_hash("test", &["app"]);
        let random_hash = [0x42u8; 10];

        let (announce_data, _has_ratchet) = AnnounceData::pack(
            identity,
            &dest_hash,
            &name_hash,
            &random_hash,
            None,
            None,
        )
        .unwrap();

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_ANNOUNCE,
        };

        let packet = RawPacket::pack(flags, 0, &dest_hash, None, constants::CONTEXT_NONE, &announce_data).unwrap();
        packet.raw
    }

    #[test]
    fn process_inbound_frame() {
        let (tx, rx) = event::channel();
        let (cbs, announces, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);

        // Send frame then shutdown
        tx.send(Event::Frame { interface_id: InterfaceId(1), data: announce_raw }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert_eq!(announces.lock().unwrap().len(), 1);
    }

    #[test]
    fn dispatch_send() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );
        let (writer, sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(1),
            raw: vec![0x01, 0x02, 0x03],
        }]);

        assert_eq!(sent.lock().unwrap().len(), 1);
        assert_eq!(sent.lock().unwrap()[0], vec![0x01, 0x02, 0x03]);

        drop(tx);
    }

    #[test]
    fn dispatch_broadcast() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        let (w1, sent1) = MockWriter::new();
        let (w2, sent2) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(w1), true));
        driver.interfaces.insert(InterfaceId(2), make_entry(2, Box::new(w2), true));

        driver.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
            raw: vec![0xAA],
            exclude: None,
        }]);

        assert_eq!(sent1.lock().unwrap().len(), 1);
        assert_eq!(sent2.lock().unwrap().len(), 1);

        drop(tx);
    }

    #[test]
    fn dispatch_broadcast_exclude() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        let (w1, sent1) = MockWriter::new();
        let (w2, sent2) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(w1), true));
        driver.interfaces.insert(InterfaceId(2), make_entry(2, Box::new(w2), true));

        driver.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
            raw: vec![0xBB],
            exclude: Some(InterfaceId(1)),
        }]);

        assert_eq!(sent1.lock().unwrap().len(), 0); // excluded
        assert_eq!(sent2.lock().unwrap().len(), 1);

        drop(tx);
    }

    #[test]
    fn tick_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: true, identity_hash: Some([0x42; 16]) },
            rx,
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Send Tick then Shutdown
        tx.send(Event::Tick).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();
        // No crash = tick was processed successfully
    }

    #[test]
    fn shutdown_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        tx.send(Event::Shutdown).unwrap();
        driver.run(); // Should return immediately
    }

    #[test]
    fn announce_callback() {
        let (tx, rx) = event::channel();
        let (cbs, announces, paths, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);

        tx.send(Event::Frame { interface_id: InterfaceId(1), data: announce_raw }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let ann = announces.lock().unwrap();
        assert_eq!(ann.len(), 1);
        // Hops should be 1 (incremented from 0 by handle_inbound)
        assert_eq!(ann[0].1, 1);

        let p = paths.lock().unwrap();
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn dispatch_skips_offline_interface() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        let (w1, sent1) = MockWriter::new();
        let (w2, sent2) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(w1), false)); // offline
        driver.interfaces.insert(InterfaceId(2), make_entry(2, Box::new(w2), true));

        // Direct send to offline interface: should be skipped
        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(1),
            raw: vec![0x01],
        }]);
        assert_eq!(sent1.lock().unwrap().len(), 0);

        // Broadcast: only online interface should receive
        driver.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
            raw: vec![0x02],
            exclude: None,
        }]);
        assert_eq!(sent1.lock().unwrap().len(), 0); // still offline
        assert_eq!(sent2.lock().unwrap().len(), 1);

        drop(tx);
    }

    #[test]
    fn interface_up_refreshes_writer() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        let (w_old, sent_old) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(w_old), false));

        // Simulate reconnect: InterfaceUp with new writer
        let (w_new, sent_new) = MockWriter::new();
        tx.send(Event::InterfaceUp(InterfaceId(1), Some(Box::new(w_new)), None)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Interface should be online now
        assert!(driver.interfaces[&InterfaceId(1)].online);

        // Send via the (now-refreshed) interface
        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(1),
            raw: vec![0xFF],
        }]);

        // Old writer should not have received anything
        assert_eq!(sent_old.lock().unwrap().len(), 0);
        // New writer should have received the data
        assert_eq!(sent_new.lock().unwrap().len(), 1);
        assert_eq!(sent_new.lock().unwrap()[0], vec![0xFF]);

        drop(tx);
    }

    #[test]
    fn dynamic_interface_register() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, iface_ups, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        let info = make_interface_info(100);
        let (writer, sent) = MockWriter::new();

        // InterfaceUp with InterfaceInfo = new dynamic interface
        tx.send(Event::InterfaceUp(
            InterfaceId(100),
            Some(Box::new(writer)),
            Some(info),
        ))
        .unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should be registered and online
        assert!(driver.interfaces.contains_key(&InterfaceId(100)));
        assert!(driver.interfaces[&InterfaceId(100)].online);
        assert!(driver.interfaces[&InterfaceId(100)].dynamic);

        // Callback should have fired
        assert_eq!(iface_ups.lock().unwrap().len(), 1);
        assert_eq!(iface_ups.lock().unwrap()[0], InterfaceId(100));

        // Can send to it
        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(100),
            raw: vec![0x42],
        }]);
        assert_eq!(sent.lock().unwrap().len(), 1);

        drop(tx);
    }

    #[test]
    fn dynamic_interface_deregister() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, iface_downs) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        // Register a dynamic interface
        let info = make_interface_info(200);
        driver.engine.register_interface(info.clone());
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(200), InterfaceEntry {
            id: InterfaceId(200),
            info,
            writer: Box::new(writer),
            online: true,
            dynamic: true,
            ifac: None,
            stats: InterfaceStats::default(),
        });

        // InterfaceDown for dynamic → should be removed entirely
        tx.send(Event::InterfaceDown(InterfaceId(200))).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert!(!driver.interfaces.contains_key(&InterfaceId(200)));
        assert_eq!(iface_downs.lock().unwrap().len(), 1);
        assert_eq!(iface_downs.lock().unwrap()[0], InterfaceId(200));
    }

    #[test]
    fn interface_callbacks_fire() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, iface_ups, iface_downs) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        // Static interface
        let (writer, _) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), false));

        tx.send(Event::InterfaceUp(InterfaceId(1), None, None)).unwrap();
        tx.send(Event::InterfaceDown(InterfaceId(1))).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert_eq!(iface_ups.lock().unwrap().len(), 1);
        assert_eq!(iface_downs.lock().unwrap().len(), 1);
        // Static interface should still exist but be offline
        assert!(driver.interfaces.contains_key(&InterfaceId(1)));
        assert!(!driver.interfaces[&InterfaceId(1)].online);
    }

    // =========================================================================
    // New tests for Phase 6a
    // =========================================================================

    #[test]
    fn frame_updates_rx_stats() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);
        let announce_len = announce_raw.len() as u64;

        tx.send(Event::Frame { interface_id: InterfaceId(1), data: announce_raw }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let stats = &driver.interfaces[&InterfaceId(1)].stats;
        assert_eq!(stats.rxb, announce_len);
        assert_eq!(stats.rx_packets, 1);
    }

    #[test]
    fn send_updates_tx_stats() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(1),
            raw: vec![0x01, 0x02, 0x03],
        }]);

        let stats = &driver.interfaces[&InterfaceId(1)].stats;
        assert_eq!(stats.txb, 3);
        assert_eq!(stats.tx_packets, 1);

        drop(tx);
    }

    #[test]
    fn broadcast_updates_tx_stats() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );
        let (w1, _s1) = MockWriter::new();
        let (w2, _s2) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(w1), true));
        driver.interfaces.insert(InterfaceId(2), make_entry(2, Box::new(w2), true));

        driver.dispatch_all(vec![TransportAction::BroadcastOnAllInterfaces {
            raw: vec![0xAA, 0xBB],
            exclude: None,
        }]);

        // Both interfaces should have tx stats updated
        assert_eq!(driver.interfaces[&InterfaceId(1)].stats.txb, 2);
        assert_eq!(driver.interfaces[&InterfaceId(1)].stats.tx_packets, 1);
        assert_eq!(driver.interfaces[&InterfaceId(2)].stats.txb, 2);
        assert_eq!(driver.interfaces[&InterfaceId(2)].stats.tx_packets, 1);

        drop(tx);
    }

    #[test]
    fn query_interface_stats() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: true, identity_hash: Some([0x42; 16]) },
            rx,
            Box::new(cbs),
        );
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::InterfaceStats, resp_tx)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let resp = resp_rx.recv().unwrap();
        match resp {
            QueryResponse::InterfaceStats(stats) => {
                assert_eq!(stats.interfaces.len(), 1);
                assert_eq!(stats.interfaces[0].name, "test-1");
                assert!(stats.interfaces[0].status);
                assert_eq!(stats.transport_id, Some([0x42; 16]));
                assert!(stats.transport_enabled);
            }
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_path_table() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Feed an announce to create a path entry
        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);
        tx.send(Event::Frame { interface_id: InterfaceId(1), data: announce_raw }).unwrap();

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::PathTable { max_hops: None }, resp_tx)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let resp = resp_rx.recv().unwrap();
        match resp {
            QueryResponse::PathTable(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].hops, 1);
            }
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_drop_path() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Feed an announce to create a path entry
        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);
        let dest_hash = rns_core::destination::destination_hash(
            "test", &["app"], Some(identity.hash()),
        );

        tx.send(Event::Frame { interface_id: InterfaceId(1), data: announce_raw }).unwrap();

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::DropPath { dest_hash }, resp_tx)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let resp = resp_rx.recv().unwrap();
        match resp {
            QueryResponse::DropPath(dropped) => {
                assert!(dropped);
            }
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn send_outbound_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );
        let (writer, sent) = MockWriter::new();
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Build a DATA packet to a destination
        let dest = [0xAA; 16];
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

        tx.send(Event::SendOutbound {
            raw: packet.raw,
            dest_type: constants::DESTINATION_PLAIN,
            attached_interface: None,
        }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // PLAIN packet should be broadcast on all interfaces
        assert_eq!(sent.lock().unwrap().len(), 1);
    }

    #[test]
    fn register_destination_and_deliver() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, deliveries, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let dest = [0xBB; 16];

        // Register destination then send a data packet to it
        tx.send(Event::RegisterDestination {
            dest_hash: dest,
            dest_type: constants::DESTINATION_SINGLE,
        }).unwrap();

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"data").unwrap();
        tx.send(Event::Frame { interface_id: InterfaceId(1), data: packet.raw }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert_eq!(deliveries.lock().unwrap().len(), 1);
        assert_eq!(deliveries.lock().unwrap()[0], dest);
    }

    #[test]
    fn query_transport_identity() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: true, identity_hash: Some([0xAA; 16]) },
            rx,
            Box::new(cbs),
        );

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::TransportIdentity, resp_tx)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::TransportIdentity(Some(hash)) => {
                assert_eq!(hash, [0xAA; 16]);
            }
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_link_count() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::LinkCount, resp_tx)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::LinkCount(count) => assert_eq!(count, 0),
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_rate_table() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::RateTable, resp_tx)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::RateTable(entries) => assert!(entries.is_empty()),
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_next_hop() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        let dest = [0xBB; 16];
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::NextHop { dest_hash: dest }, resp_tx)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::NextHop(None) => {}
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_next_hop_if_name() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        let dest = [0xCC; 16];
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::NextHopIfName { dest_hash: dest }, resp_tx)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::NextHopIfName(None) => {}
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_drop_all_via() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        let transport = [0xDD; 16];
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(
            QueryRequest::DropAllVia { transport_hash: transport },
            resp_tx,
        )).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::DropAllVia(count) => assert_eq!(count, 0),
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn query_drop_announce_queues() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::DropAnnounceQueues, resp_tx)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::DropAnnounceQueues => {}
            _ => panic!("unexpected response"),
        }
    }

    // =========================================================================
    // Phase 7e: Link wiring integration tests
    // =========================================================================

    #[test]
    fn register_link_dest_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let mut rng = OsRng;
        let sig_prv = rns_crypto::ed25519::Ed25519PrivateKey::generate(&mut rng);
        let sig_pub_bytes = sig_prv.public_key().public_bytes();
        let sig_prv_bytes = sig_prv.private_bytes();
        let dest_hash = [0xDD; 16];

        tx.send(Event::RegisterLinkDestination {
            dest_hash,
            sig_prv_bytes,
            sig_pub_bytes,
        }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Link manager should know about the destination
        assert!(driver.link_manager.is_link_destination(&dest_hash));
    }

    #[test]
    fn create_link_event() {
        let (tx, rx) = event::channel();
        let (cbs, _link_established, _, _) = MockCallbacks::with_link_tracking();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let dest_hash = [0xDD; 16];
        let dummy_sig_pub = [0xAA; 32];

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::CreateLink {
            dest_hash,
            dest_sig_pub_bytes: dummy_sig_pub,
            response_tx: resp_tx,
        }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should have received a link_id
        let link_id = resp_rx.recv().unwrap();
        assert_ne!(link_id, [0u8; 16]);

        // Link should be in pending state in the manager
        assert_eq!(driver.link_manager.link_count(), 1);

        // The LINKREQUEST packet won't be sent on the wire without a path
        // to the destination (DESTINATION_LINK requires a known path or
        // attached_interface). In a real scenario, the path would exist from
        // an announce received earlier.
    }

    #[test]
    fn deliver_local_routes_to_link_manager() {
        // Verify that DeliverLocal for a registered link destination goes to
        // the link manager instead of the callbacks.
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register a link destination
        let mut rng = OsRng;
        let sig_prv = rns_crypto::ed25519::Ed25519PrivateKey::generate(&mut rng);
        let sig_pub_bytes = sig_prv.public_key().public_bytes();
        let dest_hash = [0xEE; 16];
        driver.link_manager.register_link_destination(dest_hash, sig_prv, sig_pub_bytes);

        // dispatch_all with a DeliverLocal for that dest should route to link_manager
        // (not to callbacks). We can't easily test this via run() since we need
        // a valid LINKREQUEST, but we can check is_link_destination works.
        assert!(driver.link_manager.is_link_destination(&dest_hash));

        // Non-link destination should go to callbacks
        assert!(!driver.link_manager.is_link_destination(&[0xFF; 16]));

        drop(tx);
    }

    #[test]
    fn teardown_link_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, link_closed, _) = MockCallbacks::with_link_tracking();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Create a link first
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::CreateLink {
            dest_hash: [0xDD; 16],
            dest_sig_pub_bytes: [0xAA; 32],
            response_tx: resp_tx,
        }).unwrap();
        // Then tear it down
        // We can't receive resp_rx yet since driver.run() hasn't started,
        // but we know the link_id will be created. Send teardown after CreateLink.
        // Actually, we need to get the link_id first. Let's use a two-phase approach.
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let link_id = resp_rx.recv().unwrap();
        assert_ne!(link_id, [0u8; 16]);
        assert_eq!(driver.link_manager.link_count(), 1);

        // Now restart with same driver (just use events directly since driver loop exited)
        let teardown_actions = driver.link_manager.teardown_link(&link_id);
        driver.dispatch_link_actions(teardown_actions);

        // Callback should have been called
        assert_eq!(link_closed.lock().unwrap().len(), 1);
        assert_eq!(link_closed.lock().unwrap()[0], link_id);
    }

    #[test]
    fn link_count_includes_link_manager() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Create a link via link_manager directly
        let mut rng = OsRng;
        let dummy_sig = [0xAA; 32];
        driver.link_manager.create_link(&[0xDD; 16], &dummy_sig, 1, &mut rng);

        // Query link count — should include link_manager links
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::LinkCount, resp_tx)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::LinkCount(count) => assert_eq!(count, 1),
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn register_request_handler_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        tx.send(Event::RegisterRequestHandler {
            path: "/status".to_string(),
            allowed_list: None,
            handler: Box::new(|_link_id, _path, _data, _remote| Some(b"OK".to_vec())),
        }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Handler should be registered (we can't directly query the count,
        // but at least verify no crash)
    }

    // Phase 8c: Management announce timing tests

    #[test]
    fn management_announces_emitted_after_delay() {
        let (tx, rx) = event::channel();
        let (cbs, announces, _, _, _, _) = MockCallbacks::new();
        let identity = Identity::new(&mut OsRng);
        let identity_hash = *identity.hash();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: true, identity_hash: Some(identity_hash) },
            rx,
            Box::new(cbs),
        );

        // Register interface so announces can be sent
        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Enable management announces
        driver.management_config.enable_remote_management = true;
        driver.transport_identity = Some(identity);

        // Set started time to 10 seconds ago so the 5s delay has passed
        driver.started = time::now() - 10.0;

        // Send Tick then Shutdown
        tx.send(Event::Tick).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should have sent at least one packet (the management announce)
        let sent_packets = sent.lock().unwrap();
        assert!(!sent_packets.is_empty(),
            "Management announce should be sent after startup delay");
    }

    #[test]
    fn management_announces_not_emitted_when_disabled() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let identity = Identity::new(&mut OsRng);
        let identity_hash = *identity.hash();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: true, identity_hash: Some(identity_hash) },
            rx,
            Box::new(cbs),
        );

        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Management announces disabled (default)
        driver.transport_identity = Some(identity);
        driver.started = time::now() - 10.0;

        tx.send(Event::Tick).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should NOT have sent any packets
        let sent_packets = sent.lock().unwrap();
        assert!(sent_packets.is_empty(),
            "No announces should be sent when management is disabled");
    }

    #[test]
    fn management_announces_not_emitted_before_delay() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let identity = Identity::new(&mut OsRng);
        let identity_hash = *identity.hash();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: true, identity_hash: Some(identity_hash) },
            rx,
            Box::new(cbs),
        );

        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        driver.management_config.enable_remote_management = true;
        driver.transport_identity = Some(identity);
        // Started just now - delay hasn't passed
        driver.started = time::now();

        tx.send(Event::Tick).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let sent_packets = sent.lock().unwrap();
        assert!(sent_packets.is_empty(),
            "No announces before startup delay");
    }
}
