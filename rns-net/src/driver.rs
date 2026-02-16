//! Driver loop: receives events, drives the TransportEngine, dispatches actions.

use std::collections::HashMap;

use rns_core::packet::RawPacket;
use rns_core::transport::types::{InterfaceId, TransportAction, TransportConfig};
use rns_core::transport::TransportEngine;
use rns_crypto::{OsRng, Rng};

#[cfg(feature = "rns-hooks")]
use rns_hooks::{
    create_hook_slots, EngineAccess, HookContext, HookManager, HookPoint, HookSlot,
};

use crate::event::{
    BlackholeInfo, Event, EventReceiver, InterfaceStatsResponse,
    LocalDestinationEntry, NextHopResponse, PathTableEntry, QueryRequest, QueryResponse,
    RateTableEntry, SingleInterfaceStat,
};
use crate::ifac;
use crate::interface::{InterfaceEntry, InterfaceStats};
use crate::link_manager::{LinkManager, LinkManagerAction};
use crate::holepunch::orchestrator::{HolePunchManager, HolePunchManagerAction};
use crate::time;

/// Thin wrapper providing `EngineAccess` for a `TransportEngine` + Driver interfaces.
#[cfg(feature = "rns-hooks")]
struct EngineRef<'a> {
    engine: &'a TransportEngine,
    interfaces: &'a HashMap<InterfaceId, InterfaceEntry>,
    link_manager: &'a LinkManager,
    now: f64,
}

#[cfg(feature = "rns-hooks")]
impl<'a> EngineAccess for EngineRef<'a> {
    fn has_path(&self, dest: &[u8; 16]) -> bool {
        self.engine.has_path(dest)
    }
    fn hops_to(&self, dest: &[u8; 16]) -> Option<u8> {
        self.engine.hops_to(dest)
    }
    fn next_hop(&self, dest: &[u8; 16]) -> Option<[u8; 16]> {
        self.engine.next_hop(dest)
    }
    fn is_blackholed(&self, identity: &[u8; 16]) -> bool {
        self.engine.is_blackholed(identity, self.now)
    }
    fn interface_name(&self, id: u64) -> Option<String> {
        self.interfaces
            .get(&InterfaceId(id))
            .map(|e| e.info.name.clone())
    }
    fn interface_mode(&self, id: u64) -> Option<u8> {
        self.interfaces
            .get(&InterfaceId(id))
            .map(|e| e.info.mode)
    }
    fn identity_hash(&self) -> Option<[u8; 16]> {
        self.engine.identity_hash().copied()
    }
    fn announce_rate(&self, id: u64) -> Option<i32> {
        self.interfaces
            .get(&InterfaceId(id))
            .map(|e| (e.stats.outgoing_announce_freq() * 1000.0) as i32)
    }
    fn link_state(&self, link_hash: &[u8; 16]) -> Option<u8> {
        use rns_core::link::types::LinkState;
        self.link_manager.link_state(link_hash).map(|s| match s {
            LinkState::Pending => 0,
            LinkState::Handshake => 1,
            LinkState::Active => 2,
            LinkState::Stale => 3,
            LinkState::Closed => 4,
        })
    }
}

/// Extract the 16-byte destination hash from a raw packet header.
///
/// HEADER_1 (raw[0] & 0x40 == 0): dest at bytes 2..18
/// HEADER_2 (raw[0] & 0x40 != 0): dest at bytes 18..34 (after transport ID)
#[cfg(any(test, feature = "rns-hooks"))]
fn extract_dest_hash(raw: &[u8]) -> [u8; 16] {
    let mut dest = [0u8; 16];
    if raw.is_empty() {
        return dest;
    }
    let is_header2 = raw[0] & 0x40 != 0;
    let start = if is_header2 { 18 } else { 2 };
    let end = start + 16;
    if raw.len() >= end {
        dest.copy_from_slice(&raw[start..end]);
    }
    dest
}

/// Execute a hook chain on disjoint Driver fields (avoids &mut self borrow conflict).
#[cfg(feature = "rns-hooks")]
fn run_hook_inner(
    programs: &mut [rns_hooks::LoadedProgram],
    hook_manager: &Option<HookManager>,
    engine_access: &dyn EngineAccess,
    ctx: &HookContext,
    now: f64,
) -> Option<rns_hooks::ExecuteResult> {
    if programs.is_empty() {
        return None;
    }
    let mgr = hook_manager.as_ref()?;
    mgr.run_chain(programs, ctx, engine_access, now)
}

/// Convert a Vec of ActionWire into TransportActions for dispatch.
#[cfg(feature = "rns-hooks")]
fn convert_injected_actions(actions: Vec<rns_hooks::ActionWire>) -> Vec<TransportAction> {
    actions
        .into_iter()
        .map(|a| {
            use rns_hooks::ActionWire;
            match a {
                ActionWire::SendOnInterface { interface, raw } => {
                    TransportAction::SendOnInterface {
                        interface: InterfaceId(interface),
                        raw,
                    }
                }
                ActionWire::BroadcastOnAllInterfaces { raw, exclude, has_exclude } => {
                    TransportAction::BroadcastOnAllInterfaces {
                        raw,
                        exclude: if has_exclude != 0 { Some(InterfaceId(exclude)) } else { None },
                    }
                }
                ActionWire::DeliverLocal { destination_hash, raw, packet_hash, receiving_interface } => {
                    TransportAction::DeliverLocal {
                        destination_hash,
                        raw,
                        packet_hash,
                        receiving_interface: InterfaceId(receiving_interface),
                    }
                }
                ActionWire::PathUpdated { destination_hash, hops, next_hop, interface } => {
                    TransportAction::PathUpdated {
                        destination_hash,
                        hops,
                        next_hop,
                        interface: InterfaceId(interface),
                    }
                }
                ActionWire::CacheAnnounce { packet_hash, raw } => {
                    TransportAction::CacheAnnounce { packet_hash, raw }
                }
                ActionWire::TunnelEstablished { tunnel_id, interface } => {
                    TransportAction::TunnelEstablished {
                        tunnel_id,
                        interface: InterfaceId(interface),
                    }
                }
                ActionWire::TunnelSynthesize { interface, data, dest_hash } => {
                    TransportAction::TunnelSynthesize {
                        interface: InterfaceId(interface),
                        data,
                        dest_hash,
                    }
                }
                ActionWire::ForwardToLocalClients { raw, exclude, has_exclude } => {
                    TransportAction::ForwardToLocalClients {
                        raw,
                        exclude: if has_exclude != 0 { Some(InterfaceId(exclude)) } else { None },
                    }
                }
                ActionWire::ForwardPlainBroadcast { raw, to_local, exclude, has_exclude } => {
                    TransportAction::ForwardPlainBroadcast {
                        raw,
                        to_local: to_local != 0,
                        exclude: if has_exclude != 0 { Some(InterfaceId(exclude)) } else { None },
                    }
                }
                ActionWire::AnnounceReceived {
                    destination_hash, identity_hash, public_key,
                    name_hash, random_hash, app_data, hops, receiving_interface,
                } => {
                    TransportAction::AnnounceReceived {
                        destination_hash,
                        identity_hash,
                        public_key,
                        name_hash,
                        random_hash,
                        app_data,
                        hops,
                        receiving_interface: InterfaceId(receiving_interface),
                    }
                }
            }
        })
        .collect()
}

/// Infer the interface type string from a dynamic interface's name.
/// Dynamic interfaces (TCP server clients, backbone peers, auto peers, local server clients)
/// include their type in the name prefix set at construction.
fn infer_interface_type(name: &str) -> String {
    if name.starts_with("TCPServerInterface") {
        "TCPServerClientInterface".to_string()
    } else if name.starts_with("BackboneInterface") {
        "BackboneInterface".to_string()
    } else if name.starts_with("LocalInterface") {
        "LocalServerClientInterface".to_string()
    } else {
        // AutoInterface peers use "{group_name}:{peer_addr}" format where
        // group_name is the config section name (typically "AutoInterface" or similar).
        "AutoInterface".to_string()
    }
}

/// Callbacks for events the driver produces.
///
/// All identifiers use typed wrappers (`DestHash`, `IdentityHash`, `LinkId`, `PacketHash`)
/// for compile-time safety.
pub trait Callbacks: Send {
    fn on_announce(
        &mut self,
        announced: crate::destination::AnnouncedIdentity,
    );

    fn on_path_updated(&mut self, dest_hash: rns_core::types::DestHash, hops: u8);

    fn on_local_delivery(&mut self, dest_hash: rns_core::types::DestHash, raw: Vec<u8>, packet_hash: rns_core::types::PacketHash);

    /// Called when an interface comes online.
    fn on_interface_up(&mut self, _id: InterfaceId) {}

    /// Called when an interface goes offline.
    fn on_interface_down(&mut self, _id: InterfaceId) {}

    /// Called when a link is fully established.
    fn on_link_established(&mut self, _link_id: rns_core::types::LinkId, _dest_hash: rns_core::types::DestHash, _rtt: f64, _is_initiator: bool) {}

    /// Called when a link is closed.
    fn on_link_closed(&mut self, _link_id: rns_core::types::LinkId, _reason: Option<rns_core::link::TeardownReason>) {}

    /// Called when a remote peer identifies on a link.
    fn on_remote_identified(&mut self, _link_id: rns_core::types::LinkId, _identity_hash: rns_core::types::IdentityHash, _public_key: [u8; 64]) {}

    /// Called when a resource transfer delivers data.
    fn on_resource_received(&mut self, _link_id: rns_core::types::LinkId, _data: Vec<u8>, _metadata: Option<Vec<u8>>) {}

    /// Called when a resource transfer completes (sender-side proof validated).
    fn on_resource_completed(&mut self, _link_id: rns_core::types::LinkId) {}

    /// Called when a resource transfer fails.
    fn on_resource_failed(&mut self, _link_id: rns_core::types::LinkId, _error: String) {}

    /// Called with resource transfer progress updates.
    fn on_resource_progress(&mut self, _link_id: rns_core::types::LinkId, _received: usize, _total: usize) {}

    /// Called to ask whether to accept an incoming resource (for AcceptApp strategy).
    /// Return true to accept, false to reject.
    fn on_resource_accept_query(&mut self, _link_id: rns_core::types::LinkId, _resource_hash: Vec<u8>, _transfer_size: u64, _has_metadata: bool) -> bool {
        false
    }

    /// Called when a channel message is received on a link.
    fn on_channel_message(&mut self, _link_id: rns_core::types::LinkId, _msgtype: u16, _payload: Vec<u8>) {}

    /// Called when generic link data is received.
    fn on_link_data(&mut self, _link_id: rns_core::types::LinkId, _context: u8, _data: Vec<u8>) {}

    /// Called when a response is received on a link.
    fn on_response(&mut self, _link_id: rns_core::types::LinkId, _request_id: [u8; 16], _data: Vec<u8>) {}

    /// Called when a delivery proof is received for a packet we sent.
    /// `rtt` is the round-trip time in seconds.
    fn on_proof(&mut self, _dest_hash: rns_core::types::DestHash, _packet_hash: rns_core::types::PacketHash, _rtt: f64) {}

    /// Called for ProveApp strategy: should we prove this incoming packet?
    /// Return true to generate and send a proof, false to skip.
    fn on_proof_requested(&mut self, _dest_hash: rns_core::types::DestHash, _packet_hash: rns_core::types::PacketHash) -> bool {
        true
    }

    /// Called when a direct connection is proposed by a peer (for AskApp policy).
    /// Return true to accept, false to reject.
    fn on_direct_connect_proposed(&mut self, _link_id: rns_core::types::LinkId, _peer_identity: Option<rns_core::types::IdentityHash>) -> bool {
        false
    }

    /// Called when a direct P2P connection is established via hole punching.
    fn on_direct_connect_established(&mut self, _link_id: rns_core::types::LinkId, _interface_id: InterfaceId) {}

    /// Called when a direct connection attempt fails.
    fn on_direct_connect_failed(&mut self, _link_id: rns_core::types::LinkId, _reason: u8) {}
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
    /// Cache of known announced identities, keyed by destination hash.
    pub(crate) known_destinations: HashMap<[u8; 16], crate::destination::AnnouncedIdentity>,
    /// Destination hash for rnstransport.path.request (PLAIN).
    pub(crate) path_request_dest: [u8; 16],
    /// Proof strategies per destination hash.
    /// Maps dest_hash → (strategy, optional signing identity for generating proofs).
    pub(crate) proof_strategies: HashMap<[u8; 16], (rns_core::types::ProofStrategy, Option<rns_crypto::identity::Identity>)>,
    /// Tracked sent packets for proof matching: packet_hash → (dest_hash, sent_time).
    pub(crate) sent_packets: HashMap<[u8; 32], ([u8; 16], f64)>,
    /// Locally registered destinations: hash → dest_type.
    pub(crate) local_destinations: HashMap<[u8; 16], u8>,
    /// Hole-punch manager for direct P2P connections.
    pub(crate) holepunch_manager: HolePunchManager,
    /// Event sender for worker threads to send results back to the driver loop.
    pub(crate) event_tx: crate::event::EventSender,
    /// Hook slots for the WASM hook system (one per HookPoint).
    #[cfg(feature = "rns-hooks")]
    pub(crate) hook_slots: [HookSlot; HookPoint::COUNT],
    /// WASM hook manager (runtime + linker). None if initialization failed.
    #[cfg(feature = "rns-hooks")]
    pub(crate) hook_manager: Option<HookManager>,
}

impl Driver {
    /// Create a new driver.
    pub fn new(
        config: TransportConfig,
        rx: EventReceiver,
        tx: crate::event::EventSender,
        callbacks: Box<dyn Callbacks>,
    ) -> Self {
        let tunnel_synth_dest = rns_core::destination::destination_hash(
            "rnstransport",
            &["tunnel", "synthesize"],
            None,
        );
        let path_request_dest = rns_core::destination::destination_hash(
            "rnstransport",
            &["path", "request"],
            None,
        );
        let mut engine = TransportEngine::new(config);
        engine.register_destination(tunnel_synth_dest, rns_core::constants::DESTINATION_PLAIN);
        // Register path request destination so inbound path requests are delivered locally
        engine.register_destination(path_request_dest, rns_core::constants::DESTINATION_PLAIN);
        let mut local_destinations = HashMap::new();
        local_destinations.insert(tunnel_synth_dest, rns_core::constants::DESTINATION_PLAIN);
        local_destinations.insert(path_request_dest, rns_core::constants::DESTINATION_PLAIN);
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
            known_destinations: HashMap::new(),
            path_request_dest,
            proof_strategies: HashMap::new(),
            sent_packets: HashMap::new(),
            local_destinations,
            holepunch_manager: HolePunchManager::new(None, None),
            event_tx: tx,
            #[cfg(feature = "rns-hooks")]
            hook_slots: create_hook_slots(),
            #[cfg(feature = "rns-hooks")]
            hook_manager: HookManager::new().ok(),
        }
    }

    /// Set the probe address and optional device for hole punching.
    pub fn set_probe_config(&mut self, addr: Option<std::net::SocketAddr>, device: Option<String>) {
        self.holepunch_manager = HolePunchManager::new(addr, device);
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

                    // PreIngress hook: after IFAC, before engine processing
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Packet(&rns_hooks::PacketContext {
                            flags: if packet.is_empty() { 0 } else { packet[0] },
                            hops: if packet.len() > 1 { packet[1] } else { 0 },
                            destination_hash: extract_dest_hash(&packet),
                            context: 0,
                            packet_hash: [0; 32],
                            interface_id: interface_id.0,
                            data_offset: 0,
                            data_len: packet.len() as u32,
                        });
                        let now = time::now();
                        let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                        {
                            let exec = run_hook_inner(&mut self.hook_slots[HookPoint::PreIngress as usize].programs, &self.hook_manager, &engine_ref, &ctx, now);
                            if let Some(ref e) = exec {
                                if !e.injected_actions.is_empty() {
                                    let extra = convert_injected_actions(e.injected_actions.clone());
                                    self.dispatch_all(extra);
                                }
                                if e.hook_result.as_ref().map_or(false, |r| r.is_drop()) {
                                    continue;
                                }
                            }
                        }
                    }

                    // Record incoming announce for frequency tracking (before engine processing)
                    if packet.len() > 2 && (packet[0] & 0x03) == 0x01 {
                        let now = time::now();
                        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
                            entry.stats.record_incoming_announce(now);
                        }
                    }

                    // Sync announce frequency to engine before processing
                    if let Some(entry) = self.interfaces.get(&interface_id) {
                        self.engine.update_interface_freq(interface_id, entry.stats.incoming_announce_freq());
                    }

                    let actions = self.engine.handle_inbound(
                        &packet,
                        interface_id,
                        time::now(),
                        &mut self.rng,
                    );

                    // PreDispatch hook: after engine, before action dispatch
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Packet(&rns_hooks::PacketContext {
                            flags: if packet.is_empty() { 0 } else { packet[0] },
                            hops: if packet.len() > 1 { packet[1] } else { 0 },
                            destination_hash: extract_dest_hash(&packet),
                            context: 0,
                            packet_hash: [0; 32],
                            interface_id: interface_id.0,
                            data_offset: 0,
                            data_len: packet.len() as u32,
                        });
                        let now = time::now();
                        let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                        if let Some(ref e) = run_hook_inner(&mut self.hook_slots[HookPoint::PreDispatch as usize].programs, &self.hook_manager, &engine_ref, &ctx, now) {
                            if !e.injected_actions.is_empty() { self.dispatch_all(convert_injected_actions(e.injected_actions.clone())); }
                        }
                    }

                    self.dispatch_all(actions);
                }
                Event::Tick => {
                    // Tick hook
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Tick;
                        let now = time::now();
                        let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                        if let Some(ref e) = run_hook_inner(&mut self.hook_slots[HookPoint::Tick as usize].programs, &self.hook_manager, &engine_ref, &ctx, now) {
                            if !e.injected_actions.is_empty() { self.dispatch_all(convert_injected_actions(e.injected_actions.clone())); }
                        }
                    }

                    let now = time::now();
                    // Sync announce frequency to engine for all interfaces before tick
                    for (id, entry) in &self.interfaces {
                        self.engine.update_interface_freq(*id, entry.stats.incoming_announce_freq());
                    }
                    let actions = self.engine.tick(now, &mut self.rng);
                    self.dispatch_all(actions);
                    // Tick link manager (keepalive, stale, timeout)
                    let link_actions = self.link_manager.tick(&mut self.rng);
                    self.dispatch_link_actions(link_actions);
                    // Tick hole-punch manager
                    {
                        let tx = self.get_event_sender();
                        let hp_actions = self.holepunch_manager.tick(&tx);
                        self.dispatch_holepunch_actions(hp_actions);
                    }
                    // Emit management announces
                    self.tick_management_announces(now);
                    // Cull expired sent packet tracking entries (no proof received within 60s)
                    self.sent_packets.retain(|_, (_, sent_time)| now - *sent_time < 60.0);
                }
                Event::InterfaceUp(id, new_writer, info) => {
                    let wants_tunnel;
                    if let Some(mut info) = info {
                        // New dynamic interface (e.g., TCP server client connection)
                        log::info!("[{}] dynamic interface registered", id.0);
                        wants_tunnel = info.wants_tunnel;
                        let iface_type = infer_interface_type(&info.name);
                        // Set started time for ingress control age tracking
                        info.started = time::now();
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
                                    interface_type: iface_type,
                                },
                            );
                        }
                        self.callbacks.on_interface_up(id);
                        #[cfg(feature = "rns-hooks")]
                        {
                            let ctx = HookContext::Interface { interface_id: id.0 };
                            let now = time::now();
                            let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                            if let Some(ref e) = run_hook_inner(&mut self.hook_slots[HookPoint::InterfaceUp as usize].programs, &self.hook_manager, &engine_ref, &ctx, now) {
                                if !e.injected_actions.is_empty() { self.dispatch_all(convert_injected_actions(e.injected_actions.clone())); }
                            }
                        }
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
                        #[cfg(feature = "rns-hooks")]
                        {
                            let ctx = HookContext::Interface { interface_id: id.0 };
                            let now = time::now();
                            let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                            if let Some(ref e) = run_hook_inner(&mut self.hook_slots[HookPoint::InterfaceUp as usize].programs, &self.hook_manager, &engine_ref, &ctx, now) {
                                if !e.injected_actions.is_empty() { self.dispatch_all(convert_injected_actions(e.injected_actions.clone())); }
                            }
                        }
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
                        #[cfg(feature = "rns-hooks")]
                        {
                            let ctx = HookContext::Interface { interface_id: id.0 };
                            let now = time::now();
                            let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                            if let Some(ref e) = run_hook_inner(&mut self.hook_slots[HookPoint::InterfaceDown as usize].programs, &self.hook_manager, &engine_ref, &ctx, now) {
                                if !e.injected_actions.is_empty() { self.dispatch_all(convert_injected_actions(e.injected_actions.clone())); }
                            }
                        }
                    }
                }
                Event::SendOutbound { raw, dest_type, attached_interface } => {
                    match RawPacket::unpack(&raw) {
                        Ok(packet) => {
                            // Track sent DATA packets for proof matching
                            if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_DATA {
                                self.sent_packets.insert(
                                    packet.packet_hash,
                                    (packet.destination_hash, time::now()),
                                );
                            }
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
                    self.local_destinations.insert(dest_hash, dest_type);
                }
                Event::DeregisterDestination { dest_hash } => {
                    self.engine.deregister_destination(&dest_hash);
                    self.local_destinations.remove(&dest_hash);
                }
                Event::Query(request, response_tx) => {
                    let response = self.handle_query_mut(request);
                    let _ = response_tx.send(response);
                }
                Event::DeregisterLinkDestination { dest_hash } => {
                    self.link_manager.deregister_link_destination(&dest_hash);
                }
                Event::RegisterLinkDestination { dest_hash, sig_prv_bytes, sig_pub_bytes } => {
                    let sig_prv = rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&sig_prv_bytes);
                    self.link_manager.register_link_destination(dest_hash, sig_prv, sig_pub_bytes);
                    // Also register in transport engine so inbound packets are delivered locally
                    self.engine.register_destination(dest_hash, rns_core::constants::DESTINATION_SINGLE);
                    self.local_destinations.insert(dest_hash, rns_core::constants::DESTINATION_SINGLE);
                }
                Event::RegisterRequestHandler { path, allowed_list, handler } => {
                    self.link_manager.register_request_handler(&path, allowed_list, move |link_id, p, data, remote| {
                        handler(link_id, p, data, remote)
                    });
                }
                Event::CreateLink { dest_hash, dest_sig_pub_bytes, response_tx } => {
                    let hops = self.engine.hops_to(&dest_hash).unwrap_or(0);
                    let mtu = self.engine.next_hop_interface(&dest_hash)
                        .and_then(|iface_id| self.interfaces.get(&iface_id))
                        .map(|entry| entry.info.mtu)
                        .unwrap_or(rns_core::constants::MTU as u32);
                    let (link_id, link_actions) = self.link_manager.create_link(
                        &dest_hash, &dest_sig_pub_bytes, hops, mtu, &mut self.rng,
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
                Event::RequestPath { dest_hash } => {
                    self.handle_request_path(dest_hash);
                }
                Event::RegisterProofStrategy { dest_hash, strategy, signing_key } => {
                    let identity = signing_key.map(|key| {
                        rns_crypto::identity::Identity::from_private_key(&key)
                    });
                    self.proof_strategies.insert(dest_hash, (strategy, identity));
                }
                Event::ProposeDirectConnect { link_id } => {
                    let derived_key = self.link_manager.get_derived_key(&link_id);
                    if let Some(dk) = derived_key {
                        let tx = self.get_event_sender();
                        let hp_actions = self.holepunch_manager.propose(
                            link_id, &dk, &mut self.rng, &tx,
                        );
                        self.dispatch_holepunch_actions(hp_actions);
                    } else {
                        log::warn!("Cannot propose direct connect: no derived key for link {:02x?}", &link_id[..4]);
                    }
                }
                Event::SetDirectConnectPolicy { policy } => {
                    self.holepunch_manager.set_policy(policy);
                }
                Event::HolePunchProbeResult { link_id, session_id, observed_addr, socket } => {
                    let hp_actions = self.holepunch_manager.handle_probe_result(
                        link_id, session_id, observed_addr, socket,
                    );
                    self.dispatch_holepunch_actions(hp_actions);
                }
                Event::HolePunchProbeFailed { link_id, session_id } => {
                    let hp_actions = self.holepunch_manager.handle_probe_failed(
                        link_id, session_id,
                    );
                    self.dispatch_holepunch_actions(hp_actions);
                }
                Event::LoadHook { name, wasm_bytes, attach_point, priority, response_tx } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let result = (|| -> Result<(), String> {
                            let point_idx = crate::config::parse_hook_point(&attach_point)
                                .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                            let mgr = self.hook_manager.as_ref()
                                .ok_or_else(|| "hook manager not available".to_string())?;
                            let program = mgr.compile(name.clone(), &wasm_bytes, priority)
                                .map_err(|e| format!("compile error: {}", e))?;
                            self.hook_slots[point_idx].attach(program);
                            log::info!("Loaded hook '{}' at point {} (priority {})", name, attach_point, priority);
                            Ok(())
                        })();
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (name, wasm_bytes, attach_point, priority);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::UnloadHook { name, attach_point, response_tx } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let result = (|| -> Result<(), String> {
                            let point_idx = crate::config::parse_hook_point(&attach_point)
                                .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                            match self.hook_slots[point_idx].detach(&name) {
                                Some(_) => {
                                    log::info!("Unloaded hook '{}' from point {}", name, attach_point);
                                    Ok(())
                                }
                                None => Err(format!("hook '{}' not found at point '{}'", name, attach_point)),
                            }
                        })();
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (name, attach_point);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::ReloadHook { name, attach_point, wasm_bytes, response_tx } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let result = (|| -> Result<(), String> {
                            let point_idx = crate::config::parse_hook_point(&attach_point)
                                .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                            let old = self.hook_slots[point_idx].detach(&name)
                                .ok_or_else(|| format!("hook '{}' not found at point '{}'", name, attach_point))?;
                            let priority = old.priority;
                            let mgr = match self.hook_manager.as_ref() {
                                Some(m) => m,
                                None => {
                                    self.hook_slots[point_idx].attach(old);
                                    return Err("hook manager not available".to_string());
                                }
                            };
                            match mgr.compile(name.clone(), &wasm_bytes, priority) {
                                Ok(program) => {
                                    self.hook_slots[point_idx].attach(program);
                                    log::info!("Reloaded hook '{}' at point {} (priority {})", name, attach_point, priority);
                                    Ok(())
                                }
                                Err(e) => {
                                    self.hook_slots[point_idx].attach(old);
                                    Err(format!("compile error: {}", e))
                                }
                            }
                        })();
                        let _ = response_tx.send(result);
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (name, attach_point, wasm_bytes);
                        let _ = response_tx.send(Err("hooks not enabled".to_string()));
                    }
                }
                Event::ListHooks { response_tx } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let hook_point_names = [
                            "PreIngress", "PreDispatch", "AnnounceReceived", "PathUpdated",
                            "AnnounceRetransmit", "LinkRequestReceived", "LinkEstablished",
                            "LinkClosed", "InterfaceUp", "InterfaceDown", "InterfaceConfigChanged",
                            "SendOnInterface", "BroadcastOnAllInterfaces", "DeliverLocal",
                            "TunnelSynthesize", "Tick",
                        ];
                        let mut infos = Vec::new();
                        for (idx, slot) in self.hook_slots.iter().enumerate() {
                            let point_name = hook_point_names.get(idx).unwrap_or(&"Unknown");
                            for prog in &slot.programs {
                                infos.push(crate::event::HookInfo {
                                    name: prog.name.clone(),
                                    attach_point: point_name.to_string(),
                                    priority: prog.priority,
                                    enabled: prog.enabled,
                                    consecutive_traps: prog.consecutive_traps,
                                });
                            }
                        }
                        let _ = response_tx.send(infos);
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = response_tx.send(Vec::new());
                    }
                }
                Event::InterfaceConfigChanged(id) => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Interface { interface_id: id.0 };
                        let now = time::now();
                        let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                        if let Some(ref e) = run_hook_inner(&mut self.hook_slots[HookPoint::InterfaceConfigChanged as usize].programs, &self.hook_manager, &engine_ref, &ctx, now) {
                            if !e.injected_actions.is_empty() { self.dispatch_all(convert_injected_actions(e.injected_actions.clone())); }
                        }
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    let _ = id;
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
                        interface_type: entry.interface_type.clone(),
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
            QueryRequest::HasPath { dest_hash } => {
                QueryResponse::HasPath(self.engine.has_path(&dest_hash))
            }
            QueryRequest::HopsTo { dest_hash } => {
                QueryResponse::HopsTo(self.engine.hops_to(&dest_hash))
            }
            QueryRequest::RecallIdentity { dest_hash } => {
                QueryResponse::RecallIdentity(self.known_destinations.get(&dest_hash).cloned())
            }
            QueryRequest::LocalDestinations => {
                let entries: Vec<LocalDestinationEntry> = self
                    .local_destinations
                    .iter()
                    .map(|(hash, dest_type)| LocalDestinationEntry {
                        hash: *hash,
                        dest_type: *dest_type,
                    })
                    .collect();
                QueryResponse::LocalDestinations(entries)
            }
            QueryRequest::Links => {
                QueryResponse::Links(self.link_manager.link_entries())
            }
            QueryRequest::Resources => {
                QueryResponse::Resources(self.link_manager.resource_entries())
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

    /// Build and send a path request packet for a destination.
    fn handle_request_path(&mut self, dest_hash: [u8; 16]) {
        // Build path request data: dest_hash(16) || [transport_id(16)] || random_tag(16)
        let mut data = Vec::with_capacity(48);
        data.extend_from_slice(&dest_hash);

        if self.engine.transport_enabled() {
            if let Some(id_hash) = self.engine.identity_hash() {
                data.extend_from_slice(id_hash);
            }
        }

        // Random tag (16 bytes)
        let mut tag = [0u8; 16];
        self.rng.fill_bytes(&mut tag);
        data.extend_from_slice(&tag);

        // Build as BROADCAST DATA PLAIN packet to rnstransport.path.request
        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: rns_core::constants::FLAG_UNSET,
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: rns_core::constants::DESTINATION_PLAIN,
            packet_type: rns_core::constants::PACKET_TYPE_DATA,
        };

        if let Ok(packet) = RawPacket::pack(
            flags, 0, &self.path_request_dest, None,
            rns_core::constants::CONTEXT_NONE, &data,
        ) {
            let actions = self.engine.handle_outbound(
                &packet,
                rns_core::constants::DESTINATION_PLAIN,
                None,
                time::now(),
            );
            self.dispatch_all(actions);
        }
    }

    /// Check if we should generate a proof for a delivered packet,
    /// and if so, sign and send it.
    fn maybe_generate_proof(&mut self, dest_hash: [u8; 16], packet_hash: &[u8; 32]) {
        use rns_core::types::ProofStrategy;

        let (strategy, identity) = match self.proof_strategies.get(&dest_hash) {
            Some((s, id)) => (*s, id.as_ref()),
            None => return,
        };

        let should_prove = match strategy {
            ProofStrategy::ProveAll => true,
            ProofStrategy::ProveApp => {
                self.callbacks.on_proof_requested(
                    rns_core::types::DestHash(dest_hash),
                    rns_core::types::PacketHash(*packet_hash),
                )
            }
            ProofStrategy::ProveNone => false,
        };

        if !should_prove {
            return;
        }

        let identity = match identity {
            Some(id) => id,
            None => {
                log::warn!("Cannot generate proof for {:02x?}: no signing key", &dest_hash[..4]);
                return;
            }
        };

        // Sign the packet hash to create the proof
        let signature = match identity.sign(packet_hash) {
            Ok(sig) => sig,
            Err(e) => {
                log::warn!("Failed to sign proof for {:02x?}: {:?}", &dest_hash[..4], e);
                return;
            }
        };

        // Build explicit proof: [packet_hash:32][signature:64]
        let mut proof_data = Vec::with_capacity(96);
        proof_data.extend_from_slice(packet_hash);
        proof_data.extend_from_slice(&signature);

        // Address the proof to the truncated packet hash (first 16 bytes),
        // matching Python's ProofDestination (Packet.py:390-394).
        // Transport nodes create reverse_table entries keyed by truncated
        // packet hash when forwarding data, so this allows proofs to be
        // routed back to the sender via the reverse path.
        let mut proof_dest = [0u8; 16];
        proof_dest.copy_from_slice(&packet_hash[..16]);

        let flags = rns_core::packet::PacketFlags {
            header_type: rns_core::constants::HEADER_1,
            context_flag: rns_core::constants::FLAG_UNSET,
            transport_type: rns_core::constants::TRANSPORT_BROADCAST,
            destination_type: rns_core::constants::DESTINATION_SINGLE,
            packet_type: rns_core::constants::PACKET_TYPE_PROOF,
        };

        if let Ok(packet) = RawPacket::pack(
            flags, 0, &proof_dest, None,
            rns_core::constants::CONTEXT_NONE, &proof_data,
        ) {
            let actions = self.engine.handle_outbound(
                &packet,
                rns_core::constants::DESTINATION_SINGLE,
                None,
                time::now(),
            );
            self.dispatch_all(actions);
            log::debug!("Generated proof for packet on dest {:02x?}", &dest_hash[..4]);
        }
    }

    /// Handle an inbound proof packet: validate and fire on_proof callback.
    fn handle_inbound_proof(&mut self, dest_hash: [u8; 16], proof_data: &[u8], _raw_packet_hash: &[u8; 32]) {
        // Explicit proof format: [packet_hash:32][signature:64] = 96 bytes
        if proof_data.len() < 96 {
            log::debug!("Proof too short for explicit proof: {} bytes", proof_data.len());
            return;
        }

        let mut tracked_hash = [0u8; 32];
        tracked_hash.copy_from_slice(&proof_data[..32]);

        let signature = &proof_data[32..96];

        // Look up the tracked sent packet
        if let Some((tracked_dest, sent_time)) = self.sent_packets.remove(&tracked_hash) {
            // Validate the proof signature using the destination's public key
            // (matches Python's PacketReceipt.validate_proof behavior)
            if let Some(announced) = self.known_destinations.get(&tracked_dest) {
                let identity = rns_crypto::identity::Identity::from_public_key(&announced.public_key);
                let mut sig = [0u8; 64];
                sig.copy_from_slice(signature);
                if !identity.verify(&sig, &tracked_hash) {
                    log::debug!(
                        "Proof signature invalid for {:02x?}",
                        &tracked_hash[..4],
                    );
                    return;
                }
            } else {
                log::debug!(
                    "No known identity for dest {:02x?}, accepting proof without signature check",
                    &tracked_dest[..4],
                );
            }

            let rtt = time::now() - sent_time;
            log::debug!(
                "Proof received for {:02x?} rtt={:.3}s",
                &tracked_hash[..4], rtt,
            );
            self.callbacks.on_proof(
                rns_core::types::DestHash(tracked_dest),
                rns_core::types::PacketHash(tracked_hash),
                rtt,
            );
        } else {
            log::debug!(
                "Proof for unknown packet {:02x?} on dest {:02x?}",
                &tracked_hash[..4], &dest_hash[..4],
            );
        }
    }

    /// Dispatch a list of transport actions.
    fn dispatch_all(&mut self, actions: Vec<TransportAction>) {
        #[cfg(feature = "rns-hooks")]
        let mut hook_injected: Vec<TransportAction> = Vec::new();

        for action in actions {
            match action {
                TransportAction::SendOnInterface { interface, raw } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let pkt_ctx = rns_hooks::PacketContext {
                            flags: if raw.is_empty() { 0 } else { raw[0] },
                            hops: if raw.len() > 1 { raw[1] } else { 0 },
                            destination_hash: extract_dest_hash(&raw),
                            context: 0,
                            packet_hash: [0; 32],
                            interface_id: interface.0,
                            data_offset: 0,
                            data_len: raw.len() as u32,
                        };
                        let ctx = HookContext::Packet(&pkt_ctx);
                        let now = time::now();
                        let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                        {
                            let exec = run_hook_inner(&mut self.hook_slots[HookPoint::SendOnInterface as usize].programs, &self.hook_manager, &engine_ref, &ctx, now);
                            if let Some(ref e) = exec {
                                if !e.injected_actions.is_empty() { hook_injected.extend(convert_injected_actions(e.injected_actions.clone())); }
                                if e.hook_result.as_ref().map_or(false, |r| r.is_drop()) { continue; }
                            }
                        }
                    }
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
                    #[cfg(feature = "rns-hooks")]
                    {
                        let pkt_ctx = rns_hooks::PacketContext {
                            flags: if raw.is_empty() { 0 } else { raw[0] },
                            hops: if raw.len() > 1 { raw[1] } else { 0 },
                            destination_hash: extract_dest_hash(&raw),
                            context: 0,
                            packet_hash: [0; 32],
                            interface_id: 0,
                            data_offset: 0,
                            data_len: raw.len() as u32,
                        };
                        let ctx = HookContext::Packet(&pkt_ctx);
                        let now = time::now();
                        let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                        {
                            let exec = run_hook_inner(&mut self.hook_slots[HookPoint::BroadcastOnAllInterfaces as usize].programs, &self.hook_manager, &engine_ref, &ctx, now);
                            if let Some(ref e) = exec {
                                if !e.injected_actions.is_empty() { hook_injected.extend(convert_injected_actions(e.injected_actions.clone())); }
                                if e.hook_result.as_ref().map_or(false, |r| r.is_drop()) { continue; }
                            }
                        }
                    }
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
                    receiving_interface,
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let pkt_ctx = rns_hooks::PacketContext {
                            flags: 0,
                            hops: 0,
                            destination_hash,
                            context: 0,
                            packet_hash,
                            interface_id: receiving_interface.0,
                            data_offset: 0,
                            data_len: raw.len() as u32,
                        };
                        let ctx = HookContext::Packet(&pkt_ctx);
                        let now = time::now();
                        let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                        {
                            let exec = run_hook_inner(&mut self.hook_slots[HookPoint::DeliverLocal as usize].programs, &self.hook_manager, &engine_ref, &ctx, now);
                            if let Some(ref e) = exec {
                                if !e.injected_actions.is_empty() { hook_injected.extend(convert_injected_actions(e.injected_actions.clone())); }
                                if e.hook_result.as_ref().map_or(false, |r| r.is_drop()) { continue; }
                            }
                        }
                    }
                    if destination_hash == self.tunnel_synth_dest {
                        // Tunnel synthesis packet — validate and handle
                        self.handle_tunnel_synth_delivery(&raw);
                    } else if destination_hash == self.path_request_dest {
                        // Path request packet — extract data and handle
                        if let Ok(packet) = RawPacket::unpack(&raw) {
                            let actions = self.engine.handle_path_request(
                                &packet.data,
                                InterfaceId(0), // no specific interface
                                time::now(),
                            );
                            self.dispatch_all(actions);
                        }
                    } else if self.link_manager.is_link_destination(&destination_hash) {
                        // Link-related packet — route to link manager
                        let link_actions = self.link_manager.handle_local_delivery(
                            destination_hash, &raw, packet_hash, receiving_interface, &mut self.rng,
                        );
                        if link_actions.is_empty() {
                            // Link manager couldn't handle (e.g. opportunistic DATA
                            // for a registered link destination). Fall back to
                            // regular delivery.
                            if let Ok(packet) = RawPacket::unpack(&raw) {
                                if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_PROOF {
                                    self.handle_inbound_proof(destination_hash, &packet.data, &packet_hash);
                                    continue;
                                }
                            }
                            self.maybe_generate_proof(destination_hash, &packet_hash);
                            self.callbacks.on_local_delivery(
                                rns_core::types::DestHash(destination_hash),
                                raw,
                                rns_core::types::PacketHash(packet_hash),
                            );
                        } else {
                            self.dispatch_link_actions(link_actions);
                        }
                    } else {
                        // Check if this is a PROOF packet for a packet we sent
                        if let Ok(packet) = RawPacket::unpack(&raw) {
                            if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_PROOF {
                                self.handle_inbound_proof(destination_hash, &packet.data, &packet_hash);
                                continue;
                            }
                        }

                        // Check if destination has a proof strategy — generate proof if needed
                        self.maybe_generate_proof(destination_hash, &packet_hash);

                        self.callbacks
                            .on_local_delivery(
                                rns_core::types::DestHash(destination_hash),
                                raw,
                                rns_core::types::PacketHash(packet_hash),
                            );
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
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Announce {
                            destination_hash,
                            hops,
                            interface_id: receiving_interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                        {
                            let exec = run_hook_inner(&mut self.hook_slots[HookPoint::AnnounceReceived as usize].programs, &self.hook_manager, &engine_ref, &ctx, now);
                            if let Some(ref e) = exec {
                                if !e.injected_actions.is_empty() { hook_injected.extend(convert_injected_actions(e.injected_actions.clone())); }
                                if e.hook_result.as_ref().map_or(false, |r| r.is_drop()) { continue; }
                            }
                        }
                    }
                    // Suppress unused variable warning when feature is off
                    #[cfg(not(feature = "rns-hooks"))]
                    let _ = receiving_interface;

                    // Cache the announced identity
                    let announced = crate::destination::AnnouncedIdentity {
                        dest_hash: rns_core::types::DestHash(destination_hash),
                        identity_hash: rns_core::types::IdentityHash(identity_hash),
                        public_key,
                        app_data: app_data.clone(),
                        hops,
                        received_at: time::now(),
                    };
                    self.known_destinations.insert(destination_hash, announced.clone());
                    self.callbacks.on_announce(announced);
                }
                TransportAction::PathUpdated {
                    destination_hash,
                    hops,
                    interface,
                    ..
                } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Announce {
                            destination_hash,
                            hops,
                            interface_id: interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                        if let Some(ref e) = run_hook_inner(&mut self.hook_slots[HookPoint::PathUpdated as usize].programs, &self.hook_manager, &engine_ref, &ctx, now) {
                            if !e.injected_actions.is_empty() { hook_injected.extend(convert_injected_actions(e.injected_actions.clone())); }
                        }
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    let _ = interface;

                    self.callbacks.on_path_updated(rns_core::types::DestHash(destination_hash), hops);
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
                    #[cfg(feature = "rns-hooks")]
                    {
                        let pkt_ctx = rns_hooks::PacketContext {
                            flags: 0,
                            hops: 0,
                            destination_hash: dest_hash,
                            context: 0,
                            packet_hash: [0; 32],
                            interface_id: interface.0,
                            data_offset: 0,
                            data_len: data.len() as u32,
                        };
                        let ctx = HookContext::Packet(&pkt_ctx);
                        let now = time::now();
                        let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                        {
                            let exec = run_hook_inner(&mut self.hook_slots[HookPoint::TunnelSynthesize as usize].programs, &self.hook_manager, &engine_ref, &ctx, now);
                            if let Some(ref e) = exec {
                                if !e.injected_actions.is_empty() { hook_injected.extend(convert_injected_actions(e.injected_actions.clone())); }
                                if e.hook_result.as_ref().map_or(false, |r| r.is_drop()) { continue; }
                            }
                        }
                    }
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
                TransportAction::AnnounceRetransmit { destination_hash, hops, interface } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Announce {
                            destination_hash,
                            hops,
                            interface_id: interface.map(|i| i.0).unwrap_or(0),
                        };
                        let now = time::now();
                        let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                        if let Some(ref e) = run_hook_inner(&mut self.hook_slots[HookPoint::AnnounceRetransmit as usize].programs, &self.hook_manager, &engine_ref, &ctx, now) {
                            if !e.injected_actions.is_empty() { hook_injected.extend(convert_injected_actions(e.injected_actions.clone())); }
                        }
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (destination_hash, hops, interface);
                    }
                }
                TransportAction::LinkRequestReceived { link_id, destination_hash: _, receiving_interface } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Link { link_id, interface_id: receiving_interface.0 };
                        let now = time::now();
                        let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                        if let Some(ref e) = run_hook_inner(&mut self.hook_slots[HookPoint::LinkRequestReceived as usize].programs, &self.hook_manager, &engine_ref, &ctx, now) {
                            if !e.injected_actions.is_empty() { hook_injected.extend(convert_injected_actions(e.injected_actions.clone())); }
                        }
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (link_id, receiving_interface);
                    }
                }
                TransportAction::LinkEstablished { link_id, interface } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Link { link_id, interface_id: interface.0 };
                        let now = time::now();
                        let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                        if let Some(ref e) = run_hook_inner(&mut self.hook_slots[HookPoint::LinkEstablished as usize].programs, &self.hook_manager, &engine_ref, &ctx, now) {
                            if !e.injected_actions.is_empty() { hook_injected.extend(convert_injected_actions(e.injected_actions.clone())); }
                        }
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = (link_id, interface);
                    }
                }
                TransportAction::LinkClosed { link_id } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Link { link_id, interface_id: 0 };
                        let now = time::now();
                        let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                        if let Some(ref e) = run_hook_inner(&mut self.hook_slots[HookPoint::LinkClosed as usize].programs, &self.hook_manager, &engine_ref, &ctx, now) {
                            if !e.injected_actions.is_empty() { hook_injected.extend(convert_injected_actions(e.injected_actions.clone())); }
                        }
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    {
                        let _ = link_id;
                    }
                }
            }
        }

        // Dispatch any actions injected by hooks during action processing
        #[cfg(feature = "rns-hooks")]
        if !hook_injected.is_empty() {
            self.dispatch_all(hook_injected);
        }
    }

    /// Dispatch link manager actions.
    fn dispatch_link_actions(&mut self, actions: Vec<LinkManagerAction>) {
        #[cfg(feature = "rns-hooks")]
        let mut hook_injected: Vec<TransportAction> = Vec::new();

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
                LinkManagerAction::LinkEstablished { link_id, dest_hash, rtt, is_initiator } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Link { link_id, interface_id: 0 };
                        let now = time::now();
                        let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                        if let Some(ref e) = run_hook_inner(&mut self.hook_slots[HookPoint::LinkEstablished as usize].programs, &self.hook_manager, &engine_ref, &ctx, now) {
                            if !e.injected_actions.is_empty() { hook_injected.extend(convert_injected_actions(e.injected_actions.clone())); }
                        }
                    }
                    log::info!(
                        "Link established: {:02x?} rtt={:.3}s initiator={}",
                        &link_id[..4], rtt, is_initiator,
                    );
                    self.callbacks.on_link_established(
                        rns_core::types::LinkId(link_id),
                        rns_core::types::DestHash(dest_hash),
                        rtt,
                        is_initiator,
                    );
                }
                LinkManagerAction::LinkClosed { link_id, reason } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Link { link_id, interface_id: 0 };
                        let now = time::now();
                        let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                        if let Some(ref e) = run_hook_inner(&mut self.hook_slots[HookPoint::LinkClosed as usize].programs, &self.hook_manager, &engine_ref, &ctx, now) {
                            if !e.injected_actions.is_empty() { hook_injected.extend(convert_injected_actions(e.injected_actions.clone())); }
                        }
                    }
                    log::info!("Link closed: {:02x?} reason={:?}", &link_id[..4], reason);
                    self.holepunch_manager.link_closed(&link_id);
                    self.callbacks.on_link_closed(rns_core::types::LinkId(link_id), reason);
                }
                LinkManagerAction::RemoteIdentified { link_id, identity_hash, public_key } => {
                    log::debug!(
                        "Remote identified on link {:02x?}: {:02x?}",
                        &link_id[..4], &identity_hash[..4],
                    );
                    self.callbacks.on_remote_identified(
                        rns_core::types::LinkId(link_id),
                        rns_core::types::IdentityHash(identity_hash),
                        public_key,
                    );
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
                    self.callbacks.on_resource_received(rns_core::types::LinkId(link_id), data, metadata);
                }
                LinkManagerAction::ResourceCompleted { link_id } => {
                    self.callbacks.on_resource_completed(rns_core::types::LinkId(link_id));
                }
                LinkManagerAction::ResourceFailed { link_id, error } => {
                    log::debug!("Resource failed on link {:02x?}: {}", &link_id[..4], error);
                    self.callbacks.on_resource_failed(rns_core::types::LinkId(link_id), error);
                }
                LinkManagerAction::ResourceProgress { link_id, received, total } => {
                    self.callbacks.on_resource_progress(rns_core::types::LinkId(link_id), received, total);
                }
                LinkManagerAction::ResourceAcceptQuery { link_id, resource_hash, transfer_size, has_metadata } => {
                    let accept = self.callbacks.on_resource_accept_query(
                        rns_core::types::LinkId(link_id), resource_hash.clone(), transfer_size, has_metadata,
                    );
                    let accept_actions = self.link_manager.accept_resource(
                        &link_id, &resource_hash, accept, &mut self.rng,
                    );
                    // Re-dispatch (recursive but bounded: accept_resource won't produce more AcceptQuery)
                    self.dispatch_link_actions(accept_actions);
                }
                LinkManagerAction::ChannelMessageReceived { link_id, msgtype, payload } => {
                    // Intercept hole-punch signaling messages (0xFE00..=0xFE04)
                    if HolePunchManager::is_holepunch_message(msgtype) {
                        let derived_key = self.link_manager.get_derived_key(&link_id);
                        let tx = self.get_event_sender();
                        let (handled, hp_actions) = self.holepunch_manager.handle_signal(
                            link_id, msgtype, payload, derived_key.as_deref(), &tx,
                        );
                        if handled {
                            self.dispatch_holepunch_actions(hp_actions);
                        }
                    } else {
                        self.callbacks.on_channel_message(rns_core::types::LinkId(link_id), msgtype, payload);
                    }
                }
                LinkManagerAction::LinkDataReceived { link_id, context, data } => {
                    self.callbacks.on_link_data(rns_core::types::LinkId(link_id), context, data);
                }
                LinkManagerAction::ResponseReceived { link_id, request_id, data } => {
                    self.callbacks.on_response(rns_core::types::LinkId(link_id), request_id, data);
                }
                LinkManagerAction::LinkRequestReceived { link_id, receiving_interface } => {
                    #[cfg(feature = "rns-hooks")]
                    {
                        let ctx = HookContext::Link { link_id, interface_id: receiving_interface.0 };
                        let now = time::now();
                        let engine_ref = EngineRef { engine: &self.engine, interfaces: &self.interfaces, link_manager: &self.link_manager, now };
                        if let Some(ref e) = run_hook_inner(&mut self.hook_slots[HookPoint::LinkRequestReceived as usize].programs, &self.hook_manager, &engine_ref, &ctx, now) {
                            if !e.injected_actions.is_empty() { hook_injected.extend(convert_injected_actions(e.injected_actions.clone())); }
                        }
                    }
                    #[cfg(not(feature = "rns-hooks"))]
                    { let _ = (link_id, receiving_interface); }
                }
            }
        }

        // Dispatch any actions injected by hooks during action processing
        #[cfg(feature = "rns-hooks")]
        if !hook_injected.is_empty() {
            self.dispatch_all(hook_injected);
        }
    }

    /// Dispatch hole-punch manager actions.
    fn dispatch_holepunch_actions(&mut self, actions: Vec<HolePunchManagerAction>) {
        for action in actions {
            match action {
                HolePunchManagerAction::SendChannelMessage { link_id, msgtype, payload } => {
                    let link_actions = self.link_manager.send_channel_message(
                        &link_id, msgtype, &payload, &mut self.rng,
                    );
                    self.dispatch_link_actions(link_actions);
                }
                HolePunchManagerAction::DirectConnectEstablished { link_id, session_id, interface_id, rtt, mtu } => {
                    log::info!(
                        "Direct connection established for link {:02x?} session {:02x?} iface {} rtt={:.1}ms mtu={}",
                        &link_id[..4], &session_id[..4], interface_id.0, rtt * 1000.0, mtu
                    );
                    // Redirect the link's path to use the direct interface
                    self.engine.redirect_path(&link_id, interface_id, time::now());
                    // Update the link's RTT and MTU to reflect the direct path
                    self.link_manager.set_link_rtt(&link_id, rtt);
                    self.link_manager.set_link_mtu(&link_id, mtu);
                    // Reset inbound timer — set_rtt shortens the keepalive/stale
                    // intervals, so without this the link goes stale immediately
                    self.link_manager.record_link_inbound(&link_id);
                    // Flush holepunch signaling messages from the channel window
                    self.link_manager.flush_channel_tx(&link_id);
                    self.callbacks.on_direct_connect_established(
                        rns_core::types::LinkId(link_id),
                        interface_id,
                    );
                }
                HolePunchManagerAction::DirectConnectFailed { link_id, session_id, reason } => {
                    log::debug!(
                        "Direct connection failed for link {:02x?} session {:02x?} reason={}",
                        &link_id[..4], &session_id[..4], reason
                    );
                    self.callbacks.on_direct_connect_failed(
                        rns_core::types::LinkId(link_id),
                        reason,
                    );
                }
            }
        }
    }

    /// Get an event sender for worker threads to send results back to the driver.
    ///
    /// This is a bit of a workaround since the driver owns the receiver.
    /// We store a clone of the sender when the driver is created.
    fn get_event_sender(&self) -> crate::event::EventSender {
        // The driver doesn't directly have a sender, but node.rs creates the channel
        // and passes rx to the driver. We need to store a sender clone.
        // For now we use an internal sender that was set during construction.
        self.event_tx.clone()
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

    use rns_core::types::{DestHash, IdentityHash, LinkId as TypedLinkId, PacketHash};

    struct MockCallbacks {
        announces: Arc<Mutex<Vec<(DestHash, u8)>>>,
        paths: Arc<Mutex<Vec<(DestHash, u8)>>>,
        deliveries: Arc<Mutex<Vec<DestHash>>>,
        iface_ups: Arc<Mutex<Vec<InterfaceId>>>,
        iface_downs: Arc<Mutex<Vec<InterfaceId>>>,
        link_established: Arc<Mutex<Vec<(TypedLinkId, f64, bool)>>>,
        link_closed: Arc<Mutex<Vec<TypedLinkId>>>,
        remote_identified: Arc<Mutex<Vec<(TypedLinkId, IdentityHash)>>>,
        resources_received: Arc<Mutex<Vec<(TypedLinkId, Vec<u8>)>>>,
        resource_completed: Arc<Mutex<Vec<TypedLinkId>>>,
        resource_failed: Arc<Mutex<Vec<(TypedLinkId, String)>>>,
        channel_messages: Arc<Mutex<Vec<(TypedLinkId, u16, Vec<u8>)>>>,
        link_data: Arc<Mutex<Vec<(TypedLinkId, u8, Vec<u8>)>>>,
        responses: Arc<Mutex<Vec<(TypedLinkId, [u8; 16], Vec<u8>)>>>,
        proofs: Arc<Mutex<Vec<(DestHash, PacketHash, f64)>>>,
        proof_requested: Arc<Mutex<Vec<(DestHash, PacketHash)>>>,
    }

    impl MockCallbacks {
        fn new() -> (
            Self,
            Arc<Mutex<Vec<(DestHash, u8)>>>,
            Arc<Mutex<Vec<(DestHash, u8)>>>,
            Arc<Mutex<Vec<DestHash>>>,
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
                    proofs: Arc::new(Mutex::new(Vec::new())),
                    proof_requested: Arc::new(Mutex::new(Vec::new())),
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
            Arc<Mutex<Vec<(TypedLinkId, f64, bool)>>>,
            Arc<Mutex<Vec<TypedLinkId>>>,
            Arc<Mutex<Vec<(TypedLinkId, IdentityHash)>>>,
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
                    proofs: Arc::new(Mutex::new(Vec::new())),
                    proof_requested: Arc::new(Mutex::new(Vec::new())),
                },
                link_established,
                link_closed,
                remote_identified,
            )
        }
    }

    impl Callbacks for MockCallbacks {
        fn on_announce(&mut self, announced: crate::destination::AnnouncedIdentity) {
            self.announces.lock().unwrap().push((announced.dest_hash, announced.hops));
        }

        fn on_path_updated(&mut self, dest_hash: DestHash, hops: u8) {
            self.paths.lock().unwrap().push((dest_hash, hops));
        }

        fn on_local_delivery(&mut self, dest_hash: DestHash, _raw: Vec<u8>, _packet_hash: PacketHash) {
            self.deliveries.lock().unwrap().push(dest_hash);
        }

        fn on_interface_up(&mut self, id: InterfaceId) {
            self.iface_ups.lock().unwrap().push(id);
        }

        fn on_interface_down(&mut self, id: InterfaceId) {
            self.iface_downs.lock().unwrap().push(id);
        }

        fn on_link_established(&mut self, link_id: TypedLinkId, _dest_hash: DestHash, rtt: f64, is_initiator: bool) {
            self.link_established.lock().unwrap().push((link_id, rtt, is_initiator));
        }

        fn on_link_closed(&mut self, link_id: TypedLinkId, _reason: Option<rns_core::link::TeardownReason>) {
            self.link_closed.lock().unwrap().push(link_id);
        }

        fn on_remote_identified(&mut self, link_id: TypedLinkId, identity_hash: IdentityHash, _public_key: [u8; 64]) {
            self.remote_identified.lock().unwrap().push((link_id, identity_hash));
        }

        fn on_resource_received(&mut self, link_id: TypedLinkId, data: Vec<u8>, _metadata: Option<Vec<u8>>) {
            self.resources_received.lock().unwrap().push((link_id, data));
        }

        fn on_resource_completed(&mut self, link_id: TypedLinkId) {
            self.resource_completed.lock().unwrap().push(link_id);
        }

        fn on_resource_failed(&mut self, link_id: TypedLinkId, error: String) {
            self.resource_failed.lock().unwrap().push((link_id, error));
        }

        fn on_channel_message(&mut self, link_id: TypedLinkId, msgtype: u16, payload: Vec<u8>) {
            self.channel_messages.lock().unwrap().push((link_id, msgtype, payload));
        }

        fn on_link_data(&mut self, link_id: TypedLinkId, context: u8, data: Vec<u8>) {
            self.link_data.lock().unwrap().push((link_id, context, data));
        }

        fn on_response(&mut self, link_id: TypedLinkId, request_id: [u8; 16], data: Vec<u8>) {
            self.responses.lock().unwrap().push((link_id, request_id, data));
        }

        fn on_proof(&mut self, dest_hash: DestHash, packet_hash: PacketHash, rtt: f64) {
            self.proofs.lock().unwrap().push((dest_hash, packet_hash, rtt));
        }

        fn on_proof_requested(&mut self, dest_hash: DestHash, packet_hash: PacketHash) -> bool {
            self.proof_requested.lock().unwrap().push((dest_hash, packet_hash));
            true
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
            mtu: constants::MTU as u32,
            ia_freq: 0.0,
            started: 0.0,
            ingress_control: false,
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
            interface_type: String::new(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            interface_type: String::new(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
        assert_eq!(deliveries.lock().unwrap()[0], DestHash(dest));
    }

    #[test]
    fn query_transport_identity() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: true, identity_hash: Some([0xAA; 16]) },
            rx,
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
        assert_eq!(link_closed.lock().unwrap()[0], TypedLinkId(link_id));
    }

    #[test]
    fn link_count_includes_link_manager() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Create a link via link_manager directly
        let mut rng = OsRng;
        let dummy_sig = [0xAA; 32];
        driver.link_manager.create_link(&[0xDD; 16], &dummy_sig, 1, constants::MTU as u32, &mut rng);

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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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
            tx.clone(),
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

    // =========================================================================
    // Phase 9c: Announce + Discovery tests
    // =========================================================================

    #[test]
    fn announce_received_populates_known_destinations() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);

        let dest_hash = rns_core::destination::destination_hash(
            "test", &["app"], Some(identity.hash()),
        );

        tx.send(Event::Frame { interface_id: InterfaceId(1), data: announce_raw }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // known_destinations should be populated
        assert!(driver.known_destinations.contains_key(&dest_hash));
        let recalled = &driver.known_destinations[&dest_hash];
        assert_eq!(recalled.dest_hash.0, dest_hash);
        assert_eq!(recalled.identity_hash.0, *identity.hash());
        assert_eq!(&recalled.public_key, &identity.get_public_key().unwrap());
        assert_eq!(recalled.hops, 1);
    }

    #[test]
    fn query_has_path() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // No path yet
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::HasPath { dest_hash: [0xAA; 16] }, resp_tx)).unwrap();

        // Feed an announce to create a path
        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);
        let dest_hash = rns_core::destination::destination_hash(
            "test", &["app"], Some(identity.hash()),
        );
        tx.send(Event::Frame { interface_id: InterfaceId(1), data: announce_raw }).unwrap();

        let (resp_tx2, resp_rx2) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::HasPath { dest_hash }, resp_tx2)).unwrap();

        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // First query — no path
        match resp_rx.recv().unwrap() {
            QueryResponse::HasPath(false) => {}
            other => panic!("expected HasPath(false), got {:?}", other),
        }

        // Second query — path exists
        match resp_rx2.recv().unwrap() {
            QueryResponse::HasPath(true) => {}
            other => panic!("expected HasPath(true), got {:?}", other),
        }
    }

    #[test]
    fn query_hops_to() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Feed an announce
        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);
        let dest_hash = rns_core::destination::destination_hash(
            "test", &["app"], Some(identity.hash()),
        );

        tx.send(Event::Frame { interface_id: InterfaceId(1), data: announce_raw }).unwrap();

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::HopsTo { dest_hash }, resp_tx)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::HopsTo(Some(1)) => {}
            other => panic!("expected HopsTo(Some(1)), got {:?}", other),
        }
    }

    #[test]
    fn query_recall_identity() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let identity = Identity::new(&mut OsRng);
        let announce_raw = build_announce_packet(&identity);
        let dest_hash = rns_core::destination::destination_hash(
            "test", &["app"], Some(identity.hash()),
        );

        tx.send(Event::Frame { interface_id: InterfaceId(1), data: announce_raw }).unwrap();

        // Recall identity
        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::RecallIdentity { dest_hash }, resp_tx)).unwrap();

        // Also recall unknown destination
        let (resp_tx2, resp_rx2) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::RecallIdentity { dest_hash: [0xFF; 16] }, resp_tx2)).unwrap();

        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::RecallIdentity(Some(recalled)) => {
                assert_eq!(recalled.dest_hash.0, dest_hash);
                assert_eq!(recalled.identity_hash.0, *identity.hash());
                assert_eq!(recalled.public_key, identity.get_public_key().unwrap());
                assert_eq!(recalled.hops, 1);
            }
            other => panic!("expected RecallIdentity(Some(..)), got {:?}", other),
        }

        match resp_rx2.recv().unwrap() {
            QueryResponse::RecallIdentity(None) => {}
            other => panic!("expected RecallIdentity(None), got {:?}", other),
        }
    }

    #[test]
    fn request_path_sends_packet() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Send path request
        tx.send(Event::RequestPath { dest_hash: [0xAA; 16] }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should have sent a packet on the wire (broadcast)
        let sent_packets = sent.lock().unwrap();
        assert!(!sent_packets.is_empty(), "Path request should be sent on wire");

        // Verify the sent packet is a DATA PLAIN BROADCAST packet
        let raw = &sent_packets[0];
        let flags = rns_core::packet::PacketFlags::unpack(raw[0] & 0x7F);
        assert_eq!(flags.packet_type, constants::PACKET_TYPE_DATA);
        assert_eq!(flags.destination_type, constants::DESTINATION_PLAIN);
        assert_eq!(flags.transport_type, constants::TRANSPORT_BROADCAST);
    }

    #[test]
    fn request_path_includes_transport_id() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: true, identity_hash: Some([0xBB; 16]) },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        tx.send(Event::RequestPath { dest_hash: [0xAA; 16] }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        let sent_packets = sent.lock().unwrap();
        assert!(!sent_packets.is_empty());

        // Unpack the packet to check data length includes transport_id
        let raw = &sent_packets[0];
        if let Ok(packet) = RawPacket::unpack(raw) {
            // Data: dest_hash(16) + transport_id(16) + random_tag(16) = 48 bytes
            assert_eq!(packet.data.len(), 48, "Path request data should be 48 bytes with transport_id");
            assert_eq!(&packet.data[..16], &[0xAA; 16], "First 16 bytes should be dest_hash");
            assert_eq!(&packet.data[16..32], &[0xBB; 16], "Next 16 bytes should be transport_id");
        } else {
            panic!("Could not unpack sent packet");
        }
    }

    #[test]
    fn path_request_dest_registered() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        // The path request dest should be registered as a local PLAIN destination
        let expected_dest = rns_core::destination::destination_hash(
            "rnstransport", &["path", "request"], None,
        );
        assert_eq!(driver.path_request_dest, expected_dest);

        drop(tx);
    }

    // =========================================================================
    // Phase 9d: send_packet + proofs tests
    // =========================================================================

    #[test]
    fn register_proof_strategy_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let dest = [0xAA; 16];
        let identity = Identity::new(&mut OsRng);
        let prv_key = identity.get_private_key().unwrap();

        tx.send(Event::RegisterProofStrategy {
            dest_hash: dest,
            strategy: rns_core::types::ProofStrategy::ProveAll,
            signing_key: Some(prv_key),
        }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert!(driver.proof_strategies.contains_key(&dest));
        let (strategy, ref id_opt) = driver.proof_strategies[&dest];
        assert_eq!(strategy, rns_core::types::ProofStrategy::ProveAll);
        assert!(id_opt.is_some());
    }

    #[test]
    fn register_proof_strategy_prove_none_no_identity() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );

        let dest = [0xBB; 16];
        tx.send(Event::RegisterProofStrategy {
            dest_hash: dest,
            strategy: rns_core::types::ProofStrategy::ProveNone,
            signing_key: None,
        }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert!(driver.proof_strategies.contains_key(&dest));
        let (strategy, ref id_opt) = driver.proof_strategies[&dest];
        assert_eq!(strategy, rns_core::types::ProofStrategy::ProveNone);
        assert!(id_opt.is_none());
    }

    #[test]
    fn send_outbound_tracks_sent_packets() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Build a DATA packet
        let dest = [0xCC; 16];
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"test data").unwrap();
        let expected_hash = packet.packet_hash;

        tx.send(Event::SendOutbound {
            raw: packet.raw,
            dest_type: constants::DESTINATION_PLAIN,
            attached_interface: None,
        }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should be tracking the sent packet
        assert!(driver.sent_packets.contains_key(&expected_hash));
        let (tracked_dest, _sent_time) = &driver.sent_packets[&expected_hash];
        assert_eq!(tracked_dest, &dest);
    }

    #[test]
    fn prove_all_generates_proof_on_delivery() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, deliveries, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register a destination with ProveAll
        let dest = [0xDD; 16];
        let identity = Identity::new(&mut OsRng);
        let prv_key = identity.get_private_key().unwrap();
        driver.engine.register_destination(dest, constants::DESTINATION_SINGLE);
        driver.proof_strategies.insert(dest, (
            rns_core::types::ProofStrategy::ProveAll,
            Some(Identity::from_private_key(&prv_key)),
        ));

        // Send a DATA packet to that destination
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

        tx.send(Event::Frame { interface_id: InterfaceId(1), data: packet.raw }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should have delivered the packet
        assert_eq!(deliveries.lock().unwrap().len(), 1);

        // Should have sent at least one proof packet on the wire
        let sent_packets = sent.lock().unwrap();
        // The original DATA is not sent out (it was delivered locally), but a PROOF should be
        let has_proof = sent_packets.iter().any(|raw| {
            let flags = PacketFlags::unpack(raw[0] & 0x7F);
            flags.packet_type == constants::PACKET_TYPE_PROOF
        });
        assert!(has_proof, "ProveAll should generate a proof packet: sent {} packets", sent_packets.len());
    }

    #[test]
    fn prove_none_does_not_generate_proof() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, deliveries, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register a destination with ProveNone
        let dest = [0xDD; 16];
        driver.engine.register_destination(dest, constants::DESTINATION_SINGLE);
        driver.proof_strategies.insert(dest, (
            rns_core::types::ProofStrategy::ProveNone,
            None,
        ));

        // Send a DATA packet to that destination
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

        tx.send(Event::Frame { interface_id: InterfaceId(1), data: packet.raw }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Should have delivered the packet
        assert_eq!(deliveries.lock().unwrap().len(), 1);

        // Should NOT have sent any proof
        let sent_packets = sent.lock().unwrap();
        let has_proof = sent_packets.iter().any(|raw| {
            let flags = PacketFlags::unpack(raw[0] & 0x7F);
            flags.packet_type == constants::PACKET_TYPE_PROOF
        });
        assert!(!has_proof, "ProveNone should not generate a proof packet");
    }

    #[test]
    fn no_proof_strategy_does_not_generate_proof() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, deliveries, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register destination but NO proof strategy
        let dest = [0xDD; 16];
        driver.engine.register_destination(dest, constants::DESTINATION_SINGLE);

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"hello").unwrap();

        tx.send(Event::Frame { interface_id: InterfaceId(1), data: packet.raw }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        assert_eq!(deliveries.lock().unwrap().len(), 1);

        let sent_packets = sent.lock().unwrap();
        let has_proof = sent_packets.iter().any(|raw| {
            let flags = PacketFlags::unpack(raw[0] & 0x7F);
            flags.packet_type == constants::PACKET_TYPE_PROOF
        });
        assert!(!has_proof, "No proof strategy means no proof generated");
    }

    #[test]
    fn prove_app_calls_callback() {
        let (tx, rx) = event::channel();
        let proof_requested = Arc::new(Mutex::new(Vec::new()));
        let deliveries = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: deliveries.clone(),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: Arc::new(Mutex::new(Vec::new())),
            proof_requested: proof_requested.clone(),
        };

        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register dest with ProveApp
        let dest = [0xDD; 16];
        let identity = Identity::new(&mut OsRng);
        let prv_key = identity.get_private_key().unwrap();
        driver.engine.register_destination(dest, constants::DESTINATION_SINGLE);
        driver.proof_strategies.insert(dest, (
            rns_core::types::ProofStrategy::ProveApp,
            Some(Identity::from_private_key(&prv_key)),
        ));

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"app test").unwrap();

        tx.send(Event::Frame { interface_id: InterfaceId(1), data: packet.raw }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // on_proof_requested should have been called
        let prs = proof_requested.lock().unwrap();
        assert_eq!(prs.len(), 1);
        assert_eq!(prs[0].0, DestHash(dest));

        // Since our mock returns true, a proof should also have been sent
        let sent_packets = sent.lock().unwrap();
        let has_proof = sent_packets.iter().any(|raw| {
            let flags = PacketFlags::unpack(raw[0] & 0x7F);
            flags.packet_type == constants::PACKET_TYPE_PROOF
        });
        assert!(has_proof, "ProveApp (callback returns true) should generate a proof");
    }

    #[test]
    fn inbound_proof_fires_callback() {
        let (tx, rx) = event::channel();
        let proofs = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: proofs.clone(),
            proof_requested: Arc::new(Mutex::new(Vec::new())),
        };

        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        // Register a destination so proof packets can be delivered locally
        let dest = [0xEE; 16];
        driver.engine.register_destination(dest, constants::DESTINATION_SINGLE);

        // Simulate a sent packet that we're tracking
        let tracked_hash = [0x42u8; 32];
        let sent_time = time::now() - 0.5; // 500ms ago
        driver.sent_packets.insert(tracked_hash, (dest, sent_time));

        // Build a PROOF packet with the tracked hash + dummy signature
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&tracked_hash);
        proof_data.extend_from_slice(&[0xAA; 64]); // dummy signature

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, &proof_data).unwrap();

        tx.send(Event::Frame { interface_id: InterfaceId(1), data: packet.raw }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // on_proof callback should have been fired
        let proof_list = proofs.lock().unwrap();
        assert_eq!(proof_list.len(), 1);
        assert_eq!(proof_list[0].0, DestHash(dest));
        assert_eq!(proof_list[0].1, PacketHash(tracked_hash));
        assert!(proof_list[0].2 >= 0.4, "RTT should be approximately 0.5s, got {}", proof_list[0].2);

        // Tracked packet should be removed
        assert!(!driver.sent_packets.contains_key(&tracked_hash));
    }

    #[test]
    fn inbound_proof_for_unknown_packet_is_ignored() {
        let (tx, rx) = event::channel();
        let proofs = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: proofs.clone(),
            proof_requested: Arc::new(Mutex::new(Vec::new())),
        };

        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let dest = [0xEE; 16];
        driver.engine.register_destination(dest, constants::DESTINATION_SINGLE);

        // Build a PROOF packet for an untracked hash
        let unknown_hash = [0xFF; 32];
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&unknown_hash);
        proof_data.extend_from_slice(&[0xAA; 64]);

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, &proof_data).unwrap();

        tx.send(Event::Frame { interface_id: InterfaceId(1), data: packet.raw }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // on_proof should NOT have been called
        assert!(proofs.lock().unwrap().is_empty());
    }

    #[test]
    fn inbound_proof_with_valid_signature_fires_callback() {
        // When the destination IS in known_destinations, the proof signature is verified
        let (tx, rx) = event::channel();
        let proofs = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: proofs.clone(),
            proof_requested: Arc::new(Mutex::new(Vec::new())),
        };

        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let dest = [0xEE; 16];
        driver.engine.register_destination(dest, constants::DESTINATION_SINGLE);

        // Create real identity and add to known_destinations
        let identity = Identity::new(&mut OsRng);
        let pub_key = identity.get_public_key();
        driver.known_destinations.insert(dest, crate::destination::AnnouncedIdentity {
            dest_hash: DestHash(dest),
            identity_hash: IdentityHash(*identity.hash()),
            public_key: pub_key.unwrap(),
            app_data: None,
            hops: 0,
            received_at: time::now(),
        });

        // Sign a packet hash with the identity
        let tracked_hash = [0x42u8; 32];
        let sent_time = time::now() - 0.5;
        driver.sent_packets.insert(tracked_hash, (dest, sent_time));

        let signature = identity.sign(&tracked_hash).unwrap();
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&tracked_hash);
        proof_data.extend_from_slice(&signature);

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, &proof_data).unwrap();

        tx.send(Event::Frame { interface_id: InterfaceId(1), data: packet.raw }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Valid signature: on_proof should fire
        let proof_list = proofs.lock().unwrap();
        assert_eq!(proof_list.len(), 1);
        assert_eq!(proof_list[0].0, DestHash(dest));
        assert_eq!(proof_list[0].1, PacketHash(tracked_hash));
    }

    #[test]
    fn inbound_proof_with_invalid_signature_rejected() {
        // When known_destinations has the public key, bad signatures are rejected
        let (tx, rx) = event::channel();
        let proofs = Arc::new(Mutex::new(Vec::new()));
        let cbs = MockCallbacks {
            announces: Arc::new(Mutex::new(Vec::new())),
            paths: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            iface_ups: Arc::new(Mutex::new(Vec::new())),
            iface_downs: Arc::new(Mutex::new(Vec::new())),
            link_established: Arc::new(Mutex::new(Vec::new())),
            link_closed: Arc::new(Mutex::new(Vec::new())),
            remote_identified: Arc::new(Mutex::new(Vec::new())),
            resources_received: Arc::new(Mutex::new(Vec::new())),
            resource_completed: Arc::new(Mutex::new(Vec::new())),
            resource_failed: Arc::new(Mutex::new(Vec::new())),
            channel_messages: Arc::new(Mutex::new(Vec::new())),
            link_data: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            proofs: proofs.clone(),
            proof_requested: Arc::new(Mutex::new(Vec::new())),
        };

        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let dest = [0xEE; 16];
        driver.engine.register_destination(dest, constants::DESTINATION_SINGLE);

        // Create identity and add to known_destinations
        let identity = Identity::new(&mut OsRng);
        let pub_key = identity.get_public_key();
        driver.known_destinations.insert(dest, crate::destination::AnnouncedIdentity {
            dest_hash: DestHash(dest),
            identity_hash: IdentityHash(*identity.hash()),
            public_key: pub_key.unwrap(),
            app_data: None,
            hops: 0,
            received_at: time::now(),
        });

        // Track a sent packet
        let tracked_hash = [0x42u8; 32];
        let sent_time = time::now() - 0.5;
        driver.sent_packets.insert(tracked_hash, (dest, sent_time));

        // Use WRONG signature (all 0xAA — invalid for this identity)
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&tracked_hash);
        proof_data.extend_from_slice(&[0xAA; 64]);

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_PROOF,
        };
        let packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, &proof_data).unwrap();

        tx.send(Event::Frame { interface_id: InterfaceId(1), data: packet.raw }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Invalid signature: on_proof should NOT fire
        assert!(proofs.lock().unwrap().is_empty());
    }

    #[test]
    fn proof_data_is_valid_explicit_proof() {
        // Verify that the proof generated by ProveAll is a valid explicit proof
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            tx.clone(),
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info);
        let (writer, sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), make_entry(1, Box::new(writer), true));

        let dest = [0xDD; 16];
        let identity = Identity::new(&mut OsRng);
        let prv_key = identity.get_private_key().unwrap();
        driver.engine.register_destination(dest, constants::DESTINATION_SINGLE);
        driver.proof_strategies.insert(dest, (
            rns_core::types::ProofStrategy::ProveAll,
            Some(Identity::from_private_key(&prv_key)),
        ));

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let data_packet = RawPacket::pack(flags, 0, &dest, None, constants::CONTEXT_NONE, b"verify me").unwrap();
        let data_packet_hash = data_packet.packet_hash;

        tx.send(Event::Frame { interface_id: InterfaceId(1), data: data_packet.raw }).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        // Find the proof packet in sent
        let sent_packets = sent.lock().unwrap();
        let proof_raw = sent_packets.iter().find(|raw| {
            let f = PacketFlags::unpack(raw[0] & 0x7F);
            f.packet_type == constants::PACKET_TYPE_PROOF
        });
        assert!(proof_raw.is_some(), "Should have sent a proof");

        let proof_packet = RawPacket::unpack(proof_raw.unwrap()).unwrap();
        // Proof data should be 96 bytes: packet_hash(32) + signature(64)
        assert_eq!(proof_packet.data.len(), 96, "Explicit proof should be 96 bytes");

        // Validate using rns-core's receipt module
        let result = rns_core::receipt::validate_proof(
            &proof_packet.data,
            &data_packet_hash,
            &Identity::from_private_key(&prv_key), // same identity
        );
        assert_eq!(result, rns_core::receipt::ProofResult::Valid);
    }

    #[test]
    fn query_local_destinations_empty() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let driver_config = TransportConfig { transport_enabled: false, identity_hash: None };
        let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::LocalDestinations, resp_tx)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::LocalDestinations(entries) => {
                // Should contain the two internal destinations (tunnel_synth + path_request)
                assert_eq!(entries.len(), 2);
                for entry in &entries {
                    assert_eq!(entry.dest_type, rns_core::constants::DESTINATION_PLAIN);
                }
            }
            other => panic!("expected LocalDestinations, got {:?}", other),
        }
    }

    #[test]
    fn query_local_destinations_with_registered() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let driver_config = TransportConfig { transport_enabled: false, identity_hash: None };
        let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

        let dest_hash = [0xAA; 16];
        tx.send(Event::RegisterDestination {
            dest_hash,
            dest_type: rns_core::constants::DESTINATION_SINGLE,
        }).unwrap();

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::LocalDestinations, resp_tx)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::LocalDestinations(entries) => {
                // 2 internal + 1 registered
                assert_eq!(entries.len(), 3);
                assert!(entries.iter().any(|e| e.hash == dest_hash
                    && e.dest_type == rns_core::constants::DESTINATION_SINGLE));
            }
            other => panic!("expected LocalDestinations, got {:?}", other),
        }
    }

    #[test]
    fn query_local_destinations_tracks_link_dest() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let driver_config = TransportConfig { transport_enabled: false, identity_hash: None };
        let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

        let dest_hash = [0xBB; 16];
        tx.send(Event::RegisterLinkDestination {
            dest_hash,
            sig_prv_bytes: [0x11; 32],
            sig_pub_bytes: [0x22; 32],
        }).unwrap();

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::LocalDestinations, resp_tx)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::LocalDestinations(entries) => {
                // 2 internal + 1 link destination
                assert_eq!(entries.len(), 3);
                assert!(entries.iter().any(|e| e.hash == dest_hash
                    && e.dest_type == rns_core::constants::DESTINATION_SINGLE));
            }
            other => panic!("expected LocalDestinations, got {:?}", other),
        }
    }

    #[test]
    fn query_links_empty() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let driver_config = TransportConfig { transport_enabled: false, identity_hash: None };
        let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::Links, resp_tx)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::Links(entries) => {
                assert!(entries.is_empty());
            }
            other => panic!("expected Links, got {:?}", other),
        }
    }

    #[test]
    fn query_resources_empty() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _, _, _) = MockCallbacks::new();
        let driver_config = TransportConfig { transport_enabled: false, identity_hash: None };
        let mut driver = Driver::new(driver_config, rx, tx.clone(), Box::new(cbs));

        let (resp_tx, resp_rx) = mpsc::channel();
        tx.send(Event::Query(QueryRequest::Resources, resp_tx)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();

        match resp_rx.recv().unwrap() {
            QueryResponse::Resources(entries) => {
                assert!(entries.is_empty());
            }
            other => panic!("expected Resources, got {:?}", other),
        }
    }

    #[test]
    fn infer_interface_type_from_name() {
        assert_eq!(
            super::infer_interface_type("TCPServerInterface/Client-1234"),
            "TCPServerClientInterface"
        );
        assert_eq!(
            super::infer_interface_type("BackboneInterface/5"),
            "BackboneInterface"
        );
        assert_eq!(
            super::infer_interface_type("LocalInterface"),
            "LocalServerClientInterface"
        );
        assert_eq!(
            super::infer_interface_type("MyAutoGroup:fe80::1"),
            "AutoInterface"
        );
    }

    // ---- extract_dest_hash tests ----

    #[test]
    fn test_extract_dest_hash_empty() {
        assert_eq!(super::extract_dest_hash(&[]), [0u8; 16]);
    }

    #[test]
    fn test_extract_dest_hash_too_short() {
        // Packet too short to contain a full dest hash
        assert_eq!(super::extract_dest_hash(&[0x00, 0x00, 0xAA]), [0u8; 16]);
    }

    #[test]
    fn test_extract_dest_hash_header1() {
        // HEADER_1: bit 6 = 0, dest at bytes 2..18
        let mut raw = vec![0x00, 0x00]; // flags (header_type=0), hops
        let dest = [0x11; 16];
        raw.extend_from_slice(&dest);
        raw.extend_from_slice(&[0xFF; 10]); // trailing data
        assert_eq!(super::extract_dest_hash(&raw), dest);
    }

    #[test]
    fn test_extract_dest_hash_header2() {
        // HEADER_2: bit 6 = 1, transport_id at 2..18, dest at 18..34
        let mut raw = vec![0x40, 0x00]; // flags (header_type=1), hops
        raw.extend_from_slice(&[0xAA; 16]); // transport_id (bytes 2..18)
        let dest = [0x22; 16];
        raw.extend_from_slice(&dest); // dest (bytes 18..34)
        raw.extend_from_slice(&[0xFF; 10]); // trailing data
        assert_eq!(super::extract_dest_hash(&raw), dest);
    }

    #[test]
    fn test_extract_dest_hash_header2_too_short() {
        // HEADER_2 packet that's too short for the dest portion
        let mut raw = vec![0x40, 0x00];
        raw.extend_from_slice(&[0xAA; 16]); // transport_id only, no dest
        assert_eq!(super::extract_dest_hash(&raw), [0u8; 16]);
    }

    #[test]
    fn test_extract_dest_hash_other_flags_preserved() {
        // Ensure other flag bits don't affect header type detection
        // 0x3F = all bits set except bit 6 -> still HEADER_1
        let mut raw = vec![0x3F, 0x00];
        let dest = [0x33; 16];
        raw.extend_from_slice(&dest);
        raw.extend_from_slice(&[0xFF; 10]);
        assert_eq!(super::extract_dest_hash(&raw), dest);

        // 0xFF = all bits set including bit 6 -> HEADER_2
        let mut raw2 = vec![0xFF, 0x00];
        raw2.extend_from_slice(&[0xBB; 16]); // transport_id
        let dest2 = [0x44; 16];
        raw2.extend_from_slice(&dest2);
        raw2.extend_from_slice(&[0xFF; 10]);
        assert_eq!(super::extract_dest_hash(&raw2), dest2);
    }
}
