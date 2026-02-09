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
}

/// The driver loop. Owns the engine and all interface entries.
pub struct Driver {
    pub(crate) engine: TransportEngine,
    pub(crate) interfaces: HashMap<InterfaceId, InterfaceEntry>,
    pub(crate) rng: OsRng,
    pub(crate) rx: EventReceiver,
    pub(crate) callbacks: Box<dyn Callbacks>,
    pub(crate) started: f64,
}

impl Driver {
    /// Create a new driver.
    pub fn new(
        config: TransportConfig,
        rx: EventReceiver,
        callbacks: Box<dyn Callbacks>,
    ) -> Self {
        Driver {
            engine: TransportEngine::new(config),
            interfaces: HashMap::new(),
            rng: OsRng,
            rx,
            callbacks,
            started: time::now(),
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
                    let actions = self.engine.tick(time::now(), &mut self.rng);
                    self.dispatch_all(actions);
                }
                Event::InterfaceUp(id, new_writer, info) => {
                    if let Some(info) = info {
                        // New dynamic interface (e.g., TCP server client connection)
                        log::info!("[{}] dynamic interface registered", id.0);
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
                        entry.online = true;
                        if let Some(writer) = new_writer {
                            log::info!("[{}] writer refreshed after reconnect", id.0);
                            entry.writer = writer;
                        }
                        self.callbacks.on_interface_up(id);
                    }
                }
                Event::InterfaceDown(id) => {
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
                QueryResponse::LinkCount(self.engine.link_table_count())
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
                    self.callbacks
                        .on_local_delivery(destination_hash, raw, packet_hash);
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
            }
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
                },
                announces,
                paths,
                deliveries,
                iface_ups,
                iface_downs,
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
}
