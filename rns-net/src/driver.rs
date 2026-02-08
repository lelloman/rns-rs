//! Driver loop: receives events, drives the TransportEngine, dispatches actions.

use std::collections::HashMap;

use rns_core::transport::types::{InterfaceId, TransportAction, TransportConfig};
use rns_core::transport::TransportEngine;
use rns_crypto::OsRng;

use crate::event::{Event, EventReceiver};
use crate::interface::InterfaceEntry;
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
}

/// The driver loop. Owns the engine and all interface entries.
pub struct Driver {
    pub(crate) engine: TransportEngine,
    pub(crate) interfaces: HashMap<InterfaceId, InterfaceEntry>,
    pub(crate) rng: OsRng,
    pub(crate) rx: EventReceiver,
    pub(crate) callbacks: Box<dyn Callbacks>,
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
                    let actions = self.engine.handle_inbound(
                        &data,
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
                Event::InterfaceUp(id, new_writer) => {
                    if let Some(entry) = self.interfaces.get_mut(&id) {
                        log::info!("[{}] interface online", id.0);
                        entry.online = true;
                        if let Some(writer) = new_writer {
                            log::info!("[{}] writer refreshed after reconnect", id.0);
                            entry.writer = writer;
                        }
                    }
                }
                Event::InterfaceDown(id) => {
                    if let Some(entry) = self.interfaces.get_mut(&id) {
                        log::info!("[{}] interface offline", id.0);
                        entry.online = false;
                    }
                }
                Event::Shutdown => break,
            }
        }
    }

    /// Dispatch a list of transport actions.
    fn dispatch_all(&mut self, actions: Vec<TransportAction>) {
        for action in actions {
            match action {
                TransportAction::SendOnInterface { interface, raw } => {
                    if let Some(entry) = self.interfaces.get_mut(&interface) {
                        if entry.online {
                            if let Err(e) = entry.writer.send_frame(&raw) {
                                log::warn!("[{}] send failed: {}", entry.info.id.0, e);
                            }
                        }
                    }
                }
                TransportAction::BroadcastOnAllInterfaces { raw, exclude } => {
                    for entry in self.interfaces.values_mut() {
                        if entry.online && Some(entry.id) != exclude {
                            if let Err(e) = entry.writer.send_frame(&raw) {
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
                    ..
                } => {
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
    use crate::interface::{InterfaceEntry, Writer};
    use rns_core::announce::AnnounceData;
    use rns_core::constants;
    use rns_core::packet::{PacketFlags, RawPacket};
    use rns_core::transport::types::InterfaceInfo;
    use rns_crypto::identity::Identity;
    use std::io;
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
    }

    impl MockCallbacks {
        fn new() -> (
            Self,
            Arc<Mutex<Vec<([u8; 16], u8)>>>,
            Arc<Mutex<Vec<([u8; 16], u8)>>>,
            Arc<Mutex<Vec<[u8; 16]>>>,
        ) {
            let announces = Arc::new(Mutex::new(Vec::new()));
            let paths = Arc::new(Mutex::new(Vec::new()));
            let deliveries = Arc::new(Mutex::new(Vec::new()));
            (
                MockCallbacks {
                    announces: announces.clone(),
                    paths: paths.clone(),
                    deliveries: deliveries.clone(),
                },
                announces,
                paths,
                deliveries,
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
    }

    fn make_interface_info(id: u64) -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId(id),
            mode: constants::MODE_FULL,
            out_capable: true,
            in_capable: true,
            bitrate: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
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
        let (cbs, announces, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), InterfaceEntry {
            id: InterfaceId(1),
            info,
            writer: Box::new(writer),
            online: true,
        });

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
        let (cbs, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );
        let (writer, sent) = MockWriter::new();
        let info = make_interface_info(1);
        driver.interfaces.insert(InterfaceId(1), InterfaceEntry {
            id: InterfaceId(1),
            info,
            writer: Box::new(writer),
            online: true,
        });

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
        let (cbs, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        let (w1, sent1) = MockWriter::new();
        let (w2, sent2) = MockWriter::new();
        let info1 = make_interface_info(1);
        let info2 = make_interface_info(2);
        driver.interfaces.insert(InterfaceId(1), InterfaceEntry {
            id: InterfaceId(1), info: info1, writer: Box::new(w1), online: true,
        });
        driver.interfaces.insert(InterfaceId(2), InterfaceEntry {
            id: InterfaceId(2), info: info2, writer: Box::new(w2), online: true,
        });

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
        let (cbs, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        let (w1, sent1) = MockWriter::new();
        let (w2, sent2) = MockWriter::new();
        let info1 = make_interface_info(1);
        let info2 = make_interface_info(2);
        driver.interfaces.insert(InterfaceId(1), InterfaceEntry {
            id: InterfaceId(1), info: info1, writer: Box::new(w1), online: true,
        });
        driver.interfaces.insert(InterfaceId(2), InterfaceEntry {
            id: InterfaceId(2), info: info2, writer: Box::new(w2), online: true,
        });

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
        let (cbs, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: true, identity_hash: Some([0x42; 16]) },
            rx,
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), InterfaceEntry {
            id: InterfaceId(1), info, writer: Box::new(writer), online: true,
        });

        // Send Tick then Shutdown
        tx.send(Event::Tick).unwrap();
        tx.send(Event::Shutdown).unwrap();
        driver.run();
        // No crash = tick was processed successfully
    }

    #[test]
    fn shutdown_event() {
        let (tx, rx) = event::channel();
        let (cbs, _, _, _) = MockCallbacks::new();
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
        let (cbs, announces, paths, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );
        let info = make_interface_info(1);
        driver.engine.register_interface(info.clone());
        let (writer, _sent) = MockWriter::new();
        driver.interfaces.insert(InterfaceId(1), InterfaceEntry {
            id: InterfaceId(1), info, writer: Box::new(writer), online: true,
        });

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
        let (cbs, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        let (w1, sent1) = MockWriter::new();
        let (w2, sent2) = MockWriter::new();
        let info1 = make_interface_info(1);
        let info2 = make_interface_info(2);
        driver.interfaces.insert(InterfaceId(1), InterfaceEntry {
            id: InterfaceId(1), info: info1, writer: Box::new(w1), online: false, // offline
        });
        driver.interfaces.insert(InterfaceId(2), InterfaceEntry {
            id: InterfaceId(2), info: info2, writer: Box::new(w2), online: true,
        });

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
        let (cbs, _, _, _) = MockCallbacks::new();
        let mut driver = Driver::new(
            TransportConfig { transport_enabled: false, identity_hash: None },
            rx,
            Box::new(cbs),
        );

        let (w_old, sent_old) = MockWriter::new();
        let info = make_interface_info(1);
        driver.interfaces.insert(InterfaceId(1), InterfaceEntry {
            id: InterfaceId(1), info, writer: Box::new(w_old), online: false,
        });

        // Simulate reconnect: InterfaceUp with new writer
        let (w_new, sent_new) = MockWriter::new();
        tx.send(Event::InterfaceUp(InterfaceId(1), Some(Box::new(w_new)))).unwrap();
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
}
