//! Minimal Reticulum transport driver for ESP32.
//!
//! Stripped-down version of `rns-net/src/driver.rs`: event loop, IFAC,
//! TransportEngine integration. No hooks, hole-punching, link manager,
//! RPC, discovery, tunnels, or compression.

use std::sync::mpsc;
use std::time::Duration;

use rns_core::constants;
use rns_core::transport::TransportEngine;
use rns_core::transport::types::{
    InterfaceId, InterfaceInfo, TransportAction, TransportConfig,
};
use rns_crypto::Rng as _;
use rns_crypto::identity::Identity;

use crate::display::SharedStats;
use crate::ifac::{self, IfacState};
use crate::lora::LoRaWriter;
use crate::rng::EspRng;

/// Events processed by the driver loop.
pub enum Event {
    /// Inbound frame from an interface.
    Frame { interface_id: InterfaceId, data: Vec<u8> },
    /// Interface came online.
    InterfaceUp(InterfaceId),
    /// Interface went offline.
    InterfaceDown(InterfaceId),
    /// Periodic tick for transport engine maintenance.
    Tick,
    /// Send a ping broadcast over LoRa (button: short press).
    SendPing,
    /// Trigger a Reticulum announce (button: double press).
    SendAnnounce,
    /// Cycle display page (button: long press).
    CycleDisplayPage,
    /// Shutdown the driver.
    Shutdown,
}

/// Per-interface state tracked by the driver.
struct InterfaceEntry {
    id: InterfaceId,
    writer: LoRaWriter,
    online: bool,
    ifac: Option<IfacState>,
}

/// The transport driver: owns the engine, interfaces, and event loop.
pub struct Driver {
    engine: TransportEngine,
    interfaces: Vec<InterfaceEntry>,
    rng: EspRng,
    rx: mpsc::Receiver<Event>,
    stats: Option<SharedStats>,
    identity: Option<Identity>,
}

impl Driver {
    /// Create a new driver with the given transport config and event receiver.
    pub fn new(
        config: TransportConfig,
        rx: mpsc::Receiver<Event>,
    ) -> Self {
        Driver {
            engine: TransportEngine::new(config),
            interfaces: Vec::new(),
            rng: EspRng,
            rx,
            stats: None,
            identity: None,
        }
    }

    /// Attach shared display stats.
    pub fn set_stats(&mut self, stats: SharedStats) {
        self.stats = Some(stats);
    }

    /// Set the node identity (needed for announces).
    pub fn set_identity(&mut self, identity: Identity) {
        self.identity = Some(identity);
    }

    /// Register a LoRa interface with the transport engine.
    pub fn add_interface(
        &mut self,
        id: InterfaceId,
        writer: LoRaWriter,
        ifac: Option<IfacState>,
    ) {
        let info = InterfaceInfo {
            id,
            name: String::from("LoRa"),
            mode: constants::MODE_FULL,
            out_capable: true,
            in_capable: true,
            bitrate: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: crate::config::LORA_MTU,
            ingress_control: false,
            ia_freq: 0.0,
            started: now(),
        };

        self.engine.register_interface(info);
        self.interfaces.push(InterfaceEntry {
            id,
            writer,
            online: true,
            ifac,
        });

        log::info!("Interface {:?} registered", id);
    }

    /// Run the main event loop. Blocks until Shutdown event.
    pub fn run(&mut self) {
        log::info!("Driver event loop started");

        loop {
            let event = match self.rx.recv_timeout(Duration::from_millis(100)) {
                Ok(e) => e,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    log::warn!("Event channel disconnected, shutting down");
                    break;
                }
            };

            match event {
                Event::Frame { interface_id, data } => {
                    if let Some(ref stats) = self.stats {
                        stats.lock().unwrap().rx_bytes += data.len() as u32;
                    }
                    self.handle_frame(interface_id, data);
                }
                Event::InterfaceUp(id) => {
                    if let Some(entry) = self.interfaces.iter_mut().find(|e| e.id == id) {
                        entry.online = true;
                        log::info!("Interface {:?} up", id);
                    }
                }
                Event::InterfaceDown(id) => {
                    if let Some(entry) = self.interfaces.iter_mut().find(|e| e.id == id) {
                        entry.online = false;
                        log::info!("Interface {:?} down", id);
                    }
                }
                Event::Tick => {
                    let actions = self.engine.tick(now(), &mut self.rng);
                    self.dispatch_all(actions);
                }
                Event::SendPing => {
                    self.handle_send_ping();
                }
                Event::SendAnnounce => {
                    self.handle_send_announce();
                }
                Event::CycleDisplayPage => {
                    if let Some(ref stats) = self.stats {
                        stats.lock().unwrap().cycle_page();
                    }
                }
                Event::Shutdown => {
                    log::info!("Driver shutdown requested");
                    break;
                }
            }
        }

        log::info!("Driver event loop exited");
    }

    /// Process an inbound frame: IFAC unmask → engine.handle_inbound → dispatch.
    fn handle_frame(&mut self, interface_id: InterfaceId, data: Vec<u8>) {
        // Find the interface entry for IFAC processing
        let ifac_state = self.interfaces.iter()
            .find(|e| e.id == interface_id)
            .and_then(|e| e.ifac.as_ref());

        // IFAC unmask if configured
        let raw = if let Some(state) = ifac_state {
            match ifac::unmask_inbound(&data, state) {
                Some(unmasked) => unmasked,
                None => {
                    log::debug!("IFAC unmask failed, dropping frame");
                    return;
                }
            }
        } else {
            data
        };

        let actions = self.engine.handle_inbound(&raw, interface_id, now(), &mut self.rng);
        self.dispatch_all(actions);
    }

    /// Dispatch transport actions.
    fn dispatch_all(&mut self, actions: Vec<TransportAction>) {
        for action in actions {
            match action {
                TransportAction::SendOnInterface { interface, raw } => {
                    self.send_on_interface(interface, &raw);
                }
                TransportAction::BroadcastOnAllInterfaces { raw, exclude } => {
                    let ids: Vec<_> = self.interfaces.iter()
                        .filter(|e| e.online && Some(e.id) != exclude)
                        .map(|e| e.id)
                        .collect();
                    for id in ids {
                        self.send_on_interface(id, &raw);
                    }
                }
                TransportAction::DeliverLocal { destination_hash, packet_hash, .. } => {
                    log::info!("Local delivery: dest={} pkt={}",
                        hex(&destination_hash[..4]),
                        hex(&packet_hash[..4]));
                }
                TransportAction::AnnounceReceived { destination_hash, hops, .. } => {
                    log::info!("Announce received: dest={} hops={}",
                        hex(&destination_hash[..4]), hops);
                    if let Some(ref stats) = self.stats {
                        stats.lock().unwrap().announces += 1;
                    }
                }
                TransportAction::PathUpdated { destination_hash, hops, .. } => {
                    log::info!("Path updated: dest={} hops={}",
                        hex(&destination_hash[..4]), hops);
                }
                // Ignore actions not relevant to minimal LoRa node
                _ => {}
            }
        }
    }

    /// Send a ping broadcast: a small test packet over LoRa.
    fn handle_send_ping(&mut self) {
        log::info!("Button: sending ping");

        // Build a minimal broadcast packet (PLAIN destination, DATA type)
        // Use a fixed "ping" destination hash (all zeros = broadcast probe)
        let flags = rns_core::packet::PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_PLAIN,
            packet_type: constants::PACKET_TYPE_DATA,
        };

        let dest_hash = [0u8; 16];
        let ping_data = b"PING";

        match rns_core::packet::RawPacket::pack(
            flags, 0, &dest_hash, None,
            constants::CONTEXT_NONE, ping_data,
        ) {
            Ok(packet) => {
                let ids: Vec<_> = self.interfaces.iter()
                    .filter(|e| e.online)
                    .map(|e| e.id)
                    .collect();
                for id in ids {
                    self.send_on_interface(id, &packet.raw);
                }
                if let Some(ref stats) = self.stats {
                    stats.lock().unwrap().set_status("Ping sent!");
                }
            }
            Err(e) => log::error!("Failed to build ping: {:?}", e),
        }
    }

    /// Build and broadcast a Reticulum announce for this node's identity.
    fn handle_send_announce(&mut self) {
        let identity = match &self.identity {
            Some(id) => id,
            None => {
                log::warn!("No identity set, cannot announce");
                return;
            }
        };

        log::info!("Button: sending announce");

        let identity_hash = *identity.hash();
        let app_name = "rns_esp32";
        let aspects: &[&str] = &["transport"];
        let name_hash = rns_core::destination::name_hash(app_name, aspects);
        let dest_hash = rns_core::destination::destination_hash(
            app_name, aspects, Some(&identity_hash),
        );

        // Build random_hash with timestamp in bytes [5:10]
        // ESP32 has no RTC/NTP, so use uptime — other Reticulum nodes may see
        // these as "old" announces, but they will still be processed.
        let mut random_hash = [0u8; 10];
        self.rng.fill_bytes(&mut random_hash[..5]);
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        random_hash[5..10].copy_from_slice(&now_secs.to_be_bytes()[3..8]);

        match rns_core::announce::AnnounceData::pack(
            identity, &dest_hash, &name_hash, &random_hash, None, None,
        ) {
            Ok((announce_data, _)) => {
                let flags = rns_core::packet::PacketFlags {
                    header_type: constants::HEADER_1,
                    context_flag: constants::FLAG_UNSET,
                    transport_type: constants::TRANSPORT_BROADCAST,
                    destination_type: constants::DESTINATION_SINGLE,
                    packet_type: constants::PACKET_TYPE_ANNOUNCE,
                };

                match rns_core::packet::RawPacket::pack(
                    flags, 0, &dest_hash, None,
                    constants::CONTEXT_NONE, &announce_data,
                ) {
                    Ok(packet) => {
                        let actions = self.engine.handle_outbound(
                            &packet, constants::DESTINATION_SINGLE, None, now(),
                        );
                        self.dispatch_all(actions);
                        if let Some(ref stats) = self.stats {
                            stats.lock().unwrap().set_status("Announce sent!");
                        }
                        log::info!("Announce broadcast for dest={}", hex(&dest_hash[..4]));
                    }
                    Err(e) => log::error!("Failed to pack announce: {:?}", e),
                }
            }
            Err(e) => log::error!("Failed to build announce: {:?}", e),
        }
    }

    /// Send a frame on a specific interface, applying IFAC mask if configured.
    fn send_on_interface(&mut self, id: InterfaceId, raw: &[u8]) {
        let entry = match self.interfaces.iter_mut().find(|e| e.id == id) {
            Some(e) => e,
            None => {
                log::warn!("Send on unknown interface {:?}", id);
                return;
            }
        };

        if !entry.online {
            log::debug!("Send on offline interface {:?}, dropping", id);
            return;
        }

        // Apply IFAC mask if configured
        let frame = if let Some(ref state) = entry.ifac {
            ifac::mask_outbound(raw, state)
        } else {
            raw.to_vec()
        };

        match entry.writer.send_frame(&frame) {
            Ok(()) => {
                log::debug!("TX {} bytes on {:?}", frame.len(), id);
                if let Some(ref stats) = self.stats {
                    stats.lock().unwrap().tx_bytes += frame.len() as u32;
                }
            }
            Err(e) => {
                log::error!("TX error on {:?}: {}", id, e);
            }
        }
    }
}

/// Spawn a tick thread that sends Event::Tick at a regular interval.
pub fn spawn_tick_thread(tx: mpsc::Sender<Event>, interval_ms: u64) {
    std::thread::Builder::new()
        .name("tick".into())
        .stack_size(2048)
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(interval_ms));
                if tx.send(Event::Tick).is_err() {
                    break;
                }
            }
        })
        .expect("failed to spawn tick thread");
}

/// Get current time as seconds since boot (monotonic).
fn now() -> f64 {
    let ticks = unsafe { esp_idf_sys::esp_timer_get_time() };
    ticks as f64 / 1_000_000.0
}

/// Format bytes as hex string for logging.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
