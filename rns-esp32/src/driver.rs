//! Minimal Reticulum transport driver for ESP32.
//!
//! Stripped-down version of `rns-net/src/driver.rs`: event loop, IFAC,
//! TransportEngine integration. No hooks, hole-punching, link manager,
//! RPC, discovery, tunnels, or compression.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::Duration;

use esp_idf_hal::uart::UartDriver;
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};

use rns_core::constants;
use rns_core::packet::{PacketFlags, RawPacket};
use rns_core::transport::types::{InterfaceId, InterfaceInfo, TransportAction, TransportConfig};
use rns_core::transport::TransportEngine;
use rns_crypto::identity::Identity;
use rns_crypto::Rng as _;

use crate::display::SharedStats;
use crate::ifac::{self, IfacState};
use crate::lora::LoRaWriter;
use crate::rng::EspRng;
use crate::util::hex;
use rns_esp32::channel::TxChannel;
use rns_esp32::control::{
    authorize_request, compiled_controller_keys, control_destination, control_reply_destination,
    encode_response, AuthorizedControlRequest, ControlAuthError, ControlBody, ControlCommand,
    ControlResponseBody, ControlStatus, ReplayWindow,
};
use rns_esp32::protocol::KissFrame;
use rns_esp32::protocol::RadioConfig;
use rns_esp32::settings_store::DeviceSettings;

const NVS_NAMESPACE: &str = "rns";
const NVS_KEY_SETTINGS: &str = "settings";

/// Frames held per interface while the channel is busy, as the bridge.
const TX_QUEUE_MAX_FRAMES: usize = 32;

/// Event wait with nothing queued; bridge detection is polled this often.
/// A host gives the board 200 ms to answer DETECT (upstream's
/// RNodeInterface), and the switch to bridge mode must fit in that too.
const EVENT_WAIT_IDLE_MS: u64 = 20;

/// How often mode-specific threads check for shutdown.
pub const SHUTDOWN_POLL_MS: u64 = 20;

/// Events processed by the driver loop.
pub enum Event {
    /// Inbound frame from an interface.
    Frame {
        interface_id: InterfaceId,
        data: Vec<u8>,
    },
    /// Periodic tick for transport engine maintenance.
    Tick,
    /// Send a ping broadcast over LoRa (button: double press).
    SendPing,
    /// Trigger a Reticulum announce (button: long press, node mode only).
    SendAnnounce,
    /// Enable BLE bridge mode (button: triple press).
    EnableBle,
}

/// Reason the driver event loop exited.
pub enum DriverExit {
    /// UART detected an RNode DETECT handshake; switch to USB bridge mode.
    BridgeRequested(Vec<KissFrame>),
    /// Triple-press requested BLE bridge mode.
    BleRequested,
    /// Event channel disconnected.
    Disconnected,
}

/// Per-interface state tracked by the driver.
struct InterfaceEntry {
    id: InterfaceId,
    writer: LoRaWriter,
    online: bool,
    ifac: Option<IfacState>,
    /// Frames waiting for the channel (listen before talk).
    tx: TxChannel,
}

/// The transport driver: owns the engine, interfaces, and event loop.
pub struct Driver {
    engine: TransportEngine,
    interfaces: Vec<InterfaceEntry>,
    rng: EspRng,
    rx: mpsc::Receiver<Event>,
    stats: Option<SharedStats>,
    identity: Option<Identity>,
    control_dest_hash: Option<[u8; 16]>,
    /// `rnstransport.path.request`, where path requests arrive.
    path_request_dest: [u8; 16],
    replay_window: ReplayWindow,
    active_radio_config: RadioConfig,
    device_settings: DeviceSettings,
    settings_partition: Option<EspDefaultNvsPartition>,
    /// When the node last announced on its own (`ANNOUNCE_INTERVAL_SECS`).
    last_auto_announce: Option<f64>,
}

impl Driver {
    /// Create a new driver with the given transport config and event receiver.
    pub fn new(config: TransportConfig, rx: mpsc::Receiver<Event>) -> Self {
        let mut engine = TransportEngine::new(config);
        // Key the engine's tables so a sender cannot grind packet hashes
        // into colliding slots.
        engine.seed_table_hashing(&mut EspRng);
        // Path requests arrive as packets for this plain destination; it must
        // be registered for the engine to deliver them.
        let path_request_dest =
            rns_core::destination::destination_hash("rnstransport", &["path", "request"], None);
        engine.register_destination(path_request_dest, constants::DESTINATION_PLAIN);
        Driver {
            engine,
            interfaces: Vec::new(),
            rng: EspRng,
            rx,
            stats: None,
            identity: None,
            control_dest_hash: None,
            path_request_dest,
            replay_window: ReplayWindow::new(),
            active_radio_config: RadioConfig {
                frequency: crate::config::LORA_FREQUENCY,
                bandwidth: crate::config::LORA_BANDWIDTH,
                spreading_factor: crate::config::LORA_SPREADING_FACTOR,
                coding_rate: crate::config::LORA_CODING_RATE,
                tx_power: crate::config::LORA_TX_POWER,
            },
            device_settings: DeviceSettings::compile_default(),
            settings_partition: None,
            last_auto_announce: None,
        }
    }

    /// Attach shared display stats.
    pub fn set_stats(&mut self, stats: SharedStats) {
        self.stats = Some(stats);
    }

    /// Set the node identity (needed for announces). Its `transport`
    /// destination is registered, as upstream registers a destination on
    /// creation: the engine only sends announces for registered ones.
    pub fn set_identity(&mut self, identity: Identity) {
        let transport = rns_core::destination::destination_hash(
            "rns_esp32",
            &["transport"],
            Some(identity.hash()),
        );
        self.engine
            .register_destination(transport, constants::DESTINATION_SINGLE);
        self.control_dest_hash = if compiled_controller_keys().is_empty() {
            None
        } else {
            let dest = control_destination(identity.hash());
            self.engine
                .register_destination(dest, constants::DESTINATION_SINGLE);
            Some(dest)
        };
        self.identity = Some(identity);
    }

    pub fn set_settings_partition(&mut self, partition: EspDefaultNvsPartition) {
        self.settings_partition = Some(partition);
    }

    pub fn set_device_settings(&mut self, settings: DeviceSettings) {
        self.device_settings = settings;
    }

    pub fn active_radio_config(&self) -> RadioConfig {
        self.active_radio_config
    }

    /// Register a LoRa interface with the transport engine.
    pub fn add_interface(&mut self, id: InterfaceId, writer: LoRaWriter, ifac: Option<IfacState>) {
        let info = InterfaceInfo {
            id,
            name: String::from("LoRa"),
            mode: constants::MODE_FULL,
            gravity: 0,
            recursive_prs: false,
            announces_from_internal: false,
            announces_to_internal: None,
            out_capable: true,
            in_capable: true,
            bitrate: None,
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            hop_limiter: None,
            tunnel_id: None,
            // A frame of up to 508 bytes, split over two LoRa packets,
            // as upstream's RNode interface.
            mtu: rns_esp32::airframe::MTU as u32,
            mtu_upgradable: false,
            ingress_control: Default::default(),
            stamp_costs: Default::default(),
            ia_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: now(),
        };

        self.engine.register_interface(info);
        self.interfaces.push(InterfaceEntry {
            id,
            writer,
            online: true,
            ifac,
            tx: TxChannel::new(
                self.active_radio_config.spreading_factor,
                self.active_radio_config.bandwidth,
                self.active_radio_config.coding_rate,
                TX_QUEUE_MAX_FRAMES,
            ),
        });

        log::info!("Interface {:?} registered", id);
    }

    /// Drain any stale events from the channel (e.g. after returning from bridge mode).
    pub fn drain_events(&self) {
        while self.rx.try_recv().is_ok() {}
    }

    /// Run the main event loop. Blocks until bridge detected, shutdown, or disconnect.
    pub fn run(&mut self, uart: &UartDriver<'_>) -> DriverExit {
        log::info!("Driver event loop started");
        let mut detect_state = crate::rnode::BridgeDetectState::new();

        let exit = loop {
            self.service_tx();
            let event = match self.rx.recv_timeout(self.event_wait()) {
                Ok(e) => e,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(frames) = detect_state.poll(uart) {
                        break DriverExit::BridgeRequested(frames);
                    }
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    log::warn!("Event channel disconnected, shutting down");
                    break DriverExit::Disconnected;
                }
            };

            // Check UART for RNode DETECT handshake after each event.
            // This runs on every tick (~1s) so detection is responsive.
            if let Some(frames) = detect_state.poll(uart) {
                break DriverExit::BridgeRequested(frames);
            }

            match event {
                Event::Frame { interface_id, data } => {
                    if let Some(ref stats) = self.stats {
                        stats.lock().unwrap().rx_bytes += data.len() as u32;
                    }
                    self.handle_frame(interface_id, data);
                }
                Event::Tick => {
                    let actions = self.engine.tick(now(), &mut self.rng);
                    self.dispatch_all(actions);
                    self.announce_if_due();
                }
                Event::SendPing => {
                    self.handle_send_ping();
                }
                Event::SendAnnounce => {
                    self.handle_send_announce();
                }
                Event::EnableBle => {
                    if !self.device_settings.ble_open_control {
                        log::info!("BLE bridge request ignored: BLE open control disabled");
                        if let Some(ref stats) = self.stats {
                            stats.lock().unwrap().set_status("BLE control off");
                        }
                        continue;
                    }
                    log::info!("BLE bridge mode requested via button");
                    break DriverExit::BleRequested;
                }
            }
        };

        log::info!("Driver event loop exited");
        exit
    }

    /// Process an inbound frame: IFAC check → engine.handle_inbound → dispatch.
    fn handle_frame(&mut self, interface_id: InterfaceId, data: Vec<u8>) {
        // Find the interface entry for IFAC processing
        let ifac_state = self
            .interfaces
            .iter()
            .find(|e| e.id == interface_id)
            .and_then(|e| e.ifac.as_ref());

        // IFAC: remove a valid access code, or drop the frame
        let Some(raw) = ifac::inbound(&data, ifac_state) else {
            log::debug!("IFAC check failed, dropping frame");
            return;
        };

        let actions = self.engine.handle_inbound(
            rns_core::transport::InboundFrame::new(&raw, interface_id, now()),
            &mut self.rng,
        );
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
                    let ids: Vec<_> = self
                        .interfaces
                        .iter()
                        .filter(|e| e.online && Some(e.id) != exclude)
                        .map(|e| e.id)
                        .collect();
                    for id in ids {
                        self.send_on_interface(id, &raw);
                    }
                }
                TransportAction::DeliverLocal {
                    destination_hash,
                    raw,
                    receiving_interface,
                    ..
                } if destination_hash == self.path_request_dest => {
                    // The engine answers for a destination of its own or a
                    // path it knows, and forwards the request otherwise.
                    if let Ok(packet) = RawPacket::unpack(&raw) {
                        let actions = self.engine.handle_path_request(
                            packet.data(),
                            receiving_interface,
                            now(),
                        );
                        self.dispatch_all(actions);
                    }
                }
                TransportAction::AnnounceLocalPathResponse {
                    destination_hash,
                    interface,
                    ..
                } => {
                    self.answer_local_path_request(destination_hash, interface);
                }
                TransportAction::DeliverLocal {
                    destination_hash,
                    raw,
                    packet_hash,
                    ..
                } => {
                    if self.handle_local_delivery(destination_hash, &raw) {
                        continue;
                    }
                    log::info!(
                        "Local delivery: dest={} pkt={}",
                        hex(&destination_hash[..4]),
                        hex(&packet_hash[..4])
                    );
                }
                TransportAction::AnnounceReceived(announce) => {
                    log::info!(
                        "Announce received: dest={} hops={}",
                        hex(&announce.destination_hash),
                        announce.hops
                    );
                    if let Some(ref stats) = self.stats {
                        stats.lock().unwrap().announces += 1;
                    }
                }
                TransportAction::PathUpdated {
                    destination_hash,
                    hops,
                    ..
                } => {
                    log::info!(
                        "Path updated: dest={} hops={}",
                        hex(&destination_hash[..4]),
                        hops
                    );
                }
                // Ignore actions not relevant to minimal LoRa node
                _ => {}
            }
        }
    }

    fn handle_local_delivery(&mut self, destination_hash: [u8; 16], raw: &[u8]) -> bool {
        if Some(destination_hash) != self.control_dest_hash {
            return false;
        }

        let packet = match RawPacket::unpack(raw) {
            Ok(packet) => packet,
            Err(err) => {
                log::warn!("Control packet unpack failed: {:?}", err);
                return true;
            }
        };

        if packet.flags.packet_type != constants::PACKET_TYPE_DATA
            || packet.flags.destination_type != constants::DESTINATION_SINGLE
            || packet.context != constants::CONTEXT_COMMAND
        {
            log::debug!("Ignoring non-control local packet for control destination");
            return true;
        }

        match authorize_request(packet.data(), &destination_hash, &mut self.replay_window) {
            Ok(request) => self.execute_control_request(request),
            Err(ControlAuthError::Parse(err)) => {
                log::warn!("Malformed control request: {:?}", err);
            }
            Err(ControlAuthError::UnauthorizedController) => {
                log::warn!("Rejected control request from unauthorized controller");
            }
            Err(ControlAuthError::InvalidSignature) => {
                log::warn!("Rejected control request with invalid signature");
            }
            Err(ControlAuthError::Replay) => {
                log::warn!("Rejected replayed control request");
            }
        }

        true
    }

    fn execute_control_request(&mut self, request: AuthorizedControlRequest) {
        let controller_prefix = hex(&request.controller_identity_hash[..4]);
        let command_body = request.body.clone();
        let (status, body) = match command_body {
            ControlBody::GetRadio => (
                ControlStatus::Ok,
                ControlResponseBody::Radio(self.active_radio_config),
            ),
            ControlBody::SetRadio(config) => {
                self.active_radio_config = config;
                if let Some(entry) = self.interfaces.first_mut() {
                    entry.writer.apply_config(config);
                    entry.tx.reconfigure(
                        config.spreading_factor,
                        config.bandwidth,
                        config.coding_rate,
                    );
                }
                if let Some(ref stats) = self.stats {
                    let mut stats = stats.lock().unwrap();
                    stats.active_freq = config.frequency;
                    stats.active_bw = config.bandwidth;
                    stats.active_sf = config.spreading_factor;
                    stats.active_cr = config.coding_rate;
                    stats.active_power = config.tx_power;
                    stats.set_status("Radio cfg applied");
                }
                (
                    ControlStatus::Ok,
                    ControlResponseBody::Radio(self.active_radio_config),
                )
            }
            ControlBody::GetBlePolicy => (
                ControlStatus::Ok,
                ControlResponseBody::BlePolicy {
                    ble_open_control: self.device_settings.ble_open_control,
                },
            ),
            ControlBody::SetBlePolicy { ble_open_control } => {
                self.device_settings.ble_open_control = ble_open_control;
                if let Some(ref stats) = self.stats {
                    let mut stats = stats.lock().unwrap();
                    stats.set_status(if ble_open_control {
                        "BLE control on"
                    } else {
                        "BLE control off"
                    });
                }
                let status = if self.persist_device_settings().is_ok() {
                    ControlStatus::Ok
                } else {
                    ControlStatus::PersistFailed
                };
                (
                    status,
                    ControlResponseBody::BlePolicy {
                        ble_open_control: self.device_settings.ble_open_control,
                    },
                )
            }
        };

        if let ControlBody::SetRadio(config) = command_body {
            log::info!(
                "Applied signed radio config from controller {}: freq={} sf={} bw={} cr=4/{} tx={}dBm",
                controller_prefix,
                config.frequency,
                config.spreading_factor,
                config.bandwidth,
                config.coding_rate,
                config.tx_power
            );
        }

        self.send_control_response(
            request.controller_identity_hash,
            request.command,
            request.request_id,
            status,
            body,
        );
    }

    fn send_control_response(
        &mut self,
        controller_identity_hash: [u8; 16],
        command: ControlCommand,
        request_id: [u8; 16],
        status: ControlStatus,
        body: ControlResponseBody,
    ) {
        let Some(identity) = self.identity.as_ref() else {
            return;
        };
        let reply_dest = control_reply_destination(&controller_identity_hash);
        if !self.engine.has_path(&reply_dest) {
            log::debug!(
                "No path to controller reply destination {}, skipping control response",
                hex(&reply_dest[..4])
            );
            return;
        }

        let Some(data) = encode_response(
            identity,
            &controller_identity_hash,
            command,
            status,
            request_id,
            body,
        ) else {
            log::warn!("Failed to encode control response");
            return;
        };

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_SINGLE,
            packet_type: constants::PACKET_TYPE_DATA,
        };

        let packet = match RawPacket::pack(
            flags,
            0,
            &reply_dest,
            None,
            constants::CONTEXT_COMMAND_STATUS,
            &data,
        ) {
            Ok(packet) => packet,
            Err(err) => {
                log::warn!("Failed to pack control response: {:?}", err);
                return;
            }
        };

        let actions =
            self.engine
                .handle_outbound(&packet, constants::DESTINATION_SINGLE, None, now());
        self.dispatch_all(actions);
    }

    fn persist_device_settings(&mut self) -> Result<(), String> {
        let Some(partition) = self.settings_partition.clone() else {
            return Err("missing NVS partition".into());
        };
        let nvs = EspNvs::<NvsDefault>::new(partition, NVS_NAMESPACE, true)
            .map_err(|err| format!("NVS open: {err}"))?;
        nvs.set_blob(NVS_KEY_SETTINGS, &self.device_settings.encode())
            .map_err(|err| format!("NVS write: {err}"))
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
            flags,
            0,
            &dest_hash,
            None,
            constants::CONTEXT_NONE,
            ping_data,
        ) {
            Ok(packet) => {
                let ids: Vec<_> = self
                    .interfaces
                    .iter()
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

    /// Announce when `ANNOUNCE_INTERVAL_SECS` is set and has passed since
    /// the last one, or at the first tick after boot.
    fn announce_if_due(&mut self) {
        let interval = crate::config::ANNOUNCE_INTERVAL_SECS as f64;
        if interval <= 0.0 || self.identity.is_none() {
            return;
        }
        let now = now();
        if self
            .last_auto_announce
            .is_some_and(|last| now - last < interval)
        {
            return;
        }
        self.last_auto_announce = Some(now);
        self.handle_send_announce();
    }

    /// Build and broadcast a Reticulum announce for this node's identity.
    fn handle_send_announce(&mut self) {
        log::info!("Sending announce");
        self.send_announce_for_aspects(&["transport"], None);
        if self.control_dest_hash.is_some() {
            self.send_announce_for_aspects(&["control"], None);
        }
        if let Some(ref stats) = self.stats {
            stats.lock().unwrap().set_status("Announce sent!");
        }
    }

    /// Answer a path request for one of this node's destinations with a
    /// path-response announce on the interface it came in on
    /// (`Transport.py:3450-3457`).
    fn answer_local_path_request(&mut self, destination_hash: [u8; 16], interface: InterfaceId) {
        let Some(identity_hash) = self.identity.as_ref().map(|id| *id.hash()) else {
            return;
        };
        let transport = rns_core::destination::destination_hash(
            "rns_esp32",
            &["transport"],
            Some(&identity_hash),
        );
        if destination_hash == transport {
            self.send_announce_for_aspects(&["transport"], Some(interface));
        } else if Some(destination_hash) == self.control_dest_hash {
            self.send_announce_for_aspects(&["control"], Some(interface));
        }
    }

    /// Announce this node's `rns_esp32.<aspects>` destination: a broadcast
    /// on every interface, or, with `path_response`, a `PATH_RESPONSE`
    /// announce on that interface only.
    fn send_announce_for_aspects(&mut self, aspects: &[&str], path_response: Option<InterfaceId>) {
        let identity = match &self.identity {
            Some(id) => id,
            None => {
                log::warn!("No identity set, cannot announce");
                return;
            }
        };
        let identity_hash = *identity.hash();
        let name_hash = rns_core::destination::name_hash("rns_esp32", aspects);
        let dest_hash =
            rns_core::destination::destination_hash("rns_esp32", aspects, Some(&identity_hash));

        let mut random_hash = [0u8; 10];
        self.rng.fill_bytes(&mut random_hash[..5]);
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        random_hash[5..10].copy_from_slice(&now_secs.to_be_bytes()[3..8]);

        match rns_core::announce::AnnounceData::pack(
            identity,
            &dest_hash,
            &name_hash,
            &random_hash,
            None,
            None,
        ) {
            Ok((announce_data, _)) => {
                let flags = PacketFlags {
                    header_type: constants::HEADER_1,
                    context_flag: constants::FLAG_UNSET,
                    transport_type: constants::TRANSPORT_BROADCAST,
                    destination_type: constants::DESTINATION_SINGLE,
                    packet_type: constants::PACKET_TYPE_ANNOUNCE,
                };
                match RawPacket::pack(
                    flags,
                    0,
                    &dest_hash,
                    None,
                    if path_response.is_some() {
                        constants::CONTEXT_PATH_RESPONSE
                    } else {
                        constants::CONTEXT_NONE
                    },
                    &announce_data,
                ) {
                    Ok(packet) => {
                        let actions = self.engine.handle_outbound(
                            &packet,
                            constants::DESTINATION_SINGLE,
                            path_response,
                            now(),
                        );
                        self.dispatch_all(actions);
                        log::info!("Announce sent for dest={}", hex(&dest_hash));
                    }
                    Err(err) => log::error!("Failed to pack announce: {:?}", err),
                }
            }
            Err(err) => log::error!("Failed to build announce: {:?}", err),
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

        if !entry.tx.push(frame) {
            log::warn!("TX queue full on {:?}, dropping a frame", id);
        }
    }

    /// How long the event loop waits for an event: a fraction of a CSMA
    /// slot while frames are queued, so listen before talk is timely.
    fn event_wait(&self) -> Duration {
        let queued = self
            .interfaces
            .iter()
            .filter(|e| e.online && !e.tx.is_empty())
            .map(|e| e.tx.poll_interval_ms())
            .min();
        Duration::from_millis(queued.unwrap_or(EVENT_WAIT_IDLE_MS))
    }

    /// Send queued frames on each interface once its channel allows: listen
    /// before talk, then everything queued in one channel access, as RNode
    /// firmware does.
    fn service_tx(&mut self) {
        for entry in self.interfaces.iter_mut().filter(|e| e.online) {
            if entry.tx.is_empty() {
                continue;
            }
            let writer = &entry.writer;
            let Some(frames) = entry.tx.take_ready(
                now_ms(),
                || !writer.carrier_detected(),
                &mut crate::rng::random_range,
            ) else {
                continue;
            };
            for frame in frames {
                let result = entry.writer.send_frame(&frame);
                entry.tx.record_sent(now_ms(), &frame);
                match result {
                    Ok(()) => {
                        log::debug!("TX {} bytes on {:?}", frame.len(), entry.id);
                        if let Some(ref stats) = self.stats {
                            stats.lock().unwrap().tx_bytes += frame.len() as u32;
                        }
                    }
                    Err(e) => {
                        log::error!("TX error on {:?}: {}", entry.id, e);
                    }
                }
            }
        }
    }
}

/// Spawn a tick thread that sends Event::Tick at a regular interval.
/// Exits when `shutdown` is set to true or the channel closes.
pub fn spawn_tick_thread(
    tx: mpsc::Sender<Event>,
    interval_ms: u64,
    shutdown: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("tick".into())
        .stack_size(2048)
        .spawn(move || {
            let interval = Duration::from_millis(interval_ms);
            let mut last = std::time::Instant::now();
            loop {
                // Short sleeps, so a mode switch does not wait out a tick.
                std::thread::sleep(Duration::from_millis(SHUTDOWN_POLL_MS));
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                if last.elapsed() < interval {
                    continue;
                }
                last = std::time::Instant::now();
                if tx.send(Event::Tick).is_err() {
                    break;
                }
            }
        })
        .expect("failed to spawn tick thread")
}

/// Milliseconds since boot (monotonic), for the channel logic.
fn now_ms() -> u64 {
    let ticks = unsafe { esp_idf_sys::esp_timer_get_time() };
    (ticks / 1_000) as u64
}

/// Get current time as seconds since boot (monotonic).
fn now() -> f64 {
    let ticks = unsafe { esp_idf_sys::esp_timer_get_time() };
    ticks as f64 / 1_000_000.0
}
