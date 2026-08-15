//! Weave Device Control Link (WDCL) framing and interface state.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rns_core::transport::types::{InterfaceId, InterfaceInfo};
use rns_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use rns_crypto::sha256::sha256;
use rns_crypto::OsRng;

use super::{InterfaceConfigData, InterfaceFactory, StartContext, StartResult, Writer};
use crate::event::{DynamicInterfaceRegistration, Event, EventSender, InterfaceTelemetry};
use crate::serial::{Parity, SerialConfig, SerialPort};

pub const WDCL_T_DISCOVER: u8 = 0x00;
pub const WDCL_T_CONNECT: u8 = 0x01;
pub const WDCL_T_CMD: u8 = 0x02;
pub const WDCL_T_LOG: u8 = 0x03;
pub const WDCL_T_DISP: u8 = 0x04;
pub const WDCL_T_ENDPOINT_PKT: u8 = 0x05;
pub const WDCL_T_ENCAP_PROTO: u8 = 0x06;
pub const WDCL_BROADCAST: [u8; 4] = [0xff; 4];

pub const WDCL_CMD_ENDPOINT_PKT: u16 = 0x0001;
pub const WDCL_CMD_ENDPOINTS_LIST: u16 = 0x0100;
pub const WDCL_CMD_REMOTE_DISPLAY: u16 = 0x0a00;
pub const WDCL_CMD_REMOTE_INPUT: u16 = 0x0a01;

pub const ET_BOARD_INIT: u16 = 0x0003;
pub const ET_PROTO_WDCL_CONNECTION: u16 = 0x3002;
pub const ET_PROTO_WDCL_HOST_ENDPOINT: u16 = 0x3003;
pub const ET_PROTO_WEAVE_EP_ALIVE: u16 = 0x3102;
pub const ET_PROTO_WEAVE_EP_TIMEOUT: u16 = 0x3103;
pub const ET_PROTO_WEAVE_EP_VIA: u16 = 0x3104;
pub const ET_STAT_CPU: u16 = 0xe003;
pub const ET_STAT_MEMORY: u16 = 0xe005;

pub const WEAVE_HW_MTU: u32 = 1024;
pub const WEAVE_DEFAULT_BITRATE: u64 = 250_000;
pub const WEAVE_PEERING_TIMEOUT: f64 = 20.0;
pub const WEAVE_DUPLICATE_TTL: f64 = 0.75;
pub const WEAVE_DUPLICATE_CAPACITY: usize = 48;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WdclFrame {
    pub destination: [u8; 4],
    pub frame_type: u8,
    pub payload: Vec<u8>,
}

impl WdclFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(5 + self.payload.len());
        output.extend_from_slice(&self.destination);
        output.push(self.frame_type);
        output.extend_from_slice(&self.payload);
        output
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }
        Some(Self {
            destination: data[..4].try_into().ok()?,
            frame_type: data[4],
            payload: data[5..].to_vec(),
        })
    }

    pub fn command(destination: [u8; 4], command: u16, data: &[u8]) -> Self {
        let mut payload = Vec::with_capacity(2 + data.len());
        payload.extend_from_slice(&command.to_be_bytes());
        payload.extend_from_slice(data);
        Self {
            destination,
            frame_type: WDCL_T_CMD,
            payload,
        }
    }

    pub fn endpoint_packet(destination: [u8; 4], endpoint: [u8; 8], packet: &[u8]) -> Self {
        let mut data = Vec::with_capacity(8 + packet.len());
        data.extend_from_slice(&endpoint);
        data.extend_from_slice(packet);
        Self::command(destination, WDCL_CMD_ENDPOINT_PKT, &data)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WeaveLogFrame {
    pub timestamp: f64,
    pub level: u8,
    pub event: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WeaveInput {
    Discovery {
        switch_id: [u8; 4],
        signing_key: [u8; 32],
    },
    EndpointPacket {
        source: [u8; 8],
        packet: Vec<u8>,
    },
    Log(WeaveLogFrame),
    Display {
        offset: usize,
        total: usize,
        fragment: Vec<u8>,
    },
    Unknown(WdclFrame),
}

/// Validate and classify a device frame. Discovery signatures cover the
/// destination/signed switch ID exactly as in Reticulum 1.3.8.
pub fn parse_device_frame(data: &[u8], host_switch_id: [u8; 4]) -> Option<WeaveInput> {
    let frame = WdclFrame::decode(data)?;
    match frame.frame_type {
        WDCL_T_DISCOVER if frame.payload.len() == 96 => {
            let key: [u8; 32] = frame.payload[..32].try_into().ok()?;
            let signature: [u8; 64] = frame.payload[32..].try_into().ok()?;
            if !Ed25519PublicKey::from_bytes(&key).verify(&signature, &frame.destination) {
                return None;
            }
            Some(WeaveInput::Discovery {
                switch_id: key[28..].try_into().ok()?,
                signing_key: key,
            })
        }
        WDCL_T_ENDPOINT_PKT if frame.destination == host_switch_id && frame.payload.len() > 8 => {
            let split = frame.payload.len() - 8;
            Some(WeaveInput::EndpointPacket {
                source: frame.payload[split..].try_into().ok()?,
                packet: frame.payload[..split].to_vec(),
            })
        }
        WDCL_T_LOG if frame.payload.len() >= 9 => {
            // Firmware prepends a flow byte to the eight-byte log header.
            let data = &frame.payload[1..];
            Some(WeaveInput::Log(WeaveLogFrame {
                timestamp: u32::from_be_bytes(data[..4].try_into().ok()?) as f64 / 1000.0,
                level: data[4],
                event: u16::from_be_bytes(data[5..7].try_into().ok()?),
                data: data[7..].to_vec(),
            }))
        }
        WDCL_T_DISP if frame.payload.len() >= 9 => Some(WeaveInput::Display {
            offset: u32::from_be_bytes(frame.payload[1..5].try_into().ok()?) as usize,
            total: u32::from_be_bytes(frame.payload[5..9].try_into().ok()?) as usize,
            fragment: frame.payload[9..].to_vec(),
        }),
        _ => Some(WeaveInput::Unknown(frame)),
    }
}

#[derive(Debug, Clone)]
pub struct WeavePeerState {
    pub endpoint_id: [u8; 8],
    pub via_switch_id: Option<[u8; 4]>,
    pub last_heard: f64,
}

#[derive(Debug, Clone, Default)]
pub struct WeaveState {
    pub connected: bool,
    pub switch_id: Option<[u8; 4]>,
    pub endpoint_id: Option<[u8; 8]>,
    pub cpu_load: Option<u8>,
    pub mem_load: Option<f64>,
    pub peers: HashMap<[u8; 8], WeavePeerState>,
    pub logs: VecDeque<WeaveLogFrame>,
    pub display: Vec<u8>,
    pub unknown_events: VecDeque<WeaveLogFrame>,
    duplicates: VecDeque<([u8; 32], f64)>,
}

impl WeaveState {
    pub fn accept_packet(&mut self, packet: &[u8], now: f64) -> bool {
        while self
            .duplicates
            .front()
            .is_some_and(|entry| now >= entry.1 + WEAVE_DUPLICATE_TTL)
        {
            self.duplicates.pop_front();
        }
        let hash = sha256(packet);
        if self.duplicates.iter().any(|entry| entry.0 == hash) {
            return false;
        }
        if self.duplicates.len() == WEAVE_DUPLICATE_CAPACITY {
            self.duplicates.pop_front();
        }
        self.duplicates.push_back((hash, now));
        true
    }

    pub fn handle_log(&mut self, frame: WeaveLogFrame, now: f64) {
        if self.logs.len() == 1024 {
            self.logs.pop_front();
        }
        self.logs.push_back(frame.clone());
        match frame.event {
            ET_BOARD_INIT => {}
            ET_PROTO_WDCL_CONNECTION => self.connected = true,
            ET_PROTO_WDCL_HOST_ENDPOINT if frame.data.len() == 8 => {
                self.endpoint_id = frame.data.as_slice().try_into().ok();
            }
            ET_PROTO_WEAVE_EP_ALIVE if frame.data.len() == 8 => {
                let endpoint_id: [u8; 8] = frame.data.as_slice().try_into().unwrap();
                self.peers
                    .entry(endpoint_id)
                    .and_modify(|peer| peer.last_heard = now)
                    .or_insert(WeavePeerState {
                        endpoint_id,
                        via_switch_id: None,
                        last_heard: now,
                    });
            }
            ET_PROTO_WEAVE_EP_TIMEOUT if frame.data.len() == 8 => {
                if let Ok(endpoint) = <[u8; 8]>::try_from(frame.data.as_slice()) {
                    self.peers.remove(&endpoint);
                }
            }
            ET_PROTO_WEAVE_EP_VIA if frame.data.len() == 12 => {
                let endpoint: [u8; 8] = frame.data[..8].try_into().unwrap();
                let via: [u8; 4] = frame.data[8..].try_into().unwrap();
                if let Some(peer) = self.peers.get_mut(&endpoint) {
                    peer.via_switch_id = Some(via);
                }
            }
            ET_STAT_CPU if !frame.data.is_empty() => self.cpu_load = Some(frame.data[0]),
            ET_STAT_MEMORY if frame.data.len() == 8 => {
                let free = u32::from_be_bytes(frame.data[..4].try_into().unwrap()) as f64;
                let total = u32::from_be_bytes(frame.data[4..].try_into().unwrap()) as f64;
                self.mem_load = (total > 0.0).then_some(((total - free) / total) * 100.0);
            }
            _ => self.unknown_events.push_back(frame),
        }
    }

    pub fn expire_peers(&mut self, now: f64) -> Vec<[u8; 8]> {
        let expired: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(id, peer)| {
                (now >= peer.last_heard + WEAVE_PEERING_TIMEOUT).then_some(*id)
            })
            .collect();
        for id in &expired {
            self.peers.remove(id);
        }
        expired
    }

    pub fn apply_display(&mut self, offset: usize, total: usize, fragment: &[u8]) -> bool {
        if total > 128 * 64 / 8 || offset > total || fragment.len() > total - offset {
            return false;
        }
        self.display.resize(total, 0);
        self.display[offset..offset + fragment.len()].copy_from_slice(fragment);
        offset + fragment.len() == total
    }
}

#[derive(Debug, Clone)]
pub struct WeaveConfig {
    pub name: String,
    pub port: String,
    pub configured_bitrate: u64,
    pub interface_id: InterfaceId,
    pub state: Arc<Mutex<WeaveState>>,
}

struct WeaveSession {
    config: WeaveConfig,
    tx: EventSender,
    next_dynamic_id: Arc<AtomicU64>,
    mode: u8,
    gravity: i64,
    recursive_prs: bool,
    announces_from_internal: bool,
    announces_to_internal: Option<bool>,
    ingress_control: rns_core::transport::types::IngressControlConfig,
    ifac: Option<crate::ifac::IfacState>,
    host_identity: Arc<Ed25519PrivateKey>,
    host_public: [u8; 32],
    host_switch_id: [u8; 4],
    writer: Arc<Mutex<Option<std::fs::File>>>,
    remote_switch_id: Arc<Mutex<Option<[u8; 4]>>>,
    peer_interfaces: Arc<Mutex<HashMap<[u8; 8], InterfaceId>>>,
}

impl WeaveSession {
    fn new(config: WeaveConfig, ctx: &StartContext) -> Arc<Self> {
        let identity = Ed25519PrivateKey::generate(&mut OsRng);
        let host_public = identity.public_key().public_bytes();
        Arc::new(Self {
            config,
            tx: ctx.tx.clone(),
            next_dynamic_id: Arc::clone(&ctx.next_dynamic_id),
            mode: ctx.mode,
            gravity: ctx.gravity,
            recursive_prs: ctx.recursive_prs,
            announces_from_internal: ctx.announces_from_internal,
            announces_to_internal: ctx.announces_to_internal,
            ingress_control: ctx.ingress_control,
            ifac: ctx.ifac.clone(),
            host_identity: Arc::new(identity),
            host_public,
            host_switch_id: host_public[28..].try_into().unwrap(),
            writer: Arc::new(Mutex::new(None)),
            remote_switch_id: Arc::new(Mutex::new(None)),
            peer_interfaces: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn spawn(self: &Arc<Self>) -> io::Result<()> {
        let session = Arc::clone(self);
        thread::Builder::new()
            .name(format!("weave-session-{}", self.config.interface_id.0))
            .spawn(move || session.reconnect_loop())?;
        Ok(())
    }

    fn reconnect_loop(self: Arc<Self>) {
        loop {
            if let Err(error) = self.run_connection() {
                log::warn!(
                    "[{}] Weave connection failed: {}; retrying in five seconds",
                    self.config.name,
                    error
                );
            }
            self.disconnect_all();
            thread::sleep(Duration::from_secs(5));
        }
    }

    fn run_connection(self: &Arc<Self>) -> io::Result<()> {
        let port = SerialPort::open(&SerialConfig {
            path: self.config.port.clone(),
            baud: 3_000_000,
            data_bits: 8,
            parity: Parity::None,
            stop_bits: 1,
        })?;
        let mut reader = port.reader()?;
        *super::lock_or_recover(&self.writer, "weave writer") = Some(port.writer()?);
        *super::lock_or_recover(&self.remote_switch_id, "weave remote switch") = None;
        {
            let mut state = super::lock_or_recover(&self.config.state, "weave state");
            state.connected = false;
            state.switch_id = None;
        }

        self.send_frame(&WdclFrame {
            destination: WDCL_BROADCAST,
            frame_type: WDCL_T_DISCOVER,
            payload: self.host_switch_id.to_vec(),
        })?;

        let handshake_deadline = Instant::now() + Duration::from_secs(2);
        let mut decoder = crate::hdlc::Decoder::with_limits(5, 128 * 1024);
        let mut buffer = [0u8; 32 * 1024];
        let mut last_peer_expiry = Instant::now();
        loop {
            let mut pollfd = libc::pollfd {
                fd: reader.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut pollfd, 1, 250) };
            if ready < 0 {
                return Err(io::Error::last_os_error());
            }
            if ready > 0 {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "serial port closed",
                    ));
                }
                for frame in decoder.feed(&buffer[..read]) {
                    self.process_frame(&frame)?;
                }
            }

            let connected = super::lock_or_recover(&self.config.state, "weave state").connected;
            if !connected && Instant::now() >= handshake_deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "WDCL connection handshake timed out",
                ));
            }
            if last_peer_expiry.elapsed() >= Duration::from_secs(1) {
                self.expire_peers(crate::time::now());
                last_peer_expiry = Instant::now();
            }
        }
    }

    fn send_frame(&self, frame: &WdclFrame) -> io::Result<()> {
        let encoded = crate::hdlc::frame(&frame.encode());
        let mut writer = super::lock_or_recover(&self.writer, "weave writer");
        writer
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Weave is offline"))?
            .write_all(&encoded)
    }

    fn process_frame(self: &Arc<Self>, raw: &[u8]) -> io::Result<()> {
        let Some(input) = parse_device_frame(raw, self.host_switch_id) else {
            return Ok(());
        };
        match input {
            WeaveInput::Discovery {
                switch_id,
                signing_key: _,
            } => {
                *super::lock_or_recover(&self.remote_switch_id, "weave remote switch") =
                    Some(switch_id);
                super::lock_or_recover(&self.config.state, "weave state").switch_id =
                    Some(switch_id);
                let mut payload = self.host_public.to_vec();
                payload.extend_from_slice(&self.host_identity.sign(&switch_id));
                self.send_frame(&WdclFrame {
                    destination: switch_id,
                    frame_type: WDCL_T_CONNECT,
                    payload,
                })?;
            }
            WeaveInput::EndpointPacket { source, packet } => {
                let now = crate::time::now();
                {
                    let mut state = super::lock_or_recover(&self.config.state, "weave state");
                    state
                        .peers
                        .entry(source)
                        .and_modify(|peer| peer.last_heard = now)
                        .or_insert(WeavePeerState {
                            endpoint_id: source,
                            via_switch_id: None,
                            last_heard: now,
                        });
                    if !state.accept_packet(&packet, now) {
                        return Ok(());
                    }
                }
                let interface_id = self.ensure_peer(source, now);
                let _ = self.tx.send(Event::Frame {
                    interface_id,
                    data: packet,
                    rssi: None,
                    snr: None,
                });
            }
            WeaveInput::Log(frame) => self.process_log(frame),
            WeaveInput::Display {
                offset,
                total,
                fragment,
            } => {
                super::lock_or_recover(&self.config.state, "weave state")
                    .apply_display(offset, total, &fragment);
            }
            WeaveInput::Unknown(_) => {}
        }
        Ok(())
    }

    fn process_log(self: &Arc<Self>, frame: WeaveLogFrame) {
        let now = crate::time::now();
        let event = frame.event;
        let data = frame.data.clone();
        super::lock_or_recover(&self.config.state, "weave state").handle_log(frame, now);

        match event {
            ET_PROTO_WDCL_CONNECTION => {
                let _ = self
                    .tx
                    .send(Event::InterfaceUp(self.config.interface_id, None, None));
                self.publish_parent_telemetry();
            }
            ET_PROTO_WEAVE_EP_ALIVE if data.len() == 8 => {
                let endpoint: [u8; 8] = data.as_slice().try_into().unwrap();
                self.ensure_peer(endpoint, now);
            }
            ET_PROTO_WEAVE_EP_TIMEOUT if data.len() == 8 => {
                let endpoint: [u8; 8] = data.as_slice().try_into().unwrap();
                self.remove_peer(endpoint);
            }
            ET_PROTO_WEAVE_EP_VIA if data.len() == 12 => {
                let endpoint: [u8; 8] = data[..8].try_into().unwrap();
                let via: [u8; 4] = data[8..].try_into().unwrap();
                if let Some(interface_id) =
                    super::lock_or_recover(&self.peer_interfaces, "weave peer interfaces")
                        .get(&endpoint)
                        .copied()
                {
                    let _ = self.tx.send(Event::InterfaceTelemetry {
                        interface_id,
                        telemetry: InterfaceTelemetry {
                            via_switch_id: Some(via),
                            ..Default::default()
                        },
                    });
                }
            }
            ET_PROTO_WDCL_HOST_ENDPOINT | ET_STAT_CPU | ET_STAT_MEMORY => {
                self.publish_parent_telemetry()
            }
            _ => {}
        }
    }

    fn ensure_peer(self: &Arc<Self>, endpoint: [u8; 8], now: f64) -> InterfaceId {
        if let Some(id) = super::lock_or_recover(&self.peer_interfaces, "weave peers")
            .get(&endpoint)
            .copied()
        {
            return id;
        }
        let id = InterfaceId(self.next_dynamic_id.fetch_add(1, Ordering::Relaxed));
        super::lock_or_recover(&self.peer_interfaces, "weave peers").insert(endpoint, id);
        let via_switch_id = super::lock_or_recover(&self.config.state, "weave state")
            .peers
            .get(&endpoint)
            .and_then(|peer| peer.via_switch_id);
        let name = format!("WeaveInterfacePeer[{}]", hex(&endpoint));
        let info = InterfaceInfo {
            id,
            name,
            mode: self.mode,
            gravity: self.gravity,
            recursive_prs: self.recursive_prs,
            announces_from_internal: self.announces_from_internal,
            announces_to_internal: self.announces_to_internal,
            out_capable: true,
            in_capable: true,
            bitrate: Some(self.config.configured_bitrate),
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: rns_core::constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: WEAVE_HW_MTU,
            ia_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: now,
            ingress_control: self.ingress_control,
        };
        let _ = self.tx.send(Event::DynamicInterfaceUp {
            id,
            writer: Box::new(WeavePeerWriter {
                session: Arc::clone(self),
                endpoint,
            }),
            registration: DynamicInterfaceRegistration {
                info,
                interface_type: "WeaveInterfacePeer".into(),
                parent_id: self.config.interface_id,
                telemetry: InterfaceTelemetry {
                    via_switch_id,
                    ..Default::default()
                },
                ifac: self.ifac.clone(),
            },
        });
        self.publish_parent_telemetry();
        id
    }

    fn remove_peer(&self, endpoint: [u8; 8]) {
        if let Some(id) =
            super::lock_or_recover(&self.peer_interfaces, "weave peers").remove(&endpoint)
        {
            super::lock_or_recover(&self.config.state, "weave state")
                .peers
                .remove(&endpoint);
            let _ = self.tx.send(Event::InterfaceDown(id));
            self.publish_parent_telemetry();
        }
    }

    fn expire_peers(&self, now: f64) {
        let expired = super::lock_or_recover(&self.config.state, "weave state").expire_peers(now);
        for endpoint in &expired {
            if let Some(id) =
                super::lock_or_recover(&self.peer_interfaces, "weave peers").remove(endpoint)
            {
                let _ = self.tx.send(Event::InterfaceDown(id));
            }
        }
        if !super::lock_or_recover(&self.peer_interfaces, "weave peers").is_empty()
            || !expired.is_empty()
        {
            self.publish_parent_telemetry();
        }
    }

    fn publish_parent_telemetry(&self) {
        let state = super::lock_or_recover(&self.config.state, "weave state");
        let _ = self.tx.send(Event::InterfaceTelemetry {
            interface_id: self.config.interface_id,
            telemetry: InterfaceTelemetry {
                cpu_load: state.cpu_load.map(f64::from),
                mem_load: state.mem_load,
                switch_id: state.switch_id,
                endpoint_id: state.endpoint_id,
                via_switch_id: None,
                peers: Some(state.peers.len()),
            },
        });
    }

    fn disconnect_all(&self) {
        *super::lock_or_recover(&self.writer, "weave writer") = None;
        *super::lock_or_recover(&self.remote_switch_id, "weave remote switch") = None;
        {
            let mut state = super::lock_or_recover(&self.config.state, "weave state");
            state.connected = false;
            state.switch_id = None;
            state.peers.clear();
        }
        let peers: Vec<_> = super::lock_or_recover(&self.peer_interfaces, "weave peers")
            .drain()
            .map(|(_, id)| id)
            .collect();
        for id in peers {
            let _ = self.tx.send(Event::InterfaceDown(id));
        }
        let _ = self.tx.send(Event::InterfaceDown(self.config.interface_id));
        self.publish_parent_telemetry();
    }
}

struct WeavePeerWriter {
    session: Arc<WeaveSession>,
    endpoint: [u8; 8],
}

impl Writer for WeavePeerWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        let remote = super::lock_or_recover(&self.session.remote_switch_id, "weave remote switch")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Weave is offline"))?;
        self.session
            .send_frame(&WdclFrame::endpoint_packet(remote, self.endpoint, data))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub struct WeaveFactory;
struct ParentWriter;
impl Writer for ParentWriter {
    fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
        Ok(())
    }
}

impl InterfaceFactory for WeaveFactory {
    fn type_name(&self) -> &str {
        "WeaveInterface"
    }
    fn default_ifac_size(&self) -> usize {
        16
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        let port = params
            .get("port")
            .cloned()
            .ok_or_else(|| "WeaveInterface requires 'port'".to_string())?;
        let configured_bitrate = params
            .get("configured_bitrate")
            .and_then(|v| v.parse().ok())
            .unwrap_or(WEAVE_DEFAULT_BITRATE);
        Ok(Box::new(WeaveConfig {
            name: name.into(),
            port,
            configured_bitrate,
            interface_id: id,
            state: Arc::new(Mutex::new(WeaveState::default())),
        }))
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> io::Result<StartResult> {
        let config = *config
            .into_any()
            .downcast::<WeaveConfig>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "wrong Weave config type"))?;
        let session = WeaveSession::new(config.clone(), &ctx);
        session.spawn()?;
        let info = InterfaceInfo {
            id: config.interface_id,
            name: config.name.clone(),
            mode: ctx.mode,
            gravity: ctx.gravity,
            recursive_prs: ctx.recursive_prs,
            announces_from_internal: ctx.announces_from_internal,
            announces_to_internal: ctx.announces_to_internal,
            out_capable: false,
            in_capable: true,
            bitrate: Some(config.configured_bitrate),
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: rns_core::constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: WEAVE_HW_MTU,
            ia_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: crate::time::now(),
            ingress_control: ctx.ingress_control,
        };
        Ok(StartResult::Simple {
            id: config.interface_id,
            info,
            writer: Box::new(ParentWriter),
            interface_type_name: "WeaveInterface".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::ed25519::Ed25519PrivateKey;
    use rns_crypto::FixedRng;

    fn log_frame(host: [u8; 4], event: u16, data: &[u8]) -> Vec<u8> {
        let mut payload = vec![0, 0, 0, 0, 1, 2];
        payload.extend_from_slice(&event.to_be_bytes());
        payload.extend_from_slice(data);
        WdclFrame {
            destination: host,
            frame_type: WDCL_T_LOG,
            payload,
        }
        .encode()
    }

    #[test]
    fn wdcl_fragmented_hdlc_and_discovery_signature() {
        let private = Ed25519PrivateKey::generate(&mut FixedRng::new(&[7; 64]));
        let key = private.public_key().public_bytes();
        let signed_id = [1, 2, 3, 4];
        let mut payload = key.to_vec();
        payload.extend_from_slice(&private.sign(&signed_id));
        let frame = WdclFrame {
            destination: signed_id,
            frame_type: WDCL_T_DISCOVER,
            payload,
        }
        .encode();
        assert!(matches!(
            parse_device_frame(&frame, [9; 4]),
            Some(WeaveInput::Discovery { .. })
        ));

        let wire = crate::hdlc::frame(&frame);
        let mut decoder = crate::hdlc::Decoder::with_min_frame_size(5);
        assert!(decoder.feed(&wire[..3]).is_empty());
        assert_eq!(decoder.feed(&wire[3..]), vec![frame]);
    }

    #[test]
    fn board_init_unknown_and_duplicate_state_are_preserved() {
        let mut state = WeaveState::default();
        state.handle_log(
            WeaveLogFrame {
                timestamp: 1.0,
                level: 1,
                event: ET_BOARD_INIT,
                data: vec![1],
            },
            1.0,
        );
        state.handle_log(
            WeaveLogFrame {
                timestamp: 2.0,
                level: 1,
                event: 0x7777,
                data: vec![2],
            },
            2.0,
        );
        assert_eq!(state.logs.len(), 2);
        assert_eq!(state.unknown_events.len(), 1);
        assert!(state.accept_packet(b"packet", 3.0));
        assert!(!state.accept_packet(b"packet", 3.1));
        assert!(state.accept_packet(b"packet", 4.0));
    }

    #[test]
    fn simulated_session_authenticates_and_manages_endpoint_lifecycle() {
        let (tx, rx) = crate::event::channel();
        let config = WeaveConfig {
            name: "weave-test".into(),
            port: "/dev/null".into(),
            configured_bitrate: WEAVE_DEFAULT_BITRATE,
            interface_id: InterfaceId(55),
            state: Arc::new(Mutex::new(WeaveState::default())),
        };
        let context = StartContext {
            tx,
            next_dynamic_id: Arc::new(AtomicU64::new(10_000)),
            mode: rns_core::constants::MODE_GATEWAY,
            gravity: 0,
            recursive_prs: true,
            announces_from_internal: false,
            announces_to_internal: None,
            ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
            ifac: None,
        };
        let session = WeaveSession::new(config, &context);
        *super::super::lock_or_recover(&session.writer, "test writer") =
            Some(tempfile::tempfile().unwrap());

        let remote = Ed25519PrivateKey::generate(&mut FixedRng::new(&[0x44; 64]));
        let remote_public = remote.public_key().public_bytes();
        let mut discovery_payload = remote_public.to_vec();
        discovery_payload.extend_from_slice(&remote.sign(&session.host_switch_id));
        session
            .process_frame(
                &WdclFrame {
                    destination: session.host_switch_id,
                    frame_type: WDCL_T_DISCOVER,
                    payload: discovery_payload,
                }
                .encode(),
            )
            .unwrap();
        assert_eq!(
            *super::super::lock_or_recover(&session.remote_switch_id, "test remote"),
            Some(remote_public[28..].try_into().unwrap())
        );

        session
            .process_frame(&log_frame(
                session.host_switch_id,
                ET_PROTO_WDCL_CONNECTION,
                &[1],
            ))
            .unwrap();
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            Event::InterfaceUp(InterfaceId(55), None, None)
        ));

        let endpoint = [0x77; 8];
        session
            .process_frame(&log_frame(
                session.host_switch_id,
                ET_PROTO_WEAVE_EP_ALIVE,
                &endpoint,
            ))
            .unwrap();
        let peer_id = loop {
            if let Event::DynamicInterfaceUp {
                id, registration, ..
            } = rx.recv_timeout(Duration::from_secs(1)).unwrap()
            {
                assert_eq!(registration.interface_type, "WeaveInterfacePeer");
                assert_eq!(registration.parent_id, InterfaceId(55));
                break id;
            }
        };

        let mut endpoint_payload = b"rns-packet".to_vec();
        endpoint_payload.extend_from_slice(&endpoint);
        let endpoint_frame = WdclFrame {
            destination: session.host_switch_id,
            frame_type: WDCL_T_ENDPOINT_PKT,
            payload: endpoint_payload,
        }
        .encode();
        session.process_frame(&endpoint_frame).unwrap();
        assert!(loop {
            if let Event::Frame {
                interface_id, data, ..
            } = rx.recv_timeout(Duration::from_secs(1)).unwrap()
            {
                break interface_id == peer_id && data == b"rns-packet";
            }
        });
        session.process_frame(&endpoint_frame).unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());

        session.expire_peers(crate::time::now() + WEAVE_PEERING_TIMEOUT + 1.0);
        assert!(loop {
            if let Event::InterfaceDown(id) = rx.recv_timeout(Duration::from_secs(1)).unwrap() {
                break id == peer_id;
            }
        });
    }
}
