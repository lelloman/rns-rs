//! Weave Device Control Link (WDCL) framing and interface state.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::{Arc, Mutex};

use rns_core::transport::types::{InterfaceId, InterfaceInfo};
use rns_crypto::ed25519::Ed25519PublicKey;
use rns_crypto::sha256::sha256;

use super::{InterfaceConfigData, InterfaceFactory, StartContext, StartResult, Writer};

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
        match frame.event {
            ET_BOARD_INIT => self.logs.push_back(frame),
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
        let info = InterfaceInfo {
            id: config.interface_id,
            name: config.name,
            mode: ctx.mode,
            recursive_prs: ctx.recursive_prs,
            announces_from_internal: ctx.announces_from_internal,
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
        assert_eq!(state.logs.len(), 1);
        assert_eq!(state.unknown_events.len(), 1);
        assert!(state.accept_packet(b"packet", 3.0));
        assert!(!state.accept_packet(b"packet", 3.1));
        assert!(state.accept_packet(b"packet", 4.0));
    }
}
