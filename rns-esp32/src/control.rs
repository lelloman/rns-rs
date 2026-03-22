use std::collections::VecDeque;

use rns_core::destination::destination_hash;
use rns_crypto::identity::Identity;

use crate::protocol::{validate_radio_config, RadioConfig};

const REQUEST_SIGNATURE_LEN: usize = 64;
const REQUEST_ID_LEN: usize = 16;
const PUBLIC_KEY_LEN: usize = 64;
const RADIO_CONFIG_ENCODED_LEN: usize = 11;
const REQUEST_DOMAIN: &[u8] = b"rns-esp32-control-request-v1";
const RESPONSE_DOMAIN: &[u8] = b"rns-esp32-control-response-v1";
const MAX_REPLAY_IDS_PER_CONTROLLER: usize = 16;

pub const CONTROL_PROTOCOL_VERSION: u8 = 1;
pub const CONTROL_APP_NAME: &str = "rns_esp32";
pub const CONTROL_REQUEST_ASPECTS: &[&str] = &["control"];
pub const CONTROL_REPLY_ASPECTS: &[&str] = &["control", "reply"];

include!(concat!(env!("OUT_DIR"), "/control_build_config.rs"));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ControlCommand {
    GetRadio = 1,
    SetRadio = 2,
    GetBlePolicy = 3,
    SetBlePolicy = 4,
}

impl ControlCommand {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::GetRadio),
            2 => Some(Self::SetRadio),
            3 => Some(Self::GetBlePolicy),
            4 => Some(Self::SetBlePolicy),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ControlStatus {
    Ok = 0,
    InvalidRequest = 1,
    InvalidConfig = 2,
    Unsupported = 3,
    PersistFailed = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlBody {
    GetRadio,
    SetRadio(RadioConfig),
    GetBlePolicy,
    SetBlePolicy { ble_open_control: bool },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlRequest {
    pub command: ControlCommand,
    pub request_id: [u8; REQUEST_ID_LEN],
    pub controller_pubkey: [u8; PUBLIC_KEY_LEN],
    pub body: ControlBody,
    pub signature: [u8; REQUEST_SIGNATURE_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedControlRequest {
    pub controller_index: usize,
    pub controller_identity_hash: [u8; 16],
    pub request_id: [u8; REQUEST_ID_LEN],
    pub command: ControlCommand,
    pub body: ControlBody,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlResponseBody {
    None,
    Radio(RadioConfig),
    BlePolicy { ble_open_control: bool },
    ErrorCode(ControlStatus),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlResponse {
    pub command: ControlCommand,
    pub status: ControlStatus,
    pub request_id: [u8; REQUEST_ID_LEN],
    pub body: ControlResponseBody,
    pub signature: [u8; REQUEST_SIGNATURE_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlParseError {
    TooShort,
    UnsupportedVersion(u8),
    UnknownCommand(u8),
    InvalidBodyLength,
    InvalidRadioConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlAuthError {
    Parse(ControlParseError),
    UnauthorizedController,
    InvalidSignature,
    Replay,
}

#[derive(Clone, Debug)]
pub struct ReplayWindow {
    recent: [VecDeque<[u8; REQUEST_ID_LEN]>; 3],
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            recent: std::array::from_fn(|_| VecDeque::new()),
        }
    }

    pub fn check_and_record(
        &mut self,
        controller_index: usize,
        request_id: [u8; REQUEST_ID_LEN],
    ) -> Result<(), ControlAuthError> {
        let Some(controller_recent) = self.recent.get_mut(controller_index) else {
            return Err(ControlAuthError::UnauthorizedController);
        };
        if controller_recent.contains(&request_id) {
            return Err(ControlAuthError::Replay);
        }
        controller_recent.push_back(request_id);
        if controller_recent.len() > MAX_REPLAY_IDS_PER_CONTROLLER {
            controller_recent.pop_front();
        }
        Ok(())
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

pub fn control_destination(node_identity_hash: &[u8; 16]) -> [u8; 16] {
    destination_hash(
        CONTROL_APP_NAME,
        CONTROL_REQUEST_ASPECTS,
        Some(node_identity_hash),
    )
}

pub fn control_reply_destination(controller_identity_hash: &[u8; 16]) -> [u8; 16] {
    destination_hash(
        CONTROL_APP_NAME,
        CONTROL_REPLY_ASPECTS,
        Some(controller_identity_hash),
    )
}

pub fn compiled_controller_keys() -> &'static [[u8; PUBLIC_KEY_LEN]] {
    &CONTROL_CONTROLLER_KEYS[..CONTROL_CONTROLLER_COUNT]
}

pub fn ble_open_control_default() -> bool {
    BLE_OPEN_CONTROL_DEFAULT
}

pub fn parse_request(bytes: &[u8]) -> Result<ControlRequest, ControlParseError> {
    let min_len = 2 + REQUEST_ID_LEN + PUBLIC_KEY_LEN + REQUEST_SIGNATURE_LEN;
    if bytes.len() < min_len {
        return Err(ControlParseError::TooShort);
    }

    let version = bytes[0];
    if version != CONTROL_PROTOCOL_VERSION {
        return Err(ControlParseError::UnsupportedVersion(version));
    }

    let command =
        ControlCommand::from_u8(bytes[1]).ok_or(ControlParseError::UnknownCommand(bytes[1]))?;
    let mut request_id = [0u8; REQUEST_ID_LEN];
    request_id.copy_from_slice(&bytes[2..2 + REQUEST_ID_LEN]);

    let mut controller_pubkey = [0u8; PUBLIC_KEY_LEN];
    let body_start = 2 + REQUEST_ID_LEN + PUBLIC_KEY_LEN;
    controller_pubkey.copy_from_slice(&bytes[2 + REQUEST_ID_LEN..body_start]);

    let sig_start = bytes.len() - REQUEST_SIGNATURE_LEN;
    let mut signature = [0u8; REQUEST_SIGNATURE_LEN];
    signature.copy_from_slice(&bytes[sig_start..]);
    let body = parse_request_body(command, &bytes[body_start..sig_start])?;

    Ok(ControlRequest {
        command,
        request_id,
        controller_pubkey,
        body,
        signature,
    })
}

pub fn authorize_request(
    bytes: &[u8],
    node_control_destination: &[u8; 16],
    replay_window: &mut ReplayWindow,
) -> Result<AuthorizedControlRequest, ControlAuthError> {
    let request = parse_request(bytes).map_err(ControlAuthError::Parse)?;

    let controller_index = compiled_controller_keys()
        .iter()
        .position(|key| key == &request.controller_pubkey)
        .ok_or(ControlAuthError::UnauthorizedController)?;

    let controller_identity = Identity::from_public_key(&request.controller_pubkey);
    let transcript = request_signature_transcript(
        node_control_destination,
        request.command,
        &request.request_id,
        &request.controller_pubkey,
        body_bytes(&request.body),
    );
    if !controller_identity.verify(&request.signature, &transcript) {
        return Err(ControlAuthError::InvalidSignature);
    }

    replay_window.check_and_record(controller_index, request.request_id)?;

    Ok(AuthorizedControlRequest {
        controller_index,
        controller_identity_hash: *controller_identity.hash(),
        request_id: request.request_id,
        command: request.command,
        body: request.body,
    })
}

pub fn encode_response(
    node_identity: &Identity,
    controller_identity_hash: &[u8; 16],
    command: ControlCommand,
    status: ControlStatus,
    request_id: [u8; REQUEST_ID_LEN],
    body: ControlResponseBody,
) -> Option<Vec<u8>> {
    let reply_dest = control_reply_destination(controller_identity_hash);
    let body_bytes = response_body_bytes(&body);
    let transcript =
        response_signature_transcript(&reply_dest, command, status, &request_id, &body_bytes);
    let signature = node_identity.sign(&transcript).ok()?;

    let mut out = Vec::with_capacity(3 + REQUEST_ID_LEN + body_bytes.len() + REQUEST_SIGNATURE_LEN);
    out.push(CONTROL_PROTOCOL_VERSION);
    out.push(command as u8);
    out.push(status as u8);
    out.extend_from_slice(&request_id);
    out.extend_from_slice(&body_bytes);
    out.extend_from_slice(&signature);
    Some(out)
}

fn parse_request_body(
    command: ControlCommand,
    body: &[u8],
) -> Result<ControlBody, ControlParseError> {
    match command {
        ControlCommand::GetRadio => {
            if !body.is_empty() {
                return Err(ControlParseError::InvalidBodyLength);
            }
            Ok(ControlBody::GetRadio)
        }
        ControlCommand::SetRadio => {
            let config = decode_radio_config(body)?;
            Ok(ControlBody::SetRadio(config))
        }
        ControlCommand::GetBlePolicy => {
            if !body.is_empty() {
                return Err(ControlParseError::InvalidBodyLength);
            }
            Ok(ControlBody::GetBlePolicy)
        }
        ControlCommand::SetBlePolicy => {
            if body.len() != 1 {
                return Err(ControlParseError::InvalidBodyLength);
            }
            match body[0] {
                0 => Ok(ControlBody::SetBlePolicy {
                    ble_open_control: false,
                }),
                1 => Ok(ControlBody::SetBlePolicy {
                    ble_open_control: true,
                }),
                _ => Err(ControlParseError::InvalidBodyLength),
            }
        }
    }
}

fn body_bytes(body: &ControlBody) -> Vec<u8> {
    match body {
        ControlBody::GetRadio | ControlBody::GetBlePolicy => Vec::new(),
        ControlBody::SetRadio(config) => encode_radio_config(*config).to_vec(),
        ControlBody::SetBlePolicy { ble_open_control } => vec![u8::from(*ble_open_control)],
    }
}

fn response_body_bytes(body: &ControlResponseBody) -> Vec<u8> {
    match body {
        ControlResponseBody::None => Vec::new(),
        ControlResponseBody::Radio(config) => encode_radio_config(*config).to_vec(),
        ControlResponseBody::BlePolicy { ble_open_control } => vec![u8::from(*ble_open_control)],
        ControlResponseBody::ErrorCode(code) => vec![*code as u8],
    }
}

fn encode_radio_config(config: RadioConfig) -> [u8; RADIO_CONFIG_ENCODED_LEN] {
    let mut out = [0u8; RADIO_CONFIG_ENCODED_LEN];
    out[..4].copy_from_slice(&config.frequency.to_be_bytes());
    out[4..8].copy_from_slice(&config.bandwidth.to_be_bytes());
    out[8] = config.spreading_factor;
    out[9] = config.coding_rate;
    out[10] = config.tx_power as u8;
    out
}

fn decode_radio_config(body: &[u8]) -> Result<RadioConfig, ControlParseError> {
    if body.len() != RADIO_CONFIG_ENCODED_LEN {
        return Err(ControlParseError::InvalidBodyLength);
    }

    let config = RadioConfig {
        frequency: u32::from_be_bytes(body[..4].try_into().unwrap()),
        bandwidth: u32::from_be_bytes(body[4..8].try_into().unwrap()),
        spreading_factor: body[8],
        coding_rate: body[9],
        tx_power: body[10] as i8,
    };
    validate_radio_config(config).map_err(|_| ControlParseError::InvalidRadioConfig)?;
    Ok(config)
}

fn request_signature_transcript(
    node_control_destination: &[u8; 16],
    command: ControlCommand,
    request_id: &[u8; REQUEST_ID_LEN],
    controller_pubkey: &[u8; PUBLIC_KEY_LEN],
    body: Vec<u8>,
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(
        REQUEST_DOMAIN.len() + 16 + 1 + 1 + REQUEST_ID_LEN + PUBLIC_KEY_LEN + body.len(),
    );
    transcript.extend_from_slice(REQUEST_DOMAIN);
    transcript.extend_from_slice(node_control_destination);
    transcript.push(CONTROL_PROTOCOL_VERSION);
    transcript.push(command as u8);
    transcript.extend_from_slice(request_id);
    transcript.extend_from_slice(controller_pubkey);
    transcript.extend_from_slice(&body);
    transcript
}

fn response_signature_transcript(
    reply_destination: &[u8; 16],
    command: ControlCommand,
    status: ControlStatus,
    request_id: &[u8; REQUEST_ID_LEN],
    body: &[u8],
) -> Vec<u8> {
    let mut transcript =
        Vec::with_capacity(RESPONSE_DOMAIN.len() + 16 + 1 + 1 + 1 + REQUEST_ID_LEN + body.len());
    transcript.extend_from_slice(RESPONSE_DOMAIN);
    transcript.extend_from_slice(reply_destination);
    transcript.push(CONTROL_PROTOCOL_VERSION);
    transcript.push(command as u8);
    transcript.push(status as u8);
    transcript.extend_from_slice(request_id);
    transcript.extend_from_slice(body);
    transcript
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::FixedRng;

    fn make_identity(seed: u8) -> Identity {
        Identity::new(&mut FixedRng::new(&[seed; 64]))
    }

    fn make_request_bytes(
        controller: &Identity,
        command: ControlCommand,
        request_id: [u8; REQUEST_ID_LEN],
        body: ControlBody,
        target: &[u8; 16],
    ) -> Vec<u8> {
        let pubkey = controller.get_public_key().unwrap();
        let body_bytes = body_bytes(&body);
        let transcript =
            request_signature_transcript(target, command, &request_id, &pubkey, body_bytes.clone());
        let signature = controller.sign(&transcript).unwrap();

        let mut out = Vec::new();
        out.push(CONTROL_PROTOCOL_VERSION);
        out.push(command as u8);
        out.extend_from_slice(&request_id);
        out.extend_from_slice(&pubkey);
        out.extend_from_slice(&body_bytes);
        out.extend_from_slice(&signature);
        out
    }

    #[test]
    fn parses_set_radio_request() {
        let controller = make_identity(0x11);
        let target = [0xAA; 16];
        let request_id = [0x22; REQUEST_ID_LEN];
        let config = RadioConfig {
            frequency: 868_100_000,
            bandwidth: 125_000,
            spreading_factor: 8,
            coding_rate: 5,
            tx_power: 14,
        };

        let bytes = make_request_bytes(
            &controller,
            ControlCommand::SetRadio,
            request_id,
            ControlBody::SetRadio(config),
            &target,
        );
        let parsed = parse_request(&bytes).unwrap();

        assert_eq!(parsed.command, ControlCommand::SetRadio);
        assert_eq!(parsed.request_id, request_id);
        assert_eq!(parsed.body, ControlBody::SetRadio(config));
    }

    #[test]
    fn rejects_bad_version() {
        let mut bytes = vec![0u8; 2 + REQUEST_ID_LEN + PUBLIC_KEY_LEN + REQUEST_SIGNATURE_LEN];
        bytes[0] = 9;
        bytes[1] = ControlCommand::GetRadio as u8;
        let err = parse_request(&bytes).unwrap_err();
        assert_eq!(err, ControlParseError::UnsupportedVersion(9));
    }

    #[test]
    fn encodes_response() {
        let node = make_identity(0x33);
        let controller = make_identity(0x44);
        let request_id = [0x55; REQUEST_ID_LEN];
        let bytes = encode_response(
            &node,
            controller.hash(),
            ControlCommand::GetBlePolicy,
            ControlStatus::Ok,
            request_id,
            ControlResponseBody::BlePolicy {
                ble_open_control: true,
            },
        )
        .unwrap();

        assert_eq!(bytes[0], CONTROL_PROTOCOL_VERSION);
        assert_eq!(bytes[1], ControlCommand::GetBlePolicy as u8);
        assert_eq!(bytes[2], ControlStatus::Ok as u8);
        assert_eq!(&bytes[3..3 + REQUEST_ID_LEN], &request_id);
    }

    #[test]
    fn replay_window_rejects_duplicate_ids() {
        let mut replay = ReplayWindow::new();
        let request_id = [0x66; REQUEST_ID_LEN];
        replay.check_and_record(0, request_id).unwrap();
        let err = replay.check_and_record(0, request_id).unwrap_err();
        assert_eq!(err, ControlAuthError::Replay);
    }
}
