//! Client-side remote management helpers.
//!
//! These helpers connect to a local shared instance, derive upstream-compatible
//! remote management destinations from a remote transport identity hash, and
//! query the remote node over a Reticulum link.

use std::fmt;
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rns_core::msgpack::{self, Value};
use rns_core::types::{DestHash, LinkId};
use rns_crypto::identity::Identity;

use crate::destination::AnnouncedIdentity;
use crate::pickle::PickleValue;
use crate::shared_client::SharedClientConfig;
use crate::{Callbacks, RnsNode, TeardownReason};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemotePurpose {
    Management,
    Blackhole,
}

#[derive(Debug, Clone)]
pub enum RemoteManagementError {
    InvalidHash(String),
    MissingIdentity,
    IdentityLoad(String),
    Config(String),
    ConnectShared,
    PathTimeout([u8; 16]),
    RecallTimeout([u8; 16]),
    LinkTimeout([u8; 16]),
    RequestTimeout(String),
    LinkClosed,
    SendFailed,
    MalformedResponse(String),
    Unsupported(String),
}

impl fmt::Display for RemoteManagementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHash(s) => {
                write!(
                    f,
                    "invalid transport identity hash: {s} (expected 32 hex chars)"
                )
            }
            Self::MissingIdentity => {
                write!(
                    f,
                    "remote management requires an identity file; use -i PATH"
                )
            }
            Self::IdentityLoad(e) => write!(f, "could not load management identity: {e}"),
            Self::Config(e) => write!(f, "could not load local Reticulum config: {e}"),
            Self::ConnectShared => {
                write!(f, "could not connect to local shared Reticulum instance")
            }
            Self::PathTimeout(hash) => write!(f, "timed out waiting for path to {}", hex(hash)),
            Self::RecallTimeout(hash) => {
                write!(f, "timed out recalling identity for {}", hex(hash))
            }
            Self::LinkTimeout(hash) => write!(f, "timed out establishing link to {}", hex(hash)),
            Self::RequestTimeout(path) => write!(f, "remote request to {path} timed out"),
            Self::LinkClosed => write!(f, "remote link closed before request completed"),
            Self::SendFailed => write!(f, "could not send remote management request"),
            Self::MalformedResponse(e) => write!(f, "malformed remote response: {e}"),
            Self::Unsupported(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RemoteManagementError {}

#[derive(Debug, Clone)]
pub struct RemoteStatus {
    pub stats: PickleValue,
    pub link_count: Option<i64>,
}

struct RemoteCallbacks {
    link_established_tx: mpsc::Sender<LinkId>,
    response_tx: mpsc::Sender<(LinkId, [u8; 16], Vec<u8>)>,
    link_closed_tx: mpsc::Sender<LinkId>,
}

impl Callbacks for RemoteCallbacks {
    fn on_announce(&mut self, _announced: AnnouncedIdentity) {}

    fn on_path_updated(&mut self, _dest_hash: DestHash, _hops: u8) {}

    fn on_local_delivery(
        &mut self,
        _dest_hash: DestHash,
        _raw: Vec<u8>,
        _packet_hash: crate::PacketHash,
    ) {
    }

    fn on_link_established(
        &mut self,
        link_id: LinkId,
        _dest_hash: DestHash,
        _rtt: f64,
        _is_initiator: bool,
    ) {
        let _ = self.link_established_tx.send(link_id);
    }

    fn on_response(&mut self, link_id: LinkId, request_id: [u8; 16], data: Vec<u8>) {
        let _ = self.response_tx.send((link_id, request_id, data));
    }

    fn on_link_closed(&mut self, link_id: LinkId, reason: Option<TeardownReason>) {
        if reason == Some(TeardownReason::InitiatorClosed) {
            return;
        }
        let _ = self.link_closed_tx.send(link_id);
    }
}

pub struct RemoteManagementClient {
    node: RnsNode,
    management_identity: Option<Identity>,
    timeout: Duration,
    link_rx: mpsc::Receiver<LinkId>,
    response_rx: mpsc::Receiver<(LinkId, [u8; 16], Vec<u8>)>,
    closed_rx: mpsc::Receiver<LinkId>,
    management_link: Arc<Mutex<Option<[u8; 16]>>>,
    blackhole_link: Arc<Mutex<Option<[u8; 16]>>>,
}

impl RemoteManagementClient {
    pub fn connect(
        config_path: Option<&Path>,
        management_identity_path: Option<&Path>,
        timeout: Duration,
    ) -> Result<Self, RemoteManagementError> {
        let management_identity = match management_identity_path {
            Some(path) => Some(
                crate::storage::load_identity(path)
                    .map_err(|e| RemoteManagementError::IdentityLoad(e.to_string()))?,
            ),
            None => None,
        };

        let (link_tx, link_rx) = mpsc::channel();
        let (response_tx, response_rx) = mpsc::channel();
        let (closed_tx, closed_rx) = mpsc::channel();
        let callbacks = RemoteCallbacks {
            link_established_tx: link_tx,
            response_tx,
            link_closed_tx: closed_tx,
        };

        let config_dir = crate::storage::resolve_config_dir(config_path);
        let config_file = config_dir.join("config");
        let rns_config = if config_file.exists() {
            crate::config::parse_file(&config_file)
                .map_err(|e| RemoteManagementError::Config(e.to_string()))?
        } else {
            crate::config::parse("").map_err(|e| RemoteManagementError::Config(e.to_string()))?
        };

        let shared_config = SharedClientConfig {
            instance_name: rns_config.reticulum.instance_name.clone(),
            port: rns_config.reticulum.shared_instance_port,
            rpc_port: rns_config.reticulum.instance_control_port,
        };

        let node = RnsNode::connect_shared(shared_config, Box::new(callbacks))
            .map_err(|_| RemoteManagementError::ConnectShared)?;

        Ok(Self {
            node,
            management_identity,
            timeout,
            link_rx,
            response_rx,
            closed_rx,
            management_link: Arc::new(Mutex::new(None)),
            blackhole_link: Arc::new(Mutex::new(None)),
        })
    }

    pub fn status(
        &mut self,
        transport_identity_hash: [u8; 16],
        include_link_count: bool,
    ) -> Result<RemoteStatus, RemoteManagementError> {
        let data = msgpack::pack(&Value::Array(vec![Value::Bool(include_link_count)]));
        let response = self.request_management(transport_identity_hash, "/status", &data)?;
        decode_status_response(&response)
    }

    pub fn path_table(
        &mut self,
        transport_identity_hash: [u8; 16],
        destination_filter: Option<[u8; 16]>,
        max_hops: Option<u8>,
    ) -> Result<PickleValue, RemoteManagementError> {
        let mut request = vec![Value::Str("table".into())];
        if destination_filter.is_some() || max_hops.is_some() {
            request.push(match destination_filter {
                Some(hash) => Value::Bin(hash.to_vec()),
                None => Value::Nil,
            });
        }
        if let Some(hops) = max_hops {
            request.push(Value::UInt(hops as u64));
        }
        let data = msgpack::pack(&Value::Array(request));
        let response = self.request_management(transport_identity_hash, "/path", &data)?;
        let value = msgpack::unpack_exact(&response)
            .map_err(|e| RemoteManagementError::MalformedResponse(e.to_string()))?;
        Ok(msgpack_to_pickle(&value))
    }

    pub fn rate_table(
        &mut self,
        transport_identity_hash: [u8; 16],
        destination_filter: Option<[u8; 16]>,
    ) -> Result<PickleValue, RemoteManagementError> {
        let mut request = vec![Value::Str("rates".into())];
        if let Some(hash) = destination_filter {
            request.push(Value::Bin(hash.to_vec()));
        }
        let data = msgpack::pack(&Value::Array(request));
        let response = self.request_management(transport_identity_hash, "/path", &data)?;
        let value = msgpack::unpack_exact(&response)
            .map_err(|e| RemoteManagementError::MalformedResponse(e.to_string()))?;
        Ok(msgpack_to_pickle(&value))
    }

    pub fn published_blackhole_list(
        &mut self,
        transport_identity_hash: [u8; 16],
    ) -> Result<PickleValue, RemoteManagementError> {
        let dest_hash = crate::management::blackhole_dest_hash(&transport_identity_hash);
        let response = self.request(
            RemotePurpose::Blackhole,
            dest_hash,
            None,
            "/list",
            &[],
            false,
        )?;
        let value = msgpack::unpack_exact(&response)
            .map_err(|e| RemoteManagementError::MalformedResponse(e.to_string()))?;
        Ok(blackhole_map_to_list(&value))
    }

    fn request_management(
        &mut self,
        transport_identity_hash: [u8; 16],
        path: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, RemoteManagementError> {
        let dest_hash = crate::management::management_dest_hash(&transport_identity_hash);
        let prv_key = self
            .management_identity
            .as_ref()
            .and_then(|id| id.get_private_key())
            .ok_or(RemoteManagementError::MissingIdentity)?;
        self.request(
            RemotePurpose::Management,
            dest_hash,
            Some(prv_key),
            path,
            data,
            true,
        )
    }

    fn request(
        &mut self,
        purpose: RemotePurpose,
        dest_hash: [u8; 16],
        identity_prv_key: Option<[u8; 64]>,
        path: &str,
        data: &[u8],
        identify_on_new_link: bool,
    ) -> Result<Vec<u8>, RemoteManagementError> {
        let link_slot = match purpose {
            RemotePurpose::Management => Arc::clone(&self.management_link),
            RemotePurpose::Blackhole => Arc::clone(&self.blackhole_link),
        };

        if let Some(link_id) = *lock_link(&link_slot) {
            if self.node.send_request(link_id, path, data).is_ok() {
                return self.wait_for_response(link_id, path);
            }
            *lock_link(&link_slot) = None;
        }

        let announced = self.wait_for_destination(dest_hash)?;
        let sig_pub: [u8; 32] = announced.public_key[32..64]
            .try_into()
            .expect("slice length checked");
        let link_id = self
            .node
            .create_link(dest_hash, sig_pub)
            .map_err(|_| RemoteManagementError::LinkTimeout(dest_hash))?;
        self.wait_for_link_established(link_id, dest_hash)?;

        if identify_on_new_link {
            let prv_key = identity_prv_key.ok_or(RemoteManagementError::MissingIdentity)?;
            self.node
                .identify_on_link(link_id, prv_key)
                .map_err(|_| RemoteManagementError::SendFailed)?;
            std::thread::sleep(Duration::from_millis(200));
        }

        *lock_link(&link_slot) = Some(link_id);
        self.node
            .send_request(link_id, path, data)
            .map_err(|_| RemoteManagementError::SendFailed)?;
        self.wait_for_response(link_id, path)
    }

    fn wait_for_destination(
        &self,
        dest_hash: [u8; 16],
    ) -> Result<AnnouncedIdentity, RemoteManagementError> {
        let dest = DestHash(dest_hash);
        let deadline = Instant::now() + self.timeout;
        let _ = self.node.request_path(&dest);

        loop {
            if let Ok(Some(announced)) = self.node.recall_identity(&dest) {
                return Ok(announced);
            }
            if self.node.has_path(&dest).unwrap_or(false) {
                if let Ok(Some(announced)) = self.node.recall_identity(&dest) {
                    return Ok(announced);
                }
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(RemoteManagementError::RecallTimeout(dest_hash));
            };
            if remaining.is_zero() {
                return Err(RemoteManagementError::PathTimeout(dest_hash));
            }
            std::thread::sleep(remaining.min(Duration::from_millis(100)));
        }
    }

    fn wait_for_link_established(
        &self,
        expected_link_id: [u8; 16],
        dest_hash: [u8; 16],
    ) -> Result<(), RemoteManagementError> {
        let deadline = Instant::now() + self.timeout;
        loop {
            if let Ok(closed) = self.closed_rx.try_recv() {
                if closed.0 == expected_link_id {
                    return Err(RemoteManagementError::LinkClosed);
                }
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(RemoteManagementError::LinkTimeout(dest_hash));
            };
            match self
                .link_rx
                .recv_timeout(remaining.min(Duration::from_millis(50)))
            {
                Ok(link_id) if link_id.0 == expected_link_id => return Ok(()),
                Ok(_) => continue,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(RemoteManagementError::LinkTimeout(dest_hash));
                }
            }
        }
    }

    fn wait_for_response(
        &self,
        link_id: [u8; 16],
        path: &str,
    ) -> Result<Vec<u8>, RemoteManagementError> {
        let deadline = Instant::now() + self.timeout;
        loop {
            if let Ok(closed) = self.closed_rx.try_recv() {
                if closed.0 == link_id {
                    return Err(RemoteManagementError::LinkClosed);
                }
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(RemoteManagementError::RequestTimeout(path.into()));
            };
            match self
                .response_rx
                .recv_timeout(remaining.min(Duration::from_millis(50)))
            {
                Ok((resp_link_id, _request_id, data)) if resp_link_id.0 == link_id => {
                    return Ok(data);
                }
                Ok(_) => continue,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(RemoteManagementError::RequestTimeout(path.into()));
                }
            }
        }
    }
}

pub fn parse_transport_identity_hash(s: &str) -> Result<[u8; 16], RemoteManagementError> {
    let trimmed = s.trim();
    if trimmed.len() != 32 {
        return Err(RemoteManagementError::InvalidHash(s.into()));
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)
            .map_err(|_| RemoteManagementError::InvalidHash(s.into()))?;
    }
    Ok(out)
}

pub fn msgpack_to_pickle(value: &Value) -> PickleValue {
    match value {
        Value::Nil => PickleValue::None,
        Value::Bool(v) => PickleValue::Bool(*v),
        Value::UInt(v) => PickleValue::Int((*v).min(i64::MAX as u64) as i64),
        Value::Int(v) => PickleValue::Int(*v),
        Value::Float(v) => PickleValue::Float(*v),
        Value::Bin(v) => PickleValue::Bytes(v.clone()),
        Value::Str(v) => PickleValue::String(v.clone()),
        Value::Array(items) => PickleValue::List(items.iter().map(msgpack_to_pickle).collect()),
        Value::Map(entries) => PickleValue::Dict(
            entries
                .iter()
                .map(|(k, v)| (msgpack_to_pickle(k), msgpack_to_pickle(v)))
                .collect(),
        ),
    }
}

fn decode_status_response(data: &[u8]) -> Result<RemoteStatus, RemoteManagementError> {
    let value = msgpack::unpack_exact(data)
        .map_err(|e| RemoteManagementError::MalformedResponse(e.to_string()))?;
    let arr = value
        .as_array()
        .ok_or_else(|| RemoteManagementError::MalformedResponse("expected status array".into()))?;
    let stats = arr
        .first()
        .ok_or_else(|| RemoteManagementError::MalformedResponse("missing status dict".into()))?;
    let mut stats = msgpack_to_pickle(stats);
    normalize_remote_status(&mut stats);
    let link_count = arr.get(1).and_then(|v| v.as_integer());
    Ok(RemoteStatus { stats, link_count })
}

fn normalize_remote_status(value: &mut PickleValue) {
    let PickleValue::Dict(entries) = value else {
        return;
    };
    if !entries
        .iter()
        .any(|(k, _)| string_key(k) == Some("transport_enabled"))
    {
        entries.push((
            PickleValue::String("transport_enabled".into()),
            PickleValue::Bool(true),
        ));
    }
    if let Some((_, PickleValue::List(ifaces))) = entries
        .iter_mut()
        .find(|(k, _)| string_key(k) == Some("interfaces"))
    {
        for iface in ifaces {
            normalize_remote_interface(iface);
        }
    }
}

fn normalize_remote_interface(value: &mut PickleValue) {
    let PickleValue::Dict(entries) = value else {
        return;
    };
    copy_key(entries, "incoming_announce_freq", "ia_freq");
    copy_key(entries, "outgoing_announce_freq", "oa_freq");
    copy_key(entries, "incoming_path_request_freq", "ip_freq");
    copy_key(entries, "outgoing_path_request_freq", "op_freq");
}

fn copy_key(entries: &mut Vec<(PickleValue, PickleValue)>, from: &str, to: &str) {
    if entries.iter().any(|(k, _)| string_key(k) == Some(to)) {
        return;
    }
    if let Some((_, value)) = entries.iter().find(|(k, _)| string_key(k) == Some(from)) {
        entries.push((PickleValue::String(to.into()), value.clone()));
    }
}

fn blackhole_map_to_list(value: &Value) -> PickleValue {
    let Some(entries) = value.as_map() else {
        return msgpack_to_pickle(value);
    };
    let mut list = Vec::new();
    for (key, info) in entries {
        let Some(identity_hash) = key.as_bin() else {
            continue;
        };
        let mut item = vec![(
            PickleValue::String("identity_hash".into()),
            PickleValue::Bytes(identity_hash.to_vec()),
        )];
        if let Some(info_entries) = info.as_map() {
            for (k, v) in info_entries {
                if let Some(key) = k.as_str() {
                    let out_key = if key == "created" { "created" } else { key };
                    item.push((PickleValue::String(out_key.into()), msgpack_to_pickle(v)));
                }
            }
        }
        list.push(PickleValue::Dict(item));
    }
    PickleValue::List(list)
}

fn lock_link<'a>(
    link: &'a Arc<Mutex<Option<[u8; 16]>>>,
) -> std::sync::MutexGuard<'a, Option<[u8; 16]>> {
    match link.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn string_key(value: &PickleValue) -> Option<&str> {
    match value {
        PickleValue::String(s) => Some(s),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_transport_identity_hash_accepts_32_hex_chars() {
        let hash = parse_transport_identity_hash("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(hash[0], 0x00);
        assert_eq!(hash[15], 0xff);
    }

    #[test]
    fn parse_transport_identity_hash_rejects_invalid_input() {
        assert!(parse_transport_identity_hash("short").is_err());
        assert!(parse_transport_identity_hash("00112233445566778899aabbccddeeg").is_err());
    }

    #[test]
    fn status_response_normalizes_renderer_keys() {
        let status = Value::Map(vec![
            (
                Value::Str("interfaces".into()),
                Value::Array(vec![Value::Map(vec![
                    (Value::Str("name".into()), Value::Str("if0".into())),
                    (
                        Value::Str("incoming_announce_freq".into()),
                        Value::Float(1.5),
                    ),
                ])]),
            ),
            (Value::Str("rxb".into()), Value::UInt(1)),
            (Value::Str("txb".into()), Value::UInt(2)),
        ]);
        let data = msgpack::pack(&Value::Array(vec![status, Value::UInt(7)]));
        let decoded = decode_status_response(&data).unwrap();
        assert_eq!(decoded.link_count, Some(7));
        assert_eq!(
            decoded
                .stats
                .get("transport_enabled")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        let iface = &decoded
            .stats
            .get("interfaces")
            .and_then(|v| v.as_list())
            .unwrap()[0];
        assert_eq!(iface.get("ia_freq").and_then(|v| v.as_float()), Some(1.5));
    }

    #[test]
    fn blackhole_map_converts_to_renderer_list() {
        let value = Value::Map(vec![(
            Value::Bin(vec![0x11; 16]),
            Value::Map(vec![
                (Value::Str("expires".into()), Value::Float(123.0)),
                (Value::Str("reason".into()), Value::Str("test".into())),
            ]),
        )]);
        let list = blackhole_map_to_list(&value);
        let items = list.as_list().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0]
                .get("identity_hash")
                .and_then(|v| v.as_bytes())
                .unwrap(),
            &[0x11; 16]
        );
    }
}
