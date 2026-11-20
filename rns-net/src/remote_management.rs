//! Client-side remote management helpers.
//!
//! These helpers connect to a local shared instance, derive upstream-compatible
//! remote management destinations from a remote transport identity hash, and
//! query the remote node over a Reticulum link.

use rns_core::encoding::hex;
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

/// Which of a transport instance's destinations a link goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemotePurpose {
    /// `rnstransport.remote.management`, identified with the management
    /// identity.
    Management,
    /// `rnstransport.info.blackhole`, anonymous.
    Blackhole,
}

/// Failures of [`RemoteManagementClient`] operations.
#[derive(Debug, Clone)]
pub enum RemoteManagementError {
    /// The given text is not a 32-character hex transport identity hash.
    InvalidHash(String),
    /// The management destination needs an identity and none was given.
    MissingIdentity,
    /// The management identity file could not be loaded.
    IdentityLoad(String),
    /// The local Reticulum config could not be parsed.
    Config(String),
    /// The local shared instance could not be reached.
    ConnectShared,
    /// The wait for the destination's path and identity ran out exactly at
    /// its deadline.
    PathTimeout([u8; 16]),
    /// The wait for the destination's path and identity passed its deadline.
    RecallTimeout([u8; 16]),
    /// The link to the destination could not be created or was not
    /// established in time.
    LinkTimeout([u8; 16]),
    /// No response to the request on this path arrived in time.
    RequestTimeout(String),
    /// The link closed, by the reason the remote side gave if any.
    LinkClosed(Option<TeardownReason>),
    /// The request or the identification could not be sent, or there was
    /// no open link for it.
    SendFailed,
    /// The response could not be decoded as expected.
    MalformedResponse(String),
    /// A failure described only by its message, displayed as is.
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
            Self::LinkClosed(_) => write!(f, "remote link closed before request completed"),
            Self::SendFailed => write!(f, "could not send remote management request"),
            Self::MalformedResponse(e) => write!(f, "malformed remote response: {e}"),
            Self::Unsupported(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RemoteManagementError {}

/// The stages of a remote request a tool reports as it goes, as upstream's
/// utilities print them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteProgress {
    /// No path to the remote destination was known; one was requested.
    PathRequested([u8; 16]),
    /// The path is known and a new link is being set up.
    EstablishingLink,
    /// The link is up and the request goes out.
    SendingRequest,
}

/// The response to a remote `/status` request.
#[derive(Debug, Clone)]
pub struct RemoteStatus {
    /// The interface statistics, as received.
    pub stats: PickleValue,
    /// The remote's link count, when requested and present.
    pub link_count: Option<i64>,
    /// The remote's profiling results, when requested and present.
    pub profiling_results: Option<PickleValue>,
}

struct RemoteCallbacks {
    link_established_tx: mpsc::Sender<LinkId>,
    response_tx: mpsc::Sender<(LinkId, [u8; 16], Vec<u8>)>,
    link_closed_tx: mpsc::Sender<(LinkId, Option<TeardownReason>)>,
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
        let _ = self.link_closed_tx.send((link_id, reason));
    }
}

/// A client that reaches a remote transport instance's management and
/// blackhole destinations through the local shared instance.
pub struct RemoteManagementClient {
    node: RnsNode,
    management_identity: Option<Identity>,
    timeout: Duration,
    link_rx: mpsc::Receiver<LinkId>,
    response_rx: mpsc::Receiver<(LinkId, [u8; 16], Vec<u8>)>,
    closed_rx: mpsc::Receiver<(LinkId, Option<TeardownReason>)>,
    progress: Option<Box<dyn FnMut(RemoteProgress) + Send>>,
    management_link: Arc<Mutex<Option<[u8; 16]>>>,
    blackhole_link: Arc<Mutex<Option<[u8; 16]>>>,
}

impl RemoteManagementClient {
    /// Connect to the shared instance configured in `config_path` (or the
    /// default config directory), loading the management identity from
    /// `management_identity_path` if given. `timeout` is as
    /// [`set_timeout`](Self::set_timeout).
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
        Self::connect_with_identity(config_path, management_identity, timeout)
    }

    /// [`Self::connect`] with an already loaded management identity.
    pub fn connect_with_identity(
        config_path: Option<&Path>,
        management_identity: Option<Identity>,
        timeout: Duration,
    ) -> Result<Self, RemoteManagementError> {
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

        let shared_config = SharedClientConfig::from_reticulum(&rns_config.reticulum);
        let rpc_addr = crate::rpc::RpcAddr::for_shared_instance(&rns_config.reticulum);
        let mut node = RnsNode::connect_shared(shared_config, Box::new(callbacks))
            .map_err(|_| RemoteManagementError::ConnectShared)?;
        // Upstream rnstatus and rnpath register both types, so a shared
        // instance filtering announces still answers their path requests.
        node.use_shared_instance_rpc(&config_dir, rpc_addr, rns_config.reticulum.rpc_key);
        node.wants_destination_type("rnstransport.remote.management");
        node.wants_destination_type("rnstransport.info.blackhole");

        Ok(Self {
            node,
            management_identity,
            timeout,
            link_rx,
            response_rx,
            closed_rx,
            progress: None,
            management_link: Arc::new(Mutex::new(None)),
            blackhole_link: Arc::new(Mutex::new(None)),
        })
    }

    /// Report each stage of the requests that follow to `progress`.
    pub fn set_progress(&mut self, progress: impl FnMut(RemoteProgress) + Send + 'static) {
        self.progress = Some(Box::new(progress));
    }

    /// How long each stage of a request waits: the path, the link, the
    /// response.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// The shared instance's estimate of a reasonable path request
    /// timeout, upstream's `Reticulum.get_medium_path_timeout()`.
    pub fn medium_path_timeout(&self) -> Option<f64> {
        self.node.medium_path_timeout().ok()
    }

    /// Open the link to the transport instance's `purpose` destination, as
    /// upstream's `connect_remote` does, reporting the path request and the
    /// link setup but sending nothing. Later requests for `purpose` use it.
    pub fn open_link(
        &mut self,
        purpose: RemotePurpose,
        transport_identity_hash: [u8; 16],
    ) -> Result<(), RemoteManagementError> {
        match purpose {
            RemotePurpose::Management => {
                let dest_hash = crate::management::management_dest_hash(&transport_identity_hash);
                let prv_key = self.management_prv_key()?;
                self.establish(purpose, dest_hash, Some(prv_key), true)?;
            }
            RemotePurpose::Blackhole => {
                let dest_hash = crate::management::blackhole_dest_hash(&transport_identity_hash);
                self.establish(purpose, dest_hash, None, false)?;
            }
        }
        Ok(())
    }

    /// Wait for a path to and the identity of `dest_hash`, reporting the
    /// path request and, once known, the link setup that would follow,
    /// without opening a link.
    pub fn locate(&mut self, dest_hash: [u8; 16]) -> Result<(), RemoteManagementError> {
        if !self.node.has_path(&DestHash(dest_hash)).unwrap_or(false) {
            self.report(RemoteProgress::PathRequested(dest_hash));
        }
        self.wait_for_destination(dest_hash)?;
        self.report(RemoteProgress::EstablishingLink);
        Ok(())
    }

    /// Send a request on the link [`Self::open_link`] opened for `purpose`
    /// and wait for its response. `data` is the packed request data.
    pub fn request_on(
        &mut self,
        purpose: RemotePurpose,
        path: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, RemoteManagementError> {
        let link_id =
            (*lock_link(self.link_slot(purpose))).ok_or(RemoteManagementError::SendFailed)?;
        self.node
            .send_request(link_id, path, data)
            .map_err(|_| RemoteManagementError::SendFailed)?;
        self.wait_for_response(link_id, path)
    }

    fn link_slot(&self, purpose: RemotePurpose) -> &Arc<Mutex<Option<[u8; 16]>>> {
        match purpose {
            RemotePurpose::Management => &self.management_link,
            RemotePurpose::Blackhole => &self.blackhole_link,
        }
    }

    fn management_prv_key(&self) -> Result<[u8; 64], RemoteManagementError> {
        self.management_identity
            .as_ref()
            .and_then(|id| id.get_private_key())
            .ok_or(RemoteManagementError::MissingIdentity)
    }

    fn report(&mut self, stage: RemoteProgress) {
        if let Some(progress) = self.progress.as_mut() {
            progress(stage);
        }
    }

    /// Request the remote's `/status`, with its link count if
    /// `include_link_count`.
    pub fn status(
        &mut self,
        transport_identity_hash: [u8; 16],
        include_link_count: bool,
    ) -> Result<RemoteStatus, RemoteManagementError> {
        self.status_with_profiling(transport_identity_hash, include_link_count, false)
    }

    /// [`status`](Self::status), also asking for profiling results if
    /// `include_profiling`.
    pub fn status_with_profiling(
        &mut self,
        transport_identity_hash: [u8; 16],
        include_link_count: bool,
        include_profiling: bool,
    ) -> Result<RemoteStatus, RemoteManagementError> {
        let data = msgpack::pack(&Value::Array(vec![
            Value::Bool(include_link_count),
            Value::Bool(include_profiling),
        ]));
        let response = self.request_management(transport_identity_hash, "/status", &data)?;
        decode_status_response(&response)
    }

    /// Request the remote's path table, optionally only the entry for
    /// `destination_filter` and only paths of at most `max_hops` hops.
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

    /// Request the remote's announce rate table, optionally only the entry
    /// for `destination_filter`.
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

    /// Request the blackhole list the remote publishes on its
    /// `rnstransport.info.blackhole` destination, as a list of dicts each
    /// carrying an `identity_hash`.
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
        let prv_key = self.management_prv_key()?;
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
        if let Some(link_id) = *lock_link(self.link_slot(purpose)) {
            if self.node.send_request(link_id, path, data).is_ok() {
                return self.wait_for_response(link_id, path);
            }
            *lock_link(self.link_slot(purpose)) = None;
        }

        let link_id = self.establish(purpose, dest_hash, identity_prv_key, identify_on_new_link)?;
        self.report(RemoteProgress::SendingRequest);
        self.node
            .send_request(link_id, path, data)
            .map_err(|_| RemoteManagementError::SendFailed)?;
        self.wait_for_response(link_id, path)
    }

    /// Request a path if needed, open a link to `dest_hash`, identify on it
    /// if asked to, and keep it as `purpose`'s link.
    fn establish(
        &mut self,
        purpose: RemotePurpose,
        dest_hash: [u8; 16],
        identity_prv_key: Option<[u8; 64]>,
        identify_on_new_link: bool,
    ) -> Result<[u8; 16], RemoteManagementError> {
        if !self.node.has_path(&DestHash(dest_hash)).unwrap_or(false) {
            self.report(RemoteProgress::PathRequested(dest_hash));
        }
        let announced = self.wait_for_destination(dest_hash)?;
        self.report(RemoteProgress::EstablishingLink);
        let (_, sig_pub) = rns_crypto::identity::split_key(&announced.public_key);
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

        *lock_link(self.link_slot(purpose)) = Some(link_id);
        Ok(link_id)
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
            if let Ok((closed, reason)) = self.closed_rx.try_recv() {
                if closed.0 == expected_link_id {
                    return Err(RemoteManagementError::LinkClosed(reason));
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
            if let Ok((closed, reason)) = self.closed_rx.try_recv() {
                if closed.0 == link_id {
                    return Err(RemoteManagementError::LinkClosed(reason));
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

/// Parse a 32-character hex transport identity hash, ignoring surrounding
/// whitespace.
pub fn parse_transport_identity_hash(s: &str) -> Result<[u8; 16], RemoteManagementError> {
    rns_core::encoding::hex_decode_array(s.trim())
        .ok_or_else(|| RemoteManagementError::InvalidHash(s.into()))
}

/// Convert a msgpack value to the equivalent pickle value; unsigned
/// integers above `i64::MAX` saturate.
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
    // Passed on as received, as upstream's rnstatus prints it.
    let stats = msgpack_to_pickle(stats);
    let link_count = arr.get(1).and_then(|v| v.as_integer());
    let profiling_results = arr
        .get(2)
        .filter(|value| !matches!(value, Value::Nil))
        .map(msgpack_to_pickle);
    Ok(RemoteStatus {
        stats,
        link_count,
        profiling_results,
    })
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
    fn status_response_passes_the_stats_on_as_received() {
        let status = Value::Map(vec![
            (Value::Str("interfaces".into()), Value::Array(Vec::new())),
            (Value::Str("rxb".into()), Value::UInt(1)),
        ]);
        let data = msgpack::pack(&Value::Array(vec![status.clone(), Value::UInt(7)]));
        let decoded = decode_status_response(&data).unwrap();
        assert_eq!(decoded.link_count, Some(7));
        assert_eq!(decoded.stats, msgpack_to_pickle(&status));
    }

    #[test]
    fn status_response_decodes_profiling_results() {
        let status = Value::Map(vec![]);
        let profiling = Value::Map(vec![(
            Value::Str("entry110.remote".into()),
            Value::Map(vec![(Value::Str("count".into()), Value::UInt(2))]),
        )]);
        let data = msgpack::pack(&Value::Array(vec![status, Value::UInt(7), profiling]));
        let decoded = decode_status_response(&data).unwrap();
        assert_eq!(decoded.link_count, Some(7));
        assert_eq!(
            decoded
                .profiling_results
                .as_ref()
                .and_then(|results| results.get("entry110.remote"))
                .and_then(|sample| sample.get("count"))
                .and_then(PickleValue::as_int),
            Some(2)
        );
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
