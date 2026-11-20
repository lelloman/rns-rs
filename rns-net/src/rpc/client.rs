//! The RPC client, and reading the server's answers.

use super::*;

/// RPC client for connecting to a running daemon.
pub struct RpcClient {
    pub(super) stream: ClientStream,
}

/// The connection an `RpcClient` talks over.
pub(super) enum ClientStream {
    Tcp(TcpStream),
    #[cfg(target_os = "linux")]
    Unix(UnixStream),
}

impl ClientStream {
    pub(super) fn connect(addr: &RpcAddr) -> io::Result<Self> {
        match addr {
            RpcAddr::Tcp(host, port) => Ok(Self::Tcp(TcpStream::connect((host.as_str(), *port))?)),
            RpcAddr::Local {
                instance_name,
                port,
            } => {
                #[cfg(target_os = "linux")]
                {
                    let unix = SocketAddr::from_abstract_name(format!("rns/{instance_name}/rpc"))
                        .and_then(|addr| UnixStream::connect_addr(&addr));
                    match unix {
                        Ok(stream) => return Ok(Self::Unix(stream)),
                        Err(e) => log::debug!(
                            "No RPC socket for instance {instance_name} ({e}), using TCP port {port}"
                        ),
                    }
                }
                #[cfg(not(target_os = "linux"))]
                let _ = instance_name;
                Ok(Self::Tcp(TcpStream::connect(("127.0.0.1", *port))?))
            }
        }
    }

    pub(super) fn set_timeouts(&self, timeout: Duration) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => {
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))
            }
            #[cfg(target_os = "linux")]
            Self::Unix(stream) => {
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))
            }
        }
    }
}

impl Read for ClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buf),
            #[cfg(target_os = "linux")]
            Self::Unix(stream) => stream.read(buf),
        }
    }
}

impl Write for ClientStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buf),
            #[cfg(target_os = "linux")]
            Self::Unix(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            #[cfg(target_os = "linux")]
            Self::Unix(stream) => stream.flush(),
        }
    }
}

/// Where the local shared instance serves RPC, and the key a client
/// authenticates with: the configured `rpc_key`, else as upstream's
/// `Reticulum.rpc_key`, the full hash of the transport identity's private
/// key.
#[derive(Debug, Clone)]
pub struct SharedInstanceRpc {
    /// The shared instance's RPC server.
    pub addr: RpcAddr,
    /// The key both ends authenticate with.
    pub auth_key: [u8; 32],
}

impl SharedInstanceRpc {
    /// The shared instance RPC a config describes. `identity` gives the
    /// transport identity, and is only called without a configured
    /// `rpc_key`.
    pub fn new(
        reticulum: &crate::config::ReticulumSection,
        identity: impl FnOnce() -> io::Result<rns_crypto::identity::Identity>,
    ) -> io::Result<Self> {
        Self::with_key(
            RpcAddr::for_shared_instance(reticulum),
            reticulum.rpc_key,
            identity,
        )
    }

    /// The RPC server at `addr`, with `rpc_key` or else the key derived from
    /// the transport identity `identity` gives. An identity without a
    /// private key is an error.
    pub fn with_key(
        addr: RpcAddr,
        rpc_key: Option<[u8; 32]>,
        identity: impl FnOnce() -> io::Result<rns_crypto::identity::Identity>,
    ) -> io::Result<Self> {
        let auth_key = match rpc_key {
            Some(key) => key,
            None => {
                let private_key = identity()?.get_private_key().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "transport identity has no private key",
                    )
                })?;
                derive_auth_key(&private_key)
            }
        };
        Ok(Self { addr, auth_key })
    }

    /// Connect to the shared instance and authenticate.
    pub fn connect(&self) -> io::Result<RpcClient> {
        RpcClient::connect(&self.addr, &self.auth_key)
    }
}

impl RpcClient {
    /// Connect to an RPC server and authenticate.
    pub fn connect(addr: &RpcAddr, auth_key: &[u8; 32]) -> io::Result<Self> {
        let mut stream = ClientStream::connect(addr)?;
        stream.set_timeouts(Duration::from_secs(10))?;

        // Client-side authentication
        client_auth(&mut stream, auth_key)?;

        Ok(RpcClient { stream })
    }

    /// Send an RPC request and receive a response.
    pub fn call(&mut self, request: &PickleValue) -> io::Result<PickleValue> {
        let request_bytes = encode_rpc_payload(request, RpcCodec::Msgpack);
        send_bytes(&mut self.stream, &request_bytes)?;

        let response_bytes = recv_bytes(&mut self.stream)?;
        decode_rpc_payload(&response_bytes).map(|(value, _)| value)
    }

    /// List the hooks loaded in the node.
    pub fn list_hooks(&mut self) -> io::Result<Vec<HookInfo>> {
        let response = self.call(&PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("hooks".into()),
        )]))?;
        parse_hook_list(&response)
    }

    /// Ask the node to enter drain mode with the given timeout. Returns
    /// whether the request was accepted.
    pub fn begin_drain(&mut self, timeout: Duration) -> io::Result<bool> {
        let response = self.call(&PickleValue::Dict(vec![(
            PickleValue::String("begin_drain".into()),
            PickleValue::Float(timeout.as_secs_f64()),
        )]))?;
        Ok(response.as_bool().unwrap_or(false))
    }

    /// Current lifecycle and drain status, or `None` if the node sent none.
    pub fn drain_status(&mut self) -> io::Result<Option<DrainStatus>> {
        let response = self.call(&PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("drain_status".into()),
        )]))?;
        parse_drain_status(&response)
    }

    /// Provider bridge queue and drop counters, as the raw response value
    /// (`None` when the node runs no provider bridge).
    pub fn provider_bridge_stats(&mut self) -> io::Result<PickleValue> {
        self.call(&PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("provider_bridge_stats".into()),
        )]))
    }

    /// Load the WebAssembly hook `wasm` as `name` at `attach_point`. The inner
    /// result carries the node's error message on failure.
    pub fn load_hook(
        &mut self,
        name: &str,
        attach_point: &str,
        priority: i32,
        wasm: &[u8],
    ) -> io::Result<Result<(), String>> {
        let response = self.call(&PickleValue::Dict(vec![
            (
                PickleValue::String("hook".into()),
                PickleValue::String("load".into()),
            ),
            (
                PickleValue::String("name".into()),
                PickleValue::String(name.to_string()),
            ),
            (
                PickleValue::String("attach_point".into()),
                PickleValue::String(attach_point.to_string()),
            ),
            (
                PickleValue::String("priority".into()),
                PickleValue::Int(priority as i64),
            ),
            (
                PickleValue::String("wasm".into()),
                PickleValue::Bytes(wasm.to_vec()),
            ),
        ]))?;
        parse_hook_result(&response)
    }

    /// Load the built-in hook `builtin_id` as `name` at `attach_point`. The
    /// inner result carries the node's error message on failure.
    pub fn load_builtin_hook(
        &mut self,
        name: &str,
        attach_point: &str,
        priority: i32,
        builtin_id: &str,
    ) -> io::Result<Result<(), String>> {
        let response = self.call(&PickleValue::Dict(vec![
            (
                PickleValue::String("hook".into()),
                PickleValue::String("load_builtin".into()),
            ),
            (
                PickleValue::String("name".into()),
                PickleValue::String(name.to_string()),
            ),
            (
                PickleValue::String("attach_point".into()),
                PickleValue::String(attach_point.to_string()),
            ),
            (
                PickleValue::String("priority".into()),
                PickleValue::Int(priority as i64),
            ),
            (
                PickleValue::String("builtin_id".into()),
                PickleValue::String(builtin_id.to_string()),
            ),
        ]))?;
        parse_hook_result(&response)
    }

    /// Unload the hook `name` from `attach_point`. The inner result carries
    /// the node's error message on failure.
    pub fn unload_hook(
        &mut self,
        name: &str,
        attach_point: &str,
    ) -> io::Result<Result<(), String>> {
        let response = self.call(&PickleValue::Dict(vec![
            (
                PickleValue::String("hook".into()),
                PickleValue::String("unload".into()),
            ),
            (
                PickleValue::String("name".into()),
                PickleValue::String(name.to_string()),
            ),
            (
                PickleValue::String("attach_point".into()),
                PickleValue::String(attach_point.to_string()),
            ),
        ]))?;
        parse_hook_result(&response)
    }

    /// Enable or disable the hook `name` at `attach_point`. The inner result
    /// carries the node's error message on failure.
    pub fn set_hook_enabled(
        &mut self,
        name: &str,
        attach_point: &str,
        enabled: bool,
    ) -> io::Result<Result<(), String>> {
        let op = if enabled { "enable" } else { "disable" };
        let response = self.call(&PickleValue::Dict(vec![
            (
                PickleValue::String("hook".into()),
                PickleValue::String(op.into()),
            ),
            (
                PickleValue::String("name".into()),
                PickleValue::String(name.to_string()),
            ),
            (
                PickleValue::String("attach_point".into()),
                PickleValue::String(attach_point.to_string()),
            ),
        ]))?;
        parse_hook_result(&response)
    }

    /// Change the priority of the hook `name` at `attach_point`. The inner
    /// result carries the node's error message on failure.
    pub fn set_hook_priority(
        &mut self,
        name: &str,
        attach_point: &str,
        priority: i32,
    ) -> io::Result<Result<(), String>> {
        let response = self.call(&PickleValue::Dict(vec![
            (
                PickleValue::String("hook".into()),
                PickleValue::String("set_priority".into()),
            ),
            (
                PickleValue::String("name".into()),
                PickleValue::String(name.to_string()),
            ),
            (
                PickleValue::String("attach_point".into()),
                PickleValue::String(attach_point.to_string()),
            ),
            (
                PickleValue::String("priority".into()),
                PickleValue::Int(priority as i64),
            ),
        ]))?;
        parse_hook_result(&response)
    }

    /// Blacklist peer `ip` on the Backbone interface `interface` for
    /// `duration_secs` seconds, capped by the interface's maximum penalty.
    /// Returns whether the peer was blacklisted.
    pub fn blacklist_backbone_peer(
        &mut self,
        interface: &str,
        ip: &str,
        duration_secs: u64,
        reason: Option<&str>,
        penalty_level: Option<u8>,
    ) -> io::Result<bool> {
        let mut request = vec![
            (
                PickleValue::String("set".into()),
                PickleValue::String("backbone_peer_blacklist".into()),
            ),
            (
                PickleValue::String("interface".into()),
                PickleValue::String(interface.to_string()),
            ),
            (
                PickleValue::String("ip".into()),
                PickleValue::String(ip.to_string()),
            ),
            (
                PickleValue::String("duration_secs".into()),
                PickleValue::Int(duration_secs as i64),
            ),
        ];
        if let Some(reason) = reason {
            request.push((
                PickleValue::String("reason".into()),
                PickleValue::String(reason.to_string()),
            ));
        }
        if let Some(level) = penalty_level {
            request.push((
                PickleValue::String("penalty_level".into()),
                PickleValue::Int(level as i64),
            ));
        }
        let response = self.call(&PickleValue::Dict(request))?;
        Ok(response.as_bool().unwrap_or(false))
    }

    /// List the node's known destinations, with this implementation's
    /// fields (`{"get": "known_destination_entries"}`). The
    /// `known_destinations` call answers upstream's dict instead.
    pub fn known_destinations(&mut self) -> io::Result<Vec<KnownDestinationEntry>> {
        let response = self.call(&PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("known_destination_entries".into()),
        )]))?;
        parse_known_destination_list(&response)
    }

    /// Keep a known destination from being cleaned up. Returns whether the
    /// destination was known.
    pub fn retain_known_destination(&mut self, dest_hash: [u8; 16]) -> io::Result<bool> {
        let response = self.call(&PickleValue::Dict(vec![
            (
                PickleValue::String("set".into()),
                PickleValue::String("known_destination_retained".into()),
            ),
            (
                PickleValue::String("dest_hash".into()),
                PickleValue::Bytes(dest_hash.to_vec()),
            ),
        ]))?;
        Ok(response.as_bool().unwrap_or(false))
    }

    /// Retain every known destination of an identity. Returns whether any
    /// was found.
    pub fn retain_identity(&mut self, identity_hash: [u8; 16]) -> io::Result<bool> {
        let response = self.call(&PickleValue::Dict(vec![
            (
                PickleValue::String("set".into()),
                PickleValue::String("identity_retained".into()),
            ),
            (
                PickleValue::String("identity_hash".into()),
                PickleValue::Bytes(identity_hash.to_vec()),
            ),
        ]))?;
        Ok(response.as_bool().unwrap_or(false))
    }

    /// Stop retaining a known destination; it counts as used now. Returns
    /// whether the destination was known.
    pub fn unretain_known_destination(&mut self, dest_hash: [u8; 16]) -> io::Result<bool> {
        let response = self.call(&PickleValue::Dict(vec![
            (
                PickleValue::String("clear".into()),
                PickleValue::String("known_destination_retained".into()),
            ),
            (
                PickleValue::String("dest_hash".into()),
                PickleValue::Bytes(dest_hash.to_vec()),
            ),
        ]))?;
        Ok(response.as_bool().unwrap_or(false))
    }

    /// Mark a known destination as used now. Returns false when it is
    /// unknown or retained.
    pub fn mark_known_destination_used(&mut self, dest_hash: [u8; 16]) -> io::Result<bool> {
        let response = self.call(&PickleValue::Dict(vec![
            (
                PickleValue::String("set".into()),
                PickleValue::String("known_destination_used".into()),
            ),
            (
                PickleValue::String("dest_hash".into()),
                PickleValue::Bytes(dest_hash.to_vec()),
            ),
        ]))?;
        Ok(response.as_bool().unwrap_or(false))
    }
}

pub(super) fn parse_lifecycle_state(value: &str) -> Option<LifecycleState> {
    match value {
        "active" => Some(LifecycleState::Active),
        "draining" => Some(LifecycleState::Draining),
        "stopping" => Some(LifecycleState::Stopping),
        "stopped" => Some(LifecycleState::Stopped),
        _ => None,
    }
}

pub(super) fn parse_drain_status(value: &PickleValue) -> io::Result<Option<DrainStatus>> {
    if !matches!(value, PickleValue::Dict(_)) {
        return Ok(None);
    }
    let state = value
        .get("state")
        .and_then(|entry| entry.as_str())
        .and_then(parse_lifecycle_state)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing drain state"))?;
    let drain_age_seconds = value.get("drain_age_seconds").and_then(|entry| {
        entry
            .as_float()
            .or_else(|| entry.as_int().map(|v| v as f64))
    });
    let deadline_remaining_seconds = value.get("deadline_remaining_seconds").and_then(|entry| {
        entry
            .as_float()
            .or_else(|| entry.as_int().map(|v| v as f64))
    });
    let drain_complete = value
        .get("drain_complete")
        .and_then(|entry| entry.as_bool())
        .unwrap_or(false);
    let interface_writer_queued_frames = value
        .get("interface_writer_queued_frames")
        .and_then(|entry| entry.as_int())
        .unwrap_or(0)
        .max(0) as usize;
    let provider_backlog_events = value
        .get("provider_backlog_events")
        .and_then(|entry| entry.as_int())
        .unwrap_or(0)
        .max(0) as usize;
    let provider_consumer_queued_events = value
        .get("provider_consumer_queued_events")
        .and_then(|entry| entry.as_int())
        .unwrap_or(0)
        .max(0) as usize;
    let detail = value
        .get("detail")
        .and_then(|entry| entry.as_str().map(|v| v.to_string()));
    Ok(Some(DrainStatus {
        state,
        drain_age_seconds,
        deadline_remaining_seconds,
        drain_complete,
        interface_writer_queued_frames,
        provider_backlog_events,
        provider_consumer_queued_events,
        detail,
    }))
}

pub(super) fn parse_hook_result(response: &PickleValue) -> io::Result<Result<(), String>> {
    let ok = response
        .get("ok")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid hook response"))?;
    if ok {
        Ok(Ok(()))
    } else {
        Ok(Err(response
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown hook error")
            .to_string()))
    }
}

pub(super) fn parse_hook_list(response: &PickleValue) -> io::Result<Vec<HookInfo>> {
    let list = response
        .as_list()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid hooks response"))?;
    let mut hooks = Vec::with_capacity(list.len());
    for item in list {
        hooks.push(HookInfo {
            name: item
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing hook name"))?
                .to_string(),
            hook_type: item
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or(default_hook_type())
                .to_string(),
            attach_point: item
                .get("attach_point")
                .and_then(|v| v.as_str())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing attach_point"))?
                .to_string(),
            priority: item
                .get("priority")
                .and_then(|v| v.as_int())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing priority"))?
                as i32,
            enabled: item
                .get("enabled")
                .and_then(|v| v.as_bool())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing enabled"))?,
            consecutive_traps: item
                .get("consecutive_traps")
                .and_then(|v| v.as_int())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing consecutive_traps")
                })? as u32,
        });
    }
    Ok(hooks)
}

pub(super) fn default_hook_type() -> &'static str {
    if cfg!(feature = "rns-hooks-native") {
        "native"
    } else {
        "wasm"
    }
}
