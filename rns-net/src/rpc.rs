//! RPC server and client for cross-process daemon communication.
//!
//! Implements Python `multiprocessing.connection` wire protocol:
//! - 4-byte big-endian signed i32 length prefix + payload
//! - HMAC-SHA256 challenge-response authentication
//! - Pickle serialization for request/response dictionaries
//!
//! Server translates pickle dicts into [`QueryRequest`] events, sends
//! them through the driver event channel, and returns pickle responses.

use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::time::Duration;
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;

use rns_crypto::hmac::hmac_sha256;
use rns_crypto::sha256::sha256;

use crate::event::{
    BackboneInterfaceEntry, BackbonePeerStateEntry, BlackholeInfo, Event, EventSender, HookInfo,
    InterfaceStatsResponse, PathTableEntry, QueryRequest, QueryResponse, RateTableEntry,
    RuntimeConfigApplyMode, RuntimeConfigEntry, RuntimeConfigError, RuntimeConfigErrorCode,
    RuntimeConfigSource, RuntimeConfigValue, SingleInterfaceStat,
};
use crate::md5::hmac_md5;
use crate::pickle::{self, PickleValue};

const CHALLENGE_PREFIX: &[u8] = b"#CHALLENGE#";
const WELCOME: &[u8] = b"#WELCOME#";
const FAILURE: &[u8] = b"#FAILURE#";
const CHALLENGE_LEN: usize = 40;

/// RPC address types.
#[derive(Debug, Clone)]
pub enum RpcAddr {
    Tcp(String, u16),
}

/// RPC server that listens for incoming connections and handles queries.
pub struct RpcServer {
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl RpcServer {
    /// Start the RPC server on the given address.
    pub fn start(addr: &RpcAddr, auth_key: [u8; 32], event_tx: EventSender) -> io::Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown2 = shutdown.clone();

        let listener = match addr {
            RpcAddr::Tcp(host, port) => {
                let l = TcpListener::bind((host.as_str(), *port))?;
                // Non-blocking so we can check shutdown flag
                l.set_nonblocking(true)?;
                l
            }
        };

        let thread = thread::Builder::new()
            .name("rpc-server".into())
            .spawn(move || {
                rpc_server_loop(listener, auth_key, event_tx, shutdown2);
            })
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(RpcServer {
            shutdown,
            thread: Some(thread),
        })
    }

    /// Stop the RPC server.
    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for RpcServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn rpc_server_loop(
    listener: TcpListener,
    auth_key: [u8; 32],
    event_tx: EventSender,
    shutdown: Arc<AtomicBool>,
) {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        match listener.accept() {
            Ok((stream, _addr)) => {
                // Set blocking for this connection
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
                let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(10)));

                if let Err(e) = handle_connection(stream, &auth_key, &event_tx) {
                    log::debug!("RPC connection error: {}", e);
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No pending connection, sleep briefly and retry
                thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                log::error!("RPC accept error: {}", e);
                thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

fn handle_connection(
    mut stream: TcpStream,
    auth_key: &[u8; 32],
    event_tx: &EventSender,
) -> io::Result<()> {
    // Authentication: send challenge, verify response
    server_auth(&mut stream, auth_key)?;

    // Read request (pickle dict)
    let request_bytes = recv_bytes(&mut stream)?;
    let request = pickle::decode(&request_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    // Translate pickle dict to query, send to driver, get response
    let response = handle_rpc_request(&request, event_tx)?;

    // Encode response and send
    let response_bytes = pickle::encode(&response);
    send_bytes(&mut stream, &response_bytes)?;

    Ok(())
}

/// Server-side authentication: challenge-response.
fn server_auth(stream: &mut TcpStream, auth_key: &[u8; 32]) -> io::Result<()> {
    // Generate challenge: #CHALLENGE#{sha256}<40 random bytes>
    let mut random_bytes = [0u8; CHALLENGE_LEN];
    // Use /dev/urandom for randomness
    {
        let mut f = std::fs::File::open("/dev/urandom")?;
        f.read_exact(&mut random_bytes)?;
    }

    let mut challenge_message = Vec::with_capacity(CHALLENGE_PREFIX.len() + 8 + CHALLENGE_LEN);
    challenge_message.extend_from_slice(CHALLENGE_PREFIX);
    challenge_message.extend_from_slice(b"{sha256}");
    challenge_message.extend_from_slice(&random_bytes);

    send_bytes(stream, &challenge_message)?;

    // Read response (max 256 bytes)
    let response = recv_bytes(stream)?;

    // Verify response
    // The message to HMAC is everything after #CHALLENGE# (i.e. {sha256}<random>)
    let message = &challenge_message[CHALLENGE_PREFIX.len()..];

    if verify_response(auth_key, message, &response) {
        send_bytes(stream, WELCOME)?;
        Ok(())
    } else {
        send_bytes(stream, FAILURE)?;
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "auth failed",
        ))
    }
}

/// Verify a client's HMAC response.
fn verify_response(auth_key: &[u8; 32], message: &[u8], response: &[u8]) -> bool {
    // Modern protocol: response = {sha256}<hmac-sha256 digest>
    if response.starts_with(b"{sha256}") {
        let digest = &response[8..];
        let expected = hmac_sha256(auth_key, message);
        constant_time_eq(digest, &expected)
    }
    // Legacy protocol: response = raw 16-byte HMAC-MD5 digest
    else if response.len() == 16 {
        let expected = hmac_md5(auth_key, message);
        constant_time_eq(response, &expected)
    }
    // Legacy with {md5} prefix
    else if response.starts_with(b"{md5}") {
        let digest = &response[5..];
        let expected = hmac_md5(auth_key, message);
        constant_time_eq(digest, &expected)
    } else {
        false
    }
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Send bytes with 4-byte big-endian length prefix.
fn send_bytes(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    let len = data.len() as i32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(data)?;
    stream.flush()
}

/// Receive bytes with 4-byte big-endian length prefix.
fn recv_bytes(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = i32::from_be_bytes(len_buf);

    if len < 0 {
        // Extended format: 8-byte length
        let mut len8_buf = [0u8; 8];
        stream.read_exact(&mut len8_buf)?;
        let len = u64::from_be_bytes(len8_buf) as usize;
        if len > 64 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message too large",
            ));
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;
        Ok(buf)
    } else {
        let len = len as usize;
        if len > 64 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message too large",
            ));
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;
        Ok(buf)
    }
}

/// Translate a pickle request dict to a query event and get response.
fn handle_rpc_request(request: &PickleValue, event_tx: &EventSender) -> io::Result<PickleValue> {
    // Handle "get" requests
    if let Some(get_val) = request.get("get") {
        if let Some(path) = get_val.as_str() {
            return match path {
                "interface_stats" => {
                    let resp = send_query(event_tx, QueryRequest::InterfaceStats)?;
                    if let QueryResponse::InterfaceStats(stats) = resp {
                        Ok(interface_stats_to_pickle(&stats))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                "path_table" => {
                    let max_hops = request
                        .get("max_hops")
                        .and_then(|v| v.as_int().map(|n| n as u8));
                    let resp = send_query(event_tx, QueryRequest::PathTable { max_hops })?;
                    if let QueryResponse::PathTable(entries) = resp {
                        Ok(path_table_to_pickle(&entries))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                "rate_table" => {
                    let resp = send_query(event_tx, QueryRequest::RateTable)?;
                    if let QueryResponse::RateTable(entries) = resp {
                        Ok(rate_table_to_pickle(&entries))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                "next_hop" => {
                    let hash = extract_dest_hash(request, "destination_hash")?;
                    let resp = send_query(event_tx, QueryRequest::NextHop { dest_hash: hash })?;
                    if let QueryResponse::NextHop(Some(nh)) = resp {
                        Ok(PickleValue::Bytes(nh.next_hop.to_vec()))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                "next_hop_if_name" => {
                    let hash = extract_dest_hash(request, "destination_hash")?;
                    let resp =
                        send_query(event_tx, QueryRequest::NextHopIfName { dest_hash: hash })?;
                    if let QueryResponse::NextHopIfName(Some(name)) = resp {
                        Ok(PickleValue::String(name))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                "link_count" => {
                    let resp = send_query(event_tx, QueryRequest::LinkCount)?;
                    if let QueryResponse::LinkCount(n) = resp {
                        Ok(PickleValue::Int(n as i64))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                "transport_identity" => {
                    let resp = send_query(event_tx, QueryRequest::TransportIdentity)?;
                    if let QueryResponse::TransportIdentity(Some(hash)) = resp {
                        Ok(PickleValue::Bytes(hash.to_vec()))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                "blackholed" => {
                    let resp = send_query(event_tx, QueryRequest::GetBlackholed)?;
                    if let QueryResponse::Blackholed(entries) = resp {
                        Ok(blackholed_to_pickle(&entries))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                "discovered_interfaces" => {
                    let only_available = request
                        .get("only_available")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let only_transport = request
                        .get("only_transport")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let resp = send_query(
                        event_tx,
                        QueryRequest::DiscoveredInterfaces {
                            only_available,
                            only_transport,
                        },
                    )?;
                    if let QueryResponse::DiscoveredInterfaces(interfaces) = resp {
                        Ok(discovered_interfaces_to_pickle(&interfaces))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                "hooks" => {
                    let (response_tx, response_rx) = mpsc::channel();
                    event_tx
                        .send(Event::ListHooks { response_tx })
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::BrokenPipe, "driver shut down")
                        })?;
                    let hooks = response_rx
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "list hooks timed out")
                        })?;
                    Ok(hooks_to_pickle(&hooks))
                }
                "runtime_config" => {
                    let resp = send_query(event_tx, QueryRequest::ListRuntimeConfig)?;
                    if let QueryResponse::RuntimeConfigList(entries) = resp {
                        Ok(runtime_config_list_to_pickle(&entries))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                "runtime_config_entry" => {
                    let key = request
                        .get("key")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let resp = send_query(event_tx, QueryRequest::GetRuntimeConfig { key })?;
                    if let QueryResponse::RuntimeConfigEntry(entry) = resp {
                        Ok(entry
                            .as_ref()
                            .map(runtime_config_entry_to_pickle)
                            .unwrap_or(PickleValue::None))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                "backbone_peer_state" => {
                    let interface_name = request
                        .get("interface")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let resp =
                        send_query(event_tx, QueryRequest::BackbonePeerState { interface_name })?;
                    if let QueryResponse::BackbonePeerState(entries) = resp {
                        Ok(backbone_peer_state_to_pickle(&entries))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                "backbone_interfaces" => {
                    let resp = send_query(event_tx, QueryRequest::BackboneInterfaces)?;
                    if let QueryResponse::BackboneInterfaces(entries) = resp {
                        Ok(backbone_interfaces_to_pickle(&entries))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                _ => Ok(PickleValue::None),
            };
        }
    }

    if let Some(set_val) = request.get("set").and_then(|v| v.as_str()) {
        if set_val == "runtime_config" {
            let key = request
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let Some(value) = request
                .get("value")
                .and_then(runtime_config_value_from_pickle)
            else {
                return Ok(runtime_config_error_to_pickle(&RuntimeConfigError {
                    code: RuntimeConfigErrorCode::InvalidType,
                    message: "runtime-config set requires a scalar value".into(),
                }));
            };
            let resp = send_query(event_tx, QueryRequest::SetRuntimeConfig { key, value })?;
            return if let QueryResponse::RuntimeConfigSet(result) = resp {
                Ok(runtime_config_result_to_pickle(result))
            } else {
                Ok(PickleValue::None)
            };
        }
    }

    if let Some(reset_val) = request.get("reset").and_then(|v| v.as_str()) {
        if reset_val == "runtime_config" {
            let key = request
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let resp = send_query(event_tx, QueryRequest::ResetRuntimeConfig { key })?;
            return if let QueryResponse::RuntimeConfigReset(result) = resp {
                Ok(runtime_config_result_to_pickle(result))
            } else {
                Ok(PickleValue::None)
            };
        }
    }

    if let Some(clear_val) = request.get("clear").and_then(|v| v.as_str()) {
        if clear_val == "backbone_peer_state" {
            let interface_name = required_string(request, "interface")?;
            let peer_ip = required_string(request, "ip")?;
            let peer_ip = peer_ip
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid peer IP"))?;
            let resp = send_query(
                event_tx,
                QueryRequest::ClearBackbonePeerState {
                    interface_name,
                    peer_ip,
                },
            )?;
            return if let QueryResponse::ClearBackbonePeerState(ok) = resp {
                Ok(PickleValue::Bool(ok))
            } else {
                Ok(PickleValue::None)
            };
        }
    }

    if let Some(set_val) = request.get("set").and_then(|v| v.as_str()) {
        if set_val == "backbone_peer_blacklist" {
            let interface_name = required_string(request, "interface")?;
            let peer_ip = required_string(request, "ip")?;
            let peer_ip: IpAddr = peer_ip
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid peer IP"))?;
            let duration_secs = request
                .get("duration_secs")
                .and_then(|v| v.as_int())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing duration_secs")
                })?;
            let reason = request
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("sentinel blacklist")
                .to_string();
            let penalty_level = request
                .get("penalty_level")
                .and_then(|v| v.as_int())
                .unwrap_or(0)
                .clamp(0, u8::MAX as i64) as u8;
            let resp = send_query(
                event_tx,
                QueryRequest::BlacklistBackbonePeer {
                    interface_name,
                    peer_ip,
                    duration: Duration::from_secs(duration_secs as u64),
                    reason,
                    penalty_level,
                },
            )?;
            return if let QueryResponse::BlacklistBackbonePeer(ok) = resp {
                Ok(PickleValue::Bool(ok))
            } else {
                Ok(PickleValue::None)
            };
        }
    }

    // Handle "request_path" -- trigger a path request to the network
    if let Some(hash_val) = request.get("request_path") {
        if let Some(hash_bytes) = hash_val.as_bytes() {
            if hash_bytes.len() >= 16 {
                let mut dest_hash = [0u8; 16];
                dest_hash.copy_from_slice(&hash_bytes[..16]);
                let _ = event_tx.send(crate::event::Event::RequestPath { dest_hash });
                return Ok(PickleValue::Bool(true));
            }
        }
    }

    // Handle "send_probe" requests
    if let Some(hash_val) = request.get("send_probe") {
        if let Some(hash_bytes) = hash_val.as_bytes() {
            if hash_bytes.len() >= 16 {
                let mut dest_hash = [0u8; 16];
                dest_hash.copy_from_slice(&hash_bytes[..16]);
                let payload_size = request
                    .get("size")
                    .and_then(|v| v.as_int())
                    .and_then(|n| {
                        if n > 0 && n <= 400 {
                            Some(n as usize)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(16);
                let resp = send_query(
                    event_tx,
                    QueryRequest::SendProbe {
                        dest_hash,
                        payload_size,
                    },
                )?;
                if let QueryResponse::SendProbe(Some((packet_hash, hops))) = resp {
                    return Ok(PickleValue::Dict(vec![
                        (
                            PickleValue::String("packet_hash".into()),
                            PickleValue::Bytes(packet_hash.to_vec()),
                        ),
                        (
                            PickleValue::String("hops".into()),
                            PickleValue::Int(hops as i64),
                        ),
                    ]));
                } else {
                    return Ok(PickleValue::None);
                }
            }
        }
    }

    // Handle "check_proof" requests
    if let Some(hash_val) = request.get("check_proof") {
        if let Some(hash_bytes) = hash_val.as_bytes() {
            if hash_bytes.len() >= 32 {
                let mut packet_hash = [0u8; 32];
                packet_hash.copy_from_slice(&hash_bytes[..32]);
                let resp = send_query(event_tx, QueryRequest::CheckProof { packet_hash })?;
                if let QueryResponse::CheckProof(Some(rtt)) = resp {
                    return Ok(PickleValue::Float(rtt));
                } else {
                    return Ok(PickleValue::None);
                }
            }
        }
    }

    // Handle "blackhole" requests
    if let Some(hash_val) = request.get("blackhole") {
        if let Some(hash_bytes) = hash_val.as_bytes() {
            if hash_bytes.len() >= 16 {
                let mut identity_hash = [0u8; 16];
                identity_hash.copy_from_slice(&hash_bytes[..16]);
                let duration_hours = request.get("duration").and_then(|v| v.as_float());
                let reason = request
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let resp = send_query(
                    event_tx,
                    QueryRequest::BlackholeIdentity {
                        identity_hash,
                        duration_hours,
                        reason,
                    },
                )?;
                return Ok(PickleValue::Bool(matches!(
                    resp,
                    QueryResponse::BlackholeResult(true)
                )));
            }
        }
    }

    // Handle "unblackhole" requests
    if let Some(hash_val) = request.get("unblackhole") {
        if let Some(hash_bytes) = hash_val.as_bytes() {
            if hash_bytes.len() >= 16 {
                let mut identity_hash = [0u8; 16];
                identity_hash.copy_from_slice(&hash_bytes[..16]);
                let resp = send_query(
                    event_tx,
                    QueryRequest::UnblackholeIdentity { identity_hash },
                )?;
                return Ok(PickleValue::Bool(matches!(
                    resp,
                    QueryResponse::UnblackholeResult(true)
                )));
            }
        }
    }

    // Handle "drop" requests
    if let Some(drop_val) = request.get("drop") {
        if let Some(path) = drop_val.as_str() {
            return match path {
                "path" => {
                    let hash = extract_dest_hash(request, "destination_hash")?;
                    let resp = send_query(event_tx, QueryRequest::DropPath { dest_hash: hash })?;
                    if let QueryResponse::DropPath(ok) = resp {
                        Ok(PickleValue::Bool(ok))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                "all_via" => {
                    let hash = extract_dest_hash(request, "destination_hash")?;
                    let resp = send_query(
                        event_tx,
                        QueryRequest::DropAllVia {
                            transport_hash: hash,
                        },
                    )?;
                    if let QueryResponse::DropAllVia(n) = resp {
                        Ok(PickleValue::Int(n as i64))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                "announce_queues" => {
                    let resp = send_query(event_tx, QueryRequest::DropAnnounceQueues)?;
                    if let QueryResponse::DropAnnounceQueues = resp {
                        Ok(PickleValue::Bool(true))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                _ => Ok(PickleValue::None),
            };
        }
    }

    if let Some(hook_val) = request.get("hook").and_then(|v| v.as_str()) {
        return handle_hook_rpc_request(hook_val, request, event_tx);
    }

    Ok(PickleValue::None)
}

fn handle_hook_rpc_request(
    op: &str,
    request: &PickleValue,
    event_tx: &EventSender,
) -> io::Result<PickleValue> {
    match op {
        "load" => {
            let name = required_string(request, "name")?;
            let attach_point = required_string(request, "attach_point")?;
            let priority = request
                .get("priority")
                .and_then(|v| v.as_int())
                .unwrap_or(0) as i32;
            let wasm = request
                .get("wasm")
                .and_then(|v| v.as_bytes())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing wasm"))?
                .to_vec();
            let (response_tx, response_rx) = mpsc::channel();
            event_tx
                .send(Event::LoadHook {
                    name,
                    wasm_bytes: wasm,
                    attach_point,
                    priority,
                    response_tx,
                })
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "driver shut down"))?;
            let response = response_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "hook load timed out"))?;
            Ok(hook_result_to_pickle(response))
        }
        "unload" => {
            let name = required_string(request, "name")?;
            let attach_point = required_string(request, "attach_point")?;
            let (response_tx, response_rx) = mpsc::channel();
            event_tx
                .send(Event::UnloadHook {
                    name,
                    attach_point,
                    response_tx,
                })
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "driver shut down"))?;
            let response = response_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "hook unload timed out"))?;
            Ok(hook_result_to_pickle(response))
        }
        "enable" | "disable" => {
            let name = required_string(request, "name")?;
            let attach_point = required_string(request, "attach_point")?;
            let enabled = op == "enable";
            let (response_tx, response_rx) = mpsc::channel();
            event_tx
                .send(Event::SetHookEnabled {
                    name,
                    attach_point,
                    enabled,
                    response_tx,
                })
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "driver shut down"))?;
            let response = response_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "hook enable/disable timed out")
                })?;
            Ok(hook_result_to_pickle(response))
        }
        "set_priority" => {
            let name = required_string(request, "name")?;
            let attach_point = required_string(request, "attach_point")?;
            let priority = request
                .get("priority")
                .and_then(|v| v.as_int())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing priority"))?
                as i32;
            let (response_tx, response_rx) = mpsc::channel();
            event_tx
                .send(Event::SetHookPriority {
                    name,
                    attach_point,
                    priority,
                    response_tx,
                })
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "driver shut down"))?;
            let response = response_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "hook priority timed out"))?;
            Ok(hook_result_to_pickle(response))
        }
        _ => Ok(PickleValue::None),
    }
}

/// Send a query to the driver and wait for the response.
fn send_query(event_tx: &EventSender, request: QueryRequest) -> io::Result<QueryResponse> {
    let (resp_tx, resp_rx) = mpsc::channel();
    event_tx
        .send(Event::Query(request, resp_tx))
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "driver shut down"))?;
    resp_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "query timed out"))
}

/// Extract a 16-byte destination hash from a pickle dict field.
fn extract_dest_hash(request: &PickleValue, key: &str) -> io::Result<[u8; 16]> {
    let bytes = request
        .get(key)
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing destination_hash"))?;
    if bytes.len() < 16 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "hash too short"));
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&bytes[..16]);
    Ok(hash)
}

fn required_string(request: &PickleValue, key: &str) -> io::Result<String> {
    request
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("missing {}", key)))
}

fn hook_result_to_pickle(result: Result<(), String>) -> PickleValue {
    match result {
        Ok(()) => PickleValue::Dict(vec![(
            PickleValue::String("ok".into()),
            PickleValue::Bool(true),
        )]),
        Err(error) => PickleValue::Dict(vec![
            (PickleValue::String("ok".into()), PickleValue::Bool(false)),
            (
                PickleValue::String("error".into()),
                PickleValue::String(error),
            ),
        ]),
    }
}

// --- Pickle response builders ---

fn interface_stats_to_pickle(stats: &InterfaceStatsResponse) -> PickleValue {
    let mut ifaces = Vec::new();
    for iface in &stats.interfaces {
        ifaces.push(single_iface_to_pickle(iface));
    }

    let mut dict = vec![
        (
            PickleValue::String("interfaces".into()),
            PickleValue::List(ifaces),
        ),
        (
            PickleValue::String("transport_enabled".into()),
            PickleValue::Bool(stats.transport_enabled),
        ),
        (
            PickleValue::String("transport_uptime".into()),
            PickleValue::Float(stats.transport_uptime),
        ),
        (
            PickleValue::String("rxb".into()),
            PickleValue::Int(stats.total_rxb as i64),
        ),
        (
            PickleValue::String("txb".into()),
            PickleValue::Int(stats.total_txb as i64),
        ),
    ];

    if let Some(tid) = stats.transport_id {
        dict.push((
            PickleValue::String("transport_id".into()),
            PickleValue::Bytes(tid.to_vec()),
        ));
    } else {
        dict.push((
            PickleValue::String("transport_id".into()),
            PickleValue::None,
        ));
    }

    if let Some(pr) = stats.probe_responder {
        dict.push((
            PickleValue::String("probe_responder".into()),
            PickleValue::Bytes(pr.to_vec()),
        ));
    } else {
        dict.push((
            PickleValue::String("probe_responder".into()),
            PickleValue::None,
        ));
    }

    PickleValue::Dict(dict)
}

fn single_iface_to_pickle(s: &SingleInterfaceStat) -> PickleValue {
    let mut dict = vec![
        (
            PickleValue::String("id".into()),
            PickleValue::Int(s.id as i64),
        ),
        (
            PickleValue::String("name".into()),
            PickleValue::String(s.name.clone()),
        ),
        (
            PickleValue::String("status".into()),
            PickleValue::Bool(s.status),
        ),
        (
            PickleValue::String("mode".into()),
            PickleValue::Int(s.mode as i64),
        ),
        (
            PickleValue::String("rxb".into()),
            PickleValue::Int(s.rxb as i64),
        ),
        (
            PickleValue::String("txb".into()),
            PickleValue::Int(s.txb as i64),
        ),
        (
            PickleValue::String("rx_packets".into()),
            PickleValue::Int(s.rx_packets as i64),
        ),
        (
            PickleValue::String("tx_packets".into()),
            PickleValue::Int(s.tx_packets as i64),
        ),
        (
            PickleValue::String("started".into()),
            PickleValue::Float(s.started),
        ),
        (
            PickleValue::String("ia_freq".into()),
            PickleValue::Float(s.ia_freq),
        ),
        (
            PickleValue::String("oa_freq".into()),
            PickleValue::Float(s.oa_freq),
        ),
    ];

    match s.bitrate {
        Some(br) => dict.push((
            PickleValue::String("bitrate".into()),
            PickleValue::Int(br as i64),
        )),
        None => dict.push((PickleValue::String("bitrate".into()), PickleValue::None)),
    }

    match s.ifac_size {
        Some(sz) => dict.push((
            PickleValue::String("ifac_size".into()),
            PickleValue::Int(sz as i64),
        )),
        None => dict.push((PickleValue::String("ifac_size".into()), PickleValue::None)),
    }

    PickleValue::Dict(dict)
}

fn path_table_to_pickle(entries: &[PathTableEntry]) -> PickleValue {
    let list: Vec<PickleValue> = entries
        .iter()
        .map(|e| {
            PickleValue::Dict(vec![
                (
                    PickleValue::String("hash".into()),
                    PickleValue::Bytes(e.hash.to_vec()),
                ),
                (
                    PickleValue::String("timestamp".into()),
                    PickleValue::Float(e.timestamp),
                ),
                (
                    PickleValue::String("via".into()),
                    PickleValue::Bytes(e.via.to_vec()),
                ),
                (
                    PickleValue::String("hops".into()),
                    PickleValue::Int(e.hops as i64),
                ),
                (
                    PickleValue::String("expires".into()),
                    PickleValue::Float(e.expires),
                ),
                (
                    PickleValue::String("interface".into()),
                    PickleValue::String(e.interface_name.clone()),
                ),
            ])
        })
        .collect();
    PickleValue::List(list)
}

fn rate_table_to_pickle(entries: &[RateTableEntry]) -> PickleValue {
    let list: Vec<PickleValue> = entries
        .iter()
        .map(|e| {
            PickleValue::Dict(vec![
                (
                    PickleValue::String("hash".into()),
                    PickleValue::Bytes(e.hash.to_vec()),
                ),
                (
                    PickleValue::String("last".into()),
                    PickleValue::Float(e.last),
                ),
                (
                    PickleValue::String("rate_violations".into()),
                    PickleValue::Int(e.rate_violations as i64),
                ),
                (
                    PickleValue::String("blocked_until".into()),
                    PickleValue::Float(e.blocked_until),
                ),
                (
                    PickleValue::String("timestamps".into()),
                    PickleValue::List(
                        e.timestamps
                            .iter()
                            .map(|&t| PickleValue::Float(t))
                            .collect(),
                    ),
                ),
            ])
        })
        .collect();
    PickleValue::List(list)
}

fn blackholed_to_pickle(entries: &[BlackholeInfo]) -> PickleValue {
    let list: Vec<PickleValue> = entries
        .iter()
        .map(|e| {
            let mut dict = vec![
                (
                    PickleValue::String("identity_hash".into()),
                    PickleValue::Bytes(e.identity_hash.to_vec()),
                ),
                (
                    PickleValue::String("created".into()),
                    PickleValue::Float(e.created),
                ),
                (
                    PickleValue::String("expires".into()),
                    PickleValue::Float(e.expires),
                ),
            ];
            if let Some(ref reason) = e.reason {
                dict.push((
                    PickleValue::String("reason".into()),
                    PickleValue::String(reason.clone()),
                ));
            } else {
                dict.push((PickleValue::String("reason".into()), PickleValue::None));
            }
            PickleValue::Dict(dict)
        })
        .collect();
    PickleValue::List(list)
}

fn discovered_interfaces_to_pickle(
    interfaces: &[crate::discovery::DiscoveredInterface],
) -> PickleValue {
    let list: Vec<PickleValue> = interfaces
        .iter()
        .map(|iface| {
            let mut dict = vec![
                (
                    PickleValue::String("type".into()),
                    PickleValue::String(iface.interface_type.clone()),
                ),
                (
                    PickleValue::String("transport".into()),
                    PickleValue::Bool(iface.transport),
                ),
                (
                    PickleValue::String("name".into()),
                    PickleValue::String(iface.name.clone()),
                ),
                (
                    PickleValue::String("discovered".into()),
                    PickleValue::Float(iface.discovered),
                ),
                (
                    PickleValue::String("last_heard".into()),
                    PickleValue::Float(iface.last_heard),
                ),
                (
                    PickleValue::String("heard_count".into()),
                    PickleValue::Int(iface.heard_count as i64),
                ),
                (
                    PickleValue::String("status".into()),
                    PickleValue::String(iface.status.as_str().into()),
                ),
                (
                    PickleValue::String("stamp".into()),
                    PickleValue::Bytes(iface.stamp.clone()),
                ),
                (
                    PickleValue::String("value".into()),
                    PickleValue::Int(iface.stamp_value as i64),
                ),
                (
                    PickleValue::String("transport_id".into()),
                    PickleValue::Bytes(iface.transport_id.to_vec()),
                ),
                (
                    PickleValue::String("network_id".into()),
                    PickleValue::Bytes(iface.network_id.to_vec()),
                ),
                (
                    PickleValue::String("hops".into()),
                    PickleValue::Int(iface.hops as i64),
                ),
            ];

            // Optional location fields
            if let Some(v) = iface.latitude {
                dict.push((
                    PickleValue::String("latitude".into()),
                    PickleValue::Float(v),
                ));
            } else {
                dict.push((PickleValue::String("latitude".into()), PickleValue::None));
            }
            if let Some(v) = iface.longitude {
                dict.push((
                    PickleValue::String("longitude".into()),
                    PickleValue::Float(v),
                ));
            } else {
                dict.push((PickleValue::String("longitude".into()), PickleValue::None));
            }
            if let Some(v) = iface.height {
                dict.push((PickleValue::String("height".into()), PickleValue::Float(v)));
            } else {
                dict.push((PickleValue::String("height".into()), PickleValue::None));
            }

            // Connection info
            if let Some(ref v) = iface.reachable_on {
                dict.push((
                    PickleValue::String("reachable_on".into()),
                    PickleValue::String(v.clone()),
                ));
            } else {
                dict.push((
                    PickleValue::String("reachable_on".into()),
                    PickleValue::None,
                ));
            }
            if let Some(v) = iface.port {
                dict.push((
                    PickleValue::String("port".into()),
                    PickleValue::Int(v as i64),
                ));
            } else {
                dict.push((PickleValue::String("port".into()), PickleValue::None));
            }

            // RNode/RF specific
            if let Some(v) = iface.frequency {
                dict.push((
                    PickleValue::String("frequency".into()),
                    PickleValue::Int(v as i64),
                ));
            } else {
                dict.push((PickleValue::String("frequency".into()), PickleValue::None));
            }
            if let Some(v) = iface.bandwidth {
                dict.push((
                    PickleValue::String("bandwidth".into()),
                    PickleValue::Int(v as i64),
                ));
            } else {
                dict.push((PickleValue::String("bandwidth".into()), PickleValue::None));
            }
            if let Some(v) = iface.spreading_factor {
                dict.push((PickleValue::String("sf".into()), PickleValue::Int(v as i64)));
            } else {
                dict.push((PickleValue::String("sf".into()), PickleValue::None));
            }
            if let Some(v) = iface.coding_rate {
                dict.push((PickleValue::String("cr".into()), PickleValue::Int(v as i64)));
            } else {
                dict.push((PickleValue::String("cr".into()), PickleValue::None));
            }
            if let Some(ref v) = iface.modulation {
                dict.push((
                    PickleValue::String("modulation".into()),
                    PickleValue::String(v.clone()),
                ));
            } else {
                dict.push((PickleValue::String("modulation".into()), PickleValue::None));
            }
            if let Some(v) = iface.channel {
                dict.push((
                    PickleValue::String("channel".into()),
                    PickleValue::Int(v as i64),
                ));
            } else {
                dict.push((PickleValue::String("channel".into()), PickleValue::None));
            }

            // IFAC info
            if let Some(ref v) = iface.ifac_netname {
                dict.push((
                    PickleValue::String("ifac_netname".into()),
                    PickleValue::String(v.clone()),
                ));
            } else {
                dict.push((
                    PickleValue::String("ifac_netname".into()),
                    PickleValue::None,
                ));
            }
            if let Some(ref v) = iface.ifac_netkey {
                dict.push((
                    PickleValue::String("ifac_netkey".into()),
                    PickleValue::String(v.clone()),
                ));
            } else {
                dict.push((PickleValue::String("ifac_netkey".into()), PickleValue::None));
            }

            // Config entry
            if let Some(ref v) = iface.config_entry {
                dict.push((
                    PickleValue::String("config_entry".into()),
                    PickleValue::String(v.clone()),
                ));
            } else {
                dict.push((
                    PickleValue::String("config_entry".into()),
                    PickleValue::None,
                ));
            }

            dict.push((
                PickleValue::String("discovery_hash".into()),
                PickleValue::Bytes(iface.discovery_hash.to_vec()),
            ));

            PickleValue::Dict(dict)
        })
        .collect();
    PickleValue::List(list)
}

fn hooks_to_pickle(hooks: &[HookInfo]) -> PickleValue {
    PickleValue::List(
        hooks
            .iter()
            .map(|hook| {
                PickleValue::Dict(vec![
                    (
                        PickleValue::String("name".into()),
                        PickleValue::String(hook.name.clone()),
                    ),
                    (
                        PickleValue::String("attach_point".into()),
                        PickleValue::String(hook.attach_point.clone()),
                    ),
                    (
                        PickleValue::String("priority".into()),
                        PickleValue::Int(hook.priority as i64),
                    ),
                    (
                        PickleValue::String("enabled".into()),
                        PickleValue::Bool(hook.enabled),
                    ),
                    (
                        PickleValue::String("consecutive_traps".into()),
                        PickleValue::Int(hook.consecutive_traps as i64),
                    ),
                ])
            })
            .collect(),
    )
}

fn backbone_peer_state_to_pickle(entries: &[BackbonePeerStateEntry]) -> PickleValue {
    PickleValue::List(
        entries
            .iter()
            .map(|entry| {
                PickleValue::Dict(vec![
                    (
                        PickleValue::String("interface".into()),
                        PickleValue::String(entry.interface_name.clone()),
                    ),
                    (
                        PickleValue::String("ip".into()),
                        PickleValue::String(entry.peer_ip.to_string()),
                    ),
                    (
                        PickleValue::String("connected_count".into()),
                        PickleValue::Int(entry.connected_count as i64),
                    ),
                    (
                        PickleValue::String("blacklisted_remaining_secs".into()),
                        entry
                            .blacklisted_remaining_secs
                            .map(PickleValue::Float)
                            .unwrap_or(PickleValue::None),
                    ),
                    (
                        PickleValue::String("blacklist_reason".into()),
                        entry
                            .blacklist_reason
                            .as_ref()
                            .map(|v: &String| PickleValue::String(v.clone()))
                            .unwrap_or(PickleValue::None),
                    ),
                    (
                        PickleValue::String("reject_count".into()),
                        PickleValue::Int(entry.reject_count as i64),
                    ),
                ])
            })
            .collect(),
    )
}

fn backbone_interfaces_to_pickle(entries: &[BackboneInterfaceEntry]) -> PickleValue {
    PickleValue::List(
        entries
            .iter()
            .map(|entry| {
                PickleValue::Dict(vec![
                    (
                        PickleValue::String("id".into()),
                        PickleValue::Int(entry.interface_id.0 as i64),
                    ),
                    (
                        PickleValue::String("name".into()),
                        PickleValue::String(entry.interface_name.clone()),
                    ),
                ])
            })
            .collect(),
    )
}

fn runtime_config_value_to_pickle(value: &RuntimeConfigValue) -> PickleValue {
    match value {
        RuntimeConfigValue::Int(v) => PickleValue::Int(*v),
        RuntimeConfigValue::Float(v) => PickleValue::Float(*v),
        RuntimeConfigValue::Bool(v) => PickleValue::Bool(*v),
        RuntimeConfigValue::String(v) => PickleValue::String(v.clone()),
        RuntimeConfigValue::Null => PickleValue::None,
    }
}

fn runtime_config_value_from_pickle(value: &PickleValue) -> Option<RuntimeConfigValue> {
    match value {
        PickleValue::Int(v) => Some(RuntimeConfigValue::Int(*v)),
        PickleValue::Float(v) => Some(RuntimeConfigValue::Float(*v)),
        PickleValue::Bool(v) => Some(RuntimeConfigValue::Bool(*v)),
        PickleValue::String(v) => Some(RuntimeConfigValue::String(v.clone())),
        PickleValue::None => Some(RuntimeConfigValue::Null),
        _ => None,
    }
}

fn runtime_config_entry_to_pickle(entry: &RuntimeConfigEntry) -> PickleValue {
    PickleValue::Dict(vec![
        (
            PickleValue::String("key".into()),
            PickleValue::String(entry.key.clone()),
        ),
        (
            PickleValue::String("value".into()),
            runtime_config_value_to_pickle(&entry.value),
        ),
        (
            PickleValue::String("default".into()),
            runtime_config_value_to_pickle(&entry.default),
        ),
        (
            PickleValue::String("source".into()),
            PickleValue::String(match entry.source {
                RuntimeConfigSource::Startup => "startup".into(),
                RuntimeConfigSource::RuntimeOverride => "runtime_override".into(),
            }),
        ),
        (
            PickleValue::String("apply_mode".into()),
            PickleValue::String(match entry.apply_mode {
                RuntimeConfigApplyMode::Immediate => "immediate".into(),
                RuntimeConfigApplyMode::NewConnectionsOnly => "new_connections_only".into(),
                RuntimeConfigApplyMode::NextReconnect => "next_reconnect".into(),
                RuntimeConfigApplyMode::RestartRequired => "restart_required".into(),
            }),
        ),
        (
            PickleValue::String("description".into()),
            entry
                .description
                .as_ref()
                .map(|v| PickleValue::String(v.clone()))
                .unwrap_or(PickleValue::None),
        ),
    ])
}

fn runtime_config_list_to_pickle(entries: &[RuntimeConfigEntry]) -> PickleValue {
    PickleValue::List(entries.iter().map(runtime_config_entry_to_pickle).collect())
}

fn runtime_config_error_to_pickle(error: &RuntimeConfigError) -> PickleValue {
    PickleValue::Dict(vec![
        (
            PickleValue::String("error".into()),
            PickleValue::String(match error.code {
                RuntimeConfigErrorCode::UnknownKey => "unknown_key".into(),
                RuntimeConfigErrorCode::InvalidType => "invalid_type".into(),
                RuntimeConfigErrorCode::InvalidValue => "invalid_value".into(),
                RuntimeConfigErrorCode::Unsupported => "unsupported".into(),
                RuntimeConfigErrorCode::NotFound => "not_found".into(),
                RuntimeConfigErrorCode::ApplyFailed => "apply_failed".into(),
            }),
        ),
        (
            PickleValue::String("message".into()),
            PickleValue::String(error.message.clone()),
        ),
    ])
}

fn runtime_config_result_to_pickle(
    result: Result<RuntimeConfigEntry, RuntimeConfigError>,
) -> PickleValue {
    match result {
        Ok(entry) => runtime_config_entry_to_pickle(&entry),
        Err(error) => runtime_config_error_to_pickle(&error),
    }
}

// --- RPC Client ---

/// RPC client for connecting to a running daemon.
pub struct RpcClient {
    stream: TcpStream,
}

impl RpcClient {
    /// Connect to an RPC server and authenticate.
    pub fn connect(addr: &RpcAddr, auth_key: &[u8; 32]) -> io::Result<Self> {
        let mut stream = match addr {
            RpcAddr::Tcp(host, port) => TcpStream::connect((host.as_str(), *port))?,
        };

        stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;

        // Client-side authentication
        client_auth(&mut stream, auth_key)?;

        Ok(RpcClient { stream })
    }

    /// Send a pickle request and receive a pickle response.
    pub fn call(&mut self, request: &PickleValue) -> io::Result<PickleValue> {
        let request_bytes = pickle::encode(request);
        send_bytes(&mut self.stream, &request_bytes)?;

        let response_bytes = recv_bytes(&mut self.stream)?;
        pickle::decode(&response_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    pub fn list_hooks(&mut self) -> io::Result<Vec<HookInfo>> {
        let response = self.call(&PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("hooks".into()),
        )]))?;
        parse_hook_list(&response)
    }

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
}

fn parse_hook_result(response: &PickleValue) -> io::Result<Result<(), String>> {
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

fn parse_hook_list(response: &PickleValue) -> io::Result<Vec<HookInfo>> {
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

/// Client-side authentication: answer the server's challenge.
fn client_auth(stream: &mut TcpStream, auth_key: &[u8; 32]) -> io::Result<()> {
    // Read challenge
    let challenge = recv_bytes(stream)?;

    if !challenge.starts_with(CHALLENGE_PREFIX) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected challenge",
        ));
    }

    let message = &challenge[CHALLENGE_PREFIX.len()..];

    // Create HMAC response
    let response = create_response(auth_key, message);
    send_bytes(stream, &response)?;

    // Read welcome/failure
    let result = recv_bytes(stream)?;
    if result == WELCOME {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authentication failed",
        ))
    }
}

/// Create an HMAC response to a challenge message.
fn create_response(auth_key: &[u8; 32], message: &[u8]) -> Vec<u8> {
    // Check if message has {sha256} prefix (modern protocol)
    if message.starts_with(b"{sha256}") || message.len() > 20 {
        // Modern protocol: use HMAC-SHA256 with {sha256} prefix
        let digest = hmac_sha256(auth_key, message);
        let mut response = Vec::with_capacity(8 + 32);
        response.extend_from_slice(b"{sha256}");
        response.extend_from_slice(&digest);
        response
    } else {
        // Legacy protocol: raw HMAC-MD5
        let digest = hmac_md5(auth_key, message);
        digest.to_vec()
    }
}

/// Derive the RPC auth key from transport identity private key.
pub fn derive_auth_key(private_key: &[u8]) -> [u8; 32] {
    sha256(private_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_recv_bytes_roundtrip() {
        let (mut c1, mut c2) = tcp_pair();
        let data = b"hello world";
        send_bytes(&mut c1, data).unwrap();
        let received = recv_bytes(&mut c2).unwrap();
        assert_eq!(&received, data);
    }

    #[test]
    fn send_recv_empty() {
        let (mut c1, mut c2) = tcp_pair();
        send_bytes(&mut c1, b"").unwrap();
        let received = recv_bytes(&mut c2).unwrap();
        assert!(received.is_empty());
    }

    #[test]
    fn auth_success() {
        let key = derive_auth_key(b"test-private-key");
        let (mut server, mut client) = tcp_pair();

        let key2 = key;
        let t = thread::spawn(move || {
            client_auth(&mut client, &key2).unwrap();
        });

        server_auth(&mut server, &key).unwrap();
        t.join().unwrap();
    }

    #[test]
    fn auth_failure_wrong_key() {
        let server_key = derive_auth_key(b"server-key");
        let client_key = derive_auth_key(b"wrong-key");
        let (mut server, mut client) = tcp_pair();

        let t = thread::spawn(move || {
            let result = client_auth(&mut client, &client_key);
            assert!(result.is_err());
        });

        let result = server_auth(&mut server, &server_key);
        assert!(result.is_err());
        t.join().unwrap();
    }

    #[test]
    fn verify_sha256_response() {
        let key = derive_auth_key(b"mykey");
        let message = b"{sha256}abcdefghijklmnopqrstuvwxyz0123456789ABCD";
        let response = create_response(&key, message);
        assert!(response.starts_with(b"{sha256}"));
        assert!(verify_response(&key, message, &response));
    }

    #[test]
    fn verify_legacy_md5_response() {
        let key = derive_auth_key(b"mykey");
        // Legacy message: 20 bytes, no prefix
        let message = b"01234567890123456789";
        // Create legacy response (raw HMAC-MD5)
        let digest = hmac_md5(&key, message);
        assert!(verify_response(&key, message, &digest));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    #[test]
    fn rpc_roundtrip() {
        let key = derive_auth_key(b"test-key");
        let (event_tx, event_rx) = crate::event::channel();

        // Start server
        // Bind manually to get the actual port
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown2 = shutdown.clone();

        // Driver thread that handles queries
        let driver_thread = thread::spawn(move || loop {
            match event_rx.recv_timeout(std::time::Duration::from_secs(5)) {
                Ok(Event::Query(QueryRequest::LinkCount, resp_tx)) => {
                    let _ = resp_tx.send(QueryResponse::LinkCount(42));
                }
                Ok(Event::Query(QueryRequest::InterfaceStats, resp_tx)) => {
                    let _ = resp_tx.send(QueryResponse::InterfaceStats(InterfaceStatsResponse {
                        interfaces: vec![SingleInterfaceStat {
                            id: 7,
                            name: "TestInterface".into(),
                            status: true,
                            mode: 1,
                            rxb: 1000,
                            txb: 2000,
                            rx_packets: 10,
                            tx_packets: 20,
                            bitrate: Some(10_000_000),
                            ifac_size: None,
                            started: 1000.0,
                            ia_freq: 0.0,
                            oa_freq: 0.0,
                            interface_type: "TestInterface".into(),
                        }],
                        transport_id: None,
                        transport_enabled: true,
                        transport_uptime: 3600.0,
                        total_rxb: 1000,
                        total_txb: 2000,
                        probe_responder: None,
                    }));
                }
                _ => break,
            }
        });

        let key2 = key;
        let shutdown3 = shutdown2.clone();
        let server_thread = thread::spawn(move || {
            rpc_server_loop(listener, key2, event_tx, shutdown3);
        });

        // Give server time to start
        thread::sleep(std::time::Duration::from_millis(50));

        // Client: connect and query link count
        let server_addr = RpcAddr::Tcp("127.0.0.1".into(), port);
        let mut client = RpcClient::connect(&server_addr, &key).unwrap();
        let response = client
            .call(&PickleValue::Dict(vec![(
                PickleValue::String("get".into()),
                PickleValue::String("link_count".into()),
            )]))
            .unwrap();
        assert_eq!(response.as_int().unwrap(), 42);
        drop(client);

        // Client: query interface stats
        let mut client2 = RpcClient::connect(&server_addr, &key).unwrap();
        let response2 = client2
            .call(&PickleValue::Dict(vec![(
                PickleValue::String("get".into()),
                PickleValue::String("interface_stats".into()),
            )]))
            .unwrap();
        let ifaces = response2.get("interfaces").unwrap().as_list().unwrap();
        assert_eq!(ifaces.len(), 1);
        let iface = &ifaces[0];
        assert_eq!(
            iface.get("name").unwrap().as_str().unwrap(),
            "TestInterface"
        );
        assert_eq!(iface.get("rxb").unwrap().as_int().unwrap(), 1000);
        drop(client2);

        // Shutdown
        shutdown2.store(true, Ordering::Relaxed);
        server_thread.join().unwrap();
        driver_thread.join().unwrap();
    }

    #[test]
    fn derive_auth_key_deterministic() {
        let key1 = derive_auth_key(b"test");
        let key2 = derive_auth_key(b"test");
        assert_eq!(key1, key2);
        // Different input → different key
        let key3 = derive_auth_key(b"other");
        assert_ne!(key1, key3);
    }

    #[test]
    fn pickle_request_handling() {
        // Test the request → query translation without networking
        let (event_tx, event_rx) = crate::event::channel();

        let driver = thread::spawn(move || {
            if let Ok(Event::Query(QueryRequest::DropPath { dest_hash }, resp_tx)) = event_rx.recv()
            {
                assert_eq!(dest_hash, [1u8; 16]);
                let _ = resp_tx.send(QueryResponse::DropPath(true));
            }
        });

        let request = PickleValue::Dict(vec![
            (
                PickleValue::String("drop".into()),
                PickleValue::String("path".into()),
            ),
            (
                PickleValue::String("destination_hash".into()),
                PickleValue::Bytes(vec![1u8; 16]),
            ),
        ]);

        let response = handle_rpc_request(&request, &event_tx).unwrap();
        assert_eq!(response, PickleValue::Bool(true));
        driver.join().unwrap();
    }

    #[test]
    fn hook_list_request_handling() {
        let (event_tx, event_rx) = crate::event::channel();

        let driver = thread::spawn(move || {
            if let Ok(Event::ListHooks { response_tx }) = event_rx.recv() {
                let _ = response_tx.send(vec![HookInfo {
                    name: "stats".into(),
                    attach_point: "PreIngress".into(),
                    priority: 7,
                    enabled: true,
                    consecutive_traps: 0,
                }]);
            }
        });

        let request = PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("hooks".into()),
        )]);
        let response = handle_rpc_request(&request, &event_tx).unwrap();
        let hooks = parse_hook_list(&response).unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].name, "stats");
        driver.join().unwrap();
    }

    #[test]
    fn hook_load_request_handling() {
        let (event_tx, event_rx) = crate::event::channel();

        let driver = thread::spawn(move || {
            if let Ok(Event::LoadHook {
                name,
                wasm_bytes,
                attach_point,
                priority,
                response_tx,
            }) = event_rx.recv()
            {
                assert_eq!(name, "stats");
                assert_eq!(attach_point, "PreIngress");
                assert_eq!(priority, 11);
                assert_eq!(wasm_bytes, vec![1, 2, 3]);
                let _ = response_tx.send(Ok(()));
            }
        });

        let request = PickleValue::Dict(vec![
            (
                PickleValue::String("hook".into()),
                PickleValue::String("load".into()),
            ),
            (
                PickleValue::String("name".into()),
                PickleValue::String("stats".into()),
            ),
            (
                PickleValue::String("attach_point".into()),
                PickleValue::String("PreIngress".into()),
            ),
            (PickleValue::String("priority".into()), PickleValue::Int(11)),
            (
                PickleValue::String("wasm".into()),
                PickleValue::Bytes(vec![1, 2, 3]),
            ),
        ]);
        let response = handle_rpc_request(&request, &event_tx).unwrap();
        assert_eq!(parse_hook_result(&response).unwrap(), Ok(()));
        driver.join().unwrap();
    }

    #[test]
    fn interface_stats_pickle_format() {
        let stats = InterfaceStatsResponse {
            interfaces: vec![SingleInterfaceStat {
                id: 1,
                name: "TCP".into(),
                status: true,
                mode: 1,
                rxb: 100,
                txb: 200,
                rx_packets: 5,
                tx_packets: 10,
                bitrate: Some(1000000),
                ifac_size: Some(16),
                started: 1000.0,
                ia_freq: 0.0,
                oa_freq: 0.0,
                interface_type: "TCPClientInterface".into(),
            }],
            transport_id: Some([0xAB; 16]),
            transport_enabled: true,
            transport_uptime: 3600.0,
            total_rxb: 100,
            total_txb: 200,
            probe_responder: None,
        };

        let pickle = interface_stats_to_pickle(&stats);

        // Verify it round-trips through encode/decode
        let encoded = pickle::encode(&pickle);
        let decoded = pickle::decode(&encoded).unwrap();
        assert_eq!(
            decoded.get("transport_enabled").unwrap().as_bool().unwrap(),
            true
        );
        let ifaces = decoded.get("interfaces").unwrap().as_list().unwrap();
        assert_eq!(ifaces[0].get("id").unwrap().as_int().unwrap(), 1);
        assert_eq!(ifaces[0].get("name").unwrap().as_str().unwrap(), "TCP");
    }

    #[test]
    fn send_probe_rpc_unknown_dest() {
        let (event_tx, event_rx) = crate::event::channel();

        let driver = thread::spawn(move || {
            if let Ok(Event::Query(
                QueryRequest::SendProbe {
                    dest_hash,
                    payload_size,
                },
                resp_tx,
            )) = event_rx.recv()
            {
                assert_eq!(dest_hash, [0xAA; 16]);
                assert_eq!(payload_size, 16); // default
                let _ = resp_tx.send(QueryResponse::SendProbe(None));
            }
        });

        let request = PickleValue::Dict(vec![(
            PickleValue::String("send_probe".into()),
            PickleValue::Bytes(vec![0xAA; 16]),
        )]);

        let response = handle_rpc_request(&request, &event_tx).unwrap();
        assert_eq!(response, PickleValue::None);
        driver.join().unwrap();
    }

    #[test]
    fn send_probe_rpc_with_result() {
        let (event_tx, event_rx) = crate::event::channel();

        let packet_hash = [0xBB; 32];
        let driver = thread::spawn(move || {
            if let Ok(Event::Query(
                QueryRequest::SendProbe {
                    dest_hash,
                    payload_size,
                },
                resp_tx,
            )) = event_rx.recv()
            {
                assert_eq!(dest_hash, [0xCC; 16]);
                assert_eq!(payload_size, 32);
                let _ = resp_tx.send(QueryResponse::SendProbe(Some((packet_hash, 3))));
            }
        });

        let request = PickleValue::Dict(vec![
            (
                PickleValue::String("send_probe".into()),
                PickleValue::Bytes(vec![0xCC; 16]),
            ),
            (PickleValue::String("size".into()), PickleValue::Int(32)),
        ]);

        let response = handle_rpc_request(&request, &event_tx).unwrap();
        let ph = response.get("packet_hash").unwrap().as_bytes().unwrap();
        assert_eq!(ph, &[0xBB; 32]);
        assert_eq!(response.get("hops").unwrap().as_int().unwrap(), 3);
        driver.join().unwrap();
    }

    #[test]
    fn send_probe_rpc_size_validation() {
        let (event_tx, event_rx) = crate::event::channel();

        // Negative size should be clamped to default (16)
        let driver = thread::spawn(move || {
            if let Ok(Event::Query(QueryRequest::SendProbe { payload_size, .. }, resp_tx)) =
                event_rx.recv()
            {
                assert_eq!(payload_size, 16); // default, not negative
                let _ = resp_tx.send(QueryResponse::SendProbe(None));
            }
        });

        let request = PickleValue::Dict(vec![
            (
                PickleValue::String("send_probe".into()),
                PickleValue::Bytes(vec![0xDD; 16]),
            ),
            (PickleValue::String("size".into()), PickleValue::Int(-1)),
        ]);

        let response = handle_rpc_request(&request, &event_tx).unwrap();
        assert_eq!(response, PickleValue::None);
        driver.join().unwrap();
    }

    #[test]
    fn send_probe_rpc_size_too_large() {
        let (event_tx, event_rx) = crate::event::channel();

        // Size > 400 should be clamped to default (16)
        let driver = thread::spawn(move || {
            if let Ok(Event::Query(QueryRequest::SendProbe { payload_size, .. }, resp_tx)) =
                event_rx.recv()
            {
                assert_eq!(payload_size, 16); // default, not 999
                let _ = resp_tx.send(QueryResponse::SendProbe(None));
            }
        });

        let request = PickleValue::Dict(vec![
            (
                PickleValue::String("send_probe".into()),
                PickleValue::Bytes(vec![0xDD; 16]),
            ),
            (PickleValue::String("size".into()), PickleValue::Int(999)),
        ]);

        let response = handle_rpc_request(&request, &event_tx).unwrap();
        assert_eq!(response, PickleValue::None);
        driver.join().unwrap();
    }

    #[test]
    fn check_proof_rpc_not_found() {
        let (event_tx, event_rx) = crate::event::channel();

        let driver = thread::spawn(move || {
            if let Ok(Event::Query(QueryRequest::CheckProof { packet_hash }, resp_tx)) =
                event_rx.recv()
            {
                assert_eq!(packet_hash, [0xEE; 32]);
                let _ = resp_tx.send(QueryResponse::CheckProof(None));
            }
        });

        let request = PickleValue::Dict(vec![(
            PickleValue::String("check_proof".into()),
            PickleValue::Bytes(vec![0xEE; 32]),
        )]);

        let response = handle_rpc_request(&request, &event_tx).unwrap();
        assert_eq!(response, PickleValue::None);
        driver.join().unwrap();
    }

    #[test]
    fn check_proof_rpc_found() {
        let (event_tx, event_rx) = crate::event::channel();

        let driver = thread::spawn(move || {
            if let Ok(Event::Query(QueryRequest::CheckProof { packet_hash }, resp_tx)) =
                event_rx.recv()
            {
                assert_eq!(packet_hash, [0xFF; 32]);
                let _ = resp_tx.send(QueryResponse::CheckProof(Some(0.352)));
            }
        });

        let request = PickleValue::Dict(vec![(
            PickleValue::String("check_proof".into()),
            PickleValue::Bytes(vec![0xFF; 32]),
        )]);

        let response = handle_rpc_request(&request, &event_tx).unwrap();
        if let PickleValue::Float(rtt) = response {
            assert!((rtt - 0.352).abs() < 0.001);
        } else {
            panic!("Expected Float, got {:?}", response);
        }
        driver.join().unwrap();
    }

    #[test]
    fn request_path_rpc() {
        let (event_tx, event_rx) = crate::event::channel();

        let driver =
            thread::spawn(
                move || match event_rx.recv_timeout(std::time::Duration::from_secs(5)) {
                    Ok(Event::RequestPath { dest_hash }) => {
                        assert_eq!(dest_hash, [0x11; 16]);
                    }
                    other => panic!("Expected RequestPath event, got {:?}", other),
                },
            );

        let request = PickleValue::Dict(vec![(
            PickleValue::String("request_path".into()),
            PickleValue::Bytes(vec![0x11; 16]),
        )]);

        let response = handle_rpc_request(&request, &event_tx).unwrap();
        assert_eq!(response, PickleValue::Bool(true));
        driver.join().unwrap();
    }

    #[test]
    fn interface_stats_with_probe_responder() {
        let probe_hash = [0x42; 16];
        let stats = InterfaceStatsResponse {
            interfaces: vec![],
            transport_id: None,
            transport_enabled: true,
            transport_uptime: 100.0,
            total_rxb: 0,
            total_txb: 0,
            probe_responder: Some(probe_hash),
        };

        let pickle = interface_stats_to_pickle(&stats);
        let encoded = pickle::encode(&pickle);
        let decoded = pickle::decode(&encoded).unwrap();

        let pr = decoded.get("probe_responder").unwrap().as_bytes().unwrap();
        assert_eq!(pr, &probe_hash);
    }

    #[test]
    fn runtime_config_get_and_set_rpc() {
        let (event_tx, event_rx) = crate::event::channel();

        let driver = thread::spawn(move || {
            if let Ok(Event::Query(QueryRequest::GetRuntimeConfig { key }, resp_tx)) =
                event_rx.recv()
            {
                assert_eq!(key, "global.tick_interval_ms");
                let _ = resp_tx.send(QueryResponse::RuntimeConfigEntry(Some(
                    RuntimeConfigEntry {
                        key,
                        value: RuntimeConfigValue::Int(1000),
                        default: RuntimeConfigValue::Int(1000),
                        source: RuntimeConfigSource::Startup,
                        apply_mode: RuntimeConfigApplyMode::Immediate,
                        description: Some("tick".into()),
                    },
                )));
            } else {
                panic!("expected GetRuntimeConfig query");
            }

            if let Ok(Event::Query(QueryRequest::SetRuntimeConfig { key, value }, resp_tx)) =
                event_rx.recv()
            {
                assert_eq!(key, "global.tick_interval_ms");
                assert_eq!(value, RuntimeConfigValue::Int(250));
                let _ = resp_tx.send(QueryResponse::RuntimeConfigSet(Ok(RuntimeConfigEntry {
                    key,
                    value: RuntimeConfigValue::Int(250),
                    default: RuntimeConfigValue::Int(1000),
                    source: RuntimeConfigSource::RuntimeOverride,
                    apply_mode: RuntimeConfigApplyMode::Immediate,
                    description: Some("tick".into()),
                })));
            } else {
                panic!("expected SetRuntimeConfig query");
            }
        });

        let get_request = PickleValue::Dict(vec![
            (
                PickleValue::String("get".into()),
                PickleValue::String("runtime_config_entry".into()),
            ),
            (
                PickleValue::String("key".into()),
                PickleValue::String("global.tick_interval_ms".into()),
            ),
        ]);
        let get_response = handle_rpc_request(&get_request, &event_tx).unwrap();
        assert_eq!(
            get_response.get("key").and_then(|v| v.as_str()),
            Some("global.tick_interval_ms")
        );

        let set_request = PickleValue::Dict(vec![
            (
                PickleValue::String("set".into()),
                PickleValue::String("runtime_config".into()),
            ),
            (
                PickleValue::String("key".into()),
                PickleValue::String("global.tick_interval_ms".into()),
            ),
            (PickleValue::String("value".into()), PickleValue::Int(250)),
        ]);
        let set_response = handle_rpc_request(&set_request, &event_tx).unwrap();
        assert_eq!(
            set_response.get("value").and_then(|v| v.as_int()),
            Some(250)
        );

        driver.join().unwrap();
    }

    // Helper: create a connected TCP pair
    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (server, _) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        server
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        (server, client)
    }
}
