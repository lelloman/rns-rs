//! Answering a request by asking the driver.

use super::*;

mod get;

/// Default probe payload size when the request omits `size`.
pub(super) const DEFAULT_PROBE_PAYLOAD_SIZE: usize = 16;

/// Encode a failed `send_probe` for RPC clients.
///
/// `UnknownIdentity` stays `None` for compatibility with older clients. Other
/// failures return `{"error": <code>, ...}` so clients can tell them apart.
pub(super) fn send_probe_error_pickle(err: crate::event::SendProbeError) -> PickleValue {
    use crate::event::SendProbeError;
    let code = match err {
        SendProbeError::UnknownIdentity => return PickleValue::None,
        SendProbeError::PayloadTooLarge { .. } => "payload_too_large",
        SendProbeError::EncryptFailed => "encrypt_failed",
        SendProbeError::PackFailed => "pack_failed",
    };
    let mut entries = vec![(
        PickleValue::String("error".into()),
        PickleValue::String(code.into()),
    )];
    if let SendProbeError::PayloadTooLarge { max } = err {
        entries.push((
            PickleValue::String("max_size".into()),
            PickleValue::Int(max as i64),
        ));
    }
    PickleValue::Dict(entries)
}

/// The answer to a destination type registration: whether it was accepted.
pub(super) fn destination_type_registration(response: QueryResponse) -> PickleValue {
    PickleValue::Bool(matches!(
        response,
        QueryResponse::DestinationTypeRegistration(true)
    ))
}

/// A handler for one kind of RPC request: `None` when the request is not
/// of its kind, so the next handler gets to look at it.
type RpcHandler = fn(&PickleValue, &mut dyn RpcDriver) -> io::Result<Option<PickleValue>>;

/// The request handlers in the order they are tried.
const RPC_HANDLERS: &[RpcHandler] = &[
    handle_manage_request,
    handle_get,
    handle_begin_drain,
    handle_destination_data,
    handle_identity_data,
    handle_set_request,
    handle_reset_request,
    handle_clear_request,
    handle_set_backbone_peer_blacklist,
    handle_request_path,
    handle_send_probe,
    handle_check_proof,
    handle_blackhole_identity,
    handle_unblackhole_identity,
    handle_blackhole,
    handle_destination_type_wants,
    handle_unblackhole,
    handle_drop,
    handle_hook,
];

/// Translate an RPC request dict to a query event and get response.
pub(super) fn handle_rpc_request(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<PickleValue> {
    for handler in RPC_HANDLERS {
        if let Some(response) = handler(request, event_tx)? {
            return Ok(response);
        }
    }
    Ok(PickleValue::None)
}

/// `{"manage": <operation>, "name": ...}`: attach, detach or reload an
/// interface.
fn handle_manage_request(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
    let Some(operation) = request.get("manage").and_then(PickleValue::as_str) else {
        return Ok(None);
    };
    let operation = match operation {
        "attach_interface" => crate::event::InterfaceManagementOperation::Attach,
        "detach_interface" => crate::event::InterfaceManagementOperation::Detach,
        "reload_interface" => crate::event::InterfaceManagementOperation::Reload,
        _ => return Ok(Some(PickleValue::None)),
    };
    let name = request
        .get("name")
        .and_then(PickleValue::as_str)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing interface name"))?;
    let result = send_query(
        event_tx,
        QueryRequest::ManageInterface {
            operation,
            name: name.to_string(),
        },
    )?;
    Ok(Some(match result {
        QueryResponse::InterfaceManagement(Some(value)) => PickleValue::Bool(value),
        _ => PickleValue::None,
    }))
}

/// `{"get": <path>, ...}`, answered by [`get::handle_get_request`].
fn handle_get(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
    match request.get("get").and_then(|v| v.as_str()) {
        Some(path) => get::handle_get_request(path, request, event_tx).map(Some),
        None => Ok(None),
    }
}

/// `{"begin_drain": <timeout secs>}`: start draining.
fn handle_begin_drain(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
    let Some(begin_val) = request.get("begin_drain") else {
        return Ok(None);
    };
    let timeout_secs = begin_val
        .as_float()
        .or_else(|| begin_val.as_int().map(|value| value as f64))
        .unwrap_or(0.0)
        .max(0.0);
    let timeout = Duration::from_secs_f64(timeout_secs);
    try_send_event(event_tx, Event::BeginDrain { timeout })?;
    Ok(Some(PickleValue::Bool(true)))
}

/// Upstream's `destination_data` call: "used", "retain" or "unretain" a
/// known destination, answering whether it was known.
fn handle_destination_data(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
    let Some(operation) = request.get("destination_data").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    let dest_hash = extract_dest_hash(request, "destination_hash")?;
    let resp = match operation {
        "used" => send_query(
            event_tx,
            QueryRequest::MarkKnownDestinationUsed { dest_hash },
        )?,
        "retain" => send_query(event_tx, QueryRequest::RetainKnownDestination { dest_hash })?,
        "unretain" => send_query(
            event_tx,
            QueryRequest::UnretainKnownDestination { dest_hash },
        )?,
        _ => return Ok(Some(PickleValue::None)),
    };
    Ok(Some(match resp {
        QueryResponse::MarkKnownDestinationUsed(ok)
        | QueryResponse::RetainKnownDestination(ok)
        | QueryResponse::UnretainKnownDestination(ok) => PickleValue::Bool(ok),
        _ => PickleValue::None,
    }))
}

/// Upstream's `identity_data` call: "retain" every known destination of
/// an identity.
fn handle_identity_data(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
    let Some(operation) = request.get("identity_data").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    if operation != "retain" {
        return Ok(Some(PickleValue::None));
    }
    let identity_hash = extract_dest_hash(request, "identity_hash")?;
    let resp = send_query(event_tx, QueryRequest::RetainIdentity { identity_hash })?;
    Ok(Some(match resp {
        QueryResponse::RetainIdentity(ok) => PickleValue::Bool(ok),
        _ => PickleValue::None,
    }))
}

/// `{"set": ...}` for known destinations, identities and runtime config.
/// The backbone peer blacklist is set by
/// [`handle_set_backbone_peer_blacklist`], tried later.
fn handle_set_request(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
    let Some(set_val) = request.get("set").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    if set_val == "known_destination_retained" {
        let dest_hash = extract_dest_hash(request, "dest_hash")?;
        let resp = send_query(event_tx, QueryRequest::RetainKnownDestination { dest_hash })?;
        return if let QueryResponse::RetainKnownDestination(ok) = resp {
            Ok(Some(PickleValue::Bool(ok)))
        } else {
            Ok(Some(PickleValue::None))
        };
    }
    if set_val == "identity_retained" {
        let identity_hash = extract_dest_hash(request, "identity_hash")?;
        let resp = send_query(event_tx, QueryRequest::RetainIdentity { identity_hash })?;
        return if let QueryResponse::RetainIdentity(ok) = resp {
            Ok(Some(PickleValue::Bool(ok)))
        } else {
            Ok(Some(PickleValue::None))
        };
    }
    if set_val == "known_destination_used" {
        let dest_hash = extract_dest_hash(request, "dest_hash")?;
        let resp = send_query(
            event_tx,
            QueryRequest::MarkKnownDestinationUsed { dest_hash },
        )?;
        return if let QueryResponse::MarkKnownDestinationUsed(ok) = resp {
            Ok(Some(PickleValue::Bool(ok)))
        } else {
            Ok(Some(PickleValue::None))
        };
    }
    if set_val == "runtime_config" {
        return set_runtime_config(request, event_tx).map(Some);
    }
    Ok(None)
}

/// `{"set": "runtime_config", "key": ..., "value": ...}`.
fn set_runtime_config(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<PickleValue> {
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
    if let QueryResponse::RuntimeConfigSet(result) = resp {
        Ok(runtime_config_result_to_pickle(result))
    } else {
        Ok(PickleValue::None)
    }
}

/// `{"reset": "runtime_config", "key": ...}`.
fn handle_reset_request(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
    if request.get("reset").and_then(|v| v.as_str()) != Some("runtime_config") {
        return Ok(None);
    }
    let key = request
        .get("key")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let resp = send_query(event_tx, QueryRequest::ResetRuntimeConfig { key })?;
    if let QueryResponse::RuntimeConfigReset(result) = resp {
        Ok(Some(runtime_config_result_to_pickle(result)))
    } else {
        Ok(Some(PickleValue::None))
    }
}

/// `{"clear": ...}` for a retained known destination or a backbone peer's
/// state.
fn handle_clear_request(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
    let Some(clear_val) = request.get("clear").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    if clear_val == "known_destination_retained" {
        let dest_hash = extract_dest_hash(request, "dest_hash")?;
        let resp = send_query(
            event_tx,
            QueryRequest::UnretainKnownDestination { dest_hash },
        )?;
        return if let QueryResponse::UnretainKnownDestination(ok) = resp {
            Ok(Some(PickleValue::Bool(ok)))
        } else {
            Ok(Some(PickleValue::None))
        };
    }
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
            Ok(Some(PickleValue::Bool(ok)))
        } else {
            Ok(Some(PickleValue::None))
        };
    }
    Ok(None)
}

/// `{"set": "backbone_peer_blacklist", ...}`: blacklist a backbone peer.
fn handle_set_backbone_peer_blacklist(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
    if request.get("set").and_then(|v| v.as_str()) != Some("backbone_peer_blacklist") {
        return Ok(None);
    }
    let interface_name = required_string(request, "interface")?;
    let peer_ip = required_string(request, "ip")?;
    let peer_ip: IpAddr = peer_ip
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid peer IP"))?;
    let duration_secs = request
        .get("duration_secs")
        .and_then(|v| v.as_int())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing duration_secs"))?;
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
    if let QueryResponse::BlacklistBackbonePeer(ok) = resp {
        Ok(Some(PickleValue::Bool(ok)))
    } else {
        Ok(Some(PickleValue::None))
    }
}

/// `{"request_path": <dest hash>}`: trigger a path request to the network.
fn handle_request_path(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
    if let Some(hash_val) = request.get("request_path") {
        if let Some(hash_bytes) = hash_val.as_bytes() {
            if hash_bytes.len() >= 16 {
                let mut dest_hash = [0u8; 16];
                dest_hash.copy_from_slice(&hash_bytes[..16]);
                try_send_event(event_tx, crate::event::Event::RequestPath { dest_hash })?;
                return Ok(Some(PickleValue::Bool(true)));
            }
        }
    }
    Ok(None)
}

/// `{"send_probe": <dest hash>, "size": ...}`: send a probe packet.
fn handle_send_probe(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
    let Some(hash_bytes) = request.get("send_probe").and_then(|v| v.as_bytes()) else {
        return Ok(None);
    };
    if hash_bytes.len() < 16 {
        return Ok(None);
    }
    let mut dest_hash = [0u8; 16];
    dest_hash.copy_from_slice(&hash_bytes[..16]);
    // Missing or non-positive sizes fall back to the default;
    // oversize requests are rejected rather than silently
    // replaced, so the caller learns the real limit.
    let payload_size = match request.get("size").and_then(|v| v.as_int()) {
        Some(n) if n > 0 => usize::try_from(n).unwrap_or(usize::MAX),
        _ => DEFAULT_PROBE_PAYLOAD_SIZE,
    };
    if payload_size > crate::event::MAX_PROBE_PAYLOAD_SIZE {
        return Ok(Some(send_probe_error_pickle(
            crate::event::SendProbeError::PayloadTooLarge {
                max: crate::event::MAX_PROBE_PAYLOAD_SIZE,
            },
        )));
    }
    let resp = send_query(
        event_tx,
        QueryRequest::SendProbe {
            dest_hash,
            payload_size,
        },
    )?;
    Ok(Some(match resp {
        QueryResponse::SendProbe(Ok((packet_hash, hops))) => PickleValue::Dict(vec![
            (
                PickleValue::String("packet_hash".into()),
                PickleValue::Bytes(packet_hash.to_vec()),
            ),
            (
                PickleValue::String("hops".into()),
                PickleValue::Int(hops as i64),
            ),
        ]),
        QueryResponse::SendProbe(Err(err)) => send_probe_error_pickle(err),
        _ => PickleValue::None,
    }))
}

/// `{"check_proof": <packet hash>}`: the round-trip time of a proved
/// packet, or None.
fn handle_check_proof(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
    if let Some(hash_val) = request.get("check_proof") {
        if let Some(hash_bytes) = hash_val.as_bytes() {
            if hash_bytes.len() >= 32 {
                let mut packet_hash = [0u8; 32];
                packet_hash.copy_from_slice(&hash_bytes[..32]);
                let resp = send_query(event_tx, QueryRequest::CheckProof { packet_hash })?;
                if let QueryResponse::CheckProof(Some(rtt)) = resp {
                    return Ok(Some(PickleValue::Float(rtt)));
                } else {
                    return Ok(Some(PickleValue::None));
                }
            }
        }
    }
    Ok(None)
}

/// Upstream's `blackhole_identity`: `until` is an absolute time or nil,
/// and the answer is True when added, None when the identity already is
/// blackholed, False for an invalid hash.
fn handle_blackhole_identity(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
    let Some(hash_val) = request.get("blackhole_identity") else {
        return Ok(None);
    };
    let Some(identity_hash) = hash_val
        .as_bytes()
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
    else {
        return Ok(Some(PickleValue::Bool(false)));
    };
    let duration_hours = request
        .get("until")
        .and_then(|v| v.as_float().or_else(|| v.as_int().map(|i| i as f64)))
        .map(|until| ((until - crate::time::now()) / 3600.0).max(f64::MIN_POSITIVE));
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
    Ok(Some(match resp {
        QueryResponse::BlackholeResult(true) => PickleValue::Bool(true),
        _ => PickleValue::None,
    }))
}

/// Upstream's `unblackhole_identity`: True when lifted, None when the
/// identity was not blackholed, False for an invalid hash.
fn handle_unblackhole_identity(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
    let Some(hash_val) = request.get("unblackhole_identity") else {
        return Ok(None);
    };
    let Some(identity_hash) = hash_val
        .as_bytes()
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
    else {
        return Ok(Some(PickleValue::Bool(false)));
    };
    let resp = send_query(
        event_tx,
        QueryRequest::UnblackholeIdentity { identity_hash },
    )?;
    Ok(Some(match resp {
        QueryResponse::UnblackholeResult(true) => PickleValue::Bool(true),
        _ => PickleValue::None,
    }))
}

/// `{"blackhole": <identity hash>, "duration": <hours>, "reason": ...}`.
fn handle_blackhole(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
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
                return Ok(Some(PickleValue::Bool(matches!(
                    resp,
                    QueryResponse::BlackholeResult(true)
                ))));
            }
        }
    }
    Ok(None)
}

/// Destination type requirements of local applications (upstream
/// 825c2e19). Upstream does not validate the signature yet, so it is
/// ignored here too.
fn handle_destination_type_wants(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
    if let (Some(full_name), Some(requester)) = (
        request
            .get("wants_destination_type")
            .and_then(|v| v.as_str()),
        request.get("requester").and_then(|v| v.as_bytes()),
    ) {
        let resp = send_query(
            event_tx,
            QueryRequest::WantsDestinationType {
                full_name: full_name.to_string(),
                requester: requester.to_vec(),
            },
        )?;
        return Ok(Some(destination_type_registration(resp)));
    }
    if let (Some(full_name), Some(requester)) = (
        request
            .get("unwants_destination_type")
            .and_then(|v| v.as_str()),
        request.get("requester").and_then(|v| v.as_bytes()),
    ) {
        let resp = send_query(
            event_tx,
            QueryRequest::UnwantsDestinationType {
                full_name: full_name.to_string(),
                requester: requester.to_vec(),
            },
        )?;
        return Ok(Some(destination_type_registration(resp)));
    }
    if let (Some(_), Some(requester)) = (
        request.get("unwants_all_destination_types"),
        request.get("requester").and_then(|v| v.as_bytes()),
    ) {
        let resp = send_query(
            event_tx,
            QueryRequest::UnwantsAllDestinationTypes {
                requester: requester.to_vec(),
            },
        )?;
        return Ok(Some(destination_type_registration(resp)));
    }
    Ok(None)
}

/// `{"unblackhole": <identity hash>}`.
fn handle_unblackhole(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
    if let Some(hash_val) = request.get("unblackhole") {
        if let Some(hash_bytes) = hash_val.as_bytes() {
            if hash_bytes.len() >= 16 {
                let mut identity_hash = [0u8; 16];
                identity_hash.copy_from_slice(&hash_bytes[..16]);
                let resp = send_query(
                    event_tx,
                    QueryRequest::UnblackholeIdentity { identity_hash },
                )?;
                return Ok(Some(PickleValue::Bool(matches!(
                    resp,
                    QueryResponse::UnblackholeResult(true)
                ))));
            }
        }
    }
    Ok(None)
}

/// `{"drop": <what>, ...}`: drop a path, every path via a transport, or the
/// announce queues.
fn handle_drop(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
    let Some(path) = request.get("drop").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    let response = match path {
        "path" => {
            let hash = extract_dest_hash(request, "destination_hash")?;
            let resp = send_query(event_tx, QueryRequest::DropPath { dest_hash: hash })?;
            if let QueryResponse::DropPath(ok) = resp {
                PickleValue::Bool(ok)
            } else {
                PickleValue::None
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
                PickleValue::Int(n as i64)
            } else {
                PickleValue::None
            }
        }
        "announce_queues" => {
            send_query(event_tx, QueryRequest::DropAnnounceQueues)?;
            // Upstream's drop_announce_queues returns None.
            PickleValue::None
        }
        _ => PickleValue::None,
    };
    Ok(Some(response))
}

/// `{"hook": <op>, ...}`, answered by [`handle_hook_rpc_request`].
fn handle_hook(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<Option<PickleValue>> {
    match request.get("hook").and_then(|v| v.as_str()) {
        Some(hook_val) => handle_hook_rpc_request(hook_val, request, event_tx).map(Some),
        None => Ok(None),
    }
}

pub(super) fn handle_hook_rpc_request(
    op: &str,
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
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
            try_send_event(
                event_tx,
                Event::LoadHook {
                    name,
                    wasm_bytes: wasm,
                    attach_point,
                    priority,
                    response_tx,
                },
            )?;
            let response = response_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "hook load timed out"))?;
            Ok(hook_result_to_pickle(response))
        }
        "load_builtin" => {
            let name = required_string(request, "name")?;
            let attach_point = required_string(request, "attach_point")?;
            let builtin_id = required_string(request, "builtin_id")?;
            let priority = request
                .get("priority")
                .and_then(|v| v.as_int())
                .unwrap_or(0) as i32;
            let (response_tx, response_rx) = mpsc::channel();
            try_send_event(
                event_tx,
                Event::LoadBuiltinHook {
                    name,
                    builtin_id,
                    attach_point,
                    priority,
                    response_tx,
                },
            )?;
            let response = response_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "built-in hook load timed out")
                })?;
            Ok(hook_result_to_pickle(response))
        }
        "unload" => {
            let name = required_string(request, "name")?;
            let attach_point = required_string(request, "attach_point")?;
            let (response_tx, response_rx) = mpsc::channel();
            try_send_event(
                event_tx,
                Event::UnloadHook {
                    name,
                    attach_point,
                    response_tx,
                },
            )?;
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
            try_send_event(
                event_tx,
                Event::SetHookEnabled {
                    name,
                    attach_point,
                    enabled,
                    response_tx,
                },
            )?;
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
            try_send_event(
                event_tx,
                Event::SetHookPriority {
                    name,
                    attach_point,
                    priority,
                    response_tx,
                },
            )?;
            let response = response_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "hook priority timed out"))?;
            Ok(hook_result_to_pickle(response))
        }
        _ => Ok(PickleValue::None),
    }
}

/// What answers an RPC request: the driver, reached through its event queue
/// from a server thread, or the compact engine's driver itself, which
/// serves its RPC connections on its own loop.
pub(crate) trait RpcDriver {
    /// The driver's answer to `request`.
    fn query(&mut self, request: QueryRequest) -> io::Result<QueryResponse>;
    /// Hand the driver `event`. An event carrying a response channel has
    /// been handled, and its response sent, by the time the driver itself
    /// returns from this.
    fn send(&mut self, event: Event) -> io::Result<()>;
    fn inbound_queue_snapshot(&self) -> crate::event::InboundQueueSnapshot;
    fn dynamic_burst_stats(&self, parent: InterfaceId) -> Option<DynamicBurstStats>;
}

impl RpcDriver for EventSender {
    /// Send a query to the driver and wait for the response.
    fn query(&mut self, request: QueryRequest) -> io::Result<QueryResponse> {
        let (resp_tx, resp_rx) = mpsc::channel();
        self.send(Event::query(request, resp_tx))?;
        resp_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "query timed out"))
    }

    fn send(&mut self, event: Event) -> io::Result<()> {
        send_to_driver(self, event)
    }

    fn inbound_queue_snapshot(&self) -> crate::event::InboundQueueSnapshot {
        EventSender::inbound_queue_snapshot(self)
    }

    fn dynamic_burst_stats(&self, parent: InterfaceId) -> Option<DynamicBurstStats> {
        EventSender::dynamic_burst_stats(self, parent)
    }
}

pub(super) fn send_query(
    event_tx: &mut dyn RpcDriver,
    request: QueryRequest,
) -> io::Result<QueryResponse> {
    event_tx.query(request)
}

pub(super) fn try_send_event(event_tx: &mut dyn RpcDriver, event: Event) -> io::Result<()> {
    event_tx.send(event)
}

pub(crate) fn send_to_driver(event_tx: &EventSender, event: Event) -> io::Result<()> {
    event_tx.try_send(event).map_err(|error| match error {
        mpsc::TrySendError::Full(_) => {
            io::Error::new(io::ErrorKind::WouldBlock, "driver event queue is full")
        }
        mpsc::TrySendError::Disconnected(_) => {
            io::Error::new(io::ErrorKind::BrokenPipe, "driver shut down")
        }
    })
}

/// Extract a 16-byte destination hash from an RPC dict field.
pub(super) fn extract_dest_hash(request: &PickleValue, key: &str) -> io::Result<[u8; 16]> {
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

pub(super) fn required_string(request: &PickleValue, key: &str) -> io::Result<String> {
    request
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("missing {}", key)))
}

pub(super) fn hook_result_to_pickle(result: Result<(), crate::event::HookOpError>) -> PickleValue {
    match result {
        Ok(()) => PickleValue::Dict(vec![(
            PickleValue::String("ok".into()),
            PickleValue::Bool(true),
        )]),
        Err(error) => PickleValue::Dict(vec![
            (PickleValue::String("ok".into()), PickleValue::Bool(false)),
            (
                PickleValue::String("error".into()),
                PickleValue::String(error.to_string()),
            ),
        ]),
    }
}
