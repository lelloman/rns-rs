//! Answering a request by asking the driver.

use super::*;

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

/// Translate an RPC request dict to a query event and get response.
pub(super) fn destination_type_registration(response: QueryResponse) -> PickleValue {
    PickleValue::Bool(matches!(
        response,
        QueryResponse::DestinationTypeRegistration(true)
    ))
}

pub(super) fn handle_rpc_request(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<PickleValue> {
    if let Some(operation) = request.get("manage").and_then(PickleValue::as_str) {
        let operation = match operation {
            "attach_interface" => crate::event::InterfaceManagementOperation::Attach,
            "detach_interface" => crate::event::InterfaceManagementOperation::Detach,
            "reload_interface" => crate::event::InterfaceManagementOperation::Reload,
            _ => return Ok(PickleValue::None),
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
        return Ok(match result {
            QueryResponse::InterfaceManagement(Some(value)) => PickleValue::Bool(value),
            _ => PickleValue::None,
        });
    }
    // Handle "get" requests
    if let Some(get_val) = request.get("get") {
        if let Some(path) = get_val.as_str() {
            return match path {
                "interface_stats" => {
                    let resp = send_query(event_tx, QueryRequest::InterfaceStats)?;
                    if let QueryResponse::InterfaceStats(stats) = resp {
                        let mut response = interface_stats_to_pickle(&stats);
                        add_inbound_runtime_stats(&mut response, &stats, event_tx);
                        Ok(response)
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                "profiling_results" => {
                    Ok(crate::profiling::results_pickle().unwrap_or(PickleValue::None))
                }
                "link_distribution" => {
                    let resp = send_query(event_tx, QueryRequest::LinkDistribution)?;
                    if let QueryResponse::LinkDistribution(entries) = resp {
                        Ok(link_distribution_to_pickle(&entries))
                    } else {
                        Ok(PickleValue::Dict(Vec::new()))
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
                "lowest_interface_bitrate" => {
                    let resp = send_query(event_tx, QueryRequest::LowestInterfaceBitrate)?;
                    if let QueryResponse::LowestInterfaceBitrate(Some(bitrate)) = resp {
                        Ok(PickleValue::Int(bitrate as i64))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                "medium_path_timeout" => {
                    let resp = send_query(event_tx, QueryRequest::MediumPathTimeout)?;
                    if let QueryResponse::MediumPathTimeout(timeout) = resp {
                        Ok(PickleValue::Float(timeout))
                    } else {
                        Ok(PickleValue::Int(0))
                    }
                }
                "first_hop_timeout" => {
                    let hash = extract_dest_hash(request, "destination_hash")?;
                    let resp =
                        send_query(event_tx, QueryRequest::FirstHopTimeout { dest_hash: hash })?;
                    // Without a known bitrate upstream answers the
                    // integer DEFAULT_PER_HOP_TIMEOUT.
                    if let QueryResponse::FirstHopTimeout(timeout) = resp {
                        Ok(python_number(timeout))
                    } else {
                        Ok(PickleValue::Float(
                            rns_core::constants::LINK_ESTABLISHMENT_TIMEOUT_PER_HOP,
                        ))
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
                    // Upstream answers str(next_hop_interface): "None"
                    // when it has none.
                    if let QueryResponse::NextHopIfName(Some(name)) = resp {
                        Ok(PickleValue::String(name))
                    } else {
                        Ok(PickleValue::String("None".into()))
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
                "active_link_count" => {
                    let resp = send_query(event_tx, QueryRequest::ActiveLinkCount)?;
                    if let QueryResponse::ActiveLinkCount(n) = resp {
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
                // Upstream's `get_packet_rssi`, `get_packet_snr` and
                // `get_packet_q`: the reading a packet arrived with, or None.
                "packet_rssi" | "packet_snr" | "packet_q" => {
                    let Some(packet_hash) = request
                        .get("packet_hash")
                        .and_then(|v| v.as_bytes())
                        .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    else {
                        return Ok(PickleValue::None);
                    };
                    let resp = send_query(event_tx, QueryRequest::PacketSignal { packet_hash })?;
                    let QueryResponse::PacketSignal(Some(signal)) = resp else {
                        return Ok(PickleValue::None);
                    };
                    Ok(match path {
                        "packet_rssi" => signal
                            .rssi
                            .map_or(PickleValue::None, |v| PickleValue::Int(i64::from(v))),
                        "packet_snr" => signal
                            .snr
                            .map_or(PickleValue::None, |v| PickleValue::Float(f64::from(v))),
                        _ => signal.q.map_or(PickleValue::None, PickleValue::Float),
                    })
                }
                // Upstream's `get_blackholed_identities`: a dict from identity
                // hash to `{"source", "until", "reason"}`.
                "blackholed_identities" => {
                    let resp = send_query(event_tx, QueryRequest::GetBlackholed)?;
                    if let QueryResponse::Blackholed(entries) = resp {
                        Ok(blackholed_identities_to_pickle(&entries))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                // Upstream's `is_blackholed`.
                "is_blackholed" => {
                    let Some(identity_hash) = request
                        .get("identity_hash")
                        .and_then(|v| v.as_bytes())
                        .and_then(|b| <[u8; 16]>::try_from(b).ok())
                    else {
                        return Ok(PickleValue::Bool(false));
                    };
                    let resp = send_query(event_tx, QueryRequest::GetBlackholed)?;
                    Ok(PickleValue::Bool(matches!(
                        resp,
                        QueryResponse::Blackholed(entries)
                            if entries.iter().any(|e| e.identity_hash == identity_hash)
                    )))
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
                    try_send_event(event_tx, Event::ListHooks { response_tx })?;
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
                "known_destinations" => {
                    let resp = send_query(event_tx, QueryRequest::KnownDestinations)?;
                    if let QueryResponse::KnownDestinations(entries) = resp {
                        Ok(known_destinations_to_pickle(&entries))
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
                "provider_bridge_stats" => {
                    let resp = send_query(event_tx, QueryRequest::ProviderBridgeStats)?;
                    if let QueryResponse::ProviderBridgeStats(stats) = resp {
                        Ok(stats
                            .as_ref()
                            .map(provider_bridge_stats_to_pickle)
                            .unwrap_or(PickleValue::None))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                "drain_status" => {
                    let resp = send_query(event_tx, QueryRequest::DrainStatus)?;
                    if let QueryResponse::DrainStatus(status) = resp {
                        Ok(drain_status_to_pickle(&status))
                    } else {
                        Ok(PickleValue::None)
                    }
                }
                _ => Ok(PickleValue::None),
            };
        }
    }

    if let Some(begin_val) = request.get("begin_drain") {
        let timeout_secs = begin_val
            .as_float()
            .or_else(|| begin_val.as_int().map(|value| value as f64))
            .unwrap_or(0.0)
            .max(0.0);
        let timeout = Duration::from_secs_f64(timeout_secs);
        try_send_event(event_tx, Event::BeginDrain { timeout })?;
        return Ok(PickleValue::Bool(true));
    }

    // Upstream's `destination_data` call: "used", "retain" or "unretain" a
    // known destination, answering whether it was known.
    if let Some(operation) = request.get("destination_data").and_then(|v| v.as_str()) {
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
            _ => return Ok(PickleValue::None),
        };
        return Ok(match resp {
            QueryResponse::MarkKnownDestinationUsed(ok)
            | QueryResponse::RetainKnownDestination(ok)
            | QueryResponse::UnretainKnownDestination(ok) => PickleValue::Bool(ok),
            _ => PickleValue::None,
        });
    }

    // Upstream's `identity_data` call: "retain" every known destination of
    // an identity.
    if let Some(operation) = request.get("identity_data").and_then(|v| v.as_str()) {
        if operation != "retain" {
            return Ok(PickleValue::None);
        }
        let identity_hash = extract_dest_hash(request, "identity_hash")?;
        let resp = send_query(event_tx, QueryRequest::RetainIdentity { identity_hash })?;
        return Ok(match resp {
            QueryResponse::RetainIdentity(ok) => PickleValue::Bool(ok),
            _ => PickleValue::None,
        });
    }

    if let Some(set_val) = request.get("set").and_then(|v| v.as_str()) {
        if set_val == "known_destination_retained" {
            let dest_hash = extract_dest_hash(request, "dest_hash")?;
            let resp = send_query(event_tx, QueryRequest::RetainKnownDestination { dest_hash })?;
            return if let QueryResponse::RetainKnownDestination(ok) = resp {
                Ok(PickleValue::Bool(ok))
            } else {
                Ok(PickleValue::None)
            };
        }
        if set_val == "identity_retained" {
            let identity_hash = extract_dest_hash(request, "identity_hash")?;
            let resp = send_query(event_tx, QueryRequest::RetainIdentity { identity_hash })?;
            return if let QueryResponse::RetainIdentity(ok) = resp {
                Ok(PickleValue::Bool(ok))
            } else {
                Ok(PickleValue::None)
            };
        }
        if set_val == "known_destination_used" {
            let dest_hash = extract_dest_hash(request, "dest_hash")?;
            let resp = send_query(
                event_tx,
                QueryRequest::MarkKnownDestinationUsed { dest_hash },
            )?;
            return if let QueryResponse::MarkKnownDestinationUsed(ok) = resp {
                Ok(PickleValue::Bool(ok))
            } else {
                Ok(PickleValue::None)
            };
        }
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
        if clear_val == "known_destination_retained" {
            let dest_hash = extract_dest_hash(request, "dest_hash")?;
            let resp = send_query(
                event_tx,
                QueryRequest::UnretainKnownDestination { dest_hash },
            )?;
            return if let QueryResponse::UnretainKnownDestination(ok) = resp {
                Ok(PickleValue::Bool(ok))
            } else {
                Ok(PickleValue::None)
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
                try_send_event(event_tx, crate::event::Event::RequestPath { dest_hash })?;
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
                // Missing or non-positive sizes fall back to the default;
                // oversize requests are rejected rather than silently
                // replaced, so the caller learns the real limit.
                let payload_size = match request.get("size").and_then(|v| v.as_int()) {
                    Some(n) if n > 0 => usize::try_from(n).unwrap_or(usize::MAX),
                    _ => DEFAULT_PROBE_PAYLOAD_SIZE,
                };
                if payload_size > crate::event::MAX_PROBE_PAYLOAD_SIZE {
                    return Ok(send_probe_error_pickle(
                        crate::event::SendProbeError::PayloadTooLarge {
                            max: crate::event::MAX_PROBE_PAYLOAD_SIZE,
                        },
                    ));
                }
                let resp = send_query(
                    event_tx,
                    QueryRequest::SendProbe {
                        dest_hash,
                        payload_size,
                    },
                )?;
                return Ok(match resp {
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
                });
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

    // Upstream's `blackhole_identity`: `until` is an absolute time or nil,
    // and the answer is True when added, None when the identity already is
    // blackholed, False for an invalid hash.
    if let Some(hash_val) = request.get("blackhole_identity") {
        let Some(identity_hash) = hash_val
            .as_bytes()
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
        else {
            return Ok(PickleValue::Bool(false));
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
        return Ok(match resp {
            QueryResponse::BlackholeResult(true) => PickleValue::Bool(true),
            _ => PickleValue::None,
        });
    }

    // Upstream's `unblackhole_identity`: True when lifted, None when the
    // identity was not blackholed, False for an invalid hash.
    if let Some(hash_val) = request.get("unblackhole_identity") {
        let Some(identity_hash) = hash_val
            .as_bytes()
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
        else {
            return Ok(PickleValue::Bool(false));
        };
        let resp = send_query(
            event_tx,
            QueryRequest::UnblackholeIdentity { identity_hash },
        )?;
        return Ok(match resp {
            QueryResponse::UnblackholeResult(true) => PickleValue::Bool(true),
            _ => PickleValue::None,
        });
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

    // Destination type requirements of local applications (upstream
    // 825c2e19). Upstream does not validate the signature yet, so it is
    // ignored here too.
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
        return Ok(destination_type_registration(resp));
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
        return Ok(destination_type_registration(resp));
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
        return Ok(destination_type_registration(resp));
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
                    // Upstream's drop_announce_queues returns None.
                    if let QueryResponse::DropAnnounceQueues = resp {
                        Ok(PickleValue::None)
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
