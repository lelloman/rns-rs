//! What the node knows of the network: interfaces, destinations, paths,
//! links, resources and backbone peers.

use super::*;

pub(super) fn handle_interfaces(node: &NodeHandle) -> HttpResponse {
    with_node(node, |n| match n.query(QueryRequest::InterfaceStats) {
        Ok(QueryResponse::InterfaceStats(stats)) => {
            let ifaces: Vec<Value> = stats
                .interfaces
                .iter()
                .map(|i| {
                    json!({
                        "id": i.id,
                        "name": i.name,
                        "status": if i.status { "up" } else { "down" },
                        "mode": i.mode,
                        "interface_type": i.interface_type,
                        "rxb": i.rxb,
                        "txb": i.txb,
                        "rx_packets": i.rx_packets,
                        "tx_packets": i.tx_packets,
                        "stamped_path_requests": i.stamped_path_requests,
                        "cpu_load": i.cpu_load,
                        "mem_load": i.mem_load,
                        "switch_id": i.switch_id.map(|value| to_hex(&value)),
                        "endpoint_id": i.endpoint_id.map(|value| to_hex(&value)),
                        "via_switch_id": i.via_switch_id.map(|value| to_hex(&value)),
                        "peers": i.peers,
                        "rssi": i.rssi,
                        "snr": i.snr,
                        "signal_quality": i.signal_quality,
                        "frequency": i.frequency,
                        "bandwidth": i.bandwidth,
                        "txpower": i.txpower,
                        "sf": i.spreading_factor,
                        "cr": i.coding_rate,
                        "channel": i.channel,
                        "modulation": i.modulation,
                        "bitrate": i.bitrate,
                        "started": i.started,
                        "ia_freq": i.ia_freq,
                        "oa_freq": i.oa_freq,
                    })
                })
                .collect();
            let backbone_peer_pool = stats.backbone_peer_pool.as_ref().map(|pool| {
                json!({
                    "max_connected": pool.max_connected,
                    "active_count": pool.active_count,
                    "standby_count": pool.standby_count,
                    "cooldown_count": pool.cooldown_count,
                    "members": pool.members.iter().map(|member| {
                        json!({
                            "name": member.name,
                            "remote": member.remote,
                            "source": member.source,
                            "priority": member.priority,
                            "state": member.state,
                            "interface_id": member.interface_id,
                            "failure_count": member.failure_count,
                            "last_error": member.last_error,
                            "cooldown_remaining_seconds": member.cooldown_remaining_seconds,
                        })
                    }).collect::<Vec<_>>(),
                })
            });
            HttpResponse::ok(json!({
                "interfaces": ifaces,
                "transport_enabled": stats.transport_enabled,
                "transport_uptime": stats.transport_uptime,
                "total_rxb": stats.total_rxb,
                "total_txb": stats.total_txb,
                "backbone_peer_pool": backbone_peer_pool,
            }))
        }
        _ => HttpResponse::internal_error("Query failed"),
    })
}

pub(super) fn handle_destinations(node: &NodeHandle, state: &SharedState) -> HttpResponse {
    with_node(node, |n| match n.query(QueryRequest::LocalDestinations) {
        Ok(QueryResponse::LocalDestinations(dests)) => {
            let s = read_state(state);
            let list: Vec<Value> = dests
                .iter()
                .map(|d| {
                    let name = s
                        .destinations
                        .get(&d.hash)
                        .map(|e| e.full_name.as_str())
                        .unwrap_or("");
                    json!({
                        "hash": to_hex(&d.hash),
                        "type": d.dest_type,
                        "name": name,
                    })
                })
                .collect();
            HttpResponse::ok(json!({"destinations": list}))
        }
        _ => HttpResponse::internal_error("Query failed"),
    })
}

pub(super) fn handle_paths(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let params = parse_query(&req.query);
    let filter_hash: Option<[u8; 16]> = params.get("dest_hash").and_then(|s| hex_to_array(s));

    with_node(node, |n| {
        match n.query(QueryRequest::PathTable { max_hops: None }) {
            Ok(QueryResponse::PathTable(paths)) => {
                let list: Vec<Value> = paths
                    .iter()
                    .filter(|p| filter_hash.is_none_or(|h| p.hash == h))
                    .map(|p| {
                        json!({
                            "hash": to_hex(&p.hash),
                            "via": to_hex(&p.via),
                            "hops": p.hops,
                            "expires": p.expires,
                            "used": p.used,
                            "interface": p.interface_name,
                            "timestamp": p.timestamp,
                            "value": p.stamp_value.map(|v| v.as_f64()),
                            "lr_cost": p.lr_cost.map(|c| c.as_f64()),
                        })
                    })
                    .collect();
                HttpResponse::ok(json!({"paths": list}))
            }
            _ => HttpResponse::internal_error("Query failed"),
        }
    })
}

pub(super) fn direct_counters_json(counters: &rns_net::event::DirectLinkCounters) -> Value {
    let failed: serde_json::Map<String, Value> = counters
        .failed
        .iter()
        .map(|(reason, count)| {
            (
                rns_net::event::direct_link_reason_name(*reason).to_string(),
                json!(count),
            )
        })
        .collect();
    json!({
        "proposed": counters.proposed,
        "accepted": counters.accepted,
        "established": counters.established,
        "failed": counters.failed_total(),
        "failed_by_reason": failed,
        "lost": counters.lost,
    })
}

pub(super) fn handle_direct_links(node: &NodeHandle) -> HttpResponse {
    with_node(node, |n| match n.query(QueryRequest::DirectLinks) {
        Ok(QueryResponse::DirectLinks(status)) => {
            let links: Vec<Value> = status
                .links
                .iter()
                .map(|l| {
                    let direct = l.direct.as_ref().map(|d| {
                        json!({
                            "interface_id": d.interface_id.0,
                            "session_id": to_hex(&d.session_id),
                            "initiator": d.initiator,
                            "peer_addr": d.peer_addr.to_string(),
                            "candidate": d.candidate.as_str(),
                            "candidates": d
                                .candidates
                                .iter()
                                .map(|(addr, kind)| json!({
                                    "addr": addr.to_string(),
                                    "type": kind.as_str(),
                                }))
                                .collect::<Vec<_>>(),
                            "rtt": d.rtt,
                            "mtu": d.mtu,
                            "mtu_discovered": d.mtu_discovered,
                            "peer_max_packet": d.peer_max_packet,
                            "since": d.since,
                        })
                    });
                    json!({
                        "link_id": to_hex(&l.link_id),
                        "path": if l.direct.is_some() { "direct" } else { "transport" },
                        "direct": direct,
                        "session_state": l.session_state,
                        "peer_supported": l.peer_supported,
                        "counters": direct_counters_json(&l.counters),
                        "last_failure": l.last_failure.map(|(reason, at)| json!({
                            "reason_code": reason,
                            "reason": rns_net::event::direct_link_reason_name(reason),
                            "at": at,
                        })),
                        "last_loss": l.last_loss.map(|(cause, at)| json!({
                            "cause": cause.as_str(),
                            "at": at,
                        })),
                        "reupgrade": l.reupgrade.map(|(attempts, next_at)| json!({
                            "attempts": attempts,
                            "next_at": next_at,
                        })),
                    })
                })
                .collect();
            HttpResponse::ok(json!({
                "enabled": status.enabled,
                "probe_servers": status
                    .probe_servers
                    .iter()
                    .map(|addr| addr.to_string())
                    .collect::<Vec<_>>(),
                "probe_server": status.probe_server.map(|report| json!({
                    "answered": report.answered,
                    "rate_limited": report.rate_limited,
                })),
                "totals": direct_counters_json(&status.totals),
                "links": links,
            }))
        }
        _ => HttpResponse::internal_error("Query failed"),
    })
}

pub(super) fn handle_links(node: &NodeHandle) -> HttpResponse {
    with_node(node, |n| match n.query(QueryRequest::Links) {
        Ok(QueryResponse::Links(links)) => {
            let list: Vec<Value> = links
                .iter()
                .map(|l| {
                    json!({
                        "link_id": to_hex(&l.link_id),
                        "state": l.state,
                        "is_initiator": l.is_initiator,
                        "dest_hash": to_hex(&l.dest_hash),
                        "remote_identity": l.remote_identity.map(|h| to_hex(&h)),
                        "rtt": l.rtt,
                        "expected_hops": l.expected_hops,
                        "mdu": l.mdu,
                        "tx_packets": l.tx_packets,
                        "rx_packets": l.rx_packets,
                        "tx_bytes": l.tx_bytes,
                        "rx_bytes": l.rx_bytes,
                        "channel_window": l.channel_window,
                        "channel_outstanding": l.channel_outstanding,
                        "pending_channel_packets": l.pending_channel_packets,
                        "pending_send_packets": l.pending_send_packets,
                        "waiting_send_packets": l.waiting_send_packets,
                        "channel_send_ok": l.channel_send_ok,
                        "channel_send_not_ready": l.channel_send_not_ready,
                        "channel_send_too_big": l.channel_send_too_big,
                        "channel_send_other_error": l.channel_send_other_error,
                        "channel_messages_received": l.channel_messages_received,
                        "channel_proofs_sent": l.channel_proofs_sent,
                        "channel_proofs_received": l.channel_proofs_received,
                    })
                })
                .collect();
            HttpResponse::ok(json!({"links": list}))
        }
        _ => HttpResponse::internal_error("Query failed"),
    })
}

pub(super) fn handle_resources(node: &NodeHandle) -> HttpResponse {
    with_node(node, |n| match n.query(QueryRequest::Resources) {
        Ok(QueryResponse::Resources(resources)) => {
            let list: Vec<Value> = resources
                .iter()
                .map(|r| {
                    json!({
                        "link_id": to_hex(&r.link_id),
                        "direction": r.direction,
                        "total_parts": r.total_parts,
                        "transferred_parts": r.transferred_parts,
                        "complete": r.complete,
                    })
                })
                .collect();
            HttpResponse::ok(json!({"resources": list}))
        }
        _ => HttpResponse::internal_error("Query failed"),
    })
}

pub(super) fn handle_event_list(
    req: &HttpRequest,
    state: &SharedState,
    kind: &str,
) -> HttpResponse {
    let params = parse_query(&req.query);
    let clear = params.get("clear").is_some_and(|v| v == "true");

    let mut s = crate::state::write_state(state);
    let items: Vec<Value> = match kind {
        "announces" => {
            let v: Vec<Value> = s
                .announces
                .iter()
                .map(|r| serde_json::to_value(r).unwrap_or_default())
                .collect();
            if clear {
                s.announces.clear();
            }
            v
        }
        "packets" => {
            let v: Vec<Value> = s
                .packets
                .iter()
                .map(|r| serde_json::to_value(r).unwrap_or_default())
                .collect();
            if clear {
                s.packets.clear();
            }
            v
        }
        "proofs" => {
            let v: Vec<Value> = s
                .proofs
                .iter()
                .map(|r| serde_json::to_value(r).unwrap_or_default())
                .collect();
            if clear {
                s.proofs.clear();
            }
            v
        }
        "link_events" => {
            let v: Vec<Value> = s
                .link_events
                .iter()
                .map(|r| serde_json::to_value(r).unwrap_or_default())
                .collect();
            if clear {
                s.link_events.clear();
            }
            v
        }
        "resource_events" => {
            let v: Vec<Value> = s
                .resource_events
                .iter()
                .map(|r| serde_json::to_value(r).unwrap_or_default())
                .collect();
            if clear {
                s.resource_events.clear();
            }
            v
        }
        _ => Vec::new(),
    };

    let mut obj = serde_json::Map::new();
    obj.insert(kind.to_string(), Value::Array(items));
    HttpResponse::ok(Value::Object(obj))
}

pub(super) fn handle_recall_identity(hash_str: &str, node: &NodeHandle) -> HttpResponse {
    let dest_hash: [u8; 16] = match hex_to_array(hash_str) {
        Some(h) => h,
        None => return HttpResponse::bad_request("Invalid dest_hash hex (expected 32 hex chars)"),
    };

    with_node(node, |n| match n.recall_identity(&DestHash(dest_hash)) {
        Ok(Some(ai)) => {
            let stamp = n
                .recall_destination_stamp(&DestHash(dest_hash))
                .ok()
                .flatten();
            HttpResponse::ok(json!({
                "dest_hash": to_hex(&ai.dest_hash.0),
                "identity_hash": to_hex(&ai.identity_hash.0),
                "public_key": to_hex(&ai.public_key),
                "app_data": ai.app_data.as_ref().map(|d| to_base64(d)),
                "hops": ai.hops,
                "received_at": ai.received_at,
                "stamp_value": stamp.map(|s| s.stamp_value.as_f64()).unwrap_or(0.0),
                "lr_cost": stamp.and_then(|s| s.lr_cost).map(|cost| cost.as_f64()),
            }))
        }
        Ok(None) => HttpResponse::not_found(),
        Err(_) => HttpResponse::internal_error("Query failed"),
    })
}

pub(super) fn handle_backbone_peers(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let params = parse_query(&req.path);
    let interface_name = params.get("interface").map(|s| s.to_string());
    with_node(node, |n| {
        match n.query(QueryRequest::BackbonePeerState { interface_name }) {
            Ok(QueryResponse::BackbonePeerState(entries)) => {
                let peers: Vec<Value> = entries
                    .iter()
                    .map(|e| {
                        json!({
                            "interface": e.interface_name,
                            "ip": e.peer_ip.to_string(),
                            "connected_count": e.connected_count,
                            "blacklisted_remaining_secs": e.blacklisted_remaining_secs,
                            "blacklist_reason": e.blacklist_reason,
                            "reject_count": e.reject_count,
                        })
                    })
                    .collect();
                HttpResponse::ok(json!({ "peers": peers }))
            }
            _ => HttpResponse::internal_error("Query failed"),
        }
    })
}

pub(super) fn handle_backbone_blacklist(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let body: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return HttpResponse::bad_request("Invalid JSON body"),
    };
    let interface_name = match body.get("interface").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return HttpResponse::bad_request("Missing 'interface' field"),
    };
    let ip = match body.get("ip").and_then(|v| v.as_str()) {
        Some(s) => match s.parse::<std::net::IpAddr>() {
            Ok(addr) => addr,
            Err(_) => return HttpResponse::bad_request("Invalid IP address"),
        },
        None => return HttpResponse::bad_request("Missing 'ip' field"),
    };
    let duration_secs = match body.get("duration_secs").and_then(|v| v.as_u64()) {
        Some(d) => d,
        None => return HttpResponse::bad_request("Missing 'duration_secs' field"),
    };
    let reason = body
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("sentinel blacklist")
        .to_string();
    let penalty_level = body
        .get("penalty_level")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        .min(u8::MAX as u64) as u8;
    with_node(node, |n| {
        match n.query(QueryRequest::BlacklistBackbonePeer {
            interface_name,
            peer_ip: ip,
            duration: std::time::Duration::from_secs(duration_secs),
            reason,
            penalty_level,
        }) {
            Ok(QueryResponse::BlacklistBackbonePeer(true)) => {
                HttpResponse::ok(json!({"status": "ok"}))
            }
            Ok(QueryResponse::BlacklistBackbonePeer(false)) => HttpResponse::not_found(),
            _ => HttpResponse::internal_error("Query failed"),
        }
    })
}
