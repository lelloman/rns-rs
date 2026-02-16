use serde_json::{json, Value};

use rns_net::{
    Destination, QueryRequest, QueryResponse, RnsNode,
    DestHash, IdentityHash, ProofStrategy,
};
use rns_crypto::identity::Identity;

use crate::auth::check_auth;
use crate::config::CtlConfig;
use crate::encode::{from_base64, hex_to_array, to_base64, to_hex};
use crate::http::{parse_query, HttpRequest, HttpResponse};
use crate::state::{DestinationEntry, SharedState};

/// Handle for the node, wrapped so shutdown() can consume it.
pub type NodeHandle = std::sync::Arc<std::sync::Mutex<Option<RnsNode>>>;

/// Execute a closure with a reference to the node, returning an error response if the node is gone.
fn with_node<F>(node: &NodeHandle, f: F) -> HttpResponse
where
    F: FnOnce(&RnsNode) -> HttpResponse,
{
    let guard = node.lock().unwrap();
    match guard.as_ref() {
        Some(n) => f(n),
        None => HttpResponse::internal_error("Node is shutting down"),
    }
}

/// Route dispatch: match method + path and call the appropriate handler.
pub fn handle_request(
    req: &HttpRequest,
    node: &NodeHandle,
    state: &SharedState,
    config: &CtlConfig,
) -> HttpResponse {
    // Health check — no auth required
    if req.method == "GET" && req.path == "/health" {
        return HttpResponse::ok(json!({"status": "healthy"}));
    }

    // All other endpoints require auth
    if let Err(resp) = check_auth(req, config) {
        return resp;
    }

    match (req.method.as_str(), req.path.as_str()) {
        // Read endpoints
        ("GET", "/api/info") => handle_info(node, state),
        ("GET", "/api/interfaces") => handle_interfaces(node),
        ("GET", "/api/destinations") => handle_destinations(node, state),
        ("GET", "/api/paths") => handle_paths(req, node),
        ("GET", "/api/links") => handle_links(node),
        ("GET", "/api/resources") => handle_resources(node),
        ("GET", "/api/announces") => handle_event_list(req, state, "announces"),
        ("GET", "/api/packets") => handle_event_list(req, state, "packets"),
        ("GET", "/api/proofs") => handle_event_list(req, state, "proofs"),
        ("GET", "/api/link_events") => handle_event_list(req, state, "link_events"),
        ("GET", "/api/resource_events") => handle_event_list(req, state, "resource_events"),

        // Identity recall: /api/identity/<dest_hash>
        ("GET", path) if path.starts_with("/api/identity/") => {
            let hash_str = &path["/api/identity/".len()..];
            handle_recall_identity(hash_str, node)
        }

        // Action endpoints
        ("POST", "/api/destination") => handle_post_destination(req, node, state),
        ("POST", "/api/announce") => handle_post_announce(req, node, state),
        ("POST", "/api/send") => handle_post_send(req, node, state),
        ("POST", "/api/link") => handle_post_link(req, node),
        ("POST", "/api/link/send") => handle_post_link_send(req, node),
        ("POST", "/api/link/close") => handle_post_link_close(req, node),
        ("POST", "/api/channel") => handle_post_channel(req, node),
        ("POST", "/api/resource") => handle_post_resource(req, node),
        ("POST", "/api/path/request") => handle_post_path_request(req, node),
        ("POST", "/api/direct_connect") => handle_post_direct_connect(req, node),

        // Hook management
        ("GET", "/api/hooks") => handle_list_hooks(node),
        ("POST", "/api/hook/load") => handle_load_hook(req, node),
        ("POST", "/api/hook/unload") => handle_unload_hook(req, node),
        ("POST", "/api/hook/reload") => handle_reload_hook(req, node),

        _ => HttpResponse::not_found(),
    }
}

// --- Read handlers ---

fn handle_info(node: &NodeHandle, state: &SharedState) -> HttpResponse {
    with_node(node, |n| {
        let transport_id = match n.query(QueryRequest::TransportIdentity) {
            Ok(QueryResponse::TransportIdentity(id)) => id,
            _ => None,
        };
        let s = state.read().unwrap();
        HttpResponse::ok(json!({
            "transport_id": transport_id.map(|h| to_hex(&h)),
            "identity_hash": s.identity_hash.map(|h| to_hex(&h)),
            "uptime_seconds": s.uptime_seconds(),
        }))
    })
}

fn handle_interfaces(node: &NodeHandle) -> HttpResponse {
    with_node(node, |n| {
        match n.query(QueryRequest::InterfaceStats) {
            Ok(QueryResponse::InterfaceStats(stats)) => {
                let ifaces: Vec<Value> = stats
                    .interfaces
                    .iter()
                    .map(|i| {
                        json!({
                            "name": i.name,
                            "status": if i.status { "up" } else { "down" },
                            "mode": i.mode,
                            "interface_type": i.interface_type,
                            "rxb": i.rxb,
                            "txb": i.txb,
                            "rx_packets": i.rx_packets,
                            "tx_packets": i.tx_packets,
                            "bitrate": i.bitrate,
                            "started": i.started,
                            "ia_freq": i.ia_freq,
                            "oa_freq": i.oa_freq,
                        })
                    })
                    .collect();
                HttpResponse::ok(json!({
                    "interfaces": ifaces,
                    "transport_enabled": stats.transport_enabled,
                    "transport_uptime": stats.transport_uptime,
                    "total_rxb": stats.total_rxb,
                    "total_txb": stats.total_txb,
                }))
            }
            _ => HttpResponse::internal_error("Query failed"),
        }
    })
}

fn handle_destinations(node: &NodeHandle, state: &SharedState) -> HttpResponse {
    with_node(node, |n| {
        match n.query(QueryRequest::LocalDestinations) {
            Ok(QueryResponse::LocalDestinations(dests)) => {
                let s = state.read().unwrap();
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
        }
    })
}

fn handle_paths(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let params = parse_query(&req.query);
    let filter_hash: Option<[u8; 16]> = params
        .get("dest_hash")
        .and_then(|s| hex_to_array(s));

    with_node(node, |n| {
        match n.query(QueryRequest::PathTable { max_hops: None }) {
            Ok(QueryResponse::PathTable(paths)) => {
                let list: Vec<Value> = paths
                    .iter()
                    .filter(|p| filter_hash.map_or(true, |h| p.hash == h))
                    .map(|p| {
                        json!({
                            "hash": to_hex(&p.hash),
                            "via": to_hex(&p.via),
                            "hops": p.hops,
                            "expires": p.expires,
                            "interface": p.interface_name,
                            "timestamp": p.timestamp,
                        })
                    })
                    .collect();
                HttpResponse::ok(json!({"paths": list}))
            }
            _ => HttpResponse::internal_error("Query failed"),
        }
    })
}

fn handle_links(node: &NodeHandle) -> HttpResponse {
    with_node(node, |n| {
        match n.query(QueryRequest::Links) {
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
                        })
                    })
                    .collect();
                HttpResponse::ok(json!({"links": list}))
            }
            _ => HttpResponse::internal_error("Query failed"),
        }
    })
}

fn handle_resources(node: &NodeHandle) -> HttpResponse {
    with_node(node, |n| {
        match n.query(QueryRequest::Resources) {
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
        }
    })
}

fn handle_event_list(req: &HttpRequest, state: &SharedState, kind: &str) -> HttpResponse {
    let params = parse_query(&req.query);
    let clear = params.get("clear").map_or(false, |v| v == "true");

    let mut s = state.write().unwrap();
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

fn handle_recall_identity(hash_str: &str, node: &NodeHandle) -> HttpResponse {
    let dest_hash: [u8; 16] = match hex_to_array(hash_str) {
        Some(h) => h,
        None => return HttpResponse::bad_request("Invalid dest_hash hex (expected 32 hex chars)"),
    };

    with_node(node, |n| {
        match n.recall_identity(&DestHash(dest_hash)) {
            Ok(Some(ai)) => HttpResponse::ok(json!({
                "dest_hash": to_hex(&ai.dest_hash.0),
                "identity_hash": to_hex(&ai.identity_hash.0),
                "public_key": to_hex(&ai.public_key),
                "app_data": ai.app_data.as_ref().map(|d| to_base64(d)),
                "hops": ai.hops,
                "received_at": ai.received_at,
            })),
            Ok(None) => HttpResponse::not_found(),
            Err(_) => HttpResponse::internal_error("Query failed"),
        }
    })
}

// --- Action handlers ---

fn parse_json_body(req: &HttpRequest) -> Result<Value, HttpResponse> {
    serde_json::from_slice(&req.body).map_err(|e| HttpResponse::bad_request(&format!("Invalid JSON: {}", e)))
}

fn handle_post_destination(
    req: &HttpRequest,
    node: &NodeHandle,
    state: &SharedState,
) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let dest_type_str = body["type"].as_str().unwrap_or("");
    let app_name = match body["app_name"].as_str() {
        Some(s) => s,
        None => return HttpResponse::bad_request("Missing app_name"),
    };
    let aspects: Vec<&str> = body["aspects"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    let (identity_hash, identity_prv_key, identity_pub_key) = {
        let s = state.read().unwrap();
        let ih = s.identity_hash;
        let prv = s.identity.as_ref().and_then(|i| i.get_private_key());
        let pubk = s.identity.as_ref().and_then(|i| i.get_public_key());
        (ih, prv, pubk)
    };

    let (dest, signing_key) = match dest_type_str {
        "single" => {
            let direction = body["direction"].as_str().unwrap_or("in");
            match direction {
                "in" => {
                    let ih = match identity_hash {
                        Some(h) => IdentityHash(h),
                        None => return HttpResponse::internal_error("No identity loaded"),
                    };
                    let dest = Destination::single_in(app_name, &aspects, ih)
                        .set_proof_strategy(parse_proof_strategy(&body));
                    (dest, identity_prv_key)
                }
                "out" => {
                    let dh_str = match body["dest_hash"].as_str() {
                        Some(s) => s,
                        None => return HttpResponse::bad_request("OUT single requires dest_hash of remote"),
                    };
                    let dh: [u8; 16] = match hex_to_array(dh_str) {
                        Some(h) => h,
                        None => return HttpResponse::bad_request("Invalid dest_hash"),
                    };
                    return with_node(node, |n| {
                        match n.recall_identity(&DestHash(dh)) {
                            Ok(Some(recalled)) => {
                                let dest = Destination::single_out(app_name, &aspects, &recalled);
                                // Register in state
                                let full_name = format_dest_name(app_name, &aspects);
                                let mut s = state.write().unwrap();
                                s.destinations.insert(dest.hash.0, DestinationEntry {
                                    destination: dest.clone(),
                                    full_name: full_name.clone(),
                                });
                                HttpResponse::created(json!({
                                    "dest_hash": to_hex(&dest.hash.0),
                                    "name": full_name,
                                    "type": "single",
                                    "direction": "out",
                                }))
                            }
                            Ok(None) => HttpResponse::bad_request("No recalled identity for dest_hash"),
                            Err(_) => HttpResponse::internal_error("Query failed"),
                        }
                    });
                }
                _ => return HttpResponse::bad_request("direction must be 'in' or 'out'"),
            }
        }
        "plain" => {
            let dest = Destination::plain(app_name, &aspects)
                .set_proof_strategy(parse_proof_strategy(&body));
            (dest, None)
        }
        "group" => {
            let mut dest = Destination::group(app_name, &aspects)
                .set_proof_strategy(parse_proof_strategy(&body));
            if let Some(key_b64) = body["group_key"].as_str() {
                match from_base64(key_b64) {
                    Some(key) => {
                        if let Err(e) = dest.load_private_key(key) {
                            return HttpResponse::bad_request(&format!("Invalid group key: {}", e));
                        }
                    }
                    None => return HttpResponse::bad_request("Invalid base64 group_key"),
                }
            } else {
                dest.create_keys();
            }
            (dest, None)
        }
        _ => return HttpResponse::bad_request("type must be 'single', 'plain', or 'group'"),
    };

    with_node(node, |n| {
        match n.register_destination_with_proof(&dest, signing_key) {
            Ok(()) => {
                // For inbound single dests, also register with link manager
                // so incoming LINKREQUEST packets are accepted.
                if dest_type_str == "single"
                    && body["direction"].as_str().unwrap_or("in") == "in"
                {
                    if let (Some(prv), Some(pubk)) = (identity_prv_key, identity_pub_key) {
                        let mut sig_prv = [0u8; 32];
                        sig_prv.copy_from_slice(&prv[32..64]);
                        let mut sig_pub = [0u8; 32];
                        sig_pub.copy_from_slice(&pubk[32..64]);
                        let _ = n.register_link_destination(dest.hash.0, sig_prv, sig_pub);
                    }
                }

                let full_name = format_dest_name(app_name, &aspects);
                let hash_hex = to_hex(&dest.hash.0);
                let group_key_b64 = dest.get_private_key().map(to_base64);
                let mut s = state.write().unwrap();
                s.destinations.insert(
                    dest.hash.0,
                    DestinationEntry {
                        destination: dest,
                        full_name: full_name.clone(),
                    },
                );
                let mut resp = json!({
                    "dest_hash": hash_hex,
                    "name": full_name,
                    "type": dest_type_str,
                });
                if let Some(gk) = group_key_b64 {
                    resp["group_key"] = Value::String(gk);
                }
                HttpResponse::created(resp)
            }
            Err(_) => HttpResponse::internal_error("Failed to register destination"),
        }
    })
}

fn handle_post_announce(req: &HttpRequest, node: &NodeHandle, state: &SharedState) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let dh_str = match body["dest_hash"].as_str() {
        Some(s) => s,
        None => return HttpResponse::bad_request("Missing dest_hash"),
    };
    let dh: [u8; 16] = match hex_to_array(dh_str) {
        Some(h) => h,
        None => return HttpResponse::bad_request("Invalid dest_hash"),
    };

    let app_data: Option<Vec<u8>> = body["app_data"]
        .as_str()
        .and_then(from_base64);

    let (dest, identity) = {
        let s = state.read().unwrap();
        let dest = match s.destinations.get(&dh) {
            Some(entry) => entry.destination.clone(),
            None => return HttpResponse::bad_request("Destination not registered via API"),
        };
        let identity = match s.identity.as_ref().and_then(|i| i.get_private_key()) {
            Some(prv) => Identity::from_private_key(&prv),
            None => return HttpResponse::internal_error("No identity loaded"),
        };
        (dest, identity)
    };

    with_node(node, |n| {
        match n.announce(&dest, &identity, app_data.as_deref()) {
            Ok(()) => HttpResponse::ok(json!({"status": "announced", "dest_hash": dh_str})),
            Err(_) => HttpResponse::internal_error("Announce failed"),
        }
    })
}

fn handle_post_send(req: &HttpRequest, node: &NodeHandle, state: &SharedState) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let dh_str = match body["dest_hash"].as_str() {
        Some(s) => s,
        None => return HttpResponse::bad_request("Missing dest_hash"),
    };
    let dh: [u8; 16] = match hex_to_array(dh_str) {
        Some(h) => h,
        None => return HttpResponse::bad_request("Invalid dest_hash"),
    };
    let data = match body["data"].as_str().and_then(from_base64) {
        Some(d) => d,
        None => return HttpResponse::bad_request("Missing or invalid base64 data"),
    };

    let s = state.read().unwrap();
    let dest = match s.destinations.get(&dh) {
        Some(entry) => entry.destination.clone(),
        None => return HttpResponse::bad_request("Destination not registered via API"),
    };
    drop(s);

    with_node(node, |n| {
        match n.send_packet(&dest, &data) {
            Ok(ph) => HttpResponse::ok(json!({
                "status": "sent",
                "packet_hash": to_hex(&ph.0),
            })),
            Err(_) => HttpResponse::internal_error("Send failed"),
        }
    })
}

fn handle_post_link(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let dh_str = match body["dest_hash"].as_str() {
        Some(s) => s,
        None => return HttpResponse::bad_request("Missing dest_hash"),
    };
    let dh: [u8; 16] = match hex_to_array(dh_str) {
        Some(h) => h,
        None => return HttpResponse::bad_request("Invalid dest_hash"),
    };

    with_node(node, |n| {
        // Recall identity to get signing public key
        let recalled = match n.recall_identity(&DestHash(dh)) {
            Ok(Some(ai)) => ai,
            Ok(None) => return HttpResponse::bad_request("No recalled identity for dest_hash"),
            Err(_) => return HttpResponse::internal_error("Query failed"),
        };
        // Extract Ed25519 public key (second 32 bytes of public_key)
        let mut sig_pub = [0u8; 32];
        sig_pub.copy_from_slice(&recalled.public_key[32..64]);

        match n.create_link(dh, sig_pub) {
            Ok(link_id) => HttpResponse::created(json!({
                "link_id": to_hex(&link_id),
            })),
            Err(_) => HttpResponse::internal_error("Create link failed"),
        }
    })
}

fn handle_post_link_send(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let link_id: [u8; 16] = match body["link_id"]
        .as_str()
        .and_then(|s| hex_to_array(s))
    {
        Some(h) => h,
        None => return HttpResponse::bad_request("Missing or invalid link_id"),
    };
    let data = match body["data"].as_str().and_then(from_base64) {
        Some(d) => d,
        None => return HttpResponse::bad_request("Missing or invalid base64 data"),
    };
    let context = body["context"].as_u64().unwrap_or(0) as u8;

    with_node(node, |n| {
        match n.send_on_link(link_id, data, context) {
            Ok(()) => HttpResponse::ok(json!({"status": "sent"})),
            Err(_) => HttpResponse::internal_error("Send on link failed"),
        }
    })
}

fn handle_post_link_close(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let link_id: [u8; 16] = match body["link_id"]
        .as_str()
        .and_then(|s| hex_to_array(s))
    {
        Some(h) => h,
        None => return HttpResponse::bad_request("Missing or invalid link_id"),
    };

    with_node(node, |n| {
        match n.teardown_link(link_id) {
            Ok(()) => HttpResponse::ok(json!({"status": "closed"})),
            Err(_) => HttpResponse::internal_error("Teardown link failed"),
        }
    })
}

fn handle_post_channel(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let link_id: [u8; 16] = match body["link_id"]
        .as_str()
        .and_then(|s| hex_to_array(s))
    {
        Some(h) => h,
        None => return HttpResponse::bad_request("Missing or invalid link_id"),
    };
    let msgtype = body["msgtype"].as_u64().unwrap_or(0) as u16;
    let payload = match body["payload"].as_str().and_then(from_base64) {
        Some(d) => d,
        None => return HttpResponse::bad_request("Missing or invalid base64 payload"),
    };

    with_node(node, |n| {
        match n.send_channel_message(link_id, msgtype, payload) {
            Ok(()) => HttpResponse::ok(json!({"status": "sent"})),
            Err(_) => HttpResponse::internal_error("Channel message failed"),
        }
    })
}

fn handle_post_resource(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let link_id: [u8; 16] = match body["link_id"]
        .as_str()
        .and_then(|s| hex_to_array(s))
    {
        Some(h) => h,
        None => return HttpResponse::bad_request("Missing or invalid link_id"),
    };
    let data = match body["data"].as_str().and_then(from_base64) {
        Some(d) => d,
        None => return HttpResponse::bad_request("Missing or invalid base64 data"),
    };
    let metadata = body["metadata"]
        .as_str()
        .and_then(from_base64);

    with_node(node, |n| {
        match n.send_resource(link_id, data, metadata) {
            Ok(()) => HttpResponse::ok(json!({"status": "sent"})),
            Err(_) => HttpResponse::internal_error("Resource send failed"),
        }
    })
}

fn handle_post_path_request(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let dh_str = match body["dest_hash"].as_str() {
        Some(s) => s,
        None => return HttpResponse::bad_request("Missing dest_hash"),
    };
    let dh: [u8; 16] = match hex_to_array(dh_str) {
        Some(h) => h,
        None => return HttpResponse::bad_request("Invalid dest_hash"),
    };

    with_node(node, |n| {
        match n.request_path(&DestHash(dh)) {
            Ok(()) => HttpResponse::ok(json!({"status": "requested"})),
            Err(_) => HttpResponse::internal_error("Path request failed"),
        }
    })
}

fn handle_post_direct_connect(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let lid_str = match body["link_id"].as_str() {
        Some(s) => s,
        None => return HttpResponse::bad_request("Missing link_id"),
    };
    let link_id: [u8; 16] = match hex_to_array(lid_str) {
        Some(h) => h,
        None => return HttpResponse::bad_request("Invalid link_id"),
    };

    with_node(node, |n| {
        match n.propose_direct_connect(link_id) {
            Ok(()) => HttpResponse::ok(json!({"status": "proposed"})),
            Err(_) => HttpResponse::internal_error("Direct connect proposal failed"),
        }
    })
}

// --- Hook handlers ---

fn handle_list_hooks(node: &NodeHandle) -> HttpResponse {
    with_node(node, |n| {
        match n.list_hooks() {
            Ok(hooks) => {
                let list: Vec<Value> = hooks
                    .iter()
                    .map(|h| {
                        json!({
                            "name": h.name,
                            "attach_point": h.attach_point,
                            "priority": h.priority,
                            "enabled": h.enabled,
                            "consecutive_traps": h.consecutive_traps,
                        })
                    })
                    .collect();
                HttpResponse::ok(json!({"hooks": list}))
            }
            Err(_) => HttpResponse::internal_error("Query failed"),
        }
    })
}

/// Load a WASM hook from a filesystem path.
///
/// The `path` field in the JSON body refers to a file on the **server's** local
/// filesystem. This means the CLI and the HTTP server must have access to the
/// same filesystem for the path to resolve correctly.
fn handle_load_hook(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let name = match body["name"].as_str() {
        Some(s) => s.to_string(),
        None => return HttpResponse::bad_request("Missing name"),
    };
    let path = match body["path"].as_str() {
        Some(s) => s,
        None => return HttpResponse::bad_request("Missing path"),
    };
    let attach_point = match body["attach_point"].as_str() {
        Some(s) => s.to_string(),
        None => return HttpResponse::bad_request("Missing attach_point"),
    };
    let priority = body["priority"].as_i64().unwrap_or(0) as i32;

    // Read WASM file
    let wasm_bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return HttpResponse::bad_request(&format!("Failed to read WASM file: {}", e)),
    };

    with_node(node, |n| {
        match n.load_hook(name, wasm_bytes, attach_point, priority) {
            Ok(Ok(())) => HttpResponse::ok(json!({"status": "loaded"})),
            Ok(Err(e)) => HttpResponse::bad_request(&e),
            Err(_) => HttpResponse::internal_error("Driver unavailable"),
        }
    })
}

fn handle_unload_hook(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let name = match body["name"].as_str() {
        Some(s) => s.to_string(),
        None => return HttpResponse::bad_request("Missing name"),
    };
    let attach_point = match body["attach_point"].as_str() {
        Some(s) => s.to_string(),
        None => return HttpResponse::bad_request("Missing attach_point"),
    };

    with_node(node, |n| {
        match n.unload_hook(name, attach_point) {
            Ok(Ok(())) => HttpResponse::ok(json!({"status": "unloaded"})),
            Ok(Err(e)) => HttpResponse::bad_request(&e),
            Err(_) => HttpResponse::internal_error("Driver unavailable"),
        }
    })
}

fn handle_reload_hook(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let name = match body["name"].as_str() {
        Some(s) => s.to_string(),
        None => return HttpResponse::bad_request("Missing name"),
    };
    let path = match body["path"].as_str() {
        Some(s) => s,
        None => return HttpResponse::bad_request("Missing path"),
    };
    let attach_point = match body["attach_point"].as_str() {
        Some(s) => s.to_string(),
        None => return HttpResponse::bad_request("Missing attach_point"),
    };

    let wasm_bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return HttpResponse::bad_request(&format!("Failed to read WASM file: {}", e)),
    };

    with_node(node, |n| {
        match n.reload_hook(name, attach_point, wasm_bytes) {
            Ok(Ok(())) => HttpResponse::ok(json!({"status": "reloaded"})),
            Ok(Err(e)) => HttpResponse::bad_request(&e),
            Err(_) => HttpResponse::internal_error("Driver unavailable"),
        }
    })
}

// --- Helpers ---

fn format_dest_name(app_name: &str, aspects: &[&str]) -> String {
    if aspects.is_empty() {
        app_name.to_string()
    } else {
        format!("{}.{}", app_name, aspects.join("."))
    }
}

fn parse_proof_strategy(body: &Value) -> ProofStrategy {
    match body["proof_strategy"].as_str() {
        Some("all") => ProofStrategy::ProveAll,
        Some("app") => ProofStrategy::ProveApp,
        _ => ProofStrategy::ProveNone,
    }
}
