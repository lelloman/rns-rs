//! Requests that act on the network: destinations, announces, sends,
//! links, channels, resources, path requests.

use super::*;

pub(super) fn handle_post_destination(
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
        let s = read_state(state);
        let ih = s.identity_hash;
        let prv = s.identity.as_ref().and_then(|i| i.get_private_key());
        let pubk = s.identity.as_ref().and_then(|i| i.get_public_key());
        (ih, prv, pubk)
    };

    let (mut dest, signing_key) = match dest_type_str {
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
                        None => {
                            return HttpResponse::bad_request(
                                "OUT single requires dest_hash of remote",
                            )
                        }
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
                                let mut s = crate::state::write_state(state);
                                s.destinations.insert(
                                    dest.hash.0,
                                    DestinationEntry {
                                        destination: dest.clone(),
                                        full_name: full_name.clone(),
                                    },
                                );
                                HttpResponse::created(json!({
                                    "dest_hash": to_hex(&dest.hash.0),
                                    "name": full_name,
                                    "type": "single",
                                    "direction": "out",
                                }))
                            }
                            Ok(None) => {
                                HttpResponse::bad_request("No recalled identity for dest_hash")
                            }
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

    if !body["max_request_size"].is_null() {
        let Some(max_request_size) = body["max_request_size"].as_i64() else {
            return HttpResponse::bad_request("max_request_size must be an integer");
        };
        if dest.set_max_request_size(max_request_size).is_err() {
            return HttpResponse::bad_request("max_request_size cannot be negative");
        }
    }

    with_node(node, |n| {
        match n.register_destination_with_proof(&dest, signing_key) {
            Ok(()) => {
                // For inbound single dests, also register with link manager
                // so incoming LINKREQUEST packets are accepted.
                if dest_type_str == "single" && body["direction"].as_str().unwrap_or("in") == "in" {
                    if let (Some(prv), Some(pubk)) = (identity_prv_key, identity_pub_key) {
                        let mut sig_prv = [0u8; 32];
                        sig_prv.copy_from_slice(&prv[32..64]);
                        let mut sig_pub = [0u8; 32];
                        sig_pub.copy_from_slice(&pubk[32..64]);
                        // 1 = AcceptAll: links to API destinations accept
                        // incoming resources from the start.
                        let _ = n.register_link_destination_with_max_request_size(
                            dest.hash.0,
                            sig_prv,
                            sig_pub,
                            1,
                            dest.max_request_size,
                        );
                    }
                }

                let full_name = format_dest_name(app_name, &aspects);
                let hash_hex = to_hex(&dest.hash.0);
                let group_key_b64 = dest.get_private_key().map(to_base64);
                let mut s = crate::state::write_state(state);
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

pub(super) fn handle_post_announce(
    req: &HttpRequest,
    node: &NodeHandle,
    state: &SharedState,
) -> HttpResponse {
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

    let app_data: Option<Vec<u8>> = body["app_data"].as_str().and_then(from_base64);

    let (dest, identity) = {
        let s = read_state(state);
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

    with_active_node(node, |n| {
        match n.announce_queued(&dest, &identity, app_data.as_deref()) {
            Ok(()) => HttpResponse::ok(json!({"status": "announced", "dest_hash": dh_str})),
            Err(_) => HttpResponse::internal_error("Announce failed"),
        }
    })
}

pub(super) fn handle_post_send(
    req: &HttpRequest,
    node: &NodeHandle,
    state: &SharedState,
) -> HttpResponse {
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

    let s = read_state(state);
    let dest = match s.destinations.get(&dh) {
        Some(entry) => entry.destination.clone(),
        None => return HttpResponse::bad_request("Destination not registered via API"),
    };
    drop(s);

    let max_len = match dest.dest_type {
        rns_core::types::DestinationType::Plain => rns_core::constants::PLAIN_MDU,
        rns_core::types::DestinationType::Single | rns_core::types::DestinationType::Group => {
            rns_core::constants::ENCRYPTED_MDU
        }
    };
    if data.len() > max_len {
        return HttpResponse::bad_request(&format!(
            "Payload too large for single-packet send: {} bytes > {} byte limit",
            data.len(),
            max_len
        ));
    }

    with_active_node(node, |n| match n.send_packet_queued(&dest, &data) {
        Ok(ph) => HttpResponse::ok(json!({
            "status": "sent",
            "packet_hash": to_hex(&ph.0),
        })),
        Err(_) => HttpResponse::internal_error("Send failed"),
    })
}

pub(super) fn handle_post_link(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
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

    with_active_node(node, |n| {
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
            Ok(link_id) => {
                // Accept incoming resources on links this API opens. This is
                // set here, on the request thread, and not from the
                // link-established callback: callbacks run on the driver
                // thread and must never take the node handle lock.
                let _ = n.set_resource_strategy(link_id, 1); // 1 = AcceptAll
                HttpResponse::created(json!({
                    "link_id": to_hex(&link_id),
                }))
            }
            Err(_) => HttpResponse::internal_error("Create link failed"),
        }
    })
}

pub(super) fn handle_post_link_send(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let link_id: [u8; 16] = match body["link_id"].as_str().and_then(hex_to_array) {
        Some(h) => h,
        None => return HttpResponse::bad_request("Missing or invalid link_id"),
    };
    let data = match body["data"].as_str().and_then(from_base64) {
        Some(d) => d,
        None => return HttpResponse::bad_request("Missing or invalid base64 data"),
    };
    let context = body["context"].as_u64().unwrap_or(0) as u8;

    // Release the node handle before waiting for a slow interface, so other
    // requests can still query, drain, or shut down the node.
    let receipt = {
        let guard = lock_node_handle(node);
        let Some(n) = guard.as_ref() else {
            return HttpResponse::internal_error("Node is shutting down");
        };
        match n.try_send_on_link(link_id, data, context) {
            Ok(receipt) => receipt,
            Err(rns_net::LinkSendError::QueueFull) => {
                return HttpResponse::conflict("Outbound queue is full");
            }
            Err(_) => return HttpResponse::internal_error("Send on link failed"),
        }
    };
    match receipt.wait() {
        Ok(()) => HttpResponse::ok(json!({"status": "sent"})),
        Err(rns_net::LinkSendError::Draining) => {
            HttpResponse::conflict("Node is draining and not accepting new work")
        }
        Err(_) => HttpResponse::internal_error("Send on link failed"),
    }
}

pub(super) fn handle_post_link_close(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let link_id: [u8; 16] = match body["link_id"].as_str().and_then(hex_to_array) {
        Some(h) => h,
        None => return HttpResponse::bad_request("Missing or invalid link_id"),
    };

    with_node(node, |n| match n.teardown_link(link_id) {
        Ok(()) => HttpResponse::ok(json!({"status": "closed"})),
        Err(_) => HttpResponse::internal_error("Teardown link failed"),
    })
}

pub(super) fn handle_post_channel(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let link_id: [u8; 16] = match body["link_id"].as_str().and_then(hex_to_array) {
        Some(h) => h,
        None => return HttpResponse::bad_request("Missing or invalid link_id"),
    };
    let msgtype = body["msgtype"].as_u64().unwrap_or(0) as u16;
    let payload = match body["payload"].as_str().and_then(from_base64) {
        Some(d) => d,
        None => return HttpResponse::bad_request("Missing or invalid base64 payload"),
    };

    with_active_node(node, |n| {
        match n.send_channel_message(link_id, msgtype, payload) {
            Ok(()) => HttpResponse::ok(json!({"status": "sent"})),
            Err(_) => HttpResponse::bad_request("Channel message failed"),
        }
    })
}

pub(super) fn handle_post_resource(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let link_id: [u8; 16] = match body["link_id"].as_str().and_then(hex_to_array) {
        Some(h) => h,
        None => return HttpResponse::bad_request("Missing or invalid link_id"),
    };
    let data = match body["data"].as_str().and_then(from_base64) {
        Some(d) => d,
        None => return HttpResponse::bad_request("Missing or invalid base64 data"),
    };
    let metadata = body["metadata"].as_str().and_then(from_base64);

    with_active_node(node, |n| match n.send_resource(link_id, data, metadata) {
        Ok(()) => HttpResponse::ok(json!({"status": "sent"})),
        Err(_) => HttpResponse::internal_error("Resource send failed"),
    })
}

pub(super) fn handle_post_path_request(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
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

    with_active_node(node, |n| match n.request_path(&DestHash(dh)) {
        Ok(()) => HttpResponse::ok(json!({"status": "requested"})),
        Err(_) => HttpResponse::internal_error("Path request failed"),
    })
}

pub(super) fn handle_post_direct_connect(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
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

    with_active_node(node, |n| match n.propose_direct_connect(link_id) {
        Ok(()) => HttpResponse::ok(json!({"status": "proposed"})),
        Err(_) => HttpResponse::internal_error("Direct connect proposal failed"),
    })
}

pub(super) fn handle_post_clear_announce_queues(node: &NodeHandle) -> HttpResponse {
    with_node(node, |n| match n.query(query::DropAnnounceQueues) {
        Ok(()) => HttpResponse::ok(json!({"status": "ok"})),
        Err(_) => HttpResponse::internal_error("Query failed"),
    })
}
