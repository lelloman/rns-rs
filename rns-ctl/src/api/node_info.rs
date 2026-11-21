//! The node's info and its config: reading, checking and changing it.

use super::*;

pub(super) fn handle_node(node: &NodeHandle, state: &SharedState) -> HttpResponse {
    let (transport_id, drain_status) = {
        let guard = lock_node_handle(node);
        let Some(node) = guard.as_ref() else {
            return HttpResponse::internal_error("Node is shutting down");
        };
        let transport_id = node.query(query::TransportIdentity).ok().flatten();
        let drain_status = node.query(query::DrainStatus).ok();
        (transport_id, drain_status)
    };

    let s = read_state(state);
    HttpResponse::ok(json!({
        "server_mode": s.server_mode,
        "uptime_seconds": s.uptime_seconds(),
        "transport_id": transport_id.map(|h| to_hex(&h)),
        "identity_hash": s.identity_hash.map(|h| to_hex(&h)),
        "process_count": s.processes.len(),
        "processes_running": s.processes.values().filter(|p| p.status == "running").count(),
        "processes_ready": s.processes.values().filter(|p| p.ready).count(),
        "drain": drain_status.map(|status| json!({
            "state": format!("{:?}", status.state).to_lowercase(),
            "drain_age_seconds": status.drain_age_seconds,
            "deadline_remaining_seconds": status.deadline_remaining_seconds,
            "drain_complete": status.drain_complete,
            "interface_writer_queued_frames": status.interface_writer_queued_frames,
            "provider_backlog_events": status.provider_backlog_events,
            "provider_consumer_queued_events": status.provider_consumer_queued_events,
            "detail": status.detail,
        })),
    }))
}

pub(super) fn handle_config(state: &SharedState) -> HttpResponse {
    let s = read_state(state);
    match &s.server_config {
        Some(config) => HttpResponse::ok(json!({ "config": config })),
        None => HttpResponse::ok(json!({ "config": null })),
    }
}

pub(super) fn handle_config_schema(state: &SharedState) -> HttpResponse {
    let s = read_state(state);
    match &s.server_config_schema {
        Some(schema) => HttpResponse::ok(json!({ "schema": schema })),
        None => HttpResponse::ok(json!({ "schema": null })),
    }
}

pub(super) fn handle_config_status(state: &SharedState) -> HttpResponse {
    let s = read_state(state);
    HttpResponse::ok(json!({
        "status": s.server_config_status.snapshot(),
    }))
}

pub(super) fn handle_config_validate(req: &HttpRequest, state: &SharedState) -> HttpResponse {
    let validator = {
        let s = read_state(state);
        s.server_config_validator.clone()
    };

    match validator {
        Some(validator) => match validator(&req.body) {
            Ok(result) => HttpResponse::ok(json!({ "result": result })),
            Err(err) => HttpResponse::bad_request(&err.to_string()),
        },
        None => HttpResponse::internal_error("Server config validation is not enabled"),
    }
}

pub(super) fn handle_config_mutation(
    req: &HttpRequest,
    state: &SharedState,
    mode: crate::state::ServerConfigMutationMode,
) -> HttpResponse {
    let mutator = {
        let s = read_state(state);
        s.server_config_mutator.clone()
    };

    match mutator {
        Some(mutator) => match mutator(mode, &req.body) {
            Ok(result) => HttpResponse::ok(json!({ "result": result })),
            Err(err) => HttpResponse::bad_request(&err.to_string()),
        },
        None => HttpResponse::internal_error("Server config mutation is not enabled"),
    }
}

pub(super) fn handle_info(node: &NodeHandle, state: &SharedState) -> HttpResponse {
    with_node(node, |n| {
        let transport_id = n.query(query::TransportIdentity).ok().flatten();
        let s = read_state(state);
        HttpResponse::ok(json!({
            "transport_id": transport_id.map(|h| to_hex(&h)),
            "identity_hash": s.identity_hash.map(|h| to_hex(&h)),
            "uptime_seconds": s.uptime_seconds(),
        }))
    })
}
