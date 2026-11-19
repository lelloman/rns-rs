mod actions;
mod hook_routes;
mod network;
mod node_info;
mod processes;

use actions::*;
use hook_routes::*;
use network::*;
use node_info::*;
use processes::*;

use serde_json::{json, Value};

/// Hook type used when the caller omits `type`. Native hooks must be
/// requested explicitly.
const DEFAULT_HOOK_TYPE: &str = {
    #[cfg(feature = "rns-hooks-wasm")]
    {
        "wasm"
    }
    #[cfg(not(feature = "rns-hooks-wasm"))]
    {
        "builtin"
    }
};

use rns_crypto::identity::Identity;
use rns_net::{
    event::LifecycleState, DestHash, Destination, IdentityHash, ProofStrategy, QueryRequest,
    QueryResponse, RnsNode,
};

use crate::auth::check_auth;
use crate::encode::{from_base64, hex_to_array, to_base64, to_hex};
use crate::http::{parse_query, HttpRequest, HttpResponse};
use crate::state::{
    lock_node_handle, read_control_plane_config, read_state, ControlPlaneConfigHandle,
    DestinationEntry, SharedState,
};
use crate::stats_api;

/// Handle for the node, wrapped so shutdown() can consume it.
///
/// Request handlers hold this lock while they wait for the node's driver
/// thread to answer, so code that runs on the driver thread (the `Callbacks`
/// implementation in `bridge.rs`) must never take it: doing so deadlocks the
/// driver against any in-flight request.
pub type NodeHandle = std::sync::Arc<std::sync::Mutex<Option<RnsNode>>>;

/// Execute a closure with a reference to the node, returning an error response if the node is gone.
fn with_node<F>(node: &NodeHandle, f: F) -> HttpResponse
where
    F: FnOnce(&RnsNode) -> HttpResponse,
{
    let guard = lock_node_handle(node);
    match guard.as_ref() {
        Some(n) => f(n),
        None => HttpResponse::internal_error("Node is shutting down"),
    }
}

fn with_active_node<F>(node: &NodeHandle, f: F) -> HttpResponse
where
    F: FnOnce(&RnsNode) -> HttpResponse,
{
    with_node(node, |n| match n.query(QueryRequest::DrainStatus) {
        Ok(QueryResponse::DrainStatus(status))
            if !matches!(status.state, LifecycleState::Active) =>
        {
            HttpResponse::conflict(
                status
                    .detail
                    .as_deref()
                    .unwrap_or("Node is draining and not accepting new work"),
            )
        }
        _ => f(n),
    })
}

/// Whether a route needs the bearer token. Only the UI shell, its static
/// assets and the health check are served without it.
pub fn requires_auth(method: &str, path: &str) -> bool {
    !(method == "GET"
        && matches!(
            path,
            "/" | "/ui" | "/assets/app.css" | "/assets/app.js" | "/health"
        ))
}

/// Authenticate a request from its head alone, so the server can answer
/// `401` before reading any body bytes.
pub fn check_request_auth(
    req: &HttpRequest,
    config: &ControlPlaneConfigHandle,
) -> Result<(), HttpResponse> {
    if requires_auth(&req.method, &req.path) {
        check_auth(req, config)
    } else {
        Ok(())
    }
}

/// Route dispatch: match method + path and call the appropriate handler.
pub fn handle_request(
    req: &HttpRequest,
    node: &NodeHandle,
    state: &SharedState,
    config: &ControlPlaneConfigHandle,
) -> HttpResponse {
    if req.method == "GET" && (req.path == "/" || req.path == "/ui") {
        return HttpResponse::html(index_html(config));
    }
    if req.method == "GET" && req.path == "/assets/app.css" {
        return HttpResponse::bytes(
            200,
            "OK",
            "text/css; charset=utf-8",
            include_str!("../assets/app.css").as_bytes().to_vec(),
        );
    }
    if req.method == "GET" && req.path == "/assets/app.js" {
        return HttpResponse::bytes(
            200,
            "OK",
            "application/javascript; charset=utf-8",
            include_str!("../assets/app.js").as_bytes().to_vec(),
        );
    }

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
        ("GET", "/api/node") => handle_node(node, state),
        ("GET", "/api/config") => handle_config(state),
        ("GET", "/api/config/schema") => handle_config_schema(state),
        ("GET", "/api/config/status") => handle_config_status(state),
        ("GET", "/api/processes") => handle_processes(state),
        ("GET", "/api/process_events") => handle_process_events(state),
        ("GET", "/api/stats/summary") => stats_api::handle_summary(req, state),
        ("GET", "/api/stats/announces") => stats_api::handle_announces(req, state),
        ("GET", "/api/stats/interfaces") => stats_api::handle_interfaces(req, state),
        ("GET", "/api/stats/destinations") => stats_api::handle_destinations(req, state),
        ("GET", "/api/stats/packets") => stats_api::handle_packets(req, state),
        ("GET", "/api/stats/packets/series") => stats_api::handle_packet_series(req, state),
        ("GET", "/api/stats/links") => stats_api::handle_links(req, state),
        ("GET", "/api/stats/system") => stats_api::handle_system(req, state),
        ("GET", path) if path.starts_with("/api/processes/") && path.ends_with("/logs") => {
            handle_process_logs(path, req, state)
        }
        ("GET", "/api/info") => handle_info(node, state),
        ("GET", "/api/interfaces") => handle_interfaces(node),
        ("GET", "/api/destinations") => handle_destinations(node, state),
        ("GET", "/api/paths") => handle_paths(req, node),
        ("GET", "/api/links") => handle_links(node),
        ("GET", "/api/direct_links") => handle_direct_links(node),
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
        ("POST", "/api/config/validate") => handle_config_validate(req, state),
        ("POST", "/api/config") => {
            handle_config_mutation(req, state, crate::state::ServerConfigMutationMode::Save)
        }
        ("POST", "/api/config/apply") => {
            handle_config_mutation(req, state, crate::state::ServerConfigMutationMode::Apply)
        }
        ("POST", "/api/link") => handle_post_link(req, node),
        ("POST", "/api/link/send") => handle_post_link_send(req, node),
        ("POST", "/api/link/close") => handle_post_link_close(req, node),
        ("POST", "/api/channel") => handle_post_channel(req, node),
        ("POST", "/api/resource") => handle_post_resource(req, node),
        ("POST", "/api/path/request") => handle_post_path_request(req, node),
        ("POST", "/api/direct_connect") => handle_post_direct_connect(req, node),
        ("POST", "/api/announce_queues/clear") => handle_post_clear_announce_queues(node),
        ("POST", path) if path.starts_with("/api/processes/") && path.ends_with("/restart") => {
            handle_process_control(path, state, "restart")
        }
        ("POST", path) if path.starts_with("/api/processes/") && path.ends_with("/start") => {
            handle_process_control(path, state, "start")
        }
        ("POST", path) if path.starts_with("/api/processes/") && path.ends_with("/stop") => {
            handle_process_control(path, state, "stop")
        }

        // Backbone peer state
        ("GET", "/api/backbone/peers") => handle_backbone_peers(req, node),
        ("POST", "/api/backbone/blacklist") => handle_backbone_blacklist(req, node),

        // Hook management
        ("GET", "/api/hooks") => handle_list_hooks(node),
        ("POST", "/api/hook/load") => handle_load_hook(req, node, config),
        ("POST", "/api/hook/unload") => handle_unload_hook(req, node),
        ("POST", "/api/hook/reload") => handle_reload_hook(req, node, config),
        ("POST", "/api/hook/enable") => handle_set_hook_enabled(req, node, true),
        ("POST", "/api/hook/disable") => handle_set_hook_enabled(req, node, false),
        ("POST", "/api/hook/priority") => handle_set_hook_priority(req, node),

        _ => HttpResponse::not_found(),
    }
}

fn index_html(_config: &ControlPlaneConfigHandle) -> &'static str {
    include_str!("../assets/index_auth.html")
}

fn parse_json_body(req: &HttpRequest) -> Result<Value, HttpResponse> {
    serde_json::from_slice(&req.body)
        .map_err(|e| HttpResponse::bad_request(&format!("Invalid JSON: {}", e)))
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
