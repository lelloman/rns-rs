//! Hooks: listing, loading, reloading and configuring them.

use super::*;

pub(super) fn handle_list_hooks(node: &NodeHandle) -> HttpResponse {
    with_node(node, |n| match n.list_hooks() {
        Ok(hooks) => {
            let list: Vec<Value> = hooks
                .iter()
                .map(|h| {
                    json!({
                        "name": h.name,
                        "attach_point": h.attach_point,
                        "type": h.hook_type,
                        "priority": h.priority,
                        "enabled": h.enabled,
                        "consecutive_traps": h.consecutive_traps,
                    })
                })
                .collect();
            HttpResponse::ok(json!({"hooks": list}))
        }
        Err(_) => HttpResponse::internal_error("Query failed"),
    })
}

/// Resolve the path of a file-backed (native) hook requested through the API.
///
/// The path must be absolute and resolve to a regular file inside the
/// configured hooks directory.
pub(super) fn resolve_api_hook_file(
    config: &ControlPlaneConfigHandle,
    path: &str,
) -> Result<String, HttpResponse> {
    let hooks_dir = read_control_plane_config(config).resolved_hooks_dir();
    crate::hook_path::resolve_native_hook_path(&hooks_dir, path)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| HttpResponse::bad_request(&e))
}

/// Load a hook from a filesystem path.
///
/// The `path` field in the JSON body refers to a file on the **server's** local
/// filesystem. This means the CLI and the HTTP server must have access to the
/// same filesystem for the path to resolve correctly. Native hooks are loaded
/// only from the configured hooks directory.
pub(super) fn handle_load_hook(
    req: &HttpRequest,
    node: &NodeHandle,
    config: &ControlPlaneConfigHandle,
) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let name = match body.get("name").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return HttpResponse::bad_request("Missing name"),
    };
    let path = match body.get("path").and_then(Value::as_str) {
        Some(s) => s,
        None => return HttpResponse::bad_request("Missing path"),
    };
    let attach_point = match body.get("attach_point").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return HttpResponse::bad_request("Missing attach_point"),
    };
    let priority = body.get("priority").and_then(Value::as_i64).unwrap_or(0) as i32;
    let hook_type = body
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_HOOK_TYPE)
        .to_string();

    if hook_type == "wasm" {
        let wasm_bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                return HttpResponse::bad_request(&format!("Failed to read WASM file: {}", e));
            }
        };

        with_node(node, |n| {
            match n.load_hook(name, wasm_bytes, attach_point, priority) {
                Ok(Ok(())) => HttpResponse::ok(json!({"status": "loaded"})),
                Ok(Err(e)) => HttpResponse::bad_request(&e.to_string()),
                Err(_) => HttpResponse::internal_error("Driver unavailable"),
            }
        })
    } else if hook_type == "builtin" {
        let builtin_id = body
            .get("builtin_id")
            .and_then(Value::as_str)
            .or_else(|| body.get("id").and_then(Value::as_str))
            .unwrap_or(path)
            .to_string();
        with_node(node, |n| {
            match n.load_builtin_hook(name, builtin_id, attach_point, priority) {
                Ok(Ok(())) => HttpResponse::ok(json!({"status": "loaded"})),
                Ok(Err(e)) => HttpResponse::bad_request(&e.to_string()),
                Err(_) => HttpResponse::internal_error("Driver unavailable"),
            }
        })
    } else {
        let path = match resolve_api_hook_file(config, path) {
            Ok(p) => p,
            Err(r) => return r,
        };
        with_node(node, |n| {
            match n.load_hook_file(name, path, hook_type, attach_point, priority) {
                Ok(Ok(())) => HttpResponse::ok(json!({"status": "loaded"})),
                Ok(Err(e)) => HttpResponse::bad_request(&e.to_string()),
                Err(_) => HttpResponse::internal_error("Driver unavailable"),
            }
        })
    }
}

pub(super) fn handle_unload_hook(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let name = match body.get("name").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return HttpResponse::bad_request("Missing name"),
    };
    let attach_point = match body.get("attach_point").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return HttpResponse::bad_request("Missing attach_point"),
    };

    with_node(node, |n| match n.unload_hook(name, attach_point) {
        Ok(Ok(())) => HttpResponse::ok(json!({"status": "unloaded"})),
        Ok(Err(e)) => HttpResponse::bad_request(&e.to_string()),
        Err(_) => HttpResponse::internal_error("Driver unavailable"),
    })
}

pub(super) fn handle_reload_hook(
    req: &HttpRequest,
    node: &NodeHandle,
    config: &ControlPlaneConfigHandle,
) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let name = match body.get("name").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return HttpResponse::bad_request("Missing name"),
    };
    let path = match body.get("path").and_then(Value::as_str) {
        Some(s) => s,
        None => return HttpResponse::bad_request("Missing path"),
    };
    let attach_point = match body.get("attach_point").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return HttpResponse::bad_request("Missing attach_point"),
    };
    let hook_type = body
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_HOOK_TYPE)
        .to_string();

    if hook_type == "wasm" {
        let wasm_bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                return HttpResponse::bad_request(&format!("Failed to read WASM file: {}", e));
            }
        };

        with_node(node, |n| {
            match n.reload_hook(name, attach_point, wasm_bytes) {
                Ok(Ok(())) => HttpResponse::ok(json!({"status": "reloaded"})),
                Ok(Err(e)) => HttpResponse::bad_request(&e.to_string()),
                Err(_) => HttpResponse::internal_error("Driver unavailable"),
            }
        })
    } else if hook_type == "builtin" {
        let builtin_id = body
            .get("builtin_id")
            .and_then(Value::as_str)
            .or_else(|| body.get("id").and_then(Value::as_str))
            .unwrap_or(path)
            .to_string();
        with_node(node, |n| {
            match n.reload_builtin_hook(name, attach_point, builtin_id) {
                Ok(Ok(())) => HttpResponse::ok(json!({"status": "reloaded"})),
                Ok(Err(e)) => HttpResponse::bad_request(&e.to_string()),
                Err(_) => HttpResponse::internal_error("Driver unavailable"),
            }
        })
    } else {
        let path = match resolve_api_hook_file(config, path) {
            Ok(p) => p,
            Err(r) => return r,
        };
        with_node(node, |n| {
            match n.reload_hook_file(name, attach_point, path, hook_type) {
                Ok(Ok(())) => HttpResponse::ok(json!({"status": "reloaded"})),
                Ok(Err(e)) => HttpResponse::bad_request(&e.to_string()),
                Err(_) => HttpResponse::internal_error("Driver unavailable"),
            }
        })
    }
}

pub(super) fn handle_set_hook_enabled(
    req: &HttpRequest,
    node: &NodeHandle,
    enabled: bool,
) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let name = match body.get("name").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return HttpResponse::bad_request("Missing name"),
    };
    let attach_point = match body.get("attach_point").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return HttpResponse::bad_request("Missing attach_point"),
    };

    with_node(node, |n| {
        match n.set_hook_enabled(name, attach_point, enabled) {
            Ok(Ok(())) => HttpResponse::ok(json!({
                "status": if enabled { "enabled" } else { "disabled" }
            })),
            Ok(Err(e)) => HttpResponse::bad_request(&e.to_string()),
            Err(_) => HttpResponse::internal_error("Driver unavailable"),
        }
    })
}

pub(super) fn handle_set_hook_priority(req: &HttpRequest, node: &NodeHandle) -> HttpResponse {
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let name = match body.get("name").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return HttpResponse::bad_request("Missing name"),
    };
    let attach_point = match body.get("attach_point").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return HttpResponse::bad_request("Missing attach_point"),
    };
    let priority = match body.get("priority").and_then(Value::as_i64) {
        Some(v) => v as i32,
        None => return HttpResponse::bad_request("Missing priority"),
    };

    with_node(node, |n| {
        match n.set_hook_priority(name, attach_point, priority) {
            Ok(Ok(())) => HttpResponse::ok(json!({"status": "priority_updated"})),
            Ok(Err(e)) => HttpResponse::bad_request(&e.to_string()),
            Err(_) => HttpResponse::internal_error("Driver unavailable"),
        }
    })
}
