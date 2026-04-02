//! Integration tests for rns-ctl HTTP server.
//!
//! These tests start real RNS nodes + HTTP servers and make HTTP requests
//! using raw TcpStream (no external dependencies).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rns_crypto::identity::Identity;
use rns_crypto::OsRng;

use rns_net::{
    InterfaceConfig, InterfaceId, NodeConfig, RnsNode, TcpClientConfig, TcpServerConfig, MODE_FULL,
};

use rns_ctl::api::NodeHandle;
use rns_ctl::bridge::CtlCallbacks;
use rns_ctl::config::CtlConfig;
use rns_ctl::server::{self, ServerContext};
use rns_ctl::state::{
    ensure_process, push_process_log, CtlState, LaunchProcessSnapshot, ManagedProcessState,
    ServerConfigApplyPlan, ServerConfigChange, ServerConfigFieldSchema, ServerConfigMutationResult,
    ServerConfigSchemaSnapshot, ServerConfigSnapshot, ServerConfigStatusState,
    ServerConfigValidationSnapshot, ServerHttpConfigSnapshot, SharedState, WsBroadcast,
};

// ─── Test Server Harness ────────────────────────────────────────────────────

struct TestServer {
    ctx: Arc<ServerContext>,
    port: u16,
    _thread: JoinHandle<()>,
}

impl TestServer {
    /// Shut down the RNS node.
    fn shutdown(&self) {
        if let Some(node) = self.ctx.node.lock().unwrap().take() {
            node.shutdown();
        }
    }
}

fn find_free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};

    static NEXT_PORT: AtomicU16 = AtomicU16::new(0);

    let pid = std::process::id() as u16;
    let base = 20_000 + (pid % 250) * 160;
    let _ = NEXT_PORT.compare_exchange(0, base, Ordering::SeqCst, Ordering::SeqCst);

    loop {
        let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// Start a test server with no interfaces and auth disabled.
fn start_test_server() -> TestServer {
    start_test_server_with_config(
        CtlConfig {
            host: "127.0.0.1".into(),
            port: 0, // overridden below
            auth_token: None,
            disable_auth: true,
            config_path: None,
            daemon_mode: false,
            tls_cert: None,
            tls_key: None,
        },
        vec![],
    )
}

/// Start a test server with auth enabled and a specific token.
fn start_test_server_with_auth(token: &str) -> TestServer {
    start_test_server_with_config(
        CtlConfig {
            host: "127.0.0.1".into(),
            port: 0,
            auth_token: Some(token.to_string()),
            disable_auth: false,
            config_path: None,
            daemon_mode: false,
            tls_cert: None,
            tls_key: None,
        },
        vec![],
    )
}

/// Start a test server with the given config and interfaces.
fn start_test_server_with_config(
    mut cfg: CtlConfig,
    interfaces: Vec<InterfaceConfig>,
) -> TestServer {
    let port = find_free_port();
    cfg.port = port;
    cfg.host = "127.0.0.1".into();

    let shared_state: SharedState = Arc::new(RwLock::new(CtlState::new()));
    let ws_broadcast: WsBroadcast = Arc::new(Mutex::new(Vec::new()));

    let callbacks = Box::new(CtlCallbacks::new(
        shared_state.clone(),
        ws_broadcast.clone(),
    ));

    let identity = Identity::new(&mut OsRng);
    let node = RnsNode::start(
        NodeConfig {
            transport_enabled: false,
            identity: Some(Identity::from_private_key(
                &identity.get_private_key().unwrap(),
            )),
            interfaces,
            ..NodeConfig::default()
        },
        callbacks,
    )
    .expect("Failed to start test node");

    // Store identity in shared state
    {
        let mut s = shared_state.write().unwrap();
        s.identity_hash = Some(*identity.hash());
        if let Some(prv) = identity.get_private_key() {
            s.identity = Some(Identity::from_private_key(&prv));
        }
    }

    let node_handle: NodeHandle = Arc::new(Mutex::new(Some(node)));

    let ctx = Arc::new(ServerContext {
        node: node_handle,
        state: shared_state,
        ws_broadcast,
        config: Arc::new(RwLock::new(cfg)),
        #[cfg(feature = "tls")]
        tls_config: None,
    });

    let ctx2 = ctx.clone();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let thread = thread::Builder::new()
        .name("test-server".into())
        .spawn(move || {
            let _ = server::run_server(addr, ctx2);
        })
        .expect("Failed to spawn server thread");

    // Wait for listener to be ready
    wait_for_port(port);

    TestServer {
        ctx,
        port,
        _thread: thread,
    }
}

/// Poll until a TCP connection to the given port succeeds.
fn wait_for_port(port: u16) {
    for _ in 0..50 {
        if TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("Server did not start on port {} within 1s", port);
}

// ─── Raw HTTP Client Helpers ────────────────────────────────────────────────

struct HttpResult {
    status: u16,
    body: String,
}

impl HttpResult {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("Failed to parse JSON: {} body={}", e, self.body))
    }
}

fn http_get(port: u16, path: &str) -> HttpResult {
    http_request(port, "GET", path, None, None)
}

fn http_get_auth(port: u16, path: &str, token: &str) -> HttpResult {
    http_request(port, "GET", path, None, Some(token))
}

fn http_post(port: u16, path: &str, body: &str) -> HttpResult {
    http_request(port, "POST", path, Some(body), None)
}

#[allow(dead_code)]
fn http_post_auth(port: u16, path: &str, body: &str, token: &str) -> HttpResult {
    http_request(port, "POST", path, Some(body), Some(token))
}

fn http_request(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: Option<&str>,
) -> HttpResult {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).expect("Failed to connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let mut request = format!(
        "{} {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n",
        method, path
    );

    if let Some(token) = token {
        request.push_str(&format!("Authorization: Bearer {}\r\n", token));
    }

    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        request.push_str("Content-Type: application/json\r\n");
        request.push_str("\r\n");
        request.push_str(body);
    } else {
        request.push_str("\r\n");
    }

    stream
        .write_all(request.as_bytes())
        .expect("Failed to write request");

    let mut response = Vec::new();
    loop {
        let mut buf = [0u8; 4096];
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => panic!("Read error: {}", e),
        }
    }

    let response_str = String::from_utf8_lossy(&response);

    // Parse status line
    let status_line = response_str.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Extract body (after \r\n\r\n)
    let body = if let Some(pos) = response_str.find("\r\n\r\n") {
        response_str[pos + 4..].to_string()
    } else {
        String::new()
    };

    HttpResult { status, body }
}

fn sample_server_config_snapshot() -> ServerConfigSnapshot {
    ServerConfigSnapshot {
        config_path: Some("/tmp/rns".into()),
        resolved_config_dir: "/tmp/rns".into(),
        server_config_file_path: "/tmp/rns/rns-server.json".into(),
        server_config_file_present: true,
        server_config_file_json: "{\n  \"http\": {\n    \"port\": 8080\n  }\n}".into(),
        stats_db_path: "/tmp/rns/stats.db".into(),
        rnsd_bin: "rnsd".into(),
        sentineld_bin: "rns-sentineld".into(),
        statsd_bin: "rns-statsd".into(),
        http: ServerHttpConfigSnapshot {
            enabled: true,
            host: "127.0.0.1".into(),
            port: 8080,
            auth_mode: "disabled".into(),
            token_configured: false,
            daemon_mode: true,
        },
        launch_plan: vec![LaunchProcessSnapshot {
            name: "rnsd".into(),
            bin: "rnsd".into(),
            args: vec!["--config".into(), "/tmp/rns".into()],
            command_line: "rnsd --config /tmp/rns".into(),
        }],
    }
}

fn sample_server_config_schema() -> ServerConfigSchemaSnapshot {
    ServerConfigSchemaSnapshot {
        format: "rns-server.json".into(),
        example_config_json: "{\n  \"http\": {\n    \"port\": 8080\n  }\n}".into(),
        notes: vec!["Config note".into()],
        fields: vec![ServerConfigFieldSchema {
            field: "http.port".into(),
            field_type: "u16".into(),
            required: false,
            default_value: "8080".into(),
            description: "HTTP port".into(),
            effect: "restart rns-server".into(),
        }],
    }
}

fn sample_apply_plan() -> ServerConfigApplyPlan {
    ServerConfigApplyPlan {
        overall_action: "restart_children".into(),
        processes_to_restart: vec!["rns-statsd".into()],
        control_plane_reload_required: false,
        control_plane_restart_required: false,
        notes: vec!["Restart required for: rns-statsd.".into()],
        changes: vec![ServerConfigChange {
            field: "stats_db_path".into(),
            before: "/tmp/rns/stats.db".into(),
            after: "/tmp/rns/other.db".into(),
            effect: "restart rns-statsd".into(),
        }],
    }
}

// ─── Step 3a: Basic Server Lifecycle ────────────────────────────────────────

#[test]
fn test_health_endpoint() {
    let server = start_test_server();
    let res = http_get(server.port, "/health");
    assert_eq!(res.status, 200);
    let json = res.json();
    assert_eq!(json["status"], "healthy");
    server.shutdown();
}

// ─── Step 3b: Auth ──────────────────────────────────────────────────────────

#[test]
fn test_auth_required() {
    let server = start_test_server_with_auth("test-secret-token");
    let res = http_get(server.port, "/api/info");
    assert_eq!(res.status, 401);
    server.shutdown();
}

#[test]
fn test_auth_valid_token() {
    let server = start_test_server_with_auth("test-secret-token");
    let res = http_get_auth(server.port, "/api/info", "test-secret-token");
    assert_eq!(res.status, 200);
    server.shutdown();
}

#[test]
fn test_auth_invalid_token() {
    let server = start_test_server_with_auth("test-secret-token");
    let res = http_get_auth(server.port, "/api/info", "wrong-token");
    assert_eq!(res.status, 401);
    server.shutdown();
}

#[test]
fn test_health_no_auth() {
    let server = start_test_server_with_auth("test-secret-token");
    // /health should be accessible without auth even when auth is enabled
    let res = http_get(server.port, "/health");
    assert_eq!(res.status, 200);
    assert_eq!(res.json()["status"], "healthy");
    server.shutdown();
}

// ─── Step 3c: Read Endpoints (empty node) ───────────────────────────────────

#[test]
fn test_get_info() {
    let server = start_test_server();
    let res = http_get(server.port, "/api/info");
    assert_eq!(res.status, 200);
    let json = res.json();
    // Should have identity_hash (32 hex chars)
    let identity_hash = json["identity_hash"].as_str().unwrap();
    assert_eq!(identity_hash.len(), 32);
    // Uptime should be a small number
    let uptime = json["uptime_seconds"].as_f64().unwrap();
    assert!(uptime < 30.0);
    server.shutdown();
}

#[test]
fn test_get_interfaces_empty() {
    let server = start_test_server();
    let res = http_get(server.port, "/api/interfaces");
    assert_eq!(res.status, 200);
    let json = res.json();
    let ifaces = json["interfaces"].as_array().unwrap();
    assert!(ifaces.is_empty());
    server.shutdown();
}

#[test]
fn test_get_destinations_initial() {
    let server = start_test_server();
    let res = http_get(server.port, "/api/destinations");
    assert_eq!(res.status, 200);
    let json = res.json();
    // The node auto-registers internal protocol destinations (tunnel synth, path request),
    // so the list may not be empty. Just verify the response is valid.
    assert!(json["destinations"].as_array().is_some());
    server.shutdown();
}

#[test]
fn test_get_paths_empty() {
    let server = start_test_server();
    let res = http_get(server.port, "/api/paths");
    assert_eq!(res.status, 200);
    let json = res.json();
    let paths = json["paths"].as_array().unwrap();
    assert!(paths.is_empty());
    server.shutdown();
}

#[test]
fn test_get_links_empty() {
    let server = start_test_server();
    let res = http_get(server.port, "/api/links");
    assert_eq!(res.status, 200);
    let json = res.json();
    let links = json["links"].as_array().unwrap();
    assert!(links.is_empty());
    server.shutdown();
}

#[test]
fn test_get_resources_empty() {
    let server = start_test_server();
    let res = http_get(server.port, "/api/resources");
    assert_eq!(res.status, 200);
    let json = res.json();
    let resources = json["resources"].as_array().unwrap();
    assert!(resources.is_empty());
    server.shutdown();
}

#[test]
fn test_get_announces_empty() {
    let server = start_test_server();
    let res = http_get(server.port, "/api/announces");
    assert_eq!(res.status, 200);
    let json = res.json();
    let announces = json["announces"].as_array().unwrap();
    assert!(announces.is_empty());
    server.shutdown();
}

#[test]
fn test_clear_announce_queues() {
    let server = start_test_server();
    let res = http_post(server.port, "/api/announce_queues/clear", "{}");
    assert_eq!(res.status, 200);
    assert_eq!(res.json()["status"], "ok");
    server.shutdown();
}

#[test]
fn test_get_packets_empty() {
    let server = start_test_server();
    let res = http_get(server.port, "/api/packets");
    assert_eq!(res.status, 200);
    let json = res.json();
    let packets = json["packets"].as_array().unwrap();
    assert!(packets.is_empty());
    server.shutdown();
}

#[test]
fn test_get_proofs_empty() {
    let server = start_test_server();
    let res = http_get(server.port, "/api/proofs");
    assert_eq!(res.status, 200);
    let json = res.json();
    let proofs = json["proofs"].as_array().unwrap();
    assert!(proofs.is_empty());
    server.shutdown();
}

#[test]
fn test_get_config_snapshot() {
    let server = start_test_server();
    {
        let mut state = server.ctx.state.write().unwrap();
        state.server_config = Some(sample_server_config_snapshot());
    }

    let res = http_get(server.port, "/api/config");
    assert_eq!(res.status, 200);
    let json = res.json();
    assert_eq!(json["config"]["stats_db_path"], "/tmp/rns/stats.db");
    assert_eq!(json["config"]["rnsd_bin"], "rnsd");
    assert_eq!(json["config"]["launch_plan"][0]["name"], "rnsd");
    server.shutdown();
}

#[test]
fn test_get_config_schema() {
    let server = start_test_server();
    {
        let mut state = server.ctx.state.write().unwrap();
        state.server_config_schema = Some(sample_server_config_schema());
    }

    let res = http_get(server.port, "/api/config/schema");
    assert_eq!(res.status, 200);
    let json = res.json();
    assert_eq!(json["schema"]["format"], "rns-server.json");
    assert_eq!(json["schema"]["fields"][0]["field"], "http.port");
    server.shutdown();
}

#[test]
fn test_get_config_status() {
    let server = start_test_server();
    {
        let mut state = server.ctx.state.write().unwrap();
        state.server_config_status = ServerConfigStatusState {
            last_action: Some("save".into()),
            control_plane_reload_required: true,
            runtime_differs_from_saved: true,
            last_apply_plan: Some(ServerConfigApplyPlan {
                overall_action: "reload_control_plane".into(),
                processes_to_restart: Vec::new(),
                control_plane_reload_required: true,
                control_plane_restart_required: false,
                notes: vec![
                    "Embedded control-plane auth settings will be reloaded in place.".into(),
                ],
                changes: vec![ServerConfigChange {
                    field: "http.auth_token".into(),
                    before: "unset".into(),
                    after: "set(10 chars)".into(),
                    effect: "reload embedded HTTP auth".into(),
                }],
            }),
            ..ServerConfigStatusState::default()
        };
    }

    let res = http_get(server.port, "/api/config/status");
    assert_eq!(res.status, 200);
    let json = res.json();
    assert_eq!(json["status"]["last_action"], "save");
    assert_eq!(json["status"]["converged"], false);
    assert_eq!(json["status"]["pending_action"], "reload_control_plane");
    assert_eq!(json["status"]["pending_targets"][0], "embedded-http-auth");
    assert!(json["status"]["blocking_reason"]
        .as_str()
        .unwrap()
        .contains("Apply config"));
    server.shutdown();
}

#[test]
fn test_get_processes_exposes_log_metadata() {
    let server = start_test_server();
    {
        let mut state = server.ctx.state.write().unwrap();
        state.processes.insert(
            "rns-statsd".into(),
            ManagedProcessState {
                name: "rns-statsd".into(),
                status: "running".into(),
                ready: true,
                ready_state: "ready".into(),
                pid: Some(4242),
                last_exit_code: None,
                restart_count: 2,
                last_error: None,
                status_detail: Some("stats pipeline active".into()),
                durable_log_path: Some("/tmp/rns/logs/rns-statsd.log".into()),
                last_log_at: Some(std::time::Instant::now()),
                recent_log_lines: 3,
                started_at: Some(std::time::Instant::now()),
                last_transition_at: Some(std::time::Instant::now()),
            },
        );
    }

    let res = http_get(server.port, "/api/processes");
    assert_eq!(res.status, 200);
    let json = res.json();
    assert_eq!(
        json["processes"][0]["durable_log_path"],
        "/tmp/rns/logs/rns-statsd.log"
    );
    assert_eq!(json["processes"][0]["recent_log_lines"], 3);
    assert!(json["processes"][0]["last_log_age_seconds"]
        .as_f64()
        .is_some());
    server.shutdown();
}

#[test]
fn test_get_processes_exposes_readiness_and_failure_detail() {
    let server = start_test_server();
    {
        let mut state = server.ctx.state.write().unwrap();
        state.processes.insert(
            "rns-sentineld".into(),
            ManagedProcessState {
                name: "rns-sentineld".into(),
                status: "failed".into(),
                ready: false,
                ready_state: "not-ready".into(),
                pid: None,
                last_exit_code: Some(17),
                restart_count: 4,
                last_error: Some("hook registration timed out".into()),
                status_detail: Some("waiting for provider bridge".into()),
                durable_log_path: Some("/tmp/rns/logs/rns-sentineld.log".into()),
                last_log_at: Some(std::time::Instant::now()),
                recent_log_lines: 12,
                started_at: None,
                last_transition_at: Some(std::time::Instant::now()),
            },
        );
    }

    let res = http_get(server.port, "/api/processes");
    assert_eq!(res.status, 200);
    let json = res.json();
    assert_eq!(json["processes"][0]["name"], "rns-sentineld");
    assert_eq!(json["processes"][0]["ready_state"], "not-ready");
    assert_eq!(json["processes"][0]["restart_count"], 4);
    assert_eq!(json["processes"][0]["last_exit_code"], 17);
    assert_eq!(
        json["processes"][0]["last_error"],
        "hook registration timed out"
    );
    assert_eq!(
        json["processes"][0]["status_detail"],
        "waiting for provider bridge"
    );
    server.shutdown();
}

#[test]
fn test_get_process_logs_exposes_log_metadata() {
    let server = start_test_server();
    ensure_process(&server.ctx.state, "rns-statsd");
    {
        let mut state = server.ctx.state.write().unwrap();
        let process = state.processes.get_mut("rns-statsd").unwrap();
        process.durable_log_path = Some("/tmp/rns/logs/rns-statsd.log".into());
    }
    push_process_log(&server.ctx.state, "rns-statsd", "stdout", "statsd started");

    let res = http_get(server.port, "/api/processes/rns-statsd/logs");
    assert_eq!(res.status, 200);
    let json = res.json();
    assert_eq!(json["process"], "rns-statsd");
    assert_eq!(json["durable_log_path"], "/tmp/rns/logs/rns-statsd.log");
    assert_eq!(json["recent_log_lines"], 1);
    assert_eq!(json["lines"][0]["line"], "statsd started");
    assert!(json["last_log_age_seconds"].as_f64().is_some());
    server.shutdown();
}

#[test]
fn test_get_process_logs_limit_and_missing_process() {
    let server = start_test_server();
    ensure_process(&server.ctx.state, "rns-statsd");
    push_process_log(&server.ctx.state, "rns-statsd", "stdout", "line one");
    push_process_log(&server.ctx.state, "rns-statsd", "stdout", "line two");
    push_process_log(&server.ctx.state, "rns-statsd", "stderr", "line three");

    let limited = http_get(server.port, "/api/processes/rns-statsd/logs?limit=2");
    assert_eq!(limited.status, 200);
    let limited_json = limited.json();
    let lines = limited_json["lines"].as_array().unwrap();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["line"], "line three");
    assert_eq!(lines[1]["line"], "line two");

    let missing = http_get(server.port, "/api/processes/missing/logs");
    assert_eq!(missing.status, 404);
    server.shutdown();
}

#[test]
fn test_config_validate_endpoint_uses_validator() {
    let server = start_test_server();
    {
        let mut state = server.ctx.state.write().unwrap();
        state.server_config_validator = Some(Arc::new(|body| {
            let parsed: serde_json::Value = serde_json::from_slice(body).unwrap();
            assert_eq!(parsed["http"]["port"], 9090);
            Ok(ServerConfigValidationSnapshot {
                valid: true,
                config: sample_server_config_snapshot(),
                warnings: vec!["validation warning".into()],
            })
        }));
    }

    let res = http_post(
        server.port,
        "/api/config/validate",
        r#"{"http":{"port":9090}}"#,
    );
    assert_eq!(res.status, 200);
    let json = res.json();
    assert_eq!(json["result"]["valid"], true);
    assert_eq!(json["result"]["warnings"][0], "validation warning");
    server.shutdown();
}

#[test]
fn test_config_save_endpoint_uses_mutator() {
    let server = start_test_server();
    {
        let mut state = server.ctx.state.write().unwrap();
        state.server_config_mutator = Some(Arc::new(|mode, body| {
            match mode {
                rns_ctl::state::ServerConfigMutationMode::Save => {}
                _ => panic!("expected save mode"),
            }
            let parsed: serde_json::Value = serde_json::from_slice(body).unwrap();
            assert_eq!(parsed["stats_db_path"], "/tmp/rns/other.db");
            Ok(ServerConfigMutationResult {
                action: "save".into(),
                config: sample_server_config_snapshot(),
                apply_plan: sample_apply_plan(),
                warnings: vec!["save warning".into()],
            })
        }));
    }

    let res = http_post(
        server.port,
        "/api/config",
        r#"{"stats_db_path":"/tmp/rns/other.db"}"#,
    );
    assert_eq!(res.status, 200);
    let json = res.json();
    assert_eq!(json["result"]["action"], "save");
    assert_eq!(
        json["result"]["apply_plan"]["overall_action"],
        "restart_children"
    );
    assert_eq!(json["result"]["warnings"][0], "save warning");
    assert_eq!(
        json["result"]["apply_plan"]["processes_to_restart"][0],
        "rns-statsd"
    );
    server.shutdown();
}

#[test]
fn test_config_apply_endpoint_uses_mutator() {
    let server = start_test_server();
    {
        let mut state = server.ctx.state.write().unwrap();
        state.server_config_mutator = Some(Arc::new(|mode, _body| {
            match mode {
                rns_ctl::state::ServerConfigMutationMode::Apply => {}
                _ => panic!("expected apply mode"),
            }
            Ok(ServerConfigMutationResult {
                action: "apply".into(),
                config: sample_server_config_snapshot(),
                apply_plan: sample_apply_plan(),
                warnings: Vec::new(),
            })
        }));
    }

    let res = http_post(
        server.port,
        "/api/config/apply",
        r#"{"stats_db_path":"/tmp/rns/other.db"}"#,
    );
    assert_eq!(res.status, 200);
    let json = res.json();
    assert_eq!(json["result"]["action"], "apply");
    assert_eq!(
        json["result"]["apply_plan"]["overall_action"],
        "restart_children"
    );
    assert_eq!(
        json["result"]["apply_plan"]["changes"][0]["field"],
        "stats_db_path"
    );
    server.shutdown();
}

#[test]
fn test_config_validate_endpoint_returns_bad_request_on_validation_error() {
    let server = start_test_server();
    {
        let mut state = server.ctx.state.write().unwrap();
        state.server_config_validator = Some(Arc::new(|_body| {
            Err("stats_db_path must be absolute".into())
        }));
    }

    let res = http_post(
        server.port,
        "/api/config/validate",
        r#"{"stats_db_path":"relative.db"}"#,
    );
    assert_eq!(res.status, 400);
    assert_eq!(res.json()["error"], "stats_db_path must be absolute");
    server.shutdown();
}

#[test]
fn test_get_config_status_reports_restart_pending_targets() {
    let server = start_test_server();
    {
        let mut state = server.ctx.state.write().unwrap();
        state.server_config_status = ServerConfigStatusState {
            last_action: Some("apply".into()),
            runtime_differs_from_saved: true,
            pending_process_restarts: vec!["rns-statsd".into()],
            control_plane_restart_required: true,
            last_apply_plan: Some(ServerConfigApplyPlan {
                overall_action: "restart_children_and_server".into(),
                processes_to_restart: vec!["rns-statsd".into()],
                control_plane_reload_required: false,
                control_plane_restart_required: true,
                notes: vec!["Restart required for: rns-statsd and embedded HTTP bind.".into()],
                changes: vec![
                    ServerConfigChange {
                        field: "stats_db_path".into(),
                        before: "/tmp/rns/stats.db".into(),
                        after: "/tmp/rns/other.db".into(),
                        effect: "restart rns-statsd".into(),
                    },
                    ServerConfigChange {
                        field: "http.port".into(),
                        before: "8080".into(),
                        after: "9090".into(),
                        effect: "restart rns-server".into(),
                    },
                ],
            }),
            ..ServerConfigStatusState::default()
        };
    }

    let res = http_get(server.port, "/api/config/status");
    assert_eq!(res.status, 200);
    let json = res.json();
    assert_eq!(
        json["status"]["pending_action"],
        "restart_children_and_server"
    );
    assert_eq!(json["status"]["pending_targets"][0], "rns-statsd");
    assert_eq!(json["status"]["pending_targets"][1], "rns-server");
    assert!(json["status"]["blocking_reason"]
        .as_str()
        .unwrap()
        .contains("Restart rns-server"));
    server.shutdown();
}

#[test]
fn test_process_control_returns_internal_error_without_supervisor() {
    let server = start_test_server();
    let res = http_post(server.port, "/api/processes/rns-statsd/restart", "{}");
    assert_eq!(res.status, 500);
    assert_eq!(res.json()["error"], "Process control is not enabled");
    server.shutdown();
}

#[test]
fn test_process_control_queues_commands_when_supervision_enabled() {
    let server = start_test_server();
    let (tx, rx) = mpsc::channel();
    {
        let mut state = server.ctx.state.write().unwrap();
        state.control_tx = Some(tx);
    }

    let res = http_post(server.port, "/api/processes/rns-statsd/restart", "{}");
    assert_eq!(res.status, 200);
    assert_eq!(res.json()["queued"], true);
    assert_eq!(res.json()["action"], "restart");
    assert_eq!(res.json()["process"], "rns-statsd");
    match rx.recv_timeout(Duration::from_secs(1)).unwrap() {
        rns_ctl::state::ProcessControlCommand::Restart(name) => {
            assert_eq!(name, "rns-statsd");
        }
        _ => panic!("unexpected command variant"),
    }
    server.shutdown();
}

// ─── Step 3d: Destination Registration + Announce ───────────────────────────

#[test]
fn test_register_single_destination() {
    let server = start_test_server();
    let body = r#"{"type":"single","app_name":"test_app","aspects":["echo"]}"#;
    let res = http_post(server.port, "/api/destination", body);
    assert_eq!(res.status, 201);
    let json = res.json();
    assert_eq!(json["type"], "single");
    assert_eq!(json["name"], "test_app.echo");
    // dest_hash should be 32 hex chars
    let dh = json["dest_hash"].as_str().unwrap();
    assert_eq!(dh.len(), 32);
    server.shutdown();
}

#[test]
fn test_register_plain_destination() {
    let server = start_test_server();
    let body = r#"{"type":"plain","app_name":"test_app","aspects":["broadcast"]}"#;
    let res = http_post(server.port, "/api/destination", body);
    assert_eq!(res.status, 201);
    let json = res.json();
    assert_eq!(json["type"], "plain");
    assert_eq!(json["name"], "test_app.broadcast");
    server.shutdown();
}

#[test]
fn test_register_group_destination() {
    let server = start_test_server();
    let body = r#"{"type":"group","app_name":"test_app","aspects":["group"]}"#;
    let res = http_post(server.port, "/api/destination", body);
    assert_eq!(res.status, 201);
    let json = res.json();
    assert_eq!(json["type"], "group");
    // GROUP should return a group_key
    let gk = json["group_key"].as_str().unwrap();
    assert!(!gk.is_empty());
    server.shutdown();
}

#[test]
fn test_destinations_after_register() {
    let server = start_test_server();

    // Register a destination
    let body = r#"{"type":"plain","app_name":"myapp","aspects":["test"]}"#;
    let reg = http_post(server.port, "/api/destination", body);
    assert_eq!(reg.status, 201);
    let dest_hash = reg.json()["dest_hash"].as_str().unwrap().to_string();

    // GET destinations should now show it
    let res = http_get(server.port, "/api/destinations");
    assert_eq!(res.status, 200);
    let json = res.json();
    let dests = json["destinations"].as_array().unwrap();
    assert!(dests.iter().any(|d| d["hash"].as_str() == Some(&dest_hash)));

    server.shutdown();
}

#[test]
fn test_announce_destination() {
    let server = start_test_server();

    // Register a SINGLE destination first
    let body = r#"{"type":"single","app_name":"test_app","aspects":["ann"]}"#;
    let reg = http_post(server.port, "/api/destination", body);
    assert_eq!(reg.status, 201);
    let dest_hash = reg.json()["dest_hash"].as_str().unwrap().to_string();

    // Announce it
    let ann_body = format!(r#"{{"dest_hash":"{}"}}"#, dest_hash);
    let res = http_post(server.port, "/api/announce", &ann_body);
    assert_eq!(res.status, 200);
    let json = res.json();
    assert_eq!(json["status"], "announced");

    server.shutdown();
}

#[test]
fn test_register_bad_type() {
    let server = start_test_server();
    let body = r#"{"type":"invalid","app_name":"test_app","aspects":["echo"]}"#;
    let res = http_post(server.port, "/api/destination", body);
    assert_eq!(res.status, 400);
    server.shutdown();
}

// ─── Step 3e: Packet + Path Operations ──────────────────────────────────────

#[test]
fn test_send_packet_no_dest() {
    let server = start_test_server();
    let body = r#"{"dest_hash":"00000000000000000000000000000000","data":"aGVsbG8="}"#;
    let res = http_post(server.port, "/api/send", body);
    assert_eq!(res.status, 400); // destination not registered
    server.shutdown();
}

#[test]
fn test_path_request() {
    let server = start_test_server();
    let body = r#"{"dest_hash":"00000000000000000000000000000000"}"#;
    let res = http_post(server.port, "/api/path/request", body);
    // Should succeed (200) — no interface to send on, but the call itself doesn't fail
    assert!(res.status == 200 || res.status == 500);
    server.shutdown();
}

// ─── Step 3f: Error Handling ────────────────────────────────────────────────

#[test]
fn test_not_found() {
    let server = start_test_server();
    let res = http_get(server.port, "/nonexistent");
    assert_eq!(res.status, 404);
    server.shutdown();
}

#[test]
fn test_bad_json() {
    let server = start_test_server();
    let res = http_post(server.port, "/api/destination", "not-json");
    assert_eq!(res.status, 400);
    let json = res.json();
    assert!(json["error"].as_str().unwrap().contains("Invalid JSON"));
    server.shutdown();
}

#[test]
fn test_missing_fields() {
    let server = start_test_server();
    // Missing app_name
    let body = r#"{"type":"single","aspects":["echo"]}"#;
    let res = http_post(server.port, "/api/destination", body);
    assert_eq!(res.status, 400);
    let json = res.json();
    assert!(json["error"].as_str().unwrap().contains("app_name"));
    server.shutdown();
}

// ─── Step 4: Two-Node Tests ────────────────────────────────────────────────

struct TestPair {
    server_a: TestServer,
    server_b: TestServer,
}

impl TestPair {
    fn shutdown(&self) {
        self.server_b.shutdown();
        self.server_a.shutdown();
    }
}

/// Start two nodes connected via TCP loopback.
/// Node A runs a TCP server interface, node B connects as TCP client.
fn start_test_pair() -> TestPair {
    let tcp_port = find_free_port();
    let http_port_a = find_free_port();
    let http_port_b = find_free_port();

    // ─── Node A: TCP server ─────────────────────────────────────────────
    let cfg_a = CtlConfig {
        host: "127.0.0.1".into(),
        port: http_port_a,
        auth_token: None,
        disable_auth: true,
        config_path: None,
        daemon_mode: false,
        tls_cert: None,
        tls_key: None,
    };

    let ifaces_a = vec![InterfaceConfig {
        name: String::new(),
        type_name: "TCPServerInterface".to_string(),
        config_data: Box::new(TcpServerConfig {
            name: "Test TCP Server".into(),
            listen_ip: "127.0.0.1".into(),
            listen_port: tcp_port,
            interface_id: InterfaceId(1),
            max_connections: None,
            ..TcpServerConfig::default()
        }),
        mode: MODE_FULL,
        ifac: None,
        discovery: None,
    }];

    let server_a = start_test_server_with_config(cfg_a, ifaces_a);

    // ─── Node B: TCP client ─────────────────────────────────────────────
    let cfg_b = CtlConfig {
        host: "127.0.0.1".into(),
        port: http_port_b,
        auth_token: None,
        disable_auth: true,
        config_path: None,
        daemon_mode: false,
        tls_cert: None,
        tls_key: None,
    };

    let ifaces_b = vec![InterfaceConfig {
        name: String::new(),
        type_name: "TCPClientInterface".to_string(),
        config_data: Box::new(TcpClientConfig {
            name: "Test TCP Client".into(),
            target_host: "127.0.0.1".into(),
            target_port: tcp_port,
            interface_id: InterfaceId(1),
            ..Default::default()
        }),
        mode: MODE_FULL,
        ifac: None,
        discovery: None,
    }];

    let server_b = start_test_server_with_config(cfg_b, ifaces_b);

    // Wait for TCP connection to establish
    thread::sleep(Duration::from_secs(1));

    TestPair { server_a, server_b }
}

#[test]
fn test_announce_propagation() {
    let pair = start_test_pair();

    // Register + announce on node A
    let body = r#"{"type":"single","app_name":"test_prop","aspects":["echo"]}"#;
    let reg = http_post(pair.server_a.port, "/api/destination", body);
    assert_eq!(reg.status, 201);
    let dest_hash = reg.json()["dest_hash"].as_str().unwrap().to_string();

    let ann_body = format!(r#"{{"dest_hash":"{}"}}"#, dest_hash);
    let ann = http_post(pair.server_a.port, "/api/announce", &ann_body);
    assert_eq!(ann.status, 200);

    // Poll for announce propagation (up to 10 seconds)
    let mut found = false;
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(500));
        let res = http_get(pair.server_b.port, "/api/announces");
        if res.status == 200 {
            let json = res.json();
            if let Some(announces) = json["announces"].as_array() {
                if announces
                    .iter()
                    .any(|a| a["dest_hash"].as_str() == Some(&dest_hash))
                {
                    found = true;
                    break;
                }
            }
        }
    }

    assert!(
        found,
        "Node B should have received the announce from Node A within 10s"
    );

    pair.shutdown();
}

#[test]
fn test_identity_recall() {
    let pair = start_test_pair();

    // Register + announce on A
    let body = r#"{"type":"single","app_name":"test_recall","aspects":["id"]}"#;
    let reg = http_post(pair.server_a.port, "/api/destination", body);
    assert_eq!(reg.status, 201);
    let dest_hash = reg.json()["dest_hash"].as_str().unwrap().to_string();

    let ann_body = format!(r#"{{"dest_hash":"{}"}}"#, dest_hash);
    let ann = http_post(pair.server_a.port, "/api/announce", &ann_body);
    assert_eq!(ann.status, 200);

    // Poll for identity recall on B (up to 10 seconds)
    let mut recalled = false;
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(500));
        let res = http_get(pair.server_b.port, &format!("/api/identity/{}", dest_hash));
        if res.status == 200 {
            let json = res.json();
            assert_eq!(json["dest_hash"].as_str().unwrap(), dest_hash);
            let ih = json["identity_hash"].as_str().unwrap();
            assert_eq!(ih.len(), 32);
            let pk = json["public_key"].as_str().unwrap();
            assert_eq!(pk.len(), 128);
            recalled = true;
            break;
        }
    }

    assert!(
        recalled,
        "Node B should have recalled the identity from Node A within 10s"
    );

    pair.shutdown();
}

#[test]
fn test_packet_delivery() {
    let pair = start_test_pair();

    // Register SINGLE destination on A (inbound) with ProveAll
    let reg_body =
        r#"{"type":"single","app_name":"test_delivery","aspects":["pkt"],"proof_strategy":"all"}"#;
    let reg = http_post(pair.server_a.port, "/api/destination", reg_body);
    assert_eq!(reg.status, 201);
    let dest_hash = reg.json()["dest_hash"].as_str().unwrap().to_string();

    // Announce from A so B learns the path + identity
    let ann_body = format!(r#"{{"dest_hash":"{}"}}"#, dest_hash);
    let ann = http_post(pair.server_a.port, "/api/announce", &ann_body);
    assert_eq!(ann.status, 200);

    // Poll for identity recall on B (announce must propagate before we can create outbound dest)
    let mut ready = false;
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(500));
        let res = http_get(pair.server_b.port, &format!("/api/identity/{}", dest_hash));
        if res.status == 200 {
            ready = true;
            break;
        }
    }
    assert!(ready, "Announce should propagate to Node B within 10s");

    // On B, create outbound SINGLE destination to the same address
    let out_body = format!(
        r#"{{"type":"single","app_name":"test_delivery","aspects":["pkt"],"direction":"out","dest_hash":"{}"}}"#,
        dest_hash
    );
    let out_reg = http_post(pair.server_b.port, "/api/destination", &out_body);
    assert_eq!(
        out_reg.status, 201,
        "Failed to register outbound destination: {}",
        out_reg.body
    );
    let out_hash = out_reg.json()["dest_hash"].as_str().unwrap().to_string();

    // Send packet from B
    let send_body = format!(
        r#"{{"dest_hash":"{}","data":"aGVsbG8gd29ybGQ="}}"#,
        out_hash
    );
    let send = http_post(pair.server_b.port, "/api/send", &send_body);
    assert_eq!(send.status, 200, "Failed to send packet: {}", send.body);

    // Poll for packet delivery on A (up to 10 seconds)
    let mut delivered = false;
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(500));
        let res = http_get(pair.server_a.port, "/api/packets");
        if res.status == 200 {
            let json = res.json();
            if let Some(packets) = json["packets"].as_array() {
                if !packets.is_empty() {
                    delivered = true;
                    break;
                }
            }
        }
    }

    assert!(
        delivered,
        "Node A should have received at least one packet within 10s"
    );

    pair.shutdown();
}

// ─── TLS Tests ──────────────────────────────────────────────────────────────

#[cfg(feature = "tls")]
mod tls_tests {
    use super::*;

    use std::io::{Read, Write};
    use std::sync::Arc;

    /// Start a test server with TLS enabled using self-signed certs.
    fn start_tls_test_server() -> (TestServer, Arc<rustls::RootCertStore>) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        // Write cert and key to temp files (unique per call to avoid parallel test conflicts)
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let tmp_dir =
            std::env::temp_dir().join(format!("rns-ctl-tls-test-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cert_path = tmp_dir.join("cert.pem");
        let key_path = tmp_dir.join("key.pem");
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();

        let tls_config =
            rns_ctl::tls::load_tls_config(cert_path.to_str().unwrap(), key_path.to_str().unwrap())
                .expect("Failed to load TLS config");

        let port = find_free_port();

        let cfg = CtlConfig {
            host: "127.0.0.1".into(),
            port,
            auth_token: None,
            disable_auth: true,
            config_path: None,
            daemon_mode: false,
            tls_cert: Some(cert_path.to_str().unwrap().into()),
            tls_key: Some(key_path.to_str().unwrap().into()),
        };

        let shared_state: SharedState = Arc::new(RwLock::new(CtlState::new()));
        let ws_broadcast: WsBroadcast = Arc::new(Mutex::new(Vec::new()));

        let callbacks = Box::new(CtlCallbacks::new(
            shared_state.clone(),
            ws_broadcast.clone(),
        ));

        let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::OsRng);
        let node = RnsNode::start(
            NodeConfig {
                transport_enabled: false,
                identity: Some(rns_crypto::identity::Identity::from_private_key(
                    &identity.get_private_key().unwrap(),
                )),
                interfaces: vec![],
                ..NodeConfig::default()
            },
            callbacks,
        )
        .expect("Failed to start test node");

        {
            let mut s = shared_state.write().unwrap();
            s.identity_hash = Some(*identity.hash());
            if let Some(prv) = identity.get_private_key() {
                s.identity = Some(rns_crypto::identity::Identity::from_private_key(&prv));
            }
        }

        let node_handle: NodeHandle = Arc::new(Mutex::new(Some(node)));

        let ctx = Arc::new(ServerContext {
            node: node_handle,
            state: shared_state,
            ws_broadcast,
            config: cfg,
            tls_config: Some(tls_config),
        });

        let ctx2 = ctx.clone();
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

        let handle = thread::Builder::new()
            .name("test-tls-server".into())
            .spawn(move || {
                let _ = server::run_server(addr, ctx2);
            })
            .expect("Failed to spawn TLS server thread");

        // Wait for the port to accept TCP connections
        wait_for_port(port);

        // Build a root cert store with our self-signed cert
        let mut root_store = rustls::RootCertStore::empty();
        let der_cert = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        for c in der_cert {
            root_store.add(c).unwrap();
        }

        let server = TestServer {
            ctx,
            port,
            _thread: handle,
        };

        (server, Arc::new(root_store))
    }

    fn tls_http_get(
        port: u16,
        path: &str,
        root_store: &Arc<rustls::RootCertStore>,
    ) -> super::HttpResult {
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store.clone())
            .with_no_client_auth();

        let server_name: rustls::pki_types::ServerName = "localhost".try_into().unwrap();

        let mut conn = rustls::ClientConnection::new(Arc::new(tls_config), server_name).unwrap();
        let mut tcp = TcpStream::connect(format!("127.0.0.1:{}", port)).expect("Failed to connect");
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

        let request = format!(
            "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            path
        );
        tls.write_all(request.as_bytes())
            .expect("Failed to write request");

        let mut response = Vec::new();
        loop {
            let mut buf = [0u8; 4096];
            match tls.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => break,
                Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("TLS read error: {}", e),
            }
        }

        let response_str = String::from_utf8_lossy(&response);
        let status_line = response_str.lines().next().unwrap_or("");
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let body = if let Some(pos) = response_str.find("\r\n\r\n") {
            response_str[pos + 4..].to_string()
        } else {
            String::new()
        };

        super::HttpResult { status, body }
    }

    #[test]
    fn test_tls_health_endpoint() {
        let (server, root_store) = start_tls_test_server();
        let res = tls_http_get(server.port, "/health", &root_store);
        assert_eq!(res.status, 200);
        let json = res.json();
        assert_eq!(json["status"], "healthy");
        server.shutdown();
    }

    #[test]
    fn test_tls_api_info() {
        let (server, root_store) = start_tls_test_server();
        let res = tls_http_get(server.port, "/api/info", &root_store);
        assert_eq!(res.status, 200);
        let json = res.json();
        let identity_hash = json["identity_hash"].as_str().unwrap();
        assert_eq!(identity_hash.len(), 32);
        server.shutdown();
    }

    #[test]
    fn test_tls_plain_connection_rejected() {
        let (server, _root_store) = start_tls_test_server();
        // A plain HTTP request to a TLS server should fail
        let mut tcp =
            TcpStream::connect(format!("127.0.0.1:{}", server.port)).expect("Failed to connect");
        tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let request = "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        let _ = tcp.write_all(request.as_bytes());
        // Read — should get garbage or error, not a valid HTTP response
        let mut response = Vec::new();
        loop {
            let mut buf = [0u8; 4096];
            match tcp.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        let response_str = String::from_utf8_lossy(&response);
        // Should NOT contain a valid HTTP status line
        assert!(
            !response_str.contains("HTTP/1.1 200"),
            "Plain HTTP should not get a valid response from TLS server"
        );
        server.shutdown();
    }
}
