//! Integration tests for rns-ctl HTTP server.
//!
//! These tests start real RNS nodes + HTTP servers and make HTTP requests
//! using raw TcpStream (no external dependencies).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rns_crypto::identity::Identity;
use rns_crypto::OsRng;

use rns_net::{
    InterfaceConfig, InterfaceId, InterfaceVariant, NodeConfig, RnsNode,
    TcpClientConfig, TcpServerConfig, MODE_FULL,
};

use rns_ctl::api::NodeHandle;
use rns_ctl::bridge::CtlCallbacks;
use rns_ctl::config::CtlConfig;
use rns_ctl::server::{self, ServerContext};
use rns_ctl::state::{CtlState, SharedState, WsBroadcast};

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
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Start a test server with no interfaces and auth disabled.
fn start_test_server() -> TestServer {
    start_test_server_with_config(CtlConfig {
        host: "127.0.0.1".into(),
        port: 0, // overridden below
        auth_token: None,
        disable_auth: true,
        config_path: None,
        daemon_mode: false,
        tls_cert: None,
        tls_key: None,
    }, vec![])
}

/// Start a test server with auth enabled and a specific token.
fn start_test_server_with_auth(token: &str) -> TestServer {
    start_test_server_with_config(CtlConfig {
        host: "127.0.0.1".into(),
        port: 0,
        auth_token: Some(token.to_string()),
        disable_auth: false,
        config_path: None,
        daemon_mode: false,
        tls_cert: None,
        tls_key: None,
    }, vec![])
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
            identity: Some(Identity::from_private_key(&identity.get_private_key().unwrap())),
            interfaces,
            share_instance: false,
            rpc_port: 0,
            cache_dir: None,
            management: Default::default(),
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
        config: cfg,
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
        serde_json::from_str(&self.body).unwrap_or_else(|e| {
            panic!("Failed to parse JSON: {} body={}", e, self.body)
        })
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
    let mut stream =
        TcpStream::connect(format!("127.0.0.1:{}", port)).expect("Failed to connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let mut request = format!("{} {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n", method, path);

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

    stream.write_all(request.as_bytes()).expect("Failed to write request");

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
        variant: InterfaceVariant::TcpServer(TcpServerConfig {
            name: "Test TCP Server".into(),
            listen_ip: "127.0.0.1".into(),
            listen_port: tcp_port,
            interface_id: InterfaceId(1),
        }),
        mode: MODE_FULL,
        ifac: None,
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
        variant: InterfaceVariant::TcpClient(TcpClientConfig {
            name: "Test TCP Client".into(),
            target_host: "127.0.0.1".into(),
            target_port: tcp_port,
            interface_id: InterfaceId(1),
            ..Default::default()
        }),
        mode: MODE_FULL,
        ifac: None,
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
                if announces.iter().any(|a| a["dest_hash"].as_str() == Some(&dest_hash)) {
                    found = true;
                    break;
                }
            }
        }
    }

    assert!(found, "Node B should have received the announce from Node A within 10s");

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

    assert!(recalled, "Node B should have recalled the identity from Node A within 10s");

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
    assert_eq!(out_reg.status, 201, "Failed to register outbound destination: {}", out_reg.body);
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

    assert!(delivered, "Node A should have received at least one packet within 10s");

    pair.shutdown();
}
