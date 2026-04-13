//! End-to-end tests for rns-net.
//!
//! Exercises the full RnsNode network layer over real TCP/UDP transports:
//! announces, encrypted messaging, links, resources, channels, and edge cases.
//!
//! Run:  cargo test --package rns-net --test e2e
//! Debug: RUST_LOG=debug cargo test --package rns-net --test e2e -- --nocapture

#![allow(unused_variables, unused_assignments, dead_code)]

use std::fs;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rns_crypto::identity::Identity;
use rns_crypto::{OsRng, Rng};

use rns_net::{
    AnnouncedIdentity, Callbacks, DestHash, Destination, IdentityHash, InterfaceConfig,
    InterfaceId, NodeConfig, PacketHash, ProofStrategy, QueryRequest, QueryResponse, RnsNode,
    RuntimeConfigValue, TcpClientConfig, TcpServerConfig, UdpConfig, MODE_FULL,
};

// ─── TestEvent ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum TestEvent {
    Announce(AnnouncedIdentity),
    PathUpdated {
        dest_hash: DestHash,
        hops: u8,
    },
    Delivery {
        dest_hash: DestHash,
        raw: Vec<u8>,
        packet_hash: PacketHash,
    },
    InterfaceUp(InterfaceId),
    InterfaceDown(InterfaceId),
    LinkEstablished {
        link_id: [u8; 16],
        rtt: f64,
        is_initiator: bool,
    },
    LinkClosed {
        link_id: [u8; 16],
        reason: Option<rns_core::link::TeardownReason>,
    },
    RemoteIdentified {
        link_id: [u8; 16],
        identity_hash: rns_core::types::IdentityHash,
        public_key: [u8; 64],
    },
    ResourceReceived {
        link_id: [u8; 16],
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
    },
    ResourceCompleted {
        link_id: [u8; 16],
    },
    ResourceFailed {
        link_id: [u8; 16],
        error: String,
    },
    ResourceProgress {
        link_id: [u8; 16],
        received: usize,
        total: usize,
    },
    ChannelMessage {
        link_id: [u8; 16],
        msgtype: u16,
        payload: Vec<u8>,
    },
    LinkData {
        link_id: [u8; 16],
        context: u8,
        data: Vec<u8>,
    },
    Response {
        link_id: [u8; 16],
        request_id: [u8; 16],
        data: Vec<u8>,
    },
    Proof {
        dest_hash: DestHash,
        packet_hash: PacketHash,
        rtt: f64,
    },
}

// ─── TestCallbacks ───────────────────────────────────────────────────────────

struct TestCallbacks {
    tx: mpsc::Sender<TestEvent>,
    proof_requested_flag: Arc<Mutex<bool>>,
    resource_accept_flag: Arc<Mutex<bool>>,
}

impl TestCallbacks {
    fn new(tx: mpsc::Sender<TestEvent>) -> Self {
        TestCallbacks {
            tx,
            proof_requested_flag: Arc::new(Mutex::new(true)),
            resource_accept_flag: Arc::new(Mutex::new(true)),
        }
    }

    fn with_flags(
        tx: mpsc::Sender<TestEvent>,
        proof_flag: Arc<Mutex<bool>>,
        resource_flag: Arc<Mutex<bool>>,
    ) -> Self {
        TestCallbacks {
            tx,
            proof_requested_flag: proof_flag,
            resource_accept_flag: resource_flag,
        }
    }
}

impl Callbacks for TestCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        let _ = self.tx.send(TestEvent::Announce(announced));
    }

    fn on_path_updated(&mut self, dest_hash: DestHash, hops: u8) {
        let _ = self.tx.send(TestEvent::PathUpdated { dest_hash, hops });
    }

    fn on_local_delivery(&mut self, dest_hash: DestHash, raw: Vec<u8>, packet_hash: PacketHash) {
        let _ = self.tx.send(TestEvent::Delivery {
            dest_hash,
            raw,
            packet_hash,
        });
    }

    fn on_interface_up(&mut self, id: InterfaceId) {
        let _ = self.tx.send(TestEvent::InterfaceUp(id));
    }

    fn on_interface_down(&mut self, id: InterfaceId) {
        let _ = self.tx.send(TestEvent::InterfaceDown(id));
    }

    fn on_link_established(
        &mut self,
        link_id: rns_core::types::LinkId,
        _dest_hash: rns_core::types::DestHash,
        rtt: f64,
        is_initiator: bool,
    ) {
        let _ = self.tx.send(TestEvent::LinkEstablished {
            link_id: link_id.0,
            rtt,
            is_initiator,
        });
    }

    fn on_link_closed(
        &mut self,
        link_id: rns_core::types::LinkId,
        reason: Option<rns_core::link::TeardownReason>,
    ) {
        let _ = self.tx.send(TestEvent::LinkClosed {
            link_id: link_id.0,
            reason,
        });
    }

    fn on_remote_identified(
        &mut self,
        link_id: rns_core::types::LinkId,
        identity_hash: rns_core::types::IdentityHash,
        public_key: [u8; 64],
    ) {
        let _ = self.tx.send(TestEvent::RemoteIdentified {
            link_id: link_id.0,
            identity_hash,
            public_key,
        });
    }

    fn on_resource_received(
        &mut self,
        link_id: rns_core::types::LinkId,
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
    ) {
        let _ = self.tx.send(TestEvent::ResourceReceived {
            link_id: link_id.0,
            data,
            metadata,
        });
    }

    fn on_resource_completed(&mut self, link_id: rns_core::types::LinkId) {
        let _ = self
            .tx
            .send(TestEvent::ResourceCompleted { link_id: link_id.0 });
    }

    fn on_resource_failed(&mut self, link_id: rns_core::types::LinkId, error: String) {
        let _ = self.tx.send(TestEvent::ResourceFailed {
            link_id: link_id.0,
            error,
        });
    }

    fn on_resource_progress(
        &mut self,
        link_id: rns_core::types::LinkId,
        received: usize,
        total: usize,
    ) {
        let _ = self.tx.send(TestEvent::ResourceProgress {
            link_id: link_id.0,
            received,
            total,
        });
    }

    fn on_resource_accept_query(
        &mut self,
        _link_id: rns_core::types::LinkId,
        _resource_hash: Vec<u8>,
        _transfer_size: u64,
        _has_metadata: bool,
    ) -> bool {
        *self.resource_accept_flag.lock().unwrap()
    }

    fn on_channel_message(
        &mut self,
        link_id: rns_core::types::LinkId,
        msgtype: u16,
        payload: Vec<u8>,
    ) {
        let _ = self.tx.send(TestEvent::ChannelMessage {
            link_id: link_id.0,
            msgtype,
            payload,
        });
    }

    fn on_link_data(&mut self, link_id: rns_core::types::LinkId, context: u8, data: Vec<u8>) {
        let _ = self.tx.send(TestEvent::LinkData {
            link_id: link_id.0,
            context,
            data,
        });
    }

    fn on_response(
        &mut self,
        link_id: rns_core::types::LinkId,
        request_id: [u8; 16],
        data: Vec<u8>,
    ) {
        let _ = self.tx.send(TestEvent::Response {
            link_id: link_id.0,
            request_id,
            data,
        });
    }

    fn on_proof(&mut self, dest_hash: DestHash, packet_hash: PacketHash, rtt: f64) {
        let _ = self.tx.send(TestEvent::Proof {
            dest_hash,
            packet_hash,
            rtt,
        });
    }

    fn on_proof_requested(&mut self, _dest_hash: DestHash, _packet_hash: PacketHash) -> bool {
        *self.proof_requested_flag.lock().unwrap()
    }
}

// ─── Noop callbacks for transport relay nodes ────────────────────────────────

struct TransportCallbacks;

impl Callbacks for TransportCallbacks {
    fn on_announce(&mut self, _: AnnouncedIdentity) {}
    fn on_path_updated(&mut self, _: DestHash, _: u8) {}
    fn on_local_delivery(&mut self, _: DestHash, _: Vec<u8>, _: PacketHash) {}
}

// ─── Helper functions ────────────────────────────────────────────────────────

fn find_free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};

    static NEXT_PORT: AtomicU16 = AtomicU16::new(0);

    let pid = std::process::id() as u16;
    let base = 20_000 + (pid % 250) * 160;
    let _ = NEXT_PORT.compare_exchange(0, base, Ordering::SeqCst, Ordering::SeqCst);

    loop {
        let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

fn decrypt_delivery(raw: &[u8], identity: &Identity) -> Option<Vec<u8>> {
    let packet = rns_core::packet::RawPacket::unpack(raw).ok()?;
    identity.decrypt(&packet.data).ok()
}

/// Extract Ed25519 signing keys from an identity for link registration.
/// Private key layout: [X25519_prv(32) | Ed25519_seed(32)]
/// Public key layout:  [X25519_pub(32) | Ed25519_pub(32)]
fn extract_sig_keys(identity: &Identity) -> ([u8; 32], [u8; 32]) {
    let prv = identity.get_private_key().unwrap();
    let pub_key = identity.get_public_key().unwrap();
    let mut sig_prv = [0u8; 32];
    let mut sig_pub = [0u8; 32];
    sig_prv.copy_from_slice(&prv[32..64]);
    sig_pub.copy_from_slice(&pub_key[32..64]);
    (sig_prv, sig_pub)
}

/// Wait for an event matching a predicate, with timeout.
fn wait_for_event<F, T>(
    rx: &mpsc::Receiver<TestEvent>,
    timeout: Duration,
    mut predicate: F,
) -> Option<T>
where
    F: FnMut(&TestEvent) -> Option<T>,
{
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            return None;
        }
        match rx.recv_timeout(remaining) {
            Ok(event) => {
                if let Some(result) = predicate(&event) {
                    return Some(result);
                }
            }
            Err(_) => return None,
        }
    }
}

fn wait_for_announce(
    rx: &mpsc::Receiver<TestEvent>,
    expected_hash: &DestHash,
    timeout: Duration,
) -> Option<AnnouncedIdentity> {
    wait_for_event(rx, timeout, |event| match event {
        TestEvent::Announce(a) if a.dest_hash == *expected_hash => Some(a.clone()),
        _ => None,
    })
}

/// Announce with retry: send an announce and wait for the remote to receive it.
/// Retries up to 10 times with a 2-second wait per attempt.
fn announce_with_retry(
    node: &RnsNode,
    dest: &Destination,
    identity: &Identity,
    app_data: Option<&[u8]>,
    remote_rx: &mpsc::Receiver<TestEvent>,
) -> Option<AnnouncedIdentity> {
    for _ in 0..10 {
        let _ = node.announce(dest, identity, app_data);
        if let Some(announced) = wait_for_announce(remote_rx, &dest.hash, Duration::from_secs(2)) {
            return Some(announced);
        }
    }
    None
}

fn wait_for_any_announce(
    rx: &mpsc::Receiver<TestEvent>,
    timeout: Duration,
) -> Option<AnnouncedIdentity> {
    wait_for_event(rx, timeout, |event| match event {
        TestEvent::Announce(a) => Some(a.clone()),
        _ => None,
    })
}

fn wait_for_delivery(
    rx: &mpsc::Receiver<TestEvent>,
    timeout: Duration,
) -> Option<(DestHash, Vec<u8>, PacketHash)> {
    wait_for_event(rx, timeout, |event| match event {
        TestEvent::Delivery {
            dest_hash,
            raw,
            packet_hash,
        } => Some((dest_hash.clone(), raw.clone(), packet_hash.clone())),
        _ => None,
    })
}

fn wait_for_proof(rx: &mpsc::Receiver<TestEvent>, timeout: Duration) -> Option<(PacketHash, f64)> {
    wait_for_event(rx, timeout, |event| match event {
        TestEvent::Proof {
            packet_hash, rtt, ..
        } => Some((packet_hash.clone(), *rtt)),
        _ => None,
    })
}

fn wait_for_link_established(
    rx: &mpsc::Receiver<TestEvent>,
    timeout: Duration,
) -> Option<([u8; 16], f64, bool)> {
    wait_for_event(rx, timeout, |event| match event {
        TestEvent::LinkEstablished {
            link_id,
            rtt,
            is_initiator,
        } => Some((*link_id, *rtt, *is_initiator)),
        _ => None,
    })
}

fn wait_for_link_closed(
    rx: &mpsc::Receiver<TestEvent>,
    timeout: Duration,
) -> Option<([u8; 16], Option<rns_core::link::TeardownReason>)> {
    wait_for_event(rx, timeout, |event| match event {
        TestEvent::LinkClosed { link_id, reason } => Some((*link_id, reason.clone())),
        _ => None,
    })
}

fn wait_for_resource_received(
    rx: &mpsc::Receiver<TestEvent>,
    timeout: Duration,
) -> Option<([u8; 16], Vec<u8>, Option<Vec<u8>>)> {
    wait_for_event(rx, timeout, |event| match event {
        TestEvent::ResourceReceived {
            link_id,
            data,
            metadata,
        } => Some((*link_id, data.clone(), metadata.clone())),
        _ => None,
    })
}

fn wait_for_channel_message(
    rx: &mpsc::Receiver<TestEvent>,
    timeout: Duration,
) -> Option<([u8; 16], u16, Vec<u8>)> {
    wait_for_event(rx, timeout, |event| match event {
        TestEvent::ChannelMessage {
            link_id,
            msgtype,
            payload,
        } => Some((*link_id, *msgtype, payload.clone())),
        _ => None,
    })
}

fn wait_for_response(
    rx: &mpsc::Receiver<TestEvent>,
    timeout: Duration,
) -> Option<([u8; 16], [u8; 16], Vec<u8>)> {
    wait_for_event(rx, timeout, |event| match event {
        TestEvent::Response {
            link_id,
            request_id,
            data,
        } => Some((*link_id, *request_id, data.clone())),
        _ => None,
    })
}

fn wait_for_remote_identified(
    rx: &mpsc::Receiver<TestEvent>,
    timeout: Duration,
) -> Option<([u8; 16], rns_core::types::IdentityHash)> {
    wait_for_event(rx, timeout, |event| match event {
        TestEvent::RemoteIdentified {
            link_id,
            identity_hash,
            ..
        } => Some((*link_id, identity_hash.clone())),
        _ => None,
    })
}

fn wait_for_link_data(
    rx: &mpsc::Receiver<TestEvent>,
    timeout: Duration,
) -> Option<([u8; 16], u8, Vec<u8>)> {
    wait_for_event(rx, timeout, |event| match event {
        TestEvent::LinkData {
            link_id,
            context,
            data,
        } => Some((*link_id, *context, data.clone())),
        _ => None,
    })
}

fn wait_for_resource_failed(
    rx: &mpsc::Receiver<TestEvent>,
    timeout: Duration,
) -> Option<([u8; 16], String)> {
    wait_for_event(rx, timeout, |event| match event {
        TestEvent::ResourceFailed { link_id, error } => Some((*link_id, error.clone())),
        _ => None,
    })
}

fn wait_for_resource_progress(
    rx: &mpsc::Receiver<TestEvent>,
    timeout: Duration,
) -> Option<([u8; 16], usize, usize)> {
    wait_for_event(rx, timeout, |event| match event {
        TestEvent::ResourceProgress {
            link_id,
            received,
            total,
        } => Some((*link_id, *received, *total)),
        _ => None,
    })
}

fn runtime_config_value(node: &RnsNode, key: &str) -> RuntimeConfigValue {
    match node.query(QueryRequest::GetRuntimeConfig { key: key.into() }) {
        Ok(QueryResponse::RuntimeConfigEntry(Some(entry))) => entry.value,
        other => panic!("expected runtime config entry for {}, got {:?}", key, other),
    }
}

const TIMEOUT: Duration = Duration::from_secs(10);
const SETTLE: Duration = Duration::from_millis(1500);
const KNOWN_DESTINATIONS_TTL: Duration = Duration::from_secs(48 * 60 * 60);

const APP_NAME: &str = "e2e_test";

/// Start a transport node (TCP server) on the given port.
fn start_transport_node(port: u16) -> RnsNode {
    start_transport_node_with_limits(
        port,
        rns_core::constants::HASHLIST_MAXSIZE,
        Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
        rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
    )
}

fn start_transport_node_with_packet_hashlist(
    port: u16,
    packet_hashlist_max_entries: usize,
) -> RnsNode {
    start_transport_node_with_limits(
        port,
        packet_hashlist_max_entries,
        Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
        rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
    )
}

fn start_transport_node_with_limits(
    port: u16,
    packet_hashlist_max_entries: usize,
    announce_table_ttl: Duration,
    announce_table_max_bytes: usize,
) -> RnsNode {
    let node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: true,
            transport_enabled: true,
            identity: Some(Identity::new(&mut OsRng)),
            interfaces: vec![InterfaceConfig {
                name: String::new(),
                type_name: "TCPServerInterface".to_string(),
                config_data: Box::new(TcpServerConfig {
                    name: "Transport TCP".into(),
                    listen_ip: "127.0.0.1".into(),
                    listen_port: port,
                    interface_id: InterfaceId(1),
                    max_connections: None,
                    ..TcpServerConfig::default()
                }),
                mode: MODE_FULL,
                ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
                ifac: None,
                discovery: None,
            }],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            device: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery_required_value: None,
            respond_to_probes: false,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: 8192,
            announce_table_ttl,
            announce_table_max_bytes,
            driver_event_queue_capacity: rns_net::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity:
                rns_net::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "rns-hooks")]
            provider_bridge: None,
        },
        Box::new(TransportCallbacks),
    )
    .expect("Failed to start transport node");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match std::net::TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => {
                drop(stream);
                break;
            }
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            Err(err) => panic!("Transport listener on {} did not come up: {}", port, err),
        }
    }
    node
}

/// Start a client node (TCP client) connecting to the given port.
fn start_client_node(port: u16, identity: &Identity, callbacks: Box<dyn Callbacks>) -> RnsNode {
    start_client_node_with_packet_hashlist(
        port,
        identity,
        callbacks,
        rns_core::constants::HASHLIST_MAXSIZE,
    )
}

fn start_client_node_with_packet_hashlist(
    port: u16,
    identity: &Identity,
    callbacks: Box<dyn Callbacks>,
    packet_hashlist_max_entries: usize,
) -> RnsNode {
    RnsNode::start(
        NodeConfig {
            panic_on_interface_error: true,
            transport_enabled: false,
            identity: Some(Identity::from_private_key(
                &identity.get_private_key().unwrap(),
            )),
            interfaces: vec![InterfaceConfig {
                name: String::new(),
                type_name: "TCPClientInterface".to_string(),
                config_data: Box::new(TcpClientConfig {
                    name: "Client TCP".into(),
                    target_host: "127.0.0.1".into(),
                    target_port: port,
                    interface_id: InterfaceId(1),
                    ..Default::default()
                }),
                mode: MODE_FULL,
                ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
                ifac: None,
                discovery: None,
            }],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            device: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery_required_value: None,
            respond_to_probes: false,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: 8192,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: rns_net::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity:
                rns_net::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "rns-hooks")]
            provider_bridge: None,
        },
        callbacks,
    )
    .expect("Failed to start client node")
}

#[test]
fn config_file_ingress_control_knobs_apply_to_runtime_interface() {
    let dir = tempfile::tempdir().unwrap();
    let port = find_free_port();
    let config = format!(
        r#"[reticulum]
  enable_transport = No
  share_instance = No
  panic_on_interface_error = Yes

[interfaces]
  [[Config Knobs TCP]]
    type = TCPServerInterface
    listen_ip = 127.0.0.1
    listen_port = {}
    ingress_control = No
    ic_max_held_announces = 17
    ic_burst_hold = 1.5
    ic_burst_freq_new = 2.5
    ic_burst_freq = 3.5
    ic_new_time = 4.5
    ic_burst_penalty = 5.5
    ic_held_release_interval = 6.5
"#,
        port
    );
    fs::write(dir.path().join("config"), config).unwrap();

    let node = RnsNode::from_config(Some(dir.path()), Box::new(TransportCallbacks))
        .expect("node should start from config with custom ingress-control knobs");

    let deadline = Instant::now() + Duration::from_secs(2);
    let _client = loop {
        match std::net::TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            Err(err) => panic!("Config listener on {} did not come up: {}", port, err),
        }
    };

    let deadline = Instant::now() + Duration::from_secs(2);
    let prefix = loop {
        match node.query(QueryRequest::ListRuntimeConfig) {
            Ok(QueryResponse::RuntimeConfigList(entries)) => {
                if let Some(entry) = entries.iter().find(|entry| {
                    entry.key.starts_with("interface.TCPServerInterface/Client-")
                        && entry.key.ends_with(".ingress_control")
                }) {
                    break entry
                        .key
                        .trim_end_matches(".ingress_control")
                        .to_string();
                }
            }
            other => panic!("expected runtime config list, got {:?}", other),
        }
        if Instant::now() >= deadline {
            panic!("spawned interface runtime config did not appear");
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    assert_eq!(
        runtime_config_value(&node, &format!("{}.ingress_control", prefix)),
        RuntimeConfigValue::Bool(false)
    );
    assert_eq!(
        runtime_config_value(&node, &format!("{}.ic_max_held_announces", prefix)),
        RuntimeConfigValue::Int(17)
    );
    assert_eq!(
        runtime_config_value(&node, &format!("{}.ic_burst_hold", prefix)),
        RuntimeConfigValue::Float(1.5)
    );
    assert_eq!(
        runtime_config_value(&node, &format!("{}.ic_burst_freq_new", prefix)),
        RuntimeConfigValue::Float(2.5)
    );
    assert_eq!(
        runtime_config_value(&node, &format!("{}.ic_burst_freq", prefix)),
        RuntimeConfigValue::Float(3.5)
    );
    assert_eq!(
        runtime_config_value(&node, &format!("{}.ic_new_time", prefix)),
        RuntimeConfigValue::Float(4.5)
    );
    assert_eq!(
        runtime_config_value(&node, &format!("{}.ic_burst_penalty", prefix)),
        RuntimeConfigValue::Float(5.5)
    );
    assert_eq!(
        runtime_config_value(&node, &format!("{}.ic_held_release_interval", prefix)),
        RuntimeConfigValue::Float(6.5)
    );

    node.shutdown();
}

/// Set up a two-peer topology: Transport(TCP server) + Alice(TCP client) + Bob(TCP client).
/// Returns (transport, alice_node, alice_rx, bob_node, bob_rx, alice_identity, bob_identity, alice_dest, bob_dest).
#[allow(clippy::type_complexity)]
fn setup_two_peers() -> (
    RnsNode,
    RnsNode,
    mpsc::Receiver<TestEvent>,
    RnsNode,
    mpsc::Receiver<TestEvent>,
    Identity,
    Identity,
    Destination,
    Destination,
) {
    setup_two_peers_with_packet_hashlist(rns_core::constants::HASHLIST_MAXSIZE)
}

#[allow(clippy::type_complexity)]
fn setup_two_peers_with_packet_hashlist(
    packet_hashlist_max_entries: usize,
) -> (
    RnsNode,
    RnsNode,
    mpsc::Receiver<TestEvent>,
    RnsNode,
    mpsc::Receiver<TestEvent>,
    Identity,
    Identity,
    Destination,
    Destination,
) {
    setup_two_peers_with_packet_hashlist_and_proof(
        packet_hashlist_max_entries,
        ProofStrategy::ProveAll,
    )
}

#[allow(clippy::type_complexity)]
fn setup_two_peers_with_packet_hashlist_and_proof(
    packet_hashlist_max_entries: usize,
    proof_strategy: ProofStrategy,
) -> (
    RnsNode,
    RnsNode,
    mpsc::Receiver<TestEvent>,
    RnsNode,
    mpsc::Receiver<TestEvent>,
    Identity,
    Identity,
    Destination,
    Destination,
) {
    let port = find_free_port();
    let transport = start_transport_node_with_packet_hashlist(port, packet_hashlist_max_entries);

    let alice_identity = Identity::new(&mut OsRng);
    let alice_ih = IdentityHash(*alice_identity.hash());
    let alice_dest = Destination::single_in(APP_NAME, &["msg", "rx"], alice_ih)
        .set_proof_strategy(proof_strategy);

    let bob_identity = Identity::new(&mut OsRng);
    let bob_ih = IdentityHash(*bob_identity.hash());
    let bob_dest =
        Destination::single_in(APP_NAME, &["msg", "rx"], bob_ih).set_proof_strategy(proof_strategy);

    let (alice_tx, alice_rx) = mpsc::channel();
    let alice_node = start_client_node_with_packet_hashlist(
        port,
        &alice_identity,
        Box::new(TestCallbacks::new(alice_tx)),
        packet_hashlist_max_entries,
    );
    alice_node
        .register_destination_with_proof(
            &alice_dest,
            Some(alice_identity.get_private_key().unwrap()),
        )
        .unwrap();

    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = start_client_node_with_packet_hashlist(
        port,
        &bob_identity,
        Box::new(TestCallbacks::new(bob_tx)),
        packet_hashlist_max_entries,
    );
    bob_node
        .register_destination_with_proof(&bob_dest, Some(bob_identity.get_private_key().unwrap()))
        .unwrap();

    // Wait for both TCP interfaces to come up, then let transport settle
    wait_for_event(&alice_rx, TIMEOUT, |e| {
        matches!(e, TestEvent::InterfaceUp(_)).then_some(())
    })
    .expect("Alice InterfaceUp timed out");
    wait_for_event(&bob_rx, TIMEOUT, |e| {
        matches!(e, TestEvent::InterfaceUp(_)).then_some(())
    })
    .expect("Bob InterfaceUp timed out");
    std::thread::sleep(SETTLE);

    (
        transport,
        alice_node,
        alice_rx,
        bob_node,
        bob_rx,
        alice_identity,
        bob_identity,
        alice_dest,
        bob_dest,
    )
}

/// Set up two peers with announces already exchanged.
/// Uses announce-with-retry since the transport relay may not be fully ready
/// to forward even after InterfaceUp fires on both clients.
/// Returns everything from setup_two_peers plus the announced identities.
#[allow(clippy::type_complexity)]
fn setup_two_peers_announced() -> (
    RnsNode,
    RnsNode,
    mpsc::Receiver<TestEvent>,
    RnsNode,
    mpsc::Receiver<TestEvent>,
    Identity,
    Identity,
    Destination,
    Destination,
    AnnouncedIdentity,
    AnnouncedIdentity,
) {
    setup_two_peers_announced_with_packet_hashlist(rns_core::constants::HASHLIST_MAXSIZE)
}

#[allow(clippy::type_complexity)]
fn setup_two_peers_announced_with_packet_hashlist(
    packet_hashlist_max_entries: usize,
) -> (
    RnsNode,
    RnsNode,
    mpsc::Receiver<TestEvent>,
    RnsNode,
    mpsc::Receiver<TestEvent>,
    Identity,
    Identity,
    Destination,
    Destination,
    AnnouncedIdentity,
    AnnouncedIdentity,
) {
    let (transport, alice_node, alice_rx, bob_node, bob_rx, alice_id, bob_id, alice_dest, bob_dest) =
        setup_two_peers_with_packet_hashlist(packet_hashlist_max_entries);

    // Announce sequentially: first Bob, then Alice.
    // Simultaneous bidirectional announces can race in the transport's
    // retransmit path, causing one direction to be permanently dropped.
    let bob_announced = announce_with_retry(&bob_node, &bob_dest, &bob_id, Some(b"Bob"), &alice_rx)
        .expect("Alice never received Bob's announce after retries");
    let alice_announced =
        announce_with_retry(&alice_node, &alice_dest, &alice_id, Some(b"Alice"), &bob_rx)
            .expect("Bob never received Alice's announce after retries");

    (
        transport,
        alice_node,
        alice_rx,
        bob_node,
        bob_rx,
        alice_id,
        bob_id,
        alice_dest,
        bob_dest,
        alice_announced,
        bob_announced,
    )
}

#[allow(clippy::type_complexity)]
fn setup_two_peers_announced_no_proof_with_packet_hashlist(
    packet_hashlist_max_entries: usize,
) -> (
    RnsNode,
    RnsNode,
    mpsc::Receiver<TestEvent>,
    RnsNode,
    mpsc::Receiver<TestEvent>,
    Identity,
    Identity,
    Destination,
    Destination,
    AnnouncedIdentity,
    AnnouncedIdentity,
) {
    let (transport, alice_node, alice_rx, bob_node, bob_rx, alice_id, bob_id, alice_dest, bob_dest) =
        setup_two_peers_with_packet_hashlist_and_proof(
            packet_hashlist_max_entries,
            ProofStrategy::ProveNone,
        );

    let bob_announced = announce_with_retry(&bob_node, &bob_dest, &bob_id, Some(b"Bob"), &alice_rx)
        .expect("Alice never received Bob's announce after retries");
    let alice_announced =
        announce_with_retry(&alice_node, &alice_dest, &alice_id, Some(b"Alice"), &bob_rx)
            .expect("Bob never received Alice's announce after retries");

    (
        transport,
        alice_node,
        alice_rx,
        bob_node,
        bob_rx,
        alice_id,
        bob_id,
        alice_dest,
        bob_dest,
        alice_announced,
        bob_announced,
    )
}

/// Set up a link between Alice (initiator) and Bob (responder).
/// Returns all setup_two_peers_announced data plus link_id.
#[allow(clippy::type_complexity)]
fn setup_link() -> (
    RnsNode,
    RnsNode,
    mpsc::Receiver<TestEvent>,
    RnsNode,
    mpsc::Receiver<TestEvent>,
    Identity,
    Identity,
    Destination,
    Destination,
    [u8; 16],
) {
    let (
        transport,
        alice_node,
        alice_rx,
        bob_node,
        bob_rx,
        alice_id,
        bob_id,
        alice_dest,
        bob_dest,
        _alice_ann,
        bob_announced,
    ) = setup_two_peers_announced();

    // Bob registers as link destination
    let (bob_sig_prv, bob_sig_pub) = extract_sig_keys(&bob_id);
    bob_node
        .register_link_destination(bob_dest.hash.0, bob_sig_prv, bob_sig_pub, 0)
        .unwrap();

    // Give Bob's driver time to process the registration
    std::thread::sleep(Duration::from_millis(500));

    // Alice creates link to Bob
    let bob_pub = bob_id.get_public_key().unwrap();
    let mut bob_sig_pub_for_link = [0u8; 32];
    bob_sig_pub_for_link.copy_from_slice(&bob_pub[32..64]);

    let link_id = alice_node
        .create_link(bob_dest.hash.0, bob_sig_pub_for_link)
        .unwrap();

    // Wait for link established on both sides
    let (alice_lid, _, alice_is_init) =
        wait_for_link_established(&alice_rx, TIMEOUT).expect("Alice: link not established");
    assert_eq!(alice_lid, link_id);
    assert!(alice_is_init);

    let (bob_lid, _, bob_is_init) =
        wait_for_link_established(&bob_rx, TIMEOUT).expect("Bob: link not established");
    assert_eq!(bob_lid, link_id);
    assert!(!bob_is_init);

    // Set resource strategy to AcceptAll on Bob's side by default
    bob_node.set_resource_strategy(link_id, 1).unwrap();

    // Give the link a moment to stabilize
    std::thread::sleep(Duration::from_millis(200));

    (
        transport, alice_node, alice_rx, bob_node, bob_rx, alice_id, bob_id, alice_dest, bob_dest,
        link_id,
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
// Direct link establishment (no transport relay node)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_direct_link_no_transport() {
    let port = find_free_port();

    let bob_id = Identity::new(&mut OsRng);
    let bob_ih = IdentityHash(*bob_id.hash());
    let bob_dest = Destination::single_in(APP_NAME, &["link", "direct"], bob_ih)
        .set_proof_strategy(ProofStrategy::ProveAll);

    let alice_id = Identity::new(&mut OsRng);
    let alice_ih = IdentityHash(*alice_id.hash());
    let alice_dest = Destination::single_in(APP_NAME, &["link", "direct"], alice_ih)
        .set_proof_strategy(ProofStrategy::ProveAll);

    // Bob runs a TCP server
    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            transport_enabled: false,
            identity: Some(Identity::from_private_key(
                &bob_id.get_private_key().unwrap(),
            )),
            interfaces: vec![InterfaceConfig {
                name: String::new(),
                type_name: "TCPServerInterface".to_string(),
                config_data: Box::new(TcpServerConfig {
                    name: "Bob TCP Server".into(),
                    listen_ip: "127.0.0.1".into(),
                    listen_port: port,
                    interface_id: InterfaceId(1),
                    max_connections: None,
                    ..TcpServerConfig::default()
                }),
                mode: MODE_FULL,
                ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
                ifac: None,
                discovery: None,
            }],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            device: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery_required_value: None,
            respond_to_probes: false,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: 8192,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: rns_net::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity:
                rns_net::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "rns-hooks")]
            provider_bridge: None,
        },
        Box::new(TestCallbacks::new(bob_tx)),
    )
    .unwrap();

    bob_node
        .register_destination_with_proof(&bob_dest, Some(bob_id.get_private_key().unwrap()))
        .unwrap();

    // Alice connects as TCP client
    let (alice_tx, alice_rx) = mpsc::channel();
    let alice_node = start_client_node(port, &alice_id, Box::new(TestCallbacks::new(alice_tx)));
    alice_node
        .register_destination_with_proof(&alice_dest, Some(alice_id.get_private_key().unwrap()))
        .unwrap();

    std::thread::sleep(SETTLE);

    // Exchange announces sequentially to avoid transport retransmit race
    announce_with_retry(&bob_node, &bob_dest, &bob_id, Some(b"Bob"), &alice_rx)
        .expect("Alice did not discover Bob");
    announce_with_retry(&alice_node, &alice_dest, &alice_id, Some(b"Alice"), &bob_rx)
        .expect("Bob did not discover Alice");

    // Bob registers as link destination
    let (bob_sig_prv, bob_sig_pub) = extract_sig_keys(&bob_id);
    bob_node
        .register_link_destination(bob_dest.hash.0, bob_sig_prv, bob_sig_pub, 0)
        .unwrap();
    std::thread::sleep(Duration::from_millis(500));

    // Alice creates link
    let bob_pub = bob_id.get_public_key().unwrap();
    let mut bob_sig_pub_link = [0u8; 32];
    bob_sig_pub_link.copy_from_slice(&bob_pub[32..64]);
    let link_id = alice_node
        .create_link(bob_dest.hash.0, bob_sig_pub_link)
        .unwrap();

    // Wait for link established on both sides
    let alice_est = wait_for_link_established(&alice_rx, TIMEOUT);
    let bob_est = wait_for_link_established(&bob_rx, TIMEOUT);
    assert!(alice_est.is_some(), "Alice: link not established");
    assert!(bob_est.is_some(), "Bob: link not established");

    alice_node.teardown_link(link_id).unwrap();
    std::thread::sleep(Duration::from_millis(500));

    alice_node.shutdown();
    bob_node.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. Announce Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_announce_propagation() {
    let port = find_free_port();
    let transport = start_transport_node(port);

    let alice_identity = Identity::new(&mut OsRng);
    let alice_ih = IdentityHash(*alice_identity.hash());
    let alice_dest = Destination::single_in(APP_NAME, &["announce", "test"], alice_ih);

    let (alice_tx, _alice_rx) = mpsc::channel();
    let alice_node = start_client_node(
        port,
        &alice_identity,
        Box::new(TestCallbacks::new(alice_tx)),
    );
    alice_node
        .register_destination_with_proof(&alice_dest, None)
        .unwrap();

    let bob_identity = Identity::new(&mut OsRng);
    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = start_client_node(port, &bob_identity, Box::new(TestCallbacks::new(bob_tx)));

    std::thread::sleep(SETTLE);

    alice_node
        .announce(&alice_dest, &alice_identity, Some(b"hello"))
        .unwrap();

    let announced = wait_for_announce(&bob_rx, &alice_dest.hash, TIMEOUT)
        .expect("Bob did not receive Alice's announce");

    assert_eq!(announced.dest_hash, alice_dest.hash);
    assert_eq!(announced.app_data.as_deref(), Some(b"hello".as_slice()));

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_announce_binary_app_data() {
    let port = find_free_port();
    let transport = start_transport_node(port);

    let alice_identity = Identity::new(&mut OsRng);
    let alice_ih = IdentityHash(*alice_identity.hash());
    let alice_dest = Destination::single_in(APP_NAME, &["announce", "binary"], alice_ih);

    let (alice_tx, _alice_rx) = mpsc::channel();
    let alice_node = start_client_node(
        port,
        &alice_identity,
        Box::new(TestCallbacks::new(alice_tx)),
    );
    alice_node
        .register_destination_with_proof(&alice_dest, None)
        .unwrap();

    let bob_identity = Identity::new(&mut OsRng);
    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = start_client_node(port, &bob_identity, Box::new(TestCallbacks::new(bob_tx)));

    std::thread::sleep(SETTLE);

    // 256 random bytes as app_data
    let mut binary_data = vec![0u8; 256];
    OsRng.fill_bytes(&mut binary_data);

    alice_node
        .announce(&alice_dest, &alice_identity, Some(&binary_data))
        .unwrap();

    let announced = wait_for_announce(&bob_rx, &alice_dest.hash, TIMEOUT)
        .expect("Bob did not receive binary announce");

    assert_eq!(announced.app_data.as_deref(), Some(binary_data.as_slice()));

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_announce_relay_respects_short_ttl() {
    let port = find_free_port();
    let transport = start_transport_node_with_limits(
        port,
        rns_core::constants::HASHLIST_MAXSIZE,
        Duration::from_millis(50),
        rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
    );

    let alice_identity = Identity::new(&mut OsRng);
    let alice_dest = Destination::single_in(
        APP_NAME,
        &["announce", "ttl_drop"],
        IdentityHash(*alice_identity.hash()),
    );

    let (alice_tx, _alice_rx) = mpsc::channel();
    let alice_node = start_client_node(
        port,
        &alice_identity,
        Box::new(TestCallbacks::new(alice_tx)),
    );
    alice_node
        .register_destination_with_proof(&alice_dest, None)
        .unwrap();

    let bob_identity = Identity::new(&mut OsRng);
    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = start_client_node(port, &bob_identity, Box::new(TestCallbacks::new(bob_tx)));

    std::thread::sleep(SETTLE);

    alice_node
        .announce(&alice_dest, &alice_identity, Some(b"ttl-expire"))
        .unwrap();

    let announced = wait_for_announce(&bob_rx, &alice_dest.hash, Duration::from_secs(3));
    assert!(
        announced.is_none(),
        "Bob unexpectedly received Alice's announce despite relay TTL expiry"
    );

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_announce_relay_respects_max_bytes() {
    let port = find_free_port();
    let transport = start_transport_node_with_limits(
        port,
        rns_core::constants::HASHLIST_MAXSIZE,
        Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
        1,
    );

    let alice_identity = Identity::new(&mut OsRng);
    let alice_dest = Destination::single_in(
        APP_NAME,
        &["announce", "max_bytes_drop"],
        IdentityHash(*alice_identity.hash()),
    );

    let (alice_tx, _alice_rx) = mpsc::channel();
    let alice_node = start_client_node(
        port,
        &alice_identity,
        Box::new(TestCallbacks::new(alice_tx)),
    );
    alice_node
        .register_destination_with_proof(&alice_dest, None)
        .unwrap();

    let bob_identity = Identity::new(&mut OsRng);
    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = start_client_node(port, &bob_identity, Box::new(TestCallbacks::new(bob_tx)));

    std::thread::sleep(SETTLE);

    let large_app_data = vec![0xAB; 32];
    alice_node
        .announce(&alice_dest, &alice_identity, Some(&large_app_data))
        .unwrap();

    let announced = wait_for_announce(&bob_rx, &alice_dest.hash, Duration::from_secs(3));
    assert!(
        announced.is_none(),
        "Bob unexpectedly received Alice's announce despite relay byte cap"
    );

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_multiple_announces_cross_discovery() {
    let port = find_free_port();
    let transport = start_transport_node(port);

    let id_a = Identity::new(&mut OsRng);
    let id_b = Identity::new(&mut OsRng);
    let id_c = Identity::new(&mut OsRng);

    let dest_a = Destination::single_in(APP_NAME, &["multi", "a"], IdentityHash(*id_a.hash()));
    let dest_b = Destination::single_in(APP_NAME, &["multi", "b"], IdentityHash(*id_b.hash()));
    let dest_c = Destination::single_in(APP_NAME, &["multi", "c"], IdentityHash(*id_c.hash()));

    let (tx_a, rx_a) = mpsc::channel();
    let (tx_b, rx_b) = mpsc::channel();
    let (tx_c, rx_c) = mpsc::channel();

    let node_a = start_client_node(port, &id_a, Box::new(TestCallbacks::new(tx_a)));
    let node_b = start_client_node(port, &id_b, Box::new(TestCallbacks::new(tx_b)));
    let node_c = start_client_node(port, &id_c, Box::new(TestCallbacks::new(tx_c)));

    node_a
        .register_destination_with_proof(&dest_a, None)
        .unwrap();
    node_b
        .register_destination_with_proof(&dest_b, None)
        .unwrap();
    node_c
        .register_destination_with_proof(&dest_c, None)
        .unwrap();

    std::thread::sleep(SETTLE);

    announce_with_retry(&node_a, &dest_a, &id_a, Some(b"A"), &rx_b).expect("B did not discover A");
    announce_with_retry(&node_a, &dest_a, &id_a, Some(b"A"), &rx_c).expect("C did not discover A");

    announce_with_retry(&node_b, &dest_b, &id_b, Some(b"B"), &rx_a).expect("A did not discover B");
    announce_with_retry(&node_b, &dest_b, &id_b, Some(b"B"), &rx_c).expect("C did not discover B");

    announce_with_retry(&node_c, &dest_c, &id_c, Some(b"C"), &rx_a).expect("A did not discover C");
    announce_with_retry(&node_c, &dest_c, &id_c, Some(b"C"), &rx_b).expect("B did not discover C");

    node_a.shutdown();
    node_b.shutdown();
    node_c.shutdown();
    transport.shutdown();
}

#[test]
fn test_re_announce_updated_app_data() {
    let port = find_free_port();
    let transport = start_transport_node(port);

    let alice_identity = Identity::new(&mut OsRng);
    let alice_ih = IdentityHash(*alice_identity.hash());
    let alice_dest = Destination::single_in(APP_NAME, &["reannounce", "test"], alice_ih);

    let (alice_tx, _alice_rx) = mpsc::channel();
    let alice_node = start_client_node(
        port,
        &alice_identity,
        Box::new(TestCallbacks::new(alice_tx)),
    );
    alice_node
        .register_destination_with_proof(&alice_dest, None)
        .unwrap();

    let bob_identity = Identity::new(&mut OsRng);
    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = start_client_node(port, &bob_identity, Box::new(TestCallbacks::new(bob_tx)));

    std::thread::sleep(SETTLE);

    // First announce with v1
    alice_node
        .announce(&alice_dest, &alice_identity, Some(b"v1"))
        .unwrap();

    let first = wait_for_announce(&bob_rx, &alice_dest.hash, TIMEOUT)
        .expect("Bob did not receive first announce");
    assert_eq!(first.app_data.as_deref(), Some(b"v1".as_slice()));

    // Drain any queued v1 retransmissions before sending v2.
    // Keep draining until no more events arrive within a short window.
    loop {
        match bob_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(_) => continue,
            Err(_) => break,
        }
    }

    // Re-announce with v2, retry up to 3 times to handle transport contention
    let mut got_v2 = false;
    for _attempt in 0..3 {
        alice_node
            .announce(&alice_dest, &alice_identity, Some(b"v2"))
            .unwrap();

        if let Some(_) = wait_for_event(&bob_rx, Duration::from_secs(8), |event| match event {
            TestEvent::Announce(a)
                if a.dest_hash == alice_dest.hash
                    && a.app_data.as_deref() == Some(b"v2".as_slice()) =>
            {
                Some(())
            }
            _ => None,
        }) {
            got_v2 = true;
            break;
        }
    }
    assert!(got_v2, "Bob did not receive updated announce with v2");

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_recall_identity_after_announce() {
    let (
        transport,
        alice_node,
        _alice_rx,
        bob_node,
        _bob_rx,
        _alice_id,
        _bob_id,
        _alice_dest,
        bob_dest,
        _alice_ann,
        _bob_ann,
    ) = setup_two_peers_announced();

    // Alice should be able to recall Bob's announced identity
    let recalled = alice_node
        .recall_identity(&bob_dest.hash)
        .expect("recall_identity failed");
    assert!(recalled.is_some(), "Should recall Bob's identity");
    let recalled = recalled.unwrap();
    assert_eq!(recalled.dest_hash, bob_dest.hash);

    // Unknown destination should return None
    let unknown = DestHash([0xFF; 16]);
    let not_found = alice_node
        .recall_identity(&unknown)
        .expect("recall_identity failed");
    assert!(not_found.is_none(), "Unknown dest should return None");

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. SINGLE Encrypted Messaging
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_single_message_delivery() {
    let (
        transport,
        alice_node,
        _alice_rx,
        _bob_node,
        bob_rx,
        _alice_id,
        bob_id,
        _alice_dest,
        _bob_dest,
        _alice_ann,
        bob_announced,
    ) = setup_two_peers_announced();

    let dest_to_bob = Destination::single_out(APP_NAME, &["msg", "rx"], &bob_announced);
    let plaintext = b"Hello Bob from Alice!";
    alice_node.send_packet(&dest_to_bob, plaintext).unwrap();

    let (_, raw, _) = wait_for_delivery(&bob_rx, TIMEOUT).expect("Bob did not receive message");
    let decrypted = decrypt_delivery(&raw, &bob_id).expect("Decryption failed");
    assert_eq!(decrypted, plaintext);

    alice_node.shutdown();
    _bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_single_bidirectional() {
    let (
        transport,
        alice_node,
        alice_rx,
        bob_node,
        bob_rx,
        alice_id,
        bob_id,
        _alice_dest,
        _bob_dest,
        alice_announced,
        bob_announced,
    ) = setup_two_peers_announced();

    // Alice → Bob
    let dest_to_bob = Destination::single_out(APP_NAME, &["msg", "rx"], &bob_announced);
    alice_node.send_packet(&dest_to_bob, b"A->B").unwrap();

    // Bob → Alice
    let dest_to_alice = Destination::single_out(APP_NAME, &["msg", "rx"], &alice_announced);
    bob_node.send_packet(&dest_to_alice, b"B->A").unwrap();

    let (_, bob_raw, _) = wait_for_delivery(&bob_rx, TIMEOUT).expect("Bob did not receive");
    let bob_plain = decrypt_delivery(&bob_raw, &bob_id).expect("Bob decrypt failed");
    assert_eq!(bob_plain, b"A->B");

    let (_, alice_raw, _) = wait_for_delivery(&alice_rx, TIMEOUT).expect("Alice did not receive");
    let alice_plain = decrypt_delivery(&alice_raw, &alice_id).expect("Alice decrypt failed");
    assert_eq!(alice_plain, b"B->A");

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_single_multiple_sequential() {
    let (
        transport,
        alice_node,
        _alice_rx,
        _bob_node,
        bob_rx,
        _alice_id,
        bob_id,
        _alice_dest,
        _bob_dest,
        _alice_ann,
        bob_announced,
    ) = setup_two_peers_announced();

    let dest_to_bob = Destination::single_out(APP_NAME, &["msg", "rx"], &bob_announced);

    for i in 0..5 {
        let msg = format!("Message #{}", i);
        alice_node
            .send_packet(&dest_to_bob, msg.as_bytes())
            .unwrap();

        let (_, raw, _) = wait_for_delivery(&bob_rx, TIMEOUT)
            .unwrap_or_else(|| panic!("Bob did not receive message #{}", i));
        let decrypted = decrypt_delivery(&raw, &bob_id).expect("Decryption failed");
        assert_eq!(decrypted, msg.as_bytes());
    }

    alice_node.shutdown();
    _bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_single_empty_payload() {
    let (
        transport,
        alice_node,
        _alice_rx,
        _bob_node,
        bob_rx,
        _alice_id,
        bob_id,
        _alice_dest,
        _bob_dest,
        _alice_ann,
        bob_announced,
    ) = setup_two_peers_announced();

    let dest_to_bob = Destination::single_out(APP_NAME, &["msg", "rx"], &bob_announced);
    alice_node.send_packet(&dest_to_bob, b"").unwrap();

    let (_, raw, _) =
        wait_for_delivery(&bob_rx, TIMEOUT).expect("Bob did not receive empty message");
    let decrypted = decrypt_delivery(&raw, &bob_id).expect("Decryption failed");
    assert_eq!(decrypted, b"");

    alice_node.shutdown();
    _bob_node.shutdown();
    transport.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. PLAIN Destinations
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_plain_message_delivery() {
    // PLAIN packets are limited to 1 hop, so use direct connection
    let port = find_free_port();

    let plain_dest = Destination::plain(APP_NAME, &["plain", "test"]);

    // Bob runs TCP server
    let bob_identity = Identity::new(&mut OsRng);
    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            transport_enabled: false,
            identity: Some(Identity::from_private_key(
                &bob_identity.get_private_key().unwrap(),
            )),
            interfaces: vec![InterfaceConfig {
                name: String::new(),
                type_name: "TCPServerInterface".to_string(),
                config_data: Box::new(TcpServerConfig {
                    name: "Bob TCP Server".into(),
                    listen_ip: "127.0.0.1".into(),
                    listen_port: port,
                    interface_id: InterfaceId(1),
                    max_connections: None,
                    ..TcpServerConfig::default()
                }),
                mode: MODE_FULL,
                ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
                ifac: None,
                discovery: None,
            }],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            device: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery_required_value: None,
            respond_to_probes: false,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: 8192,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: rns_net::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity:
                rns_net::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "rns-hooks")]
            provider_bridge: None,
        },
        Box::new(TestCallbacks::new(bob_tx)),
    )
    .unwrap();
    bob_node
        .register_destination(plain_dest.hash.0, rns_core::constants::DESTINATION_PLAIN)
        .unwrap();

    // Alice connects as TCP client
    let alice_identity = Identity::new(&mut OsRng);
    let (alice_tx, _alice_rx) = mpsc::channel();
    let alice_node = start_client_node(
        port,
        &alice_identity,
        Box::new(TestCallbacks::new(alice_tx)),
    );

    std::thread::sleep(SETTLE);

    alice_node.send_packet(&plain_dest, b"plain text").unwrap();

    let (_, raw, _) =
        wait_for_delivery(&bob_rx, TIMEOUT).expect("Bob did not receive plain message");
    let packet = rns_core::packet::RawPacket::unpack(&raw).unwrap();
    assert_eq!(packet.data, b"plain text");

    alice_node.shutdown();
    bob_node.shutdown();
}

#[test]
fn test_single_duplicate_packet_dropped_until_fifo_eviction() {
    let (
        transport,
        alice_node,
        _alice_rx,
        bob_node,
        bob_rx,
        _alice_id,
        bob_id,
        _alice_dest,
        _bob_dest,
        _alice_announced,
        bob_announced,
    ) = setup_two_peers_announced_no_proof_with_packet_hashlist(2);

    let dest_to_bob = Destination::single_out(APP_NAME, &["msg", "rx"], &bob_announced);

    let hash1 = alice_node.send_packet(&dest_to_bob, b"packet-one").unwrap();
    let (_, raw1, recv_hash1) =
        wait_for_delivery(&bob_rx, TIMEOUT).expect("Bob did not receive first single packet");
    assert_eq!(recv_hash1, hash1);

    alice_node
        .send_raw(raw1.clone(), rns_core::constants::DESTINATION_SINGLE, None)
        .unwrap();
    assert!(
        wait_for_delivery(&bob_rx, Duration::from_millis(500)).is_none(),
        "duplicate single packet should be suppressed"
    );

    alice_node.send_packet(&dest_to_bob, b"packet-two").unwrap();
    wait_for_delivery(&bob_rx, TIMEOUT).expect("Bob did not receive second unique single packet");

    alice_node
        .send_packet(&dest_to_bob, b"packet-three")
        .unwrap();
    wait_for_delivery(&bob_rx, TIMEOUT).expect("Bob did not receive third unique single packet");

    alice_node
        .send_raw(raw1, rns_core::constants::DESTINATION_SINGLE, None)
        .unwrap();
    let (_, raw1_again, recv_hash1_again) = wait_for_delivery(&bob_rx, TIMEOUT)
        .expect("evicted oldest single packet should be deliverable again");
    assert_eq!(recv_hash1_again, hash1);
    let decrypted = decrypt_delivery(&raw1_again, &bob_id).expect("Decryption failed");
    assert_eq!(decrypted, b"packet-one");

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_single_duplicate_does_not_refresh_recency() {
    let (
        transport,
        alice_node,
        _alice_rx,
        bob_node,
        bob_rx,
        _alice_id,
        bob_id,
        _alice_dest,
        _bob_dest,
        _alice_announced,
        bob_announced,
    ) = setup_two_peers_announced_no_proof_with_packet_hashlist(2);

    let dest_to_bob = Destination::single_out(APP_NAME, &["msg", "rx"], &bob_announced);

    let oldest_hash = alice_node.send_packet(&dest_to_bob, b"oldest").unwrap();
    let (_, oldest_raw, recv_oldest_hash) =
        wait_for_delivery(&bob_rx, TIMEOUT).expect("Bob did not receive oldest packet");
    assert_eq!(recv_oldest_hash, oldest_hash);

    let newer_hash = alice_node.send_packet(&dest_to_bob, b"newer").unwrap();
    let (_, newer_raw, recv_newer_hash) =
        wait_for_delivery(&bob_rx, TIMEOUT).expect("Bob did not receive newer packet");
    assert_eq!(recv_newer_hash, newer_hash);

    alice_node
        .send_raw(
            oldest_raw.clone(),
            rns_core::constants::DESTINATION_SINGLE,
            None,
        )
        .unwrap();
    assert!(
        wait_for_delivery(&bob_rx, Duration::from_millis(500)).is_none(),
        "duplicate oldest packet should be suppressed"
    );

    alice_node.send_packet(&dest_to_bob, b"fresh").unwrap();
    wait_for_delivery(&bob_rx, TIMEOUT).expect("Bob did not receive fresh packet");

    alice_node
        .send_raw(
            newer_raw.clone(),
            rns_core::constants::DESTINATION_SINGLE,
            None,
        )
        .unwrap();
    assert!(
        wait_for_delivery(&bob_rx, Duration::from_millis(500)).is_none(),
        "newer packet should still be retained after duplicate of oldest"
    );

    alice_node
        .send_raw(oldest_raw, rns_core::constants::DESTINATION_SINGLE, None)
        .unwrap();
    let (_, oldest_raw_again, recv_oldest_hash_again) = wait_for_delivery(&bob_rx, TIMEOUT)
        .expect("oldest packet should be deliverable again after FIFO eviction");
    assert_eq!(recv_oldest_hash_again, oldest_hash);
    let decrypted = decrypt_delivery(&oldest_raw_again, &bob_id).expect("Decryption failed");
    assert_eq!(decrypted, b"oldest");

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. GROUP Destinations
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_group_message_delivery() {
    // GROUP packets are limited to 1 hop, so use direct connection
    let port = find_free_port();

    let mut group_dest_sender = Destination::group(APP_NAME, &["group", "test"]);
    group_dest_sender.create_keys();
    let group_key = group_dest_sender.get_private_key().unwrap().to_vec();

    let mut group_dest_receiver = Destination::group(APP_NAME, &["group", "test"]);
    group_dest_receiver.load_private_key(group_key).unwrap();

    // Bob runs TCP server
    let bob_identity = Identity::new(&mut OsRng);
    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            transport_enabled: false,
            identity: Some(Identity::from_private_key(
                &bob_identity.get_private_key().unwrap(),
            )),
            interfaces: vec![InterfaceConfig {
                name: String::new(),
                type_name: "TCPServerInterface".to_string(),
                config_data: Box::new(TcpServerConfig {
                    name: "Bob TCP Server".into(),
                    listen_ip: "127.0.0.1".into(),
                    listen_port: port,
                    interface_id: InterfaceId(1),
                    max_connections: None,
                    ..TcpServerConfig::default()
                }),
                mode: MODE_FULL,
                ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
                ifac: None,
                discovery: None,
            }],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            device: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery_required_value: None,
            respond_to_probes: false,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: 8192,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: rns_net::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity:
                rns_net::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "rns-hooks")]
            provider_bridge: None,
        },
        Box::new(TestCallbacks::new(bob_tx)),
    )
    .unwrap();
    bob_node
        .register_destination(
            group_dest_receiver.hash.0,
            rns_core::constants::DESTINATION_GROUP,
        )
        .unwrap();

    // Alice connects as TCP client
    let alice_identity = Identity::new(&mut OsRng);
    let (alice_tx, _alice_rx) = mpsc::channel();
    let alice_node = start_client_node(
        port,
        &alice_identity,
        Box::new(TestCallbacks::new(alice_tx)),
    );

    std::thread::sleep(SETTLE);

    alice_node
        .send_packet(&group_dest_sender, b"group message")
        .unwrap();

    let (_, raw, _) =
        wait_for_delivery(&bob_rx, TIMEOUT).expect("Bob did not receive group message");
    let packet = rns_core::packet::RawPacket::unpack(&raw).unwrap();
    let decrypted = group_dest_receiver
        .decrypt(&packet.data)
        .expect("GROUP decrypt failed");
    assert_eq!(decrypted, b"group message");

    alice_node.shutdown();
    bob_node.shutdown();
}

#[test]
fn test_group_wrong_key_fails() {
    // GROUP packets are limited to 1 hop, so use direct connection
    let port = find_free_port();

    let mut group_dest_sender = Destination::group(APP_NAME, &["group", "wrongkey"]);
    group_dest_sender.create_keys();

    // Receiver has a different key
    let mut group_dest_receiver = Destination::group(APP_NAME, &["group", "wrongkey"]);
    group_dest_receiver.create_keys(); // different random key

    // Bob runs TCP server
    let bob_identity = Identity::new(&mut OsRng);
    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            transport_enabled: false,
            identity: Some(Identity::from_private_key(
                &bob_identity.get_private_key().unwrap(),
            )),
            interfaces: vec![InterfaceConfig {
                name: String::new(),
                type_name: "TCPServerInterface".to_string(),
                config_data: Box::new(TcpServerConfig {
                    name: "Bob TCP Server".into(),
                    listen_ip: "127.0.0.1".into(),
                    listen_port: port,
                    interface_id: InterfaceId(1),
                    max_connections: None,
                    ..TcpServerConfig::default()
                }),
                mode: MODE_FULL,
                ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
                ifac: None,
                discovery: None,
            }],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            device: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery_required_value: None,
            respond_to_probes: false,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: 8192,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: rns_net::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity:
                rns_net::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "rns-hooks")]
            provider_bridge: None,
        },
        Box::new(TestCallbacks::new(bob_tx)),
    )
    .unwrap();
    bob_node
        .register_destination(
            group_dest_receiver.hash.0,
            rns_core::constants::DESTINATION_GROUP,
        )
        .unwrap();

    // Alice connects as TCP client
    let alice_identity = Identity::new(&mut OsRng);
    let (alice_tx, _alice_rx) = mpsc::channel();
    let alice_node = start_client_node(
        port,
        &alice_identity,
        Box::new(TestCallbacks::new(alice_tx)),
    );

    std::thread::sleep(SETTLE);

    alice_node
        .send_packet(&group_dest_sender, b"secret")
        .unwrap();

    let (_, raw, _) =
        wait_for_delivery(&bob_rx, TIMEOUT).expect("Bob did not receive group message");
    let packet = rns_core::packet::RawPacket::unpack(&raw).unwrap();
    let result = group_dest_receiver.decrypt(&packet.data);
    assert!(result.is_err(), "Decryption with wrong key should fail");

    alice_node.shutdown();
    bob_node.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. Proof Strategies
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_prove_all() {
    let (
        transport,
        alice_node,
        alice_rx,
        _bob_node,
        _bob_rx,
        _alice_id,
        _bob_id,
        _alice_dest,
        _bob_dest,
        _alice_ann,
        bob_announced,
    ) = setup_two_peers_announced();

    let dest_to_bob = Destination::single_out(APP_NAME, &["msg", "rx"], &bob_announced);
    let pkt_hash = alice_node.send_packet(&dest_to_bob, b"prove me").unwrap();

    let (proof_hash, rtt) =
        wait_for_proof(&alice_rx, TIMEOUT).expect("Alice did not receive proof");
    assert_eq!(proof_hash, pkt_hash);
    assert!(rtt > 0.0, "RTT should be positive");

    alice_node.shutdown();
    _bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_prove_app_conditional() {
    let port = find_free_port();
    let transport = start_transport_node(port);

    let alice_identity = Identity::new(&mut OsRng);
    let alice_ih = IdentityHash(*alice_identity.hash());
    let alice_dest = Destination::single_in(APP_NAME, &["prove", "app"], alice_ih)
        .set_proof_strategy(ProofStrategy::ProveAll);

    let bob_identity = Identity::new(&mut OsRng);
    let bob_ih = IdentityHash(*bob_identity.hash());
    let bob_dest = Destination::single_in(APP_NAME, &["prove", "app"], bob_ih)
        .set_proof_strategy(ProofStrategy::ProveApp);

    let (alice_tx, alice_rx) = mpsc::channel();
    let alice_node = start_client_node(
        port,
        &alice_identity,
        Box::new(TestCallbacks::new(alice_tx)),
    );
    alice_node
        .register_destination_with_proof(
            &alice_dest,
            Some(alice_identity.get_private_key().unwrap()),
        )
        .unwrap();

    let proof_flag = Arc::new(Mutex::new(true));
    let resource_flag = Arc::new(Mutex::new(true));
    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_callbacks = TestCallbacks::with_flags(bob_tx, proof_flag.clone(), resource_flag);
    let bob_node = start_client_node(port, &bob_identity, Box::new(bob_callbacks));
    bob_node
        .register_destination_with_proof(&bob_dest, Some(bob_identity.get_private_key().unwrap()))
        .unwrap();

    std::thread::sleep(SETTLE);

    let bob_ann =
        announce_with_retry(&bob_node, &bob_dest, &bob_identity, Some(b"B"), &alice_rx).unwrap();
    let _alice_ann = announce_with_retry(
        &alice_node,
        &alice_dest,
        &alice_identity,
        Some(b"A"),
        &bob_rx,
    )
    .unwrap();

    // First send: proof_flag=true → should get proof
    let dest_to_bob = Destination::single_out(APP_NAME, &["prove", "app"], &bob_ann);
    let pkt1 = alice_node.send_packet(&dest_to_bob, b"first").unwrap();
    let proof1 = wait_for_proof(&alice_rx, TIMEOUT);
    assert!(proof1.is_some(), "Should receive proof when flag=true");
    assert_eq!(proof1.unwrap().0, pkt1);

    // Set flag to false
    *proof_flag.lock().unwrap() = false;
    std::thread::sleep(Duration::from_millis(200));

    // Second send: proof_flag=false → no proof
    let _pkt2 = alice_node.send_packet(&dest_to_bob, b"second").unwrap();
    let proof2 = wait_for_proof(&alice_rx, Duration::from_secs(3));
    assert!(proof2.is_none(), "Should NOT receive proof when flag=false");

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_prove_none() {
    let port = find_free_port();
    let transport = start_transport_node(port);

    let alice_identity = Identity::new(&mut OsRng);
    let alice_ih = IdentityHash(*alice_identity.hash());
    let alice_dest = Destination::single_in(APP_NAME, &["prove", "none"], alice_ih)
        .set_proof_strategy(ProofStrategy::ProveAll);

    let bob_identity = Identity::new(&mut OsRng);
    let bob_ih = IdentityHash(*bob_identity.hash());
    let bob_dest = Destination::single_in(APP_NAME, &["prove", "none"], bob_ih)
        .set_proof_strategy(ProofStrategy::ProveNone);

    let (alice_tx, alice_rx) = mpsc::channel();
    let alice_node = start_client_node(
        port,
        &alice_identity,
        Box::new(TestCallbacks::new(alice_tx)),
    );
    alice_node
        .register_destination_with_proof(
            &alice_dest,
            Some(alice_identity.get_private_key().unwrap()),
        )
        .unwrap();

    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = start_client_node(port, &bob_identity, Box::new(TestCallbacks::new(bob_tx)));
    bob_node
        .register_destination_with_proof(&bob_dest, None)
        .unwrap();

    std::thread::sleep(SETTLE);

    let bob_ann =
        announce_with_retry(&bob_node, &bob_dest, &bob_identity, Some(b"B"), &alice_rx).unwrap();
    let _alice_ann = announce_with_retry(
        &alice_node,
        &alice_dest,
        &alice_identity,
        Some(b"A"),
        &bob_rx,
    )
    .unwrap();

    let dest_to_bob = Destination::single_out(APP_NAME, &["prove", "none"], &bob_ann);
    alice_node
        .send_packet(&dest_to_bob, b"no proof expected")
        .unwrap();

    let proof = wait_for_proof(&alice_rx, Duration::from_secs(3));
    assert!(proof.is_none(), "Should NOT receive proof with ProveNone");

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. Multi-hop & Path Queries
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_multihop_message_delivery() {
    // A ↔ Transport ↔ B (message crosses the transport hop)
    let (
        transport,
        alice_node,
        alice_rx,
        bob_node,
        bob_rx,
        alice_id,
        bob_id,
        _alice_dest,
        _bob_dest,
        _alice_ann,
        bob_announced,
    ) = setup_two_peers_announced();

    let dest_to_bob = Destination::single_out(APP_NAME, &["msg", "rx"], &bob_announced);
    alice_node.send_packet(&dest_to_bob, b"multi-hop").unwrap();

    let (_, raw, _) =
        wait_for_delivery(&bob_rx, TIMEOUT).expect("Bob did not receive multi-hop message");
    let decrypted = decrypt_delivery(&raw, &bob_id).expect("Decryption failed");
    assert_eq!(decrypted, b"multi-hop");

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_path_queries() {
    let (
        transport,
        alice_node,
        _alice_rx,
        _bob_node,
        _bob_rx,
        _alice_id,
        _bob_id,
        _alice_dest,
        bob_dest,
        _alice_ann,
        _bob_ann,
    ) = setup_two_peers_announced();

    // Alice should have a path to Bob
    let has = alice_node.has_path(&bob_dest.hash).unwrap();
    assert!(has, "Alice should have path to Bob");

    let hops = alice_node.hops_to(&bob_dest.hash).unwrap();
    assert!(hops.is_some(), "Should know hop count to Bob");

    // Unknown destination
    let unknown = DestHash([0xAA; 16]);
    let has_unknown = alice_node.has_path(&unknown).unwrap();
    assert!(!has_unknown, "Should not have path to unknown");

    let hops_unknown = alice_node.hops_to(&unknown).unwrap();
    assert!(hops_unknown.is_none(), "Unknown dest hops should be None");

    alice_node.shutdown();
    _bob_node.shutdown();
    transport.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 7. Link Lifecycle
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_link_establish_and_teardown() {
    let (
        transport,
        alice_node,
        alice_rx,
        bob_node,
        bob_rx,
        alice_id,
        bob_id,
        alice_dest,
        bob_dest,
        link_id,
    ) = setup_link();

    // Teardown from initiator (Alice)
    alice_node.teardown_link(link_id).unwrap();

    let (closed_id, _reason) =
        wait_for_link_closed(&alice_rx, TIMEOUT).expect("Alice did not get link closed");
    assert_eq!(closed_id, link_id);

    let (closed_id_bob, _reason_bob) =
        wait_for_link_closed(&bob_rx, TIMEOUT).expect("Bob did not get link closed");
    assert_eq!(closed_id_bob, link_id);

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_link_callbacks_both_sides() {
    let port = find_free_port();
    let transport = start_transport_node(port);

    let alice_id = Identity::new(&mut OsRng);
    let bob_id = Identity::new(&mut OsRng);

    let alice_dest =
        Destination::single_in(APP_NAME, &["link", "cb"], IdentityHash(*alice_id.hash()))
            .set_proof_strategy(ProofStrategy::ProveAll);
    let bob_dest = Destination::single_in(APP_NAME, &["link", "cb"], IdentityHash(*bob_id.hash()))
        .set_proof_strategy(ProofStrategy::ProveAll);

    let (alice_tx, alice_rx) = mpsc::channel();
    let alice_node = start_client_node(port, &alice_id, Box::new(TestCallbacks::new(alice_tx)));
    alice_node
        .register_destination_with_proof(&alice_dest, Some(alice_id.get_private_key().unwrap()))
        .unwrap();

    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = start_client_node(port, &bob_id, Box::new(TestCallbacks::new(bob_tx)));
    bob_node
        .register_destination_with_proof(&bob_dest, Some(bob_id.get_private_key().unwrap()))
        .unwrap();

    std::thread::sleep(SETTLE);

    let _bob_ann =
        announce_with_retry(&bob_node, &bob_dest, &bob_id, Some(b"B"), &alice_rx).unwrap();
    let _alice_ann =
        announce_with_retry(&alice_node, &alice_dest, &alice_id, Some(b"A"), &bob_rx).unwrap();

    // Register Bob as link destination
    let (bob_sig_prv, bob_sig_pub) = extract_sig_keys(&bob_id);
    bob_node
        .register_link_destination(bob_dest.hash.0, bob_sig_prv, bob_sig_pub, 0)
        .unwrap();

    let bob_pub = bob_id.get_public_key().unwrap();
    let mut bob_sig_pub_for_link = [0u8; 32];
    bob_sig_pub_for_link.copy_from_slice(&bob_pub[32..64]);
    let link_id = alice_node
        .create_link(bob_dest.hash.0, bob_sig_pub_for_link)
        .unwrap();

    // Alice: initiator
    let (a_lid, _, a_init) =
        wait_for_link_established(&alice_rx, TIMEOUT).expect("Alice link not established");
    assert_eq!(a_lid, link_id);
    assert!(a_init, "Alice should be initiator");

    // Bob: responder
    let (b_lid, _, b_init) =
        wait_for_link_established(&bob_rx, TIMEOUT).expect("Bob link not established");
    assert_eq!(b_lid, link_id, "Both sides should see the same link_id");
    assert!(!b_init, "Bob should NOT be initiator");

    alice_node.teardown_link(link_id).unwrap();
    std::thread::sleep(Duration::from_millis(500));

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_link_teardown_by_responder() {
    let (
        transport,
        alice_node,
        alice_rx,
        bob_node,
        bob_rx,
        _alice_id,
        _bob_id,
        _alice_dest,
        _bob_dest,
        link_id,
    ) = setup_link();

    // Bob (responder) tears down
    bob_node.teardown_link(link_id).unwrap();

    let (closed_bob, _) =
        wait_for_link_closed(&bob_rx, TIMEOUT).expect("Bob did not get link closed");
    assert_eq!(closed_bob, link_id);

    let (closed_alice, _) =
        wait_for_link_closed(&alice_rx, TIMEOUT).expect("Alice did not get link closed");
    assert_eq!(closed_alice, link_id);

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 8. Link Identification
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_identify_on_link() {
    let (
        transport,
        alice_node,
        _alice_rx,
        _bob_node,
        bob_rx,
        alice_id,
        _bob_id,
        _alice_dest,
        _bob_dest,
        link_id,
    ) = setup_link();

    alice_node
        .identify_on_link(link_id, alice_id.get_private_key().unwrap())
        .unwrap();

    let (id_link, id_hash) =
        wait_for_remote_identified(&bob_rx, TIMEOUT).expect("Bob did not receive identification");
    assert_eq!(id_link, link_id);
    assert_eq!(id_hash.0, *alice_id.hash());

    alice_node.teardown_link(link_id).unwrap();
    std::thread::sleep(Duration::from_millis(500));

    alice_node.shutdown();
    _bob_node.shutdown();
    transport.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 9. Request/Response
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_request_response_roundtrip() {
    let (
        transport,
        alice_node,
        alice_rx,
        bob_node,
        _bob_rx,
        _alice_id,
        _bob_id,
        _alice_dest,
        _bob_dest,
        link_id,
    ) = setup_link();

    // Register echo handler on Bob
    bob_node
        .register_request_handler("/echo", None, |_link_id, _path, data, _identity| {
            Some(data.to_vec())
        })
        .unwrap();

    std::thread::sleep(Duration::from_millis(200));

    alice_node.send_request(link_id, "/echo", b"ping").unwrap();

    let (resp_lid, _req_id, resp_data) =
        wait_for_response(&alice_rx, TIMEOUT).expect("Alice did not receive response");
    assert_eq!(resp_lid, link_id);
    // Response data is msgpack-encoded; decode and verify inner bytes
    let resp_value = rns_core::msgpack::unpack_exact(&resp_data).unwrap();
    let resp_bytes = match resp_value {
        rns_core::msgpack::Value::Bin(b) => b,
        _ => panic!("Expected msgpack Bin, got {:?}", resp_value),
    };
    assert_eq!(resp_bytes, b"ping");

    alice_node.teardown_link(link_id).unwrap();
    std::thread::sleep(Duration::from_millis(500));

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_multiple_requests_same_link() {
    let (
        transport,
        alice_node,
        alice_rx,
        bob_node,
        _bob_rx,
        _alice_id,
        _bob_id,
        _alice_dest,
        _bob_dest,
        link_id,
    ) = setup_link();

    bob_node
        .register_request_handler("/echo", None, |_link_id, _path, data, _identity| {
            Some(data.to_vec())
        })
        .unwrap();

    std::thread::sleep(Duration::from_millis(200));

    for i in 0..3 {
        let msg = format!("request-{}", i);
        alice_node
            .send_request(link_id, "/echo", msg.as_bytes())
            .unwrap();

        let (_, _, resp_data) = wait_for_response(&alice_rx, TIMEOUT)
            .unwrap_or_else(|| panic!("Did not receive response #{}", i));
        // Response data is msgpack-encoded; decode and verify inner bytes
        let resp_value = rns_core::msgpack::unpack_exact(&resp_data).unwrap();
        let resp_bytes = match resp_value {
            rns_core::msgpack::Value::Bin(b) => b,
            _ => panic!("Expected msgpack Bin, got {:?}", resp_value),
        };
        assert_eq!(resp_bytes, msg.as_bytes());
    }

    alice_node.teardown_link(link_id).unwrap();
    std::thread::sleep(Duration::from_millis(500));

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 10. Resource Transfer
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_resource_small_transfer() {
    let (
        transport,
        alice_node,
        _alice_rx,
        _bob_node,
        bob_rx,
        _alice_id,
        _bob_id,
        _alice_dest,
        _bob_dest,
        link_id,
    ) = setup_link();

    let data = vec![0x42u8; 100];
    let metadata = b"test-metadata".to_vec();

    alice_node
        .send_resource(link_id, data.clone(), Some(metadata.clone()))
        .unwrap();

    let (r_lid, r_data, r_meta) =
        wait_for_resource_received(&bob_rx, TIMEOUT).expect("Bob did not receive resource");
    assert_eq!(r_lid, link_id);
    assert_eq!(r_data, data);
    assert_eq!(r_meta.as_deref(), Some(metadata.as_slice()));

    alice_node.teardown_link(link_id).unwrap();
    std::thread::sleep(Duration::from_millis(500));

    alice_node.shutdown();
    _bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_resource_multi_part() {
    let (
        transport,
        alice_node,
        _alice_rx,
        _bob_node,
        bob_rx,
        _alice_id,
        _bob_id,
        _alice_dest,
        _bob_dest,
        link_id,
    ) = setup_link();

    // ~2KB data to encourage multi-part transfer
    let data = vec![0xAB; 2048];

    alice_node
        .send_resource(link_id, data.clone(), None)
        .unwrap();

    // Check for progress callbacks (there should be at least one)
    let mut got_progress = false;
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut received_data = None;

    while Instant::now() < deadline {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        match bob_rx.recv_timeout(remaining) {
            Ok(TestEvent::ResourceProgress { .. }) => {
                got_progress = true;
            }
            Ok(TestEvent::ResourceReceived { data, .. }) => {
                received_data = Some(data);
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }

    let received = received_data.expect("Bob did not receive resource");
    assert_eq!(received, data);
    // Progress may or may not fire depending on transfer size and SDU size

    alice_node.teardown_link(link_id).unwrap();
    std::thread::sleep(Duration::from_millis(500));

    alice_node.shutdown();
    _bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_resource_accept_none() {
    let port = find_free_port();
    let transport = start_transport_node(port);

    let alice_id = Identity::new(&mut OsRng);
    let bob_id = Identity::new(&mut OsRng);

    let alice_dest =
        Destination::single_in(APP_NAME, &["res", "none"], IdentityHash(*alice_id.hash()))
            .set_proof_strategy(ProofStrategy::ProveAll);
    let bob_dest = Destination::single_in(APP_NAME, &["res", "none"], IdentityHash(*bob_id.hash()))
        .set_proof_strategy(ProofStrategy::ProveAll);

    let (alice_tx, alice_rx) = mpsc::channel();
    let alice_node = start_client_node(port, &alice_id, Box::new(TestCallbacks::new(alice_tx)));
    alice_node
        .register_destination_with_proof(&alice_dest, Some(alice_id.get_private_key().unwrap()))
        .unwrap();

    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = start_client_node(port, &bob_id, Box::new(TestCallbacks::new(bob_tx)));
    bob_node
        .register_destination_with_proof(&bob_dest, Some(bob_id.get_private_key().unwrap()))
        .unwrap();

    std::thread::sleep(SETTLE);

    let _bob_ann =
        announce_with_retry(&bob_node, &bob_dest, &bob_id, Some(b"B"), &alice_rx).unwrap();
    let _alice_ann =
        announce_with_retry(&alice_node, &alice_dest, &alice_id, Some(b"A"), &bob_rx).unwrap();

    let (bob_sig_prv, bob_sig_pub) = extract_sig_keys(&bob_id);
    bob_node
        .register_link_destination(bob_dest.hash.0, bob_sig_prv, bob_sig_pub, 0)
        .unwrap();

    let bob_pub = bob_id.get_public_key().unwrap();
    let mut bob_sig_pub_link = [0u8; 32];
    bob_sig_pub_link.copy_from_slice(&bob_pub[32..64]);
    let link_id = alice_node
        .create_link(bob_dest.hash.0, bob_sig_pub_link)
        .unwrap();

    wait_for_link_established(&alice_rx, TIMEOUT).unwrap();
    wait_for_link_established(&bob_rx, TIMEOUT).unwrap();

    // Set strategy to AcceptNone (0)
    bob_node.set_resource_strategy(link_id, 0).unwrap();
    std::thread::sleep(Duration::from_millis(200));

    alice_node
        .send_resource(link_id, vec![0x42; 50], None)
        .unwrap();

    // Should not receive the resource
    let received = wait_for_resource_received(&bob_rx, Duration::from_secs(3));
    assert!(
        received.is_none(),
        "Should NOT receive resource with AcceptNone"
    );

    // Sender may get a failure callback
    let failed = wait_for_resource_failed(&alice_rx, Duration::from_secs(3));
    // AcceptNone may silently drop or signal failure - either is valid

    alice_node.teardown_link(link_id).unwrap();
    std::thread::sleep(Duration::from_millis(500));

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_resource_accept_app() {
    let port = find_free_port();
    let transport = start_transport_node(port);

    let alice_id = Identity::new(&mut OsRng);
    let bob_id = Identity::new(&mut OsRng);

    let alice_dest =
        Destination::single_in(APP_NAME, &["res", "app"], IdentityHash(*alice_id.hash()))
            .set_proof_strategy(ProofStrategy::ProveAll);
    let bob_dest = Destination::single_in(APP_NAME, &["res", "app"], IdentityHash(*bob_id.hash()))
        .set_proof_strategy(ProofStrategy::ProveAll);

    let (alice_tx, alice_rx) = mpsc::channel();
    let alice_node = start_client_node(port, &alice_id, Box::new(TestCallbacks::new(alice_tx)));
    alice_node
        .register_destination_with_proof(&alice_dest, Some(alice_id.get_private_key().unwrap()))
        .unwrap();

    let resource_flag = Arc::new(Mutex::new(true));
    let proof_flag = Arc::new(Mutex::new(true));
    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_callbacks = TestCallbacks::with_flags(bob_tx, proof_flag, resource_flag.clone());
    let bob_node = start_client_node(port, &bob_id, Box::new(bob_callbacks));
    bob_node
        .register_destination_with_proof(&bob_dest, Some(bob_id.get_private_key().unwrap()))
        .unwrap();

    std::thread::sleep(SETTLE);

    let _bob_ann =
        announce_with_retry(&bob_node, &bob_dest, &bob_id, Some(b"B"), &alice_rx).unwrap();
    let _alice_ann =
        announce_with_retry(&alice_node, &alice_dest, &alice_id, Some(b"A"), &bob_rx).unwrap();

    let (bob_sig_prv, bob_sig_pub) = extract_sig_keys(&bob_id);
    bob_node
        .register_link_destination(bob_dest.hash.0, bob_sig_prv, bob_sig_pub, 0)
        .unwrap();

    let bob_pub = bob_id.get_public_key().unwrap();
    let mut bob_sig_pub_link = [0u8; 32];
    bob_sig_pub_link.copy_from_slice(&bob_pub[32..64]);
    let link_id = alice_node
        .create_link(bob_dest.hash.0, bob_sig_pub_link)
        .unwrap();

    wait_for_link_established(&alice_rx, TIMEOUT).unwrap();
    wait_for_link_established(&bob_rx, TIMEOUT).unwrap();

    // Set strategy to AcceptApp (2)
    bob_node.set_resource_strategy(link_id, 2).unwrap();
    std::thread::sleep(Duration::from_millis(200));

    // First: accept=true
    *resource_flag.lock().unwrap() = true;
    alice_node
        .send_resource(link_id, vec![0x42; 50], None)
        .unwrap();

    let received = wait_for_resource_received(&bob_rx, TIMEOUT);
    assert!(
        received.is_some(),
        "Should receive resource when AcceptApp=true"
    );

    // Second: accept=false
    *resource_flag.lock().unwrap() = false;
    std::thread::sleep(Duration::from_millis(200));
    alice_node
        .send_resource(link_id, vec![0x43; 50], None)
        .unwrap();

    let not_received = wait_for_resource_received(&bob_rx, Duration::from_secs(3));
    assert!(
        not_received.is_none(),
        "Should NOT receive resource when AcceptApp=false"
    );

    alice_node.teardown_link(link_id).unwrap();
    std::thread::sleep(Duration::from_millis(500));

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 11. Channel Messages
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_channel_message() {
    let (
        transport,
        alice_node,
        _alice_rx,
        _bob_node,
        bob_rx,
        _alice_id,
        _bob_id,
        _alice_dest,
        _bob_dest,
        link_id,
    ) = setup_link();

    alice_node
        .send_channel_message(link_id, 0x1234, b"channel payload".to_vec())
        .unwrap();

    let (ch_lid, ch_msgtype, ch_payload) =
        wait_for_channel_message(&bob_rx, TIMEOUT).expect("Bob did not receive channel message");
    assert_eq!(ch_lid, link_id);
    assert_eq!(ch_msgtype, 0x1234);
    assert_eq!(ch_payload, b"channel payload");

    alice_node.teardown_link(link_id).unwrap();
    std::thread::sleep(Duration::from_millis(500));

    alice_node.shutdown();
    _bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_channel_bidirectional() {
    let (
        transport,
        alice_node,
        alice_rx,
        bob_node,
        bob_rx,
        _alice_id,
        _bob_id,
        _alice_dest,
        _bob_dest,
        link_id,
    ) = setup_link();

    // Alice → Bob
    alice_node
        .send_channel_message(link_id, 0x01, b"from alice".to_vec())
        .unwrap();

    let (_, msgtype, payload) = wait_for_channel_message(&bob_rx, TIMEOUT)
        .expect("Bob did not receive channel message from Alice");
    assert_eq!(msgtype, 0x01);
    assert_eq!(payload, b"from alice");

    // Bob → Alice
    bob_node
        .send_channel_message(link_id, 0x02, b"from bob".to_vec())
        .unwrap();

    let (_, msgtype, payload) = wait_for_channel_message(&alice_rx, TIMEOUT)
        .expect("Alice did not receive channel message from Bob");
    assert_eq!(msgtype, 0x02);
    assert_eq!(payload, b"from bob");

    alice_node.teardown_link(link_id).unwrap();
    std::thread::sleep(Duration::from_millis(500));

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 12. Generic Link Data
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_send_on_link() {
    let (
        transport,
        alice_node,
        _alice_rx,
        _bob_node,
        bob_rx,
        _alice_id,
        _bob_id,
        _alice_dest,
        _bob_dest,
        link_id,
    ) = setup_link();

    alice_node
        .send_on_link(link_id, b"custom data".to_vec(), 0x42)
        .unwrap();

    let (ld_lid, ld_ctx, ld_data) =
        wait_for_link_data(&bob_rx, TIMEOUT).expect("Bob did not receive link data");
    assert_eq!(ld_lid, link_id);
    assert_eq!(ld_ctx, 0x42);
    assert_eq!(ld_data, b"custom data");

    alice_node.teardown_link(link_id).unwrap();
    std::thread::sleep(Duration::from_millis(500));

    alice_node.shutdown();
    _bob_node.shutdown();
    transport.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 13. Query APIs
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_query_interface_stats() {
    let (
        transport,
        alice_node,
        _alice_rx,
        _bob_node,
        _bob_rx,
        _alice_id,
        _bob_id,
        _alice_dest,
        _bob_dest,
        _alice_ann,
        _bob_ann,
    ) = setup_two_peers_announced();

    let resp = alice_node.query(QueryRequest::InterfaceStats).unwrap();
    match resp {
        QueryResponse::InterfaceStats(stats) => {
            assert!(
                !stats.interfaces.is_empty(),
                "Should have at least one interface"
            );
        }
        _ => panic!("Unexpected response type"),
    }

    alice_node.shutdown();
    _bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_query_path_table() {
    let (
        transport,
        alice_node,
        _alice_rx,
        _bob_node,
        _bob_rx,
        _alice_id,
        _bob_id,
        _alice_dest,
        bob_dest,
        _alice_ann,
        _bob_ann,
    ) = setup_two_peers_announced();

    let resp = alice_node
        .query(QueryRequest::PathTable { max_hops: None })
        .unwrap();
    match resp {
        QueryResponse::PathTable(entries) => {
            let found = entries.iter().any(|e| e.hash == bob_dest.hash.0);
            assert!(found, "Bob's dest should appear in path table");
        }
        _ => panic!("Unexpected response type"),
    }

    alice_node.shutdown();
    _bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_query_local_destinations_and_links() {
    let (
        transport,
        alice_node,
        alice_rx,
        bob_node,
        bob_rx,
        alice_id,
        bob_id,
        alice_dest,
        bob_dest,
        link_id,
    ) = setup_link();

    // Query local destinations on Alice
    let resp = alice_node.query(QueryRequest::LocalDestinations).unwrap();
    match resp {
        QueryResponse::LocalDestinations(dests) => {
            let found = dests.iter().any(|d| d.hash == alice_dest.hash.0);
            assert!(found, "Alice's dest should be in local destinations");
        }
        _ => panic!("Unexpected response type"),
    }

    // Query links on Alice
    let resp = alice_node.query(QueryRequest::Links).unwrap();
    match resp {
        QueryResponse::Links(links) => {
            assert!(!links.is_empty(), "Should have at least one link");
        }
        _ => panic!("Unexpected response type"),
    }

    alice_node.teardown_link(link_id).unwrap();
    std::thread::sleep(Duration::from_millis(500));

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 14. UDP Transport
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_udp_announce_and_message() {
    let port_a = find_free_port();
    let port_b = find_free_port();

    let alice_identity = Identity::new(&mut OsRng);
    let alice_ih = IdentityHash(*alice_identity.hash());
    let alice_dest = Destination::single_in(APP_NAME, &["udp", "test"], alice_ih)
        .set_proof_strategy(ProofStrategy::ProveAll);

    let bob_identity = Identity::new(&mut OsRng);
    let bob_ih = IdentityHash(*bob_identity.hash());
    let bob_dest = Destination::single_in(APP_NAME, &["udp", "test"], bob_ih)
        .set_proof_strategy(ProofStrategy::ProveAll);

    // Alice: listens on port_a, forwards to port_b
    let (alice_tx, alice_rx) = mpsc::channel();
    let alice_node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            transport_enabled: false,
            identity: Some(Identity::from_private_key(
                &alice_identity.get_private_key().unwrap(),
            )),
            interfaces: vec![InterfaceConfig {
                name: String::new(),
                type_name: "UDPInterface".to_string(),
                config_data: Box::new(UdpConfig {
                    name: "Alice UDP".into(),
                    listen_ip: Some("127.0.0.1".into()),
                    listen_port: Some(port_a),
                    forward_ip: Some("127.0.0.1".into()),
                    forward_port: Some(port_b),
                    interface_id: InterfaceId(1),
                    ..UdpConfig::default()
                }),
                mode: MODE_FULL,
                ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
                ifac: None,
                discovery: None,
            }],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            device: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery_required_value: None,
            respond_to_probes: false,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: 8192,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: rns_net::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity:
                rns_net::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "rns-hooks")]
            provider_bridge: None,
        },
        Box::new(TestCallbacks::new(alice_tx)),
    )
    .unwrap();

    // Bob: listens on port_b, forwards to port_a
    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            transport_enabled: false,
            identity: Some(Identity::from_private_key(
                &bob_identity.get_private_key().unwrap(),
            )),
            interfaces: vec![InterfaceConfig {
                name: String::new(),
                type_name: "UDPInterface".to_string(),
                config_data: Box::new(UdpConfig {
                    name: "Bob UDP".into(),
                    listen_ip: Some("127.0.0.1".into()),
                    listen_port: Some(port_b),
                    forward_ip: Some("127.0.0.1".into()),
                    forward_port: Some(port_a),
                    interface_id: InterfaceId(1),
                    ..UdpConfig::default()
                }),
                mode: MODE_FULL,
                ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
                ifac: None,
                discovery: None,
            }],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            device: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery_required_value: None,
            respond_to_probes: false,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: 8192,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: rns_net::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity:
                rns_net::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "rns-hooks")]
            provider_bridge: None,
        },
        Box::new(TestCallbacks::new(bob_tx)),
    )
    .unwrap();

    alice_node
        .register_destination_with_proof(
            &alice_dest,
            Some(alice_identity.get_private_key().unwrap()),
        )
        .unwrap();
    bob_node
        .register_destination_with_proof(&bob_dest, Some(bob_identity.get_private_key().unwrap()))
        .unwrap();

    std::thread::sleep(SETTLE);

    // Announce
    alice_node
        .announce(&alice_dest, &alice_identity, Some(b"Alice-UDP"))
        .unwrap();
    bob_node
        .announce(&bob_dest, &bob_identity, Some(b"Bob-UDP"))
        .unwrap();

    let bob_announced = wait_for_announce(&alice_rx, &bob_dest.hash, TIMEOUT)
        .expect("Alice did not receive Bob's UDP announce");
    let _alice_announced = wait_for_announce(&bob_rx, &alice_dest.hash, TIMEOUT)
        .expect("Bob did not receive Alice's UDP announce");

    // Send message
    let dest_to_bob = Destination::single_out(APP_NAME, &["udp", "test"], &bob_announced);
    alice_node.send_packet(&dest_to_bob, b"UDP hello").unwrap();

    let (_, raw, _) = wait_for_delivery(&bob_rx, TIMEOUT).expect("Bob did not receive UDP message");
    let decrypted = decrypt_delivery(&raw, &bob_identity).expect("UDP decrypt failed");
    assert_eq!(decrypted, b"UDP hello");

    alice_node.shutdown();
    bob_node.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 15. Edge Cases
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_rapid_announces() {
    let port = find_free_port();
    let transport = start_transport_node(port);

    let alice_identity = Identity::new(&mut OsRng);
    let alice_ih = IdentityHash(*alice_identity.hash());
    let alice_dest = Destination::single_in(APP_NAME, &["rapid", "ann"], alice_ih);

    let (alice_tx, _alice_rx) = mpsc::channel();
    let alice_node = start_client_node(
        port,
        &alice_identity,
        Box::new(TestCallbacks::new(alice_tx)),
    );
    alice_node
        .register_destination_with_proof(&alice_dest, None)
        .unwrap();

    let bob_identity = Identity::new(&mut OsRng);
    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = start_client_node(port, &bob_identity, Box::new(TestCallbacks::new(bob_tx)));

    std::thread::sleep(SETTLE);

    // Fire 10 rapid announces
    for i in 0..10 {
        let data = format!("rapid-{}", i);
        alice_node
            .announce(&alice_dest, &alice_identity, Some(data.as_bytes()))
            .unwrap();
    }

    // At least 1 should be received
    let received = wait_for_any_announce(&bob_rx, TIMEOUT);
    assert!(
        received.is_some(),
        "Should receive at least one rapid announce"
    );

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

// ─── Discovery E2E ──────────────────────────────────────────────────────────

/// Test that a node with a discoverable backbone interface announces it,
/// and a connected client with discover_interfaces=true stores it.
#[test]
fn discovery_announce_received_by_client() {
    let _ = env_logger::builder().is_test(true).try_init();
    let port = find_free_port();
    let transport_identity = Identity::new(&mut OsRng);

    // Transport node: TCP server with a discoverable interface config
    let transport = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            transport_enabled: true,
            identity: Some(Identity::from_private_key(
                &transport_identity.get_private_key().unwrap(),
            )),
            interfaces: vec![InterfaceConfig {
                name: String::new(),
                type_name: "TCPServerInterface".to_string(),
                config_data: Box::new(TcpServerConfig {
                    name: "Discoverable TCP".into(),
                    listen_ip: "127.0.0.1".into(),
                    listen_port: port,
                    interface_id: InterfaceId(1),
                    max_connections: None,
                    ..TcpServerConfig::default()
                }),
                mode: MODE_FULL,
                ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
                ifac: None,
                discovery: Some(rns_net::discovery::DiscoveryConfig {
                    discovery_name: "TestBackbone".into(),
                    announce_interval: 300, // minimum
                    stamp_value: 8,         // low for fast test
                    reachable_on: Some("10.0.0.1".into()),
                    interface_type: "BackboneInterface".into(),
                    listen_port: Some(port),
                    latitude: Some(40.85),
                    longitude: Some(14.27),
                    height: Some(100.0),
                }),
            }],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            device: None,
            hooks: Vec::new(),
            discover_interfaces: true,
            discovery_required_value: None,
            respond_to_probes: false,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: 8192,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: rns_net::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity:
                rns_net::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "rns-hooks")]
            provider_bridge: None,
        },
        Box::new(TransportCallbacks),
    )
    .expect("Failed to start transport node");

    // Client node: connects to backbone, discover_interfaces enabled
    let client_identity = Identity::new(&mut OsRng);
    let (client_tx, client_rx) = mpsc::channel();

    // Use a temp dir for cache so discovered interfaces get stored
    let tmp_dir = std::env::temp_dir().join(format!("rns-e2e-discovery-{}", std::process::id()));
    let cache_dir = tmp_dir.join("cache");
    let _ = std::fs::create_dir_all(&cache_dir);

    let client = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            transport_enabled: false,
            identity: Some(Identity::from_private_key(
                &client_identity.get_private_key().unwrap(),
            )),
            interfaces: vec![InterfaceConfig {
                name: String::new(),
                type_name: "TCPClientInterface".to_string(),
                config_data: Box::new(TcpClientConfig {
                    name: "Client TCP".into(),
                    target_host: "127.0.0.1".into(),
                    target_port: port,
                    interface_id: InterfaceId(1),
                    ..Default::default()
                }),
                mode: MODE_FULL,
                ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
                ifac: None,
                discovery: None,
            }],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: Some(cache_dir.clone()),
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            device: None,
            hooks: Vec::new(),
            discover_interfaces: true,
            discovery_required_value: Some(8),
            respond_to_probes: false,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: 8192,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: rns_net::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity:
                rns_net::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "rns-hooks")]
            provider_bridge: None,
        },
        Box::new(TestCallbacks::new(client_tx)),
    )
    .expect("Failed to start client node");

    // Wait for the client to connect
    wait_for_event(&client_rx, TIMEOUT, |e| {
        matches!(e, TestEvent::InterfaceUp(_)).then_some(())
    })
    .expect("Client InterfaceUp timed out");

    // The transport's announcer fires on the first tick (last_announced=0, so it's
    // immediately due). Stamp generation at cost=8 is near-instant. The announce
    // should propagate to the client within a few ticks (~seconds).
    // Wait up to 30s for the client to receive the discovery announce.
    let mut found = false;
    for _ in 0..30 {
        std::thread::sleep(Duration::from_secs(1));
        if let Ok(QueryResponse::DiscoveredInterfaces(interfaces)) =
            client.query(QueryRequest::DiscoveredInterfaces {
                only_available: false,
                only_transport: false,
            })
        {
            if !interfaces.is_empty() {
                let iface = &interfaces[0];
                assert_eq!(iface.name, "TestBackbone");
                assert_eq!(iface.interface_type, "BackboneInterface");
                assert_eq!(iface.reachable_on.as_deref(), Some("10.0.0.1"));
                assert_eq!(iface.port, Some(port));
                assert!(iface.stamp_value >= 8, "stamp should meet minimum cost");
                found = true;
                break;
            }
        }
    }

    assert!(
        found,
        "Client should have discovered the transport's backbone interface"
    );

    // Clean up
    client.shutdown();
    transport.shutdown();
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

/// Test that a discovery announce propagates through a relay transport node.
///
/// Topology: Discoverable (TCP server:A) ← Relay (TCP client→A + TCP server:B) ← Client (TCP client→B)
///
/// The relay is a plain transport node (no discovery config). It should forward the
/// discovery announce from Discoverable to Client.
#[test]
fn discovery_announce_through_relay() {
    let _ = env_logger::builder().is_test(true).try_init();
    let port_a = find_free_port();
    let port_b = find_free_port();
    let transport_identity = Identity::new(&mut OsRng);

    // Discoverable node: TCP server with discovery config
    let discoverable = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            transport_enabled: true,
            identity: Some(Identity::from_private_key(
                &transport_identity.get_private_key().unwrap(),
            )),
            interfaces: vec![InterfaceConfig {
                name: String::new(),
                type_name: "TCPServerInterface".to_string(),
                config_data: Box::new(TcpServerConfig {
                    name: "Discoverable TCP".into(),
                    listen_ip: "127.0.0.1".into(),
                    listen_port: port_a,
                    interface_id: InterfaceId(1),
                    max_connections: None,
                    ..TcpServerConfig::default()
                }),
                mode: MODE_FULL,
                ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
                ifac: None,
                discovery: Some(rns_net::discovery::DiscoveryConfig {
                    discovery_name: "RelayedBackbone".into(),
                    announce_interval: 300,
                    stamp_value: 8,
                    reachable_on: Some("10.0.0.1".into()),
                    interface_type: "BackboneInterface".into(),
                    listen_port: Some(port_a),
                    latitude: None,
                    longitude: None,
                    height: None,
                }),
            }],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            device: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery_required_value: None,
            respond_to_probes: false,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: 8192,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: rns_net::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity:
                rns_net::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "rns-hooks")]
            provider_bridge: None,
        },
        Box::new(TransportCallbacks),
    )
    .expect("Failed to start discoverable node");

    // Wait for discoverable to be listening
    std::thread::sleep(Duration::from_millis(500));

    // Relay node: transport, connects to discoverable, serves on port_b
    let relay = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            transport_enabled: true,
            identity: Some(Identity::new(&mut OsRng)),
            interfaces: vec![
                InterfaceConfig {
                    name: String::new(),
                    type_name: "TCPClientInterface".to_string(),
                    config_data: Box::new(TcpClientConfig {
                        name: "Relay Upstream".into(),
                        target_host: "127.0.0.1".into(),
                        target_port: port_a,
                        interface_id: InterfaceId(1),
                        ..Default::default()
                    }),
                    mode: MODE_FULL,
                    ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
                    ifac: None,
                    discovery: None,
                },
                InterfaceConfig {
                    name: String::new(),
                    type_name: "TCPServerInterface".to_string(),
                    config_data: Box::new(TcpServerConfig {
                        name: "Relay Downstream".into(),
                        listen_ip: "127.0.0.1".into(),
                        listen_port: port_b,
                        interface_id: InterfaceId(2),
                        max_connections: None,
                        ..TcpServerConfig::default()
                    }),
                    mode: MODE_FULL,
                    ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
                    ifac: None,
                    discovery: None,
                },
            ],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            device: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery_required_value: None,
            respond_to_probes: false,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: 8192,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: rns_net::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity:
                rns_net::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "rns-hooks")]
            provider_bridge: None,
        },
        Box::new(TransportCallbacks),
    )
    .expect("Failed to start relay node");

    // Wait for relay to connect upstream
    std::thread::sleep(Duration::from_millis(500));

    // Client node: connects to relay, discover_interfaces enabled
    let (client_tx, _client_rx) = mpsc::channel();
    let tmp_dir = std::env::temp_dir().join(format!("rns-e2e-relay-{}", std::process::id()));
    let cache_dir = tmp_dir.join("cache");
    let _ = std::fs::create_dir_all(&cache_dir);

    let client = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            transport_enabled: false,
            identity: Some(Identity::new(&mut OsRng)),
            interfaces: vec![InterfaceConfig {
                name: String::new(),
                type_name: "TCPClientInterface".to_string(),
                config_data: Box::new(TcpClientConfig {
                    name: "Client TCP".into(),
                    target_host: "127.0.0.1".into(),
                    target_port: port_b,
                    interface_id: InterfaceId(1),
                    ..Default::default()
                }),
                mode: MODE_FULL,
                ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
                ifac: None,
                discovery: None,
            }],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: Some(cache_dir.clone()),
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            device: None,
            hooks: Vec::new(),
            discover_interfaces: true,
            discovery_required_value: Some(8),
            respond_to_probes: false,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: 8192,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: rns_net::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity:
                rns_net::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "rns-hooks")]
            provider_bridge: None,
        },
        Box::new(TestCallbacks::new(client_tx)),
    )
    .expect("Failed to start client node");

    // Wait for the discovery announce to propagate through the relay
    let mut found = false;
    for _ in 0..30 {
        std::thread::sleep(Duration::from_secs(1));
        if let Ok(QueryResponse::DiscoveredInterfaces(interfaces)) =
            client.query(QueryRequest::DiscoveredInterfaces {
                only_available: false,
                only_transport: false,
            })
        {
            if !interfaces.is_empty() {
                let iface = &interfaces[0];
                assert_eq!(iface.name, "RelayedBackbone");
                assert_eq!(iface.interface_type, "BackboneInterface");
                assert_eq!(iface.reachable_on.as_deref(), Some("10.0.0.1"));
                assert!(iface.hops >= 1, "should have at least 1 hop through relay");
                found = true;
                break;
            }
        }
    }

    assert!(
        found,
        "Client should have discovered the interface through the relay"
    );

    // Clean up
    client.shutdown();
    relay.shutdown();
    discoverable.shutdown();
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Issue #4: Shared instance client 1-hop transport injection
// ═══════════════════════════════════════════════════════════════════════════════
//
// When a shared instance client sends a SINGLE DATA packet to a destination
// that is 1 hop away (reachable through the daemon's external interface),
// the daemon silently drops the packet because it arrives as HEADER_1 with
// no transport_id.  The daemon's handle_inbound has no forwarding logic for
// this case.
//
// These E2E tests set up a real shared instance daemon with a shared client
// and a remote TCP peer, demonstrating the failure.

/// Start a daemon with share_instance=true, a TCP server for remote peers,
/// and a local server for shared instance clients.
fn start_shared_daemon(tcp_port: u16, shared_port: u16, instance_name: &str) -> RnsNode {
    let node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: true,
            transport_enabled: true,
            identity: Some(Identity::new(&mut OsRng)),
            interfaces: vec![InterfaceConfig {
                name: String::new(),
                type_name: "TCPServerInterface".to_string(),
                config_data: Box::new(TcpServerConfig {
                    name: "Daemon TCP".into(),
                    listen_ip: "127.0.0.1".into(),
                    listen_port: tcp_port,
                    interface_id: InterfaceId(1),
                    max_connections: None,
                    ..TcpServerConfig::default()
                }),
                mode: MODE_FULL,
                ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
                ifac: None,
                discovery: None,
            }],
            share_instance: true,
            instance_name: instance_name.into(),
            shared_instance_port: shared_port,
            rpc_port: 0,
            cache_dir: None,
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            device: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery_required_value: None,
            respond_to_probes: false,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: 8192,
            announce_table_ttl: Duration::from_secs(rns_core::constants::ANNOUNCE_TABLE_TTL as u64),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: rns_net::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity:
                rns_net::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "rns-hooks")]
            provider_bridge: None,
        },
        Box::new(TransportCallbacks),
    )
    .expect("Failed to start shared daemon");

    // Wait for TCP server to be ready
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match std::net::TcpStream::connect(("127.0.0.1", tcp_port)) {
            Ok(stream) => {
                drop(stream);
                break;
            }
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            Err(err) => panic!(
                "Daemon TCP listener on {} did not come up: {}",
                tcp_port, err
            ),
        }
    }

    // Wait a bit for the local server to start too
    std::thread::sleep(Duration::from_millis(100));

    node
}

/// Start a shared instance client connecting to the daemon.
fn start_shared_client(
    shared_port: u16,
    instance_name: &str,
    callbacks: Box<dyn Callbacks>,
) -> RnsNode {
    use rns_net::SharedClientConfig;

    RnsNode::connect_shared(
        SharedClientConfig {
            instance_name: instance_name.into(),
            port: shared_port,
            rpc_port: 0,
        },
        callbacks,
    )
    .expect("Failed to connect shared client")
}

#[test]
fn test_issue4_shared_client_announce_reaches_remote() {
    // Verify that announces from a shared client propagate to remote TCP peers.
    // This is a prerequisite for message delivery and confirms the announce
    // path works even if data delivery is broken.
    let tcp_port = find_free_port();
    let shared_port = find_free_port();
    let instance_name = format!("issue4-ann-{}", tcp_port);

    let daemon = start_shared_daemon(tcp_port, shared_port, &instance_name);

    // Start a remote TCP peer (Bob)
    let bob_id = Identity::new(&mut OsRng);
    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = start_client_node(tcp_port, &bob_id, Box::new(TestCallbacks::new(bob_tx)));
    let bob_dest =
        Destination::single_in(APP_NAME, &["issue4", "ann"], IdentityHash(*bob_id.hash()))
            .set_proof_strategy(ProofStrategy::ProveAll);
    bob_node
        .register_destination_with_proof(&bob_dest, Some(bob_id.get_private_key().unwrap()))
        .unwrap();

    // Start a shared client (Alice)
    let alice_id = Identity::new(&mut OsRng);
    let (alice_tx, alice_rx) = mpsc::channel();
    let alice_node = start_shared_client(
        shared_port,
        &instance_name,
        Box::new(TestCallbacks::new(alice_tx)),
    );
    let alice_dest =
        Destination::single_in(APP_NAME, &["issue4", "ann"], IdentityHash(*alice_id.hash()))
            .set_proof_strategy(ProofStrategy::ProveAll);
    alice_node
        .register_destination_with_proof(&alice_dest, Some(alice_id.get_private_key().unwrap()))
        .unwrap();

    // Wait for interfaces to settle
    wait_for_event(&alice_rx, TIMEOUT, |e| {
        matches!(e, TestEvent::InterfaceUp(_)).then_some(())
    })
    .expect("Alice InterfaceUp timed out");
    wait_for_event(&bob_rx, TIMEOUT, |e| {
        matches!(e, TestEvent::InterfaceUp(_)).then_some(())
    })
    .expect("Bob InterfaceUp timed out");
    std::thread::sleep(SETTLE);

    // Alice (shared client) announces
    alice_node
        .announce(&alice_dest, &alice_id, Some(b"issue4"))
        .unwrap();

    // Bob should receive Alice's announce
    let announced = wait_for_announce(&bob_rx, &alice_dest.hash, TIMEOUT);
    assert!(
        announced.is_some(),
        "Bob should receive Alice's announce from shared client"
    );

    alice_node.shutdown();
    bob_node.shutdown();
    daemon.shutdown();
}

#[test]
fn test_issue4_shared_client_message_to_remote_peer() {
    // This test demonstrates the core bug: a shared instance client sends
    // a SINGLE encrypted message to a remote TCP peer that is 1-hop away.
    // The daemon should forward the message, but currently drops it.
    let tcp_port = find_free_port();
    let shared_port = find_free_port();
    let instance_name = format!("issue4-msg-{}", tcp_port);

    let daemon = start_shared_daemon(tcp_port, shared_port, &instance_name);

    // Start Bob (remote TCP peer)
    let bob_id = Identity::new(&mut OsRng);
    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = start_client_node(tcp_port, &bob_id, Box::new(TestCallbacks::new(bob_tx)));
    let bob_dest =
        Destination::single_in(APP_NAME, &["issue4", "msg"], IdentityHash(*bob_id.hash()))
            .set_proof_strategy(ProofStrategy::ProveAll);
    bob_node
        .register_destination_with_proof(&bob_dest, Some(bob_id.get_private_key().unwrap()))
        .unwrap();

    // Start Alice (shared client)
    let alice_id = Identity::new(&mut OsRng);
    let (alice_tx, alice_rx) = mpsc::channel();
    let alice_node = start_shared_client(
        shared_port,
        &instance_name,
        Box::new(TestCallbacks::new(alice_tx)),
    );
    let alice_dest =
        Destination::single_in(APP_NAME, &["issue4", "msg"], IdentityHash(*alice_id.hash()))
            .set_proof_strategy(ProofStrategy::ProveAll);
    alice_node
        .register_destination_with_proof(&alice_dest, Some(alice_id.get_private_key().unwrap()))
        .unwrap();

    // Wait for interfaces
    wait_for_event(&alice_rx, TIMEOUT, |e| {
        matches!(e, TestEvent::InterfaceUp(_)).then_some(())
    })
    .expect("Alice InterfaceUp timed out");
    wait_for_event(&bob_rx, TIMEOUT, |e| {
        matches!(e, TestEvent::InterfaceUp(_)).then_some(())
    })
    .expect("Bob InterfaceUp timed out");
    std::thread::sleep(SETTLE);

    // Bob announces so Alice can discover him
    let bob_announced = announce_with_retry(&bob_node, &bob_dest, &bob_id, Some(b"bob"), &alice_rx);
    assert!(
        bob_announced.is_some(),
        "Alice should receive Bob's announce"
    );
    let bob_announced = bob_announced.unwrap();

    // Alice sends an encrypted message to Bob
    let dest_to_bob = Destination::single_out(APP_NAME, &["issue4", "msg"], &bob_announced);
    let plaintext = b"Hello from shared client!";
    alice_node.send_packet(&dest_to_bob, plaintext).unwrap();

    // Bob should receive the message — but currently doesn't (issue #4)
    let delivery = wait_for_delivery(&bob_rx, Duration::from_secs(5));

    assert!(
        delivery.is_some(),
        "ISSUE #4: Bob did not receive message from shared client — \
         the daemon dropped the 1-hop HEADER_1 packet from the local client interface"
    );

    if let Some((_, raw, _)) = delivery {
        let decrypted = decrypt_delivery(&raw, &bob_id).expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    alice_node.shutdown();
    bob_node.shutdown();
    daemon.shutdown();
}

#[test]
fn test_issue4_remote_peer_message_to_shared_client() {
    // Reverse direction: remote TCP peer sends a message to the shared client.
    // The daemon has the shared client's destination registered and should
    // deliver it locally.  This direction may or may not work depending on
    // whether the daemon registers the shared client's destinations.
    let tcp_port = find_free_port();
    let shared_port = find_free_port();
    let instance_name = format!("issue4-rev-{}", tcp_port);

    let daemon = start_shared_daemon(tcp_port, shared_port, &instance_name);

    // Start Bob (remote TCP peer)
    let bob_id = Identity::new(&mut OsRng);
    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = start_client_node(tcp_port, &bob_id, Box::new(TestCallbacks::new(bob_tx)));

    // Start Alice (shared client)
    let alice_id = Identity::new(&mut OsRng);
    let (alice_tx, alice_rx) = mpsc::channel();
    let alice_node = start_shared_client(
        shared_port,
        &instance_name,
        Box::new(TestCallbacks::new(alice_tx)),
    );
    let alice_dest =
        Destination::single_in(APP_NAME, &["issue4", "rev"], IdentityHash(*alice_id.hash()))
            .set_proof_strategy(ProofStrategy::ProveAll);
    alice_node
        .register_destination_with_proof(&alice_dest, Some(alice_id.get_private_key().unwrap()))
        .unwrap();

    // Wait for interfaces
    wait_for_event(&alice_rx, TIMEOUT, |e| {
        matches!(e, TestEvent::InterfaceUp(_)).then_some(())
    })
    .expect("Alice InterfaceUp timed out");
    wait_for_event(&bob_rx, TIMEOUT, |e| {
        matches!(e, TestEvent::InterfaceUp(_)).then_some(())
    })
    .expect("Bob InterfaceUp timed out");
    std::thread::sleep(SETTLE);

    // Alice announces so Bob can discover her
    let alice_announced =
        announce_with_retry(&alice_node, &alice_dest, &alice_id, Some(b"alice"), &bob_rx);
    assert!(
        alice_announced.is_some(),
        "Bob should receive Alice's announce from shared client"
    );
    let alice_announced = alice_announced.unwrap();

    // Bob sends an encrypted message to Alice
    let dest_to_alice = Destination::single_out(APP_NAME, &["issue4", "rev"], &alice_announced);
    let plaintext = b"Hello shared client from remote!";
    bob_node.send_packet(&dest_to_alice, plaintext).unwrap();

    // Alice should receive the message
    let delivery = wait_for_delivery(&alice_rx, Duration::from_secs(5));

    assert!(
        delivery.is_some(),
        "ISSUE #4 (reverse): Alice (shared client) did not receive message from Bob — \
         the daemon may not forward external packets to local clients for 1-hop destinations"
    );

    if let Some((_, raw, _)) = delivery {
        let decrypted = decrypt_delivery(&raw, &alice_id).expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    alice_node.shutdown();
    bob_node.shutdown();
    daemon.shutdown();
}
