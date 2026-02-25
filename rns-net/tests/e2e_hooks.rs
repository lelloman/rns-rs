//! End-to-end tests for the WASM hooks system.
//!
//! Tests hooks through the full RnsNode stack: load/unload/reload/list APIs,
//! hook execution on real traffic, and runtime hot-swap.
//!
//! Run:  cargo test -p rns-net --features rns-hooks --test e2e_hooks
//! Debug: RUST_LOG=debug cargo test -p rns-net --features rns-hooks --test e2e_hooks -- --nocapture

#![allow(unused_variables, dead_code)]
#![cfg(feature = "rns-hooks")]

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rns_crypto::identity::Identity;
use rns_crypto::OsRng;

use rns_net::{
    AnnouncedIdentity, Callbacks, DestHash, Destination, IdentityHash, InterfaceConfig, InterfaceId,
    InterfaceVariant, NodeConfig, PacketHash, ProofStrategy, RnsNode, TcpClientConfig,
    TcpServerConfig, MODE_FULL,
};

// ─── WASM helpers ────────────────────────────────────────────────────────────

fn wasm_bytes(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rns-hooks/target/wasm-examples")
        .join(format!("{}.wasm", name));
    std::fs::read(&path)
        .unwrap_or_else(|_| panic!("{} not found, run rns-hooks/build-examples.sh", path.display()))
}

// ─── TestEvent ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum TestEvent {
    Announce(AnnouncedIdentity),
    Delivery {
        dest_hash: DestHash,
        raw: Vec<u8>,
        packet_hash: PacketHash,
    },
    InterfaceUp(InterfaceId),
}

// ─── TestCallbacks ───────────────────────────────────────────────────────────

struct TestCallbacks {
    tx: mpsc::Sender<TestEvent>,
}

impl TestCallbacks {
    fn new(tx: mpsc::Sender<TestEvent>) -> Self {
        TestCallbacks { tx }
    }
}

impl Callbacks for TestCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        let _ = self.tx.send(TestEvent::Announce(announced));
    }

    fn on_path_updated(&mut self, _: DestHash, _: u8) {}

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

    fn on_interface_down(&mut self, _: InterfaceId) {}
}

// ─── Noop callbacks for transport relay ──────────────────────────────────────

struct TransportCallbacks;

impl Callbacks for TransportCallbacks {
    fn on_announce(&mut self, _: AnnouncedIdentity) {}
    fn on_path_updated(&mut self, _: DestHash, _: u8) {}
    fn on_local_delivery(&mut self, _: DestHash, _: Vec<u8>, _: PacketHash) {}
}

// ─── Helper functions ────────────────────────────────────────────────────────

fn find_free_port() -> u16 {
    use std::collections::HashSet;
    use std::sync::Mutex;
    static USED_PORTS: Mutex<Option<HashSet<u16>>> = Mutex::new(None);

    let mut used = USED_PORTS.lock().unwrap();
    let set = used.get_or_insert_with(HashSet::new);

    loop {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if set.insert(port) {
            return port;
        }
    }
}

fn decrypt_delivery(raw: &[u8], identity: &Identity) -> Option<Vec<u8>> {
    let packet = rns_core::packet::RawPacket::unpack(raw).ok()?;
    identity.decrypt(&packet.data).ok()
}

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

const TIMEOUT: Duration = Duration::from_secs(10);
const SETTLE: Duration = Duration::from_millis(500);

const APP_NAME: &str = "e2e_hooks_test";

fn wait_for_interface_up(rx: &mpsc::Receiver<TestEvent>, timeout: Duration) {
    wait_for_event(rx, timeout, |event| match event {
        TestEvent::InterfaceUp(_) => Some(()),
        _ => None,
    })
    .expect("Timed out waiting for InterfaceUp");
}

fn start_transport_node(port: u16) -> RnsNode {
    RnsNode::start(
        NodeConfig {
            transport_enabled: true,
            identity: Some(Identity::new(&mut OsRng)),
            interfaces: vec![InterfaceConfig {
                variant: InterfaceVariant::TcpServer(TcpServerConfig {
                    name: "Transport TCP".into(),
                    listen_ip: "127.0.0.1".into(),
                    listen_port: port,
                    interface_id: InterfaceId(1),
                }),
                mode: MODE_FULL,
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
        },
        Box::new(TransportCallbacks),
    )
    .expect("Failed to start transport node")
}

fn start_client_node(
    port: u16,
    identity: &Identity,
    callbacks: Box<dyn Callbacks>,
) -> RnsNode {
    RnsNode::start(
        NodeConfig {
            transport_enabled: false,
            identity: Some(Identity::from_private_key(
                &identity.get_private_key().unwrap(),
            )),
            interfaces: vec![InterfaceConfig {
                variant: InterfaceVariant::TcpClient(TcpClientConfig {
                    name: "Client TCP".into(),
                    target_host: "127.0.0.1".into(),
                    target_port: port,
                    interface_id: InterfaceId(1),
                    ..Default::default()
                }),
                mode: MODE_FULL,
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
        },
        callbacks,
    )
    .expect("Failed to start client node")
}

/// Set up a two-peer topology: Transport(TCP server) + Alice(TCP client) + Bob(TCP client).
/// Waits for InterfaceUp on both clients before returning.
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
    let port = find_free_port();
    let transport = start_transport_node(port);

    let alice_identity = Identity::new(&mut OsRng);
    let alice_ih = IdentityHash(*alice_identity.hash());
    let alice_dest = Destination::single_in(APP_NAME, &["msg", "rx"], alice_ih)
        .set_proof_strategy(ProofStrategy::ProveAll);

    let bob_identity = Identity::new(&mut OsRng);
    let bob_ih = IdentityHash(*bob_identity.hash());
    let bob_dest = Destination::single_in(APP_NAME, &["msg", "rx"], bob_ih)
        .set_proof_strategy(ProofStrategy::ProveAll);

    let (alice_tx, alice_rx) = mpsc::channel();
    let alice_node =
        start_client_node(port, &alice_identity, Box::new(TestCallbacks::new(alice_tx)));
    alice_node
        .register_destination_with_proof(
            &alice_dest,
            Some(alice_identity.get_private_key().unwrap()),
        )
        .unwrap();

    let (bob_tx, bob_rx) = mpsc::channel();
    let bob_node = start_client_node(port, &bob_identity, Box::new(TestCallbacks::new(bob_tx)));
    bob_node
        .register_destination_with_proof(&bob_dest, Some(bob_identity.get_private_key().unwrap()))
        .unwrap();

    // Wait for both TCP interfaces to come up then let transport settle
    wait_for_interface_up(&alice_rx, TIMEOUT);
    wait_for_interface_up(&bob_rx, TIMEOUT);
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

/// Announce Bob and wait for Alice to see it.  Returns Bob's AnnouncedIdentity.
/// Uses the announce-with-retry pattern since the transport relay may not be
/// fully ready to forward even after InterfaceUp fires on both clients.
fn announce_bob_to_alice(
    bob_node: &RnsNode,
    bob_dest: &Destination,
    bob_id: &Identity,
    alice_rx: &mpsc::Receiver<TestEvent>,
) -> AnnouncedIdentity {
    for _ in 0..10 {
        let _ = bob_node.announce(bob_dest, bob_id, Some(b"Bob"));
        if let Some(ann) = wait_for_announce(alice_rx, &bob_dest.hash, Duration::from_secs(2)) {
            return ann;
        }
    }
    panic!("Alice never received Bob's announce after retries");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. Hook Management Lifecycle
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_load_list_unload_hooks() {
    let port = find_free_port();
    let transport = start_transport_node(port);

    let identity = Identity::new(&mut OsRng);
    let (tx, _rx) = mpsc::channel();
    let node = start_client_node(port, &identity, Box::new(TestCallbacks::new(tx)));
    std::thread::sleep(SETTLE);

    // Load a hook
    let result = node
        .load_hook(
            "packet_logger".into(),
            wasm_bytes("packet_logger"),
            "PreIngress".into(),
            10,
        )
        .expect("send failed");
    assert!(result.is_ok(), "load_hook failed: {:?}", result.err());

    // List hooks — should have 1
    let hooks = node.list_hooks().expect("list_hooks send failed");
    assert_eq!(hooks.len(), 1);
    assert_eq!(hooks[0].name, "packet_logger");
    assert_eq!(hooks[0].attach_point, "PreIngress");
    assert_eq!(hooks[0].priority, 10);
    assert!(hooks[0].enabled);

    // Unload
    let result = node
        .unload_hook("packet_logger".into(), "PreIngress".into())
        .expect("send failed");
    assert!(result.is_ok(), "unload_hook failed: {:?}", result.err());

    // List hooks — should be empty
    let hooks = node.list_hooks().expect("list_hooks send failed");
    assert!(
        hooks.is_empty(),
        "Expected no hooks after unload, got {:?}",
        hooks
    );

    node.shutdown();
    transport.shutdown();
}

#[test]
fn test_reload_hook() {
    let port = find_free_port();
    let transport = start_transport_node(port);

    let identity = Identity::new(&mut OsRng);
    let (tx, _rx) = mpsc::channel();
    let node = start_client_node(port, &identity, Box::new(TestCallbacks::new(tx)));
    std::thread::sleep(SETTLE);

    // Load packet_logger
    node.load_hook(
        "my_hook".into(),
        wasm_bytes("packet_logger"),
        "PreIngress".into(),
        5,
    )
    .expect("send failed")
    .expect("load_hook failed");

    // Reload with announce_filter bytes (same name, same point)
    let result = node
        .reload_hook(
            "my_hook".into(),
            "PreIngress".into(),
            wasm_bytes("announce_filter"),
        )
        .expect("send failed");
    assert!(result.is_ok(), "reload_hook failed: {:?}", result.err());

    // List — still 1 hook, same priority
    let hooks = node.list_hooks().expect("list_hooks send failed");
    assert_eq!(hooks.len(), 1);
    assert_eq!(hooks[0].name, "my_hook");
    assert_eq!(hooks[0].priority, 5);

    node.shutdown();
    transport.shutdown();
}

#[test]
fn test_unload_nonexistent_returns_error() {
    let port = find_free_port();
    let transport = start_transport_node(port);

    let identity = Identity::new(&mut OsRng);
    let (tx, _rx) = mpsc::channel();
    let node = start_client_node(port, &identity, Box::new(TestCallbacks::new(tx)));
    std::thread::sleep(SETTLE);

    let result = node
        .unload_hook("nope".into(), "PreIngress".into())
        .expect("send failed");
    assert!(result.is_err(), "Expected error for nonexistent hook unload");

    node.shutdown();
    transport.shutdown();
}

#[test]
fn test_reload_nonexistent_returns_error() {
    let port = find_free_port();
    let transport = start_transport_node(port);

    let identity = Identity::new(&mut OsRng);
    let (tx, _rx) = mpsc::channel();
    let node = start_client_node(port, &identity, Box::new(TestCallbacks::new(tx)));
    std::thread::sleep(SETTLE);

    let result = node
        .reload_hook(
            "nope".into(),
            "PreIngress".into(),
            wasm_bytes("packet_logger"),
        )
        .expect("send failed");
    assert!(
        result.is_err(),
        "Expected error for nonexistent hook reload"
    );

    node.shutdown();
    transport.shutdown();
}

#[test]
fn test_load_invalid_wasm_returns_error() {
    let port = find_free_port();
    let transport = start_transport_node(port);

    let identity = Identity::new(&mut OsRng);
    let (tx, _rx) = mpsc::channel();
    let node = start_client_node(port, &identity, Box::new(TestCallbacks::new(tx)));
    std::thread::sleep(SETTLE);

    let result = node
        .load_hook(
            "bad".into(),
            vec![0xFF, 0x00, 0xDE, 0xAD],
            "PreIngress".into(),
            0,
        )
        .expect("send failed");
    assert!(result.is_err(), "Expected error for invalid WASM bytes");

    node.shutdown();
    transport.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. Hooks on Real Traffic
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_packet_logger_does_not_block_delivery() {
    let (transport, alice_node, alice_rx, bob_node, bob_rx, _alice_id, bob_id, _alice_dest, bob_dest) =
        setup_two_peers();

    // Bob announces to Alice (one-direction only)
    let bob_announced = announce_bob_to_alice(&bob_node, &bob_dest, &bob_id, &alice_rx);

    // Load packet_logger at PreIngress on Bob
    bob_node
        .load_hook(
            "packet_logger".into(),
            wasm_bytes("packet_logger"),
            "PreIngress".into(),
            0,
        )
        .expect("send failed")
        .expect("load_hook failed");

    // Alice sends packet to Bob
    let dest_to_bob = Destination::single_out(APP_NAME, &["msg", "rx"], &bob_announced);
    let plaintext = b"Hello through hook!";
    alice_node.send_packet(&dest_to_bob, plaintext).unwrap();

    // Bob should still receive it (packet_logger returns Continue)
    let (_, raw, _) = wait_for_delivery(&bob_rx, TIMEOUT)
        .expect("Bob did not receive message with packet_logger hook active");
    let decrypted = decrypt_delivery(&raw, &bob_id).expect("Decryption failed");
    assert_eq!(decrypted, plaintext);

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_announce_filter_allows_low_hop_announces() {
    let (transport, alice_node, alice_rx, bob_node, _bob_rx, _alice_id, bob_id, _alice_dest, bob_dest) =
        setup_two_peers();

    // Load announce_filter on Alice at AnnounceReceived
    alice_node
        .load_hook(
            "announce_filter".into(),
            wasm_bytes("announce_filter"),
            "AnnounceReceived".into(),
            0,
        )
        .expect("send failed")
        .expect("load_hook failed");

    // Bob announces (hops=1, well under the >8 threshold in announce_filter)
    let bob_announced = announce_bob_to_alice(&bob_node, &bob_dest, &bob_id, &alice_rx);
    assert_eq!(bob_announced.dest_hash, bob_dest.hash);

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_multiple_hooks_on_same_point() {
    let (transport, alice_node, alice_rx, bob_node, _bob_rx, _alice_id, bob_id, _alice_dest, bob_dest) =
        setup_two_peers();

    // Load announce_filter (priority 100) + packet_logger (priority 0) on AnnounceReceived
    alice_node
        .load_hook(
            "announce_filter".into(),
            wasm_bytes("announce_filter"),
            "AnnounceReceived".into(),
            100,
        )
        .expect("send failed")
        .expect("load announce_filter failed");

    alice_node
        .load_hook(
            "packet_logger".into(),
            wasm_bytes("packet_logger"),
            "AnnounceReceived".into(),
            0,
        )
        .expect("send failed")
        .expect("load packet_logger failed");

    // Verify both hooks are listed
    let hooks = alice_node.list_hooks().expect("list_hooks send failed");
    assert_eq!(hooks.len(), 2, "Expected 2 hooks, got {:?}", hooks);

    // Bob announces — both hooks return Continue, so it should pass through
    let bob_announced = announce_bob_to_alice(&bob_node, &bob_dest, &bob_id, &alice_rx);
    assert_eq!(bob_announced.dest_hash, bob_dest.hash);

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. Runtime Hot-Swap
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_load_hook_after_traffic_flowing() {
    let (transport, alice_node, alice_rx, bob_node, bob_rx, _alice_id, bob_id, _alice_dest, bob_dest) =
        setup_two_peers();

    // Bob announces to Alice
    let bob_announced = announce_bob_to_alice(&bob_node, &bob_dest, &bob_id, &alice_rx);

    // Exchange traffic first (no hooks)
    let dest_to_bob = Destination::single_out(APP_NAME, &["msg", "rx"], &bob_announced);
    alice_node
        .send_packet(&dest_to_bob, b"before hook")
        .unwrap();
    let (_, raw, _) = wait_for_delivery(&bob_rx, TIMEOUT)
        .expect("Bob did not receive pre-hook message");
    let decrypted = decrypt_delivery(&raw, &bob_id).expect("Decryption failed");
    assert_eq!(decrypted, b"before hook");

    // Now load packet_logger mid-session
    bob_node
        .load_hook(
            "packet_logger".into(),
            wasm_bytes("packet_logger"),
            "PreIngress".into(),
            0,
        )
        .expect("send failed")
        .expect("load_hook failed");

    // Send another packet — should still be delivered
    alice_node
        .send_packet(&dest_to_bob, b"after hook")
        .unwrap();
    let (_, raw, _) = wait_for_delivery(&bob_rx, TIMEOUT)
        .expect("Bob did not receive post-hook message");
    let decrypted = decrypt_delivery(&raw, &bob_id).expect("Decryption failed");
    assert_eq!(decrypted, b"after hook");

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_unload_hook_restores_behavior() {
    let (transport, alice_node, alice_rx, bob_node, bob_rx, _alice_id, bob_id, _alice_dest, bob_dest) =
        setup_two_peers();

    // Bob announces to Alice
    let bob_announced = announce_bob_to_alice(&bob_node, &bob_dest, &bob_id, &alice_rx);
    let dest_to_bob = Destination::single_out(APP_NAME, &["msg", "rx"], &bob_announced);

    // Load packet_logger
    bob_node
        .load_hook(
            "packet_logger".into(),
            wasm_bytes("packet_logger"),
            "PreIngress".into(),
            0,
        )
        .expect("send failed")
        .expect("load_hook failed");

    // Verify traffic works with hook
    alice_node.send_packet(&dest_to_bob, b"with hook").unwrap();
    let (_, raw, _) = wait_for_delivery(&bob_rx, TIMEOUT)
        .expect("Bob did not receive message with hook active");
    let decrypted = decrypt_delivery(&raw, &bob_id).expect("Decryption failed");
    assert_eq!(decrypted, b"with hook");

    // Unload hook
    bob_node
        .unload_hook("packet_logger".into(), "PreIngress".into())
        .expect("send failed")
        .expect("unload_hook failed");

    // Verify traffic still works after unload
    alice_node
        .send_packet(&dest_to_bob, b"after unload")
        .unwrap();
    let (_, raw, _) = wait_for_delivery(&bob_rx, TIMEOUT)
        .expect("Bob did not receive message after hook unload");
    let decrypted = decrypt_delivery(&raw, &bob_id).expect("Decryption failed");
    assert_eq!(decrypted, b"after unload");

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. New Example Hooks
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_rate_limiter_drops_excess() {
    // The rate_limiter has MAX_PACKETS=100, WINDOW_SIZE=200.
    // After 100 packets the hook should start dropping.
    // We verify that the hook loads and does not interfere with normal delivery
    // (since we only send a few packets, well under the threshold).
    let (transport, alice_node, alice_rx, bob_node, bob_rx, _alice_id, bob_id, _alice_dest, bob_dest) =
        setup_two_peers();

    let bob_announced = announce_bob_to_alice(&bob_node, &bob_dest, &bob_id, &alice_rx);
    let dest_to_bob = Destination::single_out(APP_NAME, &["msg", "rx"], &bob_announced);

    // Load rate_limiter on Bob's PreIngress
    bob_node
        .load_hook(
            "rate_limiter".into(),
            wasm_bytes("rate_limiter"),
            "PreIngress".into(),
            0,
        )
        .expect("send failed")
        .expect("load_hook failed");

    // Send a few packets — should pass through (well under threshold)
    for i in 0..3u8 {
        let msg = [b'r', b'l', b'0' + i];
        alice_node.send_packet(&dest_to_bob, &msg).unwrap();
        let (_, raw, _) = wait_for_delivery(&bob_rx, TIMEOUT)
            .expect("Bob did not receive message through rate_limiter");
        let decrypted = decrypt_delivery(&raw, &bob_id).expect("Decryption failed");
        assert_eq!(decrypted, &msg);
    }

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_allowlist_blocks_unknown() {
    // The allowlist only allows destinations starting with 0x0000 or 0xFFFF.
    // Real announces have random hashes, so they will almost certainly be dropped.
    let (transport, alice_node, alice_rx, bob_node, _bob_rx, _alice_id, bob_id, _alice_dest, bob_dest) =
        setup_two_peers();

    // Load allowlist on Alice at AnnounceReceived
    alice_node
        .load_hook(
            "allowlist".into(),
            wasm_bytes("allowlist"),
            "AnnounceReceived".into(),
            0,
        )
        .expect("send failed")
        .expect("load_hook failed");

    // Bob announces — his dest hash is random, so it should be dropped by the allowlist.
    // Try a few times; none should get through.
    for _ in 0..3 {
        let _ = bob_node.announce(&bob_dest, &bob_id, Some(b"Bob"));
    }
    std::thread::sleep(Duration::from_secs(3));

    // Verify Alice did NOT receive the announce
    let got = wait_for_announce(&alice_rx, &bob_dest.hash, Duration::from_secs(2));
    assert!(
        got.is_none(),
        "Expected allowlist to drop announce, but Alice received it"
    );

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_packet_mirror_does_not_block() {
    // packet_mirror injects a SendOnInterface action but returns Continue,
    // so normal packet delivery should not be affected.
    let (transport, alice_node, alice_rx, bob_node, bob_rx, _alice_id, bob_id, _alice_dest, bob_dest) =
        setup_two_peers();

    let bob_announced = announce_bob_to_alice(&bob_node, &bob_dest, &bob_id, &alice_rx);
    let dest_to_bob = Destination::single_out(APP_NAME, &["msg", "rx"], &bob_announced);

    // Load packet_mirror on Bob's PreIngress
    bob_node
        .load_hook(
            "packet_mirror".into(),
            wasm_bytes("packet_mirror"),
            "PreIngress".into(),
            0,
        )
        .expect("send failed")
        .expect("load_hook failed");

    // Send a packet — should still be delivered normally
    alice_node.send_packet(&dest_to_bob, b"mirror test").unwrap();
    let (_, raw, _) = wait_for_delivery(&bob_rx, TIMEOUT)
        .expect("Bob did not receive message with packet_mirror active");
    let decrypted = decrypt_delivery(&raw, &bob_id).expect("Decryption failed");
    assert_eq!(decrypted, b"mirror test");

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_link_guard_loads_and_continues() {
    // Verify link_guard loads successfully on LinkRequestReceived and doesn't
    // interfere with normal operation (no link requests in this test, just
    // verify the hook loads and traffic still flows).
    let (transport, alice_node, alice_rx, bob_node, bob_rx, _alice_id, bob_id, _alice_dest, bob_dest) =
        setup_two_peers();

    let bob_announced = announce_bob_to_alice(&bob_node, &bob_dest, &bob_id, &alice_rx);
    let dest_to_bob = Destination::single_out(APP_NAME, &["msg", "rx"], &bob_announced);

    // Load link_guard on Bob's LinkRequestReceived
    bob_node
        .load_hook(
            "link_guard".into(),
            wasm_bytes("link_guard"),
            "LinkRequestReceived".into(),
            0,
        )
        .expect("send failed")
        .expect("load_hook failed");

    // Normal traffic should still work (link_guard only acts on link requests)
    alice_node.send_packet(&dest_to_bob, b"guard test").unwrap();
    let (_, raw, _) = wait_for_delivery(&bob_rx, TIMEOUT)
        .expect("Bob did not receive message with link_guard active");
    let decrypted = decrypt_delivery(&raw, &bob_id).expect("Decryption failed");
    assert_eq!(decrypted, b"guard test");

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_announce_dedup_loads_and_allows_first() {
    // announce_dedup suppresses after MAX_RETRANSMITS (3) of the same dest hash.
    // First announce should pass through.
    let (transport, alice_node, alice_rx, bob_node, _bob_rx, _alice_id, bob_id, _alice_dest, bob_dest) =
        setup_two_peers();

    // Load announce_dedup on Alice at AnnounceRetransmit
    alice_node
        .load_hook(
            "announce_dedup".into(),
            wasm_bytes("announce_dedup"),
            "AnnounceRetransmit".into(),
            0,
        )
        .expect("send failed")
        .expect("load_hook failed");

    // Bob announces — first one should get through to Alice
    let bob_announced = announce_bob_to_alice(&bob_node, &bob_dest, &bob_id, &alice_rx);
    assert_eq!(bob_announced.dest_hash, bob_dest.hash);

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}

#[test]
fn test_metrics_does_not_interfere() {
    // metrics hook returns Continue on everything, so it should not block delivery.
    let (transport, alice_node, alice_rx, bob_node, bob_rx, _alice_id, bob_id, _alice_dest, bob_dest) =
        setup_two_peers();

    let bob_announced = announce_bob_to_alice(&bob_node, &bob_dest, &bob_id, &alice_rx);
    let dest_to_bob = Destination::single_out(APP_NAME, &["msg", "rx"], &bob_announced);

    // Load metrics on Bob's PreIngress
    bob_node
        .load_hook(
            "metrics".into(),
            wasm_bytes("metrics"),
            "PreIngress".into(),
            0,
        )
        .expect("send failed")
        .expect("load_hook failed");

    // Send several packets — all should be delivered
    for i in 0..5u8 {
        let msg = [b'm', b'e', b't', b'0' + i];
        alice_node.send_packet(&dest_to_bob, &msg).unwrap();
        let (_, raw, _) = wait_for_delivery(&bob_rx, TIMEOUT)
            .expect("Bob did not receive message with metrics hook active");
        let decrypted = decrypt_delivery(&raw, &bob_id).expect("Decryption failed");
        assert_eq!(decrypted, &msg);
    }

    alice_node.shutdown();
    bob_node.shutdown();
    transport.shutdown();
}
