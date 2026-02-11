//! Two-client encrypted message exchange via a local transport node.
//!
//! Self-contained: spawns three RnsNode instances in the same process:
//!   1. Transport node — TCP server with transport_enabled, relays packets
//!   2. Alice — TCP client, creates SINGLE destination, announces, sends/receives
//!   3. Bob   — TCP client, creates SINGLE destination, announces, sends/receives
//!
//! Exercises: identity creation, TCP, announcing, path discovery via transport,
//! SINGLE encryption, delivery, decryption, and proof round-trip.
//!
//! Usage: RUST_LOG=info cargo run --example message

use std::sync::mpsc;
use std::time::Duration;

use rns_crypto::identity::Identity;
use rns_crypto::OsRng;

use rns_net::{
    AnnouncedIdentity, Callbacks, DestHash, Destination, IdentityHash, InterfaceConfig,
    InterfaceId, InterfaceVariant, NodeConfig, PacketHash, ProofStrategy, RnsNode,
    TcpClientConfig, TcpServerConfig, MODE_FULL,
};

const APP_NAME: &str = "example_utilities";

// ─── Delivery from on_local_delivery ─────────────────────────────────────────

struct Delivery {
    #[allow(dead_code)]
    dest_hash: DestHash,
    raw: Vec<u8>,
}

// ─── Peer Callbacks (used by both Alice and Bob) ─────────────────────────────

struct PeerCallbacks {
    name: &'static str,
    announce_tx: mpsc::Sender<AnnouncedIdentity>,
    delivery_tx: mpsc::Sender<Delivery>,
    proof_tx: mpsc::Sender<(PacketHash, f64)>,
}

impl Callbacks for PeerCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        log::info!(
            "[{}] Announce: dest={} identity={} hops={}",
            self.name,
            announced.dest_hash,
            announced.identity_hash,
            announced.hops
        );
        let _ = self.announce_tx.send(announced);
    }

    fn on_path_updated(&mut self, dest_hash: DestHash, hops: u8) {
        log::debug!("[{}] Path updated: dest={} hops={}", self.name, dest_hash, hops);
    }

    fn on_local_delivery(&mut self, dest_hash: DestHash, raw: Vec<u8>, packet_hash: PacketHash) {
        log::info!(
            "[{}] Received packet: dest={} size={} hash={}",
            self.name,
            dest_hash,
            raw.len(),
            packet_hash
        );
        let _ = self.delivery_tx.send(Delivery { dest_hash, raw });
    }

    fn on_proof(&mut self, _dest_hash: DestHash, packet_hash: PacketHash, rtt: f64) {
        log::info!(
            "[{}] Proof: hash={} rtt={:.3}s",
            self.name,
            packet_hash,
            rtt
        );
        let _ = self.proof_tx.send((packet_hash, rtt));
    }
}

// ─── Transport node callbacks (no-op, just relays) ──────────────────────────

struct TransportCallbacks;

impl Callbacks for TransportCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        log::debug!(
            "[transport] Relaying announce: dest={} hops={}",
            announced.dest_hash,
            announced.hops
        );
    }
    fn on_path_updated(&mut self, _dest_hash: DestHash, _hops: u8) {}
    fn on_local_delivery(&mut self, _dest_hash: DestHash, _raw: Vec<u8>, _hash: PacketHash) {}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn find_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Decrypt a SINGLE packet received via on_local_delivery.
/// `raw` is the full wire packet — unpack to get the encrypted data, then decrypt.
fn decrypt_delivery(raw: &[u8], my_identity: &Identity) -> Option<Vec<u8>> {
    let packet = rns_core::packet::RawPacket::unpack(raw).ok()?;
    my_identity.decrypt(&packet.data).ok()
}

/// Wait for an announce matching `expected_hash`, discarding others.
fn wait_for_announce(
    rx: &mpsc::Receiver<AnnouncedIdentity>,
    expected_hash: &DestHash,
    timeout: Duration,
) -> Result<AnnouncedIdentity, mpsc::RecvTimeoutError> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            return Err(mpsc::RecvTimeoutError::Timeout);
        }
        let announced = rx.recv_timeout(remaining)?;
        if announced.dest_hash == *expected_hash {
            return Ok(announced);
        }
        log::debug!(
            "Ignoring announce for {} (waiting for {})",
            announced.dest_hash,
            expected_hash
        );
    }
}

fn main() {
    env_logger::init();

    let port = find_free_port();
    println!("Transport node listening on 127.0.0.1:{}", port);

    // ─── Transport Node (TCP server, relays packets) ─────────────────────

    let transport_node = RnsNode::start(
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
            }],
            share_instance: false,
            rpc_port: 0,
            cache_dir: None,
            management: Default::default(),
        },
        Box::new(TransportCallbacks),
    )
    .expect("Failed to start transport node");

    // ─── Create Identities + Destinations ────────────────────────────────

    let alice_identity = Identity::new(&mut OsRng);
    let alice_ih = IdentityHash(*alice_identity.hash());
    let alice_dest = Destination::single_in(APP_NAME, &["message", "rx"], alice_ih)
        .set_proof_strategy(ProofStrategy::ProveAll);

    let bob_identity = Identity::new(&mut OsRng);
    let bob_ih = IdentityHash(*bob_identity.hash());
    let bob_dest = Destination::single_in(APP_NAME, &["message", "rx"], bob_ih)
        .set_proof_strategy(ProofStrategy::ProveAll);

    println!("Alice destination: {}", alice_dest.hash);
    println!("Bob   destination: {}", bob_dest.hash);

    // ─── Alice Node (TCP client) ─────────────────────────────────────────

    let (alice_ann_tx, alice_ann_rx) = mpsc::channel();
    let (alice_del_tx, alice_del_rx) = mpsc::channel();
    let (alice_prf_tx, alice_prf_rx) = mpsc::channel();

    let alice_node = RnsNode::start(
        NodeConfig {
            transport_enabled: false,
            identity: Some(Identity::from_private_key(
                &alice_identity.get_private_key().unwrap(),
            )),
            interfaces: vec![InterfaceConfig {
                variant: InterfaceVariant::TcpClient(TcpClientConfig {
                    name: "Alice TCP".into(),
                    target_host: "127.0.0.1".into(),
                    target_port: port,
                    interface_id: InterfaceId(1),
                    ..Default::default()
                }),
                mode: MODE_FULL,
                ifac: None,
            }],
            share_instance: false,
            rpc_port: 0,
            cache_dir: None,
            management: Default::default(),
        },
        Box::new(PeerCallbacks {
            name: "alice",
            announce_tx: alice_ann_tx,
            delivery_tx: alice_del_tx,
            proof_tx: alice_prf_tx,
        }),
    )
    .expect("Failed to start Alice");

    alice_node
        .register_destination_with_proof(
            &alice_dest,
            Some(alice_identity.get_private_key().unwrap()),
        )
        .expect("Failed to register Alice's destination");

    // ─── Bob Node (TCP client) ───────────────────────────────────────────

    let (bob_ann_tx, bob_ann_rx) = mpsc::channel();
    let (bob_del_tx, bob_del_rx) = mpsc::channel();
    let (bob_prf_tx, bob_prf_rx) = mpsc::channel();

    let bob_node = RnsNode::start(
        NodeConfig {
            transport_enabled: false,
            identity: Some(Identity::from_private_key(
                &bob_identity.get_private_key().unwrap(),
            )),
            interfaces: vec![InterfaceConfig {
                variant: InterfaceVariant::TcpClient(TcpClientConfig {
                    name: "Bob TCP".into(),
                    target_host: "127.0.0.1".into(),
                    target_port: port,
                    interface_id: InterfaceId(1),
                    ..Default::default()
                }),
                mode: MODE_FULL,
                ifac: None,
            }],
            share_instance: false,
            rpc_port: 0,
            cache_dir: None,
            management: Default::default(),
        },
        Box::new(PeerCallbacks {
            name: "bob",
            announce_tx: bob_ann_tx,
            delivery_tx: bob_del_tx,
            proof_tx: bob_prf_tx,
        }),
    )
    .expect("Failed to start Bob");

    bob_node
        .register_destination_with_proof(
            &bob_dest,
            Some(bob_identity.get_private_key().unwrap()),
        )
        .expect("Failed to register Bob's destination");

    // ─── Wait for TCP connections ────────────────────────────────────────

    println!("Waiting for connections...");
    std::thread::sleep(Duration::from_secs(1));

    // ─── Announce Both ───────────────────────────────────────────────────

    println!("Announcing...");
    alice_node
        .announce(&alice_dest, &alice_identity, Some(b"Alice"))
        .expect("Alice announce failed");
    bob_node
        .announce(&bob_dest, &bob_identity, Some(b"Bob"))
        .expect("Bob announce failed");

    // ─── Wait for Cross-Discovery ────────────────────────────────────────

    let timeout = Duration::from_secs(10);

    println!("Waiting for announces...");
    let bob_announced = wait_for_announce(&alice_ann_rx, &bob_dest.hash, timeout)
        .expect("Alice timed out waiting for Bob's announce");
    println!(
        "Alice discovered Bob: app_data={}",
        bob_announced
            .app_data
            .as_ref()
            .and_then(|d| std::str::from_utf8(d).ok())
            .unwrap_or("<none>")
    );

    let alice_announced = wait_for_announce(&bob_ann_rx, &alice_dest.hash, timeout)
        .expect("Bob timed out waiting for Alice's announce");
    println!(
        "Bob discovered Alice: app_data={}",
        alice_announced
            .app_data
            .as_ref()
            .and_then(|d| std::str::from_utf8(d).ok())
            .unwrap_or("<none>")
    );

    // ─── Send Encrypted Messages ─────────────────────────────────────────

    // Alice → Bob
    let dest_to_bob = Destination::single_out(APP_NAME, &["message", "rx"], &bob_announced);
    let alice_msg = b"Hello Bob!";
    println!("Alice sending: {:?}", std::str::from_utf8(alice_msg).unwrap());
    let alice_pkt = alice_node
        .send_packet(&dest_to_bob, alice_msg)
        .expect("Alice send failed");

    // Bob → Alice
    let dest_to_alice = Destination::single_out(APP_NAME, &["message", "rx"], &alice_announced);
    let bob_msg = b"Hello Alice!";
    println!("Bob sending: {:?}", std::str::from_utf8(bob_msg).unwrap());
    let bob_pkt = bob_node
        .send_packet(&dest_to_alice, bob_msg)
        .expect("Bob send failed");

    // ─── Receive + Decrypt ───────────────────────────────────────────────

    println!("Waiting for deliveries...");

    match bob_del_rx.recv_timeout(timeout) {
        Ok(delivery) => match decrypt_delivery(&delivery.raw, &bob_identity) {
            Some(plaintext) => println!(
                "Bob received: {:?}",
                std::str::from_utf8(&plaintext).unwrap_or("<binary>")
            ),
            None => println!("Bob: decryption failed"),
        },
        Err(_) => println!("Bob: timed out waiting for delivery"),
    }

    match alice_del_rx.recv_timeout(timeout) {
        Ok(delivery) => match decrypt_delivery(&delivery.raw, &alice_identity) {
            Some(plaintext) => println!(
                "Alice received: {:?}",
                std::str::from_utf8(&plaintext).unwrap_or("<binary>")
            ),
            None => println!("Alice: decryption failed"),
        },
        Err(_) => println!("Alice: timed out waiting for delivery"),
    }

    // ─── Wait for Proofs ─────────────────────────────────────────────────

    println!("Waiting for proofs...");

    match alice_prf_rx.recv_timeout(timeout) {
        Ok((hash, rtt)) => {
            assert_eq!(hash, alice_pkt);
            println!("Alice got proof: RTT={:.3}s", rtt);
        }
        Err(_) => println!("Alice: no proof received"),
    }

    match bob_prf_rx.recv_timeout(timeout) {
        Ok((hash, rtt)) => {
            assert_eq!(hash, bob_pkt);
            println!("Bob got proof: RTT={:.3}s", rtt);
        }
        Err(_) => println!("Bob: no proof received"),
    }

    // ─── Cleanup ─────────────────────────────────────────────────────────

    println!("Shutting down...");
    alice_node.shutdown();
    bob_node.shutdown();
    transport_node.shutdown();
    println!("Done.");
}
