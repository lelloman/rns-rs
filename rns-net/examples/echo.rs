//! Echo example: demonstrates the application-facing API.
//!
//! Runs a server and client in the same process, connected via TCP loopback.
//! The server creates a destination, announces it, and auto-proves all packets.
//! The client discovers the server, sends an echo request, and receives a proof.
//!
//! Usage: cargo run --example echo

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

// ─── Server Callbacks ───────────────────────────────────────────────────────

struct ServerCallbacks {
    delivery_tx: mpsc::Sender<(DestHash, Vec<u8>)>,
}

impl Callbacks for ServerCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        log::info!(
            "[server] Announce: dest={} hops={}",
            announced.dest_hash,
            announced.hops
        );
    }

    fn on_path_updated(&mut self, dest_hash: DestHash, hops: u8) {
        log::debug!("[server] Path updated: dest={} hops={}", dest_hash, hops);
    }

    fn on_local_delivery(&mut self, dest_hash: DestHash, data: Vec<u8>, packet_hash: PacketHash) {
        log::info!(
            "[server] Received packet: dest={} size={} hash={}",
            dest_hash,
            data.len(),
            packet_hash
        );
        let _ = self.delivery_tx.send((dest_hash, data));
    }
}

// ─── Client Callbacks ───────────────────────────────────────────────────────

struct ClientCallbacks {
    announce_tx: mpsc::Sender<AnnouncedIdentity>,
    proof_tx: mpsc::Sender<(DestHash, PacketHash, f64)>,
}

impl Callbacks for ClientCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        log::info!(
            "[client] Announce: dest={} identity={} hops={}",
            announced.dest_hash,
            announced.identity_hash,
            announced.hops
        );
        let _ = self.announce_tx.send(announced);
    }

    fn on_path_updated(&mut self, dest_hash: DestHash, hops: u8) {
        log::debug!("[client] Path updated: dest={} hops={}", dest_hash, hops);
    }

    fn on_local_delivery(&mut self, dest_hash: DestHash, _data: Vec<u8>, _hash: PacketHash) {
        log::debug!("[client] Local delivery: dest={}", dest_hash);
    }

    fn on_proof(&mut self, dest_hash: DestHash, packet_hash: PacketHash, rtt: f64) {
        log::info!(
            "[client] Proof received: dest={} hash={} rtt={:.3}s",
            dest_hash,
            packet_hash,
            rtt
        );
        let _ = self.proof_tx.send((dest_hash, packet_hash, rtt));
    }
}

fn find_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn main() {
    env_logger::init();

    let port = find_free_port();
    log::info!("Using TCP port {}", port);

    // ─── Server Setup ───────────────────────────────────────────────────

    let server_identity = Identity::new(&mut OsRng);
    let identity_hash = IdentityHash(*server_identity.hash());

    // Create inbound SINGLE destination with PROVE_ALL
    let server_dest = Destination::single_in(APP_NAME, &["echo", "request"], identity_hash)
        .set_proof_strategy(ProofStrategy::ProveAll);

    log::info!("Server destination: {}", server_dest.hash);

    let (delivery_tx, delivery_rx) = mpsc::channel();

    let server_node = RnsNode::start(
        NodeConfig {
            transport_enabled: false,
            identity: Some(Identity::from_private_key(&server_identity.get_private_key().unwrap())),
            interfaces: vec![InterfaceConfig {
                variant: InterfaceVariant::TcpServer(TcpServerConfig {
                    name: "Echo Server TCP".into(),
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
            probe_addr: None,
            device: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery_required_value: None,
            respond_to_probes: false,
        },
        Box::new(ServerCallbacks { delivery_tx }),
    )
    .expect("Failed to start server");

    // Register the destination with proof strategy
    let signing_key = server_identity.get_private_key().unwrap();
    server_node
        .register_destination_with_proof(&server_dest, Some(signing_key))
        .expect("Failed to register destination");

    // ─── Client Setup ───────────────────────────────────────────────────

    let (announce_tx, announce_rx) = mpsc::channel();
    let (proof_tx, proof_rx) = mpsc::channel();

    let client_node = RnsNode::start(
        NodeConfig {
            transport_enabled: false,
            identity: None,
            interfaces: vec![InterfaceConfig {
                variant: InterfaceVariant::TcpClient(TcpClientConfig {
                    name: "Echo Client TCP".into(),
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
            probe_addr: None,
            device: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            discovery_required_value: None,
            respond_to_probes: false,
        },
        Box::new(ClientCallbacks {
            announce_tx,
            proof_tx,
        }),
    )
    .expect("Failed to start client");

    // Wait for client to connect before announcing
    std::thread::sleep(Duration::from_secs(1));

    // Announce the server destination
    server_node
        .announce(&server_dest, &server_identity, Some(b"Rust Echo Server"))
        .expect("Failed to announce");

    log::info!("Server announced");

    // ─── Wait for Announce ──────────────────────────────────────────────

    log::info!("Waiting for server announce...");
    let announced = announce_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("Timed out waiting for announce");

    log::info!(
        "Discovered server: dest={} app_data={}",
        announced.dest_hash,
        announced
            .app_data
            .as_ref()
            .and_then(|d| std::str::from_utf8(d).ok())
            .unwrap_or("<none>")
    );

    // Verify destination hash matches
    assert_eq!(announced.dest_hash, server_dest.hash);

    // ─── Send Echo Request ──────────────────────────────────────────────

    // Create outbound destination from the announced identity
    let client_dest = Destination::single_out(APP_NAME, &["echo", "request"], &announced);

    let message = b"Hello from Rust echo client!";
    log::info!("Sending echo request: {:?}", std::str::from_utf8(message));

    let packet_hash = client_node
        .send_packet(&client_dest, message)
        .expect("Failed to send packet");

    log::info!("Sent packet: hash={}", packet_hash);

    // ─── Wait for Delivery (server side) ────────────────────────────────

    log::info!("Waiting for server to receive packet...");
    match delivery_rx.recv_timeout(Duration::from_secs(10)) {
        Ok((dest, data)) => {
            log::info!("Server received: dest={} data={:?}", dest, std::str::from_utf8(&data));
        }
        Err(_) => {
            log::warn!("Timed out waiting for server delivery (proof may still work)");
        }
    }

    // ─── Wait for Proof (client side) ───────────────────────────────────

    log::info!("Waiting for proof...");
    match proof_rx.recv_timeout(Duration::from_secs(10)) {
        Ok((dest, hash, rtt)) => {
            log::info!(
                "Proof confirmed! dest={} hash={} RTT={:.3}s",
                dest, hash, rtt
            );
            assert_eq!(hash, packet_hash);
            println!("Echo successful! RTT: {:.3}s", rtt);
        }
        Err(_) => {
            println!("No proof received (echo may have still been delivered)");
        }
    }

    // ─── Cleanup ────────────────────────────────────────────────────────

    client_node.shutdown();
    server_node.shutdown();
    log::info!("Done.");
}
