//! End-to-end hole punching: two nodes linked over TCP upgrade their link
//! to a direct UDP connection, discovering their endpoints through a probe
//! server one of them runs.
//!
//! Run: cargo test --package rns-net --test e2e_direct_connect

use std::sync::mpsc;
use std::time::{Duration, Instant};

use rns_crypto::identity::Identity;
use rns_crypto::OsRng;

use rns_net::{
    AnnouncedIdentity, Callbacks, DestHash, Destination, IdentityHash, InterfaceConfig,
    InterfaceId, NodeConfig, PacketHash, ProofStrategy, RnsNode, TcpClientConfig, TcpServerConfig,
    MODE_FULL,
};

#[derive(Debug)]
enum TestEvent {
    Announce(DestHash),
    LinkEstablished([u8; 16]),
    DirectConnected([u8; 16], InterfaceId),
    DirectFailed([u8; 16], u8),
}

struct TestCallbacks(mpsc::Sender<TestEvent>);

impl Callbacks for TestCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        let _ = self.0.send(TestEvent::Announce(announced.dest_hash));
    }

    fn on_path_updated(&mut self, _dest_hash: DestHash, _hops: u8) {}

    fn on_local_delivery(&mut self, _dest_hash: DestHash, _raw: Vec<u8>, _hash: PacketHash) {}

    fn on_link_established(
        &mut self,
        link_id: rns_net::LinkId,
        _dest_hash: DestHash,
        _rtt: f64,
        _is_initiator: bool,
    ) {
        let _ = self.0.send(TestEvent::LinkEstablished(link_id.0));
    }

    fn on_direct_connect_established(
        &mut self,
        link_id: rns_net::LinkId,
        interface_id: InterfaceId,
    ) {
        let _ = self
            .0
            .send(TestEvent::DirectConnected(link_id.0, interface_id));
    }

    fn on_direct_connect_failed(&mut self, link_id: rns_net::LinkId, reason: u8) {
        let _ = self.0.send(TestEvent::DirectFailed(link_id.0, reason));
    }
}

fn free_port() -> u16 {
    // A port free for both TCP and UDP.
    loop {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

fn interface(type_name: &str, config: Box<dyn rns_net::InterfaceConfigData>) -> InterfaceConfig {
    InterfaceConfig {
        stamp_costs: Default::default(),
        name: String::new(),
        type_name: type_name.to_string(),
        config_data: config,
        mode: MODE_FULL,
        gravity: 0,
        recursive_prs: false,
        announces_from_internal: true,
        announces_to_internal: None,
        ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
        ifac: None,
        discovery: None,
    }
}

fn node(
    identity: &Identity,
    interface: InterfaceConfig,
    probe_port: Option<u16>,
    probe_server: std::net::SocketAddr,
    tx: mpsc::Sender<TestEvent>,
) -> RnsNode {
    RnsNode::start(
        NodeConfig {
            identity: Some(Identity::from_private_key(
                &identity.get_private_key().unwrap(),
            )),
            interfaces: vec![interface],
            share_instance: false,
            rpc_port: 0,
            probe_port,
            probe_addrs: vec![probe_server],
            direct_connect_policy: rns_net::event::HolePunchPolicy::AcceptAll,
            // Both ends are on localhost.
            direct_connect_allow_private_endpoints: true,
            ..Default::default()
        },
        Box::new(TestCallbacks(tx)),
    )
    .unwrap()
}

fn wait_for<T>(
    rx: &mpsc::Receiver<TestEvent>,
    timeout: Duration,
    mut matches: impl FnMut(&TestEvent) -> Option<T>,
) -> Option<T> {
    let deadline = Instant::now() + timeout;
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(remaining) {
            Ok(event) => {
                if let Some(found) = matches(&event) {
                    return Some(found);
                }
            }
            Err(_) => return None,
        }
    }
    None
}

/// This machine's address on its default route, which hole punching
/// accepts as a private endpoint (loopback it never accepts). Connecting a
/// UDP socket sends nothing.
fn local_address() -> Option<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

#[test]
fn link_upgrades_to_a_direct_udp_connection() {
    let _ = env_logger::builder().is_test(true).try_init();
    let Some(local) = local_address() else {
        eprintln!("skipped: no non-loopback address to punch through");
        return;
    };
    let tcp_port = free_port();
    let probe_port = free_port();
    // Probes sent to this address come from it, so each node observes its
    // own non-loopback endpoint.
    let probe_server = std::net::SocketAddr::new(local, probe_port);

    let bob_id = Identity::new(&mut OsRng);
    let bob_dest = Destination::single_in("e2e_direct", &["link"], IdentityHash(*bob_id.hash()))
        .set_proof_strategy(ProofStrategy::ProveAll);

    // Bob serves TCP and runs the probe server.
    let (bob_tx, bob_rx) = mpsc::channel();
    let bob = node(
        &bob_id,
        interface(
            "TCPServerInterface",
            Box::new(TcpServerConfig {
                name: "Bob".into(),
                listen_ip: "127.0.0.1".into(),
                listen_port: tcp_port,
                interface_id: InterfaceId(1),
                ..TcpServerConfig::default()
            }),
        ),
        Some(probe_port),
        probe_server,
        bob_tx,
    );
    bob.register_destination_with_proof(&bob_dest, Some(bob_id.get_private_key().unwrap()))
        .unwrap();
    let bob_prv = bob_id.get_private_key().unwrap();
    let bob_pub = bob_id.get_public_key().unwrap();
    let (sig_prv, sig_pub): ([u8; 32], [u8; 32]) = (
        bob_prv[32..64].try_into().unwrap(),
        bob_pub[32..64].try_into().unwrap(),
    );
    bob.register_link_destination(bob_dest.hash.0, sig_prv, sig_pub, 0)
        .unwrap();

    // Alice connects to Bob over TCP.
    let alice_id = Identity::new(&mut OsRng);
    let (alice_tx, alice_rx) = mpsc::channel();
    let alice = node(
        &alice_id,
        interface(
            "TCPClientInterface",
            Box::new(TcpClientConfig {
                name: "Alice".into(),
                target_host: "127.0.0.1".into(),
                target_port: tcp_port,
                interface_id: InterfaceId(1),
                ..Default::default()
            }),
        ),
        None,
        probe_server,
        alice_tx,
    );

    // Alice learns Bob's destination, and links to it.
    let mut found = false;
    for _ in 0..10 {
        let _ = futures::executor::block_on(bob.announce(&bob_dest, &bob_id, None));
        if wait_for(&alice_rx, Duration::from_secs(2), |event| {
            matches!(event, TestEvent::Announce(hash) if *hash == bob_dest.hash).then_some(())
        })
        .is_some()
        {
            found = true;
            break;
        }
    }
    assert!(found, "Alice did not learn Bob's destination");
    let link_id = alice.create_link(bob_dest.hash.0, sig_pub).unwrap();
    wait_for(&alice_rx, Duration::from_secs(10), |event| {
        matches!(event, TestEvent::LinkEstablished(id) if *id == link_id).then_some(())
    })
    .expect("link not established");

    // Alice proposes the upgrade: both probe, punch, and get a direct
    // interface.
    alice.propose_direct_connect(link_id).unwrap();
    let outcome = wait_for(&alice_rx, Duration::from_secs(20), |event| match event {
        TestEvent::DirectConnected(id, interface) if *id == link_id => Some(Ok(*interface)),
        TestEvent::DirectFailed(id, reason) if *id == link_id => Some(Err(*reason)),
        _ => None,
    });
    match outcome {
        Some(Ok(_interface)) => {}
        Some(Err(reason)) => panic!("direct connect failed: reason {reason}"),
        None => panic!("no direct connect outcome"),
    }
    let bob_outcome = wait_for(&bob_rx, Duration::from_secs(10), |event| match event {
        TestEvent::DirectConnected(..) => Some(true),
        TestEvent::DirectFailed(..) => Some(false),
        _ => None,
    });
    assert_eq!(bob_outcome, Some(true), "Bob's side did not connect");

    // With services and interface I/O folded, no probe, punch or direct
    // link thread was needed.
    let folded = !cfg!(any(
        feature = "engine-parallel",
        feature = "compact-threads-services",
        feature = "compact-threads-io"
    ));
    if folded {
        let threads: Vec<String> = std::fs::read_dir("/proc/self/task")
            .unwrap()
            .filter_map(|task| std::fs::read_to_string(task.unwrap().path().join("comm")).ok())
            .collect();
        for name in ["probe-worker", "udp-punch", "direct-udp-", "probe-server"] {
            assert!(
                !threads.iter().any(|thread| thread.starts_with(name)),
                "found a {name} thread in {threads:?}"
            );
        }
    }

    alice.shutdown();
    bob.shutdown();
}
