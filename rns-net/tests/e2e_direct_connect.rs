//! End-to-end Direct Link: two nodes linked over TCP upgrade their link to
//! a direct UDP connection, discovering their endpoints through a probe
//! server one of them runs.
//!
//! Run: cargo test --package rns-net --test e2e_direct_connect

use std::sync::mpsc;
use std::time::{Duration, Instant};

use rns_crypto::identity::Identity;
use rns_crypto::OsRng;

use rns_net::event::HolePunchPolicy;
use rns_net::{
    AnnouncedIdentity, Callbacks, DestHash, Destination, IdentityHash, InterfaceConfig,
    InterfaceId, NodeConfig, PacketHash, ProofStrategy, RnsNode, TcpClientConfig, TcpServerConfig,
    MODE_FULL,
};

/// `REJECT_POLICY` and `REJECT_UNSUPPORTED` from `rns_core::holepunch`.
const REJECT_POLICY: u8 = 0x01;
const REJECT_UNSUPPORTED: u8 = 0x03;

/// The application message type the tests exchange.
const APP_MSGTYPE: u16 = 0x0101;

#[derive(Debug)]
enum TestEvent {
    Announce(DestHash),
    LinkEstablished([u8; 16]),
    LinkClosed([u8; 16]),
    DirectConnected([u8; 16], InterfaceId),
    DirectFailed([u8; 16], u8),
    Channel([u8; 16], u16, Vec<u8>),
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

    fn on_link_closed(
        &mut self,
        link_id: rns_net::LinkId,
        _reason: Option<rns_net::TeardownReason>,
    ) {
        let _ = self.0.send(TestEvent::LinkClosed(link_id.0));
    }

    fn on_channel_message(&mut self, link_id: rns_net::LinkId, msgtype: u16, payload: Vec<u8>) {
        let _ = self.0.send(TestEvent::Channel(link_id.0, msgtype, payload));
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

/// A port free for both TCP and UDP, kept outside 30000-45000.
fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let seed = (std::process::id() % 4000) as u16 * 3;
    loop {
        let port = 47000 + (seed + NEXT.fetch_add(1, Ordering::Relaxed)) % 13000;
        if std::net::UdpSocket::bind(("0.0.0.0", port)).is_ok()
            && std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
        {
            return port;
        }
    }
}

fn interface(type_name: &str, config: Box<dyn rns_net::InterfaceConfigData>) -> InterfaceConfig {
    InterfaceConfig {
        stamp_costs: Default::default(),
        announce_limits: Default::default(),
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

/// Direct Link settings of one test node.
#[derive(Clone)]
struct DirectSettings {
    /// Run the probe server (facilitator) on this port.
    probe_port: Option<u16>,
    /// Use the facilitator to discover our endpoint (needed to propose).
    use_probe: bool,
    /// `None` keeps the default policy.
    policy: Option<HolePunchPolicy>,
    /// Put Alice's identity on the allowlist.
    allow_alice: bool,
}

impl DirectSettings {
    /// Proposes and accepts every proposal.
    fn willing() -> Self {
        DirectSettings {
            probe_port: None,
            use_probe: true,
            policy: Some(HolePunchPolicy::AcceptAll),
            allow_alice: false,
        }
    }

    /// No Direct Link configuration at all.
    fn unconfigured() -> Self {
        DirectSettings {
            probe_port: None,
            use_probe: false,
            policy: Some(HolePunchPolicy::Reject),
            allow_alice: false,
        }
    }

    /// No Direct Link settings at all: the node's defaults.
    fn unconfigured_default() -> Self {
        DirectSettings {
            probe_port: None,
            use_probe: false,
            policy: None,
            allow_alice: false,
        }
    }

    /// The defaults, plus a facilitator to propose through.
    fn default_with_probe() -> Self {
        DirectSettings {
            probe_port: None,
            use_probe: true,
            policy: None,
            allow_alice: false,
        }
    }
}

fn node(
    identity: &Identity,
    interface: InterfaceConfig,
    probe_server: std::net::SocketAddr,
    settings: DirectSettings,
    alice: &Identity,
    tx: mpsc::Sender<TestEvent>,
) -> RnsNode {
    let mut config = NodeConfig {
        identity: Some(Identity::from_private_key(
            &identity.get_private_key().unwrap(),
        )),
        interfaces: vec![interface],
        share_instance: false,
        rpc_port: 0,
        probe_port: settings.probe_port,
        probe_addrs: if settings.use_probe {
            vec![probe_server]
        } else {
            vec![]
        },
        // Both ends are on this host.
        direct_connect_allow_private_endpoints: true,
        direct_connect_allowed_identities: Vec::new(),
        ..Default::default()
    };
    if let Some(policy) = settings.policy {
        config.direct_connect_policy = policy;
    }
    if settings.allow_alice {
        config.direct_connect_allowed_identities = vec![*alice.hash()];
    }
    RnsNode::start(config, Box::new(TestCallbacks(tx))).unwrap()
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

/// Bob serves TCP and runs the probe server; Alice connects to him and
/// holds an established link to his destination.
struct Pair {
    alice: RnsNode,
    alice_id: Identity,
    alice_rx: mpsc::Receiver<TestEvent>,
    bob: RnsNode,
    bob_rx: mpsc::Receiver<TestEvent>,
    link_id: [u8; 16],
}

impl Pair {
    /// `None` when the host has no non-loopback address to punch through.
    fn start(alice_settings: DirectSettings, bob_settings: DirectSettings) -> Option<Pair> {
        let _ = env_logger::builder().is_test(true).try_init();
        let Some(local) = local_address() else {
            eprintln!("skipped: no non-loopback address to punch through");
            return None;
        };
        let tcp_port = free_port();
        let probe_port = free_port();
        // Probes sent to this address come from it, so each node observes
        // its own non-loopback endpoint.
        let probe_server = std::net::SocketAddr::new(local, probe_port);

        let alice_id = Identity::new(&mut OsRng);
        let bob_id = Identity::new(&mut OsRng);
        let bob_dest =
            Destination::single_in("e2e_direct", &["link"], IdentityHash(*bob_id.hash()))
                .set_proof_strategy(ProofStrategy::ProveAll);

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
            probe_server,
            DirectSettings {
                probe_port: Some(probe_port),
                ..bob_settings
            },
            &alice_id,
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
            probe_server,
            alice_settings,
            &alice_id,
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
        wait_for(&bob_rx, Duration::from_secs(10), |event| {
            matches!(event, TestEvent::LinkEstablished(id) if *id == link_id).then_some(())
        })
        .expect("Bob did not see the link");

        Some(Pair {
            alice,
            alice_id,
            alice_rx,
            bob,
            bob_rx,
            link_id,
        })
    }

    /// Alice proposes; the outcome she reports.
    fn propose(&self) -> Result<InterfaceId, u8> {
        self.alice.propose_direct_connect(self.link_id).unwrap();
        let link_id = self.link_id;
        wait_for(
            &self.alice_rx,
            Duration::from_secs(25),
            |event| match event {
                TestEvent::DirectConnected(id, interface) if *id == link_id => Some(Ok(*interface)),
                TestEvent::DirectFailed(id, reason) if *id == link_id => Some(Err(*reason)),
                _ => None,
            },
        )
        .expect("no direct connect outcome")
    }

    /// Alice proposes, and both sides establish the direct path.
    fn upgrade(&self) -> (InterfaceId, InterfaceId) {
        let alice_iface = match self.propose() {
            Ok(interface) => interface,
            Err(reason) => panic!("direct connect failed: reason {reason}"),
        };
        let bob_iface = wait_for(&self.bob_rx, Duration::from_secs(10), |event| match event {
            TestEvent::DirectConnected(_, interface) => Some(Ok(*interface)),
            TestEvent::DirectFailed(_, reason) => Some(Err(*reason)),
            _ => None,
        })
        .expect("no outcome on Bob's side")
        .expect("Bob's side did not connect");
        (alice_iface, bob_iface)
    }

    /// Alice identifies on the link, as `identity`.
    fn identify(&self, identity: &Identity) {
        self.alice
            .identify_on_link(self.link_id, identity.get_private_key().unwrap())
            .unwrap();
        // Let LINKIDENTIFY arrive before anything that depends on it.
        std::thread::sleep(Duration::from_millis(500));
    }

    /// Bob neither connected nor reported anything about Direct Link, and
    /// neither side has a direct interface.
    fn assert_bob_stayed_out(&self) {
        while let Ok(event) = self.bob_rx.try_recv() {
            if let TestEvent::DirectConnected(..) | TestEvent::DirectFailed(..) = event {
                panic!("Bob took part in Direct Link: {event:?}");
            }
        }
        assert!(direct_interfaces(&self.alice).is_empty());
        assert!(direct_interfaces(&self.bob).is_empty());
    }

    fn shutdown(self) {
        self.alice.shutdown();
        self.bob.shutdown();
    }
}

/// Send an application channel message and wait until the receiver's
/// application gets it. Returns whether it arrived within `timeout`.
fn deliver(
    from: &RnsNode,
    to_rx: &mpsc::Receiver<TestEvent>,
    link_id: [u8; 16],
    payload: &[u8],
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    while from
        .try_send_channel_message(link_id, APP_MSGTYPE, payload.to_vec())
        .is_err()
    {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    wait_for(to_rx, remaining, |event| match event {
        TestEvent::Channel(id, APP_MSGTYPE, data) if *id == link_id && data == payload => Some(()),
        _ => None,
    })
    .is_some()
}

fn interfaces(node: &RnsNode) -> Vec<rns_net::event::SingleInterfaceStat> {
    match node.query(rns_net::event::QueryRequest::InterfaceStats) {
        Ok(rns_net::event::QueryResponse::InterfaceStats(stats)) => stats.interfaces,
        other => panic!("no interface stats: {other:?}"),
    }
}

/// Bytes received and sent on an interface, as `(rx, tx)`.
fn traffic(node: &RnsNode, interface: InterfaceId) -> Option<(u64, u64)> {
    interfaces(node)
        .into_iter()
        .find(|i| i.id == interface.0)
        .map(|i| (i.rxb, i.txb))
}

fn direct_interfaces(node: &RnsNode) -> Vec<u64> {
    interfaces(node)
        .into_iter()
        .filter(|i| i.name.starts_with("DirectPeer"))
        .map(|i| i.id)
        .collect()
}

/// Poll `check` until it holds or `timeout` passes.
fn eventually(timeout: Duration, mut check: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if check() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn upgrade_carries_link_traffic_over_the_direct_path() {
    let Some(pair) = Pair::start(DirectSettings::willing(), DirectSettings::willing()) else {
        return;
    };
    let (alice_iface, bob_iface) = pair.upgrade();

    // Application data flows both ways, over the direct interfaces.
    let before_alice = traffic(&pair.alice, alice_iface).unwrap();
    let before_bob = traffic(&pair.bob, bob_iface).unwrap();
    assert!(deliver(
        &pair.alice,
        &pair.bob_rx,
        pair.link_id,
        b"alice to bob, direct",
        Duration::from_secs(10)
    ));
    assert!(deliver(
        &pair.bob,
        &pair.alice_rx,
        pair.link_id,
        b"bob to alice, direct",
        Duration::from_secs(10)
    ));
    assert!(
        eventually(Duration::from_secs(5), || {
            let (alice_rx, alice_tx) = traffic(&pair.alice, alice_iface).unwrap();
            let (bob_rx, bob_tx) = traffic(&pair.bob, bob_iface).unwrap();
            alice_tx > before_alice.1
                && alice_rx > before_alice.0
                && bob_tx > before_bob.1
                && bob_rx > before_bob.0
        }),
        "link traffic did not use the direct interfaces"
    );

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

    pair.shutdown();
}

#[test]
fn peer_without_direct_link_is_never_signalled() {
    // Bob takes no part in Direct Link: he does not answer the capability
    // query, so Alice sends him nothing else and gives up.
    let Some(pair) = Pair::start(DirectSettings::willing(), DirectSettings::unconfigured()) else {
        return;
    };
    assert!(deliver(
        &pair.alice,
        &pair.bob_rx,
        pair.link_id,
        b"before the proposal",
        Duration::from_secs(10)
    ));
    let started = Instant::now();
    assert_eq!(pair.propose(), Err(REJECT_UNSUPPORTED));
    assert!(started.elapsed() < Duration::from_secs(15));

    // The link and its channel keep working both ways, and Bob's
    // application saw only the application's own messages.
    assert!(deliver(
        &pair.alice,
        &pair.bob_rx,
        pair.link_id,
        b"after the proposal",
        Duration::from_secs(10)
    ));
    assert!(deliver(
        &pair.bob,
        &pair.alice_rx,
        pair.link_id,
        b"bob answers",
        Duration::from_secs(10)
    ));
    while let Ok(event) = pair.bob_rx.try_recv() {
        match event {
            TestEvent::Channel(_, msgtype, _) => assert_eq!(msgtype, APP_MSGTYPE),
            TestEvent::LinkClosed(id) => panic!("Bob's link {id:02x?} closed"),
            TestEvent::DirectConnected(..) | TestEvent::DirectFailed(..) => {
                panic!("Bob took part in Direct Link: {event:?}")
            }
            _ => {}
        }
    }
    assert!(direct_interfaces(&pair.alice).is_empty());
    assert!(direct_interfaces(&pair.bob).is_empty());
    pair.shutdown();
}

#[test]
fn application_channel_messages_in_the_old_signalling_range_reach_the_application() {
    // Direct Link does not use the channel: message types 0xFE00-0xFE04
    // belong to the application like any other.
    let Some(pair) = Pair::start(DirectSettings::willing(), DirectSettings::willing()) else {
        return;
    };
    for msgtype in [0xFE00u16, 0xFE03] {
        let payload = vec![0x5A; 8];
        pair.alice
            .send_channel_message(pair.link_id, msgtype, payload.clone())
            .unwrap();
        let link_id = pair.link_id;
        wait_for(&pair.bob_rx, Duration::from_secs(10), |event| match event {
            TestEvent::Channel(id, t, data)
                if *id == link_id && *t == msgtype && *data == payload =>
            {
                Some(())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("message type {msgtype:#06x} did not reach the application"));
    }
    pair.shutdown();
}

#[test]
fn default_configuration_takes_no_part() {
    // Bob runs a facilitator but has no Direct Link configuration: he does
    // not even answer the capability query, so an identified peer learns
    // nothing about him.
    let Some(pair) = Pair::start(
        DirectSettings::willing(),
        DirectSettings::unconfigured_default(),
    ) else {
        return;
    };
    pair.identify(&Identity::new(&mut OsRng));
    assert_eq!(pair.propose(), Err(REJECT_UNSUPPORTED));
    pair.assert_bob_stayed_out();
    pair.shutdown();
}

#[test]
fn default_policy_refuses_identified_strangers() {
    // Bob can propose himself (a facilitator is configured), so he answers
    // the capability query, but his default policy refuses a peer that
    // identified with a throwaway identity, before any probe or punch.
    let Some(pair) = Pair::start(
        DirectSettings::willing(),
        DirectSettings::default_with_probe(),
    ) else {
        return;
    };
    pair.identify(&Identity::new(&mut OsRng));
    assert_eq!(pair.propose(), Err(REJECT_POLICY));
    pair.assert_bob_stayed_out();
    pair.shutdown();
}

#[test]
fn allowlisted_identity_is_accepted_and_others_are_not() {
    let bob = DirectSettings {
        allow_alice: true,
        ..DirectSettings::unconfigured_default()
    };
    // Anonymous, or identified as someone else: refused.
    let Some(pair) = Pair::start(DirectSettings::willing(), bob.clone()) else {
        return;
    };
    assert_eq!(pair.propose(), Err(REJECT_POLICY));
    pair.shutdown();
    let Some(pair) = Pair::start(DirectSettings::willing(), bob.clone()) else {
        return;
    };
    pair.identify(&Identity::new(&mut OsRng));
    assert_eq!(pair.propose(), Err(REJECT_POLICY));
    pair.assert_bob_stayed_out();
    pair.shutdown();

    // Identified as the allowlisted identity: upgraded.
    let Some(pair) = Pair::start(DirectSettings::willing(), bob) else {
        return;
    };
    pair.identify(&Identity::from_private_key(
        &pair.alice_id.get_private_key().unwrap(),
    ));
    pair.upgrade();
    pair.shutdown();
}

/// Announce and path-request counters of an interface, received and sent.
fn signalling_counts(node: &RnsNode, interface: InterfaceId) -> [u64; 4] {
    let stat = interfaces(node)
        .into_iter()
        .find(|i| i.id == interface.0)
        .expect("interface gone");
    [
        stat.traffic.arxc,
        stat.traffic.atxc,
        stat.traffic.prxc,
        stat.traffic.ptxc,
    ]
}

#[test]
fn direct_interface_carries_only_its_link() {
    let Some(pair) = Pair::start(DirectSettings::willing(), DirectSettings::willing()) else {
        return;
    };
    let (alice_iface, bob_iface) = pair.upgrade();

    // Bob announces another destination; Alice asks for a path to an
    // unknown one. Neither goes over the direct interfaces.
    let other_id = Identity::new(&mut OsRng);
    let other = Destination::single_in("e2e_direct", &["other"], IdentityHash(*other_id.hash()));
    pair.bob
        .register_destination_with_proof(&other, Some(other_id.get_private_key().unwrap()))
        .unwrap();
    for _ in 0..3 {
        let _ = futures::executor::block_on(pair.bob.announce(&other, &other_id, None));
        pair.alice.request_path(&DestHash([0x77; 16])).unwrap();
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(
        eventually(Duration::from_secs(10), || pair
            .alice
            .has_path(&other.hash)
            .unwrap()),
        "the announce did not reach Alice over TCP"
    );
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(signalling_counts(&pair.alice, alice_iface), [0; 4]);
    assert_eq!(signalling_counts(&pair.bob, bob_iface), [0; 4]);

    // The link itself still runs over them.
    let (_, before) = traffic(&pair.alice, alice_iface).unwrap();
    assert!(deliver(
        &pair.alice,
        &pair.bob_rx,
        pair.link_id,
        b"still direct",
        Duration::from_secs(10)
    ));
    assert!(eventually(Duration::from_secs(5), || traffic(
        &pair.alice,
        alice_iface
    )
    .unwrap()
    .1 > before));
    pair.shutdown();
}

#[test]
fn link_teardown_removes_the_direct_interface_on_both_sides() {
    let Some(pair) = Pair::start(DirectSettings::willing(), DirectSettings::willing()) else {
        return;
    };
    pair.upgrade();
    assert_eq!(direct_interfaces(&pair.alice).len(), 1);
    assert_eq!(direct_interfaces(&pair.bob).len(), 1);

    pair.alice.teardown_link(pair.link_id).unwrap();
    let link_id = pair.link_id;
    wait_for(&pair.bob_rx, Duration::from_secs(10), |event| {
        matches!(event, TestEvent::LinkClosed(id) if *id == link_id).then_some(())
    })
    .expect("Bob's link did not close");
    assert!(
        eventually(Duration::from_secs(5), || direct_interfaces(&pair.alice)
            .is_empty()
            && direct_interfaces(&pair.bob).is_empty()),
        "direct interfaces outlived their link: alice {:?} bob {:?}",
        direct_interfaces(&pair.alice),
        direct_interfaces(&pair.bob)
    );
    pair.shutdown();
}

#[test]
fn repeated_upgrade_replaces_the_direct_interface() {
    let Some(pair) = Pair::start(DirectSettings::willing(), DirectSettings::willing()) else {
        return;
    };
    let (first_alice, first_bob) = pair.upgrade();
    // Proposals on a link are paced to one a minute on both sides.
    std::thread::sleep(Duration::from_secs(61));
    let (second_alice, second_bob) = pair.upgrade();
    assert_ne!(first_alice, second_alice);
    assert_ne!(first_bob, second_bob);
    assert!(
        eventually(Duration::from_secs(5), || {
            direct_interfaces(&pair.alice) == vec![second_alice.0]
                && direct_interfaces(&pair.bob) == vec![second_bob.0]
        }),
        "alice {:?} bob {:?}",
        direct_interfaces(&pair.alice),
        direct_interfaces(&pair.bob)
    );
    assert!(deliver(
        &pair.alice,
        &pair.bob_rx,
        pair.link_id,
        b"over the new path",
        Duration::from_secs(10)
    ));
    pair.shutdown();
}
