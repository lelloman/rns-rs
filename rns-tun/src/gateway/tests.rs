//! In-process tests of the gateway's session handling and packet
//! forwarding, against a fake node and a fake packet device. The kernel side
//! (TUN creation, routes, NAT, resolver state) stays in the Docker suite
//! `tests/docker/rntun`.

use super::*;

use std::cell::{Cell, RefCell};

use crate::packet::checksum;
use crate::policy::Cidr;
use crate::protocol::PacketFragment;
use crate::status::RuntimeStatus;

const FULL: [u8; 16] = [0xa1; 16];
const SPLIT: [u8; 16] = [0xb2; 16];
const DISABLED: [u8; 16] = [0xc3; 16];
const STRANGER: [u8; 16] = [0xd4; 16];

const LINK_A: [u8; 16] = [1; 16];
const LINK_B: [u8; 16] = [2; 16];
const LINK_C: [u8; 16] = [3; 16];

/// The Docker suite's policy, plus a split-tunnel client and a disabled one.
fn policy_toml(full_address: &str) -> String {
    format!(
        r#"
[gateway]
address = "10.77.0.1/24"

[clients.{full}]
enabled = true
address = "{full_address}"
allow_routes = ["0.0.0.0/0"]
allow_internet = true
allow_peers = []
idle_timeout_seconds = 120

[clients.{split}]
address = "10.77.0.3"
allow_routes = ["198.18.0.0/24"]

[clients.{disabled}]
enabled = false
address = "10.77.0.4"
allow_routes = ["198.18.0.0/24"]
"#,
        full = hex(&FULL),
        split = hex(&SPLIT),
        disabled = hex(&DISABLED),
    )
}

#[derive(Default)]
struct FakeNode {
    mdu: Option<usize>,
    refuse_fragments: Cell<bool>,
    controls: RefCell<Vec<([u8; 16], ControlMessage)>>,
    fragments: RefCell<Vec<([u8; 16], Vec<u8>)>>,
    teardowns: RefCell<Vec<[u8; 16]>>,
}

impl GatewayNode for FakeNode {
    fn link_mdu(&self, _link_id: [u8; 16]) -> Result<Option<usize>, rns_net::SendError> {
        Ok(self.mdu)
    }
    fn send_control_frame(
        &self,
        link_id: [u8; 16],
        frame: Vec<u8>,
    ) -> Result<(), rns_net::SendError> {
        let message = ControlMessage::decode(&frame).expect("gateway sent a valid control frame");
        self.controls.borrow_mut().push((link_id, message));
        Ok(())
    }
    fn try_send_fragment(&self, link_id: [u8; 16], frame: Vec<u8>, _timeout: Duration) -> bool {
        if self.refuse_fragments.get() {
            return false;
        }
        self.fragments.borrow_mut().push((link_id, frame));
        true
    }
    fn teardown_link(&self, link_id: [u8; 16]) -> Result<(), rns_net::SendError> {
        self.teardowns.borrow_mut().push(link_id);
        Ok(())
    }
    fn dropped_callbacks(&self) -> u64 {
        3
    }
}

impl FakeNode {
    fn take_controls(&self, link_id: [u8; 16]) -> Vec<ControlMessage> {
        let mut controls = self.controls.borrow_mut();
        let (taken, kept) = controls.drain(..).partition(|(link, _)| *link == link_id);
        *controls = kept;
        taken.into_iter().map(|(_, message)| message).collect()
    }
    fn take_fragments(&self, link_id: [u8; 16]) -> Vec<Vec<u8>> {
        let mut fragments = self.fragments.borrow_mut();
        let (taken, kept) = fragments.drain(..).partition(|(link, _)| *link == link_id);
        *fragments = kept;
        taken.into_iter().map(|(_, frame)| frame).collect()
    }
    fn torn_down(&self, link_id: [u8; 16]) -> bool {
        self.teardowns.borrow().contains(&link_id)
    }
}

#[derive(Default)]
struct FakeDevice {
    written: Vec<Vec<u8>>,
}

impl PacketDevice for FakeDevice {
    fn read_packet(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        self.written.push(packet.to_vec());
        Ok(())
    }
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    config: GatewayConfig,
    node: FakeNode,
    device: FakeDevice,
    status: SharedStatus,
}

impl Fixture {
    fn new(extra_config: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let policy_file = directory.path().join("policy.toml");
        fs::write(&policy_file, policy_toml("10.77.0.2")).unwrap();
        let config: GatewayConfig = toml::from_str(&format!(
            "policy_file = {:?}\n{extra_config}",
            policy_file.display().to_string()
        ))
        .unwrap();
        Self {
            _directory: directory,
            config,
            node: FakeNode::default(),
            device: FakeDevice::default(),
            status: SharedStatus::new(RuntimeStatus::default()),
        }
    }

    /// The Docker suite's gateway: full-tunnel DNS 198.18.0.53, 16 pending
    /// Links and 8 active sessions.
    fn docker() -> Self {
        Self::new(
            "dns_servers = [\"198.18.0.53\"]\nmax_pending_links = 16\nmax_active_sessions = 8",
        )
    }

    fn gateway(&mut self) -> GatewayLoop<'_, FakeNode, FakeDevice> {
        let policy =
            GatewayPolicy::parse_toml(&fs::read_to_string(&self.config.policy_file).unwrap())
                .unwrap();
        GatewayLoop {
            gateway: &self.config,
            node: &self.node,
            status: &self.status,
            device: &mut self.device,
            policy,
            policy_modified: fs::metadata(&self.config.policy_file)
                .unwrap()
                .modified()
                .ok(),
            sessions: HashMap::new(),
            started: Instant::now(),
        }
    }
}

type Gateway<'a> = GatewayLoop<'a, FakeNode, FakeDevice>;

fn cidr(text: &str) -> Cidr {
    text.parse().unwrap()
}

fn addr(text: &str) -> Ipv4Addr {
    text.parse().unwrap()
}

/// A valid UDP packet of `total_len` bytes.
fn packet(source: &str, destination: &str, total_len: usize) -> Vec<u8> {
    let mut packet = vec![0; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&addr(source).octets());
    packet[16..20].copy_from_slice(&addr(destination).octets());
    for (index, byte) in packet.iter_mut().enumerate().skip(20) {
        *byte = index as u8;
    }
    let sum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet
}

fn hello(routes: &[&str]) -> Vec<u8> {
    ControlMessage::ClientHello {
        versions: vec![VERSION],
        maximum_packet_size: 1280,
        requested_routes: routes.iter().map(|route| cidr(route)).collect(),
    }
    .encode()
    .unwrap()
}

fn ready(session_epoch: u64, dns_servers: &[&str]) -> Vec<u8> {
    ControlMessage::ClientReady {
        session_epoch,
        dns_servers: dns_servers.iter().map(|server| addr(server)).collect(),
    }
    .encode()
    .unwrap()
}

/// Hands `event` to the gateway. Returns whether the gateway cut the main
/// loop pass short, which it does for an event it ignored or after dropping
/// a session.
fn event(gateway: &mut Gateway<'_>, event: NodeEvent) -> bool {
    gateway.handle_event(event).unwrap().is_break()
}

fn link_up(gateway: &mut Gateway<'_>, link_id: [u8; 16]) -> bool {
    event(
        gateway,
        NodeEvent::LinkEstablished {
            link_id,
            initiator: false,
        },
    )
}

fn identify(gateway: &mut Gateway<'_>, link_id: [u8; 16], identity: [u8; 16]) -> bool {
    event(gateway, NodeEvent::RemoteIdentified { link_id, identity })
}

fn control(gateway: &mut Gateway<'_>, link_id: [u8; 16], payload: Vec<u8>) -> bool {
    event(gateway, NodeEvent::Control { link_id, payload })
}

fn only_control(gateway: &Gateway<'_>, link_id: [u8; 16]) -> ControlMessage {
    let mut controls = gateway.node.take_controls(link_id);
    assert_eq!(
        controls.len(),
        1,
        "expected one control message: {controls:?}"
    );
    controls.remove(0)
}

fn assert_rejected(gateway: &Gateway<'_>, link_id: [u8; 16], expected: u16) {
    match only_control(gateway, link_id) {
        ControlMessage::ServerReject { reason, .. } => assert_eq!(reason, expected),
        other => panic!("expected a reject, got {other:?}"),
    }
    assert!(gateway.node.torn_down(link_id));
}

fn state(gateway: &Gateway<'_>, link_id: [u8; 16]) -> Option<GatewayState> {
    gateway
        .sessions
        .get(&link_id)
        .map(|entry| entry.machine.state())
}

/// Runs the handshake up to the accept and returns it.
fn negotiate(
    gateway: &mut Gateway<'_>,
    link_id: [u8; 16],
    identity: [u8; 16],
    routes: &[&str],
) -> ControlMessage {
    link_up(gateway, link_id);
    identify(gateway, link_id, identity);
    control(gateway, link_id, hello(routes));
    only_control(gateway, link_id)
}

fn epoch_of(accept: &ControlMessage) -> u64 {
    match accept {
        ControlMessage::ServerAccept { session_epoch, .. } => *session_epoch,
        other => panic!("expected an accept, got {other:?}"),
    }
}

/// The client end of an active session.
struct Client {
    epoch: u64,
    transport: PacketTransport,
}

/// Runs the whole handshake.
fn activate(
    gateway: &mut Gateway<'_>,
    link_id: [u8; 16],
    identity: [u8; 16],
    routes: &[&str],
    dns: &[&str],
) -> Client {
    let accept = negotiate(gateway, link_id, identity, routes);
    let ControlMessage::ServerAccept {
        session_epoch,
        assigned_address,
        gateway_address,
        accepted_routes,
        packet_mtu,
        ..
    } = accept
    else {
        panic!("expected an accept, got {accept:?}");
    };
    control(gateway, link_id, ready(session_epoch, dns));
    assert_eq!(
        only_control(gateway, link_id),
        ControlMessage::ServerReady { session_epoch }
    );
    assert_eq!(state(gateway, link_id), Some(GatewayState::Active));
    Client {
        epoch: session_epoch,
        transport: PacketTransport::new(
            session_epoch,
            assigned_address,
            gateway_address,
            accepted_routes,
            packet_mtu,
            1,
        )
        .unwrap(),
    }
}

/// Sends `packet` from the client over `link_id`, one event per fragment.
fn client_sends(
    gateway: &mut Gateway<'_>,
    link_id: [u8; 16],
    client: &mut Client,
    packet: &[u8],
    link_mdu: usize,
) {
    for payload in client
        .transport
        .packetize(packet, PacketDirection::ClientToGateway, link_mdu)
        .unwrap()
    {
        event(gateway, NodeEvent::PacketData { link_id, payload });
    }
}

/// Reassembles what the gateway sent to the client over `link_id`.
fn client_receives(gateway: &Gateway<'_>, link_id: [u8; 16], client: &mut Client) -> Vec<Vec<u8>> {
    gateway
        .node
        .take_fragments(link_id)
        .iter()
        .filter_map(|frame| {
            client
                .transport
                .receive(frame, PacketDirection::GatewayToClient, Duration::ZERO)
                .unwrap()
        })
        .collect()
}

/// Moves the gateway's clock forward by `by`.
fn advance(gateway: &mut Gateway<'_>, by: Duration) {
    gateway.started = gateway
        .started
        .checked_sub(by)
        .expect("monotonic clock far enough from its origin");
}

// --- Handshake and address assignment --------------------------------

#[test]
fn split_tunnel_handshake_assigns_address_and_routes() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    link_up(&mut gateway, LINK_A);
    assert_eq!(state(&gateway, LINK_A), Some(GatewayState::PendingIdentity));
    identify(&mut gateway, LINK_A, SPLIT);
    assert_eq!(state(&gateway, LINK_A), Some(GatewayState::Negotiating));
    control(&mut gateway, LINK_A, hello(&["198.18.0.0/24"]));
    let accept = only_control(&gateway, LINK_A);
    let ControlMessage::ServerAccept {
        session_epoch,
        assigned_address,
        prefix_len,
        gateway_address,
        accepted_routes,
        dns_servers,
        packet_mtu,
        setup_timeout_secs,
        idle_timeout_secs,
    } = accept
    else {
        panic!("expected an accept, got {accept:?}");
    };
    assert_ne!(session_epoch, 0);
    assert_eq!(assigned_address, addr("10.77.0.3"));
    assert_eq!(prefix_len, 24);
    assert_eq!(gateway_address, addr("10.77.0.1"));
    assert_eq!(accepted_routes, vec![cidr("198.18.0.0/24")]);
    assert!(dns_servers.is_empty(), "a split tunnel gets no DNS");
    assert_eq!(packet_mtu, 1280);
    assert_eq!(setup_timeout_secs, 60);
    assert_eq!(idle_timeout_secs, 0);
    assert_eq!(state(&gateway, LINK_A), Some(GatewayState::DeviceSetup));

    control(&mut gateway, LINK_A, ready(session_epoch, &[]));
    assert_eq!(
        only_control(&gateway, LINK_A),
        ControlMessage::ServerReady { session_epoch }
    );
    assert_eq!(state(&gateway, LINK_A), Some(GatewayState::Active));
    assert!(!gateway.node.torn_down(LINK_A));
}

#[test]
fn full_tunnel_handshake_advertises_gateway_dns() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    let accept = negotiate(&mut gateway, LINK_A, FULL, &["0.0.0.0/0"]);
    let ControlMessage::ServerAccept {
        session_epoch,
        assigned_address,
        accepted_routes,
        dns_servers,
        idle_timeout_secs,
        ..
    } = accept
    else {
        panic!("expected an accept, got {accept:?}");
    };
    assert_eq!(assigned_address, addr("10.77.0.2"));
    assert_eq!(accepted_routes, vec![cidr("0.0.0.0/0")]);
    assert_eq!(dns_servers, vec![addr("198.18.0.53")]);
    assert_eq!(idle_timeout_secs, 120);
    control(&mut gateway, LINK_A, ready(session_epoch, &["198.18.0.53"]));
    assert_eq!(
        only_control(&gateway, LINK_A),
        ControlMessage::ServerReady { session_epoch }
    );
}

#[test]
fn hello_before_identity_is_answered_once_identified() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    link_up(&mut gateway, LINK_A);
    control(&mut gateway, LINK_A, hello(&["198.18.0.0/24"]));
    // A repeat of the same hello is harmless.
    control(&mut gateway, LINK_A, hello(&["198.18.0.0/24"]));
    assert!(gateway.node.take_controls(LINK_A).is_empty());
    identify(&mut gateway, LINK_A, SPLIT);
    epoch_of(&only_control(&gateway, LINK_A));
    assert_eq!(state(&gateway, LINK_A), Some(GatewayState::DeviceSetup));
}

#[test]
fn conflicting_hellos_before_identity_drop_the_session() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    link_up(&mut gateway, LINK_A);
    control(&mut gateway, LINK_A, hello(&["198.18.0.0/24"]));
    control(&mut gateway, LINK_A, hello(&["198.18.0.0/25"]));
    assert_rejected(&gateway, LINK_A, 2);
    assert_eq!(state(&gateway, LINK_A), None);
}

#[test]
fn ready_repeat_is_confirmed_again() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    let epoch = epoch_of(&negotiate(&mut gateway, LINK_A, SPLIT, &["198.18.0.0/24"]));
    control(&mut gateway, LINK_A, ready(epoch, &[]));
    control(&mut gateway, LINK_A, ready(epoch, &[]));
    assert_eq!(
        gateway.node.take_controls(LINK_A),
        vec![
            ControlMessage::ServerReady {
                session_epoch: epoch
            };
            2
        ]
    );
    assert_eq!(state(&gateway, LINK_A), Some(GatewayState::Active));
}

#[test]
fn ready_with_wrong_epoch_drops_the_session() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    let epoch = epoch_of(&negotiate(&mut gateway, LINK_A, SPLIT, &["198.18.0.0/24"]));
    control(&mut gateway, LINK_A, ready(epoch ^ 1, &[]));
    assert_rejected(&gateway, LINK_A, 2);
    assert_eq!(state(&gateway, LINK_A), None);
}

#[test]
fn ready_before_hello_drops_the_session() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    link_up(&mut gateway, LINK_A);
    identify(&mut gateway, LINK_A, SPLIT);
    control(&mut gateway, LINK_A, ready(5, &[]));
    assert_rejected(&gateway, LINK_A, 2);
    assert_eq!(state(&gateway, LINK_A), None);
}

#[test]
fn link_mdu_comes_from_the_node_or_defaults() {
    let mut fixture = Fixture::docker();
    fixture.node.mdu = Some(431);
    let mut gateway = fixture.gateway();
    link_up(&mut gateway, LINK_A);
    assert_eq!(gateway.sessions[&LINK_A].link_mdu, 431);
    drop(gateway);

    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    link_up(&mut gateway, LINK_A);
    assert_eq!(gateway.sessions[&LINK_A].link_mdu, 384);
}

#[test]
fn outbound_link_events_are_ignored() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    event(
        &mut gateway,
        NodeEvent::LinkEstablished {
            link_id: LINK_A,
            initiator: true,
        },
    );
    assert!(gateway.sessions.is_empty());
}

// --- Policy decisions ------------------------------------------------

#[test]
fn unlisted_and_disabled_identities_are_rejected() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    for (link_id, identity) in [(LINK_A, STRANGER), (LINK_B, DISABLED)] {
        link_up(&mut gateway, link_id);
        let pass = identify(&mut gateway, link_id, identity);
        assert!(pass);
        assert_rejected(&gateway, link_id, 1);
        assert_eq!(state(&gateway, link_id), None);
    }
}

#[test]
fn requested_routes_are_narrowed_to_the_grant() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    // Asks for more than granted, an unrelated network and the default
    // route without an Internet grant.
    let accept = negotiate(
        &mut gateway,
        LINK_A,
        SPLIT,
        &["198.18.0.0/16", "10.99.0.0/16", "0.0.0.0/0"],
    );
    let ControlMessage::ServerAccept {
        accepted_routes,
        dns_servers,
        ..
    } = accept
    else {
        panic!("expected an accept, got {accept:?}");
    };
    assert_eq!(accepted_routes, vec![cidr("198.18.0.0/24")]);
    assert!(dns_servers.is_empty());
}

#[test]
fn full_tunnel_client_may_still_ask_for_a_split_tunnel() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    let accept = negotiate(&mut gateway, LINK_A, FULL, &["198.18.0.0/24"]);
    let ControlMessage::ServerAccept {
        accepted_routes,
        dns_servers,
        ..
    } = accept
    else {
        panic!("expected an accept, got {accept:?}");
    };
    assert_eq!(accepted_routes, vec![cidr("198.18.0.0/24")]);
    assert!(dns_servers.is_empty());
}

#[test]
fn full_tunnel_needs_gateway_dns() {
    let mut fixture = Fixture::new("");
    let mut gateway = fixture.gateway();
    link_up(&mut gateway, LINK_A);
    identify(&mut gateway, LINK_A, FULL);
    control(&mut gateway, LINK_A, hello(&["0.0.0.0/0"]));
    assert_rejected(&gateway, LINK_A, 5);
}

#[test]
fn ready_must_echo_the_advertised_dns() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    let epoch = epoch_of(&negotiate(&mut gateway, LINK_A, FULL, &["0.0.0.0/0"]));
    control(&mut gateway, LINK_A, ready(epoch, &["1.1.1.1"]));
    assert_rejected(&gateway, LINK_A, 3);
    assert_eq!(state(&gateway, LINK_A), None);
}

#[test]
fn incompatible_version_or_small_mtu_is_rejected() {
    for (versions, maximum_packet_size) in [(vec![1], 1280), (vec![VERSION], 575)] {
        let mut fixture = Fixture::docker();
        let mut gateway = fixture.gateway();
        link_up(&mut gateway, LINK_A);
        identify(&mut gateway, LINK_A, SPLIT);
        let payload = ControlMessage::ClientHello {
            versions,
            maximum_packet_size,
            requested_routes: vec![cidr("198.18.0.0/24")],
        }
        .encode()
        .unwrap();
        control(&mut gateway, LINK_A, payload);
        assert_rejected(&gateway, LINK_A, 4);
    }
}

#[test]
fn hello_rejects_forget_the_session_at_once() {
    let small_mtu = ControlMessage::ClientHello {
        versions: vec![VERSION],
        maximum_packet_size: 575,
        requested_routes: vec![cidr("198.18.0.0/24")],
    }
    .encode()
    .unwrap();
    // Reason 4 on a split-tunnel client, reason 5 on a full-tunnel client
    // of a gateway without DNS servers; the hello comes both after and
    // before the identity.
    for (extra_config, identity, payload, reason) in [
        ("dns_servers = [\"198.18.0.53\"]", SPLIT, small_mtu, 4),
        ("", FULL, hello(&["0.0.0.0/0"]), 5),
    ] {
        for hello_first in [false, true] {
            let mut fixture = Fixture::new(extra_config);
            let mut gateway = fixture.gateway();
            link_up(&mut gateway, LINK_A);
            if hello_first {
                control(&mut gateway, LINK_A, payload.clone());
                assert!(identify(&mut gateway, LINK_A, identity));
            } else {
                identify(&mut gateway, LINK_A, identity);
                assert!(control(&mut gateway, LINK_A, payload.clone()));
            }
            assert_rejected(&gateway, LINK_A, reason);
            assert_eq!(state(&gateway, LINK_A), None);
            // A later hello on the torn-down Link gets no answer.
            control(&mut gateway, LINK_A, hello(&["198.18.0.0/24"]));
            assert!(gateway.node.take_controls(LINK_A).is_empty());
            gateway.publish_status();
            assert!(gateway.status.snapshot().sessions.is_empty());
        }
    }
}

#[test]
fn mtu_is_capped_at_1280() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    for (offered, expected) in [(1500, 1280), (576, 576)] {
        gateway.sessions.clear();
        link_up(&mut gateway, LINK_A);
        identify(&mut gateway, LINK_A, SPLIT);
        let payload = ControlMessage::ClientHello {
            versions: vec![VERSION],
            maximum_packet_size: offered,
            requested_routes: vec![cidr("198.18.0.0/24")],
        }
        .encode()
        .unwrap();
        control(&mut gateway, LINK_A, payload);
        match only_control(&gateway, LINK_A) {
            ControlMessage::ServerAccept { packet_mtu, .. } => assert_eq!(packet_mtu, expected),
            other => panic!("expected an accept, got {other:?}"),
        }
    }
}

// --- Malformed control traffic and unknown sessions -------------------

#[test]
fn malformed_control_message_is_rejected() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    link_up(&mut gateway, LINK_A);
    identify(&mut gateway, LINK_A, SPLIT);
    control(&mut gateway, LINK_A, b"not a control frame".to_vec());
    assert_rejected(&gateway, LINK_A, 2);
    assert_eq!(state(&gateway, LINK_A), None);
}

#[test]
fn other_protocol_version_is_rejected() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    link_up(&mut gateway, LINK_A);
    identify(&mut gateway, LINK_A, SPLIT);
    let mut payload = hello(&["198.18.0.0/24"]);
    payload[4] = VERSION + 1;
    control(&mut gateway, LINK_A, payload);
    assert_rejected(&gateway, LINK_A, 4);
    assert_eq!(state(&gateway, LINK_A), None);
}

#[test]
fn events_for_unknown_links_are_ignored() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    assert!(identify(&mut gateway, LINK_A, SPLIT));
    assert!(control(&mut gateway, LINK_A, hello(&["198.18.0.0/24"])));
    assert!(control(&mut gateway, LINK_A, b"garbage".to_vec()));
    let payload = packet("10.77.0.3", "198.18.0.10", 64);
    assert!(event(
        &mut gateway,
        NodeEvent::PacketData {
            link_id: LINK_A,
            payload
        }
    ));
    assert!(gateway.sessions.is_empty());
    assert!(gateway.node.controls.borrow().is_empty());
    assert!(gateway.node.teardowns.borrow().is_empty());
    assert!(gateway.device.written.is_empty());
}

// --- Teardown ---------------------------------------------------------

#[test]
fn client_close_is_acknowledged_and_releases_the_session() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    let epoch = activate(&mut gateway, LINK_A, SPLIT, &["198.18.0.0/24"], &[]).epoch;
    let close = ControlMessage::Close {
        session_epoch: epoch,
        reason: 0,
        diagnostic: "bye".into(),
    }
    .encode()
    .unwrap();
    control(&mut gateway, LINK_A, close);
    assert_eq!(
        only_control(&gateway, LINK_A),
        ControlMessage::CloseAck {
            session_epoch: epoch
        }
    );
    assert!(gateway.node.torn_down(LINK_A));
    assert_eq!(state(&gateway, LINK_A), None);
    gateway.publish_status();
    assert!(gateway.status.snapshot().sessions.is_empty());
}

#[test]
fn link_closed_releases_the_session() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    activate(&mut gateway, LINK_A, SPLIT, &["198.18.0.0/24"], &[]);
    gateway.publish_status();
    assert_eq!(gateway.status.snapshot().sessions.len(), 1);
    event(
        &mut gateway,
        NodeEvent::LinkClosed {
            link_id: LINK_A,
            reason: None,
        },
    );
    assert_eq!(state(&gateway, LINK_A), None);
    gateway.publish_status();
    assert!(gateway.status.snapshot().sessions.is_empty());
}

#[test]
fn reconnect_on_a_new_link_gets_a_fresh_session() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    activate(&mut gateway, LINK_A, FULL, &["0.0.0.0/0"], &["198.18.0.53"]);
    event(
        &mut gateway,
        NodeEvent::LinkClosed {
            link_id: LINK_A,
            reason: None,
        },
    );
    let mut client = activate(&mut gateway, LINK_B, FULL, &["0.0.0.0/0"], &["198.18.0.53"]);
    let reply = packet("198.18.0.10", "10.77.0.2", 84);
    gateway.forward_tun_packet(&reply);
    assert_eq!(client_receives(&gateway, LINK_B, &mut client), vec![reply]);
}

#[test]
fn reconnect_before_the_old_link_closes_replaces_the_old_session() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    let mut old = activate(&mut gateway, LINK_A, FULL, &["0.0.0.0/0"], &["198.18.0.53"]);
    // The client reconnects before the gateway notices the old Link is gone.
    let epoch = epoch_of(&negotiate(&mut gateway, LINK_B, FULL, &["0.0.0.0/0"]));
    // Until the new session is active, the old one still gets the traffic.
    let early = packet("198.18.0.10", "10.77.0.2", 84);
    gateway.forward_tun_packet(&early);
    assert_eq!(client_receives(&gateway, LINK_A, &mut old), vec![early]);
    assert!(!gateway.node.torn_down(LINK_A));
    control(&mut gateway, LINK_B, ready(epoch, &["198.18.0.53"]));
    assert_eq!(
        only_control(&gateway, LINK_B),
        ControlMessage::ServerReady {
            session_epoch: epoch
        }
    );
    assert_eq!(state(&gateway, LINK_A), None);
    assert!(gateway.node.torn_down(LINK_A));
    assert!(!gateway.node.torn_down(LINK_B));
    let mut new = Client {
        epoch,
        transport: PacketTransport::new(
            epoch,
            addr("10.77.0.2"),
            addr("10.77.0.1"),
            vec![cidr("0.0.0.0/0")],
            1280,
            1,
        )
        .unwrap(),
    };
    for _ in 0..8 {
        let reply = packet("198.18.0.10", "10.77.0.2", 84);
        gateway.forward_tun_packet(&reply);
        assert_eq!(client_receives(&gateway, LINK_B, &mut new), vec![reply]);
    }
    assert!(gateway.node.take_fragments(LINK_A).is_empty());
    // The old Link closing later leaves the new session alone.
    event(
        &mut gateway,
        NodeEvent::LinkClosed {
            link_id: LINK_A,
            reason: None,
        },
    );
    assert_eq!(state(&gateway, LINK_B), Some(GatewayState::Active));
}

#[test]
fn reconnect_at_active_capacity_replaces_the_old_session() {
    let mut fixture = Fixture::new("max_pending_links = 4\nmax_active_sessions = 1");
    let mut gateway = fixture.gateway();
    activate(&mut gateway, LINK_A, SPLIT, &["198.18.0.0/24"], &[]);
    activate(&mut gateway, LINK_B, SPLIT, &["198.18.0.0/24"], &[]);
    assert_eq!(state(&gateway, LINK_A), None);
    assert!(gateway.node.torn_down(LINK_A));
    // Another client is still held to the capacity.
    let epoch = epoch_of(&negotiate(&mut gateway, LINK_C, FULL, &["198.18.0.0/24"]));
    control(&mut gateway, LINK_C, ready(epoch, &[]));
    assert_rejected(&gateway, LINK_C, 6);
    assert_eq!(state(&gateway, LINK_B), Some(GatewayState::Active));
}

// --- Status -------------------------------------------------------------

#[test]
fn status_lists_identified_sessions() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    activate(&mut gateway, LINK_A, FULL, &["0.0.0.0/0"], &["198.18.0.53"]);
    negotiate(&mut gateway, LINK_B, SPLIT, &["198.18.0.0/24"]);
    // Not identified yet, so not listed.
    link_up(&mut gateway, LINK_C);
    gateway.publish_status();
    let status = gateway.status.snapshot();
    assert_eq!(status.queue_depths.get("dropped_node_callbacks"), Some(&3));
    let mut sessions = status.sessions;
    sessions.sort_by(|a, b| a.identity.cmp(&b.identity));
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0].identity, hex(&FULL));
    assert_eq!(sessions[0].state, "active");
    assert_eq!(sessions[0].address, addr("10.77.0.2"));
    assert_eq!(sessions[0].routes, vec!["0.0.0.0/0".to_string()]);
    assert_eq!(sessions[0].dns_servers, vec![addr("198.18.0.53")]);
    assert_eq!(sessions[1].identity, hex(&SPLIT));
    assert_eq!(sessions[1].state, "devicesetup");
    assert_eq!(sessions[1].address, addr("10.77.0.3"));
    assert_eq!(sessions[1].routes, vec!["198.18.0.0/24".to_string()]);
    assert!(sessions[1].dns_servers.is_empty());
}

// --- Session limits ---------------------------------------------------

#[test]
fn links_beyond_pending_and_active_capacity_are_torn_down() {
    let mut fixture = Fixture::new("max_pending_links = 1\nmax_active_sessions = 1");
    let mut gateway = fixture.gateway();
    assert!(!link_up(&mut gateway, LINK_A));
    assert!(!link_up(&mut gateway, LINK_B));
    assert!(link_up(&mut gateway, LINK_C));
    assert!(gateway.node.torn_down(LINK_C));
    assert!(gateway.node.take_controls(LINK_C).is_empty());
    assert_eq!(gateway.sessions.len(), 2);
}

#[test]
fn ready_beyond_active_capacity_is_rejected() {
    let mut fixture = Fixture::new("max_pending_links = 4\nmax_active_sessions = 1");
    let mut gateway = fixture.gateway();
    activate(&mut gateway, LINK_A, SPLIT, &["198.18.0.0/24"], &[]);
    let epoch = epoch_of(&negotiate(&mut gateway, LINK_B, FULL, &["198.18.0.0/24"]));
    control(&mut gateway, LINK_B, ready(epoch, &[]));
    assert_rejected(&gateway, LINK_B, 6);
    assert_eq!(state(&gateway, LINK_B), None);
    assert_eq!(state(&gateway, LINK_A), Some(GatewayState::Active));
}

// --- Client to TUN ----------------------------------------------------

#[test]
fn client_packet_is_written_to_the_tun_device() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    let mut client = activate(&mut gateway, LINK_A, SPLIT, &["198.18.0.0/24"], &[]);
    let ping = packet("10.77.0.3", "198.18.0.10", 84);
    client_sends(&mut gateway, LINK_A, &mut client, &ping, 384);
    assert_eq!(gateway.device.written, vec![ping.clone()]);
    let counters = gateway.status.snapshot().counters;
    assert_eq!(counters.packets_in, 1);
    assert_eq!(counters.bytes_in, ping.len() as u64);
    assert_eq!(counters.malformed + counters.unauthorized, 0);
}

#[test]
fn fragmented_client_packet_is_reassembled() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    let mut client = activate(&mut gateway, LINK_A, FULL, &["0.0.0.0/0"], &["198.18.0.53"]);
    let large = packet("10.77.0.2", "8.8.8.8", 1280);
    client_sends(&mut gateway, LINK_A, &mut client, &large, 200);
    assert_eq!(gateway.device.written, vec![large]);
}

#[test]
fn client_packet_outside_its_grant_is_dropped() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    let epoch = activate(&mut gateway, LINK_A, SPLIT, &["198.18.0.0/24"], &[]).epoch;
    for bad in [
        packet("10.77.0.9", "198.18.0.10", 64), // spoofed source
        packet("10.77.0.3", "8.8.8.8", 64),     // outside the routes
    ] {
        let payload = fragment(epoch, 1, &bad);
        event(
            &mut gateway,
            NodeEvent::PacketData {
                link_id: LINK_A,
                payload,
            },
        );
    }
    assert!(gateway.device.written.is_empty());
    let counters = gateway.status.snapshot().counters;
    assert_eq!(counters.unauthorized, 2);
    assert_eq!(counters.packets_in, 0);
    assert_eq!(state(&gateway, LINK_A), Some(GatewayState::Active));
}

#[test]
fn malformed_or_foreign_fragments_are_counted_and_dropped() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    let epoch = activate(&mut gateway, LINK_A, SPLIT, &["198.18.0.0/24"], &[]).epoch;
    let good = packet("10.77.0.3", "198.18.0.10", 64);
    let mut bad_checksum = good.clone();
    bad_checksum[10] ^= 0xff;
    let oversized = packet("10.77.0.3", "198.18.0.10", 1400);
    let payloads = [
        b"garbage".to_vec(),
        fragment(epoch, 1, &bad_checksum),
        fragment(epoch, 2, &oversized),
        fragment(epoch ^ 1, 3, &good), // another session's epoch
    ];
    for payload in payloads {
        event(
            &mut gateway,
            NodeEvent::PacketData {
                link_id: LINK_A,
                payload,
            },
        );
    }
    assert!(gateway.device.written.is_empty());
    let counters = gateway.status.snapshot().counters;
    assert_eq!(counters.malformed, 3);
    assert_eq!(counters.unauthorized, 1);
    // The session survives bad traffic.
    assert_eq!(state(&gateway, LINK_A), Some(GatewayState::Active));
}

#[test]
fn replayed_client_packet_is_dropped() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    let epoch = activate(&mut gateway, LINK_A, SPLIT, &["198.18.0.0/24"], &[]).epoch;
    let payload = fragment(epoch, 7, &packet("10.77.0.3", "198.18.0.10", 64));
    for _ in 0..2 {
        event(
            &mut gateway,
            NodeEvent::PacketData {
                link_id: LINK_A,
                payload: payload.clone(),
            },
        );
    }
    assert_eq!(gateway.device.written.len(), 1);
    let counters = gateway.status.snapshot().counters;
    assert_eq!(counters.packets_in, 1);
    assert_eq!(counters.unauthorized, 1);
}

#[test]
fn packet_data_before_activation_is_ignored() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    let epoch = epoch_of(&negotiate(&mut gateway, LINK_A, SPLIT, &["198.18.0.0/24"]));
    let payload = fragment(epoch, 1, &packet("10.77.0.3", "198.18.0.10", 64));
    let pass = event(
        &mut gateway,
        NodeEvent::PacketData {
            link_id: LINK_A,
            payload,
        },
    );
    assert!(pass);
    assert!(gateway.device.written.is_empty());
    assert_eq!(gateway.status.snapshot().counters.malformed, 0);
}

// --- TUN to client ----------------------------------------------------

#[test]
fn tun_packet_reaches_the_client_it_is_addressed_to() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    let mut full = activate(&mut gateway, LINK_A, FULL, &["0.0.0.0/0"], &["198.18.0.53"]);
    let mut split = activate(&mut gateway, LINK_B, SPLIT, &["198.18.0.0/24"], &[]);
    let to_full = packet("198.18.0.10", "10.77.0.2", 84);
    let to_split = packet("198.18.0.10", "10.77.0.3", 84);
    gateway.forward_tun_packet(&to_full);
    gateway.forward_tun_packet(&to_split);
    assert_eq!(client_receives(&gateway, LINK_A, &mut full), vec![to_full]);
    assert_eq!(
        client_receives(&gateway, LINK_B, &mut split),
        vec![to_split]
    );
    let counters = gateway.status.snapshot().counters;
    assert_eq!(counters.packets_out, 2);
    assert_eq!(counters.bytes_out, 168);
}

#[test]
fn tun_packet_is_fragmented_to_the_link_mdu() {
    let mut fixture = Fixture::docker();
    fixture.node.mdu = Some(200);
    let mut gateway = fixture.gateway();
    let mut client = activate(&mut gateway, LINK_A, FULL, &["0.0.0.0/0"], &["198.18.0.53"]);
    let large = packet("8.8.8.8", "10.77.0.2", 1280);
    gateway.forward_tun_packet(&large);
    let frames = gateway.node.fragments.borrow().clone();
    assert!(frames.len() > 1);
    assert!(frames.iter().all(|(_, frame)| frame.len() <= 200));
    assert_eq!(client_receives(&gateway, LINK_A, &mut client), vec![large]);
}

#[test]
fn tun_packet_for_no_active_session_is_dropped() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    activate(&mut gateway, LINK_A, SPLIT, &["198.18.0.0/24"], &[]);
    // FULL has negotiated but is not active yet.
    negotiate(&mut gateway, LINK_B, FULL, &["0.0.0.0/0"]);
    gateway.forward_tun_packet(&packet("198.18.0.10", "10.77.0.2", 64));
    gateway.forward_tun_packet(&packet("198.18.0.10", "10.77.0.99", 64));
    assert!(gateway.node.fragments.borrow().is_empty());
    let counters = gateway.status.snapshot().counters;
    assert_eq!(counters.packets_out, 0);
    assert_eq!(counters.malformed + counters.unauthorized, 0);
}

#[test]
fn invalid_or_unauthorized_tun_packets_are_dropped() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    activate(&mut gateway, LINK_A, SPLIT, &["198.18.0.0/24"], &[]);
    let mut bad_checksum = packet("198.18.0.10", "10.77.0.3", 64);
    bad_checksum[10] ^= 0xff;
    gateway.forward_tun_packet(&bad_checksum);
    gateway.forward_tun_packet(&packet("198.18.0.10", "10.77.0.3", 1400));
    gateway.forward_tun_packet(&[0x45, 0, 0]);
    assert_eq!(gateway.status.snapshot().counters.unauthorized, 0);
    // A source outside the split client's routes.
    gateway.forward_tun_packet(&packet("8.8.8.8", "10.77.0.3", 64));
    assert!(gateway.node.fragments.borrow().is_empty());
    let counters = gateway.status.snapshot().counters;
    assert_eq!(counters.unauthorized, 1);
    assert_eq!(counters.packets_out, 0);
}

#[test]
fn tun_packet_the_node_refuses_counts_a_queue_drop() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    activate(&mut gateway, LINK_A, SPLIT, &["198.18.0.0/24"], &[]);
    gateway.node.refuse_fragments.set(true);
    gateway.forward_tun_packet(&packet("198.18.0.10", "10.77.0.3", 64));
    let counters = gateway.status.snapshot().counters;
    assert_eq!(counters.queue_drops, 1);
    assert_eq!(counters.packets_out, 0);
}

#[test]
fn tun_reader_error_stops_forwarding() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    let mut client = activate(&mut gateway, LINK_A, SPLIT, &["198.18.0.0/24"], &[]);
    let (tx, rx) = mpsc::sync_channel(4);
    let reply = packet("198.18.0.10", "10.77.0.3", 64);
    tx.send(Ok(reply.clone())).unwrap();
    tx.send(Err(io::Error::other("TUN gone"))).unwrap();
    tx.send(Ok(reply.clone())).unwrap();
    assert!(gateway.forward_tun_packets(&rx).is_err());
    assert_eq!(client_receives(&gateway, LINK_A, &mut client), vec![reply]);
}

// --- Timeouts ---------------------------------------------------------

#[test]
fn unidentified_link_expires_after_identify_timeout() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    link_up(&mut gateway, LINK_A);
    advance(&mut gateway, Duration::from_secs(29));
    gateway.expire_sessions();
    assert!(state(&gateway, LINK_A).is_some());
    advance(&mut gateway, Duration::from_secs(1));
    gateway.expire_sessions();
    assert_eq!(state(&gateway, LINK_A), None);
    assert!(gateway.node.torn_down(LINK_A));
}

#[test]
fn unready_session_expires_after_setup_timeout() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    negotiate(&mut gateway, LINK_A, SPLIT, &["198.18.0.0/24"]);
    advance(&mut gateway, Duration::from_secs(59));
    gateway.expire_sessions();
    assert!(state(&gateway, LINK_A).is_some());
    advance(&mut gateway, Duration::from_secs(1));
    gateway.expire_sessions();
    assert_eq!(state(&gateway, LINK_A), None);
    assert!(gateway.node.torn_down(LINK_A));
}

#[test]
fn idle_session_expires_only_with_an_idle_timeout() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    // FULL has a 120 s idle timeout, SPLIT none.
    let mut full = activate(&mut gateway, LINK_A, FULL, &["0.0.0.0/0"], &["198.18.0.53"]);
    activate(&mut gateway, LINK_B, SPLIT, &["198.18.0.0/24"], &[]);
    advance(&mut gateway, Duration::from_secs(100));
    // Traffic in either direction counts as activity.
    client_sends(
        &mut gateway,
        LINK_A,
        &mut full,
        &packet("10.77.0.2", "8.8.8.8", 64),
        384,
    );
    advance(&mut gateway, Duration::from_secs(100));
    gateway.forward_tun_packet(&packet("8.8.8.8", "10.77.0.2", 64));
    advance(&mut gateway, Duration::from_secs(119));
    gateway.expire_sessions();
    assert_eq!(state(&gateway, LINK_A), Some(GatewayState::Active));
    advance(&mut gateway, Duration::from_secs(1));
    gateway.expire_sessions();
    assert_eq!(state(&gateway, LINK_A), None);
    assert!(gateway.node.torn_down(LINK_A));
    assert_eq!(state(&gateway, LINK_B), Some(GatewayState::Active));
}

// --- Policy reload ------------------------------------------------------

fn rewrite_policy(gateway: &mut Gateway<'_>, text: &str) {
    fs::write(&gateway.gateway.policy_file, text).unwrap();
    // Force the reload regardless of the file system's timestamp
    // granularity.
    gateway.policy_modified = None;
    gateway.reload_policy_if_changed();
}

#[test]
fn policy_reload_revokes_only_changed_grants() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    activate(&mut gateway, LINK_A, FULL, &["0.0.0.0/0"], &["198.18.0.53"]);
    activate(&mut gateway, LINK_B, SPLIT, &["198.18.0.0/24"], &[]);
    rewrite_policy(&mut gateway, &policy_toml("10.77.0.20"));
    assert_eq!(state(&gateway, LINK_A), None);
    assert!(gateway.node.torn_down(LINK_A));
    assert_eq!(state(&gateway, LINK_B), Some(GatewayState::Active));
    assert!(!gateway.node.torn_down(LINK_B));
    // The new grant applies to the next session.
    let accept = negotiate(&mut gateway, LINK_C, FULL, &["0.0.0.0/0"]);
    let ControlMessage::ServerAccept {
        assigned_address, ..
    } = accept
    else {
        panic!("expected an accept, got {accept:?}");
    };
    assert_eq!(assigned_address, addr("10.77.0.20"));
}

#[test]
fn policy_reload_revokes_removed_clients() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    activate(&mut gateway, LINK_A, SPLIT, &["198.18.0.0/24"], &[]);
    let without_split = policy_toml("10.77.0.2").replace(&hex(&SPLIT), &hex(&STRANGER));
    rewrite_policy(&mut gateway, &without_split);
    assert_eq!(state(&gateway, LINK_A), None);
    assert!(gateway.node.torn_down(LINK_A));
}

#[test]
fn policy_reload_keeps_links_waiting_for_their_identity() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    link_up(&mut gateway, LINK_A);
    link_up(&mut gateway, LINK_B);
    // LINK_B's hello arrives before its identity and is buffered.
    control(&mut gateway, LINK_B, hello(&["198.18.0.0/24"]));
    let moved_split = policy_toml("10.77.0.2")
        .replace(&hex(&SPLIT), &hex(&STRANGER))
        .replace(&hex(&DISABLED), &hex(&SPLIT));
    rewrite_policy(&mut gateway, &moved_split);
    assert_eq!(state(&gateway, LINK_A), Some(GatewayState::PendingIdentity));
    assert_eq!(state(&gateway, LINK_B), Some(GatewayState::PendingIdentity));
    assert!(gateway.node.teardowns.borrow().is_empty());
    // They are checked against the new policy once they identify: SPLIT
    // now has the disabled grant, STRANGER has SPLIT's old one.
    identify(&mut gateway, LINK_A, SPLIT);
    assert_rejected(&gateway, LINK_A, 1);
    assert_eq!(state(&gateway, LINK_A), None);
    identify(&mut gateway, LINK_B, STRANGER);
    let accept = only_control(&gateway, LINK_B);
    let ControlMessage::ServerAccept {
        assigned_address, ..
    } = accept
    else {
        panic!("expected an accept, got {accept:?}");
    };
    assert_eq!(assigned_address, addr("10.77.0.3"));
}

#[test]
fn policy_reload_that_moves_the_gateway_or_fails_is_ignored() {
    let mut fixture = Fixture::docker();
    let mut gateway = fixture.gateway();
    activate(&mut gateway, LINK_A, FULL, &["0.0.0.0/0"], &["198.18.0.53"]);
    let original = gateway.policy.clone();
    let moved = policy_toml("10.77.0.20").replace("10.77.0.1/24", "10.77.0.254/24");
    rewrite_policy(&mut gateway, &moved);
    assert_eq!(gateway.policy, original);
    rewrite_policy(&mut gateway, "not toml [");
    assert_eq!(gateway.policy, original);
    assert_eq!(state(&gateway, LINK_A), Some(GatewayState::Active));
    assert!(gateway.node.teardowns.borrow().is_empty());
}

/// One encoded fragment carrying all of `packet`, built by hand so the
/// client's own transport checks do not stop it.
fn fragment(session_epoch: u64, packet_id: u64, packet: &[u8]) -> Vec<u8> {
    PacketFragment {
        session_epoch,
        packet_id,
        total_len: packet.len() as u16,
        offset: 0,
        payload: packet.to_vec(),
    }
    .encode()
    .unwrap()
}
