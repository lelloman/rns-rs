//! Direct Link against upstream Python Reticulum, which does not implement
//! it: a Python link peer must never receive upgrade signalling, and its
//! link and channel must keep working when the Rust side proposes.
//!
//! Ignored by default (each test runs for about a minute). Run with:
//!
//! ```text
//! PYTHONPATH=$HOME/Reticulum cargo test -p rns-net \
//!     --test direct_link_python_interop -- --ignored
//! ```

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use rns_crypto::identity::Identity;
use rns_crypto::OsRng;
use rns_net::event::HolePunchPolicy;
use rns_net::{
    interface::TcpClientConfig, AnnouncedIdentity, Callbacks, DestHash, InterfaceConfig,
    InterfaceId, NodeConfig, RnsNode, MODE_FULL,
};

/// `REJECT_UNSUPPORTED` from `rns_core::holepunch`.
const REJECT_UNSUPPORTED: u8 = 0x03;
const APP_MSGTYPE: u16 = 0x0101;

/// A Python peer: a TCP server interface, a destination accepting links,
/// and, in `channel` mode, a channel echoing messages back. In `packets`
/// mode it has no channel and echoes plain link packets. Events go to
/// stdout as JSON lines, next to RNS's log, which shows only errors.
const PYTHON_PEER: &str = r#"
import sys, os, json, time, tempfile
import RNS
from RNS.Channel import MessageBase

mode = sys.argv[1]
port = int(sys.argv[2])
config_dir = tempfile.mkdtemp()
with open(os.path.join(config_dir, "config"), "w") as f:
    f.write(f"""
[reticulum]
  enable_transport = No
  share_instance = No
[logging]
  loglevel = 1
[interfaces]
  [[Rust peer]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {port}
""")

def emit(**event):
    print(json.dumps(event), flush=True)

RNS.Reticulum(configdir=config_dir)
# Since 1.6.1 emitted announces are stamped by default, and grinding the
# destination stamp in Python outlasts the test's wait for the announce.
if hasattr(RNS.Transport, "STAMP_DESTINATIONS"): RNS.Transport.STAMP_DESTINATIONS = False
if hasattr(RNS.Transport, "STAMP_PRS"): RNS.Transport.STAMP_PRS = False

class AppMessage(MessageBase):
    MSGTYPE = 0x0101
    def __init__(self, data=b""):
        self.data = data
    def pack(self):
        return self.data
    def unpack(self, raw):
        self.data = raw

identity = RNS.Identity()
destination = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "dlinterop", "python")

def on_link(link):
    emit(event="link", link_id=link.link_id.hex())
    link.set_link_closed_callback(lambda l: emit(event="link_closed", reason=l.teardown_reason))
    if mode == "channel":
        channel = link.get_channel()
        channel.register_message_type(AppMessage)
        def on_message(message):
            emit(event="message", data=message.data.decode())
            channel.send(AppMessage(b"echo:" + message.data))
            return True
        channel.add_message_handler(on_message)
    else:
        def on_packet(data, packet):
            emit(event="packet", data=data.decode())
            RNS.Packet(link, b"echo:" + data).send()
        link.set_packet_callback(on_packet)

destination.set_link_established_callback(on_link)
emit(event="ready", dest=destination.hash.hex(), sig=identity.get_public_key()[32:].hex())
while True:
    destination.announce()
    time.sleep(1)
"#;

#[derive(Debug)]
enum RustEvent {
    Announce(DestHash),
    LinkEstablished([u8; 16]),
    LinkClosed([u8; 16]),
    DirectConnected([u8; 16]),
    DirectFailed([u8; 16], u8),
    Channel(u16, Vec<u8>),
    LinkData(u8, Vec<u8>),
}

struct TestCallbacks(Sender<RustEvent>);

impl Callbacks for TestCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        let _ = self.0.send(RustEvent::Announce(announced.dest_hash));
    }
    fn on_link_established(&mut self, link_id: rns_net::LinkId, _: DestHash, _: f64, _: bool) {
        let _ = self.0.send(RustEvent::LinkEstablished(link_id.0));
    }
    fn on_link_closed(&mut self, link_id: rns_net::LinkId, _: Option<rns_net::TeardownReason>) {
        let _ = self.0.send(RustEvent::LinkClosed(link_id.0));
    }
    fn on_channel_message(&mut self, _: rns_net::LinkId, msgtype: u16, payload: Vec<u8>) {
        let _ = self.0.send(RustEvent::Channel(msgtype, payload));
    }
    fn on_link_data(&mut self, _: rns_net::LinkId, context: u8, data: Vec<u8>) {
        let _ = self.0.send(RustEvent::LinkData(context, data));
    }
    fn on_direct_connect_established(&mut self, link_id: rns_net::LinkId, _: InterfaceId) {
        let _ = self.0.send(RustEvent::DirectConnected(link_id.0));
    }
    fn on_direct_connect_failed(&mut self, link_id: rns_net::LinkId, reason: u8) {
        let _ = self.0.send(RustEvent::DirectFailed(link_id.0, reason));
    }
}

struct PythonPeer {
    child: Child,
    events: Receiver<serde_json::Value>,
    errors: Receiver<String>,
}

impl PythonPeer {
    fn spawn(mode: &str, port: u16) -> Self {
        let mut child = Command::new("python3")
            .args(["-u", "-c", PYTHON_PEER, mode, &port.to_string()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to start Python RNS");
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (events_tx, events) = mpsc::channel();
        let (errors_tx, errors) = mpsc::channel();
        let stderr_errors = errors_tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                match serde_json::from_str::<serde_json::Value>(&line) {
                    Ok(value) => {
                        eprintln!("python event: {line}");
                        let _ = events_tx.send(value);
                    }
                    Err(_) => {
                        eprintln!("python: {line}");
                        let _ = errors_tx.send(line);
                    }
                }
            }
        });
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                eprintln!("python stderr: {line}");
                let _ = stderr_errors.send(line);
            }
        });
        PythonPeer {
            child,
            events,
            errors,
        }
    }

    fn wait(&self, timeout: Duration, mut matches: impl FnMut(&serde_json::Value) -> bool) {
        let deadline = Instant::now() + timeout;
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            match self.events.recv_timeout(remaining) {
                Ok(event) => {
                    assert_ne!(event["event"], "link_closed", "Python's link closed");
                    if matches(&event) {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
        panic!("Python event not seen within {timeout:?}");
    }

    /// No link closure and no logged error on the Python side so far.
    fn assert_healthy(&self) {
        while let Ok(event) = self.events.try_recv() {
            assert_ne!(event["event"], "link_closed", "Python's link closed");
        }
        let errors: Vec<String> = self.errors.try_iter().collect();
        assert!(errors.is_empty(), "Python logged: {errors:?}");
    }
}

impl Drop for PythonPeer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn rns_available() -> bool {
    Command::new("python3")
        .args(["-c", "import RNS"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// A port free for both TCP and UDP, in 30000-32767: below the kernel's
/// ephemeral range (32768-60999 by default), where a socket bound to port
/// 0 or an outgoing connection could take it between this check and the
/// node binding it, and above the 10000-29999 the other tests use.
fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let base = 30_000 + (std::process::id() % 27) as u16 * 100;
    loop {
        let port = base + NEXT.fetch_add(1, Ordering::Relaxed) % 2700;
        let port = if port > 32_767 { port - 2_700 } else { port };
        if std::net::UdpSocket::bind(("0.0.0.0", port)).is_ok()
            && std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
        {
            return port;
        }
    }
}

fn wait_rust<T>(
    rx: &Receiver<RustEvent>,
    timeout: Duration,
    mut matches: impl FnMut(&RustEvent) -> Option<T>,
) -> Option<T> {
    let deadline = Instant::now() + timeout;
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(remaining) {
            Ok(RustEvent::LinkClosed(id)) => panic!("Rust link {id:02x?} closed"),
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

fn hex16(s: &str) -> [u8; 16] {
    hex_bytes(s).try_into().unwrap()
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// A Rust node as eager for Direct Link as configuration allows: it runs
/// its own facilitator, proposes, and accepts every proposal.
fn start_rust_node(python_port: u16, tx: Sender<RustEvent>) -> RnsNode {
    let probe_port = free_port();
    RnsNode::start(
        NodeConfig {
            identity: Some(Identity::new(&mut OsRng)),
            interfaces: vec![InterfaceConfig {
                stamp_costs: Default::default(),
                announce_limits: Default::default(),
                name: String::new(),
                type_name: "TCPClientInterface".into(),
                config_data: Box::new(TcpClientConfig {
                    name: "Python peer".into(),
                    target_host: "127.0.0.1".into(),
                    target_port: python_port,
                    interface_id: InterfaceId(1),
                    ..Default::default()
                }),
                mode: MODE_FULL,
                gravity: 0,
                hop_limiter: None,
                recursive_prs: false,
                announces_from_internal: true,
                announces_to_internal: None,
                ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
                ifac: None,
                discovery: None,
            }],
            share_instance: false,
            rpc_port: 0,
            probe_port: Some(probe_port),
            probe_addrs: vec![std::net::SocketAddr::from(([127, 0, 0, 1], probe_port))],
            direct_connect_policy: HolePunchPolicy::AcceptAll,
            direct_connect_allow_private_endpoints: true,
            direct_connect_allowed_identities: Vec::new(),
            direct_connect_reupgrade: Default::default(),
            probe_rate_limit: Default::default(),
            ..Default::default()
        },
        Box::new(TestCallbacks(tx)),
    )
    .unwrap()
}

/// Start Python in `mode`, link to it from Rust, and return both ends.
fn linked(mode: &str) -> Option<(PythonPeer, RnsNode, Receiver<RustEvent>, [u8; 16])> {
    let _ = env_logger::builder().is_test(true).try_init();
    if !rns_available() {
        eprintln!("Skipping: Python RNS not available");
        return None;
    }
    let port = free_port();
    let python = PythonPeer::spawn(mode, port);
    let mut ready = None;
    python.wait(Duration::from_secs(20), |event| {
        if event["event"] == "ready" {
            ready = Some(event.clone());
            true
        } else {
            false
        }
    });
    let ready = ready.unwrap();
    let dest = hex16(ready["dest"].as_str().unwrap());
    let sig: [u8; 32] = hex_bytes(ready["sig"].as_str().unwrap())
        .try_into()
        .unwrap();

    let (tx, rx) = mpsc::channel();
    let node = start_rust_node(port, tx);
    wait_rust(&rx, Duration::from_secs(20), |event| {
        matches!(event, RustEvent::Announce(hash) if hash.0 == dest).then_some(())
    })
    .expect("no announce from Python");
    let link_id = node.create_link(dest, sig).unwrap();
    wait_rust(&rx, Duration::from_secs(10), |event| {
        matches!(event, RustEvent::LinkEstablished(id) if *id == link_id).then_some(())
    })
    .expect("link to Python not established");
    python.wait(Duration::from_secs(10), |event| event["event"] == "link");
    Some((python, node, rx, link_id))
}

fn propose_and_expect_unsupported(node: &RnsNode, rx: &Receiver<RustEvent>, link_id: [u8; 16]) {
    let started = Instant::now();
    node.propose_direct_connect(link_id).unwrap();
    let outcome = wait_rust(rx, Duration::from_secs(20), |event| match event {
        RustEvent::DirectFailed(id, reason) if *id == link_id => Some(Err(*reason)),
        RustEvent::DirectConnected(id) if *id == link_id => Some(Ok(())),
        _ => None,
    });
    assert_eq!(outcome, Some(Err(REJECT_UNSUPPORTED)));
    assert!(started.elapsed() < Duration::from_secs(15));
}

#[test]
#[ignore = "needs Python RNS; run with PYTHONPATH=... --ignored"]
fn python_channel_peer_is_not_signalled_and_its_channel_keeps_working() {
    let Some((python, node, rx, link_id)) = linked("channel") else {
        return;
    };
    let exchange = |text: &str| {
        let payload = text.as_bytes().to_vec();
        let deadline = Instant::now() + Duration::from_secs(10);
        while node
            .try_send_channel_message(link_id, APP_MSGTYPE, payload.clone())
            .is_err()
        {
            assert!(Instant::now() < deadline, "channel not ready for {text}");
            std::thread::sleep(Duration::from_millis(100));
        }
        python.wait(Duration::from_secs(10), |event| {
            event["event"] == "message" && event["data"] == text
        });
        let echo = format!("echo:{text}").into_bytes();
        wait_rust(&rx, Duration::from_secs(10), |event| {
            matches!(event, RustEvent::Channel(APP_MSGTYPE, data) if *data == echo).then_some(())
        })
        .unwrap_or_else(|| panic!("no echo of {text}"));
    };

    exchange("before the proposal");
    // Over TCP the link signals a large MTU, and a channel message above
    // the base MTU's goes both ways in one packet, as upstream sends it.
    let mdu = node
        .links()
        .unwrap()
        .into_iter()
        .find(|link| link.link_id == link_id)
        .unwrap()
        .mdu;
    assert!(mdu > 1100, "link MDU {mdu}");
    exchange(&"m".repeat(1000));
    propose_and_expect_unsupported(&node, &rx, link_id);
    // Keep exchanging past the point where an unacknowledged channel
    // envelope would have exhausted its retries. (Traffic, not silence:
    // an idle link is not what this test is about.)
    let until = Instant::now() + Duration::from_secs(25);
    let mut n = 0;
    while Instant::now() < until {
        exchange(&format!("after the proposal {n}"));
        n += 1;
        std::thread::sleep(Duration::from_secs(2));
    }
    python.assert_healthy();
    node.shutdown();
}

#[test]
#[ignore = "needs Python RNS; run with PYTHONPATH=... --ignored"]
fn python_peer_without_channel_is_not_signalled_and_its_link_survives() {
    let Some((python, node, rx, link_id)) = linked("packets") else {
        return;
    };
    let exchange = |text: &str| {
        futures::executor::block_on(node.send_on_link(
            link_id,
            text.as_bytes().to_vec(),
            rns_core::constants::CONTEXT_NONE,
        ))
        .unwrap();
        python.wait(Duration::from_secs(10), |event| {
            event["event"] == "packet" && event["data"] == text
        });
        let echo = format!("echo:{text}").into_bytes();
        wait_rust(&rx, Duration::from_secs(10), |event| {
            matches!(event, RustEvent::LinkData(0, data) if *data == echo).then_some(())
        })
        .unwrap_or_else(|| panic!("no echo of {text}"));
    };

    exchange("before the proposal");
    propose_and_expect_unsupported(&node, &rx, link_id);
    // Before, an upgrade request sent on the channel was never proven by a
    // peer without a channel, and the link was torn down once its retries
    // ran out.
    let until = Instant::now() + Duration::from_secs(30);
    let mut n = 0;
    while Instant::now() < until {
        exchange(&format!("after the proposal {n}"));
        n += 1;
        std::thread::sleep(Duration::from_secs(2));
    }
    python.assert_healthy();
    node.shutdown();
}
