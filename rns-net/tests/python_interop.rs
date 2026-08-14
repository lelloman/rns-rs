//! Live compatibility tests between rns-rs and the Python Reticulum implementation.
//!
//! These tests spawn a real Python RNS instance with a TCPServerInterface and
//! connect a Rust RnsNode to it over a real TCP interface. They are skipped only
//! when Python RNS is not importable in the current environment.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use rns_core::packet::RawPacket;
use rns_core::types::{DestHash, IdentityHash, LinkId, PacketHash};
use rns_crypto::identity::Identity;
use rns_crypto::OsRng;
use rns_net::{
    AnnouncedIdentity, Callbacks, Destination, InterfaceConfig, NodeConfig, RnsNode,
    TcpClientConfig, MODE_FULL,
};

const KNOWN_DESTINATIONS_TTL: Duration = Duration::from_secs(48 * 60 * 60);

const APP_NAME: &str = "interop";
const PYTHON_ASPECT: &str = "python";
const RUST_ASPECT: &str = "rust";
const PYTHON_APP_DATA: &[u8] = b"python-appdata";
const RUST_APP_DATA: &[u8] = b"rust-appdata";
const RUST_TO_PYTHON_PAYLOAD: &[u8] = b"rust-to-python via python announce";
const PYTHON_TO_RUST_PAYLOAD: &[u8] = b"python-to-rust via rust announce";
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
enum RustEvent {
    Announce(AnnouncedIdentity),
    Delivery {
        dest_hash: DestHash,
        raw: Vec<u8>,
        packet_hash: PacketHash,
    },
    LinkEstablished {
        link_id: [u8; 16],
        is_initiator: bool,
    },
    LinkData {
        link_id: [u8; 16],
        context: u8,
        data: Vec<u8>,
    },
    ResourceReceived {
        link_id: [u8; 16],
        data: Vec<u8>,
    },
    ResourceCompleted {
        link_id: [u8; 16],
    },
}

struct TestCallbacks {
    tx: Sender<RustEvent>,
}

impl Callbacks for TestCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        let _ = self.tx.send(RustEvent::Announce(announced));
    }

    fn on_path_updated(&mut self, _: DestHash, _: u8) {}
    fn on_local_delivery(&mut self, dest_hash: DestHash, raw: Vec<u8>, packet_hash: PacketHash) {
        let _ = self.tx.send(RustEvent::Delivery {
            dest_hash,
            raw,
            packet_hash,
        });
    }

    fn on_link_established(
        &mut self,
        link_id: LinkId,
        _dest_hash: DestHash,
        _rtt: f64,
        is_initiator: bool,
    ) {
        let _ = self.tx.send(RustEvent::LinkEstablished {
            link_id: link_id.0,
            is_initiator,
        });
    }

    fn on_link_data(&mut self, link_id: LinkId, context: u8, data: Vec<u8>) {
        let _ = self.tx.send(RustEvent::LinkData {
            link_id: link_id.0,
            context,
            data,
        });
    }

    fn on_resource_received(&mut self, link_id: LinkId, data: Vec<u8>, _metadata: Option<Vec<u8>>) {
        let _ = self.tx.send(RustEvent::ResourceReceived {
            link_id: link_id.0,
            data,
        });
    }

    fn on_resource_completed(&mut self, link_id: LinkId) {
        let _ = self
            .tx
            .send(RustEvent::ResourceCompleted { link_id: link_id.0 });
    }
}

/// Check if Python with RNS is available.
fn rns_available() -> bool {
    Command::new("python3")
        .args(["-c", "import RNS; print('ok')"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn parse_hex_16(s: &str) -> [u8; 16] {
    assert_eq!(s.len(), 32, "expected 16-byte hex string");
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn assert_nonzero_hex_hash(s: &str, bytes: usize) {
    assert_eq!(s.len(), bytes * 2, "unexpected hash hex length");
    assert!(
        decode_hex(s).iter().any(|b| *b != 0),
        "hash should not be all zeroes"
    );
}

fn decode_hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "hex string must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn decrypt_delivery(raw: &[u8], identity: &Identity) -> Vec<u8> {
    let packet = RawPacket::unpack(raw).expect("Rust delivery should be a valid packet");
    identity
        .decrypt(&packet.data)
        .expect("Rust should decrypt Python packet")
}

fn request_python_announce(
    python: &mut PythonRns,
    rust_rx: &Receiver<RustEvent>,
    expected_hash: DestHash,
    timeout: Duration,
) -> AnnouncedIdentity {
    let expected_hash_hex = hex(&expected_hash.0);
    let deadline = Instant::now() + timeout;
    loop {
        python.command("announce_py");
        python
            .try_wait_for_event(Duration::from_secs(2), |event| {
                event["event"] == "python_announced" && event["dest_hash"] == expected_hash_hex
            })
            .expect("Python should acknowledge announce command");

        if let Some(announce) =
            wait_for_rust_event(rust_rx, Duration::from_secs(2), |event| match event {
                RustEvent::Announce(a) if a.dest_hash == expected_hash => Some(a.clone()),
                _ => None,
            })
        {
            return announce;
        }

        if Instant::now() >= deadline {
            panic!("timed out waiting for Rust to receive Python announce");
        }
    }
}

fn wait_for_rust_delivery(
    rx: &Receiver<RustEvent>,
    expected_hash: DestHash,
    timeout: Duration,
) -> (Vec<u8>, PacketHash) {
    wait_for_rust_event(rx, timeout, |event| match event {
        RustEvent::Delivery {
            dest_hash,
            raw,
            packet_hash,
        } if *dest_hash == expected_hash => Some((raw.clone(), *packet_hash)),
        _ => None,
    })
    .expect("timed out waiting for Rust local delivery callback")
}

fn wait_for_rust_event<F, T>(
    rx: &Receiver<RustEvent>,
    timeout: Duration,
    mut predicate: F,
) -> Option<T>
where
    F: FnMut(&RustEvent) -> Option<T>,
{
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.checked_duration_since(Instant::now())?;
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

struct PythonRns {
    child: Child,
    events: Receiver<serde_json::Value>,
}

impl PythonRns {
    fn spawn() -> Self {
        let mut child = Command::new("python3")
            .args(["-c", PYTHON_INTEROP_SCRIPT])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to start Python RNS process");

        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (events_tx, events_rx) = mpsc::channel();

        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                match serde_json::from_str::<serde_json::Value>(&line) {
                    Ok(value) => {
                        let _ = events_tx.send(value);
                    }
                    Err(_) => eprintln!("python stdout: {}", line),
                }
            }
        });

        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                eprintln!("python stderr: {}", line);
            }
        });

        Self {
            child,
            events: events_rx,
        }
    }

    fn command(&mut self, command: &str) {
        let stdin = self
            .child
            .stdin
            .as_mut()
            .expect("Python process stdin should be available");
        writeln!(stdin, "{command}").expect("failed to write command to Python process");
        stdin.flush().expect("failed to flush Python process stdin");
    }

    fn wait_for_event<F>(&self, timeout: Duration, mut predicate: F) -> serde_json::Value
    where
        F: FnMut(&serde_json::Value) -> bool,
    {
        self.try_wait_for_event(timeout, |event| predicate(event))
            .expect("timed out waiting for Python event")
    }

    fn try_wait_for_event<F>(
        &self,
        timeout: Duration,
        mut predicate: F,
    ) -> Option<serde_json::Value>
    where
        F: FnMut(&serde_json::Value) -> bool,
    {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.checked_duration_since(Instant::now())?;
            let event = self.events.recv_timeout(remaining).ok()?;
            if predicate(&event) {
                return Some(event);
            }
        }
    }
}

impl Drop for PythonRns {
    fn drop(&mut self) {
        if let Some(stdin) = self.child.stdin.as_mut() {
            let _ = writeln!(stdin, "stop");
            let _ = stdin.flush();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_rust_node(port: u16, tx: Sender<RustEvent>) -> RnsNode {
    RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            transport_enabled: false,
            static_transport_identity: false,
            local_hops_delta: false,
            identity: None,
            interfaces: vec![InterfaceConfig {
                name: String::new(),
                type_name: "TCPClientInterface".to_string(),
                config_data: Box::new(TcpClientConfig {
                    name: "interop-tcp".into(),
                    target_host: "127.0.0.1".into(),
                    target_port: port,
                    reconnect_wait: Duration::from_millis(500),
                    max_reconnect_tries: Some(3),
                    connect_timeout: Duration::from_secs(5),
                    ..Default::default()
                }),
                mode: MODE_FULL,
                gravity: 0,
                recursive_prs: false,
                announces_from_internal: true,
                announces_to_internal: None,
                ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
                ifac: None,
                discovery: None,
            }],
            share_instance: false,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            rpc_port: 0,
            cache_dir: None,
            ratchet_store: None,
            ratchet_expiry: std::time::Duration::from_secs(rns_core::constants::RATCHET_EXPIRY),
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            direct_connect_policy: Default::default(),
            device: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            autoconnect_interface_mode: None,
            autoconnect_interface_gravity: 0,
            autoconnect_announces_to_internal: false,
            discovery_required_value: None,
            respond_to_probes: false,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: KNOWN_DESTINATIONS_TTL,
            known_destinations_max_entries: 8192,
            announce_table_ttl: std::time::Duration::from_secs(
                rns_core::constants::ANNOUNCE_TABLE_TTL as u64,
            ),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: rns_net::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity:
                rns_net::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_rate_defaults: rns_net::AnnounceRateDefaults::default(),
            ingress_control_defaults: rns_core::transport::types::IngressControlConfig::enabled(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool: None,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: std::time::Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "hooks")]
            provider_bridge: None,
        },
        Box::new(TestCallbacks { tx }),
    )
    .expect("failed to start Rust node")
}

const PYTHON_INTEROP_SCRIPT: &str = r#"
import json
import hashlib
import os
import signal
import socket
import sys
import tempfile

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('127.0.0.1', 0))
port = sock.getsockname()[1]
sock.close()

config_dir = tempfile.mkdtemp()
config_path = os.path.join(config_dir, "config")
with open(config_path, "w") as f:
    f.write(f"""[reticulum]
  enable_transport = false
  share_instance = yes

[interfaces]
  [[TCP Server Interface]]
    type = TCPServerInterface
    interface_enabled = true
    listen_ip = 127.0.0.1
    listen_port = {port}
""")

import RNS

def emit(event, **fields):
    fields["event"] = event
    print(json.dumps(fields), flush=True)

reticulum = RNS.Reticulum(configdir=config_dir)
identity = RNS.Identity()
destination = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "interop", "python")
destination.set_default_app_data(b"python-appdata")

def packet_callback(data, packet):
    emit("python_packet", data_hex=data.hex(), packet_hash=packet.packet_hash.hex())

destination.set_packet_callback(packet_callback)

rust_destination = None
rust_link = None

def link_packet_callback(message, packet):
    emit("python_link_packet", data_hex=message.hex(), context=packet.context)

def resource_concluded(resource):
    if resource.status == RNS.Resource.COMPLETE:
        resource.data.seek(0)
        data = resource.data.read()
        emit("python_resource_received", sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    else:
        emit("python_resource_failed", status=resource.status)

def resource_sent(resource):
    emit("python_resource_sent", status=resource.status)

def link_established(link):
    global rust_link
    rust_link = link
    link.set_packet_callback(link_packet_callback)
    link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
    link.set_resource_concluded_callback(resource_concluded)
    emit("python_link_established", link_id=link.link_id.hex())
    RNS.Packet(link, b"python-to-rust over link").send()

def link_closed(link):
    emit("python_link_closed", link_id=link.link_id.hex(), status=link.status)

class RustAnnounceHandler:
    aspect_filter = "interop.rust"
    receive_path_responses = True

    def received_announce(self, destination_hash, announced_identity, app_data, announce_packet_hash, is_path_response):
        global rust_destination
        emit(
            "rust_announce",
            dest_hash=destination_hash.hex(),
            app_data_hex=app_data.hex() if app_data is not None else None,
            announce_packet_hash=announce_packet_hash.hex(),
            is_path_response=bool(is_path_response),
        )
        if not is_path_response:
            out = RNS.Destination(announced_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "interop", "rust")
            rust_destination = out
            RNS.Packet(out, b"python-to-rust via rust announce").send()
            emit("python_sent_packet_to_rust", dest_hash=destination_hash.hex())

RNS.Transport.register_announce_handler(RustAnnounceHandler())

emit("ready", port=port, python_dest_hash=destination.hash.hex())

signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
try:
    for line in sys.stdin:
        command = line.strip()
        if command == "announce_py":
            destination.announce()
            emit("python_announced", dest_hash=destination.hash.hex())
        elif command == "link_rust":
            if rust_destination is None:
                emit("python_link_error", reason="rust destination is unknown")
            else:
                rust_link = RNS.Link(rust_destination)
                rust_link.set_link_established_callback(link_established)
                rust_link.set_link_closed_callback(link_closed)
                emit("python_link_requested", link_id=rust_link.link_id.hex())
        elif command == "send_resource_rust":
            if rust_link is None:
                emit("python_resource_error", reason="link is unavailable")
            else:
                RNS.Resource(bytes((i % 251 for i in range(100000))), rust_link, callback=resource_sent, auto_compress=False)
        elif command == "stop":
            break
        elif command:
            emit("unknown_command", command=command)
except (KeyboardInterrupt, SystemExit):
    pass
"#;

#[test]
fn python_rns_bidirectional_tcp_interop() {
    if !rns_available() {
        eprintln!("Skipping: Python RNS not available");
        return;
    }

    let mut python = PythonRns::spawn();
    let ready = python.wait_for_event(TIMEOUT, |event| event["event"] == "ready");
    let port = ready["port"].as_u64().unwrap() as u16;
    let python_dest_hash_hex = ready["python_dest_hash"].as_str().unwrap();
    let python_dest_hash = DestHash(parse_hex_16(python_dest_hash_hex));

    eprintln!(
        "Python RNS server on port {}, destination {}",
        port, python_dest_hash_hex
    );

    let (rust_tx, rust_rx) = mpsc::channel();
    let node = start_rust_node(port, rust_tx);

    let rust_identity = Identity::new(&mut OsRng);
    let rust_dest = Destination::single_in(
        APP_NAME,
        &[RUST_ASPECT],
        IdentityHash(*rust_identity.hash()),
    );
    node.register_destination(rust_dest.hash.0, rust_dest.dest_type.to_wire_constant())
        .expect("Rust destination registration should succeed");
    let rust_private = rust_identity.get_private_key().unwrap();
    let rust_public = rust_identity.get_public_key().unwrap();
    let mut rust_sig_private = [0u8; 32];
    let mut rust_sig_public = [0u8; 32];
    rust_sig_private.copy_from_slice(&rust_private[32..64]);
    rust_sig_public.copy_from_slice(&rust_public[32..64]);
    node.register_link_destination(rust_dest.hash.0, rust_sig_private, rust_sig_public, 1)
        .expect("Rust link destination registration should succeed");

    let python_live_announce =
        request_python_announce(&mut python, &rust_rx, python_dest_hash, TIMEOUT);
    assert_eq!(python_live_announce.hops, 1);
    assert!(python_live_announce.public_key.iter().any(|b| *b != 0));
    assert_eq!(
        python_live_announce.app_data.as_deref(),
        Some(PYTHON_APP_DATA)
    );

    let python_out = Destination::single_out(APP_NAME, &[PYTHON_ASPECT], &python_live_announce);
    node.send_packet(&python_out, RUST_TO_PYTHON_PAYLOAD)
        .expect("Rust should send encrypted data to Python destination");
    let python_packet = python.wait_for_event(TIMEOUT, |event| {
        event["event"] == "python_packet" && event["data_hex"] == hex(RUST_TO_PYTHON_PAYLOAD)
    });
    assert_eq!(
        decode_hex(python_packet["data_hex"].as_str().unwrap()),
        RUST_TO_PYTHON_PAYLOAD
    );
    assert_nonzero_hex_hash(python_packet["packet_hash"].as_str().unwrap(), 32);

    let python_reannounce =
        request_python_announce(&mut python, &rust_rx, python_dest_hash, TIMEOUT);
    assert_eq!(python_reannounce.hops, 1);
    assert_eq!(
        python_reannounce.identity_hash,
        python_live_announce.identity_hash
    );
    assert_eq!(
        python_reannounce.public_key,
        python_live_announce.public_key
    );
    assert_eq!(python_reannounce.app_data.as_deref(), Some(PYTHON_APP_DATA));

    node.announce(&rust_dest, &rust_identity, Some(RUST_APP_DATA))
        .expect("Rust announce should send to Python");
    let rust_announce = python.wait_for_event(TIMEOUT, |event| {
        event["event"] == "rust_announce"
            && event["dest_hash"] == hex(&rust_dest.hash.0)
            && event["app_data_hex"] == hex(RUST_APP_DATA)
            && event["is_path_response"] == false
    });
    assert_eq!(rust_announce["dest_hash"], hex(&rust_dest.hash.0));
    assert_eq!(
        decode_hex(rust_announce["app_data_hex"].as_str().unwrap()),
        RUST_APP_DATA
    );
    assert_nonzero_hex_hash(rust_announce["announce_packet_hash"].as_str().unwrap(), 32);

    python.wait_for_event(TIMEOUT, |event| {
        event["event"] == "python_sent_packet_to_rust"
            && event["dest_hash"] == hex(&rust_dest.hash.0)
    });

    let (raw, packet_hash) = wait_for_rust_delivery(&rust_rx, rust_dest.hash, TIMEOUT);
    assert_ne!(packet_hash.0, [0u8; 32]);
    let plaintext = decrypt_delivery(&raw, &rust_identity);
    assert_eq!(plaintext, PYTHON_TO_RUST_PAYLOAD);

    python.command("link_rust");
    let python_link =
        python.wait_for_event(TIMEOUT, |event| event["event"] == "python_link_established");
    let link_id = parse_hex_16(python_link["link_id"].as_str().unwrap());
    let rust_link = wait_for_rust_event(&rust_rx, TIMEOUT, |event| match event {
        RustEvent::LinkEstablished {
            link_id,
            is_initiator,
        } => Some((*link_id, *is_initiator)),
        _ => None,
    })
    .expect("Rust responder should establish the Python-initiated link");
    assert_eq!(rust_link, (link_id, false));

    let python_link_data = wait_for_rust_event(&rust_rx, TIMEOUT, |event| match event {
        RustEvent::LinkData {
            link_id: received_link,
            context,
            data,
        } if *received_link == link_id => Some((*context, data.clone())),
        _ => None,
    })
    .expect("Rust should receive Python link data");
    assert_eq!(python_link_data, (0, b"python-to-rust over link".to_vec()));

    node.send_on_link(link_id, b"rust-to-python over link".to_vec(), 0)
        .expect("Rust should send data over the Python-initiated link");
    let rust_link_data = python.wait_for_event(TIMEOUT, |event| {
        event["event"] == "python_link_packet"
            && event["context"] == 0
            && event["data_hex"] == hex(b"rust-to-python over link")
    });
    assert_eq!(
        decode_hex(rust_link_data["data_hex"].as_str().unwrap()),
        b"rust-to-python over link"
    );

    python.command("send_resource_rust");
    let python_resource = wait_for_rust_event(&rust_rx, TIMEOUT, |event| match event {
        RustEvent::ResourceReceived {
            link_id: received_link,
            data,
        } if *received_link == link_id => Some(data.clone()),
        _ => None,
    })
    .expect("Rust should receive a Python 100000-byte Resource");
    assert_eq!(python_resource.len(), 100000);
    assert!(python_resource
        .iter()
        .enumerate()
        .all(|(index, byte)| *byte == (index % 251) as u8));

    let rust_resource: Vec<u8> = (0..100000).map(|index| (index % 239) as u8).collect();
    node.send_resource(link_id, rust_resource.clone(), None)
        .expect("Rust should send a Resource to Python 1.3.5");
    wait_for_rust_event(&rust_rx, TIMEOUT, |event| match event {
        RustEvent::ResourceCompleted {
            link_id: completed_link,
        } if *completed_link == link_id => Some(()),
        _ => None,
    })
    .expect("Rust should receive proof for its 100000-byte Resource");
    let python_received_resource = python.wait_for_event(TIMEOUT, |event| {
        event["event"] == "python_resource_received" && event["size"] == 100000
    });
    assert_eq!(
        python_received_resource["sha256"],
        hex(&rns_core::hash::full_hash(&rust_resource))
    );

    node.shutdown();
}
