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
        app_flag: bool,
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

    fn on_resource_received_with_app_flag(
        &mut self,
        link_id: LinkId,
        data: Vec<u8>,
        _metadata: Option<Vec<u8>>,
        app_flag: bool,
    ) {
        let _ = self.tx.send(RustEvent::ResourceReceived {
            link_id: link_id.0,
            data,
            app_flag,
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

/// Rust and Python must agree on a stamp value. Python reports fractional
/// values since rgit `78fb90ea` and whole bits before it, so a whole Python
/// value is compared against the whole part only.
fn assert_python_value(rust: rns_core::stamp::StampValue, python: f64) {
    if python.fract() == 0.0 {
        assert_eq!(
            f64::from(rust.whole()),
            python,
            "Rust value {rust} and Python value {python} disagree on whole bits"
        );
    } else {
        assert_eq!(
            rust.as_f64(),
            python,
            "Rust and Python must agree on the fractional stamp value"
        );
    }
}

fn decrypt_delivery(raw: &[u8], identity: &Identity) -> Vec<u8> {
    let packet = RawPacket::unpack(raw).expect("Rust delivery should be a valid packet");
    identity
        .decrypt(packet.data())
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
    start_rust_node_with_store(port, tx, None)
}
fn start_rust_node_with_store(
    port: u16,
    tx: Sender<RustEvent>,
    ratchet_store: Option<std::sync::Arc<dyn rns_net::storage::RatchetStore>>,
) -> RnsNode {
    start_rust_node_with(port, tx, ratchet_store, None)
}

fn start_rust_node_with(
    port: u16,
    tx: Sender<RustEvent>,
    ratchet_store: Option<std::sync::Arc<dyn rns_net::storage::RatchetStore>>,
    cache_dir: Option<std::path::PathBuf>,
) -> RnsNode {
    RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            transport_enabled: false,
            static_transport_identity: false,
            local_hops_delta: false,
            identity: None,
            interfaces: vec![InterfaceConfig {
                stamp_costs: Default::default(),
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
            cache_dir,
            ratchet_store,
            ratchet_expiry: std::time::Duration::from_secs(rns_core::constants::RATCHET_EXPIRY),
            management: Default::default(),
            probe_port: None,
            probe_addrs: vec![],
            probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
            direct_connect_policy: Default::default(),
            direct_connect_allow_private_endpoints: false,
            device: None,
            underlay_mark: None,
            hooks: Vec::new(),
            discover_interfaces: false,
            autoconnect_interface_mode: None,
            autoconnect_interface_gravity: 0,
            autoconnect_announces_to_internal: false,
            autoconnect_unverified_implementations: false,
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
import inspect
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
  share_instance = no

# Upstream d7749b0b turned Transport.STAMP_LRS off by default and made it a
# config switch; the stamped link request tests need Python to grind one.
# a8cc6cb2 turned it back on and dropped the option, which it then ignores.
# Releases before d7749b0b have no [stamps] section at all.
[stamps]
  stamp_lrs = yes

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
        emit("python_resource_received", sha256=hashlib.sha256(data).hexdigest(), size=len(data), app_flag=getattr(resource, "app_flag", None))
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
    emit("python_link_established", link_id=link.link_id.hex(), stamp_cost=getattr(link, "stamp_cost", None))
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
            link_cost=RNS.Identity.recall_link_cost(destination_hash) if hasattr(RNS.Identity, "recall_link_cost") else None,
        )
        if not is_path_response:
            out = RNS.Destination(announced_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "interop", "rust")
            rust_destination = out
            RNS.Packet(out, b"python-to-rust via rust announce").send()
            emit("python_sent_packet_to_rust", dest_hash=destination_hash.hex())

RNS.Transport.register_announce_handler(RustAnnounceHandler())

python_inbound_link = None

def inbound_link_packet_callback(message, packet):
    emit("python_inbound_link_packet", data_hex=message.hex(), context=packet.context)

def inbound_link_established(link):
    global python_inbound_link
    python_inbound_link = link
    link.set_packet_callback(inbound_link_packet_callback)
    emit(
        "python_inbound_link_established",
        link_id=link.link_id.hex(),
        lr_stamp_value=getattr(link, "stamp_cost", None),
        stamp_status=getattr(link, "stamp_status", None),
        peer_pub_hex=link.peer_pub_bytes.hex(),
        peer_sig_pub_hex=link.peer_sig_pub_bytes.hex(),
    )
    RNS.Packet(link, b"python-to-rust over stamped link").send()

destination.set_link_established_callback(inbound_link_established)

emit("ready", port=port, python_dest_hash=destination.hash.hex(),
     link_cost_supported=hasattr(RNS.Identity, "recall_link_cost") and hasattr(RNS.Destination, "set_link_cost"),
     lr_cost_length=getattr(RNS.Identity, "LRCOSTLENGTH", None))

signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
try:
    for line in sys.stdin:
        command = line.strip()
        if command == "announce_py":
            destination.announce()
            emit("python_announced", dest_hash=destination.hash.hex())
        elif command == "ratchets_py":
            destination.enable_ratchets(os.path.join(config_dir, "local-ratchets"))
            destination.set_retained_ratchets(2)
            destination.set_ratchet_interval(1)
            destination.enforce_ratchets()
            emit("ratchets_enabled", version=RNS.__version__)
        elif command == "rotate_py":
            destination.latest_ratchet_time = 0
            destination.announce()
            emit("python_rotated")
        elif command == "export_ratchets":
            emit("ratchet_export", identity=identity.get_private_key().hex(), data=open(destination.ratchets_path, "rb").read().hex())
        elif command.startswith("decrypt_ratchet "):
            data = destination.decrypt(bytes.fromhex(command.split()[1]))
            emit("ratchet_decrypted", data_hex=None if data is None else data.hex())
        elif command.startswith("probe_rust "):
            public = bytes.fromhex(command.split()[1])
            encrypted = rust_destination.identity.encrypt(b"delayed-reference", ratchet=public)
            emit("ratchet_probe", ciphertext=encrypted.hex())
        elif command.startswith("import_ratchets "):
            _, private, packed, ciphertext = command.split()
            imported_identity = RNS.Identity(create_keys=False)
            imported_identity.load_private_key(bytes.fromhex(private))
            imported = RNS.Destination(imported_identity, RNS.Destination.IN, RNS.Destination.SINGLE, "interop", "rust")
            imported_path = os.path.join(config_dir, "imported-ratchets")
            with open(imported_path, "wb") as f: f.write(bytes.fromhex(packed))
            imported.enable_ratchets(imported_path)
            imported.enforce_ratchets()
            data = imported.decrypt(bytes.fromhex(ciphertext))
            emit("ratchet_imported", data_hex=None if data is None else data.hex())
        elif command.startswith("stamped_announce_py "):
            # Reticulum >= 1.6.0 development tip (ca6451a0): announce with a
            # destination stamp and a link request cost, so the Rust initiator
            # must stamp its link request.
            if not hasattr(RNS.Transport, "STAMP_DESTINATIONS") or not hasattr(destination, "set_link_cost"):
                emit("python_stamped_announce_unsupported", version=RNS.__version__)
            else:
                import time
                from RNS.Stamps import generate_stamp
                # Fractional since 796ef2d4; earlier releases apply int().
                link_cost = float(command.split()[1])
                # Grind to at least the value the Rust node requires: releases
                # before a8cc6cb2 target 23, below its 23.5 announce cost.
                stamp_target = max(RNS.Transport.DESTINATION_VALUE, int(command.split()[2]))
                RNS.Transport.STAMP_DESTINATIONS = True
                destination.set_link_cost(link_cost)
                started = time.time()
                stamp, value = generate_stamp(destination.stamp_material(), stamp_cost=stamp_target,
                                              expand_rounds=0, size=RNS.Identity.STAMPLENGTH)
                destination.stamp, destination.stamp_value = stamp, value
                destination.announce()
                emit("python_stamped_announce", dest_hash=destination.hash.hex(), stamp_value=value,
                     stamp_hex=stamp.hex(), link_cost=destination.get_link_cost(),
                     seconds=round(time.time() - started, 2), version=RNS.__version__)
        elif command == "always_stamp_lrs":
            # a8cc6cb2's Link.py fallback stamps link requests only with
            # ALWAYS_STAMP_LRS, even to destinations that announce a cost
            # (fixed in 34bb4ac8, where it is harmless). Earlier releases
            # have no such attribute and need none.
            if hasattr(RNS.Transport, "ALWAYS_STAMP_LRS"): RNS.Transport.ALWAYS_STAMP_LRS = True
            emit("python_always_stamp_lrs", supported=hasattr(RNS.Transport, "ALWAYS_STAMP_LRS"))
        elif command == "link_rust":
            if rust_destination is None:
                emit("python_link_error", reason="rust destination is unknown")
            else:
                rust_link = RNS.Link(rust_destination)
                rust_link.set_link_established_callback(link_established)
                rust_link.set_link_closed_callback(link_closed)
                emit("python_link_requested", link_id=rust_link.link_id.hex() if getattr(rust_link, "link_id", None) else None)
        elif command == "send_resource_rust":
            if rust_link is None:
                emit("python_resource_error", reason="link is unavailable")
            else:
                # Upstream added the application flag after 1.6.0 (c1472014).
                app_flag = "app_flag" in inspect.signature(RNS.Resource.__init__).parameters
                emit("python_resource_sending", app_flag=app_flag)
                kwargs = {"app_flag": True} if app_flag else {}
                RNS.Resource(bytes((i % 251 for i in range(100000))), rust_link, callback=resource_sent, auto_compress=False, **kwargs)
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
    futures::executor::block_on(node.send_packet(&python_out, RUST_TO_PYTHON_PAYLOAD))
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

    node.try_announce(&rust_dest, &rust_identity, Some(RUST_APP_DATA))
        .expect("Rust announce should be admitted")
        .wait()
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

    futures::executor::block_on(node.send_on_link(
        link_id,
        b"rust-to-python over link".to_vec(),
        0,
    ))
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
    let python_sending =
        python.wait_for_event(TIMEOUT, |event| event["event"] == "python_resource_sending");
    let python_sets_app_flag = python_sending["app_flag"] == true;
    let (python_resource, received_app_flag) =
        wait_for_rust_event(&rust_rx, TIMEOUT, |event| match event {
            RustEvent::ResourceReceived {
                link_id: received_link,
                data,
                app_flag,
            } if *received_link == link_id => Some((data.clone(), *app_flag)),
            _ => None,
        })
        .expect("Rust should receive a Python 100000-byte Resource");
    // Python sets the flag when its Resource supports it; older releases send
    // bit 6 clear.
    assert_eq!(received_app_flag, python_sets_app_flag);
    assert_eq!(python_resource.len(), 100000);
    assert!(python_resource
        .iter()
        .enumerate()
        .all(|(index, byte)| *byte == (index % 251) as u8));

    let rust_resource: Vec<u8> = (0..100000).map(|index| (index % 239) as u8).collect();
    node.send_resource_with_options(
        link_id,
        rust_resource.clone(),
        None,
        rns_net::resource::ResourceSendOptions {
            auto_compress: true,
            app_flag: true,
        },
    )
    .expect("Rust should send a Resource to Python");
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
    // Releases without the flag ignore bit 6 and have no attribute for it.
    if python_sets_app_flag {
        assert_eq!(python_received_resource["app_flag"], true);
    } else {
        assert!(python_received_resource["app_flag"].is_null());
    }

    node.shutdown();
}

/// Live check of upstream's link request stamps (`ba8c2d76`, `30c6428e`,
/// `ca6451a0`): Python announces with a destination stamp and a link request
/// cost, the Rust node records the cost, grinds a stamped link request on its
/// worker thread, and Python validates the stamp on the responder side.
///
/// Skips on Python RNS releases without stamp support; run with `PYTHONPATH`
/// at the exact target recorded in the active audit.
#[test]
fn python_rns_stamped_link_request_interop() {
    // Fractional since upstream 796ef2d4, on the 1/256 grid.
    const LINK_COST: f64 = 8.5;
    const STAMP_WAIT: Duration = Duration::from_secs(120);

    if !rns_available() {
        eprintln!("Skipping: Python RNS not available");
        return;
    }

    let mut python = PythonRns::spawn();
    let ready = python.wait_for_event(TIMEOUT, |event| event["event"] == "ready");
    // Releases before upstream 796ef2d4 end the stamp extension with a single
    // link cost byte, which neither side reads in the other's format.
    let legacy_extension = ready["lr_cost_length"] == 1;
    let port = ready["port"].as_u64().unwrap() as u16;
    let python_dest_hash = DestHash(parse_hex_16(ready["python_dest_hash"].as_str().unwrap()));

    let (rust_tx, rust_rx) = mpsc::channel();
    let node = start_rust_node(port, rust_tx);

    // Python stamps its destination and announces a link request cost.
    let required = rns_core::constants::DESTINATION_STAMP_COST;
    python.command(&format!(
        "stamped_announce_py {LINK_COST} {}",
        required.as_f64().ceil()
    ));
    let announced = python.wait_for_event(STAMP_WAIT, |event| {
        event["event"] == "python_stamped_announce"
            || event["event"] == "python_stamped_announce_unsupported"
    });
    if announced["event"] == "python_stamped_announce_unsupported" {
        eprintln!(
            "Skipping: Python RNS {} has no destination stamps",
            announced["version"]
        );
        return;
    }
    // A float since rgit 78fb90ea made stamp values fractional; earlier
    // releases report whole bits.
    let python_stamp_value = announced["stamp_value"].as_f64().unwrap();
    assert!(
        python_stamp_value >= required.as_f64(),
        "Python stamp value {python_stamp_value} must satisfy the Rust required cost"
    );
    eprintln!(
        "Python RNS {} stamped its destination with value {} in {} s",
        announced["version"], python_stamp_value, announced["seconds"]
    );

    if legacy_extension {
        // The one-byte extension is not recognised: the announce is accepted
        // as unstamped, with the 17 extension bytes left in the app data and
        // no link cost recorded.
        assert_eq!(announced["link_cost"], LINK_COST.trunc());
        let announce = wait_for_rust_event(&rust_rx, TIMEOUT, |event| match event {
            RustEvent::Announce(a) if a.dest_hash == python_dest_hash => Some(a.clone()),
            _ => None,
        })
        .expect("Rust should receive the stamped Python announce");
        let app_data = announce
            .app_data
            .expect("the extension stays in the app data");
        assert_eq!(app_data.len(), PYTHON_APP_DATA.len() + 17);
        assert!(app_data.starts_with(PYTHON_APP_DATA));
        assert_eq!(app_data[PYTHON_APP_DATA.len()], 0xC1);
        let known = node
            .known_destinations()
            .expect("known destinations query")
            .into_iter()
            .find(|entry| entry.dest_hash == python_dest_hash.0)
            .expect("Python destination should be a known destination");
        assert_eq!(known.lr_cost, None);
        eprintln!(
            "Python RNS {} uses the one-byte link cost extension; it reads as unstamped",
            announced["version"]
        );
        node.shutdown();
        return;
    }
    assert_eq!(announced["link_cost"], LINK_COST);

    // The Rust node validates the stamp, strips the extension payload from
    // the app data, and recalls the announced link request cost.
    let announce = wait_for_rust_event(&rust_rx, TIMEOUT, |event| match event {
        RustEvent::Announce(a) if a.dest_hash == python_dest_hash => Some(a.clone()),
        _ => None,
    })
    .expect("Rust should receive the stamped Python announce");
    assert_eq!(announce.hops, 1);
    assert_eq!(announce.app_data.as_deref(), Some(PYTHON_APP_DATA));
    let known = node
        .known_destinations()
        .expect("known destinations query")
        .into_iter()
        .find(|entry| entry.dest_hash == python_dest_hash.0)
        .expect("Python destination should be a known destination");
    assert_eq!(
        known.lr_cost,
        Some(rns_core::stamp::StampCost::from_f64(LINK_COST))
    );
    assert_python_value(known.stamp_value, python_stamp_value);
    assert_eq!(
        known.stamp.map(|stamp| hex(&stamp)),
        announced["stamp_hex"].as_str().map(str::to_owned)
    );

    // Rust initiates: the link request key is ground off the driver thread
    // and must carry at least the announced cost. Link request stamping is
    // on by default again since upstream a8cc6cb2; enable it explicitly so
    // the test does not depend on that default.
    match node.query(rns_net::event::QueryRequest::SetRuntimeConfig {
        key: "global.stamp_link_requests".into(),
        value: rns_net::event::RuntimeConfigValue::Bool(true),
    }) {
        Ok(rns_net::event::QueryResponse::RuntimeConfigSet(Ok(_))) => {}
        other => panic!("enabling link request stamps failed: {other:?}"),
    }
    let mut python_sig_pub = [0u8; 32];
    python_sig_pub.copy_from_slice(&announce.public_key[32..64]);
    let started = Instant::now();
    let link_id = node
        .create_link(python_dest_hash.0, python_sig_pub)
        .expect("stamped link request should be created before LINK_STAMP_TIMEOUT");
    eprintln!(
        "Rust stamped link request at cost {LINK_COST} took {:?}",
        started.elapsed()
    );

    let rust_link = wait_for_rust_event(&rust_rx, TIMEOUT, |event| match event {
        RustEvent::LinkEstablished {
            link_id,
            is_initiator,
        } => Some((*link_id, *is_initiator)),
        _ => None,
    })
    .expect("Rust initiator should establish the stamped link");
    assert_eq!(rust_link, (link_id, true));

    // Python accepted the request and computed its stamp value from the keys.
    let python_link = python.wait_for_event(TIMEOUT, |event| {
        event["event"] == "python_inbound_link_established"
    });
    assert_eq!(
        parse_hex_16(python_link["link_id"].as_str().unwrap()),
        link_id,
        "both sides must agree on the link id"
    );
    assert_eq!(python_link["stamp_status"], true);
    let python_lr_value = python_link["lr_stamp_value"]
        .as_f64()
        .expect("Python should compute the link request stamp value");
    assert!(
        python_lr_value >= LINK_COST,
        "Python saw link request stamp value {python_lr_value}, announced cost {LINK_COST}"
    );
    let mut request = decode_hex(python_link["peer_pub_hex"].as_str().unwrap());
    request.extend(decode_hex(
        python_link["peer_sig_pub_hex"].as_str().unwrap(),
    ));
    assert_python_value(
        rns_core::link::handshake::link_request_stamp_value(&python_dest_hash.0, &request)
            .expect("Rust should compute the link request stamp value"),
        python_lr_value,
    );

    // The stamped keys produce a working link in both directions.
    let python_link_data = wait_for_rust_event(&rust_rx, TIMEOUT, |event| match event {
        RustEvent::LinkData {
            link_id: received_link,
            context,
            data,
        } if *received_link == link_id => Some((*context, data.clone())),
        _ => None,
    })
    .expect("Rust should receive Python link data on the stamped link");
    assert_eq!(
        python_link_data,
        (0, b"python-to-rust over stamped link".to_vec())
    );
    futures::executor::block_on(node.send_on_link(
        link_id,
        b"rust-to-python over stamped link".to_vec(),
        0,
    ))
    .expect("Rust should send data over the stamped link");
    python.wait_for_event(TIMEOUT, |event| {
        event["event"] == "python_inbound_link_packet"
            && event["context"] == 0
            && event["data_hex"] == hex(b"rust-to-python over stamped link")
    });

    node.shutdown();
}

/// Reverse direction of the stamped link interop: the Rust destination sets a
/// per-destination link cost (`Destination.set_link_cost`), announces it in
/// the stamp extension, Python recalls it and grinds its link request to it,
/// and the Rust responder, enforcing link request stamps, accepts the link.
#[test]
fn python_rns_link_cost_announced_by_rust_interop() {
    // Fractional since upstream 796ef2d4, on the 1/256 grid.
    const LINK_COST: f64 = 9.25;
    const STAMP_WAIT: Duration = Duration::from_secs(120);

    if !rns_available() {
        eprintln!("Skipping: Python RNS not available");
        return;
    }

    let mut python = PythonRns::spawn();
    let ready = python.wait_for_event(TIMEOUT, |event| event["event"] == "ready");
    if ready["link_cost_supported"] != true {
        eprintln!("Skipping: Python RNS has no per-destination link cost");
        return;
    }
    if ready["lr_cost_length"] == 1 {
        // Before upstream 796ef2d4 Python reads a one-byte link cost, so it
        // sees neither the stamp nor the cost of a two-byte extension.
        eprintln!("Skipping: Python RNS uses the one-byte link cost extension");
        return;
    }
    let port = ready["port"].as_u64().unwrap() as u16;

    let cache_dir = tempfile::tempdir().unwrap();
    let (rust_tx, rust_rx) = mpsc::channel();
    let mut node = start_rust_node_with(port, rust_tx, None, Some(cache_dir.path().into()));
    node.set_destination_stamping(true, rns_net::stamper::StampTargets::default());
    node.set_link_request_stamps_enforced(true);

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
    assert_eq!(node.set_link_cost(rust_dest.hash.0, LINK_COST), LINK_COST);

    // Wait for the TCP client to come up before announcing.
    std::thread::sleep(Duration::from_secs(1));
    node.announce_queued(&rust_dest, &rust_identity, Some(RUST_APP_DATA))
        .expect("stamped Rust announce should be queued");
    let rust_announce = python.wait_for_event(STAMP_WAIT, |event| {
        event["event"] == "rust_announce"
            && event["dest_hash"] == hex(&rust_dest.hash.0)
            && event["is_path_response"] == false
    });
    // Python validated the stamp, stripped the extension and recorded the
    // announced cost.
    assert_eq!(
        decode_hex(rust_announce["app_data_hex"].as_str().unwrap()),
        RUST_APP_DATA
    );
    assert_eq!(rust_announce["link_cost"], LINK_COST);

    // Python initiates and grinds its link request to the announced cost;
    // the enforcing Rust responder accepts it.
    python.command("always_stamp_lrs");
    python.wait_for_event(TIMEOUT, |event| event["event"] == "python_always_stamp_lrs");
    python.command("link_rust");
    let requested = python.wait_for_event(TIMEOUT, |event| {
        event["event"] == "python_link_requested" || event["event"] == "python_link_error"
    });
    assert_eq!(requested["event"], "python_link_requested");
    let python_link = python.wait_for_event(STAMP_WAIT, |event| {
        event["event"] == "python_link_established"
    });
    assert_eq!(python_link["stamp_cost"], LINK_COST);
    let link_id = parse_hex_16(python_link["link_id"].as_str().unwrap());
    let rust_link = wait_for_rust_event(&rust_rx, STAMP_WAIT, |event| match event {
        RustEvent::LinkEstablished {
            link_id,
            is_initiator,
        } => Some((*link_id, *is_initiator)),
        _ => None,
    })
    .expect("the enforcing Rust responder should accept the stamped request");
    assert_eq!(rust_link, (link_id, false));

    node.shutdown();
}

/// Reticulum 1.4.2 truncates retained ratchets to the default count instead of
/// `retained_ratchets`, so it never retires the oldest key. This was fixed in
/// 1.5.0.
fn ratchet_retention_enforced(version: &str) -> bool {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|part| part.parse::<u32>().ok());
    let minor = parts.next().and_then(|part| part.parse::<u32>().ok());
    matches!((major, minor), (Some(major), Some(minor)) if (major, minor) >= (1, 5))
}

/// Run with PYTHONPATH pointing at the exact baseline recorded in UPSTREAM.md.
#[test]
fn python_rns_local_ratchets_bidirectional_and_restart() {
    use std::sync::Arc;
    if !rns_available() {
        eprintln!("Skipping: Python RNS not available");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let mut python = PythonRns::spawn();
    let ready = python.wait_for_event(TIMEOUT, |e| e["event"] == "ready");
    python.command("ratchets_py");
    let enabled = python.wait_for_event(TIMEOUT, |e| e["event"] == "ratchets_enabled");
    let reference_version = enabled["version"].as_str().unwrap_or_default();
    let retention_enforced = ratchet_retention_enforced(reference_version);
    eprintln!("local ratchet reference version: {reference_version}");
    let (tx, rx) = mpsc::channel();
    let node = start_rust_node_with_store(
        ready["port"].as_u64().unwrap() as u16,
        tx,
        Some(Arc::new(rns_net::storage::FsRatchetStore::new(
            directory.path().join("remote"),
        ))),
    );
    let python_hash = DestHash(parse_hex_16(ready["python_dest_hash"].as_str().unwrap()));
    let announced = request_python_announce(&mut python, &rx, python_hash, TIMEOUT);
    let out = Destination::single_out(APP_NAME, &[PYTHON_ASPECT], &announced);
    futures::executor::block_on(node.send_packet(&out, b"ratcheted Rust to Python")).unwrap();
    python.wait_for_event(TIMEOUT, |e| {
        e["event"] == "python_packet" && e["data_hex"] == hex(b"ratcheted Rust to Python")
    });

    let identity = Identity::from_private_key(&[77; 64]);
    let dest = Destination::single_in(APP_NAME, &[RUST_ASPECT], IdentityHash(*identity.hash()));
    let path = directory.path().join("rust-private");
    let owner =
        rns_net::LocalRatchets::persistent(&dest, Identity::from_private_key(&[77; 64]), &path)
            .unwrap();
    owner.set_retained(2).unwrap();
    owner.set_interval(1).unwrap();
    owner.enforce();
    node.attach_local_ratchets(owner.clone()).unwrap();
    node.register_destination(dest.hash.0, dest.dest_type.to_wire_constant())
        .unwrap();
    futures::executor::block_on(node.announce(&dest, &identity, Some(b"ratchets"))).unwrap();
    let (raw, _) = wait_for_rust_delivery(&rx, dest.hash, TIMEOUT);
    let packet = RawPacket::unpack(&raw).unwrap();
    assert!(
        identity.decrypt(packet.data()).is_err(),
        "Python must select announced ratchet"
    );
    assert_eq!(
        owner.decrypt(packet.data()).unwrap().plaintext,
        PYTHON_TO_RUST_PAYLOAD
    );
    let first = owner.current_public().unwrap();
    python.command(&format!("probe_rust {}", hex(&first)));
    let probe = python.wait_for_event(TIMEOUT, |e| e["event"] == "ratchet_probe");
    let delayed = decode_hex(probe["ciphertext"].as_str().unwrap());
    assert_eq!(
        owner.decrypt(&delayed).unwrap().plaintext,
        b"delayed-reference"
    );
    let now = rns_net::time::now() as u64;
    owner.public_for_announce(now + 2).unwrap();
    assert_eq!(
        owner.decrypt(&delayed).unwrap().plaintext,
        b"delayed-reference"
    );
    let legacy = identity.encrypt(b"legacy", &mut OsRng).unwrap();
    assert!(owner.decrypt(&legacy).is_err());

    // Restart with the persisted ring, before emitting another announcement.
    node.shutdown();
    drop(owner);
    let owner =
        rns_net::LocalRatchets::persistent(&dest, Identity::from_private_key(&[77; 64]), &path)
            .unwrap();
    owner.enforce();
    owner.set_retained(2).unwrap();
    assert_eq!(
        owner.decrypt(&delayed).unwrap().plaintext,
        b"delayed-reference"
    );
    // Python reads the Rust-written, signed private ring and decrypts its oldest key.
    python.command(&format!(
        "import_ratchets {} {} {}",
        hex(&[77; 64]),
        hex(&std::fs::read(&path).unwrap()),
        hex(&delayed)
    ));
    python.wait_for_event(TIMEOUT, |e| {
        e["event"] == "ratchet_imported" && e["data_hex"] == hex(b"delayed-reference")
    });
    owner.public_for_announce(now + 4).unwrap();
    assert!(
        owner.decrypt(&delayed).is_err(),
        "retired key must be rejected"
    );

    // Rust imports a Python-written ring; Python verifies Rust's ciphertext,
    // including enforcement and retention across two Python rotations.
    python.command("export_ratchets");
    let export = python.wait_for_event(TIMEOUT, |e| e["event"] == "ratchet_export");
    let key: [u8; 64] = decode_hex(export["identity"].as_str().unwrap())
        .try_into()
        .unwrap();
    let py_identity = Identity::from_private_key(&key);
    let py_dest = Destination::single_in(
        APP_NAME,
        &[PYTHON_ASPECT],
        IdentityHash(*py_identity.hash()),
    );
    let imported_path = directory.path().join("python-import");
    std::fs::write(&imported_path, decode_hex(export["data"].as_str().unwrap())).unwrap();
    let imported = rns_net::LocalRatchets::persistent(
        &py_dest,
        Identity::from_private_key(&key),
        &imported_path,
    )
    .unwrap();
    imported.enforce();
    let cipher = py_identity
        .encrypt_with_ratchet(
            b"cross-file",
            imported.current_public().as_ref(),
            &mut OsRng,
        )
        .unwrap();
    assert_eq!(imported.decrypt(&cipher).unwrap().plaintext, b"cross-file");
    for rotation in 0..3 {
        if rotation > 0 {
            python.command("rotate_py");
            python.wait_for_event(TIMEOUT, |e| e["event"] == "python_rotated");
        }
        python.command(&format!("decrypt_ratchet {}", hex(&cipher)));
        let decrypted = python.wait_for_event(TIMEOUT, |e| e["event"] == "ratchet_decrypted");
        if rotation < 2 || !retention_enforced {
            assert_eq!(decrypted["data_hex"], hex(b"cross-file"));
        } else {
            assert!(decrypted["data_hex"].is_null());
        }
    }
    python.command(&format!(
        "decrypt_ratchet {}",
        hex(&py_identity.encrypt(b"legacy", &mut OsRng).unwrap())
    ));
    assert!(
        python.wait_for_event(TIMEOUT, |e| e["event"] == "ratchet_decrypted")["data_hex"].is_null()
    );
}
