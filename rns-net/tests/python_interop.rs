//! Integration test: Rust node connects to Python RNS TCP server.
//!
//! Starts a Python RNS instance with TCPServerInterface, creates a
//! destination, announces it, and verifies the Rust node receives the announce.
//!
//! Requires Python 3 with RNS installed (run from repo root).
//! Skipped if Python or RNS is not available.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use rns_net::{Callbacks, InterfaceConfig, InterfaceId, InterfaceVariant, NodeConfig, RnsNode, TcpClientConfig, MODE_FULL};
use rns_net::{DestHash, PacketHash, AnnouncedIdentity};

struct TestCallbacks {
    announce_tx: Sender<(DestHash, u8)>,
}

impl Callbacks for TestCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        let _ = self.announce_tx.send((announced.dest_hash, announced.hops));
    }

    fn on_path_updated(&mut self, _: DestHash, _: u8) {}
    fn on_local_delivery(&mut self, _: DestHash, _: Vec<u8>, _: PacketHash) {}
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

#[test]
fn python_announce_received() {
    if !rns_available() {
        eprintln!("Skipping: Python RNS not available");
        return;
    }

    // Python script that:
    // 1. Starts RNS with TCPServerInterface on a random port
    // 2. Prints the port and destination hash
    // 3. Announces the destination
    // 4. Waits for SIGTERM
    let python_script = r#"
import sys, os, time, signal, json, tempfile, socket

# Find a free port
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('127.0.0.1', 0))
port = sock.getsockname()[1]
sock.close()

# Write config
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
reticulum = RNS.Reticulum(configdir=config_dir)
identity = RNS.Identity()
destination = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "interop", "test")

dest_hash = destination.hash.hex()
print(json.dumps({"port": port, "dest_hash": dest_hash}), flush=True)

# Wait for Rust node to connect before announcing
sys.stdin.readline()
time.sleep(0.5)
destination.announce()

# Wait for signal
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
try:
    while True:
        time.sleep(1)
except (KeyboardInterrupt, SystemExit):
    pass
"#;

    // Start Python process
    let mut child = Command::new("python3")
        .args(["-c", python_script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start Python");

    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    // Read the port and dest_hash from Python
    let mut line = String::new();
    reader.read_line(&mut line).expect("Failed to read from Python");
    let info: serde_json::Value = serde_json::from_str(line.trim()).expect("Failed to parse JSON");
    let port = info["port"].as_u64().unwrap() as u16;
    let expected_dest_hash_hex = info["dest_hash"].as_str().unwrap().to_string();

    eprintln!("Python server on port {}, dest_hash={}", port, expected_dest_hash_hex);

    // Start Rust node (before triggering announce)
    let (announce_tx, announce_rx): (Sender<(DestHash, u8)>, Receiver<(DestHash, u8)>) =
        mpsc::channel();

    let node = RnsNode::start(
        NodeConfig {
            transport_enabled: false,
            identity: None,
            interfaces: vec![InterfaceConfig {
                variant: InterfaceVariant::TcpClient(TcpClientConfig {
                    name: "interop-tcp".into(),
                    target_host: "127.0.0.1".into(),
                    target_port: port,
                    interface_id: InterfaceId(1),
                    reconnect_wait: Duration::from_millis(500),
                    max_reconnect_tries: Some(3),
                    connect_timeout: Duration::from_secs(5),
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
        Box::new(TestCallbacks { announce_tx }),
    )
    .expect("Failed to start Rust node");

    // Give Rust node time to connect, then signal Python to announce
    std::thread::sleep(Duration::from_secs(2));
    if let Some(ref mut stdin) = child.stdin {
        let _ = writeln!(stdin, "go");
    }

    // Wait for announce
    let result = announce_rx.recv_timeout(Duration::from_secs(10));

    // Cleanup
    node.shutdown();
    let _ = child.kill();
    let _ = child.wait();

    match result {
        Ok((dest_hash, hops)) => {
            let received_hex: String = dest_hash.0.iter().map(|b| format!("{:02x}", b)).collect();
            eprintln!("Received announce: dest={} hops={}", received_hex, hops);
            assert_eq!(received_hex, expected_dest_hash_hex);
        }
        Err(_) => {
            // Read stderr for debugging
            panic!("Timed out waiting for announce from Python");
        }
    }
}
