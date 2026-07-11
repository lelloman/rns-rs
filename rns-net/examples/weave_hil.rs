//! Opt-in Weave hardware-in-the-loop acceptance runner.
//!
//! Usage: `cargo run -p rns-net --example weave_hil -- /dev/ttyUSB0 [timeout-seconds]`

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rns_crypto::identity::Identity;
use rns_crypto::OsRng;
use rns_net::interface::weave::{WeaveConfig, WeaveState};
use rns_net::{
    AnnouncedIdentity, Callbacks, DestHash, Destination, IdentityHash, InterfaceConfig,
    InterfaceId, NodeConfig, PacketHash, QueryRequest, QueryResponse, RnsNode, MODE_FULL,
};

struct HilCallbacks;
impl Callbacks for HilCallbacks {
    fn on_announce(&mut self, _: AnnouncedIdentity) {}
    fn on_path_updated(&mut self, _: DestHash, _: u8) {}
    fn on_local_delivery(&mut self, _: DestHash, _: Vec<u8>, _: PacketHash) {}
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let port = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("WEAVE_SERIAL_PORT").ok())
        .ok_or("provide a serial port or WEAVE_SERIAL_PORT")?;
    let timeout = std::env::args()
        .nth(2)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(90);

    let state = Arc::new(Mutex::new(WeaveState::default()));
    let interface_id = InterfaceId(1);
    let mut config = NodeConfig::default();
    config.interfaces.push(InterfaceConfig {
        name: "Weave HIL".into(),
        type_name: "WeaveInterface".into(),
        config_data: Box::new(WeaveConfig {
            name: "Weave HIL".into(),
            port,
            configured_bitrate: 250_000,
            interface_id,
            state: Arc::clone(&state),
        }),
        mode: MODE_FULL,
        recursive_prs: false,
        announces_from_internal: true,
        ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
        ifac: None,
        discovery: None,
    });
    let node = RnsNode::start(config, Box::new(HilCallbacks))?;

    let identity = Identity::new(&mut OsRng);
    let destination =
        Destination::single_in("weave_hil", &["acceptance"], IdentityHash(*identity.hash()));
    node.register_destination_with_proof(&destination, identity.get_private_key())?;

    let deadline = Instant::now() + Duration::from_secs(timeout);
    let mut announced = false;
    loop {
        if Instant::now() >= deadline {
            return Err(
                "Weave HIL timed out before bidirectional peer traffic was observed".into(),
            );
        }
        let QueryResponse::InterfaceStats(stats) = node.query(QueryRequest::InterfaceStats)? else {
            return Err("unexpected interface statistics response".into());
        };
        let parent = stats
            .interfaces
            .iter()
            .find(|entry| entry.id == interface_id.0);
        let peers: Vec<_> = stats
            .interfaces
            .iter()
            .filter(|entry| entry.interface_type == "WeaveInterfacePeer")
            .collect();

        if let Some(parent) = parent {
            eprintln!(
                "switch={:?} endpoint={:?} cpu={:?}% memory={:?}% peers={:?}",
                parent.switch_id,
                parent.endpoint_id,
                parent.cpu_load,
                parent.mem_load,
                parent.peers
            );
            if parent.status && !peers.is_empty() && !announced {
                node.announce(&destination, &identity, Some(b"rns-rs Weave HIL"))?;
                announced = true;
            }
        }

        if announced
            && peers
                .iter()
                .any(|peer| peer.rx_packets > 0 && peer.tx_packets > 0)
        {
            eprintln!("Weave HIL PASS: authenticated session and bidirectional endpoint traffic");
            node.shutdown();
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}
