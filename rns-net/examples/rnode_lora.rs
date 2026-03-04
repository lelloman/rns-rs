//! Connect to an RNode device over USB serial and log received LoRa traffic.
//!
//! Usage: cargo run --example rnode_lora -- [serial_port] [frequency_mhz]
//! Default: /dev/ttyUSB0, 868 MHz

use std::env;
use std::sync::mpsc;

use rns_net::{
    Callbacks, InterfaceConfig, InterfaceId, NodeConfig, RNodeConfig,
    RNodeSubConfig, RnsNode, MODE_FULL,
};

struct LoggingCallbacks;

impl Callbacks for LoggingCallbacks {
    fn on_announce(&mut self, announced: rns_net::AnnouncedIdentity) {
        let app_str = announced
            .app_data
            .as_ref()
            .and_then(|d| std::str::from_utf8(d).ok())
            .unwrap_or("<none>");
        log::info!(
            "Announce: dest={} identity={} hops={} app_data={}",
            announced.dest_hash,
            announced.identity_hash,
            announced.hops,
            app_str
        );
    }

    fn on_path_updated(&mut self, dest_hash: rns_net::DestHash, hops: u8) {
        log::info!("Path updated: dest={} hops={}", dest_hash, hops);
    }

    fn on_local_delivery(
        &mut self,
        dest_hash: rns_net::DestHash,
        _raw: Vec<u8>,
        _packet_hash: rns_net::PacketHash,
    ) {
        log::info!("Local delivery: dest={}", dest_hash);
    }
}

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    let port = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "/dev/ttyUSB0".into());
    let freq_mhz: f64 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(868.0);
    let frequency = (freq_mhz * 1_000_000.0) as u32;

    log::info!("Connecting to RNode on {} at {} MHz", port, freq_mhz);

    let node = RnsNode::start(
        NodeConfig {
            transport_enabled: false,
            identity: None,
            interfaces: vec![InterfaceConfig {
                type_name: "RNodeInterface".to_string(),
                config_data: Box::new(RNodeConfig {
                    name: format!("RNode {}", port),
                    port: port.clone(),
                    speed: 115200,
                    base_interface_id: InterfaceId(1),
                    subinterfaces: vec![RNodeSubConfig {
                        name: "LoRa".into(),
                        frequency,
                        bandwidth: 125000,
                        txpower: 14,
                        spreading_factor: 8,
                        coding_rate: 5,
                        flow_control: false,
                        st_alock: None,
                        lt_alock: None,
                    }],
                    id_interval: None,
                    id_callsign: None,
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
            registry: None,
        },
        Box::new(LoggingCallbacks),
    )
    .expect("Failed to start node");

    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    ctrlc::set_handler(move || {
        let _ = stop_tx.send(());
    })
    .expect("Failed to set Ctrl+C handler");

    log::info!("Running. Press Ctrl+C to stop.");
    let _ = stop_rx.recv();

    log::info!("Shutting down...");
    node.shutdown();
}
