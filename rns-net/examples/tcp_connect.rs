//! Connect to a Python RNS TCP server and log received announces.
//!
//! Usage: cargo run --example tcp_connect -- [host] [port]
//! Default: 127.0.0.1:4242

use std::env;
use std::sync::mpsc;

use rns_net::{Callbacks, InterfaceConfig, InterfaceId, InterfaceVariant, NodeConfig, RnsNode, TcpClientConfig, MODE_FULL};

struct LoggingCallbacks;

impl Callbacks for LoggingCallbacks {
    fn on_announce(&mut self, announced: rns_net::AnnouncedIdentity) {
        let app_str = announced.app_data
            .as_ref()
            .and_then(|d| std::str::from_utf8(d).ok())
            .unwrap_or("<none>");
        log::info!(
            "Announce: dest={} identity={} hops={} app_data={}",
            announced.dest_hash, announced.identity_hash, announced.hops, app_str
        );
    }

    fn on_path_updated(&mut self, dest_hash: rns_net::DestHash, hops: u8) {
        log::info!("Path updated: dest={} hops={}", dest_hash, hops);
    }

    fn on_local_delivery(&mut self, dest_hash: rns_net::DestHash, _raw: Vec<u8>, _packet_hash: rns_net::PacketHash) {
        log::info!("Local delivery: dest={}", dest_hash);
    }
}

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    let host = args.get(1).cloned().unwrap_or_else(|| "127.0.0.1".into());
    let port: u16 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(4242);

    log::info!("Connecting to {}:{}", host, port);

    let node = RnsNode::start(
        NodeConfig {
            transport_enabled: false,
            identity: None,
            interfaces: vec![InterfaceConfig {
                variant: InterfaceVariant::TcpClient(TcpClientConfig {
                    name: format!("TCP {}:{}", host, port),
                    target_host: host,
                    target_port: port,
                    interface_id: InterfaceId(1),
                    ..Default::default()
                }),
                mode: MODE_FULL,
                ifac: None,
            }],
            share_instance: false,
            rpc_port: 0,
            cache_dir: None,
            management: Default::default(),
        },
        Box::new(LoggingCallbacks),
    )
    .expect("Failed to start node");

    // Block until Ctrl+C
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
