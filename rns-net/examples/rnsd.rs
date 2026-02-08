//! Rust rnsd daemon — reads standard Python RNS config and runs a node.
//!
//! Usage:
//!   RUST_LOG=info cargo run --example rnsd [/path/to/config/dir]

use std::env;
use std::path::PathBuf;
use std::sync::mpsc;

use rns_net::Callbacks;
use rns_net::InterfaceId;
use rns_net::RnsNode;

struct LoggingCallbacks;

impl Callbacks for LoggingCallbacks {
    fn on_announce(
        &mut self,
        dest_hash: [u8; 16],
        identity_hash: [u8; 16],
        _public_key: [u8; 64],
        app_data: Option<Vec<u8>>,
        hops: u8,
    ) {
        log::info!(
            "Announce: dest={} identity={} hops={} app_data={}",
            hex(&dest_hash),
            hex(&identity_hash),
            hops,
            app_data
                .as_ref()
                .map(|d| format!("{} bytes", d.len()))
                .unwrap_or_else(|| "none".into())
        );
    }

    fn on_path_updated(&mut self, dest_hash: [u8; 16], hops: u8) {
        log::info!("Path updated: dest={} hops={}", hex(&dest_hash), hops);
    }

    fn on_local_delivery(&mut self, dest_hash: [u8; 16], raw: Vec<u8>, _packet_hash: [u8; 32]) {
        log::info!(
            "Local delivery: dest={} size={}",
            hex(&dest_hash),
            raw.len()
        );
    }

    fn on_interface_up(&mut self, id: InterfaceId) {
        log::info!("Interface up: {}", id.0);
    }

    fn on_interface_down(&mut self, id: InterfaceId) {
        log::info!("Interface down: {}", id.0);
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    env_logger::init();

    let config_path = env::args().nth(1).map(PathBuf::from);

    log::info!(
        "Starting rnsd with config: {}",
        config_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "~/.reticulum".into())
    );

    let node = RnsNode::from_config(config_path.as_deref(), Box::new(LoggingCallbacks))
        .expect("Failed to start RNS node");

    log::info!("Node started, waiting for Ctrl+C...");

    // Block until Ctrl+C
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    ctrlc::set_handler(move || {
        let _ = stop_tx.send(());
    })
    .expect("Failed to set Ctrl+C handler");

    stop_rx.recv().ok();

    log::info!("Shutting down...");
    node.shutdown();
    log::info!("Done.");
}
