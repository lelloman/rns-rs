//! Rust rnsd daemon — reads standard Python RNS config and runs a node.
//!
//! Usage:
//!   RUST_LOG=info cargo run --example rnsd [/path/to/config/dir]

use std::env;
use std::path::PathBuf;
use std::sync::mpsc;

use rns_net::{AnnouncedIdentity, Callbacks, DestHash, InterfaceId, PacketHash, RnsNode};

struct LoggingCallbacks;

impl Callbacks for LoggingCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        log::info!(
            "Announce: dest={} identity={} hops={} app_data={}",
            announced.dest_hash,
            announced.identity_hash,
            announced.hops,
            announced.app_data
                .as_ref()
                .map(|d| format!("{} bytes", d.len()))
                .unwrap_or_else(|| "none".into())
        );
    }

    fn on_path_updated(&mut self, dest_hash: DestHash, hops: u8) {
        log::info!("Path updated: dest={} hops={}", dest_hash, hops);
    }

    fn on_local_delivery(&mut self, dest_hash: DestHash, raw: Vec<u8>, _packet_hash: PacketHash) {
        log::info!(
            "Local delivery: dest={} size={}",
            dest_hash,
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
