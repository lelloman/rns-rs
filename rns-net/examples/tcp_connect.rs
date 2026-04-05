//! Connect to a Python RNS TCP server and log received announces.
//!
//! Usage: cargo run --example tcp_connect -- [host] [port]
//! Default: 127.0.0.1:4242

use std::env;
use std::sync::mpsc;

use rns_net::{Callbacks, InterfaceConfig, NodeConfig, RnsNode, TcpClientConfig, MODE_FULL};

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
    let host = args.get(1).cloned().unwrap_or_else(|| "127.0.0.1".into());
    let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(4242);

    log::info!("Connecting to {}:{}", host, port);

    let node = RnsNode::start(
        NodeConfig {
            panic_on_interface_error: false,
            transport_enabled: false,
            identity: None,
            interfaces: vec![InterfaceConfig {
                name: String::new(),
                type_name: "TCPClientInterface".to_string(),
                config_data: Box::new(TcpClientConfig {
                    name: format!("TCP {}:{}", host, port),
                    target_host: host,
                    target_port: port,
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
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: usize::MAX,
            max_tunnel_destinations_total: usize::MAX,
            known_destinations_ttl: std::time::Duration::from_secs(48 * 60 * 60),
            known_destinations_max_entries: 8192,
            announce_table_ttl: std::time::Duration::from_secs(
                rns_core::constants::ANNOUNCE_TABLE_TTL as u64,
            ),
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            driver_event_queue_capacity: rns_net::event::DEFAULT_EVENT_QUEUE_CAPACITY,
            interface_writer_queue_capacity:
                rns_net::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl: std::time::Duration::from_secs(
                rns_core::constants::ANNOUNCE_SIG_CACHE_TTL as u64,
            ),
            registry: None,
            #[cfg(feature = "rns-hooks")]
            provider_bridge: None,
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
