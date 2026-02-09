//! rnsd - Reticulum Network Stack Daemon
//!
//! Starts an RNS node from config, optionally with RPC server for external tools.

use std::path::Path;
use std::sync::mpsc;

use rns_net::{Callbacks, InterfaceId, RnsNode};
use rns_cli::args::Args;

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct DaemonCallbacks;

impl Callbacks for DaemonCallbacks {
    fn on_announce(
        &mut self,
        dest_hash: [u8; 16],
        _identity_hash: [u8; 16],
        _public_key: [u8; 64],
        _app_data: Option<Vec<u8>>,
        hops: u8,
    ) {
        log::info!(
            "Announce received for {} (hops: {})",
            hex(&dest_hash),
            hops,
        );
    }

    fn on_path_updated(&mut self, dest_hash: [u8; 16], hops: u8) {
        log::debug!("Path updated for {} (hops: {})", hex(&dest_hash), hops);
    }

    fn on_local_delivery(&mut self, dest_hash: [u8; 16], _raw: Vec<u8>, _hash: [u8; 32]) {
        log::debug!("Local delivery for {}", hex(&dest_hash));
    }

    fn on_interface_up(&mut self, id: InterfaceId) {
        log::info!("Interface {} up", id.0);
    }

    fn on_interface_down(&mut self, id: InterfaceId) {
        log::info!("Interface {} down", id.0);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let args = Args::parse();

    if args.has("version") {
        println!("rnsd {}", VERSION);
        return;
    }

    if args.has("help") || args.has("h") {
        print_usage();
        return;
    }

    // Set up logging
    let log_level = match args.verbosity {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    let log_level = if args.quiet > 0 {
        match args.quiet {
            1 => log::LevelFilter::Warn,
            _ => log::LevelFilter::Error,
        }
    } else {
        log_level
    };

    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp_secs()
        .init();

    let config_path = args.config_path().map(|s| s.to_string());

    log::info!("Starting rnsd {}", VERSION);

    let node = RnsNode::from_config(
        config_path.as_ref().map(|s| Path::new(s.as_str())),
        Box::new(DaemonCallbacks),
    );

    let node = match node {
        Ok(n) => n,
        Err(e) => {
            log::error!("Failed to start: {}", e);
            std::process::exit(1);
        }
    };

    // Set up signal handling
    let (stop_tx, stop_rx) = mpsc::channel::<()>();

    // Handle SIGTERM/SIGINT
    unsafe {
        libc::signal(libc::SIGINT, signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, signal_handler as *const () as libc::sighandler_t);
    }
    // Store the channel sender in a static so the signal handler can use it
    STOP_TX.lock().unwrap().replace(stop_tx);

    log::info!("rnsd started");

    // Block until signal
    loop {
        match stop_rx.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(()) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        }
    }

    log::info!("Shutting down...");
    node.shutdown();
    log::info!("rnsd stopped");
}

static STOP_TX: std::sync::Mutex<Option<mpsc::Sender<()>>> = std::sync::Mutex::new(None);

extern "C" fn signal_handler(_sig: libc::c_int) {
    if let Ok(guard) = STOP_TX.lock() {
        if let Some(ref tx) = *guard {
            let _ = tx.send(());
        }
    }
}

fn print_usage() {
    println!("Usage: rnsd [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --config PATH, -c PATH  Path to config directory");
    println!("  -v                      Increase verbosity (can repeat)");
    println!("  -q                      Decrease verbosity (can repeat)");
    println!("  --version               Print version and exit");
    println!("  --help, -h              Print this help");
}
