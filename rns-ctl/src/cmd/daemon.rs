//! RNS daemon node.
//!
//! Starts an RNS node from config, optionally with RPC server for external tools.

use std::fs;
use std::path::Path;
use std::sync::mpsc;

use rns_net::{Callbacks, InterfaceId, RnsNode};
use rns_net::storage;
use crate::args::Args;

struct DaemonCallbacks;

impl Callbacks for DaemonCallbacks {
    fn on_announce(&mut self, announced: rns_net::AnnouncedIdentity) {
        log::info!(
            "Announce received for {} (hops: {})",
            hex(&announced.dest_hash.0),
            announced.hops,
        );
    }

    fn on_path_updated(&mut self, dest_hash: rns_net::DestHash, hops: u8) {
        log::debug!("Path updated for {} (hops: {})", hex(&dest_hash.0), hops);
    }

    fn on_local_delivery(&mut self, dest_hash: rns_net::DestHash, _raw: Vec<u8>, _hash: rns_net::PacketHash) {
        log::debug!("Local delivery for {}", hex(&dest_hash.0));
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

pub fn run(args: Args) {
    if args.has("version") {
        println!("rns-ctl {}", env!("FULL_VERSION"));
        return;
    }

    if args.has("help") {
        print_usage();
        return;
    }

    if args.has("exampleconfig") {
        print!("{}", EXAMPLE_CONFIG);
        return;
    }

    let service_mode = args.has("s");
    let config_path = args.config_path().map(|s| s.to_string());

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

    if service_mode {
        // Service mode: log to file in config dir
        let config_dir = storage::resolve_config_dir(
            config_path.as_ref().map(|s| Path::new(s.as_str())),
        );
        let logfile_path = config_dir.join("logfile");
        match fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&logfile_path)
        {
            Ok(file) => {
                env_logger::Builder::new()
                    .filter_level(log_level)
                    .format_timestamp_secs()
                    .target(env_logger::Target::Pipe(Box::new(file)))
                    .init();
            }
            Err(e) => {
                eprintln!("Could not open logfile {}: {}", logfile_path.display(), e);
                std::process::exit(1);
            }
        }
    } else {
        env_logger::Builder::new()
            .filter_level(log_level)
            .format_timestamp_secs()
            .init();
    }

    log::info!("Starting rnsd {}", env!("FULL_VERSION"));

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
    println!("Usage: rns-ctl daemon [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --config PATH, -c PATH  Path to config directory");
    println!("  -s                      Service mode (log to file)");
    println!("  --exampleconfig         Print example config and exit");
    println!("  -v                      Increase verbosity (can repeat)");
    println!("  -q                      Decrease verbosity (can repeat)");
    println!("  --version               Print version and exit");
    println!("  --help, -h              Print this help");
}

const EXAMPLE_CONFIG: &str = r#"# This is an example Reticulum config file.
# It can be used as a starting point for your own configuration.

[reticulum]
  enable_transport = false
  share_instance = true
  shared_instance_port = 37428
  instance_control_port = 37429
  panic_on_interface_error = false

[logging]
  loglevel = 4

# ─── Interface examples ──────────────────────────────────────────────

# TCP client: connect to a remote transport node
#
# [[TCP Client]]
#   type = TCPClientInterface
#   target_host = amsterdam.connect.reticulum.network
#   target_port = 4965

# TCP server: accept incoming connections
#
# [[TCP Server]]
#   type = TCPServerInterface
#   listen_ip = 0.0.0.0
#   listen_port = 4965

# UDP interface: broadcast on LAN
#
# [[UDP Interface]]
#   type = UDPInterface
#   listen_ip = 0.0.0.0
#   listen_port = 4242
#   forward_ip = 255.255.255.255
#   forward_port = 4242

# Serial interface: point-to-point serial port
#
# [[Serial Interface]]
#   type = SerialInterface
#   port = /dev/ttyUSB0
#   speed = 115200
#   databits = 8
#   parity = none
#   stopbits = 1

# KISS interface: for TNC modems
#
# [[KISS Interface]]
#   type = KISSInterface
#   port = /dev/ttyUSB1
#   speed = 115200
#   databits = 8
#   parity = none
#   stopbits = 1
#   preamble = 350
#   txtail = 20
#   persistence = 64
#   slottime = 20
#   flow_control = false

# RNode LoRa interface
#
# [[RNode LoRa Interface]]
#   type = RNodeInterface
#   port = /dev/ttyACM0
#   frequency = 867200000
#   bandwidth = 125000
#   txpower = 7
#   spreadingfactor = 8
#   codingrate = 5

# Pipe interface: stdin/stdout of a subprocess
#
# [[Pipe Interface]]
#   type = PipeInterface
#   command = cat

# Backbone interface: TCP mesh
#
# [[Backbone]]
#   type = BackboneInterface
#   listen_ip = 0.0.0.0
#   listen_port = 4243
#   peers = 10.0.0.1:4243, 10.0.0.2:4243
"#;
