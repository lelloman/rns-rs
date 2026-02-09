//! rnstatus - Display Reticulum network interface status
//!
//! Connects to a running rnsd via RPC and displays interface statistics.

use std::path::Path;
use std::process;

use rns_net::{RpcAddr, RpcClient};
use rns_net::pickle::PickleValue;
use rns_net::rpc::derive_auth_key;
use rns_net::config;
use rns_net::storage;
use rns_cli::args::Args;
use rns_cli::format::{size_str, speed_str, prettytime, prettyhexrep};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args = Args::parse();

    if args.has("version") {
        println!("rnstatus {}", VERSION);
        return;
    }

    if args.has("help") || args.has("h") {
        print_usage();
        return;
    }

    env_logger::Builder::new()
        .filter_level(match args.verbosity {
            0 => log::LevelFilter::Warn,
            1 => log::LevelFilter::Info,
            2 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        })
        .format_timestamp_secs()
        .init();

    let config_path = args.config_path().map(|s| s.to_string());
    let json_output = args.has("j");
    let show_all = args.has("a");
    let sort_by = args.get("s").map(|s| s.to_string());
    let reverse = args.has("r");
    let filter = args.positional.first().cloned();

    // Load config to get RPC address and auth key
    let config_dir = storage::resolve_config_dir(
        config_path.as_ref().map(|s| Path::new(s.as_str())),
    );
    let config_file = config_dir.join("config");
    let rns_config = if config_file.exists() {
        match config::parse_file(&config_file) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error reading config: {}", e);
                process::exit(1);
            }
        }
    } else {
        match config::parse("") {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        }
    };

    // Load identity to derive auth key
    let paths = match storage::ensure_storage_dirs(&config_dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    let identity = match storage::load_or_create_identity(&paths.identities) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Error loading identity: {}", e);
            process::exit(1);
        }
    };

    let auth_key = derive_auth_key(
        &identity.get_private_key().unwrap_or([0u8; 64]),
    );

    let rpc_port = rns_config.reticulum.instance_control_port;
    let rpc_addr = RpcAddr::Tcp("127.0.0.1".into(), rpc_port);

    // Connect to RPC server
    let mut client = match RpcClient::connect(&rpc_addr, &auth_key) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Could not connect to rnsd: {}", e);
            eprintln!("Is rnsd running?");
            process::exit(1);
        }
    };

    // Request interface stats
    let response = match client.call(&PickleValue::Dict(vec![
        (PickleValue::String("get".into()), PickleValue::String("interface_stats".into())),
    ])) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    };

    if json_output {
        print_json(&response);
    } else {
        print_status(&response, show_all, sort_by.as_deref(), reverse, filter.as_deref());
    }
}

fn print_status(
    response: &PickleValue,
    _show_all: bool,
    _sort_by: Option<&str>,
    _reverse: bool,
    filter: Option<&str>,
) {
    // Print transport info
    if let Some(PickleValue::Bool(true)) = response.get("transport_enabled").map(|v| v) {
        print!(" Transport Instance ");
        if let Some(tid) = response.get("transport_id").and_then(|v| v.as_bytes()) {
            print!("{} ", prettyhexrep(&tid[..tid.len().min(8)]));
        }
        if let Some(PickleValue::Float(uptime)) = response.get("transport_uptime") {
            print!("running for {}", prettytime(*uptime));
        }
        println!();
        println!();
    }

    // Print interfaces
    if let Some(interfaces) = response.get("interfaces").and_then(|v| v.as_list()) {
        for iface in interfaces {
            let name = iface.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");

            // Apply filter
            if let Some(f) = filter {
                if !name.to_lowercase().contains(&f.to_lowercase()) {
                    continue;
                }
            }

            let status = iface.get("status").and_then(|v| v.as_bool()).unwrap_or(false);
            let rxb = iface.get("rxb").and_then(|v| v.as_int()).unwrap_or(0) as u64;
            let txb = iface.get("txb").and_then(|v| v.as_int()).unwrap_or(0) as u64;
            let bitrate = iface.get("bitrate").and_then(|v| v.as_int()).map(|n| n as u64);
            let mode = iface.get("mode").and_then(|v| v.as_int()).unwrap_or(0) as u8;
            let started = iface.get("started").and_then(|v| v.as_float()).unwrap_or(0.0);

            let mode_str = match mode {
                rns_net::MODE_FULL => "Full",
                rns_net::MODE_ACCESS_POINT => "Access Point",
                rns_net::MODE_POINT_TO_POINT => "Point-to-Point",
                rns_net::MODE_ROAMING => "Roaming",
                rns_net::MODE_BOUNDARY => "Boundary",
                rns_net::MODE_GATEWAY => "Gateway",
                _ => "Unknown",
            };

            println!(" {}", name);
            println!("    Status    : {}", if status { "Up" } else { "Down" });
            println!("    Mode      : {}", mode_str);
            if let Some(br) = bitrate {
                println!("    Rate      : {}", speed_str(br));
            }
            println!(
                "    Traffic   : {} \u{2191}  {} \u{2193}",
                size_str(txb),
                size_str(rxb),
            );
            if started > 0.0 {
                let uptime = rns_net::time::now() - started;
                if uptime > 0.0 {
                    println!("    Uptime    : {}", prettytime(uptime));
                }
            }
            println!();
        }
    }
}

fn print_json(response: &PickleValue) {
    // Simple JSON output
    println!("{}", pickle_to_json(response));
}

fn pickle_to_json(value: &PickleValue) -> String {
    match value {
        PickleValue::None => "null".into(),
        PickleValue::Bool(b) => if *b { "true" } else { "false" }.into(),
        PickleValue::Int(n) => format!("{}", n),
        PickleValue::Float(f) => format!("{}", f),
        PickleValue::String(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
        PickleValue::Bytes(b) => {
            format!("\"{}\"", prettyhexrep(b))
        }
        PickleValue::List(items) => {
            let inner: Vec<String> = items.iter().map(pickle_to_json).collect();
            format!("[{}]", inner.join(", "))
        }
        PickleValue::Dict(pairs) => {
            let inner: Vec<String> = pairs
                .iter()
                .map(|(k, v)| format!("{}: {}", pickle_to_json(k), pickle_to_json(v)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

fn print_usage() {
    println!("Usage: rnstatus [OPTIONS] [FILTER]");
    println!();
    println!("Options:");
    println!("  --config PATH, -c PATH  Path to config directory");
    println!("  -a                      Show all interfaces");
    println!("  -j                      JSON output");
    println!("  -s SORT                 Sort by: rate, traffic, rx, tx");
    println!("  -r                      Reverse sort order");
    println!("  -v                      Increase verbosity");
    println!("  --version               Print version and exit");
    println!("  --help, -h              Print this help");
}
