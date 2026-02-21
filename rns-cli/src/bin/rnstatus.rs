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
use rns_cli::format::{size_str, speed_str, prettytime, prettyhexrep, prettyfrequency};

const VERSION: &str = env!("FULL_VERSION");

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
    let show_totals = args.has("t");
    let show_links = args.has("l");
    let show_announces = args.has("A");
    let monitor_mode = args.has("m");
    let monitor_interval: f64 = args.get("I")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1.0);
    let remote_hash = args.get("R").map(|s| s.to_string());
    let show_discovered = args.has("d");
    let show_discovered_config = args.has("D");
    let filter = args.positional.first().cloned();

    // Remote management query via -R flag
    if let Some(ref hash_str) = remote_hash {
        remote_status(hash_str, config_path.as_deref());
        return;
    }

    // Discovered interfaces query via -d or -D flag
    if show_discovered || show_discovered_config {
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

        let mut client = match RpcClient::connect(&rpc_addr, &auth_key) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Could not connect to rnsd: {}", e);
                eprintln!("Is rnsd running?");
                process::exit(1);
            }
        };

        show_discovered_interfaces(&mut client, show_discovered_config, json_output);
        return;
    }

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

    loop {
        // Connect to RPC server
        let mut client = match RpcClient::connect(&rpc_addr, &auth_key) {
            Ok(c) => c,
            Err(e) => {
                if monitor_mode {
                    eprintln!("Could not connect to rnsd: {} — retrying...", e);
                    std::thread::sleep(std::time::Duration::from_secs_f64(monitor_interval));
                    continue;
                }
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
                if monitor_mode {
                    std::thread::sleep(std::time::Duration::from_secs_f64(monitor_interval));
                    continue;
                }
                process::exit(1);
            }
        };

        // Query link count if requested
        let link_count = if show_links {
            match client.call(&PickleValue::Dict(vec![
                (PickleValue::String("get".into()), PickleValue::String("link_count".into())),
            ])) {
                Ok(r) => r.as_int(),
                Err(_) => None,
            }
        } else {
            None
        };

        if monitor_mode {
            // Clear screen
            print!("\x1b[2J\x1b[H");
        }

        if json_output {
            print_json(&response);
        } else {
            print_status(
                &response,
                show_all,
                sort_by.as_deref(),
                reverse,
                filter.as_deref(),
                show_totals,
                show_announces,
            );
        }

        if let Some(count) = link_count {
            println!(" Active links  : {}", count);
            println!();
        }

        if !monitor_mode {
            break;
        }

        std::thread::sleep(std::time::Duration::from_secs_f64(monitor_interval));
    }
}

fn print_status(
    response: &PickleValue,
    _show_all: bool,
    sort_by: Option<&str>,
    reverse: bool,
    filter: Option<&str>,
    show_totals: bool,
    show_announces: bool,
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
        if let Some(pr) = response.get("probe_responder").and_then(|v| v.as_bytes()) {
            if !pr.is_empty() {
                println!("   Probe responder at {}", prettyhexrep(pr));
            }
        }
        println!();
    }

    // Print interfaces
    if let Some(interfaces) = response.get("interfaces").and_then(|v| v.as_list()) {
        // Collect into a sortable vec of references
        let mut iface_list: Vec<&PickleValue> = interfaces.iter().collect();

        // Apply filter
        if let Some(f) = filter {
            iface_list.retain(|iface| {
                let name = iface.get("name").and_then(|v| v.as_str()).unwrap_or("");
                name.to_lowercase().contains(&f.to_lowercase())
            });
        }

        // Sort if requested
        if let Some(sort_key) = sort_by {
            iface_list.sort_by(|a, b| {
                let cmp = match sort_key {
                    "rate" => {
                        let ra = a.get("bitrate").and_then(|v| v.as_int()).unwrap_or(0);
                        let rb = b.get("bitrate").and_then(|v| v.as_int()).unwrap_or(0);
                        ra.cmp(&rb)
                    }
                    "traffic" => {
                        let ta = a.get("rxb").and_then(|v| v.as_int()).unwrap_or(0)
                            + a.get("txb").and_then(|v| v.as_int()).unwrap_or(0);
                        let tb = b.get("rxb").and_then(|v| v.as_int()).unwrap_or(0)
                            + b.get("txb").and_then(|v| v.as_int()).unwrap_or(0);
                        ta.cmp(&tb)
                    }
                    "rx" => {
                        let ra = a.get("rxb").and_then(|v| v.as_int()).unwrap_or(0);
                        let rb = b.get("rxb").and_then(|v| v.as_int()).unwrap_or(0);
                        ra.cmp(&rb)
                    }
                    "tx" => {
                        let ta = a.get("txb").and_then(|v| v.as_int()).unwrap_or(0);
                        let tb = b.get("txb").and_then(|v| v.as_int()).unwrap_or(0);
                        ta.cmp(&tb)
                    }
                    _ => {
                        let na = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let nb = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        na.cmp(nb)
                    }
                };
                if reverse { cmp.reverse() } else { cmp }
            });
        }

        for iface in &iface_list {
            let name = iface.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
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
            if show_announces {
                let ia_freq = iface.get("ia_freq").and_then(|v| v.as_float()).unwrap_or(0.0);
                let oa_freq = iface.get("oa_freq").and_then(|v| v.as_float()).unwrap_or(0.0);
                println!(
                    "    Announces : {} in  {} out",
                    prettyfrequency(ia_freq),
                    prettyfrequency(oa_freq),
                );
            }
            println!();
        }
    }

    // Show traffic totals
    if show_totals {
        let total_rxb = response.get("rxb").and_then(|v| v.as_int()).unwrap_or(0) as u64;
        let total_txb = response.get("txb").and_then(|v| v.as_int()).unwrap_or(0) as u64;
        println!(
            " Traffic totals: {} \u{2191}  {} \u{2193}",
            size_str(total_txb),
            size_str(total_rxb),
        );
        println!();
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

fn remote_status(hash_str: &str, config_path: Option<&str>) {
    let dest_hash = match rns_cli::remote::parse_hex_hash(hash_str) {
        Some(h) => h,
        None => {
            eprintln!("Invalid destination hash: {} (expected 32 hex chars)", hash_str);
            process::exit(1);
        }
    };

    eprintln!(
        "Remote management query to {} (not yet fully implemented)",
        prettyhexrep(&dest_hash),
    );
    eprintln!("Requires an active link to the remote management destination.");
    eprintln!("This feature will work once rnsd is running and the remote node is reachable.");

    // In a full implementation, this would:
    // 1. Connect as shared client
    // 2. Wait for path to management destination
    // 3. Create link
    // 4. Identify
    // 5. Send /status request
    // 6. Parse msgpack response
    // 7. Display like local status
    let _ = (dest_hash, config_path);
}

/// Show discovered interfaces
fn show_discovered_interfaces(client: &mut RpcClient, show_config: bool, json_output: bool) {
    let response = match client.call(&PickleValue::Dict(vec![
        (PickleValue::String("get".into()), PickleValue::String("discovered_interfaces".into())),
    ])) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    };

    if json_output {
        print_json(&response);
        return;
    }

    let interfaces = match response.as_list() {
        Some(list) => list,
        None => {
            println!("No discovered interfaces found.");
            return;
        }
    };

    if interfaces.is_empty() {
        println!("No discovered interfaces found.");
        return;
    }

    if show_config {
        // Detailed view with config entries
        for (idx, iface) in interfaces.iter().enumerate() {
            if idx > 0 {
                println!("{}", "=".repeat(32));
            }

            let name = iface.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
            let if_type = iface.get("type").and_then(|v| v.as_str())
                .or_else(|| iface.get("interface_type").and_then(|v| v.as_str()))
                .unwrap_or("Unknown");
            let status = iface.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
            let transport = iface.get("transport").and_then(|v| v.as_bool()).unwrap_or(false);
            let hops = iface.get("hops").and_then(|v| v.as_int()).unwrap_or(0);
            let value = iface.get("value").or_else(|| iface.get("stamp_value"))
                .and_then(|v| v.as_int()).unwrap_or(0);
            let last_heard = iface.get("last_heard").and_then(|v| v.as_float()).unwrap_or(0.0);
            let discovered = iface.get("discovered").and_then(|v| v.as_float()).unwrap_or(0.0);

            let transport_id = iface.get("transport_id").and_then(|v| v.as_bytes())
                .map(|b| prettyhexrep(&b[..b.len().min(8)]))
                .unwrap_or_default();
            let network_id = iface.get("network_id").and_then(|v| v.as_bytes())
                .map(|b| prettyhexrep(&b[..b.len().min(8)]))
                .unwrap_or_default();

            if !network_id.is_empty() {
                println!("Network   ID : {}", network_id);
            }
            if !transport_id.is_empty() {
                println!("Transport ID : {}", transport_id);
            }

            println!("Name         : {}", name);
            println!("Type         : {}", if_type);
            println!("Status       : {}", status);
            println!("Transport    : {}", if transport { "Enabled" } else { "Disabled" });
            println!("Distance     : {} hop{}", hops, if hops == 1 { "" } else { "s" });

            let now = rns_net::time::now();
            if discovered > 0.0 {
                println!("Discovered   : {} ago", prettytime(now - discovered));
            }
            if last_heard > 0.0 {
                println!("Last Heard   : {} ago", prettytime(now - last_heard));
            }

            // Location
            let lat = iface.get("latitude").and_then(|v| v.as_float());
            let lon = iface.get("longitude").and_then(|v| v.as_float());
            let height = iface.get("height").and_then(|v| v.as_float());
            if let (Some(lat), Some(lon)) = (lat, lon) {
                let height_str = height.map(|h| format!(", {}m h", h)).unwrap_or_default();
                println!("Location     : {:.4}, {:.4}{}", lat, lon, height_str);
            }

            // Interface-specific fields
            if let Some(freq) = iface.get("frequency").and_then(|v| v.as_int()) {
                println!("Frequency    : {} Hz", freq);
            }
            if let Some(bw) = iface.get("bandwidth").and_then(|v| v.as_int()) {
                println!("Bandwidth    : {} Hz", bw);
            }
            if let Some(sf) = iface.get("sf").or_else(|| iface.get("spreading_factor")).and_then(|v| v.as_int()) {
                println!("Sprd. Factor : {}", sf);
            }
            if let Some(cr) = iface.get("cr").or_else(|| iface.get("coding_rate")).and_then(|v| v.as_int()) {
                println!("Coding Rate  : {}", cr);
            }
            if let Some(modulation) = iface.get("modulation").and_then(|v| v.as_str()) {
                println!("Modulation   : {}", modulation);
            }
            if let Some(reachable) = iface.get("reachable_on").and_then(|v| v.as_str()) {
                println!("Address      : {}", reachable);
            }
            if let Some(port) = iface.get("port").and_then(|v| v.as_int()) {
                println!("Port         : {}", port);
            }

            println!("Stamp Value  : {}", value);

            // Config entry
            if let Some(config) = iface.get("config_entry").and_then(|v| v.as_str()) {
                println!("\nConfiguration Entry:");
                for line in config.lines() {
                    println!("  {}", line);
                }
            }

            println!();
        }
    } else {
        // Table view
        println!("{:<25} {:<12} {:<12} {:<12} {:<8} {:<15}",
            "Name", "Type", "Status", "Last Heard", "Value", "Location");
        println!("{}", "-".repeat(89));

        let now = rns_net::time::now();

        for iface in interfaces {
            let name_full = iface.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
            let name = if name_full.len() > 24 {
                format!("{}...", &name_full[..21])
            } else {
                name_full.to_string()
            };

            let if_type = iface.get("type").and_then(|v| v.as_str())
                .or_else(|| iface.get("interface_type").and_then(|v| v.as_str()))
                .unwrap_or("Unknown")
                .replace("Interface", "");

            let status = iface.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
            let status_display = match status {
                "available" => "Available",
                "unknown" => "Unknown",
                "stale" => "Stale",
                _ => status,
            };

            let last_heard = iface.get("last_heard").and_then(|v| v.as_float()).unwrap_or(0.0);
            let last_heard_display = if last_heard > 0.0 {
                let diff = now - last_heard;
                if diff < 60.0 {
                    "Just now".to_string()
                } else if diff < 3600.0 {
                    format!("{}m ago", (diff / 60.0) as i32)
                } else if diff < 86400.0 {
                    format!("{}h ago", (diff / 3600.0) as i32)
                } else {
                    format!("{}d ago", (diff / 86400.0) as i32)
                }
            } else {
                "N/A".to_string()
            };

            let value = iface.get("value").or_else(|| iface.get("stamp_value"))
                .and_then(|v| v.as_int()).unwrap_or(0);

            let lat = iface.get("latitude").and_then(|v| v.as_float());
            let lon = iface.get("longitude").and_then(|v| v.as_float());
            let location = match (lat, lon) {
                (Some(lat), Some(lon)) => format!("{:.4}, {:.4}", lat, lon),
                _ => "N/A".to_string(),
            };

            println!("{:<25} {:<12} {:<12} {:<12} {:<8} {:<15}",
                name, if_type, status_display, last_heard_display, value, location);
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
    println!("  -t                      Show traffic totals");
    println!("  -l                      Show link count");
    println!("  -A                      Show announce statistics");
    println!("  -d                      Show discovered interfaces");
    println!("  -D                      Show discovered interfaces with config entries");
    println!("  -m                      Monitor mode (loop)");
    println!("  -I SECONDS              Monitor interval (default: 1.0)");
    println!("  -R HASH                 Query remote node via management link");
    println!("  -v                      Increase verbosity");
    println!("  --version               Print version and exit");
    println!("  --help, -h              Print this help");
}
