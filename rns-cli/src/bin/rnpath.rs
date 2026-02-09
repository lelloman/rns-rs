//! rnpath - Display and manage Reticulum path table
//!
//! Connects to a running rnsd via RPC to query/modify the path table.

use std::path::Path;
use std::process;

use rns_net::{RpcAddr, RpcClient};
use rns_net::pickle::PickleValue;
use rns_net::rpc::derive_auth_key;
use rns_net::config;
use rns_net::storage;
use rns_cli::args::Args;
use rns_cli::format::{prettytime, prettyhexrep, prettyfrequency};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args = Args::parse();

    if args.has("version") {
        println!("rnpath {}", VERSION);
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
            _ => log::LevelFilter::Debug,
        })
        .format_timestamp_secs()
        .init();

    let config_path = args.config_path().map(|s| s.to_string());
    let show_table = args.has("t");
    let show_rates = args.has("r");
    let drop_hash = args.get("d").map(|s| s.to_string());
    let drop_via = args.get("x").map(|s| s.to_string());
    let drop_queues = args.has("D");
    let json_output = args.has("j");
    let max_hops: Option<u8> = args.get("m").and_then(|s| s.parse().ok());
    let show_blackholed = args.has("blackholed") || args.has("b");
    let blackhole_hash = args.get("B").map(|s| s.to_string());
    let unblackhole_hash = args.get("U").map(|s| s.to_string());
    let duration_hours: Option<f64> = args.get("duration").and_then(|s| s.parse().ok());
    let reason = args.get("reason").map(|s| s.to_string());
    let remote_hash = args.get("R").map(|s| s.to_string());

    // Remote management query via -R flag
    if let Some(ref hash_str) = remote_hash {
        remote_path(hash_str, config_path.as_deref());
        return;
    }

    // Load config
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
            process::exit(1);
        }
    };

    if show_table {
        show_path_table(&mut client, json_output, max_hops);
    } else if show_rates {
        show_rate_table(&mut client, json_output);
    } else if let Some(hash_str) = blackhole_hash {
        do_blackhole(&mut client, &hash_str, duration_hours, reason);
    } else if let Some(hash_str) = unblackhole_hash {
        do_unblackhole(&mut client, &hash_str);
    } else if show_blackholed {
        show_blackholed_list(&mut client);
    } else if let Some(hash_str) = drop_hash {
        drop_path(&mut client, &hash_str);
    } else if let Some(hash_str) = drop_via {
        drop_all_via(&mut client, &hash_str);
    } else if drop_queues {
        drop_announce_queues(&mut client);
    } else if let Some(hash_str) = args.positional.first() {
        lookup_path(&mut client, hash_str);
    } else {
        print_usage();
    }
}

fn parse_hex_hash(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        match u8::from_str_radix(&s[i..i + 2], 16) {
            Ok(b) => bytes.push(b),
            Err(_) => return None,
        }
    }
    Some(bytes)
}

fn show_path_table(client: &mut RpcClient, _json_output: bool, max_hops: Option<u8>) {
    let max_hops_val = match max_hops {
        Some(h) => PickleValue::Int(h as i64),
        None => PickleValue::None,
    };

    let response = match client.call(&PickleValue::Dict(vec![
        (PickleValue::String("get".into()), PickleValue::String("path_table".into())),
        (PickleValue::String("max_hops".into()), max_hops_val),
    ])) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    };

    if let Some(entries) = response.as_list() {
        if entries.is_empty() {
            println!("Path table is empty");
            return;
        }
        println!("{:<34} {:>6} {:<34} {:<10} {}",
            "Destination", "Hops", "Via", "Expires", "Interface");
        println!("{}", "-".repeat(100));
        for entry in entries {
            let hash = entry.get("hash")
                .and_then(|v| v.as_bytes())
                .map(prettyhexrep)
                .unwrap_or_default();
            let hops = entry.get("hops")
                .and_then(|v| v.as_int())
                .unwrap_or(0);
            let via = entry.get("via")
                .and_then(|v| v.as_bytes())
                .map(prettyhexrep)
                .unwrap_or_default();
            let expires = entry.get("expires")
                .and_then(|v| v.as_float())
                .map(|e| {
                    let remaining = e - rns_net::time::now();
                    if remaining > 0.0 { prettytime(remaining) } else { "expired".into() }
                })
                .unwrap_or_default();
            let interface = entry.get("interface")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            println!("{:<34} {:>6} {:<34} {:<10} {}",
                &hash[..hash.len().min(32)],
                hops,
                &via[..via.len().min(32)],
                expires,
                interface,
            );
        }
    } else {
        eprintln!("Unexpected response format");
    }
}

fn show_rate_table(client: &mut RpcClient, _json_output: bool) {
    let response = match client.call(&PickleValue::Dict(vec![
        (PickleValue::String("get".into()), PickleValue::String("rate_table".into())),
    ])) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    };

    if let Some(entries) = response.as_list() {
        if entries.is_empty() {
            println!("Rate table is empty");
            return;
        }
        println!("{:<34} {:>12} {:>12} {:>16}",
            "Destination", "Violations", "Frequency", "Blocked Until");
        println!("{}", "-".repeat(78));
        for entry in entries {
            let hash = entry.get("hash")
                .and_then(|v| v.as_bytes())
                .map(prettyhexrep)
                .unwrap_or_default();
            let violations = entry.get("rate_violations")
                .and_then(|v| v.as_int())
                .unwrap_or(0);
            let blocked = entry.get("blocked_until")
                .and_then(|v| v.as_float())
                .map(|b| {
                    let remaining = b - rns_net::time::now();
                    if remaining > 0.0 { prettytime(remaining) } else { "not blocked".into() }
                })
                .unwrap_or_default();

            // Compute hourly frequency from timestamps
            let freq_str = if let Some(timestamps) = entry.get("timestamps").and_then(|v| v.as_list()) {
                let ts: Vec<f64> = timestamps.iter()
                    .filter_map(|v| v.as_float())
                    .collect();
                if ts.len() >= 2 {
                    let span = ts[ts.len() - 1] - ts[0];
                    if span > 0.0 {
                        let freq_per_sec = (ts.len() - 1) as f64 / span;
                        prettyfrequency(freq_per_sec)
                    } else {
                        "none".into()
                    }
                } else {
                    "none".into()
                }
            } else {
                "none".into()
            };

            println!("{:<34} {:>12} {:>12} {:>16}",
                &hash[..hash.len().min(32)],
                violations,
                freq_str,
                blocked,
            );
        }
    }
}

fn show_blackholed_list(client: &mut RpcClient) {
    let response = match client.call(&PickleValue::Dict(vec![
        (PickleValue::String("get".into()), PickleValue::String("blackholed".into())),
    ])) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    };

    if let Some(entries) = response.as_list() {
        if entries.is_empty() {
            println!("Blackhole list is empty");
            return;
        }
        println!("{:<34} {:<16} {}",
            "Identity Hash", "Expires", "Reason");
        println!("{}", "-".repeat(70));
        for entry in entries {
            let hash = entry.get("identity_hash")
                .and_then(|v| v.as_bytes())
                .map(prettyhexrep)
                .unwrap_or_default();
            let expires = entry.get("expires")
                .and_then(|v| v.as_float())
                .map(|e| {
                    if e == 0.0 {
                        "never".into()
                    } else {
                        let remaining = e - rns_net::time::now();
                        if remaining > 0.0 { prettytime(remaining) } else { "expired".into() }
                    }
                })
                .unwrap_or_default();
            let reason = entry.get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("-");

            println!("{:<34} {:<16} {}",
                &hash[..hash.len().min(32)],
                expires,
                reason,
            );
        }
    } else {
        eprintln!("Unexpected response format");
    }
}

fn do_blackhole(client: &mut RpcClient, hash_str: &str, duration_hours: Option<f64>, reason: Option<String>) {
    let hash_bytes = match parse_hex_hash(hash_str) {
        Some(b) if b.len() >= 16 => b,
        _ => {
            eprintln!("Invalid identity hash: {}", hash_str);
            process::exit(1);
        }
    };

    let mut dict = vec![
        (PickleValue::String("blackhole".into()), PickleValue::Bytes(hash_bytes[..16].to_vec())),
    ];
    if let Some(d) = duration_hours {
        dict.push((PickleValue::String("duration".into()), PickleValue::Float(d)));
    }
    if let Some(r) = reason {
        dict.push((PickleValue::String("reason".into()), PickleValue::String(r)));
    }

    match client.call(&PickleValue::Dict(dict)) {
        Ok(r) => {
            if r.as_bool() == Some(true) {
                println!("Blackholed identity {}", prettyhexrep(&hash_bytes[..16]));
            } else {
                eprintln!("Failed to blackhole identity");
            }
        }
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    }
}

fn do_unblackhole(client: &mut RpcClient, hash_str: &str) {
    let hash_bytes = match parse_hex_hash(hash_str) {
        Some(b) if b.len() >= 16 => b,
        _ => {
            eprintln!("Invalid identity hash: {}", hash_str);
            process::exit(1);
        }
    };

    match client.call(&PickleValue::Dict(vec![
        (PickleValue::String("unblackhole".into()), PickleValue::Bytes(hash_bytes[..16].to_vec())),
    ])) {
        Ok(r) => {
            if r.as_bool() == Some(true) {
                println!("Removed {} from blackhole list", prettyhexrep(&hash_bytes[..16]));
            } else {
                println!("Identity {} was not blackholed", prettyhexrep(&hash_bytes[..16]));
            }
        }
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    }
}

fn lookup_path(client: &mut RpcClient, hash_str: &str) {
    let hash_bytes = match parse_hex_hash(hash_str) {
        Some(b) if b.len() >= 16 => b,
        _ => {
            eprintln!("Invalid destination hash: {}", hash_str);
            process::exit(1);
        }
    };

    let mut dest_hash = [0u8; 16];
    dest_hash.copy_from_slice(&hash_bytes[..16]);

    // Query next hop
    let response = match client.call(&PickleValue::Dict(vec![
        (PickleValue::String("get".into()), PickleValue::String("next_hop".into())),
        (PickleValue::String("destination_hash".into()), PickleValue::Bytes(dest_hash.to_vec())),
    ])) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    };

    if let Some(next_hop) = response.as_bytes() {
        println!("Path to {} found", prettyhexrep(&dest_hash));
        println!("  Next hop: {}", prettyhexrep(next_hop));
    } else {
        println!("No path found for {}", prettyhexrep(&dest_hash));
    }
}

fn drop_path(client: &mut RpcClient, hash_str: &str) {
    let hash_bytes = match parse_hex_hash(hash_str) {
        Some(b) if b.len() >= 16 => b,
        _ => {
            eprintln!("Invalid destination hash: {}", hash_str);
            process::exit(1);
        }
    };

    let mut dest_hash = [0u8; 16];
    dest_hash.copy_from_slice(&hash_bytes[..16]);

    let response = match client.call(&PickleValue::Dict(vec![
        (PickleValue::String("drop".into()), PickleValue::String("path".into())),
        (PickleValue::String("destination_hash".into()), PickleValue::Bytes(dest_hash.to_vec())),
    ])) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    };

    if response.as_bool() == Some(true) {
        println!("Dropped path for {}", prettyhexrep(&dest_hash));
    } else {
        println!("No path found for {}", prettyhexrep(&dest_hash));
    }
}

fn drop_all_via(client: &mut RpcClient, hash_str: &str) {
    let hash_bytes = match parse_hex_hash(hash_str) {
        Some(b) if b.len() >= 16 => b,
        _ => {
            eprintln!("Invalid transport hash: {}", hash_str);
            process::exit(1);
        }
    };

    let mut transport_hash = [0u8; 16];
    transport_hash.copy_from_slice(&hash_bytes[..16]);

    let response = match client.call(&PickleValue::Dict(vec![
        (PickleValue::String("drop".into()), PickleValue::String("all_via".into())),
        (PickleValue::String("destination_hash".into()), PickleValue::Bytes(transport_hash.to_vec())),
    ])) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    };

    if let Some(n) = response.as_int() {
        println!("Dropped {} paths via {}", n, prettyhexrep(&transport_hash));
    }
}

fn drop_announce_queues(client: &mut RpcClient) {
    match client.call(&PickleValue::Dict(vec![
        (PickleValue::String("drop".into()), PickleValue::String("announce_queues".into())),
    ])) {
        Ok(_) => println!("Announce queues dropped"),
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    }
}

fn remote_path(hash_str: &str, config_path: Option<&str>) {
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

    let _ = (dest_hash, config_path);
}

fn print_usage() {
    println!("Usage: rnpath [OPTIONS] [DESTINATION_HASH]");
    println!();
    println!("Options:");
    println!("  --config PATH, -c PATH  Path to config directory");
    println!("  -t                      Show path table");
    println!("  -m HOPS                 Filter path table by max hops");
    println!("  -r                      Show rate table");
    println!("  -d HASH                 Drop path for destination");
    println!("  -x HASH                 Drop all paths via transport");
    println!("  -D                      Drop all announce queues");
    println!("  -b                      Show blackholed identities");
    println!("  -B HASH                 Blackhole an identity");
    println!("  -U HASH                 Remove identity from blackhole list");
    println!("  --duration HOURS        Blackhole duration (default: permanent)");
    println!("  --reason TEXT           Reason for blackholing");
    println!("  -R HASH                 Query remote node via management link");
    println!("  -j                      JSON output");
    println!("  -v                      Increase verbosity");
    println!("  --version               Print version and exit");
    println!("  --help, -h              Print this help");
}
