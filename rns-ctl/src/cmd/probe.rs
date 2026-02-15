//! Probe path reachability to a Reticulum destination.
//!
//! Uses RPC to query a running rnsd daemon.

use std::path::Path;
use std::process;
use std::time::{Duration, Instant};

use rns_net::{RpcAddr, RpcClient};
use rns_net::pickle::PickleValue;
use rns_net::rpc::derive_auth_key;
use rns_net::config;
use rns_net::storage;
use crate::args::Args;
use crate::format::prettyhexrep;

const DEFAULT_TIMEOUT: f64 = 15.0;

pub fn run(args: Args) {
    if args.has("version") {
        println!("rns-ctl {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    if args.has("help") {
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
    let timeout: f64 = args.get("t")
        .or_else(|| args.get("timeout"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_TIMEOUT);
    let verbosity = args.verbosity;

    // Positional args: destination_hash
    let dest_hash_hex = match args.positional.first() {
        Some(h) => h.clone(),
        None => {
            eprintln!("No destination hash specified.");
            print_usage();
            process::exit(1);
        }
    };

    let dest_hash = match parse_dest_hash(&dest_hash_hex) {
        Some(h) => h,
        None => {
            eprintln!(
                "Invalid destination hash: {} (expected 32 hex chars)",
                dest_hash_hex,
            );
            process::exit(1);
        }
    };

    // Load config
    let config_dir = storage::resolve_config_dir(
        config_path.as_ref().map(|s| Path::new(s.as_str())),
    );
    let config_file = config_dir.join("config");
    let rns_config = if config_file.exists() {
        match config::parse_file(&config_file) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Config parse error: {}", e);
                process::exit(1);
            }
        }
    } else {
        match config::parse("") {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Config parse error: {}", e);
                process::exit(1);
            }
        }
    };

    // Connect to rnsd via RPC
    let rpc_port = rns_config.reticulum.instance_control_port;
    let identity_path = config_dir.join("storage").join("identity");
    let identity = match storage::load_identity(&identity_path) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Failed to load identity (is rnsd running?): {}", e);
            process::exit(1);
        }
    };

    let prv_key = match identity.get_private_key() {
        Some(k) => k,
        None => {
            eprintln!("Identity has no private key");
            process::exit(1);
        }
    };

    let auth_key = derive_auth_key(&prv_key);
    let rpc_addr = RpcAddr::Tcp("127.0.0.1".into(), rpc_port);

    // Check if path exists
    let start = Instant::now();

    match query_path_info(&rpc_addr, &auth_key, &dest_hash) {
        Ok(Some(info)) => {
            let elapsed = start.elapsed().as_secs_f64();
            println!(
                "Path to {} found, {} hops",
                prettyhexrep(&dest_hash),
                info.hops,
            );
            if verbosity > 0 {
                println!(
                    "  via {} on {}",
                    prettyhexrep(&info.next_hop),
                    info.interface_name,
                );
                println!("  lookup completed in {:.3}s", elapsed);
            }
            process::exit(0);
        }
        Ok(None) => {
            // No path known, poll for it
        }
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    }

    // No path known — poll waiting for path to appear
    print!(
        "Waiting for path to {}... ",
        prettyhexrep(&dest_hash),
    );

    let request_start = Instant::now();
    let timeout_dur = Duration::from_secs_f64(timeout);

    let mut found = false;
    while request_start.elapsed() < timeout_dur {
        std::thread::sleep(Duration::from_millis(250));

        match query_path_info(&rpc_addr, &auth_key, &dest_hash) {
            Ok(Some(info)) => {
                let elapsed = request_start.elapsed().as_secs_f64();
                println!("found!");
                println!(
                    "Path to {} found in {:.3}s, {} hops",
                    prettyhexrep(&dest_hash),
                    elapsed,
                    info.hops,
                );
                if verbosity > 0 {
                    println!(
                        "  via {} on {}",
                        prettyhexrep(&info.next_hop),
                        info.interface_name,
                    );
                }
                found = true;
                break;
            }
            Ok(None) => continue,
            Err(_) => continue,
        }
    }

    if !found {
        println!("timeout!");
        eprintln!(
            "Path to {} not found within {:.1}s",
            prettyhexrep(&dest_hash),
            timeout,
        );
        process::exit(1);
    }
}

/// Information about a path to a destination.
struct PathInfo {
    next_hop: [u8; 16],
    hops: u8,
    interface_name: String,
}

/// Query path information for a destination via RPC.
fn query_path_info(
    addr: &RpcAddr,
    auth_key: &[u8; 32],
    dest_hash: &[u8; 16],
) -> Result<Option<PathInfo>, String> {
    // Query next hop
    let mut client = RpcClient::connect(addr, auth_key)
        .map_err(|e| format!("RPC connect: {}", e))?;

    let response = client.call(&PickleValue::Dict(vec![
        (PickleValue::String("get".into()), PickleValue::String("next_hop".into())),
        (PickleValue::String("destination_hash".into()), PickleValue::Bytes(dest_hash.to_vec())),
    ])).map_err(|e| format!("RPC call: {}", e))?;

    let next_hop = match response.as_bytes() {
        Some(b) if b.len() == 16 => {
            let mut h = [0u8; 16];
            h.copy_from_slice(b);
            h
        }
        _ => return Ok(None),
    };

    // Query interface name
    let if_name = {
        let mut client2 = RpcClient::connect(addr, auth_key)
            .map_err(|e| format!("RPC connect: {}", e))?;

        let resp = client2.call(&PickleValue::Dict(vec![
            (PickleValue::String("get".into()), PickleValue::String("next_hop_if_name".into())),
            (PickleValue::String("destination_hash".into()), PickleValue::Bytes(dest_hash.to_vec())),
        ])).map_err(|e| format!("RPC call: {}", e))?;

        match resp {
            PickleValue::String(s) => s,
            _ => "unknown".into(),
        }
    };

    // Query hop count from path table
    let hops = {
        let mut client3 = RpcClient::connect(addr, auth_key)
            .map_err(|e| format!("RPC connect: {}", e))?;

        let resp = client3.call(&PickleValue::Dict(vec![
            (PickleValue::String("get".into()), PickleValue::String("path_table".into())),
        ])).map_err(|e| format!("RPC call: {}", e))?;

        extract_hops_from_path_table(&resp, dest_hash)
    };

    Ok(Some(PathInfo {
        next_hop,
        hops,
        interface_name: if_name,
    }))
}

/// Extract hop count for a destination from a path table RPC response.
fn extract_hops_from_path_table(response: &PickleValue, dest_hash: &[u8; 16]) -> u8 {
    if let PickleValue::List(entries) = response {
        for entry in entries {
            if let PickleValue::List(fields) = entry {
                // Path table entry format: [hash_bytes, timestamp, via, hops, expires, if_name]
                if fields.len() >= 4 {
                    if let Some(hash_bytes) = fields[0].as_bytes() {
                        if hash_bytes == dest_hash {
                            if let PickleValue::Int(h) = &fields[3] {
                                return *h as u8;
                            }
                        }
                    }
                }
            }
        }
    }
    0
}

/// Parse a 32-character hex string into a 16-byte hash.
fn parse_dest_hash(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    if bytes.len() != 16 {
        return None;
    }
    let mut result = [0u8; 16];
    result.copy_from_slice(&bytes);
    Some(result)
}

fn print_usage() {
    println!("Usage: rns-ctl probe [OPTIONS] <destination_hash>");
    println!();
    println!("Probe a Reticulum destination to check path availability.");
    println!();
    println!("Arguments:");
    println!("  <destination_hash>    Hex hash of the destination (32 chars)");
    println!();
    println!("Options:");
    println!("  -c, --config PATH     Config directory path");
    println!("  -t, --timeout SECS    Timeout in seconds (default: 15)");
    println!("  -v, --verbose         Increase verbosity");
    println!("      --version         Show version");
    println!("  -h, --help            Show this help");
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_net::pickle::PickleValue;

    #[test]
    fn parse_valid_hash() {
        let hex = "0123456789abcdef0123456789abcdef";
        let hash = parse_dest_hash(hex).unwrap();
        assert_eq!(hash[0], 0x01);
        assert_eq!(hash[1], 0x23);
        assert_eq!(hash[15], 0xef);
    }

    #[test]
    fn parse_invalid_hash_short() {
        assert!(parse_dest_hash("0123").is_none());
    }

    #[test]
    fn parse_invalid_hash_long() {
        assert!(parse_dest_hash("0123456789abcdef0123456789abcdef00").is_none());
    }

    #[test]
    fn parse_invalid_hash_bad_hex() {
        assert!(parse_dest_hash("xyz3456789abcdef0123456789abcdef").is_none());
    }

    #[test]
    fn parse_uppercase_hash() {
        let hex = "0123456789ABCDEF0123456789ABCDEF";
        let hash = parse_dest_hash(hex).unwrap();
        assert_eq!(hash[0], 0x01);
        assert_eq!(hash[15], 0xEF);
    }

    #[test]
    fn default_timeout() {
        assert!((DEFAULT_TIMEOUT - 15.0).abs() < f64::EPSILON);
    }

    #[test]
    fn prettyhexrep_format() {
        let hash = [0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33,
                     0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB];
        let hex = prettyhexrep(&hash);
        assert_eq!(hex, "aabbccdd00112233445566778899aabb");
    }

    #[test]
    fn extract_hops_empty_table() {
        let table = PickleValue::List(vec![]);
        let hash = [0u8; 16];
        assert_eq!(extract_hops_from_path_table(&table, &hash), 0);
    }

    #[test]
    fn extract_hops_found() {
        let dest = vec![0xAA; 16];
        let entry = PickleValue::List(vec![
            PickleValue::Bytes(dest.clone()),
            PickleValue::Float(1000.0),
            PickleValue::Bytes(vec![0xBB; 16]),
            PickleValue::Int(3),
            PickleValue::Float(2000.0),
            PickleValue::String("TCPInterface".into()),
        ]);
        let table = PickleValue::List(vec![entry]);
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&dest);
        assert_eq!(extract_hops_from_path_table(&table, &hash), 3);
    }

    #[test]
    fn extract_hops_not_found() {
        let entry = PickleValue::List(vec![
            PickleValue::Bytes(vec![0xCC; 16]),
            PickleValue::Float(1000.0),
            PickleValue::Bytes(vec![0xBB; 16]),
            PickleValue::Int(5),
            PickleValue::Float(2000.0),
            PickleValue::String("TCPInterface".into()),
        ]);
        let table = PickleValue::List(vec![entry]);
        let hash = [0xAA; 16];
        assert_eq!(extract_hops_from_path_table(&table, &hash), 0);
    }
}
