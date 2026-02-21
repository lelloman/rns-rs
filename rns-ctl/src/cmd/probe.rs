//! Probe reachability to a Reticulum destination.
//!
//! Sends a real probe packet via RPC to a running rnsd daemon,
//! waits for the proof (delivery receipt) to measure RTT.

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
const DEFAULT_PAYLOAD_SIZE: usize = 16;

pub fn run(args: Args) {
    if args.has("version") {
        println!("rns-ctl {}", env!("FULL_VERSION"));
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
    let payload_size: usize = args.get("s")
        .or_else(|| args.get("size"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PAYLOAD_SIZE);
    let count: usize = args.get("n")
        .or_else(|| args.get("count"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let wait: f64 = args.get("w")
        .or_else(|| args.get("wait"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
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

    // First, ensure we have a path
    let timeout_dur = Duration::from_secs_f64(timeout);
    if !wait_for_path(&rpc_addr, &auth_key, &dest_hash, timeout_dur, verbosity) {
        process::exit(1);
    }

    // Send probe(s)
    let mut any_failed = false;
    for i in 0..count {
        if i > 0 && wait > 0.0 {
            std::thread::sleep(Duration::from_secs_f64(wait));
        }

        if !send_and_wait_probe(
            &rpc_addr, &auth_key, &dest_hash, payload_size, timeout_dur, verbosity,
        ) {
            any_failed = true;
        }
    }

    if any_failed {
        process::exit(1);
    }
}

/// Wait for a path to the destination, requesting it if needed.
fn wait_for_path(
    addr: &RpcAddr,
    auth_key: &[u8; 32],
    dest_hash: &[u8; 16],
    timeout: Duration,
    verbosity: u8,
) -> bool {
    // Check if path already exists
    match query_has_path(addr, auth_key, dest_hash) {
        Ok(true) => return true,
        Ok(false) => {}
        Err(e) => {
            eprintln!("RPC error: {}", e);
            return false;
        }
    }

    // Request path
    if let Err(e) = request_path(addr, auth_key, dest_hash) {
        eprintln!("RPC error requesting path: {}", e);
        return false;
    }

    eprint!("Waiting for path to {}... ", prettyhexrep(dest_hash));

    let start = Instant::now();
    while start.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(250));
        match query_has_path(addr, auth_key, dest_hash) {
            Ok(true) => {
                eprintln!("found!");
                if verbosity > 0 {
                    if let Ok(Some(info)) = query_path_info(addr, auth_key, dest_hash) {
                        eprintln!(
                            "  via {} on {}, {} hops",
                            prettyhexrep(&info.next_hop),
                            info.interface_name,
                            info.hops,
                        );
                    }
                }
                return true;
            }
            Ok(false) => continue,
            Err(_) => continue,
        }
    }

    eprintln!("timeout!");
    eprintln!(
        "Path to {} not found within {:.1}s",
        prettyhexrep(dest_hash),
        timeout.as_secs_f64(),
    );
    false
}

/// Send a probe and wait for the proof.
fn send_and_wait_probe(
    addr: &RpcAddr,
    auth_key: &[u8; 32],
    dest_hash: &[u8; 16],
    payload_size: usize,
    timeout: Duration,
    verbosity: u8,
) -> bool {
    // Send probe
    let (packet_hash, hops) = match send_probe_rpc(addr, auth_key, dest_hash, payload_size) {
        Ok(Some(result)) => result,
        Ok(None) => {
            eprintln!(
                "Could not send probe to {} (identity not known)",
                prettyhexrep(dest_hash),
            );
            return false;
        }
        Err(e) => {
            eprintln!("RPC error sending probe: {}", e);
            return false;
        }
    };

    if verbosity > 0 {
        if let Ok(Some(info)) = query_path_info(addr, auth_key, dest_hash) {
            println!(
                "Sent probe ({} bytes) to {} via {} on {}",
                payload_size,
                prettyhexrep(dest_hash),
                prettyhexrep(&info.next_hop),
                info.interface_name,
            );
        } else {
            println!(
                "Sent probe ({} bytes) to {}",
                payload_size,
                prettyhexrep(dest_hash),
            );
        }
    } else {
        println!(
            "Sent probe ({} bytes) to {}",
            payload_size,
            prettyhexrep(dest_hash),
        );
    }

    // Poll for proof
    let start = Instant::now();
    while start.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(100));
        match check_proof_rpc(addr, auth_key, &packet_hash) {
            Ok(Some(rtt)) => {
                let rtt_ms = rtt * 1000.0;
                println!(
                    "Probe reply received in {:.0}ms, {} hops",
                    rtt_ms, hops,
                );
                return true;
            }
            Ok(None) => continue,
            Err(_) => continue,
        }
    }

    println!("Probe timed out after {:.1}s", timeout.as_secs_f64());
    false
}

// --- RPC helpers ---

fn query_has_path(
    addr: &RpcAddr,
    auth_key: &[u8; 32],
    dest_hash: &[u8; 16],
) -> Result<bool, String> {
    let mut client = RpcClient::connect(addr, auth_key)
        .map_err(|e| format!("RPC connect: {}", e))?;
    let response = client.call(&PickleValue::Dict(vec![
        (PickleValue::String("get".into()), PickleValue::String("next_hop".into())),
        (PickleValue::String("destination_hash".into()), PickleValue::Bytes(dest_hash.to_vec())),
    ])).map_err(|e| format!("RPC call: {}", e))?;
    Ok(response.as_bytes().map_or(false, |b| b.len() == 16))
}

fn request_path(
    addr: &RpcAddr,
    auth_key: &[u8; 32],
    dest_hash: &[u8; 16],
) -> Result<(), String> {
    let mut client = RpcClient::connect(addr, auth_key)
        .map_err(|e| format!("RPC connect: {}", e))?;
    let _ = client.call(&PickleValue::Dict(vec![
        (PickleValue::String("request_path".into()), PickleValue::Bytes(dest_hash.to_vec())),
    ])).map_err(|e| format!("RPC call: {}", e))?;
    Ok(())
}

fn send_probe_rpc(
    addr: &RpcAddr,
    auth_key: &[u8; 32],
    dest_hash: &[u8; 16],
    payload_size: usize,
) -> Result<Option<([u8; 32], u8)>, String> {
    let mut client = RpcClient::connect(addr, auth_key)
        .map_err(|e| format!("RPC connect: {}", e))?;
    let response = client.call(&PickleValue::Dict(vec![
        (PickleValue::String("send_probe".into()), PickleValue::Bytes(dest_hash.to_vec())),
        (PickleValue::String("size".into()), PickleValue::Int(payload_size as i64)),
    ])).map_err(|e| format!("RPC call: {}", e))?;

    match &response {
        PickleValue::Dict(entries) => {
            let packet_hash = entries.iter()
                .find(|(k, _)| *k == PickleValue::String("packet_hash".into()))
                .and_then(|(_, v)| v.as_bytes());
            let hops = entries.iter()
                .find(|(k, _)| *k == PickleValue::String("hops".into()))
                .and_then(|(_, v)| v.as_int());
            if let (Some(ph), Some(h)) = (packet_hash, hops) {
                if ph.len() >= 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&ph[..32]);
                    Ok(Some((hash, h as u8)))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        }
        _ => Ok(None),
    }
}

fn check_proof_rpc(
    addr: &RpcAddr,
    auth_key: &[u8; 32],
    packet_hash: &[u8; 32],
) -> Result<Option<f64>, String> {
    let mut client = RpcClient::connect(addr, auth_key)
        .map_err(|e| format!("RPC connect: {}", e))?;
    let response = client.call(&PickleValue::Dict(vec![
        (PickleValue::String("check_proof".into()), PickleValue::Bytes(packet_hash.to_vec())),
    ])).map_err(|e| format!("RPC call: {}", e))?;

    match &response {
        PickleValue::Float(rtt) => Ok(Some(*rtt)),
        _ => Ok(None),
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

    // Query hop count
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
    println!("Send a probe packet to a Reticulum destination and measure RTT.");
    println!();
    println!("Arguments:");
    println!("  <destination_hash>    Hex hash of the destination (32 chars)");
    println!();
    println!("Options:");
    println!("  -c, --config PATH     Config directory path");
    println!("  -t, --timeout SECS    Timeout in seconds (default: 15)");
    println!("  -s, --size BYTES      Probe payload size (default: 16)");
    println!("  -n, --count N         Number of probes to send (default: 1)");
    println!("  -w, --wait SECS       Seconds between probes (default: 0)");
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
