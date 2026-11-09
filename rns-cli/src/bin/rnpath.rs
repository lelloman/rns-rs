//! rnpath - Display and manage Reticulum path table
//!
//! Connects to a running rnsd via RPC to query/modify the path table.

use std::path::Path;
use std::process;
use std::time::Duration;

use rns_cli::args::Args;
use rns_cli::format::{prettycost, prettyfrequency, prettyhexrep, prettytime};
use rns_net::config;
use rns_net::pickle::PickleValue;
use rns_net::rpc::derive_auth_key;
use rns_net::storage;
use rns_net::{RpcAddr, RpcClient};

const VERSION: &str = env!("FULL_VERSION");

#[allow(dead_code)]
fn main() {
    run_with_args(Args::parse(), "rnpath", "rnpath");
}

pub fn run_with_args(args: Args, usage_name: &str, version_name: &str) {
    if args.has("version") {
        println!("{} {}", version_name, VERSION);
        return;
    }

    if args.has("help") || args.has("h") {
        print_usage(usage_name);
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
    let show_usage = args.has("u") || args.has("usage");
    let show_rates = args.has("r");
    let drop_hash = args.get("d").map(|s| s.to_string());
    let drop_via = args.get("x").map(|s| s.to_string());
    let drop_queues = args.has("D");
    let json_output = args.has("j");
    let max_hops: Option<u8> = args.get("m").and_then(|s| s.parse().ok());
    let show_blackholed = args.has("blackholed") || args.has("b");
    let blackhole_hash = args
        .get("B")
        .or_else(|| args.get("blackhole"))
        .map(|s| s.to_string());
    let unblackhole_hash = args
        .get("U")
        .or_else(|| args.get("unblackhole"))
        .map(|s| s.to_string());
    let duration_hours: Option<f64> = args.get("duration").and_then(|s| s.parse().ok());
    let reason = args.get("reason").map(|s| s.to_string());
    let remote_blackholed = args.has("p") || args.has("blackholed-list");
    let remote_timeout = args
        .get("W")
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(rns_core::constants::PATH_REQUEST_TIMEOUT);
    let management_identity = args.get("i").or_else(|| args.get("identity"));
    let remote_hash = args.get("R").map(|s| s.to_string());

    // Remote management query via -R flag
    if let Some(ref hash_str) = remote_hash {
        remote_path(
            hash_str,
            management_identity,
            config_path.as_deref(),
            remote_timeout,
            show_table,
            show_usage,
            show_rates,
            remote_blackholed,
            max_hops,
            args.positional.first().map(String::as_str),
            drop_hash.as_deref(),
            drop_via.as_deref(),
            drop_queues,
            blackhole_hash.as_deref(),
            unblackhole_hash.as_deref(),
        );
        return;
    }

    // Load config
    let config_dir =
        storage::resolve_config_dir(config_path.as_ref().map(|s| Path::new(s.as_str())));
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

    let identity = match storage::load_rpc_identity(&paths) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Error loading identity: {}", e);
            process::exit(1);
        }
    };

    let auth_key = derive_auth_key(&identity.get_private_key().unwrap_or([0u8; 64]));

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
        show_path_table(&mut client, json_output, max_hops, show_usage);
    } else if show_rates {
        show_rate_table(&mut client, json_output);
    } else if let Some(hash_str) = blackhole_hash {
        do_blackhole(&mut client, &hash_str, duration_hours, reason);
    } else if let Some(hash_str) = unblackhole_hash {
        do_unblackhole(&mut client, &hash_str);
    } else if show_blackholed {
        show_blackholed_list(&mut client, identity.hash());
    } else if let Some(hash_str) = drop_hash {
        drop_path(&mut client, &hash_str);
    } else if let Some(hash_str) = drop_via {
        drop_all_via(&mut client, &hash_str);
    } else if drop_queues {
        drop_announce_queues(&mut client);
    } else if let Some(hash_str) = args.positional.first() {
        lookup_path(&mut client, hash_str);
    } else {
        print_usage(usage_name);
    }
}

fn parse_hex_hash(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
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

fn show_path_table(
    client: &mut RpcClient,
    _json_output: bool,
    max_hops: Option<u8>,
    show_usage: bool,
) {
    let max_hops_val = match max_hops {
        Some(h) => PickleValue::Int(h as i64),
        None => PickleValue::None,
    };

    let response = match client.call(&PickleValue::Dict(vec![
        (
            PickleValue::String("get".into()),
            PickleValue::String("path_table".into()),
        ),
        (PickleValue::String("max_hops".into()), max_hops_val),
    ])) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    };

    render_path_table(&response, show_usage);
}

fn render_path_table(response: &PickleValue, show_usage: bool) {
    if let Some(entries) = response.as_list() {
        if entries.is_empty() {
            println!("Path table is empty");
            return;
        }
        println!(
            "{:<34} {:>6} {:<34} {:<10} Interface",
            "Destination", "Hops", "Via", "Expires"
        );
        println!("{}", "-".repeat(100));
        let mut entries: Vec<&PickleValue> = entries.iter().collect();
        if show_usage {
            entries.sort_by(|a, b| {
                let used_a = a.get("used").and_then(|v| v.as_float()).unwrap_or(0.0);
                let used_b = b.get("used").and_then(|v| v.as_float()).unwrap_or(0.0);
                used_b
                    .partial_cmp(&used_a)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }
        for entry in entries {
            let hash = entry
                .get("hash")
                .and_then(|v| v.as_bytes())
                .map(prettyhexrep)
                .unwrap_or_default();
            let hops = entry.get("hops").and_then(|v| v.as_int()).unwrap_or(0);
            let via = entry
                .get("via")
                .and_then(|v| v.as_bytes())
                .map(prettyhexrep)
                .unwrap_or_default();
            let expires = entry
                .get("expires")
                .and_then(|v| v.as_float())
                .map(|e| {
                    let remaining = e - rns_net::time::now();
                    if remaining > 0.0 {
                        prettytime(remaining)
                    } else {
                        "expired".into()
                    }
                })
                .unwrap_or_default();
            let interface = entry
                .get("interface")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let usage = if !show_usage {
                String::new()
            } else {
                match entry.get("used").and_then(|v| v.as_float()) {
                    Some(used) if used > 0.0 => {
                        let age = rns_net::time::now() - used;
                        format!(", last used {} ago", prettytime(age.max(0.0)))
                    }
                    Some(_) => ", never used".into(),
                    None => ", no usage info".into(),
                }
            };
            println!(
                "{:<34} {:>6} {:<34} {:<10} {} {}{}",
                &hash[..hash.len().min(32)],
                hops,
                &via[..via.len().min(32)],
                expires,
                interface,
                path_costs(entry),
                usage,
            );
        }
    } else {
        eprintln!("Unexpected response format");
    }
}

/// The destination's stamp value and link request cost, in upstream's
/// `rnpath` notation since rgit `21170877` (`(dv:25.000/lc:19.199)`), with
/// `n` for what the daemon does not know or does not report.
fn path_costs(entry: &PickleValue) -> String {
    let number = |key: &str| {
        entry
            .get(key)
            .and_then(|v| v.as_float().or_else(|| v.as_int().map(|v| v as f64)))
    };
    format!(
        "(dv:{}/lc:{})",
        prettycost(number("value")),
        prettycost(number("lr_cost"))
    )
}

fn show_rate_table(client: &mut RpcClient, _json_output: bool) {
    let response = match client.call(&PickleValue::Dict(vec![(
        PickleValue::String("get".into()),
        PickleValue::String("rate_table".into()),
    )])) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    };

    render_rate_table(&response);
}

fn render_rate_table(response: &PickleValue) {
    if let Some(entries) = response.as_list() {
        if entries.is_empty() {
            println!("Rate table is empty");
            return;
        }
        println!(
            "{:<34} {:>12} {:>12} {:>16}",
            "Destination", "Violations", "Frequency", "Blocked Until"
        );
        println!("{}", "-".repeat(78));
        for entry in entries {
            let hash = entry
                .get("hash")
                .and_then(|v| v.as_bytes())
                .map(prettyhexrep)
                .unwrap_or_default();
            let violations = entry
                .get("rate_violations")
                .and_then(|v| v.as_int())
                .unwrap_or(0);
            let blocked = entry
                .get("blocked_until")
                .and_then(|v| v.as_float())
                .map(|b| {
                    let remaining = b - rns_net::time::now();
                    if remaining > 0.0 {
                        pretty_date_elapsed(remaining as u64)
                    } else {
                        "not blocked".into()
                    }
                })
                .unwrap_or_default();

            // Compute hourly frequency from timestamps
            let freq_str =
                if let Some(timestamps) = entry.get("timestamps").and_then(|v| v.as_list()) {
                    let ts: Vec<f64> = timestamps.iter().filter_map(|v| v.as_float()).collect();
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

            println!(
                "{:<34} {:>12} {:>12} {:>16}",
                &hash[..hash.len().min(32)],
                violations,
                freq_str,
                blocked,
            );
        }
    }
}

fn pretty_date_elapsed(seconds: u64) -> String {
    let days = seconds / 86_400;
    if days == 0 {
        if seconds < 60 {
            return format!("{} seconds", seconds);
        }
        if seconds < 70 {
            return "1 minute".into();
        }
        if seconds < 7200 {
            return format!("{} minutes", seconds / 60);
        }
        return format!("{} hours", seconds / 3600);
    }
    if days == 1 {
        return "1 day".into();
    }
    if days < 7 {
        return format!("{} days", days);
    }
    if days < 31 {
        return format!("{} weeks", days / 7);
    }
    if days < 365 {
        return format!("{} months", days / 30);
    }
    format!("{} years", days / 365)
}

fn show_blackholed_list(client: &mut RpcClient, local_identity: &[u8; 16]) {
    // Upstream's call first; an older rns-rs instance only knows `blackholed`.
    let response = match client.call(&PickleValue::Dict(vec![(
        PickleValue::String("get".into()),
        PickleValue::String("blackholed_identities".into()),
    )])) {
        Ok(PickleValue::None) | Err(_) => client.call(&PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("blackholed".into()),
        )])),
        Ok(response) => Ok(response),
    };
    match response {
        Ok(response) => render_blackholed_list(&response, Some(local_identity)),
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    }
}

/// One blackhole entry, from either upstream's dict (`hash -> {"source",
/// "until", "reason"}`) or the list of dicts older rns-rs instances and the
/// remote list reader produce.
struct BlackholeLine {
    identity_hash: Vec<u8>,
    until: Option<f64>,
    reason: Option<String>,
    source: Option<Vec<u8>>,
}

fn blackhole_line(identity_hash: Vec<u8>, fields: &PickleValue) -> BlackholeLine {
    let until = fields
        .get("until")
        .and_then(|v| v.as_float().or_else(|| v.as_int().map(|i| i as f64)))
        .or_else(|| {
            fields
                .get("expires")
                .and_then(|v| v.as_float())
                .filter(|e| *e != 0.0)
        });
    BlackholeLine {
        identity_hash,
        until,
        reason: fields
            .get("reason")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        source: fields
            .get("source")
            .and_then(|v| v.as_bytes())
            .map(<[u8]>::to_vec),
    }
}

/// Print a blackhole list as upstream's `rnpath -b` does: `<hash>
/// blackholed for <time>|indefinitely (<reason>) by <source>`, naming the
/// source only when it is not this node.
fn render_blackholed_list(response: &PickleValue, local_identity: Option<&[u8; 16]>) {
    let lines: Vec<BlackholeLine> = match response {
        PickleValue::Dict(entries) => entries
            .iter()
            .filter_map(|(k, v)| k.as_bytes().map(|h| blackhole_line(h.to_vec(), v)))
            .collect(),
        PickleValue::List(entries) => entries
            .iter()
            .filter_map(|v| {
                v.get("identity_hash")
                    .and_then(|h| h.as_bytes())
                    .map(|h| blackhole_line(h.to_vec(), v))
            })
            .collect(),
        _ => Vec::new(),
    };
    if lines.is_empty() {
        println!("No blackholed identity data available");
        process::exit(20);
    }
    let now = rns_net::time::now();
    for line in lines {
        let until = match line.until {
            Some(until) => format!("for {}", prettytime((until - now).max(0.0))),
            None => "indefinitely".into(),
        };
        let reason = match line.reason {
            Some(reason) if !reason.is_empty() => {
                let reason: String = if reason.chars().count() > 64 {
                    reason
                        .chars()
                        .take(63)
                        .chain(std::iter::once('…'))
                        .collect()
                } else {
                    reason
                };
                format!(" ({reason})")
            }
            _ => String::new(),
        };
        let by = match (&line.source, local_identity) {
            (Some(source), Some(local)) if source.as_slice() == local.as_slice() => String::new(),
            (Some(source), _) => format!(" by {}", prettyhexrep(source)),
            (None, _) => String::new(),
        };
        println!(
            "{} blackholed {until}{reason}{by}",
            prettyhexrep(&line.identity_hash)
        );
    }
}

/// The hash as plain hex, as upstream prints it in blackhole messages.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn do_blackhole(
    client: &mut RpcClient,
    hash_str: &str,
    duration_hours: Option<f64>,
    reason: Option<String>,
) {
    let hash_bytes = match parse_hex_hash(hash_str) {
        Some(b) if b.len() == 16 => b,
        _ => {
            eprintln!("Invalid identity hash: {}", hash_str);
            process::exit(1);
        }
    };
    // Upstream's `blackhole_identity`, with an absolute expiry time.
    let until = duration_hours
        .filter(|hours| *hours > 0.0)
        .map_or(PickleValue::None, |hours| {
            PickleValue::Float(rns_net::time::now() + hours * 3600.0)
        });
    let request = PickleValue::Dict(vec![
        (
            PickleValue::String("blackhole_identity".into()),
            PickleValue::Bytes(hash_bytes.clone()),
        ),
        (PickleValue::String("until".into()), until),
        (
            PickleValue::String("reason".into()),
            reason.map_or(PickleValue::None, PickleValue::String),
        ),
    ]);
    match client.call(&request) {
        Ok(PickleValue::Bool(true)) => {
            println!("Blackholed identity {}", hex(&hash_bytes))
        }
        Ok(PickleValue::None) => {
            println!("Identity {} already blackholed", hex(&hash_bytes))
        }
        Ok(_) => println!("Could not blackhole identity {}", hex(&hash_bytes)),
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    }
}

fn do_unblackhole(client: &mut RpcClient, hash_str: &str) {
    let hash_bytes = match parse_hex_hash(hash_str) {
        Some(b) if b.len() == 16 => b,
        _ => {
            eprintln!("Invalid identity hash: {}", hash_str);
            process::exit(1);
        }
    };
    match client.call(&PickleValue::Dict(vec![(
        PickleValue::String("unblackhole_identity".into()),
        PickleValue::Bytes(hash_bytes.clone()),
    )])) {
        Ok(PickleValue::Bool(true)) => {
            println!("Lifted blackhole for identity {}", hex(&hash_bytes))
        }
        Ok(PickleValue::None) => {
            println!("Identity {} not blackholed", hex(&hash_bytes))
        }
        Ok(_) => println!("Could not unblackhole identity {}", hex(&hash_bytes)),
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
        (
            PickleValue::String("get".into()),
            PickleValue::String("next_hop".into()),
        ),
        (
            PickleValue::String("destination_hash".into()),
            PickleValue::Bytes(dest_hash.to_vec()),
        ),
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
        (
            PickleValue::String("drop".into()),
            PickleValue::String("path".into()),
        ),
        (
            PickleValue::String("destination_hash".into()),
            PickleValue::Bytes(dest_hash.to_vec()),
        ),
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
        (
            PickleValue::String("drop".into()),
            PickleValue::String("all_via".into()),
        ),
        (
            PickleValue::String("destination_hash".into()),
            PickleValue::Bytes(transport_hash.to_vec()),
        ),
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
    match client.call(&PickleValue::Dict(vec![(
        PickleValue::String("drop".into()),
        PickleValue::String("announce_queues".into()),
    )])) {
        Ok(_) => println!("Announce queues dropped"),
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn remote_path(
    hash_str: &str,
    management_identity: Option<&str>,
    config_path: Option<&str>,
    remote_timeout: f64,
    show_table: bool,
    show_usage: bool,
    show_rates: bool,
    remote_blackholed: bool,
    max_hops: Option<u8>,
    destination_filter: Option<&str>,
    drop_hash: Option<&str>,
    drop_via: Option<&str>,
    drop_queues: bool,
    blackhole_hash: Option<&str>,
    unblackhole_hash: Option<&str>,
) {
    if drop_hash.is_some()
        || drop_via.is_some()
        || drop_queues
        || blackhole_hash.is_some()
        || unblackhole_hash.is_some()
    {
        eprintln!(
            "{}",
            rns_net::remote_management::RemoteManagementError::Unsupported(
                "remote path mutations are not implemented upstream in Reticulum 1.2.7".into(),
            )
        );
        process::exit(1);
    }

    let transport_hash = match rns_net::remote_management::parse_transport_identity_hash(hash_str) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    };
    let management_identity_path = match management_identity {
        Some(path) => Some(Path::new(path)),
        None if remote_blackholed => None,
        None => {
            eprintln!(
                "{}",
                rns_net::remote_management::RemoteManagementError::MissingIdentity
            );
            process::exit(1);
        }
    };
    let destination_filter = destination_filter.map(|hash| {
        parse_fixed_hash(hash, "destination").unwrap_or_else(|e| {
            eprintln!("{e}");
            process::exit(1);
        })
    });
    let timeout = Duration::from_secs_f64(remote_timeout.max(0.2));
    let mut client = match rns_net::remote_management::RemoteManagementClient::connect(
        config_path.map(Path::new),
        management_identity_path,
        timeout,
    ) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    };

    let result = if show_rates {
        client.rate_table(transport_hash, destination_filter)
    } else if remote_blackholed {
        client.published_blackhole_list(transport_hash)
    } else if show_table || destination_filter.is_some() || max_hops.is_some() {
        client.path_table(transport_hash, destination_filter, max_hops)
    } else {
        eprintln!("Remote path mode requires -t, -r, or -p/--blackholed-list");
        process::exit(1);
    };

    match result {
        Ok(response) if show_rates => render_rate_table(&response),
        Ok(response) if remote_blackholed => render_blackholed_list(&response, None),
        Ok(response) => render_path_table(&response, show_usage),
        Err(e) => {
            eprintln!("Remote path error: {e}");
            process::exit(1);
        }
    }
}

fn parse_fixed_hash(s: &str, label: &str) -> Result<[u8; 16], String> {
    let bytes = parse_hex_hash(s).ok_or_else(|| format!("Invalid {label} hash: {s}"))?;
    if bytes.len() < 16 {
        return Err(format!("Invalid {label} hash: {s}"));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[..16]);
    Ok(out)
}

fn print_usage(usage_name: &str) {
    println!("Usage: {usage_name} [OPTIONS] [DESTINATION_HASH]");
    println!();
    println!("Options:");
    println!("  --config PATH, -c PATH  Path to config directory");
    println!("  -t                      Show path table");
    println!("  -u, --usage             Show and sort by last path use");
    println!("  -m HOPS                 Filter path table by max hops");
    println!("  -r                      Show rate table");
    println!("  -d HASH                 Drop path for destination");
    println!("  -x HASH                 Drop all paths via transport");
    println!("  -D                      Drop all announce queues");
    println!("  -b                      Show blackholed identities");
    println!("  -p, --blackholed-list   View published remote blackhole list with -R");
    println!("  -B HASH                 Blackhole an identity");
    println!("  -U HASH                 Remove identity from blackhole list");
    println!("  --duration HOURS        Blackhole duration (default: permanent)");
    println!("  --reason TEXT           Reason for blackholing");
    println!("  -R HASH                 Query remote transport identity via management link");
    println!("  -i PATH                 Identity file for remote management");
    println!("  -W SECONDS              Timeout for remote path queries");
    println!("  -j                      JSON output");
    println!("  -v                      Increase verbosity");
    println!("  --version               Print version and exit");
    println!("  --help, -h              Print this help");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rnpath_pretty_date_matches_upstream_minute_boundaries() {
        assert_eq!(pretty_date_elapsed(0), "0 seconds");
        assert_eq!(pretty_date_elapsed(9), "9 seconds");
        assert_eq!(pretty_date_elapsed(59), "59 seconds");
        assert_eq!(pretty_date_elapsed(60), "1 minute");
        assert_eq!(pretty_date_elapsed(69), "1 minute");
        assert_eq!(pretty_date_elapsed(70), "1 minutes");
        assert_eq!(pretty_date_elapsed(119), "1 minutes");
        assert_eq!(pretty_date_elapsed(120), "2 minutes");
        assert_eq!(pretty_date_elapsed(3600), "60 minutes");
        assert_eq!(pretty_date_elapsed(7199), "119 minutes");
        assert_eq!(pretty_date_elapsed(7200), "2 hours");
    }

    #[test]
    fn rnpath_path_costs_use_upstream_notation() {
        let entry = |value: PickleValue, lr_cost: PickleValue| {
            PickleValue::Dict(vec![
                (PickleValue::String("value".into()), value),
                (PickleValue::String("lr_cost".into()), lr_cost),
            ])
        };
        assert_eq!(
            path_costs(&entry(
                PickleValue::Float(25.0),
                PickleValue::Float(4915.0 / 256.0)
            )),
            "(dv:25.000/lc:19.199)"
        );
        assert_eq!(
            path_costs(&entry(PickleValue::Float(0.0), PickleValue::None)),
            "(dv:0.000/lc:n)"
        );
        // A daemon from before 21170877 sends neither key.
        assert_eq!(path_costs(&PickleValue::Dict(Vec::new())), "(dv:n/lc:n)");
    }

    #[test]
    fn rnpath_pretty_date_matches_upstream_day_ranges() {
        assert_eq!(pretty_date_elapsed(86_400), "1 day");
        assert_eq!(pretty_date_elapsed(2 * 86_400), "2 days");
        assert_eq!(pretty_date_elapsed(7 * 86_400), "1 weeks");
        assert_eq!(pretty_date_elapsed(31 * 86_400), "1 months");
        assert_eq!(pretty_date_elapsed(365 * 86_400), "1 years");
    }
}
