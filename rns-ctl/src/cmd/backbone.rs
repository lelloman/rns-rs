use std::path::Path;
use std::process;

use crate::args::Args;
use rns_net::config;
use rns_net::pickle::PickleValue;
use rns_net::rpc::derive_auth_key;
use rns_net::storage;
use rns_net::{RpcAddr, RpcClient};
use serde_json::{json, Value};

pub fn run(args: Args) {
    if args.has("help") || args.positional.is_empty() {
        print_usage();
        return;
    }

    let json_output = args.has("j") || args.has("json");
    let mut client = connect(args.config_path());

    match args.positional.first().map(|s| s.as_str()) {
        Some("blacklist") => run_blacklist(&args, &mut client, json_output),
        Some("provider") => run_provider(&mut client, json_output),
        Some(other) => {
            eprintln!("Unknown backbone subcommand: {}", other);
            print_usage();
            process::exit(1);
        }
        None => print_usage(),
    }
}

fn run_blacklist(args: &Args, client: &mut RpcClient, json_output: bool) {
    match args.positional.get(1).map(|s| s.as_str()) {
        Some("list") => {
            let mut request = vec![(
                PickleValue::String("get".into()),
                PickleValue::String("backbone_peer_state".into()),
            )];
            if let Some(interface) = args.positional.get(2) {
                request.push((
                    PickleValue::String("interface".into()),
                    PickleValue::String(interface.clone()),
                ));
            }
            let response = rpc_call(client, PickleValue::Dict(request));
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&pickle_list_to_json(&response))
                        .unwrap_or_default()
                );
            } else {
                print_blacklist(&response);
            }
        }
        Some("clear") => {
            let interface = args.positional.get(2).cloned().unwrap_or_else(|| {
                eprintln!("Missing interface name");
                process::exit(1);
            });
            let ip = args.positional.get(3).cloned().unwrap_or_else(|| {
                eprintln!("Missing peer IP");
                process::exit(1);
            });
            let response = rpc_call(
                client,
                PickleValue::Dict(vec![
                    (
                        PickleValue::String("clear".into()),
                        PickleValue::String("backbone_peer_state".into()),
                    ),
                    (
                        PickleValue::String("interface".into()),
                        PickleValue::String(interface),
                    ),
                    (PickleValue::String("ip".into()), PickleValue::String(ip)),
                ]),
            );
            match response {
                PickleValue::Bool(true) => println!("Cleared"),
                PickleValue::Bool(false) => {
                    eprintln!("No matching backbone peer state entry");
                    process::exit(1);
                }
                _ => {
                    eprintln!("Unexpected response");
                    process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("Unknown backbone blacklist action");
            print_usage();
            process::exit(1);
        }
    }
}

fn run_provider(client: &mut RpcClient, json_output: bool) {
    let response = rpc_call(
        client,
        PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("provider_bridge_stats".into()),
        )]),
    );
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&provider_stats_to_json(&response)).unwrap_or_default()
        );
    } else {
        print_provider_stats(&response);
    }
}

fn print_blacklist(response: &PickleValue) {
    let Some(entries) = response.as_list() else {
        eprintln!("Unexpected response");
        process::exit(1);
    };
    if entries.is_empty() {
        println!("No backbone peer state entries");
        return;
    }

    println!(
        "{:<24} {:<40} {:>5} {:>9} {:>8}  {}",
        "Interface", "IP", "Conn", "BlkSecs", "Rejects", "Reason"
    );
    println!("{}", "-".repeat(96));
    for entry in entries {
        let interface = entry
            .get("interface")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let ip = entry.get("ip").and_then(|v| v.as_str()).unwrap_or("-");
        let connected = entry
            .get("connected_count")
            .and_then(|v| v.as_int())
            .unwrap_or(0);
        let blacklist = entry
            .get("blacklisted_remaining_secs")
            .and_then(|v| v.as_float())
            .map(|v| format!("{:.0}", v))
            .unwrap_or_else(|| "-".into());
        let rejects = entry
            .get("reject_count")
            .and_then(|v| v.as_int())
            .unwrap_or(0);
        let reason = entry
            .get("blacklist_reason")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        println!(
            "{:<24} {:<40} {:>5} {:>9} {:>8}  {}",
            interface, ip, connected, blacklist, rejects, reason
        );
    }
}

fn pickle_list_to_json(value: &PickleValue) -> Value {
    let Some(entries) = value.as_list() else {
        return Value::Null;
    };
    Value::Array(
        entries
            .iter()
            .map(|entry| {
                json!({
                    "interface": entry.get("interface").and_then(|v| v.as_str()),
                    "ip": entry.get("ip").and_then(|v| v.as_str()),
                    "connected_count": entry.get("connected_count").and_then(|v| v.as_int()),
                    "blacklisted_remaining_secs": entry.get("blacklisted_remaining_secs").and_then(|v| v.as_float()),
                    "blacklist_reason": entry.get("blacklist_reason").and_then(|v| v.as_str()),
                    "reject_count": entry.get("reject_count").and_then(|v| v.as_int()),
                })
            })
            .collect(),
    )
}

fn provider_stats_to_json(value: &PickleValue) -> Value {
    let Some(consumers) = value.get("consumers").and_then(|v| v.as_list()) else {
        return Value::Null;
    };

    json!({
        "connected": value.get("connected").and_then(|v| v.as_bool()),
        "consumer_count": value.get("consumer_count").and_then(|v| v.as_int()),
        "queue_max_events": value.get("queue_max_events").and_then(|v| v.as_int()),
        "queue_max_bytes": value.get("queue_max_bytes").and_then(|v| v.as_int()),
        "backlog_len": value.get("backlog_len").and_then(|v| v.as_int()),
        "backlog_bytes": value.get("backlog_bytes").and_then(|v| v.as_int()),
        "backlog_dropped_pending": value.get("backlog_dropped_pending").and_then(|v| v.as_int()),
        "backlog_dropped_total": value.get("backlog_dropped_total").and_then(|v| v.as_int()),
        "total_disconnect_count": value.get("total_disconnect_count").and_then(|v| v.as_int()),
        "consumers": consumers.iter().map(|consumer| {
            json!({
                "id": consumer.get("id").and_then(|v| v.as_int()),
                "connected": consumer.get("connected").and_then(|v| v.as_bool()),
                "queue_len": consumer.get("queue_len").and_then(|v| v.as_int()),
                "queued_bytes": consumer.get("queued_bytes").and_then(|v| v.as_int()),
                "dropped_pending": consumer.get("dropped_pending").and_then(|v| v.as_int()),
                "dropped_total": consumer.get("dropped_total").and_then(|v| v.as_int()),
                "queue_max_events": consumer.get("queue_max_events").and_then(|v| v.as_int()),
                "queue_max_bytes": consumer.get("queue_max_bytes").and_then(|v| v.as_int()),
            })
        }).collect::<Vec<_>>(),
    })
}

fn print_provider_stats(response: &PickleValue) {
    if matches!(response, PickleValue::None) {
        println!("Provider bridge disabled or unavailable");
        return;
    }

    let Some(consumers) = response.get("consumers").and_then(|v| v.as_list()) else {
        eprintln!("Unexpected response");
        process::exit(1);
    };

    println!(
        "Provider bridge: connected={} consumers={} queue_max_events={} queue_max_bytes={} backlog_len={} backlog_bytes={} backlog_dropped_pending={} backlog_dropped_total={} disconnects={}",
        response
            .get("connected")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        response
            .get("consumer_count")
            .and_then(|v| v.as_int())
            .unwrap_or(0),
        response
            .get("queue_max_events")
            .and_then(|v| v.as_int())
            .unwrap_or(0),
        response
            .get("queue_max_bytes")
            .and_then(|v| v.as_int())
            .unwrap_or(0),
        response
            .get("backlog_len")
            .and_then(|v| v.as_int())
            .unwrap_or(0),
        response
            .get("backlog_bytes")
            .and_then(|v| v.as_int())
            .unwrap_or(0),
        response
            .get("backlog_dropped_pending")
            .and_then(|v| v.as_int())
            .unwrap_or(0),
        response
            .get("backlog_dropped_total")
            .and_then(|v| v.as_int())
            .unwrap_or(0),
        response
            .get("total_disconnect_count")
            .and_then(|v| v.as_int())
            .unwrap_or(0),
    );

    if consumers.is_empty() {
        println!("No connected provider consumers");
        return;
    }

    println!(
        "{:<4} {:<9} {:>8} {:>12} {:>15} {:>13} {:>11} {:>10}",
        "ID",
        "Connected",
        "Queue",
        "QueuedBytes",
        "DroppedPending",
        "DroppedTotal",
        "MaxEvents",
        "MaxBytes"
    );
    println!("{}", "-".repeat(96));
    for consumer in consumers {
        println!(
            "{:<4} {:<9} {:>8} {:>12} {:>15} {:>13} {:>11} {:>10}",
            consumer.get("id").and_then(|v| v.as_int()).unwrap_or(0),
            if consumer
                .get("connected")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                "yes"
            } else {
                "no"
            },
            consumer
                .get("queue_len")
                .and_then(|v| v.as_int())
                .unwrap_or(0),
            consumer
                .get("queued_bytes")
                .and_then(|v| v.as_int())
                .unwrap_or(0),
            consumer
                .get("dropped_pending")
                .and_then(|v| v.as_int())
                .unwrap_or(0),
            consumer
                .get("dropped_total")
                .and_then(|v| v.as_int())
                .unwrap_or(0),
            consumer
                .get("queue_max_events")
                .and_then(|v| v.as_int())
                .unwrap_or(0),
            consumer
                .get("queue_max_bytes")
                .and_then(|v| v.as_int())
                .unwrap_or(0),
        );
    }
}

fn connect(config_path: Option<&str>) -> RpcClient {
    let config_dir = storage::resolve_config_dir(config_path.map(Path::new));
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

    let auth_key = derive_auth_key(&identity.get_private_key().unwrap_or([0u8; 64]));
    let rpc_addr = RpcAddr::Tcp(
        "127.0.0.1".into(),
        rns_config.reticulum.instance_control_port,
    );
    match RpcClient::connect(&rpc_addr, &auth_key) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Could not connect to rnsd: {}", e);
            eprintln!("Is rnsd running?");
            process::exit(1);
        }
    }
}

fn rpc_call(client: &mut RpcClient, request: PickleValue) -> PickleValue {
    match client.call(&request) {
        Ok(response) => response,
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    }
}

fn print_usage() {
    println!("Usage:");
    println!("    rns-ctl backbone blacklist list [INTERFACE] [--json]");
    println!("    rns-ctl backbone blacklist clear <INTERFACE> <IP>");
    println!("    rns-ctl backbone provider [--json]");
}
