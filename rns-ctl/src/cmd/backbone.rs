use super::{connect_rpc, rpc_call};
use crate::args::Args;
use rns_cli::exit::{Exit, Status};
use rns_net::pickle::PickleValue;
use rns_net::rpc::RpcClient;
use serde_json::{json, Value};

/// Run `rns-ctl backbone`: list or clear the backbone blacklist, or show
/// the provider bridge statistics, over the RPC socket of the node using the
/// config directory. Prints help without a command. Gives status 1 when
/// the node cannot be reached or the call fails.
pub fn run(args: Args) -> Status {
    if args.has("help") || args.positional.is_empty() {
        crate::cli::BACKBONE.print_help("rns-ctl backbone");
        return Ok(());
    }

    let json_output = args.has("j") || args.has("json");
    let mut client = connect_rpc(args.config_path())?;

    match args.positional.first().map(|s| s.as_str()) {
        Some("blacklist") => run_blacklist(&args, &mut client, json_output),
        Some("provider") => run_provider(&mut client, json_output),
        Some(other) => {
            crate::cli::BACKBONE.error(
                "rns-ctl backbone",
                &format!("Unknown backbone subcommand: {}", other),
            );
        }
        None => {
            crate::cli::BACKBONE.print_help("rns-ctl backbone");
            Ok(())
        }
    }
}

fn run_blacklist(args: &Args, client: &mut RpcClient, json_output: bool) -> Status {
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
            let response = rpc_call(client, PickleValue::Dict(request))?;
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&pickle_list_to_json(&response))
                        .unwrap_or_default()
                );
            } else {
                print_blacklist(&response)?;
            }
        }
        Some("clear") => {
            let Some(interface) = args.positional.get(2).cloned() else {
                eprintln!("Missing interface name");
                return Err(Exit::FAILURE);
            };
            let Some(ip) = args.positional.get(3).cloned() else {
                eprintln!("Missing peer IP");
                return Err(Exit::FAILURE);
            };
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
            )?;
            match response {
                PickleValue::Bool(true) => println!("Cleared"),
                PickleValue::Bool(false) => {
                    eprintln!("No matching backbone peer state entry");
                    return Err(Exit::FAILURE);
                }
                _ => {
                    eprintln!("Unexpected response");
                    return Err(Exit::FAILURE);
                }
            }
        }
        _ => {
            crate::cli::BACKBONE.error("rns-ctl backbone", "Unknown backbone blacklist action");
        }
    }
    Ok(())
}

fn run_provider(client: &mut RpcClient, json_output: bool) -> Status {
    let response = rpc_call(
        client,
        PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("provider_bridge_stats".into()),
        )]),
    )?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&provider_stats_to_json(&response)).unwrap_or_default()
        );
    } else {
        print_provider_stats(&response)?;
    }
    Ok(())
}

fn print_blacklist(response: &PickleValue) -> Status {
    let Some(entries) = response.as_list() else {
        eprintln!("Unexpected response");
        return Err(Exit::FAILURE);
    };
    if entries.is_empty() {
        println!("No backbone peer state entries");
        return Ok(());
    }

    println!(
        "{:<24} {:<40} {:>5} {:>9} {:>8}  Reason",
        "Interface", "IP", "Conn", "BlkSecs", "Rejects"
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
    Ok(())
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

fn print_provider_stats(response: &PickleValue) -> Status {
    if matches!(response, PickleValue::None) {
        println!("Provider bridge disabled or unavailable");
        return Ok(());
    }

    let Some(consumers) = response.get("consumers").and_then(|v| v.as_list()) else {
        eprintln!("Unexpected response");
        return Err(Exit::FAILURE);
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
        return Ok(());
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
    Ok(())
}
