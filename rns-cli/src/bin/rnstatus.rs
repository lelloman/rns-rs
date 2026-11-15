//! rnstatus - Display Reticulum network interface status
//!
//! Connects to a running rnsd via RPC and displays interface statistics.

use std::cmp::Ordering;
use std::path::Path;
use std::process;
use std::time::{Duration, Instant};

use rns_cli::args::{Args, Opt, OptionSpec};
use rns_cli::format::{
    prettycost, prettyfrequency, prettyhexrep, prettytime, python_float, size_str, speed_str,
    upstream_prettytime_compact,
};
use rns_net::config;
use rns_net::pickle::PickleValue;
use rns_net::rpc::derive_auth_key;
use rns_net::storage;
use rns_net::{RpcAddr, RpcClient};

const VERSION: &str = env!("FULL_VERSION");
const MONITOR_MIN_SLEEP: Duration = Duration::from_millis(200);

/// upstream rnstatus's options, and the Rust-only `-c` for `--config`.
/// `-q` is `--queues` here, not a quiet counter.
pub const OPTIONS: OptionSpec = OptionSpec {
    options: &[
        Opt::value("", "config"),
        Opt::value("", "attach"),
        Opt::value("", "detach"),
        Opt::value("", "reload"),
        Opt::flag("a", "all"),
        Opt::flag("A", "announce-stats"),
        Opt::flag("P", "pr-stats"),
        Opt::flag("F", "filter-stats"),
        Opt::flag("l", "link-stats"),
        Opt::flag("B", "burst"),
        Opt::flag("b", "blocked-ips"),
        Opt::flag("t", "totals"),
        Opt::flag("T", "tunnels"),
        Opt::flag("p", "pps"),
        Opt::flag("q", "queues"),
        Opt::flag("z", "profiling"),
        Opt::value("s", "sort"),
        Opt::flag("r", "reverse"),
        Opt::flag("j", "json"),
        Opt::value("R", ""),
        Opt::value("i", ""),
        Opt::value("w", ""),
        Opt::flag("d", "discovered"),
        Opt::flag("D", ""),
        Opt::flag("", "show-stale"),
        Opt::flag("", "show-unknown"),
        Opt::flag("m", "monitor"),
        Opt::value("I", "monitor-interval"),
        Opt::count("v", "verbose"),
        Opt::value("c", ""),
        Opt::value("", "identity").rust_only(),
    ],
};

#[allow(dead_code)]
fn main() {
    rns_cli::stdout::exit_quietly_on_closed_stdout();
    run_with_args(Args::parse_spec(&OPTIONS), "rnstatus", "rnstatus");
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
    let show_pps = args.has("p") || args.has("pps");
    let show_links = args.has("l");
    let show_announces = args.has("A");
    let show_pr_stats = args.has("P") || args.has("pr-stats");
    let show_filtered = args.has("F") || args.has("filter-stats");
    let show_tunnels = args.has("T") || args.has("tunnels");
    let show_bursts = args.has("B") || args.has("burst");
    let show_blocked_ips = args.has("b") || args.has("blocked-ips");
    let show_profiling = args.has("z") || args.has("profiling");
    // `q` is the queue statistics flag, as upstream has it; rns-ctl's
    // shared parser counts it as quiet.
    let show_queues = args.has("queues") || args.quiet > 0;
    let monitor_mode = args.has("m");
    let monitor_interval: f64 = args.get("I").and_then(|s| s.parse().ok()).unwrap_or(1.0);
    let remote_timeout = args
        .get("w")
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(rns_core::constants::PATH_REQUEST_TIMEOUT);
    let management_identity = args.get("i").or_else(|| args.get("identity"));
    let remote_hash = args.get("R").map(|s| s.to_string());
    let show_discovered = args.has("d");
    let show_discovered_config = args.has("D");
    let show_stale = args.has("show-stale");
    let show_unknown = args.has("show-unknown");
    let filter = args.positional.first().cloned();
    let management_actions: Vec<_> = ["attach", "detach", "reload"]
        .into_iter()
        .filter_map(|operation| args.get(operation).map(|name| (operation, name)))
        .collect();
    if management_actions.len() > 1 || (remote_hash.is_some() && !management_actions.is_empty()) {
        eprintln!("Choose one local interface management action");
        process::exit(1);
    }

    // Remote management query via -R flag
    if let Some(ref hash_str) = remote_hash {
        remote_status(
            hash_str,
            management_identity,
            config_path.as_deref(),
            remote_timeout,
            show_links,
            json_output,
            monitor_mode,
            monitor_interval,
            show_all,
            sort_by.as_deref(),
            reverse,
            filter.as_deref(),
            show_totals,
            show_pps,
            show_announces,
            show_pr_stats,
            show_filtered,
            show_tunnels,
            show_bursts,
            show_blocked_ips,
            show_queues,
            show_profiling,
        );
        return;
    }

    // Discovered interfaces query via -d or -D flag
    if (show_discovered || show_discovered_config) && management_actions.is_empty() {
        // Load config to get RPC address and auth key
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

        let auth_key = rns_config
            .reticulum
            .rpc_key
            .unwrap_or_else(|| derive_auth_key(&identity.get_private_key().unwrap_or([0u8; 64])));

        let rpc_addr = RpcAddr::for_shared_instance(&rns_config.reticulum);

        let mut client = match RpcClient::connect(&rpc_addr, &auth_key) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Could not connect to rnsd: {}", e);
                eprintln!("Is rnsd running?");
                process::exit(1);
            }
        };

        show_discovered_interfaces(
            &mut client,
            show_discovered_config,
            json_output,
            show_stale,
            show_unknown,
        );
        return;
    }

    // Load config to get RPC address and auth key
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

    // Load identity to derive auth key
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

    let auth_key = rns_config
        .reticulum
        .rpc_key
        .unwrap_or_else(|| derive_auth_key(&identity.get_private_key().unwrap_or([0u8; 64])));

    let rpc_addr = RpcAddr::for_shared_instance(&rns_config.reticulum);

    if let Some((operation, name)) = management_actions.first().copied() {
        let mut client = match RpcClient::connect(&rpc_addr, &auth_key) {
            Ok(client) => client,
            Err(error) => {
                eprintln!("Could not connect to rnsd: {error}");
                process::exit(1);
            }
        };
        let rpc_operation = format!("{operation}_interface");
        let request = PickleValue::Dict(vec![
            (
                PickleValue::String("manage".into()),
                PickleValue::String(rpc_operation),
            ),
            (
                PickleValue::String("name".into()),
                PickleValue::String(name.into()),
            ),
        ]);
        let result = client.call(&request).unwrap_or_else(|error| {
            eprintln!("RPC error: {error}");
            process::exit(1);
        });
        match result {
            PickleValue::Bool(true) => println!("Interface {name} was {operation}ed"),
            PickleValue::None => {
                eprintln!("The interface {name} does not exist");
                process::exit(1);
            }
            _ => {
                eprintln!("Could not {operation} interface {name}");
                process::exit(1);
            }
        }
        return;
    }

    loop {
        let monitor_started = Instant::now();

        // Connect to RPC server
        let mut client = match RpcClient::connect(&rpc_addr, &auth_key) {
            Ok(c) => c,
            Err(e) => {
                if monitor_mode {
                    eprintln!("Could not connect to rnsd: {} — retrying...", e);
                    std::thread::sleep(monitor_sleep_duration(
                        monitor_interval,
                        monitor_started.elapsed(),
                    ));
                    continue;
                }
                eprintln!("Could not connect to rnsd: {}", e);
                eprintln!("Is rnsd running?");
                process::exit(1);
            }
        };

        // Request interface stats
        let response = match client.call(&PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("interface_stats".into()),
        )])) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("RPC error: {}", e);
                if monitor_mode {
                    std::thread::sleep(monitor_sleep_duration(
                        monitor_interval,
                        monitor_started.elapsed(),
                    ));
                    continue;
                }
                process::exit(1);
            }
        };

        // Query link count if requested
        let link_count = if show_links {
            match client.call(&PickleValue::Dict(vec![(
                PickleValue::String("get".into()),
                PickleValue::String("link_count".into()),
            )])) {
                Ok(r) => r.as_int(),
                Err(_) => None,
            }
        } else {
            None
        };
        let active_link_count = if show_links {
            match client.call(&PickleValue::Dict(vec![(
                PickleValue::String("get".into()),
                PickleValue::String("active_link_count".into()),
            )])) {
                Ok(r) => r.as_int(),
                Err(_) => None,
            }
        } else {
            None
        };
        let profiling_results = if show_profiling {
            client
                .call(&PickleValue::Dict(vec![(
                    PickleValue::String("get".into()),
                    PickleValue::String("profiling_results".into()),
                )]))
                .ok()
                .filter(|value| !matches!(value, PickleValue::None))
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
                StatusDisplayOptions {
                    show_all,
                    sort_by: sort_by.as_deref(),
                    reverse,
                    filter: filter.as_deref(),
                    show_totals,
                    show_pps,
                    show_announces,
                    show_pr_stats,
                    show_filtered,
                    show_tunnels,
                    show_bursts,
                    show_blocked_ips,
                    show_queues,
                },
            );
            if let Some(results) = profiling_results.as_ref() {
                print_profiling_results(results);
            }
        }

        if let Some(count) = link_count {
            println!("{}", link_status_line(count, active_link_count));
            println!();
        }

        if !monitor_mode {
            break;
        }

        std::thread::sleep(monitor_sleep_duration(
            monitor_interval,
            monitor_started.elapsed(),
        ));
    }
}

fn monitor_sleep_duration(interval_secs: f64, elapsed: Duration) -> Duration {
    let interval = Duration::from_secs_f64(interval_secs);
    interval
        .checked_sub(elapsed)
        .unwrap_or(MONITOR_MIN_SLEEP)
        .max(MONITOR_MIN_SLEEP)
}

struct StatusDisplayOptions<'a> {
    show_all: bool,
    sort_by: Option<&'a str>,
    reverse: bool,
    filter: Option<&'a str>,
    show_totals: bool,
    show_pps: bool,
    show_announces: bool,
    show_pr_stats: bool,
    show_filtered: bool,
    show_tunnels: bool,
    show_bursts: bool,
    show_blocked_ips: bool,
    show_queues: bool,
}

fn print_status(response: &PickleValue, options: StatusDisplayOptions<'_>) {
    let StatusDisplayOptions {
        show_all,
        sort_by,
        reverse,
        filter,
        show_totals,
        show_pps,
        show_announces,
        show_pr_stats,
        show_filtered,
        show_tunnels,
        show_bursts,
        show_blocked_ips,
        show_queues,
    } = options;
    // Print transport info
    if let Some(PickleValue::Bool(true)) = response.get("transport_enabled") {
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

        if !show_all {
            iface_list.retain(|iface| !hidden_by_default(iface));
        }

        // Apply filter
        if let Some(f) = filter {
            iface_list.retain(|iface| {
                let name = iface.get("name").and_then(|v| v.as_str()).unwrap_or("");
                name.to_lowercase().contains(&f.to_lowercase())
            });
        }
        if show_bursts {
            iface_list.retain(|iface| interface_has_active_burst(iface));
        }

        // Sort if requested
        if let Some(sort_key) = sort_by {
            iface_list.sort_by(|a, b| {
                let cmp = compare_sort_values(
                    &interface_sort_value(a, sort_key),
                    &interface_sort_value(b, sort_key),
                );
                if reverse {
                    cmp.reverse()
                } else {
                    cmp
                }
            });
        }

        for iface in &iface_list {
            let name = iface
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");
            let status = iface
                .get("status")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let rxb = iface.get("rxb").and_then(|v| v.as_int()).unwrap_or(0) as u64;
            let txb = iface.get("txb").and_then(|v| v.as_int()).unwrap_or(0) as u64;
            let bitrate = iface
                .get("bitrate")
                .and_then(|v| v.as_int())
                .map(|n| n as u64);
            let mtu = iface
                .get("mtu")
                .and_then(|v| v.as_int())
                .and_then(|n| u32::try_from(n).ok());
            let mode = iface.get("mode").and_then(|v| v.as_int()).unwrap_or(0) as u8;
            let gravity = iface
                .get("gravity")
                .and_then(|value| value.as_int())
                .unwrap_or(0);
            let started = iface
                .get("started")
                .and_then(|v| v.as_float())
                .unwrap_or(0.0);

            let announces_to_internal = iface
                .get("announces_to_internal")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            let mode_str = interface_mode_label(mode, announces_to_internal);

            println!(" {}", name);
            println!(
                "    Status    : {}",
                interface_status_label(status, gravity)
            );
            println!("    Mode      : {}", mode_str);
            if let Some(line) = interface_rate_line(bitrate, mtu) {
                println!("{line}");
            }
            if show_tunnels {
                for line in [tunnel_id_line(iface), remote_transport_line(iface)]
                    .into_iter()
                    .flatten()
                {
                    println!("{line}");
                }
            }
            for line in device_status_lines(iface, rns_net::time::now()) {
                println!("{line}");
            }
            println!(
                "    Traffic   : {}{} \u{2191}  {} \u{2193}",
                size_str(txb),
                transmit_buffer_suffix(iface),
                size_str(rxb),
            );
            if show_filtered {
                println!("{}", filtered_status_line(iface));
            }
            if let Some(line) = tx_drop_status_line(iface) {
                println!("{line}");
            }
            for line in violation_status_lines(iface) {
                println!("{line}");
            }
            if started > 0.0 {
                let uptime = rns_net::time::now() - started;
                if uptime > 0.0 {
                    println!("    Uptime    : {}", prettytime(uptime));
                }
            }
            for line in client_status_lines(iface, show_blocked_ips) {
                println!("{}", line);
            }
            if show_announces {
                let ia_freq = iface
                    .get("ia_freq")
                    .and_then(|v| v.as_float())
                    .unwrap_or(0.0);
                let oa_freq = iface
                    .get("oa_freq")
                    .and_then(|v| v.as_float())
                    .unwrap_or(0.0);
                let clients = iface
                    .get("clients")
                    .and_then(|v| v.as_int())
                    .filter(|n| *n > 0)
                    .map(|n| n as u64);
                let peers = iface
                    .get("peers")
                    .and_then(|v| v.as_int())
                    .filter(|n| *n > 0)
                    .map(|n| n as u64);
                let ar_target = iface
                    .get("announce_rate_target")
                    .and_then(|v| v.as_number());
                let ar_penalty = iface
                    .get("announce_rate_penalty")
                    .and_then(|v| v.as_number());
                let ar_grace = iface.get("announce_rate_grace").and_then(|v| v.as_int());
                let flow = interface_flow_rates(iface, "arxs", "atxs");
                let lines = announce_status_lines(
                    ia_freq,
                    oa_freq,
                    clients,
                    peers,
                    AnnounceRateControl {
                        target: ar_target,
                        penalty: ar_penalty,
                        grace: ar_grace,
                    },
                    flow,
                );
                let arxc = iface.get("arxc").and_then(|v| v.as_int()).unwrap_or(0);
                let atxc = iface.get("atxc").and_then(|v| v.as_int()).unwrap_or(0);
                let afrxc = iface.get("afrxc").and_then(|v| v.as_int()).unwrap_or(0);
                let lines = traffic_count_lines("Announces", arxc, atxc, lines);
                for line in with_filtered_announces(lines, arxc, atxc, afrxc) {
                    println!("{}", line);
                }
            }
            if show_pr_stats {
                let ip_freq = iface
                    .get("ip_freq")
                    .and_then(|v| v.as_float())
                    .unwrap_or(0.0);
                let op_freq = iface
                    .get("op_freq")
                    .and_then(|v| v.as_float())
                    .unwrap_or(0.0);
                let clients = iface
                    .get("clients")
                    .and_then(|v| v.as_int())
                    .filter(|n| *n > 0)
                    .map(|n| n as u64);
                let peers = iface
                    .get("peers")
                    .and_then(|v| v.as_int())
                    .filter(|n| *n > 0)
                    .map(|n| n as u64);
                let flow = interface_flow_rates(iface, "prxs", "ptxs");
                let lines = path_request_status_lines(ip_freq, op_freq, clients, peers, flow);
                let prxc = iface.get("prxc").and_then(|v| v.as_int()).unwrap_or(0);
                let ptxc = iface.get("ptxc").and_then(|v| v.as_int()).unwrap_or(0);
                for line in traffic_count_lines("Path reqs", prxc, ptxc, lines) {
                    println!("{}", line);
                }
            }
            for line in burst_status_lines(iface, rns_net::time::now()) {
                println!("{}", line);
            }
            println!();
        }
    }

    // Show traffic totals
    if show_totals {
        for line in traffic_total_lines(response, show_pr_stats || show_announces, show_pps) {
            println!("{line}");
        }
        if show_filtered {
            for line in filtered_total_lines(response) {
                println!("{line}");
            }
        }
        println!();
        for line in detailed_traffic_total_lines(response, show_pr_stats, show_announces) {
            println!("{line}");
        }
        if show_pr_stats || show_announces {
            println!();
        }
    }

    if show_queues {
        for line in queue_status_lines(response) {
            println!("{line}");
        }
        println!();
    }
}

fn print_profiling_results(results: &PickleValue) {
    let rendered = format_profiling_results(results);
    if !rendered.is_empty() {
        println!("\n Profiling    :\n{rendered}");
    }
}

fn format_profiling_results(results: &PickleValue) -> String {
    let Some(entries) = (match results {
        PickleValue::Dict(entries) => Some(entries),
        _ => None,
    }) else {
        return String::new();
    };

    fn append_tag(
        output: &mut String,
        tag: &PickleValue,
        entries: &[(PickleValue, PickleValue)],
        level: usize,
    ) {
        let Some(name) = tag.get("name").and_then(PickleValue::as_str) else {
            return;
        };
        let Some(stats_all) = tag.get("stats_all") else {
            return;
        };
        let count = stats_all
            .get("count")
            .and_then(PickleValue::as_int)
            .unwrap_or(0);
        let threads = stats_all
            .get("threads")
            .and_then(PickleValue::as_int)
            .unwrap_or(0);
        let indent = "  ".repeat(level + 1);
        output.push_str(&format!(" {indent}{name}\n"));
        output.push_str(&format!(
            " {indent}  Samples  : {count} from {threads} thread{}\n",
            if threads == 1 { "" } else { "s" }
        ));
        output.push_str(&format!(
            " {indent}              {:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15}\n",
            "Mean", "Median", "Min", "Max", "St. dev", "Total"
        ));
        append_profiling_stats_row(output, &indent, "Stats", stats_all);
        for (key, label) in [
            ("stats_1m", "0-1m"),
            ("stats_5m", "1-5m"),
            ("stats_30m", "5-30m"),
            ("stats_60m", "30-60m"),
        ] {
            if let Some(stats) = tag
                .get(key)
                .filter(|value| !matches!(value, PickleValue::None))
            {
                append_profiling_stats_row(output, &indent, label, stats);
            }
        }
        output.push('\n');

        for (_, child) in entries {
            if child.get("super").and_then(PickleValue::as_str) == Some(name) {
                append_tag(output, child, entries, level + 1);
            }
        }
    }

    let mut output = String::new();
    for (_, tag) in entries {
        if matches!(tag.get("super"), None | Some(PickleValue::None)) {
            append_tag(&mut output, tag, entries, 0);
        }
    }
    output
}

fn profiling_stat(stats: &PickleValue, key: &str) -> Option<f64> {
    stats.get(key).and_then(PickleValue::as_float)
}

fn append_profiling_stats_row(output: &mut String, indent: &str, label: &str, stats: &PickleValue) {
    let formatted = |key| {
        profiling_stat(stats, key)
            .map(pretty_short_time_tight)
            .unwrap_or_else(|| "-----".into())
    };
    output.push_str(&format!(
        " {indent}  {label:>5}    : ({:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15})\n",
        formatted("mean"),
        formatted("median"),
        formatted("min"),
        formatted("max"),
        formatted("stdev"),
        formatted("sum"),
    ));
}

fn pretty_short_time_tight(seconds: f64) -> String {
    let mut micros = seconds.abs() * 1_000_000.0;
    let whole_seconds = (micros / 1_000_000.0).floor() as u64;
    micros %= 1_000_000.0;
    let millis = (micros / 1_000.0).floor() as u64;
    micros %= 1_000.0;
    let micros = (micros * 100.0).round() / 100.0;
    let mut parts = Vec::new();
    if whole_seconds > 0 {
        parts.push(format!("{whole_seconds}s"));
    }
    if millis > 0 {
        parts.push(format!("{millis}ms"));
    }
    if micros > 0.0 {
        let mut micros = format!("{micros:.2}");
        while micros.ends_with('0') {
            micros.pop();
        }
        if micros.ends_with('.') {
            micros.pop();
        }
        parts.push(format!("{micros}µs"));
    }
    let rendered = if parts.is_empty() {
        "0us".into()
    } else if parts.len() == 1 {
        parts.remove(0)
    } else {
        parts.join(" ")
    };
    if seconds.is_sign_negative() {
        format!("-{rendered}")
    } else {
        rendered
    }
}

fn interface_mode_label(mode: u8, announces_to_internal: bool) -> String {
    let base = match mode {
        rns_net::MODE_FULL => "Full",
        rns_net::MODE_ACCESS_POINT => "Access Point",
        rns_net::MODE_POINT_TO_POINT => "Point-to-Point",
        rns_net::MODE_ROAMING => "Roaming",
        rns_net::MODE_BOUNDARY => "Boundary",
        rns_net::MODE_GATEWAY => "Gateway",
        rns_net::MODE_INTERNAL => "Internal",
        _ => "Unknown",
    };
    if announces_to_internal {
        format!("{base} (a>i)")
    } else {
        base.into()
    }
}

fn interface_status_label(status: bool, gravity: i64) -> String {
    let base = if status { "Up" } else { "Down" };
    if gravity == 0 {
        base.into()
    } else {
        format!("{base}, gravity {gravity}")
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

#[derive(Debug, Clone, PartialEq)]
enum SortValue {
    Int(i64),
    Float(f64),
    String(String),
}

fn interface_sort_value(iface: &PickleValue, sort_key: &str) -> SortValue {
    match sort_key {
        "rate" => SortValue::Int(iface.get("bitrate").and_then(|v| v.as_int()).unwrap_or(0)),
        "traffic" => {
            let total = iface.get("rxb").and_then(|v| v.as_int()).unwrap_or(0)
                + iface.get("txb").and_then(|v| v.as_int()).unwrap_or(0);
            SortValue::Int(total)
        }
        "rx" => SortValue::Int(iface.get("rxb").and_then(|v| v.as_int()).unwrap_or(0)),
        "tx" => SortValue::Int(iface.get("txb").and_then(|v| v.as_int()).unwrap_or(0)),
        // Filtered traffic (upstream 134dc677).
        "frx" => SortValue::Int(iface.get("frxb").and_then(|v| v.as_int()).unwrap_or(0)),
        "ftx" => SortValue::Int(iface.get("ftxb").and_then(|v| v.as_int()).unwrap_or(0)),
        "frxs" | "ftxs" => SortValue::Float(numeric(iface.get(sort_key)).unwrap_or(0.0)),
        "txdrp" => SortValue::Int(iface.get("txdrp").and_then(|v| v.as_int()).unwrap_or(0)),
        "txdrb" => SortValue::Int(iface.get("txdrb").and_then(|v| v.as_int()).unwrap_or(0)),
        "txbuf" => SortValue::Int(
            iface
                .get("txbuffered")
                .and_then(|v| v.as_int())
                .unwrap_or(0),
        ),
        "prx" => SortValue::Float(
            iface
                .get("ip_freq")
                .and_then(|v| v.as_float())
                .unwrap_or(0.0),
        ),
        "ptx" => SortValue::Float(
            iface
                .get("op_freq")
                .and_then(|v| v.as_float())
                .unwrap_or(0.0),
        ),
        "arxc" | "atxc" | "afrxc" | "prxc" | "ptxc" => SortValue::Int(
            iface
                .get(sort_key)
                .and_then(|value| value.as_int())
                .unwrap_or(0),
        ),
        "pvs" => SortValue::Int(
            iface
                .get("protocol_violations")
                .and_then(|value| value.as_int())
                .unwrap_or(0),
        ),
        "ivs" => SortValue::Int(
            iface
                .get("ifac_violations")
                .and_then(|value| value.as_int())
                .unwrap_or(0),
        ),
        "flt" => SortValue::Int(
            iface
                .get("packet_filter_hits")
                .and_then(|value| value.as_int())
                .unwrap_or(0),
        ),
        _ => SortValue::String(
            iface
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        ),
    }
}

fn violation_status_lines(iface: &PickleValue) -> Vec<String> {
    let protocol = iface
        .get("protocol_violations")
        .and_then(|value| value.as_int())
        .unwrap_or(0);
    let ifac = iface
        .get("ifac_violations")
        .and_then(|value| value.as_int())
        .unwrap_or(0);
    let filter = iface
        .get("packet_filter_hits")
        .and_then(|value| value.as_int())
        .unwrap_or(0);
    let hop_limited = iface
        .get("hop_limiter_hits")
        .and_then(|value| value.as_int())
        .unwrap_or(0);
    let mut lines = Vec::new();
    if protocol > 0 || ifac > 0 {
        lines.push(format!(
            "    Violations: {protocol} protocol{}",
            if ifac > 0 {
                format!(", {ifac} IFAC")
            } else {
                String::new()
            }
        ));
    }
    if filter > 0 {
        lines.push(format!("    Flt. Hits : {filter}"));
    }
    if hop_limited > 0 {
        lines.push(format!("    Hop Limit : {hop_limited}"));
    }
    lines
}

fn transmit_buffer_suffix(iface: &PickleValue) -> String {
    let buffered = iface
        .get("txbuffered")
        .and_then(PickleValue::as_int)
        .unwrap_or(0);
    if buffered <= 0 {
        return String::new();
    }
    let stalled = iface
        .get("txstalled")
        .and_then(PickleValue::as_bool)
        .unwrap_or(false);
    format!(
        " ({} waiting{})",
        size_str(buffered as u64),
        if stalled { ", stalled" } else { "" }
    )
}

fn tx_drop_status_line(iface: &PickleValue) -> Option<String> {
    let drops = iface
        .get("txdrp")
        .and_then(PickleValue::as_int)
        .unwrap_or(0);
    (drops > 0).then(|| {
        let bytes = iface
            .get("txdrb")
            .and_then(PickleValue::as_int)
            .unwrap_or(0);
        format!(
            "    TX Drops  : {drops} ({})",
            size_str(bytes.max(0) as u64)
        )
    })
}

fn traffic_count_lines(
    label: &str,
    inbound: i64,
    outbound: i64,
    rate_lines: Vec<String>,
) -> Vec<String> {
    if inbound <= 0 || outbound <= 0 || rate_lines.is_empty() {
        return rate_lines;
    }
    let mut lines = vec![format!(
        "    {label:<10}: {inbound}\u{2193} {outbound}\u{2191} total"
    )];
    let prefix = format!("    {label:<10}:");
    lines.extend(rate_lines.into_iter().map(|line| {
        line.strip_prefix(&prefix)
            .map(|suffix| format!("                {suffix}"))
            .unwrap_or(line)
    }));
    lines
}

/// Upstream 819076c3: the announce total line ends with the filtered
/// announce count when there is one.
fn with_filtered_announces(
    mut lines: Vec<String>,
    arxc: i64,
    atxc: i64,
    afrxc: i64,
) -> Vec<String> {
    if arxc > 0 && atxc > 0 && afrxc > 0 {
        if let Some(total) = lines.first_mut() {
            total.push_str(&format!(", {afrxc} filtered"));
        }
    }
    lines
}

fn compare_sort_values(a: &SortValue, b: &SortValue) -> Ordering {
    match (a, b) {
        (SortValue::Int(a), SortValue::Int(b)) => a.cmp(b),
        (SortValue::Float(a), SortValue::Float(b)) => a.partial_cmp(b).unwrap_or(Ordering::Equal),
        (SortValue::String(a), SortValue::String(b)) => a.cmp(b),
        _ => Ordering::Equal,
    }
}

fn interface_has_active_burst(iface: &PickleValue) -> bool {
    iface
        .get("burst_active")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || iface
            .get("pr_burst_active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
}

/// A statistics value as upstream prints it with `str()`.
fn python_str(value: &PickleValue) -> String {
    match value {
        PickleValue::Float(f) => python_float(*f),
        PickleValue::Int(i) => i.to_string(),
        PickleValue::String(s) => s.clone(),
        PickleValue::None => "None".to_string(),
        other => format!("{other:?}"),
    }
}

/// What a device behind the interface reports, as upstream's `rnstatus`
/// prints it: an RNode's noise floor, interference, temperature, battery,
/// airtime and channel load; a Weave device's CPU and memory load, switch
/// and endpoint ids and peers. A key present without a value prints as
/// unknown. Upstream prints a missing temperature as "CPU load : Unknown"
/// and gates memory on the CPU load; these lines name what they show.
fn device_status_lines(iface: &PickleValue, now: f64) -> Vec<String> {
    let mut lines = Vec::new();
    let present = |key: &str| iface.get(key).filter(|v| !matches!(v, PickleValue::None));
    let has = |key: &str| iface.get(key).is_some();

    if has("noise_floor") {
        match present("noise_floor") {
            Some(floor) => {
                let mut line = format!("    Noise Fl. : {} dBm", python_str(floor));
                if has("interference") {
                    if let Some(rssi) =
                        present("interference").filter(|v| v.as_number() != Some(0.0))
                    {
                        line.push_str(&format!("\n    Intrfrnc. : {} dBm", python_str(rssi)));
                    } else if let (Some(ts), Some(rssi)) = (
                        present("interference_last_ts").and_then(|v| v.as_number()),
                        present("interference_last_dbm"),
                    ) {
                        line.push_str(&format!(
                            "\n    Intrfrnc. : {} dBm {} ago",
                            python_str(rssi),
                            upstream_prettytime_compact(now - ts)
                        ));
                    } else {
                        line.push_str(", no interference");
                    }
                }
                lines.push(line);
            }
            None => lines.push("    Noise Fl. : Unknown".to_string()),
        }
    }
    let mut value_line = |key: &str, label: &str, unit: &str| {
        if has(key) {
            lines.push(match present(key) {
                Some(v) => format!("    {label} : {}{unit}", python_str(v)),
                None => format!("    {label} : Unknown"),
            });
        }
    };
    value_line("cpu_load", "CPU load ", " %");
    value_line("cpu_temp", "CPU temp ", "\u{b0}C");
    value_line("mem_load", "Mem usage", " %");
    if let (Some(percent), Some(state)) = (
        present("battery_percent").and_then(|v| v.as_number()),
        present("battery_state"),
    ) {
        lines.push(format!(
            "    Battery   : {}% ({})",
            percent as i64,
            python_str(state)
        ));
    }
    let pair = |short: &str, long: &str| Some((present(short)?, present(long)?));
    if let Some((short, long)) = pair("airtime_short", "airtime_long") {
        lines.push(format!(
            "    Airtime   : {}% (15s), {}% (1h)",
            python_str(short),
            python_str(long)
        ));
    }
    if let Some((short, long)) = pair("channel_load_short", "channel_load_long") {
        lines.push(format!(
            "    Ch. Load  : {}% (15s), {}% (1h)",
            python_str(short),
            python_str(long)
        ));
    }
    let mut value_line = |key: &str, label: &str| {
        if has(key) {
            lines.push(match present(key) {
                Some(v) => format!("    {label} : {}", python_str(v)),
                None => format!("    {label} : Unknown"),
            });
        }
    };
    value_line("switch_id", "Switch ID");
    value_line("endpoint_id", "Endpoint ");
    value_line("via_switch_id", "Via      ");
    if let Some(peers) = present("peers") {
        lines.push(format!("    Peers     : {} reachable", python_str(peers)));
    }
    lines
}

/// Upstream 3281e283 `-T`: the interface's tunnel, when the instance
/// reports one.
fn tunnel_id_line(iface: &PickleValue) -> Option<String> {
    let tunnel_id = iface.get("tunnel_id")?;
    Some(match tunnel_id.as_bytes() {
        Some(bytes) => format!("    Tunnel ID : <{}>", prettyhexrep(bytes)),
        None => "    Tunnel ID : None".to_string(),
    })
}

/// Upstream 464e7598 `-T`: the transport node that synthesized a tunnel
/// over the interface, when the instance reports it.
fn remote_transport_line(iface: &PickleValue) -> Option<String> {
    let remote = iface.get("remote_transport_id")?;
    Some(match remote.as_bytes() {
        Some(bytes) => format!("    Rem.Tr.ID : <{}>", prettyhexrep(bytes)),
        None => "    Rem.Tr.ID : Unknown".to_string(),
    })
}

fn interface_rate_line(bitrate: Option<u64>, mtu: Option<u32>) -> Option<String> {
    bitrate.map(|bitrate| match mtu {
        Some(mtu) => format!("    Rate      : {}, MTU {}", speed_str(bitrate), mtu),
        None => format!("    Rate      : {}", speed_str(bitrate)),
    })
}

/// Whether upstream's rnstatus lists an interface only with `-a`: the
/// interfaces listeners spawn, local clients, and I2P interfaces that
/// cannot be reached.
fn hidden_by_default(iface: &PickleValue) -> bool {
    let name = iface
        .get("name")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    const SPAWNED_PREFIXES: [&str; 6] = [
        "LocalInterface[",
        "TCPInterface[Client",
        "BackboneInterface[Client on",
        "AutoInterfacePeer[",
        "WeaveInterfacePeer[",
        "I2PInterfacePeer[Connected peer",
    ];
    SPAWNED_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || (name.starts_with("I2PInterface[")
            && iface
                .get("i2p_connectable")
                .and_then(|value| value.as_bool())
                == Some(false))
}

fn client_status_lines(iface: &PickleValue, show_blocked_ips: bool) -> Vec<String> {
    let Some(clients) = iface.get("clients").and_then(|value| value.as_int()) else {
        return Vec::new();
    };
    let name = iface
        .get("name")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    // The shared instance serves programs; this tool asks over RPC and is
    // not one of them.
    if name.starts_with("Shared Instance[") {
        let programs = clients.max(0);
        let noun = if programs == 1 { "program" } else { "programs" };
        return vec![format!("    Serving   : {programs} {noun}")];
    }
    let mut lines = vec![format!("    Clients   : {}", clients.max(0))];
    if let Some(blocked) = iface
        .get("blocked_ips")
        .and_then(|value| value.as_int())
        .filter(|blocked| *blocked > 0)
    {
        let suffix = if blocked == 1 { "IP" } else { "IPs" };
        lines.push(format!("    Blocked   : {} {}", blocked, suffix));
    }
    if show_blocked_ips {
        if let Some(blocked_ip_list) = iface
            .get("blocked_ip_list")
            .and_then(|value| value.as_list())
        {
            lines.extend(
                blocked_ip_list
                    .iter()
                    .filter_map(|value| value.as_str())
                    .map(|ip| format!("                {ip}")),
            );
        }
    }
    lines
}

fn announce_status_lines(
    ia_freq: f64,
    oa_freq: f64,
    clients: Option<u64>,
    peers: Option<u64>,
    rate_control: AnnounceRateControl,
    flow: Option<FlowRates>,
) -> Vec<String> {
    let mut line = format!(
        "    Announces : {} in  {} out",
        prettyfrequency(ia_freq),
        prettyfrequency(oa_freq),
    );
    if let Some((count, label)) = outgoing_denominator(clients, peers) {
        line.push_str(&format!(
            "  {}/{}",
            prettyfrequency(oa_freq / count as f64),
            label
        ));
    }
    if let Some(flow) = flow {
        line.push_str(&format!(
            "  (\u{2193}{}% / \u{2191}{}% of flow)",
            flow.rx_percent(),
            flow.tx_percent()
        ));
    }

    let mut lines = vec![line];
    if let Some(target) = rate_control.target {
        let mut parts = vec![format!("target {}", prettytime(target))];
        if let Some(penalty) = rate_control.penalty {
            parts.push(format!("penalty {}", prettytime(penalty)));
        }
        if let Some(grace) = rate_control.grace {
            parts.push(format!("grace {}", grace));
        }
        lines.push(format!("                {}", parts.join(", ")));
    }
    lines
}

#[derive(Clone, Copy, Default)]
struct AnnounceRateControl {
    target: Option<f64>,
    penalty: Option<f64>,
    grace: Option<i64>,
}

fn path_request_status_lines(
    ip_freq: f64,
    op_freq: f64,
    clients: Option<u64>,
    peers: Option<u64>,
    flow: Option<FlowRates>,
) -> Vec<String> {
    let mut line = format!(
        "    Path reqs : {} in  {} out",
        prettyfrequency(ip_freq),
        prettyfrequency(op_freq),
    );
    if let Some((count, label)) = outgoing_denominator(clients, peers) {
        line.push_str(&format!(
            "  {}/{}",
            prettyfrequency(op_freq / count as f64),
            label
        ));
    }
    if let Some(flow) = flow {
        line.push_str(&format!(
            "  (\u{2193}{}% / \u{2191}{}% of flow)",
            flow.rx_percent(),
            flow.tx_percent()
        ));
    }
    vec![line]
}

#[derive(Clone, Copy)]
struct FlowRates {
    rx: f64,
    tx: f64,
    total_rx: f64,
    total_tx: f64,
}

impl FlowRates {
    fn rx_percent(self) -> u64 {
        flow_percent(self.rx, self.total_rx)
    }

    fn tx_percent(self) -> u64 {
        flow_percent(self.tx, self.total_tx)
    }
}

fn flow_percent(class_rate: f64, total_rate: f64) -> u64 {
    if class_rate <= 0.0 || total_rate <= 0.0 {
        0
    } else {
        ((class_rate / total_rate) * 100.0).clamp(0.0, 100.0) as u64
    }
}

fn numeric(value: Option<&PickleValue>) -> Option<f64> {
    value.and_then(|value| {
        value
            .as_float()
            .or_else(|| value.as_int().map(|number| number as f64))
    })
}

fn interface_flow_rates(iface: &PickleValue, rx_key: &str, tx_key: &str) -> Option<FlowRates> {
    Some(FlowRates {
        rx: numeric(iface.get(rx_key))?,
        tx: numeric(iface.get(tx_key))?,
        total_rx: numeric(iface.get("rxs"))?,
        total_tx: numeric(iface.get("txs"))?,
    })
}

fn detailed_traffic_total_lines(
    response: &PickleValue,
    show_path_requests: bool,
    show_announces: bool,
) -> Vec<String> {
    let total_rx = numeric(response.get("rxs")).unwrap_or(0.0);
    let total_tx = numeric(response.get("txs")).unwrap_or(0.0);
    let mut lines = Vec::new();
    for (enabled, label, rxb, txb, rxs, txs, rxf, txf) in [
        (
            show_path_requests,
            " Path reqs   ",
            "prxb",
            "ptxb",
            "prxs",
            "ptxs",
            "prxf",
            "ptxf",
        ),
        (
            show_announces,
            " Announces   ",
            "arxb",
            "atxb",
            "arxs",
            "atxs",
            "arxf",
            "atxf",
        ),
    ] {
        if !enabled {
            continue;
        }
        let Some(rx_bytes) = response.get(rxb).and_then(|value| value.as_int()) else {
            continue;
        };
        let Some(tx_bytes) = response.get(txb).and_then(|value| value.as_int()) else {
            continue;
        };
        let rx_rate = numeric(response.get(rxs)).unwrap_or(0.0);
        let tx_rate = numeric(response.get(txs)).unwrap_or(0.0);
        let rx_frequency = numeric(response.get(rxf));
        let tx_frequency = numeric(response.get(txf));
        let frequency_suffix = |frequency: Option<f64>| {
            frequency
                .map(|value| format!(", {}", prettyfrequency(value)))
                .unwrap_or_default()
        };
        lines.push(format!(
            "{label}: {} \u{2191}  {}  ({}% of flow){}",
            size_str(tx_bytes.max(0) as u64),
            speed_str(tx_rate.max(0.0) as u64),
            flow_percent(tx_rate, total_tx),
            frequency_suffix(tx_frequency),
        ));
        lines.push(format!(
            "              {} \u{2193}  {}  ({}% of flow){}",
            size_str(rx_bytes.max(0) as u64),
            speed_str(rx_rate.max(0.0) as u64),
            flow_percent(rx_rate, total_rx),
            frequency_suffix(rx_frequency),
        ));
    }
    lines
}

/// Filtered traffic of one interface (`-F`, upstream 134dc677): bytes
/// dropped before transport processed them, with their rates when reported.
fn filtered_status_line(iface: &PickleValue) -> String {
    let bytes = |key: &str| iface.get(key).and_then(|v| v.as_int()).unwrap_or(0).max(0) as u64;
    let rates = numeric(iface.get("frxs")).zip(numeric(iface.get("ftxs")));
    let rate = |value: f64| format!(" {}", speed_str(value.max(0.0) as u64));
    format!(
        "    Filtered  : {} \u{2191}{}  {} \u{2193}{}",
        size_str(bytes("ftxb")),
        rates.map(|(_, tx)| rate(tx)).unwrap_or_default(),
        size_str(bytes("frxb")),
        rates.map(|(rx, _)| rate(rx)).unwrap_or_default(),
    )
}

/// Filtered traffic totals (`-F -t`, upstream 134dc677).
fn filtered_total_lines(response: &PickleValue) -> Vec<String> {
    let bytes = |key: &str| {
        response
            .get(key)
            .and_then(|v| v.as_int())
            .unwrap_or(0)
            .max(0) as u64
    };
    let rate = |key: &str| {
        numeric(response.get(key))
            .map(|value| format!("  {}", speed_str(value.max(0.0) as u64)))
            .unwrap_or_default()
    };
    vec![
        format!(
            " Filtered      : {} \u{2191}{}",
            size_str(bytes("ftxb")),
            rate("ftxs")
        ),
        format!(
            "                 {} \u{2193}{}",
            size_str(bytes("frxb")),
            rate("frxs")
        ),
    ]
}

fn traffic_total_lines(
    response: &PickleValue,
    show_data_flow: bool,
    show_pps: bool,
) -> Vec<String> {
    let rx_bytes = response
        .get("rxb")
        .and_then(|value| value.as_int())
        .unwrap_or(0);
    let tx_bytes = response
        .get("txb")
        .and_then(|value| value.as_int())
        .unwrap_or(0);
    let rx_rate = numeric(response.get("rxs")).unwrap_or(0.0).max(0.0);
    let tx_rate = numeric(response.get("txs")).unwrap_or(0.0).max(0.0);
    let pps_suffix = |key: &str| {
        if show_pps {
            format!(
                ", {:.0} pps",
                numeric(response.get(key)).unwrap_or(0.0).max(0.0)
            )
        } else {
            String::new()
        }
    };
    let flow_suffix = |total: f64, class: f64| {
        if !show_data_flow || total <= 0.0 {
            String::new()
        } else {
            let fraction = (1.0 - class.max(0.0) / total).clamp(0.0, 1.0);
            let rate = total * fraction;
            format!(
                ", {}% data ({})",
                (fraction * 100.0) as u64,
                speed_str(rate as u64)
            )
        }
    };
    let class_rx =
        numeric(response.get("prxs")).unwrap_or(0.0) + numeric(response.get("arxs")).unwrap_or(0.0);
    let class_tx =
        numeric(response.get("ptxs")).unwrap_or(0.0) + numeric(response.get("atxs")).unwrap_or(0.0);
    vec![
        format!(
            " Traffic totals: {} \u{2191}  {}{}{}",
            size_str(tx_bytes.max(0) as u64),
            speed_str(tx_rate as u64),
            flow_suffix(tx_rate, class_tx),
            pps_suffix("txpps"),
        ),
        format!(
            "                 {} \u{2193}  {}{}{}",
            size_str(rx_bytes.max(0) as u64),
            speed_str(rx_rate as u64),
            flow_suffix(rx_rate, class_rx),
            pps_suffix("rxpps"),
        ),
    ]
}

fn outgoing_denominator(clients: Option<u64>, peers: Option<u64>) -> Option<(u64, &'static str)> {
    clients
        .filter(|count| *count > 0)
        .map(|count| (count, "c"))
        .or_else(|| peers.filter(|count| *count > 0).map(|count| (count, "p")))
}

fn link_status_line(link_count: i64, active_link_count: Option<i64>) -> String {
    let entry_word = if link_count == 1 { "entry" } else { "entries" };
    let active = active_link_count
        .filter(|count| *count > 0)
        .map(|count| format!(" ({count} active)"))
        .unwrap_or_default();
    format!(" Link table    : {link_count} {entry_word}{active}")
}

fn burst_status_lines(iface: &PickleValue, now: f64) -> Vec<String> {
    let mut parts = Vec::new();
    if iface
        .get("burst_active")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        let activated = iface
            .get("burst_activated")
            .and_then(|v| v.as_number())
            .unwrap_or(now);
        let count = iface
            .get("burst_count")
            .and_then(|v| v.as_int())
            .filter(|count| *count > 0)
            .map(|count| format!(" on {count}"))
            .unwrap_or_default();
        parts.push(format!(
            "announces{count} for {}",
            prettytime((now - activated).max(0.0))
        ));
    }
    if iface
        .get("pr_burst_active")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        let activated = iface
            .get("pr_burst_activated")
            .and_then(|v| v.as_number())
            .unwrap_or(now);
        let count = iface
            .get("pr_burst_count")
            .and_then(|v| v.as_int())
            .filter(|count| *count > 0)
            .map(|count| format!(" on {count}"))
            .unwrap_or_default();
        parts.push(format!(
            "path requests{count} for {}",
            prettytime((now - activated).max(0.0))
        ));
    }

    if parts.is_empty() {
        Vec::new()
    } else {
        vec![format!("    Bursts    : {}", parts.join(", "))]
    }
}

fn queue_status_lines(stats: &PickleValue) -> Vec<String> {
    let fields = [
        ("tqpressure", "rxqt", "rxqtd", "total"),
        ("dqpressure", "rxqd", "rxqdd", "data"),
        ("aqpressure", "rxqa", "rxqad", "announce"),
        ("pqpressure", "rxqp", "rxqpd", "path request"),
        ("ilqpressure", "rxqil", "rxqild", "ingress limiter"),
    ];
    let mut lines = Vec::new();
    for (index, (pressure_key, count_key, dropped_key, label)) in fields.into_iter().enumerate() {
        let Some(pressure) = stats.get(pressure_key).and_then(|value| value.as_float()) else {
            continue;
        };
        let Some(count) = stats.get(count_key).and_then(|value| value.as_int()) else {
            continue;
        };
        let prefix = if index == 0 {
            " Qu. Pressure :"
        } else {
            "               "
        };
        let dropped = stats
            .get(dropped_key)
            .and_then(|value| value.as_int())
            .filter(|dropped| *dropped > 0)
            .map(|dropped| format!(", {dropped} dropped"))
            .unwrap_or_default();
        lines.push(format!(
            "{prefix} {:.1}% {label}, {count} pkts{dropped}",
            pressure * 100.0,
        ));
    }
    lines
}

#[allow(clippy::too_many_arguments)]
fn remote_status(
    hash_str: &str,
    management_identity: Option<&str>,
    config_path: Option<&str>,
    remote_timeout: f64,
    show_links: bool,
    json_output: bool,
    monitor_mode: bool,
    monitor_interval: f64,
    show_all: bool,
    sort_by: Option<&str>,
    reverse: bool,
    filter: Option<&str>,
    show_totals: bool,
    show_pps: bool,
    show_announces: bool,
    show_pr_stats: bool,
    show_filtered: bool,
    show_tunnels: bool,
    show_bursts: bool,
    show_blocked_ips: bool,
    show_queues: bool,
    show_profiling: bool,
) {
    let transport_hash = match rns_net::remote_management::parse_transport_identity_hash(hash_str) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    };
    let Some(identity_path) = management_identity else {
        eprintln!(
            "{}",
            rns_net::remote_management::RemoteManagementError::MissingIdentity
        );
        process::exit(1);
    };
    let timeout = Duration::from_secs_f64(remote_timeout.max(0.2));
    let mut client = match rns_net::remote_management::RemoteManagementClient::connect(
        config_path.map(Path::new),
        Some(Path::new(identity_path)),
        timeout,
    ) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    };

    loop {
        let monitor_started = Instant::now();
        match client.status_with_profiling(transport_hash, show_links, show_profiling) {
            Ok(remote) => {
                if monitor_mode {
                    print!("\x1b[2J\x1b[H");
                }
                if json_output {
                    print_json(&remote.stats);
                } else {
                    print_status(
                        &remote.stats,
                        StatusDisplayOptions {
                            show_all,
                            sort_by,
                            reverse,
                            filter,
                            show_totals,
                            show_pps,
                            show_announces,
                            show_pr_stats,
                            show_filtered,
                            show_tunnels,
                            show_bursts,
                            show_blocked_ips,
                            show_queues,
                        },
                    );
                    if let Some(results) = remote.profiling_results.as_ref() {
                        print_profiling_results(results);
                    }
                }
                if let Some(count) = remote.link_count {
                    println!("{}", link_status_line(count, None));
                    println!();
                }
            }
            Err(e) => {
                eprintln!("Remote status error: {e}");
                if !monitor_mode {
                    process::exit(1);
                }
            }
        }

        if !monitor_mode {
            break;
        }
        std::thread::sleep(monitor_sleep_duration(
            monitor_interval,
            monitor_started.elapsed(),
        ));
    }
}

/// Show discovered interfaces
fn show_discovered_interfaces(
    client: &mut RpcClient,
    show_config: bool,
    json_output: bool,
    show_stale: bool,
    show_unknown: bool,
) {
    let response = match client.call(&PickleValue::Dict(vec![(
        PickleValue::String("get".into()),
        PickleValue::String("discovered_interfaces".into()),
    )])) {
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

    // Default output hides stale entries and entries with no implementation
    // information, matching upstream rnstatus. The flags opt them back in.
    let filtered: Vec<&PickleValue> = interfaces
        .iter()
        .filter(|iface| {
            let status = iface
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            if status == "stale" && !show_stale {
                return false;
            }
            if !discovered_has_impl_info(iface) && !show_unknown {
                return false;
            }
            true
        })
        .collect();

    if show_config {
        // Detailed view with config entries
        for (idx, iface) in filtered.iter().copied().enumerate() {
            if idx > 0 {
                println!("{}", "=".repeat(DISCOVERY_DETAIL_SEPARATOR_WIDTH));
            }

            let name = iface
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");
            let if_type = iface
                .get("type")
                .and_then(|v| v.as_str())
                .or_else(|| iface.get("interface_type").and_then(|v| v.as_str()))
                .unwrap_or("Unknown");
            let status = iface
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let transport = iface
                .get("transport")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let hops = iface.get("hops").and_then(|v| v.as_int()).unwrap_or(0);
            let value = discovered_stamp_value(iface);
            let last_heard = iface
                .get("last_heard")
                .and_then(|v| v.as_float())
                .unwrap_or(0.0);
            let discovered = iface
                .get("discovered")
                .and_then(|v| v.as_float())
                .unwrap_or(0.0);

            let transport_id = iface
                .get("transport_id")
                .and_then(|v| v.as_bytes())
                .map(|b| prettyhexrep(&b[..b.len().min(8)]))
                .unwrap_or_default();
            let network_id = iface
                .get("network_id")
                .and_then(|v| v.as_bytes())
                .map(|b| prettyhexrep(&b[..b.len().min(8)]))
                .unwrap_or_default();

            if !network_id.is_empty() {
                println!("Network   ID : {}", network_id);
            }
            if !transport_id.is_empty() {
                println!("Transport ID : {}", transport_id);
            }
            if let Some(address) = discovered_operator_lxmf_address(iface) {
                println!("LXMF address : {}", address);
            }

            println!("Name         : {}", name);
            println!("Type         : {}", if_type);
            println!("Stack        : {}", discovered_stack(iface));
            println!("Status       : {}", status);
            println!(
                "Transport    : {}",
                if transport { "Enabled" } else { "Disabled" }
            );
            println!("Stamp Value  : {}", value);
            if let Some(costs) = discovered_costs(iface) {
                println!("Costs        : {}", costs);
            }
            println!(
                "Distance     : {} hop{}",
                hops,
                if hops == 1 { "" } else { "s" }
            );

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
            if let Some(sf) = iface
                .get("sf")
                .or_else(|| iface.get("spreading_factor"))
                .and_then(|v| v.as_int())
            {
                println!("Sprd. Factor : {}", sf);
            }
            if let Some(cr) = iface
                .get("cr")
                .or_else(|| iface.get("coding_rate"))
                .and_then(|v| v.as_int())
            {
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
        println!(
            "{:<25} {:<10} {:<12} {:<12} {:<7} {:<16} {:<15}",
            "Name", "Type", "Status", "Last Heard", "Value", "Running", "Location"
        );
        println!("{}", "-".repeat(110));

        let now = rns_net::time::now();

        for iface in filtered.iter().copied() {
            let name_full = iface
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");
            let name = if name_full.len() > 24 {
                format!("{}...", &name_full[..21])
            } else {
                name_full.to_string()
            };

            let if_type = iface
                .get("type")
                .and_then(|v| v.as_str())
                .or_else(|| iface.get("interface_type").and_then(|v| v.as_str()))
                .unwrap_or("Unknown")
                .replace("Interface", "");

            let status = iface
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let status_display = match status {
                "available" => "Available",
                "unknown" => "Unknown",
                "stale" => "Stale",
                _ => status,
            };

            let last_heard = iface
                .get("last_heard")
                .and_then(|v| v.as_float())
                .unwrap_or(0.0);
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

            let value = discovered_stamp_value(iface);
            let stack = discovered_stack(iface);
            let stack = if stack.chars().count() > 16 {
                format!("{}…", stack.chars().take(15).collect::<String>())
            } else {
                stack
            };

            let lat = iface.get("latitude").and_then(|v| v.as_float());
            let lon = iface.get("longitude").and_then(|v| v.as_float());
            let location = match (lat, lon) {
                (Some(lat), Some(lon)) => format!("{:.4}, {:.4}", lat, lon),
                _ => "N/A".to_string(),
            };

            println!(
                "{:<25} {:<10} {:<12} {:<12} {:<7} {:<16} {:<15}",
                name, if_type, status_display, last_heard_display, value, stack, location
            );
        }
    }
}

const DISCOVERY_DETAIL_SEPARATOR_WIDTH: usize = 47;

/// A number from an RPC value, as `RNS.prettycost` accepts it: a float or
/// an integer (older daemons send whole-bit integer values), anything else
/// is no number.
fn pickle_number(value: Option<&PickleValue>) -> Option<f64> {
    value.and_then(|value| {
        value
            .as_float()
            .or_else(|| value.as_int().map(|v| v as f64))
    })
}

/// A discovered interface's stamp value as upstream prints it since rgit
/// `21170877`, with `RNS.prettycost` (`24.730`).
fn discovered_stamp_value(iface: &PickleValue) -> String {
    prettycost(pickle_number(
        iface.get("value").or_else(|| iface.get("stamp_value")),
    ))
}

/// The announced destination and path request costs, printed only when the
/// daemon reports both keys (upstream `21170877` `has_cost_info`); a cost the
/// interface did not announce prints as `n`.
fn discovered_costs(iface: &PickleValue) -> Option<String> {
    let dst_cost = iface.get("dst_cost")?;
    let pr_cost = iface.get("pr_cost")?;
    Some(format!(
        "Dst {}, PR {}",
        prettycost(pickle_number(Some(dst_cost))),
        prettycost(pickle_number(Some(pr_cost)))
    ))
}

fn discovered_stack(iface: &PickleValue) -> String {
    match (
        iface.get("impl_name").and_then(PickleValue::as_str),
        iface.get("version").and_then(PickleValue::as_str),
    ) {
        (Some(name), Some(version)) if !name.is_empty() && !version.is_empty() => {
            format!("{name} {version}")
        }
        _ => "Unknown".into(),
    }
}

fn discovered_has_impl_info(iface: &PickleValue) -> bool {
    iface
        .get("impl_name")
        .and_then(PickleValue::as_str)
        .is_some_and(|name| !name.is_empty())
        && iface
            .get("version")
            .and_then(PickleValue::as_str)
            .is_some_and(|version| !version.is_empty())
}

fn discovered_operator_lxmf_address(iface: &PickleValue) -> Option<&str> {
    iface
        .get("operator_lxmf_address")
        .and_then(|value| value.as_str())
}

fn print_usage(usage_name: &str) {
    println!("Usage: {usage_name} [OPTIONS] [FILTER]");
    println!();
    println!("Options:");
    println!("  --config PATH, -c PATH  Path to config directory");
    println!("  --attach NAME           Attach a configured interface");
    println!("  --detach NAME           Detach a running interface");
    println!("  --reload NAME           Reload a running interface from config");
    println!("  -a, --all               Show all interfaces");
    println!("  -j, --json              JSON output");
    println!("  -s, --sort SORT         Sort by: rate, traffic, rx, tx, frx, ftx, frxs, ftxs, prx, ptx, arxc, atxc, afrxc, prxc, ptxc, txdrp, txdrb, txbuf");
    println!("  -r, --reverse           Reverse sort order");
    println!("  -t, --totals            Show traffic totals");
    println!("  -p, --pps               Show packets per second in traffic totals");
    println!("  -l, --link-stats        Show link count");
    println!("  -A, --announce-stats    Show announce statistics");
    println!("  -P, --pr-stats          Show path request statistics");
    println!("  -F, --filter-stats      Show filtered traffic statistics");
    println!("  -T, --tunnels           Show tunnel information");
    println!("  -B, --burst             Only show interfaces with active burst limiting");
    println!("  -b, --blocked-ips       Show blocked IPs per interface");
    println!("  -q, --queues            Show inbound queue pressure statistics");
    println!("  -z, --profiling         Show live profiling results");
    println!("  -d, --discovered        Show discovered interfaces");
    println!("  -D                      Show discovered interfaces with config entries");
    println!("  --show-stale            Include stale discovery entries");
    println!("  --show-unknown          Include discovery entries without version info");
    println!("  -m, --monitor           Monitor mode (loop)");
    println!("  -I, --monitor-interval SECONDS  Monitor interval (default: 1.0)");
    println!("  -R HASH                 Query remote transport identity via management link");
    println!("  -i PATH                 Identity file for remote management");
    println!("  -w SECONDS              Timeout for remote queries");
    println!("  -v, --verbose           Increase verbosity");
    println!("  --version               Print version and exit");
    println!("  --help, -h              Print this help");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_upstream_invocations_as_argparse_does() {
        // (argv, options set with their values, positional filter)
        type Case<'a> = (&'a [&'a str], &'a [(&'a str, &'a str)], Option<&'a str>);
        let cases: &[Case] = &[
            (&["-a"], &[("a", "true")], None),
            (&["--all", "Backbone"], &[("a", "true")], Some("Backbone")),
            (&["-z", "Backbone"], &[("z", "true")], Some("Backbone")),
            (&["-m", "rnode"], &[("m", "true")], Some("rnode")),
            (&["-d", "rnode"], &[("d", "true")], Some("rnode")),
            (&["-B", "tcp"], &[("B", "true")], Some("tcp")),
            (
                &["tcp", "-srate", "-r"],
                &[("s", "rate"), ("r", "true")],
                Some("tcp"),
            ),
            (
                &["--sort=traffic", "--reverse"],
                &[("s", "traffic"), ("r", "true")],
                None,
            ),
            (
                &["-atpAPFlTbqz"],
                &[("t", "true"), ("p", "true"), ("q", "true"), ("z", "true")],
                None,
            ),
            (
                &["--totals", "--pps", "--link-stats", "--announce-stats"],
                &[("t", "true"), ("p", "true"), ("l", "true"), ("A", "true")],
                None,
            ),
            (
                &["--queues", "--profiling", "--burst", "--blocked-ips"],
                &[("q", "true"), ("z", "true"), ("B", "true"), ("b", "true")],
                None,
            ),
            (&["-mI", "2.5"], &[("m", "true"), ("I", "2.5")], None),
            (
                &["--monitor", "--monitor-interval=3"],
                &[("m", "true"), ("I", "3")],
                None,
            ),
            (
                &["-R", "aa", "-i", "id", "-w5"],
                &[("R", "aa"), ("i", "id"), ("w", "5")],
                None,
            ),
            (
                &["-D", "--show-stale", "--show-unknown"],
                &[
                    ("D", "true"),
                    ("show-stale", "true"),
                    ("show-unknown", "true"),
                ],
                None,
            ),
            (
                &["--discovered", "-j"],
                &[("d", "true"), ("j", "true")],
                None,
            ),
            (
                &["--attach", "If", "--config", "/c"],
                &[("attach", "If"), ("config", "/c")],
                None,
            ),
            (&["--det", "If"], &[("detach", "If")], None),
            (&["--rel=If"], &[("reload", "If")], None),
            (
                &["--monitor", "--monitor-i", "2"],
                &[("m", "true"), ("I", "2")],
                None,
            ),
        ];
        for (argv, expected, filter) in cases {
            let args =
                Args::parse_spec_from(argv.iter().map(|s| s.to_string()).collect(), &OPTIONS);
            for (key, value) in *expected {
                assert_eq!(args.get(key), Some(*value), "{argv:?}: {key}");
            }
            assert_eq!(
                args.positional.first().map(String::as_str),
                *filter,
                "{argv:?}"
            );
            assert!(args.unknown.is_empty(), "{argv:?}: {:?}", args.unknown);
            assert_eq!(args.quiet, 0, "{argv:?}");
        }
        let args = Args::parse_spec_from(vec!["-vv".into()], &OPTIONS);
        assert_eq!(args.verbosity, 2);
    }

    #[test]
    fn formats_nested_live_profiling_results() {
        fn stats(mean: f64, count: i64, threads: Option<i64>) -> PickleValue {
            PickleValue::Dict(vec![
                (PickleValue::String("count".into()), PickleValue::Int(count)),
                (PickleValue::String("mean".into()), PickleValue::Float(mean)),
                (
                    PickleValue::String("median".into()),
                    PickleValue::Float(mean),
                ),
                (
                    PickleValue::String("min".into()),
                    PickleValue::Float(mean / 2.0),
                ),
                (
                    PickleValue::String("max".into()),
                    PickleValue::Float(mean * 1.5),
                ),
                (
                    PickleValue::String("stdev".into()),
                    PickleValue::Float(mean / 4.0),
                ),
                (
                    PickleValue::String("sum".into()),
                    PickleValue::Float(mean * count as f64),
                ),
                (
                    PickleValue::String("threads".into()),
                    threads.map_or(PickleValue::None, PickleValue::Int),
                ),
            ])
        }
        fn tag(name: &str, parent: Option<&str>, count: i64, mean: f64) -> PickleValue {
            PickleValue::Dict(vec![
                (
                    PickleValue::String("name".into()),
                    PickleValue::String(name.into()),
                ),
                (
                    PickleValue::String("super".into()),
                    parent.map_or(PickleValue::None, |value| PickleValue::String(value.into())),
                ),
                (
                    PickleValue::String("stats_all".into()),
                    stats(mean, count, Some(1)),
                ),
                (
                    PickleValue::String("stats_1m".into()),
                    stats(mean, count, None),
                ),
                (PickleValue::String("stats_5m".into()), PickleValue::None),
                (PickleValue::String("stats_30m".into()), PickleValue::None),
                (PickleValue::String("stats_60m".into()), PickleValue::None),
            ])
        }
        let results = PickleValue::Dict(vec![
            (
                PickleValue::String("parent".into()),
                tag("parent", None, 2, 0.001),
            ),
            (
                PickleValue::String("child".into()),
                tag("child", Some("parent"), 1, 0.000_005),
            ),
        ]);
        let rendered = format_profiling_results(&results);
        assert!(rendered.contains("parent"));
        assert!(rendered.contains("Samples  : 2 from 1 thread"));
        assert!(rendered.contains("child"));
        assert!(rendered.contains("2ms"));
        assert!(rendered.contains("Mean"));
        assert!(rendered.contains("0-1m"));
    }

    #[test]
    fn tight_profile_times_preserve_fractional_microseconds() {
        assert_eq!(pretty_short_time_tight(0.000_005_25), "5.25µs");
        assert_eq!(pretty_short_time_tight(1.002_003_25), "1s 2ms 3.25µs");
    }

    fn client_stats(
        clients: i64,
        blocked_ips: Option<i64>,
        blocked_ip_list: &[&str],
    ) -> PickleValue {
        let mut fields = vec![(
            PickleValue::String("clients".into()),
            PickleValue::Int(clients),
        )];
        if let Some(blocked) = blocked_ips {
            fields.push((
                PickleValue::String("blocked_ips".into()),
                PickleValue::Int(blocked),
            ));
        }
        if !blocked_ip_list.is_empty() {
            fields.push((
                PickleValue::String("blocked_ip_list".into()),
                PickleValue::List(
                    blocked_ip_list
                        .iter()
                        .map(|ip| PickleValue::String((*ip).into()))
                        .collect(),
                ),
            ));
        }
        PickleValue::Dict(fields)
    }

    fn named(name: &str, extra: Vec<(PickleValue, PickleValue)>) -> PickleValue {
        let mut fields = vec![(
            PickleValue::String("name".into()),
            PickleValue::String(name.into()),
        )];
        fields.extend(extra);
        PickleValue::Dict(fields)
    }

    #[test]
    fn spawned_and_local_interfaces_are_hidden_without_all() {
        for name in [
            "LocalInterface[rns/default]",
            "TCPInterface[Client on Server/10.0.0.2:50000]",
            "BackboneInterface[Client on Backbone/10.0.0.2:50000]",
            "AutoInterfacePeer[eth0/fe80::1]",
            "WeaveInterfacePeer[01:02]",
            "I2PInterfacePeer[Connected peer on I2P]",
        ] {
            assert!(hidden_by_default(&named(name, Vec::new())), "{name}");
        }
        for name in [
            "Shared Instance[rns/default]",
            "TCPInterface[Peer/10.0.0.1:4242]",
            "TCPServerInterface[Server/0.0.0.0:4242]",
            "I2PInterfacePeer[I2P to peer.b32.i2p]",
            "I2PInterface[I2P]",
        ] {
            assert!(!hidden_by_default(&named(name, Vec::new())), "{name}");
        }
        let unreachable_i2p = named(
            "I2PInterface[I2P]",
            vec![(
                PickleValue::String("i2p_connectable".into()),
                PickleValue::Bool(false),
            )],
        );
        assert!(hidden_by_default(&unreachable_i2p));
    }

    #[test]
    fn shared_instance_reports_the_programs_it_serves() {
        let clients = |n| vec![(PickleValue::String("clients".into()), PickleValue::Int(n))];
        assert_eq!(
            client_status_lines(&named("Shared Instance[rns/default]", clients(1)), false),
            vec!["    Serving   : 1 program"]
        );
        assert_eq!(
            client_status_lines(&named("Shared Instance[37428]", clients(3)), false),
            vec!["    Serving   : 3 programs"]
        );
    }

    #[test]
    fn client_status_shows_blocked_ip_count_with_pluralization() {
        assert_eq!(
            client_status_lines(&client_stats(4, Some(1), &[]), false),
            vec!["    Clients   : 4", "    Blocked   : 1 IP"]
        );
        assert_eq!(
            client_status_lines(&client_stats(4, Some(2), &[]), false),
            vec!["    Clients   : 4", "    Blocked   : 2 IPs"]
        );
    }

    #[test]
    fn interface_rate_includes_mtu_but_accepts_older_status_payloads() {
        assert_eq!(
            interface_rate_line(Some(500_000_000), Some(131_072)),
            Some("    Rate      : 500.00 Mb/s, MTU 131072".into())
        );
        assert_eq!(
            interface_rate_line(Some(500_000_000), None),
            Some("    Rate      : 500.00 Mb/s".into())
        );
        assert_eq!(interface_rate_line(None, Some(131_072)), None);
    }

    #[test]
    fn client_status_hides_zero_or_missing_blocked_count() {
        assert_eq!(
            client_status_lines(&client_stats(0, Some(0), &[]), false),
            vec!["    Clients   : 0"]
        );
        assert_eq!(
            client_status_lines(&client_stats(3, None, &[]), false),
            vec!["    Clients   : 3"]
        );
        assert!(client_status_lines(&PickleValue::Dict(Vec::new()), false).is_empty());
    }

    #[test]
    fn client_status_shows_blocked_ip_list_only_when_requested() {
        let stats = client_stats(4, Some(2), &["192.0.2.1", "2001:db8::2"]);
        assert_eq!(
            client_status_lines(&stats, false),
            vec!["    Clients   : 4", "    Blocked   : 2 IPs"]
        );
        assert_eq!(
            client_status_lines(&stats, true),
            vec![
                "    Clients   : 4",
                "    Blocked   : 2 IPs",
                "                192.0.2.1",
                "                2001:db8::2",
            ]
        );
    }

    #[test]
    fn mode_label_marks_announces_to_internal_override() {
        assert_eq!(
            interface_mode_label(rns_net::MODE_BOUNDARY, true),
            "Boundary (a>i)"
        );
        assert_eq!(
            interface_mode_label(rns_net::MODE_BOUNDARY, false),
            "Boundary"
        );
    }

    #[test]
    fn status_label_includes_only_nonzero_gravity() {
        assert_eq!(interface_status_label(true, 4), "Up, gravity 4");
        assert_eq!(interface_status_label(false, -2), "Down, gravity -2");
        assert_eq!(interface_status_label(true, 0), "Up");
    }

    #[test]
    fn discovered_interface_extracts_operator_lxmf_address() {
        let iface = PickleValue::Dict(vec![(
            PickleValue::String("operator_lxmf_address".into()),
            PickleValue::String("a5".repeat(16)),
        )]);

        assert_eq!(
            discovered_operator_lxmf_address(&iface),
            Some("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5")
        );
        assert_eq!(
            discovered_operator_lxmf_address(&PickleValue::Dict(Vec::new())),
            None
        );
        assert_eq!("=".repeat(DISCOVERY_DETAIL_SEPARATOR_WIDTH).len(), 47);
    }

    #[test]
    fn discovered_stamp_value_prints_like_python_prettycost() {
        let iface = |value: PickleValue| {
            PickleValue::Dict(vec![(PickleValue::String("value".into()), value)])
        };
        assert_eq!(
            discovered_stamp_value(&iface(PickleValue::Float(24.73046875))),
            "24.730"
        );
        assert_eq!(
            discovered_stamp_value(&iface(PickleValue::Float(24.0))),
            "24.000"
        );
        assert_eq!(
            discovered_stamp_value(&iface(PickleValue::Int(24))),
            "24.000"
        );
        assert_eq!(discovered_stamp_value(&iface(PickleValue::None)), "n");
        assert_eq!(discovered_stamp_value(&PickleValue::Dict(Vec::new())), "n");
    }

    #[test]
    fn discovered_costs_need_both_keys_and_print_unknown_as_question_mark() {
        let key = |name: &str, value: PickleValue| (PickleValue::String(name.into()), value);
        assert_eq!(
            discovered_costs(&PickleValue::Dict(vec![
                key("dst_cost", PickleValue::Float(23.5)),
                key("pr_cost", PickleValue::Float(15.80078125)),
            ])),
            Some("Dst 23.500, PR 15.801".into())
        );
        assert_eq!(
            discovered_costs(&PickleValue::Dict(vec![
                key("dst_cost", PickleValue::None),
                key("pr_cost", PickleValue::None),
            ])),
            Some("Dst n, PR n".into())
        );
        assert_eq!(
            discovered_costs(&PickleValue::Dict(vec![key(
                "dst_cost",
                PickleValue::Float(23.5)
            )])),
            None
        );
    }

    #[test]
    fn discovered_stack_uses_both_fields_or_unknown_fallback() {
        let complete = PickleValue::Dict(vec![
            (
                PickleValue::String("impl_name".into()),
                PickleValue::String("Reticulum".into()),
            ),
            (
                PickleValue::String("version".into()),
                PickleValue::String("1.5.5".into()),
            ),
        ]);
        assert_eq!(discovered_stack(&complete), "Reticulum 1.5.5");
        assert_eq!(discovered_stack(&PickleValue::Dict(Vec::new())), "Unknown");
    }

    #[test]
    fn discovered_has_impl_info_requires_both_nonempty_fields() {
        let complete = PickleValue::Dict(vec![
            (
                PickleValue::String("impl_name".into()),
                PickleValue::String("RNS".into()),
            ),
            (
                PickleValue::String("version".into()),
                PickleValue::String("1.5.5".into()),
            ),
        ]);
        assert!(discovered_has_impl_info(&complete));

        for missing in [
            PickleValue::Dict(Vec::new()),
            PickleValue::Dict(vec![(
                PickleValue::String("impl_name".into()),
                PickleValue::String("RNS".into()),
            )]),
            PickleValue::Dict(vec![
                (
                    PickleValue::String("impl_name".into()),
                    PickleValue::String("RNS".into()),
                ),
                (
                    PickleValue::String("version".into()),
                    PickleValue::String(String::new()),
                ),
            ]),
        ] {
            assert!(!discovered_has_impl_info(&missing));
        }
    }

    #[test]
    fn monitor_sleep_accounts_for_elapsed_iteration_time() {
        assert_eq!(
            monitor_sleep_duration(1.0, Duration::from_millis(250)),
            Duration::from_millis(750)
        );
        assert_eq!(
            monitor_sleep_duration(1.0, Duration::from_millis(950)),
            MONITOR_MIN_SLEEP
        );
        assert_eq!(
            monitor_sleep_duration(1.0, Duration::from_millis(1500)),
            MONITOR_MIN_SLEEP
        );
    }

    #[test]
    fn announce_line_includes_per_client_outgoing_frequency_when_clients_present() {
        let lines = announce_status_lines(
            1.0 / 3600.0,
            4.0 / 3600.0,
            Some(4),
            None,
            AnnounceRateControl::default(),
            None,
        );

        assert_eq!(lines[0], "    Announces : 1.0/h in  4.0/h out  1.0/h/c");
    }

    #[test]
    fn announce_line_omits_per_client_frequency_without_clients() {
        let lines = announce_status_lines(
            1.0 / 3600.0,
            4.0 / 3600.0,
            None,
            None,
            AnnounceRateControl::default(),
            None,
        );

        assert_eq!(lines[0], "    Announces : 1.0/h in  4.0/h out");
    }

    #[test]
    fn announce_line_uses_per_peer_frequency_when_clients_are_absent() {
        let lines = announce_status_lines(
            1.0 / 3600.0,
            4.0 / 3600.0,
            None,
            Some(2),
            AnnounceRateControl::default(),
            None,
        );

        assert_eq!(lines[0], "    Announces : 1.0/h in  4.0/h out  2.0/h/p");
    }

    #[test]
    fn path_request_line_includes_per_client_outgoing_frequency_when_clients_present() {
        let lines = path_request_status_lines(2.0 / 3600.0, 8.0 / 3600.0, Some(4), None, None);

        assert_eq!(lines[0], "    Path reqs : 2.0/h in  8.0/h out  2.0/h/c");
    }

    #[test]
    fn path_request_line_uses_per_peer_frequency_when_clients_are_absent() {
        let lines = path_request_status_lines(2.0 / 3600.0, 8.0 / 3600.0, None, Some(2), None);

        assert_eq!(lines[0], "    Path reqs : 2.0/h in  8.0/h out  4.0/h/p");
    }

    #[test]
    fn path_request_line_omits_per_client_frequency_without_clients() {
        let lines = path_request_status_lines(2.0 / 3600.0, 8.0 / 3600.0, None, None, None);

        assert_eq!(lines[0], "    Path reqs : 2.0/h in  8.0/h out");
    }

    #[test]
    fn link_status_distinguishes_table_entries_from_active_links() {
        assert_eq!(
            link_status_line(1, Some(1)),
            " Link table    : 1 entry (1 active)"
        );
        assert_eq!(
            link_status_line(3, Some(2)),
            " Link table    : 3 entries (2 active)"
        );
        assert_eq!(link_status_line(3, Some(0)), " Link table    : 3 entries");
        assert_eq!(link_status_line(3, None), " Link table    : 3 entries");
    }

    #[test]
    fn class_lines_show_independent_capped_flow_percentages() {
        let announce = announce_status_lines(
            1.0,
            2.0,
            None,
            None,
            AnnounceRateControl::default(),
            Some(FlowRates {
                rx: 25.0,
                tx: 250.0,
                total_rx: 100.0,
                total_tx: 200.0,
            }),
        );
        assert!(announce[0].ends_with("(\u{2193}25% / \u{2191}100% of flow)"));

        let path = path_request_status_lines(
            1.0,
            2.0,
            None,
            None,
            Some(FlowRates {
                rx: 10.0,
                tx: 40.0,
                total_rx: 100.0,
                total_tx: 200.0,
            }),
        );
        assert!(path[0].ends_with("(\u{2193}10% / \u{2191}20% of flow)"));
    }

    #[test]
    fn detailed_totals_render_bytes_rates_and_independent_flow_shares() {
        let response = PickleValue::Dict(vec![
            (PickleValue::String("rxs".into()), PickleValue::Float(800.0)),
            (
                PickleValue::String("txs".into()),
                PickleValue::Float(1600.0),
            ),
            (PickleValue::String("prxb".into()), PickleValue::Int(33)),
            (PickleValue::String("ptxb".into()), PickleValue::Int(44)),
            (PickleValue::String("prxs".into()), PickleValue::Float(80.0)),
            (
                PickleValue::String("ptxs".into()),
                PickleValue::Float(320.0),
            ),
            (PickleValue::String("arxb".into()), PickleValue::Int(11)),
            (PickleValue::String("atxb".into()), PickleValue::Int(22)),
            (
                PickleValue::String("arxs".into()),
                PickleValue::Float(200.0),
            ),
            (
                PickleValue::String("atxs".into()),
                PickleValue::Float(400.0),
            ),
            (PickleValue::String("arxf".into()), PickleValue::Float(0.5)),
            (PickleValue::String("atxf".into()), PickleValue::Float(1.0)),
            (PickleValue::String("prxf".into()), PickleValue::Float(2.0)),
            (PickleValue::String("ptxf".into()), PickleValue::Float(4.0)),
        ]);

        assert_eq!(
            detailed_traffic_total_lines(&response, true, true),
            vec![
                " Path reqs   : 44 B \u{2191}  320 b/s  (20% of flow), 240.0/m",
                "              33 B \u{2193}  80 b/s  (10% of flow), 120.0/m",
                " Announces   : 22 B \u{2191}  400 b/s  (25% of flow), 60.0/m",
                "              11 B \u{2193}  200 b/s  (25% of flow), 30.0/m",
            ]
        );
    }

    #[test]
    fn traffic_totals_show_non_pathing_data_percentage_and_speed() {
        let response = PickleValue::Dict(vec![
            (PickleValue::String("rxb".into()), PickleValue::Int(100)),
            (PickleValue::String("txb".into()), PickleValue::Int(200)),
            (PickleValue::String("rxs".into()), PickleValue::Float(800.0)),
            (
                PickleValue::String("txs".into()),
                PickleValue::Float(1600.0),
            ),
            (
                PickleValue::String("arxs".into()),
                PickleValue::Float(200.0),
            ),
            (
                PickleValue::String("atxs".into()),
                PickleValue::Float(400.0),
            ),
            (PickleValue::String("prxs".into()), PickleValue::Float(80.0)),
            (
                PickleValue::String("ptxs".into()),
                PickleValue::Float(320.0),
            ),
        ]);

        let lines = traffic_total_lines(&response, true, false);
        assert!(lines[0].contains("55% data (880 b/s)"));
        assert!(lines[1].contains("65% data (520 b/s)"));
        let without_detail = traffic_total_lines(&response, false, false);
        assert!(!without_detail.iter().any(|line| line.contains("% data")));

        let with_pps = PickleValue::Dict(vec![
            (
                PickleValue::String("rxpps".into()),
                PickleValue::Float(12.4),
            ),
            (PickleValue::String("txpps".into()), PickleValue::Float(7.6)),
        ]);
        assert_eq!(
            traffic_total_lines(&with_pps, false, true),
            vec![
                " Traffic totals: 0 B \u{2191}  0 b/s, 8 pps",
                "                 0 B \u{2193}  0 b/s, 12 pps",
            ]
        );
    }

    #[test]
    fn burst_filter_matches_announce_or_path_request_bursts() {
        let inactive = PickleValue::Dict(vec![]);
        let announce = PickleValue::Dict(vec![(
            PickleValue::String("burst_active".into()),
            PickleValue::Bool(true),
        )]);
        let path_request = PickleValue::Dict(vec![(
            PickleValue::String("pr_burst_active".into()),
            PickleValue::Bool(true),
        )]);

        assert!(!interface_has_active_burst(&inactive));
        assert!(interface_has_active_burst(&announce));
        assert!(interface_has_active_burst(&path_request));
    }

    #[test]
    fn sort_value_supports_path_request_frequency_keys() {
        let iface = PickleValue::Dict(vec![
            (
                PickleValue::String("ip_freq".into()),
                PickleValue::Float(1.25),
            ),
            (
                PickleValue::String("op_freq".into()),
                PickleValue::Float(2.5),
            ),
        ]);

        assert_eq!(interface_sort_value(&iface, "prx"), SortValue::Float(1.25));
        assert_eq!(interface_sort_value(&iface, "ptx"), SortValue::Float(2.5));
    }

    #[test]
    fn transmit_status_renders_and_sorts_drop_and_buffer_metrics() {
        let iface = PickleValue::Dict(vec![
            (PickleValue::String("txdrp".into()), PickleValue::Int(3)),
            (PickleValue::String("txdrb".into()), PickleValue::Int(4096)),
            (
                PickleValue::String("txbuffered".into()),
                PickleValue::Int(2048),
            ),
            (
                PickleValue::String("txstalled".into()),
                PickleValue::Bool(true),
            ),
        ]);

        assert_eq!(
            tx_drop_status_line(&iface).as_deref(),
            Some("    TX Drops  : 3 (4.10 KB)")
        );
        assert_eq!(
            transmit_buffer_suffix(&iface),
            " (2.05 KB waiting, stalled)"
        );
        assert_eq!(interface_sort_value(&iface, "txdrp"), SortValue::Int(3));
        assert_eq!(interface_sort_value(&iface, "txdrb"), SortValue::Int(4096));
        assert_eq!(interface_sort_value(&iface, "txbuf"), SortValue::Int(2048));
    }

    #[test]
    fn total_packet_counts_render_and_sort_independently() {
        let iface = PickleValue::Dict(vec![
            (PickleValue::String("arxc".into()), PickleValue::Int(11)),
            (PickleValue::String("atxc".into()), PickleValue::Int(22)),
            (PickleValue::String("prxc".into()), PickleValue::Int(33)),
            (PickleValue::String("ptxc".into()), PickleValue::Int(44)),
        ]);
        assert_eq!(interface_sort_value(&iface, "arxc"), SortValue::Int(11));
        assert_eq!(interface_sort_value(&iface, "ptxc"), SortValue::Int(44));
        assert_eq!(
            traffic_count_lines(
                "Announces",
                11,
                22,
                vec!["    Announces : 1.0/h in  2.0/h out".into()],
            ),
            vec![
                "    Announces : 11\u{2193} 22\u{2191} total",
                "                 1.0/h in  2.0/h out",
            ]
        );
    }

    #[test]
    fn device_status_lines_match_upstream() {
        let dict = |entries: Vec<(&str, PickleValue)>| {
            PickleValue::Dict(
                entries
                    .into_iter()
                    .map(|(k, v)| (PickleValue::String(k.into()), v))
                    .collect(),
            )
        };
        // An RNode, as a Python 1.6.0 rnsd reports one: no interference,
        // no temperature, battery state unknown.
        let rnode = dict(vec![
            ("noise_floor", PickleValue::Int(-99)),
            ("interference", PickleValue::None),
            ("cpu_temp", PickleValue::None),
            ("battery_percent", PickleValue::Int(0)),
            ("airtime_short", PickleValue::Float(0.0)),
            ("airtime_long", PickleValue::Float(2.52)),
            ("channel_load_short", PickleValue::Float(11.13)),
            ("channel_load_long", PickleValue::Float(2.54)),
            ("peers", PickleValue::None),
        ]);
        assert_eq!(
            device_status_lines(&rnode, 0.0),
            vec![
                "    Noise Fl. : -99 dBm, no interference",
                "    CPU temp  : Unknown",
                "    Airtime   : 0.0% (15s), 2.52% (1h)",
                "    Ch. Load  : 11.13% (15s), 2.54% (1h)",
            ]
        );
        let busy = dict(vec![
            ("noise_floor", PickleValue::Int(-99)),
            ("interference", PickleValue::Int(-80)),
            ("cpu_temp", PickleValue::Int(58)),
            ("battery_percent", PickleValue::Int(91)),
            ("battery_state", PickleValue::String("discharging".into())),
        ]);
        assert_eq!(
            device_status_lines(&busy, 0.0),
            vec![
                "    Noise Fl. : -99 dBm\n    Intrfrnc. : -80 dBm",
                "    CPU temp  : 58\u{b0}C",
                "    Battery   : 91% (discharging)",
            ]
        );
        let earlier = dict(vec![
            ("noise_floor", PickleValue::Int(-99)),
            ("interference", PickleValue::None),
            ("interference_last_ts", PickleValue::Float(1_000.0)),
            ("interference_last_dbm", PickleValue::Int(-80)),
        ]);
        assert_eq!(
            device_status_lines(&earlier, 1_065.0),
            vec!["    Noise Fl. : -99 dBm\n    Intrfrnc. : -80 dBm 1m and 5s ago"]
        );
        let unknown = dict(vec![("noise_floor", PickleValue::None)]);
        assert_eq!(
            device_status_lines(&unknown, 0.0),
            vec!["    Noise Fl. : Unknown"]
        );
        // A Weave device.
        let weave = dict(vec![
            ("cpu_load", PickleValue::Int(12)),
            ("mem_load", PickleValue::Float(40.5)),
            ("switch_id", PickleValue::String("01:02:03:04".into())),
            ("endpoint_id", PickleValue::None),
            ("peers", PickleValue::Int(3)),
        ]);
        assert_eq!(
            device_status_lines(&weave, 0.0),
            vec![
                "    CPU load  : 12 %",
                "    Mem usage : 40.5 %",
                "    Switch ID : 01:02:03:04",
                "    Endpoint  : Unknown",
                "    Peers     : 3 reachable",
            ]
        );
        assert!(device_status_lines(&dict(vec![]), 0.0).is_empty());
    }

    #[test]
    fn tunnel_id_line_matches_upstream() {
        // Upstream 3281e283 `-T`.
        let with = |value: PickleValue| {
            PickleValue::Dict(vec![(PickleValue::String("tunnel_id".into()), value)])
        };
        assert_eq!(
            tunnel_id_line(&with(PickleValue::Bytes(vec![0xAB; 32]))),
            Some(format!("    Tunnel ID : <{}>", "ab".repeat(32)))
        );
        assert_eq!(
            tunnel_id_line(&with(PickleValue::None)),
            Some("    Tunnel ID : None".into())
        );
        assert_eq!(tunnel_id_line(&PickleValue::Dict(Vec::new())), None);
    }

    #[test]
    fn remote_transport_line_matches_upstream() {
        // Upstream 464e7598 `-T`.
        let with = |value: PickleValue| {
            PickleValue::Dict(vec![(
                PickleValue::String("remote_transport_id".into()),
                value,
            )])
        };
        assert_eq!(
            remote_transport_line(&with(PickleValue::Bytes(vec![0xCD; 16]))),
            Some(format!("    Rem.Tr.ID : <{}>", "cd".repeat(16)))
        );
        assert_eq!(
            remote_transport_line(&with(PickleValue::None)),
            Some("    Rem.Tr.ID : Unknown".into())
        );
        assert_eq!(remote_transport_line(&PickleValue::Dict(Vec::new())), None);
    }

    #[test]
    fn filtered_announces_render_and_sort() {
        // Upstream 819076c3: `afrxc` per interface and its sort key.
        let iface = PickleValue::Dict(vec![(
            PickleValue::String("afrxc".into()),
            PickleValue::Int(7),
        )]);
        assert_eq!(interface_sort_value(&iface, "afrxc"), SortValue::Int(7));
        let lines = || {
            traffic_count_lines(
                "Announces",
                11,
                22,
                vec!["    Announces : 1.0/h in  2.0/h out".into()],
            )
        };
        assert_eq!(
            with_filtered_announces(lines(), 11, 22, 7),
            vec![
                "    Announces : 11\u{2193} 22\u{2191} total, 7 filtered",
                "                 1.0/h in  2.0/h out",
            ]
        );
        assert_eq!(with_filtered_announces(lines(), 11, 22, 0), lines());
        // Without both totals there is no total line to extend.
        let rate_only = vec!["    Announces : 1.0/h in  2.0/h out".to_string()];
        assert_eq!(
            with_filtered_announces(rate_only.clone(), 0, 22, 7),
            rate_only
        );
    }

    #[test]
    fn filtered_stats_render_and_sort() {
        // Upstream 134dc677 `-F`: filtered bytes and rates per interface and
        // in the totals, and the frx/ftx/frxs/ftxs sort keys.
        let stats = |frxb: i64, frxs: f64| {
            PickleValue::Dict(vec![
                (PickleValue::String("frxb".into()), PickleValue::Int(frxb)),
                (PickleValue::String("ftxb".into()), PickleValue::Int(0)),
                (PickleValue::String("frxs".into()), PickleValue::Float(frxs)),
                (PickleValue::String("ftxs".into()), PickleValue::Float(0.0)),
            ])
        };
        let iface = stats(1500, 800.0);
        assert_eq!(
            filtered_status_line(&iface),
            format!(
                "    Filtered  : {} \u{2191} {}  {} \u{2193} {}",
                size_str(0),
                speed_str(0),
                size_str(1500),
                speed_str(800)
            )
        );
        assert_eq!(
            filtered_total_lines(&stats(2048, 16.0)),
            vec![
                format!(
                    " Filtered      : {} \u{2191}  {}",
                    size_str(0),
                    speed_str(0)
                ),
                format!(
                    "                 {} \u{2193}  {}",
                    size_str(2048),
                    speed_str(16)
                ),
            ]
        );
        // Without rates, only the byte counts.
        let bytes_only = PickleValue::Dict(vec![(
            PickleValue::String("frxb".into()),
            PickleValue::Int(10),
        )]);
        assert_eq!(
            filtered_status_line(&bytes_only),
            format!(
                "    Filtered  : {} \u{2191}  {} \u{2193}",
                size_str(0),
                size_str(10)
            )
        );
        assert_eq!(interface_sort_value(&iface, "frx"), SortValue::Int(1500));
        assert_eq!(interface_sort_value(&iface, "ftx"), SortValue::Int(0));
        assert_eq!(
            interface_sort_value(&iface, "frxs"),
            SortValue::Float(800.0)
        );
        assert_eq!(interface_sort_value(&iface, "ftxs"), SortValue::Float(0.0));
    }

    #[test]
    fn violation_stats_render_and_sort_independently() {
        let iface = PickleValue::Dict(vec![
            (
                PickleValue::String("protocol_violations".into()),
                PickleValue::Int(3),
            ),
            (
                PickleValue::String("ifac_violations".into()),
                PickleValue::Int(2),
            ),
            (
                PickleValue::String("packet_filter_hits".into()),
                PickleValue::Int(7),
            ),
            (
                PickleValue::String("hop_limiter_hits".into()),
                PickleValue::Int(4),
            ),
        ]);
        assert_eq!(
            violation_status_lines(&iface),
            vec![
                "    Violations: 3 protocol, 2 IFAC",
                "    Flt. Hits : 7",
                "    Hop Limit : 4"
            ]
        );
        assert_eq!(interface_sort_value(&iface, "pvs"), SortValue::Int(3));
        assert_eq!(interface_sort_value(&iface, "ivs"), SortValue::Int(2));
        assert_eq!(interface_sort_value(&iface, "flt"), SortValue::Int(7));
    }

    #[test]
    fn burst_status_line_shows_announce_and_path_request_durations() {
        let iface = PickleValue::Dict(vec![
            (
                PickleValue::String("burst_active".into()),
                PickleValue::Bool(true),
            ),
            (
                PickleValue::String("burst_activated".into()),
                PickleValue::Float(90.0),
            ),
            (
                PickleValue::String("pr_burst_active".into()),
                PickleValue::Bool(true),
            ),
            (
                PickleValue::String("pr_burst_activated".into()),
                PickleValue::Float(95.0),
            ),
            (
                PickleValue::String("burst_count".into()),
                PickleValue::Int(3),
            ),
            (
                PickleValue::String("pr_burst_count".into()),
                PickleValue::Int(2),
            ),
        ]);

        assert_eq!(
            burst_status_lines(&iface, 100.0),
            vec!["    Bursts    : announces on 3 for 10s, path requests on 2 for 5s"]
        );
    }

    #[test]
    fn queue_status_uses_each_traffic_class_pressure() {
        let stats = PickleValue::Dict(vec![
            (
                PickleValue::String("tqpressure".into()),
                PickleValue::Float(0.11),
            ),
            (PickleValue::String("rxqt".into()), PickleValue::Int(15)),
            (PickleValue::String("rxqtd".into()), PickleValue::Int(10)),
            (
                PickleValue::String("dqpressure".into()),
                PickleValue::Float(0.22),
            ),
            (PickleValue::String("rxqd".into()), PickleValue::Int(1)),
            (PickleValue::String("rxqdd".into()), PickleValue::Int(0)),
            (
                PickleValue::String("aqpressure".into()),
                PickleValue::Float(0.33),
            ),
            (PickleValue::String("rxqa".into()), PickleValue::Int(2)),
            (PickleValue::String("rxqad".into()), PickleValue::Int(3)),
            (
                PickleValue::String("pqpressure".into()),
                PickleValue::Float(0.44),
            ),
            (PickleValue::String("rxqp".into()), PickleValue::Int(4)),
            (PickleValue::String("rxqpd".into()), PickleValue::Int(2)),
            (
                PickleValue::String("ilqpressure".into()),
                PickleValue::Float(0.55),
            ),
            (PickleValue::String("rxqil".into()), PickleValue::Int(8)),
            (PickleValue::String("rxqild".into()), PickleValue::Int(5)),
        ]);

        assert_eq!(
            queue_status_lines(&stats),
            vec![
                " Qu. Pressure : 11.0% total, 15 pkts, 10 dropped",
                "                22.0% data, 1 pkts",
                "                33.0% announce, 2 pkts, 3 dropped",
                "                44.0% path request, 4 pkts, 2 dropped",
                "                55.0% ingress limiter, 8 pkts, 5 dropped",
            ]
        );
    }

    #[test]
    fn queue_status_ignores_unavailable_statistics() {
        assert!(queue_status_lines(&PickleValue::Dict(Vec::new())).is_empty());
    }

    #[test]
    fn queue_status_supports_remotes_without_drop_statistics() {
        let stats = PickleValue::Dict(vec![
            (
                PickleValue::String("tqpressure".into()),
                PickleValue::Float(0.5),
            ),
            (PickleValue::String("rxqt".into()), PickleValue::Int(7)),
        ]);

        assert_eq!(
            queue_status_lines(&stats),
            vec![" Qu. Pressure : 50.0% total, 7 pkts"]
        );
    }
}
