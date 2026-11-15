//! rnstatus - Display Reticulum network interface status
//!
//! Connects to a running rnsd via RPC and displays interface statistics.

use std::path::Path;
use std::process;
use std::time::{Duration, Instant};

use rns_cli::args::{Args, Opt, OptionSpec};
use rns_cli::format::{prettycost, prettyhexrep, upstream_prettytime_compact};
use rns_cli::pyfmt::Num;
use rns_cli::rnstatus_view::{render, Extras, ViewOptions};
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
    let view = ViewOptions {
        dispall: show_all,
        name_filter: filter.clone(),
        astats: show_announces,
        pstats: show_pr_stats,
        lstats: show_links,
        sorting: sort_by.clone(),
        sort_reverse: reverse,
        traffic_totals: show_totals,
        burst_filter: show_bursts,
        blocked_ips: show_blocked_ips,
        queue_stats: show_queues,
        pps: show_pps,
        fstats: show_filtered,
        tstats: show_tunnels,
    };
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
            json_output,
            monitor_mode,
            monitor_interval,
            &view,
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
        let Ok(mut client) = RpcClient::connect(&rpc_addr, &auth_key) else {
            println!("No shared RNS instance available to get status from");
            process::exit(1);
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
        // upstream's messages, all on stdout.
        match client.call(&request) {
            Ok(PickleValue::Bool(true)) => {
                println!("Interface {name} was {operation}ed");
                return;
            }
            Ok(PickleValue::Bool(false)) => println!("Could not {operation} interface {name}"),
            Ok(PickleValue::None) => println!("The interface {name} does not exist"),
            _ => println!("Unknown error while {operation}ing interface {name}"),
        }
        process::exit(1);
    }

    // Like upstream's client, each query is a connection of its own.
    let query = |what: &str| -> std::io::Result<PickleValue> {
        RpcClient::connect(&rpc_addr, &auth_key)?.call(&PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String(what.into()),
        )]))
    };
    if RpcClient::connect(&rpc_addr, &auth_key).is_err() {
        println!("No shared RNS instance available to get status from");
        process::exit(1);
    }

    loop {
        let monitor_started = Instant::now();

        let count = |what: &str| query(what).ok().and_then(|r| r.as_int());
        let link_count = show_links.then(|| count("link_count")).flatten();
        let active_link_count = show_links.then(|| count("active_link_count")).flatten();
        let profiling_results = show_profiling
            .then(|| query("profiling_results").ok())
            .flatten()
            .filter(|value| !matches!(value, PickleValue::None));

        let response = match query("interface_stats") {
            Ok(response) if !matches!(response, PickleValue::None) => response,
            _ => {
                if monitor_mode {
                    print!("\x1b[H\x1b[2J");
                    println!("Could not get RNS status");
                    std::thread::sleep(monitor_sleep_duration(
                        monitor_interval,
                        monitor_started.elapsed(),
                    ));
                    continue;
                }
                println!("Could not get RNS status");
                process::exit(2);
            }
        };

        if monitor_mode {
            print!("\x1b[H\x1b[2J");
        }

        if json_output {
            print_json(&response);
        } else {
            show_status(
                &response,
                &view,
                &Extras {
                    link_count: link_count.map(Num::Int),
                    active_link_count: active_link_count.map(Num::Int),
                    profiling_results: profiling_results.as_ref(),
                },
            );
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

fn print_json(response: &PickleValue) {
    println!("{}", upstream_json(response));
}

/// upstream's `json.dumps(stats)` after it turns the bytes in the stats and
/// in their lists of dicts into plain hex.
fn upstream_json(stats: &PickleValue) -> String {
    rns_cli::format::python_json(stats)
}

/// Print the status display as upstream does.
fn show_status(stats: &PickleValue, view: &ViewOptions, extras: &Extras<'_>) {
    print!("{}", render(stats, view, extras, rns_net::time::now()));
}

#[allow(clippy::too_many_arguments)]
fn remote_status(
    hash_str: &str,
    management_identity: Option<&str>,
    config_path: Option<&str>,
    remote_timeout: f64,
    json_output: bool,
    monitor_mode: bool,
    monitor_interval: f64,
    view: &ViewOptions,
    show_profiling: bool,
) {
    let show_links = view.lstats;
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
                    print!("\x1b[H\x1b[2J");
                }
                if json_output {
                    print_json(&remote.stats);
                } else {
                    show_status(
                        &remote.stats,
                        view,
                        &Extras {
                            link_count: remote.link_count.map(Num::Int),
                            active_link_count: None,
                            profiling_results: remote.profiling_results.as_ref(),
                        },
                    );
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
                println!(
                    "Discovered   : {} ago",
                    upstream_prettytime_compact(now - discovered)
                );
            }
            if last_heard > 0.0 {
                println!(
                    "Last Heard   : {} ago",
                    upstream_prettytime_compact(now - last_heard)
                );
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
}
