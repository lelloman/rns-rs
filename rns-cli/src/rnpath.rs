//! rnpath - Display and manage Reticulum path table
//!
//! Connects to a running rnsd via RPC to query/modify the path table.

use rns_core::encoding::hex;
use std::io::Write;
use std::path::Path;
use std::process;
use std::time::Duration;

use crate::args::{Args, Opt, OptionSpec};
use crate::format::{
    prettycost, python_float, python_json, upstream_prettytime, upstream_prettytime_compact,
};
use rns_net::config;
use rns_net::pickle::PickleValue;
use rns_net::rpc::derive_auth_key;
use rns_net::storage;
use rns_net::{RpcAddr, RpcClient};

const VERSION: &str = env!("FULL_VERSION");

/// upstream rnpath's options, and the Rust-only `-c` for `--config`. `-d`,
/// `-x`, `-B` and `-U` are flags acting on the positional destination.
pub const OPTIONS: OptionSpec = OptionSpec {
    options: &[
        Opt::value("", "config"),
        Opt::flag("t", "table"),
        Opt::flag("u", "usage"),
        Opt::value("m", "max"),
        Opt::flag("r", "rates"),
        Opt::flag("d", "drop"),
        Opt::flag("D", "drop-announces"),
        Opt::flag("x", "drop-via"),
        Opt::value("w", ""),
        Opt::value("R", ""),
        Opt::value("i", ""),
        Opt::value("W", ""),
        Opt::flag("b", "blackholed"),
        Opt::flag("B", "blackhole"),
        Opt::flag("U", "unblackhole"),
        Opt::value("", "duration"),
        Opt::value("", "reason"),
        Opt::flag("p", "blackholed-list"),
        Opt::flag("j", "json"),
        Opt::count("v", "verbose"),
        Opt::value("c", ""),
        Opt::value("", "identity").rust_only(),
    ],
};

/// The `rnpath` binary: options from the command line.
pub fn main() {
    crate::stdout::exit_quietly_on_closed_stdout();
    run_with_args(Args::parse_spec(&OPTIONS), "rnpath", "rnpath");
}

/// The destination a flag such as `-d` acts on: upstream's positional
/// destination, or the flag's own value where rns-ctl's parser reads
/// `-d HASH` as one.
fn flag_target(args: &Args, short: &str) -> Option<String> {
    match args.get(short)? {
        "true" => Some(args.positional.first().cloned().unwrap_or_default()),
        value => Some(value.to_string()),
    }
}

/// Runs `rnpath` on already parsed `args`. `usage_name` is the program name
/// printed in usage and errors (e.g. `rns-ctl rnpath`), `version_name` the one
/// printed by `--version`.
///
/// Blocks until the command is done, and exits the process itself on an
/// argument error or a failure, with upstream's exit status.
pub fn run_with_args(args: Args, usage_name: &str, version_name: &str) {
    crate::argparse::enforce(&args, "rnpath", usage_name);
    if args.has("version") {
        println!("{} {}", version_name, VERSION);
        return;
    }

    if args.has("help") || args.has("h") {
        print_usage(usage_name);
        return;
    }

    // `RNS.Reticulum(configdir, loglevel=3+verbosity)`.
    crate::pylog::install_utility_logging(
        args.config_path(),
        Some(crate::pylog::LOG_NOTICE + i32::from(args.verbosity)),
        0,
        false,
    );

    let config_path = args.config_path().map(|s| s.to_string());
    let show_table = args.has("t");
    let show_usage = args.has("u") || args.has("usage");
    let show_rates = args.has("r");
    let drop_hash = flag_target(&args, "d");
    let drop_via = flag_target(&args, "x");
    let drop_queues = args.has("D");
    let json_output = args.has("j");
    let max_hops: Option<u8> = args.get("m").and_then(|s| s.parse().ok());
    let show_blackholed = args.has("blackholed") || args.has("b");
    let blackhole_hash = flag_target(&args, "B");
    let unblackhole_hash = flag_target(&args, "U");
    let duration_hours: Option<f64> = args.get("duration").and_then(|s| s.parse().ok());
    let reason = args.get("reason").map(|s| s.to_string());
    let remote_blackholed = args.has("p") || args.has("blackholed-list");
    let remote_timeout = args
        .get("W")
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(rns_core::constants::PATH_REQUEST_TIMEOUT);
    let management_identity = args.get("i").or_else(|| args.get("identity"));
    let destination = args.positional.first().cloned();
    let list_filter = args.positional.get(1).cloned();

    // As upstream, nothing to do without one of these.
    let has_destination = destination.as_deref().is_some_and(|d| !d.is_empty())
        || [&drop_hash, &drop_via, &blackhole_hash, &unblackhole_hash]
            .iter()
            .any(|target| target.as_deref().is_some_and(|t| !t.is_empty()));
    let has_work = drop_queues || show_table || show_rates || has_destination || show_blackholed;
    if !has_work {
        println!();
        print_usage(usage_name);
        println!();
        return;
    }
    crate::pylog::set_loglevel(crate::pylog::LOG_NOTICE + i32::from(args.verbosity));

    // `-R`: everything goes through the management link.
    if let Some(remote) = args.get("R") {
        let action = if show_blackholed {
            RemoteAction::Blackholed
        } else if remote_blackholed {
            RemoteAction::PublishedList(destination.clone())
        } else if blackhole_hash.is_some() || unblackhole_hash.is_some() {
            RemoteAction::Unsupported(
                "Blackholing identity on remote instances not yet implemented",
            )
        } else if show_table {
            RemoteAction::Table(destination.clone())
        } else if show_rates {
            RemoteAction::Rates(destination.clone())
        } else if drop_queues {
            RemoteAction::Unsupported(
                "Dropping announce queues on remote instances not yet implemented",
            )
        } else if drop_hash.is_some() {
            RemoteAction::Unsupported("Dropping path on remote instances not yet implemented")
        } else if drop_via.is_some() {
            RemoteAction::Unsupported(
                "Dropping all paths via specific transport instance on remote instances yet not implemented",
            )
        } else {
            RemoteAction::Unsupported("Requesting paths on remote instances not implemented")
        };
        let view = TableView {
            destination: None,
            json: json_output,
            usage: show_usage,
            sort: false,
        };
        remote_path(
            remote,
            management_identity,
            config_path.as_deref(),
            remote_timeout,
            max_hops,
            &view,
            list_filter.as_deref(),
            action,
        );
        return;
    }

    // upstream's `-p <identity hash> [filter]`: the blackhole list that
    // transport instance publishes.
    if remote_blackholed && !show_blackholed {
        published_blackhole_list(
            config_path.as_deref(),
            destination.as_deref(),
            list_filter.as_deref(),
            remote_timeout,
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

    let auth_key = rns_config
        .reticulum
        .rpc_key
        .unwrap_or_else(|| derive_auth_key(&identity.get_private_key().unwrap_or([0u8; 64])));

    let rpc_addr = RpcAddr::for_shared_instance(&rns_config.reticulum);

    // As upstream's rnpath, a Reticulum client for every local mode, which
    // logs its startup: whether a path is known, and its hops, also come
    // from its own path table when looking one up.
    let node =
        rns_net::RnsNode::connect_shared_from_config(Some(&config_dir), Box::new(NoCallbacks)).ok();

    let mut client = match RpcClient::connect(&rpc_addr, &auth_key) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Could not connect to rnsd: {}", e);
            process::exit(1);
        }
    };

    // In upstream's order, for invocations that combine them.
    if show_blackholed {
        let local = client_transport_identity(&rns_config, &paths);
        show_blackholed_list(&mut client, local.as_ref(), destination.as_deref());
    } else if let Some(hash_str) = blackhole_hash {
        do_blackhole(&mut client, &hash_str, duration_hours, reason);
    } else if let Some(hash_str) = unblackhole_hash {
        do_unblackhole(&mut client, &hash_str);
    } else if show_table {
        let destination = destination_filter(destination.as_deref());
        show_path_table(&mut client, json_output, max_hops, show_usage, destination);
    } else if show_rates {
        let destination = destination_filter(destination.as_deref());
        show_rate_table(&mut client, json_output, destination);
    } else if drop_queues {
        drop_announce_queues(&mut client);
    } else if let Some(hash_str) = drop_hash {
        drop_path(&mut client, &hash_str);
    } else if let Some(hash_str) = drop_via {
        drop_all_via(&mut client, &hash_str);
    } else if let Some(hash_str) = destination {
        let timeout = args
            .get("w")
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(rns_core::constants::PATH_REQUEST_TIMEOUT);
        drop(client);
        let connect = || match RpcClient::connect(&rpc_addr, &auth_key) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Could not connect to rnsd: {}", e);
                process::exit(1);
            }
        };
        // The next hop and its interface come from the instance.
        lookup_path(&connect, node.as_ref(), &hash_str, timeout);
    } else {
        print_usage(usage_name);
    }
    if let Some(node) = node {
        node.shutdown();
    }
}

fn parse_hex_hash(s: &str) -> Option<Vec<u8>> {
    rns_core::encoding::hex_decode(s.trim())
}

/// `RNS.prettyhexrep`: the hash in hex, between angle brackets.
fn pretty(hash: &[u8]) -> String {
    crate::pyfmt::prettyhexrep(hash)
}

/// upstream's destination argument check, with its messages.
fn parse_destination(hash_str: &str) -> Result<[u8; 16], &'static str> {
    if hash_str.chars().count() != 32 {
        return Err("Destination length is invalid, must be 32 hexadecimal characters (16 bytes).");
    }
    let bytes = parse_hex_hash(hash_str).ok_or("Invalid destination entered. Check your input.")?;
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

/// The destination argument of a table view, or upstream's message and
/// exit.
fn destination_filter(destination: Option<&str>) -> Option<[u8; 16]> {
    destination.map(|hash_str| {
        parse_destination(hash_str).unwrap_or_else(|message| {
            println!("{message}");
            process::exit(1);
        })
    })
}

/// A Python number (bools are ints there).
fn number(value: &PickleValue) -> Option<f64> {
    match value {
        PickleValue::Float(f) => Some(*f),
        PickleValue::Int(i) => Some(*i as f64),
        PickleValue::Bool(b) => Some(*b as u8 as f64),
        _ => None,
    }
}

/// Python truthiness of a table value.
fn truthy(value: &PickleValue) -> bool {
    match value {
        PickleValue::None => false,
        PickleValue::Bool(b) => *b,
        PickleValue::Int(i) => *i != 0,
        PickleValue::Float(f) => *f != 0.0,
        PickleValue::String(s) => !s.is_empty(),
        PickleValue::Bytes(b) => !b.is_empty(),
        PickleValue::List(l) => !l.is_empty(),
        PickleValue::Dict(d) => !d.is_empty(),
    }
}

/// Python's `str()` of a table value, for the interface name.
fn python_str(value: Option<&PickleValue>) -> String {
    match value {
        Some(PickleValue::String(s)) => s.clone(),
        Some(PickleValue::Int(i)) => i.to_string(),
        Some(PickleValue::Float(f)) => python_float(*f),
        _ => "None".into(),
    }
}

/// What `rnpath -t` and `-r` print, and the exit status upstream ends with.
struct Rendered {
    text: String,
    status: i32,
}

impl Rendered {
    fn print_and_exit(self) {
        print!("{}", self.text);
        let _ = std::io::stdout().flush();
        if self.status != 0 {
            process::exit(self.status);
        }
    }
}

fn show_path_table(
    client: &mut RpcClient,
    json_output: bool,
    max_hops: Option<u8>,
    show_usage: bool,
    destination: Option<[u8; 16]>,
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

    if response.as_list().is_none() {
        eprintln!("Unexpected response format");
        process::exit(1);
    }
    let view = TableView {
        destination,
        json: json_output,
        usage: show_usage,
        sort: true,
    };
    render_path_table(&response, &view, rns_net::time::now()).print_and_exit();
}

/// What a table view shows, as upstream's options choose it.
struct TableView {
    /// Only this destination's entry (`rnpath -t <hash>`).
    destination: Option<[u8; 16]>,
    json: bool,
    /// `-u`: last use, most recent first.
    usage: bool,
    /// upstream sorts a local path table by interface and hops; a remote
    /// one is shown as it arrives.
    sort: bool,
}

/// upstream's `rnpath -t`: one line per path, sorted by interface and hops
/// (`<hash>   1h via <hash> on <interface> expires in 6d and 23h
/// (dv:n/lc:n)`), or the table in JSON with `-j`. An empty table prints
/// nothing.
fn render_path_table(response: &PickleValue, view: &TableView, now: f64) -> Rendered {
    let Some(entries) = response.as_list() else {
        return Rendered {
            text: String::new(),
            status: 0,
        };
    };
    let mut table: Vec<&PickleValue> = entries.iter().collect();
    if view.sort {
        table.sort_by(|a, b| {
            let key = |e: &PickleValue| {
                (
                    python_str(e.get("interface")),
                    e.get("hops").and_then(number).unwrap_or(0.0),
                )
            };
            let (a, b) = (key(a), key(b));
            a.0.cmp(&b.0)
                .then(a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        });
    }

    if view.json {
        let table = PickleValue::List(table.into_iter().cloned().collect());
        return Rendered {
            text: format!("{}\n", python_json(&table)),
            status: 0,
        };
    }

    // upstream sorts by last use when every entry has one it can compare.
    if view.usage
        && table
            .iter()
            .all(|e| e.get("used").and_then(number).is_some())
    {
        table.sort_by(|a, b| {
            let used = |e: &PickleValue| e.get("used").and_then(number).unwrap_or(0.0);
            used(b)
                .partial_cmp(&used(a))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    let mut text = String::new();
    let mut displayed = 0;
    for path in table {
        let hash = path.get("hash").and_then(|v| v.as_bytes()).unwrap_or(&[]);
        if view.destination.is_some_and(|d| d.as_slice() != hash) {
            continue;
        }
        displayed += 1;
        let hops = match path.get("hops") {
            Some(PickleValue::Int(hops)) => hops.to_string(),
            other => python_str(other),
        };
        let via = path.get("via").and_then(|v| v.as_bytes()).unwrap_or(&[]);
        let expires = path.get("expires").and_then(number).unwrap_or(0.0);
        let usage = match path.get("used") {
            None => ", no usage info".to_string(),
            Some(used) if view.usage && truthy(used) => format!(
                ", last used {} ago",
                upstream_prettytime(now - number(used).unwrap_or(0.0))
            ),
            Some(_) if view.usage => ", never used".to_string(),
            Some(_) => String::new(),
        };
        text.push_str(&format!(
            "{} {hops:>3}h via {} on {} expires in {} {}{usage}\n",
            pretty(hash),
            pretty(via),
            python_str(path.get("interface")),
            upstream_prettytime_compact(expires - now),
            path_costs(path),
        ));
    }

    if view.destination.is_some() && displayed == 0 {
        text.push_str("No path known\n");
        return Rendered { text, status: 1 };
    }
    Rendered { text, status: 0 }
}

/// The destination's stamp value and link request cost, in upstream's
/// `rnpath` notation since rgit `21170877` (`(dv:25.000/lc:19.199)`), with
/// `n` for what the daemon does not know or does not report.
fn path_costs(entry: &PickleValue) -> String {
    // Python's prettycost takes ints and floats, not bools.
    let cost = |key: &str| match entry.get(key) {
        Some(PickleValue::Float(f)) => Some(*f),
        Some(PickleValue::Int(i)) => Some(*i as f64),
        _ => None,
    };
    format!(
        "(dv:{}/lc:{})",
        prettycost(cost("value")),
        prettycost(cost("lr_cost"))
    )
}

fn show_rate_table(client: &mut RpcClient, json_output: bool, destination: Option<[u8; 16]>) {
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

    let view = TableView {
        destination,
        json: json_output,
        usage: false,
        sort: true,
    };
    render_rate_table(&response, &view, rns_net::time::now()).print_and_exit();
}

/// upstream's `rnpath -r`: by time last heard, `<hash> last heard 5
/// minutes ago, 2 announces/hour in the last 3 hours`, with any active
/// rate violations and blocking, or the table in JSON with `-j`.
fn render_rate_table(response: &PickleValue, view: &TableView, now: f64) -> Rendered {
    let mut table: Vec<&PickleValue> = response
        .as_list()
        .map(|entries| entries.iter().collect())
        .unwrap_or_default();
    table.sort_by(|a, b| {
        let last = |e: &PickleValue| e.get("last").and_then(number).unwrap_or(0.0);
        last(a)
            .partial_cmp(&last(b))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if view.json {
        let table = PickleValue::List(table.into_iter().cloned().collect());
        return Rendered {
            text: format!("{}\n", python_json(&table)),
            status: 0,
        };
    }
    if table.is_empty() {
        return Rendered {
            text: "No information available\n".into(),
            status: 0,
        };
    }

    let mut text = String::new();
    let mut displayed = 0;
    for entry in table {
        let hash = entry.get("hash").and_then(|v| v.as_bytes()).unwrap_or(&[]);
        if view.destination.is_some_and(|d| d.as_slice() != hash) {
            continue;
        }
        displayed += 1;
        let timestamps: Vec<f64> = entry
            .get("timestamps")
            .and_then(|v| v.as_list())
            .map(|ts| ts.iter().filter_map(number).collect())
            .unwrap_or_default();
        let Some(&start) = timestamps.first() else {
            // upstream's handler for the IndexError of an empty list.
            text.push_str(&format!(
                "Error while processing entry for {}\nlist index out of range\n",
                pretty(hash)
            ));
            continue;
        };
        let last = entry.get("last").and_then(number).unwrap_or(0.0);
        let last_str = pretty_date(now - last.trunc());
        let span_hours = (now - start).max(3600.0) / 3600.0;
        let span_str = pretty_date(now - start.trunc());
        let rate: f64 = format!("{:.3}", timestamps.len() as f64 / span_hours)
            .parse()
            .unwrap_or(0.0);
        let rate = if rate.fract() == 0.0 {
            format!("{}", rate as i64)
        } else {
            python_float(rate)
        };
        let violations = entry.get("rate_violations").and_then(number).unwrap_or(0.0) as i64;
        let violations = match violations {
            v if v > 1 => format!(", {v} active rate violations"),
            1 => ", 1 active rate violation".to_string(),
            _ => String::new(),
        };
        let blocked_until = entry.get("blocked_until").and_then(number).unwrap_or(0.0);
        let blocked = if blocked_until > now {
            // upstream: pretty_date(int(now - (int(blocked_until) - now))),
            // the time left until announces are allowed again.
            let since = now - (blocked_until.trunc() - now);
            format!(
                ", new announces allowed in {}",
                pretty_date(now - since.trunc())
            )
        } else {
            String::new()
        };
        text.push_str(&format!(
            "{} last heard {last_str} ago, {rate} announces/hour in the last {span_str}{violations}{blocked}\n",
            pretty(hash)
        ));
    }

    if view.destination.is_some() && displayed == 0 {
        text.push_str("No information available\n");
        return Rendered { text, status: 1 };
    }
    Rendered { text, status: 0 }
}

/// upstream rnpath's `pretty_date`, given how long ago the (whole second)
/// time was: `5 seconds`, `1 minute`, `3 hours`, `2 days`; nothing for a
/// time in the future.
fn pretty_date(elapsed: f64) -> String {
    let days = (elapsed / 86_400.0).floor() as i64;
    let seconds = (elapsed - days as f64 * 86_400.0).floor() as i64;
    if days < 0 {
        return String::new();
    }
    if days == 0 {
        return match seconds {
            s if s < 60 => format!("{s} seconds"),
            s if s < 70 => "1 minute".into(),
            s if s < 7200 => format!("{} minutes", s / 60),
            s => format!("{} hours", s / 3600),
        };
    }
    match days {
        1 => "1 day".into(),
        d if d < 7 => format!("{d} days"),
        d if d < 31 => format!("{} weeks", d / 7),
        d if d < 365 => format!("{} months", d / 30),
        d => format!("{} years", d / 365),
    }
}

/// `RNS.Transport.identity` of this program, a client of the shared
/// instance: the stored transport identity with `static_transport_identity`,
/// else an ephemeral one that no blackhole entry names.
fn client_transport_identity(
    rns_config: &config::RnsConfig,
    paths: &storage::StoragePaths,
) -> Option<[u8; 16]> {
    if !rns_config.reticulum.static_transport_identity {
        return None;
    }
    storage::load_identity(&storage::transport_identity_path(paths))
        .ok()
        .map(|identity| *identity.hash())
}

/// [`client_transport_identity`] for the config directory `config_path`.
fn client_transport_identity_at(config_path: Option<&str>) -> Option<[u8; 16]> {
    let config_dir = storage::resolve_config_dir(config_path.map(Path::new));
    let config_file = config_dir.join("config");
    if !config_file.exists() {
        return None;
    }
    let rns_config = config::parse_file(&config_file).ok()?;
    let paths = storage::ensure_storage_dirs(&config_dir).ok()?;
    client_transport_identity(&rns_config, &paths)
}

/// `rnpath -b [filter]`: the instance's blackholed identities.
fn show_blackholed_list(
    client: &mut RpcClient,
    local_identity: Option<&[u8; 16]>,
    filter: Option<&str>,
) {
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
        Ok(response) => render_blackholed_list(&response, local_identity, filter),
        Err(e) => {
            println!("Could not get blackholed identities from RNS instance: {e}");
            process::exit(20);
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
        // `if until`: a zero time is no expiry.
        .filter(|until| *until != 0.0)
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

/// Print a blackhole list as upstream's `rnpath -b` and `-p` do: `<hash>
/// blackholed for <time>|indefinitely (<reason>) by <source>`, naming the
/// source unless it is this program's transport identity, and only the
/// entries whose `<hash> <until> <reason> <by>` contains `filter`.
fn render_blackholed_list(
    response: &PickleValue,
    local_identity: Option<&[u8; 16]>,
    filter: Option<&str>,
) {
    match blackholed_lines(response, local_identity, filter, rns_net::time::now()) {
        Some(lines) => lines.iter().for_each(|line| println!("{line}")),
        None => {
            println!("No blackholed identity data available");
            process::exit(20);
        }
    }
}

/// The lines [`render_blackholed_list`] prints at `now`, or `None` for an
/// empty list.
fn blackholed_lines(
    response: &PickleValue,
    local_identity: Option<&[u8; 16]>,
    filter: Option<&str>,
    now: f64,
) -> Option<Vec<String>> {
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
        return None;
    }
    let mut out = Vec::new();
    for line in lines {
        let until = match line.until {
            Some(until) => format!("for {}", upstream_prettytime((until - now).max(0.0))),
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
        let by = match &line.source {
            Some(source) if local_identity.is_some_and(|l| l.as_slice() == source.as_slice()) => {
                String::new()
            }
            Some(source) => format!(" by {}", pretty(source)),
            None => String::new(),
        };
        let hash = pretty(&line.identity_hash);
        if filter.is_some_and(|f| !format!("{hash} {until} {reason} {by}").contains(f)) {
            continue;
        }
        out.push(format!("{hash} blackholed {until}{reason}{by}"));
    }
    Some(out)
}

/// upstream's `parse_hash`, for the identity hash the blackhole options
/// take; a missing one fails as `len(None)` does.
fn parse_hash(input: Option<&str>) -> Result<[u8; 16], String> {
    let Some(input) = input else {
        return Err("object of type 'NoneType' has no len()".into());
    };
    if input.chars().count() != 32 {
        return Err("Hash length is invalid, must be 32 hexadecimal characters (16 bytes).".into());
    }
    match crate::pylog::fromhex(input) {
        Ok(bytes) if bytes.len() == 16 => {
            let mut hash = [0u8; 16];
            hash.copy_from_slice(&bytes);
            Ok(hash)
        }
        _ => Err("Invalid hash entered. Check your input.".into()),
    }
}

fn do_blackhole(
    client: &mut RpcClient,
    hash_str: &str,
    duration_hours: Option<f64>,
    reason: Option<String>,
) {
    let hash_bytes = match parse_hash(Some(hash_str)) {
        Ok(hash) => hash.to_vec(),
        Err(e) => {
            println!("Could not blackhole identity: {e}");
            process::exit(20);
        }
    };
    // Upstream's `blackhole_identity`, with an absolute expiry time.
    let until = duration_hours
        .filter(|hours| *hours != 0.0)
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
    let hash_bytes = match parse_hash(Some(hash_str)) {
        Ok(hash) => hash.to_vec(),
        Err(e) => {
            println!("Could not unblackhole identity: {e}");
            process::exit(20);
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

/// One RPC `get` for a destination, as upstream's shared-instance clients
/// make it.
fn get_for(connect: &dyn Fn() -> RpcClient, what: &str, dest_hash: &[u8; 16]) -> PickleValue {
    match connect().call(&PickleValue::Dict(vec![
        (
            PickleValue::String("get".into()),
            PickleValue::String(what.into()),
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
    }
}

fn hops_to(connect: &dyn Fn() -> RpcClient, dest_hash: &[u8; 16]) -> i64 {
    let table = connect()
        .call(&PickleValue::Dict(vec![
            (
                PickleValue::String("get".into()),
                PickleValue::String("path_table".into()),
            ),
            (PickleValue::String("max_hops".into()), PickleValue::None),
        ]))
        .unwrap_or(PickleValue::None);
    table
        .as_list()
        .and_then(|entries| {
            entries.iter().find(|entry| {
                entry.get("hash").and_then(|v| v.as_bytes()) == Some(dest_hash.as_slice())
            })
        })
        .and_then(|entry| entry.get("hops").and_then(|v| v.as_int()))
        .unwrap_or(rns_core::constants::PATHFINDER_M as i64)
}

/// upstream's `rnpath <destination>`: request a path unless one is known,
/// wait up to `timeout` (at least the instance's medium path timeout) for
/// it, and show where it leads.
/// Each RPC connection serves one call, so every query opens one.
struct NoCallbacks;

impl rns_net::Callbacks for NoCallbacks {}

fn lookup_path(
    connect: &dyn Fn() -> RpcClient,
    node: Option<&rns_net::RnsNode>,
    hash_str: &str,
    timeout: f64,
) {
    if hash_str.len() != 32 {
        println!("Destination length is invalid, must be 32 hexadecimal characters (16 bytes).");
        process::exit(1);
    }
    let Some(hash_bytes) = parse_hex_hash(hash_str) else {
        println!("Invalid destination entered. Check your input.");
        process::exit(1);
    };
    let mut dest_hash = [0u8; 16];
    dest_hash.copy_from_slice(&hash_bytes);
    let pretty = pretty(&dest_hash);
    let has_path = || match node {
        Some(node) => node
            .has_path(&rns_net::DestHash(dest_hash))
            .unwrap_or(false),
        None => get_for(connect, "next_hop", &dest_hash)
            .as_bytes()
            .is_some(),
    };

    if !has_path() {
        match node {
            Some(node) => {
                let _ = node.request_path(&rns_net::DestHash(dest_hash));
            }
            None => {
                let _ = connect().call(&PickleValue::Dict(vec![(
                    PickleValue::String("request_path".into()),
                    PickleValue::Bytes(dest_hash.to_vec()),
                )]));
            }
        }
        print!("Path to {pretty} requested   ");
        let _ = std::io::stdout().flush();
    }

    let medium = connect()
        .call(&PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("medium_path_timeout".into()),
        )]))
        .ok()
        .and_then(|v| v.as_float().or_else(|| v.as_int().map(|i| i as f64)))
        .unwrap_or(0.0);
    let wait = std::time::Duration::try_from_secs_f64(timeout.max(medium).max(0.0))
        .unwrap_or(std::time::Duration::MAX);
    let now = std::time::Instant::now();
    // An unrepresentable limit (an infinite timeout) waits as long as it can.
    let limit = now
        .checked_add(wait)
        .unwrap_or(now + std::time::Duration::from_secs(u32::MAX as u64));
    let syms: Vec<char> = "⢄⢂⢁⡁⡈⡐⡠".chars().collect();
    let mut i = 0;
    while !has_path() && std::time::Instant::now() < limit {
        std::thread::sleep(std::time::Duration::from_millis(100));
        print!("\x08\x08{} ", syms[i]);
        let _ = std::io::stdout().flush();
        i = (i + 1) % syms.len();
    }

    if has_path() {
        let hops = match node {
            Some(node) => node
                .hops_to(&rns_net::DestHash(dest_hash))
                .ok()
                .flatten()
                .map(i64::from)
                .unwrap_or(rns_core::constants::PATHFINDER_M as i64),
            None => hops_to(connect, &dest_hash),
        };
        let next_hop = get_for(connect, "next_hop", &dest_hash);
        let Some(next_hop) = next_hop.as_bytes() else {
            println!("\r                                                       \rError: Invalid path data returned");
            process::exit(1);
        };
        let next_hop = crate::pyfmt::prettyhexrep(next_hop);
        let interface = get_for(connect, "next_hop_if_name", &dest_hash)
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| "None".into());
        let ms = if hops != 1 { "s" } else { "" };
        println!(
            "\rPath found, destination {pretty} is {hops} hop{ms} away via {next_hop} on {interface}"
        );
    } else {
        println!("\r                                                       \rPath not found");
        process::exit(1);
    }
}

fn drop_path(client: &mut RpcClient, hash_str: &str) {
    let dest_hash = parse_destination(hash_str).unwrap_or_else(|message| {
        println!("{message}");
        process::exit(1);
    });
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

    if truthy(&response) {
        println!("Dropped path to {}", pretty(&dest_hash));
    } else {
        println!(
            "Unable to drop path to {}. Does it exist?",
            pretty(&dest_hash)
        );
        process::exit(1);
    }
}

fn drop_all_via(client: &mut RpcClient, hash_str: &str) {
    let transport_hash = parse_destination(hash_str).unwrap_or_else(|message| {
        println!("{message}");
        process::exit(1);
    });
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

    // upstream reports the number of paths dropped only as success.
    if truthy(&response) {
        println!("Dropped all paths via {}", pretty(&transport_hash));
    } else {
        println!(
            "Unable to drop paths via {}. Does the transport instance exist?",
            pretty(&transport_hash)
        );
        process::exit(1);
    }
}

fn drop_announce_queues(client: &mut RpcClient) {
    println!("Dropping announce queues on all interfaces...");
    if let Err(e) = client.call(&PickleValue::Dict(vec![(
        PickleValue::String("drop".into()),
        PickleValue::String("announce_queues".into()),
    )])) {
        eprintln!("RPC error: {}", e);
        process::exit(1);
    }
}

/// upstream's `output_rst_str`: blank the line the progress was on.
const RST: &str = "\r                                                          \r";

/// Print without a newline, at once, as upstream's progress does.
fn say(text: &str) {
    print!("{text}");
    let _ = std::io::stdout().flush();
}

/// What `rnpath -R` does once the management link is up, in upstream's
/// order of options.
enum RemoteAction {
    /// `-b`: not implemented upstream for remote instances.
    Blackholed,
    /// `-p <hash>`: upstream sends the published list's `/list` request on
    /// the management link that is already up, which fails.
    PublishedList(Option<String>),
    /// `-t [destination]`.
    Table(Option<String>),
    /// `-r [destination]`.
    Rates(Option<String>),
    /// What upstream has no remote version of, with its message.
    Unsupported(&'static str),
}

/// A remote request's progress, printed as upstream's `connect_remote`
/// prints it.
fn print_progress(client: &mut rns_net::remote_management::RemoteManagementClient) {
    use rns_net::remote_management::RemoteProgress;
    client.set_progress(|stage| match stage {
        RemoteProgress::PathRequested(dest) => {
            say(&format!("Path to {} requested ", pretty(&dest)))
        }
        RemoteProgress::EstablishingLink => say(&format!(
            "{RST}Establishing link with remote transport instance... "
        )),
        RemoteProgress::SendingRequest => say(&format!("{RST}Sending request... ")),
    });
}

/// Connect to the shared instance for remote requests, waiting for paths
/// as long as upstream's `connect_remote` does.
fn remote_client(
    config_path: Option<&str>,
    management_identity: Option<rns_crypto::identity::Identity>,
    remote_timeout: f64,
) -> rns_net::remote_management::RemoteManagementClient {
    let timeout = Duration::try_from_secs_f64(remote_timeout.max(0.2)).unwrap_or(Duration::MAX);
    let mut client = match rns_net::remote_management::RemoteManagementClient::connect_with_identity(
        config_path.map(Path::new),
        management_identity,
        timeout,
    ) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Could not connect to rnsd: {e}");
            process::exit(1);
        }
    };
    let medium = client.medium_path_timeout().unwrap_or(0.0);
    client.set_timeout(
        Duration::try_from_secs_f64(remote_timeout.max(medium).max(0.2)).unwrap_or(Duration::MAX),
    );
    print_progress(&mut client);
    client
}

/// A failed remote request, reported as upstream's link callbacks and
/// request checks report it, then exit.
fn remote_failure(error: rns_net::remote_management::RemoteManagementError, failed: &str) -> ! {
    use rns_net::remote_management::RemoteManagementError as E;
    let (message, code) = match error {
        E::PathTimeout(_) | E::RecallTimeout(_) => ("Path request timed out", 12),
        E::LinkTimeout(_) | E::LinkClosed(Some(rns_net::TeardownReason::Timeout)) => {
            ("The link timed out, exiting now", 10)
        }
        E::LinkClosed(Some(rns_net::TeardownReason::DestinationClosed)) => {
            ("The link was closed by the server, exiting now", 10)
        }
        E::LinkClosed(_) => ("Link closed unexpectedly, exiting now", 10),
        _ => (failed, 10),
    };
    println!("{RST}{message}");
    process::exit(code);
}

/// upstream's `-p <identity hash> [filter]` without `-R`: request the
/// published blackhole list over a link to the instance's
/// `rnstransport.info.blackhole` destination.
fn published_blackhole_list(
    config_path: Option<&str>,
    destination: Option<&str>,
    filter: Option<&str>,
    remote_timeout: f64,
) {
    use rns_net::remote_management::RemotePurpose;
    let identity_hash = parse_hash(destination).unwrap_or_else(|e| {
        println!("{e}");
        process::exit(20);
    });
    let mut client = remote_client(config_path, None, remote_timeout);
    let failed = "The remote request failed.";
    if let Err(e) = client.open_link(RemotePurpose::Blackhole, identity_hash) {
        remote_failure(e, failed);
    }
    say(&format!("{RST}Sending request... "));
    let response = client
        .request_on(
            RemotePurpose::Blackhole,
            "/list",
            &rns_core::msgpack::pack(&rns_core::msgpack::Value::Nil),
        )
        .unwrap_or_else(|e| remote_failure(e, failed));
    show_published_list(&response, config_path, filter);
}

/// A `/list` response: the blackhole dict, or upstream's failure.
fn show_published_list(response: &[u8], config_path: Option<&str>, filter: Option<&str>) {
    let list = rns_core::msgpack::unpack_exact(response)
        .ok()
        .map(|value| rns_net::remote_management::msgpack_to_pickle(&value));
    match list {
        Some(list @ PickleValue::Dict(_)) => {
            say(RST);
            let local = client_transport_identity_at(config_path);
            render_blackholed_list(&list, local.as_ref(), filter);
        }
        _ => {
            println!("{RST}The remote request failed.");
            process::exit(10);
        }
    }
}

/// `rnpath -R <hash>`: upstream's remote management, its progress lines,
/// messages and exit codes.
#[allow(clippy::too_many_arguments)]
fn remote_path(
    hash_str: &str,
    management_identity: Option<&str>,
    config_path: Option<&str>,
    remote_timeout: f64,
    max_hops: Option<u8>,
    view: &TableView,
    list_filter: Option<&str>,
    action: RemoteAction,
) {
    use rns_core::msgpack::{self, Value};
    use rns_net::remote_management::RemotePurpose;

    let fail = |message: &str| -> ! {
        println!("{message}");
        process::exit(20);
    };
    let transport_hash = match parse_destination(hash_str) {
        Ok(hash) => hash,
        Err(message) => fail(message),
    };
    let Some(identity_path) = management_identity else {
        fail("expected str, bytes or os.PathLike object, not NoneType");
    };
    let Some(identity) = crate::pylog::identity_from_file(&crate::pylog::expanduser(identity_path))
    else {
        fail(&format!(
            "Could not load management identity from {identity_path}"
        ));
    };
    let mut client = remote_client(config_path, Some(identity), remote_timeout);
    let auth_failed = "The remote request failed. Likely authentication failure.";
    if let Err(e) = client.open_link(RemotePurpose::Management, transport_hash) {
        remote_failure(e, auth_failed);
    }

    let request = |client: &mut rns_net::remote_management::RemoteManagementClient,
                   path: &str,
                   data: Value,
                   failed: &str|
     -> Vec<u8> {
        say(&format!("{RST}Sending request... "));
        client
            .request_on(RemotePurpose::Management, path, &msgpack::pack(&data))
            .unwrap_or_else(|e| remote_failure(e, failed))
    };
    let table = |client: &mut rns_net::remote_management::RemoteManagementClient,
                 data: Value|
     -> PickleValue {
        let response = request(client, "/path", data, auth_failed);
        let value = msgpack::unpack_exact(&response)
            .ok()
            .map(|value| rns_net::remote_management::msgpack_to_pickle(&value));
        match value {
            Some(value) if truthy(&value) => {
                say(RST);
                value
            }
            _ => {
                println!("{RST}{auth_failed}");
                process::exit(10);
            }
        }
    };
    let hash_value = |hash: Option<[u8; 16]>| hash.map_or(Value::Nil, |h| Value::Bin(h.to_vec()));

    match action {
        RemoteAction::Blackholed => {
            println!("{RST}Listing blackholed identities on remote instances not yet implemented");
            process::exit(255);
        }
        RemoteAction::PublishedList(destination) => {
            let identity_hash = parse_hash(destination.as_deref()).unwrap_or_else(|e| {
                println!("{e}");
                process::exit(20);
            });
            let blackhole = rns_net::management::blackhole_dest_hash(&identity_hash);
            if let Err(e) = client.locate(blackhole) {
                remote_failure(e, "The remote request failed.");
            }
            let response = request(
                &mut client,
                "/list",
                Value::Nil,
                "The remote request failed.",
            );
            show_published_list(&response, config_path, list_filter);
        }
        RemoteAction::Table(destination) => {
            let destination = destination_filter(destination.as_deref());
            let data = Value::Array(vec![
                Value::Str("table".into()),
                hash_value(destination),
                max_hops.map_or(Value::Nil, |h| Value::UInt(h.into())),
            ]);
            let response = table(&mut client, data);
            let view = TableView {
                destination,
                ..*view
            };
            render_path_table(&response, &view, rns_net::time::now()).print_and_exit();
        }
        RemoteAction::Rates(destination) => {
            let destination = destination_filter(destination.as_deref());
            let data = Value::Array(vec![Value::Str("rates".into()), hash_value(destination)]);
            let response = table(&mut client, data);
            let view = TableView {
                destination,
                ..*view
            };
            render_rate_table(&response, &view, rns_net::time::now()).print_and_exit();
        }
        RemoteAction::Unsupported(message) => {
            println!("{RST}{message}");
            process::exit(255);
        }
    }
}

fn print_usage(usage_name: &str) {
    crate::argparse::print_help("rnpath", usage_name);
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn parses_upstream_invocations_as_argparse_does() {
        let parse = |argv: &[&str]| {
            Args::parse_spec_from(argv.iter().map(|s| s.to_string()).collect(), &OPTIONS)
        };
        // (argv, options set with their values, destination)
        type Case<'a> = (&'a [&'a str], &'a [(&'a str, &'a str)], Option<&'a str>);
        let cases: &[Case] = &[
            (&["-t"], &[("t", "true")], None),
            (&["--table", "-m", "2"], &[("t", "true"), ("m", "2")], None),
            (&["-tm2"], &[("t", "true"), ("m", "2")], None),
            (&["-t", "--max=3", "-u"], &[("m", "3"), ("u", "true")], None),
            (&["-t", HASH], &[("t", "true")], Some(HASH)),
            (&["-tj"], &[("t", "true"), ("j", "true")], None),
            (
                &["--rates", "--json", HASH],
                &[("r", "true"), ("j", "true")],
                Some(HASH),
            ),
            (&["-d", HASH], &[("d", "true")], Some(HASH)),
            (&[HASH, "-d"], &[("d", "true")], Some(HASH)),
            (&["--drop-via", HASH], &[("x", "true")], Some(HASH)),
            (&["-x", HASH], &[("x", "true")], Some(HASH)),
            (&["-D"], &[("D", "true")], None),
            (&["--drop-a"], &[("D", "true")], None),
            (
                &["-B", HASH, "--duration", "2", "--reason", "spam"],
                &[("B", "true"), ("duration", "2"), ("reason", "spam")],
                Some(HASH),
            ),
            (&["-U", HASH], &[("U", "true")], Some(HASH)),
            (&["-b"], &[("b", "true")], None),
            (&["-p", HASH, "filter"], &[("p", "true")], Some(HASH)),
            (
                &["-R", HASH, "-i", "id", "-W5", "-t"],
                &[("R", HASH), ("i", "id"), ("W", "5")],
                None,
            ),
            (&[HASH, "-w", "10"], &[("w", "10")], Some(HASH)),
            (
                &["--config", "/c", HASH, "-w3"],
                &[("config", "/c"), ("w", "3")],
                Some(HASH),
            ),
        ];
        for (argv, expected, destination) in cases {
            let args = parse(argv);
            for (key, value) in *expected {
                assert_eq!(args.get(key), Some(*value), "{argv:?}: {key}");
            }
            assert_eq!(
                args.positional.first().map(String::as_str),
                *destination,
                "{argv:?}"
            );
            assert!(args.unknown.is_empty(), "{argv:?}: {:?}", args.unknown);
        }
        // Flags act on the positional destination; rns-ctl reads `-d HASH`
        // as a value.
        assert_eq!(
            flag_target(&parse(&[HASH, "-x"]), "x").as_deref(),
            Some(HASH)
        );
        assert_eq!(flag_target(&parse(&["-t"]), "x"), None);
        let control = Args::parse_control_from(vec!["-d".into(), HASH.into()]);
        assert_eq!(flag_target(&control, "d").as_deref(), Some(HASH));
    }

    const PLAIN: &str = concat!(
        r#"<22222222222222222222222222222222>   3h via <bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb> on AutoInterface[Local] expires in 1h and 1m (dv:25.000/lc:19.199)"#,
        "\n",
        r#"<44444444444444444444444444444444>  12h via <cccccccccccccccccccccccccccccccc> on AutoInterface[Local] expires in 1d (dv:n/lc:7.000)"#,
        "\n",
        r#"<11111111111111111111111111111111>   1h via <aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa> on TCPInterface[B/127.0.0.1:4242] expires in 6d and 23h (dv:n/lc:n)"#,
        "\n",
        r#"<33333333333333333333333333333333>   2h via <bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb> on TCPInterface[B/127.0.0.1:4242] expires in -30s (dv:0.000/lc:n)"#,
        "\n",
    );
    const USAGE: &str = concat!(
        r#"<44444444444444444444444444444444>  12h via <cccccccccccccccccccccccccccccccc> on AutoInterface[Local] expires in 1d (dv:n/lc:7.000), last used 1.0s ago"#,
        "\n",
        r#"<11111111111111111111111111111111>   1h via <aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa> on TCPInterface[B/127.0.0.1:4242] expires in 6d and 23h (dv:n/lc:n), last used 1m and 5.5s ago"#,
        "\n",
        r#"<33333333333333333333333333333333>   2h via <bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb> on TCPInterface[B/127.0.0.1:4242] expires in -30s (dv:0.000/lc:n), last used 2h ago"#,
        "\n",
        r#"<22222222222222222222222222222222>   3h via <bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb> on AutoInterface[Local] expires in 1h and 1m (dv:25.000/lc:19.199), never used"#,
        "\n",
    );
    const NO_USED: &str = concat!(
        r#"<22222222222222222222222222222222>   3h via <bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb> on AutoInterface[Local] expires in 1h and 1m (dv:25.000/lc:19.199)"#,
        "\n",
        r#"<44444444444444444444444444444444>  12h via <cccccccccccccccccccccccccccccccc> on AutoInterface[Local] expires in 1d (dv:n/lc:7.000)"#,
        "\n",
        r#"<11111111111111111111111111111111>   1h via <aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa> on TCPInterface[B/127.0.0.1:4242] expires in 6d and 23h (dv:n/lc:n), no usage info"#,
        "\n",
        r#"<33333333333333333333333333333333>   2h via <bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb> on TCPInterface[B/127.0.0.1:4242] expires in -30s (dv:0.000/lc:n)"#,
        "\n",
    );
    const JSON: &str = r#"[{"hash": "22222222222222222222222222222222", "timestamp": 1763099900.25, "via": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "hops": 3, "expires": 1763103662.15, "value": 25.0, "used": 0, "lr_cost": 19.19921875, "interface": "AutoInterface[Local]"}, {"hash": "44444444444444444444444444444444", "timestamp": 1763099900.25, "via": "cccccccccccccccccccccccccccccccc", "hops": 12, "expires": 1763186400.25, "value": null, "used": 1763099999.25, "lr_cost": 7, "interface": "AutoInterface[Local]"}, {"hash": "11111111111111111111111111111111", "timestamp": 1763099900.25, "via": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "hops": 1, "expires": 1763704700.75, "value": null, "used": 1763099934.75, "lr_cost": null, "interface": "TCPInterface[B/127.0.0.1:4242]"}, {"hash": "33333333333333333333333333333333", "timestamp": 1763099900.25, "via": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "hops": 2, "expires": 1763099970.25, "value": 0.0, "used": 1763092800.25, "lr_cost": null, "interface": "TCPInterface[B/127.0.0.1:4242]"}]"#;
    const RATES: &str = concat!(
        r#"<77777777777777777777777777777777> last heard 1 day ago, 0.028 announces/hour in the last 3 days, 1 active rate violation"#,
        "\n",
        r#"<66666666666666666666666666666666> last heard 6 minutes ago, 3 announces/hour in the last 15 minutes, 2 active rate violations, new announces allowed in 66 minutes"#,
        "\n",
        r#"<55555555555555555555555555555555> last heard 31 seconds ago, 1.44 announces/hour in the last 83 minutes"#,
        "\n",
        r#"<88888888888888888888888888888888> last heard 10 seconds ago, 7 announces/hour in the last 10 seconds"#,
        "\n",
    );
    const RATES_JSON: &str = r#"[{"hash": "77777777777777777777777777777777", "last": 1763010000.25, "rate_violations": 1, "blocked_until": 1763099995.25, "timestamps": [1762840800.75, 1763010000.25]}, {"hash": "66666666666666666666666666666666", "last": 1763099600.25, "rate_violations": 2, "blocked_until": 1763104000.65, "timestamps": [1763099100.25, 1763099400.25, 1763099600.25]}, {"hash": "55555555555555555555555555555555", "last": 1763099969.55, "rate_violations": 0, "blocked_until": 0, "timestamps": [1763094999.95, 1763099969.55]}, {"hash": "88888888888888888888888888888888", "last": 1763099990.25, "rate_violations": 0, "blocked_until": 0, "timestamps": [1763099990.25, 1763099990.25, 1763099990.25, 1763099990.25, 1763099990.25, 1763099990.25, 1763099990.25]}]"#;

    const NOW: f64 = 1763100000.25;

    fn dict(items: Vec<(&str, PickleValue)>) -> PickleValue {
        PickleValue::Dict(
            items
                .into_iter()
                .map(|(k, v)| (PickleValue::String(k.into()), v))
                .collect(),
        )
    }

    /// A path table entry as upstream's get_path_table builds it.
    #[allow(clippy::too_many_arguments)]
    fn path(
        byte: u8,
        via: u8,
        hops: i64,
        expires: f64,
        value: PickleValue,
        used: Option<PickleValue>,
        lr_cost: PickleValue,
        interface: &str,
    ) -> PickleValue {
        let mut items = vec![
            ("hash", PickleValue::Bytes(vec![byte; 16])),
            ("timestamp", PickleValue::Float(NOW - 100.0)),
            ("via", PickleValue::Bytes(vec![via; 16])),
            ("hops", PickleValue::Int(hops)),
            ("expires", PickleValue::Float(NOW + expires)),
            ("value", value),
        ];
        if let Some(used) = used {
            items.push(("used", used));
        }
        items.push(("lr_cost", lr_cost));
        items.push(("interface", PickleValue::String(interface.into())));
        dict(items)
    }

    fn path_table(first_used: bool) -> PickleValue {
        let tcp = "TCPInterface[B/127.0.0.1:4242]";
        let auto = "AutoInterface[Local]";
        PickleValue::List(vec![
            path(
                0x11,
                0xaa,
                1,
                604700.5,
                PickleValue::None,
                first_used.then_some(PickleValue::Float(NOW - 65.5)),
                PickleValue::None,
                tcp,
            ),
            path(
                0x22,
                0xbb,
                3,
                3661.9,
                PickleValue::Float(25.0),
                Some(PickleValue::Int(0)),
                PickleValue::Float(4915.0 / 256.0),
                auto,
            ),
            path(
                0x33,
                0xbb,
                2,
                -30.0,
                PickleValue::Float(0.0),
                Some(PickleValue::Float(NOW - 7200.0)),
                PickleValue::None,
                tcp,
            ),
            path(
                0x44,
                0xcc,
                12,
                86400.0,
                PickleValue::None,
                Some(PickleValue::Float(NOW - 1.0)),
                PickleValue::Int(7),
                auto,
            ),
        ])
    }

    fn view(destination: Option<u8>, json: bool, usage: bool) -> TableView {
        TableView {
            destination: destination.map(|b| [b; 16]),
            json,
            usage,
            sort: true,
        }
    }

    // The expected texts are what upstream rnpath 1.6.0 prints for the same
    // tables: its rendering code, run on them with the same time.
    #[test]
    fn path_table_prints_as_upstream() {
        let plain = render_path_table(&path_table(true), &view(None, false, false), NOW);
        assert_eq!(plain.text, PLAIN);
        let usage = render_path_table(&path_table(true), &view(None, false, true), NOW);
        assert_eq!(usage.text, USAGE);
        let no_used = render_path_table(&path_table(false), &view(None, false, false), NOW);
        assert_eq!(no_used.text, NO_USED);
        let json = render_path_table(&path_table(true), &view(None, true, false), NOW);
        assert_eq!(json.text, format!("{JSON}\n"));

        // One destination, or upstream's message when it has no path.
        let one = render_path_table(&path_table(true), &view(Some(0x33), false, false), NOW);
        assert_eq!(one.text, format!("{}\n", PLAIN.lines().nth(3).unwrap()));
        assert_eq!(one.status, 0);
        let none = render_path_table(&path_table(true), &view(Some(0x99), false, false), NOW);
        assert_eq!((none.text.as_str(), none.status), ("No path known\n", 1));

        // An empty table prints nothing, or an empty JSON list.
        let empty = PickleValue::List(Vec::new());
        let rendered = render_path_table(&empty, &view(None, false, false), NOW);
        assert_eq!(rendered.text, "");
        let rendered = render_path_table(&empty, &view(None, true, false), NOW);
        assert_eq!(rendered.text, "[]\n");
    }

    fn rate(byte: u8, last: f64, violations: i64, blocked: PickleValue, ts: &[f64]) -> PickleValue {
        dict(vec![
            ("hash", PickleValue::Bytes(vec![byte; 16])),
            ("last", PickleValue::Float(NOW - last)),
            ("rate_violations", PickleValue::Int(violations)),
            ("blocked_until", blocked),
            (
                "timestamps",
                PickleValue::List(ts.iter().map(|t| PickleValue::Float(NOW - t)).collect()),
            ),
        ])
    }

    fn rate_table() -> PickleValue {
        PickleValue::List(vec![
            rate(0x55, 30.7, 0, PickleValue::Int(0), &[5000.3, 30.7]),
            rate(
                0x66,
                400.0,
                2,
                PickleValue::Float(NOW + 4000.4),
                &[900.0, 600.0, 400.0],
            ),
            rate(
                0x77,
                90000.0,
                1,
                PickleValue::Float(NOW - 5.0),
                &[3.0 * 86400.0 - 0.5, 90000.0],
            ),
            rate(0x88, 10.0, 0, PickleValue::Int(0), &[10.0; 7]),
        ])
    }

    #[test]
    fn rate_table_prints_as_upstream() {
        let rates = render_rate_table(&rate_table(), &view(None, false, false), NOW);
        assert_eq!(rates.text, RATES);
        let json = render_rate_table(&rate_table(), &view(None, true, false), NOW);
        assert_eq!(json.text, format!("{RATES_JSON}\n"));
        let one = render_rate_table(&rate_table(), &view(Some(0x66), false, false), NOW);
        assert_eq!(one.text, format!("{}\n", RATES.lines().nth(1).unwrap()));
        let none = render_rate_table(&rate_table(), &view(Some(0x99), false, false), NOW);
        assert_eq!(
            (none.text.as_str(), none.status),
            ("No information available\n", 1)
        );
        let empty = PickleValue::List(Vec::new());
        assert_eq!(
            render_rate_table(&empty, &view(None, false, false), NOW).text,
            "No information available\n"
        );
    }

    #[test]
    fn blackhole_list_prints_and_filters_as_upstream() {
        let entry = |until: PickleValue, reason: PickleValue, source: u8| {
            dict(vec![
                ("source", PickleValue::Bytes(vec![source; 16])),
                ("until", until),
                ("reason", reason),
            ])
        };
        let list = PickleValue::Dict(vec![
            (
                PickleValue::Bytes(vec![0x11; 16]),
                entry(
                    PickleValue::Float(NOW + 3725.5),
                    PickleValue::String("spam".into()),
                    0xaa,
                ),
            ),
            (
                PickleValue::Bytes(vec![0x22; 16]),
                entry(PickleValue::None, PickleValue::None, 0xbb),
            ),
            (
                PickleValue::Bytes(vec![0x33; 16]),
                entry(
                    PickleValue::Int(0),
                    PickleValue::String("x".repeat(80)),
                    0xaa,
                ),
            ),
        ]);
        let all = blackholed_lines(&list, Some(&[0xbb; 16]), None, NOW).unwrap();
        assert_eq!(
            all,
            [
                format!(
                    "<{}> blackholed for 1h, 2m and 5.5s (spam) by <{}>",
                    "11".repeat(16),
                    "aa".repeat(16)
                ),
                format!("<{}> blackholed indefinitely", "22".repeat(16)),
                format!(
                    "<{}> blackholed indefinitely ({}…) by <{}>",
                    "33".repeat(16),
                    "x".repeat(63),
                    "aa".repeat(16)
                ),
            ]
        );
        // The filter matches `<hash> <until> <reason> <by>`.
        let filtered = |filter: &str| {
            blackholed_lines(&list, Some(&[0xbb; 16]), Some(filter), NOW)
                .unwrap()
                .len()
        };
        assert_eq!(filtered("indefinitely"), 2);
        assert_eq!(filtered(" (spam) "), 1);
        assert_eq!(filtered(&"aa".repeat(16)), 2);
        assert_eq!(filtered("2222"), 1);
        assert_eq!(filtered("nothing"), 0);
        // Without a static transport identity every source is named.
        assert!(blackholed_lines(&list, None, None, NOW).unwrap()[1]
            .ends_with(&format!(" by <{}>", "bb".repeat(16))));
        assert_eq!(
            blackholed_lines(&PickleValue::Dict(vec![]), None, None, NOW),
            None
        );
    }

    #[test]
    fn blackhole_hashes_parse_as_upstream() {
        assert_eq!(parse_hash(Some(HASH)).unwrap()[0], 0x01);
        let error = |input: Option<&str>| parse_hash(input).unwrap_err();
        assert_eq!(
            error(Some("abc")),
            "Hash length is invalid, must be 32 hexadecimal characters (16 bytes)."
        );
        assert_eq!(
            error(Some("zz23456789abcdef0123456789abcdef")),
            "Invalid hash entered. Check your input."
        );
        assert_eq!(error(None), "object of type 'NoneType' has no len()");
    }

    #[test]
    fn rnpath_pretty_date_matches_upstream() {
        let cases = [
            (0.0, "0 seconds"),
            (59.9, "59 seconds"),
            (60.0, "1 minute"),
            (69.0, "1 minute"),
            (70.0, "1 minutes"),
            (7199.0, "119 minutes"),
            (7200.0, "2 hours"),
            (86_399.9, "23 hours"),
            (86_400.0, "1 day"),
            (2.0 * 86_400.0, "2 days"),
            (7.0 * 86_400.0, "1 weeks"),
            (31.0 * 86_400.0, "1 months"),
            (365.0 * 86_400.0, "1 years"),
            (-1.0, ""),
        ];
        for (elapsed, text) in cases {
            assert_eq!(pretty_date(elapsed), text, "{elapsed}");
        }
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
}
