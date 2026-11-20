//! rnstatus - Display Reticulum network interface status
//!
//! Connects to a running rnsd via RPC and displays interface statistics.

use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use crate::args::{Args, Opt, OptionSpec};
use crate::exit::{self, Exit, Status};
use crate::pyfmt::{prettyhexrep, Num};
use crate::rnstatus_view::{
    render, render_discovered, render_discovered_json, upstream_discovery_record, Extras,
    ViewOptions,
};
use crate::shared_instance::LocalInstance;
use rns_net::pickle::PickleValue;
use rns_net::storage;
use rns_net::RpcClient;
use rns_net::TeardownReason;

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

/// The `rnstatus` binary: options from the command line.
pub fn main() -> ExitCode {
    crate::stdout::exit_quietly_on_closed_stdout();
    exit::exit_code(run_with_args(
        Args::parse_spec(&OPTIONS),
        "rnstatus",
        "rnstatus",
    ))
}

/// Runs `rnstatus` on already parsed `args`. `usage_name` is the program name
/// printed in usage and errors (e.g. `rns-ctl rnstatus`), `version_name` the one
/// printed by `--version`.
///
/// Blocks until the command is done, and gives upstream's exit status on a
/// failure; exits the process itself on an argument error.
pub fn run_with_args(args: Args, usage_name: &str, version_name: &str) -> Status {
    crate::argparse::enforce(&args, "rnstatus", usage_name);
    if args.has("version") {
        println!("{} {}", version_name, VERSION);
        return Ok(());
    }

    if args.has("help") || args.has("h") {
        print_usage(usage_name);
        return Ok(());
    }

    // `RNS.Reticulum(configdir, loglevel=3+verbosity)`.
    crate::pylog::install_utility_logging(
        args.config_path(),
        Some(crate::pylog::LOG_NOTICE + i32::from(args.verbosity)),
        0,
        false,
    );

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
        return Err(Exit::FAILURE);
    }

    // Remote management query via -R flag
    if let Some(ref hash_str) = remote_hash {
        return remote_status(
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
    }

    // Discovered interfaces query via -d or -D flag
    if (show_discovered || show_discovered_config) && management_actions.is_empty() {
        // Load config to get RPC address and auth key
        let config_dir =
            storage::resolve_config_dir(config_path.as_ref().map(|s| Path::new(s.as_str())));
        let LocalInstance { paths, rpc, .. } = match LocalInstance::open(&config_dir) {
            Ok(instance) => instance,
            Err(e) => {
                eprintln!("{e}");
                return Err(Exit::FAILURE);
            }
        };

        let _instance_client = attach_to_instance(&config_dir);
        let Ok(mut client) = rpc.connect() else {
            println!("No shared RNS instance available to get status from");
            return Err(Exit::FAILURE);
        };

        show_discovered_interfaces(
            &mut client,
            show_discovered_config,
            json_output,
            show_stale,
            show_unknown,
            filter.as_deref(),
            &paths.discovered_interfaces,
        );
        return Ok(());
    }

    // Load config to get RPC address and auth key
    let config_dir =
        storage::resolve_config_dir(config_path.as_ref().map(|s| Path::new(s.as_str())));
    let rpc = match LocalInstance::open(&config_dir) {
        Ok(instance) => instance.rpc,
        Err(e) => {
            eprintln!("{e}");
            return Err(Exit::FAILURE);
        }
    };

    let _instance_client = attach_to_instance(&config_dir);
    if let Some((operation, name)) = management_actions.first().copied() {
        let Ok(mut client) = rpc.connect() else {
            println!("No shared RNS instance available to get status from");
            return Err(Exit::FAILURE);
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
                return Ok(());
            }
            Ok(PickleValue::Bool(false)) => println!("Could not {operation} interface {name}"),
            Ok(PickleValue::None) => println!("The interface {name} does not exist"),
            _ => println!("Unknown error while {operation}ing interface {name}"),
        }
        return Err(Exit::FAILURE);
    }

    // Like upstream's client, each query is a connection of its own.
    let query = |what: &str| -> std::io::Result<PickleValue> {
        rpc.connect()?.call(&PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String(what.into()),
        )]))
    };
    if rpc.connect().is_err() {
        println!("No shared RNS instance available to get status from");
        return Err(Exit::FAILURE);
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
                return Err(Exit(2));
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
    Ok(())
}

struct NoCallbacks;

impl rns_net::Callbacks for NoCallbacks {}

/// Start Reticulum as a client of the shared instance, as upstream's
/// rnstatus does (`require_shared_instance`): the instance then serves it
/// as one of its programs, which its "Serving" count leaves out by
/// subtracting one, and lists it among its local clients. Kept for as
/// long as rnstatus runs; whether the instance answers is the RPC's to
/// tell.
fn attach_to_instance(config_dir: &Path) -> Option<rns_net::RnsNode> {
    rns_net::RnsNode::connect_shared_from_config(Some(config_dir), Box::new(NoCallbacks)).ok()
}

fn monitor_sleep_duration(interval_secs: f64, elapsed: Duration) -> Duration {
    let interval = Duration::try_from_secs_f64(interval_secs.max(0.0)).unwrap_or(Duration::MAX);
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
    crate::format::python_json(stats)
}

/// Print the status display as upstream does.
fn show_status(stats: &PickleValue, view: &ViewOptions, extras: &Extras<'_>) {
    print!("{}", render(stats, view, extras, rns_net::time::now()));
}

/// upstream's `"\r" + 58 spaces + "\r"`, which clears its progress line.
const CLEAR_LINE: &str = "\r                                                          \r";

/// Where `-R` progress goes: straight to stdout, or, in monitor mode, into
/// the frame printed after the screen is cleared, as upstream buffers it.
#[derive(Clone, Default)]
struct ProgressOut(std::sync::Arc<std::sync::Mutex<Option<String>>>);

impl ProgressOut {
    fn write(&self, text: &str) {
        let mut buffer = self.0.lock().unwrap_or_else(|e| e.into_inner());
        match buffer.as_mut() {
            Some(buffer) => buffer.push_str(text),
            None => {
                print!("{text}");
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }
        }
    }

    fn buffer(&self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(String::new());
    }

    fn take(&self) -> String {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(String::new())
            .unwrap_or_default()
    }
}

/// `-R`: upstream's `get_remote_status` and the remote branch of
/// `program_setup`, with its progress lines, messages and exit codes.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a separate command-line option of the -R mode"
)]
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
) -> Status {
    use rns_net::remote_management::{RemoteManagementError as E, RemoteProgress};

    let fail = |message: &str| -> Status {
        println!("{message}");
        Err(Exit(20))
    };
    let Some(identity_path) = management_identity else {
        return fail("Remote management requires an identity file. Use -i to specify the path to a management identity.");
    };
    if hash_str.chars().count() != 32 {
        return fail(
            "Destination length is invalid, must be 32 hexadecimal characters (16 bytes).",
        );
    }
    let Ok(transport_hash) = rns_net::remote_management::parse_transport_identity_hash(hash_str)
    else {
        return fail("Invalid destination entered. Check your input.");
    };
    let identity_path = crate::app::expand_path(identity_path);
    let timeout = Duration::try_from_secs_f64(remote_timeout.max(0.2)).unwrap_or(Duration::MAX);
    let mut client = match rns_net::remote_management::RemoteManagementClient::connect(
        config_path.map(Path::new),
        Some(identity_path.as_path()),
        timeout,
    ) {
        Ok(client) => client,
        Err(E::IdentityLoad(_)) => {
            return fail(&format!(
                "Could not load management identity from {}",
                management_identity.unwrap_or_default()
            ))
        }
        Err(_) => {
            println!("No shared RNS instance available to get status from");
            return Err(Exit::FAILURE);
        }
    };

    let out = ProgressOut::default();
    if monitor_mode {
        out.buffer();
    }
    // upstream's get_remote_status prints nothing of its progress for -j.
    if !json_output {
        let progress = out.clone();
        client.set_progress(move |stage| match stage {
            RemoteProgress::PathRequested(dest) => {
                progress.write(&format!("Path to {} requested ", prettyhexrep(&dest)));
            }
            RemoteProgress::EstablishingLink => progress.write(&format!(
                "{CLEAR_LINE}Establishing link with remote transport instance... "
            )),
            RemoteProgress::SendingRequest => {
                progress.write(&format!("{CLEAR_LINE}Sending request... "));
            }
        });
    }

    loop {
        let monitor_started = Instant::now();
        let result = client.status_with_profiling(transport_hash, view.lstats, show_profiling);
        let quiet = json_output;
        let say = |line: &str| {
            if !quiet {
                out.write(&format!("{CLEAR_LINE}{line}\n"));
            }
        };
        let remote = match result {
            Ok(remote) => {
                out.write(CLEAR_LINE);
                Some(remote)
            }
            Err(E::PathTimeout(_) | E::RecallTimeout(_)) => {
                say("Path request timed out");
                finish_frame(&out, monitor_mode);
                return Err(Exit(12));
            }
            Err(E::LinkTimeout(_)) | Err(E::LinkClosed(Some(TeardownReason::Timeout))) => {
                say("The link timed out, exiting now");
                finish_frame(&out, monitor_mode);
                return Err(Exit(10));
            }
            Err(E::LinkClosed(Some(TeardownReason::DestinationClosed))) => {
                say("The link was closed by the server, exiting now");
                finish_frame(&out, monitor_mode);
                return Err(Exit(10));
            }
            Err(E::LinkClosed(_)) => {
                say("Link closed unexpectedly, exiting now");
                finish_frame(&out, monitor_mode);
                return Err(Exit(10));
            }
            Err(E::RequestTimeout(_) | E::SendFailed) => {
                say("The remote status request failed. Likely authentication failure.");
                None
            }
            Err(_) => None,
        };

        match remote {
            Some(remote) => {
                let frame = out.take();
                if monitor_mode {
                    print!("\x1b[H\x1b[2J");
                }
                print!("{frame}");
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
            None => {
                out.write(&format!(
                    "Could not get RNS status from remote transport instance {}\n",
                    prettyhexrep(&transport_hash)
                ));
                if !monitor_mode {
                    return Err(Exit(2));
                }
                finish_frame(&out, monitor_mode);
            }
        }

        if !monitor_mode {
            break;
        }
        out.buffer();
        std::thread::sleep(monitor_sleep_duration(
            monitor_interval,
            monitor_started.elapsed(),
        ));
    }
    Ok(())
}

/// In monitor mode, show what was buffered for this frame.
fn finish_frame(out: &ProgressOut, monitor_mode: bool) {
    if monitor_mode {
        print!("\x1b[H\x1b[2J{}", out.take());
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
}

/// Show discovered interfaces
fn show_discovered_interfaces(
    client: &mut RpcClient,
    show_config: bool,
    json_output: bool,
    show_stale: bool,
    show_unknown: bool,
    name_filter: Option<&str>,
    discovered_dir: &Path,
) {
    let response = client
        .call(&PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("discovered_interfaces".into()),
        )]))
        .ok()
        .filter(|response| response.as_list().is_some())
        .unwrap_or_else(|| {
            // An instance without this call (upstream's has none): read the
            // stored records, as upstream's rnstatus always does.
            let mut interfaces =
                rns_net::discovery::DiscoveredInterfaceStorage::new(discovered_dir.to_path_buf())
                    .list()
                    .unwrap_or_default();
            rns_net::discovery::filter_and_sort_interfaces(&mut interfaces, false, false);
            rns_net::rpc::discovered_interfaces_to_pickle(&interfaces)
        });

    let records: Vec<PickleValue> = response
        .as_list()
        .map(|list| list.iter().map(upstream_discovery_record).collect())
        .unwrap_or_default();
    if json_output {
        print!("{}", render_discovered_json(&records));
    } else {
        print!(
            "{}",
            render_discovered(
                &records,
                show_config,
                name_filter,
                show_stale,
                show_unknown,
                rns_net::time::now(),
            )
        );
    }
}

fn print_usage(usage_name: &str) {
    crate::argparse::print_help("rnstatus", usage_name);
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
