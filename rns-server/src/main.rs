use std::path::PathBuf;
use std::sync::{mpsc, Arc, RwLock};
use std::thread;
use std::time::Duration;

use rns_ctl::cmd::http::{prepare_embedded_with_state, HttpRunOptions};
use rns_ctl::state::{ensure_process, set_control_tx, set_server_mode, CtlState, SharedState};
use rns_server::args::Args;
use rns_server::supervisor::{Supervisor, SupervisorConfig};

fn main() {
    let args = Args::parse();

    if args.has("version") {
        println!("rns-server {}", env!("FULL_VERSION"));
        return;
    }

    if args.has("help") || args.positional.is_empty() {
        print_help();
        return;
    }

    init_logging(&args);

    match args.positional[0].as_str() {
        "start" => run_start(args),
        other => {
            eprintln!("Unknown subcommand: {}", other);
            print_help();
            std::process::exit(1);
        }
    }
}

fn run_start(args: Args) {
    let shared_state: SharedState = Arc::new(RwLock::new(CtlState::new()));
    let (control_tx, control_rx) = mpsc::channel();
    set_server_mode(&shared_state, "supervised");
    set_control_tx(&shared_state, control_tx);
    ensure_process(&shared_state, "rnsd");
    ensure_process(&shared_state, "rns-sentineld");
    ensure_process(&shared_state, "rns-statsd");

    let config_path = args.config_path().map(PathBuf::from);
    let config_dir = rns_net::storage::resolve_config_dir(args.config_path().map(std::path::Path::new));
    let default_stats_db = config_dir.join("stats.db");

    let dry_run = args.has("dry-run");
    let config = SupervisorConfig {
        config_path,
        stats_db_path: args
            .get("stats-db")
            .map(PathBuf::from)
            .unwrap_or(default_stats_db),
        rnsd_bin: args
            .get("rnsd-bin")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("rnsd")),
        sentineld_bin: args
            .get("sentineld-bin")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("rns-sentineld")),
        statsd_bin: args
            .get("statsd-bin")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("rns-statsd")),
        shared_state: Some(shared_state.clone()),
        control_rx: Some(control_rx),
        dry_run,
    };

    if dry_run {
        let supervisor = Supervisor::new(config);
        for spec in supervisor.specs() {
            println!("{}", spec.command_line());
        }
        if !args.has("no-http") {
            println!("{}", control_http_command_line(&args));
        }
        return;
    }

    let supervisor = Supervisor::new(config);

    let http_enabled = !args.has("no-http");

    match supervisor.run_with_started_hook(|| {
        if http_enabled {
            start_control_http(&args, shared_state.clone())?;
        }
        Ok(())
    }) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("rns-server: {}", err);
            std::process::exit(1);
        }
    }
}

fn init_logging(args: &Args) {
    let log_level = if args.quiet > 0 {
        match args.quiet {
            1 => log::LevelFilter::Warn,
            _ => log::LevelFilter::Error,
        }
    } else {
        match args.verbosity {
            0 => log::LevelFilter::Info,
            1 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        }
    };

    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp_secs()
        .init();
}

fn start_control_http(args: &Args, shared_state: SharedState) -> Result<(), String> {
    let ctl_args = build_ctl_http_args(args);
    log::info!("starting embedded control plane");
    thread::Builder::new()
        .name("rns-server-http".into())
        .spawn(move || {
            for attempt in 1..=50 {
                match prepare_embedded_with_state(
                    ctl_args(),
                    HttpRunOptions::embedded(),
                    Some(shared_state.clone()),
                ) {
                    Ok(prepared) => {
                        if let Err(err) = rns_ctl::server::run_server(prepared.addr, prepared.ctx) {
                            log::error!("embedded control plane failed: {}", err);
                        }
                        return;
                    }
                    Err(err) => {
                        if attempt == 50 {
                            log::error!("embedded control plane failed: {}", err);
                            return;
                        }
                        log::debug!(
                            "embedded control plane not ready yet (attempt {}): {}",
                            attempt,
                            err
                        );
                        thread::sleep(Duration::from_millis(200));
                    }
                }
            }
        })
        .map_err(|e| format!("failed to spawn control plane thread: {}", e))?;
    Ok(())
}

fn build_ctl_http_args(args: &Args) -> impl Fn() -> rns_ctl::args::Args + Send + 'static {
    let config_path = args.config_path().map(ToOwned::to_owned);
    let host = args.get("http-host").map(ToOwned::to_owned);
    let port = args.get("http-port").map(ToOwned::to_owned);
    let token = args.get("http-token").map(ToOwned::to_owned);
    let disable_auth = args.has("disable-auth");
    let verbosity = args.verbosity;

    move || {
        let mut argv = vec!["--daemon".to_string()];
        if let Some(config_path) = &config_path {
            argv.push("--config".into());
            argv.push(config_path.clone());
        }
        if let Some(host) = &host {
            argv.push("--host".into());
            argv.push(host.clone());
        }
        if let Some(port) = &port {
            argv.push("--port".into());
            argv.push(port.clone());
        }
        if let Some(token) = &token {
            argv.push("--token".into());
            argv.push(token.clone());
        }
        if disable_auth {
            argv.push("--disable-auth".into());
        }
        if verbosity > 0 {
            argv.push(format!("-{}", "v".repeat(verbosity as usize)));
        }
        rns_ctl::args::Args::parse_from(argv)
    }
}

fn control_http_command_line(args: &Args) -> String {
    let mut parts = vec!["embedded rns-ctl http".to_string(), "--daemon".to_string()];
    if let Some(config) = args.config_path() {
        parts.push("--config".to_string());
        parts.push(config.to_string());
    }
    if let Some(host) = args.get("http-host") {
        parts.push("--host".to_string());
        parts.push(host.to_string());
    }
    if let Some(port) = args.get("http-port") {
        parts.push("--port".to_string());
        parts.push(port.to_string());
    }
    if let Some(token) = args.get("http-token") {
        parts.push("--token".to_string());
        parts.push(token.to_string());
    }
    if args.has("disable-auth") {
        parts.push("--disable-auth".to_string());
    }
    parts.join(" ")
}

fn print_help() {
    println!(
        "rns-server - batteries-included Reticulum node server

USAGE:
    rns-server start [OPTIONS]

OPTIONS:
    -c, --config PATH        Path to config directory
        --stats-db PATH      Path to stats SQLite database
        --rnsd-bin PATH      Path to rnsd executable (default: rnsd)
        --sentineld-bin PATH Path to rns-sentineld executable (default: rns-sentineld)
        --statsd-bin PATH    Path to rns-statsd executable (default: rns-statsd)
        --http-host HOST     Host for embedded control HTTP server
        --http-port PORT     Port for embedded control HTTP server
        --http-token TOKEN   Auth token for embedded control HTTP server
        --disable-auth       Disable auth on embedded control HTTP server
        --no-http            Disable the embedded control HTTP server
        --dry-run            Print the child process plan and exit
    -v                       Increase verbosity (repeat for more)
    -q                       Decrease verbosity (repeat for more)
    -h, --help               Show this help
        --version            Show version"
    );
}
