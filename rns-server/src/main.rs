use std::sync::{mpsc, Arc, RwLock};
use std::thread;
use std::time::Duration;

use rns_ctl::cmd::http::{prepare_embedded_with_state, HttpRunOptions};
use rns_ctl::state::{
    ensure_process, set_control_tx, set_server_config, set_server_mode, CtlState, SharedState,
};
use rns_server::args::Args;
use rns_server::config::ServerConfig;
use rns_server::supervisor::Supervisor;

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
    let config = ServerConfig::from_args(&args);
    set_server_config(&shared_state, config.snapshot());
    let dry_run = args.has("dry-run");

    if dry_run {
        let supervisor = Supervisor::new(config.supervisor_config(None, None));
        for spec in supervisor.specs() {
            println!("{}", spec.command_line());
        }
        if config.http_enabled() {
            println!("{}", config.control_http_command_line());
        }
        return;
    }

    let supervisor =
        Supervisor::new(config.supervisor_config(Some(shared_state.clone()), Some(control_rx)));

    match supervisor.run_with_started_hook(|| {
        if config.http_enabled() {
            start_control_http(&config, args.verbosity, shared_state.clone())?;
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

fn start_control_http(
    config: &ServerConfig,
    verbosity: u8,
    shared_state: SharedState,
) -> Result<(), String> {
    let config = config.clone();
    log::info!("starting embedded control plane");
    thread::Builder::new()
        .name("rns-server-http".into())
        .spawn(move || {
            for attempt in 1..=50 {
                match prepare_embedded_with_state(
                    config.ctl_args(verbosity),
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
