use std::net::TcpListener;
use std::thread;

use rns_cli::args::Args as CliArgs;
use rns_ctl::cmd::http::{prepare_embedded_with_state, HttpRunOptions};
use rns_ctl::state::SharedState;
use rns_server::args::Args;
use rns_server::config::ServerConfig;
use rns_server::control_plane::{install_config_bridge, new_supervised_state};
use rns_server::supervisor::Supervisor;

fn main() {
    let args = Args::parse();

    if let Some(role) = args.get("internal-role") {
        run_internal_role(role);
    }

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

fn run_internal_role(role: &str) -> ! {
    let child_args = CliArgs::parse_from(sanitized_internal_argv());
    match role {
        "rnsd" => rns_cli::rnsd::main_entry_from(child_args),
        #[cfg(feature = "rns-hooks")]
        "rns-sentineld" => rns_cli::sentineld::main_entry_from(child_args),
        #[cfg(feature = "rns-hooks")]
        "rns-statsd" => rns_cli::statsd::main_entry_from(child_args),
        other => {
            eprintln!("rns-server: unknown internal role '{}'", other);
            std::process::exit(1);
        }
    }
    std::process::exit(0);
}

fn sanitized_internal_argv() -> Vec<String> {
    let mut args = std::env::args().skip(1);
    let mut sanitized = Vec::new();
    while let Some(arg) = args.next() {
        if arg == "--internal-role" {
            let _ = args.next();
            continue;
        }
        sanitized.push(arg);
    }
    sanitized
}

fn run_start(args: Args) {
    let (shared_state, _control_tx, control_rx) = new_supervised_state();
    let config = ServerConfig::from_args(&args);
    if let Err(err) = config.ensure_runtime_bootstrap() {
        eprintln!("rns-server: {}", err);
        std::process::exit(1);
    }
    install_config_bridge(&shared_state, &args, &config);
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
    let prepared = prepare_embedded_with_state(
        config.ctl_args(verbosity),
        HttpRunOptions::embedded(),
        Some(shared_state.clone()),
    )?;
    let listener = TcpListener::bind(prepared.addr).map_err(|e| {
        format!(
            "failed to bind embedded control plane {}: {}",
            prepared.addr, e
        )
    })?;

    thread::Builder::new()
        .name("rns-server-http".into())
        .spawn(move || {
            let _ = (config, verbosity, shared_state);
            if let Err(err) = rns_ctl::server::run_server_with_listener(listener, prepared.ctx) {
                log::error!("embedded control plane failed: {}", err);
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
        --rnsd-bin PATH      Advanced override for rnsd executable
        --sentineld-bin PATH Advanced override for rns-sentineld executable
        --statsd-bin PATH    Advanced override for rns-statsd executable
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

#[cfg(test)]
mod tests {
    use super::*;
    use rns_server::config::{HttpConfig, ServerConfig, ServerConfigFile};
    use rns_server::control_plane::new_supervised_state;
    use std::path::PathBuf;

    fn test_server_config(http_port: u16) -> ServerConfig {
        let config_dir = std::env::temp_dir().join(format!(
            "rns-server-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&config_dir).unwrap();
        ServerConfig {
            config_path: Some(config_dir.clone()),
            resolved_config_dir: config_dir.clone(),
            server_config_file_path: config_dir.join("rns-server.json"),
            server_config_file_present: false,
            file_config: ServerConfigFile::default(),
            stats_db_path: config_dir.join("stats.db"),
            rnsd_bin: PathBuf::new(),
            sentineld_bin: PathBuf::new(),
            statsd_bin: PathBuf::new(),
            http: HttpConfig {
                enabled: true,
                host: "127.0.0.1".into(),
                port: http_port,
                auth_token: None,
                disable_auth: true,
                daemon_mode: true,
            },
            rnsd_rpc_addr: "127.0.0.1:37429".parse().unwrap(),
        }
    }

    #[test]
    fn start_control_http_fails_fast_when_port_is_in_use() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = test_server_config(port);
        let (shared_state, _control_tx, _control_rx) = new_supervised_state();

        let err = start_control_http(&config, 0, shared_state).unwrap_err();
        assert!(err.contains("failed to bind embedded control plane"));
    }
}
