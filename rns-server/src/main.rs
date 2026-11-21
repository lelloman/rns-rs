//! rns-server - supervises rnsd and its sidecars behind an embedded HTTP
//! control plane.

use std::net::TcpListener;
use std::process::ExitCode;
use std::thread;

use rns_cli::args::Args as CliArgs;
use rns_ctl::cmd::http::{prepare_embedded_with_state, HttpRunOptions};
use rns_ctl::state::SharedState;
use rns_server::args::Args;
use rns_server::config::ServerConfig;
use rns_server::control_plane::{install_config_bridge, new_supervised_state};
use rns_server::supervisor::Supervisor;

fn main() -> ExitCode {
    let args = Args::parse();

    if let Some(role) = args.get("internal-role") {
        return run_internal_role(role);
    }

    if args.has("version") {
        println!("rns-server {}", env!("FULL_VERSION"));
        return ExitCode::SUCCESS;
    }

    let Some(subcommand) = args.positional.first().filter(|_| !args.has("help")) else {
        print_help();
        return ExitCode::SUCCESS;
    };
    let subcommand = subcommand.clone();

    init_logging(&args);

    match subcommand.as_str() {
        "start" => run_start(args),
        other => {
            eprintln!("Unknown subcommand: {}", other);
            print_help();
            ExitCode::FAILURE
        }
    }
}

fn run_internal_role(role: &str) -> ExitCode {
    let argv = sanitized_internal_argv();
    match role {
        "rnsd" => rns_cli::exit::exit_code(rns_cli::rnsd::main_entry_from(
            CliArgs::parse_spec_from(argv, &rns_cli::rnsd::OPTIONS),
        )),
        #[cfg(any(
            feature = "rns-hooks-native",
            feature = "rns-hooks-wasm",
            feature = "rns-hooks-builtin"
        ))]
        "rns-sentineld" => {
            rns_cli::sentineld::main_entry_from(rns_cli::sentineld::parse_args(argv))
        }
        #[cfg(any(
            feature = "rns-hooks-native",
            feature = "rns-hooks-wasm",
            feature = "rns-hooks-builtin"
        ))]
        "rns-statsd" => rns_cli::statsd::main_entry_from(rns_cli::statsd::parse_args(argv)),
        other => {
            eprintln!("rns-server: unknown internal role '{}'", other);
            ExitCode::FAILURE
        }
    }
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

fn run_start(args: Args) -> ExitCode {
    let (shared_state, _control_tx, control_rx) = new_supervised_state();
    let config = ServerConfig::from_args(&args);
    if let Err(err) = config.ensure_runtime_bootstrap() {
        eprintln!("rns-server: {}", err);
        return ExitCode::FAILURE;
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
        return ExitCode::SUCCESS;
    }

    let supervisor =
        Supervisor::new(config.supervisor_config(Some(shared_state.clone()), Some(control_rx)));

    match supervisor.run_with_started_hook(|| {
        if config.http_enabled() {
            start_control_http(&config, args.verbosity, shared_state.clone())?;
        }
        Ok(())
    }) {
        Ok(code) => rns_cli::exit::code(code),
        Err(err) => {
            eprintln!("rns-server: {}", err);
            ExitCode::FAILURE
        }
    }
}

fn init_logging(args: &Args) {
    let configured = configured_logging(args.config_path());
    let log_level =
        rns_net::logging::adjust_log_level(configured.loglevel, args.verbosity, args.quiet);
    let filter = rns_net::logging::numeric_log_filter(log_level);

    let mut builder = env_logger::Builder::new();
    builder
        .filter_level(filter.default)
        .filter_module(rns_net::logging::PATHING_LOG_TARGET, filter.pathing);
    if configured.logtimestamps {
        builder.format_timestamp_secs();
    } else {
        builder.format_timestamp(None);
    }
    builder.init();
}

fn configured_logging(config_path: Option<&str>) -> rns_net::config::LoggingSection {
    let config_dir = rns_net::storage::resolve_config_dir(config_path.map(std::path::Path::new));
    let config_file = config_dir.join("config");
    if config_file.exists() {
        match rns_net::config::parse_file(&config_file) {
            Ok(config) => config.logging,
            Err(err) => {
                eprintln!(
                    "Could not parse logging config {}: {}",
                    config_file.display(),
                    err
                );
                rns_net::config::LoggingSection::default()
            }
        }
    } else {
        rns_net::config::LoggingSection::default()
    }
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
            log_policy: rns_server::logs::LogPolicy::default(),
            stats_policy: rns_server::config::StatsPolicy {
                max_age_days: Some(30),
                max_size_mb: Some(4096),
            },
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
            rnsd_rpc_addr: rns_net::RpcAddr::local("default", 37429),
            rnsd_rpc_key: None,
        }
    }

    #[test]
    fn configured_logging_reads_reticulum_logging_section() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config"),
            "[logging]\nloglevel = 7\nlogtimestamps = no\n",
        )
        .unwrap();

        let configured = configured_logging(dir.path().to_str());
        assert_eq!(configured.loglevel, rns_net::logging::LOG_PATHING);
        assert!(!configured.logtimestamps);
    }

    #[test]
    fn configured_logging_defaults_when_config_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let configured = configured_logging(dir.path().to_str());

        assert_eq!(configured.loglevel, rns_net::logging::LOG_INFO);
        assert!(configured.logtimestamps);
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
