//! HTTP/WebSocket control server subcommand.

use std::io::{IsTerminal, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rns_crypto::identity::Identity;
use rns_crypto::Rng;

use crate::api;
use crate::args::Args;
use crate::{bridge, config, encode, server, state};

pub fn run(args: Args) {
    if let Err(err) = run_embedded(args, HttpRunOptions::standalone()) {
        eprintln!("rns-ctl http: {}", err);
        std::process::exit(1);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HttpRunOptions {
    pub init_logging: bool,
    pub install_signal_handler: bool,
}

impl HttpRunOptions {
    pub fn standalone() -> Self {
        Self {
            init_logging: true,
            install_signal_handler: true,
        }
    }

    pub fn embedded() -> Self {
        Self {
            init_logging: false,
            install_signal_handler: false,
        }
    }
}

pub fn run_embedded(args: Args, options: HttpRunOptions) -> Result<(), String> {
    if args.has("help") {
        print_help();
        return Ok(());
    }

    if args.has("version") {
        println!("rns-ctl {}", env!("FULL_VERSION"));
        return Ok(());
    }

    let prepared = prepare_embedded_with_state(args, options, None)?;
    server::run_server(prepared.addr, prepared.ctx).map_err(|e| format!("server error: {}", e))
}

pub struct PreparedHttpServer {
    pub addr: SocketAddr,
    pub ctx: Arc<server::ServerContext>,
}

pub fn prepare_embedded_with_state(
    args: Args,
    options: HttpRunOptions,
    shared_state_override: Option<state::SharedState>,
) -> Result<PreparedHttpServer, String> {
    if options.init_logging {
        // Init logging
        let log_level = match args.verbosity {
            0 => "info",
            1 => "debug",
            _ => "trace",
        };
        if std::env::var("RUST_LOG").is_err() {
            std::env::set_var(
                "RUST_LOG",
                format!(
                    "rns_ctl={},rns_net={},rns_hooks={}",
                    log_level, log_level, log_level
                ),
            );
        }
        let _ = env_logger::try_init();
    }

    let mut cfg = config::from_args_and_env(&args);

    // Generate a random auth token if none provided and auth is not disabled
    if cfg.auth_token.is_none() && !cfg.disable_auth {
        let mut token_bytes = [0u8; 24];
        rns_crypto::OsRng.fill_bytes(&mut token_bytes);
        let token = encode::to_hex(&token_bytes);
        publish_generated_token(&token, cfg.config_path.as_deref().map(Path::new))?;
        cfg.auth_token = Some(token);
    }

    // Create shared state and broadcast registry
    let shared_state = shared_state_override
        .unwrap_or_else(|| Arc::new(std::sync::RwLock::new(state::CtlState::new())));
    let ws_broadcast: state::WsBroadcast = Arc::new(Mutex::new(Vec::new()));

    // Resolve config path and expose local identity before the shared node client is ready.
    let config_path = cfg.config_path.as_deref().map(Path::new);
    load_identity_into_state(config_path, &shared_state);

    // Wrap node for shared access. Daemon mode attaches the shared client asynchronously
    // so the HTTP control plane can bind even while rnsd is still bringing up slow peers.
    let node_handle: api::NodeHandle = Arc::new(Mutex::new(None));
    let node_for_shutdown = node_handle.clone();

    // Store node handle in shared state so callbacks can access it
    {
        let mut s = state::write_state(&shared_state);
        s.node_handle = Some(node_handle.clone());
    }

    if cfg.daemon_mode {
        start_shared_node_connector(
            cfg.clone(),
            shared_state.clone(),
            ws_broadcast.clone(),
            node_handle.clone(),
        );
    } else {
        let callbacks = Box::new(bridge::CtlCallbacks::new(
            shared_state.clone(),
            ws_broadcast.clone(),
        ));
        log::info!("Starting RNS node...");
        let node = rns_net::RnsNode::from_config(config_path, callbacks)
            .map_err(|e| format!("failed to start node: {}", e))?;
        *state::lock_node_handle(&node_handle) = Some(node);
    }

    // Set up ctrl-c handler
    if options.install_signal_handler {
        let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_flag_handler = shutdown_flag.clone();

        ctrlc_handler(move || {
            if shutdown_flag_handler.swap(true, std::sync::atomic::Ordering::SeqCst) {
                std::process::exit(1);
            }
            log::info!("Shutting down...");
            if let Some(node) = state::lock_node_handle(&node_for_shutdown).take() {
                node.shutdown();
            }
            std::process::exit(0);
        });
    } else {
        let _ = node_for_shutdown;
    }

    // Validate and load TLS config
    #[cfg(feature = "tls")]
    let tls_config = {
        match (&cfg.tls_cert, &cfg.tls_key) {
            (Some(cert), Some(key)) => match crate::tls::load_tls_config(cert, key) {
                Ok(config) => {
                    log::info!("TLS enabled with cert={} key={}", cert, key);
                    Some(config)
                }
                Err(e) => {
                    return Err(format!("failed to load TLS config: {}", e));
                }
            },
            (Some(_), None) | (None, Some(_)) => {
                return Err("both --tls-cert and --tls-key must be provided together".into());
            }
            (None, None) => None,
        }
    };

    #[cfg(not(feature = "tls"))]
    {
        if cfg.tls_cert.is_some() || cfg.tls_key.is_some() {
            return Err(
                "TLS options require the 'tls' feature. Rebuild with: cargo build --features tls"
                    .into(),
            );
        }
    }

    // Build server context
    let config_handle = Arc::new(std::sync::RwLock::new(cfg));
    state::set_control_plane_config(&shared_state, config_handle.clone());
    let ctx = Arc::new(server::ServerContext {
        node: node_handle,
        state: shared_state,
        ws_broadcast,
        config: config_handle.clone(),
        #[cfg(feature = "tls")]
        tls_config,
    });

    let cfg = state::read_control_plane_config(&config_handle);
    let addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port)
        .parse()
        .map_err(|_| "invalid bind address".to_string())?;

    Ok(PreparedHttpServer { addr, ctx })
}

/// Name of the file, inside the config directory, that receives a generated
/// bearer token.
pub const TOKEN_FILE_NAME: &str = "http-token";

/// Path of the generated token file for a config directory.
pub fn token_file_path(config_path: Option<&Path>) -> PathBuf {
    rns_net::storage::resolve_config_dir(config_path).join(TOKEN_FILE_NAME)
}

/// Make a generated token available to the operator without passing it
/// through the logger: it is written to an owner-only file, and printed
/// once when stdout is a terminal.
fn publish_generated_token(token: &str, config_path: Option<&Path>) -> Result<(), String> {
    let path = token_file_path(config_path);
    let interactive = std::io::stdout().is_terminal();
    match write_token_file(&path, token) {
        Ok(()) => log::info!("{}", token_file_log_message(&path)),
        Err(err) => {
            let msg = format!(
                "failed to write auth token file {}: {}",
                path.display(),
                err
            );
            if !interactive {
                return Err(msg);
            }
            log::warn!("{}", msg);
        }
    }
    if interactive {
        println!(
            "Auth token (shown once; also stored in {}): {}",
            path.display(),
            token
        );
    }
    Ok(())
}

/// Log line announcing where the generated token was stored.
fn token_file_log_message(path: &Path) -> String {
    format!("Generated auth token written to {}", path.display())
}

/// Write `token` to `path` with mode 0600, replacing any previous file.
fn write_token_file(path: &Path, token: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        let file = options.open(path)?;
        // `mode` only applies on creation; tighten a pre-existing file too.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        write_token(file, token)
    }
    #[cfg(not(unix))]
    {
        write_token(options.open(path)?, token)
    }
}

fn write_token(mut file: std::fs::File, token: &str) -> std::io::Result<()> {
    writeln!(file, "{}", token)?;
    file.sync_all()
}

fn load_identity_into_state(config_path: Option<&Path>, shared_state: &state::SharedState) {
    let config_dir = rns_net::storage::resolve_config_dir(config_path);
    let paths = rns_net::storage::ensure_storage_dirs(&config_dir).ok();
    let identity: Option<Identity> = paths
        .as_ref()
        .and_then(|p| rns_net::storage::load_or_create_identity(&p.identities).ok());

    let mut s = state::write_state(shared_state);
    if let Some(ref id) = identity {
        s.identity_hash = Some(*id.hash());
        // Identity doesn't impl Clone; copy via private key.
        if let Some(prv) = id.get_private_key() {
            s.identity = Some(Identity::from_private_key(&prv));
        }
    }
}

fn start_shared_node_connector(
    cfg: config::CtlConfig,
    shared_state: state::SharedState,
    ws_broadcast: state::WsBroadcast,
    node_handle: api::NodeHandle,
) {
    thread::Builder::new()
        .name("rns-ctl-shared-client".into())
        .spawn(move || {
            let mut attempt: u64 = 0;
            log::info!("Connecting as shared client (daemon mode)");
            loop {
                attempt += 1;
                let callbacks = Box::new(bridge::CtlCallbacks::new(
                    shared_state.clone(),
                    ws_broadcast.clone(),
                ));
                let config_path = cfg.config_path.as_deref().map(Path::new);

                match rns_net::RnsNode::connect_shared_from_config(config_path, callbacks) {
                    Ok(node) => {
                        *state::lock_node_handle(&node_handle) = Some(node);
                        log::info!("connected embedded HTTP control plane to shared rnsd");
                        return;
                    }
                    Err(err) => {
                        if attempt == 1 || attempt.is_multiple_of(10) {
                            log::warn!(
                                "shared rnsd not ready for embedded HTTP control plane (attempt {}): {}",
                                attempt,
                                err
                            );
                        } else {
                            log::debug!(
                                "shared rnsd not ready for embedded HTTP control plane (attempt {}): {}",
                                attempt,
                                err
                            );
                        }
                        thread::sleep(Duration::from_millis(500));
                    }
                }
            }
        })
        .ok();
}

/// Set up a shutdown signal handler for SIGINT and SIGTERM.
fn ctrlc_handler<F: FnOnce() + Send + 'static>(handler: F) {
    let handler = Mutex::new(Some(handler));
    libc_signal(move || {
        if let Some(f) = match handler.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::error!("recovering from poisoned signal handler lock");
                poisoned.into_inner()
            }
        }
        .take()
        {
            f();
        }
    });
}

/// Register a SIGINT and SIGTERM handler using libc, polling in a background
/// thread. SIGTERM is what `docker stop`, `systemctl stop` and `kill` send;
/// without it the process ran until the supervisor's kill timeout.
fn libc_signal<F: FnMut() + Send + 'static>(mut callback: F) {
    std::thread::Builder::new()
        .name("signal-handler".into())
        .spawn(move || {
            use std::sync::atomic::{AtomicBool, Ordering};
            static SIGNALED: AtomicBool = AtomicBool::new(false);

            #[cfg(unix)]
            {
                extern "C" fn sig_handler(_: i32) {
                    SIGNALED.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                unsafe {
                    libc_ffi::signal(libc_ffi::SIGINT, sig_handler as *const () as usize);
                    libc_ffi::signal(libc_ffi::SIGTERM, sig_handler as *const () as usize);
                }
            }

            loop {
                std::thread::sleep(Duration::from_millis(100));
                if SIGNALED.swap(false, Ordering::SeqCst) {
                    callback();
                    break;
                }
            }
        })
        .ok();
}

#[cfg(unix)]
mod libc_ffi {
    extern "C" {
        pub fn signal(sig: i32, handler: usize) -> usize;
    }
    pub const SIGINT: i32 = 2;
    pub const SIGTERM: i32 = 15;
}

fn print_help() {
    println!(
        "rns-ctl http - HTTP/WebSocket control interface for Reticulum

USAGE:
    rns-ctl http [OPTIONS]

OPTIONS:
    -c, --config PATH       Path to RNS config directory
    -p, --port PORT         HTTP port (default: 8080, env: RNSCTL_HTTP_PORT)
    -H, --host HOST         Bind host (default: 127.0.0.1, env: RNSCTL_HOST)
    -t, --token TOKEN       Auth bearer token (env: RNSCTL_AUTH_TOKEN). When unset, a
                            token is generated and written to <config dir>/http-token
    -d, --daemon            Connect as client to running rnsd
        --disable-auth      Disable authentication
        --tls-cert PATH     TLS certificate file (env: RNSCTL_TLS_CERT, requires 'tls' feature)
        --tls-key PATH      TLS private key file (env: RNSCTL_TLS_KEY, requires 'tls' feature)
        --hooks-dir PATH    Directory native hooks may be loaded from through the API
                            (default: <config dir>/hooks, env: RNSCTL_HOOKS_DIR)
    -v                      Increase verbosity (repeat for more)
    -h, --help              Show this help
        --version           Show version"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Args {
        Args::parse_from(values.iter().map(|value| value.to_string()).collect())
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rns-ctl-http-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn token_file_is_owner_only_and_holds_token() {
        let dir = temp_dir("token-file");
        let path = token_file_path(Some(&dir));
        assert_eq!(path, dir.join(TOKEN_FILE_NAME));

        write_token_file(&path, "0123abcd").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "0123abcd");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn token_file_replaces_previous_token_and_mode() {
        let dir = temp_dir("token-replace");
        let path = dir.join(TOKEN_FILE_NAME);
        std::fs::write(&path, "an-older-and-longer-token-value\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        write_token_file(&path, "fresh").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "fresh\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn publish_generated_token_logs_path_not_token() {
        let dir = temp_dir("token-log");
        let token = "5f3c9a7e21b84d06c1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6";
        publish_generated_token(token, Some(&dir)).unwrap();

        let path = dir.join(TOKEN_FILE_NAME);
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), token);
        let message = token_file_log_message(&path);
        assert!(message.contains(&path.display().to_string()));
        assert!(!message.contains(token));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_mode_prepares_http_context_before_shared_rnsd_is_ready() {
        let config_dir = std::env::temp_dir().join(format!(
            "rns-ctl-http-daemon-not-ready-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&config_dir);

        let prepared = prepare_embedded_with_state(
            args(&[
                "--daemon",
                "--disable-auth",
                "--config",
                config_dir.to_str().unwrap(),
                "--host",
                "127.0.0.1",
                "--port",
                "0",
            ]),
            HttpRunOptions::embedded(),
            None,
        )
        .expect("daemon-mode HTTP context should not require rnsd RPC readiness");

        assert_eq!(prepared.addr.ip().to_string(), "127.0.0.1");
        assert_eq!(prepared.addr.port(), 0);
        assert!(
            prepared.ctx.node.lock().unwrap().is_none(),
            "shared node client should attach asynchronously"
        );
        assert!(
            prepared.ctx.state.read().unwrap().node_handle.is_some(),
            "HTTP APIs should still receive a node handle placeholder"
        );
    }
}
