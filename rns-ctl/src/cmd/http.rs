//! HTTP/WebSocket control server subcommand.

use std::fmt;
use std::io::{self, IsTerminal, Write};
use std::net::{AddrParseError, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rns_crypto::identity::Identity;
use rns_crypto::Rng;

use crate::api;
use crate::args::Args;
use crate::{bridge, config, encode, server, state};

/// Run `rns-ctl http` in the foreground: start the node (or attach to
/// `rnsd` in daemon mode) and serve the control plane until interrupted. Exits
/// with status 1 if it cannot start.
pub fn run(args: Args) -> rns_cli::exit::Status {
    run_embedded(args, HttpRunOptions::standalone()).map_err(|err| {
        eprintln!("rns-ctl http: {}", err);
        rns_cli::exit::Exit::FAILURE
    })
}

/// Process-wide side effects the HTTP control plane may take on when it
/// starts. A host process that sets these up itself (`rns-server`) turns them
/// off.
#[derive(Debug, Clone, Copy)]
pub struct HttpRunOptions {
    /// Initialise `env_logger` at the verbosity from the arguments; `RUST_LOG`
    /// still wins when set.
    pub init_logging: bool,
    /// Install a SIGINT/SIGTERM handler that shuts the node down and exits the
    /// process.
    pub install_signal_handler: bool,
}

impl HttpRunOptions {
    fn standalone() -> Self {
        Self {
            init_logging: true,
            install_signal_handler: true,
        }
    }

    /// No logging setup and no signal handler, for a host process.
    pub fn embedded() -> Self {
        Self {
            init_logging: false,
            install_signal_handler: false,
        }
    }
}

/// Why the control plane could not be set up.
///
/// Its `Display` text is what `rns-ctl http` and `rns-server` print.
#[derive(Debug)]
#[non_exhaustive]
pub enum HttpSetupError {
    /// A generated auth token could not be written to its file while stdout
    /// is not a terminal, so the operator would have no way to learn it.
    TokenFile {
        /// The token file.
        path: PathBuf,
        /// Why it could not be written.
        source: io::Error,
    },
    /// The node could not be started.
    StartNode(io::Error),
    /// The TLS certificate or key could not be loaded.
    #[cfg(feature = "tls")]
    LoadTls(io::Error),
    /// Only one of `--tls-cert` and `--tls-key` was given.
    #[cfg(feature = "tls")]
    IncompleteTls,
    /// TLS options were given to a build without the `tls` feature.
    #[cfg(not(feature = "tls"))]
    TlsUnsupported,
    /// The configured host and port do not form a socket address.
    InvalidBindAddress(AddrParseError),
}

impl fmt::Display for HttpSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpSetupError::TokenFile { path, source } => write!(
                f,
                "failed to write auth token file {}: {}",
                path.display(),
                source
            ),
            HttpSetupError::StartNode(error) => write!(f, "failed to start node: {}", error),
            #[cfg(feature = "tls")]
            HttpSetupError::LoadTls(error) => write!(f, "failed to load TLS config: {}", error),
            #[cfg(feature = "tls")]
            HttpSetupError::IncompleteTls => {
                f.write_str("both --tls-cert and --tls-key must be provided together")
            }
            #[cfg(not(feature = "tls"))]
            HttpSetupError::TlsUnsupported => f.write_str(
                "TLS options require the 'tls' feature. Rebuild with: cargo build --features tls",
            ),
            HttpSetupError::InvalidBindAddress(_) => f.write_str("invalid bind address"),
        }
    }
}

impl std::error::Error for HttpSetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HttpSetupError::TokenFile { source, .. } => Some(source),
            HttpSetupError::StartNode(error) => Some(error),
            #[cfg(feature = "tls")]
            HttpSetupError::LoadTls(error) => Some(error),
            #[cfg(feature = "tls")]
            HttpSetupError::IncompleteTls => None,
            #[cfg(not(feature = "tls"))]
            HttpSetupError::TlsUnsupported => None,
            HttpSetupError::InvalidBindAddress(error) => Some(error),
        }
    }
}

/// Why `rns-ctl http` stopped with an error.
#[derive(Debug)]
enum HttpRunError {
    Setup(HttpSetupError),
    Serve(io::Error),
}

impl From<HttpSetupError> for HttpRunError {
    fn from(error: HttpSetupError) -> Self {
        HttpRunError::Setup(error)
    }
}

impl fmt::Display for HttpRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpRunError::Setup(error) => write!(f, "{}", error),
            HttpRunError::Serve(error) => write!(f, "server error: {}", error),
        }
    }
}

fn run_embedded(args: Args, options: HttpRunOptions) -> Result<(), HttpRunError> {
    if args.has("help") {
        crate::cli::HTTP.print_help("rns-ctl http");
        return Ok(());
    }

    if args.has("version") {
        println!("rns-ctl {}", env!("FULL_VERSION"));
        return Ok(());
    }

    let prepared = prepare_embedded_with_state(args, options, None)?;
    server::run_server(prepared.addr, prepared.ctx).map_err(HttpRunError::Serve)
}

/// A control plane ready to serve: hand both parts to
/// [`server::run_server`] or bind `addr` yourself and use
/// [`server::run_server_with_listener`].
pub struct PreparedHttpServer {
    /// Address from the configured host and port.
    pub addr: SocketAddr,
    /// Everything the connection handlers need.
    pub ctx: Arc<server::ServerContext>,
}

/// Set up the control plane from `rns-ctl http` arguments without serving it
/// yet.
///
/// Generates an auth token when none is configured and auth is enabled, and
/// writes it to [`token_file_path`]. Loads the node identity, then starts the
/// node, or in daemon mode starts a background thread that keeps retrying,
/// every 500 ms, to attach to `rnsd` as a shared-instance client (endpoints
/// that need the node fail until it is attached). Pass
/// `shared_state_override` to report into state the caller already holds;
/// otherwise fresh state is made.
///
/// Fails when the node cannot start, the token file cannot be written while
/// stdout is not a terminal, the TLS options are incomplete or unloadable (or
/// given without the `tls` feature), or the bind address is invalid.
pub fn prepare_embedded_with_state(
    args: Args,
    options: HttpRunOptions,
    shared_state_override: Option<state::SharedState>,
) -> Result<PreparedHttpServer, HttpSetupError> {
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
            .map_err(HttpSetupError::StartNode)?;
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
                    return Err(HttpSetupError::LoadTls(e));
                }
            },
            (Some(_), None) | (None, Some(_)) => {
                return Err(HttpSetupError::IncompleteTls);
            }
            (None, None) => None,
        }
    };

    #[cfg(not(feature = "tls"))]
    {
        if cfg.tls_cert.is_some() || cfg.tls_key.is_some() {
            return Err(HttpSetupError::TlsUnsupported);
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
        .map_err(HttpSetupError::InvalidBindAddress)?;

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
fn publish_generated_token(token: &str, config_path: Option<&Path>) -> Result<(), HttpSetupError> {
    let path = token_file_path(config_path);
    let interactive = std::io::stdout().is_terminal();
    if let Err(source) = write_token_file(&path, token) {
        let error = HttpSetupError::TokenFile {
            path: path.clone(),
            source,
        };
        if !interactive {
            return Err(error);
        }
        log::warn!("{}", error);
    } else {
        log::info!("{}", token_file_log_message(&path));
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

/// Run `handler` on a background thread on SIGINT or SIGTERM. SIGTERM is
/// what `docker stop`, `systemctl stop` and `kill` send; without it the
/// process ran until the supervisor's kill timeout.
///
/// The signal handler writes a byte to a pipe, which is async-signal-safe,
/// and the thread sleeps reading it, rather than checking a flag every
/// 100 ms.
fn ctrlc_handler<F: FnOnce() + Send + 'static>(handler: F) {
    use rns_cli::signals::{SignalPipe, SIGINT, SIGTERM};
    let pipe = match SignalPipe::new(false) {
        Ok(pipe) => pipe,
        Err(e) => {
            log::error!("cannot set up signal handling: {}", e);
            return;
        }
    };
    pipe.route(&[SIGINT, SIGTERM], 1);
    thread::Builder::new()
        .name("signal-handler".into())
        .spawn(move || match pipe.wait() {
            Ok(_) => handler(),
            Err(_) => log::warn!("signal pipe closed; not waiting for signals any more"),
        })
        .ok();
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
    fn setup_errors_keep_their_messages() {
        let io = || std::io::Error::other("denied");
        let mut cases = vec![
            (
                HttpSetupError::TokenFile {
                    path: PathBuf::from("/etc/rns/http-token"),
                    source: io(),
                }
                .to_string(),
                "failed to write auth token file /etc/rns/http-token: denied",
            ),
            (
                HttpSetupError::StartNode(io()).to_string(),
                "failed to start node: denied",
            ),
            (
                HttpSetupError::InvalidBindAddress("x".parse::<SocketAddr>().unwrap_err())
                    .to_string(),
                "invalid bind address",
            ),
            (
                HttpRunError::Serve(io()).to_string(),
                "server error: denied",
            ),
            (
                HttpRunError::Setup(HttpSetupError::StartNode(io())).to_string(),
                "failed to start node: denied",
            ),
        ];
        #[cfg(feature = "tls")]
        cases.extend([
            (
                HttpSetupError::LoadTls(io()).to_string(),
                "failed to load TLS config: denied",
            ),
            (
                HttpSetupError::IncompleteTls.to_string(),
                "both --tls-cert and --tls-key must be provided together",
            ),
        ]);
        #[cfg(not(feature = "tls"))]
        cases.push((
            HttpSetupError::TlsUnsupported.to_string(),
            "TLS options require the 'tls' feature. Rebuild with: cargo build --features tls",
        ));
        for (actual, expected) in cases {
            assert_eq!(actual, expected);
        }
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
