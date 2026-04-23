//! HTTP/WebSocket control server subcommand.

use std::net::SocketAddr;
use std::path::Path;
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
        log::info!("Generated auth token: {}", token);
        println!("Auth token: {}", token);
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
                        if attempt == 1 || attempt % 10 == 0 {
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

/// Set up a ctrl-c signal handler.
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

/// Register a SIGINT handler using libc, polling in a background thread.
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
    -t, --token TOKEN       Auth bearer token (env: RNSCTL_AUTH_TOKEN)
    -d, --daemon            Connect as client to running rnsd
        --disable-auth      Disable authentication
        --tls-cert PATH     TLS certificate file (env: RNSCTL_TLS_CERT, requires 'tls' feature)
        --tls-key PATH      TLS private key file (env: RNSCTL_TLS_KEY, requires 'tls' feature)
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
