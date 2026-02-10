use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rns_crypto::Rng;
use rns_crypto::identity::Identity;

use rns_ctl::{bridge, config, encode, server, state};
use rns_ctl::api;

fn main() {
    let args = config::Args::parse();

    if args.has("help") {
        config::print_help();
        return;
    }

    if args.has("version") {
        println!("rns-ctl 0.1.0");
        return;
    }

    // Init logging
    let log_level = match args.verbosity {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    std::env::set_var("RUST_LOG", format!("rns_ctl={},rns_net={}", log_level, log_level));
    env_logger::init();

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
    let shared_state = Arc::new(std::sync::RwLock::new(state::CtlState::new()));
    let ws_broadcast: state::WsBroadcast = Arc::new(Mutex::new(Vec::new()));

    // Create callbacks
    let callbacks = Box::new(bridge::CtlCallbacks::new(
        shared_state.clone(),
        ws_broadcast.clone(),
    ));

    // Resolve config path
    let config_path = cfg.config_path.as_deref().map(Path::new);

    // Start the RNS node
    log::info!("Starting RNS node...");
    let node = if cfg.daemon_mode {
        log::info!("Connecting as shared client (daemon mode)");
        rns_net::RnsNode::connect_shared_from_config(config_path, callbacks)
    } else {
        rns_net::RnsNode::from_config(config_path, callbacks)
    };

    let node = match node {
        Ok(n) => n,
        Err(e) => {
            log::error!("Failed to start node: {}", e);
            std::process::exit(1);
        }
    };

    // Get identity from the config dir
    let config_dir = rns_net::storage::resolve_config_dir(config_path);
    let paths = rns_net::storage::ensure_storage_dirs(&config_dir).ok();
    let identity: Option<Identity> = paths
        .as_ref()
        .and_then(|p| rns_net::storage::load_or_create_identity(&p.identities).ok());

    // Store identity info in shared state
    {
        let mut s = shared_state.write().unwrap();
        if let Some(ref id) = identity {
            s.identity_hash = Some(*id.hash());
            // Identity doesn't impl Clone; copy via private key
            if let Some(prv) = id.get_private_key() {
                s.identity = Some(Identity::from_private_key(&prv));
            }
        }
    }

    // Wrap node for shared access
    let node_handle: api::NodeHandle = Arc::new(Mutex::new(Some(node)));
    let node_for_shutdown = node_handle.clone();

    // Set up ctrl-c handler
    let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_flag_handler = shutdown_flag.clone();

    ctrlc_handler(move || {
        if shutdown_flag_handler.swap(true, std::sync::atomic::Ordering::SeqCst) {
            // Second ctrl-c: force exit
            std::process::exit(1);
        }
        log::info!("Shutting down...");
        if let Some(node) = node_for_shutdown.lock().unwrap().take() {
            node.shutdown();
        }
        std::process::exit(0);
    });

    // Build server context
    let ctx = Arc::new(server::ServerContext {
        node: node_handle,
        state: shared_state,
        ws_broadcast,
        config: cfg,
    });

    let addr: SocketAddr = format!("{}:{}", ctx.config.host, ctx.config.port)
        .parse()
        .unwrap_or_else(|_| {
            log::error!("Invalid bind address");
            std::process::exit(1);
        });

    // Run server (blocks)
    if let Err(e) = server::run_server(addr, ctx) {
        log::error!("Server error: {}", e);
        std::process::exit(1);
    }
}

/// Set up a ctrl-c signal handler.
fn ctrlc_handler<F: FnOnce() + Send + 'static>(handler: F) {
    let handler = Mutex::new(Some(handler));
    libc_signal(move || {
        if let Some(f) = handler.lock().unwrap().take() {
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
                std::thread::sleep(std::time::Duration::from_millis(100));
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
