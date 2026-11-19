//! Starting an AutoInterface and its threads.

use super::*;

/// Start an AutoInterface. Discovers local IPv6 link-local interfaces,
/// sets up multicast discovery, and creates UDP data servers.
///
/// Returns a vec of (InterfaceId, Writer) for each initial peer (typically empty
/// since peers are discovered dynamically via InterfaceUp events).
pub fn start(
    config: AutoConfig,
    tx: EventSender,
    next_dynamic_id: Arc<AtomicU64>,
) -> io::Result<()> {
    start_with_template(config, tx, next_dynamic_id, None, None).map(|_| ())
}

pub(super) fn start_with_template(
    config: AutoConfig,
    tx: EventSender,
    next_dynamic_id: Arc<AtomicU64>,
    dynamic_template: Option<crate::interface::DynamicInterfaceTemplate>,
    underlay_mark: Option<u32>,
) -> io::Result<crate::interface::ListenerControl> {
    let group_id = config.group_id.clone();
    let mcast_addr_str = derive_multicast_address(
        &group_id,
        &config.multicast_address_type,
        &config.discovery_scope,
    );

    let mcast_ip = match parse_multicast_addr(&mcast_addr_str) {
        Some(ip) => ip,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid multicast address: {}", mcast_addr_str),
            ));
        }
    };

    {
        let startup = AutoRuntime::from_config(&config);
        *lock_or_recover(&config.runtime, "auto runtime") = startup;
    }
    let runtime = Arc::clone(&config.runtime);
    let mut shared_state = SharedState::new(next_dynamic_id);
    shared_state.max_peers = config.max_peers;
    let shared = Arc::new(Mutex::new(shared_state));
    let running = Arc::new(AtomicBool::new(true));

    let worker_context = AutoWorkerContext {
        group_id,
        mcast_ip,
        discovery_port: config.discovery_port,
        unicast_discovery_port: config.discovery_port + 1,
        data_port: config.data_port,
        name: config.name.clone(),
        configured_bitrate: config.configured_bitrate,
        ingress_control: config.ingress_control,
        runtime: runtime.clone(),
        shared: shared.clone(),
        tx: tx.clone(),
        dynamic_template,
        underlay_mark,
    };

    if crate::engine::FOLD_IO {
        folded::start(
            config.interface_id,
            worker_context,
            config.allowed_interfaces.clone(),
            config.ignored_interfaces.clone(),
            running.clone(),
        )?;
    } else {
        start_threads(&config, worker_context, &shared, &runtime, &running)?;
    }

    let announce_interval = lock_or_recover(&runtime, "auto runtime").announce_interval_secs;
    let peering_wait = Duration::from_secs_f64(announce_interval * 1.2);
    thread::sleep(peering_wait);

    {
        let mut state = lock_or_recover(&shared, "auto shared state");
        state.online = true;
    }

    log::info!("[{}] AutoInterface online", config.name);

    Ok(crate::interface::ListenerControl::with_running_flag(
        running,
    ))
}

/// Run an AutoInterface on threads of its own: a supervisor that adopts
/// network interfaces (each served by its own threads) and a peer-jobs
/// thread that culls silent peers.
pub(super) fn start_threads(
    config: &AutoConfig,
    worker_context: AutoWorkerContext,
    shared: &Arc<Mutex<SharedState>>,
    runtime: &Arc<Mutex<AutoRuntime>>,
    running: &Arc<AtomicBool>,
) -> io::Result<()> {
    {
        let shared = shared.clone();
        let tx = worker_context.tx.clone();
        let running = running.clone();
        let name = config.name.clone();
        let runtime = runtime.clone();

        thread::Builder::new()
            .name(format!("auto-peer-jobs-{}", name))
            .spawn(move || {
                peer_jobs_loop(shared, tx, runtime, &running, &name);
            })?;
    }

    {
        let allowed = config.allowed_interfaces.clone();
        let ignored = config.ignored_interfaces.clone();
        let running = running.clone();
        let name = config.name.clone();
        thread::Builder::new()
            .name(format!("auto-supervisor-{}", name))
            .spawn(move || {
                auto_supervisor_loop(allowed, ignored, worker_context, running, &name);
            })?;
    }

    Ok(())
}
