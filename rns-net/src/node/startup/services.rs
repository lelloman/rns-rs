//! Setting up the driver's services as the node starts: hooks, interface
//! runtime settings, the local server, the RPC servers.

use super::*;

/// Upstream's lines for the path and tunnel tables found in storage.
pub(super) fn log_restored_tables(
    stats: &rns_core::transport::persistence::RestoreStats,
    storage_dir: &Path,
) {
    // Upstream's lines, for the tables it found in storage.
    let entries = |n: usize| if n == 1 { "entry" } else { "entries" };
    if storage_dir.join("destination_table").is_file() {
        let filtered = if stats.filtered_paths > 0 {
            format!(", {} filtered", stats.filtered_paths)
        } else {
            String::new()
        };
        log::info!(
            "Loaded {} path table {} from storage{}",
            stats.paths,
            entries(stats.paths),
            filtered
        );
    }
    if storage_dir.join("tunnels").is_file() {
        log::info!(
            "Loaded {} tunnel table {} from storage",
            stats.tunnels,
            entries(stats.tunnels)
        );
    }
}

/// Load the enabled hooks of the config into `driver`'s hook slots,
/// skipping, with a warning or an error, those that cannot be loaded.
#[cfg(feature = "hooks")]
pub(super) fn load_configured_hooks(driver: &mut Driver, hooks: &[config::ParsedHook]) {
    for hook_cfg in hooks {
        if !hook_cfg.enabled {
            continue;
        }
        let point_idx = match config::parse_hook_point(&hook_cfg.attach_point) {
            Some(idx) => idx,
            None => {
                log::warn!(
                    "Unknown hook point '{}' for hook '{}'",
                    hook_cfg.attach_point,
                    hook_cfg.name,
                );
                continue;
            }
        };
        let mgr = match driver.hook_manager.as_ref() {
            Some(m) => m,
            None => {
                log::warn!(
                    "Hook manager not available, skipping hook '{}'",
                    hook_cfg.name
                );
                continue;
            }
        };
        let hook_backend = match config::parse_hook_backend(&hook_cfg.hook_type) {
            Ok(backend) => backend,
            Err(e) => {
                log::warn!(
                    "Invalid hook type '{}' for hook '{}': {}",
                    hook_cfg.hook_type,
                    hook_cfg.name,
                    e,
                );
                continue;
            }
        };
        let load_result = if hook_backend == rns_hooks::HookBackend::Builtin {
            let builtin_id = hook_cfg
                .builtin_id
                .as_deref()
                .filter(|id| !id.is_empty())
                .or_else(|| (!hook_cfg.path.is_empty()).then_some(hook_cfg.path.as_str()));
            match builtin_id {
                Some(id) => mgr.load_builtin(hook_cfg.name.clone(), id, hook_cfg.priority),
                None => Err(rns_hooks::HookError::CompileError(
                    "built-in hook requires builtin/id or path".to_string(),
                )),
            }
        } else {
            mgr.load_file_backend(
                hook_cfg.name.clone(),
                std::path::Path::new(&hook_cfg.path),
                hook_cfg.priority,
                hook_backend,
            )
        };
        match load_result {
            Ok(program) => {
                driver.hook_slots[point_idx].attach(program);
                log::info!(
                    "Loaded hook '{}' at point {} (priority {})",
                    hook_cfg.name,
                    hook_cfg.attach_point,
                    hook_cfg.priority,
                );
            }
            Err(e) => {
                log::error!(
                    "Failed to load hook '{}' from '{}': {}",
                    hook_cfg.name,
                    hook_cfg.path,
                    e,
                );
            }
        }
    }
}

/// Register the runtime settings of a configured interface with the driver,
/// for the interface types that have them.
#[cfg(runtime_config_ifaces)]
pub(super) fn register_interface_runtime(
    driver: &mut Driver,
    iface_config: &InterfaceConfig,
    #[cfg(any(feature = "iface-tcp", feature = "iface-backbone"))] transport_enabled: bool,
) {
    #[cfg(feature = "iface-backbone")]
    if iface_config.type_name == "BackboneInterface" {
        if let Some(mode) = iface_config
            .config_data
            .as_any()
            .downcast_ref::<BackboneMode>()
        {
            if let Some(handle) = runtime_handle_from_mode(mode) {
                driver.register_backbone_runtime(handle);
            }
            if let Some(handle) = peer_state_handle_from_mode(mode, iface_config) {
                driver.register_backbone_peer_state(handle);
            }
            if let Some(handle) = client_runtime_handle_from_mode(mode) {
                driver.register_backbone_client_runtime(handle);
            }
            if let Some(handle) = backbone_discovery_runtime_from_interface(
                &iface_config.name,
                mode,
                iface_config.discovery.as_ref(),
                transport_enabled,
                iface_config.ifac.as_ref(),
            ) {
                driver.register_backbone_discovery_runtime(handle);
            }
        }
    }
    #[cfg(feature = "iface-tcp")]
    if iface_config.type_name == "TCPClientInterface" {
        if let Some(tcp_config) = iface_config
            .config_data
            .as_any()
            .downcast_ref::<TcpClientConfig>()
        {
            driver.register_tcp_client_runtime(tcp_client_runtime_handle_from_config(tcp_config));
        }
    }
    #[cfg(feature = "iface-tcp")]
    if iface_config.type_name == "TCPServerInterface" {
        if let Some(tcp_config) = iface_config
            .config_data
            .as_any()
            .downcast_ref::<TcpServerConfig>()
        {
            driver.register_tcp_server_runtime(tcp_runtime_handle_from_config(tcp_config));
            driver.register_tcp_server_discovery_runtime(
                tcp_server_discovery_runtime_from_interface(
                    &iface_config.name,
                    tcp_config,
                    iface_config.discovery.as_ref(),
                    transport_enabled,
                    iface_config.ifac.as_ref(),
                ),
            );
        }
    }
    #[cfg(feature = "iface-udp")]
    if iface_config.type_name == "UDPInterface" {
        if let Some(udp_config) = iface_config
            .config_data
            .as_any()
            .downcast_ref::<UdpConfig>()
        {
            driver.register_udp_runtime(udp_runtime_handle_from_config(udp_config));
        }
    }
    #[cfg(feature = "iface-auto")]
    if iface_config.type_name == "AutoInterface" {
        if let Some(auto_config) = iface_config
            .config_data
            .as_any()
            .downcast_ref::<AutoConfig>()
        {
            driver.register_auto_runtime(auto_runtime_handle_from_config(auto_config));
        }
    }
    #[cfg(feature = "iface-i2p")]
    if iface_config.type_name == "I2PInterface" {
        if let Some(i2p_config) = iface_config
            .config_data
            .as_any()
            .downcast_ref::<I2pConfig>()
        {
            driver.register_i2p_runtime(i2p_runtime_handle_from_config(i2p_config));
        }
    }
    #[cfg(feature = "iface-pipe")]
    if iface_config.type_name == "PipeInterface" {
        if let Some(pipe_config) = iface_config
            .config_data
            .as_any()
            .downcast_ref::<PipeConfig>()
        {
            driver.register_pipe_runtime(pipe_runtime_handle_from_config(pipe_config));
        }
    }
    #[cfg(feature = "iface-rnode")]
    if iface_config.type_name == "RNodeInterface" {
        if let Some(rnode_config) = iface_config
            .config_data
            .as_any()
            .downcast_ref::<RNodeConfig>()
        {
            driver.register_rnode_runtime(rnode_runtime_handle_from_config(rnode_config));
        }
    }
}

/// The host and port a configured TCP or Backbone client connects to, which
/// an auto-connect must not duplicate.
#[cfg(feature = "iface-backbone")]
pub(super) fn configured_client_target(iface_config: &InterfaceConfig) -> Option<(String, u16)> {
    #[cfg(feature = "iface-tcp")]
    if let Some(tcp) = iface_config
        .config_data
        .as_any()
        .downcast_ref::<crate::interface::tcp::TcpClientConfig>()
    {
        return Some((tcp.target_host.clone(), tcp.target_port));
    }
    #[cfg(feature = "iface-backbone")]
    if let Some(BackboneMode::Client(client, _)) = iface_config
        .config_data
        .as_any()
        .downcast_ref::<BackboneMode>()
    {
        return Some((client.target_host.clone(), client.target_port));
    }
    None
}

/// The shared instance's local server, which clients of this instance
/// connect to. Failing to start it is logged; the node runs on without it.
#[cfg(feature = "iface-local")]
pub(super) fn start_local_server(
    driver: &mut Driver,
    instance_name: &str,
    port: u16,
    use_af_unix: bool,
    tx: EventSender,
    next_dynamic_id: Arc<AtomicU64>,
) {
    let local_server_config = LocalServerConfig {
        instance_name: instance_name.to_string(),
        port,
        // Keys the listener on the driver loop when interface I/O is
        // folded; clients get ids of their own.
        interface_id: rns_core::transport::types::InterfaceId(
            next_dynamic_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ),
        use_af_unix,
    };
    let listener_id = local_server_config.interface_id;
    match crate::interface::local::start_shared_instance_server(
        local_server_config,
        tx,
        next_dynamic_id,
    ) {
        Ok((control, endpoint)) => {
            driver.register_listener_control(control);
            driver.register_shared_instance_listener(listener_id, endpoint);
            log::debug!(
                "Local shared instance server started (instance={}, port={})",
                instance_name,
                port
            );
        }
        Err(e) => {
            log::error!("Failed to start local shared instance server: {}", e);
        }
    }
}

/// The RPC servers of a shared instance that run on threads of their own.
pub(super) struct RpcServers {
    /// The server on TCP.
    pub(super) tcp: Option<crate::rpc::RpcServer>,
    /// The server on the abstract Unix socket.
    #[cfg(target_os = "linux")]
    pub(super) unix: Option<crate::rpc::RpcServer>,
}

/// Start the RPC servers if share_instance is enabled: on threads, or on
/// the driver loop when the compact engine folds services.
///
/// As upstream, the RPC server listens on the abstract Unix socket where
/// the shared instance uses one, and on TCP only otherwise
/// (`shared_instance_type = tcp`, other platforms, or when the socket
/// cannot be bound): two instances on the default control port then do not
/// collide. A server that fails to start is logged and left out.
pub(super) fn start_rpc_servers(
    driver: &mut Driver,
    config: &NodeConfig,
    rpc_auth_key: [u8; 32],
    tx: &EventSender,
) -> RpcServers {
    let serve_rpc_threads = config.share_instance && !crate::engine::FOLD_SERVICES;
    let rpc_on_unix = |bound: io::Result<()>| -> bool {
        match bound {
            Ok(()) => {
                log::debug!(
                    "RPC server started on abstract Unix socket for {}",
                    config.instance_name
                );
                true
            }
            Err(e) => {
                log::warn!("Abstract Unix RPC socket unavailable ({e}), serving RPC over TCP");
                false
            }
        }
    };
    if config.share_instance && crate::engine::FOLD_SERVICES {
        let mut service = crate::driver::RpcService::new(rpc_auth_key, Arc::clone(tx.poller()));
        #[cfg(target_os = "linux")]
        let on_unix = config.shared_instance.use_af_unix
            && rpc_on_unix(
                crate::rpc::bind_abstract_unix(&config.instance_name).and_then(|listener| {
                    service.add_listener(crate::driver::RpcListener::Unix(listener))
                }),
            );
        #[cfg(not(target_os = "linux"))]
        let on_unix = false;
        if !on_unix {
            match std::net::TcpListener::bind(("127.0.0.1", config.rpc_port)).and_then(|listener| {
                service.add_listener(crate::driver::RpcListener::Tcp(listener))
            }) {
                Ok(()) => log::debug!("RPC server started on 127.0.0.1:{}", config.rpc_port),
                Err(e) => log::error!("Failed to start RPC server: {}", e),
            }
        }
        driver.rpc_service = Some(service);
    }
    #[cfg(target_os = "linux")]
    let rpc_unix_server = if serve_rpc_threads && config.shared_instance.use_af_unix {
        let started = crate::rpc::RpcServer::start_abstract_unix(
            &config.instance_name,
            rpc_auth_key,
            tx.clone(),
        );
        match started {
            Ok(server) => rpc_on_unix(Ok(())).then_some(server),
            Err(e) => {
                rpc_on_unix(Err(e));
                None
            }
        }
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    let on_unix = rpc_unix_server.is_some();
    #[cfg(not(target_os = "linux"))]
    let on_unix = {
        let _ = rpc_on_unix;
        false
    };
    let rpc_server = if serve_rpc_threads && !on_unix {
        let rpc_addr = crate::rpc::RpcAddr::Tcp("127.0.0.1".into(), config.rpc_port);
        match crate::rpc::RpcServer::start(&rpc_addr, rpc_auth_key, tx.clone()) {
            Ok(server) => {
                log::debug!("RPC server started on 127.0.0.1:{}", config.rpc_port);
                Some(server)
            }
            Err(e) => {
                log::error!("Failed to start RPC server: {}", e);
                None
            }
        }
    } else {
        None
    };
    RpcServers {
        tcp: rpc_server,
        #[cfg(target_os = "linux")]
        unix: rpc_unix_server,
    }
}

impl RnsNode {
    /// The last steps of starting a node: open its destination stamp
    /// store, and ask for the destination types it needs.
    pub(super) fn finish_start(
        &mut self,
        storage_dir: Option<std::path::PathBuf>,
        discover_interfaces: bool,
    ) {
        // Destination stamps live under `storage/stamps` next to the cache
        // directory, the layout `from_config_dirs` uses; a node without a
        // cache directory cannot stamp its announces.
        if let Some(storage_dir) = storage_dir {
            self.set_stamp_store(crate::stamps::DestinationStampStore::new(&storage_dir));
        }
        // InterfaceDiscovery (upstream 884f109b): an instance discovering
        // interfaces wants their announces, so `required_only` keeps them.
        #[cfg(feature = "iface-local")]
        if discover_interfaces {
            self.wants_destination_type(&format!(
                "{}.discovery.interface",
                crate::discovery::APP_NAME
            ));
        }
        #[cfg(not(feature = "iface-local"))]
        let _ = discover_interfaces;
    }
}
