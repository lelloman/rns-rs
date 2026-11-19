//! Setting up the driver's services as the node starts: hooks, interface
//! runtime settings, the local server.

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
pub(super) fn register_interface_runtime(
    driver: &mut Driver,
    iface_config: &InterfaceConfig,
    transport_enabled: bool,
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
