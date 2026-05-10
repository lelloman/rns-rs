use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeConfigFamily {
    #[cfg(feature = "iface-backbone")]
    Backbone,
    #[cfg(feature = "iface-backbone")]
    BackboneClient,
    #[cfg(feature = "iface-tcp")]
    TcpServer,
    #[cfg(feature = "iface-tcp")]
    TcpClient,
    #[cfg(feature = "iface-udp")]
    Udp,
    #[cfg(feature = "iface-auto")]
    Auto,
    #[cfg(feature = "iface-i2p")]
    I2p,
    #[cfg(feature = "iface-pipe")]
    Pipe,
    #[cfg(feature = "iface-rnode")]
    Rnode,
    Interface,
}

impl Driver {
    fn is_discovery_runtime_setting(setting: &str) -> bool {
        matches!(
            setting,
            "discoverable"
                | "discovery_name"
                | "announce_interval_secs"
                | "reachable_on"
                | "stamp_value"
                | "latitude"
                | "longitude"
                | "height"
        )
    }

    fn discovery_runtime_entry(
        key: &str,
        setting: &str,
        interface_label: &str,
        current_discoverable: bool,
        startup_discoverable: bool,
        current_config: &crate::discovery::DiscoveryConfig,
        startup_config: &crate::discovery::DiscoveryConfig,
    ) -> Option<RuntimeConfigEntry> {
        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          description: String|
         -> RuntimeConfigEntry {
            RuntimeConfigEntry {
                key: key.to_string(),
                source: if value == default {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value,
                default,
                apply_mode: RuntimeConfigApplyMode::Immediate,
                description: Some(description),
            }
        };

        match setting {
            "discoverable" => Some(make_entry(
                RuntimeConfigValue::Bool(current_discoverable),
                RuntimeConfigValue::Bool(startup_discoverable),
                format!(
                    "Whether this {} interface is advertised through interface discovery.",
                    interface_label
                ),
            )),
            "discovery_name" => Some(make_entry(
                RuntimeConfigValue::String(current_config.discovery_name.clone()),
                RuntimeConfigValue::String(startup_config.discovery_name.clone()),
                format!(
                    "Human-readable discovery name advertised for this {} interface.",
                    interface_label
                ),
            )),
            "announce_interval_secs" => Some(make_entry(
                RuntimeConfigValue::Int(current_config.announce_interval as i64),
                RuntimeConfigValue::Int(startup_config.announce_interval as i64),
                format!(
                    "Discovery announce interval for this {} interface in seconds.",
                    interface_label
                ),
            )),
            "reachable_on" => Some(make_entry(
                current_config
                    .reachable_on
                    .clone()
                    .map(RuntimeConfigValue::String)
                    .unwrap_or(RuntimeConfigValue::Null),
                startup_config
                    .reachable_on
                    .clone()
                    .map(RuntimeConfigValue::String)
                    .unwrap_or(RuntimeConfigValue::Null),
                format!(
                    "Reachable hostname or IP advertised for this {} interface; null clears it.",
                    interface_label
                ),
            )),
            "stamp_value" => Some(make_entry(
                RuntimeConfigValue::Int(current_config.stamp_value as i64),
                RuntimeConfigValue::Int(startup_config.stamp_value as i64),
                format!(
                    "Discovery proof-of-work stamp cost for this {} interface.",
                    interface_label
                ),
            )),
            "latitude" => Some(make_entry(
                current_config
                    .latitude
                    .map(RuntimeConfigValue::Float)
                    .unwrap_or(RuntimeConfigValue::Null),
                startup_config
                    .latitude
                    .map(RuntimeConfigValue::Float)
                    .unwrap_or(RuntimeConfigValue::Null),
                format!(
                    "Latitude advertised for this {} interface; null clears it.",
                    interface_label
                ),
            )),
            "longitude" => Some(make_entry(
                current_config
                    .longitude
                    .map(RuntimeConfigValue::Float)
                    .unwrap_or(RuntimeConfigValue::Null),
                startup_config
                    .longitude
                    .map(RuntimeConfigValue::Float)
                    .unwrap_or(RuntimeConfigValue::Null),
                format!(
                    "Longitude advertised for this {} interface; null clears it.",
                    interface_label
                ),
            )),
            "height" => Some(make_entry(
                current_config
                    .height
                    .map(RuntimeConfigValue::Float)
                    .unwrap_or(RuntimeConfigValue::Null),
                startup_config
                    .height
                    .map(RuntimeConfigValue::Float)
                    .unwrap_or(RuntimeConfigValue::Null),
                format!(
                    "Height advertised for this {} interface; null clears it.",
                    interface_label
                ),
            )),
            _ => None,
        }
    }

    pub(crate) fn runtime_config_family_for_key(key: &str) -> Option<RuntimeConfigFamily> {
        #[cfg(feature = "iface-backbone")]
        if key.starts_with("backbone.") {
            return Some(RuntimeConfigFamily::Backbone);
        }
        #[cfg(feature = "iface-backbone")]
        if key.starts_with("backbone_client.") {
            return Some(RuntimeConfigFamily::BackboneClient);
        }
        #[cfg(feature = "iface-tcp")]
        if key.starts_with("tcp_server.") {
            return Some(RuntimeConfigFamily::TcpServer);
        }
        #[cfg(feature = "iface-tcp")]
        if key.starts_with("tcp_client.") {
            return Some(RuntimeConfigFamily::TcpClient);
        }
        #[cfg(feature = "iface-udp")]
        if key.starts_with("udp.") {
            return Some(RuntimeConfigFamily::Udp);
        }
        #[cfg(feature = "iface-auto")]
        if key.starts_with("auto.") {
            return Some(RuntimeConfigFamily::Auto);
        }
        #[cfg(feature = "iface-i2p")]
        if key.starts_with("i2p.") {
            return Some(RuntimeConfigFamily::I2p);
        }
        #[cfg(feature = "iface-pipe")]
        if key.starts_with("pipe.") {
            return Some(RuntimeConfigFamily::Pipe);
        }
        #[cfg(feature = "iface-rnode")]
        if key.starts_with("rnode.") {
            return Some(RuntimeConfigFamily::Rnode);
        }
        if key.starts_with("interface.") {
            return Some(RuntimeConfigFamily::Interface);
        }
        None
    }

    pub(crate) fn runtime_config_family_entry(
        &self,
        family: RuntimeConfigFamily,
        key: &str,
    ) -> Option<RuntimeConfigEntry> {
        match family {
            #[cfg(feature = "iface-backbone")]
            RuntimeConfigFamily::Backbone => self.backbone_runtime_entry(key),
            #[cfg(feature = "iface-backbone")]
            RuntimeConfigFamily::BackboneClient => self.backbone_client_runtime_entry(key),
            #[cfg(feature = "iface-tcp")]
            RuntimeConfigFamily::TcpServer => self.tcp_server_runtime_entry(key),
            #[cfg(feature = "iface-tcp")]
            RuntimeConfigFamily::TcpClient => self.tcp_client_runtime_entry(key),
            #[cfg(feature = "iface-udp")]
            RuntimeConfigFamily::Udp => self.udp_runtime_entry(key),
            #[cfg(feature = "iface-auto")]
            RuntimeConfigFamily::Auto => self.auto_runtime_entry(key),
            #[cfg(feature = "iface-i2p")]
            RuntimeConfigFamily::I2p => self.i2p_runtime_entry(key),
            #[cfg(feature = "iface-pipe")]
            RuntimeConfigFamily::Pipe => self.pipe_runtime_entry(key),
            #[cfg(feature = "iface-rnode")]
            RuntimeConfigFamily::Rnode => self.rnode_runtime_entry(key),
            RuntimeConfigFamily::Interface => self.generic_interface_runtime_entry(key),
        }
    }

    pub(crate) fn runtime_config_family_entries(
        &self,
        family: RuntimeConfigFamily,
    ) -> Vec<RuntimeConfigEntry> {
        match family {
            #[cfg(feature = "iface-backbone")]
            RuntimeConfigFamily::Backbone => self.list_backbone_runtime_config(),
            #[cfg(feature = "iface-backbone")]
            RuntimeConfigFamily::BackboneClient => self.list_backbone_client_runtime_config(),
            #[cfg(feature = "iface-tcp")]
            RuntimeConfigFamily::TcpServer => self.list_tcp_server_runtime_config(),
            #[cfg(feature = "iface-tcp")]
            RuntimeConfigFamily::TcpClient => self.list_tcp_client_runtime_config(),
            #[cfg(feature = "iface-udp")]
            RuntimeConfigFamily::Udp => self.list_udp_runtime_config(),
            #[cfg(feature = "iface-auto")]
            RuntimeConfigFamily::Auto => self.list_auto_runtime_config(),
            #[cfg(feature = "iface-i2p")]
            RuntimeConfigFamily::I2p => self.list_i2p_runtime_config(),
            #[cfg(feature = "iface-pipe")]
            RuntimeConfigFamily::Pipe => self.list_pipe_runtime_config(),
            #[cfg(feature = "iface-rnode")]
            RuntimeConfigFamily::Rnode => self.list_rnode_runtime_config(),
            RuntimeConfigFamily::Interface => self.list_generic_interface_runtime_config(),
        }
    }

    pub(crate) fn set_runtime_config_family_value(
        &mut self,
        family: RuntimeConfigFamily,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        match family {
            #[cfg(feature = "iface-backbone")]
            RuntimeConfigFamily::Backbone => self.set_backbone_runtime_config(key, value),
            #[cfg(feature = "iface-backbone")]
            RuntimeConfigFamily::BackboneClient => {
                self.set_backbone_client_runtime_config(key, value)
            }
            #[cfg(feature = "iface-tcp")]
            RuntimeConfigFamily::TcpServer => self.set_tcp_server_runtime_config(key, value),
            #[cfg(feature = "iface-tcp")]
            RuntimeConfigFamily::TcpClient => self.set_tcp_client_runtime_config(key, value),
            #[cfg(feature = "iface-udp")]
            RuntimeConfigFamily::Udp => self.set_udp_runtime_config(key, value),
            #[cfg(feature = "iface-auto")]
            RuntimeConfigFamily::Auto => self.set_auto_runtime_config(key, value),
            #[cfg(feature = "iface-i2p")]
            RuntimeConfigFamily::I2p => self.set_i2p_runtime_config(key, value),
            #[cfg(feature = "iface-pipe")]
            RuntimeConfigFamily::Pipe => self.set_pipe_runtime_config(key, value),
            #[cfg(feature = "iface-rnode")]
            RuntimeConfigFamily::Rnode => self.set_rnode_runtime_config(key, value),
            RuntimeConfigFamily::Interface => self.set_generic_interface_runtime_config(key, value),
        }
    }

    pub(crate) fn reset_runtime_config_family_value(
        &mut self,
        family: RuntimeConfigFamily,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        match family {
            #[cfg(feature = "iface-backbone")]
            RuntimeConfigFamily::Backbone => self.reset_backbone_runtime_config(key),
            #[cfg(feature = "iface-backbone")]
            RuntimeConfigFamily::BackboneClient => self.reset_backbone_client_runtime_config(key),
            #[cfg(feature = "iface-tcp")]
            RuntimeConfigFamily::TcpServer => self.reset_tcp_server_runtime_config(key),
            #[cfg(feature = "iface-tcp")]
            RuntimeConfigFamily::TcpClient => self.reset_tcp_client_runtime_config(key),
            #[cfg(feature = "iface-udp")]
            RuntimeConfigFamily::Udp => self.reset_udp_runtime_config(key),
            #[cfg(feature = "iface-auto")]
            RuntimeConfigFamily::Auto => self.reset_auto_runtime_config(key),
            #[cfg(feature = "iface-i2p")]
            RuntimeConfigFamily::I2p => self.reset_i2p_runtime_config(key),
            #[cfg(feature = "iface-pipe")]
            RuntimeConfigFamily::Pipe => self.reset_pipe_runtime_config(key),
            #[cfg(feature = "iface-rnode")]
            RuntimeConfigFamily::Rnode => self.reset_rnode_runtime_config(key),
            RuntimeConfigFamily::Interface => self.reset_generic_interface_runtime_config(key),
        }
    }

    pub(crate) fn register_backbone_runtime(&mut self, handle: BackboneRuntimeConfigHandle) {
        self.backbone_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn register_backbone_peer_state(&mut self, handle: BackbonePeerStateHandle) {
        self.backbone_peer_state
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn register_backbone_client_runtime(
        &mut self,
        handle: BackboneClientRuntimeConfigHandle,
    ) {
        self.backbone_client_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn register_backbone_discovery_runtime(
        &mut self,
        handle: BackboneDiscoveryRuntimeHandle,
    ) {
        self.backbone_discovery_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn configure_backbone_peer_pool(
        &mut self,
        settings: BackbonePeerPoolSettings,
        candidates: Vec<BackbonePeerPoolCandidateConfig>,
    ) {
        if settings.max_connected == 0 || candidates.is_empty() {
            self.backbone_peer_pool = None;
            return;
        }
        self.backbone_peer_pool = Some(BackbonePeerPool {
            settings,
            candidates: candidates
                .into_iter()
                .map(|config| BackbonePeerPoolCandidate {
                    config,
                    active_id: None,
                    failures: Vec::new(),
                    retry_after: None,
                    cooldown_until: None,
                    last_error: None,
                })
                .collect(),
        });
        self.maintain_backbone_peer_pool();
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn maintain_backbone_peer_pool(&mut self) {
        let Some(pool) = self.backbone_peer_pool.as_mut() else {
            return;
        };
        let now = time::now();
        for candidate in &mut pool.candidates {
            if candidate.cooldown_until.is_some_and(|until| until <= now) {
                candidate.cooldown_until = None;
                candidate.retry_after = None;
            }
        }

        loop {
            let Some(pool) = self.backbone_peer_pool.as_ref() else {
                return;
            };
            let active = pool
                .candidates
                .iter()
                .filter(|candidate| candidate.active_id.is_some())
                .count();
            if active >= pool.settings.max_connected {
                return;
            }
            let next = pool.candidates.iter().position(|candidate| {
                candidate.active_id.is_none()
                    && candidate
                        .cooldown_until
                        .map(|until| until <= now)
                        .unwrap_or(true)
                    && candidate
                        .retry_after
                        .map(|retry_after| retry_after <= now)
                        .unwrap_or(true)
            });
            let Some(index) = next else {
                return;
            };
            if let Err(err) = self.start_backbone_peer_pool_candidate(index) {
                self.record_backbone_peer_pool_failure(index, err.to_string());
            }
        }
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn start_backbone_peer_pool_candidate(
        &mut self,
        index: usize,
    ) -> std::io::Result<()> {
        let Some(pool) = self.backbone_peer_pool.as_ref() else {
            return Ok(());
        };
        let Some(candidate) = pool.candidates.get(index) else {
            return Ok(());
        };
        let mut client = candidate.config.client.clone();
        client.max_reconnect_tries = Some(0);
        if let Ok(mut runtime) = client.runtime.lock() {
            runtime.max_reconnect_tries = Some(0);
        }
        let id = client.interface_id;
        let name = client.name.clone();
        let mode = candidate.config.mode;
        let ingress_control = candidate.config.ingress_control;
        let ifac_runtime = candidate.config.ifac_runtime.clone();
        let ifac_enabled = candidate.config.ifac_enabled;
        let interface_type_name = candidate.config.interface_type_name.clone();
        let writer = start_client(client.clone(), self.event_tx.clone())?;
        let info = rns_core::transport::types::InterfaceInfo {
            id,
            name: name.clone(),
            mode,
            out_capable: true,
            in_capable: true,
            bitrate: Some(1_000_000_000),
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: rns_core::constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: 65535,
            ingress_control,
            ia_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: time::now(),
        };
        let (writer, async_writer_metrics) = self.wrap_interface_writer(id, &name, writer);
        let ifac_state = if ifac_enabled {
            Some(
                ifac::derive_ifac(
                    ifac_runtime.netname.as_deref(),
                    ifac_runtime.netkey.as_deref(),
                    ifac_runtime.size,
                )
                .map_err(io::Error::other)?,
            )
        } else {
            None
        };
        self.register_backbone_client_runtime(BackboneClientRuntimeConfigHandle {
            interface_name: name.clone(),
            runtime: Arc::clone(&client.runtime),
            startup: BackboneClientRuntime::from_config(&client),
        });
        self.register_interface_runtime_defaults(&info);
        self.register_interface_ifac_runtime(&name, ifac_runtime);
        self.engine.register_interface(info.clone());
        self.interfaces.insert(
            id,
            InterfaceEntry {
                id,
                info,
                writer,
                async_writer_metrics: Some(async_writer_metrics),
                enabled: true,
                online: false,
                dynamic: false,
                ifac: ifac_state,
                stats: InterfaceStats {
                    started: time::now(),
                    ..Default::default()
                },
                interface_type: interface_type_name,
                send_retry_at: None,
                send_retry_backoff: Duration::ZERO,
            },
        );

        if let Some(pool) = self.backbone_peer_pool.as_mut() {
            if let Some(candidate) = pool.candidates.get_mut(index) {
                candidate.active_id = Some(id);
                candidate.retry_after = None;
                candidate.last_error = None;
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn record_backbone_peer_pool_failure(&mut self, index: usize, error: String) {
        let Some(pool) = self.backbone_peer_pool.as_mut() else {
            return;
        };
        let Some(candidate) = pool.candidates.get_mut(index) else {
            return;
        };
        let now = time::now();
        let window = pool.settings.failure_window.as_secs_f64();
        candidate.failures.retain(|ts| now - *ts <= window);
        candidate.failures.push(now);
        candidate.last_error = Some(error);
        candidate.active_id = None;
        if candidate.failures.len() >= pool.settings.failure_threshold {
            candidate.cooldown_until = Some(now + pool.settings.cooldown.as_secs_f64());
            candidate.retry_after = None;
        } else {
            let reconnect_wait = candidate
                .config
                .client
                .runtime
                .lock()
                .map(|runtime| runtime.reconnect_wait)
                .unwrap_or(candidate.config.client.reconnect_wait);
            candidate.retry_after = Some(now + reconnect_wait.as_secs_f64());
        }
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn handle_backbone_peer_pool_down(&mut self, id: InterfaceId) {
        let Some(index) = self.backbone_peer_pool.as_ref().and_then(|pool| {
            pool.candidates
                .iter()
                .position(|candidate| candidate.active_id == Some(id))
        }) else {
            return;
        };

        if let Some(entry) = self.interfaces.remove(&id) {
            let name = entry.info.name;
            self.interface_runtime_defaults.remove(&name);
            self.interface_ifac_runtime.remove(&name);
            self.interface_ifac_runtime_defaults.remove(&name);
            self.backbone_client_runtime.remove(&name);
            self.engine.deregister_interface(id);
        }
        self.record_backbone_peer_pool_failure(index, "interface down".into());
        self.maintain_backbone_peer_pool();
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn backbone_peer_pool_status(&self) -> Option<BackbonePeerPoolStatus> {
        let pool = self.backbone_peer_pool.as_ref()?;
        let now = time::now();
        let mut active_count = 0usize;
        let mut standby_count = 0usize;
        let mut cooldown_count = 0usize;
        let members = pool
            .candidates
            .iter()
            .map(|candidate| {
                let (state, cooldown_remaining_seconds) =
                    if let Some(until) = candidate.cooldown_until {
                        cooldown_count += 1;
                        ("cooldown".to_string(), Some((until - now).max(0.0)))
                    } else if let Some(id) = candidate.active_id {
                        active_count += 1;
                        let online = self
                            .interfaces
                            .get(&id)
                            .map(|entry| entry.online)
                            .unwrap_or(false);
                        (
                            if online { "active" } else { "connecting" }.to_string(),
                            None,
                        )
                    } else {
                        standby_count += 1;
                        ("standby".to_string(), None)
                    };
                BackbonePeerPoolMemberStatus {
                    name: candidate.config.client.name.clone(),
                    remote: format!(
                        "{}:{}",
                        candidate.config.client.target_host, candidate.config.client.target_port
                    ),
                    state,
                    interface_id: candidate.active_id.map(|id| id.0),
                    failure_count: candidate.failures.len(),
                    last_error: candidate.last_error.clone(),
                    cooldown_remaining_seconds,
                }
            })
            .collect();
        Some(BackbonePeerPoolStatus {
            max_connected: pool.settings.max_connected,
            active_count,
            standby_count,
            cooldown_count,
            members,
        })
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn list_backbone_peer_state(
        &self,
        interface_name: Option<&str>,
    ) -> Vec<BackbonePeerStateEntry> {
        let mut names: Vec<&String> = match interface_name {
            Some(name) => self
                .backbone_peer_state
                .keys()
                .filter(|candidate| candidate.as_str() == name)
                .collect(),
            None => self.backbone_peer_state.keys().collect(),
        };
        names.sort();

        let mut entries = Vec::new();
        for name in names {
            if let Some(handle) = self.backbone_peer_state.get(name) {
                entries.extend(
                    recover_mutex_guard(&handle.peer_state, "backbone peer state").list(name),
                );
            }
        }
        entries.sort_by(|a, b| {
            a.interface_name
                .cmp(&b.interface_name)
                .then_with(|| a.peer_ip.cmp(&b.peer_ip))
        });
        entries
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn list_backbone_interfaces(&self) -> Vec<crate::event::BackboneInterfaceEntry> {
        let mut entries: Vec<_> = self
            .backbone_peer_state
            .values()
            .map(|handle| crate::event::BackboneInterfaceEntry {
                interface_id: handle.interface_id,
                interface_name: handle.interface_name.clone(),
            })
            .collect();
        entries.sort_by(|a, b| a.interface_name.cmp(&b.interface_name));
        entries
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn clear_backbone_peer_state(
        &mut self,
        interface_name: &str,
        peer_ip: std::net::IpAddr,
    ) -> bool {
        self.backbone_peer_state
            .get(interface_name)
            .map(|handle| {
                recover_mutex_guard(&handle.peer_state, "backbone peer state").clear(peer_ip)
            })
            .unwrap_or(false)
    }

    pub(crate) fn blacklist_backbone_peer(
        &mut self,
        interface_name: &str,
        peer_ip: std::net::IpAddr,
        duration: std::time::Duration,
        reason: String,
        penalty_level: u8,
    ) -> bool {
        let capped_duration = self
            .backbone_runtime
            .get(interface_name)
            .and_then(|handle| {
                handle
                    .runtime
                    .lock()
                    .ok()
                    .map(|runtime| runtime.abuse.max_penalty_duration)
            })
            .flatten()
            .map(|max| duration.min(max))
            .unwrap_or(duration);
        let Some(handle) = self.backbone_peer_state.get(interface_name) else {
            return false;
        };
        let ok = recover_mutex_guard(&handle.peer_state, "backbone peer state").blacklist(
            peer_ip,
            capped_duration,
            reason,
        );
        if ok {
            #[cfg(feature = "hooks")]
            self.run_backbone_peer_hook(
                "BackbonePeerPenalty",
                HookPoint::BackbonePeerPenalty,
                &BackbonePeerHookEvent {
                    server_interface_id: self
                        .interfaces
                        .iter()
                        .find(|(_, entry)| entry.info.name == interface_name)
                        .map(|(id, _)| *id)
                        .unwrap_or(InterfaceId(0)),
                    peer_interface_id: None,
                    peer_ip,
                    peer_port: 0,
                    connected_for: Duration::ZERO,
                    had_received_data: false,
                    penalty_level,
                    blacklist_for: capped_duration,
                },
            );
            #[cfg(not(feature = "hooks"))]
            let _ = (peer_ip, capped_duration, penalty_level);
        }
        ok
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn register_tcp_server_runtime(&mut self, handle: TcpServerRuntimeConfigHandle) {
        self.tcp_server_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn register_tcp_client_runtime(&mut self, handle: TcpClientRuntimeConfigHandle) {
        self.tcp_client_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn register_tcp_server_discovery_runtime(
        &mut self,
        handle: TcpServerDiscoveryRuntimeHandle,
    ) {
        self.tcp_server_discovery_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-udp")]
    pub(crate) fn register_udp_runtime(&mut self, handle: UdpRuntimeConfigHandle) {
        self.udp_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-auto")]
    pub(crate) fn register_auto_runtime(&mut self, handle: AutoRuntimeConfigHandle) {
        self.auto_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-i2p")]
    pub(crate) fn register_i2p_runtime(&mut self, handle: I2pRuntimeConfigHandle) {
        self.i2p_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-pipe")]
    pub(crate) fn register_pipe_runtime(&mut self, handle: PipeRuntimeConfigHandle) {
        self.pipe_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    #[cfg(feature = "iface-rnode")]
    pub(crate) fn register_rnode_runtime(&mut self, handle: RNodeRuntimeConfigHandle) {
        self.rnode_runtime
            .insert(handle.interface_name.clone(), handle);
    }

    pub(crate) fn register_interface_runtime_defaults(
        &mut self,
        info: &rns_core::transport::types::InterfaceInfo,
    ) {
        self.interface_runtime_defaults
            .entry(info.name.clone())
            .or_insert_with(|| info.clone());
    }

    pub(crate) fn register_interface_ifac_runtime(
        &mut self,
        interface_name: &str,
        startup: IfacRuntimeConfig,
    ) {
        self.interface_ifac_runtime_defaults
            .entry(interface_name.to_string())
            .or_insert_with(|| startup.clone());
        self.interface_ifac_runtime
            .entry(interface_name.to_string())
            .or_insert(startup);
    }

    pub(crate) fn runtime_config_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let defaults = self.runtime_config_defaults;
        let make_entry = |key: &str,
                          value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          apply_mode: RuntimeConfigApplyMode,
                          description: &str| RuntimeConfigEntry {
            key: key.to_string(),
            source: if value == default {
                RuntimeConfigSource::Startup
            } else {
                RuntimeConfigSource::RuntimeOverride
            },
            value,
            default,
            apply_mode,
            description: Some(description.to_string()),
        };

        match key {
            "global.tick_interval_ms" => Some(make_entry(
                key,
                RuntimeConfigValue::Int(self.tick_interval_ms.load(Ordering::Relaxed) as i64),
                RuntimeConfigValue::Int(defaults.tick_interval_ms as i64),
                RuntimeConfigApplyMode::Immediate,
                "Driver tick interval in milliseconds.",
            )),
            "global.known_destinations_ttl_secs" => Some(make_entry(
                key,
                RuntimeConfigValue::Float(self.known_destinations_ttl),
                RuntimeConfigValue::Float(defaults.known_destinations_ttl),
                RuntimeConfigApplyMode::Immediate,
                "TTL for known destinations without an active path.",
            )),
            "global.rate_limiter_ttl_secs" => Some(make_entry(
                key,
                RuntimeConfigValue::Float(self.rate_limiter_ttl_secs),
                RuntimeConfigValue::Float(defaults.rate_limiter_ttl_secs),
                RuntimeConfigApplyMode::Immediate,
                "TTL for announce rate-limiter entries without an active path.",
            )),
            "global.known_destinations_cleanup_interval_ticks" => Some(make_entry(
                key,
                RuntimeConfigValue::Int(self.known_destinations_cleanup_interval_ticks as i64),
                RuntimeConfigValue::Int(defaults.known_destinations_cleanup_interval_ticks as i64),
                RuntimeConfigApplyMode::Immediate,
                "Tick interval between known-destinations cleanup passes.",
            )),
            "global.announce_cache_cleanup_interval_ticks" => Some(make_entry(
                key,
                RuntimeConfigValue::Int(self.announce_cache_cleanup_interval_ticks as i64),
                RuntimeConfigValue::Int(defaults.announce_cache_cleanup_interval_ticks as i64),
                RuntimeConfigApplyMode::Immediate,
                "Tick interval between announce-cache cleanup cycles.",
            )),
            "global.announce_cache_cleanup_batch_size" => Some(make_entry(
                key,
                RuntimeConfigValue::Int(self.announce_cache_cleanup_batch_size as i64),
                RuntimeConfigValue::Int(defaults.announce_cache_cleanup_batch_size as i64),
                RuntimeConfigApplyMode::Immediate,
                "Number of announce-cache entries processed per cleanup tick.",
            )),
            "global.discovery_cleanup_interval_ticks" => Some(make_entry(
                key,
                RuntimeConfigValue::Int(self.discovery_cleanup_interval_ticks as i64),
                RuntimeConfigValue::Int(defaults.discovery_cleanup_interval_ticks as i64),
                RuntimeConfigApplyMode::Immediate,
                "Tick interval between discovered-interface cleanup passes.",
            )),
            "global.management_announce_interval_secs" => Some(make_entry(
                key,
                RuntimeConfigValue::Float(self.management_announce_interval_secs),
                RuntimeConfigValue::Float(defaults.management_announce_interval_secs),
                RuntimeConfigApplyMode::Immediate,
                "Interval between management announces in seconds.",
            )),
            "global.direct_connect_policy" => Some(make_entry(
                key,
                RuntimeConfigValue::String(Self::holepunch_policy_name(
                    self.holepunch_manager.policy(),
                )),
                RuntimeConfigValue::String(Self::holepunch_policy_name(
                    defaults.direct_connect_policy,
                )),
                RuntimeConfigApplyMode::Immediate,
                "Policy for incoming direct-connect proposals.",
            )),
            #[cfg(feature = "hooks")]
            "provider.queue_max_events" => {
                let value = self
                    .provider_bridge
                    .as_ref()
                    .map(|b| b.queue_max_events())
                    .unwrap_or(defaults.provider_queue_max_events);
                Some(make_entry(
                    key,
                    RuntimeConfigValue::Int(value as i64),
                    RuntimeConfigValue::Int(defaults.provider_queue_max_events as i64),
                    RuntimeConfigApplyMode::Immediate,
                    "Max queued events in the provider bridge.",
                ))
            }
            #[cfg(feature = "hooks")]
            "provider.queue_max_bytes" => {
                let value = self
                    .provider_bridge
                    .as_ref()
                    .map(|b| b.queue_max_bytes())
                    .unwrap_or(defaults.provider_queue_max_bytes);
                Some(make_entry(
                    key,
                    RuntimeConfigValue::Int(value as i64),
                    RuntimeConfigValue::Int(defaults.provider_queue_max_bytes as i64),
                    RuntimeConfigApplyMode::Immediate,
                    "Max queued bytes in the provider bridge.",
                ))
            }
            _ => Self::runtime_config_family_for_key(key)
                .and_then(|family| self.runtime_config_family_entry(family, key)),
        }
    }

    pub(crate) fn list_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries: Vec<RuntimeConfigEntry> = [
            "global.tick_interval_ms",
            "global.known_destinations_ttl_secs",
            "global.rate_limiter_ttl_secs",
            "global.known_destinations_cleanup_interval_ticks",
            "global.announce_cache_cleanup_interval_ticks",
            "global.announce_cache_cleanup_batch_size",
            "global.discovery_cleanup_interval_ticks",
            "global.management_announce_interval_secs",
            "global.direct_connect_policy",
        ]
        .into_iter()
        .filter_map(|key| self.runtime_config_entry(key))
        .collect();

        #[cfg(feature = "hooks")]
        {
            entries.extend(
                ["provider.queue_max_events", "provider.queue_max_bytes"]
                    .into_iter()
                    .filter_map(|key| self.runtime_config_entry(key)),
            );
        }
        #[cfg(feature = "iface-backbone")]
        entries.extend(self.runtime_config_family_entries(RuntimeConfigFamily::Backbone));
        #[cfg(feature = "iface-backbone")]
        entries.extend(self.runtime_config_family_entries(RuntimeConfigFamily::BackboneClient));
        #[cfg(feature = "iface-tcp")]
        entries.extend(self.runtime_config_family_entries(RuntimeConfigFamily::TcpServer));
        #[cfg(feature = "iface-tcp")]
        entries.extend(self.runtime_config_family_entries(RuntimeConfigFamily::TcpClient));
        #[cfg(feature = "iface-udp")]
        entries.extend(self.runtime_config_family_entries(RuntimeConfigFamily::Udp));
        #[cfg(feature = "iface-auto")]
        entries.extend(self.runtime_config_family_entries(RuntimeConfigFamily::Auto));
        #[cfg(feature = "iface-i2p")]
        entries.extend(self.runtime_config_family_entries(RuntimeConfigFamily::I2p));
        #[cfg(feature = "iface-pipe")]
        entries.extend(self.runtime_config_family_entries(RuntimeConfigFamily::Pipe));
        #[cfg(feature = "iface-rnode")]
        entries.extend(self.runtime_config_family_entries(RuntimeConfigFamily::Rnode));
        entries.extend(self.runtime_config_family_entries(RuntimeConfigFamily::Interface));

        entries
    }

    pub(crate) fn holepunch_policy_name(policy: crate::event::HolePunchPolicy) -> String {
        match policy {
            crate::event::HolePunchPolicy::Reject => "reject".to_string(),
            crate::event::HolePunchPolicy::AcceptAll => "accept_all".to_string(),
            crate::event::HolePunchPolicy::AskApp => "ask_app".to_string(),
        }
    }

    pub(crate) fn parse_holepunch_policy(
        value: &RuntimeConfigValue,
    ) -> Option<crate::event::HolePunchPolicy> {
        match value {
            RuntimeConfigValue::String(s) => match s.to_ascii_lowercase().as_str() {
                "reject" => Some(crate::event::HolePunchPolicy::Reject),
                "accept_all" | "acceptall" => Some(crate::event::HolePunchPolicy::AcceptAll),
                "ask_app" | "askapp" => Some(crate::event::HolePunchPolicy::AskApp),
                _ => None,
            },
            _ => None,
        }
    }

    pub(crate) fn expect_u64(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<u64, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::Int(v) if v >= 0 => Ok(v as u64),
            RuntimeConfigValue::Int(_) => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidValue,
                message: format!("{} must be >= 0", key),
            }),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects an integer", key),
            }),
        }
    }

    pub(crate) fn expect_f64(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<f64, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::Float(v) if v >= 0.0 => Ok(v),
            RuntimeConfigValue::Int(v) if v >= 0 => Ok(v as f64),
            RuntimeConfigValue::Float(_) | RuntimeConfigValue::Int(_) => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidValue,
                message: format!("{} must be >= 0", key),
            }),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects a numeric value", key),
            }),
        }
    }

    pub(crate) fn expect_i64(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<i64, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::Int(v) => Ok(v),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects an integer", key),
            }),
        }
    }

    pub(crate) fn expect_bool(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<bool, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::Bool(v) => Ok(v),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects a boolean", key),
            }),
        }
    }

    pub(crate) fn expect_string(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<String, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::String(v) => Ok(v),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects a string", key),
            }),
        }
    }

    pub(crate) fn expect_optional_f64(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<Option<f64>, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::Null => Ok(None),
            RuntimeConfigValue::Float(v) => Ok(Some(v)),
            RuntimeConfigValue::Int(v) => Ok(Some(v as f64)),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects a numeric value or null", key),
            }),
        }
    }

    pub(crate) fn expect_optional_string(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<Option<String>, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::Null => Ok(None),
            RuntimeConfigValue::String(v) => Ok(Some(v)),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects a string or null", key),
            }),
        }
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn split_backbone_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("backbone.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn set_optional_duration(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<Option<Duration>, RuntimeConfigError> {
        let secs = Self::expect_f64(value, key)?;
        if secs == 0.0 {
            Ok(None)
        } else {
            Ok(Some(Duration::from_secs_f64(secs)))
        }
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn set_optional_usize(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<Option<usize>, RuntimeConfigError> {
        let raw = Self::expect_u64(value, key)?;
        if raw == 0 {
            Ok(None)
        } else {
            Ok(Some(raw as usize))
        }
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn set_backbone_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_backbone_runtime_key(key)?;
        if matches!(
            setting,
            "discoverable"
                | "discovery_name"
                | "announce_interval_secs"
                | "reachable_on"
                | "stamp_value"
                | "latitude"
                | "longitude"
                | "height"
        ) {
            return self.set_backbone_discovery_runtime_config(key, value);
        }
        let handle = self.backbone_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("backbone interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "backbone runtime");
        match setting {
            "idle_timeout_secs" => {
                runtime.idle_timeout = Self::set_optional_duration(value, key)?;
                Ok(())
            }
            "write_stall_timeout_secs" => {
                runtime.write_stall_timeout = Self::set_optional_duration(value, key)?;
                Ok(())
            }
            "max_penalty_duration_secs" => {
                runtime.abuse.max_penalty_duration = Self::set_optional_duration(value, key)?;
                Ok(())
            }
            "max_connections" => {
                runtime.max_connections = Self::set_optional_usize(value, key)?;
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn split_backbone_discovery_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("backbone.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn set_backbone_discovery_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_backbone_discovery_runtime_key(key)?;
        let handle = self
            .backbone_discovery_runtime
            .get_mut(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("backbone interface '{}' not found", name),
            })?;
        match setting {
            "discoverable" => {
                handle.current.discoverable = Self::expect_bool(value, key)?;
            }
            "discovery_name" => {
                handle.current.config.discovery_name = Self::expect_string(value, key)?;
            }
            "announce_interval_secs" => {
                let secs = Self::expect_u64(value, key)?;
                if secs < 300 {
                    return Err(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::InvalidValue,
                        message: format!("{} must be >= 300", key),
                    });
                }
                handle.current.config.announce_interval = secs;
            }
            "reachable_on" => {
                handle.current.config.reachable_on = Self::expect_optional_string(value, key)?;
            }
            "stamp_value" => {
                let raw = Self::expect_u64(value, key)?;
                if raw > u8::MAX as u64 {
                    return Err(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::InvalidValue,
                        message: format!("{} must be <= {}", key, u8::MAX),
                    });
                }
                handle.current.config.stamp_value = raw as u8;
            }
            "latitude" => {
                handle.current.config.latitude = Self::expect_optional_f64(value, key)?;
            }
            "longitude" => {
                handle.current.config.longitude = Self::expect_optional_f64(value, key)?;
            }
            "height" => {
                handle.current.config.height = Self::expect_optional_f64(value, key)?;
            }
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                });
            }
        }
        self.sync_backbone_discovery_runtime(name)
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn reset_backbone_discovery_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_backbone_discovery_runtime_key(key)?;
        let handle = self
            .backbone_discovery_runtime
            .get_mut(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("backbone interface '{}' not found", name),
            })?;
        match setting {
            "discoverable" => handle.current.discoverable = handle.startup.discoverable,
            "discovery_name" => {
                handle.current.config.discovery_name = handle.startup.config.discovery_name.clone()
            }
            "announce_interval_secs" => {
                handle.current.config.announce_interval = handle.startup.config.announce_interval
            }
            "reachable_on" => {
                handle.current.config.reachable_on = handle.startup.config.reachable_on.clone()
            }
            "stamp_value" => handle.current.config.stamp_value = handle.startup.config.stamp_value,
            "latitude" => handle.current.config.latitude = handle.startup.config.latitude,
            "longitude" => handle.current.config.longitude = handle.startup.config.longitude,
            "height" => handle.current.config.height = handle.startup.config.height,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                });
            }
        }
        self.sync_backbone_discovery_runtime(name)
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn reset_backbone_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_backbone_runtime_key(key)?;
        if matches!(
            setting,
            "discoverable"
                | "discovery_name"
                | "announce_interval_secs"
                | "reachable_on"
                | "stamp_value"
                | "latitude"
                | "longitude"
                | "height"
        ) {
            return self.reset_backbone_discovery_runtime_config(key);
        }
        let handle = self.backbone_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("backbone interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "backbone runtime");
        let startup = handle.startup.clone();
        match setting {
            "idle_timeout_secs" => runtime.idle_timeout = startup.idle_timeout,
            "write_stall_timeout_secs" => runtime.write_stall_timeout = startup.write_stall_timeout,
            "max_penalty_duration_secs" => {
                runtime.abuse.max_penalty_duration = startup.abuse.max_penalty_duration
            }
            "max_connections" => runtime.max_connections = startup.max_connections,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn list_backbone_client_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.backbone_client_runtime.keys().collect();
        names.sort();
        for name in names {
            for suffix in [
                "connect_timeout_secs",
                "reconnect_wait_secs",
                "max_reconnect_tries",
            ] {
                let key = format!("backbone_client.{}.{}", name, suffix);
                if let Some(entry) = self.backbone_client_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn backbone_client_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("backbone_client.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.backbone_client_runtime.get(name)?;
        let current = recover_mutex_guard(&handle.runtime, "backbone client runtime").clone();
        let startup = handle.startup.clone();
        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          description: &str|
         -> RuntimeConfigEntry {
            RuntimeConfigEntry {
                key: key.to_string(),
                source: if value == default {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value,
                default,
                apply_mode: RuntimeConfigApplyMode::NextReconnect,
                description: Some(description.to_string()),
            }
        };
        match setting {
            "connect_timeout_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.connect_timeout.as_secs_f64()),
                RuntimeConfigValue::Float(startup.connect_timeout.as_secs_f64()),
                "Backbone client connect timeout in seconds; applies on the next reconnect.",
            )),
            "reconnect_wait_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.reconnect_wait.as_secs_f64()),
                RuntimeConfigValue::Float(startup.reconnect_wait.as_secs_f64()),
                "Delay between backbone client reconnect attempts in seconds.",
            )),
            "max_reconnect_tries" => Some(make_entry(
                RuntimeConfigValue::Int(current.max_reconnect_tries.unwrap_or(0) as i64),
                RuntimeConfigValue::Int(startup.max_reconnect_tries.unwrap_or(0) as i64),
                "Maximum backbone client reconnect attempts; 0 disables the cap.",
            )),
            _ => None,
        }
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn split_backbone_client_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key
            .strip_prefix("backbone_client.")
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn set_backbone_client_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_backbone_client_runtime_key(key)?;
        let handle = self
            .backbone_client_runtime
            .get(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("backbone client interface '{}' not found", name),
            })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "backbone client runtime");
        match setting {
            "connect_timeout_secs" => {
                runtime.connect_timeout = Duration::from_secs_f64(Self::expect_f64(value, key)?);
                Ok(())
            }
            "reconnect_wait_secs" => {
                runtime.reconnect_wait = Duration::from_secs_f64(Self::expect_f64(value, key)?);
                Ok(())
            }
            "max_reconnect_tries" => {
                runtime.max_reconnect_tries = match Self::expect_u64(value, key)? {
                    0 => None,
                    raw => Some(raw as u32),
                };
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn reset_backbone_client_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_backbone_client_runtime_key(key)?;
        let handle = self
            .backbone_client_runtime
            .get(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("backbone client interface '{}' not found", name),
            })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "backbone client runtime");
        let startup = handle.startup.clone();
        match setting {
            "connect_timeout_secs" => runtime.connect_timeout = startup.connect_timeout,
            "reconnect_wait_secs" => runtime.reconnect_wait = startup.reconnect_wait,
            "max_reconnect_tries" => runtime.max_reconnect_tries = startup.max_reconnect_tries,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn list_tcp_server_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.tcp_server_runtime.keys().collect();
        names.sort();
        for name in names {
            for suffix in [
                "max_connections",
                "discoverable",
                "discovery_name",
                "announce_interval_secs",
                "reachable_on",
                "stamp_value",
                "latitude",
                "longitude",
                "height",
            ] {
                let key = format!("tcp_server.{}.{}", name, suffix);
                if let Some(entry) = self.tcp_server_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn list_tcp_client_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.tcp_client_runtime.keys().collect();
        names.sort();
        for name in names {
            for suffix in [
                "connect_timeout_secs",
                "reconnect_wait_secs",
                "max_reconnect_tries",
            ] {
                let key = format!("tcp_client.{}.{}", name, suffix);
                if let Some(entry) = self.tcp_client_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn tcp_client_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("tcp_client.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.tcp_client_runtime.get(name)?;
        let current = recover_mutex_guard(&handle.runtime, "tcp client runtime").clone();
        let startup = handle.startup.clone();
        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          description: &str|
         -> RuntimeConfigEntry {
            RuntimeConfigEntry {
                key: key.to_string(),
                source: if value == default {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value,
                default,
                apply_mode: RuntimeConfigApplyMode::NextReconnect,
                description: Some(description.to_string()),
            }
        };
        match setting {
            "connect_timeout_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.connect_timeout.as_secs_f64()),
                RuntimeConfigValue::Float(startup.connect_timeout.as_secs_f64()),
                "TCP client connect timeout in seconds; applies on the next reconnect.",
            )),
            "reconnect_wait_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.reconnect_wait.as_secs_f64()),
                RuntimeConfigValue::Float(startup.reconnect_wait.as_secs_f64()),
                "Delay between TCP client reconnect attempts in seconds.",
            )),
            "max_reconnect_tries" => Some(make_entry(
                RuntimeConfigValue::Int(current.max_reconnect_tries.unwrap_or(0) as i64),
                RuntimeConfigValue::Int(startup.max_reconnect_tries.unwrap_or(0) as i64),
                "Maximum TCP client reconnect attempts; 0 disables the cap.",
            )),
            _ => None,
        }
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn split_tcp_client_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("tcp_client.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn set_tcp_client_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_tcp_client_runtime_key(key)?;
        let handle = self
            .tcp_client_runtime
            .get(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp client interface '{}' not found", name),
            })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "tcp client runtime");
        match setting {
            "connect_timeout_secs" => {
                runtime.connect_timeout = Duration::from_secs_f64(Self::expect_f64(value, key)?);
                Ok(())
            }
            "reconnect_wait_secs" => {
                runtime.reconnect_wait = Duration::from_secs_f64(Self::expect_f64(value, key)?);
                Ok(())
            }
            "max_reconnect_tries" => {
                runtime.max_reconnect_tries = match Self::expect_u64(value, key)? {
                    0 => None,
                    raw => Some(raw as u32),
                };
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn reset_tcp_client_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_tcp_client_runtime_key(key)?;
        let handle = self
            .tcp_client_runtime
            .get(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp client interface '{}' not found", name),
            })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "tcp client runtime");
        let startup = handle.startup.clone();
        match setting {
            "connect_timeout_secs" => runtime.connect_timeout = startup.connect_timeout,
            "reconnect_wait_secs" => runtime.reconnect_wait = startup.reconnect_wait,
            "max_reconnect_tries" => runtime.max_reconnect_tries = startup.max_reconnect_tries,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-udp")]
    pub(crate) fn list_udp_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.udp_runtime.keys().collect();
        names.sort();
        for name in names {
            for suffix in ["forward_ip", "forward_port"] {
                let key = format!("udp.{}.{}", name, suffix);
                if let Some(entry) = self.udp_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-udp")]
    pub(crate) fn udp_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("udp.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.udp_runtime.get(name)?;
        let current = recover_mutex_guard(&handle.runtime, "udp runtime").clone();
        let startup = handle.startup.clone();
        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          description: &str|
         -> RuntimeConfigEntry {
            RuntimeConfigEntry {
                key: key.to_string(),
                source: if value == default {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value,
                default,
                apply_mode: RuntimeConfigApplyMode::Immediate,
                description: Some(description.to_string()),
            }
        };
        match setting {
            "forward_ip" => Some(make_entry(
                current
                    .forward_ip
                    .clone()
                    .map(RuntimeConfigValue::String)
                    .unwrap_or(RuntimeConfigValue::Null),
                startup
                    .forward_ip
                    .clone()
                    .map(RuntimeConfigValue::String)
                    .unwrap_or(RuntimeConfigValue::Null),
                "Outbound UDP destination IP or hostname; null clears it.",
            )),
            "forward_port" => Some(make_entry(
                current
                    .forward_port
                    .map(|value| RuntimeConfigValue::Int(value as i64))
                    .unwrap_or(RuntimeConfigValue::Null),
                startup
                    .forward_port
                    .map(|value| RuntimeConfigValue::Int(value as i64))
                    .unwrap_or(RuntimeConfigValue::Null),
                "Outbound UDP destination port; null clears it.",
            )),
            _ => None,
        }
    }

    #[cfg(feature = "iface-udp")]
    pub(crate) fn split_udp_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("udp.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-udp")]
    pub(crate) fn set_udp_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_udp_runtime_key(key)?;
        let handle = self.udp_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("udp interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "udp runtime");
        match setting {
            "forward_ip" => {
                runtime.forward_ip = Self::expect_optional_string(value, key)?;
                Ok(())
            }
            "forward_port" => {
                runtime.forward_port = match value {
                    RuntimeConfigValue::Null => None,
                    other => Some(Self::expect_u64(other, key)? as u16),
                };
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-udp")]
    pub(crate) fn reset_udp_runtime_config(&mut self, key: &str) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_udp_runtime_key(key)?;
        let handle = self.udp_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("udp interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "udp runtime");
        let startup = handle.startup.clone();
        match setting {
            "forward_ip" => runtime.forward_ip = startup.forward_ip,
            "forward_port" => runtime.forward_port = startup.forward_port,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-auto")]
    pub(crate) fn list_auto_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.auto_runtime.keys().collect();
        names.sort();
        for name in names {
            for suffix in [
                "announce_interval_secs",
                "peer_timeout_secs",
                "peer_job_interval_secs",
            ] {
                let key = format!("auto.{}.{}", name, suffix);
                if let Some(entry) = self.auto_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-auto")]
    pub(crate) fn auto_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("auto.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.auto_runtime.get(name)?;
        let current = recover_mutex_guard(&handle.runtime, "auto runtime").clone();
        let startup = handle.startup.clone();
        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          description: &str|
         -> RuntimeConfigEntry {
            RuntimeConfigEntry {
                key: key.to_string(),
                source: if value == default {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value,
                default,
                apply_mode: RuntimeConfigApplyMode::Immediate,
                description: Some(description.to_string()),
            }
        };
        match setting {
            "announce_interval_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.announce_interval_secs),
                RuntimeConfigValue::Float(startup.announce_interval_secs),
                "Interval between multicast discovery announces in seconds.",
            )),
            "peer_timeout_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.peer_timeout_secs),
                RuntimeConfigValue::Float(startup.peer_timeout_secs),
                "How long an Auto peer may stay quiet before being culled.",
            )),
            "peer_job_interval_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.peer_job_interval_secs),
                RuntimeConfigValue::Float(startup.peer_job_interval_secs),
                "Interval between Auto peer maintenance passes.",
            )),
            _ => None,
        }
    }

    #[cfg(feature = "iface-auto")]
    pub(crate) fn split_auto_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("auto.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-auto")]
    pub(crate) fn set_auto_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_auto_runtime_key(key)?;
        let handle = self.auto_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("auto interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "auto runtime");
        match setting {
            "announce_interval_secs" => {
                runtime.announce_interval_secs = Self::expect_f64(value, key)?.max(0.1)
            }
            "peer_timeout_secs" => {
                runtime.peer_timeout_secs = Self::expect_f64(value, key)?.max(0.1)
            }
            "peer_job_interval_secs" => {
                runtime.peer_job_interval_secs = Self::expect_f64(value, key)?.max(0.1)
            }
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                });
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-auto")]
    pub(crate) fn reset_auto_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_auto_runtime_key(key)?;
        let handle = self.auto_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("auto interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "auto runtime");
        let startup = handle.startup.clone();
        match setting {
            "announce_interval_secs" => {
                runtime.announce_interval_secs = startup.announce_interval_secs
            }
            "peer_timeout_secs" => runtime.peer_timeout_secs = startup.peer_timeout_secs,
            "peer_job_interval_secs" => {
                runtime.peer_job_interval_secs = startup.peer_job_interval_secs
            }
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                });
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-i2p")]
    pub(crate) fn list_i2p_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.i2p_runtime.keys().collect();
        names.sort();
        for name in names {
            let key = format!("i2p.{}.reconnect_wait_secs", name);
            if let Some(entry) = self.i2p_runtime_entry(&key) {
                entries.push(entry);
            }
        }
        entries
    }

    #[cfg(feature = "iface-i2p")]
    pub(crate) fn i2p_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("i2p.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.i2p_runtime.get(name)?;
        let current = recover_mutex_guard(&handle.runtime, "i2p runtime").clone();
        let startup = handle.startup.clone();
        match setting {
            "reconnect_wait_secs" => Some(RuntimeConfigEntry {
                key: key.to_string(),
                source: if current.reconnect_wait == startup.reconnect_wait {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value: RuntimeConfigValue::Float(current.reconnect_wait.as_secs_f64()),
                default: RuntimeConfigValue::Float(startup.reconnect_wait.as_secs_f64()),
                apply_mode: RuntimeConfigApplyMode::NextReconnect,
                description: Some(
                    "Delay before retrying outbound I2P peer connections.".to_string(),
                ),
            }),
            _ => None,
        }
    }

    #[cfg(feature = "iface-i2p")]
    pub(crate) fn split_i2p_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("i2p.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-i2p")]
    pub(crate) fn set_i2p_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_i2p_runtime_key(key)?;
        let handle = self.i2p_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("i2p interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "i2p runtime");
        match setting {
            "reconnect_wait_secs" => {
                runtime.reconnect_wait =
                    Duration::from_secs_f64(Self::expect_f64(value, key)?.max(0.1));
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-i2p")]
    pub(crate) fn reset_i2p_runtime_config(&mut self, key: &str) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_i2p_runtime_key(key)?;
        let handle = self.i2p_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("i2p interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "i2p runtime");
        let startup = handle.startup.clone();
        match setting {
            "reconnect_wait_secs" => runtime.reconnect_wait = startup.reconnect_wait,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                });
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-pipe")]
    pub(crate) fn list_pipe_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.pipe_runtime.keys().collect();
        names.sort();
        for name in names {
            let key = format!("pipe.{}.respawn_delay_secs", name);
            if let Some(entry) = self.pipe_runtime_entry(&key) {
                entries.push(entry);
            }
        }
        entries
    }

    #[cfg(feature = "iface-pipe")]
    pub(crate) fn pipe_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("pipe.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.pipe_runtime.get(name)?;
        let current = recover_mutex_guard(&handle.runtime, "pipe runtime").clone();
        let startup = handle.startup.clone();
        match setting {
            "respawn_delay_secs" => Some(RuntimeConfigEntry {
                key: key.to_string(),
                source: if current.respawn_delay == startup.respawn_delay {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value: RuntimeConfigValue::Float(current.respawn_delay.as_secs_f64()),
                default: RuntimeConfigValue::Float(startup.respawn_delay.as_secs_f64()),
                apply_mode: RuntimeConfigApplyMode::NextReconnect,
                description: Some(
                    "Delay before respawning the pipe subprocess after exit.".to_string(),
                ),
            }),
            _ => None,
        }
    }

    #[cfg(feature = "iface-pipe")]
    pub(crate) fn split_pipe_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("pipe.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-pipe")]
    pub(crate) fn set_pipe_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_pipe_runtime_key(key)?;
        let handle = self.pipe_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("pipe interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "pipe runtime");
        match setting {
            "respawn_delay_secs" => {
                runtime.respawn_delay =
                    Duration::from_secs_f64(Self::expect_f64(value, key)?.max(0.1));
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-pipe")]
    pub(crate) fn reset_pipe_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_pipe_runtime_key(key)?;
        let handle = self.pipe_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("pipe interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "pipe runtime");
        let startup = handle.startup.clone();
        match setting {
            "respawn_delay_secs" => runtime.respawn_delay = startup.respawn_delay,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                });
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-rnode")]
    pub(crate) fn list_rnode_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.rnode_runtime.keys().collect();
        names.sort();
        for name in names {
            for suffix in [
                "frequency_hz",
                "bandwidth_hz",
                "txpower_dbm",
                "spreading_factor",
                "coding_rate",
                "st_alock_pct",
                "lt_alock_pct",
            ] {
                let key = format!("rnode.{}.{}", name, suffix);
                if let Some(entry) = self.rnode_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-rnode")]
    pub(crate) fn rnode_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("rnode.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.rnode_runtime.get(name)?;
        let current = recover_mutex_guard(&handle.runtime, "rnode runtime").clone();
        let startup = handle.startup.clone();
        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          description: &str|
         -> RuntimeConfigEntry {
            RuntimeConfigEntry {
                key: key.to_string(),
                source: if value == default {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value,
                default,
                apply_mode: RuntimeConfigApplyMode::Immediate,
                description: Some(description.to_string()),
            }
        };
        match setting {
            "frequency_hz" => Some(make_entry(
                RuntimeConfigValue::Int(current.sub.frequency as i64),
                RuntimeConfigValue::Int(startup.sub.frequency as i64),
                "RNode radio frequency in Hz.",
            )),
            "bandwidth_hz" => Some(make_entry(
                RuntimeConfigValue::Int(current.sub.bandwidth as i64),
                RuntimeConfigValue::Int(startup.sub.bandwidth as i64),
                "RNode radio bandwidth in Hz.",
            )),
            "txpower_dbm" => Some(make_entry(
                RuntimeConfigValue::Int(current.sub.txpower as i64),
                RuntimeConfigValue::Int(startup.sub.txpower as i64),
                "RNode transmit power in dBm.",
            )),
            "spreading_factor" => Some(make_entry(
                RuntimeConfigValue::Int(current.sub.spreading_factor as i64),
                RuntimeConfigValue::Int(startup.sub.spreading_factor as i64),
                "RNode LoRa spreading factor.",
            )),
            "coding_rate" => Some(make_entry(
                RuntimeConfigValue::Int(current.sub.coding_rate as i64),
                RuntimeConfigValue::Int(startup.sub.coding_rate as i64),
                "RNode LoRa coding rate.",
            )),
            "st_alock_pct" => Some(make_entry(
                current
                    .sub
                    .st_alock
                    .map(|value| RuntimeConfigValue::Float(value as f64))
                    .unwrap_or(RuntimeConfigValue::Null),
                startup
                    .sub
                    .st_alock
                    .map(|value| RuntimeConfigValue::Float(value as f64))
                    .unwrap_or(RuntimeConfigValue::Null),
                "RNode short-term airtime lock percent; null clears it.",
            )),
            "lt_alock_pct" => Some(make_entry(
                current
                    .sub
                    .lt_alock
                    .map(|value| RuntimeConfigValue::Float(value as f64))
                    .unwrap_or(RuntimeConfigValue::Null),
                startup
                    .sub
                    .lt_alock
                    .map(|value| RuntimeConfigValue::Float(value as f64))
                    .unwrap_or(RuntimeConfigValue::Null),
                "RNode long-term airtime lock percent; null clears it.",
            )),
            _ => None,
        }
    }

    #[cfg(feature = "iface-rnode")]
    pub(crate) fn split_rnode_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("rnode.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-rnode")]
    pub(crate) fn apply_rnode_runtime(
        runtime: &mut RNodeRuntime,
    ) -> Result<(), RuntimeConfigError> {
        if let Some(err) = validate_sub_config(&runtime.sub) {
            return Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidValue,
                message: err,
            });
        }
        if let Some(writer) = runtime.writer.clone() {
            crate::interface::rnode::configure_subinterface(&writer, 0, &runtime.sub, false)
                .map_err(|e| RuntimeConfigError {
                    code: RuntimeConfigErrorCode::ApplyFailed,
                    message: format!("failed to apply RNode config: {}", e),
                })?;
        }
        Ok(())
    }

    #[cfg(feature = "iface-rnode")]
    pub(crate) fn set_rnode_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_rnode_runtime_key(key)?;
        let updated_sub = {
            let handle = self.rnode_runtime.get(name).ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("rnode interface '{}' not found", name),
            })?;
            let mut runtime = recover_mutex_guard(&handle.runtime, "rnode runtime");
            let old = runtime.sub.clone();
            match setting {
                "frequency_hz" => runtime.sub.frequency = Self::expect_u64(value, key)? as u32,
                "bandwidth_hz" => runtime.sub.bandwidth = Self::expect_u64(value, key)? as u32,
                "txpower_dbm" => runtime.sub.txpower = Self::expect_i64(value, key)? as i8,
                "spreading_factor" => {
                    runtime.sub.spreading_factor = Self::expect_u64(value, key)? as u8
                }
                "coding_rate" => runtime.sub.coding_rate = Self::expect_u64(value, key)? as u8,
                "st_alock_pct" => {
                    runtime.sub.st_alock = match value {
                        RuntimeConfigValue::Null => None,
                        other => Some(Self::expect_f64(other, key)? as f32),
                    };
                }
                "lt_alock_pct" => {
                    runtime.sub.lt_alock = match value {
                        RuntimeConfigValue::Null => None,
                        other => Some(Self::expect_f64(other, key)? as f32),
                    };
                }
                _ => {
                    return Err(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::UnknownKey,
                        message: format!("unknown runtime-config key '{}'", key),
                    });
                }
            }
            if let Err(err) = Self::apply_rnode_runtime(&mut runtime) {
                runtime.sub = old;
                return Err(err);
            }
            runtime.sub.clone()
        };
        self.refresh_rnode_interface_bitrate(name, &updated_sub);
        Ok(())
    }

    #[cfg(feature = "iface-rnode")]
    pub(crate) fn reset_rnode_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_rnode_runtime_key(key)?;
        let updated_sub = {
            let handle = self.rnode_runtime.get(name).ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("rnode interface '{}' not found", name),
            })?;
            let mut runtime = recover_mutex_guard(&handle.runtime, "rnode runtime");
            let old = runtime.sub.clone();
            let startup = handle.startup.clone();
            match setting {
                "frequency_hz" => runtime.sub.frequency = startup.sub.frequency,
                "bandwidth_hz" => runtime.sub.bandwidth = startup.sub.bandwidth,
                "txpower_dbm" => runtime.sub.txpower = startup.sub.txpower,
                "spreading_factor" => runtime.sub.spreading_factor = startup.sub.spreading_factor,
                "coding_rate" => runtime.sub.coding_rate = startup.sub.coding_rate,
                "st_alock_pct" => runtime.sub.st_alock = startup.sub.st_alock,
                "lt_alock_pct" => runtime.sub.lt_alock = startup.sub.lt_alock,
                _ => {
                    return Err(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::UnknownKey,
                        message: format!("unknown runtime-config key '{}'", key),
                    });
                }
            }
            if let Err(err) = Self::apply_rnode_runtime(&mut runtime) {
                runtime.sub = old;
                return Err(err);
            }
            runtime.sub.clone()
        };
        self.refresh_rnode_interface_bitrate(name, &updated_sub);
        Ok(())
    }

    #[cfg(feature = "iface-rnode")]
    fn refresh_rnode_interface_bitrate(&mut self, name: &str, sub: &RNodeSubConfig) {
        let bitrate = Some(crate::interface::rnode::estimate_lora_bitrate_bps(sub));
        let airtime_profile = Some(crate::interface::rnode::lora_airtime_profile(sub));
        let mut refreshed = Vec::new();
        for entry in self.interfaces.values_mut() {
            if entry.info.name == name {
                entry.info.bitrate = bitrate;
                entry.info.airtime_profile = airtime_profile;
                refreshed.push(entry.info.clone());
            }
        }
        for info in refreshed {
            self.engine.register_interface(info);
        }
    }

    pub(crate) fn list_generic_interface_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<String> = self
            .interfaces
            .values()
            .map(|entry| entry.info.name.clone())
            .collect();
        names.sort();
        names.dedup();
        for name in names {
            for suffix in [
                "enabled",
                "mode",
                "announce_rate_target",
                "announce_rate_grace",
                "announce_rate_penalty",
                "announce_cap",
                "ingress_control",
                "ic_max_held_announces",
                "ic_burst_hold",
                "ic_burst_freq_new",
                "ic_burst_freq",
                "ic_new_time",
                "ic_burst_penalty",
                "ic_held_release_interval",
            ] {
                let key = format!("interface.{}.{}", name, suffix);
                if let Some(entry) = self.generic_interface_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
            if self.interface_ifac_runtime.contains_key(&name) {
                for suffix in ["ifac_netname", "ifac_passphrase", "ifac_size_bytes"] {
                    let key = format!("interface.{}.{}", name, suffix);
                    if let Some(entry) = self.generic_interface_runtime_entry(&key) {
                        entries.push(entry);
                    }
                }
            }
        }
        entries
    }

    pub(crate) fn generic_interface_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("interface.")?;
        let (name, setting) = rest.rsplit_once('.')?;
        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          apply_mode: RuntimeConfigApplyMode,
                          description: &str|
         -> RuntimeConfigEntry {
            RuntimeConfigEntry {
                key: key.to_string(),
                source: if value == default {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value,
                default,
                apply_mode,
                description: Some(description.to_string()),
            }
        };
        match setting {
            "enabled" => {
                let entry = self
                    .interfaces
                    .values()
                    .find(|entry| entry.info.name == name)?;
                Some(make_entry(
                    RuntimeConfigValue::Bool(entry.enabled),
                    RuntimeConfigValue::Bool(true),
                    RuntimeConfigApplyMode::Immediate,
                    "Administrative enable/disable state for this interface.",
                ))
            }
            "ifac_netname" => {
                let current = self.interface_ifac_runtime.get(name)?;
                let startup = self.interface_ifac_runtime_defaults.get(name)?;
                Some(make_entry(
                    current
                        .netname
                        .clone()
                        .map(RuntimeConfigValue::String)
                        .unwrap_or(RuntimeConfigValue::Null),
                    startup
                        .netname
                        .clone()
                        .map(RuntimeConfigValue::String)
                        .unwrap_or(RuntimeConfigValue::Null),
                    RuntimeConfigApplyMode::Immediate,
                    "IFAC network name for this interface; null clears it.",
                ))
            }
            "ifac_passphrase" => {
                let current = self.interface_ifac_runtime.get(name)?;
                let startup = self.interface_ifac_runtime_defaults.get(name)?;
                let current_value = current
                    .netkey
                    .as_ref()
                    .map(|_| RuntimeConfigValue::String("<redacted>".to_string()))
                    .unwrap_or(RuntimeConfigValue::Null);
                let default_value = startup
                    .netkey
                    .as_ref()
                    .map(|_| RuntimeConfigValue::String("<redacted>".to_string()))
                    .unwrap_or(RuntimeConfigValue::Null);
                Some(RuntimeConfigEntry {
                    key: key.to_string(),
                    source: if current.netkey == startup.netkey {
                        RuntimeConfigSource::Startup
                    } else {
                        RuntimeConfigSource::RuntimeOverride
                    },
                    value: current_value,
                    default: default_value,
                    apply_mode: RuntimeConfigApplyMode::Immediate,
                    description: Some(
                        "IFAC passphrase for this interface; write-only, set a string to change it or null to clear it."
                            .to_string(),
                    ),
                })
            }
            "ifac_size_bytes" => {
                let current = self.interface_ifac_runtime.get(name)?;
                let startup = self.interface_ifac_runtime_defaults.get(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Int(current.size as i64),
                    RuntimeConfigValue::Int(startup.size as i64),
                    RuntimeConfigApplyMode::Immediate,
                    "IFAC size in bytes; applies when IFAC is enabled.",
                ))
            }
            "mode" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::String(Self::interface_mode_name(current.mode)),
                    RuntimeConfigValue::String(Self::interface_mode_name(startup.mode)),
                    RuntimeConfigApplyMode::Immediate,
                    "Routing mode for this interface.",
                ))
            }
            "announce_rate_target" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    current
                        .announce_rate_target
                        .map(RuntimeConfigValue::Float)
                        .unwrap_or(RuntimeConfigValue::Null),
                    startup
                        .announce_rate_target
                        .map(RuntimeConfigValue::Float)
                        .unwrap_or(RuntimeConfigValue::Null),
                    RuntimeConfigApplyMode::Immediate,
                    "Optional announce rate target in announces/sec; null disables it.",
                ))
            }
            "announce_rate_grace" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Int(current.announce_rate_grace as i64),
                    RuntimeConfigValue::Int(startup.announce_rate_grace as i64),
                    RuntimeConfigApplyMode::Immediate,
                    "Announce rate grace period in announces.",
                ))
            }
            "announce_rate_penalty" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.announce_rate_penalty),
                    RuntimeConfigValue::Float(startup.announce_rate_penalty),
                    RuntimeConfigApplyMode::Immediate,
                    "Announce rate penalty multiplier.",
                ))
            }
            "announce_cap" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.announce_cap),
                    RuntimeConfigValue::Float(startup.announce_cap),
                    RuntimeConfigApplyMode::Immediate,
                    "Fraction of bitrate reserved for announces.",
                ))
            }
            "ingress_control" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Bool(current.ingress_control.enabled),
                    RuntimeConfigValue::Bool(startup.ingress_control.enabled),
                    RuntimeConfigApplyMode::Immediate,
                    "Whether ingress control is enabled for this interface.",
                ))
            }
            "ic_max_held_announces" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Int(current.ingress_control.max_held_announces as i64),
                    RuntimeConfigValue::Int(startup.ingress_control.max_held_announces as i64),
                    RuntimeConfigApplyMode::Immediate,
                    "Maximum held announces retained while ingress control is limiting this interface.",
                ))
            }
            "ic_burst_hold" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.ingress_control.burst_hold),
                    RuntimeConfigValue::Float(startup.ingress_control.burst_hold),
                    RuntimeConfigApplyMode::Immediate,
                    "Seconds to keep ingress-control burst state active before releasing held announces.",
                ))
            }
            "ic_burst_freq_new" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.ingress_control.burst_freq_new),
                    RuntimeConfigValue::Float(startup.ingress_control.burst_freq_new),
                    RuntimeConfigApplyMode::Immediate,
                    "Announce frequency threshold for new interfaces.",
                ))
            }
            "ic_burst_freq" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.ingress_control.burst_freq),
                    RuntimeConfigValue::Float(startup.ingress_control.burst_freq),
                    RuntimeConfigApplyMode::Immediate,
                    "Announce frequency threshold for established interfaces.",
                ))
            }
            "ic_new_time" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.ingress_control.new_time),
                    RuntimeConfigValue::Float(startup.ingress_control.new_time),
                    RuntimeConfigApplyMode::Immediate,
                    "Seconds after interface start that ingress control uses the new-interface burst threshold.",
                ))
            }
            "ic_burst_penalty" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.ingress_control.burst_penalty),
                    RuntimeConfigValue::Float(startup.ingress_control.burst_penalty),
                    RuntimeConfigApplyMode::Immediate,
                    "Seconds to wait after a burst before releasing held announces.",
                ))
            }
            "ic_held_release_interval" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.ingress_control.held_release_interval),
                    RuntimeConfigValue::Float(startup.ingress_control.held_release_interval),
                    RuntimeConfigApplyMode::Immediate,
                    "Seconds between held announce releases.",
                ))
            }
            _ => None,
        }
    }

    pub(crate) fn split_generic_interface_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("interface.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.rsplit_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    pub(crate) fn interface_runtime_infos_by_name(
        &self,
        name: &str,
    ) -> Option<(
        rns_core::transport::types::InterfaceId,
        &rns_core::transport::types::InterfaceInfo,
        &rns_core::transport::types::InterfaceInfo,
    )> {
        let (id, entry) = self
            .interfaces
            .iter()
            .find(|(_, entry)| entry.info.name == name)?;
        let startup = self.interface_runtime_defaults.get(name)?;
        Some((*id, &entry.info, startup))
    }

    pub(crate) fn interface_mode_name(mode: u8) -> String {
        match mode {
            rns_core::constants::MODE_FULL => "full".to_string(),
            rns_core::constants::MODE_ACCESS_POINT => "access_point".to_string(),
            rns_core::constants::MODE_POINT_TO_POINT => "point_to_point".to_string(),
            rns_core::constants::MODE_ROAMING => "roaming".to_string(),
            rns_core::constants::MODE_BOUNDARY => "boundary".to_string(),
            rns_core::constants::MODE_GATEWAY => "gateway".to_string(),
            _ => mode.to_string(),
        }
    }

    pub(crate) fn parse_interface_mode(value: &RuntimeConfigValue) -> Option<u8> {
        match value {
            RuntimeConfigValue::Int(v) if *v >= 0 && *v <= u8::MAX as i64 => Some(*v as u8),
            RuntimeConfigValue::String(s) => match s.to_ascii_lowercase().as_str() {
                "full" => Some(rns_core::constants::MODE_FULL),
                "access_point" | "accesspoint" | "ap" => {
                    Some(rns_core::constants::MODE_ACCESS_POINT)
                }
                "point_to_point" | "pointtopoint" | "ptp" => {
                    Some(rns_core::constants::MODE_POINT_TO_POINT)
                }
                "roaming" => Some(rns_core::constants::MODE_ROAMING),
                "boundary" => Some(rns_core::constants::MODE_BOUNDARY),
                "gateway" | "gw" => Some(rns_core::constants::MODE_GATEWAY),
                _ => None,
            },
            _ => None,
        }
    }

    pub(crate) fn apply_interface_ifac_runtime(
        entry: &mut InterfaceEntry,
        config: &IfacRuntimeConfig,
    ) {
        entry.ifac = if config.netname.is_some() || config.netkey.is_some() {
            match ifac::derive_ifac(
                config.netname.as_deref(),
                config.netkey.as_deref(),
                config.size,
            ) {
                Ok(state) => Some(state),
                Err(err) => {
                    log::warn!(
                        "failed to apply IFAC runtime for {}: {}",
                        entry.info.name,
                        err
                    );
                    None
                }
            }
        } else {
            None
        };
    }

    pub(crate) fn set_generic_interface_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_generic_interface_runtime_key(key)?;
        let (id, _) = self
            .interfaces
            .iter()
            .find(|(_, entry)| entry.info.name == name)
            .map(|(id, entry)| (*id, entry))
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("interface '{}' not found", name),
            })?;
        let entry = self.interfaces.get_mut(&id).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("interface '{}' not found", name),
        })?;
        match setting {
            "enabled" => {
                entry.enabled = Self::expect_bool(value, key)?;
            }
            "ifac_netname" => {
                let runtime =
                    self.interface_ifac_runtime
                        .get_mut(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                runtime.netname = match value {
                    RuntimeConfigValue::Null => None,
                    RuntimeConfigValue::String(value) => Some(value),
                    _ => {
                        return Err(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::InvalidType,
                            message: format!("{} expects a string or null", key),
                        })
                    }
                };
                Self::apply_interface_ifac_runtime(entry, runtime);
            }
            "ifac_passphrase" => {
                let runtime =
                    self.interface_ifac_runtime
                        .get_mut(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                runtime.netkey = match value {
                    RuntimeConfigValue::Null => None,
                    RuntimeConfigValue::String(value) => Some(value),
                    _ => {
                        return Err(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::InvalidType,
                            message: format!("{} expects a string or null", key),
                        })
                    }
                };
                Self::apply_interface_ifac_runtime(entry, runtime);
            }
            "ifac_size_bytes" => {
                let runtime =
                    self.interface_ifac_runtime
                        .get_mut(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                runtime.size =
                    (Self::expect_u64(value, key)? as usize).max(crate::ifac::IFAC_MIN_SIZE);
                Self::apply_interface_ifac_runtime(entry, runtime);
            }
            "mode" => {
                entry.info.mode = Self::parse_interface_mode(&value).ok_or(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::InvalidValue,
                    message: format!("{} must be a valid interface mode", key),
                })?;
            }
            "announce_rate_target" => {
                entry.info.announce_rate_target = match value {
                    RuntimeConfigValue::Null => None,
                    RuntimeConfigValue::Float(v) if v >= 0.0 => Some(v),
                    RuntimeConfigValue::Int(v) if v >= 0 => Some(v as f64),
                    RuntimeConfigValue::Float(_) | RuntimeConfigValue::Int(_) => {
                        return Err(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::InvalidValue,
                            message: format!("{} must be >= 0", key),
                        })
                    }
                    _ => {
                        return Err(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::InvalidType,
                            message: format!("{} expects a numeric value or null", key),
                        })
                    }
                };
            }
            "announce_rate_grace" => {
                entry.info.announce_rate_grace = Self::expect_u64(value, key)? as u32
            }
            "announce_rate_penalty" => {
                entry.info.announce_rate_penalty = Self::expect_f64(value, key)?
            }
            "announce_cap" => entry.info.announce_cap = Self::expect_f64(value, key)?,
            "ingress_control" => {
                entry.info.ingress_control.enabled = Self::expect_bool(value, key)?
            }
            "ic_max_held_announces" => {
                entry.info.ingress_control.max_held_announces =
                    Self::expect_u64(value, key)? as usize
            }
            "ic_burst_hold" => {
                entry.info.ingress_control.burst_hold = Self::expect_f64(value, key)?
            }
            "ic_burst_freq_new" => {
                entry.info.ingress_control.burst_freq_new = Self::expect_f64(value, key)?
            }
            "ic_burst_freq" => {
                entry.info.ingress_control.burst_freq = Self::expect_f64(value, key)?
            }
            "ic_new_time" => entry.info.ingress_control.new_time = Self::expect_f64(value, key)?,
            "ic_burst_penalty" => {
                entry.info.ingress_control.burst_penalty = Self::expect_f64(value, key)?
            }
            "ic_held_release_interval" => {
                entry.info.ingress_control.held_release_interval = Self::expect_f64(value, key)?
            }
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        let info = entry.info.clone();
        self.engine.register_interface(info);
        Ok(())
    }

    pub(crate) fn reset_generic_interface_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_generic_interface_runtime_key(key)?;
        let startup =
            self.interface_runtime_defaults
                .get(name)
                .cloned()
                .ok_or(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::NotFound,
                    message: format!("interface '{}' not found", name),
                })?;
        let entry = self
            .interfaces
            .values_mut()
            .find(|entry| entry.info.name == name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("interface '{}' not found", name),
            })?;
        match setting {
            "enabled" => entry.enabled = true,
            "ifac_netname" => {
                let startup_ifac =
                    self.interface_ifac_runtime_defaults
                        .get(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                let runtime =
                    self.interface_ifac_runtime
                        .get_mut(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                runtime.netname = startup_ifac.netname.clone();
                Self::apply_interface_ifac_runtime(entry, runtime);
            }
            "ifac_passphrase" => {
                let startup_ifac =
                    self.interface_ifac_runtime_defaults
                        .get(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                let runtime =
                    self.interface_ifac_runtime
                        .get_mut(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                runtime.netkey = startup_ifac.netkey.clone();
                Self::apply_interface_ifac_runtime(entry, runtime);
            }
            "ifac_size_bytes" => {
                let startup_ifac =
                    self.interface_ifac_runtime_defaults
                        .get(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                let runtime =
                    self.interface_ifac_runtime
                        .get_mut(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                runtime.size = startup_ifac.size;
                Self::apply_interface_ifac_runtime(entry, runtime);
            }
            "mode" => entry.info.mode = startup.mode,
            "announce_rate_target" => {
                entry.info.announce_rate_target = startup.announce_rate_target
            }
            "announce_rate_grace" => entry.info.announce_rate_grace = startup.announce_rate_grace,
            "announce_rate_penalty" => {
                entry.info.announce_rate_penalty = startup.announce_rate_penalty
            }
            "announce_cap" => entry.info.announce_cap = startup.announce_cap,
            "ingress_control" => {
                entry.info.ingress_control.enabled = startup.ingress_control.enabled
            }
            "ic_max_held_announces" => {
                entry.info.ingress_control.max_held_announces =
                    startup.ingress_control.max_held_announces
            }
            "ic_burst_hold" => {
                entry.info.ingress_control.burst_hold = startup.ingress_control.burst_hold
            }
            "ic_burst_freq_new" => {
                entry.info.ingress_control.burst_freq_new = startup.ingress_control.burst_freq_new
            }
            "ic_burst_freq" => {
                entry.info.ingress_control.burst_freq = startup.ingress_control.burst_freq
            }
            "ic_new_time" => entry.info.ingress_control.new_time = startup.ingress_control.new_time,
            "ic_burst_penalty" => {
                entry.info.ingress_control.burst_penalty = startup.ingress_control.burst_penalty
            }
            "ic_held_release_interval" => {
                entry.info.ingress_control.held_release_interval =
                    startup.ingress_control.held_release_interval
            }
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        let info = entry.info.clone();
        self.engine.register_interface(info);
        Ok(())
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn tcp_server_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("tcp_server.")?;
        let (name, setting) = rest.split_once('.')?;
        if Self::is_discovery_runtime_setting(setting) {
            let handle = self.tcp_server_discovery_runtime.get(name)?;
            return Self::discovery_runtime_entry(
                key,
                setting,
                "TCP server",
                handle.current.discoverable,
                handle.startup.discoverable,
                &handle.current.config,
                &handle.startup.config,
            );
        }

        let handle = self.tcp_server_runtime.get(name)?;
        let current = recover_mutex_guard(&handle.runtime, "tcp server runtime").clone();
        let startup = handle.startup.clone();
        match setting {
            "max_connections" => Some(RuntimeConfigEntry {
                key: key.to_string(),
                value: RuntimeConfigValue::Int(current.max_connections.unwrap_or(0) as i64),
                default: RuntimeConfigValue::Int(startup.max_connections.unwrap_or(0) as i64),
                source: if current.max_connections == startup.max_connections {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                apply_mode: RuntimeConfigApplyMode::NewConnectionsOnly,
                description: Some(
                    "Maximum simultaneous inbound TCP server connections; 0 disables the cap."
                        .to_string(),
                ),
            }),
            _ => None,
        }
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn split_tcp_server_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("tcp_server.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn set_tcp_server_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_tcp_server_runtime_key(key)?;
        if matches!(
            setting,
            "discoverable"
                | "discovery_name"
                | "announce_interval_secs"
                | "reachable_on"
                | "stamp_value"
                | "latitude"
                | "longitude"
                | "height"
        ) {
            return self.set_tcp_server_discovery_runtime_config(key, value);
        }
        let handle = self
            .tcp_server_runtime
            .get(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp server interface '{}' not found", name),
            })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "tcp server runtime");
        match setting {
            "max_connections" => {
                runtime.max_connections = Self::set_optional_usize(value, key)?;
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn reset_tcp_server_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_tcp_server_runtime_key(key)?;
        if matches!(
            setting,
            "discoverable"
                | "discovery_name"
                | "announce_interval_secs"
                | "reachable_on"
                | "stamp_value"
                | "latitude"
                | "longitude"
                | "height"
        ) {
            return self.reset_tcp_server_discovery_runtime_config(key);
        }
        let handle = self
            .tcp_server_runtime
            .get(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp server interface '{}' not found", name),
            })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "tcp server runtime");
        let startup = handle.startup.clone();
        match setting {
            "max_connections" => runtime.max_connections = startup.max_connections,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn set_tcp_server_discovery_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_tcp_server_runtime_key(key)?;
        let handle = self
            .tcp_server_discovery_runtime
            .get_mut(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp server interface '{}' not found", name),
            })?;
        match setting {
            "discoverable" => handle.current.discoverable = Self::expect_bool(value, key)?,
            "discovery_name" => {
                handle.current.config.discovery_name = Self::expect_string(value, key)?
            }
            "announce_interval_secs" => {
                let secs = Self::expect_u64(value, key)?;
                if secs < 300 {
                    return Err(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::InvalidValue,
                        message: format!("{} must be >= 300", key),
                    });
                }
                handle.current.config.announce_interval = secs;
            }
            "reachable_on" => {
                handle.current.config.reachable_on = Self::expect_optional_string(value, key)?
            }
            "stamp_value" => {
                let raw = Self::expect_u64(value, key)?;
                if raw > u8::MAX as u64 {
                    return Err(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::InvalidValue,
                        message: format!("{} must be <= {}", key, u8::MAX),
                    });
                }
                handle.current.config.stamp_value = raw as u8;
            }
            "latitude" => handle.current.config.latitude = Self::expect_optional_f64(value, key)?,
            "longitude" => handle.current.config.longitude = Self::expect_optional_f64(value, key)?,
            "height" => handle.current.config.height = Self::expect_optional_f64(value, key)?,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        self.sync_tcp_server_discovery_runtime(name)
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn reset_tcp_server_discovery_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_tcp_server_runtime_key(key)?;
        let handle = self
            .tcp_server_discovery_runtime
            .get_mut(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp server interface '{}' not found", name),
            })?;
        match setting {
            "discoverable" => handle.current.discoverable = handle.startup.discoverable,
            "discovery_name" => {
                handle.current.config.discovery_name = handle.startup.config.discovery_name.clone()
            }
            "announce_interval_secs" => {
                handle.current.config.announce_interval = handle.startup.config.announce_interval
            }
            "reachable_on" => {
                handle.current.config.reachable_on = handle.startup.config.reachable_on.clone()
            }
            "stamp_value" => handle.current.config.stamp_value = handle.startup.config.stamp_value,
            "latitude" => handle.current.config.latitude = handle.startup.config.latitude,
            "longitude" => handle.current.config.longitude = handle.startup.config.longitude,
            "height" => handle.current.config.height = handle.startup.config.height,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        self.sync_tcp_server_discovery_runtime(name)
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn list_backbone_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.backbone_runtime.keys().collect();
        names.sort();
        for name in names {
            for suffix in [
                "idle_timeout_secs",
                "write_stall_timeout_secs",
                "max_penalty_duration_secs",
                "max_connections",
            ] {
                let key = format!("backbone.{}.{}", name, suffix);
                if let Some(entry) = self.backbone_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
            for suffix in [
                "discoverable",
                "discovery_name",
                "announce_interval_secs",
                "reachable_on",
                "stamp_value",
                "latitude",
                "longitude",
                "height",
            ] {
                let key = format!("backbone.{}.{}", name, suffix);
                if let Some(entry) = self.backbone_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn backbone_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("backbone.")?;
        let (name, setting) = rest.split_once('.')?;

        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          apply_mode: RuntimeConfigApplyMode,
                          description: &str| RuntimeConfigEntry {
            key: key.to_string(),
            source: if value == default {
                RuntimeConfigSource::Startup
            } else {
                RuntimeConfigSource::RuntimeOverride
            },
            value,
            default,
            apply_mode,
            description: Some(description.to_string()),
        };

        if Self::is_discovery_runtime_setting(setting) {
            let handle = self.backbone_discovery_runtime.get(name)?;
            return Self::discovery_runtime_entry(
                key,
                setting,
                "backbone",
                handle.current.discoverable,
                handle.startup.discoverable,
                &handle.current.config,
                &handle.startup.config,
            );
        }

        if let Some(handle) = self.backbone_runtime.get(name) {
            let current = recover_mutex_guard(&handle.runtime, "backbone runtime").clone();
            let startup = handle.startup.clone();
            return match setting {
                "idle_timeout_secs" => Some(make_entry(
                    RuntimeConfigValue::Float(current.idle_timeout.map(|d| d.as_secs_f64()).unwrap_or(0.0)),
                    RuntimeConfigValue::Float(startup.idle_timeout.map(|d| d.as_secs_f64()).unwrap_or(0.0)),
                    RuntimeConfigApplyMode::Immediate,
                    "Disconnect silent inbound peers after this many seconds; 0 disables the timeout.",
                )),
                "write_stall_timeout_secs" => Some(make_entry(
                    RuntimeConfigValue::Float(current.write_stall_timeout.map(|d| d.as_secs_f64()).unwrap_or(0.0)),
                    RuntimeConfigValue::Float(startup.write_stall_timeout.map(|d| d.as_secs_f64()).unwrap_or(0.0)),
                    RuntimeConfigApplyMode::Immediate,
                    "Disconnect peers whose send buffer remains unwritable for this many seconds; 0 disables the timeout.",
                )),
                "max_penalty_duration_secs" => Some(make_entry(
                    RuntimeConfigValue::Float(current.abuse.max_penalty_duration.map(|d| d.as_secs_f64()).unwrap_or(0.0)),
                    RuntimeConfigValue::Float(startup.abuse.max_penalty_duration.map(|d| d.as_secs_f64()).unwrap_or(0.0)),
                    RuntimeConfigApplyMode::Immediate,
                    "Maximum accepted backbone blacklist duration; 0 means no cap.",
                )),
                "max_connections" => Some(make_entry(
                    RuntimeConfigValue::Int(current.max_connections.unwrap_or(0) as i64),
                    RuntimeConfigValue::Int(startup.max_connections.unwrap_or(0) as i64),
                    RuntimeConfigApplyMode::NewConnectionsOnly,
                    "Maximum simultaneous inbound backbone connections; 0 disables the cap.",
                )),
                _ => None,
            };
        }

        None
    }
}
