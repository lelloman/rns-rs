//! The backbone peer pool: candidates from discovery, connecting to them
//! and keeping the pool healthy, and the peer state it reports.

use super::*;

impl Driver {
    #[cfg(feature = "iface-backbone")]
    pub(crate) fn configure_backbone_peer_pool(
        &mut self,
        settings: BackbonePeerPoolSettings,
        candidates: Vec<BackbonePeerPoolCandidateConfig>,
    ) {
        if settings.max_connected == 0 || (candidates.is_empty() && !self.discovery.enabled) {
            self.backbone_peer_pool = None;
            return;
        }
        self.backbone_peer_pool = Some(BackbonePeerPool::new(settings, candidates));
        if !self.discovery.enabled {
            self.maintain_backbone_peer_pool();
        }
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn seed_backbone_peer_pool_from_discovery_cache(&mut self) {
        if !self.discovery.enabled || self.backbone_peer_pool.is_none() {
            return;
        }
        match self.discovery.storage.list() {
            Ok(mut interfaces) => {
                interfaces.sort_by(|a, b| {
                    BackbonePeerPool::discovery_candidate_order(a)
                        .cmp(&BackbonePeerPool::discovery_candidate_order(b))
                });
                for iface in interfaces {
                    self.upsert_discovered_backbone_peer_pool_candidate(iface);
                }
            }
            Err(err) => log::warn!(
                "Failed to load discovered Backbone peer-pool candidates: {}",
                err
            ),
        }
        self.maintain_backbone_peer_pool();
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn upsert_discovered_backbone_peer_pool_candidate(
        &mut self,
        iface: crate::discovery::DiscoveredInterface,
    ) -> bool {
        if !self.discovery.enabled || self.backbone_peer_pool.is_none() {
            return false;
        }
        let Some(endpoint) = BackbonePeerPool::discovered_backbone_peer_endpoint(&iface) else {
            return false;
        };

        if !Self::autoconnect_qualified(
            &iface,
            self.discovery.autoconnect_unverified_implementations,
        ) {
            log::debug!(
                "Not auto-connecting discovered {} \"{}\", auto-connect criteria not satisfied (transport {}, implementation {} version {})",
                iface.interface_type,
                iface.name,
                iface.transport,
                iface.impl_name.as_deref().unwrap_or("unknown"),
                iface.impl_version.as_deref().unwrap_or("unknown"),
            );
            return false;
        }

        if !self.discovered_costs_affordable(&iface) {
            return false;
        }

        let mode = self.discovery.autoconnect_mode.unwrap_or_else(|| {
            if iface.transport && self.engine.transport_enabled() {
                rns_core::constants::MODE_GATEWAY
            } else {
                rns_core::constants::MODE_FULL
            }
        });
        let settings = DiscoveredCandidateSettings {
            mode,
            gravity: self.discovery.autoconnect_gravity,
            announces_to_internal: self.discovery.autoconnect_announces_to_internal,
            ingress_control: self.interface_settings.ingress_control,
        };
        let Some(pool) = self.backbone_peer_pool.as_mut() else {
            return false;
        };
        if pool.has_configured_endpoint(&endpoint) {
            return false;
        }
        pool.upsert_discovered(iface, endpoint, settings, &self.registry.next_dynamic_id);
        self.maintain_backbone_peer_pool();
        true
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn cull_stale_discovered_backbone_peer_pool_candidates(&mut self) {
        let cached_discoveries: Option<std::collections::HashSet<[u8; 32]>> =
            self.discovery.storage.list().ok().map(|interfaces| {
                interfaces
                    .into_iter()
                    .map(|interface| interface.discovery_hash)
                    .collect()
            });
        if let Some(pool) = self.backbone_peer_pool.as_mut() {
            pool.cull_stale_discovered(cached_discoveries);
        }
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn autoconnect_qualified(
        iface: &crate::discovery::DiscoveredInterface,
        allow_unverified: bool,
    ) -> bool {
        use crate::common::discovery::TRANSPORT_IMPLEMENTATION_NAME;

        // Only transport-enabled interfaces are auto-connected, even when the
        // unverified-implementation override is active.
        if !iface.transport {
            return false;
        }
        if allow_unverified {
            return true;
        }

        // The canonical Reticulum implementation and this native implementation
        // are trusted. Upstream only lists its own name because it does not know
        // about native discoverers.
        const AUTOCONNECT_IMPLS: [&str; 2] = ["RNS", TRANSPORT_IMPLEMENTATION_NAME];
        // Raised from 1.5.2 in upstream 9b464382.
        const AUTOCONNECT_MIN_VERSION: [u32; 3] = [1, 5, 7];

        let Some(impl_name) = iface.impl_name.as_deref() else {
            return false;
        };
        if !AUTOCONNECT_IMPLS.contains(&impl_name) {
            return false;
        }
        // Native versions track the crate release cycle rather than the upstream
        // Reticulum protocol version, so they are not gated on the minimum.
        if impl_name == TRANSPORT_IMPLEMENTATION_NAME {
            return true;
        }
        let Some(version) = iface.impl_version.as_deref().and_then(parse_version_tuple) else {
            return false;
        };
        version.as_slice() >= AUTOCONNECT_MIN_VERSION.as_slice()
    }

    /// Upstream 9b464382: a discovered interface is only auto-connected when
    /// the announce and path request costs it requires are within the stamp
    /// values this node generates (`DESTINATION_VALUE`, `PR_VALUE`). An
    /// interface that announced no cost requires none.
    #[cfg(feature = "iface-backbone")]
    pub(crate) fn discovered_costs_affordable(
        &self,
        iface: &crate::discovery::DiscoveredInterface,
    ) -> bool {
        let targets = self.stamps.stamper.targets();
        let dst_cost = iface.dst_cost.unwrap_or_default();
        let pr_cost = iface.pr_cost.unwrap_or_default();
        let dst_cost_ok = dst_cost <= targets.destination_value;
        let pr_cost_ok = pr_cost <= targets.path_request_value;
        if !dst_cost_ok {
            log::debug!(
                "Destination cost {} higher than configured value {} for {} \"{}\", not auto-connecting",
                dst_cost,
                targets.destination_value,
                iface.interface_type,
                iface.name,
            );
        }
        if !pr_cost_ok {
            log::debug!(
                "Path request cost {} higher than configured value {} for {} \"{}\", not auto-connecting",
                pr_cost,
                targets.path_request_value,
                iface.interface_type,
                iface.name,
            );
        }
        dst_cost_ok && pr_cost_ok
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn maintain_backbone_peer_pool(&mut self) {
        let Some(pool) = self.backbone_peer_pool.as_mut() else {
            return;
        };
        let now = time::now();
        pool.expire_cooldowns(now);
        while let Some((index, evict)) = self
            .backbone_peer_pool
            .as_ref()
            .and_then(|pool| pool.next_to_start(now))
        {
            match self.start_backbone_peer_pool_candidate(index) {
                Ok(()) => {
                    if let Some(victim) = evict {
                        self.evict_backbone_peer_pool_member(victim, index);
                    }
                }
                Err(err) => self.record_backbone_peer_pool_failure(index, err.to_string()),
            }
        }
    }

    /// Disconnect the active discovered member `id` to give its slot to the
    /// candidate at `replacement`, which has just connected. The evicted
    /// member goes back to standby without counting a failure.
    #[cfg(feature = "iface-backbone")]
    pub(super) fn evict_backbone_peer_pool_member(&mut self, id: InterfaceId, replacement: usize) {
        let Some(pool) = self.backbone_peer_pool.as_ref() else {
            return;
        };
        let replacement_name = pool
            .candidates
            .get(replacement)
            .map(|candidate| candidate.config.client.name.clone())
            .unwrap_or_default();
        let Some((index, name)) = self.release_backbone_peer_pool_member(id) else {
            return;
        };
        log::info!(
            "[{}] backbone peer pool full, disconnecting discovered peer [{}] in favour of configured peer",
            replacement_name,
            name
        );
        if let Some(candidate) = self
            .backbone_peer_pool
            .as_mut()
            .and_then(|pool| pool.candidates.get_mut(index))
        {
            candidate.retry_after = None;
        }
        self.callbacks.on_interface_down(id);
    }

    /// Stop and deregister the pool member running as interface `id`, and
    /// mark its candidate inactive. Returns the candidate index and the
    /// interface name, or `None` if no candidate is active as `id`.
    #[cfg(feature = "iface-backbone")]
    pub(super) fn release_backbone_peer_pool_member(
        &mut self,
        id: InterfaceId,
    ) -> Option<(usize, String)> {
        let (index, control, candidate_name) = self.backbone_peer_pool.as_mut()?.take_member(id)?;
        let name = self.stop_dynamic_backbone_client(id, control, candidate_name);
        Some((index, name))
    }

    /// Stop the dynamic Backbone client running as interface `id` and
    /// deregister it. Returns its interface name, or `fallback_name` when
    /// it is no longer registered.
    #[cfg(feature = "iface-backbone")]
    pub(crate) fn stop_dynamic_backbone_client(
        &mut self,
        id: InterfaceId,
        control: Option<crate::interface::ListenerControl>,
        fallback_name: String,
    ) -> String {
        if let Some(control) = control {
            control.request_stop();
            control.finish();
        }
        let name = if let Some(entry) = self.interfaces.remove(&id) {
            entry.info.name
        } else {
            fallback_name
        };
        self.runtime_config.interface_defaults.remove(&name);
        self.runtime_config.ifac.remove(&name);
        self.runtime_config.ifac_defaults.remove(&name);
        self.runtime_config.backbone_client.remove(&name);
        self.registry.display_names.remove(&id);
        if self.engine.interface_info(&id).is_some() {
            self.engine.deregister_interface(id);
        }
        name
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
        // The pool reconnects its members itself.
        let config = candidate.config.clone();
        let control = self.start_dynamic_backbone_client(&config, Some(0))?;
        if let Some(pool) = self.backbone_peer_pool.as_mut() {
            pool.mark_started(index, config.client.interface_id, control);
        }
        Ok(())
    }

    /// Start a Backbone client for `config` as a new interface and register
    /// it. `max_reconnect_tries` overrides the client's own reconnect limit.
    #[cfg(feature = "iface-backbone")]
    pub(crate) fn start_dynamic_backbone_client(
        &mut self,
        config: &BackbonePeerPoolCandidateConfig,
        max_reconnect_tries: Option<u32>,
    ) -> std::io::Result<crate::interface::ListenerControl> {
        let candidate = config;
        let mut client = candidate.client.clone();
        client.max_reconnect_tries = max_reconnect_tries;
        if let Ok(mut runtime) = client.runtime.lock() {
            runtime.max_reconnect_tries = max_reconnect_tries;
        }
        let id = client.interface_id;
        let name = client.name.clone();
        let mode = candidate.mode;
        let gravity = candidate.gravity;
        let recursive_prs = candidate.recursive_prs;
        let announces_from_internal = candidate.announces_from_internal;
        let announces_to_internal = candidate.announces_to_internal;
        let ingress_control = candidate.ingress_control;
        let stamp_costs = candidate.stamp_costs;
        let ifac_runtime = candidate.ifac_runtime.clone();
        let ifac_enabled = candidate.ifac_enabled;
        let interface_kind = candidate.interface_kind;
        let is_discovered = candidate.source == BackbonePeerPoolCandidateSource::Discovered;
        let wire_ifac_size = if ifac_enabled { ifac_runtime.size } else { 0 };
        let control = crate::interface::ListenerControl::new();
        // A client that reconnects on its own (an auto-connected one) is
        // kept, offline, when its target cannot be reached yet, as
        // upstream's is; one whose owner reconnects it (a peer pool
        // member) fails to start, which its owner accounts for.
        let start = if max_reconnect_tries == Some(0) {
            start_client_with_ifac
        } else {
            start_retrying_client
        };
        let writer = start(
            client.clone(),
            self.event_tx.clone(),
            wire_ifac_size,
            self.interface_settings.underlay_mark,
            control.clone(),
        )?;
        let info = rns_core::transport::types::InterfaceInfo {
            stamp_costs,
            id,
            name: name.clone(),
            mode,
            gravity,
            recursive_prs,
            announces_from_internal,
            announces_to_internal,
            out_capable: true,
            in_capable: true,
            bitrate: Some(client.bitrate),
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: rns_core::constants::ANNOUNCE_CAP,
            is_local_client: false,
            // Upstream's BackboneClientInterface, which discovery
            // auto-connects, synthesizes a tunnel on connect.
            wants_tunnel: interface_kind == crate::interface::InterfaceKind::BackboneClient,
            shared_medium: false,
            hop_limiter: None,
            tunnel_id: None,
            mtu: client.hw_mtu() as u32,
            mtu_upgradable: true,
            ingress_control,
            ia_freq: 0.0,
            ia_samples: 0,
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
        // Upstream's `str()` of the BackboneClientInterface it starts.
        self.registry.display_names.insert(
            id,
            crate::interface::display::backbone(&name, &client.target_host, client.target_port),
        );
        self.interfaces.insert(
            id,
            InterfaceEntry {
                id,
                info,
                writer,
                async_writer_metrics: Some(async_writer_metrics),
                enabled: true,
                online: false,
                dynamic: is_discovered,
                ifac: ifac_state,
                stats: InterfaceStats {
                    started: time::now(),
                    ..Default::default()
                },
                interface_type: interface_kind.type_name().to_string(),
                send_retry_at: None,
                send_retry_backoff: Duration::ZERO,
            },
        );
        Ok(control)
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn record_backbone_peer_pool_failure(&mut self, index: usize, error: String) {
        if let Some(pool) = self.backbone_peer_pool.as_mut() {
            pool.record_failure(index, error);
        }
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn handle_backbone_peer_pool_down(&mut self, id: InterfaceId) {
        let Some((index, _)) = self.release_backbone_peer_pool_member(id) else {
            return;
        };
        self.record_backbone_peer_pool_failure(index, "interface down".into());
        self.maintain_backbone_peer_pool();
    }

    /// The network a peer pool member connected from a discovery was
    /// announced by.
    #[cfg(feature = "iface-backbone")]
    pub(crate) fn backbone_peer_pool_discovery_network(&self, id: InterfaceId) -> Option<[u8; 16]> {
        self.backbone_peer_pool.as_ref()?.discovery_network(id)
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn backbone_peer_pool_status(&self) -> Option<BackbonePeerPoolStatus> {
        Some(self.backbone_peer_pool.as_ref()?.status(&self.interfaces))
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn blacklist_backbone_peer(
        &mut self,
        interface_name: &str,
        peer_ip: std::net::IpAddr,
        duration: std::time::Duration,
        reason: String,
        penalty_level: u8,
    ) -> bool {
        let Some(capped_duration) =
            self.runtime_config
                .blacklist_backbone_peer(interface_name, peer_ip, duration, reason)
        else {
            return false;
        };
        if self.hooks.attached(HookPoint::BackbonePeerPenalty) {
            let peer = BackbonePeerHookEvent {
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
            };
            self.run_hooks_with_effects(
                HookPoint::BackbonePeerPenalty,
                &HookEvent::BackbonePeer(&peer),
                InjectedActions::Dispatch,
            );
        }
        true
    }

    #[cfg(not(feature = "iface-backbone"))]
    pub(crate) fn blacklist_backbone_peer(
        &mut self,
        _interface_name: &str,
        _peer_ip: std::net::IpAddr,
        _duration: std::time::Duration,
        _reason: String,
        _penalty_level: u8,
    ) -> bool {
        false
    }
}
