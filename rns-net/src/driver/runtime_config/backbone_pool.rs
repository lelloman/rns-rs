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
        self.backbone_peer_pool = Some(BackbonePeerPool {
            settings,
            candidates: candidates
                .into_iter()
                .map(|config| BackbonePeerPoolCandidate {
                    config,
                    active_id: None,
                    failures: Vec::new(),
                    consecutive_failures: 0,
                    retry_after: None,
                    cooldown_until: None,
                    last_error: None,
                    control: None,
                })
                .collect(),
        });
        if let Some(pool) = self.backbone_peer_pool.as_mut() {
            Self::sort_backbone_peer_pool_candidates(pool);
        }
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
                    Self::discovery_candidate_order(a).cmp(&Self::discovery_candidate_order(b))
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
        let Some((remote, port, transport_identity, discovery)) =
            Self::discovered_backbone_peer_endpoint(&iface)
        else {
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

        if self.backbone_peer_pool.as_ref().is_some_and(|pool| {
            pool.candidates.iter().any(|candidate| {
                candidate.config.source == BackbonePeerPoolCandidateSource::Configured
                    && Self::pool_candidate_matches_endpoint(
                        &candidate.config,
                        &remote,
                        port,
                        Some(&transport_identity),
                    )
            })
        }) {
            return false;
        }

        let Some(pool) = self.backbone_peer_pool.as_mut() else {
            return false;
        };
        if let Some(candidate) = pool.candidates.iter_mut().find(|candidate| {
            candidate.config.source == BackbonePeerPoolCandidateSource::Discovered
                && (candidate
                    .config
                    .discovery
                    .as_ref()
                    .is_some_and(|old| old.discovery_hash == discovery.discovery_hash)
                    || Self::pool_candidate_matches_endpoint(
                        &candidate.config,
                        &remote,
                        port,
                        Some(&transport_identity),
                    ))
        }) {
            candidate.config.client.target_host = remote;
            candidate.config.client.target_port = port;
            candidate.config.client.transport_identity = Some(transport_identity);
            candidate.config.mode = self.discovery.autoconnect_mode.unwrap_or_else(|| {
                if iface.transport && self.engine.transport_enabled() {
                    rns_core::constants::MODE_GATEWAY
                } else {
                    rns_core::constants::MODE_FULL
                }
            });
            candidate.config.gravity = self.discovery.autoconnect_gravity;
            candidate.config.announces_to_internal =
                self.discovery.autoconnect_announces_to_internal;
            if candidate.active_id.is_none() {
                candidate.config.client.name = Self::discovered_pool_candidate_name(&iface);
            }
            candidate.config.discovery = Some(discovery);
            candidate.config.ifac_runtime = IfacRuntimeConfig {
                netname: iface.ifac_netname,
                netkey: iface.ifac_netkey,
                size: 16,
            };
            candidate.config.ifac_enabled = candidate.config.ifac_runtime.netname.is_some()
                || candidate.config.ifac_runtime.netkey.is_some();
            Self::sort_backbone_peer_pool_candidates(pool);
            self.maintain_backbone_peer_pool();
            return true;
        }

        let id = InterfaceId(
            self.registry
                .next_dynamic_id
                .fetch_add(1, Ordering::Relaxed),
        );
        let mut client = BackboneClientConfig {
            name: Self::discovered_pool_candidate_name(&iface),
            target_host: remote,
            target_port: port,
            interface_id: id,
            transport_identity: Some(transport_identity),
            ..BackboneClientConfig::default()
        };
        client.runtime = Arc::new(Mutex::new(BackboneClientRuntime::from_config(&client)));
        let ifac_runtime = IfacRuntimeConfig {
            netname: iface.ifac_netname,
            netkey: iface.ifac_netkey,
            size: 16,
        };
        let ifac_enabled = ifac_runtime.netname.is_some() || ifac_runtime.netkey.is_some();
        let mode = self.discovery.autoconnect_mode.unwrap_or_else(|| {
            if iface.transport && self.engine.transport_enabled() {
                rns_core::constants::MODE_GATEWAY
            } else {
                rns_core::constants::MODE_FULL
            }
        });
        pool.candidates.push(BackbonePeerPoolCandidate {
            config: BackbonePeerPoolCandidateConfig {
                client,
                mode,
                gravity: self.discovery.autoconnect_gravity,
                recursive_prs: false,
                announces_from_internal: true,
                announces_to_internal: self.discovery.autoconnect_announces_to_internal,
                ingress_control: self.interface_settings.ingress_control,
                stamp_costs: Default::default(),
                ifac_runtime,
                ifac_enabled,
                interface_type_name: "BackboneInterface".to_string(),
                source: BackbonePeerPoolCandidateSource::Discovered,
                priority: crate::driver::BACKBONE_PEER_POOL_DISCOVERED_PRIORITY,
                discovery: Some(discovery),
            },
            active_id: None,
            failures: Vec::new(),
            consecutive_failures: 0,
            retry_after: None,
            cooldown_until: None,
            last_error: None,
            control: None,
        });
        Self::sort_backbone_peer_pool_candidates(pool);
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
        let Some(pool) = self.backbone_peer_pool.as_mut() else {
            return;
        };
        let now = time::now();
        pool.candidates.retain(|candidate| {
            if candidate.config.source == BackbonePeerPoolCandidateSource::Configured {
                return true;
            }
            let Some(discovery) = candidate.config.discovery.as_ref() else {
                return false;
            };
            if cached_discoveries
                .as_ref()
                .is_some_and(|cached| !cached.contains(&discovery.discovery_hash))
            {
                return false;
            }
            if candidate.active_id.is_some() {
                return true;
            }
            discovery.status != crate::discovery::DiscoveredStatus::Stale
                && now - discovery.last_heard <= crate::discovery::THRESHOLD_REMOVE
        });
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
    pub(super) fn discovered_backbone_peer_endpoint(
        iface: &crate::discovery::DiscoveredInterface,
    ) -> Option<(String, u16, String, BackbonePeerPoolDiscoveryCandidate)> {
        if !matches!(
            iface.interface_type.as_str(),
            "BackboneInterface" | "TCPServerInterface"
        ) {
            return None;
        }
        let remote = iface.reachable_on.as_ref()?;
        if !(crate::discovery::is_ip_address(remote) || crate::discovery::is_hostname(remote)) {
            return None;
        }
        let status = iface.compute_status(crate::time::now());
        if status == crate::discovery::DiscoveredStatus::Stale {
            return None;
        }
        Some((
            remote.clone(),
            iface.port.unwrap_or(4242),
            rns_core::encoding::hex(&iface.transport_id),
            BackbonePeerPoolDiscoveryCandidate {
                discovery_hash: iface.discovery_hash,
                status,
                hops: iface.hops,
                stamp_value: iface.stamp_value,
                last_heard: iface.last_heard,
                network_id: iface.network_id,
            },
        ))
    }

    #[cfg(feature = "iface-backbone")]
    pub(super) fn discovered_pool_candidate_name(
        iface: &crate::discovery::DiscoveredInterface,
    ) -> String {
        let hex = rns_core::encoding::hex(&iface.discovery_hash);
        format!("{} ({})", iface.name, &hex[..8])
    }

    #[cfg(feature = "iface-backbone")]
    pub(super) fn pool_candidate_matches_endpoint(
        candidate: &BackbonePeerPoolCandidateConfig,
        remote: &str,
        port: u16,
        transport_identity: Option<&str>,
    ) -> bool {
        candidate.client.target_host == remote && candidate.client.target_port == port
            || transport_identity.is_some_and(|identity| {
                candidate
                    .client
                    .transport_identity
                    .as_ref()
                    .is_some_and(|candidate_identity| {
                        candidate_identity.eq_ignore_ascii_case(identity)
                    })
            })
    }

    #[cfg(feature = "iface-backbone")]
    pub(super) fn sort_backbone_peer_pool_candidates(pool: &mut BackbonePeerPool) {
        pool.candidates
            .sort_by(|a, b| Self::candidate_pool_order(a).cmp(&Self::candidate_pool_order(b)));
    }

    #[cfg(feature = "iface-backbone")]
    pub(super) fn discovery_candidate_order(
        iface: &crate::discovery::DiscoveredInterface,
    ) -> (
        u8,
        u8,
        std::cmp::Reverse<rns_core::stamp::StampValue>,
        std::cmp::Reverse<u64>,
        [u8; 32],
    ) {
        (
            match iface.compute_status(crate::time::now()) {
                crate::discovery::DiscoveredStatus::Available => 0,
                crate::discovery::DiscoveredStatus::Unknown => 1,
                crate::discovery::DiscoveredStatus::Stale => 2,
            },
            iface.hops,
            std::cmp::Reverse(iface.stamp_value),
            std::cmp::Reverse((iface.last_heard * 1000.0).max(0.0) as u64),
            iface.discovery_hash,
        )
    }

    #[cfg(feature = "iface-backbone")]
    pub(super) fn candidate_discovery_order(
        candidate: &BackbonePeerPoolCandidate,
    ) -> (
        u8,
        u8,
        std::cmp::Reverse<rns_core::stamp::StampValue>,
        std::cmp::Reverse<u64>,
        [u8; 32],
    ) {
        if let Some(discovery) = candidate.config.discovery.as_ref() {
            (
                match discovery.status {
                    crate::discovery::DiscoveredStatus::Available => 0,
                    crate::discovery::DiscoveredStatus::Unknown => 1,
                    crate::discovery::DiscoveredStatus::Stale => 2,
                },
                discovery.hops,
                std::cmp::Reverse(discovery.stamp_value),
                std::cmp::Reverse((discovery.last_heard * 1000.0).max(0.0) as u64),
                discovery.discovery_hash,
            )
        } else {
            (
                0,
                0,
                std::cmp::Reverse(rns_core::stamp::StampValue::ZERO),
                std::cmp::Reverse(0),
                [0; 32],
            )
        }
    }

    #[cfg(feature = "iface-backbone")]
    pub(super) fn candidate_pool_order(
        candidate: &BackbonePeerPoolCandidate,
    ) -> BackboneCandidateOrder {
        let source_order = match candidate.config.source {
            BackbonePeerPoolCandidateSource::Configured => 0,
            BackbonePeerPoolCandidateSource::Discovered => 1,
        };
        let (status_order, hops, stamp, last_heard, discovery_hash) =
            Self::candidate_discovery_order(candidate);
        (
            std::cmp::Reverse(candidate.config.priority),
            source_order,
            status_order,
            hops,
            stamp,
            last_heard,
            discovery_hash,
        )
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
            // A full pool only makes room for a configured peer, and only by
            // evicting a discovered peer it outranks. Otherwise a configured
            // peer whose slot a discovered one took while it was reconnecting
            // would stay down until some other peer happened to disconnect.
            let evict = if active >= pool.settings.max_connected {
                if pool.candidates[index].config.source
                    != BackbonePeerPoolCandidateSource::Configured
                {
                    return;
                }
                let victim = pool
                    .candidates
                    .iter()
                    .enumerate()
                    .skip(index + 1)
                    .rev()
                    .find(|(_, candidate)| {
                        candidate.active_id.is_some()
                            && candidate.config.source
                                == BackbonePeerPoolCandidateSource::Discovered
                    })
                    .and_then(|(_, candidate)| candidate.active_id);
                let Some(victim) = victim else {
                    return;
                };
                Some(victim)
            } else {
                None
            };
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
        let pool = self.backbone_peer_pool.as_mut()?;
        let (index, candidate) = pool
            .candidates
            .iter_mut()
            .enumerate()
            .find(|(_, candidate)| candidate.active_id == Some(id))?;
        candidate.active_id = None;
        let control = candidate.control.take();
        let candidate_name = candidate.config.client.name.clone();
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
            if let Some(candidate) = pool.candidates.get_mut(index) {
                candidate.active_id = Some(config.client.interface_id);
                candidate.consecutive_failures = 0;
                candidate.retry_after = None;
                candidate.last_error = None;
                candidate.control = Some(control);
            }
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
        let interface_type_name = candidate.interface_type_name.clone();
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
            wants_tunnel: interface_type_name == "BackboneClientInterface",
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
                interface_type: interface_type_name,
                send_retry_at: None,
                send_retry_backoff: Duration::ZERO,
            },
        );
        Ok(control)
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
        let reconnect_wait = candidate
            .config
            .client
            .runtime
            .lock()
            .map(|runtime| runtime.reconnect_wait)
            .unwrap_or(crate::interface::backbone::RECONNECT_WAIT);
        if candidate.config.source == BackbonePeerPoolCandidateSource::Configured {
            // Configured peers are ones the operator asked for: like a
            // standalone Backbone client (and Python, which retries every
            // 5 s forever) keep retrying with a bounded backoff instead of
            // the long cooldown meant for discovered peers.
            let backoff = crate::interface::backbone::reconnect_backoff(
                reconnect_wait,
                candidate.consecutive_failures,
            );
            candidate.consecutive_failures = candidate.consecutive_failures.saturating_add(1);
            candidate.cooldown_until = None;
            candidate.retry_after = Some(now + backoff.as_secs_f64());
        } else if candidate.failures.len() >= pool.settings.failure_threshold {
            candidate.cooldown_until = Some(now + pool.settings.cooldown.as_secs_f64());
            candidate.retry_after = None;
        } else {
            candidate.retry_after = Some(now + reconnect_wait.as_secs_f64());
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
        self.backbone_peer_pool
            .as_ref()?
            .candidates
            .iter()
            .find(|candidate| candidate.active_id == Some(id))?
            .config
            .discovery
            .as_ref()
            .map(|discovery| discovery.network_id)
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
                    source: candidate.config.source.as_str().to_string(),
                    priority: candidate.config.priority,
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
                .runtime_config
                .backbone_peer_state
                .keys()
                .filter(|candidate| candidate.as_str() == name)
                .collect(),
            None => self.runtime_config.backbone_peer_state.keys().collect(),
        };
        names.sort();

        let mut entries = Vec::new();
        for name in names {
            if let Some(handle) = self.runtime_config.backbone_peer_state.get(name) {
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

    #[cfg(not(feature = "iface-backbone"))]
    pub(crate) fn list_backbone_peer_state(
        &self,
        _interface_name: Option<&str>,
    ) -> Vec<BackbonePeerStateEntry> {
        Vec::new()
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn list_backbone_interfaces(&self) -> Vec<crate::event::BackboneInterfaceEntry> {
        let mut entries: Vec<_> = self
            .runtime_config
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

    #[cfg(not(feature = "iface-backbone"))]
    pub(crate) fn list_backbone_interfaces(&self) -> Vec<crate::event::BackboneInterfaceEntry> {
        Vec::new()
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn clear_backbone_peer_state(
        &mut self,
        interface_name: &str,
        peer_ip: std::net::IpAddr,
    ) -> bool {
        self.runtime_config
            .backbone_peer_state
            .get(interface_name)
            .map(|handle| {
                let peer_cleared =
                    recover_mutex_guard(&handle.peer_state, "backbone peer state").clear(peer_ip);
                let flap_cleared =
                    recover_mutex_guard(&handle.fast_flap_state, "backbone fast-flap state")
                        .clear(peer_ip);
                peer_cleared || flap_cleared
            })
            .unwrap_or(false)
    }

    #[cfg(not(feature = "iface-backbone"))]
    pub(crate) fn clear_backbone_peer_state(
        &mut self,
        _interface_name: &str,
        _peer_ip: std::net::IpAddr,
    ) -> bool {
        false
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
        let capped_duration = self
            .runtime_config
            .backbone
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
        let Some(handle) = self.runtime_config.backbone_peer_state.get(interface_name) else {
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
