//! The backbone peer pool: its settings and candidates.

use super::*;

#[cfg(feature = "iface-backbone")]
pub(super) type BackboneCandidateOrder = (
    std::cmp::Reverse<u8>,
    u8,
    u8,
    u8,
    std::cmp::Reverse<rns_core::stamp::StampValue>,
    std::cmp::Reverse<u64>,
    [u8; 32],
);

#[cfg(feature = "iface-backbone")]
/// Limits of the backbone peer pool, from the `backbone_peer_pool_*` options.
#[derive(Debug, Clone)]
pub struct BackbonePeerPoolSettings {
    /// Most outbound pool connections active at once.
    pub max_connected: usize,
    /// Failures within `failure_window` that put a discovered peer in cooldown.
    pub failure_threshold: usize,
    /// How long a failure counts toward `failure_threshold`.
    pub failure_window: Duration,
    /// How long a discovered peer stays in cooldown before it is retried.
    pub cooldown: Duration,
}

#[cfg(feature = "iface-backbone")]
pub(crate) const BACKBONE_PEER_POOL_CONFIGURED_DEFAULT_PRIORITY: u8 = 60;

#[cfg(feature = "iface-backbone")]
pub(crate) const BACKBONE_PEER_POOL_DISCOVERED_PRIORITY: u8 = 40;

#[cfg(feature = "iface-backbone")]
#[derive(Clone)]
pub(crate) struct BackbonePeerPoolCandidateConfig {
    pub(crate) client: BackboneClientConfig,
    pub(crate) mode: u8,
    pub(crate) gravity: i64,
    pub(crate) recursive_prs: bool,
    pub(crate) announces_from_internal: bool,
    pub(crate) announces_to_internal: Option<bool>,
    pub(crate) ingress_control: rns_core::transport::types::IngressControlConfig,
    pub(crate) stamp_costs: rns_core::transport::types::InterfaceStampCosts,
    pub(crate) ifac_runtime: IfacRuntimeConfig,
    pub(crate) ifac_enabled: bool,
    pub(crate) interface_kind: crate::interface::InterfaceKind,
    pub(crate) source: BackbonePeerPoolCandidateSource,
    pub(crate) priority: u8,
    pub(crate) discovery: Option<BackbonePeerPoolDiscoveryCandidate>,
}

#[cfg(feature = "iface-backbone")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackbonePeerPoolCandidateSource {
    Configured,
    Discovered,
}

#[cfg(feature = "iface-backbone")]
impl BackbonePeerPoolCandidateSource {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Discovered => "discovered",
        }
    }
}

#[cfg(feature = "iface-backbone")]
#[derive(Debug, Clone)]
pub(crate) struct BackbonePeerPoolDiscoveryCandidate {
    pub(crate) discovery_hash: [u8; 32],
    pub(crate) status: crate::discovery::DiscoveredStatus,
    pub(crate) hops: u8,
    pub(crate) stamp_value: rns_core::stamp::StampValue,
    pub(crate) last_heard: f64,
    /// The network that announced it (upstream's `network_id`).
    pub(crate) network_id: [u8; 16],
}

#[cfg(feature = "iface-backbone")]
pub(super) struct BackbonePeerPool {
    pub(super) settings: BackbonePeerPoolSettings,
    pub(super) candidates: Vec<BackbonePeerPoolCandidate>,
}

#[cfg(feature = "iface-backbone")]
pub(super) struct BackbonePeerPoolCandidate {
    pub(super) config: BackbonePeerPoolCandidateConfig,
    pub(super) active_id: Option<InterfaceId>,
    pub(super) failures: Vec<f64>,
    /// Failed attempts since the last successful connect; drives the
    /// reconnect backoff of configured peers.
    pub(super) consecutive_failures: u32,
    pub(super) retry_after: Option<f64>,
    pub(super) cooldown_until: Option<f64>,
    pub(super) last_error: Option<String>,
    /// Stops the active connection's reader when the pool evicts it.
    pub(super) control: Option<crate::interface::ListenerControl>,
}

/// Where a discovered interface can be reached, and what the pool keeps
/// of its discovery.
pub(super) struct DiscoveredEndpoint {
    pub(super) remote: String,
    pub(super) port: u16,
    pub(super) transport_identity: String,
    pub(super) discovery: BackbonePeerPoolDiscoveryCandidate,
}

/// How the pool sets up a candidate it takes from a discovery.
pub(super) struct DiscoveredCandidateSettings {
    pub(super) mode: u8,
    pub(super) gravity: i64,
    pub(super) announces_to_internal: Option<bool>,
    pub(super) ingress_control: rns_core::transport::types::IngressControlConfig,
}

impl BackbonePeerPool {
    pub(super) fn new(
        settings: BackbonePeerPoolSettings,
        candidates: Vec<BackbonePeerPoolCandidateConfig>,
    ) -> Self {
        let mut pool = Self {
            settings,
            candidates: candidates
                .into_iter()
                .map(BackbonePeerPoolCandidate::standby)
                .collect(),
        };
        pool.sort_candidates();
        pool
    }

    /// Whether a configured candidate already connects to this endpoint.
    pub(super) fn has_configured_endpoint(&self, endpoint: &DiscoveredEndpoint) -> bool {
        self.candidates.iter().any(|candidate| {
            candidate.config.source == BackbonePeerPoolCandidateSource::Configured
                && Self::pool_candidate_matches_endpoint(
                    &candidate.config,
                    &endpoint.remote,
                    endpoint.port,
                    Some(&endpoint.transport_identity),
                )
        })
    }

    /// Update the discovered candidate for this discovery or endpoint, or
    /// add one with an interface id taken from `next_dynamic_id`.
    pub(super) fn upsert_discovered(
        &mut self,
        iface: crate::discovery::DiscoveredInterface,
        endpoint: DiscoveredEndpoint,
        settings: DiscoveredCandidateSettings,
        next_dynamic_id: &AtomicU64,
    ) {
        let DiscoveredEndpoint {
            remote,
            port,
            transport_identity,
            discovery,
        } = endpoint;
        if let Some(candidate) = self.candidates.iter_mut().find(|candidate| {
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
            candidate.config.mode = settings.mode;
            candidate.config.gravity = settings.gravity;
            candidate.config.announces_to_internal = settings.announces_to_internal;
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
            self.sort_candidates();
            return;
        }

        let id = InterfaceId(next_dynamic_id.fetch_add(1, Ordering::Relaxed));
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
        self.candidates.push(BackbonePeerPoolCandidate::standby(
            BackbonePeerPoolCandidateConfig {
                client,
                mode: settings.mode,
                gravity: settings.gravity,
                recursive_prs: false,
                announces_from_internal: true,
                announces_to_internal: settings.announces_to_internal,
                ingress_control: settings.ingress_control,
                stamp_costs: Default::default(),
                ifac_runtime,
                ifac_enabled,
                interface_kind: crate::interface::InterfaceKind::Backbone,
                source: BackbonePeerPoolCandidateSource::Discovered,
                priority: BACKBONE_PEER_POOL_DISCOVERED_PRIORITY,
                discovery: Some(discovery),
            },
        ));
        self.sort_candidates();
    }

    /// Drop the discovered candidates whose discovery went stale or left
    /// the discovery cache, `cached_discoveries` when it could be read.
    pub(super) fn cull_stale_discovered(
        &mut self,
        cached_discoveries: Option<std::collections::HashSet<[u8; 32]>>,
    ) {
        let now = time::now();
        self.candidates.retain(|candidate| {
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

    /// End the cooldowns that ran out by `now`.
    pub(super) fn expire_cooldowns(&mut self, now: f64) {
        for candidate in &mut self.candidates {
            if candidate.cooldown_until.is_some_and(|until| until <= now) {
                candidate.cooldown_until = None;
                candidate.retry_after = None;
            }
        }
    }

    /// The next candidate to connect, with the active member to evict for
    /// it when the pool is full, or `None` when no candidate should
    /// connect now.
    pub(super) fn next_to_start(&self, now: f64) -> Option<(usize, Option<InterfaceId>)> {
        let active = self
            .candidates
            .iter()
            .filter(|candidate| candidate.active_id.is_some())
            .count();
        let index = self.candidates.iter().position(|candidate| {
            candidate.active_id.is_none()
                && candidate
                    .cooldown_until
                    .map(|until| until <= now)
                    .unwrap_or(true)
                && candidate
                    .retry_after
                    .map(|retry_after| retry_after <= now)
                    .unwrap_or(true)
        })?;
        // A full pool only makes room for a configured peer, and only by
        // evicting a discovered peer it outranks. Otherwise a configured
        // peer whose slot a discovered one took while it was reconnecting
        // would stay down until some other peer happened to disconnect.
        if active < self.settings.max_connected {
            return Some((index, None));
        }
        if self.candidates[index].config.source != BackbonePeerPoolCandidateSource::Configured {
            return None;
        }
        let victim = self
            .candidates
            .iter()
            .enumerate()
            .skip(index + 1)
            .rev()
            .find(|(_, candidate)| {
                candidate.active_id.is_some()
                    && candidate.config.source == BackbonePeerPoolCandidateSource::Discovered
            })
            .and_then(|(_, candidate)| candidate.active_id)?;
        Some((index, Some(victim)))
    }

    /// The candidate at `index` connected as interface `id`.
    pub(super) fn mark_started(
        &mut self,
        index: usize,
        id: InterfaceId,
        control: crate::interface::ListenerControl,
    ) {
        if let Some(candidate) = self.candidates.get_mut(index) {
            candidate.active_id = Some(id);
            candidate.consecutive_failures = 0;
            candidate.retry_after = None;
            candidate.last_error = None;
            candidate.control = Some(control);
        }
    }

    /// Mark the candidate active as interface `id` inactive. Returns its
    /// index, the control of its connection and its name.
    pub(super) fn take_member(
        &mut self,
        id: InterfaceId,
    ) -> Option<(usize, Option<crate::interface::ListenerControl>, String)> {
        let (index, candidate) = self
            .candidates
            .iter_mut()
            .enumerate()
            .find(|(_, candidate)| candidate.active_id == Some(id))?;
        candidate.active_id = None;
        let control = candidate.control.take();
        Some((index, control, candidate.config.client.name.clone()))
    }

    pub(super) fn record_failure(&mut self, index: usize, error: String) {
        let Some(candidate) = self.candidates.get_mut(index) else {
            return;
        };
        let now = time::now();
        let window = self.settings.failure_window.as_secs_f64();
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
        } else if candidate.failures.len() >= self.settings.failure_threshold {
            candidate.cooldown_until = Some(now + self.settings.cooldown.as_secs_f64());
            candidate.retry_after = None;
        } else {
            candidate.retry_after = Some(now + reconnect_wait.as_secs_f64());
        }
    }

    /// The network a member connected from a discovery was announced by.
    pub(super) fn discovery_network(&self, id: InterfaceId) -> Option<[u8; 16]> {
        self.candidates
            .iter()
            .find(|candidate| candidate.active_id == Some(id))?
            .config
            .discovery
            .as_ref()
            .map(|discovery| discovery.network_id)
    }

    pub(super) fn status(&self, interfaces: &Interfaces) -> BackbonePeerPoolStatus {
        let now = time::now();
        let mut active_count = 0usize;
        let mut standby_count = 0usize;
        let mut cooldown_count = 0usize;
        let members = self
            .candidates
            .iter()
            .map(|candidate| {
                let (state, cooldown_remaining_seconds) =
                    if let Some(until) = candidate.cooldown_until {
                        cooldown_count += 1;
                        ("cooldown".to_string(), Some((until - now).max(0.0)))
                    } else if let Some(id) = candidate.active_id {
                        active_count += 1;
                        let online = interfaces
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
        BackbonePeerPoolStatus {
            max_connected: self.settings.max_connected,
            active_count,
            standby_count,
            cooldown_count,
            members,
        }
    }

    pub(super) fn discovered_backbone_peer_endpoint(
        iface: &crate::discovery::DiscoveredInterface,
    ) -> Option<DiscoveredEndpoint> {
        use crate::interface::InterfaceKind;

        if !matches!(
            InterfaceKind::from_type_name(&iface.interface_type),
            Some(InterfaceKind::Backbone | InterfaceKind::TcpServer)
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
        Some(DiscoveredEndpoint {
            remote: remote.clone(),
            port: iface.port.unwrap_or(4242),
            transport_identity: rns_core::encoding::hex(&iface.transport_id),
            discovery: BackbonePeerPoolDiscoveryCandidate {
                discovery_hash: iface.discovery_hash,
                status,
                hops: iface.hops,
                stamp_value: iface.stamp_value,
                last_heard: iface.last_heard,
                network_id: iface.network_id,
            },
        })
    }

    pub(super) fn discovered_pool_candidate_name(
        iface: &crate::discovery::DiscoveredInterface,
    ) -> String {
        let hex = rns_core::encoding::hex(&iface.discovery_hash);
        format!("{} ({})", iface.name, &hex[..8])
    }

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

    fn sort_candidates(&mut self) {
        self.candidates
            .sort_by(|a, b| Self::candidate_pool_order(a).cmp(&Self::candidate_pool_order(b)));
    }

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
}

impl BackbonePeerPoolCandidate {
    /// A candidate that is not connected.
    fn standby(config: BackbonePeerPoolCandidateConfig) -> Self {
        Self {
            config,
            active_id: None,
            failures: Vec::new(),
            consecutive_failures: 0,
            retry_after: None,
            cooldown_until: None,
            last_error: None,
            control: None,
        }
    }
}
