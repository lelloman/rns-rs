//! The steps of turning a node's parsed config into the settings it
//! starts with.

use super::*;

/// The node's config file, as read and parsed.
pub(super) struct ReadConfig {
    pub(super) config_file: std::path::PathBuf,
    pub(super) rns_config: config::RnsConfig,
    pub(super) link_mtu_discovery: bool,
}

/// Read and parse the config file, upstream's default one when there is
/// none (private nodes run on what they were given).
pub(super) fn read_config(config_dir: &Path, private: bool) -> io::Result<ReadConfig> {
    if !private {
        storage::ensure_config_file(config_dir)?;
    }
    let config_file = config_dir.join("config");
    let config_content = if config_file.exists() {
        std::fs::read_to_string(&config_file)?
    } else {
        String::new()
    };
    let rns_config = config::parse(&config_content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?;
    let link_mtu_discovery = config::parse_link_mtu_discovery(&config_content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?;
    Ok(ReadConfig {
        config_file,
        rns_config,
        link_mtu_discovery,
    })
}

/// Whether another process already serves the shared instance this config
/// shares, logging that this node attaches to it as a client.
#[cfg(feature = "iface-local")]
pub(super) fn shared_instance_already_running(rns_config: &config::RnsConfig) -> bool {
    if !rns_config.reticulum.share_instance {
        return false;
    }
    let shared = crate::shared_client::SharedClientConfig::from_reticulum(&rns_config.reticulum);
    if crate::interface::local::shared_instance_running(
        &shared.instance_name,
        shared.port,
        shared.use_af_unix,
    ) {
        log::info!(
            "Shared instance {} is already running, connecting to it as a client",
            shared.instance_name
        );
        return true;
    }
    false
}

/// The key of the shared instance's RPC server, derived from the persisted
/// transport identity as Python clients derive theirs, even when their
/// non-transport instance uses an ephemeral one.
pub(super) fn shared_rpc_auth_key(
    rns_config: &config::RnsConfig,
    identity: &Identity,
    private: bool,
) -> Option<[u8; 32]> {
    if !private && rns_config.reticulum.share_instance {
        #[allow(
            clippy::expect_used,
            reason = "the transport identity is always loaded from or created as a private key"
        )]
        let key = identity
            .get_private_key()
            .expect("transport identity has private key");
        Some(crate::rpc::derive_auth_key(&key))
    } else {
        None
    }
}

/// The settings of runtime interface management, unless the node is
/// private or the config disables it.
pub(super) fn interface_management_config(
    rns_config: &config::RnsConfig,
    config_file: &Path,
    paths: &storage::StoragePaths,
    initial_ids: HashMap<String, rns_core::transport::types::InterfaceId>,
    private: bool,
    underlay_mark: Option<u32>,
) -> Option<InterfaceManagementConfig> {
    if private || !rns_config.reticulum.enable_interface_management {
        None
    } else {
        Some(InterfaceManagementConfig {
            config_file: config_file.to_path_buf(),
            storage_dir: paths.storage.clone(),
            initial_ids,
            queue_capacity: rns_config.reticulum.interface_writer_queue_capacity,
            transport_enabled: rns_config.reticulum.enable_transport,
            static_transport_identity: rns_config.reticulum.static_transport_identity,
            underlay_mark: underlay_mark.or(rns_config.reticulum.underlay_mark),
        })
    }
}

/// What the node config takes besides the config's own settings: what
/// startup loaded from storage and parsed out of the config before.
pub(super) struct NodeConfigParts<'a> {
    pub(super) config_dir: &'a Path,
    pub(super) private: bool,
    pub(super) underlay_mark: Option<u32>,
    pub(super) identity: Identity,
    pub(super) network_identity: Option<Identity>,
    pub(super) cache_dir: std::path::PathBuf,
    pub(super) ratchet_store: Arc<dyn storage::RatchetStore>,
    pub(super) interfaces: Vec<InterfaceConfig>,
    pub(super) mgmt_allowed: Vec<[u8; 16]>,
    pub(super) probe_addrs: Vec<std::net::SocketAddr>,
    pub(super) probe_protocol: rns_core::holepunch::ProbeProtocol,
    pub(super) upstream_policy: bool,
    pub(super) bootstrap_interfaces: Vec<String>,
}

/// The node config of `rns_config`.
pub(super) fn node_config_from(
    rns_config: &config::RnsConfig,
    parts: NodeConfigParts,
) -> NodeConfig {
    let NodeConfigParts {
        config_dir,
        private,
        underlay_mark,
        identity,
        network_identity,
        cache_dir,
        ratchet_store,
        interfaces,
        mgmt_allowed,
        probe_addrs,
        probe_protocol,
        upstream_policy,
        bootstrap_interfaces,
    } = parts;
    #[cfg(not(feature = "hooks"))]
    let _ = config_dir;
    let reticulum = &rns_config.reticulum;
    NodeConfig {
        transport_enabled: reticulum.enable_transport,
        static_transport_identity: reticulum.static_transport_identity,
        local_hops_delta: reticulum.local_hops_delta,
        identity: Some(identity),
        network_identity,
        share_instance: !private && reticulum.share_instance,
        instance_name: reticulum.instance_name.clone(),
        shared_instance_port: reticulum.shared_instance_port,
        rpc_port: reticulum.instance_control_port,
        cache_dir: Some(cache_dir),
        ratchet_store: Some(ratchet_store),
        ratchet_expiry: Duration::from_secs(reticulum.ratchet_expiry),
        management: management_config(reticulum, private, mgmt_allowed),
        probe_port: reticulum.probe_port,
        probe_addrs,
        probe_protocol,
        direct_connect_policy: reticulum.direct_connect_policy,
        direct_connect_allow_private_endpoints: reticulum.direct_connect_allow_private_endpoints,
        direct_connect_allowed_identities: reticulum.direct_connect_allowed_identities.clone(),
        direct_connect_reupgrade: reticulum.direct_connect_reupgrade,
        probe_rate_limit: reticulum.probe_rate_limit,
        device: reticulum.device.clone(),
        underlay_mark: underlay_mark.or(reticulum.underlay_mark),
        hooks: if private {
            Vec::new()
        } else {
            rns_config.hooks.clone()
        },
        discover_interfaces: reticulum.discover_interfaces,
        discovery: DiscoverySettings {
            interface_discovery_sources: reticulum.interface_discovery_sources.clone(),
            autoconnect_discovered_interfaces: if upstream_policy {
                let (target, warnings) = upstream_autoconnect_target(
                    reticulum.autoconnect_discovered_interfaces,
                    reticulum.autoconnect_discovered_interfaces_caps_disabled,
                );
                for line in warnings {
                    log::warn!("{line}");
                }
                target
            } else {
                0
            },
            bootstrap_interfaces: if upstream_policy {
                bootstrap_interfaces
            } else {
                Vec::new()
            },
        },
        shared_instance: SharedInstanceSettings {
            use_af_unix: !reticulum.shared_instance_tcp,
            rpc_key: reticulum.rpc_key,
            force_bitrate: reticulum.force_shared_instance_bitrate,
        },
        autoconnect_interface_mode: reticulum
            .autoconnect_interface_mode
            .as_deref()
            .and_then(parse_optional_interface_mode),
        autoconnect_interface_gravity: reticulum.autoconnect_interface_gravity,
        autoconnect_announces_to_internal: reticulum.autoconnect_announces_to_internal,
        autoconnect_unverified_implementations: reticulum.autoconnect_unverified_implementations,
        discovery_required_value: reticulum.required_discovery_value,
        respond_to_probes: reticulum.respond_to_probes,
        use_implicit_proof: reticulum.use_implicit_proof,
        prefer_shorter_path: reticulum.prefer_shorter_path,
        max_paths_per_destination: reticulum.max_paths_per_destination,
        unresponsive_path_recovery: reticulum.unresponsive_path_recovery,
        packet_hashlist_max_entries: reticulum.packet_hashlist_max_entries,
        packet_hashlist_allocation: reticulum.packet_hashlist_allocation,
        max_discovery_pr_tags: reticulum.max_discovery_pr_tags,
        max_path_destinations: reticulum.max_path_destinations,
        max_tunnel_destinations_total: reticulum.max_tunnel_destinations_total,
        known_destinations_ttl: Duration::from_secs(reticulum.known_destinations_ttl),
        known_destinations_max_entries: reticulum.known_destinations_max_entries,
        announce_table_ttl: Duration::from_secs(reticulum.announce_table_ttl),
        announce_table_max_bytes: reticulum.announce_table_max_bytes,
        driver_event_queue_capacity: reticulum.driver_event_queue_capacity,
        interface_writer_queue_capacity: reticulum.interface_writer_queue_capacity,
        announce_rate_defaults: AnnounceRateDefaults {
            target: reticulum.default_ar_target,
            penalty: reticulum.default_ar_penalty,
            grace: reticulum.default_ar_grace,
        },
        ingress_control_defaults: ingress_control_defaults(reticulum),
        #[cfg(feature = "iface-backbone")]
        backbone_peer_pool: backbone_peer_pool_settings(reticulum, upstream_policy),
        announce_sig_cache_enabled: reticulum.announce_sig_cache_enabled,
        announce_sig_cache_max_entries: reticulum.announce_sig_cache_max_entries,
        announce_sig_cache_ttl: Duration::from_secs(reticulum.announce_sig_cache_ttl),
        interfaces,
        registry: None,
        panic_on_interface_error: private || reticulum.panic_on_interface_error,
        link_proof_verify_threads: Default::default(),
        stamps: rns_config.stamps.clone(),
        #[cfg(feature = "hooks")]
        provider_bridge: provider_bridge_config(reticulum, config_dir, private),
    }
}

/// The remote management settings; a private node has none.
fn management_config(
    reticulum: &config::ReticulumSection,
    private: bool,
    mgmt_allowed: Vec<[u8; 16]>,
) -> crate::management::ManagementConfig {
    if private {
        crate::management::ManagementConfig::default()
    } else {
        crate::management::ManagementConfig {
            enable_remote_management: reticulum.enable_remote_management,
            remote_management_allowed: mgmt_allowed,
            publish_blackhole: reticulum.publish_blackhole,
            blackhole_sources: reticulum.blackhole_sources.clone(),
            blackhole_update_interval: reticulum.blackhole_update_interval,
        }
    }
}

/// The ingress control interfaces get by default.
fn ingress_control_defaults(
    reticulum: &config::ReticulumSection,
) -> rns_core::transport::types::IngressControlConfig {
    rns_core::transport::types::IngressControlConfig {
        enabled: true,
        egress_enabled: reticulum.default_egress_control,
        max_held_announces: reticulum.default_ic_max_held_announces,
        burst_freq_new: reticulum.default_ic_burst_freq_new,
        burst_freq: reticulum.default_ic_burst_freq,
        pr_burst_freq_new: reticulum.default_ic_pr_burst_freq_new,
        pr_burst_freq: reticulum.default_ic_pr_burst_freq,
        egress_pr_freq: reticulum.default_ec_pr_freq,
        new_time: reticulum.default_ic_new_time,
        burst_hold: reticulum.default_ic_burst_hold,
        burst_penalty: reticulum.default_ic_burst_penalty,
        held_release_interval: reticulum.default_ic_held_release_interval,
    }
}

/// The Backbone peer pool settings, when the pool autoconnect policy
/// keeps connected peers.
#[cfg(feature = "iface-backbone")]
fn backbone_peer_pool_settings(
    reticulum: &config::ReticulumSection,
    upstream_policy: bool,
) -> Option<BackbonePeerPoolSettings> {
    if !upstream_policy && reticulum.backbone_peer_pool_max_connected > 0 {
        Some(BackbonePeerPoolSettings {
            max_connected: reticulum.backbone_peer_pool_max_connected,
            failure_threshold: reticulum.backbone_peer_pool_failure_threshold,
            failure_window: Duration::from_secs(reticulum.backbone_peer_pool_failure_window),
            cooldown: Duration::from_secs(reticulum.backbone_peer_pool_cooldown),
        })
    } else {
        None
    }
}

/// The provider bridge settings, when the bridge is enabled on a node that
/// is not private.
#[cfg(feature = "hooks")]
fn provider_bridge_config(
    reticulum: &config::ReticulumSection,
    config_dir: &Path,
    private: bool,
) -> Option<crate::provider_bridge::ProviderBridgeConfig> {
    if !private && reticulum.provider_bridge {
        Some(crate::provider_bridge::ProviderBridgeConfig {
            enabled: true,
            socket_path: reticulum
                .provider_socket_path
                .as_ref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| config_dir.join("provider.sock")),
            queue_max_events: reticulum.provider_queue_max_events,
            queue_max_bytes: reticulum.provider_queue_max_bytes,
            overflow_policy: match reticulum.provider_overflow_policy.as_str() {
                "drop_oldest" => crate::provider_bridge::OverflowPolicy::DropOldest,
                _ => crate::provider_bridge::OverflowPolicy::DropNewest,
            },
            node_instance: reticulum.instance_name.clone(),
        })
    } else {
        None
    }
}

/// The driver and announce queue settings of `rns_config`.
pub(super) fn queue_config_from(
    rns_config: &config::RnsConfig,
    rpc_auth_key: Option<[u8; 32]>,
    link_mtu_discovery: bool,
) -> NodeQueueConfig {
    let reticulum = &rns_config.reticulum;
    NodeQueueConfig {
        rpc_auth_key,
        announce_max_entries: reticulum.announce_queue_max_entries,
        announce_max_interfaces: reticulum.announce_queue_max_interfaces,
        announce_max_bytes: reticulum.announce_queue_max_bytes,
        announce_ttl_secs: reticulum.announce_queue_ttl as f64,
        announce_overflow_policy: match reticulum.announce_queue_overflow_policy.as_str() {
            "drop_newest" => AnnounceQueueOverflowPolicy::DropNewest,
            "drop_oldest" => AnnounceQueueOverflowPolicy::DropOldest,
            _ => AnnounceQueueOverflowPolicy::DropWorst,
        },
        inbound_capacities: reticulum.inbound_queue_capacities,
        link_mtu_discovery,
        filter: rns_config.filter.clone(),
        hop_limiter: reticulum.hop_limiter,
        destination_type_names: Default::default(),
    }
}

/// Above this many auto-connected interfaces upstream warns (aecc1547
/// `__autoconnect_warn`).
const AUTOCONNECT_WARN: usize = 6;
/// Upstream caps the auto-connected interfaces at this many (aecc1547
/// `__autoconnect_cap`).
const AUTOCONNECT_CAP: usize = 12;

/// The number of discovered interfaces to auto-connect, and the warnings
/// upstream logs for it, line by line (aecc1547): above
/// [`AUTOCONNECT_CAP`] the count is capped, and above [`AUTOCONNECT_WARN`]
/// it is called excessive, unless the caps are disabled.
fn upstream_autoconnect_target(configured: usize, caps_disabled: bool) -> (usize, Vec<String>) {
    let mut target = configured;
    let mut warnings = Vec::new();
    if caps_disabled {
        return (target, warnings);
    }
    if target > AUTOCONNECT_CAP {
        target = AUTOCONNECT_CAP;
        warnings.extend([
            String::new(),
            format!("Auto-connect interface target was capped to {target}"),
            "Using large numbers of auto-connected interfaces will not lead to better".into(),
            "connectivity or redundancy. If you really know what you're doing, and are".into(),
            "certain that you need this, you will also know how to get around this check.".into(),
        ]);
    }
    if target > AUTOCONNECT_WARN {
        warnings.extend([
            String::new(),
            format!("You have configured more than {AUTOCONNECT_WARN} auto-connect interfaces."),
            "In almost all situations, this is excessive, and should be avoided.".into(),
            "For a normal home or office node, 2-3 autoconnects will be sufficient.".into(),
            String::new(),
            "If you're running a fast, well-connected transport node that can actually".into(),
            "provide additional capacity and transport to the network, you can consider".into(),
            format!(
                "raising this number to {}-{}. Only in the rarest of cases will going beyond",
                AUTOCONNECT_WARN,
                AUTOCONNECT_WARN + 3
            ),
            "this actually provide any benefit.".into(),
            String::new(),
        ]);
    }
    (target, warnings)
}

impl RnsNode {
    /// Hand the node the known destinations loaded from storage, with the
    /// stamp store beside them, and start flushing them back.
    pub(super) fn adopt_known_destinations(
        &mut self,
        known_destinations_path: &Path,
        known_destinations_store: Option<Arc<crate::storage_sqlite::KnownDestinationsStore>>,
        known_destinations: HashMap<[u8; 16], storage::KnownDestination>,
        storage_dir: &Path,
    ) {
        self.known_destinations_path = Some(known_destinations_path.to_path_buf());
        self.known_destinations_store = known_destinations_store;
        let flushed: std::collections::HashMap<[u8; 16], storage::KnownDestination> =
            known_destinations.clone().into_iter().collect();
        self.set_stamp_store(crate::stamps::DestinationStampStore::new(storage_dir));
        self.restore_known_destinations(known_destinations);
        self.start_known_destinations_flush(flushed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autoconnect_count_is_capped_unless_caps_are_disabled() {
        let (target, warnings) = upstream_autoconnect_target(20, false);
        assert_eq!(target, 12);
        assert_eq!(
            warnings[1],
            "Auto-connect interface target was capped to 12"
        );
        assert!(warnings
            .contains(&"You have configured more than 6 auto-connect interfaces.".to_string()));
        assert!(warnings.contains(
            &"raising this number to 6-9. Only in the rarest of cases will going beyond"
                .to_string()
        ));
        assert_eq!(warnings.len(), 5 + 10);

        assert_eq!(upstream_autoconnect_target(20, true), (20, Vec::new()));

        let (target, warnings) = upstream_autoconnect_target(7, false);
        assert_eq!(target, 7);
        assert_eq!(warnings.len(), 10);
        assert_eq!(
            warnings[1],
            "You have configured more than 6 auto-connect interfaces."
        );

        assert_eq!(upstream_autoconnect_target(6, false), (6, Vec::new()));
        assert_eq!(upstream_autoconnect_target(0, false), (0, Vec::new()));
    }
}
