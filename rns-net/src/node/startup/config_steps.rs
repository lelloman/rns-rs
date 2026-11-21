//! The steps of reading a node's config and storage.

use super::*;

/// What the node's known destination storage holds when it starts.
pub(super) struct KnownDestinationsStorage {
    pub(super) destinations: HashMap<[u8; 16], storage::KnownDestination>,
    pub(super) ratchet_store: Arc<dyn storage::RatchetStore>,
    /// The known destinations database, when it could be opened.
    pub(super) database: Option<Arc<crate::storage_sqlite::KnownDestinationsStore>>,
}

/// The known destinations and the ratchet store: from the known
/// destinations database, into which legacy storage is imported once, or
/// from legacy storage when the database cannot be opened.
pub(super) fn open_known_destinations(
    paths: &storage::StoragePaths,
    known_destinations_path: &Path,
    ratchet_expiry: u64,
) -> KnownDestinationsStorage {
    let known_destinations_db = crate::storage_sqlite::default_path(&paths.storage);
    match crate::storage_sqlite::KnownDestinationsStore::open(&known_destinations_db) {
        Ok(store) => {
            let store = Arc::new(store);
            let started = std::time::Instant::now();
            let mut destinations: std::collections::HashMap<[u8; 16], storage::KnownDestination> =
                store
                    .load_all()
                    .map(|entries| entries.into_iter().collect())
                    .unwrap_or_else(|err| {
                        log::warn!("failed to load known destinations from database: {}", err);
                        Default::default()
                    });
            if destinations.is_empty() && known_destinations_path.is_file() {
                match store.import_legacy(known_destinations_path) {
                    Ok(imported) if imported > 0 => {
                        log::info!(
                            "Imported {} known destinations from legacy storage into the known destinations database",
                            imported
                        );
                        let _ = std::fs::rename(
                            known_destinations_path,
                            known_destinations_path.with_extension("imported"),
                        );
                        destinations = store
                            .load_all()
                            .map(|entries| entries.into_iter().collect())
                            .unwrap_or_default();
                    }
                    Ok(_) => {}
                    Err(err) => {
                        log::warn!("could not import legacy known destinations: {}", err)
                    }
                }
            }
            log::info!(
                "Loaded {} known destinations from storage in {}",
                destinations.len(),
                crate::logging::prettyshorttime(started.elapsed().as_secs_f64())
            );
            let known_destination_hashes: HashSet<[u8; 16]> =
                destinations.keys().copied().collect();
            if let Err(err) = store.import_legacy_ratchets(
                &paths.ratchets,
                time::now() - ratchet_expiry as f64,
                &known_destination_hashes,
            ) {
                log::warn!("could not import legacy ratchets: {}", err);
            }
            KnownDestinationsStorage {
                destinations,
                ratchet_store: store.clone(),
                database: Some(store),
            }
        }
        Err(err) => {
            log::warn!(
                "could not initialise known destinations database, falling back to legacy storage: {}",
                err
            );
            let destinations = match storage::load_known_destinations(known_destinations_path) {
                Ok(destinations) => destinations,
                Err(err) if err.kind() == io::ErrorKind::NotFound => Default::default(),
                Err(err) => {
                    log::warn!("failed to load known destinations: {}", err);
                    Default::default()
                }
            };
            KnownDestinationsStorage {
                destinations,
                ratchet_store: Arc::new(storage::FsRatchetStore::new(paths.ratchets.clone())),
                database: None,
            }
        }
    }
}

/// The transport identity. It lives in storage/transport_identity, as
/// upstream keeps it, so a config directory keeps its transport identity
/// whichever implementation runs it. Directories written before only hold
/// storage/identities/identity: carry that over, or create one when
/// neither exists.
pub(super) fn load_transport_identity(paths: &storage::StoragePaths) -> io::Result<Identity> {
    let transport_identity_path = storage::transport_identity_path(paths);
    if transport_identity_path.exists() {
        let identity = storage::load_identity(&transport_identity_path)?;
        log::info!("Loaded Transport Identity from storage");
        return Ok(identity);
    }
    let node_identity_path = paths.identities.join("identity");
    let identity = if node_identity_path.exists() {
        let identity = storage::load_identity(&node_identity_path)?;
        log::info!("Loaded Transport Identity from storage");
        identity
    } else {
        log::info!("No valid Transport Identity in storage, creating...");
        let identity = create_identity();
        storage::save_identity(&identity, &node_identity_path)?;
        identity
    };
    storage::save_identity(&identity, &transport_identity_path)?;
    Ok(identity)
}

/// The configs of the enabled interfaces in `rns_config`, and the ids they
/// start with. An interface whose config is wrong is skipped with a warning,
/// or fails the start on a private node, which runs only what it was given.
pub(super) fn build_interface_configs(
    rns_config: &config::RnsConfig,
    paths: &storage::StoragePaths,
    private: bool,
) -> io::Result<(
    Vec<InterfaceConfig>,
    HashMap<String, rns_core::transport::types::InterfaceId>,
)> {
    let registry = crate::interface::registry::InterfaceRegistry::with_builtins();
    let mut interface_configs = Vec::new();
    let mut initial_ids = HashMap::new();
    let mut next_id_val = 1u64;

    for iface in &rns_config.interfaces {
        if !iface.enabled {
            continue;
        }

        let iface_id = rns_core::transport::types::InterfaceId(next_id_val);
        next_id_val += 1;

        let factory = match registry.get(&iface.interface_type) {
            Some(f) => f,
            None => {
                if private {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "unsupported enabled interface type '{}' for '{}'",
                            iface.interface_type, iface.name
                        ),
                    ));
                }
                log::warn!(
                    "Unsupported interface type '{}' for '{}'",
                    iface.interface_type,
                    iface.name,
                );
                continue;
            }
        };

        let mut iface_mode = parse_interface_mode(&iface.mode);

        let discoverable = discoverable_on_instance(
            &iface.name,
            iface
                .params
                .get("discoverable")
                .and_then(|value| config::parse_bool_pub(value))
                .unwrap_or(false),
            rns_config.reticulum.enable_transport,
            rns_config.reticulum.static_transport_identity,
        );
        let ignore_config_warnings = iface
            .params
            .get("ignore_config_warnings")
            .and_then(|value| config::parse_bool_pub(value))
            .unwrap_or(false);
        let normalized_mode = normalize_discovery_mode(
            &iface.interface_type,
            iface_mode,
            discoverable,
            ignore_config_warnings,
        );
        if normalized_mode != iface_mode {
            log::info!(
                "Interface '{}' has discovery enabled, auto-configuring mode to {}",
                iface.name,
                if normalized_mode == rns_core::constants::MODE_ACCESS_POINT {
                    "ACCESS_POINT"
                } else {
                    "GATEWAY"
                }
            );
            iface_mode = normalized_mode;
        }

        let default_ifac_size = factory.default_ifac_size();
        let ifac_config = extract_ifac_config(&iface.params, default_ifac_size);
        let discovery_config = discoverable
            .then(|| extract_discovery_config(&iface.name, &iface.interface_type, &iface.params))
            .flatten();
        let ingress_control =
            match parse_ingress_control_config(&iface.interface_type, &iface.params) {
                Ok(config) => config,
                Err(e) => {
                    if private {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid ingress control for '{}': {e}", iface.name),
                        ));
                    }
                    log::warn!(
                        "Failed to parse ingress control config for '{}': {}",
                        iface.name,
                        e
                    );
                    continue;
                }
            };
        let stamp_costs = match parse_interface_stamp_costs(&iface.params) {
            Ok(costs) => costs,
            Err(e) => {
                if private {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid stamp cost for '{}': {e}", iface.name),
                    ));
                }
                log::warn!("Failed to parse stamp costs for '{}': {}", iface.name, e);
                continue;
            }
        };
        let announce_limits = match parse_interface_announce_limits(&iface.params) {
            Ok(limits) => limits,
            Err(e) => {
                if private {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid announce limits for '{}': {e}", iface.name),
                    ));
                }
                log::warn!(
                    "Failed to parse announce limits for '{}': {}",
                    iface.name,
                    e
                );
                continue;
            }
        };
        let recursive_prs = iface
            .params
            .get("recursive_prs")
            .and_then(|v| config::parse_bool_pub(v))
            .unwrap_or(false);
        let announces_from_internal = iface
            .params
            .get("announces_from_internal")
            .and_then(|v| config::parse_bool_pub(v))
            .unwrap_or(true);
        let gravity = parse_interface_gravity(
            iface.params.get("gravity").map(String::as_str),
            rns_config.reticulum.default_gravity,
        );
        let announces_to_internal = iface
            .params
            .get("announces_to_internal")
            .and_then(|v| config::parse_bool_pub(v));

        // Inject storage_dir for I2P (and any future factories that need it)
        let mut params = iface.params.clone();
        if !params.contains_key("storage_dir") {
            params.insert(
                "storage_dir".to_string(),
                paths.storage.to_string_lossy().to_string(),
            );
        }
        // Inject device for TCP client
        if let Some(ref device) = rns_config.reticulum.device {
            if !params.contains_key("device") {
                params.insert("device".to_string(), device.clone());
            }
        }

        let config_data = match factory.parse_config_section(
            &iface.name,
            iface_id,
            crate::interface::ConfigSection {
                params: &params,
                children: &iface.subinterfaces,
            },
        ) {
            Ok(data) => data,
            Err(e) => {
                if private {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid interface '{}': {e}", iface.name),
                    ));
                }
                log::warn!("Failed to parse config for '{}': {}", iface.name, e);
                continue;
            }
        };
        // Ids are handed out in the order interfaces are added; an
        // RNodeMultiInterface's subinterfaces take the ones after its
        // own.
        next_id_val = iface_id.0 + reserved_interface_ids(config_data.as_ref());

        interface_configs.push(InterfaceConfig {
            name: iface.name.clone(),
            type_name: iface.interface_type.clone(),
            config_data,
            mode: iface_mode,
            gravity,
            hop_limiter: parse_interface_hop_limiter(
                iface.params.get("hop_limiter").map(String::as_str),
            ),
            recursive_prs,
            announces_from_internal,
            announces_to_internal,
            ingress_control,
            stamp_costs,
            announce_limits,
            ifac: ifac_config,
            discovery: discovery_config,
        });
        initial_ids.insert(iface.name.clone(), iface_id);
    }
    Ok((interface_configs, initial_ids))
}

/// The identity hashes `remote_management_allowed` lists, skipping and
/// logging entries that are not 32 hex digits.
pub(super) fn parse_management_allowed(entries: &[String]) -> Vec<[u8; 16]> {
    let mut mgmt_allowed = Vec::new();
    for hex_hash in entries {
        if hex_hash.len() == 32 {
            if let Some(hash) = rns_core::encoding::hex_decode_array(hex_hash) {
                mgmt_allowed.push(hash);
            } else {
                log::warn!("Invalid hex in remote_management_allowed: {}", hex_hash);
            }
        } else {
            log::warn!(
                "Invalid entry in remote_management_allowed (expected 32 hex chars, got {}): {}",
                hex_hash.len(),
                hex_hash,
            );
        }
    }
    mgmt_allowed
}

/// The probe servers `probe_addr` lists, comma separated, skipping and
/// logging entries that do not parse.
pub(super) fn parse_probe_addrs(probe_addr: Option<&str>) -> Vec<std::net::SocketAddr> {
    probe_addr
        .map(|s| {
            s.split(',')
                .filter_map(|entry| {
                    let trimmed = entry.trim();
                    if trimmed.is_empty() {
                        return None;
                    }
                    trimmed
                        .parse::<std::net::SocketAddr>()
                        .map_err(|e| {
                            log::warn!("Invalid probe_addr entry '{}': {}", trimmed, e);
                            e
                        })
                        .ok()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `probe_protocol`: STUN when it says so, else RNSP.
pub(super) fn parse_probe_protocol(
    probe_protocol: Option<&str>,
) -> rns_core::holepunch::ProbeProtocol {
    match probe_protocol.map(|s| s.to_lowercase()) {
        Some(ref s) if s == "stun" => rns_core::holepunch::ProbeProtocol::Stun,
        _ => rns_core::holepunch::ProbeProtocol::Rnsp,
    }
}

/// Remove ratchets of destinations no longer known, and expired ones.
pub(super) fn clean_ratchets(
    ratchet_store: &dyn storage::RatchetStore,
    known_destinations: &HashMap<[u8; 16], storage::KnownDestination>,
    ratchet_expiry: u64,
) {
    let known_destination_hashes: HashSet<[u8; 16]> = known_destinations.keys().copied().collect();
    match ratchet_store.cleanup(
        &known_destination_hashes,
        time::now(),
        ratchet_expiry as f64,
    ) {
        Ok(stats) if stats.processed > 0 => log::debug!(
            "Processed {} ratchets, not in use {}, removed {}",
            stats.processed,
            stats.not_known,
            stats.removed
        ),
        Ok(_) => {}
        Err(err) => log::warn!("failed to clean ratchets: {}", err),
    }
}

/// Whether `autoconnect_policy` is upstream's, and the bootstrap-only
/// interfaces. The settings of the policy not chosen are read but ignored,
/// with a warning.
pub(super) fn autoconnect_policy(rns_config: &config::RnsConfig) -> (bool, Vec<String>) {
    let upstream_policy =
        rns_config.reticulum.autoconnect_policy == config::AutoconnectPolicy::Upstream;
    let bootstrap_interfaces: Vec<String> = rns_config
        .interfaces
        .iter()
        .filter(|iface| {
            iface
                .params
                .get("bootstrap_only")
                .and_then(|v| config::parse_bool_pub(v))
                .unwrap_or(false)
        })
        .map(|iface| iface.name.clone())
        .collect();
    if upstream_policy && rns_config.reticulum.backbone_peer_pool_max_connected > 0 {
        log::warn!(
            "backbone_peer_pool_max_connected applies only with autoconnect_policy = pool; ignoring it"
        );
    }
    if !upstream_policy
        && (rns_config.reticulum.autoconnect_discovered_interfaces > 0
            || !bootstrap_interfaces.is_empty())
    {
        log::warn!(
            "autoconnect_discovered_interfaces and bootstrap_only apply only with autoconnect_policy = upstream; ignoring them"
        );
    }
    (upstream_policy, bootstrap_interfaces)
}
