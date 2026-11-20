//! The transport identity's built-in destinations: remote management,
//! the blackhole list and the probe responder.

use super::*;

/// Register the transport identity's built-in destinations the config
/// enables, logging the tables restored from `transport_state_dir` among
/// them where upstream does, and announce that a transport instance
/// started.
pub(super) fn enable_builtin_destinations(
    driver: &mut Driver,
    config: &NodeConfig,
    restored_tables: Option<rns_core::transport::persistence::RestoreStats>,
    transport_state_dir: Option<&Path>,
) {
    // The management destinations belong to the transport identity,
    // `Transport.identity`: on an instance without transport and
    // without static_transport_identity, the ephemeral one.
    let transport_id = Identity::from_private_key(
        &driver
            .transport_identity
            .as_ref()
            .and_then(|identity| identity.get_private_key())
            .expect("the node has a transport identity"),
    );
    if config.management.enable_remote_management {
        enable_remote_management(driver, &transport_id, &config.management);
    }
    if config.management.publish_blackhole {
        enable_blackhole_publishing(driver, &transport_id);
    }
    if let (Some(stats), Some(storage_dir)) = (restored_tables, transport_state_dir) {
        log_restored_tables(&stats, storage_dir);
    }
    if config.respond_to_probes && config.transport_enabled {
        enable_probe_responder(driver, &transport_id);
    }
    if config.transport_enabled {
        log::info!("Transport instance <{}> started", hex(transport_id.hash()));
    }
}

/// Register `dest` as a built-in SINGLE destination taking links, signed
/// with the Ed25519 half of `prv_key`, as the management destinations are.
pub(super) fn register_builtin_link_destination(
    driver: &mut Driver,
    dest: [u8; 16],
    prv_key: &[u8; 64],
) {
    let (_, sig_seed) = rns_crypto::identity::split_key(prv_key);
    let sig_prv = rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&sig_seed);
    let sig_pub_bytes = sig_prv.public_key().public_bytes();
    driver
        .engine
        .register_destination(dest, rns_core::constants::DESTINATION_SINGLE);
    driver
        .local_destinations
        .insert(dest, rns_core::constants::DESTINATION_SINGLE);
    driver.builtin_link_destinations.insert(dest);
    driver.link_manager.register_link_destination(
        dest,
        sig_prv,
        sig_pub_bytes,
        crate::link_manager::ResourceStrategy::AcceptNone,
    );
}

/// The remote management destination of the transport identity
/// `transport_id`, answering status and path requests.
pub(super) fn enable_remote_management(
    driver: &mut Driver,
    transport_id: &Identity,
    management: &crate::management::ManagementConfig,
) {
    let Some(prv_key) = transport_id.get_private_key() else {
        return;
    };
    let identity_hash = *transport_id.hash();
    let mgmt_dest = crate::management::management_dest_hash(&identity_hash);
    register_builtin_link_destination(driver, mgmt_dest, &prv_key);
    driver
        .link_manager
        .register_management_path(crate::management::status_path_hash());
    driver
        .link_manager
        .register_management_path(crate::management::path_path_hash());
    log::info!(
        target: crate::logging::NOTICE_TARGET,
        "Enabled remote management on <rnstransport.remote.management.{}:{}>",
        hex(&identity_hash),
        hex(&mgmt_dest),
    );
    if !management.remote_management_allowed.is_empty() {
        log::info!(
            "Remote management allowed for {} identities",
            management.remote_management_allowed.len(),
        );
    }
}

/// The blackhole list destination of the transport identity
/// `transport_id`.
pub(super) fn enable_blackhole_publishing(driver: &mut Driver, transport_id: &Identity) {
    let Some(prv_key) = transport_id.get_private_key() else {
        return;
    };
    let identity_hash = *transport_id.hash();
    let bh_dest = crate::management::blackhole_dest_hash(&identity_hash);
    register_builtin_link_destination(driver, bh_dest, &prv_key);
    driver
        .link_manager
        .register_management_path(crate::management::list_path_hash());
    // Upstream 426673e9: requesting the list costs a 5.25 stamp, below the
    // `LR_COST` default.
    driver
        .link_manager
        .link_request_costs()
        .set(bh_dest, rns_core::constants::BLACKHOLE_LINK_COST.as_f64());
    log::info!(
        target: crate::logging::NOTICE_TARGET,
        "Enabled blackhole list publishing for transport identity <{}>",
        hex(&identity_hash),
    );
}

/// The probe destination of the transport identity `transport_id`, which
/// proves every packet it receives.
pub(super) fn enable_probe_responder(driver: &mut Driver, transport_id: &Identity) {
    let identity_hash = *transport_id.hash();
    let probe_dest = crate::management::probe_dest_hash(&identity_hash);

    // Register as SINGLE destination in transport engine
    driver
        .engine
        .register_destination(probe_dest, rns_core::constants::DESTINATION_SINGLE);
    driver
        .local_destinations
        .insert(probe_dest, rns_core::constants::DESTINATION_SINGLE);

    // Register PROVE_ALL proof strategy with transport identity
    let probe_identity = rns_crypto::identity::Identity::from_private_key(
        &transport_id
            .get_private_key()
            .expect("the transport identity was built from its private key"),
    );
    driver.proof_strategies.insert(
        probe_dest,
        (
            rns_core::types::ProofStrategy::ProveAll,
            Some(probe_identity),
        ),
    );

    driver.probe_responder_hash = Some(probe_dest);

    log::info!(
        target: crate::logging::NOTICE_TARGET,
        "Transport Instance will respond to probe requests on <rnstransport.probe.{}:{}>",
        hex(&identity_hash),
        hex(&probe_dest),
    );
}
