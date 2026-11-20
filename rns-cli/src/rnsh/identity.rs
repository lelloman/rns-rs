//! Identities: our own, and those allowed to connect.

use super::*;

pub(super) fn prepare_identity(
    rnsh_config: &Path,
    rns_config: &Path,
    explicit_path: Option<&str>,
    service: Option<&str>,
    home: &Path,
) -> Result<Identity, RnshError> {
    let path = rnsh_identity_path(rnsh_config, explicit_path, service, home);
    if explicit_path.is_none() {
        let old_path = legacy_rnsh_identity_path(rns_config, service);
        if let Some(warning) = legacy_identity_migration_warning(&path, &old_path) {
            eprintln!("{warning}");
        }
    }
    prepare_identity_at(&path)
}

pub(super) fn rnsh_identity_path(
    config_dir: &Path,
    explicit_path: Option<&str>,
    service: Option<&str>,
    home: &Path,
) -> PathBuf {
    if let Some(path) = explicit_path {
        return expand_user_path(path, home);
    }
    let suffix = service.map(sanitize_service_name).unwrap_or_default();
    if suffix.is_empty() {
        config_dir.join("identity")
    } else {
        config_dir.join(format!("identity.{suffix}"))
    }
}

pub(super) fn legacy_rnsh_identity_path(rns_config: &Path, service: Option<&str>) -> PathBuf {
    let suffix = service.map(sanitize_service_name).unwrap_or_default();
    let filename = if suffix.is_empty() {
        APP_NAME.to_string()
    } else {
        format!("{APP_NAME}.{suffix}")
    };
    rns_config.join("storage").join("identities").join(filename)
}

pub(super) fn legacy_identity_migration_warning(
    new_path: &Path,
    old_path: &Path,
) -> Option<String> {
    (!new_path.exists() && old_path.is_file()).then(|| {
        format!(
            "warning: existing pre-migration rnsh identity found at '{}'; rnsh now uses '{}'. Move the identity explicitly or pass --identity to retain the same destination. No private key was copied.",
            old_path.display(),
            new_path.display(),
        )
    })
}

pub(super) fn prepare_identity_at(path: &Path) -> Result<Identity, RnshError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    // Upstream's prepare_identity: "Loading identity" and the key creation
    // at Verbose, "Creating identity" at Notice.
    if path.exists() {
        log::info!("Loading identity from {}", path.display());
        Ok(rns_net::storage::load_identity(path)?)
    } else {
        log::info!(target: crate::pylog::NOTICE_TARGET, "Creating identity {}", path.display());
        let identity = crate::pylog::new_identity();
        rns_net::storage::save_identity(&identity, path)?;
        Ok(identity)
    }
}

pub(super) fn print_identity(opts: &CliOptions) -> Result<(), RnshError> {
    let home = home_dir();
    let rnsh_config = resolve_rnsh_config_dir(opts.rnsh_config.as_deref(), &home)?;
    let rns_config = resolve_rns_config_dir(opts.rns_config.as_deref(), &home);
    // `RNS.Reticulum(configdir, loglevel=RNS.LOG_INFO)`, logging to stdout.
    crate::pylog::install_utility_logging(
        rns_config.to_str(),
        Some(crate::pylog::LOG_INFO),
        0,
        false,
    );
    // Upstream starts Reticulum in full: attached to a running shared
    // instance, or as one of its own, which writes the default config when
    // there is none. It persists its state when it exits.
    let (tx, _) = mpsc::channel();
    let callbacks = || Box::new(RnshCallbacks { tx: tx.clone() });
    let node = RnsNode::connect_shared_from_config(Some(&rns_config), callbacks())
        .or_else(|_| RnsNode::from_config(Some(&rns_config), callbacks()))?;
    let printed = print_identity_info(opts, &rnsh_config, &rns_config, &home);
    node.shutdown();
    printed
}

fn print_identity_info(
    opts: &CliOptions,
    rnsh_config: &Path,
    rns_config: &Path,
    home: &Path,
) -> Result<(), RnshError> {
    if let Some(service) = opts.service.as_deref().filter(|s| !s.is_empty()) {
        println!("Using service name \"{service}\"");
    }
    let identity = prepare_identity(
        rnsh_config,
        rns_config,
        opts.identity.as_deref(),
        opts.service.as_deref(),
        home,
    )?;
    println!("Identity     : {}", prettyhexrep(identity.hash()));
    if opts.listen {
        let dest = Destination::single_in(APP_NAME, &[], IdentityHash(*identity.hash()));
        println!("Listening on : {}", prettyhexrep(&dest.hash.0));
    }
    Ok(())
}

pub(super) fn load_allowed_identities(
    opts: &CliOptions,
    config_dir: &Path,
) -> Result<HashSet<[u8; 16]>, RnshError> {
    let mut allowed = HashSet::new();
    for entry in &opts.allowed {
        if let Some(hash) = parse_hash_16(entry) {
            allowed.insert(hash);
        } else {
            return Err(RnshError::Protocol(format!(
                "invalid allowed identity hash: {entry}"
            )));
        }
    }
    let path = config_dir.join("allowed_identities");
    if path.is_file() {
        let contents = fs::read_to_string(path)?;
        for line in contents
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            if let Some(hash) = parse_hash_16(line) {
                allowed.insert(hash);
            }
        }
    }
    Ok(allowed)
}

pub(super) fn sanitize_service_name(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

pub(super) fn parse_hash_16(value: &str) -> Option<[u8; 16]> {
    rns_core::encoding::hex_decode_array(value.trim())
}

pub(super) fn extract_sig_keys(identity: &Identity) -> Result<([u8; 32], [u8; 32]), RnshError> {
    let private = identity
        .get_private_key()
        .ok_or_else(|| RnshError::Protocol("identity has no private key".into()))?;
    let public = identity
        .get_public_key()
        .ok_or_else(|| RnshError::Protocol("identity has no public key".into()))?;
    let mut sig_prv = [0u8; 32];
    let mut sig_pub = [0u8; 32];
    sig_prv.copy_from_slice(&private[32..64]);
    sig_pub.copy_from_slice(&public[32..64]);
    Ok((sig_prv, sig_pub))
}
