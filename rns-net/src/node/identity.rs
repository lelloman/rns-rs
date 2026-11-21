//! The node's transport and network identities.

use super::*;

/// Load the `network_identity` configured at `path`, or create and save one
/// there when the file is missing, logging as upstream's
/// `Reticulum.__apply_config` does.
/// A new identity, logged as upstream's `Identity.create_keys` logs it.
pub(crate) fn create_identity() -> Identity {
    let identity = Identity::new(&mut OsRng);
    log::info!("Identity keys created for <{}>", hex(identity.hash()));
    identity
}

pub(crate) fn load_network_identity(path: &str) -> io::Result<Identity> {
    let identity_path = expand_home(path);
    let load = || -> io::Result<Identity> {
        if !identity_path.is_file() {
            let identity = create_identity();
            storage::save_identity(&identity, &identity_path)?;
            log::info!(
                "Network identity generated and persisted to {}",
                identity_path.display()
            );
            Ok(identity)
        } else {
            let identity = storage::load_identity(&identity_path)?;
            log::info!("Network identity loaded from {}", identity_path.display());
            Ok(identity)
        }
    };
    load().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Could not set network identity from {path}: {e}"),
        )
    })
}

/// Expand a leading `~` or `~/` to `$HOME`, as `os.path.expanduser` does.
pub(super) fn expand_home(path: &str) -> std::path::PathBuf {
    let home = || std::env::var_os("HOME").map(std::path::PathBuf::from);
    if path == "~" {
        if let Some(home) = home() {
            return home;
        }
    } else if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home() {
            return home.join(rest);
        }
    }
    std::path::PathBuf::from(path)
}
