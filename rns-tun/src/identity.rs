use std::fs;
use std::io;
use std::path::Path;

use rns_crypto::identity::Identity;
use rns_crypto::OsRng;

/// Load an application identity or atomically create one with private-key
/// permissions. The Reticulum transport identity is managed separately by the
/// private node state directory.
pub fn load_or_create(path: &Path) -> io::Result<Identity> {
    match rns_net::storage::load_identity(path) {
        Ok(identity) => return Ok(identity),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let identity = Identity::new(&mut OsRng);
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    rns_net::storage::save_identity(&identity, &temporary)?;
    set_private_permissions(&temporary)?;
    match fs::rename(&temporary, path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            return rns_net::storage::load_identity(path);
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
    }
    set_private_permissions(path)?;
    Ok(identity)
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

pub fn signature_keys(identity: &Identity) -> io::Result<([u8; 32], [u8; 32])> {
    let private = identity
        .get_private_key()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "identity has no private key"))?;
    let public = identity
        .get_public_key()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "identity has no public key"))?;
    let mut signature_private = [0; 32];
    let mut signature_public = [0; 32];
    signature_private.copy_from_slice(&private[32..]);
    signature_public.copy_from_slice(&public[32..]);
    Ok((signature_private, signature_public))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        let first = load_or_create(&path).unwrap();
        let second = load_or_create(&path).unwrap();
        assert_eq!(first.hash(), second.hash());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
