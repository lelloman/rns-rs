//! Resolution of native hook library paths requested through the control plane.
//!
//! Native hooks requested over the HTTP API are loaded only from the
//! configured hooks directory. Startup hooks declared in the node's config
//! file do not go through this check.

use std::path::{Path, PathBuf};

/// Error returned when a requested native hook path is not accepted.
pub const NATIVE_HOOK_PATH_ERROR: &str =
    "native hook path must be inside the configured hooks directory";

/// Name of the hooks subdirectory used when no hooks directory is configured.
pub const DEFAULT_HOOKS_SUBDIR: &str = "hooks";

/// Hooks directory used when none is configured: `<config dir>/hooks`.
pub fn default_hooks_dir(config_path: Option<&str>) -> PathBuf {
    rns_net::storage::resolve_config_dir(config_path.map(Path::new)).join(DEFAULT_HOOKS_SUBDIR)
}

/// Resolve the hooks directory from an explicit setting or the config path.
pub fn resolve_hooks_dir(hooks_dir: Option<&str>, config_path: Option<&str>) -> PathBuf {
    match hooks_dir {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => default_hooks_dir(config_path),
    }
}

/// Check a requested native hook path against the hooks directory.
///
/// The requested path must be absolute (bare or relative names are refused so
/// that the dynamic loader's search path is never consulted), must resolve to a
/// regular file, and its canonical form must lie inside the canonical hooks
/// directory. Returns the canonical path to load.
pub fn resolve_native_hook_path(hooks_dir: &Path, requested: &str) -> Result<PathBuf, String> {
    let requested = Path::new(requested);
    if requested.as_os_str().is_empty() || !requested.is_absolute() {
        return Err(NATIVE_HOOK_PATH_ERROR.into());
    }
    let dir = hooks_dir
        .canonicalize()
        .map_err(|_| NATIVE_HOOK_PATH_ERROR.to_string())?;
    let file = requested
        .canonicalize()
        .map_err(|_| NATIVE_HOOK_PATH_ERROR.to_string())?;
    if file == dir || !file.starts_with(&dir) {
        return Err(NATIVE_HOOK_PATH_ERROR.into());
    }
    let meta = std::fs::metadata(&file).map_err(|_| NATIVE_HOOK_PATH_ERROR.to_string())?;
    if !meta.is_file() {
        return Err(NATIVE_HOOK_PATH_ERROR.into());
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rns-ctl-hook-path-{}-{}-{}",
                label,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn setup(label: &str) -> (TempDir, PathBuf) {
        let root = TempDir::new(label);
        let hooks = root.0.join("hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        (root, hooks)
    }

    #[test]
    fn file_inside_hooks_dir_is_accepted() {
        let (_root, hooks) = setup("inside");
        let lib = hooks.join("libhook.so");
        std::fs::write(&lib, b"x").unwrap();
        let resolved = resolve_native_hook_path(&hooks, lib.to_str().unwrap()).unwrap();
        assert_eq!(resolved, lib.canonicalize().unwrap());
    }

    #[test]
    fn file_in_nested_dir_inside_hooks_dir_is_accepted() {
        let (_root, hooks) = setup("nested");
        std::fs::create_dir_all(hooks.join("sub")).unwrap();
        let lib = hooks.join("sub").join("libhook.so");
        std::fs::write(&lib, b"x").unwrap();
        assert!(resolve_native_hook_path(&hooks, lib.to_str().unwrap()).is_ok());
    }

    #[test]
    fn file_outside_hooks_dir_is_rejected() {
        let (root, hooks) = setup("outside");
        let lib = root.0.join("libother.so");
        std::fs::write(&lib, b"x").unwrap();
        let err = resolve_native_hook_path(&hooks, lib.to_str().unwrap()).unwrap_err();
        assert_eq!(err, NATIVE_HOOK_PATH_ERROR);
    }

    #[test]
    fn dot_dot_path_leaving_hooks_dir_is_rejected() {
        let (root, hooks) = setup("dotdot");
        std::fs::write(root.0.join("libother.so"), b"x").unwrap();
        let requested = hooks.join("..").join("libother.so");
        assert!(resolve_native_hook_path(&hooks, requested.to_str().unwrap()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_pointing_outside_hooks_dir_is_rejected() {
        let (root, hooks) = setup("symlink");
        let target = root.0.join("libother.so");
        std::fs::write(&target, b"x").unwrap();
        let link = hooks.join("liblink.so");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(resolve_native_hook_path(&hooks, link.to_str().unwrap()).is_err());
    }

    #[test]
    fn relative_and_bare_names_are_rejected() {
        let (_root, hooks) = setup("relative");
        std::fs::write(hooks.join("libhook.so"), b"x").unwrap();
        assert!(resolve_native_hook_path(&hooks, "libhook.so").is_err());
        assert!(resolve_native_hook_path(&hooks, "hooks/libhook.so").is_err());
        assert!(resolve_native_hook_path(&hooks, "./libhook.so").is_err());
        assert!(resolve_native_hook_path(&hooks, "").is_err());
    }

    #[test]
    fn directory_and_missing_file_are_rejected() {
        let (_root, hooks) = setup("dir");
        std::fs::create_dir_all(hooks.join("sub")).unwrap();
        assert!(resolve_native_hook_path(&hooks, hooks.join("sub").to_str().unwrap()).is_err());
        assert!(resolve_native_hook_path(&hooks, hooks.to_str().unwrap()).is_err());
        assert!(
            resolve_native_hook_path(&hooks, hooks.join("missing.so").to_str().unwrap()).is_err()
        );
    }

    #[test]
    fn missing_hooks_dir_rejects_everything() {
        let root = TempDir::new("nodir");
        let lib = root.0.join("libhook.so");
        std::fs::write(&lib, b"x").unwrap();
        let hooks = root.0.join("hooks");
        assert!(resolve_native_hook_path(&hooks, lib.to_str().unwrap()).is_err());
    }

    #[test]
    fn hooks_dir_defaults_to_config_subdir() {
        assert_eq!(
            resolve_hooks_dir(None, Some("/srv/rns")),
            PathBuf::from("/srv/rns/hooks")
        );
        assert_eq!(
            resolve_hooks_dir(Some("/opt/rns-hooks"), Some("/srv/rns")),
            PathBuf::from("/opt/rns-hooks")
        );
    }
}
