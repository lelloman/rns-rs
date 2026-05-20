use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use rns_crypto::identity::Identity;
use rns_crypto::OsRng;
use rns_net::storage;

use crate::{Error, Result};

pub fn default_rngit_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("RNGIT_CONFIG") {
        return PathBuf::from(path);
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        let legacy = home.join(".rngit");
        let xdg = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"))
            .join("rngit");
        if xdg.exists() || !legacy.exists() {
            return xdg;
        }
        return legacy;
    }
    PathBuf::from(".rngit")
}

pub fn default_reticulum_dir() -> Option<PathBuf> {
    std::env::var_os("RNS_CONFIG").map(PathBuf::from)
}

pub fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    Ok(())
}

pub fn load_or_create_identity(path: &Path) -> Result<Identity> {
    if path.exists() {
        return storage::load_identity(path).map_err(Error::from);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let identity = Identity::new(&mut OsRng);
    storage::save_identity(&identity, path)?;
    Ok(identity)
}

pub fn hex(bytes: &[u8]) -> String {
    const CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(CHARS[(b >> 4) as usize] as char);
        out.push(CHARS[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn parse_hex_16(s: &str) -> Result<[u8; 16]> {
    let clean = s.trim();
    if clean.len() != 32 {
        return Err(Error::msg("expected 32 hex characters"));
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = parse_hex_byte(&clean[i * 2..i * 2 + 2])?;
    }
    Ok(out)
}

fn parse_hex_byte(s: &str) -> Result<u8> {
    u8::from_str_radix(s, 16).map_err(|_| Error::msg("invalid hex"))
}

pub fn parse_rns_url(url: &str) -> Result<([u8; 16], String)> {
    parse_rns_url_with_aliases(url, &BTreeMap::new())
}

pub fn parse_rns_url_with_aliases(
    url: &str,
    destination_aliases: &BTreeMap<String, [u8; 16]>,
) -> Result<([u8; 16], String)> {
    let rest = url
        .strip_prefix("rns://")
        .ok_or_else(|| Error::msg("RNS Git URL must start with rns://"))?;
    let (hash, repo) = rest
        .split_once('/')
        .ok_or_else(|| Error::msg("RNS Git URL must be rns://<destination>/<repo>"))?;
    let dest_hash = destination_aliases
        .get(hash)
        .copied()
        .map(Ok)
        .unwrap_or_else(|| parse_hex_16(hash))?;
    validate_repo_name(repo)?;
    Ok((dest_hash, repo.trim_matches('/').to_string()))
}

pub fn resolve_rns_url_aliases(
    url: &str,
    destination_aliases: &BTreeMap<String, [u8; 16]>,
) -> Result<String> {
    if !url.starts_with("rns://") {
        return Ok(url.to_string());
    }
    let (dest_hash, repo) = parse_rns_url_with_aliases(url, destination_aliases)?;
    Ok(format!("rns://{}/{}", hex(&dest_hash), repo))
}

pub fn validate_repo_name(name: &str) -> Result<()> {
    let trimmed = name.trim_matches('/');
    if trimmed.is_empty() || trimmed.len() > 256 {
        return Err(Error::msg("invalid repository name"));
    }
    for component in trimmed.split('/') {
        if component.is_empty() || component == "." || component == ".." || component.contains('\\')
        {
            return Err(Error::msg("invalid repository name"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    #[test]
    fn parse_url_extracts_destination_and_repo() {
        let (hash, repo) =
            parse_rns_url("rns://00112233445566778899aabbccddeeff/group/repo").unwrap();
        assert_eq!(hash[0], 0x00);
        assert_eq!(hash[15], 0xff);
        assert_eq!(repo, "group/repo");
    }

    #[test]
    fn parse_url_resolves_destination_aliases() {
        let mut aliases = BTreeMap::new();
        aliases.insert(
            "home".to_string(),
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
        );

        let (hash, repo) = parse_rns_url_with_aliases("rns://home/group/repo", &aliases).unwrap();

        assert_eq!(hash[0], 0x00);
        assert_eq!(hash[15], 0xff);
        assert_eq!(repo, "group/repo");
    }

    #[test]
    fn resolve_url_aliases_canonicalizes_rns_urls() {
        let mut aliases = BTreeMap::new();
        aliases.insert(
            "home".to_string(),
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
        );

        assert_eq!(
            resolve_rns_url_aliases("rns://home/group/repo", &aliases).unwrap(),
            "rns://00112233445566778899aabbccddeeff/group/repo"
        );
        assert_eq!(
            resolve_rns_url_aliases("https://example.invalid/repo.git", &aliases).unwrap(),
            "https://example.invalid/repo.git"
        );
    }

    #[test]
    fn parse_url_rejects_unknown_destination_aliases() {
        let aliases = BTreeMap::new();
        assert!(parse_rns_url_with_aliases("rns://unknown/group/repo", &aliases).is_err());
    }

    #[test]
    fn rejects_path_traversal_repo_names() {
        assert!(validate_repo_name("../repo").is_err());
        assert!(validate_repo_name("group/../repo").is_err());
        assert!(validate_repo_name("group/repo").is_ok());
    }

    #[test]
    fn default_rngit_dir_prefers_xdg_config_path() {
        let _guard = env_lock().lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let saved = SavedEnv::capture();
        std::env::remove_var("RNGIT_CONFIG");
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::set_var("HOME", tmp.path());

        assert_eq!(
            default_rngit_dir(),
            tmp.path().join(".config").join("rngit")
        );

        saved.restore();
    }

    #[test]
    fn default_rngit_dir_keeps_existing_legacy_path() {
        let _guard = env_lock().lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let saved = SavedEnv::capture();
        std::env::remove_var("RNGIT_CONFIG");
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::set_var("HOME", tmp.path());
        std::fs::create_dir_all(tmp.path().join(".rngit")).unwrap();

        assert_eq!(default_rngit_dir(), tmp.path().join(".rngit"));

        saved.restore();
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct SavedEnv {
        home: Option<std::ffi::OsString>,
        xdg_config_home: Option<std::ffi::OsString>,
        rngit_config: Option<std::ffi::OsString>,
    }

    impl SavedEnv {
        fn capture() -> Self {
            Self {
                home: std::env::var_os("HOME"),
                xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
                rngit_config: std::env::var_os("RNGIT_CONFIG"),
            }
        }

        fn restore(self) {
            restore_var("HOME", self.home);
            restore_var("XDG_CONFIG_HOME", self.xdg_config_home);
            restore_var("RNGIT_CONFIG", self.rngit_config);
        }
    }

    fn restore_var(key: &str, value: Option<std::ffi::OsString>) {
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }
}
