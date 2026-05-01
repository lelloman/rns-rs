use std::fs;
use std::path::{Path, PathBuf};

use rns_crypto::identity::Identity;
use rns_crypto::OsRng;
use rns_net::storage;

use crate::{Error, Result};

pub fn default_rngit_dir() -> PathBuf {
    std::env::var_os("RNGIT_CONFIG")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rngit")))
        .unwrap_or_else(|| PathBuf::from(".rngit"))
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
    let rest = url
        .strip_prefix("rns://")
        .ok_or_else(|| Error::msg("RNS Git URL must start with rns://"))?;
    let (hash, repo) = rest
        .split_once('/')
        .ok_or_else(|| Error::msg("RNS Git URL must be rns://<destination>/<repo>"))?;
    let dest_hash = parse_hex_16(hash)?;
    validate_repo_name(repo)?;
    Ok((dest_hash, repo.trim_matches('/').to_string()))
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

    #[test]
    fn parse_url_extracts_destination_and_repo() {
        let (hash, repo) =
            parse_rns_url("rns://00112233445566778899aabbccddeeff/group/repo").unwrap();
        assert_eq!(hash[0], 0x00);
        assert_eq!(hash[15], 0xff);
        assert_eq!(repo, "group/repo");
    }

    #[test]
    fn rejects_path_traversal_repo_names() {
        assert!(validate_repo_name("../repo").is_err());
        assert!(validate_repo_name("group/../repo").is_err());
        assert!(validate_repo_name("group/repo").is_ok());
    }
}
