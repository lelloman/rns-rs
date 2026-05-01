use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::Result;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub dir: PathBuf,
    pub reticulum_dir: Option<PathBuf>,
    pub repositories_dir: PathBuf,
    pub identity_path: PathBuf,
    pub client_identity_path: PathBuf,
    pub announce_interval_secs: u64,
    pub allow_read: Vec<String>,
    pub allow_write: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub dir: PathBuf,
    pub reticulum_dir: Option<PathBuf>,
    pub identity_path: PathBuf,
    pub connect_timeout_secs: u64,
    pub request_timeout_secs: u64,
}

impl ServerConfig {
    pub fn load_or_create(dir: PathBuf, reticulum_dir: Option<PathBuf>) -> Result<(Self, bool)> {
        fs::create_dir_all(&dir)?;
        let path = dir.join("server_config");
        if !path.exists() {
            fs::write(&path, default_server_config())?;
            return Ok((Self::defaults(dir, reticulum_dir), true));
        }
        let ini = parse_ini(&fs::read_to_string(&path)?)?;
        let mut cfg = Self::defaults(dir, reticulum_dir);
        if let Some(v) = get(&ini, "repositories", "path") {
            cfg.repositories_dir = resolve_path(&cfg.dir, v);
        }
        if let Some(v) = get(&ini, "rngit", "identity") {
            cfg.identity_path = resolve_path(&cfg.dir, v);
        }
        if let Some(v) = get(&ini, "rngit", "client_identity") {
            cfg.client_identity_path = resolve_path(&cfg.dir, v);
        }
        if let Some(v) = get(&ini, "rngit", "announce_interval") {
            cfg.announce_interval_secs = v.parse().unwrap_or(cfg.announce_interval_secs);
        }
        cfg.allow_read = split_list(get(&ini, "access", "read").unwrap_or("all"));
        cfg.allow_write = split_list(get(&ini, "access", "write").unwrap_or("none"));
        Ok((cfg, false))
    }

    fn defaults(dir: PathBuf, reticulum_dir: Option<PathBuf>) -> Self {
        Self {
            repositories_dir: dir.join("repositories"),
            identity_path: dir.join("repositories_identity"),
            client_identity_path: dir.join("client_identity"),
            dir,
            reticulum_dir,
            announce_interval_secs: 300,
            allow_read: vec!["all".to_string()],
            allow_write: vec!["none".to_string()],
        }
    }
}

impl ClientConfig {
    pub fn load_or_create(dir: PathBuf, reticulum_dir: Option<PathBuf>) -> Result<(Self, bool)> {
        fs::create_dir_all(&dir)?;
        let path = dir.join("client_config");
        if !path.exists() {
            fs::write(&path, default_client_config())?;
            return Ok((Self::defaults(dir, reticulum_dir), true));
        }
        let ini = parse_ini(&fs::read_to_string(&path)?)?;
        let mut cfg = Self::defaults(dir, reticulum_dir);
        if let Some(v) = get(&ini, "client", "identity") {
            cfg.identity_path = resolve_path(&cfg.dir, v);
        }
        if let Some(v) = get(&ini, "client", "connect_timeout") {
            cfg.connect_timeout_secs = v.parse().unwrap_or(cfg.connect_timeout_secs);
        }
        if let Some(v) = get(&ini, "client", "request_timeout") {
            cfg.request_timeout_secs = v.parse().unwrap_or(cfg.request_timeout_secs);
        }
        Ok((cfg, false))
    }

    fn defaults(dir: PathBuf, reticulum_dir: Option<PathBuf>) -> Self {
        Self {
            identity_path: dir.join("client_identity"),
            dir,
            reticulum_dir,
            connect_timeout_secs: 30,
            request_timeout_secs: 300,
        }
    }
}

type Ini = BTreeMap<String, BTreeMap<String, String>>;

fn parse_ini(input: &str) -> Result<Ini> {
    let mut section = "rngit".to_string();
    let mut out = Ini::new();
    for raw in input.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            out.entry(section.clone())
                .or_default()
                .insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    Ok(out)
}

fn get<'a>(ini: &'a Ini, section: &str, key: &str) -> Option<&'a str> {
    ini.get(section)?.get(key).map(String::as_str)
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn expand_home(value: &str) -> PathBuf {
    if let Some(rest) = value.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(value)
}

fn resolve_path(base: &Path, value: &str) -> PathBuf {
    let path = expand_home(value);
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn default_server_config() -> &'static str {
    "[rngit]\nannounce_interval = 300\nidentity = repositories_identity\nclient_identity = client_identity\n\n[repositories]\npath = repositories\n\n[access]\nread = all\nwrite = none\n"
}

fn default_client_config() -> &'static str {
    "[client]\nidentity = client_identity\nconnect_timeout = 30\nrequest_timeout = 300\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sections_and_lists() {
        let ini = parse_ini("[access]\nread = all, 0011\nwrite = none\n").unwrap();
        assert_eq!(get(&ini, "access", "write"), Some("none"));
        assert_eq!(split_list(get(&ini, "access", "read").unwrap()).len(), 2);
    }

    #[test]
    fn creates_default_server_config_once() {
        let tmp = tempfile::tempdir().unwrap();
        let (_cfg, created) = ServerConfig::load_or_create(tmp.path().to_path_buf(), None).unwrap();
        assert!(created);
        let (_cfg, created) = ServerConfig::load_or_create(tmp.path().to_path_buf(), None).unwrap();
        assert!(!created);
    }
}
