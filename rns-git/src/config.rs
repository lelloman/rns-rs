use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::logging::DEFAULT_LOG_LEVEL;
use crate::util::parse_hex_16;
use crate::Result;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub dir: PathBuf,
    pub reticulum_dir: Option<PathBuf>,
    pub repositories_dir: PathBuf,
    pub identity_path: PathBuf,
    pub client_identity_path: PathBuf,
    pub node_name: String,
    pub announce_interval_secs: u64,
    pub serve_nomadnet: bool,
    pub templates_dir: PathBuf,
    pub unicode_icons: bool,
    pub record_stats: bool,
    pub stats_ignore_identities: Vec<[u8; 16]>,
    pub allow_read: Vec<String>,
    pub allow_write: Vec<String>,
    pub allow_create: Vec<String>,
    pub allow_stats: Vec<String>,
    pub allow_release: Vec<String>,
    pub allow_interact: Vec<String>,
    pub allow_admin: Vec<String>,
    pub log_level: u8,
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub dir: PathBuf,
    pub reticulum_dir: Option<PathBuf>,
    pub identity_path: PathBuf,
    pub connect_timeout_secs: u64,
    pub request_timeout_secs: u64,
    pub log_level: u8,
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
        if let Some(v) = get(&ini, "rngit", "node_name") {
            cfg.node_name = v.to_string();
        }
        if let Some(v) = get(&ini, "rngit", "announce_interval") {
            cfg.announce_interval_secs = v.parse().unwrap_or(cfg.announce_interval_secs);
        }
        if let Some(v) = get(&ini, "rngit", "record_stats") {
            cfg.record_stats = parse_bool(v, cfg.record_stats);
        }
        if let Some(v) = get(&ini, "rngit", "stats_ignore_identities") {
            cfg.stats_ignore_identities = split_list(v)
                .into_iter()
                .filter_map(|value| parse_hex_16(&value).ok())
                .collect();
        }
        if let Some(v) = get(&ini, "pages", "serve_nomadnet") {
            cfg.serve_nomadnet = parse_bool(v, cfg.serve_nomadnet);
        }
        if let Some(v) = get(&ini, "pages", "templates_dir") {
            cfg.templates_dir = resolve_path(&cfg.dir, v);
        }
        if let Some(v) = get(&ini, "pages", "unicode_icons") {
            cfg.unicode_icons = parse_bool(v, cfg.unicode_icons);
        }
        if let Some(v) = get(&ini, "logging", "loglevel") {
            cfg.log_level = parse_log_level(v, cfg.log_level);
        }
        cfg.allow_read = split_list(get(&ini, "access", "read").unwrap_or("all"));
        cfg.allow_write = split_list(get(&ini, "access", "write").unwrap_or("none"));
        cfg.allow_create = split_list(get(&ini, "access", "create").unwrap_or("none"));
        cfg.allow_stats = split_list(get(&ini, "access", "stats").unwrap_or("none"));
        cfg.allow_release = split_list(get(&ini, "access", "release").unwrap_or("none"));
        cfg.allow_interact = split_list(get(&ini, "access", "interact").unwrap_or("none"));
        cfg.allow_admin = split_list(get(&ini, "access", "admin").unwrap_or("none"));
        Ok((cfg, false))
    }

    fn defaults(dir: PathBuf, reticulum_dir: Option<PathBuf>) -> Self {
        Self {
            repositories_dir: dir.join("repositories"),
            identity_path: dir.join("repositories_identity"),
            client_identity_path: dir.join("client_identity"),
            node_name: "Anonymous Git Node".to_string(),
            dir: dir.clone(),
            reticulum_dir,
            announce_interval_secs: 300,
            serve_nomadnet: false,
            templates_dir: dir.join("templates"),
            unicode_icons: false,
            record_stats: false,
            stats_ignore_identities: Vec::new(),
            allow_read: vec!["all".to_string()],
            allow_write: vec!["none".to_string()],
            allow_create: vec!["none".to_string()],
            allow_stats: vec!["none".to_string()],
            allow_release: vec!["none".to_string()],
            allow_interact: vec!["none".to_string()],
            allow_admin: vec!["none".to_string()],
            log_level: DEFAULT_LOG_LEVEL,
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
        if let Some(v) = get(&ini, "logging", "loglevel") {
            cfg.log_level = parse_log_level(v, cfg.log_level);
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
            log_level: DEFAULT_LOG_LEVEL,
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

fn parse_log_level(value: &str, fallback: u8) -> u8 {
    value
        .parse::<u8>()
        .map(|level| level.min(7))
        .unwrap_or(fallback)
}

fn parse_bool(value: &str, fallback: bool) -> bool {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => fallback,
    }
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
    "[rngit]\nannounce_interval = 300\nidentity = repositories_identity\nclient_identity = client_identity\n# node_name = Anonymous Git Node\n# record_stats = no\n# stats_ignore_identities = 00112233445566778899aabbccddeeff\n\n[repositories]\npath = repositories\n\n[access]\nread = all\nwrite = none\ncreate = none\nstats = none\nrelease = none\ninteract = none\nadmin = none\n\n[pages]\n# serve_nomadnet = no\n# templates_dir = templates\n# unicode_icons = no\n\n[logging]\nloglevel = 4\n"
}

fn default_client_config() -> &'static str {
    "[client]\nidentity = client_identity\nconnect_timeout = 30\nrequest_timeout = 300\n\n[logging]\nloglevel = 4\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sections_and_lists() {
        let ini = parse_ini("[access]\nread = all, 0011\nwrite = none\ncreate = all\n").unwrap();
        assert_eq!(get(&ini, "access", "write"), Some("none"));
        assert_eq!(get(&ini, "access", "create"), Some("all"));
        assert_eq!(split_list(get(&ini, "access", "read").unwrap()).len(), 2);
    }

    #[test]
    fn parses_and_clamps_log_level() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("client_config"),
            "[client]\nrequest_timeout = 5\n[logging]\nloglevel = 99\n",
        )
        .unwrap();
        let (cfg, created) = ClientConfig::load_or_create(tmp.path().to_path_buf(), None).unwrap();
        assert!(!created);
        assert_eq!(cfg.log_level, 7);
    }

    #[test]
    fn creates_default_server_config_once() {
        let tmp = tempfile::tempdir().unwrap();
        let (_cfg, created) = ServerConfig::load_or_create(tmp.path().to_path_buf(), None).unwrap();
        assert!(created);
        let (_cfg, created) = ServerConfig::load_or_create(tmp.path().to_path_buf(), None).unwrap();
        assert!(!created);
    }

    #[test]
    fn parses_nomadnet_page_config() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("server_config"),
            "[rngit]\nnode_name = Public Git Node\n[pages]\nserve_nomadnet = yes\ntemplates_dir = custom_templates\nunicode_icons = yes\n",
        )
        .unwrap();
        let (cfg, created) = ServerConfig::load_or_create(tmp.path().to_path_buf(), None).unwrap();
        assert!(!created);
        assert_eq!(cfg.node_name, "Public Git Node");
        assert!(cfg.serve_nomadnet);
        assert_eq!(cfg.templates_dir, tmp.path().join("custom_templates"));
        assert!(cfg.unicode_icons);
    }

    #[test]
    fn parses_stats_config_and_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("server_config"),
            "[rngit]\nrecord_stats = yes\nstats_ignore_identities = 00112233445566778899aabbccddeeff\n[access]\nstats = all, 0102030405060708090a0b0c0d0e0f10\n",
        )
        .unwrap();

        let (cfg, created) = ServerConfig::load_or_create(tmp.path().to_path_buf(), None).unwrap();
        assert!(!created);
        assert!(cfg.record_stats);
        assert_eq!(
            cfg.stats_ignore_identities,
            vec![[
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]]
        );
        assert_eq!(
            cfg.allow_stats,
            vec![
                "all".to_string(),
                "0102030405060708090a0b0c0d0e0f10".to_string()
            ]
        );
    }

    #[test]
    fn parses_release_permission_config() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("server_config"),
            "[access]\nrelease = all, 0102030405060708090a0b0c0d0e0f10\ninteract = all\nadmin = 00112233445566778899aabbccddeeff\n",
        )
        .unwrap();

        let (cfg, created) = ServerConfig::load_or_create(tmp.path().to_path_buf(), None).unwrap();
        assert!(!created);
        assert_eq!(
            cfg.allow_release,
            vec![
                "all".to_string(),
                "0102030405060708090a0b0c0d0e0f10".to_string()
            ]
        );
        assert_eq!(cfg.allow_interact, vec!["all".to_string()]);
        assert_eq!(
            cfg.allow_admin,
            vec!["00112233445566778899aabbccddeeff".to_string()]
        );
    }

    #[test]
    fn missing_pages_section_keeps_nomadnet_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("server_config"), "[rngit]\n").unwrap();
        let (cfg, created) = ServerConfig::load_or_create(tmp.path().to_path_buf(), None).unwrap();
        assert!(!created);
        assert_eq!(cfg.node_name, "Anonymous Git Node");
        assert!(!cfg.serve_nomadnet);
        assert_eq!(cfg.templates_dir, tmp.path().join("templates"));
        assert!(!cfg.unicode_icons);
        assert!(!cfg.record_stats);
        assert!(cfg.stats_ignore_identities.is_empty());
        assert_eq!(cfg.allow_stats, vec!["none".to_string()]);
        assert_eq!(cfg.allow_release, vec!["none".to_string()]);
        assert_eq!(cfg.allow_interact, vec!["none".to_string()]);
        assert_eq!(cfg.allow_admin, vec!["none".to_string()]);
    }
}
