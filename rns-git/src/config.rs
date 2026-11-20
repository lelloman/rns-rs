use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::logging::DEFAULT_LOG_LEVEL;
use crate::util::parse_hex_16;
use crate::{Error, Result};

/// Server settings. Each field is filled from the `server_config` file in
/// [`dir`](Self::dir); settings the file leaves out keep their defaults.
/// Relative paths in the file are resolved against `dir`.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// The rngit directory holding `server_config`, identities and logs.
    pub dir: PathBuf,
    /// Reticulum configuration directory for the node; `None` uses the node's default.
    pub reticulum_dir: Option<PathBuf>,
    /// Where the bare repositories live, as `<group>/<repo>` (default `repositories`).
    pub repositories_dir: PathBuf,
    /// Identity file of the repository and page destinations (default `repositories_identity`).
    pub identity_path: PathBuf,
    /// The operator's client identity file, whose hash `rngit --print-identity`
    /// shows beside the server's (default `client_identity`).
    pub client_identity_path: PathBuf,
    /// Name announced with the Nomad Network page destination.
    pub node_name: String,
    /// Seconds between announces (default 300).
    pub announce_interval_secs: u64,
    /// `[rngit] link_cost` and `stamp_value`: the costs of the repository
    /// destination.
    pub costs: DestinationCosts,
    /// `[pages] link_cost` and `stamp_value`: the costs of the Nomad Network
    /// page destination. Upstream reads these only when it starts the page
    /// node, so an invalid value is kept here as the error message and only
    /// fails startup when pages are served.
    pub pages_costs: std::result::Result<DestinationCosts, String>,
    /// Whether to serve Nomad Network pages for browsing the repositories (default off).
    pub serve_nomadnet: bool,
    /// Directory of `<name>.mu` page templates that override the built-in ones
    /// (default `templates`).
    pub templates_dir: PathBuf,
    /// Whether pages decorate links with Unicode icons (default off).
    pub unicode_icons: bool,
    /// Whether images served on pages are converted to WebP when a converter is
    /// installed (default on).
    pub media_conversion: bool,
    /// Whether to count views, fetches, pushes and downloads (default off).
    pub record_stats: bool,
    /// Identity hashes whose activity is never counted.
    pub stats_ignore_identities: Vec<[u8; 16]>,
    /// Identity hashes whose pushes are not counted; their other activity is.
    pub stats_push_ignore_identities: Vec<[u8; 16]>,
    /// Identity hashes denied every operation. The null identity hash here also
    /// blocks unidentified page requests.
    pub blocked_identities: Vec<[u8; 16]>,
    /// Names from the `[aliases]` section that the identity lists and access rules may use
    /// in place of hex identity hashes.
    pub identity_aliases: BTreeMap<String, [u8; 16]>,
    /// Server-wide read access: `all`, `none`, or identity hashes and aliases (default `all`).
    pub allow_read: Vec<String>,
    /// Server-wide push access to existing repositories (default `none`).
    pub allow_write: Vec<String>,
    /// Server-wide access to create repositories (default `none`).
    pub allow_create: Vec<String>,
    /// Server-wide access to the statistics pages (default `none`).
    pub allow_stats: Vec<String>,
    /// Server-wide access to create, delete and promote releases (default `none`).
    pub allow_release: Vec<String>,
    /// Server-wide access to comment on work documents (default `none`).
    pub allow_interact: Vec<String>,
    /// Server-wide access to propose work documents (default `none`).
    pub allow_propose: Vec<String>,
    /// Server-wide admin access, which implies every other permission (default `none`).
    pub allow_admin: Vec<String>,
    /// Numeric log level, 0-8 (default 4).
    pub log_level: u8,
}

/// A served destination's required link stamp cost and announce stamp
/// target value, as upstream rngit's `link_cost` and `stamp_value` (05ac4bba).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DestinationCosts {
    /// Required link request stamp cost, quantised as upstream's
    /// `Stamps.quantize_cost` (default [`DEFAULT_LINK_COST`]). The node clamps
    /// it to `0..=LINK_COST_CAP`.
    pub link_cost: f64,
    /// Announce stamp target value, quantised. Applied only when it is
    /// above 0, as upstream's `if self.stamp_value:`; otherwise the node's
    /// default target is used.
    pub stamp_value: Option<f64>,
}

/// Upstream rngit's `DEFAULT_LINK_COST`, of both the repository and the page
/// destination.
pub const DEFAULT_LINK_COST: f64 = 18.0;

impl Default for DestinationCosts {
    fn default() -> Self {
        Self {
            link_cost: DEFAULT_LINK_COST,
            stamp_value: None,
        }
    }
}

impl DestinationCosts {
    /// Apply the costs to `destination` before it is announced, as upstream
    /// does right after creating it: `set_value` only for a non-zero
    /// `stamp_value`, then `set_link_cost`.
    pub fn apply(&self, node: &rns_net::RnsNode, destination: &mut rns_net::Destination) {
        if let Some(value) = self.applied_stamp_value() {
            destination.set_value(value);
        }
        node.set_link_cost(destination.hash.0, self.link_cost);
    }

    /// The stamp value [`apply`](Self::apply) sets: a configured one other
    /// than 0, which Python reads as false.
    fn applied_stamp_value(&self) -> Option<f64> {
        self.stamp_value.filter(|value| *value != 0.0)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ClientConfig {
    pub dir: PathBuf,
    pub reticulum_dir: Option<PathBuf>,
    pub identity_path: PathBuf,
    pub connect_timeout_secs: u64,
    pub request_timeout_secs: u64,
    pub destination_aliases: BTreeMap<String, [u8; 16]>,
    pub log_level: u8,
}

impl ServerConfig {
    pub(crate) fn load_or_create_for_run(
        dir: PathBuf,
        reticulum_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let (config, _created) = Self::load_or_create(dir, reticulum_dir)?;
        Ok(config)
    }

    pub(crate) fn load_or_create(
        dir: PathBuf,
        reticulum_dir: Option<PathBuf>,
    ) -> Result<(Self, bool)> {
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
        // Upstream reads `stamp_value` before `link_cost` in [rngit], and the
        // other way round in [pages].
        cfg.costs = parse_costs(&ini, "rngit", &["stamp_value", "link_cost"])
            .map_err(|e| Error::msg(format!("{e} in {}", path.display())))?;
        cfg.pages_costs = parse_costs(&ini, "pages", &["link_cost", "stamp_value"])
            .map_err(|e| format!("{e} in {}", path.display()));
        if let Some(v) = get(&ini, "rngit", "record_stats") {
            cfg.record_stats = parse_bool(v, cfg.record_stats);
        }
        cfg.identity_aliases = parse_aliases(&ini, "aliases");
        if let Some(v) = get(&ini, "rngit", "stats_ignore_identities") {
            cfg.stats_ignore_identities = parse_identity_list(v, &cfg.identity_aliases);
        }
        if let Some(v) = get(&ini, "rngit", "stats_push_ignore_identities") {
            cfg.stats_push_ignore_identities = parse_identity_list(v, &cfg.identity_aliases);
        }
        if let Some(v) = get(&ini, "rngit", "blocked_identities") {
            cfg.blocked_identities = parse_identity_list(v, &cfg.identity_aliases);
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
        if let Some(v) = get(&ini, "pages", "media_conversion") {
            cfg.media_conversion = parse_bool(v, cfg.media_conversion);
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
        cfg.allow_propose = split_list(get(&ini, "access", "propose").unwrap_or("none"));
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
            costs: DestinationCosts::default(),
            pages_costs: Ok(DestinationCosts::default()),
            serve_nomadnet: false,
            templates_dir: dir.join("templates"),
            unicode_icons: false,
            media_conversion: true,
            record_stats: false,
            stats_ignore_identities: Vec::new(),
            stats_push_ignore_identities: Vec::new(),
            blocked_identities: Vec::new(),
            identity_aliases: BTreeMap::new(),
            allow_read: vec!["all".to_string()],
            allow_write: vec!["none".to_string()],
            allow_create: vec!["none".to_string()],
            allow_stats: vec!["none".to_string()],
            allow_release: vec!["none".to_string()],
            allow_interact: vec!["none".to_string()],
            allow_propose: vec!["none".to_string()],
            allow_admin: vec!["none".to_string()],
            log_level: DEFAULT_LOG_LEVEL,
        }
    }
}

impl ClientConfig {
    pub(crate) fn load_or_create_for_run(
        dir: PathBuf,
        reticulum_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let (config, _created) = Self::load_or_create(dir, reticulum_dir)?;
        Ok(config)
    }

    pub(crate) fn load_or_create(
        dir: PathBuf,
        reticulum_dir: Option<PathBuf>,
    ) -> Result<(Self, bool)> {
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
        cfg.destination_aliases = parse_aliases(&ini, "aliases");
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
            destination_aliases: BTreeMap::new(),
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

fn parse_identity_list(value: &str, aliases: &BTreeMap<String, [u8; 16]>) -> Vec<[u8; 16]> {
    split_list(value)
        .into_iter()
        .filter_map(|value| {
            aliases
                .get(&value)
                .copied()
                .or_else(|| parse_hex_16(&value).ok())
        })
        .collect()
}

fn parse_aliases(ini: &Ini, section: &str) -> BTreeMap<String, [u8; 16]> {
    ini.get(section)
        .into_iter()
        .flat_map(|section| section.iter())
        .filter_map(|(alias, value)| parse_hex_16(value).ok().map(|hash| (alias.clone(), hash)))
        .collect()
}

/// The `link_cost` and `stamp_value` of `section`, read in `order`. Each is
/// `RNS.Stamps.quantize_cost(section.as_float(key))`, and like upstream's
/// `as_float` or `quantize_cost` raising, a value that is not a float, or is
/// NaN or infinite, is an error.
fn parse_costs(
    ini: &Ini,
    section: &str,
    order: &[&str; 2],
) -> std::result::Result<DestinationCosts, String> {
    let mut costs = DestinationCosts::default();
    for key in order {
        let Some(value) = get(ini, section, key) else {
            continue;
        };
        let cost =
            quantize_cost(value).map_err(|e| format!("Invalid {key} in [{section}]: {e}"))?;
        if *key == "link_cost" {
            costs.link_cost = cost;
        } else {
            costs.stamp_value = Some(cost);
        }
    }
    Ok(costs)
}

/// `quantize_cost(as_float(value))`: Python's `float()`, then rounded to the
/// 1/256 grid and clamped to `0..=STAMP_COST_CAP` as `cost_to_fp` does, whose
/// `math.floor` raises for NaN and infinity.
fn quantize_cost(value: &str) -> std::result::Result<f64, String> {
    let cost = python_float(value)
        .ok_or_else(|| format!("could not convert string to float: '{value}'"))?;
    if cost.is_nan() {
        return Err("cannot convert float NaN to integer".into());
    }
    if cost.is_infinite() {
        return Err("cannot convert float infinity to integer".into());
    }
    Ok(rns_core::stamp::StampCost::from_f64(cost).as_f64())
}

/// Python's `float(value)`: surrounding whitespace, a sign, `inf`, `nan`,
/// and underscores between digits are accepted.
fn python_float(value: &str) -> Option<f64> {
    let value = value.trim();
    let chars: Vec<char> = value.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if *c == '_' {
            let digit = |j: Option<&char>| j.is_some_and(|c| c.is_ascii_digit());
            if i == 0 || !digit(chars.get(i - 1)) || !digit(chars.get(i + 1)) {
                return None;
            }
        }
    }
    value.replace('_', "").parse().ok()
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
        .map(|level| level.min(rns_net::logging::LOG_EXTREME))
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
    "[rngit]\nannounce_interval = 300\nidentity = repositories_identity\nclient_identity = client_identity\n# node_name = Anonymous Git Node\n\n# You can configure the required link stamp cost for\n# connecting to the repository node.\n\n# link_cost = 18.0\n\n# The target stamp value for the repositories destination\n# can also be configured.\n\n# stamp_value = 25.0\n\n# record_stats = no\n# stats_ignore_identities = 00112233445566778899aabbccddeeff\n# stats_push_ignore_identities = 0102030405060708090a0b0c0d0e0f10\n# blocked_identities = 00112233445566778899aabbccddeeff\n# To reject unidentified scrapers and crawlers, add the null identity hash:\n# blocked_identities = d7db22f63b453c23bb0688dde565b7c1\n\n[repositories]\npath = repositories\n\n[aliases]\n# alice = 00112233445566778899aabbccddeeff\n\n[access]\nread = all\nwrite = none\ncreate = none\nstats = none\nrelease = none\ninteract = none\npropose = none\nadmin = none\n\n[pages]\n# serve_nomadnet = no\n\n# You can configure the required link stamp cost for\n# connecting to the page node.\n\n# link_cost = 18.0\n\n# The target stamp value for the node destination can\n# also be configured.\n\n# stamp_value = 25.0\n\n# templates_dir = templates\n# unicode_icons = no\n# media_conversion = yes\n\n[logging]\nloglevel = 4\n"
}

fn default_client_config() -> &'static str {
    "[client]\nidentity = client_identity\nconnect_timeout = 30\nrequest_timeout = 300\n\n[aliases]\n# my_node = 00112233445566778899aabbccddeeff\n\n[logging]\nloglevel = 4\n"
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
        assert_eq!(cfg.log_level, 8);
    }

    #[test]
    fn client_run_config_continues_after_creating_default_config() {
        let tmp = tempfile::tempdir().unwrap();

        let cfg = ClientConfig::load_or_create_for_run(tmp.path().to_path_buf(), None).unwrap();

        assert_eq!(cfg.dir, tmp.path());
        assert!(tmp.path().join("client_config").exists());
    }

    #[test]
    fn server_run_config_continues_after_creating_default_config() {
        let tmp = tempfile::tempdir().unwrap();

        let cfg = ServerConfig::load_or_create_for_run(tmp.path().to_path_buf(), None).unwrap();

        assert_eq!(cfg.dir, tmp.path());
        assert!(tmp.path().join("server_config").exists());
    }

    #[test]
    fn creates_default_server_config_once() {
        let tmp = tempfile::tempdir().unwrap();
        let (_cfg, created) = ServerConfig::load_or_create(tmp.path().to_path_buf(), None).unwrap();
        assert!(created);
        let (_cfg, created) = ServerConfig::load_or_create(tmp.path().to_path_buf(), None).unwrap();
        assert!(!created);
        let generated = fs::read_to_string(tmp.path().join("server_config")).unwrap();
        assert!(generated.contains("blocked_identities = d7db22f63b453c23bb0688dde565b7c1"));
    }

    #[test]
    fn parses_nomadnet_page_config() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("server_config"),
            "[rngit]\nnode_name = Public Git Node\n[pages]\nserve_nomadnet = yes\ntemplates_dir = custom_templates\nunicode_icons = yes\nmedia_conversion = no\n",
        )
        .unwrap();
        let (cfg, created) = ServerConfig::load_or_create(tmp.path().to_path_buf(), None).unwrap();
        assert!(!created);
        assert_eq!(cfg.node_name, "Public Git Node");
        assert!(cfg.serve_nomadnet);
        assert_eq!(cfg.templates_dir, tmp.path().join("custom_templates"));
        assert!(cfg.unicode_icons);
        assert!(!cfg.media_conversion);
    }

    #[test]
    fn parses_stats_config_and_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("server_config"),
            "[rngit]\nrecord_stats = yes\nstats_ignore_identities = alice\nstats_push_ignore_identities = 0102030405060708090a0b0c0d0e0f10\nblocked_identities = alice\n[aliases]\nalice = 00112233445566778899aabbccddeeff\n[access]\nstats = all, 0102030405060708090a0b0c0d0e0f10\n",
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
            cfg.stats_push_ignore_identities,
            vec![[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10
            ]]
        );
        assert_eq!(cfg.blocked_identities, cfg.stats_ignore_identities);
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
    fn parses_client_destination_aliases() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("client_config"),
            "[client]\n[aliases]\nhome = 00112233445566778899aabbccddeeff\nbad = not-hex\n",
        )
        .unwrap();

        let (cfg, created) = ClientConfig::load_or_create(tmp.path().to_path_buf(), None).unwrap();

        assert!(!created);
        assert_eq!(cfg.destination_aliases.len(), 1);
        assert_eq!(cfg.destination_aliases["home"][15], 0xff);
    }

    #[test]
    fn parses_server_identity_aliases() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("server_config"),
            "[aliases]\nalice = 00112233445566778899aabbccddeeff\nbad = not-hex\n",
        )
        .unwrap();

        let (cfg, created) = ServerConfig::load_or_create(tmp.path().to_path_buf(), None).unwrap();

        assert!(!created);
        assert_eq!(cfg.identity_aliases.len(), 1);
        assert_eq!(cfg.identity_aliases["alice"][15], 0xff);
    }

    /// Upstream 05ac4bba: both destinations default to a link cost of 18.0
    /// and the node's own stamp target, and the generated config documents
    /// both keys in both sections.
    #[test]
    fn destination_costs_default_to_upstreams() {
        let tmp = tempfile::tempdir().unwrap();
        let (cfg, created) = ServerConfig::load_or_create(tmp.path().to_path_buf(), None).unwrap();
        assert!(created);
        let defaults = DestinationCosts {
            link_cost: 18.0,
            stamp_value: None,
        };
        assert_eq!(cfg.costs, defaults);
        assert_eq!(cfg.pages_costs, Ok(defaults));
        let (cfg, created) = ServerConfig::load_or_create(tmp.path().to_path_buf(), None).unwrap();
        assert!(!created);
        assert_eq!(cfg.costs, defaults);
        assert_eq!(cfg.pages_costs, Ok(defaults));
        let generated = fs::read_to_string(tmp.path().join("server_config")).unwrap();
        for section in [
            "# connecting to the repository node.\n\n# link_cost = 18.0\n\n# The target stamp value for the repositories destination\n# can also be configured.\n\n# stamp_value = 25.0\n",
            "# connecting to the page node.\n\n# link_cost = 18.0\n\n# The target stamp value for the node destination can\n# also be configured.\n\n# stamp_value = 25.0\n",
        ] {
            assert!(generated.contains(section), "{generated}");
        }
    }

    /// `quantize_cost(as_float(v))` per section: Python float syntax,
    /// rounding to the 1/256 grid and clamping to 0..=100.
    #[test]
    fn parses_and_quantizes_destination_costs() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("server_config"),
            "[rngit]\nlink_cost = 18.5\nstamp_value = 27.501\n[pages]\nlink_cost = 1_2.7\nstamp_value = -3\n",
        )
        .unwrap();
        let (cfg, _) = ServerConfig::load_or_create(tmp.path().to_path_buf(), None).unwrap();
        assert_eq!(
            cfg.costs,
            DestinationCosts {
                link_cost: 18.5,
                stamp_value: Some(27.5)
            }
        );
        let pages = cfg.pages_costs.unwrap();
        assert_eq!(pages.link_cost, 3251.0 / 256.0);
        // Clamped to 0, which upstream's `if self.stamp_value:` skips.
        assert_eq!(pages.stamp_value, Some(0.0));
        assert_eq!(pages.applied_stamp_value(), None);
        assert_eq!(cfg.costs.applied_stamp_value(), Some(27.5));

        for (value, quantized) in [(" 1e3 ", 100.0), ("+0.001", 0.0), ("0.002", 1.0 / 256.0)] {
            assert_eq!(quantize_cost(value), Ok(quantized), "{value}");
        }
    }

    /// As upstream, where `as_float` or `quantize_cost` raises: an invalid
    /// `[rngit]` cost stops startup, and an invalid `[pages]` one stops
    /// starting the page node.
    #[test]
    fn invalid_destination_costs_are_errors() {
        for value in ["abc", "", "nan", "-inf", "Infinity", "1__0", "_1", "18,0"] {
            assert!(quantize_cost(value).is_err(), "{value:?}");
        }
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("server_config");
        fs::write(&path, "[rngit]\nlink_cost = high\n").unwrap();
        let error = ServerConfig::load_or_create(tmp.path().to_path_buf(), None)
            .unwrap_err()
            .to_string();
        assert!(
            error.starts_with(
                "Invalid link_cost in [rngit]: could not convert string to float: 'high'"
            ),
            "{error}"
        );
        fs::write(&path, "[rngit]\nstamp_value = nan\n").unwrap();
        assert!(ServerConfig::load_or_create(tmp.path().to_path_buf(), None).is_err());

        fs::write(&path, "[pages]\nstamp_value = inf\n").unwrap();
        let (cfg, _) = ServerConfig::load_or_create(tmp.path().to_path_buf(), None).unwrap();
        let error = cfg.pages_costs.unwrap_err();
        assert!(
            error.starts_with(
                "Invalid stamp_value in [pages]: cannot convert float infinity to integer"
            ),
            "{error}"
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
        assert!(cfg.media_conversion);
        assert!(!cfg.record_stats);
        assert!(cfg.stats_ignore_identities.is_empty());
        assert_eq!(cfg.allow_stats, vec!["none".to_string()]);
        assert_eq!(cfg.allow_release, vec!["none".to_string()]);
        assert_eq!(cfg.allow_interact, vec!["none".to_string()]);
        assert_eq!(cfg.allow_admin, vec!["none".to_string()]);
    }
}
