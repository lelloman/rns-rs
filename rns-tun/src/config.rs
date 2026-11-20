//! The rntun TOML configuration file and its validation.

use std::fmt;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::de::IgnoredAny;
use serde::Deserialize;

use crate::policy::{is_forbidden_special, Cidr};

fn default_mark() -> u32 {
    0x5254
}
fn default_table() -> u32 {
    0x5254
}
fn default_underlay_priority() -> u32 {
    100
}
fn default_tunnel_priority() -> u32 {
    110
}
fn default_client_tun() -> String {
    "rntun0".into()
}
fn default_gateway_tun() -> String {
    "rntung0".into()
}
fn default_announce() -> u64 {
    1800
}
fn default_pending() -> usize {
    16
}
fn default_active() -> usize {
    64
}

/// Why a configuration could not be loaded or failed validation.
#[derive(Debug)]
pub enum ConfigError {
    /// A file could not be read.
    Io(std::io::Error),
    /// The file is not valid TOML or does not match the expected schema.
    Toml(String),
    /// The file parsed but a value is out of range or inconsistent; the
    /// message names the problem.
    Invalid(String),
}
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Toml(e) => write!(f, "invalid rntun TOML: {e}"),
            Self::Invalid(e) => write!(f, "invalid rntun config: {e}"),
        }
    }
}
impl std::error::Error for ConfigError {}
impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// A parsed rntun configuration file. Exactly one of `client` and `gateway`
/// is set once [`Config::validate`] has passed.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Configuration schema version; must be 1.
    pub version: u8,
    /// Directory for identities, the Linux ownership journal and the default
    /// status socket.
    pub state_dir: PathBuf,
    /// Reticulum configuration directory of the private node rntun starts.
    pub node_config_dir: PathBuf,
    /// Firewall mark put on the node's own sockets so their traffic bypasses
    /// the tunnel. Must be nonzero; defaults to `0x5254`.
    #[serde(default = "default_mark")]
    pub underlay_mark: u32,
    /// Path of the status Unix socket; `state_dir/status.sock` when unset.
    pub status_socket: Option<PathBuf>,
    /// Client settings; present when this host connects to a gateway.
    #[serde(default)]
    pub client: Option<ClientConfig>,
    /// Gateway settings; present when this host serves clients.
    #[serde(default)]
    pub gateway: Option<GatewayConfig>,
}
/// The `[client]` section.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    /// Client identity file; `state_dir/client_identity` when unset. Created
    /// on first use.
    pub identity_file: Option<PathBuf>,
    /// IPv4 CIDRs the client trusts the gateway to route; a granted route
    /// outside all of them fails the handshake.
    #[serde(default)]
    pub allowed_routes: Vec<String>,
    /// IPv4 CIDRs the client asks the gateway to route through the tunnel.
    #[serde(default)]
    pub requested_routes: Vec<String>,
    /// Route all IPv4 traffic through the tunnel. Must be true exactly when
    /// both route lists contain `0.0.0.0/0`, and needs `allowed_dns`.
    #[serde(default)]
    pub allow_default_route: bool,
    /// DNS resolvers the client accepts from the gateway; any other
    /// advertised resolver fails the handshake.
    #[serde(default)]
    pub allowed_dns: Vec<Ipv4Addr>,
    /// TUN interface name; defaults to `rntun0`.
    #[serde(default = "default_client_tun")]
    pub tun_name: String,
    /// Largest packet, in bytes, the client offers to carry, within
    /// 576..=1500; 1280 when unset.
    pub tun_mtu: Option<u16>,
    /// Policy routing table that holds the tunnel routes; defaults to
    /// `0x5254`.
    #[serde(default = "default_table")]
    pub routing_table: u32,
    /// Priority of the rule that sends marked underlay traffic to
    /// `physical_table`; must be lower than `tunnel_rule_priority`.
    #[serde(default = "default_underlay_priority")]
    pub underlay_rule_priority: u32,
    /// Priority of the rules that send traffic to `routing_table`.
    #[serde(default = "default_tunnel_priority")]
    pub tunnel_rule_priority: u32,
    /// Routing table the underlay traffic uses; defaults to 254 (`main`).
    #[serde(default = "default_physical_table")]
    pub physical_table: u32,
}
fn default_physical_table() -> u32 {
    254
}
/// The `[gateway]` section.
#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    /// Gateway identity file; `state_dir/gateway_identity` when unset.
    /// Created on first use.
    pub identity_file: Option<PathBuf>,
    /// Path of the client policy TOML (see
    /// [`GatewayPolicy`](crate::policy::GatewayPolicy)). Reloaded when it
    /// changes on disk.
    pub policy_file: PathBuf,
    /// DNS resolvers advertised to full-tunnel clients; at most four.
    #[serde(default)]
    pub dns_servers: Vec<Ipv4Addr>,
    /// TUN interface name; defaults to `rntung0`.
    #[serde(default = "default_gateway_tun")]
    pub tun_name: String,
    /// Seconds between announces of the gateway destination; defaults to
    /// 1800.
    #[serde(default = "default_announce")]
    pub announce_interval_seconds: u64,
    /// Links that may be mid-handshake at once, 1..=64; defaults to 16.
    #[serde(default = "default_pending")]
    pub max_pending_links: usize,
    /// Sessions that may be active at once, 1..=256; defaults to 64.
    #[serde(default = "default_active")]
    pub max_active_sessions: usize,
    /// The removed `address` key. Older configs carried it; the gateway
    /// address comes from the policy file, so [`Config::load`] only warns.
    #[serde(default, rename = "address")]
    legacy_address: Option<IgnoredAny>,
}

impl Config {
    /// Read, parse and validate the file at `path`. Relative paths inside it
    /// are resolved against the file's directory.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        let mut cfg: Self =
            toml::from_str(&content).map_err(|e| ConfigError::Toml(e.to_string()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        cfg.resolve_relative(base);
        cfg.validate()?;
        if let Some(gateway) = &cfg.gateway {
            if gateway.legacy_address.is_some() {
                log::warn!(
                    "{}: ignoring [gateway] address; the gateway address comes from the policy file {}",
                    path.display(),
                    gateway.policy_file.display()
                );
            }
        }
        Ok(cfg)
    }
    fn resolve_relative(&mut self, base: &Path) {
        if self.state_dir.is_relative() {
            self.state_dir = base.join(&self.state_dir)
        }
        if self.node_config_dir.is_relative() {
            self.node_config_dir = base.join(&self.node_config_dir)
        }
        if let Some(path) = &self.status_socket {
            if path.is_relative() {
                self.status_socket = Some(base.join(path));
            }
        }
        if let Some(client) = &mut self.client {
            if let Some(path) = &client.identity_file {
                if path.is_relative() {
                    client.identity_file = Some(base.join(path));
                }
            }
        }
        if let Some(gateway) = &mut self.gateway {
            if gateway.policy_file.is_relative() {
                gateway.policy_file = base.join(&gateway.policy_file)
            }
            if let Some(path) = &gateway.identity_file {
                if path.is_relative() {
                    gateway.identity_file = Some(base.join(path));
                }
            }
        }
    }
    /// Check value ranges and cross-field rules. [`Config::load`] already
    /// calls this; call it again after changing a loaded config.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(ConfigError::Invalid("version must be 1".into()));
        }
        if self.underlay_mark == 0 {
            return Err(ConfigError::Invalid("underlay_mark must be nonzero".into()));
        }
        if self.client.is_none() == self.gateway.is_none() {
            return Err(ConfigError::Invalid(
                "exactly one client or gateway section is required".into(),
            ));
        }
        if let Some(c) = &self.client {
            if let Some(mtu) = c.tun_mtu {
                if !(576..=1500).contains(&mtu) {
                    return Err(ConfigError::Invalid("tun_mtu must be 576..=1500".into()));
                }
            }
            for route in c.allowed_routes.iter().chain(&c.requested_routes) {
                route
                    .parse::<Cidr>()
                    .map_err(|_| ConfigError::Invalid(format!("invalid route {route}")))?;
            }
            let allowed_default = c.allowed_routes.iter().any(|route| route == "0.0.0.0/0");
            let requested_default = c.requested_routes.iter().any(|route| route == "0.0.0.0/0");
            if c.allow_default_route != (allowed_default && requested_default) {
                return Err(ConfigError::Invalid(
                    "allow_default_route requires 0.0.0.0/0 in both allowed_routes and requested_routes"
                        .into(),
                ));
            }
            if c.allow_default_route && c.allowed_dns.is_empty() {
                return Err(ConfigError::Invalid(
                    "full tunnel requires allowed_dns".into(),
                ));
            }
            if c.allowed_dns
                .iter()
                .any(|address| is_forbidden_special(*address))
            {
                return Err(ConfigError::Invalid(
                    "allowed_dns contains a special-use address".into(),
                ));
            }
            if c.underlay_rule_priority >= c.tunnel_rule_priority {
                return Err(ConfigError::Invalid(
                    "underlay rule must precede tunnel rule".into(),
                ));
            }
        }
        if let Some(g) = &self.gateway {
            if g.max_pending_links == 0
                || g.max_pending_links > 64
                || g.max_active_sessions == 0
                || g.max_active_sessions > 256
            {
                return Err(ConfigError::Invalid(
                    "gateway capacities out of range".into(),
                ));
            }
            if g.dns_servers.len() > 4 {
                return Err(ConfigError::Invalid("at most four DNS servers".into()));
            }
            if g.dns_servers
                .iter()
                .any(|address| is_forbidden_special(*address))
            {
                return Err(ConfigError::Invalid(
                    "dns_servers contains a special-use address".into(),
                ));
            }
        }
        Ok(())
    }
}

/// `$XDG_CONFIG_HOME/rntun/config.toml`, else `$HOME/.config/rntun/config.toml`,
/// else `rntun.toml` in the current directory.
pub fn default_config_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(dir).join("rntun/config.toml")
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".config/rntun/config.toml")
    } else {
        PathBuf::from("rntun.toml")
    }
}

/// Enforce the Linux full-tunnel underlay allowlist before policy routing is
/// changed. Hostnames and externally owned carrier processes cannot inherit
/// the private node's socket mark and are rejected.
pub fn validate_full_tunnel_node_config(config_dir: &Path) -> Result<(), ConfigError> {
    let content = fs::read_to_string(config_dir.join("config"))?;
    validate_full_tunnel_node_config_text(&content)
}

/// [`validate_full_tunnel_node_config`] for the contents of a Reticulum
/// config file instead of its directory.
pub fn validate_full_tunnel_node_config_text(content: &str) -> Result<(), ConfigError> {
    let parsed = rns_net::config::parse(content)
        .map_err(|error| ConfigError::Invalid(format!("invalid Reticulum config: {error}")))?;
    for interface in parsed
        .interfaces
        .iter()
        .filter(|interface| interface.enabled)
    {
        match interface.interface_type.as_str() {
            "TCPClientInterface"
            | "TCPServerInterface"
            | "UDPInterface"
            | "AutoInterface"
            | "BackboneInterface"
            | "BackboneClientInterface"
            | "SerialInterface"
            | "KISSInterface"
            | "AX25KISSInterface"
            | "RNodeInterface"
            | "RNodeMultiInterface" => {}
            other => {
                return Err(ConfigError::Invalid(format!(
                    "interface '{}' uses unsafe full-tunnel type '{other}'",
                    interface.name
                )))
            }
        }
        validate_numeric_endpoints(&interface.name, &interface.params)?;
        for child in &interface.subinterfaces {
            validate_numeric_endpoints(&child.name, &child.params)?;
        }
    }
    Ok(())
}

fn validate_numeric_endpoints(
    interface_name: &str,
    params: &std::collections::HashMap<String, String>,
) -> Result<(), ConfigError> {
    for key in ["target_host", "remote", "listen_ip", "forward_ip"] {
        if let Some(value) = params.get(key) {
            if value.parse::<std::net::IpAddr>().is_err() {
                return Err(ConfigError::Invalid(format!(
                    "full-tunnel interface '{interface_name}' requires numeric {key}, got '{value}'"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_config() {
        let cfg: Config = toml::from_str("version=1\nstate_dir='state'\nnode_config_dir='node'\n[client]\nallow_default_route=true\nallowed_routes=['0.0.0.0/0']\nrequested_routes=['0.0.0.0/0']\nallowed_dns=['1.1.1.1']\n").unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.underlay_mark, 0x5254);
    }

    #[test]
    fn gateway_address_key_is_accepted_and_ignored() {
        let base = "version=1\nstate_dir='state'\nnode_config_dir='node'\n[gateway]\npolicy_file='policy.toml'\n";
        let cfg: Config = toml::from_str(base).unwrap();
        cfg.validate().unwrap();
        assert!(cfg.gateway.unwrap().legacy_address.is_none());
        let cfg: Config = toml::from_str(&format!("{base}address='not a cidr'\n")).unwrap();
        cfg.validate().unwrap();
        assert!(cfg.gateway.unwrap().legacy_address.is_some());
    }

    #[test]
    fn full_tunnel_rejects_hostname_and_pipe() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("config"),
            "[interfaces]\n  [[uplink]]\n    type = TCPClientInterface\n    enabled = yes\n    target_host = example.com\n    target_port = 4242\n",
        )
        .unwrap();
        assert!(validate_full_tunnel_node_config(directory.path()).is_err());
        fs::write(
            directory.path().join("config"),
            "[interfaces]\n  [[pipe]]\n    type = PipeInterface\n    enabled = yes\n    command = /bin/false\n",
        )
        .unwrap();
        assert!(validate_full_tunnel_node_config(directory.path()).is_err());
    }
}
