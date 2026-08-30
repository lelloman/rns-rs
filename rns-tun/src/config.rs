use std::fmt;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

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

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Toml(String),
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

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub version: u8,
    pub state_dir: PathBuf,
    pub node_config_dir: PathBuf,
    #[serde(default = "default_mark")]
    pub underlay_mark: u32,
    pub status_socket: Option<PathBuf>,
    #[serde(default)]
    pub client: Option<ClientConfig>,
    #[serde(default)]
    pub gateway: Option<GatewayConfig>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    pub identity_file: Option<PathBuf>,
    #[serde(default)]
    pub allowed_routes: Vec<String>,
    #[serde(default)]
    pub requested_routes: Vec<String>,
    #[serde(default)]
    pub allow_default_route: bool,
    #[serde(default)]
    pub allowed_dns: Vec<Ipv4Addr>,
    #[serde(default = "default_client_tun")]
    pub tun_name: String,
    pub tun_mtu: Option<u16>,
    #[serde(default = "default_table")]
    pub routing_table: u32,
    #[serde(default = "default_underlay_priority")]
    pub underlay_rule_priority: u32,
    #[serde(default = "default_tunnel_priority")]
    pub tunnel_rule_priority: u32,
    #[serde(default = "default_physical_table")]
    pub physical_table: u32,
}
fn default_physical_table() -> u32 {
    254
}
#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub identity_file: Option<PathBuf>,
    pub address: String,
    pub policy_file: PathBuf,
    #[serde(default)]
    pub dns_servers: Vec<Ipv4Addr>,
    #[serde(default = "default_gateway_tun")]
    pub tun_name: String,
    #[serde(default = "default_announce")]
    pub announce_interval_seconds: u64,
    #[serde(default = "default_pending")]
    pub max_pending_links: usize,
    #[serde(default = "default_active")]
    pub max_active_sessions: usize,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        let mut cfg: Self =
            toml::from_str(&content).map_err(|e| ConfigError::Toml(e.to_string()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        cfg.resolve_relative(base);
        cfg.validate()?;
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
            let cidr: Cidr = g
                .address
                .parse()
                .map_err(|_| ConfigError::Invalid("invalid gateway address".into()))?;
            if cidr.prefix_len() == 0 || cidr.prefix_len() > 30 {
                return Err(ConfigError::Invalid(
                    "gateway prefix must be /1 through /30".into(),
                ));
            }
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
    fn full_tunnel_rejects_hostname_and_pipe() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("config"),
            "[interfaces]\n  [[uplink]]\n    type = TCPClientInterface\n    target_host = example.com\n    target_port = 4242\n",
        )
        .unwrap();
        assert!(validate_full_tunnel_node_config(directory.path()).is_err());
        fs::write(
            directory.path().join("config"),
            "[interfaces]\n  [[pipe]]\n    type = PipeInterface\n    command = /bin/false\n",
        )
        .unwrap();
        assert!(validate_full_tunnel_node_config(directory.path()).is_err());
    }
}
