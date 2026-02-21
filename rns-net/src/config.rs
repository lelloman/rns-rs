//! ConfigObj parser for RNS config files.
//!
//! Python RNS uses ConfigObj format — NOT TOML, NOT standard INI.
//! Key differences: nested `[[sections]]`, booleans `Yes`/`No`/`True`/`False`,
//! comments with `#`, unquoted string values.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::io;

/// Parsed RNS configuration.
#[derive(Debug, Clone)]
pub struct RnsConfig {
    pub reticulum: ReticulumSection,
    pub logging: LoggingSection,
    pub interfaces: Vec<ParsedInterface>,
    pub hooks: Vec<ParsedHook>,
}

/// A parsed hook from `[[subsection]]` within `[hooks]`.
#[derive(Debug, Clone)]
pub struct ParsedHook {
    pub name: String,
    pub path: String,
    pub attach_point: String,
    pub priority: i32,
    pub enabled: bool,
}

/// The `[reticulum]` section.
#[derive(Debug, Clone)]
pub struct ReticulumSection {
    pub enable_transport: bool,
    pub share_instance: bool,
    pub instance_name: String,
    pub shared_instance_port: u16,
    pub instance_control_port: u16,
    pub panic_on_interface_error: bool,
    pub use_implicit_proof: bool,
    pub network_identity: Option<String>,
    pub respond_to_probes: bool,
    pub enable_remote_management: bool,
    pub remote_management_allowed: Vec<String>,
    pub publish_blackhole: bool,
    pub probe_port: Option<u16>,
    pub probe_addr: Option<String>,
    /// Network interface to bind outbound sockets to (e.g. "usb0").
    pub device: Option<String>,
    /// Enable interface discovery (advertise discoverable interfaces and
    /// listen for discovery announces from the network).
    pub discover_interfaces: bool,
    /// Minimum stamp value for accepting discovered interfaces.
    pub required_discovery_value: Option<u8>,
}

impl Default for ReticulumSection {
    fn default() -> Self {
        ReticulumSection {
            enable_transport: false,
            share_instance: true,
            instance_name: "default".into(),
            shared_instance_port: 37428,
            instance_control_port: 37429,
            panic_on_interface_error: false,
            use_implicit_proof: true,
            network_identity: None,
            respond_to_probes: false,
            enable_remote_management: false,
            remote_management_allowed: Vec::new(),
            publish_blackhole: false,
            probe_port: None,
            probe_addr: None,
            device: None,
            discover_interfaces: false,
            required_discovery_value: None,
        }
    }
}

/// The `[logging]` section.
#[derive(Debug, Clone)]
pub struct LoggingSection {
    pub loglevel: u8,
}

impl Default for LoggingSection {
    fn default() -> Self {
        LoggingSection { loglevel: 4 }
    }
}

/// A parsed interface from `[[subsection]]` within `[interfaces]`.
#[derive(Debug, Clone)]
pub struct ParsedInterface {
    pub name: String,
    pub interface_type: String,
    pub enabled: bool,
    pub mode: String,
    pub params: HashMap<String, String>,
}

/// Configuration parse error.
#[derive(Debug, Clone)]
pub enum ConfigError {
    Io(String),
    Parse(String),
    InvalidValue { key: String, value: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(msg) => write!(f, "Config I/O error: {}", msg),
            ConfigError::Parse(msg) => write!(f, "Config parse error: {}", msg),
            ConfigError::InvalidValue { key, value } => {
                write!(f, "Invalid value for '{}': '{}'", key, value)
            }
        }
    }
}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> Self {
        ConfigError::Io(e.to_string())
    }
}

/// Parse a config string into an `RnsConfig`.
pub fn parse(input: &str) -> Result<RnsConfig, ConfigError> {
    let mut current_section: Option<String> = None;
    let mut current_subsection: Option<String> = None;

    let mut reticulum_kvs: HashMap<String, String> = HashMap::new();
    let mut logging_kvs: HashMap<String, String> = HashMap::new();
    let mut interfaces: Vec<ParsedInterface> = Vec::new();
    let mut current_iface_kvs: Option<HashMap<String, String>> = None;
    let mut current_iface_name: Option<String> = None;
    let mut hooks: Vec<ParsedHook> = Vec::new();
    let mut current_hook_kvs: Option<HashMap<String, String>> = None;
    let mut current_hook_name: Option<String> = None;

    for line in input.lines() {
        // Strip comments (# to end of line, unless inside quotes)
        let line = strip_comment(line);
        let trimmed = line.trim();

        // Skip empty lines
        if trimmed.is_empty() {
            continue;
        }

        // Check for subsection [[name]]
        if trimmed.starts_with("[[") && trimmed.ends_with("]]") {
            let name = trimmed[2..trimmed.len() - 2].trim().to_string();
            // Finalize previous interface subsection if any
            if let (Some(iface_name), Some(kvs)) =
                (current_iface_name.take(), current_iface_kvs.take())
            {
                interfaces.push(build_parsed_interface(iface_name, kvs));
            }
            // Finalize previous hook subsection if any
            if let (Some(hook_name), Some(kvs)) =
                (current_hook_name.take(), current_hook_kvs.take())
            {
                hooks.push(build_parsed_hook(hook_name, kvs));
            }
            current_subsection = Some(name.clone());
            // Determine which section we're in to know subsection type
            if current_section.as_deref() == Some("hooks") {
                current_hook_name = Some(name);
                current_hook_kvs = Some(HashMap::new());
            } else {
                current_iface_name = Some(name);
                current_iface_kvs = Some(HashMap::new());
            }
            continue;
        }

        // Check for section [name]
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            // Finalize previous interface subsection if any
            if let (Some(iface_name), Some(kvs)) =
                (current_iface_name.take(), current_iface_kvs.take())
            {
                interfaces.push(build_parsed_interface(iface_name, kvs));
            }
            // Finalize previous hook subsection if any
            if let (Some(hook_name), Some(kvs)) =
                (current_hook_name.take(), current_hook_kvs.take())
            {
                hooks.push(build_parsed_hook(hook_name, kvs));
            }
            current_subsection = None;

            let name = trimmed[1..trimmed.len() - 1].trim().to_lowercase();
            current_section = Some(name);
            continue;
        }

        // Parse key = value
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim().to_string();
            let value = trimmed[eq_pos + 1..].trim().to_string();

            if current_subsection.is_some() {
                // Inside a [[subsection]] — exactly one of these should be Some
                debug_assert!(
                    !(current_hook_kvs.is_some() && current_iface_kvs.is_some()),
                    "hook and interface subsections should never be active simultaneously"
                );
                if let Some(ref mut kvs) = current_hook_kvs {
                    kvs.insert(key, value);
                } else if let Some(ref mut kvs) = current_iface_kvs {
                    kvs.insert(key, value);
                }
            } else if let Some(ref section) = current_section {
                match section.as_str() {
                    "reticulum" => {
                        reticulum_kvs.insert(key, value);
                    }
                    "logging" => {
                        logging_kvs.insert(key, value);
                    }
                    _ => {} // ignore unknown sections
                }
            }
        }
    }

    // Finalize last subsections
    if let (Some(iface_name), Some(kvs)) = (current_iface_name.take(), current_iface_kvs.take()) {
        interfaces.push(build_parsed_interface(iface_name, kvs));
    }
    if let (Some(hook_name), Some(kvs)) = (current_hook_name.take(), current_hook_kvs.take()) {
        hooks.push(build_parsed_hook(hook_name, kvs));
    }

    // Build typed sections
    let reticulum = build_reticulum_section(&reticulum_kvs)?;
    let logging = build_logging_section(&logging_kvs)?;

    Ok(RnsConfig {
        reticulum,
        logging,
        interfaces,
        hooks,
    })
}

/// Parse a config file from disk.
pub fn parse_file(path: &Path) -> Result<RnsConfig, ConfigError> {
    let content = std::fs::read_to_string(path)?;
    parse(&content)
}

/// Strip `#` comments from a line (simple: not inside quotes).
fn strip_comment(line: &str) -> &str {
    // Find # that is not inside quotes
    let mut in_quote = false;
    let mut quote_char = '"';
    for (i, ch) in line.char_indices() {
        if !in_quote && (ch == '"' || ch == '\'') {
            in_quote = true;
            quote_char = ch;
        } else if in_quote && ch == quote_char {
            in_quote = false;
        } else if !in_quote && ch == '#' {
            return &line[..i];
        }
    }
    line
}

/// Parse a string as a boolean (ConfigObj style). Public API for use by node.rs.
pub fn parse_bool_pub(value: &str) -> Option<bool> {
    parse_bool(value)
}

/// Parse a string as a boolean (ConfigObj style).
fn parse_bool(value: &str) -> Option<bool> {
    match value.to_lowercase().as_str() {
        "yes" | "true" | "1" | "on" => Some(true),
        "no" | "false" | "0" | "off" => Some(false),
        _ => None,
    }
}

fn build_parsed_interface(name: String, mut kvs: HashMap<String, String>) -> ParsedInterface {
    let interface_type = kvs.remove("type").unwrap_or_default();
    let enabled = kvs
        .remove("enabled")
        .and_then(|v| parse_bool(&v))
        .unwrap_or(true);
    // Python checks `interface_mode` first, then falls back to `mode`
    let mode = kvs
        .remove("interface_mode")
        .or_else(|| kvs.remove("mode"))
        .unwrap_or_else(|| "full".into());

    ParsedInterface {
        name,
        interface_type,
        enabled,
        mode,
        params: kvs,
    }
}

fn build_parsed_hook(name: String, mut kvs: HashMap<String, String>) -> ParsedHook {
    let path = kvs.remove("path").unwrap_or_default();
    let attach_point = kvs.remove("attach_point").unwrap_or_default();
    let priority = kvs
        .remove("priority")
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0);
    let enabled = kvs
        .remove("enabled")
        .and_then(|v| parse_bool(&v))
        .unwrap_or(true);

    ParsedHook {
        name,
        path,
        attach_point,
        priority,
        enabled,
    }
}

/// Map a hook point name string to its index. Returns None for unknown names.
pub fn parse_hook_point(s: &str) -> Option<usize> {
    match s {
        "PreIngress" => Some(0),
        "PreDispatch" => Some(1),
        "AnnounceReceived" => Some(2),
        "PathUpdated" => Some(3),
        "AnnounceRetransmit" => Some(4),
        "LinkRequestReceived" => Some(5),
        "LinkEstablished" => Some(6),
        "LinkClosed" => Some(7),
        "InterfaceUp" => Some(8),
        "InterfaceDown" => Some(9),
        "InterfaceConfigChanged" => Some(10),
        "SendOnInterface" => Some(11),
        "BroadcastOnAllInterfaces" => Some(12),
        "DeliverLocal" => Some(13),
        "TunnelSynthesize" => Some(14),
        "Tick" => Some(15),
        _ => None,
    }
}

fn build_reticulum_section(
    kvs: &HashMap<String, String>,
) -> Result<ReticulumSection, ConfigError> {
    let mut section = ReticulumSection::default();

    if let Some(v) = kvs.get("enable_transport") {
        section.enable_transport = parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "enable_transport".into(),
            value: v.clone(),
        })?;
    }
    if let Some(v) = kvs.get("share_instance") {
        section.share_instance = parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "share_instance".into(),
            value: v.clone(),
        })?;
    }
    if let Some(v) = kvs.get("instance_name") {
        section.instance_name = v.clone();
    }
    if let Some(v) = kvs.get("shared_instance_port") {
        section.shared_instance_port =
            v.parse::<u16>().map_err(|_| ConfigError::InvalidValue {
                key: "shared_instance_port".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("instance_control_port") {
        section.instance_control_port =
            v.parse::<u16>().map_err(|_| ConfigError::InvalidValue {
                key: "instance_control_port".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("panic_on_interface_error") {
        section.panic_on_interface_error =
            parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
                key: "panic_on_interface_error".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("use_implicit_proof") {
        section.use_implicit_proof = parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "use_implicit_proof".into(),
            value: v.clone(),
        })?;
    }
    if let Some(v) = kvs.get("network_identity") {
        section.network_identity = Some(v.clone());
    }
    if let Some(v) = kvs.get("respond_to_probes") {
        section.respond_to_probes = parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "respond_to_probes".into(),
            value: v.clone(),
        })?;
    }
    if let Some(v) = kvs.get("enable_remote_management") {
        section.enable_remote_management = parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "enable_remote_management".into(),
            value: v.clone(),
        })?;
    }
    if let Some(v) = kvs.get("remote_management_allowed") {
        // Value is a comma-separated list of hex identity hashes
        for item in v.split(',') {
            let trimmed = item.trim();
            if !trimmed.is_empty() {
                section.remote_management_allowed.push(trimmed.to_string());
            }
        }
    }
    if let Some(v) = kvs.get("publish_blackhole") {
        section.publish_blackhole = parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "publish_blackhole".into(),
            value: v.clone(),
        })?;
    }
    if let Some(v) = kvs.get("probe_port") {
        section.probe_port = Some(v.parse::<u16>().map_err(|_| ConfigError::InvalidValue {
            key: "probe_port".into(),
            value: v.clone(),
        })?);
    }
    if let Some(v) = kvs.get("probe_addr") {
        section.probe_addr = Some(v.clone());
    }
    if let Some(v) = kvs.get("device") {
        section.device = Some(v.clone());
    }
    if let Some(v) = kvs.get("discover_interfaces") {
        section.discover_interfaces = parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "discover_interfaces".into(),
            value: v.clone(),
        })?;
    }
    if let Some(v) = kvs.get("required_discovery_value") {
        section.required_discovery_value = Some(v.parse::<u8>().map_err(|_| ConfigError::InvalidValue {
            key: "required_discovery_value".into(),
            value: v.clone(),
        })?);
    }

    Ok(section)
}

fn build_logging_section(kvs: &HashMap<String, String>) -> Result<LoggingSection, ConfigError> {
    let mut section = LoggingSection::default();

    if let Some(v) = kvs.get("loglevel") {
        section.loglevel = v.parse::<u8>().map_err(|_| ConfigError::InvalidValue {
            key: "loglevel".into(),
            value: v.clone(),
        })?;
    }

    Ok(section)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty() {
        let config = parse("").unwrap();
        assert!(!config.reticulum.enable_transport);
        assert!(config.reticulum.share_instance);
        assert_eq!(config.reticulum.instance_name, "default");
        assert_eq!(config.logging.loglevel, 4);
        assert!(config.interfaces.is_empty());
    }

    #[test]
    fn parse_default_config() {
        // The default config from Python's __default_rns_config__
        let input = r#"
[reticulum]
enable_transport = False
share_instance = Yes
instance_name = default

[logging]
loglevel = 4

[interfaces]

  [[Default Interface]]
    type = AutoInterface
    enabled = Yes
"#;
        let config = parse(input).unwrap();
        assert!(!config.reticulum.enable_transport);
        assert!(config.reticulum.share_instance);
        assert_eq!(config.reticulum.instance_name, "default");
        assert_eq!(config.logging.loglevel, 4);
        assert_eq!(config.interfaces.len(), 1);
        assert_eq!(config.interfaces[0].name, "Default Interface");
        assert_eq!(config.interfaces[0].interface_type, "AutoInterface");
        assert!(config.interfaces[0].enabled);
    }

    #[test]
    fn parse_reticulum_section() {
        let input = r#"
[reticulum]
enable_transport = True
share_instance = No
instance_name = mynode
shared_instance_port = 12345
instance_control_port = 12346
panic_on_interface_error = Yes
use_implicit_proof = False
respond_to_probes = True
network_identity = /home/user/.reticulum/identity
"#;
        let config = parse(input).unwrap();
        assert!(config.reticulum.enable_transport);
        assert!(!config.reticulum.share_instance);
        assert_eq!(config.reticulum.instance_name, "mynode");
        assert_eq!(config.reticulum.shared_instance_port, 12345);
        assert_eq!(config.reticulum.instance_control_port, 12346);
        assert!(config.reticulum.panic_on_interface_error);
        assert!(!config.reticulum.use_implicit_proof);
        assert!(config.reticulum.respond_to_probes);
        assert_eq!(
            config.reticulum.network_identity.as_deref(),
            Some("/home/user/.reticulum/identity")
        );
    }

    #[test]
    fn parse_logging_section() {
        let input = "[logging]\nloglevel = 6\n";
        let config = parse(input).unwrap();
        assert_eq!(config.logging.loglevel, 6);
    }

    #[test]
    fn parse_interface_tcp_client() {
        let input = r#"
[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    enabled = Yes
    target_host = 87.106.8.245
    target_port = 4242
"#;
        let config = parse(input).unwrap();
        assert_eq!(config.interfaces.len(), 1);
        let iface = &config.interfaces[0];
        assert_eq!(iface.name, "TCP Client");
        assert_eq!(iface.interface_type, "TCPClientInterface");
        assert!(iface.enabled);
        assert_eq!(iface.params.get("target_host").unwrap(), "87.106.8.245");
        assert_eq!(iface.params.get("target_port").unwrap(), "4242");
    }

    #[test]
    fn parse_interface_tcp_server() {
        let input = r#"
[interfaces]
  [[TCP Server]]
    type = TCPServerInterface
    enabled = Yes
    listen_ip = 0.0.0.0
    listen_port = 4242
"#;
        let config = parse(input).unwrap();
        assert_eq!(config.interfaces.len(), 1);
        let iface = &config.interfaces[0];
        assert_eq!(iface.name, "TCP Server");
        assert_eq!(iface.interface_type, "TCPServerInterface");
        assert_eq!(iface.params.get("listen_ip").unwrap(), "0.0.0.0");
        assert_eq!(iface.params.get("listen_port").unwrap(), "4242");
    }

    #[test]
    fn parse_interface_udp() {
        let input = r#"
[interfaces]
  [[UDP Interface]]
    type = UDPInterface
    enabled = Yes
    listen_ip = 0.0.0.0
    listen_port = 4242
    forward_ip = 255.255.255.255
    forward_port = 4242
"#;
        let config = parse(input).unwrap();
        assert_eq!(config.interfaces.len(), 1);
        let iface = &config.interfaces[0];
        assert_eq!(iface.name, "UDP Interface");
        assert_eq!(iface.interface_type, "UDPInterface");
        assert_eq!(iface.params.get("listen_ip").unwrap(), "0.0.0.0");
        assert_eq!(iface.params.get("forward_ip").unwrap(), "255.255.255.255");
    }

    #[test]
    fn parse_multiple_interfaces() {
        let input = r#"
[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    target_host = 10.0.0.1
    target_port = 4242

  [[UDP Broadcast]]
    type = UDPInterface
    listen_ip = 0.0.0.0
    listen_port = 5555
    forward_ip = 255.255.255.255
    forward_port = 5555
"#;
        let config = parse(input).unwrap();
        assert_eq!(config.interfaces.len(), 2);
        assert_eq!(config.interfaces[0].name, "TCP Client");
        assert_eq!(config.interfaces[0].interface_type, "TCPClientInterface");
        assert_eq!(config.interfaces[1].name, "UDP Broadcast");
        assert_eq!(config.interfaces[1].interface_type, "UDPInterface");
    }

    #[test]
    fn parse_booleans() {
        // Test all boolean variants
        for (input, expected) in &[
            ("Yes", true),
            ("No", false),
            ("True", true),
            ("False", false),
            ("true", true),
            ("false", false),
            ("1", true),
            ("0", false),
            ("on", true),
            ("off", false),
        ] {
            let result = parse_bool(input);
            assert_eq!(result, Some(*expected), "parse_bool({}) failed", input);
        }
    }

    #[test]
    fn parse_comments() {
        let input = r#"
# This is a comment
[reticulum]
enable_transport = True  # inline comment
# share_instance = No
instance_name = test
"#;
        let config = parse(input).unwrap();
        assert!(config.reticulum.enable_transport);
        assert!(config.reticulum.share_instance); // commented out line should be ignored
        assert_eq!(config.reticulum.instance_name, "test");
    }

    #[test]
    fn parse_interface_mode_field() {
        let input = r#"
[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    interface_mode = access_point
    target_host = 10.0.0.1
    target_port = 4242
"#;
        let config = parse(input).unwrap();
        assert_eq!(config.interfaces[0].mode, "access_point");
    }

    #[test]
    fn parse_mode_fallback() {
        // Python also accepts "mode" as fallback for "interface_mode"
        let input = r#"
[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    mode = gateway
    target_host = 10.0.0.1
    target_port = 4242
"#;
        let config = parse(input).unwrap();
        assert_eq!(config.interfaces[0].mode, "gateway");
    }

    #[test]
    fn parse_interface_mode_takes_precedence() {
        // If both interface_mode and mode are set, interface_mode wins
        let input = r#"
[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    interface_mode = roaming
    mode = boundary
    target_host = 10.0.0.1
    target_port = 4242
"#;
        let config = parse(input).unwrap();
        assert_eq!(config.interfaces[0].mode, "roaming");
    }

    #[test]
    fn parse_disabled_interface() {
        let input = r#"
[interfaces]
  [[Disabled TCP]]
    type = TCPClientInterface
    enabled = No
    target_host = 10.0.0.1
    target_port = 4242
"#;
        let config = parse(input).unwrap();
        assert_eq!(config.interfaces.len(), 1);
        assert!(!config.interfaces[0].enabled);
    }

    #[test]
    fn parse_serial_interface() {
        let input = r#"
[interfaces]
  [[Serial Port]]
    type = SerialInterface
    enabled = Yes
    port = /dev/ttyUSB0
    speed = 115200
    databits = 8
    parity = N
    stopbits = 1
"#;
        let config = parse(input).unwrap();
        assert_eq!(config.interfaces.len(), 1);
        let iface = &config.interfaces[0];
        assert_eq!(iface.name, "Serial Port");
        assert_eq!(iface.interface_type, "SerialInterface");
        assert!(iface.enabled);
        assert_eq!(iface.params.get("port").unwrap(), "/dev/ttyUSB0");
        assert_eq!(iface.params.get("speed").unwrap(), "115200");
        assert_eq!(iface.params.get("databits").unwrap(), "8");
        assert_eq!(iface.params.get("parity").unwrap(), "N");
        assert_eq!(iface.params.get("stopbits").unwrap(), "1");
    }

    #[test]
    fn parse_kiss_interface() {
        let input = r#"
[interfaces]
  [[KISS TNC]]
    type = KISSInterface
    enabled = Yes
    port = /dev/ttyUSB1
    speed = 9600
    preamble = 350
    txtail = 20
    persistence = 64
    slottime = 20
    flow_control = True
    id_interval = 600
    id_callsign = MYCALL
"#;
        let config = parse(input).unwrap();
        assert_eq!(config.interfaces.len(), 1);
        let iface = &config.interfaces[0];
        assert_eq!(iface.name, "KISS TNC");
        assert_eq!(iface.interface_type, "KISSInterface");
        assert_eq!(iface.params.get("port").unwrap(), "/dev/ttyUSB1");
        assert_eq!(iface.params.get("speed").unwrap(), "9600");
        assert_eq!(iface.params.get("preamble").unwrap(), "350");
        assert_eq!(iface.params.get("txtail").unwrap(), "20");
        assert_eq!(iface.params.get("persistence").unwrap(), "64");
        assert_eq!(iface.params.get("slottime").unwrap(), "20");
        assert_eq!(iface.params.get("flow_control").unwrap(), "True");
        assert_eq!(iface.params.get("id_interval").unwrap(), "600");
        assert_eq!(iface.params.get("id_callsign").unwrap(), "MYCALL");
    }

    #[test]
    fn parse_ifac_networkname() {
        let input = r#"
[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    target_host = 10.0.0.1
    target_port = 4242
    networkname = testnet
"#;
        let config = parse(input).unwrap();
        assert_eq!(config.interfaces[0].params.get("networkname").unwrap(), "testnet");
    }

    #[test]
    fn parse_ifac_passphrase() {
        let input = r#"
[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    target_host = 10.0.0.1
    target_port = 4242
    passphrase = secret123
    ifac_size = 64
"#;
        let config = parse(input).unwrap();
        assert_eq!(config.interfaces[0].params.get("passphrase").unwrap(), "secret123");
        assert_eq!(config.interfaces[0].params.get("ifac_size").unwrap(), "64");
    }

    #[test]
    fn parse_remote_management_config() {
        let input = r#"
[reticulum]
enable_transport = True
enable_remote_management = Yes
remote_management_allowed = aabbccdd00112233aabbccdd00112233, 11223344556677881122334455667788
publish_blackhole = Yes
"#;
        let config = parse(input).unwrap();
        assert!(config.reticulum.enable_remote_management);
        assert!(config.reticulum.publish_blackhole);
        assert_eq!(config.reticulum.remote_management_allowed.len(), 2);
        assert_eq!(
            config.reticulum.remote_management_allowed[0],
            "aabbccdd00112233aabbccdd00112233"
        );
        assert_eq!(
            config.reticulum.remote_management_allowed[1],
            "11223344556677881122334455667788"
        );
    }

    #[test]
    fn parse_remote_management_defaults() {
        let input = "[reticulum]\n";
        let config = parse(input).unwrap();
        assert!(!config.reticulum.enable_remote_management);
        assert!(!config.reticulum.publish_blackhole);
        assert!(config.reticulum.remote_management_allowed.is_empty());
    }

    #[test]
    fn parse_hooks_section() {
        let input = r#"
[hooks]
  [[drop_tick]]
    path = /tmp/drop_tick.wasm
    attach_point = Tick
    priority = 10
    enabled = Yes

  [[log_announce]]
    path = /tmp/log_announce.wasm
    attach_point = AnnounceReceived
    priority = 5
    enabled = No
"#;
        let config = parse(input).unwrap();
        assert_eq!(config.hooks.len(), 2);
        assert_eq!(config.hooks[0].name, "drop_tick");
        assert_eq!(config.hooks[0].path, "/tmp/drop_tick.wasm");
        assert_eq!(config.hooks[0].attach_point, "Tick");
        assert_eq!(config.hooks[0].priority, 10);
        assert!(config.hooks[0].enabled);
        assert_eq!(config.hooks[1].name, "log_announce");
        assert_eq!(config.hooks[1].attach_point, "AnnounceReceived");
        assert!(!config.hooks[1].enabled);
    }

    #[test]
    fn parse_empty_hooks() {
        let input = "[hooks]\n";
        let config = parse(input).unwrap();
        assert!(config.hooks.is_empty());
    }

    #[test]
    fn parse_hook_point_names() {
        assert_eq!(parse_hook_point("PreIngress"), Some(0));
        assert_eq!(parse_hook_point("PreDispatch"), Some(1));
        assert_eq!(parse_hook_point("AnnounceReceived"), Some(2));
        assert_eq!(parse_hook_point("PathUpdated"), Some(3));
        assert_eq!(parse_hook_point("AnnounceRetransmit"), Some(4));
        assert_eq!(parse_hook_point("LinkRequestReceived"), Some(5));
        assert_eq!(parse_hook_point("LinkEstablished"), Some(6));
        assert_eq!(parse_hook_point("LinkClosed"), Some(7));
        assert_eq!(parse_hook_point("InterfaceUp"), Some(8));
        assert_eq!(parse_hook_point("InterfaceDown"), Some(9));
        assert_eq!(parse_hook_point("InterfaceConfigChanged"), Some(10));
        assert_eq!(parse_hook_point("SendOnInterface"), Some(11));
        assert_eq!(parse_hook_point("BroadcastOnAllInterfaces"), Some(12));
        assert_eq!(parse_hook_point("DeliverLocal"), Some(13));
        assert_eq!(parse_hook_point("TunnelSynthesize"), Some(14));
        assert_eq!(parse_hook_point("Tick"), Some(15));
        assert_eq!(parse_hook_point("Unknown"), None);
    }

    #[test]
    fn backbone_extra_params_preserved() {
        let config = r#"
[reticulum]
enable_transport = True

[interfaces]
  [[Public Entrypoint]]
    type = BackboneInterface
    enabled = yes
    listen_ip = 0.0.0.0
    listen_port = 4242
    interface_mode = gateway
    discoverable = Yes
    discovery_name = PizzaSpaghettiMandolino
    announce_interval = 600
    discovery_stamp_value = 24
    reachable_on = 87.106.8.245
"#;
        let parsed = parse(config).unwrap();
        assert_eq!(parsed.interfaces.len(), 1);
        let iface = &parsed.interfaces[0];
        assert_eq!(iface.name, "Public Entrypoint");
        assert_eq!(iface.interface_type, "BackboneInterface");
        // After removing type, enabled, interface_mode, remaining params should include discovery keys
        assert_eq!(iface.params.get("discoverable").map(|s| s.as_str()), Some("Yes"));
        assert_eq!(iface.params.get("discovery_name").map(|s| s.as_str()), Some("PizzaSpaghettiMandolino"));
        assert_eq!(iface.params.get("announce_interval").map(|s| s.as_str()), Some("600"));
        assert_eq!(iface.params.get("discovery_stamp_value").map(|s| s.as_str()), Some("24"));
        assert_eq!(iface.params.get("reachable_on").map(|s| s.as_str()), Some("87.106.8.245"));
        assert_eq!(iface.params.get("listen_ip").map(|s| s.as_str()), Some("0.0.0.0"));
        assert_eq!(iface.params.get("listen_port").map(|s| s.as_str()), Some("4242"));
    }
}
