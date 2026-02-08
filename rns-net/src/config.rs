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
            // Finalize previous subsection if any
            if let (Some(iface_name), Some(kvs)) =
                (current_iface_name.take(), current_iface_kvs.take())
            {
                interfaces.push(build_parsed_interface(iface_name, kvs));
            }
            current_subsection = Some(name.clone());
            current_iface_name = Some(name);
            current_iface_kvs = Some(HashMap::new());
            continue;
        }

        // Check for section [name]
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            // Finalize previous subsection if any
            if let (Some(iface_name), Some(kvs)) =
                (current_iface_name.take(), current_iface_kvs.take())
            {
                interfaces.push(build_parsed_interface(iface_name, kvs));
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
                // Inside a [[subsection]] within [interfaces]
                if let Some(ref mut kvs) = current_iface_kvs {
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

    // Finalize last subsection
    if let (Some(iface_name), Some(kvs)) = (current_iface_name.take(), current_iface_kvs.take()) {
        interfaces.push(build_parsed_interface(iface_name, kvs));
    }

    // Build typed sections
    let reticulum = build_reticulum_section(&reticulum_kvs)?;
    let logging = build_logging_section(&logging_kvs)?;

    Ok(RnsConfig {
        reticulum,
        logging,
        interfaces,
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
}
