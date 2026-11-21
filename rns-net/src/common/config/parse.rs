//! Reading the ConfigObj text and its values.

use super::*;

/// Parse a config string into an `RnsConfig`.
pub fn parse(input: &str) -> Result<RnsConfig, ConfigError> {
    let mut current_section: Option<String> = None;
    let mut current_subsection: Option<String> = None;

    let mut reticulum_kvs: HashMap<String, String> = HashMap::new();
    // The [reticulum] keys in file order, for the options whose effect
    // upstream's in-order reading makes depend on it.
    let mut reticulum_key_order: Vec<String> = Vec::new();
    let mut logging_kvs: HashMap<String, String> = HashMap::new();
    let mut stamps_kvs: HashMap<String, String> = HashMap::new();
    let mut filter_kvs: HashMap<String, String> = HashMap::new();
    // The [filter] keys in file order: upstream applies them in that order,
    // so whether an allowed type is logged depends on it.
    let mut filter_key_order: Vec<String> = Vec::new();
    let mut interfaces: Vec<ParsedInterface> = Vec::new();
    let mut current_iface_kvs: Option<HashMap<String, String>> = None;
    let mut current_iface_name: Option<String> = None;
    let mut current_iface_subinterfaces: Vec<ParsedSubinterface> = Vec::new();
    let mut current_subiface_name: Option<String> = None;
    let mut current_subiface_kvs: Option<HashMap<String, String>> = None;
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

        // Check for third-level subsection [[[name]]] before [[name]].
        if trimmed.starts_with("[[[") && trimmed.ends_with("]]]") {
            if current_iface_kvs.is_none() {
                return Err(ConfigError::Parse(
                    "third-level section outside an interface".into(),
                ));
            }
            if let (Some(name), Some(params)) =
                (current_subiface_name.take(), current_subiface_kvs.take())
            {
                current_iface_subinterfaces.push(ParsedSubinterface { name, params });
            }
            current_subiface_name = Some(trimmed[3..trimmed.len() - 3].trim().to_string());
            current_subiface_kvs = Some(HashMap::new());
            continue;
        }

        // Check for subsection [[name]]
        if trimmed.starts_with("[[") && trimmed.ends_with("]]") {
            let name = trimmed[2..trimmed.len() - 2].trim().to_string();
            if let (Some(name), Some(params)) =
                (current_subiface_name.take(), current_subiface_kvs.take())
            {
                current_iface_subinterfaces.push(ParsedSubinterface { name, params });
            }
            // Finalize previous interface subsection if any
            if let (Some(iface_name), Some(kvs)) =
                (current_iface_name.take(), current_iface_kvs.take())
            {
                interfaces.push(build_parsed_interface(
                    iface_name,
                    kvs,
                    std::mem::take(&mut current_iface_subinterfaces),
                )?);
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
            if let (Some(name), Some(params)) =
                (current_subiface_name.take(), current_subiface_kvs.take())
            {
                current_iface_subinterfaces.push(ParsedSubinterface { name, params });
            }
            // Finalize previous interface subsection if any
            if let (Some(iface_name), Some(kvs)) =
                (current_iface_name.take(), current_iface_kvs.take())
            {
                interfaces.push(build_parsed_interface(
                    iface_name,
                    kvs,
                    std::mem::take(&mut current_iface_subinterfaces),
                )?);
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
                if let Some(ref mut kvs) = current_subiface_kvs {
                    kvs.insert(key, value);
                } else if let Some(ref mut kvs) = current_hook_kvs {
                    kvs.insert(key, value);
                } else if let Some(ref mut kvs) = current_iface_kvs {
                    kvs.insert(key, value);
                }
            } else if let Some(ref section) = current_section {
                match section.as_str() {
                    "reticulum" => {
                        // A repeated key (which ConfigObj rejects) keeps
                        // its last value, so it takes its last position.
                        reticulum_key_order.retain(|k| *k != key);
                        reticulum_key_order.push(key.clone());
                        reticulum_kvs.insert(key, value);
                    }
                    "logging" => {
                        logging_kvs.insert(key, value);
                    }
                    "stamps" => {
                        stamps_kvs.insert(key, value);
                    }
                    "filter" => {
                        filter_key_order.retain(|k| *k != key);
                        filter_key_order.push(key.clone());
                        filter_kvs.insert(key, value);
                    }
                    _ => {} // ignore unknown sections
                }
            }
        }
    }

    // Finalize last subsections
    if let (Some(name), Some(params)) = (current_subiface_name.take(), current_subiface_kvs.take())
    {
        current_iface_subinterfaces.push(ParsedSubinterface { name, params });
    }
    if let (Some(iface_name), Some(kvs)) = (current_iface_name.take(), current_iface_kvs.take()) {
        interfaces.push(build_parsed_interface(
            iface_name,
            kvs,
            current_iface_subinterfaces,
        )?);
    }
    if let (Some(hook_name), Some(kvs)) = (current_hook_name.take(), current_hook_kvs.take()) {
        hooks.push(build_parsed_hook(hook_name, kvs));
    }

    // Build typed sections
    let mut reticulum = build_reticulum_section(&reticulum_kvs, &reticulum_key_order)?;
    if let Some(hop_limiter) = parse_hop_limiter(&filter_kvs)? {
        reticulum.hop_limiter = hop_limiter;
    }
    let logging = build_logging_section(&logging_kvs)?;
    let stamps = build_stamps_section(&stamps_kvs)?;
    let filter = build_filter_section(&filter_kvs, filter_key_order)?;

    Ok(RnsConfig {
        reticulum,
        logging,
        stamps,
        filter,
        interfaces,
        hooks,
    })
}

/// Parse a config file from disk.
pub fn parse_file(path: &Path) -> Result<RnsConfig, ConfigError> {
    let content = std::fs::read_to_string(path)?;
    parse(&content)
}

pub(crate) fn parse_link_mtu_discovery(input: &str) -> Result<bool, ConfigError> {
    let mut in_reticulum = false;
    for line in input.lines() {
        let trimmed = strip_comment(line).trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_reticulum = trimmed.eq_ignore_ascii_case("[reticulum]");
            continue;
        }
        if !in_reticulum {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        if key.trim() == "link_mtu_discovery" {
            let value = value.trim();
            return parse_bool(value).ok_or_else(|| ConfigError::InvalidValue {
                key: "link_mtu_discovery".into(),
                value: value.into(),
            });
        }
    }
    Ok(true)
}

/// Strip `#` comments from a line (simple: not inside quotes).
pub(super) fn strip_comment(line: &str) -> &str {
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
pub(crate) fn parse_bool_pub(value: &str) -> Option<bool> {
    parse_bool(value)
}

/// Parse a string as a boolean (ConfigObj style).
pub(super) fn parse_bool(value: &str) -> Option<bool> {
    match value.to_lowercase().as_str() {
        "yes" | "true" | "1" | "on" => Some(true),
        "no" | "false" | "0" | "off" => Some(false),
        _ => None,
    }
}

/// Parse an integer as ConfigObj's `as_int` does, saturating values beyond
/// the `i64` range instead of rejecting them, since every caller clamps.
pub(crate) fn parse_config_int(value: &str) -> Option<i64> {
    let value = value.trim();
    if let Ok(n) = value.parse::<i64>() {
        return Some(n);
    }
    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(if value.starts_with('-') {
        i64::MIN
    } else {
        i64::MAX
    })
}

/// Parse a float as ConfigObj's `as_float` (Python `float()`) does,
/// including `inf` and `nan`, which callers clamp.
pub(crate) fn parse_config_float(value: &str) -> Option<f64> {
    value.trim().parse::<f64>().ok()
}

/// `[filter] hop_limiter`: `max(0, min(as_int(v), PATHFINDER_M))`
/// (Reticulum.py since 01aef5bc). A limit of 0 drops every inbound packet.
pub(super) fn parse_hop_limiter(kvs: &HashMap<String, String>) -> Result<Option<u8>, ConfigError> {
    let n = super::keys::Keys(kvs).with("hop_limiter", parse_config_int)?;
    Ok(n.map(|n| n.clamp(0, i64::from(rns_core::constants::PATHFINDER_M)) as u8))
}

/// The `rpc_key` hex value as the 32-byte key rns-rs authenticates with.
///
/// The key is used as an HMAC key, which is padded with zeros to the hash
/// block size, so a shorter key authenticates exactly as the same key
/// padded with zeros to 32 bytes. Like upstream, an invalid key falls back
/// to the default one; so does a key longer than 32 bytes, which rns-rs does
/// not support.
pub(super) fn parse_rpc_key(value: &str) -> Option<[u8; 32]> {
    let value = value.trim();
    match rns_core::encoding::hex_decode(value) {
        Some(bytes) if !bytes.is_empty() && bytes.len() <= 32 => {
            let mut key = [0u8; 32];
            for (slot, byte) in key.iter_mut().zip(&bytes) {
                *slot = *byte;
            }
            Some(key)
        }
        Some(bytes) if bytes.len() > 32 => {
            log::error!(
                "Shared instance RPC keys longer than 32 bytes are not supported, falling back to default key"
            );
            None
        }
        _ => {
            log::error!("Invalid shared instance RPC key specified, falling back to default key");
            None
        }
    }
}

/// A 16-byte identity hash written as 32 hexadecimal characters.
pub(super) fn parse_identity_hash_hex(hexhash: &str) -> Option<[u8; 16]> {
    rns_core::encoding::hex_decode_array(hexhash)
}
