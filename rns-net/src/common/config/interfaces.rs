//! An interface's options: which ones it takes and how they are read.

use super::*;

/// Interface options upstream's `Reticulum._synthesize_interface` reads with
/// ConfigObj's `as_int`.
pub(super) const INTERFACE_INT_OPTIONS: &[&str] = &[
    "gravity",
    "hop_limiter",
    "ifac_size",
    "ic_max_held_announces",
    "bitrate",
    "announce_rate_target",
    "announce_rate_grace",
    "announce_rate_penalty",
];

/// Interface options it reads with `as_float`.
pub(super) const INTERFACE_FLOAT_OPTIONS: &[&str] = &[
    "destination_cost",
    "pr_cost",
    "ic_burst_hold",
    "ic_burst_freq_new",
    "ic_burst_freq",
    "ic_pr_burst_freq_new",
    "ic_pr_burst_freq",
    "ec_pr_freq",
    "ic_new_time",
    "ic_burst_penalty",
    "ic_held_release_interval",
    "announce_cap",
];

/// Interface options it reads with `as_bool`.
pub(super) const INTERFACE_BOOL_OPTIONS: &[&str] = &[
    "ingress_control",
    "egress_control",
    "bootstrap_only",
    "recursive_prs",
    "announces_from_internal",
    "announces_to_internal",
    "ignore_config_warnings",
    "discoverable",
];

/// Discovery options it reads, with these conversions, once `discoverable`
/// is true.
pub(super) const DISCOVERY_INT_OPTIONS: &[&str] = &[
    "announce_interval",
    "discovery_frequency",
    "discovery_bandwidth",
    "discovery_modulation",
];

pub(super) const DISCOVERY_FLOAT_OPTIONS: &[&str] =
    &["discovery_stamp_value", "latitude", "longitude", "height"];

pub(super) const DISCOVERY_BOOL_OPTIONS: &[&str] = &["discovery_encrypt", "publish_ifac"];

/// Check an interface section's generic options as upstream converts them.
/// Upstream raises on a value `as_int`, `as_float` or `as_bool` cannot
/// convert, and `_synthesize_interface` then logs that the interface could
/// not be created and stops the instance (`RNS.panic`). It converts every
/// generic option before it checks whether the interface is enabled, so a
/// disabled section is checked too; `outgoing` only once the interface
/// exists.
pub(super) fn check_interface_options(
    name: &str,
    kvs: &HashMap<String, String>,
) -> Result<(), ConfigError> {
    let fail = |exception: String| {
        Err(ConfigError::Parse(format!(
            "The interface \"{name}\" could not be created. Check your configuration file \
             for errors! The contained exception was: {exception}"
        )))
    };
    let as_int = |key: &str| -> Result<(), ConfigError> {
        match kvs.get(key) {
            Some(value) if parse_config_int(value).is_none() => {
                fail(format!("invalid literal for int() with base 10: '{value}'"))
            }
            _ => Ok(()),
        }
    };
    let as_float = |key: &str| -> Result<(), ConfigError> {
        match kvs.get(key) {
            Some(value) if parse_config_float(value).is_none() => {
                fail(format!("could not convert string to float: '{value}'"))
            }
            _ => Ok(()),
        }
    };
    let as_bool = |key: &str| -> Result<Option<bool>, ConfigError> {
        match kvs.get(key) {
            None => Ok(None),
            Some(value) => match parse_bool(value.trim()) {
                Some(parsed) => Ok(Some(parsed)),
                None => fail(format!("Value \"{value}\" is neither True nor False")).map(|()| None),
            },
        }
    };

    for key in INTERFACE_INT_OPTIONS {
        as_int(key)?;
    }
    for key in INTERFACE_FLOAT_OPTIONS {
        as_float(key)?;
    }
    for key in INTERFACE_BOOL_OPTIONS {
        as_bool(key)?;
    }
    if as_bool("discoverable")? == Some(true) {
        for key in DISCOVERY_INT_OPTIONS {
            as_int(key)?;
        }
        for key in DISCOVERY_FLOAT_OPTIONS {
            as_float(key)?;
        }
        for key in DISCOVERY_BOOL_OPTIONS {
            as_bool(key)?;
        }
    }
    // `("interface_enabled" in c and c.as_bool(..) == True) or ("enabled"
    // in c and c.as_bool(..) == True)`: `enabled` is only converted when
    // `interface_enabled` did not enable the interface.
    let enabled = as_bool("interface_enabled")? == Some(true) || as_bool("enabled")? == Some(true);
    if enabled {
        as_bool("outgoing")?;
    }
    Ok(())
}

pub(super) fn build_parsed_interface(
    name: String,
    mut kvs: HashMap<String, String>,
    subinterfaces: Vec<ParsedSubinterface>,
) -> Result<ParsedInterface, ConfigError> {
    check_interface_options(&name, &kvs)?;
    let interface_type = kvs.remove("type").unwrap_or_default();
    // As upstream: an interface runs only when `interface_enabled` or
    // `enabled` says so; without either it is skipped.
    let interface_enabled = kvs.remove("interface_enabled");
    let enabled_key = kvs.remove("enabled");
    let enabled = [interface_enabled, enabled_key]
        .iter()
        .flatten()
        .any(|v| parse_bool(v) == Some(true));
    // Python checks `interface_mode` first, then falls back to `mode`
    let mode = kvs
        .remove("interface_mode")
        .or_else(|| kvs.remove("mode"))
        .unwrap_or_else(|| "full".into());

    Ok(ParsedInterface {
        name,
        interface_type,
        enabled,
        mode,
        params: kvs,
        subinterfaces,
    })
}
