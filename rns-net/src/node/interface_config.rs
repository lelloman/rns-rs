//! Reading an interface's section of the config: its mode, IFAC,
//! ingress control, discovery and announce settings.

use super::*;
use crate::interface::{InterfaceConfigError, InterfaceKind};

/// Parse an interface mode string to the corresponding constant.
/// Matches Python's `_synthesize_interface()` in `RNS/Reticulum.py`.
pub(super) fn parse_interface_mode(mode: &str) -> u8 {
    match mode.to_lowercase().as_str() {
        "full" => rns_core::constants::MODE_FULL,
        "access_point" | "accesspoint" | "ap" => rns_core::constants::MODE_ACCESS_POINT,
        "pointtopoint" | "ptp" => rns_core::constants::MODE_POINT_TO_POINT,
        "roaming" => rns_core::constants::MODE_ROAMING,
        "boundary" => rns_core::constants::MODE_BOUNDARY,
        "gateway" | "gw" => rns_core::constants::MODE_GATEWAY,
        "internal" => rns_core::constants::MODE_INTERNAL,
        _ => rns_core::constants::MODE_FULL,
    }
}

pub(super) fn parse_optional_interface_mode(mode: &str) -> Option<u8> {
    match mode.to_lowercase().as_str() {
        "full" => Some(rns_core::constants::MODE_FULL),
        "access_point" | "accesspoint" | "ap" => Some(rns_core::constants::MODE_ACCESS_POINT),
        "pointtopoint" | "ptp" => Some(rns_core::constants::MODE_POINT_TO_POINT),
        "roaming" => Some(rns_core::constants::MODE_ROAMING),
        "boundary" => Some(rns_core::constants::MODE_BOUNDARY),
        "gateway" | "gw" => Some(rns_core::constants::MODE_GATEWAY),
        "internal" => Some(rns_core::constants::MODE_INTERNAL),
        _ => None,
    }
}

pub(super) fn parse_interface_gravity(value: Option<&str>, default_gravity: i64) -> i64 {
    value
        .and_then(|value| value.parse().ok())
        .unwrap_or(default_gravity)
}

/// Parse an interface's `hop_limiter` option (upstream bb63dd44): `as_int`,
/// clamped to `0..=PATHFINDER_M`. Upstream checks it as a truth value, so 0
/// leaves the interface without a limiter of its own. A config file with a
/// value that is not an integer is refused when it is parsed, as upstream
/// refuses to create the interface; here such a value is no limiter.
pub(crate) fn parse_interface_hop_limiter(value: Option<&str>) -> Option<u8> {
    let limit = value?.trim().parse::<i64>().ok()?;
    let limit = limit.clamp(0, i64::from(rns_core::constants::PATHFINDER_M)) as u8;
    (limit > 0).then_some(limit)
}

/// Whether an interface configured with `discoverable` is made
/// discoverable. As upstream's `Reticulum._synthesize_interface` (since
/// 606a1691), an instance with transport disabled makes none discoverable
/// unless `static_transport_identity` is set, since its transport identity
/// is otherwise ephemeral; the interface is set up without discovery and
/// upstream's warning tells the operator how to allow it.
pub(super) fn discoverable_on_instance(
    interface_name: &str,
    discoverable: bool,
    transport_enabled: bool,
    static_transport_identity: bool,
) -> bool {
    if discoverable && !static_transport_identity && !transport_enabled {
        log::warn!("");
        log::warn!(
            "The interface \"{interface_name}\" was configured discoverable, but this instance has transport disabled"
        );
        log::warn!(
            "and is using an ephemeral transport identity. To make interfaces discoverable for non-transport"
        );
        log::warn!(
            "instances, you will have explicitly enable using static transport identity in the config file,"
        );
        log::warn!("by adding \"static_transport_identity = yes\" to the [reticulum] section.");
        log::warn!("");
        return false;
    }
    discoverable
}

/// Apply Reticulum's mode normalization for discoverable interfaces.
pub(super) fn normalize_discovery_mode(
    kind: Option<InterfaceKind>,
    configured_mode: u8,
    discoverable: bool,
    ignore_config_warnings: bool,
) -> u8 {
    if !discoverable
        || ignore_config_warnings
        || matches!(
            configured_mode,
            rns_core::constants::MODE_ACCESS_POINT
                | rns_core::constants::MODE_GATEWAY
                | rns_core::constants::MODE_INTERNAL
        )
    {
        return configured_mode;
    }

    if matches!(kind, Some(InterfaceKind::RNode | InterfaceKind::RNodeMulti)) {
        rns_core::constants::MODE_ACCESS_POINT
    } else {
        rns_core::constants::MODE_GATEWAY
    }
}

pub(super) fn default_ingress_control_for_type(
    kind: Option<InterfaceKind>,
) -> rns_core::transport::types::IngressControlConfig {
    if kind.is_some_and(InterfaceKind::ingress_control_by_default) {
        rns_core::transport::types::IngressControlConfig::enabled()
    } else {
        rns_core::transport::types::IngressControlConfig::disabled()
    }
}

pub(super) fn parse_ingress_control_config(
    kind: Option<InterfaceKind>,
    params: &std::collections::HashMap<String, String>,
) -> Result<rns_core::transport::types::IngressControlConfig, InterfaceConfigError> {
    let mut config = default_ingress_control_for_type(kind);

    if let Some(v) = params.get("ingress_control") {
        config.enabled = config::parse_bool_pub(v).ok_or_else(|| {
            InterfaceConfigError::invalid_value(
                "ingress_control",
                format!("ingress_control must be a boolean, got '{}'", v),
            )
        })?;
    }
    if let Some(v) = params.get("ic_max_held_announces") {
        config.max_held_announces = v.parse::<usize>().map_err(|_| {
            InterfaceConfigError::invalid_value(
                "ic_max_held_announces",
                format!("ic_max_held_announces must be an integer, got '{}'", v),
            )
        })?;
    }
    if let Some(v) = params.get("ic_burst_hold") {
        config.burst_hold = parse_nonnegative_f64("ic_burst_hold", v)?;
    }
    if let Some(v) = params.get("ic_burst_freq_new") {
        config.burst_freq_new = parse_nonnegative_f64("ic_burst_freq_new", v)?;
    }
    if let Some(v) = params.get("ic_burst_freq") {
        config.burst_freq = parse_nonnegative_f64("ic_burst_freq", v)?;
    }
    if let Some(v) = params.get("ic_pr_burst_freq_new") {
        config.pr_burst_freq_new = parse_nonnegative_f64("ic_pr_burst_freq_new", v)?;
    }
    if let Some(v) = params.get("ic_pr_burst_freq") {
        config.pr_burst_freq = parse_nonnegative_f64("ic_pr_burst_freq", v)?;
    }
    if let Some(v) = params.get("egress_control") {
        config.egress_enabled = config::parse_bool_pub(v).ok_or_else(|| {
            InterfaceConfigError::invalid_value(
                "egress_control",
                format!("egress_control must be a boolean, got '{}'", v),
            )
        })?;
    }
    if let Some(v) = params.get("ec_pr_freq") {
        config.egress_pr_freq = parse_nonnegative_f64("ec_pr_freq", v)?;
    }
    if let Some(v) = params.get("ic_new_time") {
        config.new_time = parse_nonnegative_f64("ic_new_time", v)?;
    }
    if let Some(v) = params.get("ic_burst_penalty") {
        config.burst_penalty = parse_nonnegative_f64("ic_burst_penalty", v)?;
    }
    if let Some(v) = params.get("ic_held_release_interval") {
        config.held_release_interval = parse_nonnegative_f64("ic_held_release_interval", v)?;
    }

    Ok(config)
}

pub(super) fn parse_nonnegative_f64(
    key: &'static str,
    value: &str,
) -> Result<f64, InterfaceConfigError> {
    let parsed = value.parse::<f64>().map_err(|_| {
        InterfaceConfigError::invalid_value(
            key,
            format!("{} must be numeric, got '{}'", key, value),
        )
    })?;
    if parsed < 0.0 {
        return Err(InterfaceConfigError::invalid_value(
            key,
            format!("{} must be >= 0, got '{}'", key, value),
        ));
    }
    Ok(parsed)
}

/// Reject empty and the nonsensical literal `"None"` IFAC config values.
///
/// Upstream treats `"None"` as an unset value and logs a warning, because a
/// quoted TOML/JSON `None` is commonly mistaken for a real network name or
/// passphrase. Empty strings are also ignored.
pub(super) fn sanitize_ifac_config_string(kind: &str, value: &str) -> Option<String> {
    if value == "None" {
        log::warn!(
            "Ambiguous IFAC {} \"None\", this value is ignored and an IFAC {} has NOT been set",
            kind,
            kind
        );
        return None;
    }
    if value.is_empty() {
        return None;
    }
    Some(value.to_string())
}

/// Extract IFAC configuration from interface params, if present.
/// Returns None if neither networkname/network_name nor passphrase/pass_phrase is set.
pub(super) fn extract_ifac_config(
    params: &std::collections::HashMap<String, String>,
    default_size: usize,
) -> Option<IfacConfig> {
    let netname = params
        .get("networkname")
        .or_else(|| params.get("network_name"))
        .cloned()
        .and_then(|value| sanitize_ifac_config_string("network name", &value));
    let netkey = params
        .get("passphrase")
        .or_else(|| params.get("pass_phrase"))
        .cloned()
        .and_then(|value| sanitize_ifac_config_string("passphrase", &value));

    if netname.is_none() && netkey.is_none() {
        return None;
    }

    // ifac_size is specified in bits in config, divide by 8 for bytes
    let size = params
        .get("ifac_size")
        .and_then(|v| v.parse::<usize>().ok())
        .map(|bits| (bits / 8).max(1))
        .unwrap_or(default_size);

    Some(IfacConfig {
        netname,
        netkey,
        size,
    })
}

/// Extract discovery configuration from interface params, if `discoverable` is set.
pub(super) fn extract_discovery_config(
    iface_name: &str,
    iface_type: &str,
    params: &std::collections::HashMap<String, String>,
) -> Option<crate::discovery::DiscoveryConfig> {
    let discoverable = params
        .get("discoverable")
        .and_then(|v| config::parse_bool_pub(v))
        .unwrap_or(false);
    if !discoverable {
        return None;
    }

    let kind = InterfaceKind::from_type_name(iface_type);
    if kind == Some(InterfaceKind::TcpClient) {
        log::error!(
            "Invalid interface discovery configuration for {}, aborting discovery announce",
            iface_name
        );
        return None;
    }

    let discovery_name = params
        .get("discovery_name")
        .cloned()
        .unwrap_or_else(|| iface_name.to_string());

    // `announce_interval` is in minutes, as upstream reads it
    // (`as_int(..)*60`): at least 5 minutes, 6 hours by default. Kept in
    // seconds from here on.
    let announce_interval = params
        .get("announce_interval")
        .and_then(|v| config::parse_config_int(v))
        .map(|minutes| (minutes.max(0) as u64).saturating_mul(60).max(300))
        .unwrap_or(21600);

    // `as_float` since upstream 796ef2d4.
    let stamp_value = params
        .get("discovery_stamp_value")
        .and_then(|v| config::parse_config_float(v))
        .map(|v| rns_core::stamp::clamp_cost(v, rns_core::constants::STAMP_COST_CAP))
        .unwrap_or(crate::discovery::DEFAULT_STAMP_VALUE);

    let reachable_on = params.get("reachable_on").cloned();

    let listen_port = params
        .get("listen_port")
        .or_else(|| params.get("port"))
        .and_then(|v| v.parse().ok());

    let location_cmd = params.get("location_cmd").cloned();

    let latitude = params
        .get("latitude")
        .or_else(|| params.get("lat"))
        .and_then(|v| v.parse().ok());
    let longitude = params
        .get("longitude")
        .or_else(|| params.get("lon"))
        .and_then(|v| v.parse().ok());
    let height = params.get("height").and_then(|v| v.parse().ok());
    let operator_lxmf_address = params.get("discovery_lxmf_address").and_then(|value| {
        let parsed = parse_discovery_lxmf_address(value);
        if parsed.is_none() {
            log::error!(
                "Invalid interface discovery LXMF address for '{}': {}",
                iface_name,
                value
            );
        }
        parsed
    });

    let flag = |key: &str| {
        params
            .get(key)
            .and_then(|v| config::parse_bool_pub(v))
            .unwrap_or(false)
    };
    let number = |keys: &[&str]| {
        keys.iter()
            .find_map(|key| params.get(*key))
            .and_then(|v| v.trim().parse::<u64>().ok())
    };
    // An RNode announces its own radio settings; a KISS or Weave interface
    // announces the ones given for discovery.
    let radio = match kind {
        Some(InterfaceKind::RNode) => crate::discovery::DiscoveryRadio {
            frequency: number(&["frequency"]),
            bandwidth: number(&["bandwidth"]),
            spreading_factor: number(&["spreadingfactor", "spreading_factor"]),
            coding_rate: number(&["codingrate", "coding_rate"]),
            modulation: None,
        },
        Some(InterfaceKind::Kiss | InterfaceKind::Weave) => crate::discovery::DiscoveryRadio {
            frequency: number(&["discovery_frequency"]),
            bandwidth: number(&["discovery_bandwidth"]),
            spreading_factor: None,
            coding_rate: None,
            modulation: params
                .get("discovery_modulation")
                .map(|v| v.trim().to_string()),
        },
        _ => crate::discovery::DiscoveryRadio::default(),
    };

    Some(crate::discovery::DiscoveryConfig {
        publish_ifac: flag("publish_ifac"),
        encrypt: flag("discovery_encrypt"),
        radio,
        discovery_name,
        announce_interval,
        stamp_value,
        reachable_on,
        interface_type: iface_type.to_string(),
        listen_port,
        location_cmd,
        latitude,
        longitude,
        height,
        operator_lxmf_address,
        // Invalid values were already rejected with the interface itself.
        stamp_costs: parse_interface_stamp_costs(params).unwrap_or_default(),
    })
}

#[cfg(any(feature = "iface-tcp", feature = "iface-backbone"))]
pub(super) fn default_discovery_runtime_config(
    interface_name: &str,
    interface_type: &str,
    listen_port: Option<u16>,
) -> crate::discovery::DiscoveryConfig {
    crate::discovery::DiscoveryConfig {
        stamp_costs: Default::default(),
        publish_ifac: false,
        encrypt: false,
        radio: Default::default(),
        discovery_name: interface_name.to_string(),
        announce_interval: 21600,
        stamp_value: crate::discovery::DEFAULT_STAMP_VALUE,
        reachable_on: None,
        interface_type: interface_type.to_string(),
        listen_port,
        location_cmd: None,
        latitude: None,
        longitude: None,
        height: None,
        operator_lxmf_address: None,
    }
}

pub(super) fn parse_discovery_lxmf_address(value: &str) -> Option<[u8; 16]> {
    rns_core::encoding::hex_decode_array(value)
}

#[cfg(any(feature = "iface-tcp", feature = "iface-backbone"))]
pub(super) fn discovery_runtime_ifac_fields(
    ifac: Option<&IfacConfig>,
) -> (Option<String>, Option<String>) {
    (
        ifac.and_then(|cfg| cfg.netname.clone()),
        ifac.and_then(|cfg| cfg.netkey.clone()),
    )
}

#[cfg(feature = "iface-backbone")]
pub(crate) fn backbone_discovery_runtime_from_interface(
    interface_name: &str,
    mode: &BackboneMode,
    discovery: Option<&crate::discovery::DiscoveryConfig>,
    transport_enabled: bool,
    ifac: Option<&IfacConfig>,
) -> Option<crate::driver::BackboneDiscoveryRuntimeHandle> {
    let config = match mode {
        BackboneMode::Server(config) => config,
        BackboneMode::Client(_, _) => return None,
    };

    let startup_config = discovery.cloned().unwrap_or_else(|| {
        default_discovery_runtime_config(
            interface_name,
            InterfaceKind::Backbone.type_name(),
            Some(config.listen_port),
        )
    });
    let (ifac_netname, ifac_netkey) = discovery_runtime_ifac_fields(ifac);

    Some(crate::driver::BackboneDiscoveryRuntimeHandle::from_parts(
        config.name.clone(),
        startup_config,
        transport_enabled,
        ifac_netname,
        ifac_netkey,
        discovery.is_some(),
    ))
}

#[cfg(feature = "iface-tcp")]
pub(crate) fn tcp_server_discovery_runtime_from_interface(
    interface_name: &str,
    config: &crate::interface::tcp_server::TcpServerConfig,
    discovery: Option<&crate::discovery::DiscoveryConfig>,
    transport_enabled: bool,
    ifac: Option<&IfacConfig>,
) -> crate::driver::TcpServerDiscoveryRuntimeHandle {
    let startup_config = discovery.cloned().unwrap_or_else(|| {
        default_discovery_runtime_config(
            interface_name,
            InterfaceKind::TcpServer.type_name(),
            Some(config.listen_port),
        )
    });
    let (ifac_netname, ifac_netkey) = discovery_runtime_ifac_fields(ifac);

    crate::driver::TcpServerDiscoveryRuntimeHandle::from_parts(
        config.name.clone(),
        startup_config,
        transport_enabled,
        ifac_netname,
        ifac_netkey,
        discovery.is_some(),
    )
}

pub(crate) fn ifac_runtime_from_config(
    ifac: Option<&IfacConfig>,
    default_size: usize,
) -> crate::driver::IfacRuntimeConfig {
    crate::driver::IfacRuntimeConfig::from_parts(
        ifac.and_then(|cfg| cfg.netname.clone()),
        ifac.and_then(|cfg| cfg.netkey.clone()),
        ifac.map(|cfg| cfg.size).unwrap_or(default_size),
    )
}

pub(crate) fn discoverable_interface_from_config(
    interface_name: &str,
    discovery: &crate::discovery::DiscoveryConfig,
    transport_enabled: bool,
    ifac: Option<&IfacConfig>,
) -> crate::discovery::DiscoverableInterface {
    if discovery.publish_ifac
        && ifac.is_none_or(|cfg| cfg.netname.is_none() && cfg.netkey.is_none())
    {
        log::warn!(
            "IFAC publishing was enabled for discoverable interface {interface_name}, but neither IFAC netname nor passphrase is configured"
        );
    }
    crate::discovery::DiscoverableInterface {
        interface_name: interface_name.to_string(),
        config: discovery.clone(),
        transport_enabled,
        ifac_netname: ifac.and_then(|cfg| cfg.netname.clone()),
        ifac_netkey: ifac.and_then(|cfg| cfg.netkey.clone()),
    }
}

pub(crate) fn derive_ifac_state(
    ifac: Option<&IfacConfig>,
    interface_name: &str,
) -> io::Result<Option<crate::ifac::IfacState>> {
    let Some(ifac) = ifac else {
        return Ok(None);
    };
    if ifac.netname.is_none() && ifac.netkey.is_none() {
        return Ok(None);
    }

    ifac::derive_ifac(ifac.netname.as_deref(), ifac.netkey.as_deref(), ifac.size)
        .map(Some)
        .map_err(|err| {
            io::Error::other(format!(
                "failed to derive IFAC for {}: {}",
                interface_name, err
            ))
        })
}

/// Parse the per-interface `destination_cost` and `pr_cost` options
/// (upstream 9b464382): `as_float`, clamped to `0..=STAMP_COST_CAP`.
pub(crate) fn parse_interface_stamp_costs(
    params: &HashMap<String, String>,
) -> Result<rns_core::transport::types::InterfaceStampCosts, InterfaceConfigError> {
    let cost =
        |key: &'static str| -> Result<Option<rns_core::stamp::StampCost>, InterfaceConfigError> {
            let Some(value) = params.get(key) else {
                return Ok(None);
            };
            let value = config::parse_config_float(value).ok_or_else(|| {
                InterfaceConfigError::invalid_value(
                    key,
                    format!("{key} must be a number, got '{value}'"),
                )
            })?;
            Ok(Some(rns_core::stamp::clamp_cost(
                value,
                rns_core::constants::STAMP_COST_CAP,
            )))
        };
    Ok(rns_core::transport::types::InterfaceStampCosts {
        destination_cost: cost("destination_cost")?,
        pr_cost: cost("pr_cost")?,
    })
}

/// Parse an interface section's announce rate and cap options as
/// Reticulum.py does: `announce_rate_target` with `as_int`, kept when above
/// 0; `announce_rate_grace` and `announce_rate_penalty` with `as_int`, kept
/// when 0 or more; `announce_cap` with `as_float`, kept when in `(0, 100]`
/// and stored as a fraction. A value that is not a number is an error.
pub(crate) fn parse_interface_announce_limits(
    params: &HashMap<String, String>,
) -> Result<InterfaceAnnounceLimits, InterfaceConfigError> {
    let int = |key: &'static str| -> Result<Option<i64>, InterfaceConfigError> {
        params
            .get(key)
            .map(|value| {
                config::parse_config_int(value).ok_or_else(|| {
                    InterfaceConfigError::invalid_value(
                        key,
                        format!("{key} must be an integer, got '{value}'"),
                    )
                })
            })
            .transpose()
    };
    let cap = params
        .get("announce_cap")
        .map(|value| {
            config::parse_config_float(value).ok_or_else(|| {
                InterfaceConfigError::invalid_value(
                    "announce_cap",
                    format!("announce_cap must be a number, got '{value}'"),
                )
            })
        })
        .transpose()?;
    Ok(InterfaceAnnounceLimits {
        rate_target: int("announce_rate_target")?
            .filter(|v| *v > 0)
            .map(|v| v as f64),
        rate_grace: int("announce_rate_grace")?
            .filter(|v| *v >= 0)
            .map(|v| u32::try_from(v).unwrap_or(u32::MAX)),
        rate_penalty: int("announce_rate_penalty")?
            .filter(|v| *v >= 0)
            .map(|v| v as f64),
        cap: cap.filter(|v| *v > 0.0 && *v <= 100.0).map(|v| v / 100.0),
    })
}

/// How many ids a configured interface takes: its own, and for an
/// `RNodeMultiInterface` one per subinterface after it.
pub(crate) fn reserved_interface_ids(data: &dyn crate::interface::InterfaceConfigData) -> u64 {
    #[cfg(feature = "iface-rnode")]
    if let crate::interface::KnownConfig::RNode(rnode) = data.known() {
        if rnode.multi {
            return 1 + rnode.subinterfaces.len() as u64;
        }
    }
    let _ = data;
    1
}

/// The config of the interface `iface` of `parsed`, the config file reread
/// to attach it. As upstream, whether it may be discoverable follows the
/// running instance (`management`), not the file reread.
pub(crate) fn parse_managed_interface(
    iface: &config::ParsedInterface,
    parsed: &config::RnsConfig,
    management: &InterfaceManagementConfig,
    id: rns_core::transport::types::InterfaceId,
    registry: &crate::interface::registry::InterfaceRegistry,
) -> io::Result<InterfaceConfig> {
    let factory = registry.get(&iface.interface_type).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported interface type '{}'", iface.interface_type),
        )
    })?;
    let discoverable = discoverable_on_instance(
        &iface.name,
        iface
            .params
            .get("discoverable")
            .and_then(|value| config::parse_bool_pub(value))
            .unwrap_or(false),
        management.transport_enabled,
        management.static_transport_identity,
    );
    let ignore_warnings = iface
        .params
        .get("ignore_config_warnings")
        .and_then(|value| config::parse_bool_pub(value))
        .unwrap_or(false);
    let kind = iface.kind();
    let mode = normalize_discovery_mode(
        kind,
        parse_interface_mode(&iface.mode),
        discoverable,
        ignore_warnings,
    );
    let ifac = extract_ifac_config(&iface.params, factory.default_ifac_size());
    let discovery = discoverable
        .then(|| extract_discovery_config(&iface.name, &iface.interface_type, &iface.params))
        .flatten();
    let ingress_control = parse_ingress_control_config(kind, &iface.params)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let stamp_costs = parse_interface_stamp_costs(&iface.params)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let announce_limits = parse_interface_announce_limits(&iface.params)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let recursive_prs = iface
        .params
        .get("recursive_prs")
        .and_then(|value| config::parse_bool_pub(value))
        .unwrap_or(false);
    let announces_from_internal = iface
        .params
        .get("announces_from_internal")
        .and_then(|value| config::parse_bool_pub(value))
        .unwrap_or(true);
    let announces_to_internal = iface
        .params
        .get("announces_to_internal")
        .and_then(|value| config::parse_bool_pub(value));
    let gravity = parse_interface_gravity(
        iface.params.get("gravity").map(String::as_str),
        parsed.reticulum.default_gravity,
    );
    let mut params = iface.params.clone();
    params
        .entry("storage_dir".to_string())
        .or_insert_with(|| management.storage_dir.to_string_lossy().to_string());
    if let Some(device) = &parsed.reticulum.device {
        params
            .entry("device".to_string())
            .or_insert_with(|| device.clone());
    }
    let config_data = factory
        .parse_config_section(
            &iface.name,
            id,
            crate::interface::ConfigSection {
                params: &params,
                children: &iface.subinterfaces,
            },
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Ok(InterfaceConfig {
        name: iface.name.clone(),
        type_name: iface.interface_type.clone(),
        config_data,
        mode,
        gravity,
        hop_limiter: parse_interface_hop_limiter(
            iface.params.get("hop_limiter").map(String::as_str),
        ),
        recursive_prs,
        announces_from_internal,
        announces_to_internal,
        ingress_control,
        stamp_costs,
        announce_limits,
        ifac,
        discovery,
    })
}
