//! Runtime settings every interface has: mode, IFAC, announce limits
//! and the like.

use super::*;

impl Driver {
    pub(crate) fn list_generic_interface_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<String> = self
            .interfaces
            .values()
            .map(|entry| entry.info.name.clone())
            .collect();
        names.sort();
        names.dedup();
        for name in names {
            for suffix in [
                "enabled",
                "mode",
                "gravity",
                "announce_rate_target",
                "announce_rate_grace",
                "announce_rate_penalty",
                "announce_cap",
                "ingress_control",
                "ic_max_held_announces",
                "ic_burst_hold",
                "ic_burst_freq_new",
                "ic_burst_freq",
                "ic_pr_burst_freq_new",
                "ic_pr_burst_freq",
                "egress_control",
                "ec_pr_freq",
                "ic_new_time",
                "ic_burst_penalty",
                "ic_held_release_interval",
            ] {
                let key = format!("interface.{}.{}", name, suffix);
                if let Some(entry) = self.generic_interface_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
            if self.runtime_config.ifac.contains_key(&name) {
                for suffix in ["ifac_netname", "ifac_passphrase", "ifac_size_bytes"] {
                    let key = format!("interface.{}.{}", name, suffix);
                    if let Some(entry) = self.generic_interface_runtime_entry(&key) {
                        entries.push(entry);
                    }
                }
            }
        }
        entries
    }

    pub(crate) fn generic_interface_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("interface.")?;
        let (name, setting) = rest.rsplit_once('.')?;
        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          apply_mode: RuntimeConfigApplyMode,
                          description: &str|
         -> RuntimeConfigEntry {
            RuntimeConfigEntry {
                key: key.to_string(),
                source: if value == default {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value,
                default,
                apply_mode,
                description: Some(description.to_string()),
            }
        };
        match setting {
            "enabled" => {
                let entry = self
                    .interfaces
                    .values()
                    .find(|entry| entry.info.name == name)?;
                Some(make_entry(
                    RuntimeConfigValue::Bool(entry.enabled),
                    RuntimeConfigValue::Bool(true),
                    RuntimeConfigApplyMode::Immediate,
                    "Administrative enable/disable state for this interface.",
                ))
            }
            "ifac_netname" => {
                let current = self.runtime_config.ifac.get(name)?;
                let startup = self.runtime_config.ifac_defaults.get(name)?;
                Some(make_entry(
                    current
                        .netname
                        .clone()
                        .map(RuntimeConfigValue::String)
                        .unwrap_or(RuntimeConfigValue::Null),
                    startup
                        .netname
                        .clone()
                        .map(RuntimeConfigValue::String)
                        .unwrap_or(RuntimeConfigValue::Null),
                    RuntimeConfigApplyMode::Immediate,
                    "IFAC network name for this interface; null clears it.",
                ))
            }
            "ifac_passphrase" => {
                let current = self.runtime_config.ifac.get(name)?;
                let startup = self.runtime_config.ifac_defaults.get(name)?;
                let current_value = current
                    .netkey
                    .as_ref()
                    .map(|_| RuntimeConfigValue::String("<redacted>".to_string()))
                    .unwrap_or(RuntimeConfigValue::Null);
                let default_value = startup
                    .netkey
                    .as_ref()
                    .map(|_| RuntimeConfigValue::String("<redacted>".to_string()))
                    .unwrap_or(RuntimeConfigValue::Null);
                Some(RuntimeConfigEntry {
                    key: key.to_string(),
                    source: if current.netkey == startup.netkey {
                        RuntimeConfigSource::Startup
                    } else {
                        RuntimeConfigSource::RuntimeOverride
                    },
                    value: current_value,
                    default: default_value,
                    apply_mode: RuntimeConfigApplyMode::Immediate,
                    description: Some(
                        "IFAC passphrase for this interface; write-only, set a string to change it or null to clear it."
                            .to_string(),
                    ),
                })
            }
            "ifac_size_bytes" => {
                let current = self.runtime_config.ifac.get(name)?;
                let startup = self.runtime_config.ifac_defaults.get(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Int(current.size as i64),
                    RuntimeConfigValue::Int(startup.size as i64),
                    RuntimeConfigApplyMode::Immediate,
                    "IFAC size in bytes; applies when IFAC is enabled.",
                ))
            }
            "mode" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::String(Self::interface_mode_name(current.mode)),
                    RuntimeConfigValue::String(Self::interface_mode_name(startup.mode)),
                    RuntimeConfigApplyMode::Immediate,
                    "Routing mode for this interface.",
                ))
            }
            "gravity" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Int(current.gravity),
                    RuntimeConfigValue::Int(startup.gravity),
                    RuntimeConfigApplyMode::Immediate,
                    "Signed path-selection preference for this interface.",
                ))
            }
            "announce_rate_target" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    current
                        .announce_rate_target
                        .map(RuntimeConfigValue::Float)
                        .unwrap_or(RuntimeConfigValue::Null),
                    startup
                        .announce_rate_target
                        .map(RuntimeConfigValue::Float)
                        .unwrap_or(RuntimeConfigValue::Null),
                    RuntimeConfigApplyMode::Immediate,
                    "Optional announce rate target in announces/sec; null disables it.",
                ))
            }
            "announce_rate_grace" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Int(current.announce_rate_grace as i64),
                    RuntimeConfigValue::Int(startup.announce_rate_grace as i64),
                    RuntimeConfigApplyMode::Immediate,
                    "Announce rate grace period in announces.",
                ))
            }
            "announce_rate_penalty" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.announce_rate_penalty),
                    RuntimeConfigValue::Float(startup.announce_rate_penalty),
                    RuntimeConfigApplyMode::Immediate,
                    "Announce rate penalty multiplier.",
                ))
            }
            "announce_cap" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.announce_cap),
                    RuntimeConfigValue::Float(startup.announce_cap),
                    RuntimeConfigApplyMode::Immediate,
                    "Fraction of bitrate reserved for announces.",
                ))
            }
            "ingress_control" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Bool(current.ingress_control.enabled),
                    RuntimeConfigValue::Bool(startup.ingress_control.enabled),
                    RuntimeConfigApplyMode::Immediate,
                    "Whether ingress control is enabled for this interface.",
                ))
            }
            "ic_max_held_announces" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Int(current.ingress_control.max_held_announces as i64),
                    RuntimeConfigValue::Int(startup.ingress_control.max_held_announces as i64),
                    RuntimeConfigApplyMode::Immediate,
                    "Maximum held announces retained while ingress control is limiting this interface.",
                ))
            }
            "ic_burst_hold" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.ingress_control.burst_hold),
                    RuntimeConfigValue::Float(startup.ingress_control.burst_hold),
                    RuntimeConfigApplyMode::Immediate,
                    "Seconds to keep ingress-control burst state active before releasing held announces.",
                ))
            }
            "ic_burst_freq_new" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.ingress_control.burst_freq_new),
                    RuntimeConfigValue::Float(startup.ingress_control.burst_freq_new),
                    RuntimeConfigApplyMode::Immediate,
                    "Announce frequency threshold for new interfaces.",
                ))
            }
            "ic_burst_freq" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.ingress_control.burst_freq),
                    RuntimeConfigValue::Float(startup.ingress_control.burst_freq),
                    RuntimeConfigApplyMode::Immediate,
                    "Announce frequency threshold for established interfaces.",
                ))
            }
            "ic_pr_burst_freq_new" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.ingress_control.pr_burst_freq_new),
                    RuntimeConfigValue::Float(startup.ingress_control.pr_burst_freq_new),
                    RuntimeConfigApplyMode::Immediate,
                    "Path request frequency threshold for new interfaces.",
                ))
            }
            "ic_pr_burst_freq" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.ingress_control.pr_burst_freq),
                    RuntimeConfigValue::Float(startup.ingress_control.pr_burst_freq),
                    RuntimeConfigApplyMode::Immediate,
                    "Path request frequency threshold for established interfaces.",
                ))
            }
            "egress_control" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Bool(current.ingress_control.egress_enabled),
                    RuntimeConfigValue::Bool(startup.ingress_control.egress_enabled),
                    RuntimeConfigApplyMode::Immediate,
                    "Whether egress path request limiting is enabled for this interface.",
                ))
            }
            "ec_pr_freq" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.ingress_control.egress_pr_freq),
                    RuntimeConfigValue::Float(startup.ingress_control.egress_pr_freq),
                    RuntimeConfigApplyMode::Immediate,
                    "Outgoing path request frequency threshold for egress control.",
                ))
            }
            "ic_new_time" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.ingress_control.new_time),
                    RuntimeConfigValue::Float(startup.ingress_control.new_time),
                    RuntimeConfigApplyMode::Immediate,
                    "Seconds after interface start that ingress control uses the new-interface burst threshold.",
                ))
            }
            "ic_burst_penalty" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.ingress_control.burst_penalty),
                    RuntimeConfigValue::Float(startup.ingress_control.burst_penalty),
                    RuntimeConfigApplyMode::Immediate,
                    "Seconds to wait after a burst before releasing held announces.",
                ))
            }
            "ic_held_release_interval" => {
                let (_, current, startup) = self.interface_runtime_infos_by_name(name)?;
                Some(make_entry(
                    RuntimeConfigValue::Float(current.ingress_control.held_release_interval),
                    RuntimeConfigValue::Float(startup.ingress_control.held_release_interval),
                    RuntimeConfigApplyMode::Immediate,
                    "Seconds between held announce releases.",
                ))
            }
            _ => None,
        }
    }

    pub(crate) fn split_generic_interface_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("interface.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.rsplit_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    pub(crate) fn interface_runtime_infos_by_name(
        &self,
        name: &str,
    ) -> Option<(
        rns_core::transport::types::InterfaceId,
        &rns_core::transport::types::InterfaceInfo,
        &rns_core::transport::types::InterfaceInfo,
    )> {
        let (id, entry) = self
            .interfaces
            .iter()
            .find(|(_, entry)| entry.info.name == name)?;
        let startup = self.runtime_config.interface_defaults.get(name)?;
        Some((*id, &entry.info, startup))
    }

    pub(crate) fn interface_mode_name(mode: u8) -> String {
        match mode {
            rns_core::constants::MODE_FULL => "full".to_string(),
            rns_core::constants::MODE_ACCESS_POINT => "access_point".to_string(),
            rns_core::constants::MODE_POINT_TO_POINT => "point_to_point".to_string(),
            rns_core::constants::MODE_ROAMING => "roaming".to_string(),
            rns_core::constants::MODE_BOUNDARY => "boundary".to_string(),
            rns_core::constants::MODE_GATEWAY => "gateway".to_string(),
            rns_core::constants::MODE_INTERNAL => "internal".to_string(),
            _ => mode.to_string(),
        }
    }

    pub(crate) fn parse_interface_mode(value: &RuntimeConfigValue) -> Option<u8> {
        match value {
            RuntimeConfigValue::Int(v) if *v >= 0 && *v <= u8::MAX as i64 => Some(*v as u8),
            RuntimeConfigValue::String(s) => match s.to_ascii_lowercase().as_str() {
                "full" => Some(rns_core::constants::MODE_FULL),
                "access_point" | "accesspoint" | "ap" => {
                    Some(rns_core::constants::MODE_ACCESS_POINT)
                }
                "point_to_point" | "pointtopoint" | "ptp" => {
                    Some(rns_core::constants::MODE_POINT_TO_POINT)
                }
                "roaming" => Some(rns_core::constants::MODE_ROAMING),
                "boundary" => Some(rns_core::constants::MODE_BOUNDARY),
                "gateway" | "gw" => Some(rns_core::constants::MODE_GATEWAY),
                "internal" => Some(rns_core::constants::MODE_INTERNAL),
                _ => None,
            },
            _ => None,
        }
    }

    pub(crate) fn apply_interface_ifac_runtime(
        entry: &mut InterfaceEntry,
        config: &IfacRuntimeConfig,
    ) {
        entry.ifac = if config.netname.is_some() || config.netkey.is_some() {
            match ifac::derive_ifac(
                config.netname.as_deref(),
                config.netkey.as_deref(),
                config.size,
            ) {
                Ok(state) => Some(state),
                Err(err) => {
                    log::warn!(
                        "failed to apply IFAC runtime for {}: {}",
                        entry.info.name,
                        err
                    );
                    None
                }
            }
        } else {
            None
        };
    }

    pub(crate) fn set_generic_interface_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_generic_interface_runtime_key(key)?;
        let (id, _) = self
            .interfaces
            .iter()
            .find(|(_, entry)| entry.info.name == name)
            .map(|(id, entry)| (*id, entry))
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("interface '{}' not found", name),
            })?;
        let entry = self.interfaces.get_mut(&id).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("interface '{}' not found", name),
        })?;
        match setting {
            "enabled" => {
                entry.enabled = Self::expect_bool(value, key)?;
            }
            "ifac_netname" => {
                let runtime = self
                    .runtime_config
                    .ifac
                    .get_mut(name)
                    .ok_or(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::UnknownKey,
                        message: format!("unknown runtime-config key '{}'", key),
                    })?;
                runtime.netname = match value {
                    RuntimeConfigValue::Null => None,
                    RuntimeConfigValue::String(value) => Some(value),
                    _ => {
                        return Err(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::InvalidType,
                            message: format!("{} expects a string or null", key),
                        })
                    }
                };
                Self::apply_interface_ifac_runtime(entry, runtime);
            }
            "ifac_passphrase" => {
                let runtime = self
                    .runtime_config
                    .ifac
                    .get_mut(name)
                    .ok_or(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::UnknownKey,
                        message: format!("unknown runtime-config key '{}'", key),
                    })?;
                runtime.netkey = match value {
                    RuntimeConfigValue::Null => None,
                    RuntimeConfigValue::String(value) => Some(value),
                    _ => {
                        return Err(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::InvalidType,
                            message: format!("{} expects a string or null", key),
                        })
                    }
                };
                Self::apply_interface_ifac_runtime(entry, runtime);
            }
            "ifac_size_bytes" => {
                let runtime = self
                    .runtime_config
                    .ifac
                    .get_mut(name)
                    .ok_or(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::UnknownKey,
                        message: format!("unknown runtime-config key '{}'", key),
                    })?;
                runtime.size =
                    (Self::expect_u64(value, key)? as usize).max(crate::ifac::IFAC_MIN_SIZE);
                Self::apply_interface_ifac_runtime(entry, runtime);
            }
            "mode" => {
                entry.info.mode = Self::parse_interface_mode(&value).ok_or(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::InvalidValue,
                    message: format!("{} must be a valid interface mode", key),
                })?;
            }
            "gravity" => entry.info.gravity = Self::expect_i64(value, key)?,
            "announce_rate_target" => {
                entry.info.announce_rate_target = match value {
                    RuntimeConfigValue::Null => None,
                    RuntimeConfigValue::Float(v) if v >= 0.0 => Some(v),
                    RuntimeConfigValue::Int(v) if v >= 0 => Some(v as f64),
                    RuntimeConfigValue::Float(_) | RuntimeConfigValue::Int(_) => {
                        return Err(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::InvalidValue,
                            message: format!("{} must be >= 0", key),
                        })
                    }
                    _ => {
                        return Err(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::InvalidType,
                            message: format!("{} expects a numeric value or null", key),
                        })
                    }
                };
            }
            "announce_rate_grace" => {
                entry.info.announce_rate_grace = Self::expect_u64(value, key)? as u32
            }
            "announce_rate_penalty" => {
                entry.info.announce_rate_penalty = Self::expect_f64(value, key)?
            }
            "announce_cap" => entry.info.announce_cap = Self::expect_f64(value, key)?,
            "ingress_control" => {
                entry.info.ingress_control.enabled = Self::expect_bool(value, key)?
            }
            "ic_max_held_announces" => {
                entry.info.ingress_control.max_held_announces =
                    Self::expect_u64(value, key)? as usize
            }
            "ic_burst_hold" => {
                entry.info.ingress_control.burst_hold = Self::expect_f64(value, key)?
            }
            "ic_burst_freq_new" => {
                entry.info.ingress_control.burst_freq_new = Self::expect_f64(value, key)?
            }
            "ic_burst_freq" => {
                entry.info.ingress_control.burst_freq = Self::expect_f64(value, key)?
            }
            "ic_pr_burst_freq_new" => {
                entry.info.ingress_control.pr_burst_freq_new = Self::expect_f64(value, key)?
            }
            "ic_pr_burst_freq" => {
                entry.info.ingress_control.pr_burst_freq = Self::expect_f64(value, key)?
            }
            "egress_control" => {
                entry.info.ingress_control.egress_enabled = Self::expect_bool(value, key)?
            }
            "ec_pr_freq" => {
                entry.info.ingress_control.egress_pr_freq = Self::expect_f64(value, key)?
            }
            "ic_new_time" => entry.info.ingress_control.new_time = Self::expect_f64(value, key)?,
            "ic_burst_penalty" => {
                entry.info.ingress_control.burst_penalty = Self::expect_f64(value, key)?
            }
            "ic_held_release_interval" => {
                entry.info.ingress_control.held_release_interval = Self::expect_f64(value, key)?
            }
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        let info = entry.info.clone();
        self.engine.register_interface(info);
        Ok(())
    }

    pub(crate) fn reset_generic_interface_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_generic_interface_runtime_key(key)?;
        let startup = self
            .runtime_config
            .interface_defaults
            .get(name)
            .cloned()
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("interface '{}' not found", name),
            })?;
        let entry = self
            .interfaces
            .values_mut()
            .find(|entry| entry.info.name == name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("interface '{}' not found", name),
            })?;
        match setting {
            "enabled" => entry.enabled = true,
            "ifac_netname" => {
                let startup_ifac =
                    self.runtime_config
                        .ifac_defaults
                        .get(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                let runtime = self
                    .runtime_config
                    .ifac
                    .get_mut(name)
                    .ok_or(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::UnknownKey,
                        message: format!("unknown runtime-config key '{}'", key),
                    })?;
                runtime.netname = startup_ifac.netname.clone();
                Self::apply_interface_ifac_runtime(entry, runtime);
            }
            "ifac_passphrase" => {
                let startup_ifac =
                    self.runtime_config
                        .ifac_defaults
                        .get(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                let runtime = self
                    .runtime_config
                    .ifac
                    .get_mut(name)
                    .ok_or(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::UnknownKey,
                        message: format!("unknown runtime-config key '{}'", key),
                    })?;
                runtime.netkey = startup_ifac.netkey.clone();
                Self::apply_interface_ifac_runtime(entry, runtime);
            }
            "ifac_size_bytes" => {
                let startup_ifac =
                    self.runtime_config
                        .ifac_defaults
                        .get(name)
                        .ok_or(RuntimeConfigError {
                            code: RuntimeConfigErrorCode::UnknownKey,
                            message: format!("unknown runtime-config key '{}'", key),
                        })?;
                let runtime = self
                    .runtime_config
                    .ifac
                    .get_mut(name)
                    .ok_or(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::UnknownKey,
                        message: format!("unknown runtime-config key '{}'", key),
                    })?;
                runtime.size = startup_ifac.size;
                Self::apply_interface_ifac_runtime(entry, runtime);
            }
            "mode" => entry.info.mode = startup.mode,
            "gravity" => entry.info.gravity = startup.gravity,
            "announce_rate_target" => {
                entry.info.announce_rate_target = startup.announce_rate_target
            }
            "announce_rate_grace" => entry.info.announce_rate_grace = startup.announce_rate_grace,
            "announce_rate_penalty" => {
                entry.info.announce_rate_penalty = startup.announce_rate_penalty
            }
            "announce_cap" => entry.info.announce_cap = startup.announce_cap,
            "ingress_control" => {
                entry.info.ingress_control.enabled = startup.ingress_control.enabled
            }
            "ic_max_held_announces" => {
                entry.info.ingress_control.max_held_announces =
                    startup.ingress_control.max_held_announces
            }
            "ic_burst_hold" => {
                entry.info.ingress_control.burst_hold = startup.ingress_control.burst_hold
            }
            "ic_burst_freq_new" => {
                entry.info.ingress_control.burst_freq_new = startup.ingress_control.burst_freq_new
            }
            "ic_burst_freq" => {
                entry.info.ingress_control.burst_freq = startup.ingress_control.burst_freq
            }
            "ic_pr_burst_freq_new" => {
                entry.info.ingress_control.pr_burst_freq_new =
                    startup.ingress_control.pr_burst_freq_new
            }
            "ic_pr_burst_freq" => {
                entry.info.ingress_control.pr_burst_freq = startup.ingress_control.pr_burst_freq
            }
            "egress_control" => {
                entry.info.ingress_control.egress_enabled = startup.ingress_control.egress_enabled
            }
            "ec_pr_freq" => {
                entry.info.ingress_control.egress_pr_freq = startup.ingress_control.egress_pr_freq
            }
            "ic_new_time" => entry.info.ingress_control.new_time = startup.ingress_control.new_time,
            "ic_burst_penalty" => {
                entry.info.ingress_control.burst_penalty = startup.ingress_control.burst_penalty
            }
            "ic_held_release_interval" => {
                entry.info.ingress_control.held_release_interval =
                    startup.ingress_control.held_release_interval
            }
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        let info = entry.info.clone();
        self.engine.register_interface(info);
        Ok(())
    }
}
