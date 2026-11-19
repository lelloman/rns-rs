//! Runtime settings of UDP interfaces.

use super::*;

impl Driver {
    #[cfg(feature = "iface-udp")]
    pub(crate) fn list_udp_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.udp_runtime.keys().collect();
        names.sort();
        for name in names {
            for suffix in ["forward_ip", "forward_port"] {
                let key = format!("udp.{}.{}", name, suffix);
                if let Some(entry) = self.udp_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-udp")]
    pub(crate) fn udp_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("udp.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.udp_runtime.get(name)?;
        let current = recover_mutex_guard(&handle.runtime, "udp runtime").clone();
        let startup = handle.startup.clone();
        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
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
                apply_mode: RuntimeConfigApplyMode::Immediate,
                description: Some(description.to_string()),
            }
        };
        match setting {
            "forward_ip" => Some(make_entry(
                current
                    .forward_ip
                    .clone()
                    .map(RuntimeConfigValue::String)
                    .unwrap_or(RuntimeConfigValue::Null),
                startup
                    .forward_ip
                    .clone()
                    .map(RuntimeConfigValue::String)
                    .unwrap_or(RuntimeConfigValue::Null),
                "Outbound UDP destination IP or hostname; null clears it.",
            )),
            "forward_port" => Some(make_entry(
                current
                    .forward_port
                    .map(|value| RuntimeConfigValue::Int(value as i64))
                    .unwrap_or(RuntimeConfigValue::Null),
                startup
                    .forward_port
                    .map(|value| RuntimeConfigValue::Int(value as i64))
                    .unwrap_or(RuntimeConfigValue::Null),
                "Outbound UDP destination port; null clears it.",
            )),
            _ => None,
        }
    }

    #[cfg(feature = "iface-udp")]
    pub(crate) fn split_udp_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("udp.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-udp")]
    pub(crate) fn set_udp_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_udp_runtime_key(key)?;
        let handle = self.udp_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("udp interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "udp runtime");
        match setting {
            "forward_ip" => {
                runtime.forward_ip = Self::expect_optional_string(value, key)?;
                Ok(())
            }
            "forward_port" => {
                runtime.forward_port = match value {
                    RuntimeConfigValue::Null => None,
                    other => Some(Self::expect_u64(other, key)? as u16),
                };
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-udp")]
    pub(crate) fn reset_udp_runtime_config(&mut self, key: &str) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_udp_runtime_key(key)?;
        let handle = self.udp_runtime.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("udp interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "udp runtime");
        let startup = handle.startup.clone();
        match setting {
            "forward_ip" => runtime.forward_ip = startup.forward_ip,
            "forward_port" => runtime.forward_port = startup.forward_port,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        Ok(())
    }
}
