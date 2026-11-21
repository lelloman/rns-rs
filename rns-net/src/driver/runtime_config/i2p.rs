//! Runtime settings of I2P interfaces.

use super::*;

impl RuntimeConfigHandles {
    #[cfg(feature = "iface-i2p")]
    pub(crate) fn list_i2p_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.i2p.keys().collect();
        names.sort();
        for name in names {
            let key = format!("i2p.{}.reconnect_wait_secs", name);
            if let Some(entry) = self.i2p_runtime_entry(&key) {
                entries.push(entry);
            }
        }
        entries
    }

    #[cfg(feature = "iface-i2p")]
    pub(crate) fn i2p_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("i2p.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.i2p.get(name)?;
        let current = recover_mutex_guard(&handle.runtime, "i2p runtime").clone();
        let startup = handle.startup.clone();
        match setting {
            "reconnect_wait_secs" => Some(RuntimeConfigEntry {
                key: key.to_string(),
                source: if current.reconnect_wait == startup.reconnect_wait {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value: RuntimeConfigValue::Float(current.reconnect_wait.as_secs_f64()),
                default: RuntimeConfigValue::Float(startup.reconnect_wait.as_secs_f64()),
                apply_mode: RuntimeConfigApplyMode::NextReconnect,
                description: Some(
                    "Delay before retrying outbound I2P peer connections.".to_string(),
                ),
            }),
            _ => None,
        }
    }

    #[cfg(feature = "iface-i2p")]
    pub(crate) fn split_i2p_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("i2p.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-i2p")]
    pub(crate) fn set_i2p_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_i2p_runtime_key(key)?;
        let handle = self.i2p.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("i2p interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "i2p runtime");
        match setting {
            "reconnect_wait_secs" => {
                runtime.reconnect_wait = duration_from_secs(expect_f64(value, key)?.max(0.1), key)?;
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-i2p")]
    pub(crate) fn reset_i2p_runtime_config(&mut self, key: &str) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_i2p_runtime_key(key)?;
        let handle = self.i2p.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("i2p interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "i2p runtime");
        let startup = handle.startup.clone();
        match setting {
            "reconnect_wait_secs" => runtime.reconnect_wait = startup.reconnect_wait,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                });
            }
        }
        Ok(())
    }
}
