//! Runtime settings of pipe interfaces.

use super::*;

impl Driver {
    #[cfg(feature = "iface-pipe")]
    pub(crate) fn list_pipe_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.runtime_config.pipe.keys().collect();
        names.sort();
        for name in names {
            let key = format!("pipe.{}.respawn_delay_secs", name);
            if let Some(entry) = self.pipe_runtime_entry(&key) {
                entries.push(entry);
            }
        }
        entries
    }

    #[cfg(feature = "iface-pipe")]
    pub(crate) fn pipe_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("pipe.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.runtime_config.pipe.get(name)?;
        let current = recover_mutex_guard(&handle.runtime, "pipe runtime").clone();
        let startup = handle.startup.clone();
        match setting {
            "respawn_delay_secs" => Some(RuntimeConfigEntry {
                key: key.to_string(),
                source: if current.respawn_delay == startup.respawn_delay {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                value: RuntimeConfigValue::Float(current.respawn_delay.as_secs_f64()),
                default: RuntimeConfigValue::Float(startup.respawn_delay.as_secs_f64()),
                apply_mode: RuntimeConfigApplyMode::NextReconnect,
                description: Some(
                    "Delay before respawning the pipe subprocess after exit.".to_string(),
                ),
            }),
            _ => None,
        }
    }

    #[cfg(feature = "iface-pipe")]
    pub(crate) fn split_pipe_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("pipe.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-pipe")]
    pub(crate) fn set_pipe_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_pipe_runtime_key(key)?;
        let handle = self
            .runtime_config
            .pipe
            .get(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("pipe interface '{}' not found", name),
            })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "pipe runtime");
        match setting {
            "respawn_delay_secs" => {
                runtime.respawn_delay =
                    Self::duration_from_secs(Self::expect_f64(value, key)?.max(0.1), key)?;
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-pipe")]
    pub(crate) fn reset_pipe_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_pipe_runtime_key(key)?;
        let handle = self
            .runtime_config
            .pipe
            .get(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("pipe interface '{}' not found", name),
            })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "pipe runtime");
        let startup = handle.startup.clone();
        match setting {
            "respawn_delay_secs" => runtime.respawn_delay = startup.respawn_delay,
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
