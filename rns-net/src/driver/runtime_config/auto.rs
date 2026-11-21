//! Runtime settings of AutoInterfaces.

use super::*;

impl RuntimeConfigHandles {
    #[cfg(feature = "iface-auto")]
    pub(crate) fn list_auto_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.auto.keys().collect();
        names.sort();
        for name in names {
            for suffix in [
                "announce_interval_secs",
                "peer_timeout_secs",
                "peer_job_interval_secs",
            ] {
                let key = format!("auto.{}.{}", name, suffix);
                if let Some(entry) = self.auto_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-auto")]
    pub(crate) fn auto_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("auto.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.auto.get(name)?;
        let current = recover_mutex_guard(&handle.runtime, "auto runtime").clone();
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
            "announce_interval_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.announce_interval_secs),
                RuntimeConfigValue::Float(startup.announce_interval_secs),
                "Interval between multicast discovery announces in seconds.",
            )),
            "peer_timeout_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.peer_timeout_secs),
                RuntimeConfigValue::Float(startup.peer_timeout_secs),
                "How long an Auto peer may stay quiet before being culled.",
            )),
            "peer_job_interval_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.peer_job_interval_secs),
                RuntimeConfigValue::Float(startup.peer_job_interval_secs),
                "Interval between Auto peer maintenance passes.",
            )),
            _ => None,
        }
    }

    #[cfg(feature = "iface-auto")]
    pub(crate) fn split_auto_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("auto.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-auto")]
    pub(crate) fn set_auto_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_auto_runtime_key(key)?;
        let handle = self.auto.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("auto interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "auto runtime");
        match setting {
            "announce_interval_secs" => {
                let secs = expect_f64(value, key)?.max(0.1);
                // The auto interface sleeps for 1.2x the announce interval
                // before peering, so that value must be a valid duration too.
                duration_from_secs(secs * 1.2, key)?;
                runtime.announce_interval_secs = secs
            }
            "peer_timeout_secs" => {
                let secs = expect_f64(value, key)?.max(0.1);
                duration_from_secs(secs, key)?;
                runtime.peer_timeout_secs = secs
            }
            "peer_job_interval_secs" => {
                let secs = expect_f64(value, key)?.max(0.1);
                duration_from_secs(secs, key)?;
                runtime.peer_job_interval_secs = secs
            }
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                });
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-auto")]
    pub(crate) fn reset_auto_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_auto_runtime_key(key)?;
        let handle = self.auto.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("auto interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "auto runtime");
        let startup = handle.startup.clone();
        match setting {
            "announce_interval_secs" => {
                runtime.announce_interval_secs = startup.announce_interval_secs
            }
            "peer_timeout_secs" => runtime.peer_timeout_secs = startup.peer_timeout_secs,
            "peer_job_interval_secs" => {
                runtime.peer_job_interval_secs = startup.peer_job_interval_secs
            }
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
