//! Runtime settings of backbone interfaces, their clients and their
//! discovery.

use super::*;

impl RuntimeConfigHandles {
    #[cfg(feature = "iface-backbone")]
    pub(crate) fn split_backbone_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("backbone.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    /// Returns the interface's name when a discovery setting changed, so
    /// the driver brings its discovery announces in step.
    #[cfg(feature = "iface-backbone")]
    pub(crate) fn set_backbone_runtime_config<'a>(
        &mut self,
        key: &'a str,
        value: RuntimeConfigValue,
    ) -> Result<Option<&'a str>, RuntimeConfigError> {
        let (name, setting) = self.split_backbone_runtime_key(key)?;
        if matches!(
            setting,
            "discoverable"
                | "discovery_name"
                | "announce_interval_secs"
                | "reachable_on"
                | "location_cmd"
                | "stamp_value"
                | "latitude"
                | "longitude"
                | "height"
        ) {
            return self
                .set_backbone_discovery_runtime_config(key, value)
                .map(Some);
        }
        let handle = self.backbone.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("backbone interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "backbone runtime");
        match setting {
            "idle_timeout_secs" => {
                runtime.idle_timeout = set_optional_duration(value, key)?;
                Ok(None)
            }
            "write_stall_timeout_secs" => {
                runtime.write_stall_timeout = set_optional_duration(value, key)?;
                Ok(None)
            }
            "max_penalty_duration_secs" => {
                runtime.abuse.max_penalty_duration = set_optional_duration(value, key)?;
                Ok(None)
            }
            "max_connections" => {
                runtime.max_connections = set_optional_usize(value, key)?;
                Ok(None)
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn split_backbone_discovery_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("backbone.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn set_backbone_discovery_runtime_config<'a>(
        &mut self,
        key: &'a str,
        value: RuntimeConfigValue,
    ) -> Result<&'a str, RuntimeConfigError> {
        let (name, setting) = self.split_backbone_discovery_runtime_key(key)?;
        let handle = self
            .backbone_discovery
            .get_mut(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("backbone interface '{}' not found", name),
            })?;
        match setting {
            "discoverable" => {
                handle.current.discoverable = expect_bool(value, key)?;
            }
            "discovery_name" => {
                handle.current.config.discovery_name = expect_string(value, key)?;
            }
            "announce_interval_secs" => {
                let secs = expect_u64(value, key)?;
                if secs < 300 {
                    return Err(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::InvalidValue,
                        message: format!("{} must be >= 300", key),
                    });
                }
                handle.current.config.announce_interval = secs;
            }
            "reachable_on" => {
                handle.current.config.reachable_on = expect_optional_string(value, key)?;
            }
            "location_cmd" => {
                handle.current.config.location_cmd = expect_optional_string(value, key)?;
            }
            "stamp_value" => {
                handle.current.config.stamp_value = expect_discovery_stamp_value(value, key)?;
            }
            "latitude" => {
                handle.current.config.latitude = expect_optional_f64(value, key)?;
            }
            "longitude" => {
                handle.current.config.longitude = expect_optional_f64(value, key)?;
            }
            "height" => {
                handle.current.config.height = expect_optional_f64(value, key)?;
            }
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                });
            }
        }
        Ok(name)
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn reset_backbone_discovery_runtime_config<'a>(
        &mut self,
        key: &'a str,
    ) -> Result<&'a str, RuntimeConfigError> {
        let (name, setting) = self.split_backbone_discovery_runtime_key(key)?;
        let handle = self
            .backbone_discovery
            .get_mut(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("backbone interface '{}' not found", name),
            })?;
        match setting {
            "discoverable" => handle.current.discoverable = handle.startup.discoverable,
            "discovery_name" => {
                handle.current.config.discovery_name = handle.startup.config.discovery_name.clone()
            }
            "announce_interval_secs" => {
                handle.current.config.announce_interval = handle.startup.config.announce_interval
            }
            "reachable_on" => {
                handle.current.config.reachable_on = handle.startup.config.reachable_on.clone()
            }
            "location_cmd" => {
                handle.current.config.location_cmd = handle.startup.config.location_cmd.clone()
            }
            "stamp_value" => handle.current.config.stamp_value = handle.startup.config.stamp_value,
            "latitude" => handle.current.config.latitude = handle.startup.config.latitude,
            "longitude" => handle.current.config.longitude = handle.startup.config.longitude,
            "height" => handle.current.config.height = handle.startup.config.height,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                });
            }
        }
        Ok(name)
    }

    /// Returns the interface's name when a discovery setting changed, so
    /// the driver brings its discovery announces in step.
    #[cfg(feature = "iface-backbone")]
    pub(crate) fn reset_backbone_runtime_config<'a>(
        &mut self,
        key: &'a str,
    ) -> Result<Option<&'a str>, RuntimeConfigError> {
        let (name, setting) = self.split_backbone_runtime_key(key)?;
        if matches!(
            setting,
            "discoverable"
                | "discovery_name"
                | "announce_interval_secs"
                | "reachable_on"
                | "location_cmd"
                | "stamp_value"
                | "latitude"
                | "longitude"
                | "height"
        ) {
            return self.reset_backbone_discovery_runtime_config(key).map(Some);
        }
        let handle = self.backbone.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("backbone interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "backbone runtime");
        let startup = handle.startup.clone();
        match setting {
            "idle_timeout_secs" => runtime.idle_timeout = startup.idle_timeout,
            "write_stall_timeout_secs" => runtime.write_stall_timeout = startup.write_stall_timeout,
            "max_penalty_duration_secs" => {
                runtime.abuse.max_penalty_duration = startup.abuse.max_penalty_duration
            }
            "max_connections" => runtime.max_connections = startup.max_connections,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        Ok(None)
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn list_backbone_client_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.backbone_client.keys().collect();
        names.sort();
        for name in names {
            for suffix in [
                "connect_timeout_secs",
                "reconnect_wait_secs",
                "max_reconnect_tries",
            ] {
                let key = format!("backbone_client.{}.{}", name, suffix);
                if let Some(entry) = self.backbone_client_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn backbone_client_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("backbone_client.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.backbone_client.get(name)?;
        let current = recover_mutex_guard(&handle.runtime, "backbone client runtime").clone();
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
                apply_mode: RuntimeConfigApplyMode::NextReconnect,
                description: Some(description.to_string()),
            }
        };
        match setting {
            "connect_timeout_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.connect_timeout.as_secs_f64()),
                RuntimeConfigValue::Float(startup.connect_timeout.as_secs_f64()),
                "Backbone client connect timeout in seconds; applies on the next reconnect.",
            )),
            "reconnect_wait_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.reconnect_wait.as_secs_f64()),
                RuntimeConfigValue::Float(startup.reconnect_wait.as_secs_f64()),
                "Delay between backbone client reconnect attempts in seconds.",
            )),
            "max_reconnect_tries" => Some(make_entry(
                RuntimeConfigValue::Int(current.max_reconnect_tries.unwrap_or(0) as i64),
                RuntimeConfigValue::Int(startup.max_reconnect_tries.unwrap_or(0) as i64),
                "Maximum backbone client reconnect attempts; 0 disables the cap.",
            )),
            _ => None,
        }
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn split_backbone_client_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key
            .strip_prefix("backbone_client.")
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn set_backbone_client_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_backbone_client_runtime_key(key)?;
        let handle = self.backbone_client.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("backbone client interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "backbone client runtime");
        match setting {
            "connect_timeout_secs" => {
                runtime.connect_timeout = expect_duration_secs(value, key)?;
                Ok(())
            }
            "reconnect_wait_secs" => {
                runtime.reconnect_wait = expect_duration_secs(value, key)?;
                Ok(())
            }
            "max_reconnect_tries" => {
                runtime.max_reconnect_tries = match expect_u64(value, key)? {
                    0 => None,
                    raw => Some(raw as u32),
                };
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn reset_backbone_client_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_backbone_client_runtime_key(key)?;
        let handle = self.backbone_client.get(name).ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::NotFound,
            message: format!("backbone client interface '{}' not found", name),
        })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "backbone client runtime");
        let startup = handle.startup.clone();
        match setting {
            "connect_timeout_secs" => runtime.connect_timeout = startup.connect_timeout,
            "reconnect_wait_secs" => runtime.reconnect_wait = startup.reconnect_wait,
            "max_reconnect_tries" => runtime.max_reconnect_tries = startup.max_reconnect_tries,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn list_backbone_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.backbone.keys().collect();
        names.sort();
        for name in names {
            for suffix in [
                "idle_timeout_secs",
                "write_stall_timeout_secs",
                "max_penalty_duration_secs",
                "max_connections",
            ] {
                let key = format!("backbone.{}.{}", name, suffix);
                if let Some(entry) = self.backbone_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
            for suffix in [
                "discoverable",
                "discovery_name",
                "announce_interval_secs",
                "reachable_on",
                "location_cmd",
                "stamp_value",
                "latitude",
                "longitude",
                "height",
            ] {
                let key = format!("backbone.{}.{}", name, suffix);
                if let Some(entry) = self.backbone_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-backbone")]
    pub(crate) fn backbone_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("backbone.")?;
        let (name, setting) = rest.split_once('.')?;

        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          apply_mode: RuntimeConfigApplyMode,
                          description: &str| RuntimeConfigEntry {
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
        };

        if Self::is_discovery_runtime_setting(setting) {
            let handle = self.backbone_discovery.get(name)?;
            return Self::discovery_runtime_entry(
                key,
                setting,
                "backbone",
                handle.current.discoverable,
                handle.startup.discoverable,
                &handle.current.config,
                &handle.startup.config,
            );
        }

        if let Some(handle) = self.backbone.get(name) {
            let current = recover_mutex_guard(&handle.runtime, "backbone runtime").clone();
            let startup = handle.startup.clone();
            return match setting {
                "idle_timeout_secs" => Some(make_entry(
                    RuntimeConfigValue::Float(current.idle_timeout.map(|d| d.as_secs_f64()).unwrap_or(0.0)),
                    RuntimeConfigValue::Float(startup.idle_timeout.map(|d| d.as_secs_f64()).unwrap_or(0.0)),
                    RuntimeConfigApplyMode::Immediate,
                    "Disconnect silent inbound peers after this many seconds; 0 disables the timeout.",
                )),
                "write_stall_timeout_secs" => Some(make_entry(
                    RuntimeConfigValue::Float(current.write_stall_timeout.map(|d| d.as_secs_f64()).unwrap_or(0.0)),
                    RuntimeConfigValue::Float(startup.write_stall_timeout.map(|d| d.as_secs_f64()).unwrap_or(0.0)),
                    RuntimeConfigApplyMode::Immediate,
                    "Disconnect peers whose send buffer remains unwritable for this many seconds; 0 disables the timeout.",
                )),
                "max_penalty_duration_secs" => Some(make_entry(
                    RuntimeConfigValue::Float(current.abuse.max_penalty_duration.map(|d| d.as_secs_f64()).unwrap_or(0.0)),
                    RuntimeConfigValue::Float(startup.abuse.max_penalty_duration.map(|d| d.as_secs_f64()).unwrap_or(0.0)),
                    RuntimeConfigApplyMode::Immediate,
                    "Maximum accepted backbone blacklist duration; 0 means no cap.",
                )),
                "max_connections" => Some(make_entry(
                    RuntimeConfigValue::Int(current.max_connections.unwrap_or(0) as i64),
                    RuntimeConfigValue::Int(startup.max_connections.unwrap_or(0) as i64),
                    RuntimeConfigApplyMode::NewConnectionsOnly,
                    "Maximum simultaneous inbound backbone connections; 0 disables the cap.",
                )),
                _ => None,
            };
        }

        None
    }
}
