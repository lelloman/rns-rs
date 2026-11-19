//! Runtime settings of TCP servers and clients.

use super::*;

impl Driver {
    #[cfg(feature = "iface-tcp")]
    pub(crate) fn list_tcp_server_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.tcp_server_runtime.keys().collect();
        names.sort();
        for name in names {
            for suffix in [
                "max_connections",
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
                let key = format!("tcp_server.{}.{}", name, suffix);
                if let Some(entry) = self.tcp_server_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn list_tcp_client_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.tcp_client_runtime.keys().collect();
        names.sort();
        for name in names {
            for suffix in [
                "connect_timeout_secs",
                "reconnect_wait_secs",
                "max_reconnect_tries",
            ] {
                let key = format!("tcp_client.{}.{}", name, suffix);
                if let Some(entry) = self.tcp_client_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn tcp_client_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("tcp_client.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.tcp_client_runtime.get(name)?;
        let current = recover_mutex_guard(&handle.runtime, "tcp client runtime").clone();
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
                "TCP client connect timeout in seconds; applies on the next reconnect.",
            )),
            "reconnect_wait_secs" => Some(make_entry(
                RuntimeConfigValue::Float(current.reconnect_wait.as_secs_f64()),
                RuntimeConfigValue::Float(startup.reconnect_wait.as_secs_f64()),
                "Delay between TCP client reconnect attempts in seconds.",
            )),
            "max_reconnect_tries" => Some(make_entry(
                RuntimeConfigValue::Int(current.max_reconnect_tries.unwrap_or(0) as i64),
                RuntimeConfigValue::Int(startup.max_reconnect_tries.unwrap_or(0) as i64),
                "Maximum TCP client reconnect attempts; 0 disables the cap.",
            )),
            _ => None,
        }
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn split_tcp_client_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("tcp_client.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn set_tcp_client_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_tcp_client_runtime_key(key)?;
        let handle = self
            .tcp_client_runtime
            .get(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp client interface '{}' not found", name),
            })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "tcp client runtime");
        match setting {
            "connect_timeout_secs" => {
                runtime.connect_timeout = Self::expect_duration_secs(value, key)?;
                Ok(())
            }
            "reconnect_wait_secs" => {
                runtime.reconnect_wait = Self::expect_duration_secs(value, key)?;
                Ok(())
            }
            "max_reconnect_tries" => {
                runtime.max_reconnect_tries = match Self::expect_u64(value, key)? {
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

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn reset_tcp_client_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_tcp_client_runtime_key(key)?;
        let handle = self
            .tcp_client_runtime
            .get(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp client interface '{}' not found", name),
            })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "tcp client runtime");
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

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn tcp_server_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("tcp_server.")?;
        let (name, setting) = rest.split_once('.')?;
        if Self::is_discovery_runtime_setting(setting) {
            let handle = self.tcp_server_discovery_runtime.get(name)?;
            return Self::discovery_runtime_entry(
                key,
                setting,
                "TCP server",
                handle.current.discoverable,
                handle.startup.discoverable,
                &handle.current.config,
                &handle.startup.config,
            );
        }

        let handle = self.tcp_server_runtime.get(name)?;
        let current = recover_mutex_guard(&handle.runtime, "tcp server runtime").clone();
        let startup = handle.startup.clone();
        match setting {
            "max_connections" => Some(RuntimeConfigEntry {
                key: key.to_string(),
                value: RuntimeConfigValue::Int(current.max_connections.unwrap_or(0) as i64),
                default: RuntimeConfigValue::Int(startup.max_connections.unwrap_or(0) as i64),
                source: if current.max_connections == startup.max_connections {
                    RuntimeConfigSource::Startup
                } else {
                    RuntimeConfigSource::RuntimeOverride
                },
                apply_mode: RuntimeConfigApplyMode::NewConnectionsOnly,
                description: Some(
                    "Maximum simultaneous inbound TCP server connections; 0 disables the cap."
                        .to_string(),
                ),
            }),
            _ => None,
        }
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn split_tcp_server_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("tcp_server.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn set_tcp_server_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_tcp_server_runtime_key(key)?;
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
            return self.set_tcp_server_discovery_runtime_config(key, value);
        }
        let handle = self
            .tcp_server_runtime
            .get(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp server interface '{}' not found", name),
            })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "tcp server runtime");
        match setting {
            "max_connections" => {
                runtime.max_connections = Self::set_optional_usize(value, key)?;
                Ok(())
            }
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::UnknownKey,
                message: format!("unknown runtime-config key '{}'", key),
            }),
        }
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn reset_tcp_server_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_tcp_server_runtime_key(key)?;
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
            return self.reset_tcp_server_discovery_runtime_config(key);
        }
        let handle = self
            .tcp_server_runtime
            .get(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp server interface '{}' not found", name),
            })?;
        let mut runtime = recover_mutex_guard(&handle.runtime, "tcp server runtime");
        let startup = handle.startup.clone();
        match setting {
            "max_connections" => runtime.max_connections = startup.max_connections,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        Ok(())
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn set_tcp_server_discovery_runtime_config(
        &mut self,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_tcp_server_runtime_key(key)?;
        let handle = self
            .tcp_server_discovery_runtime
            .get_mut(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp server interface '{}' not found", name),
            })?;
        match setting {
            "discoverable" => handle.current.discoverable = Self::expect_bool(value, key)?,
            "discovery_name" => {
                handle.current.config.discovery_name = Self::expect_string(value, key)?
            }
            "announce_interval_secs" => {
                let secs = Self::expect_u64(value, key)?;
                if secs < 300 {
                    return Err(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::InvalidValue,
                        message: format!("{} must be >= 300", key),
                    });
                }
                handle.current.config.announce_interval = secs;
            }
            "reachable_on" => {
                handle.current.config.reachable_on = Self::expect_optional_string(value, key)?
            }
            "location_cmd" => {
                handle.current.config.location_cmd = Self::expect_optional_string(value, key)?
            }
            "stamp_value" => {
                handle.current.config.stamp_value = Self::expect_discovery_stamp_value(value, key)?;
            }
            "latitude" => handle.current.config.latitude = Self::expect_optional_f64(value, key)?,
            "longitude" => handle.current.config.longitude = Self::expect_optional_f64(value, key)?,
            "height" => handle.current.config.height = Self::expect_optional_f64(value, key)?,
            _ => {
                return Err(RuntimeConfigError {
                    code: RuntimeConfigErrorCode::UnknownKey,
                    message: format!("unknown runtime-config key '{}'", key),
                })
            }
        }
        self.sync_tcp_server_discovery_runtime(name)
    }

    #[cfg(feature = "iface-tcp")]
    pub(crate) fn reset_tcp_server_discovery_runtime_config(
        &mut self,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_tcp_server_runtime_key(key)?;
        let handle = self
            .tcp_server_discovery_runtime
            .get_mut(name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp server interface '{}' not found", name),
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
                })
            }
        }
        self.sync_tcp_server_discovery_runtime(name)
    }
}
