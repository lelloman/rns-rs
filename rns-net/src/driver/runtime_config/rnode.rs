//! Runtime settings of RNode interfaces.

use super::*;

impl RuntimeConfigHandles {
    #[cfg(feature = "iface-rnode")]
    pub(crate) fn list_rnode_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries = Vec::new();
        let mut names: Vec<&String> = self.rnode.keys().collect();
        names.sort();
        for name in names {
            for suffix in [
                "frequency_hz",
                "bandwidth_hz",
                "txpower_dbm",
                "spreading_factor",
                "coding_rate",
                "st_alock_pct",
                "lt_alock_pct",
            ] {
                let key = format!("rnode.{}.{}", name, suffix);
                if let Some(entry) = self.rnode_runtime_entry(&key) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    #[cfg(feature = "iface-rnode")]
    pub(crate) fn rnode_runtime_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let rest = key.strip_prefix("rnode.")?;
        let (name, setting) = rest.split_once('.')?;
        let handle = self.rnode.get(name)?;
        let current = recover_mutex_guard(&handle.runtime, "rnode runtime").clone();
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
            "frequency_hz" => Some(make_entry(
                RuntimeConfigValue::Int(current.sub.frequency as i64),
                RuntimeConfigValue::Int(startup.sub.frequency as i64),
                "RNode radio frequency in Hz.",
            )),
            "bandwidth_hz" => Some(make_entry(
                RuntimeConfigValue::Int(current.sub.bandwidth as i64),
                RuntimeConfigValue::Int(startup.sub.bandwidth as i64),
                "RNode radio bandwidth in Hz.",
            )),
            "txpower_dbm" => Some(make_entry(
                RuntimeConfigValue::Int(current.sub.txpower as i64),
                RuntimeConfigValue::Int(startup.sub.txpower as i64),
                "RNode transmit power in dBm.",
            )),
            "spreading_factor" => Some(make_entry(
                RuntimeConfigValue::Int(current.sub.spreading_factor as i64),
                RuntimeConfigValue::Int(startup.sub.spreading_factor as i64),
                "RNode LoRa spreading factor.",
            )),
            "coding_rate" => Some(make_entry(
                RuntimeConfigValue::Int(current.sub.coding_rate as i64),
                RuntimeConfigValue::Int(startup.sub.coding_rate as i64),
                "RNode LoRa coding rate.",
            )),
            "st_alock_pct" => Some(make_entry(
                current
                    .sub
                    .st_alock
                    .map(|value| RuntimeConfigValue::Float(value as f64))
                    .unwrap_or(RuntimeConfigValue::Null),
                startup
                    .sub
                    .st_alock
                    .map(|value| RuntimeConfigValue::Float(value as f64))
                    .unwrap_or(RuntimeConfigValue::Null),
                "RNode short-term airtime lock percent; null clears it.",
            )),
            "lt_alock_pct" => Some(make_entry(
                current
                    .sub
                    .lt_alock
                    .map(|value| RuntimeConfigValue::Float(value as f64))
                    .unwrap_or(RuntimeConfigValue::Null),
                startup
                    .sub
                    .lt_alock
                    .map(|value| RuntimeConfigValue::Float(value as f64))
                    .unwrap_or(RuntimeConfigValue::Null),
                "RNode long-term airtime lock percent; null clears it.",
            )),
            _ => None,
        }
    }

    #[cfg(feature = "iface-rnode")]
    pub(crate) fn split_rnode_runtime_key<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str), RuntimeConfigError> {
        let rest = key.strip_prefix("rnode.").ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })?;
        rest.split_once('.').ok_or(RuntimeConfigError {
            code: RuntimeConfigErrorCode::UnknownKey,
            message: format!("unknown runtime-config key '{}'", key),
        })
    }

    #[cfg(feature = "iface-rnode")]
    pub(crate) fn apply_rnode_runtime(
        runtime: &mut RNodeRuntime,
    ) -> Result<(), RuntimeConfigError> {
        if let Some(err) = validate_sub_config(&runtime.sub) {
            return Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidValue,
                message: err,
            });
        }
        if let Some(writer) = runtime.writer.clone() {
            crate::interface::rnode::configure_subinterface(&writer, 0, &runtime.sub, false)
                .map_err(|e| RuntimeConfigError {
                    code: RuntimeConfigErrorCode::ApplyFailed,
                    message: format!("failed to apply RNode config: {}", e),
                })?;
        }
        Ok(())
    }

    #[cfg(feature = "iface-rnode")]
    pub(crate) fn set_rnode_runtime_config(
        &mut self,
        interfaces: &mut Interfaces,
        engine: &mut TransportEngine,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_rnode_runtime_key(key)?;
        let updated_sub = {
            let handle = self.rnode.get(name).ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("rnode interface '{}' not found", name),
            })?;
            let mut runtime = recover_mutex_guard(&handle.runtime, "rnode runtime");
            let old = runtime.sub.clone();
            match setting {
                "frequency_hz" => runtime.sub.frequency = expect_u64(value, key)? as u32,
                "bandwidth_hz" => runtime.sub.bandwidth = expect_u64(value, key)? as u32,
                "txpower_dbm" => runtime.sub.txpower = expect_i64(value, key)? as i8,
                "spreading_factor" => runtime.sub.spreading_factor = expect_u64(value, key)? as u8,
                "coding_rate" => runtime.sub.coding_rate = expect_u64(value, key)? as u8,
                "st_alock_pct" => {
                    runtime.sub.st_alock = match value {
                        RuntimeConfigValue::Null => None,
                        other => Some(expect_f64(other, key)? as f32),
                    };
                }
                "lt_alock_pct" => {
                    runtime.sub.lt_alock = match value {
                        RuntimeConfigValue::Null => None,
                        other => Some(expect_f64(other, key)? as f32),
                    };
                }
                _ => {
                    return Err(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::UnknownKey,
                        message: format!("unknown runtime-config key '{}'", key),
                    });
                }
            }
            if let Err(err) = Self::apply_rnode_runtime(&mut runtime) {
                runtime.sub = old;
                return Err(err);
            }
            runtime.sub.clone()
        };
        Self::refresh_rnode_interface_bitrate(interfaces, engine, name, &updated_sub);
        Ok(())
    }

    #[cfg(feature = "iface-rnode")]
    pub(crate) fn reset_rnode_runtime_config(
        &mut self,
        interfaces: &mut Interfaces,
        engine: &mut TransportEngine,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let (name, setting) = self.split_rnode_runtime_key(key)?;
        let updated_sub = {
            let handle = self.rnode.get(name).ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("rnode interface '{}' not found", name),
            })?;
            let mut runtime = recover_mutex_guard(&handle.runtime, "rnode runtime");
            let old = runtime.sub.clone();
            let startup = handle.startup.clone();
            match setting {
                "frequency_hz" => runtime.sub.frequency = startup.sub.frequency,
                "bandwidth_hz" => runtime.sub.bandwidth = startup.sub.bandwidth,
                "txpower_dbm" => runtime.sub.txpower = startup.sub.txpower,
                "spreading_factor" => runtime.sub.spreading_factor = startup.sub.spreading_factor,
                "coding_rate" => runtime.sub.coding_rate = startup.sub.coding_rate,
                "st_alock_pct" => runtime.sub.st_alock = startup.sub.st_alock,
                "lt_alock_pct" => runtime.sub.lt_alock = startup.sub.lt_alock,
                _ => {
                    return Err(RuntimeConfigError {
                        code: RuntimeConfigErrorCode::UnknownKey,
                        message: format!("unknown runtime-config key '{}'", key),
                    });
                }
            }
            if let Err(err) = Self::apply_rnode_runtime(&mut runtime) {
                runtime.sub = old;
                return Err(err);
            }
            runtime.sub.clone()
        };
        Self::refresh_rnode_interface_bitrate(interfaces, engine, name, &updated_sub);
        Ok(())
    }

    #[cfg(feature = "iface-rnode")]
    fn refresh_rnode_interface_bitrate(
        interfaces: &mut Interfaces,
        engine: &mut TransportEngine,
        name: &str,
        sub: &RNodeSubConfig,
    ) {
        let bitrate = Some(crate::interface::rnode::estimate_lora_bitrate_bps(sub));
        let airtime_profile = Some(crate::interface::rnode::lora_airtime_profile(sub));
        let mut refreshed = Vec::new();
        for entry in interfaces.values_mut() {
            if entry.info.name == name {
                entry.info.bitrate = bitrate;
                entry.info.airtime_profile = airtime_profile;
                refreshed.push(entry.info.clone());
            }
        }
        for info in refreshed {
            engine.register_interface(info);
        }
    }
}
