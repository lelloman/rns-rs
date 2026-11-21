//! Runtime config keys: listing and reading them, and routing a key to
//! the family of settings it belongs to.

use super::*;

impl Driver {
    pub(crate) fn runtime_config_family_for_key(key: &str) -> Option<RuntimeConfigFamily> {
        #[cfg(feature = "iface-backbone")]
        if key.starts_with("backbone.") {
            return Some(RuntimeConfigFamily::Backbone);
        }
        #[cfg(feature = "iface-backbone")]
        if key.starts_with("backbone_client.") {
            return Some(RuntimeConfigFamily::BackboneClient);
        }
        #[cfg(feature = "iface-tcp")]
        if key.starts_with("tcp_server.") {
            return Some(RuntimeConfigFamily::TcpServer);
        }
        #[cfg(feature = "iface-tcp")]
        if key.starts_with("tcp_client.") {
            return Some(RuntimeConfigFamily::TcpClient);
        }
        #[cfg(feature = "iface-udp")]
        if key.starts_with("udp.") {
            return Some(RuntimeConfigFamily::Udp);
        }
        #[cfg(feature = "iface-auto")]
        if key.starts_with("auto.") {
            return Some(RuntimeConfigFamily::Auto);
        }
        #[cfg(feature = "iface-i2p")]
        if key.starts_with("i2p.") {
            return Some(RuntimeConfigFamily::I2p);
        }
        #[cfg(feature = "iface-pipe")]
        if key.starts_with("pipe.") {
            return Some(RuntimeConfigFamily::Pipe);
        }
        #[cfg(feature = "iface-rnode")]
        if key.starts_with("rnode.") {
            return Some(RuntimeConfigFamily::Rnode);
        }
        if key.starts_with("interface.") {
            return Some(RuntimeConfigFamily::Interface);
        }
        None
    }

    pub(crate) fn set_runtime_config_family_value(
        &mut self,
        family: RuntimeConfigFamily,
        key: &str,
        value: RuntimeConfigValue,
    ) -> Result<(), RuntimeConfigError> {
        let config = &mut self.runtime_config;
        match family {
            #[cfg(feature = "iface-backbone")]
            RuntimeConfigFamily::Backbone => {
                match config.set_backbone_runtime_config(key, value)? {
                    Some(name) => self.sync_backbone_discovery_runtime(name),
                    None => Ok(()),
                }
            }
            #[cfg(feature = "iface-backbone")]
            RuntimeConfigFamily::BackboneClient => {
                config.set_backbone_client_runtime_config(key, value)
            }
            #[cfg(feature = "iface-tcp")]
            RuntimeConfigFamily::TcpServer => {
                match config.set_tcp_server_runtime_config(key, value)? {
                    Some(name) => self.sync_tcp_server_discovery_runtime(name),
                    None => Ok(()),
                }
            }
            #[cfg(feature = "iface-tcp")]
            RuntimeConfigFamily::TcpClient => config.set_tcp_client_runtime_config(key, value),
            #[cfg(feature = "iface-udp")]
            RuntimeConfigFamily::Udp => config.set_udp_runtime_config(key, value),
            #[cfg(feature = "iface-auto")]
            RuntimeConfigFamily::Auto => config.set_auto_runtime_config(key, value),
            #[cfg(feature = "iface-i2p")]
            RuntimeConfigFamily::I2p => config.set_i2p_runtime_config(key, value),
            #[cfg(feature = "iface-pipe")]
            RuntimeConfigFamily::Pipe => config.set_pipe_runtime_config(key, value),
            #[cfg(feature = "iface-rnode")]
            RuntimeConfigFamily::Rnode => {
                config.set_rnode_runtime_config(&mut self.interfaces, &mut self.engine, key, value)
            }
            RuntimeConfigFamily::Interface => config.set_generic_interface_runtime_config(
                &mut self.interfaces,
                &mut self.engine,
                key,
                value,
            ),
        }
    }

    pub(crate) fn reset_runtime_config_family_value(
        &mut self,
        family: RuntimeConfigFamily,
        key: &str,
    ) -> Result<(), RuntimeConfigError> {
        let config = &mut self.runtime_config;
        match family {
            #[cfg(feature = "iface-backbone")]
            RuntimeConfigFamily::Backbone => match config.reset_backbone_runtime_config(key)? {
                Some(name) => self.sync_backbone_discovery_runtime(name),
                None => Ok(()),
            },
            #[cfg(feature = "iface-backbone")]
            RuntimeConfigFamily::BackboneClient => config.reset_backbone_client_runtime_config(key),
            #[cfg(feature = "iface-tcp")]
            RuntimeConfigFamily::TcpServer => match config.reset_tcp_server_runtime_config(key)? {
                Some(name) => self.sync_tcp_server_discovery_runtime(name),
                None => Ok(()),
            },
            #[cfg(feature = "iface-tcp")]
            RuntimeConfigFamily::TcpClient => config.reset_tcp_client_runtime_config(key),
            #[cfg(feature = "iface-udp")]
            RuntimeConfigFamily::Udp => config.reset_udp_runtime_config(key),
            #[cfg(feature = "iface-auto")]
            RuntimeConfigFamily::Auto => config.reset_auto_runtime_config(key),
            #[cfg(feature = "iface-i2p")]
            RuntimeConfigFamily::I2p => config.reset_i2p_runtime_config(key),
            #[cfg(feature = "iface-pipe")]
            RuntimeConfigFamily::Pipe => config.reset_pipe_runtime_config(key),
            #[cfg(feature = "iface-rnode")]
            RuntimeConfigFamily::Rnode => {
                config.reset_rnode_runtime_config(&mut self.interfaces, &mut self.engine, key)
            }
            RuntimeConfigFamily::Interface => config.reset_generic_interface_runtime_config(
                &mut self.interfaces,
                &mut self.engine,
                key,
            ),
        }
    }

    pub(crate) fn runtime_config_entry(&self, key: &str) -> Option<RuntimeConfigEntry> {
        let defaults = self.runtime_config.defaults;
        let make_entry = |key: &str,
                          value: RuntimeConfigValue,
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

        match key {
            "global.tick_interval_ms" => Some(make_entry(
                key,
                RuntimeConfigValue::Int(self.tick_interval_ms.load(Ordering::Relaxed) as i64),
                RuntimeConfigValue::Int(defaults.tick_interval_ms as i64),
                RuntimeConfigApplyMode::Immediate,
                "Driver tick interval in milliseconds.",
            )),
            "global.known_destinations_ttl_secs" => Some(make_entry(
                key,
                RuntimeConfigValue::Float(self.known.ttl),
                RuntimeConfigValue::Float(defaults.known_destinations_ttl),
                RuntimeConfigApplyMode::Immediate,
                "TTL for known destinations without an active path.",
            )),
            "global.rate_limiter_ttl_secs" => Some(make_entry(
                key,
                RuntimeConfigValue::Float(self.rate_limiter_ttl_secs),
                RuntimeConfigValue::Float(defaults.rate_limiter_ttl_secs),
                RuntimeConfigApplyMode::Immediate,
                "TTL for announce rate-limiter entries without an active path.",
            )),
            "global.known_destinations_cleanup_interval_ticks" => Some(make_entry(
                key,
                RuntimeConfigValue::Int(self.known.cleanup_interval_ticks as i64),
                RuntimeConfigValue::Int(defaults.known_destinations_cleanup_interval_ticks as i64),
                RuntimeConfigApplyMode::Immediate,
                "Tick interval between known-destinations cleanup passes.",
            )),
            "global.announce_cache_cleanup_interval_ticks" => Some(make_entry(
                key,
                RuntimeConfigValue::Int(self.housekeeping.announce_cache_cleanup_interval_ticks as i64),
                RuntimeConfigValue::Int(defaults.announce_cache_cleanup_interval_ticks as i64),
                RuntimeConfigApplyMode::Immediate,
                "Tick interval between announce-cache cleanup cycles.",
            )),
            "global.announce_cache_cleanup_batch_size" => Some(make_entry(
                key,
                RuntimeConfigValue::Int(self.housekeeping.announce_cache_cleanup_batch_size as i64),
                RuntimeConfigValue::Int(defaults.announce_cache_cleanup_batch_size as i64),
                RuntimeConfigApplyMode::Immediate,
                "Number of announce-cache entries processed per cleanup tick.",
            )),
            "global.discovery_cleanup_interval_ticks" => Some(make_entry(
                key,
                RuntimeConfigValue::Int(self.discovery.cleanup_interval_ticks as i64),
                RuntimeConfigValue::Int(defaults.discovery_cleanup_interval_ticks as i64),
                RuntimeConfigApplyMode::Immediate,
                "Tick interval between discovered-interface cleanup passes.",
            )),
            "global.management_announce_interval_secs" => Some(make_entry(
                key,
                RuntimeConfigValue::Float(self.management.announce_interval_secs),
                RuntimeConfigValue::Float(defaults.management_announce_interval_secs),
                RuntimeConfigApplyMode::Immediate,
                "Interval between management announces in seconds.",
            )),
            "global.stamp_destinations" => Some(make_entry(
                key,
                RuntimeConfigValue::Bool(self.stamps.stamp_destinations.load(Ordering::Relaxed)),
                RuntimeConfigValue::Bool(defaults.stamp_destinations),
                RuntimeConfigApplyMode::Immediate,
                "Stamp announces emitted by this node (Transport.STAMP_DESTINATIONS); stamps are ground on the stamper worker.",
            )),
            "global.stamp_path_requests" => Some(make_entry(
                key,
                RuntimeConfigValue::Bool(self.engine.stamp_prs()),
                RuntimeConfigValue::Bool(defaults.stamp_path_requests),
                RuntimeConfigApplyMode::Immediate,
                "Stamp path requests emitted or forwarded for local clients by this node (Transport.STAMP_PRS).",
            )),
            "global.stamps_enforced" => Some(make_entry(
                key,
                RuntimeConfigValue::Bool(self.engine.stamp_requirements().enforced),
                RuntimeConfigValue::Bool(defaults.stamps_enforced),
                RuntimeConfigApplyMode::Immediate,
                "Drop received announces and path requests whose stamp is below the required cost (Transport.STAMPS_ENFORCED).",
            )),
            "global.lr_stamps_enforced" => Some(make_entry(
                key,
                RuntimeConfigValue::Bool(self.link_manager.link_request_costs().enforced()),
                RuntimeConfigValue::Bool(defaults.lr_stamps_enforced),
                RuntimeConfigApplyMode::Immediate,
                "Drop incoming link requests whose stamp is below the destination's link cost (Transport.LR_STAMPS_ENFORCED).",
            )),
            "global.stamp_link_requests" => Some(make_entry(
                key,
                RuntimeConfigValue::Bool(self.stamps.settings.stamp_lrs),
                RuntimeConfigValue::Bool(defaults.stamp_link_requests),
                RuntimeConfigApplyMode::Immediate,
                "Stamp link requests to destinations that announce a link request cost (Transport.STAMP_LRS); keys are ground off the driver thread.",
            )),
            "global.always_stamp_link_requests" => Some(make_entry(
                key,
                RuntimeConfigValue::Bool(self.stamps.settings.always_stamp_lrs),
                RuntimeConfigValue::Bool(defaults.always_stamp_link_requests),
                RuntimeConfigApplyMode::Immediate,
                "Also stamp link requests to destinations that announce no link request cost, at the local lr_cost (Transport.ALWAYS_STAMP_LRS).",
            )),
            "global.direct_connect_policy" => Some(make_entry(
                key,
                RuntimeConfigValue::String(Self::holepunch_policy_name(
                    self.holepunch_manager.policy(),
                )),
                RuntimeConfigValue::String(Self::holepunch_policy_name(
                    defaults.direct_connect_policy,
                )),
                RuntimeConfigApplyMode::Immediate,
                "Policy for incoming direct-connect proposals.",
            )),
            "provider.queue_max_events" if HookHost::PROVIDER_BRIDGE => {
                let value = self
                    .hooks
                    .provider_queue_max_events()
                    .unwrap_or(defaults.provider_queue_max_events);
                Some(make_entry(
                    key,
                    RuntimeConfigValue::Int(value as i64),
                    RuntimeConfigValue::Int(defaults.provider_queue_max_events as i64),
                    RuntimeConfigApplyMode::Immediate,
                    "Max queued events in the provider bridge.",
                ))
            }
            "provider.queue_max_bytes" if HookHost::PROVIDER_BRIDGE => {
                let value = self
                    .hooks
                    .provider_queue_max_bytes()
                    .unwrap_or(defaults.provider_queue_max_bytes);
                Some(make_entry(
                    key,
                    RuntimeConfigValue::Int(value as i64),
                    RuntimeConfigValue::Int(defaults.provider_queue_max_bytes as i64),
                    RuntimeConfigApplyMode::Immediate,
                    "Max queued bytes in the provider bridge.",
                ))
            }
            _ => Self::runtime_config_family_for_key(key)
                .and_then(|family| self.runtime_config
                    .runtime_config_family_entry(&self.interfaces, family, key)),
        }
    }

    pub(crate) fn list_runtime_config(&self) -> Vec<RuntimeConfigEntry> {
        let mut entries: Vec<RuntimeConfigEntry> = [
            "global.tick_interval_ms",
            "global.known_destinations_ttl_secs",
            "global.rate_limiter_ttl_secs",
            "global.known_destinations_cleanup_interval_ticks",
            "global.announce_cache_cleanup_interval_ticks",
            "global.announce_cache_cleanup_batch_size",
            "global.discovery_cleanup_interval_ticks",
            "global.management_announce_interval_secs",
            "global.stamp_destinations",
            "global.stamp_path_requests",
            "global.stamps_enforced",
            "global.lr_stamps_enforced",
            "global.stamp_link_requests",
            "global.always_stamp_link_requests",
            "global.direct_connect_policy",
        ]
        .into_iter()
        .filter_map(|key| self.runtime_config_entry(key))
        .collect();

        if HookHost::PROVIDER_BRIDGE {
            entries.extend(
                ["provider.queue_max_events", "provider.queue_max_bytes"]
                    .into_iter()
                    .filter_map(|key| self.runtime_config_entry(key)),
            );
        }
        #[cfg(feature = "iface-backbone")]
        entries.extend(
            self.runtime_config
                .runtime_config_family_entries(&self.interfaces, RuntimeConfigFamily::Backbone),
        );
        #[cfg(feature = "iface-backbone")]
        entries.extend(
            self.runtime_config.runtime_config_family_entries(
                &self.interfaces,
                RuntimeConfigFamily::BackboneClient,
            ),
        );
        #[cfg(feature = "iface-tcp")]
        entries.extend(
            self.runtime_config
                .runtime_config_family_entries(&self.interfaces, RuntimeConfigFamily::TcpServer),
        );
        #[cfg(feature = "iface-tcp")]
        entries.extend(
            self.runtime_config
                .runtime_config_family_entries(&self.interfaces, RuntimeConfigFamily::TcpClient),
        );
        #[cfg(feature = "iface-udp")]
        entries.extend(
            self.runtime_config
                .runtime_config_family_entries(&self.interfaces, RuntimeConfigFamily::Udp),
        );
        #[cfg(feature = "iface-auto")]
        entries.extend(
            self.runtime_config
                .runtime_config_family_entries(&self.interfaces, RuntimeConfigFamily::Auto),
        );
        #[cfg(feature = "iface-i2p")]
        entries.extend(
            self.runtime_config
                .runtime_config_family_entries(&self.interfaces, RuntimeConfigFamily::I2p),
        );
        #[cfg(feature = "iface-pipe")]
        entries.extend(
            self.runtime_config
                .runtime_config_family_entries(&self.interfaces, RuntimeConfigFamily::Pipe),
        );
        #[cfg(feature = "iface-rnode")]
        entries.extend(
            self.runtime_config
                .runtime_config_family_entries(&self.interfaces, RuntimeConfigFamily::Rnode),
        );
        entries.extend(
            self.runtime_config
                .runtime_config_family_entries(&self.interfaces, RuntimeConfigFamily::Interface),
        );

        entries
    }

    pub(crate) fn holepunch_policy_name(policy: crate::event::HolePunchPolicy) -> String {
        match policy {
            crate::event::HolePunchPolicy::Reject => "reject".to_string(),
            crate::event::HolePunchPolicy::AcceptAll => "accept_all".to_string(),
            crate::event::HolePunchPolicy::IdentifiedOnly => "identified_only".to_string(),
            crate::event::HolePunchPolicy::AskApp => "ask_app".to_string(),
        }
    }

    pub(crate) fn parse_holepunch_policy(
        value: &RuntimeConfigValue,
    ) -> Option<crate::event::HolePunchPolicy> {
        match value {
            RuntimeConfigValue::String(s) => match s.to_ascii_lowercase().as_str() {
                "reject" => Some(crate::event::HolePunchPolicy::Reject),
                "accept_all" | "acceptall" => Some(crate::event::HolePunchPolicy::AcceptAll),
                "identified_only" | "identifiedonly" => {
                    Some(crate::event::HolePunchPolicy::IdentifiedOnly)
                }
                "ask_app" | "askapp" => Some(crate::event::HolePunchPolicy::AskApp),
                _ => None,
            },
            _ => None,
        }
    }
}

impl RuntimeConfigHandles {
    #[cfg(any(feature = "iface-tcp", feature = "iface-backbone"))]
    pub(super) fn is_discovery_runtime_setting(setting: &str) -> bool {
        matches!(
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
        )
    }

    #[cfg(any(feature = "iface-tcp", feature = "iface-backbone"))]
    pub(super) fn discovery_runtime_entry(
        key: &str,
        setting: &str,
        interface_label: &str,
        current_discoverable: bool,
        startup_discoverable: bool,
        current_config: &crate::discovery::DiscoveryConfig,
        startup_config: &crate::discovery::DiscoveryConfig,
    ) -> Option<RuntimeConfigEntry> {
        let make_entry = |value: RuntimeConfigValue,
                          default: RuntimeConfigValue,
                          description: String|
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
                description: Some(description),
            }
        };

        match setting {
            "discoverable" => Some(make_entry(
                RuntimeConfigValue::Bool(current_discoverable),
                RuntimeConfigValue::Bool(startup_discoverable),
                format!(
                    "Whether this {} interface is advertised through interface discovery.",
                    interface_label
                ),
            )),
            "discovery_name" => Some(make_entry(
                RuntimeConfigValue::String(current_config.discovery_name.clone()),
                RuntimeConfigValue::String(startup_config.discovery_name.clone()),
                format!(
                    "Human-readable discovery name advertised for this {} interface.",
                    interface_label
                ),
            )),
            "announce_interval_secs" => Some(make_entry(
                RuntimeConfigValue::Int(current_config.announce_interval as i64),
                RuntimeConfigValue::Int(startup_config.announce_interval as i64),
                format!(
                    "Discovery announce interval for this {} interface in seconds.",
                    interface_label
                ),
            )),
            "reachable_on" => Some(make_entry(
                current_config
                    .reachable_on
                    .clone()
                    .map(RuntimeConfigValue::String)
                    .unwrap_or(RuntimeConfigValue::Null),
                startup_config
                    .reachable_on
                    .clone()
                    .map(RuntimeConfigValue::String)
                    .unwrap_or(RuntimeConfigValue::Null),
                format!(
                    "Reachable hostname or IP advertised for this {} interface; null clears it.",
                    interface_label
                ),
            )),
            "location_cmd" => Some(make_entry(
                current_config
                    .location_cmd
                    .clone()
                    .map(RuntimeConfigValue::String)
                    .unwrap_or(RuntimeConfigValue::Null),
                startup_config
                    .location_cmd
                    .clone()
                    .map(RuntimeConfigValue::String)
                    .unwrap_or(RuntimeConfigValue::Null),
                format!(
                    "Executable resolving discovery coordinates for this {} interface; null clears it.",
                    interface_label
                ),
            )),
            "stamp_value" => Some(make_entry(
                RuntimeConfigValue::Float(current_config.stamp_value.as_f64()),
                RuntimeConfigValue::Float(startup_config.stamp_value.as_f64()),
                format!(
                    "Discovery proof-of-work stamp cost for this {} interface.",
                    interface_label
                ),
            )),
            "latitude" => Some(make_entry(
                current_config
                    .latitude
                    .map(RuntimeConfigValue::Float)
                    .unwrap_or(RuntimeConfigValue::Null),
                startup_config
                    .latitude
                    .map(RuntimeConfigValue::Float)
                    .unwrap_or(RuntimeConfigValue::Null),
                format!(
                    "Latitude advertised for this {} interface; null clears it.",
                    interface_label
                ),
            )),
            "longitude" => Some(make_entry(
                current_config
                    .longitude
                    .map(RuntimeConfigValue::Float)
                    .unwrap_or(RuntimeConfigValue::Null),
                startup_config
                    .longitude
                    .map(RuntimeConfigValue::Float)
                    .unwrap_or(RuntimeConfigValue::Null),
                format!(
                    "Longitude advertised for this {} interface; null clears it.",
                    interface_label
                ),
            )),
            "height" => Some(make_entry(
                current_config
                    .height
                    .map(RuntimeConfigValue::Float)
                    .unwrap_or(RuntimeConfigValue::Null),
                startup_config
                    .height
                    .map(RuntimeConfigValue::Float)
                    .unwrap_or(RuntimeConfigValue::Null),
                format!(
                    "Height advertised for this {} interface; null clears it.",
                    interface_label
                ),
            )),
            _ => None,
        }
    }

    pub(crate) fn runtime_config_family_entry(
        &self,
        interfaces: &Interfaces,
        family: RuntimeConfigFamily,
        key: &str,
    ) -> Option<RuntimeConfigEntry> {
        match family {
            #[cfg(feature = "iface-backbone")]
            RuntimeConfigFamily::Backbone => self.backbone_runtime_entry(key),
            #[cfg(feature = "iface-backbone")]
            RuntimeConfigFamily::BackboneClient => self.backbone_client_runtime_entry(key),
            #[cfg(feature = "iface-tcp")]
            RuntimeConfigFamily::TcpServer => self.tcp_server_runtime_entry(key),
            #[cfg(feature = "iface-tcp")]
            RuntimeConfigFamily::TcpClient => self.tcp_client_runtime_entry(key),
            #[cfg(feature = "iface-udp")]
            RuntimeConfigFamily::Udp => self.udp_runtime_entry(key),
            #[cfg(feature = "iface-auto")]
            RuntimeConfigFamily::Auto => self.auto_runtime_entry(key),
            #[cfg(feature = "iface-i2p")]
            RuntimeConfigFamily::I2p => self.i2p_runtime_entry(key),
            #[cfg(feature = "iface-pipe")]
            RuntimeConfigFamily::Pipe => self.pipe_runtime_entry(key),
            #[cfg(feature = "iface-rnode")]
            RuntimeConfigFamily::Rnode => self.rnode_runtime_entry(key),
            RuntimeConfigFamily::Interface => self.generic_interface_runtime_entry(interfaces, key),
        }
    }

    pub(crate) fn runtime_config_family_entries(
        &self,
        interfaces: &Interfaces,
        family: RuntimeConfigFamily,
    ) -> Vec<RuntimeConfigEntry> {
        match family {
            #[cfg(feature = "iface-backbone")]
            RuntimeConfigFamily::Backbone => self.list_backbone_runtime_config(),
            #[cfg(feature = "iface-backbone")]
            RuntimeConfigFamily::BackboneClient => self.list_backbone_client_runtime_config(),
            #[cfg(feature = "iface-tcp")]
            RuntimeConfigFamily::TcpServer => self.list_tcp_server_runtime_config(),
            #[cfg(feature = "iface-tcp")]
            RuntimeConfigFamily::TcpClient => self.list_tcp_client_runtime_config(),
            #[cfg(feature = "iface-udp")]
            RuntimeConfigFamily::Udp => self.list_udp_runtime_config(),
            #[cfg(feature = "iface-auto")]
            RuntimeConfigFamily::Auto => self.list_auto_runtime_config(),
            #[cfg(feature = "iface-i2p")]
            RuntimeConfigFamily::I2p => self.list_i2p_runtime_config(),
            #[cfg(feature = "iface-pipe")]
            RuntimeConfigFamily::Pipe => self.list_pipe_runtime_config(),
            #[cfg(feature = "iface-rnode")]
            RuntimeConfigFamily::Rnode => self.list_rnode_runtime_config(),
            RuntimeConfigFamily::Interface => {
                self.list_generic_interface_runtime_config(interfaces)
            }
        }
    }
}
