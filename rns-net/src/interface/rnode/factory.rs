//! Building RNode interfaces from their config.

use super::*;
use crate::interface::InterfaceConfigError;

/// Factory for `RNodeInterface`.
pub struct RNodeFactory;

impl InterfaceFactory for RNodeFactory {
    fn type_name(&self) -> &str {
        "RNodeInterface"
    }

    fn default_ifac_size(&self) -> usize {
        8
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, InterfaceConfigError> {
        let pre_opened_fd = params.get("fd").and_then(|v| v.parse::<i32>().ok());

        let port = params
            .get("port")
            .cloned()
            .or_else(|| pre_opened_fd.map(|_| "usb-bridge".to_string()))
            .ok_or_else(|| InterfaceConfigError::missing("RNodeInterface", &["port", "fd"]))?;

        let speed = params
            .get("speed")
            .and_then(|v| v.parse().ok())
            .unwrap_or(115200u32);

        let frequency = params
            .get("frequency")
            .and_then(|v| v.parse().ok())
            .unwrap_or(868_000_000u32);

        let bandwidth = params
            .get("bandwidth")
            .and_then(|v| v.parse().ok())
            .unwrap_or(125_000u32);

        let txpower = params
            .get("txpower")
            .and_then(|v| v.parse().ok())
            .unwrap_or(7i8);

        let spreading_factor = params
            .get("spreadingfactor")
            .or_else(|| params.get("spreading_factor"))
            .and_then(|v| v.parse().ok())
            .unwrap_or(8u8);

        let coding_rate = params
            .get("codingrate")
            .or_else(|| params.get("coding_rate"))
            .and_then(|v| v.parse().ok())
            .unwrap_or(5u8);

        let flow_control = params
            .get("flow_control")
            .and_then(|v| crate::config::parse_bool_pub(v))
            .unwrap_or(false);

        // Upstream's keys, with the earlier Rust names still accepted.
        let st_alock = params
            .get("airtime_limit_short")
            .or_else(|| params.get("st_alock"))
            .and_then(|v| v.parse().ok());

        let lt_alock = params
            .get("airtime_limit_long")
            .or_else(|| params.get("lt_alock"))
            .and_then(|v| v.parse().ok());

        let id_interval = params.get("id_interval").and_then(|v| v.parse().ok());

        let id_callsign = params.get("id_callsign").map(|v| v.as_bytes().to_vec());
        // As upstream, a callsign longer than CALLSIGN_MAX_LEN makes the
        // configuration invalid.
        if id_interval.is_some() && id_callsign.as_ref().is_some_and(|c| c.len() > 32) {
            return Err(InterfaceConfigError::invalid_value(
                "id_callsign",
                format!(
                    "The encoded ID callsign for RNodeInterface[{name}] exceeds the max length of 32 bytes."
                ),
            ));
        }

        let sub = RNodeSubConfig {
            name: name.to_string(),
            vport: 0,
            outgoing: true,
            frequency,
            bandwidth,
            txpower,
            spreading_factor,
            coding_rate,
            flow_control,
            st_alock,
            lt_alock,
        };

        Ok(Box::new(RNodeConfig {
            name: name.to_string(),
            port,
            speed,
            subinterfaces: vec![sub],
            multi: false,
            id_interval,
            id_callsign,
            interface_id: id,
            base_interface_id: id,
            pre_opened_fd,
            underlay_mark: None,
            runtime: Arc::new(Mutex::new(RNodeRuntime {
                sub: RNodeSubConfig {
                    name: name.to_string(),
                    vport: 0,
                    outgoing: true,
                    frequency,
                    bandwidth,
                    txpower,
                    spreading_factor,
                    coding_rate,
                    flow_control,
                    st_alock,
                    lt_alock,
                },
                writer: None,
            })),
            ble: Default::default(),
            reported_phy: Default::default(),
        }))
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> std::io::Result<StartResult> {
        let mut rnode_config = *config.into_any().downcast::<RNodeConfig>().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "wrong config type")
        })?;
        rnode_config.underlay_mark = ctx.underlay_mark;

        let sub_bitrates: Vec<u64> = rnode_config
            .subinterfaces
            .iter()
            .map(estimate_lora_bitrate_bps)
            .collect();
        let airtime_profiles: Vec<AirtimeProfile> = rnode_config
            .subinterfaces
            .iter()
            .map(lora_airtime_profile)
            .collect();

        let (pairs, control) = start_with_control(rnode_config.clone(), ctx.tx)?;

        let mut subs = Vec::with_capacity(pairs.len());
        for (index, (sub_id, writer)) in pairs.into_iter().enumerate() {
            let sub_name = rnode_config.subinterfaces[index].name.clone();

            let info = InterfaceInfo {
                stamp_costs: Default::default(),
                id: sub_id,
                name: sub_name,
                mode: ctx.mode,
                gravity: ctx.gravity,
                recursive_prs: ctx.recursive_prs,
                announces_from_internal: ctx.announces_from_internal,
                announces_to_internal: ctx.announces_to_internal,
                out_capable: rnode_config.subinterfaces[index].outgoing,
                in_capable: true,
                bitrate: sub_bitrates.get(index).copied(),
                airtime_profile: airtime_profiles.get(index).copied(),
                announce_rate_target: None,
                announce_rate_grace: 0,
                announce_rate_penalty: 0.0,
                announce_cap: rns_core::constants::ANNOUNCE_CAP,
                is_local_client: false,
                wants_tunnel: false,
                shared_medium: true,
                hop_limiter: None,
                tunnel_id: None,
                // Upstream RNodeInterface.HW_MTU. Links never negotiate
                // above the default over a radio (not `mtu_upgradable`).
                mtu: HW_MTU,
                mtu_upgradable: false,
                ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
                ia_freq: 0.0,
                ia_samples: 0,
                ip_freq: 0.0,
                op_freq: 0.0,
                op_samples: 0,
                started: crate::time::now(),
            };

            subs.push(SubInterface {
                id: sub_id,
                info,
                writer,
                interface_type_name: if rnode_config.multi {
                    "RNodeMultiInterface"
                } else {
                    "RNodeInterface"
                }
                .to_string(),
            });
        }

        Ok(StartResult::Multi {
            subinterfaces: subs,
            control: Some(control),
        })
    }
}

/// Factory for ConfigObj-driven `RNodeMultiInterface` devices.
pub struct RNodeMultiFactory;

impl InterfaceFactory for RNodeMultiFactory {
    fn type_name(&self) -> &str {
        "RNodeMultiInterface"
    }

    fn default_ifac_size(&self) -> usize {
        8
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, InterfaceConfigError> {
        self.parse_config_section(
            name,
            id,
            ConfigSection {
                params,
                children: &[],
            },
        )
    }

    fn parse_config_section(
        &self,
        name: &str,
        id: InterfaceId,
        section: ConfigSection<'_>,
    ) -> Result<Box<dyn InterfaceConfigData>, InterfaceConfigError> {
        let base = RNodeFactory.parse_config(name, id, section.params)?;
        let mut config = *base
            .into_any()
            .downcast::<RNodeConfig>()
            .map_err(|_| InterfaceConfigError::Invalid("wrong RNode config type".into()))?;

        let mut subinterfaces = Vec::new();
        for child in section.children {
            let enabled = child
                .params
                .get("interface_enabled")
                .or_else(|| child.params.get("enabled"))
                .and_then(|value| crate::config::parse_bool_pub(value))
                .unwrap_or(true);
            if !enabled {
                continue;
            }
            if subinterfaces.len() >= 11 {
                return Err(InterfaceConfigError::Invalid(
                    "RNodeMultiInterface supports at most 11 enabled subinterfaces".into(),
                ));
            }
            let vport = child
                .params
                .get("vport")
                .ok_or_else(|| {
                    InterfaceConfigError::missing(
                        format!("subinterface '{}'", child.name),
                        &["vport"],
                    )
                })?
                .parse::<u8>()
                .map_err(|_| {
                    InterfaceConfigError::invalid_value(
                        "vport",
                        format!("invalid RNode virtual port for '{}'", child.name),
                    )
                })?;
            if vport > 10
                || subinterfaces
                    .iter()
                    .any(|sub: &RNodeSubConfig| sub.vport == vport)
            {
                return Err(InterfaceConfigError::invalid_value(
                    "vport",
                    format!("invalid or duplicate RNode virtual port {}", vport),
                ));
            }
            let parse_u32 = |key: &str, default| {
                child
                    .params
                    .get(key)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(default)
            };
            let parse_u8_alias = |first: &str, second: &str, default| {
                child
                    .params
                    .get(first)
                    .or_else(|| child.params.get(second))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(default)
            };
            let sub = RNodeSubConfig {
                name: child.name.clone(),
                vport,
                outgoing: child
                    .params
                    .get("outgoing")
                    .and_then(|v| crate::config::parse_bool_pub(v))
                    .unwrap_or(true),
                frequency: parse_u32("frequency", 868_000_000),
                bandwidth: parse_u32("bandwidth", 125_000),
                txpower: child
                    .params
                    .get("txpower")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(7),
                spreading_factor: parse_u8_alias("spreadingfactor", "spreading_factor", 8),
                coding_rate: parse_u8_alias("codingrate", "coding_rate", 5),
                flow_control: child
                    .params
                    .get("flow_control")
                    .and_then(|v| crate::config::parse_bool_pub(v))
                    .unwrap_or(false),
                st_alock: child
                    .params
                    .get("airtime_limit_short")
                    .or_else(|| child.params.get("st_alock"))
                    .and_then(|v| v.parse().ok()),
                lt_alock: child
                    .params
                    .get("airtime_limit_long")
                    .or_else(|| child.params.get("lt_alock"))
                    .and_then(|v| v.parse().ok()),
            };
            if let Some(error) = validate_sub_config(&sub) {
                return Err(InterfaceConfigError::Invalid(error));
            }
            subinterfaces.push(sub);
        }
        if subinterfaces.is_empty() {
            return Err(InterfaceConfigError::Invalid(
                "RNodeMultiInterface requires at least one enabled subinterface".into(),
            ));
        }
        config.multi = true;
        // Upstream adds the interface, then each subinterface once its
        // device is configured: they take the ids after its own.
        config.base_interface_id = InterfaceId(id.0 + 1);
        config.subinterfaces = subinterfaces;
        *lock_or_recover(&config.runtime, "rnode runtime") = RNodeRuntime::from_config(&config);
        Ok(Box::new(config))
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> io::Result<StartResult> {
        RNodeFactory.start(config, ctx)
    }
}
