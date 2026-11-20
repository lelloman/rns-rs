//! Building AutoInterfaces from their config.

use super::*;

/// Factory for `AutoInterface`.
pub struct AutoFactory;

impl InterfaceFactory for AutoFactory {
    fn type_name(&self) -> &str {
        "AutoInterface"
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        let group_id = params
            .get("group_id")
            .map(|v| v.as_bytes().to_vec())
            .unwrap_or_else(|| DEFAULT_GROUP_ID.to_vec());

        let discovery_scope = params
            .get("discovery_scope")
            .map(|v| match v.to_lowercase().as_str() {
                "link" => SCOPE_LINK.to_string(),
                "admin" => SCOPE_ADMIN.to_string(),
                "site" => SCOPE_SITE.to_string(),
                "organisation" | "organization" => SCOPE_ORGANISATION.to_string(),
                "global" => SCOPE_GLOBAL.to_string(),
                _ => v.clone(),
            })
            .unwrap_or_else(|| SCOPE_LINK.to_string());

        let discovery_port = params
            .get("discovery_port")
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_DISCOVERY_PORT);

        let data_port = params
            .get("data_port")
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_DATA_PORT);

        let multicast_address_type = params
            .get("multicast_address_type")
            .map(|v| match v.to_lowercase().as_str() {
                "permanent" => MULTICAST_PERMANENT_ADDRESS_TYPE.to_string(),
                "temporary" => MULTICAST_TEMPORARY_ADDRESS_TYPE.to_string(),
                _ => v.clone(),
            })
            .unwrap_or_else(|| MULTICAST_TEMPORARY_ADDRESS_TYPE.to_string());

        let configured_bitrate = params
            .get("configured_bitrate")
            .or_else(|| params.get("bitrate"))
            .and_then(|v| v.parse().ok())
            .unwrap_or(BITRATE_GUESS);

        let allowed_interfaces = params
            .get("devices")
            .or_else(|| params.get("allowed_interfaces"))
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let ignored_interfaces = params
            .get("ignored_devices")
            .or_else(|| params.get("ignored_interfaces"))
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let max_peers = params
            .get("max_peers")
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|max_peers| *max_peers > 0)
            .unwrap_or(DEFAULT_MAX_PEERS);

        Ok(Box::new(AutoConfig {
            name: name.to_string(),
            group_id,
            discovery_scope,
            discovery_port,
            data_port,
            multicast_address_type,
            allowed_interfaces,
            ignored_interfaces,
            configured_bitrate,
            max_peers,
            interface_id: id,
            runtime: Arc::new(Mutex::new(AutoRuntime::default())),
        }))
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> std::io::Result<StartResult> {
        let auto_config = *config.into_any().downcast::<AutoConfig>().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "wrong config type")
        })?;

        let parent_id = auto_config.interface_id;
        let control = start_with_template(
            auto_config,
            ctx.tx,
            ctx.next_dynamic_id,
            Some(crate::interface::DynamicInterfaceTemplate {
                parent_id,
                interface_type: "AutoInterfacePeer".into(),
                ifac: ctx.ifac,
                mode: ctx.mode,
                gravity: ctx.gravity,
                // Upstream does not pass `hop_limiter` to these peers.
                hop_limiter: None,
                recursive_prs: ctx.recursive_prs,
                announces_from_internal: ctx.announces_from_internal,
                announces_to_internal: ctx.announces_to_internal,
                stamp_costs: ctx.stamp_costs,
                announce_limits: ctx.announce_limits,
            }),
            ctx.underlay_mark,
        )?;
        Ok(StartResult::Listener {
            control: Some(control),
        })
    }
}
