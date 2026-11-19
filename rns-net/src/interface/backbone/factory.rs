//! Building backbone interfaces from their config.

use super::*;

/// Internal enum used by [`BackboneInterfaceFactory`] to carry either a
/// server or client config through the opaque `InterfaceConfigData` channel.
#[derive(Clone)]
pub(crate) enum BackboneMode {
    Server(BackboneConfig),
    Client(BackboneClientConfig, u8),
}

/// Factory for `BackboneInterface`.
///
/// If the config params contain `"remote"` or `"target_host"` the interface
/// is started in client mode; otherwise it is started as a TCP listener
/// (server mode).
pub struct BackboneInterfaceFactory;

/// Compatibility name used by Reticulum 1.3.8 for a forced client-mode
/// Backbone interface.
pub struct BackboneClientInterfaceFactory;

impl InterfaceFactory for BackboneClientInterfaceFactory {
    fn type_name(&self) -> &str {
        "BackboneClientInterface"
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        if !params.contains_key("remote") && !params.contains_key("target_host") {
            return Err("BackboneClientInterface requires 'remote' or 'target_host'".into());
        }
        BackboneInterfaceFactory.parse_config(name, id, params)
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> io::Result<StartResult> {
        BackboneInterfaceFactory.start(config, ctx)
    }
}

pub(super) fn parse_positive_duration_secs(
    params: &HashMap<String, String>,
    key: &str,
) -> Option<Duration> {
    params
        .get(key)
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .and_then(|v| Duration::try_from_secs_f64(v).ok())
        .filter(|duration| Instant::now().checked_add(*duration).is_some())
}

pub(super) fn parse_nonnegative_duration(
    params: &HashMap<String, String>,
    key: &str,
    multiplier: f64,
    default: Duration,
) -> Result<Duration, String> {
    let Some(raw) = params.get(key) else {
        return Ok(default);
    };
    let value = raw
        .parse::<f64>()
        .map_err(|_| format!("invalid {key} '{raw}' (expected a non-negative number)"))?;
    let seconds = value * multiplier;
    if !value.is_finite() || value < 0.0 || !seconds.is_finite() || seconds > u64::MAX as f64 {
        return Err(format!(
            "invalid {key} '{raw}' (expected a finite non-negative number)"
        ));
    }
    let duration = Duration::from_secs_f64(seconds);
    if Instant::now().checked_add(duration).is_none() {
        return Err(format!("invalid {key} '{raw}' (duration is too large)"));
    }
    Ok(duration)
}

/// The listener's limit on concurrent clients: upstream's `client_limit`
/// (an integer; 0 or absent means `BACKBONE_CLIENT_LIMIT`), unless the
/// rns-rs `max_connections` key is set, which takes precedence and keeps its
/// meaning: a positive limit, or 0 for none. `None` means unlimited.
pub(super) fn parse_client_limit(
    params: &HashMap<String, String>,
) -> Result<Option<usize>, String> {
    let client_limit = match params.get("client_limit") {
        Some(raw) => raw.trim().parse::<usize>().map_err(|_| {
            format!("invalid client_limit '{raw}' (expected a non-negative integer)")
        })?,
        None => 0,
    };
    let client_limit = if client_limit == 0 {
        BACKBONE_CLIENT_LIMIT
    } else {
        client_limit
    };
    match params
        .get("max_connections")
        .and_then(|v| v.trim().parse::<usize>().ok())
    {
        Some(0) => Ok(None),
        Some(max) => Ok(Some(max)),
        None => Ok(Some(client_limit)),
    }
}

pub(super) fn parse_fast_flap_config(
    params: &HashMap<String, String>,
) -> Result<BackboneFastFlapConfig, String> {
    let defaults = BackboneFastFlapConfig::default();
    let enabled = match params.get("block_fast_flapping") {
        Some(raw) => crate::config::parse_bool_pub(raw)
            .ok_or_else(|| format!("invalid block_fast_flapping '{raw}' (expected yes or no)"))?,
        None => defaults.enabled,
    };
    let connection_threshold = parse_nonnegative_duration(
        params,
        "fast_flapping_threshold",
        1.0,
        defaults.connection_threshold,
    )?;
    let grace = match params.get("fast_flapping_grace") {
        Some(raw) => raw.parse::<u64>().map_err(|_| {
            format!("invalid fast_flapping_grace '{raw}' (expected a non-negative integer)")
        })?,
        None => defaults.grace,
    };
    let block_duration = parse_nonnegative_duration(
        params,
        "fast_flapping_block_time",
        60.0,
        defaults.block_duration,
    )?;

    Ok(BackboneFastFlapConfig {
        enabled,
        connection_threshold,
        grace,
        block_duration,
    })
}

impl InterfaceFactory for BackboneInterfaceFactory {
    fn type_name(&self) -> &str {
        "BackboneInterface"
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        if let Some(target_host) = params.get("remote").or_else(|| params.get("target_host")) {
            // Client mode
            let target_host = target_host.clone();
            let target_port = params
                .get("target_port")
                .or_else(|| params.get("port"))
                .and_then(|v| v.parse().ok())
                .unwrap_or(4242);
            let transport_identity = params.get("transport_identity").cloned();
            // Like Python, retry forever unless max_reconnect_tries is set.
            let max_reconnect_tries = match params.get("max_reconnect_tries") {
                Some(value) => Some(value.trim().parse::<u32>().map_err(|_| {
                    format!(
                        "invalid Backbone max_reconnect_tries '{}' (expected a non-negative integer)",
                        value
                    )
                })?),
                None => None,
            };
            let priority = match params.get("priority") {
                Some(value) => value.parse::<u8>().map_err(|_| {
                    format!(
                        "invalid Backbone peer priority '{}' (expected 0..100)",
                        value
                    )
                })?,
                None => crate::driver::BACKBONE_PEER_POOL_CONFIGURED_DEFAULT_PRIORITY,
            };
            if priority > 100 {
                return Err(format!(
                    "invalid Backbone peer priority '{}' (expected 0..100)",
                    priority
                ));
            }
            let mut client = BackboneClientConfig {
                name: name.to_string(),
                target_host,
                target_port,
                interface_id: id,
                max_reconnect_tries,
                transport_identity,
                ..BackboneClientConfig::default()
            };
            client.runtime = Arc::new(Mutex::new(BackboneClientRuntime::from_config(&client)));
            Ok(Box::new(BackboneMode::Client(client, priority)))
        } else {
            // Server mode. `listen_on` replaces `listen_ip`, as upstream
            // copies it over for Backbone interfaces.
            let listen_ip = params
                .get("listen_on")
                .or_else(|| params.get("listen_ip"))
                .or_else(|| params.get("device"))
                .cloned()
                .unwrap_or_else(|| "0.0.0.0".into());
            let listen_port = params
                .get("listen_port")
                .or_else(|| params.get("port"))
                .and_then(|v| v.parse().ok())
                .unwrap_or(4242);
            let max_connections = parse_client_limit(params)?;
            let idle_timeout = parse_positive_duration_secs(params, "idle_timeout");
            let write_stall_timeout = parse_positive_duration_secs(params, "write_stall_timeout");
            let abuse = BackboneAbuseConfig {
                max_penalty_duration: parse_positive_duration_secs(params, "max_penalty_duration"),
            };
            let fast_flap = parse_fast_flap_config(params)?;
            let mut config = BackboneConfig {
                name: name.to_string(),
                listen_ip,
                listen_port,
                interface_id: id,
                mode: constants::MODE_FULL,
                gravity: 0,
                recursive_prs: false,
                announces_from_internal: true,
                announces_to_internal: None,
                max_connections,
                idle_timeout,
                write_stall_timeout,
                abuse,
                fast_flap,
                fast_flap_state: shared_fast_flap_monitor(),
                ingress_control: IngressControlConfig::enabled(),
                runtime: Arc::new(Mutex::new(BackboneServerRuntime {
                    max_connections: None,
                    idle_timeout: None,
                    write_stall_timeout: None,
                    abuse: BackboneAbuseConfig::default(),
                })),
                peer_state: Arc::new(Mutex::new(BackbonePeerMonitor::new())),
            };
            let startup = BackboneServerRuntime::from_config(&config);
            config.runtime = Arc::new(Mutex::new(startup));
            Ok(Box::new(BackboneMode::Server(config)))
        }
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> io::Result<StartResult> {
        let mode = *config.into_any().downcast::<BackboneMode>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "wrong config type for BackboneInterface",
            )
        })?;

        match mode {
            BackboneMode::Client(cfg, _) => {
                let id = cfg.interface_id;
                let name = cfg.name.clone();
                let info = InterfaceInfo {
                    stamp_costs: Default::default(),
                    id,
                    name,
                    mode: ctx.mode,
                    gravity: ctx.gravity,
                    recursive_prs: ctx.recursive_prs,
                    announces_from_internal: ctx.announces_from_internal,
                    announces_to_internal: ctx.announces_to_internal,
                    out_capable: true,
                    in_capable: true,
                    bitrate: Some(cfg.bitrate),
                    airtime_profile: None,
                    announce_rate_target: None,
                    announce_rate_grace: 0,
                    announce_rate_penalty: 0.0,
                    announce_cap: constants::ANNOUNCE_CAP,
                    is_local_client: false,
                    // Synthesize a tunnel on each connect, as upstream's
                    // BackboneClientInterface does.
                    wants_tunnel: true,
                    hop_limiter: None,
                    tunnel_id: None,
                    mtu: cfg.hw_mtu() as u32,
                    mtu_upgradable: true,
                    ingress_control: ctx.ingress_control,
                    ia_freq: 0.0,
                    ia_samples: 0,
                    ip_freq: 0.0,
                    op_freq: 0.0,
                    op_samples: 0,
                    started: crate::time::now(),
                };
                let ifac_size = ctx.ifac.as_ref().map(|ifac| ifac.size).unwrap_or(0);
                let control = ListenerControl::new();
                let writer = start_retrying_client(
                    cfg,
                    ctx.tx,
                    ifac_size,
                    ctx.underlay_mark,
                    control.clone(),
                )?;
                Ok(StartResult::Simple {
                    control: Some(control),
                    id,
                    info,
                    writer,
                    // Upstream starts a BackboneClientInterface for a
                    // Backbone interface with a target host.
                    interface_type_name: "BackboneClientInterface".to_string(),
                })
            }
            BackboneMode::Server(mut cfg) => {
                cfg.ingress_control = ctx.ingress_control;
                cfg.mode = ctx.mode;
                cfg.gravity = ctx.gravity;
                cfg.recursive_prs = ctx.recursive_prs;
                cfg.announces_from_internal = ctx.announces_from_internal;
                cfg.announces_to_internal = ctx.announces_to_internal;
                let parent_id = cfg.interface_id;
                start_with_template(
                    cfg,
                    ctx.tx,
                    ctx.next_dynamic_id,
                    Some(DynamicInterfaceTemplate {
                        parent_id,
                        interface_type: "BackboneInterfacePeer".into(),
                        ifac: ctx.ifac,
                        mode: ctx.mode,
                        gravity: ctx.gravity,
                        hop_limiter: ctx.hop_limiter,
                        recursive_prs: ctx.recursive_prs,
                        announces_from_internal: ctx.announces_from_internal,
                        announces_to_internal: ctx.announces_to_internal,
                        stamp_costs: ctx.stamp_costs,
                        announce_limits: ctx.announce_limits,
                    }),
                    ctx.underlay_mark,
                )?;
                Ok(StartResult::Listener { control: None })
            }
        }
    }
}
