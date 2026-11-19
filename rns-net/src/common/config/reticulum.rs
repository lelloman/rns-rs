//! The `[reticulum]` section.

use super::*;

pub(super) fn build_reticulum_section(
    kvs: &HashMap<String, String>,
) -> Result<ReticulumSection, ConfigError> {
    let mut section = ReticulumSection::default();

    if let Some(v) = kvs.get("enable_transport") {
        section.enable_transport = parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "enable_transport".into(),
            value: v.clone(),
        })?;
    }
    if let Some(v) = kvs.get("static_transport_identity") {
        section.static_transport_identity =
            parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
                key: "static_transport_identity".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("local_hops_delta") {
        section.local_hops_delta = parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "local_hops_delta".into(),
            value: v.clone(),
        })?;
    }
    if let Some(v) = kvs.get("share_instance") {
        section.share_instance = parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "share_instance".into(),
            value: v.clone(),
        })?;
    }
    if let Some(v) = kvs.get("enable_interface_management") {
        section.enable_interface_management =
            parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
                key: "enable_interface_management".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("instance_name") {
        section.instance_name = v.clone();
    }
    if let Some(v) = kvs.get("shared_instance_port") {
        section.shared_instance_port = v.parse::<u16>().map_err(|_| ConfigError::InvalidValue {
            key: "shared_instance_port".into(),
            value: v.clone(),
        })?;
    }
    if let Some(v) = kvs.get("instance_control_port") {
        section.instance_control_port =
            v.parse::<u16>().map_err(|_| ConfigError::InvalidValue {
                key: "instance_control_port".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("panic_on_interface_error") {
        section.panic_on_interface_error =
            parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
                key: "panic_on_interface_error".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("use_implicit_proof") {
        section.use_implicit_proof = parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "use_implicit_proof".into(),
            value: v.clone(),
        })?;
    }
    if let Some(v) = kvs.get("network_identity") {
        section.network_identity = Some(v.clone());
    }
    if let Some(v) = kvs.get("respond_to_probes") {
        section.respond_to_probes = parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "respond_to_probes".into(),
            value: v.clone(),
        })?;
    }
    if let Some(v) = kvs.get("enable_remote_management") {
        section.enable_remote_management =
            parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
                key: "enable_remote_management".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("remote_management_allowed") {
        // Value is a comma-separated list of hex identity hashes
        for item in v.split(',') {
            let trimmed = item.trim();
            if !trimmed.is_empty() {
                section.remote_management_allowed.push(trimmed.to_string());
            }
        }
    }
    if let Some(v) = kvs.get("publish_blackhole") {
        section.publish_blackhole = parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "publish_blackhole".into(),
            value: v.clone(),
        })?;
    }
    if let Some(v) = kvs.get("blackhole_sources") {
        for hexhash in v.split(',').map(str::trim).filter(|h| !h.is_empty()) {
            let source =
                parse_identity_hash_hex(hexhash).ok_or_else(|| ConfigError::InvalidValue {
                    key: "blackhole_sources".into(),
                    value: hexhash.to_string(),
                })?;
            if !section.blackhole_sources.contains(&source) {
                section.blackhole_sources.push(source);
            }
        }
    }
    if let Some(v) = kvs.get("shared_instance_type") {
        // Upstream ignores values other than these two.
        match v.trim().to_ascii_lowercase().as_str() {
            "tcp" => section.shared_instance_tcp = true,
            "unix" => section.shared_instance_tcp = false,
            _ => {}
        }
    }
    if let Some(v) = kvs.get("rpc_key") {
        section.rpc_key = parse_rpc_key(v);
    }
    if let Some(v) = kvs.get("force_shared_instance_bitrate") {
        section.force_shared_instance_bitrate =
            Some(
                v.trim()
                    .parse::<u64>()
                    .map_err(|_| ConfigError::InvalidValue {
                        key: "force_shared_instance_bitrate".into(),
                        value: v.clone(),
                    })?,
            );
    }
    if let Some(v) = kvs.get("interface_discovery_sources") {
        for hexhash in v.split(',').map(str::trim).filter(|h| !h.is_empty()) {
            let source =
                parse_identity_hash_hex(hexhash).ok_or_else(|| ConfigError::InvalidValue {
                    key: "interface_discovery_sources".into(),
                    value: hexhash.to_string(),
                })?;
            if !section.interface_discovery_sources.contains(&source) {
                section.interface_discovery_sources.push(source);
            }
        }
    }
    if let Some(v) = kvs.get("blackhole_update_interval") {
        let minutes = v
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|m| m.is_finite())
            .ok_or_else(|| ConfigError::InvalidValue {
                key: "blackhole_update_interval".into(),
                value: v.clone(),
            })?;
        section.blackhole_update_interval = Some(minutes.max(2.0) * 60.0);
    }
    if let Some(v) = kvs.get("probe_port") {
        section.probe_port = Some(v.parse::<u16>().map_err(|_| ConfigError::InvalidValue {
            key: "probe_port".into(),
            value: v.clone(),
        })?);
    }
    if let Some(v) = kvs.get("probe_source_rate") {
        section.probe_rate_limit.per_source_rate = v
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|rate| rate.is_finite() && *rate >= 0.0)
            .ok_or_else(|| ConfigError::InvalidValue {
                key: "probe_source_rate".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("probe_source_burst") {
        section.probe_rate_limit.per_source_burst = v
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|burst| *burst > 0)
            .ok_or_else(|| ConfigError::InvalidValue {
                key: "probe_source_burst".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("probe_total_rate") {
        section.probe_rate_limit.total_rate =
            v.trim()
                .parse::<u32>()
                .map_err(|_| ConfigError::InvalidValue {
                    key: "probe_total_rate".into(),
                    value: v.clone(),
                })?;
    }
    if let Some(v) = kvs.get("probe_addr") {
        section.probe_addr = Some(v.clone());
    }
    if let Some(v) = kvs.get("probe_protocol") {
        section.probe_protocol = Some(v.clone());
    }
    if let Some(v) = kvs.get("direct_connect_policy") {
        section.direct_connect_policy = match v.to_ascii_lowercase().as_str() {
            "reject" => crate::event::HolePunchPolicy::Reject,
            "accept_all" => crate::event::HolePunchPolicy::AcceptAll,
            "identified_only" => crate::event::HolePunchPolicy::IdentifiedOnly,
            "ask_app" => crate::event::HolePunchPolicy::AskApp,
            _ => {
                return Err(ConfigError::InvalidValue {
                    key: "direct_connect_policy".into(),
                    value: v.clone(),
                })
            }
        };
    }
    if let Some(v) = kvs.get("direct_connect_allow_private_endpoints") {
        section.direct_connect_allow_private_endpoints =
            parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
                key: "direct_connect_allow_private_endpoints".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("direct_connect_allowed_identities") {
        for hexhash in v.split(',').map(str::trim).filter(|h| !h.is_empty()) {
            let identity =
                parse_identity_hash_hex(hexhash).ok_or_else(|| ConfigError::InvalidValue {
                    key: "direct_connect_allowed_identities".into(),
                    value: hexhash.to_string(),
                })?;
            if !section
                .direct_connect_allowed_identities
                .contains(&identity)
            {
                section.direct_connect_allowed_identities.push(identity);
            }
        }
    }
    if let Some(v) = kvs.get("direct_connect_reupgrade") {
        section.direct_connect_reupgrade.enabled =
            parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
                key: "direct_connect_reupgrade".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("direct_connect_reupgrade_attempts") {
        section.direct_connect_reupgrade.max_attempts =
            v.parse::<u32>().map_err(|_| ConfigError::InvalidValue {
                key: "direct_connect_reupgrade_attempts".into(),
                value: v.clone(),
            })?;
    }
    for (key, field) in [
        (
            "direct_connect_reupgrade_delay",
            &mut section.direct_connect_reupgrade.initial_delay,
        ),
        (
            "direct_connect_reupgrade_max_delay",
            &mut section.direct_connect_reupgrade.max_delay,
        ),
    ] {
        if let Some(v) = kvs.get(key) {
            *field = v
                .parse::<f64>()
                .ok()
                .filter(|secs| secs.is_finite() && *secs >= 0.0)
                .and_then(|secs| std::time::Duration::try_from_secs_f64(secs).ok())
                .ok_or_else(|| ConfigError::InvalidValue {
                    key: key.into(),
                    value: v.clone(),
                })?;
        }
    }
    if let Some(v) = kvs.get("device") {
        section.device = Some(v.clone());
    }
    if let Some(v) = kvs.get("underlay_mark") {
        let mark = v.parse::<u32>().map_err(|_| ConfigError::InvalidValue {
            key: "underlay_mark".into(),
            value: v.clone(),
        })?;
        if mark == 0 {
            return Err(ConfigError::InvalidValue {
                key: "underlay_mark".into(),
                value: v.clone(),
            });
        }
        section.underlay_mark = Some(mark);
    }
    if let Some(v) = kvs.get("discover_interfaces") {
        section.discover_interfaces = parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "discover_interfaces".into(),
            value: v.clone(),
        })?;
    }
    if let Some(v) = kvs.get("default_gravity") {
        section.default_gravity = v.parse::<i64>().map_err(|_| ConfigError::InvalidValue {
            key: "default_gravity".into(),
            value: v.clone(),
        })?;
    }
    // Retain the short-lived pre-release name as a compatibility alias. The
    // final upstream option takes precedence when both are present.
    if let Some(v) = kvs.get("autoconnect_discovered_mode") {
        section.autoconnect_interface_mode = Some(v.to_lowercase());
    }
    if let Some(v) = kvs.get("autoconnect_interface_mode") {
        section.autoconnect_interface_mode = Some(v.to_lowercase());
    }
    if let Some(v) = kvs.get("autoconnect_interface_gravity") {
        section.autoconnect_interface_gravity =
            v.parse::<i64>().map_err(|_| ConfigError::InvalidValue {
                key: "autoconnect_interface_gravity".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("autoconnect_announces_to_internal") {
        section.autoconnect_announces_to_internal =
            parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
                key: "autoconnect_announces_to_internal".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("autoconnect_unverified_implementations") {
        section.autoconnect_unverified_implementations =
            parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
                key: "autoconnect_unverified_implementations".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("autoconnect_policy") {
        section.autoconnect_policy = match v.trim().to_ascii_lowercase().as_str() {
            "upstream" => AutoconnectPolicy::Upstream,
            "pool" => AutoconnectPolicy::Pool,
            _ => {
                return Err(ConfigError::InvalidValue {
                    key: "autoconnect_policy".into(),
                    value: v.clone(),
                })
            }
        };
    }
    if let Some(v) = kvs.get("autoconnect_discovered_interfaces") {
        // Reticulum.py reads it with `as_int` and uses it only when `> 0`.
        let n = v
            .trim()
            .parse::<i64>()
            .map_err(|_| ConfigError::InvalidValue {
                key: "autoconnect_discovered_interfaces".into(),
                value: v.clone(),
            })?;
        section.autoconnect_discovered_interfaces = n.max(0) as usize;
    }
    if let Some(v) = kvs.get("required_discovery_value") {
        // Reticulum.py: `v = as_float(option)`, used only when `v > 0`.
        let v = parse_config_float(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "required_discovery_value".into(),
            value: v.clone(),
        })?;
        section.required_discovery_value =
            (v > 0.0).then(|| rns_core::stamp::clamp_cost(v, rns_core::constants::STAMP_COST_CAP));
    }
    if kvs.contains_key("hop_limiter") {
        // Reticulum.py reads it from `[filter]` since 01aef5bc and ignores
        // this one; say so rather than drop a configured limit silently.
        log::warn!("[reticulum] hop_limiter is no longer read; set it in the [filter] section");
    }
    if let Some(v) = kvs.get("prefer_shorter_path") {
        section.prefer_shorter_path = parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "prefer_shorter_path".into(),
            value: v.clone(),
        })?;
    }
    if let Some(v) = kvs.get("max_paths_per_destination") {
        let n = v.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
            key: "max_paths_per_destination".into(),
            value: v.clone(),
        })?;
        section.max_paths_per_destination = n.max(1);
    }
    if let Some(v) = kvs.get("packet_hashlist_max_entries") {
        let n = v.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
            key: "packet_hashlist_max_entries".into(),
            value: v.clone(),
        })?;
        section.packet_hashlist_max_entries = n.max(1);
    }
    if let Some(v) = kvs.get("packet_hashlist_allocation") {
        section.packet_hashlist_allocation = match v.to_ascii_lowercase().as_str() {
            "eager" => rns_core::transport::types::PacketHashlistAllocation::Eager,
            "lazy" => rns_core::transport::types::PacketHashlistAllocation::Lazy,
            _ => {
                return Err(ConfigError::InvalidValue {
                    key: "packet_hashlist_allocation".into(),
                    value: v.clone(),
                });
            }
        };
    }
    if let Some(v) = kvs.get("max_discovery_pr_tags") {
        let n = v.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
            key: "max_discovery_pr_tags".into(),
            value: v.clone(),
        })?;
        section.max_discovery_pr_tags = n.max(1);
    }
    if let Some(v) = kvs.get("max_path_destinations") {
        let n = v.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
            key: "max_path_destinations".into(),
            value: v.clone(),
        })?;
        section.max_path_destinations = n.max(1);
    }
    if let Some(v) = kvs.get("max_tunnel_destinations_total") {
        let n = v.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
            key: "max_tunnel_destinations_total".into(),
            value: v.clone(),
        })?;
        section.max_tunnel_destinations_total = n.max(1);
    }
    if let Some(v) = kvs.get("known_destinations_ttl") {
        section.known_destinations_ttl =
            v.parse::<u64>().map_err(|_| ConfigError::InvalidValue {
                key: "known_destinations_ttl".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("known_destinations_max_entries") {
        let n = v.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
            key: "known_destinations_max_entries".into(),
            value: v.clone(),
        })?;
        if n == 0 {
            return Err(ConfigError::InvalidValue {
                key: "known_destinations_max_entries".into(),
                value: v.clone(),
            });
        }
        section.known_destinations_max_entries = n;
    }
    if let Some(v) = kvs.get("ratchet_expiry") {
        let expiry = v.parse::<u64>().map_err(|_| ConfigError::InvalidValue {
            key: "ratchet_expiry".into(),
            value: v.clone(),
        })?;
        if expiry == 0 {
            return Err(ConfigError::InvalidValue {
                key: "ratchet_expiry".into(),
                value: v.clone(),
            });
        }
        section.ratchet_expiry = expiry;
    }
    if let Some(v) = kvs.get("destination_timeout_secs") {
        section.known_destinations_ttl =
            v.parse::<u64>().map_err(|_| ConfigError::InvalidValue {
                key: "destination_timeout_secs".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("announce_table_ttl") {
        let ttl = v.parse::<u64>().map_err(|_| ConfigError::InvalidValue {
            key: "announce_table_ttl".into(),
            value: v.clone(),
        })?;
        if ttl == 0 {
            return Err(ConfigError::InvalidValue {
                key: "announce_table_ttl".into(),
                value: v.clone(),
            });
        }
        section.announce_table_ttl = ttl;
    }
    if let Some(v) = kvs.get("announce_table_max_bytes") {
        let max_bytes = v.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
            key: "announce_table_max_bytes".into(),
            value: v.clone(),
        })?;
        if max_bytes == 0 {
            return Err(ConfigError::InvalidValue {
                key: "announce_table_max_bytes".into(),
                value: v.clone(),
            });
        }
        section.announce_table_max_bytes = max_bytes;
    }
    if let Some(v) = kvs.get("announce_signature_cache_enabled") {
        section.announce_sig_cache_enabled = match v.as_str() {
            "true" | "yes" | "True" | "Yes" => true,
            "false" | "no" | "False" | "No" => false,
            _ => {
                return Err(ConfigError::InvalidValue {
                    key: "announce_signature_cache_enabled".into(),
                    value: v.clone(),
                })
            }
        };
    }
    if let Some(v) = kvs.get("announce_signature_cache_max_entries") {
        let n = v.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
            key: "announce_signature_cache_max_entries".into(),
            value: v.clone(),
        })?;
        section.announce_sig_cache_max_entries = n;
    }
    if let Some(v) = kvs.get("announce_signature_cache_ttl") {
        let ttl = v.parse::<u64>().map_err(|_| ConfigError::InvalidValue {
            key: "announce_signature_cache_ttl".into(),
            value: v.clone(),
        })?;
        section.announce_sig_cache_ttl = ttl;
    }
    if let Some(v) = kvs.get("announce_queue_max_entries") {
        let n = v.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
            key: "announce_queue_max_entries".into(),
            value: v.clone(),
        })?;
        if n == 0 {
            return Err(ConfigError::InvalidValue {
                key: "announce_queue_max_entries".into(),
                value: v.clone(),
            });
        }
        section.announce_queue_max_entries = n;
    }
    if let Some(v) = kvs.get("announce_queue_max_interfaces") {
        let n = v.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
            key: "announce_queue_max_interfaces".into(),
            value: v.clone(),
        })?;
        if n == 0 {
            return Err(ConfigError::InvalidValue {
                key: "announce_queue_max_interfaces".into(),
                value: v.clone(),
            });
        }
        section.announce_queue_max_interfaces = n;
    }
    if let Some(v) = kvs.get("default_ar_target") {
        let target = v.parse::<f64>().map_err(|_| ConfigError::InvalidValue {
            key: "default_ar_target".into(),
            value: v.clone(),
        })?;
        if !target.is_finite() || target < 0.0 {
            return Err(ConfigError::InvalidValue {
                key: "default_ar_target".into(),
                value: v.clone(),
            });
        }
        section.default_ar_target = if target == 0.0 { None } else { Some(target) };
    }
    if let Some(v) = kvs.get("default_ar_penalty") {
        let penalty = v.parse::<f64>().map_err(|_| ConfigError::InvalidValue {
            key: "default_ar_penalty".into(),
            value: v.clone(),
        })?;
        if !penalty.is_finite() || penalty < 0.0 {
            return Err(ConfigError::InvalidValue {
                key: "default_ar_penalty".into(),
                value: v.clone(),
            });
        }
        section.default_ar_penalty = penalty;
    }
    if let Some(v) = kvs.get("default_ar_grace") {
        let grace = v.parse::<u32>().map_err(|_| ConfigError::InvalidValue {
            key: "default_ar_grace".into(),
            value: v.clone(),
        })?;
        section.default_ar_grace = grace;
    }
    // Upstream reads this with `or Interface.MAX_HELD_ANNOUNCES`, so 0
    // keeps the default; a per-interface 0 is taken literally.
    if let Some(v) = parse_usize_option(kvs, "ic_max_held_announces")? {
        if v > 0 {
            section.default_ic_max_held_announces = v;
        }
    }
    if let Some(v) = parse_nonnegative_f64_option(kvs, "ic_burst_hold")? {
        section.default_ic_burst_hold = v;
    }
    if let Some(v) = parse_nonnegative_f64_option(kvs, "ic_burst_freq_new")? {
        section.default_ic_burst_freq_new = v;
    }
    if let Some(v) = parse_nonnegative_f64_option(kvs, "ic_burst_freq")? {
        section.default_ic_burst_freq = v;
    }
    if let Some(v) = parse_nonnegative_f64_option(kvs, "ic_pr_burst_freq_new")? {
        section.default_ic_pr_burst_freq_new = v;
    }
    if let Some(v) = parse_nonnegative_f64_option(kvs, "ic_pr_burst_freq")? {
        section.default_ic_pr_burst_freq = v;
    }
    if let Some(v) = parse_nonnegative_f64_option(kvs, "ic_new_time")? {
        section.default_ic_new_time = v;
    }
    if let Some(v) = parse_nonnegative_f64_option(kvs, "ic_burst_penalty")? {
        section.default_ic_burst_penalty = v;
    }
    if let Some(v) = parse_nonnegative_f64_option(kvs, "ic_held_release_interval")? {
        section.default_ic_held_release_interval = v;
    }
    if let Some(v) = kvs.get("egress_control") {
        section.default_egress_control =
            parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
                key: "egress_control".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = parse_nonnegative_f64_option(kvs, "ec_pr_freq")? {
        section.default_ec_pr_freq = v;
    }
    if let Some(v) = kvs.get("announce_queue_max_bytes") {
        let n = v.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
            key: "announce_queue_max_bytes".into(),
            value: v.clone(),
        })?;
        if n == 0 {
            return Err(ConfigError::InvalidValue {
                key: "announce_queue_max_bytes".into(),
                value: v.clone(),
            });
        }
        section.announce_queue_max_bytes = n;
    }
    if let Some(v) = kvs.get("announce_queue_ttl") {
        let ttl = v.parse::<u64>().map_err(|_| ConfigError::InvalidValue {
            key: "announce_queue_ttl".into(),
            value: v.clone(),
        })?;
        if ttl == 0 {
            return Err(ConfigError::InvalidValue {
                key: "announce_queue_ttl".into(),
                value: v.clone(),
            });
        }
        section.announce_queue_ttl = ttl;
    }
    if let Some(v) = kvs.get("announce_queue_overflow_policy") {
        let normalized = v.to_lowercase();
        if normalized != "drop_newest" && normalized != "drop_oldest" && normalized != "drop_worst"
        {
            return Err(ConfigError::InvalidValue {
                key: "announce_queue_overflow_policy".into(),
                value: v.clone(),
            });
        }
        section.announce_queue_overflow_policy = normalized;
    }
    if let Some(v) = kvs.get("driver_event_queue_capacity") {
        let n = v.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
            key: "driver_event_queue_capacity".into(),
            value: v.clone(),
        })?;
        if n == 0 {
            return Err(ConfigError::InvalidValue {
                key: "driver_event_queue_capacity".into(),
                value: v.clone(),
            });
        }
        section.driver_event_queue_capacity = n;
        section.inbound_queue_capacities =
            crate::event::InboundQueueCapacities::from_shared_capacity(n);
    }
    for (key, queue) in [
        ("qlen_in_data", 0),
        ("qlen_in_announce", 1),
        ("qlen_in_pr", 2),
        ("qlen_in_il", 3),
    ] {
        let Some(v) = kvs.get(key) else {
            continue;
        };
        let n = v.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
            key: key.into(),
            value: v.clone(),
        })?;
        if n == 0 {
            return Err(ConfigError::InvalidValue {
                key: key.into(),
                value: v.clone(),
            });
        }
        match queue {
            0 => section.inbound_queue_capacities.data = n,
            1 => section.inbound_queue_capacities.announce = n,
            2 => section.inbound_queue_capacities.path_request = n,
            _ => section.inbound_queue_capacities.ingress_limited = n,
        }
    }
    if let Some(v) = kvs.get("interface_writer_queue_capacity") {
        let n = v.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
            key: "interface_writer_queue_capacity".into(),
            value: v.clone(),
        })?;
        if n == 0 {
            return Err(ConfigError::InvalidValue {
                key: "interface_writer_queue_capacity".into(),
                value: v.clone(),
            });
        }
        section.interface_writer_queue_capacity = n;
    }
    if let Some(v) = kvs.get("backbone_peer_pool_max_connected") {
        section.backbone_peer_pool_max_connected =
            v.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
                key: "backbone_peer_pool_max_connected".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("backbone_peer_pool_failure_threshold") {
        let n = v.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
            key: "backbone_peer_pool_failure_threshold".into(),
            value: v.clone(),
        })?;
        if n == 0 {
            return Err(ConfigError::InvalidValue {
                key: "backbone_peer_pool_failure_threshold".into(),
                value: v.clone(),
            });
        }
        section.backbone_peer_pool_failure_threshold = n;
    }
    if let Some(v) = kvs.get("backbone_peer_pool_failure_window") {
        section.backbone_peer_pool_failure_window =
            v.parse::<u64>().map_err(|_| ConfigError::InvalidValue {
                key: "backbone_peer_pool_failure_window".into(),
                value: v.clone(),
            })?;
    }
    if let Some(v) = kvs.get("backbone_peer_pool_cooldown") {
        section.backbone_peer_pool_cooldown =
            v.parse::<u64>().map_err(|_| ConfigError::InvalidValue {
                key: "backbone_peer_pool_cooldown".into(),
                value: v.clone(),
            })?;
    }
    #[cfg(feature = "hooks")]
    if let Some(v) = kvs.get("provider_bridge") {
        section.provider_bridge = parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "provider_bridge".into(),
            value: v.clone(),
        })?;
    }
    #[cfg(feature = "hooks")]
    if let Some(v) = kvs.get("provider_socket_path") {
        section.provider_socket_path = Some(v.clone());
    }
    #[cfg(feature = "hooks")]
    if let Some(v) = kvs.get("provider_queue_max_events") {
        section.provider_queue_max_events =
            v.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
                key: "provider_queue_max_events".into(),
                value: v.clone(),
            })?;
    }
    #[cfg(feature = "hooks")]
    if let Some(v) = kvs.get("provider_queue_max_bytes") {
        section.provider_queue_max_bytes =
            v.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
                key: "provider_queue_max_bytes".into(),
                value: v.clone(),
            })?;
    }
    #[cfg(feature = "hooks")]
    if let Some(v) = kvs.get("provider_overflow_policy") {
        let normalized = v.to_lowercase();
        if normalized != "drop_newest" && normalized != "drop_oldest" {
            return Err(ConfigError::InvalidValue {
                key: "provider_overflow_policy".into(),
                value: v.clone(),
            });
        }
        section.provider_overflow_policy = normalized;
    }

    Ok(section)
}
