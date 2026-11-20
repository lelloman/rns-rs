//! The `[reticulum]` section.

use super::keys::Keys;
use super::*;

pub(super) fn build_reticulum_section(
    kvs: &HashMap<String, String>,
    key_order: &[String],
) -> Result<ReticulumSection, ConfigError> {
    let keys = Keys(kvs);
    let mut section = ReticulumSection::default();
    let s = &mut section;

    keys.set_bool("enable_transport", &mut s.enable_transport)?;
    keys.set_bool(
        "static_transport_identity",
        &mut s.static_transport_identity,
    )?;
    keys.set_bool("local_hops_delta", &mut s.local_hops_delta)?;
    keys.set_bool("share_instance", &mut s.share_instance)?;
    keys.set_bool(
        "enable_interface_management",
        &mut s.enable_interface_management,
    )?;
    if let Some(v) = keys.get("instance_name") {
        s.instance_name = v.clone();
    }
    keys.set("shared_instance_port", &mut s.shared_instance_port)?;
    keys.set("instance_control_port", &mut s.instance_control_port)?;
    keys.set_bool("panic_on_interface_error", &mut s.panic_on_interface_error)?;
    keys.set_bool("use_implicit_proof", &mut s.use_implicit_proof)?;
    keys.set_string("network_identity", &mut s.network_identity);
    keys.set_bool("respond_to_probes", &mut s.respond_to_probes)?;
    keys.set_bool("enable_remote_management", &mut s.enable_remote_management)?;
    if let Some(v) = keys.get("remote_management_allowed") {
        // Value is a comma-separated list of hex identity hashes
        for item in v.split(',') {
            let trimmed = item.trim();
            if !trimmed.is_empty() {
                s.remote_management_allowed.push(trimmed.to_string());
            }
        }
    }
    keys.set_bool("publish_blackhole", &mut s.publish_blackhole)?;
    keys.add_identity_hashes("blackhole_sources", &mut s.blackhole_sources)?;
    if let Some(v) = keys.get("shared_instance_type") {
        // Upstream ignores values other than these two.
        match v.trim().to_ascii_lowercase().as_str() {
            "tcp" => s.shared_instance_tcp = true,
            "unix" => s.shared_instance_tcp = false,
            _ => {}
        }
    }
    if let Some(v) = keys.get("rpc_key") {
        s.rpc_key = parse_rpc_key(v);
    }
    if let Some(v) = keys.parse("force_shared_instance_bitrate")? {
        s.force_shared_instance_bitrate = Some(v);
    }
    keys.add_identity_hashes(
        "interface_discovery_sources",
        &mut s.interface_discovery_sources,
    )?;
    let finite = |v: &str| v.parse::<f64>().ok().filter(|n| n.is_finite());
    if let Some(minutes) = keys.with("blackhole_update_interval", finite)? {
        s.blackhole_update_interval = Some(minutes.max(2.0) * 60.0);
    }
    if let Some(v) = keys.parse("probe_port")? {
        s.probe_port = Some(v);
    }
    if let Some(v) = keys.nonnegative_f64("probe_source_rate")? {
        s.probe_rate_limit.per_source_rate = v;
    }
    keys.set_nonzero(
        "probe_source_burst",
        &mut s.probe_rate_limit.per_source_burst,
    )?;
    keys.set("probe_total_rate", &mut s.probe_rate_limit.total_rate)?;
    keys.set_string("probe_addr", &mut s.probe_addr);
    keys.set_string("probe_protocol", &mut s.probe_protocol);
    if let Some(v) = keys.with("direct_connect_policy", |v| {
        use crate::event::HolePunchPolicy;
        match v.to_ascii_lowercase().as_str() {
            "reject" => Some(HolePunchPolicy::Reject),
            "accept_all" => Some(HolePunchPolicy::AcceptAll),
            "identified_only" => Some(HolePunchPolicy::IdentifiedOnly),
            "ask_app" => Some(HolePunchPolicy::AskApp),
            _ => None,
        }
    })? {
        s.direct_connect_policy = v;
    }
    keys.set_bool(
        "direct_connect_allow_private_endpoints",
        &mut s.direct_connect_allow_private_endpoints,
    )?;
    keys.add_identity_hashes(
        "direct_connect_allowed_identities",
        &mut s.direct_connect_allowed_identities,
    )?;
    keys.set_bool(
        "direct_connect_reupgrade",
        &mut s.direct_connect_reupgrade.enabled,
    )?;
    keys.set(
        "direct_connect_reupgrade_attempts",
        &mut s.direct_connect_reupgrade.max_attempts,
    )?;
    let duration = |v: &str| {
        v.parse::<f64>()
            .ok()
            .filter(|secs| secs.is_finite() && *secs >= 0.0)
            .and_then(|secs| std::time::Duration::try_from_secs_f64(secs).ok())
    };
    if let Some(v) = keys.with("direct_connect_reupgrade_delay", duration)? {
        s.direct_connect_reupgrade.initial_delay = v;
    }
    if let Some(v) = keys.with("direct_connect_reupgrade_max_delay", duration)? {
        s.direct_connect_reupgrade.max_delay = v;
    }
    keys.set_string("device", &mut s.device);
    if let Some(mark) = keys.nonzero("underlay_mark")? {
        s.underlay_mark = Some(mark);
    }
    keys.set_bool("discover_interfaces", &mut s.discover_interfaces)?;
    keys.set("default_gravity", &mut s.default_gravity)?;
    // Retain the short-lived pre-release name as a compatibility alias. The
    // final upstream option takes precedence when both are present.
    for key in ["autoconnect_discovered_mode", "autoconnect_interface_mode"] {
        if let Some(v) = keys.get(key) {
            s.autoconnect_interface_mode = Some(v.to_lowercase());
        }
    }
    keys.set(
        "autoconnect_interface_gravity",
        &mut s.autoconnect_interface_gravity,
    )?;
    keys.set_bool(
        "autoconnect_announces_to_internal",
        &mut s.autoconnect_announces_to_internal,
    )?;
    keys.set_bool(
        "autoconnect_unverified_implementations",
        &mut s.autoconnect_unverified_implementations,
    )?;
    if let Some(v) = keys.with("autoconnect_policy", |v| {
        match v.trim().to_ascii_lowercase().as_str() {
            "upstream" => Some(AutoconnectPolicy::Upstream),
            "pool" => Some(AutoconnectPolicy::Pool),
            _ => None,
        }
    })? {
        s.autoconnect_policy = v;
    }
    // Reticulum.py reads it with `as_int` and uses it only when `> 0`.
    if let Some(n) = keys.parse::<i64>("autoconnect_discovered_interfaces")? {
        s.autoconnect_discovered_interfaces = n.max(0) as usize;
    }
    // Upstream aecc1547 reads the options in file order and applies the
    // caps when it reads the count, so disabling them only takes effect
    // when the disable key comes first.
    let disable_caps_key = "autoconnect_discovered_interfaces_disable_caps";
    if keys.bool(disable_caps_key)? == Some(true) {
        let position = |key: &str| key_order.iter().position(|k| k == key);
        s.autoconnect_discovered_interfaces_caps_disabled =
            match position("autoconnect_discovered_interfaces") {
                Some(count) => position(disable_caps_key).is_some_and(|disable| disable < count),
                None => true,
            };
    }
    // Reticulum.py: `v = as_float(option)`, used only when `v > 0`.
    if let Some(v) = keys.with("required_discovery_value", parse_config_float)? {
        s.required_discovery_value =
            (v > 0.0).then(|| rns_core::stamp::clamp_cost(v, rns_core::constants::STAMP_COST_CAP));
    }
    if keys.get("hop_limiter").is_some() {
        // Reticulum.py reads it from `[filter]` since 01aef5bc and ignores
        // this one; say so rather than drop a configured limit silently.
        log::warn!("[reticulum] hop_limiter is no longer read; set it in the [filter] section");
    }
    keys.set_bool("prefer_shorter_path", &mut s.prefer_shorter_path)?;
    // Zero means one for these limits.
    for (key, field) in [
        (
            "max_paths_per_destination",
            &mut s.max_paths_per_destination,
        ),
        (
            "packet_hashlist_max_entries",
            &mut s.packet_hashlist_max_entries,
        ),
    ] {
        if let Some(n) = keys.parse::<usize>(key)? {
            *field = n.max(1);
        }
    }
    if let Some(v) = keys.with("unresponsive_path_recovery", |v| {
        use rns_core::transport::types::UnresponsivePathRecovery;
        match v {
            "native" => Some(UnresponsivePathRecovery::Native),
            "upstream" => Some(UnresponsivePathRecovery::Upstream),
            _ => None,
        }
    })? {
        s.unresponsive_path_recovery = v;
    }
    if let Some(v) = keys.with("packet_hashlist_allocation", |v| {
        use rns_core::transport::types::PacketHashlistAllocation;
        match v.to_ascii_lowercase().as_str() {
            "eager" => Some(PacketHashlistAllocation::Eager),
            "lazy" => Some(PacketHashlistAllocation::Lazy),
            _ => None,
        }
    })? {
        s.packet_hashlist_allocation = v;
    }
    for (key, field) in [
        ("max_discovery_pr_tags", &mut s.max_discovery_pr_tags),
        ("max_path_destinations", &mut s.max_path_destinations),
        (
            "max_tunnel_destinations_total",
            &mut s.max_tunnel_destinations_total,
        ),
    ] {
        if let Some(n) = keys.parse::<usize>(key)? {
            *field = n.max(1);
        }
    }
    keys.set("known_destinations_ttl", &mut s.known_destinations_ttl)?;
    keys.set_nonzero(
        "known_destinations_max_entries",
        &mut s.known_destinations_max_entries,
    )?;
    keys.set_nonzero("ratchet_expiry", &mut s.ratchet_expiry)?;
    keys.set("destination_timeout_secs", &mut s.known_destinations_ttl)?;
    keys.set_nonzero("announce_table_ttl", &mut s.announce_table_ttl)?;
    keys.set_nonzero("announce_table_max_bytes", &mut s.announce_table_max_bytes)?;
    if let Some(v) = keys.with("announce_signature_cache_enabled", |v| match v {
        "true" | "yes" | "True" | "Yes" => Some(true),
        "false" | "no" | "False" | "No" => Some(false),
        _ => None,
    })? {
        s.announce_sig_cache_enabled = v;
    }
    keys.set(
        "announce_signature_cache_max_entries",
        &mut s.announce_sig_cache_max_entries,
    )?;
    keys.set(
        "announce_signature_cache_ttl",
        &mut s.announce_sig_cache_ttl,
    )?;
    keys.set_nonzero(
        "announce_queue_max_entries",
        &mut s.announce_queue_max_entries,
    )?;
    keys.set_nonzero(
        "announce_queue_max_interfaces",
        &mut s.announce_queue_max_interfaces,
    )?;
    if let Some(target) = keys.nonnegative_f64("default_ar_target")? {
        s.default_ar_target = (target != 0.0).then_some(target);
    }
    if let Some(v) = keys.nonnegative_f64("default_ar_penalty")? {
        s.default_ar_penalty = v;
    }
    keys.set("default_ar_grace", &mut s.default_ar_grace)?;
    // Upstream reads this with `or Interface.MAX_HELD_ANNOUNCES`, so 0
    // keeps the default; a per-interface 0 is taken literally.
    if let Some(v) = keys.parse::<usize>("ic_max_held_announces")? {
        if v > 0 {
            s.default_ic_max_held_announces = v;
        }
    }
    for (key, field) in [
        ("ic_burst_hold", &mut s.default_ic_burst_hold),
        ("ic_burst_freq_new", &mut s.default_ic_burst_freq_new),
        ("ic_burst_freq", &mut s.default_ic_burst_freq),
        ("ic_pr_burst_freq_new", &mut s.default_ic_pr_burst_freq_new),
        ("ic_pr_burst_freq", &mut s.default_ic_pr_burst_freq),
        ("ic_new_time", &mut s.default_ic_new_time),
        ("ic_burst_penalty", &mut s.default_ic_burst_penalty),
        (
            "ic_held_release_interval",
            &mut s.default_ic_held_release_interval,
        ),
    ] {
        if let Some(v) = keys.nonnegative_f64(key)? {
            *field = v;
        }
    }
    keys.set_bool("egress_control", &mut s.default_egress_control)?;
    if let Some(v) = keys.nonnegative_f64("ec_pr_freq")? {
        s.default_ec_pr_freq = v;
    }
    keys.set_nonzero("announce_queue_max_bytes", &mut s.announce_queue_max_bytes)?;
    keys.set_nonzero("announce_queue_ttl", &mut s.announce_queue_ttl)?;
    if let Some(v) = keys.with("announce_queue_overflow_policy", |v| {
        let normalized = v.to_lowercase();
        matches!(
            normalized.as_str(),
            "drop_newest" | "drop_oldest" | "drop_worst"
        )
        .then_some(normalized)
    })? {
        s.announce_queue_overflow_policy = v;
    }
    if let Some(n) = keys.nonzero("driver_event_queue_capacity")? {
        s.driver_event_queue_capacity = n;
        s.inbound_queue_capacities = crate::event::InboundQueueCapacities::from_shared_capacity(n);
    }
    let queues = &mut s.inbound_queue_capacities;
    for (key, field) in [
        ("qlen_in_data", &mut queues.data),
        ("qlen_in_announce", &mut queues.announce),
        ("qlen_in_pr", &mut queues.path_request),
        ("qlen_in_il", &mut queues.ingress_limited),
    ] {
        keys.set_nonzero(key, field)?;
    }
    keys.set_nonzero(
        "interface_writer_queue_capacity",
        &mut s.interface_writer_queue_capacity,
    )?;
    keys.set(
        "backbone_peer_pool_max_connected",
        &mut s.backbone_peer_pool_max_connected,
    )?;
    keys.set_nonzero(
        "backbone_peer_pool_failure_threshold",
        &mut s.backbone_peer_pool_failure_threshold,
    )?;
    keys.set(
        "backbone_peer_pool_failure_window",
        &mut s.backbone_peer_pool_failure_window,
    )?;
    keys.set(
        "backbone_peer_pool_cooldown",
        &mut s.backbone_peer_pool_cooldown,
    )?;
    #[cfg(feature = "hooks")]
    {
        keys.set_bool("provider_bridge", &mut s.provider_bridge)?;
        keys.set_string("provider_socket_path", &mut s.provider_socket_path);
        keys.set(
            "provider_queue_max_events",
            &mut s.provider_queue_max_events,
        )?;
        keys.set("provider_queue_max_bytes", &mut s.provider_queue_max_bytes)?;
        if let Some(v) = keys.with("provider_overflow_policy", |v| {
            let normalized = v.to_lowercase();
            matches!(normalized.as_str(), "drop_newest" | "drop_oldest").then_some(normalized)
        })? {
            s.provider_overflow_policy = v;
        }
    }

    Ok(section)
}
