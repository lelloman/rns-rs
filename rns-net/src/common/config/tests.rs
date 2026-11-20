use super::*;

#[test]
fn parse_empty() {
    let config = parse("").unwrap();
    assert!(!config.reticulum.enable_transport);
    assert!(!config.reticulum.static_transport_identity);
    assert!(!config.reticulum.local_hops_delta);
    assert!(config.reticulum.share_instance);
    assert_eq!(config.reticulum.instance_name, "default");
    assert_eq!(config.logging.loglevel, 4);
    assert!(config.logging.logtimestamps);
    assert!(config.interfaces.is_empty());
    assert_eq!(
        config.reticulum.packet_hashlist_max_entries,
        rns_core::constants::HASHLIST_MAXSIZE
    );
    assert_eq!(
        config.reticulum.packet_hashlist_allocation,
        rns_core::transport::types::PacketHashlistAllocation::Lazy
    );
    assert_eq!(
        config.reticulum.announce_table_ttl,
        rns_core::constants::ANNOUNCE_TABLE_TTL as u64
    );
    assert_eq!(
        config.reticulum.announce_table_max_bytes,
        rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES
    );
    assert_eq!(
        config.reticulum.ratchet_expiry,
        rns_core::constants::RATCHET_EXPIRY
    );
    assert_eq!(
        config.reticulum.inbound_queue_capacities,
        crate::event::InboundQueueCapacities::default()
    );
}

#[test]
fn parse_reticulum_inbound_queue_lengths() {
    let config = parse(
        r#"
[reticulum]
qlen_in_data = 101
qlen_in_announce = 102
qlen_in_pr = 103
qlen_in_il = 104
"#,
    )
    .unwrap();

    assert_eq!(
        config.reticulum.inbound_queue_capacities,
        crate::event::InboundQueueCapacities {
            data: 101,
            announce: 102,
            path_request: 103,
            ingress_limited: 104,
        }
    );
}

#[test]
fn inbound_queue_lengths_must_be_positive_integers() {
    for key in [
        "qlen_in_data",
        "qlen_in_announce",
        "qlen_in_pr",
        "qlen_in_il",
    ] {
        for value in ["0", "-1", "many"] {
            let input = format!("[reticulum]\n{key} = {value}\n");
            assert!(matches!(
                parse(&input),
                Err(ConfigError::InvalidValue { key: invalid_key, .. })
                    if invalid_key == key
            ));
        }
    }
}

#[test]
fn legacy_event_capacity_still_scales_class_defaults() {
    let config = parse("[reticulum]\ndriver_event_queue_capacity = 64\n").unwrap();
    assert_eq!(
        config.reticulum.inbound_queue_capacities,
        crate::event::InboundQueueCapacities {
            data: 64,
            announce: 64,
            path_request: 64,
            ingress_limited: 8,
        }
    );
}

#[cfg(feature = "hooks")]
#[test]
fn parse_provider_bridge_config() {
    let config = parse(
        r#"
[reticulum]
provider_bridge = yes
provider_socket_path = /tmp/rns-provider.sock
provider_queue_max_events = 42
provider_queue_max_bytes = 8192
provider_overflow_policy = drop_oldest
"#,
    )
    .unwrap();

    assert!(config.reticulum.provider_bridge);
    assert_eq!(
        config.reticulum.provider_socket_path.as_deref(),
        Some("/tmp/rns-provider.sock")
    );
    assert_eq!(config.reticulum.provider_queue_max_events, 42);
    assert_eq!(config.reticulum.provider_queue_max_bytes, 8192);
    assert_eq!(config.reticulum.provider_overflow_policy, "drop_oldest");
}

#[test]
fn an_interface_runs_only_when_enabled_says_so() {
    let config = parse(
            "[interfaces]\n  [[A]]\n    type = UDPInterface\n  [[B]]\n    type = UDPInterface\n    enabled = no\n  [[C]]\n    type = UDPInterface\n    enabled = yes\n  [[D]]\n    type = UDPInterface\n    interface_enabled = true\n",
        )
        .unwrap();
    let enabled: Vec<_> = config
        .interfaces
        .iter()
        .map(|i| (i.name.as_str(), i.enabled))
        .collect();
    assert_eq!(
        enabled,
        vec![("A", false), ("B", false), ("C", true), ("D", true)]
    );
}

#[test]
fn parse_default_config() {
    // The default config from Python's __default_rns_config__, with the
    // commented-out [stamps] section added in upstream f57fa265.
    let input = r#"
[reticulum]
enable_transport = False
share_instance = Yes
instance_name = default

[stamps]

# destination_cost = 23.5
# destination_value = 25.0
# pr_cost = 15.8
# pr_value = 15.8
# lr_cost = 12.5
# lr_stamp_timeout = 15
# pr_stamp_timeout = 15

[logging]
loglevel = 4

[interfaces]

  [[Default Interface]]
    type = AutoInterface
    enabled = Yes
"#;
    let config = parse(input).unwrap();
    assert!(!config.reticulum.enable_transport);
    assert!(config.reticulum.share_instance);
    assert_eq!(config.reticulum.instance_name, "default");
    assert_eq!(config.logging.loglevel, 4);
    assert_eq!(config.interfaces.len(), 1);
    assert_eq!(config.interfaces[0].name, "Default Interface");
    assert_eq!(config.interfaces[0].interface_type, "AutoInterface");
    assert!(config.interfaces[0].enabled);
    assert_eq!(config.stamps, StampsSection::default());
}

#[test]
fn parse_reticulum_section() {
    let input = r#"
[reticulum]
enable_transport = True
share_instance = No
instance_name = mynode
shared_instance_port = 12345
instance_control_port = 12346
panic_on_interface_error = Yes
use_implicit_proof = False
respond_to_probes = True
network_identity = /home/user/.reticulum/identity
known_destinations_ttl = 1234
known_destinations_max_entries = 4321
ratchet_expiry = 9876
announce_table_ttl = 45
announce_table_max_bytes = 65536
packet_hashlist_max_entries = 321
max_discovery_pr_tags = 222
max_path_destinations = 111
max_tunnel_destinations_total = 99
announce_signature_cache_enabled = false
announce_signature_cache_max_entries = 500
announce_signature_cache_ttl = 300
announce_queue_max_entries = 123
announce_queue_max_interfaces = 321
announce_queue_max_bytes = 4567
announce_queue_ttl = 89
announce_queue_overflow_policy = drop_oldest
driver_event_queue_capacity = 6543
interface_writer_queue_capacity = 210
underlay_mark = 51820
backbone_peer_pool_max_connected = 6
backbone_peer_pool_failure_threshold = 4
backbone_peer_pool_failure_window = 120
backbone_peer_pool_cooldown = 300
"#;
    let config = parse(input).unwrap();
    assert!(config.reticulum.enable_transport);
    assert!(!config.reticulum.share_instance);
    assert_eq!(config.reticulum.instance_name, "mynode");
    assert_eq!(config.reticulum.shared_instance_port, 12345);
    assert_eq!(config.reticulum.instance_control_port, 12346);
    assert!(config.reticulum.panic_on_interface_error);
    assert!(!config.reticulum.use_implicit_proof);
    assert!(config.reticulum.respond_to_probes);
    assert_eq!(config.reticulum.underlay_mark, Some(51820));
    assert_eq!(
        config.reticulum.network_identity.as_deref(),
        Some("/home/user/.reticulum/identity")
    );
    assert_eq!(config.reticulum.known_destinations_ttl, 1234);
    assert_eq!(config.reticulum.known_destinations_max_entries, 4321);
    assert_eq!(config.reticulum.ratchet_expiry, 9876);
    assert_eq!(config.reticulum.announce_table_ttl, 45);
    assert_eq!(config.reticulum.announce_table_max_bytes, 65536);
    assert_eq!(config.reticulum.packet_hashlist_max_entries, 321);
    assert_eq!(config.reticulum.max_discovery_pr_tags, 222);
    assert_eq!(config.reticulum.max_path_destinations, 111);
    assert_eq!(config.reticulum.max_tunnel_destinations_total, 99);
    assert!(!config.reticulum.announce_sig_cache_enabled);
    assert_eq!(config.reticulum.announce_sig_cache_max_entries, 500);
    assert_eq!(config.reticulum.announce_sig_cache_ttl, 300);
    assert_eq!(config.reticulum.announce_queue_max_entries, 123);
    assert_eq!(config.reticulum.announce_queue_max_interfaces, 321);
    assert_eq!(config.reticulum.announce_queue_max_bytes, 4567);
    assert_eq!(config.reticulum.announce_queue_ttl, 89);
    assert_eq!(
        config.reticulum.announce_queue_overflow_policy,
        "drop_oldest"
    );
    assert_eq!(config.reticulum.driver_event_queue_capacity, 6543);
    assert_eq!(config.reticulum.interface_writer_queue_capacity, 210);
    assert_eq!(config.reticulum.backbone_peer_pool_max_connected, 6);
    assert_eq!(config.reticulum.backbone_peer_pool_failure_threshold, 4);
    assert_eq!(config.reticulum.backbone_peer_pool_failure_window, 120);
    assert_eq!(config.reticulum.backbone_peer_pool_cooldown, 300);
}

#[test]
fn underlay_mark_defaults_to_disabled() {
    let config = parse("[reticulum]\n").unwrap();
    assert_eq!(config.reticulum.underlay_mark, None);
}

#[test]
fn underlay_mark_rejects_zero_and_non_numeric_values() {
    for value in ["0", "-1", "not-a-mark", "4294967296"] {
        let error = parse(&format!("[reticulum]\nunderlay_mark = {value}\n"))
            .expect_err("invalid underlay mark must be rejected");
        assert!(matches!(
            error,
            ConfigError::InvalidValue { ref key, .. } if key == "underlay_mark"
        ));
    }
}

#[test]
fn parse_reticulum_announce_rate_defaults() {
    let input = r#"
[reticulum]
default_ar_target = 7200
default_ar_penalty = 15
default_ar_grace = 7
"#;
    let config = parse(input).unwrap();

    assert_eq!(config.reticulum.default_ar_target, Some(7200.0));
    assert_eq!(config.reticulum.default_ar_penalty, 15.0);
    assert_eq!(config.reticulum.default_ar_grace, 7);
}

#[test]
fn parse_interface_gravity_defaults_and_autoconnect_options() {
    let config = parse(
        r#"
[reticulum]
default_gravity = -3
autoconnect_discovered_mode = full
autoconnect_interface_mode = boundary
autoconnect_interface_gravity = 7
autoconnect_announces_to_internal = yes
autoconnect_unverified_implementations = yes
"#,
    )
    .unwrap();

    assert_eq!(
        config.reticulum.autoconnect_interface_mode.as_deref(),
        Some("boundary")
    );
    assert_eq!(config.reticulum.default_gravity, -3);
    assert_eq!(config.reticulum.autoconnect_interface_gravity, 7);
    assert!(config.reticulum.autoconnect_announces_to_internal);
    assert!(config.reticulum.autoconnect_unverified_implementations);
}

#[test]
fn autoconnect_unverified_implementations_defaults_to_false() {
    let config = parse("[reticulum]\n").unwrap();
    assert!(!config.reticulum.autoconnect_unverified_implementations);
}

#[test]
fn interface_gravity_options_default_to_zero() {
    let config = parse("[reticulum]\n").unwrap();
    assert_eq!(config.reticulum.default_gravity, 0);
    assert_eq!(config.reticulum.autoconnect_interface_gravity, 0);
}

#[test]
fn parses_packet_hashlist_allocation_case_insensitively() {
    for (value, expected) in [
        (
            "eager",
            rns_core::transport::types::PacketHashlistAllocation::Eager,
        ),
        (
            "LAZY",
            rns_core::transport::types::PacketHashlistAllocation::Lazy,
        ),
        (
            "LaZy",
            rns_core::transport::types::PacketHashlistAllocation::Lazy,
        ),
    ] {
        let input = format!("[reticulum]\npacket_hashlist_allocation = {value}\n");
        assert_eq!(
            parse(&input).unwrap().reticulum.packet_hashlist_allocation,
            expected
        );
    }
}

#[test]
fn rejects_invalid_packet_hashlist_allocation() {
    assert!(parse("[reticulum]\npacket_hashlist_allocation = dynamic\n").is_err());
}

#[test]
fn parses_unresponsive_path_recovery() {
    use rns_core::transport::types::UnresponsivePathRecovery;
    assert_eq!(
        parse("[reticulum]\n")
            .unwrap()
            .reticulum
            .unresponsive_path_recovery,
        UnresponsivePathRecovery::Native
    );
    for (value, expected) in [
        ("native", UnresponsivePathRecovery::Native),
        ("upstream", UnresponsivePathRecovery::Upstream),
    ] {
        let input = format!("[reticulum]\nunresponsive_path_recovery = {value}\n");
        assert_eq!(
            parse(&input).unwrap().reticulum.unresponsive_path_recovery,
            expected
        );
    }
    for value in ["python", "yes", ""] {
        let input = format!("[reticulum]\nunresponsive_path_recovery = {value}\n");
        assert!(parse(&input).is_err(), "{value:?}");
    }
}

#[test]
fn rejects_non_integer_global_gravity_options() {
    assert!(parse("[reticulum]\ndefault_gravity = heavy\n").is_err());
    assert!(parse("[reticulum]\nautoconnect_interface_gravity = light\n").is_err());
}

#[test]
fn parse_reticulum_announce_rate_target_zero_disables_default() {
    let input = r#"
[reticulum]
default_ar_target = 0
default_ar_penalty = 0
default_ar_grace = 0
"#;
    let config = parse(input).unwrap();

    assert_eq!(config.reticulum.default_ar_target, None);
    assert_eq!(config.reticulum.default_ar_penalty, 0.0);
    assert_eq!(config.reticulum.default_ar_grace, 0);
}

#[test]
fn parse_reticulum_announce_rate_defaults_reject_negative_values() {
    for (key, value) in [
        ("default_ar_target", "-1"),
        ("default_ar_target", "NaN"),
        ("default_ar_target", "inf"),
        ("default_ar_penalty", "-1"),
        ("default_ar_penalty", "NaN"),
        ("default_ar_penalty", "inf"),
        ("default_ar_grace", "-1"),
    ] {
        let input = format!("[reticulum]\n{key} = {value}\n");
        let err = parse(&input).unwrap_err();
        assert!(
            err.to_string().contains(key),
            "error {err:?} should mention {key}"
        );
    }
}

#[test]
fn parse_reticulum_ingress_and_egress_control_defaults() {
    let input = r#"[reticulum]
ic_max_held_announces = 17
ic_burst_hold = 1.5
ic_burst_freq_new = 2.5
ic_burst_freq = 3.5
ic_pr_burst_freq_new = 4.5
ic_pr_burst_freq = 5.5
ic_new_time = 6.5
ic_burst_penalty = 7.5
ic_held_release_interval = 8.5
egress_control = Yes
ec_pr_freq = 9.5
"#;

    let config = parse(input).unwrap();

    assert_eq!(config.reticulum.default_ic_max_held_announces, 17);
    assert_eq!(config.reticulum.default_ic_burst_hold, 1.5);
    assert_eq!(config.reticulum.default_ic_burst_freq_new, 2.5);
    assert_eq!(config.reticulum.default_ic_burst_freq, 3.5);
    assert_eq!(config.reticulum.default_ic_pr_burst_freq_new, 4.5);
    assert_eq!(config.reticulum.default_ic_pr_burst_freq, 5.5);
    assert_eq!(config.reticulum.default_ic_new_time, 6.5);
    assert_eq!(config.reticulum.default_ic_burst_penalty, 7.5);
    assert_eq!(config.reticulum.default_ic_held_release_interval, 8.5);
    assert!(config.reticulum.default_egress_control);
    assert_eq!(config.reticulum.default_ec_pr_freq, 9.5);
}

#[test]
fn parse_reticulum_ic_max_held_announces_zero_keeps_default() {
    let config = parse("[reticulum]\nic_max_held_announces = 0\n").unwrap();
    assert_eq!(
        config.reticulum.default_ic_max_held_announces,
        rns_core::constants::IC_MAX_HELD_ANNOUNCES
    );
    assert_eq!(config.reticulum.default_ic_max_held_announces, 64);
}

#[test]
fn parse_reticulum_ingress_and_egress_defaults_reject_invalid_values() {
    for (key, value) in [
        ("ic_max_held_announces", "-1"),
        ("ic_burst_hold", "-1"),
        ("ic_burst_hold", "NaN"),
        ("ic_burst_freq_new", "-1"),
        ("ic_burst_freq", "inf"),
        ("ic_pr_burst_freq_new", "-1"),
        ("ic_pr_burst_freq", "NaN"),
        ("ic_new_time", "-1"),
        ("ic_burst_penalty", "-1"),
        ("ic_held_release_interval", "-1"),
        ("ec_pr_freq", "-1"),
        ("ec_pr_freq", "inf"),
    ] {
        let input = format!("[reticulum]\n{key} = {value}\n");
        let err = parse(&input).unwrap_err();
        assert!(
            format!("{err}").contains(key),
            "error {err} should mention {key}"
        );
    }
}

#[test]
fn parse_backbone_peer_pool_defaults_disabled() {
    let config = parse("[reticulum]\n").unwrap();
    assert_eq!(config.reticulum.backbone_peer_pool_max_connected, 0);
    assert_eq!(config.reticulum.backbone_peer_pool_failure_threshold, 3);
    assert_eq!(config.reticulum.backbone_peer_pool_failure_window, 600);
    assert_eq!(config.reticulum.backbone_peer_pool_cooldown, 900);
}

#[test]
fn parse_announce_table_limits_reject_zero() {
    let err = parse(
        r#"
[reticulum]
announce_table_ttl = 0
"#,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, .. } if key == "announce_table_ttl"
    ));

    let err = parse(
        r#"
[reticulum]
known_destinations_max_entries = 0
"#,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, .. } if key == "known_destinations_max_entries"
    ));

    let err = parse(
        r#"
[reticulum]
ratchet_expiry = 0
"#,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, .. } if key == "ratchet_expiry"
    ));

    let err = parse(
        r#"
[reticulum]
announce_table_max_bytes = 0
"#,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, .. } if key == "announce_table_max_bytes"
    ));

    let err = parse(
        r#"
[reticulum]
announce_queue_max_entries = 0
"#,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, .. } if key == "announce_queue_max_entries"
    ));

    let err = parse(
        r#"
[reticulum]
announce_queue_max_interfaces = 0
"#,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, .. } if key == "announce_queue_max_interfaces"
    ));

    let err = parse(
        r#"
[reticulum]
announce_queue_max_bytes = 0
"#,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, .. } if key == "announce_queue_max_bytes"
    ));

    let err = parse(
        r#"
[reticulum]
driver_event_queue_capacity = 0
"#,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, .. } if key == "driver_event_queue_capacity"
    ));

    let err = parse(
        r#"
[reticulum]
interface_writer_queue_capacity = 0
"#,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, .. } if key == "interface_writer_queue_capacity"
    ));

    let err = parse(
        r#"
[reticulum]
announce_queue_ttl = 0
"#,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, .. } if key == "announce_queue_ttl"
    ));
}

#[test]
fn parse_announce_queue_overflow_policy_rejects_invalid() {
    let err = parse(
        r#"
[reticulum]
announce_queue_overflow_policy = keep_everything
"#,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, .. } if key == "announce_queue_overflow_policy"
    ));
}

#[test]
fn parse_destination_timeout_secs_alias() {
    let config = parse(
        r#"
[reticulum]
destination_timeout_secs = 777
"#,
    )
    .unwrap();

    assert_eq!(config.reticulum.known_destinations_ttl, 777);
}

#[test]
fn parse_logging_section() {
    let input = "[logging]\nloglevel = 6\nlogtimestamps = no\n";
    let config = parse(input).unwrap();
    assert_eq!(config.logging.loglevel, 6);
    assert!(!config.logging.logtimestamps);
}

#[test]
fn parse_logging_accepts_pathing_and_extreme_levels() {
    for level in [7, 8] {
        let config = parse(&format!("[logging]\nloglevel = {level}\n")).unwrap();
        assert_eq!(config.logging.loglevel, level);
    }
}

#[test]
fn parse_logging_rejects_levels_above_extreme() {
    for value in ["9", "255", "256", "-1"] {
        let err = parse(&format!("[logging]\nloglevel = {value}\n")).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidValue { key, .. } if key == "loglevel"
        ));
    }
}

#[test]
fn parse_logging_rejects_invalid_logtimestamps() {
    let err = parse("[logging]\nlogtimestamps = maybe\n").unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, .. } if key == "logtimestamps"
    ));
}

#[test]
fn parse_interface_tcp_client() {
    let input = r#"
[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    enabled = Yes
    target_host = 87.106.8.245
    target_port = 4242
"#;
    let config = parse(input).unwrap();
    assert_eq!(config.interfaces.len(), 1);
    let iface = &config.interfaces[0];
    assert_eq!(iface.name, "TCP Client");
    assert_eq!(iface.interface_type, "TCPClientInterface");
    assert!(iface.enabled);
    assert_eq!(iface.params.get("target_host").unwrap(), "87.106.8.245");
    assert_eq!(iface.params.get("target_port").unwrap(), "4242");
}

#[test]
fn parse_interface_tcp_server() {
    let input = r#"
[interfaces]
  [[TCP Server]]
    type = TCPServerInterface
    enabled = Yes
    listen_ip = 0.0.0.0
    listen_port = 4242
"#;
    let config = parse(input).unwrap();
    assert_eq!(config.interfaces.len(), 1);
    let iface = &config.interfaces[0];
    assert_eq!(iface.name, "TCP Server");
    assert_eq!(iface.interface_type, "TCPServerInterface");
    assert_eq!(iface.params.get("listen_ip").unwrap(), "0.0.0.0");
    assert_eq!(iface.params.get("listen_port").unwrap(), "4242");
}

#[test]
fn parse_interface_udp() {
    let input = r#"
[interfaces]
  [[UDP Interface]]
    type = UDPInterface
    enabled = Yes
    listen_ip = 0.0.0.0
    listen_port = 4242
    forward_ip = 255.255.255.255
    forward_port = 4242
"#;
    let config = parse(input).unwrap();
    assert_eq!(config.interfaces.len(), 1);
    let iface = &config.interfaces[0];
    assert_eq!(iface.name, "UDP Interface");
    assert_eq!(iface.interface_type, "UDPInterface");
    assert_eq!(iface.params.get("listen_ip").unwrap(), "0.0.0.0");
    assert_eq!(iface.params.get("forward_ip").unwrap(), "255.255.255.255");
}

#[test]
fn parse_multiple_interfaces() {
    let input = r#"
[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    enabled = yes
    target_host = 10.0.0.1
    target_port = 4242

  [[UDP Broadcast]]
    type = UDPInterface
    enabled = yes
    listen_ip = 0.0.0.0
    listen_port = 5555
    forward_ip = 255.255.255.255
    forward_port = 5555
"#;
    let config = parse(input).unwrap();
    assert_eq!(config.interfaces.len(), 2);
    assert_eq!(config.interfaces[0].name, "TCP Client");
    assert_eq!(config.interfaces[0].interface_type, "TCPClientInterface");
    assert_eq!(config.interfaces[1].name, "UDP Broadcast");
    assert_eq!(config.interfaces[1].interface_type, "UDPInterface");
}

#[test]
fn parse_third_level_interface_sections() {
    let config = parse(
            "[interfaces]\n[[radio]]\n  type = RNodeMultiInterface\n  port = /dev/ttyUSB0\n  [[[fast]]]\n    enabled = yes\n    vport = 7\n    frequency = 915000000\n  [[[disabled]]]\n    enabled = no\n    vport = 2\n",
        )
        .unwrap();
    assert_eq!(config.interfaces.len(), 1);
    let interface = &config.interfaces[0];
    assert_eq!(interface.params["port"], "/dev/ttyUSB0");
    assert_eq!(interface.subinterfaces.len(), 2);
    assert_eq!(interface.subinterfaces[0].name, "fast");
    assert_eq!(interface.subinterfaces[0].params["vport"], "7");
}

#[test]
fn parse_booleans() {
    // Test all boolean variants
    for (input, expected) in &[
        ("Yes", true),
        ("No", false),
        ("True", true),
        ("False", false),
        ("true", true),
        ("false", false),
        ("1", true),
        ("0", false),
        ("on", true),
        ("off", false),
    ] {
        let result = parse_bool(input);
        assert_eq!(result, Some(*expected), "parse_bool({}) failed", input);
    }
}

#[test]
fn parse_comments() {
    let input = r#"
# This is a comment
[reticulum]
enable_transport = True  # inline comment
# share_instance = No
instance_name = test
"#;
    let config = parse(input).unwrap();
    assert!(config.reticulum.enable_transport);
    assert!(config.reticulum.share_instance); // commented out line should be ignored
    assert_eq!(config.reticulum.instance_name, "test");
}

#[test]
fn parse_interface_mode_field() {
    let input = r#"
[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    enabled = yes
    interface_mode = access_point
    target_host = 10.0.0.1
    target_port = 4242
"#;
    let config = parse(input).unwrap();
    assert_eq!(config.interfaces[0].mode, "access_point");
}

#[test]
fn parse_mode_fallback() {
    // Python also accepts "mode" as fallback for "interface_mode"
    let input = r#"
[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    enabled = yes
    mode = gateway
    target_host = 10.0.0.1
    target_port = 4242
"#;
    let config = parse(input).unwrap();
    assert_eq!(config.interfaces[0].mode, "gateway");
}

#[test]
fn parse_interface_mode_takes_precedence() {
    // If both interface_mode and mode are set, interface_mode wins
    let input = r#"
[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    enabled = yes
    interface_mode = roaming
    mode = boundary
    target_host = 10.0.0.1
    target_port = 4242
"#;
    let config = parse(input).unwrap();
    assert_eq!(config.interfaces[0].mode, "roaming");
}

#[test]
fn parse_disabled_interface() {
    let input = r#"
[interfaces]
  [[Disabled TCP]]
    type = TCPClientInterface
    enabled = No
    target_host = 10.0.0.1
    target_port = 4242
"#;
    let config = parse(input).unwrap();
    assert_eq!(config.interfaces.len(), 1);
    assert!(!config.interfaces[0].enabled);
}

#[test]
fn parse_serial_interface() {
    let input = r#"
[interfaces]
  [[Serial Port]]
    type = SerialInterface
    enabled = Yes
    port = /dev/ttyUSB0
    speed = 115200
    databits = 8
    parity = N
    stopbits = 1
"#;
    let config = parse(input).unwrap();
    assert_eq!(config.interfaces.len(), 1);
    let iface = &config.interfaces[0];
    assert_eq!(iface.name, "Serial Port");
    assert_eq!(iface.interface_type, "SerialInterface");
    assert!(iface.enabled);
    assert_eq!(iface.params.get("port").unwrap(), "/dev/ttyUSB0");
    assert_eq!(iface.params.get("speed").unwrap(), "115200");
    assert_eq!(iface.params.get("databits").unwrap(), "8");
    assert_eq!(iface.params.get("parity").unwrap(), "N");
    assert_eq!(iface.params.get("stopbits").unwrap(), "1");
}

#[test]
fn parse_kiss_interface() {
    let input = r#"
[interfaces]
  [[KISS TNC]]
    type = KISSInterface
    enabled = Yes
    port = /dev/ttyUSB1
    speed = 9600
    preamble = 350
    txtail = 20
    persistence = 64
    slottime = 20
    flow_control = True
    id_interval = 600
    id_callsign = MYCALL
"#;
    let config = parse(input).unwrap();
    assert_eq!(config.interfaces.len(), 1);
    let iface = &config.interfaces[0];
    assert_eq!(iface.name, "KISS TNC");
    assert_eq!(iface.interface_type, "KISSInterface");
    assert_eq!(iface.params.get("port").unwrap(), "/dev/ttyUSB1");
    assert_eq!(iface.params.get("speed").unwrap(), "9600");
    assert_eq!(iface.params.get("preamble").unwrap(), "350");
    assert_eq!(iface.params.get("txtail").unwrap(), "20");
    assert_eq!(iface.params.get("persistence").unwrap(), "64");
    assert_eq!(iface.params.get("slottime").unwrap(), "20");
    assert_eq!(iface.params.get("flow_control").unwrap(), "True");
    assert_eq!(iface.params.get("id_interval").unwrap(), "600");
    assert_eq!(iface.params.get("id_callsign").unwrap(), "MYCALL");
}

#[test]
fn parse_ifac_networkname() {
    let input = r#"
[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    enabled = yes
    target_host = 10.0.0.1
    target_port = 4242
    networkname = testnet
"#;
    let config = parse(input).unwrap();
    assert_eq!(
        config.interfaces[0].params.get("networkname").unwrap(),
        "testnet"
    );
}

#[test]
fn parse_ifac_passphrase() {
    let input = r#"
[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    enabled = yes
    target_host = 10.0.0.1
    target_port = 4242
    passphrase = secret123
    ifac_size = 64
"#;
    let config = parse(input).unwrap();
    assert_eq!(
        config.interfaces[0].params.get("passphrase").unwrap(),
        "secret123"
    );
    assert_eq!(config.interfaces[0].params.get("ifac_size").unwrap(), "64");
}

#[test]
fn parse_remote_management_config() {
    let input = r#"
[reticulum]
enable_transport = True
enable_remote_management = Yes
remote_management_allowed = aabbccdd00112233aabbccdd00112233, 11223344556677881122334455667788
publish_blackhole = Yes
"#;
    let config = parse(input).unwrap();
    assert!(config.reticulum.enable_remote_management);
    assert!(config.reticulum.publish_blackhole);
    assert_eq!(config.reticulum.remote_management_allowed.len(), 2);
    assert_eq!(
        config.reticulum.remote_management_allowed[0],
        "aabbccdd00112233aabbccdd00112233"
    );
    assert_eq!(
        config.reticulum.remote_management_allowed[1],
        "11223344556677881122334455667788"
    );
}

#[test]
fn parse_blackhole_sources_and_update_interval() {
    let config = parse(
            "[reticulum]\n\
             blackhole_sources = aabbccdd00112233aabbccdd00112233, 11223344556677881122334455667788, aabbccdd00112233aabbccdd00112233\n\
             blackhole_update_interval = 90\n",
        )
        .unwrap();
    // Duplicates are listed once, as upstream does.
    assert_eq!(
        config.reticulum.blackhole_sources,
        vec![
            [
                0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x11,
                0x22, 0x33
            ],
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                0x77, 0x88
            ],
        ]
    );
    // Minutes, stored as seconds.
    assert_eq!(config.reticulum.blackhole_update_interval, Some(5400.0));

    // Upstream raises an interval under two minutes to two.
    let config = parse("[reticulum]\nblackhole_update_interval = 0.5\n").unwrap();
    assert_eq!(config.reticulum.blackhole_update_interval, Some(120.0));

    let config =
        parse("[reticulum]\ninterface_discovery_sources = 521c87a83afb8f29e4455e77930b973b\n")
            .unwrap();
    assert_eq!(config.reticulum.interface_discovery_sources.len(), 1);
    assert_eq!(config.reticulum.interface_discovery_sources[0][0], 0x52);
    assert!(parse("[reticulum]\ninterface_discovery_sources = 52\n").is_err());

    let defaults = parse("[reticulum]\n").unwrap();
    assert!(defaults.reticulum.blackhole_sources.is_empty());
    assert!(defaults.reticulum.interface_discovery_sources.is_empty());
    assert_eq!(defaults.reticulum.blackhole_update_interval, None);

    // A hash of the wrong length, as upstream, is a config error.
    assert!(parse("[reticulum]\nblackhole_sources = aabbccdd\n").is_err());
    assert!(parse("[reticulum]\nblackhole_update_interval = soon\n").is_err());
}

#[test]
fn parse_shared_instance_type_rpc_key_and_forced_bitrate() {
    let defaults = parse("[reticulum]\n").unwrap().reticulum;
    assert!(!defaults.shared_instance_tcp);
    assert_eq!(defaults.rpc_key, None);
    assert_eq!(defaults.force_shared_instance_bitrate, None);

    let config = parse(
        "[reticulum]\nshared_instance_type = TCP\nforce_shared_instance_bitrate = 9600\n\
             rpc_key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n",
    )
    .unwrap()
    .reticulum;
    assert!(config.shared_instance_tcp);
    assert_eq!(config.force_shared_instance_bitrate, Some(9600));
    let key = config.rpc_key.unwrap();
    assert_eq!(key[0], 0x00);
    assert_eq!(key[31], 0xff);

    // Unknown types are ignored, as upstream does.
    assert!(
        !parse("[reticulum]\nshared_instance_type = pipe\n")
            .unwrap()
            .reticulum
            .shared_instance_tcp
    );
    // A short key is the same HMAC key padded with zeros.
    let short = parse("[reticulum]\nrpc_key = abcd\n")
        .unwrap()
        .reticulum
        .rpc_key
        .unwrap();
    assert_eq!(&short[..2], &[0xab, 0xcd]);
    assert!(short[2..].iter().all(|b| *b == 0));
    // Invalid or overlong keys fall back to the default key.
    for invalid in ["zz", "abc", &"ab".repeat(33)] {
        let config = parse(&format!("[reticulum]\nrpc_key = {invalid}\n")).unwrap();
        assert_eq!(config.reticulum.rpc_key, None, "{invalid}");
    }
    assert!(parse("[reticulum]\nforce_shared_instance_bitrate = fast\n").is_err());
}

#[test]
fn parse_autoconnect_policy_and_count() {
    let defaults = parse("[reticulum]\n").unwrap().reticulum;
    assert_eq!(defaults.autoconnect_policy, AutoconnectPolicy::Upstream);
    assert_eq!(defaults.autoconnect_discovered_interfaces, 0);

    let config =
        parse("[reticulum]\nautoconnect_policy = Pool\nautoconnect_discovered_interfaces = 4\n")
            .unwrap()
            .reticulum;
    assert_eq!(config.autoconnect_policy, AutoconnectPolicy::Pool);
    assert_eq!(config.autoconnect_discovered_interfaces, 4);

    // Upstream only auto-connects with a count above zero.
    let config = parse("[reticulum]\nautoconnect_discovered_interfaces = -2\n").unwrap();
    assert_eq!(config.reticulum.autoconnect_discovered_interfaces, 0);
    assert!(parse("[reticulum]\nautoconnect_policy = mesh\n").is_err());
    assert!(parse("[reticulum]\nautoconnect_discovered_interfaces = some\n").is_err());
}

// Upstream aecc1547 reads `[reticulum]` options in file order, so the
// disable key only lifts the caps when it comes before the count.
#[test]
fn autoconnect_caps_are_disabled_only_by_a_key_before_the_count() {
    let caps_disabled = |text: &str| {
        parse(text)
            .unwrap()
            .reticulum
            .autoconnect_discovered_interfaces_caps_disabled
    };
    assert!(!caps_disabled(
        "[reticulum]\nautoconnect_discovered_interfaces = 20\n"
    ));
    assert!(caps_disabled(
        "[reticulum]\nautoconnect_discovered_interfaces_disable_caps = yes\nautoconnect_discovered_interfaces = 20\n"
    ));
    assert!(!caps_disabled(
        "[reticulum]\nautoconnect_discovered_interfaces = 20\nautoconnect_discovered_interfaces_disable_caps = yes\n"
    ));
    assert!(!caps_disabled(
        "[reticulum]\nautoconnect_discovered_interfaces_disable_caps = no\nautoconnect_discovered_interfaces = 20\n"
    ));
    let config = parse(
        "[reticulum]\nautoconnect_discovered_interfaces_disable_caps = yes\nautoconnect_discovered_interfaces = 20\n",
    )
    .unwrap();
    assert_eq!(config.reticulum.autoconnect_discovered_interfaces, 20);
    assert!(
        parse("[reticulum]\nautoconnect_discovered_interfaces_disable_caps = maybe\n").is_err()
    );
}

#[test]
fn parse_remote_management_defaults() {
    let input = "[reticulum]\n";
    let config = parse(input).unwrap();
    assert!(!config.reticulum.enable_remote_management);
    assert!(!config.reticulum.publish_blackhole);
    assert!(config.reticulum.remote_management_allowed.is_empty());
}

#[test]
fn parse_hooks_section() {
    let input = r#"
[hooks]
  [[drop_tick]]
    path = /tmp/drop_tick.wasm
    attach_point = Tick
    priority = 10
    enabled = Yes

  [[log_announce]]
    path = /tmp/log_announce.wasm
    type = native
    attach_point = AnnounceReceived
    priority = 5
    enabled = No

  [[builtin_tick]]
    builtin = example.tick
    type = builtin
    attach_point = Tick
"#;
    let config = parse(input).unwrap();
    assert_eq!(config.hooks.len(), 3);
    assert_eq!(config.hooks[0].name, "drop_tick");
    assert_eq!(config.hooks[0].path, "/tmp/drop_tick.wasm");
    assert_eq!(config.hooks[0].hook_type, default_hook_type());
    assert_eq!(config.hooks[0].attach_point, "Tick");
    assert_eq!(config.hooks[0].priority, 10);
    assert!(config.hooks[0].enabled);
    assert_eq!(config.hooks[1].name, "log_announce");
    assert_eq!(config.hooks[1].hook_type, "native");
    assert_eq!(config.hooks[1].attach_point, "AnnounceReceived");
    assert!(!config.hooks[1].enabled);
    assert_eq!(config.hooks[2].hook_type, "builtin");
    assert_eq!(config.hooks[2].builtin_id.as_deref(), Some("example.tick"));
}

#[test]
fn parse_empty_hooks() {
    let input = "[hooks]\n";
    let config = parse(input).unwrap();
    assert!(config.hooks.is_empty());
}

#[test]
fn parse_hook_point_names() {
    assert_eq!(parse_hook_point("PreIngress"), Some(0));
    assert_eq!(parse_hook_point("PreDispatch"), Some(1));
    assert_eq!(parse_hook_point("AnnounceReceived"), Some(2));
    assert_eq!(parse_hook_point("PathUpdated"), Some(3));
    assert_eq!(parse_hook_point("AnnounceRetransmit"), Some(4));
    assert_eq!(parse_hook_point("LinkRequestReceived"), Some(5));
    assert_eq!(parse_hook_point("LinkEstablished"), Some(6));
    assert_eq!(parse_hook_point("LinkClosed"), Some(7));
    assert_eq!(parse_hook_point("InterfaceUp"), Some(8));
    assert_eq!(parse_hook_point("InterfaceDown"), Some(9));
    assert_eq!(parse_hook_point("InterfaceConfigChanged"), Some(10));
    assert_eq!(parse_hook_point("BackbonePeerConnected"), Some(11));
    assert_eq!(parse_hook_point("BackbonePeerDisconnected"), Some(12));
    assert_eq!(parse_hook_point("BackbonePeerIdleTimeout"), Some(13));
    assert_eq!(parse_hook_point("BackbonePeerWriteStall"), Some(14));
    assert_eq!(parse_hook_point("BackbonePeerPenalty"), Some(15));
    assert_eq!(parse_hook_point("SendOnInterface"), Some(16));
    assert_eq!(parse_hook_point("BroadcastOnAllInterfaces"), Some(17));
    assert_eq!(parse_hook_point("DeliverLocal"), Some(18));
    assert_eq!(parse_hook_point("TunnelSynthesize"), Some(19));
    assert_eq!(parse_hook_point("Tick"), Some(20));
    assert_eq!(parse_hook_point("Unknown"), None);
}

#[test]
fn backbone_extra_params_preserved() {
    let config = r#"
[reticulum]
enable_transport = True

[interfaces]
  [[Public Entrypoint]]
    type = BackboneInterface
    enabled = yes
    listen_ip = 0.0.0.0
    listen_port = 4242
    interface_mode = gateway
    discoverable = Yes
    discovery_name = PizzaSpaghettiMandolino
    announce_interval = 600
    discovery_stamp_value = 24
    reachable_on = 87.106.8.245
"#;
    let parsed = parse(config).unwrap();
    assert_eq!(parsed.interfaces.len(), 1);
    let iface = &parsed.interfaces[0];
    assert_eq!(iface.name, "Public Entrypoint");
    assert_eq!(iface.interface_type, "BackboneInterface");
    // After removing type, enabled, interface_mode, remaining params should include discovery keys
    assert_eq!(
        iface.params.get("discoverable").map(|s| s.as_str()),
        Some("Yes")
    );
    assert_eq!(
        iface.params.get("discovery_name").map(|s| s.as_str()),
        Some("PizzaSpaghettiMandolino")
    );
    assert_eq!(
        iface.params.get("announce_interval").map(|s| s.as_str()),
        Some("600")
    );
    assert_eq!(
        iface
            .params
            .get("discovery_stamp_value")
            .map(|s| s.as_str()),
        Some("24")
    );
    assert_eq!(
        iface.params.get("reachable_on").map(|s| s.as_str()),
        Some("87.106.8.245")
    );
    assert_eq!(
        iface.params.get("listen_ip").map(|s| s.as_str()),
        Some("0.0.0.0")
    );
    assert_eq!(
        iface.params.get("listen_port").map(|s| s.as_str()),
        Some("4242")
    );
}

#[test]
fn parse_probe_protocol() {
    let input = r#"
[reticulum]
probe_addr = 1.2.3.4:19302
probe_protocol = stun
"#;
    let config = parse(input).unwrap();
    assert_eq!(
        config.reticulum.probe_addr.as_deref(),
        Some("1.2.3.4:19302")
    );
    assert_eq!(config.reticulum.probe_protocol.as_deref(), Some("stun"));
}

#[test]
fn parse_probe_protocol_defaults_to_none() {
    let input = r#"
[reticulum]
probe_addr = 1.2.3.4:4343
"#;
    let config = parse(input).unwrap();
    assert_eq!(config.reticulum.probe_addr.as_deref(), Some("1.2.3.4:4343"));
    assert!(config.reticulum.probe_protocol.is_none());
}

#[test]
fn parse_direct_connect_policy() {
    let config = parse(
        r#"
[reticulum]
direct_connect_policy = identified_only
"#,
    )
    .unwrap();
    assert_eq!(
        config.reticulum.direct_connect_policy,
        crate::event::HolePunchPolicy::IdentifiedOnly
    );
}

#[test]
fn direct_connect_policy_defaults_to_reject_and_rejects_invalid() {
    let config = parse("[reticulum]\n").unwrap();
    assert_eq!(
        config.reticulum.direct_connect_policy,
        crate::event::HolePunchPolicy::Reject
    );
    assert!(config
        .reticulum
        .direct_connect_allowed_identities
        .is_empty());
    let config = parse("[reticulum]\ndirect_connect_policy = accept_all\n").unwrap();
    assert_eq!(
        config.reticulum.direct_connect_policy,
        crate::event::HolePunchPolicy::AcceptAll
    );
    assert!(parse("[reticulum]\ndirect_connect_policy = sometimes\n").is_err());
}

#[test]
fn direct_connect_reupgrade_parses_and_defaults() {
    let config = parse("[reticulum]\n").unwrap();
    assert_eq!(
        config.reticulum.direct_connect_reupgrade,
        crate::event::DirectReupgradeConfig::default()
    );
    assert!(config.reticulum.direct_connect_reupgrade.enabled);
    let config = parse(
        "[reticulum]\ndirect_connect_reupgrade = no\n\
             direct_connect_reupgrade_attempts = 3\n\
             direct_connect_reupgrade_delay = 90\n\
             direct_connect_reupgrade_max_delay = 600.5\n",
    )
    .unwrap();
    let reupgrade = config.reticulum.direct_connect_reupgrade;
    assert!(!reupgrade.enabled);
    assert_eq!(reupgrade.max_attempts, 3);
    assert_eq!(reupgrade.initial_delay, std::time::Duration::from_secs(90));
    assert_eq!(
        reupgrade.max_delay,
        std::time::Duration::from_secs_f64(600.5)
    );
    for bad in [
        "direct_connect_reupgrade = maybe",
        "direct_connect_reupgrade_attempts = -1",
        "direct_connect_reupgrade_delay = soon",
        "direct_connect_reupgrade_max_delay = -5",
        "direct_connect_reupgrade_max_delay = inf",
    ] {
        assert!(parse(&format!("[reticulum]\n{bad}\n")).is_err(), "{bad}");
    }
}

#[test]
fn probe_rate_limits_parse_and_default() {
    let config = parse("[reticulum]\nprobe_port = 4343\n").unwrap();
    assert_eq!(
        config.reticulum.probe_rate_limit,
        crate::event::ProbeRateLimit::default()
    );
    let config = parse(
        "[reticulum]\nprobe_source_rate = 0.5\nprobe_source_burst = 4\n\
             probe_total_rate = 0\n",
    )
    .unwrap();
    let limit = config.reticulum.probe_rate_limit;
    assert_eq!(limit.per_source_rate, 0.5);
    assert_eq!(limit.per_source_burst, 4);
    assert_eq!(limit.total_rate, 0);
    for bad in [
        "probe_source_rate = -1",
        "probe_source_rate = nan",
        "probe_source_burst = 0",
        "probe_total_rate = lots",
    ] {
        assert!(parse(&format!("[reticulum]\n{bad}\n")).is_err(), "{bad}");
    }
}

#[test]
fn direct_connect_allowed_identities_parse_as_a_list() {
    let config = parse(
        "[reticulum]\ndirect_connect_allowed_identities = \
             00112233445566778899aabbccddeeff, ffeeddccbbaa99887766554433221100,\
             00112233445566778899aabbccddeeff\n",
    )
    .unwrap();
    assert_eq!(
        config.reticulum.direct_connect_allowed_identities,
        vec![
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ],
            [
                0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
                0x11, 0x00
            ],
        ]
    );
    assert!(parse("[reticulum]\ndirect_connect_allowed_identities = 0011\n").is_err());
    assert!(parse(
        "[reticulum]\ndirect_connect_allowed_identities = zz112233445566778899aabbccddeeff\n"
    )
    .is_err());
}

#[test]
fn direct_connect_allow_private_endpoints_parses_and_defaults_false() {
    let config = parse("[reticulum]\n").unwrap();
    assert!(!config.reticulum.direct_connect_allow_private_endpoints);
    let config = parse("[reticulum]\ndirect_connect_allow_private_endpoints = yes\n").unwrap();
    assert!(config.reticulum.direct_connect_allow_private_endpoints);
    let config = parse("[reticulum]\ndirect_connect_allow_private_endpoints = False\n").unwrap();
    assert!(!config.reticulum.direct_connect_allow_private_endpoints);
    assert!(parse("[reticulum]\ndirect_connect_allow_private_endpoints = maybe\n").is_err());
}

#[test]
fn link_mtu_discovery_defaults_true_and_honors_both_boolean_values() {
    assert!(parse_link_mtu_discovery("").unwrap());
    assert!(parse_link_mtu_discovery("[reticulum]\nlink_mtu_discovery = Yes\n").unwrap());
    assert!(!parse_link_mtu_discovery("[reticulum]\nlink_mtu_discovery = False\n").unwrap());
    assert!(parse_link_mtu_discovery("[logging]\nlink_mtu_discovery = No\n").unwrap());
    assert!(parse_link_mtu_discovery("[reticulum]\nlink_mtu_discovery = maybe\n").is_err());
}

#[test]
fn filter_section_defaults_to_no_filtering() {
    let config = parse("").unwrap();
    assert_eq!(config.filter, FilterSection::default());
    assert!(!config.filter.required_only);
}

#[test]
fn filter_section_takes_name_hashes_in_brackets() {
    // Upstream e96c81c3: a destination type can be a `<hex>` name hash.
    use rns_core::transport::destination_filter::destination_type;
    let node = destination_type("nomadnetwork.node");
    let hex: String = node.iter().map(|b| format!("{b:02x}")).collect();
    let config = parse(&format!(
        "[filter]\nrequired_only = Yes\nignored_types = <{hex}>\nallowed_types = <{}>\n",
        destination_type("lxmf.delivery")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
    .unwrap();
    let filter = config.filter.destination_filter();
    assert!(filter.blocks(&node));
    assert!(filter.allows(&destination_type("lxmf.delivery"), false));
    assert!(!filter.allows(&destination_type("rncp.receive"), false));
}

#[test]
fn filter_section_parses_every_option() {
    let config = parse(
        "[filter]\n\
             required_only = Yes\n\
             ignored_types = nomadnetwork.node, lxmf.propagation\n\
             allowed_types = lxmf.delivery\n",
    )
    .unwrap();
    assert_eq!(
        config.filter,
        FilterSection {
            required_only: true,
            ignored_types: vec!["nomadnetwork.node".into(), "lxmf.propagation".into()],
            allowed_types: vec!["lxmf.delivery".into()],
        }
    );

    use rns_core::transport::destination_filter::destination_type;
    let filter = config.filter.destination_filter();
    assert!(filter.required_only());
    assert!(!filter.allows(&destination_type("nomadnetwork.node"), true));
    assert!(filter.allows(&destination_type("lxmf.delivery"), false));
    assert!(!filter.allows(&destination_type("rncp.receive"), false));
}

#[test]
fn interface_options_are_converted_as_upstream_converts_them() {
    // Upstream's as_int, as_float and as_bool raise on a value they
    // cannot convert, and the interface is not created; the instance
    // stops. Disabled sections are converted too.
    let section = |options: &str| {
        parse(&format!(
            "[interfaces]\n  [[Iface]]\n    type = TCPClientInterface\n{options}"
        ))
    };
    let refused = |options: &str| match section(options) {
        Err(ConfigError::Parse(message)) => message,
        other => panic!("{options:?} should be refused, got {other:?}"),
    };
    assert!(section("    enabled = yes\n    gravity = -3\n    announce_cap = 2.5\n").is_ok());
    assert_eq!(
        refused("    enabled = yes\n    gravity = high\n"),
        "The interface \"Iface\" could not be created. Check your configuration file for \
             errors! The contained exception was: invalid literal for int() with base 10: 'high'"
    );
    assert!(refused("    enabled = no\n    hop_limiter = 2.5\n").contains("int()"));
    assert!(refused("    enabled = yes\n    pr_cost = cheap\n").contains("float: 'cheap'"));
    assert!(refused("    enabled = yes\n    recursive_prs = maybe\n")
        .contains("Value \"maybe\" is neither True nor False"));

    // Discovery options are only converted on a discoverable interface.
    assert!(section("    enabled = yes\n    announce_interval = soon\n").is_ok());
    assert!(
        refused("    enabled = yes\n    discoverable = yes\n    announce_interval = soon\n")
            .contains("'soon'")
    );

    // `enabled` is only converted when `interface_enabled` did not
    // enable the interface, and `outgoing` only on an enabled one.
    assert!(section("    interface_enabled = yes\n    enabled = perhaps\n").is_ok());
    assert!(refused("    interface_enabled = no\n    enabled = perhaps\n").contains("perhaps"));
    assert!(section("    enabled = no\n    outgoing = sometimes\n").is_ok());
    assert!(refused("    enabled = yes\n    outgoing = sometimes\n").contains("sometimes"));
}

#[test]
fn filter_section_rejects_an_invalid_boolean() {
    assert!(parse("[filter]\nrequired_only = maybe\n").is_err());
}

#[test]
fn stamps_section_defaults_to_the_protocol_constants() {
    use rns_core::constants;
    let config = parse("").unwrap();
    assert_eq!(config.stamps, StampsSection::default());
    let stamps = config.stamps;
    let flags = [
        stamps.stamps_enforced,
        stamps.lr_stamps_enforced,
        stamps.always_stamp_lrs,
    ];
    assert_eq!(flags, [false; 3]);
    // 51fa8413: announces and path requests are stamped by default.
    assert!(stamps.stamp_destinations);
    assert!(stamps.stamp_prs);
    // a8cc6cb2: link requests are stamped when a cost is announced.
    assert!(stamps.stamp_lrs);
    assert_eq!(stamps.destination_cost, constants::DESTINATION_STAMP_COST);
    assert_eq!(stamps.destination_value, StampCost::from_whole(25));
    assert_eq!(stamps.pr_cost, constants::PATH_REQUEST_STAMP_COST);
    assert_eq!(stamps.pr_value, constants::PATH_REQUEST_STAMP_VALUE);
    assert_eq!(stamps.lr_cost, constants::LINK_REQUEST_STAMP_COST);
    assert_eq!(
        stamps.link_stamp_timeout(),
        std::time::Duration::from_secs(15)
    );
    assert_eq!(
        stamps.path_request_stamp_timeout(),
        std::time::Duration::from_secs(15)
    );
    assert_eq!(config.reticulum.hop_limiter, constants::PATHFINDER_M);
}

#[test]
fn stamps_section_parses_every_option() {
    let config = parse(
        "[stamps]\n\
             enforce_stamps = yes\n\
             stamp_destinations = Yes\n\
             stamp_prs = true\n\
             always_stamp_lrs = on\n\
             destination_cost = 20\n\
             destination_value = 30\n\
             pr_cost = 12\n\
             pr_value = 14\n\
             lr_cost = 9\n\
             lr_stamp_timeout = 2.5\n\
             pr_stamp_timeout = 7\n",
    )
    .unwrap();
    let stamps = config.stamps;
    // `enforce_stamps` sets both STAMPS_ENFORCED and LR_STAMPS_ENFORCED.
    assert!(stamps.stamps_enforced);
    assert!(stamps.lr_stamps_enforced);
    assert!(stamps.stamp_destinations);
    assert!(stamps.stamp_prs);
    assert!(stamps.always_stamp_lrs);
    assert_eq!(stamps.destination_cost, StampCost::from_whole(20));
    assert_eq!(stamps.destination_value, StampCost::from_whole(30));
    assert_eq!(stamps.pr_cost, StampCost::from_whole(12));
    assert_eq!(stamps.pr_value, StampCost::from_whole(14));
    assert_eq!(stamps.lr_cost, StampCost::from_whole(9));
    assert_eq!(
        stamps.link_stamp_timeout(),
        std::time::Duration::from_millis(2500)
    );
    assert_eq!(
        stamps.path_request_stamp_timeout(),
        std::time::Duration::from_secs(7)
    );
}

#[test]
fn stamps_section_booleans_can_only_enable() {
    // Reticulum.py applies each option as `if value == True: X = True`,
    // so `no` keeps the built-in default instead of forcing it off.
    let config = parse(
        "[stamps]\n\
             enforce_stamps = no\n\
             stamp_destinations = False\n\
             stamp_prs = off\n\
             always_stamp_lrs = 0\n",
    )
    .unwrap();
    assert_eq!(config.stamps, StampsSection::default());
    assert!(parse("[stamps]\nstamp_prs = maybe\n").is_err());
    assert!(parse("[stamps]\nenforce_stamps = 2\n").is_err());
}

#[test]
fn stamps_section_ignores_the_removed_stamp_lrs_option() {
    // a8cc6cb2 dropped `stamp_lrs`; `no` no longer turns stamping off.
    let config = parse("[stamps]\nstamp_lrs = no\n").unwrap();
    assert_eq!(config.stamps, StampsSection::default());
    assert!(config.stamps.stamp_lrs);
}

#[test]
fn stamps_section_costs_are_fractional() {
    // Reticulum.py reads them with `as_float` since 796ef2d4.
    let config = parse(
        "[stamps]\n\
             destination_cost = 23.5\n\
             pr_value = 15.8\n\
             lr_cost = 12\n\
             pr_cost = inf\n\
             destination_value = nan\n",
    )
    .unwrap();
    let stamps = config.stamps;
    assert_eq!(stamps.destination_cost, StampCost::from_fp(6016));
    assert_eq!(stamps.pr_value, StampCost::from_f64(15.8));
    assert_eq!(stamps.lr_cost, StampCost::from_whole(12));
    // `max(0, min(v, cap))` in Python: infinity clamps to the cap, NaN to 0.
    assert_eq!(stamps.pr_cost, StampCost::from_whole(100));
    assert_eq!(stamps.destination_value, StampCost::ZERO);
    assert!(parse("[stamps]\npr_cost = high\n").is_err());
}

#[test]
fn stamps_section_clamps_costs_and_timeouts() {
    use rns_core::constants;
    let config = parse(
        "[stamps]\n\
             destination_cost = 500\n\
             destination_value = -3\n\
             pr_cost = 101\n\
             pr_value = 99999999999999999999999\n\
             lr_cost = 41\n\
             lr_stamp_timeout = 0\n\
             pr_stamp_timeout = -10\n",
    )
    .unwrap();
    let stamps = config.stamps;
    let cap = StampCost::from_whole(u32::from(constants::STAMP_COST_CAP));
    assert_eq!(stamps.destination_cost, cap);
    assert_eq!(stamps.destination_value, StampCost::ZERO);
    assert_eq!(stamps.pr_cost, cap);
    assert_eq!(stamps.pr_value, cap);
    // `lr_cost` has its own, lower cap.
    assert_eq!(
        stamps.lr_cost,
        StampCost::from_whole(u32::from(constants::LINK_COST_CAP))
    );
    assert_eq!(
        stamps.link_stamp_timeout(),
        std::time::Duration::from_millis(20)
    );
    assert_eq!(
        stamps.path_request_stamp_timeout(),
        std::time::Duration::from_millis(20)
    );

    let config = parse("[stamps]\nlr_cost = -1\npr_stamp_timeout = nan\n").unwrap();
    assert_eq!(config.stamps.lr_cost, StampCost::ZERO);
    assert_eq!(
        config.stamps.path_request_stamp_timeout(),
        std::time::Duration::from_millis(20)
    );
    let config = parse("[stamps]\nlr_stamp_timeout = inf\n").unwrap();
    assert_eq!(config.stamps.link_stamp_timeout(), std::time::Duration::MAX);

    // `as_float` rejects non-numbers.
    assert!(parse("[stamps]\npr_cost = lots\n").is_err());
    assert!(parse("[stamps]\npr_stamp_timeout = soon\n").is_err());
}

#[test]
fn stamps_section_parses_worker_limits() {
    let defaults = parse("[stamps]\n").unwrap().stamps;
    assert_eq!(defaults.max_workers, None);
    assert_eq!(defaults.worker_niceness, 16);

    let stamps = parse("[stamps]\nmax_workers = 3\nworker_niceness = 5\n")
        .unwrap()
        .stamps;
    assert_eq!(stamps.max_workers, Some(3));
    assert_eq!(stamps.worker_niceness, 5);

    // Upstream clamps both: at least one worker, niceness 0 to 20.
    let stamps = parse("[stamps]\nmax_workers = 0\nworker_niceness = 40\n")
        .unwrap()
        .stamps;
    assert_eq!(stamps.max_workers, Some(1));
    assert_eq!(stamps.worker_niceness, 20);
    let stamps = parse("[stamps]\nworker_niceness = -5\n").unwrap().stamps;
    assert_eq!(stamps.worker_niceness, 0);

    assert!(parse("[stamps]\nmax_workers = many\n").is_err());
}

#[test]
fn stamps_options_outside_the_stamps_section_are_ignored() {
    let config = parse("[reticulum]\nstamp_prs = yes\ndestination_cost = 5\n").unwrap();
    assert_eq!(config.stamps, StampsSection::default());
}

#[test]
fn hop_limiter_is_read_from_the_filter_section() {
    // Reticulum.py since 01aef5bc: `[filter] hop_limiter`, clamped with
    // `max(0, min(as_int(v), PATHFINDER_M))`; `[reticulum]` no longer
    // sets it.
    use rns_core::constants::PATHFINDER_M;
    let limiter = |value: &str| {
        parse(&format!("[filter]\nhop_limiter = {value}\n"))
            .unwrap()
            .reticulum
            .hop_limiter
    };
    assert_eq!(limiter("16"), 16);
    assert_eq!(limiter("1"), 1);
    assert_eq!(limiter("0"), 0);
    assert_eq!(limiter("-5"), 0);
    assert_eq!(limiter("128"), PATHFINDER_M);
    assert_eq!(limiter("1000"), PATHFINDER_M);
    assert!(parse("[filter]\nhop_limiter = many\n").is_err());
    assert!(parse("[filter]\nhop_limiter = 4.5\n").is_err());

    let legacy = parse("[reticulum]\nhop_limiter = 16\n").unwrap();
    assert_eq!(legacy.reticulum.hop_limiter, PATHFINDER_M);
    assert!(parse("[reticulum]\nhop_limiter = many\n").is_ok());
    let both = parse("[reticulum]\nhop_limiter = 9\n[filter]\nhop_limiter = 14\n").unwrap();
    assert_eq!(both.reticulum.hop_limiter, 14);
}
