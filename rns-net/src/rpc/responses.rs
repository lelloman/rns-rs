//! The other answers, as upstream's RPC responses, and known
//! destinations both ways.

use super::*;

pub(super) fn link_distribution_to_pickle(entries: &[LinkDistributionEntry]) -> PickleValue {
    let mut dict = Vec::with_capacity(entries.len());
    for entry in entries {
        dict.push((
            PickleValue::Bytes(entry.destination_hash.to_vec()),
            PickleValue::Dict(vec![
                (
                    PickleValue::String("total".into()),
                    PickleValue::Int(entry.total as i64),
                ),
                (
                    PickleValue::String("active".into()),
                    PickleValue::Int(entry.active as i64),
                ),
            ]),
        ));
    }
    PickleValue::Dict(dict)
}

/// Upstream's `get_path_table()` entries, keys in its order.
pub(super) fn path_table_to_pickle(entries: &[PathTableEntry]) -> PickleValue {
    let list: Vec<PickleValue> = entries
        .iter()
        .map(|e| {
            let key = |k: &str| PickleValue::String(k.into());
            PickleValue::Dict(vec![
                (key("hash"), PickleValue::Bytes(e.hash.to_vec())),
                (key("timestamp"), PickleValue::Float(e.timestamp)),
                (key("via"), PickleValue::Bytes(e.via.to_vec())),
                (key("hops"), PickleValue::Int(e.hops as i64)),
                (key("expires"), PickleValue::Float(e.expires)),
                // Upstream 21170877: the known destination's stamp value and
                // link request cost, None when it is not a known destination
                // (or announced no cost). rnpath reads both unconditionally.
                // Upstream remembers a destination without a stamp with
                // the int 0, and a path never used with the int 0.
                (
                    key("value"),
                    match e.stamp_value {
                        None => PickleValue::None,
                        Some(value) if value == rns_core::stamp::StampValue::ZERO => {
                            PickleValue::Int(0)
                        }
                        Some(value) => PickleValue::Float(value.as_f64()),
                    },
                ),
                (
                    key("used"),
                    if e.used == 0.0 {
                        PickleValue::Int(0)
                    } else {
                        PickleValue::Float(e.used)
                    },
                ),
                (
                    key("lr_cost"),
                    e.lr_cost
                        .map(|cost| PickleValue::Float(cost.as_f64()))
                        .unwrap_or(PickleValue::None),
                ),
                (
                    key("interface"),
                    PickleValue::String(e.interface_display_name.clone()),
                ),
            ])
        })
        .collect();
    PickleValue::List(list)
}

/// [`path_table_to_pickle`]'s entries as msgpack, for the remote
/// management `/path` handler.
pub(crate) fn path_table_msgpack(entries: &[PathTableEntry]) -> Vec<MsgpackValue> {
    match pickle_to_msgpack(&path_table_to_pickle(entries)) {
        MsgpackValue::Array(entries) => entries,
        _ => Vec::new(),
    }
}

/// [`rate_table_to_pickle`]'s entries as msgpack, for the remote
/// management `/path` handler.
pub(crate) fn rate_table_msgpack(entries: &[RateTableEntry]) -> Vec<MsgpackValue> {
    match pickle_to_msgpack(&rate_table_to_pickle(entries)) {
        MsgpackValue::Array(entries) => entries,
        _ => Vec::new(),
    }
}

/// Upstream's `get_rate_table()` entries: the announce rate table's dict
/// (`AnnounceRateTable.items()`) with `hash` added last.
pub(super) fn rate_table_to_pickle(entries: &[RateTableEntry]) -> PickleValue {
    let list: Vec<PickleValue> = entries
        .iter()
        .map(|e| {
            let key = |k: &str| PickleValue::String(k.into());
            PickleValue::Dict(vec![
                (key("last"), PickleValue::Float(e.last)),
                (
                    key("rate_violations"),
                    PickleValue::Int(e.rate_violations as i64),
                ),
                (key("blocked_until"), PickleValue::Float(e.blocked_until)),
                (
                    key("timestamps"),
                    PickleValue::List(
                        e.timestamps
                            .iter()
                            .map(|&t| PickleValue::Float(t))
                            .collect(),
                    ),
                ),
                (key("hash"), PickleValue::Bytes(e.hash.to_vec())),
            ])
        })
        .collect();
    PickleValue::List(list)
}

/// Upstream's `Transport.blackholed_identities`: identity hash to
/// `{"source", "until", "reason"}`, `until` nil for an entry that never
/// expires.
pub(super) fn blackholed_identities_to_pickle(entries: &[BlackholeInfo]) -> PickleValue {
    PickleValue::Dict(
        entries
            .iter()
            .map(|e| {
                (
                    PickleValue::Bytes(e.identity_hash.to_vec()),
                    PickleValue::Dict(vec![
                        (
                            PickleValue::String("source".into()),
                            e.source
                                .map_or(PickleValue::None, |s| PickleValue::Bytes(s.to_vec())),
                        ),
                        (
                            PickleValue::String("until".into()),
                            if e.expires == 0.0 {
                                PickleValue::None
                            } else {
                                PickleValue::Float(e.expires)
                            },
                        ),
                        (
                            PickleValue::String("reason".into()),
                            e.reason
                                .clone()
                                .map_or(PickleValue::None, PickleValue::String),
                        ),
                    ]),
                )
            })
            .collect(),
    )
}

pub(super) fn blackholed_to_pickle(entries: &[BlackholeInfo]) -> PickleValue {
    let list: Vec<PickleValue> = entries
        .iter()
        .map(|e| {
            let mut dict = vec![
                (
                    PickleValue::String("identity_hash".into()),
                    PickleValue::Bytes(e.identity_hash.to_vec()),
                ),
                (
                    PickleValue::String("created".into()),
                    PickleValue::Float(e.created),
                ),
                (
                    PickleValue::String("expires".into()),
                    PickleValue::Float(e.expires),
                ),
            ];
            if let Some(ref reason) = e.reason {
                dict.push((
                    PickleValue::String("reason".into()),
                    PickleValue::String(reason.clone()),
                ));
            } else {
                dict.push((PickleValue::String("reason".into()), PickleValue::None));
            }
            PickleValue::Dict(dict)
        })
        .collect();
    PickleValue::List(list)
}

/// Discovered interfaces as the `discovered_interfaces` RPC call returns them.
pub fn discovered_interfaces_to_pickle(
    interfaces: &[crate::discovery::DiscoveredInterface],
) -> PickleValue {
    let list: Vec<PickleValue> = interfaces
        .iter()
        .map(|iface| {
            let mut dict = vec![
                (
                    PickleValue::String("type".into()),
                    PickleValue::String(iface.interface_type.clone()),
                ),
                (
                    PickleValue::String("impl_name".into()),
                    iface
                        .impl_name
                        .clone()
                        .map(PickleValue::String)
                        .unwrap_or(PickleValue::None),
                ),
                (
                    PickleValue::String("version".into()),
                    iface
                        .impl_version
                        .clone()
                        .map(PickleValue::String)
                        .unwrap_or(PickleValue::None),
                ),
                // Upstream 9b464382 info keys.
                (
                    PickleValue::String("dst_cost".into()),
                    iface
                        .dst_cost
                        .map(|cost| PickleValue::Float(cost.as_f64()))
                        .unwrap_or(PickleValue::None),
                ),
                (
                    PickleValue::String("pr_cost".into()),
                    iface
                        .pr_cost
                        .map(|cost| PickleValue::Float(cost.as_f64()))
                        .unwrap_or(PickleValue::None),
                ),
                (
                    PickleValue::String("transport".into()),
                    PickleValue::Bool(iface.transport),
                ),
                (
                    PickleValue::String("name".into()),
                    PickleValue::String(iface.name.clone()),
                ),
                (
                    PickleValue::String("discovered".into()),
                    PickleValue::Float(iface.discovered),
                ),
                (
                    PickleValue::String("last_heard".into()),
                    PickleValue::Float(iface.last_heard),
                ),
                (
                    PickleValue::String("heard_count".into()),
                    PickleValue::Int(iface.heard_count as i64),
                ),
                (
                    PickleValue::String("status".into()),
                    PickleValue::String(iface.status.as_str().into()),
                ),
                (
                    PickleValue::String("stamp".into()),
                    PickleValue::Bytes(iface.stamp.clone()),
                ),
                (
                    PickleValue::String("value".into()),
                    PickleValue::Float(iface.stamp_value.as_f64()),
                ),
                (
                    PickleValue::String("transport_id".into()),
                    PickleValue::Bytes(iface.transport_id.to_vec()),
                ),
                (
                    PickleValue::String("network_id".into()),
                    PickleValue::Bytes(iface.network_id.to_vec()),
                ),
                (
                    PickleValue::String("hops".into()),
                    PickleValue::Int(iface.hops as i64),
                ),
            ];

            // Optional location fields
            if let Some(v) = iface.latitude {
                dict.push((
                    PickleValue::String("latitude".into()),
                    PickleValue::Float(v),
                ));
            } else {
                dict.push((PickleValue::String("latitude".into()), PickleValue::None));
            }
            if let Some(v) = iface.longitude {
                dict.push((
                    PickleValue::String("longitude".into()),
                    PickleValue::Float(v),
                ));
            } else {
                dict.push((PickleValue::String("longitude".into()), PickleValue::None));
            }
            if let Some(v) = iface.height {
                dict.push((PickleValue::String("height".into()), PickleValue::Float(v)));
            } else {
                dict.push((PickleValue::String("height".into()), PickleValue::None));
            }
            if let Some(v) = iface.operator_lxmf_address {
                dict.push((
                    PickleValue::String("operator_lxmf_address".into()),
                    PickleValue::String(rns_core::encoding::hex(&v)),
                ));
            }

            // Connection info
            if let Some(ref v) = iface.reachable_on {
                dict.push((
                    PickleValue::String("reachable_on".into()),
                    PickleValue::String(v.clone()),
                ));
            } else {
                dict.push((
                    PickleValue::String("reachable_on".into()),
                    PickleValue::None,
                ));
            }
            if let Some(v) = iface.port {
                dict.push((
                    PickleValue::String("port".into()),
                    PickleValue::Int(v as i64),
                ));
            } else {
                dict.push((PickleValue::String("port".into()), PickleValue::None));
            }

            // RNode/RF specific
            if let Some(v) = iface.frequency {
                dict.push((
                    PickleValue::String("frequency".into()),
                    PickleValue::Int(v as i64),
                ));
            } else {
                dict.push((PickleValue::String("frequency".into()), PickleValue::None));
            }
            if let Some(v) = iface.bandwidth {
                dict.push((
                    PickleValue::String("bandwidth".into()),
                    PickleValue::Int(v as i64),
                ));
            } else {
                dict.push((PickleValue::String("bandwidth".into()), PickleValue::None));
            }
            if let Some(v) = iface.spreading_factor {
                dict.push((PickleValue::String("sf".into()), PickleValue::Int(v as i64)));
            } else {
                dict.push((PickleValue::String("sf".into()), PickleValue::None));
            }
            if let Some(v) = iface.coding_rate {
                dict.push((PickleValue::String("cr".into()), PickleValue::Int(v as i64)));
            } else {
                dict.push((PickleValue::String("cr".into()), PickleValue::None));
            }
            if let Some(ref v) = iface.modulation {
                dict.push((
                    PickleValue::String("modulation".into()),
                    PickleValue::String(v.clone()),
                ));
            } else {
                dict.push((PickleValue::String("modulation".into()), PickleValue::None));
            }
            if let Some(v) = iface.channel {
                dict.push((
                    PickleValue::String("channel".into()),
                    PickleValue::Int(v as i64),
                ));
            } else {
                dict.push((PickleValue::String("channel".into()), PickleValue::None));
            }

            // IFAC info
            if let Some(ref v) = iface.ifac_netname {
                dict.push((
                    PickleValue::String("ifac_netname".into()),
                    PickleValue::String(v.clone()),
                ));
            } else {
                dict.push((
                    PickleValue::String("ifac_netname".into()),
                    PickleValue::None,
                ));
            }
            if let Some(ref v) = iface.ifac_netkey {
                dict.push((
                    PickleValue::String("ifac_netkey".into()),
                    PickleValue::String(v.clone()),
                ));
            } else {
                dict.push((PickleValue::String("ifac_netkey".into()), PickleValue::None));
            }

            // Config entry
            if let Some(ref v) = iface.config_entry {
                dict.push((
                    PickleValue::String("config_entry".into()),
                    PickleValue::String(v.clone()),
                ));
            } else {
                dict.push((
                    PickleValue::String("config_entry".into()),
                    PickleValue::None,
                ));
            }

            dict.push((
                PickleValue::String("discovery_hash".into()),
                PickleValue::Bytes(iface.discovery_hash.to_vec()),
            ));

            PickleValue::Dict(dict)
        })
        .collect();
    PickleValue::List(list)
}

pub(super) fn hooks_to_pickle(hooks: &[HookInfo]) -> PickleValue {
    PickleValue::List(
        hooks
            .iter()
            .map(|hook| {
                PickleValue::Dict(vec![
                    (
                        PickleValue::String("name".into()),
                        PickleValue::String(hook.name.clone()),
                    ),
                    (
                        PickleValue::String("type".into()),
                        PickleValue::String(hook.hook_type.clone()),
                    ),
                    (
                        PickleValue::String("attach_point".into()),
                        PickleValue::String(hook.attach_point.clone()),
                    ),
                    (
                        PickleValue::String("priority".into()),
                        PickleValue::Int(hook.priority as i64),
                    ),
                    (
                        PickleValue::String("enabled".into()),
                        PickleValue::Bool(hook.enabled),
                    ),
                    (
                        PickleValue::String("consecutive_traps".into()),
                        PickleValue::Int(hook.consecutive_traps as i64),
                    ),
                ])
            })
            .collect(),
    )
}

pub(super) fn backbone_peer_state_to_pickle(entries: &[BackbonePeerStateEntry]) -> PickleValue {
    PickleValue::List(
        entries
            .iter()
            .map(|entry| {
                PickleValue::Dict(vec![
                    (
                        PickleValue::String("interface".into()),
                        PickleValue::String(entry.interface_name.clone()),
                    ),
                    (
                        PickleValue::String("ip".into()),
                        PickleValue::String(entry.peer_ip.to_string()),
                    ),
                    (
                        PickleValue::String("connected_count".into()),
                        PickleValue::Int(entry.connected_count as i64),
                    ),
                    (
                        PickleValue::String("blacklisted_remaining_secs".into()),
                        entry
                            .blacklisted_remaining_secs
                            .map(PickleValue::Float)
                            .unwrap_or(PickleValue::None),
                    ),
                    (
                        PickleValue::String("blacklist_reason".into()),
                        entry
                            .blacklist_reason
                            .as_ref()
                            .map(|v: &String| PickleValue::String(v.clone()))
                            .unwrap_or(PickleValue::None),
                    ),
                    (
                        PickleValue::String("reject_count".into()),
                        PickleValue::Int(entry.reject_count as i64),
                    ),
                ])
            })
            .collect(),
    )
}

pub(super) fn backbone_interfaces_to_pickle(entries: &[BackboneInterfaceEntry]) -> PickleValue {
    PickleValue::List(
        entries
            .iter()
            .map(|entry| {
                PickleValue::Dict(vec![
                    (
                        PickleValue::String("id".into()),
                        PickleValue::Int(entry.interface_id.0 as i64),
                    ),
                    (
                        PickleValue::String("name".into()),
                        PickleValue::String(entry.interface_name.clone()),
                    ),
                ])
            })
            .collect(),
    )
}

pub(super) fn provider_bridge_stats_to_pickle(stats: &ProviderBridgeStats) -> PickleValue {
    PickleValue::Dict(vec![
        (
            PickleValue::String("connected".into()),
            PickleValue::Bool(stats.connected),
        ),
        (
            PickleValue::String("consumer_count".into()),
            PickleValue::Int(stats.consumer_count as i64),
        ),
        (
            PickleValue::String("queue_max_events".into()),
            PickleValue::Int(stats.queue_max_events as i64),
        ),
        (
            PickleValue::String("queue_max_bytes".into()),
            PickleValue::Int(stats.queue_max_bytes as i64),
        ),
        (
            PickleValue::String("backlog_len".into()),
            PickleValue::Int(stats.backlog_len as i64),
        ),
        (
            PickleValue::String("backlog_bytes".into()),
            PickleValue::Int(stats.backlog_bytes as i64),
        ),
        (
            PickleValue::String("backlog_dropped_pending".into()),
            PickleValue::Int(stats.backlog_dropped_pending as i64),
        ),
        (
            PickleValue::String("backlog_dropped_total".into()),
            PickleValue::Int(stats.backlog_dropped_total as i64),
        ),
        (
            PickleValue::String("total_disconnect_count".into()),
            PickleValue::Int(stats.total_disconnect_count as i64),
        ),
        (
            PickleValue::String("consumers".into()),
            PickleValue::List(
                stats
                    .consumers
                    .iter()
                    .map(|consumer| {
                        PickleValue::Dict(vec![
                            (
                                PickleValue::String("id".into()),
                                PickleValue::Int(consumer.id as i64),
                            ),
                            (
                                PickleValue::String("connected".into()),
                                PickleValue::Bool(consumer.connected),
                            ),
                            (
                                PickleValue::String("queue_len".into()),
                                PickleValue::Int(consumer.queue_len as i64),
                            ),
                            (
                                PickleValue::String("queued_bytes".into()),
                                PickleValue::Int(consumer.queued_bytes as i64),
                            ),
                            (
                                PickleValue::String("dropped_pending".into()),
                                PickleValue::Int(consumer.dropped_pending as i64),
                            ),
                            (
                                PickleValue::String("dropped_total".into()),
                                PickleValue::Int(consumer.dropped_total as i64),
                            ),
                            (
                                PickleValue::String("queue_max_events".into()),
                                PickleValue::Int(consumer.queue_max_events as i64),
                            ),
                            (
                                PickleValue::String("queue_max_bytes".into()),
                                PickleValue::Int(consumer.queue_max_bytes as i64),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

pub(super) fn lifecycle_state_name(state: LifecycleState) -> &'static str {
    match state {
        LifecycleState::Active => "active",
        LifecycleState::Draining => "draining",
        LifecycleState::Stopping => "stopping",
        LifecycleState::Stopped => "stopped",
    }
}

pub(super) fn drain_status_to_pickle(status: &DrainStatus) -> PickleValue {
    PickleValue::Dict(vec![
        (
            PickleValue::String("state".into()),
            PickleValue::String(lifecycle_state_name(status.state).into()),
        ),
        (
            PickleValue::String("drain_age_seconds".into()),
            status
                .drain_age_seconds
                .map(PickleValue::Float)
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("deadline_remaining_seconds".into()),
            status
                .deadline_remaining_seconds
                .map(PickleValue::Float)
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("drain_complete".into()),
            PickleValue::Bool(status.drain_complete),
        ),
        (
            PickleValue::String("interface_writer_queued_frames".into()),
            PickleValue::Int(status.interface_writer_queued_frames as i64),
        ),
        (
            PickleValue::String("provider_backlog_events".into()),
            PickleValue::Int(status.provider_backlog_events as i64),
        ),
        (
            PickleValue::String("provider_consumer_queued_events".into()),
            PickleValue::Int(status.provider_consumer_queued_events as i64),
        ),
        (
            PickleValue::String("detail".into()),
            status
                .detail
                .as_ref()
                .map(|detail| PickleValue::String(detail.clone()))
                .unwrap_or(PickleValue::None),
        ),
    ])
}

pub(super) fn runtime_config_value_to_pickle(value: &RuntimeConfigValue) -> PickleValue {
    match value {
        RuntimeConfigValue::Int(v) => PickleValue::Int(*v),
        RuntimeConfigValue::Float(v) => PickleValue::Float(*v),
        RuntimeConfigValue::Bool(v) => PickleValue::Bool(*v),
        RuntimeConfigValue::String(v) => PickleValue::String(v.clone()),
        RuntimeConfigValue::Null => PickleValue::None,
    }
}

pub(super) fn runtime_config_value_from_pickle(value: &PickleValue) -> Option<RuntimeConfigValue> {
    match value {
        PickleValue::Int(v) => Some(RuntimeConfigValue::Int(*v)),
        PickleValue::Float(v) => Some(RuntimeConfigValue::Float(*v)),
        PickleValue::Bool(v) => Some(RuntimeConfigValue::Bool(*v)),
        PickleValue::String(v) => Some(RuntimeConfigValue::String(v.clone())),
        PickleValue::None => Some(RuntimeConfigValue::Null),
        _ => None,
    }
}

pub(super) fn runtime_config_entry_to_pickle(entry: &RuntimeConfigEntry) -> PickleValue {
    PickleValue::Dict(vec![
        (
            PickleValue::String("key".into()),
            PickleValue::String(entry.key.clone()),
        ),
        (
            PickleValue::String("value".into()),
            runtime_config_value_to_pickle(&entry.value),
        ),
        (
            PickleValue::String("default".into()),
            runtime_config_value_to_pickle(&entry.default),
        ),
        (
            PickleValue::String("source".into()),
            PickleValue::String(match entry.source {
                RuntimeConfigSource::Startup => "startup".into(),
                RuntimeConfigSource::RuntimeOverride => "runtime_override".into(),
            }),
        ),
        (
            PickleValue::String("apply_mode".into()),
            PickleValue::String(match entry.apply_mode {
                RuntimeConfigApplyMode::Immediate => "immediate".into(),
                RuntimeConfigApplyMode::NewConnectionsOnly => "new_connections_only".into(),
                RuntimeConfigApplyMode::NextReconnect => "next_reconnect".into(),
            }),
        ),
        (
            PickleValue::String("description".into()),
            entry
                .description
                .as_ref()
                .map(|v| PickleValue::String(v.clone()))
                .unwrap_or(PickleValue::None),
        ),
    ])
}

pub(super) fn runtime_config_list_to_pickle(entries: &[RuntimeConfigEntry]) -> PickleValue {
    PickleValue::List(entries.iter().map(runtime_config_entry_to_pickle).collect())
}

pub(super) fn runtime_config_error_to_pickle(error: &RuntimeConfigError) -> PickleValue {
    PickleValue::Dict(vec![
        (
            PickleValue::String("error".into()),
            PickleValue::String(match error.code {
                RuntimeConfigErrorCode::UnknownKey => "unknown_key".into(),
                RuntimeConfigErrorCode::InvalidType => "invalid_type".into(),
                RuntimeConfigErrorCode::InvalidValue => "invalid_value".into(),
                RuntimeConfigErrorCode::Unsupported => "unsupported".into(),
                RuntimeConfigErrorCode::NotFound => "not_found".into(),
                RuntimeConfigErrorCode::ApplyFailed => "apply_failed".into(),
            }),
        ),
        (
            PickleValue::String("message".into()),
            PickleValue::String(error.message.clone()),
        ),
    ])
}

pub(super) fn runtime_config_result_to_pickle(
    result: Result<RuntimeConfigEntry, RuntimeConfigError>,
) -> PickleValue {
    match result {
        Ok(entry) => runtime_config_entry_to_pickle(&entry),
        Err(error) => runtime_config_error_to_pickle(&error),
    }
}

pub(super) fn known_destination_entry_to_pickle(entry: &KnownDestinationEntry) -> PickleValue {
    PickleValue::Dict(vec![
        (
            PickleValue::String("dest_hash".into()),
            PickleValue::Bytes(entry.dest_hash.to_vec()),
        ),
        (
            PickleValue::String("identity_hash".into()),
            PickleValue::Bytes(entry.identity_hash.to_vec()),
        ),
        (
            PickleValue::String("public_key".into()),
            PickleValue::Bytes(entry.public_key.to_vec()),
        ),
        (
            PickleValue::String("app_data".into()),
            entry
                .app_data
                .as_ref()
                .map(|data: &Vec<u8>| PickleValue::Bytes(data.clone()))
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("hops".into()),
            PickleValue::Int(entry.hops as i64),
        ),
        (
            PickleValue::String("received_at".into()),
            PickleValue::Float(entry.received_at),
        ),
        (
            PickleValue::String("receiving_interface".into()),
            PickleValue::Int(entry.receiving_interface.0 as i64),
        ),
        (
            PickleValue::String("was_used".into()),
            PickleValue::Bool(entry.was_used),
        ),
        (
            PickleValue::String("last_used_at".into()),
            entry
                .last_used_at
                .map(PickleValue::Float)
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("retained".into()),
            PickleValue::Bool(entry.retained),
        ),
        (
            PickleValue::String("stamp".into()),
            entry
                .stamp
                .map(|stamp| PickleValue::Bytes(stamp.to_vec()))
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("stamp_value".into()),
            PickleValue::Float(entry.stamp_value.as_f64()),
        ),
        (
            PickleValue::String("lr_cost".into()),
            entry
                .lr_cost
                .map(|cost| PickleValue::Float(cost.as_f64()))
                .unwrap_or(PickleValue::None),
        ),
    ])
}

pub(super) fn known_destinations_to_pickle(entries: &[KnownDestinationEntry]) -> PickleValue {
    PickleValue::List(
        entries
            .iter()
            .map(known_destination_entry_to_pickle)
            .collect(),
    )
}

pub(super) fn parse_known_destination_entry(
    value: &PickleValue,
) -> io::Result<KnownDestinationEntry> {
    let get_bytes = |key: &str, len: usize| -> io::Result<Vec<u8>> {
        let value = value.get(key).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("missing {}", key))
        })?;
        let bytes = value.as_bytes().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}", key))
        })?;
        if bytes.len() != len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid {} length", key),
            ));
        }
        Ok(bytes.to_vec())
    };
    let get_int = |key: &str| -> io::Result<i64> {
        value
            .get(key)
            .and_then(|v| v.as_int())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}", key)))
    };
    let get_float = |key: &str| -> io::Result<f64> {
        value
            .get(key)
            .and_then(|v| v.as_float())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}", key)))
    };
    let get_bool = |key: &str| -> io::Result<bool> {
        value
            .get(key)
            .and_then(|v| v.as_bool())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}", key)))
    };

    let mut dest_hash = [0u8; 16];
    dest_hash.copy_from_slice(&get_bytes("dest_hash", 16)?);
    let mut identity_hash = [0u8; 16];
    identity_hash.copy_from_slice(&get_bytes("identity_hash", 16)?);
    let mut public_key = [0u8; 64];
    public_key.copy_from_slice(&get_bytes("public_key", 64)?);
    let app_data = value
        .get("app_data")
        .and_then(|v| v.as_bytes())
        .map(|bytes| bytes.to_vec());
    let last_used_at = value.get("last_used_at").and_then(|v| v.as_float());
    let stamp = value
        .get("stamp")
        .and_then(|v| v.as_bytes())
        .filter(|bytes| bytes.len() == rns_core::constants::STAMP_LENGTH)
        .map(|bytes| {
            let mut stamp = [0u8; rns_core::constants::STAMP_LENGTH];
            stamp.copy_from_slice(bytes);
            stamp
        });
    // Integer values from before fractional stamp values read as whole bits.
    let stamp_value = value
        .get("stamp_value")
        .and_then(|v| v.as_float().or_else(|| v.as_int().map(|n| n as f64)))
        .map(rns_core::stamp::StampValue::from_f64)
        .unwrap_or_default();

    Ok(KnownDestinationEntry {
        dest_hash,
        identity_hash,
        public_key,
        app_data,
        hops: get_int("hops")? as u8,
        received_at: get_float("received_at")?,
        receiving_interface: rns_core::transport::types::InterfaceId(
            get_int("receiving_interface")? as u64,
        ),
        was_used: get_bool("was_used")?,
        last_used_at,
        retained: get_bool("retained")?,
        stamp,
        stamp_value,
        lr_cost: value
            .get("lr_cost")
            .and_then(|v| v.as_float().or_else(|| v.as_int().map(|n| n as f64)))
            .and_then(crate::storage::stored_link_cost),
    })
}

pub(super) fn parse_known_destination_list(
    value: &PickleValue,
) -> io::Result<Vec<KnownDestinationEntry>> {
    let list = value
        .as_list()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected list"))?;
    list.iter().map(parse_known_destination_entry).collect()
}
