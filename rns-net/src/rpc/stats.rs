//! Interface statistics as upstream's `interface_stats` response.

use super::*;
use crate::event::{BackbonePeerPoolMemberStatus, BackbonePeerPoolStatus, TrafficDetail};

/// The `interface_stats` dict as msgpack, as remote management's `/status`
/// carries it.
pub(crate) fn interface_stats_msgpack(stats: &InterfaceStatsResponse) -> MsgpackValue {
    pickle_to_msgpack(&interface_stats_to_pickle(stats))
}

/// A number upstream starts at the integer 0 and only replaces with a float
/// once there is something to measure: 0 stays an int.
pub(super) fn zero_or_float(value: f64) -> PickleValue {
    if value == 0.0 {
        PickleValue::Int(0)
    } else {
        PickleValue::Float(value)
    }
}

/// One key-value entry of a pickled dict.
type PickleEntry = (PickleValue, PickleValue);

/// Upstream's `interface_stats` dict: every interface, the node's totals
/// and, on a transport node, the transport's identity.
pub(super) fn interface_stats_to_pickle(stats: &InterfaceStatsResponse) -> PickleValue {
    // Upstream's traffic totals are sums over the interfaces its traffic
    // counter measures, the top-level ones but the shared instance's: the
    // integer 0 when there are none, floats otherwise.
    let counted = stats.interfaces.iter().any(measured_by_traffic_counter);
    let mut ifaces = Vec::new();
    for iface in &stats.interfaces {
        ifaces.push(single_iface_to_pickle(iface));
    }

    let totals = node_total_entries(stats);
    let traffic = node_traffic_entries(&stats.traffic, counted);
    let mut dict = Vec::with_capacity(2 + totals.len() + traffic.len());
    dict.push((
        PickleValue::String("interfaces".into()),
        PickleValue::List(ifaces),
    ));
    dict.push((
        PickleValue::String("transport_enabled".into()),
        PickleValue::Bool(stats.transport_enabled),
    ));
    dict.extend(totals);
    dict.extend(traffic);

    // As upstream: the transport's identity, network, uptime and probe
    // responder only when transport is enabled.
    if stats.transport_enabled {
        push_transport_entries(stats, &mut dict);
    }

    // Upstream's resident set size, in bytes (None where it is unknown).
    dict.push((
        PickleValue::String("rss".into()),
        resident_set_size()
            .map(|bytes| PickleValue::Int(bytes as i64))
            .unwrap_or(PickleValue::None),
    ));

    dict.push((
        PickleValue::String("backbone_peer_pool".into()),
        stats
            .backbone_peer_pool
            .as_ref()
            .map(backbone_peer_pool_to_pickle)
            .unwrap_or(PickleValue::None),
    ));

    PickleValue::Dict(dict)
}

/// The node's byte, packet, link and path pool totals and its packet rates.
fn node_total_entries(stats: &InterfaceStatsResponse) -> [PickleEntry; 16] {
    [
        (
            PickleValue::String("rxb".into()),
            PickleValue::Int(stats.total_rxb as i64),
        ),
        (
            PickleValue::String("txb".into()),
            PickleValue::Int(stats.total_txb as i64),
        ),
        (
            PickleValue::String("rxpkts".into()),
            PickleValue::Int(stats.total_rx_packets as i64),
        ),
        (
            PickleValue::String("txpkts".into()),
            PickleValue::Int(stats.total_tx_packets as i64),
        ),
        (
            PickleValue::String("arxpkts".into()),
            PickleValue::Int(stats.total_announce_rx as i64),
        ),
        (
            PickleValue::String("atxpkts".into()),
            PickleValue::Int(stats.total_announce_tx as i64),
        ),
        (
            PickleValue::String("prxpkts".into()),
            PickleValue::Int(stats.total_path_request_rx as i64),
        ),
        (
            PickleValue::String("ptxpkts".into()),
            PickleValue::Int(stats.total_path_request_tx as i64),
        ),
        (
            PickleValue::String("tlinks".into()),
            PickleValue::Int(stats.total_links as i64),
        ),
        (
            PickleValue::String("alinks".into()),
            PickleValue::Int(stats.active_links as i64),
        ),
        (
            PickleValue::String("plinks".into()),
            PickleValue::Int(stats.pending_links as i64),
        ),
        (
            PickleValue::String("tpcount".into()),
            PickleValue::Int(stats.path_pool_total as i64),
        ),
        (
            PickleValue::String("unupcount".into()),
            PickleValue::Int(stats.path_pool_unused as i64),
        ),
        (
            PickleValue::String("actpcount".into()),
            PickleValue::Int(stats.path_pool_active as i64),
        ),
        (
            PickleValue::String("rxpps".into()),
            // `int(round(pps))`.
            PickleValue::Int(stats.rx_pps.round() as i64),
        ),
        (
            PickleValue::String("txpps".into()),
            // `int(round(pps))`.
            PickleValue::Int(stats.tx_pps.round() as i64),
        ),
    ]
}

/// The node's traffic totals: speeds (the integer 0 unless `counted`),
/// filtered, announce and path request bytes, counts, speeds and
/// frequencies.
fn node_traffic_entries(traffic: &TrafficDetail, counted: bool) -> [PickleEntry; 22] {
    let speed = |value: f64| {
        if counted {
            PickleValue::Float(value)
        } else {
            PickleValue::Int(0)
        }
    };
    [
        (PickleValue::String("rxs".into()), speed(traffic.rxs)),
        (PickleValue::String("txs".into()), speed(traffic.txs)),
        // Filtered traffic (upstream 134dc677). Always present: upstream's
        // `rnstatus -F` reads these keys unguarded.
        (
            PickleValue::String("frxb".into()),
            PickleValue::Int(traffic.frxb as i64),
        ),
        (
            PickleValue::String("ftxb".into()),
            PickleValue::Int(traffic.ftxb as i64),
        ),
        (PickleValue::String("frxs".into()), speed(traffic.frxs)),
        (PickleValue::String("ftxs".into()), speed(traffic.ftxs)),
        (
            PickleValue::String("arxb".into()),
            PickleValue::Int(traffic.arxb as i64),
        ),
        (
            PickleValue::String("atxb".into()),
            PickleValue::Int(traffic.atxb as i64),
        ),
        (
            PickleValue::String("arxc".into()),
            PickleValue::Int(traffic.arxc as i64),
        ),
        (
            PickleValue::String("atxc".into()),
            PickleValue::Int(traffic.atxc as i64),
        ),
        (PickleValue::String("arxs".into()), speed(traffic.arxs)),
        (PickleValue::String("atxs".into()), speed(traffic.atxs)),
        (
            PickleValue::String("prxb".into()),
            PickleValue::Int(traffic.prxb as i64),
        ),
        (
            PickleValue::String("ptxb".into()),
            PickleValue::Int(traffic.ptxb as i64),
        ),
        (
            PickleValue::String("prxc".into()),
            PickleValue::Int(traffic.prxc as i64),
        ),
        (
            PickleValue::String("ptxc".into()),
            PickleValue::Int(traffic.ptxc as i64),
        ),
        (PickleValue::String("prxs".into()), speed(traffic.prxs)),
        (PickleValue::String("ptxs".into()), speed(traffic.ptxs)),
        (
            PickleValue::String("arxf".into()),
            zero_or_float(traffic.arxf),
        ),
        (
            PickleValue::String("atxf".into()),
            zero_or_float(traffic.atxf),
        ),
        (
            PickleValue::String("prxf".into()),
            zero_or_float(traffic.prxf),
        ),
        (
            PickleValue::String("ptxf".into()),
            zero_or_float(traffic.ptxf),
        ),
    ]
}

/// A transport node's identity, network, uptime and probe responder.
fn push_transport_entries(stats: &InterfaceStatsResponse, dict: &mut Vec<PickleEntry>) {
    dict.push((
        PickleValue::String("transport_id".into()),
        stats
            .transport_id
            .map(|tid| PickleValue::Bytes(tid.to_vec()))
            .unwrap_or(PickleValue::None),
    ));
    dict.push((
        PickleValue::String("network_id".into()),
        stats
            .network_id
            .map(|id| PickleValue::Bytes(id.to_vec()))
            .unwrap_or(PickleValue::None),
    ));
    dict.push((
        PickleValue::String("transport_uptime".into()),
        PickleValue::Float(stats.transport_uptime),
    ));
    dict.push((
        PickleValue::String("probe_responder".into()),
        stats
            .probe_responder
            .map(|pr| PickleValue::Bytes(pr.to_vec()))
            .unwrap_or(PickleValue::None),
    ));
}

/// The outbound Backbone peer pool: its counts and each member's state.
fn backbone_peer_pool_to_pickle(pool: &BackbonePeerPoolStatus) -> PickleValue {
    let members = pool
        .members
        .iter()
        .map(backbone_peer_pool_member_to_pickle)
        .collect();
    PickleValue::Dict(vec![
        (
            PickleValue::String("max_connected".into()),
            PickleValue::Int(pool.max_connected as i64),
        ),
        (
            PickleValue::String("active_count".into()),
            PickleValue::Int(pool.active_count as i64),
        ),
        (
            PickleValue::String("standby_count".into()),
            PickleValue::Int(pool.standby_count as i64),
        ),
        (
            PickleValue::String("cooldown_count".into()),
            PickleValue::Int(pool.cooldown_count as i64),
        ),
        (
            PickleValue::String("members".into()),
            PickleValue::List(members),
        ),
    ])
}

/// One Backbone peer pool member's state.
fn backbone_peer_pool_member_to_pickle(member: &BackbonePeerPoolMemberStatus) -> PickleValue {
    let mut member_dict = vec![
        (
            PickleValue::String("name".into()),
            PickleValue::String(member.name.clone()),
        ),
        (
            PickleValue::String("remote".into()),
            PickleValue::String(member.remote.clone()),
        ),
        (
            PickleValue::String("source".into()),
            PickleValue::String(member.source.clone()),
        ),
        (
            PickleValue::String("priority".into()),
            PickleValue::Int(member.priority as i64),
        ),
        (
            PickleValue::String("state".into()),
            PickleValue::String(member.state.clone()),
        ),
        (
            PickleValue::String("failure_count".into()),
            PickleValue::Int(member.failure_count as i64),
        ),
    ];
    member_dict.push((
        PickleValue::String("interface_id".into()),
        member
            .interface_id
            .map(|id| PickleValue::Int(id as i64))
            .unwrap_or(PickleValue::None),
    ));
    member_dict.push((
        PickleValue::String("last_error".into()),
        member
            .last_error
            .as_ref()
            .map(|err| PickleValue::String(err.clone()))
            .unwrap_or(PickleValue::None),
    ));
    member_dict.push((
        PickleValue::String("cooldown_remaining_seconds".into()),
        member
            .cooldown_remaining_seconds
            .map(PickleValue::Float)
            .unwrap_or(PickleValue::None),
    ));
    PickleValue::Dict(member_dict)
}

pub(super) fn add_inbound_runtime_stats(
    response: &mut PickleValue,
    stats: &InterfaceStatsResponse,
    event_tx: &dyn RpcDriver,
) {
    let PickleValue::Dict(dict) = response else {
        return;
    };
    if let Some((_, PickleValue::List(ifaces))) = dict
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("interfaces"))
    {
        for (iface, stat) in ifaces.iter_mut().zip(&stats.interfaces) {
            let PickleValue::Dict(iface_dict) = iface else {
                continue;
            };
            let burst_stats = if stat.interface_type == "BackboneInterface" {
                event_tx
                    .dynamic_burst_stats(InterfaceId(stat.id))
                    .or(Some(DynamicBurstStats {
                        announce: BurstClassStats {
                            count: 0,
                            activated: None,
                        },
                        path_request: BurstClassStats {
                            count: 0,
                            activated: None,
                        },
                    }))
            } else {
                None
            };
            iface_dict.push((
                PickleValue::String("burst_count".into()),
                burst_stats
                    .map(|stats| PickleValue::Int(stats.announce.count as i64))
                    .unwrap_or(PickleValue::None),
            ));
            iface_dict.push((
                PickleValue::String("pr_burst_count".into()),
                burst_stats
                    .map(|stats| PickleValue::Int(stats.path_request.count as i64))
                    .unwrap_or(PickleValue::None),
            ));
            if let Some(stats) = burst_stats {
                set_pickle_dict_entry(
                    iface_dict,
                    "burst_active",
                    PickleValue::Bool(stats.announce.count > 0),
                );
                set_pickle_dict_entry(
                    iface_dict,
                    "burst_activated",
                    stats
                        .announce
                        .activated
                        .map(PickleValue::Float)
                        .unwrap_or(PickleValue::None),
                );
                set_pickle_dict_entry(
                    iface_dict,
                    "pr_burst_active",
                    PickleValue::Bool(stats.path_request.count > 0),
                );
                set_pickle_dict_entry(
                    iface_dict,
                    "pr_burst_activated",
                    stats
                        .path_request
                        .activated
                        .map(PickleValue::Float)
                        .unwrap_or(PickleValue::None),
                );
            }
        }
    }

    let snapshot = event_tx.inbound_queue_snapshot();
    let total_height = snapshot.total_height();
    let total_capacity = snapshot.total_capacity();
    let total_dropped = snapshot.total_dropped();
    let pressure = |height: usize, capacity: usize| {
        if height == 0 {
            0.0
        } else {
            height as f64 / capacity as f64
        }
    };
    dict.extend([
        (
            PickleValue::String("rxqt".into()),
            PickleValue::Int(total_height as i64),
        ),
        (
            PickleValue::String("rxqd".into()),
            PickleValue::Int(snapshot.heights[0] as i64),
        ),
        (
            PickleValue::String("rxqa".into()),
            PickleValue::Int(snapshot.heights[1] as i64),
        ),
        (
            PickleValue::String("rxqp".into()),
            PickleValue::Int(snapshot.heights[2] as i64),
        ),
        (
            PickleValue::String("rxqil".into()),
            PickleValue::Int(snapshot.heights[3] as i64),
        ),
        (
            PickleValue::String("rxqtd".into()),
            PickleValue::Int(total_dropped as i64),
        ),
        (
            PickleValue::String("rxqdd".into()),
            PickleValue::Int(snapshot.dropped[0] as i64),
        ),
        (
            PickleValue::String("rxqad".into()),
            PickleValue::Int(snapshot.dropped[1] as i64),
        ),
        (
            PickleValue::String("rxqpd".into()),
            PickleValue::Int(snapshot.dropped[2] as i64),
        ),
        (
            PickleValue::String("rxqild".into()),
            PickleValue::Int(snapshot.dropped[3] as i64),
        ),
        (
            PickleValue::String("tqpressure".into()),
            zero_or_float(pressure(total_height, total_capacity)),
        ),
        (
            PickleValue::String("dqpressure".into()),
            zero_or_float(pressure(snapshot.heights[0], snapshot.capacities[0])),
        ),
        (
            PickleValue::String("aqpressure".into()),
            zero_or_float(pressure(snapshot.heights[1], snapshot.capacities[1])),
        ),
        (
            PickleValue::String("pqpressure".into()),
            zero_or_float(pressure(snapshot.heights[2], snapshot.capacities[2])),
        ),
        (
            PickleValue::String("ilqpressure".into()),
            zero_or_float(pressure(snapshot.heights[3], snapshot.capacities[3])),
        ),
        (PickleValue::String("txq".into()), PickleValue::None),
    ]);
}

pub(super) fn set_pickle_dict_entry(
    dict: &mut Vec<(PickleValue, PickleValue)>,
    key: &str,
    value: PickleValue,
) {
    if let Some((_, existing)) = dict
        .iter_mut()
        .find(|(candidate, _)| candidate.as_str() == Some(key))
    {
        *existing = value;
    } else {
        dict.push((PickleValue::String(key.into()), value));
    }
}

/// This process's resident set size in bytes, from `/proc/self/status`.
pub(super) fn resident_set_size() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    let kilobytes: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kilobytes * 1024)
}

/// A number as upstream would hold it: an int when it is whole (as from a
/// config value or an unset `0`), else a float.
pub(super) fn python_number(value: f64) -> PickleValue {
    if value.fract() == 0.0 && value.abs() < 9_007_199_254_740_992.0 {
        PickleValue::Int(value as i64)
    } else {
        PickleValue::Float(value)
    }
}

/// Upstream's class name for an interface type: spawned clients of TCP and
/// local servers are `TCPClientInterface` and `LocalClientInterface` there.
pub(crate) fn upstream_interface_type(interface_type: &str) -> &str {
    match interface_type {
        "TCPServerClientInterface" => "TCPClientInterface",
        "LocalServerClientInterface" => "LocalClientInterface",
        other => other,
    }
}

/// The Weave statistics, under upstream's keys and only on the interfaces
/// that carry them: a key present with no value makes upstream's `rnstatus`
/// print an "Unknown" line. `WeaveInterface` has the device's CPU and memory
/// load, switch and endpoint ids; `WeaveInterfacePeer` the switch it is
/// reached through. Ids are `RNS.hexrep` strings, loads as upstream keeps
/// them (whole CPU percent, memory percent to two decimals).
pub(super) fn weave_stats_to_pickle(
    s: &SingleInterfaceStat,
    dict: &mut Vec<(PickleValue, PickleValue)>,
) {
    let hexrep = |bytes: &[u8]| {
        PickleValue::String(
            bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        )
    };
    let key = |name: &str| PickleValue::String(name.into());
    match s.interface_type.as_str() {
        "WeaveInterface" => {
            dict.push((
                key("cpu_load"),
                s.cpu_load
                    .map(|v| PickleValue::Int(v.round() as i64))
                    .unwrap_or(PickleValue::None),
            ));
            dict.push((
                key("mem_load"),
                s.mem_load
                    .map(|v| PickleValue::Float((v * 100.0).round() / 100.0))
                    .unwrap_or(PickleValue::None),
            ));
            dict.push((
                key("switch_id"),
                s.switch_id.map(|v| hexrep(&v)).unwrap_or(PickleValue::None),
            ));
            dict.push((
                key("endpoint_id"),
                s.endpoint_id
                    .map(|v| hexrep(&v))
                    .unwrap_or(PickleValue::None),
            ));
        }
        "WeaveInterfacePeer" => dict.push((
            key("via_switch_id"),
            s.via_switch_id
                .map(|v| hexrep(&v))
                .unwrap_or(PickleValue::None),
        )),
        _ => {}
    }
}

/// What an RNode reports about its channel and itself, under upstream's
/// keys and only on RNode interfaces, as upstream's `interface_stats`:
/// airtime and channel load (percent), noise floor, interference and its
/// last sighting, temperature (`cpu_temp`) and battery (the state only
/// once known).
pub(super) fn radio_stats_to_pickle(
    s: &SingleInterfaceStat,
    dict: &mut Vec<(PickleValue, PickleValue)>,
) {
    let Some(radio) = s.radio.as_ref() else {
        return;
    };
    let key = |name: &str| PickleValue::String(name.into());
    let dbm = |v: Option<i16>| v.map_or(PickleValue::None, |v| PickleValue::Int(i64::from(v)));
    dict.push((
        key("airtime_short"),
        PickleValue::Float(radio.airtime_short),
    ));
    dict.push((key("airtime_long"), PickleValue::Float(radio.airtime_long)));
    dict.push((
        key("channel_load_short"),
        PickleValue::Float(radio.channel_load_short),
    ));
    dict.push((
        key("channel_load_long"),
        PickleValue::Float(radio.channel_load_long),
    ));
    dict.push((key("noise_floor"), dbm(radio.noise_floor)));
    dict.push((key("interference"), dbm(radio.interference)));
    if let Some((ts, rssi)) = radio.interference_last {
        dict.push((key("interference_last_ts"), PickleValue::Float(ts)));
        dict.push((
            key("interference_last_dbm"),
            PickleValue::Int(i64::from(rssi)),
        ));
    }
    dict.push((key("cpu_temp"), dbm(radio.temperature)));
    if radio.battery_state != 0 {
        dict.push((
            key("battery_state"),
            PickleValue::String(radio.battery_state_name().into()),
        ));
    }
    dict.push((
        key("battery_percent"),
        PickleValue::Int(i64::from(radio.battery_percent)),
    ));
}

/// Whether upstream's traffic counter measures the interface's speeds: a
/// top-level interface other than the shared instance's. The others keep
/// the integer 0 it starts them at.
pub(super) fn measured_by_traffic_counter(s: &SingleInterfaceStat) -> bool {
    s.parent_display_name.is_none()
        && !s.display_name.starts_with("Shared Instance[")
        && !s.display_name.starts_with("LocalInterface[")
}

/// One interface's entry of upstream's `interface_stats` list.
pub(super) fn single_iface_to_pickle(s: &SingleInterfaceStat) -> PickleValue {
    let identity = iface_identity_entries(s);
    let remote = remote_transport_entries(s.remote_transport_info.as_ref());
    let state = iface_state_entries(s);
    let traffic = iface_traffic_entries(&s.traffic, measured_by_traffic_counter(s));
    let counters = iface_counter_entries(s);
    let link = iface_link_entries(s);
    let announce = iface_announce_entries(s);
    let config = iface_config_entries(s);
    let mut dict = Vec::with_capacity(
        identity.len()
            + remote.len()
            + state.len()
            + traffic.len()
            + counters.len()
            + link.len()
            + announce.len()
            + config.len(),
    );
    dict.extend(identity);
    dict.extend(remote);
    dict.extend(state);
    dict.extend(traffic);
    dict.extend(counters);
    dict.extend(link);
    dict.extend(announce);
    dict.extend(config);
    weave_stats_to_pickle(s, &mut dict);
    radio_stats_to_pickle(s, &mut dict);
    push_iface_origin_entries(s, &mut dict);
    push_iface_rate_and_size_entries(s, &mut dict);
    PickleValue::Dict(dict)
}

/// The interface's id, names' hash and tunnel and remote transport ids.
fn iface_identity_entries(s: &SingleInterfaceStat) -> [PickleEntry; 5] {
    [
        (
            PickleValue::String("id".into()),
            PickleValue::Int(s.id as i64),
        ),
        // Upstream's `str(interface)`, which its rnstatus prints and keys
        // on; `short_name` is the interface's own name.
        (
            PickleValue::String("name".into()),
            PickleValue::String(s.display_name.clone()),
        ),
        // Upstream `Interface.get_hash()`: the full hash of `str(interface)`.
        (
            PickleValue::String("hash".into()),
            PickleValue::Bytes(rns_core::hash::full_hash(s.display_name.as_bytes()).to_vec()),
        ),
        (
            PickleValue::String("tunnel_id".into()),
            s.tunnel_id
                .map(|tunnel_id| PickleValue::Bytes(tunnel_id.to_vec()))
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("remote_transport_id".into()),
            s.remote_transport_id
                .map(|identity_hash| PickleValue::Bytes(identity_hash.to_vec()))
                .unwrap_or(PickleValue::None),
        ),
    ]
}

/// Upstream b7a93b9b: what the remote transport node reported in its
/// synthesis extension, `None` when unknown or on a shared medium.
fn remote_transport_entries(
    remote_info: Option<&rns_core::transport::tunnel::RemoteTransportInfo>,
) -> [PickleEntry; 5] {
    [
        (
            PickleValue::String("rem_impl".into()),
            remote_info
                .map(|info| PickleValue::String(info.implementation.clone()))
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("rem_vers".into()),
            remote_info
                .map(|info| {
                    PickleValue::List(
                        info.version
                            .iter()
                            .map(|component| PickleValue::Int(i64::from(*component)))
                            .collect(),
                    )
                })
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("rem_is_tn".into()),
            remote_info
                .map(|info| PickleValue::Bool(info.is_transport))
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("rem_dst_cost".into()),
            remote_info
                .map(|info| PickleValue::Float(info.destination_cost.as_f64()))
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("rem_pr_cost".into()),
            remote_info
                .map(|info| PickleValue::Float(info.pr_cost.as_f64()))
                .unwrap_or(PickleValue::None),
        ),
    ]
}

/// The interface's status, mode, gravity, byte counts and transmit queue.
fn iface_state_entries(s: &SingleInterfaceStat) -> [PickleEntry; 10] {
    [
        (
            PickleValue::String("status".into()),
            PickleValue::Bool(s.status),
        ),
        (
            PickleValue::String("mode".into()),
            PickleValue::Int(s.mode as i64),
        ),
        (
            PickleValue::String("gravity".into()),
            PickleValue::Int(s.gravity),
        ),
        (
            PickleValue::String("announces_to_internal".into()),
            s.announces_to_internal
                .map(PickleValue::Bool)
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("rxb".into()),
            PickleValue::Int(s.rxb as i64),
        ),
        (
            PickleValue::String("txb".into()),
            PickleValue::Int(s.txb as i64),
        ),
        (
            PickleValue::String("txdrp".into()),
            PickleValue::Int(s.tx_drops as i64),
        ),
        (
            PickleValue::String("txdrb".into()),
            PickleValue::Int(s.tx_dropped_bytes as i64),
        ),
        (
            PickleValue::String("txstalled".into()),
            PickleValue::Bool(s.tx_stalled),
        ),
        (
            PickleValue::String("txbuffered".into()),
            PickleValue::Int(s.tx_buffered as i64),
        ),
    ]
}

/// The interface's speeds (the integer 0 unless `measured`) and its
/// filtered, announce and path request bytes, counts and speeds.
fn iface_traffic_entries(traffic: &TrafficDetail, measured: bool) -> [PickleEntry; 19] {
    let speed = |value: f64| {
        if measured {
            PickleValue::Float(value)
        } else {
            PickleValue::Int(0)
        }
    };
    [
        (PickleValue::String("rxs".into()), speed(traffic.rxs)),
        (PickleValue::String("txs".into()), speed(traffic.txs)),
        // Filtered traffic (upstream 134dc677). Always present: upstream's
        // `rnstatus -F` reads these keys unguarded.
        (
            PickleValue::String("frxb".into()),
            PickleValue::Int(traffic.frxb as i64),
        ),
        (
            PickleValue::String("ftxb".into()),
            PickleValue::Int(traffic.ftxb as i64),
        ),
        (PickleValue::String("frxs".into()), speed(traffic.frxs)),
        (PickleValue::String("ftxs".into()), speed(traffic.ftxs)),
        (
            PickleValue::String("arxb".into()),
            PickleValue::Int(traffic.arxb as i64),
        ),
        (
            PickleValue::String("atxb".into()),
            PickleValue::Int(traffic.atxb as i64),
        ),
        (
            PickleValue::String("arxc".into()),
            PickleValue::Int(traffic.arxc as i64),
        ),
        (
            PickleValue::String("afrxc".into()),
            PickleValue::Int(traffic.afrxc as i64),
        ),
        (
            PickleValue::String("atxc".into()),
            PickleValue::Int(traffic.atxc as i64),
        ),
        (PickleValue::String("arxs".into()), speed(traffic.arxs)),
        (PickleValue::String("atxs".into()), speed(traffic.atxs)),
        (
            PickleValue::String("prxb".into()),
            PickleValue::Int(traffic.prxb as i64),
        ),
        (
            PickleValue::String("ptxb".into()),
            PickleValue::Int(traffic.ptxb as i64),
        ),
        (
            PickleValue::String("prxc".into()),
            PickleValue::Int(traffic.prxc as i64),
        ),
        (
            PickleValue::String("ptxc".into()),
            PickleValue::Int(traffic.ptxc as i64),
        ),
        (PickleValue::String("prxs".into()), speed(traffic.prxs)),
        (PickleValue::String("ptxs".into()), speed(traffic.ptxs)),
    ]
}

/// The interface's violation, filter and packet counters.
fn iface_counter_entries(s: &SingleInterfaceStat) -> [PickleEntry; 7] {
    [
        (
            PickleValue::String("protocol_violations".into()),
            PickleValue::Int(s.protocol_violations as i64),
        ),
        (
            PickleValue::String("ifac_violations".into()),
            PickleValue::Int(s.ifac_violations as i64),
        ),
        (
            PickleValue::String("packet_filter_hits".into()),
            PickleValue::Int(s.packet_filter_hits as i64),
        ),
        (
            PickleValue::String("hop_limiter_hits".into()),
            PickleValue::Int(s.hop_limiter_hits as i64),
        ),
        (
            PickleValue::String("stamped_path_requests".into()),
            PickleValue::Int(s.stamped_path_requests as i64),
        ),
        (
            PickleValue::String("rx_packets".into()),
            PickleValue::Int(s.rx_packets as i64),
        ),
        (
            PickleValue::String("tx_packets".into()),
            PickleValue::Int(s.tx_packets as i64),
        ),
    ]
}

/// The interface's peer count, signal readings and radio parameters, each
/// None when the interface has none.
fn iface_link_entries(s: &SingleInterfaceStat) -> [PickleEntry; 11] {
    [
        (
            PickleValue::String("peers".into()),
            s.peers
                .map(|v| PickleValue::Int(v as i64))
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("rssi".into()),
            s.rssi
                .map(|v| PickleValue::Int(v as i64))
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("snr".into()),
            s.snr
                .map(|v| PickleValue::Float(f64::from(v)))
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("signal_quality".into()),
            s.signal_quality
                .map(PickleValue::Float)
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("frequency".into()),
            s.frequency
                .map(|v| PickleValue::Int(i64::from(v)))
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("bandwidth".into()),
            s.bandwidth
                .map(|v| PickleValue::Int(i64::from(v)))
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("txpower".into()),
            s.txpower
                .map(|v| PickleValue::Int(i64::from(v)))
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("sf".into()),
            s.spreading_factor
                .map(|v| PickleValue::Int(i64::from(v)))
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("cr".into()),
            s.coding_rate
                .map(|v| PickleValue::Int(i64::from(v)))
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("channel".into()),
            s.channel
                .map(|v| PickleValue::Int(i64::from(v)))
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("modulation".into()),
            s.modulation
                .clone()
                .map(PickleValue::String)
                .unwrap_or(PickleValue::None),
        ),
    ]
}

/// The interface's start time, announce and path request frequencies,
/// burst state, client count and announce rate grace and penalty.
fn iface_announce_entries(s: &SingleInterfaceStat) -> [PickleEntry; 16] {
    [
        (
            PickleValue::String("started".into()),
            PickleValue::Float(s.started),
        ),
        (
            PickleValue::String("ia_freq".into()),
            PickleValue::Float(s.ia_freq),
        ),
        (
            PickleValue::String("oa_freq".into()),
            PickleValue::Float(s.oa_freq),
        ),
        (
            PickleValue::String("ip_freq".into()),
            PickleValue::Float(s.ip_freq),
        ),
        (
            PickleValue::String("op_freq".into()),
            PickleValue::Float(s.op_freq),
        ),
        (
            PickleValue::String("burst_active".into()),
            PickleValue::Bool(s.burst_active),
        ),
        (
            PickleValue::String("burst_activated".into()),
            python_number(s.burst_activated),
        ),
        (
            PickleValue::String("pr_burst_active".into()),
            PickleValue::Bool(s.pr_burst_active),
        ),
        (
            PickleValue::String("pr_burst_activated".into()),
            python_number(s.pr_burst_activated),
        ),
        (
            PickleValue::String("clients".into()),
            s.clients
                .map(|clients| PickleValue::Int(clients as i64))
                .unwrap_or(PickleValue::None),
        ),
        (
            // None without an announce rate target, as upstream leaves
            // them unconfigured.
            PickleValue::String("announce_rate_grace".into()),
            if s.announce_rate_target.is_some() {
                PickleValue::Int(s.announce_rate_grace as i64)
            } else {
                PickleValue::None
            },
        ),
        (
            PickleValue::String("announce_rate_penalty".into()),
            if s.announce_rate_target.is_some() {
                python_number(s.announce_rate_penalty)
            } else {
                PickleValue::None
            },
        ),
        // Upstream's names for the frequencies above, which its rnstatus
        // reads.
        (
            PickleValue::String("incoming_announce_frequency".into()),
            python_number(s.ia_freq),
        ),
        (
            PickleValue::String("outgoing_announce_frequency".into()),
            python_number(s.oa_freq),
        ),
        (
            PickleValue::String("incoming_pr_frequency".into()),
            python_number(s.ip_freq),
        ),
        (
            PickleValue::String("outgoing_pr_frequency".into()),
            python_number(s.op_freq),
        ),
    ]
}

/// The interface's type, own name, announce queues and IFAC settings.
fn iface_config_entries(s: &SingleInterfaceStat) -> [PickleEntry; 6] {
    [
        (
            PickleValue::String("type".into()),
            PickleValue::String(upstream_interface_type(&s.interface_type).into()),
        ),
        (
            PickleValue::String("short_name".into()),
            PickleValue::String(s.name.clone()),
        ),
        (
            PickleValue::String("held_announces".into()),
            PickleValue::Int(s.held_announces as i64),
        ),
        (
            PickleValue::String("announce_queue".into()),
            PickleValue::Int(s.announce_queue as i64),
        ),
        (
            PickleValue::String("ifac_netname".into()),
            s.ifac_netname
                .clone()
                .map(PickleValue::String)
                .unwrap_or(PickleValue::None),
        ),
        (
            PickleValue::String("ifac_signature".into()),
            s.ifac_signature
                .map(|signature| PickleValue::Bytes(signature.to_vec()))
                .unwrap_or(PickleValue::None),
        ),
    ]
}

/// Where the interface came from: blocked addresses of a listener, the
/// auto-connect source, an I2P endpoint or tunnel state, and the listener
/// a spawned interface came from.
fn push_iface_origin_entries(s: &SingleInterfaceStat, dict: &mut Vec<PickleEntry>) {
    // Only listeners that block addresses report them: upstream's rnstatus
    // compares `blocked_ips` with 0 whenever the key is present.
    if let Some(blocked) = s.blocked_ips {
        dict.push((
            PickleValue::String("blocked_ips".into()),
            PickleValue::Int(blocked as i64),
        ));
    }
    if let Some(blocked) = &s.blocked_ip_list {
        dict.push((
            PickleValue::String("blocked_ip_list".into()),
            PickleValue::List(blocked.iter().cloned().map(PickleValue::String).collect()),
        ));
    }
    // Every interface reports where it was auto-connected from, None for
    // one that was not.
    dict.push((
        PickleValue::String("autoconnect_source".into()),
        s.autoconnect_source
            .clone()
            .map(PickleValue::String)
            .unwrap_or(PickleValue::None),
    ));
    // Only an I2P interface reports its endpoint, with `i2p_b32` None
    // until its address is known.
    if let Some(i2p) = &s.i2p {
        dict.push((
            PickleValue::String("i2p_connectable".into()),
            PickleValue::Bool(i2p.connectable),
        ));
        dict.push((
            PickleValue::String("i2p_b32".into()),
            i2p.b32
                .clone()
                .map(PickleValue::String)
                .unwrap_or(PickleValue::None),
        ));
    }
    // Only I2P peers report their tunnel state.
    if let Some(state) = &s.i2p_tunnel_state {
        dict.push((
            PickleValue::String("tunnelstate".into()),
            state
                .clone()
                .map(PickleValue::String)
                .unwrap_or(PickleValue::None),
        ));
    }
    // Upstream reports the listener a spawned interface came from.
    if let Some(parent) = &s.parent_display_name {
        dict.push((
            PickleValue::String("parent_interface_name".into()),
            PickleValue::String(parent.clone()),
        ));
        dict.push((
            PickleValue::String("parent_interface_hash".into()),
            PickleValue::Bytes(rns_core::hash::full_hash(parent.as_bytes()).to_vec()),
        ));
    }
}

/// The interface's announce rate target, bitrate, MTU and IFAC size, each
/// None when unset.
fn push_iface_rate_and_size_entries(s: &SingleInterfaceStat, dict: &mut Vec<PickleEntry>) {
    match s.announce_rate_target {
        Some(target) => dict.push((
            PickleValue::String("announce_rate_target".into()),
            python_number(target),
        )),
        None => dict.push((
            PickleValue::String("announce_rate_target".into()),
            PickleValue::None,
        )),
    }

    match s.bitrate {
        Some(br) if s.bitrate_is_float => dict.push((
            PickleValue::String("bitrate".into()),
            PickleValue::Float(br as f64),
        )),
        Some(br) => dict.push((
            PickleValue::String("bitrate".into()),
            PickleValue::Int(br as i64),
        )),
        None => dict.push((PickleValue::String("bitrate".into()), PickleValue::None)),
    }

    match s.mtu {
        Some(mtu) => dict.push((
            PickleValue::String("mtu".into()),
            PickleValue::Int(mtu as i64),
        )),
        None => dict.push((PickleValue::String("mtu".into()), PickleValue::None)),
    }

    match s.ifac_size {
        Some(sz) => dict.push((
            PickleValue::String("ifac_size".into()),
            PickleValue::Int(sz as i64),
        )),
        None => dict.push((PickleValue::String("ifac_size".into()), PickleValue::None)),
    }
}
