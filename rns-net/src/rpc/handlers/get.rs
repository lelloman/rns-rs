//! Answering `{"get": <path>, ...}` requests.

use super::*;

/// Answer a `get` request for `path`; an unknown path answers None.
pub(super) fn handle_get_request(
    path: &str,
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<PickleValue> {
    match path {
        "interface_stats" => get_interface_stats(event_tx),
        "profiling_results" => Ok(crate::profiling::results_pickle().unwrap_or(PickleValue::None)),
        "link_distribution" => get_link_distribution(event_tx),
        "path_table" => get_path_table(request, event_tx),
        "rate_table" => get_rate_table(event_tx),
        "lowest_interface_bitrate" => get_lowest_interface_bitrate(event_tx),
        "medium_path_timeout" => get_medium_path_timeout(event_tx),
        "first_hop_timeout" => get_first_hop_timeout(request, event_tx),
        "next_hop" => get_next_hop(request, event_tx),
        "next_hop_if_name" => get_next_hop_if_name(request, event_tx),
        "link_count" => get_link_count(event_tx),
        "active_link_count" => get_active_link_count(event_tx),
        "transport_identity" => get_transport_identity(event_tx),
        "blackholed" => get_blackholed(event_tx),
        // Upstream's `get_packet_rssi`, `get_packet_snr` and
        // `get_packet_q`: the reading a packet arrived with, or None.
        "packet_rssi" | "packet_snr" | "packet_q" => get_packet_signal(path, request, event_tx),
        // Upstream's `get_blackholed_identities`: a dict from identity
        // hash to `{"source", "until", "reason"}`.
        "blackholed_identities" => get_blackholed_identities(event_tx),
        // Upstream's `is_blackholed`.
        "is_blackholed" => get_is_blackholed(request, event_tx),
        "discovered_interfaces" => get_discovered_interfaces(request, event_tx),
        "hooks" => get_hooks(event_tx),
        "runtime_config" => get_runtime_config(event_tx),
        "known_destinations" => get_known_destinations(event_tx),
        "runtime_config_entry" => get_runtime_config_entry(request, event_tx),
        "backbone_peer_state" => get_backbone_peer_state(request, event_tx),
        "backbone_interfaces" => get_backbone_interfaces(event_tx),
        "provider_bridge_stats" => get_provider_bridge_stats(event_tx),
        "drain_status" => get_drain_status(event_tx),
        _ => Ok(PickleValue::None),
    }
}

/// Upstream's `interface_stats` dict, with the inbound runtime counters.
fn get_interface_stats(event_tx: &mut dyn RpcDriver) -> io::Result<PickleValue> {
    let resp = send_query(event_tx, QueryRequest::InterfaceStats)?;
    if let QueryResponse::InterfaceStats(stats) = resp {
        let mut response = interface_stats_to_pickle(&stats);
        add_inbound_runtime_stats(&mut response, &stats, event_tx);
        Ok(response)
    } else {
        Ok(PickleValue::None)
    }
}

/// The link distribution per interface.
fn get_link_distribution(event_tx: &mut dyn RpcDriver) -> io::Result<PickleValue> {
    let resp = send_query(event_tx, QueryRequest::LinkDistribution)?;
    if let QueryResponse::LinkDistribution(entries) = resp {
        Ok(link_distribution_to_pickle(&entries))
    } else {
        Ok(PickleValue::Dict(Vec::new()))
    }
}

/// The path table, optionally limited to `max_hops`.
fn get_path_table(request: &PickleValue, event_tx: &mut dyn RpcDriver) -> io::Result<PickleValue> {
    let max_hops = request
        .get("max_hops")
        .and_then(|v| v.as_int().map(|n| n as u8));
    let resp = send_query(event_tx, QueryRequest::PathTable { max_hops })?;
    if let QueryResponse::PathTable(entries) = resp {
        Ok(path_table_to_pickle(&entries))
    } else {
        Ok(PickleValue::None)
    }
}

/// The announce rate table.
fn get_rate_table(event_tx: &mut dyn RpcDriver) -> io::Result<PickleValue> {
    let resp = send_query(event_tx, QueryRequest::RateTable)?;
    if let QueryResponse::RateTable(entries) = resp {
        Ok(rate_table_to_pickle(&entries))
    } else {
        Ok(PickleValue::None)
    }
}

/// The lowest bitrate among the interfaces, or None.
fn get_lowest_interface_bitrate(event_tx: &mut dyn RpcDriver) -> io::Result<PickleValue> {
    let resp = send_query(event_tx, QueryRequest::LowestInterfaceBitrate)?;
    if let QueryResponse::LowestInterfaceBitrate(Some(bitrate)) = resp {
        Ok(PickleValue::Int(bitrate as i64))
    } else {
        Ok(PickleValue::None)
    }
}

/// The medium path timeout in seconds.
fn get_medium_path_timeout(event_tx: &mut dyn RpcDriver) -> io::Result<PickleValue> {
    let resp = send_query(event_tx, QueryRequest::MediumPathTimeout)?;
    if let QueryResponse::MediumPathTimeout(timeout) = resp {
        Ok(PickleValue::Float(timeout))
    } else {
        Ok(PickleValue::Int(0))
    }
}

/// The first-hop timeout towards `destination_hash`.
fn get_first_hop_timeout(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<PickleValue> {
    let hash = extract_dest_hash(request, "destination_hash")?;
    let resp = send_query(event_tx, QueryRequest::FirstHopTimeout { dest_hash: hash })?;
    // Without a known bitrate upstream answers the
    // integer DEFAULT_PER_HOP_TIMEOUT.
    if let QueryResponse::FirstHopTimeout(timeout) = resp {
        Ok(python_number(timeout))
    } else {
        Ok(PickleValue::Float(
            rns_core::constants::LINK_ESTABLISHMENT_TIMEOUT_PER_HOP,
        ))
    }
}

/// The next hop towards `destination_hash`, or None.
fn get_next_hop(request: &PickleValue, event_tx: &mut dyn RpcDriver) -> io::Result<PickleValue> {
    let hash = extract_dest_hash(request, "destination_hash")?;
    let resp = send_query(event_tx, QueryRequest::NextHop { dest_hash: hash })?;
    if let QueryResponse::NextHop(Some(nh)) = resp {
        Ok(PickleValue::Bytes(nh.next_hop.to_vec()))
    } else {
        Ok(PickleValue::None)
    }
}

/// The name of the next-hop interface towards `destination_hash`.
fn get_next_hop_if_name(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<PickleValue> {
    let hash = extract_dest_hash(request, "destination_hash")?;
    let resp = send_query(event_tx, QueryRequest::NextHopIfName { dest_hash: hash })?;
    // Upstream answers str(next_hop_interface): "None"
    // when it has none.
    if let QueryResponse::NextHopIfName(Some(name)) = resp {
        Ok(PickleValue::String(name))
    } else {
        Ok(PickleValue::String("None".into()))
    }
}

/// The number of links.
fn get_link_count(event_tx: &mut dyn RpcDriver) -> io::Result<PickleValue> {
    let resp = send_query(event_tx, QueryRequest::LinkCount)?;
    if let QueryResponse::LinkCount(n) = resp {
        Ok(PickleValue::Int(n as i64))
    } else {
        Ok(PickleValue::None)
    }
}

/// The number of active links.
fn get_active_link_count(event_tx: &mut dyn RpcDriver) -> io::Result<PickleValue> {
    let resp = send_query(event_tx, QueryRequest::ActiveLinkCount)?;
    if let QueryResponse::ActiveLinkCount(n) = resp {
        Ok(PickleValue::Int(n as i64))
    } else {
        Ok(PickleValue::None)
    }
}

/// The transport identity hash, or None.
fn get_transport_identity(event_tx: &mut dyn RpcDriver) -> io::Result<PickleValue> {
    let resp = send_query(event_tx, QueryRequest::TransportIdentity)?;
    if let QueryResponse::TransportIdentity(Some(hash)) = resp {
        Ok(PickleValue::Bytes(hash.to_vec()))
    } else {
        Ok(PickleValue::None)
    }
}

/// The blackholed identities as a list.
fn get_blackholed(event_tx: &mut dyn RpcDriver) -> io::Result<PickleValue> {
    let resp = send_query(event_tx, QueryRequest::GetBlackholed)?;
    if let QueryResponse::Blackholed(entries) = resp {
        Ok(blackholed_to_pickle(&entries))
    } else {
        Ok(PickleValue::None)
    }
}

/// The RSSI, SNR or link quality (by `path`) a packet arrived with.
fn get_packet_signal(
    path: &str,
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<PickleValue> {
    let Some(packet_hash) = request
        .get("packet_hash")
        .and_then(|v| v.as_bytes())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    else {
        return Ok(PickleValue::None);
    };
    let resp = send_query(event_tx, QueryRequest::PacketSignal { packet_hash })?;
    let QueryResponse::PacketSignal(Some(signal)) = resp else {
        return Ok(PickleValue::None);
    };
    Ok(match path {
        "packet_rssi" => signal
            .rssi
            .map_or(PickleValue::None, |v| PickleValue::Int(i64::from(v))),
        "packet_snr" => signal
            .snr
            .map_or(PickleValue::None, |v| PickleValue::Float(f64::from(v))),
        _ => signal.q.map_or(PickleValue::None, PickleValue::Float),
    })
}

/// The blackholed identities as a dict keyed by identity hash.
fn get_blackholed_identities(event_tx: &mut dyn RpcDriver) -> io::Result<PickleValue> {
    let resp = send_query(event_tx, QueryRequest::GetBlackholed)?;
    if let QueryResponse::Blackholed(entries) = resp {
        Ok(blackholed_identities_to_pickle(&entries))
    } else {
        Ok(PickleValue::None)
    }
}

/// Whether `identity_hash` is blackholed.
fn get_is_blackholed(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<PickleValue> {
    let Some(identity_hash) = request
        .get("identity_hash")
        .and_then(|v| v.as_bytes())
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
    else {
        return Ok(PickleValue::Bool(false));
    };
    let resp = send_query(event_tx, QueryRequest::GetBlackholed)?;
    Ok(PickleValue::Bool(matches!(
        resp,
        QueryResponse::Blackholed(entries)
            if entries.iter().any(|e| e.identity_hash == identity_hash)
    )))
}

/// The discovered interfaces, filtered as the request asks.
fn get_discovered_interfaces(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<PickleValue> {
    let only_available = request
        .get("only_available")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let only_transport = request
        .get("only_transport")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let resp = send_query(
        event_tx,
        QueryRequest::DiscoveredInterfaces {
            only_available,
            only_transport,
        },
    )?;
    if let QueryResponse::DiscoveredInterfaces(interfaces) = resp {
        Ok(discovered_interfaces_to_pickle(&interfaces))
    } else {
        Ok(PickleValue::None)
    }
}

/// The loaded hooks.
fn get_hooks(event_tx: &mut dyn RpcDriver) -> io::Result<PickleValue> {
    let (response_tx, response_rx) = mpsc::channel();
    try_send_event(event_tx, Event::ListHooks { response_tx })?;
    let hooks = response_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "list hooks timed out"))?;
    Ok(hooks_to_pickle(&hooks))
}

/// Every runtime-config entry.
fn get_runtime_config(event_tx: &mut dyn RpcDriver) -> io::Result<PickleValue> {
    let resp = send_query(event_tx, QueryRequest::ListRuntimeConfig)?;
    if let QueryResponse::RuntimeConfigList(entries) = resp {
        Ok(runtime_config_list_to_pickle(&entries))
    } else {
        Ok(PickleValue::None)
    }
}

/// The known destinations.
fn get_known_destinations(event_tx: &mut dyn RpcDriver) -> io::Result<PickleValue> {
    let resp = send_query(event_tx, QueryRequest::KnownDestinations)?;
    if let QueryResponse::KnownDestinations(entries) = resp {
        Ok(known_destinations_to_pickle(&entries))
    } else {
        Ok(PickleValue::None)
    }
}

/// The runtime-config entry for `key`, or None.
fn get_runtime_config_entry(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<PickleValue> {
    let key = request
        .get("key")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let resp = send_query(event_tx, QueryRequest::GetRuntimeConfig { key })?;
    if let QueryResponse::RuntimeConfigEntry(entry) = resp {
        Ok(entry
            .as_ref()
            .map(runtime_config_entry_to_pickle)
            .unwrap_or(PickleValue::None))
    } else {
        Ok(PickleValue::None)
    }
}

/// The backbone peer state, optionally of one interface.
fn get_backbone_peer_state(
    request: &PickleValue,
    event_tx: &mut dyn RpcDriver,
) -> io::Result<PickleValue> {
    let interface_name = request
        .get("interface")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let resp = send_query(event_tx, QueryRequest::BackbonePeerState { interface_name })?;
    if let QueryResponse::BackbonePeerState(entries) = resp {
        Ok(backbone_peer_state_to_pickle(&entries))
    } else {
        Ok(PickleValue::None)
    }
}

/// The backbone interfaces.
fn get_backbone_interfaces(event_tx: &mut dyn RpcDriver) -> io::Result<PickleValue> {
    let resp = send_query(event_tx, QueryRequest::BackboneInterfaces)?;
    if let QueryResponse::BackboneInterfaces(entries) = resp {
        Ok(backbone_interfaces_to_pickle(&entries))
    } else {
        Ok(PickleValue::None)
    }
}

/// The provider bridge statistics, or None.
fn get_provider_bridge_stats(event_tx: &mut dyn RpcDriver) -> io::Result<PickleValue> {
    let resp = send_query(event_tx, QueryRequest::ProviderBridgeStats)?;
    if let QueryResponse::ProviderBridgeStats(stats) = resp {
        Ok(stats
            .as_ref()
            .map(provider_bridge_stats_to_pickle)
            .unwrap_or(PickleValue::None))
    } else {
        Ok(PickleValue::None)
    }
}

/// The drain status.
fn get_drain_status(event_tx: &mut dyn RpcDriver) -> io::Result<PickleValue> {
    let resp = send_query(event_tx, QueryRequest::DrainStatus)?;
    if let QueryResponse::DrainStatus(status) = resp {
        Ok(drain_status_to_pickle(&status))
    } else {
        Ok(PickleValue::None)
    }
}
