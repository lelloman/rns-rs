//! Builders shared by the transport engine's per-module tests.

use super::*;

pub(super) fn config(transport_enabled: bool) -> TransportConfig {
    TransportConfig {
        transport_enabled,
        identity_hash: transport_enabled.then_some([0x42; 16]),
        local_hops_delta: 0,
        prefer_shorter_path: false,
        max_paths_per_destination: 1,
        packet_hashlist_max_entries: constants::HASHLIST_MAXSIZE,
        packet_hashlist_allocation: types::PacketHashlistAllocation::Eager,
        max_discovery_pr_tags: constants::MAX_PR_TAGS,
        max_path_destinations: usize::MAX,
        max_tunnel_destinations_total: usize::MAX,
        destination_timeout_secs: constants::DESTINATION_TIMEOUT,
        announce_table_ttl_secs: constants::ANNOUNCE_TABLE_TTL,
        announce_table_max_bytes: constants::ANNOUNCE_TABLE_MAX_BYTES,
        announce_sig_cache_enabled: true,
        announce_sig_cache_max_entries: constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
        announce_sig_cache_ttl_secs: constants::ANNOUNCE_SIG_CACHE_TTL,
        announce_queue_max_entries: 256,
        announce_queue_max_interfaces: 1024,
    }
}

pub(super) fn engine(transport_enabled: bool) -> TransportEngine {
    TransportEngine::new(config(transport_enabled))
}

pub(super) fn interface(id: u64, mode: u8) -> InterfaceInfo {
    InterfaceInfo {
        stamp_costs: Default::default(),
        id: InterfaceId(id),
        name: String::from("test"),
        mode,
        gravity: 0,
        recursive_prs: false,
        announces_from_internal: true,
        announces_to_internal: None,
        out_capable: true,
        in_capable: true,
        bitrate: None,
        airtime_profile: None,
        announce_rate_target: None,
        announce_rate_grace: 0,
        announce_rate_penalty: 0.0,
        announce_cap: constants::ANNOUNCE_CAP,
        is_local_client: false,
        wants_tunnel: false,
        hop_limiter: None,
        tunnel_id: None,
        mtu: constants::MTU as u32,
        mtu_upgradable: false,
        ingress_control: types::IngressControlConfig::disabled(),
        ia_freq: 0.0,
        ip_freq: 0.0,
        op_freq: 0.0,
        op_samples: 0,
        started: 0.0,
    }
}

/// A HEADER_1 announce frame for `destination_hash` carrying `payload`.
pub(super) fn announce_raw(destination_hash: &[u8; 16], payload: &[u8]) -> Vec<u8> {
    let mut raw = vec![constants::PACKET_TYPE_ANNOUNCE, 0x02];
    raw.extend_from_slice(destination_hash);
    raw.push(constants::CONTEXT_NONE);
    raw.extend_from_slice(payload);
    raw
}

/// A path through `next_hop` on `receiving_interface`, with a cached
/// announce to answer path requests from.
pub(super) fn path_entry(
    destination_hash: &[u8; 16],
    timestamp: f64,
    hops: u8,
    receiving_interface: InterfaceId,
    next_hop: [u8; 16],
) -> PathEntry {
    PathEntry {
        timestamp,
        next_hop,
        hops,
        expires: timestamp + constants::DESTINATION_TIMEOUT,
        random_blobs: Vec::new(),
        receiving_interface,
        packet_hash: [0; 32],
        used: 0.0,
        announce_raw: Some(announce_raw(destination_hash, &[0xAB; 32])),
    }
}

/// Path request data: destination hash, the optional requesting transport
/// id, the tag and the optional stamp extension.
pub(super) fn path_request(
    destination_hash: &[u8; 16],
    transport_id: Option<&[u8; 16]>,
    tag: &[u8],
    ext_payload: Option<&[u8]>,
) -> Vec<u8> {
    let mut data = destination_hash.to_vec();
    if let Some(id) = transport_id {
        data.extend_from_slice(id);
    }
    data.extend_from_slice(tag);
    if let Some(ext) = ext_payload {
        data.extend_from_slice(ext);
    }
    data
}
