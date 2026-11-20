//! Entry point for the fuzz targets in `fuzz/`: every packet a transport
//! node takes from its interfaces. Not a stable API.

use super::*;

/// A transport node's configuration, as the engine's tests and the fuzz
/// target build it.
pub fn config(transport_enabled: bool) -> TransportConfig {
    TransportConfig {
        transport_enabled,
        identity_hash: transport_enabled.then_some([0x42; 16]),
        local_hops_delta: 0,
        prefer_shorter_path: false,
        max_paths_per_destination: 1,
        unresponsive_path_recovery: crate::transport::types::UnresponsivePathRecovery::Native,
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

/// An interface in `mode`, as the engine's tests and the fuzz target build
/// it.
pub fn interface(id: u64, mode: u8) -> InterfaceInfo {
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
        shared_medium: false,
        hop_limiter: None,
        tunnel_id: None,
        mtu: constants::MTU as u32,
        mtu_upgradable: false,
        ingress_control: types::IngressControlConfig::disabled(),
        ia_freq: 0.0,
        ia_samples: 0,
        ip_freq: 0.0,
        op_freq: 0.0,
        op_samples: 0,
        started: 0.0,
    }
}

/// Feed `data`, as a sequence of packets, to a transport node with two
/// interfaces. Each packet is a two-byte length whose top bit picks the
/// interface, then that many bytes; the clock advances a second per packet
/// and the node runs its periodic jobs every eight.
pub fn inbound(data: &[u8]) {
    // A node's hashlist grows with what it has seen, as by default; the
    // tests' eager one would cost every run the full table.
    let mut engine = TransportEngine::new(TransportConfig {
        packet_hashlist_allocation: types::PacketHashlistAllocation::Lazy,
        ..config(true)
    });
    engine.register_interface(interface(1, constants::MODE_FULL));
    engine.register_interface(interface(2, constants::MODE_FULL));
    let mut rng = rns_crypto::FixedRng::new(&[0x5a, 0x3c, 0x96]);
    let mut rest = data;
    let mut now = 1_000.0;
    let mut count = 0u32;
    while let Some((header, tail)) = rest.split_first_chunk::<2>() {
        let header = u16::from_be_bytes(*header);
        let iface = InterfaceId(1 + u64::from(header >> 15));
        let (raw, tail) = tail.split_at((usize::from(header & 0x7fff)).min(tail.len()));
        rest = tail;
        now += 1.0;
        let _ = engine.handle_inbound(InboundFrame::new(raw, iface, now), &mut rng);
        count += 1;
        if count.is_multiple_of(8) {
            let _ = engine.tick(now, &mut rng);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_takes_any_bytes() {
        let mut path_request = vec![0x00, 0x00];
        path_request.extend_from_slice(&[0x08, 0x00]);
        path_request.extend_from_slice(&[0x6b; 16]);
        path_request.push(constants::CONTEXT_NONE);
        path_request.extend_from_slice(&[0x11; 32]);
        let len = (path_request.len() - 2) as u16 | 0x8000;
        path_request[..2].copy_from_slice(&len.to_be_bytes());
        let inputs: [&[u8]; 5] = [b"", &[0xff], &[0x7f, 0xff, 1, 2], &[0; 600], &path_request];
        for data in inputs {
            inbound(data);
        }
    }
}
