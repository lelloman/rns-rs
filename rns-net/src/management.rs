//! Remote management destinations for the Reticulum transport node.
//!
//! Implements the server-side handlers for:
//! - `/status` on `rnstransport.remote.management` destination
//! - `/path` on `rnstransport.remote.management` destination
//! - `/list` on `rnstransport.info.blackhole` destination
//!
//! Python reference: Transport.py:220-241, 2591-2643, 3243-3249

use std::collections::HashMap;

use rns_core::constants;
use rns_core::destination::destination_hash;
use rns_core::hash::truncated_hash;
use rns_core::msgpack::{self, Value};
use rns_core::transport::TransportEngine;

use crate::interface::InterfaceEntry;
use crate::time;

/// Get the path hash for "/status".
pub fn status_path_hash() -> [u8; 16] {
    truncated_hash(b"/status")
}

/// Get the path hash for "/path".
pub fn path_path_hash() -> [u8; 16] {
    truncated_hash(b"/path")
}

/// Get the path hash for "/list".
pub fn list_path_hash() -> [u8; 16] {
    truncated_hash(b"/list")
}

/// Check if a path hash matches a known management path.
pub fn is_management_path(path_hash: &[u8; 16]) -> bool {
    *path_hash == status_path_hash()
        || *path_hash == path_path_hash()
        || *path_hash == list_path_hash()
}

/// Compute the remote management destination hash.
///
/// Destination: `rnstransport.remote.management` with transport identity.
pub fn management_dest_hash(transport_identity_hash: &[u8; 16]) -> [u8; 16] {
    destination_hash("rnstransport", &["remote", "management"], Some(transport_identity_hash))
}

/// Compute the blackhole info destination hash.
///
/// Destination: `rnstransport.info.blackhole` with transport identity.
pub fn blackhole_dest_hash(transport_identity_hash: &[u8; 16]) -> [u8; 16] {
    destination_hash("rnstransport", &["info", "blackhole"], Some(transport_identity_hash))
}

/// Compute the probe responder destination hash.
///
/// Destination: `rnstransport.probe` with transport identity.
pub fn probe_dest_hash(transport_identity_hash: &[u8; 16]) -> [u8; 16] {
    destination_hash("rnstransport", &["probe"], Some(transport_identity_hash))
}

/// Build an announce packet for the probe responder destination.
///
/// Returns raw packet bytes ready for `engine.handle_outbound()`.
pub fn build_probe_announce(
    identity: &rns_crypto::identity::Identity,
    rng: &mut dyn rns_crypto::Rng,
) -> Option<Vec<u8>> {
    let identity_hash = *identity.hash();
    let dest_hash = probe_dest_hash(&identity_hash);
    let name_hash = rns_core::destination::name_hash("rnstransport", &["probe"]);
    let mut random_hash = [0u8; 10];
    rng.fill_bytes(&mut random_hash);

    let (announce_data, _has_ratchet) = rns_core::announce::AnnounceData::pack(
        identity,
        &dest_hash,
        &name_hash,
        &random_hash,
        None,
        None,
    )
    .ok()?;

    let flags = rns_core::packet::PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
    };

    let packet = rns_core::packet::RawPacket::pack(
        flags, 0, &dest_hash, None, constants::CONTEXT_NONE, &announce_data,
    )
    .ok()?;

    Some(packet.raw)
}

/// Management configuration.
#[derive(Debug, Clone)]
pub struct ManagementConfig {
    /// Enable remote management destination.
    pub enable_remote_management: bool,
    /// Identity hashes allowed to query management.
    pub remote_management_allowed: Vec<[u8; 16]>,
    /// Enable blackhole list publication.
    pub publish_blackhole: bool,
}

impl Default for ManagementConfig {
    fn default() -> Self {
        ManagementConfig {
            enable_remote_management: false,
            remote_management_allowed: Vec::new(),
            publish_blackhole: false,
        }
    }
}

/// Handle a `/status` request.
///
/// Request data: msgpack([include_lstats]) where include_lstats is bool.
/// Response: msgpack([interface_stats_dict, link_count?]) matching Python format.
pub fn handle_status_request(
    data: &[u8],
    engine: &TransportEngine,
    interfaces: &HashMap<rns_core::transport::types::InterfaceId, InterfaceEntry>,
    started: f64,
    probe_responder_hash: Option<[u8; 16]>,
) -> Option<Vec<u8>> {
    // Decode request data
    let include_lstats = match msgpack::unpack_exact(data) {
        Ok(Value::Array(arr)) if !arr.is_empty() => {
            arr[0].as_bool().unwrap_or(false)
        }
        _ => false,
    };

    // Build interface stats
    let mut iface_list = Vec::new();
    let mut total_rxb: u64 = 0;
    let mut total_txb: u64 = 0;

    for (id, entry) in interfaces {
        total_rxb += entry.stats.rxb;
        total_txb += entry.stats.txb;

        let mut ifstats: Vec<(&str, Value)> = Vec::new();
        ifstats.push(("name", Value::Str(entry.info.name.clone())));
        ifstats.push(("short_name", Value::Str(entry.info.name.clone())));
        ifstats.push(("status", Value::Bool(entry.online)));
        ifstats.push(("mode", Value::UInt(entry.info.mode as u64)));
        ifstats.push(("rxb", Value::UInt(entry.stats.rxb)));
        ifstats.push(("txb", Value::UInt(entry.stats.txb)));
        if let Some(br) = entry.info.bitrate {
            ifstats.push(("bitrate", Value::UInt(br)));
        } else {
            ifstats.push(("bitrate", Value::Nil));
        }
        ifstats.push(("incoming_announce_freq", Value::Float(entry.stats.incoming_announce_freq())));
        ifstats.push(("outgoing_announce_freq", Value::Float(entry.stats.outgoing_announce_freq())));
        ifstats.push(("held_announces", Value::UInt(engine.held_announce_count(id) as u64)));

        // IFAC info
        ifstats.push(("ifac_signature", Value::Nil));
        ifstats.push(("ifac_size", if entry.info.bitrate.is_some() {
            Value::UInt(0)
        } else {
            Value::Nil
        }));
        ifstats.push(("ifac_netname", Value::Nil));

        // Unused by Rust but expected by Python clients
        ifstats.push(("clients", Value::Nil));
        ifstats.push(("announce_queue", Value::Nil));
        ifstats.push(("rxs", Value::UInt(0)));
        ifstats.push(("txs", Value::UInt(0)));

        // Build as map
        let map = ifstats.into_iter()
            .map(|(k, v)| (Value::Str(k.into()), v))
            .collect();
        iface_list.push(Value::Map(map));
    }

    // Build top-level stats dict
    let mut stats: Vec<(&str, Value)> = Vec::new();
    stats.push(("interfaces", Value::Array(iface_list)));
    stats.push(("rxb", Value::UInt(total_rxb)));
    stats.push(("txb", Value::UInt(total_txb)));
    stats.push(("rxs", Value::UInt(0)));
    stats.push(("txs", Value::UInt(0)));

    if let Some(identity_hash) = engine.config().identity_hash {
        stats.push(("transport_id", Value::Bin(identity_hash.to_vec())));
        stats.push(("transport_uptime", Value::Float(time::now() - started)));
    }
    stats.push(("probe_responder", match probe_responder_hash {
        Some(hash) => Value::Bin(hash.to_vec()),
        None => Value::Nil,
    }));
    stats.push(("rss", Value::Nil));

    let stats_map = stats.into_iter()
        .map(|(k, v)| (Value::Str(k.into()), v))
        .collect();

    // Build response: [stats_dict] or [stats_dict, link_count]
    let mut response = vec![Value::Map(stats_map)];
    if include_lstats {
        let link_count = engine.link_table_count();
        response.push(Value::UInt(link_count as u64));
    }

    Some(msgpack::pack(&Value::Array(response)))
}

/// Handle a `/path` request.
///
/// Request data: msgpack([command, destination_hash?, max_hops?])
/// - command = "table" → returns path table entries
/// - command = "rates" → returns rate table entries
pub fn handle_path_request(
    data: &[u8],
    engine: &TransportEngine,
) -> Option<Vec<u8>> {
    let arr = match msgpack::unpack_exact(data) {
        Ok(Value::Array(arr)) if !arr.is_empty() => arr,
        _ => return None,
    };

    let command = match &arr[0] {
        Value::Str(s) => s.as_str(),
        _ => return None,
    };

    let dest_filter: Option<[u8; 16]> = if arr.len() > 1 {
        match &arr[1] {
            Value::Bin(b) if b.len() == 16 => {
                let mut h = [0u8; 16];
                h.copy_from_slice(b);
                Some(h)
            }
            _ => None,
        }
    } else {
        None
    };

    let max_hops: Option<u8> = if arr.len() > 2 {
        arr[2].as_uint().map(|v| v as u8)
    } else {
        None
    };

    match command {
        "table" => {
            let paths = engine.get_path_table(max_hops);
            let mut entries = Vec::new();
            for p in &paths {
                if let Some(ref filter) = dest_filter {
                    if p.0 != *filter {
                        continue;
                    }
                }
                // p = (dest_hash, timestamp, next_hop, hops, expires, interface)
                let entry = vec![
                    (Value::Str("hash".into()), Value::Bin(p.0.to_vec())),
                    (Value::Str("timestamp".into()), Value::Float(p.1)),
                    (Value::Str("via".into()), Value::Bin(p.2.to_vec())),
                    (Value::Str("hops".into()), Value::UInt(p.3 as u64)),
                    (Value::Str("expires".into()), Value::Float(p.4)),
                    (Value::Str("interface".into()), Value::Str(p.5.clone())),
                ];
                entries.push(Value::Map(entry));
            }
            Some(msgpack::pack(&Value::Array(entries)))
        }
        "rates" => {
            let rates = engine.get_rate_table();
            let mut entries = Vec::new();
            for r in &rates {
                if let Some(ref filter) = dest_filter {
                    if r.0 != *filter {
                        continue;
                    }
                }
                // r = (dest_hash, last, rate_violations, blocked_until, timestamps)
                let timestamps: Vec<Value> = r.4.iter().map(|t| Value::Float(*t)).collect();
                let entry = vec![
                    (Value::Str("hash".into()), Value::Bin(r.0.to_vec())),
                    (Value::Str("last".into()), Value::Float(r.1)),
                    (Value::Str("rate_violations".into()), Value::UInt(r.2 as u64)),
                    (Value::Str("blocked_until".into()), Value::Float(r.3)),
                    (Value::Str("timestamps".into()), Value::Array(timestamps)),
                ];
                entries.push(Value::Map(entry));
            }
            Some(msgpack::pack(&Value::Array(entries)))
        }
        _ => None,
    }
}

/// Handle a `/list` (blackhole list) request.
///
/// Returns the blackholed_identities dict as msgpack.
pub fn handle_blackhole_list_request(
    engine: &TransportEngine,
) -> Option<Vec<u8>> {
    let blackholed = engine.get_blackholed();
    let mut map_entries = Vec::new();
    for (hash, created, expires, reason) in &blackholed {
        let mut entry = vec![
            (Value::Str("created".into()), Value::Float(*created)),
            (Value::Str("expires".into()), Value::Float(*expires)),
        ];
        if let Some(r) = reason {
            entry.push((Value::Str("reason".into()), Value::Str(r.clone())));
        }
        map_entries.push((Value::Bin(hash.to_vec()), Value::Map(entry)));
    }
    Some(msgpack::pack(&Value::Map(map_entries)))
}

/// Build an announce packet for the management destination.
///
/// Returns raw packet bytes ready for `engine.handle_outbound()`.
pub fn build_management_announce(
    identity: &rns_crypto::identity::Identity,
    rng: &mut dyn rns_crypto::Rng,
) -> Option<Vec<u8>> {
    let identity_hash = *identity.hash();
    let dest_hash = management_dest_hash(&identity_hash);
    let name_hash = rns_core::destination::name_hash("rnstransport", &["remote", "management"]);
    let mut random_hash = [0u8; 10];
    rng.fill_bytes(&mut random_hash);

    let (announce_data, _has_ratchet) = rns_core::announce::AnnounceData::pack(
        identity,
        &dest_hash,
        &name_hash,
        &random_hash,
        None, // no ratchet
        None, // no app_data
    )
    .ok()?;

    let flags = rns_core::packet::PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
    };

    let packet = rns_core::packet::RawPacket::pack(
        flags, 0, &dest_hash, None, constants::CONTEXT_NONE, &announce_data,
    )
    .ok()?;

    Some(packet.raw)
}

/// Build an announce packet for the blackhole info destination.
///
/// Returns raw packet bytes ready for `engine.handle_outbound()`.
pub fn build_blackhole_announce(
    identity: &rns_crypto::identity::Identity,
    rng: &mut dyn rns_crypto::Rng,
) -> Option<Vec<u8>> {
    let identity_hash = *identity.hash();
    let dest_hash = blackhole_dest_hash(&identity_hash);
    let name_hash = rns_core::destination::name_hash("rnstransport", &["info", "blackhole"]);
    let mut random_hash = [0u8; 10];
    rng.fill_bytes(&mut random_hash);

    let (announce_data, _has_ratchet) = rns_core::announce::AnnounceData::pack(
        identity,
        &dest_hash,
        &name_hash,
        &random_hash,
        None,
        None,
    )
    .ok()?;

    let flags = rns_core::packet::PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
    };

    let packet = rns_core::packet::RawPacket::pack(
        flags, 0, &dest_hash, None, constants::CONTEXT_NONE, &announce_data,
    )
    .ok()?;

    Some(packet.raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::{InterfaceStats, Writer};
    use crate::ifac::IfacState;
    use rns_core::transport::types::{InterfaceId, InterfaceInfo, TransportConfig};
    use std::io;

    struct NullWriter;
    impl Writer for NullWriter {
        fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
            Ok(())
        }
    }

    fn make_engine() -> TransportEngine {
        TransportEngine::new(TransportConfig {
            transport_enabled: true,
            identity_hash: Some([0xAA; 16]),
        })
    }

    fn make_interfaces() -> HashMap<InterfaceId, InterfaceEntry> {
        let mut map = HashMap::new();
        let id = InterfaceId(1);
        let info = InterfaceInfo {
            id,
            name: "TestInterface".into(),
            mode: constants::MODE_FULL,
            out_capable: true,
            in_capable: true,
            bitrate: Some(115200),
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: rns_core::constants::MTU as u32,
            ia_freq: 0.0,
            started: 0.0,
            ingress_control: false,
        };
        map.insert(id, InterfaceEntry {
            id,
            info,
            writer: Box::new(NullWriter),
            online: true,
            dynamic: false,
            ifac: None,
            stats: InterfaceStats {
                rxb: 1234,
                txb: 5678,
                rx_packets: 10,
                tx_packets: 20,
                started: 1000.0,
                ia_timestamps: vec![],
                oa_timestamps: vec![],
            },
            interface_type: "TestInterface".to_string(),
        });
        map
    }

    #[test]
    fn test_management_dest_hash() {
        let id_hash = [0x42; 16];
        let dh = management_dest_hash(&id_hash);
        // Should be deterministic
        assert_eq!(dh, management_dest_hash(&id_hash));
        // Different identity → different hash
        assert_ne!(dh, management_dest_hash(&[0x43; 16]));
    }

    #[test]
    fn test_blackhole_dest_hash() {
        let id_hash = [0x42; 16];
        let dh = blackhole_dest_hash(&id_hash);
        assert_eq!(dh, blackhole_dest_hash(&id_hash));
        // Different from management dest
        assert_ne!(dh, management_dest_hash(&id_hash));
    }

    #[test]
    fn test_path_hashes_distinct() {
        let s = status_path_hash();
        let p = path_path_hash();
        let l = list_path_hash();
        assert_ne!(s, p);
        assert_ne!(s, l);
        assert_ne!(p, l);
        // Non-zero
        assert_ne!(s, [0u8; 16]);
    }

    #[test]
    fn test_management_config_default() {
        let config = ManagementConfig::default();
        assert!(!config.enable_remote_management);
        assert!(config.remote_management_allowed.is_empty());
        assert!(!config.publish_blackhole);
    }

    #[test]
    fn test_is_management_path() {
        assert!(is_management_path(&status_path_hash()));
        assert!(is_management_path(&path_path_hash()));
        assert!(is_management_path(&list_path_hash()));
        assert!(!is_management_path(&[0u8; 16]));
    }

    #[test]
    fn test_status_request_basic() {
        let engine = make_engine();
        let interfaces = make_interfaces();
        let started = time::now() - 100.0; // 100 seconds ago

        // Request with include_lstats = false
        let request = msgpack::pack(&Value::Array(vec![Value::Bool(false)]));
        let response = handle_status_request(&request, &engine, &interfaces, started, None).unwrap();

        // Decode response
        let val = msgpack::unpack_exact(&response).unwrap();
        match val {
            Value::Array(arr) => {
                assert_eq!(arr.len(), 1); // no link stats
                match &arr[0] {
                    Value::Map(map) => {
                        // Check that transport_id is present
                        let transport_id = map.iter()
                            .find(|(k, _)| *k == Value::Str("transport_id".into()))
                            .map(|(_, v)| v);
                        assert!(transport_id.is_some());

                        // Check rxb/txb totals
                        let rxb = map.iter()
                            .find(|(k, _)| *k == Value::Str("rxb".into()))
                            .map(|(_, v)| v.as_uint().unwrap());
                        assert_eq!(rxb, Some(1234));

                        let txb = map.iter()
                            .find(|(k, _)| *k == Value::Str("txb".into()))
                            .map(|(_, v)| v.as_uint().unwrap());
                        assert_eq!(txb, Some(5678));

                        // Check interfaces array
                        let ifaces = map.iter()
                            .find(|(k, _)| *k == Value::Str("interfaces".into()))
                            .map(|(_, v)| v);
                        match ifaces {
                            Some(Value::Array(iface_arr)) => {
                                assert_eq!(iface_arr.len(), 1);
                            }
                            _ => panic!("Expected interfaces array"),
                        }

                        // Check uptime
                        let uptime = map.iter()
                            .find(|(k, _)| *k == Value::Str("transport_uptime".into()))
                            .and_then(|(_, v)| v.as_float());
                        assert!(uptime.unwrap() >= 100.0);
                    }
                    _ => panic!("Expected map in response"),
                }
            }
            _ => panic!("Expected array response"),
        }
    }

    #[test]
    fn test_status_request_with_lstats() {
        let engine = make_engine();
        let interfaces = make_interfaces();
        let started = time::now();

        let request = msgpack::pack(&Value::Array(vec![Value::Bool(true)]));
        let response = handle_status_request(&request, &engine, &interfaces, started, None).unwrap();

        let val = msgpack::unpack_exact(&response).unwrap();
        match val {
            Value::Array(arr) => {
                assert_eq!(arr.len(), 2); // stats + link count
                assert_eq!(arr[1].as_uint(), Some(0)); // no links
            }
            _ => panic!("Expected array response"),
        }
    }

    #[test]
    fn test_status_request_empty_data() {
        let engine = make_engine();
        let interfaces = make_interfaces();
        let started = time::now();

        // Empty data should still work (include_lstats defaults to false)
        let response = handle_status_request(&[], &engine, &interfaces, started, None).unwrap();
        let val = msgpack::unpack_exact(&response).unwrap();
        match val {
            Value::Array(arr) => assert_eq!(arr.len(), 1),
            _ => panic!("Expected array response"),
        }
    }

    #[test]
    fn test_path_request_table() {
        let engine = make_engine();

        // Request table with no entries
        let request = msgpack::pack(&Value::Array(vec![Value::Str("table".into())]));
        let response = handle_path_request(&request, &engine).unwrap();
        let val = msgpack::unpack_exact(&response).unwrap();
        match val {
            Value::Array(arr) => assert_eq!(arr.len(), 0),
            _ => panic!("Expected array"),
        }
    }

    #[test]
    fn test_path_request_rates() {
        let engine = make_engine();

        let request = msgpack::pack(&Value::Array(vec![Value::Str("rates".into())]));
        let response = handle_path_request(&request, &engine).unwrap();
        let val = msgpack::unpack_exact(&response).unwrap();
        match val {
            Value::Array(arr) => assert_eq!(arr.len(), 0),
            _ => panic!("Expected array"),
        }
    }

    #[test]
    fn test_path_request_unknown_command() {
        let engine = make_engine();

        let request = msgpack::pack(&Value::Array(vec![Value::Str("unknown".into())]));
        let response = handle_path_request(&request, &engine);
        assert!(response.is_none());
    }

    #[test]
    fn test_path_request_invalid_data() {
        let engine = make_engine();
        let response = handle_path_request(&[], &engine);
        assert!(response.is_none());
    }

    #[test]
    fn test_blackhole_list_empty() {
        let engine = make_engine();
        let response = handle_blackhole_list_request(&engine).unwrap();
        let val = msgpack::unpack_exact(&response).unwrap();
        match val {
            Value::Map(entries) => assert_eq!(entries.len(), 0),
            _ => panic!("Expected map"),
        }
    }

    // Phase 8c: Announce building tests

    #[test]
    fn test_build_management_announce() {
        use rns_crypto::identity::Identity;
        use rns_crypto::OsRng;

        let identity = Identity::new(&mut OsRng);
        let raw = build_management_announce(&identity, &mut OsRng);
        assert!(raw.is_some(), "Should build management announce");

        let raw = raw.unwrap();
        // Parse it as a valid packet
        let pkt = rns_core::packet::RawPacket::unpack(&raw).unwrap();
        assert_eq!(pkt.flags.packet_type, constants::PACKET_TYPE_ANNOUNCE);
        assert_eq!(pkt.flags.destination_type, constants::DESTINATION_SINGLE);
        assert_eq!(pkt.destination_hash, management_dest_hash(identity.hash()));
    }

    #[test]
    fn test_build_blackhole_announce() {
        use rns_crypto::identity::Identity;
        use rns_crypto::OsRng;

        let identity = Identity::new(&mut OsRng);
        let raw = build_blackhole_announce(&identity, &mut OsRng);
        assert!(raw.is_some(), "Should build blackhole announce");

        let raw = raw.unwrap();
        let pkt = rns_core::packet::RawPacket::unpack(&raw).unwrap();
        assert_eq!(pkt.flags.packet_type, constants::PACKET_TYPE_ANNOUNCE);
        assert_eq!(pkt.destination_hash, blackhole_dest_hash(identity.hash()));
    }

    #[test]
    fn test_management_announce_validates() {
        use rns_crypto::identity::Identity;
        use rns_crypto::OsRng;

        let identity = Identity::new(&mut OsRng);
        let raw = build_management_announce(&identity, &mut OsRng).unwrap();

        let pkt = rns_core::packet::RawPacket::unpack(&raw).unwrap();

        // Validate the announce data
        let validated = rns_core::announce::AnnounceData::unpack(&pkt.data, false);
        assert!(validated.is_ok(), "Announce data should unpack");

        let ann = validated.unwrap();
        let result = ann.validate(&pkt.destination_hash);
        assert!(result.is_ok(), "Announce should validate: {:?}", result.err());
    }

    #[test]
    fn test_blackhole_announce_validates() {
        use rns_crypto::identity::Identity;
        use rns_crypto::OsRng;

        let identity = Identity::new(&mut OsRng);
        let raw = build_blackhole_announce(&identity, &mut OsRng).unwrap();

        let pkt = rns_core::packet::RawPacket::unpack(&raw).unwrap();
        let ann = rns_core::announce::AnnounceData::unpack(&pkt.data, false).unwrap();
        let result = ann.validate(&pkt.destination_hash);
        assert!(result.is_ok(), "Blackhole announce should validate: {:?}", result.err());
    }

    #[test]
    fn test_probe_dest_hash() {
        let id_hash = [0x42; 16];
        let dh = probe_dest_hash(&id_hash);
        // Should be deterministic
        assert_eq!(dh, probe_dest_hash(&id_hash));
        // Different identity → different hash
        assert_ne!(dh, probe_dest_hash(&[0x43; 16]));
        // Different from management and blackhole dests
        assert_ne!(dh, management_dest_hash(&id_hash));
        assert_ne!(dh, blackhole_dest_hash(&id_hash));
    }

    #[test]
    fn test_build_probe_announce() {
        use rns_crypto::identity::Identity;
        use rns_crypto::OsRng;

        let identity = Identity::new(&mut OsRng);
        let raw = build_probe_announce(&identity, &mut OsRng);
        assert!(raw.is_some(), "Should build probe announce");

        let raw = raw.unwrap();
        let pkt = rns_core::packet::RawPacket::unpack(&raw).unwrap();
        assert_eq!(pkt.flags.packet_type, constants::PACKET_TYPE_ANNOUNCE);
        assert_eq!(pkt.flags.destination_type, constants::DESTINATION_SINGLE);
        assert_eq!(pkt.destination_hash, probe_dest_hash(identity.hash()));
    }

    #[test]
    fn test_probe_announce_validates() {
        use rns_crypto::identity::Identity;
        use rns_crypto::OsRng;

        let identity = Identity::new(&mut OsRng);
        let raw = build_probe_announce(&identity, &mut OsRng).unwrap();
        let pkt = rns_core::packet::RawPacket::unpack(&raw).unwrap();
        let ann = rns_core::announce::AnnounceData::unpack(&pkt.data, false).unwrap();
        let result = ann.validate(&pkt.destination_hash);
        assert!(result.is_ok(), "Probe announce should validate: {:?}", result.err());
    }

    #[test]
    fn test_management_announce_different_from_blackhole() {
        use rns_crypto::identity::Identity;
        use rns_crypto::OsRng;

        let identity = Identity::new(&mut OsRng);
        let mgmt_raw = build_management_announce(&identity, &mut OsRng).unwrap();
        let bh_raw = build_blackhole_announce(&identity, &mut OsRng).unwrap();

        let mgmt_pkt = rns_core::packet::RawPacket::unpack(&mgmt_raw).unwrap();
        let bh_pkt = rns_core::packet::RawPacket::unpack(&bh_raw).unwrap();

        assert_ne!(mgmt_pkt.destination_hash, bh_pkt.destination_hash,
            "Management and blackhole should have different dest hashes");
    }
}
