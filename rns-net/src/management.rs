//! The node's built-in management destinations.

pub(crate) use crate::common::management::*;
pub use crate::common::management::{blackhole_dest_hash, ManagementConfig};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time;
    use rns_core::constants;
    use rns_core::msgpack::{self, Value};
    use rns_core::transport::types::{TransportConfig, DEFAULT_MAX_PATH_DESTINATIONS};
    use rns_core::transport::TransportEngine;

    fn make_engine() -> TransportEngine {
        TransportEngine::new(TransportConfig {
            transport_enabled: true,
            identity_hash: Some([0xAA; 16]),
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
            unresponsive_path_recovery:
                rns_core::transport::types::UnresponsivePathRecovery::Native,
            packet_hashlist_max_entries: rns_core::constants::HASHLIST_MAXSIZE,
            packet_hashlist_allocation: rns_core::transport::types::PacketHashlistAllocation::Eager,
            max_discovery_pr_tags: rns_core::constants::MAX_PR_TAGS,
            max_path_destinations: DEFAULT_MAX_PATH_DESTINATIONS,
            max_tunnel_destinations_total: usize::MAX,
            destination_timeout_secs: rns_core::constants::DESTINATION_TIMEOUT,
            announce_table_ttl_secs: rns_core::constants::ANNOUNCE_TABLE_TTL,
            announce_table_max_bytes: rns_core::constants::ANNOUNCE_TABLE_MAX_BYTES,
            announce_sig_cache_enabled: true,
            announce_sig_cache_max_entries: rns_core::constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
            announce_sig_cache_ttl_secs: rns_core::constants::ANNOUNCE_SIG_CACHE_TTL,
            announce_queue_max_entries: 256,
            announce_queue_max_interfaces: 1024,
        })
    }

    #[test]
    fn test_management_dest_hash() {
        let id_hash = [0x42; 16];
        let dh = management_dest_hash(&id_hash);
        assert_eq!(dh, management_dest_hash(&id_hash));
        assert_ne!(dh, management_dest_hash(&[0x43; 16]));
    }

    #[test]
    fn test_blackhole_dest_hash() {
        let id_hash = [0x42; 16];
        let dh = blackhole_dest_hash(&id_hash);
        assert_eq!(dh, blackhole_dest_hash(&id_hash));
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

    fn status_reply(data: &[u8]) -> Option<Vec<Value>> {
        let stats = Value::Map(vec![(Value::Str("rxb".into()), Value::UInt(7))]);
        let response = handle_status_request(data, stats, 3)?;
        let Value::Array(items) = msgpack::unpack_exact(&response).unwrap() else {
            panic!("expected status response array");
        };
        Some(items)
    }

    #[test]
    fn status_request_answers_the_stats_it_is_given() {
        let items = status_reply(&msgpack::pack(&Value::Array(vec![Value::Bool(false)]))).unwrap();
        assert_eq!(
            items,
            vec![Value::Map(vec![(Value::Str("rxb".into()), Value::UInt(7))])]
        );
    }

    #[test]
    fn status_request_adds_the_link_count_when_asked() {
        let items = status_reply(&msgpack::pack(&Value::Array(vec![Value::Bool(true)]))).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[1], Value::UInt(3));
    }

    #[test]
    fn status_request_adds_profiling_results_when_asked() {
        {
            let _sample = crate::profiling::profile("entry110.remote");
        }
        let request = msgpack::pack(&Value::Array(vec![Value::Bool(true), Value::Bool(true)]));
        let items = status_reply(&request).unwrap();
        assert_eq!(items.len(), 3);
        assert!(matches!(items[2], Value::Map(_)));
        let request = msgpack::pack(&Value::Array(vec![Value::Bool(false), Value::Bool(true)]));
        assert_eq!(status_reply(&request).unwrap().len(), 2);
    }

    /// As upstream's handler: only a non-empty list is answered.
    #[test]
    fn status_request_without_a_flag_list_is_not_answered() {
        assert!(status_reply(&[]).is_none());
        assert!(status_reply(&msgpack::pack(&Value::Array(Vec::new()))).is_none());
        assert!(status_reply(&msgpack::pack(&Value::Bool(true))).is_none());
    }

    fn entry(fields: &[(&str, Value)]) -> Value {
        Value::Map(
            fields
                .iter()
                .map(|(k, v)| (Value::Str((*k).into()), v.clone()))
                .collect(),
        )
    }

    fn table() -> Vec<Value> {
        (1..=3u8)
            .map(|i| {
                entry(&[
                    ("hash", Value::Bin(vec![i; 16])),
                    ("hops", Value::UInt(i as u64)),
                ])
            })
            .collect()
    }

    fn rates() -> Vec<Value> {
        vec![entry(&[
            ("last", Value::Float(1.0)),
            ("hash", Value::Bin(vec![2; 16])),
        ])]
    }

    /// The hashes of the entries a `/path` request is answered with.
    fn answer(request: Value) -> Option<Vec<u8>> {
        let response = handle_path_request(&msgpack::pack(&request), table, rates)?;
        let Value::Array(entries) = msgpack::unpack_exact(&response).unwrap() else {
            panic!("expected a list");
        };
        Some(
            entries
                .iter()
                .map(|e| {
                    e.as_map()
                        .unwrap()
                        .iter()
                        .find(|(k, _)| k.as_str() == Some("hash"))
                        .and_then(|(_, v)| v.as_bin())
                        .unwrap()[0]
                })
                .collect(),
        )
    }

    /// As upstream's `remote_path_handler`.
    #[test]
    fn path_requests_are_answered_as_upstream() {
        let s = |s: &str| Value::Str(s.into());
        assert_eq!(answer(Value::Array(vec![s("table")])), Some(vec![1, 2, 3]));
        assert_eq!(
            answer(Value::Array(vec![s("table"), Value::Nil, Value::UInt(2)])),
            Some(vec![1, 2])
        );
        assert_eq!(
            answer(Value::Array(vec![
                s("table"),
                Value::Nil,
                Value::Float(1.5)
            ])),
            Some(vec![1])
        );
        assert_eq!(
            answer(Value::Array(vec![s("table"), Value::Bin(vec![3; 16])])),
            Some(vec![3])
        );
        // A destination that is no entry's hash, whatever its type, matches
        // none.
        assert_eq!(
            answer(Value::Array(vec![s("table"), Value::Bin(vec![3; 4])])),
            Some(vec![])
        );
        assert_eq!(answer(Value::Array(vec![s("table"), s("x")])), Some(vec![]));
        assert_eq!(answer(Value::Array(vec![s("rates")])), Some(vec![2]));
        assert_eq!(
            answer(Value::Array(vec![s("rates"), Value::Bin(vec![1; 16])])),
            Some(vec![])
        );
        // Upstream returns None, which is not sent.
        assert_eq!(answer(Value::Array(vec![s("unknown")])), None);
        assert_eq!(answer(Value::Array(vec![])), None);
        assert_eq!(answer(s("table")), None);
        assert_eq!(
            answer(Value::Array(vec![s("table"), Value::Nil, s("2")])),
            None
        );
        assert!(handle_path_request(&[], table, rates).is_none());
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

    #[test]
    fn test_build_management_announce() {
        use rns_crypto::identity::Identity;
        use rns_crypto::OsRng;

        let identity = Identity::new(&mut OsRng);
        let raw = build_management_announce(&identity, &mut OsRng, time::now(), false);
        assert!(raw.is_some(), "Should build management announce");

        let raw = raw.unwrap();
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
        let raw = build_blackhole_announce(&identity, &mut OsRng, time::now(), false);
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
        let raw = build_management_announce(&identity, &mut OsRng, time::now(), false).unwrap();
        let pkt = rns_core::packet::RawPacket::unpack(&raw).unwrap();
        let validated = rns_core::announce::AnnounceData::unpack(pkt.data(), false);
        assert!(validated.is_ok(), "Announce data should unpack");
        let ann = validated.unwrap();
        let result = ann.validate(&pkt.destination_hash);
        assert!(
            result.is_ok(),
            "Announce should validate: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_blackhole_announce_validates() {
        use rns_crypto::identity::Identity;
        use rns_crypto::OsRng;

        let identity = Identity::new(&mut OsRng);
        let raw = build_blackhole_announce(&identity, &mut OsRng, time::now(), false).unwrap();
        let pkt = rns_core::packet::RawPacket::unpack(&raw).unwrap();
        let ann = rns_core::announce::AnnounceData::unpack(pkt.data(), false).unwrap();
        let result = ann.validate(&pkt.destination_hash);
        assert!(
            result.is_ok(),
            "Blackhole announce should validate: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_probe_dest_hash() {
        let id_hash = [0x42; 16];
        let dh = probe_dest_hash(&id_hash);
        assert_eq!(dh, probe_dest_hash(&id_hash));
        assert_ne!(dh, probe_dest_hash(&[0x43; 16]));
        assert_ne!(dh, management_dest_hash(&id_hash));
        assert_ne!(dh, blackhole_dest_hash(&id_hash));
    }

    #[test]
    fn test_build_probe_announce() {
        use rns_crypto::identity::Identity;
        use rns_crypto::OsRng;

        let identity = Identity::new(&mut OsRng);
        let raw = build_probe_announce(&identity, &mut OsRng, time::now(), false);
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
        let raw = build_probe_announce(&identity, &mut OsRng, time::now(), false).unwrap();
        let pkt = rns_core::packet::RawPacket::unpack(&raw).unwrap();
        let ann = rns_core::announce::AnnounceData::unpack(pkt.data(), false).unwrap();
        let result = ann.validate(&pkt.destination_hash);
        assert!(
            result.is_ok(),
            "Probe announce should validate: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_management_announce_different_from_blackhole() {
        use rns_crypto::identity::Identity;
        use rns_crypto::OsRng;

        let identity = Identity::new(&mut OsRng);
        let mgmt_raw =
            build_management_announce(&identity, &mut OsRng, time::now(), false).unwrap();
        let bh_raw = build_blackhole_announce(&identity, &mut OsRng, time::now(), false).unwrap();

        let mgmt_pkt = rns_core::packet::RawPacket::unpack(&mgmt_raw).unwrap();
        let bh_pkt = rns_core::packet::RawPacket::unpack(&bh_raw).unwrap();

        assert_ne!(
            mgmt_pkt.destination_hash, bh_pkt.destination_hash,
            "Management and blackhole should have different dest hashes"
        );
    }

    #[test]
    fn test_builtin_announces_encode_emission_time() {
        use rns_core::transport::pathfinder::timebase_from_random_blob;
        use rns_crypto::identity::Identity;
        use rns_crypto::OsRng;

        let identity = Identity::new(&mut OsRng);
        let now = time::now();
        let builders: [(&str, Option<Vec<u8>>); 3] = [
            (
                "management",
                build_management_announce(&identity, &mut OsRng, now, false),
            ),
            (
                "blackhole",
                build_blackhole_announce(&identity, &mut OsRng, now, false),
            ),
            (
                "probe",
                build_probe_announce(&identity, &mut OsRng, now, false),
            ),
        ];
        for (label, raw) in builders {
            let raw = raw.unwrap_or_else(|| panic!("{label} announce should build"));
            let pkt = rns_core::packet::RawPacket::unpack(&raw).unwrap();
            // public key (64) + name hash (10), then the 10-byte random blob.
            let blob: [u8; 10] = pkt.data()[74..84].try_into().unwrap();
            let emitted = timebase_from_random_blob(&blob) as f64;
            assert!(
                (emitted - now).abs() <= 60.0,
                "{label} announce emission time {emitted} not within 60 s of {now}"
            );
        }
    }

    #[test]
    fn test_announce_random_blob_layout() {
        use rns_core::transport::pathfinder::timebase_from_random_blob;
        use rns_crypto::OsRng;

        let blob = announce_random_blob(&mut OsRng, 1_700_000_000.7);
        assert_eq!(timebase_from_random_blob(&blob), 1_700_000_000);
        assert_eq!(&blob[5..10], &1_700_000_000u64.to_be_bytes()[3..8]);
    }

    #[test]
    fn test_builtin_announces_path_response_context() {
        use rns_crypto::identity::Identity;
        use rns_crypto::OsRng;

        let identity = Identity::new(&mut OsRng);
        let now = time::now();
        for path_response in [false, true] {
            let expected = if path_response {
                constants::CONTEXT_PATH_RESPONSE
            } else {
                constants::CONTEXT_NONE
            };
            for raw in [
                build_management_announce(&identity, &mut OsRng, now, path_response),
                build_blackhole_announce(&identity, &mut OsRng, now, path_response),
                build_probe_announce(&identity, &mut OsRng, now, path_response),
            ] {
                let pkt = rns_core::packet::RawPacket::unpack(&raw.unwrap()).unwrap();
                assert_eq!(pkt.context, expected);
                let ann = rns_core::announce::AnnounceData::unpack(pkt.data(), false).unwrap();
                assert!(ann.validate(&pkt.destination_hash).is_ok());
            }
        }
    }
}
