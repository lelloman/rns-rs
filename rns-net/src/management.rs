//! Remote management — re-exports from common, tests kept here.

pub use crate::common::management::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::{InterfaceEntry, InterfaceStats, Writer};
    use rns_core::constants;
    use rns_core::msgpack::{self, Value};
    use rns_core::transport::types::{InterfaceId, InterfaceInfo, TransportConfig};
    use rns_core::transport::TransportEngine;
    use std::collections::HashMap;
    use std::io;
    use crate::time;

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
            prefer_shorter_path: false,
            max_paths_per_destination: 1,
        })
    }

    fn make_interface_views() -> (HashMap<InterfaceId, InterfaceEntry>, Vec<InterfaceId>) {
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
        let ids: Vec<InterfaceId> = map.keys().copied().collect();
        (map, ids)
    }

    /// Helper: collect InterfaceEntry refs as trait object refs.
    fn as_views(map: &HashMap<InterfaceId, InterfaceEntry>) -> Vec<&dyn InterfaceStatusView> {
        map.values().map(|e| e as &dyn InterfaceStatusView).collect()
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

    #[test]
    fn test_status_request_basic() {
        let engine = make_engine();
        let (interfaces, _) = make_interface_views();
        let views = as_views(&interfaces);
        let started = time::now() - 100.0;

        let request = msgpack::pack(&Value::Array(vec![Value::Bool(false)]));
        let response = handle_status_request(&request, &engine, &views, started, None).unwrap();

        let val = msgpack::unpack_exact(&response).unwrap();
        match val {
            Value::Array(arr) => {
                assert_eq!(arr.len(), 1);
                match &arr[0] {
                    Value::Map(map) => {
                        let transport_id = map.iter()
                            .find(|(k, _)| *k == Value::Str("transport_id".into()))
                            .map(|(_, v)| v);
                        assert!(transport_id.is_some());

                        let rxb = map.iter()
                            .find(|(k, _)| *k == Value::Str("rxb".into()))
                            .map(|(_, v)| v.as_uint().unwrap());
                        assert_eq!(rxb, Some(1234));

                        let txb = map.iter()
                            .find(|(k, _)| *k == Value::Str("txb".into()))
                            .map(|(_, v)| v.as_uint().unwrap());
                        assert_eq!(txb, Some(5678));

                        let ifaces = map.iter()
                            .find(|(k, _)| *k == Value::Str("interfaces".into()))
                            .map(|(_, v)| v);
                        match ifaces {
                            Some(Value::Array(iface_arr)) => {
                                assert_eq!(iface_arr.len(), 1);
                            }
                            _ => panic!("Expected interfaces array"),
                        }

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
        let (interfaces, _) = make_interface_views();
        let views = as_views(&interfaces);
        let started = time::now();

        let request = msgpack::pack(&Value::Array(vec![Value::Bool(true)]));
        let response = handle_status_request(&request, &engine, &views, started, None).unwrap();

        let val = msgpack::unpack_exact(&response).unwrap();
        match val {
            Value::Array(arr) => {
                assert_eq!(arr.len(), 2);
                assert_eq!(arr[1].as_uint(), Some(0));
            }
            _ => panic!("Expected array response"),
        }
    }

    #[test]
    fn test_status_request_empty_data() {
        let engine = make_engine();
        let (interfaces, _) = make_interface_views();
        let views = as_views(&interfaces);
        let started = time::now();

        let response = handle_status_request(&[], &engine, &views, started, None).unwrap();
        let val = msgpack::unpack_exact(&response).unwrap();
        match val {
            Value::Array(arr) => assert_eq!(arr.len(), 1),
            _ => panic!("Expected array response"),
        }
    }

    #[test]
    fn test_path_request_table() {
        let engine = make_engine();
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

    #[test]
    fn test_build_management_announce() {
        use rns_crypto::identity::Identity;
        use rns_crypto::OsRng;

        let identity = Identity::new(&mut OsRng);
        let raw = build_management_announce(&identity, &mut OsRng);
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
