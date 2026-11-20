use super::super::engine_fixtures::{engine, interface, path_entry, path_request};
use super::*;

fn known_path(engine: &mut TransportEngine, destination: [u8; 16], via: InterfaceId) {
    engine.paths.table.insert(
        destination,
        PathSet::from_single(path_entry(&destination, 900.0, 2, via, [0xBB; 16]), 1),
    );
}

/// Transport.py:3976-3984: a node is not told of a path whose next hop is
/// the node itself, and the request is not searched for further either.
#[test]
fn path_request_from_the_next_hop_is_not_answered() {
    let mut engine = engine(true);
    engine.set_stamp_prs(false);
    engine.register_interface(interface(1, constants::MODE_ACCESS_POINT));
    engine.register_interface(interface(2, constants::MODE_FULL));
    let destination = [0xD1; 16];
    known_path(&mut engine, destination, InterfaceId(2));

    let from_next_hop = path_request(&destination, Some(&[0xBB; 16]), &[0x01; 16], None);
    let actions = engine.handle_path_request(&from_next_hop, InterfaceId(1), 1000.0);
    assert!(actions.is_empty());
    assert!(!engine.announces.table.contains_key(&destination));
    assert!(!engine.path_requests.discovery.contains_key(&destination));

    let from_another = path_request(&destination, Some(&[0xCC; 16]), &[0x02; 16], None);
    engine.handle_path_request(&from_another, InterfaceId(1), 1000.0);
    assert!(engine.announces.table.contains_key(&destination));

    // A legacy request carries no transport id and is answered.
    let mut engine = super::super::engine_fixtures::engine(true);
    engine.register_interface(interface(1, constants::MODE_ACCESS_POINT));
    known_path(&mut engine, destination, InterfaceId(2));
    let legacy = path_request(&destination, None, &[0xBB; 16], None);
    engine.handle_path_request(&legacy, InterfaceId(1), 1000.0);
    assert!(engine.announces.table.contains_key(&destination));
}

fn sent_interfaces(actions: &[TransportAction]) -> Vec<InterfaceId> {
    actions
        .iter()
        .filter_map(|action| match action {
            TransportAction::SendOnInterface { interface, .. } => Some(*interface),
            _ => None,
        })
        .collect()
}

#[test]
fn egress_limit_check_uses_the_interface_settings() {
    let mut engine = engine(true);
    let mut limited = interface(1, constants::MODE_FULL);
    limited.ingress_control.egress_enabled = true;
    engine.register_interface(limited);
    engine.register_interface(interface(2, constants::MODE_FULL));
    let freq = constants::EC_PR_FREQ * 2.0;
    let samples = constants::EC_BURST_MIN_SAMPLES;

    assert!(engine.should_egress_limit_path_request(InterfaceId(1), freq, samples));
    assert!(!engine.should_egress_limit_path_request(InterfaceId(1), 0.0, samples));
    assert!(!engine.should_egress_limit_path_request(InterfaceId(2), freq, samples));
    assert!(!engine.should_egress_limit_path_request(InterfaceId(9), freq, samples));
}

/// Upstream only searches for unknown paths with transport enabled.
#[test]
fn without_transport_an_unknown_path_is_not_searched_for() {
    let mut engine = engine(false);
    engine.set_stamp_prs(false);
    engine.register_interface(interface(1, constants::MODE_ACCESS_POINT));
    engine.register_interface(interface(2, constants::MODE_FULL));
    let request = path_request(&[0xD2; 16], Some(&[0x99; 16]), &[0x01; 16], None);
    assert!(engine
        .handle_path_request(&request, InterfaceId(1), 1000.0)
        .is_empty());
    assert!(engine.path_requests.discovery.is_empty());
}

#[test]
fn path_request_shorter_than_a_destination_hash_is_dropped() {
    let mut engine = engine(true);
    engine.register_interface(interface(1, constants::MODE_ACCESS_POINT));
    assert!(engine
        .handle_path_request(&[0xD3; 10], InterfaceId(1), 1000.0)
        .is_empty());
    assert!(engine.path_requests.gates.is_empty());
}

/// An extension without the stamp marker carries no stamp, so a node
/// enforcing stamps drops the request even at a path request cost of zero.
#[test]
fn extension_without_the_stamp_marker_is_unstamped() {
    let mut engine = engine(true);
    engine.register_interface(interface(1, constants::MODE_ACCESS_POINT));
    engine.register_interface(interface(2, constants::MODE_FULL));
    engine.set_stamp_requirements(StampRequirements {
        enforced: true,
        destination_cost: constants::DESTINATION_STAMP_COST,
        path_request_cost: crate::stamp::StampCost::ZERO,
    });
    let mut ext = [0xAA; constants::PR_EXT_PAYLOAD_LENGTH];
    ext[0] = constants::EXT_PAYLOAD_MARKER.wrapping_add(1);
    let request = path_request(&[0xD4; 16], Some(&[0x99; 16]), &[0x01; 16], Some(&ext));
    assert!(engine
        .accept_path_request(&request, InterfaceId(1), 1000.0)
        .is_none());

    ext[0] = constants::EXT_PAYLOAD_MARKER;
    let request = path_request(&[0xD4; 16], Some(&[0x99; 16]), &[0x02; 16], Some(&ext));
    let accepted = engine
        .accept_path_request(&request, InterfaceId(1), 1000.0)
        .expect("a marked stamp meets a cost of zero");
    assert!(accepted.stamped());
}

/// A request batched into a search this node started itself gets the
/// search's deadline of PATH_REQUEST_TIMEOUT from when it arrived.
#[test]
fn batched_request_sets_the_search_deadline() {
    let mut engine = engine(true);
    engine.register_interface(interface(1, constants::MODE_ACCESS_POINT));
    let destination = [0xD5; 16];
    engine.record_outbound_path_request(destination, 990.0);
    let request = path_request(&destination, Some(&[0x99; 16]), &[0x01; 16], None);
    assert!(engine
        .handle_path_request(&request, InterfaceId(1), 1000.0)
        .is_empty());
    assert_eq!(
        engine.path_requests.discovery_deadlines.get(&destination),
        Some(&(1000.0 + constants::PATH_REQUEST_TIMEOUT))
    );
}

#[test]
fn discovery_sets_the_search_deadline_and_reserves_the_request_airtime() {
    let mut engine = engine(true);
    engine.set_stamp_prs(false);
    engine.register_interface(interface(1, constants::MODE_ACCESS_POINT));
    let mut egress = interface(2, constants::MODE_FULL);
    egress.bitrate = Some(constants::MINIMUM_BITRATE.max(1_000_000));
    let bitrate = egress.bitrate.unwrap();
    engine.register_interface(egress);
    let destination = [0xD6; 16];
    let request = path_request(&destination, Some(&[0x99; 16]), &[0x01; 16], None);
    let actions = engine.handle_path_request(&request, InterfaceId(1), 1000.0);
    assert_eq!(sent_interfaces(&actions), vec![InterfaceId(2)]);

    let timeout = discovery_path_request_timeout(&engine.interfaces);
    assert_eq!(
        engine.path_requests.discovery_deadlines.get(&destination),
        Some(&(1000.0 + timeout))
    );
    // Transport.py:3895: the request's data plus HEADER_MINSIZE.
    let data_len = request.len();
    let tx_time = ((data_len + constants::HEADER_MINSIZE) * 8) as f64 / bitrate as f64;
    let allowed_at = engine
        .announces
        .queues
        .queue_for(&InterfaceId(2))
        .unwrap()
        .announce_allowed_at;
    assert!((allowed_at - (1000.0 + tx_time / constants::ANNOUNCE_CAP)).abs() < 1e-9);
}

#[test]
fn stamp_settings_read_back_what_was_set() {
    let mut engine = engine(true);
    engine.set_stamp_prs(true);
    assert!(engine.stamp_prs());
    engine.set_stamp_prs(false);
    assert!(!engine.stamp_prs());

    let requirements = StampRequirements {
        enforced: !constants::STAMPS_ENFORCED,
        destination_cost: crate::stamp::StampCost::from_whole(3),
        path_request_cost: crate::stamp::StampCost::from_whole(5),
    };
    engine.set_stamp_requirements(requirements);
    assert_eq!(engine.stamp_requirements(), requirements);

    let blocked = super::super::destination_filter::destination_type("lxmf.delivery");
    engine.destination_filter_mut().block(blocked);
    assert!(engine.destination_filter().blocks(&blocked));
}

#[test]
fn build_path_request_carries_the_transport_id_tag_and_extension() {
    let engine = engine(true);
    let destination = [0xD7; 16];
    let ext = [0x5A; constants::PR_EXT_PAYLOAD_LENGTH];
    let raw = engine
        .build_path_request(&destination, &[0x01; 16], Some(&ext))
        .unwrap();
    let packet = RawPacket::unpack(&raw).unwrap();
    assert_eq!(
        packet.destination_hash,
        crate::destination::destination_hash("rnstransport", &["path", "request"], None)
    );
    assert_eq!(
        packet.data(),
        path_request(&destination, Some(&[0x42; 16]), &[0x01; 16], Some(&ext))
    );
}

/// Transport.py:3974: on a roaming interface, a path learned on that same
/// interface is not answered; one learned elsewhere is, after the grace
/// time plus PATH_REQUEST_RG.
#[test]
fn roaming_interface_answers_only_paths_learned_elsewhere() {
    let destination = [0xD8; 16];
    let mut engine = engine(true);
    engine.register_interface(interface(1, constants::MODE_ROAMING));
    engine.register_interface(interface(2, constants::MODE_FULL));
    known_path(&mut engine, destination, InterfaceId(1));
    let request = path_request(&destination, Some(&[0x99; 16]), &[0x01; 16], None);
    assert!(engine
        .handle_path_request(&request, InterfaceId(1), 1000.0)
        .is_empty());
    assert!(!engine.announces.table.contains_key(&destination));
    assert!(!engine.path_requests.discovery.contains_key(&destination));

    let mut engine = super::super::engine_fixtures::engine(true);
    engine.register_interface(interface(1, constants::MODE_ROAMING));
    engine.register_interface(interface(2, constants::MODE_FULL));
    known_path(&mut engine, destination, InterfaceId(2));
    engine.handle_path_request(&request, InterfaceId(1), 1000.0);
    assert_eq!(
        engine.announces.table[&destination].retransmit_timeout,
        1000.0 + constants::PATH_REQUEST_GRACE + constants::PATH_REQUEST_RG
    );
}

#[test]
fn known_path_is_answered_after_the_grace_time() {
    let destination = [0xD9; 16];
    let mut engine = engine(true);
    engine.register_interface(interface(1, constants::MODE_FULL));
    engine.register_interface(interface(2, constants::MODE_FULL));
    known_path(&mut engine, destination, InterfaceId(2));
    let request = path_request(&destination, Some(&[0x99; 16]), &[0x01; 16], None);
    engine.handle_path_request(&request, InterfaceId(1), 1000.0);
    assert_eq!(
        engine.announces.table[&destination].retransmit_timeout,
        1000.0 + constants::PATH_REQUEST_GRACE
    );
}

/// A request on an interface that does not search for unknown paths is
/// still forwarded to local clients by a shared instance with transport.
#[test]
fn non_searching_interface_forwards_unknown_requests_to_local_clients() {
    let mut engine = engine(true);
    engine.set_stamp_prs(false);
    engine.register_interface(interface(1, constants::MODE_FULL));
    let mut client = interface(2, constants::MODE_FULL);
    client.is_local_client = true;
    engine.register_interface(client);
    let request = path_request(&[0xDA; 16], Some(&[0x99; 16]), &[0x01; 16], None);
    let actions = engine.handle_path_request(&request, InterfaceId(1), 1000.0);
    assert_eq!(sent_interfaces(&actions), vec![InterfaceId(2)]);
}

/// Interfaces in DISCOVER_PATHS_FOR, or with recursive path requests,
/// search on every mode; a boundary interface searches only on the
/// boundary search modes; other interfaces do not search.
#[test]
fn search_mode_filter_follows_the_receiving_interface_mode() {
    for mode in constants::DISCOVER_PATHS_FOR {
        assert_eq!(search_mode_filter(mode, false), Some(None));
    }
    assert_eq!(search_mode_filter(constants::MODE_FULL, true), Some(None));
    assert_eq!(
        search_mode_filter(constants::MODE_BOUNDARY, false),
        Some(Some(&constants::BOUNDARY_SEARCH_MODES[..]))
    );
    assert_eq!(search_mode_filter(constants::MODE_FULL, false), None);
}

#[test]
fn accepted_request_reports_its_stamp() {
    let mut engine = engine(true);
    engine.register_interface(interface(1, constants::MODE_ACCESS_POINT));
    let unstamped = path_request(&[0xDB; 16], Some(&[0x99; 16]), &[0x01; 16], None);
    let accepted = engine
        .accept_path_request(&unstamped, InterfaceId(1), 1000.0)
        .unwrap();
    assert_eq!(accepted.stamp_value(), None);
    assert!(!accepted.stamped());

    let mut ext = [0u8; constants::PR_EXT_PAYLOAD_LENGTH];
    ext[0] = constants::EXT_PAYLOAD_MARKER;
    ext[2..].fill(0xAA);
    let tag = [0x02; 16];
    let stamped = path_request(&[0xDB; 16], Some(&[0x99; 16]), &tag, Some(&ext));
    let accepted = engine
        .accept_path_request(&stamped, InterfaceId(1), 1000.0)
        .unwrap();
    let mut material = vec![0xDB; 16];
    material.extend_from_slice(&tag);
    let workblock = crate::stamp::stamp_workblock(&material, 0);
    let value = crate::stamp::stamp_value(&workblock, &ext[constants::EXT_HEADER_LENGTH..]);
    assert_eq!(accepted.stamp_value(), Some(value));
    assert_ne!(Some(value), Some(Default::default()));
}

#[test]
fn request_on_an_unregistered_interface_is_answered_after_the_grace_time() {
    let destination = [0xDC; 16];
    let mut engine = engine(true);
    engine.register_interface(interface(2, constants::MODE_FULL));
    known_path(&mut engine, destination, InterfaceId(2));
    let request = path_request(&destination, Some(&[0x99; 16]), &[0x01; 16], None);
    engine.handle_path_request(&request, InterfaceId(7), 1000.0);
    assert_eq!(
        engine.announces.table[&destination].retransmit_timeout,
        1000.0 + constants::PATH_REQUEST_GRACE
    );
}
