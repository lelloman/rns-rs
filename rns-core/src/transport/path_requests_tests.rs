use super::super::engine_fixtures::{engine, interface, path_entry, path_request};
use super::*;

fn known_path(engine: &mut TransportEngine, destination: [u8; 16], via: InterfaceId) {
    engine.path_table.insert(
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
    assert!(!engine.announce_table.contains_key(&destination));
    assert!(!engine.discovery_path_requests.contains_key(&destination));

    let from_another = path_request(&destination, Some(&[0xCC; 16]), &[0x02; 16], None);
    engine.handle_path_request(&from_another, InterfaceId(1), 1000.0);
    assert!(engine.announce_table.contains_key(&destination));

    // A legacy request carries no transport id and is answered.
    let mut engine = super::super::engine_fixtures::engine(true);
    engine.register_interface(interface(1, constants::MODE_ACCESS_POINT));
    known_path(&mut engine, destination, InterfaceId(2));
    let legacy = path_request(&destination, None, &[0xBB; 16], None);
    engine.handle_path_request(&legacy, InterfaceId(1), 1000.0);
    assert!(engine.announce_table.contains_key(&destination));
}
