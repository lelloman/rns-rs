//! Which diagnostic an untransportable link request proof gets.

use super::*;

fn entry(next_hop_interface: u64, received_interface: u64) -> LinkEntry {
    LinkEntry {
        timestamp: 1000.0,
        next_hop_transport_id: [0x77; 16],
        next_hop_interface: InterfaceId(next_hop_interface),
        remaining_hops: 3,
        received_interface: InterfaceId(received_interface),
        taken_hops: 5,
        destination_hash: [0x99; 16],
        validated: false,
        proof_timeout: 1010.0,
        traffic: 0,
    }
}

/// A proof matches the route's hops when they are the hops expected on the
/// side it arrived from: the remaining hops from the next hop, the taken
/// hops from the initiator's side, and either when both sides share one
/// interface.
#[test]
fn proof_hops_are_checked_against_the_side_it_arrived_on() {
    let same = entry(1, 1);
    assert!(link_route_hops_match(3, &same, InterfaceId(1)));
    assert!(link_route_hops_match(5, &same, InterfaceId(1)));
    assert!(!link_route_hops_match(4, &same, InterfaceId(1)));

    let split = entry(1, 2);
    assert!(link_route_hops_match(3, &split, InterfaceId(1)));
    assert!(!link_route_hops_match(5, &split, InterfaceId(1)));
    assert!(link_route_hops_match(5, &split, InterfaceId(2)));
    assert!(!link_route_hops_match(3, &split, InterfaceId(2)));

    // On an unrelated interface the failure is the interface, not the hops.
    assert!(link_route_hops_match(9, &split, InterfaceId(7)));
}
