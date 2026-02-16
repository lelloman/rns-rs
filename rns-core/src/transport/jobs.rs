use alloc::vec::Vec;

use super::announce_proc::build_retransmit_announce;
use super::tables::AnnounceEntry;
use super::types::{InterfaceId, TransportAction};
use crate::constants;

/// Process announces pending retransmission.
///
/// Transport.py:519-577: For each announce_table entry where the
/// retransmit timeout has passed, either complete (remove) or
/// retransmit and schedule the next retry.
pub fn process_pending_announces(
    announce_table: &mut alloc::collections::BTreeMap<[u8; 16], AnnounceEntry>,
    held_announces: &mut alloc::collections::BTreeMap<[u8; 16], AnnounceEntry>,
    transport_identity_hash: &[u8; 16],
    now: f64,
) -> Vec<TransportAction> {
    let mut actions = Vec::new();
    let mut completed = Vec::new();

    for (dest_hash, entry) in announce_table.iter_mut() {
        // Check local rebroadcast limit (Transport.py:523 checks retries >= LOCAL_REBROADCASTS_MAX)
        if entry.retries > 0 && entry.retries >= constants::LOCAL_REBROADCASTS_MAX {
            completed.push(*dest_hash);
            continue;
        }

        // Check retry limit
        if entry.retries > constants::PATHFINDER_R {
            completed.push(*dest_hash);
            continue;
        }

        // Check if it's time to retransmit
        if now > entry.retransmit_timeout {
            entry.retransmit_timeout = now + constants::PATHFINDER_G + constants::PATHFINDER_RW;
            entry.retries += 1;

            // Build retransmit packet
            let raw = build_retransmit_announce(entry, transport_identity_hash);

            if let Some(attached) = entry.attached_interface {
                actions.push(TransportAction::SendOnInterface {
                    interface: attached,
                    raw,
                });
            } else {
                actions.push(TransportAction::BroadcastOnAllInterfaces {
                    raw,
                    exclude: None,
                });
            }

            actions.push(TransportAction::AnnounceRetransmit {
                destination_hash: *dest_hash,
                hops: entry.hops,
                interface: entry.attached_interface,
            });

            // Check for held announces to reinsert
            if let Some(held) = held_announces.remove(dest_hash) {
                // We'll reinsert it after removing completed entries
                // For now, we just note that we need to handle this
                // The held entry replaces the current entry after completion
                // Actually in Python, the held announce is reinserted into announce_table
                // only after the current retransmit completes. We handle this by
                // storing it temporarily and reinserting below.
                held_announces.insert(*dest_hash, held);
            }
        }
    }

    for dest_hash in &completed {
        announce_table.remove(dest_hash);
        // Reinsert held announces
        if let Some(held) = held_announces.remove(dest_hash) {
            announce_table.insert(*dest_hash, held);
        }
    }

    actions
}

/// Cull expired entries from the reverse table.
pub fn cull_reverse_table(
    reverse_table: &mut alloc::collections::BTreeMap<[u8; 16], super::tables::ReverseEntry>,
    interfaces: &alloc::collections::BTreeMap<InterfaceId, super::types::InterfaceInfo>,
    now: f64,
) -> usize {
    let mut stale = Vec::new();
    for (hash, entry) in reverse_table.iter() {
        if now > entry.timestamp + constants::REVERSE_TIMEOUT {
            stale.push(*hash);
        } else if !interfaces.contains_key(&entry.outbound_interface) {
            stale.push(*hash);
        } else if !interfaces.contains_key(&entry.receiving_interface) {
            stale.push(*hash);
        }
    }

    let count = stale.len();
    for hash in stale {
        reverse_table.remove(&hash);
    }
    count
}

/// Cull expired entries from the link table.
pub fn cull_link_table(
    link_table: &mut alloc::collections::BTreeMap<[u8; 16], super::tables::LinkEntry>,
    interfaces: &alloc::collections::BTreeMap<InterfaceId, super::types::InterfaceInfo>,
    now: f64,
) -> (usize, Vec<TransportAction>) {
    let mut stale = Vec::new();
    for (link_id, entry) in link_table.iter() {
        if entry.validated {
            if now > entry.timestamp + constants::LINK_TIMEOUT {
                stale.push(*link_id);
            } else if !interfaces.contains_key(&entry.next_hop_interface) {
                stale.push(*link_id);
            } else if !interfaces.contains_key(&entry.received_interface) {
                stale.push(*link_id);
            }
        } else {
            // Unvalidated: check proof timeout
            if now > entry.proof_timeout {
                stale.push(*link_id);
            }
        }
    }

    let count = stale.len();
    let mut actions = Vec::new();
    for id in &stale {
        actions.push(TransportAction::LinkClosed { link_id: *id });
    }
    for id in stale {
        link_table.remove(&id);
    }
    (count, actions)
}

/// Cull expired entries from the path table.
pub fn cull_path_table(
    path_table: &mut alloc::collections::BTreeMap<[u8; 16], super::tables::PathEntry>,
    interfaces: &alloc::collections::BTreeMap<InterfaceId, super::types::InterfaceInfo>,
    now: f64,
) -> usize {
    let mut stale = Vec::new();
    for (dest_hash, entry) in path_table.iter() {
        if now > entry.expires {
            stale.push(*dest_hash);
        } else if !interfaces.contains_key(&entry.receiving_interface) {
            stale.push(*dest_hash);
        }
    }

    let count = stale.len();
    for hash in stale {
        path_table.remove(&hash);
    }
    count
}

/// Remove path state entries that no longer have a corresponding path.
pub fn cull_path_states(
    path_states: &mut alloc::collections::BTreeMap<[u8; 16], u8>,
    path_table: &alloc::collections::BTreeMap<[u8; 16], super::tables::PathEntry>,
) -> usize {
    let mut stale = Vec::new();
    for dest_hash in path_states.keys() {
        if !path_table.contains_key(dest_hash) {
            stale.push(*dest_hash);
        }
    }

    let count = stale.len();
    for hash in stale {
        path_states.remove(&hash);
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tables::*;
    use super::super::types::*;
    use alloc::collections::BTreeMap;

    fn make_announce_entry(
        dest_hash: [u8; 16],
        retransmit_timeout: f64,
        retries: u8,
        local_rebroadcasts: u8,
    ) -> AnnounceEntry {
        AnnounceEntry {
            timestamp: 1000.0,
            retransmit_timeout,
            retries,
            received_from: [0xAA; 16],
            hops: 2,
            packet_raw: vec![0x01, 0x02], // minimal
            packet_data: vec![0xCC; 10],
            destination_hash: dest_hash,
            context_flag: 0,
            local_rebroadcasts,
            block_rebroadcasts: false,
            attached_interface: None,
        }
    }

    fn make_interface_info(id: u64) -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId(id),
            name: String::from("test"),
            mode: constants::MODE_FULL,
            out_capable: true,
            in_capable: true,
            bitrate: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: constants::MTU as u32,
            ingress_control: false,
            ia_freq: 0.0,
            started: 0.0,
        }
    }

    #[test]
    fn test_process_pending_retransmit() {
        let dest = [0x11; 16];
        let mut table = BTreeMap::new();
        table.insert(dest, make_announce_entry(dest, 999.0, 0, 0));
        let mut held = BTreeMap::new();
        let transport_hash = [0xBB; 16];

        let actions = process_pending_announces(&mut table, &mut held, &transport_hash, 1000.0);

        // Should have retransmitted (broadcast + announce retransmit notification)
        assert_eq!(actions.len(), 2);
        assert!(matches!(&actions[0], TransportAction::BroadcastOnAllInterfaces { .. }));
        assert!(matches!(&actions[1], TransportAction::AnnounceRetransmit { .. }));

        // Retries should have increased
        assert_eq!(table[&dest].retries, 1);
    }

    #[test]
    fn test_process_pending_retry_limit_reached() {
        let dest = [0x22; 16];
        let mut table = BTreeMap::new();
        table.insert(dest, make_announce_entry(dest, 999.0, 2, 0)); // retries > PATHFINDER_R(1)
        let mut held = BTreeMap::new();

        let actions = process_pending_announces(&mut table, &mut held, &[0; 16], 1000.0);

        assert!(actions.is_empty());
        assert!(!table.contains_key(&dest)); // removed
    }

    #[test]
    fn test_process_pending_local_rebroadcast_limit() {
        let dest = [0x33; 16];
        let mut table = BTreeMap::new();
        // Python Transport.py:523: checks retries >= LOCAL_REBROADCASTS_MAX(2)
        let entry = make_announce_entry(dest, 999.0, 2, 0); // retries=2 >= MAX(2), retries > 0
        table.insert(dest, entry);
        let mut held = BTreeMap::new();

        let actions = process_pending_announces(&mut table, &mut held, &[0; 16], 1000.0);

        assert!(actions.is_empty());
        assert!(!table.contains_key(&dest));
    }

    #[test]
    fn test_process_pending_not_yet_time() {
        let dest = [0x44; 16];
        let mut table = BTreeMap::new();
        table.insert(dest, make_announce_entry(dest, 2000.0, 0, 0)); // timeout in future
        let mut held = BTreeMap::new();

        let actions = process_pending_announces(&mut table, &mut held, &[0; 16], 1000.0);

        assert!(actions.is_empty());
        assert!(table.contains_key(&dest)); // still there
    }

    #[test]
    fn test_cull_reverse_table_timeout() {
        let mut table = BTreeMap::new();
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface_info(1));
        interfaces.insert(InterfaceId(2), make_interface_info(2));

        table.insert(
            [0x11; 16],
            ReverseEntry {
                receiving_interface: InterfaceId(1),
                outbound_interface: InterfaceId(2),
                timestamp: 100.0,
            },
        );

        // now > 100.0 + 480.0 = 580.0
        let count = cull_reverse_table(&mut table, &interfaces, 600.0);
        assert_eq!(count, 1);
        assert!(table.is_empty());
    }

    #[test]
    fn test_cull_reverse_table_missing_interface() {
        let mut table = BTreeMap::new();
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface_info(1));
        // Interface 2 is missing

        table.insert(
            [0x22; 16],
            ReverseEntry {
                receiving_interface: InterfaceId(1),
                outbound_interface: InterfaceId(2), // missing
                timestamp: 1000.0,
            },
        );

        let count = cull_reverse_table(&mut table, &interfaces, 1001.0);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_cull_link_table_validated_timeout() {
        let mut table = BTreeMap::new();
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface_info(1));
        interfaces.insert(InterfaceId(2), make_interface_info(2));

        table.insert(
            [0x33; 16],
            LinkEntry {
                timestamp: 100.0,
                next_hop_transport_id: [0; 16],
                next_hop_interface: InterfaceId(1),
                remaining_hops: 3,
                received_interface: InterfaceId(2),
                taken_hops: 2,
                destination_hash: [0xAA; 16],
                validated: true,
                proof_timeout: 200.0,
            },
        );

        // now > 100.0 + 900.0 = 1000.0
        let (count, closed_actions) = cull_link_table(&mut table, &interfaces, 1100.0);
        assert_eq!(count, 1);
        assert_eq!(closed_actions.len(), 1);
        assert!(matches!(&closed_actions[0], TransportAction::LinkClosed { link_id } if *link_id == [0x33; 16]));
    }

    #[test]
    fn test_cull_link_table_unvalidated_proof_timeout() {
        let mut table = BTreeMap::new();
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface_info(1));
        interfaces.insert(InterfaceId(2), make_interface_info(2));

        table.insert(
            [0x44; 16],
            LinkEntry {
                timestamp: 100.0,
                next_hop_transport_id: [0; 16],
                next_hop_interface: InterfaceId(1),
                remaining_hops: 3,
                received_interface: InterfaceId(2),
                taken_hops: 2,
                destination_hash: [0xAA; 16],
                validated: false,
                proof_timeout: 200.0,
            },
        );

        // now > proof_timeout (200.0)
        let (count, closed_actions) = cull_link_table(&mut table, &interfaces, 201.0);
        assert_eq!(count, 1);
        assert_eq!(closed_actions.len(), 1);
        assert!(matches!(&closed_actions[0], TransportAction::LinkClosed { link_id } if *link_id == [0x44; 16]));
    }

    #[test]
    fn test_cull_path_table() {
        let mut table = BTreeMap::new();
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface_info(1));

        table.insert(
            [0x55; 16],
            PathEntry {
                timestamp: 100.0,
                next_hop: [0; 16],
                hops: 2,
                expires: 500.0,
                random_blobs: Vec::new(),
                receiving_interface: InterfaceId(1),
                packet_hash: [0; 32],
                announce_raw: None,
            },
        );

        let count = cull_path_table(&mut table, &interfaces, 600.0);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_cull_path_states() {
        let mut states = BTreeMap::new();
        let path_table = BTreeMap::new(); // empty path table

        states.insert([0x66; 16], constants::STATE_RESPONSIVE);
        states.insert([0x77; 16], constants::STATE_UNRESPONSIVE);

        let count = cull_path_states(&mut states, &path_table);
        assert_eq!(count, 2);
        assert!(states.is_empty());
    }

    #[test]
    fn test_cull_retains_valid_entries() {
        let mut table = BTreeMap::new();
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface_info(1));

        table.insert(
            [0x88; 16],
            PathEntry {
                timestamp: 1000.0,
                next_hop: [0; 16],
                hops: 1,
                expires: 9999.0, // far future
                random_blobs: Vec::new(),
                receiving_interface: InterfaceId(1),
                packet_hash: [0; 32],
                announce_raw: None,
            },
        );

        let count = cull_path_table(&mut table, &interfaces, 1100.0);
        assert_eq!(count, 0);
        assert_eq!(table.len(), 1);
    }
}
