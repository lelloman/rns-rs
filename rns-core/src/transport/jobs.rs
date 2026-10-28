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
    let mut due = Vec::new();

    for (dest_hash, entry) in announce_table.iter() {
        // Check local rebroadcast limit (Transport.py:523 checks retries >= LOCAL_REBROADCASTS_MAX)
        if entry.retries >= constants::LOCAL_REBROADCASTS_MAX {
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
            due.push((*dest_hash, entry.hops));
        }
    }

    due.sort_by_key(|(dest_hash, hops)| (*hops, *dest_hash));

    for (dest_hash, _) in due {
        let retransmit = if let Some(entry) = announce_table.get_mut(&dest_hash) {
            entry.retransmit_timeout = now + constants::PATHFINDER_G + constants::PATHFINDER_RW;
            entry.retries += 1;

            // Build retransmit packet
            let raw = build_retransmit_announce(entry, transport_identity_hash);
            Some((raw, entry.attached_interface, entry.hops))
        } else {
            None
        };

        if let Some((raw, attached_interface, hops)) = retransmit {
            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                "Rebroadcasting announce for {:02x?} with hop count {}{}",
                &dest_hash[..4],
                hops,
                if attached_interface.is_some() { " as path response" } else { "" },
            );
            if let Some(attached) = attached_interface {
                actions.push(TransportAction::SendOnInterface {
                    interface: attached,
                    raw: raw.into(),
                });
            } else {
                actions.push(TransportAction::BroadcastOnAllInterfaces {
                    raw: raw.into(),
                    exclude: None,
                });
            }

            actions.push(TransportAction::AnnounceRetransmit {
                destination_hash: dest_hash,
                hops,
                interface: attached_interface,
            });

            // Check for held announces to reinsert
            if let Some(held) = held_announces.remove(&dest_hash) {
                announce_table.insert(dest_hash, held);
            }
        }
    }

    for dest_hash in &completed {
        announce_table.remove(dest_hash);
    }

    actions
}

/// Cull expired entries from the reverse table.
pub fn cull_reverse_table(
    reverse_table: &mut super::tables::ReverseTable,
    interfaces: &alloc::collections::BTreeMap<InterfaceId, super::types::InterfaceInfo>,
    now: f64,
) -> usize {
    let mut stale = Vec::new();
    for (hash, entry) in reverse_table.iter() {
        if now > entry.timestamp + constants::REVERSE_TIMEOUT
            || !interfaces.contains_key(&entry.outbound_interface)
            || !interfaces.contains_key(&entry.receiving_interface)
        {
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
            if now > entry.timestamp + constants::LINK_TIMEOUT
                || !interfaces.contains_key(&entry.next_hop_interface)
                || !interfaces.contains_key(&entry.received_interface)
            {
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

/// Whether paths learnt on this interface are treated as slow: a known,
/// non-zero bitrate below `PATH_SLOW_BITRATE`.
fn is_slow_interface(
    interfaces: &alloc::collections::BTreeMap<InterfaceId, super::types::InterfaceInfo>,
    interface_id: &InterfaceId,
) -> bool {
    interfaces
        .get(interface_id)
        .and_then(|info| info.bitrate)
        .is_some_and(|bitrate| 0 < bitrate && bitrate < crate::constants::PATH_SLOW_BITRATE)
}

/// Cull expired entries from the path table.
///
/// Culls individual paths within each PathSet, then removes empty PathSets.
/// Never-used paths expire after `unused_path_linger`, multiplied by
/// `PATH_SLOW_LINGER_FACTOR` on slow interfaces, where paths are expensive to
/// relearn. When the never-used pool exceeds its target, entries on fast
/// interfaces are removed before entries on slow ones, each group ordered by
/// expiry ascending so the earliest-expiring ones go first. Removing the
/// newest entries instead would keep stale paths and discard fresh ones.
pub fn cull_path_table(
    path_table: &mut alloc::collections::BTreeMap<[u8; 16], super::tables::PathSet>,
    interfaces: &alloc::collections::BTreeMap<InterfaceId, super::types::InterfaceInfo>,
    now: f64,
    unused_path_linger: f64,
    unused_pool_target: usize,
) -> usize {
    let mut culled = 0usize;
    let mut unused: alloc::vec::Vec<(u8, f64, [u8; 16], [u8; 16])> = alloc::vec::Vec::new();
    for (dest_hash, ps) in path_table.iter_mut() {
        let before = ps.len();
        ps.retain(|p| {
            let linger = if is_slow_interface(interfaces, &p.receiving_interface) {
                unused_path_linger * crate::constants::PATH_SLOW_LINGER_FACTOR
            } else {
                unused_path_linger
            };
            now <= p.expires
                && interfaces.contains_key(&p.receiving_interface)
                && !(p.used == 0.0 && now > p.timestamp + linger)
        });
        culled += before - ps.len();
        for path in ps.iter() {
            if path.used == 0.0 {
                let slow = u8::from(is_slow_interface(interfaces, &path.receiving_interface));
                unused.push((slow, path.expires, *dest_hash, path.next_hop));
            }
        }
    }
    if unused.len() > unused_pool_target {
        let remove_count = unused.len() - unused_pool_target;
        unused.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.partial_cmp(&b.1).unwrap_or(core::cmp::Ordering::Equal))
        });
        for (_, _, dest_hash, next_hop) in unused.into_iter().take(remove_count) {
            if let Some(ps) = path_table.get_mut(&dest_hash) {
                let before = ps.len();
                ps.retain(|p| p.next_hop != next_hop);
                culled += before - ps.len();
            }
        }
    }
    path_table.retain(|_, ps| !ps.is_empty());
    if culled > 0 {
        log::trace!(target: crate::logging::PATHING_LOG_TARGET,
            "Removed {} expired, unavailable, or unused path table entries",
            culled,
        );
    }
    culled
}

/// Remove path state entries that no longer have a corresponding path.
pub fn cull_path_states(
    path_states: &mut alloc::collections::BTreeMap<[u8; 16], u8>,
    path_table: &alloc::collections::BTreeMap<[u8; 16], super::tables::PathSet>,
) -> usize {
    let mut stale = Vec::new();
    for dest_hash in path_states.keys() {
        let has_path = path_table.get(dest_hash).is_some_and(|ps| !ps.is_empty());
        if !has_path {
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
    use super::super::tables::*;
    use super::super::types::*;
    use super::*;
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
            tunnel_id: None,
            mtu: constants::MTU as u32,
            ingress_control: crate::transport::types::IngressControlConfig::disabled(),
            ia_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
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
        assert!(matches!(
            &actions[0],
            TransportAction::BroadcastOnAllInterfaces { .. }
        ));
        assert!(matches!(
            &actions[1],
            TransportAction::AnnounceRetransmit { .. }
        ));

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
    fn process_pending_retransmits_due_announces_in_hop_order() {
        let high_hop_dest = [0x11; 16];
        let low_hop_dest = [0x22; 16];
        let mut high_hop = make_announce_entry(high_hop_dest, 999.0, 0, 0);
        high_hop.hops = 5;
        let mut low_hop = make_announce_entry(low_hop_dest, 999.0, 0, 0);
        low_hop.hops = 1;
        let mut table = BTreeMap::new();
        table.insert(high_hop_dest, high_hop);
        table.insert(low_hop_dest, low_hop);
        let mut held = BTreeMap::new();

        let actions = process_pending_announces(&mut table, &mut held, &[0; 16], 1000.0);

        let sent_hops: Vec<u8> = actions
            .iter()
            .filter_map(|action| match action {
                TransportAction::BroadcastOnAllInterfaces { raw, .. } => raw.get(1).copied(),
                TransportAction::SendOnInterface { raw, .. } => raw.get(1).copied(),
                _ => None,
            })
            .collect();
        assert_eq!(sent_hops, vec![1, 5]);
    }

    #[test]
    fn process_pending_reinserts_held_announce_after_path_response_retransmit() {
        let dest = [0x55; 16];
        let mut path_response = make_announce_entry(dest, 999.0, 0, 0);
        path_response.hops = 2;
        path_response.block_rebroadcasts = true;
        let mut held_entry = make_announce_entry(dest, 1500.0, 0, 0);
        held_entry.hops = 7;
        held_entry.block_rebroadcasts = false;
        held_entry.packet_data = vec![0x77; 10];
        let mut table = BTreeMap::new();
        table.insert(dest, path_response);
        let mut held = BTreeMap::new();
        held.insert(dest, held_entry.clone());

        let actions = process_pending_announces(&mut table, &mut held, &[0; 16], 1000.0);

        assert!(actions.iter().any(|action| matches!(
            action,
            TransportAction::AnnounceRetransmit {
                destination_hash,
                hops: 2,
                ..
            } if *destination_hash == dest
        )));
        assert!(held.is_empty());
        let active = table
            .get(&dest)
            .expect("held announce should be reinserted");
        assert_eq!(active.hops, 7);
        assert_eq!(active.packet_data, vec![0x77; 10]);
        assert!(!active.block_rebroadcasts);
    }

    #[test]
    fn test_cull_reverse_table_timeout() {
        let mut table = crate::transport::tables::ReverseTable::default();
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
        let mut table = crate::transport::tables::ReverseTable::default();
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
        assert!(
            matches!(&closed_actions[0], TransportAction::LinkClosed { link_id } if *link_id == [0x33; 16])
        );
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
        assert!(
            matches!(&closed_actions[0], TransportAction::LinkClosed { link_id } if *link_id == [0x44; 16])
        );
    }

    #[test]
    fn test_cull_path_table() {
        let mut table = BTreeMap::new();
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface_info(1));

        table.insert(
            [0x55; 16],
            super::super::tables::PathSet::from_single(
                PathEntry {
                    timestamp: 100.0,
                    next_hop: [0; 16],
                    hops: 2,
                    expires: 500.0,
                    random_blobs: Vec::new(),
                    receiving_interface: InterfaceId(1),
                    packet_hash: [0; 32],
                    announce_raw: None,
                    used: 0.0,
                },
                1,
            ),
        );

        let count = cull_path_table(
            &mut table,
            &interfaces,
            600.0,
            crate::constants::UNUSED_PATH_LINGER,
            crate::constants::PATH_POOL_UNUSED_TARGET,
        );
        assert_eq!(count, 1);
    }

    fn path_with_usage(timestamp: f64, expires: f64, used: f64) -> super::super::tables::PathSet {
        super::super::tables::PathSet::from_single(
            PathEntry {
                timestamp,
                next_hop: [0; 16],
                hops: 1,
                expires,
                random_blobs: Vec::new(),
                receiving_interface: InterfaceId(1),
                packet_hash: [0; 32],
                announce_raw: None,
                used,
            },
            1,
        )
    }

    #[test]
    fn test_cull_never_used_paths_after_linger() {
        let mut table = BTreeMap::new();
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface_info(1));

        table.insert([0x11; 16], path_with_usage(100.0, 9999.0, 0.0));
        table.insert([0x22; 16], path_with_usage(100.0, 9999.0, 150.0));

        let count = cull_path_table(&mut table, &interfaces, 300.0, 100.0, 2048);
        assert_eq!(count, 1);
        assert!(!table.contains_key(&[0x11; 16]));
        assert!(table.contains_key(&[0x22; 16]));
    }

    #[test]
    fn test_cull_never_used_pool_to_target() {
        let mut table = BTreeMap::new();
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface_info(1));

        table.insert([0x31; 16], path_with_usage(100.0, 1000.0, 0.0));
        table.insert([0x32; 16], path_with_usage(100.0, 2000.0, 0.0));
        table.insert([0x33; 16], path_with_usage(100.0, 3000.0, 0.0));

        let count = cull_path_table(&mut table, &interfaces, 200.0, 9999.0, 2);
        assert_eq!(count, 1);
        assert!(!table.contains_key(&[0x31; 16]));
        assert!(table.contains_key(&[0x32; 16]));
        assert!(table.contains_key(&[0x33; 16]));
    }

    #[test]
    fn unused_path_pool_order_is_by_expiry_not_insertion() {
        let mut table = BTreeMap::new();
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), make_interface_info(1));

        // Insert newest-expiring first so insertion order and expiry order
        // disagree; culling must still drop the earliest-expiring entry.
        table.insert([0x41; 16], path_with_usage(100.0, 3000.0, 0.0));
        table.insert([0x42; 16], path_with_usage(100.0, 1000.0, 0.0));
        table.insert([0x43; 16], path_with_usage(100.0, 2000.0, 0.0));

        let count = cull_path_table(&mut table, &interfaces, 200.0, 9999.0, 2);
        assert_eq!(count, 1);
        assert!(!table.contains_key(&[0x42; 16]));
        assert!(table.contains_key(&[0x41; 16]));
        assert!(table.contains_key(&[0x43; 16]));
    }

    fn path_on_interface(
        interface: InterfaceId,
        timestamp: f64,
        expires: f64,
        used: f64,
    ) -> super::super::tables::PathSet {
        super::super::tables::PathSet::from_single(
            PathEntry {
                timestamp,
                next_hop: [0; 16],
                hops: 1,
                expires,
                random_blobs: Vec::new(),
                receiving_interface: interface,
                packet_hash: [0; 32],
                announce_raw: None,
                used,
            },
            1,
        )
    }

    fn slow_and_fast_interfaces() -> BTreeMap<InterfaceId, InterfaceInfo> {
        let mut interfaces = BTreeMap::new();
        let mut slow = make_interface_info(1);
        slow.bitrate = Some(crate::constants::PATH_SLOW_BITRATE - 1);
        interfaces.insert(InterfaceId(1), slow);
        let mut fast = make_interface_info(2);
        fast.bitrate = Some(crate::constants::PATH_SLOW_BITRATE);
        interfaces.insert(InterfaceId(2), fast);
        // No bitrate known: not slow.
        interfaces.insert(InterfaceId(3), make_interface_info(3));
        // A zero bitrate is "unknown", not slow.
        let mut zero = make_interface_info(4);
        zero.bitrate = Some(0);
        interfaces.insert(InterfaceId(4), zero);
        interfaces
    }

    #[test]
    fn never_used_paths_on_slow_interfaces_linger_longer() {
        let interfaces = slow_and_fast_interfaces();
        let linger = 100.0;
        let mut table = BTreeMap::new();
        for (dest, iface) in [(0x51u8, 1u64), (0x52, 2), (0x53, 3), (0x54, 4)] {
            table.insert(
                [dest; 16],
                path_on_interface(InterfaceId(iface), 100.0, 99_999.0, 0.0),
            );
        }
        // Past the plain linger: everything but the slow-interface path goes.
        let now = 100.0 + linger + 1.0;
        let count = cull_path_table(&mut table, &interfaces, now, linger, 2048);
        assert_eq!(count, 3);
        assert!(table.contains_key(&[0x51; 16]));

        // The slow-interface path survives until the factored linger passes.
        let before_factored = 100.0 + linger * crate::constants::PATH_SLOW_LINGER_FACTOR;
        assert_eq!(
            cull_path_table(&mut table, &interfaces, before_factored, linger, 2048),
            0
        );
        assert_eq!(
            cull_path_table(&mut table, &interfaces, before_factored + 1.0, linger, 2048),
            1
        );
        assert!(table.is_empty());
    }

    #[test]
    fn used_paths_on_slow_interfaces_are_not_special() {
        let interfaces = slow_and_fast_interfaces();
        let mut table = BTreeMap::new();
        table.insert(
            [0x61; 16],
            path_on_interface(InterfaceId(1), 100.0, 500.0, 150.0),
        );
        // A used path expires on its own timer regardless of the interface.
        assert_eq!(
            cull_path_table(&mut table, &interfaces, 499.0, 10.0, 2048),
            0
        );
        assert_eq!(
            cull_path_table(&mut table, &interfaces, 501.0, 10.0, 2048),
            1
        );
    }

    #[test]
    fn unused_pool_cull_removes_fast_interface_paths_before_slow_ones() {
        let interfaces = slow_and_fast_interfaces();
        let mut table = BTreeMap::new();
        // Slow-interface paths expire earliest, which would make them the
        // first victims under plain expiry ordering.
        table.insert(
            [0x71; 16],
            path_on_interface(InterfaceId(1), 100.0, 1000.0, 0.0),
        );
        table.insert(
            [0x72; 16],
            path_on_interface(InterfaceId(1), 100.0, 1100.0, 0.0),
        );
        table.insert(
            [0x73; 16],
            path_on_interface(InterfaceId(2), 100.0, 3000.0, 0.0),
        );
        table.insert(
            [0x74; 16],
            path_on_interface(InterfaceId(3), 100.0, 2000.0, 0.0),
        );
        table.insert(
            [0x75; 16],
            path_on_interface(InterfaceId(4), 100.0, 4000.0, 0.0),
        );

        // Cull two to reach a pool target of three: the two earliest-expiring
        // fast-interface paths go, the slow-interface ones stay.
        let count = cull_path_table(&mut table, &interfaces, 200.0, 99_999.0, 3);
        assert_eq!(count, 2);
        assert!(table.contains_key(&[0x71; 16]));
        assert!(table.contains_key(&[0x72; 16]));
        assert!(!table.contains_key(&[0x74; 16]), "fast, expires 2000");
        assert!(!table.contains_key(&[0x73; 16]), "fast, expires 3000");
        assert!(table.contains_key(&[0x75; 16]), "fast, expires 4000");

        // The last fast-interface path goes before any slow one.
        let count = cull_path_table(&mut table, &interfaces, 200.0, 99_999.0, 2);
        assert_eq!(count, 1);
        assert!(!table.contains_key(&[0x75; 16]));

        // Once only slow-interface paths remain they are culled by expiry.
        let count = cull_path_table(&mut table, &interfaces, 200.0, 99_999.0, 1);
        assert_eq!(count, 1);
        assert!(!table.contains_key(&[0x71; 16]));
        assert!(table.contains_key(&[0x72; 16]));
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
            super::super::tables::PathSet::from_single(
                PathEntry {
                    timestamp: 1000.0,
                    next_hop: [0; 16],
                    hops: 1,
                    expires: 9999.0, // far future
                    random_blobs: Vec::new(),
                    receiving_interface: InterfaceId(1),
                    packet_hash: [0; 32],
                    announce_raw: None,
                    used: 0.0,
                },
                1,
            ),
        );

        let count = cull_path_table(
            &mut table,
            &interfaces,
            1100.0,
            crate::constants::UNUSED_PATH_LINGER,
            crate::constants::PATH_POOL_UNUSED_TARGET,
        );
        assert_eq!(count, 0);
        assert_eq!(table.len(), 1);
    }
}
