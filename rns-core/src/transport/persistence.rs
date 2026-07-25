//! Restart-safe transport state snapshots.
//!
//! Encoding is owned by `rns-net`; this module keeps the I/O-free transport
//! engine responsible for selecting and reconstructing valid state.

use alloc::vec::Vec;

use super::tables::PathEntry;
use super::tunnel::TunnelPath;
use super::types::InterfaceId;
use super::TransportEngine;
use crate::constants;
use crate::packet::RawPacket;

const PERSIST_RANDOM_BLOBS: usize = 32;

#[derive(Debug, Clone, PartialEq)]
pub struct PersistedPath {
    pub destination_hash: [u8; 16],
    pub timestamp: f64,
    pub received_from: [u8; 16],
    pub hops: u8,
    pub expires: f64,
    pub random_blobs: Vec<[u8; 10]>,
    pub interface_hash: Option<[u8; 32]>,
    pub packet_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq)]
pub struct PersistedTunnel {
    pub tunnel_id: [u8; 32],
    pub interface_hash: Option<[u8; 32]>,
    pub paths: Vec<PersistedPath>,
    pub expires: f64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TransportStateSnapshot {
    pub packet_hashes: Vec<[u8; 32]>,
    pub paths: Vec<PersistedPath>,
    pub tunnels: Vec<PersistedTunnel>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RestoreStats {
    pub packet_hashes: usize,
    pub paths: usize,
    pub tunnels: usize,
    pub skipped_paths: usize,
}

impl TransportEngine {
    /// Copy the restart-relevant portion of transport state.
    pub fn persistence_snapshot(&self) -> TransportStateSnapshot {
        if !self.config.transport_enabled {
            return TransportStateSnapshot::default();
        }

        let packet_hashes = self.packet_hashlist.iter().copied().collect();
        let mut paths = Vec::new();
        for (destination_hash, path_set) in &self.path_table {
            for entry in path_set.iter() {
                let Some(interface_hash) = self.interface_hashes.get(&entry.receiving_interface)
                else {
                    continue;
                };
                paths.push(PersistedPath::from_path_entry(
                    *destination_hash,
                    entry,
                    Some(*interface_hash),
                ));
            }
        }

        let tunnels = self
            .tunnel_table
            .iter()
            .map(|(tunnel_id, tunnel)| {
                let interface_hash = tunnel
                    .interface
                    .and_then(|id| self.interface_hashes.get(&id).copied());
                let paths = tunnel
                    .paths
                    .iter()
                    .map(|(destination_hash, path)| PersistedPath {
                        destination_hash: *destination_hash,
                        timestamp: path.timestamp,
                        received_from: path.received_from,
                        hops: path.hops,
                        expires: path.expires,
                        random_blobs: tail_random_blobs(&path.random_blobs),
                        interface_hash,
                        packet_hash: path.packet_hash,
                    })
                    .collect();
                PersistedTunnel {
                    tunnel_id: *tunnel_id,
                    interface_hash,
                    paths,
                    expires: tunnel.expires,
                }
            })
            .collect();

        TransportStateSnapshot {
            packet_hashes,
            paths,
            tunnels,
        }
    }

    /// Restore state after interfaces and the announce cache are available.
    pub fn restore_persistence_snapshot<F>(
        &mut self,
        snapshot: TransportStateSnapshot,
        now: f64,
        mut announce_lookup: F,
    ) -> RestoreStats
    where
        F: FnMut(&[u8; 32]) -> Option<Vec<u8>>,
    {
        let mut stats = RestoreStats::default();
        if !self.config.transport_enabled {
            return stats;
        }

        for packet_hash in snapshot.packet_hashes {
            self.packet_hashlist.add(packet_hash);
        }
        stats.packet_hashes = self.packet_hashlist.len();

        let interface_ids: alloc::collections::BTreeMap<[u8; 32], InterfaceId> = self
            .interface_hashes
            .iter()
            .map(|(id, hash)| (*hash, *id))
            .collect();

        for path in snapshot.paths {
            let Some(interface_hash) = path.interface_hash else {
                stats.skipped_paths += 1;
                continue;
            };
            let Some(interface_id) = interface_ids.get(&interface_hash).copied() else {
                stats.skipped_paths += 1;
                continue;
            };
            let Some(raw) = load_cached_announce(&path, &mut announce_lookup) else {
                stats.skipped_paths += 1;
                continue;
            };
            if path.expires < now {
                stats.skipped_paths += 1;
                continue;
            }
            let destination_hash = path.destination_hash;
            let entry = PathEntry {
                timestamp: path.timestamp,
                next_hop: path.received_from,
                hops: path.hops,
                expires: path.expires,
                random_blobs: path.random_blobs,
                receiving_interface: interface_id,
                packet_hash: path.packet_hash,
                announce_raw: Some(raw),
            };
            self.upsert_path_destination(destination_hash, entry, now);
            stats.paths += 1;
        }

        for tunnel in snapshot.tunnels {
            if tunnel.expires < now {
                stats.skipped_paths += tunnel.paths.len();
                continue;
            }
            let mut restored_paths = alloc::collections::BTreeMap::new();
            for path in tunnel.paths {
                if path.expires < now || load_cached_announce(&path, &mut announce_lookup).is_none()
                {
                    stats.skipped_paths += 1;
                    continue;
                }
                restored_paths.insert(
                    path.destination_hash,
                    TunnelPath {
                        timestamp: path.timestamp,
                        received_from: path.received_from,
                        hops: path.hops,
                        expires: path.expires,
                        random_blobs: path.random_blobs,
                        packet_hash: path.packet_hash,
                    },
                );
            }
            if restored_paths.is_empty() {
                continue;
            }
            self.tunnel_table
                .restore_detached(tunnel.tunnel_id, restored_paths, tunnel.expires);
            stats.tunnels += 1;
        }

        stats
    }
}

impl PersistedPath {
    fn from_path_entry(
        destination_hash: [u8; 16],
        entry: &PathEntry,
        interface_hash: Option<[u8; 32]>,
    ) -> Self {
        Self {
            destination_hash,
            timestamp: entry.timestamp,
            received_from: entry.next_hop,
            hops: entry.hops,
            expires: entry.expires,
            random_blobs: tail_random_blobs(&entry.random_blobs),
            interface_hash,
            packet_hash: entry.packet_hash,
        }
    }
}

fn tail_random_blobs(blobs: &[[u8; 10]]) -> Vec<[u8; 10]> {
    blobs[blobs.len().saturating_sub(PERSIST_RANDOM_BLOBS)..].to_vec()
}

fn load_cached_announce<F>(path: &PersistedPath, lookup: &mut F) -> Option<Vec<u8>>
where
    F: FnMut(&[u8; 32]) -> Option<Vec<u8>>,
{
    let raw = lookup(&path.packet_hash)?;
    let packet = RawPacket::unpack(&raw).ok()?;
    if packet.packet_hash != path.packet_hash
        || packet.destination_hash != path.destination_hash
        || packet.flags.packet_type != constants::PACKET_TYPE_ANNOUNCE
    {
        return None;
    }
    Some(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants;
    use crate::hash;
    use crate::packet::{PacketFlags, RawPacket};
    use crate::transport::tables::PathEntry;
    use crate::transport::tunnel::TunnelPath;
    use crate::transport::types::{
        IngressControlConfig, InterfaceId, InterfaceInfo, TransportConfig,
    };
    use crate::transport::TransportEngine;
    use alloc::collections::BTreeMap;
    use alloc::string::String;
    use alloc::vec;

    fn config(hash_capacity: usize) -> TransportConfig {
        TransportConfig {
            transport_enabled: true,
            identity_hash: Some([0x42; 16]),
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 4,
            packet_hashlist_max_entries: hash_capacity,
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

    fn interface(id: u64, name: &str) -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId(id),
            name: String::from(name),
            mode: constants::MODE_FULL,
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
            ingress_control: IngressControlConfig::disabled(),
            ia_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: 0.0,
        }
    }

    fn announce(dest: [u8; 16]) -> RawPacket {
        RawPacket::pack(
            PacketFlags {
                header_type: constants::HEADER_1,
                context_flag: constants::FLAG_UNSET,
                transport_type: constants::TRANSPORT_BROADCAST,
                destination_type: constants::DESTINATION_SINGLE,
                packet_type: constants::PACKET_TYPE_ANNOUNCE,
            },
            0,
            &dest,
            None,
            constants::CONTEXT_NONE,
            &[0x77; 32],
        )
        .unwrap()
    }

    fn persisted_path(dest: [u8; 16], packet: &RawPacket, iface: &str) -> PersistedPath {
        PersistedPath {
            destination_hash: dest,
            timestamp: 100.0,
            received_from: [0x22; 16],
            hops: 3,
            expires: 500.0,
            random_blobs: vec![[0x33; 10]],
            interface_hash: Some(hash::full_hash(iface.as_bytes())),
            packet_hash: packet.packet_hash,
        }
    }

    #[test]
    fn snapshot_preserves_fifo_hash_order_and_caps_random_blob_history() {
        let mut engine = TransportEngine::new(config(3));
        engine.register_interface(interface(1, "alpha"));
        engine.packet_hashlist.add([1; 32]);
        engine.packet_hashlist.add([2; 32]);
        engine.packet_hashlist.add([3; 32]);
        engine.packet_hashlist.add([4; 32]);
        let packet = announce([9; 16]);
        engine.inject_path(
            [9; 16],
            PathEntry {
                timestamp: 100.0,
                next_hop: [8; 16],
                hops: 2,
                expires: 500.0,
                random_blobs: (0..40).map(|n| [n; 10]).collect(),
                receiving_interface: InterfaceId(1),
                packet_hash: packet.packet_hash,
                announce_raw: Some(packet.raw.clone()),
            },
        );

        let snapshot = engine.persistence_snapshot();
        assert_eq!(snapshot.packet_hashes, vec![[2; 32], [3; 32], [4; 32]]);
        assert_eq!(snapshot.paths[0].random_blobs.len(), 32);
        assert_eq!(snapshot.paths[0].random_blobs[0], [8; 10]);
        assert_eq!(
            snapshot.paths[0].interface_hash,
            Some(hash::full_hash(b"alpha"))
        );
    }

    #[test]
    fn snapshot_skips_paths_whose_interface_is_not_registered() {
        let mut engine = TransportEngine::new(config(8));
        engine.inject_path(
            [9; 16],
            PathEntry {
                timestamp: 100.0,
                next_hop: [8; 16],
                hops: 2,
                expires: 500.0,
                random_blobs: Vec::new(),
                receiving_interface: InterfaceId(404),
                packet_hash: [7; 32],
                announce_raw: None,
            },
        );
        assert!(engine.persistence_snapshot().paths.is_empty());
    }

    #[test]
    fn restore_requires_live_interface_cached_announce_and_unexpired_path() {
        let good_packet = announce([1; 16]);
        let missing_packet = announce([2; 16]);
        let mut missing_iface = persisted_path([3; 16], &good_packet, "gone");
        missing_iface.packet_hash = good_packet.packet_hash;
        let mut expired = persisted_path([4; 16], &good_packet, "alpha");
        expired.expires = 99.0;
        let snapshot = TransportStateSnapshot {
            packet_hashes: vec![[1; 32], [2; 32], [3; 32]],
            paths: vec![
                persisted_path([1; 16], &good_packet, "alpha"),
                persisted_path([2; 16], &missing_packet, "alpha"),
                missing_iface,
                expired,
            ],
            tunnels: Vec::new(),
        };
        let mut cache = BTreeMap::new();
        cache.insert(good_packet.packet_hash, good_packet.raw.clone());
        let mut engine = TransportEngine::new(config(2));
        engine.register_interface(interface(7, "alpha"));
        let stats =
            engine.restore_persistence_snapshot(snapshot, 100.0, |hash| cache.get(hash).cloned());

        assert_eq!(stats.packet_hashes, 2);
        assert_eq!(stats.paths, 1);
        assert_eq!(stats.skipped_paths, 3);
        assert!(engine.has_path(&[1; 16]));
        assert_eq!(engine.next_hop_interface(&[1; 16]), Some(InterfaceId(7)));
        assert!(!engine.has_path(&[2; 16]));
        assert_eq!(
            engine.persistence_snapshot().packet_hashes,
            vec![[2; 32], [3; 32]]
        );
    }

    #[test]
    fn detached_tunnel_round_trips_when_at_least_one_cached_path_survives() {
        let packet = announce([5; 16]);
        let mut source = TransportEngine::new(config(8));
        source.register_interface(interface(9, "tunnel-iface"));
        source.handle_tunnel([0x44; 32], InterfaceId(9), 100.0);
        source.tunnel_table.store_tunnel_path(
            &[0x44; 32],
            [5; 16],
            TunnelPath {
                timestamp: 100.0,
                received_from: [6; 16],
                hops: 2,
                expires: 500.0,
                random_blobs: vec![[7; 10]],
                packet_hash: packet.packet_hash,
            },
            100.0,
            constants::DESTINATION_TIMEOUT,
            usize::MAX,
        );
        let snapshot = source.persistence_snapshot();
        assert_eq!(
            snapshot.tunnels[0].interface_hash,
            Some(hash::full_hash(b"tunnel-iface"))
        );

        let mut restored = TransportEngine::new(config(8));
        let stats = restored.restore_persistence_snapshot(snapshot, 101.0, |hash| {
            (hash == &packet.packet_hash).then(|| packet.raw.clone())
        });
        assert_eq!(stats.tunnels, 1);
        let round_trip = restored.persistence_snapshot();
        assert_eq!(round_trip.tunnels.len(), 1);
        assert_eq!(round_trip.tunnels[0].interface_hash, None);
        assert_eq!(round_trip.tunnels[0].paths[0].destination_hash, [5; 16]);
    }
}
