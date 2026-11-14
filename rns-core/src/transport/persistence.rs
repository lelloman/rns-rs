//! Restart-safe transport state snapshots.
//!
//! Encoding is owned by `rns-net`; this module keeps the I/O-free transport
//! engine responsible for selecting and reconstructing valid state.

use alloc::vec::Vec;

use super::tables::{PathEntry, RateEntry};
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
    /// Last time this path was used; 0 means never used.
    pub used: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PersistedTunnel {
    pub tunnel_id: [u8; 32],
    pub interface_hash: Option<[u8; 32]>,
    pub paths: Vec<PersistedPath>,
    pub expires: f64,
}

/// One announce rate table entry (upstream d5f1e014 persists the table).
#[derive(Debug, Clone, PartialEq)]
pub struct PersistedAnnounceRate {
    pub destination_hash: [u8; 16],
    /// Last non-violating announce time.
    pub last: f64,
    pub rate_violations: u32,
    pub blocked_until: f64,
    /// Recent announce times, oldest first.
    pub timestamps: Vec<f64>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TransportStateSnapshot {
    pub packet_hashes: Vec<[u8; 32]>,
    pub paths: Vec<PersistedPath>,
    pub tunnels: Vec<PersistedTunnel>,
    pub announce_rates: Vec<PersistedAnnounceRate>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RestoreStats {
    pub packet_hashes: usize,
    pub paths: usize,
    pub tunnels: usize,
    pub announce_rates: usize,
    pub skipped_paths: usize,
    /// Paths not restored because the destination type filter rejects
    /// their announce (upstream 20e25a9f).
    pub filtered_paths: usize,
}

impl TransportEngine {
    /// Copy the restart-relevant portion of transport state.
    pub fn persistence_snapshot(&self) -> TransportStateSnapshot {
        if !self.config.transport_enabled {
            return TransportStateSnapshot::default();
        }

        let packet_hashes = self.packet_hashlist.iter().collect();
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
                        used: 0.0,
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

        let announce_rates = self
            .rate_limiter
            .entries()
            .map(|(destination_hash, entry)| PersistedAnnounceRate {
                destination_hash: *destination_hash,
                last: entry.last,
                rate_violations: entry.rate_violations,
                blocked_until: entry.blocked_until,
                timestamps: entry.timestamps.clone(),
            })
            .collect();

        TransportStateSnapshot {
            packet_hashes,
            paths,
            tunnels,
            announce_rates,
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
            if !self.admits_restored_announce(&raw) {
                stats.filtered_paths += 1;
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
                used: path.used,
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
            // A restored tunnel waits at most TUNNEL_RECONNECT_WINDOW for its
            // endpoint to synthesize it again (upstream 023849ed).
            let expires = tunnel.expires.min(now + constants::TUNNEL_RECONNECT_WINDOW);
            self.tunnel_table
                .restore_detached(tunnel.tunnel_id, restored_paths, expires);
            stats.tunnels += 1;
        }

        // Rate state survives a restart, so a restart does not reset a
        // blocked destination's penalty or its accumulated violations.
        for rate in snapshot.announce_rates {
            let mut timestamps = rate.timestamps;
            let excess = timestamps
                .len()
                .saturating_sub(constants::MAX_RATE_TIMESTAMPS);
            timestamps.drain(..excess);
            self.rate_limiter.restore(
                rate.destination_hash,
                RateEntry {
                    last: rate.last,
                    rate_violations: rate.rate_violations,
                    blocked_until: rate.blocked_until,
                    timestamps,
                },
            );
            stats.announce_rates += 1;
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
            used: entry.used,
        }
    }
}

fn tail_random_blobs(blobs: &[[u8; 10]]) -> Vec<[u8; 10]> {
    blobs[blobs.len().saturating_sub(PERSIST_RANDOM_BLOBS)..].to_vec()
}

impl TransportEngine {
    /// Whether the destination type filter lets a path with this cached
    /// announce be restored (upstream 20e25a9f). Like upstream, the type is
    /// the name hash after the announce's public key; an announce too short
    /// to hold one is not filtered.
    fn admits_restored_announce(&self, raw: &[u8]) -> bool {
        let Ok(packet) = RawPacket::unpack(raw) else {
            return true;
        };
        let start = constants::KEYSIZE / 8;
        let Some(name_hash) = packet
            .data()
            .get(start..start + constants::NAME_HASH_LENGTH / 8)
        else {
            return true;
        };
        let mut destination_type = [0u8; constants::NAME_HASH_LENGTH / 8];
        destination_type.copy_from_slice(name_hash);
        self.destination_filter.admits_restored(&destination_type)
    }
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

    /// `[byte; 32]` as the packet hashlist stores and snapshots it: the
    /// first 16 bytes, the rest zero.
    fn stored(byte: u8) -> [u8; 32] {
        let mut hash = [0u8; 32];
        hash[..16].fill(byte);
        hash
    }
    use crate::constants;
    use crate::hash;
    use crate::packet::{PacketFlags, RawPacket};
    use crate::transport::tables::PathEntry;
    use crate::transport::tunnel::TunnelPath;
    use crate::transport::types::{
        IngressControlConfig, InterfaceId, InterfaceInfo, PacketHashlistAllocation, TransportConfig,
    };
    use crate::transport::TransportEngine;
    use alloc::collections::BTreeMap;
    use alloc::string::String;
    use alloc::vec;

    fn config(hash_capacity: usize) -> TransportConfig {
        config_with_allocation(hash_capacity, PacketHashlistAllocation::Eager)
    }

    fn config_with_allocation(
        hash_capacity: usize,
        allocation: PacketHashlistAllocation,
    ) -> TransportConfig {
        TransportConfig {
            transport_enabled: true,
            identity_hash: Some([0x42; 16]),
            local_hops_delta: 0,
            prefer_shorter_path: false,
            max_paths_per_destination: 4,
            packet_hashlist_max_entries: hash_capacity,
            packet_hashlist_allocation: allocation,
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

    #[test]
    fn restore_packet_hashes_into_lazy_storage_preserves_order_and_truncates() {
        let mut engine =
            TransportEngine::new(config_with_allocation(3, PacketHashlistAllocation::Lazy));
        let snapshot = TransportStateSnapshot {
            packet_hashes: vec![[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]],
            paths: Vec::new(),
            tunnels: Vec::new(),
            announce_rates: Vec::new(),
        };

        let stats = engine.restore_persistence_snapshot(snapshot, 100.0, |_| None);

        assert_eq!(stats.packet_hashes, 3);
        assert_eq!(
            engine.persistence_snapshot().packet_hashes,
            vec![stored(3), stored(4), stored(5)]
        );
    }

    fn interface(id: u64, name: &str) -> InterfaceInfo {
        InterfaceInfo {
            stamp_costs: Default::default(),
            id: InterfaceId(id),
            name: String::from(name),
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

    /// An announce whose name hash (after the 64-byte public key) is
    /// `name_hash`.
    fn typed_announce(dest: [u8; 16], name_hash: [u8; 10]) -> RawPacket {
        let mut data = vec![0x77; constants::KEYSIZE / 8];
        data.extend_from_slice(&name_hash);
        data.extend_from_slice(&[0x66; 74]);
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
            &data,
        )
        .unwrap()
    }

    #[test]
    fn restore_skips_paths_whose_destination_type_is_filtered() {
        // Upstream 20e25a9f: a blocked type, or with required_only a type
        // not allowed, is not loaded into the path table.
        let blocked = typed_announce([1; 16], [0xB1; 10]);
        let allowed = typed_announce([2; 16], [0xA1; 10]);
        let other = typed_announce([3; 16], [0xC1; 10]);
        let short = announce([4; 16]);
        let packets = [&blocked, &allowed, &other, &short];
        let snapshot = |packets: &[&RawPacket]| TransportStateSnapshot {
            packet_hashes: Vec::new(),
            paths: packets
                .iter()
                .map(|packet| persisted_path(packet.destination_hash, packet, "alpha"))
                .collect(),
            tunnels: Vec::new(),
            announce_rates: Vec::new(),
        };
        let cache: BTreeMap<[u8; 32], Vec<u8>> = packets
            .iter()
            .map(|packet| (packet.packet_hash, packet.raw.clone()))
            .collect();

        let mut engine = TransportEngine::new(config(8));
        engine.register_interface(interface(7, "alpha"));
        engine.destination_filter_mut().block([0xB1; 10]);
        let stats = engine.restore_persistence_snapshot(snapshot(&packets), 100.0, |hash| {
            cache.get(hash).cloned()
        });
        assert_eq!((stats.paths, stats.filtered_paths), (3, 1));
        assert!(!engine.has_path(&[1; 16]));
        assert!(engine.has_path(&[2; 16]));
        assert!(engine.has_path(&[3; 16]));
        // Too short to carry a type: not filtered, as upstream.
        assert!(engine.has_path(&[4; 16]));

        let mut engine = TransportEngine::new(config(8));
        engine.register_interface(interface(7, "alpha"));
        engine.destination_filter_mut().set_required_only(true);
        engine.destination_filter_mut().allow([0xA1; 10]);
        let stats = engine.restore_persistence_snapshot(snapshot(&packets), 100.0, |hash| {
            cache.get(hash).cloned()
        });
        assert_eq!((stats.paths, stats.filtered_paths), (2, 2));
        assert!(engine.has_path(&[2; 16]));
        assert!(!engine.has_path(&[3; 16]));
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
            used: 0.0,
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
                used: 0.0,
            },
        );

        let snapshot = engine.persistence_snapshot();
        assert_eq!(
            snapshot.packet_hashes,
            vec![stored(2), stored(3), stored(4)]
        );
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
                used: 0.0,
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
            announce_rates: Vec::new(),
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
            vec![stored(2), stored(3)]
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
        assert_eq!(
            snapshot.tunnels[0].expires,
            100.0 + constants::TUNNEL_TIMEOUT
        );
        assert_eq!(snapshot.tunnels[0].paths[0].expires, 500.0);

        let mut restored = TransportEngine::new(config(8));
        let stats = restored.restore_persistence_snapshot(snapshot, 101.0, |hash| {
            (hash == &packet.packet_hash).then(|| packet.raw.clone())
        });
        assert_eq!(stats.tunnels, 1);
        let round_trip = restored.persistence_snapshot();
        assert_eq!(round_trip.tunnels.len(), 1);
        assert_eq!(round_trip.tunnels[0].interface_hash, None);
        // A restored tunnel waits at most TUNNEL_RECONNECT_WINDOW (023849ed).
        assert_eq!(
            round_trip.tunnels[0].expires,
            101.0 + constants::TUNNEL_RECONNECT_WINDOW
        );
        assert_eq!(round_trip.tunnels[0].paths[0].expires, 500.0);
        assert_eq!(round_trip.tunnels[0].paths[0].destination_hash, [5; 16]);

        // An expiry already inside the window is kept.
        let mut snapshot = restored.persistence_snapshot();
        snapshot.tunnels[0].expires = 300.0;
        let mut again = TransportEngine::new(config(8));
        again.restore_persistence_snapshot(snapshot, 200.0, |hash| {
            (hash == &packet.packet_hash).then(|| packet.raw.clone())
        });
        assert_eq!(again.persistence_snapshot().tunnels[0].expires, 300.0);
    }

    /// Upstream d5f1e014 persists the announce rate table, so a restart
    /// keeps a blocked destination blocked until its penalty ends.
    #[test]
    fn announce_rate_block_survives_snapshot_restore() {
        let dest = [0x3A; 16];
        let mut source = TransportEngine::new(config(8));
        // target 10s, grace 0, penalty 30s: the second fast announce blocks
        // until 100 + 10 + 30 = 140.
        assert!(!source
            .rate_limiter
            .check_and_update(&dest, 100.0, Some(10.0), 0, 30.0));
        assert!(source
            .rate_limiter
            .check_and_update(&dest, 101.0, Some(10.0), 0, 30.0));

        let snapshot = source.persistence_snapshot();
        assert_eq!(
            snapshot.announce_rates,
            vec![PersistedAnnounceRate {
                destination_hash: dest,
                last: 100.0,
                rate_violations: 1,
                blocked_until: 140.0,
                timestamps: vec![100.0, 101.0],
            }]
        );

        let mut restored = TransportEngine::new(config(8));
        let stats = restored.restore_persistence_snapshot(snapshot, 120.0, |_| None);
        assert_eq!(stats.announce_rates, 1);
        assert!(restored
            .rate_limiter
            .check_and_update(&dest, 120.0, Some(10.0), 0, 30.0));
        // An unrestored engine would admit it as a first announce.
        assert!(!TransportEngine::new(config(8))
            .rate_limiter
            .check_and_update(&dest, 120.0, Some(10.0), 0, 30.0));
    }

    #[test]
    fn restored_announce_rate_keeps_only_the_newest_timestamps() {
        let mut engine = TransportEngine::new(config(8));
        let timestamps: Vec<f64> = (0..20).map(f64::from).collect();
        engine.restore_persistence_snapshot(
            TransportStateSnapshot {
                announce_rates: vec![PersistedAnnounceRate {
                    destination_hash: [1; 16],
                    last: 19.0,
                    rate_violations: 0,
                    blocked_until: 0.0,
                    timestamps: timestamps.clone(),
                }],
                ..TransportStateSnapshot::default()
            },
            20.0,
            |_| None,
        );
        assert_eq!(
            engine.persistence_snapshot().announce_rates[0].timestamps,
            timestamps[20 - constants::MAX_RATE_TIMESTAMPS..].to_vec()
        );
    }
}
