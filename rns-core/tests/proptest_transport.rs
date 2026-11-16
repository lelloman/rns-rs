//! Property tests for transport engine invariants: path table updates,
//! packet deduplication, announce rate limiting and hop counting.
//!
//! The engine is driven through its public API (`handle_inbound`, `tick`,
//! `inject_path`, the announce queues and rate limiter) and checked against
//! small reference models of the rules it implements.

use std::collections::{BTreeMap, VecDeque};
use std::sync::OnceLock;

use proptest::prelude::*;

use rns_core::announce::AnnounceData;
use rns_core::constants;
use rns_core::destination::{destination_hash, name_hash};
use rns_core::packet::{PacketFlags, RawPacket};
use rns_core::transport::announce_queue::{AnnounceQueues, InterfaceAnnounceQueue};
use rns_core::transport::dedup::PacketHashlist;
use rns_core::transport::pathfinder::MAX_EMISSION_TIME_SKEW_SECS;
use rns_core::transport::rate_limit::AnnounceRateLimiter;
use rns_core::transport::tables::PathEntry;
use rns_core::transport::types::{
    IngressControlConfig, InterfaceId, InterfaceInfo, PacketHashlistAllocation, TransportAction,
    TransportConfig,
};
use rns_core::transport::{InboundFrame, RxMetadata, TransportEngine};
use rns_crypto::identity::Identity;
use rns_crypto::FixedRng;

/// `cases` per property, unless `PROPTEST_CASES` asks for a deeper run.
fn config(cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|cases| cases.parse().ok())
        .unwrap_or(cases);
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

// =============================================================================
// Engine harness
// =============================================================================

/// A wall-clock time in the range real announces carry.
const NOW: f64 = 1_700_000_000.0;

fn transport_config(identity_hash: Option<[u8; 16]>, hashlist_max: usize) -> TransportConfig {
    TransportConfig {
        transport_enabled: identity_hash.is_some(),
        identity_hash,
        local_hops_delta: 0,
        prefer_shorter_path: false,
        max_paths_per_destination: 1,
        packet_hashlist_max_entries: hashlist_max,
        packet_hashlist_allocation: PacketHashlistAllocation::Eager,
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

fn interface(id: u64, bitrate: Option<u64>, announce_cap: f64) -> InterfaceInfo {
    InterfaceInfo {
        stamp_costs: Default::default(),
        id: InterfaceId(id),
        name: format!("prop-{id}"),
        mode: constants::MODE_FULL,
        gravity: 0,
        recursive_prs: false,
        announces_from_internal: true,
        announces_to_internal: None,
        out_capable: true,
        in_capable: true,
        bitrate,
        airtime_profile: None,
        announce_rate_target: None,
        announce_rate_grace: 0,
        announce_rate_penalty: 0.0,
        announce_cap,
        is_local_client: false,
        wants_tunnel: false,
        hop_limiter: None,
        tunnel_id: None,
        mtu: constants::MTU as u32,
        mtu_upgradable: false,
        ingress_control: IngressControlConfig::disabled(),
        ia_freq: 0.0,
        ip_freq: 0.0,
        op_freq: 0.0,
        op_samples: 0,
        started: 0.0,
    }
}

fn engine(identity_hash: Option<[u8; 16]>, hashlist_max: usize) -> TransportEngine {
    let mut engine = TransportEngine::new(transport_config(identity_hash, hashlist_max));
    engine.register_interface(interface(1, None, constants::ANNOUNCE_CAP));
    engine.register_interface(interface(2, None, constants::ANNOUNCE_CAP));
    engine
}

fn inbound(engine: &mut TransportEngine, raw: &[u8], iface: u64, now: f64) -> Vec<TransportAction> {
    let mut rng = FixedRng::new(&[0x42; 32]);
    engine.handle_inbound(
        InboundFrame {
            raw,
            iface: InterfaceId(iface),
            now,
            rx: RxMetadata::default(),
        },
        &mut rng,
    )
}

fn sent_on(actions: &[TransportAction]) -> Vec<(InterfaceId, Vec<u8>)> {
    actions
        .iter()
        .filter_map(|action| match action {
            TransportAction::SendOnInterface { interface, raw } => Some((*interface, raw.to_vec())),
            _ => None,
        })
        .collect()
}

// =============================================================================
// Signed announces
// =============================================================================

/// Emission time carried in bytes 5..10 of an announce's random blob.
fn emitted(blob: &[u8; 10]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes[3..].copy_from_slice(&blob[5..]);
    u64::from_be_bytes(bytes)
}

struct AnnouncePool {
    destination: [u8; 16],
    /// Signed announce payloads and the random blob each carries.
    announces: Vec<(Vec<u8>, [u8; 10])>,
}

/// Announces for one destination, signed once and shared by every case.
/// They differ in their random blob: some share an emission time, and the
/// last claims an emission time implausibly far in the future.
fn announce_pool() -> &'static AnnouncePool {
    static POOL: OnceLock<AnnouncePool> = OnceLock::new();
    POOL.get_or_init(|| {
        let identity = Identity::from_private_key(&[0x37; 64]);
        let destination = destination_hash("proptest", &["path"], Some(identity.hash()));
        let name = name_hash("proptest", &["path"]);
        let base = NOW as u64 - 1000;
        let emissions = [
            base,
            base,
            base + 1,
            base + 2,
            base + 3,
            base + 5,
            NOW as u64 + 3 * MAX_EMISSION_TIME_SKEW_SECS,
        ];
        let announces = emissions
            .iter()
            .enumerate()
            .map(|(i, emission)| {
                let mut blob = [i as u8 + 1; 10];
                blob[5..].copy_from_slice(&emission.to_be_bytes()[3..]);
                let (data, _) =
                    AnnounceData::pack(&identity, &destination, &name, &blob, None, None).unwrap();
                (data, blob)
            })
            .collect();
        AnnouncePool {
            destination,
            announces,
        }
    })
}

fn announce_raw(data: &[u8], destination: &[u8; 16], hops: u8) -> Vec<u8> {
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
    };
    RawPacket::pack(
        flags,
        hops,
        destination,
        None,
        constants::CONTEXT_NONE,
        data,
    )
    .unwrap()
    .raw
}

fn wire_hops() -> impl Strategy<Value = u8> {
    prop_oneof![
        4 => 0u8..8,
        1 => (constants::PATHFINDER_M - 4)..constants::PATHFINDER_M,
    ]
}

// =============================================================================
// Path table
// =============================================================================

/// What the path table should hold for the pool's destination.
#[derive(Debug, Clone, PartialEq)]
struct ModelPath {
    hops: u8,
    expires: f64,
    random_blobs: Vec<[u8; 10]>,
}

/// An emission time counts only when it is not implausibly far ahead of
/// `now`; otherwise it is treated as unknown (0).
fn trusted(emitted: u64, now: f64) -> u64 {
    if emitted as f64 <= now + MAX_EMISSION_TIME_SKEW_SECS as f64 {
        emitted
    } else {
        0
    }
}

/// The path replacement rules (upstream Transport.py inbound announce
/// handling, plus the distrust of implausible emission times) for a single
/// next hop, a responsive path, interfaces of equal gravity, no transport
/// (so no announce table) and `prefer_shorter_path` off:
///
/// - an unknown destination takes the first path;
/// - an announce for a destination still in the path table, expired or
///   not, is prefiltered unless its emission time is later than every
///   emission time the path has seen (upstream 096e6726);
/// - an announce with no more hops replaces the path when its random blob
///   is new and its emission time is later than every emission time the
///   path has seen;
/// - an announce with more hops replaces the path when its random blob is
///   new and either the path has expired or its emission time is later.
///   After the prefilter only the later emission time can apply, until the
///   expired path is culled.
fn model_accepts(path: Option<&ModelPath>, hops: u8, blob: &[u8; 10], now: f64) -> bool {
    if hops > constants::PATHFINDER_M {
        return false;
    }
    let Some(path) = path else {
        return true;
    };
    let blob_is_new = !path.random_blobs.contains(blob);
    let announce_emitted = trusted(emitted(blob), now);
    let path_timebase = path
        .random_blobs
        .iter()
        .map(|blob| trusted(emitted(blob), now))
        .max()
        .unwrap_or(0);
    if announce_emitted <= path_timebase {
        return false;
    }
    if hops <= path.hops {
        blob_is_new && announce_emitted > path_timebase
    } else {
        blob_is_new && (now >= path.expires || announce_emitted > path_timebase)
    }
}

fn path_for(engine: &TransportEngine, destination: &[u8; 16]) -> Option<PathEntry> {
    engine
        .path_table_entries()
        .find(|(dest, _)| *dest == destination)
        .map(|(_, entry)| entry.clone())
}

#[derive(Debug, Clone)]
struct AnnounceStep {
    announce: usize,
    hops: u8,
    advance: f64,
    iface: u64,
}

fn announce_steps() -> impl Strategy<Value = Vec<AnnounceStep>> {
    let len = announce_pool().announces.len();
    prop::collection::vec(
        (
            0..len,
            wire_hops(),
            prop_oneof![
                4 => Just(0.0),
                4 => 0.0..120.0f64,
                1 => Just(constants::PATHFINDER_E + 1.0),
            ],
            1u64..=2,
        )
            .prop_map(|(announce, hops, advance, iface)| AnnounceStep {
                announce,
                hops,
                advance,
                iface,
            }),
        1..24,
    )
}

proptest! {
    #![proptest_config(config(64))]

    /// After every announce the path table holds exactly what the
    /// replacement rules say, and no path is longer than PATHFINDER_M.
    #[test]
    fn path_table_follows_replacement_rules(steps in announce_steps()) {
        let pool = announce_pool();
        let dest = pool.destination;
        let mut engine = engine(None, constants::HASHLIST_MAXSIZE);
        let mut model: Option<ModelPath> = None;
        let mut now = NOW;

        for step in steps {
            now += step.advance;
            let (data, blob) = &pool.announces[step.announce];
            let raw = announce_raw(data, &dest, step.hops);
            inbound(&mut engine, &raw, step.iface, now);

            let hops = step.hops + 1;
            if model_accepts(model.as_ref(), hops, blob, now) {
                let mut random_blobs = model.take().map(|p| p.random_blobs).unwrap_or_default();
                if !random_blobs.contains(blob) {
                    random_blobs.push(*blob);
                }
                model = Some(ModelPath {
                    hops,
                    expires: now + constants::PATHFINDER_E,
                    random_blobs,
                });
            }

            let path = path_for(&engine, &dest);
            let actual = path.as_ref().map(|p| ModelPath {
                hops: p.hops,
                expires: p.expires,
                random_blobs: p.random_blobs.clone(),
            });
            prop_assert_eq!(&actual, &model, "after {:?} at {}", step, now);
            if let Some(path) = path {
                prop_assert!(path.hops <= constants::PATHFINDER_M);
                prop_assert_eq!(engine.hops_to(&dest), Some(path.hops));
            }
        }
    }
}

// =============================================================================
// Packet deduplication
// =============================================================================

#[derive(Debug, Clone)]
enum HashlistOp {
    Add(u8),
    Remove(u8),
}

fn hash_of(seed: u8) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    hash[31] = seed.wrapping_mul(7);
    hash
}

proptest! {
    #![proptest_config(config(256))]

    /// The packet hashlist behaves as a FIFO of unique hashes bounded by its
    /// size: a retained hash is a duplicate, re-adding one does not refresh
    /// it, and the oldest hash is evicted first.
    #[test]
    fn packet_hashlist_matches_fifo_model(
        max_size in 0usize..12,
        seeded in prop::option::of(any::<u64>()),
        lazy in any::<bool>(),
        ops in prop::collection::vec(
            prop_oneof![
                4 => (0u8..24).prop_map(HashlistOp::Add),
                1 => (0u8..24).prop_map(HashlistOp::Remove),
            ],
            0..64,
        ),
    ) {
        let allocation = if lazy {
            PacketHashlistAllocation::Lazy
        } else {
            PacketHashlistAllocation::Eager
        };
        let mut list = PacketHashlist::with_allocation(max_size, allocation);
        if let Some(seed) = seeded {
            list.seed_hashing(seed);
        }
        let mut model: VecDeque<u8> = VecDeque::new();
        for op in ops {
            match op {
                HashlistOp::Add(seed) => {
                    list.add(hash_of(seed));
                    if max_size > 0 && !model.contains(&seed) {
                        if model.len() == max_size {
                            model.pop_front();
                        }
                        model.push_back(seed);
                    }
                }
                HashlistOp::Remove(seed) => {
                    let was_there = model.iter().position(|s| *s == seed);
                    if let Some(at) = was_there {
                        model.remove(at);
                    }
                    prop_assert_eq!(list.remove(&hash_of(seed)), was_there.is_some());
                }
            }
            prop_assert_eq!(list.len(), model.len());
            for seed in 0u8..24 {
                prop_assert_eq!(list.is_duplicate(&hash_of(seed)), model.contains(&seed));
            }
            let retained: Vec<[u8; 32]> = list.iter().collect();
            let expected: Vec<[u8; 32]> = model
                .iter()
                .map(|seed| {
                    let mut hash = [0u8; 32];
                    hash[..16].copy_from_slice(&hash_of(*seed)[..16]);
                    hash
                })
                .collect();
            prop_assert_eq!(retained, expected);
        }
    }
}

fn data_packet(dest: &[u8; 16], payload: u8, hops: u8) -> Vec<u8> {
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    RawPacket::pack(
        flags,
        hops,
        dest,
        None,
        constants::CONTEXT_NONE,
        &[payload; 9],
    )
    .unwrap()
    .raw
}

proptest! {
    #![proptest_config(config(128))]

    /// A data packet for a local destination is delivered the first time and
    /// dropped on every later delivery while its hash is retained (whatever
    /// hop count the copy carries), and delivered again only once newer
    /// packets have pushed its hash out of the window.
    #[test]
    fn duplicate_packets_are_delivered_once_per_window(
        window in 1usize..8,
        deliveries in prop::collection::vec((0u8..12, 0u8..6, 1u64..=2), 1..48),
    ) {
        let dest = [0x5d; 16];
        let mut engine = engine(None, window);
        engine.register_destination(dest, constants::DESTINATION_SINGLE);
        let mut seen: VecDeque<u8> = VecDeque::new();
        let mut now = NOW;

        for (payload, hops, iface) in deliveries {
            now += 0.5;
            let raw = data_packet(&dest, payload, hops);
            let actions = inbound(&mut engine, &raw, iface, now);
            let delivered = actions
                .iter()
                .filter(|action| matches!(action, TransportAction::DeliverLocal { .. }))
                .count();
            let duplicate = seen.contains(&payload);
            prop_assert_eq!(delivered, usize::from(!duplicate), "payload {}", payload);
            if !duplicate {
                if seen.len() == window {
                    seen.pop_front();
                }
                seen.push_back(payload);
            }
        }
    }
}

// =============================================================================
// Announce rate limiting
// =============================================================================

proptest! {
    #![proptest_config(config(256))]

    /// Per-destination announce rate limiting: the first announce passes, no
    /// rate target never blocks, and an announce that passes less than
    /// `rate_target` after the previous one that passed is a violation, of
    /// which at most `rate_grace` can pass in a row. Nothing passes while
    /// a block is in force.
    #[test]
    fn announce_rate_limiter_allows_at_most_grace_rapid_announces(
        rate_target in 1.0f64..60.0,
        rate_grace in 0u32..4,
        rate_penalty in 0.0f64..60.0,
        gaps in prop::collection::vec(prop_oneof![0.0f64..5.0, 0.0f64..120.0], 1..64),
    ) {
        let dest = [0x11; 16];
        let mut limiter = AnnounceRateLimiter::new();
        let mut unlimited = AnnounceRateLimiter::new();
        let mut now = NOW;
        let mut last_pass: Option<f64> = None;
        let mut rapid_run = 0u32;

        for (i, gap) in gaps.into_iter().enumerate() {
            now += gap;
            let blocked_until = limiter
                .entries()
                .find(|(d, _)| **d == dest)
                .map(|(_, entry)| entry.blocked_until);
            let blocked =
                limiter.check_and_update(&dest, now, Some(rate_target), rate_grace, rate_penalty);
            prop_assert!(!unlimited.check_and_update(&dest, now, None, rate_grace, rate_penalty));
            if i == 0 {
                prop_assert!(!blocked, "the first announce is never blocked");
            }
            if blocked {
                continue;
            }
            if let Some(blocked_until) = blocked_until {
                prop_assert!(now > blocked_until, "passed at {} while blocked until {}", now, blocked_until);
            }
            if let Some(last) = last_pass {
                if now - last < rate_target {
                    rapid_run += 1;
                } else {
                    rapid_run = 0;
                }
                prop_assert!(
                    rapid_run <= rate_grace,
                    "{} rapid announces passed in a row with grace {}",
                    rapid_run,
                    rate_grace
                );
            }
            last_pass = Some(now);
        }
    }
}

#[derive(Debug, Clone)]
enum QueueOp {
    /// Gate an announce of this many bytes on an interface after a delay.
    Gate {
        advance: f64,
        iface: u64,
        len: usize,
    },
    /// Run the queue processing after a delay.
    Process { advance: f64 },
}

fn queue_ops() -> impl Strategy<Value = Vec<QueueOp>> {
    let advance = prop_oneof![3 => Just(0.0), 3 => 0.0..2.0f64, 1 => 0.0..30.0f64];
    prop::collection::vec(
        prop_oneof![
            (advance.clone(), 1u64..=2, 20usize..=500).prop_map(|(advance, iface, len)| {
                QueueOp::Gate {
                    advance,
                    iface,
                    len,
                }
            }),
            advance.prop_map(|advance| QueueOp::Process { advance }),
        ],
        1..64,
    )
}

proptest! {
    #![proptest_config(config(256))]

    /// Announces released on an interface with a bitrate keep within its
    /// announce cap: after an announce of `len` bytes, the next one is not
    /// released before `len * 8 / bitrate / announce_cap` seconds have
    /// passed, whether it was sent at once or released from the queue.
    #[test]
    fn announce_queue_releases_within_bandwidth_cap(
        bitrates in (100u64..20_000, 100u64..20_000),
        announce_cap in 0.01f64..=1.0,
        ops in queue_ops(),
    ) {
        let mut interfaces = BTreeMap::new();
        interfaces.insert(InterfaceId(1), interface(1, Some(bitrates.0), announce_cap));
        interfaces.insert(InterfaceId(2), interface(2, Some(bitrates.1), announce_cap));
        let mut queues = AnnounceQueues::new(16);
        let mut now = NOW;
        let mut next_dest = 0u32;
        // Earliest time each interface may release another announce.
        let mut allowed_at: BTreeMap<InterfaceId, f64> = BTreeMap::new();

        let mut check_release = |interface: InterfaceId, len: usize, now: f64|
            -> Result<(), TestCaseError>
        {
            if let Some(&at) = allowed_at.get(&interface) {
                prop_assert!(
                    now + 1e-9 >= at,
                    "announce released on {:?} at {} before {}",
                    interface,
                    now,
                    at
                );
            }
            let info = &interfaces[&interface];
            let next = InterfaceAnnounceQueue::calculate_next_allowed(
                now,
                len,
                info.bitrate.unwrap(),
                None,
                info.announce_cap,
            );
            prop_assert!(next > now);
            allowed_at.insert(interface, next);
            Ok(())
        };

        for op in ops {
            match op {
                QueueOp::Gate { advance, iface, len } => {
                    now += advance;
                    next_dest += 1;
                    let mut dest = [0u8; 16];
                    dest[..4].copy_from_slice(&next_dest.to_be_bytes());
                    let info = &interfaces[&InterfaceId(iface)];
                    let sent = queues.gate_announce(
                        InterfaceId(iface),
                        vec![0xa5; len].into(),
                        dest,
                        1,
                        now,
                        now,
                        info.bitrate,
                        None,
                        info.announce_cap,
                    );
                    if let Some(TransportAction::SendOnInterface { interface, raw }) = sent {
                        prop_assert_eq!(interface, InterfaceId(iface));
                        check_release(interface, raw.len(), now)?;
                    }
                }
                QueueOp::Process { advance } => {
                    now += advance;
                    let released = queues.process_queues(now, &interfaces);
                    for action in released {
                        let TransportAction::SendOnInterface { interface, raw } = action else {
                            panic!("unexpected action {action:?}");
                        };
                        check_release(interface, raw.len(), now)?;
                    }
                }
            }
        }
    }
}

// =============================================================================
// Hop counting
// =============================================================================

fn transport_id(node: usize) -> [u8; 16] {
    [0x80 + node as u8; 16]
}

proptest! {
    #![proptest_config(config(128))]

    /// A packet relayed through a chain of transport nodes gains exactly one
    /// hop at each node. Every node but the last rewrites the transport id to
    /// its next hop; the last strips the transport header. Destination,
    /// context, payload and packet hash are untouched throughout.
    #[test]
    fn forwarded_packets_gain_one_hop_per_node(
        nodes in 1usize..6,
        start_hops in 0u8..64,
        dest in any::<[u8; 16]>(),
        destination_type in prop::sample::select(vec![
            constants::DESTINATION_SINGLE,
            constants::DESTINATION_LINK,
        ]),
        payload in prop::collection::vec(any::<u8>(), 1..200),
    ) {
        let mut engines: Vec<TransportEngine> = (0..nodes)
            .map(|node| {
                let mut engine = engine(Some(transport_id(node)), constants::HASHLIST_MAXSIZE);
                engine.inject_path(
                    dest,
                    PathEntry {
                        timestamp: NOW,
                        next_hop: transport_id(node + 1),
                        hops: (nodes - node) as u8,
                        expires: NOW + constants::PATHFINDER_E,
                        random_blobs: Vec::new(),
                        receiving_interface: InterfaceId(2),
                        packet_hash: [0; 32],
                        used: 0.0,
                        announce_raw: None,
                    },
                );
                engine
            })
            .collect();

        let flags = PacketFlags {
            header_type: constants::HEADER_2,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_TRANSPORT,
            destination_type,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let first = RawPacket::pack(
            flags,
            start_hops,
            &dest,
            Some(&transport_id(0)),
            constants::CONTEXT_NONE,
            &payload,
        )
        .unwrap();
        let mut raw = first.raw.clone();

        for (node, engine) in engines.iter_mut().enumerate() {
            let incoming = RawPacket::unpack(&raw).unwrap();
            let sent = sent_on(&inbound(engine, &raw, 1, NOW));
            prop_assert_eq!(sent.len(), 1, "node {} sent {:?}", node, sent);
            let (out_iface, out_raw) = &sent[0];
            prop_assert_eq!(*out_iface, InterfaceId(2));
            let out = RawPacket::unpack(out_raw).unwrap();
            prop_assert_eq!(out.hops, incoming.hops + 1);
            prop_assert_eq!(out.hops as usize, start_hops as usize + node + 1);
            if node + 1 < nodes {
                prop_assert_eq!(out.flags.header_type, constants::HEADER_2);
                prop_assert_eq!(out.transport_id, Some(transport_id(node + 1)));
            } else {
                prop_assert_eq!(out.flags.header_type, constants::HEADER_1);
                prop_assert_eq!(out.transport_id, None);
            }
            prop_assert_eq!(out.flags.destination_type, destination_type);
            prop_assert_eq!(out.destination_hash, dest);
            prop_assert_eq!(out.context, constants::CONTEXT_NONE);
            prop_assert_eq!(out.data(), &payload[..]);
            prop_assert_eq!(out.packet_hash, first.packet_hash);
            raw = out_raw.clone();
        }
    }

    /// A transport node rebroadcasts a received announce with exactly one
    /// more hop than it arrived with, and never with a hop count that does
    /// not decode (PATHFINDER_M or more).
    #[test]
    fn rebroadcast_announces_gain_one_hop(
        announce in 0usize..6,
        hops in wire_hops(),
    ) {
        let pool = announce_pool();
        let (data, _) = &pool.announces[announce];
        let raw = announce_raw(data, &pool.destination, hops);
        let mut engine = engine(Some(transport_id(0)), constants::HASHLIST_MAXSIZE);
        inbound(&mut engine, &raw, 1, NOW);
        prop_assert_eq!(engine.hops_to(&pool.destination), Some(hops + 1));

        let mut rng = FixedRng::new(&[0x42; 32]);
        let mut rebroadcasts = Vec::new();
        for step in 1..=4 {
            let now = NOW + step as f64 * constants::PATHFINDER_RW;
            for (_, out) in sent_on(&engine.tick(now, &mut rng)) {
                rebroadcasts.push(out);
            }
        }
        for out in &rebroadcasts {
            let out = RawPacket::unpack(out);
            prop_assert!(out.is_ok(), "rebroadcast does not decode: {:?}", out.err());
            let out = out.unwrap();
            prop_assert_eq!(out.flags.packet_type, constants::PACKET_TYPE_ANNOUNCE);
            prop_assert_eq!(out.hops, hops + 1);
            prop_assert_eq!(out.transport_id, Some(transport_id(0)));
            prop_assert_eq!(out.data(), &data[..]);
        }
        if hops + 1 < constants::PATHFINDER_M {
            prop_assert!(!rebroadcasts.is_empty(), "announce was not rebroadcast");
        }
    }
}
