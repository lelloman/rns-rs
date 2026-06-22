use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use rns_core::announce::AnnounceData;
use rns_core::constants;
use rns_core::destination;
use rns_core::packet::{PacketFlags, RawPacket};
use rns_core::transport::types::{
    IngressControlConfig, InterfaceId, InterfaceInfo, TransportConfig,
};
use rns_core::transport::{InboundFrame, RxMetadata, TransportEngine};
use rns_crypto::identity::Identity;
use rns_crypto::FixedRng;

fn make_config(transport_enabled: bool) -> TransportConfig {
    TransportConfig {
        transport_enabled,
        identity_hash: if transport_enabled {
            Some([0x42; 16])
        } else {
            None
        },
        prefer_shorter_path: false,
        max_paths_per_destination: 2,
        packet_hashlist_max_entries: constants::HASHLIST_MAXSIZE,
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

fn make_interface(id: u64, mode: u8, is_local_client: bool) -> InterfaceInfo {
    InterfaceInfo {
        id: InterfaceId(id),
        name: format!("bench-{id}"),
        mode,
        recursive_prs: false,
        out_capable: true,
        in_capable: true,
        bitrate: None,
        airtime_profile: None,
        announce_rate_target: None,
        announce_rate_grace: 0,
        announce_rate_penalty: 0.0,
        announce_cap: constants::ANNOUNCE_CAP,
        is_local_client,
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

fn build_announce_packet(identity: &Identity, name_hash: [u8; 10], hops: u8) -> RawPacket {
    let dest_hash = destination::destination_hash("bench", &["announce"], Some(identity.hash()));
    let random_hash = [name_hash[0]; 10];
    let (announce_data, has_ratchet) = AnnounceData::pack(
        identity,
        &dest_hash,
        &name_hash,
        &random_hash,
        None,
        Some(b"bench-app-data"),
    )
    .unwrap();
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: if has_ratchet {
            constants::FLAG_SET
        } else {
            constants::FLAG_UNSET
        },
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
    };
    RawPacket::pack(
        flags,
        hops,
        &dest_hash,
        None,
        constants::CONTEXT_NONE,
        &announce_data,
    )
    .unwrap()
}

fn build_announce_packets(count: usize) -> Vec<RawPacket> {
    (0..count)
        .map(|i| {
            let mut prv = [0u8; 64];
            for (j, byte) in prv.iter_mut().enumerate() {
                *byte = (i as u8)
                    .wrapping_mul(17)
                    .wrapping_add(j as u8)
                    .wrapping_add(1);
            }
            let identity = Identity::from_private_key(&prv);
            let mut name_hash = [0u8; 10];
            name_hash[..8].copy_from_slice(&(i as u64).to_be_bytes());
            name_hash[8] = (i as u8).wrapping_mul(3);
            name_hash[9] = (i as u8).wrapping_mul(7);
            build_announce_packet(&identity, name_hash, 1)
        })
        .collect()
}

fn build_broadcast_announce() -> RawPacket {
    let identity = Identity::from_private_key(&[0x42; 64]);
    let name_hash = destination::name_hash("bench", &["fanout"]);
    build_announce_packet(&identity, name_hash, 1)
}

fn bench_announce_fanout(c: &mut Criterion) {
    let packet = build_broadcast_announce();
    let mut group = c.benchmark_group("transport_announce");
    group.sample_size(10);
    group.throughput(Throughput::Elements(8));
    group.bench_function("outbound_fanout_8_interfaces", |b| {
        b.iter_batched(
            || {
                let mut engine = TransportEngine::new(make_config(true));
                for id in 0..8 {
                    engine.register_interface(make_interface(id + 1, constants::MODE_FULL, false));
                }
                engine
            },
            |mut engine| {
                black_box(engine.handle_outbound(
                    &packet,
                    constants::DESTINATION_SINGLE,
                    None,
                    1000.0,
                ))
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_path_table_churn(c: &mut Criterion) {
    let packets = build_announce_packets(128);
    let mut group = c.benchmark_group("transport_path_table");
    group.sample_size(10);
    group.throughput(Throughput::Elements(packets.len() as u64));
    group.bench_function("inbound_announce_insert_128", |b| {
        b.iter_batched(
            || {
                let mut engine = TransportEngine::new(make_config(true));
                engine.register_interface(make_interface(1, constants::MODE_FULL, false));
                let rng = FixedRng::new(&[0x5A; 128]);
                (engine, rng)
            },
            |(mut engine, mut rng)| {
                for packet in &packets {
                    black_box(engine.handle_inbound(
                        InboundFrame {
                            raw: &packet.raw,
                            iface: InterfaceId(1),
                            now: 1000.0 + f64::from(packet.raw[2]),
                            rx: RxMetadata {
                                rssi: None,
                                snr: None,
                            },
                        },
                        &mut rng,
                    ));
                }
                black_box(engine.path_table_count())
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(benches, bench_announce_fanout, bench_path_table_churn);
criterion_main!(benches);
