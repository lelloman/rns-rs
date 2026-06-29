use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use rns_core::constants;
use rns_core::packet::RawPacket;
use rns_crypto::ed25519::Ed25519PrivateKey;
use rns_crypto::{FixedRng, Rng};
use rns_net::link_manager::{LinkManager, ResourceStrategy};
use rns_net::{InterfaceId, LinkManagerAction};

fn make_rng(seed: u8) -> FixedRng {
    FixedRng::new(&[seed; 128])
}

fn make_dest_keys(rng: &mut dyn Rng) -> (Ed25519PrivateKey, [u8; 32]) {
    let sig_prv = Ed25519PrivateKey::generate(rng);
    let sig_pub_bytes = sig_prv.public_key().public_bytes();
    (sig_prv, sig_pub_bytes)
}

fn extract_send_packet(actions: &[LinkManagerAction]) -> Vec<u8> {
    actions
        .iter()
        .find_map(|action| match action {
            LinkManagerAction::SendPacket { raw, .. } => Some(raw.clone()),
            _ => None,
        })
        .expect("expected SendPacket action")
}

fn extract_send_packet_at(actions: &[LinkManagerAction], index: usize) -> Vec<u8> {
    match &actions[index] {
        LinkManagerAction::SendPacket { raw, .. } => raw.clone(),
        _ => panic!("expected SendPacket at index {index}"),
    }
}

fn extract_any_send_packet(actions: &[LinkManagerAction]) -> Vec<u8> {
    extract_send_packet(actions)
}

fn setup_active_link() -> (LinkManager, LinkManager, [u8; 16]) {
    let mut rng = make_rng(0x31);
    let dest_hash = [0xDD; 16];

    let mut responder_mgr = LinkManager::new();
    let (sig_prv, sig_pub_bytes) = make_dest_keys(&mut rng);
    responder_mgr.register_link_destination(
        dest_hash,
        sig_prv,
        sig_pub_bytes,
        ResourceStrategy::AcceptAll,
    );

    let mut initiator_mgr = LinkManager::new();
    let (link_id, init_actions) = initiator_mgr.create_link(
        &dest_hash,
        &sig_pub_bytes,
        1,
        constants::MTU as u32,
        &mut rng,
    );
    let linkrequest_raw = extract_send_packet_at(&init_actions, 1);
    let lr_packet = RawPacket::unpack(&linkrequest_raw).unwrap();

    let resp_actions = responder_mgr.handle_local_delivery(
        lr_packet.destination_hash,
        &linkrequest_raw,
        lr_packet.packet_hash,
        InterfaceId(0),
        &mut rng,
    );
    let lrproof_raw = extract_send_packet_at(&resp_actions, 1);
    let lrproof_packet = RawPacket::unpack(&lrproof_raw).unwrap();

    let init_actions2 = initiator_mgr.handle_local_delivery(
        lrproof_packet.destination_hash,
        &lrproof_raw,
        lrproof_packet.packet_hash,
        InterfaceId(0),
        &mut rng,
    );
    let lrrtt_raw = extract_any_send_packet(&init_actions2);
    let lrrtt_packet = RawPacket::unpack(&lrrtt_raw).unwrap();

    responder_mgr.handle_local_delivery(
        lrrtt_packet.destination_hash,
        &lrrtt_raw,
        lrrtt_packet.packet_hash,
        InterfaceId(0),
        &mut rng,
    );

    (initiator_mgr, responder_mgr, link_id)
}

fn bench_send_on_link(c: &mut Criterion) {
    let payload = vec![0xAB; 256];
    let mut group = c.benchmark_group("link_dispatch");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(payload.len() as u64));
    group.bench_function("send_on_link_256b", |b| {
        b.iter_batched(
            setup_active_link,
            |(init_mgr, _resp_mgr, link_id)| {
                let mut rng = make_rng(0x41);
                black_box(init_mgr.send_on_link(
                    &link_id,
                    &payload,
                    constants::CONTEXT_NONE,
                    &mut rng,
                ))
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_send_request(c: &mut Criterion) {
    let request_data = vec![0xC0; 128];
    let mut group = c.benchmark_group("link_request_dispatch");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(request_data.len() as u64));
    group.bench_function("send_request_128b", |b| {
        b.iter_batched(
            setup_active_link,
            |(mut init_mgr, mut resp_mgr, link_id)| {
                resp_mgr.register_request_handler(
                    "/bench",
                    None,
                    |_link_id, _path, _data, _remote| Some(b"OK".to_vec()),
                );
                let mut rng = make_rng(0x51);
                black_box(init_mgr.send_request(&link_id, "/bench", &request_data, &mut rng))
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_send_resource(c: &mut Criterion) {
    let payload = vec![0xCD; 4096];
    let mut group = c.benchmark_group("resource_dispatch");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(payload.len() as u64));
    group.bench_function("send_resource_4k", |b| {
        b.iter_batched(
            setup_active_link,
            |(mut init_mgr, _resp_mgr, link_id)| {
                let mut rng = make_rng(0x61);
                black_box(init_mgr.send_resource(&link_id, &payload, None, &mut rng))
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_send_on_link,
    bench_send_request,
    bench_send_resource
);
criterion_main!(benches);
