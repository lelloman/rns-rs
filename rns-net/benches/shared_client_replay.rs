use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use std::time::Duration;

fn bench_shared_replay(c: &mut Criterion) {
    let mut group = c.benchmark_group("shared_client_replay");
    group.sample_size(10);
    group.throughput(Throughput::Elements(8));
    group.bench_function("replay_8_announces_after_reconnect", |b| {
        b.iter_batched(
            || (),
            |_| {
                let replayed = rns_net::shared_client::bench_shared_client_replay_once(
                    8,
                    Duration::from_millis(10),
                )
                .unwrap();
                black_box(replayed);
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(benches, bench_shared_replay);
criterion_main!(benches);
