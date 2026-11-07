//! The packet deduplication table at its default retention, full: what
//! every new packet costs once 250,000 hashes are retained (a check, then
//! an insert that evicts the oldest), and a check of a retained hash.

use criterion::{criterion_group, criterion_main, Criterion};
use rns_core::transport::dedup::PacketHashlist;
use rns_core::transport::types::PacketHashlistAllocation;
use std::hint::black_box;

const RETAINED: usize = rns_core::constants::HASHLIST_MAXSIZE;

/// Distinct pseudo-random packet hashes.
fn hashes(seed: u64) -> impl Iterator<Item = [u8; 32]> {
    let mut state = seed;
    core::iter::repeat_with(move || {
        let mut hash = [0u8; 32];
        for chunk in hash.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chunk.copy_from_slice(&state.to_le_bytes());
        }
        hash
    })
}

fn full_table(allocation: PacketHashlistAllocation) -> PacketHashlist {
    let mut table = PacketHashlist::with_allocation(RETAINED, allocation);
    table.seed_hashing(0x5eed);
    for hash in hashes(1).take(RETAINED) {
        table.add(hash);
    }
    table
}

fn bench_full_table(c: &mut Criterion) {
    let mut group = c.benchmark_group("dedup/full");
    let mut table = full_table(PacketHashlistAllocation::Eager);
    let mut fresh = hashes(2);
    group.bench_function("new_packet", |b| {
        b.iter(|| {
            let hash = fresh.next().unwrap();
            if !table.is_duplicate(black_box(&hash)) {
                table.add(hash);
            }
        })
    });
    let table = full_table(PacketHashlistAllocation::Eager);
    let retained: Vec<[u8; 32]> = hashes(1).take(RETAINED).collect();
    let mut next = 0;
    group.bench_function("duplicate", |b| {
        b.iter(|| {
            next = (next + 7919) % RETAINED;
            black_box(table.is_duplicate(black_box(&retained[next])))
        })
    });
    group.finish();
}

criterion_group!(benches, bench_full_table);
criterion_main!(benches);
