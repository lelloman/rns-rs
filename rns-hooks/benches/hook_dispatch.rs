use criterion::{criterion_group, criterion_main, Criterion};
use rns_hooks::engine_access::NullEngine;
use rns_hooks::hooks::HookContext;
use rns_hooks::manager::HookManager;
use rns_hooks::{create_hook_slots, hook_noop, PacketContext};
use std::path::PathBuf;

fn wasm_examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/wasm-examples")
}

/// Baseline: call the noop function pointer (cost when no hooks are loaded).
fn bench_noop_slot(c: &mut Criterion) {
    let slots = create_hook_slots();
    let pkt_ctx = PacketContext {
        flags: 0,
        hops: 0,
        destination_hash: [0u8; 16],
        context: 0,
        packet_hash: [0u8; 32],
        interface_id: 0,
        data_offset: 0,
        data_len: 64,
    };
    let ctx = HookContext::Packet { ctx: &pkt_ctx, raw: &[] };

    c.bench_function("noop_slot", |b| {
        b.iter(|| {
            let _ = hook_noop(&slots[0], &ctx);
        });
    });
}

/// Load a trivial hook (announce_filter) and benchmark a single execution.
fn bench_trivial_hook(c: &mut Criterion) {
    let mgr = match HookManager::new() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Skipping trivial_hook bench: {}", e);
            return;
        }
    };

    let path = wasm_examples_dir().join("announce_filter.wasm");
    if !path.exists() {
        eprintln!(
            "Skipping trivial_hook bench: {} not found. Run build-examples.sh first.",
            path.display()
        );
        return;
    }

    let mut prog = mgr
        .load_file("announce_filter".to_string(), &path, 0)
        .expect("failed to load announce_filter.wasm");

    let ctx = HookContext::Announce {
        destination_hash: [0xAA; 16],
        hops: 3,
        interface_id: 1,
    };

    c.bench_function("trivial_hook", |b| {
        b.iter(|| {
            let _ = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0, None);
        });
    });
}

/// Load a more complex hook (packet_logger) that calls host functions
/// and benchmark a single execution.
fn bench_complex_hook(c: &mut Criterion) {
    let mgr = match HookManager::new() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Skipping complex_hook bench: {}", e);
            return;
        }
    };

    let path = wasm_examples_dir().join("packet_logger.wasm");
    if !path.exists() {
        eprintln!(
            "Skipping complex_hook bench: {} not found. Run build-examples.sh first.",
            path.display()
        );
        return;
    }

    let mut prog = mgr
        .load_file("packet_logger".to_string(), &path, 0)
        .expect("failed to load packet_logger.wasm");

    let pkt_ctx = PacketContext {
        flags: 0,
        hops: 0,
        destination_hash: [0u8; 16],
        context: 0,
        packet_hash: [0u8; 32],
        interface_id: 1,
        data_offset: 0,
        data_len: 128,
    };
    let ctx = HookContext::Packet { ctx: &pkt_ctx, raw: &[] };

    c.bench_function("complex_hook", |b| {
        b.iter(|| {
            let _ = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0, None);
        });
    });
}

criterion_group!(benches, bench_noop_slot, bench_trivial_hook, bench_complex_hook);
criterion_main!(benches);
