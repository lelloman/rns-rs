use rns_hooks::engine_access::NullEngine;
use rns_hooks::hooks::HookContext;
use rns_hooks::manager::HookManager;
use rns_hooks::result::Verdict;
use std::path::PathBuf;

fn wasm_examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/wasm-examples")
}

fn load_example(mgr: &HookManager, name: &str) -> Option<rns_hooks::LoadedProgram> {
    let path = wasm_examples_dir().join(format!("{}.wasm", name));
    if !path.exists() {
        eprintln!(
            "Skipping test: {} not found. Run build-examples.sh first.",
            path.display()
        );
        return None;
    }
    Some(
        mgr.load_file(name.to_string(), &path, 0)
            .expect("failed to load wasm example"),
    )
}

// --- announce_filter tests ---

#[test]
fn announce_filter_continue_low_hops() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "announce_filter") else { return };

    let ctx = HookContext::Announce {
        destination_hash: [0xAA; 16],
        hops: 3,
        interface_id: 1,
    };
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    let r = exec.hook_result.unwrap();
    assert_eq!(r.verdict, Verdict::Continue as u32);
}

#[test]
fn announce_filter_drop_high_hops() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "announce_filter") else { return };

    let ctx = HookContext::Announce {
        destination_hash: [0xBB; 16],
        hops: 12,
        interface_id: 2,
    };
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    let r = exec.hook_result.unwrap();
    assert!(r.is_drop());
}

#[test]
fn announce_filter_continue_non_announce() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "announce_filter") else { return };

    let ctx = HookContext::Tick;
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    let r = exec.hook_result.unwrap();
    assert_eq!(r.verdict, Verdict::Continue as u32);
}

// --- packet_logger tests ---

#[test]
fn packet_logger_continue_on_packet() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "packet_logger") else { return };

    let pkt = rns_hooks::PacketContext {
        flags: 0,
        hops: 2,
        destination_hash: [0x11; 16],
        context: 0,
        packet_hash: [0x22; 32],
        interface_id: 5,
        data_offset: 0,
        data_len: 0,
    };
    let ctx = HookContext::Packet(&pkt);
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    let r = exec.hook_result.unwrap();
    assert_eq!(r.verdict, Verdict::Continue as u32);
}

#[test]
fn packet_logger_continue_on_tick() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "packet_logger") else { return };

    let ctx = HookContext::Tick;
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    let r = exec.hook_result.unwrap();
    assert_eq!(r.verdict, Verdict::Continue as u32);
}

#[test]
fn packet_logger_continue_on_announce() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "packet_logger") else { return };

    let ctx = HookContext::Announce {
        destination_hash: [0xCC; 16],
        hops: 1,
        interface_id: 3,
    };
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    let r = exec.hook_result.unwrap();
    assert_eq!(r.verdict, Verdict::Continue as u32);
}

// --- path_modifier tests ---

#[test]
fn path_modifier_modify_on_packet() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "path_modifier") else { return };

    let pkt = rns_hooks::PacketContext {
        flags: 0,
        hops: 1,
        destination_hash: [0x33; 16],
        context: 0,
        packet_hash: [0x44; 32],
        interface_id: 7,
        data_offset: 0,
        data_len: 0,
    };
    let ctx = HookContext::Packet(&pkt);
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    let r = exec.hook_result.unwrap();
    assert_eq!(r.verdict, Verdict::Modify as u32);
    // Modified data should start with the 0xFF marker byte
    let data = exec.modified_data.unwrap();
    assert_eq!(data[0], 0xFF);
}

#[test]
fn path_modifier_continue_on_non_packet() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "path_modifier") else { return };

    let ctx = HookContext::Tick;
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    let r = exec.hook_result.unwrap();
    assert_eq!(r.verdict, Verdict::Continue as u32);
}

// --- chain test ---

#[test]
fn chain_filter_drop_stops_logger() {
    let mgr = HookManager::new().unwrap();
    let filter = load_example(&mgr, "announce_filter");
    let logger = load_example(&mgr, "packet_logger");
    let (Some(mut filter), Some(logger)) = (filter, logger) else { return };

    // Set filter to high priority so it runs first
    filter.priority = 100;
    let mut programs = vec![filter, logger];
    programs.sort_by(|a, b| b.priority.cmp(&a.priority));

    // Announce with high hops → filter drops, logger should not run
    let ctx = HookContext::Announce {
        destination_hash: [0xDD; 16],
        hops: 15,
        interface_id: 1,
    };
    let exec = mgr
        .run_chain(&mut programs, &ctx, &NullEngine, 0.0)
        .unwrap();
    let r = exec.hook_result.unwrap();
    assert!(r.is_drop());
}

// --- rate_limiter tests ---

fn make_packet_ctx() -> rns_hooks::PacketContext {
    rns_hooks::PacketContext {
        flags: 0,
        hops: 1,
        destination_hash: [0x11; 16],
        context: 0,
        packet_hash: [0x22; 32],
        interface_id: 1,
        data_offset: 0,
        data_len: 0,
    }
}

#[test]
fn rate_limiter_continues_below_threshold() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "rate_limiter") else { return };

    let pkt = make_packet_ctx();
    let ctx = HookContext::Packet(&pkt);
    // First call — well below MAX_PACKETS=100
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert_eq!(exec.hook_result.unwrap().verdict, Verdict::Continue as u32);
}

#[test]
fn rate_limiter_drops_after_threshold() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "rate_limiter") else { return };

    let pkt = make_packet_ctx();
    let ctx = HookContext::Packet(&pkt);
    // Send 100 packets (all should continue)
    for _ in 0..100 {
        let exec = mgr
            .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
            .unwrap();
        assert_eq!(exec.hook_result.unwrap().verdict, Verdict::Continue as u32);
    }
    // 101st should be dropped
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert!(exec.hook_result.unwrap().is_drop());
}

#[test]
fn rate_limiter_continues_on_non_packet() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "rate_limiter") else { return };

    let ctx = HookContext::Tick;
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert_eq!(exec.hook_result.unwrap().verdict, Verdict::Continue as u32);
}

// --- allowlist tests ---

#[test]
fn allowlist_drops_unknown_announce() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "allowlist") else { return };

    // 0xAA prefix is not in the allowlist
    let ctx = HookContext::Announce {
        destination_hash: [0xAA; 16],
        hops: 1,
        interface_id: 1,
    };
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert!(exec.hook_result.unwrap().is_drop());
}

#[test]
fn allowlist_allows_known_prefix() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "allowlist") else { return };

    // 0x0000 prefix IS in the allowlist
    let mut dest = [0x00; 16];
    dest[2] = 0x42; // rest doesn't matter
    let ctx = HookContext::Announce {
        destination_hash: dest,
        hops: 1,
        interface_id: 1,
    };
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert_eq!(exec.hook_result.unwrap().verdict, Verdict::Continue as u32);
}

#[test]
fn allowlist_drops_unknown_link() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "allowlist") else { return };

    let ctx = HookContext::Link {
        link_id: [0xBB; 16],
        interface_id: 1,
    };
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert!(exec.hook_result.unwrap().is_drop());
}

#[test]
fn allowlist_continues_on_tick() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "allowlist") else { return };

    let ctx = HookContext::Tick;
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert_eq!(exec.hook_result.unwrap().verdict, Verdict::Continue as u32);
}

// --- packet_mirror tests ---

#[test]
fn packet_mirror_continues_and_injects_action() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "packet_mirror") else { return };

    let pkt = make_packet_ctx();
    let ctx = HookContext::Packet(&pkt);
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert_eq!(exec.hook_result.unwrap().verdict, Verdict::Continue as u32);
    // Should have injected a SendOnInterface action
    assert_eq!(exec.injected_actions.len(), 1);
}

#[test]
fn packet_mirror_no_action_on_non_packet() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "packet_mirror") else { return };

    let ctx = HookContext::Tick;
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert_eq!(exec.hook_result.unwrap().verdict, Verdict::Continue as u32);
    assert!(exec.injected_actions.is_empty());
}

// --- link_guard tests ---

#[test]
fn link_guard_continues_below_threshold() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "link_guard") else { return };

    let ctx = HookContext::Link {
        link_id: [0x11; 16],
        interface_id: 1,
    };
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert_eq!(exec.hook_result.unwrap().verdict, Verdict::Continue as u32);
}

#[test]
fn link_guard_drops_after_threshold() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "link_guard") else { return };

    let ctx = HookContext::Link {
        link_id: [0x11; 16],
        interface_id: 1,
    };
    // Send 50 link requests (all should continue)
    for _ in 0..50 {
        let exec = mgr
            .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
            .unwrap();
        assert_eq!(exec.hook_result.unwrap().verdict, Verdict::Continue as u32);
    }
    // 51st should be dropped
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert!(exec.hook_result.unwrap().is_drop());
}

#[test]
fn link_guard_continues_on_non_link() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "link_guard") else { return };

    let ctx = HookContext::Tick;
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert_eq!(exec.hook_result.unwrap().verdict, Verdict::Continue as u32);
}

// --- announce_dedup tests ---

#[test]
fn announce_dedup_allows_first_few() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "announce_dedup") else { return };

    let ctx = HookContext::Announce {
        destination_hash: [0xAA; 16],
        hops: 1,
        interface_id: 1,
    };
    // First 3 should continue (MAX_RETRANSMITS=3, drop on >= 3 seen)
    for _ in 0..3 {
        let exec = mgr
            .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
            .unwrap();
        assert_eq!(exec.hook_result.unwrap().verdict, Verdict::Continue as u32);
    }
}

#[test]
fn announce_dedup_suppresses_after_threshold() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "announce_dedup") else { return };

    let ctx = HookContext::Announce {
        destination_hash: [0xBB; 16],
        hops: 1,
        interface_id: 1,
    };
    // First 3 continue
    for _ in 0..3 {
        mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0, None).unwrap();
    }
    // 4th should be dropped
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert!(exec.hook_result.unwrap().is_drop());
}

#[test]
fn announce_dedup_different_dests_independent() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "announce_dedup") else { return };

    let ctx_a = HookContext::Announce {
        destination_hash: [0xCC; 16],
        hops: 1,
        interface_id: 1,
    };
    let ctx_b = HookContext::Announce {
        destination_hash: [0xDD; 16],
        hops: 1,
        interface_id: 1,
    };
    // Interleave — each should get its own counter
    for _ in 0..3 {
        let exec = mgr
            .execute_program(&mut prog, &ctx_a, &NullEngine, 0.0, None)
            .unwrap();
        assert_eq!(exec.hook_result.unwrap().verdict, Verdict::Continue as u32);
        let exec = mgr
            .execute_program(&mut prog, &ctx_b, &NullEngine, 0.0, None)
            .unwrap();
        assert_eq!(exec.hook_result.unwrap().verdict, Verdict::Continue as u32);
    }
}

#[test]
fn announce_dedup_continues_on_non_announce() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "announce_dedup") else { return };

    let ctx = HookContext::Tick;
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert_eq!(exec.hook_result.unwrap().verdict, Verdict::Continue as u32);
}

// --- metrics tests ---

#[test]
fn metrics_continues_on_all_context_types() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "metrics") else { return };

    let pkt = make_packet_ctx();
    let contexts: Vec<HookContext> = vec![
        HookContext::Packet(&pkt),
        HookContext::Tick,
        HookContext::Announce {
            destination_hash: [0x11; 16],
            hops: 1,
            interface_id: 1,
        },
        HookContext::Link {
            link_id: [0x22; 16],
            interface_id: 1,
        },
        HookContext::Interface { interface_id: 1 },
    ];

    for ctx in &contexts {
        let exec = mgr
            .execute_program(&mut prog, ctx, &NullEngine, 0.0, None)
            .unwrap();
        assert_eq!(
            exec.hook_result.unwrap().verdict,
            Verdict::Continue as u32,
            "metrics should always return Continue"
        );
    }
}

#[test]
fn metrics_no_injected_actions() {
    let mgr = HookManager::new().unwrap();
    let Some(mut prog) = load_example(&mgr, "metrics") else { return };

    let pkt = make_packet_ctx();
    let ctx = HookContext::Packet(&pkt);
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert!(exec.injected_actions.is_empty());
}
