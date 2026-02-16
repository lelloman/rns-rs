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
