use super::wasm::HOST_ABI_VERSION;
use super::*;
use crate::engine_access::NullEngine;
use wasmtime::Store;

fn make_manager() -> HookManager {
    HookManager::new().expect("failed to create HookManager")
}

/// WAT module that returns Continue (verdict=0).
const WAT_CONTINUE: &str = r#"
        (module
            (memory (export "memory") 1)
            (func (export "__rns_abi_version") (result i32) (i32.const 2))
            (func (export "on_hook") (param i32) (result i32)
                ;; Write HookResult at offset 0x2000
                ;; verdict = 0 (Continue)
                (i32.store (i32.const 0x2000) (i32.const 0))
                ;; modified_data_offset = 0
                (i32.store (i32.add (i32.const 0x2000) (i32.const 4)) (i32.const 0))
                ;; modified_data_len = 0
                (i32.store (i32.add (i32.const 0x2000) (i32.const 8)) (i32.const 0))
                (i32.const 0x2000)
            )
        )
    "#;

/// WAT module that returns Drop (verdict=1).
const WAT_DROP: &str = r#"
        (module
            (memory (export "memory") 1)
            (func (export "__rns_abi_version") (result i32) (i32.const 2))
            (func (export "on_hook") (param i32) (result i32)
                (i32.store (i32.const 0x2000) (i32.const 1))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 4)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 8)) (i32.const 0))
                (i32.const 0x2000)
            )
        )
    "#;

/// WAT module that traps immediately.
const WAT_TRAP: &str = r#"
        (module
            (memory (export "memory") 1)
            (func (export "__rns_abi_version") (result i32) (i32.const 2))
            (func (export "on_hook") (param i32) (result i32)
                unreachable
            )
        )
    "#;

/// WAT module with infinite loop (will exhaust fuel).
const WAT_INFINITE: &str = r#"
        (module
            (memory (export "memory") 1)
            (func (export "__rns_abi_version") (result i32) (i32.const 2))
            (func (export "on_hook") (param i32) (result i32)
                (loop $inf (br $inf))
                (i32.const 0)
            )
        )
    "#;

/// Exhausts fuel on the first call, then succeeds from the same cached
/// instance. This verifies both store recovery and per-call fuel reset.
const WAT_FUEL_RECOVERY: &str = r#"
        (module
            (memory (export "memory") 1)
            (global $calls (mut i32) (i32.const 0))
            (func (export "__rns_abi_version") (result i32) (i32.const 2))
            (func (export "on_hook") (param i32) (result i32)
                (global.set $calls (i32.add (global.get $calls) (i32.const 1)))
                (if (i32.eq (global.get $calls) (i32.const 1))
                    (then (loop $inf (br $inf))))
                (i32.store (i32.const 0x2000) (i32.const 0))
                (i32.store (i32.const 0x2004) (i32.const 0))
                (i32.store (i32.const 0x2008) (i32.const 0))
                (i32.store (i32.const 0x200c) (i32.const 0))
                (i32.store (i32.const 0x2010) (i32.const 0))
                (i32.store (i32.const 0x2014) (i32.const 0))
                (i32.store (i32.const 0x2018) (i32.const 0))
                (i32.const 0x2000))
        )
    "#;

/// Exercises Wasmtime's fuel-accounted bulk-memory implementation and
/// returns the copied bytes through the hook ABI.
const WAT_BULK_MEMORY: &str = r#"
        (module
            (memory (export "memory") 2)
            (func (export "__rns_abi_version") (result i32) (i32.const 2))
            (func (export "on_hook") (param i32) (result i32)
                (memory.fill (i32.const 0x10000) (i32.const 0x5a) (i32.const 0x4000))
                (memory.copy (i32.const 0x14000) (i32.const 0x10000) (i32.const 0x4000))
                (i32.store (i32.const 0x2000) (i32.const 2))
                (i32.store (i32.const 0x2004) (i32.const 0x14000))
                (i32.store (i32.const 0x2008) (i32.const 0x4000))
                (i32.store (i32.const 0x200c) (i32.const 0))
                (i32.store (i32.const 0x2010) (i32.const 0))
                (i32.store (i32.const 0x2014) (i32.const 0))
                (i32.store (i32.const 0x2018) (i32.const 0))
                (i32.const 0x2000))
        )
    "#;

/// WAT module that calls host_has_path and drops if path exists.
const WAT_HOST_HAS_PATH: &str = r#"
        (module
            (import "env" "host_has_path" (func $has_path (param i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "__rns_abi_version") (result i32) (i32.const 2))
            (func (export "on_hook") (param $ctx_ptr i32) (result i32)
                ;; Check if path exists for a 16-byte dest at offset 0x3000
                ;; (we'll write the dest hash there in the test)
                (if (call $has_path (i32.const 0x3000))
                    (then
                        ;; Drop
                        (i32.store (i32.const 0x2000) (i32.const 1))
                    )
                    (else
                        ;; Continue
                        (i32.store (i32.const 0x2000) (i32.const 0))
                    )
                )
                (i32.store (i32.add (i32.const 0x2000) (i32.const 4)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 8)) (i32.const 0))
                (i32.const 0x2000)
            )
        )
    "#;

#[test]
fn pass_through() {
    let mgr = make_manager();
    let mut prog = mgr
        .compile("test".into(), WAT_CONTINUE.as_bytes(), 0)
        .unwrap();
    let ctx = HookContext::Tick;
    let result = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0, None);
    // Continue → Some with verdict=0
    let exec = result.unwrap();
    let r = exec.hook_result.unwrap();
    assert_eq!(r.verdict, Verdict::Continue as u32);
}

#[test]
fn drop_hook() {
    let mgr = make_manager();
    let mut prog = mgr
        .compile("dropper".into(), WAT_DROP.as_bytes(), 0)
        .unwrap();
    let ctx = HookContext::Tick;
    let result = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0, None);
    let exec = result.unwrap();
    let r = exec.hook_result.unwrap();
    assert!(r.is_drop());
}

#[test]
fn trap_failopen() {
    let mgr = make_manager();
    let mut prog = mgr.compile("trap".into(), WAT_TRAP.as_bytes(), 0).unwrap();
    let ctx = HookContext::Tick;
    let result = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0, None);
    assert!(result.is_none());
    assert_eq!(prog.consecutive_traps, 1);
    assert!(prog.enabled);
}

#[test]
fn auto_disable() {
    let mgr = make_manager();
    let mut prog = mgr.compile("bad".into(), WAT_TRAP.as_bytes(), 0).unwrap();
    let ctx = HookContext::Tick;
    for _ in 0..10 {
        let _ = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0, None);
    }
    assert!(!prog.enabled);
    assert_eq!(prog.consecutive_traps, 10);
}

#[test]
fn fuel_exhaustion() {
    let mgr = make_manager();
    let mut prog = mgr
        .compile("loop".into(), WAT_INFINITE.as_bytes(), 0)
        .unwrap();
    let ctx = HookContext::Tick;
    let result = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0, None);
    // Should fail-open (fuel exhausted = trap)
    assert!(result.is_none());
    assert_eq!(prog.consecutive_traps, 1);
}

#[test]
fn fuel_exhaustion_recovers_cached_store_on_next_call() {
    let mgr = make_manager();
    let mut prog = mgr
        .compile("fuel-recovery".into(), WAT_FUEL_RECOVERY.as_bytes(), 0)
        .unwrap();
    let ctx = HookContext::Tick;

    assert!(mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .is_none());
    assert_eq!(prog.consecutive_traps, 1);

    let recovered = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .expect("fuel must be reset before reusing the cached store");
    assert_eq!(
        recovered.hook_result.unwrap().verdict,
        Verdict::Continue as u32
    );
    assert_eq!(prog.consecutive_traps, 0);
}

#[test]
fn bulk_memory_fill_and_copy_preserve_all_bytes() {
    let mgr = make_manager();
    let mut prog = mgr
        .compile("bulk-memory".into(), WAT_BULK_MEMORY.as_bytes(), 0)
        .unwrap();

    let result = mgr
        .execute_program(&mut prog, &HookContext::Tick, &NullEngine, 0.0, None)
        .unwrap();
    let copied = result.modified_data.unwrap();
    assert_eq!(copied.len(), 0x4000);
    assert!(copied.iter().all(|byte| *byte == 0x5a));
}

#[test]
fn chain_ordering() {
    let mgr = make_manager();
    let high = mgr
        .compile("high".into(), WAT_DROP.as_bytes(), 100)
        .unwrap();
    let low = mgr
        .compile("low".into(), WAT_CONTINUE.as_bytes(), 0)
        .unwrap();
    // Programs sorted by priority desc: high first
    let mut programs = vec![high, low];
    // Sort descending by priority (as attach would do)
    programs.sort_by_key(|program| std::cmp::Reverse(program.priority));

    let ctx = HookContext::Tick;
    let result = mgr.run_chain(&mut programs, &ctx, &NullEngine, 0.0);
    // High priority drops → chain stops
    let exec = result.unwrap();
    let r = exec.hook_result.unwrap();
    assert!(r.is_drop());
}

#[test]
fn attach_detach() {
    use crate::hooks::HookSlot;

    let mgr = make_manager();
    let mut slot = HookSlot {
        programs: Vec::new(),
        runner: crate::hooks::hook_noop,
    };

    let p1 = mgr
        .compile("alpha".into(), WAT_CONTINUE.as_bytes(), 10)
        .unwrap();
    let p2 = mgr.compile("beta".into(), WAT_DROP.as_bytes(), 20).unwrap();

    slot.attach(p1);
    assert_eq!(slot.programs.len(), 1);
    assert!(!std::ptr::eq(
        slot.runner as *const (),
        crate::hooks::hook_noop as *const (),
    ));

    slot.attach(p2);
    assert_eq!(slot.programs.len(), 2);
    // Sorted descending: beta(20) before alpha(10)
    assert_eq!(slot.programs[0].name, "beta");
    assert_eq!(slot.programs[1].name, "alpha");

    let removed = slot.detach("beta");
    assert!(removed.is_some());
    assert_eq!(slot.programs.len(), 1);
    assert_eq!(slot.programs[0].name, "alpha");

    let removed2 = slot.detach("alpha");
    assert!(removed2.is_some());
    assert!(slot.programs.is_empty());
    assert_eq!(
        slot.runner as *const () as usize,
        crate::hooks::hook_noop as *const () as usize
    );
}

#[test]
fn host_has_path() {
    use crate::engine_access::EngineAccess;

    struct MockEngine;
    impl EngineAccess for MockEngine {
        fn has_path(&self, _dest: &[u8; 16]) -> bool {
            true
        }
        fn hops_to(&self, _: &[u8; 16]) -> Option<u8> {
            None
        }
        fn next_hop(&self, _: &[u8; 16]) -> Option<[u8; 16]> {
            None
        }
        fn is_blackholed(&self, _: &[u8; 16]) -> bool {
            false
        }
        fn interface_name(&self, _: u64) -> Option<String> {
            None
        }
        fn interface_mode(&self, _: u64) -> Option<u8> {
            None
        }
        fn identity_hash(&self) -> Option<[u8; 16]> {
            None
        }
        fn announce_rate(&self, _: u64) -> Option<i32> {
            None
        }
        fn link_state(&self, _: &[u8; 16]) -> Option<u8> {
            None
        }
    }

    let mgr = make_manager();
    let mut prog = mgr
        .compile("pathcheck".into(), WAT_HOST_HAS_PATH.as_bytes(), 0)
        .unwrap();
    let ctx = HookContext::Tick;
    let result = mgr.execute_program(&mut prog, &ctx, &MockEngine, 0.0, None);
    // MockEngine.has_path returns true → WASM drops
    let exec = result.unwrap();
    let r = exec.hook_result.unwrap();
    assert!(r.is_drop());
}

#[test]
fn host_has_path_null_engine() {
    // NullEngine.has_path returns false → WASM continues
    let mgr = make_manager();
    let mut prog = mgr
        .compile("pathcheck".into(), WAT_HOST_HAS_PATH.as_bytes(), 0)
        .unwrap();
    let ctx = HookContext::Tick;
    let result = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0, None);
    let exec = result.unwrap();
    let r = exec.hook_result.unwrap();
    assert_eq!(r.verdict, Verdict::Continue as u32);
}

// --- New Phase 2 tests ---

/// Configurable mock engine for testing host functions.
struct MockEngineCustom {
    announce_rate_val: Option<i32>,
    link_state_val: Option<u8>,
}

impl EngineAccess for MockEngineCustom {
    fn has_path(&self, _: &[u8; 16]) -> bool {
        false
    }
    fn hops_to(&self, _: &[u8; 16]) -> Option<u8> {
        None
    }
    fn next_hop(&self, _: &[u8; 16]) -> Option<[u8; 16]> {
        None
    }
    fn is_blackholed(&self, _: &[u8; 16]) -> bool {
        false
    }
    fn interface_name(&self, _: u64) -> Option<String> {
        None
    }
    fn interface_mode(&self, _: u64) -> Option<u8> {
        None
    }
    fn identity_hash(&self) -> Option<[u8; 16]> {
        None
    }
    fn announce_rate(&self, _: u64) -> Option<i32> {
        self.announce_rate_val
    }
    fn link_state(&self, _: &[u8; 16]) -> Option<u8> {
        self.link_state_val
    }
}

/// WAT: calls host_get_announce_rate(42), if result >= 0 → Drop, else Continue.
const WAT_ANNOUNCE_RATE: &str = r#"
        (module
            (import "env" "host_get_announce_rate" (func $get_rate (param i64) (result i32)))
            (memory (export "memory") 1)
            (func (export "__rns_abi_version") (result i32) (i32.const 2))
            (func (export "on_hook") (param $ctx_ptr i32) (result i32)
                (if (i32.ge_s (call $get_rate (i64.const 42)) (i32.const 0))
                    (then
                        (i32.store (i32.const 0x2000) (i32.const 1)) ;; Drop
                    )
                    (else
                        (i32.store (i32.const 0x2000) (i32.const 0)) ;; Continue
                    )
                )
                (i32.store (i32.add (i32.const 0x2000) (i32.const 4)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 8)) (i32.const 0))
                (i32.const 0x2000)
            )
        )
    "#;

#[test]
fn host_get_announce_rate_found() {
    // announce_rate returns Some(1500) (1.5 Hz * 1000) → Drop
    let engine = MockEngineCustom {
        announce_rate_val: Some(1500),
        link_state_val: None,
    };
    let mgr = make_manager();
    let mut prog = mgr
        .compile("rate".into(), WAT_ANNOUNCE_RATE.as_bytes(), 0)
        .unwrap();
    let ctx = HookContext::Tick;
    let exec = mgr
        .execute_program(&mut prog, &ctx, &engine, 0.0, None)
        .unwrap();
    assert!(exec.hook_result.unwrap().is_drop());
}

#[test]
fn host_get_announce_rate_not_found() {
    // announce_rate returns None → -1 → Continue
    let engine = MockEngineCustom {
        announce_rate_val: None,
        link_state_val: None,
    };
    let mgr = make_manager();
    let mut prog = mgr
        .compile("rate".into(), WAT_ANNOUNCE_RATE.as_bytes(), 0)
        .unwrap();
    let ctx = HookContext::Tick;
    let exec = mgr
        .execute_program(&mut prog, &ctx, &engine, 0.0, None)
        .unwrap();
    assert_eq!(exec.hook_result.unwrap().verdict, Verdict::Continue as u32);
}

/// WAT: calls host_get_link_state with 16-byte hash at 0x3000.
/// If state == 2 (Active) → Drop, else Continue.
const WAT_LINK_STATE: &str = r#"
        (module
            (import "env" "host_get_link_state" (func $link_state (param i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "__rns_abi_version") (result i32) (i32.const 2))
            (func (export "on_hook") (param $ctx_ptr i32) (result i32)
                (if (i32.eq (call $link_state (i32.const 0x3000)) (i32.const 2))
                    (then
                        (i32.store (i32.const 0x2000) (i32.const 1)) ;; Drop
                    )
                    (else
                        (i32.store (i32.const 0x2000) (i32.const 0)) ;; Continue
                    )
                )
                (i32.store (i32.add (i32.const 0x2000) (i32.const 4)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 8)) (i32.const 0))
                (i32.const 0x2000)
            )
        )
    "#;

#[test]
fn host_get_link_state_active() {
    // link_state returns Some(2) (Active) → Drop
    let engine = MockEngineCustom {
        announce_rate_val: None,
        link_state_val: Some(2),
    };
    let mgr = make_manager();
    let mut prog = mgr
        .compile("linkst".into(), WAT_LINK_STATE.as_bytes(), 0)
        .unwrap();
    let ctx = HookContext::Tick;
    let exec = mgr
        .execute_program(&mut prog, &ctx, &engine, 0.0, None)
        .unwrap();
    assert!(exec.hook_result.unwrap().is_drop());
}

#[test]
fn host_get_link_state_not_found() {
    // link_state returns None → -1, which != 2 → Continue
    let engine = MockEngineCustom {
        announce_rate_val: None,
        link_state_val: None,
    };
    let mgr = make_manager();
    let mut prog = mgr
        .compile("linkst".into(), WAT_LINK_STATE.as_bytes(), 0)
        .unwrap();
    let ctx = HookContext::Tick;
    let exec = mgr
        .execute_program(&mut prog, &ctx, &engine, 0.0, None)
        .unwrap();
    assert_eq!(exec.hook_result.unwrap().verdict, Verdict::Continue as u32);
}

/// WAT: writes a SendOnInterface ActionWire at 0x3000 and calls host_inject_action.
/// Binary: tag=0 (SendOnInterface), interface=1 (u64 LE), data_offset=0x3100, data_len=4
/// Data at 0x3100: [0xDE, 0xAD, 0xBE, 0xEF]
/// Returns Continue.
const WAT_INJECT_ACTION: &str = r#"
        (module
            (import "env" "host_inject_action" (func $inject (param i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "__rns_abi_version") (result i32) (i32.const 2))
            (func (export "on_hook") (param $ctx_ptr i32) (result i32)
                ;; Write the data payload at 0x3100
                (i32.store8 (i32.const 0x3100) (i32.const 0xDE))
                (i32.store8 (i32.const 0x3101) (i32.const 0xAD))
                (i32.store8 (i32.const 0x3102) (i32.const 0xBE))
                (i32.store8 (i32.const 0x3103) (i32.const 0xEF))

                ;; Write ActionWire at 0x3000:
                ;; byte 0: tag = 0 (SendOnInterface)
                (i32.store8 (i32.const 0x3000) (i32.const 0))
                ;; bytes 1-8: interface = 1 (u64 LE)
                (i64.store (i32.const 0x3001) (i64.const 1))
                ;; bytes 9-12: data_offset = 0x3100 (u32 LE)
                (i32.store (i32.const 0x3009) (i32.const 0x3100))
                ;; bytes 13-16: data_len = 4 (u32 LE)
                (i32.store (i32.const 0x300D) (i32.const 4))

                ;; Call inject: ptr=0x3000, len=17 (1 + 8 + 4 + 4)
                (drop (call $inject (i32.const 0x3000) (i32.const 17)))

                ;; Return Continue
                (i32.store (i32.const 0x2000) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 4)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 8)) (i32.const 0))
                (i32.const 0x2000)
            )
        )
    "#;

#[test]
fn host_inject_action_send() {
    let mgr = make_manager();
    let mut prog = mgr
        .compile("inject".into(), WAT_INJECT_ACTION.as_bytes(), 0)
        .unwrap();
    let ctx = HookContext::Tick;
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert_eq!(exec.hook_result.unwrap().verdict, Verdict::Continue as u32);
    assert_eq!(exec.injected_actions.len(), 1);
    match &exec.injected_actions[0] {
        crate::wire::ActionWire::SendOnInterface { interface, raw } => {
            assert_eq!(*interface, 1);
            assert_eq!(raw, &[0xDE, 0xAD, 0xBE, 0xEF]);
        }
        other => panic!("expected SendOnInterface, got {:?}", other),
    }
}

/// WAT: returns Modify (verdict=2) with modified data at 0x2100 (4 bytes).
const WAT_MODIFY: &str = r#"
        (module
            (memory (export "memory") 1)
            (func (export "__rns_abi_version") (result i32) (i32.const 2))
            (func (export "on_hook") (param $ctx_ptr i32) (result i32)
                ;; Write modified data at 0x2100
                (i32.store8 (i32.const 0x2100) (i32.const 0xAA))
                (i32.store8 (i32.const 0x2101) (i32.const 0xBB))
                (i32.store8 (i32.const 0x2102) (i32.const 0xCC))
                (i32.store8 (i32.const 0x2103) (i32.const 0xDD))

                ;; verdict = 2 (Modify)
                (i32.store (i32.const 0x2000) (i32.const 2))
                ;; modified_data_offset = 0x2100
                (i32.store (i32.add (i32.const 0x2000) (i32.const 4)) (i32.const 0x2100))
                ;; modified_data_len = 4
                (i32.store (i32.add (i32.const 0x2000) (i32.const 8)) (i32.const 4))
                (i32.const 0x2000)
            )
        )
    "#;

#[test]
fn modify_extracts_data() {
    let mgr = make_manager();
    let mut prog = mgr.compile("mod".into(), WAT_MODIFY.as_bytes(), 0).unwrap();
    let ctx = HookContext::Tick;
    let exec = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    let r = exec.hook_result.unwrap();
    assert_eq!(r.verdict, Verdict::Modify as u32);
    let data = exec.modified_data.unwrap();
    assert_eq!(data, vec![0xAA, 0xBB, 0xCC, 0xDD]);
}

#[test]
fn chain_accumulates_injected_actions() {
    // Chain: inject_action module (Continue) + Drop module
    // Both should contribute to the result; injected actions should be accumulated
    let mgr = make_manager();
    let injector = mgr
        .compile("injector".into(), WAT_INJECT_ACTION.as_bytes(), 100)
        .unwrap();
    let dropper = mgr
        .compile("dropper".into(), WAT_DROP.as_bytes(), 0)
        .unwrap();
    let mut programs = vec![injector, dropper];
    programs.sort_by_key(|program| std::cmp::Reverse(program.priority));

    let ctx = HookContext::Tick;
    let exec = mgr
        .run_chain(&mut programs, &ctx, &NullEngine, 0.0)
        .unwrap();
    // Chain should drop (second hook)
    assert!(exec.hook_result.unwrap().is_drop());
    // But injected action from first hook should be present
    assert_eq!(exec.injected_actions.len(), 1);
}

// --- Instance persistence tests ---

/// WAT module with a mutable global counter. Each call increments it and
/// writes the counter value into the verdict field (abusing it as an integer).
/// This lets us verify that the global persists across calls.
const WAT_COUNTER: &str = r#"
        (module
            (memory (export "memory") 1)
            (func (export "__rns_abi_version") (result i32) (i32.const 2))
            (global $counter (mut i32) (i32.const 0))
            (func (export "on_hook") (param i32) (result i32)
                ;; Increment counter
                (global.set $counter (i32.add (global.get $counter) (i32.const 1)))
                ;; Write counter value at 0x3000 (scratch area)
                (i32.store (i32.const 0x3000) (global.get $counter))
                ;; Return Continue with the counter stashed in modified_data region
                ;; verdict = 2 (Modify) so we can extract the counter via modified_data
                (i32.store (i32.const 0x2000) (i32.const 2))
                ;; modified_data_offset = 0x3000
                (i32.store (i32.add (i32.const 0x2000) (i32.const 4)) (i32.const 0x3000))
                ;; modified_data_len = 4
                (i32.store (i32.add (i32.const 0x2000) (i32.const 8)) (i32.const 4))
                (i32.const 0x2000)
            )
        )
    "#;

fn extract_counter(exec: &ExecuteResult) -> u32 {
    let data = exec.modified_data.as_ref().expect("no modified data");
    assert_eq!(data.len(), 4);
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

#[test]
fn instance_persistence_counter() {
    let mgr = make_manager();
    let mut prog = mgr
        .compile("counter".into(), WAT_COUNTER.as_bytes(), 0)
        .unwrap();
    let ctx = HookContext::Tick;

    // Call 3 times — counter should increment across calls
    let exec1 = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert_eq!(extract_counter(&exec1), 1);

    let exec2 = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert_eq!(extract_counter(&exec2), 2);

    let exec3 = mgr
        .execute_program(&mut prog, &ctx, &NullEngine, 0.0, None)
        .unwrap();
    assert_eq!(extract_counter(&exec3), 3);
}

// --- ABI version validation tests ---

/// WAT module without __rns_abi_version export.
const WAT_NO_ABI_VERSION: &str = r#"
        (module
            (memory (export "memory") 1)
            (func (export "on_hook") (param i32) (result i32)
                (i32.store (i32.const 0x2000) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 4)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 8)) (i32.const 0))
                (i32.const 0x2000)
            )
        )
    "#;

/// WAT module with wrong ABI version (9999).
const WAT_WRONG_ABI_VERSION: &str = r#"
        (module
            (memory (export "memory") 1)
            (func (export "__rns_abi_version") (result i32) (i32.const 9999))
            (func (export "on_hook") (param i32) (result i32)
                (i32.store (i32.const 0x2000) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 4)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 8)) (i32.const 0))
                (i32.const 0x2000)
            )
        )
    "#;

/// WAT module built against ABI version 1, whose result was 28 bytes:
/// the current fields followed by four reserved words.
const WAT_ABI_V1: &str = r#"
        (module
            (memory (export "memory") 1)
            (func (export "__rns_abi_version") (result i32) (i32.const 1))
            (func (export "on_hook") (param i32) (result i32)
                (i32.store (i32.const 0x2000) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 4)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 8)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 12)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 16)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 20)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 24)) (i32.const 0))
                (i32.const 0x2000)
            )
        )
    "#;

#[test]
fn rejects_abi_v1_hook() {
    let mgr = make_manager();
    let result = mgr.compile("v1_hook".into(), WAT_ABI_V1.as_bytes(), 0);
    match result {
        Err(HookError::AbiVersionMismatch {
            hook_name,
            expected,
            found,
        }) => {
            assert_eq!(hook_name, "v1_hook");
            assert_eq!(expected, 2);
            assert_eq!(found, Some(1));
        }
        other => panic!(
            "expected AbiVersionMismatch with found=Some(1), got {:?}",
            other.err()
        ),
    }
}

#[test]
fn rejects_missing_abi_version() {
    let mgr = make_manager();
    let result = mgr.compile("no_abi".into(), WAT_NO_ABI_VERSION.as_bytes(), 0);
    match result {
        Err(HookError::AbiVersionMismatch {
            hook_name,
            expected,
            found,
        }) => {
            assert_eq!(hook_name, "no_abi");
            assert_eq!(expected, HOST_ABI_VERSION);
            assert_eq!(found, None);
        }
        other => panic!(
            "expected AbiVersionMismatch with found=None, got {:?}",
            other.err()
        ),
    }
}

#[test]
fn rejects_wrong_abi_version() {
    let mgr = make_manager();
    let result = mgr.compile("bad_abi".into(), WAT_WRONG_ABI_VERSION.as_bytes(), 0);
    match result {
        Err(HookError::AbiVersionMismatch {
            hook_name,
            expected,
            found,
        }) => {
            assert_eq!(hook_name, "bad_abi");
            assert_eq!(expected, HOST_ABI_VERSION);
            assert_eq!(found, Some(9999));
        }
        other => panic!(
            "expected AbiVersionMismatch with found=Some(9999), got {:?}",
            other.err()
        ),
    }
}

#[test]
fn accepts_correct_abi_version() {
    let mgr = make_manager();
    let result = mgr.compile("good_abi".into(), WAT_CONTINUE.as_bytes(), 0);
    assert!(
        result.is_ok(),
        "compile should succeed with correct ABI version"
    );
}

#[test]
fn host_emit_event_collects_provider_event() {
    let mgr = make_manager();
    let wat = r#"
            (module
                (import "env" "host_emit_event" (func $emit (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0x3000) "packet")
                (data (i32.const 0x3010) "\01\02\03")
                (func (export "__rns_abi_version") (result i32) (i32.const 2))
                (func (export "on_hook") (param i32) (result i32)
                    (drop (call $emit (i32.const 0x3000) (i32.const 6) (i32.const 0x3010) (i32.const 3)))
                    (i32.store (i32.const 0x2000) (i32.const 0))
                    (i32.store (i32.add (i32.const 0x2000) (i32.const 4)) (i32.const 0))
                    (i32.store (i32.add (i32.const 0x2000) (i32.const 8)) (i32.const 0))
                    (i32.const 0x2000)
                )
            )
        "#;
    let module = mgr.runtime.compile(&wat::parse_str(wat).unwrap()).unwrap();
    let mut prog = LoadedProgram::new("emit".into(), module, 0);
    let ctx = HookContext::Tick;

    let exec = mgr
        .execute_program_with_provider_events(&mut prog, &ctx, &NullEngine, 0.0, true, None)
        .unwrap();
    assert_eq!(exec.provider_events.len(), 1);
    assert_eq!(exec.provider_events[0].hook_name, "emit");
    assert_eq!(exec.provider_events[0].payload_type, "packet");
    assert_eq!(exec.provider_events[0].payload, vec![1, 2, 3]);
}

#[test]
fn host_emit_event_is_ignored_when_disabled() {
    let mgr = make_manager();
    let wat = r#"
            (module
                (import "env" "host_emit_event" (func $emit (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0x3000) "packet")
                (data (i32.const 0x3010) "\01\02\03")
                (func (export "__rns_abi_version") (result i32) (i32.const 2))
                (func (export "on_hook") (param i32) (result i32)
                    (drop (call $emit (i32.const 0x3000) (i32.const 6) (i32.const 0x3010) (i32.const 3)))
                    (i32.store (i32.const 0x2000) (i32.const 0))
                    (i32.store (i32.add (i32.const 0x2000) (i32.const 4)) (i32.const 0))
                    (i32.store (i32.add (i32.const 0x2000) (i32.const 8)) (i32.const 0))
                    (i32.const 0x2000)
                )
            )
        "#;
    let module = mgr.runtime.compile(&wat::parse_str(wat).unwrap()).unwrap();
    let mut prog = LoadedProgram::new("emit".into(), module, 0);
    let ctx = HookContext::Tick;

    let exec = mgr
        .execute_program_with_provider_events(&mut prog, &ctx, &NullEngine, 0.0, false, None)
        .unwrap();
    assert!(exec.provider_events.is_empty());
}

#[test]
fn run_chain_returns_continue_only_provider_events() {
    let manager = make_manager();
    let wasm = wat::parse_str(
        r#"(module
                (import "env" "host_emit_event" (func $emit (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 4096) "\00\00\00\00")
                (data (i32.const 8192) "packet")
                (data (i32.const 8208) "\01\02\03")
                (func (export "__rns_abi_version") (result i32) i32.const 2)
                (func (export "on_hook") (param i32) (result i32)
                    i32.const 8192
                    i32.const 6
                    i32.const 8208
                    i32.const 3
                    call $emit
                    drop
                    i32.const 4096
                )
            )"#,
    )
    .unwrap();

    let mut programs = vec![manager.compile("emit".into(), &wasm, 0).unwrap()];
    let pkt_ctx = crate::PacketContext {
        flags: 0,
        hops: 0,
        destination_hash: [0; 16],
        context: 0,
        packet_hash: [0; 32],
        interface_id: 1,
        data_offset: 0,
        data_len: 0,
    };
    let ctx = crate::HookContext::Packet {
        ctx: &pkt_ctx,
        raw: &[],
    };

    let exec = manager
        .run_chain_with_provider_events(&mut programs, &ctx, &NullEngine, 0.0, true)
        .expect("expected provider event result");
    assert!(exec.hook_result.is_none());
    assert!(exec.injected_actions.is_empty());
    assert_eq!(exec.provider_events.len(), 1);
    assert_eq!(exec.provider_events[0].payload_type, "packet");
    assert_eq!(exec.provider_events[0].payload, vec![1, 2, 3]);
}

/// Build a hook module whose `on_hook` runs `body` and then returns a
/// Modify verdict exposing `out_len` bytes at 0x3000 (or Continue when
/// `out_len` is 0).
fn hook_module(imports: &str, pages: u32, body: &str, out_len: u32) -> String {
    let verdict = if out_len == 0 { 0 } else { 2 };
    format!(
        r#"(module
                {imports}
                (memory (export "memory") {pages})
                (global $calls (mut i32) (i32.const 0))
                (func (export "__rns_abi_version") (result i32) (i32.const 2))
                (func (export "on_hook") (param i32) (result i32)
                    (local $i i32)
                    (global.set $calls (i32.add (global.get $calls) (i32.const 1)))
                    {body}
                    (i32.store (i32.const 0x2000) (i32.const {verdict}))
                    (i32.store (i32.const 0x2004) (i32.const 0x3000))
                    (i32.store (i32.const 0x2008) (i32.const {out_len}))
                    (i32.store (i32.const 0x200c) (i32.const 0))
                    (i32.store (i32.const 0x2010) (i32.const 0))
                    (i32.store (i32.const 0x2014) (i32.const 0))
                    (i32.store (i32.const 0x2018) (i32.const 0))
                    (i32.const 0x2000)))"#
    )
}

fn read_i32s(data: &[u8]) -> Vec<i32> {
    data.chunks_exact(4)
        .map(|c| i32::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

fn cached_store(prog: &LoadedProgram) -> &Store<StoreData> {
    match &prog.backend {
        ProgramBackend::Wasm(wasm) => &wasm.cached.as_ref().expect("cached store").0,
        _ => panic!("expected a wasm program"),
    }
}

struct AnsweringEngine;
impl EngineAccess for AnsweringEngine {
    fn has_path(&self, _: &[u8; 16]) -> bool {
        true
    }
    fn hops_to(&self, _: &[u8; 16]) -> Option<u8> {
        Some(2)
    }
    fn next_hop(&self, _: &[u8; 16]) -> Option<[u8; 16]> {
        Some([7; 16])
    }
    fn is_blackholed(&self, _: &[u8; 16]) -> bool {
        true
    }
    fn interface_name(&self, _: u64) -> Option<String> {
        Some("eth0".into())
    }
    fn interface_mode(&self, _: u64) -> Option<u8> {
        Some(1)
    }
    fn identity_hash(&self) -> Option<[u8; 16]> {
        Some([9; 16])
    }
    fn announce_rate(&self, _: u64) -> Option<i32> {
        Some(1)
    }
    fn link_state(&self, _: &[u8; 16]) -> Option<u8> {
        Some(2)
    }
}

const ALL_MEMORY_HOST_FNS: &str = r#"
        (import "env" "host_log" (func $log (param i32 i32)))
        (import "env" "host_has_path" (func $has_path (param i32) (result i32)))
        (import "env" "host_get_hops" (func $hops (param i32) (result i32)))
        (import "env" "host_get_next_hop" (func $next_hop (param i32 i32) (result i32)))
        (import "env" "host_is_blackholed" (func $blackholed (param i32) (result i32)))
        (import "env" "host_get_interface_name" (func $ifname (param i64 i32 i32) (result i32)))
        (import "env" "host_get_transport_identity" (func $identity (param i32) (result i32)))
        (import "env" "host_get_link_state" (func $link (param i32) (result i32)))
        (import "env" "host_inject_action" (func $inject (param i32 i32) (result i32)))
        (import "env" "host_emit_event" (func $emit (param i32 i32 i32 i32) (result i32)))
    "#;

#[test]
fn host_fns_reject_out_of_range_guest_pointers() {
    let mgr = make_manager();
    let body = r#"
            (call $log (i32.const -16) (i32.const 0x7fffffff))
            (call $log (i32.const 0x100) (i32.const -1))
            (i32.store (i32.const 0x3000) (call $has_path (i32.const -16)))
            (i32.store (i32.const 0x3004) (call $hops (i32.const -16)))
            (i32.store (i32.const 0x3008) (call $next_hop (i32.const 0x100) (i32.const -16)))
            (i32.store (i32.const 0x300c) (call $next_hop (i32.const -16) (i32.const 0x100)))
            (i32.store (i32.const 0x3010) (call $blackholed (i32.const -16)))
            (i32.store (i32.const 0x3014)
                (call $ifname (i64.const 1) (i32.const -16) (i32.const 0x7fffffff)))
            (i32.store (i32.const 0x3018) (call $identity (i32.const -16)))
            (i32.store (i32.const 0x301c) (call $link (i32.const -16)))
            (i32.store (i32.const 0x3020) (call $inject (i32.const -16) (i32.const 0x7fffffff)))
            (i32.store (i32.const 0x3024)
                (call $emit (i32.const -16) (i32.const 16) (i32.const 0) (i32.const 0)))
            (i32.store (i32.const 0x3028)
                (call $emit (i32.const 0) (i32.const 0) (i32.const -16) (i32.const 16)))
            (i32.store (i32.const 0x302c) (call $next_hop (i32.const 0x100) (i32.const 0x200)))
        "#;
    let wat = hook_module(ALL_MEMORY_HOST_FNS, 1, body, 48);
    let mut prog = mgr.compile("bounds".into(), wat.as_bytes(), 0).unwrap();
    let expected = vec![0, -1, 0, 0, 0, -1, 0, -1, -1, -1, -1, 1];

    for _ in 0..2 {
        let exec = mgr
            .execute_program_with_provider_events(
                &mut prog,
                &HookContext::Tick,
                &AnsweringEngine,
                0.0,
                true,
                None,
            )
            .expect("hook keeps running after out-of-range pointers");
        assert_eq!(read_i32s(&exec.modified_data.unwrap()), expected);
        assert!(exec.injected_actions.is_empty());
        assert!(exec.provider_events.is_empty());
    }
    assert_eq!(prog.consecutive_traps, 0);
}

#[test]
fn result_offset_near_end_of_address_space_is_rejected() {
    let mgr = make_manager();
    let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "__rns_abi_version") (result i32) (i32.const 2))
            (func (export "on_hook") (param i32) (result i32) (i32.const -4)))"#;
    let mut prog = mgr.compile("offset".into(), wat.as_bytes(), 0).unwrap();
    assert!(mgr
        .execute_program(&mut prog, &HookContext::Tick, &NullEngine, 0.0, None)
        .is_none());
    assert_eq!(prog.consecutive_traps, 1);

    let mut valid = mgr
        .compile("valid".into(), WAT_CONTINUE.as_bytes(), 0)
        .unwrap();
    assert!(mgr
        .execute_program(&mut valid, &HookContext::Tick, &NullEngine, 0.0, None)
        .is_some());
}

#[test]
fn host_panic_is_contained_and_program_recovers() {
    struct PanickingEngine;
    impl EngineAccess for PanickingEngine {
        fn has_path(&self, _: &[u8; 16]) -> bool {
            panic!("engine lookup failed")
        }
        fn hops_to(&self, _: &[u8; 16]) -> Option<u8> {
            None
        }
        fn next_hop(&self, _: &[u8; 16]) -> Option<[u8; 16]> {
            None
        }
        fn is_blackholed(&self, _: &[u8; 16]) -> bool {
            false
        }
        fn interface_name(&self, _: u64) -> Option<String> {
            None
        }
        fn interface_mode(&self, _: u64) -> Option<u8> {
            None
        }
        fn identity_hash(&self) -> Option<[u8; 16]> {
            None
        }
        fn announce_rate(&self, _: u64) -> Option<i32> {
            None
        }
        fn link_state(&self, _: &[u8; 16]) -> Option<u8> {
            None
        }
    }

    let mgr = make_manager();
    let mut prog = mgr
        .compile("pathcheck".into(), WAT_HOST_HAS_PATH.as_bytes(), 0)
        .unwrap();
    assert!(mgr
        .execute_program(&mut prog, &HookContext::Tick, &PanickingEngine, 0.0, None)
        .is_none());
    assert_eq!(prog.consecutive_traps, 1);

    let exec = mgr
        .execute_program(&mut prog, &HookContext::Tick, &AnsweringEngine, 0.0, None)
        .expect("program runs again after a contained host panic");
    assert!(exec.hook_result.unwrap().is_drop());
    assert_eq!(prog.consecutive_traps, 0);
}

#[test]
fn memory_grow_past_limit_traps_and_host_continues() {
    let mgr = make_manager();
    let body = r#"
            (if (i32.eq (global.get $calls) (i32.const 1))
                (then (drop (memory.grow (i32.const 8192)))))
            (i32.store (i32.const 0x3000) (memory.size))
        "#;
    let wat = hook_module("", 1, body, 4);
    let mut prog = mgr.compile("grow".into(), wat.as_bytes(), 0).unwrap();
    assert!(mgr
        .execute_program(&mut prog, &HookContext::Tick, &NullEngine, 0.0, None)
        .is_none());
    assert_eq!(prog.consecutive_traps, 1);

    let exec = mgr
        .execute_program(&mut prog, &HookContext::Tick, &NullEngine, 0.0, None)
        .expect("program runs after a refused grow");
    assert_eq!(read_i32s(&exec.modified_data.unwrap()), vec![1]);
}

#[test]
fn memory_grow_within_limit_succeeds() {
    let mgr = make_manager();
    let body = r#"
            (i32.store (i32.const 0x3000) (memory.grow (i32.const 100)))
            (i32.store (i32.const 0x3004) (memory.size))
        "#;
    let wat = hook_module("", 1, body, 8);
    let mut prog = mgr.compile("grow".into(), wat.as_bytes(), 0).unwrap();
    let exec = mgr
        .execute_program(&mut prog, &HookContext::Tick, &NullEngine, 0.0, None)
        .unwrap();
    assert_eq!(read_i32s(&exec.modified_data.unwrap()), vec![1, 101]);
}

#[test]
fn rejects_memory64_modules() {
    let mgr = make_manager();
    let wat = r#"(module
            (memory (export "memory") i64 1)
            (func (export "__rns_abi_version") (result i32) (i32.const 2)))"#;
    let err = mgr
        .compile("m64".into(), wat.as_bytes(), 0)
        .err()
        .expect("memory64 module is rejected");
    assert!(err.to_string().contains("memory64"), "{}", err);
}

#[test]
fn rejects_declared_minimum_memory_above_limit() {
    let mgr = make_manager();
    let exported = r#"(module
            (memory (export "memory") 1024)
            (func (export "__rns_abi_version") (result i32) (i32.const 2)))"#;
    let err = mgr
        .compile("big".into(), exported.as_bytes(), 0)
        .err()
        .expect("module above the memory limit is rejected");
    assert!(err.to_string().contains("minimum memory"), "{}", err);

    let internal = r#"(module
            (memory 1024)
            (func (export "__rns_abi_version") (result i32) (i32.const 2)))"#;
    assert!(mgr.compile("big".into(), internal.as_bytes(), 0).is_err());
}

#[test]
fn module_at_memory_limit_runs() {
    let mgr = make_manager();
    let pages = (crate::runtime::DEFAULT_MAX_MEMORY / 65536) as u32;
    let body = r#"(i32.store (i32.const 0x3000) (memory.size))"#;
    let wat = hook_module("", pages, body, 4);
    let mut prog = mgr.compile("full".into(), wat.as_bytes(), 0).unwrap();
    let exec = mgr
        .execute_program(&mut prog, &HookContext::Tick, &NullEngine, 0.0, None)
        .unwrap();
    assert_eq!(read_i32s(&exec.modified_data.unwrap()), vec![pages as i32]);
}

#[test]
fn host_log_forwards_at_most_the_per_call_cap() {
    let mgr = make_manager();
    let imports = r#"(import "env" "host_log" (func $log (param i32 i32)))"#;
    let body = r#"
            (local.set $i (i32.const 0))
            (block $done (loop $next
                (br_if $done (i32.ge_u (local.get $i) (i32.const 100)))
                (call $log (i32.const 0x4000) (i32.const 4096))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $next)))
        "#;
    let wat = hook_module(imports, 1, body, 0);
    let mut prog = mgr.compile("log".into(), wat.as_bytes(), 0).unwrap();
    for _ in 0..2 {
        mgr.execute_program(&mut prog, &HookContext::Tick, &NullEngine, 0.0, None)
            .unwrap();
        let data = cached_store(&prog).data();
        assert_eq!(
            data.log_messages_forwarded,
            crate::runtime::MAX_LOG_MESSAGES_PER_CALL
        );
        assert_eq!(
            data.log_messages_dropped,
            100 - crate::runtime::MAX_LOG_MESSAGES_PER_CALL
        );
    }
}

/// Write a SendOnInterface action at 0x3100 whose payload is
/// `payload_len` bytes at 0x10000, then inject it `count` times. Stores
/// the number of accepted calls at 0x3000 and the last return code at 0x3004.
fn inject_repeatedly(count: u32, payload_len: u32) -> String {
    let imports =
        r#"(import "env" "host_inject_action" (func $inject (param i32 i32) (result i32)))"#;
    let body = format!(
        r#"
            (i32.store8 (i32.const 0x3100) (i32.const 0))
            (i64.store (i32.const 0x3101) (i64.const 1))
            (i32.store (i32.const 0x3109) (i32.const 0x10000))
            (i32.store (i32.const 0x310d) (i32.const {payload_len}))
            (i32.store (i32.const 0x3000) (i32.const 0))
            (local.set $i (i32.const 0))
            (block $done (loop $next
                (br_if $done (i32.ge_u (local.get $i) (i32.const {count})))
                (i32.store (i32.const 0x3004) (call $inject (i32.const 0x3100) (i32.const 17)))
                (if (i32.eqz (i32.load (i32.const 0x3004)))
                    (then (i32.store (i32.const 0x3000)
                        (i32.add (i32.load (i32.const 0x3000)) (i32.const 1)))))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $next)))
            "#
    );
    hook_module(imports, 3, &body, 8)
}

#[test]
fn host_inject_action_refuses_actions_beyond_count_cap() {
    let mgr = make_manager();
    let cap = crate::runtime::MAX_INJECTED_ACTIONS_PER_CALL;
    let wat = inject_repeatedly(cap as u32 + 6, 4);
    let mut prog = mgr.compile("inject".into(), wat.as_bytes(), 0).unwrap();
    let exec = mgr
        .execute_program(&mut prog, &HookContext::Tick, &NullEngine, 0.0, None)
        .unwrap();
    assert_eq!(
        read_i32s(&exec.modified_data.unwrap()),
        vec![cap as i32, host_fns::LIMIT_REACHED]
    );
    assert_eq!(exec.injected_actions.len(), cap);
}

#[test]
fn host_inject_action_refuses_actions_beyond_byte_cap() {
    let mgr = make_manager();
    let wat = inject_repeatedly(5, 65536);
    let mut prog = mgr.compile("inject".into(), wat.as_bytes(), 0).unwrap();
    let exec = mgr
        .execute_program(&mut prog, &HookContext::Tick, &NullEngine, 0.0, None)
        .unwrap();
    // Each action carries 17 + 65536 bytes; three fit in 256 KiB.
    assert_eq!(
        read_i32s(&exec.modified_data.unwrap()),
        vec![3, host_fns::LIMIT_REACHED]
    );
    assert_eq!(exec.injected_actions.len(), 3);
    for action in &exec.injected_actions {
        match action {
            crate::wire::ActionWire::SendOnInterface { raw, .. } => {
                assert_eq!(raw.len(), 65536)
            }
            other => panic!("expected SendOnInterface, got {:?}", other),
        }
    }
}

#[test]
fn host_emit_event_refuses_events_beyond_count_cap() {
    let mgr = make_manager();
    let cap = crate::runtime::MAX_PROVIDER_EVENTS_PER_CALL;
    let imports =
        r#"(import "env" "host_emit_event" (func $emit (param i32 i32 i32 i32) (result i32)))"#;
    let body = format!(
        r#"
            (i32.store (i32.const 0x3000) (i32.const 0))
            (local.set $i (i32.const 0))
            (block $done (loop $next
                (br_if $done (i32.ge_u (local.get $i) (i32.const {count})))
                (i32.store (i32.const 0x3004)
                    (call $emit (i32.const 0x3100) (i32.const 4) (i32.const 0x3200) (i32.const 8)))
                (if (i32.eqz (i32.load (i32.const 0x3004)))
                    (then (i32.store (i32.const 0x3000)
                        (i32.add (i32.load (i32.const 0x3000)) (i32.const 1)))))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $next)))
            "#,
        count = cap + 10
    );
    let wat = hook_module(imports, 1, &body, 8);
    let mut prog = mgr.compile("emit".into(), wat.as_bytes(), 0).unwrap();
    let exec = mgr
        .execute_program_with_provider_events(
            &mut prog,
            &HookContext::Tick,
            &NullEngine,
            0.0,
            true,
            None,
        )
        .unwrap();
    assert_eq!(
        read_i32s(&exec.modified_data.unwrap()),
        vec![cap as i32, host_fns::LIMIT_REACHED]
    );
    assert_eq!(exec.provider_events.len(), cap);
}

#[test]
fn host_copies_consume_fuel_per_byte() {
    let mgr = make_manager();
    let imports =
        r#"(import "env" "host_emit_event" (func $emit (param i32 i32 i32 i32) (result i32)))"#;
    let fuel_used = |payload_len: u32| {
        let body = format!(
            r#"(drop (call $emit (i32.const 0x100) (i32.const 4)
                    (i32.const 0x4000) (i32.const {payload_len})))"#
        );
        let wat = hook_module(imports, 2, &body, 0);
        let mut prog = mgr.compile("fuel".into(), wat.as_bytes(), 0).unwrap();
        let exec = mgr
            .execute_program_with_provider_events(
                &mut prog,
                &HookContext::Tick,
                &NullEngine,
                0.0,
                true,
                None,
            )
            .unwrap();
        assert_eq!(exec.provider_events[0].payload.len(), payload_len as usize);
        mgr.runtime.fuel() - cached_store(&prog).get_fuel().unwrap()
    };
    let small = fuel_used(0);
    let large = fuel_used(100_000);
    assert!(
        large - small >= 100_000,
        "fuel used: {} without payload, {} with 100000 bytes",
        small,
        large
    );
}
