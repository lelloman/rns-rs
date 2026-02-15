use crate::arena;
use crate::engine_access::EngineAccess;
use crate::error::HookError;
use crate::hooks::HookContext;
use crate::host_fns;
use crate::program::LoadedProgram;
use crate::result::{HookResult, Verdict};
use crate::runtime::{StoreData, WasmRuntime};
use wasmtime::{Linker, Store};

/// Central manager for WASM hook execution.
///
/// Owns the wasmtime runtime and pre-configured linker. Programs are stored
/// in `HookSlot`s (one per hook point); the manager provides execution.
pub struct HookManager {
    runtime: WasmRuntime,
    linker: Linker<StoreData>,
}

impl HookManager {
    pub fn new() -> Result<Self, HookError> {
        let runtime = WasmRuntime::new().map_err(|e| HookError::CompileError(e.to_string()))?;
        let mut linker = Linker::new(runtime.engine());
        host_fns::register_host_functions(&mut linker)
            .map_err(|e| HookError::CompileError(e.to_string()))?;
        Ok(HookManager { runtime, linker })
    }

    /// Compile WASM bytes into a LoadedProgram.
    pub fn compile(
        &self,
        name: String,
        bytes: &[u8],
        priority: i32,
    ) -> Result<LoadedProgram, HookError> {
        let module = self
            .runtime
            .compile(bytes)
            .map_err(|e| HookError::CompileError(e.to_string()))?;
        Ok(LoadedProgram::new(name, module, priority))
    }

    /// Compile a WASM file from disk.
    pub fn load_file(
        &self,
        name: String,
        path: &std::path::Path,
        priority: i32,
    ) -> Result<LoadedProgram, HookError> {
        let bytes = std::fs::read(path)?;
        self.compile(name, &bytes, priority)
    }

    /// Execute a single program against a hook context. Returns the HookResult
    /// on success (including Continue), or None on trap/fuel exhaustion (fail-open).
    pub fn execute_program(
        &self,
        program: &mut LoadedProgram,
        ctx: &HookContext,
        engine_access: &dyn EngineAccess,
        now: f64,
    ) -> Option<HookResult> {
        if !program.enabled {
            return None;
        }

        let store_data = StoreData {
            // Safety: transmute erases the lifetime on the fat pointer. The pointer
            // is only dereferenced during this function call, while the borrow is valid.
            engine_access: unsafe {
                std::mem::transmute(engine_access as *const dyn EngineAccess)
            },
            now,
            injected_actions: Vec::new(),
            log_messages: Vec::new(),
        };

        let mut store = Store::new(self.runtime.engine(), store_data);
        if let Err(e) = store.set_fuel(self.runtime.fuel()) {
            log::warn!("failed to set fuel for hook '{}': {}", program.name, e);
            return None;
        }

        let instance = match self.linker.instantiate(&mut store, &program.module) {
            Ok(inst) => inst,
            Err(e) => {
                log::warn!("failed to instantiate hook '{}': {}", program.name, e);
                program.record_trap();
                return None;
            }
        };

        // Write context into guest memory
        let memory = match instance.get_memory(&mut store, "memory") {
            Some(mem) => mem,
            None => {
                log::warn!("hook '{}' has no exported memory", program.name);
                program.record_trap();
                return None;
            }
        };

        if let Err(e) = arena::write_context(&memory, &mut store, ctx) {
            log::warn!("failed to write context for hook '{}': {}", program.name, e);
            program.record_trap();
            return None;
        }

        // Call the exported hook function
        let func = match instance.get_typed_func::<i32, i32>(&mut store, &program.export_name) {
            Ok(f) => f,
            Err(e) => {
                log::warn!(
                    "hook '{}' missing export '{}': {}",
                    program.name,
                    program.export_name,
                    e
                );
                program.record_trap();
                return None;
            }
        };

        let result_offset = match func.call(&mut store, arena::ARENA_BASE as i32) {
            Ok(offset) => offset,
            Err(e) => {
                // Fail-open: trap or fuel exhaustion → continue
                let auto_disabled = program.record_trap();
                if auto_disabled {
                    log::error!(
                        "hook '{}' auto-disabled after {} consecutive traps",
                        program.name,
                        program.consecutive_traps
                    );
                } else {
                    log::warn!("hook '{}' trapped: {}", program.name, e);
                }
                return None;
            }
        };

        // Read result from guest memory
        match arena::read_result(&memory, &store, result_offset as usize) {
            Ok(result) => {
                program.record_success();
                Some(result)
            }
            Err(e) => {
                log::warn!("hook '{}' returned invalid result: {}", program.name, e);
                program.record_trap();
                None
            }
        }
    }

    /// Run a chain of programs. Stops on Drop or Halt, continues on Continue or Modify.
    /// Returns the last meaningful result (Drop/Halt/Modify), or None if all continued.
    pub fn run_chain(
        &self,
        programs: &mut [LoadedProgram],
        ctx: &HookContext,
        engine_access: &dyn EngineAccess,
        now: f64,
    ) -> Option<HookResult> {
        let mut last_result: Option<HookResult> = None;
        for program in programs.iter_mut() {
            if !program.enabled {
                continue;
            }
            if let Some(result) = self.execute_program(program, ctx, engine_access, now) {
                let verdict = Verdict::from_u32(result.verdict);
                match verdict {
                    Some(Verdict::Drop) | Some(Verdict::Halt) => return Some(result),
                    Some(Verdict::Modify) => last_result = Some(result),
                    _ => {} // Continue → keep going
                }
            }
        }
        last_result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_access::NullEngine;

    fn make_manager() -> HookManager {
        HookManager::new().expect("failed to create HookManager")
    }

    /// WAT module that returns Continue (verdict=0).
    const WAT_CONTINUE: &str = r#"
        (module
            (memory (export "memory") 1)
            (func (export "on_hook") (param i32) (result i32)
                ;; Write HookResult at offset 0x2000
                ;; verdict = 0 (Continue)
                (i32.store (i32.const 0x2000) (i32.const 0))
                ;; modified_data_offset = 0
                (i32.store (i32.add (i32.const 0x2000) (i32.const 4)) (i32.const 0))
                ;; modified_data_len = 0
                (i32.store (i32.add (i32.const 0x2000) (i32.const 8)) (i32.const 0))
                ;; inject_actions_offset = 0
                (i32.store (i32.add (i32.const 0x2000) (i32.const 12)) (i32.const 0))
                ;; inject_actions_count = 0
                (i32.store (i32.add (i32.const 0x2000) (i32.const 16)) (i32.const 0))
                ;; log_offset = 0
                (i32.store (i32.add (i32.const 0x2000) (i32.const 20)) (i32.const 0))
                ;; log_len = 0
                (i32.store (i32.add (i32.const 0x2000) (i32.const 24)) (i32.const 0))
                (i32.const 0x2000)
            )
        )
    "#;

    /// WAT module that returns Drop (verdict=1).
    const WAT_DROP: &str = r#"
        (module
            (memory (export "memory") 1)
            (func (export "on_hook") (param i32) (result i32)
                (i32.store (i32.const 0x2000) (i32.const 1))
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

    /// WAT module that traps immediately.
    const WAT_TRAP: &str = r#"
        (module
            (memory (export "memory") 1)
            (func (export "on_hook") (param i32) (result i32)
                unreachable
            )
        )
    "#;

    /// WAT module with infinite loop (will exhaust fuel).
    const WAT_INFINITE: &str = r#"
        (module
            (memory (export "memory") 1)
            (func (export "on_hook") (param i32) (result i32)
                (loop $inf (br $inf))
                (i32.const 0)
            )
        )
    "#;

    /// WAT module that calls host_has_path and drops if path exists.
    const WAT_HOST_HAS_PATH: &str = r#"
        (module
            (import "env" "host_has_path" (func $has_path (param i32) (result i32)))
            (memory (export "memory") 1)
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
                (i32.store (i32.add (i32.const 0x2000) (i32.const 12)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 16)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 20)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 24)) (i32.const 0))
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
        let result = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0);
        // Continue → Some with verdict=0
        let r = result.unwrap();
        assert_eq!(r.verdict, Verdict::Continue as u32);
    }

    #[test]
    fn drop_hook() {
        let mgr = make_manager();
        let mut prog = mgr.compile("dropper".into(), WAT_DROP.as_bytes(), 0).unwrap();
        let ctx = HookContext::Tick;
        let result = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0);
        let r = result.unwrap();
        assert!(r.is_drop());
    }

    #[test]
    fn trap_failopen() {
        let mgr = make_manager();
        let mut prog = mgr.compile("trap".into(), WAT_TRAP.as_bytes(), 0).unwrap();
        let ctx = HookContext::Tick;
        let result = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0);
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
            let _ = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0);
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
        let result = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0);
        // Should fail-open (fuel exhausted = trap)
        assert!(result.is_none());
        assert_eq!(prog.consecutive_traps, 1);
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
        programs.sort_by(|a, b| b.priority.cmp(&a.priority));

        let ctx = HookContext::Tick;
        let result = mgr.run_chain(&mut programs, &ctx, &NullEngine, 0.0);
        // High priority drops → chain stops
        let r = result.unwrap();
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
        let p2 = mgr
            .compile("beta".into(), WAT_DROP.as_bytes(), 20)
            .unwrap();

        slot.attach(p1);
        assert_eq!(slot.programs.len(), 1);
        assert!(slot.runner as *const () as usize != crate::hooks::hook_noop as *const () as usize);

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
        assert_eq!(slot.runner as *const () as usize, crate::hooks::hook_noop as *const () as usize);
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
        }

        let mgr = make_manager();
        let mut prog = mgr
            .compile("pathcheck".into(), WAT_HOST_HAS_PATH.as_bytes(), 0)
            .unwrap();
        let ctx = HookContext::Tick;
        let result = mgr.execute_program(&mut prog, &ctx, &MockEngine, 0.0);
        // MockEngine.has_path returns true → WASM drops
        let r = result.unwrap();
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
        let result = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0);
        let r = result.unwrap();
        assert_eq!(r.verdict, Verdict::Continue as u32);
    }
}
