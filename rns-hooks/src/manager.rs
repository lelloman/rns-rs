use crate::arena;
use crate::engine_access::{EngineAccess, NullEngine};
use crate::error::HookError;
use crate::hooks::HookContext;
use crate::host_fns;
use crate::program::LoadedProgram;
use crate::result::{ExecuteResult, HookResult, Verdict};
use crate::runtime::{StoreData, WasmRuntime};
use wasmtime::{Linker, Store};

/// ABI version the host expects from compiled hook modules.
const HOST_ABI_VERSION: i32 = rns_hooks_abi::ABI_VERSION;

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
    ///
    /// Validates that the module exports `__rns_abi_version` returning the
    /// expected ABI version before accepting it.
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
        self.validate_abi_version(&name, &module)?;
        Ok(LoadedProgram::new(name, module, priority))
    }

    /// Check that the module exports `__rns_abi_version() -> i32` and that
    /// the returned value matches [`HOST_ABI_VERSION`].
    fn validate_abi_version(
        &self,
        name: &str,
        module: &wasmtime::Module,
    ) -> Result<(), HookError> {
        // Check if the export exists in the module's type information.
        let has_export = module
            .exports()
            .any(|e| e.name() == "__rns_abi_version");
        if !has_export {
            return Err(HookError::AbiVersionMismatch {
                hook_name: name.to_string(),
                expected: HOST_ABI_VERSION,
                found: None,
            });
        }

        // Instantiate the module to call the function and read the version.
        static NULL_ENGINE: NullEngine = NullEngine;
        let mut store = Store::new(self.runtime.engine(), StoreData {
            engine_access: &NULL_ENGINE as *const dyn EngineAccess,
            now: 0.0,
            injected_actions: Vec::new(),
            log_messages: Vec::new(),
        });
        store
            .set_fuel(self.runtime.fuel())
            .map_err(|e| HookError::CompileError(e.to_string()))?;

        let instance = self
            .linker
            .instantiate(&mut store, module)
            .map_err(|e| HookError::InstantiationError(e.to_string()))?;

        let func = instance
            .get_typed_func::<(), i32>(&mut store, "__rns_abi_version")
            .map_err(|e| HookError::CompileError(format!(
                "__rns_abi_version has wrong signature: {}", e
            )))?;

        let version = func
            .call(&mut store, ())
            .map_err(|e| HookError::Trap(format!(
                "__rns_abi_version trapped: {}", e
            )))?;

        if version != HOST_ABI_VERSION {
            return Err(HookError::AbiVersionMismatch {
                hook_name: name.to_string(),
                expected: HOST_ABI_VERSION,
                found: Some(version),
            });
        }

        Ok(())
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

    /// Execute a single program against a hook context. Returns an `ExecuteResult`
    /// containing the hook result, any injected actions, and modified data (all
    /// extracted from WASM memory before the store is dropped). Returns `None`
    /// on trap/fuel exhaustion (fail-open).
    ///
    /// If `data_override` is provided (from a previous Modify verdict in a chain),
    /// it replaces the packet data region in the arena after writing the context.
    ///
    /// The store and instance are cached in the program for cross-call state
    /// persistence (WASM linear memory survives across invocations). On each call
    /// we reset fuel and per-call StoreData fields but keep the WASM globals and
    /// memory intact.
    pub fn execute_program(
        &self,
        program: &mut LoadedProgram,
        ctx: &HookContext,
        engine_access: &dyn EngineAccess,
        now: f64,
        data_override: Option<&[u8]>,
    ) -> Option<ExecuteResult> {
        if !program.enabled {
            return None;
        }

        // Safety: transmute erases the lifetime on the fat pointer. The pointer
        // is only dereferenced during this function call, while the borrow is valid.
        let engine_access_ptr: *const dyn EngineAccess = unsafe {
            std::mem::transmute(engine_access as *const dyn EngineAccess)
        };

        // Take the cached store+instance out of program (or create fresh).
        // We take ownership to avoid borrow-checker conflicts with program.record_*().
        let (mut store, instance) = if let Some(cached) = program.cached.take() {
            let (mut s, i) = cached;
            // Reset per-call state: fuel, engine_access, injected_actions, log_messages
            s.data_mut().reset_per_call(engine_access_ptr, now);
            if let Err(e) = s.set_fuel(self.runtime.fuel()) {
                log::warn!("failed to set fuel for hook '{}': {}", program.name, e);
                program.cached = Some((s, i));
                return None;
            }
            (s, i)
        } else {
            let store_data = StoreData {
                engine_access: engine_access_ptr,
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

            (store, instance)
        };

        // Write context into guest memory
        let memory = match instance.get_memory(&mut store, "memory") {
            Some(mem) => mem,
            None => {
                log::warn!("hook '{}' has no exported memory", program.name);
                program.record_trap();
                program.cached = Some((store, instance));
                return None;
            }
        };

        if let Err(e) = arena::write_context(&memory, &mut store, ctx) {
            log::warn!("failed to write context for hook '{}': {}", program.name, e);
            program.record_trap();
            program.cached = Some((store, instance));
            return None;
        }

        // If a previous hook in the chain returned Modify, override the packet data
        if let Some(override_data) = data_override {
            if let Err(e) = arena::write_data_override(&memory, &mut store, override_data) {
                log::warn!(
                    "failed to write data override for hook '{}': {}",
                    program.name,
                    e
                );
                // Non-fatal: continue with original data
            }
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
                program.cached = Some((store, instance));
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
                program.cached = Some((store, instance));
                return None;
            }
        };

        // Read result from guest memory
        let ret = match arena::read_result(&memory, &store, result_offset as usize) {
            Ok(result) => {
                program.record_success();

                // Extract modified data from WASM memory
                let modified_data = if Verdict::from_u32(result.verdict) == Some(Verdict::Modify) {
                    arena::read_modified_data(&memory, &store, &result)
                } else {
                    None
                };

                // Extract injected actions from the store
                let injected_actions = std::mem::take(&mut store.data_mut().injected_actions);

                Some(ExecuteResult {
                    hook_result: Some(result),
                    injected_actions,
                    modified_data,
                })
            }
            Err(e) => {
                log::warn!("hook '{}' returned invalid result: {}", program.name, e);
                program.record_trap();
                None
            }
        };

        // Put the store+instance back for next call
        program.cached = Some((store, instance));
        ret
    }

    /// Run a chain of programs. Stops on Drop or Halt, continues on Continue or Modify.
    /// Returns an `ExecuteResult` accumulating all injected actions across the chain
    /// and the last meaningful hook result (Drop/Halt/Modify), or None if all continued.
    ///
    /// When a hook returns Modify with modified data, subsequent hooks in the chain
    /// receive the modified data (only applicable to Packet contexts).
    pub fn run_chain(
        &self,
        programs: &mut [LoadedProgram],
        ctx: &HookContext,
        engine_access: &dyn EngineAccess,
        now: f64,
    ) -> Option<ExecuteResult> {
        let mut accumulated_actions = Vec::new();
        let mut last_result: Option<HookResult> = None;
        let mut last_modified_data: Option<Vec<u8>> = None;
        let is_packet_ctx = matches!(ctx, HookContext::Packet(_));

        for program in programs.iter_mut() {
            if !program.enabled {
                continue;
            }
            let override_ref = if is_packet_ctx {
                last_modified_data.as_deref()
            } else {
                None
            };
            if let Some(exec_result) =
                self.execute_program(program, ctx, engine_access, now, override_ref)
            {
                accumulated_actions.extend(exec_result.injected_actions);

                if let Some(ref result) = exec_result.hook_result {
                    let verdict = Verdict::from_u32(result.verdict);
                    match verdict {
                        Some(Verdict::Drop) | Some(Verdict::Halt) => {
                            return Some(ExecuteResult {
                                hook_result: exec_result.hook_result,
                                injected_actions: accumulated_actions,
                                modified_data: exec_result.modified_data.or(last_modified_data),
                            });
                        }
                        Some(Verdict::Modify) => {
                            last_result = exec_result.hook_result;
                            if is_packet_ctx {
                                if let Some(data) = exec_result.modified_data {
                                    last_modified_data = Some(data);
                                }
                            }
                        }
                        _ => {} // Continue → keep going
                    }
                }
            }
        }

        if last_result.is_some() || !accumulated_actions.is_empty() {
            Some(ExecuteResult {
                hook_result: last_result,
                injected_actions: accumulated_actions,
                modified_data: last_modified_data,
            })
        } else {
            None
        }
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
            (func (export "__rns_abi_version") (result i32) (i32.const 1))
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
            (func (export "__rns_abi_version") (result i32) (i32.const 1))
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
            (func (export "__rns_abi_version") (result i32) (i32.const 1))
            (func (export "on_hook") (param i32) (result i32)
                unreachable
            )
        )
    "#;

    /// WAT module with infinite loop (will exhaust fuel).
    const WAT_INFINITE: &str = r#"
        (module
            (memory (export "memory") 1)
            (func (export "__rns_abi_version") (result i32) (i32.const 1))
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
            (func (export "__rns_abi_version") (result i32) (i32.const 1))
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
        let result = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0, None);
        // Continue → Some with verdict=0
        let exec = result.unwrap();
        let r = exec.hook_result.unwrap();
        assert_eq!(r.verdict, Verdict::Continue as u32);
    }

    #[test]
    fn drop_hook() {
        let mgr = make_manager();
        let mut prog = mgr.compile("dropper".into(), WAT_DROP.as_bytes(), 0).unwrap();
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
        fn has_path(&self, _: &[u8; 16]) -> bool { false }
        fn hops_to(&self, _: &[u8; 16]) -> Option<u8> { None }
        fn next_hop(&self, _: &[u8; 16]) -> Option<[u8; 16]> { None }
        fn is_blackholed(&self, _: &[u8; 16]) -> bool { false }
        fn interface_name(&self, _: u64) -> Option<String> { None }
        fn interface_mode(&self, _: u64) -> Option<u8> { None }
        fn identity_hash(&self) -> Option<[u8; 16]> { None }
        fn announce_rate(&self, _: u64) -> Option<i32> { self.announce_rate_val }
        fn link_state(&self, _: &[u8; 16]) -> Option<u8> { self.link_state_val }
    }

    /// WAT: calls host_get_announce_rate(42), if result >= 0 → Drop, else Continue.
    const WAT_ANNOUNCE_RATE: &str = r#"
        (module
            (import "env" "host_get_announce_rate" (func $get_rate (param i64) (result i32)))
            (memory (export "memory") 1)
            (func (export "__rns_abi_version") (result i32) (i32.const 1))
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
                (i32.store (i32.add (i32.const 0x2000) (i32.const 12)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 16)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 20)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 24)) (i32.const 0))
                (i32.const 0x2000)
            )
        )
    "#;

    #[test]
    fn host_get_announce_rate_found() {
        // announce_rate returns Some(1500) (1.5 Hz * 1000) → Drop
        let engine = MockEngineCustom { announce_rate_val: Some(1500), link_state_val: None };
        let mgr = make_manager();
        let mut prog = mgr.compile("rate".into(), WAT_ANNOUNCE_RATE.as_bytes(), 0).unwrap();
        let ctx = HookContext::Tick;
        let exec = mgr.execute_program(&mut prog, &ctx, &engine, 0.0, None).unwrap();
        assert!(exec.hook_result.unwrap().is_drop());
    }

    #[test]
    fn host_get_announce_rate_not_found() {
        // announce_rate returns None → -1 → Continue
        let engine = MockEngineCustom { announce_rate_val: None, link_state_val: None };
        let mgr = make_manager();
        let mut prog = mgr.compile("rate".into(), WAT_ANNOUNCE_RATE.as_bytes(), 0).unwrap();
        let ctx = HookContext::Tick;
        let exec = mgr.execute_program(&mut prog, &ctx, &engine, 0.0, None).unwrap();
        assert_eq!(exec.hook_result.unwrap().verdict, Verdict::Continue as u32);
    }

    /// WAT: calls host_get_link_state with 16-byte hash at 0x3000.
    /// If state == 2 (Active) → Drop, else Continue.
    const WAT_LINK_STATE: &str = r#"
        (module
            (import "env" "host_get_link_state" (func $link_state (param i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "__rns_abi_version") (result i32) (i32.const 1))
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
                (i32.store (i32.add (i32.const 0x2000) (i32.const 12)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 16)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 20)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 24)) (i32.const 0))
                (i32.const 0x2000)
            )
        )
    "#;

    #[test]
    fn host_get_link_state_active() {
        // link_state returns Some(2) (Active) → Drop
        let engine = MockEngineCustom { announce_rate_val: None, link_state_val: Some(2) };
        let mgr = make_manager();
        let mut prog = mgr.compile("linkst".into(), WAT_LINK_STATE.as_bytes(), 0).unwrap();
        let ctx = HookContext::Tick;
        let exec = mgr.execute_program(&mut prog, &ctx, &engine, 0.0, None).unwrap();
        assert!(exec.hook_result.unwrap().is_drop());
    }

    #[test]
    fn host_get_link_state_not_found() {
        // link_state returns None → -1, which != 2 → Continue
        let engine = MockEngineCustom { announce_rate_val: None, link_state_val: None };
        let mgr = make_manager();
        let mut prog = mgr.compile("linkst".into(), WAT_LINK_STATE.as_bytes(), 0).unwrap();
        let ctx = HookContext::Tick;
        let exec = mgr.execute_program(&mut prog, &ctx, &engine, 0.0, None).unwrap();
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
            (func (export "__rns_abi_version") (result i32) (i32.const 1))
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
                (i32.store (i32.add (i32.const 0x2000) (i32.const 12)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 16)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 20)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 24)) (i32.const 0))
                (i32.const 0x2000)
            )
        )
    "#;

    #[test]
    fn host_inject_action_send() {
        let mgr = make_manager();
        let mut prog = mgr.compile("inject".into(), WAT_INJECT_ACTION.as_bytes(), 0).unwrap();
        let ctx = HookContext::Tick;
        let exec = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0, None).unwrap();
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
            (func (export "__rns_abi_version") (result i32) (i32.const 1))
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
                (i32.store (i32.add (i32.const 0x2000) (i32.const 12)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 16)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 20)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 24)) (i32.const 0))
                (i32.const 0x2000)
            )
        )
    "#;

    #[test]
    fn modify_extracts_data() {
        let mgr = make_manager();
        let mut prog = mgr.compile("mod".into(), WAT_MODIFY.as_bytes(), 0).unwrap();
        let ctx = HookContext::Tick;
        let exec = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0, None).unwrap();
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
        let injector = mgr.compile("injector".into(), WAT_INJECT_ACTION.as_bytes(), 100).unwrap();
        let dropper = mgr.compile("dropper".into(), WAT_DROP.as_bytes(), 0).unwrap();
        let mut programs = vec![injector, dropper];
        programs.sort_by(|a, b| b.priority.cmp(&a.priority));

        let ctx = HookContext::Tick;
        let exec = mgr.run_chain(&mut programs, &ctx, &NullEngine, 0.0).unwrap();
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
            (func (export "__rns_abi_version") (result i32) (i32.const 1))
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
                (i32.store (i32.add (i32.const 0x2000) (i32.const 12)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 16)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 20)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 24)) (i32.const 0))
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
        let mut prog = mgr.compile("counter".into(), WAT_COUNTER.as_bytes(), 0).unwrap();
        let ctx = HookContext::Tick;

        // Call 3 times — counter should increment across calls
        let exec1 = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0, None).unwrap();
        assert_eq!(extract_counter(&exec1), 1);

        let exec2 = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0, None).unwrap();
        assert_eq!(extract_counter(&exec2), 2);

        let exec3 = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0, None).unwrap();
        assert_eq!(extract_counter(&exec3), 3);
    }

    #[test]
    fn instance_persistence_resets_on_drop_cache() {
        let mgr = make_manager();
        let mut prog = mgr.compile("counter".into(), WAT_COUNTER.as_bytes(), 0).unwrap();
        let ctx = HookContext::Tick;

        // Increment twice
        mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0, None).unwrap();
        let exec2 = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0, None).unwrap();
        assert_eq!(extract_counter(&exec2), 2);

        // Drop cache (simulates reload)
        prog.drop_cache();

        // Counter should restart at 1
        let exec3 = mgr.execute_program(&mut prog, &ctx, &NullEngine, 0.0, None).unwrap();
        assert_eq!(extract_counter(&exec3), 1);
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
                (i32.store (i32.add (i32.const 0x2000) (i32.const 12)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 16)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 20)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 24)) (i32.const 0))
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
                (i32.store (i32.add (i32.const 0x2000) (i32.const 12)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 16)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 20)) (i32.const 0))
                (i32.store (i32.add (i32.const 0x2000) (i32.const 24)) (i32.const 0))
                (i32.const 0x2000)
            )
        )
    "#;

    #[test]
    fn rejects_missing_abi_version() {
        let mgr = make_manager();
        let result = mgr.compile("no_abi".into(), WAT_NO_ABI_VERSION.as_bytes(), 0);
        match result {
            Err(HookError::AbiVersionMismatch { hook_name, expected, found }) => {
                assert_eq!(hook_name, "no_abi");
                assert_eq!(expected, HOST_ABI_VERSION);
                assert_eq!(found, None);
            }
            other => panic!("expected AbiVersionMismatch with found=None, got {:?}", other.err()),
        }
    }

    #[test]
    fn rejects_wrong_abi_version() {
        let mgr = make_manager();
        let result = mgr.compile("bad_abi".into(), WAT_WRONG_ABI_VERSION.as_bytes(), 0);
        match result {
            Err(HookError::AbiVersionMismatch { hook_name, expected, found }) => {
                assert_eq!(hook_name, "bad_abi");
                assert_eq!(expected, HOST_ABI_VERSION);
                assert_eq!(found, Some(9999));
            }
            other => panic!("expected AbiVersionMismatch with found=Some(9999), got {:?}", other.err()),
        }
    }

    #[test]
    fn accepts_correct_abi_version() {
        let mgr = make_manager();
        let result = mgr.compile("good_abi".into(), WAT_CONTINUE.as_bytes(), 0);
        assert!(result.is_ok(), "compile should succeed with correct ABI version");
    }
}
