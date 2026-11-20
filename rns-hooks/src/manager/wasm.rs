#![allow(
    unsafe_code,
    reason = "hook runtime state shared with host functions by raw pointer"
)]

//! The WASM backend: ABI checks and running programs in Wasmtime.

use super::HookManager;
use crate::arena;
use crate::engine_access::{EngineAccess, NullEngine};
use crate::error::HookError;
use crate::hooks::HookContext;
use crate::program::{LoadedProgram, ProgramBackend};
use crate::result::{ExecuteResult, Verdict};
use crate::runtime::StoreData;
use wasmtime::Store;

/// ABI version the host expects from compiled hook modules.
pub(super) const HOST_ABI_VERSION: i32 = rns_hooks_abi::ABI_VERSION;

impl HookManager {
    /// Check that the module exports `__rns_abi_version() -> i32` and that
    /// the returned value matches [`HOST_ABI_VERSION`].
    pub(super) fn validate_abi_version(
        &self,
        name: &str,
        module: &wasmtime::Module,
    ) -> Result<(), HookError> {
        // Check if the export exists in the module's type information.
        let has_export = module.exports().any(|e| e.name() == "__rns_abi_version");
        if !has_export {
            return Err(HookError::AbiVersionMismatch {
                hook_name: name.to_string(),
                expected: HOST_ABI_VERSION,
                found: None,
            });
        }

        // Instantiate the module to call the function and read the version.
        static NULL_ENGINE: NullEngine = NullEngine;
        let mut store = self
            .runtime
            .new_store(StoreData::new(
                name.to_string(),
                &NULL_ENGINE as *const dyn EngineAccess,
                0.0,
                false,
                self.runtime.max_memory(),
            ))
            .map_err(|e| HookError::CompileError(e.to_string()))?;

        let instance = guard_guest_call(|| self.linker.instantiate(&mut store, module))
            .map_err(|e| HookError::InstantiationError(e.to_string()))?;

        let func = instance
            .get_typed_func::<(), i32>(&mut store, "__rns_abi_version")
            .map_err(|e| {
                HookError::CompileError(format!("__rns_abi_version has wrong signature: {}", e))
            })?;

        let version = guard_guest_call(|| func.call(&mut store, ()))
            .map_err(|e| HookError::Trap(format!("__rns_abi_version trapped: {}", e)))?;

        if version != HOST_ABI_VERSION {
            return Err(HookError::AbiVersionMismatch {
                hook_name: name.to_string(),
                expected: HOST_ABI_VERSION,
                found: Some(version),
            });
        }

        Ok(())
    }

    pub(super) fn execute_wasm_program(
        &self,
        program: &mut LoadedProgram,
        ctx: &HookContext,
        engine_access: &dyn EngineAccess,
        now: f64,
        provider_events_enabled: bool,
        data_override: Option<&[u8]>,
    ) -> Option<ExecuteResult> {
        // Safety: transmute erases the lifetime on the fat pointer. The pointer
        // is only dereferenced during this function call, while the borrow is valid.
        let engine_access_ptr: *const dyn EngineAccess =
            unsafe { std::mem::transmute(engine_access as *const dyn EngineAccess) };

        // Take the cached store+instance out of program (or create fresh).
        // We take ownership to avoid borrow-checker conflicts with program.record_*().
        let cached = match &mut program.backend {
            ProgramBackend::Builtin(_) => unreachable!(),
            ProgramBackend::Wasm(wasm) => wasm.cached.take(),
            #[cfg(feature = "native")]
            ProgramBackend::Native(_) => unreachable!(),
        };
        let (mut store, instance) = if let Some(cached) = cached {
            let (mut s, i) = cached;
            // Reset per-call state: fuel, engine_access, injected_actions, log_messages
            s.data_mut()
                .reset_per_call(engine_access_ptr, now, provider_events_enabled);
            if let Err(e) = s.set_fuel(self.runtime.fuel()) {
                log::warn!("failed to set fuel for hook '{}': {}", program.name, e);
                self.cache_wasm_instance(program, s, i);
                return None;
            }
            (s, i)
        } else {
            let store_data = StoreData::new(
                program.name.clone(),
                engine_access_ptr,
                now,
                provider_events_enabled,
                self.runtime.max_memory(),
            );

            let mut store = match self.runtime.new_store(store_data) {
                Ok(store) => store,
                Err(e) => {
                    log::warn!("failed to set fuel for hook '{}': {}", program.name, e);
                    return None;
                }
            };

            let module = match &program.backend {
                ProgramBackend::Builtin(_) => unreachable!(),
                ProgramBackend::Wasm(wasm) => wasm.module.clone(),
                #[cfg(feature = "native")]
                ProgramBackend::Native(_) => unreachable!(),
            };
            let instance = match guard_guest_call(|| self.linker.instantiate(&mut store, &module)) {
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
                self.cache_wasm_instance(program, store, instance);
                return None;
            }
        };

        if let Err(e) = arena::write_context(&memory, &mut store, ctx) {
            log::warn!("failed to write context for hook '{}': {}", program.name, e);
            program.record_trap();
            self.cache_wasm_instance(program, store, instance);
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
        let export_name = match &program.backend {
            ProgramBackend::Builtin(_) => unreachable!(),
            ProgramBackend::Wasm(wasm) => wasm.export_name.clone(),
            #[cfg(feature = "native")]
            ProgramBackend::Native(_) => unreachable!(),
        };
        let func = match instance.get_typed_func::<i32, i32>(&mut store, &export_name) {
            Ok(f) => f,
            Err(e) => {
                log::warn!(
                    "hook '{}' missing export '{}': {}",
                    program.name,
                    export_name,
                    e
                );
                program.record_trap();
                self.cache_wasm_instance(program, store, instance);
                return None;
            }
        };

        let call = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            func.call(&mut store, arena::ARENA_BASE as i32)
        }));
        let result_offset = match call {
            Ok(Ok(offset)) => offset,
            Err(panic) => {
                // A host function panicked while serving this program. The
                // store may hold partial state, so drop it instead of caching
                // it; the next call instantiates a fresh one.
                let auto_disabled = program.record_trap();
                log::warn!(
                    "hook '{}' aborted: host panic: {}",
                    program.name,
                    panic_message(&*panic)
                );
                if auto_disabled {
                    log::error!(
                        "hook '{}' auto-disabled after {} consecutive traps",
                        program.name,
                        program.consecutive_traps
                    );
                }
                return None;
            }
            Ok(Err(e)) => {
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
                self.cache_wasm_instance(program, store, instance);
                return None;
            }
        };

        // Read result from guest memory
        // Guest pointers are unsigned 32-bit offsets.
        let ret = match arena::read_result(&memory, &store, result_offset as u32 as usize) {
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
                let provider_events = std::mem::take(&mut store.data_mut().provider_events)
                    .into_iter()
                    .map(|event| crate::result::EmittedProviderEvent {
                        hook_name: program.name.clone(),
                        payload_type: event.payload_type,
                        payload: event.payload,
                    })
                    .collect();

                Some(ExecuteResult {
                    hook_result: Some(result),
                    injected_actions,
                    provider_events,
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
        self.cache_wasm_instance(program, store, instance);
        ret
    }

    pub(super) fn cache_wasm_instance(
        &self,
        program: &mut LoadedProgram,
        store: Store<StoreData>,
        instance: wasmtime::Instance,
    ) {
        match &mut program.backend {
            ProgramBackend::Builtin(_) => unreachable!(),
            ProgramBackend::Wasm(wasm) => wasm.cached = Some((store, instance)),
            #[cfg(feature = "native")]
            ProgramBackend::Native(_) => unreachable!(),
        }
    }
}

/// Run a call into guest code, converting a panic raised by a host function
/// into an error so a single program cannot unwind through the driver thread.
pub(super) fn guard_guest_call<T>(
    call: impl FnOnce() -> Result<T, wasmtime::Error>,
) -> Result<T, wasmtime::Error> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(call)) {
        Ok(result) => result,
        Err(panic) => Err(wasmtime::format_err!(
            "host panic: {}",
            panic_message(&*panic)
        )),
    }
}

fn panic_message(panic: &(dyn std::any::Any + Send)) -> &str {
    if let Some(msg) = panic.downcast_ref::<&str>() {
        msg
    } else if let Some(msg) = panic.downcast_ref::<String>() {
        msg
    } else {
        "unknown panic"
    }
}
