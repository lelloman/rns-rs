#[cfg(feature = "wasm")]
use crate::engine_access::EngineAccess;
#[cfg(feature = "wasm")]
use crate::wire::ActionWire;

#[derive(Debug, Clone)]
pub struct RawProviderEvent {
    pub payload_type: String,
    pub payload: Vec<u8>,
}

/// Default fuel budget per WASM invocation.
pub const DEFAULT_FUEL: u64 = 10_000_000;
/// Default maximum memory for WASM modules (16 MB).
pub const DEFAULT_MAX_MEMORY: usize = 16 * 1024 * 1024;

/// Data stored in each wasmtime `Store`.
///
/// Uses a raw pointer for `EngineAccess` because `Linker<T>` requires `T`
/// without lifetime parameters. The Store is cached across calls for instance
/// persistence, but `engine_access` is refreshed each call via `reset_per_call`
/// and must only be dereferenced during the active call.
#[cfg(feature = "wasm")]
pub struct StoreData {
    pub engine_access: *const dyn EngineAccess,
    pub now: f64,
    pub injected_actions: Vec<ActionWire>,
    pub log_messages: Vec<String>,
    pub provider_events: Vec<RawProviderEvent>,
    pub provider_events_enabled: bool,
}

// Safety: StoreData is only used within a single-threaded driver loop.
// The `engine_access` raw pointer is refreshed each call and only dereferenced
// during that call while the borrow is live.
#[cfg(feature = "wasm")]
unsafe impl Send for StoreData {}
#[cfg(feature = "wasm")]
unsafe impl Sync for StoreData {}

#[cfg(feature = "wasm")]
impl StoreData {
    /// Access the engine through the raw pointer.
    ///
    /// # Safety
    /// The caller must ensure the pointer is still valid.
    pub unsafe fn engine(&self) -> &dyn EngineAccess {
        &*self.engine_access
    }

    /// Reset per-call fields while preserving the store (and WASM linear memory).
    pub fn reset_per_call(
        &mut self,
        engine_access: *const dyn EngineAccess,
        now: f64,
        provider_events_enabled: bool,
    ) {
        self.engine_access = engine_access;
        self.now = now;
        self.injected_actions.clear();
        self.log_messages.clear();
        self.provider_events.clear();
        self.provider_events_enabled = provider_events_enabled;
    }
}

/// Wrapper around `wasmtime::Engine` with fuel-metering enabled.
#[cfg(feature = "wasm")]
pub struct WasmRuntime {
    engine: wasmtime::Engine,
    fuel: u64,
}

#[cfg(feature = "wasm")]
impl WasmRuntime {
    pub fn new() -> Result<Self, wasmtime::Error> {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        // Hooks use the stable core-module ABI only. Keep proposals which add
        // reference types and exception control flow outside the sandbox even
        // if a Wasmtime release enables them by default.
        config.wasm_gc(false);
        config.wasm_exceptions(false);
        let engine = wasmtime::Engine::new(&config)?;
        Ok(WasmRuntime {
            engine,
            fuel: DEFAULT_FUEL,
        })
    }

    pub fn compile(&self, bytes: &[u8]) -> Result<wasmtime::Module, wasmtime::Error> {
        wasmtime::Module::new(&self.engine, bytes)
    }

    pub fn engine(&self) -> &wasmtime::Engine {
        &self.engine
    }

    pub fn fuel(&self) -> u64 {
        self.fuel
    }
}

#[cfg(all(test, feature = "wasm"))]
mod tests {
    use super::WasmRuntime;

    #[test]
    fn compiles_core_hook_instruction_set() {
        let runtime = WasmRuntime::new().unwrap();
        runtime
            .compile(
                br#"(module
                    (memory 2)
                    (func (export "bulk")
                        i32.const 0
                        i32.const 90
                        i32.const 4096
                        memory.fill
                        i32.const 8192
                        i32.const 0
                        i32.const 4096
                        memory.copy))"#,
            )
            .unwrap();
    }

    #[test]
    fn rejects_webassembly_gc_modules() {
        let runtime = WasmRuntime::new().unwrap();
        let result = runtime.compile(
            br#"(module
                (type $record (struct (field i32)))
                (func (export "make") (result (ref null $record))
                    ref.null $record))"#,
        );

        assert!(result.is_err(), "the hook sandbox must not enable Wasm GC");
    }

    #[test]
    fn rejects_webassembly_exception_modules() {
        let runtime = WasmRuntime::new().unwrap();
        let result = runtime.compile(
            br#"(module
                (tag $failure)
                (func (export "raise")
                    throw $failure))"#,
        );

        assert!(
            result.is_err(),
            "the hook sandbox must not enable Wasm exception handling"
        );
    }
}
