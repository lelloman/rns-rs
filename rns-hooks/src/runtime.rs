use crate::engine_access::EngineAccess;
use crate::wire::ActionWire;

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
pub struct StoreData {
    pub engine_access: *const dyn EngineAccess,
    pub now: f64,
    pub injected_actions: Vec<ActionWire>,
    pub log_messages: Vec<String>,
}

// Safety: StoreData is only used within a single-threaded driver loop.
// The `engine_access` raw pointer is refreshed each call and only dereferenced
// during that call while the borrow is live.
unsafe impl Send for StoreData {}
unsafe impl Sync for StoreData {}

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
    ) {
        self.engine_access = engine_access;
        self.now = now;
        self.injected_actions.clear();
        self.log_messages.clear();
    }
}

/// Wrapper around `wasmtime::Engine` with fuel-metering enabled.
pub struct WasmRuntime {
    engine: wasmtime::Engine,
    fuel: u64,
}

impl WasmRuntime {
    pub fn new() -> Result<Self, wasmtime::Error> {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
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
