use crate::engine_access::EngineAccess;
use crate::wire::ActionWire;

/// Default fuel budget per WASM invocation.
pub const DEFAULT_FUEL: u64 = 10_000_000;
/// Default maximum memory for WASM modules (16 MB).
pub const DEFAULT_MAX_MEMORY: usize = 16 * 1024 * 1024;

/// Data stored in each wasmtime `Store`.
///
/// Uses a raw pointer for `EngineAccess` because `Linker<T>` requires `T`
/// without lifetime parameters. The pointer is valid for the duration of
/// a single hook call within `Driver::run()`.
pub struct StoreData {
    pub engine_access: *const dyn EngineAccess,
    pub now: f64,
    pub injected_actions: Vec<ActionWire>,
    pub log_messages: Vec<String>,
}

// Safety: StoreData is only used within a single-threaded driver loop.
// The raw pointer is valid for the duration of the Store's lifetime.
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
