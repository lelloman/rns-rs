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
/// Maximum number of tables a hook instance may define.
pub const MAX_TABLES: usize = 4;
/// Maximum number of elements across a hook instance's tables.
pub const MAX_TABLE_ELEMENTS: usize = 65_536;
/// Maximum number of log messages forwarded per invocation; extras are counted and dropped.
pub const MAX_LOG_MESSAGES_PER_CALL: usize = 64;
/// Maximum length of a single forwarded log message; longer messages are truncated.
pub const MAX_LOG_MESSAGE_BYTES: usize = 4 * 1024;
/// Maximum number of actions a hook may inject per invocation.
pub const MAX_INJECTED_ACTIONS_PER_CALL: usize = 64;
/// Maximum total payload bytes of actions injected per invocation.
pub const MAX_INJECTED_ACTION_BYTES_PER_CALL: usize = 256 * 1024;
/// Maximum number of provider events a hook may emit per invocation.
pub const MAX_PROVIDER_EVENTS_PER_CALL: usize = 256;
/// Maximum total bytes (type + payload) of provider events emitted per invocation.
pub const MAX_PROVIDER_EVENT_BYTES_PER_CALL: usize = 256 * 1024;
/// WebAssembly page size.
#[cfg(feature = "wasm")]
const WASM_PAGE_SIZE: u64 = 64 * 1024;

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
    /// Total payload bytes of `injected_actions` in the current call.
    pub injected_action_bytes: usize,
    /// Name of the program owning this store, used to tag forwarded log lines.
    pub program_name: String,
    /// Log messages forwarded to the host logger in the current call.
    pub log_messages_forwarded: usize,
    /// Log messages dropped in the current call because the per-call cap was reached.
    pub log_messages_dropped: usize,
    pub provider_events: Vec<RawProviderEvent>,
    /// Total bytes (type + payload) of `provider_events` in the current call.
    pub provider_event_bytes: usize,
    pub provider_events_enabled: bool,
    /// Resource limits (memory size, instance/table/memory counts) for the store.
    pub limits: wasmtime::StoreLimits,
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
    /// Create store data for one program with resource limits capping linear
    /// memory at `max_memory` bytes.
    pub fn new(
        program_name: String,
        engine_access: *const dyn EngineAccess,
        now: f64,
        provider_events_enabled: bool,
        max_memory: usize,
    ) -> Self {
        StoreData {
            engine_access,
            now,
            injected_actions: Vec::new(),
            injected_action_bytes: 0,
            program_name,
            log_messages_forwarded: 0,
            log_messages_dropped: 0,
            provider_events: Vec::new(),
            provider_event_bytes: 0,
            provider_events_enabled,
            limits: wasmtime::StoreLimitsBuilder::new()
                .memory_size(max_memory)
                .instances(1)
                .memories(1)
                .tables(MAX_TABLES)
                .table_elements(MAX_TABLE_ELEMENTS)
                .trap_on_grow_failure(true)
                .build(),
        }
    }

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
        self.injected_action_bytes = 0;
        self.log_messages_forwarded = 0;
        self.log_messages_dropped = 0;
        self.provider_events.clear();
        self.provider_event_bytes = 0;
        self.provider_events_enabled = provider_events_enabled;
    }
}

/// Wrapper around `wasmtime::Engine` with fuel-metering enabled.
#[cfg(feature = "wasm")]
pub struct WasmRuntime {
    engine: wasmtime::Engine,
    fuel: u64,
    max_memory: usize,
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
        // Host functions treat guest pointers as 32-bit offsets.
        config.wasm_memory64(false);
        let engine = wasmtime::Engine::new(&config)?;
        Ok(WasmRuntime {
            engine,
            fuel: DEFAULT_FUEL,
            max_memory: DEFAULT_MAX_MEMORY,
        })
    }

    /// Compile a module, rejecting any memory whose declared minimum size
    /// exceeds the runtime's memory limit.
    pub fn compile(&self, bytes: &[u8]) -> Result<wasmtime::Module, wasmtime::Error> {
        let module = wasmtime::Module::new(&self.engine, bytes)?;
        let memories = module
            .exports()
            .map(|e| e.ty())
            .chain(module.imports().map(|i| i.ty()))
            .filter_map(|ty| ty.memory().cloned());
        for memory in memories {
            let min_bytes = memory.minimum().saturating_mul(WASM_PAGE_SIZE);
            if min_bytes > self.max_memory as u64 {
                wasmtime::bail!(
                    "module declares a minimum memory of {} bytes, above the limit of {} bytes",
                    min_bytes,
                    self.max_memory
                );
            }
        }
        Ok(module)
    }

    pub fn engine(&self) -> &wasmtime::Engine {
        &self.engine
    }

    pub fn fuel(&self) -> u64 {
        self.fuel
    }

    /// Maximum linear memory size, in bytes, for each hook instance.
    pub fn max_memory(&self) -> usize {
        self.max_memory
    }

    /// Create a store for one program with fuel and memory limits applied.
    pub fn new_store(
        &self,
        data: StoreData,
    ) -> Result<wasmtime::Store<StoreData>, wasmtime::Error> {
        let mut store = wasmtime::Store::new(&self.engine, data);
        store.limiter(|data| &mut data.limits);
        store.set_fuel(self.fuel)?;
        Ok(store)
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
