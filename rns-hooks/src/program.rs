#[cfg(feature = "native")]
use crate::native::NativeProgram;
#[cfg(feature = "wasm")]
use crate::runtime::StoreData;
#[cfg(feature = "wasm")]
use wasmtime::{Instance, Module, Store};

pub enum ProgramBackend {
    #[cfg(feature = "wasm")]
    Wasm(WasmProgram),
    #[cfg(feature = "native")]
    Native(NativeProgram),
}

#[cfg(feature = "wasm")]
pub struct WasmProgram {
    pub module: Module,
    pub export_name: String,
    /// Cached store and instance for cross-call state persistence.
    pub cached: Option<(Store<StoreData>, Instance)>,
}

/// A loaded hook program ready for execution.
pub struct LoadedProgram {
    pub name: String,
    pub priority: i32,
    pub consecutive_traps: u32,
    pub enabled: bool,
    pub max_consecutive_traps: u32,
    pub backend: ProgramBackend,
}

impl LoadedProgram {
    #[cfg(feature = "wasm")]
    pub fn new(name: String, module: Module, priority: i32) -> Self {
        LoadedProgram {
            name,
            priority,
            consecutive_traps: 0,
            enabled: true,
            max_consecutive_traps: 10,
            backend: ProgramBackend::Wasm(WasmProgram {
                module,
                export_name: "on_hook".to_string(),
                cached: None,
            }),
        }
    }

    #[cfg(feature = "native")]
    pub fn new_native(name: String, native: NativeProgram, priority: i32) -> Self {
        LoadedProgram {
            name,
            priority,
            consecutive_traps: 0,
            enabled: true,
            max_consecutive_traps: 10,
            backend: ProgramBackend::Native(native),
        }
    }

    /// Reset the consecutive trap counter after a successful execution.
    pub fn record_success(&mut self) {
        self.consecutive_traps = 0;
    }

    /// Drop the cached store/instance (e.g. on reload).
    pub fn drop_cache(&mut self) {
        match &mut self.backend {
            #[cfg(feature = "wasm")]
            ProgramBackend::Wasm(wasm) => {
                wasm.cached = None;
            }
            #[cfg(feature = "native")]
            ProgramBackend::Native(_) => {}
        }
    }

    pub fn backend_name(&self) -> &'static str {
        match &self.backend {
            #[cfg(feature = "wasm")]
            ProgramBackend::Wasm(_) => "wasm",
            #[cfg(feature = "native")]
            ProgramBackend::Native(_) => "native",
        }
    }

    /// Increment the trap counter. Returns `true` if the program was auto-disabled.
    pub fn record_trap(&mut self) -> bool {
        self.consecutive_traps += 1;
        if self.consecutive_traps >= self.max_consecutive_traps {
            self.enabled = false;
            true
        } else {
            false
        }
    }
}
