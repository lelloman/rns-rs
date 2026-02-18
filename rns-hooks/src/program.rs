use crate::runtime::StoreData;
use wasmtime::{Instance, Module, Store};

/// A compiled WASM hook program ready for execution.
pub struct LoadedProgram {
    pub name: String,
    pub module: Module,
    pub priority: i32,
    pub consecutive_traps: u32,
    pub enabled: bool,
    pub max_consecutive_traps: u32,
    pub export_name: String,
    /// Cached store and instance for cross-call state persistence.
    pub cached: Option<(Store<StoreData>, Instance)>,
}

impl LoadedProgram {
    pub fn new(name: String, module: Module, priority: i32) -> Self {
        LoadedProgram {
            name,
            module,
            priority,
            consecutive_traps: 0,
            enabled: true,
            max_consecutive_traps: 10,
            export_name: "on_hook".to_string(),
            cached: None,
        }
    }

    /// Reset the consecutive trap counter after a successful execution.
    pub fn record_success(&mut self) {
        self.consecutive_traps = 0;
    }

    /// Drop the cached store/instance (e.g. on reload).
    pub fn drop_cache(&mut self) {
        self.cached = None;
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
