use crate::builtin::BuiltinProgram;
#[cfg(feature = "native")]
use crate::native::NativeProgram;
#[cfg(feature = "wasm")]
use crate::runtime::StoreData;
#[cfg(feature = "wasm")]
use wasmtime::{Instance, Module, Store};

pub(crate) enum ProgramBackend {
    Builtin(BuiltinProgram),
    #[cfg(feature = "wasm")]
    Wasm(WasmProgram),
    #[cfg(feature = "native")]
    Native(NativeProgram),
}

#[cfg(feature = "wasm")]
impl ProgramBackend {
    /// The WebAssembly program, if this is one.
    pub(crate) fn wasm(&self) -> Option<&WasmProgram> {
        match self {
            ProgramBackend::Wasm(wasm) => Some(wasm),
            _ => None,
        }
    }

    /// [`Self::wasm`], mutably.
    pub(crate) fn wasm_mut(&mut self) -> Option<&mut WasmProgram> {
        match self {
            ProgramBackend::Wasm(wasm) => Some(wasm),
            _ => None,
        }
    }
}

#[cfg(feature = "wasm")]
pub(crate) struct WasmProgram {
    pub(crate) module: Module,
    pub(crate) export_name: String,
    /// Cached store and instance for cross-call state persistence.
    pub(crate) cached: Option<(Store<StoreData>, Instance)>,
}

/// A loaded hook program ready for execution.
///
/// Created by the [`HookManager`](crate::HookManager) loaders and attached
/// to a [`HookSlot`](crate::HookSlot).
pub struct LoadedProgram {
    /// Name the program was loaded under; unique within a hook point.
    pub name: String,
    /// Higher priorities run first within a hook point.
    pub priority: i32,
    /// Failed runs in a row; reset by a successful run. At 10 the program
    /// is disabled.
    pub consecutive_traps: u32,
    /// Disabled programs are skipped. Set to false automatically after too
    /// many consecutive failures.
    pub enabled: bool,
    pub(crate) max_consecutive_traps: u32,
    pub(crate) backend: ProgramBackend,
}

impl LoadedProgram {
    pub(crate) fn new_builtin(name: String, builtin: BuiltinProgram, priority: i32) -> Self {
        LoadedProgram {
            name,
            priority,
            consecutive_traps: 0,
            enabled: true,
            max_consecutive_traps: 10,
            backend: ProgramBackend::Builtin(builtin),
        }
    }

    #[cfg(feature = "wasm")]
    pub(crate) fn new(name: String, module: Module, priority: i32) -> Self {
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
    pub(crate) fn new_native(name: String, native: NativeProgram, priority: i32) -> Self {
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
    pub(crate) fn record_success(&mut self) {
        self.consecutive_traps = 0;
    }

    /// The backend's name: `"builtin"`, `"wasm"` or `"native"`.
    pub fn backend_name(&self) -> &'static str {
        match &self.backend {
            ProgramBackend::Builtin(_) => "builtin",
            #[cfg(feature = "wasm")]
            ProgramBackend::Wasm(_) => "wasm",
            #[cfg(feature = "native")]
            ProgramBackend::Native(_) => "native",
        }
    }

    /// Increment the trap counter. Returns `true` if the program was auto-disabled.
    pub(crate) fn record_trap(&mut self) -> bool {
        self.consecutive_traps += 1;
        if self.consecutive_traps >= self.max_consecutive_traps {
            self.enabled = false;
            true
        } else {
            false
        }
    }
}
