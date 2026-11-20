#[cfg(feature = "native")]
use crate::arena;
use crate::engine_access::EngineAccess;
use crate::error::HookError;
use crate::hooks::HookContext;
#[cfg(feature = "wasm")]
use crate::host_fns;
use crate::program::{LoadedProgram, ProgramBackend};
use crate::result::{ExecuteResult, HookResult, Verdict};
#[cfg(feature = "wasm")]
use crate::runtime::{StoreData, WasmRuntime};
#[cfg(feature = "wasm")]
use wasmtime::Linker;

#[cfg(feature = "wasm")]
mod wasm;

/// Central manager for hook execution.
///
/// Owns any enabled backend runtime state. Programs are stored in `HookSlot`s
/// (one per hook point); the manager provides execution.
pub struct HookManager {
    #[cfg(feature = "wasm")]
    runtime: WasmRuntime,
    #[cfg(feature = "wasm")]
    linker: Linker<StoreData>,
}

/// Where a hook program comes from.
///
/// Parses from `"wasm"`, `"native"` (or `"dylib"`, `"dynamic"`) and
/// `"builtin"` (or `"built-in"`, `"static"`), ignoring case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookBackend {
    /// A WebAssembly module, run sandboxed with fuel and memory limits.
    /// Needs the `wasm` feature.
    Wasm,
    /// A shared library loaded into the process, unsandboxed. Needs the
    /// `native` feature.
    Native,
    /// A Rust hook registered with
    /// [`register_builtin_hook`](crate::register_builtin_hook).
    Builtin,
}

impl HookBackend {
    /// The canonical name: `"wasm"`, `"native"` or `"builtin"`.
    pub fn as_str(self) -> &'static str {
        match self {
            HookBackend::Wasm => "wasm",
            HookBackend::Native => "native",
            HookBackend::Builtin => "builtin",
        }
    }
}

impl std::str::FromStr for HookBackend {
    type Err = UnknownHookBackend;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "wasm" => Ok(HookBackend::Wasm),
            "native" | "dylib" | "dynamic" => Ok(HookBackend::Native),
            "builtin" | "built-in" | "static" => Ok(HookBackend::Builtin),
            other => Err(UnknownHookBackend {
                name: other.to_string(),
            }),
        }
    }
}

/// A hook type that names no [`HookBackend`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownHookBackend {
    /// The type as given, lowercased.
    pub name: String,
}

impl std::fmt::Display for UnknownHookBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown hook type '{}'", self.name)
    }
}

impl std::error::Error for UnknownHookBackend {}

impl HookManager {
    /// Creates the manager, setting up the WASM engine and its host
    /// functions when the `wasm` feature is on. Fails with
    /// [`HookError::CompileError`] if Wasmtime cannot be configured.
    pub fn new() -> Result<Self, HookError> {
        #[cfg(feature = "wasm")]
        {
            let runtime = WasmRuntime::new().map_err(|e| HookError::CompileError(e.to_string()))?;
            let mut linker = Linker::new(runtime.engine());
            host_fns::register_host_functions(&mut linker)
                .map_err(|e| HookError::CompileError(e.to_string()))?;
            Ok(HookManager { runtime, linker })
        }
        #[cfg(not(feature = "wasm"))]
        {
            Ok(HookManager {})
        }
    }

    /// Compile WASM bytes into a LoadedProgram.
    ///
    /// Validates that the module exports `__rns_abi_version` returning the
    /// expected ABI version before accepting it; that runs the module's
    /// start code once. Fails with [`HookError::CompileError`] for an invalid
    /// module (or without the `wasm` feature),
    /// [`HookError::AbiVersionMismatch`] for a missing or different version,
    /// and [`HookError::InstantiationError`] or [`HookError::Trap`] if
    /// checking the version fails. Each run calls the module's `on_hook` export.
    pub fn compile(
        &self,
        name: String,
        bytes: &[u8],
        priority: i32,
    ) -> Result<LoadedProgram, HookError> {
        #[cfg(not(feature = "wasm"))]
        {
            let _ = (name, bytes, priority);
            Err(HookError::CompileError(
                "WASM hook backend not enabled".to_string(),
            ))
        }
        #[cfg(feature = "wasm")]
        {
            let module = self
                .runtime
                .compile(bytes)
                .map_err(|e| HookError::CompileError(format!("{:#}", e)))?;
            self.validate_abi_version(&name, &module)?;
            Ok(LoadedProgram::new(name, module, priority))
        }
    }

    /// Compile a WASM file from disk, as [`compile`](Self::compile); fails
    /// with [`HookError::IoError`] if the file cannot be read.
    pub fn load_file(
        &self,
        name: String,
        path: &std::path::Path,
        priority: i32,
    ) -> Result<LoadedProgram, HookError> {
        let bytes = std::fs::read(path)?;
        self.compile(name, &bytes, priority)
    }

    /// Loads a WASM module or native library from `path`, as the backend
    /// says. Fails with [`HookError::CompileError`] for
    /// [`HookBackend::Builtin`], which is loaded by id with
    /// [`load_builtin`](Self::load_builtin), and for a backend this build
    /// does not include.
    pub fn load_file_backend(
        &self,
        name: String,
        path: &std::path::Path,
        priority: i32,
        backend: HookBackend,
    ) -> Result<LoadedProgram, HookError> {
        match backend {
            HookBackend::Wasm => self.load_file(name, path, priority),
            HookBackend::Builtin => Err(HookError::CompileError(
                "built-in hooks are loaded by ID, not file path".to_string(),
            )),
            HookBackend::Native => {
                #[cfg(feature = "native")]
                {
                    let native = crate::native::NativeProgram::load(path)?;
                    Ok(LoadedProgram::new_native(name, native, priority))
                }
                #[cfg(not(feature = "native"))]
                {
                    let _ = (name, path, priority);
                    Err(HookError::CompileError(
                        "native hook backend not enabled".to_string(),
                    ))
                }
            }
        }
    }

    /// Wraps the built-in hook registered under `id` as a program named
    /// `name`. Fails with [`HookError::CompileError`] if no hook is
    /// registered under `id`.
    pub fn load_builtin(
        &self,
        name: String,
        id: impl Into<String>,
        priority: i32,
    ) -> Result<LoadedProgram, HookError> {
        let builtin = crate::builtin::BuiltinProgram::load(id)?;
        Ok(LoadedProgram::new_builtin(name, builtin, priority))
    }

    /// Execute a single program against a hook context. Returns an `ExecuteResult`
    /// containing the hook result, any injected actions, and modified data (all
    /// extracted from WASM memory before the store is dropped). Returns `None`
    /// if the program is disabled or fails (trap, fuel exhaustion, invalid
    /// result): failures are logged and fail open, and enough of them in a
    /// row disable the program.
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
        self.execute_program_with_provider_events(
            program,
            ctx,
            engine_access,
            now,
            false,
            data_override,
        )
    }

    /// [`execute_program`](Self::execute_program), with provider events
    /// allowed when `provider_events_enabled` is true.
    pub fn execute_program_with_provider_events(
        &self,
        program: &mut LoadedProgram,
        ctx: &HookContext,
        engine_access: &dyn EngineAccess,
        now: f64,
        provider_events_enabled: bool,
        data_override: Option<&[u8]>,
    ) -> Option<ExecuteResult> {
        if !program.enabled {
            return None;
        }

        if matches!(program.backend, ProgramBackend::Builtin(_)) {
            let result = match &program.backend {
                ProgramBackend::Builtin(builtin) => builtin.execute(
                    ctx,
                    data_override,
                    engine_access,
                    now,
                    provider_events_enabled,
                ),
                #[cfg(feature = "wasm")]
                ProgramBackend::Wasm(_) => unreachable!(),
                #[cfg(feature = "native")]
                ProgramBackend::Native(_) => unreachable!(),
            };
            return match result {
                Ok(mut exec) => {
                    program.record_success();
                    for event in &mut exec.provider_events {
                        event.hook_name = program.name.clone();
                    }
                    Some(exec)
                }
                Err(e) => {
                    let auto_disabled = program.record_trap();
                    if auto_disabled {
                        log::error!(
                            "built-in hook '{}' auto-disabled after {} consecutive errors",
                            program.name,
                            program.consecutive_traps
                        );
                    } else {
                        log::warn!("built-in hook '{}' failed: {}", program.name, e);
                    }
                    None
                }
            };
        }

        #[cfg(feature = "native")]
        if matches!(program.backend, ProgramBackend::Native(_)) {
            let ctx_bytes = match arena::context_to_bytes(ctx, data_override) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::warn!(
                        "failed to encode native hook context '{}': {}",
                        program.name,
                        e
                    );
                    program.record_trap();
                    return None;
                }
            };
            let result = match &program.backend {
                ProgramBackend::Native(native) => {
                    native.execute(&ctx_bytes, engine_access, provider_events_enabled)
                }
                ProgramBackend::Builtin(_) => unreachable!(),
                #[cfg(feature = "wasm")]
                ProgramBackend::Wasm(_) => unreachable!(),
            };
            return match result {
                Ok(mut exec) => {
                    program.record_success();
                    for event in &mut exec.provider_events {
                        event.hook_name = program.name.clone();
                    }
                    Some(exec)
                }
                Err(e) => {
                    let auto_disabled = program.record_trap();
                    if auto_disabled {
                        log::error!(
                            "native hook '{}' auto-disabled after {} consecutive errors",
                            program.name,
                            program.consecutive_traps
                        );
                    } else {
                        log::warn!("native hook '{}' failed: {}", program.name, e);
                    }
                    None
                }
            };
        }

        #[cfg(not(feature = "wasm"))]
        {
            let _ = (
                ctx,
                engine_access,
                now,
                provider_events_enabled,
                data_override,
            );
            None
        }

        #[cfg(feature = "wasm")]
        {
            self.execute_wasm_program(
                program,
                ctx,
                engine_access,
                now,
                provider_events_enabled,
                data_override,
            )
        }
    }

    /// Run a chain of programs. Stops on Drop or Halt, continues on Continue or Modify.
    /// Returns an `ExecuteResult` accumulating all injected actions across the chain
    /// and the last meaningful hook result (Drop/Halt/Modify), or None if all continued.
    ///
    /// When a hook returns Modify with modified data, subsequent hooks in the chain
    /// receive the modified data (only applicable to Packet contexts).
    /// Runs the enabled programs in order (highest priority first), without
    /// provider events; see
    /// [`run_chain_with_provider_events`](Self::run_chain_with_provider_events).
    pub fn run_chain(
        &self,
        programs: &mut [LoadedProgram],
        ctx: &HookContext,
        engine_access: &dyn EngineAccess,
        now: f64,
    ) -> Option<ExecuteResult> {
        self.run_chain_with_provider_events(programs, ctx, engine_access, now, false)
    }

    /// Runs the enabled programs in order, stopping at the first `Drop` or
    /// `Halt`.
    ///
    /// For a packet context, each `Modify` replaces the packet bytes the
    /// following programs see. Injected actions and provider events are
    /// collected from every program that ran. A program that fails is
    /// skipped (fail-open). Returns `None` if nothing needs acting on: every
    /// program continued and none injected actions or emitted events.
    pub fn run_chain_with_provider_events(
        &self,
        programs: &mut [LoadedProgram],
        ctx: &HookContext,
        engine_access: &dyn EngineAccess,
        now: f64,
        provider_events_enabled: bool,
    ) -> Option<ExecuteResult> {
        let mut accumulated_actions = Vec::new();
        let mut accumulated_provider_events = Vec::new();
        let mut last_result: Option<HookResult> = None;
        let mut last_modified_data: Option<Vec<u8>> = None;
        let is_packet_ctx = matches!(ctx, HookContext::Packet { .. });

        for program in programs.iter_mut() {
            if !program.enabled {
                continue;
            }
            let override_ref = if is_packet_ctx {
                last_modified_data.as_deref()
            } else {
                None
            };
            if let Some(exec_result) = self.execute_program_with_provider_events(
                program,
                ctx,
                engine_access,
                now,
                provider_events_enabled,
                override_ref,
            ) {
                accumulated_actions.extend(exec_result.injected_actions);
                accumulated_provider_events.extend(exec_result.provider_events);

                if let Some(ref result) = exec_result.hook_result {
                    let verdict = Verdict::from_u32(result.verdict);
                    match verdict {
                        Some(Verdict::Drop) | Some(Verdict::Halt) => {
                            return Some(ExecuteResult {
                                hook_result: exec_result.hook_result,
                                injected_actions: accumulated_actions,
                                provider_events: accumulated_provider_events,
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

        if last_result.is_some()
            || !accumulated_actions.is_empty()
            || !accumulated_provider_events.is_empty()
        {
            Some(ExecuteResult {
                hook_result: last_result,
                injected_actions: accumulated_actions,
                provider_events: accumulated_provider_events,
                modified_data: last_modified_data,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
#[cfg(feature = "wasm")]
mod tests;
