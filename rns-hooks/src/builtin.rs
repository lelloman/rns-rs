use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

use crate::engine_access::EngineAccess;
use crate::error::HookError;
use crate::hooks::HookContext;
use crate::result::{ExecuteResult, HookResult, Verdict};
use crate::runtime::RawProviderEvent;
use crate::wire::ActionWire;

/// Invocation data passed to a built-in hook.
///
/// Built-in hooks are regular Rust code linked into the host process. They are
/// intended for first-party hooks and appliance builds where the hook code is
/// trusted and should not require a WASM runtime or a dynamic library file.
pub struct BuiltinHookCall<'a> {
    pub ctx: &'a HookContext<'a>,
    pub data_override: Option<&'a [u8]>,
    pub engine_access: &'a dyn EngineAccess,
    pub now: f64,
    pub provider_events_enabled: bool,
}

/// Host-side effects a built-in hook may request during one invocation.
#[derive(Default)]
pub struct BuiltinHookHost {
    injected_actions: Vec<ActionWire>,
    provider_events: Vec<RawProviderEvent>,
    modified_data: Option<Vec<u8>>,
}

impl BuiltinHookHost {
    pub fn inject_action(&mut self, action: ActionWire) {
        self.injected_actions.push(action);
    }

    pub fn emit_event(
        &mut self,
        call: &BuiltinHookCall<'_>,
        payload_type: impl Into<String>,
        payload: impl Into<Vec<u8>>,
    ) -> Result<(), HookError> {
        if !call.provider_events_enabled {
            return Err(HookError::Trap(
                "provider events are not enabled for this invocation".into(),
            ));
        }
        self.provider_events.push(RawProviderEvent {
            payload_type: payload_type.into(),
            payload: payload.into(),
        });
        Ok(())
    }

    pub fn set_modified_data(&mut self, data: impl Into<Vec<u8>>) {
        self.modified_data = Some(data.into());
    }

    fn finish(self, result: HookResult) -> ExecuteResult {
        ExecuteResult {
            hook_result: Some(result),
            injected_actions: self.injected_actions,
            provider_events: self
                .provider_events
                .into_iter()
                .map(|event| crate::result::EmittedProviderEvent {
                    hook_name: String::new(),
                    payload_type: event.payload_type,
                    payload: event.payload,
                })
                .collect(),
            modified_data: self.modified_data,
        }
    }
}

pub trait BuiltinHook: Send + Sync + 'static {
    fn call(
        &self,
        call: BuiltinHookCall<'_>,
        host: &mut BuiltinHookHost,
    ) -> Result<HookResult, HookError>;
}

impl<F> BuiltinHook for F
where
    F: for<'a, 'b> Fn(
            BuiltinHookCall<'a>,
            &'b mut BuiltinHookHost,
        ) -> Result<HookResult, HookError>
        + Send
        + Sync
        + 'static,
{
    fn call(
        &self,
        call: BuiltinHookCall<'_>,
        host: &mut BuiltinHookHost,
    ) -> Result<HookResult, HookError> {
        self(call, host)
    }
}

#[derive(Clone)]
pub struct BuiltinProgram {
    id: String,
    hook: Arc<dyn BuiltinHook>,
}

impl BuiltinProgram {
    pub fn load(id: impl Into<String>) -> Result<Self, HookError> {
        let id = id.into();
        let hook = resolve_builtin_hook(&id).ok_or_else(|| {
            HookError::CompileError(format!("built-in hook '{}' is not registered", id))
        })?;
        Ok(Self { id, hook })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn execute(
        &self,
        ctx: &HookContext<'_>,
        data_override: Option<&[u8]>,
        engine_access: &dyn EngineAccess,
        now: f64,
        provider_events_enabled: bool,
    ) -> Result<ExecuteResult, HookError> {
        let call = BuiltinHookCall {
            ctx,
            data_override,
            engine_access,
            now,
            provider_events_enabled,
        };
        let mut host = BuiltinHookHost::default();
        let result = self.hook.call(call, &mut host)?;
        if Verdict::from_u32(result.verdict).is_none() {
            return Err(HookError::InvalidResult(format!(
                "invalid verdict value: {}",
                result.verdict
            )));
        }
        Ok(host.finish(result))
    }
}

static BUILTIN_HOOKS: OnceLock<RwLock<HashMap<String, Arc<dyn BuiltinHook>>>> = OnceLock::new();

fn registry() -> &'static RwLock<HashMap<String, Arc<dyn BuiltinHook>>> {
    BUILTIN_HOOKS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Register a built-in hook implementation under a stable ID.
///
/// Third-party binaries can call this at startup after linking a plugin crate:
///
/// ```ignore
/// rns_hooks::register_builtin_hook("vendor.my_hook", my_hook::hook)?;
/// ```
pub fn register_builtin_hook(
    id: impl Into<String>,
    hook: impl BuiltinHook,
) -> Result<(), HookError> {
    let id = id.into();
    let mut hooks = registry()
        .write()
        .map_err(|_| HookError::CompileError("built-in hook registry poisoned".into()))?;
    if hooks.contains_key(&id) {
        return Err(HookError::CompileError(format!(
            "built-in hook '{}' is already registered",
            id
        )));
    }
    hooks.insert(id, Arc::new(hook));
    Ok(())
}

pub fn resolve_builtin_hook(id: &str) -> Option<Arc<dyn BuiltinHook>> {
    registry().read().ok()?.get(id).cloned()
}

#[cfg(test)]
pub fn clear_builtin_hooks_for_tests() {
    if let Ok(mut hooks) = registry().write() {
        hooks.clear();
    }
}
