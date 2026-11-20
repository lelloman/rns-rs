//! Hook management events: loading, unloading, reloading and listing hook
//! programs. Handled here rather than in the driver loop's own match so the
//! compact engine's RPC service can apply them inline (see `rpc_service`).

use super::*;

impl Driver {
    /// Apply a hook management event. Other events are ignored.
    pub(crate) fn handle_hook_event(&mut self, event: Event) {
        let hooks = &mut self.hooks;
        match event {
            Event::LoadHook {
                name,
                wasm_bytes,
                attach_point,
                priority,
                response_tx,
            } => {
                let _ =
                    response_tx.send(hooks.load_wasm(name, &wasm_bytes, &attach_point, priority));
            }
            Event::LoadHookFile {
                name,
                path,
                hook_type,
                attach_point,
                priority,
                response_tx,
            } => {
                let _ = response_tx.send(hooks.load_file(
                    name,
                    &path,
                    &hook_type,
                    &attach_point,
                    priority,
                ));
            }
            Event::LoadBuiltinHook {
                name,
                builtin_id,
                attach_point,
                priority,
                response_tx,
            } => {
                let _ = response_tx.send(hooks.load_builtin(
                    name,
                    &builtin_id,
                    &attach_point,
                    priority,
                ));
            }
            Event::UnloadHook {
                name,
                attach_point,
                response_tx,
            } => {
                let _ = response_tx.send(hooks.unload(&name, &attach_point));
            }
            Event::ReloadHook {
                name,
                attach_point,
                wasm_bytes,
                response_tx,
            } => {
                let _ = response_tx.send(hooks.reload_wasm(&name, &attach_point, &wasm_bytes));
            }
            Event::ReloadHookFile {
                name,
                attach_point,
                path,
                hook_type,
                response_tx,
            } => {
                let _ =
                    response_tx.send(hooks.reload_file(&name, &attach_point, &path, &hook_type));
            }
            Event::ReloadBuiltinHook {
                name,
                attach_point,
                builtin_id,
                response_tx,
            } => {
                let _ = response_tx.send(hooks.reload_builtin(&name, &attach_point, &builtin_id));
            }
            Event::SetHookEnabled {
                name,
                attach_point,
                enabled,
                response_tx,
            } => {
                let _ = response_tx.send(hooks.set_enabled(&name, &attach_point, enabled));
            }
            Event::SetHookPriority {
                name,
                attach_point,
                priority,
                response_tx,
            } => {
                let _ = response_tx.send(hooks.set_priority(&name, &attach_point, priority));
            }
            Event::ListHooks { response_tx } => {
                let _ = response_tx.send(hooks.list());
            }
            _ => {}
        }
    }
}
