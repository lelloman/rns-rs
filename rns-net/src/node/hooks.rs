//! Loading and managing hooks.

use super::*;
use crate::event::HookOpError;

impl RnsNode {
    /// Load an in-memory WASM hook at runtime.
    pub fn load_hook(
        &self,
        name: String,
        wasm_bytes: Vec<u8>,
        attach_point: String,
        priority: i32,
    ) -> Result<Result<(), HookOpError>, SendError> {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::LoadHook {
                name,
                wasm_bytes,
                attach_point,
                priority,
                response_tx,
            })
            .map_err(|_| SendError)?;
        response_rx.recv().map_err(|_| SendError)
    }

    /// Load a hook from a server-local filesystem path at runtime.
    pub fn load_hook_file(
        &self,
        name: String,
        path: String,
        hook_type: String,
        attach_point: String,
        priority: i32,
    ) -> Result<Result<(), HookOpError>, SendError> {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::LoadHookFile {
                name,
                path,
                hook_type,
                attach_point,
                priority,
                response_tx,
            })
            .map_err(|_| SendError)?;
        response_rx.recv().map_err(|_| SendError)
    }

    /// Load a registered built-in hook at runtime.
    pub fn load_builtin_hook(
        &self,
        name: String,
        builtin_id: String,
        attach_point: String,
        priority: i32,
    ) -> Result<Result<(), HookOpError>, SendError> {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::LoadBuiltinHook {
                name,
                builtin_id,
                attach_point,
                priority,
                response_tx,
            })
            .map_err(|_| SendError)?;
        response_rx.recv().map_err(|_| SendError)
    }

    /// Unload a hook at runtime.
    pub fn unload_hook(
        &self,
        name: String,
        attach_point: String,
    ) -> Result<Result<(), HookOpError>, SendError> {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::UnloadHook {
                name,
                attach_point,
                response_tx,
            })
            .map_err(|_| SendError)?;
        response_rx.recv().map_err(|_| SendError)
    }

    /// Reload an in-memory WASM hook at runtime (detach + recompile + reattach with same priority).
    pub fn reload_hook(
        &self,
        name: String,
        attach_point: String,
        wasm_bytes: Vec<u8>,
    ) -> Result<Result<(), HookOpError>, SendError> {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::ReloadHook {
                name,
                attach_point,
                wasm_bytes,
                response_tx,
            })
            .map_err(|_| SendError)?;
        response_rx.recv().map_err(|_| SendError)
    }

    /// Reload a hook from a server-local filesystem path at runtime.
    pub fn reload_hook_file(
        &self,
        name: String,
        attach_point: String,
        path: String,
        hook_type: String,
    ) -> Result<Result<(), HookOpError>, SendError> {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::ReloadHookFile {
                name,
                attach_point,
                path,
                hook_type,
                response_tx,
            })
            .map_err(|_| SendError)?;
        response_rx.recv().map_err(|_| SendError)
    }

    /// Reload a registered built-in hook at runtime.
    pub fn reload_builtin_hook(
        &self,
        name: String,
        attach_point: String,
        builtin_id: String,
    ) -> Result<Result<(), HookOpError>, SendError> {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::ReloadBuiltinHook {
                name,
                attach_point,
                builtin_id,
                response_tx,
            })
            .map_err(|_| SendError)?;
        response_rx.recv().map_err(|_| SendError)
    }

    /// Enable or disable a loaded hook at runtime.
    pub fn set_hook_enabled(
        &self,
        name: String,
        attach_point: String,
        enabled: bool,
    ) -> Result<Result<(), HookOpError>, SendError> {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::SetHookEnabled {
                name,
                attach_point,
                enabled,
                response_tx,
            })
            .map_err(|_| SendError)?;
        response_rx.recv().map_err(|_| SendError)
    }

    /// Update the priority of a loaded hook at runtime.
    pub fn set_hook_priority(
        &self,
        name: String,
        attach_point: String,
        priority: i32,
    ) -> Result<Result<(), HookOpError>, SendError> {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::SetHookPriority {
                name,
                attach_point,
                priority,
                response_tx,
            })
            .map_err(|_| SendError)?;
        response_rx.recv().map_err(|_| SendError)
    }

    /// List all loaded hooks.
    pub fn list_hooks(&self) -> Result<Vec<crate::event::HookInfo>, SendError> {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::ListHooks { response_tx })
            .map_err(|_| SendError)?;
        response_rx.recv().map_err(|_| SendError)
    }
}
