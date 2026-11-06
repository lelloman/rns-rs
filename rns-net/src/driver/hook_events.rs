//! Hook management events: loading, unloading, reloading and listing hook
//! programs. Handled here rather than in the driver loop's own match so the
//! compact engine's RPC service can apply them inline (see `rpc_service`).

use super::*;

impl Driver {
    /// Apply a hook management event. Other events are ignored.
    pub(crate) fn handle_hook_event(&mut self, event: Event) {
        match event {
            Event::LoadHook {
                name,
                wasm_bytes,
                attach_point,
                priority,
                response_tx,
            } => {
                #[cfg(feature = "hooks")]
                {
                    let result = (|| -> Result<(), String> {
                        let point_idx = crate::config::parse_hook_point(&attach_point)
                            .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                        let mgr = self
                            .hook_manager
                            .as_ref()
                            .ok_or_else(|| "hook manager not available".to_string())?;
                        let program = mgr
                            .compile(name.clone(), &wasm_bytes, priority)
                            .map_err(|e| format!("compile error: {}", e))?;
                        self.hook_slots[point_idx].attach(program);
                        log::info!(
                            "Loaded hook '{}' at point {} (priority {})",
                            name,
                            attach_point,
                            priority
                        );
                        Ok(())
                    })();
                    let _ = response_tx.send(result);
                }
                #[cfg(not(feature = "hooks"))]
                {
                    let _ = (name, wasm_bytes, attach_point, priority);
                    let _ = response_tx.send(Err("hooks not enabled".to_string()));
                }
            }
            Event::LoadHookFile {
                name,
                path,
                hook_type,
                attach_point,
                priority,
                response_tx,
            } => {
                #[cfg(feature = "hooks")]
                {
                    let result = (|| -> Result<(), String> {
                        let point_idx = crate::config::parse_hook_point(&attach_point)
                            .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                        let backend = crate::config::parse_hook_backend(&hook_type)?;
                        let mgr = self
                            .hook_manager
                            .as_ref()
                            .ok_or_else(|| "hook manager not available".to_string())?;
                        let program = mgr
                            .load_file_backend(
                                name.clone(),
                                std::path::Path::new(&path),
                                priority,
                                backend,
                            )
                            .map_err(|e| format!("load error: {}", e))?;
                        self.hook_slots[point_idx].attach(program);
                        log::info!(
                            "Loaded {} hook '{}' at point {} (priority {})",
                            backend.as_str(),
                            name,
                            attach_point,
                            priority
                        );
                        Ok(())
                    })();
                    let _ = response_tx.send(result);
                }
                #[cfg(not(feature = "hooks"))]
                {
                    let _ = (name, path, hook_type, attach_point, priority);
                    let _ = response_tx.send(Err("hooks not enabled".to_string()));
                }
            }
            Event::LoadBuiltinHook {
                name,
                builtin_id,
                attach_point,
                priority,
                response_tx,
            } => {
                #[cfg(feature = "hooks")]
                {
                    let result = (|| -> Result<(), String> {
                        let point_idx = crate::config::parse_hook_point(&attach_point)
                            .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                        let mgr = self
                            .hook_manager
                            .as_ref()
                            .ok_or_else(|| "hook manager not available".to_string())?;
                        let program = mgr
                            .load_builtin(name.clone(), builtin_id.as_str(), priority)
                            .map_err(|e| format!("load error: {}", e))?;
                        self.hook_slots[point_idx].attach(program);
                        log::info!(
                            "Loaded built-in hook '{}' ({}) at point {} (priority {})",
                            name,
                            builtin_id,
                            attach_point,
                            priority
                        );
                        Ok(())
                    })();
                    let _ = response_tx.send(result);
                }
                #[cfg(not(feature = "hooks"))]
                {
                    let _ = (name, builtin_id, attach_point, priority);
                    let _ = response_tx.send(Err("hooks not enabled".to_string()));
                }
            }
            Event::UnloadHook {
                name,
                attach_point,
                response_tx,
            } => {
                #[cfg(feature = "hooks")]
                {
                    let result = (|| -> Result<(), String> {
                        let point_idx = crate::config::parse_hook_point(&attach_point)
                            .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                        match self.hook_slots[point_idx].detach(&name) {
                            Some(_) => {
                                log::info!("Unloaded hook '{}' from point {}", name, attach_point);
                                Ok(())
                            }
                            None => Err(format!(
                                "hook '{}' not found at point '{}'",
                                name, attach_point
                            )),
                        }
                    })();
                    let _ = response_tx.send(result);
                }
                #[cfg(not(feature = "hooks"))]
                {
                    let _ = (name, attach_point);
                    let _ = response_tx.send(Err("hooks not enabled".to_string()));
                }
            }
            Event::ReloadHook {
                name,
                attach_point,
                wasm_bytes,
                response_tx,
            } => {
                #[cfg(feature = "hooks")]
                {
                    let result = (|| -> Result<(), String> {
                        let point_idx = crate::config::parse_hook_point(&attach_point)
                            .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                        let old = self.hook_slots[point_idx].detach(&name).ok_or_else(|| {
                            format!("hook '{}' not found at point '{}'", name, attach_point)
                        })?;
                        let priority = old.priority;
                        let mgr = match self.hook_manager.as_ref() {
                            Some(m) => m,
                            None => {
                                self.hook_slots[point_idx].attach(old);
                                return Err("hook manager not available".to_string());
                            }
                        };
                        match mgr.compile(name.clone(), &wasm_bytes, priority) {
                            Ok(program) => {
                                self.hook_slots[point_idx].attach(program);
                                log::info!(
                                    "Reloaded hook '{}' at point {} (priority {})",
                                    name,
                                    attach_point,
                                    priority
                                );
                                Ok(())
                            }
                            Err(e) => {
                                self.hook_slots[point_idx].attach(old);
                                Err(format!("compile error: {}", e))
                            }
                        }
                    })();
                    let _ = response_tx.send(result);
                }
                #[cfg(not(feature = "hooks"))]
                {
                    let _ = (name, attach_point, wasm_bytes);
                    let _ = response_tx.send(Err("hooks not enabled".to_string()));
                }
            }
            Event::ReloadHookFile {
                name,
                attach_point,
                path,
                hook_type,
                response_tx,
            } => {
                #[cfg(feature = "hooks")]
                {
                    let result = (|| -> Result<(), String> {
                        let point_idx = crate::config::parse_hook_point(&attach_point)
                            .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                        let old = self.hook_slots[point_idx].detach(&name).ok_or_else(|| {
                            format!("hook '{}' not found at point '{}'", name, attach_point)
                        })?;
                        let priority = old.priority;
                        let backend = match crate::config::parse_hook_backend(&hook_type) {
                            Ok(backend) => backend,
                            Err(e) => {
                                self.hook_slots[point_idx].attach(old);
                                return Err(e);
                            }
                        };
                        let mgr = match self.hook_manager.as_ref() {
                            Some(m) => m,
                            None => {
                                self.hook_slots[point_idx].attach(old);
                                return Err("hook manager not available".to_string());
                            }
                        };
                        match mgr.load_file_backend(
                            name.clone(),
                            std::path::Path::new(&path),
                            priority,
                            backend,
                        ) {
                            Ok(program) => {
                                self.hook_slots[point_idx].attach(program);
                                log::info!(
                                    "Reloaded {} hook '{}' at point {} (priority {})",
                                    backend.as_str(),
                                    name,
                                    attach_point,
                                    priority
                                );
                                Ok(())
                            }
                            Err(e) => {
                                self.hook_slots[point_idx].attach(old);
                                Err(format!("load error: {}", e))
                            }
                        }
                    })();
                    let _ = response_tx.send(result);
                }
                #[cfg(not(feature = "hooks"))]
                {
                    let _ = (name, attach_point, path, hook_type);
                    let _ = response_tx.send(Err("hooks not enabled".to_string()));
                }
            }
            Event::ReloadBuiltinHook {
                name,
                attach_point,
                builtin_id,
                response_tx,
            } => {
                #[cfg(feature = "hooks")]
                {
                    let result = (|| -> Result<(), String> {
                        let point_idx = crate::config::parse_hook_point(&attach_point)
                            .ok_or_else(|| format!("unknown hook point '{}'", attach_point))?;
                        let old = self.hook_slots[point_idx].detach(&name).ok_or_else(|| {
                            format!("hook '{}' not found at point '{}'", name, attach_point)
                        })?;
                        let priority = old.priority;
                        let mgr = match self.hook_manager.as_ref() {
                            Some(m) => m,
                            None => {
                                self.hook_slots[point_idx].attach(old);
                                return Err("hook manager not available".to_string());
                            }
                        };
                        match mgr.load_builtin(name.clone(), builtin_id.as_str(), priority) {
                            Ok(program) => {
                                self.hook_slots[point_idx].attach(program);
                                log::info!(
                                    "Reloaded built-in hook '{}' ({}) at point {} (priority {})",
                                    name,
                                    builtin_id,
                                    attach_point,
                                    priority
                                );
                                Ok(())
                            }
                            Err(e) => {
                                self.hook_slots[point_idx].attach(old);
                                Err(format!("load error: {}", e))
                            }
                        }
                    })();
                    let _ = response_tx.send(result);
                }
                #[cfg(not(feature = "hooks"))]
                {
                    let _ = (name, attach_point, builtin_id);
                    let _ = response_tx.send(Err("hooks not enabled".to_string()));
                }
            }
            Event::SetHookEnabled {
                name,
                attach_point,
                enabled,
                response_tx,
            } => {
                #[cfg(feature = "hooks")]
                {
                    let result = self.update_hook_program(&name, &attach_point, |program| {
                        program.enabled = enabled;
                    });
                    if result.is_ok() {
                        log::info!(
                            "{} hook '{}' at point {}",
                            if enabled { "Enabled" } else { "Disabled" },
                            name,
                            attach_point,
                        );
                    }
                    let _ = response_tx.send(result);
                }
                #[cfg(not(feature = "hooks"))]
                {
                    let _ = (name, attach_point, enabled);
                    let _ = response_tx.send(Err("hooks not enabled".to_string()));
                }
            }
            Event::SetHookPriority {
                name,
                attach_point,
                priority,
                response_tx,
            } => {
                #[cfg(feature = "hooks")]
                {
                    let result = self.update_hook_program(&name, &attach_point, |program| {
                        program.priority = priority;
                    });
                    if result.is_ok() {
                        if let Some(point_idx) = crate::config::parse_hook_point(&attach_point) {
                            self.hook_slots[point_idx]
                                .programs
                                .sort_by_key(|program| std::cmp::Reverse(program.priority));
                            log::info!(
                                "Updated hook '{}' at point {} to priority {}",
                                name,
                                attach_point,
                                priority,
                            );
                        } else {
                            log::error!(
                                "hook point '{}' became invalid during priority update",
                                attach_point
                            );
                        }
                    }
                    let _ = response_tx.send(result);
                }
                #[cfg(not(feature = "hooks"))]
                {
                    let _ = (name, attach_point, priority);
                    let _ = response_tx.send(Err("hooks not enabled".to_string()));
                }
            }
            Event::ListHooks { response_tx } => {
                #[cfg(feature = "hooks")]
                {
                    let hook_point_names = [
                        "PreIngress",
                        "PreDispatch",
                        "AnnounceReceived",
                        "PathUpdated",
                        "AnnounceRetransmit",
                        "LinkRequestReceived",
                        "LinkEstablished",
                        "LinkClosed",
                        "InterfaceUp",
                        "InterfaceDown",
                        "InterfaceConfigChanged",
                        "BackbonePeerConnected",
                        "BackbonePeerDisconnected",
                        "BackbonePeerIdleTimeout",
                        "BackbonePeerWriteStall",
                        "BackbonePeerPenalty",
                        "SendOnInterface",
                        "BroadcastOnAllInterfaces",
                        "DeliverLocal",
                        "TunnelSynthesize",
                        "Tick",
                    ];
                    let mut infos = Vec::new();
                    for (idx, slot) in self.hook_slots.iter().enumerate() {
                        let point_name = hook_point_names.get(idx).unwrap_or(&"Unknown");
                        for prog in &slot.programs {
                            infos.push(crate::event::HookInfo {
                                name: prog.name.clone(),
                                hook_type: prog.backend_name().to_string(),
                                attach_point: point_name.to_string(),
                                priority: prog.priority,
                                enabled: prog.enabled,
                                consecutive_traps: prog.consecutive_traps,
                            });
                        }
                    }
                    let _ = response_tx.send(infos);
                }
                #[cfg(not(feature = "hooks"))]
                {
                    let _ = response_tx.send(Vec::new());
                }
            }
            _ => {}
        }
    }
}
