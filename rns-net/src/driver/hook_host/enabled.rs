//! The hook host of builds with hooks: hook slots, the manager that runs
//! them, and the provider bridge their events go to.

use super::*;
use crate::config::{parse_hook_backend, parse_hook_point, ParsedHook};
use crate::event::{HookInfo, HookOpError, ProviderBridgeStats};
use crate::provider_bridge::ProviderBridge;
pub(crate) use rns_hooks::HookPoint;
use rns_hooks::{
    create_hook_slots, ActionWire, EngineAccess, ExecuteResult, HookBackend, HookContext,
    HookError, HookManager, HookSlot, LoadedProgram, PacketContext, Verdict,
};

/// Hook point names, indexed by [`HookPoint`].
const HOOK_POINT_NAMES: [&str; HookPoint::COUNT] = [
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

/// The programmable hook system's driver-side state.
pub(crate) struct HookHost {
    /// Hook slots, one per [`HookPoint`].
    pub(crate) slots: [HookSlot; HookPoint::COUNT],
    /// Hook manager. None if initialization failed.
    pub(crate) manager: Option<HookManager>,
    /// Hands the events hooks emit to connected consumers, when enabled.
    pub(crate) provider_bridge: Option<ProviderBridge>,
    /// Per hook point count of `Modify` replacements that failed validation
    /// and were therefore treated as `Drop`.
    pub(crate) rejected_modifications: [u64; HookPoint::COUNT],
}

/// What a hook chain produced.
pub(crate) struct HookRun(ExecuteResult);

impl HookRun {
    /// Whether a hook dropped what the hook point handles.
    pub(crate) fn dropped(&self) -> bool {
        self.0.hook_result.as_ref().is_some_and(|r| r.is_drop())
    }

    /// Take the actions the hooks injected.
    pub(crate) fn take_injected(&mut self) -> Vec<TransportAction> {
        let injected = std::mem::take(&mut self.0.injected_actions);
        if injected.is_empty() {
            Vec::new()
        } else {
            convert_injected_actions(injected)
        }
    }
}

impl HookHost {
    pub(crate) fn new() -> Self {
        Self {
            slots: create_hook_slots(),
            manager: HookManager::new().ok(),
            provider_bridge: None,
            rejected_modifications: [0; HookPoint::COUNT],
        }
    }

    /// Whether any program is attached at `point`. Per-packet hook points
    /// check this before building their event.
    #[inline]
    pub(crate) fn attached(&self, point: HookPoint) -> bool {
        !self.slots[point as usize].programs.is_empty()
    }

    /// Run the hook chain at `point` on `event`. `None` when no program is
    /// attached or there is no manager.
    pub(crate) fn run(
        &mut self,
        point: HookPoint,
        event: &HookEvent<'_>,
        env: &HookEnv<'_>,
    ) -> Option<HookRun> {
        let programs = &mut self.slots[point as usize].programs;
        if programs.is_empty() {
            return None;
        }
        let manager = self.manager.as_ref()?;
        let now = time::now();
        let engine = EngineRef { env, now };
        let packet_ctx;
        let ctx = match *event {
            HookEvent::Packet {
                flags,
                hops,
                destination_hash,
                packet_hash,
                interface_id,
                raw,
            } => {
                packet_ctx = PacketContext {
                    flags,
                    hops,
                    destination_hash,
                    context: 0,
                    packet_hash,
                    interface_id,
                    data_offset: 0,
                    data_len: raw.len() as u32,
                };
                HookContext::Packet {
                    ctx: &packet_ctx,
                    raw,
                }
            }
            HookEvent::Interface { interface_id } => HookContext::Interface { interface_id },
            HookEvent::Tick => HookContext::Tick,
            HookEvent::Announce {
                destination_hash,
                hops,
                interface_id,
            } => HookContext::Announce {
                destination_hash,
                hops,
                interface_id,
            },
            HookEvent::Link {
                link_id,
                interface_id,
            } => HookContext::Link {
                link_id,
                interface_id,
            },
            HookEvent::BackbonePeer(peer) => HookContext::BackbonePeer {
                server_interface_id: peer.server_interface_id.0,
                peer_interface_id: peer.peer_interface_id.map(|id| id.0),
                peer_ip: peer.peer_ip,
                peer_port: peer.peer_port,
                connected_for: peer.connected_for,
                had_received_data: peer.had_received_data,
                penalty_level: peer.penalty_level,
                blacklist_for: peer.blacklist_for,
            },
        };
        manager
            .run_chain_with_provider_events(
                programs,
                &ctx,
                &engine,
                now,
                self.provider_bridge.is_some(),
            )
            .map(HookRun)
    }

    /// Hand the events the hooks of `run` emitted to the provider bridge.
    pub(crate) fn emit_provider_events(&self, point: HookPoint, run: &HookRun) {
        if let Some(ref bridge) = self.provider_bridge {
            for event in &run.0.provider_events {
                bridge.emit_event(
                    HOOK_POINT_NAMES[point as usize],
                    event.hook_name.clone(),
                    event.payload_type.clone(),
                    event.payload.clone(),
                );
            }
        }
    }

    /// Turn a packet hook chain result into the action the hook point takes.
    ///
    /// `Drop` stops the packet. `Modify` with replacement bytes is validated
    /// against `max_len` and the packet decoder; a replacement that fails
    /// validation is treated as `Drop` and counted in
    /// `rejected_modifications`. `Modify` without bytes, `Continue` and
    /// `Halt` keep the current bytes.
    pub(crate) fn packet_outcome(
        &mut self,
        point: HookPoint,
        run: &HookRun,
        max_len: usize,
    ) -> PacketHookOutcome {
        let Some(result) = run.0.hook_result.as_ref() else {
            return PacketHookOutcome::Keep;
        };
        if result.is_drop() {
            return PacketHookOutcome::Drop;
        }
        if Verdict::from_u32(result.verdict) != Some(Verdict::Modify) {
            return PacketHookOutcome::Keep;
        }
        let Some(data) = run.0.modified_data.as_deref() else {
            return PacketHookOutcome::Keep;
        };
        match validate_hook_replacement(data, max_len) {
            Ok(packet) => PacketHookOutcome::Replace(packet),
            Err(reason) => {
                let rejected = &mut self.rejected_modifications[point as usize];
                *rejected = rejected.saturating_add(1);
                log::debug!("{:?} hook: {}; dropping packet", point, reason);
                PacketHookOutcome::Drop
            }
        }
    }

    /// Load a WASM hook from `wasm_bytes` at `attach_point`.
    pub(crate) fn load_wasm(
        &mut self,
        name: String,
        wasm_bytes: &[u8],
        attach_point: &str,
        priority: i32,
    ) -> Result<(), HookOpError> {
        let point_idx = point_index(attach_point)?;
        let manager = self.manager.as_ref().ok_or(HookOpError::NoManager)?;
        let program = manager
            .compile(name.clone(), wasm_bytes, priority)
            .map_err(HookOpError::Compile)?;
        self.slots[point_idx].attach(program);
        log::info!(
            "Loaded hook '{}' at point {} (priority {})",
            name,
            attach_point,
            priority
        );
        Ok(())
    }

    /// Load a hook of type `hook_type` from the file at `path`.
    pub(crate) fn load_file(
        &mut self,
        name: String,
        path: &str,
        hook_type: &str,
        attach_point: &str,
        priority: i32,
    ) -> Result<(), HookOpError> {
        let point_idx = point_index(attach_point)?;
        let backend = parse_hook_backend(hook_type).map_err(HookOpError::Backend)?;
        let manager = self.manager.as_ref().ok_or(HookOpError::NoManager)?;
        let program = manager
            .load_file_backend(name.clone(), std::path::Path::new(path), priority, backend)
            .map_err(HookOpError::Load)?;
        self.slots[point_idx].attach(program);
        log::info!(
            "Loaded {} hook '{}' at point {} (priority {})",
            backend.as_str(),
            name,
            attach_point,
            priority
        );
        Ok(())
    }

    /// Load the built-in hook registered as `builtin_id`.
    pub(crate) fn load_builtin(
        &mut self,
        name: String,
        builtin_id: &str,
        attach_point: &str,
        priority: i32,
    ) -> Result<(), HookOpError> {
        let point_idx = point_index(attach_point)?;
        let manager = self.manager.as_ref().ok_or(HookOpError::NoManager)?;
        let program = manager
            .load_builtin(name.clone(), builtin_id, priority)
            .map_err(HookOpError::Load)?;
        self.slots[point_idx].attach(program);
        log::info!(
            "Loaded built-in hook '{}' ({}) at point {} (priority {})",
            name,
            builtin_id,
            attach_point,
            priority
        );
        Ok(())
    }

    /// Detach the hook `name` from `attach_point`.
    pub(crate) fn unload(&mut self, name: &str, attach_point: &str) -> Result<(), HookOpError> {
        let point_idx = point_index(attach_point)?;
        match self.slots[point_idx].detach(name) {
            Some(_) => {
                log::info!("Unloaded hook '{}' from point {}", name, attach_point);
                Ok(())
            }
            None => Err(not_found(name, attach_point)),
        }
    }

    /// Replace the hook `name` at `attach_point` with one compiled from
    /// `wasm_bytes`, at the same priority.
    pub(crate) fn reload_wasm(
        &mut self,
        name: &str,
        attach_point: &str,
        wasm_bytes: &[u8],
    ) -> Result<(), HookOpError> {
        let (priority, ()) = self.replace_program(name, attach_point, |manager, priority| {
            let manager = manager.ok_or(HookOpError::NoManager)?;
            let program = manager
                .compile(name.to_string(), wasm_bytes, priority)
                .map_err(HookOpError::Compile)?;
            Ok((program, ()))
        })?;
        log::info!(
            "Reloaded hook '{}' at point {} (priority {})",
            name,
            attach_point,
            priority
        );
        Ok(())
    }

    /// Replace the hook `name` at `attach_point` with one of type
    /// `hook_type` loaded from `path`, at the same priority.
    pub(crate) fn reload_file(
        &mut self,
        name: &str,
        attach_point: &str,
        path: &str,
        hook_type: &str,
    ) -> Result<(), HookOpError> {
        let (priority, backend) =
            self.replace_program(name, attach_point, |manager, priority| {
                let backend = parse_hook_backend(hook_type).map_err(HookOpError::Backend)?;
                let manager = manager.ok_or(HookOpError::NoManager)?;
                let program = manager
                    .load_file_backend(
                        name.to_string(),
                        std::path::Path::new(path),
                        priority,
                        backend,
                    )
                    .map_err(HookOpError::Load)?;
                Ok((program, backend))
            })?;
        log::info!(
            "Reloaded {} hook '{}' at point {} (priority {})",
            backend.as_str(),
            name,
            attach_point,
            priority
        );
        Ok(())
    }

    /// Replace the hook `name` at `attach_point` with the built-in hook
    /// registered as `builtin_id`, at the same priority.
    pub(crate) fn reload_builtin(
        &mut self,
        name: &str,
        attach_point: &str,
        builtin_id: &str,
    ) -> Result<(), HookOpError> {
        let (priority, ()) = self.replace_program(name, attach_point, |manager, priority| {
            let manager = manager.ok_or(HookOpError::NoManager)?;
            let program = manager
                .load_builtin(name.to_string(), builtin_id, priority)
                .map_err(HookOpError::Load)?;
            Ok((program, ()))
        })?;
        log::info!(
            "Reloaded built-in hook '{}' ({}) at point {} (priority {})",
            name,
            builtin_id,
            attach_point,
            priority
        );
        Ok(())
    }

    /// Enable or disable the hook `name` at `attach_point`.
    pub(crate) fn set_enabled(
        &mut self,
        name: &str,
        attach_point: &str,
        enabled: bool,
    ) -> Result<(), HookOpError> {
        self.program_mut(name, attach_point)?.1.enabled = enabled;
        log::info!(
            "{} hook '{}' at point {}",
            if enabled { "Enabled" } else { "Disabled" },
            name,
            attach_point,
        );
        Ok(())
    }

    /// Give the hook `name` at `attach_point` a new priority.
    pub(crate) fn set_priority(
        &mut self,
        name: &str,
        attach_point: &str,
        priority: i32,
    ) -> Result<(), HookOpError> {
        let (point_idx, program) = self.program_mut(name, attach_point)?;
        program.priority = priority;
        self.slots[point_idx]
            .programs
            .sort_by_key(|program| std::cmp::Reverse(program.priority));
        log::info!(
            "Updated hook '{}' at point {} to priority {}",
            name,
            attach_point,
            priority,
        );
        Ok(())
    }

    /// Every attached hook, by hook point and in run order.
    pub(crate) fn list(&self) -> Vec<HookInfo> {
        let mut infos = Vec::new();
        for (point_name, slot) in HOOK_POINT_NAMES.iter().zip(&self.slots) {
            for program in &slot.programs {
                infos.push(HookInfo {
                    name: program.name.clone(),
                    hook_type: program.backend_name().to_string(),
                    attach_point: point_name.to_string(),
                    priority: program.priority,
                    enabled: program.enabled,
                    consecutive_traps: program.consecutive_traps,
                });
            }
        }
        infos
    }

    /// Load the enabled hooks of the config, skipping, with a warning or an
    /// error, those that cannot be loaded.
    pub(crate) fn load_configured(&mut self, hooks: &[ParsedHook]) {
        for hook_cfg in hooks {
            if !hook_cfg.enabled {
                continue;
            }
            let point_idx = match parse_hook_point(&hook_cfg.attach_point) {
                Some(idx) => idx,
                None => {
                    log::warn!(
                        "Unknown hook point '{}' for hook '{}'",
                        hook_cfg.attach_point,
                        hook_cfg.name,
                    );
                    continue;
                }
            };
            let Some(manager) = self.manager.as_ref() else {
                log::warn!(
                    "Hook manager not available, skipping hook '{}'",
                    hook_cfg.name
                );
                continue;
            };
            let hook_backend = match parse_hook_backend(&hook_cfg.hook_type) {
                Ok(backend) => backend,
                Err(e) => {
                    log::warn!(
                        "Invalid hook type '{}' for hook '{}': {}",
                        hook_cfg.hook_type,
                        hook_cfg.name,
                        e,
                    );
                    continue;
                }
            };
            let load_result = if hook_backend == HookBackend::Builtin {
                let builtin_id = hook_cfg
                    .builtin_id
                    .as_deref()
                    .filter(|id| !id.is_empty())
                    .or_else(|| (!hook_cfg.path.is_empty()).then_some(hook_cfg.path.as_str()));
                match builtin_id {
                    Some(id) => manager.load_builtin(hook_cfg.name.clone(), id, hook_cfg.priority),
                    None => Err(HookError::CompileError(
                        "built-in hook requires builtin/id or path".to_string(),
                    )),
                }
            } else {
                manager.load_file_backend(
                    hook_cfg.name.clone(),
                    std::path::Path::new(&hook_cfg.path),
                    hook_cfg.priority,
                    hook_backend,
                )
            };
            match load_result {
                Ok(program) => {
                    self.slots[point_idx].attach(program);
                    log::info!(
                        "Loaded hook '{}' at point {} (priority {})",
                        hook_cfg.name,
                        hook_cfg.attach_point,
                        hook_cfg.priority,
                    );
                }
                Err(e) => {
                    log::error!(
                        "Failed to load hook '{}' from '{}': {}",
                        hook_cfg.name,
                        hook_cfg.path,
                        e,
                    );
                }
            }
        }
    }

    /// Serve the provider bridge's sockets the driver poller reported ready.
    pub(crate) fn serve_provider_bridge(&self, ready: &crate::poll::Events) {
        if let Some(bridge) = &self.provider_bridge {
            bridge.serve(ready);
        }
    }

    /// Make the provider bridge stop taking new consumers.
    pub(crate) fn stop_provider_bridge(&self) {
        if let Some(bridge) = self.provider_bridge.as_ref() {
            bridge.stop_accepting();
        }
    }

    /// The provider bridge's statistics, when it runs.
    pub(crate) fn provider_bridge_stats(&self) -> Option<ProviderBridgeStats> {
        self.provider_bridge.as_ref().map(|bridge| bridge.stats())
    }

    /// Events the provider bridge holds: in its backlog, and queued for its
    /// consumers.
    pub(crate) fn provider_queued_events(&self) -> (usize, usize) {
        self.provider_bridge
            .as_ref()
            .map(|bridge| {
                let stats = bridge.stats();
                (
                    stats.backlog_len,
                    stats
                        .consumers
                        .iter()
                        .map(|consumer| consumer.queue_len)
                        .sum(),
                )
            })
            .unwrap_or((0, 0))
    }

    /// Detach the hook `name` from `attach_point` and attach what `load`
    /// makes at its priority in its place, putting the old hook back if
    /// `load` fails. Returns the priority and what `load` returned with the
    /// program.
    fn replace_program<T>(
        &mut self,
        name: &str,
        attach_point: &str,
        load: impl FnOnce(Option<&HookManager>, i32) -> Result<(LoadedProgram, T), HookOpError>,
    ) -> Result<(i32, T), HookOpError> {
        let point_idx = point_index(attach_point)?;
        let old = self.slots[point_idx]
            .detach(name)
            .ok_or_else(|| not_found(name, attach_point))?;
        let priority = old.priority;
        match load(self.manager.as_ref(), priority) {
            Ok((program, loaded)) => {
                self.slots[point_idx].attach(program);
                Ok((priority, loaded))
            }
            Err(error) => {
                self.slots[point_idx].attach(old);
                Err(error)
            }
        }
    }

    /// The hook `name` at `attach_point`, with the index of its hook point.
    fn program_mut(
        &mut self,
        name: &str,
        attach_point: &str,
    ) -> Result<(usize, &mut LoadedProgram), HookOpError> {
        let point_idx = point_index(attach_point)?;
        let program = self.slots[point_idx]
            .programs
            .iter_mut()
            .find(|program| program.name == name)
            .ok_or_else(|| not_found(name, attach_point))?;
        Ok((point_idx, program))
    }
}

/// The index of the hook point named `attach_point`.
fn point_index(attach_point: &str) -> Result<usize, HookOpError> {
    parse_hook_point(attach_point).ok_or_else(|| HookOpError::UnknownPoint(attach_point.into()))
}

fn not_found(name: &str, attach_point: &str) -> HookOpError {
    HookOpError::NotFound {
        name: name.to_string(),
        point: attach_point.to_string(),
    }
}

/// [`EngineAccess`] over the driver state hooks may read.
struct EngineRef<'a> {
    env: &'a HookEnv<'a>,
    now: f64,
}

impl EngineAccess for EngineRef<'_> {
    fn has_path(&self, dest: &[u8; 16]) -> bool {
        self.env.engine.has_path(dest)
    }
    fn hops_to(&self, dest: &[u8; 16]) -> Option<u8> {
        self.env.engine.hops_to(dest)
    }
    fn next_hop(&self, dest: &[u8; 16]) -> Option<[u8; 16]> {
        self.env.engine.next_hop(dest)
    }
    fn is_blackholed(&self, identity: &[u8; 16]) -> bool {
        self.env.engine.is_blackholed(identity, self.now)
    }
    fn interface_name(&self, id: u64) -> Option<String> {
        self.env
            .interfaces
            .get(&InterfaceId(id))
            .map(|e| e.info.name.clone())
    }
    fn interface_mode(&self, id: u64) -> Option<u8> {
        self.env
            .interfaces
            .get(&InterfaceId(id))
            .map(|e| e.info.mode)
    }
    fn identity_hash(&self) -> Option<[u8; 16]> {
        self.env.engine.identity_hash().copied()
    }
    fn announce_rate(&self, id: u64) -> Option<i32> {
        self.env
            .interfaces
            .get(&InterfaceId(id))
            .map(|e| (e.stats.outgoing_announce_freq(time::now()) * 1000.0) as i32)
    }
    fn link_state(&self, link_hash: &[u8; 16]) -> Option<u8> {
        use rns_core::link::types::LinkState;
        self.env
            .link_manager
            .link_state(link_hash)
            .map(|s| match s {
                LinkState::Pending => 0,
                LinkState::Handshake => 1,
                LinkState::Active => 2,
                LinkState::Stale => 3,
                LinkState::Closed => 4,
            })
    }
}

/// Validate replacement bytes from a `Modify` verdict: they must be non-empty,
/// fit within `max_len`, and decode as a packet.
fn validate_hook_replacement(data: &[u8], max_len: usize) -> Result<RawPacket, &'static str> {
    if data.is_empty() {
        return Err("replacement is empty");
    }
    if data.len() > max_len {
        return Err("replacement exceeds the packet size limit");
    }
    RawPacket::unpack(data).map_err(|_| "replacement does not decode as a packet")
}

/// Convert the actions hooks injected into transport actions.
fn convert_injected_actions(actions: Vec<ActionWire>) -> Vec<TransportAction> {
    actions
        .into_iter()
        .map(|a| match a {
            ActionWire::SendOnInterface { interface, raw } => TransportAction::SendOnInterface {
                interface: InterfaceId(interface),
                raw: raw.into(),
            },
            ActionWire::BroadcastOnAllInterfaces {
                raw,
                exclude,
                has_exclude,
            } => TransportAction::BroadcastOnAllInterfaces {
                raw: raw.into(),
                exclude: if has_exclude != 0 {
                    Some(InterfaceId(exclude))
                } else {
                    None
                },
            },
            ActionWire::DeliverLocal {
                destination_hash,
                raw,
                packet_hash,
                receiving_interface,
            } => TransportAction::DeliverLocal {
                destination_hash,
                raw: raw.into(),
                packet_hash,
                receiving_interface: InterfaceId(receiving_interface),
            },
            ActionWire::PathUpdated {
                destination_hash,
                hops,
                next_hop,
                interface,
            } => TransportAction::PathUpdated {
                destination_hash,
                hops,
                next_hop,
                interface: InterfaceId(interface),
            },
            ActionWire::CacheAnnounce { packet_hash, raw } => TransportAction::CacheAnnounce {
                packet_hash,
                raw: raw.into(),
            },
            ActionWire::TunnelEstablished {
                tunnel_id,
                interface,
            } => TransportAction::TunnelEstablished {
                tunnel_id,
                interface: InterfaceId(interface),
            },
            ActionWire::TunnelSynthesize {
                interface,
                data,
                dest_hash,
            } => TransportAction::TunnelSynthesize {
                interface: InterfaceId(interface),
                data,
                dest_hash,
            },
            ActionWire::ForwardToLocalClients {
                raw,
                exclude,
                has_exclude,
            } => TransportAction::ForwardToLocalClients {
                raw: raw.into(),
                exclude: if has_exclude != 0 {
                    Some(InterfaceId(exclude))
                } else {
                    None
                },
            },
            ActionWire::ForwardPlainBroadcast {
                raw,
                to_local,
                exclude,
                has_exclude,
            } => TransportAction::ForwardPlainBroadcast {
                raw: raw.into(),
                to_local: to_local != 0,
                exclude: if has_exclude != 0 {
                    Some(InterfaceId(exclude))
                } else {
                    None
                },
            },
            ActionWire::AnnounceReceived {
                destination_hash,
                identity_hash,
                public_key,
                name_hash,
                random_hash,
                app_data,
                hops,
                receiving_interface,
            } => TransportAction::AnnounceReceived(Box::new(ReceivedAnnounce {
                // A hook-injected announce came in no packet.
                packet_hash: [0u8; 32],
                destination_hash,
                identity_hash,
                public_key,
                name_hash,
                random_hash,
                ratchet: None,
                app_data,
                stamp: None,
                stamp_value: rns_core::stamp::StampValue::ZERO,
                lr_cost: None,
                hops,
                receiving_interface: InterfaceId(receiving_interface),
                rx: rns_core::transport::RxMetadata::default(),
            })),
        })
        .collect()
}
