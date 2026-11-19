//! Calling hooks from the driver and forwarding their side effects.

use super::*;
#[cfg(feature = "hooks")]
use crate::event::HookOpError;

impl Driver {
    #[cfg(feature = "hooks")]
    pub(super) fn provider_events_enabled(&self) -> bool {
        self.provider_bridge.is_some()
    }

    /// Whether any program is attached at `point`. Per-packet hook points
    /// check this before building a hook context, which reads the clock.
    #[cfg(feature = "hooks")]
    pub(crate) fn hooks_attached(&self, point: HookPoint) -> bool {
        !self.hook_slots[point as usize].programs.is_empty()
    }

    #[cfg(feature = "hooks")]
    pub(super) fn run_backbone_peer_hook(
        &mut self,
        attach_point: &str,
        point: HookPoint,
        event: &BackbonePeerHookEvent,
    ) {
        let ctx = backbone_peer_hook_context(event);
        let now = time::now();
        let engine_ref = EngineRef {
            engine: &self.engine,
            interfaces: &self.interfaces,
            link_manager: &self.link_manager,
            now,
        };
        let provider_events_enabled = self.provider_events_enabled();
        if let Some(ref e) = run_hook_inner(
            &mut self.hook_slots[point as usize].programs,
            &self.hook_manager,
            &engine_ref,
            &ctx,
            now,
            provider_events_enabled,
        ) {
            self.forward_hook_side_effects(attach_point, e);
        }
    }

    #[cfg(feature = "hooks")]
    pub(super) fn update_hook_program<F>(
        &mut self,
        name: &str,
        attach_point: &str,
        mut update: F,
    ) -> Result<(), HookOpError>
    where
        F: FnMut(&mut rns_hooks::LoadedProgram),
    {
        let point_idx = crate::config::parse_hook_point(attach_point)
            .ok_or_else(|| HookOpError::UnknownPoint(attach_point.to_string()))?;
        let program = self.hook_slots[point_idx]
            .programs
            .iter_mut()
            .find(|program| program.name == name)
            .ok_or_else(|| HookOpError::NotFound {
                name: name.to_string(),
                point: attach_point.to_string(),
            })?;
        update(program);
        Ok(())
    }

    /// Turn a packet hook chain result into the action the hook point takes.
    ///
    /// `Drop` stops the packet. `Modify` with replacement bytes is validated
    /// against `max_len` and the packet decoder; a replacement that fails
    /// validation is treated as `Drop` and counted in
    /// `hook_rejected_modifications`. `Modify` without bytes, `Continue` and
    /// `Halt` keep the current bytes.
    #[cfg(feature = "hooks")]
    pub(crate) fn packet_hook_outcome(
        &mut self,
        point: HookPoint,
        exec: &rns_hooks::ExecuteResult,
        max_len: usize,
    ) -> PacketHookOutcome {
        let Some(result) = exec.hook_result.as_ref() else {
            return PacketHookOutcome::Keep;
        };
        if result.is_drop() {
            return PacketHookOutcome::Drop;
        }
        if rns_hooks::Verdict::from_u32(result.verdict) != Some(rns_hooks::Verdict::Modify) {
            return PacketHookOutcome::Keep;
        }
        let Some(data) = exec.modified_data.as_deref() else {
            return PacketHookOutcome::Keep;
        };
        match validate_hook_replacement(data, max_len) {
            Ok(packet) => PacketHookOutcome::Replace(packet),
            Err(reason) => {
                let rejected = &mut self.hook_rejected_modifications[point as usize];
                *rejected = rejected.saturating_add(1);
                log::debug!("{:?} hook: {}; dropping packet", point, reason);
                PacketHookOutcome::Drop
            }
        }
    }

    /// Largest packet a hook may substitute for one handled on `interface`.
    #[cfg(feature = "hooks")]
    pub(crate) fn hook_packet_limit(&self, interface: InterfaceId) -> usize {
        self.interfaces
            .get(&interface)
            .map(|entry| entry.info.mtu as usize)
            .filter(|mtu| *mtu > 0)
            .unwrap_or(rns_core::constants::MTU)
    }

    /// Point a pending confirmed link send at the replacement bytes a hook
    /// produced for the packet it was tracking.
    #[cfg(feature = "hooks")]
    pub(crate) fn retarget_tracked_link_send(&mut self, original: &[u8], replacement: &RawPacket) {
        let Some((hash, _)) = self.tracked_link_send.as_mut() else {
            return;
        };
        if RawPacket::unpack(original).is_ok_and(|packet| packet.packet_hash == *hash) {
            *hash = replacement.packet_hash;
        }
    }

    #[cfg(feature = "hooks")]
    pub(super) fn forward_hook_side_effects(
        &mut self,
        attach_point: &str,
        exec: &rns_hooks::ExecuteResult,
    ) {
        if !exec.injected_actions.is_empty() {
            self.dispatch_all(convert_injected_actions(exec.injected_actions.clone()));
        }
        if let Some(ref bridge) = self.provider_bridge {
            for event in &exec.provider_events {
                bridge.emit_event(
                    attach_point,
                    event.hook_name.clone(),
                    event.payload_type.clone(),
                    event.payload.clone(),
                );
            }
        }
    }

    #[cfg(feature = "hooks")]
    pub(super) fn collect_hook_side_effects(
        &mut self,
        attach_point: &str,
        exec: &rns_hooks::ExecuteResult,
        out: &mut Vec<TransportAction>,
    ) {
        if !exec.injected_actions.is_empty() {
            out.extend(convert_injected_actions(exec.injected_actions.clone()));
        }
        if let Some(ref bridge) = self.provider_bridge {
            for event in &exec.provider_events {
                bridge.emit_event(
                    attach_point,
                    event.hook_name.clone(),
                    event.payload_type.clone(),
                    event.payload.clone(),
                );
            }
        }
    }
}
