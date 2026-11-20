//! Calling hooks from the driver and carrying out what they inject.

use super::*;

impl Driver {
    /// Run the hooks attached at `point` on `event`.
    #[inline]
    pub(super) fn run_hooks(&mut self, point: HookPoint, event: &HookEvent<'_>) -> Option<HookRun> {
        let env = HookEnv {
            engine: &self.engine,
            interfaces: &self.interfaces,
            link_manager: &self.link_manager,
        };
        self.hooks.run(point, event, &env)
    }

    /// Run the hooks attached at `point` on `event` and carry out their side
    /// effects. Returns whether a hook dropped what the hook point handles.
    #[inline]
    pub(super) fn run_hooks_with_effects(
        &mut self,
        point: HookPoint,
        event: &HookEvent<'_>,
        injected: InjectedActions<'_>,
    ) -> bool {
        match self.run_hooks(point, event) {
            Some(mut run) => {
                self.apply_hook_effects(point, &mut run, injected);
                run.dropped()
            }
            None => false,
        }
    }

    /// Run the packet hooks attached at `point` on `event`, carry out their
    /// side effects, and decide what happens to the packet. A replacement
    /// may be at most `max_len` bytes long.
    #[inline]
    pub(super) fn run_packet_hooks(
        &mut self,
        point: HookPoint,
        event: &HookEvent<'_>,
        injected: InjectedActions<'_>,
        max_len: impl FnOnce(&Self) -> usize,
    ) -> PacketHookOutcome {
        let Some(mut run) = self.run_hooks(point, event) else {
            return PacketHookOutcome::Keep;
        };
        self.apply_hook_effects(point, &mut run, injected);
        let max_len = max_len(self);
        self.hooks.packet_outcome(point, &run, max_len)
    }

    /// Carry out what the hooks of `run` asked for: the actions they
    /// injected, then the events they emitted for the provider bridge.
    fn apply_hook_effects(
        &mut self,
        point: HookPoint,
        run: &mut HookRun,
        injected: InjectedActions<'_>,
    ) {
        let actions = run.take_injected();
        match injected {
            InjectedActions::Dispatch => {
                if !actions.is_empty() {
                    self.dispatch_all(actions);
                }
            }
            InjectedActions::Collect(out) => out.extend(actions),
        }
        self.hooks.emit_provider_events(point, run);
    }

    /// Run the hook attached to a Backbone peer event (connected,
    /// disconnected, idle timeout, write stall, penalty).
    pub(super) fn handle_backbone_peer_event(&mut self, event: &Event) {
        if let Some((point, peer)) = backbone_peer_hook(event) {
            self.run_hooks_with_effects(
                point,
                &HookEvent::BackbonePeer(&peer),
                InjectedActions::Dispatch,
            );
        }
    }

    /// Largest packet a hook may substitute for one handled on `interface`.
    pub(crate) fn hook_packet_limit(&self, interface: InterfaceId) -> usize {
        self.interfaces
            .get(&interface)
            .map(|entry| entry.info.mtu as usize)
            .filter(|mtu| *mtu > 0)
            .unwrap_or(rns_core::constants::MTU)
    }

    /// Point a pending confirmed link send at the replacement bytes a hook
    /// produced for the packet it was tracking.
    pub(crate) fn retarget_tracked_link_send(&mut self, original: &[u8], replacement: &RawPacket) {
        let Some((hash, _)) = self.tracked_link_send.as_mut() else {
            return;
        };
        if RawPacket::unpack(original).is_ok_and(|packet| packet.packet_hash == *hash) {
            *hash = replacement.packet_hash;
        }
    }
}

/// The hook point a Backbone peer event runs and the peer it hands the
/// hook. `None` for other events.
fn backbone_peer_hook(event: &Event) -> Option<(HookPoint, BackbonePeerHookEvent)> {
    let peer = |server_interface_id, peer_interface_id, peer_ip, peer_port| BackbonePeerHookEvent {
        server_interface_id,
        peer_interface_id: Some(peer_interface_id),
        peer_ip,
        peer_port,
        connected_for: Duration::ZERO,
        had_received_data: false,
        penalty_level: 0,
        blacklist_for: Duration::ZERO,
    };
    Some(match *event {
        Event::BackbonePeerConnected {
            server_interface_id,
            peer_interface_id,
            peer_ip,
            peer_port,
        } => (
            HookPoint::BackbonePeerConnected,
            peer(server_interface_id, peer_interface_id, peer_ip, peer_port),
        ),
        Event::BackbonePeerDisconnected {
            server_interface_id,
            peer_interface_id,
            peer_ip,
            peer_port,
            connected_for,
            had_received_data,
        } => (
            HookPoint::BackbonePeerDisconnected,
            BackbonePeerHookEvent {
                connected_for,
                had_received_data,
                ..peer(server_interface_id, peer_interface_id, peer_ip, peer_port)
            },
        ),
        Event::BackbonePeerIdleTimeout {
            server_interface_id,
            peer_interface_id,
            peer_ip,
            peer_port,
            connected_for,
        } => (
            HookPoint::BackbonePeerIdleTimeout,
            BackbonePeerHookEvent {
                connected_for,
                ..peer(server_interface_id, peer_interface_id, peer_ip, peer_port)
            },
        ),
        Event::BackbonePeerWriteStall {
            server_interface_id,
            peer_interface_id,
            peer_ip,
            peer_port,
            connected_for,
        } => (
            HookPoint::BackbonePeerWriteStall,
            BackbonePeerHookEvent {
                connected_for,
                ..peer(server_interface_id, peer_interface_id, peer_ip, peer_port)
            },
        ),
        Event::BackbonePeerPenalty {
            server_interface_id,
            peer_ip,
            penalty_level,
            blacklist_for,
        } => (
            HookPoint::BackbonePeerPenalty,
            BackbonePeerHookEvent {
                server_interface_id,
                peer_interface_id: None,
                peer_ip,
                peer_port: 0,
                connected_for: Duration::ZERO,
                had_received_data: false,
                penalty_level,
                blacklist_for,
            },
        ),
        _ => return None,
    })
}
