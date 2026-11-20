//! Interfaces coming up, going down and reporting telemetry.

use super::*;

impl Driver {
    pub(crate) fn handle_interface_up_event(
        &mut self,
        id: InterfaceId,
        new_writer: Option<Box<dyn crate::interface::Writer>>,
        info: Option<rns_core::transport::types::InterfaceInfo>,
    ) {
        self.housekeeping.state_snapshot_schedule.mark_dirty();
        let wants_tunnel;
        let mut came_up = false;
        let mut replay_shared_announces = false;
        if let Some(info) = info {
            wants_tunnel = self.register_dynamic_interface(id, new_writer, info, true);
            came_up = true;
        } else {
            let is_local_client = self
                .interfaces
                .get(&id)
                .map(|entry| entry.info.is_local_client)
                .unwrap_or(false);
            // A shared client announces its destinations whenever its
            // connection to the instance comes up, the first one included:
            // the announce of a destination registered before the interface
            // was online was dropped.
            let coming_online = self.connected_to_shared_instance
                && self.interfaces.get(&id).is_some_and(|entry| !entry.online);
            replay_shared_announces = is_local_client
                && (self.shared_reconnect_pending.remove(&id).unwrap_or(false) || coming_online);
            let interface_name = self
                .interfaces
                .get(&id)
                .map(|entry| entry.info.name.clone())
                .unwrap_or_else(|| format!("iface-{}", id.0));
            let wrapped_writer =
                new_writer.map(|writer| self.wrap_interface_writer(id, &interface_name, writer));
            // A dynamic interface kept while it reconnected counts with
            // its parent again.
            if let Some(parent_id) = self.dynamic_interface_parents.get(&id) {
                self.event_tx.register_dynamic_parent(id, *parent_id);
            }
            if let Some(entry) = self.interfaces.get_mut(&id) {
                // Upstream logs no such line.
                log::debug!("[{}] interface online", id.0);
                wants_tunnel = entry.info.wants_tunnel;
                entry.online = true;
                if let Some((writer, async_writer_metrics)) = wrapped_writer {
                    log::info!("[{}] writer refreshed after reconnect", id.0);
                    entry.writer = writer;
                    entry.async_writer_metrics = Some(async_writer_metrics);
                }
                came_up = true;
            } else {
                wants_tunnel = false;
            }
        }

        // Upstream f361a354 and ad6c709e synthesize on connect, before the
        // interface is online, so the synthesis is the first frame on the
        // connection. Here it is sent before anything else can use the
        // interface: before the callback and the `InterfaceUp` hook, whose
        // injected actions are dispatched at once.
        if wants_tunnel {
            // Upstream b7a93b9b: a dialing interface starts each connection
            // with no remote transport and no synthesis received.
            self.engine.reset_tunnel_synthesis(id);
            self.synthesize_tunnel_for_interface(id);
        }
        if came_up {
            self.notify_interface_up(id);
        }
        if replay_shared_announces {
            self.replay_shared_announces();
        }
    }

    /// Tell the application callback and the `InterfaceUp` hook that an
    /// interface came up.
    pub(super) fn notify_interface_up(&mut self, id: InterfaceId) {
        self.callbacks.on_interface_up(id);
        #[cfg(feature = "hooks")]
        {
            let ctx = HookContext::Interface { interface_id: id.0 };
            let now = time::now();
            let engine_ref = EngineRef {
                engine: &self.engine,
                interfaces: &self.interfaces,
                link_manager: &self.link_manager,
                now,
            };
            let provider_events_enabled = self.provider_events_enabled();
            if let Some(ref e) = run_hook_inner(
                &mut self.hooks.slots[HookPoint::InterfaceUp as usize].programs,
                &self.hooks.manager,
                &engine_ref,
                &ctx,
                now,
                provider_events_enabled,
            ) {
                self.forward_hook_side_effects("InterfaceUp", e);
            }
        }
    }

    /// Register a new dynamic interface, with its entry when it has a
    /// writer, `online` or not. Returns whether it wants a tunnel.
    pub(super) fn register_dynamic_interface(
        &mut self,
        id: InterfaceId,
        new_writer: Option<Box<dyn crate::interface::Writer>>,
        mut info: rns_core::transport::types::InterfaceInfo,
        online: bool,
    ) -> bool {
        log::debug!("[{}] dynamic interface registered", id.0);
        if info.is_local_client {
            if let Some(bitrate) = self.forced_local_bitrate {
                info.bitrate = Some(bitrate);
            }
        }
        self.apply_interface_announce_limits(&mut info);
        self.apply_announce_rate_defaults(&mut info);
        self.apply_ingress_control_defaults(&mut info);
        let wants_tunnel = info.wants_tunnel;
        let iface_type = infer_interface_type(&info.name);
        info.started = time::now();
        self.register_interface_runtime_defaults(&info);
        self.engine.register_interface(info.clone());
        if let Some(writer) = new_writer {
            #[cfg(feature = "iface-local")]
            if info.is_local_client {
                self.name_local_client(id);
            }
            let (writer, async_writer_metrics) = self.wrap_interface_writer(id, &info.name, writer);
            self.interfaces.insert(
                id,
                InterfaceEntry {
                    id,
                    info,
                    writer,
                    async_writer_metrics: Some(async_writer_metrics),
                    enabled: true,
                    online,
                    dynamic: true,
                    ifac: None,
                    stats: InterfaceStats {
                        started: time::now(),
                        ..Default::default()
                    },
                    interface_type: iface_type,
                    send_retry_at: None,
                    send_retry_backoff: Duration::ZERO,
                },
            );
        }
        wants_tunnel
    }

    pub(crate) fn handle_dynamic_interface_up_event(
        &mut self,
        id: InterfaceId,
        writer: Box<dyn crate::interface::Writer>,
        mut registration: crate::event::DynamicInterfaceRegistration,
    ) {
        self.housekeeping.state_snapshot_schedule.mark_dirty();
        let parent_id = registration.parent_id;
        if self.retired_interface_parents.contains(&parent_id) {
            return;
        }
        let parent_ifac = self.interfaces.get(&parent_id).and_then(|parent| {
            registration.info.mode = parent.info.mode;
            registration.info.gravity = parent.info.gravity;
            registration.info.recursive_prs = parent.info.recursive_prs;
            registration.info.announces_from_internal = parent.info.announces_from_internal;
            registration.info.announces_to_internal = parent.info.announces_to_internal;
            registration.info.announce_rate_target = parent.info.announce_rate_target;
            registration.info.announce_rate_grace = parent.info.announce_rate_grace;
            registration.info.announce_rate_penalty = parent.info.announce_rate_penalty;
            registration.info.announce_cap = parent.info.announce_cap;
            registration.info.ingress_control = parent.info.ingress_control;
            registration.info.stamp_costs = parent.info.stamp_costs;
            parent.ifac.clone()
        });
        let inherited_ifac = registration.ifac.take().or(parent_ifac);

        let interface_type = registration.interface_type;
        let telemetry = registration.telemetry;
        let display_name = registration.display_name;
        let short_name = registration.short_name;
        let reconnecting = registration.reconnecting;
        if reconnecting {
            // Offline until it connects, so not up yet.
            self.register_dynamic_interface(id, Some(writer), registration.info, false);
        } else {
            self.handle_interface_up_event(id, Some(writer), Some(registration.info));
        }
        if let Some(entry) = self.interfaces.get_mut(&id) {
            // Kept, offline, when it goes down.
            entry.dynamic = !reconnecting;
            if let Some(display_name) = display_name {
                self.interface_display_names.insert(id, display_name);
            }
            if let Some(short_name) = short_name {
                self.interface_short_names.insert(id, short_name);
            }
            self.dynamic_interface_parents.insert(id, parent_id);
            self.event_tx.register_dynamic_parent(id, parent_id);
            entry.interface_type = interface_type;
            entry.ifac = inherited_ifac;
            Self::apply_interface_telemetry(entry, telemetry);
        }
    }

    pub(super) fn apply_interface_telemetry(
        entry: &mut crate::interface::InterfaceEntry,
        telemetry: crate::event::InterfaceTelemetry,
    ) {
        entry.stats.cpu_load = telemetry.cpu_load;
        entry.stats.mem_load = telemetry.mem_load;
        entry.stats.switch_id = telemetry.switch_id;
        entry.stats.endpoint_id = telemetry.endpoint_id;
        entry.stats.via_switch_id = telemetry.via_switch_id;
        entry.stats.peers = telemetry.peers;
        if telemetry.rssi.is_some() {
            entry.stats.rssi = telemetry.rssi;
        }
        if telemetry.snr.is_some() {
            entry.stats.snr = telemetry.snr;
        }
        if telemetry.signal_quality.is_some() {
            entry.stats.signal_quality = telemetry.signal_quality;
        }
        if telemetry.frequency.is_some() {
            entry.stats.frequency = telemetry.frequency;
        }
        if telemetry.bandwidth.is_some() {
            entry.stats.bandwidth = telemetry.bandwidth;
        }
        if telemetry.txpower.is_some() {
            entry.stats.txpower = telemetry.txpower;
        }
        if telemetry.spreading_factor.is_some() {
            entry.stats.spreading_factor = telemetry.spreading_factor;
        }
        if telemetry.coding_rate.is_some() {
            entry.stats.coding_rate = telemetry.coding_rate;
        }
        if telemetry.channel.is_some() {
            entry.stats.channel = telemetry.channel;
        }
        if telemetry.radio.is_some() {
            entry.stats.radio = telemetry.radio;
        }
        if telemetry.modulation.is_some() {
            entry.stats.modulation = telemetry.modulation;
        }
    }

    pub(crate) fn handle_interface_telemetry_event(
        &mut self,
        interface_id: InterfaceId,
        telemetry: crate::event::InterfaceTelemetry,
    ) {
        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
            Self::apply_interface_telemetry(entry, telemetry);
        }
    }

    pub(crate) fn handle_interface_down_event(&mut self, id: InterfaceId) {
        self.housekeeping.state_snapshot_schedule.mark_dirty();
        let lost_direct = self.holepunch_manager.direct_interface_down(id);
        self.event_tx.remove_interface(id);
        if let Some(entry) = self.interfaces.get(&id) {
            if let Some(tunnel_id) = entry.info.tunnel_id {
                // A removed dynamic interface starts the tunnel's reconnect
                // window, as upstream's cull does for an interface no longer
                // in Transport.interfaces; a static one only goes offline.
                if entry.dynamic {
                    self.engine
                        .release_tunnel_interface(&tunnel_id, time::now());
                } else {
                    self.engine.void_tunnel_interface(&tunnel_id);
                }
            }
        }

        if let Some(entry) = self.interfaces.get(&id) {
            let is_dynamic = entry.dynamic;
            let is_local_client = entry.info.is_local_client;
            let interface_name = entry.info.name.clone();
            if is_dynamic {
                log::info!("[{}] dynamic interface removed", id.0);
                self.runtime_config
                    .interface_defaults
                    .remove(&interface_name);
                self.engine.deregister_interface(id);
                self.interfaces.remove(&id);
                self.dynamic_interface_parents.remove(&id);
                self.interface_display_names.remove(&id);
                self.interface_short_names.remove(&id);
            } else {
                log::info!("[{}] interface offline", id.0);
                if let Some(entry) = self.interfaces.get_mut(&id) {
                    entry.online = false;
                } else {
                    log::warn!(
                        "interface {} disappeared while handling interface-down",
                        id.0
                    );
                    return;
                }
                if is_local_client {
                    self.handle_shared_interface_down(id);
                }
            }
            self.callbacks.on_interface_down(id);
            #[cfg(feature = "hooks")]
            {
                let ctx = HookContext::Interface { interface_id: id.0 };
                let now = time::now();
                let engine_ref = EngineRef {
                    engine: &self.engine,
                    interfaces: &self.interfaces,
                    link_manager: &self.link_manager,
                    now,
                };
                let provider_events_enabled = self.provider_events_enabled();
                if let Some(ref e) = run_hook_inner(
                    &mut self.hooks.slots[HookPoint::InterfaceDown as usize].programs,
                    &self.hooks.manager,
                    &engine_ref,
                    &ctx,
                    now,
                    provider_events_enabled,
                ) {
                    self.forward_hook_side_effects("InterfaceDown", e);
                }
            }
        }
        #[cfg(feature = "iface-backbone")]
        self.handle_backbone_peer_pool_down(id);
        if let Some((link_id, session_id)) = lost_direct {
            log::info!(
                "[{}] direct interface of link {:02x?} went down; falling back",
                id.0,
                &link_id[..4]
            );
            self.direct_path_lost(link_id, id, Some(session_id), true);
        }
    }
}
