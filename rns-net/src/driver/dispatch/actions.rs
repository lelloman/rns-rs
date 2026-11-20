//! Dispatching the transport engine's actions.

use super::*;

impl Driver {
    /// Dispatch a list of transport actions.
    pub(crate) fn dispatch_all(&mut self, actions: Vec<TransportAction>) {
        self.dispatch_all_with_ingress_class(actions, false);
    }

    pub(crate) fn dispatch_all_with_ingress_class(
        &mut self,
        actions: Vec<TransportAction>,
        ingress_limited: bool,
    ) {
        self.dispatch_actions_at_depth(actions, ingress_limited, 0);
    }

    /// Re-dispatch actions injected by hooks one nesting level below
    /// `depth`. Injected actions skip the per-action packet hooks
    /// (`SendOnInterface`, `BroadcastOnAllInterfaces`, `DeliverLocal`), and
    /// nesting through other hook points is capped at
    /// `MAX_HOOK_INJECTION_DEPTH`; anything beyond that is logged and dropped.
    #[cfg(feature = "hooks")]
    pub(super) fn dispatch_hook_injected(&mut self, injected: Vec<TransportAction>, depth: usize) {
        if injected.is_empty() {
            return;
        }
        if depth >= MAX_HOOK_INJECTION_DEPTH {
            log::warn!(
                "dropping {} hook-injected action(s): nesting depth limit {} reached",
                injected.len(),
                MAX_HOOK_INJECTION_DEPTH
            );
            return;
        }
        self.dispatch_actions_at_depth(injected, false, depth + 1);
    }

    /// Dispatch `actions`. `depth` is 0 for top-level actions and counts how
    /// many hook-injection levels deep the batch is otherwise; per-action
    /// packet hooks run only at depth 0.
    pub(super) fn dispatch_actions_at_depth(
        &mut self,
        mut actions: Vec<TransportAction>,
        ingress_limited: bool,
        depth: usize,
    ) {
        let run_packet_hooks = depth == 0;
        #[cfg(feature = "hooks")]
        let mut hook_injected: Vec<TransportAction> = Vec::new();
        #[cfg(not(feature = "hooks"))]
        let mut hook_injected: Vec<TransportAction> = Vec::new();

        for action in actions.drain(..) {
            match action {
                TransportAction::SendOnInterface { interface, raw } => {
                    self.dispatch_send_on_interface_action_with_hooks(
                        interface,
                        raw,
                        &mut hook_injected,
                        run_packet_hooks,
                    );
                }
                TransportAction::BroadcastOnAllInterfaces { raw, exclude } => {
                    self.dispatch_broadcast_action(
                        raw,
                        exclude,
                        &mut hook_injected,
                        run_packet_hooks,
                    );
                }
                TransportAction::DeliverLocal {
                    destination_hash,
                    raw,
                    packet_hash,
                    receiving_interface,
                } => {
                    self.dispatch_deliver_local_action(
                        destination_hash,
                        raw,
                        packet_hash,
                        receiving_interface,
                        ingress_limited,
                        &mut hook_injected,
                        run_packet_hooks,
                    );
                }
                TransportAction::AnnounceReceived(announce) => {
                    let ReceivedAnnounce {
                        destination_hash,
                        identity_hash,
                        public_key,
                        name_hash,
                        ratchet,
                        app_data,
                        stamp,
                        stamp_value,
                        lr_cost,
                        hops,
                        receiving_interface,
                        rx,
                        ..
                    } = *announce;
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Announce {
                            destination_hash,
                            hops,
                            interface_id: receiving_interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        {
                            let exec = run_hook_inner(
                                &mut self.hook_slots[HookPoint::AnnounceReceived as usize].programs,
                                &self.hook_manager,
                                &engine_ref,
                                &ctx,
                                now,
                                provider_events_enabled,
                            );
                            if let Some(ref e) = exec {
                                self.collect_hook_side_effects(
                                    "AnnounceReceived",
                                    e,
                                    &mut hook_injected,
                                );
                                if e.hook_result.as_ref().is_some_and(|r| r.is_drop()) {
                                    continue;
                                }
                            }
                        }
                    }

                    // Check if this is a discovery announce (matched by name_hash
                    // since discovery is a SINGLE destination — its dest hash varies
                    // with the sender's identity).
                    if name_hash == self.discovery_name_hash && self.discover_interfaces {
                        if !self.discovery_source_allowed(&identity_hash) {
                            log::debug!(
                                "Interface discovered from non-authorized network identity {:02x?}, ignoring",
                                &identity_hash[..4]
                            );
                        } else if let Some(ref app_data) = app_data {
                            if let Some(mut discovered) =
                                crate::discovery::parse_interface_announce_with_identity(
                                    app_data,
                                    &identity_hash,
                                    hops,
                                    self.discovery_required_value,
                                    &mut self.discovery_stamp_cache,
                                    self.network_identity.as_ref(),
                                    crate::time::now(),
                                )
                            {
                                crate::discovery::apply_transport_autoconnect_mode(
                                    &mut discovered,
                                    self.engine.transport_enabled(),
                                    self.autoconnect_interface_mode,
                                );
                                if let Err(e) =
                                    self.discovered_interfaces.store_received(&mut discovered)
                                {
                                    log::warn!("Failed to store discovered interface: {}", e);
                                } else {
                                    let stack = match (
                                        discovered.impl_name.as_deref(),
                                        discovered.impl_version.as_deref(),
                                    ) {
                                        (Some(name), Some(version))
                                            if !name.is_empty() && !version.is_empty() =>
                                        {
                                            format!("{name} {version}")
                                        }
                                        _ => "unknown implementation".into(),
                                    };
                                    log::debug!(
                                        "Discovered interface '{}' ({}; {}) at {}:{} [stamp={}]",
                                        discovered.name,
                                        discovered.interface_type,
                                        stack,
                                        discovered.reachable_on.as_deref().unwrap_or("?"),
                                        discovered
                                            .port
                                            .map(|p| p.to_string())
                                            .unwrap_or_else(|| "?".into()),
                                        discovered.stamp_value,
                                    );
                                }
                                self.autoconnect_discovered(&discovered);
                                #[cfg(feature = "iface-backbone")]
                                self.upsert_discovered_backbone_peer_pool_candidate(discovered);
                            }
                        }
                    }
                    // Still cache the identity and notify callbacks

                    if let (Some(store), Some(ratchet)) = (&self.ratchet_store, ratchet) {
                        let entry = crate::storage::RatchetEntry {
                            ratchet,
                            received_at: time::now(),
                        };
                        if let Err(err) = store.remember(destination_hash, entry) {
                            log::warn!(
                                "failed to persist ratchet for {:02x}{:02x}{:02x}{:02x}..: {}",
                                destination_hash[0],
                                destination_hash[1],
                                destination_hash[2],
                                destination_hash[3],
                                err
                            );
                        }
                    }

                    // Cache the announced identity
                    let announced = crate::destination::AnnouncedIdentity {
                        dest_hash: rns_core::types::DestHash(destination_hash),
                        identity_hash: rns_core::types::IdentityHash(identity_hash),
                        public_key,
                        app_data: app_data.clone(),
                        hops,
                        received_at: time::now(),
                        receiving_interface,
                        rssi: rx.rssi,
                        snr: rx.snr,
                    };
                    self.upsert_known_destination(destination_hash, announced.clone());
                    self.record_known_destination_stamp(
                        destination_hash,
                        stamp,
                        stamp_value,
                        lr_cost,
                    );
                    // Upstream d5891fde adds the stamp value to the valid
                    // announce line, `n` when there is none.
                    let value_str = if stamp_value == rns_core::stamp::StampValue::ZERO {
                        String::from("n")
                    } else {
                        rns_crypto::stamp_value::pretty_cost(stamp_value.as_f64())
                    };
                    log::debug!(
                        "Announce:validated dest={:02x}{:02x}{:02x}{:02x}.. (v:{}) hops={}",
                        destination_hash[0],
                        destination_hash[1],
                        destination_hash[2],
                        destination_hash[3],
                        value_str,
                        hops,
                    );
                    self.callbacks.on_announce(announced);
                }
                TransportAction::PathUpdated {
                    destination_hash,
                    hops,
                    next_hop,
                    interface,
                } => {
                    let stamp_value = self.recall_stamp_value(&destination_hash);
                    let value_str = match stamp_value
                        .filter(|value| *value != rns_core::stamp::StampValue::ZERO)
                    {
                        Some(value) => format!(
                            " (v:{})",
                            rns_crypto::stamp_value::pretty_cost(value.as_f64())
                        ),
                        None => String::from(" (v:n)"),
                    };
                    log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                        "Destination {:02x?}{} is now {} hops away via {:02x?} on interface {}",
                        &destination_hash[..4],
                        value_str,
                        hops,
                        &next_hop[..4],
                        interface.0,
                    );
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Announce {
                            destination_hash,
                            hops,
                            interface_id: interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::PathUpdated as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects("PathUpdated", e, &mut hook_injected);
                        }
                    }
                    #[cfg(not(feature = "hooks"))]
                    let _ = interface;

                    let _ = self.mark_known_destination_used(&destination_hash);
                    self.callbacks
                        .on_path_updated(rns_core::types::DestHash(destination_hash), hops);
                }
                TransportAction::ForwardToLocalClients { raw, exclude } => {
                    for entry in self.interfaces.values_mut() {
                        if entry.online
                            && entry.enabled
                            && entry.info.is_local_client
                            && Some(entry.id) != exclude
                        {
                            if Self::interface_send_deferred_now(entry) {
                                continue;
                            }
                            let data = if let Some(ref ifac_state) = entry.ifac {
                                ifac::mask_outbound(&raw, ifac_state)
                            } else {
                                raw.to_vec()
                            };
                            entry.stats.txb += data.len() as u64;
                            entry.stats.tx_packets += 1;
                            let send_result = entry.writer.send_frame(&data);
                            Self::record_send_result(
                                entry,
                                &send_result,
                                "forward to local client",
                                entry.id,
                            );
                        }
                    }
                }
                TransportAction::ForwardPlainBroadcast {
                    raw,
                    to_local,
                    exclude,
                } => {
                    for entry in self.interfaces.values_mut() {
                        if entry.online
                            && entry.enabled
                            && entry.info.is_local_client == to_local
                            && Some(entry.id) != exclude
                            && !self.holepunch_manager.is_direct_interface(entry.id)
                        {
                            if Self::interface_send_deferred_now(entry) {
                                continue;
                            }
                            let data = if let Some(ref ifac_state) = entry.ifac {
                                ifac::mask_outbound(&raw, ifac_state)
                            } else {
                                raw.to_vec()
                            };
                            entry.stats.txb += data.len() as u64;
                            entry.stats.tx_packets += 1;
                            let send_result = entry.writer.send_frame(&data);
                            Self::record_send_result(
                                entry,
                                &send_result,
                                "forward plain broadcast",
                                entry.id,
                            );
                        }
                    }
                }
                TransportAction::CacheAnnounce { packet_hash, raw } => {
                    if let Some(ref cache) = self.announce_cache {
                        if let Err(e) = cache.store(&packet_hash, &raw, None) {
                            log::warn!("Failed to cache announce: {}", e);
                        }
                    }
                }
                TransportAction::TunnelSynthesize {
                    interface,
                    data,
                    dest_hash,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let pkt_ctx = rns_hooks::PacketContext {
                            flags: 0,
                            hops: 0,
                            destination_hash: dest_hash,
                            context: 0,
                            packet_hash: [0; 32],
                            interface_id: interface.0,
                            data_offset: 0,
                            data_len: data.len() as u32,
                        };
                        let ctx = HookContext::Packet {
                            ctx: &pkt_ctx,
                            raw: &data,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        // The hook sees the synthesis payload, not a packet, so
                        // `Modify` acts as `Continue` and its bytes are ignored.
                        {
                            let exec = run_hook_inner(
                                &mut self.hook_slots[HookPoint::TunnelSynthesize as usize].programs,
                                &self.hook_manager,
                                &engine_ref,
                                &ctx,
                                now,
                                provider_events_enabled,
                            );
                            if let Some(ref e) = exec {
                                self.collect_hook_side_effects(
                                    "TunnelSynthesize",
                                    e,
                                    &mut hook_injected,
                                );
                                if e.hook_result.as_ref().is_some_and(|r| r.is_drop()) {
                                    continue;
                                }
                            }
                        }
                    }
                    // Pack as BROADCAST DATA PLAIN packet and send on interface
                    let flags = rns_core::packet::PacketFlags {
                        header_type: rns_core::constants::HEADER_1,
                        context_flag: rns_core::constants::FLAG_UNSET,
                        transport_type: rns_core::constants::TRANSPORT_BROADCAST,
                        destination_type: rns_core::constants::DESTINATION_PLAIN,
                        packet_type: rns_core::constants::PACKET_TYPE_DATA,
                    };
                    if let Ok(packet) = rns_core::packet::RawPacket::pack(
                        flags,
                        0,
                        &dest_hash,
                        None,
                        rns_core::constants::CONTEXT_NONE,
                        &data,
                    ) {
                        if let Some(entry) = self.interfaces.get_mut(&interface) {
                            if entry.online && entry.enabled {
                                let raw = if let Some(ref ifac_state) = entry.ifac {
                                    ifac::mask_outbound(&packet.raw, ifac_state)
                                } else {
                                    packet.raw
                                };
                                entry.stats.txb += raw.len() as u64;
                                entry.stats.tx_packets += 1;
                                if let Err(e) = entry.writer.send_frame(&raw) {
                                    log::warn!(
                                        "[{}] tunnel synthesize send failed: {}",
                                        entry.info.id.0,
                                        e
                                    );
                                }
                            }
                        }
                    }
                }
                TransportAction::TunnelEstablished {
                    tunnel_id,
                    interface,
                } => {
                    log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                        "Tunnel established: {:02x?} on interface {}",
                        &tunnel_id[..4],
                        interface.0
                    );
                }
                TransportAction::AnnounceRetransmit {
                    destination_hash,
                    hops,
                    interface,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Announce {
                            destination_hash,
                            hops,
                            interface_id: interface.map(|i| i.0).unwrap_or(0),
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::AnnounceRetransmit as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects(
                                "AnnounceRetransmit",
                                e,
                                &mut hook_injected,
                            );
                        }
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (destination_hash, hops, interface);
                    }
                }
                TransportAction::LinkRequestReceived {
                    link_id,
                    destination_hash: _,
                    receiving_interface,
                } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: receiving_interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkRequestReceived as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects(
                                "LinkRequestReceived",
                                e,
                                &mut hook_injected,
                            );
                        }
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (link_id, receiving_interface);
                    }
                }
                TransportAction::LinkEstablished { link_id, interface } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: interface.0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkEstablished as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects(
                                "LinkEstablished",
                                e,
                                &mut hook_injected,
                            );
                        }
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = (link_id, interface);
                    }
                }
                TransportAction::LinkClosed { link_id } => {
                    #[cfg(feature = "hooks")]
                    {
                        let ctx = HookContext::Link {
                            link_id,
                            interface_id: 0,
                        };
                        let now = time::now();
                        let engine_ref = EngineRef {
                            engine: &self.engine,
                            interfaces: &self.interfaces,
                            link_manager: &self.link_manager,
                            now,
                        };
                        let provider_events_enabled = self.provider_events_enabled();
                        if let Some(ref e) = run_hook_inner(
                            &mut self.hook_slots[HookPoint::LinkClosed as usize].programs,
                            &self.hook_manager,
                            &engine_ref,
                            &ctx,
                            now,
                            provider_events_enabled,
                        ) {
                            self.collect_hook_side_effects("LinkClosed", e, &mut hook_injected);
                        }
                    }
                    #[cfg(not(feature = "hooks"))]
                    {
                        let _ = link_id;
                    }
                }
                TransportAction::ProtocolViolation { interface } => {
                    if let Some(entry) = self.interfaces.get_mut(&interface) {
                        entry.stats.protocol_violations += 1;
                    }
                }
                TransportAction::AnnounceLocalPathResponse {
                    destination_hash,
                    tag,
                    interface,
                } => {
                    self.answer_local_path_request(destination_hash, tag, interface);
                }
                TransportAction::StampPathRequest {
                    destination_hash,
                    tag,
                    interface,
                } => {
                    self.enqueue_path_request_stamp(
                        destination_hash,
                        tag,
                        PathRequestTarget::Interface(interface),
                    );
                }
                TransportAction::RediscoverPath {
                    destination_hash,
                    skip_interface,
                } => {
                    self.rediscover_path(destination_hash, skip_interface);
                }
            }
        }
        self.transport_actions.give(actions);

        // Dispatch any actions injected by hooks during action processing
        #[cfg(feature = "hooks")]
        self.dispatch_hook_injected(hook_injected, depth);
        #[cfg(not(feature = "hooks"))]
        let _ = depth;
    }
}
