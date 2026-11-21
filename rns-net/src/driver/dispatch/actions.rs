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
    #[inline]
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
                    self.dispatch_announce_received(announce, &mut hook_injected);
                }
                TransportAction::PathUpdated {
                    destination_hash,
                    hops,
                    next_hop,
                    interface,
                } => {
                    self.dispatch_path_updated(
                        destination_hash,
                        hops,
                        next_hop,
                        interface,
                        &mut hook_injected,
                    );
                }
                TransportAction::ForwardToLocalClients { raw, exclude } => {
                    self.forward_to_local_clients(&raw, exclude);
                }
                TransportAction::ForwardPlainBroadcast {
                    raw,
                    to_local,
                    exclude,
                } => {
                    self.forward_plain_broadcast(&raw, to_local, exclude);
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
                    self.dispatch_tunnel_synthesize(
                        interface,
                        &data,
                        dest_hash,
                        &mut hook_injected,
                    );
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
                    self.run_hooks_with_effects(
                        HookPoint::AnnounceRetransmit,
                        &HookEvent::Announce {
                            destination_hash,
                            hops,
                            interface_id: interface.map(|i| i.0).unwrap_or(0),
                        },
                        InjectedActions::Collect(&mut hook_injected),
                    );
                }
                TransportAction::LinkRequestReceived {
                    link_id,
                    destination_hash: _,
                    receiving_interface,
                } => {
                    self.run_hooks_with_effects(
                        HookPoint::LinkRequestReceived,
                        &HookEvent::Link {
                            link_id,
                            interface_id: receiving_interface.0,
                        },
                        InjectedActions::Collect(&mut hook_injected),
                    );
                }
                TransportAction::LinkEstablished { link_id, interface } => {
                    self.run_hooks_with_effects(
                        HookPoint::LinkEstablished,
                        &HookEvent::Link {
                            link_id,
                            interface_id: interface.0,
                        },
                        InjectedActions::Collect(&mut hook_injected),
                    );
                }
                TransportAction::LinkClosed { link_id } => {
                    self.run_hooks_with_effects(
                        HookPoint::LinkClosed,
                        &HookEvent::Link {
                            link_id,
                            interface_id: 0,
                        },
                        InjectedActions::Collect(&mut hook_injected),
                    );
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
        self.dispatch_hook_injected(hook_injected, depth);
    }

    /// A validated announce: run its hook, take in a discovery announce,
    /// keep its ratchet and identity, and tell the application.
    fn dispatch_announce_received(
        &mut self,
        announce: Box<ReceivedAnnounce>,
        hook_injected: &mut Vec<TransportAction>,
    ) {
        let ReceivedAnnounce {
            destination_hash,
            packet_hash,
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
        if self.run_hooks_with_effects(
            HookPoint::AnnounceReceived,
            &HookEvent::Announce {
                destination_hash,
                hops,
                interface_id: receiving_interface.0,
            },
            InjectedActions::Collect(hook_injected),
        ) {
            return;
        }

        // Check if this is a discovery announce (matched by name_hash
        // since discovery is a SINGLE destination — its dest hash varies
        // with the sender's identity).
        if name_hash == self.discovery.name_hash && self.discovery.enabled {
            self.ingest_discovery_announce(&identity_hash, hops, app_data.as_deref());
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
        self.known.record_packet_hash(destination_hash, packet_hash);
        self.known
            .record_stamp(destination_hash, stamp, stamp_value, lr_cost);
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

    /// Store the interface a discovery announce describes, when its
    /// network is accepted, and auto-connect it if it qualifies.
    fn ingest_discovery_announce(
        &mut self,
        identity_hash: &[u8; 16],
        hops: u8,
        app_data: Option<&[u8]>,
    ) {
        if !self.discovery.source_allowed(identity_hash) {
            log::debug!(
                "Interface discovered from non-authorized network identity {:02x?}, ignoring",
                &identity_hash[..4]
            );
        } else if let Some(app_data) = app_data {
            if let Some(mut discovered) = crate::discovery::parse_interface_announce_with_identity(
                app_data,
                identity_hash,
                hops,
                self.discovery.required_value,
                &mut self.discovery.stamp_cache,
                self.network_identity.as_ref(),
                crate::time::now(),
            ) {
                crate::discovery::apply_transport_autoconnect_mode(
                    &mut discovered,
                    self.engine.transport_enabled(),
                    self.discovery.autoconnect_mode,
                );
                if let Err(e) = self.discovery.storage.store_received(&mut discovered) {
                    log::warn!("Failed to store discovered interface: {}", e);
                } else {
                    let stack = match (
                        discovered.impl_name.as_deref(),
                        discovered.impl_version.as_deref(),
                    ) {
                        (Some(name), Some(version)) if !name.is_empty() && !version.is_empty() => {
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

    /// A path changed: log it, run its hook and tell the application.
    fn dispatch_path_updated(
        &mut self,
        destination_hash: [u8; 16],
        hops: u8,
        next_hop: [u8; 16],
        interface: InterfaceId,
        hook_injected: &mut Vec<TransportAction>,
    ) {
        let stamp_value = self.known.stamp_value(&destination_hash);
        let value_str =
            match stamp_value.filter(|value| *value != rns_core::stamp::StampValue::ZERO) {
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
        self.run_hooks_with_effects(
            HookPoint::PathUpdated,
            &HookEvent::Announce {
                destination_hash,
                hops,
                interface_id: interface.0,
            },
            InjectedActions::Collect(hook_injected),
        );

        let _ = self.known.mark_used(&destination_hash);
        self.callbacks
            .on_path_updated(rns_core::types::DestHash(destination_hash), hops);
    }

    /// Send `raw` to every connected local client but `exclude`.
    fn forward_to_local_clients(&mut self, raw: &[u8], exclude: Option<InterfaceId>) {
        for entry in self.interfaces.values_mut() {
            if entry.online
                && entry.enabled
                && entry.info.is_local_client
                && Some(entry.id) != exclude
            {
                Self::send_forwarded(entry, raw, "forward to local client");
            }
        }
    }

    /// Send a plain broadcast to the local clients, `to_local`, or to the
    /// other interfaces but direct ones, except `exclude`.
    fn forward_plain_broadcast(
        &mut self,
        raw: &[u8],
        to_local: bool,
        exclude: Option<InterfaceId>,
    ) {
        for entry in self.interfaces.values_mut() {
            if entry.online
                && entry.enabled
                && entry.info.is_local_client == to_local
                && Some(entry.id) != exclude
                && !self.holepunch_manager.is_direct_interface(entry.id)
            {
                Self::send_forwarded(entry, raw, "forward plain broadcast");
            }
        }
    }

    /// Send a forwarded packet on `entry`, masked with its IFAC, unless
    /// its sends are deferred.
    #[inline]
    fn send_forwarded(entry: &mut InterfaceEntry, raw: &[u8], context: &str) {
        if Self::interface_send_deferred_now(entry) {
            return;
        }
        let data = if let Some(ref ifac_state) = entry.ifac {
            ifac::mask_outbound(raw, ifac_state)
        } else {
            raw.to_vec()
        };
        entry.stats.txb += data.len() as u64;
        entry.stats.tx_packets += 1;
        let send_result = entry.writer.send_frame(&data);
        Self::record_send_result(entry, &send_result, context, entry.id);
    }

    /// Send a tunnel synthesis payload on `interface` as a broadcast plain
    /// data packet, unless its hook drops it.
    fn dispatch_tunnel_synthesize(
        &mut self,
        interface: InterfaceId,
        data: &[u8],
        dest_hash: [u8; 16],
        hook_injected: &mut Vec<TransportAction>,
    ) {
        // The hook sees the synthesis payload, not a packet, so `Modify`
        // acts as `Continue` and its bytes are ignored.
        if self.run_hooks_with_effects(
            HookPoint::TunnelSynthesize,
            &HookEvent::Packet {
                flags: 0,
                hops: 0,
                destination_hash: dest_hash,
                packet_hash: [0; 32],
                interface_id: interface.0,
                raw: data,
            },
            InjectedActions::Collect(hook_injected),
        ) {
            return;
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
            data,
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
                        log::warn!("[{}] tunnel synthesize send failed: {}", entry.info.id.0, e);
                    }
                }
            }
        }
    }
}
