//! Dispatching the link manager's actions.

use super::*;

impl Driver {
    /// Dispatch link manager actions.
    pub(crate) fn dispatch_link_actions(&mut self, mut actions: Vec<LinkManagerAction>) {
        let mut hook_injected: Vec<TransportAction> = Vec::new();

        for action in actions.drain(..) {
            if matches!(
                action,
                LinkManagerAction::LinkEstablished { .. }
                    | LinkManagerAction::LinkClosed { .. }
                    | LinkManagerAction::RemoteIdentified { .. }
            ) {
                self.housekeeping.state_snapshot_schedule.mark_dirty();
            }
            match action {
                LinkManagerAction::SendPacket {
                    raw,
                    dest_type,
                    attached_interface,
                } => {
                    self.dispatch_link_send_packet(raw, dest_type, attached_interface);
                }
                LinkManagerAction::PacketProved {
                    link_id,
                    packet_hash,
                } => self
                    .proofs
                    .link_packet_proved(&mut *self.callbacks, link_id, packet_hash),
                LinkManagerAction::LinkEstablished {
                    link_id,
                    dest_hash,
                    hops,
                    rebalanced_at,
                    rtt,
                    is_initiator,
                } => {
                    if is_initiator {
                        self.credit_established_link_path(
                            &dest_hash,
                            hops,
                            rebalanced_at.is_some(),
                        );
                    }
                    self.link_established(
                        link_id,
                        dest_hash,
                        rtt,
                        is_initiator,
                        &mut hook_injected,
                    );
                }
                LinkManagerAction::LinkClosed { link_id, reason } => {
                    self.link_closed(link_id, reason, &mut hook_injected);
                }
                LinkManagerAction::PendingLinkFailed { dest_hash } => {
                    self.rediscover_path_after_failed_link(dest_hash);
                }
                LinkManagerAction::RemoteIdentified {
                    link_id,
                    identity_hash,
                    public_key,
                } => {
                    self.remote_identified(link_id, identity_hash, public_key);
                }
                LinkManagerAction::RegisterLinkDest { link_id } => {
                    // Register the link_id as a LINK destination in the transport engine
                    self.engine
                        .register_destination(link_id, rns_core::constants::DESTINATION_LINK);
                }
                LinkManagerAction::DeregisterLinkDest { link_id } => {
                    self.engine.deregister_destination(&link_id);
                }
                LinkManagerAction::ManagementRequest {
                    link_id,
                    path_hash,
                    data,
                    request_id,
                    remote_identity,
                } => {
                    self.handle_management_request(
                        link_id,
                        path_hash,
                        data,
                        request_id,
                        remote_identity,
                    );
                }
                LinkManagerAction::ResourceAcceptQuery {
                    link_id,
                    resource_hash,
                    transfer_size,
                    has_metadata,
                    app_flag,
                } => {
                    self.resource_accept_query(
                        link_id,
                        resource_hash,
                        transfer_size,
                        has_metadata,
                        app_flag,
                    );
                }
                action @ (LinkManagerAction::ResourceReceived { .. }
                | LinkManagerAction::ResourceFileReceived { .. }
                | LinkManagerAction::ResourceSegmentReceived { .. }
                | LinkManagerAction::ResourceStreamReceived { .. }
                | LinkManagerAction::ResourceCompleted { .. }
                | LinkManagerAction::ResourceFailed { .. }
                | LinkManagerAction::ResourceStarted { .. }
                | LinkManagerAction::ResourceProgress { .. }
                | LinkManagerAction::ResourceStreamCompleted { .. }
                | LinkManagerAction::ResourceStreamFailed { .. }
                | LinkManagerAction::ResourceSegmentProgress { .. }
                | LinkManagerAction::ResourceStreamProgress { .. }
                | LinkManagerAction::ChannelMessageReceived { .. }
                | LinkManagerAction::LinkDataReceived { .. }) => {
                    self.notify_link_application(action)
                }
                LinkManagerAction::DirectLinkSignal { link_id, data } => {
                    self.handle_direct_link_signal(link_id, &data);
                }
                LinkManagerAction::DirectPathFailed { link_id } => {
                    log::info!(
                        "Direct path of link {:02x?} failed; falling back",
                        &link_id[..4]
                    );
                    self.fall_back_from_direct(
                        link_id,
                        crate::event::DirectLossCause::LinkFailed,
                        true,
                    );
                }
                LinkManagerAction::ProofRequired {
                    link_id,
                    dest_hash,
                    packet_hash,
                } => {
                    if self.proofs.link_packet_proof_wanted(
                        &mut *self.callbacks,
                        dest_hash,
                        &packet_hash,
                    ) {
                        let proof = self.link_manager.prove_link_packet(&link_id, &packet_hash);
                        self.dispatch_link_actions(proof);
                    }
                }
                LinkManagerAction::ResponseReceived {
                    link_id,
                    request_id,
                    data,
                    metadata,
                } => {
                    if let Some(source) = self.blackhole.update_source(&link_id) {
                        self.blackhole_update_response(link_id, source, Some(&data));
                        continue;
                    }
                    self.callbacks.on_response_with_metadata(
                        rns_core::types::LinkId(link_id),
                        request_id,
                        data,
                        metadata,
                    );
                }
                LinkManagerAction::RequestFailed {
                    link_id,
                    request_id,
                    reason,
                } => {
                    if let Some(source) = self.blackhole.update_source(&link_id) {
                        log::debug!("Blackhole list request failed: {reason:?}");
                        self.blackhole_update_response(link_id, source, None);
                        continue;
                    }
                    self.callbacks.on_request_failed(
                        rns_core::types::LinkId(link_id),
                        request_id,
                        reason,
                    );
                }
                LinkManagerAction::LinkRequestReceived {
                    link_id,
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
                LinkManagerAction::ProtocolViolation {
                    receiving_interface,
                } => {
                    if let Some(entry) = self.interfaces.get_mut(&receiving_interface) {
                        entry.stats.protocol_violations += 1;
                    }
                }
            }
        }
        self.link_actions.give(actions);

        // Dispatch any actions injected by hooks during action processing
        self.dispatch_hook_injected(hook_injected, 0);
    }

    /// Send a packet the link manager built: on its link's route when it
    /// has one, through the transport engine's outbound path.
    #[inline]
    fn dispatch_link_send_packet(
        &mut self,
        raw: rns_core::transport::types::PacketBytes,
        dest_type: u8,
        mut attached_interface: Option<InterfaceId>,
    ) {
        // Take the bytes instead of copying them; resource parts,
        // part requests and proofs are not hashed, since nothing
        // reads their hashes.
        let mut decoded = RawPacket::unpack_outbound_shared(raw);
        // Upstream's `Packet.send` counts the packet as packed,
        // before `Transport.outbound` routes it (or fails to).
        if let Ok(packet) = &decoded {
            self.link_manager.count_sent_link_packet(packet);
        }
        // The outbound path records the hash for deduplication;
        // start loading its bucket while routing runs.
        if let Ok(packet) = &decoded {
            if !packet.is_unhashed_link_resource() {
                self.engine.prefetch_packet_hash(&packet.packet_hash);
            }
        }
        if dest_type == rns_core::constants::DESTINATION_LINK && attached_interface.is_none() {
            if let Ok(packet) = &decoded {
                let link_id = packet.destination_hash;
                if let Some(route_hint) = self.link_manager.get_link_route_hint(&link_id) {
                    // Packed for a larger MTU than the link has
                    // now: built for a direct path the link fell
                    // back from before it went out. The smaller
                    // route may not carry it. Nothing within the
                    // base MTU is held back.
                    let limit = (route_hint.mtu as usize).max(rns_core::constants::MTU);
                    if packet.raw.len() > limit {
                        log::debug!(
                            "Link {:02x?}: dropped a {} byte packet over the link MTU {}",
                            &link_id[..4],
                            packet.raw.len(),
                            route_hint.mtu
                        );
                        return;
                    }
                    attached_interface = Some(route_hint.interface);
                    if packet.flags.header_type == rns_core::constants::HEADER_1 {
                        if let Some(next_hop) = route_hint.transport_id {
                            let raw = inject_transport_header(&packet.raw, &next_hop);
                            // Reparse only when routing changed the wire header,
                            // releasing the old payload copies first.
                            drop(decoded);
                            decoded = RawPacket::unpack_outbound_shared(raw.into());
                            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                                "Link SendPacket rewrite: link={:02x?} iface={} header=1->2 tid={:02x?}",
                                &link_id[..4],
                                route_hint.interface.0,
                                &next_hop[..4]
                            );
                        } else {
                            log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                                "Link SendPacket route: link={:02x?} iface={} header=1 (no transport_id)",
                                &link_id[..4],
                                route_hint.interface.0
                            );
                        }
                    }
                } else {
                    log::trace!(target: crate::logging::PATHING_LOG_TARGET,
                        "Link SendPacket no route hint: link={:02x?}",
                        &link_id[..4]
                    );
                }
            }
        }

        // Route through the transport engine's outbound path
        match decoded {
            Ok(packet) => {
                self.link_manager.record_outbound_packet(&packet);
                // Track only packets a proof can answer. Kept until
                // expiry, the others filled the table under load.
                if packet.flags.packet_type == rns_core::constants::PACKET_TYPE_DATA
                    && !packet.is_unproven_link_data()
                {
                    self.proofs
                        .sent_packets
                        .insert(packet.packet_hash, (packet.destination_hash, time::now()));
                }
                let mut transport_actions = self.transport_actions.take();
                self.engine.handle_outbound_into(
                    &packet,
                    dest_type,
                    attached_interface,
                    time::now(),
                    &mut transport_actions,
                );
                self.dispatch_all(transport_actions);
            }
            Err(e) => {
                log::warn!("LinkManager SendPacket: failed to unpack: {:?}", e);
            }
        }
    }

    /// A link we initiated came up: its path delivered, and the
    /// destination proved itself alive by signing the proof of our link
    /// request (`Link.validate_proof`).
    #[inline]
    fn credit_established_link_path(&mut self, dest_hash: &[u8; 16], hops: u8, rebalanced: bool) {
        if rebalanced {
            self.engine.rebalance_destination_path_hops(dest_hash, hops);
        }
        self.engine.mark_path_responsive(dest_hash, time::now());
    }

    /// A link came up: run its hook, and tell whoever owns it.
    fn link_established(
        &mut self,
        link_id: [u8; 16],
        dest_hash: [u8; 16],
        rtt: f64,
        is_initiator: bool,
        hook_injected: &mut Vec<TransportAction>,
    ) {
        self.run_hooks_with_effects(
            HookPoint::LinkEstablished,
            &HookEvent::Link {
                link_id,
                interface_id: 0,
            },
            InjectedActions::Collect(hook_injected),
        );
        // Upstream logs this at LOG_DEBUG.
        log::debug!(
            "Link established: {:02x?} rtt={:.3}s initiator={}",
            &link_id[..4],
            rtt,
            is_initiator,
        );
        if is_initiator && self.blackhole.update_source(&link_id).is_some() {
            self.blackhole_update_link_established(link_id);
            return;
        }
        // Upstream keeps links to its built-in destinations
        // inside Transport: the application never hears of them.
        if !is_initiator && self.builtin.link_destinations.contains(&dest_hash) {
            self.builtin.links.insert(link_id);
            return;
        }
        self.callbacks.on_link_established(
            rns_core::types::LinkId(link_id),
            rns_core::types::DestHash(dest_hash),
            rtt,
            is_initiator,
        );
    }

    /// A link went down: run its hook, drop its direct interface, and
    /// tell whoever owns it.
    fn link_closed(
        &mut self,
        link_id: [u8; 16],
        reason: Option<rns_core::link::TeardownReason>,
        hook_injected: &mut Vec<TransportAction>,
    ) {
        self.run_hooks_with_effects(
            HookPoint::LinkClosed,
            &HookEvent::Link {
                link_id,
                interface_id: 0,
            },
            InjectedActions::Collect(hook_injected),
        );
        log::debug!("Link closed: {:02x?} reason={:?}", &link_id[..4], reason);
        // The link's direct interface, if any, goes with it.
        self.holepunch_manager.link_closed(&link_id);
        if self.blackhole.update_source(&link_id).is_some() {
            self.blackhole.update_link_closed(&link_id);
            return;
        }
        if self.builtin.links.remove(&link_id) {
            return;
        }
        self.callbacks
            .on_link_closed(rns_core::types::LinkId(link_id), reason);
    }

    /// The peer of a link identified itself: tear the link down if the
    /// identity is blackholed, else tell the application.
    fn remote_identified(
        &mut self,
        link_id: [u8; 16],
        identity_hash: [u8; 16],
        public_key: [u8; 64],
    ) {
        if self.engine.is_blackholed(&identity_hash, time::now()) {
            log::debug!(
                "Terminating link {:02x?} from blackholed identity {:02x?}",
                &link_id[..4],
                &identity_hash[..4],
            );
            let teardown_actions = self.link_manager.teardown_link(&link_id);
            self.dispatch_link_actions(teardown_actions);
            return;
        }
        log::debug!(
            "Remote identified on link {:02x?}: {:02x?}",
            &link_id[..4],
            &identity_hash[..4],
        );
        if self.builtin.links.contains(&link_id) {
            return;
        }
        self.callbacks.on_remote_identified(
            rns_core::types::LinkId(link_id),
            rns_core::types::IdentityHash(identity_hash),
            public_key,
        );
    }

    /// Ask the application whether to accept an advertised resource.
    fn resource_accept_query(
        &mut self,
        link_id: [u8; 16],
        resource_hash: Vec<u8>,
        transfer_size: u64,
        has_metadata: bool,
        app_flag: bool,
    ) {
        let accept = self.callbacks.on_resource_accept_query_with_app_flag(
            rns_core::types::LinkId(link_id),
            resource_hash.clone(),
            transfer_size,
            has_metadata,
            app_flag,
        );
        let accept_actions =
            self.link_manager
                .accept_resource(&link_id, &resource_hash, accept, &mut self.rng);
        // Re-dispatch (recursive but bounded: accept_resource won't produce more AcceptQuery)
        self.dispatch_link_actions(accept_actions);
    }

    /// Hand the application a link event: resources, channel messages and
    /// link data. Events on links to the built-in destinations stay with
    /// transport.
    #[inline]
    fn notify_link_application(&mut self, action: LinkManagerAction) {
        let (LinkManagerAction::ResourceReceived { link_id, .. }
        | LinkManagerAction::ResourceFileReceived { link_id, .. }
        | LinkManagerAction::ResourceSegmentReceived { link_id, .. }
        | LinkManagerAction::ResourceStreamReceived { link_id, .. }
        | LinkManagerAction::ResourceCompleted { link_id, .. }
        | LinkManagerAction::ResourceFailed { link_id, .. }
        | LinkManagerAction::ResourceStarted { link_id, .. }
        | LinkManagerAction::ResourceProgress { link_id, .. }
        | LinkManagerAction::ResourceStreamCompleted { link_id, .. }
        | LinkManagerAction::ResourceStreamFailed { link_id, .. }
        | LinkManagerAction::ResourceSegmentProgress { link_id, .. }
        | LinkManagerAction::ResourceStreamProgress { link_id, .. }
        | LinkManagerAction::ChannelMessageReceived { link_id, .. }
        | LinkManagerAction::LinkDataReceived { link_id, .. }) = &action
        else {
            return;
        };
        if self.builtin.links.contains(link_id) {
            return;
        }
        match action {
            LinkManagerAction::ResourceReceived {
                link_id,
                data,
                metadata,
                app_flag,
            } => {
                self.callbacks.on_resource_received_with_app_flag(
                    rns_core::types::LinkId(link_id),
                    data,
                    metadata,
                    app_flag,
                );
            }
            LinkManagerAction::ResourceFileReceived { link_id, resource } => {
                self.callbacks
                    .on_resource_file_received(rns_core::types::LinkId(link_id), resource);
            }
            LinkManagerAction::ResourceSegmentReceived {
                link_id,
                original_hash,
                offset,
                data,
            } => {
                self.callbacks.on_resource_segment(
                    rns_core::types::LinkId(link_id),
                    original_hash,
                    offset,
                    data,
                );
            }
            LinkManagerAction::ResourceStreamReceived { link_id, resource } => {
                self.callbacks
                    .on_resource_stream_received(rns_core::types::LinkId(link_id), resource);
            }
            LinkManagerAction::ResourceCompleted { link_id } => {
                self.callbacks
                    .on_resource_completed(rns_core::types::LinkId(link_id));
            }
            LinkManagerAction::ResourceFailed { link_id, error } => {
                log::debug!("Resource failed on link {:02x?}: {}", &link_id[..4], error);
                self.callbacks
                    .on_resource_failed(rns_core::types::LinkId(link_id), error);
            }
            LinkManagerAction::ResourceStarted {
                link_id,
                resource_hash,
                data_size,
            } => {
                self.callbacks.on_resource_started(
                    rns_core::types::LinkId(link_id),
                    resource_hash,
                    data_size,
                );
            }
            LinkManagerAction::ResourceProgress {
                link_id,
                received,
                total,
            } => {
                self.callbacks.on_resource_progress(
                    rns_core::types::LinkId(link_id),
                    received,
                    total,
                );
            }
            LinkManagerAction::ResourceStreamCompleted {
                link_id,
                transfer_id,
            } => {
                self.callbacks
                    .on_resource_stream_completed(rns_core::types::LinkId(link_id), transfer_id);
            }
            LinkManagerAction::ResourceStreamFailed {
                link_id,
                transfer_id,
                error,
            } => {
                self.callbacks.on_resource_stream_failed(
                    rns_core::types::LinkId(link_id),
                    transfer_id,
                    error,
                );
            }
            LinkManagerAction::ResourceSegmentProgress {
                link_id,
                segment_progress,
                transfer_size,
            } => {
                self.callbacks.on_resource_segment_progress(
                    rns_core::types::LinkId(link_id),
                    segment_progress,
                    transfer_size,
                );
            }
            LinkManagerAction::ResourceStreamProgress {
                link_id,
                transfer_id,
                transferred,
                total,
            } => {
                self.callbacks.on_resource_stream_progress(
                    rns_core::types::LinkId(link_id),
                    transfer_id,
                    transferred,
                    total,
                );
            }
            LinkManagerAction::ChannelMessageReceived {
                link_id,
                msgtype,
                payload,
            } => {
                self.callbacks.on_channel_message(
                    rns_core::types::LinkId(link_id),
                    msgtype,
                    payload,
                );
            }
            LinkManagerAction::LinkDataReceived {
                link_id,
                context,
                data,
            } => {
                self.callbacks
                    .on_link_data(rns_core::types::LinkId(link_id), context, data);
            }
            _ => {}
        }
    }
}
