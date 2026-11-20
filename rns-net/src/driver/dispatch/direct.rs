//! Direct paths: authorizing them, their signalling and falling back.

use super::*;

impl Driver {
    pub(crate) fn authorize_direct_connect_proposal(
        &mut self,
        policy: crate::event::HolePunchPolicy,
        link_id: [u8; 16],
        peer_identity: Option<[u8; 16]>,
        payload: &[u8],
    ) -> Option<bool> {
        if let Err(error) = rns_core::holepunch::HolePunchEngine::validate_upgrade_request(payload)
        {
            log::warn!("Dropping malformed direct-connect proposal: {}", error);
            return None;
        }
        Some(self.authorize_direct_connect(policy, link_id, peer_identity))
    }

    pub(crate) fn authorize_direct_connect(
        &mut self,
        policy: crate::event::HolePunchPolicy,
        link_id: [u8; 16],
        peer_identity: Option<[u8; 16]>,
    ) -> bool {
        if peer_identity.is_some_and(|identity| self.holepunch_manager.identity_allowed(&identity))
        {
            return true;
        }
        match policy {
            crate::event::HolePunchPolicy::Reject => false,
            crate::event::HolePunchPolicy::AcceptAll => true,
            crate::event::HolePunchPolicy::IdentifiedOnly => peer_identity.is_some(),
            crate::event::HolePunchPolicy::AskApp => self.callbacks.on_direct_connect_proposed(
                rns_core::types::LinkId(link_id),
                peer_identity.map(rns_core::types::IdentityHash),
            ),
        }
    }

    /// Handle Direct Link signalling from a link peer. A node that takes no
    /// part in Direct Link drops it unanswered, as a node without support
    /// for it does.
    pub(crate) fn handle_direct_link_signal(&mut self, link_id: [u8; 16], data: &[u8]) {
        // A link already on a direct path still hears about it after the
        // configuration changed.
        let upgraded = self.holepunch_manager.direct_session(&link_id).is_some();
        if !self.holepunch_manager.enabled() && !upgraded {
            return;
        }
        let Some((msgtype, body)) = rns_core::holepunch::decode_signal(data) else {
            log::debug!(
                "Dropping Direct Link signalling of an unknown version on link {:02x?}",
                &link_id[..4]
            );
            return;
        };
        if msgtype == rns_core::holepunch::FALLBACK {
            self.handle_fallback_signal(link_id, body);
            return;
        }
        if !self.holepunch_manager.enabled() {
            return;
        }
        let derived_key = self.link_manager.get_derived_key(&link_id);
        let tx = self.get_event_sender();
        if msgtype == rns_core::holepunch::HELLO {
            let actions = self.holepunch_manager.handle_hello(
                link_id,
                body,
                derived_key.as_deref(),
                &mut self.rng,
                &tx,
            );
            self.dispatch_holepunch_actions(actions);
            return;
        }
        if !HolePunchManager::is_holepunch_message(msgtype) {
            return;
        }
        let configured_policy = self.holepunch_manager.policy();
        if msgtype == rns_core::holepunch::UPGRADE_REQUEST {
            // A repeated request is answered with the replies already sent,
            // without asking the policy again.
            if let Some(replay) = self
                .holepunch_manager
                .replay_for_repeated_request(link_id, body)
            {
                self.dispatch_holepunch_actions(replay);
                return;
            }
            // Both sides proposed at once: the link initiator's proposal
            // goes ahead, and the other side answers it as the responder.
            // The initiator leaves the peer's request unanswered: the peer
            // drops its own proposal when ours reaches it.
            if self.holepunch_manager.proposing(&link_id) {
                if self.link_manager.is_link_initiator(&link_id) == Some(true) {
                    log::debug!(
                        "Both sides proposed on link {:02x?}; keeping ours",
                        &link_id[..4]
                    );
                    return;
                }
                log::debug!(
                    "Both sides proposed on link {:02x?}; answering theirs",
                    &link_id[..4]
                );
                self.holepunch_manager.yield_proposal(&link_id);
            }
            let peer_identity = self.link_manager.remote_identity_hash(&link_id);
            let Some(accept) = self.authorize_direct_connect_proposal(
                configured_policy,
                link_id,
                peer_identity,
                body,
            ) else {
                return;
            };
            self.holepunch_manager.set_policy(if accept {
                crate::event::HolePunchPolicy::AcceptAll
            } else {
                crate::event::HolePunchPolicy::Reject
            });
        }
        let (handled, hp_actions) = self.holepunch_manager.handle_signal(
            link_id,
            msgtype,
            body.to_vec(),
            derived_key.as_deref(),
            &tx,
        );
        self.holepunch_manager.set_policy(configured_policy);
        if handled {
            self.dispatch_holepunch_actions(hp_actions);
        }
    }

    /// The peer stopped using the direct path of `session`: stop using it
    /// too, and answer if it asks, so its link hears from us on the
    /// original route.
    pub(super) fn handle_fallback_signal(&mut self, link_id: [u8; 16], body: &[u8]) {
        let Ok((session_id, reply_wanted)) = rns_core::holepunch::decode_fallback(body) else {
            log::debug!("Dropping malformed Direct Link FALLBACK");
            return;
        };
        if self.holepunch_manager.direct_session(&link_id) == Some(session_id) {
            log::info!(
                "Link peer fell back from the direct path of link {:02x?}",
                &link_id[..4]
            );
            self.fall_back_from_direct(link_id, crate::event::DirectLossCause::PeerFallback, false);
        }
        if reply_wanted {
            self.send_fallback(link_id, session_id, false);
        }
    }

    /// Send FALLBACK for `session` to the link peer, on the link's current
    /// route.
    pub(super) fn send_fallback(
        &mut self,
        link_id: [u8; 16],
        session_id: [u8; 16],
        reply_wanted: bool,
    ) {
        let framed = rns_core::holepunch::encode_signal(
            rns_core::holepunch::FALLBACK,
            &rns_core::holepunch::encode_fallback(&session_id, reply_wanted),
        );
        let actions = self
            .link_manager
            .send_direct_link_signal(&link_id, &framed, &mut self.rng);
        self.dispatch_link_actions(actions);
    }

    /// Stop using the link's direct path: return the link to its original
    /// route and MTU, remove the direct interface, tell the application,
    /// and with `notify_peer` tell the peer over the original route (asking
    /// for an answer, which also shows the link that path is alive).
    pub(crate) fn fall_back_from_direct(
        &mut self,
        link_id: [u8; 16],
        cause: crate::event::DirectLossCause,
        notify_peer: bool,
    ) {
        let direct = self.holepunch_manager.take_direct(&link_id, cause);
        let detached = self.link_manager.detach_direct_route(&link_id);
        let Some(interface_id) = direct.map(|(interface, _)| interface).or(detached) else {
            return;
        };
        // Its mapping is gone, so removing it does not come back here.
        self.handle_interface_down_event(interface_id);
        self.direct_path_lost(link_id, interface_id, direct.map(|(_, s)| s), notify_peer);
    }

    /// After a link's direct interface is gone: the link back on its
    /// original route, the peer told, the application told.
    pub(crate) fn direct_path_lost(
        &mut self,
        link_id: [u8; 16],
        interface_id: rns_core::transport::types::InterfaceId,
        session_id: Option<[u8; 16]>,
        notify_peer: bool,
    ) {
        self.link_manager.detach_direct_route(&link_id);
        if let (true, Some(session_id)) = (notify_peer, session_id) {
            self.send_fallback(link_id, session_id, true);
        }
        self.callbacks
            .on_direct_connect_lost(rns_core::types::LinkId(link_id), interface_id);
    }

    /// A direct interface found its path MTU: the link it carries uses it,
    /// never above what the peer accepts on the direct path.
    pub(crate) fn direct_path_mtu_discovered(
        &mut self,
        interface_id: rns_core::transport::types::InterfaceId,
        mtu: u32,
    ) {
        let Some(link_id) = self.holepunch_manager.direct_link_of(interface_id) else {
            return;
        };
        if let Some(entry) = self.interfaces.get_mut(&interface_id) {
            entry.info.mtu = mtu;
        }
        self.holepunch_manager.note_direct_mtu(interface_id, mtu);
        if let Some(applied) = self
            .link_manager
            .set_direct_mtu(&link_id, interface_id, mtu)
        {
            log::debug!(
                "Link {:02x?} uses MTU {} on its direct path",
                &link_id[..4],
                applied
            );
        }
    }

    /// Dispatch hole-punch manager actions.
    pub(crate) fn dispatch_holepunch_actions(&mut self, actions: Vec<HolePunchManagerAction>) {
        for action in actions {
            match action {
                HolePunchManagerAction::SendSignal {
                    link_id,
                    msgtype,
                    payload,
                } => {
                    let framed = rns_core::holepunch::encode_signal(msgtype, &payload);
                    let link_actions =
                        self.link_manager
                            .send_direct_link_signal(&link_id, &framed, &mut self.rng);
                    self.dispatch_link_actions(link_actions);
                }
                HolePunchManagerAction::DirectConnectEstablished {
                    link_id,
                    session_id,
                    interface_id,
                    writer,
                    info,
                    rtt,
                    mtu,
                    peer_max_packet,
                } => {
                    log::info!(
                        "Direct connection established for link {:02x?} session {:02x?} iface {} rtt={:.1}ms mtu={} peer max packet={:?}",
                        &link_id[..4], &session_id[..4], interface_id.0, rtt * 1000.0, mtu, peer_max_packet
                    );
                    // The interface is registered before the link uses it.
                    self.handle_interface_up_event(interface_id, Some(writer), Some(*info));
                    if !self.link_manager.attach_direct_route(
                        &link_id,
                        interface_id,
                        mtu,
                        peer_max_packet,
                    ) {
                        // The link closed meanwhile.
                        self.holepunch_manager.link_closed(&link_id);
                        continue;
                    }
                    self.callbacks.on_direct_connect_established(
                        rns_core::types::LinkId(link_id),
                        interface_id,
                    );
                }
                HolePunchManagerAction::RemoveDirectInterface {
                    link_id,
                    interface_id,
                } => {
                    log::debug!(
                        "Removing direct interface {} of link {:02x?}",
                        interface_id.0,
                        &link_id[..4]
                    );
                    self.handle_interface_down_event(interface_id);
                }
                HolePunchManagerAction::DirectConnectFailed {
                    link_id,
                    session_id,
                    reason,
                } => {
                    log::info!(
                        "Direct connection failed for link {:02x?} session {:02x?}: {} (0x{:02x})",
                        &link_id[..4],
                        &session_id[..4],
                        crate::event::direct_link_reason_name(reason),
                        reason
                    );
                    self.holepunch_manager.note_failed(link_id, reason);
                    self.holepunch_manager.reupgrade_failed(link_id, reason);
                    self.callbacks
                        .on_direct_connect_failed(rns_core::types::LinkId(link_id), reason);
                }
                HolePunchManagerAction::Reupgrade { link_id } => {
                    self.reupgrade_direct_link(link_id);
                }
            }
        }
    }

    /// Propose again on a link that lost its direct path, if it is still
    /// active: a stale link is looked at again shortly, a closed one stops.
    pub(super) fn reupgrade_direct_link(&mut self, link_id: [u8; 16]) {
        use rns_core::link::LinkState;
        let state = self.link_manager.link_state(&link_id);
        let derived_key = self.link_manager.get_derived_key(&link_id);
        let derived_key = match (state, derived_key) {
            (Some(LinkState::Active), Some(key)) if !self.is_draining() => key,
            (Some(LinkState::Stale), _) => {
                self.holepunch_manager.postpone_reupgrade(link_id);
                return;
            }
            _ => {
                log::debug!(
                    "Not re-upgrading link {:02x?}: it is not active",
                    &link_id[..4]
                );
                self.holepunch_manager.cancel_reupgrade(&link_id);
                return;
            }
        };
        log::info!("Re-upgrading link {:02x?} to a direct path", &link_id[..4]);
        let tx = self.get_event_sender();
        let actions = self
            .holepunch_manager
            .propose(link_id, &derived_key, &mut self.rng, &tx);
        self.dispatch_holepunch_actions(actions);
    }
}
