//! Signalling messages over the link: handling them and building them.

use super::*;

/// A proposal that could not start.
pub(super) fn not_started(link_id: [u8; 16]) -> HolePunchManagerAction {
    HolePunchManagerAction::DirectConnectFailed {
        link_id,
        session_id: [0u8; 16],
        reason: rns_core::holepunch::FAIL_NOT_STARTED,
    }
}

/// A `HELLO` to the link peer.
pub(super) fn hello(link_id: [u8; 16], reply_wanted: bool) -> HolePunchManagerAction {
    HolePunchManagerAction::SendSignal {
        link_id,
        msgtype: HELLO,
        payload: rns_core::holepunch::encode_hello(reply_wanted),
    }
}

/// Build an `UPGRADE_REJECT` reply for a request that is not taken up.
pub(super) fn refuse_request(
    link_id: [u8; 16],
    payload: &[u8],
    reason: u8,
) -> Vec<HolePunchManagerAction> {
    match HolePunchEngine::build_reject(link_id, payload, reason) {
        Ok(action) => convert_engine_actions(link_id, &[action]),
        Err(e) => {
            log::warn!("Failed to build reject for proposal: {}", e);
            Vec::new()
        }
    }
}

/// Convert engine actions to manager actions (free function to avoid borrow issues).
pub(super) fn convert_engine_actions(
    link_id: [u8; 16],
    actions: &[HolePunchAction],
) -> Vec<HolePunchManagerAction> {
    let mut mgr_actions = Vec::new();
    for action in actions {
        match action {
            HolePunchAction::SendSignal {
                link_id,
                msgtype,
                payload,
            } => {
                mgr_actions.push(HolePunchManagerAction::SendSignal {
                    link_id: *link_id,
                    msgtype: *msgtype,
                    payload: payload.clone(),
                });
            }
            HolePunchAction::DiscoverEndpoints { .. } => {
                // Handled separately via probe workers
            }
            HolePunchAction::StartUdpPunch { .. } => {
                // Handled separately via punch threads
            }
            HolePunchAction::Succeeded { .. } => {
                // Handled directly in tick() where the interface_id is available
            }
            HolePunchAction::Failed { session_id, reason } => {
                mgr_actions.push(HolePunchManagerAction::DirectConnectFailed {
                    link_id,
                    session_id: *session_id,
                    reason: *reason,
                });
            }
        }
    }
    mgr_actions
}

/// Convert an Endpoint (from rns-core) to a SocketAddr.
pub(crate) fn endpoint_to_socket_addr(ep: &Endpoint) -> Option<SocketAddr> {
    match ep.addr.len() {
        4 => {
            let ip = std::net::Ipv4Addr::from(<[u8; 4]>::try_from(ep.addr.as_slice()).ok()?);
            Some(SocketAddr::new(ip.into(), ep.port))
        }
        16 => {
            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(ep.addr.as_slice()).ok()?);
            Some(SocketAddr::new(ip.into(), ep.port))
        }
        _ => None,
    }
}

impl HolePunchManager {
    /// Handle an incoming hole-punch signaling message.
    ///
    /// Returns true if the message was handled (caller should not forward to app).
    pub(crate) fn handle_signal(
        &mut self,
        link_id: [u8; 16],
        msgtype: u8,
        payload: Vec<u8>,
        derived_key: Option<&[u8]>,
        tx: &EventSender,
    ) -> (bool, Vec<HolePunchManagerAction>) {
        self.handle_signal_at(link_id, msgtype, payload, derived_key, tx, Instant::now())
    }

    pub(super) fn handle_signal_at(
        &mut self,
        link_id: [u8; 16],
        msgtype: u8,
        payload: Vec<u8>,
        derived_key: Option<&[u8]>,
        tx: &EventSender,
        now_instant: Instant,
    ) -> (bool, Vec<HolePunchManagerAction>) {
        if !is_holepunch_msgtype(msgtype) {
            return (false, Vec::new());
        }
        // Only a node implementing Direct Link sends these.
        self.peer_support.insert(link_id, PeerSupport::Supported);

        // For UPGRADE_REQUEST, check policy first
        if msgtype == UPGRADE_REQUEST {
            match self.policy {
                HolePunchPolicy::Reject => {
                    log::debug!("Rejecting hole punch proposal (policy=Reject)");
                    match HolePunchEngine::build_reject(link_id, &payload, REJECT_POLICY) {
                        Ok(action) => {
                            let mgr_actions = convert_engine_actions(link_id, &[action]);
                            return (true, mgr_actions);
                        }
                        Err(e) => {
                            log::warn!("Failed to build reject for proposal: {}", e);
                            return (true, Vec::new());
                        }
                    }
                }
                HolePunchPolicy::AcceptAll => {
                    // Proceed
                }
                HolePunchPolicy::IdentifiedOnly | HolePunchPolicy::AskApp => {
                    // Identity-aware and application decisions are made by the
                    // driver. Direct manager users fail closed.
                    log::debug!("Rejecting hole punch proposal pending driver authorization");
                    match HolePunchEngine::build_reject(link_id, &payload, REJECT_POLICY) {
                        Ok(action) => {
                            let mgr_actions = convert_engine_actions(link_id, &[action]);
                            return (true, mgr_actions);
                        }
                        Err(e) => {
                            log::warn!("Failed to build reject for proposal: {}", e);
                            return (true, Vec::new());
                        }
                    }
                }
            }

            if !self.inbound_limiter.check_and_record(link_id, now_instant) {
                log::debug!(
                    "Refusing hole punch proposal on link {:02x?}: request window",
                    &link_id[..4]
                );
                return (true, refuse_request(link_id, &payload, REJECT_BUSY));
            }

            // A new request replaces any earlier session on this link.
            self.remove_link_session(&link_id);

            let active_inbound = self
                .sessions
                .values()
                .filter(|s| s.is_active_inbound())
                .count();
            if active_inbound >= MAX_CONCURRENT_SESSIONS {
                log::debug!(
                    "Refusing hole punch proposal on link {:02x?}: {} sessions active",
                    &link_id[..4],
                    active_inbound
                );
                return (true, refuse_request(link_id, &payload, REJECT_BUSY));
            }

            // Create engine for responder (no probe_addr needed — facilitator comes from request)
            // Protocol will be set from the decoded UPGRADE_REQUEST payload.
            let mut engine = HolePunchEngine::new(link_id, None, ProbeProtocol::Rnsp);
            let now = time::now();
            let actions = match engine.handle_signal(msgtype, &payload, derived_key, now) {
                Ok(a) => a,
                Err(e) => {
                    log::warn!("Error handling UPGRADE_REQUEST: {}", e);
                    return (true, Vec::new());
                }
            };

            // Both endpoints in the request are chosen by the peer: check them
            // before anything is sent to either.
            let initiator_addr = engine
                .peer_public_endpoint()
                .and_then(|ep| self.endpoint_allowed(ep));
            let facilitator_ok = actions.iter().all(|a| match a {
                HolePunchAction::DiscoverEndpoints { probe_addr, .. } => {
                    self.endpoint_allowed(probe_addr).is_some()
                }
                _ => true,
            });
            let Some(initiator_addr) = initiator_addr.filter(|_| facilitator_ok) else {
                log::debug!(
                    "Refusing hole punch proposal on link {:02x?}: endpoint outside the accepted ranges",
                    &link_id[..4]
                );
                return (true, refuse_request(link_id, &payload, REJECT_POLICY));
            };
            let facilitator = actions.iter().find_map(|a| match a {
                HolePunchAction::DiscoverEndpoints { probe_addr, .. } => {
                    endpoint_to_socket_addr(probe_addr)
                }
                _ => None,
            });
            if let Some(why) = self.punch_target_refusal(initiator_addr, facilitator, None) {
                log::debug!(
                    "Refusing hole punch proposal on link {:02x?}: initiator endpoint is {}",
                    &link_id[..4],
                    why
                );
                return (true, refuse_request(link_id, &payload, REJECT_POLICY));
            }
            if self.target_in_use(initiator_addr, None) {
                log::debug!(
                    "Refusing hole punch proposal on link {:02x?}: {} already has a session",
                    &link_id[..4],
                    initiator_addr
                );
                return (true, refuse_request(link_id, &payload, REJECT_BUSY));
            }

            let session_id = *engine.session_id();
            self.link_to_session.insert(link_id, session_id);
            let mut session = HolePunchSession::new(engine, now);
            session.punch_target = Some(initiator_addr);
            self.sessions.insert(session_id, session);
            self.count(link_id, |c| c.accepted += 1);

            let mgr_actions = convert_engine_actions(link_id, &actions);

            // Engine emits DiscoverEndpoints with facilitator from request — start probe
            self.start_endpoint_discovery_from_actions(link_id, &actions, tx);

            return (true, mgr_actions);
        }

        // For other message types, find existing session
        let session_id = match self.link_to_session.get(&link_id) {
            Some(s) => *s,
            None => {
                log::debug!("No hole punch session for link {:02x?}", &link_id[..4]);
                return (true, Vec::new());
            }
        };

        let session = match self.sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return (true, Vec::new()),
        };

        let now = time::now();
        let actions = match session
            .engine
            .handle_signal(msgtype, &payload, derived_key, now)
        {
            Ok(a) => a,
            Err(e) => {
                log::debug!("Error handling signal 0x{:02x}: {}", msgtype, e);
                return (true, Vec::new());
            }
        };

        let mut mgr_actions = convert_engine_actions(link_id, &actions);

        // Check if engine now wants to start punching
        mgr_actions.extend(self.start_punch_from_actions(link_id, &session_id, &actions));

        (true, mgr_actions)
    }

    /// Check if a signalling kind is an upgrade negotiation message.
    pub(crate) fn is_holepunch_message(msgtype: u8) -> bool {
        is_holepunch_msgtype(msgtype)
    }
}
