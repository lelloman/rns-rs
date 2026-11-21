//! Proposing a direct path, answering a proposal, and the rules that
//! pace and pair them.

use super::*;

impl HolePunchManager {
    /// Why `target`, named by the peer, may not be punched toward, or
    /// `None` if it may: it is a facilitator, this node itself (as its
    /// probe saw it, or one of its listening ports there), or of another
    /// address family than the punch socket's mapping.
    pub(super) fn punch_target_refusal(
        &self,
        target: SocketAddr,
        facilitator: Option<SocketAddr>,
        observed: Option<SocketAddr>,
    ) -> Option<&'static str> {
        let target = canonical(target);
        if facilitator
            .into_iter()
            .chain(self.probe_addrs.iter().copied())
            .any(|f| canonical(f) == target)
        {
            return Some("a facilitator");
        }
        let observed = observed.map(canonical)?;
        if observed == target
            || (observed.ip() == target.ip() && self.own_ports.contains(&target.port()))
        {
            return Some("this node");
        }
        if observed.is_ipv4() != target.is_ipv4() {
            return Some("of another address family than the probed mapping");
        }
        None
    }

    /// Propose a direct connection on a link.
    ///
    /// Signalling goes only to a peer known to implement Direct Link. For a
    /// peer not known yet, this sends a `HELLO` and the proposal starts when
    /// the peer answers; a peer that stays silent for [`HELLO_TIMEOUT`] is
    /// taken not to support it, and the proposal fails with
    /// `REJECT_UNSUPPORTED`.
    ///
    /// `derived_key` is the link's derived session key (from LinkEngine).
    pub(crate) fn propose(
        &mut self,
        link_id: [u8; 16],
        derived_key: &[u8],
        rng: &mut dyn rns_crypto::Rng,
        tx: &EventSender,
    ) -> Vec<HolePunchManagerAction> {
        let now = time::now();
        if self.probe_addrs.is_empty() {
            log::warn!(
                "Cannot propose direct connect on link {:02x?}: no probe_addr configured",
                &link_id[..4]
            );
            return vec![not_started(link_id)];
        }
        if self.rate_limited(&link_id, now) {
            return vec![not_started(link_id)];
        }
        match self.peer_support.get(&link_id) {
            Some(PeerSupport::Supported) => self.start_proposal(link_id, derived_key, rng, tx),
            // Already asking: the proposal starts with the answer.
            Some(PeerSupport::Querying { .. }) => Vec::new(),
            None => {
                self.peer_support.insert(
                    link_id,
                    PeerSupport::Querying {
                        since: now,
                        last_sent: now,
                    },
                );
                vec![hello(link_id, true)]
            }
        }
    }

    /// Handle a `HELLO` from a link peer: note that it implements Direct
    /// Link, answer it when it asks, and start a proposal that waited for it.
    pub(crate) fn handle_hello(
        &mut self,
        link_id: [u8; 16],
        body: &[u8],
        derived_key: Option<&[u8]>,
        rng: &mut dyn rns_crypto::Rng,
        tx: &EventSender,
    ) -> Vec<HolePunchManagerAction> {
        let hello_msg = match rns_core::holepunch::decode_hello(body) {
            Ok(h) => h,
            Err(e) => {
                log::debug!("Dropping malformed Direct Link HELLO: {}", e);
                return Vec::new();
            }
        };
        let mut actions = Vec::new();
        if hello_msg.reply_wanted {
            actions.push(hello(link_id, false));
        }
        let waiting = matches!(
            self.peer_support.insert(link_id, PeerSupport::Supported),
            Some(PeerSupport::Querying { .. })
        );
        if waiting {
            match derived_key {
                Some(key) => actions.extend(self.start_proposal(link_id, key, rng, tx)),
                None => log::warn!(
                    "Cannot propose direct connect: no derived key for link {:02x?}",
                    &link_id[..4]
                ),
            }
        }
        actions
    }

    /// One proposal per link per [`PROPOSAL_COOLDOWN`](rns_core::holepunch::PROPOSAL_COOLDOWN).
    pub(super) fn rate_limited(&self, link_id: &[u8; 16], now: f64) -> bool {
        let limited = self
            .link_to_session
            .get(link_id)
            .and_then(|session_id| self.sessions.get(session_id))
            .is_some_and(|session| {
                now - session.last_proposal < rns_core::holepunch::PROPOSAL_COOLDOWN
            });
        if limited {
            log::debug!(
                "Hole punch proposal rate limited for link {:02x?}",
                &link_id[..4]
            );
        }
        limited
    }

    /// Start the upgrade on a link whose peer implements Direct Link.
    ///
    /// Per the spec, the initiator first discovers its own public endpoint
    /// (Phase 1), then sends UPGRADE_REQUEST (Phase 2).
    pub(super) fn start_proposal(
        &mut self,
        link_id: [u8; 16],
        derived_key: &[u8],
        rng: &mut dyn rns_crypto::Rng,
        tx: &EventSender,
    ) -> Vec<HolePunchManagerAction> {
        let now = time::now();

        if self.rate_limited(&link_id, now) {
            return vec![not_started(link_id)];
        }

        // Clean up any existing session for this link
        self.remove_link_session(&link_id);

        let probe_endpoint = self.probe_addrs.first().map(|addr| Endpoint {
            addr: match addr {
                SocketAddr::V4(v4) => v4.ip().octets().to_vec(),
                SocketAddr::V6(v6) => v6.ip().octets().to_vec(),
            },
            port: addr.port(),
        });

        let mut engine = HolePunchEngine::new(link_id, probe_endpoint, self.probe_protocol);
        let actions = match engine.propose(derived_key, now, rng) {
            Ok(a) => a,
            Err(e) => {
                log::warn!("Failed to propose hole punch: {}", e);
                return vec![not_started(link_id)];
            }
        };

        let session_id = *engine.session_id();
        self.link_to_session.insert(link_id, session_id);
        self.sessions
            .insert(session_id, HolePunchSession::new(engine, now));
        self.count(link_id, |c| c.proposed += 1);

        let mgr_actions = convert_engine_actions(link_id, &actions);

        // Engine emits DiscoverEndpoints — start probe worker
        self.start_endpoint_discovery_from_actions(link_id, &actions, tx);

        mgr_actions
    }

    /// Whether this node is itself proposing on `link_id`: asking the peer
    /// about Direct Link for a proposal, or running an initiator session
    /// that has not finished.
    pub(crate) fn proposing(&self, link_id: &[u8; 16]) -> bool {
        if matches!(
            self.peer_support.get(link_id),
            Some(PeerSupport::Querying { .. })
        ) {
            return true;
        }
        self.link_to_session
            .get(link_id)
            .and_then(|session_id| self.sessions.get(session_id))
            .is_some_and(|session| {
                session.engine.is_initiator()
                    && matches!(
                        session.engine.state(),
                        HolePunchState::Discovering
                            | HolePunchState::Proposing
                            | HolePunchState::WaitingReady
                            | HolePunchState::Punching
                    )
            })
    }

    /// Both sides proposed on the same link at once, and the peer's
    /// proposal wins (the link initiator's does): drop ours without
    /// reporting a failure, since the upgrade goes ahead with us as the
    /// responder.
    pub(crate) fn yield_proposal(&mut self, link_id: &[u8; 16]) {
        if matches!(
            self.peer_support.get(link_id),
            Some(PeerSupport::Querying { .. })
        ) {
            // The peer sent a request, so it implements Direct Link.
            self.peer_support.insert(*link_id, PeerSupport::Supported);
        }
        let ours = self
            .link_to_session
            .get(link_id)
            .and_then(|session_id| self.sessions.get(session_id))
            .is_some_and(|session| session.engine.is_initiator());
        if ours {
            self.remove_link_session(link_id);
        }
    }

    /// Responder: replies to resend when `payload` repeats the request of
    /// the session running on `link_id` (its earlier replies may have been
    /// lost). `None` for a new request.
    pub(crate) fn replay_for_repeated_request(
        &self,
        link_id: [u8; 16],
        payload: &[u8],
    ) -> Option<Vec<HolePunchManagerAction>> {
        let session_id = HolePunchEngine::request_session_id(payload).ok()?;
        let current = self.link_to_session.get(&link_id)?;
        if *current != session_id {
            return None;
        }
        let session = self.sessions.get(current)?;
        if session.engine.is_initiator() {
            return None;
        }
        Some(convert_engine_actions(
            link_id,
            &session.engine.replay_replies(),
        ))
    }

    /// Remove the session bound to `link_id`, stopping its punch thread.
    pub(super) fn remove_link_session(&mut self, link_id: &[u8; 16]) {
        if let Some(session_id) = self.link_to_session.remove(link_id) {
            if let Some(mut session) = self.sessions.remove(&session_id) {
                session.cancel_punch();
            }
        }
    }

    /// Whether another session (other than `except`) is probing or punching
    /// toward `target`.
    pub(super) fn target_in_use(&self, target: SocketAddr, except: Option<&[u8; 16]>) -> bool {
        self.sessions.iter().any(|(id, s)| {
            Some(id) != except
                && s.punch_target == Some(target)
                && (s.is_punching() || s.is_active_inbound())
        })
    }

    /// Abort and remove all active hole-punch sessions.
    pub(crate) fn abort_all_sessions(&mut self) {
        for (_, mut session) in self.sessions.drain() {
            if let Some(handle) = session.punch_handle.take() {
                handle.cancel();
            }
        }
        self.link_to_session.clear();
        self.peer_support.clear();
        self.reupgrades.clear();
    }
}
