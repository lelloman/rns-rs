//! The periodic tick: timeouts, retries and scheduled upgrades.

use super::*;

impl HolePunchManager {
    /// Tick all sessions for timeout checks.
    pub fn tick(&mut self, tx: &EventSender) -> Vec<HolePunchManagerAction> {
        let now = time::now();
        let mut all_actions = Vec::new();

        // Direct interfaces of closed links whose last packets have left.
        let mut retiring = std::mem::take(&mut self.retiring);
        retiring.retain(|(link_id, interface_id, due)| {
            if *due > now {
                return true;
            }
            all_actions.push(HolePunchManagerAction::RemoveDirectInterface {
                link_id: *link_id,
                interface_id: *interface_id,
            });
            false
        });
        self.retiring = retiring;

        // Links due to propose again after losing their direct path.
        for (link_id, entry) in self.reupgrades.iter_mut() {
            if !entry.in_flight && entry.due.is_some_and(|due| due <= now) {
                entry.due = None;
                entry.in_flight = true;
                all_actions.push(HolePunchManagerAction::Reupgrade { link_id: *link_id });
            }
        }

        // Peers asked whether they implement Direct Link: ask again, and
        // after HELLO_TIMEOUT of silence fail the waiting proposal.
        let mut unanswered = Vec::new();
        for (link_id, support) in self.peer_support.iter_mut() {
            if let PeerSupport::Querying { since, last_sent } = support {
                if now - *since >= HELLO_TIMEOUT {
                    unanswered.push(*link_id);
                } else if now - *last_sent >= HELLO_RETRY_INTERVAL {
                    *last_sent = now;
                    all_actions.push(hello(*link_id, true));
                }
            }
        }
        for link_id in unanswered {
            self.peer_support.remove(&link_id);
            log::debug!(
                "Link peer {:02x?} did not answer HELLO: Direct Link unsupported",
                &link_id[..4]
            );
            all_actions.push(HolePunchManagerAction::DirectConnectFailed {
                link_id,
                session_id: [0u8; 16],
                reason: REJECT_UNSUPPORTED,
            });
        }

        // Build a snapshot of session IDs and their corresponding link IDs
        let session_link_pairs: Vec<([u8; 16], Option<[u8; 16]>)> = self
            .sessions
            .keys()
            .map(|sid| {
                let link_id = self
                    .link_to_session
                    .iter()
                    .find(|(_, v)| *v == sid)
                    .map(|(k, _)| *k);
                (*sid, link_id)
            })
            .collect();

        // Collect results from punch handles
        struct PunchCompletion {
            session_id: [u8; 16],
            link_id: [u8; 16],
            succeeded: bool,
            socket: Option<std::net::UdpSocket>,
            peer_addr: Option<SocketAddr>,
            learned: Vec<SocketAddr>,
            rtt: Option<f64>,
        }
        let mut completions: Vec<PunchCompletion> = Vec::new();

        for (session_id, link_id) in &session_link_pairs {
            if let Some(session) = self.sessions.get_mut(session_id) {
                let punch_done = session
                    .punch_handle
                    .as_ref()
                    .map(|h| !h.is_running())
                    .unwrap_or(false);

                if punch_done {
                    let succeeded = session
                        .punch_handle
                        .as_ref()
                        .map(|h| h.succeeded())
                        .unwrap_or(false);

                    if let Some(link_id) = link_id {
                        if succeeded {
                            if let Some(handle) = session.punch_handle.take() {
                                if let Some(result) = handle.join() {
                                    let rtt_secs = result.rtt.as_secs_f64();
                                    completions.push(PunchCompletion {
                                        session_id: *session_id,
                                        link_id: *link_id,
                                        succeeded: true,
                                        socket: Some(result.socket),
                                        peer_addr: Some(result.peer_addr),
                                        learned: result.learned,
                                        rtt: Some(rtt_secs),
                                    });
                                }
                            }
                        } else {
                            session.punch_handle.take();
                            completions.push(PunchCompletion {
                                session_id: *session_id,
                                link_id: *link_id,
                                succeeded: false,
                                socket: None,
                                peer_addr: None,
                                learned: Vec::new(),
                                rtt: None,
                            });
                        }
                    }
                }
            }
        }

        // Process completions
        for completion in completions {
            if completion.succeeded {
                if let (Some(socket), Some(peer_addr)) = (completion.socket, completion.peer_addr) {
                    // Register direct interface
                    let interface_id =
                        rns_core::transport::types::InterfaceId(self.next_interface_id);
                    self.next_interface_id += 1;

                    let mut started = None;
                    let blackhole = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let initiated = self
                        .sessions
                        .get(&completion.session_id)
                        .is_some_and(|session| session.engine.is_initiator());
                    let mut candidates = self
                        .sessions
                        .get(&completion.session_id)
                        .map(|session| session.candidates.clone())
                        .unwrap_or_default();
                    candidates.extend(
                        completion
                            .learned
                            .iter()
                            .map(|addr| (*addr, DirectCandidateKind::PeerReflexive)),
                    );
                    let candidate = candidates
                        .iter()
                        .find(|(addr, _)| canonical(*addr) == canonical(peer_addr))
                        .map_or(DirectCandidateKind::PeerReflexive, |(_, kind)| *kind);
                    if let Some(session) = self.sessions.get(&completion.session_id) {
                        let params = udp_direct::DirectPathParams {
                            link_id: completion.link_id,
                            session_id: *session.engine.session_id(),
                            keepalive_key: *session.engine.keepalive_key(),
                            blackhole: blackhole.clone(),
                        };
                        match udp_direct::start_direct_interface(
                            socket,
                            peer_addr,
                            interface_id,
                            params,
                            tx.clone(),
                        ) {
                            Ok((writer, info)) => {
                                log::info!("Direct UDP interface started: {}", info.name);
                                started = Some((writer, info));
                            }
                            Err(e) => {
                                log::warn!("Failed to start direct interface: {}", e);
                            }
                        }
                    }

                    // Notify engine of success
                    if let Some(session) = self.sessions.get_mut(&completion.session_id) {
                        let peer_max_packet = session.engine.peer_max_packet();
                        let engine_actions =
                            session.engine.punch_succeeded(now).unwrap_or_default();
                        for action in engine_actions {
                            match action {
                                HolePunchAction::Succeeded { session_id } => {
                                    let Some((writer, info)) = started.take() else {
                                        all_actions.push(
                                            HolePunchManagerAction::DirectConnectFailed {
                                                link_id: completion.link_id,
                                                session_id,
                                                reason: rns_core::holepunch::types::FAIL_TIMEOUT,
                                            },
                                        );
                                        continue;
                                    };
                                    // One direct interface per link: a
                                    // repeated upgrade replaces the old one.
                                    if let Some(old) = self.direct.insert(
                                        completion.link_id,
                                        DirectPath {
                                            interface_id,
                                            session_id,
                                            blackhole: blackhole.clone(),
                                            initiated,
                                            since: now,
                                            peer_addr,
                                            candidate,
                                            candidates: candidates.clone(),
                                            rtt: completion.rtt.unwrap_or(0.0),
                                            mtu: udp_direct::DIRECT_MTU,
                                            mtu_discovered: false,
                                            peer_max_packet,
                                        },
                                    ) {
                                        all_actions.push(
                                            HolePunchManagerAction::RemoveDirectInterface {
                                                link_id: completion.link_id,
                                                interface_id: old.interface_id,
                                            },
                                        );
                                    }
                                    self.count(completion.link_id, |c| c.established += 1);
                                    if let Some(entry) =
                                        self.reupgrades.get_mut(&completion.link_id)
                                    {
                                        entry.in_flight = false;
                                        entry.due = None;
                                    }
                                    all_actions.push(
                                        HolePunchManagerAction::DirectConnectEstablished {
                                            link_id: completion.link_id,
                                            session_id,
                                            interface_id,
                                            writer,
                                            info: Box::new(info),
                                            rtt: completion.rtt.unwrap_or(0.0),
                                            mtu: udp_direct::DIRECT_MTU,
                                            peer_max_packet,
                                        },
                                    );
                                }
                                _ => {
                                    let mgr = convert_engine_actions(completion.link_id, &[action]);
                                    all_actions.extend(mgr);
                                }
                            }
                        }
                    }
                }
            } else {
                // Punch failed
                if let Some(session) = self.sessions.get_mut(&completion.session_id) {
                    let engine_actions = session.engine.punch_failed(now).unwrap_or_default();
                    let mgr = convert_engine_actions(completion.link_id, engine_actions.as_slice());
                    all_actions.extend(mgr);
                }
            }
        }

        // Tick engines for timeouts
        for (session_id, link_id) in &session_link_pairs {
            if let Some(link_id) = link_id {
                if let Some(session) = self.sessions.get_mut(session_id) {
                    let timeout_actions = session.engine.tick(now);
                    if !timeout_actions.is_empty() {
                        let mgr = convert_engine_actions(*link_id, timeout_actions.as_slice());
                        all_actions.extend(mgr);
                    }
                }
            }
        }

        // Clean up Failed sessions
        let failed_sessions: Vec<[u8; 16]> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.engine.state() == HolePunchState::Failed)
            .map(|(id, _)| *id)
            .collect();

        for session_id in failed_sessions {
            if let Some(mut session) = self.sessions.remove(&session_id) {
                session.cancel_punch();
            }
            self.link_to_session.retain(|_, v| *v != session_id);
        }

        all_actions
    }
}
