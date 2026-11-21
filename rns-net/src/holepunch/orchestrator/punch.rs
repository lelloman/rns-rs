//! Discovering endpoints with probes and starting the punch.

use super::*;

pub(super) fn run_probe_worker(
    servers: Vec<SocketAddr>,
    protocol: ProbeProtocol,
    session_id: [u8; 16],
    link_id: [u8; 16],
    tx: EventSender,
    device: Option<String>,
    underlay_mark: Option<u32>,
) {
    match probe::probe_endpoint_failover_with_mark(
        &servers,
        protocol,
        std::time::Duration::from_secs(3),
        device.as_deref(),
        underlay_mark,
    ) {
        Ok((observed, socket, probe_server)) => {
            log::info!(
                "Probe discovered endpoint: {} via server {} for session {:02x?}",
                observed,
                probe_server,
                &session_id[..4]
            );
            let _ = tx.send(Event::HolePunchProbeResult {
                link_id,
                session_id,
                observed_addr: observed,
                socket,
                probe_server,
            });
        }
        Err(e) => {
            log::warn!(
                "Probe failed for session {:02x?} (tried {} servers): {}",
                &session_id[..4],
                servers.len(),
                e
            );
            let _ = tx.send(Event::HolePunchProbeFailed {
                link_id,
                session_id,
            });
        }
    }
}

/// The probe servers that can be used: not addresses synthesized from IPv4
/// by a translator (NAT64), whose reply would name the translator's IPv4
/// mapping for an IPv6 socket.
pub(super) fn usable_probe_servers(servers: Vec<SocketAddr>) -> Vec<SocketAddr> {
    servers
        .into_iter()
        .filter(|server| {
            let synthesized = crate::holepunch::admission::is_synthesized(&server.ip());
            if synthesized {
                log::warn!(
                    "Ignoring probe server {}: an address synthesized by NAT64, not a direct endpoint",
                    server
                );
            }
            !synthesized
        })
        .collect()
}

impl HolePunchManager {
    /// Start endpoint discovery if the engine actions contain a DiscoverEndpoints.
    pub(super) fn start_endpoint_discovery_from_actions(
        &self,
        link_id: [u8; 16],
        actions: &[HolePunchAction],
        tx: &EventSender,
    ) {
        for action in actions {
            if let HolePunchAction::DiscoverEndpoints {
                probe_addr,
                protocol,
            } = action
            {
                let session_id = match self.link_to_session.get(&link_id) {
                    Some(s) => *s,
                    None => continue,
                };

                let session = match self.sessions.get(&session_id) {
                    Some(s) => s,
                    None => continue,
                };

                // Initiator: try all configured servers with failover.
                // Responder: use only the facilitator from UPGRADE_REQUEST.
                let servers: Vec<SocketAddr> = if session.engine.is_initiator() {
                    self.probe_addrs.clone()
                } else {
                    match self.endpoint_allowed(probe_addr) {
                        Some(a) => vec![a],
                        None => {
                            log::warn!("Invalid probe endpoint: {:?}", probe_addr);
                            continue;
                        }
                    }
                };

                if servers.is_empty() {
                    log::warn!(
                        "No probe servers available for session {:02x?}",
                        &session_id[..4]
                    );
                    continue;
                }

                if !self.spawn_workers {
                    continue;
                }

                let tx_clone = tx.clone();
                let session_id_copy = session_id;
                let device_clone = self.device.clone();
                let underlay_mark = self.underlay_mark;
                let protocol_copy = *protocol;

                if crate::engine::FOLD_SERVICES {
                    crate::holepunch::folded_probe::start(
                        crate::holepunch::folded_probe::ProbeJob {
                            servers,
                            protocol: protocol_copy,
                            session_id: session_id_copy,
                            link_id,
                            tx: tx_clone,
                            device: device_clone,
                            underlay_mark,
                            timeout: crate::holepunch::folded_probe::PROBE_TIMEOUT,
                        },
                    );
                    continue;
                }

                if let Err(e) =
                    thread::Builder::new()
                        .name("probe-worker".into())
                        .spawn(move || {
                            run_probe_worker(
                                servers,
                                protocol_copy,
                                session_id_copy,
                                link_id,
                                tx_clone,
                                device_clone,
                                underlay_mark,
                            );
                        })
                {
                    log::warn!("Failed to spawn probe worker: {}", e);
                }
            }
        }
    }

    /// Start punch if the engine actions contain a StartUdpPunch.
    pub(super) fn start_punch_from_actions(
        &mut self,
        link_id: [u8; 16],
        session_id: &[u8; 16],
        actions: &[HolePunchAction],
    ) -> Vec<HolePunchManagerAction> {
        let mut mgr_actions = Vec::new();
        for action in actions {
            if let HolePunchAction::StartUdpPunch {
                peer_public,
                peer_hosts,
                punch_token,
                ..
            } = action
            {
                mgr_actions.extend(self.start_punch_for_session(
                    link_id,
                    session_id,
                    peer_public,
                    peer_hosts,
                    punch_token,
                ));
            }
        }
        mgr_actions
    }

    pub(super) fn start_punch_for_session(
        &mut self,
        link_id: [u8; 16],
        session_id: &[u8; 16],
        peer_public: &Endpoint,
        peer_hosts: &[Endpoint],
        punch_token: &[u8; 32],
    ) -> Vec<HolePunchManagerAction> {
        let refusal = self.sessions.get(session_id).and_then(|session| {
            let target = self.endpoint_allowed(peer_public)?;
            self.punch_target_refusal(target, session.facilitator, session.observed)
        });
        if let Some(why) = refusal {
            log::warn!(
                "Not punching session {:02x?}: peer endpoint {:?} is {}",
                &session_id[..4],
                peer_public,
                why
            );
        }
        let peer_addr = self
            .endpoint_allowed(peer_public)
            .filter(|_| refusal.is_none());
        let running = self.sessions.values().filter(|s| s.is_punching()).count();
        let networks = if peer_hosts.is_empty() {
            Vec::new()
        } else {
            self.local_networks()
        };
        let target_busy = peer_addr
            .map(|addr| self.target_in_use(addr, Some(session_id)))
            .unwrap_or(false);

        let session = match self.sessions.get_mut(session_id) {
            Some(s) => s,
            None => return Vec::new(),
        };

        if session.punch_handle.is_some() {
            return Vec::new(); // Already punching
        }

        let peer_addr = match peer_addr {
            Some(a) if !target_busy && running < MAX_CONCURRENT_SESSIONS => a,
            other => {
                match other {
                    None if refusal.is_some() => {}
                    None => log::warn!(
                        "Not punching session {:02x?}: peer endpoint {:?} outside the accepted ranges",
                        &session_id[..4],
                        peer_public
                    ),
                    Some(a) => log::debug!(
                        "Not punching session {:02x?} to {}: target busy or {} punches running",
                        &session_id[..4],
                        a,
                        running
                    ),
                }
                session.socket = None;
                let actions = session.engine.punch_failed(time::now()).unwrap_or_default();
                return convert_engine_actions(link_id, &actions);
            }
        };
        session.punch_target = Some(peer_addr);

        // The peer's host candidates, if it is a neighbour behind our NAT.
        let facilitator = session.facilitator;
        let hosts: Vec<SocketAddr> = match session.observed {
            Some(observed) => peer_hosts
                .iter()
                .filter_map(endpoint_to_socket_addr)
                .filter(|host| {
                    let refusal = crate::holepunch::candidates::host_candidate_refusal(
                        *host, &networks, observed, peer_addr,
                    )
                    .or_else(|| {
                        facilitator
                            .into_iter()
                            .chain(self.probe_addrs.iter().copied())
                            .any(|f| canonical(f) == canonical(*host))
                            .then_some("a facilitator")
                    });
                    if let Some(why) = refusal {
                        log::debug!(
                            "Not punching host candidate {} of session {:02x?}: {}",
                            host,
                            &session_id[..4],
                            why
                        );
                    }
                    refusal.is_none()
                })
                .collect(),
            None => Vec::new(),
        };
        let session = match self.sessions.get_mut(session_id) {
            Some(s) => s,
            None => return Vec::new(),
        };
        session.candidates = std::iter::once((peer_addr, DirectCandidateKind::Reflexive))
            .chain(hosts.iter().map(|h| (*h, DirectCandidateKind::Host)))
            .collect();

        if !self.spawn_workers {
            return Vec::new();
        }

        let socket = match session.socket.take() {
            Some(s) => s,
            None => {
                log::warn!("No socket available for punching");
                return Vec::new();
            }
        };

        let punch_token_copy = *punch_token;
        let session_id_copy = *session.engine.session_id();

        log::info!(
            "Starting UDP hole punch for session {:02x?} to {}",
            &session_id_copy[..4],
            peer_addr
        );

        let started = match &self.event_tx {
            Some(tx) if crate::engine::FOLD_SERVICES => puncher::start_udp_punch_on_loop(
                socket,
                vec![peer_addr],
                hosts,
                session_id_copy,
                punch_token_copy,
                tx,
            ),
            _ => puncher::start_udp_punch(
                socket,
                vec![peer_addr],
                hosts,
                session_id_copy,
                punch_token_copy,
            ),
        };
        match started {
            Ok(handle) => {
                session.punch_handle = Some(handle);
            }
            Err(e) => {
                log::warn!("Failed to start UDP punch: {}", e);
            }
        }
        Vec::new()
    }

    /// Called when a probe result arrives from the worker thread.
    pub fn handle_probe_result(
        &mut self,
        link_id: [u8; 16],
        session_id: [u8; 16],
        observed_addr: SocketAddr,
        socket: UdpSocket,
        probe_server: SocketAddr,
    ) -> Vec<HolePunchManagerAction> {
        // A mapping of another family than the socket's (a probe that went
        // through a translator) or a synthesized one cannot be punched.
        let socket_v4 = socket.local_addr().map(|a| a.is_ipv4()).unwrap_or(true);
        let observed_v4 = canonical(observed_addr).is_ipv4();
        if crate::holepunch::admission::is_synthesized(&observed_addr.ip())
            || (socket_v4 && !observed_v4)
            || (!socket_v4 && observed_v4 && !observed_addr.is_ipv6())
        {
            log::warn!(
                "Probe of session {:02x?} reported {} for a socket of another family; not usable",
                &session_id[..4],
                observed_addr
            );
            return self.handle_probe_failed(link_id, session_id);
        }
        let networks = self.local_networks();
        let session = match self.sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return Vec::new(),
        };

        // Our host candidates, for a peer on the same network.
        let hosts = match socket.local_addr() {
            Ok(local) => crate::holepunch::candidates::host_candidates(
                &networks,
                self.device.as_deref(),
                local.port(),
                observed_addr,
            ),
            Err(_) => Vec::new(),
        };
        session.engine.set_host_endpoints(
            hosts
                .iter()
                .map(|host| Endpoint {
                    addr: match host {
                        SocketAddr::V4(v4) => v4.ip().octets().to_vec(),
                        SocketAddr::V6(v6) => v6.ip().octets().to_vec(),
                    },
                    port: host.port(),
                })
                .collect(),
        );

        // Store the socket for reuse during punching (same NAT mapping)
        session.socket = Some(socket);
        session.facilitator = Some(probe_server);
        session.observed = Some(observed_addr);

        // If a different server succeeded than the first configured one,
        // update the engine's facilitator so UPGRADE_REQUEST carries the correct address.
        if session.engine.is_initiator() {
            let first = self.probe_addrs.first().copied();
            if first != Some(probe_server) {
                let facilitator_ep = Endpoint {
                    addr: match probe_server {
                        SocketAddr::V4(v4) => v4.ip().octets().to_vec(),
                        SocketAddr::V6(v6) => v6.ip().octets().to_vec(),
                    },
                    port: probe_server.port(),
                };
                session.engine.set_facilitator(facilitator_ep);
            }
        }

        // Bump-to-top: move the successful server to index 0
        if let Some(idx) = self.probe_addrs.iter().position(|a| *a == probe_server) {
            if let Some(moved) = self.probe_addrs.get_mut(..=idx) {
                moved.rotate_right(1);
            }
        }

        let public_endpoint = Endpoint {
            addr: match observed_addr {
                SocketAddr::V4(v4) => v4.ip().octets().to_vec(),
                SocketAddr::V6(v6) => v6.ip().octets().to_vec(),
            },
            port: observed_addr.port(),
        };

        let now = time::now();
        let actions = match session.engine.endpoints_discovered(public_endpoint, now) {
            Ok(a) => a,
            Err(e) => {
                log::warn!("Error in endpoints_discovered: {}", e);
                return Vec::new();
            }
        };

        let mut mgr_actions = convert_engine_actions(link_id, &actions);

        // Check if engine now wants to start punching (responder after discovery)
        mgr_actions.extend(self.start_punch_from_actions(link_id, &session_id, &actions));

        mgr_actions
    }

    /// Called when a probe fails.
    pub fn handle_probe_failed(
        &mut self,
        link_id: [u8; 16],
        session_id: [u8; 16],
    ) -> Vec<HolePunchManagerAction> {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return Vec::new();
        };
        // A responder tells the initiator instead of leaving it waiting;
        // the failed session is cleaned up on the next tick.
        match session.engine.discovery_failed(time::now()) {
            Ok(actions) => convert_engine_actions(link_id, &actions),
            Err(_) => Vec::new(),
        }
    }
}
