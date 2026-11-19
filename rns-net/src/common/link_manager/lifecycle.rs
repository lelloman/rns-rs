//! Keeping links alive, timing them out and tearing them down.

use super::*;

impl LinkManager {
    /// Tear down a link.
    pub fn teardown_link(&mut self, link_id: &LinkId) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let previous_state = link.engine.state();
        if previous_state == LinkState::Closed {
            return Vec::new();
        }

        // Pending links have not established link encryption and are closed
        // locally without transmitting LINKCLOSE.
        let close_packet = if previous_state == LinkState::Pending {
            None
        } else {
            Self::linkclose_packet(&link.engine, link_id)
        };
        let teardown_actions = link.engine.teardown();
        if let Some(ref mut channel) = link.channel {
            channel.shutdown();
        }

        let mut actions = self.process_link_actions(link_id, &teardown_actions);
        actions.extend(close_packet);
        actions
    }

    /// Build the LINKCLOSE packet announcing this link's teardown to the peer.
    ///
    /// Mirrors Python `Link.__teardown_packet`: a link DATA packet with
    /// context LINKCLOSE whose payload is the link id encrypted with the link
    /// key. Returns `None` when the link has no session key yet.
    pub(super) fn linkclose_packet(
        engine: &LinkEngine,
        link_id: &LinkId,
    ) -> Option<LinkManagerAction> {
        let encrypted_close = engine.encrypt(link_id, &mut OsRng).ok()?;
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let (raw, _packet_hash) = RawPacket::pack_raw_with_hash(
            flags,
            0,
            link_id,
            None,
            constants::CONTEXT_LINKCLOSE,
            &encrypted_close,
        )
        .ok()?;
        Some(LinkManagerAction::SendPacket {
            raw: raw.into(),
            dest_type: constants::DESTINATION_LINK,
            attached_interface: None,
        })
    }

    /// A KEEPALIVE packet: `0xff` is the initiator's probe, `0xfe` the
    /// responder's answer, as upstream.
    pub(super) fn keepalive_packet(link_id: &LinkId, payload: u8) -> Option<LinkManagerAction> {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let (raw, _packet_hash) = RawPacket::pack_raw_with_hash(
            flags,
            0,
            link_id,
            None,
            constants::CONTEXT_KEEPALIVE,
            &[payload],
        )
        .ok()?;
        Some(LinkManagerAction::SendPacket {
            raw: raw.into(),
            dest_type: constants::DESTINATION_LINK,
            attached_interface: None,
        })
    }

    /// Tear down all managed links.
    pub fn teardown_all_links(&mut self) -> Vec<LinkManagerAction> {
        let link_ids: Vec<LinkId> = self.links.keys().copied().collect();
        let mut actions = Vec::new();
        for link_id in link_ids {
            actions.extend(self.teardown_link(&link_id));
        }
        actions
    }

    /// Periodic tick: check keepalive, stale, timeouts for all links.
    pub fn tick(&mut self, rng: &mut dyn Rng) -> Vec<LinkManagerAction> {
        self.tick_at(time::now(), rng)
    }

    /// [`Self::tick`] at an explicit time.
    pub(crate) fn tick_at(&mut self, now: f64, rng: &mut dyn Rng) -> Vec<LinkManagerAction> {
        let mut all_actions = Vec::new();
        self.sweep_decryptions();
        self.sweep_built_segments();

        // Collect link_ids to avoid borrow issues
        let link_ids: Vec<LinkId> = self.links.keys().copied().collect();

        for link_id in &link_ids {
            let link = match self.links.get_mut(link_id) {
                Some(l) => l,
                None => continue,
            };

            // Run the engine's watchdog. Like Python's, it asks for the
            // keepalive probe before it marks the link stale in the same
            // run, so the probe goes out first and its answer can recover
            // the link.
            let previous_state = link.engine.state();
            let tick_actions = link.engine.tick(now);
            if tick_actions
                .iter()
                .any(|action| matches!(action, LinkAction::SendKeepalive { .. }))
            {
                log::debug!("Link keepalive probe queued: link={:02x?}", &link_id[..4]);
                all_actions.extend(Self::keepalive_packet(link_id, 0xff));
            }
            // Python's watchdog sends LINKCLOSE (from either role) right
            // before closing a stale link with reason TIMEOUT, so the peer
            // tears the link down too. Establishment timeouts (PENDING /
            // HANDSHAKE) close silently, as upstream does.
            if previous_state == LinkState::Stale && link.engine.state() == LinkState::Closed {
                if let Some(channel) = link.channel.as_mut() {
                    channel.shutdown();
                }
                all_actions.extend(Self::linkclose_packet(&link.engine, link_id));
            }
            all_actions.extend(self.process_link_actions(link_id, &tick_actions));

            let link = match self.links.get_mut(link_id) {
                Some(l) => l,
                None => continue,
            };
            if let Some(channel) = link.channel.as_mut() {
                let chan_actions = channel.tick(now);
                let _ = channel;
                let _ = link;
                all_actions.extend(self.process_channel_actions(link_id, chan_actions, rng));
            }
        }

        // Tick resource senders and receivers
        for link_id in &link_ids {
            let link = match self.links.get_mut(link_id) {
                Some(l) => l,
                None => continue,
            };

            // Tick outgoing resources (senders)
            let mut sender_actions = Vec::new();
            let mut failed_splits = Vec::new();
            for sender in &mut link.outgoing_resources {
                let actions = sender.tick(now);
                if sender.flags.split
                    && actions.iter().any(|action| {
                        matches!(action, rns_core::resource::ResourceAction::Failed(_))
                    })
                {
                    failed_splits.push(sender.original_hash);
                    if let Some(stream) = link.outgoing_streams.remove(&sender.original_hash) {
                        // As when a proof fails it: the stream reports the failure.
                        all_actions.push(LinkManagerAction::ResourceStreamFailed {
                            link_id: *link_id,
                            transfer_id: stream.transfer_id,
                            error: ResourceTransferError::Protocol(
                                rns_core::resource::ResourceError::Timeout.to_string(),
                            ),
                        });
                        sender_actions.extend(actions.into_iter().filter(|action| {
                            !matches!(action, rns_core::resource::ResourceAction::Failed(_))
                        }));
                        continue;
                    }
                }
                sender_actions.extend(actions);
            }
            if !failed_splits.is_empty() {
                // Later segments already prepared go with the failed one.
                link.outgoing_resources
                    .retain(|s| !s.flags.split || !failed_splits.contains(&s.original_hash));
            }

            // Tick incoming resources (receivers)
            let mut receiver_actions = Vec::new();
            for receiver in &mut link.incoming_resources {
                let decrypt_fn = |parts: &[&[u8]], skip: usize| -> Result<Vec<u8>, ()> {
                    link.engine.decrypt_chunks(parts, skip).map_err(|_| ())
                };
                receiver_actions.extend(receiver.tick(now, &decrypt_fn, &Bzip2Compressor));
            }

            let failed_request_ids: Vec<[u8; 16]> = link
                .outgoing_resources
                .iter()
                .filter(|sender| {
                    sender.flags.is_request
                        && sender.status >= rns_core::resource::ResourceStatus::Failed
                })
                .filter_map(|sender| Self::response_request_id(&sender.request_id))
                .collect();
            for request_id in failed_request_ids {
                link.pending_requests.remove(&request_id);
            }
            // Upstream's request timeout: the receipt fails and the
            // requester's failed callback runs.
            let expired: Vec<[u8; 16]> = link
                .pending_requests
                .iter()
                .filter(|(_, request)| request.deadline.is_some_and(|expires_at| now > expires_at))
                .map(|(request_id, _)| *request_id)
                .collect();
            for request_id in expired {
                link.pending_requests.remove(&request_id);
                all_actions.push(LinkManagerAction::RequestFailed {
                    link_id: *link_id,
                    request_id,
                    reason: RequestFailure::TimedOut,
                });
            }

            // Clean up completed/failed resources
            link.outgoing_resources
                .retain(|s| s.status < rns_core::resource::ResourceStatus::Complete);
            link.incoming_resources
                .retain(|r| r.status < rns_core::resource::ResourceStatus::Complete);
            link.concluded_incoming.clear();
            let active_split_hashes: Vec<[u8; 32]> = link
                .outgoing_resources
                .iter()
                .filter(|s| s.flags.split)
                .map(|s| s.original_hash)
                .collect();
            link.outgoing_splits.retain(|original_hash, split| {
                split.completed_segments < split.total_segments
                    && active_split_hashes.contains(original_hash)
            });

            let _ = link;
            all_actions.extend(self.process_resource_actions(link_id, sender_actions, rng));
            all_actions.extend(self.process_resource_actions(link_id, receiver_actions, rng));
        }

        // Clean up closed links
        let closed: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(_, l)| l.engine.state() == LinkState::Closed)
            .map(|(id, _)| *id)
            .collect();
        for id in closed {
            if let Some(link) = self.links.remove(&id) {
                if link.engine.is_initiator() && link.engine.activated_at().is_none() {
                    all_actions.push(LinkManagerAction::PendingLinkFailed {
                        dest_hash: *link.engine.destination_hash(),
                    });
                }
            }
            all_actions.push(LinkManagerAction::DeregisterLinkDest { link_id: id });
        }

        all_actions
    }

    /// Convert LinkActions to LinkManagerActions.
    pub(super) fn process_link_actions(
        &self,
        link_id: &LinkId,
        actions: &[LinkAction],
    ) -> Vec<LinkManagerAction> {
        let mut result = Vec::new();
        for action in actions {
            match action {
                LinkAction::StateChanged {
                    new_state, reason, ..
                } => {
                    log::debug!(
                        "Link state changed: link={:02x?} state={new_state:?} reason={reason:?}",
                        &link_id[..4]
                    );
                    if new_state == &LinkState::Closed {
                        result.push(LinkManagerAction::LinkClosed {
                            link_id: *link_id,
                            reason: *reason,
                        });
                    }
                    if new_state == &LinkState::Stale
                        && self
                            .links
                            .get(link_id)
                            .is_some_and(|link| link.direct_route.is_some())
                    {
                        result.push(LinkManagerAction::DirectPathFailed { link_id: *link_id });
                    }
                }
                LinkAction::LinkEstablished {
                    rtt, is_initiator, ..
                } => {
                    let keepalive = self
                        .links
                        .get(link_id)
                        .map(|link| link.engine.keepalive_interval())
                        .unwrap_or_default();
                    log::debug!(
                        "Link timers established: link={:02x?} rtt={rtt:.6} keepalive={keepalive:.6} stale={:.6} initiator={is_initiator}",
                        &link_id[..4],
                        keepalive * rns_core::constants::LINK_STALE_FACTOR
                    );
                    let dest_hash = self
                        .links
                        .get(link_id)
                        .map(|l| l.dest_hash)
                        .unwrap_or([0u8; 16]);
                    let hops = self
                        .links
                        .get(link_id)
                        .map(|link| link.engine.expected_hops())
                        .unwrap_or(rns_core::constants::PATHFINDER_M);
                    let rebalanced_at = self
                        .links
                        .get(link_id)
                        .and_then(|link| link.engine.rebalanced_at());
                    result.push(LinkManagerAction::LinkEstablished {
                        link_id: *link_id,
                        dest_hash,
                        hops,
                        rebalanced_at,
                        rtt: *rtt,
                        is_initiator: *is_initiator,
                    });
                }
                LinkAction::RemoteIdentified {
                    identity_hash,
                    public_key,
                    ..
                } => {
                    result.push(LinkManagerAction::RemoteIdentified {
                        link_id: *link_id,
                        identity_hash: *identity_hash,
                        public_key: *public_key,
                    });
                }
                LinkAction::DataReceived { .. } => {
                    // Data delivery is handled at a higher level
                }
                LinkAction::SendKeepalive { .. } => {
                    // Sent by `tick_at`, which sees the watchdog's actions
                    // first.
                }
            }
        }
        result
    }
}
