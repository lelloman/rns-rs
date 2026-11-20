//! Path requests: sending them, rediscovering lost paths, and answering
//! for a local client's destinations.

use super::*;

impl Driver {
    /// Emit a path request for a destination, as `Transport.request_path`
    /// without an interface.
    ///
    /// The request is `dest_hash || transport_id || random_tag`; since
    /// Reticulum 1.6.0 (upstream 156c7323) it always carries the transport
    /// identity. With `STAMP_PRS` the request also needs a stamp over the
    /// destination hash and tag: a cached one is appended at once, otherwise
    /// the request is recorded as pending and handed to the stamper, which
    /// posts it back as `Event::SendStampedPathRequest`.
    pub(crate) fn handle_request_path(&mut self, dest_hash: [u8; 16]) {
        let mut tag = [0u8; 16];
        self.rng.fill_bytes(&mut tag);

        if self.engine.stamp_prs() {
            match self
                .stamps
                .stamper
                .cached_path_request_stamp(&dest_hash, &tag)
            {
                Some(stamp) => {
                    let payload = rns_core::stamp::path_request_ext_payload(&stamp, 0);
                    let mut ext_payload = [0u8; rns_core::constants::PR_EXT_PAYLOAD_LENGTH];
                    ext_payload.copy_from_slice(&payload);
                    self.send_path_request(
                        dest_hash,
                        &tag,
                        Some(&ext_payload),
                        PathRequestTarget::All,
                    );
                }
                None => {
                    self.engine
                        .record_outbound_path_request(dest_hash, time::now());
                    self.enqueue_path_request_stamp(
                        dest_hash,
                        tag.to_vec(),
                        PathRequestTarget::All,
                    );
                }
            }
            return;
        }
        self.send_path_request(dest_hash, &tag, None, PathRequestTarget::All);
    }

    /// A link this node initiated was never established (Transport.py
    /// 842-862). A transport node leaves its path alone: the link table job
    /// rediscovers paths for the links it forwards. So does any node for an
    /// instance-local (hops-0) destination (upstream 5bd93ad9). Any other
    /// node expires the path, and unless a shared instance will send the
    /// request for it, queues a new path request at most every
    /// `PATH_REQUEST_MI` seconds.
    pub(crate) fn rediscover_path_after_failed_link(&mut self, dest_hash: [u8; 16]) {
        let local_destination = self.engine.hops_to(&dest_hash) == Some(0);
        if local_destination || self.engine.transport_enabled() {
            return;
        }
        self.engine.expire_path(&dest_hash);
        if self.connected_to_shared_instance {
            return;
        }
        let now = time::now();
        let throttled = self
            .engine
            .last_path_request(&dest_hash)
            .is_some_and(|requested_at| now - requested_at <= rns_core::constants::PATH_REQUEST_MI);
        if !throttled {
            log::trace!(target: rns_core::logging::PATHING_LOG_TARGET,
                "Trying to rediscover path for {:02x?} since an attempted link was never established",
                &dest_hash[..4]
            );
            self.engine.queue_path_rediscovery(dest_hash, None, now);
        }
    }

    /// `Transport.handle_disovery_path_requests` for one queued destination.
    ///
    /// Without an interface to skip this is a plain path request. Otherwise
    /// one request with a new tag goes out on every other interface; with
    /// `STAMP_PRS` its stamp is ground once and the same stamped request is
    /// sent everywhere (upstream acb38a8a). Like `stamp_path_request`, the
    /// stamp cache is checked first, though a fresh tag never hits it.
    pub(crate) fn rediscover_path(
        &mut self,
        dest_hash: [u8; 16],
        skip_interface: Option<InterfaceId>,
    ) {
        let Some(skip_interface) = skip_interface else {
            self.handle_request_path(dest_hash);
            return;
        };
        let target = PathRequestTarget::AllExcept(skip_interface);
        let mut tag = [0u8; 16];
        self.rng.fill_bytes(&mut tag);
        if self.engine.stamp_prs() {
            log::trace!(target: rns_core::logging::PATHING_LOG_TARGET,
                "Stamping discovery path request for {:02x?}",
                &dest_hash[..4]
            );
            match self
                .stamps
                .stamper
                .cached_path_request_stamp(&dest_hash, &tag)
            {
                Some(stamp) => {
                    let payload = rns_core::stamp::path_request_ext_payload(&stamp, 0);
                    let mut ext_payload = [0u8; rns_core::constants::PR_EXT_PAYLOAD_LENGTH];
                    ext_payload.copy_from_slice(&payload);
                    self.send_path_request(dest_hash, &tag, Some(&ext_payload), target);
                }
                None => {
                    self.engine
                        .record_outbound_path_request(dest_hash, time::now());
                    self.enqueue_path_request_stamp(dest_hash, tag.to_vec(), target);
                }
            }
            return;
        }
        self.send_path_request(dest_hash, &tag, None, target);
    }

    /// `Transport.enqueue_stamped_pr`: a full queue drops the request.
    pub(crate) fn enqueue_path_request_stamp(
        &mut self,
        dest_hash: [u8; 16],
        tag: Vec<u8>,
        target: PathRequestTarget,
    ) {
        let job = crate::stamper::PathRequestStampJob {
            destination_hash: dest_hash,
            tag,
            target,
        };
        if self.stamps.stamper.enqueue_path_request(job).is_err() {
            log::debug!(
                "Stamp queue full, dropping path request for {:02x?}",
                &dest_hash[..4]
            );
        }
    }

    /// Build and send a path request frame: broadcast, on one interface
    /// alone when forwarding a local client's request, or on every interface
    /// but one when rediscovering a path.
    pub(crate) fn send_path_request(
        &mut self,
        dest_hash: [u8; 16],
        tag: &[u8],
        ext_payload: Option<&[u8; rns_core::constants::PR_EXT_PAYLOAD_LENGTH]>,
        target: PathRequestTarget,
    ) {
        let Some(raw) = self.engine.build_path_request(&dest_hash, tag, ext_payload) else {
            return;
        };
        let now = time::now();
        match target {
            PathRequestTarget::Interface(interface) => {
                self.dispatch_all(vec![TransportAction::SendOnInterface {
                    interface,
                    raw: raw.into(),
                }]);
            }
            PathRequestTarget::AllExcept(skip_interface) => {
                self.engine.record_outbound_path_request(dest_hash, now);
                let raw: PacketBytes = raw.into();
                let actions = self
                    .engine
                    .out_capable_interfaces()
                    .filter(|interface| *interface != skip_interface)
                    .map(|interface| TransportAction::SendOnInterface {
                        interface,
                        raw: raw.clone(),
                    })
                    .collect();
                self.dispatch_all(actions);
            }
            PathRequestTarget::All => {
                let Ok(packet) = RawPacket::unpack(&raw) else {
                    return;
                };
                self.engine.record_outbound_path_request(dest_hash, now);
                let actions = self.engine.handle_outbound(
                    &packet,
                    rns_core::constants::DESTINATION_PLAIN,
                    None,
                    now,
                );
                self.dispatch_all(actions);
            }
        }
    }

    /// How long a path-response announce is replayed for a repeated tag
    /// (Python `Destination.PR_TAG_WINDOW`).
    pub(crate) const LOCAL_PATH_RESPONSE_WINDOW: f64 = 30.0;

    /// Upper bound on cached path-response announces.
    pub(crate) const LOCAL_PATH_RESPONSE_MAX_ENTRIES: usize = 1024;

    /// Answer a path request for a destination hosted on this node, as Python
    /// `Transport.path_request()` does with
    /// `destination.announce(path_response=True, tag=tag, attached_interface=...)`.
    ///
    /// The announce has context `PATH_RESPONSE` and goes out only on the
    /// interface the request arrived on. A repeated tag within
    /// `LOCAL_PATH_RESPONSE_WINDOW` replays the same bytes, like
    /// `Destination.path_responses`.
    pub(crate) fn answer_local_path_request(
        &mut self,
        dest_hash: [u8; 16],
        tag: Vec<u8>,
        interface: InterfaceId,
    ) {
        let now = time::now();
        self.expire_local_path_responses(now);

        let key = (dest_hash, tag);
        let raw = if let Some((_, raw)) = self.path_responses.local_cache.get(&key) {
            raw.clone()
        } else {
            let waiting = WaitingPathResponse::Answer {
                tag: key.1.clone(),
                interface,
            };
            let Some(raw) = self.build_local_path_response(&dest_hash, now, Some(waiting)) else {
                return;
            };
            if self.path_responses.local_cache.len() >= Self::LOCAL_PATH_RESPONSE_MAX_ENTRIES {
                if let Some(oldest) = self
                    .path_responses
                    .local_cache
                    .iter()
                    .min_by(|a, b| a.1 .0.total_cmp(&b.1 .0))
                    .map(|(key, _)| key.clone())
                {
                    self.path_responses.local_cache.remove(&oldest);
                }
            }
            self.path_responses
                .local_cache
                .insert(key, (now, raw.clone()));
            raw
        };
        self.send_local_path_response(dest_hash, &raw, interface, now);
    }

    /// Send a path-response announce for a local destination on the
    /// interface its path request came from.
    pub(super) fn send_local_path_response(
        &mut self,
        dest_hash: [u8; 16],
        raw: &[u8],
        interface: InterfaceId,
        now: f64,
    ) {
        let Ok(packet) = RawPacket::unpack(raw) else {
            return;
        };
        // Locally originated (hops 0), so the engine applies no announce
        // bandwidth queue, and an attached interface skips mode filtering.
        let actions = self.engine.handle_outbound(
            &packet,
            rns_core::constants::DESTINATION_SINGLE,
            Some(interface),
            now,
        );
        self.dispatch_all(actions);
        log::debug!(
            "Answered path request for local destination {:02x?} on interface {}",
            &dest_hash[..4],
            interface.0,
        );
    }

    /// Build the path-response announce of a destination registered with
    /// its identity, stamped as `Destination.announce` stamps it under
    /// `STAMP_DESTINATIONS`. Without a stamp store it goes out unstamped,
    /// as a node's own announces do. Without a stamp yet, a stamper job is
    /// queued and `waiting`, if any, is sent once the stamp is ready.
    pub(super) fn build_path_responder_announce(
        &mut self,
        dest_hash: &[u8; 16],
        waiting: Option<WaitingPathResponse>,
    ) -> Option<Vec<u8>> {
        let responder = self.path_responses.responders.get(dest_hash)?;
        let mut record = responder.record.clone();
        let store = self
            .stamps
            .stamper
            .stamp_store()
            .filter(|_| self.stamps.stamp_destinations.load(Ordering::Relaxed));
        if let Some(store) = store {
            let identity =
                rns_crypto::identity::Identity::from_private_key(&record.identity_prv_key);
            let public_key = identity.get_public_key()?;
            let material = rns_core::stamp::destination_stamp_material(
                dest_hash,
                &public_key,
                &record.name_hash,
            );
            let target = self
                .stamps
                .stamper
                .targets()
                .destination_target(&responder.destination);
            match store.load(dest_hash, &material, target) {
                Some((stamp, _value)) => {
                    let link_cost = self.link_manager.link_request_costs().get(dest_hash);
                    record.app_data =
                        Some(rns_core::stamp::announce_ext_payload(&stamp, 0, link_cost));
                }
                None => {
                    let waiting = waiting?;
                    let job = crate::stamper::DestinationStampJob {
                        dest: responder.destination.clone(),
                        identity_prv_key: record.identity_prv_key,
                    };
                    if self
                        .stamps
                        .stamper
                        .enqueue_path_response_stamp(job)
                        .is_err()
                    {
                        log::debug!(
                            "Stamp queue full, dropping path response for {:02x?}",
                            &dest_hash[..4]
                        );
                        return None;
                    }
                    self.path_responses
                        .waiting_for_stamp
                        .entry(*dest_hash)
                        .or_default()
                        .push(waiting);
                    return None;
                }
            }
        }
        self.build_shared_announce_raw(dest_hash, &record, true)
    }

    /// Announce a destination registered with its identity as a path
    /// response on every interface.
    pub(crate) fn send_path_responder_announce(&mut self, dest_hash: [u8; 16]) {
        if let Some(raw) =
            self.build_path_responder_announce(&dest_hash, Some(WaitingPathResponse::Broadcast))
        {
            self.send_shared_path_response_raw(&dest_hash, &raw);
        }
    }

    /// Send the path responses that waited for `dest_hash`'s stamp. One
    /// that still finds no stamp (it could not be persisted) is dropped.
    pub(super) fn send_stamp_waiting_path_responses(&mut self, dest_hash: [u8; 16]) {
        let Some(waiting) = self.path_responses.waiting_for_stamp.remove(&dest_hash) else {
            return;
        };
        let now = time::now();
        for waiting in waiting {
            let Some(raw) = self.build_path_responder_announce(&dest_hash, None) else {
                continue;
            };
            match waiting {
                WaitingPathResponse::Broadcast => {
                    self.send_shared_path_response_raw(&dest_hash, &raw);
                }
                WaitingPathResponse::Answer { tag, interface } => {
                    self.path_responses
                        .local_cache
                        .insert((dest_hash, tag), (now, raw.clone()));
                    self.send_local_path_response(dest_hash, &raw, interface, now);
                }
            }
        }
    }

    /// Drop path-response announces older than the replay window.
    pub(crate) fn expire_local_path_responses(&mut self, now: f64) {
        self.path_responses
            .local_cache
            .retain(|_, (created, _)| now - *created <= Self::LOCAL_PATH_RESPONSE_WINDOW);
    }

    /// Build a fresh `PATH_RESPONSE` announce for a local destination.
    ///
    /// A destination registered with its identity but not announced has no
    /// stamp in its record: when its stamp is not ground yet, `waiting` is
    /// sent once the stamper has it, and nothing is built now.
    pub(crate) fn build_local_path_response(
        &mut self,
        dest_hash: &[u8; 16],
        now: f64,
        waiting: Option<WaitingPathResponse>,
    ) -> Option<Vec<u8>> {
        if let Some(destination) = self.enabled_builtin_destination(dest_hash) {
            return self.build_builtin_announce(destination, now, true);
        }

        if let Some(record) = self.path_responses.shared_announces.get(dest_hash).cloned() {
            return self.build_shared_announce_raw(dest_hash, &record, true);
        }

        // Registered with its identity but never announced: announce it on
        // demand, as upstream does from the Destination object.
        if self.path_responses.responders.contains_key(dest_hash) {
            return self.build_path_responder_announce(dest_hash, waiting);
        }

        log::debug!(
            "Cannot answer path request for local destination {:02x?}: no announce record",
            &dest_hash[..4],
        );
        None
    }
}
