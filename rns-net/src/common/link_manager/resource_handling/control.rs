//! Resource requests, hashmap updates, proofs and cancels.

use super::*;

impl LinkManager {
    /// Handle resource request (CONTEXT_RESOURCE_REQ) — feed to sender,
    /// appending to `out`.
    pub(in crate::common::link_manager) fn handle_resource_req_into(
        &mut self,
        link_id: &LinkId,
        plaintext: &[u8],
        rng: &mut dyn Rng,
        out: &mut Vec<LinkManagerAction>,
    ) {
        let mut all_actions = core::mem::take(&mut self.resource_scratch);
        let Some(link) = self.links.get_mut(link_id) else {
            self.resource_scratch = all_actions;
            return;
        };

        let now = time::now();
        let mut progress_update = None;
        let mut progress_stream_hash = None;
        let mut segment_progress = None;
        // Requested parts are packed straight from the sender's data.
        let mut parts = core::mem::take(&mut self.resource_part_scratch);
        let mut part_sender = None;
        for (index, sender) in link.outgoing_resources.iter_mut().enumerate() {
            if sender.flags.split && sender.status == rns_core::resource::ResourceStatus::Queued {
                continue;
            }
            let before_sent = sender.sent_parts;
            let before = all_actions.len();
            let was_awaiting_proof =
                sender.status == rns_core::resource::ResourceStatus::AwaitingProof;
            sender.handle_request_parts_into(plaintext, now, &mut parts, &mut all_actions);
            if all_actions.len() > before || !parts.is_empty() {
                part_sender = Some(index);
                if !was_awaiting_proof
                    && sender.status == rns_core::resource::ResourceStatus::AwaitingProof
                    && sender.flags.split
                    && sender.segment_index < sender.total_segments
                    && link.outgoing_streams.contains_key(&sender.original_hash)
                {
                    self.stream_prebuilds.push((
                        *link_id,
                        sender.original_hash,
                        sender.segment_index,
                    ));
                }
                if sender.sent_parts != before_sent {
                    progress_stream_hash = Some(sender.original_hash);
                    segment_progress = Some((
                        (sender.sent_parts as f64 / sender.total_parts().max(1) as f64).min(1.0),
                        sender.transfer_size as u64,
                    ));
                    if sender.flags.split {
                        if let Some(split) = link.outgoing_splits.get_mut(&sender.original_hash) {
                            split.current_segment_index = sender.segment_index;
                            split.current_sent_parts = sender.sent_parts;
                            split.current_total_parts = sender.total_parts();
                            progress_update =
                                Some(Self::outgoing_split_progress(split, sender.sdu));
                        }
                    } else {
                        progress_update = Some((sender.sent_parts, sender.total_parts()));
                    }
                }
                break;
            }
        }

        let _ = link;
        if let Some(sender) = part_sender {
            for &part in &parts {
                if !self.resource_link_is_active(link_id) {
                    out.extend(self.abort_resources_on_inactive_link(link_id));
                    continue;
                }
                let data = self
                    .links
                    .get(link_id)
                    .and_then(|link| link.outgoing_resources.get(sender))
                    .and_then(|sender| sender.part_data(part));
                if let Some(data) = data {
                    // Parts are NOT link-encrypted — send raw as CONTEXT_RESOURCE
                    self.build_link_packet_into(link_id, constants::CONTEXT_RESOURCE, data, out);
                }
            }
        }
        parts.clear();
        self.resource_part_scratch = parts;
        self.process_resource_actions_into(link_id, all_actions.drain(..), rng, out);
        self.resource_scratch = all_actions;
        if let Some((segment_progress, transfer_size)) = segment_progress {
            out.push(LinkManagerAction::ResourceSegmentProgress {
                link_id: *link_id,
                segment_progress,
                transfer_size,
            });
        }
        if let Some((received, total)) = progress_update {
            if let Some((stream, transferred)) = progress_stream_hash.and_then(|hash| {
                self.links.get(link_id).and_then(|link| {
                    link.outgoing_streams.get(&hash).map(|stream| {
                        let transferred = if total == 0 {
                            0
                        } else {
                            stream.declared_length.saturating_mul(received as u64) / total as u64
                        };
                        (stream, transferred.min(stream.declared_length))
                    })
                })
            }) {
                out.push(LinkManagerAction::ResourceStreamProgress {
                    link_id: *link_id,
                    transfer_id: stream.transfer_id,
                    transferred,
                    total: stream.declared_length,
                });
            } else {
                out.push(LinkManagerAction::ResourceProgress {
                    link_id: *link_id,
                    received,
                    total,
                });
            }
        }
    }

    /// Handle resource HMU (CONTEXT_RESOURCE_HMU) — feed to receiver.
    pub(in crate::common::link_manager) fn handle_resource_hmu(
        &mut self,
        link_id: &LinkId,
        plaintext: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let now = time::now();
        let mut all_actions = Vec::new();
        for receiver in &mut link.incoming_resources {
            let resource_actions = receiver.handle_hashmap_update(plaintext, now);
            if !resource_actions.is_empty() {
                all_actions.extend(resource_actions);
                break;
            }
        }

        let _ = link;
        self.process_resource_actions(link_id, all_actions, rng)
    }

    /// Handle resource proof (CONTEXT_RESOURCE_PRF) — feed to sender.
    pub(in crate::common::link_manager) fn handle_resource_prf(
        &mut self,
        link_id: &LinkId,
        plaintext: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let now = time::now();
        let mut result_actions = Vec::new();
        let mut completed_sender = None;
        let mut completed_request_id = None;
        let mut failed_split = None;
        let mut failed_request_id = None;
        let proof_hash = plaintext.get(..32);
        for sender in &mut link.outgoing_resources {
            if proof_hash.is_some_and(|hash| hash != sender.resource_hash.as_slice()) {
                continue;
            }
            let resource_actions = sender.handle_proof(plaintext, now);
            if !resource_actions.is_empty() {
                if resource_actions
                    .iter()
                    .any(|action| matches!(action, ResourceAction::Completed))
                {
                    completed_sender = Some((
                        sender.original_hash,
                        sender.segment_index,
                        sender.total_segments,
                        sender.total_parts(),
                    ));
                    if sender.flags.is_request && sender.segment_index == sender.total_segments {
                        completed_request_id = Self::response_request_id(&sender.request_id);
                    }
                }
                if resource_actions
                    .iter()
                    .any(|action| matches!(action, ResourceAction::Failed(_)))
                {
                    failed_split = Some(sender.original_hash);
                }
                if resource_actions
                    .iter()
                    .any(|action| matches!(action, ResourceAction::Failed(_)))
                    && sender.flags.is_request
                {
                    failed_request_id = Self::response_request_id(&sender.request_id);
                }
                result_actions.extend(resource_actions);
                break;
            }
        }

        // Convert to LinkManagerActions
        let mut actions = Vec::new();
        let mut advertise_next = None;
        let mut stream_failure = None;
        // A next segment built on the builder thread, taken once `link` is
        // released; and the stream whose following segment to build then.
        let mut take_built = None;
        let mut schedule_next = None;
        for ra in result_actions {
            match ra {
                ResourceAction::Completed => {
                    if let Some((original_hash, segment_index, total_segments, total_parts)) =
                        completed_sender
                    {
                        if total_segments > 1 && segment_index < total_segments {
                            if let Some(split) = link.outgoing_splits.get_mut(&original_hash) {
                                split.completed_segments = segment_index;
                                split.current_segment_index = segment_index;
                                split.current_sent_parts = total_parts;
                                split.current_total_parts = total_parts;
                            }
                            if let Some(next) = link.outgoing_resources.iter_mut().find(|s| {
                                s.flags.split
                                    && s.original_hash == original_hash
                                    && s.segment_index == segment_index + 1
                            }) {
                                if let Some(split) = link.outgoing_splits.get_mut(&original_hash) {
                                    split.current_segment_index = next.segment_index;
                                    split.current_sent_parts = 0;
                                    split.current_total_parts = next.total_parts();
                                }
                                advertise_next = Some(next.advertise(now));
                                schedule_next = Some(original_hash);
                            } else if self
                                .segment_builder
                                .as_ref()
                                .is_some_and(|b| b.has(&(*link_id, original_hash)))
                            {
                                take_built = Some((original_hash, total_parts));
                            } else if let Some(mut stream) =
                                link.outgoing_streams.remove(&original_hash)
                            {
                                match Self::build_stream_segment(
                                    link,
                                    &mut stream,
                                    None,
                                    segment_index + 1,
                                    total_segments,
                                    Some(original_hash),
                                    rng,
                                    now,
                                ) {
                                    Ok(mut next) => {
                                        if let Some(split) =
                                            link.outgoing_splits.get_mut(&original_hash)
                                        {
                                            split.current_segment_index = next.segment_index;
                                            split.current_sent_parts = 0;
                                            split.current_total_parts = next.total_parts();
                                        }
                                        advertise_next = Some(next.advertise(now));
                                        link.outgoing_resources.push(next);
                                        link.outgoing_streams.insert(original_hash, stream);
                                    }
                                    Err(error) => {
                                        stream_failure = Some((stream.transfer_id, error));
                                        link.outgoing_splits.remove(&original_hash);
                                    }
                                }
                            }
                        } else {
                            link.outgoing_splits.remove(&original_hash);
                            if let Some(stream) = link.outgoing_streams.remove(&original_hash) {
                                actions.push(LinkManagerAction::ResourceStreamCompleted {
                                    link_id: *link_id,
                                    transfer_id: stream.transfer_id,
                                });
                            } else {
                                actions.push(LinkManagerAction::ResourceCompleted {
                                    link_id: *link_id,
                                });
                            }
                        }
                    } else {
                        actions.push(LinkManagerAction::ResourceCompleted { link_id: *link_id });
                    }
                }
                ResourceAction::Failed(e) => {
                    if let Some(original_hash) = failed_split {
                        link.outgoing_splits.remove(&original_hash);
                        if let Some(stream) = link.outgoing_streams.remove(&original_hash) {
                            actions.push(LinkManagerAction::ResourceStreamFailed {
                                link_id: *link_id,
                                transfer_id: stream.transfer_id,
                                error: ResourceTransferError::Protocol(e.to_string()),
                            });
                            continue;
                        }
                    }
                    actions.push(LinkManagerAction::ResourceFailed {
                        link_id: *link_id,
                        error: format!("{}", e),
                    });
                }
                _ => {}
            }
        }

        if let Some((transfer_id, error)) = stream_failure {
            actions.push(LinkManagerAction::ResourceStreamFailed {
                link_id: *link_id,
                transfer_id,
                error,
            });
        }

        if let Some(request_id) = completed_request_id {
            let default_deadline = Self::request_response_deadline(link, now);
            if let Some(entry) = link.pending_requests.get_mut(&request_id) {
                entry.deadline = Some(entry.timeout.map_or(default_deadline, |t| now + t));
            }
        }
        if let Some(request_id) = failed_request_id {
            link.pending_requests.remove(&request_id);
        }

        // Clean up completed/failed senders
        link.outgoing_resources
            .retain(|s| s.status < rns_core::resource::ResourceStatus::Complete);

        let _ = link;
        if let Some(next_actions) = advertise_next {
            actions.extend(self.process_resource_actions(link_id, next_actions, rng));
        }
        if let Some((original_hash, _)) = take_built {
            match self.take_built_segment(link_id, original_hash) {
                Some(Ok(mut next)) => {
                    if let Some(link) = self.links.get_mut(link_id) {
                        if let Some(split) = link.outgoing_splits.get_mut(&original_hash) {
                            split.current_segment_index = next.segment_index;
                            split.current_sent_parts = 0;
                            split.current_total_parts = next.total_parts();
                        }
                        let advertisement = next.advertise(now);
                        link.outgoing_resources.push(next);
                        actions.extend(self.process_resource_actions(link_id, advertisement, rng));
                        schedule_next = Some(original_hash);
                    }
                }
                Some(Err(error)) => {
                    if let Some(link) = self.links.get_mut(link_id) {
                        link.outgoing_splits.remove(&original_hash);
                        if let Some(stream) = link.outgoing_streams.remove(&original_hash) {
                            actions.push(LinkManagerAction::ResourceStreamFailed {
                                link_id: *link_id,
                                transfer_id: stream.transfer_id,
                                error,
                            });
                        }
                    }
                }
                // Lost with a failed builder: the stream cannot go on.
                None => {
                    if let Some(link) = self.links.get_mut(link_id) {
                        link.outgoing_splits.remove(&original_hash);
                        if let Some(stream) = link.outgoing_streams.remove(&original_hash) {
                            actions.push(LinkManagerAction::ResourceStreamFailed {
                                link_id: *link_id,
                                transfer_id: stream.transfer_id,
                                error: ResourceTransferError::Protocol(
                                    "stream segment build lost".into(),
                                ),
                            });
                        }
                    }
                }
            }
        }
        if let Some(original_hash) = schedule_next {
            self.schedule_segment_build(link_id, original_hash);
        }

        actions
    }

    /// Cancel only the incoming transfer named by an authenticated ICL packet.
    pub(in crate::common::link_manager) fn handle_resource_icl(
        &mut self,
        link_id: &LinkId,
        resource_hash: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let Some(hash) = Self::resource_hash_key(resource_hash) else {
            return Vec::new();
        };
        let Some(link) = self.links.get_mut(link_id) else {
            return Vec::new();
        };
        let Some(idx) = link.incoming_resources.iter().position(|receiver| {
            receiver.resource_hash == hash
                && receiver.status < rns_core::resource::ResourceStatus::Complete
        }) else {
            return Vec::new();
        };
        let mut receiver = link.incoming_resources.remove(idx);
        if receiver.flags.split {
            if let Some(original) = Self::resource_hash_key(&receiver.original_hash) {
                link.incoming_resources
                    .retain(|r| !r.flags.split || r.original_hash != original);
                if let Some(IncomingSplitTransfer {
                    storage: IncomingSplitStorage::File { file, path, .. },
                    ..
                }) = link.incoming_splits.remove(&original)
                {
                    drop(file);
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        if receiver.flags.is_response {
            if let Some(request) = Self::response_request_id(&receiver.request_id) {
                link.pending_requests.remove(&request);
            }
        }
        // Removing its assembly identity invalidates only this transfer's worker
        // result. Other transfers retain their link generation and pending work.
        // Upstream cancels the incoming resource in turn, which answers the
        // sender with RESOURCE_RCL.
        let actions = receiver.handle_cancel();
        let _ = link;
        self.process_resource_actions(link_id, actions, rng)
    }

    /// Reject only the outgoing transfer named by an authenticated RCL packet.
    pub(in crate::common::link_manager) fn handle_resource_rcl(
        &mut self,
        link_id: &LinkId,
        resource_hash: &[u8],
    ) -> Vec<LinkManagerAction> {
        let Some(hash) = Self::resource_hash_key(resource_hash) else {
            return Vec::new();
        };
        let Some(link) = self.links.get_mut(link_id) else {
            return Vec::new();
        };
        let Some(idx) = link.outgoing_resources.iter().position(|sender| {
            sender.resource_hash == hash
                && sender.status < rns_core::resource::ResourceStatus::Complete
        }) else {
            return Vec::new();
        };
        let mut sender = link.outgoing_resources.remove(idx);
        if sender.flags.split {
            // Buffered senders may already hold later segments of this transfer.
            link.outgoing_resources
                .retain(|s| !s.flags.split || s.original_hash != sender.original_hash);
            link.outgoing_splits.remove(&sender.original_hash);
        }
        if sender.flags.is_request {
            if let Some(request) = Self::response_request_id(&sender.request_id) {
                link.pending_requests.remove(&request);
            }
        }
        let mut actions: Vec<_> = sender
            .handle_reject()
            .into_iter()
            .filter_map(|action| match action {
                ResourceAction::Failed(error) => Some(LinkManagerAction::ResourceFailed {
                    link_id: *link_id,
                    error: error.to_string(),
                }),
                _ => None,
            })
            .collect();
        if let Some(stream) = link.outgoing_streams.remove(&sender.original_hash) {
            actions.push(LinkManagerAction::ResourceStreamFailed {
                link_id: *link_id,
                transfer_id: stream.transfer_id,
                error: ResourceTransferError::Cancelled,
            });
        }
        actions
    }

    pub(super) fn resource_link_is_active(&self, link_id: &LinkId) -> bool {
        self.links
            .get(link_id)
            .is_some_and(|link| link.engine.state() == LinkState::Active)
    }

    pub(super) fn abort_resources_on_inactive_link(
        &mut self,
        link_id: &LinkId,
    ) -> Vec<LinkManagerAction> {
        let Some(link) = self.links.get_mut(link_id) else {
            return Vec::new();
        };
        for sender in &mut link.outgoing_resources {
            let _ = sender.cancel();
        }
        for receiver in &mut link.incoming_resources {
            let _ = receiver.cancel();
        }
        link.outgoing_resources.clear();
        link.incoming_resources.clear();
        link.outgoing_splits.clear();
        let actions = link
            .outgoing_streams
            .drain()
            .map(|(_, stream)| LinkManagerAction::ResourceStreamFailed {
                link_id: *link_id,
                transfer_id: stream.transfer_id,
                error: ResourceTransferError::Cancelled,
            })
            .collect();
        link.incoming_splits.clear();
        link.pending_requests.clear();
        actions
    }
}
