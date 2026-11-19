//! Resource advertisements: accepting or refusing them.

use super::*;

impl LinkManager {
    /// Handle resource advertisement (CONTEXT_RESOURCE_ADV).
    pub(in crate::common::link_manager) fn handle_resource_adv(
        &mut self,
        link_id: &LinkId,
        adv_plaintext: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let has_request_handlers = (!self.request_handlers.is_empty()
            || !self.deferred_request_handlers.is_empty()
            || !self.management_paths.is_empty())
            && self.link_answers_requests(link_id);
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let link_rtt = link.engine.rtt().unwrap_or(1.0);
        let resource_sdu = Self::resource_sdu_for_link(link);
        let now = time::now();

        let mut receiver = match ResourceReceiver::from_advertisement(
            adv_plaintext,
            resource_sdu,
            link_rtt,
            now,
            None,
            None,
        ) {
            Ok(r) => r,
            Err(e) => {
                log::debug!("Resource ADV rejected: {}", e);
                let _ = link;
                return self.teardown_link(link_id);
            }
        };
        receiver.set_establishment_cost(link.engine.establishment_cost());

        // Advertisement retries belong to the existing transfer. A second receiver
        // would request the same parts and deliver the payload again. Preserve
        // pending approval, progress and assembly; its normal retry timer handles
        // lost requests. Concluded receivers remain protected until tick cleanup.
        if Self::resource_hash_key(&receiver.resource_hash)
            .is_some_and(|key| link.concluded_incoming.contains(&key))
            || link
                .incoming_resources
                .iter()
                .any(|existing| existing.resource_hash == receiver.resource_hash)
        {
            return Vec::new();
        }

        let active_incoming = link
            .incoming_resources
            .iter()
            .filter(|existing| existing.status < rns_core::resource::ResourceStatus::Complete)
            .count();
        if active_incoming >= MAX_ACTIVE_INCOMING_RESOURCES {
            log::debug!(
                "refused resource advertisement on link {:02x?}: {} transfers in progress",
                &link_id[..4],
                active_incoming
            );
            let reject_actions = receiver.reject();
            let _ = link;
            return self.process_resource_actions(link_id, reject_actions, rng);
        }

        let strategy = link.resource_strategy;
        let resource_hash = receiver.resource_hash.clone();
        let transfer_size = receiver.transfer_size;
        let has_metadata = receiver.has_metadata;
        let app_flag = receiver.flags.app_flag;
        let is_request = receiver.flags.is_request;
        let is_response = receiver.flags.is_response;
        let is_split = receiver.flags.split;
        let segment_index = receiver.segment_index;
        let total_segments = receiver.total_segments;
        let original_hash = match Self::resource_hash_key(&receiver.original_hash) {
            Some(key) => key,
            None => return Vec::new(),
        };
        let mut receiver = receiver;

        if !is_request && !is_response {
            let maximum = match &link.resource_receive_mode {
                ResourceReceiveMode::Memory { max_bytes } => Some(*max_bytes),
                ResourceReceiveMode::TemporaryFile { max_bytes, .. } => *max_bytes,
                ResourceReceiveMode::Stream { max_bytes } => *max_bytes,
            };
            if maximum.is_some_and(|maximum| receiver.data_size > maximum) {
                let reject_actions = {
                    let mut receiver = receiver;
                    receiver.reject()
                };
                let _ = link;
                return self.process_resource_actions(link_id, reject_actions, rng);
            }
        }

        if is_split && segment_index > 1 {
            let should_accept = link
                .incoming_splits
                .get(&original_hash)
                .is_some_and(|split| {
                    split.completed_segments + 1 == segment_index
                        && split.total_segments == total_segments
                });

            if !should_accept {
                let reject_actions = {
                    let mut r = receiver;
                    r.reject()
                };
                let _ = link;
                return self.process_resource_actions(link_id, reject_actions, rng);
            }

            let current_total_parts = receiver.total_parts;
            if let Some((window, eifr)) = link
                .incoming_splits
                .get(&original_hash)
                .and_then(|split| split.window.clone())
            {
                receiver.continue_from(window, eifr);
            }
            link.incoming_resources.push(receiver);
            let idx = link.incoming_resources.len() - 1;
            if let Some(split) = link.incoming_splits.get_mut(&original_hash) {
                split.current_segment_index = segment_index;
                split.current_received_parts = 0;
                split.current_total_parts = current_total_parts;
            }
            let resource_actions = link.incoming_resources[idx].accept(now);
            let _ = link;
            return self.process_resource_actions(link_id, resource_actions, rng);
        }

        if is_request {
            // A request resource is only useful when this destination has a
            // request handler, and request IDs are truncated hashes.
            if !has_request_handlers || Self::response_request_id(&receiver.request_id).is_none() {
                return Vec::new();
            }
            if link
                .max_request_size
                .is_some_and(|limit| receiver.data_size > limit as u64)
            {
                log::debug!(
                    "ignored request with excessive size {} bytes on link {:02x?}",
                    receiver.data_size,
                    &link_id[..4]
                );
                let reject_actions = {
                    let mut receiver = receiver;
                    receiver.reject()
                };
                let _ = link;
                return self.process_resource_actions(link_id, reject_actions, rng);
            }
            if is_split {
                link.incoming_splits.insert(
                    original_hash,
                    IncomingSplitTransfer {
                        total_segments,
                        completed_segments: 0,
                        current_segment_index: segment_index,
                        current_received_parts: 0,
                        current_total_parts: receiver.total_parts,
                        storage: IncomingSplitStorage::Memory(Vec::new()),
                        metadata: None,
                        is_request: true,
                        is_response: false,
                        window: None,
                    },
                );
            }
            link.incoming_resources.push(receiver);
            let idx = link.incoming_resources.len() - 1;
            let resource_actions = link.incoming_resources[idx].accept(now);
            let _ = link;
            return self.process_resource_actions(link_id, resource_actions, rng);
        }

        if is_response {
            // Response resources bypass the application acceptance strategy —
            // they are answers to pending requests, not independent resources.
            let Some(request_id) = Self::response_request_id(&receiver.request_id) else {
                return Vec::new();
            };
            let Some(pending) = link.pending_requests.get(&request_id) else {
                return Vec::new();
            };
            if let Some(maximum) = pending.max_response_size {
                if receiver.data_size > maximum as u64 {
                    let response_size = receiver.data_size;
                    link.pending_requests.remove(&request_id);
                    log::debug!(
                        "rejected response with excessive size {} bytes on link {:02x?}",
                        response_size,
                        &link_id[..4]
                    );
                    let reject_actions = {
                        let mut receiver = receiver;
                        receiver.reject()
                    };
                    let _ = link;
                    let mut actions = self.process_resource_actions(link_id, reject_actions, rng);
                    actions.push(LinkManagerAction::RequestFailed {
                        link_id: *link_id,
                        request_id,
                        reason: RequestFailure::ResponseTooLarge {
                            size: response_size,
                            maximum,
                        },
                    });
                    return actions;
                }
            }
            if is_split {
                link.incoming_splits.insert(
                    original_hash,
                    IncomingSplitTransfer {
                        total_segments,
                        completed_segments: 0,
                        current_segment_index: segment_index,
                        current_received_parts: 0,
                        current_total_parts: receiver.total_parts,
                        storage: IncomingSplitStorage::Memory(Vec::new()),
                        metadata: None,
                        is_request: false,
                        is_response,
                        window: None,
                    },
                );
            }
            link.incoming_resources.push(receiver);
            let idx = link.incoming_resources.len() - 1;
            let resource_actions = link.incoming_resources[idx].accept(now);
            let _ = link;
            return self.process_resource_actions(link_id, resource_actions, rng);
        }

        match strategy {
            ResourceStrategy::AcceptNone => {
                // Reject: send RCL
                let reject_actions = {
                    let mut r = receiver;
                    r.reject()
                };
                self.process_resource_actions(link_id, reject_actions, rng)
            }
            ResourceStrategy::AcceptAll => {
                if is_split {
                    let storage = match Self::incoming_storage(
                        &link.resource_receive_mode,
                        &original_hash,
                        receiver.data_size,
                    ) {
                        Ok(storage) => storage,
                        Err(error) => {
                            let reject_actions = {
                                let mut receiver = receiver;
                                receiver.reject()
                            };
                            let _ = link;
                            let mut actions =
                                self.process_resource_actions(link_id, reject_actions, rng);
                            actions.push(LinkManagerAction::ResourceFailed {
                                link_id: *link_id,
                                error: format!("resource storage failed: {error}"),
                            });
                            return actions;
                        }
                    };
                    link.incoming_splits.insert(
                        original_hash,
                        IncomingSplitTransfer {
                            total_segments,
                            completed_segments: 0,
                            current_segment_index: segment_index,
                            current_received_parts: 0,
                            current_total_parts: receiver.total_parts,
                            storage,
                            metadata: None,
                            is_request: false,
                            is_response,
                            window: None,
                        },
                    );
                }
                link.incoming_resources.push(receiver);
                let idx = link.incoming_resources.len() - 1;
                let started = LinkManagerAction::ResourceStarted {
                    link_id: *link_id,
                    resource_hash: link.incoming_resources[idx].resource_hash.clone(),
                    data_size: link.incoming_resources[idx].data_size,
                };
                let resource_actions = link.incoming_resources[idx].accept(now);
                let _ = link;
                let mut actions = vec![started];
                actions.extend(self.process_resource_actions(link_id, resource_actions, rng));
                actions
            }
            ResourceStrategy::AcceptApp => {
                link.incoming_resources.push(receiver);
                // Query application callback
                vec![LinkManagerAction::ResourceAcceptQuery {
                    link_id: *link_id,
                    resource_hash,
                    transfer_size,
                    has_metadata,
                    app_flag,
                }]
            }
        }
    }

    /// Accept or reject a pending resource (for AcceptApp strategy).
    pub fn accept_resource(
        &mut self,
        link_id: &LinkId,
        resource_hash: &[u8],
        accept: bool,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let now = time::now();
        let idx = link
            .incoming_resources
            .iter()
            .position(|r| r.resource_hash == resource_hash);
        let idx = match idx {
            Some(i) => i,
            None => return Vec::new(),
        };

        if accept && link.incoming_resources[idx].flags.split {
            if let Some(original_hash) =
                Self::resource_hash_key(&link.incoming_resources[idx].original_hash)
            {
                if !link.incoming_splits.contains_key(&original_hash) {
                    let storage = match Self::incoming_storage(
                        &link.resource_receive_mode,
                        &original_hash,
                        link.incoming_resources[idx].data_size,
                    ) {
                        Ok(storage) => storage,
                        Err(error) => {
                            let resource_actions = link.incoming_resources[idx].reject();
                            let _ = link;
                            let mut actions =
                                self.process_resource_actions(link_id, resource_actions, rng);
                            actions.push(LinkManagerAction::ResourceFailed {
                                link_id: *link_id,
                                error: format!("resource storage failed: {error}"),
                            });
                            return actions;
                        }
                    };
                    link.incoming_splits.insert(
                        original_hash,
                        IncomingSplitTransfer {
                            total_segments: link.incoming_resources[idx].total_segments,
                            completed_segments: 0,
                            current_segment_index: link.incoming_resources[idx].segment_index,
                            current_received_parts: 0,
                            current_total_parts: link.incoming_resources[idx].total_parts,
                            storage,
                            metadata: None,
                            is_request: link.incoming_resources[idx].flags.is_request,
                            is_response: link.incoming_resources[idx].flags.is_response,
                            window: None,
                        },
                    );
                }
            }
        }

        let mut actions = Vec::new();
        let resource_actions = if accept {
            actions.push(LinkManagerAction::ResourceStarted {
                link_id: *link_id,
                resource_hash: link.incoming_resources[idx].resource_hash.clone(),
                data_size: link.incoming_resources[idx].data_size,
            });
            link.incoming_resources[idx].accept(now)
        } else {
            link.incoming_resources[idx].reject()
        };

        let _ = link;
        actions.extend(self.process_resource_actions(link_id, resource_actions, rng));
        actions
    }

    pub fn set_resource_receive_mode(&mut self, link_id: &LinkId, mode: ResourceReceiveMode) {
        if let Some(link) = self.links.get_mut(link_id) {
            link.resource_receive_mode = mode;
        }
    }
}
