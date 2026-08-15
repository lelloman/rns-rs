use super::*;

pub(super) struct ResourceSendParams<'a> {
    pub(super) data: &'a [u8],
    pub(super) metadata: Option<&'a [u8]>,
    pub(super) auto_compress: bool,
    pub(super) is_response: bool,
    pub(super) request_id: Option<Vec<u8>>,
    pub(super) rng: &'a mut dyn Rng,
    pub(super) now: f64,
}

impl LinkManager {
    pub(super) fn request_response_deadline(link: &ManagedLink, now: f64) -> f64 {
        now + link.engine.rtt().unwrap_or(1.0) * constants::LINK_TRAFFIC_TIMEOUT_FACTOR
            + constants::RESOURCE_RESPONSE_MAX_GRACE_TIME * 1.125
    }

    pub(super) fn build_resource_senders(
        link: &ManagedLink,
        params: ResourceSendParams<'_>,
    ) -> Result<Vec<ResourceSender>, rns_core::resource::ResourceError> {
        let ResourceSendParams {
            data,
            metadata,
            auto_compress,
            is_response,
            request_id,
            rng,
            now,
        } = params;
        let link_rtt = link.engine.rtt().unwrap_or(1.0);
        let resource_sdu = Self::resource_sdu_for_link(link);
        let metadata_overhead = metadata.map(|m| 3 + m.len()).unwrap_or(0);
        let logical_size = metadata_overhead + data.len();

        if logical_size <= constants::RESOURCE_MAX_EFFICIENT_SIZE {
            let enc_rng = std::cell::RefCell::new(rns_crypto::OsRng);
            let encrypt_fn = |plaintext: &[u8]| -> Vec<u8> {
                link.engine
                    .encrypt(plaintext, &mut *enc_rng.borrow_mut())
                    .unwrap_or_else(|_| plaintext.to_vec())
            };
            return ResourceSender::new(
                data,
                metadata,
                resource_sdu,
                &encrypt_fn,
                &Bzip2Compressor,
                rng,
                now,
                auto_compress,
                is_response,
                request_id,
                1,
                1,
                None,
                link_rtt,
                6.0,
            )
            .map(|sender| vec![sender]);
        }

        if metadata_overhead > constants::RESOURCE_MAX_EFFICIENT_SIZE {
            return Err(rns_core::resource::ResourceError::TooLarge);
        }

        let first_payload_len = core::cmp::min(
            data.len(),
            constants::RESOURCE_MAX_EFFICIENT_SIZE - metadata_overhead,
        );
        let remaining = data.len().saturating_sub(first_payload_len);
        let total_segments = 1 + remaining.div_ceil(constants::RESOURCE_MAX_EFFICIENT_SIZE) as u64;

        let enc_rng = std::cell::RefCell::new(rns_crypto::OsRng);
        let encrypt_fn = |plaintext: &[u8]| -> Vec<u8> {
            link.engine
                .encrypt(plaintext, &mut *enc_rng.borrow_mut())
                .unwrap_or_else(|_| plaintext.to_vec())
        };

        let mut senders = Vec::new();
        let mut first = ResourceSender::new(
            &data[..first_payload_len],
            metadata,
            resource_sdu,
            &encrypt_fn,
            &Bzip2Compressor,
            rng,
            now,
            auto_compress,
            is_response,
            request_id.clone(),
            1,
            total_segments,
            None,
            link_rtt,
            6.0,
        )?;
        first.data_size = logical_size;
        let original_hash = first.original_hash;
        let has_metadata = metadata.is_some();
        senders.push(first);

        let mut offset = first_payload_len;
        let mut segment_index = 2;
        while offset < data.len() {
            let end = core::cmp::min(offset + constants::RESOURCE_MAX_EFFICIENT_SIZE, data.len());
            let mut sender = ResourceSender::new(
                &data[offset..end],
                None,
                resource_sdu,
                &encrypt_fn,
                &Bzip2Compressor,
                rng,
                now,
                auto_compress,
                is_response,
                request_id.clone(),
                segment_index,
                total_segments,
                Some(original_hash),
                link_rtt,
                6.0,
            )?;
            sender.data_size = logical_size;
            sender.flags.has_metadata = has_metadata;
            senders.push(sender);
            segment_index += 1;
            offset = end;
        }

        Ok(senders)
    }

    fn read_stream_segment(
        stream: &mut OutgoingStreamTransfer,
        capacity: usize,
    ) -> Result<Vec<u8>, ResourceTransferError> {
        let length = stream.remaining.min(capacity as u64) as usize;
        let mut data = vec![0; length];
        stream
            .reader
            .read_exact(&mut data)
            .map_err(|error| ResourceTransferError::Source(error.to_string()))?;
        stream.remaining -= length as u64;
        if stream.remaining == 0 {
            let mut trailing = [0u8; 1];
            if stream
                .reader
                .read(&mut trailing)
                .map_err(|error| ResourceTransferError::Source(error.to_string()))?
                != 0
            {
                return Err(ResourceTransferError::Source(
                    "resource source exceeds declared length".into(),
                ));
            }
        }
        Ok(data)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_stream_segment(
        link: &ManagedLink,
        stream: &mut OutgoingStreamTransfer,
        metadata: Option<&[u8]>,
        segment_index: u64,
        total_segments: u64,
        original_hash: Option<[u8; 32]>,
        rng: &mut dyn Rng,
        now: f64,
    ) -> Result<ResourceSender, ResourceTransferError> {
        let metadata_overhead = metadata.map(|value| 3 + value.len()).unwrap_or(0);
        if metadata_overhead > constants::RESOURCE_MAX_EFFICIENT_SIZE {
            return Err(ResourceTransferError::Protocol(
                "resource metadata exceeds maximum segment size".into(),
            ));
        }
        let data = Self::read_stream_segment(
            stream,
            constants::RESOURCE_MAX_EFFICIENT_SIZE - metadata_overhead,
        )?;
        let enc_rng = std::cell::RefCell::new(rns_crypto::OsRng);
        let encrypt_fn = |plaintext: &[u8]| -> Vec<u8> {
            link.engine
                .encrypt(plaintext, &mut *enc_rng.borrow_mut())
                .unwrap_or_else(|_| plaintext.to_vec())
        };
        let mut sender = ResourceSender::new(
            &data,
            metadata,
            Self::resource_sdu_for_link(link),
            &encrypt_fn,
            &Bzip2Compressor,
            rng,
            now,
            stream.auto_compress,
            false,
            None,
            segment_index,
            total_segments,
            original_hash,
            link.engine.rtt().unwrap_or(1.0),
            6.0,
        )
        .map_err(|error| ResourceTransferError::Protocol(error.to_string()))?;
        sender.data_size = (stream.declared_length + stream.metadata_overhead) as usize;
        sender.flags.has_metadata = stream.metadata_overhead != 0;
        Ok(sender)
    }

    pub(super) fn start_resource_senders(
        link: &mut ManagedLink,
        mut senders: Vec<ResourceSender>,
        now: f64,
    ) -> Vec<ResourceAction> {
        if senders.is_empty() {
            return Vec::new();
        }

        let mut first = senders.remove(0);
        let adv_actions = first.advertise(now);

        if first.total_segments > 1 {
            let original_hash = first.original_hash;
            let split = OutgoingSplitTransfer {
                total_segments: first.total_segments,
                completed_segments: 0,
                current_segment_index: first.segment_index,
                current_sent_parts: 0,
                current_total_parts: first.total_parts(),
            };
            link.outgoing_splits.insert(original_hash, split);
        }

        link.outgoing_resources.push(first);
        link.outgoing_resources.extend(senders);
        adv_actions
    }

    /// Handle resource advertisement (CONTEXT_RESOURCE_ADV).
    pub(super) fn handle_resource_adv(
        &mut self,
        link_id: &LinkId,
        adv_plaintext: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let has_request_handlers = !self.request_handlers.is_empty()
            || !self.deferred_request_handlers.is_empty()
            || !self.management_paths.is_empty();
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let link_rtt = link.engine.rtt().unwrap_or(1.0);
        let resource_sdu = Self::resource_sdu_for_link(link);
        let now = time::now();

        let receiver = match ResourceReceiver::from_advertisement(
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

        let strategy = link.resource_strategy;
        let resource_hash = receiver.resource_hash.clone();
        let transfer_size = receiver.transfer_size;
        let has_metadata = receiver.has_metadata;
        let is_request = receiver.flags.is_request;
        let is_response = receiver.flags.is_response;
        let is_split = receiver.flags.split;
        let segment_index = receiver.segment_index;
        let total_segments = receiver.total_segments;
        let original_hash = match Self::resource_hash_key(&receiver.original_hash) {
            Some(key) => key,
            None => return Vec::new(),
        };

        if !is_request && !is_response {
            let maximum = match &link.resource_receive_mode {
                ResourceReceiveMode::Memory { max_bytes } => Some(*max_bytes),
                ResourceReceiveMode::TemporaryFile { max_bytes, .. } => *max_bytes,
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
                    let storage =
                        match Self::incoming_storage(&link.resource_receive_mode, &original_hash) {
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
                        },
                    );
                }
                link.incoming_resources.push(receiver);
                let idx = link.incoming_resources.len() - 1;
                let resource_actions = link.incoming_resources[idx].accept(now);
                let _ = link;
                self.process_resource_actions(link_id, resource_actions, rng)
            }
            ResourceStrategy::AcceptApp => {
                link.incoming_resources.push(receiver);
                // Query application callback
                vec![LinkManagerAction::ResourceAcceptQuery {
                    link_id: *link_id,
                    resource_hash,
                    transfer_size,
                    has_metadata,
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
                    let storage =
                        match Self::incoming_storage(&link.resource_receive_mode, &original_hash) {
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
                        },
                    );
                }
            }
        }

        let resource_actions = if accept {
            link.incoming_resources[idx].accept(now)
        } else {
            link.incoming_resources[idx].reject()
        };

        let _ = link;
        self.process_resource_actions(link_id, resource_actions, rng)
    }

    /// Handle resource request (CONTEXT_RESOURCE_REQ) — feed to sender.
    pub(super) fn handle_resource_req(
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
        let mut progress_update = None;
        let mut progress_stream_hash = None;
        for sender in &mut link.outgoing_resources {
            if sender.flags.split && sender.status == rns_core::resource::ResourceStatus::Queued {
                continue;
            }
            let before_sent = sender.sent_parts;
            let resource_actions = sender.handle_request(plaintext, now);
            if !resource_actions.is_empty() {
                if sender.sent_parts != before_sent {
                    progress_stream_hash = Some(sender.original_hash);
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
                all_actions.extend(resource_actions);
                break;
            }
        }

        let _ = link;
        let mut out = self.process_resource_actions(link_id, all_actions, rng);
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
        out
    }

    /// Handle resource HMU (CONTEXT_RESOURCE_HMU) — feed to receiver.
    pub(super) fn handle_resource_hmu(
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

    /// Handle resource part (CONTEXT_RESOURCE) — feed raw to receiver.
    pub(super) fn handle_resource_part(
        &mut self,
        link_id: &LinkId,
        raw_data: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let now = time::now();
        let resource_sdu = Self::resource_sdu_for_link(link);
        let mut all_actions = Vec::new();
        let mut assemble_idx = None;
        let mut assembled_is_request = false;
        let mut assembled_is_response = false;
        let mut request_request_id = None;
        let mut response_request_id = None;
        let mut completed_file = None;
        let mut storage_failure = None;

        for (idx, receiver) in link.incoming_resources.iter_mut().enumerate() {
            if receiver.status >= rns_core::resource::ResourceStatus::Complete {
                continue;
            }
            let resource_actions = receiver.receive_part(raw_data, now);
            if !resource_actions.is_empty() {
                if receiver.received_count == receiver.total_parts {
                    assemble_idx = Some(idx);
                }
                if receiver.flags.split {
                    if let Some(key) = Self::resource_hash_key(&receiver.original_hash) {
                        if let Some(split) = link.incoming_splits.get_mut(&key) {
                            split.current_segment_index = receiver.segment_index;
                            split.current_received_parts = receiver.received_count;
                            split.current_total_parts = receiver.total_parts;
                            let (received, total) =
                                Self::incoming_split_progress(split, resource_sdu);
                            for action in resource_actions {
                                match action {
                                    ResourceAction::ProgressUpdate { .. } => {
                                        all_actions.push(ResourceAction::ProgressUpdate {
                                            received,
                                            total,
                                        });
                                    }
                                    other => all_actions.push(other),
                                }
                            }
                        } else {
                            all_actions.extend(resource_actions);
                        }
                    } else {
                        all_actions.extend(resource_actions);
                    }
                } else {
                    all_actions.extend(resource_actions);
                }
                break;
            }
        }

        if let Some(idx) = assemble_idx {
            let split_key = if link.incoming_resources[idx].flags.split {
                Self::resource_hash_key(&link.incoming_resources[idx].original_hash)
            } else {
                None
            };
            let split_segment_index = link.incoming_resources[idx].segment_index;
            let split_segment_total = link.incoming_resources[idx].total_segments;
            let split_segment_parts = link.incoming_resources[idx].total_parts;
            let split_is_request = link.incoming_resources[idx].flags.is_request;
            let split_is_response = link.incoming_resources[idx].flags.is_response;
            let resource_original_hash =
                Self::resource_hash_key(&link.incoming_resources[idx].original_hash)
                    .unwrap_or([0; 32]);
            let resource_request_id =
                Self::response_request_id(&link.incoming_resources[idx].request_id);
            if split_is_request {
                request_request_id = resource_request_id;
            } else if split_is_response {
                response_request_id = resource_request_id;
            }
            let decrypt_fn = |ciphertext: &[u8]| -> Result<Vec<u8>, ()> {
                link.engine.decrypt(ciphertext).map_err(|_| ())
            };
            let mut assemble_actions =
                link.incoming_resources[idx].assemble(&decrypt_fn, &Bzip2Compressor);
            assembled_is_request = split_is_request;
            assembled_is_response = split_is_response;

            if let Some(key) = split_key {
                let mut converted_actions = Vec::new();
                let mut segment_data = None;
                let mut segment_metadata = None;
                for action in assemble_actions {
                    match action {
                        ResourceAction::DataReceived { data, metadata } => {
                            segment_data = Some(data);
                            segment_metadata = metadata;
                        }
                        ResourceAction::Completed => {}
                        other => converted_actions.push(other),
                    }
                }

                if let Some(data) = segment_data {
                    if let Some(split) = link.incoming_splits.get_mut(&key) {
                        let write_result = match &mut split.storage {
                            IncomingSplitStorage::Memory(buffer) => {
                                buffer.extend_from_slice(&data);
                                Ok(())
                            }
                            IncomingSplitStorage::File { file, size, .. } => {
                                file.write_all(&data).map(|()| *size += data.len() as u64)
                            }
                        };
                        if let Err(error) = write_result {
                            storage_failure = Some(error.to_string());
                        }
                        if segment_metadata.is_some() {
                            split.metadata = segment_metadata;
                        }
                        split.completed_segments = split_segment_index;
                        split.current_segment_index = split_segment_index;
                        split.current_received_parts = split_segment_parts;
                        split.current_total_parts = split_segment_parts;
                    }

                    if storage_failure.is_none() && split_segment_index == split_segment_total {
                        if let Some(split) = link.incoming_splits.remove(&key) {
                            assembled_is_request = split.is_request;
                            assembled_is_response = split.is_response;
                            match split.storage {
                                IncomingSplitStorage::Memory(data) => {
                                    converted_actions.push(ResourceAction::DataReceived {
                                        data,
                                        metadata: split.metadata,
                                    });
                                }
                                IncomingSplitStorage::File { file, path, size } => {
                                    match file.sync_all() {
                                        Ok(()) => {
                                            completed_file = Some(ReceivedResourceFile::new(
                                                path,
                                                key,
                                                size,
                                                split.metadata,
                                            ));
                                        }
                                        Err(error) => storage_failure = Some(error.to_string()),
                                    }
                                }
                            }
                            converted_actions.push(ResourceAction::Completed);
                        }
                    }
                    if storage_failure.is_some() {
                        link.incoming_splits.remove(&key);
                        converted_actions.clear();
                        converted_actions.push(ResourceAction::SendCancelReceiver(Vec::new()));
                    }
                }

                assemble_actions = converted_actions;
            } else if !split_is_request
                && !split_is_response
                && matches!(
                    link.resource_receive_mode,
                    ResourceReceiveMode::TemporaryFile { .. }
                )
            {
                let directory = match &link.resource_receive_mode {
                    ResourceReceiveMode::TemporaryFile { directory, .. } => directory.clone(),
                    ResourceReceiveMode::Memory { .. } => unreachable!(),
                };
                let mut converted_actions = Vec::new();
                for action in assemble_actions {
                    match action {
                        ResourceAction::DataReceived { data, metadata } => {
                            match crate::resource::create_receive_file(
                                &directory,
                                &resource_original_hash,
                            )
                            .and_then(|(mut file, path)| {
                                file.write_all(&data)?;
                                file.sync_all()?;
                                Ok(ReceivedResourceFile::new(
                                    path,
                                    resource_original_hash,
                                    data.len() as u64,
                                    metadata,
                                ))
                            }) {
                                Ok(resource) => completed_file = Some(resource),
                                Err(error) => storage_failure = Some(error.to_string()),
                            }
                        }
                        other => converted_actions.push(other),
                    }
                }
                if storage_failure.is_some() {
                    converted_actions.retain(|action| {
                        !matches!(
                            action,
                            ResourceAction::SendProof(_) | ResourceAction::Completed
                        )
                    });
                    converted_actions.push(ResourceAction::SendCancelReceiver(Vec::new()));
                }
                assemble_actions = converted_actions;
            }
            all_actions.extend(assemble_actions);
        }

        let _ = link;
        let mut out = self.process_resource_actions(link_id, all_actions, rng);
        if let Some(resource) = completed_file {
            out.push(LinkManagerAction::ResourceFileReceived {
                link_id: *link_id,
                resource,
            });
        }
        if let Some(error) = storage_failure {
            out.push(LinkManagerAction::ResourceFailed {
                link_id: *link_id,
                error: format!("resource storage failed: {error}"),
            });
        }

        if assembled_is_request {
            let mut converted = Vec::new();
            for action in out {
                match action {
                    LinkManagerAction::ResourceReceived { data, .. } => {
                        if let Some(request_id) = request_request_id {
                            converted.extend(self.handle_request(link_id, &data, request_id, rng));
                        }
                    }
                    LinkManagerAction::ResourceAcceptQuery { .. } => {
                        // Request resources bypass application resource acceptance.
                    }
                    other => converted.push(other),
                }
            }
            out = converted;
        } else if assembled_is_response {
            let mut converted = Vec::new();
            for action in out {
                match action {
                    LinkManagerAction::ResourceReceived { data, metadata, .. } => {
                        converted.extend(self.handle_response(
                            link_id,
                            &data,
                            metadata,
                            response_request_id,
                        ));
                    }
                    LinkManagerAction::ResourceAcceptQuery { .. } => {
                        // Response resources bypass application acceptance
                    }
                    other => converted.push(other),
                }
            }
            out = converted;
        }

        out
    }

    /// Handle resource proof (CONTEXT_RESOURCE_PRF) — feed to sender.
    pub(super) fn handle_resource_prf(
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
            let deadline = Self::request_response_deadline(link, now);
            if let Some(entry) = link.pending_requests.get_mut(&request_id) {
                entry.deadline = Some(deadline);
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

        actions
    }

    /// Handle cancel from initiator (CONTEXT_RESOURCE_ICL).
    pub(super) fn handle_resource_icl(&mut self, link_id: &LinkId) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let mut actions = Vec::new();
        for receiver in &mut link.incoming_resources {
            let ra = receiver.handle_cancel();
            for a in ra {
                if let ResourceAction::Failed(ref e) = a {
                    actions.push(LinkManagerAction::ResourceFailed {
                        link_id: *link_id,
                        error: format!("{}", e),
                    });
                }
            }
        }
        link.incoming_resources
            .retain(|r| r.status < rns_core::resource::ResourceStatus::Complete);
        link.incoming_splits.clear();
        actions
    }

    /// Handle cancel from receiver (CONTEXT_RESOURCE_RCL).
    pub(super) fn handle_resource_rcl(&mut self, link_id: &LinkId) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        let request_ids: Vec<[u8; 16]> = link
            .outgoing_resources
            .iter()
            .filter(|sender| sender.flags.is_request)
            .filter_map(|sender| Self::response_request_id(&sender.request_id))
            .collect();
        let mut actions = Vec::new();
        for sender in &mut link.outgoing_resources {
            let ra = sender.handle_reject();
            for a in ra {
                if let ResourceAction::Failed(ref e) = a {
                    actions.push(LinkManagerAction::ResourceFailed {
                        link_id: *link_id,
                        error: format!("{}", e),
                    });
                }
            }
        }
        link.outgoing_resources
            .retain(|s| s.status < rns_core::resource::ResourceStatus::Complete);
        link.outgoing_splits.clear();
        actions.extend(link.outgoing_streams.drain().map(|(_, stream)| {
            LinkManagerAction::ResourceStreamFailed {
                link_id: *link_id,
                transfer_id: stream.transfer_id,
                error: ResourceTransferError::Cancelled,
            }
        }));
        for request_id in request_ids {
            link.pending_requests.remove(&request_id);
        }
        actions
    }

    fn resource_link_is_active(&self, link_id: &LinkId) -> bool {
        self.links
            .get(link_id)
            .is_some_and(|link| link.engine.state() == LinkState::Active)
    }

    fn abort_resources_on_inactive_link(&mut self, link_id: &LinkId) -> Vec<LinkManagerAction> {
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

    /// Convert ResourceActions to LinkManagerActions.
    pub(super) fn process_resource_actions(
        &mut self,
        link_id: &LinkId,
        actions: Vec<ResourceAction>,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let mut result = Vec::new();
        for action in actions {
            let requires_active_link = matches!(
                &action,
                ResourceAction::SendAdvertisement(_)
                    | ResourceAction::SendPart(_)
                    | ResourceAction::SendRequest(_)
                    | ResourceAction::SendHmu(_)
                    | ResourceAction::SendProof(_)
            );
            if requires_active_link && !self.resource_link_is_active(link_id) {
                result.extend(self.abort_resources_on_inactive_link(link_id));
                continue;
            }

            match action {
                ResourceAction::SendAdvertisement(data) => {
                    // Link-encrypt and send as CONTEXT_RESOURCE_ADV
                    let encrypted = self
                        .links
                        .get(link_id)
                        .and_then(|link| link.engine.encrypt(&data, rng).ok());
                    if let Some(encrypted) = encrypted {
                        result.extend(self.build_link_packet(
                            link_id,
                            constants::CONTEXT_RESOURCE_ADV,
                            &encrypted,
                        ));
                    }
                }
                ResourceAction::SendPart(data) => {
                    // Parts are NOT link-encrypted — send raw as CONTEXT_RESOURCE
                    result.extend(self.build_link_packet(
                        link_id,
                        constants::CONTEXT_RESOURCE,
                        &data,
                    ));
                }
                ResourceAction::SendRequest(data) => {
                    let encrypted = self
                        .links
                        .get(link_id)
                        .and_then(|link| link.engine.encrypt(&data, rng).ok());
                    if let Some(encrypted) = encrypted {
                        result.extend(self.build_link_packet(
                            link_id,
                            constants::CONTEXT_RESOURCE_REQ,
                            &encrypted,
                        ));
                    }
                }
                ResourceAction::SendHmu(data) => {
                    let encrypted = self
                        .links
                        .get(link_id)
                        .and_then(|link| link.engine.encrypt(&data, rng).ok());
                    if let Some(encrypted) = encrypted {
                        result.extend(self.build_link_packet(
                            link_id,
                            constants::CONTEXT_RESOURCE_HMU,
                            &encrypted,
                        ));
                    }
                }
                ResourceAction::SendProof(data) => {
                    let flags = PacketFlags {
                        header_type: constants::HEADER_1,
                        context_flag: constants::FLAG_UNSET,
                        transport_type: constants::TRANSPORT_BROADCAST,
                        destination_type: constants::DESTINATION_LINK,
                        packet_type: constants::PACKET_TYPE_PROOF,
                    };
                    if let Ok((raw, _packet_hash)) = RawPacket::pack_raw_with_hash(
                        flags,
                        0,
                        link_id,
                        None,
                        constants::CONTEXT_RESOURCE_PRF,
                        &data,
                    ) {
                        result.push(LinkManagerAction::SendPacket {
                            raw,
                            dest_type: constants::DESTINATION_LINK,
                            attached_interface: None,
                        });
                    }
                }
                ResourceAction::SendCancelInitiator(data) => {
                    let encrypted = self
                        .links
                        .get(link_id)
                        .filter(|link| link.engine.state() == LinkState::Active)
                        .and_then(|link| link.engine.encrypt(&data, rng).ok());
                    if let Some(encrypted) = encrypted {
                        result.extend(self.build_link_packet(
                            link_id,
                            constants::CONTEXT_RESOURCE_ICL,
                            &encrypted,
                        ));
                    }
                }
                ResourceAction::SendCancelReceiver(data) => {
                    let encrypted = self
                        .links
                        .get(link_id)
                        .filter(|link| link.engine.state() == LinkState::Active)
                        .and_then(|link| link.engine.encrypt(&data, rng).ok());
                    if let Some(encrypted) = encrypted {
                        result.extend(self.build_link_packet(
                            link_id,
                            constants::CONTEXT_RESOURCE_RCL,
                            &encrypted,
                        ));
                    }
                }
                ResourceAction::DataReceived { data, metadata } => {
                    result.push(LinkManagerAction::ResourceReceived {
                        link_id: *link_id,
                        data,
                        metadata,
                    });
                }
                ResourceAction::Completed => {
                    result.push(LinkManagerAction::ResourceCompleted { link_id: *link_id });
                }
                ResourceAction::Failed(e) => {
                    result.push(LinkManagerAction::ResourceFailed {
                        link_id: *link_id,
                        error: format!("{}", e),
                    });
                }
                ResourceAction::TeardownLink => {
                    let teardown_actions = match self.links.get_mut(link_id) {
                        Some(link) => link.engine.handle_teardown(),
                        None => Vec::new(),
                    };
                    result.extend(self.process_link_actions(link_id, &teardown_actions));
                }
                ResourceAction::ProgressUpdate { received, total } => {
                    result.push(LinkManagerAction::ResourceProgress {
                        link_id: *link_id,
                        received,
                        total,
                    });
                }
            }
        }
        result
    }

    /// Build a link DATA packet with a given context and data.
    pub(super) fn build_link_packet(
        &self,
        link_id: &LinkId,
        context: u8,
        data: &[u8],
    ) -> Vec<LinkManagerAction> {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let mut actions = Vec::new();
        let max_mtu = self
            .links
            .get(link_id)
            .map(|l| l.engine.mtu() as usize)
            .unwrap_or(constants::MTU);
        if let Ok((raw, _packet_hash)) = RawPacket::pack_raw_with_hash_with_max_mtu(
            flags, 0, link_id, None, context, data, max_mtu,
        ) {
            actions.push(LinkManagerAction::SendPacket {
                raw,
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            });
        }
        actions
    }

    /// Start sending a resource on a link.
    pub fn send_resource(
        &mut self,
        link_id: &LinkId,
        data: &[u8],
        metadata: Option<&[u8]>,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        self.send_resource_with_auto_compress(link_id, data, metadata, true, rng)
    }

    /// Start sending a resource on a link, controlling automatic compression.
    pub fn send_resource_with_auto_compress(
        &mut self,
        link_id: &LinkId,
        data: &[u8],
        metadata: Option<&[u8]>,
        auto_compress: bool,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        if link.engine.state() != LinkState::Active {
            return Vec::new();
        }

        let now = time::now();

        let senders = match Self::build_resource_senders(
            link,
            ResourceSendParams {
                data,
                metadata,
                auto_compress,
                is_response: false,
                request_id: None,
                rng,
                now,
            },
        ) {
            Ok(s) => s,
            Err(e) => {
                log::debug!("Failed to create ResourceSender: {}", e);
                return Vec::new();
            }
        };

        let adv_actions = Self::start_resource_senders(link, senders, now);

        let _ = link;
        self.process_resource_actions(link_id, adv_actions, rng)
    }

    /// Start a bounded-memory Resource transfer from a sequential reader.
    #[allow(clippy::too_many_arguments)]
    pub fn send_resource_stream(
        &mut self,
        link_id: &LinkId,
        transfer_id: ResourceTransferId,
        reader: Box<dyn Read + Send>,
        declared_length: u64,
        metadata: Option<Vec<u8>>,
        auto_compress: bool,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let Some(link) = self.links.get_mut(link_id) else {
            return vec![LinkManagerAction::ResourceStreamFailed {
                link_id: *link_id,
                transfer_id,
                error: ResourceTransferError::Protocol("link does not exist".into()),
            }];
        };
        if link.engine.state() != LinkState::Active {
            return vec![LinkManagerAction::ResourceStreamFailed {
                link_id: *link_id,
                transfer_id,
                error: ResourceTransferError::Protocol("link is not active".into()),
            }];
        }

        let metadata_overhead = metadata.as_ref().map(|value| 3 + value.len()).unwrap_or(0);
        let Some(logical_size) = declared_length.checked_add(metadata_overhead as u64) else {
            return vec![LinkManagerAction::ResourceStreamFailed {
                link_id: *link_id,
                transfer_id,
                error: ResourceTransferError::Protocol("resource length overflow".into()),
            }];
        };
        if usize::try_from(logical_size).is_err()
            || metadata_overhead > constants::RESOURCE_MAX_EFFICIENT_SIZE
        {
            return vec![LinkManagerAction::ResourceStreamFailed {
                link_id: *link_id,
                transfer_id,
                error: ResourceTransferError::Protocol(
                    "resource length cannot be represented by this platform".into(),
                ),
            }];
        }

        let first_capacity = constants::RESOURCE_MAX_EFFICIENT_SIZE - metadata_overhead;
        let first_length = declared_length.min(first_capacity as u64);
        let remaining_after_first = declared_length - first_length;
        let total_segments =
            1 + remaining_after_first.div_ceil(constants::RESOURCE_MAX_EFFICIENT_SIZE as u64);
        let now = time::now();
        let mut stream = OutgoingStreamTransfer {
            transfer_id,
            reader,
            remaining: declared_length,
            declared_length,
            metadata_overhead: metadata_overhead as u64,
            auto_compress,
        };
        let mut first = match Self::build_stream_segment(
            link,
            &mut stream,
            metadata.as_deref(),
            1,
            total_segments,
            None,
            rng,
            now,
        ) {
            Ok(sender) => sender,
            Err(error) => {
                return vec![LinkManagerAction::ResourceStreamFailed {
                    link_id: *link_id,
                    transfer_id,
                    error,
                }]
            }
        };
        let original_hash = first.original_hash;
        let current_total_parts = first.total_parts();
        let adv_actions = first.advertise(now);
        if total_segments > 1 {
            link.outgoing_splits.insert(
                original_hash,
                OutgoingSplitTransfer {
                    total_segments,
                    completed_segments: 0,
                    current_segment_index: 1,
                    current_sent_parts: 0,
                    current_total_parts,
                },
            );
        }
        link.outgoing_streams.insert(original_hash, stream);
        link.outgoing_resources.push(first);
        let _ = link;
        self.process_resource_actions(link_id, adv_actions, rng)
    }

    /// Set the resource acceptance strategy for a link.
    pub fn set_resource_strategy(&mut self, link_id: &LinkId, strategy: ResourceStrategy) {
        if let Some(link) = self.links.get_mut(link_id) {
            link.resource_strategy = strategy;
        }
    }

    pub fn set_resource_receive_mode(&mut self, link_id: &LinkId, mode: ResourceReceiveMode) {
        if let Some(link) = self.links.get_mut(link_id) {
            link.resource_receive_mode = mode;
        }
    }
}
