//! Receiving resource parts.

use super::*;

impl LinkManager {
    /// Handle resource part (CONTEXT_RESOURCE) — feed raw to receiver,
    /// appending to `out`.
    pub(in crate::common::link_manager) fn handle_resource_part_into(
        &mut self,
        link_id: &LinkId,
        raw_data: &[u8],
        rng: &mut dyn Rng,
        out: &mut Vec<LinkManagerAction>,
    ) {
        let mut scratch = core::mem::take(&mut self.resource_scratch);
        self.receive_resource_part_into(link_id, raw_data, rng, &mut scratch, out);
        scratch.clear();
        self.resource_scratch = scratch;
        self.prune_concluded_incoming(link_id);
    }

    /// Drop a link's incoming Resources that have concluded, as soon as they
    /// do, keeping only their hashes until the next tick. Kept whole until
    /// then, they piled up under many small Resources, and every advertisement
    /// and status query scanned them.
    pub(in crate::common::link_manager) fn prune_concluded_incoming(&mut self, link_id: &LinkId) {
        if let Some(link) = self.links.get_mut(link_id) {
            let concluded = &mut link.concluded_incoming;
            link.incoming_resources.retain(|r| {
                let active = r.status < rns_core::resource::ResourceStatus::Complete;
                if !active {
                    // Receivers hold a validated 32-byte hash.
                    if let Some(key) = Self::resource_hash_key(&r.resource_hash) {
                        concluded.insert(key);
                    }
                }
                active
            });
        }
    }

    /// Feed a resource part to the link's receivers, appending what follows
    /// to `out`. `all_actions` is an empty scratch buffer.
    pub(super) fn receive_resource_part_into(
        &mut self,
        link_id: &LinkId,
        raw_data: &[u8],
        rng: &mut dyn Rng,
        all_actions: &mut Vec<ResourceAction>,
        out: &mut Vec<LinkManagerAction>,
    ) {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return,
        };

        let now = time::now();
        let resource_sdu = Self::resource_sdu_for_link(link);
        let mut assemble_idx = None;
        let mut assembled_is_request = false;
        let mut assembled_is_response = false;
        let mut request_request_id = None;
        let mut response_request_id = None;
        let mut completed_file = None;
        // Streamed delivery: this segment, and the whole Resource once its
        // last segment arrived.
        let mut stream_segment: Option<([u8; 32], u64, Vec<u8>)> = None;
        let mut completed_stream = None;
        let mut storage_failure = None;
        // The resource that took the part.
        let mut accepted = None;
        let mut segment_progress = None;

        for (idx, receiver) in link.incoming_resources.iter_mut().enumerate() {
            if receiver.status >= rns_core::resource::ResourceStatus::Assembling {
                continue;
            }
            let before = all_actions.len();
            receiver.receive_part_into(raw_data, now, all_actions);
            if all_actions.len() > before {
                accepted = Self::resource_hash_key(&receiver.resource_hash);
                segment_progress = Some((
                    (receiver.received_count as f64 / receiver.total_parts.max(1) as f64).min(1.0),
                    receiver.transfer_size,
                ));
                if receiver.received_count == receiver.total_parts {
                    assemble_idx = Some(idx);
                } else if !Self::feeds_decryption() && receiver.has_parts_to_decrypt() {
                    // Without the decryption thread (the compact engine, or
                    // one CPU), parts are decrypted ahead in idle slices:
                    // pinned, a single-segment resource ran at 150 MB/s
                    // decrypted at assembly against 197 decrypted ahead.
                    // With the thread, it takes resources of 64 KiB and up,
                    // and smaller ones decrypt at assembly.
                    if let Ok(hash) = <[u8; 32]>::try_from(&receiver.resource_hash[..]) {
                        if !self.receive_decrypts.contains(&(*link_id, hash)) {
                            self.receive_decrypts.push_back((*link_id, hash));
                        }
                    }
                }
                if receiver.flags.split {
                    if let Some(key) = Self::resource_hash_key(&receiver.original_hash) {
                        if let Some(split) = link.incoming_splits.get_mut(&key) {
                            split.current_segment_index = receiver.segment_index;
                            split.current_received_parts = receiver.received_count;
                            split.current_total_parts = receiver.total_parts;
                            let (received, total) =
                                Self::incoming_split_progress(split, resource_sdu);
                            // Progress is reported for the whole split.
                            for action in &mut all_actions[before..] {
                                if let ResourceAction::ProgressUpdate {
                                    received: r,
                                    total: t,
                                } = action
                                {
                                    *r = received;
                                    *t = total;
                                }
                            }
                        }
                    }
                }
                break;
            }
        }

        if let Some((segment_progress, transfer_size)) = segment_progress {
            out.push(LinkManagerAction::ResourceSegmentProgress {
                link_id: *link_id,
                segment_progress,
                transfer_size,
            });
        }
        // Parts held in order go to the decryption feeder as they line up;
        // a resource about to assemble takes its decryption back.
        if let Some(hash) = accepted {
            if assemble_idx.is_some() {
                self.finish_decryption(link_id, hash);
            } else {
                self.feed_decryption(link_id, hash);
            }
        }
        if let Some(idx) = assemble_idx {
            let Some(link) = self.links.get_mut(link_id) else {
                return;
            };
            let eligible = Self::receive_offload_eligible(link, &link.incoming_resources[idx]);
            let Some(resource_hash) =
                Self::resource_hash_key(&link.incoming_resources[idx].resource_hash)
            else {
                return;
            };
            // Earlier application completions go first, with their final
            // action types.
            out.extend(self.wait_receive_for(link_id, rng));
            if eligible && !crate::engine::FOLD_WORK {
                self.ensure_receive_worker();
            }
            // A preceding corrupt assembly may have torn down this link, and
            // polling the worker prunes receivers that completed meanwhile, so
            // the receiver is located again by hash: its index may have moved.
            let Some(link) = self
                .links
                .get_mut(link_id)
                .filter(|link| link.engine.state() == LinkState::Active)
            else {
                return;
            };
            let Some(idx) = link
                .incoming_resources
                .iter()
                .position(|r| r.resource_hash[..] == resource_hash[..])
            else {
                return;
            };
            if eligible && crate::engine::FOLD_WORK {
                let receiver = &mut link.incoming_resources[idx];
                let actions = match receiver.prepare_assembly(&|parts, skip| {
                    link.engine.decrypt_chunks(parts, skip).map_err(|_| ())
                }) {
                    Ok(assembly) => {
                        let generation = link.resource_generation.clone();
                        match Self::queue_folded_assembly(
                            &mut self.folded_assemblies,
                            *link_id,
                            generation,
                            assembly,
                        ) {
                            Ok(()) => Vec::new(),
                            Err(assembly) => {
                                receiver.complete_assembly(assembly.run(&Bzip2Compressor))
                            }
                        }
                    }
                    Err(actions) => actions,
                };
                all_actions.extend(actions);
                self.process_resource_actions_into(link_id, all_actions.drain(..), rng, out);
                return;
            }
            let worker = self.receive_worker.as_mut().filter(|_| eligible);
            if let Some(worker) = worker {
                let receiver = &mut link.incoming_resources[idx];
                let actions = match receiver.prepare_assembly(&|parts, skip| {
                    link.engine.decrypt_chunks(parts, skip).map_err(|_| ())
                }) {
                    Ok(assembly) => {
                        match worker.submit(*link_id, link.resource_generation.clone(), assembly) {
                            Ok(()) => Vec::new(),
                            // Admission/disconnection fallback uses the already-authenticated
                            // handoff; no additional decryption or unbounded retry.
                            Err(assembly) => {
                                receiver.complete_assembly(assembly.run(&Bzip2Compressor))
                            }
                        }
                    }
                    Err(actions) => actions,
                };
                all_actions.extend(actions);
                self.process_resource_actions_into(link_id, all_actions.drain(..), rng, out);
                return;
            }
            let split_key = if link.incoming_resources[idx].flags.split {
                Self::resource_hash_key(&link.incoming_resources[idx].original_hash)
            } else {
                None
            };
            let split_segment_index = link.incoming_resources[idx].segment_index;
            let split_window = (
                link.incoming_resources[idx].window.clone(),
                link.incoming_resources[idx].eifr,
            );
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
            let decrypt_fn = |parts: &[&[u8]], skip: usize| -> Result<Vec<u8>, ()> {
                link.engine.decrypt_chunks(parts, skip).map_err(|_| ())
            };
            let mut assemble_actions =
                link.incoming_resources[idx].assemble(&decrypt_fn, &Bzip2Compressor);
            assembled_is_request = split_is_request;
            assembled_is_response = split_is_response;

            if let Some(key) = split_key {
                let mut converted_actions = Vec::new();
                let mut segment_data = None;
                let mut segment_metadata = None;
                let mut segment_app_flag = false;
                for action in assemble_actions {
                    match action {
                        ResourceAction::DataReceived {
                            data,
                            metadata,
                            app_flag,
                        } => {
                            segment_data = Some(data);
                            segment_metadata = metadata;
                            // Every segment carries the flag; the last one
                            // completes the Resource, as in Python.
                            segment_app_flag = app_flag;
                        }
                        ResourceAction::Completed => {}
                        other => converted_actions.push(other),
                    }
                }

                if let Some(mut data) = segment_data {
                    if let Some(split) = link.incoming_splits.get_mut(&key) {
                        let write_result = match &mut split.storage {
                            IncomingSplitStorage::Memory(buffer) => {
                                buffer.extend_from_slice(&data);
                                Ok(())
                            }
                            IncomingSplitStorage::File { file, size, .. } => {
                                file.write_all(&data).map(|()| *size += data.len() as u64)
                            }
                            IncomingSplitStorage::Stream { size } => {
                                let offset = *size;
                                *size += data.len() as u64;
                                stream_segment = Some((key, offset, std::mem::take(&mut data)));
                                Ok(())
                            }
                        };
                        if let Err(error) = write_result {
                            storage_failure = Some(error.to_string());
                        }
                        if segment_metadata.is_some() {
                            split.metadata = segment_metadata;
                        }
                        split.completed_segments = split_segment_index;
                        split.window = Some(split_window);
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
                                        app_flag: segment_app_flag,
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
                                                segment_app_flag,
                                            ));
                                        }
                                        Err(error) => storage_failure = Some(error.to_string()),
                                    }
                                }
                                IncomingSplitStorage::Stream { size } => {
                                    completed_stream =
                                        Some(crate::resource::ReceivedResourceStream {
                                            original_hash: key,
                                            size,
                                            metadata: split.metadata,
                                            app_flag: segment_app_flag,
                                        });
                                }
                            }
                            converted_actions.push(ResourceAction::Completed);
                        }
                    }
                    if storage_failure.is_some() {
                        link.incoming_splits.remove(&key);
                        converted_actions.clear();
                        converted_actions.push(ResourceAction::SendCancelReceiver(
                            link.incoming_resources[idx].resource_hash.clone(),
                        ));
                    }
                }

                assemble_actions = converted_actions;
            } else if !split_is_request
                && !split_is_response
                && matches!(
                    link.resource_receive_mode,
                    ResourceReceiveMode::Stream { .. }
                )
            {
                // A Resource of one segment streams as that segment.
                let mut converted_actions = Vec::new();
                for action in assemble_actions {
                    match action {
                        ResourceAction::DataReceived {
                            data,
                            metadata,
                            app_flag,
                        } => {
                            completed_stream = Some(crate::resource::ReceivedResourceStream {
                                original_hash: resource_original_hash,
                                size: data.len() as u64,
                                metadata,
                                app_flag,
                            });
                            stream_segment = Some((resource_original_hash, 0, data));
                        }
                        other => converted_actions.push(other),
                    }
                }
                assemble_actions = converted_actions;
            } else if let (false, false, ResourceReceiveMode::TemporaryFile { directory, .. }) = (
                split_is_request,
                split_is_response,
                &link.resource_receive_mode,
            ) {
                let directory = directory.clone();
                let mut converted_actions = Vec::new();
                for action in assemble_actions {
                    match action {
                        ResourceAction::DataReceived {
                            data,
                            metadata,
                            app_flag,
                        } => {
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
                                    app_flag,
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
                    converted_actions.push(ResourceAction::SendCancelReceiver(
                        link.incoming_resources[idx].resource_hash.clone(),
                    ));
                }
                assemble_actions = converted_actions;
            }
            all_actions.extend(assemble_actions);
        }

        // Only this Resource's actions pass through request/response
        // conversion, from `start` on.
        let start = out.len();
        self.process_resource_actions_into(link_id, all_actions.drain(..), rng, out);
        if let Some(resource) = completed_file {
            out.push(LinkManagerAction::ResourceFileReceived {
                link_id: *link_id,
                resource,
            });
        }
        if storage_failure.is_none() {
            if let Some((original_hash, offset, data)) = stream_segment {
                out.push(LinkManagerAction::ResourceSegmentReceived {
                    link_id: *link_id,
                    original_hash,
                    offset,
                    data,
                });
            }
            if let Some(resource) = completed_stream {
                out.push(LinkManagerAction::ResourceStreamReceived {
                    link_id: *link_id,
                    resource,
                });
            }
        }
        if let Some(error) = storage_failure {
            out.push(LinkManagerAction::ResourceFailed {
                link_id: *link_id,
                error: format!("resource storage failed: {error}"),
            });
        }

        if assembled_is_request {
            let mut converted = Vec::new();
            for action in out.drain(start..).collect::<Vec<_>>() {
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
            out.extend(converted);
        } else if assembled_is_response {
            let mut converted = Vec::new();
            for action in out.drain(start..).collect::<Vec<_>>() {
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
            out.extend(converted);
        }
    }
}
