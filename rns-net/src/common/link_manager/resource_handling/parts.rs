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
        let intake = Self::offer_part_to_receivers(
            link,
            link_id,
            raw_data,
            all_actions,
            &mut self.receive_decrypts,
        );

        if let Some((segment_progress, transfer_size)) = intake.segment_progress {
            out.push(LinkManagerAction::ResourceSegmentProgress {
                link_id: *link_id,
                segment_progress,
                transfer_size,
            });
        }
        // Parts held in order go to the decryption feeder as they line up;
        // a resource about to assemble takes its decryption back.
        if let Some(hash) = intake.accepted {
            if intake.assemble_idx.is_some() {
                self.finish_decryption(link_id, hash);
            } else {
                self.feed_decryption(link_id, hash);
            }
        }
        let assembled = match intake.assemble_idx {
            Some(idx) => match self.assemble_received_resource(link_id, idx, rng, all_actions, out)
            {
                Some(assembled) => assembled,
                None => return,
            },
            None => AssembledResource::default(),
        };

        // Only this Resource's actions pass through request/response
        // conversion, from `start` on.
        let start = out.len();
        self.process_resource_actions_into(link_id, all_actions.drain(..), rng, out);
        let AssembledResource {
            is_request,
            is_response,
            request_request_id,
            response_request_id,
            completed_file,
            stream_segment,
            completed_stream,
            storage_failure,
        } = assembled;
        Self::push_received_storage(
            link_id,
            completed_file,
            stream_segment,
            completed_stream,
            storage_failure,
            out,
        );

        if is_request {
            self.convert_request_resource(link_id, start, request_request_id, rng, out);
        } else if is_response {
            self.convert_response_resource(link_id, start, response_request_id, out);
        }
    }

    /// Offer a part to the first receiver still taking parts that accepts
    /// it, appending its actions to `all_actions`.
    #[inline]
    fn offer_part_to_receivers(
        link: &mut ManagedLink,
        link_id: &LinkId,
        raw_data: &[u8],
        all_actions: &mut Vec<ResourceAction>,
        receive_decrypts: &mut std::collections::VecDeque<(LinkId, [u8; 32])>,
    ) -> PartIntake {
        let now = time::now();
        let resource_sdu = Self::resource_sdu_for_link(link);
        let mut intake = PartIntake {
            accepted: None,
            segment_progress: None,
            assemble_idx: None,
        };

        for (idx, receiver) in link.incoming_resources.iter_mut().enumerate() {
            if receiver.status >= rns_core::resource::ResourceStatus::Assembling {
                continue;
            }
            let before = all_actions.len();
            receiver.receive_part_into(raw_data, now, all_actions);
            if all_actions.len() > before {
                intake.accepted = Self::resource_hash_key(&receiver.resource_hash);
                intake.segment_progress = Some((
                    (receiver.received_count as f64 / receiver.total_parts.max(1) as f64).min(1.0),
                    receiver.transfer_size,
                ));
                if receiver.received_count == receiver.total_parts {
                    intake.assemble_idx = Some(idx);
                } else if !Self::feeds_decryption() && receiver.has_parts_to_decrypt() {
                    // Without the decryption thread (the compact engine, or
                    // one CPU), parts are decrypted ahead in idle slices:
                    // pinned, a single-segment resource ran at 150 MB/s
                    // decrypted at assembly against 197 decrypted ahead.
                    // With the thread, it takes resources of 64 KiB and up,
                    // and smaller ones decrypt at assembly.
                    if let Ok(hash) = <[u8; 32]>::try_from(&receiver.resource_hash[..]) {
                        if !receive_decrypts.contains(&(*link_id, hash)) {
                            receive_decrypts.push_back((*link_id, hash));
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
                            for action in all_actions.iter_mut().skip(before) {
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
        intake
    }

    /// Assemble the receiver at `idx`, which holds all its parts: hand it to
    /// the folded queue or the receive worker, whose actions are processed
    /// here (`None`), or assemble it now and say what it delivered.
    #[inline]
    fn assemble_received_resource(
        &mut self,
        link_id: &LinkId,
        idx: usize,
        rng: &mut dyn Rng,
        all_actions: &mut Vec<ResourceAction>,
        out: &mut Vec<LinkManagerAction>,
    ) -> Option<AssembledResource> {
        let link = self.links.get_mut(link_id)?;
        let receiver = link.incoming_resources.get(idx)?;
        let eligible = Self::receive_offload_eligible(link, receiver);
        let resource_hash = Self::resource_hash_key(&receiver.resource_hash)?;
        // Earlier application completions go first, with their final
        // action types.
        out.extend(self.wait_receive_for(link_id, rng));
        if eligible && !crate::engine::FOLD_WORK {
            self.ensure_receive_worker();
        }
        // A preceding corrupt assembly may have torn down this link, and
        // polling the worker prunes receivers that completed meanwhile, so
        // the receiver is located again by hash: its index may have moved.
        let link = self
            .links
            .get_mut(link_id)
            .filter(|link| link.engine.state() == LinkState::Active)?;
        let idx = link
            .incoming_resources
            .iter()
            .position(|r| r.resource_hash[..] == resource_hash[..])?;
        if eligible && crate::engine::FOLD_WORK {
            let actions = Self::hand_off_assembly(link, idx, |generation, assembly| {
                Self::queue_folded_assembly(
                    &mut self.folded_assemblies,
                    *link_id,
                    generation,
                    assembly,
                )
            });
            all_actions.extend(actions);
            self.process_resource_actions_into(link_id, all_actions.drain(..), rng, out);
            return None;
        }
        let worker = self.receive_worker.as_mut().filter(|_| eligible);
        if let Some(worker) = worker {
            // Admission/disconnection fallback uses the already-authenticated
            // handoff; no additional decryption or unbounded retry.
            let actions = Self::hand_off_assembly(link, idx, |generation, assembly| {
                worker.submit(*link_id, generation, assembly)
            });
            all_actions.extend(actions);
            self.process_resource_actions_into(link_id, all_actions.drain(..), rng, out);
            return None;
        }
        let mut assembled = AssembledResource::default();
        let assemble_actions = Self::assemble_in_place(link, idx, &mut assembled);
        all_actions.extend(assemble_actions);
        Some(assembled)
    }

    /// Decrypt the receiver's parts and `submit` the assembly to run off
    /// the driver; one `submit` refuses is assembled here instead.
    #[inline]
    fn hand_off_assembly(
        link: &mut ManagedLink,
        idx: usize,
        submit: impl FnOnce(
            std::sync::Arc<()>,
            rns_core::resource::ResourceAssembly,
        ) -> Result<(), rns_core::resource::ResourceAssembly>,
    ) -> Vec<ResourceAction> {
        let Some(receiver) = link.incoming_resources.get_mut(idx) else {
            return Vec::new();
        };
        match receiver.prepare_assembly(&|parts, skip| {
            link.engine.decrypt_chunks(parts, skip).map_err(|_| ())
        }) {
            Ok(assembly) => match submit(link.resource_generation.clone(), assembly) {
                Ok(()) => Vec::new(),
                Err(assembly) => receiver.complete_assembly(assembly.run(&Bzip2Compressor)),
            },
            Err(actions) => actions,
        }
    }

    /// Assemble the receiver at `idx` on this thread, and route its data by
    /// the link's receive mode: into a split's storage, a stream, or a file.
    #[inline]
    fn assemble_in_place(
        link: &mut ManagedLink,
        idx: usize,
        assembled: &mut AssembledResource,
    ) -> Vec<ResourceAction> {
        let Some(receiver) = link.incoming_resources.get_mut(idx) else {
            return Vec::new();
        };
        let split_key = if receiver.flags.split {
            Self::resource_hash_key(&receiver.original_hash)
        } else {
            None
        };
        let segment = SplitSegment {
            index: receiver.segment_index,
            window: (receiver.window.clone(), receiver.eifr),
            total: receiver.total_segments,
            parts: receiver.total_parts,
        };
        let is_request = receiver.flags.is_request;
        let is_response = receiver.flags.is_response;
        let resource_original_hash =
            Self::resource_hash_key(&receiver.original_hash).unwrap_or([0; 32]);
        let resource_request_id = Self::response_request_id(&receiver.request_id);
        if is_request {
            assembled.request_request_id = resource_request_id;
        } else if is_response {
            assembled.response_request_id = resource_request_id;
        }
        let decrypt_fn = |parts: &[&[u8]], skip: usize| -> Result<Vec<u8>, ()> {
            link.engine.decrypt_chunks(parts, skip).map_err(|_| ())
        };
        let assemble_actions = receiver.assemble(&decrypt_fn, &Bzip2Compressor);
        assembled.is_request = is_request;
        assembled.is_response = is_response;

        if let Some(key) = split_key {
            Self::collect_split_segment(link, idx, key, segment, assemble_actions, assembled)
        } else if !is_request
            && !is_response
            && matches!(
                link.resource_receive_mode,
                ResourceReceiveMode::Stream { .. }
            )
        {
            Self::stream_single_segment(assemble_actions, resource_original_hash, assembled)
        } else if let (false, false, ResourceReceiveMode::TemporaryFile { directory, .. }) =
            (is_request, is_response, &link.resource_receive_mode)
        {
            Self::store_in_temporary_file(
                directory,
                resource_original_hash,
                link.incoming_resources
                    .get(idx)
                    .map_or(&[][..], |receiver| &receiver.resource_hash),
                assemble_actions,
                assembled,
            )
        } else {
            assemble_actions
        }
    }

    /// Add one assembled segment of a split Resource to the split's
    /// storage, and complete the Resource with its last segment.
    #[inline]
    fn collect_split_segment(
        link: &mut ManagedLink,
        idx: usize,
        key: [u8; 32],
        segment: SplitSegment,
        assemble_actions: Vec<ResourceAction>,
        assembled: &mut AssembledResource,
    ) -> Vec<ResourceAction> {
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

        if let Some(data) = segment_data {
            let segment_index = segment.index;
            let segment_total = segment.total;
            if let Some(split) = link.incoming_splits.get_mut(&key) {
                Self::store_split_segment(split, key, data, segment_metadata, segment, assembled);
            }

            if assembled.storage_failure.is_none() && segment_index == segment_total {
                if let Some(split) = link.incoming_splits.remove(&key) {
                    Self::complete_split(
                        split,
                        key,
                        segment_app_flag,
                        assembled,
                        &mut converted_actions,
                    );
                }
            }
            if assembled.storage_failure.is_some() {
                link.incoming_splits.remove(&key);
                converted_actions.clear();
                let resource_hash = link
                    .incoming_resources
                    .get(idx)
                    .map(|receiver| receiver.resource_hash.clone())
                    .unwrap_or_default();
                converted_actions.push(ResourceAction::SendCancelReceiver(resource_hash));
            }
        }

        converted_actions
    }

    /// Write a segment's data to its split's storage (a stream hands it on
    /// instead) and move the split's progress past it.
    #[inline]
    fn store_split_segment(
        split: &mut IncomingSplitTransfer,
        key: [u8; 32],
        mut data: Vec<u8>,
        segment_metadata: Option<Vec<u8>>,
        segment: SplitSegment,
        assembled: &mut AssembledResource,
    ) {
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
                assembled.stream_segment = Some((key, offset, std::mem::take(&mut data)));
                Ok(())
            }
        };
        if let Err(error) = write_result {
            assembled.storage_failure = Some(error.to_string());
        }
        if segment_metadata.is_some() {
            split.metadata = segment_metadata;
        }
        split.completed_segments = segment.index;
        split.window = Some(segment.window);
        split.current_segment_index = segment.index;
        split.current_received_parts = segment.parts;
        split.current_total_parts = segment.parts;
    }

    /// Deliver a split Resource whose last segment arrived, from the
    /// storage it was collected in.
    #[inline]
    fn complete_split(
        split: IncomingSplitTransfer,
        key: [u8; 32],
        app_flag: bool,
        assembled: &mut AssembledResource,
        converted_actions: &mut Vec<ResourceAction>,
    ) {
        assembled.is_request = split.is_request;
        assembled.is_response = split.is_response;
        match split.storage {
            IncomingSplitStorage::Memory(data) => {
                converted_actions.push(ResourceAction::DataReceived {
                    data,
                    metadata: split.metadata,
                    app_flag,
                });
            }
            IncomingSplitStorage::File { file, path, size } => match file.sync_all() {
                Ok(()) => {
                    assembled.completed_file = Some(ReceivedResourceFile::new(
                        path,
                        key,
                        size,
                        split.metadata,
                        app_flag,
                    ));
                }
                Err(error) => assembled.storage_failure = Some(error.to_string()),
            },
            IncomingSplitStorage::Stream { size } => {
                assembled.completed_stream = Some(crate::resource::ReceivedResourceStream {
                    original_hash: key,
                    size,
                    metadata: split.metadata,
                    app_flag,
                });
            }
        }
        converted_actions.push(ResourceAction::Completed);
    }

    /// A Resource of one segment streams as that segment.
    #[inline]
    fn stream_single_segment(
        assemble_actions: Vec<ResourceAction>,
        resource_original_hash: [u8; 32],
        assembled: &mut AssembledResource,
    ) -> Vec<ResourceAction> {
        let mut converted_actions = Vec::new();
        for action in assemble_actions {
            match action {
                ResourceAction::DataReceived {
                    data,
                    metadata,
                    app_flag,
                } => {
                    assembled.completed_stream = Some(crate::resource::ReceivedResourceStream {
                        original_hash: resource_original_hash,
                        size: data.len() as u64,
                        metadata,
                        app_flag,
                    });
                    assembled.stream_segment = Some((resource_original_hash, 0, data));
                }
                other => converted_actions.push(other),
            }
        }
        converted_actions
    }

    /// Write an assembled Resource to a temporary file in `directory`; one
    /// that cannot be stored is cancelled rather than proven.
    #[inline]
    fn store_in_temporary_file(
        directory: &std::path::Path,
        resource_original_hash: [u8; 32],
        resource_hash: &[u8],
        assemble_actions: Vec<ResourceAction>,
        assembled: &mut AssembledResource,
    ) -> Vec<ResourceAction> {
        let mut converted_actions = Vec::new();
        for action in assemble_actions {
            match action {
                ResourceAction::DataReceived {
                    data,
                    metadata,
                    app_flag,
                } => {
                    match crate::resource::create_receive_file(directory, &resource_original_hash)
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
                        Ok(resource) => assembled.completed_file = Some(resource),
                        Err(error) => assembled.storage_failure = Some(error.to_string()),
                    }
                }
                other => converted_actions.push(other),
            }
        }
        if assembled.storage_failure.is_some() {
            converted_actions.retain(|action| {
                !matches!(
                    action,
                    ResourceAction::SendProof(_) | ResourceAction::Completed
                )
            });
            converted_actions.push(ResourceAction::SendCancelReceiver(resource_hash.to_vec()));
        }
        converted_actions
    }

    /// Report a Resource delivered to a file or a stream, or the storage
    /// failure that cancelled it.
    #[inline]
    fn push_received_storage(
        link_id: &LinkId,
        completed_file: Option<ReceivedResourceFile>,
        stream_segment: Option<([u8; 32], u64, Vec<u8>)>,
        completed_stream: Option<crate::resource::ReceivedResourceStream>,
        storage_failure: Option<String>,
        out: &mut Vec<LinkManagerAction>,
    ) {
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
    }

    /// Turn a received request Resource, the actions from `start` on, into
    /// the request it carries.
    fn convert_request_resource(
        &mut self,
        link_id: &LinkId,
        start: usize,
        request_id: Option<[u8; 16]>,
        rng: &mut dyn Rng,
        out: &mut Vec<LinkManagerAction>,
    ) {
        let mut converted = Vec::new();
        for action in out.drain(start..).collect::<Vec<_>>() {
            match action {
                LinkManagerAction::ResourceReceived { data, .. } => {
                    if let Some(request_id) = request_id {
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
    }

    /// Turn a received response Resource, the actions from `start` on, into
    /// the response it carries.
    fn convert_response_resource(
        &mut self,
        link_id: &LinkId,
        start: usize,
        request_id: Option<[u8; 16]>,
        out: &mut Vec<LinkManagerAction>,
    ) {
        let mut converted = Vec::new();
        for action in out.drain(start..).collect::<Vec<_>>() {
            match action {
                LinkManagerAction::ResourceReceived { data, metadata, .. } => {
                    converted.extend(self.handle_response(link_id, &data, metadata, request_id));
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

/// What offering a part to a link's receivers came to.
struct PartIntake {
    /// The hash of the Resource that took the part.
    accepted: Option<[u8; 32]>,
    /// That Resource's segment progress and transfer size.
    segment_progress: Option<(f64, u64)>,
    /// Its index, once it holds all its parts.
    assemble_idx: Option<usize>,
}

/// Where an assembled segment sits in its split Resource.
struct SplitSegment {
    index: u64,
    window: (rns_core::resource::WindowState, Option<f64>),
    total: u64,
    parts: usize,
}

/// What assembling a Resource on the driver produced, besides its actions.
#[derive(Default)]
struct AssembledResource {
    is_request: bool,
    is_response: bool,
    request_request_id: Option<[u8; 16]>,
    response_request_id: Option<[u8; 16]>,
    completed_file: Option<ReceivedResourceFile>,
    /// Streamed delivery: this segment, and the whole Resource once its
    /// last segment arrived.
    stream_segment: Option<([u8; 32], u64, Vec<u8>)>,
    completed_stream: Option<crate::resource::ReceivedResourceStream>,
    storage_failure: Option<String>,
}
