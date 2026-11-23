//! Streamed resources: reading and building their segments.

use super::*;

impl LinkManager {
    pub(in crate::common::link_manager) fn read_stream_segment(
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

    #[allow(
        clippy::too_many_arguments,
        reason = "each argument is an independent input of the segment; the link and stream are disjoint borrows of link manager state"
    )]
    pub(super) fn build_stream_segment(
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
        let encrypt_fn = LinkResourceEncrypt(&link.engine);
        let mut sender = ResourceSender::new(
            &data,
            metadata,
            Self::resource_sdu_for_link(link),
            &encrypt_fn,
            &ResourceCompressor,
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
        Self::configure_sender(link, &mut sender, stream.app_flag);
        Ok(sender)
    }

    /// Prepare the next segment of one stream whose current segment is fully
    /// sent and awaits its proof, so that the proof can advertise it at once.
    pub(super) fn prepare_next_stream_segment(
        &mut self,
        (link_id, original_hash, segment_index): (LinkId, [u8; 32], u64),
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        // Built, or being built, on the builder thread.
        if self.segment_building(&link_id, &original_hash) {
            return Vec::new();
        }
        let Some(link) = self
            .links
            .get_mut(&link_id)
            .filter(|link| link.engine.state() == LinkState::Active)
        else {
            return Vec::new();
        };
        let mut total_segments = None;
        for sender in &link.outgoing_resources {
            if !sender.flags.split || sender.original_hash != original_hash {
                continue;
            }
            if sender.segment_index > segment_index {
                // Already prepared, or the proof came first.
                return Vec::new();
            }
            if sender.segment_index == segment_index
                && sender.status == rns_core::resource::ResourceStatus::AwaitingProof
            {
                total_segments = Some(sender.total_segments);
            }
        }
        let Some(total_segments) = total_segments else {
            return Vec::new();
        };
        let Some(mut stream) = link.outgoing_streams.remove(&original_hash) else {
            return Vec::new();
        };
        match Self::build_stream_segment(
            link,
            &mut stream,
            None,
            segment_index + 1,
            total_segments,
            Some(original_hash),
            rng,
            time::now(),
        ) {
            Ok(next) => {
                link.outgoing_resources.push(next);
                link.outgoing_streams.insert(original_hash, stream);
                Vec::new()
            }
            Err(error) => {
                // The source has advanced past this segment: the transfer
                // cannot go on, so its segment in flight is cancelled.
                let mut cancel = Vec::new();
                for sender in &mut link.outgoing_resources {
                    if sender.flags.split && sender.original_hash == original_hash {
                        cancel.extend(sender.cancel());
                    }
                }
                link.outgoing_resources
                    .retain(|s| !s.flags.split || s.original_hash != original_hash);
                link.outgoing_splits.remove(&original_hash);
                let mut actions = self.process_resource_actions(&link_id, cancel, rng);
                actions.extend(stream.failed(link_id, error));
                actions
            }
        }
    }

    /// Start a bounded-memory Resource transfer from a sequential reader.
    ///
    /// The declared-length reader is consumed directly. Unlike the upstream
    /// zero-stat compatibility path, no temporary buffered proxy must be
    /// flushed and rewound before its size or first segment can be observed.
    #[allow(
        clippy::too_many_arguments,
        reason = "public link manager entry point; each argument is an independent property of the transfer"
    )]
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
        self.send_resource_stream_with_options(
            link_id,
            transfer_id,
            reader,
            declared_length,
            metadata,
            ResourceSendOptions {
                auto_compress,
                ..ResourceSendOptions::default()
            },
            rng,
        )
    }

    /// Start a bounded-memory Resource transfer from a sequential reader with
    /// explicit send options.
    #[allow(
        clippy::too_many_arguments,
        reason = "public link manager entry point; each argument is an independent property of the transfer"
    )]
    pub fn send_resource_stream_with_options(
        &mut self,
        link_id: &LinkId,
        transfer_id: ResourceTransferId,
        reader: Box<dyn Read + Send>,
        declared_length: u64,
        metadata: Option<Vec<u8>>,
        options: ResourceSendOptions,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        self.start_segmented_resource(
            link_id,
            StreamReport::Transfer(transfer_id),
            reader,
            declared_length,
            metadata,
            options,
            rng,
        )
    }

    /// Start sending a buffered Resource. One that fits a segment is built
    /// at once. A larger one is sent like a reader transfer, each segment
    /// built while the one before it is in flight instead of all of them
    /// before the first is advertised, and reports its progress, completion
    /// and failure as a buffered Resource.
    pub(crate) fn send_owned_resource(
        &mut self,
        link_id: &LinkId,
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        options: ResourceSendOptions,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let metadata_overhead = metadata.as_ref().map_or(0, |value| 3 + value.len());
        if metadata_overhead.saturating_add(data.len()) <= constants::RESOURCE_MAX_EFFICIENT_SIZE {
            return self.send_resource_with_options(
                link_id,
                &data,
                metadata.as_deref(),
                options,
                rng,
            );
        }
        let declared_length = data.len() as u64;
        self.start_segmented_resource(
            link_id,
            StreamReport::Buffered,
            Box::new(std::io::Cursor::new(data)),
            declared_length,
            metadata,
            options,
            rng,
        )
    }

    /// Start a Resource read from `reader` segment by segment, reporting
    /// as `report` says.
    #[allow(
        clippy::too_many_arguments,
        reason = "each argument is an independent property of the transfer"
    )]
    fn start_segmented_resource(
        &mut self,
        link_id: &LinkId,
        report: StreamReport,
        reader: Box<dyn Read + Send>,
        declared_length: u64,
        metadata: Option<Vec<u8>>,
        options: ResourceSendOptions,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        // A transfer that cannot start: a reader transfer reports it, a
        // buffered send logs it, as buffered sends always have.
        let not_started = |error: ResourceTransferError| match report {
            StreamReport::Transfer(transfer_id) => vec![LinkManagerAction::ResourceStreamFailed {
                link_id: *link_id,
                transfer_id,
                error,
            }],
            StreamReport::Buffered => {
                log::debug!("Failed to create ResourceSender: {}", error);
                Vec::new()
            }
        };
        let Some(link) = self.links.get_mut(link_id) else {
            return not_started(ResourceTransferError::Protocol(
                "link does not exist".into(),
            ));
        };
        if link.engine.state() != LinkState::Active {
            return not_started(ResourceTransferError::Protocol("link is not active".into()));
        }

        let metadata_overhead = metadata.as_ref().map(|value| 3 + value.len()).unwrap_or(0);
        let Some(logical_size) = declared_length.checked_add(metadata_overhead as u64) else {
            return not_started(ResourceTransferError::Protocol(
                "resource length overflow".into(),
            ));
        };
        if usize::try_from(logical_size).is_err()
            || metadata_overhead > constants::RESOURCE_MAX_EFFICIENT_SIZE
        {
            return not_started(ResourceTransferError::Protocol(
                "resource length cannot be represented by this platform".into(),
            ));
        }

        let first_capacity = constants::RESOURCE_MAX_EFFICIENT_SIZE - metadata_overhead;
        let first_length = declared_length.min(first_capacity as u64);
        let remaining_after_first = declared_length - first_length;
        let total_segments =
            1 + remaining_after_first.div_ceil(constants::RESOURCE_MAX_EFFICIENT_SIZE as u64);
        let now = time::now();
        let mut stream = OutgoingStreamTransfer {
            report,
            reader,
            remaining: declared_length,
            declared_length,
            metadata_overhead: metadata_overhead as u64,
            auto_compress: options.auto_compress,
            app_flag: options.app_flag,
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
            Err(error) => return not_started(error),
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
        let actions = self.process_resource_actions(link_id, adv_actions, rng);
        if total_segments > 1 {
            self.schedule_segment_build(link_id, original_hash);
        }
        actions
    }
}
