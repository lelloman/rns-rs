//! Sending resources: building their senders and starting them.

use super::*;

impl LinkManager {
    pub(in crate::common::link_manager) fn request_response_deadline(
        link: &ManagedLink,
        now: f64,
    ) -> f64 {
        now + link.engine.rtt().unwrap_or(1.0) * constants::LINK_TRAFFIC_TIMEOUT_FACTOR
            + constants::RESOURCE_RESPONSE_MAX_GRACE_TIME * 1.125
    }

    /// Apply the per-transfer advertisement settings shared by every segment:
    /// the application flag, and the link MDU an advertisement must fit
    /// before its hashmap is deferred.
    pub(in crate::common::link_manager) fn configure_sender(
        link: &ManagedLink,
        sender: &mut ResourceSender,
        app_flag: bool,
    ) {
        sender.flags.app_flag = app_flag;
        sender.advertisement_mdu =
            rns_core::link::compute_mdu(Self::resource_mtu_for_link(link) as usize);
    }

    pub(in crate::common::link_manager) fn build_resource_senders(
        link: &ManagedLink,
        params: ResourceSendParams<'_>,
    ) -> Result<Vec<ResourceSender>, rns_core::resource::ResourceError> {
        let ResourceSendParams {
            data,
            metadata,
            auto_compress,
            app_flag,
            compressor,
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
            let encrypt_fn = LinkResourceEncrypt(&link.engine);
            return ResourceSender::new(
                data,
                metadata,
                resource_sdu,
                &encrypt_fn,
                compressor,
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
            .map(|mut sender| {
                Self::configure_sender(link, &mut sender, app_flag);
                vec![sender]
            });
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

        let encrypt_fn = LinkResourceEncrypt(&link.engine);

        let mut senders = Vec::new();
        let mut first = ResourceSender::new(
            &data[..first_payload_len],
            metadata,
            resource_sdu,
            &encrypt_fn,
            compressor,
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
        Self::configure_sender(link, &mut first, app_flag);
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
                compressor,
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
            Self::configure_sender(link, &mut sender, app_flag);
            senders.push(sender);
            segment_index += 1;
            offset = end;
        }

        Ok(senders)
    }

    pub(in crate::common::link_manager) fn start_resource_senders(
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
        self.send_resource_with_options(
            link_id,
            data,
            metadata,
            ResourceSendOptions {
                auto_compress,
                ..ResourceSendOptions::default()
            },
            rng,
        )
    }

    /// Start sending a resource on a link with explicit send options.
    pub fn send_resource_with_options(
        &mut self,
        link_id: &LinkId,
        data: &[u8],
        metadata: Option<&[u8]>,
        options: ResourceSendOptions,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        self.send_resource_with_compressor(link_id, data, metadata, options, &Bzip2Compressor, rng)
    }

    pub(crate) fn send_resource_with_compressor(
        &mut self,
        link_id: &LinkId,
        data: &[u8],
        metadata: Option<&[u8]>,
        options: ResourceSendOptions,
        compressor: &dyn rns_core::buffer::types::Compressor,
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
                auto_compress: options.auto_compress,
                app_flag: options.app_flag,
                compressor,
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

    /// Set the resource acceptance strategy for a link.
    pub fn set_resource_strategy(&mut self, link_id: &LinkId, strategy: ResourceStrategy) {
        if let Some(link) = self.links.get_mut(link_id) {
            link.resource_strategy = strategy;
        }
    }
}
