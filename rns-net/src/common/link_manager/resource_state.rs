//! Resource bookkeeping shared by sends and receives.

use super::*;

impl LinkManager {
    /// The MTU resources on the link are sized for: the link MTU, or on a
    /// direct path the MTU both sides started it with (see
    /// `DirectRoute::resource_mtu`).
    pub(super) fn resource_mtu_for_link(link: &ManagedLink) -> u32 {
        let mtu = link.engine.mtu();
        link.direct_route
            .as_ref()
            .map_or(mtu, |direct| mtu.min(direct.resource_mtu))
    }

    pub(super) fn resource_sdu_for_link(link: &ManagedLink) -> usize {
        // Python parity: Resource.sdu = link.mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE
        // when MTU signalling is available on the link.
        let mtu = Self::resource_mtu_for_link(link) as usize;
        let derived = mtu.saturating_sub(constants::HEADER_MAXSIZE + constants::IFAC_MIN_SIZE);
        if derived > 0 {
            derived
        } else {
            constants::RESOURCE_SDU
        }
    }

    pub(super) fn split_progress_parts(
        segment_index: u64,
        total_segments: u64,
        current_done: usize,
        current_total: usize,
        sdu: usize,
    ) -> (usize, usize) {
        let max_parts_per_segment = constants::RESOURCE_MAX_EFFICIENT_SIZE.div_ceil(sdu.max(1));
        let total = (total_segments as usize).saturating_mul(max_parts_per_segment);
        let completed_segments = segment_index.saturating_sub(1) as usize;
        let completed = completed_segments.saturating_mul(max_parts_per_segment);
        let current = if current_total == 0 {
            0
        } else if current_total < max_parts_per_segment {
            let scaled =
                (current_done as f64) * (max_parts_per_segment as f64 / current_total as f64);
            scaled.floor() as usize
        } else {
            current_done
        };
        (completed.saturating_add(current).min(total), total)
    }

    /// Keep a handled plaintext's buffer for the next decryption.
    pub(super) fn recycle_plaintext(&mut self, mut plaintext: Vec<u8>) {
        if plaintext.capacity() > self.plaintext_scratch.capacity() {
            plaintext.clear();
            self.plaintext_scratch = plaintext;
        }
    }

    pub(super) fn resource_hash_key(hash: &[u8]) -> Option<[u8; 32]> {
        let mut key = [0u8; 32];
        if hash.len() != key.len() {
            return None;
        }
        key.copy_from_slice(hash);
        Some(key)
    }

    /// Storage for an incoming split Resource whose advertised logical size
    /// is `data_size`.
    pub(super) fn incoming_storage(
        mode: &ResourceReceiveMode,
        original_hash: &[u8; 32],
        data_size: u64,
    ) -> std::io::Result<IncomingSplitStorage> {
        match mode {
            // Reserve the whole Resource once so appending segments never
            // reallocates and copies the data received so far. The size is the
            // peer's claim, so the reservation never exceeds the mode's limit.
            ResourceReceiveMode::Memory { max_bytes } => {
                let capacity = usize::try_from(data_size.min(*max_bytes)).unwrap_or(0);
                let buffer = Vec::with_capacity(capacity);
                #[cfg(target_os = "linux")]
                advise_huge_pages(&buffer);
                Ok(IncomingSplitStorage::Memory(buffer))
            }
            ResourceReceiveMode::TemporaryFile { directory, .. } => {
                let (file, path) = crate::resource::create_receive_file(directory, original_hash)?;
                Ok(IncomingSplitStorage::File {
                    file,
                    path,
                    size: 0,
                })
            }
            ResourceReceiveMode::Stream { .. } => Ok(IncomingSplitStorage::Stream { size: 0 }),
        }
    }

    pub(super) fn incoming_split_progress(
        split: &IncomingSplitTransfer,
        sdu: usize,
    ) -> (usize, usize) {
        Self::split_progress_parts(
            split.current_segment_index,
            split.total_segments,
            split.current_received_parts,
            split.current_total_parts,
            sdu,
        )
    }

    pub(super) fn outgoing_split_progress(
        split: &OutgoingSplitTransfer,
        sdu: usize,
    ) -> (usize, usize) {
        Self::split_progress_parts(
            split.current_segment_index,
            split.total_segments,
            split.current_sent_parts,
            split.current_total_parts,
            sdu,
        )
    }

    /// Get the number of active resource transfers across all links.
    pub fn resource_transfer_count(&self) -> usize {
        self.links
            .values()
            .map(|managed| {
                managed
                    .incoming_resources
                    .iter()
                    .filter(|resource| !resource.flags.split && resource.assembly_id().is_none())
                    .count()
                    + managed.incoming_splits.len()
                    + managed
                        .outgoing_resources
                        .iter()
                        .filter(|resource| !resource.flags.split)
                        .count()
                    + managed.outgoing_splits.len()
            })
            .sum::<usize>()
            + self
                .receive_worker
                .as_ref()
                .map_or(0, |worker| worker.len())
    }

    /// Cancel all active resource transfers and return the generated actions.
    pub fn cancel_all_resources(&mut self, rng: &mut dyn Rng) -> Vec<LinkManagerAction> {
        let link_ids: Vec<LinkId> = self.links.keys().copied().collect();
        let mut all_actions = Vec::new();

        for link_id in &link_ids {
            let link = match self.links.get_mut(link_id) {
                Some(l) => l,
                None => continue,
            };

            let mut sender_actions = Vec::new();
            for sender in &mut link.outgoing_resources {
                sender_actions.extend(sender.cancel());
            }

            let mut receiver_actions = Vec::new();
            for receiver in &mut link.incoming_resources {
                receiver_actions.extend(receiver.cancel());
            }

            link.outgoing_resources
                .retain(|s| s.status < rns_core::resource::ResourceStatus::Complete);
            link.incoming_resources
                .retain(|r| r.status < rns_core::resource::ResourceStatus::Complete);
            link.outgoing_splits.clear();
            all_actions.extend(link.outgoing_streams.drain().map(|(_, stream)| {
                LinkManagerAction::ResourceStreamFailed {
                    link_id: *link_id,
                    transfer_id: stream.transfer_id,
                    error: ResourceTransferError::Cancelled,
                }
            }));
            link.incoming_splits.clear();

            all_actions.extend(self.process_resource_actions(link_id, sender_actions, rng));
            all_actions.extend(self.process_resource_actions(link_id, receiver_actions, rng));
        }

        all_actions
    }

    /// Get information about all active resource transfers.
    pub fn resource_entries(&self) -> Vec<crate::event::ResourceInfoEntry> {
        let mut entries = Vec::new();
        for (link_id, managed) in &self.links {
            let resource_sdu = Self::resource_sdu_for_link(managed);
            for split in managed.incoming_splits.values() {
                let (received, total) = Self::incoming_split_progress(split, resource_sdu);
                entries.push(crate::event::ResourceInfoEntry {
                    link_id: *link_id,
                    direction: "incoming".to_string(),
                    total_parts: total,
                    transferred_parts: received,
                    complete: received >= total && total > 0,
                });
            }
            for recv in &managed.incoming_resources {
                if recv.flags.split {
                    continue;
                }
                let (received, total) = recv.progress();
                entries.push(crate::event::ResourceInfoEntry {
                    link_id: *link_id,
                    direction: "incoming".to_string(),
                    total_parts: total,
                    transferred_parts: received,
                    complete: received >= total && total > 0,
                });
            }
            for split in managed.outgoing_splits.values() {
                let (sent, total) = Self::outgoing_split_progress(split, resource_sdu);
                entries.push(crate::event::ResourceInfoEntry {
                    link_id: *link_id,
                    direction: "outgoing".to_string(),
                    total_parts: total,
                    transferred_parts: sent,
                    complete: sent >= total && total > 0,
                });
            }
            for send in &managed.outgoing_resources {
                if send.flags.split {
                    continue;
                }
                let total = send.total_parts();
                let sent = send.sent_parts;
                entries.push(crate::event::ResourceInfoEntry {
                    link_id: *link_id,
                    direction: "outgoing".to_string(),
                    total_parts: total,
                    transferred_parts: sent,
                    complete: sent >= total && total > 0,
                });
            }
        }
        entries
    }
}
