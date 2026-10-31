use alloc::vec;
use alloc::vec::Vec;

use super::advertisement::ResourceAdvertisement;
use super::assembly::{AssemblyData, AssemblyId, AssemblyResult, ResourceAssembly};
use super::parts::map_hash;
use super::types::*;
use super::window::WindowState;
use crate::buffer::types::Compressor;
use crate::constants::*;

/// Decrypts a resource's ciphertext held as its parts, in order, dropping the
/// first `skip` plaintext bytes (the random prefix). It must authenticate the
/// whole ciphertext before returning any plaintext.
pub type PartsDecryptFn<'a> = dyn Fn(&[&[u8]], usize) -> Result<Vec<u8>, ()> + 'a;

/// Resource receiver state machine.
///
/// Unpacks advertisements, requests parts, receives parts, assembles data.
/// Returns `Vec<ResourceAction>` — no I/O, no callbacks.
pub struct ResourceReceiver {
    assembly_id: Option<AssemblyId>,
    /// Current status
    pub status: ResourceStatus,
    /// Resource hash (from advertisement, 32 bytes)
    pub resource_hash: Vec<u8>,
    /// Random hash (from advertisement)
    pub random_hash: Vec<u8>,
    /// Original hash
    pub original_hash: Vec<u8>,
    /// Flags
    pub flags: AdvFlags,
    /// Transfer size (encrypted)
    pub transfer_size: u64,
    /// Total uncompressed data size
    pub data_size: u64,
    /// Total parts
    pub total_parts: usize,
    /// Received parts data (None = not yet received)
    parts: Vec<Option<Vec<u8>>>,
    /// Hashmap: part index -> map_hash (None if not yet known)
    hashmap: Vec<Option<[u8; RESOURCE_MAPHASH_LEN]>>,
    /// Number of hashmap entries populated
    hashmap_height: usize,
    /// Whether we're waiting for a hashmap update
    pub waiting_for_hmu: bool,
    /// Number of parts received
    pub received_count: usize,
    /// Outstanding parts in current window request
    pub outstanding_parts: usize,
    /// Consecutive completed height (-1 means none)
    consecutive_completed_height: isize,
    /// SDU size
    sdu: usize,
    /// Link RTT estimate (from link establishment)
    link_rtt: f64,
    /// Retries left
    pub retries_left: usize,
    /// Max retries
    max_retries: usize,
    /// RTT estimate
    pub rtt: Option<f64>,
    /// Part timeout factor
    part_timeout_factor: f64,
    /// Last activity timestamp
    pub last_activity: f64,
    /// Request sent timestamp
    pub req_sent: f64,
    /// Request sent bytes
    req_sent_bytes: usize,
    /// Request response timestamp
    req_resp: Option<f64>,
    /// RTT received bytes
    rtt_rxd_bytes: usize,
    /// RTT received bytes at part request
    rtt_rxd_bytes_at_part_req: usize,
    /// Request response RTT rate
    req_resp_rtt_rate: f64,
    /// Request data RTT rate
    req_data_rtt_rate: f64,
    /// EIFR
    pub eifr: Option<f64>,
    /// Previous EIFR from prior transfer
    previous_eifr: Option<f64>,
    /// Segment index
    pub segment_index: u64,
    /// Total segments
    pub total_segments: u64,
    /// Has metadata
    pub has_metadata: bool,
    /// Request ID
    pub request_id: Option<Vec<u8>>,
    /// Window state
    pub window: WindowState,
    /// Original advertisement bytes for this incoming transfer.
    pub advertisement_packet: Vec<u8>,
    /// Maximum allowed decompressed size for compressed resource payloads.
    pub max_decompressed_size: usize,
}

impl ResourceReceiver {
    /// Create a receiver from an advertisement packet.
    pub fn from_advertisement(
        adv_data: &[u8],
        sdu: usize,
        link_rtt: f64,
        now: f64,
        previous_window: Option<usize>,
        previous_eifr: Option<f64>,
    ) -> Result<Self, ResourceError> {
        let adv = ResourceAdvertisement::unpack(adv_data)?;

        // Validate resource_hash is 32 bytes
        if adv.resource_hash.len() != 32 {
            return Err(ResourceError::InvalidAdvertisement);
        }
        if adv.random_hash.len() != RESOURCE_RANDOM_HASH_SIZE || adv.original_hash.len() != 32 {
            return Err(ResourceError::InvalidAdvertisement);
        }
        // Split advertisements carry the logical size of the complete
        // Resource in data_size, while each receiver only assembles one
        // bounded segment. Aggregate receive policy is enforced by rns-net.
        if adv.transfer_size > RESOURCE_AUTO_COMPRESS_MAX_SIZE as u64
            || (!adv.flags.split && adv.data_size > RESOURCE_AUTO_COMPRESS_MAX_SIZE as u64)
        {
            return Err(ResourceError::TooLarge);
        }

        // Python derives the part count of the transfer it receives from the
        // advertised (encrypted, compressed) transfer size of this segment:
        // ceil(t / sdu). Senders compute `n` the same way over the same SDU,
        // so a matching advertisement carries exactly that count. No tolerance
        // applies: Python's receiver ignores `n` and expects exactly this many
        // parts, so a transfer advertising any other count cannot complete.
        let total_parts = usize::try_from(adv.num_parts).map_err(|_| ResourceError::TooLarge)?;
        if total_parts == 0 {
            return Err(ResourceError::InvalidAdvertisement);
        }
        let transfer_size =
            usize::try_from(adv.transfer_size).map_err(|_| ResourceError::TooLarge)?;
        let expected_parts = transfer_size.div_ceil(sdu.max(1));
        if total_parts != expected_parts {
            return Err(ResourceError::PartCountMismatch);
        }

        // Part storage grows as parts arrive, so an accepted advertisement
        // that is never followed by data holds no per-part allocation. The
        // hashmap holds only the entries the advertisement carries.
        let initial_hashes = core::cmp::min(adv.hashmap.len() / RESOURCE_MAPHASH_LEN, total_parts);
        let parts_vec: Vec<Option<Vec<u8>>> = Vec::new();
        let mut hashmap_vec: Vec<Option<[u8; RESOURCE_MAPHASH_LEN]>> =
            Vec::with_capacity(initial_hashes);

        // Populate initial hashmap from advertisement
        for chunk in adv
            .hashmap
            .chunks_exact(RESOURCE_MAPHASH_LEN)
            .take(initial_hashes)
        {
            let mut h = [0u8; RESOURCE_MAPHASH_LEN];
            h.copy_from_slice(chunk);
            hashmap_vec.push(Some(h));
        }
        let hashmap_height = hashmap_vec.len();

        let mut window_state = WindowState::new();
        if let Some(prev_w) = previous_window {
            window_state.restore(prev_w);
        }

        Ok(ResourceReceiver {
            assembly_id: None,
            status: ResourceStatus::None,
            resource_hash: adv.resource_hash,
            random_hash: adv.random_hash,
            original_hash: adv.original_hash,
            flags: adv.flags,
            transfer_size: adv.transfer_size,
            data_size: adv.data_size,
            total_parts,
            parts: parts_vec,
            hashmap: hashmap_vec,
            hashmap_height,
            waiting_for_hmu: false,
            received_count: 0,
            outstanding_parts: 0,
            consecutive_completed_height: -1,
            sdu,
            link_rtt,
            retries_left: RESOURCE_MAX_RETRIES,
            max_retries: RESOURCE_MAX_RETRIES,
            rtt: None,
            part_timeout_factor: RESOURCE_PART_TIMEOUT_FACTOR,
            last_activity: now,
            req_sent: 0.0,
            req_sent_bytes: 0,
            req_resp: None,
            rtt_rxd_bytes: 0,
            rtt_rxd_bytes_at_part_req: 0,
            req_resp_rtt_rate: 0.0,
            req_data_rtt_rate: 0.0,
            eifr: None,
            previous_eifr,
            segment_index: adv.segment_index,
            total_segments: adv.total_segments,
            has_metadata: adv.flags.has_metadata,
            request_id: adv.request_id,
            window: window_state,
            advertisement_packet: adv_data.to_vec(),
            max_decompressed_size: RESOURCE_AUTO_COMPRESS_MAX_SIZE,
        })
    }

    fn has_part(&self, index: usize) -> bool {
        self.parts.get(index).is_some_and(Option::is_some)
    }

    fn store_part(&mut self, index: usize, data: Vec<u8>) {
        if self.parts.len() <= index {
            self.parts.resize(index + 1, None);
        }
        self.parts[index] = Some(data);
    }

    fn hash_at(&self, index: usize) -> Option<&[u8; RESOURCE_MAPHASH_LEN]> {
        self.hashmap.get(index).and_then(Option::as_ref)
    }

    fn store_hash(&mut self, index: usize, hash: [u8; RESOURCE_MAPHASH_LEN]) {
        if self.hashmap.len() <= index {
            self.hashmap.resize(index + 1, None);
        }
        self.hashmap[index] = Some(hash);
    }

    /// Accept the advertised resource. Begins transfer.
    pub fn accept(&mut self, now: f64) -> Vec<ResourceAction> {
        if self.status >= ResourceStatus::Assembling {
            return vec![];
        }
        self.status = ResourceStatus::Transferring;
        self.last_activity = now;
        self.request_next(now)
    }

    /// Reject the advertised resource.
    pub fn reject(&mut self) -> Vec<ResourceAction> {
        self.status = ResourceStatus::Rejected;
        vec![ResourceAction::SendCancelReceiver(
            self.resource_hash.clone(),
        )]
    }

    /// Cancel an accepted incoming transfer.
    pub fn cancel(&mut self) -> Vec<ResourceAction> {
        if self.status < ResourceStatus::Complete {
            self.status = ResourceStatus::Failed;
            vec![ResourceAction::SendCancelReceiver(
                self.resource_hash.clone(),
            )]
        } else {
            Vec::new()
        }
    }

    fn corrupt_actions(&mut self, error: ResourceError) -> Vec<ResourceAction> {
        self.status = ResourceStatus::Corrupt;
        vec![
            ResourceAction::SendCancelReceiver(self.resource_hash.clone()),
            ResourceAction::Failed(error),
            ResourceAction::TeardownLink,
        ]
    }

    /// Receive a part. Matches by map hash and stores it.
    pub fn receive_part(&mut self, part_data: &[u8], now: f64) -> Vec<ResourceAction> {
        if self.status >= ResourceStatus::Assembling {
            return vec![];
        }

        self.last_activity = now;
        self.retries_left = self.max_retries;

        // Update RTT on first part of window
        if self.req_resp.is_none() {
            self.req_resp = Some(now);
            let rtt = now - self.req_sent;
            self.part_timeout_factor = RESOURCE_PART_TIMEOUT_FACTOR_AFTER_RTT;

            if self.rtt.is_none() {
                self.rtt = Some(rtt);
            } else if let Some(current_rtt) = self.rtt {
                if rtt < current_rtt {
                    self.rtt = Some(f64::max(current_rtt - current_rtt * 0.05, rtt));
                } else {
                    self.rtt = Some(f64::min(current_rtt + current_rtt * 0.05, rtt));
                }
            }

            if rtt > 0.0 {
                let req_resp_cost = part_data.len() + self.req_sent_bytes;
                self.req_resp_rtt_rate = req_resp_cost as f64 / rtt;
                self.window.update_req_resp_rate(self.req_resp_rtt_rate);
            }
        }

        self.status = ResourceStatus::Transferring;

        // Compute map hash for this part
        let part_hash = map_hash(part_data, &self.random_hash);

        // Align with request_next(): the completed height itself is not part
        // of the outstanding window, which starts at the following index.
        let search_start = (self.consecutive_completed_height + 1) as usize;
        let mut matched = false;
        let search_end = core::cmp::min(search_start + self.window.window, self.total_parts);
        for i in search_start..search_end {
            if let Some(h) = self.hash_at(i) {
                if *h == part_hash {
                    if !self.has_part(i) {
                        self.store_part(i, part_data.to_vec());
                        self.rtt_rxd_bytes += part_data.len();
                        self.received_count += 1;
                        self.outstanding_parts = self.outstanding_parts.saturating_sub(1);

                        // Walk forward to extend consecutive height
                        let mut cp = (self.consecutive_completed_height + 1) as usize;
                        while cp < self.total_parts && self.has_part(cp) {
                            self.consecutive_completed_height = cp as isize;
                            cp += 1;
                        }

                        matched = true;
                    }
                    break;
                }
            }
        }

        let mut actions = Vec::new();

        // Check if all parts received
        if self.received_count == self.total_parts {
            actions.push(ResourceAction::ProgressUpdate {
                received: self.received_count,
                total: self.total_parts,
            });
            // Assembly will be triggered by caller
            return actions;
        }

        if matched {
            actions.push(ResourceAction::ProgressUpdate {
                received: self.received_count,
                total: self.total_parts,
            });
        }

        // Request next window when outstanding is 0
        if self.outstanding_parts == 0 && self.received_count < self.total_parts {
            // Window complete — grow
            self.window.on_window_complete();

            // Update data rate
            if self.req_sent > 0.0 {
                let rtt = now - self.req_sent;
                let req_transferred = self.rtt_rxd_bytes - self.rtt_rxd_bytes_at_part_req;
                if rtt > 0.0 {
                    self.req_data_rtt_rate = req_transferred as f64 / rtt;
                    self.rtt_rxd_bytes_at_part_req = self.rtt_rxd_bytes;
                    self.window.update_data_rate(self.req_data_rtt_rate);
                }
            }

            let next_actions = self.request_next(now);
            actions.extend(next_actions);
        }

        actions
    }

    /// Handle a hashmap update packet.
    ///
    /// HMU format: [resource_hash: 32 bytes][msgpack([segment, hashmap])]
    pub fn handle_hashmap_update(&mut self, hmu_data: &[u8], now: f64) -> Vec<ResourceAction> {
        if self.status >= ResourceStatus::Assembling || !self.waiting_for_hmu {
            return vec![];
        }

        if hmu_data.len() < 32 || hmu_data[..32] != self.resource_hash {
            return vec![];
        }
        if hmu_data.len() == 32 {
            return self.cancel();
        }

        let payload = &hmu_data[32..];
        let value = match crate::msgpack::unpack_exact(payload) {
            Ok(v) => v,
            Err(_) => return self.cancel(),
        };

        let arr = match value.as_array() {
            Some(a) if a.len() == 2 => a,
            _ => return self.cancel(),
        };

        let segment = match arr[0].as_uint() {
            Some(s) => match usize::try_from(s) {
                Ok(segment) => segment,
                Err(_) => return self.cancel(),
            },
            None => return self.cancel(),
        };

        let hashmap_bytes = match arr[1].as_bin() {
            Some(b) => b,
            None => return self.cancel(),
        };

        if hashmap_bytes.is_empty() || !hashmap_bytes.len().is_multiple_of(RESOURCE_MAPHASH_LEN) {
            return self.cancel();
        }

        let seg_len = RESOURCE_HASHMAP_MAX_LEN;
        let segment_start = match segment.checked_mul(seg_len) {
            Some(start) if start < self.total_parts => start,
            _ => return self.cancel(),
        };
        let num_hashes = hashmap_bytes.len() / RESOURCE_MAPHASH_LEN;
        if num_hashes > seg_len || segment_start.saturating_add(num_hashes) > self.total_parts {
            return self.cancel();
        }

        self.last_activity = now;
        self.retries_left = self.max_retries;
        self.status = ResourceStatus::Transferring;

        // Populate hashmap slots
        for i in 0..num_hashes {
            let idx = segment_start + i;
            let start = i * RESOURCE_MAPHASH_LEN;
            let end = start + RESOURCE_MAPHASH_LEN;
            if self.hash_at(idx).is_none() {
                self.hashmap_height += 1;
            }
            let mut h = [0u8; RESOURCE_MAPHASH_LEN];
            h.copy_from_slice(&hashmap_bytes[start..end]);
            self.store_hash(idx, h);
        }

        self.waiting_for_hmu = false;
        self.request_next(now)
    }

    /// Build and return request for next window of parts.
    pub fn request_next(&mut self, now: f64) -> Vec<ResourceAction> {
        if self.status >= ResourceStatus::Assembling {
            return vec![];
        }
        if self.status == ResourceStatus::Failed || self.waiting_for_hmu {
            return vec![];
        }

        self.outstanding_parts = 0;
        let mut hashmap_exhausted = RESOURCE_HASHMAP_IS_NOT_EXHAUSTED;
        let mut requested_hashes = Vec::new();

        if self.hash_at(0).is_none() {
            // The advertisement carried no hashmap because it would not fit
            // the sender's link MDU. No part can be requested before the
            // sender delivers the first segment.
            hashmap_exhausted = RESOURCE_HASHMAP_IS_EMPTY;
        } else {
            let pn_start = (self.consecutive_completed_height + 1) as usize;
            let search_end = core::cmp::min(pn_start + self.window.window, self.total_parts);
            let mut i = 0;

            for pn in pn_start..search_end {
                if !self.has_part(pn) {
                    match self.hash_at(pn) {
                        Some(h) => {
                            requested_hashes.extend_from_slice(h);
                            self.outstanding_parts += 1;
                            i += 1;
                        }
                        None => {
                            hashmap_exhausted = RESOURCE_HASHMAP_IS_EXHAUSTED;
                        }
                    }
                }
                if i >= self.window.window || hashmap_exhausted == RESOURCE_HASHMAP_IS_EXHAUSTED {
                    break;
                }
            }
        }

        let mut request_data = Vec::new();
        request_data.push(hashmap_exhausted);
        if hashmap_exhausted == RESOURCE_HASHMAP_IS_EXHAUSTED {
            // Append last known map hash
            if self.hashmap_height > 0 {
                if let Some(last_hash) = self.hash_at(self.hashmap_height - 1) {
                    request_data.extend_from_slice(last_hash);
                } else {
                    request_data.extend_from_slice(&[0u8; RESOURCE_MAPHASH_LEN]);
                }
            } else {
                request_data.extend_from_slice(&[0u8; RESOURCE_MAPHASH_LEN]);
            }
            self.waiting_for_hmu = true;
        }
        if hashmap_exhausted == RESOURCE_HASHMAP_IS_EMPTY {
            self.waiting_for_hmu = true;
        }

        request_data.extend_from_slice(&self.resource_hash);
        request_data.extend_from_slice(&requested_hashes);

        self.last_activity = now;
        self.req_sent = now;
        self.req_sent_bytes = request_data.len();
        self.req_resp = None;

        vec![ResourceAction::SendRequest(request_data)]
    }

    /// Assemble received parts, decrypt, decompress, verify hash.
    pub fn assemble(
        &mut self,
        decrypt_fn: &PartsDecryptFn<'_>,
        compressor: &dyn Compressor,
    ) -> Vec<ResourceAction> {
        match self.prepare_data(decrypt_fn) {
            Ok(data) => self.finish_data(data.run(compressor)),
            Err(actions) => actions,
        }
    }

    /// Authenticate and decrypt the parts, then transfer owned plaintext to an assembly job.
    /// Keep this receiver alive until completion or cancellation. A pending attempt
    /// ignores duplicate parts and ordinary part-receive timeouts.
    pub fn prepare_assembly(
        &mut self,
        decrypt_fn: &PartsDecryptFn<'_>,
    ) -> Result<ResourceAssembly, Vec<ResourceAction>> {
        let data = self.prepare_data(decrypt_fn)?;
        let id = AssemblyId::new();
        self.assembly_id = Some(id.clone());
        Ok(ResourceAssembly { id, data })
    }

    pub fn assembly_id(&self) -> Option<&AssemblyId> {
        (self.status == ResourceStatus::Assembling)
            .then_some(self.assembly_id.as_ref())
            .flatten()
    }

    /// Publish a result only for the still-pending attempt that produced it.
    /// Results from another receiver or a cancelled attempt are discarded.
    pub fn complete_assembly(&mut self, result: AssemblyResult) -> Vec<ResourceAction> {
        if self.assembly_id() != Some(&result.id) {
            return Vec::new();
        }
        self.assembly_id = None;
        self.finish_data(result.result)
    }

    /// Fail a pending worker attempt without blaming the peer for a local failure.
    pub fn fail_assembly(&mut self, id: &AssemblyId) -> Vec<ResourceAction> {
        if self.assembly_id() != Some(id) {
            return Vec::new();
        }
        self.assembly_id = None;
        let mut actions = self.cancel();
        actions.push(ResourceAction::Failed(ResourceError::InvalidState));
        actions
    }

    fn finish_data(
        &mut self,
        result: Result<Vec<ResourceAction>, ResourceError>,
    ) -> Vec<ResourceAction> {
        match result {
            Ok(actions) => {
                self.status = ResourceStatus::Complete;
                actions
            }
            Err(error) => self.corrupt_actions(error),
        }
    }

    fn prepare_data(
        &mut self,
        decrypt_fn: &PartsDecryptFn<'_>,
    ) -> Result<AssemblyData, Vec<ResourceAction>> {
        if self.status >= ResourceStatus::Assembling || self.received_count != self.total_parts {
            return Err(vec![ResourceAction::Failed(ResourceError::InvalidState)]);
        }

        self.status = ResourceStatus::Assembling;

        // Part storage grows as parts arrive; a short vector means a part is missing.
        if self.parts.len() != self.total_parts {
            self.status = ResourceStatus::Failed;
            return Err(vec![ResourceAction::Failed(ResourceError::InvalidState)]);
        }

        // Every part must be held; size from the parts actually held, not the
        // advertised transfer size.
        let mut stream_len = 0usize;
        for part in &self.parts {
            match part {
                Some(data) => match stream_len.checked_add(data.len()) {
                    Some(len) => stream_len = len,
                    None => {
                        self.status = ResourceStatus::Failed;
                        return Err(vec![ResourceAction::Failed(ResourceError::TooLarge)]);
                    }
                },
                None => {
                    self.status = ResourceStatus::Failed;
                    return Err(vec![ResourceAction::Failed(ResourceError::InvalidState)]);
                }
            }
        }
        // Assembly is terminal for part reception. The parts are released once
        // authentication has produced the plaintext, including on failure.
        let parts = core::mem::take(&mut self.parts);
        self.hashmap = Vec::new();

        // The plaintext starts with the random prefix, which is dropped here.
        let plaintext = if self.flags.encrypted {
            // Each part is authenticated and decrypted in turn, without
            // joining the ciphertext first.
            let chunks: Vec<&[u8]> = parts.iter().flatten().map(Vec::as_slice).collect();
            let decrypted = decrypt_fn(&chunks, RESOURCE_RANDOM_HASH_SIZE);
            drop(chunks);
            drop(parts);
            match decrypted {
                Ok(d) => d,
                Err(_) => {
                    self.status = ResourceStatus::Failed;
                    return Err(vec![ResourceAction::Failed(
                        ResourceError::DecryptionFailed,
                    )]);
                }
            }
        } else {
            let Some(len) = stream_len.checked_sub(RESOURCE_RANDOM_HASH_SIZE) else {
                return Err(self.corrupt_actions(ResourceError::InvalidPart));
            };
            let mut plaintext = Vec::with_capacity(len);
            let mut skip = RESOURCE_RANDOM_HASH_SIZE;
            for data in parts.iter().flatten() {
                let from = skip.min(data.len());
                plaintext.extend_from_slice(&data[from..]);
                skip -= from;
            }
            plaintext
        };

        let (Ok(resource_hash), Ok(random_hash)) = (
            self.resource_hash.as_slice().try_into(),
            self.random_hash.as_slice().try_into(),
        ) else {
            return Err(self.corrupt_actions(ResourceError::InvalidAdvertisement));
        };
        Ok(AssemblyData {
            plaintext,
            resource_hash,
            random_hash,
            compressed: self.flags.compressed,
            metadata: self.has_metadata && self.segment_index == 1,
            app_flag: self.flags.app_flag,
            limit: self.max_decompressed_size,
        })
    }

    /// Handle cancel from sender (RESOURCE_ICL).
    pub fn handle_cancel(&mut self) -> Vec<ResourceAction> {
        if self.status < ResourceStatus::Complete {
            self.status = ResourceStatus::Failed;
            return vec![ResourceAction::Failed(ResourceError::Rejected)];
        }
        vec![]
    }

    /// Periodic tick. Checks for timeouts.
    pub fn tick(
        &mut self,
        now: f64,
        decrypt_fn: &PartsDecryptFn<'_>,
        compressor: &dyn Compressor,
    ) -> Vec<ResourceAction> {
        if self.status >= ResourceStatus::Assembling {
            return vec![];
        }

        if self.status == ResourceStatus::Transferring {
            // Check if all parts received — trigger assembly
            if self.received_count == self.total_parts {
                return self.assemble(decrypt_fn, compressor);
            }

            // Compute timeout
            let eifr = self.compute_eifr();
            let retries_used = self.max_retries - self.retries_left;
            let extra_wait = retries_used as f64 * RESOURCE_PER_RETRY_DELAY;
            let expected_hmu_wait =
                if eifr > 0.0 && (self.waiting_for_hmu || self.outstanding_parts == 0) {
                    (self.sdu as f64 * 8.0 * RESOURCE_HMU_WAIT_FACTOR) / eifr
                } else {
                    0.0
                };
            let expected_tof = if self.outstanding_parts > 0 && eifr > 0.0 {
                (self.outstanding_parts as f64 * self.sdu as f64 * 8.0) / eifr
            } else if eifr > 0.0 {
                (3.0 * self.sdu as f64) / eifr
            } else {
                10.0 // fallback
            };

            let sleep_time = self.last_activity
                + self.part_timeout_factor * expected_tof
                + expected_hmu_wait
                + RESOURCE_RETRY_GRACE_TIME
                + extra_wait;

            if now > sleep_time {
                if self.retries_left > 0 {
                    // Timeout — shrink window, retry
                    self.window.on_timeout();
                    self.retries_left -= 1;
                    self.waiting_for_hmu = false;
                    return self.request_next(now);
                } else {
                    self.status = ResourceStatus::Failed;
                    return vec![ResourceAction::Failed(ResourceError::MaxRetriesExceeded)];
                }
            }
        }

        vec![]
    }

    /// Compute EIFR (expected inflight rate) and update self.eifr.
    fn compute_eifr(&mut self) -> f64 {
        let eifr = if self.req_data_rtt_rate > 0.0 {
            self.req_data_rtt_rate * 8.0
        } else if let Some(prev) = self.previous_eifr {
            prev
        } else {
            // Fallback: use link_rtt as establishment cost estimate
            let rtt = self.rtt.unwrap_or(self.link_rtt);
            if rtt > 0.0 {
                (self.sdu as f64 * 8.0) / rtt
            } else {
                10000.0
            }
        };
        self.eifr = Some(eifr);
        eifr
    }

    /// Get current progress as (received, total).
    pub fn progress(&self) -> (usize, usize) {
        (self.received_count, self.total_parts)
    }

    /// Get window and EIFR for passing to next transfer.
    pub fn get_transfer_state(&self) -> (usize, Option<f64>) {
        (self.window.window, self.eifr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::types::{Compressor, DecompressError, NoopCompressor};
    use crate::resource::advertisement::ResourceAdvertisement;
    use crate::resource::sender::ResourceSender;

    fn identity_encrypt(data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    fn identity_decrypt(parts: &[&[u8]], skip: usize) -> Result<Vec<u8>, ()> {
        let joined = parts.concat();
        joined.get(skip..).map(<[u8]>::to_vec).ok_or(())
    }

    struct ExpandingCompressor;

    impl Compressor for ExpandingCompressor {
        fn compress(&self, data: &[u8]) -> Option<Vec<u8>> {
            Some(data[..data.len() / 2].to_vec())
        }

        fn decompress(&self, data: &[u8]) -> Option<Vec<u8>> {
            self.decompress_bounded(data, usize::MAX).ok()
        }

        fn decompress_bounded(
            &self,
            data: &[u8],
            max_output_size: usize,
        ) -> Result<Vec<u8>, DecompressError> {
            let mut out = data.to_vec();
            out.extend_from_slice(data);
            if out.len() > max_output_size {
                return Err(DecompressError::TooLarge);
            }
            Ok(out)
        }
    }

    fn base_timeout(receiver: &ResourceReceiver, eifr: f64) -> f64 {
        let expected_tof = if receiver.outstanding_parts > 0 {
            (receiver.outstanding_parts as f64 * receiver.sdu as f64 * 8.0) / eifr
        } else {
            (3.0 * receiver.sdu as f64) / eifr
        };

        receiver.last_activity
            + receiver.part_timeout_factor * expected_tof
            + RESOURCE_RETRY_GRACE_TIME
    }

    fn hmu_timeout(receiver: &ResourceReceiver, eifr: f64) -> f64 {
        let expected_hmu_wait = (receiver.sdu as f64 * 8.0 * RESOURCE_HMU_WAIT_FACTOR) / eifr;
        base_timeout(receiver, eifr) + expected_hmu_wait
    }

    fn make_sender_receiver() -> (ResourceSender, ResourceReceiver) {
        let mut rng = rns_crypto::FixedRng::new(&[0x42; 64]);
        let data = b"Hello, Resource Transfer!";

        let sender = ResourceSender::new(
            data,
            None,
            RESOURCE_SDU,
            &identity_encrypt,
            &NoopCompressor,
            &mut rng,
            1000.0,
            false,
            false,
            None,
            1,
            1,
            None,
            0.5,
            6.0,
        )
        .unwrap();

        let adv_data = sender.get_advertisement(0);
        let receiver =
            ResourceReceiver::from_advertisement(&adv_data, RESOURCE_SDU, 0.5, 1000.0, None, None)
                .unwrap();

        (sender, receiver)
    }

    fn ready_receiver() -> ResourceReceiver {
        let (mut sender, mut receiver) = make_sender_receiver();
        for action in receiver.accept(1001.0) {
            if let ResourceAction::SendRequest(request) = action {
                for action in sender.handle_request(&request, 1002.0) {
                    if let ResourceAction::SendPart(part) = action {
                        receiver.receive_part(&part, 1003.0);
                    }
                }
            }
        }
        assert_eq!(receiver.received_count, receiver.total_parts);
        receiver
    }

    #[test]
    fn assembly_handoff_matches_synchronous_actions_and_releases_parts() {
        let mut receiver = ready_receiver();
        let job = receiver.prepare_assembly(&identity_decrypt).unwrap();
        assert!(receiver.parts.is_empty() && receiver.hashmap.is_empty());
        receiver.waiting_for_hmu = true;
        assert!(receiver
            .handle_hashmap_update(&receiver.resource_hash.clone(), 1004.0)
            .is_empty());
        assert!(receiver.accept(1004.0).is_empty());
        assert!(receiver.request_next(1004.0).is_empty());
        assert_eq!(receiver.assembly_id(), Some(job.id()));
        assert!(receiver.receive_part(b"duplicate", 1004.0).is_empty());
        assert!(receiver
            .tick(
                100000.0,
                &|_, _| panic!("pending assembly decrypted again"),
                &NoopCompressor
            )
            .is_empty());
        assert!(receiver.prepare_assembly(&identity_decrypt).is_err());
        let actions = receiver.complete_assembly(job.run(&NoopCompressor));
        let expected = ready_receiver().assemble(&identity_decrypt, &NoopCompressor);
        assert_eq!(format!("{actions:?}"), format!("{expected:?}"));
        assert_eq!(receiver.status, ResourceStatus::Complete);
        assert!(receiver.assembly_id().is_none());
    }

    #[test]
    fn assembly_result_requires_original_live_attempt_even_for_same_hash() {
        let mut first = ready_receiver();
        let mut second = ready_receiver();
        assert_eq!(first.resource_hash, second.resource_hash);
        let first_job = first.prepare_assembly(&identity_decrypt).unwrap();
        let second_job = second.prepare_assembly(&identity_decrypt).unwrap();
        assert_ne!(first_job.id(), second_job.id());
        assert!(first
            .complete_assembly(second_job.run(&NoopCompressor))
            .is_empty());
        first.cancel();
        assert!(first
            .complete_assembly(first_job.run(&NoopCompressor))
            .is_empty());
        assert_eq!(first.status, ResourceStatus::Failed);
    }

    #[test]
    fn assembly_local_failure_and_authentication_failure_cannot_publish_success() {
        let mut receiver = ready_receiver();
        assert!(receiver.prepare_assembly(&|_, _| Err(())).is_err());
        assert!(receiver.assembly_id().is_none());
        assert!(receiver.parts.is_empty() && receiver.hashmap.is_empty());
        assert!(receiver
            .prepare_assembly(&|_, _| panic!("failed assembly retried"))
            .is_err());
        let mut receiver = ready_receiver();
        let job = receiver.prepare_assembly(&identity_decrypt).unwrap();
        let actions = receiver.fail_assembly(job.id());
        assert!(matches!(
            actions.as_slice(),
            [
                ResourceAction::SendCancelReceiver(_),
                ResourceAction::Failed(ResourceError::InvalidState)
            ]
        ));
        assert!(receiver.fail_assembly(job.id()).is_empty());
        assert!(receiver
            .complete_assembly(job.run(&NoopCompressor))
            .is_empty());
    }

    #[test]
    fn test_assembly_joins_actual_parts_independent_of_advertised_size() {
        let (mut sender, mut receiver) = make_sender_receiver();
        let mut stream = Vec::new();
        for action in receiver.accept(1001.0) {
            if let ResourceAction::SendRequest(request) = action {
                for response in sender.handle_request(&request, 1002.0) {
                    if let ResourceAction::SendPart(part) = response {
                        stream.extend_from_slice(&part);
                    }
                }
            }
        }
        // Exercise uneven parts and a misleading size without allocating from it.
        receiver.parts = stream.chunks(7).map(|part| Some(part.to_vec())).collect();
        receiver.total_parts = receiver.parts.len();
        receiver.received_count = receiver.total_parts;
        receiver.transfer_size = u64::MAX;
        let actions = receiver.assemble(
            &|parts, skip| {
                // The parts reach decryption as held, without being joined.
                assert_eq!(parts.len(), stream.len().div_ceil(7));
                assert!(parts.iter().all(|part| part.len() <= 7));
                assert_eq!(parts.concat(), stream);
                identity_decrypt(parts, skip)
            },
            &NoopCompressor,
        );
        assert!(actions.iter().any(|action| matches!(action,
            ResourceAction::DataReceived { data, .. } if data == b"Hello, Resource Transfer!")));
        assert_eq!(receiver.status, ResourceStatus::Complete);
    }

    #[test]
    fn test_assembly_rejects_missing_part_before_decryption() {
        let (_, mut receiver) = make_sender_receiver();
        receiver.received_count = receiver.total_parts;
        let actions = receiver.assemble(
            &|_, _| panic!("missing part reached decryption"),
            &NoopCompressor,
        );
        assert!(matches!(
            actions.as_slice(),
            [ResourceAction::Failed(ResourceError::InvalidState)]
        ));
        assert_eq!(receiver.status, ResourceStatus::Failed);
    }

    #[test]
    fn test_from_advertisement() {
        let (sender, receiver) = make_sender_receiver();
        assert_eq!(receiver.total_parts, sender.total_parts());
        assert_eq!(receiver.transfer_size, sender.transfer_size as u64);
        assert_eq!(receiver.resource_hash, sender.resource_hash.to_vec());
        assert!(!receiver.advertisement_packet.is_empty());
        assert_eq!(
            receiver.max_decompressed_size,
            RESOURCE_AUTO_COMPRESS_MAX_SIZE
        );
    }

    #[test]
    fn test_from_advertisement_rejects_huge_part_count() {
        let adv = ResourceAdvertisement {
            transfer_size: 1024,
            data_size: 1024,
            num_parts: u64::MAX,
            resource_hash: vec![0x11; 32],
            random_hash: vec![0x22; RESOURCE_RANDOM_HASH_SIZE],
            original_hash: vec![0x33; 32],
            hashmap: vec![0x44; RESOURCE_MAPHASH_LEN],
            flags: AdvFlags {
                encrypted: false,
                compressed: false,
                split: false,
                is_request: false,
                is_response: false,
                has_metadata: false,
                app_flag: false,
            },
            segment_index: 1,
            total_segments: 1,
            request_id: None,
        };

        let err = match ResourceReceiver::from_advertisement(
            &adv.pack(0),
            RESOURCE_SDU,
            0.5,
            1000.0,
            None,
            None,
        ) {
            Ok(_) => panic!("huge advertisement should be rejected"),
            Err(err) => err,
        };

        assert_eq!(err, ResourceError::PartCountMismatch);
    }

    fn sized_advertisement(transfer_size: u64, num_parts: u64) -> ResourceAdvertisement {
        ResourceAdvertisement {
            transfer_size,
            data_size: transfer_size,
            num_parts,
            resource_hash: vec![0x11; 32],
            random_hash: vec![0x22; RESOURCE_RANDOM_HASH_SIZE],
            original_hash: vec![0x33; 32],
            hashmap: vec![0x44; RESOURCE_MAPHASH_LEN * num_parts.min(512) as usize],
            flags: AdvFlags {
                encrypted: true,
                compressed: false,
                split: false,
                is_request: false,
                is_response: false,
                has_metadata: false,
                app_flag: false,
            },
            segment_index: 1,
            total_segments: 1,
            request_id: None,
        }
    }

    fn receive_advertisement(
        adv: &ResourceAdvertisement,
        sdu: usize,
    ) -> Result<ResourceReceiver, ResourceError> {
        ResourceReceiver::from_advertisement(&adv.pack(0), sdu, 0.5, 1000.0, None, None)
    }

    #[test]
    fn part_count_above_transfer_size_is_refused() {
        let adv = sized_advertisement(1, 140_000);
        assert_eq!(
            receive_advertisement(&adv, RESOURCE_SDU).err(),
            Some(ResourceError::PartCountMismatch)
        );
        assert_eq!(
            receive_advertisement(&adv, 1).err(),
            Some(ResourceError::PartCountMismatch)
        );
    }

    #[test]
    fn part_count_below_transfer_size_is_refused() {
        let sdu = RESOURCE_SDU;
        let adv = sized_advertisement(10 * sdu as u64 + 1, 10);
        assert_eq!(
            receive_advertisement(&adv, sdu).err(),
            Some(ResourceError::PartCountMismatch)
        );
    }

    #[test]
    fn part_count_matching_transfer_size_is_accepted() {
        let sdu = RESOURCE_SDU;
        let receiver = receive_advertisement(&sized_advertisement(1, 1), sdu).unwrap();
        assert_eq!(receiver.total_parts, 1);

        let receiver = receive_advertisement(&sized_advertisement(sdu as u64 + 1, 2), sdu).unwrap();
        assert_eq!(receiver.total_parts, 2);
    }

    #[test]
    fn transfer_size_on_sdu_boundary_needs_no_extra_part() {
        let sdu = RESOURCE_SDU;
        let exact = 3 * sdu as u64;
        let receiver = receive_advertisement(&sized_advertisement(exact, 3), sdu).unwrap();
        assert_eq!(receiver.total_parts, 3);
        assert_eq!(
            receive_advertisement(&sized_advertisement(exact, 4), sdu).err(),
            Some(ResourceError::PartCountMismatch)
        );
        assert_eq!(
            receive_advertisement(&sized_advertisement(exact, 2), sdu).err(),
            Some(ResourceError::PartCountMismatch)
        );
    }

    #[test]
    fn split_segment_part_count_follows_segment_transfer_size() {
        let sdu = RESOURCE_SDU;
        let segment_size = RESOURCE_MAX_EFFICIENT_SIZE as u64 + 61;
        let segment_parts = segment_size.div_ceil(sdu as u64);
        let mut adv = sized_advertisement(segment_size, segment_parts);
        adv.data_size = 3 * RESOURCE_MAX_EFFICIENT_SIZE as u64;
        adv.flags.split = true;
        adv.segment_index = 2;
        adv.total_segments = 3;

        let receiver = receive_advertisement(&adv, sdu).unwrap();
        assert_eq!(receiver.total_parts as u64, segment_parts);
        assert_eq!(receiver.segment_index, 2);

        // The logical size of the whole split resource does not set the count.
        adv.num_parts = adv.data_size.div_ceil(sdu as u64);
        assert_eq!(
            receive_advertisement(&adv, sdu).err(),
            Some(ResourceError::PartCountMismatch)
        );
    }

    #[test]
    fn transfer_size_above_segment_limit_is_refused_up_front() {
        let limit = 3 * RESOURCE_MAX_EFFICIENT_SIZE as u64;
        let adv = sized_advertisement(limit + 1, (limit + 1).div_ceil(RESOURCE_SDU as u64));
        assert_eq!(
            receive_advertisement(&adv, RESOURCE_SDU).err(),
            Some(ResourceError::InvalidAdvertisement)
        );
    }

    #[test]
    fn idle_accepted_advertisement_holds_no_part_storage() {
        let sdu = 48;
        let limit = 3 * RESOURCE_MAX_EFFICIENT_SIZE as u64;
        let parts = limit.div_ceil(sdu as u64);
        let mut receiver = receive_advertisement(&sized_advertisement(limit, parts), sdu).unwrap();
        assert_eq!(receiver.total_parts as u64, parts);

        let actions = receiver.accept(1000.0);
        assert!(actions
            .iter()
            .any(|action| matches!(action, ResourceAction::SendRequest(_))));
        assert_eq!(receiver.parts.capacity(), 0);
        assert!(receiver.hashmap.capacity() <= RESOURCE_HASHMAP_MAX_LEN);
        assert_eq!(receiver.hashmap.len(), receiver.hashmap_height);
    }

    #[test]
    fn part_storage_grows_with_received_parts() {
        let mut rng = rns_crypto::FixedRng::new(&[0x42; 64]);
        let sdu = 8;
        let data: Vec<u8> = (0..100u8).collect();
        let mut sender = ResourceSender::new(
            &data,
            None,
            sdu,
            &identity_encrypt,
            &NoopCompressor,
            &mut rng,
            1000.0,
            false,
            false,
            None,
            1,
            1,
            None,
            0.5,
            6.0,
        )
        .unwrap();
        let mut receiver = ResourceReceiver::from_advertisement(
            &sender.get_advertisement(0),
            sdu,
            0.5,
            1000.0,
            None,
            None,
        )
        .unwrap();
        assert!(receiver.total_parts > 1);
        assert!(receiver.parts.is_empty());

        let request = receiver
            .accept(1000.0)
            .into_iter()
            .find_map(|action| match action {
                ResourceAction::SendRequest(request) => Some(request),
                _ => None,
            })
            .unwrap();
        let first_part = sender
            .handle_request(&request, 1001.0)
            .into_iter()
            .find_map(|action| match action {
                ResourceAction::SendPart(part) => Some(part),
                _ => None,
            })
            .unwrap();
        receiver.receive_part(&first_part, 1002.0);
        assert_eq!(receiver.received_count, 1);
        assert_eq!(receiver.parts.len(), 1);
    }

    #[test]
    fn test_from_advertisement_rejects_oversized_transfer() {
        let adv = ResourceAdvertisement {
            transfer_size: RESOURCE_AUTO_COMPRESS_MAX_SIZE as u64 + 1,
            data_size: 1024,
            num_parts: 1,
            resource_hash: vec![0x11; 32],
            random_hash: vec![0x22; RESOURCE_RANDOM_HASH_SIZE],
            original_hash: vec![0x33; 32],
            hashmap: vec![0x44; RESOURCE_MAPHASH_LEN],
            flags: AdvFlags {
                encrypted: false,
                compressed: false,
                split: false,
                is_request: false,
                is_response: false,
                has_metadata: false,
                app_flag: false,
            },
            segment_index: 1,
            total_segments: 1,
            request_id: None,
        };

        let err = match ResourceReceiver::from_advertisement(
            &adv.pack(0),
            RESOURCE_SDU,
            0.5,
            1000.0,
            None,
            None,
        ) {
            Ok(_) => panic!("oversized advertisement should be rejected"),
            Err(err) => err,
        };

        assert_eq!(err, ResourceError::InvalidAdvertisement);
    }

    #[test]
    fn test_accept() {
        let (_, mut receiver) = make_sender_receiver();
        let actions = receiver.accept(1000.0);
        assert_eq!(receiver.status, ResourceStatus::Transferring);
        assert!(!actions.is_empty());
        assert!(actions
            .iter()
            .any(|a| matches!(a, ResourceAction::SendRequest(_))));
    }

    #[test]
    fn test_reject() {
        let (_, mut receiver) = make_sender_receiver();
        let actions = receiver.reject();
        assert_eq!(receiver.status, ResourceStatus::Rejected);
        assert!(actions
            .iter()
            .any(|a| matches!(a, ResourceAction::SendCancelReceiver(_))));
    }

    #[test]
    fn test_cancel_is_distinct_from_advertisement_rejection() {
        let (_, mut receiver) = make_sender_receiver();
        receiver.accept(1000.0);
        let actions = receiver.cancel();
        assert_eq!(receiver.status, ResourceStatus::Failed);
        assert!(actions
            .iter()
            .any(|a| matches!(a, ResourceAction::SendCancelReceiver(_))));
        assert!(receiver.cancel().is_empty());
    }

    fn hmu(resource_hash: &[u8], segment: u64, hashmap: Vec<u8>) -> Vec<u8> {
        let payload = crate::msgpack::pack(&crate::msgpack::Value::Array(vec![
            crate::msgpack::Value::UInt(segment),
            crate::msgpack::Value::Bin(hashmap),
        ]));
        let mut data = resource_hash.to_vec();
        data.extend_from_slice(&payload);
        data
    }

    #[test]
    fn test_unsolicited_hmu_is_ignored_without_refreshing_timeout_state() {
        let (_, mut receiver) = make_sender_receiver();
        receiver.status = ResourceStatus::Transferring;
        receiver.waiting_for_hmu = false;
        receiver.last_activity = 1000.0;
        receiver.retries_left = 1;
        let update = hmu(&receiver.resource_hash, 0, vec![0x99; RESOURCE_MAPHASH_LEN]);

        let actions = receiver.handle_hashmap_update(&update, 2000.0);

        assert!(actions.is_empty());
        assert_eq!(receiver.status, ResourceStatus::Transferring);
        assert!(!receiver.waiting_for_hmu);
        assert_eq!(receiver.last_activity, 1000.0);
        assert_eq!(receiver.retries_left, 1);
    }

    #[test]
    fn test_empty_hmu_cancels_waiting_receiver() {
        let (_, mut receiver) = make_sender_receiver();
        receiver.status = ResourceStatus::Transferring;
        receiver.waiting_for_hmu = true;
        let update = hmu(&receiver.resource_hash, 1, Vec::new());

        let actions = receiver.handle_hashmap_update(&update, 1001.0);

        assert_eq!(receiver.status, ResourceStatus::Failed);
        assert!(actions
            .iter()
            .any(|action| matches!(action, ResourceAction::SendCancelReceiver(_))));
        assert!(!actions
            .iter()
            .any(|action| matches!(action, ResourceAction::SendRequest(_))));
    }

    #[test]
    fn test_malformed_hmu_cancels_waiting_receiver() {
        let (_, mut receiver) = make_sender_receiver();
        receiver.status = ResourceStatus::Transferring;
        receiver.waiting_for_hmu = true;
        let mut malformed = receiver.resource_hash.clone();
        malformed.extend_from_slice(&[0xc1]);

        let actions = receiver.handle_hashmap_update(&malformed, 1001.0);

        assert_eq!(receiver.status, ResourceStatus::Failed);
        assert!(actions
            .iter()
            .any(|action| matches!(action, ResourceAction::SendCancelReceiver(_))));
    }

    #[test]
    fn test_hmu_without_payload_cancels_waiting_receiver() {
        let (_, mut receiver) = make_sender_receiver();
        receiver.status = ResourceStatus::Transferring;
        receiver.waiting_for_hmu = true;
        let update = receiver.resource_hash.clone();

        let actions = receiver.handle_hashmap_update(&update, 1001.0);

        assert_eq!(receiver.status, ResourceStatus::Failed);
        assert!(actions
            .iter()
            .any(|action| matches!(action, ResourceAction::SendCancelReceiver(_))));
    }

    #[test]
    fn test_hmu_for_another_resource_is_ignored() {
        let (_, mut receiver) = make_sender_receiver();
        receiver.status = ResourceStatus::Transferring;
        receiver.waiting_for_hmu = true;
        receiver.last_activity = 1000.0;
        let update = hmu(&[0xEE; 32], 0, vec![0x99; RESOURCE_MAPHASH_LEN]);

        let actions = receiver.handle_hashmap_update(&update, 2000.0);

        assert!(actions.is_empty());
        assert!(receiver.waiting_for_hmu);
        assert_eq!(receiver.last_activity, 1000.0);
    }

    #[test]
    fn test_misaligned_hmu_hashmap_cancels_waiting_receiver() {
        let (_, mut receiver) = make_sender_receiver();
        receiver.status = ResourceStatus::Transferring;
        receiver.waiting_for_hmu = true;
        let update = hmu(
            &receiver.resource_hash,
            0,
            vec![0x99; RESOURCE_MAPHASH_LEN + 1],
        );

        let actions = receiver.handle_hashmap_update(&update, 1001.0);

        assert_eq!(receiver.status, ResourceStatus::Failed);
        assert!(actions
            .iter()
            .any(|action| matches!(action, ResourceAction::SendCancelReceiver(_))));
    }

    #[test]
    fn test_out_of_range_hmu_segment_cancels_waiting_receiver() {
        let (_, mut receiver) = make_sender_receiver();
        receiver.status = ResourceStatus::Transferring;
        receiver.waiting_for_hmu = true;
        let update = hmu(
            &receiver.resource_hash,
            u64::MAX,
            vec![0x99; RESOURCE_MAPHASH_LEN],
        );

        let actions = receiver.handle_hashmap_update(&update, 1001.0);

        assert_eq!(receiver.status, ResourceStatus::Failed);
        assert!(actions
            .iter()
            .any(|action| matches!(action, ResourceAction::SendCancelReceiver(_))));
    }

    #[test]
    fn test_tick_is_inert_once_receiver_starts_assembling() {
        for status in [
            ResourceStatus::Assembling,
            ResourceStatus::Complete,
            ResourceStatus::Failed,
            ResourceStatus::Corrupt,
            ResourceStatus::Rejected,
        ] {
            let (_, mut receiver) = make_sender_receiver();
            receiver.status = status;
            receiver.last_activity = 1.0;
            receiver.retries_left = 0;

            let actions = receiver.tick(10_000.0, &identity_decrypt, &NoopCompressor);

            assert!(actions.is_empty(), "tick emitted an action for {status:?}");
            assert_eq!(receiver.status, status);
            assert_eq!(receiver.last_activity, 1.0);
        }
    }

    #[test]
    fn test_receive_part_stores() {
        let (mut sender, mut receiver) = make_sender_receiver();
        receiver.accept(1000.0);

        // Get part data from sender (we use identity encryption so parts ARE the raw data)
        // Request first part
        let mut request = Vec::new();
        request.push(RESOURCE_HASHMAP_IS_NOT_EXHAUSTED);
        request.extend_from_slice(&sender.resource_hash);
        request.extend_from_slice(&sender.part_hashes[0]);

        let send_actions = sender.handle_request(&request, 1001.0);
        let part_data = send_actions
            .iter()
            .find_map(|a| match a {
                ResourceAction::SendPart(d) => Some(d.clone()),
                _ => None,
            })
            .unwrap();

        // Give it to receiver
        receiver.req_sent = 1000.5;
        let _actions = receiver.receive_part(&part_data, 1001.0);
        assert_eq!(receiver.received_count, 1);
    }

    #[test]
    fn test_consecutive_completed_height() {
        let (sender, mut receiver) = make_sender_receiver();
        receiver.accept(1000.0);

        // Simulate receiving parts in order for a multi-part resource
        if sender.total_parts() > 1 {
            // This only applies to multi-part transfers
            assert_eq!(receiver.consecutive_completed_height, -1);
        }
    }

    #[test]
    fn receive_part_search_window_matches_request_after_completed_height() {
        let mut rng = rns_crypto::FixedRng::new(&[0x5a; 64]);
        let data: Vec<u8> = (0..48).collect();
        let mut sender = ResourceSender::new(
            &data,
            None,
            8,
            &identity_encrypt,
            &NoopCompressor,
            &mut rng,
            1000.0,
            false,
            false,
            None,
            1,
            1,
            None,
            0.5,
            6.0,
        )
        .unwrap();
        assert!(sender.total_parts() > 5);

        let advertisement = sender.get_advertisement(0);
        let mut receiver =
            ResourceReceiver::from_advertisement(&advertisement, 8, 0.5, 1000.0, None, None)
                .unwrap();
        let first_request = receiver
            .accept(1000.0)
            .into_iter()
            .find_map(|action| match action {
                ResourceAction::SendRequest(data) => Some(data),
                _ => None,
            })
            .unwrap();
        let first_parts = sender.handle_request(&first_request, 1001.0);
        let first_part = first_parts
            .iter()
            .find_map(|action| match action {
                ResourceAction::SendPart(data)
                    if map_hash(data, &receiver.random_hash) == sender.part_hashes[0] =>
                {
                    Some(data.clone())
                }
                _ => None,
            })
            .unwrap();
        receiver.receive_part(&first_part, 1002.0);
        assert_eq!(receiver.consecutive_completed_height, 0);

        let next_request = receiver
            .request_next(1003.0)
            .into_iter()
            .find_map(|action| match action {
                ResourceAction::SendRequest(data) => Some(data),
                _ => None,
            })
            .unwrap();
        let next_parts = sender.handle_request(&next_request, 1004.0);
        let window_tail_index = receiver.window.window;
        let window_tail = next_parts
            .iter()
            .find_map(|action| match action {
                ResourceAction::SendPart(data)
                    if map_hash(data, &receiver.random_hash)
                        == sender.part_hashes[window_tail_index] =>
                {
                    Some(data.clone())
                }
                _ => None,
            })
            .expect("request must include the inclusive tail of the next window");

        let actions = receiver.receive_part(&window_tail, 1005.0);
        assert!(receiver.parts[window_tail_index].is_some());
        assert_eq!(receiver.received_count, 2);
        assert_eq!(receiver.consecutive_completed_height, 0);
        assert!(actions.iter().any(|action| matches!(
            action,
            ResourceAction::ProgressUpdate {
                received: 2,
                total,
            } if *total == receiver.total_parts
        )));
    }

    #[test]
    fn test_handle_cancel() {
        let (_, mut receiver) = make_sender_receiver();
        receiver.accept(1000.0);
        let _actions = receiver.handle_cancel();
        assert_eq!(receiver.status, ResourceStatus::Failed);
    }

    #[test]
    fn test_assemble_compressed_resource_rejects_oversized_decompression() {
        let data = b"oversized!";
        let mut rng = rns_crypto::FixedRng::new(&[0x93; 64]);

        let mut sender = ResourceSender::new(
            data,
            None,
            RESOURCE_SDU,
            &identity_encrypt,
            &ExpandingCompressor,
            &mut rng,
            1000.0,
            true,
            false,
            None,
            1,
            1,
            None,
            0.5,
            6.0,
        )
        .unwrap();

        let adv = sender.get_advertisement(0);
        let mut receiver =
            ResourceReceiver::from_advertisement(&adv, RESOURCE_SDU, 0.5, 1000.0, None, None)
                .unwrap();
        receiver.max_decompressed_size = data.len() - 1;

        let request_data = receiver
            .accept(1001.0)
            .into_iter()
            .find_map(|a| match a {
                ResourceAction::SendRequest(d) => Some(d),
                _ => None,
            })
            .unwrap();

        let send_actions = sender.handle_request(&request_data, 1002.0);
        receiver.req_sent = 1001.0;
        for action in &send_actions {
            if let ResourceAction::SendPart(part_data) = action {
                receiver.receive_part(part_data, 1003.0);
            }
        }

        let assemble_actions = receiver.assemble(&identity_decrypt, &ExpandingCompressor);
        assert_eq!(receiver.status, ResourceStatus::Corrupt);
        assert!(assemble_actions
            .iter()
            .any(|a| matches!(a, ResourceAction::SendCancelReceiver(_))));
        assert!(assemble_actions
            .iter()
            .any(|a| matches!(a, ResourceAction::Failed(ResourceError::TooLarge))));
        assert!(assemble_actions
            .iter()
            .any(|a| matches!(a, ResourceAction::TeardownLink)));
    }

    #[test]
    fn test_full_transfer_small_data() {
        // End-to-end: sender creates, receiver accepts, parts flow, assembly completes
        let data = b"small data";
        let mut rng = rns_crypto::FixedRng::new(&[0x77; 64]);

        let mut sender = ResourceSender::new(
            data,
            None,
            RESOURCE_SDU,
            &identity_encrypt,
            &NoopCompressor,
            &mut rng,
            1000.0,
            false,
            false,
            None,
            1,
            1,
            None,
            0.5,
            6.0,
        )
        .unwrap();

        let adv = sender.get_advertisement(0);
        let mut receiver =
            ResourceReceiver::from_advertisement(&adv, RESOURCE_SDU, 0.5, 1000.0, None, None)
                .unwrap();

        // Accept
        let req_actions = receiver.accept(1001.0);
        assert_eq!(receiver.status, ResourceStatus::Transferring);

        // Get request data
        let request_data = req_actions
            .iter()
            .find_map(|a| match a {
                ResourceAction::SendRequest(d) => Some(d.clone()),
                _ => None,
            })
            .unwrap();

        // Sender handles request
        let send_actions = sender.handle_request(&request_data, 1002.0);

        // Feed all parts to receiver
        receiver.req_sent = 1001.0;
        for action in &send_actions {
            if let ResourceAction::SendPart(part_data) = action {
                receiver.receive_part(part_data, 1003.0);
            }
        }

        assert_eq!(receiver.received_count, receiver.total_parts);

        // Assemble
        let assemble_actions = receiver.assemble(&identity_decrypt, &NoopCompressor);

        // Check for proof and data
        let has_proof = assemble_actions
            .iter()
            .any(|a| matches!(a, ResourceAction::SendProof(_)));
        let has_data = assemble_actions
            .iter()
            .any(|a| matches!(a, ResourceAction::DataReceived { .. }));
        let has_complete = assemble_actions
            .iter()
            .any(|a| matches!(a, ResourceAction::Completed));

        assert!(has_proof, "Should send proof");
        assert!(has_data, "Should return data");
        assert!(has_complete, "Should be completed");

        // Verify data matches
        let received_data = assemble_actions
            .iter()
            .find_map(|a| match a {
                ResourceAction::DataReceived { data, .. } => Some(data.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(received_data, data);

        // Verify proof validates on sender side
        let proof_data = assemble_actions
            .iter()
            .find_map(|a| match a {
                ResourceAction::SendProof(d) => Some(d.clone()),
                _ => None,
            })
            .unwrap();

        let _proof_actions = sender.handle_proof(&proof_data, 1004.0);
        assert_eq!(sender.status, ResourceStatus::Complete);
    }

    /// Drive an accepted transfer to completion from the receiver's first
    /// actions, returning the request flags it sent and the assembly actions.
    fn run_transfer(
        sender: &mut ResourceSender,
        receiver: &mut ResourceReceiver,
        mut pending: Vec<ResourceAction>,
    ) -> (Vec<u8>, Vec<ResourceAction>) {
        let mut now = 1001.0;
        let mut request_flags = Vec::new();
        for _ in 0..1000 {
            if receiver.received_count == receiver.total_parts {
                break;
            }
            now += 0.01;
            let mut next = Vec::new();
            for action in pending.drain(..) {
                if let ResourceAction::SendRequest(request) = action {
                    request_flags.push(request[0]);
                    for reply in sender.handle_request(&request, now) {
                        match reply {
                            ResourceAction::SendPart(part) => {
                                next.extend(receiver.receive_part(&part, now))
                            }
                            ResourceAction::SendHmu(hmu) => {
                                next.extend(receiver.handle_hashmap_update(&hmu, now))
                            }
                            other => panic!("unexpected sender action {other:?}"),
                        }
                    }
                }
            }
            pending = next;
        }
        assert_eq!(receiver.received_count, receiver.total_parts);
        (
            request_flags,
            receiver.assemble(&identity_decrypt, &NoopCompressor),
        )
    }

    fn multi_hashmap_sender(advertisement_mdu: usize) -> (Vec<u8>, ResourceSender) {
        let mut rng = rns_crypto::FixedRng::new(&[0x5a; 64]);
        // More parts than one advertisement hashmap segment holds.
        let data: Vec<u8> = (0..(RESOURCE_HASHMAP_MAX_LEN + 26) * RESOURCE_SDU)
            .map(|i| (i * 7 + i / 251) as u8)
            .collect();
        let mut sender = ResourceSender::new(
            &data,
            None,
            RESOURCE_SDU,
            &identity_encrypt,
            &NoopCompressor,
            &mut rng,
            1000.0,
            false,
            false,
            None,
            1,
            1,
            None,
            0.5,
            6.0,
        )
        .unwrap();
        assert!(sender.total_parts() > RESOURCE_HASHMAP_MAX_LEN);
        sender.advertisement_mdu = advertisement_mdu;
        (data, sender)
    }

    #[test]
    fn advertisement_too_large_for_link_mdu_defers_the_initial_hashmap() {
        // Python packs an advertisement exceeding the link MDU with an empty
        // hashmap; the receiver asks for it with HASHMAP_IS_EMPTY and the
        // sender answers with segment 0 before any part is requested.
        let (data, mut sender) = multi_hashmap_sender(200);
        let adv = sender.advertise(1000.0);
        let ResourceAction::SendAdvertisement(adv_data) = &adv[0] else {
            panic!("expected an advertisement");
        };
        assert!(adv_data.len() <= 200);
        assert!(ResourceAdvertisement::unpack(adv_data)
            .unwrap()
            .hashmap
            .is_empty());

        let mut receiver =
            ResourceReceiver::from_advertisement(adv_data, RESOURCE_SDU, 0.5, 1000.0, None, None)
                .unwrap();
        let first = receiver.accept(1000.5);
        let [ResourceAction::SendRequest(request)] = first.as_slice() else {
            panic!("expected one request, got {first:?}");
        };
        // Flag, resource hash, no last map hash and no part hashes.
        assert_eq!(request[0], RESOURCE_HASHMAP_IS_EMPTY);
        assert_eq!(request.len(), 1 + 32);
        assert!(receiver.waiting_for_hmu);

        let (flags, actions) = run_transfer(&mut sender, &mut receiver, first);
        assert_eq!(flags[0], RESOURCE_HASHMAP_IS_EMPTY);
        assert!(
            flags.contains(&RESOURCE_HASHMAP_IS_EXHAUSTED),
            "the second hashmap segment still uses the exhausted path: {flags:?}"
        );
        let received = actions.iter().find_map(|a| match a {
            ResourceAction::DataReceived { data, .. } => Some(data.clone()),
            _ => None,
        });
        assert_eq!(received.as_deref(), Some(data.as_slice()));
        let proof = actions
            .iter()
            .find_map(|a| match a {
                ResourceAction::SendProof(proof) => Some(proof.clone()),
                _ => None,
            })
            .unwrap();
        sender.handle_proof(&proof, 1100.0);
        assert_eq!(sender.status, ResourceStatus::Complete);
    }

    #[test]
    fn advertisement_within_link_mdu_keeps_its_hashmap() {
        let (data, mut sender) = multi_hashmap_sender(LINK_MDU);
        let adv = sender.get_advertisement(0);
        assert!(adv.len() <= LINK_MDU);
        assert_eq!(
            ResourceAdvertisement::unpack(&adv).unwrap().hashmap.len(),
            RESOURCE_HASHMAP_MAX_LEN * RESOURCE_MAPHASH_LEN
        );
        let mut receiver =
            ResourceReceiver::from_advertisement(&adv, RESOURCE_SDU, 0.5, 1000.0, None, None)
                .unwrap();
        let first = receiver.accept(1001.0);
        let (flags, actions) = run_transfer(&mut sender, &mut receiver, first);
        assert_eq!(flags[0], RESOURCE_HASHMAP_IS_NOT_EXHAUSTED);
        assert!(!flags.contains(&RESOURCE_HASHMAP_IS_EMPTY));
        assert!(actions.iter().any(
            |a| matches!(a, ResourceAction::DataReceived { data: received, .. } if *received == data)
        ));
    }

    #[test]
    fn app_flag_reaches_the_receiver() {
        let (mut sender, _) = make_sender_receiver();
        sender.flags.app_flag = true;
        let adv = sender.get_advertisement(0);
        let unpacked = ResourceAdvertisement::unpack(&adv).unwrap();
        assert_eq!(unpacked.flags.to_byte() & 0x40, 0x40);
        let mut receiver =
            ResourceReceiver::from_advertisement(&adv, RESOURCE_SDU, 0.5, 1000.0, None, None)
                .unwrap();
        assert!(receiver.flags.app_flag);
        let first = receiver.accept(1001.0);
        let (_, actions) = run_transfer(&mut sender, &mut receiver, first);
        assert!(actions
            .iter()
            .any(|a| matches!(a, ResourceAction::DataReceived { app_flag: true, .. })));

        let (mut sender, mut receiver) = make_sender_receiver();
        let first = receiver.accept(1001.0);
        let (_, actions) = run_transfer(&mut sender, &mut receiver, first);
        assert!(actions.iter().any(|a| matches!(
            a,
            ResourceAction::DataReceived {
                app_flag: false,
                ..
            }
        )));
    }

    #[test]
    fn test_full_transfer_with_metadata() {
        let data = b"data with metadata";
        let metadata = b"some metadata";
        let mut rng = rns_crypto::FixedRng::new(&[0x88; 64]);

        let mut sender = ResourceSender::new(
            data,
            Some(metadata),
            RESOURCE_SDU,
            &identity_encrypt,
            &NoopCompressor,
            &mut rng,
            1000.0,
            false,
            false,
            None,
            1,
            1,
            None,
            0.5,
            6.0,
        )
        .unwrap();

        assert!(sender.flags.has_metadata);

        let adv = sender.get_advertisement(0);
        let mut receiver =
            ResourceReceiver::from_advertisement(&adv, RESOURCE_SDU, 0.5, 1000.0, None, None)
                .unwrap();

        assert!(receiver.has_metadata);

        // Transfer all parts
        let req_actions = receiver.accept(1001.0);
        let request_data = req_actions
            .iter()
            .find_map(|a| match a {
                ResourceAction::SendRequest(d) => Some(d.clone()),
                _ => None,
            })
            .unwrap();

        let send_actions = sender.handle_request(&request_data, 1002.0);
        receiver.req_sent = 1001.0;
        for action in &send_actions {
            if let ResourceAction::SendPart(part_data) = action {
                receiver.receive_part(part_data, 1003.0);
            }
        }

        let assemble_actions = receiver.assemble(&identity_decrypt, &NoopCompressor);

        let (recv_data, recv_meta) = assemble_actions
            .iter()
            .find_map(|a| match a {
                ResourceAction::DataReceived { data, metadata, .. } => {
                    Some((data.clone(), metadata.clone()))
                }
                _ => None,
            })
            .unwrap();

        assert_eq!(recv_data, data);
        assert_eq!(recv_meta.unwrap(), metadata);
    }

    #[test]
    fn test_previous_window_restore() {
        let (_, _receiver) = make_sender_receiver();
        // Create with previous window
        let adv_data = {
            let mut rng = rns_crypto::FixedRng::new(&[0x42; 64]);
            let sender = ResourceSender::new(
                b"test",
                None,
                RESOURCE_SDU,
                &identity_encrypt,
                &NoopCompressor,
                &mut rng,
                1000.0,
                false,
                false,
                None,
                1,
                1,
                None,
                0.5,
                6.0,
            )
            .unwrap();
            sender.get_advertisement(0)
        };

        let receiver = ResourceReceiver::from_advertisement(
            &adv_data,
            RESOURCE_SDU,
            0.5,
            1000.0,
            Some(8),
            Some(50000.0),
        )
        .unwrap();
        assert_eq!(receiver.window.window, 8);
    }

    #[test]
    fn test_tick_timeout_retry() {
        let (_, mut receiver) = make_sender_receiver();
        receiver.accept(1000.0);
        receiver.rtt = Some(0.1);

        // Way past timeout
        let actions = receiver.tick(9999.0, &identity_decrypt, &NoopCompressor);
        // Should have retried (window decreased, request_next called)
        assert!(!actions.is_empty() || receiver.retries_left < RESOURCE_MAX_RETRIES);
    }

    #[test]
    fn test_tick_waiting_for_hmu_gets_extra_timeout() {
        let (_, mut receiver) = make_sender_receiver();
        receiver.accept(1000.0);
        receiver.waiting_for_hmu = true;
        receiver.outstanding_parts = 0;
        let eifr = 10_000.0;
        receiver.previous_eifr = Some(eifr);
        receiver.last_activity = 1000.0;

        let old_timeout = base_timeout(&receiver, eifr);
        let now = old_timeout + 0.01;

        let actions = receiver.tick(now, &identity_decrypt, &NoopCompressor);

        assert!(actions.is_empty(), "receiver should keep waiting for HMU");
        assert_eq!(receiver.retries_left, RESOURCE_MAX_RETRIES);
        assert_eq!(receiver.status, ResourceStatus::Transferring);
    }

    #[test]
    fn test_tick_zero_outstanding_parts_gets_extra_timeout_without_hmu_flag() {
        let (_, mut receiver) = make_sender_receiver();
        receiver.accept(1000.0);
        receiver.waiting_for_hmu = false;
        receiver.outstanding_parts = 0;
        let eifr = 10_000.0;
        receiver.previous_eifr = Some(eifr);
        receiver.last_activity = 1000.0;

        let old_timeout = base_timeout(&receiver, eifr);
        let now = old_timeout + 0.01;

        let actions = receiver.tick(now, &identity_decrypt, &NoopCompressor);

        assert!(
            actions.is_empty(),
            "receiver should keep waiting for follow-up hashmap data"
        );
        assert_eq!(receiver.retries_left, RESOURCE_MAX_RETRIES);
        assert_eq!(receiver.status, ResourceStatus::Transferring);
    }

    #[test]
    fn test_tick_waiting_for_hmu_retries_after_extended_timeout() {
        let (_, mut receiver) = make_sender_receiver();
        receiver.accept(1000.0);
        receiver.waiting_for_hmu = true;
        receiver.outstanding_parts = 0;
        let eifr = 10_000.0;
        receiver.previous_eifr = Some(eifr);
        receiver.last_activity = 1000.0;

        let now = hmu_timeout(&receiver, eifr) + 0.01;
        let _actions = receiver.tick(now, &identity_decrypt, &NoopCompressor);

        assert_eq!(receiver.retries_left, RESOURCE_MAX_RETRIES - 1);
        assert!(!receiver.waiting_for_hmu);
    }

    #[test]
    fn test_tick_inflight_parts_do_not_get_hmu_timeout_extension() {
        let (_, mut receiver) = make_sender_receiver();
        receiver.accept(1000.0);
        receiver.waiting_for_hmu = false;
        receiver.outstanding_parts = 2;
        let eifr = 10_000.0;
        receiver.previous_eifr = Some(eifr);
        receiver.last_activity = 1000.0;

        let now = base_timeout(&receiver, eifr) + 0.01;
        let _actions = receiver.tick(now, &identity_decrypt, &NoopCompressor);

        assert_eq!(receiver.retries_left, RESOURCE_MAX_RETRIES - 1);
    }

    #[test]
    fn test_tick_max_retries_exceeded() {
        let (_, mut receiver) = make_sender_receiver();
        receiver.accept(1000.0);
        receiver.retries_left = 0;
        receiver.rtt = Some(0.001);
        receiver.eifr = Some(100000.0);

        let _actions = receiver.tick(9999.0, &identity_decrypt, &NoopCompressor);
        assert_eq!(receiver.status, ResourceStatus::Failed);
    }
}
