use alloc::vec;
use alloc::vec::Vec;

use crate::constants::*;
use crate::buffer::types::Compressor;
use super::types::*;
use super::advertisement::ResourceAdvertisement;
use super::parts::{map_hash, extract_metadata};
use super::proof::{compute_resource_hash, compute_expected_proof, build_proof_data};
use super::window::WindowState;

/// Resource receiver state machine.
///
/// Unpacks advertisements, requests parts, receives parts, assembles data.
/// Returns `Vec<ResourceAction>` — no I/O, no callbacks.
pub struct ResourceReceiver {
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

        let total_parts = adv.num_parts as usize;
        let parts_vec: Vec<Option<Vec<u8>>> = vec![None; total_parts];
        let mut hashmap_vec: Vec<Option<[u8; RESOURCE_MAPHASH_LEN]>> = vec![None; total_parts];

        // Populate initial hashmap from advertisement
        let initial_hashes = adv.hashmap.len() / RESOURCE_MAPHASH_LEN;
        let mut hashmap_height = 0;
        for i in 0..initial_hashes {
            if i < total_parts {
                let start = i * RESOURCE_MAPHASH_LEN;
                let end = start + RESOURCE_MAPHASH_LEN;
                let mut h = [0u8; RESOURCE_MAPHASH_LEN];
                h.copy_from_slice(&adv.hashmap[start..end]);
                hashmap_vec[i] = Some(h);
                hashmap_height += 1;
            }
        }

        let mut window_state = WindowState::new();
        if let Some(prev_w) = previous_window {
            window_state.restore(prev_w);
        }

        Ok(ResourceReceiver {
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
        })
    }

    /// Accept the advertised resource. Begins transfer.
    pub fn accept(&mut self, now: f64) -> Vec<ResourceAction> {
        self.status = ResourceStatus::Transferring;
        self.last_activity = now;
        self.request_next(now)
    }

    /// Reject the advertised resource.
    pub fn reject(&mut self) -> Vec<ResourceAction> {
        self.status = ResourceStatus::Rejected;
        vec![ResourceAction::SendCancelReceiver(self.resource_hash.clone())]
    }

    /// Receive a part. Matches by map hash and stores it.
    pub fn receive_part(&mut self, part_data: &[u8], now: f64) -> Vec<ResourceAction> {
        if self.status == ResourceStatus::Failed {
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

        // Search in the window around consecutive_completed_height
        let consecutive_idx = if self.consecutive_completed_height >= 0 {
            self.consecutive_completed_height as usize
        } else {
            0
        };

        let mut matched = false;
        let search_end = core::cmp::min(consecutive_idx + self.window.window, self.total_parts);
        for i in consecutive_idx..search_end {
            if let Some(ref h) = self.hashmap[i] {
                if *h == part_hash {
                    if self.parts[i].is_none() {
                        self.parts[i] = Some(part_data.to_vec());
                        self.rtt_rxd_bytes += part_data.len();
                        self.received_count += 1;
                        self.outstanding_parts = self.outstanding_parts.saturating_sub(1);

                        // Update consecutive completed height
                        if i as isize == self.consecutive_completed_height + 1 {
                            self.consecutive_completed_height = i as isize;
                        }

                        // Walk forward to extend consecutive height
                        let mut cp = (self.consecutive_completed_height + 1) as usize;
                        while cp < self.total_parts && self.parts[cp].is_some() {
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
        if self.status == ResourceStatus::Failed {
            return vec![];
        }

        self.last_activity = now;
        self.retries_left = self.max_retries;

        if hmu_data.len() <= 32 {
            return vec![];
        }

        let payload = &hmu_data[32..];
        let (value, _) = match crate::msgpack::unpack(payload) {
            Ok(v) => v,
            Err(_) => return vec![],
        };

        let arr = match value.as_array() {
            Some(a) if a.len() >= 2 => a,
            _ => return vec![],
        };

        let segment = match arr[0].as_uint() {
            Some(s) => s as usize,
            None => return vec![],
        };

        let hashmap_bytes = match arr[1].as_bin() {
            Some(b) => b,
            None => return vec![],
        };

        // Populate hashmap slots
        let seg_len = RESOURCE_HASHMAP_MAX_LEN;
        let num_hashes = hashmap_bytes.len() / RESOURCE_MAPHASH_LEN;
        for i in 0..num_hashes {
            let idx = i + segment * seg_len;
            if idx < self.total_parts {
                let start = i * RESOURCE_MAPHASH_LEN;
                let end = start + RESOURCE_MAPHASH_LEN;
                if self.hashmap[idx].is_none() {
                    self.hashmap_height += 1;
                }
                let mut h = [0u8; RESOURCE_MAPHASH_LEN];
                h.copy_from_slice(&hashmap_bytes[start..end]);
                self.hashmap[idx] = Some(h);
            }
        }

        self.waiting_for_hmu = false;
        self.request_next(now)
    }

    /// Build and return request for next window of parts.
    pub fn request_next(&mut self, now: f64) -> Vec<ResourceAction> {
        if self.status == ResourceStatus::Failed || self.waiting_for_hmu {
            return vec![];
        }

        self.outstanding_parts = 0;
        let mut hashmap_exhausted = RESOURCE_HASHMAP_IS_NOT_EXHAUSTED;
        let mut requested_hashes = Vec::new();

        let pn_start = (self.consecutive_completed_height + 1) as usize;
        let search_end = core::cmp::min(pn_start + self.window.window, self.total_parts);
        let mut i = 0;

        for pn in pn_start..search_end {
            if self.parts[pn].is_none() {
                match self.hashmap[pn] {
                    Some(ref h) => {
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

        let mut request_data = Vec::new();
        request_data.push(hashmap_exhausted);
        if hashmap_exhausted == RESOURCE_HASHMAP_IS_EXHAUSTED {
            // Append last known map hash
            if self.hashmap_height > 0 {
                if let Some(ref last_hash) = self.hashmap[self.hashmap_height - 1] {
                    request_data.extend_from_slice(last_hash);
                } else {
                    request_data.extend_from_slice(&[0u8; RESOURCE_MAPHASH_LEN]);
                }
            } else {
                request_data.extend_from_slice(&[0u8; RESOURCE_MAPHASH_LEN]);
            }
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
        decrypt_fn: &dyn Fn(&[u8]) -> Result<Vec<u8>, ()>,
        compressor: &dyn Compressor,
    ) -> Vec<ResourceAction> {
        if self.received_count != self.total_parts {
            return vec![ResourceAction::Failed(ResourceError::InvalidState)];
        }

        self.status = ResourceStatus::Assembling;

        // Join all parts
        let mut stream = Vec::new();
        for part in &self.parts {
            match part {
                Some(data) => stream.extend_from_slice(data),
                None => {
                    self.status = ResourceStatus::Failed;
                    return vec![ResourceAction::Failed(ResourceError::InvalidState)];
                }
            }
        }

        // Decrypt
        let decrypted = if self.flags.encrypted {
            match decrypt_fn(&stream) {
                Ok(d) => d,
                Err(_) => {
                    self.status = ResourceStatus::Failed;
                    return vec![ResourceAction::Failed(ResourceError::DecryptionFailed)];
                }
            }
        } else {
            stream
        };

        // Strip random hash prefix
        if decrypted.len() < RESOURCE_RANDOM_HASH_SIZE {
            self.status = ResourceStatus::Corrupt;
            return vec![ResourceAction::Failed(ResourceError::InvalidPart)];
        }
        let data_after_random = &decrypted[RESOURCE_RANDOM_HASH_SIZE..];

        // Decompress
        let decompressed = if self.flags.compressed {
            match compressor.decompress(data_after_random) {
                Some(d) => d,
                None => {
                    self.status = ResourceStatus::Corrupt;
                    return vec![ResourceAction::Failed(ResourceError::DecompressionFailed)];
                }
            }
        } else {
            data_after_random.to_vec()
        };

        // Verify hash
        let calculated_hash = compute_resource_hash(&decompressed, &self.random_hash);
        if calculated_hash.as_slice() != self.resource_hash.as_slice() {
            self.status = ResourceStatus::Corrupt;
            return vec![ResourceAction::Failed(ResourceError::HashMismatch)];
        }

        // Compute proof before metadata extraction (proof uses full decompressed data)
        let expected_proof = compute_expected_proof(&decompressed, &calculated_hash);
        let proof_data = build_proof_data(&calculated_hash, &expected_proof);

        // Extract metadata if present
        let (data, metadata) = if self.has_metadata && self.segment_index == 1 {
            match extract_metadata(&decompressed) {
                Some((meta, rest)) => (rest, Some(meta)),
                None => {
                    self.status = ResourceStatus::Corrupt;
                    return vec![ResourceAction::Failed(ResourceError::InvalidPart)];
                }
            }
        } else {
            (decompressed, None)
        };

        self.status = ResourceStatus::Complete;

        vec![
            ResourceAction::SendProof(proof_data),
            ResourceAction::DataReceived { data, metadata },
            ResourceAction::Completed,
        ]
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
        decrypt_fn: &dyn Fn(&[u8]) -> Result<Vec<u8>, ()>,
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
            let expected_tof = if self.outstanding_parts > 0 && eifr > 0.0 {
                (self.outstanding_parts as f64 * self.sdu as f64 * 8.0) / eifr
            } else {
                if eifr > 0.0 {
                    (3.0 * self.sdu as f64) / eifr
                } else {
                    10.0 // fallback
                }
            };

            let sleep_time = self.last_activity
                + self.part_timeout_factor * expected_tof
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
    use crate::buffer::types::NoopCompressor;
    use crate::resource::sender::ResourceSender;

    fn identity_encrypt(data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    fn identity_decrypt(data: &[u8]) -> Result<Vec<u8>, ()> {
        Ok(data.to_vec())
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
        let receiver = ResourceReceiver::from_advertisement(
            &adv_data,
            RESOURCE_SDU,
            0.5,
            1000.0,
            None,
            None,
        )
        .unwrap();

        (sender, receiver)
    }

    #[test]
    fn test_from_advertisement() {
        let (sender, receiver) = make_sender_receiver();
        assert_eq!(receiver.total_parts, sender.total_parts());
        assert_eq!(receiver.transfer_size, sender.transfer_size as u64);
        assert_eq!(receiver.resource_hash, sender.resource_hash.to_vec());
    }

    #[test]
    fn test_accept() {
        let (_, mut receiver) = make_sender_receiver();
        let actions = receiver.accept(1000.0);
        assert_eq!(receiver.status, ResourceStatus::Transferring);
        assert!(!actions.is_empty());
        assert!(actions.iter().any(|a| matches!(a, ResourceAction::SendRequest(_))));
    }

    #[test]
    fn test_reject() {
        let (_, mut receiver) = make_sender_receiver();
        let actions = receiver.reject();
        assert_eq!(receiver.status, ResourceStatus::Rejected);
        assert!(actions.iter().any(|a| matches!(a, ResourceAction::SendCancelReceiver(_))));
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
    fn test_handle_cancel() {
        let (_, mut receiver) = make_sender_receiver();
        receiver.accept(1000.0);
        let _actions = receiver.handle_cancel();
        assert_eq!(receiver.status, ResourceStatus::Failed);
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
        let mut receiver = ResourceReceiver::from_advertisement(
            &adv,
            RESOURCE_SDU,
            0.5,
            1000.0,
            None,
            None,
        )
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
        let has_proof = assemble_actions.iter().any(|a| matches!(a, ResourceAction::SendProof(_)));
        let has_data = assemble_actions.iter().any(|a| matches!(a, ResourceAction::DataReceived { .. }));
        let has_complete = assemble_actions.iter().any(|a| matches!(a, ResourceAction::Completed));

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
        let mut receiver = ResourceReceiver::from_advertisement(
            &adv,
            RESOURCE_SDU,
            0.5,
            1000.0,
            None,
            None,
        )
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
                ResourceAction::DataReceived { data, metadata } => Some((data.clone(), metadata.clone())),
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
