use alloc::vec;
use alloc::vec::Vec;

use rns_crypto::Rng;

use crate::constants::*;
use crate::hash::get_random_hash;
use crate::buffer::types::Compressor;
use super::types::*;
use super::advertisement::ResourceAdvertisement;
use super::parts::{split_into_parts, build_hashmap, has_collision, prepend_metadata};
use super::proof::{compute_resource_hash, compute_expected_proof, validate_proof};

/// Resource sender state machine.
///
/// Creates an advertisement, handles part requests, sends parts, and validates proofs.
/// Returns `Vec<ResourceAction>` — no I/O, no callbacks.
pub struct ResourceSender {
    /// Current status
    pub status: ResourceStatus,
    /// Resource hash (SHA-256 of unencrypted data + random_hash), 32 bytes
    pub resource_hash: [u8; 32],
    /// Truncated hash (first 16 bytes of resource_hash)
    pub truncated_hash: [u8; 16],
    /// Expected proof (SHA-256 of unencrypted data + resource_hash)
    pub expected_proof: [u8; 32],
    /// Original hash (for multi-segment, first segment's hash)
    pub original_hash: [u8; 32],
    /// Random hash for map hashing (4 bytes)
    pub random_hash: Vec<u8>,
    /// SDU size
    pub sdu: usize,
    /// Encrypted parts data
    parts: Vec<Vec<u8>>,
    /// Part map hashes (4 bytes each)
    pub part_hashes: Vec<[u8; RESOURCE_MAPHASH_LEN]>,
    /// Concatenated hashmap bytes
    hashmap: Vec<u8>,
    /// Number of parts
    total_parts: usize,
    /// Number of unique parts sent
    pub sent_parts: usize,
    /// Tracks which part indices have been sent (for dedup)
    sent_indices: Vec<bool>,
    /// Flags
    pub flags: AdvFlags,
    /// Transfer size (encrypted data size)
    pub transfer_size: usize,
    /// Total uncompressed data size
    pub data_size: usize,
    /// Segment index (1-based)
    pub segment_index: u64,
    /// Total segments
    pub total_segments: u64,
    /// Request ID
    pub request_id: Option<Vec<u8>>,
    /// Retries left
    pub retries_left: usize,
    /// Max retries
    pub max_retries: usize,
    /// Max advertisement retries
    pub max_adv_retries: usize,
    /// RTT estimate (seconds)
    pub rtt: Option<f64>,
    /// Link RTT estimate (from link establishment)
    pub link_rtt: f64,
    /// Timeout factor
    pub timeout_factor: f64,
    /// Last activity timestamp
    pub last_activity: f64,
    /// Advertisement sent timestamp
    pub adv_sent: f64,
    /// Last part sent timestamp
    pub last_part_sent: f64,
    /// Sender grace time
    pub sender_grace_time: f64,
    /// Receiver min consecutive height (for search optimization)
    receiver_min_consecutive_height: usize,
}

impl ResourceSender {
    /// Create a new ResourceSender from unencrypted data.
    ///
    /// - `data`: raw application data (no metadata prefix)
    /// - `metadata`: optional pre-serialized metadata bytes
    /// - `sdu`: SDU size (usually RESOURCE_SDU = 464)
    /// - `encrypt_fn`: closure to encrypt the full data blob
    /// - `compressor`: Compressor trait for optional compression
    /// - `rng`: random number generator
    /// - `now`: current timestamp
    /// - `auto_compress`: whether to attempt compression
    /// - `is_response`: whether this is a response to a request
    /// - `request_id`: optional request ID
    /// - `segment_index`: 1-based segment number (1 for single-segment)
    /// - `total_segments`: total number of segments
    /// - `original_hash`: original hash from first segment (None for first segment)
    /// - `link_rtt`: current link RTT estimate
    /// - `traffic_timeout_factor`: link traffic timeout factor
    pub fn new(
        data: &[u8],
        metadata: Option<&[u8]>,
        sdu: usize,
        encrypt_fn: &dyn Fn(&[u8]) -> Vec<u8>,
        compressor: &dyn Compressor,
        rng: &mut dyn Rng,
        now: f64,
        auto_compress: bool,
        is_response: bool,
        request_id: Option<Vec<u8>>,
        segment_index: u64,
        total_segments: u64,
        original_hash: Option<[u8; 32]>,
        link_rtt: f64,
        traffic_timeout_factor: f64,
    ) -> Result<Self, ResourceError> {
        // Build unencrypted data (metadata prefix + data)
        let uncompressed_data = match metadata {
            Some(meta) => prepend_metadata(data, meta),
            None => data.to_vec(),
        };
        let has_metadata = metadata.is_some();

        let data_size = uncompressed_data.len();

        // Try compression
        let (working_data, compressed) = if auto_compress {
            match compressor.compress(&uncompressed_data) {
                Some(compressed_data) if compressed_data.len() < uncompressed_data.len() => {
                    (compressed_data, true)
                }
                _ => (uncompressed_data.clone(), false),
            }
        } else {
            (uncompressed_data.clone(), false)
        };

        // Prepend random hash (4 bytes)
        let random_prefix: [u8; RESOURCE_RANDOM_HASH_SIZE] = {
            let rh = get_random_hash(rng);
            let mut buf = [0u8; RESOURCE_RANDOM_HASH_SIZE];
            buf.copy_from_slice(&rh[..RESOURCE_RANDOM_HASH_SIZE]);
            buf
        };
        let mut data_with_random = Vec::with_capacity(RESOURCE_RANDOM_HASH_SIZE + working_data.len());
        data_with_random.extend_from_slice(&random_prefix);
        data_with_random.extend_from_slice(&working_data);

        // Encrypt
        let encrypted_data = encrypt_fn(&data_with_random);
        let transfer_size = encrypted_data.len();

        // Keep trying until no collision in hashmap (max 100 attempts)
        let mut resource_hash;
        let mut truncated_resource_hash;
        let mut expected_proof;
        let mut final_random_hash;
        let mut parts_data;
        let mut part_hashes;
        let mut collision_retries = 0;
        const MAX_COLLISION_RETRIES: usize = 100;

        loop {
            final_random_hash = {
                let rh = get_random_hash(rng);
                rh[..RESOURCE_RANDOM_HASH_SIZE].to_vec()
            };

            resource_hash = compute_resource_hash(&uncompressed_data, &final_random_hash);
            truncated_resource_hash = {
                let mut t = [0u8; 16];
                t.copy_from_slice(&resource_hash[..16]);
                t
            };
            expected_proof = compute_expected_proof(&uncompressed_data, &resource_hash);

            let (p, h) = split_into_parts(&encrypted_data, sdu, &final_random_hash);
            parts_data = p;
            part_hashes = h;

            if !has_collision(&part_hashes) {
                break;
            }
            // Collision detected, retry with new random hash
            collision_retries += 1;
            if collision_retries >= MAX_COLLISION_RETRIES {
                return Err(ResourceError::CollisionDetected);
            }
        }

        let hashmap = build_hashmap(&part_hashes);
        let total_parts = parts_data.len();

        let orig_hash = original_hash.unwrap_or(resource_hash);

        let flags = AdvFlags {
            encrypted: true,
            compressed,
            split: total_segments > 1,
            is_request: request_id.is_some() && !is_response,
            is_response: request_id.is_some() && is_response,
            has_metadata,
        };

        Ok(ResourceSender {
            status: ResourceStatus::Queued,
            resource_hash,
            truncated_hash: truncated_resource_hash,
            expected_proof,
            original_hash: orig_hash,
            random_hash: final_random_hash,
            sdu,
            parts: parts_data,
            part_hashes,
            hashmap,
            total_parts,
            sent_parts: 0,
            sent_indices: vec![false; total_parts],
            flags,
            transfer_size,
            data_size,
            segment_index,
            total_segments,
            request_id,
            retries_left: RESOURCE_MAX_RETRIES,
            max_retries: RESOURCE_MAX_RETRIES,
            max_adv_retries: RESOURCE_MAX_ADV_RETRIES,
            rtt: None,
            link_rtt,
            timeout_factor: traffic_timeout_factor,
            last_activity: now,
            adv_sent: now,
            last_part_sent: now,
            sender_grace_time: RESOURCE_SENDER_GRACE_TIME,
            receiver_min_consecutive_height: 0,
        })
    }

    /// Generate the advertisement for the given hashmap segment.
    pub fn get_advertisement(&self, segment: usize) -> Vec<u8> {
        let adv = ResourceAdvertisement {
            transfer_size: self.transfer_size as u64,
            data_size: self.data_size as u64,
            num_parts: self.total_parts as u64,
            resource_hash: self.resource_hash.to_vec(),
            random_hash: self.random_hash.clone(),
            original_hash: self.original_hash.to_vec(),
            hashmap: self.hashmap.clone(),
            flags: self.flags,
            segment_index: self.segment_index,
            total_segments: self.total_segments,
            request_id: self.request_id.clone(),
        };
        adv.pack(segment)
    }

    /// Advertise the resource. Returns SendAdvertisement action.
    pub fn advertise(&mut self, now: f64) -> Vec<ResourceAction> {
        self.status = ResourceStatus::Advertised;
        self.last_activity = now;
        self.adv_sent = now;
        self.retries_left = self.max_adv_retries;
        let adv_data = self.get_advertisement(0);
        vec![ResourceAction::SendAdvertisement(adv_data)]
    }

    /// Handle a request for parts (RESOURCE_REQ context).
    ///
    /// request_data format:
    /// [exhausted_flag: u8][last_map_hash: 4 bytes if exhausted][resource_hash: 32 bytes][requested_hashes: N*4 bytes]
    pub fn handle_request(&mut self, request_data: &[u8], now: f64) -> Vec<ResourceAction> {
        if self.status == ResourceStatus::Failed {
            return vec![];
        }

        // Measure RTT from advertisement
        if self.rtt.is_none() {
            self.rtt = Some(now - self.adv_sent);
        }

        if self.status != ResourceStatus::Transferring {
            self.status = ResourceStatus::Transferring;
        }

        self.retries_left = self.max_retries;
        self.last_activity = now;

        let wants_more_hashmap = request_data.first() == Some(&RESOURCE_HASHMAP_IS_EXHAUSTED);
        let pad = if wants_more_hashmap {
            1 + RESOURCE_MAPHASH_LEN
        } else {
            1
        };

        if request_data.len() < pad + 32 {
            return vec![];
        }

        let requested_hashes_data = &request_data[pad + 32..];
        let mut actions = Vec::new();

        // Parse requested map hashes
        let num_requested = requested_hashes_data.len() / RESOURCE_MAPHASH_LEN;
        let mut map_hashes_requested = Vec::with_capacity(num_requested);
        for i in 0..num_requested {
            let start = i * RESOURCE_MAPHASH_LEN;
            let end = start + RESOURCE_MAPHASH_LEN;
            if end <= requested_hashes_data.len() {
                let mut h = [0u8; RESOURCE_MAPHASH_LEN];
                h.copy_from_slice(&requested_hashes_data[start..end]);
                map_hashes_requested.push(h);
            }
        }

        // Search for requested parts within guard window
        let search_start = self.receiver_min_consecutive_height;
        let search_end = core::cmp::min(
            search_start + RESOURCE_COLLISION_GUARD_SIZE,
            self.total_parts,
        );

        for part_idx in search_start..search_end {
            if map_hashes_requested.contains(&self.part_hashes[part_idx]) {
                actions.push(ResourceAction::SendPart(self.parts[part_idx].clone()));
                if !self.sent_indices[part_idx] {
                    self.sent_indices[part_idx] = true;
                    self.sent_parts += 1;
                }
                self.last_part_sent = now;
            }
        }

        // Handle hashmap exhaustion
        if wants_more_hashmap {
            if let Some(hmu) = self.build_hmu(request_data, now) {
                actions.push(ResourceAction::SendHmu(hmu));
            }
        }

        // Check if all parts sent
        if self.sent_parts >= self.total_parts {
            self.status = ResourceStatus::AwaitingProof;
            self.retries_left = 3; // hardcoded in Python
        }

        actions
    }

    /// Build hashmap update data.
    fn build_hmu(&mut self, request_data: &[u8], now: f64) -> Option<Vec<u8>> {
        if request_data.len() < 1 + RESOURCE_MAPHASH_LEN {
            return None;
        }

        let last_map_hash_bytes = &request_data[1..1 + RESOURCE_MAPHASH_LEN];
        let mut last_map_hash = [0u8; RESOURCE_MAPHASH_LEN];
        last_map_hash.copy_from_slice(last_map_hash_bytes);

        // Find the part index of the last map hash
        let search_start = self.receiver_min_consecutive_height;
        let search_end = core::cmp::min(
            search_start + RESOURCE_COLLISION_GUARD_SIZE,
            self.total_parts,
        );

        let mut part_index = search_start;
        for idx in search_start..search_end {
            part_index = idx + 1;
            if self.part_hashes[idx] == last_map_hash {
                break;
            }
        }

        // Update receiver min consecutive height
        self.receiver_min_consecutive_height =
            if part_index > RESOURCE_WINDOW_MAX { part_index - 1 - RESOURCE_WINDOW_MAX } else { 0 };

        // Verify alignment
        if part_index % RESOURCE_HASHMAP_MAX_LEN != 0 {
            return None; // sequencing error
        }

        let segment = part_index / RESOURCE_HASHMAP_MAX_LEN;
        let hashmap_start = segment * RESOURCE_HASHMAP_MAX_LEN;
        let hashmap_end = core::cmp::min(
            (segment + 1) * RESOURCE_HASHMAP_MAX_LEN,
            self.total_parts,
        );

        let mut hashmap_segment = Vec::new();
        for i in hashmap_start..hashmap_end {
            hashmap_segment.extend_from_slice(&self.hashmap[i * RESOURCE_MAPHASH_LEN..(i + 1) * RESOURCE_MAPHASH_LEN]);
        }

        // Build HMU: resource_hash + msgpack([segment, hashmap])
        let hmu_payload = crate::msgpack::pack(&crate::msgpack::Value::Array(vec![
            crate::msgpack::Value::UInt(segment as u64),
            crate::msgpack::Value::Bin(hashmap_segment),
        ]));

        let mut hmu = Vec::with_capacity(32 + hmu_payload.len());
        hmu.extend_from_slice(&self.resource_hash);
        hmu.extend_from_slice(&hmu_payload);

        self.last_activity = now;
        Some(hmu)
    }

    /// Handle proof from receiver.
    pub fn handle_proof(&mut self, proof_data: &[u8], _now: f64) -> Vec<ResourceAction> {
        if self.status == ResourceStatus::Failed {
            return vec![];
        }

        match validate_proof(proof_data, &self.resource_hash, &self.expected_proof) {
            Ok(true) => {
                self.status = ResourceStatus::Complete;
                vec![ResourceAction::Completed]
            }
            Ok(false) => {
                self.status = ResourceStatus::Failed;
                vec![ResourceAction::Failed(ResourceError::InvalidProof)]
            }
            Err(e) => {
                self.status = ResourceStatus::Failed;
                vec![ResourceAction::Failed(e)]
            }
        }
    }

    /// Handle rejection from receiver.
    pub fn handle_reject(&mut self) -> Vec<ResourceAction> {
        self.status = ResourceStatus::Rejected;
        vec![ResourceAction::Failed(ResourceError::Rejected)]
    }

    /// Cancel the transfer.
    pub fn cancel(&mut self) -> Vec<ResourceAction> {
        if self.status < ResourceStatus::Complete {
            self.status = ResourceStatus::Failed;
            vec![ResourceAction::SendCancelInitiator(self.resource_hash.to_vec())]
        } else {
            vec![]
        }
    }

    /// Periodic tick. Checks for timeouts.
    pub fn tick(&mut self, now: f64) -> Vec<ResourceAction> {
        if self.status >= ResourceStatus::Complete {
            return vec![];
        }

        match self.status {
            ResourceStatus::Advertised => {
                let timeout = self.adv_sent
                    + self.rtt.unwrap_or(self.link_rtt * self.timeout_factor)
                    + RESOURCE_PROCESSING_GRACE;
                if now > timeout {
                    if self.retries_left == 0 {
                        self.status = ResourceStatus::Failed;
                        return vec![ResourceAction::Failed(ResourceError::Timeout)];
                    }
                    self.retries_left -= 1;
                    self.last_activity = now;
                    self.adv_sent = now;
                    let adv_data = self.get_advertisement(0);
                    return vec![ResourceAction::SendAdvertisement(adv_data)];
                }
            }
            ResourceStatus::Transferring => {
                let rtt = self.rtt.unwrap_or(1.0);
                let max_extra_wait: f64 = (0..self.max_retries)
                    .map(|r| (r as f64 + 1.0) * RESOURCE_PER_RETRY_DELAY)
                    .sum();
                let max_wait = rtt * self.timeout_factor * self.max_retries as f64
                    + self.sender_grace_time
                    + max_extra_wait;
                if now > self.last_activity + max_wait {
                    self.status = ResourceStatus::Failed;
                    return vec![ResourceAction::Failed(ResourceError::Timeout)];
                }
            }
            ResourceStatus::AwaitingProof => {
                let rtt = self.rtt.unwrap_or(1.0);
                let timeout = self.last_part_sent
                    + rtt * RESOURCE_PROOF_TIMEOUT_FACTOR
                    + self.sender_grace_time;
                if now > timeout {
                    if self.retries_left == 0 {
                        self.status = ResourceStatus::Failed;
                        return vec![ResourceAction::Failed(ResourceError::Timeout)];
                    }
                    self.retries_left -= 1;
                    self.last_part_sent = now;
                    // In Python, this queries network cache. We just signal retry.
                    return vec![];
                }
            }
            _ => {}
        }

        vec![]
    }

    /// Get the total number of parts.
    pub fn total_parts(&self) -> usize {
        self.total_parts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::types::NoopCompressor;

    fn identity_encrypt(data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    fn make_sender(data: &[u8]) -> ResourceSender {
        let mut rng = rns_crypto::FixedRng::new(&[0x42; 64]);
        ResourceSender::new(
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
        .unwrap()
    }

    #[test]
    fn test_new_sender_status() {
        let sender = make_sender(b"test data");
        assert_eq!(sender.status, ResourceStatus::Queued);
    }

    #[test]
    fn test_new_sender_parts() {
        let data = vec![0xAA; 1000];
        let sender = make_sender(&data);
        // 4 (random) + 1000 data = 1004 encrypted bytes
        // 1004 / 464 = 3 parts (464, 464, 76)
        assert_eq!(sender.total_parts(), 3);
    }

    #[test]
    fn test_advertise() {
        let mut sender = make_sender(b"test data");
        let actions = sender.advertise(1000.0);
        assert_eq!(sender.status, ResourceStatus::Advertised);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            ResourceAction::SendAdvertisement(data) => {
                assert!(!data.is_empty());
            }
            _ => panic!("Expected SendAdvertisement"),
        }
    }

    #[test]
    fn test_handle_request_basic() {
        let mut sender = make_sender(b"short");
        sender.advertise(1000.0);

        // Build a request: [not_exhausted][resource_hash][first part hash]
        let mut request = Vec::new();
        request.push(RESOURCE_HASHMAP_IS_NOT_EXHAUSTED);
        request.extend_from_slice(&sender.resource_hash);
        request.extend_from_slice(&sender.part_hashes[0]);

        let actions = sender.handle_request(&request, 1001.0);
        assert!(!actions.is_empty());
        // Should have sent a part
        let has_part = actions.iter().any(|a| matches!(a, ResourceAction::SendPart(_)));
        assert!(has_part);
    }

    #[test]
    fn test_all_parts_sent_awaiting_proof() {
        let mut sender = make_sender(b"hi");
        sender.advertise(1000.0);

        // Request all parts
        let mut request = Vec::new();
        request.push(RESOURCE_HASHMAP_IS_NOT_EXHAUSTED);
        request.extend_from_slice(&sender.resource_hash);
        for h in &sender.part_hashes.clone() {
            request.extend_from_slice(h);
        }

        let _actions = sender.handle_request(&request, 1001.0);
        assert_eq!(sender.status, ResourceStatus::AwaitingProof);
        assert_eq!(sender.retries_left, 3);
    }

    #[test]
    fn test_valid_proof() {
        let mut sender = make_sender(b"data");
        sender.advertise(1000.0);

        let proof_data = super::super::proof::build_proof_data(
            &sender.resource_hash,
            &sender.expected_proof,
        );
        let actions = sender.handle_proof(&proof_data, 1002.0);
        assert_eq!(sender.status, ResourceStatus::Complete);
        assert!(actions.iter().any(|a| matches!(a, ResourceAction::Completed)));
    }

    #[test]
    fn test_invalid_proof() {
        let mut sender = make_sender(b"data");
        sender.advertise(1000.0);

        let wrong_proof = [0xFF; 32];
        let proof_data = super::super::proof::build_proof_data(
            &sender.resource_hash,
            &wrong_proof,
        );
        let _actions = sender.handle_proof(&proof_data, 1002.0);
        assert_eq!(sender.status, ResourceStatus::Failed);
    }

    #[test]
    fn test_handle_reject() {
        let mut sender = make_sender(b"data");
        sender.advertise(1000.0);
        let _actions = sender.handle_reject();
        assert_eq!(sender.status, ResourceStatus::Rejected);
    }

    #[test]
    fn test_cancel() {
        let mut sender = make_sender(b"data");
        sender.advertise(1000.0);
        let actions = sender.cancel();
        assert_eq!(sender.status, ResourceStatus::Failed);
        assert!(actions.iter().any(|a| matches!(a, ResourceAction::SendCancelInitiator(_))));
    }

    #[test]
    fn test_cancel_already_complete() {
        let mut sender = make_sender(b"data");
        sender.status = ResourceStatus::Complete;
        let actions = sender.cancel();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_tick_advertised_timeout() {
        let mut sender = make_sender(b"data");
        sender.advertise(1000.0);
        sender.retries_left = 0;

        // Way past timeout
        let _actions = sender.tick(2000.0);
        assert_eq!(sender.status, ResourceStatus::Failed);
    }

    #[test]
    fn test_tick_advertised_retry() {
        let mut sender = make_sender(b"data");
        sender.advertise(1000.0);
        assert!(sender.retries_left > 0);

        let actions = sender.tick(2000.0);
        // Should retry advertisement
        assert!(actions.iter().any(|a| matches!(a, ResourceAction::SendAdvertisement(_))));
    }

    #[test]
    fn test_resource_hash_is_32_bytes() {
        let sender = make_sender(b"data");
        assert_eq!(sender.resource_hash.len(), 32);
        assert_eq!(sender.expected_proof.len(), 32);
    }

    #[test]
    fn test_sender_with_metadata() {
        let mut rng = rns_crypto::FixedRng::new(&[0x55; 64]);
        let sender = ResourceSender::new(
            b"data",
            Some(b"metadata"),
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
    }

    #[test]
    fn test_multi_segment_sender() {
        let orig_hash = [0xBB; 32];
        let mut rng = rns_crypto::FixedRng::new(&[0x66; 64]);
        let sender = ResourceSender::new(
            b"segment 2 data",
            None,
            RESOURCE_SDU,
            &identity_encrypt,
            &NoopCompressor,
            &mut rng,
            1000.0,
            false,
            false,
            None,
            2,
            5,
            Some(orig_hash),
            0.5,
            6.0,
        )
        .unwrap();
        assert_eq!(sender.segment_index, 2);
        assert_eq!(sender.total_segments, 5);
        assert_eq!(sender.original_hash, orig_hash);
        assert!(sender.flags.split);
    }
}
