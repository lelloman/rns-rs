use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use rns_crypto::Rng;

use super::advertisement::AdvertisementFields;
use super::parts::{
    build_hashmap, has_collision, map_hash, map_hashes_with_data, prepend_metadata,
};
use super::proof::{data_hash_state, finish_with, validate_proof};
use super::types::*;
use crate::buffer::types::Compressor;
use crate::constants::*;
use crate::hash::get_random_hash;

/// How a resource's data is encrypted. Any `Fn(&[u8]) -> Vec<u8>` is one.
pub trait ResourceEncrypt {
    /// Encrypt `data`.
    fn encrypt(&self, data: &[u8]) -> Vec<u8>;

    /// The encryption with its tag left to the caller, when it has that
    /// form: the last 32 bytes are zero, and the MAC, fed every byte before
    /// them, finalizes to the tag. The sender then hashes those bytes
    /// together with its other passes.
    fn encrypt_untagged(&self, _data: &[u8]) -> Option<(Vec<u8>, rns_crypto::hmac::HmacSha256)> {
        None
    }
}

impl<F: Fn(&[u8]) -> Vec<u8>> ResourceEncrypt for F {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self(data)
    }
}

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
    /// Encrypted bytes retained once; parts are slices of this buffer.
    parts: Box<[u8]>,
    /// Original partition size, independent of the public SDU field.
    part_sdu: usize,
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
    /// MDU of the link carrying the advertisement. An advertisement that
    /// would exceed it is sent without its hashmap, which the receiver then
    /// requests as a hashmap update.
    pub advertisement_mdu: usize,
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
    #[allow(
        clippy::too_many_arguments,
        reason = "each argument is an independent property of the resource segment being built"
    )]
    pub fn new(
        data: &[u8],
        metadata: Option<&[u8]>,
        sdu: usize,
        encrypt_fn: &dyn ResourceEncrypt,
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
            Some(meta) => Cow::Owned(prepend_metadata(data, meta)),
            None => Cow::Borrowed(data),
        };
        let has_metadata = metadata.is_some();

        let data_size = uncompressed_data.len();

        // Try compression
        let (working_data, compressed) =
            if auto_compress && uncompressed_data.len() <= RESOURCE_AUTO_COMPRESS_MAX_SIZE {
                match compressor.compress(&uncompressed_data) {
                    Some(compressed_data) if compressed_data.len() < uncompressed_data.len() => {
                        (Cow::Owned(compressed_data), true)
                    }
                    _ => (Cow::Borrowed(uncompressed_data.as_ref()), false),
                }
            } else {
                (Cow::Borrowed(uncompressed_data.as_ref()), false)
            };

        // Prepend random hash (4 bytes)
        let random_prefix: [u8; RESOURCE_RANDOM_HASH_SIZE] = {
            let rh = get_random_hash(rng);
            let mut buf = [0u8; RESOURCE_RANDOM_HASH_SIZE];
            buf.copy_from_slice(&rh[..RESOURCE_RANDOM_HASH_SIZE]);
            buf
        };
        let mut data_with_random =
            Vec::with_capacity(RESOURCE_RANDOM_HASH_SIZE + working_data.len());
        data_with_random.extend_from_slice(&random_prefix);
        data_with_random.extend_from_slice(&working_data);

        // Encrypt. A tag left to this function is written with the first
        // attempt's map hashes.
        let (mut encrypted_data, mut mac) = match encrypt_fn.encrypt_untagged(&data_with_random) {
            Some((bytes, mac)) => (bytes, Some(mac)),
            None => (encrypt_fn.encrypt(&data_with_random), None),
        };
        let transfer_size = encrypted_data.len();
        if sdu == 0 {
            if let Some(mut mac) = mac.take() {
                let signed = encrypted_data.len() - 32;
                mac.update(&encrypted_data[..signed]);
                let tag = mac.finalize();
                encrypted_data[signed..].copy_from_slice(&tag);
            }
        }

        // Keep trying until no collision in hashmap (max 100 attempts)
        let mut resource_hash;
        let mut truncated_resource_hash;
        let mut expected_proof;
        let mut final_random_hash;
        let mut part_hashes;
        let mut collision_retries = 0;
        const MAX_COLLISION_RETRIES: usize = 100;

        // The data hash is taken with the first attempt's map hashes.
        let mut data_state = None;
        loop {
            final_random_hash = {
                let rh = get_random_hash(rng);
                rh[..RESOURCE_RANDOM_HASH_SIZE].to_vec()
            };

            part_hashes = match (&data_state, sdu) {
                (_, 0) => Vec::new(),
                (None, _) => {
                    let mut state = rns_crypto::sha256::Sha256::new();
                    let hashes = map_hashes_with_data(
                        &mut encrypted_data,
                        sdu,
                        &final_random_hash,
                        &uncompressed_data,
                        &mut state,
                        mac.take(),
                    );
                    data_state = Some(state);
                    hashes
                }
                (Some(_), _) => encrypted_data
                    .chunks(sdu)
                    .map(|part| map_hash(part, &final_random_hash))
                    .collect(),
            };
            let state = data_state.get_or_insert_with(|| data_hash_state(&uncompressed_data));

            resource_hash = finish_with(state, &final_random_hash);
            truncated_resource_hash = {
                let mut t = [0u8; 16];
                t.copy_from_slice(&resource_hash[..16]);
                t
            };
            expected_proof = finish_with(state, &resource_hash);

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
        let total_parts = part_hashes.len();

        let orig_hash = original_hash.unwrap_or(resource_hash);

        let flags = AdvFlags {
            encrypted: true,
            compressed,
            split: total_segments > 1,
            is_request: request_id.is_some() && !is_response,
            is_response: request_id.is_some() && is_response,
            has_metadata,
            app_flag: false,
        };

        Ok(ResourceSender {
            status: ResourceStatus::Queued,
            resource_hash,
            truncated_hash: truncated_resource_hash,
            expected_proof,
            original_hash: orig_hash,
            random_hash: final_random_hash,
            sdu,
            // Discard spare encryption capacity rather than retaining it per transfer.
            parts: if sdu == 0 {
                Box::default()
            } else {
                encrypted_data.into_boxed_slice()
            },
            part_sdu: sdu.max(1),
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
            advertisement_mdu: LINK_MDU,
        })
    }

    /// Generate the advertisement for the given hashmap segment.
    pub fn get_advertisement(&self, segment: usize) -> Vec<u8> {
        AdvertisementFields {
            transfer_size: self.transfer_size as u64,
            data_size: self.data_size as u64,
            num_parts: self.total_parts as u64,
            resource_hash: &self.resource_hash,
            random_hash: &self.random_hash,
            original_hash: &self.original_hash,
            hashmap: &self.hashmap,
            flags: self.flags,
            segment_index: self.segment_index,
            total_segments: self.total_segments,
            request_id: self.request_id.as_deref(),
        }
        .pack_for_mdu(segment, self.advertisement_mdu)
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
        let mut actions = Vec::new();
        self.handle_request_into(request_data, now, &mut actions);
        actions
    }

    /// [`Self::handle_request`], appending the actions to `out`.
    pub fn handle_request_into(
        &mut self,
        request_data: &[u8],
        now: f64,
        out: &mut Vec<ResourceAction>,
    ) {
        let mut parts = Vec::new();
        let start = out.len();
        self.handle_request_parts_into(request_data, now, &mut parts, out);
        // The parts go out before anything else the request produced.
        out.splice(
            start..start,
            parts
                .iter()
                .map(|&(index, _)| ResourceAction::SendPart(self.part(index).to_vec())),
        );
    }

    /// [`Self::handle_request_into`] without copying the requested parts:
    /// their indices are appended to `parts` in sending order, each standing
    /// for a [`ResourceAction::SendPart`] of [`Self::part_data`] that comes
    /// before the actions appended to `out`. With each index goes whether
    /// that part was sent before: upstream's `Resource.request` sends a
    /// part with `part.send()` the first time and `part.resend()` after,
    /// and only the first counts toward the link's traffic (01ffb98e
    /// `Transport.link_txb`).
    pub fn handle_request_parts_into(
        &mut self,
        request_data: &[u8],
        now: f64,
        parts: &mut Vec<(usize, bool)>,
        out: &mut Vec<ResourceAction>,
    ) {
        if self.status == ResourceStatus::Failed {
            return;
        }

        let hashmap_is_empty = request_data.first() == Some(&RESOURCE_HASHMAP_IS_EMPTY);
        let hashmap_is_exhausted = request_data.first() == Some(&RESOURCE_HASHMAP_IS_EXHAUSTED);
        let wants_more_hashmap = hashmap_is_empty || hashmap_is_exhausted;
        let pad = if hashmap_is_exhausted {
            1 + RESOURCE_MAPHASH_LEN
        } else {
            1
        };

        if request_data.len() < pad + 32 || request_data[pad..pad + 32] != self.resource_hash {
            return;
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

        // Requested map hashes, read in place.
        let map_hashes_requested = request_data[pad + 32..].chunks_exact(RESOURCE_MAPHASH_LEN);

        // Search for requested parts within guard window
        let search_start = self.receiver_min_consecutive_height;
        let search_end = core::cmp::min(
            search_start + RESOURCE_COLLISION_GUARD_SIZE,
            self.total_parts,
        );

        for part_idx in search_start..search_end {
            if map_hashes_requested
                .clone()
                .any(|h| h == self.part_hashes[part_idx].as_slice())
            {
                parts.push((part_idx, self.sent_indices[part_idx]));
                if !self.sent_indices[part_idx] {
                    self.sent_indices[part_idx] = true;
                    self.sent_parts += 1;
                }
                self.last_part_sent = now;
            }
        }

        // Handle hashmap exhaustion
        if wants_more_hashmap {
            match self.build_hmu(request_data, hashmap_is_empty, now) {
                Ok(hmu) => out.push(ResourceAction::SendHmu(hmu)),
                Err(_) => {
                    out.extend(self.cancel());
                    return;
                }
            }
        }

        // Check if all parts sent
        if self.sent_parts >= self.total_parts {
            self.status = ResourceStatus::AwaitingProof;
            self.retries_left = 3; // hardcoded in Python
        }
    }

    /// Build hashmap update data.
    ///
    /// For an exhausted hashmap the request names the last map hash the
    /// receiver holds; for an empty one (an advertisement sent without its
    /// hashmap) it names none and the update starts at the receiver's
    /// consecutive height, as in Python.
    fn build_hmu(
        &mut self,
        request_data: &[u8],
        hashmap_is_empty: bool,
        now: f64,
    ) -> Result<Vec<u8>, ResourceError> {
        let mut part_index = self.receiver_min_consecutive_height;
        if !hashmap_is_empty {
            if request_data.len() < 1 + RESOURCE_MAPHASH_LEN {
                return Err(ResourceError::InvalidState);
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

            for idx in search_start..search_end {
                part_index = idx + 1;
                if self.part_hashes[idx] == last_map_hash {
                    break;
                }
            }
        }

        // Update receiver min consecutive height
        self.receiver_min_consecutive_height = if part_index > RESOURCE_WINDOW_MAX {
            part_index - 1 - RESOURCE_WINDOW_MAX
        } else {
            0
        };

        // Verify alignment
        if !hashmap_is_empty && !part_index.is_multiple_of(RESOURCE_HASHMAP_MAX_LEN) {
            return Err(ResourceError::InvalidState);
        }

        let segment = part_index / RESOURCE_HASHMAP_MAX_LEN;
        let hashmap_start = segment * RESOURCE_HASHMAP_MAX_LEN;
        let hashmap_end =
            core::cmp::min((segment + 1) * RESOURCE_HASHMAP_MAX_LEN, self.total_parts);

        let mut hashmap_segment = Vec::new();
        for i in hashmap_start..hashmap_end {
            hashmap_segment.extend_from_slice(
                &self.hashmap[i * RESOURCE_MAPHASH_LEN..(i + 1) * RESOURCE_MAPHASH_LEN],
            );
        }

        if hashmap_segment.is_empty() {
            return Err(ResourceError::InvalidState);
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
        Ok(hmu)
    }

    /// Handle proof from receiver.
    ///
    /// As upstream's `validate_proof`, a proof that does not match the
    /// expected one is ignored: the sender keeps waiting for a valid proof
    /// and, failing that, times out as [`Self::tick`] decides.
    pub fn handle_proof(&mut self, proof_data: &[u8], _now: f64) -> Vec<ResourceAction> {
        if self.status == ResourceStatus::Failed {
            return vec![];
        }

        match validate_proof(proof_data, &self.resource_hash, &self.expected_proof) {
            Ok(true) => {
                self.status = ResourceStatus::Complete;
                vec![ResourceAction::Completed]
            }
            Ok(false) | Err(_) => vec![],
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
            vec![ResourceAction::SendCancelInitiator(
                self.resource_hash.to_vec(),
            )]
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
                        return self.time_out();
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
                    return self.time_out();
                }
            }
            ResourceStatus::AwaitingProof => {
                let rtt = self.rtt.unwrap_or(1.0);
                let timeout = self.last_part_sent
                    + rtt * RESOURCE_PROOF_TIMEOUT_FACTOR
                    + self.sender_grace_time;
                if now > timeout {
                    if self.retries_left == 0 {
                        return self.time_out();
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

    /// Give up on a timeout as upstream does, by cancelling: the receiver
    /// is told with RESOURCE_ICL.
    fn time_out(&mut self) -> Vec<ResourceAction> {
        let mut actions = self.cancel();
        actions.push(ResourceAction::Failed(ResourceError::Timeout));
        actions
    }

    /// The bytes of part `index` as sent, or `None` past the last part.
    pub fn part_data(&self, index: usize) -> Option<&[u8]> {
        (index < self.total_parts).then(|| self.part(index))
    }

    fn part(&self, index: usize) -> &[u8] {
        let start = index * self.part_sdu;
        &self.parts[start..start + self.part_sdu.min(self.parts.len() - start)]
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
    use crate::resource::proof::{compute_expected_proof, compute_resource_hash};

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

    fn varying_data(len: usize) -> Vec<u8> {
        let mut state = 0x1234_5678u32;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 16) as u8
            })
            .collect()
    }

    #[test]
    fn preparation_wire_transcript_matches_owned_buffer_baseline() {
        // Exercise absent/empty metadata and compression skipped, unavailable,
        // equal-sized, larger, or accepted. The synthetic codec isolates buffer
        // selection; full codec round trips are covered separately.
        struct Codec(u8);
        impl Compressor for Codec {
            fn compress(&self, data: &[u8]) -> Option<Vec<u8>> {
                match self.0 {
                    0 | 1 => None,
                    2 => Some(data.to_vec()),
                    3 => Some([data, &[0]].concat()),
                    _ => Some(data[..data.len() / 2].to_vec()),
                }
            }
            fn decompress_bounded(
                &self,
                _: &[u8],
                _: usize,
            ) -> Result<Vec<u8>, crate::buffer::types::DecompressError> {
                unreachable!("sender-only transcript")
            }
        }
        let mut transcript = Vec::new();
        for len in [0, 1, 1000] {
            let data = varying_data(len);
            for metadata in [None, Some(&b""[..]), Some(&b"metadata"[..])] {
                for mode in 0..5 {
                    for response in [false, true] {
                        let mut rng = rns_crypto::FixedRng::new(&[0x42; 64]);
                        let mut sender = ResourceSender::new(
                            &data,
                            metadata,
                            RESOURCE_SDU,
                            &identity_encrypt,
                            &Codec(mode),
                            &mut rng,
                            1000.0,
                            mode != 0,
                            response,
                            Some(vec![0xAB; 16]),
                            2,
                            3,
                            Some([0xCD; 32]),
                            0.5,
                            6.0,
                        )
                        .unwrap();
                        transcript.extend_from_slice(&sender.resource_hash);
                        transcript.extend_from_slice(&sender.expected_proof);
                        transcript.extend_from_slice(&(sender.data_size as u64).to_be_bytes());
                        for action in sender.advertise(1000.0) {
                            if let ResourceAction::SendAdvertisement(raw) = action {
                                transcript.extend_from_slice(&(raw.len() as u64).to_be_bytes());
                                transcript.extend_from_slice(&raw);
                            } else {
                                panic!("expected advertisement");
                            }
                        }
                        for part in sender.parts.chunks(sender.part_sdu) {
                            transcript.extend_from_slice(&(part.len() as u64).to_be_bytes());
                            transcript.extend_from_slice(part);
                        }
                    }
                }
            }
        }
        // Recorded from the original preparation code before borrowing buffers.
        assert_eq!(
            crate::hash::full_hash(&transcript),
            [
                67, 44, 221, 45, 186, 73, 169, 206, 206, 134, 142, 225, 182, 205, 22, 233, 153,
                131, 88, 228, 84, 36, 149, 65, 72, 213, 69, 130, 12, 198, 159, 159
            ]
        );
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
        let has_part = actions
            .iter()
            .any(|a| matches!(a, ResourceAction::SendPart(_)));
        assert!(has_part);
    }

    #[test]
    fn requested_parts_and_retries_preserve_original_partition() {
        for len in [
            0,
            1,
            RESOURCE_SDU - 4,
            RESOURCE_SDU - 3,
            RESOURCE_SDU * 3 + 17,
        ] {
            let data = varying_data(len);
            let mut sender = make_sender(&data);
            // FixedRng and identity encryption leave the original bytes visible.
            let mut encrypted = vec![0; RESOURCE_RANDOM_HASH_SIZE];
            // The random prefix is a hash of RNG output, not raw RNG bytes.
            encrypted[..RESOURCE_RANDOM_HASH_SIZE]
                .copy_from_slice(&crate::hash::full_hash(&[0x42; 16])[..RESOURCE_RANDOM_HASH_SIZE]);
            encrypted.extend_from_slice(&data);
            let expected: Vec<Vec<u8>> =
                encrypted.chunks(RESOURCE_SDU).map(<[u8]>::to_vec).collect();
            sender.advertise(1000.0);
            let mut request = vec![RESOURCE_HASHMAP_IS_NOT_EXHAUSTED];
            request.extend_from_slice(&sender.resource_hash);
            for hash in &sender.part_hashes {
                request.extend_from_slice(hash);
            }
            // Public SDU changes must not repartition a transfer already prepared.
            sender.sdu = 1;
            for now in [1001.0, 1002.0] {
                let parts: Vec<Vec<u8>> = sender
                    .handle_request(&request, now)
                    .into_iter()
                    .filter_map(|action| match action {
                        ResourceAction::SendPart(part) => Some(part),
                        _ => None,
                    })
                    .collect();
                assert_eq!(parts, expected);
                assert_eq!(sender.sent_parts, expected.len());
            }
        }
    }

    #[test]
    fn requested_parts_say_whether_they_were_sent_before() {
        // upstream's Resource.request: part.send() the first time a part is
        // requested, part.resend() after.
        let data = varying_data(RESOURCE_SDU * 2 + 5);
        let mut sender = make_sender(&data);
        sender.advertise(1000.0);
        let request = |hashes: &[[u8; RESOURCE_MAPHASH_LEN]], sender: &ResourceSender| {
            let mut request = vec![RESOURCE_HASHMAP_IS_NOT_EXHAUSTED];
            request.extend_from_slice(&sender.resource_hash);
            for hash in hashes {
                request.extend_from_slice(hash);
            }
            request
        };
        let hashes = sender.part_hashes.clone();
        let mut ask = |hashes: Vec<[u8; RESOURCE_MAPHASH_LEN]>, now: f64| {
            let request = request(&hashes, &sender);
            let (mut parts, mut out) = (Vec::new(), Vec::new());
            sender.handle_request_parts_into(&request, now, &mut parts, &mut out);
            parts
        };
        assert_eq!(ask(vec![hashes[0]], 1001.0), [(0, false)]);
        assert_eq!(
            ask(hashes.clone(), 1002.0),
            [(0, true), (1, false), (2, false)]
        );
        assert_eq!(ask(hashes, 1003.0), [(0, true), (1, true), (2, true)]);
    }

    #[test]
    fn test_request_for_another_resource_is_ignored_without_mutating_sender() {
        let mut sender = make_sender(b"short");
        sender.advertise(1000.0);
        let status = sender.status;
        let last_activity = sender.last_activity;
        let retries_left = sender.retries_left;
        let mut request = Vec::new();
        request.push(RESOURCE_HASHMAP_IS_NOT_EXHAUSTED);
        request.extend_from_slice(&[0xEE; 32]);
        request.extend_from_slice(&sender.part_hashes[0]);

        let actions = sender.handle_request(&request, 2000.0);

        assert!(actions.is_empty());
        assert_eq!(sender.status, status);
        assert_eq!(sender.last_activity, last_activity);
        assert_eq!(sender.retries_left, retries_left);
        assert_eq!(sender.sent_parts, 0);
    }

    fn exhausted_request(
        sender: &ResourceSender,
        last_map_hash: [u8; RESOURCE_MAPHASH_LEN],
    ) -> Vec<u8> {
        let mut request = Vec::new();
        request.push(RESOURCE_HASHMAP_IS_EXHAUSTED);
        request.extend_from_slice(&last_map_hash);
        request.extend_from_slice(&sender.resource_hash);
        request
    }

    #[test]
    fn test_empty_hmu_generation_cancels_sender() {
        let data =
            varying_data(RESOURCE_HASHMAP_MAX_LEN * RESOURCE_SDU - RESOURCE_RANDOM_HASH_SIZE);
        let mut sender = make_sender(&data);
        assert_eq!(sender.total_parts(), RESOURCE_HASHMAP_MAX_LEN);
        sender.advertise(1000.0);
        let request = exhausted_request(&sender, sender.part_hashes[RESOURCE_HASHMAP_MAX_LEN - 1]);

        let actions = sender.handle_request(&request, 1001.0);

        assert_eq!(sender.status, ResourceStatus::Failed);
        assert!(actions
            .iter()
            .any(|action| matches!(action, ResourceAction::SendCancelInitiator(_))));
        assert!(!actions
            .iter()
            .any(|action| matches!(action, ResourceAction::SendHmu(_))));
    }

    #[test]
    fn test_misaligned_hmu_request_cancels_sender() {
        let data = varying_data((RESOURCE_HASHMAP_MAX_LEN + 2) * RESOURCE_SDU);
        let mut sender = make_sender(&data);
        sender.advertise(1000.0);
        let request = exhausted_request(&sender, sender.part_hashes[5]);

        let actions = sender.handle_request(&request, 1001.0);

        assert_eq!(sender.status, ResourceStatus::Failed);
        assert!(actions
            .iter()
            .any(|action| matches!(action, ResourceAction::SendCancelInitiator(_))));
        assert!(!actions
            .iter()
            .any(|action| matches!(action, ResourceAction::SendHmu(_))));
    }

    #[test]
    fn test_valid_nonempty_hmu_is_emitted() {
        let data = varying_data((RESOURCE_HASHMAP_MAX_LEN + 2) * RESOURCE_SDU);
        let mut sender = make_sender(&data);
        sender.advertise(1000.0);
        let request = exhausted_request(&sender, sender.part_hashes[RESOURCE_HASHMAP_MAX_LEN - 1]);

        let actions = sender.handle_request(&request, 1001.0);

        assert_ne!(sender.status, ResourceStatus::Failed);
        let hmu = actions
            .iter()
            .find_map(|action| match action {
                ResourceAction::SendHmu(data) => Some(data),
                _ => None,
            })
            .expect("valid exhausted request should produce an HMU");
        let (value, consumed) = crate::msgpack::unpack(&hmu[32..]).unwrap();
        assert_eq!(consumed, hmu.len() - 32);
        let array = value.as_array().unwrap();
        assert_eq!(array[0].as_uint(), Some(1));
        assert_eq!(
            array[1].as_bin().map(<[u8]>::len),
            Some((sender.total_parts() - RESOURCE_HASHMAP_MAX_LEN) * RESOURCE_MAPHASH_LEN)
        );
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

        let proof_data =
            super::super::proof::build_proof_data(&sender.resource_hash, &sender.expected_proof);
        let actions = sender.handle_proof(&proof_data, 1002.0);
        assert_eq!(sender.status, ResourceStatus::Complete);
        assert!(actions
            .iter()
            .any(|a| matches!(a, ResourceAction::Completed)));
    }

    #[test]
    fn invalid_proof_is_ignored_and_the_proof_wait_times_out() {
        let mut sender = make_sender(b"hi");
        sender.advertise(1000.0);
        let total = sender.total_parts();
        sender.handle_request(&request_for(&sender, 0..total), 1000.5);
        assert_eq!(sender.status, ResourceStatus::AwaitingProof);

        // Upstream ignores a proof that does not match, or is malformed.
        let wrong = super::super::proof::build_proof_data(&sender.resource_hash, &[0xFF; 32]);
        for proof in [&wrong[..], &wrong[..40]] {
            assert!(sender.handle_proof(proof, 1001.0).is_empty());
            assert_eq!(sender.status, ResourceStatus::AwaitingProof);
            assert_eq!(sender.retries_left, 3);
        }

        // A valid proof still completes it.
        let mut completing = make_sender(b"hi");
        completing.advertise(1000.0);
        completing.handle_request(&request_for(&completing, 0..total), 1000.5);
        completing.handle_proof(&wrong, 1001.0);
        let valid = super::super::proof::build_proof_data(
            &completing.resource_hash,
            &completing.expected_proof,
        );
        assert_eq!(
            completing.handle_proof(&valid, 1001.5),
            vec![ResourceAction::Completed]
        );

        // Otherwise the proof wait retries three times and then cancels.
        let deadline = 1000.5 + 0.5 * RESOURCE_PROOF_TIMEOUT_FACTOR + RESOURCE_SENDER_GRACE_TIME;
        let mut now = deadline;
        for retries_left in (0..3).rev() {
            now += 1e-3;
            assert!(sender.tick(now).is_empty());
            assert_eq!(sender.retries_left, retries_left);
            now += 0.5 * RESOURCE_PROOF_TIMEOUT_FACTOR + RESOURCE_SENDER_GRACE_TIME;
        }
        assert_eq!(
            sender.tick(now + 1e-3),
            vec![
                ResourceAction::SendCancelInitiator(sender.resource_hash.to_vec()),
                ResourceAction::Failed(ResourceError::Timeout)
            ]
        );
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
        assert!(actions
            .iter()
            .any(|a| matches!(a, ResourceAction::SendCancelInitiator(_))));
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

        // Way past timeout: upstream cancels, telling the receiver.
        let actions = sender.tick(2000.0);
        assert_eq!(sender.status, ResourceStatus::Failed);
        assert_eq!(
            actions,
            vec![
                ResourceAction::SendCancelInitiator(sender.resource_hash.to_vec()),
                ResourceAction::Failed(ResourceError::Timeout)
            ]
        );
    }

    #[test]
    fn test_tick_advertised_retry() {
        let mut sender = make_sender(b"data");
        sender.advertise(1000.0);
        assert!(sender.retries_left > 0);

        let actions = sender.tick(2000.0);
        // Should retry advertisement
        assert!(actions
            .iter()
            .any(|a| matches!(a, ResourceAction::SendAdvertisement(_))));
    }

    #[test]
    fn test_resource_hash_is_32_bytes() {
        let sender = make_sender(b"data");
        assert_eq!(sender.resource_hash.len(), 32);
        assert_eq!(sender.expected_proof.len(), 32);
    }

    #[test]
    fn multipart_resource_identity_uses_complete_original_data() {
        let data = varying_data(RESOURCE_SDU * 3 + 17);
        let sender = make_sender(&data);

        assert!(sender.total_parts() > 1);
        assert_eq!(
            sender.resource_hash,
            compute_resource_hash(&data, &sender.random_hash)
        );
        assert_eq!(
            sender.expected_proof,
            compute_expected_proof(&data, &sender.resource_hash)
        );
        assert_ne!(
            sender.resource_hash,
            compute_resource_hash(sender.part(0), &sender.random_hash)
        );
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

    fn request_for(sender: &ResourceSender, parts: core::ops::Range<usize>) -> Vec<u8> {
        let mut request = vec![RESOURCE_HASHMAP_IS_NOT_EXHAUSTED];
        request.extend_from_slice(&sender.resource_hash);
        for index in parts {
            request.extend_from_slice(&sender.part_hashes[index]);
        }
        request
    }

    #[test]
    fn first_request_measures_rtt_from_the_advertisement() {
        let data = varying_data(3 * RESOURCE_SDU);
        let mut sender = make_sender(&data);
        sender.advertise(1000.0);
        assert_eq!(sender.status, ResourceStatus::Advertised);
        sender.handle_request(&request_for(&sender, 0..1), 1000.5);
        assert_eq!(sender.status, ResourceStatus::Transferring);
        assert_eq!(sender.rtt, Some(0.5));
        // Later requests leave it.
        sender.handle_request(&request_for(&sender, 1..2), 1003.0);
        assert_eq!(sender.rtt, Some(0.5));
    }

    #[test]
    fn part_data_is_each_part_as_sent() {
        let data = varying_data(3 * RESOURCE_SDU);
        let mut sender = make_sender(&data);
        sender.advertise(1000.0);
        let total = sender.total_parts();
        assert!(total > 1);
        let sent: Vec<Vec<u8>> = sender
            .handle_request(&request_for(&sender, 0..total), 1001.0)
            .into_iter()
            .filter_map(|action| match action {
                ResourceAction::SendPart(part) => Some(part),
                _ => None,
            })
            .collect();
        assert_eq!(sent.len(), total);
        for (index, part) in sent.iter().enumerate() {
            assert_eq!(sender.part_data(index), Some(part.as_slice()));
        }
        assert_eq!(sender.part_data(total), None);
    }

    #[test]
    fn hashmap_update_moves_the_receiver_search_window() {
        let data = varying_data((2 * RESOURCE_HASHMAP_MAX_LEN + 10) * RESOURCE_SDU);
        let mut sender = make_sender(&data);
        sender.advertise(1000.0);
        let last = 2 * RESOURCE_HASHMAP_MAX_LEN - 1;
        let request = exhausted_request(&sender, sender.part_hashes[last]);

        let actions = sender.handle_request(&request, 1001.0);

        assert!(actions
            .iter()
            .any(|action| matches!(action, ResourceAction::SendHmu(_))));
        // Upstream: max(part_index - 1 - WINDOW_MAX, 0), part_index being
        // one past the last map hash the receiver holds.
        assert_eq!(
            sender.receiver_min_consecutive_height,
            last + 1 - 1 - RESOURCE_WINDOW_MAX
        );
    }

    #[test]
    fn hashmap_update_near_the_start_keeps_the_search_at_the_start() {
        let data = varying_data((2 * RESOURCE_HASHMAP_MAX_LEN + 10) * RESOURCE_SDU);
        let mut sender = make_sender(&data);
        sender.advertise(1000.0);
        // The last held map hash ends exactly WINDOW_MAX parts in, which is
        // not a hashmap segment boundary.
        let request = exhausted_request(&sender, sender.part_hashes[RESOURCE_WINDOW_MAX - 1]);

        let actions = sender.handle_request(&request, 1001.0);

        assert_eq!(sender.receiver_min_consecutive_height, 0);
        assert!(actions
            .iter()
            .any(|action| matches!(action, ResourceAction::SendCancelInitiator(_))));
    }

    #[test]
    fn advertisement_is_resent_strictly_after_its_timeout() {
        let advertised = || {
            let mut sender = make_sender(b"data");
            sender.advertise(1000.0);
            sender
        };
        let deadline = 1000.0 + 0.5 * 6.0 + RESOURCE_PROCESSING_GRACE;
        let mut sender = advertised();
        assert!(sender.tick(deadline).is_empty());
        let retries = sender.retries_left;
        let actions = sender.tick(deadline + 1e-6);
        assert!(matches!(
            actions.as_slice(),
            [ResourceAction::SendAdvertisement(_)]
        ));
        assert_eq!(sender.retries_left, retries - 1);
        assert_eq!(sender.adv_sent, deadline + 1e-6);
    }

    #[test]
    fn transferring_sender_gives_up_strictly_after_the_longest_wait() {
        let data = varying_data(3 * RESOURCE_SDU);
        let transferring = || {
            let mut sender = make_sender(&data);
            sender.advertise(1000.0);
            sender.handle_request(&request_for(&sender, 0..1), 1000.5);
            assert_eq!(sender.status, ResourceStatus::Transferring);
            sender
        };
        // Upstream: rtt * timeout factor * retries, the sender's grace time,
        // and the delay each retry adds.
        let max_extra_wait: f64 = (1..=RESOURCE_MAX_RETRIES)
            .map(|r| r as f64 * RESOURCE_PER_RETRY_DELAY)
            .sum();
        let deadline = 1000.5
            + (0.5 * 6.0 * RESOURCE_MAX_RETRIES as f64
                + RESOURCE_SENDER_GRACE_TIME
                + max_extra_wait);
        assert!(transferring().tick(deadline).is_empty());
        let mut sender = transferring();
        assert_eq!(
            sender.tick(deadline + 1e-6),
            vec![
                ResourceAction::SendCancelInitiator(sender.resource_hash.to_vec()),
                ResourceAction::Failed(ResourceError::Timeout)
            ]
        );
        assert_eq!(sender.status, ResourceStatus::Failed);
    }

    #[test]
    fn sender_awaiting_proof_retries_strictly_after_its_timeout() {
        let mut sender = make_sender(b"hi");
        sender.advertise(1000.0);
        let total = sender.total_parts();
        sender.handle_request(&request_for(&sender, 0..total), 1000.5);
        assert_eq!(sender.status, ResourceStatus::AwaitingProof);
        assert_eq!(sender.retries_left, 3);

        let deadline = 1000.5 + 0.5 * RESOURCE_PROOF_TIMEOUT_FACTOR + RESOURCE_SENDER_GRACE_TIME;
        assert!(sender.tick(deadline).is_empty());
        assert_eq!(sender.retries_left, 3);
        assert!(sender.tick(deadline + 1e-6).is_empty());
        assert_eq!(sender.retries_left, 2);
        assert_eq!(sender.status, ResourceStatus::AwaitingProof);
        assert_eq!(sender.last_part_sent, deadline + 1e-6);

        sender.retries_left = 0;
        assert_eq!(
            sender.tick(deadline + 100.0),
            vec![
                ResourceAction::SendCancelInitiator(sender.resource_hash.to_vec()),
                ResourceAction::Failed(ResourceError::Timeout)
            ]
        );
        assert_eq!(sender.status, ResourceStatus::Failed);
    }
}
