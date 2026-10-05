//! Owned, authenticated Resource data that can be verified away from its receiver.
use super::{
    parts::extract_metadata_owned,
    proof::{build_proof_data, compute_expected_proof, compute_resource_hash},
    ResourceAction, ResourceError,
};
use crate::{
    buffer::types::{Compressor, DecompressError},
    constants::RESOURCE_RANDOM_HASH_SIZE,
};
use alloc::{sync::Arc, vec, vec::Vec};

/// Identity of one assembly attempt. Equality compares attempts, not Resource hashes.
#[derive(Clone, Debug)]
pub struct AssemblyId(Arc<()>);
impl AssemblyId {
    pub(super) fn new() -> Self {
        Self(Arc::new(()))
    }
}
impl PartialEq for AssemblyId {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for AssemblyId {}

/// A consuming handoff. Authentication has already succeeded when encryption is used.
/// No protocol actions are published until the receiver accepts the returned result.
pub struct ResourceAssembly {
    pub(super) id: AssemblyId,
    pub(super) data: AssemblyData,
}
/// A completed attempt, bound to its original receiver. Contents are deliberately private.
pub struct AssemblyResult {
    pub(super) id: AssemblyId,
    pub(super) result: Result<Vec<ResourceAction>, ResourceError>,
}
impl ResourceAssembly {
    pub fn id(&self) -> &AssemblyId {
        &self.id
    }
    /// Owned plaintext capacity retained while the attempt is queued.
    pub fn input_capacity(&self) -> usize {
        self.data.plaintext.capacity()
    }
    /// Decoder output bound, independent of the advertised data size.
    pub fn max_output_size(&self) -> usize {
        self.data.limit
    }
    pub fn run(self, compressor: &dyn Compressor) -> AssemblyResult {
        AssemblyResult {
            id: self.id,
            result: self.data.run(compressor),
        }
    }
}

pub(super) struct AssemblyData {
    pub plaintext: Vec<u8>,
    pub random_hash: [u8; RESOURCE_RANDOM_HASH_SIZE],
    pub resource_hash: [u8; 32],
    pub compressed: bool,
    pub metadata: bool,
    pub limit: usize,
}
impl AssemblyData {
    pub fn run(self, compressor: &dyn Compressor) -> Result<Vec<ResourceAction>, ResourceError> {
        let mut plaintext = self.plaintext;
        let input = plaintext
            .get(RESOURCE_RANDOM_HASH_SIZE..)
            .ok_or(ResourceError::InvalidPart)?;
        let decompressed = if self.compressed {
            compressor
                .decompress_bounded(input, self.limit)
                .map_err(|error| match error {
                    DecompressError::TooLarge => ResourceError::TooLarge,
                    DecompressError::InvalidData => ResourceError::DecompressionFailed,
                })?
        } else {
            let len = input.len();
            plaintext.copy_within(RESOURCE_RANDOM_HASH_SIZE.., 0);
            plaintext.truncate(len);
            plaintext
        };
        let hash = compute_resource_hash(&decompressed, &self.random_hash);
        if hash != self.resource_hash {
            return Err(ResourceError::HashMismatch);
        }
        // Proof covers the complete data, including its metadata prefix.
        let proof = build_proof_data(&hash, &compute_expected_proof(&decompressed, &hash));
        let (data, metadata) = if self.metadata {
            let (metadata, data) =
                extract_metadata_owned(decompressed).ok_or(ResourceError::InvalidPart)?;
            (data, Some(metadata))
        } else {
            (decompressed, None)
        };
        Ok(vec![
            ResourceAction::SendProof(proof),
            ResourceAction::DataReceived { data, metadata },
            ResourceAction::Completed,
        ])
    }
}
