//! Owned, authenticated Resource data that can be verified away from its receiver.
use super::{
    parts::extract_metadata_owned,
    proof::{build_proof_data, data_hash_state, finish_with},
    ResourceAction, ResourceError,
};
use crate::{
    buffer::types::{Compressor, DecompressError},
    constants::RESOURCE_RANDOM_HASH_SIZE,
};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use rns_crypto::sha256::Sha256;

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
fn decompress_error(error: DecompressError) -> ResourceError {
    match error {
        DecompressError::TooLarge => ResourceError::TooLarge,
        DecompressError::InvalidData => ResourceError::DecompressionFailed,
    }
}

impl ResourceAssembly {
    pub fn id(&self) -> &AssemblyId {
        &self.id
    }
    /// Whether the data is compressed and must be decompressed to assemble.
    pub fn is_compressed(&self) -> bool {
        self.data.compressed
    }
    /// Take the authenticated data still to be decompressed, for a caller
    /// that decompresses it in pieces and then calls
    /// [`Self::finish_decompressed`] or [`Self::decompression_failed`].
    pub fn take_compressed_data(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.data.plaintext)
    }
    /// [`Self::run`] for data the caller decompressed itself, within
    /// [`Self::max_output_size`]; `data_state`, when given, is SHA-256 over
    /// `decompressed`.
    pub fn finish_decompressed(
        self,
        decompressed: Vec<u8>,
        data_state: Option<Sha256>,
    ) -> AssemblyResult {
        AssemblyResult {
            id: self.id,
            result: self.data.finish(decompressed, data_state),
        }
    }
    /// The result of an assembly whose decompression failed: `too_large`
    /// when the output exceeded [`Self::max_output_size`].
    pub fn decompression_failed(self, too_large: bool) -> AssemblyResult {
        AssemblyResult {
            id: self.id,
            result: Err(decompress_error(if too_large {
                DecompressError::TooLarge
            } else {
                DecompressError::InvalidData
            })),
        }
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
    /// SHA-256 over `plaintext`, when it was hashed as it was decrypted.
    pub data_state: Option<Box<Sha256>>,
    pub random_hash: [u8; RESOURCE_RANDOM_HASH_SIZE],
    pub resource_hash: [u8; 32],
    pub compressed: bool,
    pub metadata: bool,
    pub app_flag: bool,
    pub limit: usize,
}
impl AssemblyData {
    pub fn run(
        mut self,
        compressor: &dyn Compressor,
    ) -> Result<Vec<ResourceAction>, ResourceError> {
        // The receiver already dropped the random prefix.
        let plaintext = core::mem::take(&mut self.plaintext);
        let (decompressed, data_state) = if self.compressed {
            let decompressed = compressor
                .decompress_bounded(&plaintext, self.limit)
                .map_err(decompress_error)?;
            (decompressed, None)
        } else {
            (plaintext, self.data_state.take().map(|state| *state))
        };
        self.finish(decompressed, data_state)
    }

    /// Check `decompressed` against the resource hash and build the proof and
    /// delivery. `data_state`, when given, is SHA-256 over `decompressed`.
    fn finish(
        self,
        decompressed: Vec<u8>,
        data_state: Option<Sha256>,
    ) -> Result<Vec<ResourceAction>, ResourceError> {
        let data_state = data_state.unwrap_or_else(|| data_hash_state(&decompressed));
        let hash = finish_with(&data_state, &self.random_hash);
        if hash != self.resource_hash {
            return Err(ResourceError::HashMismatch);
        }
        // Proof covers the complete data, including its metadata prefix.
        let proof = build_proof_data(&hash, &finish_with(&data_state, &hash));
        let (data, metadata) = if self.metadata {
            let (metadata, data) =
                extract_metadata_owned(decompressed).ok_or(ResourceError::InvalidPart)?;
            (data, Some(metadata))
        } else {
            (decompressed, None)
        };
        Ok(vec![
            ResourceAction::SendProof(proof),
            ResourceAction::DataReceived {
                data,
                metadata,
                app_flag: self.app_flag,
            },
            ResourceAction::Completed,
        ])
    }
}
