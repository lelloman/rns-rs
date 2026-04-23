use alloc::vec::Vec;
use core::fmt;

pub type StreamId = u16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompressError {
    InvalidData,
    TooLarge,
}

/// Compression trait for buffer operations (`no_std` compatible).
pub trait Compressor {
    fn compress(&self, data: &[u8]) -> Option<Vec<u8>>;
    fn decompress(&self, data: &[u8]) -> Option<Vec<u8>> {
        self.decompress_bounded(data, usize::MAX).ok()
    }
    fn decompress_bounded(
        &self,
        data: &[u8],
        max_output_size: usize,
    ) -> Result<Vec<u8>, DecompressError>;
}

/// No-op compressor (default for `no_std`).
pub struct NoopCompressor;

impl Compressor for NoopCompressor {
    fn compress(&self, _data: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn decompress(&self, _data: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn decompress_bounded(
        &self,
        _data: &[u8],
        _max_output_size: usize,
    ) -> Result<Vec<u8>, DecompressError> {
        Err(DecompressError::InvalidData)
    }
}

/// Errors in buffer operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BufferError {
    InvalidStreamId,
    InvalidData,
    DecompressionFailed,
}

impl fmt::Display for BufferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BufferError::InvalidStreamId => write!(f, "Invalid stream ID"),
            BufferError::InvalidData => write!(f, "Invalid stream data"),
            BufferError::DecompressionFailed => write!(f, "Decompression failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_compressor() {
        let c = NoopCompressor;
        assert!(c.compress(b"test").is_none());
        assert!(c.decompress(b"test").is_none());
        assert_eq!(
            c.decompress_bounded(b"test", 8),
            Err(DecompressError::InvalidData)
        );
    }
}
