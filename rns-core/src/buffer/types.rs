use alloc::vec::Vec;
use core::fmt;

/// Buffer stream identifier; 14 bits are carried on the wire.
pub type StreamId = u16;

/// Errors from bounded decompression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompressError {
    /// Input is not valid compressed data, or decompression is unavailable.
    InvalidData,
    /// Output would exceed the size limit.
    TooLarge,
}

/// Compression trait for buffer operations (`no_std` compatible).
pub trait Compressor {
    /// Compress `data`; `None` when it cannot be compressed.
    fn compress(&self, data: &[u8]) -> Option<Vec<u8>>;
    /// Decompress `data` without a size limit; `None` on failure.
    fn decompress(&self, data: &[u8]) -> Option<Vec<u8>> {
        self.decompress_bounded(data, usize::MAX).ok()
    }
    /// Decompress `data`, failing with [`DecompressError::TooLarge`] when the
    /// output would exceed `max_output_size` bytes.
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
    /// Invalid stream ID; not produced within this crate.
    InvalidStreamId,
    /// Message is shorter than its header.
    InvalidData,
    /// Compressed data could not be decompressed within the limit.
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

    #[test]
    fn unbounded_decompression_is_bounded_decompression_without_a_limit() {
        struct Doubling;
        impl Compressor for Doubling {
            fn compress(&self, _: &[u8]) -> Option<Vec<u8>> {
                None
            }
            fn decompress_bounded(
                &self,
                data: &[u8],
                max_output_size: usize,
            ) -> Result<Vec<u8>, DecompressError> {
                assert_eq!(max_output_size, usize::MAX);
                Ok([data, data].concat())
            }
        }
        assert_eq!(Doubling.decompress(b"ab"), Some(b"abab".to_vec()));
        assert_eq!(NoopCompressor.decompress(b"ab"), None);
    }

    #[test]
    fn errors_describe_themselves() {
        assert_eq!(
            BufferError::InvalidStreamId.to_string(),
            "Invalid stream ID"
        );
    }
}
