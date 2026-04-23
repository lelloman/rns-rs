use rns_core::buffer::types::{Compressor, DecompressError};

pub struct Bzip2Compressor;

impl Compressor for Bzip2Compressor {
    fn compress(&self, data: &[u8]) -> Option<Vec<u8>> {
        use bzip2::read::BzEncoder;
        use bzip2::Compression;
        use std::io::Read;
        let mut encoder = BzEncoder::new(data, Compression::default());
        let mut compressed = Vec::new();
        encoder.read_to_end(&mut compressed).ok()?;
        Some(compressed)
    }

    fn decompress(&self, data: &[u8]) -> Option<Vec<u8>> {
        self.decompress_bounded(data, usize::MAX).ok()
    }

    fn decompress_bounded(
        &self,
        data: &[u8],
        max_output_size: usize,
    ) -> Result<Vec<u8>, DecompressError> {
        use bzip2::read::BzDecoder;
        use std::io::Read;
        let mut decoder = BzDecoder::new(data);
        let mut decompressed = Vec::new();
        let mut buf = [0u8; 8192];

        loop {
            let remaining = max_output_size.saturating_sub(decompressed.len());
            if remaining == 0 {
                let mut extra = [0u8; 1];
                return match decoder.read(&mut extra) {
                    Ok(0) => Ok(decompressed),
                    Ok(_) => Err(DecompressError::TooLarge),
                    Err(_) => Err(DecompressError::InvalidData),
                };
            }

            let read_len = remaining.min(buf.len());
            match decoder.read(&mut buf[..read_len]) {
                Ok(0) => return Ok(decompressed),
                Ok(n) => decompressed.extend_from_slice(&buf[..n]),
                Err(_) => return Err(DecompressError::InvalidData),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bzip2_bounded_roundtrip_within_limit() {
        let compressor = Bzip2Compressor;
        let input = b"hello hello hello hello";
        let compressed = compressor.compress(input).unwrap();
        let decompressed = compressor
            .decompress_bounded(&compressed, input.len())
            .unwrap();
        assert_eq!(decompressed, input);
    }

    #[test]
    fn bzip2_bounded_rejects_oversized_output() {
        let compressor = Bzip2Compressor;
        let input = vec![b'A'; 4096];
        let compressed = compressor.compress(&input).unwrap();
        assert_eq!(
            compressor.decompress_bounded(&compressed, 64),
            Err(DecompressError::TooLarge)
        );
    }
}
