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

    const INTEROP_PLAINTEXT: &[u8] =
        b"Reticulum resource compression interoperability vector\x00\xff";
    const INTEROP_BZIP2_HEX: &str = concat!(
        "425a6836314159265359116659ff000002d380c000400010003a27df200000a000",
        "50a6134d01a62113d413c088d94d9bbcd69421c457d265cbfab3d6a2a2bc0653",
        "d74711b78f01487710a8f5f8bb9229c284808b32cff8",
    );

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(pair, 16).unwrap()
            })
            .collect()
    }

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

    #[test]
    fn bzip2_matches_reference_libbz2_wire_vector() {
        let compressor = Bzip2Compressor;
        let reference = decode_hex(INTEROP_BZIP2_HEX);

        assert_eq!(compressor.compress(INTEROP_PLAINTEXT).unwrap(), reference);
        assert_eq!(
            compressor.decompress(&reference).unwrap(),
            INTEROP_PLAINTEXT
        );
    }

    #[test]
    fn bzip2_empty_payload_respects_zero_limit() {
        let compressor = Bzip2Compressor;
        let compressed = compressor.compress(b"").unwrap();

        assert_eq!(compressed, decode_hex("425a683617724538509000000000"));
        assert_eq!(
            compressor.decompress_bounded(&compressed, 0),
            Ok(Vec::new())
        );
    }

    #[test]
    fn bzip2_nonempty_payload_exceeds_zero_limit() {
        let compressor = Bzip2Compressor;
        let compressed = compressor.compress(b"x").unwrap();

        assert_eq!(
            compressor.decompress_bounded(&compressed, 0),
            Err(DecompressError::TooLarge)
        );
    }

    #[test]
    fn bzip2_rejects_invalid_header_truncation_and_checksum_corruption() {
        let compressor = Bzip2Compressor;
        let compressed = compressor.compress(INTEROP_PLAINTEXT).unwrap();

        assert_eq!(
            compressor.decompress_bounded(b"not a bzip2 stream", 1024),
            Err(DecompressError::InvalidData)
        );
        assert_eq!(
            compressor.decompress_bounded(&compressed[..compressed.len() - 5], 1024),
            Err(DecompressError::InvalidData)
        );

        let mut corrupted = compressed;
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0x80;
        assert_eq!(
            compressor.decompress_bounded(&corrupted, 1024),
            Err(DecompressError::InvalidData)
        );
    }

    #[test]
    fn bzip2_roundtrips_across_multiple_compression_blocks() {
        let compressor = Bzip2Compressor;
        let input: Vec<u8> = (0..1_100_000usize)
            .map(|i| ((i.wrapping_mul(31) + i / 251) & 0xff) as u8)
            .collect();
        let compressed = compressor.compress(&input).unwrap();

        assert_eq!(
            compressor.decompress_bounded(&compressed, input.len()),
            Ok(input)
        );
    }

    #[test]
    fn bzip2_roundtrips_maximum_resource_segment_with_periodic_data() {
        let compressor = Bzip2Compressor;
        let input: Vec<u8> = (0..rns_core::constants::RESOURCE_MAX_EFFICIENT_SIZE)
            .map(|index| (index % 251) as u8)
            .collect();
        let compressed = compressor.compress(&input).unwrap();

        assert_eq!(
            compressor.decompress_bounded(&compressed, input.len()),
            Ok(input)
        );
    }
}
