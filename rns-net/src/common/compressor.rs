use rns_core::buffer::types::Compressor;

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
        use bzip2::read::BzDecoder;
        use std::io::Read;
        let mut decoder = BzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).ok()?;
        Some(decompressed)
    }
}
