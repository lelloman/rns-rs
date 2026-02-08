pub mod types;

use alloc::vec::Vec;

use crate::constants::STREAM_DATA_OVERHEAD;
#[cfg(test)]
use crate::constants::STREAM_ID_MAX;

pub use types::{BufferError, Compressor, NoopCompressor, StreamId};

/// Stream data message: 2-byte header + data.
///
/// Header format: `(stream_id & 0x3FFF) | (eof << 15) | (compressed << 14)`
#[derive(Debug, Clone, PartialEq)]
pub struct StreamDataMessage {
    pub stream_id: StreamId,
    pub compressed: bool,
    pub eof: bool,
    pub data: Vec<u8>,
}

impl StreamDataMessage {
    /// Create a new stream data message.
    pub fn new(stream_id: StreamId, data: Vec<u8>, eof: bool, compressed: bool) -> Self {
        StreamDataMessage {
            stream_id,
            compressed,
            eof,
            data,
        }
    }

    /// Pack the message: `[header:2 BE][data]`.
    pub fn pack(&self) -> Vec<u8> {
        let mut header_val: u16 = self.stream_id & 0x3FFF;
        if self.eof {
            header_val |= 0x8000;
        }
        if self.compressed {
            header_val |= 0x4000;
        }

        let mut packed = Vec::with_capacity(2 + self.data.len());
        packed.extend_from_slice(&header_val.to_be_bytes());
        packed.extend_from_slice(&self.data);
        packed
    }

    /// Unpack from raw bytes (decompresses if compressed flag is set).
    pub fn unpack(raw: &[u8], compressor: &dyn Compressor) -> Result<Self, BufferError> {
        if raw.len() < 2 {
            return Err(BufferError::InvalidData);
        }

        let header = u16::from_be_bytes([raw[0], raw[1]]);
        let eof = (header & 0x8000) != 0;
        let compressed = (header & 0x4000) != 0;
        let stream_id = header & 0x3FFF;

        let mut data = raw[2..].to_vec();

        if compressed {
            data = compressor.decompress(&data)
                .ok_or(BufferError::DecompressionFailed)?;
        }

        Ok(StreamDataMessage {
            stream_id,
            compressed,
            eof,
            data,
        })
    }

    /// Maximum data length for a given link MDU.
    pub fn max_data_len(link_mdu: usize) -> usize {
        link_mdu.saturating_sub(STREAM_DATA_OVERHEAD)
    }
}

/// Chunks data into StreamDataMessages.
pub struct BufferWriter {
    stream_id: StreamId,
    closed: bool,
}

impl BufferWriter {
    pub fn new(stream_id: StreamId) -> Self {
        BufferWriter {
            stream_id,
            closed: false,
        }
    }

    /// Write data → one or more StreamDataMessages.
    ///
    /// Tries compression if data > 32 bytes and compression reduces size.
    pub fn write(
        &mut self,
        data: &[u8],
        link_mdu: usize,
        compressor: &dyn Compressor,
    ) -> Vec<StreamDataMessage> {
        if self.closed || data.is_empty() {
            return Vec::new();
        }

        let max_data = StreamDataMessage::max_data_len(link_mdu);
        if max_data == 0 {
            return Vec::new();
        }

        let mut messages = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let end = (offset + max_data).min(data.len());
            let chunk = &data[offset..end];

            // Try compression for larger chunks
            let (msg_data, compressed) = if chunk.len() > 32 {
                if let Some(compressed_data) = compressor.compress(chunk) {
                    if compressed_data.len() < chunk.len() && compressed_data.len() <= max_data {
                        (compressed_data, true)
                    } else {
                        (chunk.to_vec(), false)
                    }
                } else {
                    (chunk.to_vec(), false)
                }
            } else {
                (chunk.to_vec(), false)
            };

            messages.push(StreamDataMessage::new(
                self.stream_id,
                msg_data,
                false,
                compressed,
            ));

            offset = end;
        }

        messages
    }

    /// Signal EOF → final StreamDataMessage with eof=true.
    pub fn close(&mut self) -> StreamDataMessage {
        self.closed = true;
        StreamDataMessage::new(self.stream_id, Vec::new(), true, false)
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

/// Reassembles a stream from messages.
pub struct BufferReader {
    stream_id: StreamId,
    buffer: Vec<u8>,
    eof: bool,
}

impl BufferReader {
    pub fn new(stream_id: StreamId) -> Self {
        BufferReader {
            stream_id,
            buffer: Vec::new(),
            eof: false,
        }
    }

    /// Receive a stream data message.
    pub fn receive(&mut self, msg: &StreamDataMessage) {
        if msg.stream_id != self.stream_id {
            return;
        }
        if !msg.data.is_empty() {
            self.buffer.extend_from_slice(&msg.data);
        }
        if msg.eof {
            self.eof = true;
        }
    }

    /// Read up to `max_bytes` from the buffer.
    pub fn read(&mut self, max_bytes: usize) -> Vec<u8> {
        let n = max_bytes.min(self.buffer.len());
        let data: Vec<u8> = self.buffer.drain(..n).collect();
        data
    }

    /// Number of bytes available to read.
    pub fn available(&self) -> usize {
        self.buffer.len()
    }

    /// Whether EOF has been received.
    pub fn is_eof(&self) -> bool {
        self.eof
    }

    /// Whether all data has been consumed (EOF received and buffer empty).
    pub fn is_done(&self) -> bool {
        self.eof && self.buffer.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_unpack_roundtrip() {
        let msg = StreamDataMessage::new(42, b"hello".to_vec(), false, false);
        let packed = msg.pack();
        let unpacked = StreamDataMessage::unpack(&packed, &NoopCompressor).unwrap();
        assert_eq!(unpacked.stream_id, 42);
        assert_eq!(unpacked.data, b"hello");
        assert!(!unpacked.eof);
        assert!(!unpacked.compressed);
    }

    #[test]
    fn test_pack_unpack_eof() {
        let msg = StreamDataMessage::new(0, Vec::new(), true, false);
        let packed = msg.pack();
        let unpacked = StreamDataMessage::unpack(&packed, &NoopCompressor).unwrap();
        assert_eq!(unpacked.stream_id, 0);
        assert!(unpacked.eof);
        assert!(unpacked.data.is_empty());
    }

    #[test]
    fn test_header_bit_layout() {
        // stream_id = 0x1234, eof = true, compressed = true
        let msg = StreamDataMessage::new(0x1234, vec![0xFF], true, true);
        let packed = msg.pack();
        let header = u16::from_be_bytes([packed[0], packed[1]]);
        assert_eq!(header & 0x3FFF, 0x1234);
        assert!(header & 0x8000 != 0); // eof
        assert!(header & 0x4000 != 0); // compressed
    }

    #[test]
    fn test_max_stream_id() {
        let msg = StreamDataMessage::new(STREAM_ID_MAX, vec![0x42], false, false);
        let packed = msg.pack();
        let unpacked = StreamDataMessage::unpack(&packed, &NoopCompressor).unwrap();
        assert_eq!(unpacked.stream_id, STREAM_ID_MAX);
    }

    #[test]
    fn test_stream_id_overflow() {
        // If stream_id > STREAM_ID_MAX, only lower 14 bits are used
        let msg = StreamDataMessage::new(0xFFFF, vec![], false, false);
        let packed = msg.pack();
        let unpacked = StreamDataMessage::unpack(&packed, &NoopCompressor).unwrap();
        assert_eq!(unpacked.stream_id, 0x3FFF);
    }

    #[test]
    fn test_unpack_too_short() {
        assert_eq!(StreamDataMessage::unpack(&[0x00], &NoopCompressor), Err(BufferError::InvalidData));
    }

    #[test]
    fn test_max_data_len() {
        let mdl = StreamDataMessage::max_data_len(431);
        assert_eq!(mdl, 431 - STREAM_DATA_OVERHEAD);
    }

    #[test]
    fn test_writer_single_chunk() {
        let mut writer = BufferWriter::new(1);
        let data = vec![0x42; 100];
        let msgs = writer.write(&data, 431, &NoopCompressor);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].data, data);
        assert_eq!(msgs[0].stream_id, 1);
        assert!(!msgs[0].eof);
    }

    #[test]
    fn test_writer_chunking() {
        let mut writer = BufferWriter::new(1);
        let data = vec![0x42; 1000];
        // Use small MDU to force multiple chunks
        let msgs = writer.write(&data, 50, &NoopCompressor);
        let max_data = StreamDataMessage::max_data_len(50);
        assert!(msgs.len() > 1);

        // Verify total data equals original
        let total: Vec<u8> = msgs.iter().flat_map(|m| m.data.clone()).collect();
        assert_eq!(total, data);

        // Each chunk should be at most max_data
        for msg in &msgs {
            assert!(msg.data.len() <= max_data);
        }
    }

    #[test]
    fn test_writer_close() {
        let mut writer = BufferWriter::new(5);
        let msg = writer.close();
        assert!(msg.eof);
        assert!(msg.data.is_empty());
        assert_eq!(msg.stream_id, 5);
        assert!(writer.is_closed());
    }

    #[test]
    fn test_writer_no_write_after_close() {
        let mut writer = BufferWriter::new(1);
        writer.close();
        let msgs = writer.write(b"test", 431, &NoopCompressor);
        assert!(msgs.is_empty());
    }

    #[test]
    fn test_reader_reassembly() {
        let mut reader = BufferReader::new(1);
        let msg1 = StreamDataMessage::new(1, b"hello ".to_vec(), false, false);
        let msg2 = StreamDataMessage::new(1, b"world".to_vec(), false, false);
        let eof = StreamDataMessage::new(1, Vec::new(), true, false);

        reader.receive(&msg1);
        reader.receive(&msg2);
        assert_eq!(reader.available(), 11);
        assert!(!reader.is_eof());

        reader.receive(&eof);
        assert!(reader.is_eof());

        let data = reader.read(100);
        assert_eq!(data, b"hello world");
        assert!(reader.is_done());
    }

    #[test]
    fn test_reader_partial_read() {
        let mut reader = BufferReader::new(1);
        let msg = StreamDataMessage::new(1, b"abcdefgh".to_vec(), false, false);
        reader.receive(&msg);

        let first = reader.read(4);
        assert_eq!(first, b"abcd");
        assert_eq!(reader.available(), 4);

        let rest = reader.read(100);
        assert_eq!(rest, b"efgh");
        assert_eq!(reader.available(), 0);
    }

    #[test]
    fn test_reader_ignores_wrong_stream() {
        let mut reader = BufferReader::new(1);
        let msg = StreamDataMessage::new(2, b"wrong".to_vec(), false, false);
        reader.receive(&msg);
        assert_eq!(reader.available(), 0);
    }

    #[test]
    fn test_writer_empty_data() {
        let mut writer = BufferWriter::new(1);
        let msgs = writer.write(&[], 431, &NoopCompressor);
        assert!(msgs.is_empty());
    }

    // Test with a mock compressor
    struct HalfCompressor;
    impl Compressor for HalfCompressor {
        fn compress(&self, data: &[u8]) -> Option<Vec<u8>> {
            // "Compress" by taking first half
            Some(data[..data.len() / 2].to_vec())
        }
        fn decompress(&self, data: &[u8]) -> Option<Vec<u8>> {
            // "Decompress" by doubling
            let mut out = data.to_vec();
            out.extend_from_slice(data);
            Some(out)
        }
    }

    #[test]
    fn test_compression_used_when_smaller() {
        let mut writer = BufferWriter::new(1);
        let data = vec![0x42; 100]; // > 32 bytes, compression will be tried
        let msgs = writer.write(&data, 431, &HalfCompressor);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].compressed);
        assert_eq!(msgs[0].data.len(), 50); // half
    }

    #[test]
    fn test_compressed_unpack() {
        let msg = StreamDataMessage::new(1, b"compressed".to_vec(), false, true);
        let packed = msg.pack();
        let unpacked = StreamDataMessage::unpack(&packed, &HalfCompressor).unwrap();
        // HalfCompressor doubles data on decompress
        assert_eq!(unpacked.data, b"compressedcompressed");
    }
}
