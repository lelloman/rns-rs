//! HDLC framing for TCP transport.
//!
//! Matches Python `TCPInterface.py` HDLC encoding/decoding.

use rns_core::constants::HEADER_MINSIZE;

const FLAG: u8 = 0x7E;
const ESC: u8 = 0x7D;
const ESC_MASK: u8 = 0x20;

/// Escape special bytes in data (FLAG and ESC).
pub fn escape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        match b {
            ESC => {
                out.push(ESC);
                out.push(ESC ^ ESC_MASK);
            }
            FLAG => {
                out.push(ESC);
                out.push(FLAG ^ ESC_MASK);
            }
            _ => out.push(b),
        }
    }
    out
}

/// Wrap data in HDLC frame: [FLAG] + escape(data) + [FLAG].
pub fn frame(data: &[u8]) -> Vec<u8> {
    let escaped = escape(data);
    let mut out = Vec::with_capacity(escaped.len() + 2);
    out.push(FLAG);
    out.extend_from_slice(&escaped);
    out.push(FLAG);
    out
}

/// Unescape HDLC-escaped data.
fn unescape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == ESC && i + 1 < data.len() {
            out.push(data[i + 1] ^ ESC_MASK);
            i += 2;
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    out
}

/// Streaming HDLC frame decoder.
///
/// Accumulates bytes via `feed()` and yields complete decoded frames.
/// Matches the decode loop in `TCPInterface.py:381-394`.
pub struct Decoder {
    buffer: Vec<u8>,
    min_frame_size: usize,
    max_frame_size: Option<usize>,
    max_buffer_size: usize,
}

/// Complete frames and non-empty frames rejected by configured size bounds.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct DecodeBatch {
    pub frames: Vec<Vec<u8>>,
    pub invalid_frame_lengths: Vec<usize>,
}

impl Decoder {
    pub fn new() -> Self {
        Self::with_limits(HEADER_MINSIZE, 64 * 1024)
    }

    /// Construct a decoder for protocols with a different minimum frame size.
    pub fn with_min_frame_size(min_frame_size: usize) -> Self {
        Self::with_limits(min_frame_size, 64 * 1024)
    }

    pub fn with_limits(min_frame_size: usize, max_buffer_size: usize) -> Self {
        Decoder {
            buffer: Vec::new(),
            min_frame_size,
            max_frame_size: None,
            max_buffer_size: max_buffer_size.max(2),
        }
    }

    /// Construct a decoder with Reticulum's TCP-style frame bounds.
    ///
    /// Decoded frames must be strictly larger than `HEADER_MINSIZE` and no
    /// larger than the interface hardware MTU plus on-wire IFAC bytes. The
    /// unterminated encoded tail is retained up to twice the hardware MTU.
    pub fn reticulum(hardware_mtu: usize, ifac_size: usize) -> Self {
        Decoder {
            buffer: Vec::new(),
            min_frame_size: HEADER_MINSIZE.saturating_add(1),
            max_frame_size: Some(hardware_mtu.saturating_add(ifac_size)),
            max_buffer_size: hardware_mtu.saturating_mul(2).max(2),
        }
    }

    /// Feed raw bytes into the decoder and return any complete frames.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        self.feed_with_diagnostics(chunk).frames
    }

    /// Feed raw bytes and retain the decoded lengths of non-empty frames that
    /// were rejected by the configured minimum or maximum.
    pub fn feed_with_diagnostics(&mut self, chunk: &[u8]) -> DecodeBatch {
        self.buffer.extend_from_slice(chunk);
        let mut decoded = DecodeBatch::default();

        loop {
            // Find first FLAG
            let start = match self.buffer.iter().position(|&b| b == FLAG) {
                Some(pos) => pos,
                None => {
                    // No FLAG found, discard buffer
                    self.buffer.clear();
                    break;
                }
            };

            // Trim garbage before first FLAG
            if start > 0 {
                self.buffer.drain(..start);
            }

            // Find second FLAG (after position 0)
            let end = match self.buffer[1..].iter().position(|&b| b == FLAG) {
                Some(pos) => pos + 1, // offset back to buffer index
                None => break,        // incomplete frame, wait for more data
            };

            // Extract bytes between the two FLAGs
            let between = &self.buffer[1..end];
            let unescaped = unescape(between);

            let frame_len = unescaped.len();
            let within_maximum = self
                .max_frame_size
                .is_none_or(|max_frame_size| frame_len <= max_frame_size);
            if frame_len >= self.min_frame_size && within_maximum {
                decoded.frames.push(unescaped);
            } else if frame_len != 0 {
                decoded.invalid_frame_lengths.push(frame_len);
            }

            // Keep the closing FLAG as the opening FLAG of the next frame
            // (matches Python: frame_buffer = frame_buffer[frame_end:])
            self.buffer.drain(..end);
        }

        // Bound only the unconsumed tail. Applying the limit before decoding
        // can discard a large batch of complete coalesced frames.
        if self.buffer.len() > self.max_buffer_size {
            if let Some(last_flag) = self.buffer.iter().rposition(|&byte| byte == FLAG) {
                if self.buffer.len() - last_flag <= self.max_buffer_size {
                    self.buffer.drain(..last_flag);
                } else {
                    self.buffer.clear();
                }
            } else {
                self.buffer.clear();
            }
        }

        decoded
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_passthrough() {
        let data = b"hello world";
        assert_eq!(escape(data), data.to_vec());
    }

    #[test]
    fn escape_flag() {
        assert_eq!(escape(&[FLAG]), vec![ESC, FLAG ^ ESC_MASK]);
        assert_eq!(escape(&[0x7E]), vec![0x7D, 0x5E]);
    }

    #[test]
    fn escape_esc() {
        assert_eq!(escape(&[ESC]), vec![ESC, ESC ^ ESC_MASK]);
        assert_eq!(escape(&[0x7D]), vec![0x7D, 0x5D]);
    }

    #[test]
    fn escape_mixed() {
        let data = [0x01, FLAG, 0x02, ESC, 0x03];
        let expected = vec![0x01, ESC, FLAG ^ ESC_MASK, 0x02, ESC, ESC ^ ESC_MASK, 0x03];
        assert_eq!(escape(&data), expected);
    }

    #[test]
    fn frame_structure() {
        let data = b"test";
        let framed = frame(data);
        assert_eq!(framed[0], FLAG);
        assert_eq!(*framed.last().unwrap(), FLAG);
        assert_eq!(&framed[1..framed.len() - 1], &escape(data));
    }

    #[test]
    fn roundtrip_all_bytes() {
        // Frame all 256 byte values, decode back
        let data: Vec<u8> = (0..=255).collect();
        let framed = frame(&data);

        let mut decoder = Decoder::new();
        let frames = decoder.feed(&framed);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], data);
    }

    #[test]
    fn decoder_single_frame() {
        // A frame with enough data (>= HEADER_MINSIZE = 19 bytes)
        let data: Vec<u8> = (0..32).collect();
        let framed = frame(&data);

        let mut decoder = Decoder::new();
        let frames = decoder.feed(&framed);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], data);
    }

    #[test]
    fn decoder_two_frames_one_chunk() {
        let data1: Vec<u8> = (0..24).collect();
        let data2: Vec<u8> = (100..130).collect();
        let mut combined = frame(&data1);
        // The closing FLAG of frame1 is the opening FLAG of frame2
        // But frame() adds its own opening FLAG, so two adjacent frames
        // share the FLAG byte. We can just concatenate since the closing
        // FLAG of frame1 serves as opening FLAG of frame2.
        let framed2 = frame(&data2);
        // Skip the opening FLAG of frame2 since frame1's closing FLAG serves that role
        combined.extend_from_slice(&framed2[1..]);

        let mut decoder = Decoder::new();
        let frames = decoder.feed(&combined);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], data1);
        assert_eq!(frames[1], data2);
    }

    #[test]
    fn decoder_split_frame() {
        let data: Vec<u8> = (0..32).collect();
        let framed = frame(&data);

        // Split in the middle
        let mid = framed.len() / 2;
        let mut decoder = Decoder::new();

        let frames1 = decoder.feed(&framed[..mid]);
        assert_eq!(frames1.len(), 0); // incomplete

        let frames2 = decoder.feed(&framed[mid..]);
        assert_eq!(frames2.len(), 1);
        assert_eq!(frames2[0], data);
    }

    #[test]
    fn decoder_does_not_drop_large_coalesced_batches() {
        let payload = vec![0x42; 32];
        let encoded = frame(&payload);
        let count = 3_000;
        let mut batch = Vec::with_capacity(encoded.len() * count);
        for index in 0..count {
            if index == 0 {
                batch.extend_from_slice(&encoded);
            } else {
                batch.extend_from_slice(&encoded[1..]);
            }
        }
        let mut decoder = Decoder::with_limits(HEADER_MINSIZE, 64 * 1024);
        let frames = decoder.feed(&batch);
        assert_eq!(frames.len(), count);
        assert!(frames.iter().all(|decoded| decoded == &payload));
    }

    #[test]
    fn decoder_drops_short() {
        // Frame with < HEADER_MINSIZE (19) bytes of payload
        let data = vec![0x01, 0x02, 0x03]; // only 3 bytes
        let framed = frame(&data);

        let mut decoder = Decoder::new();
        let frames = decoder.feed(&framed);
        assert_eq!(frames.len(), 0); // dropped as too short
    }

    #[test]
    fn reticulum_decoder_enforces_strict_minimum_and_ifac_adjusted_maximum() {
        let hardware_mtu = 64;
        let ifac_size = 8;
        let mut decoder = Decoder::reticulum(hardware_mtu, ifac_size);
        let lengths = [
            HEADER_MINSIZE,
            HEADER_MINSIZE + 1,
            hardware_mtu + ifac_size,
            hardware_mtu + ifac_size + 1,
        ];
        let mut encoded = vec![FLAG];
        for length in lengths {
            encoded.extend_from_slice(&frame(&vec![0x42; length])[1..]);
        }

        let decoded = decoder.feed_with_diagnostics(&encoded);

        assert_eq!(
            decoded.frames.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![HEADER_MINSIZE + 1, hardware_mtu + ifac_size]
        );
        assert_eq!(
            decoded.invalid_frame_lengths,
            vec![HEADER_MINSIZE, hardware_mtu + ifac_size + 1]
        );
    }

    #[test]
    fn empty_frames_are_ignored_without_invalid_frame_diagnostics() {
        let mut decoder = Decoder::reticulum(64, 0);

        let decoded = decoder.feed_with_diagnostics(&[FLAG, FLAG, FLAG]);

        assert!(decoded.frames.is_empty());
        assert!(decoded.invalid_frame_lengths.is_empty());
    }

    #[test]
    fn oversized_complete_frame_is_dropped_and_next_frame_is_recovered() {
        let mut decoder = Decoder::reticulum(64, 0);
        let oversized = frame(&vec![0x55; 65]);
        let valid = frame(&vec![0x33; HEADER_MINSIZE + 1]);
        let mut encoded = oversized;
        encoded.extend_from_slice(&valid[1..]);

        let decoded = decoder.feed_with_diagnostics(&encoded);

        assert_eq!(decoded.frames, vec![vec![0x33; HEADER_MINSIZE + 1]]);
        assert_eq!(decoded.invalid_frame_lengths, vec![65]);
    }

    #[test]
    fn fragmented_frame_larger_than_legacy_buffer_limit_is_preserved() {
        let hardware_mtu = 70 * 1024;
        let payload = vec![0x42; hardware_mtu];
        let encoded = frame(&payload);
        let split = 65 * 1024;
        let mut decoder = Decoder::reticulum(hardware_mtu, 0);

        let first = decoder.feed_with_diagnostics(&encoded[..split]);
        assert!(first.frames.is_empty());
        assert!(first.invalid_frame_lengths.is_empty());
        assert_eq!(decoder.buffer.len(), split);

        let second = decoder.feed_with_diagnostics(&encoded[split..]);
        assert_eq!(second.frames, vec![payload]);
        assert!(second.invalid_frame_lengths.is_empty());
    }

    #[test]
    fn unterminated_tail_is_dropped_only_after_twice_hardware_mtu() {
        let hardware_mtu = 32;
        let mut decoder = Decoder::reticulum(hardware_mtu, 0);
        let mut exact_limit = vec![FLAG];
        exact_limit.extend(vec![0x22; hardware_mtu * 2 - 1]);

        assert!(decoder.feed(&exact_limit).is_empty());
        assert_eq!(decoder.buffer.len(), hardware_mtu * 2);

        assert!(decoder.feed(&[0x22]).is_empty());
        assert!(decoder.buffer.is_empty());

        let payload = vec![0x44; HEADER_MINSIZE + 1];
        assert_eq!(decoder.feed(&frame(&payload)), vec![payload]);
    }

    #[test]
    fn decoded_length_not_escaped_wire_length_controls_frame_limit() {
        let hardware_mtu = 64;
        let payload = vec![FLAG; hardware_mtu];
        let encoded = frame(&payload);
        assert!(encoded.len() > hardware_mtu * 2);
        let mut decoder = Decoder::reticulum(hardware_mtu, 0);

        let decoded = decoder.feed_with_diagnostics(&encoded);

        assert_eq!(decoded.frames, vec![payload]);
        assert!(decoded.invalid_frame_lengths.is_empty());
    }
}
