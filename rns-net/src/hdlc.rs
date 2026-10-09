//! HDLC framing for TCP transport.
//!
//! Matches Python `TCPInterface.py` HDLC encoding/decoding.

use rns_core::constants::HEADER_MINSIZE;

const FLAG: u8 = 0x7E;
const ESC: u8 = 0x7D;
const ESC_MASK: u8 = 0x20;

/// Exact on-wire length after HDLC escaping and delimiter insertion.
pub(crate) fn framed_len(data: &[u8]) -> usize {
    data.len()
        .saturating_add(memchr::memchr2_iter(FLAG, ESC, data).count())
        .saturating_add(2)
}

/// Escape special bytes in data (FLAG and ESC).
pub fn escape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(framed_len(data).saturating_sub(2));
    append_escaped(data, &mut out);
    out
}

fn append_escaped(data: &[u8], out: &mut Vec<u8>) {
    let mut offset = 0;
    for index in memchr::memchr2_iter(FLAG, ESC, data) {
        out.extend_from_slice(&data[offset..index]);
        out.extend_from_slice(&[ESC, data[index] ^ ESC_MASK]);
        offset = index + 1;
    }
    out.extend_from_slice(&data[offset..]);
}

/// Append one HDLC frame (delimiters plus escaped payload) to `out`.
///
/// Produces exactly the bytes of [`frame`], without a per-frame allocation,
/// so writers can coalesce several queued frames into one socket write.
pub(crate) fn append_frame(data: &[u8], out: &mut Vec<u8>) {
    out.push(FLAG);
    append_escaped(data, out);
    out.push(FLAG);
}

/// Bytes a writer coalesces before issuing one socket write.
pub(crate) const WRITE_BATCH_BYTES: usize = 256 * 1024;

/// Encode `frames` in order and write them with as few `write_all` calls as
/// possible, flushing whenever the pending batch reaches
/// [`WRITE_BATCH_BYTES`]. The wire bytes are identical to writing each
/// frame separately; only the number of system calls changes.
pub(crate) fn write_frames<W: std::io::Write>(
    writer: &mut W,
    frames: &[Vec<u8>],
    scratch: &mut Vec<u8>,
) -> std::io::Result<()> {
    scratch.clear();
    for frame in frames {
        append_frame(frame, scratch);
        if scratch.len() >= WRITE_BATCH_BYTES {
            writer.write_all(scratch)?;
            scratch.clear();
        }
    }
    if !scratch.is_empty() {
        writer.write_all(scratch)?;
        scratch.clear();
    }
    if scratch.capacity() > WRITE_BATCH_BYTES * 2 {
        scratch.shrink_to(WRITE_BATCH_BYTES);
    }
    Ok(())
}

/// Wrap data in the same HDLC delimiters and escaping as the scalar encoder.
pub fn frame(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(framed_len(data));
    out.push(FLAG);
    append_escaped(data, &mut out);
    out.push(FLAG);
    out
}

fn unescape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut offset = 0;
    while let Some(relative) = memchr::memchr(ESC, &data[offset..]) {
        let index = offset + relative;
        out.extend_from_slice(&data[offset..index]);
        match data.get(index + 1).copied() {
            Some(byte) if byte == FLAG ^ ESC_MASK || byte == ESC ^ ESC_MASK => {
                out.push(byte ^ ESC_MASK);
                offset = index + 2;
            }
            _ => {
                // Unknown escapes and a trailing ESC remain literal.
                out.push(ESC);
                offset = index + 1;
            }
        }
    }
    out.extend_from_slice(&data[offset..]);
    out
}

/// Streaming HDLC frame decoder.
///
/// Accumulates bytes via `feed()` and yields complete decoded frames.
/// Matches the decode loop in `TCPInterface.py:381-394`.
pub struct Decoder {
    buffer: Vec<u8>,
    offset: usize,
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
            offset: 0,
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
            offset: 0,
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
            // Find first FLAG in the unconsumed tail.
            let start = match memchr::memchr(FLAG, &self.buffer[self.offset..]) {
                Some(pos) => self.offset + pos,
                None => {
                    // No FLAG found, discard buffer.
                    self.buffer.clear();
                    self.offset = 0;
                    break;
                }
            };

            // Find second FLAG after the opening marker.
            let end = match memchr::memchr(FLAG, &self.buffer[start + 1..]) {
                Some(pos) => start + 1 + pos,
                None => {
                    if self.buffer.len() - self.offset > self.max_buffer_size {
                        self.buffer.clear();
                        self.offset = 0;
                    }
                    break;
                }
            };

            // Extract bytes between the two FLAGs
            let between = &self.buffer[start + 1..end];
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

            // Keep the closing FLAG as the next opening marker. Avoid a
            // front-drain per frame; compact only after consuming half.
            self.offset = end;
            if self.offset > 0 && self.offset >= self.buffer.len() / 2 {
                self.buffer.drain(..self.offset);
                self.offset = 0;
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
    fn canonical_frame_matches_wrapped_escape_for_every_byte() {
        let data: Vec<u8> = (0..=u8::MAX).collect();
        let mut expected = Vec::with_capacity(escape(&data).len() + 2);
        expected.push(FLAG);
        expected.extend_from_slice(&escape(&data));
        expected.push(FLAG);

        let framed = frame(&data);

        assert_eq!(framed, expected);
        assert_eq!(framed.capacity(), framed.len());
    }

    #[test]
    fn framed_len_matches_exact_encoded_length() {
        for data in [
            Vec::new(),
            vec![0x01, 0x02],
            vec![FLAG, ESC, 0x03],
            vec![FLAG; 1_024],
        ] {
            assert_eq!(framed_len(&data), frame(&data).len());
        }
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
    fn unescape_preserves_unknown_and_trailing_escape_bytes() {
        let mut decoder = Decoder::with_min_frame_size(0);

        let frames = decoder.feed(&[FLAG, ESC, 0x00, ESC, FLAG]);

        assert_eq!(frames, vec![vec![ESC, 0x00, ESC]]);
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
        let count = 20_000;
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
    fn decoder_defers_compaction_until_consumed_prefix_reaches_half() {
        let first = vec![0x31; 32];
        let second = vec![0x42; 200];
        let mut stream = frame(&first);
        stream.extend_from_slice(&escape(&second));
        let mut decoder = Decoder::with_limits(HEADER_MINSIZE, 1024);

        assert_eq!(decoder.feed(&stream), vec![first]);
        assert!(decoder.offset > 0);
        assert!(decoder.buffer.len() - decoder.offset > decoder.offset);

        assert_eq!(decoder.feed(&[FLAG]), vec![second]);
        assert_eq!(decoder.buffer, vec![FLAG]);
        assert_eq!(decoder.offset, 0);
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
        let oversized = frame(&[0x55; 65]);
        let valid = frame(&[0x33; HEADER_MINSIZE + 1]);
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

#[cfg(test)]
#[path = "hdlc_baseline.rs"]
mod scalar_baseline;
#[cfg(test)]
mod bulk_regression {
    use super::*;
    fn compare(wire: &[u8], chunk: usize, mtu: usize) {
        let mut scalar = scalar_baseline::Decoder::reticulum(mtu, 0);
        let mut bulk = Decoder::reticulum(mtu, 0);
        for part in wire.chunks(chunk) {
            let a = scalar.feed_with_diagnostics(part);
            let b = bulk.feed_with_diagnostics(part);
            assert_eq!(a.frames, b.frames);
            assert_eq!(a.invalid_frame_lengths, b.invalid_frame_lengths);
        }
        let recovery = frame(&vec![0x11; mtu.clamp(20, 64)]);
        let a = scalar.feed_with_diagnostics(&recovery);
        let b = bulk.feed_with_diagnostics(&recovery);
        assert_eq!(a.frames, b.frames);
        assert_eq!(a.invalid_frame_lengths, b.invalid_frame_lengths);
    }
    #[test]
    fn every_two_byte_escape_and_unknown_sequence_matches_scalar() {
        for first in 0..=255u8 {
            for second in 0..=255u8 {
                let data = [first, second];
                assert_eq!(escape(&data), scalar_baseline::escape(&data));
                assert_eq!(frame(&data), scalar_baseline::frame(&data));
                let mut wire = vec![FLAG];
                wire.extend_from_slice(&[0x11; 20]);
                wire.extend_from_slice(&[first, second, FLAG]);
                for chunk in [1, 2, 23, 64] {
                    compare(&wire, chunk, 64);
                }
            }
        }
    }
    #[test]
    fn arbitrary_wire_fragmentation_limits_and_recovery_match_scalar() {
        let mut state = 0x723b19u64;
        for len in [
            0, 1, 18, 19, 20, 63, 64, 65, 499, 500, 501, 8191, 8192, 8193, 16385,
        ] {
            let data: Vec<u8> = (0..len)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect();
            assert_eq!(escape(&data), scalar_baseline::escape(&data));
            assert_eq!(frame(&data), scalar_baseline::frame(&data));
            for chunk in [1, 2, 7, 128, 2048, 65536] {
                for mtu in [64, 500, 8192] {
                    compare(&data, chunk, mtu);
                    compare(&frame(&data), chunk, mtu);
                }
            }
        }
        for byte in [FLAG, ESC, 0x11] {
            for chunk in [1, 7, 2048] {
                compare(&vec![byte; 16385], chunk, 8192);
            }
        }
    }
}
