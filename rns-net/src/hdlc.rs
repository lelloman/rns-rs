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
}

impl Decoder {
    pub fn new() -> Self {
        Decoder { buffer: Vec::new() }
    }

    /// Feed raw bytes into the decoder and return any complete frames.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        self.buffer.extend_from_slice(chunk);
        let mut frames = Vec::new();

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

            // Only yield frames that meet minimum size
            if unescaped.len() >= HEADER_MINSIZE {
                frames.push(unescaped);
            }

            // Keep the closing FLAG as the opening FLAG of the next frame
            // (matches Python: frame_buffer = frame_buffer[frame_end:])
            self.buffer.drain(..end);
        }

        frames
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
    fn decoder_drops_short() {
        // Frame with < HEADER_MINSIZE (19) bytes of payload
        let data = vec![0x01, 0x02, 0x03]; // only 3 bytes
        let framed = frame(&data);

        let mut decoder = Decoder::new();
        let frames = decoder.feed(&framed);
        assert_eq!(frames.len(), 0); // dropped as too short
    }
}
