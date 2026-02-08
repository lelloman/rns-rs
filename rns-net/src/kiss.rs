//! KISS framing for serial/radio interfaces.
//!
//! Matches Python `KISSInterface.py` KISS encoding/decoding.

pub const FEND: u8 = 0xC0;
pub const FESC: u8 = 0xDB;
pub const TFEND: u8 = 0xDC;
pub const TFESC: u8 = 0xDD;

pub const CMD_DATA: u8 = 0x00;
pub const CMD_TXDELAY: u8 = 0x01;
pub const CMD_P: u8 = 0x02;
pub const CMD_SLOTTIME: u8 = 0x03;
pub const CMD_TXTAIL: u8 = 0x04;
pub const CMD_FULLDUPLEX: u8 = 0x05;
pub const CMD_SETHARDWARE: u8 = 0x06;
pub const CMD_READY: u8 = 0x0F;
pub const CMD_RETURN: u8 = 0xFF;
pub const CMD_UNKNOWN: u8 = 0xFE;

/// Escape data for KISS framing.
/// Order matters: escape 0xDB first, then 0xC0 (same as Python).
pub fn escape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        match b {
            FESC => {
                out.push(FESC);
                out.push(TFESC);
            }
            FEND => {
                out.push(FESC);
                out.push(TFEND);
            }
            _ => out.push(b),
        }
    }
    out
}

/// Unescape KISS data.
pub fn unescape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut esc = false;
    for &b in data {
        if esc {
            match b {
                TFEND => out.push(FEND),
                TFESC => out.push(FESC),
                _ => out.push(b), // spec violation, pass through
            }
            esc = false;
        } else if b == FESC {
            esc = true;
        } else {
            out.push(b);
        }
    }
    out
}

/// Wrap data as a KISS DATA frame: [FEND][CMD_DATA][escaped_data][FEND].
pub fn frame(data: &[u8]) -> Vec<u8> {
    let escaped = escape(data);
    let mut out = Vec::with_capacity(escaped.len() + 3);
    out.push(FEND);
    out.push(CMD_DATA);
    out.extend_from_slice(&escaped);
    out.push(FEND);
    out
}

/// Build a KISS command frame: [FEND][cmd][escaped_value][FEND].
pub fn command_frame(cmd: u8, value: &[u8]) -> Vec<u8> {
    let escaped = escape(value);
    let mut out = Vec::with_capacity(escaped.len() + 3);
    out.push(FEND);
    out.push(cmd);
    out.extend_from_slice(&escaped);
    out.push(FEND);
    out
}

/// Events yielded by the KISS Decoder.
#[derive(Debug, Clone, PartialEq)]
pub enum KissEvent {
    /// A CMD_DATA frame was received with the decoded payload.
    DataFrame(Vec<u8>),
    /// A CMD_READY frame was received (flow control).
    Ready,
}

/// Streaming KISS decoder. Feed bytes, yields decoded frames.
///
/// Matches the readLoop in `KISSInterface.py:290-356`.
pub struct Decoder {
    in_frame: bool,
    escape: bool,
    command: u8,
    buffer: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Decoder {
            in_frame: false,
            escape: false,
            command: CMD_UNKNOWN,
            buffer: Vec::new(),
        }
    }

    /// Feed raw bytes and return any decoded events.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<KissEvent> {
        let mut events = Vec::new();

        for &byte in bytes {
            if self.in_frame && byte == FEND && self.command == CMD_DATA {
                // End of data frame
                self.in_frame = false;
                if !self.buffer.is_empty() {
                    events.push(KissEvent::DataFrame(
                        core::mem::take(&mut self.buffer),
                    ));
                }
            } else if byte == FEND {
                // Start of new frame
                self.in_frame = true;
                self.command = CMD_UNKNOWN;
                self.buffer.clear();
                self.escape = false;
            } else if self.in_frame {
                if self.buffer.is_empty() && self.command == CMD_UNKNOWN {
                    // First byte after FEND is the command, strip port nibble
                    self.command = byte & 0x0F;
                } else if self.command == CMD_DATA {
                    if byte == FESC {
                        self.escape = true;
                    } else if self.escape {
                        match byte {
                            TFEND => self.buffer.push(FEND),
                            TFESC => self.buffer.push(FESC),
                            _ => self.buffer.push(byte),
                        }
                        self.escape = false;
                    } else {
                        self.buffer.push(byte);
                    }
                } else if self.command == CMD_READY {
                    events.push(KissEvent::Ready);
                    // Reset state so we don't fire Ready again for trailing bytes
                    self.command = CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
        }

        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_fend() {
        assert_eq!(escape(&[FEND]), vec![FESC, TFEND]);
        assert_eq!(escape(&[0xC0]), vec![0xDB, 0xDC]);
    }

    #[test]
    fn escape_fesc() {
        assert_eq!(escape(&[FESC]), vec![FESC, TFESC]);
        assert_eq!(escape(&[0xDB]), vec![0xDB, 0xDD]);
    }

    #[test]
    fn escape_passthrough() {
        let data = b"hello world";
        assert_eq!(escape(data), data.to_vec());
    }

    #[test]
    fn unescape_roundtrip() {
        // All 256 byte values
        let data: Vec<u8> = (0..=255).collect();
        let escaped = escape(&data);
        let recovered = unescape(&escaped);
        assert_eq!(recovered, data);
    }

    #[test]
    fn frame_data() {
        let data = b"test";
        let framed = frame(data);
        assert_eq!(framed[0], FEND);
        assert_eq!(framed[1], CMD_DATA);
        assert_eq!(*framed.last().unwrap(), FEND);
        // Middle should be escaped data
        let middle = &framed[2..framed.len() - 1];
        assert_eq!(middle, &escape(data)[..]);
    }

    #[test]
    fn decoder_single_frame() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let framed = frame(&data);

        let mut decoder = Decoder::new();
        let events = decoder.feed(&framed);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], KissEvent::DataFrame(data));
    }

    #[test]
    fn decoder_ready_event() {
        // Build a CMD_READY frame
        let ready_frame = vec![FEND, CMD_READY, 0x01, FEND];

        let mut decoder = Decoder::new();
        let events = decoder.feed(&ready_frame);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], KissEvent::Ready);
    }

    #[test]
    fn decoder_fragmented() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let framed = frame(&data);

        let mut decoder = Decoder::new();

        // Feed byte by byte
        let mut all_events = Vec::new();
        for &byte in &framed {
            all_events.extend(decoder.feed(&[byte]));
        }

        assert_eq!(all_events.len(), 1);
        assert_eq!(all_events[0], KissEvent::DataFrame(data));
    }
}
