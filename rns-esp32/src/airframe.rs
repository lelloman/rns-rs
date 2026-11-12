//! The RNode on-air framing, as RNode firmware's `transmit()` and
//! `receive_callback()` do it, so this firmware's LoRa packets are
//! understood by RNode-based Reticulum nodes and the other way round.
//!
//! Every LoRa packet starts with a one-byte header: a random sequence
//! number in the upper four bits, and `FLAG_SPLIT` when the frame did not
//! fit one packet. A frame of up to 254 bytes is one packet; a longer one,
//! up to 508 bytes, is two packets carrying the same header.

/// The largest frame, split over two packets (RNode firmware `MTU`).
pub const MTU: usize = 508;
/// The largest LoRa packet (RNode firmware `SINGLE_MTU`).
pub const SINGLE_MTU: usize = 255;
/// The header's length (RNode firmware `HEADER_L`).
pub const HEADER_L: usize = 1;
/// Set in the header of both packets of a split frame.
pub const FLAG_SPLIT: u8 = 0x01;

/// The LoRa packets that carry `frame`, `random` supplying the sequence
/// number. `None` for a frame longer than [`MTU`].
pub fn packets(frame: &[u8], random: u8) -> Option<Vec<Vec<u8>>> {
    if frame.len() > MTU {
        return None;
    }
    let mut header = random & 0xF0;
    if frame.len() > SINGLE_MTU - HEADER_L {
        header |= FLAG_SPLIT;
    }
    let first = frame.len().min(SINGLE_MTU - HEADER_L);
    let mut out = Vec::with_capacity(2);
    for part in [&frame[..first], &frame[first..]] {
        if part.is_empty() && !out.is_empty() {
            break;
        }
        let mut packet = Vec::with_capacity(HEADER_L + part.len());
        packet.push(header);
        packet.extend_from_slice(part);
        out.push(packet);
    }
    Some(out)
}

/// Rebuilds frames from received LoRa packets.
#[derive(Default)]
pub struct Reassembler {
    /// The sequence of the split frame whose first half is held.
    seq: Option<u8>,
    buffer: Vec<u8>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take one received packet; returns a frame when one is complete.
    pub fn feed(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        let (&header, data) = packet.split_first()?;
        let sequence = header >> 4;
        let split = header & FLAG_SPLIT != 0;
        let ready = match (split, self.seq) {
            // The first half of a split frame, or the first half of a new
            // one when the held half's sequence differs.
            (true, None) => {
                self.start(sequence, data);
                false
            }
            (true, Some(seq)) if seq != sequence => {
                self.start(sequence, data);
                false
            }
            // Its second half.
            (true, Some(_)) => {
                self.buffer.extend_from_slice(data);
                self.seq = None;
                true
            }
            // A whole frame; a held half is dropped.
            (false, _) => {
                self.seq = None;
                self.buffer.clear();
                self.buffer.extend_from_slice(data);
                true
            }
        };
        if ready && !self.buffer.is_empty() {
            Some(std::mem::take(&mut self.buffer))
        } else {
            None
        }
    }

    fn start(&mut self, sequence: u8, data: &[u8]) {
        self.seq = Some(sequence);
        self.buffer.clear();
        self.buffer.extend_from_slice(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + 3) as u8).collect()
    }

    #[test]
    fn short_frames_are_one_packet_with_a_sequence_header() {
        let packets = packets(b"hello", 0xA7).unwrap();
        assert_eq!(packets, vec![[&[0xA0][..], b"hello"].concat()]);
        let packets = packets_of(254);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].len(), 255);
        assert_eq!(packets[0][0] & FLAG_SPLIT, 0);
    }

    fn packets_of(len: usize) -> Vec<Vec<u8>> {
        packets(&frame(len), 0x5F).unwrap()
    }

    #[test]
    fn long_frames_split_after_254_bytes() {
        for len in [255, 300, 508] {
            let packets = packets_of(len);
            assert_eq!(packets.len(), 2, "{len}");
            assert_eq!(packets[0].len(), 255);
            assert_eq!(packets[1].len(), 1 + len - 254);
            assert_eq!(packets[0][0], 0x51);
            assert_eq!(packets[1][0], 0x51);
            assert_eq!([&packets[0][1..], &packets[1][1..]].concat(), frame(len));
        }
        assert!(packets(&frame(509), 0).is_none());
    }

    #[test]
    fn frames_survive_the_round_trip() {
        let mut reassembler = Reassembler::new();
        for len in [1, 100, 254, 255, 400, 508] {
            let packets = packets(&frame(len), len as u8).unwrap();
            let mut got = None;
            for packet in &packets {
                got = reassembler.feed(packet);
            }
            assert_eq!(got, Some(frame(len)), "{len}");
        }
    }

    #[test]
    fn reassembly_follows_rnode_firmware() {
        let first_of = |seq: u8| [vec![(seq << 4) | FLAG_SPLIT], vec![1; 254]].concat();
        let second_of = |seq: u8| vec![(seq << 4) | FLAG_SPLIT, 2, 2];
        let mut r = Reassembler::new();
        // A whole frame in between drops the held half.
        assert_eq!(r.feed(&first_of(3)), None);
        assert_eq!(r.feed(&[0x30, 9, 9]), Some(vec![9, 9]));
        assert_eq!(r.feed(&second_of(3)), None);
        // A half with another sequence starts a new frame.
        assert_eq!(r.feed(&first_of(4)), None);
        assert_eq!(r.feed(&first_of(5)), None);
        let whole = r.feed(&second_of(5)).unwrap();
        assert_eq!(whole.len(), 256);
        assert_eq!(&whole[254..], &[2, 2]);
        // A header alone carries nothing.
        assert_eq!(r.feed(&[0x10]), None);
        assert_eq!(r.feed(&[]), None);
    }
}
