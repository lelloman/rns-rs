//! Channel messages carried in parts after a Direct Link fallback.
//!
//! On a direct path a link may use a larger MTU than on its original route,
//! so a channel envelope sent there may not fit a packet of the original
//! route once the link falls back. Such an envelope keeps its place in the
//! channel's sequence and is resent in pieces, each in a `CHANNEL_PART`
//! signalling message small enough for the original route; the peer
//! reassembles the envelope, hands it to its channel as if it had arrived
//! in one packet, and answers `CHANNEL_PART_ACK`, which stands for the
//! proof the sender would otherwise wait for. Only peers that ran a link
//! over a direct path exchange them, so links that never upgraded never
//! carry them.
//!
//! `CHANNEL_PART` body: `{"q": sequence, "i": part index, "n": part count,
//! "d": part bytes}`; `CHANNEL_PART_ACK` body: `{"q": sequence}`.

use alloc::vec::Vec;

use super::types::{HolePunchError, DIRECT_MAX_PACKET};
use crate::msgpack::{self, pack_bin, pack_uint};

/// Most bytes a framed `CHANNEL_PART` adds around its part bytes: the
/// signalling header (2), the map header (1), the keys (4 × 2), the
/// sequence (up to 3), index and count (1 each) and the bin header (up to
/// 3).
pub const CHANNEL_PART_OVERHEAD: usize = 19;

/// Most parts an envelope is split into. An envelope is never larger than
/// [`DIRECT_MAX_PACKET`], and a link's MDU is never below the base one, so
/// a handful always suffice.
pub const MAX_CHANNEL_PARTS: u8 = 16;

/// Envelopes reassembled at once on a link; a part of another one evicts
/// the oldest (its sender resends every part on its next retry).
pub const MAX_PENDING_ENVELOPES: usize = 4;

/// One decoded `CHANNEL_PART`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelPart<'a> {
    /// Channel sequence of the envelope it belongs to.
    pub sequence: u16,
    /// Position of this part, from 0.
    pub index: u8,
    /// Number of parts of the envelope.
    pub count: u8,
    /// This part's bytes of the envelope.
    pub data: &'a [u8],
}

/// Part bytes per `CHANNEL_PART` on a link with MDU `link_mdu`.
pub fn channel_part_size(link_mdu: usize) -> usize {
    link_mdu.saturating_sub(CHANNEL_PART_OVERHEAD)
}

/// Encode a `CHANNEL_PART` body.
pub fn encode_channel_part(part: &ChannelPart<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(CHANNEL_PART_OVERHEAD + part.data.len());
    out.push(0x84);
    out.extend_from_slice(&[0xa1, b'q']);
    pack_uint(part.sequence as u64, &mut out);
    out.extend_from_slice(&[0xa1, b'i']);
    pack_uint(part.index as u64, &mut out);
    out.extend_from_slice(&[0xa1, b'n']);
    pack_uint(part.count as u64, &mut out);
    out.extend_from_slice(&[0xa1, b'd']);
    pack_bin(part.data, &mut out);
    out
}

/// Decode a `CHANNEL_PART` body. A part outside its count, a count of 0 or
/// above [`MAX_CHANNEL_PARTS`], or an empty part is malformed.
pub fn decode_channel_part(body: &[u8]) -> Result<ChannelPart<'_>, HolePunchError> {
    let value = msgpack::unpack_exact_ref(body).map_err(|_| HolePunchError::InvalidPayload)?;
    let field = |key| {
        value
            .map_get(key)
            .and_then(|v| v.as_uint())
            .ok_or(HolePunchError::InvalidPayload)
    };
    let sequence = u16::try_from(field("q")?).map_err(|_| HolePunchError::InvalidPayload)?;
    let index = field("i")?;
    let count = field("n")?;
    let data = value
        .map_get("d")
        .and_then(|v| v.as_bin())
        .ok_or(HolePunchError::InvalidPayload)?;
    if count == 0 || count > MAX_CHANNEL_PARTS as u64 || index >= count || data.is_empty() {
        return Err(HolePunchError::InvalidPayload);
    }
    Ok(ChannelPart {
        sequence,
        index: index as u8,
        count: count as u8,
        data,
    })
}

/// Encode a `CHANNEL_PART_ACK` body.
pub fn encode_channel_part_ack(sequence: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.push(0x81);
    out.extend_from_slice(&[0xa1, b'q']);
    pack_uint(sequence as u64, &mut out);
    out
}

/// Decode a `CHANNEL_PART_ACK` body into the sequence it acknowledges.
pub fn decode_channel_part_ack(body: &[u8]) -> Result<u16, HolePunchError> {
    let value = msgpack::unpack_exact_ref(body).map_err(|_| HolePunchError::InvalidPayload)?;
    value
        .map_get("q")
        .and_then(|v| v.as_uint())
        .and_then(|q| u16::try_from(q).ok())
        .ok_or(HolePunchError::InvalidPayload)
}

struct PendingEnvelope {
    sequence: u16,
    parts: Vec<Option<Vec<u8>>>,
    len: usize,
}

/// Reassembles envelopes from their `CHANNEL_PART`s. Empty until the first
/// part arrives, and holds at most [`MAX_PENDING_ENVELOPES`] envelopes of
/// at most [`DIRECT_MAX_PACKET`] bytes.
#[derive(Default)]
pub struct ChannelPartAssembler {
    pending: Vec<PendingEnvelope>,
}

impl ChannelPartAssembler {
    /// Add a part; returns the whole envelope once its last part is in.
    /// A part whose count disagrees with the parts already held for its
    /// sequence starts that envelope over; one that would make it larger
    /// than [`DIRECT_MAX_PACKET`] drops it.
    pub fn insert(&mut self, part: ChannelPart<'_>) -> Option<Vec<u8>> {
        let position = match self
            .pending
            .iter()
            .position(|pending| pending.sequence == part.sequence)
        {
            Some(position) if self.pending[position].parts.len() == part.count as usize => position,
            found => {
                if let Some(position) = found {
                    self.pending.remove(position);
                } else if self.pending.len() >= MAX_PENDING_ENVELOPES {
                    self.pending.remove(0);
                }
                self.pending.push(PendingEnvelope {
                    sequence: part.sequence,
                    parts: alloc::vec![None; part.count as usize],
                    len: 0,
                });
                self.pending.len() - 1
            }
        };
        let pending = &mut self.pending[position];
        let slot = &mut pending.parts[part.index as usize];
        if slot.is_none() {
            pending.len += part.data.len();
            if pending.len > DIRECT_MAX_PACKET as usize {
                self.pending.remove(position);
                return None;
            }
            *slot = Some(part.data.to_vec());
        }
        if pending.parts.iter().any(Option::is_none) {
            return None;
        }
        let pending = self.pending.remove(position);
        let mut envelope = Vec::with_capacity(pending.len);
        for data in pending.parts.into_iter().flatten() {
            envelope.extend_from_slice(&data);
        }
        Some(envelope)
    }

    /// Number of envelopes partly received.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::holepunch::types::{decode_signal, encode_signal, CHANNEL_PART};

    fn part(sequence: u16, index: u8, count: u8, data: &[u8]) -> ChannelPart<'_> {
        ChannelPart {
            sequence,
            index,
            count,
            data,
        }
    }

    #[test]
    fn part_round_trips_within_its_overhead() {
        let data = alloc::vec![0x5a; 1000];
        for sequence in [0, 0x7f, 0x80, 0xffff] {
            let sent = part(sequence, MAX_CHANNEL_PARTS - 1, MAX_CHANNEL_PARTS, &data);
            let framed = encode_signal(CHANNEL_PART, &encode_channel_part(&sent));
            assert!(framed.len() <= data.len() + CHANNEL_PART_OVERHEAD);
            let (kind, body) = decode_signal(&framed).unwrap();
            assert_eq!(kind, CHANNEL_PART);
            assert_eq!(decode_channel_part(body), Ok(sent));
        }
        let sent = part(0xffff, 0, 1, &[1]);
        assert_eq!(decode_channel_part(&encode_channel_part(&sent)), Ok(sent));
    }

    #[test]
    fn malformed_parts_are_refused() {
        for bad in [
            part(1, 2, 2, b"x"),
            part(1, 0, 0, b"x"),
            part(1, 0, MAX_CHANNEL_PARTS + 1, b"x"),
            part(1, 0, 2, b""),
        ] {
            assert_eq!(
                decode_channel_part(&encode_channel_part(&bad)),
                Err(HolePunchError::InvalidPayload)
            );
        }
        assert!(decode_channel_part(&[0x80]).is_err());
        assert!(decode_channel_part(&encode_channel_part_ack(3)).is_err());
    }

    #[test]
    fn ack_round_trips() {
        for sequence in [0, 200, 0xffff] {
            assert_eq!(
                decode_channel_part_ack(&encode_channel_part_ack(sequence)),
                Ok(sequence)
            );
        }
        assert!(decode_channel_part_ack(&[0x80]).is_err());
    }

    #[test]
    fn envelope_is_whole_once_every_part_is_in_whatever_the_order() {
        let envelope: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let chunks: Vec<&[u8]> = envelope.chunks(400).collect();
        let mut assembler = ChannelPartAssembler::default();
        assert_eq!(assembler.insert(part(7, 2, 3, chunks[2])), None);
        assert_eq!(assembler.insert(part(7, 0, 3, chunks[0])), None);
        // A repeated part changes nothing.
        assert_eq!(assembler.insert(part(7, 0, 3, chunks[0])), None);
        assert_eq!(assembler.insert(part(7, 1, 3, chunks[1])), Some(envelope));
        assert_eq!(assembler.pending(), 0);
    }

    #[test]
    fn a_new_count_starts_the_envelope_over() {
        let mut assembler = ChannelPartAssembler::default();
        assert_eq!(assembler.insert(part(1, 0, 3, b"aa")), None);
        assert_eq!(assembler.insert(part(1, 0, 2, b"bb")), None);
        assert_eq!(
            assembler.insert(part(1, 1, 2, b"cc")),
            Some(b"bbcc".to_vec())
        );
    }

    #[test]
    fn pending_envelopes_are_bounded() {
        let mut assembler = ChannelPartAssembler::default();
        for sequence in 0..=MAX_PENDING_ENVELOPES as u16 {
            assembler.insert(part(sequence, 0, 2, b"a"));
        }
        assert_eq!(assembler.pending(), MAX_PENDING_ENVELOPES);
        // The oldest went first.
        assert_eq!(assembler.insert(part(0, 1, 2, b"b")), None);
        let last = MAX_PENDING_ENVELOPES as u16;
        assert_eq!(
            assembler.insert(part(last, 1, 2, b"b")),
            Some(b"ab".to_vec())
        );

        let big = alloc::vec![0; DIRECT_MAX_PACKET as usize];
        let mut assembler = ChannelPartAssembler::default();
        assert_eq!(assembler.insert(part(9, 0, 2, &big)), None);
        assert_eq!(assembler.insert(part(9, 1, 2, b"x")), None);
        assert_eq!(assembler.pending(), 0);
    }

    #[test]
    fn part_size_leaves_room_for_the_overhead() {
        assert_eq!(channel_part_size(431), 431 - CHANNEL_PART_OVERHEAD);
        assert_eq!(channel_part_size(10), 0);
    }
}
