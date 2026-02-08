use alloc::vec::Vec;

use crate::constants::CHANNEL_ENVELOPE_OVERHEAD;
use super::types::ChannelError;

/// Pack envelope: `[msgtype:u16 BE][sequence:u16 BE][length:u16 BE][payload]`.
pub fn pack_envelope(msgtype: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u16;
    let mut raw = Vec::with_capacity(CHANNEL_ENVELOPE_OVERHEAD + payload.len());
    raw.extend_from_slice(&msgtype.to_be_bytes());
    raw.extend_from_slice(&sequence.to_be_bytes());
    raw.extend_from_slice(&len.to_be_bytes());
    raw.extend_from_slice(payload);
    raw
}

/// Unpack envelope header. Returns `(msgtype, sequence, payload)`.
pub fn unpack_envelope(raw: &[u8]) -> Result<(u16, u16, &[u8]), ChannelError> {
    if raw.len() < CHANNEL_ENVELOPE_OVERHEAD {
        return Err(ChannelError::InvalidEnvelope);
    }

    let msgtype = u16::from_be_bytes([raw[0], raw[1]]);
    let sequence = u16::from_be_bytes([raw[2], raw[3]]);
    let length = u16::from_be_bytes([raw[4], raw[5]]) as usize;
    let payload = &raw[CHANNEL_ENVELOPE_OVERHEAD..];

    if payload.len() < length {
        return Err(ChannelError::InvalidEnvelope);
    }

    Ok((msgtype, sequence, &payload[..length]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let msgtype = 0x1234;
        let sequence = 42;
        let payload = b"Hello, Channel!";
        let packed = pack_envelope(msgtype, sequence, payload);
        let (mt, seq, pl) = unpack_envelope(&packed).unwrap();
        assert_eq!(mt, msgtype);
        assert_eq!(seq, sequence);
        assert_eq!(pl, payload);
    }

    #[test]
    fn test_empty_payload() {
        let packed = pack_envelope(0x0001, 0, &[]);
        assert_eq!(packed.len(), CHANNEL_ENVELOPE_OVERHEAD);
        let (mt, seq, pl) = unpack_envelope(&packed).unwrap();
        assert_eq!(mt, 1);
        assert_eq!(seq, 0);
        assert_eq!(pl.len(), 0);
    }

    #[test]
    fn test_max_sequence() {
        let packed = pack_envelope(0xFFFF, 0xFFFF, b"x");
        let (mt, seq, pl) = unpack_envelope(&packed).unwrap();
        assert_eq!(mt, 0xFFFF);
        assert_eq!(seq, 0xFFFF);
        assert_eq!(pl, b"x");
    }

    #[test]
    fn test_truncated_header() {
        assert_eq!(unpack_envelope(&[0, 1, 2]), Err(ChannelError::InvalidEnvelope));
    }

    #[test]
    fn test_truncated_payload() {
        // Header says 10 bytes of payload but only 2 available
        let mut data = Vec::new();
        data.extend_from_slice(&0x01u16.to_be_bytes());
        data.extend_from_slice(&0x00u16.to_be_bytes());
        data.extend_from_slice(&10u16.to_be_bytes());
        data.extend_from_slice(&[0xAA, 0xBB]);
        assert_eq!(unpack_envelope(&data), Err(ChannelError::InvalidEnvelope));
    }

    #[test]
    fn test_header_layout() {
        let packed = pack_envelope(0xABCD, 0x1234, &[0xFF]);
        assert_eq!(packed[0], 0xAB);
        assert_eq!(packed[1], 0xCD);
        assert_eq!(packed[2], 0x12);
        assert_eq!(packed[3], 0x34);
        assert_eq!(packed[4], 0x00);
        assert_eq!(packed[5], 0x01); // length = 1
        assert_eq!(packed[6], 0xFF);
    }

    #[test]
    fn test_large_payload() {
        let payload = vec![0x42u8; 400];
        let packed = pack_envelope(0x0001, 0, &payload);
        let (_, _, pl) = unpack_envelope(&packed).unwrap();
        assert_eq!(pl.len(), 400);
        assert_eq!(pl, &payload[..]);
    }

    #[test]
    fn test_extra_data_after_payload() {
        // If raw has more data than length says, only return up to length
        let mut packed = pack_envelope(0x0001, 0, &[0xAA, 0xBB]);
        packed.push(0xCC); // extra byte
        let (_, _, pl) = unpack_envelope(&packed).unwrap();
        assert_eq!(pl, &[0xAA, 0xBB]);
    }
}
