use alloc::vec::Vec;

use super::tables::{AnnounceEntry, PathEntry};
use super::types::InterfaceId;
use crate::constants;

/// Build raw bytes for a retransmitted announce (HEADER_2, TRANSPORT).
///
/// Layout:
/// ```text
/// [H2_TRANSPORT_flags][hops][transport_id:16][dest_hash:16][context][data]
/// ```
///
/// The flags byte preserves the lower 4 bits from the original packet
/// (destination_type + packet_type) and sets HEADER_2 + TRANSPORT.
pub fn build_retransmit_announce(
    entry: &AnnounceEntry,
    transport_identity_hash: &[u8; 16],
) -> Vec<u8> {
    // Determine the context byte
    let context = if entry.block_rebroadcasts {
        constants::CONTEXT_PATH_RESPONSE
    } else {
        constants::CONTEXT_NONE
    };

    // Build flags: HEADER_2(1) << 6 | context_flag << 5 | TRANSPORT(1) << 4 | (original lower 4 bits)
    // original lower 4 bits = destination_type << 2 | packet_type
    // For an announce: packet_type = ANNOUNCE(0x01), destination_type = SINGLE(0x00)
    // So lower bits = 0x01
    // But we preserve original flags from the raw packet
    let original_flags = if !entry.packet_raw.is_empty() {
        entry.packet_raw[0] & 0x0F
    } else {
        // Fallback: SINGLE ANNOUNCE
        (constants::DESTINATION_SINGLE << 2) | constants::PACKET_TYPE_ANNOUNCE
    };

    let new_flags = (constants::HEADER_2 << 6)
        | ((entry.context_flag & 0x01) << 5)
        | (constants::TRANSPORT_TRANSPORT << 4)
        | original_flags;

    let mut raw = Vec::new();
    raw.push(new_flags);
    raw.push(entry.hops);
    raw.extend_from_slice(transport_identity_hash);
    raw.extend_from_slice(&entry.destination_hash);
    raw.push(context);
    raw.extend_from_slice(&entry.packet_data);

    raw
}

/// Create a PathEntry and optionally an AnnounceEntry from a validated announce.
///
/// The AnnounceEntry is created only if `transport_enabled` is true and
/// `is_path_response` is false.
#[allow(clippy::too_many_arguments)]
pub fn process_validated_announce(
    destination_hash: [u8; 16],
    hops: u8,
    packet_data: &[u8],
    packet_raw: &[u8],
    packet_hash: [u8; 32],
    context_flag: u8,
    received_from: [u8; 16],
    receiving_interface: InterfaceId,
    now: f64,
    mut random_blobs: Vec<[u8; 10]>,
    random_blob: [u8; 10],
    expires: f64,
    rng_value: f64,
    transport_enabled: bool,
    is_path_response: bool,
    rate_blocked: bool,
    original_raw: Option<Vec<u8>>,
) -> (PathEntry, Option<AnnounceEntry>) {
    // Add the new blob if it's not already there
    if !random_blobs.contains(&random_blob) {
        random_blobs.push(random_blob);
        // Cap at MAX_RANDOM_BLOBS
        if random_blobs.len() > constants::MAX_RANDOM_BLOBS {
            let start = random_blobs.len() - constants::MAX_RANDOM_BLOBS;
            random_blobs = random_blobs[start..].to_vec();
        }
    }

    let path_entry = PathEntry {
        timestamp: now,
        next_hop: received_from,
        hops,
        expires,
        random_blobs,
        receiving_interface,
        packet_hash,
        announce_raw: original_raw,
    };

    let announce_entry = if transport_enabled && !is_path_response && !rate_blocked {
        let retransmit_timeout = now + (rng_value * constants::PATHFINDER_RW);

        Some(AnnounceEntry {
            timestamp: now,
            retransmit_timeout,
            retries: 0,
            received_from,
            hops,
            packet_raw: packet_raw.to_vec(),
            packet_data: packet_data.to_vec(),
            destination_hash,
            context_flag,
            local_rebroadcasts: 0,
            block_rebroadcasts: false,
            attached_interface: None,
        })
    } else {
        None
    };

    (path_entry, announce_entry)
}

/// Compute the path expiry time based on the receiving interface mode.
pub fn compute_path_expires(now: f64, interface_mode: u8) -> f64 {
    match interface_mode {
        constants::MODE_ACCESS_POINT => now + constants::AP_PATH_TIME,
        constants::MODE_ROAMING => now + constants::ROAMING_PATH_TIME,
        _ => now + constants::PATHFINDER_E,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_retransmit_announce_basic() {
        let entry = AnnounceEntry {
            timestamp: 1000.0,
            retransmit_timeout: 1001.0,
            retries: 0,
            received_from: [0xAA; 16],
            hops: 3,
            // Original packet: HEADER_1, BROADCAST, SINGLE, ANNOUNCE
            // flags = 0b00000001 = 0x01
            packet_raw: {
                let mut v = Vec::new();
                v.push(0x01); // flags: H1, broadcast, single, announce
                v.push(0x03); // hops
                v.extend_from_slice(&[0xDD; 16]); // dest
                v.push(0x00); // context
                v.extend_from_slice(&[0xEE; 10]); // data
                v
            },
            packet_data: vec![0xEE; 10],
            destination_hash: [0xDD; 16],
            context_flag: 0,
            local_rebroadcasts: 0,
            block_rebroadcasts: false,
            attached_interface: None,
        };

        let transport_hash = [0xBB; 16];
        let raw = build_retransmit_announce(&entry, &transport_hash);

        // Expected flags: H2(1)<<6 | ctx(0)<<5 | TRANSPORT(1)<<4 | 0x01 = 0x51
        assert_eq!(raw[0], 0x51);
        // Hops
        assert_eq!(raw[1], 3);
        // Transport ID
        assert_eq!(&raw[2..18], &[0xBB; 16]);
        // Destination hash
        assert_eq!(&raw[18..34], &[0xDD; 16]);
        // Context = NONE
        assert_eq!(raw[34], constants::CONTEXT_NONE);
        // Data
        assert_eq!(&raw[35..], &[0xEE; 10]);
    }

    #[test]
    fn test_build_retransmit_with_block_rebroadcasts() {
        let entry = AnnounceEntry {
            timestamp: 1000.0,
            retransmit_timeout: 1001.0,
            retries: 0,
            received_from: [0xAA; 16],
            hops: 2,
            packet_raw: vec![0x01, 0x02], // H1, announce
            packet_data: vec![0xFF; 5],
            destination_hash: [0xCC; 16],
            context_flag: 0,
            local_rebroadcasts: 0,
            block_rebroadcasts: true,
            attached_interface: None,
        };

        let raw = build_retransmit_announce(&entry, &[0x11; 16]);
        // Context should be PATH_RESPONSE
        assert_eq!(raw[34], constants::CONTEXT_PATH_RESPONSE);
    }

    #[test]
    fn test_build_retransmit_with_context_flag() {
        let entry = AnnounceEntry {
            timestamp: 1000.0,
            retransmit_timeout: 1001.0,
            retries: 0,
            received_from: [0xAA; 16],
            hops: 1,
            packet_raw: vec![0x21, 0x01], // H1, context_flag=1, announce
            packet_data: vec![],
            destination_hash: [0xCC; 16],
            context_flag: 1, // FLAG_SET (ratchet)
            local_rebroadcasts: 0,
            block_rebroadcasts: false,
            attached_interface: None,
        };

        let raw = build_retransmit_announce(&entry, &[0x22; 16]);
        // flags: H2(1)<<6 | ctx_flag(1)<<5 | TRANSPORT(1)<<4 | 0x01 = 0x71
        assert_eq!(raw[0], 0x71);
    }

    #[test]
    fn test_process_validated_announce_with_transport() {
        let dest_hash = [0xAA; 16];
        let blob = [0xBB; 10];
        let data = [0xCC; 20];
        let raw = [0xDD; 30];
        let hash = [0xEE; 32];

        let (path, announce) = process_validated_announce(
            dest_hash,
            3,
            &data,
            &raw,
            hash,
            0,
            [0x11; 16],
            InterfaceId(1),
            1000.0,
            Vec::new(),
            blob,
            2000.0,
            0.5,
            true,  // transport enabled
            false, // not path response
            false, // not rate blocked
            None,
        );

        assert_eq!(path.hops, 3);
        assert_eq!(path.next_hop, [0x11; 16]);
        assert_eq!(path.expires, 2000.0);
        assert!(path.random_blobs.contains(&blob));

        let ann = announce.unwrap();
        assert_eq!(ann.hops, 3);
        assert_eq!(ann.destination_hash, dest_hash);
        // retransmit_timeout = 1000.0 + 0.5 * PATHFINDER_RW(0.5) = 1000.25
        assert!((ann.retransmit_timeout - 1000.25).abs() < 0.001);
    }

    #[test]
    fn test_process_validated_announce_no_transport() {
        let (path, announce) = process_validated_announce(
            [0xAA; 16],
            2,
            &[],
            &[],
            [0; 32],
            0,
            [0x11; 16],
            InterfaceId(1),
            1000.0,
            Vec::new(),
            [0xBB; 10],
            2000.0,
            0.5,
            false, // transport disabled
            false,
            false,
            None,
        );

        assert_eq!(path.hops, 2);
        assert!(announce.is_none());
    }

    #[test]
    fn test_process_validated_announce_path_response_no_retransmit() {
        let (_, announce) = process_validated_announce(
            [0xAA; 16],
            2,
            &[],
            &[],
            [0; 32],
            0,
            [0x11; 16],
            InterfaceId(1),
            1000.0,
            Vec::new(),
            [0xBB; 10],
            2000.0,
            0.5,
            true,
            true, // path response → no announce entry
            false,
            None,
        );

        assert!(announce.is_none());
    }

    #[test]
    fn test_process_validated_announce_rate_blocked() {
        let (_, announce) = process_validated_announce(
            [0xAA; 16],
            2,
            &[],
            &[],
            [0; 32],
            0,
            [0x11; 16],
            InterfaceId(1),
            1000.0,
            Vec::new(),
            [0xBB; 10],
            2000.0,
            0.5,
            true,
            false,
            true, // rate blocked → no announce entry
            None,
        );

        assert!(announce.is_none());
    }

    #[test]
    fn test_process_validated_announce_caps_blobs() {
        let mut existing_blobs: Vec<[u8; 10]> = Vec::new();
        for i in 0..constants::MAX_RANDOM_BLOBS {
            let mut b = [0u8; 10];
            b[0] = i as u8;
            existing_blobs.push(b);
        }

        let new_blob = [0xFF; 10];
        let (path, _) = process_validated_announce(
            [0xAA; 16],
            1,
            &[],
            &[],
            [0; 32],
            0,
            [0; 16],
            InterfaceId(1),
            1000.0,
            existing_blobs,
            new_blob,
            2000.0,
            0.5,
            false,
            false,
            false,
            None,
        );

        assert_eq!(path.random_blobs.len(), constants::MAX_RANDOM_BLOBS);
        assert!(path.random_blobs.contains(&new_blob));
        // The oldest blob (index 0) should have been dropped
        assert!(!path.random_blobs.contains(&[0u8; 10]));
    }

    #[test]
    fn test_compute_path_expires() {
        let now = 1000.0;
        assert_eq!(
            compute_path_expires(now, constants::MODE_ACCESS_POINT),
            now + constants::AP_PATH_TIME
        );
        assert_eq!(
            compute_path_expires(now, constants::MODE_ROAMING),
            now + constants::ROAMING_PATH_TIME
        );
        assert_eq!(
            compute_path_expires(now, constants::MODE_FULL),
            now + constants::PATHFINDER_E
        );
    }
}
