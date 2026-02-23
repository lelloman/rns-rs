use super::tables::PathEntry;
use crate::constants;

/// Extract emission timestamp from bytes [5:10] of a random_blob (big-endian u64).
pub fn timebase_from_random_blob(blob: &[u8; 10]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes[3..8].copy_from_slice(&blob[5..10]);
    u64::from_be_bytes(bytes)
}

/// Maximum emission timestamp across all random blobs.
pub fn timebase_from_random_blobs(blobs: &[[u8; 10]]) -> u64 {
    let mut timebase: u64 = 0;
    for blob in blobs {
        let emitted = timebase_from_random_blob(blob);
        if emitted > timebase {
            timebase = emitted;
        }
    }
    timebase
}

/// Extract the random_blob from announce packet data.
///
/// Located at offset `KEYSIZE/8 + NAME_HASH_LENGTH/8` = 64 + 10 = 74,
/// length 10 bytes.
pub fn extract_random_blob(packet_data: &[u8]) -> Option<[u8; 10]> {
    let offset = constants::KEYSIZE / 8 + constants::NAME_HASH_LENGTH / 8;
    if packet_data.len() < offset + 10 {
        return None;
    }
    let mut blob = [0u8; 10];
    blob.copy_from_slice(&packet_data[offset..offset + 10]);
    Some(blob)
}

#[derive(Debug, PartialEq, Eq)]
pub enum PathDecision {
    Add,
    Reject,
}

/// Full path update decision tree from Transport.py:1604-1686.
///
/// Determines whether an incoming announce should update the path table.
pub fn should_update_path(
    existing: Option<&PathEntry>,
    announce_hops: u8,
    announce_emitted_ts: u64,
    random_blob: &[u8; 10],
    path_is_unresponsive: bool,
    now: f64,
    prefer_shorter_path: bool,
) -> PathDecision {
    // Hop limit
    if announce_hops >= constants::PATHFINDER_M + 1 {
        return PathDecision::Reject;
    }

    let existing = match existing {
        None => return PathDecision::Add,
        Some(e) => e,
    };

    let path_timebase = timebase_from_random_blobs(&existing.random_blobs);
    let blob_is_new = !existing.random_blobs.contains(random_blob);

    if announce_hops <= existing.hops {
        // Accept strictly shorter path even with duplicate blob
        if prefer_shorter_path && announce_hops < existing.hops {
            return PathDecision::Add;
        }
        // Equal or fewer hops: accept if new blob AND newer emission
        if blob_is_new && announce_emitted_ts > path_timebase {
            return PathDecision::Add;
        }
        // Same emission + unresponsive path: accept for path recovery
        if announce_emitted_ts == path_timebase && path_is_unresponsive {
            return PathDecision::Add;
        }
        PathDecision::Reject
    } else {
        // More hops than existing path
        let path_expired = now >= existing.expires;

        if path_expired && blob_is_new {
            return PathDecision::Add;
        }

        if announce_emitted_ts > path_timebase && blob_is_new {
            return PathDecision::Add;
        }

        if announce_emitted_ts == path_timebase && path_is_unresponsive {
            return PathDecision::Add;
        }

        PathDecision::Reject
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::InterfaceId;

    fn make_blob(timebase: u64) -> [u8; 10] {
        let mut blob = [0u8; 10];
        let bytes = timebase.to_be_bytes();
        // timebase is stored in blob[5..10] = last 5 bytes of u64
        blob[5..10].copy_from_slice(&bytes[3..8]);
        blob
    }

    fn make_path_entry(hops: u8, blobs: &[[u8; 10]], expires: f64) -> PathEntry {
        PathEntry {
            timestamp: 1000.0,
            next_hop: [0xAA; 16],
            hops,
            expires,
            random_blobs: blobs.to_vec(),
            receiving_interface: InterfaceId(1),
            packet_hash: [0xBB; 32],
            announce_raw: None,
        }
    }

    #[test]
    fn test_timebase_extraction() {
        let blob = make_blob(12345);
        assert_eq!(timebase_from_random_blob(&blob), 12345);
    }

    #[test]
    fn test_timebase_from_multiple_blobs() {
        let b1 = make_blob(100);
        let b2 = make_blob(200);
        let b3 = make_blob(50);
        assert_eq!(timebase_from_random_blobs(&[b1, b2, b3]), 200);
    }

    #[test]
    fn test_timebase_empty_blobs() {
        assert_eq!(timebase_from_random_blobs(&[]), 0);
    }

    #[test]
    fn test_extract_random_blob() {
        // Need at least 74 + 10 = 84 bytes
        let mut data = [0u8; 100];
        // Put a known blob at offset 74
        data[74..84].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let blob = extract_random_blob(&data).unwrap();
        assert_eq!(blob, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn test_extract_random_blob_too_short() {
        let data = [0u8; 80]; // too short
        assert!(extract_random_blob(&data).is_none());
    }

    // --- Decision tree tests ---

    #[test]
    fn test_no_existing_path_always_add() {
        let blob = make_blob(100);
        assert_eq!(
            should_update_path(None, 3, 100, &blob, false, 1000.0, false),
            PathDecision::Add
        );
    }

    #[test]
    fn test_hop_limit_reject() {
        let blob = make_blob(100);
        assert_eq!(
            should_update_path(None, 129, 100, &blob, false, 1000.0, false),
            PathDecision::Reject
        );
    }

    #[test]
    fn test_fewer_hops_new_blob_newer_emission_add() {
        let old_blob = make_blob(100);
        let new_blob = make_blob(200);
        let entry = make_path_entry(5, &[old_blob], 9999.0);
        assert_eq!(
            should_update_path(Some(&entry), 3, 200, &new_blob, false, 1000.0, false),
            PathDecision::Add
        );
    }

    #[test]
    fn test_fewer_hops_duplicate_blob_reject() {
        let blob = make_blob(100);
        let entry = make_path_entry(5, &[blob], 9999.0);
        assert_eq!(
            should_update_path(Some(&entry), 3, 200, &blob, false, 1000.0, false),
            PathDecision::Reject
        );
    }

    #[test]
    fn test_fewer_hops_same_emission_unresponsive_add() {
        let old_blob = make_blob(100);
        let mut different_blob = [0u8; 10];
        different_blob[0] = 0xFF;
        different_blob[5..10].copy_from_slice(&100u64.to_be_bytes()[3..8]);

        let entry = make_path_entry(5, &[old_blob], 9999.0);
        assert_eq!(
            should_update_path(Some(&entry), 3, 100, &different_blob, true, 1000.0, false),
            PathDecision::Add
        );
    }

    #[test]
    fn test_fewer_hops_same_emission_responsive_reject() {
        let old_blob = make_blob(100);
        let mut different_blob = [0u8; 10];
        different_blob[0] = 0xFF;
        different_blob[5..10].copy_from_slice(&100u64.to_be_bytes()[3..8]);

        let entry = make_path_entry(5, &[old_blob], 9999.0);
        assert_eq!(
            should_update_path(Some(&entry), 3, 100, &different_blob, false, 1000.0, false),
            PathDecision::Reject
        );
    }

    #[test]
    fn test_more_hops_expired_path_new_blob_add() {
        let old_blob = make_blob(100);
        let new_blob = make_blob(50); // older emission but path expired
        let entry = make_path_entry(2, &[old_blob], 500.0); // expires at 500

        assert_eq!(
            should_update_path(Some(&entry), 5, 50, &new_blob, false, 600.0, false), // now > expires
            PathDecision::Add
        );
    }

    #[test]
    fn test_more_hops_not_expired_older_emission_reject() {
        let old_blob = make_blob(200);
        let new_blob = make_blob(100);
        let entry = make_path_entry(2, &[old_blob], 9999.0);

        assert_eq!(
            should_update_path(Some(&entry), 5, 100, &new_blob, false, 1000.0, false),
            PathDecision::Reject
        );
    }

    #[test]
    fn test_more_hops_newer_emission_new_blob_add() {
        let old_blob = make_blob(100);
        let new_blob = make_blob(200);
        let entry = make_path_entry(2, &[old_blob], 9999.0);

        assert_eq!(
            should_update_path(Some(&entry), 5, 200, &new_blob, false, 1000.0, false),
            PathDecision::Add
        );
    }

    #[test]
    fn test_more_hops_same_emission_unresponsive_add() {
        let old_blob = make_blob(100);
        let mut different_blob = [0u8; 10];
        different_blob[0] = 0xFF;
        different_blob[5..10].copy_from_slice(&100u64.to_be_bytes()[3..8]);

        let entry = make_path_entry(2, &[old_blob], 9999.0);

        assert_eq!(
            should_update_path(Some(&entry), 5, 100, &different_blob, true, 1000.0, false),
            PathDecision::Add
        );
    }

    #[test]
    fn test_more_hops_same_emission_responsive_reject() {
        let old_blob = make_blob(100);
        let mut different_blob = [0u8; 10];
        different_blob[0] = 0xFF;
        different_blob[5..10].copy_from_slice(&100u64.to_be_bytes()[3..8]);

        let entry = make_path_entry(2, &[old_blob], 9999.0);

        assert_eq!(
            should_update_path(Some(&entry), 5, 100, &different_blob, false, 1000.0, false),
            PathDecision::Reject
        );
    }

    #[test]
    fn test_more_hops_duplicate_blob_reject() {
        let blob = make_blob(200);
        let entry = make_path_entry(2, &[blob], 9999.0);

        assert_eq!(
            should_update_path(Some(&entry), 5, 200, &blob, false, 1000.0, false),
            PathDecision::Reject
        );
    }

    #[test]
    fn test_equal_hops_new_blob_newer_emission_add() {
        let old_blob = make_blob(100);
        let new_blob = make_blob(200);
        let entry = make_path_entry(3, &[old_blob], 9999.0);

        assert_eq!(
            should_update_path(Some(&entry), 3, 200, &new_blob, false, 1000.0, false),
            PathDecision::Add
        );
    }

    // --- prefer_shorter_path tests ---

    #[test]
    fn test_prefer_shorter_path_strictly_fewer_hops_duplicate_blob_add() {
        let blob = make_blob(100);
        let entry = make_path_entry(5, &[blob], 9999.0);
        assert_eq!(
            should_update_path(Some(&entry), 3, 100, &blob, false, 1000.0, true),
            PathDecision::Add
        );
    }

    #[test]
    fn test_prefer_shorter_path_equal_hops_duplicate_blob_reject() {
        // Equal hops with same blob: no benefit, still rejected
        let blob = make_blob(100);
        let entry = make_path_entry(3, &[blob], 9999.0);
        assert_eq!(
            should_update_path(Some(&entry), 3, 100, &blob, false, 1000.0, true),
            PathDecision::Reject
        );
    }

    #[test]
    fn test_prefer_shorter_path_more_hops_duplicate_blob_reject() {
        // More hops: prefer_shorter_path does not help
        let blob = make_blob(100);
        let entry = make_path_entry(2, &[blob], 9999.0);
        assert_eq!(
            should_update_path(Some(&entry), 5, 100, &blob, false, 1000.0, true),
            PathDecision::Reject
        );
    }
}
