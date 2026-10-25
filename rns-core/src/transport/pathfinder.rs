use super::tables::{PathEntry, PathSet};
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

/// How far into the future (relative to our own clock) an announce emission
/// time may lie before we stop trusting it for path selection.
///
/// Bytes 5..10 of an announce's random blob carry its emission time in
/// seconds. Path selection only lets a newer announce displace an existing
/// path when its emission time is strictly greater than the path's timebase
/// (Transport.py, inbound announce handling, ~2236-2296). rns-rs releases
/// before 0.4.0 filled all ten bytes of some built-in announces (probe
/// responder, management, blackhole, interface discovery) randomly, which
/// yields "emission times" around 1e12 s, i.e. tens of thousands of years in
/// the future. Third-party nodes cached those announces and keep serving them
/// as path responses; once such a path is installed, no genuine announce can
/// ever beat its timebase, so it sticks until it expires (up to a week) and
/// fresh direct path responses are rejected.
///
/// One day comfortably covers ordinary clock skew between nodes while still
/// rejecting such garbage values. **This deliberately deviates from the
/// Python reference implementation**, which trusts any emission time.
pub const MAX_EMISSION_TIME_SKEW_SECS: u64 = 86_400;

/// Whether `emitted` (seconds since the epoch, from a random blob) is a
/// plausible emission time given our current time `now`.
///
/// See [`MAX_EMISSION_TIME_SKEW_SECS`].
pub fn is_plausible_emission_time(emitted: u64, now: f64) -> bool {
    (emitted as f64) <= now + MAX_EMISSION_TIME_SKEW_SECS as f64
}

/// The emission time to use when comparing an incoming announce against
/// existing paths: implausibly-future values are treated as unknown (0), so
/// they can never win on timestamp.
///
/// See [`MAX_EMISSION_TIME_SKEW_SECS`].
pub fn trusted_emission_time(emitted: u64, now: f64) -> u64 {
    if is_plausible_emission_time(emitted, now) {
        emitted
    } else {
        0
    }
}

/// Like [`timebase_from_random_blobs`], but ignores blobs whose emission
/// time is implausibly far in the future, so a cached garbage announce
/// cannot pin a path's timebase above every genuine announce.
///
/// See [`MAX_EMISSION_TIME_SKEW_SECS`].
pub fn trusted_timebase_from_random_blobs(blobs: &[[u8; 10]], now: f64) -> u64 {
    blobs
        .iter()
        .map(timebase_from_random_blob)
        .filter(|emitted| is_plausible_emission_time(*emitted, now))
        .max()
        .unwrap_or(0)
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
///
/// Emission times implausibly far in the future (see
/// [`MAX_EMISSION_TIME_SKEW_SECS`]) are ignored both in the stored blobs and
/// in the incoming announce, deliberately deviating from Python.
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
    if announce_hops > constants::PATHFINDER_M {
        return PathDecision::Reject;
    }

    let existing = match existing {
        None => return PathDecision::Add,
        Some(e) => e,
    };

    // Deliberate deviation from Transport.py: distrust implausibly-future
    // emission times so that announces with random emission bytes (pre-0.4.0
    // rns-rs) can neither pin a path nor win on timestamp. They can still be
    // accepted where Python ignores the timestamp (first path, shorter path
    // with prefer_shorter_path, expired path).
    let path_timebase = trusted_timebase_from_random_blobs(&existing.random_blobs, now);
    let announce_emitted_ts = trusted_emission_time(announce_emitted_ts, now);
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

/// Decision for multi-path announce processing.
#[derive(Debug, PartialEq, Eq)]
pub enum MultiPathDecision {
    /// Replace/update the primary path (or the path with the same next_hop).
    ReplacePrimary,
    /// Accept as an alternative path via a new next_hop.
    AddAlternative,
    /// Reject this announce.
    Reject,
}

/// Multi-path aware announce decision.
///
/// Determines whether an incoming announce should update the primary path,
/// be stored as an alternative, or be rejected.
///
/// - No existing `PathSet` → `ReplacePrimary` (first path for this dest)
/// - Same `next_hop` exists in the set → delegate to `should_update_path`
///   against **that** specific path entry
/// - New `next_hop` → accept as `AddAlternative` if the blob is genuinely
///   new (not in any stored path's blobs) and emission timestamp is valid
#[allow(clippy::too_many_arguments)]
pub fn decide_announce_multipath(
    existing_set: Option<&PathSet>,
    announce_hops: u8,
    announce_emitted_ts: u64,
    random_blob: &[u8; 10],
    next_hop: &[u8; 16],
    path_is_unresponsive: bool,
    now: f64,
    prefer_shorter_path: bool,
) -> MultiPathDecision {
    decide_announce_multipath_with_gravity(
        existing_set,
        announce_hops,
        announce_emitted_ts,
        random_blob,
        next_hop,
        path_is_unresponsive,
        now,
        prefer_shorter_path,
        None,
        None,
    )
}

/// Multi-path announce decision with interface gravity context.
#[allow(clippy::too_many_arguments)]
pub fn decide_announce_multipath_with_gravity(
    existing_set: Option<&PathSet>,
    announce_hops: u8,
    announce_emitted_ts: u64,
    random_blob: &[u8; 10],
    next_hop: &[u8; 16],
    path_is_unresponsive: bool,
    now: f64,
    prefer_shorter_path: bool,
    current_gravity: Option<i64>,
    announce_gravity: Option<i64>,
) -> MultiPathDecision {
    // Hop limit
    if announce_hops > constants::PATHFINDER_M {
        return MultiPathDecision::Reject;
    }

    let path_set = match existing_set {
        None => return MultiPathDecision::ReplacePrimary,
        Some(ps) if ps.is_empty() => return MultiPathDecision::ReplacePrimary,
        Some(ps) => ps,
    };

    if is_higher_gravity_replacement(
        path_set,
        announce_hops,
        announce_emitted_ts,
        now,
        current_gravity,
        announce_gravity,
    ) {
        return MultiPathDecision::ReplacePrimary;
    }

    // Check if there's already a path with the same next_hop
    if let Some(existing_path) = path_set.find_by_next_hop(next_hop) {
        let decision = should_update_path(
            Some(existing_path),
            announce_hops,
            announce_emitted_ts,
            random_blob,
            path_is_unresponsive,
            now,
            prefer_shorter_path,
        );
        match decision {
            PathDecision::Add => MultiPathDecision::ReplacePrimary,
            PathDecision::Reject => MultiPathDecision::Reject,
        }
    } else {
        // New next_hop — check if blob is genuinely new across all paths
        let all_blobs = path_set.all_random_blobs();
        let blob_is_new = !all_blobs.contains(random_blob);

        if !blob_is_new {
            return MultiPathDecision::Reject;
        }

        // Deliberate deviation from Transport.py: see MAX_EMISSION_TIME_SKEW_SECS.
        let max_timebase = trusted_timebase_from_random_blobs(&all_blobs, now);
        if trusted_emission_time(announce_emitted_ts, now) >= max_timebase {
            MultiPathDecision::AddAlternative
        } else {
            MultiPathDecision::Reject
        }
    }
}

/// Whether a same-emission announce should replace the primary path solely
/// because it arrived on an interface with higher gravity.
///
/// Implausibly-future emission times (see [`MAX_EMISSION_TIME_SKEW_SECS`])
/// only match an identical raw value, never a genuine timebase.
pub fn is_higher_gravity_replacement(
    path_set: &PathSet,
    announce_hops: u8,
    announce_emitted_ts: u64,
    now: f64,
    current_gravity: Option<i64>,
    announce_gravity: Option<i64>,
) -> bool {
    let (Some(primary), Some(current_gravity), Some(announce_gravity)) =
        (path_set.primary(), current_gravity, announce_gravity)
    else {
        return false;
    };
    // Deliberate deviation from Transport.py (see MAX_EMISSION_TIME_SKEW_SECS):
    // a plausible emission time is compared against the timebase of the
    // plausible blobs only. An implausible one only matches the exact same
    // raw value, i.e. the very same (garbage) emission re-heard, so it can
    // never displace a path learned from a genuine, more recent announce.
    let same_emission = if is_plausible_emission_time(announce_emitted_ts, now) {
        announce_emitted_ts == trusted_timebase_from_random_blobs(&primary.random_blobs, now)
    } else {
        announce_emitted_ts == timebase_from_random_blobs(&primary.random_blobs)
    };
    announce_hops <= primary.hops && same_emission && announce_gravity > current_gravity
}

#[cfg(test)]
mod tests {
    use super::super::types::InterfaceId;
    use super::*;

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
            used: 0.0,
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

    // --- MultiPathDecision tests ---

    #[test]
    fn test_multipath_no_existing_set_replace_primary() {
        let blob = make_blob(100);
        assert_eq!(
            decide_announce_multipath(None, 3, 100, &blob, &[0xBB; 16], false, 1000.0, false),
            MultiPathDecision::ReplacePrimary
        );
    }

    #[test]
    fn test_multipath_same_nexthop_update() {
        let blob_old = make_blob(100);
        let blob_new = make_blob(200);
        let entry = make_path_entry(3, &[blob_old], 9999.0);
        let ps = PathSet::from_single(entry, 3);

        // Same next_hop, newer blob → ReplacePrimary
        assert_eq!(
            decide_announce_multipath(
                Some(&ps),
                2,
                200,
                &blob_new,
                &[0xAA; 16],
                false,
                1000.0,
                false
            ),
            MultiPathDecision::ReplacePrimary
        );
    }

    #[test]
    fn test_multipath_same_nexthop_reject() {
        let blob = make_blob(100);
        let entry = make_path_entry(3, &[blob], 9999.0);
        let ps = PathSet::from_single(entry, 3);

        // Same next_hop, same blob → Reject
        assert_eq!(
            decide_announce_multipath(Some(&ps), 3, 100, &blob, &[0xAA; 16], false, 1000.0, false),
            MultiPathDecision::Reject
        );
    }

    #[test]
    fn test_multipath_new_nexthop_novel_blob_add_alternative() {
        let blob_existing = make_blob(100);
        let blob_new = make_blob(200);
        let entry = make_path_entry(3, &[blob_existing], 9999.0);
        let ps = PathSet::from_single(entry, 3);

        // Different next_hop, novel blob, newer emission → AddAlternative
        assert_eq!(
            decide_announce_multipath(
                Some(&ps),
                4,
                200,
                &blob_new,
                &[0xCC; 16],
                false,
                1000.0,
                false
            ),
            MultiPathDecision::AddAlternative
        );
    }

    #[test]
    fn test_multipath_new_nexthop_known_blob_reject() {
        let blob = make_blob(100);
        let entry = make_path_entry(3, &[blob], 9999.0);
        let ps = PathSet::from_single(entry, 3);

        // Different next_hop but blob already known → Reject
        assert_eq!(
            decide_announce_multipath(Some(&ps), 4, 100, &blob, &[0xCC; 16], false, 1000.0, false),
            MultiPathDecision::Reject
        );
    }

    #[test]
    fn test_multipath_new_nexthop_older_emission_reject() {
        let blob_existing = make_blob(200);
        let blob_new = make_blob(100); // older emission
        let entry = make_path_entry(3, &[blob_existing], 9999.0);
        let ps = PathSet::from_single(entry, 3);

        // Novel blob but older emission timestamp → Reject
        assert_eq!(
            decide_announce_multipath(
                Some(&ps),
                4,
                100,
                &blob_new,
                &[0xCC; 16],
                false,
                1000.0,
                false
            ),
            MultiPathDecision::Reject
        );
    }

    #[test]
    fn test_multipath_hop_limit_reject() {
        let blob = make_blob(100);
        assert_eq!(
            decide_announce_multipath(None, 129, 100, &blob, &[0xBB; 16], false, 1000.0, false),
            MultiPathDecision::Reject
        );
    }

    #[test]
    fn same_emission_prefers_strictly_higher_gravity() {
        let blob = make_blob(100);
        let entry = make_path_entry(3, &[blob], 9999.0);
        let ps = PathSet::from_single(entry, 3);

        let decide = |current, incoming, hops| {
            decide_announce_multipath_with_gravity(
                Some(&ps),
                hops,
                100,
                &blob,
                &[0xCC; 16],
                false,
                1000.0,
                false,
                Some(current),
                Some(incoming),
            )
        };

        assert_eq!(decide(0, 1, 3), MultiPathDecision::ReplacePrimary);
        assert_eq!(decide(-5, -2, 3), MultiPathDecision::ReplacePrimary);
        assert_eq!(decide(1, 1, 3), MultiPathDecision::Reject);
        assert_eq!(decide(2, 1, 3), MultiPathDecision::Reject);
        assert_eq!(decide(0, 1, 4), MultiPathDecision::Reject);

        assert!(is_higher_gravity_replacement(
            &ps,
            3,
            100,
            1000.0,
            Some(0),
            Some(1)
        ));
        assert!(!is_higher_gravity_replacement(
            &ps,
            3,
            100,
            1000.0,
            Some(1),
            Some(1)
        ));
        assert_eq!(crate::logging::GRAVITY_UPDATE_LOG_LEVEL, log::Level::Trace);
        assert_eq!(crate::logging::PATHING_LOG_TARGET, "rns::pathing");
    }

    // --- Implausibly-future emission times (deliberate deviation from Python) ---

    /// Roughly "now" at the time of writing, in Unix seconds.
    const NOW: f64 = 1_790_000_000.0;
    /// An emission time decoded from a pre-0.4.0 rns-rs built-in announce
    /// whose ten random-blob bytes were all random (observed live).
    const GARBAGE_TS: u64 = 1_076_900_000_000;

    fn blob_with(tag: u8, timebase: u64) -> [u8; 10] {
        let mut blob = make_blob(timebase);
        blob[0] = tag;
        blob
    }

    #[test]
    fn plausible_emission_time_tolerates_skew_up_to_limit() {
        let now_ts = NOW as u64;
        assert!(is_plausible_emission_time(now_ts, NOW));
        assert!(is_plausible_emission_time(0, NOW));
        assert!(is_plausible_emission_time(
            now_ts + MAX_EMISSION_TIME_SKEW_SECS,
            NOW
        ));
        assert!(!is_plausible_emission_time(
            now_ts + MAX_EMISSION_TIME_SKEW_SECS + 1,
            NOW
        ));
        assert!(!is_plausible_emission_time(GARBAGE_TS, NOW));
        assert_eq!(trusted_emission_time(now_ts, NOW), now_ts);
        assert_eq!(trusted_emission_time(GARBAGE_TS, NOW), 0);
    }

    #[test]
    fn trusted_timebase_ignores_garbage_blobs() {
        let genuine = blob_with(1, NOW as u64 - 10);
        let garbage = blob_with(2, GARBAGE_TS);
        assert_eq!(timebase_from_random_blobs(&[genuine, garbage]), GARBAGE_TS);
        assert_eq!(
            trusted_timebase_from_random_blobs(&[genuine, garbage], NOW),
            NOW as u64 - 10
        );
        assert_eq!(trusted_timebase_from_random_blobs(&[garbage], NOW), 0);
        assert_eq!(trusted_timebase_from_random_blobs(&[], NOW), 0);
    }

    /// Reproduction of the live poisoning: a third party serves a cached
    /// pre-0.4.0 announce with a garbage emission time, installing a 2-hop
    /// path; the destination's genuine direct 1-hop path response (emitted
    /// now) must replace it.
    #[test]
    fn repro_garbage_emission_blocks_direct_path_response() {
        let poisoned_blob = blob_with(0x11, GARBAGE_TS);
        let direct_blob = blob_with(0x22, NOW as u64);
        let third_party = [0xAA; 16];
        let direct = [0xDD; 16];

        for prefer_shorter_path in [false, true] {
            let mut poisoned = make_path_entry(2, &[poisoned_blob], NOW + 7.0 * 86_400.0);
            poisoned.next_hop = third_party;
            let mut ps = PathSet::from_single(poisoned, 3);

            let decision = decide_announce_multipath(
                Some(&ps),
                1,
                timebase_from_random_blob(&direct_blob),
                &direct_blob,
                &direct,
                false,
                NOW,
                prefer_shorter_path,
            );
            assert_ne!(
                decision,
                MultiPathDecision::Reject,
                "prefer_shorter_path={prefer_shorter_path}"
            );

            let mut entry = make_path_entry(1, &[direct_blob], NOW + 7.0 * 86_400.0);
            entry.next_hop = direct;
            match decision {
                MultiPathDecision::ReplacePrimary => ps.upsert_primary(entry),
                MultiPathDecision::AddAlternative => ps.upsert(entry),
                MultiPathDecision::Reject => unreachable!(),
            }
            let primary = ps.primary().unwrap();
            assert_eq!(primary.next_hop, direct);
            assert_eq!(primary.hops, 1);
        }
    }

    /// Same next hop: a genuine announce must be able to update a path whose
    /// stored blobs carry a garbage emission time.
    #[test]
    fn genuine_announce_replaces_garbage_path_same_next_hop() {
        let poisoned_blob = blob_with(0x11, GARBAGE_TS);
        let genuine_blob = blob_with(0x22, NOW as u64);
        let entry = make_path_entry(2, &[poisoned_blob], NOW + 86_400.0);

        for hops in [1, 2, 3] {
            assert_eq!(
                should_update_path(
                    Some(&entry),
                    hops,
                    NOW as u64,
                    &genuine_blob,
                    false,
                    NOW,
                    false
                ),
                PathDecision::Add,
                "hops={hops}"
            );
        }
    }

    #[test]
    fn garbage_announce_does_not_replace_genuine_path() {
        let genuine_blob = blob_with(0x11, NOW as u64 - 60);
        let garbage_blob = blob_with(0x22, GARBAGE_TS);
        let entry = make_path_entry(2, &[genuine_blob], NOW + 86_400.0);
        let ps = PathSet::from_single(entry.clone(), 3);

        for prefer_shorter_path in [false, true] {
            // Same next hop, equal or more hops: rejected.
            for hops in [2, 3] {
                assert_eq!(
                    should_update_path(
                        Some(&entry),
                        hops,
                        GARBAGE_TS,
                        &garbage_blob,
                        false,
                        NOW,
                        prefer_shorter_path
                    ),
                    PathDecision::Reject
                );
            }
            // New next hop, any hop count: rejected as an alternative.
            for hops in [1, 2, 3] {
                assert_eq!(
                    decide_announce_multipath(
                        Some(&ps),
                        hops,
                        GARBAGE_TS,
                        &garbage_blob,
                        &[0xCC; 16],
                        false,
                        NOW,
                        prefer_shorter_path
                    ),
                    MultiPathDecision::Reject
                );
            }
            // Never a gravity replacement against a genuine timebase.
            assert!(!is_higher_gravity_replacement(
                &ps,
                2,
                GARBAGE_TS,
                NOW,
                Some(0),
                Some(10)
            ));
        }

        // Fewer hops via the same next hop: without prefer_shorter_path the
        // garbage timestamp no longer wins (Python would accept it).
        assert_eq!(
            should_update_path(
                Some(&entry),
                1,
                GARBAGE_TS,
                &garbage_blob,
                false,
                NOW,
                false
            ),
            PathDecision::Reject
        );
        // With prefer_shorter_path the hop count alone decides, as for any
        // announce.
        assert_eq!(
            should_update_path(Some(&entry), 1, GARBAGE_TS, &garbage_blob, false, NOW, true),
            PathDecision::Add
        );
    }

    #[test]
    fn garbage_announce_still_accepted_as_first_or_after_expiry() {
        let garbage_blob = blob_with(0x22, GARBAGE_TS);
        assert_eq!(
            should_update_path(None, 3, GARBAGE_TS, &garbage_blob, false, NOW, false),
            PathDecision::Add
        );

        let genuine_blob = blob_with(0x11, NOW as u64 - 60);
        let expired = make_path_entry(2, &[genuine_blob], NOW - 1.0);
        assert_eq!(
            should_update_path(
                Some(&expired),
                3,
                GARBAGE_TS,
                &garbage_blob,
                false,
                NOW,
                false
            ),
            PathDecision::Add
        );
    }

    #[test]
    fn slightly_future_emission_within_tolerance_compares_normally() {
        let skewed_ts = NOW as u64 + 3_600;
        let current_ts = NOW as u64;
        let skewed_blob = blob_with(0x11, skewed_ts);
        let current_blob = blob_with(0x22, current_ts);

        // A slightly-future announce beats a current path...
        let entry = make_path_entry(2, &[current_blob], NOW + 86_400.0);
        assert_eq!(
            should_update_path(Some(&entry), 2, skewed_ts, &skewed_blob, false, NOW, false),
            PathDecision::Add
        );

        // ...and a slightly-future path still blocks an older announce.
        let entry = make_path_entry(2, &[skewed_blob], NOW + 86_400.0);
        assert_eq!(
            should_update_path(
                Some(&entry),
                2,
                current_ts,
                &current_blob,
                false,
                NOW,
                false
            ),
            PathDecision::Reject
        );
        let ps = PathSet::from_single(entry, 3);
        assert_eq!(
            decide_announce_multipath(
                Some(&ps),
                1,
                current_ts,
                &current_blob,
                &[0xCC; 16],
                false,
                NOW,
                false
            ),
            MultiPathDecision::Reject
        );
    }
}
