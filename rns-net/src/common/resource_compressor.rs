//! Compression of outgoing Resources: bzip2, skipped for large payloads in
//! which nothing looks compressible.
//!
//! Upstream runs a full bzip2 attempt on every Resource segment and sends the
//! segment uncompressed when that does not shrink it. On incompressible data
//! (already compressed or encrypted files) that attempt is wasted, and it is
//! most of the sender's CPU time. An uncompressed segment is always valid on
//! the wire, so a sender may skip the attempt; what it must not do is skip it
//! on data bzip2 would have shrunk, since on slow links the bytes cost more
//! than the CPU.
//!
//! Payloads below [`SCREEN_MIN_SIZE`] get the full attempt, exactly as
//! upstream. A larger payload gets it unless all of these checks pass:
//!
//! 1. Distribution: for the bytes, and for their differences at distances
//!    1, 2 and 4 ([`LAGS`]), coding each [`CHUNK_SIZE`] chunk by its own
//!    byte distribution would save under a thousandth of the payload
//!    ([`SAVINGS_LIMIT_PER_MILLE`]), as estimated from chi-square. This
//!    looks at every byte. bzip2 adds about 5 thousandths to random data,
//!    and gains less than this estimate from byte frequencies, so skew it
//!    could save on is caught wherever it is. The differences catch data
//!    whose bytes are evenly spread but each close to the one before it
//!    (8-, 16- or 32-bit samples of a signal, counters).
//! 2. Repetition: the [`FINGERPRINT_SIZE`]-byte strings seen twice at
//!    content-defined anchors (one position in [`ANCHOR_SPACING`] on
//!    average) stand for under a thousandth of the payload, counting each
//!    as generously as a whole repeated string. This also looks at every
//!    byte, and catches repetition at any distance, such as a file stored
//!    twice, or records drawn from a small set, which have random byte
//!    distributions. A 1 MiB payload is flagged at five repeats, which a
//!    repeated run of about 100 bytes yields on average.
//! 3. Samples: no [`SAMPLE_SIZE`] window at the start, middle or end shrinks
//!    at all under bzip2: the compressor's own judgement, for structure of
//!    any other kind that runs through the payload.
//!
//! So the attempt is skipped only when neither skewed distributions nor
//! repeated strings anywhere in the payload could save a thousandth of it,
//! a fifth of what bzip2 adds to data it cannot compress, and bzip2 cannot
//! shrink the sampled windows. Compressible data can still pass only with
//! structure of another kind (strings under 16 bytes repeated with flat
//! byte frequencies, say) confined to the unsampled regions. A false
//! positive costs the full attempt, as before.
//!
//! On a 1 MiB segment of random data the checks take about an eighth of the
//! time of the bzip2 attempt they replace, most of it the samples.

use rns_core::buffer::{Compressor, DecompressError};

use super::compressor::Bzip2Compressor;
use super::FastHashSet;

/// Payloads below this size are always compressed in full.
pub(crate) const SCREEN_MIN_SIZE: usize = 256 * 1024;
/// Size of each window compressed as a sample.
const SAMPLE_SIZE: usize = 16 * 1024;
/// Chunk over which byte distributions are measured.
const CHUNK_SIZE: usize = 4 * 1024;
/// Mean chi-square of a chunk of random bytes (255 degrees of freedom).
const RANDOM_CHI_SQUARE: u64 = 255;
/// Estimated savings, in thousandths of the payload, above which skewed
/// distributions are taken as compressible. bzip2 adds about 5 thousandths
/// to random data, so a smaller saving does not shrink the payload.
const SAVINGS_LIMIT_PER_MILLE: u64 = 1;
/// Length of the strings whose repetition is looked for.
const FINGERPRINT_SIZE: usize = 16;
/// Average distance between content-defined anchors.
const ANCHOR_SPACING: u64 = 16;

/// bzip2 for Resource payloads: [`Bzip2Compressor`], except that a payload
/// in which [`worth_compressing`] finds nothing compressible is not
/// compressed. Decompression is [`Bzip2Compressor`]'s.
pub(crate) struct ResourceCompressor;

impl Compressor for ResourceCompressor {
    fn compress(&self, data: &[u8]) -> Option<Vec<u8>> {
        worth_compressing(data)
            .then(|| Bzip2Compressor.compress(data))
            .flatten()
    }

    fn decompress_bounded(
        &self,
        data: &[u8],
        max_output_size: usize,
    ) -> Result<Vec<u8>, DecompressError> {
        Bzip2Compressor.decompress_bounded(data, max_output_size)
    }
}

/// Whether a full bzip2 attempt on `data` may pay off; `false` only when the
/// checks in the module documentation find nothing compressible.
pub(crate) fn worth_compressing(data: &[u8]) -> bool {
    data.len() < SCREEN_MIN_SIZE
        || has_skewed_bytes(data)
        || has_repeated_strings(data)
        || has_compressible_sample(data)
}

/// Whether bzip2 shrinks a window at the start, middle or end of `data`.
fn has_compressible_sample(data: &[u8]) -> bool {
    let middle = (data.len() / 2).saturating_sub(SAMPLE_SIZE / 2);
    let end = data.len().saturating_sub(SAMPLE_SIZE);
    [0, middle, end].into_iter().any(|start| {
        let window = data.get(start..start + SAMPLE_SIZE).unwrap_or(data);
        // Level 1: within one 100 kB block, the output size is the same at
        // every level, and the codec's workspace is the smallest.
        let mut encoder = bzip2::read::BzEncoder::new(window, bzip2::Compression::fast());
        let mut compressed = Vec::with_capacity(window.len() + window.len() / 64 + 64);
        // A failed sample says nothing; leave the decision to the full attempt.
        std::io::Read::read_to_end(&mut encoder, &mut compressed).is_err()
            || compressed.len() < window.len()
    })
}

/// Distances of the byte differences whose distribution is checked, 0
/// standing for the bytes themselves. A difference is uniform on random
/// data, but skewed on data where each byte (or 16- or 32-bit value) is
/// close to the one before it, such as samples of a signal, even when the
/// bytes themselves are evenly spread.
const LAGS: [usize; 4] = [0, 1, 2, 4];

/// Whether the bytes, or their differences at some lag, are skewed enough
/// across `data` that coding each chunk by its own distribution could save
/// more than [`SAVINGS_LIMIT_PER_MILLE`].
///
/// Over the `n` bytes of a chunk, with `n / 256` expected per value,
/// chi-square is `256 * sum(count^2) / n - n`. It averages
/// [`RANDOM_CHI_SQUARE`] on random data, plus about `2 ln(2) * n` times the
/// entropy deficit in bits per byte; the excess over that mean, divided by
/// `16 ln(2)` (about 11), estimates the bytes order-0 coding saves. That
/// is close for slight skew and generous for strong skew, where chi-square
/// grows faster than the deficit. On random data the excesses add up to
/// about 0.2 thousandths of the payload.
fn has_skewed_bytes(data: &[u8]) -> bool {
    // Excess chi-square summed per lag, against estimated savings of
    // SAVINGS_LIMIT_PER_MILLE: 11 per byte saved.
    let limit = data.len() as u64 * 11 * SAVINGS_LIMIT_PER_MILLE / 1000;
    let mut excess = [0u64; LAGS.len()];
    let mut start = 0;
    while start < data.len() {
        let end = (start + CHUNK_SIZE).min(data.len());
        for (sum, lag) in excess.iter_mut().zip(LAGS) {
            let mut counts = [0u32; 256];
            let from = start.max(lag);
            let current = data.get(from..end).unwrap_or_default();
            if lag == 0 {
                for &byte in current {
                    if let Some(count) = counts.get_mut(usize::from(byte)) {
                        *count += 1;
                    }
                }
            } else {
                let previous = data.get(from - lag..end - lag).unwrap_or_default();
                for (&byte, &before) in current.iter().zip(previous) {
                    if let Some(count) = counts.get_mut(usize::from(byte.wrapping_sub(before))) {
                        *count += 1;
                    }
                }
            }
            *sum += excess_chi_square(&counts, current.len() as u64);
            if *sum > limit {
                return true;
            }
        }
        start = end;
    }
    false
}

/// Chi-square of `counts` over `n` bytes, less [`RANDOM_CHI_SQUARE`].
fn excess_chi_square(counts: &[u32; 256], n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let squares: u64 = counts.iter().map(|&c| u64::from(c) * u64::from(c)).sum();
    (256 * squares / n).saturating_sub(n + RANDOM_CHI_SQUARE)
}

/// A random value per byte for the gear rolling hash.
#[allow(
    clippy::indexing_slicing,
    reason = "the loop runs over the table's own indices; slice accessors are not const"
)]
const GEAR: [u64; 256] = {
    let mut table = [0u64; 256];
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut i = 0;
    while i < 256 {
        // splitmix64
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        table[i] = z ^ (z >> 31);
        i += 1;
    }
    table
};

/// Whether `data` repeats enough [`FINGERPRINT_SIZE`]-byte strings, as
/// seen at content-defined anchors, to save more than
/// [`SAVINGS_LIMIT_PER_MILLE`].
///
/// A gear hash shifted by four bits per byte depends on exactly the last 16
/// bytes, so equal strings hash equally wherever they occur. A position is
/// an anchor when the hash's top four bits are zero, which depends on the
/// string alone, so each copy of a repeated string has the same anchors.
///
/// One string in [`ANCHOR_SPACING`] is an anchor, so each repeat seen
/// stands for that many repeated strings, and each of those for at most
/// [`FINGERPRINT_SIZE`] bytes saved (when they are separate strings rather
/// than one run, whose strings overlap).
fn has_repeated_strings(data: &[u8]) -> bool {
    const SHIFT: u32 = (u64::BITS as usize / FINGERPRINT_SIZE) as u32;
    const ANCHOR_BITS: u32 = ANCHOR_SPACING.trailing_zeros();
    let limit = data.len() as u64 * SAVINGS_LIMIT_PER_MILLE
        / 1000
        / (ANCHOR_SPACING * FINGERPRINT_SIZE as u64);
    let mut seen = FastHashSet::default();
    seen.reserve(data.len() / ANCHOR_SPACING as usize);
    let mut repeats = 0;
    let mut hash: u64 = 0;
    for (index, &byte) in data.iter().enumerate() {
        let gear = GEAR.get(usize::from(byte)).copied().unwrap_or_default();
        hash = (hash << SHIFT).wrapping_add(gear);
        if index + 1 >= FINGERPRINT_SIZE
            && hash >> (u64::BITS - ANCHOR_BITS) == 0
            && !seen.insert(hash)
        {
            repeats += 1;
            if repeats > limit {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic bytes indistinguishable from random to bzip2.
    fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        let mut out = Vec::with_capacity(len + 8);
        while out.len() < len {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            out.extend_from_slice(&(z ^ (z >> 31)).to_le_bytes());
        }
        out.truncate(len);
        out
    }

    fn text(len: usize) -> Vec<u8> {
        let words = [
            "resource ",
            "segment ",
            "transfer ",
            "the ",
            "of ",
            "link ",
            "and ",
            "proof ",
            "a ",
            "packet ",
            "window ",
            "hashmap ",
            "to ",
            "is ",
            "upstream\n",
        ];
        let mut out = Vec::with_capacity(len + 16);
        let mut state = 7u64;
        while out.len() < len {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.extend_from_slice(words[(state >> 33) as usize % words.len()].as_bytes());
        }
        out.truncate(len);
        out
    }

    fn bzip2_shrinks(data: &[u8]) -> bool {
        Bzip2Compressor
            .compress(data)
            .is_some_and(|compressed| compressed.len() < data.len())
    }

    const SEGMENT: usize = rns_core::constants::RESOURCE_MAX_EFFICIENT_SIZE;

    /// An offset in the gap between the start and middle samples, away from
    /// chunk boundaries.
    const GAP: usize = SEGMENT / 4 + 1234;

    #[test]
    fn random_data_is_not_worth_compressing() {
        for (len, seed) in [
            (SCREEN_MIN_SIZE, 1),
            (SEGMENT, 2),
            (SEGMENT + 3, 3),
            (700_001, 4),
        ] {
            let data = random_bytes(len, seed);
            assert!(!worth_compressing(&data), "len {len}");
            assert!(!bzip2_shrinks(&data), "len {len}");
            assert_eq!(ResourceCompressor.compress(&data), None);
        }
    }

    #[test]
    fn small_payloads_always_get_the_full_attempt() {
        let data = random_bytes(SCREEN_MIN_SIZE - 1, 5);
        assert!(worth_compressing(&data));
        assert_eq!(
            ResourceCompressor.compress(&data),
            Bzip2Compressor.compress(&data)
        );
    }

    #[test]
    fn uniformly_compressible_data_compresses_exactly_as_before() {
        let periodic: Vec<u8> = (0..SEGMENT).map(|i| (i % 251) as u8).collect();
        let tokens = {
            // 16-byte random tokens from a set of 1000.
            let dictionary = random_bytes(16 * 1000, 6);
            let picks = random_bytes(SEGMENT / 16 * 2, 7);
            picks
                .chunks(2)
                .flat_map(|pick| {
                    let index = usize::from(u16::from_le_bytes([pick[0], pick[1]])) % 1000;
                    dictionary[index * 16..index * 16 + 16].to_vec()
                })
                .collect::<Vec<u8>>()
        };
        for (name, data) in [
            ("zeros", vec![0u8; SEGMENT]),
            ("text", text(SEGMENT)),
            ("periodic", periodic),
            ("tokens", tokens),
        ] {
            assert!(worth_compressing(&data), "{name}");
            let expected = Bzip2Compressor.compress(&data);
            assert!(
                expected.as_ref().is_some_and(|c| c.len() < data.len()),
                "{name}"
            );
            assert_eq!(ResourceCompressor.compress(&data), expected, "{name}");
        }
    }

    /// Random data with `region` written at `offset`, outside every sample.
    fn random_with(region: &[u8], offset: usize, seed: u64) -> Vec<u8> {
        let mut data = random_bytes(SEGMENT, seed);
        data[offset..offset + region.len()].copy_from_slice(region);
        assert!(!has_compressible_sample(&data));
        data
    }

    #[test]
    fn compressible_region_between_samples_is_found() {
        let base64ish: Vec<u8> = random_bytes(64 * 1024, 8)
            .iter()
            .map(|b| {
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                    [usize::from(b % 64)]
            })
            .collect();
        let hex: Vec<u8> = random_bytes(16 * 1024, 9)
            .iter()
            .map(|b| b"0123456789abcdef"[usize::from(b % 16)])
            .collect();
        for (name, region) in [
            ("zeros", vec![0u8; 8 * 1024]),
            ("text", text(8 * 1024)),
            ("base64", base64ish),
            ("hex", hex),
        ] {
            let data = random_with(&region, GAP, 10);
            assert!(worth_compressing(&data), "{name}");
        }
    }

    /// Random walks: each byte (or 16-bit value) a small random step from
    /// the one before, so that the bytes themselves are evenly spread.
    fn walk(len: usize, seed: u64, width: usize, step: u16) -> Vec<u8> {
        let steps = random_bytes(len, seed);
        let mut value = 0u16;
        let mut out = Vec::with_capacity(len + 2);
        for pair in steps.chunks(2) {
            let delta = u16::from_le_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]) % step;
            for _ in 0..(2 / width) {
                value = value.wrapping_add(delta);
                out.extend_from_slice(&value.to_le_bytes()[..width]);
            }
        }
        out.truncate(len);
        out
    }

    #[test]
    fn signal_like_data_is_found() {
        // 8-bit steps of up to 32 between the samples; 16-bit values with
        // steps of up to 600, spread through the whole payload.
        let region = walk(64 * 1024, 16, 1, 32);
        let data = random_with(&region, GAP, 17);
        assert!(!has_repeated_strings(&data));
        assert!(bzip2_shrinks(&data));
        assert!(worth_compressing(&data));

        let data = walk(SEGMENT, 18, 2, 600);
        assert!(bzip2_shrinks(&data));
        assert!(has_skewed_bytes(&data));
    }

    #[test]
    fn short_repeated_strings_between_samples_are_found() {
        // 16-byte random tokens from a set of 1000, placed between samples:
        // the byte distributions are those of random data.
        let dictionary = random_bytes(16 * 1000, 19);
        let picks = random_bytes(64 * 1024 / 16 * 2, 20);
        let region: Vec<u8> = picks
            .chunks(2)
            .flat_map(|pick| {
                let index = usize::from(u16::from_le_bytes([pick[0], pick[1]])) % 1000;
                dictionary[index * 16..index * 16 + 16].to_vec()
            })
            .collect();
        let data = random_with(&region, GAP, 21);
        assert!(bzip2_shrinks(&data));
        assert!(has_repeated_strings(&data));
    }

    #[test]
    fn weak_skew_spread_over_the_payload_is_found() {
        // Bytes drawn uniformly from 240 values: 7.91 bits each, which bzip2
        // turns into a saving of about 0.5 %.
        let data: Vec<u8> = random_bytes(SEGMENT * 2, 11)
            .into_iter()
            .filter(|&b| b < 240)
            .take(SEGMENT)
            .collect();
        assert_eq!(data.len(), SEGMENT);
        assert!(bzip2_shrinks(&data));
        assert!(worth_compressing(&data));
    }

    #[test]
    fn repetition_at_a_distance_is_found() {
        // A random 300 KiB repeated: no sample shrinks, yet bzip2 halves it
        // when both copies share a block.
        let half = random_bytes(300 * 1024, 12);
        let data = [half.as_slice(), half.as_slice()].concat();
        assert!(!has_compressible_sample(&data));
        assert!(has_repeated_strings(&data));
        assert!(bzip2_shrinks(&data));
        assert!(worth_compressing(&data));

        // A 32 KiB run copied between the samples.
        let mut data = random_bytes(SEGMENT, 13);
        let run = data[GAP..GAP + 32 * 1024].to_vec();
        data[GAP + 100_000..GAP + 100_000 + 32 * 1024].copy_from_slice(&run);
        assert!(has_repeated_strings(&data));
        assert!(bzip2_shrinks(&data));
    }

    /// Wherever a compressible region lies outside the samples, a payload
    /// that bzip2 would shrink is compressed. The regions are just large
    /// enough for bzip2 to shrink the payload.
    #[test]
    fn no_shrinkable_payload_is_skipped() {
        let hex: Vec<u8> = random_bytes(24 * 1024, 14)
            .iter()
            .map(|b| b"0123456789abcdef"[usize::from(b % 16)])
            .collect();
        let regions = [
            ("zeros", vec![0u8; 6 * 1024]),
            ("text", text(12 * 1024)),
            ("hex", hex),
        ];
        for (name, region) in regions {
            let last = SEGMENT - SAMPLE_SIZE - region.len() - 1;
            let mut offsets: Vec<usize> =
                (SAMPLE_SIZE + 1..last).step_by(97 * 1024 + 333).collect();
            offsets.push(last);
            for offset in offsets {
                if offset + region.len() > SEGMENT / 2 - SAMPLE_SIZE / 2
                    && offset < SEGMENT / 2 + SAMPLE_SIZE / 2
                {
                    continue;
                }
                let data = random_with(&region, offset, 15);
                assert!(worth_compressing(&data), "{name} at {offset}");
                assert!(
                    bzip2_shrinks(&data),
                    "{name} at {offset} is not a real case"
                );
            }
        }
    }

    #[test]
    fn skew_and_repeat_checks_pass_random_data() {
        for seed in 20..28 {
            let data = random_bytes(SEGMENT, seed);
            assert!(!has_skewed_bytes(&data), "seed {seed}");
            assert!(!has_repeated_strings(&data), "seed {seed}");
        }
    }
}
