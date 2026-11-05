//! SHA-256 over a block state of its own, so that two independent messages
//! can be compressed together (see [`update_pair`]); blocks go through the
//! `sha2` compression function otherwise.

use sha2::block_api::compress256;
use sha2::Digest;

const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    /// A block not yet complete.
    block: [u8; 64],
    block_len: usize,
    /// Bytes absorbed in total.
    len: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            state: INITIAL_STATE,
            block: [0; 64],
            block_len: 0,
            len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let rest = self.top_up(data);
        let (blocks, tail) = rest.as_chunks::<64>();
        compress256(&mut self.state, blocks);
        self.keep(tail);
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut padded = self.clone();
        let bits = padded.len.wrapping_mul(8);
        padded.block[padded.block_len] = 0x80;
        padded.block[padded.block_len + 1..].fill(0);
        if padded.block_len >= 56 {
            compress256(&mut padded.state, core::slice::from_ref(&padded.block));
            padded.block.fill(0);
        }
        padded.block[56..].copy_from_slice(&bits.to_be_bytes());
        compress256(&mut padded.state, core::slice::from_ref(&padded.block));
        let mut out = [0u8; 32];
        for (bytes, word) in out.chunks_exact_mut(4).zip(padded.state) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Complete a partly filled block from `data`, compressing it once
    /// full, and return the rest of `data`. A non-empty rest means the block
    /// is empty.
    fn top_up<'a>(&mut self, data: &'a [u8]) -> &'a [u8] {
        self.len = self.len.wrapping_add(data.len() as u64);
        if self.block_len == 0 {
            return data;
        }
        let n = (64 - self.block_len).min(data.len());
        self.block[self.block_len..self.block_len + n].copy_from_slice(&data[..n]);
        self.block_len += n;
        if self.block_len == 64 {
            compress256(&mut self.state, core::slice::from_ref(&self.block));
            self.block_len = 0;
        }
        &data[n..]
    }

    /// Hold the bytes after the last whole block of a rest from `top_up`.
    fn keep(&mut self, tail: &[u8]) {
        if !tail.is_empty() {
            self.block[..tail.len()].copy_from_slice(tail);
            self.block_len = tail.len();
        }
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// `a.update(a_data)` and `b.update(b_data)`, with as many of their blocks
/// as possible compressed together.
pub fn update_pair(a: &mut Sha256, a_data: &[u8], b: &mut Sha256, b_data: &[u8]) {
    let (a_blocks, a_tail) = a.top_up(a_data).as_chunks::<64>();
    let (b_blocks, b_tail) = b.top_up(b_data).as_chunks::<64>();
    let n = a_blocks.len().min(b_blocks.len());
    compress_pair(&mut a.state, &a_blocks[..n], &mut b.state, &b_blocks[..n]);
    compress256(&mut a.state, &a_blocks[n..]);
    compress256(&mut b.state, &b_blocks[n..]);
    a.keep(a_tail);
    b.keep(b_tail);
}

/// The updates of three hashes, with as many of their blocks as possible
/// compressed together.
pub fn update_triple(
    a: &mut Sha256,
    a_data: &[u8],
    b: &mut Sha256,
    b_data: &[u8],
    c: &mut Sha256,
    c_data: &[u8],
) {
    let (mut a_blocks, a_tail) = a.top_up(a_data).as_chunks::<64>();
    let (mut b_blocks, b_tail) = b.top_up(b_data).as_chunks::<64>();
    let (mut c_blocks, c_tail) = c.top_up(c_data).as_chunks::<64>();
    let n = a_blocks.len().min(b_blocks.len()).min(c_blocks.len());
    compress_triple(
        (&mut a.state, &a_blocks[..n]),
        (&mut b.state, &b_blocks[..n]),
        (&mut c.state, &c_blocks[..n]),
    );
    (a_blocks, b_blocks, c_blocks) = (&a_blocks[n..], &b_blocks[n..], &c_blocks[n..]);
    // At most two have blocks left: pair them, then the longer goes alone.
    let mut rest = [
        (&mut a.state, a_blocks),
        (&mut b.state, b_blocks),
        (&mut c.state, c_blocks),
    ];
    rest.sort_by_key(|(_, blocks)| core::cmp::Reverse(blocks.len()));
    let [(x, x_blocks), (y, y_blocks), _] = rest;
    let m = y_blocks.len();
    compress_pair(x, &x_blocks[..m], y, y_blocks);
    compress256(x, &x_blocks[m..]);
    a.keep(a_tail);
    b.keep(b_tail);
    c.keep(c_tail);
}

type Lane<'a> = (&'a mut [u32; 8], &'a [[u8; 64]]);

fn compress_triple(a: Lane<'_>, b: Lane<'_>, c: Lane<'_>) {
    #[cfg(target_arch = "x86_64")]
    if crate::sha256_x2::compress_triple(a.0, a.1, b.0, b.1, c.0, c.1) {
        return;
    }
    compress256(a.0, a.1);
    compress256(b.0, b.1);
    compress256(c.0, c.1);
}

fn compress_pair(a: &mut [u32; 8], a_blocks: &[[u8; 64]], b: &mut [u32; 8], b_blocks: &[[u8; 64]]) {
    #[cfg(target_arch = "x86_64")]
    if crate::sha256_x2::compress_pair(a, a_blocks, b, b_blocks) {
        return;
    }
    compress256(a, a_blocks);
    compress256(b, b_blocks);
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(sha256(b""), expected);
    }

    #[test]
    fn test_sha256_abc() {
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(sha256(b"abc"), expected);
    }

    #[test]
    fn test_sha256_long() {
        let data = [b'a'; 1000];
        let result = sha256(&data);
        let expected = [
            0x41, 0xed, 0xec, 0xe4, 0x2d, 0x63, 0xe8, 0xd9, 0xbf, 0x51, 0x5a, 0x9b, 0xa6, 0x93,
            0x2e, 0x1c, 0x20, 0xcb, 0xc9, 0xf5, 0xa5, 0xd1, 0x34, 0x64, 0x5a, 0xdb, 0x5d, 0xb1,
            0xb9, 0x73, 0x7e, 0xa3,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha256_incremental() {
        let mut hasher = Sha256::new();
        hasher.update(b"ab");
        hasher.update(b"c");
        assert_eq!(hasher.digest(), sha256(b"abc"));
    }

    #[test]
    fn test_sha256_million_a_known_answer() {
        let mut hasher = Sha256::new();
        for _ in 0..1000 {
            hasher.update(&[b'a'; 1000]);
        }
        assert_eq!(
            hasher.digest().to_vec(),
            hex_to_bytes("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
        );
    }

    #[test]
    fn test_sha256_incremental_matches_one_shot_across_padding_boundaries() {
        for length in [0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 255] {
            let input: alloc::vec::Vec<u8> = (0..length)
                .map(|index| ((index * 37 + 11) & 0xff) as u8)
                .collect();
            let expected = sha256(&input);
            for chunk_size in [1, 3, 7, 64] {
                let mut hasher = Sha256::new();
                for chunk in input.chunks(chunk_size) {
                    hasher.update(chunk);
                }
                assert_eq!(
                    hasher.digest(),
                    expected,
                    "length={length}, chunk={chunk_size}"
                );
            }
        }
    }

    #[test]
    fn test_sha256_digest_snapshot_does_not_consume_state() {
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        let snapshot = hasher.digest();
        hasher.update(b"def");

        assert_eq!(snapshot, sha256(b"abc"));
        assert_eq!(hasher.digest(), sha256(b"abcdef"));
    }

    #[test]
    fn paired_updates_match_separate_hashes() {
        let a: alloc::vec::Vec<u8> = (0..5000).map(|i| (i * 31 + 7) as u8).collect();
        let b: alloc::vec::Vec<u8> = (0..5000).map(|i| (i * 17 + 3) as u8).collect();
        for (a_len, b_len) in [
            (0, 0),
            (1, 0),
            (64, 64),
            (100, 3000),
            (4999, 64),
            (5000, 5000),
        ] {
            for (a_step, b_step) in [(1, 1), (7, 64), (64, 1), (100, 333), (5000, 5000)] {
                let (mut x, mut y) = (Sha256::new(), Sha256::new());
                // Odd starting offsets leave partly filled blocks.
                x.update(&[0x55; 3]);
                let (mut ai, mut bi) = (0, 0);
                while ai < a_len || bi < b_len {
                    let a_end = (ai + a_step).min(a_len);
                    let b_end = (bi + b_step).min(b_len);
                    update_pair(&mut x, &a[ai..a_end], &mut y, &b[bi..b_end]);
                    (ai, bi) = (a_end, b_end);
                }
                let mut expected_a = alloc::vec![0x55; 3];
                expected_a.extend_from_slice(&a[..a_len]);
                assert_eq!(
                    x.digest(),
                    sha256(&expected_a),
                    "a {a_len} {a_step}/{b_step}"
                );
                assert_eq!(
                    y.digest(),
                    sha256(&b[..b_len]),
                    "b {b_len} {a_step}/{b_step}"
                );
            }
        }
    }

    #[test]
    fn tripled_updates_match_separate_hashes() {
        let data: alloc::vec::Vec<u8> = (0..6000).map(|i| (i * 29 + 5) as u8).collect();
        for lens in [
            [0, 0, 0],
            [6000, 0, 0],
            [100, 3000, 6000],
            [6000, 6000, 6000],
            [64, 1, 4000],
        ] {
            for steps in [[1, 1, 1], [64, 7, 500], [6000, 6000, 6000], [100, 333, 64]] {
                let mut hashes = [Sha256::new(), Sha256::new(), Sha256::new()];
                hashes[1].update(&[9; 5]);
                let mut at = [0usize; 3];
                while (0..3).any(|i| at[i] < lens[i]) {
                    let end: [usize; 3] = core::array::from_fn(|i| (at[i] + steps[i]).min(lens[i]));
                    let [x, y, z] = &mut hashes;
                    update_triple(
                        x,
                        &data[at[0]..end[0]],
                        y,
                        &data[at[1]..end[1]],
                        z,
                        &data[at[2]..end[2]],
                    );
                    at = end;
                }
                let mut second = alloc::vec![9; 5];
                second.extend_from_slice(&data[..lens[1]]);
                assert_eq!(
                    hashes[0].digest(),
                    sha256(&data[..lens[0]]),
                    "{lens:?} {steps:?}"
                );
                assert_eq!(hashes[1].digest(), sha256(&second), "{lens:?} {steps:?}");
                assert_eq!(
                    hashes[2].digest(),
                    sha256(&data[..lens[2]]),
                    "{lens:?} {steps:?}"
                );
            }
        }
    }

    fn hex_to_bytes(hex: &str) -> alloc::vec::Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect()
    }
}
