//! SHA-256 compression of two independent messages at once on the x86_64 SHA
//! instructions. One message's rounds form a dependency chain that leaves the
//! SHA unit idle between instructions; stepping a second message through the
//! same rounds fills those gaps.

use core::arch::x86_64::*;

cpufeatures::new!(sha_ni, "sha", "sse2", "ssse3", "sse4.1");

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// A state in the layout of the SHA instructions: words A, B, E, F and C, D, G, H.
#[derive(Clone, Copy)]
struct Lanes {
    abef: __m128i,
    cdgh: __m128i,
}

/// Compress `a_blocks` into `a` and `b_blocks` into `b`, which must be as
/// many. Returns false, doing nothing, when the CPU lacks the instructions.
pub(crate) fn compress_pair(
    a: &mut [u32; 8],
    a_blocks: &[[u8; 64]],
    b: &mut [u32; 8],
    b_blocks: &[[u8; 64]],
) -> bool {
    assert_eq!(a_blocks.len(), b_blocks.len());
    if !sha_ni::get() {
        return false;
    }
    // SAFETY: the instructions these functions are compiled for are present.
    unsafe {
        let mut la = load(a);
        let mut lb = load(b);
        for (block_a, block_b) in a_blocks.iter().zip(b_blocks) {
            compress2(&mut la, block_a, &mut lb, block_b);
        }
        store(la, a);
        store(lb, b);
    }
    true
}

#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn load(state: &[u32; 8]) -> Lanes {
    let dcba = _mm_loadu_si128(state.as_ptr().cast());
    let hgfe = _mm_loadu_si128(state.as_ptr().add(4).cast());
    let cdab = _mm_shuffle_epi32(dcba, 0xB1);
    let efgh = _mm_shuffle_epi32(hgfe, 0x1B);
    Lanes {
        abef: _mm_alignr_epi8(cdab, efgh, 8),
        cdgh: _mm_blend_epi16(efgh, cdab, 0xF0),
    }
}

#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn store(lanes: Lanes, state: &mut [u32; 8]) {
    let feba = _mm_shuffle_epi32(lanes.abef, 0x1B);
    let dchg = _mm_shuffle_epi32(lanes.cdgh, 0xB1);
    _mm_storeu_si128(state.as_mut_ptr().cast(), _mm_blend_epi16(feba, dchg, 0xF0));
    _mm_storeu_si128(
        state.as_mut_ptr().add(4).cast(),
        _mm_alignr_epi8(dchg, feba, 8),
    );
}

/// Four rounds of one state with the message words `w`.
macro_rules! rounds4 {
    ($s:ident, $w:expr, $i:expr) => {{
        let t = _mm_add_epi32($w, _mm_loadu_si128(K.as_ptr().add($i * 4).cast()));
        $s.cdgh = _mm_sha256rnds2_epu32($s.cdgh, $s.abef, t);
        $s.abef = _mm_sha256rnds2_epu32($s.abef, $s.cdgh, _mm_shuffle_epi32(t, 0x0E));
    }};
}

/// Message words `i` (four of them) from the four groups before.
macro_rules! schedule {
    ($w:ident, $i:expr) => {{
        let t = _mm_sha256msg1_epu32($w[($i - 4) % 4], $w[($i - 3) % 4]);
        let t = _mm_add_epi32(t, _mm_alignr_epi8($w[($i - 1) % 4], $w[($i - 2) % 4], 4));
        $w[$i % 4] = _mm_sha256msg2_epu32(t, $w[($i - 1) % 4]);
    }};
}

#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn compress2(a: &mut Lanes, block_a: &[u8; 64], b: &mut Lanes, block_b: &[u8; 64]) {
    let big_endian = _mm_set_epi64x(0x0c0d0e0f08090a0b, 0x0405060700010203);
    let (start_a, start_b) = (*a, *b);
    let mut wa = [_mm_setzero_si128(); 4];
    let mut wb = [_mm_setzero_si128(); 4];
    for i in 0..4 {
        wa[i] = _mm_shuffle_epi8(
            _mm_loadu_si128(block_a.as_ptr().add(i * 16).cast()),
            big_endian,
        );
        wb[i] = _mm_shuffle_epi8(
            _mm_loadu_si128(block_b.as_ptr().add(i * 16).cast()),
            big_endian,
        );
    }
    for i in 0..16 {
        if i >= 4 {
            schedule!(wa, i);
            schedule!(wb, i);
        }
        rounds4!(a, wa[i % 4], i);
        rounds4!(b, wb[i % 4], i);
    }
    a.abef = _mm_add_epi32(a.abef, start_a.abef);
    a.cdgh = _mm_add_epi32(a.cdgh, start_a.cdgh);
    b.abef = _mm_add_epi32(b.abef, start_b.abef);
    b.cdgh = _mm_add_epi32(b.cdgh, start_b.cdgh);
}

/// [`compress_pair`] for three states; the blocks must be as many for each.
pub(crate) fn compress_triple(
    a: &mut [u32; 8],
    a_blocks: &[[u8; 64]],
    b: &mut [u32; 8],
    b_blocks: &[[u8; 64]],
    c: &mut [u32; 8],
    c_blocks: &[[u8; 64]],
) -> bool {
    assert!(a_blocks.len() == b_blocks.len() && b_blocks.len() == c_blocks.len());
    if !sha_ni::get() {
        return false;
    }
    // SAFETY: the instructions these functions are compiled for are present.
    unsafe {
        let mut la = load(a);
        let mut lb = load(b);
        let mut lc = load(c);
        for ((block_a, block_b), block_c) in a_blocks.iter().zip(b_blocks).zip(c_blocks) {
            compress3(&mut la, block_a, &mut lb, block_b, &mut lc, block_c);
        }
        store(la, a);
        store(lb, b);
        store(lc, c);
    }
    true
}

#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn compress3(
    a: &mut Lanes,
    block_a: &[u8; 64],
    b: &mut Lanes,
    block_b: &[u8; 64],
    c: &mut Lanes,
    block_c: &[u8; 64],
) {
    let big_endian = _mm_set_epi64x(0x0c0d0e0f08090a0b, 0x0405060700010203);
    let (start_a, start_b, start_c) = (*a, *b, *c);
    let mut wa = [_mm_setzero_si128(); 4];
    let mut wb = [_mm_setzero_si128(); 4];
    let mut wc = [_mm_setzero_si128(); 4];
    for i in 0..4 {
        let at = i * 16;
        wa[i] = _mm_shuffle_epi8(_mm_loadu_si128(block_a.as_ptr().add(at).cast()), big_endian);
        wb[i] = _mm_shuffle_epi8(_mm_loadu_si128(block_b.as_ptr().add(at).cast()), big_endian);
        wc[i] = _mm_shuffle_epi8(_mm_loadu_si128(block_c.as_ptr().add(at).cast()), big_endian);
    }
    for i in 0..16 {
        if i >= 4 {
            schedule!(wa, i);
            schedule!(wb, i);
            schedule!(wc, i);
        }
        rounds4!(a, wa[i % 4], i);
        rounds4!(b, wb[i % 4], i);
        rounds4!(c, wc[i % 4], i);
    }
    for (lanes, start) in [(a, start_a), (b, start_b), (c, start_c)] {
        lanes.abef = _mm_add_epi32(lanes.abef, start.abef);
        lanes.cdgh = _mm_add_epi32(lanes.cdgh, start.cdgh);
    }
}
