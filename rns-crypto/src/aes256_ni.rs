//! AES-256-CBC encryption with the x86_64 AES instructions.
//!
//! CBC encryption is serial: each block waits for the previous one, so its
//! speed is the latency of the fourteen rounds. Issuing them straight from
//! round keys held in registers takes about half the time of encrypting
//! block by block through the generic cipher interface.

use core::arch::x86_64::*;

cpufeatures::new!(aes_ni, "aes", "sse2");

/// Encrypt block-aligned `buf` in place with AES-256-CBC. Returns `false`,
/// leaving `buf` untouched, when the CPU lacks the AES instructions.
pub(crate) fn encrypt_cbc(key: &[u8; 32], iv: &[u8; 16], buf: &mut [u8]) -> bool {
    debug_assert!(buf.len().is_multiple_of(16));
    if !aes_ni::get() {
        return false;
    }
    // SAFETY: the AES and SSE2 instructions were detected at run time.
    unsafe {
        let keys = expand_key(key);
        encrypt_cbc_blocks(&keys, iv, buf);
    }
    true
}

#[target_feature(enable = "aes,sse2")]
unsafe fn expand_key(key: &[u8; 32]) -> [__m128i; 15] {
    #[inline(always)]
    unsafe fn spread(mut word: __m128i) -> __m128i {
        // w ^= w << 32; w ^= w << 64: each word gets the xor of those before it.
        word = _mm_xor_si128(word, _mm_slli_si128(word, 4));
        _mm_xor_si128(word, _mm_slli_si128(word, 8))
    }
    let mut keys = [_mm_setzero_si128(); 15];
    // SAFETY: both loads read 16 bytes inside the 32-byte key.
    let mut even = _mm_loadu_si128(key.as_ptr().cast());
    let mut odd = _mm_loadu_si128(key.as_ptr().add(16).cast());
    keys[0] = even;
    keys[1] = odd;
    macro_rules! even_round {
        ($i:expr, $rcon:expr) => {
            let assist = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(odd, $rcon), 0xff);
            even = _mm_xor_si128(spread(even), assist);
            keys[$i] = even;
        };
    }
    macro_rules! odd_round {
        ($i:expr) => {
            let assist = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(even, 0), 0xaa);
            odd = _mm_xor_si128(spread(odd), assist);
            keys[$i] = odd;
        };
    }
    even_round!(2, 0x01);
    odd_round!(3);
    even_round!(4, 0x02);
    odd_round!(5);
    even_round!(6, 0x04);
    odd_round!(7);
    even_round!(8, 0x08);
    odd_round!(9);
    even_round!(10, 0x10);
    odd_round!(11);
    even_round!(12, 0x20);
    odd_round!(13);
    even_round!(14, 0x40);
    keys
}

#[target_feature(enable = "aes,sse2")]
unsafe fn encrypt_cbc_blocks(keys: &[__m128i; 15], iv: &[u8; 16], buf: &mut [u8]) {
    // SAFETY: unaligned loads and stores stay within each 16-byte block.
    let mut chain = _mm_loadu_si128(iv.as_ptr().cast());
    for block in buf.chunks_exact_mut(16) {
        let plain = _mm_loadu_si128(block.as_ptr().cast());
        let mut state = _mm_xor_si128(_mm_xor_si128(plain, chain), keys[0]);
        for key in &keys[1..14] {
            state = _mm_aesenc_si128(state, *key);
        }
        chain = _mm_aesenclast_si128(state, keys[14]);
        _mm_storeu_si128(block.as_mut_ptr().cast(), chain);
    }
}
