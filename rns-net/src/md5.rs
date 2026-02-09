//! MD5 hash function (RFC 1321) and HMAC-MD5 (RFC 2104).
//!
//! Used only for legacy auth compatibility with Python `multiprocessing.connection`.

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// Compute MD5 hash of input data.
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    // Pre-processing: pad message
    let orig_len_bits = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&orig_len_bits.to_le_bytes());

    // Process each 512-bit (64-byte) chunk
    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }

        let mut a = a0;
        let mut b = b0;
        let mut c = c0;
        let mut d = d0;

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };

            let f = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&a0.to_le_bytes());
    result[4..8].copy_from_slice(&b0.to_le_bytes());
    result[8..12].copy_from_slice(&c0.to_le_bytes());
    result[12..16].copy_from_slice(&d0.to_le_bytes());
    result
}

/// Compute HMAC-MD5 (RFC 2104).
pub fn hmac_md5(key: &[u8], message: &[u8]) -> [u8; 16] {
    const BLOCK_SIZE: usize = 64;

    // Step 1: If key > block size, hash it
    let key_block = if key.len() > BLOCK_SIZE {
        let h = md5(key);
        let mut k = [0u8; BLOCK_SIZE];
        k[..16].copy_from_slice(&h);
        k
    } else {
        let mut k = [0u8; BLOCK_SIZE];
        k[..key.len()].copy_from_slice(key);
        k
    };

    // Step 2: Create inner and outer padded keys
    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    // Step 3: Inner hash = MD5(ipad || message)
    let mut inner = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(message);
    let inner_hash = md5(&inner);

    // Step 4: Outer hash = MD5(opad || inner_hash)
    let mut outer = Vec::with_capacity(BLOCK_SIZE + 16);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    md5(&outer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // RFC 1321 test vectors
    #[test]
    fn md5_empty() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn md5_a() {
        assert_eq!(hex(&md5(b"a")), "0cc175b9c0f1b6a831c399e269772661");
    }

    #[test]
    fn md5_abc() {
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn md5_message_digest() {
        assert_eq!(
            hex(&md5(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
    }

    #[test]
    fn md5_alphabet() {
        assert_eq!(
            hex(&md5(b"abcdefghijklmnopqrstuvwxyz")),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
    }

    #[test]
    fn md5_alphanumeric() {
        assert_eq!(
            hex(&md5(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );
    }

    #[test]
    fn md5_numeric_sequence() {
        assert_eq!(
            hex(&md5(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890")),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    // HMAC-MD5 test vectors from RFC 2104
    #[test]
    fn hmac_md5_rfc2104_1() {
        let key = [0x0bu8; 16];
        let data = b"Hi There";
        assert_eq!(hex(&hmac_md5(&key, data)), "9294727a3638bb1c13f48ef8158bfc9d");
    }

    #[test]
    fn hmac_md5_rfc2104_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        assert_eq!(
            hex(&hmac_md5(key, data)),
            "750c783e6ab0b503eaa86e310a5db738"
        );
    }

    #[test]
    fn hmac_md5_rfc2104_3() {
        let key = [0xaau8; 16];
        let data = [0xddu8; 50];
        assert_eq!(
            hex(&hmac_md5(&key, &data)),
            "56be34521d144c88dbb8c733f0e8b3f6"
        );
    }

    #[test]
    fn hmac_md5_long_key() {
        // Key longer than block size gets hashed
        let key = [0xAAu8; 80];
        let data = b"Test With Truncation";
        // This just verifies it doesn't panic and produces 16 bytes
        let result = hmac_md5(&key, data);
        assert_eq!(result.len(), 16);
    }
}
