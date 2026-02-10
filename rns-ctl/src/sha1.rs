/// SHA-1 hash (FIPS 180-4). Only used for WebSocket Sec-WebSocket-Accept.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let bit_len = (data.len() as u64) * 8;

    // Pad: append 0x80, then zeros, then 8-byte big-endian bit length
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::to_hex;

    #[test]
    fn sha1_empty() {
        let hash = sha1(b"");
        assert_eq!(to_hex(&hash), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn sha1_abc() {
        let hash = sha1(b"abc");
        assert_eq!(to_hex(&hash), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn sha1_fox() {
        let hash = sha1(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(to_hex(&hash), "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
    }

    #[test]
    fn sha1_websocket_accept() {
        // Test WebSocket Sec-WebSocket-Accept computation
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let magic = "258EAFA5-E914-47DA-95CA-5AB5DC11D045";
        let combined = format!("{}{}", key, magic);
        let hash = sha1(combined.as_bytes());
        assert_eq!(to_hex(&hash), "47255391f6ef808bbebc064b6eecf285b72b1ffd");
        let accept = crate::encode::to_base64(&hash);
        assert_eq!(accept, "RyVTkfbvgIu+vAZLbuzyhbcrH/0=");
    }
}
