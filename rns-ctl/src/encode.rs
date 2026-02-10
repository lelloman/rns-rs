/// Encode bytes as lowercase hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize]);
        s.push(HEX_CHARS[(b & 0x0f) as usize]);
    }
    s
}

const HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// Decode a hex string to bytes. Returns None on invalid input.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode a hex string to a fixed-size array. Returns None on invalid input or wrong length.
pub fn hex_to_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    let v = from_hex(s)?;
    if v.len() != N {
        return None;
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&v);
    Some(arr)
}

const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as standard base64 with padding.
pub fn to_base64(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let chunks = data.chunks(3);
    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(B64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(B64_CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_CHARS[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decode standard base64 (with or without padding) to bytes. Returns None on invalid input.
pub fn from_base64(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let bytes = s.as_bytes();
    let chunks = bytes.chunks(4);
    for chunk in chunks {
        let mut vals = [0u32; 4];
        let n = chunk.len();
        for i in 0..n {
            vals[i] = b64_val(chunk[i])? as u32;
        }
        if n >= 2 {
            out.push(((vals[0] << 2) | (vals[1] >> 4)) as u8);
        }
        if n >= 3 {
            out.push(((vals[1] << 4) | (vals[2] >> 2)) as u8);
        }
        if n >= 4 {
            out.push(((vals[2] << 6) | vals[3]) as u8);
        }
    }
    Some(out)
}

fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let data = b"\x00\x01\x0a\xff\xde\xad";
        assert_eq!(to_hex(data), "00010affdead");
        assert_eq!(from_hex("00010affDEAD").unwrap(), data);
    }

    #[test]
    fn hex_empty() {
        assert_eq!(to_hex(&[]), "");
        assert_eq!(from_hex("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn hex_invalid() {
        assert!(from_hex("0").is_none()); // odd length
        assert!(from_hex("zz").is_none()); // bad chars
    }

    #[test]
    fn hex_to_array_works() {
        let arr: [u8; 3] = hex_to_array("aabbcc").unwrap();
        assert_eq!(arr, [0xaa, 0xbb, 0xcc]);
        assert!(hex_to_array::<4>("aabb").is_none()); // wrong length
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = to_base64(data);
        assert_eq!(encoded, "SGVsbG8sIFdvcmxkIQ==");
        assert_eq!(from_base64(&encoded).unwrap(), data);
    }

    #[test]
    fn base64_empty() {
        assert_eq!(to_base64(&[]), "");
        assert_eq!(from_base64("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn base64_no_padding() {
        // 3 bytes → 4 chars, no padding
        assert_eq!(to_base64(b"abc"), "YWJj");
        assert_eq!(from_base64("YWJj").unwrap(), b"abc");
    }

    #[test]
    fn base64_one_pad() {
        // 2 bytes → 3 chars + 1 pad
        assert_eq!(to_base64(b"ab"), "YWI=");
        assert_eq!(from_base64("YWI=").unwrap(), b"ab");
        assert_eq!(from_base64("YWI").unwrap(), b"ab"); // without padding
    }
}
