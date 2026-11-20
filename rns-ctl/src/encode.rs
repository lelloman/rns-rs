pub use rns_core::encoding::hex as to_hex;
/// Decode a hex string to bytes. Returns None on invalid input.
pub use rns_core::encoding::hex_decode as from_hex;
/// Decode a hex string to a fixed-size array. Returns None on invalid input or wrong length.
pub use rns_core::encoding::hex_decode_array as hex_to_array;

use rns_core::encoding::BASE64_STANDARD;

/// Encode bytes as standard base64 with padding.
pub fn to_base64(data: &[u8]) -> String {
    BASE64_STANDARD.encode(data)
}

/// Decode standard base64, padded or not, to bytes. Returns None on invalid
/// input. Any number of trailing `=` is accepted, and a lone character left
/// over after the last whole group is checked but carries no byte.
pub fn from_base64(s: &str) -> Option<Vec<u8>> {
    let mut data = s.trim_end_matches('=').as_bytes();
    if data.contains(&b'=') {
        return None;
    }
    if data.len() % 4 == 1 {
        let (last, whole) = data.split_last()?;
        BASE64_STANDARD.sextet(*last)?;
        data = whole;
    }
    BASE64_STANDARD.decode(data).ok()
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
    fn base64_lenient_padding() {
        assert_eq!(from_base64("YWI====").unwrap(), b"ab");
        assert_eq!(from_base64("YWJjZ").unwrap(), b"abc");
        assert!(from_base64("YWJj!").is_none());
        assert!(from_base64("YQ==YQ").is_none());
        assert!(from_base64("YW!=").is_none());
    }

    #[test]
    fn base64_one_pad() {
        // 2 bytes → 3 chars + 1 pad
        assert_eq!(to_base64(b"ab"), "YWI=");
        assert_eq!(from_base64("YWI=").unwrap(), b"ab");
        assert_eq!(from_base64("YWI").unwrap(), b"ab"); // without padding
    }
}
