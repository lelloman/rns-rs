use alloc::string::String;
use alloc::vec::Vec;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// `data` as lowercase hex digits, two per byte, as Python's `bytes.hex()`
/// writes it.
pub fn hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    push_hex(&mut out, data);
    out
}

/// Append `data` to `out` as lowercase hex digits, two per byte.
pub fn push_hex(out: &mut String, data: &[u8]) {
    for &byte in data {
        out.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
}

/// `data` as lowercase hex bytes separated by `delimiter`, as upstream's
/// `hexrep(data, delimit=True)` writes it with `":"`.
pub fn hex_delimited(data: &[u8], delimiter: char) -> String {
    let mut out = String::with_capacity(data.len() * 3);
    for (index, byte) in data.iter().enumerate() {
        if index > 0 {
            out.push(delimiter);
        }
        push_hex(&mut out, core::slice::from_ref(byte));
    }
    out
}

/// The value of one hex digit, either case.
pub fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decode hex digits, either case, two per byte, into `out`, which must be
/// exactly half as long as `text`. Anything but hex digits fails: no
/// whitespace, separators or signs.
pub fn hex_decode_into(text: &str, out: &mut [u8]) -> Option<()> {
    let text = text.as_bytes();
    if text.len() != out.len() * 2 {
        return None;
    }
    for (byte, pair) in out.iter_mut().zip(text.chunks_exact(2)) {
        *byte = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Some(())
}

/// Decode an even number of hex digits, either case, as Python's
/// `bytes.fromhex` reads text without whitespace.
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = alloc::vec![0u8; text.len() / 2];
    hex_decode_into(text, &mut out)?;
    Some(out)
}

/// Decode exactly `2 * N` hex digits, either case, into an array.
pub fn hex_decode_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    hex_decode_into(text, &mut out)?;
    Some(out)
}

/// Why [`Base64::decode`] rejected its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    /// A byte that is neither in the alphabet nor `=`.
    InvalidByte(u8),
    /// A final group of a single character, which cannot hold a byte.
    InvalidLength,
    /// `=` followed by data in its group, or more than two `=` in a group.
    InvalidPadding,
}

const INVALID: u8 = 0xff;

/// A base64 alphabet: the 64 characters it encodes with, and the
/// characters it decodes, which may include aliases of them.
pub struct Base64 {
    encode: [u8; 64],
    decode: [u8; 256],
}

impl Base64 {
    const fn new(alphabet: &[u8; 64]) -> Self {
        let mut decode = [INVALID; 256];
        let mut i = 0;
        while i < 64 {
            decode[alphabet[i] as usize] = i as u8;
            i += 1;
        }
        Self {
            encode: *alphabet,
            decode,
        }
    }

    /// Also decode `alias` as the value `value`.
    const fn with_alias(mut self, alias: u8, value: u8) -> Self {
        self.decode[alias as usize] = value;
        self
    }

    /// The 6-bit value of one character, or `None` outside the alphabet.
    pub fn sextet(&self, byte: u8) -> Option<u8> {
        let value = self.decode[usize::from(byte)];
        (value != INVALID).then_some(value)
    }

    /// `data` in base64, padded with `=` to a multiple of four characters.
    pub fn encode(&self, data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let mut group = [0u8; 3];
            group[..chunk.len()].copy_from_slice(chunk);
            let bits =
                (u32::from(group[0]) << 16) | (u32::from(group[1]) << 8) | u32::from(group[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    let sextet = (bits >> (18 - 6 * i)) & 0x3f;
                    out.push(char::from(self.encode[sextet as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    /// Decode base64 in groups of four characters. A group may end in up to
    /// two `=`, and a group may be padded in the middle of the text. The
    /// last group may be short, its missing characters counting as `=`.
    /// Bits beyond the last whole byte of a group are ignored.
    pub fn decode(&self, text: &[u8]) -> Result<Vec<u8>, Base64Error> {
        let mut out = Vec::with_capacity(text.len().div_ceil(4) * 3);
        for group in text.chunks(4) {
            if group.len() == 1 {
                return Err(Base64Error::InvalidLength);
            }
            let mut bits = 0u32;
            let mut pad = 0;
            for &byte in group {
                let value = if byte == b'=' {
                    pad += 1;
                    0
                } else if pad > 0 {
                    return Err(Base64Error::InvalidPadding);
                } else {
                    self.sextet(byte).ok_or(Base64Error::InvalidByte(byte))?
                };
                bits = (bits << 6) | u32::from(value);
            }
            bits <<= 6 * (4 - group.len());
            pad += 4 - group.len();
            if pad > 2 {
                return Err(Base64Error::InvalidPadding);
            }
            out.extend_from_slice(&bits.to_be_bytes()[1..4 - pad]);
        }
        Ok(out)
    }
}

/// Standard base64 (RFC 4648 section 4): `+` and `/`.
pub static BASE64_STANDARD: Base64 =
    Base64::new(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");

/// URL- and filename-safe base64 (RFC 4648 section 5): `-` and `_`, as
/// upstream's `base64.urlsafe_b64encode` writes it.
pub static BASE64_URL_SAFE: Base64 =
    Base64::new(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");

/// Encodes standard base64; decodes both the standard and the URL-safe
/// alphabets, even mixed.
pub static BASE64_EITHER: Base64 =
    Base64::new(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        .with_alias(b'-', 62)
        .with_alias(b'_', 63);

/// I2P's base64: `-` and `~`.
pub static BASE64_I2P: Base64 =
    Base64::new(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~");

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec;

    #[test]
    fn hex_is_two_lowercase_digits_per_byte() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        let all: Vec<u8> = (0..=255).collect();
        let expected: String = all.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex(&all), expected);
    }

    #[test]
    fn push_hex_appends() {
        let mut out = String::from("a.");
        push_hex(&mut out, &[0xde, 0xad]);
        assert_eq!(out, "a.dead");
    }

    #[test]
    fn hex_delimited_separates_bytes() {
        assert_eq!(hex_delimited(&[], ':'), "");
        assert_eq!(hex_delimited(&[0x0a], ':'), "0a");
        assert_eq!(hex_delimited(&[0x0a, 0xff, 0x00], ':'), "0a:ff:00");
    }

    #[test]
    fn hex_decode_reads_either_case() {
        assert_eq!(hex_decode(""), Some(vec![]));
        assert_eq!(hex_decode("00fFaA19"), Some(vec![0x00, 0xff, 0xaa, 0x19]));
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(hex_decode(&hex(&all)), Some(all.clone()));
        assert_eq!(hex_decode(&hex(&all).to_uppercase()), Some(all));
    }

    #[test]
    fn hex_decode_rejects_anything_but_digit_pairs() {
        for text in [
            "0", "abc", "0g", "g0", "+f", "-1", " 0a", "0a ", "0 a", "é0", "0é",
        ] {
            assert_eq!(hex_decode(text), None, "{text:?}");
        }
    }

    #[test]
    fn hex_decode_array_needs_the_exact_length() {
        assert_eq!(hex_decode_array::<2>("0a0B"), Some([0x0a, 0x0b]));
        assert_eq!(hex_decode_array::<2>("0a0b0c"), None);
        assert_eq!(hex_decode_array::<2>("0a0"), None);
        assert_eq!(hex_decode_array::<2>("0a0x"), None);
        assert_eq!(hex_decode_array::<0>(""), Some([]));
        // Four bytes of UTF-8, two characters: still not hex.
        assert_eq!(hex_decode_array::<2>("éé"), None);
    }

    #[test]
    fn hex_digit_values() {
        assert_eq!(hex_digit(b'0'), Some(0));
        assert_eq!(hex_digit(b'9'), Some(9));
        assert_eq!(hex_digit(b'a'), Some(10));
        assert_eq!(hex_digit(b'F'), Some(15));
        assert_eq!(hex_digit(b'g'), None);
        assert_eq!(hex_digit(b'+'), None);
    }

    #[test]
    fn base64_encodes_rfc4648_vectors() {
        let vectors = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, encoded) in vectors {
            assert_eq!(BASE64_STANDARD.encode(plain.as_bytes()), encoded);
            assert_eq!(BASE64_URL_SAFE.encode(plain.as_bytes()), encoded);
            assert_eq!(BASE64_I2P.encode(plain.as_bytes()), encoded);
            assert_eq!(
                BASE64_STANDARD.decode(encoded.as_bytes()),
                Ok(plain.as_bytes().to_vec())
            );
        }
    }

    #[test]
    fn base64_alphabets_differ_in_the_last_two_characters() {
        let data = [0xfb, 0xff, 0xfe];
        assert_eq!(BASE64_STANDARD.encode(&data), "+//+");
        assert_eq!(BASE64_URL_SAFE.encode(&data), "-__-");
        assert_eq!(BASE64_I2P.encode(&data), "-~~-");
        assert_eq!(BASE64_EITHER.encode(&data), "+//+");
        assert_eq!(BASE64_STANDARD.decode(b"+//+"), Ok(data.to_vec()));
        assert_eq!(BASE64_URL_SAFE.decode(b"-__-"), Ok(data.to_vec()));
        assert_eq!(BASE64_I2P.decode(b"-~~-"), Ok(data.to_vec()));
        assert_eq!(BASE64_EITHER.decode(b"+_/-"), Ok(data.to_vec()));
        assert_eq!(
            BASE64_STANDARD.decode(b"-__-"),
            Err(Base64Error::InvalidByte(b'-'))
        );
        assert_eq!(
            BASE64_I2P.decode(b"+//+"),
            Err(Base64Error::InvalidByte(b'+'))
        );
    }

    #[test]
    fn base64_roundtrips_every_length_and_byte() {
        let all: Vec<u8> = (0..=255).collect();
        for len in 0..all.len() {
            for alphabet in [&BASE64_STANDARD, &BASE64_URL_SAFE, &BASE64_I2P] {
                let encoded = alphabet.encode(&all[..len]);
                assert_eq!(alphabet.decode(encoded.as_bytes()), Ok(all[..len].to_vec()));
            }
        }
    }

    #[test]
    fn base64_decode_padding_rules() {
        // A short last group counts as padded.
        assert_eq!(BASE64_STANDARD.decode(b"Zg"), Ok(b"f".to_vec()));
        assert_eq!(BASE64_STANDARD.decode(b"Zm8"), Ok(b"fo".to_vec()));
        assert_eq!(BASE64_STANDARD.decode(b"Zg="), Ok(b"f".to_vec()));
        // A group may be padded mid-text.
        assert_eq!(BASE64_STANDARD.decode(b"Zg==Zg=="), Ok(b"ff".to_vec()));
        // Unused low bits are ignored.
        assert_eq!(BASE64_STANDARD.decode(b"Zh=="), Ok(b"f".to_vec()));
        assert_eq!(
            BASE64_STANDARD.decode(b"Z"),
            Err(Base64Error::InvalidLength)
        );
        assert_eq!(
            BASE64_STANDARD.decode(b"Zm9vZ"),
            Err(Base64Error::InvalidLength)
        );
        for text in [&b"Z==="[..], b"====", b"Z=", b"Zg=a", b"Zg====", b"=Zg="] {
            assert_eq!(
                BASE64_STANDARD.decode(text),
                Err(Base64Error::InvalidPadding),
                "{text:?}"
            );
        }
        assert_eq!(
            BASE64_STANDARD.decode(b"Zm 9"),
            Err(Base64Error::InvalidByte(b' '))
        );
    }
}
