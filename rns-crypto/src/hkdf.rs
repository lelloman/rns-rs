use alloc::vec::Vec;
use core::fmt;

use crate::hmac::{hmac_sha256, HmacSha256};

#[derive(Debug, PartialEq)]
pub enum HkdfError {
    InvalidLength,
    EmptyInput,
}

impl fmt::Display for HkdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HkdfError::InvalidLength => write!(f, "Invalid output key length"),
            HkdfError::EmptyInput => write!(f, "Cannot derive key from empty input material"),
        }
    }
}

/// Custom HKDF implementation matching RNS/Cryptography/HKDF.py.
/// WARNING: This is NOT RFC 5869. The counter wraps modulo 256.
pub fn hkdf(
    length: usize,
    derive_from: &[u8],
    salt: Option<&[u8]>,
    context: Option<&[u8]>,
) -> Result<Vec<u8>, HkdfError> {
    let hash_len: usize = 32;

    if length < 1 {
        return Err(HkdfError::InvalidLength);
    }

    if derive_from.is_empty() {
        return Err(HkdfError::EmptyInput);
    }

    let salt = match salt {
        Some(s) if !s.is_empty() => s.to_vec(),
        _ => alloc::vec![0u8; hash_len],
    };

    let context = context.unwrap_or(b"");

    // Extract
    let prk = hmac_sha256(&salt, derive_from);

    // Expand
    let expansion_hmac = HmacSha256::new(&prk);
    let mut block = [0u8; 32];
    let mut has_block = false;
    let mut derived = Vec::with_capacity(length);

    let iterations = length.div_ceil(hash_len);
    for i in 0..iterations {
        let mut hmac = expansion_hmac.clone();
        if has_block {
            hmac.update(&block);
        }
        hmac.update(context);
        hmac.update(&[((i + 1) % 256) as u8]);
        block = hmac.finalize();
        has_block = true;
        derived.extend_from_slice(&block);
    }

    derived.truncate(length);
    Ok(derived)
}

// Cargo discovers this module through the crate test harness, so the HKDF
// vectors run under `cargo test --workspace` without a manual runner registry.
#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid test vector"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    fn reference_hkdf(length: usize, ikm: &[u8], salt: &[u8], context: &[u8]) -> Vec<u8> {
        let prk = hmac_sha256(salt, ikm);
        let mut block = Vec::new();
        let mut derived = Vec::with_capacity(length);
        for index in 0..length.div_ceil(32) {
            let mut input = block;
            input.extend_from_slice(context);
            input.push(((index + 1) % 256) as u8);
            block = hmac_sha256(&prk, &input).to_vec();
            derived.extend_from_slice(&block);
        }
        derived.truncate(length);
        derived
    }

    #[test]
    fn optimized_expansion_matches_reference_across_counter_wrap() {
        let ikm = b"deterministic input material";
        let salt = b"deterministic salt";
        let context = b"counter-wrap";
        for length in [8191, 8192, 8193] {
            assert_eq!(
                hkdf(length, ikm, Some(salt), Some(context)).unwrap(),
                reference_hkdf(length, ikm, salt, context)
            );
        }
    }

    #[test]
    fn rfc5869_sha256_vectors() {
        let cases = [
            (
                vec![0x0b; 22],
                (0x00..0x0d).collect::<Vec<_>>(),
                (0xf0..0xfa).collect::<Vec<_>>(),
                42,
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            ),
            (
                (0x00..0x50).collect::<Vec<_>>(),
                (0x60..0xb0).collect::<Vec<_>>(),
                (0xb0..=0xff).collect::<Vec<_>>(),
                82,
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
            ),
            (
                vec![0x0b; 22],
                Vec::new(),
                Vec::new(),
                42,
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            ),
        ];

        for (ikm, salt, context, length, expected) in cases {
            assert_eq!(
                hkdf(length, &ikm, Some(&salt), Some(&context)).unwrap(),
                decode_hex(expected)
            );
        }
    }

    #[test]
    fn test_hkdf_32bytes() {
        let ikm = b"input key material";
        let salt = b"salt value";
        let result = hkdf(32, ikm, Some(salt), None).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hkdf_64bytes() {
        let ikm = b"input key material";
        let salt = b"salt value";
        let result = hkdf(64, ikm, Some(salt), None).unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_hkdf_with_context() {
        let ikm = b"input key material";
        let salt = b"salt";
        let ctx = b"context info";
        let result = hkdf(32, ikm, Some(salt), Some(ctx)).unwrap();
        assert_eq!(result.len(), 32);
        // With context should differ from without
        let result2 = hkdf(32, ikm, Some(salt), None).unwrap();
        assert_ne!(result, result2);
    }

    #[test]
    fn test_hkdf_none_salt() {
        let ikm = b"input key material";
        let result = hkdf(32, ikm, None, None).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hkdf_empty_salt() {
        let ikm = b"input key material";
        let result1 = hkdf(32, ikm, Some(b""), None).unwrap();
        let result2 = hkdf(32, ikm, None, None).unwrap();
        // Empty salt and None salt should produce same result
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_hkdf_invalid_length() {
        assert_eq!(hkdf(0, b"ikm", None, None), Err(HkdfError::InvalidLength));
    }

    #[test]
    fn test_hkdf_empty_ikm() {
        assert_eq!(hkdf(32, b"", None, None), Err(HkdfError::EmptyInput));
    }
}
