use alloc::vec::Vec;
use core::fmt;

use crate::hmac::hmac_sha256;

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
    let mut block: Vec<u8> = Vec::new();
    let mut derived = Vec::with_capacity(length);

    let iterations = (length + hash_len - 1) / hash_len;
    for i in 0..iterations {
        let mut input = Vec::new();
        input.extend_from_slice(&block);
        input.extend_from_slice(context);
        input.push(((i + 1) % 256) as u8);

        block = hmac_sha256(&prk, &input).to_vec();
        derived.extend_from_slice(&block);
    }

    derived.truncate(length);
    Ok(derived)
}

#[cfg(test)]
mod tests {
    use super::*;

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
