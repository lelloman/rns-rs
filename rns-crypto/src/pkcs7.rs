use alloc::vec::Vec;
use core::fmt;

/// Why padding could not be removed.
#[derive(Debug, PartialEq)]
pub enum PadError {
    /// The last byte names more padding than a block holds.
    InvalidPadding,
    /// There is no data to unpad.
    EmptyInput,
}

impl fmt::Display for PadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PadError::InvalidPadding => write!(f, "Invalid padding"),
            PadError::EmptyInput => write!(f, "Empty input"),
        }
    }
}

/// The AES block size, in bytes.
pub const BLOCK_SIZE: usize = 16;

/// `data` padded to a multiple of `block_size`, always adding at least one byte.
pub fn pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let n = block_size - (data.len() % block_size);
    let mut result = Vec::with_capacity(data.len() + n);
    result.extend_from_slice(data);
    for _ in 0..n {
        result.push(n as u8);
    }
    result
}

/// `data` without its padding.
pub fn unpad(data: &[u8], block_size: usize) -> Result<&[u8], PadError> {
    let Some(&n) = data.last() else {
        return Err(PadError::EmptyInput);
    };
    let n = n as usize;
    if n > block_size {
        return Err(PadError::InvalidPadding);
    }
    data.len()
        .checked_sub(n)
        .and_then(|len| data.get(..len))
        .ok_or(PadError::InvalidPadding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_hello() {
        let result = pad(b"hello", 16);
        assert_eq!(result.len(), 16);
        assert_eq!(&result[..5], b"hello");
        for &b in &result[5..] {
            assert_eq!(b, 0x0B);
        }
    }

    #[test]
    fn test_pad_unpad_roundtrip() {
        let data = b"test data here!";
        let padded = pad(data, 16);
        let unpadded = unpad(&padded, 16).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_pad_block_aligned() {
        let data = [0u8; 16];
        let padded = pad(&data, 16);
        assert_eq!(padded.len(), 32);
        for &b in &padded[16..] {
            assert_eq!(b, 0x10);
        }
    }

    #[test]
    fn test_unpad_invalid() {
        let mut data = [0u8; 16];
        data[15] = 17; // > block_size
        assert_eq!(unpad(&data, 16), Err(PadError::InvalidPadding));
    }

    #[test]
    fn test_pad_empty() {
        let padded = pad(b"", 16);
        assert_eq!(padded.len(), 16);
        for &b in &padded {
            assert_eq!(b, 0x10);
        }
    }
}
