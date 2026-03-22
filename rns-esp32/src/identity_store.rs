pub const IDENTITY_KEY_LEN: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoredIdentityError {
    InvalidLength(usize),
}

pub fn decode_identity_key(
    raw: Option<&[u8]>,
) -> Result<Option<[u8; IDENTITY_KEY_LEN]>, StoredIdentityError> {
    let Some(raw) = raw else {
        return Ok(None);
    };

    if raw.len() != IDENTITY_KEY_LEN {
        return Err(StoredIdentityError::InvalidLength(raw.len()));
    }

    let mut key = [0u8; IDENTITY_KEY_LEN];
    key.copy_from_slice(raw);
    Ok(Some(key))
}

#[cfg(test)]
mod tests {
    use super::{decode_identity_key, StoredIdentityError, IDENTITY_KEY_LEN};

    #[test]
    fn accepts_exact_key_length() {
        let raw = [0x42u8; IDENTITY_KEY_LEN];
        let decoded = decode_identity_key(Some(&raw)).unwrap();
        assert_eq!(decoded, Some(raw));
    }

    #[test]
    fn rejects_short_key() {
        let raw = [0x42u8; IDENTITY_KEY_LEN - 1];
        let err = decode_identity_key(Some(&raw)).unwrap_err();
        assert_eq!(
            err,
            StoredIdentityError::InvalidLength(IDENTITY_KEY_LEN - 1)
        );
    }

    #[test]
    fn rejects_oversized_key() {
        let raw = [0x42u8; IDENTITY_KEY_LEN + 1];
        let err = decode_identity_key(Some(&raw)).unwrap_err();
        assert_eq!(
            err,
            StoredIdentityError::InvalidLength(IDENTITY_KEY_LEN + 1)
        );
    }
}
