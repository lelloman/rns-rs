use alloc::string::String;
use core::fmt;

use crate::constants;
use crate::hash;

#[derive(Debug)]
pub enum DestinationError {
    DotInAppName,
    DotInAspect,
}

impl fmt::Display for DestinationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DestinationError::DotInAppName => write!(f, "Dots can't be used in app names"),
            DestinationError::DotInAspect => write!(f, "Dots can't be used in aspects"),
        }
    }
}

/// Expand name: "app_name.aspect1.aspect2[.hexhash]"
///
/// If identity_hash is provided, appends its hex representation.
pub fn expand_name(
    app_name: &str,
    aspects: &[&str],
    identity_hash: Option<&[u8; 16]>,
) -> Result<String, DestinationError> {
    if app_name.contains('.') {
        return Err(DestinationError::DotInAppName);
    }

    let mut name = String::from(app_name);
    for aspect in aspects {
        if aspect.contains('.') {
            return Err(DestinationError::DotInAspect);
        }
        name.push('.');
        name.push_str(aspect);
    }

    if let Some(hash) = identity_hash {
        name.push('.');
        for b in hash {
            use core::fmt::Write;
            write!(name, "{:02x}", b).unwrap();
        }
    }

    Ok(name)
}

/// Compute name hash from app_name and aspects.
///
/// = SHA-256("app_name.aspect1.aspect2".as_bytes())[:10]
pub fn name_hash(
    app_name: &str,
    aspects: &[&str],
) -> [u8; constants::NAME_HASH_LENGTH / 8] {
    hash::name_hash(app_name, aspects)
}

/// Compute destination hash.
///
/// 1. name_hash = SHA256(expand_name(None, app_name, aspects))[:10]
/// 2. addr_material = name_hash || identity_hash (if present)
/// 3. destination_hash = SHA256(addr_material)[:16]
pub fn destination_hash(
    app_name: &str,
    aspects: &[&str],
    identity_hash: Option<&[u8; 16]>,
) -> [u8; constants::TRUNCATED_HASHLENGTH / 8] {
    let nh = name_hash(app_name, aspects);

    let mut addr_material = alloc::vec::Vec::new();
    addr_material.extend_from_slice(&nh);
    if let Some(ih) = identity_hash {
        addr_material.extend_from_slice(ih);
    }

    hash::truncated_hash(&addr_material)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_name_basic() {
        let name = expand_name("app", &["aspect"], None).unwrap();
        assert_eq!(name, "app.aspect");
    }

    #[test]
    fn test_expand_name_multiple_aspects() {
        let name = expand_name("app", &["a", "b"], None).unwrap();
        assert_eq!(name, "app.a.b");
    }

    #[test]
    fn test_expand_name_with_identity() {
        let hash = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                     0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];
        let name = expand_name("app", &["a", "b"], Some(&hash)).unwrap();
        assert_eq!(name, "app.a.b.0102030405060708090a0b0c0d0e0f10");
    }

    #[test]
    fn test_expand_name_dot_in_app_name() {
        assert!(expand_name("app.bad", &["aspect"], None).is_err());
    }

    #[test]
    fn test_expand_name_dot_in_aspect() {
        assert!(expand_name("app", &["bad.aspect"], None).is_err());
    }

    #[test]
    fn test_destination_hash_plain() {
        // PLAIN destination: no identity hash
        let dh = destination_hash("app", &["aspect"], None);
        assert_eq!(dh.len(), 16);

        // Should be deterministic
        let dh2 = destination_hash("app", &["aspect"], None);
        assert_eq!(dh, dh2);
    }

    #[test]
    fn test_destination_hash_with_identity() {
        let id_hash = [0x42; 16];
        let dh = destination_hash("app", &["aspect"], Some(&id_hash));
        assert_eq!(dh.len(), 16);

        // Different identity hash should give different destination hash
        let id_hash2 = [0x43; 16];
        let dh2 = destination_hash("app", &["aspect"], Some(&id_hash2));
        assert_ne!(dh, dh2);
    }

    #[test]
    fn test_destination_hash_computation() {
        // Manually verify the computation
        let nh = name_hash("app", &["aspect"]);
        let id_hash = [0xAA; 16];

        let mut material = alloc::vec::Vec::new();
        material.extend_from_slice(&nh);
        material.extend_from_slice(&id_hash);

        let expected = crate::hash::truncated_hash(&material);
        let actual = destination_hash("app", &["aspect"], Some(&id_hash));
        assert_eq!(actual, expected);
    }
}
