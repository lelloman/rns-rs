use rns_crypto::Rng;

use crate::constants;

/// Compute full SHA-256 hash of data.
pub fn full_hash(data: &[u8]) -> [u8; 32] {
    rns_crypto::sha256::sha256(data)
}

/// Compute truncated SHA-256 hash (first 16 bytes).
pub fn truncated_hash(data: &[u8]) -> [u8; 16] {
    let full = full_hash(data);
    let mut result = [0u8; 16];
    result.copy_from_slice(&full[..16]);
    result
}

/// Generate a random truncated hash: truncated_hash(random(16)).
pub fn get_random_hash(rng: &mut dyn Rng) -> [u8; 16] {
    let mut random_bytes = [0u8; 16];
    rng.fill_bytes(&mut random_bytes);
    truncated_hash(&random_bytes)
}

/// Compute name hash from app_name and aspects.
/// = SHA-256("app_name.aspect1.aspect2".as_bytes())[:10]
///
/// Panics if app_name or any aspect contains a dot, matching Python's
/// `ValueError("Dots can't be used in app names/aspects")`.
pub fn name_hash(app_name: &str, aspects: &[&str]) -> [u8; constants::NAME_HASH_LENGTH / 8] {
    assert!(!app_name.contains('.'), "Dots can't be used in app names");
    for aspect in aspects {
        assert!(!aspect.contains('.'), "Dots can't be used in aspects");
    }
    let mut name = alloc::string::String::from(app_name);
    for aspect in aspects {
        name.push('.');
        name.push_str(aspect);
    }
    let full = full_hash(name.as_bytes());
    let mut result = [0u8; constants::NAME_HASH_LENGTH / 8];
    result.copy_from_slice(&full[..constants::NAME_HASH_LENGTH / 8]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncated_hash_is_prefix_of_full_hash() {
        let data = b"test data";
        let full = full_hash(data);
        let trunc = truncated_hash(data);
        assert_eq!(&full[..16], &trunc);
    }

    #[test]
    fn test_name_hash_basic() {
        let nh = name_hash("app", &["aspect"]);
        assert_eq!(nh.len(), 10);
        // Verify it's deterministic
        let nh2 = name_hash("app", &["aspect"]);
        assert_eq!(nh, nh2);
    }

    #[test]
    fn test_name_hash_multiple_aspects() {
        // name_hash("app", &["a", "b"]) should hash "app.a.b"
        let nh = name_hash("app", &["a", "b"]);
        let expected = full_hash(b"app.a.b");
        assert_eq!(nh, expected[..10]);
    }

    #[test]
    fn test_get_random_hash() {
        let mut rng = rns_crypto::FixedRng::new(&[0x42; 32]);
        let h = get_random_hash(&mut rng);
        assert_eq!(h.len(), 16);
    }

    #[test]
    #[should_panic(expected = "Dots can't be used in app names")]
    fn test_name_hash_rejects_dot_in_app_name() {
        name_hash("app.bad", &["aspect"]);
    }

    #[test]
    #[should_panic(expected = "Dots can't be used in aspects")]
    fn test_name_hash_rejects_dot_in_aspect() {
        name_hash("app", &["bad.aspect"]);
    }
}
