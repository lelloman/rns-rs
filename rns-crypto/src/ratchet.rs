//! Destination ratchet history. No clock, filesystem, or global state is required.
use crate::{x25519::X25519PrivateKey, Rng};
use alloc::vec::Vec;
use zeroize::Zeroizing;

pub const DEFAULT_INTERVAL: u64 = 30 * 60;
pub const DEFAULT_RETAINED: usize = 512;
/// Allocation/decryption-work limit, including when importing untrusted storage.
pub const MAX_RETAINED: usize = 4096;

pub struct Decrypted {
    pub plaintext: Vec<u8>,
    pub ratchet_id: Option<[u8; 10]>,
}

pub fn ratchet_id(public: &[u8; 32]) -> [u8; 10] {
    crate::sha256::sha256(public)[..10].try_into().unwrap()
}

/// Newest-first private key history. Clones and retired keys are zeroized on drop.
#[derive(Clone)]
pub struct RatchetRing {
    keys: Zeroizing<Vec<[u8; 32]>>,
    last_rotation: Option<u64>,
}

impl core::fmt::Debug for RatchetRing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RatchetRing")
            .field("retained", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl Default for RatchetRing {
    fn default() -> Self {
        Self::new()
    }
}

impl RatchetRing {
    pub fn new() -> Self {
        Self {
            keys: Zeroizing::new(Vec::new()),
            last_rotation: None,
        }
    }

    /// Imports newest-first keys; the first fresh announce after reload rotates,
    /// matching the reference (rotation time is not stored in its key file).
    pub fn from_keys(keys: Vec<[u8; 32]>) -> Option<Self> {
        let keys = Zeroizing::new(keys);
        if keys.len() > MAX_RETAINED {
            return None;
        }
        Some(Self {
            keys,
            last_rotation: None,
        })
    }

    /// Exposes secrets only for explicit persistence implementations.
    pub fn keys(&self) -> &[[u8; 32]] {
        &self.keys
    }

    pub fn current_public(&self) -> Option<[u8; 32]> {
        self.keys.first().map(|key| {
            X25519PrivateKey::from_bytes(key)
                .public_key()
                .public_bytes()
        })
    }

    pub fn retains(&self, public: &[u8; 32]) -> bool {
        self.keys.iter().any(|key| {
            X25519PrivateKey::from_bytes(key)
                .public_key()
                .public_bytes()
                == *public
        })
    }

    /// Build a candidate; callers must durably commit it before replacing self.
    pub fn rotated(
        &self,
        now: u64,
        interval: u64,
        retained: usize,
        rng: &mut dyn Rng,
    ) -> Option<Self> {
        if interval == 0 || !(1..=MAX_RETAINED).contains(&retained) {
            return None;
        }
        if !self.keys.is_empty()
            && self
                .last_rotation
                .is_some_and(|last| now <= last.saturating_add(interval))
        {
            return None;
        }
        let mut keys = Zeroizing::new(Vec::with_capacity((self.keys.len() + 1).min(retained)));
        keys.push(X25519PrivateKey::generate(rng).private_bytes());
        keys.extend_from_slice(&self.keys[..self.keys.len().min(retained - 1)]);
        Some(Self {
            keys,
            last_rotation: Some(now),
        })
    }

    pub fn prune(&mut self, retained: usize) {
        use zeroize::Zeroize;
        for key in self.keys.iter_mut().skip(retained) {
            key.zeroize();
        }
        self.keys.truncate(retained);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{identity::Identity, FixedRng};

    #[test]
    fn pinned_python_ratchet_vectors() {
        fn bytes(value: &serde_json::Value) -> Vec<u8> {
            let text = value.as_str().unwrap();
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                .collect()
        }
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/crypto/local_ratchet_1_5_6.json"
        ))
        .unwrap();
        let identity =
            Identity::from_private_key(&bytes(&vectors["identity_private"]).try_into().unwrap());
        let ring = RatchetRing::from_keys(
            vectors["keys_newest_first"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| bytes(v).try_into().unwrap())
                .collect(),
        )
        .unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            for enforce in [false, true] {
                let result =
                    identity.decrypt_with_ratchets(&bytes(&case["ciphertext"]), &ring, enforce);
                let accept = case[if enforce {
                    "enforced_accept"
                } else {
                    "fallback_accept"
                }]
                .as_bool()
                .unwrap();
                assert_eq!(result.is_ok(), accept, "{} enforce={enforce}", case["name"]);
                if let Ok(result) = result {
                    assert_eq!(result.plaintext, bytes(&case["plaintext"]));
                    assert_eq!(
                        result.ratchet_id,
                        if case["ratchet_id"].is_null() {
                            None
                        } else {
                            Some(bytes(&case["ratchet_id"]).try_into().unwrap())
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn lifecycle_and_enforcement() {
        let id = Identity::from_private_key(&[3; 64]);
        let mut rng = FixedRng::new(&[7; 64]);
        let first = RatchetRing::new().rotated(100, 10, 2, &mut rng).unwrap();
        assert!(first.rotated(110, 10, 2, &mut rng).is_none());
        assert!(first.rotated(90, 10, 2, &mut rng).is_none());
        let ciphertext = id
            .encrypt_with_ratchet(b"", first.current_public().as_ref(), &mut rng)
            .unwrap();
        let second = first
            .rotated(111, 10, 2, &mut FixedRng::new(&[8; 64]))
            .unwrap();
        let result = id
            .decrypt_with_ratchets(&ciphertext, &second, true)
            .unwrap();
        assert!(result.plaintext.is_empty());
        assert_eq!(
            result.ratchet_id,
            Some(ratchet_id(&first.current_public().unwrap()))
        );
        let third = second
            .rotated(122, 10, 2, &mut FixedRng::new(&[9; 64]))
            .unwrap();
        assert!(id.decrypt_with_ratchets(&ciphertext, &third, true).is_err());
        let legacy = id.encrypt(b"legacy", &mut rng).unwrap();
        assert!(id.decrypt_with_ratchets(&legacy, &third, true).is_err());
        assert_eq!(
            id.decrypt_with_ratchets(&legacy, &third, false)
                .unwrap()
                .plaintext,
            b"legacy"
        );
        assert!(id
            .decrypt_with_ratchets(&legacy, &RatchetRing::new(), true)
            .is_err());
        for size in 0..100 {
            assert!(id
                .decrypt_with_ratchets(&alloc::vec![0; size], &third, true)
                .is_err());
        }
        assert!(Identity::from_private_key(&[4; 64])
            .decrypt_with_ratchets(&ciphertext, &first, true)
            .is_err());
    }
}
