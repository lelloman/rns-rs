use core::fmt;

use crate::Rng;
use ed25519_dalek::Signer;
use ed25519_dalek::Verifier;

#[derive(Debug, PartialEq)]
pub enum Ed25519Error {
    /// The 32 bytes do not decode to a valid compressed Edwards point.
    InvalidPublicKey,
}

impl fmt::Display for Ed25519Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ed25519Error::InvalidPublicKey => write!(f, "Invalid Ed25519 public key bytes"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Ed25519Error {}

#[derive(Clone)]
pub struct Ed25519PrivateKey {
    inner: ed25519_dalek::SigningKey,
}

#[derive(Clone)]
pub struct Ed25519PublicKey {
    inner: ed25519_dalek::VerifyingKey,
}

impl Ed25519PrivateKey {
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Ed25519PrivateKey {
            inner: ed25519_dalek::SigningKey::from_bytes(seed),
        }
    }

    pub fn generate(rng: &mut dyn Rng) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_bytes(&seed)
    }

    pub fn private_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey {
            inner: self.inner.verifying_key(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        #[cfg(feature = "ed25519-aws-lc")]
        if let Some(signature) = self.sign_aws_lc(message) {
            return signature;
        }
        self.inner.sign(message).to_bytes()
    }

    /// The same signature from aws-lc, which signs in about half the time
    /// (Ed25519 signatures are deterministic, so the bytes are identical).
    #[cfg(feature = "ed25519-aws-lc")]
    fn sign_aws_lc(&self, message: &[u8]) -> Option<[u8; 64]> {
        crate::aws_lc_init();
        // aws-lc's private key form: the seed, then the public key.
        let mut key = zeroize::Zeroizing::new([0u8; 64]);
        key[..32].copy_from_slice(self.inner.as_bytes());
        key[32..].copy_from_slice(self.inner.verifying_key().as_bytes());
        let mut signature = [0u8; 64];
        // SAFETY: `signature` and `key` are 64 bytes and `message` is
        // `message.len()` bytes, as the function takes.
        let ok = unsafe {
            aws_lc_sys::ED25519_sign(
                signature.as_mut_ptr(),
                message.as_ptr(),
                message.len(),
                key.as_ptr(),
            )
        };
        (ok == 1).then_some(signature)
    }
}

impl Ed25519PublicKey {
    /// Decode a compressed Ed25519 public key.
    ///
    /// Not every 32-byte string is a valid point encoding; such input
    /// returns `Ed25519Error::InvalidPublicKey`.
    pub fn from_bytes(data: &[u8; 32]) -> Result<Self, Ed25519Error> {
        ed25519_dalek::VerifyingKey::from_bytes(data)
            .map(|inner| Ed25519PublicKey { inner })
            .map_err(|_| Ed25519Error::InvalidPublicKey)
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    pub fn verify(&self, signature: &[u8; 64], message: &[u8]) -> bool {
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        self.inner.verify(message, &sig).is_ok()
    }
}

/// Check several signatures at once: true only when every one is valid.
///
/// One multiscalar multiplication covers the whole batch, so a batch costs
/// a fraction of checking each signature with [`Ed25519PublicKey::verify`].
/// A false result does not say which signature failed; check them one by
/// one to find out. The batch equation is the cofactored one, so a
/// signature crafted with small-order components can pass here and fail
/// [`Ed25519PublicKey::verify`]: only its signer can make one, and an honest
/// signature passes both.
#[cfg(feature = "ed25519-batch")]
pub fn verify_batch(items: &[(&Ed25519PublicKey, &[u8; 64], &[u8])]) -> bool {
    use alloc::vec::Vec;
    let messages: Vec<&[u8]> = items.iter().map(|(_, _, message)| *message).collect();
    let signatures: Vec<ed25519_dalek::Signature> = items
        .iter()
        .map(|(_, signature, _)| ed25519_dalek::Signature::from_bytes(signature))
        .collect();
    let keys: Vec<ed25519_dalek::VerifyingKey> =
        items.iter().map(|(key, _, _)| key.inner).collect();
    ed25519_dalek::verify_batch(&messages, &signatures, &keys).is_ok()
}

#[cfg(test)]
mod tests {

    #[cfg(feature = "ed25519-aws-lc")]
    #[test]
    fn aws_lc_signs_the_same_bytes_as_dalek() {
        use ed25519_dalek::Signer;
        for seed in 0u8..32 {
            let key = Ed25519PrivateKey::from_bytes(&[seed.wrapping_mul(37).wrapping_add(1); 32]);
            for len in [0usize, 1, 32, 64, 500] {
                let message: Vec<u8> = (0..len).map(|i| (i as u8) ^ seed).collect();
                let expected = key.inner.sign(&message).to_bytes();
                assert_eq!(key.sign_aws_lc(&message), Some(expected));
                assert_eq!(key.sign(&message), expected);
                assert!(key.public_key().verify(&expected, &message));
            }
        }
    }

    use super::*;

    #[cfg(feature = "ed25519-batch")]
    #[test]
    fn batch_accepts_valid_signatures_and_rejects_any_bad_one() {
        let keys: alloc::vec::Vec<Ed25519PrivateKey> = (0u8..8)
            .map(|i| Ed25519PrivateKey::from_bytes(&[i + 1; 32]))
            .collect();
        let messages: alloc::vec::Vec<[u8; 32]> = (0u8..8).map(|i| [i; 32]).collect();
        let publics: alloc::vec::Vec<Ed25519PublicKey> =
            keys.iter().map(|key| key.public_key()).collect();
        let mut signatures: alloc::vec::Vec<[u8; 64]> = keys
            .iter()
            .zip(&messages)
            .map(|(key, message)| key.sign(message))
            .collect();
        let items = |signatures: &[[u8; 64]]| -> bool {
            let batch: alloc::vec::Vec<(&Ed25519PublicKey, &[u8; 64], &[u8])> = publics
                .iter()
                .zip(signatures)
                .zip(&messages)
                .map(|((key, signature), message)| (key, signature, &message[..]))
                .collect();
            verify_batch(&batch)
        };
        assert!(items(&signatures));
        assert!(verify_batch(&[]));
        signatures[5][0] ^= 1;
        assert!(!items(&signatures));
    }

    struct Rfc8032Vector {
        seed: &'static str,
        public_key: &'static str,
        message: &'static str,
        signature: &'static str,
    }

    const RFC8032_VECTORS: &[Rfc8032Vector] = &[
        Rfc8032Vector {
            seed: "9d61b19deffd5a60ba844af492ec2cc4\
                   4449c5697b326919703bac031cae7f60",
            public_key: "d75a980182b10ab7d54bfed3c964073a\
                         0ee172f3daa62325af021a68f707511a",
            message: "",
            signature: "e5564300c360ac729086e2cc806e828a\
                        84877f1eb8e5d974d873e06522490155\
                        5fb8821590a33bacc61e39701cf9b46b\
                        d25bf5f0595bbe24655141438e7a100b",
        },
        Rfc8032Vector {
            seed: "4ccd089b28ff96da9db6c346ec114e0f\
                   5b8a319f35aba624da8cf6ed4fb8a6fb",
            public_key: "3d4017c3e843895a92b70aa74d1b7ebc\
                         9c982ccf2ec4968cc0cd55f12af4660c",
            message: "72",
            signature: "92a009a9f0d4cab8720e820b5f642540\
                        a2b27b5416503f8fb3762223ebdb69da\
                        085ac1e43e15996e458f3613d0f11d8c\
                        387b2eaeb4302aeeb00d291612bb0c00",
        },
        Rfc8032Vector {
            seed: "c5aa8df43f9f837bedb7442f31dcb7b1\
                   66d38535076f094b85ce3a2e0b4458f7",
            public_key: "fc51cd8e6218a1a38da47ed00230f058\
                         0816ed13ba3303ac5deb911548908025",
            message: "af82",
            signature: "6291d657deec24024827e69c3abe01a3\
                        0ce548a284743a445e3680d7db5ac3ac\
                        18ff9b538d16f290ae67f760984dc659\
                        4a7c15e9716ed28dc027beceea1ec40a",
        },
    ];

    #[test]
    fn test_ed25519_sign_verify_roundtrip() {
        let seed = [42u8; 32];
        let key = Ed25519PrivateKey::from_bytes(&seed);
        let pubkey = key.public_key();
        let msg = b"Hello, Ed25519!";
        let sig = key.sign(msg);
        assert!(pubkey.verify(&sig, msg));
    }

    #[test]
    fn test_ed25519_verify_tampered() {
        let seed = [42u8; 32];
        let key = Ed25519PrivateKey::from_bytes(&seed);
        let pubkey = key.public_key();
        let msg = b"Hello, Ed25519!";
        let sig = key.sign(msg);
        assert!(!pubkey.verify(&sig, b"Hello, Ed25519?"));
    }

    #[test]
    fn test_ed25519_pubkey_deterministic() {
        let seed = [1u8; 32];
        let key1 = Ed25519PrivateKey::from_bytes(&seed);
        let key2 = Ed25519PrivateKey::from_bytes(&seed);
        assert_eq!(
            key1.public_key().public_bytes(),
            key2.public_key().public_bytes()
        );
    }

    #[test]
    fn test_ed25519_rfc8032_known_answers() {
        for vector in RFC8032_VECTORS {
            let seed: [u8; 32] = decode_hex(vector.seed).try_into().unwrap();
            let expected_public: [u8; 32] = decode_hex(vector.public_key).try_into().unwrap();
            let message = decode_hex(vector.message);
            let expected_signature: [u8; 64] = decode_hex(vector.signature).try_into().unwrap();
            let key = Ed25519PrivateKey::from_bytes(&seed);

            assert_eq!(key.private_bytes(), seed);
            assert_eq!(key.public_key().public_bytes(), expected_public);
            assert_eq!(key.sign(&message), expected_signature);
            assert!(key.public_key().verify(&expected_signature, &message));
            assert!(Ed25519PublicKey::from_bytes(&expected_public)
                .unwrap()
                .verify(&expected_signature, &message));
        }
    }

    #[test]
    fn test_ed25519_rejects_signature_and_message_mutations() {
        let key = Ed25519PrivateKey::from_bytes(&[0x42; 32]);
        let public = key.public_key();
        let message = b"Reticulum signature compatibility";
        let signature = key.sign(message);

        for index in [0, 31, 32, 63] {
            let mut mutated = signature;
            mutated[index] ^= 0x80;
            assert!(!public.verify(&mutated, message));
        }

        let mut mutated_message = *b"Reticulum signature compatibility";
        mutated_message[0] ^= 1;
        assert!(!public.verify(&signature, &mutated_message));
    }

    #[test]
    fn test_ed25519_rejects_noncanonical_scalar() {
        let key = Ed25519PrivateKey::from_bytes(&[0x24; 32]);
        let public = key.public_key();
        let message = b"noncanonical signature scalar";
        let mut signature = key.sign(message);

        signature[32..].copy_from_slice(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ]);

        assert!(!public.verify(&signature, message));
    }

    #[test]
    fn test_ed25519_invalid_public_key_bytes_return_error() {
        // y = 2 has no corresponding x on the curve, so this is not a valid
        // compressed point encoding.
        let mut invalid = [0u8; 32];
        invalid[0] = 2;
        assert!(matches!(
            Ed25519PublicKey::from_bytes(&invalid),
            Err(Ed25519Error::InvalidPublicKey)
        ));
    }

    #[test]
    fn test_ed25519_valid_public_key_bytes_roundtrip() {
        let public = Ed25519PrivateKey::from_bytes(&[7; 32]).public_key();
        let bytes = public.public_bytes();
        let decoded = Ed25519PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.public_bytes(), bytes);
    }

    fn decode_hex(hex: &str) -> alloc::vec::Vec<u8> {
        let compact: alloc::string::String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        (0..compact.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&compact[index..index + 2], 16).unwrap())
            .collect()
    }
}
