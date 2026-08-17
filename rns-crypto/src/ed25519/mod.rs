use crate::Rng;
use ed25519_dalek::Signer;
use ed25519_dalek::Verifier;

pub struct Ed25519PrivateKey {
    inner: ed25519_dalek::SigningKey,
}

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
        self.inner.sign(message).to_bytes()
    }
}

impl Ed25519PublicKey {
    pub fn from_bytes(data: &[u8; 32]) -> Self {
        Ed25519PublicKey {
            inner: ed25519_dalek::VerifyingKey::from_bytes(data)
                .expect("invalid Ed25519 public key bytes"),
        }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    pub fn verify(&self, signature: &[u8; 64], message: &[u8]) -> bool {
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        self.inner.verify(message, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn decode_hex(hex: &str) -> alloc::vec::Vec<u8> {
        let compact: alloc::string::String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        (0..compact.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&compact[index..index + 2], 16).unwrap())
            .collect()
    }
}
