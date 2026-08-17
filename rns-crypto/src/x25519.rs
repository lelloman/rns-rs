use crate::Rng;

fn clamp(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes[0] &= 248; // clear bits 0, 1, 2
    bytes[31] &= 127; // clear bit 255
    bytes[31] |= 64; // set bit 254
    bytes
}

pub struct X25519PublicKey {
    bytes: [u8; 32],
}

pub struct X25519PrivateKey {
    bytes: [u8; 32], // clamped scalar
}

impl X25519PrivateKey {
    pub fn from_bytes(data: &[u8; 32]) -> Self {
        X25519PrivateKey {
            bytes: clamp(*data),
        }
    }

    pub fn generate(rng: &mut dyn Rng) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes(&bytes)
    }

    pub fn private_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    pub fn public_key(&self) -> X25519PublicKey {
        let secret = x25519_dalek::StaticSecret::from(self.bytes);
        let public = x25519_dalek::PublicKey::from(&secret);
        X25519PublicKey {
            bytes: *public.as_bytes(),
        }
    }

    pub fn exchange(&self, peer: &X25519PublicKey) -> [u8; 32] {
        let secret = x25519_dalek::StaticSecret::from(self.bytes);
        let peer_public = x25519_dalek::PublicKey::from(peer.bytes);
        *secret.diffie_hellman(&peer_public).as_bytes()
    }
}

impl X25519PublicKey {
    pub fn from_bytes(data: &[u8; 32]) -> Self {
        X25519PublicKey { bytes: *data }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_clamping() {
        let bytes = [0xFF; 32];
        let key = X25519PrivateKey::from_bytes(&bytes);
        let scalar_bytes = key.private_bytes();
        // Bits 0-2 should be cleared
        assert_eq!(scalar_bytes[0] & 7, 0);
        // Bit 255 (byte 31 bit 7) should be cleared
        assert_eq!(scalar_bytes[31] & 0x80, 0);
        // Bit 254 (byte 31 bit 6) should be set
        assert_eq!(scalar_bytes[31] & 0x40, 0x40);
    }

    #[test]
    fn test_x25519_roundtrip() {
        // RFC 7748 test vectors
        let alice_priv_bytes: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_priv_bytes: [u8; 32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];

        let alice = X25519PrivateKey::from_bytes(&alice_priv_bytes);
        let bob = X25519PrivateKey::from_bytes(&bob_priv_bytes);

        let alice_pub = alice.public_key();
        let bob_pub = bob.public_key();

        let shared_ab = alice.exchange(&bob_pub);
        let shared_ba = bob.exchange(&alice_pub);

        assert_eq!(
            alice_pub.public_bytes(),
            decode_hex_array("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            bob_pub.public_bytes(),
            decode_hex_array("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        assert_eq!(shared_ab, shared_ba);
        assert_eq!(
            shared_ab,
            decode_hex_array("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
    }

    #[test]
    fn test_x25519_private_serialization_is_clamped_and_idempotent() {
        for input in [[0; 32], [0xff; 32], [0x55; 32], [0xaa; 32]] {
            let first = X25519PrivateKey::from_bytes(&input);
            let serialized = first.private_bytes();
            let second = X25519PrivateKey::from_bytes(&serialized);

            assert_eq!(second.private_bytes(), serialized);
            assert_eq!(
                second.public_key().public_bytes(),
                first.public_key().public_bytes()
            );
        }
    }

    #[test]
    fn test_x25519_peer_u_coordinate_high_bit_is_ignored() {
        let private = X25519PrivateKey::from_bytes(&[0x42; 32]);
        let peer = X25519PrivateKey::from_bytes(&[0x24; 32]).public_key();
        let mut high_bit_peer = peer.public_bytes();
        high_bit_peer[31] ^= 0x80;

        assert_eq!(
            private.exchange(&peer),
            private.exchange(&X25519PublicKey::from_bytes(&high_bit_peer))
        );
    }

    #[test]
    fn test_x25519_low_order_peer_produces_zero_shared_secret() {
        let private = X25519PrivateKey::from_bytes(&[0x42; 32]);
        let zero_peer = X25519PublicKey::from_bytes(&[0; 32]);

        assert_eq!(private.exchange(&zero_peer), [0; 32]);
    }

    fn decode_hex_array(hex: &str) -> [u8; 32] {
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect::<alloc::vec::Vec<_>>()
            .try_into()
            .unwrap()
    }
}
