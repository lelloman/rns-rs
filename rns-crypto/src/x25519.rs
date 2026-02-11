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
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_priv_bytes: [u8; 32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
            0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
            0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
            0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
        ];

        let alice = X25519PrivateKey::from_bytes(&alice_priv_bytes);
        let bob = X25519PrivateKey::from_bytes(&bob_priv_bytes);

        let alice_pub = alice.public_key();
        let bob_pub = bob.public_key();

        let shared_ab = alice.exchange(&bob_pub);
        let shared_ba = bob.exchange(&alice_pub);

        assert_eq!(shared_ab, shared_ba);
    }
}
