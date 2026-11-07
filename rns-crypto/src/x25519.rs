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

impl Drop for X25519PrivateKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.bytes);
    }
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
        #[cfg(all(
            feature = "x25519-aws-lc",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        if let Some(bytes) = aws_lc::public_key(&self.bytes) {
            return X25519PublicKey { bytes };
        }
        let secret = x25519_dalek::StaticSecret::from(self.bytes);
        let public = x25519_dalek::PublicKey::from(&secret);
        X25519PublicKey {
            bytes: *public.as_bytes(),
        }
    }

    pub fn exchange(&self, peer: &X25519PublicKey) -> [u8; 32] {
        #[cfg(all(
            feature = "x25519-aws-lc",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        if let Some(shared) = aws_lc::exchange(&self.bytes, &peer.bytes) {
            return shared;
        }
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

/// X25519 on aws-lc. It refuses an all-zero shared secret (a low-order
/// peer key), where x25519-dalek returns zeros; `None` leaves such a result
/// to x25519-dalek, so both builds agree.
///
/// aws-lc's raw functions, not its key objects: building a private key
/// object derives its public key, a second scalar multiplication on every
/// exchange.
#[cfg(all(
    feature = "x25519-aws-lc",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod aws_lc {
    use crate::aws_lc_init as init;

    pub(super) fn public_key(private: &[u8; 32]) -> Option<[u8; 32]> {
        init();
        let mut public = [0u8; 32];
        // SAFETY: both pointers address 32-byte arrays, as the function takes.
        unsafe { aws_lc_sys::X25519_public_from_private(public.as_mut_ptr(), private.as_ptr()) };
        Some(public)
    }

    pub(super) fn exchange(private: &[u8; 32], peer: &[u8; 32]) -> Option<[u8; 32]> {
        init();
        let mut shared = zeroize::Zeroizing::new([0u8; 32]);
        // SAFETY: all three pointers address 32-byte arrays, as the function
        // takes.
        let ok =
            unsafe { aws_lc_sys::X25519(shared.as_mut_ptr(), private.as_ptr(), peer.as_ptr()) };
        (ok == 1).then(|| *shared)
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

    /// x25519-dalek's results, whichever backend the build uses.
    fn reference_exchange(private: &[u8; 32], peer: &[u8; 32]) -> [u8; 32] {
        let secret = x25519_dalek::StaticSecret::from(clamp(*private));
        *secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(*peer))
            .as_bytes()
    }

    #[test]
    fn exchange_and_public_key_match_the_reference_for_any_peer_key() {
        let mut low_order = alloc::vec![[0u8; 32], {
            let mut one = [0u8; 32];
            one[0] = 1;
            one
        }];
        // The other low-order points of Curve25519, and one with the high bit.
        for hex in [
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ] {
            let bytes: alloc::vec::Vec<u8> = (0..32)
                .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
                .collect();
            low_order.push(bytes.try_into().unwrap());
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            let mut out = [0u8; 32];
            for byte in &mut out {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            out
        };
        for round in 0..200 {
            let private = X25519PrivateKey::from_bytes(&next());
            let mut peer = next();
            if round % 2 == 0 {
                peer[31] |= 0x80;
            }
            let reference_public = x25519_dalek::PublicKey::from(
                &x25519_dalek::StaticSecret::from(private.private_bytes()),
            );
            assert_eq!(
                private.public_key().public_bytes(),
                *reference_public.as_bytes()
            );
            for peer in core::iter::once(peer).chain(low_order.iter().copied()) {
                assert_eq!(
                    private.exchange(&X25519PublicKey::from_bytes(&peer)),
                    reference_exchange(&private.private_bytes(), &peer),
                    "peer {peer:02x?}"
                );
            }
        }
    }
}
