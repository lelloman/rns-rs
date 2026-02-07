use crate::bigint::{BigUint, mod_pow};
use crate::Rng;

/// P = 2^255 - 19
fn p() -> BigUint {
    let p255 = &BigUint::one() << 255;
    &p255 - &BigUint::from_u64(19)
}

const A: u64 = 486662;

fn unpack_number(s: &[u8; 32]) -> BigUint {
    BigUint::from_bytes_le(s)
}

fn pack_number(n: &BigUint) -> [u8; 32] {
    let bytes = n.to_bytes_le(32);
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes[..32]);
    result
}

fn fix_secret(n: &BigUint) -> BigUint {
    let mut n = n.clone();
    // n &= ~7
    n.clear_bit(0);
    n.clear_bit(1);
    n.clear_bit(2);
    // n &= ~(128 << 8 * 31) = clear bit 255
    n.clear_bit(255);
    // n |= 64 << 8 * 31 = set bit 254
    n.set_bit(254, true);
    n
}

#[cfg(test)]
fn fix_base_point(n: &BigUint) -> BigUint {
    let mut n = n.clone();
    // n &= ~(2^255) = clear bit 255
    n.clear_bit(255);
    n
}

type Point = (BigUint, BigUint);

fn point_add(point_n: &Point, point_m: &Point, point_diff: &Point, p: &BigUint) -> Point {
    let (ref xn, ref zn) = point_n;
    let (ref xm, ref zm) = point_m;
    let (ref x_diff, ref z_diff) = point_diff;

    // x = (z_diff << 2) * (xm * xn - zm * zn) ** 2
    let xm_xn = &(xm * xn) % p;
    let zm_zn = &(zm * zn) % p;
    // xm*xn - zm*zn mod p
    let diff = if xm_xn >= zm_zn {
        &xm_xn - &zm_zn
    } else {
        &(p - &(&zm_zn - &xm_xn)) % p
    };
    let diff_sq = &(&diff * &diff) % p;
    let z_diff_4 = &(z_diff << 2) % p;
    let x = &(&z_diff_4 * &diff_sq) % p;

    // z = (x_diff << 2) * (xm * zn - zm * xn) ** 2
    let xm_zn = &(xm * zn) % p;
    let zm_xn = &(zm * xn) % p;
    let diff2 = if xm_zn >= zm_xn {
        &xm_zn - &zm_xn
    } else {
        &(p - &(&zm_xn - &xm_zn)) % p
    };
    let diff2_sq = &(&diff2 * &diff2) % p;
    let x_diff_4 = &(x_diff << 2) % p;
    let z = &(&x_diff_4 * &diff2_sq) % p;

    (x, z)
}

fn point_double(point_n: &Point, p: &BigUint) -> Point {
    let (ref xn, ref zn) = point_n;
    let a_val = BigUint::from_u64(A);

    let xn2 = &(xn * xn) % p;
    let zn2 = &(zn * zn) % p;

    // x = (xn2 - zn2) ** 2
    let diff = if xn2 >= zn2 {
        &xn2 - &zn2
    } else {
        &(p - &(&zn2 - &xn2)) % p
    };
    let x = &(&diff * &diff) % p;

    // z = 4 * xzn * (xn2 + _A * xzn + zn2)
    let xzn = &(xn * zn) % p;
    let a_xzn = &(&a_val * &xzn) % p;
    let inner = &(&(&xn2 + &a_xzn) + &zn2) % p;
    let four = BigUint::from_u64(4);
    let z = &(&(&(&four * &xzn) % p) * &inner) % p;

    (x, z)
}

fn const_time_swap(a: &Point, b: &Point, swap: bool) -> (Point, Point) {
    if swap {
        (b.clone(), a.clone())
    } else {
        (a.clone(), b.clone())
    }
}

fn raw_curve25519(base: &BigUint, n: &BigUint) -> BigUint {
    let p = p();
    let zero: Point = (BigUint::one(), BigUint::zero());
    let one: Point = (base.clone(), BigUint::one());
    let mut m_p = zero;
    let mut m1_p = one.clone();

    for i in (0..256).rev() {
        let bit = n.bit(i);
        let (a, b) = const_time_swap(&m_p, &m1_p, bit);
        m_p = a;
        m1_p = b;
        let new_mp = point_double(&m_p, &p);
        let new_m1p = point_add(&m_p, &m1_p, &one, &p);
        m_p = new_mp;
        m1_p = new_m1p;
        let (a, b) = const_time_swap(&m_p, &m1_p, bit);
        m_p = a;
        m1_p = b;
    }

    let (ref x, ref z) = m_p;
    let p_minus_2 = &p - &BigUint::from_u64(2);
    let inv_z = mod_pow(z, &p_minus_2, &p);
    &(x * &inv_z) % &p
}

pub struct X25519PublicKey {
    x: [u8; 32],
}

pub struct X25519PrivateKey {
    scalar: BigUint,
}

impl X25519PrivateKey {
    pub fn from_bytes(data: &[u8; 32]) -> Self {
        let n = unpack_number(data);
        let scalar = fix_secret(&n);
        X25519PrivateKey { scalar }
    }

    pub fn generate(rng: &mut dyn Rng) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes(&bytes)
    }

    pub fn private_bytes(&self) -> [u8; 32] {
        pack_number(&self.scalar)
    }

    pub fn public_key(&self) -> X25519PublicKey {
        let nine = BigUint::from_u64(9);
        let result = raw_curve25519(&nine, &self.scalar);
        X25519PublicKey {
            x: pack_number(&result),
        }
    }

    pub fn exchange(&self, peer: &X25519PublicKey) -> [u8; 32] {
        let peer_x = unpack_number(&peer.x);
        let result = raw_curve25519(&peer_x, &self.scalar);
        pack_number(&result)
    }
}

impl X25519PublicKey {
    pub fn from_bytes(data: &[u8; 32]) -> Self {
        X25519PublicKey { x: *data }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.x
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
        // Known test: RFC 7748 test vectors
        // Alice's private key
        let alice_priv_bytes: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        // Bob's private key
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

    #[test]
    fn test_x25519_rfc7748_vector1() {
        // RFC 7748 Section 6.1
        let scalar_bytes: [u8; 32] = [
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d,
            0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
            0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18,
            0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4,
        ];
        let u_bytes: [u8; 32] = [
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb,
            0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
            0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b,
            0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c,
        ];
        let expected: [u8; 32] = [
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90,
            0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f,
            0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7,
            0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52,
        ];

        let scalar = fix_secret(&unpack_number(&scalar_bytes));
        let base = fix_base_point(&unpack_number(&u_bytes));
        let result = raw_curve25519(&base, &scalar);
        assert_eq!(pack_number(&result), expected);
    }
}
