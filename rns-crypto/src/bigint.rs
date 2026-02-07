use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::ops::{Add, BitAnd, BitOr, Mul, Rem, Shl, Shr, Sub};

/// Variable-width unsigned big integer, Vec<u64> limbs (little-endian).
/// limbs[0] is the least significant 64-bit word.
#[derive(Clone, Debug)]
pub struct BigUint {
    limbs: Vec<u64>,
}

impl BigUint {
    pub fn zero() -> Self {
        BigUint { limbs: vec![0] }
    }

    pub fn one() -> Self {
        BigUint { limbs: vec![1] }
    }

    pub fn from_u64(v: u64) -> Self {
        BigUint { limbs: vec![v] }
    }

    fn normalize(&mut self) {
        while self.limbs.len() > 1 && *self.limbs.last().unwrap() == 0 {
            self.limbs.pop();
        }
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&x| x == 0)
    }

    pub fn bit(&self, i: usize) -> bool {
        let limb_idx = i / 64;
        let bit_idx = i % 64;
        if limb_idx >= self.limbs.len() {
            false
        } else {
            (self.limbs[limb_idx] >> bit_idx) & 1 == 1
        }
    }

    pub fn bits(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        let top = self.limbs.len() - 1;
        let top_bits = 64 - self.limbs[top].leading_zeros() as usize;
        top * 64 + top_bits
    }

    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }
        let mut limbs = Vec::with_capacity((bytes.len() + 7) / 8);
        for chunk in bytes.chunks(8) {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            limbs.push(u64::from_le_bytes(buf));
        }
        let mut r = BigUint { limbs };
        r.normalize();
        r
    }

    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }
        let mut reversed = bytes.to_vec();
        reversed.reverse();
        Self::from_bytes_le(&reversed)
    }

    pub fn to_bytes_le(&self, size: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.limbs.len() * 8);
        for &limb in &self.limbs {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
        bytes.resize(size, 0);
        bytes.truncate(size);
        bytes
    }

    pub fn to_bytes_be(&self, size: usize) -> Vec<u8> {
        let mut bytes = self.to_bytes_le(size);
        bytes.reverse();
        bytes
    }

    /// Set a specific bit
    pub fn set_bit(&mut self, i: usize, val: bool) {
        let limb_idx = i / 64;
        let bit_idx = i % 64;
        while self.limbs.len() <= limb_idx {
            self.limbs.push(0);
        }
        if val {
            self.limbs[limb_idx] |= 1u64 << bit_idx;
        } else {
            self.limbs[limb_idx] &= !(1u64 << bit_idx);
        }
        self.normalize();
    }

    /// Clear a specific bit
    pub fn clear_bit(&mut self, i: usize) {
        self.set_bit(i, false);
    }
}

impl PartialEq for BigUint {
    fn eq(&self, other: &Self) -> bool {
        // Compare normalized forms
        let a = {
            let mut c = self.clone();
            c.normalize();
            c
        };
        let b = {
            let mut c = other.clone();
            c.normalize();
            c
        };
        a.limbs == b.limbs
    }
}

impl Eq for BigUint {}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        let a_bits = self.bits();
        let b_bits = other.bits();
        if a_bits != b_bits {
            return a_bits.cmp(&b_bits);
        }
        // Same number of significant bits, compare from most significant limb
        let max_len = self.limbs.len().max(other.limbs.len());
        for i in (0..max_len).rev() {
            let a = if i < self.limbs.len() { self.limbs[i] } else { 0 };
            let b = if i < other.limbs.len() { other.limbs[i] } else { 0 };
            match a.cmp(&b) {
                Ordering::Equal => continue,
                other => return other,
            }
        }
        Ordering::Equal
    }
}

impl Add for &BigUint {
    type Output = BigUint;
    fn add(self, rhs: &BigUint) -> BigUint {
        let max_len = self.limbs.len().max(rhs.limbs.len());
        let mut result = Vec::with_capacity(max_len + 1);
        let mut carry = 0u64;
        for i in 0..max_len {
            let a = if i < self.limbs.len() { self.limbs[i] } else { 0 };
            let b = if i < rhs.limbs.len() { rhs.limbs[i] } else { 0 };
            let (sum1, c1) = a.overflowing_add(b);
            let (sum2, c2) = sum1.overflowing_add(carry);
            result.push(sum2);
            carry = (c1 as u64) + (c2 as u64);
        }
        if carry > 0 {
            result.push(carry);
        }
        let mut r = BigUint { limbs: result };
        r.normalize();
        r
    }
}

impl Add for BigUint {
    type Output = BigUint;
    fn add(self, rhs: BigUint) -> BigUint {
        &self + &rhs
    }
}

impl Sub for &BigUint {
    type Output = BigUint;
    fn sub(self, rhs: &BigUint) -> BigUint {
        assert!(self >= rhs, "BigUint subtraction underflow");
        let mut result = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0i64;
        for i in 0..self.limbs.len() {
            let a = self.limbs[i] as i128;
            let b = if i < rhs.limbs.len() { rhs.limbs[i] as i128 } else { 0 };
            let diff = a - b - borrow as i128;
            if diff < 0 {
                result.push((diff + (1i128 << 64)) as u64);
                borrow = 1;
            } else {
                result.push(diff as u64);
                borrow = 0;
            }
        }
        let mut r = BigUint { limbs: result };
        r.normalize();
        r
    }
}

impl Sub for BigUint {
    type Output = BigUint;
    fn sub(self, rhs: BigUint) -> BigUint {
        &self - &rhs
    }
}

impl Mul for &BigUint {
    type Output = BigUint;
    fn mul(self, rhs: &BigUint) -> BigUint {
        if self.is_zero() || rhs.is_zero() {
            return BigUint::zero();
        }
        let mut result = vec![0u64; self.limbs.len() + rhs.limbs.len()];
        for i in 0..self.limbs.len() {
            let mut carry = 0u128;
            for j in 0..rhs.limbs.len() {
                let prod = (self.limbs[i] as u128) * (rhs.limbs[j] as u128)
                    + result[i + j] as u128
                    + carry;
                result[i + j] = prod as u64;
                carry = prod >> 64;
            }
            // Propagate carry upward through remaining result limbs
            let mut c = carry;
            let mut k = i + rhs.limbs.len();
            while c > 0 && k < result.len() {
                let sum = result[k] as u128 + c;
                result[k] = sum as u64;
                c = sum >> 64;
                k += 1;
            }
        }
        let mut r = BigUint { limbs: result };
        r.normalize();
        r
    }
}

impl Mul for BigUint {
    type Output = BigUint;
    fn mul(self, rhs: BigUint) -> BigUint {
        &self * &rhs
    }
}

/// Returns (quotient, remainder)
fn divmod(a: &BigUint, b: &BigUint) -> (BigUint, BigUint) {
    assert!(!b.is_zero(), "division by zero");

    if a < b {
        return (BigUint::zero(), a.clone());
    }

    if b.limbs.len() == 1 && b.limbs[0] != 0 {
        // Optimize single-limb divisor
        return divmod_single(a, b.limbs[0]);
    }

    let a_bits = a.bits();

    let mut quotient = BigUint::zero();
    let mut remainder = BigUint::zero();

    for i in (0..a_bits).rev() {
        // Shift remainder left by 1 and add the next bit of a
        remainder = &remainder << 1;
        if a.bit(i) {
            remainder = &remainder + &BigUint::one();
        }
        if remainder >= *b {
            remainder = &remainder - b;
            quotient.set_bit(i, true);
        }
    }

    quotient.normalize();
    remainder.normalize();
    (quotient, remainder)
}

fn divmod_single(a: &BigUint, b: u64) -> (BigUint, BigUint) {
    let mut result = vec![0u64; a.limbs.len()];
    let mut remainder = 0u128;
    for i in (0..a.limbs.len()).rev() {
        let dividend = (remainder << 64) | (a.limbs[i] as u128);
        result[i] = (dividend / b as u128) as u64;
        remainder = dividend % b as u128;
    }
    let mut q = BigUint { limbs: result };
    q.normalize();
    (q, BigUint::from_u64(remainder as u64))
}

impl Rem for &BigUint {
    type Output = BigUint;
    fn rem(self, rhs: &BigUint) -> BigUint {
        divmod(self, rhs).1
    }
}

impl Rem for BigUint {
    type Output = BigUint;
    fn rem(self, rhs: BigUint) -> BigUint {
        &self % &rhs
    }
}

impl Shl<usize> for &BigUint {
    type Output = BigUint;
    fn shl(self, shift: usize) -> BigUint {
        if self.is_zero() || shift == 0 {
            return self.clone();
        }
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        let mut result = vec![0u64; self.limbs.len() + word_shift + 1];
        if bit_shift == 0 {
            for i in 0..self.limbs.len() {
                result[i + word_shift] = self.limbs[i];
            }
        } else {
            let mut carry = 0u64;
            for i in 0..self.limbs.len() {
                let shifted = (self.limbs[i] as u128) << bit_shift;
                result[i + word_shift] = shifted as u64 | carry;
                carry = (shifted >> 64) as u64;
            }
            if carry > 0 {
                result[self.limbs.len() + word_shift] = carry;
            }
        }
        let mut r = BigUint { limbs: result };
        r.normalize();
        r
    }
}

impl Shl<usize> for BigUint {
    type Output = BigUint;
    fn shl(self, shift: usize) -> BigUint {
        &self << shift
    }
}

impl Shr<usize> for &BigUint {
    type Output = BigUint;
    fn shr(self, shift: usize) -> BigUint {
        if self.is_zero() || shift == 0 {
            return self.clone();
        }
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        if word_shift >= self.limbs.len() {
            return BigUint::zero();
        }
        let new_len = self.limbs.len() - word_shift;
        let mut result = vec![0u64; new_len];
        if bit_shift == 0 {
            for i in 0..new_len {
                result[i] = self.limbs[i + word_shift];
            }
        } else {
            for i in 0..new_len {
                result[i] = self.limbs[i + word_shift] >> bit_shift;
                if i + word_shift + 1 < self.limbs.len() {
                    result[i] |= self.limbs[i + word_shift + 1] << (64 - bit_shift);
                }
            }
        }
        let mut r = BigUint { limbs: result };
        r.normalize();
        r
    }
}

impl Shr<usize> for BigUint {
    type Output = BigUint;
    fn shr(self, shift: usize) -> BigUint {
        &self >> shift
    }
}

impl BitAnd for &BigUint {
    type Output = BigUint;
    fn bitand(self, rhs: &BigUint) -> BigUint {
        let min_len = self.limbs.len().min(rhs.limbs.len());
        let mut result = vec![0u64; min_len];
        for i in 0..min_len {
            result[i] = self.limbs[i] & rhs.limbs[i];
        }
        let mut r = BigUint { limbs: result };
        r.normalize();
        r
    }
}

impl BitAnd for BigUint {
    type Output = BigUint;
    fn bitand(self, rhs: BigUint) -> BigUint {
        &self & &rhs
    }
}

impl BitOr for &BigUint {
    type Output = BigUint;
    fn bitor(self, rhs: &BigUint) -> BigUint {
        let max_len = self.limbs.len().max(rhs.limbs.len());
        let mut result = vec![0u64; max_len];
        for i in 0..max_len {
            let a = if i < self.limbs.len() { self.limbs[i] } else { 0 };
            let b = if i < rhs.limbs.len() { rhs.limbs[i] } else { 0 };
            result[i] = a | b;
        }
        let mut r = BigUint { limbs: result };
        r.normalize();
        r
    }
}

impl BitOr for BigUint {
    type Output = BigUint;
    fn bitor(self, rhs: BigUint) -> BigUint {
        &self | &rhs
    }
}

/// Modular exponentiation: base^exp mod modulus
pub fn mod_pow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    assert!(!modulus.is_zero(), "modulus cannot be zero");
    if modulus == &BigUint::one() {
        return BigUint::zero();
    }

    let mut result = BigUint::one();
    let mut base = base % modulus;
    let exp_bits = exp.bits();

    for i in 0..exp_bits {
        if exp.bit(i) {
            result = &(&result * &base) % modulus;
        }
        base = &(&base * &base) % modulus;
    }

    result
}

/// Modular inverse using Fermat's little theorem: a^(p-2) mod p
/// Only works when p is prime.
pub fn mod_inv(a: &BigUint, p: &BigUint) -> BigUint {
    let exp = p - &BigUint::from_u64(2);
    mod_pow(a, &exp, p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biguint_from_to_bytes_le_roundtrip() {
        let bytes: Vec<u8> = (0..32).collect();
        let n = BigUint::from_bytes_le(&bytes);
        assert_eq!(n.to_bytes_le(32), bytes);
    }

    #[test]
    fn test_biguint_from_to_bytes_be_roundtrip() {
        let bytes: Vec<u8> = (0..32).collect();
        let n = BigUint::from_bytes_be(&bytes);
        assert_eq!(n.to_bytes_be(32), bytes);
    }

    #[test]
    fn test_biguint_add() {
        let a = BigUint::from_u64(u64::MAX);
        let b = BigUint::from_u64(1);
        let c = &a + &b;
        assert_eq!(c.limbs, vec![0, 1]);
    }

    #[test]
    fn test_biguint_sub() {
        let a = BigUint { limbs: vec![0, 1] }; // 2^64
        let b = BigUint::from_u64(1);
        let c = &a - &b;
        assert_eq!(c, BigUint::from_u64(u64::MAX));
    }

    #[test]
    fn test_biguint_mul() {
        let a = BigUint::from_u64(u64::MAX);
        let b = BigUint::from_u64(2);
        let c = &a * &b;
        // u64::MAX * 2 = 2^65 - 2
        assert_eq!(c.limbs, vec![u64::MAX - 1, 1]);
    }

    #[test]
    fn test_biguint_div_rem() {
        let a = BigUint::from_u64(100);
        let b = BigUint::from_u64(7);
        let (q, r) = divmod(&a, &b);
        assert_eq!(q, BigUint::from_u64(14));
        assert_eq!(r, BigUint::from_u64(2));
    }

    #[test]
    fn test_mod_pow() {
        // 2^10 mod 1000 = 1024 mod 1000 = 24
        let base = BigUint::from_u64(2);
        let exp = BigUint::from_u64(10);
        let modulus = BigUint::from_u64(1000);
        assert_eq!(mod_pow(&base, &exp, &modulus), BigUint::from_u64(24));
    }

    #[test]
    fn test_mod_inv() {
        // For prime p=17, inv(3) = 3^15 mod 17 = 6, since 3*6=18≡1 mod 17
        let a = BigUint::from_u64(3);
        let p = BigUint::from_u64(17);
        let inv = mod_inv(&a, &p);
        assert_eq!(inv, BigUint::from_u64(6));
        // Verify: a * inv mod p == 1
        let product = &(&a * &inv) % &p;
        assert_eq!(product, BigUint::one());
    }

    #[test]
    fn test_biguint_shift() {
        let a = BigUint::from_u64(1);
        let b = &a << 64;
        assert_eq!(b.limbs, vec![0, 1]);
        let c = &b >> 64;
        assert_eq!(c, BigUint::from_u64(1));
    }

    #[test]
    fn test_biguint_bitops() {
        let a = BigUint::from_u64(0xFF);
        let b = BigUint::from_u64(0x0F);
        assert_eq!(&a & &b, BigUint::from_u64(0x0F));
        assert_eq!(&a | &b, BigUint::from_u64(0xFF));
    }

    #[test]
    fn test_biguint_512bit() {
        // 64-byte value (for Ed25519 Hint)
        let bytes: Vec<u8> = (0..64).collect();
        let n = BigUint::from_bytes_be(&bytes);
        let roundtrip = n.to_bytes_be(64);
        assert_eq!(roundtrip, bytes);
    }

    #[test]
    fn test_biguint_mul_carry_propagation() {
        // Test that multiplication carry propagation works for large numbers
        // where result[i + rhs.limbs.len()] += carry can overflow
        let a = BigUint { limbs: vec![u64::MAX, u64::MAX, u64::MAX, u64::MAX] };
        let b = BigUint { limbs: vec![u64::MAX, u64::MAX, u64::MAX, u64::MAX] };
        let c = &a * &b;
        // Verify by checking: (2^256 - 1)^2 = 2^512 - 2^257 + 1
        let two_512 = &BigUint::one() << 512;
        let two_257 = &BigUint::one() << 257;
        let expected = &(&two_512 - &two_257) + &BigUint::one();
        assert_eq!(c, expected, "Large multiplication carry propagation failed");
    }

    #[test]
    fn test_biguint_bit() {
        let a = BigUint::from_u64(0b1010);
        assert!(!a.bit(0));
        assert!(a.bit(1));
        assert!(!a.bit(2));
        assert!(a.bit(3));
        assert!(!a.bit(100));
    }
}
