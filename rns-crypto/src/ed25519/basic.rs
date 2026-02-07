use crate::bigint::{BigUint, mod_pow};
use alloc::vec::Vec;

/// Q = 2^255 - 19
pub(crate) fn q() -> BigUint {
    &(&BigUint::one() << 255) - &BigUint::from_u64(19)
}

/// L = 2^252 + 27742317777372353535851937790883648493
pub(crate) fn l() -> BigUint {
    let base = &BigUint::one() << 252;
    // 27742317777372353535851937790883648493 in bytes (big-endian hex):
    // 14def9dea2f79cd65812631a5cf5d3ed
    let offset_hex = b"14def9dea2f79cd65812631a5cf5d3ed";
    let offset = BigUint::from_bytes_be(&hex_decode(offset_hex));
    &base + &offset
}

fn hex_decode(hex: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let hi = hex_char(hex[i]);
        let lo = hex_char(hex[i + 1]);
        result.push((hi << 4) | lo);
    }
    result
}

fn hex_char(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("invalid hex char"),
    }
}

pub(crate) fn inv(x: &BigUint) -> BigUint {
    let q = q();
    let exp = &q - &BigUint::from_u64(2);
    mod_pow(x, &exp, &q)
}

/// d = -121665 * inv(121666) mod Q
pub(crate) fn d_const() -> BigUint {
    let q = q();
    let inv_121666 = inv(&BigUint::from_u64(121666));
    // -121665 mod Q = Q - 121665
    let neg = &q - &BigUint::from_u64(121665);
    &(&neg * &inv_121666) % &q
}

/// I = 2^((Q-1)/4) mod Q
pub(crate) fn i_const() -> BigUint {
    let q = q();
    let exp = &(&q - &BigUint::one()) >> 2; // (Q-1)/4 since Q-1 is divisible by 4
    mod_pow(&BigUint::from_u64(2), &exp, &q)
}

pub(crate) fn xrecover(y: &BigUint) -> BigUint {
    let q = q();
    let d = d_const();
    let i_val = i_const();

    // xx = (y*y - 1) * inv(d*y*y + 1)
    let yy = &(y * y) % &q;
    let num = if yy >= BigUint::one() {
        &yy - &BigUint::one()
    } else {
        &(&q + &yy) - &BigUint::one()
    };
    let den_inner = &(&d * &yy) % &q;
    let den = &(&den_inner + &BigUint::one()) % &q;
    let xx = &(&num * &inv(&den)) % &q;

    // x = pow(xx, (Q+3)/8, Q)
    let exp = &(&q + &BigUint::from_u64(3)) >> 3;
    let mut x = mod_pow(&xx, &exp, &q);

    // if (x*x - xx) % Q != 0: x = (x * I) % Q
    let x2 = &(&x * &x) % &q;
    let diff = if x2 >= xx {
        &(&x2 - &xx) % &q
    } else {
        &(&q - &(&xx - &x2)) % &q
    };
    if !diff.is_zero() {
        x = &(&x * &i_val) % &q;
    }

    // if x % 2 != 0: x = Q - x
    if x.bit(0) {
        x = &q - &x;
    }

    x
}

/// Base point B = (xrecover(By), By) where By = 4 * inv(5)
pub(crate) fn base_point() -> (BigUint, BigUint) {
    let q = q();
    let by = &(&BigUint::from_u64(4) * &inv(&BigUint::from_u64(5))) % &q;
    let bx = &xrecover(&by) % &q;
    (bx, by)
}

/// Extended coordinates (X, Y, Z, T) where x=X/Z, y=Y/Z, x*y=T/Z
pub(crate) type ExtendedPoint = (BigUint, BigUint, BigUint, BigUint);

pub(crate) fn affine_to_extended(pt: &(BigUint, BigUint)) -> ExtendedPoint {
    let q = q();
    let (x, y) = pt;
    let x = x % &q;
    let y = y % &q;
    let t = &(&x * &y) % &q;
    (x, y, BigUint::one(), t)
}

pub(crate) fn extended_to_affine(pt: &ExtendedPoint) -> (BigUint, BigUint) {
    let q = q();
    let (x, y, z, _) = pt;
    let inv_z = inv(z);
    let ax = &(x * &inv_z) % &q;
    let ay = &(y * &inv_z) % &q;
    (ax, ay)
}

pub(crate) fn double_element(pt: &ExtendedPoint) -> ExtendedPoint {
    let q = q();
    let (x1, y1, z1, _) = pt;

    let a = &(x1 * x1) % &q;
    let b_val = &(y1 * y1) % &q;
    let c = &(&BigUint::from_u64(2) * &(&(z1 * z1) % &q)) % &q;
    // D = (-A) % Q
    let d_val = &(&q - &a) % &q;
    // J = (X1 + Y1) % Q
    let j = &(x1 + y1) % &q;
    // E = (J*J - A - B) % Q
    let jj = &(&j * &j) % &q;
    let e_tmp = if jj >= a {
        &jj - &a
    } else {
        &(&q - &(&a - &jj)) % &q
    };
    let e = if e_tmp >= b_val {
        &(&e_tmp - &b_val) % &q
    } else {
        &(&q - &(&b_val - &e_tmp)) % &q
    };
    // G = (D + B) % Q
    let g = &(&d_val + &b_val) % &q;
    // F = (G - C) % Q
    let f = if g >= c {
        &(&g - &c) % &q
    } else {
        &(&q - &(&c - &g)) % &q
    };
    // H = (D - B) % Q
    let h = if d_val >= b_val {
        &(&d_val - &b_val) % &q
    } else {
        &(&q - &(&b_val - &d_val)) % &q
    };

    let x3 = &(&e * &f) % &q;
    let y3 = &(&g * &h) % &q;
    let z3 = &(&f * &g) % &q;
    let t3 = &(&e * &h) % &q;
    (x3, y3, z3, t3)
}

/// add-2008-hwcd-4: NOT unified, only for pt1 != pt2
fn add_elements_nonunified(pt1: &ExtendedPoint, pt2: &ExtendedPoint) -> ExtendedPoint {
    let q = q();
    let (x1, y1, z1, t1) = pt1;
    let (x2, y2, z2, t2) = pt2;

    // A = ((Y1-X1)*(Y2+X2)) % Q
    let y1_minus_x1 = if y1 >= x1 {
        &(y1 - x1) % &q
    } else {
        &(&q - &(x1 - y1)) % &q
    };
    let y2_plus_x2 = &(y2 + x2) % &q;
    let a = &(&y1_minus_x1 * &y2_plus_x2) % &q;

    // B = ((Y1+X1)*(Y2-X2)) % Q
    let y1_plus_x1 = &(y1 + x1) % &q;
    let y2_minus_x2 = if y2 >= x2 {
        &(y2 - x2) % &q
    } else {
        &(&q - &(x2 - y2)) % &q
    };
    let b_val = &(&y1_plus_x1 * &y2_minus_x2) % &q;

    // C = (Z1*2*T2) % Q
    let c = &(&(&BigUint::from_u64(2) * &(&(z1 * t2) % &q)) % &q) % &q;

    // D = (T1*2*Z2) % Q
    let d_val2 = &(&(&BigUint::from_u64(2) * &(&(t1 * z2) % &q)) % &q) % &q;

    // E = (D + C) % Q
    let e = &(&d_val2 + &c) % &q;
    // F = (B - A) % Q
    let f = if b_val >= a {
        &(&b_val - &a) % &q
    } else {
        &(&q - &(&a - &b_val)) % &q
    };
    // G = (B + A) % Q
    let g = &(&b_val + &a) % &q;
    // H = (D - C) % Q
    let h = if d_val2 >= c {
        &(&d_val2 - &c) % &q
    } else {
        &(&q - &(&c - &d_val2)) % &q
    };

    let x3 = &(&e * &f) % &q;
    let y3 = &(&g * &h) % &q;
    let z3 = &(&f * &g) % &q;
    let t3 = &(&e * &h) % &q;
    (x3, y3, z3, t3)
}

/// add-2008-hwcd-3: Unified (safe for general-purpose addition)
pub(crate) fn add_elements(pt1: &ExtendedPoint, pt2: &ExtendedPoint) -> ExtendedPoint {
    let q = q();
    let d = d_const();
    let (x1, y1, z1, t1) = pt1;
    let (x2, y2, z2, t2) = pt2;

    // A = ((Y1-X1)*(Y2-X2)) % Q
    let y1_minus_x1 = if y1 >= x1 {
        &(y1 - x1) % &q
    } else {
        &(&q - &(x1 - y1)) % &q
    };
    let y2_minus_x2 = if y2 >= x2 {
        &(y2 - x2) % &q
    } else {
        &(&q - &(x2 - y2)) % &q
    };
    let a = &(&y1_minus_x1 * &y2_minus_x2) % &q;

    // B = ((Y1+X1)*(Y2+X2)) % Q
    let y1_plus_x1 = &(y1 + x1) % &q;
    let y2_plus_x2 = &(y2 + x2) % &q;
    let b_val = &(&y1_plus_x1 * &y2_plus_x2) % &q;

    // C = T1*(2*d)*T2 % Q
    let two_d = &(&BigUint::from_u64(2) * &d) % &q;
    let t1_2d = &(t1 * &two_d) % &q;
    let c = &(&t1_2d * t2) % &q;

    // D = Z1*2*Z2 % Q
    let z1_2 = &(z1 * &BigUint::from_u64(2)) % &q;
    let d_val2 = &(&z1_2 * z2) % &q;

    // E = (B - A) % Q
    let e = if b_val >= a {
        &(&b_val - &a) % &q
    } else {
        &(&q - &(&a - &b_val)) % &q
    };
    // F = (D - C) % Q
    let f = if d_val2 >= c {
        &(&d_val2 - &c) % &q
    } else {
        &(&q - &(&c - &d_val2)) % &q
    };
    // G = (D + C) % Q
    let g = &(&d_val2 + &c) % &q;
    // H = (B + A) % Q
    let h = &(&b_val + &a) % &q;

    let x3 = &(&e * &f) % &q;
    let y3 = &(&g * &h) % &q;
    let t3 = &(&e * &h) % &q;
    let z3 = &(&f * &g) % &q;
    (x3, y3, z3, t3)
}

/// Scalar multiplication (for main 1*L subgroup points using non-unified addition)
pub(crate) fn scalarmult_element(pt: &ExtendedPoint, n: &BigUint) -> ExtendedPoint {
    if n.is_zero() {
        return affine_to_extended(&(BigUint::zero(), BigUint::one()));
    }
    let doubled = double_element(&scalarmult_element(pt, &(n >> 1)));
    if n.bit(0) {
        add_elements_nonunified(&doubled, pt)
    } else {
        doubled
    }
}

/// Scalar multiplication using unified addition (safe for all points)
pub(crate) fn scalarmult_element_safe(pt: &ExtendedPoint, n: &BigUint) -> ExtendedPoint {
    if n.is_zero() {
        return affine_to_extended(&(BigUint::zero(), BigUint::one()));
    }
    let doubled = double_element(&scalarmult_element_safe(pt, &(n >> 1)));
    if n.bit(0) {
        add_elements(&doubled, pt)
    } else {
        doubled
    }
}

pub(crate) fn encodepoint(pt: &(BigUint, BigUint)) -> [u8; 32] {
    let (x, y) = pt;
    let mut y_val = y.clone();
    if x.bit(0) {
        y_val.set_bit(255, true);
    }
    let bytes = y_val.to_bytes_le(32);
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes[..32]);
    result
}

pub(crate) fn isoncurve(pt: &(BigUint, BigUint)) -> bool {
    let q = q();
    let d = d_const();
    let (x, y) = pt;
    let xx = &(x * x) % &q;
    let yy = &(y * y) % &q;
    let dxxyy = &(&d * &(&(&xx * &yy) % &q)) % &q;

    // -x*x + y*y - 1 - d*x*x*y*y ≡ 0 (mod Q)
    // Compute: (Q - xx + yy + Q - 1 + Q - dxxyy) % Q
    let mut val = &q - &xx;
    val = &(&val + &yy) % &q;
    val = if val >= BigUint::one() {
        &(&val - &BigUint::one()) % &q
    } else {
        &(&q - &(&BigUint::one() - &val)) % &q
    };
    val = if val >= dxxyy {
        &(&val - &dxxyy) % &q
    } else {
        &(&q - &(&dxxyy - &val)) % &q
    };
    val.is_zero()
}

pub(crate) fn decodepoint(s: &[u8; 32]) -> (BigUint, BigUint) {
    let q = q();
    let unclamped = BigUint::from_bytes_le(s);
    // Clear MSB to get y
    let mut clamp = BigUint::one();
    clamp = &clamp << 255;
    clamp = &clamp - &BigUint::one();
    let y = &unclamped & &clamp;

    let mut x = xrecover(&y);

    // Check sign bit
    let sign_bit = unclamped.bit(255);
    if x.bit(0) != sign_bit {
        x = &q - &x;
    }

    let pt = (x, y);
    assert!(isoncurve(&pt), "decoding point that is not on curve");
    pt
}

/// Decode a point and verify it belongs to the prime-order L subgroup.
/// Mirrors Python's bytes_to_element() in basic.py:359-368.
pub(crate) fn bytes_to_element(s: &[u8; 32]) -> Result<(BigUint, BigUint), &'static str> {
    let pt = decodepoint(s);
    let ext = affine_to_extended(&pt);
    if is_extended_zero(&ext) {
        return Err("element was Zero");
    }
    let l_val = l();
    let scaled = scalarmult_element_safe(&ext, &l_val);
    if !is_extended_zero(&scaled) {
        return Err("element is not in the right group");
    }
    Ok(pt)
}

pub(crate) fn bytes_to_scalar(s: &[u8]) -> BigUint {
    assert_eq!(s.len(), 32);
    BigUint::from_bytes_le(s)
}

pub(crate) fn bytes_to_clamped_scalar(s: &[u8]) -> BigUint {
    let a = bytes_to_scalar(s);
    // AND_CLAMP = (1<<254) - 1 - 7
    let and_clamp = &(&(&BigUint::one() << 254) - &BigUint::one()) - &BigUint::from_u64(7);
    // OR_CLAMP = 1<<254
    let or_clamp = &BigUint::one() << 254;
    &(&a & &and_clamp) | &or_clamp
}

pub(crate) fn scalar_to_bytes(y: &BigUint) -> [u8; 32] {
    let l = l();
    let reduced = y % &l;
    let bytes = reduced.to_bytes_le(32);
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes[..32]);
    result
}

pub(crate) fn is_extended_zero(pt: &ExtendedPoint) -> bool {
    let q = q();
    let (x, y, z, _) = pt;
    let y_mod = y % &q;
    let z_mod = z % &q;
    x.is_zero() && y_mod == z_mod && !y_mod.is_zero()
}
