use crate::bigint::BigUint;
use crate::sha512::sha512;
use super::basic::{
    self, bytes_to_clamped_scalar, bytes_to_scalar, scalar_to_bytes,
    base_point, affine_to_extended, extended_to_affine, encodepoint,
    scalarmult_element, bytes_to_element, l,
};

fn h(m: &[u8]) -> [u8; 64] {
    sha512(m)
}

/// Hint: SHA-512 of message, interpreted as little-endian integer
fn hint(m: &[u8]) -> BigUint {
    let hash = h(m);
    // Python: int(binascii.hexlify(h[::-1]), 16)
    // This is reading the hash bytes in reversed order as big-endian hex
    // which is the same as interpreting the hash as little-endian
    BigUint::from_bytes_le(&hash)
}

pub(crate) fn publickey(seed: &[u8; 32]) -> [u8; 32] {
    let h = h(seed);
    let a = bytes_to_clamped_scalar(&h[..32]);
    let bp = base_point();
    let bp_ext = affine_to_extended(&bp);
    let l_val = l();
    let a_mod = &a % &l_val;
    let result = scalarmult_element(&bp_ext, &a_mod);
    let affine = extended_to_affine(&result);
    encodepoint(&affine)
}

pub(crate) fn signature(msg: &[u8], sk: &[u8; 32], pk: &[u8; 32]) -> [u8; 64] {
    let h_val = h(sk);
    let a_bytes = &h_val[..32];
    let inter = &h_val[32..];
    let a = bytes_to_clamped_scalar(a_bytes);
    let l_val = l();

    // r = Hint(inter || msg)
    let mut r_input = alloc::vec::Vec::with_capacity(inter.len() + msg.len());
    r_input.extend_from_slice(inter);
    r_input.extend_from_slice(msg);
    let r = hint(&r_input);

    // R = Base * r
    let bp = base_point();
    let bp_ext = affine_to_extended(&bp);
    let r_mod = &r % &l_val;
    let r_point = scalarmult_element(&bp_ext, &r_mod);
    let r_affine = extended_to_affine(&r_point);
    let r_bytes = encodepoint(&r_affine);

    // S = r + Hint(R_bytes || pk || msg) * a
    let mut hint_input = alloc::vec::Vec::with_capacity(32 + 32 + msg.len());
    hint_input.extend_from_slice(&r_bytes);
    hint_input.extend_from_slice(pk);
    hint_input.extend_from_slice(msg);
    let h_ram = hint(&hint_input);

    let s = &(&r + &(&h_ram * &a)) % &l_val;
    let s_bytes = scalar_to_bytes(&s);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(&s_bytes);
    sig
}

pub(crate) fn checkvalid(sig: &[u8; 64], msg: &[u8], pk: &[u8; 32]) -> bool {
    let r_bytes: [u8; 32] = sig[..32].try_into().unwrap();
    let s = bytes_to_scalar(&sig[32..]);

    let l_val = l();

    let r_point = match bytes_to_element(&r_bytes) {
        Ok(pt) => pt,
        Err(_) => return false,
    };
    let a_point = match bytes_to_element(pk) {
        Ok(pt) => pt,
        Err(_) => return false,
    };

    // h = Hint(R_bytes || pk || msg)
    let mut hint_input = alloc::vec::Vec::with_capacity(32 + 32 + msg.len());
    hint_input.extend_from_slice(&r_bytes);
    hint_input.extend_from_slice(pk);
    hint_input.extend_from_slice(msg);
    let h_val = hint(&hint_input);

    let bp = base_point();
    let bp_ext = affine_to_extended(&bp);

    // v1 = Base * S
    let s_mod = &s % &l_val;
    let v1 = scalarmult_element(&bp_ext, &s_mod);
    let v1_affine = extended_to_affine(&v1);

    // v2 = R + A * h
    let r_ext = affine_to_extended(&r_point);
    let a_ext = affine_to_extended(&a_point);
    let h_mod = &h_val % &l_val;
    let ah = scalarmult_element(&a_ext, &h_mod);
    let v2 = basic::add_elements(&r_ext, &ah);
    let v2_affine = extended_to_affine(&v2);

    encodepoint(&v1_affine) == encodepoint(&v2_affine)
}
