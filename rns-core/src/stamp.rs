//! Stamp validation functions for proof-of-work verification.
//!
//! These functions implement the stamp/workblock algorithm used for:
//! - LXMF message stamps
//! - Interface discovery verification
//! - Peering key validation

use alloc::vec::Vec;

use rns_crypto::hkdf::hkdf;
use rns_crypto::sha256::sha256;

extern crate alloc;

/// Generate a workblock from material with the specified number of HKDF expansion rounds.
///
/// Each round produces 256 bytes via HKDF with a salt derived from SHA256(material + msgpack(n)).
/// Total workblock size = rounds * 256 bytes.
pub fn stamp_workblock(material: &[u8], expand_rounds: u32) -> Vec<u8> {
    use crate::msgpack::{self, Value};

    let mut workblock = Vec::with_capacity(expand_rounds as usize * 256);
    for n in 0..expand_rounds {
        let packed_n = msgpack::pack(&Value::UInt(n as u64));
        let mut salt_input = Vec::with_capacity(material.len() + packed_n.len());
        salt_input.extend_from_slice(material);
        salt_input.extend_from_slice(&packed_n);
        let salt = sha256(&salt_input);

        let expanded = hkdf(256, material, Some(&salt), None)
            .expect("HKDF expansion should not fail");
        workblock.extend_from_slice(&expanded);
    }
    workblock
}

/// Count leading zero bits in a 32-byte hash.
pub fn leading_zeros(hash: &[u8; 32]) -> u32 {
    let mut count = 0u32;
    for &byte in hash.iter() {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Calculate the stamp value (number of leading zero bits in SHA256(workblock + stamp)).
pub fn stamp_value(workblock: &[u8], stamp: &[u8]) -> u32 {
    let mut material = Vec::with_capacity(workblock.len() + stamp.len());
    material.extend_from_slice(workblock);
    material.extend_from_slice(stamp);
    let hash = sha256(&material);
    leading_zeros(&hash)
}

/// Check if a stamp meets the target cost.
///
/// Returns true if SHA256(workblock + stamp) has >= target_cost leading zero bits.
pub fn stamp_valid(stamp: &[u8], target_cost: u8, workblock: &[u8]) -> bool {
    let mut material = Vec::with_capacity(workblock.len() + stamp.len());
    material.extend_from_slice(workblock);
    material.extend_from_slice(stamp);
    let result = sha256(&material);

    // Check: int.from_bytes(result, "big") <= (1 << (256 - target_cost))
    // Equivalent to: leading_zeros(result) >= target_cost
    // But Python uses `>` not `>=` for the comparison with target:
    //   target = 1 << (256 - target_cost)
    //   int.from_bytes(result) > target -> invalid
    // So valid means: int.from_bytes(result) <= target
    // Which is: leading_zeros >= target_cost
    leading_zeros(&result) >= target_cost as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leading_zeros_all_zero() {
        assert_eq!(leading_zeros(&[0u8; 32]), 256);
    }

    #[test]
    fn test_leading_zeros_first_byte_nonzero() {
        let mut hash = [0u8; 32];
        hash[0] = 0x80; // 10000000 - 0 leading zero bits
        assert_eq!(leading_zeros(&hash), 0);

        hash[0] = 0x40; // 01000000 - 1 leading zero bit
        assert_eq!(leading_zeros(&hash), 1);

        hash[0] = 0x01; // 00000001 - 7 leading zero bits
        assert_eq!(leading_zeros(&hash), 7);

        hash[0] = 0xFF; // 11111111 - 0 leading zero bits
        assert_eq!(leading_zeros(&hash), 0);
    }

    #[test]
    fn test_leading_zeros_multiple_bytes() {
        let mut hash = [0u8; 32];
        hash[0] = 0;
        hash[1] = 0x80; // 8 (from 0x00) + 0 (from 0x80) = 8 leading zero bits
        assert_eq!(leading_zeros(&hash), 8);

        hash[1] = 0x01; // 8 (from 0x00) + 7 (from 0x01) = 15 leading zero bits
        assert_eq!(leading_zeros(&hash), 15);
    }

    #[test]
    fn test_stamp_workblock_size() {
        let material = b"test material";
        let wb = stamp_workblock(material, 20);
        assert_eq!(wb.len(), 20 * 256);
    }

    #[test]
    fn test_stamp_workblock_deterministic() {
        let material = b"test material";
        let wb1 = stamp_workblock(material, 5);
        let wb2 = stamp_workblock(material, 5);
        assert_eq!(wb1, wb2);
    }

    #[test]
    fn test_python_interop_workblock_and_stamp() {
        // Values from Python:
        //   packed = b"test data"
        //   infohash = RNS.Identity.full_hash(packed)
        //   wb = LXStamper.stamp_workblock(infohash, expand_rounds=20)
        //   stamp = LXStamper.generate_stamp(infohash, stamp_cost=8, expand_rounds=20)[0]
        let infohash = hex_to_bytes("916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9");
        let expected_wb_prefix = hex_to_bytes("9e36b853221f04ca1cf54447abce3e9eb47d01d55215414ee5b540eaa796caf2");
        let stamp = hex_to_bytes("4a1aa3a295482fa9a340b05f2c4779e701b53cd0f158c1bbe559730ae5ff6d17");

        let wb = stamp_workblock(&infohash, 20);
        assert_eq!(wb.len(), 5120);
        assert_eq!(&wb[..32], &expected_wb_prefix[..]);

        let value = stamp_value(&wb, &stamp);
        assert_eq!(value, 8);
        assert!(stamp_valid(&stamp, 8, &wb));
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect()
    }
}
