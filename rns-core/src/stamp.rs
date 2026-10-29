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

    // Upstream `stamp_workblock` returns the material itself when no
    // expansion is requested; destination and path request stamps use this
    // unexpanded form. An empty block here would hash the stamp alone and
    // reject every stamp a Python node emits.
    if expand_rounds == 0 {
        return material.to_vec();
    }

    let mut workblock = Vec::with_capacity(expand_rounds as usize * 256);
    for n in 0..expand_rounds {
        let packed_n = msgpack::pack(&Value::UInt(n as u64));
        let mut salt_input = Vec::with_capacity(material.len() + packed_n.len());
        salt_input.extend_from_slice(material);
        salt_input.extend_from_slice(&packed_n);
        let salt = sha256(&salt_input);

        let Ok(expanded) = hkdf(256, material, Some(&salt), None) else {
            break;
        };
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

/// Clamp a configured per-destination link request cost.
///
/// Mirrors `Destination.set_link_cost`:
/// `max(0, min(int(cost), Transport.LINK_COST_CAP))`.
pub fn clamp_link_cost(cost: i64) -> u8 {
    cost.clamp(0, i64::from(crate::constants::LINK_COST_CAP)) as u8
}

/// The link request cost a destination announces and requires.
///
/// Mirrors `Destination.get_link_cost`: the configured cost, or `default`
/// (`Transport.LR_COST`, settable through `[stamps] lr_cost`) when none was
/// set, clamped to `STAMP_COST_CAP`.
pub fn announced_link_cost(configured: Option<u8>, default: u8) -> u8 {
    configured
        .unwrap_or(default)
        .min(crate::constants::STAMP_COST_CAP)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_cost_setter_clamps_like_upstream() {
        assert_eq!(clamp_link_cost(-5), 0);
        assert_eq!(clamp_link_cost(0), 0);
        assert_eq!(clamp_link_cost(8), 8);
        assert_eq!(clamp_link_cost(40), 40);
        assert_eq!(clamp_link_cost(41), crate::constants::LINK_COST_CAP);
        assert_eq!(clamp_link_cost(i64::MAX), crate::constants::LINK_COST_CAP);
    }

    #[test]
    fn announced_link_cost_defaults_to_lr_cost() {
        let lr_cost = crate::constants::LINK_REQUEST_STAMP_COST;
        assert_eq!(announced_link_cost(None, lr_cost), lr_cost);
        assert_eq!(announced_link_cost(None, 9), 9);
        assert_eq!(announced_link_cost(Some(0), lr_cost), 0);
        assert_eq!(announced_link_cost(Some(17), 9), 17);
        assert_eq!(
            announced_link_cost(Some(u8::MAX), lr_cost),
            crate::constants::STAMP_COST_CAP
        );
    }

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
        let infohash =
            hex_to_bytes("916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9");
        let expected_wb_prefix =
            hex_to_bytes("9e36b853221f04ca1cf54447abce3e9eb47d01d55215414ee5b540eaa796caf2");
        let stamp =
            hex_to_bytes("4a1aa3a295482fa9a340b05f2c4779e701b53cd0f158c1bbe559730ae5ff6d17");

        let wb = stamp_workblock(&infohash, 20);
        assert_eq!(wb.len(), 5120);
        assert_eq!(&wb[..32], &expected_wb_prefix[..]);

        let value = stamp_value(&wb, &stamp);
        assert_eq!(value, 8);
        assert!(stamp_valid(&stamp, 8, &wb));
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn unexpanded_workblock_is_the_material() {
        let material = [0x5Au8; 90];
        assert_eq!(stamp_workblock(&material, 0), material.to_vec());
        assert!(stamp_workblock(&material, 1).len() > material.len());
    }

    /// Cross-implementation vector: a destination stamp generated by Python
    /// Reticulum 1.6.0 (`ca6451a0`) with `generate_stamp(material,
    /// stamp_cost=8, expand_rounds=0, size=14)`, where the material is
    /// `destination_hash || public_key || name_hash` for the destination
    /// `interop.python`. Python reported value 8.
    #[test]
    fn python_destination_stamp_vector_validates_with_unexpanded_workblock() {
        fn unhex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        let mut material = unhex("978690ff4cc658832dd1604250e74e76");
        material.extend(unhex(
            "2b2897e307ed442f21a403c7ffaa0a72913e7e0828671f5a887e10edef972960\
             65c9668d776b55538af5a4d60019c1e12af79cc164e7fdc3c99aa1cfcb6c26c1",
        ));
        material.extend(unhex("52b1626704f20f667110"));
        assert_eq!(material.len(), 16 + 64 + 10);
        let stamp = unhex("e42059a12ebbbc4dbb60c46fd539");
        let workblock = stamp_workblock(&material, 0);
        assert_eq!(stamp_value(&workblock, &stamp), 8);
        assert!(stamp_valid(&stamp, 8, &workblock));
        assert!(!stamp_valid(&stamp, 9, &workblock));
        // The former behaviour hashed the stamp alone, which does not reach
        // the value Python computed.
        assert_ne!(stamp_value(&[], &stamp), 8);
    }
}
