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

/// Leading zero bits of a 256-bit stamp product (the legacy integer value),
/// fractional stamp values and their fixed-point type. See
/// [`rns_crypto::stamp_value`].
pub use rns_crypto::stamp_value::{leading_zeros, stamp_value, StampCost, StampValue};

/// Check if a stamp meets the target cost.
///
/// Valid when `SHA256(workblock + stamp)`, read as a big-endian integer, is
/// at most `target_from_fp(cost_to_fp(target_cost))`. For a whole cost the
/// target is `2^(256 - cost)`, the legacy leading-zero check.
pub fn stamp_valid(stamp: &[u8], target_cost: StampCost, workblock: &[u8]) -> bool {
    let mut material = Vec::with_capacity(workblock.len() + stamp.len());
    material.extend_from_slice(workblock);
    material.extend_from_slice(stamp);
    target_cost.admits(&sha256(&material))
}

/// A float cost clamped as upstream clamps configured and API costs,
/// `max(0, min(cost, cap))`, on the 1/256 grid every use of the cost reads
/// it through. NaN reads as 0, as Python's `max(0, min(nan, cap))` does, and
/// infinity as the cap.
pub fn clamp_cost(cost: f64, cap: u8) -> StampCost {
    if cost.is_nan() {
        return StampCost::ZERO;
    }
    StampCost::from_f64(cost.min(f64::from(cap)))
}

/// Clamp a configured per-destination link request cost.
///
/// Mirrors `Destination.set_link_cost` since upstream 796ef2d4:
/// `max(0, min(float(cost), Transport.LINK_COST_CAP))`.
pub fn clamp_link_cost(cost: f64) -> StampCost {
    clamp_cost(cost, crate::constants::LINK_COST_CAP)
}

/// The link request cost a destination announces and requires.
///
/// Mirrors `Destination.get_link_cost`: the configured cost, or `default`
/// (`Transport.LR_COST`, settable through `[stamps] lr_cost`) when none was
/// set. Since upstream 796ef2d4 the fraction is kept and announced.
pub fn announced_link_cost(configured: Option<StampCost>, default: StampCost) -> StampCost {
    configured.unwrap_or(default)
}

/// The two trailing bytes of an announce extension carrying `cost`
/// (upstream `bytes([cost_bytes[1], cost_bytes[0]])`): the 1/256 fraction,
/// then the whole part as the anchor byte. Costs are capped at
/// `STAMP_COST_CAP`, so the anchor's high bit stays clear.
pub fn link_cost_ext_bytes(cost: StampCost) -> [u8; 2] {
    let fp = cost.fp();
    [(fp & 0xFF) as u8, (fp >> 8) as u8]
}

/// Read the link request cost from the last two bytes of an announce
/// extension (`Identity.validate_announce`). `None` when the anchor's high
/// bit marks a newer extension format, or the cost exceeds `STAMP_COST_CAP`;
/// either way the extension must not be interpreted.
pub fn link_cost_from_ext_bytes(fraction: u8, anchor: u8) -> Option<StampCost> {
    if anchor & 0x80 != 0 {
        return None;
    }
    StampCost::from_fp_checked((u32::from(anchor) << 8) | u32::from(fraction))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_cost_setter_clamps_like_upstream() {
        let cap = StampCost::from_whole(u32::from(crate::constants::LINK_COST_CAP));
        assert_eq!(clamp_link_cost(-5.0), StampCost::ZERO);
        assert_eq!(clamp_link_cost(0.0), StampCost::ZERO);
        assert_eq!(clamp_link_cost(8.0), StampCost::from_whole(8));
        // Examples/Link.py: 14.2 is kept fractional, rounded to the grid.
        assert_eq!(clamp_link_cost(14.2), StampCost::from_fp(3635));
        assert_eq!(clamp_link_cost(40.0), cap);
        assert_eq!(clamp_link_cost(40.5), cap);
        assert_eq!(clamp_link_cost(f64::INFINITY), cap);
        assert_eq!(clamp_link_cost(f64::NEG_INFINITY), StampCost::ZERO);
        assert_eq!(clamp_link_cost(f64::NAN), StampCost::ZERO);
    }

    #[test]
    fn announced_link_cost_defaults_to_lr_cost() {
        let lr_cost = crate::constants::LINK_REQUEST_STAMP_COST;
        assert_eq!(announced_link_cost(None, lr_cost), lr_cost);
        let nine = StampCost::from_whole(9);
        assert_eq!(announced_link_cost(None, nine), nine);
        assert_eq!(
            announced_link_cost(Some(StampCost::ZERO), lr_cost),
            StampCost::ZERO
        );
        let configured = StampCost::from_f64(17.5);
        assert_eq!(announced_link_cost(Some(configured), nine), configured);
    }

    #[test]
    fn link_cost_ext_bytes_round_trip_like_upstream() {
        // bytes([cost_bytes[1], cost_bytes[0]]) for cost_to_bytes(12.5) and
        // cost_to_bytes(14.2) in upstream 796ef2d4.
        assert_eq!(link_cost_ext_bytes(StampCost::from_f64(12.5)), [0x80, 12]);
        assert_eq!(link_cost_ext_bytes(StampCost::from_f64(14.2)), [0x33, 14]);
        assert_eq!(link_cost_ext_bytes(StampCost::from_whole(100)), [0, 100]);
        for fp in [0, 1, 255, 256, 3200, 3635, 25_599, 25_600] {
            let cost = StampCost::from_fp(fp);
            let [fraction, anchor] = link_cost_ext_bytes(cost);
            assert_eq!(link_cost_from_ext_bytes(fraction, anchor), Some(cost));
        }
        // Above the cap or with the extension bit set: not interpreted.
        assert_eq!(link_cost_from_ext_bytes(1, 100), None);
        assert_eq!(link_cost_from_ext_bytes(0, 101), None);
        assert_eq!(link_cost_from_ext_bytes(0, 0x80 | 12), None);
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
        assert_eq!(value.whole(), 8);
        assert!(stamp_valid(&stamp, StampCost::from_whole(8), &wb));
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
        assert_eq!(stamp_value(&workblock, &stamp).whole(), 8);
        assert!(stamp_valid(&stamp, StampCost::from_whole(8), &workblock));
        assert!(!stamp_valid(&stamp, StampCost::from_whole(9), &workblock));
        // The former behaviour hashed the stamp alone, which does not reach
        // the value Python computed.
        assert_ne!(stamp_value(&[], &stamp).whole(), 8);
    }
}
