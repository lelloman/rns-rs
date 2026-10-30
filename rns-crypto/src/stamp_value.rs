//! Fractional stamp values (upstream `RNS.Stamps.stamp_value` since rgit
//! `78fb90ea`).
//!
//! A stamp's value is the base-2 logarithm of how unlikely its stamp product
//! `SHA-256(workblock || stamp)` is, quantized down onto a 1/256 grid. The
//! integer part is the leading zero bit count (the legacy value) and the
//! fraction is read off the next 33 bits of the product through the
//! authoritative mantissa table [`TAB`]. Values are carried as exact
//! fixed-point [`StampValue`]s; conversion to `f64` only happens where a value
//! leaves the process, as upstream reports them as floats.

use core::fmt;

use crate::sha256;

/// Significand bits of the normalized mantissa (upstream `MANTISSA_BITS`).
pub const MANTISSA_BITS: u32 = 33;

/// Fractional bits of the fixed-point representation (`COST_FP_BITS`).
pub const COST_FP_BITS: u32 = 8;

/// Fixed-point scale: a value of 1.0 is `COST_FP` (`COST_FP`).
pub const COST_FP: u32 = 1 << COST_FP_BITS;

/// SHA-256 of the comma-joined decimal [`TAB`] entries (`TAB_DIGEST`).
pub const TAB_DIGEST: &str = "55ba3ce1df224895b0dfdc102eb4359fc2f5a7efefee68df0cc90c8a8ac24f48";

/// SHA-256 pinning the table digest and parameters (`PRM_DIGEST`).
pub const PRM_DIGEST: &str = "21436fc98e76a12cad7c52ebeb6ab76c2ae93b4cd768949df7fdd4e2f98c378d";

/// Fixed-point stamp target mantissa table,
/// `TAB[f] = floor(2^33 * 2^(f/256))` for `f = 0..=255`. Copied verbatim from
/// upstream, which declares the values authoritative: they must not be
/// recomputed. The tests pin them to [`TAB_DIGEST`].
pub const TAB: [u64; COST_FP as usize] = [
    0x200000000,
    0x201635f4b,
    0x202c7b53f,
    0x2042d0287,
    0x2059347ce,
    0x206fa85c2,
    0x20862bd0d,
    0x209cbee5e,
    0x20b361a62,
    0x20ca141c7,
    0x20e0d653b,
    0x20f7a856e,
    0x210e8a30e,
    0x21257becc,
    0x213c7d958,
    0x21538f363,
    0x216ab0d9f,
    0x2181e28bc,
    0x21992456e,
    0x21b076467,
    0x21c7d865a,
    0x21df4abfb,
    0x21f6cd5ff,
    0x220e6051a,
    0x222603a02,
    0x223db756b,
    0x22557b80d,
    0x226d5029e,
    0x2285355d5,
    0x229d2b269,
    0x22b531914,
    0x22cd48a8e,
    0x22e57078f,
    0x22fda90d2,
    0x2315f2711,
    0x232e4cb06,
    0x2346b7d6d,
    0x235f33f02,
    0x2377c1080,
    0x23905f2a5,
    0x23a90e62d,
    0x23c1cebd6,
    0x23daa045f,
    0x23f383087,
    0x240c7710c,
    0x24257c6af,
    0x243e9322f,
    0x2457bb44f,
    0x2470f4dce,
    0x248a3ff70,
    0x24a39c9f6,
    0x24bd0ae23,
    0x24d68acbc,
    0x24f01c683,
    0x2509bfc3e,
    0x252374eb2,
    0x253d3bea3,
    0x255714cda,
    0x2570ffa1b,
    0x258afc72e,
    0x25a50b4dc,
    0x25bf2c3ec,
    0x25d95f527,
    0x25f3a4957,
    0x260dfc146,
    0x262865dbd,
    0x2642e1f89,
    0x265d70775,
    0x26781164c,
    0x2692c4cdc,
    0x26ad8abf2,
    0x26c86345b,
    0x26e34e6e7,
    0x26fe4c463,
    0x27195cda0,
    0x27348036e,
    0x274fb669c,
    0x276aff7fd,
    0x27865b862,
    0x27a1ca89d,
    0x27bd4c982,
    0x27d8e1be3,
    0x27f48a095,
    0x28104586c,
    0x282c1443e,
    0x2847f64e1,
    0x2863ebb2a,
    0x287ff47f0,
    0x289c10c0c,
    0x28b840854,
    0x28d483da3,
    0x28f0dacd1,
    0x290d456b8,
    0x2929c3c32,
    0x294655e1a,
    0x2962fbd4d,
    0x297fb5aa6,
    0x299c83702,
    0x29b96533f,
    0x29d65b03b,
    0x29f364ed3,
    0x2a1082fe8,
    0x2a2db5459,
    0x2a4afbd07,
    0x2a6856ad3,
    0x2a85c5e9e,
    0x2aa34994b,
    0x2ac0e1bbd,
    0x2ade8e6d6,
    0x2afc4fb7c,
    0x2b1a25a92,
    0x2b38104ff,
    0x2b560fba9,
    0x2b7423f75,
    0x2b924d14b,
    0x2bb08b213,
    0x2bcede2b5,
    0x2bed4641b,
    0x2c0bc372e,
    0x2c2a55cd9,
    0x2c48fd607,
    0x2c67ba3a3,
    0x2c868c699,
    0x2ca573fd7,
    0x2cc47104a,
    0x2ce3838e1,
    0x2d02aba89,
    0x2d21e9633,
    0x2d413cccf,
    0x2d60a5f4e,
    0x2d8024ea1,
    0x2d9fb9bba,
    0x2dbf6478c,
    0x2ddf2530b,
    0x2dfefbf2a,
    0x2e1ee8cde,
    0x2e3eebd1d,
    0x2e5f050dd,
    0x2e7f34914,
    0x2e9f7a6ba,
    0x2ebfd6ac8,
    0x2ee049635,
    0x2f00d29fb,
    0x2f2172715,
    0x2f4228e7d,
    0x2f62f612e,
    0x2f83da026,
    0x2fa4d4c5f,
    0x2fc5e66d9,
    0x2fe70f092,
    0x30084ea87,
    0x3029a55ba,
    0x304b13329,
    0x306c983d7,
    0x308e348c4,
    0x30afe82f3,
    0x30d1b3368,
    0x30f395b26,
    0x31158fb31,
    0x3137a148f,
    0x3159ca845,
    0x317c0b75a,
    0x319e642d6,
    0x31c0d4bc1,
    0x31e35d322,
    0x3205fda05,
    0x3228b6172,
    0x324b86a75,
    0x326e6f619,
    0x32917056b,
    0x32b489979,
    0x32d7bb34e,
    0x32fb053fb,
    0x331e67c8f,
    0x3341e2e19,
    0x3365769aa,
    0x338923054,
    0x33ace8329,
    0x33d0c633c,
    0x33f4bd1a0,
    0x3418ccf6b,
    0x343cf5db1,
    0x346137d89,
    0x348593008,
    0x34aa07647,
    0x34ce9515e,
    0x34f33c266,
    0x3517fca78,
    0x353cd6aaf,
    0x3561ca426,
    0x3586d77fa,
    0x35abfe747,
    0x35d13f32b,
    0x35f699cc4,
    0x361c0e531,
    0x36419cd93,
    0x366745709,
    0x368d082b6,
    0x36b2e51bc,
    0x36d8dc53e,
    0x36feede5f,
    0x372519e44,
    0x374b60614,
    0x3771c16f3,
    0x37983d209,
    0x37bed387e,
    0x37e584b7a,
    0x380c50c28,
    0x383337bb0,
    0x385a39b3f,
    0x388156bff,
    0x38a88ef1f,
    0x38cfe25ca,
    0x38f751131,
    0x391edb280,
    0x394680aea,
    0x396e41b9d,
    0x39961e5cd,
    0x39be16aab,
    0x39e62ab6b,
    0x3a0e5a940,
    0x3a36a6561,
    0x3a5f0e101,
    0x3a8791d59,
    0x3ab031b9f,
    0x3ad8edd0c,
    0x3b01c62d9,
    0x3b2abae3f,
    0x3b53cc07b,
    0x3b7cf9ac7,
    0x3ba643e60,
    0x3bcfaac83,
    0x3bf92e66f,
    0x3c22ced63,
    0x3c4c8c29e,
    0x3c7666762,
    0x3ca05dcf1,
    0x3cca7248c,
    0x3cf4a3f78,
    0x3d1ef2ef9,
    0x3d495f454,
    0x3d73e90cf,
    0x3d9e905b1,
    0x3dc955443,
    0x3df437dcc,
    0x3e1f38396,
    0x3e4a566ed,
    0x3e759291b,
    0x3ea0ecb6d,
    0x3ecc64f31,
    0x3ef7fb5b3,
    0x3f23b0044,
    0x3f4f83033,
    0x3f7b746d2,
    0x3fa784571,
    0x3fd3b2d65,
];

/// Largest representable value: a stamp product of zero has value 256.
const MAX_FP: u32 = 256 * COST_FP;

/// A stamp value in fixed point, in 1/256 steps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StampValue(u32);

impl StampValue {
    pub const ZERO: StampValue = StampValue(0);

    /// Value from its fixed-point representation, clamped to the maximum.
    pub const fn from_fp(fp: u32) -> Self {
        StampValue(if fp > MAX_FP { MAX_FP } else { fp })
    }

    /// Value of a whole number of bits, such as a legacy integer value.
    pub const fn from_whole(value: u32) -> Self {
        StampValue::from_fp(value.saturating_mul(COST_FP))
    }

    /// Value read from a float, floored onto the grid. Values written by this
    /// implementation or upstream lie on the grid exactly; non-finite or
    /// negative input reads as zero.
    pub fn from_f64(value: f64) -> Self {
        if !value.is_finite() || value <= 0.0 {
            return StampValue::ZERO;
        }
        let fp = value * COST_FP as f64;
        if fp >= MAX_FP as f64 {
            StampValue(MAX_FP)
        } else {
            StampValue(fp as u32)
        }
    }

    /// Fixed-point representation.
    pub const fn fp(self) -> u32 {
        self.0
    }

    /// Whole bits of value: the legacy leading-zero value (`cost_int`).
    pub const fn whole(self) -> u32 {
        self.0 >> COST_FP_BITS
    }

    /// The value as upstream reports it (`cost_from_fp`).
    pub fn as_f64(self) -> f64 {
        f64::from(self.0) / f64::from(COST_FP)
    }

    /// Whether the value reaches `cost`, as upstream compares a reported
    /// value with a required cost (`value < get_link_cost()`). Validity of
    /// a stamp itself is decided against the target, see
    /// [`StampCost::admits`].
    pub const fn meets(self, cost: StampCost) -> bool {
        self.0 >= cost.0
    }
}

impl fmt::Display for StampValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.as_f64(), f)
    }
}

/// Global hard cap on stamp costs (`Transport.STAMP_COST_CAP`).
pub const STAMP_COST_CAP: u32 = 100;

const MAX_COST_FP: u32 = STAMP_COST_CAP * COST_FP;

const _: () = assert!((MAX_FP - MAX_COST_FP) >> COST_FP_BITS >= MANTISSA_BITS);

/// A stamp cost in fixed point, in 1/256 steps, clamped to
/// [`STAMP_COST_CAP`]. Since rgit `a8cc6cb2` the default costs are
/// fractional; a cost becomes a target through [`TAB`] exactly as a value is
/// read through it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StampCost(u32);

impl StampCost {
    pub const ZERO: StampCost = StampCost(0);

    /// Cost from its fixed-point representation, clamped to the cap.
    pub const fn from_fp(fp: u32) -> Self {
        StampCost(if fp > MAX_COST_FP { MAX_COST_FP } else { fp })
    }

    /// Cost from its fixed-point representation, or `None` above the cap,
    /// for costs read off the wire.
    pub const fn from_fp_checked(fp: u32) -> Option<Self> {
        if fp > MAX_COST_FP {
            None
        } else {
            Some(StampCost(fp))
        }
    }

    /// Cost of a whole number of bits, such as a configured integer cost.
    pub const fn from_whole(cost: u32) -> Self {
        StampCost::from_fp(cost.saturating_mul(COST_FP))
    }

    /// Cost read from a float, rounded to the nearest grid point and clamped
    /// (`cost_to_fp`). Non-finite or negative input reads as zero.
    pub fn from_f64(cost: f64) -> Self {
        if !cost.is_finite() || cost <= 0.0 {
            return StampCost::ZERO;
        }
        // floor(cost * COST_FP + 0.5); truncation floors positive input.
        let fp = cost * COST_FP as f64 + 0.5;
        if fp >= MAX_COST_FP as f64 {
            StampCost(MAX_COST_FP)
        } else {
            StampCost(fp as u32)
        }
    }

    /// Fixed-point representation.
    pub const fn fp(self) -> u32 {
        self.0
    }

    /// Whole bits of the cost (`cost_int`).
    pub const fn whole(self) -> u32 {
        self.0 >> COST_FP_BITS
    }

    /// The cost as upstream reports it (`cost_from_fp`).
    pub fn as_f64(self) -> f64 {
        f64::from(self.0) / f64::from(COST_FP)
    }

    /// The stamp target for this cost (`target_from_fp`) as a big-endian
    /// 256-bit number, or `None` for a zero cost, whose target is `2^256`
    /// and admits every product.
    pub fn target(self) -> Option<[u8; 32]> {
        if self.0 == 0 {
            return None;
        }
        // i, f = divmod(256*COST_FP - fp, COST_FP);
        // target = (TAB[f] << i) >> MANTISSA_BITS. With fp >= 1, i <= 255
        // and TAB[f] < 2^34, so the target fits in 256 bits.
        let rest = MAX_FP - self.0;
        let exponent = rest >> COST_FP_BITS;
        let mantissa = TAB[(rest & (COST_FP - 1)) as usize];
        // The cap keeps the exponent at 156 or more, so the shift is left.
        let shift = exponent - MANTISSA_BITS;
        let (limb, offset) = ((shift / 64) as usize, shift % 64);
        let mut limbs = [0u64; 4];
        limbs[limb] = mantissa << offset;
        if offset > 0 && limb + 1 < limbs.len() {
            limbs[limb + 1] = mantissa >> (64 - offset);
        }
        let mut target = [0u8; 32];
        for (i, limb) in limbs.iter().rev().enumerate() {
            target[i * 8..i * 8 + 8].copy_from_slice(&limb.to_be_bytes());
        }
        Some(target)
    }

    /// Whether a stamp product meets this cost: the product, read as a
    /// big-endian integer, is at most the target (`stamp_valid`).
    pub fn admits(self, product: &[u8; 32]) -> bool {
        match self.target() {
            None => true,
            Some(target) => product[..] <= target[..],
        }
    }
}

impl fmt::Display for StampCost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.as_f64(), f)
    }
}

/// Value of a 256-bit stamp product.
pub fn value_of_product(product: &[u8; 32]) -> StampValue {
    let lz = leading_zeros(product);
    if lz == 256 {
        return StampValue(MAX_FP);
    }
    // The normalized mantissa is the leading one followed by MANTISSA_BITS
    // bits. Bits past the end of the product read as zero, which matches
    // upstream left-shifting short products.
    let start = (lz / 8) as usize;
    let mut window = [0u8; 16];
    let available = (32 - start).min(16);
    window[..available].copy_from_slice(&product[start..start + available]);
    let aligned = u128::from_be_bytes(window) << (lz % 8);
    let mantissa = (aligned >> (128 - (MANTISSA_BITS + 1))) as u64;
    // Right-bisecting TAB counts the grid points at or below the mantissa,
    // which floors the value onto the grid without ever over-valuing it.
    let climb = TAB.partition_point(|&entry| entry <= mantissa) as u32;
    StampValue((lz + 1) * COST_FP - climb)
}

/// Value of `stamp` over `workblock` (`stamp_value`).
pub fn stamp_value(workblock: &[u8], stamp: &[u8]) -> StampValue {
    let mut input = alloc::vec::Vec::with_capacity(workblock.len() + stamp.len());
    input.extend_from_slice(workblock);
    input.extend_from_slice(stamp);
    value_of_product(&sha256::sha256(&input))
}

/// Leading zero bits of a 256-bit product (`stamp_value_legacy`).
pub fn leading_zeros(product: &[u8; 32]) -> u32 {
    let mut count = 0u32;
    for &byte in product {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec::Vec;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn table_matches_upstream_digests() {
        assert_eq!(TAB[0], 1 << MANTISSA_BITS);
        assert!(TAB.windows(2).all(|w| w[1] > w[0]));
        let joined: Vec<String> = TAB.iter().map(|v| format!("{v}")).collect();
        let tab_digest = hex(&sha256::sha256(joined.join(",").as_bytes()));
        assert_eq!(tab_digest, TAB_DIGEST);
        let params = format!(
            "master|{TAB_DIGEST}|{MANTISSA_BITS}|{}|{COST_FP_BITS}|{COST_FP}|",
            TAB.len()
        );
        assert_eq!(hex(&sha256::sha256(params.as_bytes())), PRM_DIGEST);
    }

    /// `(stamp, value * 256)` pairs computed by upstream rgit `78fb90ea`
    /// `RNS.Stamps.stamp_value` over the workblock below, spanning leading
    /// zero counts 0 to 16.
    const UPSTREAM_WORKBLOCK: &[u8] = b"rns-rs fractional stamp vectors";
    const UPSTREAM_VECTORS: &[(&str, u32)] = &[
        ("af5570f5a1810b7af78caf4bc70a", 236),
        ("cd2662154e6d76b2b2b92e70c0ca", 668),
        ("cd04a4754498e06db5a13c5f371f", 88),
        ("d5688a52d55a02ec4aea5ec1eadf", 112),
        ("8005f02d43fa06e7d0585fb64c96", 276),
        ("5dee4dd60ff8d0ba9900fe91e90e", 188),
        ("14ac577cdb2ef6d986078b4054cc", 886),
        ("a3eb8db89fc5123ccfd49585059f", 160),
        ("4c0e071832d527694adea57b50dd", 349),
        ("5924513516a5993435ec4a240610", 111),
        ("7a42e3892368f826928202014a6c", 620),
        ("561f627b4213258dc8863498bb9b", 742),
        ("42f28a46039f894d3a0179d09085", 577),
        ("1d7968ffc995d6a495071668f4a9", 730),
        ("539b4c4c41a13f1f0452f5a35a67", 393),
        ("ea676268c71eb961cae5f1a68dc8", 597),
        ("e9a5f5201eb3c3c856e0a224527a", 511),
        ("6a339ff6defc6e73cf17dea3ea81", 392),
        ("0db5549dd341d8a11a21a653574f", 438),
        ("dd677f19feae7d8e78334c0096d7", 1125),
        ("76a872016c45a5edd4d933a2e45c", 1613),
        ("23768e05b10a7f0335d3e35a9d30", 1477),
        ("dc9684c3cd2e0715b1f151fda6d7", 1975),
        ("d279f9164d2bf5ad26307e1a1f86", 2268),
        ("d6050af84e83c2183c1a3005633f", 2693),
        ("e6570450c0e7e92eb09bb2fb732c", 2426),
        ("3e5bdd07714a45a792e880eeef89", 3027),
        ("1d726593f982f447e8a65d82f51b", 4271),
        ("cd3ff1775c55c55f6c5494b8eaa1", 3266),
        ("f15bb2b358c7de7fbbd7a5280908", 3426),
    ];

    #[test]
    fn values_match_upstream_vectors() {
        for &(stamp, fp) in UPSTREAM_VECTORS {
            let stamp = unhex(stamp);
            assert_eq!(stamp_value(UPSTREAM_WORKBLOCK, &stamp).fp(), fp);
        }
    }

    #[test]
    fn value_stays_within_its_legacy_integer_step() {
        for i in 0u32..4096 {
            let product = sha256::sha256(&i.to_be_bytes());
            let legacy = leading_zeros(&product);
            let value = value_of_product(&product);
            assert_eq!(value.whole(), legacy);
            assert!(value.fp() >= legacy * COST_FP);
            assert!(value.fp() < (legacy + 1) * COST_FP);
            assert!(value.meets(StampCost::from_whole(legacy)));
            assert!(!value.meets(StampCost::from_whole(legacy + 1)));
        }
    }

    #[test]
    fn value_is_monotone_in_the_product() {
        // Smaller products are less likely and must never be worth less.
        let mut product = [0u8; 32];
        product[3] = 0x01;
        let mut last = value_of_product(&product);
        for top in (0x01u8..=0xff).step_by(3) {
            product[4] = top;
            let value = value_of_product(&product);
            assert!(value <= last);
            last = value;
        }
    }

    #[test]
    fn extreme_products() {
        assert_eq!(value_of_product(&[0u8; 32]).as_f64(), 256.0);
        assert_eq!(value_of_product(&[0xff; 32]).fp(), 0);
        let mut one = [0u8; 32];
        one[31] = 1;
        // Shorter than the mantissa window: bits past the end read as zero,
        // so the mantissa is exactly TAB[0]. An exact grid match floors one
        // step below the ceiling, as in upstream.
        assert_eq!(value_of_product(&one).fp(), 256 * COST_FP - 1);
    }

    /// `(cost, cost_to_fp(cost), target_from_fp(fp))` from upstream rgit
    /// `a8cc6cb2`, including its fractional default costs.
    const UPSTREAM_TARGETS: &[(f64, u32, &str)] = &[
        (
            23.5,
            6016,
            "0000016a09e66780000000000000000000000000000000000000000000000000",
        ),
        (
            25.0,
            6400,
            "0000008000000000000000000000000000000000000000000000000000000000",
        ),
        (
            19.8,
            5069,
            "0000125e85711800000000000000000000000000000000000000000000000000",
        ),
        (
            19.2,
            4915,
            "00001bdf69c3f000000000000000000000000000000000000000000000000000",
        ),
        (
            0.01,
            3,
            "fdedd1b480000000000000000000000000000000000000000000000000000000",
        ),
        (
            1.0,
            256,
            "8000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            8.0,
            2048,
            "0100000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            99.99,
            25597,
            "0000000000000000000000001021681438000000000000000000000000000000",
        ),
        (
            100.0,
            25600,
            "0000000000000000000000001000000000000000000000000000000000000000",
        ),
    ];

    /// `(fp, target_from_fp(fp))` from upstream, around step boundaries.
    const UPSTREAM_FP_TARGETS: &[(u32, &str)] = &[
        (
            1,
            "ff4ecb5940000000000000000000000000000000000000000000000000000000",
        ),
        (
            255,
            "8058d7d2c0000000000000000000000000000000000000000000000000000000",
        ),
        (
            257,
            "7fa765aca0000000000000000000000000000000000000000000000000000000",
        ),
        (
            8447,
            "000000008058d7d2c00000000000000000000000000000000000000000000000",
        ),
        (
            8448,
            "0000000080000000000000000000000000000000000000000000000000000000",
        ),
        (
            8455,
            "000000007d98c9e6200000000000000000000000000000000000000000000000",
        ),
    ];

    #[test]
    fn costs_and_targets_match_upstream() {
        for &(cost, fp, target) in UPSTREAM_TARGETS {
            let cost = StampCost::from_f64(cost);
            assert_eq!(cost.fp(), fp);
            assert_eq!(hex(&cost.target().unwrap()), target);
        }
        for &(fp, target) in UPSTREAM_FP_TARGETS {
            assert_eq!(hex(&StampCost::from_fp(fp).target().unwrap()), target);
        }
        assert_eq!(StampCost::ZERO.target(), None);
        assert!(StampCost::ZERO.admits(&[0xff; 32]));
        assert_eq!(
            StampCost::from_f64(1000.0),
            StampCost::from_whole(STAMP_COST_CAP)
        );
        assert_eq!(StampCost::from_f64(-1.0), StampCost::ZERO);
        assert_eq!(StampCost::from_f64(f64::NAN), StampCost::ZERO);
        // Rounded to nearest, not floored like a value.
        assert_eq!(StampCost::from_f64(19.8).fp(), 5069);
        assert_eq!(StampValue::from_f64(19.8).fp(), 5068);
    }

    #[test]
    fn whole_cost_targets_are_leading_zero_counts() {
        for i in 0u32..4096 {
            let product = sha256::sha256(&i.to_be_bytes());
            let lz = leading_zeros(&product);
            for cost in [0, 1, lz.saturating_sub(1), lz, lz + 1, 8, 100] {
                let cost = StampCost::from_whole(cost);
                assert_eq!(cost.admits(&product), lz >= cost.whole(), "{i} {cost}");
            }
        }
    }

    #[test]
    fn target_agrees_with_the_value_off_the_boundary() {
        // A product meets a cost exactly when its value does, except for a
        // product equal to the target itself, which the target admits.
        for i in 0u32..4096 {
            let product = sha256::sha256(&i.to_le_bytes());
            let value = value_of_product(&product);
            for fp in [1, 37, 255, 256, 300, value.fp(), value.fp() + 1, 6016] {
                let cost = StampCost::from_fp(fp);
                assert_eq!(cost.admits(&product), value.meets(cost), "{i} {fp}");
            }
        }
        let cost = StampCost::from_fp(6016);
        let target = cost.target().unwrap();
        assert!(cost.admits(&target));
        assert!(!value_of_product(&target).meets(cost));
    }

    #[test]
    fn float_conversions_round_trip_on_the_grid() {
        for fp in [0, 1, 128, 255, 256, 23 * 256 + 187, MAX_FP] {
            let value = StampValue::from_fp(fp);
            assert_eq!(StampValue::from_f64(value.as_f64()), value);
        }
        assert_eq!(StampValue::from_f64(8.5).fp(), 8 * 256 + 128);
        assert_eq!(StampValue::from_f64(-1.0), StampValue::ZERO);
        assert_eq!(StampValue::from_f64(f64::NAN), StampValue::ZERO);
        assert_eq!(StampValue::from_f64(1e9).fp(), MAX_FP);
        assert_eq!(StampValue::from_whole(24).as_f64(), 24.0);
        assert_eq!(format!("{}", StampValue::from_fp(8 * 256 + 128)), "8.5");
        assert_eq!(format!("{}", StampValue::from_whole(8)), "8");
    }
}
