use alloc::vec::Vec;
use core::fmt;

use rns_crypto::identity::Identity;
use rns_crypto::sha256::Sha256;

use crate::constants;
use crate::hash;
use crate::stamp::{stamp_valid, stamp_value, stamp_workblock, StampCost, StampValue};

/// Errors building or validating an announce.
#[derive(Debug)]
pub enum AnnounceError {
    /// Announce data is shorter than its fixed fields.
    DataTooShort,
    /// Public key or signature is invalid.
    InvalidSignature,
    /// Destination hash does not match the announced name hash and identity.
    DestinationMismatch,
    /// Signing the announce failed.
    SigningError,
}

impl fmt::Display for AnnounceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnnounceError::DataTooShort => write!(f, "Announce data too short"),
            AnnounceError::InvalidSignature => write!(f, "Invalid announce signature"),
            AnnounceError::DestinationMismatch => write!(f, "Destination hash mismatch"),
            AnnounceError::SigningError => write!(f, "Could not sign announce"),
        }
    }
}

/// Parsed announce data.
///
/// Layout without ratchet:
/// ```text
/// [public_key:64][name_hash:10][random_hash:10][signature:64][app_data:*]
/// ```
///
/// Layout with ratchet (context_flag == FLAG_SET):
/// ```text
/// [public_key:64][name_hash:10][random_hash:10][ratchet:32][signature:64][app_data:*]
/// ```
#[derive(Debug, Clone)]
pub struct AnnounceData {
    /// Announcing identity's public key (X25519 then Ed25519).
    pub public_key: [u8; 64],
    /// Name hash of the destination.
    pub name_hash: [u8; 10],
    /// Random hash of the announce (random bytes and a timestamp in upstream's announces).
    pub random_hash: [u8; 10],
    /// Ratchet public key, when the context flag is set.
    pub ratchet: Option<[u8; 32]>,
    /// Ed25519 signature over the destination hash and the announce fields.
    pub signature: [u8; 64],
    /// Application data, if any.
    pub app_data: Option<Vec<u8>>,
}

/// Result of a successfully validated announce.
#[derive(Debug)]
pub struct ValidatedAnnounce {
    /// Truncated hash of the announcing identity.
    pub identity_hash: [u8; 16],
    /// Announcing identity's public key (X25519 then Ed25519).
    pub public_key: [u8; 64],
    /// Name hash of the destination.
    pub name_hash: [u8; 10],
    /// Random hash of the announce.
    pub random_hash: [u8; 10],
    /// Ratchet public key, if the announce carried one.
    pub ratchet: Option<[u8; 32]>,
    /// Application data, if any.
    pub app_data: Option<Vec<u8>>,
    /// Detached destination stamp parsed from the announce, if present.
    pub stamp: Option<[u8; constants::STAMP_LENGTH]>,
    /// Fractional value of the parsed stamp, including one below the
    /// required cost (upstream 0cc6f5ae), or zero when no stamp is present.
    pub stamp_value: StampValue,
    /// Link request stamp cost announced in the extension's last two bytes,
    /// if present.
    pub lr_cost: Option<StampCost>,
}

/// Outcome of checking an announce's optional stamp extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnounceStampStatus {
    /// No stamp extension was present.
    NotStamped,
    /// A stamp extension was present and met the required cost.
    Valid,
    /// A stamp extension was present but was below the required cost.
    Invalid,
}

impl ValidatedAnnounce {
    /// Parse and validate an announce stamp extension in-place.
    ///
    /// Mirrors upstream `Identity.validate_announce`: only a valid stamp is
    /// stripped from `app_data`. A present-but-invalid stamp stays in
    /// `app_data` and still records its value (upstream 0cc6f5ae), while
    /// enforcement decides whether the announce is accepted.
    pub fn apply_stamp(
        &mut self,
        destination_hash: &[u8; 16],
        required_value: StampCost,
    ) -> AnnounceStampStatus {
        if !constants::STAMPS_ENABLED {
            return AnnounceStampStatus::NotStamped;
        }
        let Some(app_data) = self.app_data.as_ref() else {
            return AnnounceStampStatus::NotStamped;
        };
        let Some((stripped, ext)) =
            app_data.split_last_chunk::<{ constants::EXT_PAYLOAD_LENGTH }>()
        else {
            return AnnounceStampStatus::NotStamped;
        };
        // [marker][header byte][stamp][link request cost: fraction, anchor]
        let [marker, _, stamp @ .., lr_cost_fraction, lr_cost_anchor] = ext;
        if *marker != constants::EXT_PAYLOAD_MARKER {
            return AnnounceStampStatus::NotStamped;
        }

        // The trailing anchor carries the whole part of the announced link
        // request cost and the byte before it the 1/256 fraction (796ef2d4).
        // A set anchor high bit marks a newer, longer extension format that
        // this version must not interpret.
        let Some(lr_cost) =
            crate::stamp::link_cost_from_ext_bytes(*lr_cost_fraction, *lr_cost_anchor)
        else {
            return AnnounceStampStatus::NotStamped;
        };

        let stamp: [u8; constants::STAMP_LENGTH] = *stamp;
        self.stamp = Some(stamp);

        let mut material = Vec::with_capacity(16 + 64 + 10);
        material.extend_from_slice(destination_hash);
        material.extend_from_slice(&self.public_key);
        material.extend_from_slice(&self.name_hash);
        let workblock = stamp_workblock(&material, 0);
        self.stamp_value = stamp_value(&workblock, &stamp);

        if stamp_valid(&stamp, required_value, &workblock) {
            self.app_data = if stripped.is_empty() {
                None
            } else {
                Some(stripped.to_vec())
            };
            self.lr_cost = Some(lr_cost);
            AnnounceStampStatus::Valid
        } else {
            AnnounceStampStatus::Invalid
        }
    }
}

impl AnnounceData {
    /// Pack announce fields into bytes, signing with the provided identity.
    ///
    /// Returns (announce_data_bytes, has_ratchet).
    pub fn pack(
        identity: &Identity,
        destination_hash: &[u8; 16],
        name_hash: &[u8; 10],
        random_hash: &[u8; 10],
        ratchet: Option<&[u8; 32]>,
        app_data: Option<&[u8]>,
    ) -> Result<(Vec<u8>, bool), AnnounceError> {
        let public_key = identity
            .get_public_key()
            .ok_or(AnnounceError::SigningError)?;

        // Build signed data: destination_hash + public_key + name_hash + random_hash + ratchet + app_data
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(destination_hash);
        signed_data.extend_from_slice(&public_key);
        signed_data.extend_from_slice(name_hash);
        signed_data.extend_from_slice(random_hash);

        let has_ratchet = ratchet.is_some();
        if let Some(r) = ratchet {
            signed_data.extend_from_slice(r);
        }
        if let Some(ad) = app_data {
            signed_data.extend_from_slice(ad);
        }

        let signature = identity
            .sign(&signed_data)
            .map_err(|_| AnnounceError::SigningError)?;

        // Build announce data: public_key + name_hash + random_hash + [ratchet] + signature + [app_data]
        let mut announce_data = Vec::new();
        announce_data.extend_from_slice(&public_key);
        announce_data.extend_from_slice(name_hash);
        announce_data.extend_from_slice(random_hash);
        if let Some(r) = ratchet {
            announce_data.extend_from_slice(r);
        }
        announce_data.extend_from_slice(&signature);
        if let Some(ad) = app_data {
            announce_data.extend_from_slice(ad);
        }

        Ok((announce_data, has_ratchet))
    }

    /// Parse announce bytes into structured data.
    ///
    /// `has_ratchet` corresponds to context_flag == FLAG_SET.
    pub fn unpack(data: &[u8], has_ratchet: bool) -> Result<Self, AnnounceError> {
        // [public_key:64][name_hash:10][random_hash:10][ratchet:32 if has_ratchet]
        // [signature:64][app_data:*]
        fn take<const N: usize>(rest: &mut &[u8]) -> Result<[u8; N], AnnounceError> {
            let (field, tail) = rest
                .split_first_chunk::<N>()
                .ok_or(AnnounceError::DataTooShort)?;
            *rest = tail;
            Ok(*field)
        }
        let mut rest = data;
        let public_key: [u8; constants::KEYSIZE / 8] = take(&mut rest)?;
        let name_hash: [u8; constants::NAME_HASH_LENGTH / 8] = take(&mut rest)?;
        let random_hash: [u8; 10] = take(&mut rest)?;
        let ratchet: Option<[u8; constants::RATCHETSIZE / 8]> = if has_ratchet {
            Some(take(&mut rest)?)
        } else {
            None
        };
        let signature: [u8; constants::SIGLENGTH / 8] = take(&mut rest)?;

        // From Python: app_data is present if len(data) > keysize + name_hash_len + 10 + sig_len [+ ratchetsize]
        let app_data = if rest.is_empty() {
            None
        } else {
            Some(rest.to_vec())
        };

        Ok(AnnounceData {
            public_key,
            name_hash,
            random_hash,
            ratchet,
            signature,
            app_data,
        })
    }

    /// Feed each part of the signed data, in order, to `f`:
    /// destination_hash + public_key + name_hash + random_hash + ratchet + app_data.
    ///
    /// Python builds signed_data with `app_data = b""` when there is no app data,
    /// so absent optional fields contribute nothing.
    fn for_each_signed_part(&self, destination_hash: &[u8; 16], mut f: impl FnMut(&[u8])) {
        f(destination_hash);
        f(&self.public_key);
        f(&self.name_hash);
        f(&self.random_hash);
        if let Some(ref ratchet) = self.ratchet {
            f(ratchet);
        }
        if let Some(ref ad) = self.app_data {
            f(ad);
        }
    }

    /// The bytes covered by the announce signature.
    fn signed_data(&self, destination_hash: &[u8; 16]) -> Vec<u8> {
        let mut signed_data = Vec::new();
        self.for_each_signed_part(destination_hash, |part| signed_data.extend_from_slice(part));
        signed_data
    }

    /// Key for the announce signature cache: SHA-256 over the signed data
    /// followed by the signature.
    ///
    /// Two announces share a key only when every signed field and the
    /// signature are identical, so a cached verification result applies to
    /// exactly the announce it was computed for.
    pub fn signature_cache_key(&self, destination_hash: &[u8; 16]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        self.for_each_signed_part(destination_hash, |part| hasher.update(part));
        hasher.update(&self.signature);
        hasher.digest()
    }

    /// Check that `destination_hash == truncated_hash(name_hash || identity_hash)`.
    fn check_destination_binding(
        &self,
        destination_hash: &[u8; 16],
        identity_hash: &[u8; 16],
    ) -> Result<(), AnnounceError> {
        let mut hash_material = [0u8; 26];
        hash_material[..10].copy_from_slice(&self.name_hash);
        hash_material[10..].copy_from_slice(identity_hash);

        let expected_hash = hash::truncated_hash(&hash_material);

        if &expected_hash != destination_hash {
            return Err(AnnounceError::DestinationMismatch);
        }
        Ok(())
    }

    fn to_validated(&self, identity_hash: [u8; 16]) -> ValidatedAnnounce {
        ValidatedAnnounce {
            identity_hash,
            public_key: self.public_key,
            name_hash: self.name_hash,
            random_hash: self.random_hash,
            ratchet: self.ratchet,
            app_data: self.app_data.clone(),
            stamp: None,
            stamp_value: StampValue::ZERO,
            lr_cost: None,
        }
    }

    /// Validate an announce: verify signature and check destination hash.
    ///
    /// Follows Python Identity.validate_announce():
    /// 1. Create Identity from public_key
    /// 2. Build signed_data = destination_hash + public_key + name_hash + random_hash + ratchet + app_data
    /// 3. Verify signature over signed_data
    /// 4. Compute identity_hash = truncated_hash(public_key)
    /// 5. expected_hash = truncated_hash(name_hash || identity_hash)
    /// 6. Verify expected_hash == destination_hash
    pub fn validate(
        &self,
        destination_hash: &[u8; 16],
    ) -> Result<ValidatedAnnounce, AnnounceError> {
        // Create identity from public key. Key bytes that do not decode to a
        // valid Ed25519 point cannot carry a valid signature, so the announce
        // is rejected the same way (Python returns False from validate_announce).
        let announced_identity = Identity::from_public_key(&self.public_key)
            .map_err(|_| AnnounceError::InvalidSignature)?;

        // Verify signature
        let signed_data = self.signed_data(destination_hash);
        if !announced_identity.verify(&self.signature, &signed_data) {
            return Err(AnnounceError::InvalidSignature);
        }

        // Verify destination hash
        let identity_hash = *announced_identity.hash();
        self.check_destination_binding(destination_hash, &identity_hash)?;

        Ok(self.to_validated(identity_hash))
    }

    /// Build a `ValidatedAnnounce` for an announce whose signature cache key
    /// (see [`Self::signature_cache_key`]) is already in the signature cache.
    ///
    /// The signature was verified for an identical announce earlier; the
    /// structural checks are repeated here: the identity hash is recomputed
    /// from `public_key` and the destination hash binding is checked. The
    /// public key decoded successfully when that earlier announce was
    /// verified, since the cache key covers the key bytes.
    pub fn to_validated_with_cached_signature(
        &self,
        destination_hash: &[u8; 16],
    ) -> Result<ValidatedAnnounce, AnnounceError> {
        let identity_hash = hash::truncated_hash(&self.public_key);
        self.check_destination_binding(destination_hash, &identity_hash)?;
        Ok(self.to_validated(identity_hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination;

    #[test]
    fn test_pack_unpack_roundtrip_no_ratchet() {
        let identity = Identity::from_private_key(&[0x42; 64]);
        let id_hash = *identity.hash();

        let nh = destination::name_hash("testapp", &["aspect"]);
        let dh = destination::destination_hash("testapp", &["aspect"], Some(&id_hash));
        let random = [0xAA; 10];

        let (data, has_ratchet) =
            AnnounceData::pack(&identity, &dh, &nh, &random, None, None).unwrap();
        assert!(!has_ratchet);

        let parsed = AnnounceData::unpack(&data, false).unwrap();
        assert_eq!(parsed.public_key, identity.get_public_key().unwrap());
        assert_eq!(parsed.name_hash, nh);
        assert_eq!(parsed.random_hash, random);
        assert!(parsed.ratchet.is_none());
        assert!(parsed.app_data.is_none());
    }

    #[test]
    fn test_pack_unpack_roundtrip_with_ratchet() {
        let identity = Identity::from_private_key(&[0x42; 64]);
        let id_hash = *identity.hash();

        let nh = destination::name_hash("testapp", &["aspect"]);
        let dh = destination::destination_hash("testapp", &["aspect"], Some(&id_hash));
        let random = [0xBB; 10];
        let ratchet = [0xCC; 32];

        let (data, has_ratchet) =
            AnnounceData::pack(&identity, &dh, &nh, &random, Some(&ratchet), None).unwrap();
        assert!(has_ratchet);

        let parsed = AnnounceData::unpack(&data, true).unwrap();
        assert_eq!(parsed.ratchet.unwrap(), ratchet);
    }

    #[test]
    fn test_pack_unpack_with_app_data() {
        let identity = Identity::from_private_key(&[0x42; 64]);
        let id_hash = *identity.hash();

        let nh = destination::name_hash("testapp", &["aspect"]);
        let dh = destination::destination_hash("testapp", &["aspect"], Some(&id_hash));
        let random = [0xDD; 10];
        let app_data = b"hello app data";

        let (data, _) =
            AnnounceData::pack(&identity, &dh, &nh, &random, None, Some(app_data)).unwrap();

        let parsed = AnnounceData::unpack(&data, false).unwrap();
        assert_eq!(parsed.app_data.as_deref(), Some(app_data.as_slice()));
    }

    #[test]
    fn test_validate_valid_announce() {
        let identity = Identity::from_private_key(&[0x42; 64]);
        let id_hash = *identity.hash();

        let nh = destination::name_hash("testapp", &["aspect"]);
        let dh = destination::destination_hash("testapp", &["aspect"], Some(&id_hash));
        let random = [0xEE; 10];

        let (data, _) =
            AnnounceData::pack(&identity, &dh, &nh, &random, None, Some(b"data")).unwrap();

        let parsed = AnnounceData::unpack(&data, false).unwrap();
        let validated = parsed.validate(&dh).unwrap();

        assert_eq!(validated.identity_hash, id_hash);
        assert_eq!(validated.name_hash, nh);
    }

    #[test]
    fn test_validate_tampered_signature() {
        let identity = Identity::from_private_key(&[0x42; 64]);
        let id_hash = *identity.hash();

        let nh = destination::name_hash("testapp", &["aspect"]);
        let dh = destination::destination_hash("testapp", &["aspect"], Some(&id_hash));
        let random = [0xFF; 10];

        let (mut data, _) = AnnounceData::pack(&identity, &dh, &nh, &random, None, None).unwrap();

        // Tamper with the signature (located at offset 84 = 64 + 10 + 10)
        data[84] ^= 0xFF;

        let parsed = AnnounceData::unpack(&data, false).unwrap();
        assert!(parsed.validate(&dh).is_err());
    }

    #[test]
    fn test_validate_rejects_announce_with_invalid_signing_key() {
        let identity = Identity::from_private_key(&[0x42; 64]);
        let id_hash = *identity.hash();

        let nh = destination::name_hash("testapp", &["aspect"]);
        let dh = destination::destination_hash("testapp", &["aspect"], Some(&id_hash));
        let random = [0x22; 10];

        let (mut data, _) = AnnounceData::pack(&identity, &dh, &nh, &random, None, None).unwrap();

        // Replace the Ed25519 half of the public key (bytes 32..64) with
        // y = 2, which is not a valid compressed point encoding.
        data[32..64].copy_from_slice(&[0; 32]);
        data[32] = 2;

        let parsed = AnnounceData::unpack(&data, false).unwrap();
        assert!(matches!(
            parsed.validate(&dh),
            Err(AnnounceError::InvalidSignature)
        ));
    }

    #[test]
    fn test_validate_wrong_destination_hash() {
        let identity = Identity::from_private_key(&[0x42; 64]);
        let id_hash = *identity.hash();

        let nh = destination::name_hash("testapp", &["aspect"]);
        let dh = destination::destination_hash("testapp", &["aspect"], Some(&id_hash));
        let random = [0x11; 10];

        let (data, _) = AnnounceData::pack(&identity, &dh, &nh, &random, None, None).unwrap();

        let parsed = AnnounceData::unpack(&data, false).unwrap();
        let wrong_hash = [0x00; 16];
        assert!(parsed.validate(&wrong_hash).is_err());
    }

    #[test]
    fn test_to_validated_with_cached_signature_matches_validate() {
        let identity = Identity::from_private_key(&[0x42; 64]);
        let id_hash = *identity.hash();

        let nh = destination::name_hash("testapp", &["aspect"]);
        let dh = destination::destination_hash("testapp", &["aspect"], Some(&id_hash));
        let random = [0xAB; 10];

        let (data, _) =
            AnnounceData::pack(&identity, &dh, &nh, &random, None, Some(b"appdata")).unwrap();

        let parsed = AnnounceData::unpack(&data, false).unwrap();
        let validated = parsed.validate(&dh).unwrap();
        let unchecked = parsed.to_validated_with_cached_signature(&dh).unwrap();

        assert_eq!(validated.identity_hash, unchecked.identity_hash);
        assert_eq!(validated.public_key, unchecked.public_key);
        assert_eq!(validated.name_hash, unchecked.name_hash);
        assert_eq!(validated.random_hash, unchecked.random_hash);
        assert_eq!(validated.ratchet, unchecked.ratchet);
        assert_eq!(validated.app_data, unchecked.app_data);
    }
    fn signed_announce(
        app_data: Option<&[u8]>,
        ratchet: Option<&[u8; 32]>,
    ) -> (AnnounceData, [u8; 16]) {
        let identity = Identity::from_private_key(&[0x42; 64]);
        let id_hash = *identity.hash();
        let nh = destination::name_hash("testapp", &["aspect"]);
        let dh = destination::destination_hash("testapp", &["aspect"], Some(&id_hash));
        let (data, has_ratchet) =
            AnnounceData::pack(&identity, &dh, &nh, &[0x31; 10], ratchet, app_data).unwrap();
        (AnnounceData::unpack(&data, has_ratchet).unwrap(), dh)
    }

    #[test]
    fn test_cached_signature_path_checks_destination_binding() {
        let (parsed, dh) = signed_announce(None, None);
        let mut other_dh = dh;
        other_dh[0] ^= 0x01;
        assert!(matches!(
            parsed.to_validated_with_cached_signature(&other_dh),
            Err(AnnounceError::DestinationMismatch)
        ));

        let other = Identity::from_private_key(&[0x43; 64]);
        let mut swapped = parsed.clone();
        swapped.public_key = other.get_public_key().unwrap();
        assert!(matches!(
            swapped.to_validated_with_cached_signature(&dh),
            Err(AnnounceError::DestinationMismatch)
        ));
    }

    #[test]
    fn test_signature_cache_key_covers_every_signed_field() {
        let ratchet = [0x44; 32];
        let (base, dh) = signed_announce(Some(b"app"), Some(&ratchet));
        let key = base.signature_cache_key(&dh);
        assert_eq!(key, base.clone().signature_cache_key(&dh));

        let mut other_dh = dh;
        other_dh[15] ^= 0x01;
        assert_ne!(key, base.signature_cache_key(&other_dh));

        let mut variants = Vec::new();
        let mut v = base.clone();
        v.public_key[0] ^= 0x01;
        variants.push(v);
        let mut v = base.clone();
        v.name_hash[0] ^= 0x01;
        variants.push(v);
        let mut v = base.clone();
        v.random_hash[0] ^= 0x01;
        variants.push(v);
        let mut v = base.clone();
        v.ratchet = None;
        variants.push(v);
        let mut v = base.clone();
        v.ratchet.as_mut().unwrap()[0] ^= 0x01;
        variants.push(v);
        let mut v = base.clone();
        v.app_data = None;
        variants.push(v);
        let mut v = base.clone();
        v.app_data = Some(b"apq".to_vec());
        variants.push(v);
        let mut v = base.clone();
        v.signature[0] ^= 0x01;
        variants.push(v);

        for variant in &variants {
            assert_ne!(key, variant.signature_cache_key(&dh));
        }
    }

    #[test]
    fn test_signature_cache_key_is_hash_of_signed_data_and_signature() {
        let (parsed, dh) = signed_announce(Some(b"payload"), None);
        let mut material = parsed.signed_data(&dh);
        material.extend_from_slice(&parsed.signature);
        assert_eq!(parsed.signature_cache_key(&dh), hash::full_hash(&material));
    }

    /// Link request cost carried in the test announces' extension anchor.
    const LINK_COST: StampCost = StampCost::from_fp(11 * 256 + 64);

    fn stamped_announce(
        app_data: Option<&[u8]>,
        cost: StampCost,
    ) -> (
        AnnounceData,
        [u8; 16],
        [u8; constants::STAMP_LENGTH],
        StampValue,
    ) {
        use rns_crypto::{OsRng, Rng};

        let identity = Identity::from_private_key(&[0x42; 64]);
        let id_hash = *identity.hash();
        let nh = destination::name_hash("testapp", &["aspect"]);
        let dh = destination::destination_hash("testapp", &["aspect"], Some(&id_hash));
        let public_key = identity.get_public_key().unwrap();

        let mut material = Vec::new();
        material.extend_from_slice(&dh);
        material.extend_from_slice(&public_key);
        material.extend_from_slice(&nh);
        let workblock = stamp_workblock(&material, 0);

        let mut rng = OsRng;
        let mut stamp = [0u8; constants::STAMP_LENGTH];
        loop {
            rng.fill_bytes(&mut stamp);
            if stamp_valid(&stamp, cost, &workblock) {
                break;
            }
        }
        let value = stamp_value(&workblock, &stamp);

        let mut wire = app_data.map(|data| data.to_vec()).unwrap_or_default();
        wire.push(constants::EXT_PAYLOAD_MARKER);
        wire.push(0);
        wire.extend_from_slice(&stamp);
        wire.extend_from_slice(&crate::stamp::link_cost_ext_bytes(LINK_COST));

        let (data, _) =
            AnnounceData::pack(&identity, &dh, &nh, &[0x31; 10], None, Some(&wire)).unwrap();
        (
            AnnounceData::unpack(&data, false).unwrap(),
            dh,
            stamp,
            value,
        )
    }

    #[test]
    fn test_announce_stamp_valid_is_stripped_and_valued() {
        let (parsed, dh, stamp, value) =
            stamped_announce(Some(b"app-data"), StampCost::from_whole(4));
        let mut validated = parsed.validate(&dh).unwrap();
        assert_eq!(
            validated.apply_stamp(&dh, StampCost::from_whole(4)),
            AnnounceStampStatus::Valid
        );
        assert_eq!(validated.stamp, Some(stamp));
        assert_eq!(validated.stamp_value, value);
        assert_eq!(validated.lr_cost, Some(LINK_COST));
        assert_eq!(validated.app_data.as_deref(), Some(b"app-data".as_slice()));
    }

    #[test]
    fn test_announce_stamp_valid_without_app_data_strips_to_none() {
        let (parsed, dh, _, _) = stamped_announce(None, StampCost::from_whole(4));
        let mut validated = parsed.validate(&dh).unwrap();
        assert_eq!(
            validated.apply_stamp(&dh, StampCost::from_whole(4)),
            AnnounceStampStatus::Valid
        );
        assert_eq!(validated.app_data, None);
    }

    #[test]
    fn test_announce_stamp_below_required_value_is_kept_invalid_and_valued() {
        let (parsed, dh, stamp, value) =
            stamped_announce(Some(b"app-data"), StampCost::from_whole(4));
        let mut validated = parsed.validate(&dh).unwrap();
        assert_eq!(
            validated.apply_stamp(&dh, StampCost::from_whole(200)),
            AnnounceStampStatus::Invalid
        );
        assert_eq!(validated.stamp, Some(stamp));
        assert!(value > StampValue::ZERO);
        assert_eq!(validated.stamp_value, value);
        assert_eq!(validated.lr_cost, None);
        assert_eq!(
            validated.app_data.as_ref().map(|data| data.len()),
            Some(b"app-data".len() + constants::EXT_PAYLOAD_LENGTH)
        );
    }

    #[test]
    fn test_announce_without_stamp_is_not_stamped() {
        let (parsed, dh) = signed_announce(Some(b"app-data"), None);
        let mut validated = parsed.validate(&dh).unwrap();
        assert_eq!(
            validated.apply_stamp(&dh, StampCost::from_whole(4)),
            AnnounceStampStatus::NotStamped
        );
        assert_eq!(validated.stamp, None);
        assert_eq!(validated.stamp_value, StampValue::ZERO);
        assert_eq!(validated.lr_cost, None);
        assert_eq!(validated.app_data.as_deref(), Some(b"app-data".as_slice()));
    }

    #[test]
    fn test_announce_stamp_with_one_byte_link_cost_is_not_stamped() {
        // Releases before upstream 796ef2d4 end the extension with a single
        // cost byte. Read as the two-byte format, its 18 trailing bytes start
        // inside the application data, so it is left there unparsed.
        let (parsed, dh, _, _) = stamped_announce(Some(b"app-data"), StampCost::from_whole(4));
        let mut app_data = parsed.app_data.clone().unwrap();
        let fraction = app_data.len() - 2;
        app_data.remove(fraction);
        let identity = Identity::from_private_key(&[0x42; 64]);
        let (data, _) = AnnounceData::pack(
            &identity,
            &dh,
            &parsed.name_hash,
            &parsed.random_hash,
            None,
            Some(&app_data),
        )
        .unwrap();
        let mut validated = AnnounceData::unpack(&data, false)
            .unwrap()
            .validate(&dh)
            .unwrap();
        assert_eq!(
            validated.apply_stamp(&dh, StampCost::from_whole(4)),
            AnnounceStampStatus::NotStamped
        );
        assert_eq!(validated.lr_cost, None);
        assert_eq!(validated.app_data, Some(app_data));
    }

    #[test]
    fn test_announce_stamp_extended_format_is_not_interpreted() {
        let (parsed, dh, _, _) = stamped_announce(Some(b"app-data"), StampCost::from_whole(4));
        let mut announce = parsed.clone();
        // Flip the anchor's high bit: this marks a newer, longer extension.
        let app_data = announce.app_data.as_mut().unwrap();
        let last = app_data.len() - 1;
        app_data[last] |= 0x80;

        // Re-sign because the extension is covered by the announce signature.
        let identity = Identity::from_private_key(&[0x42; 64]);
        let (data, _) = AnnounceData::pack(
            &identity,
            &dh,
            &announce.name_hash,
            &announce.random_hash,
            None,
            Some(app_data),
        )
        .unwrap();
        let reparsed = AnnounceData::unpack(&data, false).unwrap();
        let mut validated = reparsed.validate(&dh).unwrap();
        assert_eq!(
            validated.apply_stamp(&dh, StampCost::from_whole(4)),
            AnnounceStampStatus::NotStamped
        );
        assert_eq!(validated.stamp, None);
        assert_eq!(validated.lr_cost, None);
    }
}
