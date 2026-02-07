use alloc::vec::Vec;
use core::fmt;

use rns_crypto::identity::Identity;

use crate::constants;
use crate::hash;

#[derive(Debug)]
pub enum AnnounceError {
    DataTooShort,
    InvalidSignature,
    DestinationMismatch,
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
    pub public_key: [u8; 64],
    pub name_hash: [u8; 10],
    pub random_hash: [u8; 10],
    pub ratchet: Option<[u8; 32]>,
    pub signature: [u8; 64],
    pub app_data: Option<Vec<u8>>,
}

/// Result of a successfully validated announce.
#[derive(Debug)]
pub struct ValidatedAnnounce {
    pub identity_hash: [u8; 16],
    pub public_key: [u8; 64],
    pub name_hash: [u8; 10],
    pub random_hash: [u8; 10],
    pub ratchet: Option<[u8; 32]>,
    pub app_data: Option<Vec<u8>>,
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
        let keysize = constants::KEYSIZE / 8; // 64
        let name_hash_len = constants::NAME_HASH_LENGTH / 8; // 10
        let sig_len = constants::SIGLENGTH / 8; // 64
        let ratchet_size = constants::RATCHETSIZE / 8; // 32

        let min_len = if has_ratchet {
            keysize + name_hash_len + 10 + ratchet_size + sig_len
        } else {
            keysize + name_hash_len + 10 + sig_len
        };

        if data.len() < min_len {
            return Err(AnnounceError::DataTooShort);
        }

        let mut public_key = [0u8; 64];
        public_key.copy_from_slice(&data[..keysize]);

        let mut name_hash = [0u8; 10];
        name_hash.copy_from_slice(&data[keysize..keysize + name_hash_len]);

        let mut random_hash = [0u8; 10];
        random_hash.copy_from_slice(&data[keysize + name_hash_len..keysize + name_hash_len + 10]);

        let (ratchet, sig_start) = if has_ratchet {
            let mut ratchet = [0u8; 32];
            ratchet.copy_from_slice(
                &data[keysize + name_hash_len + 10..keysize + name_hash_len + 10 + ratchet_size],
            );
            (Some(ratchet), keysize + name_hash_len + 10 + ratchet_size)
        } else {
            (None, keysize + name_hash_len + 10)
        };

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[sig_start..sig_start + sig_len]);

        // Determine app_data
        // From Python: app_data is present if len(data) > keysize + name_hash_len + 10 + sig_len [+ ratchetsize]
        let app_data_start = sig_start + sig_len;
        let app_data = if data.len() > app_data_start {
            Some(data[app_data_start..].to_vec())
        } else {
            None
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
        // Create identity from public key
        let announced_identity = Identity::from_public_key(&self.public_key);

        // Build signed data
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(destination_hash);
        signed_data.extend_from_slice(&self.public_key);
        signed_data.extend_from_slice(&self.name_hash);
        signed_data.extend_from_slice(&self.random_hash);

        if let Some(ref ratchet) = self.ratchet {
            signed_data.extend_from_slice(ratchet);
        }

        // When building signed_data, use app_data bytes (or empty if None)
        // Python uses app_data = b"" for building signed_data when no app_data
        if let Some(ref ad) = self.app_data {
            signed_data.extend_from_slice(ad);
        }

        // Verify signature
        if !announced_identity.verify(&self.signature, &signed_data) {
            return Err(AnnounceError::InvalidSignature);
        }

        // Verify destination hash
        let identity_hash = *announced_identity.hash();

        let mut hash_material = Vec::new();
        hash_material.extend_from_slice(&self.name_hash);
        hash_material.extend_from_slice(&identity_hash);

        let expected_hash = hash::truncated_hash(&hash_material);

        if &expected_hash != destination_hash {
            return Err(AnnounceError::DestinationMismatch);
        }

        Ok(ValidatedAnnounce {
            identity_hash,
            public_key: self.public_key,
            name_hash: self.name_hash,
            random_hash: self.random_hash,
            ratchet: self.ratchet,
            app_data: self.app_data.clone(),
        })
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

        let (mut data, _) =
            AnnounceData::pack(&identity, &dh, &nh, &random, None, None).unwrap();

        // Tamper with the signature (located at offset 84 = 64 + 10 + 10)
        data[84] ^= 0xFF;

        let parsed = AnnounceData::unpack(&data, false).unwrap();
        assert!(parsed.validate(&dh).is_err());
    }

    #[test]
    fn test_validate_wrong_destination_hash() {
        let identity = Identity::from_private_key(&[0x42; 64]);
        let id_hash = *identity.hash();

        let nh = destination::name_hash("testapp", &["aspect"]);
        let dh = destination::destination_hash("testapp", &["aspect"], Some(&id_hash));
        let random = [0x11; 10];

        let (data, _) =
            AnnounceData::pack(&identity, &dh, &nh, &random, None, None).unwrap();

        let parsed = AnnounceData::unpack(&data, false).unwrap();
        let wrong_hash = [0x00; 16];
        assert!(parsed.validate(&wrong_hash).is_err());
    }
}
