//! Parsing a device's EEPROM, as upstream `rnodeconf.py`'s `parse_eeprom`
//! does: the provisioning record, its MD5 checksum, the device signature
//! and the TNC configuration.

use std::path::Path;

use crate::rom;
use crate::signature::{self, PublicKey};

/// What the EEPROM says about the device.
#[derive(Debug, Clone, Default)]
pub struct DeviceInfo {
    pub provisioned: bool,
    pub product: u8,
    pub model: u8,
    pub hw_rev: u8,
    pub serialno: [u8; 4],
    pub made: [u8; 4],
    pub checksum: [u8; 16],
    pub checksum_valid: bool,
    pub signature: Vec<u8>,
    pub signature_valid: bool,
    pub locally_signed: bool,
    /// The model is not one upstream knows: its band and output power are
    /// unknown.
    pub model_unknown: bool,
    pub vendor: Option<String>,
    pub min_freq: u64,
    pub max_freq: u64,
    pub max_output: u8,
    pub tnc: Option<TncConfig>,
}

/// The startup radio configuration stored for TNC mode.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TncConfig {
    pub sf: u8,
    pub cr: u8,
    pub txpower: u8,
    pub frequency: u32,
    pub bandwidth: u32,
}

fn be32(eeprom: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([eeprom[at], eeprom[at + 1], eeprom[at + 2], eeprom[at + 3]])
}

/// The keys a signature is checked against: upstream's vendor keys, the
/// public half of a local `firmware/signing.key`, and every
/// `trusted_keys/*.pubkey`, the local ones as vendor `LOCAL`.
pub fn known_keys(config_dir: &Path, log: &mut dyn FnMut(&str)) -> Vec<(String, PublicKey)> {
    let mut keys: Vec<(String, Vec<u8>)> = signature::KNOWN_KEYS
        .iter()
        .filter_map(|(vendor, hex)| Some((vendor.to_string(), signature::unhex(hex)?)))
        .collect();
    let add_local = |der: Vec<u8>, keys: &mut Vec<(String, Vec<u8>)>| {
        if !keys.iter().any(|(_, known)| *known == der) {
            keys.push(("LOCAL".to_string(), der));
        }
    };
    let signing_key = config_dir.join("firmware").join("signing.key");
    if signing_key.is_file() {
        match std::fs::read(&signing_key) {
            Ok(private) => match signature::public_key_of_private(&private) {
                Some(public) => add_local(signature::encode_public_key(&public), &mut keys),
                None => log("Could not deserialize local signing key"),
            },
            Err(_) => log("Could not load local signing key"),
        }
    }
    if let Ok(entries) = std::fs::read_dir(config_dir.join("trusted_keys")) {
        let mut paths: Vec<_> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();
        for path in paths {
            if path.is_file() && path.extension().is_some_and(|ext| ext == "pubkey") {
                match std::fs::read(&path) {
                    Ok(der) => add_local(der, &mut keys),
                    Err(_) => log(&format!(
                        "Could not load trusted signing key{}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    )),
                }
            }
        }
    }
    keys.into_iter()
        .filter_map(|(vendor, der)| Some((vendor, signature::parse_public_key(&der)?)))
        .collect()
}

/// Parse an EEPROM image. An image too short for the fields upstream reads
/// is an error, with the message upstream's parser fails with.
pub fn parse(eeprom: &[u8], keys: &[(String, PublicKey)]) -> Result<DeviceInfo, String> {
    parse_fields(eeprom, keys).ok_or_else(|| "index out of range".to_string())
}

fn parse_fields(eeprom: &[u8], keys: &[(String, PublicKey)]) -> Option<DeviceInfo> {
    let mut info = DeviceInfo::default();
    if *eeprom.get(rom::ADDR_INFO_LOCK as usize)? != rom::INFO_LOCK_BYTE {
        return Some(info);
    }
    let get = |at: u8| eeprom.get(at as usize).copied();
    info.provisioned = true;
    info.product = get(rom::ADDR_PRODUCT)?;
    info.model = get(rom::ADDR_MODEL)?;
    info.hw_rev = get(rom::ADDR_HW_REV)?;
    info.serialno = eeprom
        .get(rom::ADDR_SERIAL as usize..rom::ADDR_SERIAL as usize + 4)?
        .try_into()
        .ok()?;
    info.made = eeprom
        .get(rom::ADDR_MADE as usize..rom::ADDR_MADE as usize + 4)?
        .try_into()
        .ok()?;
    match rom::model(info.model) {
        Some(model) => {
            info.min_freq = model.min_freq;
            info.max_freq = model.max_freq;
            info.max_output = model.max_output;
        }
        None => info.model_unknown = true,
    }
    info.checksum = eeprom
        .get(rom::ADDR_CHKSUM as usize..rom::ADDR_CHKSUM as usize + 16)?
        .try_into()
        .ok()?;
    info.signature = eeprom
        .get(rom::ADDR_SIGNATURE as usize..rom::ADDR_SIGNATURE as usize + 128)?
        .to_vec();

    let mut checksummed = vec![info.product, info.model, info.hw_rev];
    checksummed.extend_from_slice(&info.serialno);
    checksummed.extend_from_slice(&info.made);
    info.checksum_valid = rns_net::md5::md5(&checksummed) == info.checksum;
    if !info.checksum_valid {
        info.provisioned = false;
        return Some(info);
    }

    // Like upstream, a later key that verifies overrides an earlier one.
    for (vendor, key) in keys {
        if signature::verify_pss(key, &info.checksum, &info.signature) {
            info.locally_signed |= vendor == "LOCAL";
            info.signature_valid = true;
            info.vendor = Some(vendor.clone());
        }
    }

    if get(rom::ADDR_CONF_OK)? == rom::CONF_OK_BYTE {
        info.tnc = Some(TncConfig {
            sf: get(rom::ADDR_CONF_SF)?,
            cr: get(rom::ADDR_CONF_CR)?,
            txpower: get(rom::ADDR_CONF_TXP)?,
            frequency: be32(eeprom, rom::ADDR_CONF_FREQ as usize),
            bandwidth: be32(eeprom, rom::ADDR_CONF_BW as usize),
        });
    }
    Some(info)
}

/// An EEPROM image for a provisioned device.
#[cfg(test)]
pub fn provisioned_image(
    product: u8,
    model: u8,
    hw_rev: u8,
    serialno: [u8; 4],
    made: [u8; 4],
    tnc: Option<TncConfig>,
) -> Vec<u8> {
    let mut eeprom = vec![0xFFu8; 4096];
    eeprom[rom::ADDR_PRODUCT as usize] = product;
    eeprom[rom::ADDR_MODEL as usize] = model;
    eeprom[rom::ADDR_HW_REV as usize] = hw_rev;
    eeprom[rom::ADDR_SERIAL as usize..rom::ADDR_SERIAL as usize + 4].copy_from_slice(&serialno);
    eeprom[rom::ADDR_MADE as usize..rom::ADDR_MADE as usize + 4].copy_from_slice(&made);
    let mut checksummed = vec![product, model, hw_rev];
    checksummed.extend_from_slice(&serialno);
    checksummed.extend_from_slice(&made);
    let checksum = rns_net::md5::md5(&checksummed);
    eeprom[rom::ADDR_CHKSUM as usize..rom::ADDR_CHKSUM as usize + 16].copy_from_slice(&checksum);
    eeprom[rom::ADDR_INFO_LOCK as usize] = rom::INFO_LOCK_BYTE;
    if let Some(tnc) = tnc {
        eeprom[rom::ADDR_CONF_SF as usize] = tnc.sf;
        eeprom[rom::ADDR_CONF_CR as usize] = tnc.cr;
        eeprom[rom::ADDR_CONF_TXP as usize] = tnc.txpower;
        eeprom[rom::ADDR_CONF_FREQ as usize..rom::ADDR_CONF_FREQ as usize + 4]
            .copy_from_slice(&tnc.frequency.to_be_bytes());
        eeprom[rom::ADDR_CONF_BW as usize..rom::ADDR_CONF_BW as usize + 4]
            .copy_from_slice(&tnc.bandwidth.to_be_bytes());
        eeprom[rom::ADDR_CONF_OK as usize] = rom::CONF_OK_BYTE;
    }
    eeprom
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_provisioned_tnc_image() {
        let tnc = TncConfig {
            sf: 8,
            cr: 5,
            txpower: 14,
            frequency: 867_200_000,
            bandwidth: 125_000,
        };
        let image = provisioned_image(0x03, 0xA9, 3, [1, 2, 3, 4], [0x66, 0, 0, 0], Some(tnc));
        let info = parse(&image, &[]).unwrap();
        assert!(!info.model_unknown);
        assert!(info.provisioned && info.checksum_valid);
        assert!(!info.signature_valid);
        assert_eq!(info.tnc, Some(tnc));
        assert_eq!(info.max_output, 17);

        let mut broken = image.clone();
        broken[rom::ADDR_HW_REV as usize] = 9;
        let info = parse(&broken, &[]).unwrap();
        assert!(!info.provisioned && !info.checksum_valid);
    }

    #[test]
    fn local_signing_key_signs_devices() {
        let private =
            signature::unhex(include_str!("../tests/vectors/pss_private_key_pkcs8.hex")).unwrap();
        let public = signature::public_key_of_private(&private).unwrap();
        let expected =
            signature::unhex(include_str!("../tests/vectors/pss_public_key.hex")).unwrap();
        assert_eq!(signature::encode_public_key(&public), expected);
    }
}
