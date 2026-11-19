//! EEPROM provisioning and the signing keys it uses.

use super::*;

/// upstream `download_eeprom` with its `parse_eeprom`: read the EEPROM and
/// report its checksum and signature.
pub(super) fn read_eeprom(rnode: &mut RNode, port: &str) -> (Vec<u8>, eeprom::DeviceInfo) {
    let image = match rnode.download_eeprom() {
        Ok(Some(image)) => image,
        _ => {
            log("Could not download EEPROM from device. Is a valid firmware installed?");
            graceful_exit(0);
        }
    };
    let keys = eeprom::known_keys(&config_dir(), &mut |m| log(m));
    let parsed = eeprom::parse(&image, &keys);
    let info = match &parsed {
        Ok(info) => info.clone(),
        Err(e) => {
            log("Invalid EEPROM data, could not parse device EEPROM.");
            log(&format!("The contained exception was: {e}"));
            eeprom::DeviceInfo::default()
        }
    };
    if info.model_unknown {
        // upstream's lookup fails with a KeyError naming the model.
        log("Error: Model band and output power capabilities are unknown!");
        log(&format!("The contained exception was: {}", info.model));
    }
    if parsed.is_ok() && image.get(rom::ADDR_INFO_LOCK as usize) == Some(&rom::INFO_LOCK_BYTE) {
        if !info.checksum_valid {
            log("EEPROM checksum mismatch");
            graceful_exit(0);
        }
        log("EEPROM checksum correct");
        if info.signature_valid {
            log("Device signature validated");
        } else {
            log("Device signature validation failed");
            print_unverified_warning(port);
        }
    }
    (image, info)
}

/// `--trust-key`: trust a vendor public key for device verification, stored
/// as `trusted_keys/<sha256 of the key>.pubkey`.
pub(super) fn trust_key(hex: &str) {
    let Some(public) = signature::unhex(hex) else {
        log("Invalid key data supplied");
        return;
    };
    if signature::parse_public_key(&public).is_none() {
        log("Could not create public key from supplied data. Check that the key format is valid.");
        log("Could not deserialize key data");
        return;
    }
    let key_hash = hexstr(&rns_crypto::sha256::sha256(&public));
    log(&format!("Trusting key: {key_hash}"));
    let path = config_dir()
        .join("trusted_keys")
        .join(format!("{key_hash}.pubkey"));
    if let Err(e) = std::fs::write(&path, &public) {
        log(&format!("Could not write {}: {e}", path.display()));
    }
}

/// `-P`: show the public halves of the EEPROM and device signing keys.
pub(super) fn show_public_keys() {
    let firmware = firmware_dir();
    match std::fs::read(keys::signing_key_path(&firmware)) {
        Err(_) => {
            log("Could not load EEPROM signing key");
            log("Could not deserialize signing key");
        }
        Ok(private) => match keys::signing_public_key(&private) {
            Ok(public) => {
                log("EEPROM Signing Public key:");
                log(&hexstr(&public));
            }
            Err(e) => {
                log("Could not deserialize signing key");
                log(&e);
            }
        },
    }
    match rns_net::storage::load_identity(&keys::device_key_path(&firmware))
        .ok()
        .and_then(|identity| identity.get_public_key())
    {
        Some(public) => {
            log("");
            log("Device Signing Public key:");
            log(&hexrep(&public[32..]));
        }
        None => log("Could not load device signing key"),
    }
}

/// `-k`: create the device signing key and the EEPROM signing key when
/// missing.
/// `-k`, or key generation for the autoinstall wizard, which leaves an
/// existing EEPROM signing key alone without saying so and does not show a
/// new one.
pub(super) fn generate_keys(autoinstall: bool) {
    let firmware = firmware_dir();
    let device_key = keys::device_key_path(&firmware);
    if !device_key.is_file() {
        log("Generating a new device signing key...");
        let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::OsRng);
        if let Err(e) = rns_net::storage::save_identity(&identity, &device_key) {
            log(&format!(
                "Could not create new device signing key at {}. The contained exception was:",
                device_key.display()
            ));
            log(&e.to_string());
            log("Please ensure filesystem access and try again.");
            graceful_exit(81);
        }
        log(&format!(
            "Device signing key written to {}",
            device_key.display()
        ));
    } else if let Err(e) = rns_net::storage::load_identity(&device_key) {
        log(&format!(
            "Could not load device signing key from {}. The contained exception was:",
            device_key.display()
        ));
        log(&e.to_string());
        log("Please restore or clear the key and try again.");
        graceful_exit(82);
    }

    let signing_key = keys::signing_key_path(&firmware);
    if !signing_key.is_file() {
        log("Generating a new EEPROM signing key...");
    }
    let private = match keys::generate_signing_key() {
        Ok(private) => private,
        Err(e) => {
            log(&format!("Could not generate EEPROM signing key: {e}"));
            graceful_exit(1);
        }
    };
    let _ = std::fs::create_dir_all(&firmware);
    if signing_key.is_file() {
        if !autoinstall {
            log("EEPROM Signing key already exists, not overwriting!");
            log("Manually delete this key to create a new one.");
        }
    } else {
        if let Err(e) = std::fs::write(&signing_key, &private) {
            log(&format!("Could not write {}: {e}", signing_key.display()));
            graceful_exit(1);
        }
        if !autoinstall {
            log("Wrote signing key");
            log("Public key:");
            log(&hexstr(
                &keys::signing_public_key(&private).unwrap_or_default(),
            ));
        }
    }
}

/// `--eeprom-backup`. Upstream joins its EEPROM directory and the file name
/// without a separator, so its backups land beside the directory; these go
/// inside it.
pub(super) fn backup_eeprom(image: &[u8]) {
    let filename = local_time("%Y-%m-%d_%H-%M-%S", now());
    let path = config_dir()
        .join("eeprom")
        .join(format!("{filename}.eeprom"));
    match std::fs::write(&path, image) {
        Ok(()) => log(&format!("EEPROM backup written to: {}", path.display())),
        Err(_) => {
            log("EEPROM was successfully downloaded from device,");
            log("but file could not be written to disk.");
        }
    }
}

/// `-r`: write a provisioning record to an unprovisioned device's EEPROM,
/// signed with the local EEPROM signing key, then read it back.
/// What `-r` writes: from the command line, or from the autoinstall
/// wizard.
pub(super) struct Bootstrap {
    pub(super) product: u8,
    pub(super) model: Option<u8>,
    pub(super) hwrev: Option<u8>,
    pub(super) autoinstall: bool,
}

pub(super) fn bootstrap_eeprom(
    rnode: &mut RNode,
    spec: &Bootstrap,
    info: &eeprom::DeviceInfo,
    platform: u8,
    port: &str,
    provision: Option<(&firmware::Firmware, &str)>,
) {
    use std::time::Duration;
    let pause = |ms: u64| std::thread::sleep(Duration::from_millis(ms));

    // The wizard reinstalls a provisioned device unless its signature
    // is valid.
    if (info.provisioned && !spec.autoinstall) || info.signature_valid {
        log("EEPROM bootstrap was requested, but a valid EEPROM was already present.");
        log("No changes are being made.");
        graceful_exit(0);
    }
    if spec.autoinstall {
        log("Clearing old EEPROM, this will take about 15 seconds...");
        let _ = rnode.wipe_eeprom(rnode.reported().board);
    }
    match platform {
        rom::PLATFORM_ESP32 => {
            log("Waiting for ESP32 reset...");
            pause(6000);
        }
        rom::PLATFORM_NRF52 => {
            log("Waiting for NRF52 reset...");
            pause(18000);
        }
        _ => pause(3000),
    }

    let firmware = firmware_dir();
    let counter_path = firmware.join("serial.counter");
    let counter: u32 = if counter_path.is_file() {
        match std::fs::read_to_string(&counter_path)
            .ok()
            .and_then(|text| text.trim().parse().ok())
        {
            Some(counter) => counter,
            None => {
                log("Could not create device serial number, exiting");
                graceful_exit(0);
            }
        }
    } else {
        0
    };
    let serialno = counter + 1;
    let product = spec.product;
    let (Some(model), Some(hwrev)) = (spec.model, spec.hwrev) else {
        log("Invalid data specified, cancelling EEPROM write");
        graceful_exit(0);
    };

    let time_bytes = (now() as u32).to_be_bytes();
    let serial_bytes = serialno.to_be_bytes();
    let _ = std::fs::write(&counter_path, serialno.to_string());
    let mut info_chunk = vec![product, model, hwrev];
    info_chunk.extend_from_slice(&serial_bytes);
    info_chunk.extend_from_slice(&time_bytes);
    let checksum = rns_net::md5::md5(&info_chunk);

    log("Loading signing key...");
    let signing_key = keys::signing_key_path(&firmware);
    if !signing_key.is_file() {
        log("No signing key found");
        graceful_exit(0);
    }
    let signature = match std::fs::read(&signing_key)
        .map_err(|e| e.to_string())
        .and_then(|private| keys::sign_checksum(&private, &checksum))
    {
        Ok(signature) => signature,
        Err(e) => {
            log("Error while signing EEPROM");
            log(&e);
            log("An error occurred while writing EEPROM. The contained exception was:");
            log("no signature");
            graceful_exit(1);
        }
    };

    log("Bootstrapping device EEPROM...");
    let mut writes: Vec<(u8, u8)> = vec![
        (rom::ADDR_PRODUCT, product),
        (rom::ADDR_MODEL, model),
        (rom::ADDR_HW_REV, hwrev),
    ];
    for (i, byte) in serial_bytes.iter().enumerate() {
        writes.push((rom::ADDR_SERIAL + i as u8, *byte));
    }
    for (i, byte) in time_bytes.iter().enumerate() {
        writes.push((rom::ADDR_MADE + i as u8, *byte));
    }
    for (i, byte) in checksum.iter().enumerate() {
        writes.push((rom::ADDR_CHKSUM + i as u8, *byte));
    }
    for (i, byte) in signature.iter().enumerate() {
        writes.push((rom::ADDR_SIGNATURE + i as u8, *byte));
    }
    for (addr, byte) in writes {
        if rnode.write_eeprom(addr, byte).is_err() {
            graceful_exit(1);
        }
        pause(6);
    }
    let _ = rnode.write_eeprom(rom::ADDR_INFO_LOCK, rom::INFO_LOCK_BYTE);
    if platform == rom::PLATFORM_NRF52 {
        pause(3000);
    }
    log("EEPROM written! Validating...");
    if let Some((firmware, fw_filename)) = provision {
        if let Some(hash) = installed_firmware_hash(firmware, platform, fw_filename) {
            pause(750);
            log("Setting firmware checksum...");
            let _ = rnode.set_firmware_hash(&hash);
        }
    }

    match platform {
        rom::PLATFORM_ESP32 => {
            let _ = rnode.hard_reset();
            log("Waiting for ESP32 reset...");
            pause(7000);
            if [
                rom::MODEL_AC,
                rom::MODEL_A6,
                rom::MODEL_A1,
                rom::MODEL_AA,
                rom::MODEL_A5,
            ]
            .contains(&model)
            {
                pause(5000);
            }
        }
        rom::PLATFORM_NRF52 => {
            // Upstream finds the board again by its USB serial number,
            // since the port can change across this reset; this keeps
            // the same port.
            let _ = rnode.hard_reset();
            log("Waiting for NRF52 reset...");
            pause(20000);
        }
        _ => {
            let _ = rnode.hard_reset();
        }
    }

    let (image, written) = read_eeprom(rnode, port);
    if written.provisioned {
        log("EEPROM Bootstrapping successful!");
        let _ = rnode.hard_reset();
        if spec.autoinstall {
            wizard::print_completion();
        }
        let device_db = firmware.join("device_db");
        let saved = std::fs::create_dir_all(&device_db)
            .and_then(|_| std::fs::write(device_db.join(hexstr(&serial_bytes)), &image));
        if saved.is_err() {
            log("WARNING: Could not backup device EEPROM to disk");
        }
    } else {
        log("EEPROM was written, but validation failed. Check your settings.");
    }
    graceful_exit(0);
}

pub(super) fn print_unverified_warning(port: &str) {
    for line in [
        "     ",
        "     WARNING! This device is NOT verifiable and should NOT be trusted.",
        "     Someone could have added privacy-breaking or malicious code to it.",
        "     ",
        "     Please verify the signing key is present on this machine.",
        "     Autogenerated keys will not match another machine's signature.",
        "     ",
        "     Proceed at your own risk and responsibility! If you created this",
        "     device yourself, please read the documentation on how to sign your",
        "     device to avoid this warning.",
        "     ",
        "     Always use a firmware downloaded as binaries or compiled from source",
        "     from one of the following locations:",
        "     ",
        "        https://github.com/markqvist/rnode_firmware",
        "        https://github.com/liberatedsystems/RNode_Firmware_CE",
        "     ",
        "     You can reflash and bootstrap this device to a verifiable state",
        "     by using this utility. It is recommended to do so NOW!",
        "     ",
        "     To initialise this device to a verifiable state, please run:",
        "     ",
    ] {
        println!("{line}");
    }
    println!("              rnodeconf {port} --autoinstall");
    println!();
}
