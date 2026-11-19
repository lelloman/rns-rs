//! `rnodeconf`: configure RNode devices, compatible with upstream
//! Reticulum's `rnodeconf` utility.
//!
//! Every upstream option is implemented, from device information to the
//! firmware autoinstall wizard.

mod cli;
mod connection;
mod device_config;
mod device_info;
mod flashing;
mod output;
mod provisioning;
#[cfg(test)]
mod tests;

use cli::*;
use connection::*;
use device_config::*;
use device_info::*;
use flashing::*;
use output::*;
use provisioning::*;

mod device;
mod eeprom;
mod firmware;
mod keys;
mod kiss;
mod ports;
mod rom;
mod signature;
mod wizard;

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::exit;

use device::{RNode, RadioConfig};

/// upstream `program_version`.
const PROGRAM_VERSION: &str = "2.5.0";
/// upstream `rnode_baudrate`.
const RNODE_BAUDRATE: u32 = 115_200;

fn main() {
    let args = parse_args();
    for option in INT_OPTIONS {
        args.int(option);
    }
    if args.has("--help") {
        print_help();
        exit(0);
    }
    ensure_config_dirs();

    if args.has("--version") {
        println!("rnodeconf {PROGRAM_VERSION}");
        graceful_exit(0);
    }

    if args.has("--clear-cache") {
        log("Clearing local firmware cache...");
        let _ = std::fs::remove_dir_all(config_dir().join("update"));
        log("Done");
        graceful_exit(0);
    }
    let mut firmware = firmware::Firmware {
        config_dir: config_dir(),
        selected_version: None,
        selected_hash: None,
        fw_url: args.value("--fw-url").map(str::to_string),
        nocheck: args.has("--nocheck"),
    };
    if let Some(version) = args.value("--fw-version") {
        if version.trim().parse::<f64>().is_err() {
            log(&format!(
                "Selected version \"{version}\" does not appear to be a number."
            ));
            graceful_exit(0);
        }
        firmware.selected_version = Some(version.to_string());
    }
    let force_update = args.has("--force-update");
    let use_extracted = args.has("--use-extracted");

    if let Some(key) = args.value("--trust-key") {
        trust_key(key);
        graceful_exit(0);
    }

    let autoinstall = args.has("--autoinstall");
    if use_extracted && ((args.has("--update") && args.port.is_some()) || autoinstall) {
        println!();
        println!("You have specified that rnodeconf should use a firmware extracted");
        println!("from another device. Please note that this *only* works if you are");
        println!("targeting a device of the same type that the firmware came from!");
        println!();
        println!("Flashing this firmware to a device it was not created for will most");
        println!("likely result in it being inoperable until it is updated with the");
        println!("correct firmware. Hit enter to continue.");
        wait_for_enter();
    }

    if args.has("--extract") {
        extract_firmware(&args);
    }

    // The wizard settles the port, the board and its firmware, then hands
    // on to key generation, flashing and bootstrapping.
    let mut board: Option<wizard::Board> = None;
    let mut fw_filename: Option<String> = None;
    let mut port = args.port.clone();
    if autoinstall {
        let (wizard_port, chosen, fw) =
            wizard::run(args.port.as_deref(), use_extracted, &mut firmware);
        port = Some(wizard_port);
        board = Some(chosen);
        fw_filename = Some(fw);
    }

    if args.has("--public") {
        show_public_keys();
        graceful_exit(0);
    }
    if args.has("--key") || autoinstall {
        generate_keys(autoinstall);
        if !autoinstall {
            graceful_exit(0);
        }
    }

    let Some(port) = port else {
        println!();
        print_help();
        println!();
        graceful_exit(0);
    };

    let baud_flash = args.value("--baud-flash").unwrap_or("921600").to_string();
    let target = firmware::FlashTarget {
        port: &port,
        baud_flash: &baud_flash,
    };
    let mut rom_requested = args.has("--rom");
    let mut wants_fw_provision = false;
    if args.has("--flash") || autoinstall {
        // upstream keeps `--platform` as given, a string no platform code
        // equals, and flashes an AVR board when it is not given; the
        // wizard sets the board's.
        let platform = match (&board, args.value("--platform")) {
            (Some(board), _) => {
                firmware::FlashPlatform::Rom(board.platform.unwrap_or(rom::PLATFORM_AVR))
            }
            (None, Some(name)) => firmware::FlashPlatform::Named(name.to_string()),
            (None, None) => firmware::FlashPlatform::Rom(rom::PLATFORM_AVR),
        };
        let fw = fw_filename
            .get_or_insert_with(|| "rnode_firmware.hex".to_string())
            .clone();
        if firmware.selected_version.is_none() {
            log("Missing parameters, cannot continue");
            graceful_exit(68);
        }
        wants_fw_provision = flash_firmware(&firmware, &platform, &fw, &target);
        rom_requested = true;
    }

    let (mut rnode, mut reported, mut platform) = connect(&port);
    if args.has("--eeprom-wipe") {
        log("WARNING: EEPROM is being wiped! Power down device NOW if you do not want this!");
        let _ = rnode.wipe_eeprom(reported.board);
        if platform != rom::PLATFORM_NRF52 {
            let _ = rnode.hard_reset();
        }
        graceful_exit(0);
    }

    log("Reading EEPROM...");
    let (mut image, mut info) = read_eeprom(&mut rnode, &port);

    if info.provisioned {
        fw_filename = firmware_for(&info, &reported, platform, use_extracted);
        if fw_filename.is_none() && platform == rom::PLATFORM_NRF52 && args.has("--update") {
            log("ERROR: No firmware found for this board. Cannot update.");
            graceful_exit(0);
        }
    }

    let mut show_device_info = args.has("--info");
    if args.has("--update") && !autoinstall {
        if !info.provisioned {
            log("Device not provisioned. Cannot update device firmware.");
            graceful_exit(1);
        }
        if use_extracted {
            fw_filename = Some(firmware::EXTRACTED.to_string());
        }
        let fw = fw_filename.clone().unwrap_or_else(|| "None".to_string());
        log("Checking firmware file availability...");
        let mut ensured = false;
        if firmware.selected_version.is_none() {
            firmware.ensure(&fw);
            ensured = true;
        }
        let selected = firmware.selected_version.clone().unwrap_or_default();
        let installed = reported.version().unwrap_or_default();
        if !force_update {
            let which = if args.has("--fw-version") {
                "Specified"
            } else {
                "Latest"
            };
            if installed == selected {
                log(&format!(
                    "{which} firmware version ({selected}) is already installed on this device"
                ));
                log("Override with -U option to install anyway");
                graceful_exit(0);
            }
            // upstream compares the version strings.
            if installed > selected {
                log(&format!(
                    "{which} firmware version ({selected}) is older than firmware already installed on this device"
                ));
                log("Override with -U option to install anyway");
                graceful_exit(0);
            }
        }
        if !ensured {
            firmware.ensure(&fw);
        }
        if fw.ends_with(".zip") && fw != firmware::EXTRACTED {
            log("Decompressing firmware...");
            if firmware.decompress(&fw).is_err() {
                log("Could not decompress firmware from downloaded zip file");
                graceful_exit(0);
            }
            log("Firmware decompressed");
        }

        let update_file = if fw == firmware::EXTRACTED {
            firmware
                .extracted_dir()
                .join("extracted_rnode_firmware.version")
        } else {
            PathBuf::from(format!("{}/{fw}", firmware.version_dir()))
        };
        if !update_file.is_file() {
            log("Firmware update file not found");
            graceful_exit(0);
        }
        show_device_info = false;
        log(&format!("Updating RNode firmware for device on {port}"));
        let hash = installed_firmware_hash(&firmware, platform, &fw);
        if let Some(hash) = &hash {
            if rnode.indicate_firmware_update().is_err() {
                log("Error while indicating firmware update start to board, attempting update anyway...");
            }
            let _ = rnode.set_firmware_hash(hash);
            std::thread::sleep(std::time::Duration::from_secs(1));
            if platform == rom::PLATFORM_NRF52 {
                std::thread::sleep(std::time::Duration::from_secs(14));
            }
        }
        if rnode.disconnect().is_err() {
            log("Error while gracefully disconnecting device before firmware update, attempting update anyway...");
        }
        let call = firmware::flasher_call(
            &firmware,
            &firmware::FlashPlatform::Rom(platform),
            &fw,
            &target,
        );
        match run_flasher(call) {
            Err(e) => {
                log("Error while updating firmware");
                log(&e);
                graceful_exit(0);
            }
            Ok(0) => {
                log("Flashing new firmware completed");
                (rnode, reported, platform) = connect(&port);
                log("Reading EEPROM...");
                (image, info) = read_eeprom(&mut rnode, &port);
                if info.provisioned {
                    fw_filename = firmware_for(&info, &reported, platform, false);
                    show_device_info = true;
                    if let Some(hash) = &hash {
                        let _ = rnode.set_firmware_hash(hash);
                    }
                }
                if show_device_info {
                    log("");
                    log("Firmware update completed successfully");
                }
            }
            Ok(_) => {
                log("An error occurred while flashing the new firmware, exiting now.");
                graceful_exit(0);
            }
        }
    }

    if args.has("--config") {
        show_config(&mut rnode, &image, platform, args.has("--show-psk"));
        let _ = rnode.leave();
        graceful_exit(0);
    }

    if args.has("--eeprom-dump") {
        log("EEPROM contents:");
        log(&hexrep(&image));
        graceful_exit(0);
    }

    if args.has("--eeprom-backup") {
        backup_eeprom(&image);
        graceful_exit(0);
    }

    configure_peripherals(&mut rnode, &args);

    if show_device_info {
        if info.provisioned {
            show_info(&info, &reported);
            let _ = rnode.leave();
            graceful_exit(0);
        } else {
            log("EEPROM is invalid, no further information available");
            graceful_exit(0);
        }
    }

    if rom_requested {
        let provision =
            wants_fw_provision.then(|| (&firmware, fw_filename.as_deref().unwrap_or_default()));
        let spec = match &board {
            // The wizard's board, with upstream's TCXO models stored as
            // their base models, and hardware revision 1.
            Some(board) => Bootstrap {
                product: board.product.unwrap_or(rom::PRODUCT_RNODE),
                model: board.model.map(|model| match model {
                    rom::MODEL_B4_TCXO => rom::MODEL_B4,
                    rom::MODEL_B9_TCXO => rom::MODEL_B9,
                    model => model,
                }),
                hwrev: Some(1),
                autoinstall: true,
            },
            None => Bootstrap {
                product: hex_code(args.value("--product")).unwrap_or(rom::PRODUCT_RNODE),
                model: hex_code(args.value("--model")),
                hwrev: args
                    .int("--hwrev")
                    .filter(|v| *v > 0 && *v < 256)
                    .map(|v| v as u8),
                autoinstall: false,
            },
        };
        bootstrap_eeprom(&mut rnode, &spec, &info, platform, &port, provision);
    }

    if args.has("--sign") {
        if info.provisioned {
            let device_key = keys::device_key_path(&firmware_dir());
            let signer = match rns_net::storage::load_identity(&device_key) {
                Ok(signer) => Some(signer),
                Err(_) => {
                    log("Could not load device signing key");
                    None
                }
            };
            match (rnode.reported().device_hash, signer) {
                (None, _) => log("No device hash present, skipping device signing"),
                (Some(_), None) => {
                    log("No device signer loaded, cannot sign device");
                    graceful_exit(78);
                }
                (Some(hash), Some(signer)) => match signer.sign(&hash) {
                    Ok(signature) => {
                        let _ = rnode.store_signature(&signature);
                        log("Device signed");
                    }
                    Err(_) => {
                        log("No device signer loaded, cannot sign device");
                        graceful_exit(78);
                    }
                },
            }
        } else {
            log("This device has not been provisioned yet, cannot create device signature");
            graceful_exit(79);
        }
    }

    if let Some(hash) = args.value("--firmware-hash") {
        if info.provisioned {
            match signature::unhex(hash).filter(|h| h.len() == 32) {
                Some(hash) => {
                    let _ = rnode.set_firmware_hash(&hash);
                    log("Firmware hash set");
                }
                None => {
                    log("The provided value was not a valid SHA256 hash");
                    graceful_exit(78);
                }
            }
        } else {
            log("This device has not been provisioned yet, cannot set firmware hash");
            graceful_exit(77);
        }
    }

    for (flag, which) in [
        ("--get-target-firmware-hash", "target"),
        ("--get-firmware-hash", "actual"),
    ] {
        if args.has(flag) {
            if info.provisioned {
                let reported = rnode.reported();
                let hash = if which == "target" {
                    reported.firmware_hash_target
                } else {
                    reported.firmware_hash
                };
                log(&format!(
                    "The {which} firmware hash is: {}",
                    hash.map_or_else(|| "None".to_string(), |h| hexstr(&h))
                ));
            } else {
                log("This device has not been provisioned yet, cannot get firmware hash");
                exit(77);
            }
        }
    }

    if info.provisioned {
        if args.has("--normal") {
            if rnode.set_normal_mode().is_err() {
                graceful_exit(1);
            }
            log("Device set to normal (host-controlled) operating mode");
            graceful_exit(0);
        }
        if args.has("--tnc") {
            set_tnc_mode(&mut rnode, &args, platform);
            graceful_exit(0);
        }
    } else {
        log("This device contains a valid firmware, but EEPROM is invalid.");
        log("Probably the device has not been initialised, or the EEPROM has been erased.");
        log("Please correctly initialise the device and try again!");
    }
    graceful_exit(0);
}
