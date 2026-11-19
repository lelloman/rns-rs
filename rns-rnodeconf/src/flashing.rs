//! Choosing, extracting and flashing firmware.

use super::*;

/// The firmware package for a provisioned device: its model's, or for a
/// homebrew model (0xFF) its board's.
pub(super) fn firmware_for(
    info: &eeprom::DeviceInfo,
    reported: &device::Reported,
    platform: u8,
    use_extracted: bool,
) -> Option<String> {
    if info.model != rom::MODEL_FF {
        return rom::model(info.model)
            .and_then(|m| m.firmware)
            .map(str::to_string);
    }
    if use_extracted {
        return Some(firmware::EXTRACTED.to_string());
    }
    let mcu = reported.mcu.unwrap_or(rom::MCU_1284P);
    let name = match platform {
        rom::PLATFORM_AVR if mcu == rom::MCU_1284P => "rnode_firmware.hex",
        rom::PLATFORM_AVR if mcu == rom::MCU_2560 => "rnode_firmware_m2560.hex",
        rom::PLATFORM_ESP32 if reported.board == Some(rom::BOARD_HUZZAH32) => {
            "rnode_firmware_featheresp32.zip"
        }
        rom::PLATFORM_ESP32 if reported.board == Some(rom::BOARD_GENERIC_ESP32) => {
            "rnode_firmware_esp32_generic.zip"
        }
        rom::PLATFORM_NRF52 if reported.board == Some(rom::BOARD_RAK4631) => {
            "rnode_firmware_rak4631.zip"
        }
        _ => return None,
    };
    Some(name.to_string())
}

/// The firmware hash a device reports once `fw_filename` is installed:
/// recorded at extraction for an extracted firmware, computed from the
/// image otherwise.
pub(super) fn installed_firmware_hash(
    firmware: &firmware::Firmware,
    platform: u8,
    fw_filename: &str,
) -> Option<Vec<u8>> {
    if fw_filename == firmware::EXTRACTED {
        let info = std::fs::read_to_string(
            firmware
                .extracted_dir()
                .join("extracted_rnode_firmware.version"),
        )
        .ok()?;
        return signature::unhex(info.split_whitespace().nth(1)?);
    }
    let partition = fw_filename.replace(".zip", ".bin");
    firmware::partition_hash(platform, &format!("{}/{partition}", firmware.version_dir()))
}

/// Run a flasher as upstream's `subprocess.call` does, with the output
/// going to the terminal: its exit status, negative for a signal.
#[allow(unsafe_code, reason = "strerror for the flasher's exit reason")]
pub(super) fn run_flasher(call: Option<Vec<String>>) -> Result<i32, String> {
    let Some(call) = call else {
        return Err("expected str, bytes or os.PathLike object, not NoneType".into());
    };
    let status = std::process::Command::new(&call[0])
        .args(&call[1..])
        .status()
        .map_err(|e| {
            let errno = e.raw_os_error().unwrap_or(0);
            // SAFETY: strerror returns a static string for any errno.
            let reason =
                unsafe { std::ffi::CStr::from_ptr(libc::strerror(errno)) }.to_string_lossy();
            format!("[Errno {errno}] {reason}: '{}'", call[0])
        })?;
    use std::os::unix::process::ExitStatusExt;
    Ok(status
        .code()
        .unwrap_or_else(|| -status.signal().unwrap_or(0)))
}

/// `-f`: flash `fw_filename` of the selected version. Returns whether the
/// device's firmware hash is then set while bootstrapping its EEPROM.
pub(super) fn flash_firmware(
    firmware: &firmware::Firmware,
    platform: &firmware::FlashPlatform,
    fw_filename: &str,
    target: &firmware::FlashTarget,
) -> bool {
    use std::time::Duration;
    let esp32 = *platform == firmware::FlashPlatform::Rom(rom::PLATFORM_ESP32);
    let nrf52 = *platform == firmware::FlashPlatform::Rom(rom::PLATFORM_NRF52);
    if fw_filename == firmware::EXTRACTED {
        log(&format!(
            "Flashing RNode firmware to device on {}",
            target.port
        ));
        let call = firmware::flasher_call(firmware, platform, fw_filename, target);
        return match run_flasher(call) {
            Ok(0) => {
                log("Done flashing");
                if esp32 {
                    log("Waiting for ESP32 reset...");
                    std::thread::sleep(Duration::from_secs(7));
                }
                esp32
            }
            Ok(_) => graceful_exit(0),
            Err(e) => {
                log("Error while flashing");
                log(&e);
                graceful_exit(1);
            }
        };
    }

    let package = format!("{}/{fw_filename}", firmware.version_dir());
    if !Path::new(&package).is_file() {
        log("Firmware file not found");
        graceful_exit(0);
    }
    if fw_filename.ends_with(".zip") {
        log("Decompressing firmware...");
        if firmware.decompress(fw_filename).is_err() {
            log("Could not decompress firmware from downloaded zip file");
            graceful_exit(0);
        }
        log("Firmware decompressed");
    }
    log(&format!(
        "Flashing RNode firmware to device on {}",
        target.port
    ));
    let call = firmware::flasher_call(firmware, platform, fw_filename, target);
    match run_flasher(call) {
        Ok(0) => {
            log("Done flashing");
            if esp32 {
                log("Waiting for ESP32 reset...");
                std::thread::sleep(Duration::from_secs(8));
            }
            if nrf52 {
                log("Waiting for NRF52 reset...");
                std::thread::sleep(Duration::from_secs(6));
            }
            esp32 || nrf52
        }
        Ok(status) => {
            log(&format!("Error from flasher ({status}) while writing."));
            log("Some boards have trouble flashing at high speeds, and you can");
            log("try flashing with a lower baud rate, as in this example:");
            log("rnodeconf --autoinstall --baud-flash 115200");
            graceful_exit(0);
        }
        Err(e) => {
            log("Error while flashing");
            log(&e);
            graceful_exit(1);
        }
    }
}

/// The parts of an ESP32 RNode's flash `-e` copies: what each is, where it
/// lies, how long it is, and the file it goes to.
pub(super) const EXTRACTION_PARTS: &[(&str, &str, &str, &str)] = &[
    (
        "bootloader",
        "0x1000",
        "0x4650",
        "extracted_rnode_firmware.bootloader",
    ),
    (
        "partition table",
        "0x8000",
        "0xC00",
        "extracted_rnode_firmware.partitions",
    ),
    (
        "app boot",
        "0xe000",
        "0x2000",
        "extracted_rnode_firmware.boot_app0",
    ),
    (
        "application image",
        "0x10000",
        "0x200000",
        "extracted_rnode_firmware.bin",
    ),
    (
        "console image",
        "0x210000",
        "0x1F0000",
        "extracted_console_image.bin",
    ),
];

/// `-e`: copy the firmware images off an ESP32 RNode into
/// `~/.config/rnodeconf/extracted/`, for `--use-extracted`.
pub(super) fn extract_firmware(args: &Args) -> ! {
    println!();
    println!("RNode Firmware Extraction");
    println!();
    let port = match &args.port {
        None => {
            let port = select_port();
            println!(
                "\nOk, using device on {} ({}, {})",
                port.device,
                ports::py_str(&port.product),
                ports::py_str(&port.serial_number)
            );
            port.device
        }
        // Upstream fails with a Python error on a port it does not list,
        // such as a pseudo-terminal; it is used as given here.
        Some(port) => {
            println!("\nUsing device on {port}");
            port.clone()
        }
    };
    println!("\nProbing device...");
    let (reader, writer) = match open_serial(&port) {
        Ok(handles) => handles,
        Err(e) => {
            log("Could not open the specified serial port. The contained exception was:");
            log(&format!(
                "[Errno {}] could not open port {port}: {e}",
                e.raw_os_error().unwrap_or(0)
            ));
            graceful_exit(0);
        }
    };
    let mut rnode = RNode::new(reader, writer);
    if rnode.device_probe().is_err() {
        log("No answer from device");
    } else {
        let reported = rnode.reported();
        log("Device connected");
        log(&format!(
            "Current firmware version: {}",
            reported.version().unwrap_or_else(|| "None".into())
        ));
    }
    let reported = rnode.reported();
    let mut info = eeprom::DeviceInfo::default();
    if reported.detected == Some(true) {
        log("Trying to read EEPROM...");
        info = read_eeprom(&mut rnode, &port).1;
    } else {
        log("Could not detect a connected RNode");
    }

    if reported.platform != Some(rom::PLATFORM_ESP32) {
        println!("\nFirmware extraction is currently only supported on ESP32-based RNodes.");
        graceful_exit(170);
    }
    if info.provisioned {
        if !info.signature_valid {
            println!(
                "\nThe device signature in this RNode is unknown and cannot be verified. It is still"
            );
            println!(
                "possible to extract the firmware from it, but you should make absolutely sure that"
            );
            println!(
                "it comes from a trusted source. It is possible that someone could have modified the"
            );
            println!(
                "firmware. If that is the case, these modifications will propagate to any new RNodes"
            );
            println!("descendent from this one!");
            println!("\nHit enter if you are sure you want to continue.");
            wait_for_enter();
        }
        let Some(hash) = &reported.firmware_hash else {
            println!("Could not read firmware information from device");
            println!("\nRNode firmware extraction failed");
            graceful_exit(180);
        };
        let version = format!(
            "{} {}",
            reported.version().unwrap_or_else(|| "None".into()),
            hexstr(hash)
        );
        let _ = rnode.disconnect();
        println!("\nFound RNode Firmvare v{version}");
        println!("\nReady to extract firmware images from the RNode");
        println!("Press enter to start the extraction process");
        wait_for_enter();
        let Some(esptool) = firmware::extraction_esptool(&config_dir()) else {
            log("Error: No esptool is available to read the device's flash with.");
            log("Install it with: pip3 install esptool");
            graceful_exit(181);
        };
        let extracted = config_dir().join("extracted");
        let _ = std::fs::write(extracted.join("extracted_rnode_firmware.version"), &version);
        let baud = args.value("--baud-flash").unwrap_or("921600");
        for (part, offset, size, file) in EXTRACTION_PARTS {
            println!("Extracting {part}...");
            let mut command = esptool.clone();
            command.extend(
                [
                    "--chip",
                    "esp32",
                    "--port",
                    &port,
                    "--baud",
                    baud,
                    "--before",
                    "default_reset",
                    "--after",
                    "hard_reset",
                    "read_flash",
                    offset,
                    size,
                ]
                .map(str::to_string),
            );
            command.push(extracted.join(file).display().to_string());
            let done = std::process::Command::new(&command[0])
                .args(&command[1..])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|status| status.success());
            if !done {
                let shown: Vec<String> = command
                    .iter()
                    .map(|a| {
                        if a.contains('/') {
                            format!("\"{a}\"")
                        } else {
                            a.clone()
                        }
                    })
                    .collect();
                println!(
                    "The extraction failed, the following command did not complete successfully:\n{}",
                    shown.join(" ")
                );
                exit(182);
            }
        }
        println!("\nFirmware successfully extracted!");
        println!("\nYou can now use this firmware to update or autoinstall other RNodes");
        exit(0);
    }
    println!("\nRNode firmware extraction failed");
    graceful_exit(180);
}

pub(super) fn firmware_dir() -> PathBuf {
    config_dir().join("firmware")
}
