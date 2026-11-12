//! `rnodeconf`: configure RNode devices, compatible with upstream
//! Reticulum's `rnodeconf` utility.
//!
//! Implemented so far: everything but installing, updating and extracting
//! firmware.

mod device;
mod eeprom;
mod firmware;
mod keys;
mod kiss;
mod ports;
mod rom;
mod signature;

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::exit;

use device::{RNode, RadioConfig};

/// upstream `program_version`.
const PROGRAM_VERSION: &str = "2.5.0";
/// upstream `rnode_baudrate`.
const RNODE_BAUDRATE: u32 = 115_200;

/// Options that take a value, by every name they have.
const VALUE_OPTIONS: &[&str] = &[
    "--fw-version",
    "--fw-url",
    "--baud-flash",
    "-w",
    "--wifi",
    "--channel",
    "--ssid",
    "--psk",
    "--ip",
    "--nm",
    "-D",
    "--display",
    "-t",
    "--timeout",
    "-R",
    "--rotation",
    "--display-addr",
    "--np",
    "--freq",
    "--bw",
    "--txp",
    "--sf",
    "--cr",
    "--trust-key",
    "-H",
    "--firmware-hash",
    "--platform",
    "--product",
    "--model",
    "--hwrev",
];

/// Flags, short form to long form.
const FLAGS: &[(&str, &str)] = &[
    ("-i", "--info"),
    ("-a", "--autoinstall"),
    ("-u", "--update"),
    ("-U", "--force-update"),
    ("", "--nocheck"),
    ("-e", "--extract"),
    ("-E", "--use-extracted"),
    ("-C", "--clear-cache"),
    ("-N", "--normal"),
    ("-T", "--tnc"),
    ("-b", "--bluetooth-on"),
    ("-B", "--bluetooth-off"),
    ("-p", "--bluetooth-pair"),
    ("", "--show-psk"),
    ("", "--recondition-display"),
    ("-x", "--ia-enable"),
    ("-X", "--ia-disable"),
    ("-c", "--config"),
    ("", "--eeprom-backup"),
    ("", "--eeprom-dump"),
    ("", "--eeprom-wipe"),
    ("-P", "--public"),
    ("", "--version"),
    ("-f", "--flash"),
    ("-r", "--rom"),
    ("-k", "--key"),
    ("-S", "--sign"),
    ("-K", "--get-target-firmware-hash"),
    ("-L", "--get-firmware-hash"),
    ("-h", "--help"),
];

/// Short value options and their long names.
const VALUE_ALIASES: &[(&str, &str)] = &[
    ("-w", "--wifi"),
    ("-D", "--display"),
    ("-t", "--timeout"),
    ("-R", "--rotation"),
    ("-H", "--firmware-hash"),
];

/// Options of later implementation stages.
const NOT_YET: &[&str] = &["--autoinstall"];

/// Options upstream's argument parser reads as integers, rejecting the
/// command line before doing anything else when one is not.
const INT_OPTIONS: &[&str] = &[
    "--display",
    "--timeout",
    "--rotation",
    "--np",
    "--freq",
    "--bw",
    "--txp",
    "--sf",
    "--cr",
    "--hwrev",
];

#[derive(Default)]
struct Args {
    flags: Vec<&'static str>,
    values: Vec<(&'static str, String)>,
    port: Option<String>,
}

impl Args {
    fn has(&self, long: &str) -> bool {
        self.flags.contains(&long) || self.values.iter().any(|(k, _)| *k == long)
    }

    fn value(&self, long: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(k, _)| *k == long)
            .map(|(_, v)| v.as_str())
    }

    fn int(&self, long: &str) -> Option<i64> {
        let value = self.value(long)?;
        match value.trim().parse::<i64>() {
            Ok(v) => Some(v),
            Err(_) => usage_error(&format!("argument {long}: invalid int value: '{value}'")),
        }
    }
}

fn usage_error(message: &str) -> ! {
    eprintln!("usage: rnodeconf [-h] [options] [port]");
    eprintln!("rnodeconf: error: {message}");
    exit(2)
}

fn parse_args() -> Args {
    let mut args = Args::default();
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) if name.starts_with("--") => {
                (name.to_string(), Some(value.to_string()))
            }
            _ => (arg.clone(), None),
        };
        if let Some(&option) = VALUE_OPTIONS.iter().find(|o| **o == name) {
            let long = VALUE_ALIASES
                .iter()
                .find(|(short, _)| *short == option)
                .map_or(option, |(_, long)| *long);
            let value = match inline.or_else(|| iter.next()) {
                Some(value) => value,
                None => usage_error(&format!("argument {name}: expected one argument")),
            };
            args.values.push((long, value));
        } else if let Some((_, long)) = FLAGS
            .iter()
            .find(|(short, long)| *short == name || *long == name)
        {
            args.flags.push(long);
        } else if name.starts_with('-') && name.len() > 1 {
            usage_error(&format!("unrecognized arguments: {arg}"));
        } else if args.port.is_none() {
            args.port = Some(arg);
        } else {
            usage_error(&format!("unrecognized arguments: {arg}"));
        }
    }
    args
}

/// upstream's `--help`, as Python's argparse lays it out at 80 columns.
const HELP: &str = r#"usage: rnodeconf [-h] [-i] [-a] [-u] [-U] [--fw-version version]
                 [--fw-url url] [--nocheck] [-e] [-E] [-C]
                 [--baud-flash baud_flash] [-N] [-T] [-b] [-B] [-p] [-w mode]
                 [--channel channel] [--ssid ssid] [--psk psk] [--show-psk]
                 [--ip ip] [--nm nm] [-D i] [-t s] [-R rotation]
                 [--display-addr byte] [--recondition-display] [--np i]
                 [--freq Hz] [--bw Hz] [--txp dBm] [--sf factor] [--cr rate]
                 [-x] [-X] [-c] [--eeprom-backup] [--eeprom-dump]
                 [--eeprom-wipe] [-P] [--trust-key hexbytes] [--version] [-f]
                 [-r] [-k] [-S] [-H FIRMWARE_HASH] [--platform platform]
                 [--product product] [--model model] [--hwrev revision]
                 [port]

RNode Configuration and firmware utility. This program allows you to change
various settings and startup modes of RNode. It can also install, flash and
update the firmware on supported devices.

positional arguments:
  port                  serial port where RNode is attached

options:
  -h, --help            show this help message and exit
  -i, --info            Show device info
  -a, --autoinstall     Automatic installation on various supported devices
  -u, --update          Update firmware to the latest version
  -U, --force-update    Update to specified firmware even if version matches
                        or is older than installed version
  --fw-version version  Use a specific firmware version for update or
                        autoinstall
  --fw-url url          Use an alternate firmware download URL
  --nocheck             Don't check for firmware updates online
  -e, --extract         Extract firmware from connected RNode for later use
  -E, --use-extracted   Use the extracted firmware for autoinstallation or
                        update
  -C, --clear-cache     Clear locally cached firmware files
  --baud-flash baud_flash
                        Set specific baud rate when flashing device. Default
                        is 921600
  -N, --normal          Switch device to normal mode
  -T, --tnc             Switch device to TNC mode
  -b, --bluetooth-on    Turn device bluetooth on
  -B, --bluetooth-off   Turn device bluetooth off
  -p, --bluetooth-pair  Put device into bluetooth pairing mode
  -w mode, --wifi mode  Set WiFi mode (OFF, AP or STATION)
  --channel channel     Set WiFi channel
  --ssid ssid           Set WiFi SSID (NONE to delete)
  --psk psk             Set WiFi PSK (NONE to delete)
  --show-psk            Display stored WiFi PSK
  --ip ip               Set static WiFi IP address (NONE for DHCP)
  --nm nm               Set static WiFi network mask (NONE for DHCP)
  -D i, --display i     Set display intensity (0-255)
  -t s, --timeout s     Set display timeout in seconds, 0 to disable
  -R rotation, --rotation rotation
                        Set display rotation, valid values are 0 through 3
  --display-addr byte   Set display address as hex byte (00 - FF)
  --recondition-display
                        Start display reconditioning
  --np i                Set NeoPixel intensity (0-255)
  --freq Hz             Frequency in Hz for TNC mode
  --bw Hz               Bandwidth in Hz for TNC mode
  --txp dBm             TX power in dBm for TNC mode
  --sf factor           Spreading factor for TNC mode (7 - 12)
  --cr rate             Coding rate for TNC mode (5 - 8)
  -x, --ia-enable       Enable interference avoidance
  -X, --ia-disable      Disable interference avoidance
  -c, --config          Print device configuration
  --eeprom-backup       Backup EEPROM to file
  --eeprom-dump         Dump EEPROM to console
  --eeprom-wipe         Unlock and wipe EEPROM
  -P, --public          Display public part of signing key
  --trust-key hexbytes  Public key to trust for device verification
  --version             Print program version and exit
  -f, --flash           Flash firmware and bootstrap EEPROM
  -r, --rom             Bootstrap EEPROM without flashing firmware
  -k, --key             Generate a new signing key and exit
  -S, --sign            Display public part of signing key
  -H FIRMWARE_HASH, --firmware-hash FIRMWARE_HASH
                        Set installed firmware hash
  --platform platform   Platform specification for device bootstrap
  --product product     Product specification for device bootstrap
  --model model         Model code for device bootstrap
  --hwrev revision      Hardware revision for device bootstrap
"#;

fn print_help() {
    print!("{HELP}");
}

/// upstream's `RNS.log` as `rnodeconf` sets it up: `[HH:MM:SS] message`, in
/// local time.
fn log(message: &str) {
    println!("[{}] {message}", local_time("%H:%M:%S", now()));
    let _ = std::io::stdout().flush();
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Format `timestamp` in local time with `strftime`.
fn local_time(format: &str, timestamp: i64) -> String {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let time: libc::time_t = timestamp as libc::time_t;
    // SAFETY: localtime_r and strftime write only into the buffers given.
    unsafe {
        if libc::localtime_r(&time, &mut tm).is_null() {
            return String::new();
        }
        let format = std::ffi::CString::new(format).unwrap_or_default();
        let mut buf = [0u8; 64];
        let len = libc::strftime(
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            format.as_ptr(),
            &tm,
        );
        String::from_utf8_lossy(&buf[..len]).into_owned()
    }
}

/// A float as Python's `str()` writes it, for the values `rnodeconf`
/// prints.
fn py_float(value: f64) -> String {
    format!("{value:?}")
}

/// Python's `round(value, digits)`.
fn py_round(value: f64, digits: usize) -> f64 {
    format!("{value:.digits$}").parse().unwrap_or(value)
}

/// `RNS.hexrep`: lowercase hex bytes, colon-delimited.
fn hexrep(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// upstream `graceful_exit`.
fn graceful_exit(code: i32) -> ! {
    let _ = std::io::stdout().flush();
    exit(code)
}

fn config_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    home.join(".config").join("rnodeconf")
}

/// upstream creates its working directories on startup.
fn ensure_config_dirs() {
    let base = config_dir();
    for sub in [
        "",
        "update",
        "firmware",
        "extracted",
        "trusted_keys",
        "eeprom",
    ] {
        if let Err(e) = std::fs::create_dir_all(base.join(sub)) {
            println!(
                "No access to directory {}. This utility needs file system access to store firmware and data files. Cannot continue.",
                base.display()
            );
            println!("The contained exception was:");
            println!("{e}");
            graceful_exit(99);
        }
    }
}

fn open_serial(port: &str) -> std::io::Result<(std::fs::File, std::fs::File)> {
    let serial = rns_net::serial::SerialPort::open(&rns_net::serial::SerialConfig {
        path: port.to_string(),
        baud: RNODE_BAUDRATE,
        data_bits: 8,
        parity: rns_net::serial::Parity::None,
        stop_bits: 1,
    })?;
    let reader = serial.reader()?;
    let writer = serial.writer()?;
    // The duplicated descriptors keep the port open.
    drop(serial);
    Ok((reader, writer))
}

/// upstream's `input()` where only Enter is awaited.
fn wait_for_enter() {
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
}

fn prompt_int(prompt: &str) -> i64 {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        graceful_exit(0);
    }
    match line.trim().parse() {
        Ok(v) => v,
        Err(_) => {
            println!("\nInvalid number: {}", line.trim());
            graceful_exit(1);
        }
    }
}

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

    if let Some(option) = NOT_YET.iter().find(|o| args.has(o)) {
        println!("The {option} option is not implemented in this version of rnodeconf yet.");
        graceful_exit(1);
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

    if use_extracted && args.has("--update") && args.port.is_some() {
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
    if args.has("--public") {
        show_public_keys();
        graceful_exit(0);
    }
    if args.has("--key") {
        generate_keys();
        graceful_exit(0);
    }

    let Some(port) = args.port.clone() else {
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
    let mut fw_filename: Option<String> = None;
    if args.has("--flash") {
        // upstream keeps `--platform` as given, a string no platform code
        // equals, and flashes an AVR board when it is not given.
        let platform = match args.value("--platform") {
            Some(name) => firmware::FlashPlatform::Named(name.to_string()),
            None => firmware::FlashPlatform::Rom(rom::PLATFORM_AVR),
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
    if args.has("--update") {
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
        bootstrap_eeprom(&mut rnode, &args, &info, platform, &port, provision);
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

/// Python's `int()` on a string: surrounding whitespace, an optional sign,
/// and digits that single underscores may separate.
fn py_int(text: &str) -> Option<i64> {
    let text = text.trim();
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    let valid = !digits.is_empty()
        && !digits.starts_with('_')
        && !digits.ends_with('_')
        && !digits.contains("__")
        && digits.chars().all(|c| c.is_ascii_digit() || c == '_');
    if !valid {
        return None;
    }
    text.replace('_', "").parse().ok()
}

/// upstream `set_wifi_ip` and `set_wifi_nm`: a dotted quad as four bytes.
fn ip_bytes(text: &str) -> Result<[u8; 4], String> {
    let octets: Vec<&str> = text.split('.').collect();
    if octets.len() != 4 {
        return Err("Invalid IP address length".into());
    }
    let mut bytes = [0u8; 4];
    for (i, octet) in octets.iter().enumerate() {
        let value = py_int(octet).ok_or_else(|| {
            format!("Could not decode IP address octet: invalid literal for int() with base 10: '{octet}'")
        })?;
        if !(0..=255).contains(&value) {
            return Err("Could not decode IP address octet: Invalid IP octet value".into());
        }
        bytes[i] = value as u8;
    }
    Ok(bytes)
}

/// A WiFi string setting: UTF-8 with a closing NUL, or a lone NUL to
/// delete it.
fn wifi_string(value: Option<&str>) -> Vec<u8> {
    match value {
        None => vec![0x00],
        Some(text) => {
            let mut data = text.as_bytes().to_vec();
            data.push(0x00);
            data
        }
    }
}

/// The display, NeoPixel, interference avoidance, Bluetooth and WiFi
/// settings, in upstream's order. Each is sent to the device as given;
/// the device stores it.
fn configure_peripherals(rnode: &mut RNode, args: &Args) {
    let sent = |result: std::io::Result<()>| {
        if let Err(e) = result {
            println!("{e}");
            graceful_exit(1);
        }
    };
    let byte = |value: i64, max: i64| value.clamp(0, max) as u8;

    if let Some(intensity) = args.int("--display") {
        let intensity = byte(intensity, 255);
        log(&format!("Setting display intensity to {intensity}"));
        sent(rnode.send(
            kiss::CMD_DISP_INT,
            &[intensity],
            "sending display intensity command to device",
        ));
    }
    if let Some(timeout) = args.int("--timeout") {
        let timeout = byte(timeout, 255);
        if timeout == 0 {
            log("Disabling display blanking");
        } else {
            log(&format!("Setting display timeout to {timeout}"));
        }
        sent(rnode.send(
            kiss::CMD_DISP_BLNK,
            &[timeout],
            "sending display blanking timeout command to device",
        ));
    }
    if let Some(rotation) = args.int("--rotation") {
        let rotation = byte(rotation, 3);
        log(&format!("Setting display rotation to {rotation}"));
        sent(rnode.send(
            kiss::CMD_DISP_ROT,
            &[rotation],
            "sending display rotation command to device",
        ));
    }
    if args.has("--recondition-display") {
        log("Starting display reconditioning");
        sent(rnode.send(
            kiss::CMD_DISP_RCND,
            &[0x01],
            "sending display recondition command to device",
        ));
    }
    for (option, disabled, message) in [
        ("--ia-enable", 0x00, "Enabling interference avoidance"),
        ("--ia-disable", 0x01, "Disabling interference avoidance"),
    ] {
        if args.has(option) {
            log(message);
            sent(rnode.send(
                kiss::CMD_DIS_IA,
                &[disabled],
                "sending interference avoidance configuration command to device",
            ));
        }
    }
    if let Some(intensity) = args.int("--np") {
        let intensity = byte(intensity, 255);
        log(&format!("Setting NeoPixel intensity to {intensity}"));
        sent(rnode.send(
            kiss::CMD_NP_INT,
            &[intensity],
            "sending NeoPixel intensity command to device",
        ));
    }
    if let Some(address) = args.value("--display-addr") {
        let address = address.strip_prefix("0x").unwrap_or(address);
        match signature::unhex(address).as_deref() {
            Some([address]) => {
                log(&format!("Setting display address to {address:02x}"));
                sent(rnode.send(
                    kiss::CMD_DISP_ADR,
                    &[*address],
                    "sending display address command to device",
                ));
                let _ = rnode.hard_reset();
                graceful_exit(0);
            }
            _ => log("Invalid display address specified"),
        }
    }

    for (option, control, message) in [
        ("--bluetooth-on", 0x01, "Enabling Bluetooth..."),
        ("--bluetooth-off", 0x00, "Disabling Bluetooth..."),
        (
            "--bluetooth-pair",
            0x02,
            "Putting device into Bluetooth pairing mode. Press enter to exit when done.",
        ),
    ] {
        if args.has(option) {
            log(message);
            sent(rnode.send(
                kiss::CMD_BT_CTRL,
                &[control],
                "sending bluetooth command to device",
            ));
            if control == 0x02 {
                let mut line = String::new();
                let _ = std::io::stdin().lock().read_line(&mut line);
            }
            sent(rnode.leave());
        }
    }

    // A WiFi setting the device refuses ends the run, as upstream's does.
    let refused = |what: &str, error: String| -> ! {
        println!("Could not set WiFi {what}: {error}");
        graceful_exit(0);
    };
    if let Some(channel) = args.value("--channel").filter(|v| !v.is_empty()) {
        log(&format!("Setting WiFi channel to {channel}"));
        match py_int(channel).filter(|ch| (1..=14).contains(ch)) {
            Some(ch) => sent(rnode.send(
                kiss::CMD_WIFI_CHN,
                &[ch as u8],
                "sending wifi channel to device",
            )),
            None => refused("channel", "Invalid WiFi channel".into()),
        }
    }
    if let Some(ssid) = args.value("--ssid").filter(|v| !v.is_empty()) {
        let ssid = if ssid.to_lowercase() == "none" {
            log("Deleting WiFi SSID");
            None
        } else {
            log(&format!("Setting WiFi SSID to: {ssid}"));
            Some(ssid)
        };
        let data = wifi_string(ssid);
        if ssid.is_some() && data.len() > 33 {
            refused("SSID", "Invalid SSID length".into());
        }
        sent(rnode.send(kiss::CMD_WIFI_SSID, &data, "sending wifi SSID to device"));
    }
    if let Some(psk) = args.value("--psk").filter(|v| !v.is_empty()) {
        let psk = if psk.to_lowercase() == "none" {
            log("Deleting WiFi PSK");
            None
        } else {
            log("Setting WiFi PSK");
            Some(psk)
        };
        let data = wifi_string(psk);
        // Upstream counts the closing NUL, so a 7-character PSK passes.
        if psk.is_some() && !(8..=33).contains(&data.len()) {
            refused("PSK", "Invalid psk length".into());
        }
        sent(rnode.send(kiss::CMD_WIFI_PSK, &data, "sending wifi SSID to device"));
    }
    for (option, what, command, dhcp, set) in [
        (
            "--ip",
            "IP",
            kiss::CMD_WIFI_IP,
            "Setting WiFi IP to DHCP...",
            "Setting WiFi static IP to: ",
        ),
        (
            "--nm",
            "netmask",
            kiss::CMD_WIFI_NM,
            "Deleting WiFi static netmask configuration...",
            "Setting WiFi static netmask to: ",
        ),
    ] {
        let Some(value) = args.value(option).filter(|v| !v.is_empty()) else {
            continue;
        };
        let bytes = if value.to_lowercase() == "none" {
            log(dhcp);
            [0u8; 4]
        } else {
            log(&format!("{set}{value}"));
            match ip_bytes(value) {
                Ok(bytes) => bytes,
                Err(e) => refused(what, e),
            }
        };
        let described = if command == kiss::CMD_WIFI_IP {
            "sending wifi IP address to device"
        } else {
            "sending wifi netmask to device"
        };
        sent(rnode.send(command, &bytes, described));
    }
    if let Some(mode) = args.value("--wifi").filter(|v| !v.is_empty()) {
        let mode = mode.to_lowercase();
        let mode = if mode.starts_with("sta") {
            log("Setting WiFi to station mode");
            0x01
        } else if mode.starts_with("ap") {
            log("Setting WiFi to AP mode");
            0x02
        } else {
            log("Disabling WiFi...");
            0x00
        };
        sent(rnode.send(
            kiss::CMD_WIFI_MODE,
            &[mode],
            "sending wifi mode command to device",
        ));
    }
}

/// Open `port` and probe the device, as upstream does before each use:
/// the device, what it reported, and its platform (AVR when it does not
/// say).
fn connect(port: &str) -> (RNode, device::Reported, u8) {
    log(&format!("Opening serial port {port}..."));
    let (reader, writer) = match open_serial(port) {
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
    if let Err(e) = rnode.device_probe() {
        log("Serial port opened, but RNode did not respond. Is a valid firmware installed?");
        println!("{e}");
        graceful_exit(0);
    }
    let reported = rnode.reported();
    log("Device connected");
    log(&format!(
        "Current firmware version: {}",
        reported.version().unwrap_or_else(|| "None".into())
    ));
    let platform = match (reported.platform, reported.mcu) {
        (Some(platform), Some(_)) => platform,
        _ => rom::PLATFORM_AVR,
    };
    (rnode, reported, platform)
}

/// The firmware package for a provisioned device: its model's, or for a
/// homebrew model (0xFF) its board's.
fn firmware_for(
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
fn installed_firmware_hash(
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
fn run_flasher(call: Option<Vec<String>>) -> Result<i32, String> {
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
fn flash_firmware(
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

/// upstream's serial port menu: the detected ports, newest first, and the
/// one chosen by number, exiting when none is.
fn select_port() -> ports::PortInfo {
    let mut ports = ports::comports();
    ports.reverse();
    println!("Detected serial ports:");
    for (i, port) in ports.iter().enumerate() {
        println!(
            "  [{}] {} ({}, {})",
            i + 1,
            port.device,
            ports::py_str(&port.product),
            ports::py_str(&port.serial_number)
        );
    }
    print!("\nEnter the number of the serial port your device is connected to:\n? ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    match py_int(&line) {
        Some(n) if n >= 1 && (n as usize) <= ports.len() => ports.swap_remove(n as usize - 1),
        _ => {
            println!("That port does not exist, exiting now.");
            graceful_exit(0);
        }
    }
}

/// The parts of an ESP32 RNode's flash `-e` copies: what each is, where it
/// lies, how long it is, and the file it goes to.
const EXTRACTION_PARTS: &[(&str, &str, &str, &str)] = &[
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
fn extract_firmware(args: &Args) -> ! {
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

fn firmware_dir() -> PathBuf {
    config_dir().join("firmware")
}

/// Lowercase hex without delimiters.
fn hexstr(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// upstream `download_eeprom` with its `parse_eeprom`: read the EEPROM and
/// report its checksum and signature.
fn read_eeprom(rnode: &mut RNode, port: &str) -> (Vec<u8>, eeprom::DeviceInfo) {
    let image = match rnode.download_eeprom() {
        Ok(Some(image)) => image,
        _ => {
            log("Could not download EEPROM from device. Is a valid firmware installed?");
            graceful_exit(0);
        }
    };
    let keys = eeprom::known_keys(&config_dir(), &mut |m| log(m));
    let info = match eeprom::parse(&image, &keys) {
        Some(info) => info,
        None => {
            log("Invalid EEPROM data, could not parse device EEPROM.");
            eeprom::DeviceInfo::default()
        }
    };
    if image.get(rom::ADDR_INFO_LOCK as usize) == Some(&rom::INFO_LOCK_BYTE) {
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
fn trust_key(hex: &str) {
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
fn show_public_keys() {
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
fn generate_keys() {
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
        log("EEPROM Signing key already exists, not overwriting!");
        log("Manually delete this key to create a new one.");
    } else {
        if let Err(e) = std::fs::write(&signing_key, &private) {
            log(&format!("Could not write {}: {e}", signing_key.display()));
            graceful_exit(1);
        }
        log("Wrote signing key");
        log("Public key:");
        log(&hexstr(
            &keys::signing_public_key(&private).unwrap_or_default(),
        ));
    }
}

/// `--eeprom-backup`. Upstream joins its EEPROM directory and the file name
/// without a separator, so its backups land beside the directory; these go
/// inside it.
fn backup_eeprom(image: &[u8]) {
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

/// A two-digit hex code from `--product` or `--model`.
fn hex_code(value: Option<&str>) -> Option<u8> {
    let value = value?;
    if value.len() != 2 {
        return None;
    }
    u8::from_str_radix(value, 16).ok()
}

/// `-r`: write a provisioning record to an unprovisioned device's EEPROM,
/// signed with the local EEPROM signing key, then read it back.
fn bootstrap_eeprom(
    rnode: &mut RNode,
    args: &Args,
    info: &eeprom::DeviceInfo,
    platform: u8,
    port: &str,
    provision: Option<(&firmware::Firmware, &str)>,
) {
    use std::time::Duration;
    let pause = |ms: u64| std::thread::sleep(Duration::from_millis(ms));

    if info.provisioned || info.signature_valid {
        log("EEPROM bootstrap was requested, but a valid EEPROM was already present.");
        log("No changes are being made.");
        graceful_exit(0);
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
    let product = hex_code(args.value("--product")).unwrap_or(rom::PRODUCT_RNODE);
    let model = hex_code(args.value("--model"));
    let hwrev = args
        .int("--hwrev")
        .filter(|v| *v > 0 && *v < 256)
        .map(|v| v as u8);
    let (Some(model), Some(hwrev)) = (model, hwrev) else {
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

fn print_unverified_warning(port: &str) {
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

/// `-i`.
fn show_info(info: &eeprom::DeviceInfo, reported: &device::Reported) {
    let timestamp = u32::from_be_bytes(info.made) as i64;
    let timestring = local_time("%Y-%m-%d %H:%M:%S", timestamp);
    let sigstring = if info.signature_valid {
        if info.locally_signed {
            "Validated - Local signature".to_string()
        } else {
            format!(
                "Genuine board, vendor is {}",
                info.vendor.clone().unwrap_or_default()
            )
        }
    } else {
        "Unverified".to_string()
    };
    let board_string = reported
        .board
        .map_or(String::new(), |board| format!(":{board:02x}"));
    let model = rom::model(info.model);
    log("");
    log("Device info:");
    log(&format!(
        "\tProduct            : {} {} ({:02x}:{:02x}{board_string})",
        rom::product_name(info.product).unwrap_or("Unknown product"),
        model.as_ref().map_or("(Unknown model)", |m| m.band),
        info.product,
        info.model
    ));
    log(&format!("\tDevice signature   : {sigstring}"));
    log(&format!(
        "\tFirmware version   : {}",
        reported.version().unwrap_or_else(|| "None".into())
    ));
    log(&format!("\tHardware revision  : {}", info.hw_rev));
    log(&format!(
        "\tSerial number      : {}",
        hexrep(&info.serialno)
    ));
    log(&format!(
        "\tModem chip         : {}",
        model.as_ref().map_or("Unknown", |m| m.modem)
    ));
    log(&format!(
        "\tFrequency range    : {} MHz - {} MHz",
        py_float(info.min_freq as f64 / 1e6),
        py_float(info.max_freq as f64 / 1e6)
    ));
    log(&format!("\tMax TX power       : {} dBm", info.max_output));
    log(&format!("\tManufactured       : {timestring}"));
    match info.tnc {
        Some(tnc) => {
            let bitrate = tnc.sf as f64
                * ((4.0 / tnc.cr as f64)
                    / (2f64.powi(tnc.sf as i32) / (tnc.bandwidth as f64 / 1000.0)))
                * 1000.0;
            let txp_mw = py_round(10f64.powf(tnc.txpower as f64 / 10.0), 3);
            log("");
            log("\tDevice mode        : TNC");
            log(&format!(
                "\t  Frequency        : {} MHz",
                py_float(tnc.frequency as f64 / 1_000_000.0)
            ));
            log(&format!(
                "\t  Bandwidth        : {} KHz",
                py_float(tnc.bandwidth as f64 / 1000.0)
            ));
            log(&format!(
                "\t  TX power         : {} dBm ({} mW)",
                tnc.txpower,
                py_float(txp_mw)
            ));
            log(&format!("\t  Spreading factor : {}", tnc.sf));
            log(&format!("\t  Coding rate      : {}", tnc.cr));
            log(&format!(
                "\t  On-air bitrate   : {} kbps",
                py_float(py_round(bitrate / 1000.0, 2))
            ));
        }
        None => log("\tDevice mode        : Normal (host-controlled)"),
    }
    println!();
}

/// `-c`.
fn show_config(rnode: &mut RNode, image: &[u8], _platform: u8, show_psk: bool) {
    let cfg_sector = rnode.download_cfg_sector().ok().flatten();
    let at = |addr: u8| image.get(addr as usize).copied().unwrap_or(0xFF);
    let ec_bt = at(rom::ADDR_CONF_BT);
    let ec_dint = at(rom::ADDR_CONF_DINT);
    let ec_dadr = at(rom::ADDR_CONF_DADR);
    let ec_dblk = at(rom::ADDR_CONF_DBLK);
    let ec_drot = at(rom::ADDR_CONF_DROT);
    let ec_pset = at(rom::ADDR_CONF_PSET);
    let ec_pint = at(rom::ADDR_CONF_PINT);
    let ec_bset = at(rom::ADDR_CONF_BSET);
    let ec_dia = at(rom::ADDR_CONF_DIA);
    let ec_wifi = at(rom::ADDR_CONF_WIFI);
    let mut ec_wchn = at(rom::ADDR_CONF_WCHN);
    let mut ec_ssid: Option<String> = None;
    let mut ec_psk: Option<String> = None;
    let mut ec_ip: Option<String> = None;
    let mut ec_nm: Option<String> = None;
    if !(1..=14).contains(&ec_wchn) {
        ec_wchn = 1;
    }
    if let Some(sector) = cfg_sector.as_ref() {
        let text = |start: u8| -> Vec<u8> {
            let mut bytes = Vec::new();
            for i in 0..32 {
                let byte = sector.get(start as usize + i).copied().unwrap_or(0);
                let byte = if byte == 0xFF { 0 } else { byte };
                if byte == 0 {
                    break;
                }
                bytes.push(byte);
            }
            bytes
        };
        let address = |start: u8| -> Option<String> {
            let b = sector.get(start as usize..start as usize + 4)?;
            let ip = format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
            (ip != "255.255.255.255" && ip != "0.0.0.0").then_some(ip)
        };
        match String::from_utf8(text(rom::ADDR_CONF_SSID)) {
            Ok(ssid) => ec_ssid = Some(ssid),
            Err(_) => println!("Error: Could not decode WiFi SSID read from device"),
        }
        let psk_bytes = text(rom::ADDR_CONF_PSK);
        ec_ip = address(rom::ADDR_CONF_IP);
        ec_nm = address(rom::ADDR_CONF_NM);
        if ec_wifi == 0x02 {
            ec_ip = Some("10.0.0.1".into());
            ec_nm = Some("255.255.255.0".into());
        }
        match String::from_utf8(psk_bytes) {
            Ok(psk) => ec_psk = Some(psk),
            Err(_) => println!("Error: Could not decode WiFi PSK read from device"),
        }
        if !show_psk {
            if let Some(psk) = ec_psk.as_mut().filter(|psk| !psk.is_empty()) {
                *psk = "*".repeat(psk.chars().count());
            }
        }
    }
    let set = |value: &Option<String>| value.as_ref().filter(|v| !v.is_empty()).cloned();

    println!("\nDevice configuration:");
    if ec_bt == 0x73 {
        println!("  Bluetooth              : Enabled");
    } else {
        println!("  Bluetooth              : Disabled");
    }
    match ec_wifi {
        0x01 => println!("  WiFi                   : Enabled (Station)"),
        0x02 => println!("  WiFi                   : Enabled (AP)"),
        _ => println!("  WiFi                   : Disabled"),
    }
    if ec_wifi == 0x01 || ec_wifi == 0x02 {
        println!("    Channel              : {ec_wchn}");
        match set(&ec_ssid) {
            None => println!("    SSID                 : Not set"),
            Some(ssid) => println!("    SSID                 : {ssid}"),
        }
        match set(&ec_psk) {
            None => println!("    PSK                  : Not set"),
            Some(psk) => println!("    PSK                  : {psk}"),
        }
        match &ec_ip {
            None => println!("    IP Address           : DHCP"),
            Some(ip) => println!("    IP Address           : {ip}"),
        }
        if let (Some(_), Some(nm)) = (&ec_ip, &ec_nm) {
            println!("    Network Mask         : {nm}");
        }
    }
    if ec_dia == 0x00 {
        println!("  Interference avoidance : Enabled");
    } else {
        println!("  Interference avoidance : Disabled");
    }
    println!("  Display brightness     : {ec_dint}");
    if ec_dadr == 0xFF {
        println!("  Display address        : Default");
    } else {
        println!("  Display address        : {ec_dadr:02x}");
    }
    if ec_bset == 0x73 && ec_dblk != 0x00 {
        println!("  Display blanking       : {ec_dblk}s");
    } else {
        println!("  Display blanking       : Disabled");
    }
    if ec_drot != 0xFF {
        let rotation = match ec_drot {
            0x00 => "Landscape",
            0x01 => "Portrait",
            0x02 => "Landscape 180",
            0x03 => "Portrait 180",
            _ => "Unknown",
        };
        println!("  Display rotation       : {rotation}");
    } else {
        println!("  Display rotation       : Default");
    }
    if ec_pset == 0x73 {
        println!("  Neopixel Intensity     : {ec_pint}");
    }
    println!();
}

/// `-T`: store the TNC radio parameters and switch to TNC mode, asking for
/// the ones not given.
fn set_tnc_mode(rnode: &mut RNode, args: &Args, platform: u8) {
    let freq = args.int("--freq").filter(|v| *v != 0);
    let bw = args.int("--bw").filter(|v| *v != 0);
    let txp = args.int("--txp");
    let sf = args.int("--sf").filter(|v| *v != 0);
    let cr = args.int("--cr").filter(|v| *v != 0);
    if !(freq.is_some()
        && bw.is_some()
        && txp.is_some_and(|v| v != 0)
        && sf.is_some()
        && cr.is_some())
    {
        log("Please input startup configuration:");
    }
    println!();
    let frequency = freq.unwrap_or_else(|| prompt_int("Frequency in Hz:\t"));
    let bandwidth = bw.unwrap_or_else(|| prompt_int("Bandwidth in Hz:\t"));
    let txpower = match txp {
        Some(v) if (0..=17).contains(&v) => v,
        _ => prompt_int("TX Power in dBm:\t"),
    };
    let sf = sf.unwrap_or_else(|| prompt_int("Spreading factor:\t"));
    let cr = cr.unwrap_or_else(|| prompt_int("Coding rate:\t\t"));
    println!();
    let radio = RadioConfig {
        frequency: frequency as u32,
        bandwidth: bandwidth as u32,
        txpower: txpower as u8,
        sf: sf as u8,
        cr: cr as u8,
    };
    if rnode.init_radio(&radio).is_err() {
        graceful_exit(1);
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    if rnode.set_tnc_mode(platform).is_err() {
        graceful_exit(1);
    }
    log("Device set to TNC operating mode");
    std::thread::sleep(std::time::Duration::from_secs(1));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_number_formatting() {
        assert_eq!(py_float(410000000.0 / 1e6), "410.0");
        assert_eq!(py_float(867200000.0 / 1_000_000.0), "867.2");
        assert_eq!(py_float(125000.0 / 1000.0), "125.0");
        assert_eq!(py_float(py_round(10f64.powf(1.4), 3)), "25.119");
        assert_eq!(py_float(py_round(5.46875, 2)), "5.47");
        assert_eq!(hexrep(&[0xde, 0xad, 0x01]), "de:ad:01");
    }
}
