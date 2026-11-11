//! `rnodeconf`: configure RNode devices, compatible with upstream
//! Reticulum's `rnodeconf` utility.
//!
//! Implemented so far: detecting a device, showing its information (`-i`)
//! and configuration (`-c`), and switching between TNC and normal mode
//! (`-T`, `-N`) with the TNC radio parameters.

mod device;
mod eeprom;
mod keys;
mod kiss;
mod rom;
mod signature;

use std::io::{BufRead, Write};
use std::path::PathBuf;
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
const NOT_YET: &[&str] = &[
    "--autoinstall",
    "--update",
    "--force-update",
    "--fw-version",
    "--fw-url",
    "--nocheck",
    "--extract",
    "--use-extracted",
    "--clear-cache",
    "--baud-flash",
    "--bluetooth-on",
    "--bluetooth-off",
    "--bluetooth-pair",
    "--wifi",
    "--channel",
    "--ssid",
    "--psk",
    "--ip",
    "--nm",
    "--display",
    "--timeout",
    "--rotation",
    "--display-addr",
    "--recondition-display",
    "--np",
    "--ia-enable",
    "--ia-disable",
    "--flash",
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

fn print_help() {
    println!(
        "\nusage: rnodeconf [-h] [-i] [-a] [-u] [-U] [--fw-version version] [--fw-url url]\n                 [--nocheck] [-e] [-E] [-C] [--baud-flash baud_flash] [-N] [-T]\n                 [-b] [-B] [-p] [-w mode] [--channel channel] [--ssid ssid]\n                 [--psk psk] [--show-psk] [--ip ip] [--nm nm] [-D i] [-t s]\n                 [-R rotation] [--display-addr byte] [--recondition-display]\n                 [--np i] [--freq Hz] [--bw Hz] [--txp dBm] [--sf factor]\n                 [--cr rate] [-x] [-X] [-c] [--eeprom-backup] [--eeprom-dump]\n                 [--eeprom-wipe] [-P] [--trust-key hexbytes] [--version] [-f]\n                 [-r] [-k] [-S] [-H FIRMWARE_HASH] [--platform platform]\n                 [--product product] [--model model] [--hwrev revision]\n                 [port]\n\nRNode Configuration and firmware utility. This program allows you to change\nvarious settings and startup modes of RNode. It can also install, flash and\nupdate the firmware on supported devices.\n\npositional arguments:\n  port                  serial port where RNode is attached\n\noptions:\n  -h, --help            show this help message and exit\n  -i, --info            Show device info\n  -N, --normal          Switch device to normal mode\n  -T, --tnc             Switch device to TNC mode\n  --freq Hz             Frequency in Hz for TNC mode\n  --bw Hz               Bandwidth in Hz for TNC mode\n  --txp dBm             TX power in dBm for TNC mode\n  --sf factor           Spreading factor for TNC mode (7 - 12)\n  --cr rate             Coding rate for TNC mode (5 - 8)\n  -c, --config          Print device configuration\n  --show-psk            Display stored WiFi PSK\n  --version             Print program version and exit\n\nFirmware installation, EEPROM, key, Bluetooth, WiFi, display and\ninterference avoidance options are not implemented in this version yet.\n"
    );
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

    if let Some(key) = args.value("--trust-key") {
        trust_key(key);
        graceful_exit(0);
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
        print_help();
        graceful_exit(0);
    };

    log(&format!("Opening serial port {port}..."));
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
    // upstream assumes an AVR board when it does not say.
    let (platform, _mcu) = match (reported.platform, reported.mcu) {
        (Some(platform), Some(mcu)) => (platform, mcu),
        _ => (rom::PLATFORM_AVR, rom::MCU_1284P),
    };

    if args.has("--eeprom-wipe") {
        log("WARNING: EEPROM is being wiped! Power down device NOW if you do not want this!");
        let _ = rnode.wipe_eeprom(reported.board);
        if platform != rom::PLATFORM_NRF52 {
            let _ = rnode.hard_reset();
        }
        graceful_exit(0);
    }

    log("Reading EEPROM...");
    let (image, info) = read_eeprom(&mut rnode, &port);

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

    if args.has("--info") {
        if info.provisioned {
            show_info(&info, &reported);
            let _ = rnode.leave();
            graceful_exit(0);
        } else {
            log("EEPROM is invalid, no further information available");
            graceful_exit(0);
        }
    }

    if args.has("--rom") {
        bootstrap_eeprom(&mut rnode, &args, &info, platform, &port);
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
