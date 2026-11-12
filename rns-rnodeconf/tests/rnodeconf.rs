//! `rnodeconf` against a fake RNode on a pseudo-terminal.
//!
//! The Python comparisons run upstream's `rnodeconf` against the same fake
//! device and require the same output (timestamps aside) and the same frames
//! sent to the device. They need Python Reticulum on `PYTHONPATH`, with
//! `pyserial` and `cryptography`, and are ignored by default.

#[path = "support/fake_rnode.rs"]
mod fake_rnode;

use std::path::Path;
use std::process::Command;

use fake_rnode::*;

const PLATFORM_ESP32: u8 = 0x80;
const MCU_ESP32: u8 = 0x81;
const BOARD_LORA32_V2_1: u8 = 0x37;
/// 2023-11-14 22:13:20 UTC.
const MADE: u32 = 1_700_000_000;

fn device(eeprom: Vec<u8>) -> Device {
    let mut cfg_sector = vec![0xFFu8; 296];
    cfg_sector[0x00..0x08].copy_from_slice(b"meshwifi");
    cfg_sector[0x08] = 0x00;
    cfg_sector[0x21..0x27].copy_from_slice(b"s3cret");
    cfg_sector[0x27] = 0x00;
    cfg_sector[0x42..0x46].copy_from_slice(&[192, 168, 1, 50]);
    cfg_sector[0x46..0x4A].copy_from_slice(&[255, 255, 255, 0]);
    Device {
        eeprom,
        cfg_sector,
        version: (1, 82),
        platform: PLATFORM_ESP32,
        mcu: MCU_ESP32,
        board: BOARD_LORA32_V2_1,
    }
}

/// Lines of output with their `[HH:MM:SS] ` prefixes removed.
fn lines(stdout: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .map(|line| {
            let bytes = line.as_bytes();
            if bytes.len() >= 11 && bytes[0] == b'[' && bytes[9] == b']' && bytes[10] == b' ' {
                line[11..].to_string()
            } else {
                line.to_string()
            }
        })
        .collect()
}

/// Run a command, giving it `input` on stdin when there is some.
fn run(mut command: Command, input: Option<&str>) -> std::process::Output {
    let Some(input) = input else {
        return command.output().expect("run");
    };
    use std::io::Write;
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().expect("wait")
}

fn rust_command(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rnodeconf"));
    command.args(args).env("HOME", home).env("TZ", "UTC");
    command
}

fn python_command(home: &Path, args: &[&str]) -> Command {
    let mut argv = vec!["rnodeconf".to_string()];
    argv.extend(args.iter().map(|a| a.to_string()));
    let mut command = Command::new("python3");
    command
        .arg("-c")
        .arg(format!(
            "import sys; sys.argv={argv:?}; from RNS.Utilities import rnodeconf; rnodeconf.main()"
        ))
        .env("HOME", home)
        .env("TZ", "UTC")
        .env("PYTHONUNBUFFERED", "1");
    command
}

fn rust_rnodeconf(home: &Path, args: &[&str]) -> std::process::Output {
    run(rust_command(home, args), None)
}

fn python_rnodeconf(home: &Path, args: &[&str]) -> std::process::Output {
    run(python_command(home, args), None)
}

/// The `RNS.__version__` of the Python on `PYTHONPATH`.
fn python_version() -> (u32, u32, u32) {
    let out = Command::new("python3")
        .args(["-c", "import RNS; print(RNS.__version__)"])
        .output()
        .expect("run python");
    let v: Vec<u32> = String::from_utf8_lossy(&out.stdout)
        .trim()
        .split('.')
        .filter_map(|p| p.parse().ok())
        .collect();
    (
        v.first().copied().unwrap_or(0),
        v.get(1).copied().unwrap_or(0),
        v.get(2).copied().unwrap_or(0),
    )
}

fn signed_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    let firmware = home.path().join(".config/rnodeconf/firmware");
    std::fs::create_dir_all(&firmware).unwrap();
    let key = include_str!("vectors/pss_private_key_pkcs8.hex");
    let key: Vec<u8> = (0..key.trim().len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&key.trim()[i..i + 2], 16).unwrap())
        .collect();
    std::fs::write(firmware.join("signing.key"), key).unwrap();
    home
}

fn signed_tnc_eeprom() -> Vec<u8> {
    let mut e = eeprom(
        0x03,
        0xA9,
        3,
        [1, 2, 3, 4],
        MADE,
        Some((8, 5, 14, 867_200_000, 125_000)),
    );
    let sig = include_str!("vectors/device_signature.hex").trim();
    for i in 0..128 {
        e[0x1B + i] = u8::from_str_radix(&sig[i * 2..i * 2 + 2], 16).unwrap();
    }
    e
}

#[test]
fn info_shows_an_unverified_device_in_normal_mode() {
    let fake = FakeRNode::start(device(eeprom(
        0xE0,
        0xE9,
        2,
        [0xde, 0xad, 0xbe, 0xef],
        MADE,
        None,
    )));
    let home = tempfile::tempdir().unwrap();
    let out = rust_rnodeconf(home.path(), &["-i", &fake.path]);
    assert!(out.status.success());
    let lines = lines(&out.stdout);
    for expected in [
        "Device connected",
        "Current firmware version: 1.82",
        "EEPROM checksum correct",
        "Device signature validation failed",
        "     WARNING! This device is NOT verifiable and should NOT be trusted.",
        "\tProduct            : LilyGO T-Beam 850 - 950 MHz (e0:e9:37)",
        "\tDevice signature   : Unverified",
        "\tFirmware version   : 1.82",
        "\tHardware revision  : 2",
        "\tSerial number      : de:ad:be:ef",
        "\tModem chip         : SX1276",
        "\tFrequency range    : 850.0 MHz - 950.0 MHz",
        "\tMax TX power       : 17 dBm",
        "\tManufactured       : 2023-11-14 22:13:20",
        "\tDevice mode        : Normal (host-controlled)",
    ] {
        assert!(
            lines.iter().any(|l| l == expected),
            "missing {expected:?} in {lines:#?}"
        );
    }
    // It asked for the device's identity and EEPROM, then left.
    let commands: Vec<u8> = fake.received().iter().map(|f| f[0]).collect();
    assert!(commands.starts_with(&[CMD_DETECT, CMD_FW_VERSION, CMD_PLATFORM, CMD_MCU, CMD_BOARD]));
    assert!(commands.contains(&CMD_ROM_READ));
    assert_eq!(commands.last(), Some(&CMD_LEAVE));
}

#[test]
fn info_validates_a_locally_signed_tnc_device() {
    let fake = FakeRNode::start(device(signed_tnc_eeprom()));
    let home = signed_home();
    let out = rust_rnodeconf(home.path(), &["-i", &fake.path]);
    let lines = lines(&out.stdout);
    for expected in [
        "Device signature validated",
        "\tProduct            : RNode 820 - 1020 MHz (03:a9:37)",
        "\tDevice signature   : Validated - Local signature",
        "\tDevice mode        : TNC",
        "\t  Frequency        : 867.2 MHz",
        "\t  Bandwidth        : 125.0 KHz",
        "\t  TX power         : 14 dBm (25.119 mW)",
        "\t  Spreading factor : 8",
        "\t  Coding rate      : 5",
        "\t  On-air bitrate   : 3.12 kbps",
    ] {
        assert!(
            lines.iter().any(|l| l == expected),
            "missing {expected:?} in {lines:#?}"
        );
    }
    assert!(!lines.iter().any(|l| l.contains("NOT verifiable")));
}

#[test]
fn config_shows_the_device_configuration() {
    let mut e = eeprom(0xE0, 0xE9, 2, [1, 1, 1, 1], MADE, None);
    e[0xB0] = 0x73; // Bluetooth on
    e[0xBA] = 0x01; // WiFi station
    e[0xBB] = 6; // channel
    e[0xB2] = 180; // display intensity
    e[0xB9] = 0x00; // interference avoidance on
    let fake = FakeRNode::start(device(e));
    let home = tempfile::tempdir().unwrap();
    let out = rust_rnodeconf(home.path(), &["-c", &fake.path]);
    let text = String::from_utf8_lossy(&out.stdout);
    let expected = "\nDevice configuration:\n  Bluetooth              : Enabled\n  WiFi                   : Enabled (Station)\n    Channel              : 6\n    SSID                 : meshwifi\n    PSK                  : ******\n    IP Address           : 192.168.1.50\n    Network Mask         : 255.255.255.0\n  Interference avoidance : Enabled\n  Display brightness     : 180\n  Display address        : Default\n  Display blanking       : Disabled\n  Display rotation       : Default\n\n";
    assert!(text.contains(expected), "{text}");
}

#[test]
fn tnc_mode_stores_the_radio_parameters() {
    let fake = FakeRNode::start(device(eeprom(0xE0, 0xE9, 2, [1, 1, 1, 1], MADE, None)));
    let home = tempfile::tempdir().unwrap();
    let out = rust_rnodeconf(
        home.path(),
        &[
            "-T",
            "--freq",
            "868000000",
            "--bw",
            "125000",
            "--txp",
            "14",
            "--sf",
            "8",
            "--cr",
            "5",
            &fake.path,
        ],
    );
    assert!(lines(&out.stdout)
        .iter()
        .any(|l| l == "Device set to TNC operating mode"));
    let frames = fake.received();
    let after_eeprom: Vec<Vec<u8>> = frames
        .iter()
        .skip_while(|f| f[0] != CMD_ROM_READ)
        .skip(1)
        .cloned()
        .collect();
    assert_eq!(
        after_eeprom,
        vec![
            [vec![CMD_FREQUENCY], 868_000_000u32.to_be_bytes().to_vec()].concat(),
            [vec![CMD_BANDWIDTH], 125_000u32.to_be_bytes().to_vec()].concat(),
            vec![CMD_TXPOWER, 14],
            vec![CMD_SF, 8],
            vec![CMD_CR, 5],
            vec![CMD_RADIO_STATE, 0x01],
            vec![CMD_CONF_SAVE, 0x00],
            // An ESP32 board restarts into TNC mode.
            vec![CMD_RESET, 0xf8],
        ]
    );
}

#[test]
fn normal_mode_deletes_the_tnc_configuration() {
    let fake = FakeRNode::start(device(eeprom(0xE0, 0xE9, 2, [1, 1, 1, 1], MADE, None)));
    let home = tempfile::tempdir().unwrap();
    let out = rust_rnodeconf(home.path(), &["-N", &fake.path]);
    assert!(lines(&out.stdout)
        .iter()
        .any(|l| l == "Device set to normal (host-controlled) operating mode"));
    assert_eq!(fake.received().last(), Some(&vec![CMD_CONF_DELETE, 0x00]));
}

/// Output with timestamps, upstream's closing exit-code line and the port
/// path normalized away.
fn normalize(out: &[u8], path: &str) -> Vec<String> {
    lines(out)
        .into_iter()
        .filter(|l| !l.starts_with("Exiting: Code"))
        .map(|l| l.replace(path, "PORT"))
        .collect()
}

/// Run upstream's `rnodeconf` and ours, each against its own fake device
/// and in its own home.
fn run_both(
    device: Device,
    python_home: &Path,
    rust_home: &Path,
    args: &[&str],
) -> (Vec<String>, FakeRNode, Vec<String>, FakeRNode) {
    run_both_with_input(device, python_home, rust_home, args, None)
}

fn run_both_with_input(
    device: Device,
    python_home: &Path,
    rust_home: &Path,
    args: &[&str],
    input: Option<&str>,
) -> (Vec<String>, FakeRNode, Vec<String>, FakeRNode) {
    let python_fake = FakeRNode::start(device.clone());
    let mut python_args = args.to_vec();
    python_args.push(&python_fake.path);
    let python = run(python_command(python_home, &python_args), input);
    assert!(
        python.status.success(),
        "python rnodeconf failed: {}",
        String::from_utf8_lossy(&python.stderr)
    );

    let rust_fake = FakeRNode::start(device);
    let mut rust_args = args.to_vec();
    rust_args.push(&rust_fake.path);
    let rust = run(rust_command(rust_home, &rust_args), input);
    (
        normalize(&python.stdout, &python_fake.path),
        python_fake,
        normalize(&rust.stdout, &rust_fake.path),
        rust_fake,
    )
}

/// The same scenario through upstream's `rnodeconf` and ours: the same
/// output and the same frames sent to the device.
fn compare_with_python(eeprom: Vec<u8>, home: &Path, args: &[&str]) {
    compare_device_with_python(device(eeprom), home, args);
}

fn compare_device_with_python(device: Device, home: &Path, args: &[&str]) {
    let (python, python_fake, rust, rust_fake) = run_both(device, home, home, args);
    assert_eq!(rust, python);
    assert_eq!(rust_fake.received(), python_fake.received());
}

#[test]
#[ignore = "requires Python Reticulum with pyserial and cryptography"]
fn python_comparison_info_unverified() {
    let home = tempfile::tempdir().unwrap();
    compare_with_python(
        eeprom(0xE0, 0xE9, 2, [0xde, 0xad, 0xbe, 0xef], MADE, None),
        home.path(),
        &["-i"],
    );
}

#[test]
#[ignore = "requires Python Reticulum with pyserial and cryptography"]
fn python_comparison_info_signed_tnc() {
    let home = signed_home();
    compare_with_python(signed_tnc_eeprom(), home.path(), &["-i"]);
}

#[test]
#[ignore = "requires Python Reticulum with pyserial and cryptography"]
fn python_comparison_config() {
    // Before upstream ebd9b862 (released in 1.5.0) `-c` printed both
    // "Enabled (Station)" and "Disabled" for a station-mode device.
    if python_version() < (1, 5, 0) {
        eprintln!("Python rnodeconf predates the -c summary fix; skipping");
        return;
    }
    let mut e = eeprom(0xE0, 0xE9, 2, [1, 1, 1, 1], MADE, None);
    e[0xB0] = 0x73;
    e[0xBA] = 0x01;
    e[0xBB] = 6;
    e[0xB2] = 180;
    e[0xB9] = 0x00;
    let home = tempfile::tempdir().unwrap();
    compare_with_python(e, home.path(), &["-c"]);
}

#[test]
#[ignore = "requires Python Reticulum with pyserial and cryptography"]
fn python_comparison_tnc_and_normal() {
    let home = tempfile::tempdir().unwrap();
    let e = eeprom(0xE0, 0xE9, 2, [1, 1, 1, 1], MADE, None);
    compare_with_python(
        e.clone(),
        home.path(),
        &[
            "-T",
            "--freq",
            "868000000",
            "--bw",
            "125000",
            "--txp",
            "14",
            "--sf",
            "8",
            "--cr",
            "5",
        ],
    );
    compare_with_python(e, home.path(), &["-N"]);
}

// Stage 2: keys, EEPROM maintenance, bootstrap and firmware hashes.

const PLATFORM_AVR: u8 = 0x90;
const MCU_1284P: u8 = 0x91;

/// An AVR board: bootstrapping it skips the ESP32 and NRF52 reset waits.
fn avr_device(eeprom: Vec<u8>) -> Device {
    Device {
        platform: PLATFORM_AVR,
        mcu: MCU_1284P,
        board: 0x00,
        ..device(eeprom)
    }
}

fn blank_eeprom() -> Vec<u8> {
    vec![0xFF; 296]
}

fn unhex(text: &str) -> Vec<u8> {
    let text = text.trim();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn firmware(home: &Path) -> std::path::PathBuf {
    home.join(".config/rnodeconf/firmware")
}

/// A home with both signing keys, made by our `-k`.
fn keyed_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    let out = rust_rnodeconf(home.path(), &["-k"]);
    assert!(out.status.success());
    home
}

fn copy_home(from: &Path) -> tempfile::TempDir {
    let to = tempfile::tempdir().unwrap();
    let firmware_to = firmware(to.path());
    std::fs::create_dir_all(&firmware_to).unwrap();
    for entry in std::fs::read_dir(firmware(from)).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), firmware_to.join(entry.file_name())).unwrap();
        }
    }
    to
}

fn has_line(lines: &[String], expected: &str) -> bool {
    lines.iter().any(|l| l == expected)
}

#[test]
fn trust_key_stores_the_key_under_its_hash() {
    let home = tempfile::tempdir().unwrap();
    let key = include_str!("vectors/pss_public_key.hex").trim();
    let out = rust_rnodeconf(home.path(), &["--trust-key", key]);
    assert!(out.status.success());
    let hash: String = rns_crypto::sha256::sha256(&unhex(key))
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(has_line(
        &lines(&out.stdout),
        &format!("Trusting key: {hash}")
    ));
    let stored = home
        .path()
        .join(format!(".config/rnodeconf/trusted_keys/{hash}.pubkey"));
    assert_eq!(std::fs::read(stored).unwrap(), unhex(key));

    let out = rust_rnodeconf(home.path(), &["--trust-key", "zz"]);
    assert!(has_line(&lines(&out.stdout), "Invalid key data supplied"));
    let out = rust_rnodeconf(home.path(), &["--trust-key", "0011"]);
    assert!(has_line(
        &lines(&out.stdout),
        "Could not create public key from supplied data. Check that the key format is valid."
    ));
}

#[test]
fn key_generation_and_public_keys() {
    let home = tempfile::tempdir().unwrap();
    let out = rust_rnodeconf(home.path(), &["-k"]);
    let generated = lines(&out.stdout);
    let device_key = firmware(home.path()).join("device.key");
    for expected in [
        "Generating a new device signing key...",
        &format!("Device signing key written to {}", device_key.display()),
        "Generating a new EEPROM signing key...",
        "Wrote signing key",
        "Public key:",
    ] {
        assert!(has_line(&generated, expected), "missing {expected:?}");
    }
    let signing_key = std::fs::read(firmware(home.path()).join("signing.key")).unwrap();

    // A second run keeps both keys.
    let out = rust_rnodeconf(home.path(), &["-k"]);
    let again = lines(&out.stdout);
    assert!(has_line(
        &again,
        "EEPROM Signing key already exists, not overwriting!"
    ));
    assert_eq!(
        std::fs::read(firmware(home.path()).join("signing.key")).unwrap(),
        signing_key
    );

    let out = rust_rnodeconf(home.path(), &["-P"]);
    let public = lines(&out.stdout);
    let at = public
        .iter()
        .position(|l| l == "EEPROM Signing Public key:")
        .unwrap();
    // The same public key `-k` printed.
    let printed = generated.iter().position(|l| l == "Public key:").unwrap();
    assert_eq!(public[at + 1], generated[printed + 1]);
    let identity = rns_net::storage::load_identity(&device_key).unwrap();
    let expected: Vec<String> = identity.get_public_key().unwrap()[32..]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(has_line(&public, "Device Signing Public key:"));
    assert!(has_line(&public, &expected.join(":")));
}

#[test]
fn public_keys_without_keys() {
    let home = tempfile::tempdir().unwrap();
    let out = rust_rnodeconf(home.path(), &["-P"]);
    let lines = lines(&out.stdout);
    assert!(has_line(&lines, "Could not load EEPROM signing key"));
    assert!(has_line(&lines, "Could not load device signing key"));
}

#[test]
fn eeprom_dump_and_backup() {
    let image = eeprom(0xE0, 0xE9, 2, [1, 2, 3, 4], MADE, None);
    let fake = FakeRNode::start(device(image.clone()));
    let home = tempfile::tempdir().unwrap();
    let out = rust_rnodeconf(home.path(), &["--eeprom-dump", &fake.path]);
    let dump = lines(&out.stdout);
    let at = dump.iter().position(|l| l == "EEPROM contents:").unwrap();
    let hex: Vec<String> = image.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(dump[at + 1], hex.join(":"));

    let out = rust_rnodeconf(home.path(), &["--eeprom-backup", &fake.path]);
    let backup = lines(&out.stdout);
    let line = backup
        .iter()
        .find(|l| l.starts_with("EEPROM backup written to: "))
        .unwrap();
    let path = line.trim_start_matches("EEPROM backup written to: ");
    assert!(path.starts_with(
        &home
            .path()
            .join(".config/rnodeconf/eeprom/")
            .display()
            .to_string()
    ));
    assert!(path.ends_with(".eeprom"));
    assert_eq!(std::fs::read(path).unwrap(), image);
}

#[test]
fn eeprom_wipe_clears_the_device() {
    let fake = FakeRNode::start(avr_device(eeprom(0xE0, 0xE9, 2, [1, 2, 3, 4], MADE, None)));
    let home = tempfile::tempdir().unwrap();
    let out = rust_rnodeconf(home.path(), &["--eeprom-wipe", &fake.path]);
    assert!(out.status.success());
    assert!(has_line(
        &lines(&out.stdout),
        "WARNING: EEPROM is being wiped! Power down device NOW if you do not want this!"
    ));
    let frames = fake.received();
    assert!(frames.contains(&vec![CMD_ROM_WIPE, 0xf8]));
    assert_eq!(frames.last(), Some(&vec![CMD_RESET, 0xf8]));
    assert_eq!(fake.device.lock().unwrap().eeprom, blank_eeprom());
}

#[test]
fn bootstrap_provisions_a_blank_device() {
    let home = keyed_home();
    let fake = FakeRNode::start(avr_device(blank_eeprom()));
    let out = rust_rnodeconf(
        home.path(),
        &["-r", "--model", "a9", "--hwrev", "3", &fake.path],
    );
    assert!(out.status.success());
    let lines_out = lines(&out.stdout);
    for expected in [
        "Loading signing key...",
        "Bootstrapping device EEPROM...",
        "EEPROM written! Validating...",
        "EEPROM checksum correct",
        "Device signature validated",
        "EEPROM Bootstrapping successful!",
    ] {
        assert!(
            has_line(&lines_out, expected),
            "missing {expected:?} in {lines_out:#?}"
        );
    }
    let written = fake.device.lock().unwrap().eeprom.clone();
    assert_eq!(&written[0..4], &[0x03, 0xA9, 3, 0]);
    assert_eq!(&written[3..7], &[0, 0, 0, 1]);
    assert_eq!(written[0x9B], 0x73);
    let firmware = firmware(home.path());
    assert_eq!(
        std::fs::read_to_string(firmware.join("serial.counter")).unwrap(),
        "1"
    );
    assert_eq!(
        std::fs::read(firmware.join("device_db/00000001")).unwrap(),
        written
    );

    // The device now shows as validated by the local key.
    let out = rust_rnodeconf(home.path(), &["-i", &fake.path]);
    assert!(has_line(
        &lines(&out.stdout),
        "\tDevice signature   : Validated - Local signature"
    ));

    // A provisioned device is left alone.
    let out = rust_rnodeconf(
        home.path(),
        &["-r", "--model", "a9", "--hwrev", "3", &fake.path],
    );
    assert!(has_line(
        &lines(&out.stdout),
        "EEPROM bootstrap was requested, but a valid EEPROM was already present."
    ));
}

#[test]
fn bootstrap_needs_a_model_and_a_key() {
    let home = keyed_home();
    let fake = FakeRNode::start(avr_device(blank_eeprom()));
    let out = rust_rnodeconf(home.path(), &["-r", "--hwrev", "3", &fake.path]);
    assert!(has_line(
        &lines(&out.stdout),
        "Invalid data specified, cancelling EEPROM write"
    ));

    let home = tempfile::tempdir().unwrap();
    let out = rust_rnodeconf(
        home.path(),
        &["-r", "--model", "a9", "--hwrev", "3", &fake.path],
    );
    assert!(has_line(&lines(&out.stdout), "No signing key found"));
    assert_eq!(fake.device.lock().unwrap().eeprom, blank_eeprom());
}

#[test]
fn sign_stores_the_device_signature() {
    let home = keyed_home();
    let fake = FakeRNode::start(device(eeprom(0xE0, 0xE9, 2, [1, 2, 3, 4], MADE, None)));
    let out = rust_rnodeconf(home.path(), &["-S", &fake.path]);
    assert!(out.status.success());
    assert!(has_line(&lines(&out.stdout), "Device signed"));
    let identity =
        rns_net::storage::load_identity(&firmware(home.path()).join("device.key")).unwrap();
    let mut expected = vec![CMD_DEV_SIG];
    expected.extend(identity.sign(&[0x11; 32]).unwrap());
    assert!(fake.received().contains(&expected));

    // Not without provisioning.
    let fake = FakeRNode::start(device(blank_eeprom()));
    let out = rust_rnodeconf(home.path(), &["-S", &fake.path]);
    assert_eq!(out.status.code(), Some(79));
}

#[test]
fn firmware_hashes() {
    let home = tempfile::tempdir().unwrap();
    let fake = FakeRNode::start(device(eeprom(0xE0, 0xE9, 2, [1, 2, 3, 4], MADE, None)));
    let hash = "ab".repeat(32);
    let out = rust_rnodeconf(home.path(), &["-H", &hash, &fake.path]);
    assert!(has_line(&lines(&out.stdout), "Firmware hash set"));
    let mut expected = vec![CMD_FW_HASH];
    expected.extend([0xab; 32]);
    assert!(fake.received().contains(&expected));

    let out = rust_rnodeconf(home.path(), &["-H", "abcd", &fake.path]);
    assert_eq!(out.status.code(), Some(78));

    let out = rust_rnodeconf(home.path(), &["-K", "-L", &fake.path]);
    let lines = lines(&out.stdout);
    assert!(has_line(
        &lines,
        &format!("The target firmware hash is: {}", "22".repeat(32))
    ));
    assert!(has_line(
        &lines,
        &format!("The actual firmware hash is: {}", "33".repeat(32))
    ));

    let fake = FakeRNode::start(device(blank_eeprom()));
    let out = rust_rnodeconf(home.path(), &["-K", &fake.path]);
    assert_eq!(out.status.code(), Some(77));
}

/// Run both without a device and compare their output.
fn compare_offline(python_home: &Path, rust_home: &Path, args: &[&str]) {
    let python = python_rnodeconf(python_home, args);
    assert!(
        python.status.success(),
        "python rnodeconf failed: {}",
        String::from_utf8_lossy(&python.stderr)
    );
    let rust = rust_rnodeconf(rust_home, args);
    assert_eq!(normalize(&rust.stdout, "-"), normalize(&python.stdout, "-"));
}

#[test]
#[ignore = "requires Python Reticulum with pyserial and cryptography"]
fn python_comparison_trust_key() {
    let python_home = tempfile::tempdir().unwrap();
    let rust_home = tempfile::tempdir().unwrap();
    let key = include_str!("vectors/pss_public_key.hex").trim();
    compare_offline(python_home.path(), rust_home.path(), &["--trust-key", key]);
    let trusted = |home: &Path| {
        let dir = home.join(".config/rnodeconf/trusted_keys");
        let mut files: Vec<(std::ffi::OsString, Vec<u8>)> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.file_name(), std::fs::read(e.path()).unwrap())
            })
            .collect();
        files.sort();
        files
    };
    assert_eq!(trusted(rust_home.path()), trusted(python_home.path()));
    assert_eq!(trusted(rust_home.path()).len(), 1);
    compare_offline(python_home.path(), rust_home.path(), &["--trust-key", "zz"]);
}

#[test]
#[ignore = "requires Python Reticulum with pyserial and cryptography"]
fn python_comparison_public_keys() {
    // Upstream reads the keys our -k writes.
    let home = keyed_home();
    compare_offline(home.path(), home.path(), &["-P"]);
}

#[test]
#[ignore = "requires Python Reticulum with pyserial and cryptography"]
fn python_comparison_key_generation() {
    // Keys are random, so compare the messages, then check each tool
    // reads the other's keys.
    let python_home = tempfile::tempdir().unwrap();
    let rust_home = tempfile::tempdir().unwrap();
    let python = python_rnodeconf(python_home.path(), &["-k"]);
    let rust = rust_rnodeconf(rust_home.path(), &["-k"]);
    let messages = |out: &[u8], home: &Path| -> Vec<String> {
        let mut lines = normalize(out, &home.display().to_string());
        // The line after "Public key:" is the key itself.
        if let Some(at) = lines.iter().position(|l| l == "Public key:") {
            lines.remove(at + 1);
        }
        lines
    };
    assert_eq!(
        messages(&rust.stdout, rust_home.path()),
        messages(&python.stdout, python_home.path())
    );
    let python_on_rust = python_rnodeconf(rust_home.path(), &["-P"]);
    let rust_on_python = rust_rnodeconf(python_home.path(), &["-P"]);
    let rust_on_rust = rust_rnodeconf(rust_home.path(), &["-P"]);
    let python_on_python = python_rnodeconf(python_home.path(), &["-P"]);
    assert_eq!(
        normalize(&rust_on_rust.stdout, "-"),
        normalize(&python_on_rust.stdout, "-")
    );
    assert_eq!(
        normalize(&rust_on_python.stdout, "-"),
        normalize(&python_on_python.stdout, "-")
    );
}

#[test]
#[ignore = "requires Python Reticulum with pyserial and cryptography"]
fn python_comparison_eeprom_dump() {
    let home = tempfile::tempdir().unwrap();
    compare_with_python(
        eeprom(
            0xE0,
            0xE9,
            2,
            [1, 2, 3, 4],
            MADE,
            Some((8, 5, 14, 867_200_000, 125_000)),
        ),
        home.path(),
        &["--eeprom-dump"],
    );
}

#[test]
#[ignore = "requires Python Reticulum with pyserial and cryptography"]
fn python_comparison_eeprom_wipe() {
    let home = tempfile::tempdir().unwrap();
    let (python, python_fake, rust, rust_fake) = run_both(
        avr_device(eeprom(0xE0, 0xE9, 2, [1, 2, 3, 4], MADE, None)),
        home.path(),
        home.path(),
        &["--eeprom-wipe"],
    );
    assert_eq!(rust, python);
    assert_eq!(rust_fake.received(), python_fake.received());
    assert_eq!(rust_fake.device.lock().unwrap().eeprom, blank_eeprom());
}

#[test]
#[ignore = "requires Python Reticulum with pyserial and cryptography"]
fn python_comparison_sign() {
    // Ed25519 signatures are deterministic, so the frames match too.
    let home = keyed_home();
    compare_with_python(
        eeprom(0xE0, 0xE9, 2, [1, 2, 3, 4], MADE, None),
        home.path(),
        &["-S"],
    );
}

#[test]
#[ignore = "requires Python Reticulum with pyserial and cryptography"]
fn python_comparison_firmware_hashes() {
    let home = tempfile::tempdir().unwrap();
    let e = eeprom(0xE0, 0xE9, 2, [1, 2, 3, 4], MADE, None);
    compare_with_python(e.clone(), home.path(), &["-H", &"ab".repeat(32)]);
    compare_with_python(e, home.path(), &["-K", "-L"]);
}

#[test]
#[ignore = "requires Python Reticulum with pyserial and cryptography"]
fn python_comparison_bootstrap() {
    let keys = keyed_home();
    let python_home = copy_home(keys.path());
    let rust_home = copy_home(keys.path());
    let (python, python_fake, rust, rust_fake) = run_both(
        avr_device(blank_eeprom()),
        python_home.path(),
        rust_home.path(),
        &["-r", "--model", "a9", "--hwrev", "3"],
    );
    assert_eq!(rust, python);

    // The same EEPROM writes, in the same order. The values differ only in
    // the manufacturing time and what depends on it.
    let writes = |fake: &FakeRNode| -> Vec<u8> {
        fake.received()
            .iter()
            .filter(|f| f[0] == CMD_ROM_WRITE)
            .map(|f| f[1])
            .collect()
    };
    assert_eq!(writes(&rust_fake), writes(&python_fake));
    let rust_written = rust_fake.device.lock().unwrap().eeprom.clone();
    let python_written = python_fake.device.lock().unwrap().eeprom.clone();
    assert_eq!(rust_written[..7], python_written[..7]);
    assert_eq!(rust_written[0x9B..], python_written[0x9B..]);

    // Each tool accepts the EEPROM the other wrote.
    compare_device_with_python(avr_device(rust_written), keys.path(), &["-i"]);
    compare_device_with_python(avr_device(python_written), keys.path(), &["-i"]);
    let out = rust_rnodeconf(keys.path(), &["-i", &python_fake.path]);
    assert!(has_line(
        &lines(&out.stdout),
        "\tDevice signature   : Validated - Local signature"
    ));

    for home in [python_home.path(), rust_home.path()] {
        assert_eq!(
            std::fs::read_to_string(firmware(home).join("serial.counter")).unwrap(),
            "1"
        );
        assert!(firmware(home).join("device_db/00000001").is_file());
    }
}

// Stage 3: display, NeoPixel, interference avoidance, Bluetooth and WiFi.

fn provisioned() -> Vec<u8> {
    eeprom(0xE0, 0xE9, 2, [1, 2, 3, 4], MADE, None)
}

/// The frames after the EEPROM read: what the settings sent.
fn settings_sent(fake: &FakeRNode) -> Vec<Vec<u8>> {
    let frames = fake.received();
    let at = frames.iter().position(|f| f[0] == CMD_ROM_READ).unwrap();
    frames[at + 1..].to_vec()
}

#[test]
fn display_neopixel_and_interference_avoidance() {
    let fake = FakeRNode::start(device(provisioned()));
    let home = tempfile::tempdir().unwrap();
    let out = rust_rnodeconf(
        home.path(),
        &[
            "-D",
            "300",
            "-t",
            "0",
            "-R",
            "2",
            "--recondition-display",
            "-x",
            "-X",
            "--np",
            "192",
            &fake.path,
        ],
    );
    assert!(out.status.success());
    let lines = lines(&out.stdout);
    for expected in [
        "Setting display intensity to 255",
        "Disabling display blanking",
        "Setting display rotation to 2",
        "Starting display reconditioning",
        "Enabling interference avoidance",
        "Disabling interference avoidance",
        "Setting NeoPixel intensity to 192",
    ] {
        assert!(has_line(&lines, expected), "missing {expected:?}");
    }
    assert_eq!(
        settings_sent(&fake),
        vec![
            vec![CMD_DISP_INT, 255],
            vec![CMD_DISP_BLNK, 0],
            vec![CMD_DISP_ROT, 2],
            vec![CMD_DISP_RCND, 1],
            vec![CMD_DIS_IA, 0],
            vec![CMD_DIS_IA, 1],
            // 0xC0 is escaped, where upstream sends it raw.
            vec![CMD_NP_INT, 192],
        ]
    );
}

#[test]
fn display_address_resets_the_device() {
    let fake = FakeRNode::start(device(provisioned()));
    let home = tempfile::tempdir().unwrap();
    let out = rust_rnodeconf(home.path(), &["--display-addr", "0x3d", "-i", &fake.path]);
    let lines = lines(&out.stdout);
    assert!(has_line(&lines, "Setting display address to 3d"));
    // It exits before showing the information.
    assert!(!lines.iter().any(|l| l.contains("Device info")));
    assert_eq!(
        settings_sent(&fake),
        vec![vec![CMD_DISP_ADR, 0x3d], vec![CMD_RESET, 0xf8]]
    );

    let out = rust_rnodeconf(home.path(), &["--display-addr", "3d3d", &fake.path]);
    assert!(has_line(
        &lines_of(&out),
        "Invalid display address specified"
    ));
}

fn lines_of(out: &std::process::Output) -> Vec<String> {
    lines(&out.stdout)
}

#[test]
fn bluetooth_controls() {
    let fake = FakeRNode::start(device(provisioned()));
    let home = tempfile::tempdir().unwrap();
    let out = run(
        rust_command(home.path(), &["-b", "-B", "-p", &fake.path]),
        Some("\n"),
    );
    let lines = lines(&out.stdout);
    for expected in [
        "Enabling Bluetooth...",
        "Disabling Bluetooth...",
        "Putting device into Bluetooth pairing mode. Press enter to exit when done.",
    ] {
        assert!(has_line(&lines, expected), "missing {expected:?}");
    }
    assert_eq!(
        settings_sent(&fake),
        vec![
            vec![CMD_BT_CTRL, 1],
            vec![CMD_LEAVE, 0xFF],
            vec![CMD_BT_CTRL, 0],
            vec![CMD_LEAVE, 0xFF],
            vec![CMD_BT_CTRL, 2],
            vec![CMD_LEAVE, 0xFF],
        ]
    );
}

#[test]
fn wifi_settings() {
    let fake = FakeRNode::start(device(provisioned()));
    let home = tempfile::tempdir().unwrap();
    let out = rust_rnodeconf(
        home.path(),
        &[
            "--channel",
            "6",
            "--ssid",
            "mesh",
            "--psk",
            "s3cretpw",
            "--ip",
            "10.0.0.2",
            "--nm",
            "NONE",
            "-w",
            "STATION",
            &fake.path,
        ],
    );
    let lines = lines(&out.stdout);
    for expected in [
        "Setting WiFi channel to 6",
        "Setting WiFi SSID to: mesh",
        "Setting WiFi PSK",
        "Setting WiFi static IP to: 10.0.0.2",
        "Deleting WiFi static netmask configuration...",
        "Setting WiFi to station mode",
    ] {
        assert!(has_line(&lines, expected), "missing {expected:?}");
    }
    assert_eq!(
        settings_sent(&fake),
        vec![
            vec![CMD_WIFI_CHN, 6],
            [&[CMD_WIFI_SSID][..], b"mesh\0"].concat(),
            [&[CMD_WIFI_PSK][..], b"s3cretpw\0"].concat(),
            vec![CMD_WIFI_IP, 10, 0, 0, 2],
            vec![CMD_WIFI_NM, 0, 0, 0, 0],
            vec![CMD_WIFI_MODE, 1],
        ]
    );
}

#[test]
fn wifi_settings_refused() {
    let home = tempfile::tempdir().unwrap();
    for (args, expected) in [
        (
            &["--channel", "15"][..],
            "Could not set WiFi channel: Invalid WiFi channel",
        ),
        (&["--psk", "short"], "Could not set WiFi PSK: Invalid psk length"),
        (
            &["--ssid", "this-ssid-is-much-too-long-for-wifi"],
            "Could not set WiFi SSID: Invalid SSID length",
        ),
        (
            &["--ip", "10.0.0"],
            "Could not set WiFi IP: Invalid IP address length",
        ),
        (
            &["--ip", "10.0.0.256"],
            "Could not set WiFi IP: Could not decode IP address octet: Invalid IP octet value",
        ),
        (
            &["--nm", "255.x.0.0"],
            "Could not set WiFi netmask: Could not decode IP address octet: invalid literal for int() with base 10: 'x'",
        ),
    ] {
        let fake = FakeRNode::start(device(provisioned()));
        let mut argv = args.to_vec();
        argv.push(&fake.path);
        let out = rust_rnodeconf(home.path(), &argv);
        assert!(
            has_line(&lines_of(&out), expected),
            "missing {expected:?} for {args:?}"
        );
        assert!(settings_sent(&fake).is_empty(), "sent something for {args:?}");
    }
}

#[test]
fn invalid_integer_options_are_rejected_first() {
    let home = tempfile::tempdir().unwrap();
    let out = rust_rnodeconf(home.path(), &["-D", "bright", "/dev/null"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
}

#[test]
#[ignore = "requires Python Reticulum with pyserial and cryptography"]
fn python_comparison_help() {
    let home = tempfile::tempdir().unwrap();
    let python = python_command(home.path(), &["-h"])
        .env("COLUMNS", "80")
        .output()
        .unwrap();
    // Python 3.13 changed how argparse shows short options with values.
    let text = String::from_utf8_lossy(&python.stdout);
    if text.contains("-w, --wifi mode") {
        eprintln!("argparse lays out options differently on this Python; skipping");
        return;
    }
    assert_eq!(rust_rnodeconf(home.path(), &["-h"]).stdout, python.stdout);
}

#[test]
#[ignore = "requires Python Reticulum with pyserial and cryptography"]
fn python_comparison_display_and_neopixel() {
    let home = tempfile::tempdir().unwrap();
    // Values other than 0xC0 and 0xDB, which upstream sends unescaped.
    compare_with_python(
        provisioned(),
        home.path(),
        &[
            "-D",
            "300",
            "-t",
            "45",
            "-R",
            "7",
            "--recondition-display",
            "-x",
            "-X",
            "--np",
            "-4",
            "-i",
        ],
    );
    compare_with_python(provisioned(), home.path(), &["-t", "0"]);
    compare_with_python(
        provisioned(),
        home.path(),
        &["--display-addr", "0x3d", "-i"],
    );
    compare_with_python(provisioned(), home.path(), &["--display-addr", "zz"]);
}

#[test]
#[ignore = "requires Python Reticulum with pyserial and cryptography"]
fn python_comparison_bluetooth() {
    let home = tempfile::tempdir().unwrap();
    let (python, python_fake, rust, rust_fake) = run_both_with_input(
        device(provisioned()),
        home.path(),
        home.path(),
        &["-b", "-B", "-p"],
        Some("\n"),
    );
    assert_eq!(rust, python);
    assert_eq!(rust_fake.received(), python_fake.received());
}

#[test]
#[ignore = "requires Python Reticulum with pyserial and cryptography"]
fn python_comparison_wifi() {
    let home = tempfile::tempdir().unwrap();
    for args in [
        &[
            "--channel",
            "6",
            "--ssid",
            "mesh",
            "--psk",
            "s3cretpw",
            "--ip",
            "10.0.0.2",
            "--nm",
            "255.255.255.0",
            "-w",
            "ap",
        ][..],
        &[
            "--ssid", "none", "--psk", "NONE", "--ip", "none", "--nm", "none", "-w", "off",
        ],
        &["-w", "station"],
        &["--channel", "0"],
        &["--channel", "six"],
        &["--psk", "1234567"],
        &["--psk", "123456"],
        &["--ssid", "this-ssid-is-much-too-long-for-wifi"],
        &["--ip", "10.0.0"],
        &["--ip", "10.0.0.256"],
        &["--nm", "255.x.0.0"],
    ] {
        compare_with_python(provisioned(), home.path(), args);
    }
    // On an unprovisioned device too: the settings come before the checks.
    compare_with_python(blank_eeprom(), home.path(), &["-w", "sta"]);
}
