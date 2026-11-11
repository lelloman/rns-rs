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

fn rust_rnodeconf(home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rnodeconf"))
        .args(args)
        .env("HOME", home)
        .env("TZ", "UTC")
        .output()
        .expect("run rnodeconf")
}

fn python_rnodeconf(home: &Path, args: &[&str]) -> std::process::Output {
    let mut argv = vec!["rnodeconf".to_string()];
    argv.extend(args.iter().map(|a| a.to_string()));
    Command::new("python3")
        .arg("-c")
        .arg(format!(
            "import sys; sys.argv={argv:?}; from RNS.Utilities import rnodeconf; rnodeconf.main()"
        ))
        .env("HOME", home)
        .env("TZ", "UTC")
        .env("PYTHONUNBUFFERED", "1")
        .output()
        .expect("run python rnodeconf")
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

/// The same scenario through upstream's `rnodeconf` and ours: the same
/// output and the same frames sent to the device.
fn compare_with_python(eeprom: Vec<u8>, home: &Path, args: &[&str]) {
    let python_fake = FakeRNode::start(device(eeprom.clone()));
    let mut python_args = args.to_vec();
    python_args.push(&python_fake.path);
    let python = python_rnodeconf(home, &python_args);
    assert!(
        python.status.success(),
        "python rnodeconf failed: {}",
        String::from_utf8_lossy(&python.stderr)
    );

    let rust_fake = FakeRNode::start(device(eeprom));
    let mut rust_args = args.to_vec();
    rust_args.push(&rust_fake.path);
    let rust = rust_rnodeconf(home, &rust_args);

    // Upstream's last line logs its exit code.
    let normalize = |out: &[u8], path: &str| -> Vec<String> {
        lines(out)
            .into_iter()
            .filter(|l| !l.starts_with("Exiting: Code"))
            .map(|l| l.replace(path, "PORT"))
            .collect()
    };
    assert_eq!(
        normalize(&rust.stdout, &rust_fake.path),
        normalize(&python.stdout, &python_fake.path)
    );
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
