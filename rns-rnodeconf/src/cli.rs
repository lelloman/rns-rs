//! Command line options and help, as upstream rnodeconf takes them.

use super::*;

/// Options that take a value, by every name they have.
pub(super) const VALUE_OPTIONS: &[&str] = &[
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
pub(super) const FLAGS: &[(&str, &str)] = &[
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
pub(super) const VALUE_ALIASES: &[(&str, &str)] = &[
    ("-w", "--wifi"),
    ("-D", "--display"),
    ("-t", "--timeout"),
    ("-R", "--rotation"),
    ("-H", "--firmware-hash"),
];

/// Options upstream's argument parser reads as integers, rejecting the
/// command line before doing anything else when one is not.
pub(super) const INT_OPTIONS: &[&str] = &[
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
pub(super) struct Args {
    pub(super) flags: Vec<&'static str>,
    pub(super) values: Vec<(&'static str, String)>,
    pub(super) port: Option<String>,
}

impl Args {
    pub(super) fn has(&self, long: &str) -> bool {
        self.flags.contains(&long) || self.values.iter().any(|(k, _)| *k == long)
    }

    pub(super) fn value(&self, long: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(k, _)| *k == long)
            .map(|(_, v)| v.as_str())
    }

    pub(super) fn int(&self, long: &str) -> Option<i64> {
        let value = self.value(long)?;
        match value.trim().parse::<i64>() {
            Ok(v) => Some(v),
            Err(_) => usage_error(&format!("argument {long}: invalid int value: '{value}'")),
        }
    }
}

pub(super) fn usage_error(message: &str) -> ! {
    eprintln!("usage: rnodeconf [-h] [options] [port]");
    eprintln!("rnodeconf: error: {message}");
    exit(2)
}

pub(super) fn parse_args() -> Args {
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
pub(super) const HELP: &str = r#"usage: rnodeconf [-h] [-i] [-a] [-u] [-U] [--fw-version version]
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

pub(super) fn print_help() {
    print!("{HELP}");
}
