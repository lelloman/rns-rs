#![allow(dead_code)]

/// Hardcoded LoRa radio parameters for Heltec V3 + SX1262.

/// A decimal number from a build-time environment variable, or `default`
/// when it is not set. An invalid number fails the build.
const fn env_number(value: Option<&str>, default: i64) -> i64 {
    let Some(value) = value else {
        return default;
    };
    let bytes = value.as_bytes();
    let (negative, mut i) = match bytes.first() {
        Some(b'-') => (true, 1),
        _ => (false, 0),
    };
    assert!(i < bytes.len(), "empty number in a RNS_ESP32_* variable");
    let mut n: i64 = 0;
    while i < bytes.len() {
        let digit = bytes[i];
        assert!(
            digit.is_ascii_digit(),
            "invalid number in a RNS_ESP32_* variable"
        );
        n = n * 10 + (digit - b'0') as i64;
        i += 1;
    }
    if negative {
        -n
    } else {
        n
    }
}

/// LoRa frequency in Hz (868 MHz EU band). This and the other LoRa
/// settings can be set at build time with `RNS_ESP32_LORA_FREQUENCY`,
/// `RNS_ESP32_LORA_BANDWIDTH`, `RNS_ESP32_LORA_SF`, `RNS_ESP32_LORA_CR` and
/// `RNS_ESP32_LORA_TXPOWER`.
pub const LORA_FREQUENCY: u32 =
    env_number(option_env!("RNS_ESP32_LORA_FREQUENCY"), 868_000_000) as u32;

/// LoRa bandwidth in Hz.
pub const LORA_BANDWIDTH: u32 = env_number(option_env!("RNS_ESP32_LORA_BANDWIDTH"), 125_000) as u32;

/// LoRa spreading factor (7-12).
pub const LORA_SPREADING_FACTOR: u8 = env_number(option_env!("RNS_ESP32_LORA_SF"), 8) as u8;

/// LoRa coding rate (5 = 4/5, 6 = 4/6, 7 = 4/7, 8 = 4/8).
pub const LORA_CODING_RATE: u8 = env_number(option_env!("RNS_ESP32_LORA_CR"), 5) as u8;

/// TX power in dBm (max 22 for SX1262).
pub const LORA_TX_POWER: i8 = env_number(option_env!("RNS_ESP32_LORA_TXPOWER"), 14) as i8;

/// Announce the node's destinations every this many seconds, starting at
/// boot (`RNS_ESP32_ANNOUNCE_INTERVAL` at build time); 0, the default,
/// announces only on a long button press.
pub const ANNOUNCE_INTERVAL_SECS: u64 =
    env_number(option_env!("RNS_ESP32_ANNOUNCE_INTERVAL"), 0) as u64;

/// A build-time string setting: `None` when the variable is unset or empty.
const fn env_text(value: Option<&'static str>) -> Option<&'static str> {
    match value {
        Some(text) if !text.is_empty() => Some(text),
        _ => None,
    }
}

/// Interface access code (IFAC) for the node's LoRa interface in
/// standalone mode, as `network_name` and `passphrase` set it on a
/// Reticulum interface: `RNS_ESP32_IFAC_NETNAME` and
/// `RNS_ESP32_IFAC_PASSPHRASE` at build time. Either or both enable IFAC;
/// neither, the default, leaves the interface open. Bridge mode is not
/// affected: there the host applies its own IFAC.
pub const IFAC_NETNAME: Option<&str> = env_text(option_env!("RNS_ESP32_IFAC_NETNAME"));

/// See [`IFAC_NETNAME`].
pub const IFAC_PASSPHRASE: Option<&str> = env_text(option_env!("RNS_ESP32_IFAC_PASSPHRASE"));

/// IFAC length in bits (`RNS_ESP32_IFAC_SIZE`, as `ifac_size` in a
/// Reticulum interface config). The default, 64, is RNode interfaces'
/// default of 8 bytes. It must be 8 to 512; it is rounded down to whole
/// bytes.
pub const IFAC_SIZE_BITS: i64 = env_number(option_env!("RNS_ESP32_IFAC_SIZE"), 64);

const _: () = assert!(
    IFAC_SIZE_BITS >= 8 && IFAC_SIZE_BITS <= 512,
    "RNS_ESP32_IFAC_SIZE must be 8 to 512 bits"
);

/// IFAC length in bytes.
pub const IFAC_SIZE: usize = (IFAC_SIZE_BITS / 8) as usize;

/// Enable CRC on LoRa packets.
pub const LORA_CRC_ON: bool = true;

/// SX1262 max payload size.
pub const LORA_MTU: u32 = 255;

/// Host-serial receive buffer, in bytes. Sending a frame blocks the bridge
/// loop for its whole airtime (over a second at SF8), and the host does not
/// wait between frames: it writes a full resource window back to back. The
/// UART driver's default buffer (256 bytes) holds less than one frame, so
/// every frame after the first in a window was lost. 16 KiB holds a slow-link
/// window (10 frames of up to 508 bytes) even with worst-case KISS escaping.
pub const SERIAL_RX_BUFFER: usize = 16 * 1024;

// Heltec V3 SX1262 GPIO pin assignments
pub const PIN_SCK: i32 = 9;
pub const PIN_MOSI: i32 = 10;
pub const PIN_MISO: i32 = 11;
pub const PIN_NSS: i32 = 8;
pub const PIN_RST: i32 = 12;
pub const PIN_BUSY: i32 = 13;
pub const PIN_DIO1: i32 = 14;
pub const PIN_VEXT: i32 = 36;

// Heltec V3 OLED display (SSD1306 128x64 I2C)
pub const OLED_SDA: i32 = 17;
pub const OLED_SCL: i32 = 18;
pub const OLED_RST: i32 = 21;
pub const OLED_ADDR: u8 = 0x3C;

/// Transport engine tick interval in milliseconds.
pub const TICK_INTERVAL_MS: u64 = 1000;
