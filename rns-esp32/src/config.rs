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

/// Enable CRC on LoRa packets.
pub const LORA_CRC_ON: bool = true;

/// SX1262 max payload size.
pub const LORA_MTU: u32 = 255;

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
