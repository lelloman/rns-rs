/// Hardcoded LoRa radio parameters for Heltec V3 + SX1262.

/// LoRa frequency in Hz (868 MHz EU band).
pub const LORA_FREQUENCY: u32 = 868_000_000;

/// LoRa bandwidth in Hz.
pub const LORA_BANDWIDTH: u32 = 125_000;

/// LoRa spreading factor (7-12).
pub const LORA_SPREADING_FACTOR: u8 = 8;

/// LoRa coding rate (5 = 4/5, 6 = 4/6, 7 = 4/7, 8 = 4/8).
pub const LORA_CODING_RATE: u8 = 5;

/// TX power in dBm (max 22 for SX1262).
pub const LORA_TX_POWER: i8 = 14;

/// Preamble length in symbols.
pub const LORA_PREAMBLE_LENGTH: u16 = 8;

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
