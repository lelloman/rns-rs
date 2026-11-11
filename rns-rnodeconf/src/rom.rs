#![allow(dead_code)] // The full table; later stages use the rest.
//! Device identification constants and tables, as upstream `rnodeconf.py`'s
//! `ROM` class and its `products`, `platforms`, `mcus` and `models` define
//! them.

pub const PLATFORM_AVR: u8 = 0x90;
pub const PLATFORM_ESP32: u8 = 0x80;
pub const PLATFORM_NRF52: u8 = 0x70;
pub const MCU_1284P: u8 = 0x91;
pub const MCU_2560: u8 = 0x92;
pub const MCU_ESP32: u8 = 0x81;
pub const MCU_NRF52: u8 = 0x71;
pub const PRODUCT_RNODE: u8 = 0x03;
pub const MODEL_A1: u8 = 0xA1;
pub const MODEL_A6: u8 = 0xA6;
pub const MODEL_A4: u8 = 0xA4;
pub const MODEL_A9: u8 = 0xA9;
pub const MODEL_A3: u8 = 0xA3;
pub const MODEL_A8: u8 = 0xA8;
pub const MODEL_A2: u8 = 0xA2;
pub const MODEL_A7: u8 = 0xA7;
pub const MODEL_A5: u8 = 0xA5;
pub const MODEL_AA: u8 = 0xAA;
pub const MODEL_AC: u8 = 0xAC;
pub const PRODUCT_T32_10: u8 = 0xB2;
pub const MODEL_BA: u8 = 0xBA;
pub const MODEL_BB: u8 = 0xBB;
pub const PRODUCT_T32_20: u8 = 0xB0;
pub const MODEL_B3: u8 = 0xB3;
pub const MODEL_B8: u8 = 0xB8;
pub const PRODUCT_T32_21: u8 = 0xB1;
pub const MODEL_B4: u8 = 0xB4;
pub const MODEL_B9: u8 = 0xB9;
/// The TCXO model codes are only used here to select the correct firmware,
pub const MODEL_B4_TCXO: u8 = 0x04;
/// actual model codes in firmware is still 0xB4 and 0xB9.
pub const MODEL_B9_TCXO: u8 = 0x09;
pub const PRODUCT_H32_V2: u8 = 0xC0;
pub const MODEL_C4: u8 = 0xC4;
pub const MODEL_C9: u8 = 0xC9;
pub const PRODUCT_H32_V3: u8 = 0xC1;
pub const MODEL_C5: u8 = 0xC5;
pub const MODEL_CA: u8 = 0xCA;
pub const PRODUCT_H32_V4: u8 = 0xC3;
/// 868/915/923 MHz with PA
pub const MODEL_C8: u8 = 0xC8;
pub const PRODUCT_TBEAM: u8 = 0xE0;
pub const MODEL_E4: u8 = 0xE4;
pub const MODEL_E9: u8 = 0xE9;
pub const MODEL_E3: u8 = 0xE3;
pub const MODEL_E8: u8 = 0xE8;
pub const PRODUCT_TBEAM_S_V1: u8 = 0xEA;
pub const MODEL_DB: u8 = 0xDB;
pub const MODEL_DC: u8 = 0xDC;
pub const PRODUCT_TDECK: u8 = 0xD0;
pub const MODEL_D4: u8 = 0xD4;
pub const MODEL_D9: u8 = 0xD9;
pub const PRODUCT_RAK4631: u8 = 0x10;
pub const MODEL_11: u8 = 0x11;
pub const MODEL_12: u8 = 0x12;
pub const MODEL_13: u8 = 0x13;
pub const MODEL_14: u8 = 0x14;
pub const PRODUCT_OPENCOM_XL: u8 = 0x20;
pub const MODEL_21: u8 = 0x21;
pub const PRODUCT_TECHO: u8 = 0x15;
pub const MODEL_16: u8 = 0x16;
pub const MODEL_17: u8 = 0x17;
pub const PRODUCT_HELTEC_T114: u8 = 0xC2;
pub const BOARD_HELTEC_T114: u8 = 0x3C;
/// Heltec Mesh Node T114, 470-510 MHz (HT-n5262-LF)
pub const MODEL_C6: u8 = 0xC6;
/// Heltec Mesh Node T114, 863-928 MHz (HT-n5262-HF)
pub const MODEL_C7: u8 = 0xC7;
pub const PRODUCT_XIAO_S3: u8 = 0xEB;
pub const BOARD_XIAO_S3: u8 = 0x3E;
/// Xiao ESP32S3 with Wio-SX1262 module, 433 MHz
pub const MODEL_DE: u8 = 0xDE;
/// Xiao ESP32S3 with Wio-SX1262 module, 868 MHz
pub const MODEL_DD: u8 = 0xDD;
pub const PRODUCT_HMBRW: u8 = 0xF0;
pub const MODEL_FF: u8 = 0xFF;
pub const MODEL_FE: u8 = 0xFE;
pub const ADDR_PRODUCT: u8 = 0x00;
pub const ADDR_MODEL: u8 = 0x01;
pub const ADDR_HW_REV: u8 = 0x02;
pub const ADDR_SERIAL: u8 = 0x03;
pub const ADDR_MADE: u8 = 0x07;
pub const ADDR_CHKSUM: u8 = 0x0B;
pub const ADDR_SIGNATURE: u8 = 0x1B;
pub const ADDR_INFO_LOCK: u8 = 0x9B;
pub const ADDR_CONF_SF: u8 = 0x9C;
pub const ADDR_CONF_CR: u8 = 0x9D;
pub const ADDR_CONF_TXP: u8 = 0x9E;
pub const ADDR_CONF_BW: u8 = 0x9F;
pub const ADDR_CONF_FREQ: u8 = 0xA3;
pub const ADDR_CONF_OK: u8 = 0xA7;
pub const ADDR_CONF_BT: u8 = 0xB0;
pub const ADDR_CONF_DSET: u8 = 0xB1;
pub const ADDR_CONF_DINT: u8 = 0xB2;
pub const ADDR_CONF_DADR: u8 = 0xB3;
pub const ADDR_CONF_DBLK: u8 = 0xB4;
pub const ADDR_CONF_DROT: u8 = 0xB8;
pub const ADDR_CONF_PSET: u8 = 0xB5;
pub const ADDR_CONF_PINT: u8 = 0xB6;
pub const ADDR_CONF_BSET: u8 = 0xB7;
pub const ADDR_CONF_DIA: u8 = 0xB9;
pub const ADDR_CONF_WIFI: u8 = 0xBA;
pub const ADDR_CONF_WCHN: u8 = 0xBB;
pub const ADDR_CONF_SSID: u8 = 0x00;
pub const ADDR_CONF_PSK: u8 = 0x21;
pub const ADDR_CONF_IP: u8 = 0x42;
pub const ADDR_CONF_NM: u8 = 0x46;
pub const INFO_LOCK_BYTE: u8 = 0x73;
pub const CONF_OK_BYTE: u8 = 0x73;
pub const BOARD_RNODE: u8 = 0x31;
pub const BOARD_HMBRW: u8 = 0x32;
pub const BOARD_TBEAM: u8 = 0x33;
pub const BOARD_TDECK: u8 = 0x3B;
pub const BOARD_HUZZAH32: u8 = 0x34;
pub const BOARD_GENERIC_ESP32: u8 = 0x35;
pub const BOARD_LORA32_V2_0: u8 = 0x36;
pub const BOARD_LORA32_V2_1: u8 = 0x37;
pub const BOARD_TECHO: u8 = 0x43;
pub const BOARD_RAK4631: u8 = 0x51;

/// A model's band and output power (upstream `models`).
pub struct Model {
    pub min_freq: u64,
    pub max_freq: u64,
    pub max_output: u8,
    pub band: &'static str,
    pub firmware: Option<&'static str>,
    pub modem: &'static str,
}

pub fn product_name(product: u8) -> Option<&'static str> {
    match product {
        PRODUCT_RNODE => Some("RNode"),
        PRODUCT_HMBRW => Some("Hombrew RNode"),
        PRODUCT_TBEAM => Some("LilyGO T-Beam"),
        PRODUCT_TBEAM_S_V1 => Some("LilyGO T-Beam Supreme"),
        PRODUCT_TDECK => Some("LilyGO T-Deck"),
        PRODUCT_T32_10 => Some("LilyGO LoRa32 v1.0"),
        PRODUCT_T32_20 => Some("LilyGO LoRa32 v2.0"),
        PRODUCT_T32_21 => Some("LilyGO LoRa32 v2.1"),
        PRODUCT_H32_V2 => Some("Heltec LoRa32 v2"),
        PRODUCT_H32_V3 => Some("Heltec LoRa32 v3"),
        PRODUCT_H32_V4 => Some("Heltec LoRa32 v4"),
        PRODUCT_TECHO => Some("LilyGO T-Echo"),
        PRODUCT_RAK4631 => Some("RAK4631"),
        PRODUCT_OPENCOM_XL => Some("openCom XL"),
        PRODUCT_HELTEC_T114 => Some("Heltec Mesh Node T114"),
        PRODUCT_XIAO_S3 => Some("Seeed XIAO ESP32S3 Wio-SX1262"),
        _ => None,
    }
}

pub fn platform_name(platform: u8) -> Option<&'static str> {
    match platform {
        PLATFORM_AVR => Some("AVR"),
        PLATFORM_ESP32 => Some("ESP32"),
        PLATFORM_NRF52 => Some("NRF52"),
        _ => None,
    }
}

pub fn mcu_name(mcu: u8) -> Option<&'static str> {
    match mcu {
        MCU_1284P => Some("ATmega1284P"),
        MCU_2560 => Some("ATmega2560"),
        MCU_ESP32 => Some("Espressif Systems ESP32"),
        MCU_NRF52 => Some("Nordic Semiconductor nRF52840"),
        _ => None,
    }
}

pub fn model(model: u8) -> Option<Model> {
    let (min_freq, max_freq, max_output, band, firmware, modem) = match model {
        0xA4 => (
            410000000,
            525000000,
            14,
            "410 - 525 MHz",
            Some("rnode_firmware.hex"),
            "SX1278",
        ),
        0xA9 => (
            820000000,
            1020000000,
            17,
            "820 - 1020 MHz",
            Some("rnode_firmware.hex"),
            "SX1276",
        ),
        0xA1 => (
            410000000,
            525000000,
            22,
            "410 - 525 MHz",
            Some("rnode_firmware_t3s3.zip"),
            "SX1268",
        ),
        0xA6 => (
            820000000,
            1020000000,
            22,
            "820 - 960 MHz",
            Some("rnode_firmware_t3s3.zip"),
            "SX1262",
        ),
        0xA5 => (
            410000000,
            525000000,
            17,
            "410 - 525 MHz",
            Some("rnode_firmware_t3s3_sx127x.zip"),
            "SX1278",
        ),
        0xAA => (
            820000000,
            1020000000,
            17,
            "820 - 960 MHz",
            Some("rnode_firmware_t3s3_sx127x.zip"),
            "SX1276",
        ),
        0xAC => (
            2400000000,
            2500000000,
            20,
            "2.4 - 2.5 GHz",
            Some("rnode_firmware_t3s3_sx1280_pa.zip"),
            "SX1280",
        ),
        0xA2 => (
            410000000,
            525000000,
            17,
            "410 - 525 MHz",
            Some("rnode_firmware_ng21.zip"),
            "SX1278",
        ),
        0xA7 => (
            820000000,
            1020000000,
            17,
            "820 - 1020 MHz",
            Some("rnode_firmware_ng21.zip"),
            "SX1276",
        ),
        0xA3 => (
            410000000,
            525000000,
            17,
            "410 - 525 MHz",
            Some("rnode_firmware_ng20.zip"),
            "SX1278",
        ),
        0xA8 => (
            820000000,
            1020000000,
            17,
            "820 - 1020 MHz",
            Some("rnode_firmware_ng20.zip"),
            "SX1276",
        ),
        0xB3 => (
            420000000,
            520000000,
            17,
            "420 - 520 MHz",
            Some("rnode_firmware_lora32v20.zip"),
            "SX1278",
        ),
        0xB8 => (
            850000000,
            950000000,
            17,
            "850 - 950 MHz",
            Some("rnode_firmware_lora32v20.zip"),
            "SX1276",
        ),
        0xB4 => (
            420000000,
            520000000,
            17,
            "420 - 520 MHz",
            Some("rnode_firmware_lora32v21.zip"),
            "SX1278",
        ),
        0xB9 => (
            850000000,
            950000000,
            17,
            "850 - 950 MHz",
            Some("rnode_firmware_lora32v21.zip"),
            "SX1276",
        ),
        0x04 => (
            420000000,
            520000000,
            17,
            "420 - 520 MHz",
            Some("rnode_firmware_lora32v21_tcxo.zip"),
            "SX1278",
        ),
        0x09 => (
            850000000,
            950000000,
            17,
            "850 - 950 MHz",
            Some("rnode_firmware_lora32v21_tcxo.zip"),
            "SX1276",
        ),
        0xBA => (
            420000000,
            520000000,
            17,
            "420 - 520 MHz",
            Some("rnode_firmware_lora32v10.zip"),
            "SX1278",
        ),
        0xBB => (
            850000000,
            950000000,
            17,
            "850 - 950 MHz",
            Some("rnode_firmware_lora32v10.zip"),
            "SX1276",
        ),
        0xC4 => (
            420000000,
            520000000,
            17,
            "420 - 520 MHz",
            Some("rnode_firmware_heltec32v2.zip"),
            "SX1278",
        ),
        0xC9 => (
            850000000,
            950000000,
            17,
            "850 - 950 MHz",
            Some("rnode_firmware_heltec32v2.zip"),
            "SX1276",
        ),
        0xC5 => (
            420000000,
            520000000,
            22,
            "420 - 520 MHz",
            Some("rnode_firmware_heltec32v3.zip"),
            "SX1268",
        ),
        0xCA => (
            850000000,
            950000000,
            22,
            "850 - 950 MHz",
            Some("rnode_firmware_heltec32v3.zip"),
            "SX1262",
        ),
        0xC8 => (
            860000000,
            930000000,
            28,
            "850 - 950 MHz",
            Some("rnode_firmware_heltec32v4pa.zip"),
            "SX1262",
        ),
        0xC6 => (
            420000000,
            520000000,
            22,
            "420 - 520 MHz",
            Some("rnode_firmware_heltec_t114.zip"),
            "SX1268",
        ),
        0xC7 => (
            850000000,
            950000000,
            22,
            "850 - 950 MHz",
            Some("rnode_firmware_heltec_t114.zip"),
            "SX1262",
        ),
        0xE4 => (
            420000000,
            520000000,
            17,
            "420 - 520 MHz",
            Some("rnode_firmware_tbeam.zip"),
            "SX1278",
        ),
        0xE9 => (
            850000000,
            950000000,
            17,
            "850 - 950 MHz",
            Some("rnode_firmware_tbeam.zip"),
            "SX1276",
        ),
        0xD4 => (
            420000000,
            520000000,
            22,
            "420 - 520 MHz",
            Some("rnode_firmware_tdeck.zip"),
            "SX1268",
        ),
        0xD9 => (
            850000000,
            950000000,
            22,
            "850 - 950 MHz",
            Some("rnode_firmware_tdeck.zip"),
            "SX1262",
        ),
        0xDB => (
            420000000,
            520000000,
            22,
            "420 - 520 MHz",
            Some("rnode_firmware_tbeam_supreme.zip"),
            "SX1268",
        ),
        0xDC => (
            850000000,
            950000000,
            22,
            "850 - 950 MHz",
            Some("rnode_firmware_tbeam_supreme.zip"),
            "SX1262",
        ),
        0xE3 => (
            420000000,
            520000000,
            22,
            "420 - 520 MHz",
            Some("rnode_firmware_tbeam_sx1262.zip"),
            "SX1268",
        ),
        0xE8 => (
            850000000,
            950000000,
            22,
            "850 - 950 MHz",
            Some("rnode_firmware_tbeam_sx1262.zip"),
            "SX1262",
        ),
        0x11 => (
            430000000,
            510000000,
            22,
            "430 - 510 MHz",
            Some("rnode_firmware_rak4631.zip"),
            "SX1262",
        ),
        0x12 => (
            779000000,
            928000000,
            22,
            "779 - 928 MHz",
            Some("rnode_firmware_rak4631.zip"),
            "SX1262",
        ),
        0x13 => (
            430000000,
            510000000,
            22,
            "430 - 510 MHz",
            Some("rnode_firmware_rak4631_sx1280.zip"),
            "SX1262 + SX1280",
        ),
        0x14 => (
            779000000,
            928000000,
            22,
            "779 - 928 MHz",
            Some("rnode_firmware_rak4631_sx1280.zip"),
            "SX1262 + SX1280",
        ),
        0x16 => (
            779000000,
            928000000,
            22,
            "430 - 510 Mhz",
            Some("rnode_firmware_techo.zip"),
            "SX1262",
        ),
        0x17 => (
            779000000,
            928000000,
            22,
            "779 - 928 Mhz",
            Some("rnode_firmware_techo.zip"),
            "SX1262",
        ),
        0x21 => (
            820000000,
            960000000,
            22,
            "820 - 960 MHz",
            Some("rnode_firmware_opencom_xl.zip"),
            "SX1262 + SX1280",
        ),
        0xDE => (
            420000000,
            520000000,
            22,
            "420 - 520 MHz",
            Some("rnode_firmware_xiao_esp32s3.zip"),
            "SX1262",
        ),
        0xDD => (
            850000000,
            950000000,
            22,
            "850 - 950 MHz",
            Some("rnode_firmware_xiao_esp32s3.zip"),
            "SX1262",
        ),
        0xFE => (
            100000000,
            1100000000,
            17,
            "(Band capabilities unknown)",
            None,
            "Unknown",
        ),
        0xFF => (
            100000000,
            1100000000,
            14,
            "(Band capabilities unknown)",
            None,
            "Unknown",
        ),
        _ => return None,
    };
    Some(Model {
        min_freq,
        max_freq,
        max_output,
        band,
        firmware,
        modem,
    })
}
