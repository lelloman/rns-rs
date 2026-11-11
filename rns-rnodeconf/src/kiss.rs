#![allow(dead_code)] // The full table; later stages use the rest.
//! The KISS framing and command set RNode firmware speaks, as upstream
//! `rnodeconf.py`'s `KISS` class defines it.

pub const FEND: u8 = 0xC0;
pub const FESC: u8 = 0xDB;
pub const TFEND: u8 = 0xDC;
pub const TFESC: u8 = 0xDD;
pub const CMD_UNKNOWN: u8 = 0xFE;
pub const CMD_DATA: u8 = 0x00;
pub const CMD_FREQUENCY: u8 = 0x01;
pub const CMD_BANDWIDTH: u8 = 0x02;
pub const CMD_TXPOWER: u8 = 0x03;
pub const CMD_SF: u8 = 0x04;
pub const CMD_CR: u8 = 0x05;
pub const CMD_RADIO_STATE: u8 = 0x06;
pub const CMD_RADIO_LOCK: u8 = 0x07;
pub const CMD_DETECT: u8 = 0x08;
pub const CMD_LEAVE: u8 = 0x0A;
pub const CMD_READY: u8 = 0x0F;
pub const CMD_STAT_RX: u8 = 0x21;
pub const CMD_STAT_TX: u8 = 0x22;
pub const CMD_STAT_RSSI: u8 = 0x23;
pub const CMD_STAT_SNR: u8 = 0x24;
pub const CMD_BLINK: u8 = 0x30;
pub const CMD_RANDOM: u8 = 0x40;
pub const CMD_DISP_INT: u8 = 0x45;
pub const CMD_NP_INT: u8 = 0x65;
pub const CMD_DISP_ADR: u8 = 0x63;
pub const CMD_DISP_BLNK: u8 = 0x64;
pub const CMD_DISP_ROT: u8 = 0x67;
pub const CMD_DISP_RCND: u8 = 0x68;
pub const CMD_BT_CTRL: u8 = 0x46;
pub const CMD_BT_PIN: u8 = 0x62;
pub const CMD_DIS_IA: u8 = 0x69;
pub const CMD_WIFI_MODE: u8 = 0x6A;
pub const CMD_WIFI_SSID: u8 = 0x6B;
pub const CMD_WIFI_PSK: u8 = 0x6C;
pub const CMD_WIFI_CHN: u8 = 0x6E;
pub const CMD_WIFI_IP: u8 = 0x84;
pub const CMD_WIFI_NM: u8 = 0x85;
pub const CMD_BOARD: u8 = 0x47;
pub const CMD_PLATFORM: u8 = 0x48;
pub const CMD_MCU: u8 = 0x49;
pub const CMD_FW_VERSION: u8 = 0x50;
pub const CMD_CFG_READ: u8 = 0x6D;
pub const CMD_ROM_READ: u8 = 0x51;
pub const CMD_ROM_WRITE: u8 = 0x52;
pub const CMD_ROM_WIPE: u8 = 0x59;
pub const CMD_CONF_SAVE: u8 = 0x53;
pub const CMD_CONF_DELETE: u8 = 0x54;
pub const CMD_RESET: u8 = 0x55;
pub const CMD_DEV_HASH: u8 = 0x56;
pub const CMD_DEV_SIG: u8 = 0x57;
pub const CMD_HASHES: u8 = 0x60;
pub const CMD_FW_HASH: u8 = 0x58;
pub const CMD_FW_UPD: u8 = 0x61;
pub const DETECT_REQ: u8 = 0x73;
pub const DETECT_RESP: u8 = 0x46;
pub const RADIO_STATE_OFF: u8 = 0x00;
pub const RADIO_STATE_ON: u8 = 0x01;
pub const RADIO_STATE_ASK: u8 = 0xFF;
pub const CMD_ERROR: u8 = 0x90;
pub const ERROR_INITRADIO: u8 = 0x01;
pub const ERROR_TXFAILED: u8 = 0x02;
pub const ERROR_EEPROM_LOCKED: u8 = 0x03;

/// Escape `FESC` and `FEND` in a frame payload.
pub fn escape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for &byte in data {
        match byte {
            FESC => out.extend_from_slice(&[FESC, TFESC]),
            FEND => out.extend_from_slice(&[FESC, TFEND]),
            _ => out.push(byte),
        }
    }
    out
}

/// A command frame: `FEND`, the command, the escaped payload, `FEND`.
pub fn frame(command: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![FEND, command];
    out.extend_from_slice(&escape(payload));
    out.push(FEND);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_matches_upstream_order() {
        // Upstream replaces FESC first, then FEND.
        assert_eq!(
            escape(&[0xc0, 0xdb, 0x01]),
            vec![0xdb, 0xdc, 0xdb, 0xdd, 0x01]
        );
        assert_eq!(frame(CMD_TXPOWER, &[17]), vec![FEND, CMD_TXPOWER, 17, FEND]);
    }
}
