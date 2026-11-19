//! RNode-specific KISS protocol commands and streaming decoder.
//!
//! Extends `kiss.rs` with RNode command constants, multi-byte responses,
//! and subinterface routing for multi-radio RNode devices.
//! Matches Python `RNodeInterface.py` and `RNodeMultiInterface.py`.

use crate::kiss;

// ── RNode KISS command bytes ────────────────────────────────────────────

/// Set or report the radio frequency (4 bytes, big-endian, Hz).
pub const CMD_FREQUENCY: u8 = 0x01;
/// Set or report the radio bandwidth (4 bytes, big-endian, Hz).
pub const CMD_BANDWIDTH: u8 = 0x02;
/// Set or report the TX power (1 byte, dBm).
pub const CMD_TXPOWER: u8 = 0x03;
/// Set or report the LoRa spreading factor.
pub const CMD_SF: u8 = 0x04;
/// Set or report the LoRa coding rate.
pub const CMD_CR: u8 = 0x05;
/// Set or report the radio state (`RADIO_STATE_OFF` / `RADIO_STATE_ON`).
pub const CMD_RADIO_STATE: u8 = 0x06;
/// Radio lock state report, as upstream's `CMD_RADIO_LOCK`.
pub const CMD_RADIO_LOCK: u8 = 0x07;
/// Device detection; the request carries `DETECT_REQ`, the reply `DETECT_RESP`.
pub const CMD_DETECT: u8 = 0x08;
/// Tell the device the host is leaving (sent with value `0xFF`).
pub const CMD_LEAVE: u8 = 0x0A;
/// Set or report the short-term airtime limit (percent * 100, 2 bytes big-endian).
pub const CMD_ST_ALOCK: u8 = 0x0B;
/// Set or report the long-term airtime limit (percent * 100, 2 bytes big-endian).
pub const CMD_LT_ALOCK: u8 = 0x0C;
/// Flow control: the device is ready for the next packet.
pub const CMD_READY: u8 = 0x0F;
/// Select the subinterface that following commands apply to.
pub const CMD_SEL_INT: u8 = 0x1F;
/// RSSI of the last received packet (raw byte, RSSI plus 157).
pub const CMD_STAT_RSSI: u8 = 0x23;
/// SNR of the last received packet (signed, in 0.25 dB steps).
pub const CMD_STAT_SNR: u8 = 0x24;
/// Channel airtime, load and noise statistics.
pub const CMD_STAT_CHTM: u8 = 0x25;
/// Radio PHY timing parameters.
pub const CMD_STAT_PHYPRM: u8 = 0x26;
/// Battery state and charge percent.
pub const CMD_STAT_BAT: u8 = 0x27;
/// CSMA contention window parameters.
pub const CMD_STAT_CSMA: u8 = 0x28;
/// Device temperature.
pub const CMD_STAT_TEMP: u8 = 0x29;
/// Random byte from the device, as upstream's `CMD_RANDOM`.
pub const CMD_RANDOM: u8 = 0x40;
/// Device platform byte.
pub const CMD_PLATFORM: u8 = 0x48;
/// Device MCU byte.
pub const CMD_MCU: u8 = 0x49;
/// Firmware version (major, minor).
pub const CMD_FW_VERSION: u8 = 0x50;
/// Detailed firmware version string (upstream's `CMD_ROM_READ`, same byte).
pub const CMD_FW_DETAIL: u8 = 0x51;
/// Reset the device, as upstream's `CMD_RESET`.
pub const CMD_RESET: u8 = 0x55;
/// Subinterface list query; each reply carries an index and a type byte.
pub const CMD_INTERFACES: u8 = 0x71;
/// Error report from the device (1-byte error code).
pub const CMD_ERROR: u8 = 0x90;

/// Value sent with `CMD_DETECT` to probe for an RNode.
pub const DETECT_REQ: u8 = 0x73;
/// Value an RNode answers `CMD_DETECT` with.
pub const DETECT_RESP: u8 = 0x46;

/// `CMD_RADIO_STATE` value: radio off.
pub const RADIO_STATE_OFF: u8 = 0x00;
/// `CMD_RADIO_STATE` value: radio on.
pub const RADIO_STATE_ON: u8 = 0x01;

// Subinterface data command bytes (from RNodeMultiInterface.py)
const CMD_INT0_DATA: u8 = 0x00;
const CMD_INT1_DATA: u8 = 0x10;
const CMD_INT2_DATA: u8 = 0x20;
const CMD_INT3_DATA: u8 = 0x70;
const CMD_INT4_DATA: u8 = 0x75;
const CMD_INT5_DATA: u8 = 0x90;
const CMD_INT6_DATA: u8 = 0xA0;
const CMD_INT7_DATA: u8 = 0xB0;
const CMD_INT8_DATA: u8 = 0xC0;
const CMD_INT9_DATA: u8 = 0xD0;
const CMD_INT10_DATA: u8 = 0xE0;
const CMD_INT11_DATA: u8 = 0xF0;

/// All subinterface data command bytes, indexed by subinterface number.
const DATA_CMDS: [u8; 12] = [
    CMD_INT0_DATA,
    CMD_INT1_DATA,
    CMD_INT2_DATA,
    CMD_INT3_DATA,
    CMD_INT4_DATA,
    CMD_INT5_DATA,
    CMD_INT6_DATA,
    CMD_INT7_DATA,
    CMD_INT8_DATA,
    CMD_INT9_DATA,
    CMD_INT10_DATA,
    CMD_INT11_DATA,
];

/// Map a command byte to a subinterface data index, or None.
fn data_cmd_to_index(cmd: u8) -> Option<usize> {
    DATA_CMDS.iter().position(|&c| c == cmd)
}

// ── Events ──────────────────────────────────────────────────────────────

/// Events yielded by the RNode decoder.
#[derive(Debug, Clone, PartialEq)]
pub enum RNodeEvent {
    /// A data frame was received on the given subinterface.
    DataFrame {
        /// Subinterface index.
        index: usize,
        /// Unescaped frame payload.
        data: Vec<u8>,
    },
    /// Device detection response.
    Detected(bool),
    /// Firmware version reported.
    FirmwareVersion {
        /// Major version.
        major: u8,
        /// Minor version.
        minor: u8,
    },
    /// Platform byte reported.
    Platform(u8),
    /// MCU byte reported.
    Mcu(u8),
    /// Interface type for a given index.
    InterfaceType {
        /// Subinterface index.
        index: u8,
        /// Raw radio type byte reported by the device.
        type_byte: u8,
    },
    /// Reported frequency (Hz).
    Frequency(u32),
    /// Reported bandwidth (Hz).
    Bandwidth(u32),
    /// Reported TX power (dBm, signed).
    TxPower(i8),
    /// Reported spreading factor.
    SpreadingFactor(u8),
    /// Reported coding rate.
    CodingRate(u8),
    /// Reported radio state.
    RadioState(u8),
    /// Reported RSSI (raw byte, caller subtracts RSSI_OFFSET=157).
    StatRssi(u8),
    /// Reported SNR (signed, multiply by 0.25 for dB).
    StatSnr(i8),
    /// Channel state (`CMD_STAT_CHTM`): airtime and channel load in
    /// hundredths of a percent, RSSI values plus 157 (interference 0xFF:
    /// none).
    ChannelStats {
        /// Short-term airtime, percent * 100.
        airtime_short: u16,
        /// Long-term airtime, percent * 100.
        airtime_long: u16,
        /// Short-term channel load, percent * 100.
        channel_load_short: u16,
        /// Long-term channel load, percent * 100.
        channel_load_long: u16,
        /// Current RSSI, dBm plus 157.
        current_rssi: u8,
        /// Noise floor, dBm plus 157.
        noise_floor: u8,
        /// Interference level, dBm plus 157; 0xFF means none.
        interference: u8,
    },
    /// Radio timing (`CMD_STAT_PHYPRM`): symbol time in µs, symbol rate,
    /// preamble in symbols and ms, CSMA slot and DIFS in ms.
    PhyStats {
        /// Symbol time in microseconds.
        symbol_time_us: u16,
        /// Symbol rate in baud.
        symbol_rate: u16,
        /// Preamble length in symbols.
        preamble_symbols: u16,
        /// Preamble length in milliseconds.
        preamble_ms: u16,
        /// CSMA slot time in milliseconds.
        csma_slot_ms: u16,
        /// DIFS in milliseconds.
        difs_ms: u16,
    },
    /// CSMA contention window (`CMD_STAT_CSMA`): band and bounds in slots.
    CsmaStats {
        /// Contention window band.
        band: u8,
        /// Lower bound of the window, in slots.
        window_min: u8,
        /// Upper bound of the window, in slots.
        window_max: u8,
    },
    /// Battery (`CMD_STAT_BAT`): state (0 unknown, 1 discharging,
    /// 2 charging, 3 charged) and percent.
    Battery {
        /// 0 unknown, 1 discharging, 2 charging, 3 charged.
        state: u8,
        /// Charge in percent.
        percent: u8,
    },
    /// Device temperature (`CMD_STAT_TEMP`), °C plus 120.
    Temperature(u8),
    /// Reported short-term airtime lock (percent * 100).
    StAlock(u16),
    /// Reported long-term airtime lock (percent * 100).
    LtAlock(u16),
    /// Flow control: device ready for next packet.
    Ready,
    /// Selected subinterface changed.
    SelectedInterface(u8),
    /// Detailed firmware version string (e.g. "0.1.142-f63fb02").
    FirmwareDetail(String),
    /// Error code from device.
    Error(u8),
}

// ── Decoder ─────────────────────────────────────────────────────────────

/// Streaming RNode KISS decoder.
///
/// Handles KISS framing, KISS escape sequences, multi-byte command
/// responses, and subinterface data routing.
pub struct RNodeDecoder {
    in_frame: bool,
    escape: bool,
    command: u8,
    data_buffer: Vec<u8>,
    command_buffer: Vec<u8>,
    selected_index: u8,
}

impl RNodeDecoder {
    /// Create a decoder outside any frame, with subinterface 0 selected.
    pub fn new() -> Self {
        RNodeDecoder {
            in_frame: false,
            escape: false,
            command: kiss::CMD_UNKNOWN,
            data_buffer: Vec::new(),
            command_buffer: Vec::new(),
            selected_index: 0,
        }
    }

    /// Current selected subinterface index.
    pub fn selected_index(&self) -> u8 {
        self.selected_index
    }

    /// Feed raw bytes and return decoded events.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<RNodeEvent> {
        let mut events = Vec::new();

        for &byte in bytes {
            if self.in_frame && byte == kiss::FEND {
                // End of frame — check if we have buffered data for a data command
                if let Some(idx) = data_cmd_to_index(self.command) {
                    if !self.data_buffer.is_empty() {
                        events.push(RNodeEvent::DataFrame {
                            index: idx,
                            data: core::mem::take(&mut self.data_buffer),
                        });
                    }
                } else if self.command == kiss::CMD_DATA {
                    if !self.data_buffer.is_empty() {
                        events.push(RNodeEvent::DataFrame {
                            index: self.selected_index as usize,
                            data: core::mem::take(&mut self.data_buffer),
                        });
                    }
                } else if self.command == CMD_FW_DETAIL && !self.data_buffer.is_empty() {
                    let s = String::from_utf8_lossy(&self.data_buffer).into_owned();
                    events.push(RNodeEvent::FirmwareDetail(s));
                    self.data_buffer.clear();
                }
                // Start new frame (closing FLAG = opening FLAG of next)
                self.in_frame = true;
                self.command = kiss::CMD_UNKNOWN;
                self.data_buffer.clear();
                self.command_buffer.clear();
                self.escape = false;
            } else if byte == kiss::FEND {
                // Opening frame
                self.in_frame = true;
                self.command = kiss::CMD_UNKNOWN;
                self.data_buffer.clear();
                self.command_buffer.clear();
                self.escape = false;
            } else if self.in_frame {
                if self.data_buffer.is_empty()
                    && self.command_buffer.is_empty()
                    && self.command == kiss::CMD_UNKNOWN
                {
                    // First byte after FEND is the command
                    self.command = byte;
                } else if self.command == kiss::CMD_DATA
                    || self.command == CMD_FW_DETAIL
                    || data_cmd_to_index(self.command).is_some()
                {
                    // Data frame: accumulate with KISS unescaping
                    if byte == kiss::FESC {
                        self.escape = true;
                    } else if self.escape {
                        match byte {
                            kiss::TFEND => self.data_buffer.push(kiss::FEND),
                            kiss::TFESC => self.data_buffer.push(kiss::FESC),
                            _ => self.data_buffer.push(byte),
                        }
                        self.escape = false;
                    } else {
                        self.data_buffer.push(byte);
                    }
                } else {
                    // Command response: accumulate with KISS unescaping, then parse
                    let val = if byte == kiss::FESC {
                        self.escape = true;
                        continue;
                    } else if self.escape {
                        self.escape = false;
                        match byte {
                            kiss::TFEND => kiss::FEND,
                            kiss::TFESC => kiss::FESC,
                            _ => byte,
                        }
                    } else {
                        byte
                    };

                    self.command_buffer.push(val);
                    self.parse_command(&mut events);
                }
            }
        }

        events
    }

    /// Check if a complete command response has been accumulated and emit event.
    fn parse_command(&mut self, events: &mut Vec<RNodeEvent>) {
        let buf = &self.command_buffer;
        match self.command {
            CMD_DETECT => {
                if !buf.is_empty() {
                    events.push(RNodeEvent::Detected(buf[0] == DETECT_RESP));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_FW_VERSION => {
                if buf.len() >= 2 {
                    events.push(RNodeEvent::FirmwareVersion {
                        major: buf[0],
                        minor: buf[1],
                    });
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_PLATFORM => {
                if !buf.is_empty() {
                    events.push(RNodeEvent::Platform(buf[0]));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_MCU => {
                if !buf.is_empty() {
                    events.push(RNodeEvent::Mcu(buf[0]));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_INTERFACES => {
                if buf.len() >= 2 {
                    events.push(RNodeEvent::InterfaceType {
                        index: buf[0],
                        type_byte: buf[1],
                    });
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_FREQUENCY => {
                if buf.len() >= 4 {
                    let freq = (buf[0] as u32) << 24
                        | (buf[1] as u32) << 16
                        | (buf[2] as u32) << 8
                        | buf[3] as u32;
                    events.push(RNodeEvent::Frequency(freq));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_BANDWIDTH => {
                if buf.len() >= 4 {
                    let bw = (buf[0] as u32) << 24
                        | (buf[1] as u32) << 16
                        | (buf[2] as u32) << 8
                        | buf[3] as u32;
                    events.push(RNodeEvent::Bandwidth(bw));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_TXPOWER => {
                if !buf.is_empty() {
                    events.push(RNodeEvent::TxPower(buf[0] as i8));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_SF => {
                if !buf.is_empty() {
                    events.push(RNodeEvent::SpreadingFactor(buf[0]));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_CR => {
                if !buf.is_empty() {
                    events.push(RNodeEvent::CodingRate(buf[0]));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_RADIO_STATE => {
                if !buf.is_empty() {
                    events.push(RNodeEvent::RadioState(buf[0]));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_STAT_RSSI => {
                if !buf.is_empty() {
                    events.push(RNodeEvent::StatRssi(buf[0]));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_STAT_SNR => {
                if !buf.is_empty() {
                    events.push(RNodeEvent::StatSnr(buf[0] as i8));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_STAT_CHTM => {
                if buf.len() >= 11 {
                    let be = |i: usize| u16::from_be_bytes([buf[i], buf[i + 1]]);
                    events.push(RNodeEvent::ChannelStats {
                        airtime_short: be(0),
                        airtime_long: be(2),
                        channel_load_short: be(4),
                        channel_load_long: be(6),
                        current_rssi: buf[8],
                        noise_floor: buf[9],
                        interference: buf[10],
                    });
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_STAT_PHYPRM => {
                if buf.len() >= 12 {
                    let be = |i: usize| u16::from_be_bytes([buf[i], buf[i + 1]]);
                    events.push(RNodeEvent::PhyStats {
                        symbol_time_us: be(0),
                        symbol_rate: be(2),
                        preamble_symbols: be(4),
                        preamble_ms: be(6),
                        csma_slot_ms: be(8),
                        difs_ms: be(10),
                    });
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_STAT_CSMA => {
                if buf.len() >= 3 {
                    events.push(RNodeEvent::CsmaStats {
                        band: buf[0],
                        window_min: buf[1],
                        window_max: buf[2],
                    });
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_STAT_BAT => {
                if buf.len() >= 2 {
                    events.push(RNodeEvent::Battery {
                        state: buf[0],
                        percent: buf[1],
                    });
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_STAT_TEMP => {
                if !buf.is_empty() {
                    events.push(RNodeEvent::Temperature(buf[0]));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_ST_ALOCK => {
                if buf.len() >= 2 {
                    let val = (buf[0] as u16) << 8 | buf[1] as u16;
                    events.push(RNodeEvent::StAlock(val));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_LT_ALOCK => {
                if buf.len() >= 2 {
                    let val = (buf[0] as u16) << 8 | buf[1] as u16;
                    events.push(RNodeEvent::LtAlock(val));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_READY => {
                events.push(RNodeEvent::Ready);
                self.command = kiss::CMD_UNKNOWN;
                self.in_frame = false;
            }
            CMD_SEL_INT => {
                if !buf.is_empty() {
                    self.selected_index = buf[0];
                    events.push(RNodeEvent::SelectedInterface(buf[0]));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_ERROR if !buf.is_empty() => {
                events.push(RNodeEvent::Error(buf[0]));
                self.command = kiss::CMD_UNKNOWN;
                self.in_frame = false;
            }
            _ => {
                // Unknown command, ignore
            }
        }
    }
}

impl Default for RNodeDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Command builders ────────────────────────────────────────────────────

/// Build a KISS command frame: [FEND][cmd][escaped value][FEND].
pub fn rnode_command(cmd: u8, value: &[u8]) -> Vec<u8> {
    let escaped = kiss::escape(value);
    let mut out = Vec::with_capacity(escaped.len() + 3);
    out.push(kiss::FEND);
    out.push(cmd);
    out.extend_from_slice(&escaped);
    out.push(kiss::FEND);
    out
}

/// Build a command frame with subinterface selection prefix:
/// [FEND][CMD_SEL_INT][index][FEND][cmd][escaped value][FEND].
pub fn rnode_select_command(index: u8, cmd: u8, value: &[u8]) -> Vec<u8> {
    let mut out = rnode_command(CMD_SEL_INT, &[index]);
    out.extend_from_slice(&rnode_command(cmd, value));
    out
}

/// Build the detect request frame.
pub fn detect_request() -> Vec<u8> {
    rnode_command(CMD_DETECT, &[DETECT_REQ])
}

/// Tell the device the host is leaving (upstream `RNodeInterface.leave`).
pub fn leave_request() -> Vec<u8> {
    rnode_command(CMD_LEAVE, &[0xFF])
}

/// Build a data frame for a subinterface:
/// [FEND][CMD_INTn_DATA][escaped data][FEND].
pub fn rnode_data_frame(index: u8, data: &[u8]) -> Vec<u8> {
    let cmd = if (index as usize) < DATA_CMDS.len() {
        DATA_CMDS[index as usize]
    } else {
        CMD_INT0_DATA
    };
    let escaped = kiss::escape(data);
    let mut out = Vec::with_capacity(escaped.len() + 3);
    out.push(kiss::FEND);
    out.push(cmd);
    out.extend_from_slice(&escaped);
    out.push(kiss::FEND);
    out
}

/// Build the Python `RNodeMultiInterface` transmit sequence. Outbound multi
/// frames select the actual virtual port and then use `CMD_DATA`; the
/// `CMD_INTn_DATA` values are device-to-host demultiplexing commands.
pub fn rnode_multi_data_frame(index: u8, data: &[u8]) -> Vec<u8> {
    rnode_select_command(index, kiss::CMD_DATA, data)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_request_format() {
        let req = detect_request();
        assert_eq!(req, vec![kiss::FEND, CMD_DETECT, DETECT_REQ, kiss::FEND]);
    }

    #[test]
    fn decoder_detect_response() {
        let response = vec![kiss::FEND, CMD_DETECT, DETECT_RESP, kiss::FEND];
        let mut decoder = RNodeDecoder::new();
        let events = decoder.feed(&response);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], RNodeEvent::Detected(true));
    }

    #[test]
    fn decoder_firmware_version() {
        // Version 1.52 with KISS escaping possible
        let response = vec![kiss::FEND, CMD_FW_VERSION, 0x01, 0x34, kiss::FEND];
        let mut decoder = RNodeDecoder::new();
        let events = decoder.feed(&response);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            RNodeEvent::FirmwareVersion {
                major: 1,
                minor: 0x34
            }
        );
    }

    #[test]
    fn decoder_platform() {
        let response = vec![kiss::FEND, CMD_PLATFORM, 0x80, kiss::FEND]; // ESP32
        let mut decoder = RNodeDecoder::new();
        let events = decoder.feed(&response);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], RNodeEvent::Platform(0x80));
    }

    #[test]
    fn decoder_interfaces() {
        let response = vec![kiss::FEND, CMD_INTERFACES, 0x00, 0x01, kiss::FEND];
        let mut decoder = RNodeDecoder::new();
        let events = decoder.feed(&response);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            RNodeEvent::InterfaceType {
                index: 0,
                type_byte: 0x01
            }
        );
    }

    #[test]
    fn decoder_frequency() {
        // 868200000 Hz = 0x33C15740 (but let's use a simpler value)
        // 867200000 Hz = 0x33B5_D100
        let freq: u32 = 867_200_000;
        let response = vec![
            kiss::FEND,
            CMD_FREQUENCY,
            (freq >> 24) as u8,
            (freq >> 16) as u8,
            (freq >> 8) as u8,
            (freq & 0xFF) as u8,
            kiss::FEND,
        ];
        let mut decoder = RNodeDecoder::new();
        let events = decoder.feed(&response);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], RNodeEvent::Frequency(867_200_000));
    }

    #[test]
    fn decoder_data_frame_int0() {
        let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        // CMD_INT0_DATA = 0x00 (same as CMD_DATA)
        let mut frame = vec![kiss::FEND, CMD_INT0_DATA];
        frame.extend_from_slice(&kiss::escape(&payload));
        frame.push(kiss::FEND);

        let mut decoder = RNodeDecoder::new();
        let events = decoder.feed(&frame);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            RNodeEvent::DataFrame {
                index: 0,
                data: payload
            }
        );
    }

    #[test]
    fn decoder_multi_sub_data() {
        let payload = vec![0xAA, 0xBB];
        // CMD_INT1_DATA = 0x10
        let mut frame = vec![kiss::FEND, CMD_INT1_DATA];
        frame.extend_from_slice(&kiss::escape(&payload));
        frame.push(kiss::FEND);

        let mut decoder = RNodeDecoder::new();
        let events = decoder.feed(&frame);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            RNodeEvent::DataFrame {
                index: 1,
                data: payload
            }
        );
    }

    #[test]
    fn rnode_select_command_format() {
        // Select subinterface 1, then set frequency
        let freq: u32 = 868_000_000;
        let freq_bytes = [
            (freq >> 24) as u8,
            (freq >> 16) as u8,
            (freq >> 8) as u8,
            (freq & 0xFF) as u8,
        ];
        let cmd = rnode_select_command(1, CMD_FREQUENCY, &freq_bytes);

        // Should start with [FEND][CMD_SEL_INT][0x01][FEND]
        assert_eq!(cmd[0], kiss::FEND);
        assert_eq!(cmd[1], CMD_SEL_INT);
        assert_eq!(cmd[2], 0x01);
        assert_eq!(cmd[3], kiss::FEND);

        // Then [FEND][CMD_FREQUENCY][escaped bytes][FEND]
        assert_eq!(cmd[4], kiss::FEND);
        assert_eq!(cmd[5], CMD_FREQUENCY);
    }

    #[test]
    fn rnode_data_frame_format() {
        let data = vec![0x01, 0x02, 0x03];
        let frame = rnode_data_frame(0, &data);
        assert_eq!(frame[0], kiss::FEND);
        assert_eq!(frame[1], CMD_INT0_DATA);
        assert_eq!(*frame.last().unwrap(), kiss::FEND);

        // Subinterface 1
        let frame1 = rnode_data_frame(1, &data);
        assert_eq!(frame1[1], CMD_INT1_DATA);

        // Subinterface 2
        let frame2 = rnode_data_frame(2, &data);
        assert_eq!(frame2[1], CMD_INT2_DATA);
    }

    #[test]
    fn rnode_multi_data_frame_selects_actual_virtual_port() {
        let frame = rnode_multi_data_frame(7, &[1, 2, 3]);
        assert_eq!(
            frame,
            vec![
                kiss::FEND,
                CMD_SEL_INT,
                7,
                kiss::FEND,
                kiss::FEND,
                kiss::CMD_DATA,
                1,
                2,
                3,
                kiss::FEND,
            ]
        );
    }

    #[test]
    fn decoder_device_reports() {
        // Bytes as RNode firmware 1.86 sends them (kiss_indicate_*), an
        // escaped FEND inside the channel stats.
        let mut stream = vec![
            kiss::FEND,
            CMD_STAT_CHTM,
            0x00,
            0x7B,
            0x13,
            0x88,
            0x09,
            0xC4,
            0x27,
            0x10,
            47,
            kiss::FESC,
            kiss::TFEND,
            0xFF,
            kiss::FEND,
        ];
        stream.extend_from_slice(&[
            kiss::FEND,
            CMD_STAT_PHYPRM,
            0x08,
            0x00,
            0x01,
            0xE8,
            0,
            18,
            0,
            37,
            0,
            24,
            0,
            48,
            kiss::FEND,
        ]);
        stream.extend_from_slice(&[kiss::FEND, CMD_STAT_CSMA, 1, 0, 14, kiss::FEND]);
        stream.extend_from_slice(&[kiss::FEND, CMD_STAT_BAT, 1, 91, kiss::FEND]);
        stream.extend_from_slice(&[kiss::FEND, CMD_STAT_TEMP, 178, kiss::FEND]);
        let events = RNodeDecoder::new().feed(&stream);
        assert_eq!(
            events,
            vec![
                RNodeEvent::ChannelStats {
                    airtime_short: 123,
                    airtime_long: 5000,
                    channel_load_short: 2500,
                    channel_load_long: 10_000,
                    current_rssi: 47,
                    noise_floor: kiss::FEND,
                    interference: 0xFF,
                },
                RNodeEvent::PhyStats {
                    symbol_time_us: 2048,
                    symbol_rate: 488,
                    preamble_symbols: 18,
                    preamble_ms: 37,
                    csma_slot_ms: 24,
                    difs_ms: 48,
                },
                RNodeEvent::CsmaStats {
                    band: 1,
                    window_min: 0,
                    window_max: 14,
                },
                RNodeEvent::Battery {
                    state: 1,
                    percent: 91,
                },
                RNodeEvent::Temperature(178),
            ]
        );
    }
}
