//! RNode-specific KISS protocol commands and streaming decoder.
//!
//! Extends `kiss.rs` with RNode command constants, multi-byte responses,
//! and subinterface routing for multi-radio RNode devices.
//! Matches Python `RNodeInterface.py` and `RNodeMultiInterface.py`.

use crate::kiss;

// ── RNode KISS command bytes ────────────────────────────────────────────

pub const CMD_FREQUENCY: u8 = 0x01;
pub const CMD_BANDWIDTH: u8 = 0x02;
pub const CMD_TXPOWER: u8 = 0x03;
pub const CMD_SF: u8 = 0x04;
pub const CMD_CR: u8 = 0x05;
pub const CMD_RADIO_STATE: u8 = 0x06;
pub const CMD_RADIO_LOCK: u8 = 0x07;
pub const CMD_DETECT: u8 = 0x08;
pub const CMD_LEAVE: u8 = 0x0A;
pub const CMD_ST_ALOCK: u8 = 0x0B;
pub const CMD_LT_ALOCK: u8 = 0x0C;
pub const CMD_READY: u8 = 0x0F;
pub const CMD_SEL_INT: u8 = 0x1F;
pub const CMD_STAT_RSSI: u8 = 0x23;
pub const CMD_STAT_SNR: u8 = 0x24;
pub const CMD_RANDOM: u8 = 0x40;
pub const CMD_PLATFORM: u8 = 0x48;
pub const CMD_MCU: u8 = 0x49;
pub const CMD_FW_VERSION: u8 = 0x50;
pub const CMD_RESET: u8 = 0x55;
pub const CMD_INTERFACES: u8 = 0x71;
pub const CMD_ERROR: u8 = 0x90;

pub const DETECT_REQ: u8 = 0x73;
pub const DETECT_RESP: u8 = 0x46;

pub const RADIO_STATE_OFF: u8 = 0x00;
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
    CMD_INT0_DATA, CMD_INT1_DATA, CMD_INT2_DATA, CMD_INT3_DATA,
    CMD_INT4_DATA, CMD_INT5_DATA, CMD_INT6_DATA, CMD_INT7_DATA,
    CMD_INT8_DATA, CMD_INT9_DATA, CMD_INT10_DATA, CMD_INT11_DATA,
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
    DataFrame { index: usize, data: Vec<u8> },
    /// Device detection response.
    Detected(bool),
    /// Firmware version reported.
    FirmwareVersion { major: u8, minor: u8 },
    /// Platform byte reported.
    Platform(u8),
    /// MCU byte reported.
    Mcu(u8),
    /// Interface type for a given index.
    InterfaceType { index: u8, type_byte: u8 },
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
    /// Reported short-term airtime lock (percent * 100).
    StAlock(u16),
    /// Reported long-term airtime lock (percent * 100).
    LtAlock(u16),
    /// Flow control: device ready for next packet.
    Ready,
    /// Selected subinterface changed.
    SelectedInterface(u8),
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
                } else if self.command == kiss::CMD_DATA || data_cmd_to_index(self.command).is_some()
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
                if buf.len() >= 1 {
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
                if buf.len() >= 1 {
                    events.push(RNodeEvent::Platform(buf[0]));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_MCU => {
                if buf.len() >= 1 {
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
                    let freq =
                        (buf[0] as u32) << 24 | (buf[1] as u32) << 16 | (buf[2] as u32) << 8 | buf[3] as u32;
                    events.push(RNodeEvent::Frequency(freq));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_BANDWIDTH => {
                if buf.len() >= 4 {
                    let bw =
                        (buf[0] as u32) << 24 | (buf[1] as u32) << 16 | (buf[2] as u32) << 8 | buf[3] as u32;
                    events.push(RNodeEvent::Bandwidth(bw));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_TXPOWER => {
                if buf.len() >= 1 {
                    events.push(RNodeEvent::TxPower(buf[0] as i8));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_SF => {
                if buf.len() >= 1 {
                    events.push(RNodeEvent::SpreadingFactor(buf[0]));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_CR => {
                if buf.len() >= 1 {
                    events.push(RNodeEvent::CodingRate(buf[0]));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_RADIO_STATE => {
                if buf.len() >= 1 {
                    events.push(RNodeEvent::RadioState(buf[0]));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_STAT_RSSI => {
                if buf.len() >= 1 {
                    events.push(RNodeEvent::StatRssi(buf[0]));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_STAT_SNR => {
                if buf.len() >= 1 {
                    events.push(RNodeEvent::StatSnr(buf[0] as i8));
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
                if buf.len() >= 1 {
                    self.selected_index = buf[0];
                    events.push(RNodeEvent::SelectedInterface(buf[0]));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            CMD_ERROR => {
                if buf.len() >= 1 {
                    events.push(RNodeEvent::Error(buf[0]));
                    self.command = kiss::CMD_UNKNOWN;
                    self.in_frame = false;
                }
            }
            _ => {
                // Unknown command, ignore
            }
        }
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
}
