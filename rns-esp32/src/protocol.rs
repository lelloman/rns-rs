const FEND: u8 = 0xC0;
const FESC: u8 = 0xDB;
const TFEND: u8 = 0xDC;
const TFESC: u8 = 0xDD;

pub const CMD_DATA: u8 = 0x00;
pub const CMD_FREQUENCY: u8 = 0x01;
pub const CMD_BANDWIDTH: u8 = 0x02;
pub const CMD_TXPOWER: u8 = 0x03;
pub const CMD_SF: u8 = 0x04;
pub const CMD_CR: u8 = 0x05;
pub const CMD_RADIO_STATE: u8 = 0x06;
pub const CMD_DETECT: u8 = 0x08;
pub const CMD_LEAVE: u8 = 0x0A;
pub const CMD_ST_ALOCK: u8 = 0x0B;
pub const CMD_LT_ALOCK: u8 = 0x0C;
pub const CMD_READY: u8 = 0x0F;
pub const CMD_STAT_RX: u8 = 0x21;
pub const CMD_STAT_TX: u8 = 0x22;
pub const CMD_STAT_RSSI: u8 = 0x23;
pub const CMD_STAT_SNR: u8 = 0x24;
pub const CMD_STAT_CHTM: u8 = 0x25;
pub const CMD_STAT_PHYPRM: u8 = 0x26;
pub const CMD_STAT_CSMA: u8 = 0x28;
pub const CMD_PLATFORM: u8 = 0x48;
pub const CMD_MCU: u8 = 0x49;
pub const CMD_FW_VERSION: u8 = 0x50;
pub const CMD_FW_DETAIL: u8 = 0x51;

pub const DETECT_REQ: u8 = 0x73;
pub const DETECT_RESP: u8 = 0x46;
pub const RADIO_STATE_ON: u8 = 0x01;

const FREQ_MIN_HZ: u32 = 137_000_000;
const FREQ_MAX_HZ: u32 = 1_020_000_000;
const TX_POWER_MIN_DBM: i8 = 0;
const TX_POWER_MAX_DBM: i8 = 22;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KissFrame {
    pub command: u8,
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RadioConfig {
    pub frequency: u32,
    pub bandwidth: u32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub tx_power: i8,
}

pub struct KissDecoder {
    in_frame: bool,
    escape: bool,
    command: u8,
    buffer: Vec<u8>,
}

impl KissDecoder {
    pub fn new() -> Self {
        Self {
            in_frame: false,
            escape: false,
            command: 0xFF,
            buffer: Vec::new(),
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Vec<KissFrame> {
        let mut frames = Vec::new();

        for &byte in bytes {
            if byte == FEND {
                if self.in_frame && self.command != 0xFF && !self.buffer.is_empty() {
                    frames.push(KissFrame {
                        command: self.command,
                        data: core::mem::take(&mut self.buffer),
                    });
                } else if self.in_frame && self.command != 0xFF && self.command != CMD_DATA {
                    frames.push(KissFrame {
                        command: self.command,
                        data: Vec::new(),
                    });
                }
                self.in_frame = true;
                self.command = 0xFF;
                self.buffer.clear();
                self.escape = false;
            } else if self.in_frame {
                if self.command == 0xFF {
                    self.command = byte;
                } else if byte == FESC {
                    self.escape = true;
                } else if self.escape {
                    match byte {
                        TFEND => self.buffer.push(FEND),
                        TFESC => self.buffer.push(FESC),
                        _ => self.buffer.push(byte),
                    }
                    self.escape = false;
                } else {
                    self.buffer.push(byte);
                }
            }
        }

        frames
    }
}

impl Default for KissDecoder {
    fn default() -> Self {
        Self::new()
    }
}

pub fn kiss_encode(cmd: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 4);
    out.push(FEND);
    out.push(cmd);
    for &b in data {
        match b {
            FESC => {
                out.push(FESC);
                out.push(TFESC);
            }
            FEND => {
                out.push(FESC);
                out.push(TFEND);
            }
            _ => out.push(b),
        }
    }
    out.push(FEND);
    out
}

pub struct DetectBuffer {
    decoder: KissDecoder,
}

impl DetectBuffer {
    pub fn new() -> Self {
        Self {
            decoder: KissDecoder::new(),
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Option<Vec<KissFrame>> {
        let frames = self.decoder.feed(bytes);
        if frames
            .iter()
            .any(|frame| frame.command == CMD_DETECT && frame.data.first() == Some(&DETECT_REQ))
        {
            Some(frames)
        } else {
            None
        }
    }
}

impl Default for DetectBuffer {
    fn default() -> Self {
        Self::new()
    }
}

pub fn validate_radio_config(config: RadioConfig) -> Result<(), &'static str> {
    if !(FREQ_MIN_HZ..=FREQ_MAX_HZ).contains(&config.frequency) {
        return Err("frequency out of supported range");
    }

    match config.bandwidth {
        7_800 | 10_400 | 15_600 | 20_800 | 31_250 | 41_700 | 62_500 | 125_000 | 250_000
        | 500_000 => {}
        _ => return Err("unsupported bandwidth"),
    }

    if !(5..=12).contains(&config.spreading_factor) {
        return Err("spreading factor out of range");
    }

    if !(5..=8).contains(&config.coding_rate) {
        return Err("coding rate out of range");
    }

    if !(TX_POWER_MIN_DBM..=TX_POWER_MAX_DBM).contains(&config.tx_power) {
        return Err("TX power out of range");
    }

    Ok(())
}

/// The host-side offset RNode firmware adds to a packet's RSSI in dBm.
pub const RSSI_OFFSET: i16 = 157;

/// The reception stats RNode firmware sends just before a received frame:
/// `CMD_STAT_RSSI` with the packet RSSI plus [`RSSI_OFFSET`], and
/// `CMD_STAT_SNR` with the raw SNR in quarter dB (signed). Hosts attach both
/// to the frame that follows.
pub fn reception_stat_frames(rssi_dbm: i16, snr_raw: i8) -> [Vec<u8>; 2] {
    let rssi = (rssi_dbm + RSSI_OFFSET).clamp(0, 255) as u8;
    [
        kiss_encode(CMD_STAT_RSSI, &[rssi]),
        kiss_encode(CMD_STAT_SNR, &[snr_raw as u8]),
    ]
}

/// A dBm value as RNode firmware sends it: plus [`RSSI_OFFSET`], in a byte.
fn rssi_byte(dbm: i16) -> u8 {
    (dbm + RSSI_OFFSET).clamp(0, 255) as u8
}

/// A share of time (0.0 to 1.0) in hundredths of a percent, as RNode
/// firmware sends airtime and channel load.
fn hundredths_of_percent(share: f64) -> [u8; 2] {
    ((share * 10_000.0).clamp(0.0, u16::MAX as f64) as u16).to_be_bytes()
}

/// `CMD_STAT_RX` / `CMD_STAT_TX`: a packet count, as RNode firmware answers
/// the host's request.
pub fn packet_count_frame(command: u8, count: u32) -> Vec<u8> {
    kiss_encode(command, &count.to_be_bytes())
}

/// Channel state for `CMD_STAT_CHTM`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ChannelReport {
    pub airtime_short: f64,
    pub airtime_long: f64,
    pub channel_load_short: f64,
    pub channel_load_long: f64,
    pub current_rssi: i16,
    pub noise_floor: i16,
    /// RSSI of interference on the channel, if any.
    pub interference: Option<i16>,
}

/// `CMD_STAT_CHTM`, as RNode firmware's `kiss_indicate_channel_stats`.
pub fn channel_stats_frame(report: &ChannelReport) -> Vec<u8> {
    let mut data = Vec::with_capacity(11);
    data.extend_from_slice(&hundredths_of_percent(report.airtime_short));
    data.extend_from_slice(&hundredths_of_percent(report.airtime_long));
    data.extend_from_slice(&hundredths_of_percent(report.channel_load_short));
    data.extend_from_slice(&hundredths_of_percent(report.channel_load_long));
    data.push(rssi_byte(report.current_rssi));
    data.push(rssi_byte(report.noise_floor));
    data.push(report.interference.map_or(0xFF, rssi_byte));
    kiss_encode(CMD_STAT_CHTM, &data)
}

/// `CMD_STAT_PHYPRM`, as RNode firmware's `kiss_indicate_phy_stats`:
/// symbol time (µs), symbol rate (baud), preamble (symbols and ms), CSMA
/// slot and DIFS (ms).
pub fn phy_stats_frame(
    spreading_factor: u8,
    bandwidth: u32,
    preamble_symbols: u16,
    slot_ms: u64,
    difs_ms: u64,
) -> Vec<u8> {
    let symbol_ms = crate::modem::symbol_time_ms(spreading_factor, bandwidth);
    let symbol_rate = bandwidth as f64 / (1u32 << spreading_factor) as f64;
    let preamble_ms = (preamble_symbols as f64 * symbol_ms).ceil();
    let mut data = Vec::with_capacity(12);
    for value in [
        (symbol_ms * 1000.0) as u16,
        symbol_rate as u16,
        preamble_symbols,
        preamble_ms as u16,
        slot_ms as u16,
        difs_ms as u16,
    ] {
        data.extend_from_slice(&value.to_be_bytes());
    }
    kiss_encode(CMD_STAT_PHYPRM, &data)
}

/// `CMD_STAT_CSMA`: contention window band and its bounds in slots.
pub fn csma_stats_frame(band: u8, window_min: u8, window_max: u8) -> Vec<u8> {
    kiss_encode(CMD_STAT_CSMA, &[band, window_min, window_max])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_preserves_fragmented_detect_frame() {
        let frame = kiss_encode(CMD_DETECT, &[DETECT_REQ]);
        let split = 2;
        let mut decoder = KissDecoder::new();

        assert!(decoder.feed(&frame[..split]).is_empty());
        let frames = decoder.feed(&frame[split..]);

        assert_eq!(
            frames,
            vec![KissFrame {
                command: CMD_DETECT,
                data: vec![DETECT_REQ],
            }]
        );
    }

    #[test]
    fn detect_buffer_returns_all_frames_from_handshake_read() {
        let mut buf = DetectBuffer::new();
        let mut bytes = kiss_encode(CMD_DETECT, &[DETECT_REQ]);
        bytes.extend_from_slice(&kiss_encode(CMD_FREQUENCY, &[0x00, 0x00, 0x00, 0x01]));

        let frames = buf.feed(&bytes).expect("detect should trigger bridge mode");

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].command, CMD_DETECT);
        assert_eq!(frames[1].command, CMD_FREQUENCY);
    }

    #[test]
    fn accepts_default_config() {
        let cfg = RadioConfig {
            frequency: crate::config::LORA_FREQUENCY,
            bandwidth: crate::config::LORA_BANDWIDTH,
            spreading_factor: crate::config::LORA_SPREADING_FACTOR,
            coding_rate: crate::config::LORA_CODING_RATE,
            tx_power: crate::config::LORA_TX_POWER,
        };

        assert!(validate_radio_config(cfg).is_ok());
    }

    #[test]
    fn rejects_invalid_spreading_factor() {
        let cfg = RadioConfig {
            frequency: crate::config::LORA_FREQUENCY,
            bandwidth: crate::config::LORA_BANDWIDTH,
            spreading_factor: 13,
            coding_rate: crate::config::LORA_CODING_RATE,
            tx_power: crate::config::LORA_TX_POWER,
        };

        assert!(validate_radio_config(cfg).is_err());
    }

    #[test]
    fn rejects_invalid_bandwidth() {
        let cfg = RadioConfig {
            frequency: crate::config::LORA_FREQUENCY,
            bandwidth: 123_456,
            spreading_factor: crate::config::LORA_SPREADING_FACTOR,
            coding_rate: crate::config::LORA_CODING_RATE,
            tx_power: crate::config::LORA_TX_POWER,
        };

        assert!(validate_radio_config(cfg).is_err());
    }

    #[test]
    fn reception_stats_use_rnode_encoding() {
        // -25 dBm and an SNR of 13.75 dB (55 quarter dB), as upstream
        // RNodeInterface decodes them: byte - 157, signed byte * 0.25.
        let [rssi, snr] = reception_stat_frames(-25, 55);
        assert_eq!(rssi, kiss_encode(CMD_STAT_RSSI, &[132]));
        assert_eq!(snr, kiss_encode(CMD_STAT_SNR, &[55]));
        let [_, negative] = reception_stat_frames(-120, -30);
        assert_eq!(negative, kiss_encode(CMD_STAT_SNR, &[(-30i8) as u8]));
    }

    #[test]
    fn reception_rssi_is_clamped_to_a_byte() {
        let [low, _] = reception_stat_frames(-200, 0);
        assert_eq!(low, kiss_encode(CMD_STAT_RSSI, &[0]));
        let [high, _] = reception_stat_frames(120, 0);
        assert_eq!(high, kiss_encode(CMD_STAT_RSSI, &[255]));
    }

    #[test]
    fn channel_stats_frame_matches_rnode_layout() {
        let frame = channel_stats_frame(&ChannelReport {
            airtime_short: 0.0123,
            airtime_long: 0.5,
            channel_load_short: 0.25,
            channel_load_long: 1.0,
            current_rssi: -110,
            noise_floor: -118,
            interference: None,
        });
        assert_eq!(
            frame,
            vec![
                0xC0,
                CMD_STAT_CHTM,
                0,
                123,
                0x13,
                0x88,
                0x09,
                0xC4,
                0x27,
                0x10,
                47,
                39,
                0xFF,
                0xC0
            ]
        );
        let busy = channel_stats_frame(&ChannelReport {
            interference: Some(-90),
            ..ChannelReport {
                airtime_short: 0.0,
                airtime_long: 0.0,
                channel_load_short: 0.0,
                channel_load_long: 0.0,
                current_rssi: -90,
                noise_floor: -118,
                interference: None,
            }
        });
        assert_eq!(busy[12], 67);
    }

    #[test]
    fn phy_stats_frame_matches_rnode_values() {
        // SF8 / 125 kHz: 2.048 ms symbols, 488 baud; 18 symbols ~ 37 ms;
        // CSMA slot 24 ms, DIFS 48 ms, as upstream computes them.
        let frame = phy_stats_frame(8, 125_000, 18, 24, 48);
        assert_eq!(
            frame,
            vec![
                0xC0,
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
                0xC0
            ]
        );
    }

    #[test]
    fn packet_count_and_csma_frames() {
        assert_eq!(
            packet_count_frame(CMD_STAT_RX, 0x0102_0304),
            vec![0xC0, CMD_STAT_RX, 1, 2, 3, 4, 0xC0]
        );
        assert_eq!(
            csma_stats_frame(1, 0, 14),
            vec![0xC0, CMD_STAT_CSMA, 1, 0, 14, 0xC0]
        );
    }
}
