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

#[cfg(test)]
mod tests {
    use super::{
        kiss_encode, validate_radio_config, DetectBuffer, KissDecoder, KissFrame, RadioConfig,
        CMD_DETECT, CMD_FREQUENCY, DETECT_REQ,
    };

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
}
