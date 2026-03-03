//! RNode-compatible KISS protocol handler for ESP32.
//!
//! Implements the device side of the RNode protocol: responds to DETECT
//! handshake, accepts radio configuration commands, and bridges data frames
//! between USB serial and the SX1262 LoRa radio.

use std::time::{Duration, Instant};

use esp_idf_hal::uart::UartDriver;

use crate::lora::SharedRadio;

// KISS framing constants
const FEND: u8 = 0xC0;
const FESC: u8 = 0xDB;
const TFEND: u8 = 0xDC;
const TFESC: u8 = 0xDD;

// RNode command bytes (subset matching rns-net/src/rnode_kiss.rs)
const CMD_DATA: u8 = 0x00;
const CMD_FREQUENCY: u8 = 0x01;
const CMD_BANDWIDTH: u8 = 0x02;
const CMD_TXPOWER: u8 = 0x03;
const CMD_SF: u8 = 0x04;
const CMD_CR: u8 = 0x05;
const CMD_RADIO_STATE: u8 = 0x06;
const CMD_DETECT: u8 = 0x08;
const CMD_READY: u8 = 0x0F;
const CMD_PLATFORM: u8 = 0x48;
const CMD_MCU: u8 = 0x49;
const CMD_FW_VERSION: u8 = 0x50;

const DETECT_REQ: u8 = 0x73;
const DETECT_RESP: u8 = 0x46;
const RADIO_STATE_ON: u8 = 0x01;

// Device identity
const PLATFORM_ESP32: u8 = 0x80;
const MCU_ESP32: u8 = 0x01;
const FW_VERSION_MAJOR: u8 = 0x01;
const FW_VERSION_MINOR: u8 = 0x01;

/// Idle timeout before reverting to standalone mode.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Reason the bridge loop exited.
pub enum BridgeExit {
    IdleTimeout,
}

/// KISS frame decoded from serial input.
struct KissFrame {
    command: u8,
    data: Vec<u8>,
}

/// Streaming KISS decoder for serial input.
struct KissDecoder {
    in_frame: bool,
    escape: bool,
    command: u8,
    buffer: Vec<u8>,
}

impl KissDecoder {
    fn new() -> Self {
        Self {
            in_frame: false,
            escape: false,
            command: 0xFF,
            buffer: Vec::new(),
        }
    }

    /// Feed bytes and return any complete frames.
    fn feed(&mut self, bytes: &[u8]) -> Vec<KissFrame> {
        let mut frames = Vec::new();

        for &byte in bytes {
            if byte == FEND {
                if self.in_frame && self.command != 0xFF && !self.buffer.is_empty() {
                    frames.push(KissFrame {
                        command: self.command,
                        data: core::mem::take(&mut self.buffer),
                    });
                } else if self.in_frame && self.command != 0xFF && self.command != CMD_DATA {
                    // Command with no payload (e.g. radio state query)
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

/// KISS-encode a command frame: FEND + cmd + escaped(data) + FEND.
fn kiss_encode(cmd: u8, data: &[u8]) -> Vec<u8> {
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

/// RNode bridge: handles serial protocol and bridges data to/from LoRa.
pub struct RNodeBridge<'a, 'b> {
    radio: SharedRadio,
    uart: &'b UartDriver<'a>,
    pending_freq: Option<u32>,
    pending_bw: Option<u32>,
    pending_sf: Option<u8>,
    pending_cr: Option<u8>,
    pending_power: Option<i8>,
}

impl<'a, 'b> RNodeBridge<'a, 'b> {
    pub fn new(radio: SharedRadio, uart: &'b UartDriver<'a>) -> Self {
        Self {
            radio,
            uart,
            pending_freq: None,
            pending_bw: None,
            pending_sf: None,
            pending_cr: None,
            pending_power: None,
        }
    }

    /// Run the RNode bridge loop. Blocks until serial goes idle.
    pub fn run(&mut self) -> BridgeExit {
        log::info!("RNode bridge mode active");

        let mut decoder = KissDecoder::new();
        let mut rx_buf = [0u8; 512];
        let mut last_activity = Instant::now();

        loop {
            // Check idle timeout
            if last_activity.elapsed() > IDLE_TIMEOUT {
                log::info!("RNode bridge: idle timeout, reverting to standalone");
                return BridgeExit::IdleTimeout;
            }

            // Poll serial RX (non-blocking with short timeout)
            match self.uart.read(&mut rx_buf, 10) {
                Ok(n) if n > 0 => {
                    last_activity = Instant::now();
                    let frames = decoder.feed(&rx_buf[..n]);
                    for frame in frames {
                        self.handle_frame(frame);
                    }
                }
                _ => {}
            }

            // Poll LoRa RX
            let received = {
                let mut radio = self.radio.lock().unwrap();
                radio.try_receive()
            };
            if let Some(data) = received {
                last_activity = Instant::now();
                log::info!("RNode: LoRa RX {} bytes, forwarding to serial", data.len());
                let frame = kiss_encode(CMD_DATA, &data);
                let _ = self.uart.write(&frame);
            }

            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Handle a decoded KISS frame from serial.
    fn handle_frame(&mut self, frame: KissFrame) {
        match frame.command {
            CMD_DETECT => {
                if frame.data.first() == Some(&DETECT_REQ) {
                    log::info!("RNode: DETECT handshake received");
                    let resp = kiss_encode(CMD_DETECT, &[DETECT_RESP]);
                    let _ = self.uart.write(&resp);
                }
            }
            CMD_FW_VERSION => {
                let resp = kiss_encode(CMD_FW_VERSION, &[FW_VERSION_MAJOR, FW_VERSION_MINOR]);
                let _ = self.uart.write(&resp);
            }
            CMD_PLATFORM => {
                let resp = kiss_encode(CMD_PLATFORM, &[PLATFORM_ESP32]);
                let _ = self.uart.write(&resp);
            }
            CMD_MCU => {
                let resp = kiss_encode(CMD_MCU, &[MCU_ESP32]);
                let _ = self.uart.write(&resp);
            }
            CMD_FREQUENCY => {
                if frame.data.len() >= 4 {
                    let freq = (frame.data[0] as u32) << 24
                        | (frame.data[1] as u32) << 16
                        | (frame.data[2] as u32) << 8
                        | frame.data[3] as u32;
                    log::info!("RNode: set frequency {}Hz", freq);
                    self.pending_freq = Some(freq);
                    // Echo back confirmation
                    let resp = kiss_encode(CMD_FREQUENCY, &frame.data[..4]);
                    let _ = self.uart.write(&resp);
                }
            }
            CMD_BANDWIDTH => {
                if frame.data.len() >= 4 {
                    let bw = (frame.data[0] as u32) << 24
                        | (frame.data[1] as u32) << 16
                        | (frame.data[2] as u32) << 8
                        | frame.data[3] as u32;
                    log::info!("RNode: set bandwidth {}Hz", bw);
                    self.pending_bw = Some(bw);
                    let resp = kiss_encode(CMD_BANDWIDTH, &frame.data[..4]);
                    let _ = self.uart.write(&resp);
                }
            }
            CMD_TXPOWER => {
                if !frame.data.is_empty() {
                    let power = frame.data[0] as i8;
                    log::info!("RNode: set TX power {}dBm", power);
                    self.pending_power = Some(power);
                    let resp = kiss_encode(CMD_TXPOWER, &[frame.data[0]]);
                    let _ = self.uart.write(&resp);
                }
            }
            CMD_SF => {
                if !frame.data.is_empty() {
                    log::info!("RNode: set SF {}", frame.data[0]);
                    self.pending_sf = Some(frame.data[0]);
                    let resp = kiss_encode(CMD_SF, &[frame.data[0]]);
                    let _ = self.uart.write(&resp);
                }
            }
            CMD_CR => {
                if !frame.data.is_empty() {
                    log::info!("RNode: set CR 4/{}", frame.data[0]);
                    self.pending_cr = Some(frame.data[0]);
                    let resp = kiss_encode(CMD_CR, &[frame.data[0]]);
                    let _ = self.uart.write(&resp);
                }
            }
            CMD_RADIO_STATE => {
                if frame.data.first() == Some(&RADIO_STATE_ON) {
                    self.apply_radio_config();
                    let resp = kiss_encode(CMD_RADIO_STATE, &[RADIO_STATE_ON]);
                    let _ = self.uart.write(&resp);
                }
            }
            CMD_DATA => {
                if !frame.data.is_empty() {
                    log::info!("RNode: TX {} bytes over LoRa", frame.data.len());
                    let result = {
                        let mut radio = self.radio.lock().unwrap();
                        let r = radio.transmit(&frame.data);
                        radio.set_rx_continuous();
                        r
                    };
                    match result {
                        Ok(()) => {
                            // Signal ready for next packet
                            let resp = kiss_encode(CMD_READY, &[0x01]);
                            let _ = self.uart.write(&resp);
                        }
                        Err(e) => {
                            log::error!("RNode: LoRa TX failed: {}", e);
                        }
                    }
                }
            }
            _ => {
                log::debug!("RNode: ignoring command 0x{:02X}", frame.command);
            }
        }
    }

    /// Apply pending radio configuration to the SX1262.
    fn apply_radio_config(&mut self) {
        let freq = self.pending_freq.unwrap_or(crate::config::LORA_FREQUENCY);
        let bw = self.pending_bw.unwrap_or(crate::config::LORA_BANDWIDTH);
        let sf = self.pending_sf.unwrap_or(crate::config::LORA_SPREADING_FACTOR);
        let cr = self.pending_cr.unwrap_or(crate::config::LORA_CODING_RATE);
        let power = self.pending_power.unwrap_or(crate::config::LORA_TX_POWER);

        let mut radio = self.radio.lock().unwrap();
        radio.reconfigure(freq, bw, sf, cr, power);

        log::info!("RNode: radio config applied");
    }
}

/// Watch UART for the RNode DETECT handshake using a proper KISS decoder.
/// When DETECT is received, responds to it and any other info queries
/// (FW_VERSION, PLATFORM, MCU) that arrive in the same batch.
/// Returns `true` if DETECT was received and responded to.
/// Returns `false` on timeout (no DETECT seen).
pub fn wait_for_detect(uart: &UartDriver<'_>) -> bool {
    let mut decoder = KissDecoder::new();
    let mut rx_buf = [0u8; 256];

    // The PC sends DETECT + FW_VERSION + PLATFORM + MCU as one batch.
    // Read with a short timeout; this is called in a loop by the monitor.
    match uart.read(&mut rx_buf, 100) {
        Ok(n) if n > 0 => {
            let frames = decoder.feed(&rx_buf[..n]);
            let mut detected = false;

            for frame in &frames {
                if frame.command == CMD_DETECT && frame.data.first() == Some(&DETECT_REQ) {
                    detected = true;
                }
            }

            if detected {
                // Respond to all frames in the batch
                for frame in frames {
                    match frame.command {
                        CMD_DETECT => {
                            if frame.data.first() == Some(&DETECT_REQ) {
                                log::info!("RNode: DETECT handshake received, responding");
                                let resp = kiss_encode(CMD_DETECT, &[DETECT_RESP]);
                                let _ = uart.write(&resp);
                            }
                        }
                        CMD_FW_VERSION => {
                            let resp = kiss_encode(CMD_FW_VERSION, &[FW_VERSION_MAJOR, FW_VERSION_MINOR]);
                            let _ = uart.write(&resp);
                        }
                        CMD_PLATFORM => {
                            let resp = kiss_encode(CMD_PLATFORM, &[PLATFORM_ESP32]);
                            let _ = uart.write(&resp);
                        }
                        CMD_MCU => {
                            let resp = kiss_encode(CMD_MCU, &[MCU_ESP32]);
                            let _ = uart.write(&resp);
                        }
                        _ => {}
                    }
                }
                return true;
            }
        }
        _ => {}
    }

    false
}

/// Restore the radio to default standalone configuration from config.rs.
pub fn restore_default_radio_config(radio: &SharedRadio) {
    let mut r = radio.lock().unwrap();
    r.reconfigure(
        crate::config::LORA_FREQUENCY,
        crate::config::LORA_BANDWIDTH,
        crate::config::LORA_SPREADING_FACTOR,
        crate::config::LORA_CODING_RATE,
        crate::config::LORA_TX_POWER,
    );
    log::info!("Radio restored to default config");
}
