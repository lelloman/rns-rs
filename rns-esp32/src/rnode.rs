//! RNode-compatible KISS protocol handler for ESP32.
//!
//! Implements the device side of the RNode protocol: responds to DETECT
//! handshake, accepts radio configuration commands, and bridges data frames
//! between a serial transport (USB UART or BLE NUS) and the SX1262 LoRa radio.

use std::io;
use std::time::{Duration, Instant};

use core::num::NonZeroU32;

use esp_idf_hal::delay::TickType;
use esp_idf_hal::gpio::{Input, InterruptType, PinDriver};
use esp_idf_hal::task::notification::Notification;
use esp_idf_hal::uart::UartDriver;

use crate::display::SharedStats;
use crate::lora::SharedRadio;
use crate::version;
use rns_esp32::channel::{airtime_limit, Airtime, Csma};
use rns_esp32::protocol::{
    kiss_encode, reception_stat_frames, validate_radio_config, DetectBuffer, KissDecoder,
    KissFrame, RadioConfig, CMD_BANDWIDTH, CMD_CR, CMD_DATA, CMD_DETECT, CMD_FREQUENCY,
    CMD_FW_DETAIL, CMD_FW_VERSION, CMD_LEAVE, CMD_LT_ALOCK, CMD_MCU, CMD_PLATFORM, CMD_RADIO_STATE,
    CMD_READY, CMD_SF, CMD_ST_ALOCK, CMD_TXPOWER, DETECT_REQ, DETECT_RESP, RADIO_STATE_ON,
};

/// Transport-agnostic serial interface for the RNode bridge.
/// Implemented by both UART (USB) and BLE NUS transports.
pub trait BridgeTransport {
    /// Read bytes with a timeout in milliseconds. Returns number of bytes read.
    fn read(&self, buf: &mut [u8], timeout_ms: u32) -> usize;
    /// Write a frame in full.
    fn write(&self, data: &[u8]) -> io::Result<()>;
    /// Whether the host is still there, where the transport can tell.
    fn connected(&self) -> bool {
        true
    }
}

/// UART transport — wraps the existing UartDriver for USB serial bridge.
pub struct UartTransport<'a, 'b> {
    uart: &'b UartDriver<'a>,
}

impl<'a, 'b> UartTransport<'a, 'b> {
    pub fn new(uart: &'b UartDriver<'a>) -> Self {
        Self { uart }
    }
}

impl<'a, 'b> BridgeTransport for UartTransport<'a, 'b> {
    fn read(&self, buf: &mut [u8], timeout_ms: u32) -> usize {
        match self.uart.read(buf, timeout_ms) {
            Ok(n) => n,
            Err(_) => 0,
        }
    }

    fn write(&self, data: &[u8]) -> io::Result<()> {
        match self.uart.write(data) {
            Ok(n) if n == data.len() => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "UART short write while sending RNode frame",
            )),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("UART write failed: {e}"),
            )),
        }
    }
}

/// BLE NUS transport — wraps the BLE module for wireless serial bridge.
pub struct BleTransport;

impl BleTransport {
    pub fn new() -> Self {
        Self
    }
}

impl BridgeTransport for BleTransport {
    fn read(&self, buf: &mut [u8], timeout_ms: u32) -> usize {
        crate::ble::read_timeout(buf, Duration::from_millis(timeout_ms as u64))
    }

    fn connected(&self) -> bool {
        crate::ble::is_connected()
    }

    fn write(&self, data: &[u8]) -> io::Result<()> {
        match crate::ble::write(data) {
            Ok(()) => Ok(()),
            Err(err) => {
                crate::ble::disconnect();
                Err(err)
            }
        }
    }
}

// Device identity
const PLATFORM_ESP32: u8 = 0x80;
const MCU_ESP32: u8 = 0x01;

const DETECT_POLL_MS: u32 = 5;

/// Frames from the host held while the channel is busy or airtime-locked.
const TX_QUEUE_MAX_FRAMES: usize = 32;

/// How long a host that detected the board may stay silent before it has
/// switched the radio on, after which the board reverts to standalone. Once
/// the radio is on the bridge stays up, as upstream firmware, until the host
/// sends LEAVE, the transport disconnects (BLE) or the board resets: hosts
/// send no keepalive over serial, so silence is not a sign they left.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Reason the bridge loop exited.
pub enum BridgeExit {
    IdleTimeout,
    Leave,
    TransportError,
}

/// RNode bridge: handles serial protocol and bridges data to/from LoRa.
/// Generic over the serial transport (UART for USB, BLE NUS for wireless).
pub struct RNodeBridge<T: BridgeTransport> {
    radio: SharedRadio,
    transport: T,
    dio1: PinDriver<'static, Input>,
    stats: Option<SharedStats>,
    pending_frames: Vec<KissFrame>,
    pending_freq: Option<u32>,
    pending_bw: Option<u32>,
    pending_sf: Option<u8>,
    pending_cr: Option<u8>,
    pending_power: Option<i8>,
    /// The host switched the radio on.
    radio_on: bool,
    /// Frames from the host waiting for the channel, oldest first.
    tx_queue: std::collections::VecDeque<Vec<u8>>,
    /// Listen before talk for the configured channel.
    csma: Csma,
    /// This node's own airtime and the host's limits on it.
    airtime: Airtime,
    short_term_limit: Option<f64>,
    long_term_limit: Option<f64>,
    /// The configured channel, for airtime accounting.
    channel: RadioConfig,
    /// Origin of the millisecond clock the channel logic runs on.
    epoch: Instant,
    /// KISS decoder for the host's bytes.
    decoder: KissDecoder,
}

impl<T: BridgeTransport> RNodeBridge<T> {
    pub fn new(
        radio: SharedRadio,
        transport: T,
        dio1: PinDriver<'static, Input>,
        stats: Option<SharedStats>,
        pending_frames: Vec<KissFrame>,
    ) -> Self {
        Self {
            radio,
            transport,
            dio1,
            stats,
            pending_frames,
            pending_freq: None,
            pending_bw: None,
            pending_sf: None,
            pending_cr: None,
            pending_power: None,
            radio_on: false,
            tx_queue: std::collections::VecDeque::new(),
            csma: Csma::new(
                crate::config::LORA_SPREADING_FACTOR,
                crate::config::LORA_BANDWIDTH,
            ),
            airtime: Airtime::new(),
            short_term_limit: None,
            long_term_limit: None,
            channel: RadioConfig {
                frequency: crate::config::LORA_FREQUENCY,
                bandwidth: crate::config::LORA_BANDWIDTH,
                spreading_factor: crate::config::LORA_SPREADING_FACTOR,
                coding_rate: crate::config::LORA_CODING_RATE,
                tx_power: crate::config::LORA_TX_POWER,
            },
            epoch: Instant::now(),
            decoder: KissDecoder::new(),
        }
    }

    /// Run the RNode bridge loop. Blocks until serial goes idle or host sends LEAVE.
    pub fn run(mut self) -> (BridgeExit, PinDriver<'static, Input>) {
        log::info!("RNode bridge mode active");

        let mut rx_buf = [0u8; 512];
        let mut last_activity = Instant::now();
        let notification = Notification::new();
        let notifier = notification.notifier();

        self.dio1.set_interrupt_type(InterruptType::PosEdge).ok();
        unsafe {
            self.dio1
                .subscribe_nonstatic(move || {
                    let _ = notifier.notify(NonZeroU32::new(1).unwrap());
                })
                .ok();
        }

        for frame in core::mem::take(&mut self.pending_frames) {
            match self.handle_frame(frame) {
                Ok(true) => {
                    let _ = self.dio1.unsubscribe();
                    return (BridgeExit::Leave, self.dio1);
                }
                Ok(false) => {}
                Err(err) => {
                    log::warn!("RNode bridge: pending frame handling failed: {}", err);
                    let _ = self.dio1.unsubscribe();
                    return (BridgeExit::TransportError, self.dio1);
                }
            }
        }

        let exit = loop {
            // Check idle timeout
            if !self.transport.connected() {
                log::info!("RNode bridge: host disconnected");
                break BridgeExit::TransportError;
            }
            if !self.radio_on && last_activity.elapsed() > IDLE_TIMEOUT {
                log::info!("RNode bridge: idle timeout, reverting to standalone");
                break BridgeExit::IdleTimeout;
            }

            let n = self.transport.read(&mut rx_buf, 0);
            if n > 0 {
                last_activity = Instant::now();
                let frames = self.decoder.feed(&rx_buf[..n]);
                for frame in frames {
                    match self.handle_frame(frame) {
                        Ok(true) => {
                            let _ = self.dio1.unsubscribe();
                            return (BridgeExit::Leave, self.dio1);
                        }
                        Ok(false) => {}
                        Err(err) => {
                            log::warn!("RNode bridge: serial transport failed: {}", err);
                            let _ = self.dio1.unsubscribe();
                            return (BridgeExit::TransportError, self.dio1);
                        }
                    }
                }
            } else {
                if self.dio1.enable_interrupt().is_ok() {
                    let _ = notification.wait(TickType::new_millis(10).ticks());
                }
            }

            let received = {
                let mut radio = self.radio.lock().unwrap();
                radio
                    .receive()
                    .map(|data| (data, radio.last_packet_stats()))
            };
            if let Some((data, (rssi, snr))) = received {
                log::debug!("RNode: LoRa RX {} bytes, forwarding to serial", data.len());
                if let Some(ref stats) = self.stats {
                    stats.lock().unwrap().bridge_rx_bytes += data.len() as u32;
                }
                // As upstream firmware: reception stats, then the frame.
                let [rssi_frame, snr_frame] = reception_stat_frames(rssi, snr);
                let mut frame = rssi_frame;
                frame.extend_from_slice(&snr_frame);
                frame.extend_from_slice(&kiss_encode(CMD_DATA, &data));
                if let Err(err) = self.transport.write(&frame) {
                    log::warn!("RNode bridge: LoRa->serial forwarding failed: {}", err);
                    break BridgeExit::TransportError;
                }
            }

            if let Err(err) = self.service_tx_queue() {
                log::warn!("RNode bridge: serial transport failed: {}", err);
                break BridgeExit::TransportError;
            }
        };

        let _ = self.dio1.unsubscribe();
        (exit, self.dio1)
    }

    /// Handle a decoded KISS frame from serial. Returns true if bridge should exit.
    fn handle_frame(&mut self, frame: KissFrame) -> io::Result<bool> {
        match frame.command {
            CMD_DETECT => {
                if frame.data.first() == Some(&DETECT_REQ) {
                    log::info!("RNode: DETECT handshake received");
                    let resp = kiss_encode(CMD_DETECT, &[DETECT_RESP]);
                    self.transport.write(&resp)?;
                    log::info!("RNode: firmware {}", version::FULL_VERSION);
                }
            }
            CMD_LEAVE => {
                log::info!("RNode: LEAVE received, exiting bridge mode");
                return Ok(true);
            }
            CMD_FW_VERSION => {
                let resp = kiss_encode(
                    CMD_FW_VERSION,
                    &[version::RNODE_PROTOCOL_MAJOR, version::RNODE_PROTOCOL_MINOR],
                );
                self.transport.write(&resp)?;
            }
            CMD_FW_DETAIL => {
                let resp = kiss_encode(CMD_FW_DETAIL, version::FULL_VERSION.as_bytes());
                self.transport.write(&resp)?;
            }
            CMD_PLATFORM => {
                let resp = kiss_encode(CMD_PLATFORM, &[PLATFORM_ESP32]);
                self.transport.write(&resp)?;
            }
            CMD_MCU => {
                let resp = kiss_encode(CMD_MCU, &[MCU_ESP32]);
                self.transport.write(&resp)?;
            }
            CMD_FREQUENCY => {
                if frame.data.len() >= 4 {
                    let freq = (frame.data[0] as u32) << 24
                        | (frame.data[1] as u32) << 16
                        | (frame.data[2] as u32) << 8
                        | frame.data[3] as u32;
                    log::info!("RNode: set frequency {}Hz", freq);
                    self.pending_freq = Some(freq);
                    let resp = kiss_encode(CMD_FREQUENCY, &frame.data[..4]);
                    self.transport.write(&resp)?;
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
                    self.transport.write(&resp)?;
                }
            }
            CMD_TXPOWER => {
                if !frame.data.is_empty() {
                    let power = frame.data[0] as i8;
                    log::info!("RNode: set TX power {}dBm", power);
                    self.pending_power = Some(power);
                    let resp = kiss_encode(CMD_TXPOWER, &[frame.data[0]]);
                    self.transport.write(&resp)?;
                }
            }
            CMD_SF => {
                if !frame.data.is_empty() {
                    log::info!("RNode: set SF {}", frame.data[0]);
                    self.pending_sf = Some(frame.data[0]);
                    let resp = kiss_encode(CMD_SF, &[frame.data[0]]);
                    self.transport.write(&resp)?;
                }
            }
            CMD_CR => {
                if !frame.data.is_empty() {
                    log::info!("RNode: set CR 4/{}", frame.data[0]);
                    self.pending_cr = Some(frame.data[0]);
                    let resp = kiss_encode(CMD_CR, &[frame.data[0]]);
                    self.transport.write(&resp)?;
                }
            }
            CMD_ST_ALOCK => {
                if frame.data.len() >= 2 {
                    let value = (frame.data[0] as u16) << 8 | frame.data[1] as u16;
                    log::info!("RNode: set ST airtime lock {}%", value as f32 / 100.0);
                    self.short_term_limit = airtime_limit(value);
                    let resp = kiss_encode(CMD_ST_ALOCK, &frame.data[..2]);
                    self.transport.write(&resp)?;
                }
            }
            CMD_LT_ALOCK => {
                if frame.data.len() >= 2 {
                    let value = (frame.data[0] as u16) << 8 | frame.data[1] as u16;
                    log::info!("RNode: set LT airtime lock {}%", value as f32 / 100.0);
                    self.long_term_limit = airtime_limit(value);
                    let resp = kiss_encode(CMD_LT_ALOCK, &frame.data[..2]);
                    self.transport.write(&resp)?;
                }
            }
            CMD_RADIO_STATE => {
                if frame.data.first() == Some(&RADIO_STATE_ON) {
                    if self.apply_radio_config() {
                        self.radio_on = true;
                        let resp = kiss_encode(CMD_RADIO_STATE, &[RADIO_STATE_ON]);
                        self.transport.write(&resp)?;
                        let ready = kiss_encode(CMD_READY, &[0x01]);
                        self.transport.write(&ready)?;
                    }
                }
            }
            CMD_DATA => {
                if !frame.data.is_empty() {
                    // Queued for the channel; upstream refuses frames while
                    // its queue is full.
                    if self.tx_queue.len() < TX_QUEUE_MAX_FRAMES {
                        self.tx_queue.push_back(frame.data);
                    } else {
                        log::warn!("RNode: TX queue full, dropping a frame");
                    }
                }
            }
            _ => {
                log::debug!("RNode: ignoring command 0x{:02X}", frame.command);
            }
        }
        Ok(false)
    }

    /// Milliseconds since the bridge started, for the channel logic.
    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Send the queued frames once the channel allows, as upstream's
    /// `tx_queue_handler`: nothing while an airtime limit is reached; else
    /// wait for listen before talk, then send everything queued.
    fn service_tx_queue(&mut self) -> io::Result<()> {
        if self.tx_queue.is_empty() || !self.radio_on {
            return Ok(());
        }
        let now = self.now_ms();
        if self
            .airtime
            .locked(now, self.short_term_limit, self.long_term_limit)
        {
            return Ok(());
        }
        let short_term = self.airtime.short_term(now);
        self.csma.set_airtime(short_term);
        let channel_free = !self.radio.lock().unwrap().carrier_detected();
        let mut random = |lo: u32, hi: u32| {
            // SAFETY: esp_random reads the hardware random number generator.
            let r = unsafe { esp_idf_sys::esp_random() };
            lo + r % (hi - lo + 1)
        };
        if !self.csma.may_transmit(now, channel_free, &mut random) {
            return Ok(());
        }
        // One channel access sends everything queued, as upstream's
        // flush_queue.
        while let Some(frame) = self.tx_queue.pop_front() {
            log::debug!("RNode: TX {} bytes over LoRa", frame.len());
            if let Some(ref stats) = self.stats {
                stats.lock().unwrap().bridge_tx_bytes += frame.len() as u32;
            }
            let result = self.radio.lock().unwrap().send(&frame);
            let sent_at = self.now_ms();
            self.airtime.add(sent_at, self.frame_airtime_ms(&frame));
            match result {
                Ok(()) => {
                    let resp = kiss_encode(CMD_READY, &[0x01]);
                    self.transport.write(&resp)?;
                }
                Err(e) => log::error!("RNode: LoRa TX failed: {}", e),
            }
        }
        self.radio.lock().unwrap().set_rx_continuous();
        Ok(())
    }

    /// Airtime of a frame: one LoRa packet, or two for a split frame.
    fn frame_airtime_ms(&self, frame: &[u8]) -> f64 {
        let channel = self.channel;
        let preamble = rns_esp32::modem::preamble_symbols(
            channel.spreading_factor,
            channel.bandwidth,
            channel.coding_rate,
        );
        rns_esp32::airframe::packets(frame, 0)
            .unwrap_or_default()
            .iter()
            .map(|packet| {
                rns_esp32::channel::packet_airtime_ms(
                    packet.len(),
                    channel.spreading_factor,
                    channel.bandwidth,
                    channel.coding_rate,
                    preamble,
                )
            })
            .sum()
    }

    /// Apply pending radio configuration to the SX1262.
    fn apply_radio_config(&mut self) -> bool {
        let config = RadioConfig {
            frequency: self.pending_freq.unwrap_or(crate::config::LORA_FREQUENCY),
            bandwidth: self.pending_bw.unwrap_or(crate::config::LORA_BANDWIDTH),
            spreading_factor: self
                .pending_sf
                .unwrap_or(crate::config::LORA_SPREADING_FACTOR),
            coding_rate: self.pending_cr.unwrap_or(crate::config::LORA_CODING_RATE),
            tx_power: self.pending_power.unwrap_or(crate::config::LORA_TX_POWER),
        };

        if let Err(err) = validate_radio_config(config) {
            log::warn!("RNode: rejecting invalid radio config: {}", err);
            if let Some(ref stats) = self.stats {
                stats.lock().unwrap().set_status("Invalid radio cfg");
            }
            return false;
        }

        self.channel = config;
        self.csma = Csma::new(config.spreading_factor, config.bandwidth);
        let mut radio = self.radio.lock().unwrap();
        radio.reconfigure(
            config.frequency,
            config.bandwidth,
            config.spreading_factor,
            config.coding_rate,
            config.tx_power,
        );

        if let Some(ref stats) = self.stats {
            let mut s = stats.lock().unwrap();
            s.bridge_freq = Some(config.frequency);
            s.bridge_bw = Some(config.bandwidth);
            s.bridge_sf = Some(config.spreading_factor);
            s.bridge_cr = Some(config.coding_rate);
            s.bridge_power = Some(config.tx_power);
        }

        log::info!("RNode: radio config applied");
        true
    }
}

pub struct BridgeDetectState {
    detector: DetectBuffer,
    rx_buf: [u8; 256],
}

impl BridgeDetectState {
    pub fn new() -> Self {
        Self {
            detector: DetectBuffer::new(),
            rx_buf: [0u8; 256],
        }
    }

    pub fn poll(&mut self, uart: &UartDriver<'_>) -> Option<Vec<KissFrame>> {
        match uart.read(&mut self.rx_buf, DETECT_POLL_MS) {
            Ok(n) if n > 0 => self.detector.feed(&self.rx_buf[..n]),
            _ => None,
        }
    }
}

/// Restore the radio to a standalone configuration.
pub fn restore_radio_config(radio: &SharedRadio, config: RadioConfig) {
    let mut r = radio.lock().unwrap();
    r.reconfigure(
        config.frequency,
        config.bandwidth,
        config.spreading_factor,
        config.coding_rate,
        config.tx_power,
    );
    log::info!("Radio restored to standalone config");
}
