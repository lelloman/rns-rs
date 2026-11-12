//! Bench-top hardware-in-the-loop test for two ESP32 RNode devices.
//!
//! Usage:
//!   cargo run --example rnode_hil -- /dev/ttyUSB0 /dev/ttyUSB1 [frequency_mhz]
//!
//! The runner:
//! - detects both boards and records firmware/platform/MCU responses
//! - configures both radios with matching LoRa settings
//! - verifies A -> B and B -> A payload delivery over RF
//! - sends LEAVE and verifies each board can be detected again

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use rns_net::rnode_kiss::{self, RNodeDecoder, RNodeEvent};
use rns_net::serial::{SerialConfig, SerialPort};
use rns_net::Parity;

const BAUD: u32 = 115_200;
const BANDWIDTH: u32 = 125_000;
const TXPOWER: i8 = 14;
const SPREADING_FACTOR: u8 = 8;
const CODING_RATE: u8 = 5;
const DETECT_TIMEOUT: Duration = Duration::from_secs(5);
const CONFIG_TIMEOUT: Duration = Duration::from_secs(3);
const RF_TIMEOUT: Duration = Duration::from_secs(8);
const LEAVE_SETTLE: Duration = Duration::from_millis(500);

struct HarnessNode {
    label: String,
    _port: SerialPort,
    reader: File,
    writer: File,
    decoder: RNodeDecoder,
}

#[derive(Debug)]
struct DeviceInfo {
    fw_major: u8,
    fw_minor: u8,
    fw_detail: String,
    platform: u8,
    mcu: u8,
}

fn main() -> io::Result<()> {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    let port_a = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "/dev/ttyUSB0".to_string());
    let port_b = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "/dev/ttyUSB1".to_string());
    let freq_mhz = args
        .get(3)
        .and_then(|arg| arg.parse::<f64>().ok())
        .unwrap_or(868.0);
    let frequency = (freq_mhz * 1_000_000.0) as u32;

    let mut node_a = HarnessNode::open("A", &port_a)?;
    let mut node_b = HarnessNode::open("B", &port_b)?;

    log::info!("Starting HIL run on {} and {}", port_a, port_b);

    let info_a = node_a.detect()?;
    let info_b = node_b.detect()?;
    log::info!(
        "A detected: fw={} platform=0x{:02X} mcu=0x{:02X}",
        if info_a.fw_detail.is_empty() {
            format!("{}.{}", info_a.fw_major, info_a.fw_minor)
        } else {
            info_a.fw_detail.clone()
        },
        info_a.platform,
        info_a.mcu
    );
    log::info!(
        "B detected: fw={} platform=0x{:02X} mcu=0x{:02X}",
        if info_b.fw_detail.is_empty() {
            format!("{}.{}", info_b.fw_major, info_b.fw_minor)
        } else {
            info_b.fw_detail.clone()
        },
        info_b.platform,
        info_b.mcu
    );

    node_a.configure_radio(frequency)?;
    node_b.configure_radio(frequency)?;

    let payload_ab = b"rnode-hil:a-to-b";
    let payload_ba = b"rnode-hil:b-to-a";
    exchange_payload(&mut node_a, &mut node_b, payload_ab)?;
    exchange_payload(&mut node_b, &mut node_a, payload_ba)?;

    // Frames over 254 bytes go out as two LoRa packets (RNode firmware's
    // split packets); every byte value, KISS escapes included.
    let long_ab: Vec<u8> = (0..400u32).map(|i| (i * 7) as u8).collect();
    let long_ba: Vec<u8> = (0..508u32).map(|i| (i * 13 + 5) as u8).collect();
    exchange_payload(&mut node_a, &mut node_b, &long_ab)?;
    exchange_payload(&mut node_b, &mut node_a, &long_ba)?;

    node_a.leave_and_redetect()?;
    node_b.leave_and_redetect()?;

    log::info!("HIL run passed");
    Ok(())
}

impl HarnessNode {
    fn open(label: &str, path: &str) -> io::Result<Self> {
        let port = SerialPort::open(&SerialConfig {
            path: path.to_string(),
            baud: BAUD,
            data_bits: 8,
            parity: Parity::None,
            stop_bits: 1,
        })?;
        let reader = port.reader()?;
        let writer = port.writer()?;
        let mut node = Self {
            label: label.to_string(),
            _port: port,
            reader,
            writer,
            decoder: RNodeDecoder::new(),
        };
        node.drain_input()?;
        Ok(node)
    }

    fn detect(&mut self) -> io::Result<DeviceInfo> {
        self.drain_input()?;
        self.write_frame(&rnode_kiss::detect_request())?;
        self.write_frame(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_FW_VERSION,
            &[0x00],
        ))?;
        self.write_frame(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_FW_DETAIL,
            &[0x00],
        ))?;
        self.write_frame(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_PLATFORM,
            &[0x00],
        ))?;
        self.write_frame(&rnode_kiss::rnode_command(rnode_kiss::CMD_MCU, &[0x00]))?;

        let start = Instant::now();
        let mut detected = false;
        let mut info = DeviceInfo {
            fw_major: 0,
            fw_minor: 0,
            fw_detail: String::new(),
            platform: 0,
            mcu: 0,
        };
        let mut have_fw = false;
        let mut have_platform = false;
        let mut have_mcu = false;

        while start.elapsed() < DETECT_TIMEOUT {
            for event in self.read_events(Duration::from_millis(250))? {
                match event {
                    RNodeEvent::Detected(true) => detected = true,
                    RNodeEvent::FirmwareVersion { major, minor } => {
                        info.fw_major = major;
                        info.fw_minor = minor;
                        have_fw = true;
                    }
                    // rns-esp32 answers ROM_READ with its build version; an
                    // RNode with its EEPROM, which is not text.
                    RNodeEvent::FirmwareDetail(detail)
                        if detail.chars().all(|c| c.is_ascii_graphic()) =>
                    {
                        info.fw_detail = detail;
                    }
                    RNodeEvent::Platform(platform) => {
                        info.platform = platform;
                        have_platform = true;
                    }
                    RNodeEvent::Mcu(mcu) => {
                        info.mcu = mcu;
                        have_mcu = true;
                    }
                    _ => {}
                }
            }

            if detected && have_fw && have_platform && have_mcu {
                return Ok(info);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{}: timed out waiting for detect responses", self.label),
        ))
    }

    /// Configure the radio and wait for each setting to be echoed back. A
    /// READY frame is not awaited: rns-esp32 sends one here, RNode firmware
    /// does not.
    fn configure_radio(&mut self, frequency: u32) -> io::Result<()> {
        self.drain_input()?;

        self.write_frame(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_FREQUENCY,
            &frequency.to_be_bytes(),
        ))?;
        self.write_frame(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_BANDWIDTH,
            &BANDWIDTH.to_be_bytes(),
        ))?;
        self.write_frame(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_TXPOWER,
            &[TXPOWER as u8],
        ))?;
        self.write_frame(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_SF,
            &[SPREADING_FACTOR],
        ))?;
        self.write_frame(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_CR,
            &[CODING_RATE],
        ))?;
        self.write_frame(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_RADIO_STATE,
            &[rnode_kiss::RADIO_STATE_ON],
        ))?;

        let start = Instant::now();
        let mut got_frequency = false;
        let mut got_bandwidth = false;
        let mut got_power = false;
        let mut got_sf = false;
        let mut got_cr = false;
        let mut got_radio_state = false;

        while start.elapsed() < CONFIG_TIMEOUT {
            for event in self.read_events(Duration::from_millis(250))? {
                match event {
                    RNodeEvent::Frequency(value) if value == frequency => got_frequency = true,
                    RNodeEvent::Bandwidth(value) if value == BANDWIDTH => got_bandwidth = true,
                    RNodeEvent::TxPower(value) if value == TXPOWER => got_power = true,
                    RNodeEvent::SpreadingFactor(value) if value == SPREADING_FACTOR => {
                        got_sf = true
                    }
                    RNodeEvent::CodingRate(value) if value == CODING_RATE => got_cr = true,
                    RNodeEvent::RadioState(value) if value == rnode_kiss::RADIO_STATE_ON => {
                        got_radio_state = true
                    }
                    _ => {}
                }
            }

            if got_frequency && got_bandwidth && got_power && got_sf && got_cr && got_radio_state {
                log::info!(
                    "{} configured at {} MHz / BW {} / SF{} / CR 4/{} / {} dBm",
                    self.label,
                    frequency as f64 / 1_000_000.0,
                    BANDWIDTH,
                    SPREADING_FACTOR,
                    CODING_RATE,
                    TXPOWER
                );
                return Ok(());
            }
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "{}: timed out waiting for config acknowledgements",
                self.label
            ),
        ))
    }

    /// Hand a frame to the radio. RNode firmware reports no READY after
    /// transmitting (rns-esp32 does), so delivery is checked at the
    /// receiver.
    fn send_payload(&mut self, payload: &[u8]) -> io::Result<()> {
        self.write_frame(&rnode_kiss::rnode_data_frame(0, payload))
    }

    fn expect_payload(&mut self, payload: &[u8]) -> io::Result<()> {
        self.wait_for(RF_TIMEOUT, "RF data frame", |event| {
            matches!(
                event,
                RNodeEvent::DataFrame { index: 0, data } if data == payload
            )
        })?;
        Ok(())
    }

    fn leave_and_redetect(&mut self) -> io::Result<()> {
        self.write_frame(&rnode_kiss::rnode_command(rnode_kiss::CMD_LEAVE, &[]))?;
        std::thread::sleep(LEAVE_SETTLE);
        let info = self.detect()?;
        let fw = if info.fw_detail.is_empty() {
            format!("{}.{}", info.fw_major, info.fw_minor)
        } else {
            info.fw_detail.clone()
        };
        log::info!(
            "{} returned to standalone and re-detected as fw={}",
            self.label,
            fw
        );
        Ok(())
    }

    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        self.writer.write_all(frame)?;
        self.writer.flush()
    }

    fn drain_input(&mut self) -> io::Result<()> {
        let mut buf = [0u8; 512];
        while poll_read(self.reader.as_raw_fd(), 25)? {
            let n = self.reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let _ = self.decoder.feed(&buf[..n]);
        }
        Ok(())
    }

    fn read_events(&mut self, timeout: Duration) -> io::Result<Vec<RNodeEvent>> {
        if !poll_read(self.reader.as_raw_fd(), duration_to_poll_ms(timeout))? {
            return Ok(Vec::new());
        }

        let mut buf = [0u8; 1024];
        let n = self.reader.read(&mut buf)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{}: serial port closed", self.label),
            ));
        }
        Ok(self.decoder.feed(&buf[..n]))
    }

    fn wait_for<F>(&mut self, timeout: Duration, what: &str, mut predicate: F) -> io::Result<()>
    where
        F: FnMut(&RNodeEvent) -> bool,
    {
        let start = Instant::now();
        while start.elapsed() < timeout {
            for event in self.read_events(Duration::from_millis(250))? {
                if predicate(&event) {
                    return Ok(());
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{}: timed out waiting for {}", self.label, what),
        ))
    }
}

fn exchange_payload(
    sender: &mut HarnessNode,
    receiver: &mut HarnessNode,
    payload: &[u8],
) -> io::Result<()> {
    sender.send_payload(payload)?;
    receiver.expect_payload(payload)?;
    log::info!(
        "{} -> {} delivered {} bytes",
        sender.label,
        receiver.label,
        payload.len()
    );
    Ok(())
}

fn poll_read(fd: i32, timeout_ms: i32) -> io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc > 0)
}

fn duration_to_poll_ms(duration: Duration) -> i32 {
    duration.as_millis().min(i32::MAX as u128) as i32
}
