//! Setting up an RNode's device once its connection is open, as upstream's
//! `RNodeInterface.configure_device` does: detect it, configure the radio,
//! and check what the device reports back, with upstream's log lines.

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::transport::Transport;
use super::{
    configure_subinterface, detect_and_configure, reader_ready, wait_while_running, DeviceWriter,
    RNodeConfig, RNodeSubConfig,
};
use crate::interface::lock_or_recover;
use crate::rnode_kiss::{self, RNodeEvent};

/// How long upstream gives the hardware after opening its connection.
const SETTLE: Duration = Duration::from_secs(2);
/// How long a detect request may take to be answered.
const DETECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How the device is reached, as upstream tells its connections apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Link {
    Serial,
    Tcp,
    Ble,
}

impl Link {
    pub(super) fn of(port: &str) -> Link {
        if super::ble::is_ble_port(port) {
            Link::Ble
        } else if port.starts_with("tcp:") {
            Link::Tcp
        } else {
            Link::Serial
        }
    }

    /// How long upstream waits for the radio to report its configuration.
    fn validation_wait(self) -> Duration {
        match self {
            Link::Serial => Duration::from_millis(250),
            Link::Tcp => Duration::from_millis(1500),
            Link::Ble => Duration::from_secs(1),
        }
    }
}

/// Whether `config` is a single RNode over BLE, which upstream opens,
/// loses and reopens in ways of its own.
pub(super) fn is_ble(config: &RNodeConfig) -> bool {
    !config.multi && config.pre_opened_fd.is_none() && Link::of(&config.port) == Link::Ble
}

/// The port as upstream names it in its log lines.
pub(super) fn port_display(config: &RNodeConfig) -> String {
    if is_ble(config) {
        super::ble::port_display(&config.ble)
    } else {
        config.port.clone()
    }
}

/// Upstream's `str()` of a single RNode interface.
pub(super) fn display_name(config: &RNodeConfig) -> String {
    format!("RNodeInterface[{}]", config.name)
}

/// The message upstream logs when it starts opening the connection.
pub(super) fn log_opening(config: &RNodeConfig) {
    if config.multi {
        return;
    }
    match Link::of(&config.port) {
        Link::Serial => log::info!(
            target: crate::logging::NOTICE_TARGET,
            "Opening serial port {}...",
            config.port
        ),
        Link::Tcp => log::info!(
            target: crate::logging::NOTICE_TARGET,
            "Opening TCP connection for {}...",
            display_name(config)
        ),
        Link::Ble => log::info!(
            target: crate::logging::NOTICE_TARGET,
            "Opening BLE connection for {}...",
            display_name(config)
        ),
    }
}

/// Settle, then detect and configure the device on a connection just
/// opened. Fails when the interface stops meanwhile.
pub(super) fn setup_device(
    reader: &mut Transport,
    writer: &Arc<Mutex<DeviceWriter>>,
    config: &RNodeConfig,
    running: &AtomicBool,
) -> io::Result<()> {
    if !wait_while_running(running, SETTLE) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "the interface stopped",
        ));
    }
    if config.multi {
        detect_and_configure(reader, writer, config)
    } else {
        let result = configure_device(reader, writer, config);
        if result.is_err() {
            // As upstream closes the connection: a BLE device is
            // disconnected.
            reader.close();
        }
        result
    }
}

/// What the device reports about its radio, kept as upstream's `r_*`
/// fields, logging what upstream logs as reports arrive.
#[derive(Debug, Default, Clone)]
pub(super) struct RadioReports {
    pub(super) detected: bool,
    pub(super) frequency: Option<u32>,
    pub(super) bandwidth: Option<u32>,
    pub(super) txpower: Option<u8>,
    pub(super) spreading_factor: Option<u8>,
    pub(super) coding_rate: Option<u8>,
    pub(super) state: Option<u8>,
    /// The radio timing last reported, shared across the interface's
    /// connections.
    phy: Arc<Mutex<Option<[u16; 6]>>>,
}

impl RadioReports {
    pub(super) fn new(config: &RNodeConfig) -> Self {
        RadioReports {
            phy: Arc::clone(&config.reported_phy),
            ..RadioReports::default()
        }
    }

    /// Take one report from the device. `name` is the interface as
    /// upstream writes it.
    pub(super) fn apply(&mut self, event: &RNodeEvent, name: &str) {
        match *event {
            RNodeEvent::Detected(detected) => self.detected = detected,
            RNodeEvent::Frequency(hz) => {
                self.frequency = Some(hz);
                log::debug!(
                    "{} Radio reporting frequency is {} MHz",
                    name,
                    py_float(f64::from(hz) / 1_000_000.0)
                );
                self.update_bitrate(name);
            }
            RNodeEvent::Bandwidth(hz) => {
                self.bandwidth = Some(hz);
                log::debug!(
                    "{} Radio reporting bandwidth is {} KHz",
                    name,
                    py_float(f64::from(hz) / 1000.0)
                );
                self.update_bitrate(name);
            }
            RNodeEvent::TxPower(dbm) => {
                // Upstream keeps the raw byte.
                let raw = dbm as u8;
                self.txpower = Some(raw);
                log::debug!("{} Radio reporting TX power is {} dBm", name, raw);
            }
            RNodeEvent::SpreadingFactor(sf) => {
                self.spreading_factor = Some(sf);
                log::debug!("{} Radio reporting spreading factor is {}", name, sf);
                self.update_bitrate(name);
            }
            RNodeEvent::CodingRate(cr) => {
                self.coding_rate = Some(cr);
                log::debug!("{} Radio reporting coding rate is {}", name, cr);
                self.update_bitrate(name);
            }
            RNodeEvent::RadioState(state) => {
                self.state = Some(state);
                if state == 0 {
                    log::debug!("{} Radio reporting state is offline", name);
                }
            }
            RNodeEvent::StAlock(at) => log::debug!(
                "{} Radio reporting short-term airtime limit is {}%",
                name,
                py_float(f64::from(at) / 100.0)
            ),
            RNodeEvent::LtAlock(at) => log::debug!(
                "{} Radio reporting long-term airtime limit is {}%",
                name,
                py_float(f64::from(at) / 100.0)
            ),
            RNodeEvent::PhyStats {
                symbol_time_us,
                symbol_rate,
                preamble_symbols,
                preamble_ms,
                csma_slot_ms,
                difs_ms,
            } => {
                let reported = [
                    symbol_time_us,
                    symbol_rate,
                    preamble_symbols,
                    preamble_ms,
                    csma_slot_ms,
                    difs_ms,
                ];
                let mut last = lock_or_recover(&self.phy, "rnode reported phy");
                if *last != Some(reported) {
                    *last = Some(reported);
                    let symbol_ms = py_round2(f64::from(symbol_time_us) / 1000.0).unwrap_or(0.0);
                    log::debug!(
                        "{} Radio reporting symbol time is {}ms ({} baud)",
                        name,
                        py_float(symbol_ms),
                        symbol_rate
                    );
                    log::debug!(
                        "{} Radio reporting preamble is {} symbols ({}ms)",
                        name,
                        preamble_symbols,
                        preamble_ms
                    );
                    log::debug!(
                        "{} Radio reporting CSMA slot time is {}ms",
                        name,
                        csma_slot_ms
                    );
                    log::debug!("{} Radio reporting DIFS time is {}ms", name, difs_ms);
                }
            }
            RNodeEvent::ChannelStats { interference, .. } if interference != 0xFF => {
                log::debug!(
                    "{} Radio detected interference at {} dBm",
                    name,
                    i16::from(interference) - 157
                );
            }
            RNodeEvent::Error(code) => log_hardware_error(name, code),
            _ => {}
        }
    }

    /// Upstream's `updateBitrate`: logged once every parameter it needs
    /// has been reported.
    fn update_bitrate(&self, name: &str) {
        if let Some(kbps) = self.bitrate_kbps() {
            log::info!("{} On-air bitrate is now {} kbps", name, py_float(kbps));
        }
    }

    fn bitrate_kbps(&self) -> Option<f64> {
        let sf = f64::from(self.spreading_factor?);
        let cr = f64::from(self.coding_rate?);
        let bw = f64::from(self.bandwidth?);
        if cr == 0.0 || bw == 0.0 {
            return None;
        }
        let bitrate = sf * ((4.0 / cr) / (2f64.powf(sf) / (bw / 1000.0))) * 1000.0;
        py_round2(bitrate / 1000.0)
    }
}

/// Upstream's line for an error the device reports.
fn log_hardware_error(name: &str, code: u8) {
    match code {
        0x01 => log::error!("{} hardware initialisation error (code {:02x})", name, code),
        0x02 => log::error!("{} hardware TX error (code {:02x})", name, code),
        0x05 => log::error!(
            "{} hardware error (code {:02x}): Memory exhausted",
            name,
            code
        ),
        0x06 => log::error!(
            "{} hardware error (code {:02x}): Modem communication timed out",
            name,
            code
        ),
        _ => log::error!("{} hardware error (code {:02x})", name, code),
    }
}

/// Python's `str()` of a float in the range RNode reports use: the
/// shortest form that reads back the same, with `.0` on whole numbers.
pub(super) fn py_float(value: f64) -> String {
    let text = format!("{value}");
    if !value.is_finite() || text.contains('.') {
        text
    } else {
        format!("{text}.0")
    }
}

/// Python's `round(value, 2)`.
fn py_round2(value: f64) -> Option<f64> {
    value
        .is_finite()
        .then(|| format!("{value:.2}").parse().ok())
        .flatten()
}

/// Read what the device sends until `deadline`, or until `done` says so,
/// feeding every report to `reports`. Errs with `UnexpectedEof` when the
/// connection closes.
fn read_reports(
    reader: &mut (impl Read + AsRawFd),
    decoder: &mut rnode_kiss::RNodeDecoder,
    reports: &mut RadioReports,
    name: &str,
    deadline: Instant,
    done: impl Fn(&RadioReports) -> bool,
) -> io::Result<()> {
    let mut buf = [0u8; 4096];
    while !done(reports) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }
        if !reader_ready(reader, remaining.min(Duration::from_millis(100))) {
            continue;
        }
        match reader.read(&mut buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the device connection closed",
                ))
            }
            Ok(n) => {
                for event in decoder.feed(buf.get(..n).unwrap_or_default()) {
                    reports.apply(&event, name);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// How long the device's answer to turning its radio off is waited for
/// while a BLE connection closes.
pub(super) const CLOSING_ANSWER_WAIT: Duration = Duration::from_secs(1);

/// Read what the device answers while its connection closes, logging as
/// upstream's reader does until the connection is gone: up to the radio
/// state it reports, or `deadline`.
pub(super) fn read_closing_answer(
    reader: &mut (impl Read + AsRawFd),
    config: &RNodeConfig,
    deadline: Instant,
) {
    let mut reports = RadioReports::new(config);
    let _ = read_reports(
        reader,
        &mut rnode_kiss::RNodeDecoder::new(),
        &mut reports,
        &display_name(config),
        deadline,
        |reports| reports.state.is_some(),
    );
}

/// Detect a single RNode, configure its radio and check what it reports,
/// as upstream's `configure_device`.
fn configure_device(
    reader: &mut Transport,
    writer: &Arc<Mutex<DeviceWriter>>,
    config: &RNodeConfig,
) -> io::Result<()> {
    let name = display_name(config);
    let link = Link::of(&config.port);
    let sub = config.subinterfaces.first().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "No subinterfaces configured")
    })?;
    let mut decoder = rnode_kiss::RNodeDecoder::new();
    let mut reports = RadioReports::new(config);

    lock_or_recover(writer, "rnode shared writer").write_all(&detect_command())?;
    let detecting = read_reports(
        reader,
        &mut decoder,
        &mut reports,
        &name,
        Instant::now() + DETECT_TIMEOUT,
        |reports| reports.detected,
    );
    match detecting {
        Ok(()) => {}
        // A BLE device that goes away is noticed only once detecting it
        // timed out.
        Err(e) if link == Link::Ble && e.kind() == io::ErrorKind::UnexpectedEof => {
            reader.lost();
        }
        Err(e) => return Err(e),
    }
    if !reports.detected {
        match link {
            Link::Tcp => log::error!("RNode detect timed out over TCP"),
            Link::Ble => log::error!("RNode detect timed out over BLE"),
            Link::Serial => {}
        }
        log::error!("Could not detect device for {}", name);
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "RNode detection timed out",
        ));
    }

    match link {
        Link::Serial => log::info!("Serial port {} is now open", config.port),
        Link::Tcp => log::info!(
            "TCP connection to {} is now open",
            config.port.trim_start_matches("tcp:")
        ),
        Link::Ble => log::info!("BLE connection to {} is now open", name),
    }
    log::info!("Configuring RNode interface...");
    configure_subinterface(writer, sub.vport, sub, false)?;

    let mut disappeared = false;
    let mut settle = |wait: Duration, reports: &mut RadioReports| -> io::Result<()> {
        if disappeared {
            return Ok(());
        }
        match read_reports(
            reader,
            &mut decoder,
            reports,
            &name,
            Instant::now() + wait,
            |_| false,
        ) {
            Err(e) if link == Link::Ble && e.kind() == io::ErrorKind::UnexpectedEof => {
                reader.lost();
                disappeared = true;
                Ok(())
            }
            other => other,
        }
    };
    if link == Link::Ble {
        // Upstream gives a radio over BLE two seconds to take its settings.
        settle(Duration::from_secs(2), &mut reports)?;
    }
    log::info!("Waiting for radio configuration validation for {}...", name);
    settle(link.validation_wait(), &mut reports)?;
    if disappeared {
        log::error!(
            "Device disappeared during radio state validation for {}",
            name
        );
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the device disappeared during radio state validation",
        ));
    }

    if !radio_state_valid(&reports, sub) {
        log::error!(
            "After configuring {}, the reported radio parameters did not match your configuration.",
            name
        );
        log::error!(
            "Make sure that your hardware actually supports the parameters specified in the configuration"
        );
        log::error!("Aborting RNode startup");
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the reported radio parameters did not match the configuration",
        ));
    }
    log::info!(
        target: crate::logging::NOTICE_TARGET,
        "{} is configured and powered up",
        name
    );
    std::thread::sleep(Duration::from_millis(300));
    Ok(())
}

/// Upstream's detect request, with the firmware details asked for too.
fn detect_command() -> Vec<u8> {
    let mut cmd = rnode_kiss::detect_request();
    for command in [
        rnode_kiss::CMD_FW_VERSION,
        rnode_kiss::CMD_FW_DETAIL,
        rnode_kiss::CMD_PLATFORM,
        rnode_kiss::CMD_MCU,
    ] {
        cmd.extend_from_slice(&rnode_kiss::rnode_command(command, &[0x00]));
    }
    cmd
}

/// Upstream's `validateRadioState`: the radio reports what was configured.
fn radio_state_valid(reports: &RadioReports, sub: &RNodeSubConfig) -> bool {
    let mut valid = true;
    if let Some(frequency) = reports.frequency {
        if (i64::from(sub.frequency) - i64::from(frequency)).abs() > 100 {
            log::error!("Frequency mismatch");
            valid = false;
        }
    }
    if reports.bandwidth != Some(sub.bandwidth) {
        log::error!("Bandwidth mismatch");
        valid = false;
    }
    if reports.txpower != Some(sub.txpower as u8) {
        log::error!("TX power mismatch");
        valid = false;
    }
    if reports.spreading_factor != Some(sub.spreading_factor) {
        log::error!("Spreading factor mismatch");
        valid = false;
    }
    if reports.state != Some(rnode_kiss::RADIO_STATE_ON) {
        log::error!("Radio state mismatch");
        valid = false;
    }
    valid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_read_as_python_writes_them() {
        assert_eq!(py_float(868.0), "868.0");
        assert_eq!(py_float(869.525), "869.525");
        assert_eq!(py_float(125.0), "125.0");
        assert_eq!(py_float(62.5), "62.5");
        assert_eq!(py_float(10.0), "10.0");
    }

    #[test]
    fn bitrate_is_upstreams_once_known() {
        let mut reports = RadioReports {
            bandwidth: Some(125_000),
            spreading_factor: Some(8),
            ..Default::default()
        };
        assert_eq!(reports.bitrate_kbps(), None);
        reports.coding_rate = Some(5);
        // round(3.125, 2) in Python is 3.12.
        assert_eq!(py_float(reports.bitrate_kbps().unwrap()), "3.12");
        reports.spreading_factor = Some(7);
        reports.bandwidth = Some(250_000);
        assert_eq!(py_float(reports.bitrate_kbps().unwrap()), "10.94");
        reports.spreading_factor = Some(12);
        reports.bandwidth = Some(7_800);
        reports.coding_rate = Some(8);
        assert_eq!(py_float(reports.bitrate_kbps().unwrap()), "0.01");
    }

    #[test]
    fn radio_timing_is_kept_across_connections() {
        let config = RNodeConfig::default();
        let phy = RNodeEvent::PhyStats {
            symbol_time_us: 2048,
            symbol_rate: 488,
            preamble_symbols: 18,
            preamble_ms: 37,
            csma_slot_ms: 24,
            difs_ms: 48,
        };
        let mut first = RadioReports::new(&config);
        first.apply(&phy, "RNodeInterface[t]");
        // A later connection shares what was reported, so the same timing
        // is not reported as new.
        let second = RadioReports::new(&config);
        assert_eq!(
            *second.phy.lock().unwrap(),
            Some([2048, 488, 18, 37, 24, 48])
        );
        assert_eq!(py_float(py_round2(2048.0 / 1000.0).unwrap()), "2.05");
    }

    #[test]
    fn radio_state_must_match_what_was_configured() {
        let sub = RNodeSubConfig {
            name: "test".into(),
            vport: 0,
            outgoing: true,
            frequency: 868_000_000,
            bandwidth: 125_000,
            txpower: 7,
            spreading_factor: 8,
            coding_rate: 5,
            flow_control: false,
            st_alock: None,
            lt_alock: None,
        };
        let reported = RadioReports {
            detected: true,
            frequency: Some(868_000_050),
            bandwidth: Some(125_000),
            txpower: Some(7),
            spreading_factor: Some(8),
            coding_rate: Some(5),
            state: Some(rnode_kiss::RADIO_STATE_ON),
            phy: Default::default(),
        };
        assert!(radio_state_valid(&reported, &sub));
        // An unreported frequency is not checked, as upstream.
        let mut unreported = reported.clone();
        unreported.frequency = None;
        assert!(radio_state_valid(&unreported, &sub));
        for broken in [
            RadioReports {
                frequency: Some(868_000_200),
                ..reported.clone()
            },
            RadioReports {
                bandwidth: None,
                ..reported.clone()
            },
            RadioReports {
                txpower: Some(2),
                ..reported.clone()
            },
            RadioReports {
                spreading_factor: Some(9),
                ..reported.clone()
            },
            RadioReports {
                state: Some(0),
                ..reported.clone()
            },
        ] {
            assert!(!radio_state_valid(&broken, &sub));
        }
    }
}
