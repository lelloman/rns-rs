//! RNode LoRa radio interface.
//!
//! Manages serial connection to RNode device, detects firmware,
//! configures radio parameters per subinterface. Supports single-radio
//! (RNodeInterface) and multi-radio (RNodeMultiInterface) devices.
//!
//! Matches Python `RNodeInterface.py` and `RNodeMultiInterface.py`.

mod ble;
mod folded;
mod setup;
mod transport;

pub use ble::LinkState as BleLinkState;

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use transport::Transport;

/// The shared write side of an RNode connection.
pub type DeviceWriter = crate::interface::device_writer::DeviceWriter<Transport>;

use rns_core::transport::types::{AirtimeProfile, InterfaceId};

use crate::common::interface_stats::RadioStats;
use crate::event::{Event, EventSender, InterfaceTelemetry};
use crate::interface::{lock_or_recover, Writer};
use crate::rnode_kiss;
use crate::serial::{Parity, SerialConfig};

/// Validation limits matching Python RNodeInterface.
pub const FREQ_MIN: u32 = 137_000_000;
pub const FREQ_MAX: u32 = 3_000_000_000;
pub const BW_MIN: u32 = 7_800;
pub const BW_MAX: u32 = 1_625_000;
pub const SF_MIN: u8 = 5;
pub const SF_MAX: u8 = 12;
pub const CR_MIN: u8 = 5;
pub const CR_MAX: u8 = 8;
pub const TXPOWER_MIN: i8 = 0;
pub const TXPOWER_MAX: i8 = 37;
pub const HW_MTU: u32 = 508;
pub const LORA_PREAMBLE_SYMBOLS: u16 = 8;
pub const LORA_EXPLICIT_HEADER: bool = true;
pub const LORA_CRC: bool = true;

/// Configuration for one RNode subinterface (radio).
#[derive(Debug, Clone)]
pub struct RNodeSubConfig {
    pub name: String,
    pub vport: u8,
    pub outgoing: bool,
    pub frequency: u32,
    pub bandwidth: u32,
    pub txpower: i8,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub flow_control: bool,
    pub st_alock: Option<f32>,
    pub lt_alock: Option<f32>,
}

/// Configuration for the RNode device.
#[derive(Debug, Clone)]
pub struct RNodeConfig {
    pub name: String,
    pub port: String,
    pub speed: u32,
    pub subinterfaces: Vec<RNodeSubConfig>,
    pub multi: bool,
    pub id_interval: Option<u32>,
    pub id_callsign: Option<Vec<u8>>,
    /// The interface's own id. An `RNodeMultiInterface` is listed under it
    /// while its subinterfaces take the ids after it, from
    /// `base_interface_id` on, in the order upstream adds them; a single
    /// RNode's only subinterface is the interface itself.
    pub interface_id: InterfaceId,
    /// The id of the first subinterface; the others follow it.
    pub base_interface_id: InterfaceId,
    /// Pre-opened file descriptor (e.g. from a USB bridge socketpair on Android).
    /// When set, `start()` uses this fd directly instead of opening `port`.
    pub pre_opened_fd: Option<i32>,
    pub underlay_mark: Option<u32>,
    pub runtime: Arc<Mutex<RNodeRuntime>>,
    /// What a BLE connection (`port = ble://...`) remembers between
    /// connections.
    pub ble: Arc<Mutex<BleLinkState>>,
    /// The radio timing a single RNode last reported, kept across
    /// connections: upstream logs it only when it changes.
    pub reported_phy: Arc<Mutex<Option<[u16; 6]>>>,
}

#[derive(Debug, Clone)]
pub struct RNodeRuntime {
    pub sub: RNodeSubConfig,
    pub writer: Option<Arc<Mutex<DeviceWriter>>>,
}

impl RNodeRuntime {
    pub fn from_config(config: &RNodeConfig) -> Self {
        Self {
            sub: config
                .subinterfaces
                .first()
                .cloned()
                .unwrap_or_else(|| RNodeSubConfig {
                    name: config.name.clone(),
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
                }),
            writer: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RNodeRuntimeConfigHandle {
    pub interface_name: String,
    pub runtime: Arc<Mutex<RNodeRuntime>>,
    pub startup: RNodeRuntime,
}

impl Default for RNodeConfig {
    fn default() -> Self {
        let mut config = RNodeConfig {
            name: String::new(),
            port: String::new(),
            speed: 115200,
            subinterfaces: Vec::new(),
            multi: false,
            id_interval: None,
            id_callsign: None,
            interface_id: InterfaceId(0),
            base_interface_id: InterfaceId(0),
            pre_opened_fd: None,
            underlay_mark: None,
            runtime: Arc::new(Mutex::new(RNodeRuntime {
                sub: RNodeSubConfig {
                    name: String::new(),
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
                },
                writer: None,
            })),
            ble: Default::default(),
            reported_phy: Default::default(),
        };
        let startup = RNodeRuntime::from_config(&config);
        config.runtime = Arc::new(Mutex::new(startup));
        config
    }
}

/// Validate subinterface configuration. Returns error message if invalid.
pub fn validate_sub_config(sub: &RNodeSubConfig) -> Option<String> {
    if sub.frequency < FREQ_MIN || sub.frequency > FREQ_MAX {
        return Some(format!(
            "Invalid frequency {} for {}",
            sub.frequency, sub.name
        ));
    }
    if sub.bandwidth < BW_MIN || sub.bandwidth > BW_MAX {
        return Some(format!(
            "Invalid bandwidth {} for {}",
            sub.bandwidth, sub.name
        ));
    }
    if sub.spreading_factor < SF_MIN || sub.spreading_factor > SF_MAX {
        return Some(format!(
            "Invalid SF {} for {}",
            sub.spreading_factor, sub.name
        ));
    }
    if sub.coding_rate < CR_MIN || sub.coding_rate > CR_MAX {
        return Some(format!("Invalid CR {} for {}", sub.coding_rate, sub.name));
    }
    if sub.txpower < TXPOWER_MIN || sub.txpower > TXPOWER_MAX {
        return Some(format!("Invalid TX power {} for {}", sub.txpower, sub.name));
    }
    if let Some(st) = sub.st_alock {
        if !(0.0..=100.0).contains(&st) {
            return Some(format!("Invalid ST airtime limit {} for {}", st, sub.name));
        }
    }
    if let Some(lt) = sub.lt_alock {
        if !(0.0..=100.0).contains(&lt) {
            return Some(format!("Invalid LT airtime limit {} for {}", lt, sub.name));
        }
    }
    None
}

/// Estimate the LoRa physical bit rate for announce bandwidth gating.
///
/// Formula: SF * (bandwidth / 2^SF) * (4 / coding_rate).
pub fn estimate_lora_bitrate_bps(sub: &RNodeSubConfig) -> u64 {
    let symbols_per_second = sub.bandwidth as f64 / (1u64 << sub.spreading_factor) as f64;
    let bits_per_symbol = sub.spreading_factor as f64 * (4.0 / sub.coding_rate as f64);
    (symbols_per_second * bits_per_symbol).round().max(1.0) as u64
}

pub fn lora_airtime_profile(sub: &RNodeSubConfig) -> AirtimeProfile {
    AirtimeProfile::Lora {
        bandwidth: sub.bandwidth,
        spreading_factor: sub.spreading_factor,
        coding_rate: sub.coding_rate,
        preamble_symbols: LORA_PREAMBLE_SYMBOLS,
        explicit_header: LORA_EXPLICIT_HEADER,
        crc: LORA_CRC,
    }
}

/// Writer for a specific RNode subinterface.
/// Wraps a shared serial writer with subinterface-specific data framing.
struct RNodeSubWriter {
    confirmed_pending: Option<Vec<u8>>,
    writer: Arc<Mutex<DeviceWriter>>,
    index: u8,
    flow_control: bool,
    flow_state: Arc<Mutex<SubFlowState>>,
    multi: bool,
}

struct SubFlowState {
    ready: bool,
    queue: std::collections::VecDeque<Vec<u8>>,
}

fn make_sub_writer(
    writer: Arc<Mutex<DeviceWriter>>,
    index: u8,
    flow_control: bool,
    flow_state: Arc<Mutex<SubFlowState>>,
    multi: bool,
) -> Box<dyn Writer> {
    Box::new(RNodeSubWriter {
        confirmed_pending: None,
        writer,
        index,
        flow_control,
        flow_state,
        multi,
    })
}

impl Writer for RNodeSubWriter {
    fn send_frame_confirmed(&mut self, data: &[u8]) -> io::Result<()> {
        if !self.flow_control {
            return self.send_frame(data);
        }
        self.confirmed_pending = Some(if self.multi {
            rnode_kiss::rnode_multi_data_frame(self.index, data)
        } else {
            rnode_kiss::rnode_data_frame(self.index, data)
        });
        self.flush()
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.confirmed_pending.is_none() {
            return Ok(());
        }
        let mut state = lock_or_recover(&self.flow_state, "rnode flow state");
        if !state.ready || !state.queue.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        state.ready = false;
        drop(state);
        lock_or_recover(&self.writer, "rnode shared writer")
            .write_all(&self.confirmed_pending.take().unwrap())
    }
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        let frame = if self.multi {
            rnode_kiss::rnode_multi_data_frame(self.index, data)
        } else {
            rnode_kiss::rnode_data_frame(self.index, data)
        };
        if self.flow_control {
            let mut state = lock_or_recover(&self.flow_state, "rnode flow state");
            if state.ready {
                state.ready = false;
                drop(state);
                lock_or_recover(&self.writer, "rnode shared writer").write_all(&frame)
            } else {
                state.queue.push_back(data.to_vec());
                Ok(())
            }
        } else {
            lock_or_recover(&self.writer, "rnode shared writer").write_all(&frame)
        }
    }

    fn enqueue_confirmed(
        &mut self,
        data: &[u8],
        completion: &mut Option<crate::link_send::Completion>,
    ) -> io::Result<()> {
        // Driver-run (see `sends_inline`): a confirmed frame is taken only
        // when it is written at once; else WouldBlock leaves the completion
        // untouched and the driver retries.
        let frame = self.frame(data);
        let mut state = lock_or_recover(&self.flow_state, "rnode flow state");
        let mut writer = lock_or_recover(&self.writer, "rnode shared writer");
        if (self.flow_control && (!state.ready || !state.queue.is_empty()))
            || !writer.fits(frame.len())
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "RNode cannot take a frame yet",
            ));
        }
        writer.write_all(&frame)?;
        if self.flow_control {
            state.ready = false;
        }
        drop((writer, state));
        if let Some(completion) = completion.take() {
            completion.finish(Ok(()));
        }
        Ok(())
    }

    fn sends_inline(&self) -> bool {
        // With interface I/O folded the shared device writer never blocks.
        crate::engine::FOLD_IO
    }

    fn flush_pending(&mut self) {
        lock_or_recover(&self.writer, "rnode shared writer").drain();
    }
}

impl RNodeSubWriter {
    fn frame(&self, data: &[u8]) -> Vec<u8> {
        if self.multi {
            rnode_kiss::rnode_multi_data_frame(self.index, data)
        } else {
            rnode_kiss::rnode_data_frame(self.index, data)
        }
    }
}

type RNodeWriters = Vec<(InterfaceId, Box<dyn Writer>)>;

/// Start the RNode interface.
///
/// Opens serial port, spawns reader thread which performs detect+configure,
/// then enters data relay mode.
///
/// Returns one `(InterfaceId, Box<dyn Writer>)` per subinterface.
pub fn start(
    config: RNodeConfig,
    tx: EventSender,
) -> io::Result<Vec<(InterfaceId, Box<dyn Writer>)>> {
    start_with_control(config, tx).map(|(writers, _)| writers)
}

fn start_with_control(
    config: RNodeConfig,
    tx: EventSender,
) -> io::Result<(RNodeWriters, super::ListenerControl)> {
    // Validate all subinterface configs upfront
    for sub in &config.subinterfaces {
        if let Some(err) = validate_sub_config(sub) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, err));
        }
    }

    if config.subinterfaces.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "No subinterfaces configured",
        ));
    }

    let (reader_file, writer_transport) = if let Some(fd) = config.pre_opened_fd {
        // Pre-opened fd from USB bridge — dup for independent reader/writer handles
        let (reader, writer) = Transport::open_from_fd(fd)?;
        (Some(reader), writer)
    } else if setup::is_ble(&config) {
        // Finding and connecting a BLE device takes seconds: the setup
        // thread opens it.
        (None, Transport::Offline)
    } else {
        match open_device(&config) {
            Ok((reader, writer)) => (Some(reader), writer),
            // As upstream, the interface still comes up, offline, and
            // keeps trying to open its device.
            Err(e) => {
                log_open_failure(&config, &e);
                (None, Transport::Offline)
            }
        }
    };
    let shared_writer = Arc::new(Mutex::new(if crate::engine::FOLD_IO {
        DeviceWriter::driven(
            writer_transport,
            Arc::clone(tx.poller()),
            crate::interface::loop_writer::write_key(config.base_interface_id),
            &config.name,
        )
    } else {
        DeviceWriter::new(writer_transport)
    }));

    // Build per-subinterface writers and IDs
    let num_subs = config.subinterfaces.len();
    let mut writers: Vec<(InterfaceId, Box<dyn Writer>)> = Vec::with_capacity(num_subs);
    let mut flow_states: Vec<Arc<Mutex<SubFlowState>>> = Vec::with_capacity(num_subs);

    for (i, sub) in config.subinterfaces.iter().enumerate() {
        let sub_id = InterfaceId(config.base_interface_id.0 + i as u64);
        let flow_state = Arc::new(Mutex::new(SubFlowState {
            ready: true,
            queue: std::collections::VecDeque::new(),
        }));
        flow_states.push(flow_state.clone());
        let sub_writer = make_sub_writer(
            shared_writer.clone(),
            sub.vport,
            sub.flow_control,
            flow_state,
            config.multi,
        );
        writers.push((sub_id, sub_writer));
    }

    // Spawn reader thread
    let reader_shared_writer = shared_writer.clone();
    {
        let mut runtime = lock_or_recover(&config.runtime, "rnode runtime");
        runtime.writer = Some(shared_writer.clone());
        runtime.sub = config
            .subinterfaces
            .first()
            .cloned()
            .unwrap_or(runtime.sub.clone());
    }
    let running = Arc::new(AtomicBool::new(true));
    let shared_writer_for_leave = Arc::clone(&shared_writer);
    let finish_config = config.clone();
    if crate::engine::FOLD_IO {
        folded::RNodeLink::new(config, tx, shared_writer, flow_states, Arc::clone(&running))
            .start(reader_file)?;
        let control = super::ListenerControl::with_running_flag(running);
        return Ok((
            writers,
            with_leave_on_finish(control, shared_writer_for_leave, &finish_config),
        ));
    }
    let reader_config = config.clone();
    let reader_flow_states = flow_states;
    let reader_running = Arc::clone(&running);
    thread::Builder::new()
        .name(format!("rnode-reader-{}", config.base_interface_id.0))
        .spawn(move || {
            reader_loop(
                reader_file,
                reader_shared_writer,
                reader_config,
                tx,
                reader_flow_states,
                reader_running,
            );
        })?;

    // Spawn keepalive thread — sends periodic DETECT to prevent firmware
    // bridge idle timeout (ESP32 RNode reverts to standalone after 30s idle).
    let keepalive_writer = shared_writer.clone();
    let keepalive_name = config.name.clone();
    let keepalive_running = Arc::clone(&running);
    thread::Builder::new()
        .name(format!("rnode-keepalive-{}", config.base_interface_id.0))
        .spawn(move || {
            let detect = rnode_kiss::detect_request();
            while keepalive_running.load(Ordering::Relaxed) {
                if !wait_while_running(&keepalive_running, Duration::from_secs(15)) {
                    break;
                }
                if let Err(e) =
                    lock_or_recover(&keepalive_writer, "rnode shared writer").write_all(&detect)
                {
                    // Not while the device is away: that was said already.
                    if e.kind() != io::ErrorKind::NotConnected {
                        log::debug!("[{}] keepalive write failed: {}", keepalive_name, e);
                    }
                }
            }
        })?;

    let control = super::ListenerControl::with_running_flag(running);
    Ok((
        writers,
        with_leave_on_finish(control, shared_writer_for_leave, &finish_config),
    ))
}

/// Turn the radios off and send LEAVE when the interface finishes, as
/// upstream's `detach()`: the device can then stop bridging instead of
/// waiting for the host.
fn with_leave_on_finish(
    control: super::ListenerControl,
    writer: Arc<Mutex<DeviceWriter>>,
    config: &RNodeConfig,
) -> super::ListenerControl {
    let multi = config.multi;
    let vports: Vec<u8> = config.subinterfaces.iter().map(|sub| sub.vport).collect();
    let config = config.clone();
    control.with_on_finish(move || {
        let mut writer = lock_or_recover(&writer, "rnode shared writer");
        let off = [rnode_kiss::RADIO_STATE_OFF];
        if multi {
            for &vport in &vports {
                let _ = writer.write_all(&rnode_kiss::rnode_select_command(
                    vport,
                    rnode_kiss::CMD_RADIO_STATE,
                    &off,
                ));
            }
        } else {
            let _ = writer.write_all(&rnode_kiss::rnode_command(
                rnode_kiss::CMD_RADIO_STATE,
                &off,
            ));
        }
        let _ = writer.write_all(&rnode_kiss::leave_request());
        // Nothing serves a driven writer any more: send what it holds.
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        while writer.holds_unwritten() && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
            writer.drain();
        }
        // A BLE device is disconnected, as upstream's detach does, and
        // what it answers meanwhile is read, as upstream's reader keeps
        // reading until the connection is gone: the radio reporting it is
        // off.
        writer.transport().close_reading(|notify| {
            setup::read_closing_answer(
                notify,
                &config,
                std::time::Instant::now() + setup::CLOSING_ANSWER_WAIT,
            )
        });
    })
}

fn wait_while_running(running: &AtomicBool, duration: Duration) -> bool {
    let deadline = std::time::Instant::now() + duration;
    while running.load(Ordering::Relaxed) {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return true;
        }
        thread::sleep(remaining.min(Duration::from_millis(100)));
    }
    false
}

/// Reader loop: detect device, configure radios, then relay data frames.
fn reader_loop(
    reader: Option<Transport>,
    writer: Arc<Mutex<DeviceWriter>>,
    config: RNodeConfig,
    tx: EventSender,
    flow_states: Vec<Arc<Mutex<SubFlowState>>>,
    running: Arc<AtomicBool>,
) {
    let reader = reader.or_else(|| {
        setup::is_ble(&config)
            .then(|| first_ble_open(&config, &writer))
            .flatten()
    });
    let configured = reader.and_then(|mut reader| {
        match setup::setup_device(&mut reader, &writer, &config, &running) {
            Ok(()) => Some(reader),
            Err(e) => {
                log::debug!("[{}] initial RNode setup failed: {}", config.name, e);
                None
            }
        }
    });
    let (reader, reopened) = match configured {
        Some(reader) => (reader, false),
        // As upstream, keep trying to bring the device up.
        None => match open_until_configured(&config, &writer, &flow_states, &running) {
            Some(reader) => (reader, true),
            None => return,
        },
    };
    signal_interface_up(&tx, &config, &writer, &flow_states, reopened);
    reader_loop_connected(reader, writer, config, tx, flow_states, running);
}

/// Upstream `RNodeInterface.RECONNECT_WAIT`: how long to wait before each
/// attempt to open a device that could not be opened at start.
const OPEN_RETRY_WAIT: Duration = Duration::from_secs(5);

/// Open and configure a device that could not be opened at start, as
/// upstream's `reconnect_port` does: wait, then try, until it works or the
/// interface stops. Returns the configured connection.
fn open_until_configured(
    config: &RNodeConfig,
    writer: &Arc<Mutex<DeviceWriter>>,
    flow_states: &[Arc<Mutex<SubFlowState>>],
    running: &AtomicBool,
) -> Option<Transport> {
    loop {
        let attempt_at = std::time::Instant::now() + OPEN_RETRY_WAIT;
        let early = if setup::is_ble(config) {
            connect_ble_meanwhile(config, running, attempt_at)
        } else {
            None
        };
        if !wait_while_running(
            running,
            attempt_at.saturating_duration_since(std::time::Instant::now()),
        ) {
            return None;
        }
        if config.multi {
            log::debug!(
                "[{}] attempting to reconnect serial port {}",
                config.name,
                config.port
            );
        } else {
            log::info!(
                "Attempting to reconnect serial port {} for {}...",
                setup::port_display(config),
                setup::display_name(config)
            );
        }
        let opened = match early {
            // Connected while waiting: upstream's attempt finds it open.
            Some((reader, new_writer)) => {
                setup::log_opening(config);
                lock_or_recover(writer, "rnode shared writer").replace(new_writer);
                Ok(reader)
            }
            None => reopen_connection(config, writer),
        };
        match opened {
            Ok(mut reader) => {
                reset_flow_states(flow_states);
                match setup::setup_device(&mut reader, writer, config, running) {
                    Ok(()) => {
                        if config.multi {
                            log::info!("[{}] reconnected serial port {}", config.name, config.port);
                        } else {
                            log::info!(
                                target: crate::logging::NOTICE_TARGET,
                                "Reconnected port for {}",
                                setup::display_name(config)
                            );
                        }
                        return Some(reader);
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => return None,
                    // Upstream logs why the device did not come up while
                    // setting it up.
                    Err(e) if !config.multi && setup_error_logged(&e) => {}
                    Err(e) => log_reconnect_error(config, &e),
                }
            }
            Err(e) => log_reconnect_error(config, &e),
        }
    }
}

/// Look for and connect a BLE device while waiting for the next attempt
/// at `attempt_at`, as upstream's connection job keeps doing between
/// attempts (unless looking for it failed outright, which ends the job).
fn connect_ble_meanwhile(
    config: &RNodeConfig,
    running: &AtomicBool,
    attempt_at: std::time::Instant,
) -> Option<(Transport, Transport)> {
    if ble::job_ended(&config.ble) || !wait_while_running(running, ble::JOB_INTERVAL) {
        return None;
    }
    let budget = attempt_at.saturating_duration_since(std::time::Instant::now());
    if budget.is_zero() {
        return None;
    }
    let target = ble::Target::parse(&config.port).unwrap_or_default();
    Transport::open_ble(&target, &setup::display_name(config), &config.ble, budget).ok()
}

/// Whether setting a single RNode up already said why it failed.
fn setup_error_logged(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::InvalidData
    )
}

fn log_reconnect_error(config: &RNodeConfig, error: &io::Error) {
    if config.multi {
        log::error!(
            "[{}] error while reconnecting port, the contained exception was: {}",
            config.name,
            error
        );
    } else {
        log::error!(
            "Error while reconnecting port, the contained exception was: {}",
            error
        );
    }
}

/// Read a configured device until the interface stops, reconnecting when
/// the connection is lost.
fn reader_loop_connected(
    mut reader: Transport,
    writer: Arc<Mutex<DeviceWriter>>,
    config: RNodeConfig,
    tx: EventSender,
    flow_states: Vec<Arc<Mutex<SubFlowState>>>,
    running: Arc<AtomicBool>,
) {
    const RECONNECT_INITIAL_DELAY: Duration = Duration::from_millis(200);
    const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(2);
    // RNode is the PHY-stat-capable interface: retain each modem report until
    // the matching frame is enqueued, attach it to that frame, then clear it
    // so later frames cannot inherit stale RSSI or SNR.
    let mut last_rssi: Option<i16> = None;
    let mut last_snr: Option<f32> = None;
    // What the device reports about its channel and itself.
    let mut radio = RadioStats::default();
    let name = setup::display_name(&config);
    while running.load(Ordering::Relaxed) {
        let mut decoder = rnode_kiss::RNodeDecoder::new();
        let mut reports = setup::RadioReports::new(&config);
        let mut buf = [0u8; 4096];
        let disconnected = loop {
            if !running.load(Ordering::Relaxed) {
                return;
            }
            if !reader_ready(&reader, Duration::from_millis(200)) {
                continue;
            }
            // Once stopped, nothing more is read here: a BLE connection
            // reads the device's last answers while it closes.
            if !running.load(Ordering::Relaxed) {
                return;
            }
            match reader.read(&mut buf) {
                Ok(0) => {
                    if !running.load(Ordering::Relaxed) {
                        return;
                    }
                    if setup::is_ble(&config) {
                        reader.lost();
                    } else {
                        log::warn!("[{}] serial port closed", config.name);
                    }
                    signal_interface_down(&tx, &config);
                    break true;
                }
                Ok(n) => {
                    for event in decoder.feed(&buf[..n]) {
                        if config.multi {
                            log_multi_radio_report(&event, &config.name);
                        } else {
                            reports.apply(&event, &name);
                        }
                        if update_radio_stats(&event, &mut radio, crate::time::now()) {
                            publish_radio_telemetry(&tx, &config, &radio);
                            continue;
                        }
                        let phy_stat = matches!(
                            &event,
                            rnode_kiss::RNodeEvent::StatRssi(_)
                                | rnode_kiss::RNodeEvent::StatSnr(_)
                        );
                        if update_pending_rx_metadata(&event, &mut last_rssi, &mut last_snr) {
                            if phy_stat {
                                publish_phy_telemetry(&tx, &config, last_rssi, last_snr);
                            }
                            continue;
                        }
                        match event {
                            rnode_kiss::RNodeEvent::DataFrame { index, data } => {
                                let Some(position) = config
                                    .subinterfaces
                                    .iter()
                                    .position(|sub| usize::from(sub.vport) == index)
                                else {
                                    continue;
                                };
                                let sub_id =
                                    InterfaceId(config.base_interface_id.0 + position as u64);
                                if tx
                                    .send(Event::Frame {
                                        interface_id: sub_id,
                                        data: data.into(),
                                        rssi: last_rssi,
                                        snr: last_snr,
                                    })
                                    .is_err()
                                {
                                    return;
                                }
                                last_rssi = None;
                                last_snr = None;
                            }
                            rnode_kiss::RNodeEvent::Ready => {
                                // Flow control: unlock all subinterfaces that have flow_control
                                for (i, fs) in flow_states.iter().enumerate() {
                                    if config.subinterfaces[i].flow_control {
                                        process_flow_queue(
                                            fs,
                                            &writer,
                                            config.subinterfaces[i].vport,
                                            config.multi,
                                        );
                                    }
                                }
                            }
                            rnode_kiss::RNodeEvent::Error(code) if config.multi => {
                                log::error!("[{}] RNode error: 0x{:02X}", config.name, code);
                            }
                            _ => {
                                // Status updates logged but not acted on
                            }
                        }
                    }
                }
                Err(e) => {
                    if !running.load(Ordering::Relaxed) {
                        return;
                    }
                    if setup::is_ble(&config) {
                        reader.lost();
                    } else {
                        log::error!("[{}] serial read error: {}", config.name, e);
                    }
                    signal_interface_down(&tx, &config);
                    break true;
                }
            }
        };

        clear_pending_rx_metadata(&mut last_rssi, &mut last_snr);
        radio = RadioStats::default();

        if !running.load(Ordering::Relaxed) || !disconnected || config.pre_opened_fd.is_some() {
            return;
        }

        if setup::is_ble(&config) {
            // As upstream: wait, then try again, until the device is back.
            match open_until_configured(&config, &writer, &flow_states, &running) {
                Some(new_reader) => {
                    reader = new_reader;
                    signal_interface_up(&tx, &config, &writer, &flow_states, true);
                    continue;
                }
                None => return,
            }
        }

        let mut backoff = RECONNECT_INITIAL_DELAY;
        while running.load(Ordering::Relaxed) {
            match reopen_connection(&config, &writer) {
                Ok(new_reader) => {
                    reset_flow_states(&flow_states);
                    reader = new_reader;
                    if let Err(e) = setup::setup_device(&mut reader, &writer, &config, &running) {
                        log::warn!("[{}] reconnect configure failed: {}", config.name, e);
                        if !wait_while_running(&running, backoff) {
                            return;
                        }
                        backoff = std::cmp::min(backoff.saturating_mul(2), RECONNECT_MAX_DELAY);
                        continue;
                    }
                    signal_interface_up(&tx, &config, &writer, &flow_states, true);
                    break;
                }
                Err(e) => {
                    log::warn!("[{}] reconnect open failed: {}", config.name, e);
                    if !wait_while_running(&running, backoff) {
                        return;
                    }
                    backoff = std::cmp::min(backoff.saturating_mul(2), RECONNECT_MAX_DELAY);
                }
            }
        }
    }
}

fn reader_ready(reader: &impl AsRawFd, timeout: Duration) -> bool {
    let mut pfd = libc::pollfd {
        fd: reader.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    unsafe { libc::poll(&mut pfd, 1, timeout_ms) > 0 }
}

fn detect_and_configure(
    reader: &mut Transport,
    writer: &Arc<Mutex<DeviceWriter>>,
    config: &RNodeConfig,
) -> io::Result<()> {
    let detect_cmd = rnode_kiss::detect_request();
    let mut cmd = detect_cmd;
    cmd.extend_from_slice(&rnode_kiss::rnode_command(
        rnode_kiss::CMD_FW_VERSION,
        &[0x00],
    ));
    cmd.extend_from_slice(&rnode_kiss::rnode_command(
        rnode_kiss::CMD_FW_DETAIL,
        &[0x00],
    ));
    cmd.extend_from_slice(&rnode_kiss::rnode_command(
        rnode_kiss::CMD_PLATFORM,
        &[0x00],
    ));
    cmd.extend_from_slice(&rnode_kiss::rnode_command(rnode_kiss::CMD_MCU, &[0x00]));

    lock_or_recover(writer, "rnode shared writer").write_all(&cmd)?;

    let mut decoder = rnode_kiss::RNodeDecoder::new();
    let mut buf = [0u8; 4096];
    let mut detected = false;
    let detect_start = std::time::Instant::now();
    let detect_timeout = Duration::from_secs(5);

    while !detected && detect_start.elapsed() < detect_timeout {
        match reader.read(&mut buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "serial port closed during detect",
                ));
            }
            Ok(n) => {
                for event in decoder.feed(&buf[..n]) {
                    match event {
                        rnode_kiss::RNodeEvent::Detected(true) => {
                            detected = true;
                            log::info!("[{}] RNode device detected", config.name);
                        }
                        rnode_kiss::RNodeEvent::FirmwareVersion { major, minor } => {
                            log::info!("[{}] firmware version {}.{}", config.name, major, minor);
                        }
                        rnode_kiss::RNodeEvent::FirmwareDetail(ref detail) => {
                            log::info!("[{}] firmware detail: {}", config.name, detail);
                        }
                        rnode_kiss::RNodeEvent::Platform(p) => {
                            log::info!("[{}] platform: 0x{:02X}", config.name, p);
                        }
                        rnode_kiss::RNodeEvent::Mcu(m) => {
                            log::info!("[{}] MCU: 0x{:02X}", config.name, m);
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("serial read error during detect: {}", e),
                ));
            }
        }
    }

    if !detected {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "RNode detection timed out",
        ));
    }

    for sub in &config.subinterfaces {
        configure_subinterface(writer, sub.vport, sub, config.multi)?;
    }

    thread::sleep(Duration::from_millis(300));
    log::info!(
        "[{}] RNode configured with {} subinterface(s)",
        config.name,
        config.subinterfaces.len()
    );
    Ok(())
}

fn signal_interface_down(tx: &EventSender, config: &RNodeConfig) {
    for i in 0..config.subinterfaces.len() {
        let sub_id = InterfaceId(config.base_interface_id.0 + i as u64);
        let _ = tx.send(Event::InterfaceDown(sub_id));
    }
}

fn update_pending_rx_metadata(
    event: &rnode_kiss::RNodeEvent,
    last_rssi: &mut Option<i16>,
    last_snr: &mut Option<f32>,
) -> bool {
    match event {
        rnode_kiss::RNodeEvent::StatRssi(rssi) => {
            *last_rssi = Some(*rssi as i16 - 157);
            true
        }
        rnode_kiss::RNodeEvent::StatSnr(snr) => {
            *last_snr = Some(*snr as f32 * 0.25);
            true
        }
        _ => false,
    }
}

fn signal_interface_up(
    tx: &EventSender,
    config: &RNodeConfig,
    writer: &Arc<Mutex<DeviceWriter>>,
    flow_states: &[Arc<Mutex<SubFlowState>>],
    reconnected: bool,
) {
    for (i, flow_state) in flow_states.iter().enumerate() {
        let sub_id = InterfaceId(config.base_interface_id.0 + i as u64);
        let new_writer = reconnected.then(|| {
            make_sub_writer(
                writer.clone(),
                config.subinterfaces[i].vport,
                config.subinterfaces[i].flow_control,
                flow_state.clone(),
                config.multi,
            )
        });
        let _ = tx.send(Event::InterfaceUp(sub_id, new_writer, None));
    }
    // A device just (re)connected has reported nothing yet; upstream starts
    // from zero airtime and load and an unknown noise floor.
    for event in phy_telemetry(config, None, None, Some(RadioStats::default())) {
        let _ = tx.send(event);
    }
}

/// Apply a device report to `radio`, as upstream `RNodeInterface` keeps
/// it. Returns whether it changed what the interface reports; PHY and CSMA
/// reports are only logged, as upstream.
fn update_radio_stats(event: &rnode_kiss::RNodeEvent, radio: &mut RadioStats, now: f64) -> bool {
    const RSSI_OFFSET: i16 = 157;
    match *event {
        rnode_kiss::RNodeEvent::ChannelStats {
            airtime_short,
            airtime_long,
            channel_load_short,
            channel_load_long,
            current_rssi,
            noise_floor,
            interference,
        } => {
            radio.airtime_short = f64::from(airtime_short) / 100.0;
            radio.airtime_long = f64::from(airtime_long) / 100.0;
            radio.channel_load_short = f64::from(channel_load_short) / 100.0;
            radio.channel_load_long = f64::from(channel_load_long) / 100.0;
            radio.current_rssi = Some(i16::from(current_rssi) - RSSI_OFFSET);
            radio.noise_floor = Some(i16::from(noise_floor) - RSSI_OFFSET);
            radio.interference =
                (interference != 0xFF).then(|| i16::from(interference) - RSSI_OFFSET);
            if let Some(rssi) = radio.interference {
                radio.interference_last = Some((now, rssi));
            }
            true
        }
        rnode_kiss::RNodeEvent::Battery { state, percent } => {
            radio.battery_state = state;
            radio.battery_percent = percent.min(100);
            true
        }
        rnode_kiss::RNodeEvent::Temperature(raw) => {
            let celsius = i16::from(raw) - 120;
            radio.temperature = (-30..=90).contains(&celsius).then_some(celsius);
            true
        }
        // Logged by the caller, as upstream logs them.
        rnode_kiss::RNodeEvent::PhyStats { .. } | rnode_kiss::RNodeEvent::CsmaStats { .. } => false,
        _ => false,
    }
}

/// Log the radio timing and contention reports of an RNodeMultiInterface
/// device (a single RNode's are logged as upstream by its reports).
fn log_multi_radio_report(event: &rnode_kiss::RNodeEvent, name: &str) {
    match *event {
        rnode_kiss::RNodeEvent::PhyStats {
            symbol_time_us,
            symbol_rate,
            preamble_symbols,
            preamble_ms,
            csma_slot_ms,
            difs_ms,
        } => log::debug!(
            "[{}] radio reports {:.2} ms symbols ({} baud), {}-symbol preamble ({} ms), \
             CSMA slot {} ms, DIFS {} ms",
            name,
            f64::from(symbol_time_us) / 1000.0,
            symbol_rate,
            preamble_symbols,
            preamble_ms,
            csma_slot_ms,
            difs_ms
        ),
        rnode_kiss::RNodeEvent::CsmaStats {
            band,
            window_min,
            window_max,
        } => log::trace!(
            "[{}] radio reports contention window band {} ({}-{} slots)",
            name,
            band,
            window_min,
            window_max
        ),
        _ => {}
    }
}

/// Telemetry carrying only the device's channel and self report.
fn radio_telemetry<'a>(
    config: &'a RNodeConfig,
    radio: &'a RadioStats,
) -> impl Iterator<Item = Event> + 'a {
    (0..config.subinterfaces.len()).map(move |i| Event::InterfaceTelemetry {
        interface_id: InterfaceId(config.base_interface_id.0 + i as u64),
        telemetry: Box::new(InterfaceTelemetry {
            radio: Some(*radio),
            ..Default::default()
        }),
    })
}

fn publish_radio_telemetry(tx: &EventSender, config: &RNodeConfig, radio: &RadioStats) {
    for event in radio_telemetry(config, radio) {
        let _ = tx.send(event);
    }
}

/// Python RNodeInterface's signal-quality mapping, clamped to 0..100 and
/// rounded to one decimal place.
fn signal_quality(spreading_factor: u8, snr: f32) -> f64 {
    let sfs = spreading_factor.saturating_sub(7) as f64;
    let q_snr_min = -9.0 - sfs * 2.0;
    let q_snr_max = 6.0;
    let span = q_snr_max - q_snr_min;
    if span <= 0.0 {
        return 0.0;
    }
    let quality = (((f64::from(snr) - q_snr_min) / span) * 100.0).clamp(0.0, 100.0);
    (quality * 10.0).round() / 10.0
}

fn publish_phy_telemetry(
    tx: &EventSender,
    config: &RNodeConfig,
    rssi: Option<i16>,
    snr: Option<f32>,
) {
    for event in phy_telemetry(config, rssi, snr, None) {
        let _ = tx.send(event);
    }
}

/// One telemetry event per subinterface.
fn phy_telemetry(
    config: &RNodeConfig,
    rssi: Option<i16>,
    snr: Option<f32>,
    radio: Option<RadioStats>,
) -> impl Iterator<Item = Event> + '_ {
    config
        .subinterfaces
        .iter()
        .enumerate()
        .map(move |(i, sub)| {
            let telemetry = InterfaceTelemetry {
                rssi,
                snr,
                signal_quality: snr.map(|snr| signal_quality(sub.spreading_factor, snr)),
                frequency: Some(sub.frequency),
                bandwidth: Some(sub.bandwidth),
                txpower: Some(sub.txpower),
                spreading_factor: Some(sub.spreading_factor),
                coding_rate: Some(sub.coding_rate),
                channel: None,
                modulation: Some("LoRa".to_string()),
                radio,
                ..Default::default()
            };
            Event::InterfaceTelemetry {
                interface_id: InterfaceId(config.base_interface_id.0 + i as u64),
                telemetry: Box::new(telemetry),
            }
        })
}

fn reset_flow_states(flow_states: &[Arc<Mutex<SubFlowState>>]) {
    for flow_state in flow_states {
        let mut state = lock_or_recover(flow_state, "rnode flow state");
        state.ready = true;
        state.queue.clear();
    }
}

fn clear_pending_rx_metadata(last_rssi: &mut Option<i16>, last_snr: &mut Option<f32>) {
    *last_rssi = None;
    *last_snr = None;
}

/// Open the device's connection, saying so as upstream does.
fn open_device(config: &RNodeConfig) -> io::Result<(Transport, Transport)> {
    setup::log_opening(config);
    if setup::is_ble(config) {
        let target = ble::Target::parse(&config.port).unwrap_or_default();
        return Transport::open_ble(
            &target,
            &setup::display_name(config),
            &config.ble,
            ble::CONNECT_TIMEOUT,
        );
    }
    let serial_config = SerialConfig {
        path: config.port.clone(),
        baud: config.speed,
        data_bits: 8,
        parity: Parity::None,
        stop_bits: 1,
    };
    Transport::open(&serial_config, config.underlay_mark)
}

/// Upstream's lines when the device cannot be opened at start.
fn log_open_failure(config: &RNodeConfig, error: &io::Error) {
    let kind = if config.multi {
        "RNodeMultiInterface"
    } else {
        "RNodeInterface"
    };
    log::error!(
        "Could not open serial port for interface {}[{}]",
        kind,
        config.name
    );
    log::error!("The contained exception was: {}", error);
    log::error!("Reticulum will attempt to bring up this interface periodically");
}

/// Open a BLE device the interface just started with, as upstream opens
/// it at start.
fn first_ble_open(config: &RNodeConfig, writer: &Arc<Mutex<DeviceWriter>>) -> Option<Transport> {
    match reopen_connection(config, writer) {
        Ok(reader) => Some(reader),
        Err(e) => {
            log_open_failure(config, &e);
            None
        }
    }
}

fn reopen_connection(
    config: &RNodeConfig,
    writer: &Arc<Mutex<DeviceWriter>>,
) -> io::Result<Transport> {
    let (reader, new_writer) = open_device(config)?;
    lock_or_recover(writer, "rnode shared writer").replace(new_writer);
    Ok(reader)
}

/// Configure a single subinterface on the RNode device.
pub(crate) fn configure_subinterface(
    writer: &Arc<Mutex<DeviceWriter>>,
    index: u8,
    sub: &RNodeSubConfig,
    multi: bool,
) -> io::Result<()> {
    let mut w = lock_or_recover(writer, "rnode shared writer");

    // For multi-radio, send select command before each parameter
    let freq_bytes = [
        (sub.frequency >> 24) as u8,
        (sub.frequency >> 16) as u8,
        (sub.frequency >> 8) as u8,
        (sub.frequency & 0xFF) as u8,
    ];
    let bw_bytes = [
        (sub.bandwidth >> 24) as u8,
        (sub.bandwidth >> 16) as u8,
        (sub.bandwidth >> 8) as u8,
        (sub.bandwidth & 0xFF) as u8,
    ];
    let txp = if sub.txpower < 0 {
        (sub.txpower as i16 + 256) as u8
    } else {
        sub.txpower as u8
    };

    if multi {
        w.write_all(&rnode_kiss::rnode_select_command(
            index,
            rnode_kiss::CMD_FREQUENCY,
            &freq_bytes,
        ))?;
        w.write_all(&rnode_kiss::rnode_select_command(
            index,
            rnode_kiss::CMD_BANDWIDTH,
            &bw_bytes,
        ))?;
        w.write_all(&rnode_kiss::rnode_select_command(
            index,
            rnode_kiss::CMD_TXPOWER,
            &[txp],
        ))?;
        w.write_all(&rnode_kiss::rnode_select_command(
            index,
            rnode_kiss::CMD_SF,
            &[sub.spreading_factor],
        ))?;
        w.write_all(&rnode_kiss::rnode_select_command(
            index,
            rnode_kiss::CMD_CR,
            &[sub.coding_rate],
        ))?;
    } else {
        w.write_all(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_FREQUENCY,
            &freq_bytes,
        ))?;
        w.write_all(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_BANDWIDTH,
            &bw_bytes,
        ))?;
        w.write_all(&rnode_kiss::rnode_command(rnode_kiss::CMD_TXPOWER, &[txp]))?;
        w.write_all(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_SF,
            &[sub.spreading_factor],
        ))?;
        w.write_all(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_CR,
            &[sub.coding_rate],
        ))?;
    }

    // Airtime locks
    if let Some(st) = sub.st_alock {
        let st_val = (st * 100.0) as u16;
        let st_bytes = [(st_val >> 8) as u8, (st_val & 0xFF) as u8];
        if multi {
            w.write_all(&rnode_kiss::rnode_select_command(
                index,
                rnode_kiss::CMD_ST_ALOCK,
                &st_bytes,
            ))?;
        } else {
            w.write_all(&rnode_kiss::rnode_command(
                rnode_kiss::CMD_ST_ALOCK,
                &st_bytes,
            ))?;
        }
    }
    if let Some(lt) = sub.lt_alock {
        let lt_val = (lt * 100.0) as u16;
        let lt_bytes = [(lt_val >> 8) as u8, (lt_val & 0xFF) as u8];
        if multi {
            w.write_all(&rnode_kiss::rnode_select_command(
                index,
                rnode_kiss::CMD_LT_ALOCK,
                &lt_bytes,
            ))?;
        } else {
            w.write_all(&rnode_kiss::rnode_command(
                rnode_kiss::CMD_LT_ALOCK,
                &lt_bytes,
            ))?;
        }
    }

    // Turn on radio
    if multi {
        w.write_all(&rnode_kiss::rnode_select_command(
            index,
            rnode_kiss::CMD_RADIO_STATE,
            &[rnode_kiss::RADIO_STATE_ON],
        ))?;
    } else {
        w.write_all(&rnode_kiss::rnode_command(
            rnode_kiss::CMD_RADIO_STATE,
            &[rnode_kiss::RADIO_STATE_ON],
        ))?;
    }

    Ok(())
}

/// Process flow control queue for a subinterface.
fn process_flow_queue(
    flow_state: &Arc<Mutex<SubFlowState>>,
    writer: &Arc<Mutex<DeviceWriter>>,
    index: u8,
    multi: bool,
) {
    let mut state = lock_or_recover(flow_state, "rnode flow state");
    if let Some(data) = state.queue.pop_front() {
        state.ready = false;
        drop(state);
        let frame = if multi {
            rnode_kiss::rnode_multi_data_frame(index, &data)
        } else {
            rnode_kiss::rnode_data_frame(index, &data)
        };
        let _ = lock_or_recover(writer, "rnode shared writer").write_all(&frame);
    } else {
        state.ready = true;
    }
}

// --- Factory implementation ---

use super::{
    ConfigSection, InterfaceConfigData, InterfaceFactory, StartContext, StartResult, SubInterface,
};
use rns_core::transport::types::InterfaceInfo;
use std::collections::HashMap;

/// Factory for `RNodeInterface`.
pub struct RNodeFactory;

impl InterfaceFactory for RNodeFactory {
    fn type_name(&self) -> &str {
        "RNodeInterface"
    }

    fn default_ifac_size(&self) -> usize {
        8
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        let pre_opened_fd = params.get("fd").and_then(|v| v.parse::<i32>().ok());

        let port = params
            .get("port")
            .cloned()
            .or_else(|| pre_opened_fd.map(|_| "usb-bridge".to_string()))
            .ok_or_else(|| "RNodeInterface requires 'port' or 'fd'".to_string())?;

        let speed = params
            .get("speed")
            .and_then(|v| v.parse().ok())
            .unwrap_or(115200u32);

        let frequency = params
            .get("frequency")
            .and_then(|v| v.parse().ok())
            .unwrap_or(868_000_000u32);

        let bandwidth = params
            .get("bandwidth")
            .and_then(|v| v.parse().ok())
            .unwrap_or(125_000u32);

        let txpower = params
            .get("txpower")
            .and_then(|v| v.parse().ok())
            .unwrap_or(7i8);

        let spreading_factor = params
            .get("spreadingfactor")
            .or_else(|| params.get("spreading_factor"))
            .and_then(|v| v.parse().ok())
            .unwrap_or(8u8);

        let coding_rate = params
            .get("codingrate")
            .or_else(|| params.get("coding_rate"))
            .and_then(|v| v.parse().ok())
            .unwrap_or(5u8);

        let flow_control = params
            .get("flow_control")
            .and_then(|v| crate::config::parse_bool_pub(v))
            .unwrap_or(false);

        // Upstream's keys, with the earlier Rust names still accepted.
        let st_alock = params
            .get("airtime_limit_short")
            .or_else(|| params.get("st_alock"))
            .and_then(|v| v.parse().ok());

        let lt_alock = params
            .get("airtime_limit_long")
            .or_else(|| params.get("lt_alock"))
            .and_then(|v| v.parse().ok());

        let id_interval = params.get("id_interval").and_then(|v| v.parse().ok());

        let id_callsign = params.get("id_callsign").map(|v| v.as_bytes().to_vec());

        let sub = RNodeSubConfig {
            name: name.to_string(),
            vport: 0,
            outgoing: true,
            frequency,
            bandwidth,
            txpower,
            spreading_factor,
            coding_rate,
            flow_control,
            st_alock,
            lt_alock,
        };

        Ok(Box::new(RNodeConfig {
            name: name.to_string(),
            port,
            speed,
            subinterfaces: vec![sub],
            multi: false,
            id_interval,
            id_callsign,
            interface_id: id,
            base_interface_id: id,
            pre_opened_fd,
            underlay_mark: None,
            runtime: Arc::new(Mutex::new(RNodeRuntime {
                sub: RNodeSubConfig {
                    name: name.to_string(),
                    vport: 0,
                    outgoing: true,
                    frequency,
                    bandwidth,
                    txpower,
                    spreading_factor,
                    coding_rate,
                    flow_control,
                    st_alock,
                    lt_alock,
                },
                writer: None,
            })),
            ble: Default::default(),
            reported_phy: Default::default(),
        }))
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> std::io::Result<StartResult> {
        let mut rnode_config = *config.into_any().downcast::<RNodeConfig>().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "wrong config type")
        })?;
        rnode_config.underlay_mark = ctx.underlay_mark;

        let sub_bitrates: Vec<u64> = rnode_config
            .subinterfaces
            .iter()
            .map(estimate_lora_bitrate_bps)
            .collect();
        let airtime_profiles: Vec<AirtimeProfile> = rnode_config
            .subinterfaces
            .iter()
            .map(lora_airtime_profile)
            .collect();

        let (pairs, control) = start_with_control(rnode_config.clone(), ctx.tx)?;

        let mut subs = Vec::with_capacity(pairs.len());
        for (index, (sub_id, writer)) in pairs.into_iter().enumerate() {
            let sub_name = rnode_config.subinterfaces[index].name.clone();

            let info = InterfaceInfo {
                stamp_costs: Default::default(),
                id: sub_id,
                name: sub_name,
                mode: ctx.mode,
                gravity: ctx.gravity,
                recursive_prs: ctx.recursive_prs,
                announces_from_internal: ctx.announces_from_internal,
                announces_to_internal: ctx.announces_to_internal,
                out_capable: rnode_config.subinterfaces[index].outgoing,
                in_capable: true,
                bitrate: sub_bitrates.get(index).copied(),
                airtime_profile: airtime_profiles.get(index).copied(),
                announce_rate_target: None,
                announce_rate_grace: 0,
                announce_rate_penalty: 0.0,
                announce_cap: rns_core::constants::ANNOUNCE_CAP,
                is_local_client: false,
                wants_tunnel: false,
                hop_limiter: None,
                tunnel_id: None,
                // Upstream RNodeInterface.HW_MTU. Links never negotiate
                // above the default over a radio (not `mtu_upgradable`).
                mtu: HW_MTU,
                mtu_upgradable: false,
                ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
                ia_freq: 0.0,
                ia_samples: 0,
                ip_freq: 0.0,
                op_freq: 0.0,
                op_samples: 0,
                started: crate::time::now(),
            };

            subs.push(SubInterface {
                id: sub_id,
                info,
                writer,
                interface_type_name: if rnode_config.multi {
                    "RNodeMultiInterface"
                } else {
                    "RNodeInterface"
                }
                .to_string(),
            });
        }

        Ok(StartResult::Multi {
            subinterfaces: subs,
            control: Some(control),
        })
    }
}

/// Factory for ConfigObj-driven `RNodeMultiInterface` devices.
pub struct RNodeMultiFactory;

impl InterfaceFactory for RNodeMultiFactory {
    fn type_name(&self) -> &str {
        "RNodeMultiInterface"
    }

    fn default_ifac_size(&self) -> usize {
        8
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        self.parse_config_section(
            name,
            id,
            ConfigSection {
                params,
                children: &[],
            },
        )
    }

    fn parse_config_section(
        &self,
        name: &str,
        id: InterfaceId,
        section: ConfigSection<'_>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        let base = RNodeFactory.parse_config(name, id, section.params)?;
        let mut config = *base
            .into_any()
            .downcast::<RNodeConfig>()
            .map_err(|_| "wrong RNode config type".to_string())?;

        let mut subinterfaces = Vec::new();
        for child in section.children {
            let enabled = child
                .params
                .get("interface_enabled")
                .or_else(|| child.params.get("enabled"))
                .and_then(|value| crate::config::parse_bool_pub(value))
                .unwrap_or(true);
            if !enabled {
                continue;
            }
            if subinterfaces.len() >= 11 {
                return Err("RNodeMultiInterface supports at most 11 enabled subinterfaces".into());
            }
            let vport = child
                .params
                .get("vport")
                .ok_or_else(|| format!("subinterface '{}' requires 'vport'", child.name))?
                .parse::<u8>()
                .map_err(|_| format!("invalid RNode virtual port for '{}'", child.name))?;
            if vport > 10
                || subinterfaces
                    .iter()
                    .any(|sub: &RNodeSubConfig| sub.vport == vport)
            {
                return Err(format!("invalid or duplicate RNode virtual port {}", vport));
            }
            let parse_u32 = |key: &str, default| {
                child
                    .params
                    .get(key)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(default)
            };
            let parse_u8_alias = |first: &str, second: &str, default| {
                child
                    .params
                    .get(first)
                    .or_else(|| child.params.get(second))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(default)
            };
            let sub = RNodeSubConfig {
                name: child.name.clone(),
                vport,
                outgoing: child
                    .params
                    .get("outgoing")
                    .and_then(|v| crate::config::parse_bool_pub(v))
                    .unwrap_or(true),
                frequency: parse_u32("frequency", 868_000_000),
                bandwidth: parse_u32("bandwidth", 125_000),
                txpower: child
                    .params
                    .get("txpower")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(7),
                spreading_factor: parse_u8_alias("spreadingfactor", "spreading_factor", 8),
                coding_rate: parse_u8_alias("codingrate", "coding_rate", 5),
                flow_control: child
                    .params
                    .get("flow_control")
                    .and_then(|v| crate::config::parse_bool_pub(v))
                    .unwrap_or(false),
                st_alock: child
                    .params
                    .get("airtime_limit_short")
                    .or_else(|| child.params.get("st_alock"))
                    .and_then(|v| v.parse().ok()),
                lt_alock: child
                    .params
                    .get("airtime_limit_long")
                    .or_else(|| child.params.get("lt_alock"))
                    .and_then(|v| v.parse().ok()),
            };
            if let Some(error) = validate_sub_config(&sub) {
                return Err(error);
            }
            subinterfaces.push(sub);
        }
        if subinterfaces.is_empty() {
            return Err("RNodeMultiInterface requires at least one enabled subinterface".into());
        }
        config.multi = true;
        // Upstream adds the interface, then each subinterface once its
        // device is configured: they take the ids after its own.
        config.base_interface_id = InterfaceId(id.0 + 1);
        config.subinterfaces = subinterfaces;
        *lock_or_recover(&config.runtime, "rnode runtime") = RNodeRuntime::from_config(&config);
        Ok(Box::new(config))
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> io::Result<StartResult> {
        RNodeFactory.start(config, ctx)
    }
}

pub(crate) fn rnode_runtime_handle_from_config(config: &RNodeConfig) -> RNodeRuntimeConfigHandle {
    RNodeRuntimeConfigHandle {
        interface_name: config.name.clone(),
        runtime: Arc::clone(&config.runtime),
        startup: RNodeRuntime::from_config(config),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event;
    use crate::kiss;
    use crate::serial::open_pty_pair;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::path::PathBuf;
    use std::sync::mpsc::RecvTimeoutError;
    use tempfile::tempdir;
    /// Helper: poll an fd for reading with timeout (ms).
    fn poll_read(fd: i32, timeout_ms: i32) -> bool {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        ret > 0
    }

    /// Read all available bytes from an fd.
    fn read_available(file: &mut Transport) -> Vec<u8> {
        let mut all = Vec::new();
        let mut buf = [0u8; 4096];
        while poll_read(file.as_raw_fd(), 100) {
            match file.read(&mut buf) {
                Ok(n) if n > 0 => all.extend_from_slice(&buf[..n]),
                _ => break,
            }
        }
        all
    }

    fn slave_tty_path(fd: i32) -> PathBuf {
        let mut buf = [0u8; 256];
        let rc = unsafe { libc::ttyname_r(fd, buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(rc, 0, "ttyname_r failed for fd {}", fd);
        let nul = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        PathBuf::from(std::str::from_utf8(&buf[..nul]).unwrap())
    }

    unsafe fn transport_from_raw_fd(fd: i32) -> Transport {
        Transport::Serial(std::fs::File::from_raw_fd(fd))
    }

    fn wait_for_interface_event<F>(
        rx: &crate::event::EventReceiver,
        timeout: Duration,
        predicate: F,
    ) -> Event
    where
        F: Fn(&Event) -> bool,
    {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            match rx.recv_timeout(remaining) {
                Ok(event) if predicate(&event) => return event,
                Ok(_) => continue,
                Err(RecvTimeoutError::Timeout) => panic!("timed out waiting for interface event"),
                Err(RecvTimeoutError::Disconnected) => panic!("event channel disconnected"),
            }
        }
    }

    /// Mock RNode: respond to detect with DETECT_RESP, FW version, platform
    fn mock_respond_detect(master: &mut Transport) {
        // Respond: DETECT_RESP
        master
            .write_all(&rnode_kiss::rnode_command(
                rnode_kiss::CMD_DETECT,
                &[rnode_kiss::DETECT_RESP],
            ))
            .unwrap();
        // FW version 1.74
        master
            .write_all(&rnode_kiss::rnode_command(
                rnode_kiss::CMD_FW_VERSION,
                &[0x01, 0x4A],
            ))
            .unwrap();
        // Platform ESP32
        master
            .write_all(&rnode_kiss::rnode_command(
                rnode_kiss::CMD_PLATFORM,
                &[0x80],
            ))
            .unwrap();
        // MCU
        master
            .write_all(&rnode_kiss::rnode_command(rnode_kiss::CMD_MCU, &[0x01]))
            .unwrap();
        master.flush().unwrap();
    }

    /// Mock RNode: report the radio configured as `sub`, as the firmware
    /// answers each setting.
    fn mock_report_configured(master: &mut Transport, sub: &RNodeSubConfig) {
        for (command, data) in [
            (
                rnode_kiss::CMD_FREQUENCY,
                sub.frequency.to_be_bytes().to_vec(),
            ),
            (
                rnode_kiss::CMD_BANDWIDTH,
                sub.bandwidth.to_be_bytes().to_vec(),
            ),
            (rnode_kiss::CMD_TXPOWER, vec![sub.txpower as u8]),
            (rnode_kiss::CMD_SF, vec![sub.spreading_factor]),
            (rnode_kiss::CMD_CR, vec![sub.coding_rate]),
            (
                rnode_kiss::CMD_RADIO_STATE,
                vec![rnode_kiss::RADIO_STATE_ON],
            ),
        ] {
            master
                .write_all(&rnode_kiss::rnode_command(command, &data))
                .unwrap();
        }
        master.flush().unwrap();
    }

    #[test]
    fn rnode_detect_over_pty() {
        // Test that the RNode decoder can parse detect responses from a PTY
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        let mut master = unsafe { transport_from_raw_fd(master_fd) };
        let mut slave = unsafe { transport_from_raw_fd(slave_fd) };

        // Write detect response to master
        mock_respond_detect(&mut master);

        let mut decoder = rnode_kiss::RNodeDecoder::new();
        let mut events = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);

        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
            if !poll_read(slave.as_raw_fd(), timeout_ms) {
                break;
            }

            let chunk = read_available(&mut slave);
            if chunk.is_empty() {
                continue;
            }

            events.extend(decoder.feed(&chunk));

            let saw_detect = events
                .iter()
                .any(|e| matches!(e, rnode_kiss::RNodeEvent::Detected(true)));
            let saw_firmware = events
                .iter()
                .any(|e| matches!(e, rnode_kiss::RNodeEvent::FirmwareVersion { .. }));
            if saw_detect && saw_firmware {
                break;
            }
        }

        assert!(
            events
                .iter()
                .any(|e| matches!(e, rnode_kiss::RNodeEvent::Detected(true))),
            "should detect device"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, rnode_kiss::RNodeEvent::FirmwareVersion { .. })),
            "should get firmware version"
        );
    }

    #[test]
    fn rnode_configure_commands() {
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        let mut master = unsafe { transport_from_raw_fd(master_fd) };
        let writer_file = unsafe { transport_from_raw_fd(libc::dup(slave_fd)) };
        let writer = Arc::new(Mutex::new(DeviceWriter::new(writer_file)));

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

        configure_subinterface(&writer, 0, &sub, false).unwrap();

        // Read what was sent
        let data = read_available(&mut master);

        // Should contain frequency command
        assert!(
            data.windows(2)
                .any(|w| w[0] == kiss::FEND && w[1] == rnode_kiss::CMD_FREQUENCY),
            "should contain FREQUENCY command"
        );
        // Should contain bandwidth command
        assert!(
            data.windows(2)
                .any(|w| w[0] == kiss::FEND && w[1] == rnode_kiss::CMD_BANDWIDTH),
            "should contain BANDWIDTH command"
        );
        // Should contain RADIO_STATE ON
        assert!(
            data.windows(3).any(|w| w[0] == kiss::FEND
                && w[1] == rnode_kiss::CMD_RADIO_STATE
                && w[2] == rnode_kiss::RADIO_STATE_ON),
            "should contain RADIO_STATE ON command"
        );

        unsafe { libc::close(slave_fd) };
    }

    #[test]
    fn rnode_data_roundtrip() {
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        let mut master = unsafe { transport_from_raw_fd(master_fd) };
        let slave = unsafe { transport_from_raw_fd(slave_fd) };

        // Write a data frame (subinterface 0) to master
        let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let frame = rnode_kiss::rnode_data_frame(0, &payload);
        master.write_all(&frame).unwrap();
        master.flush().unwrap();

        // Read from slave with RNode decoder
        assert!(poll_read(slave.as_raw_fd(), 2000));
        let mut decoder = rnode_kiss::RNodeDecoder::new();
        let mut buf = [0u8; 4096];
        let mut slave_file = slave;
        let n = slave_file.read(&mut buf).unwrap();
        let events = decoder.feed(&buf[..n]);

        assert_eq!(events.len(), 1);
        match &events[0] {
            rnode_kiss::RNodeEvent::DataFrame { index, data } => {
                assert_eq!(*index, 0);
                assert_eq!(data, &payload);
            }
            other => panic!("expected DataFrame, got {:?}", other),
        }
    }

    #[test]
    fn rnode_flow_control() {
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        let writer_file = unsafe { transport_from_raw_fd(slave_fd) };
        let shared_writer = Arc::new(Mutex::new(DeviceWriter::new(writer_file)));

        let flow_state = Arc::new(Mutex::new(SubFlowState {
            ready: true,
            queue: std::collections::VecDeque::new(),
        }));

        let mut sub_writer = RNodeSubWriter {
            confirmed_pending: None,
            writer: shared_writer.clone(),
            index: 0,
            flow_control: true,
            flow_state: flow_state.clone(),
            multi: false,
        };

        // First send: should go through (ready=true) and set ready=false
        sub_writer.send_frame(b"hello").unwrap();
        assert!(!flow_state.lock().unwrap().ready);

        // Second send: should be queued
        sub_writer.send_frame(b"world").unwrap();
        assert_eq!(flow_state.lock().unwrap().queue.len(), 1);

        // Process flow queue (simulates CMD_READY)
        process_flow_queue(&flow_state, &shared_writer, 0, false);
        assert_eq!(flow_state.lock().unwrap().queue.len(), 0);
        assert!(!flow_state.lock().unwrap().ready); // sent queued, still locked

        // Process again with empty queue: sets ready=true
        process_flow_queue(&flow_state, &shared_writer, 0, false);
        assert!(flow_state.lock().unwrap().ready);

        unsafe { libc::close(master_fd) };
    }

    #[test]
    fn device_reports_update_radio_stats_as_upstream() {
        let mut radio = RadioStats::default();
        let channel = rnode_kiss::RNodeEvent::ChannelStats {
            airtime_short: 697,
            airtime_long: 2,
            channel_load_short: 1113,
            channel_load_long: 4,
            current_rssi: 47,
            noise_floor: 58,
            interference: 0xFF,
        };
        assert!(update_radio_stats(&channel, &mut radio, 100.0));
        assert_eq!(radio.airtime_short, 6.97);
        assert_eq!(radio.airtime_long, 0.02);
        assert_eq!(radio.channel_load_short, 11.13);
        assert_eq!(radio.channel_load_long, 0.04);
        assert_eq!(radio.current_rssi, Some(-110));
        assert_eq!(radio.noise_floor, Some(-99));
        assert_eq!(radio.interference, None);
        assert_eq!(radio.interference_last, None);

        let busy = rnode_kiss::RNodeEvent::ChannelStats {
            airtime_short: 0,
            airtime_long: 0,
            channel_load_short: 0,
            channel_load_long: 0,
            current_rssi: 77,
            noise_floor: 58,
            interference: 77,
        };
        assert!(update_radio_stats(&busy, &mut radio, 200.0));
        assert_eq!(radio.interference, Some(-80));
        assert_eq!(radio.interference_last, Some((200.0, -80)));
        // Cleared now, but the last sighting stays.
        assert!(update_radio_stats(&channel, &mut radio, 300.0));
        assert_eq!(radio.interference, None);
        assert_eq!(radio.interference_last, Some((200.0, -80)));

        let battery = rnode_kiss::RNodeEvent::Battery {
            state: 2,
            percent: 140,
        };
        assert!(update_radio_stats(&battery, &mut radio, 0.0));
        assert_eq!(radio.battery_state_name(), "charging");
        assert_eq!(radio.battery_percent, 100);

        // Temperature is offset by 120 and kept only between -30 and 90.
        let temp = |raw| rnode_kiss::RNodeEvent::Temperature(raw);
        assert!(update_radio_stats(&temp(178), &mut radio, 0.0));
        assert_eq!(radio.temperature, Some(58));
        assert!(update_radio_stats(&temp(250), &mut radio, 0.0));
        assert_eq!(radio.temperature, None);

        let phy = rnode_kiss::RNodeEvent::PhyStats {
            symbol_time_us: 2048,
            symbol_rate: 488,
            preamble_symbols: 18,
            preamble_ms: 37,
            csma_slot_ms: 24,
            difs_ms: 48,
        };
        assert!(!update_radio_stats(&phy, &mut radio, 0.0));
        assert!(!update_radio_stats(
            &rnode_kiss::RNodeEvent::Ready,
            &mut radio,
            0.0
        ));
    }

    #[test]
    fn signal_quality_matches_python_mapping_and_clamps() {
        assert_eq!(signal_quality(8, -11.0), 0.0);
        assert_eq!(signal_quality(8, -2.5), 50.0);
        assert_eq!(signal_quality(8, 6.0), 100.0);
        assert_eq!(signal_quality(8, 30.0), 100.0);
        assert_eq!(signal_quality(8, -40.0), 0.0);
        assert_eq!(signal_quality(10, -2.5), 59.5);
    }

    #[test]
    fn rnode_reset_clears_pending_rx_metadata() {
        let mut last_rssi = Some(-101);
        let mut last_snr = Some(7.25);

        clear_pending_rx_metadata(&mut last_rssi, &mut last_snr);

        assert_eq!(last_rssi, None);
        assert_eq!(last_snr, None);
    }

    #[test]
    fn confirmed_rnode_frame_waits_for_ready_and_flushes_once() {
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        let mut master = unsafe { transport_from_raw_fd(master_fd) };
        let state = Arc::new(Mutex::new(SubFlowState {
            ready: false,
            queue: std::collections::VecDeque::new(),
        }));
        let mut writer = RNodeSubWriter {
            confirmed_pending: None,
            writer: Arc::new(Mutex::new(DeviceWriter::new(unsafe {
                transport_from_raw_fd(slave_fd)
            }))),
            index: 0,
            flow_control: true,
            flow_state: state.clone(),
            multi: false,
        };
        assert_eq!(
            writer
                .send_frame_confirmed(b"confirmed")
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(state.lock().unwrap().queue.is_empty());
        assert!(!poll_read(master.as_raw_fd(), 20));
        state.lock().unwrap().ready = true;
        Writer::flush(&mut writer).unwrap();
        let expected = rnode_kiss::rnode_data_frame(0, b"confirmed");
        let mut actual = vec![0; expected.len()];
        master.read_exact(&mut actual).unwrap();
        assert_eq!(actual, expected);
        Writer::flush(&mut writer).unwrap();
        assert!(!poll_read(master.as_raw_fd(), 20));
    }

    #[test]
    fn rnode_snr_metadata_does_not_depend_on_rssi() {
        let mut last_rssi = None;
        let mut last_snr = None;

        assert!(update_pending_rx_metadata(
            &rnode_kiss::RNodeEvent::StatSnr(-12),
            &mut last_rssi,
            &mut last_snr,
        ));

        assert_eq!(last_rssi, None);
        assert_eq!(last_snr, Some(-3.0));
    }

    #[test]
    fn rnode_rx_metadata_reports_rssi_and_snr() {
        let mut last_rssi = None;
        let mut last_snr = None;

        assert!(update_pending_rx_metadata(
            &rnode_kiss::RNodeEvent::StatRssi(57),
            &mut last_rssi,
            &mut last_snr,
        ));
        assert!(update_pending_rx_metadata(
            &rnode_kiss::RNodeEvent::StatSnr(-12),
            &mut last_rssi,
            &mut last_snr,
        ));

        assert_eq!(last_rssi, Some(-100));
        assert_eq!(last_snr, Some(-3.0));
    }

    #[test]
    fn rnode_sub_writer_format() {
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        let mut master = unsafe { transport_from_raw_fd(master_fd) };
        let writer_file = unsafe { transport_from_raw_fd(slave_fd) };
        let shared_writer = Arc::new(Mutex::new(DeviceWriter::new(writer_file)));

        let flow_state = Arc::new(Mutex::new(SubFlowState {
            ready: true,
            queue: std::collections::VecDeque::new(),
        }));

        let mut sub_writer = RNodeSubWriter {
            confirmed_pending: None,
            writer: shared_writer,
            index: 1, // subinterface 1
            flow_control: false,
            flow_state,
            multi: false,
        };

        let payload = vec![0xAA, 0xBB, 0xCC];
        sub_writer.send_frame(&payload).unwrap();

        // Read from master
        assert!(poll_read(master.as_raw_fd(), 2000));
        let mut buf = [0u8; 256];
        let n = master.read(&mut buf).unwrap();

        // Should start with FEND, CMD_INT1_DATA (0x10)
        assert_eq!(buf[0], kiss::FEND);
        assert_eq!(buf[1], 0x10); // CMD_INT1_DATA
        assert_eq!(buf[n - 1], kiss::FEND);
    }

    #[test]
    fn rnode_multi_sub_routing() {
        // Test that data frames on different CMD_INTn route to different indices
        let mut decoder = rnode_kiss::RNodeDecoder::new();

        let payload0 = vec![0x01, 0x02];
        let frame0 = rnode_kiss::rnode_data_frame(0, &payload0);
        let events0 = decoder.feed(&frame0);
        assert_eq!(events0.len(), 1);
        assert_eq!(
            events0[0],
            rnode_kiss::RNodeEvent::DataFrame {
                index: 0,
                data: payload0
            }
        );

        let payload1 = vec![0x03, 0x04];
        let frame1 = rnode_kiss::rnode_data_frame(1, &payload1);
        let events1 = decoder.feed(&frame1);
        assert_eq!(events1.len(), 1);
        assert_eq!(
            events1[0],
            rnode_kiss::RNodeEvent::DataFrame {
                index: 1,
                data: payload1
            }
        );
    }

    #[test]
    fn rnode_error_handling() {
        // NOTE: CMD_ERROR (0x90) == CMD_INT5_DATA (0x90) — they share the same
        // byte value. In multi-radio mode, 0x90 is treated as INT5_DATA.
        // Error events only appear on single-radio devices where there's no
        // INT5_DATA. The decoder treats 0x90 as INT5_DATA (data wins).
        // For real error detection, we rely on the data frame being invalid
        // or the device sending a different error indicator.
        // Test that cmd 0x90 is correctly handled as a data frame.
        let mut decoder = rnode_kiss::RNodeDecoder::new();
        let frame = rnode_kiss::rnode_command(rnode_kiss::CMD_ERROR, &[0x02]);
        let events = decoder.feed(&frame);
        assert_eq!(events.len(), 1);
        // 0x90 = CMD_INT5_DATA, so it's a DataFrame with index 5
        assert_eq!(
            events[0],
            rnode_kiss::RNodeEvent::DataFrame {
                index: 5,
                data: vec![0x02]
            }
        );
    }

    #[test]
    fn rnode_config_validation() {
        let good = RNodeSubConfig {
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
        assert!(validate_sub_config(&good).is_none());

        // Bad frequency
        let mut bad = good.clone();
        bad.frequency = 100;
        assert!(validate_sub_config(&bad).is_some());

        // Bad SF
        bad = good.clone();
        bad.spreading_factor = 13;
        assert!(validate_sub_config(&bad).is_some());

        // Bad CR
        bad = good.clone();
        bad.coding_rate = 9;
        assert!(validate_sub_config(&bad).is_some());

        // Bad BW
        bad = good.clone();
        bad.bandwidth = 5;
        assert!(validate_sub_config(&bad).is_some());

        // Bad TX power
        bad = good.clone();
        bad.txpower = 50;
        assert!(validate_sub_config(&bad).is_some());
    }

    #[test]
    fn multi_factory_preserves_nonsequential_virtual_ports_and_disabled_children() {
        let parent = HashMap::from([
            ("port".to_string(), "/dev/ttyUSB0".to_string()),
            ("speed".to_string(), "115200".to_string()),
        ]);
        let children = vec![
            crate::config::ParsedSubinterface {
                name: "disabled".into(),
                params: HashMap::from([
                    ("interface_enabled".into(), "no".into()),
                    ("vport".into(), "2".into()),
                ]),
            },
            crate::config::ParsedSubinterface {
                name: "high".into(),
                params: HashMap::from([
                    ("interface_enabled".into(), "yes".into()),
                    ("vport".into(), "7".into()),
                    ("frequency".into(), "915000000".into()),
                    ("airtime_limit_short".into(), "12.5".into()),
                    ("outgoing".into(), "no".into()),
                ]),
            },
            crate::config::ParsedSubinterface {
                name: "low".into(),
                params: HashMap::from([
                    ("enabled".into(), "yes".into()),
                    ("vport".into(), "1".into()),
                ]),
            },
        ];
        let parsed = RNodeMultiFactory
            .parse_config_section(
                "multi",
                InterfaceId(40),
                ConfigSection {
                    params: &parent,
                    children: &children,
                },
            )
            .unwrap();
        let config = parsed.into_any().downcast::<RNodeConfig>().unwrap();
        assert_eq!(config.subinterfaces.len(), 2);
        assert_eq!(config.subinterfaces[0].vport, 7);
        assert_eq!(config.subinterfaces[1].vport, 1);
        assert!(!config.subinterfaces[0].outgoing);
        assert_eq!(config.subinterfaces[0].st_alock, Some(12.5));
    }

    #[test]
    fn rnode_factory_reads_upstream_airtime_limit_keys() {
        let parse = |params: &[(&str, &str)]| {
            let params: HashMap<String, String> = params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let parsed = RNodeFactory
                .parse_config("radio", InterfaceId(41), &params)
                .unwrap();
            let config = parsed.into_any().downcast::<RNodeConfig>().unwrap();
            (
                config.subinterfaces[0].st_alock,
                config.subinterfaces[0].lt_alock,
            )
        };
        // Upstream RNodeInterface reads airtime_limit_short / _long.
        assert_eq!(
            parse(&[
                ("port", "/dev/ttyUSB0"),
                ("airtime_limit_short", "25"),
                ("airtime_limit_long", "3.5"),
            ]),
            (Some(25.0), Some(3.5))
        );
        // The earlier Rust names still work.
        assert_eq!(
            parse(&[
                ("port", "/dev/ttyUSB0"),
                ("st_alock", "10"),
                ("lt_alock", "1")
            ]),
            (Some(10.0), Some(1.0))
        );
        assert_eq!(parse(&[("port", "/dev/ttyUSB0")]), (None, None));
    }

    #[test]
    fn rnode_lora_bitrate_estimate_uses_radio_params() {
        let mut sub = RNodeSubConfig {
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

        assert_eq!(estimate_lora_bitrate_bps(&sub), 3125);

        sub.spreading_factor = 12;
        assert_eq!(estimate_lora_bitrate_bps(&sub), 293);

        sub.bandwidth = 250_000;
        assert_eq!(estimate_lora_bitrate_bps(&sub), 586);
    }

    #[test]
    fn rnode_lora_airtime_profile_uses_radio_params() {
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

        let profile = lora_airtime_profile(&sub);
        assert!((profile.transmit_time_secs(100) - 0.307712).abs() < 0.000001);
        assert_eq!(
            profile,
            AirtimeProfile::Lora {
                bandwidth: 125_000,
                spreading_factor: 8,
                coding_rate: 5,
                preamble_symbols: LORA_PREAMBLE_SYMBOLS,
                explicit_header: LORA_EXPLICIT_HEADER,
                crc: LORA_CRC,
            }
        );
    }

    fn thread_named(prefix: &str) -> bool {
        std::fs::read_dir("/proc/self/task").unwrap().any(|task| {
            let comm = task.unwrap().path().join("comm");
            std::fs::read_to_string(comm).is_ok_and(|comm| comm.trim().starts_with(prefix))
        })
    }

    /// Data frames the device side reads within `timeout_ms`, past the
    /// host's commands.
    fn device_reads(master: &mut Transport, want: usize, timeout_ms: i32) -> Vec<Vec<u8>> {
        let mut decoder = rnode_kiss::RNodeDecoder::new();
        let mut frames = Vec::new();
        let mut buf = [0u8; 1024];
        while frames.len() < want && poll_read(master.as_raw_fd(), timeout_ms) {
            let n = master.read(&mut buf).unwrap();
            for event in decoder.feed(&buf[..n]) {
                if let rnode_kiss::RNodeEvent::DataFrame { data, .. } = event {
                    frames.push(data);
                }
            }
        }
        frames
    }

    #[test]
    fn folded_rnode_runs_on_the_driver_loop() {
        if !crate::engine::FOLD_IO {
            return;
        }
        let tempdir = tempdir().unwrap();
        let port_path = tempdir.path().join("rnode-port");
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        std::os::unix::fs::symlink(slave_tty_path(slave_fd), &port_path).unwrap();
        let mut master = unsafe { transport_from_raw_fd(master_fd) };
        let slave = unsafe { transport_from_raw_fd(slave_fd) };

        let (tx, rx) = event::channel();
        let mut config = RNodeConfig {
            name: "folded-rnode".into(),
            port: port_path.display().to_string(),
            subinterfaces: vec![RNodeSubConfig {
                name: "folded-rnode".into(),
                vport: 0,
                outgoing: true,
                frequency: 868_000_000,
                bandwidth: 125_000,
                txpower: 7,
                spreading_factor: 8,
                coding_rate: 5,
                flow_control: true,
                st_alock: None,
                lt_alock: None,
            }],
            interface_id: InterfaceId(43),
            base_interface_id: InterfaceId(43),
            ..Default::default()
        };
        config.runtime = Arc::new(Mutex::new(RNodeRuntime::from_config(&config)));
        let sub = config.subinterfaces[0].clone();
        let (mut writers, control) = start_with_control(config, tx.clone()).unwrap();
        let (_, writer) = writers.remove(0);
        assert!(writer.sends_inline());
        let (mut writer, _) =
            crate::interface::wrap_async_writer(writer, InterfaceId(43), "rnode", tx, 16);

        thread::sleep(Duration::from_millis(2500));
        mock_respond_detect(&mut master);
        mock_report_configured(&mut master, &sub);
        wait_for_interface_event(&rx, Duration::from_secs(4), |event| {
            matches!(event, Event::InterfaceUp(InterfaceId(43), None, None))
        });
        // Setup is done: only the driver serves the device now.
        thread::sleep(Duration::from_millis(100));
        assert!(!thread_named("rnode-setup-43"));
        assert!(!thread_named("rnode-reader-43"));
        assert!(!thread_named("rnode-keepaliv"));
        assert!(!thread_named("iface-writer-43"));

        // Inbound, with the modem's report attached.
        master
            .write_all(&rnode_kiss::rnode_command(
                rnode_kiss::CMD_STAT_RSSI,
                &[100],
            ))
            .unwrap();
        let payload: Vec<u8> = (0..32).collect();
        master
            .write_all(&rnode_kiss::rnode_data_frame(0, &payload))
            .unwrap();
        match wait_for_interface_event(&rx, Duration::from_secs(2), |event| {
            matches!(event, Event::Frame { .. })
        }) {
            Event::Frame {
                interface_id,
                data,
                rssi,
                ..
            } => {
                assert_eq!(interface_id, InterfaceId(43));
                assert_eq!(&*data, &payload[..]);
                assert_eq!(rssi, Some(-57));
            }
            _ => unreachable!(),
        }

        // Outbound: the second frame waits for the device to report ready.
        writer.send_frame(b"first frame").unwrap();
        writer.send_frame(b"second frame").unwrap();
        writer.flush_pending();
        assert_eq!(
            device_reads(&mut master, 2, 200),
            vec![b"first frame".to_vec()]
        );
        master
            .write_all(&rnode_kiss::rnode_command(rnode_kiss::CMD_READY, &[0x01]))
            .unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
        assert_eq!(
            device_reads(&mut master, 1, 2000),
            vec![b"second frame".to_vec()]
        );

        // The device going away is reported.
        drop(master);
        drop(slave);
        wait_for_interface_event(&rx, Duration::from_secs(2), |event| {
            matches!(event, Event::InterfaceDown(InterfaceId(43)))
        });
        control.request_stop();
    }

    /// As upstream, an RNodeMultiInterface whose device cannot be opened
    /// still starts, offline, and tries to open it every five seconds.
    #[test]
    fn rnode_multi_starts_without_its_device_and_opens_it_later() {
        let tempdir = tempdir().unwrap();
        let port_path = tempdir.path().join("rnode-port");
        let sub = |name: &str, vport: u8| RNodeSubConfig {
            name: name.into(),
            vport,
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
        let mut config = RNodeConfig {
            name: "test-multi".into(),
            port: port_path.display().to_string(),
            subinterfaces: vec![sub("a", 0), sub("b", 1)],
            multi: true,
            base_interface_id: InterfaceId(51),
            ..RNodeConfig::default()
        };
        config.runtime = Arc::new(Mutex::new(RNodeRuntime::from_config(&config)));
        let (tx, rx) = event::channel();

        let started = std::time::Instant::now();
        let (writers, control) = start_with_control(config, tx).unwrap();
        // Both subinterfaces have writers, which cannot write yet.
        assert_eq!(writers.len(), 2);

        // The device appears after start.
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        std::os::unix::fs::symlink(slave_tty_path(slave_fd), &port_path).unwrap();
        let mut master = unsafe { transport_from_raw_fd(master_fd) };
        let _slave = unsafe { transport_from_raw_fd(slave_fd) };
        // Nothing comes up before the first attempt, five seconds in.
        assert!(rx.recv_timeout(Duration::from_secs(4)).is_err());
        // The device answers once the port was opened (and the hardware
        // given its two seconds).
        thread::sleep(Duration::from_millis(3500));
        mock_respond_detect(&mut master);
        for id in [51, 52] {
            let up = wait_for_interface_event(
                &rx,
                Duration::from_secs(5),
                |event| matches!(event, Event::InterfaceUp(InterfaceId(i), _, _) if *i == id),
            );
            // With a writer on the connection now open.
            assert!(matches!(up, Event::InterfaceUp(_, Some(_), None)));
        }
        assert!(started.elapsed() >= OPEN_RETRY_WAIT);
        control.request_stop();
    }

    #[test]
    fn rnode_reconnects_after_serial_disconnect() {
        let tempdir = tempdir().unwrap();
        let port_path = tempdir.path().join("rnode-port");

        let (master1_fd, slave1_fd) = open_pty_pair().unwrap();
        let slave1_path = slave_tty_path(slave1_fd);
        std::os::unix::fs::symlink(&slave1_path, &port_path).unwrap();

        let mut master1 = unsafe { transport_from_raw_fd(master1_fd) };
        let slave1 = unsafe { transport_from_raw_fd(slave1_fd) };

        let (tx, rx) = event::channel();
        let sub = RNodeSubConfig {
            name: "test-rnode".into(),
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
        let mut config = RNodeConfig {
            name: "test-rnode".into(),
            port: port_path.display().to_string(),
            speed: 115200,
            subinterfaces: vec![sub],
            multi: false,
            id_interval: None,
            id_callsign: None,
            interface_id: InterfaceId(41),
            base_interface_id: InterfaceId(41),
            pre_opened_fd: None,
            underlay_mark: None,
            runtime: Arc::new(Mutex::new(RNodeRuntime {
                sub: RNodeSubConfig {
                    name: String::new(),
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
                },
                writer: None,
            })),
            ble: Default::default(),
            reported_phy: Default::default(),
        };
        config.runtime = Arc::new(Mutex::new(RNodeRuntime::from_config(&config)));

        let sub = config.subinterfaces[0].clone();
        let (_writers, control) = start_with_control(config, tx).unwrap();

        thread::sleep(Duration::from_secs(3));
        mock_respond_detect(&mut master1);
        mock_report_configured(&mut master1, &sub);
        let up = wait_for_interface_event(&rx, Duration::from_secs(4), |event| {
            matches!(event, Event::InterfaceUp(InterfaceId(41), _, _))
        });
        assert!(matches!(
            up,
            Event::InterfaceUp(InterfaceId(41), None, None)
        ));

        drop(master1);
        drop(slave1);

        let down = wait_for_interface_event(&rx, Duration::from_secs(4), |event| {
            matches!(event, Event::InterfaceDown(InterfaceId(41)))
        });
        assert!(matches!(down, Event::InterfaceDown(InterfaceId(41))));

        let (master2_fd, slave2_fd) = open_pty_pair().unwrap();
        let slave2_path = slave_tty_path(slave2_fd);
        std::fs::remove_file(&port_path).unwrap();
        std::os::unix::fs::symlink(&slave2_path, &port_path).unwrap();

        let mut master2 = unsafe { transport_from_raw_fd(master2_fd) };
        let _slave2 = unsafe { transport_from_raw_fd(slave2_fd) };

        thread::sleep(Duration::from_secs(3));
        mock_respond_detect(&mut master2);
        mock_report_configured(&mut master2, &sub);
        let up = wait_for_interface_event(&rx, Duration::from_secs(4), |event| {
            matches!(event, Event::InterfaceUp(InterfaceId(41), _, _))
        });
        assert!(matches!(
            up,
            Event::InterfaceUp(InterfaceId(41), Some(_), None)
        ));

        // signal_interface_up publishes telemetry right after InterfaceUp;
        // wait for it so it cannot land in the post-stop silence window.
        let telemetry = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            telemetry,
            Event::InterfaceTelemetry {
                interface_id: InterfaceId(41),
                ..
            }
        ));

        control.request_stop();
        assert!(control.should_stop());
        // A stopped reader must not report the intentional serial close as a
        // hardware failure or start another reconnect attempt.
        drop(master2);
        assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
    }

    /// Every line logged while the tests run, as (level, message).
    fn logged() -> &'static Mutex<Vec<(log::Level, String)>> {
        struct Capture;
        static LINES: std::sync::OnceLock<Mutex<Vec<(log::Level, String)>>> =
            std::sync::OnceLock::new();
        impl log::Log for Capture {
            fn enabled(&self, _: &log::Metadata<'_>) -> bool {
                true
            }
            fn log(&self, record: &log::Record<'_>) {
                if let Some(lines) = LINES.get() {
                    lines
                        .lock()
                        .unwrap()
                        .push((record.level(), record.args().to_string()));
                }
            }
            fn flush(&self) {}
        }
        static CAPTURE: Capture = Capture;
        let lines = LINES.get_or_init(|| Mutex::new(Vec::new()));
        static INSTALLED: std::sync::Once = std::sync::Once::new();
        INSTALLED.call_once(|| {
            log::set_logger(&CAPTURE).expect("no other logger in these tests");
            log::set_max_level(log::LevelFilter::Trace);
        });
        lines
    }

    /// The lines logged so far about `iface` reporting on its radio.
    fn radio_lines(iface: &str) -> Vec<(log::Level, String)> {
        logged()
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, line)| {
                line.starts_with(iface)
                    && (line.contains(" Radio reporting ") || line.contains(" On-air bitrate "))
            })
            .cloned()
            .collect()
    }

    /// The radio timing the mock firmware reports for 125 kHz, SF8.
    const MOCK_PHY: [u16; 6] = [2048, 488, 18, 37, 24, 48];

    /// A mock RNode answering the host as the firmware does, including
    /// where it reports its radio timing: only while the radio is on, each
    /// time bandwidth, spreading factor or coding rate change and when the
    /// radio starts. Returns the commands it got.
    fn mock_firmware(
        mut master: Transport,
        radio_on: bool,
        stop: Arc<AtomicBool>,
    ) -> thread::JoinHandle<Vec<(u8, Vec<u8>)>> {
        thread::spawn(move || {
            let mut online = radio_on;
            let mut got = Vec::new();
            let mut pending = Vec::new();
            let mut buf = [0u8; 1024];
            let phy: Vec<u8> = MOCK_PHY.iter().flat_map(|v| v.to_be_bytes()).collect();
            let answer = |master: &mut Transport, command: u8, data: &[u8]| {
                master
                    .write_all(&rnode_kiss::rnode_command(command, data))
                    .unwrap();
            };
            while !stop.load(Ordering::Relaxed) {
                if !poll_read(master.as_raw_fd(), 50) {
                    continue;
                }
                let n = match master.read(&mut buf) {
                    Ok(n) if n > 0 => n,
                    _ => break,
                };
                pending.extend_from_slice(&buf[..n]);
                while let Some(end) = pending.iter().skip(1).position(|b| *b == kiss::FEND) {
                    let frame: Vec<u8> = pending.drain(..=end).collect();
                    let frame = kiss::unescape(&frame[1..]);
                    let Some((&command, data)) = frame.split_first() else {
                        continue;
                    };
                    got.push((command, data.to_vec()));
                    match command {
                        rnode_kiss::CMD_DETECT => mock_respond_detect(&mut master),
                        rnode_kiss::CMD_FREQUENCY | rnode_kiss::CMD_TXPOWER => {
                            answer(&mut master, command, data)
                        }
                        rnode_kiss::CMD_BANDWIDTH | rnode_kiss::CMD_SF | rnode_kiss::CMD_CR => {
                            if online {
                                answer(&mut master, rnode_kiss::CMD_STAT_PHYPRM, &phy);
                            }
                            answer(&mut master, command, data);
                        }
                        rnode_kiss::CMD_RADIO_STATE => {
                            if data == [rnode_kiss::RADIO_STATE_ON] && !online {
                                online = true;
                                for _ in 0..3 {
                                    answer(&mut master, rnode_kiss::CMD_STAT_PHYPRM, &phy);
                                }
                            } else if data == [rnode_kiss::RADIO_STATE_OFF] {
                                online = false;
                            }
                            answer(&mut master, command, &[u8::from(online)]);
                        }
                        _ => {}
                    }
                }
            }
            got
        })
    }

    /// A single RNode interface up on a pty, served by the mock firmware.
    struct MockRNode {
        rx: crate::event::EventReceiver,
        control: super::super::ListenerControl,
        stop: Arc<AtomicBool>,
        firmware: thread::JoinHandle<Vec<(u8, Vec<u8>)>>,
        _slave: Transport,
        _dir: tempfile::TempDir,
    }

    impl MockRNode {
        fn start(name: &str, id: u64, radio_on: bool) -> MockRNode {
            // Capture from the start.
            logged();
            let dir = tempdir().unwrap();
            let port_path = dir.path().join("rnode-port");
            let (master_fd, slave_fd) = open_pty_pair().unwrap();
            std::os::unix::fs::symlink(slave_tty_path(slave_fd), &port_path).unwrap();
            let master = unsafe { transport_from_raw_fd(master_fd) };
            // Kept open so the pty does not hang up.
            let slave = unsafe { transport_from_raw_fd(slave_fd) };
            let mut config = RNodeConfig {
                name: name.into(),
                port: port_path.display().to_string(),
                subinterfaces: vec![RNodeSubConfig {
                    name: name.into(),
                    vport: 0,
                    outgoing: true,
                    frequency: 868_000_000,
                    bandwidth: 125_000,
                    txpower: 14,
                    spreading_factor: 8,
                    coding_rate: 5,
                    flow_control: false,
                    st_alock: None,
                    lt_alock: None,
                }],
                interface_id: InterfaceId(id),
                base_interface_id: InterfaceId(id),
                ..Default::default()
            };
            config.runtime = Arc::new(Mutex::new(RNodeRuntime::from_config(&config)));
            let stop = Arc::new(AtomicBool::new(false));
            let firmware = mock_firmware(master, radio_on, Arc::clone(&stop));
            let (tx, rx) = event::channel();
            let (_writers, control) = start_with_control(config, tx).unwrap();
            wait_for_interface_event(
                &rx,
                Duration::from_secs(6),
                |event| matches!(event, Event::InterfaceUp(InterfaceId(i), _, _) if *i == id),
            );
            MockRNode {
                rx,
                control,
                stop,
                firmware,
                _slave: slave,
                _dir: dir,
            }
        }

        /// Shut the interface down as the driver does, and return the
        /// commands the device got.
        fn shut_down(self) -> Vec<(u8, Vec<u8>)> {
            // The device is being read when the stop comes.
            let _ = self.rx.recv_timeout(Duration::from_millis(300));
            self.control.request_stop();
            self.control.finish();
            // Whatever the device still answers has time to be read.
            let _ = self.rx.recv_timeout(Duration::from_millis(300));
            self.stop.store(true, Ordering::Relaxed);
            self.firmware.join().unwrap()
        }
    }

    fn debug_lines(iface: &str, lines: &[&str]) -> Vec<(log::Level, String)> {
        lines
            .iter()
            .map(|line| {
                let level = if line.starts_with("On-air") {
                    log::Level::Info
                } else {
                    log::Level::Debug
                };
                (level, format!("{} {}", iface, line))
            })
            .collect()
    }

    const TIMING_LINES: [&str; 4] = [
        "Radio reporting symbol time is 2.05ms (488 baud)",
        "Radio reporting preamble is 18 symbols (37ms)",
        "Radio reporting CSMA slot time is 24ms",
        "Radio reporting DIFS time is 48ms",
    ];

    /// The radio timing is logged where the device reports it: a radio
    /// still off reports it once started, after the settings are
    /// answered; a radio left on reports it with the first setting that
    /// changes its timing, the bandwidth.
    #[test]
    fn rnode_logs_radio_timing_where_the_device_reports_it() {
        let settings = [
            "Radio reporting bandwidth is 125.0 KHz",
            "Radio reporting TX power is 14 dBm",
            "Radio reporting spreading factor is 8",
            "Radio reporting coding rate is 5",
            "On-air bitrate is now 3.12 kbps",
        ];
        let frequency = "Radio reporting frequency is 868.0 MHz";

        let iface = "RNodeInterface[timing-radio-off]";
        let rnode = MockRNode::start("timing-radio-off", 61, false);
        let mut want = vec![frequency];
        want.extend(settings);
        want.extend(TIMING_LINES);
        assert_eq!(radio_lines(iface), debug_lines(iface, &want));
        rnode.shut_down();

        let iface = "RNodeInterface[timing-radio-on]";
        let rnode = MockRNode::start("timing-radio-on", 62, true);
        let mut want = vec![frequency];
        want.extend(TIMING_LINES);
        want.extend(settings);
        assert_eq!(radio_lines(iface), debug_lines(iface, &want));
        rnode.shut_down();
    }

    /// On shutdown the radio is turned off before the host leaves, as
    /// upstream's detach. A serial port closes right after, before the
    /// device's answer is read, so nothing more is logged, as upstream.
    #[test]
    fn rnode_turns_its_radio_off_on_shutdown() {
        let iface = "RNodeInterface[shutdown-serial]";
        let rnode = MockRNode::start("shutdown-serial", 63, false);
        let got = rnode.shut_down();
        let tail: Vec<_> = got.iter().rev().take(2).rev().cloned().collect();
        assert_eq!(
            tail,
            vec![
                (
                    rnode_kiss::CMD_RADIO_STATE,
                    vec![rnode_kiss::RADIO_STATE_OFF]
                ),
                (rnode_kiss::CMD_LEAVE, vec![0xFF]),
            ]
        );
        assert!(!radio_lines(iface)
            .iter()
            .any(|(_, line)| line.ends_with("Radio reporting state is offline")));
    }

    /// What a BLE device answers while its connection closes is read up
    /// to the radio's state, which is logged as upstream's reader does.
    #[test]
    fn closing_answer_is_read_up_to_the_radio_state() {
        logged();
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        let mut master = unsafe { transport_from_raw_fd(master_fd) };
        let mut slave = unsafe { std::fs::File::from_raw_fd(slave_fd) };
        let config = RNodeConfig {
            name: "closing-answer".into(),
            ..Default::default()
        };
        master
            .write_all(&rnode_kiss::rnode_command(
                rnode_kiss::CMD_RADIO_STATE,
                &[rnode_kiss::RADIO_STATE_OFF],
            ))
            .unwrap();
        let started = std::time::Instant::now();
        setup::read_closing_answer(&mut slave, &config, started + setup::CLOSING_ANSWER_WAIT);
        assert!(started.elapsed() < setup::CLOSING_ANSWER_WAIT);
        assert_eq!(
            radio_lines("RNodeInterface[closing-answer]"),
            vec![(
                log::Level::Debug,
                "RNodeInterface[closing-answer] Radio reporting state is offline".to_string()
            )]
        );

        // A device that does not answer is waited for no longer than the
        // deadline.
        let started = std::time::Instant::now();
        setup::read_closing_answer(&mut slave, &config, started + Duration::from_millis(200));
        assert!(started.elapsed() < Duration::from_millis(700));
    }
}
