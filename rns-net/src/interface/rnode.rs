//! RNode LoRa radio interface.
//!
//! Manages serial connection to RNode device, detects firmware,
//! configures radio parameters per subinterface. Supports single-radio
//! (RNodeInterface) and multi-radio (RNodeMultiInterface) devices.
//!
//! Matches Python `RNodeInterface.py` and `RNodeMultiInterface.py`.

use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rns_core::transport::types::InterfaceId;

use crate::event::{Event, EventSender};
use crate::interface::Writer;
use crate::rnode_kiss;
use crate::serial::{Parity, SerialConfig, SerialPort};

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

/// Configuration for one RNode subinterface (radio).
#[derive(Debug, Clone)]
pub struct RNodeSubConfig {
    pub name: String,
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
    pub id_interval: Option<u32>,
    pub id_callsign: Option<Vec<u8>>,
    pub base_interface_id: InterfaceId,
}

impl Default for RNodeConfig {
    fn default() -> Self {
        RNodeConfig {
            name: String::new(),
            port: String::new(),
            speed: 115200,
            subinterfaces: Vec::new(),
            id_interval: None,
            id_callsign: None,
            base_interface_id: InterfaceId(0),
        }
    }
}

/// Validate subinterface configuration. Returns error message if invalid.
pub fn validate_sub_config(sub: &RNodeSubConfig) -> Option<String> {
    if sub.frequency < FREQ_MIN || sub.frequency > FREQ_MAX {
        return Some(format!("Invalid frequency {} for {}", sub.frequency, sub.name));
    }
    if sub.bandwidth < BW_MIN || sub.bandwidth > BW_MAX {
        return Some(format!("Invalid bandwidth {} for {}", sub.bandwidth, sub.name));
    }
    if sub.spreading_factor < SF_MIN || sub.spreading_factor > SF_MAX {
        return Some(format!("Invalid SF {} for {}", sub.spreading_factor, sub.name));
    }
    if sub.coding_rate < CR_MIN || sub.coding_rate > CR_MAX {
        return Some(format!("Invalid CR {} for {}", sub.coding_rate, sub.name));
    }
    if sub.txpower < TXPOWER_MIN || sub.txpower > TXPOWER_MAX {
        return Some(format!("Invalid TX power {} for {}", sub.txpower, sub.name));
    }
    if let Some(st) = sub.st_alock {
        if st < 0.0 || st > 100.0 {
            return Some(format!("Invalid ST airtime limit {} for {}", st, sub.name));
        }
    }
    if let Some(lt) = sub.lt_alock {
        if lt < 0.0 || lt > 100.0 {
            return Some(format!("Invalid LT airtime limit {} for {}", lt, sub.name));
        }
    }
    None
}

/// Writer for a specific RNode subinterface.
/// Wraps a shared serial writer with subinterface-specific data framing.
struct RNodeSubWriter {
    writer: Arc<Mutex<std::fs::File>>,
    index: u8,
    flow_control: bool,
    flow_state: Arc<Mutex<SubFlowState>>,
}

struct SubFlowState {
    ready: bool,
    queue: std::collections::VecDeque<Vec<u8>>,
}

impl Writer for RNodeSubWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        let frame = rnode_kiss::rnode_data_frame(self.index, data);
        if self.flow_control {
            let mut state = self.flow_state.lock().unwrap();
            if state.ready {
                state.ready = false;
                drop(state);
                self.writer.lock().unwrap().write_all(&frame)
            } else {
                state.queue.push_back(data.to_vec());
                Ok(())
            }
        } else {
            self.writer.lock().unwrap().write_all(&frame)
        }
    }
}

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

    let serial_config = SerialConfig {
        path: config.port.clone(),
        baud: config.speed,
        data_bits: 8,
        parity: Parity::None,
        stop_bits: 1,
    };

    let port = SerialPort::open(&serial_config)?;
    let reader_file = port.reader()?;
    let config_writer = port.writer()?;
    let shared_writer = Arc::new(Mutex::new(config_writer));

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

        let sub_writer: Box<dyn Writer> = Box::new(RNodeSubWriter {
            writer: shared_writer.clone(),
            index: i as u8,
            flow_control: sub.flow_control,
            flow_state,
        });
        writers.push((sub_id, sub_writer));
    }

    // Spawn reader thread
    let reader_shared_writer = shared_writer.clone();
    let reader_config = config.clone();
    let reader_flow_states = flow_states;
    thread::Builder::new()
        .name(format!("rnode-reader-{}", config.base_interface_id.0))
        .spawn(move || {
            reader_loop(
                reader_file,
                reader_shared_writer,
                reader_config,
                tx,
                reader_flow_states,
            );
        })?;

    Ok(writers)
}

/// Reader loop: detect device, configure radios, then relay data frames.
fn reader_loop(
    mut reader: std::fs::File,
    writer: Arc<Mutex<std::fs::File>>,
    config: RNodeConfig,
    tx: EventSender,
    flow_states: Vec<Arc<Mutex<SubFlowState>>>,
) {
    // Initial delay for hardware init (matches Python: sleep(2.0))
    thread::sleep(Duration::from_secs(2));

    // Send detect request
    {
        let detect_cmd = rnode_kiss::detect_request();
        // Also request FW version, platform, MCU (matches Python detect())
        let mut cmd = detect_cmd;
        cmd.extend_from_slice(&rnode_kiss::rnode_command(rnode_kiss::CMD_FW_VERSION, &[0x00]));
        cmd.extend_from_slice(&rnode_kiss::rnode_command(rnode_kiss::CMD_PLATFORM, &[0x00]));
        cmd.extend_from_slice(&rnode_kiss::rnode_command(rnode_kiss::CMD_MCU, &[0x00]));

        if let Err(e) = writer.lock().unwrap().write_all(&cmd) {
            log::error!("[{}] failed to send detect: {}", config.name, e);
            return;
        }
    }

    let mut decoder = rnode_kiss::RNodeDecoder::new();
    let mut buf = [0u8; 4096];
    let mut detected = false;

    // Detection phase: read until we get Detected or timeout
    let detect_start = std::time::Instant::now();
    let detect_timeout = Duration::from_secs(5);

    while !detected && detect_start.elapsed() < detect_timeout {
        match reader.read(&mut buf) {
            Ok(0) => {
                log::warn!("[{}] serial port closed during detect", config.name);
                return;
            }
            Ok(n) => {
                for event in decoder.feed(&buf[..n]) {
                    match event {
                        rnode_kiss::RNodeEvent::Detected(true) => {
                            detected = true;
                            log::info!("[{}] RNode device detected", config.name);
                        }
                        rnode_kiss::RNodeEvent::FirmwareVersion { major, minor } => {
                            log::info!(
                                "[{}] firmware version {}.{}",
                                config.name,
                                major,
                                minor
                            );
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
                log::error!("[{}] serial read error during detect: {}", config.name, e);
                return;
            }
        }
    }

    if !detected {
        log::error!("[{}] RNode detection timed out", config.name);
        return;
    }

    // Configure each subinterface
    for (i, sub) in config.subinterfaces.iter().enumerate() {
        if let Err(e) = configure_subinterface(&writer, i as u8, sub, config.subinterfaces.len() > 1) {
            log::error!("[{}] failed to configure subinterface {}: {}", config.name, i, e);
            return;
        }
    }

    // Brief delay for configuration to settle (matches Python: sleep(0.3))
    thread::sleep(Duration::from_millis(300));

    // Signal all subinterfaces as online
    for i in 0..config.subinterfaces.len() {
        let sub_id = InterfaceId(config.base_interface_id.0 + i as u64);
        let _ = tx.send(Event::InterfaceUp(sub_id, None, None));
    }

    log::info!(
        "[{}] RNode configured with {} subinterface(s)",
        config.name,
        config.subinterfaces.len()
    );

    // Data relay loop
    loop {
        match reader.read(&mut buf) {
            Ok(0) => {
                log::warn!("[{}] serial port closed", config.name);
                for i in 0..config.subinterfaces.len() {
                    let sub_id = InterfaceId(config.base_interface_id.0 + i as u64);
                    let _ = tx.send(Event::InterfaceDown(sub_id));
                }
                // TODO: reconnect logic
                return;
            }
            Ok(n) => {
                for event in decoder.feed(&buf[..n]) {
                    match event {
                        rnode_kiss::RNodeEvent::DataFrame { index, data } => {
                            let sub_id = InterfaceId(config.base_interface_id.0 + index as u64);
                            if tx
                                .send(Event::Frame {
                                    interface_id: sub_id,
                                    data,
                                })
                                .is_err()
                            {
                                return;
                            }
                        }
                        rnode_kiss::RNodeEvent::Ready => {
                            // Flow control: unlock all subinterfaces that have flow_control
                            for (i, fs) in flow_states.iter().enumerate() {
                                if config.subinterfaces[i].flow_control {
                                    process_flow_queue(fs, &writer, i as u8);
                                }
                            }
                        }
                        rnode_kiss::RNodeEvent::Error(code) => {
                            log::error!("[{}] RNode error: 0x{:02X}", config.name, code);
                        }
                        _ => {
                            // Status updates logged but not acted on
                        }
                    }
                }
            }
            Err(e) => {
                log::error!("[{}] serial read error: {}", config.name, e);
                for i in 0..config.subinterfaces.len() {
                    let sub_id = InterfaceId(config.base_interface_id.0 + i as u64);
                    let _ = tx.send(Event::InterfaceDown(sub_id));
                }
                return;
            }
        }
    }
}

/// Configure a single subinterface on the RNode device.
fn configure_subinterface(
    writer: &Arc<Mutex<std::fs::File>>,
    index: u8,
    sub: &RNodeSubConfig,
    multi: bool,
) -> io::Result<()> {
    let mut w = writer.lock().unwrap();

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
        w.write_all(&rnode_kiss::rnode_select_command(index, rnode_kiss::CMD_FREQUENCY, &freq_bytes))?;
        w.write_all(&rnode_kiss::rnode_select_command(index, rnode_kiss::CMD_BANDWIDTH, &bw_bytes))?;
        w.write_all(&rnode_kiss::rnode_select_command(index, rnode_kiss::CMD_TXPOWER, &[txp]))?;
        w.write_all(&rnode_kiss::rnode_select_command(index, rnode_kiss::CMD_SF, &[sub.spreading_factor]))?;
        w.write_all(&rnode_kiss::rnode_select_command(index, rnode_kiss::CMD_CR, &[sub.coding_rate]))?;
    } else {
        w.write_all(&rnode_kiss::rnode_command(rnode_kiss::CMD_FREQUENCY, &freq_bytes))?;
        w.write_all(&rnode_kiss::rnode_command(rnode_kiss::CMD_BANDWIDTH, &bw_bytes))?;
        w.write_all(&rnode_kiss::rnode_command(rnode_kiss::CMD_TXPOWER, &[txp]))?;
        w.write_all(&rnode_kiss::rnode_command(rnode_kiss::CMD_SF, &[sub.spreading_factor]))?;
        w.write_all(&rnode_kiss::rnode_command(rnode_kiss::CMD_CR, &[sub.coding_rate]))?;
    }

    // Airtime locks
    if let Some(st) = sub.st_alock {
        let st_val = (st * 100.0) as u16;
        let st_bytes = [(st_val >> 8) as u8, (st_val & 0xFF) as u8];
        if multi {
            w.write_all(&rnode_kiss::rnode_select_command(index, rnode_kiss::CMD_ST_ALOCK, &st_bytes))?;
        } else {
            w.write_all(&rnode_kiss::rnode_command(rnode_kiss::CMD_ST_ALOCK, &st_bytes))?;
        }
    }
    if let Some(lt) = sub.lt_alock {
        let lt_val = (lt * 100.0) as u16;
        let lt_bytes = [(lt_val >> 8) as u8, (lt_val & 0xFF) as u8];
        if multi {
            w.write_all(&rnode_kiss::rnode_select_command(index, rnode_kiss::CMD_LT_ALOCK, &lt_bytes))?;
        } else {
            w.write_all(&rnode_kiss::rnode_command(rnode_kiss::CMD_LT_ALOCK, &lt_bytes))?;
        }
    }

    // Turn on radio
    if multi {
        w.write_all(&rnode_kiss::rnode_select_command(index, rnode_kiss::CMD_RADIO_STATE, &[rnode_kiss::RADIO_STATE_ON]))?;
    } else {
        w.write_all(&rnode_kiss::rnode_command(rnode_kiss::CMD_RADIO_STATE, &[rnode_kiss::RADIO_STATE_ON]))?;
    }

    Ok(())
}

/// Process flow control queue for a subinterface.
fn process_flow_queue(
    flow_state: &Arc<Mutex<SubFlowState>>,
    writer: &Arc<Mutex<std::fs::File>>,
    index: u8,
) {
    let mut state = flow_state.lock().unwrap();
    if let Some(data) = state.queue.pop_front() {
        state.ready = false;
        drop(state);
        let frame = rnode_kiss::rnode_data_frame(index, &data);
        let _ = writer.lock().unwrap().write_all(&frame);
    } else {
        state.ready = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kiss;
    use crate::serial::open_pty_pair;
    use std::os::unix::io::{AsRawFd, FromRawFd};
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
    fn read_available(file: &mut std::fs::File) -> Vec<u8> {
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

    /// Mock RNode: respond to detect with DETECT_RESP, FW version, platform
    fn mock_respond_detect(master: &mut std::fs::File) {
        // Respond: DETECT_RESP
        master
            .write_all(&rnode_kiss::rnode_command(rnode_kiss::CMD_DETECT, &[rnode_kiss::DETECT_RESP]))
            .unwrap();
        // FW version 1.74
        master
            .write_all(&rnode_kiss::rnode_command(rnode_kiss::CMD_FW_VERSION, &[0x01, 0x4A]))
            .unwrap();
        // Platform ESP32
        master
            .write_all(&rnode_kiss::rnode_command(rnode_kiss::CMD_PLATFORM, &[0x80]))
            .unwrap();
        // MCU
        master
            .write_all(&rnode_kiss::rnode_command(rnode_kiss::CMD_MCU, &[0x01]))
            .unwrap();
        master.flush().unwrap();
    }

    #[test]
    fn rnode_detect_over_pty() {
        // Test that the RNode decoder can parse detect responses from a PTY
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        let mut master = unsafe { std::fs::File::from_raw_fd(master_fd) };
        let mut slave = unsafe { std::fs::File::from_raw_fd(slave_fd) };

        // Write detect response to master
        mock_respond_detect(&mut master);

        // Read from slave with RNode decoder
        assert!(poll_read(slave.as_raw_fd(), 2000));
        let mut decoder = rnode_kiss::RNodeDecoder::new();
        let mut buf = [0u8; 4096];
        let n = slave.read(&mut buf).unwrap();
        let events = decoder.feed(&buf[..n]);

        assert!(
            events.iter().any(|e| matches!(e, rnode_kiss::RNodeEvent::Detected(true))),
            "should detect device"
        );
        assert!(
            events.iter().any(|e| matches!(e, rnode_kiss::RNodeEvent::FirmwareVersion { .. })),
            "should get firmware version"
        );
    }

    #[test]
    fn rnode_configure_commands() {
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        let mut master = unsafe { std::fs::File::from_raw_fd(master_fd) };
        let writer_file = unsafe { std::fs::File::from_raw_fd(libc::dup(slave_fd)) };
        let writer = Arc::new(Mutex::new(writer_file));

        let sub = RNodeSubConfig {
            name: "test".into(),
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
        assert!(data.windows(2).any(|w| w[0] == kiss::FEND && w[1] == rnode_kiss::CMD_FREQUENCY),
            "should contain FREQUENCY command");
        // Should contain bandwidth command
        assert!(data.windows(2).any(|w| w[0] == kiss::FEND && w[1] == rnode_kiss::CMD_BANDWIDTH),
            "should contain BANDWIDTH command");
        // Should contain RADIO_STATE ON
        assert!(data.windows(3).any(|w| w[0] == kiss::FEND && w[1] == rnode_kiss::CMD_RADIO_STATE && w[2] == rnode_kiss::RADIO_STATE_ON),
            "should contain RADIO_STATE ON command");

        unsafe { libc::close(slave_fd) };
    }

    #[test]
    fn rnode_data_roundtrip() {
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        let mut master = unsafe { std::fs::File::from_raw_fd(master_fd) };
        let slave = unsafe { std::fs::File::from_raw_fd(slave_fd) };

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
        let writer_file = unsafe { std::fs::File::from_raw_fd(slave_fd) };
        let shared_writer = Arc::new(Mutex::new(writer_file));

        let flow_state = Arc::new(Mutex::new(SubFlowState {
            ready: true,
            queue: std::collections::VecDeque::new(),
        }));

        let mut sub_writer = RNodeSubWriter {
            writer: shared_writer.clone(),
            index: 0,
            flow_control: true,
            flow_state: flow_state.clone(),
        };

        // First send: should go through (ready=true) and set ready=false
        sub_writer.send_frame(b"hello").unwrap();
        assert!(!flow_state.lock().unwrap().ready);

        // Second send: should be queued
        sub_writer.send_frame(b"world").unwrap();
        assert_eq!(flow_state.lock().unwrap().queue.len(), 1);

        // Process flow queue (simulates CMD_READY)
        process_flow_queue(&flow_state, &shared_writer, 0);
        assert_eq!(flow_state.lock().unwrap().queue.len(), 0);
        assert!(!flow_state.lock().unwrap().ready); // sent queued, still locked

        // Process again with empty queue: sets ready=true
        process_flow_queue(&flow_state, &shared_writer, 0);
        assert!(flow_state.lock().unwrap().ready);

        unsafe { libc::close(master_fd) };
    }

    #[test]
    fn rnode_sub_writer_format() {
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        let mut master = unsafe { std::fs::File::from_raw_fd(master_fd) };
        let writer_file = unsafe { std::fs::File::from_raw_fd(slave_fd) };
        let shared_writer = Arc::new(Mutex::new(writer_file));

        let flow_state = Arc::new(Mutex::new(SubFlowState {
            ready: true,
            queue: std::collections::VecDeque::new(),
        }));

        let mut sub_writer = RNodeSubWriter {
            writer: shared_writer,
            index: 1, // subinterface 1
            flow_control: false,
            flow_state,
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
        assert_eq!(events0[0], rnode_kiss::RNodeEvent::DataFrame { index: 0, data: payload0 });

        let payload1 = vec![0x03, 0x04];
        let frame1 = rnode_kiss::rnode_data_frame(1, &payload1);
        let events1 = decoder.feed(&frame1);
        assert_eq!(events1.len(), 1);
        assert_eq!(events1[0], rnode_kiss::RNodeEvent::DataFrame { index: 1, data: payload1 });
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
}
