//! KISS interface with flow control and TNC configuration.
//!
//! Matches Python `KISSInterface.py` — opens a serial port,
//! sends TNC configuration commands, handles KISS framing with
//! optional flow control.

use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::collections::VecDeque;

use rns_core::transport::types::InterfaceId;

use crate::event::{Event, EventSender};
use crate::kiss;
use crate::interface::Writer;
use crate::serial::{Parity, SerialConfig, SerialPort};

/// Configuration for a KISS interface.
#[derive(Debug, Clone)]
pub struct KissIfaceConfig {
    pub name: String,
    pub port: String,
    pub speed: u32,
    pub data_bits: u8,
    pub parity: Parity,
    pub stop_bits: u8,
    pub preamble: u16,       // ms, default 350
    pub txtail: u16,         // ms, default 20
    pub persistence: u8,     // 0-255, default 64
    pub slottime: u16,       // ms, default 20
    pub flow_control: bool,  // default false
    pub beacon_interval: Option<u32>,  // seconds
    pub beacon_data: Option<Vec<u8>>,  // padded to 15 bytes
    pub interface_id: InterfaceId,
}

impl Default for KissIfaceConfig {
    fn default() -> Self {
        KissIfaceConfig {
            name: String::new(),
            port: String::new(),
            speed: 9600,
            data_bits: 8,
            parity: Parity::None,
            stop_bits: 1,
            preamble: 350,
            txtail: 20,
            persistence: 64,
            slottime: 20,
            flow_control: false,
            beacon_interval: None,
            beacon_data: None,
            interface_id: InterfaceId(0),
        }
    }
}

/// Shared flow-control state between writer and reader threads.
struct FlowState {
    ready: bool,
    queue: VecDeque<Vec<u8>>,
    lock_time: Instant,
}

/// Writer that sends KISS-framed data over a serial port.
/// Handles flow control: when enabled, queues packets until CMD_READY.
struct KissWriter {
    file: std::fs::File,
    flow_control: bool,
    flow_state: Arc<Mutex<FlowState>>,
}

impl Writer for KissWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        if self.flow_control {
            let mut state = self.flow_state.lock().unwrap();
            if state.ready {
                state.ready = false;
                state.lock_time = Instant::now();
                drop(state);
                self.file.write_all(&kiss::frame(data))
            } else {
                state.queue.push_back(data.to_vec());
                Ok(())
            }
        } else {
            self.file.write_all(&kiss::frame(data))
        }
    }
}

/// Start the KISS interface. Opens the port, configures TNC, spawns reader thread.
pub fn start(config: KissIfaceConfig, tx: EventSender) -> io::Result<Box<dyn Writer>> {
    let serial_config = SerialConfig {
        path: config.port.clone(),
        baud: config.speed,
        data_bits: config.data_bits,
        parity: config.parity,
        stop_bits: config.stop_bits,
    };

    let port = SerialPort::open(&serial_config)?;
    let reader_file = port.reader()?;
    let mut writer_file = port.writer()?;
    let flow_writer_file = port.writer()?;

    let id = config.interface_id;

    // Initial 2-second delay for TNC initialization (matches Python)
    thread::sleep(Duration::from_secs(2));

    // Signal interface up
    let _ = tx.send(Event::InterfaceUp(id, None, None));

    // Send TNC configuration commands
    configure_tnc(&mut writer_file, &config)?;

    let flow_state = Arc::new(Mutex::new(FlowState {
        ready: true,
        queue: VecDeque::new(),
        lock_time: Instant::now(),
    }));

    let reader_flow_state = flow_state.clone();

    // Spawn reader thread
    let reader_config = config.clone();
    thread::Builder::new()
        .name(format!("kiss-reader-{}", id.0))
        .spawn(move || {
            reader_loop(reader_file, flow_writer_file, id, reader_config, tx, reader_flow_state);
        })?;

    Ok(Box::new(KissWriter {
        file: writer_file,
        flow_control: config.flow_control,
        flow_state,
    }))
}

/// Send TNC configuration commands via KISS.
/// Matches Python `KISSInterface.configure_device()`.
fn configure_tnc(writer: &mut std::fs::File, config: &KissIfaceConfig) -> io::Result<()> {
    log::info!("[{}] configuring KISS interface parameters", config.name);

    // Preamble: value is ms/10, clamped to 0-255
    let preamble_val = (config.preamble / 10).min(255) as u8;
    writer.write_all(&kiss::command_frame(kiss::CMD_TXDELAY, &[preamble_val]))?;

    // TX tail: value is ms/10, clamped to 0-255
    let txtail_val = (config.txtail / 10).min(255) as u8;
    writer.write_all(&kiss::command_frame(kiss::CMD_TXTAIL, &[txtail_val]))?;

    // Persistence: raw value, clamped to 0-255
    writer.write_all(&kiss::command_frame(kiss::CMD_P, &[config.persistence]))?;

    // Slot time: value is ms/10, clamped to 0-255
    let slottime_val = (config.slottime / 10).min(255) as u8;
    writer.write_all(&kiss::command_frame(kiss::CMD_SLOTTIME, &[slottime_val]))?;

    // Flow control: send CMD_READY with 0x01 (matches Python setFlowControl)
    writer.write_all(&kiss::command_frame(kiss::CMD_READY, &[0x01]))?;

    log::info!("[{}] KISS interface configured", config.name);
    Ok(())
}

/// Reader loop: reads from serial, KISS-decodes, dispatches events.
/// Also handles flow control unlocking and beacon transmission.
fn reader_loop(
    mut reader: std::fs::File,
    mut flow_writer: std::fs::File,
    id: InterfaceId,
    config: KissIfaceConfig,
    tx: EventSender,
    flow_state: Arc<Mutex<FlowState>>,
) {
    let mut decoder = kiss::Decoder::new();
    let mut buf = [0u8; 4096];
    let mut first_tx: Option<Instant> = None;

    loop {
        match reader.read(&mut buf) {
            Ok(0) => {
                log::warn!("[{}] KISS port closed", config.name);
                let _ = tx.send(Event::InterfaceDown(id));
                match reconnect(&config, &tx, &flow_state) {
                    Some((new_reader, new_flow_writer)) => {
                        reader = new_reader;
                        flow_writer = new_flow_writer;
                        decoder = kiss::Decoder::new();
                        continue;
                    }
                    None => return,
                }
            }
            Ok(n) => {
                for event in decoder.feed(&buf[..n]) {
                    match event {
                        kiss::KissEvent::DataFrame(data) => {
                            if tx.send(Event::Frame { interface_id: id, data }).is_err() {
                                return;
                            }
                        }
                        kiss::KissEvent::Ready => {
                            process_queue(&flow_state, &mut flow_writer, &mut first_tx, &config);
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("[{}] KISS read error: {}", config.name, e);
                let _ = tx.send(Event::InterfaceDown(id));
                match reconnect(&config, &tx, &flow_state) {
                    Some((new_reader, new_flow_writer)) => {
                        reader = new_reader;
                        flow_writer = new_flow_writer;
                        decoder = kiss::Decoder::new();
                        continue;
                    }
                    None => return,
                }
            }
        }

        // Flow control timeout check
        if config.flow_control {
            let state = flow_state.lock().unwrap();
            if !state.ready && state.lock_time.elapsed() > Duration::from_secs(5) {
                drop(state);
                log::warn!("[{}] unlocking flow control due to timeout", config.name);
                process_queue(&flow_state, &mut flow_writer, &mut first_tx, &config);
            }
        }

        // Beacon check
        if let (Some(interval), Some(ref beacon_data)) = (config.beacon_interval, &config.beacon_data) {
            if let Some(first) = first_tx {
                if first.elapsed() > Duration::from_secs(interval as u64) {
                    log::debug!("[{}] transmitting beacon data", config.name);
                    // Pad to minimum 15 bytes
                    let mut frame = beacon_data.clone();
                    while frame.len() < 15 {
                        frame.push(0x00);
                    }
                    let _ = flow_writer.write_all(&kiss::frame(&frame));
                    first_tx = None;
                }
            }
        }
    }
}

/// Process the flow control queue: send next queued packet, mark ready.
fn process_queue(
    flow_state: &Arc<Mutex<FlowState>>,
    writer: &mut std::fs::File,
    first_tx: &mut Option<Instant>,
    _config: &KissIfaceConfig,
) {
    let mut state = flow_state.lock().unwrap();
    if let Some(data) = state.queue.pop_front() {
        state.ready = false;
        state.lock_time = Instant::now();
        drop(state);
        let _ = writer.write_all(&kiss::frame(&data));
        if first_tx.is_none() {
            *first_tx = Some(Instant::now());
        }
    } else {
        state.ready = true;
    }
}

/// Attempt to reconnect the serial port.
fn reconnect(
    config: &KissIfaceConfig,
    tx: &EventSender,
    flow_state: &Arc<Mutex<FlowState>>,
) -> Option<(std::fs::File, std::fs::File)> {
    loop {
        thread::sleep(Duration::from_secs(5));
        log::info!("[{}] attempting to reconnect KISS port {}...", config.name, config.port);

        let serial_config = SerialConfig {
            path: config.port.clone(),
            baud: config.speed,
            data_bits: config.data_bits,
            parity: config.parity,
            stop_bits: config.stop_bits,
        };

        match SerialPort::open(&serial_config) {
            Ok(port) => {
                match (port.reader(), port.writer(), port.writer()) {
                    (Ok(reader), Ok(mut cfg_writer), Ok(flow_writer)) => {
                        // 2-second init delay
                        thread::sleep(Duration::from_secs(2));
                        if let Err(e) = configure_tnc(&mut cfg_writer, config) {
                            log::warn!("[{}] TNC config failed: {}", config.name, e);
                            continue;
                        }
                        // Reset flow state
                        let mut state = flow_state.lock().unwrap();
                        state.ready = true;
                        state.queue.clear();
                        drop(state);

                        let new_writer: Box<dyn Writer> = Box::new(KissWriter {
                            file: cfg_writer,
                            flow_control: config.flow_control,
                            flow_state: flow_state.clone(),
                        });
                        let _ = tx.send(Event::InterfaceUp(config.interface_id, Some(new_writer), None));
                        log::info!("[{}] KISS port reconnected", config.name);
                        return Some((reader, flow_writer));
                    }
                    _ => {
                        log::warn!("[{}] failed to get handles from serial port", config.name);
                    }
                }
            }
            Err(e) => {
                log::warn!("[{}] KISS reconnect failed: {}", config.name, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serial::open_pty_pair;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::sync::mpsc;

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

    #[test]
    fn kiss_data_roundtrip() {
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        let mut master_file = unsafe { std::fs::File::from_raw_fd(master_fd) };
        let mut slave_file = unsafe { std::fs::File::from_raw_fd(slave_fd) };

        // Write a KISS data frame to the master side
        let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let framed = kiss::frame(&payload);
        master_file.write_all(&framed).unwrap();
        master_file.flush().unwrap();

        // Read from slave using KISS decoder
        assert!(poll_read(slave_file.as_raw_fd(), 2000));

        let mut decoder = kiss::Decoder::new();
        let mut buf = [0u8; 4096];
        let n = slave_file.read(&mut buf).unwrap();
        let events = decoder.feed(&buf[..n]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], kiss::KissEvent::DataFrame(payload));
    }

    #[test]
    fn kiss_writer_frames() {
        let (master_fd, slave_fd) = open_pty_pair().unwrap();

        let writer_file = unsafe { std::fs::File::from_raw_fd(slave_fd) };
        let flow_state = Arc::new(Mutex::new(FlowState {
            ready: true,
            queue: VecDeque::new(),
            lock_time: Instant::now(),
        }));

        let mut writer = KissWriter {
            file: writer_file,
            flow_control: false,
            flow_state,
        };

        let payload = vec![0xC0, 0xDB, 0x01]; // includes bytes that need KISS escaping
        writer.send_frame(&payload).unwrap();

        // Read from master
        let mut master_file = unsafe { std::fs::File::from_raw_fd(master_fd) };
        assert!(poll_read(master_file.as_raw_fd(), 2000));

        let expected = kiss::frame(&payload);
        let mut buf = [0u8; 256];
        let n = master_file.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], &expected[..]);
    }

    #[test]
    fn kiss_config_commands() {
        let (master_fd, slave_fd) = open_pty_pair().unwrap();

        let mut writer_file = unsafe { std::fs::File::from_raw_fd(slave_fd) };
        let config = KissIfaceConfig {
            preamble: 350,
            txtail: 20,
            persistence: 64,
            slottime: 20,
            ..Default::default()
        };

        configure_tnc(&mut writer_file, &config).unwrap();

        // Read all commands from master
        let mut master_file = unsafe { std::fs::File::from_raw_fd(master_fd) };
        assert!(poll_read(master_file.as_raw_fd(), 2000));

        let mut buf = [0u8; 1024];
        let n = master_file.read(&mut buf).unwrap();
        let data = &buf[..n];

        // Should contain TXDELAY command: FEND, CMD_TXDELAY, value, FEND
        // preamble: 350/10 = 35
        assert!(data.windows(4).any(|w|
            w[0] == kiss::FEND && w[1] == kiss::CMD_TXDELAY && w[2] == 35 && w[3] == kiss::FEND
        ), "should contain TXDELAY command");

        // TXTAIL: 20/10 = 2
        assert!(data.windows(4).any(|w|
            w[0] == kiss::FEND && w[1] == kiss::CMD_TXTAIL && w[2] == 2 && w[3] == kiss::FEND
        ), "should contain TXTAIL command");

        // Persistence: 64
        assert!(data.windows(4).any(|w|
            w[0] == kiss::FEND && w[1] == kiss::CMD_P && w[2] == 64 && w[3] == kiss::FEND
        ), "should contain P command");

        // Slottime: 20/10 = 2
        assert!(data.windows(4).any(|w|
            w[0] == kiss::FEND && w[1] == kiss::CMD_SLOTTIME && w[2] == 2 && w[3] == kiss::FEND
        ), "should contain SLOTTIME command");
    }

    #[test]
    fn kiss_flow_control_lock() {
        let flow_state = Arc::new(Mutex::new(FlowState {
            ready: true,
            queue: VecDeque::new(),
            lock_time: Instant::now(),
        }));

        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        let writer_file = unsafe { std::fs::File::from_raw_fd(slave_fd) };

        let mut writer = KissWriter {
            file: writer_file,
            flow_control: true,
            flow_state: flow_state.clone(),
        };

        // First send should go through (ready=true) and lock
        writer.send_frame(b"hello").unwrap();
        assert!(!flow_state.lock().unwrap().ready);

        // Second send should be queued (ready=false)
        writer.send_frame(b"world").unwrap();
        assert_eq!(flow_state.lock().unwrap().queue.len(), 1);

        // Simulate CMD_READY: process_queue
        let mut flow_writer = unsafe { std::fs::File::from_raw_fd(libc::dup(master_fd)) };
        let mut first_tx = None;
        let config = KissIfaceConfig::default();
        process_queue(&flow_state, &mut flow_writer, &mut first_tx, &config);

        // Queue should be empty now (dequeued "world"), but ready=false because it sent
        assert_eq!(flow_state.lock().unwrap().queue.len(), 0);
        assert!(!flow_state.lock().unwrap().ready);

        // Process again with empty queue: should set ready=true
        process_queue(&flow_state, &mut flow_writer, &mut first_tx, &config);
        assert!(flow_state.lock().unwrap().ready);

        // Clean up
        unsafe { libc::close(master_fd) };
    }

    #[test]
    fn kiss_flow_control_timeout() {
        let flow_state = Arc::new(Mutex::new(FlowState {
            ready: false,
            queue: VecDeque::new(),
            lock_time: Instant::now() - Duration::from_secs(6), // already timed out
        }));

        // Check that the timeout condition triggers
        let state = flow_state.lock().unwrap();
        assert!(!state.ready);
        assert!(state.lock_time.elapsed() > Duration::from_secs(5));
    }

    #[test]
    fn kiss_fragmented() {
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        let mut master_file = unsafe { std::fs::File::from_raw_fd(master_fd) };
        let slave_file = unsafe { std::fs::File::from_raw_fd(slave_fd) };

        let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let framed = kiss::frame(&payload);
        let mid = framed.len() / 2;

        // Spawn reader thread first (it will block waiting for data)
        let (tx, rx) = mpsc::channel::<kiss::KissEvent>();
        let reader_thread = thread::spawn(move || {
            let mut reader = slave_file;
            let mut decoder = kiss::Decoder::new();
            let mut buf = [0u8; 4096];

            loop {
                match reader.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        for event in decoder.feed(&buf[..n]) {
                            let _ = tx.send(event.clone());
                            if matches!(event, kiss::KissEvent::DataFrame(_)) {
                                return;
                            }
                        }
                    }
                    _ => return,
                }
            }
        });

        // Write first half
        master_file.write_all(&framed[..mid]).unwrap();
        master_file.flush().unwrap();

        thread::sleep(Duration::from_millis(50));

        // Write second half
        master_file.write_all(&framed[mid..]).unwrap();
        master_file.flush().unwrap();

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(event, kiss::KissEvent::DataFrame(payload));

        let _ = reader_thread.join();
    }
}
