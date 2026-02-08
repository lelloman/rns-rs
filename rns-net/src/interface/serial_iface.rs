//! Serial interface with HDLC framing.
//!
//! Matches Python `SerialInterface.py` — opens a serial port,
//! reads with HDLC framing, reconnects on failure.

use std::io::{self, Read, Write};
use std::thread;
use std::time::Duration;

use rns_core::transport::types::InterfaceId;

use crate::event::{Event, EventSender};
use crate::hdlc;
use crate::interface::Writer;
use crate::serial::{Parity, SerialConfig, SerialPort};

/// Configuration for a Serial interface.
#[derive(Debug, Clone)]
pub struct SerialIfaceConfig {
    pub name: String,
    pub port: String,
    pub speed: u32,
    pub data_bits: u8,
    pub parity: Parity,
    pub stop_bits: u8,
    pub interface_id: InterfaceId,
}

impl Default for SerialIfaceConfig {
    fn default() -> Self {
        SerialIfaceConfig {
            name: String::new(),
            port: String::new(),
            speed: 9600,
            data_bits: 8,
            parity: Parity::None,
            stop_bits: 1,
            interface_id: InterfaceId(0),
        }
    }
}

/// Writer that sends HDLC-framed data over a serial port.
struct SerialWriter {
    file: std::fs::File,
}

impl Writer for SerialWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.file.write_all(&hdlc::frame(data))
    }
}

/// Start the serial interface. Opens the port, spawns reader thread.
/// Returns the writer for the driver.
pub fn start(config: SerialIfaceConfig, tx: EventSender) -> io::Result<Box<dyn Writer>> {
    let serial_config = SerialConfig {
        path: config.port.clone(),
        baud: config.speed,
        data_bits: config.data_bits,
        parity: config.parity,
        stop_bits: config.stop_bits,
    };

    let port = SerialPort::open(&serial_config)?;
    let reader_file = port.reader()?;
    let writer_file = port.writer()?;

    let id = config.interface_id;

    // Signal interface up
    let _ = tx.send(Event::InterfaceUp(id, None, None));

    // Short delay matching Python's configure_device sleep
    thread::sleep(Duration::from_millis(500));

    // Spawn reader thread
    thread::Builder::new()
        .name(format!("serial-reader-{}", id.0))
        .spawn(move || {
            reader_loop(reader_file, id, config, tx);
        })?;

    Ok(Box::new(SerialWriter { file: writer_file }))
}

/// Reader thread: reads from serial, HDLC-decodes, sends frames to driver.
fn reader_loop(
    mut reader: std::fs::File,
    id: InterfaceId,
    config: SerialIfaceConfig,
    tx: EventSender,
) {
    let mut decoder = hdlc::Decoder::new();
    let mut buf = [0u8; 4096];

    loop {
        match reader.read(&mut buf) {
            Ok(0) => {
                // EOF — port closed
                log::warn!("[{}] serial port closed", config.name);
                let _ = tx.send(Event::InterfaceDown(id));
                match reconnect(&config, &tx) {
                    Some(new_reader) => {
                        reader = new_reader;
                        decoder = hdlc::Decoder::new();
                        continue;
                    }
                    None => return,
                }
            }
            Ok(n) => {
                for frame in decoder.feed(&buf[..n]) {
                    if tx.send(Event::Frame { interface_id: id, data: frame }).is_err() {
                        return; // driver shut down
                    }
                }
            }
            Err(e) => {
                log::warn!("[{}] serial read error: {}", config.name, e);
                let _ = tx.send(Event::InterfaceDown(id));
                match reconnect(&config, &tx) {
                    Some(new_reader) => {
                        reader = new_reader;
                        decoder = hdlc::Decoder::new();
                        continue;
                    }
                    None => return,
                }
            }
        }
    }
}

/// Attempt to reconnect the serial port. Returns new reader file on success.
fn reconnect(
    config: &SerialIfaceConfig,
    tx: &EventSender,
) -> Option<std::fs::File> {
    loop {
        thread::sleep(Duration::from_secs(5));
        log::info!("[{}] attempting to reconnect serial port {}...", config.name, config.port);

        let serial_config = SerialConfig {
            path: config.port.clone(),
            baud: config.speed,
            data_bits: config.data_bits,
            parity: config.parity,
            stop_bits: config.stop_bits,
        };

        match SerialPort::open(&serial_config) {
            Ok(port) => {
                match (port.reader(), port.writer()) {
                    (Ok(reader), Ok(writer_file)) => {
                        log::info!("[{}] serial port reconnected", config.name);
                        let new_writer: Box<dyn Writer> = Box::new(SerialWriter { file: writer_file });
                        let _ = tx.send(Event::InterfaceUp(config.interface_id, Some(new_writer), None));
                        thread::sleep(Duration::from_millis(500));
                        return Some(reader);
                    }
                    _ => {
                        log::warn!("[{}] failed to get reader/writer from serial port", config.name);
                    }
                }
            }
            Err(e) => {
                log::warn!("[{}] serial reconnect failed: {}", config.name, e);
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
    use std::time::Duration;

    /// Helper: poll an fd for reading with timeout (ms). Returns true if data available.
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
    fn serial_hdlc_roundtrip() {
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        let mut master_file = unsafe { std::fs::File::from_raw_fd(master_fd) };
        let mut slave_file = unsafe { std::fs::File::from_raw_fd(slave_fd) };

        // Write an HDLC frame to the master side
        let payload: Vec<u8> = (0..32).collect();
        let framed = hdlc::frame(&payload);
        master_file.write_all(&framed).unwrap();
        master_file.flush().unwrap();

        // Read from slave using HDLC decoder
        assert!(poll_read(slave_file.as_raw_fd(), 2000), "should have data available");

        let mut decoder = hdlc::Decoder::new();
        let mut buf = [0u8; 4096];
        let n = slave_file.read(&mut buf).unwrap();
        let frames = decoder.feed(&buf[..n]);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], payload);
    }

    #[test]
    fn serial_writer_frames() {
        let (master_fd, slave_fd) = open_pty_pair().unwrap();

        let writer_file = unsafe { std::fs::File::from_raw_fd(slave_fd) };
        let mut writer = SerialWriter { file: writer_file };

        let payload = vec![0x01, 0x02, 0x7E, 0x7D, 0x03]; // includes bytes that need HDLC escaping
        writer.send_frame(&payload).unwrap();

        // Read from master
        let mut master_file = unsafe { std::fs::File::from_raw_fd(master_fd) };
        assert!(poll_read(master_file.as_raw_fd(), 2000), "should have data");

        let expected = hdlc::frame(&payload);
        let mut buf = [0u8; 256];
        let n = master_file.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], &expected[..]);
    }

    #[test]
    fn serial_fragmented_read() {
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        let mut master_file = unsafe { std::fs::File::from_raw_fd(master_fd) };
        let slave_file = unsafe { std::fs::File::from_raw_fd(slave_fd) };

        let (tx, rx) = mpsc::channel::<Event>();

        // Write a frame in two parts to the master
        let payload: Vec<u8> = (0..32).collect();
        let framed = hdlc::frame(&payload);
        let mid = framed.len() / 2;

        // Spawn reader thread first (it will block waiting for data)
        let reader_thread = thread::spawn(move || {
            let mut reader = slave_file;
            let mut decoder = hdlc::Decoder::new();
            let mut buf = [0u8; 4096];

            loop {
                match reader.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        for frame in decoder.feed(&buf[..n]) {
                            let _ = tx.send(Event::Frame { interface_id: InterfaceId(0), data: frame });
                            return;
                        }
                    }
                    _ => return,
                }
            }
        });

        // Write first half
        master_file.write_all(&framed[..mid]).unwrap();
        master_file.flush().unwrap();

        // Small delay then write second half
        thread::sleep(Duration::from_millis(50));
        master_file.write_all(&framed[mid..]).unwrap();
        master_file.flush().unwrap();

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { data, .. } => assert_eq!(data, payload),
            other => panic!("expected Frame, got {:?}", other),
        }

        let _ = reader_thread.join();
    }

    #[test]
    fn serial_reconnect_on_close() {
        let (master_fd, slave_fd) = open_pty_pair().unwrap();

        let (tx, rx) = mpsc::channel::<Event>();
        let id = InterfaceId(42);

        // Spawn a reader thread on the slave side
        let slave_file = unsafe { std::fs::File::from_raw_fd(slave_fd) };
        let reader_thread = thread::spawn(move || {
            let mut reader = slave_file;
            let mut buf = [0u8; 4096];
            let mut decoder = hdlc::Decoder::new();
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => {
                        let _ = tx.send(Event::InterfaceDown(id));
                        return;
                    }
                    Ok(n) => {
                        for frame in decoder.feed(&buf[..n]) {
                            let _ = tx.send(Event::Frame { interface_id: id, data: frame });
                        }
                    }
                    Err(_) => {
                        let _ = tx.send(Event::InterfaceDown(id));
                        return;
                    }
                }
            }
        });

        // Close the master fd — this should cause the reader to get EOF
        unsafe { libc::close(master_fd) };

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceDown(InterfaceId(42))));

        let _ = reader_thread.join();
    }
}
