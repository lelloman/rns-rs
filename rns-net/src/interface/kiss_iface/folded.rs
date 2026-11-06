//! A KISS port on the compact engine's driver loop.
//!
//! With interface I/O folded (see [`crate::engine::FOLD_IO`]) the port is a
//! loop source read on the driver thread, and the driver writes it through
//! [`KissLoopWriter`], which it calls directly. Both share the port's
//! [`Port`] state: the bytes not yet written and, with flow control, the
//! frames held until the TNC reports it is ready. The flow-control timeout
//! and the beacon are checked on the driver's tick.

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::{reopen_port, Ax25Address, KissIfaceConfig};
use crate::event::{Event, EventSender, LoopContext, LoopSource, SourceStatus};
use crate::interface::stream_read::{set_nonblocking, STREAM_READ_BUDGET};
use crate::interface::{lock_or_recover, ListenerControl, Writer};
use crate::kiss;
use crate::link_send::Completion;
use crate::poll::{Event as Interest, Poller};

/// Bytes a port holds, written or waiting for the TNC, before new frames
/// are refused: about what the threaded writer's queue holds, so frames do
/// not wait minutes behind a backlog on a slow line.
const BUFFER_LIMIT: usize = 128 * 1024;

/// How long flow control waits for the TNC's ready report before sending
/// the next frame anyway.
const FLOW_TIMEOUT: Duration = Duration::from_secs(5);

/// A beacon is padded to at least this many bytes.
const BEACON_MIN_LEN: usize = 15;

/// What the writer and the reader of one open port share.
struct Port {
    /// The port, written without blocking; registered for writable
    /// interest under the interface's write key.
    file: std::fs::File,
    poller: Arc<Poller>,
    key: usize,
    registered: bool,
    want_writable: bool,
    out: Vec<u8>,
    head: usize,
    failed: bool,
    flow_control: bool,
    /// Whether the TNC may take a frame now (always, without flow control).
    ready: bool,
    lock_time: Instant,
    /// Framed data held until the TNC reports ready, and its size.
    held: VecDeque<Vec<u8>>,
    held_bytes: usize,
    /// When data was first sent since the last beacon.
    first_tx: Option<Instant>,
    beacon: Option<(Duration, Vec<u8>)>,
    name: String,
}

impl Port {
    fn new(file: std::fs::File, config: &KissIfaceConfig, poller: Arc<Poller>) -> Self {
        let key = crate::interface::loop_writer::write_key(config.interface_id);
        // SAFETY: `file` is kept open until `Drop` removes the registration.
        let registered = match unsafe { poller.add(file.as_raw_fd(), Interest::none(key)) } {
            Ok(()) => true,
            Err(error) => {
                log::warn!(
                    "[{}] cannot register the KISS port with the driver poller: {}",
                    config.name,
                    error
                );
                false
            }
        };
        let beacon = match (config.beacon_interval, &config.beacon_data) {
            (Some(interval), Some(data)) => {
                let mut frame = data.clone();
                frame.resize(frame.len().max(BEACON_MIN_LEN), 0);
                Some((Duration::from_secs(interval.into()), kiss::frame(&frame)))
            }
            _ => None,
        };
        Self {
            file,
            poller,
            key,
            registered,
            want_writable: false,
            out: Vec::new(),
            head: 0,
            failed: false,
            flow_control: config.flow_control,
            ready: true,
            lock_time: Instant::now(),
            held: VecDeque::new(),
            held_bytes: 0,
            first_tx: None,
            beacon,
            name: config.name.clone(),
        }
    }

    fn buffered(&self) -> usize {
        self.out.len() - self.head + self.held_bytes
    }

    fn check(&self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "KISS port is offline",
            ));
        }
        Ok(())
    }

    /// Whether a frame of `bytes` is taken now. A frame is always taken
    /// while nothing is buffered, whatever its size.
    fn fits(&self, bytes: usize) -> bool {
        self.buffered() == 0 || self.buffered() + bytes <= BUFFER_LIMIT
    }

    /// Whether a frame would be written now rather than held for the TNC.
    fn sends_now(&self) -> bool {
        !self.flow_control || (self.ready && self.held.is_empty())
    }

    /// Send a framed data frame, or hold it until the TNC is ready.
    fn submit(&mut self, frame: Vec<u8>) {
        if self.sends_now() {
            self.transmit(&frame);
        } else {
            self.held_bytes += frame.len();
            self.held.push_back(frame);
        }
    }

    /// Write a framed data frame, locking flow control until the TNC
    /// reports ready again.
    fn transmit(&mut self, frame: &[u8]) {
        if self.flow_control {
            self.ready = false;
            self.lock_time = Instant::now();
        }
        self.first_tx.get_or_insert_with(Instant::now);
        self.append(frame);
    }

    fn append(&mut self, bytes: &[u8]) {
        if self.head == self.out.len() {
            self.out.clear();
            self.head = 0;
        }
        self.out.extend_from_slice(bytes);
        self.drain();
    }

    /// The TNC is ready: send the next held frame, or note it is ready.
    fn tnc_ready(&mut self) {
        match self.held.pop_front() {
            Some(frame) => {
                self.held_bytes -= frame.len();
                self.transmit(&frame);
            }
            None => self.ready = true,
        }
    }

    /// Unlock flow control the TNC left locked too long, and send a beacon
    /// when one is due.
    fn tick(&mut self) {
        if self.failed {
            return;
        }
        if self.flow_control && !self.ready && self.lock_time.elapsed() > FLOW_TIMEOUT {
            log::warn!("[{}] unlocking flow control due to timeout", self.name);
            self.tnc_ready();
        }
        let beacon = match (&self.beacon, self.first_tx) {
            (Some((interval, frame)), Some(first)) if first.elapsed() > *interval => frame.clone(),
            _ => return,
        };
        log::debug!("[{}] transmitting beacon data", self.name);
        self.first_tx = None;
        self.append(&beacon);
    }

    /// Write what the port takes without blocking, and watch for room
    /// exactly while bytes remain.
    fn drain(&mut self) {
        while !self.failed && self.head < self.out.len() {
            let pending = &self.out[self.head..];
            // SAFETY: `pending` is a valid initialized slice; the port is
            // non-blocking (set when it is served).
            let written = unsafe {
                libc::write(
                    self.file.as_raw_fd(),
                    pending.as_ptr().cast(),
                    pending.len(),
                )
            };
            if written < 0 {
                let error = io::Error::last_os_error();
                match error.kind() {
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::WouldBlock => break,
                    _ => {
                        // The reader sees the port fail too and reopens it.
                        log::warn!("[{}] KISS write error: {}", self.name, error);
                        self.failed = true;
                        self.out.clear();
                        self.head = 0;
                        self.held.clear();
                        self.held_bytes = 0;
                        break;
                    }
                }
            }
            if written == 0 {
                break;
            }
            self.head += written as usize;
        }
        if self.head == self.out.len() {
            self.out.clear();
            self.head = 0;
        }
        self.set_writable_interest(self.head < self.out.len());
    }

    /// Interest is one-shot: a delivered writable event disarms it, so
    /// wanting it re-arms on every call.
    fn set_writable_interest(&mut self, want: bool) {
        if !self.registered || (!want && !self.want_writable) {
            return;
        }
        let interest = if want {
            Interest::writable(self.key)
        } else {
            Interest::none(self.key)
        };
        match self.poller.modify(self.file.as_fd(), interest) {
            Ok(()) => self.want_writable = want,
            Err(error) => log::warn!(
                "[{}] cannot update KISS port poll interest: {}",
                self.name,
                error
            ),
        }
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        // The reader holds a duplicate of the descriptor, so closing this
        // one would not end the registration.
        if self.registered {
            let _ = self.poller.delete(self.file.as_fd());
        }
    }
}

/// Writes a KISS port on the driver thread (see the module docs).
pub(super) struct KissLoopWriter {
    port: Arc<Mutex<Port>>,
    ax25_source: Option<Ax25Address>,
}

impl KissLoopWriter {
    fn frame(&self, data: &[u8]) -> Vec<u8> {
        match &self.ax25_source {
            Some(source) => kiss::frame(&super::super::ax25_kiss::encode_ui_frame(source, data)),
            None => kiss::frame(data),
        }
    }

    fn port(&self) -> std::sync::MutexGuard<'_, Port> {
        lock_or_recover(&self.port, "kiss port")
    }
}

fn full() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "KISS port buffer is full")
}

impl Writer for KissLoopWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        let frame = self.frame(data);
        let mut port = self.port();
        port.check()?;
        if !port.fits(frame.len()) {
            return Err(full());
        }
        port.submit(frame);
        Ok(())
    }

    fn enqueue_confirmed(
        &mut self,
        data: &[u8],
        completion: &mut Option<Completion>,
    ) -> io::Result<()> {
        // A confirmed frame is taken only when it is written at once; else
        // WouldBlock leaves the completion untouched and the driver retries.
        let frame = self.frame(data);
        let mut port = self.port();
        port.check()?;
        if !port.sends_now() || !port.fits(frame.len()) {
            return Err(full());
        }
        port.transmit(&frame);
        drop(port);
        if let Some(completion) = completion.take() {
            completion.finish(Ok(()));
        }
        Ok(())
    }

    fn sends_inline(&self) -> bool {
        true
    }

    fn flush_pending(&mut self) {
        self.port().drain();
    }

    fn tick(&mut self) {
        self.port().tick();
    }
}

/// What reading a port on the driver loop needs across reopenings.
pub(super) struct KissLink {
    config: KissIfaceConfig,
    tx: EventSender,
    control: ListenerControl,
}

impl KissLink {
    pub(super) fn new(
        config: KissIfaceConfig,
        tx: EventSender,
        control: ListenerControl,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            tx,
            control,
        })
    }

    /// Serve a configured port on the driver thread from now on: read it
    /// as a loop source and return the writer that writes it. `writer` is
    /// a second handle to the same port.
    pub(super) fn serve(
        self: &Arc<Self>,
        reader: std::fs::File,
        writer: std::fs::File,
    ) -> io::Result<Box<dyn Writer>> {
        // Both handles share one open file, so this makes both non-blocking.
        set_nonblocking(reader.as_raw_fd())?;
        let port = Arc::new(Mutex::new(Port::new(
            writer,
            &self.config,
            Arc::clone(self.tx.poller()),
        )));
        self.tx.register_source(
            crate::interface::loop_writer::read_key(self.config.interface_id),
            Box::new(KissSource {
                reader,
                decoder: kiss::Decoder::new(),
                port: Arc::clone(&port),
                link: Arc::clone(self),
            }),
        )?;
        Ok(Box::new(KissLoopWriter {
            port,
            ax25_source: self.config.ax25_source.clone(),
        }))
    }

    /// Reopen the port on a thread of its own, which exits once the
    /// reopened port is served on the driver.
    pub(super) fn reopen(self: &Arc<Self>) -> io::Result<()> {
        let link = Arc::clone(self);
        thread::Builder::new()
            .name(format!("kiss-reconnect-{}", self.config.interface_id.0))
            .spawn(move || link.reopen_now())?;
        Ok(())
    }

    fn reopen_now(self: &Arc<Self>) {
        let id = self.config.interface_id;
        while let Some((reader, writer)) = reopen_port(&self.config, &self.control) {
            match self.serve(reader, writer) {
                Ok(writer) => {
                    let _ = self.tx.send(Event::InterfaceUp(id, Some(writer), None));
                    log::info!("[{}] KISS port reconnected", self.config.name);
                    return;
                }
                Err(e) => {
                    log::warn!(
                        "[{}] cannot serve the reopened KISS port: {}",
                        self.config.name,
                        e
                    );
                }
            }
        }
    }

    /// Report the port down and reopen it.
    fn connection_lost(self: &Arc<Self>) {
        let _ = self
            .tx
            .push_from_loop([Event::InterfaceDown(self.config.interface_id)]);
        if let Err(e) = self.reopen() {
            log::error!(
                "[{}] cannot start reconnecting, giving up: {}",
                self.config.name,
                e
            );
        }
    }
}

/// A KISS port, read on the driver thread.
struct KissSource {
    reader: std::fs::File,
    decoder: kiss::Decoder,
    port: Arc<Mutex<Port>>,
    link: Arc<KissLink>,
}

enum Read {
    Rearm,
    Suspend,
    Lost(Option<io::Error>),
    DriverGone,
}

impl KissSource {
    fn read(&mut self, cx: &mut LoopContext<'_>) -> Read {
        let link = &self.link;
        if !link.tx.inbound_data_has_room() {
            return Read::Suspend;
        }
        let id = link.config.interface_id;
        let ax25 = link.config.ax25_source.is_some();
        let mut read = 0;
        while read < STREAM_READ_BUDGET {
            // SAFETY: `cx.buf` is a valid writable buffer for the call; the
            // port is non-blocking.
            let n = unsafe {
                libc::read(
                    self.reader.as_raw_fd(),
                    cx.buf.as_mut_ptr().cast(),
                    cx.buf.len(),
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::WouldBlock => return Read::Rearm,
                    io::ErrorKind::Interrupted => continue,
                    _ => return Read::Lost(Some(e)),
                }
            }
            if n == 0 {
                return Read::Lost(None);
            }
            let n = n as usize;
            read += n;
            let mut frames = Vec::new();
            for event in self.decoder.feed(&cx.buf[..n]) {
                match event {
                    kiss::KissEvent::DataFrame(data) => {
                        let data = if ax25 {
                            match super::super::ax25_kiss::decode_ui_frame(&data) {
                                Some(payload) => payload.to_vec(),
                                None => continue,
                            }
                        } else {
                            data
                        };
                        frames.push(Event::Frame {
                            interface_id: id,
                            data: data.into(),
                            rssi: None,
                            snr: None,
                        });
                    }
                    kiss::KissEvent::Ready => lock_or_recover(&self.port, "kiss port").tnc_ready(),
                }
            }
            match link.tx.push_from_loop(frames) {
                Ok(true) => {}
                Ok(false) => return Read::Suspend,
                Err(_) => return Read::DriverGone,
            }
            if n < cx.buf.len() {
                break;
            }
        }
        Read::Rearm
    }
}

impl LoopSource for KissSource {
    fn fd(&self) -> std::os::fd::RawFd {
        self.reader.as_raw_fd()
    }

    fn stopped(&self) -> bool {
        self.link.control.should_stop()
    }

    fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
        if self.link.control.should_stop() {
            return SourceStatus::Remove;
        }
        match self.read(cx) {
            Read::Rearm => SourceStatus::Rearm,
            Read::Suspend => SourceStatus::Suspend,
            Read::Lost(error) => {
                let name = &self.link.config.name;
                match error {
                    Some(e) => log::warn!("[{}] KISS read error: {}", name, e),
                    None => log::warn!("[{}] KISS port closed", name),
                }
                self.link.connection_lost();
                SourceStatus::Remove
            }
            Read::DriverGone => SourceStatus::Remove,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serial::open_pty_pair;
    use std::io::Read;
    use std::os::unix::io::FromRawFd;

    fn port(config: &KissIfaceConfig) -> (Port, std::fs::File) {
        let (master_fd, slave_fd) = open_pty_pair().unwrap();
        set_nonblocking(slave_fd).unwrap();
        let slave = unsafe { std::fs::File::from_raw_fd(slave_fd) };
        let master = unsafe { std::fs::File::from_raw_fd(master_fd) };
        (
            Port::new(slave, config, Arc::new(Poller::new().unwrap())),
            master,
        )
    }

    fn read_frames(master: &mut std::fs::File) -> Vec<Vec<u8>> {
        let mut decoder = kiss::Decoder::new();
        let mut frames = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let mut pfd = libc::pollfd {
                fd: master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut pfd, 1, 200) } <= 0 {
                return frames;
            }
            let n = master.read(&mut buf).unwrap();
            for event in decoder.feed(&buf[..n]) {
                if let kiss::KissEvent::DataFrame(data) = event {
                    frames.push(data);
                }
            }
        }
    }

    #[test]
    fn tick_unlocks_a_tnc_that_never_reports_ready() {
        let config = KissIfaceConfig {
            flow_control: true,
            ..Default::default()
        };
        let (mut port, mut master) = port(&config);
        port.submit(kiss::frame(b"one"));
        port.submit(kiss::frame(b"two"));
        assert_eq!(read_frames(&mut master), vec![b"one".to_vec()]);
        port.tick();
        assert!(read_frames(&mut master).is_empty());
        port.lock_time -= FLOW_TIMEOUT + Duration::from_secs(1);
        port.tick();
        assert_eq!(read_frames(&mut master), vec![b"two".to_vec()]);
        assert!(!port.ready);
    }

    #[test]
    fn tick_sends_the_beacon_once_after_data() {
        let config = KissIfaceConfig {
            beacon_interval: Some(0),
            beacon_data: Some(b"N0CALL".to_vec()),
            ..Default::default()
        };
        let (mut port, mut master) = port(&config);
        port.tick();
        assert!(read_frames(&mut master).is_empty());
        port.submit(kiss::frame(b"data"));
        std::thread::sleep(Duration::from_millis(5));
        port.tick();
        port.tick();
        let mut beacon = b"N0CALL".to_vec();
        beacon.resize(BEACON_MIN_LEN, 0);
        assert_eq!(read_frames(&mut master), vec![b"data".to_vec(), beacon]);
    }

    #[test]
    fn a_full_port_refuses_frames_and_holds_none_past_the_limit() {
        let config = KissIfaceConfig {
            flow_control: true,
            ..Default::default()
        };
        let (port, _master) = port(&config);
        let port = Arc::new(Mutex::new(port));
        let mut writer = KissLoopWriter {
            port: Arc::clone(&port),
            ax25_source: None,
        };
        writer.send_frame(&[1; 1000]).unwrap();
        let mut refused = false;
        for _ in 0..200 {
            if let Err(e) = writer.send_frame(&[2; 1000]) {
                assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
                refused = true;
                break;
            }
        }
        assert!(refused);
        assert!(port.lock().unwrap().buffered() <= BUFFER_LIMIT);
        // A confirmed frame waits for the TNC rather than joining the queue.
        let mut completion = None;
        assert_eq!(
            writer
                .enqueue_confirmed(b"confirmed", &mut completion)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
