//! The shared-instance server on the driver loop.
//!
//! With interface I/O folded (see [`crate::engine::FOLD_IO`]) the listening
//! socket and each client connection are loop sources, read on the driver
//! thread, and each client's writer is written by the driver directly (see
//! `loop_writer`), as the TCP server's clients are. No thread is started.
//!
//! Where clients may sleep (Android), a client's writer has to drop frames
//! while the client is paused, which a driver-written socket cannot do, so
//! there the writer keeps its worker thread; reading is folded either way.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rns_core::transport::types::InterfaceId;

use super::{
    android_client_sleep_hold, frame_decoder, make_local_interface_info, ClientSleepHold,
    LocalWriter,
};
use crate::event::{Event, EventSender, LoopContext, LoopSource, SourceStatus};
use crate::hdlc;
use crate::interface::stream_read::{
    accept_error_step, read_stream_frames, AcceptStep, StreamRead,
};
use crate::interface::transmit_buffer::TransmitBuffer;
use crate::interface::{ListenerControl, Writer};

/// Connections accepted per readiness before other sources get a turn.
const ACCEPT_BURST: usize = 64;

pub(super) enum Listener {
    Tcp(TcpListener),
    #[cfg(target_os = "linux")]
    Unix(std::os::unix::net::UnixListener),
}

impl Listener {
    fn accept(&self) -> io::Result<Stream> {
        match self {
            Listener::Tcp(listener) => {
                let (stream, _) = listener.accept()?;
                if let Err(e) = stream.set_nodelay(true) {
                    log::warn!("Local server set_nodelay failed: {}", e);
                }
                Ok(Stream::Tcp(stream))
            }
            #[cfg(target_os = "linux")]
            Listener::Unix(listener) => listener.accept().map(|(stream, _)| Stream::Unix(stream)),
        }
    }
}

impl AsRawFd for Listener {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Listener::Tcp(listener) => listener.as_raw_fd(),
            #[cfg(target_os = "linux")]
            Listener::Unix(listener) => listener.as_raw_fd(),
        }
    }
}

enum Stream {
    Tcp(TcpStream),
    #[cfg(target_os = "linux")]
    Unix(std::os::unix::net::UnixStream),
}

impl Stream {
    fn try_clone(&self) -> io::Result<Self> {
        match self {
            Stream::Tcp(stream) => stream.try_clone().map(Stream::Tcp),
            #[cfg(target_os = "linux")]
            Stream::Unix(stream) => stream.try_clone().map(Stream::Unix),
        }
    }

    /// The writer for a client that may sleep: framed and written on a
    /// worker thread, which drops frames while the client is paused.
    fn sleeping_writer(self, sleep_hold: ClientSleepHold) -> Box<dyn Writer> {
        match self {
            Stream::Tcp(stream) => Box::new(LocalWriter {
                stream,
                sleep_hold: Some(sleep_hold),
                transmit_buffer: TransmitBuffer::new(),
            }),
            #[cfg(target_os = "linux")]
            Stream::Unix(stream) => Box::new(super::UnixLocalWriter {
                stream,
                sleep_hold: Some(sleep_hold),
                transmit_buffer: TransmitBuffer::new(),
            }),
        }
    }
}

impl AsRawFd for Stream {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Stream::Tcp(stream) => stream.as_raw_fd(),
            #[cfg(target_os = "linux")]
            Stream::Unix(stream) => stream.as_raw_fd(),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(stream) => stream.write(buf),
            #[cfg(target_os = "linux")]
            Stream::Unix(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(stream) => stream.read(buf),
            #[cfg(target_os = "linux")]
            Stream::Unix(stream) => stream.read(buf),
        }
    }
}

/// HDLC writer for a client connection the driver writes directly.
struct ClientWriter {
    stream: Stream,
    /// Reused encoding buffer for coalesced writes.
    scratch: Vec<u8>,
}

impl Writer for ClientWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(&hdlc::frame(data))
    }

    fn send_frames(&mut self, frames: &[crate::interface::FrameBytes]) -> io::Result<()> {
        hdlc::write_frames(&mut self.stream, frames, &mut self.scratch)
    }

    fn loop_socket(&self) -> Option<RawFd> {
        Some(self.stream.as_raw_fd())
    }
}

/// Serve `listener` on the driver loop under `key` from now on.
pub(super) fn serve(
    listener: Listener,
    key: usize,
    name: String,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
    control: ListenerControl,
    dynamic_template: Option<crate::interface::DynamicInterfaceTemplate>,
) -> io::Result<()> {
    let ifac_size = super::template_ifac_size(dynamic_template.as_ref());
    tx.register_source(
        key,
        Box::new(ListenerSource {
            listener,
            name,
            tx: tx.clone(),
            next_id,
            control,
            dynamic_template,
            ifac_size,
        }),
    )
}

/// The listening socket: accepts clients, registers them with the driver
/// and adds a source per client.
struct ListenerSource {
    listener: Listener,
    name: String,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
    control: ListenerControl,
    dynamic_template: Option<crate::interface::DynamicInterfaceTemplate>,
    ifac_size: usize,
}

impl LoopSource for ListenerSource {
    fn fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }

    fn stopped(&self) -> bool {
        self.control.should_stop()
    }

    fn on_removed(&mut self) {
        log::info!("[{}] Local listener stopping", self.name);
    }

    fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
        if self.control.should_stop() {
            return SourceStatus::Remove;
        }
        for _ in 0..ACCEPT_BURST {
            let stream = match self.listener.accept() {
                Ok(stream) => stream,
                Err(e) => match accept_error_step(&e) {
                    AcceptStep::Drained => break,
                    AcceptStep::Next => {
                        log::debug!("[{}] Local server accept failed: {}", self.name, e);
                        continue;
                    }
                    AcceptStep::Pause => {
                        log::warn!(
                            "[{}] Local server accept failed: {}; accepting resumes on the next tick",
                            self.name,
                            e
                        );
                        return SourceStatus::Pause;
                    }
                },
            };
            match self.admit(stream) {
                Admitted::Client(id, source) => {
                    cx.add_source(crate::interface::loop_writer::read_key(id), source)
                }
                Admitted::Rejected => {}
                Admitted::DriverGone => return SourceStatus::Remove,
            }
        }
        SourceStatus::Rearm
    }
}

enum Admitted {
    Client(InterfaceId, Box<dyn LoopSource>),
    Rejected,
    DriverGone,
}

impl ListenerSource {
    fn admit(&self, stream: Stream) -> Admitted {
        let writer_stream = match stream.try_clone() {
            Ok(stream) => stream,
            Err(e) => {
                log::warn!("Local server clone failed: {}", e);
                return Admitted::Rejected;
            }
        };
        let client_id = InterfaceId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let sleep_hold = android_client_sleep_hold();
        let writer: Box<dyn Writer> = match &sleep_hold {
            Some(hold) => writer_stream.sleeping_writer(hold.clone()),
            None => Box::new(ClientWriter {
                stream: writer_stream,
                scratch: Vec::new(),
            }),
        };
        let info = make_local_interface_info(client_id);
        // Register the client with the driver before any of its frames: the
        // queue never delivers a frame ahead of an older control event.
        let registration = if let Some(template) = &self.dynamic_template {
            Event::DynamicInterfaceUp {
                id: client_id,
                writer,
                registration: Box::new(template.registration(info)),
            }
        } else {
            Event::InterfaceUp(client_id, Some(writer), Some(Box::new(info)))
        };
        if self.tx.push_from_loop([registration]).is_err() {
            return Admitted::DriverGone;
        }
        Admitted::Client(
            client_id,
            Box::new(ClientSource {
                stream,
                id: client_id,
                tx: self.tx.clone(),
                decoder: frame_decoder(self.ifac_size),
                sleep_hold,
            }),
        )
    }
}

/// One connected client. Unlike the listener it is not stopped by the
/// server's control: as with the reader threads, a client is served until
/// it disconnects, also while the node drains.
struct ClientSource {
    stream: Stream,
    id: InterfaceId,
    tx: EventSender,
    decoder: hdlc::Decoder,
    sleep_hold: Option<ClientSleepHold>,
}

impl LoopSource for ClientSource {
    fn fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    fn on_abandoned(&mut self) {
        // The driver was told about this client; it will never be read.
        let _ = self.tx.push_from_loop([Event::InterfaceDown(self.id)]);
    }

    fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
        let sleep_hold = &self.sleep_hold;
        match read_stream_frames(
            self.stream.as_raw_fd(),
            &mut self.decoder,
            cx,
            &self.tx,
            self.id,
            "LocalInterface",
            |_, _| {
                if let Some(hold) = sleep_hold {
                    hold.refresh();
                }
            },
        ) {
            StreamRead::Rearm => SourceStatus::Rearm,
            StreamRead::Suspend => SourceStatus::Suspend,
            StreamRead::Closed => {
                log::info!("Local client {} disconnected", self.id.0);
                let _ = self.tx.push_from_loop([Event::InterfaceDown(self.id)]);
                SourceStatus::Remove
            }
            StreamRead::Failed(e) => {
                log::warn!("Local client {} read error: {}", self.id.0, e);
                let _ = self.tx.push_from_loop([Event::InterfaceDown(self.id)]);
                SourceStatus::Remove
            }
            StreamRead::DriverGone => SourceStatus::Remove,
        }
    }
}
