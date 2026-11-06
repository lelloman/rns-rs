use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::io::AsRawFd;

use crate::serial::SerialConfig;
use crate::serial::SerialPort;

const DEFAULT_PORT: u32 = 7633;

#[derive(Debug)]
pub enum Transport {
    Serial(std::fs::File),
    Tcp(TcpStream),
}

impl Transport {
    pub fn open(
        config: &SerialConfig,
        underlay_mark: Option<u32>,
    ) -> io::Result<(Transport, Transport)> {
        if let Some(addr) = config.path.strip_prefix("tcp:") {
            let addr = if addr.contains(':') {
                addr.to_string()
            } else {
                format!("{}:{}", addr, DEFAULT_PORT)
            };

            let address = addr
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| io::Error::other("RNode TCP address did not resolve"))?;
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(address),
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;
            crate::interface::apply_underlay_mark(socket.as_raw_fd(), underlay_mark)?;
            socket.connect(&address.into())?;
            let stream: TcpStream = socket.into();
            let reader = stream.try_clone()?;
            Ok((Transport::Tcp(reader), Transport::Tcp(stream)))
        } else {
            let port = SerialPort::open(config)?;
            Ok((
                Transport::Serial(port.reader()?),
                Transport::Serial(port.writer()?),
            ))
        }
    }

    pub fn open_from_fd(fd: i32) -> io::Result<(Transport, Transport)> {
        let port = SerialPort::from_raw_fd(fd);
        let reader = port.reader()?;
        let writer = port.writer()?;
        std::mem::forget(port);
        Ok((Transport::Serial(reader), Transport::Serial(writer)))
    }
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Transport::Serial(f) => f.read(buf),
            Transport::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Transport::Serial(f) => f.write(buf),
            Transport::Tcp(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Transport::Serial(f) => f.flush(),
            Transport::Tcp(s) => s.flush(),
        }
    }
}

impl AsRawFd for Transport {
    fn as_raw_fd(&self) -> i32 {
        match self {
            Transport::Serial(f) => f.as_raw_fd(),
            Transport::Tcp(s) => s.as_raw_fd(),
        }
    }
}

/// Bytes the device writer holds unwritten on the driver loop before new
/// frames are refused: about what a threaded writer's queue holds, so
/// frames do not wait minutes behind a backlog on a slow radio.
const DRIVEN_BUFFER_LIMIT: usize = 128 * 1024;

/// The write side of an RNode connection, shared by the subinterfaces'
/// writers, the reader (flow control, keepalive) and runtime reconfiguring.
///
/// Normally it writes straight to the transport. On the compact engine's
/// driver loop (see [`crate::engine::FOLD_IO`]) it is *driven*: writes are
/// buffered and written without blocking, and the rest is written when the
/// driver reports the transport writable (see [`DeviceWriter::drain`]).
pub struct DeviceWriter {
    transport: Transport,
    driven: Option<Driven>,
}

struct Driven {
    poller: std::sync::Arc<crate::poll::Poller>,
    key: usize,
    name: String,
    registered: bool,
    want_writable: bool,
    out: Vec<u8>,
    head: usize,
    failed: bool,
}

impl std::fmt::Debug for DeviceWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceWriter")
            .field("transport", &self.transport)
            .field("driven", &self.driven.is_some())
            .finish()
    }
}

impl DeviceWriter {
    /// A writer that writes straight to `transport`.
    pub fn new(transport: Transport) -> Self {
        Self {
            transport,
            driven: None,
        }
    }

    /// A writer driven by the driver loop whose poller is `poller`, with
    /// writable interest under `key`.
    pub(crate) fn driven(
        transport: Transport,
        poller: std::sync::Arc<crate::poll::Poller>,
        key: usize,
        name: &str,
    ) -> Self {
        let mut writer = Self {
            transport,
            driven: Some(Driven {
                poller,
                key,
                name: name.to_string(),
                registered: false,
                want_writable: false,
                out: Vec::new(),
                head: 0,
                failed: false,
            }),
        };
        writer.register();
        writer
    }

    fn register(&mut self) {
        let fd = self.transport.as_raw_fd();
        let Some(driven) = &mut self.driven else {
            return;
        };
        // SAFETY: the transport is kept open until `unregister` (called on
        // replacement and in `Drop`) removes the registration.
        match unsafe { driven.poller.add(fd, crate::poll::Event::none(driven.key)) } {
            Ok(()) => driven.registered = true,
            Err(error) => log::warn!(
                "[{}] cannot register the RNode writer with the driver poller: {}",
                driven.name,
                error
            ),
        }
        driven.want_writable = false;
    }

    fn unregister(&mut self) {
        let fd = self.transport.as_raw_fd();
        if let Some(driven) = &mut self.driven {
            if driven.registered {
                // SAFETY: the descriptor is open; it is only borrowed here.
                let source = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
                let _ = driven.poller.delete(source);
                driven.registered = false;
            }
        }
    }

    /// Write to a reopened connection from now on, dropping whatever was
    /// left unwritten on the old one.
    pub(crate) fn replace(&mut self, transport: Transport) {
        self.unregister();
        self.transport = transport;
        if let Some(driven) = &mut self.driven {
            driven.out.clear();
            driven.head = 0;
            driven.failed = false;
        }
        self.register();
    }

    /// Whether `bytes` more would be taken now. Always true when not driven.
    pub(crate) fn fits(&self, bytes: usize) -> bool {
        match &self.driven {
            None => true,
            Some(driven) => {
                let buffered = driven.out.len() - driven.head;
                !driven.failed && (buffered == 0 || buffered + bytes <= DRIVEN_BUFFER_LIMIT)
            }
        }
    }

    /// Write what the transport takes without blocking, and watch for room
    /// exactly while bytes remain. Does nothing when not driven.
    pub(crate) fn drain(&mut self) {
        let fd = self.transport.as_raw_fd();
        let Some(driven) = &mut self.driven else {
            return;
        };
        while !driven.failed && driven.head < driven.out.len() {
            let pending = &driven.out[driven.head..];
            // SAFETY: `pending` is a valid initialized slice.
            let written = unsafe { libc::write(fd, pending.as_ptr().cast(), pending.len()) };
            if written < 0 {
                let error = io::Error::last_os_error();
                match error.kind() {
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::WouldBlock => break,
                    _ => {
                        // The reader sees the connection fail too and
                        // reopens it.
                        log::warn!("[{}] RNode write error: {}", driven.name, error);
                        driven.failed = true;
                        driven.out.clear();
                        driven.head = 0;
                        break;
                    }
                }
            }
            if written == 0 {
                break;
            }
            driven.head += written as usize;
        }
        if driven.head == driven.out.len() {
            driven.out.clear();
            driven.head = 0;
        }
        let want = driven.head < driven.out.len();
        // Interest is one-shot: a delivered writable event disarms it, so
        // wanting it re-arms on every call.
        if driven.registered && (want || driven.want_writable) {
            let interest = if want {
                crate::poll::Event::writable(driven.key)
            } else {
                crate::poll::Event::none(driven.key)
            };
            // SAFETY: the descriptor is open; it is only borrowed here.
            let source = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
            match driven.poller.modify(source, interest) {
                Ok(()) => driven.want_writable = want,
                Err(error) => log::warn!(
                    "[{}] cannot update RNode writer poll interest: {}",
                    driven.name,
                    error
                ),
            }
        }
    }
}

impl Write for DeviceWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.driven.is_none() {
            return self.transport.write(buf);
        }
        if !self.fits(buf.len()) {
            let failed = self.driven.as_ref().is_some_and(|driven| driven.failed);
            return Err(if failed {
                io::Error::new(io::ErrorKind::BrokenPipe, "RNode connection is offline")
            } else {
                io::Error::new(io::ErrorKind::WouldBlock, "RNode writer buffer is full")
            });
        }
        if let Some(driven) = &mut self.driven {
            driven.out.extend_from_slice(buf);
        }
        self.drain();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.driven {
            None => self.transport.flush(),
            Some(_) => Ok(()),
        }
    }
}

impl Drop for DeviceWriter {
    fn drop(&mut self) {
        // The reader holds a duplicate of the descriptor, so closing this
        // one would not end the registration.
        self.unregister();
    }
}
