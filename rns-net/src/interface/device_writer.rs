//! A device writer that several interface writers share, run by the
//! driver on the compact engine (see [`DeviceWriter`]).

use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};

/// Bytes a driven writer holds unwritten before new frames are refused:
/// about what a threaded writer's queue holds, so frames do not wait
/// minutes behind a backlog on a slow line.
const DRIVEN_BUFFER_LIMIT: usize = 128 * 1024;

/// The write side of a device connection that several writers share, such
/// as an RNode's (its subinterfaces' writers, its reader's flow control and
/// keepalive, runtime reconfiguring) or a Weave device's (its peers).
///
/// Normally it writes straight to the transport. On the compact engine's
/// driver loop (see [`crate::engine::FOLD_IO`]) it is *driven*: writes are
/// buffered and written without blocking, and the rest is written when the
/// driver reports the transport writable (see [`DeviceWriter::drain`]).
pub struct DeviceWriter<T> {
    transport: T,
    driven: Option<Driven>,
}

struct Driven {
    poller: std::sync::Arc<crate::poll::Poller>,
    /// The descriptor registered with the poller, while `registered`.
    fd: RawFd,
    key: usize,
    name: String,
    registered: bool,
    want_writable: bool,
    out: Vec<u8>,
    head: usize,
    failed: bool,
}

impl<T: std::fmt::Debug> std::fmt::Debug for DeviceWriter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceWriter")
            .field("transport", &self.transport)
            .field("driven", &self.driven.is_some())
            .finish()
    }
}

impl<T: Write + AsRawFd> DeviceWriter<T> {
    /// A writer that writes straight to `transport`.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            driven: None,
        }
    }

    /// A writer driven by the driver loop whose poller is `poller`, with
    /// writable interest under `key`.
    pub(crate) fn driven(
        transport: T,
        poller: std::sync::Arc<crate::poll::Poller>,
        key: usize,
        name: &str,
    ) -> Self {
        let mut writer = Self {
            transport,
            driven: Some(Driven {
                poller,
                key,
                fd: -1,
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
            Ok(()) => {
                driven.registered = true;
                driven.fd = fd;
            }
            Err(error) => log::warn!(
                "[{}] cannot register the device writer with the driver poller: {}",
                driven.name,
                error
            ),
        }
        driven.want_writable = false;
    }

    /// Write to a reopened connection from now on, dropping whatever was
    /// left unwritten on the old one.
    pub(crate) fn replace(&mut self, transport: T) {
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
                        log::warn!("[{}] device write error: {}", driven.name, error);
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
                    "[{}] cannot update device writer poll interest: {}",
                    driven.name,
                    error
                ),
            }
        }
    }
}

impl<T: Write + AsRawFd> Write for DeviceWriter<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.driven.is_none() {
            return self.transport.write(buf);
        }
        if !self.fits(buf.len()) {
            let failed = self.driven.as_ref().is_some_and(|driven| driven.failed);
            return Err(if failed {
                io::Error::new(io::ErrorKind::BrokenPipe, "the device is offline")
            } else {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "the device writer buffer is full",
                )
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

impl<T> DeviceWriter<T> {
    fn unregister(&mut self) {
        if let Some(driven) = &mut self.driven {
            if driven.registered {
                // SAFETY: the descriptor is still open: the transport owning
                // it is replaced or dropped only after this.
                let source = unsafe { std::os::fd::BorrowedFd::borrow_raw(driven.fd) };
                let _ = driven.poller.delete(source);
                driven.registered = false;
            }
        }
    }
}

impl<T> Drop for DeviceWriter<T> {
    fn drop(&mut self) {
        // The reader holds a duplicate of the descriptor, so closing this
        // one would not end the registration.
        self.unregister();
    }
}
