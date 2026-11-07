//! What the supervisor loop sleeps on between passes.
//!
//! The loop waits until something needs it: a stop signal, a control
//! command, a child exiting, or the next readiness probe. Signals and
//! commands write a byte to a pipe; child exits are watched through pidfds,
//! which become readable when the process exits without reaping it, so the
//! loop's `try_wait` still collects the status.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Written by a stop signal: SIGINT or SIGTERM.
const STOP: u8 = b'S';
/// Written when there is a control command to handle.
const WORK: u8 = b'W';

/// The write end of the latest run's pipe, for the signal handler; -1 when
/// none. As with a stop channel, the latest run is the one stopped.
static STOP_FD: AtomicI32 = AtomicI32::new(-1);

/// A run's wake pipe.
pub(crate) struct Wake {
    read: OwnedFd,
    write: Arc<OwnedFd>,
}

/// Wakes a run's loop from another thread.
#[derive(Clone)]
pub(crate) struct Waker(Arc<OwnedFd>);

impl Waker {
    pub(crate) fn wake(&self) {
        write_byte(self.0.as_raw_fd(), WORK);
    }
}

fn write_byte(fd: RawFd, byte: u8) {
    // SAFETY: one byte from a valid buffer. `write` is async-signal-safe;
    // the pipe is non-blocking, so a full pipe (already waking the loop)
    // drops the byte instead of blocking.
    unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
}

extern "C" fn stop_handler(_sig: libc::c_int) {
    request_stop();
}

/// Ask the latest run to stop, as SIGINT and SIGTERM do.
pub(crate) fn request_stop() {
    let fd = STOP_FD.load(Ordering::SeqCst);
    if fd >= 0 {
        write_byte(fd, STOP);
    }
}

impl Wake {
    pub(crate) fn new() -> io::Result<Self> {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` has room for the two descriptors.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both descriptors were just opened and are owned here.
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        for fd in [read.as_raw_fd(), write.as_raw_fd()] {
            // SAFETY: valid descriptors; children must not inherit them.
            unsafe {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                let flags = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        Ok(Self {
            read,
            write: Arc::new(write),
        })
    }

    /// Route SIGINT and SIGTERM to this run.
    pub(crate) fn install_signal_handlers(&self) {
        STOP_FD.store(self.write.as_raw_fd(), Ordering::SeqCst);
        // SAFETY: the handler only performs async-signal-safe calls.
        unsafe {
            libc::signal(
                libc::SIGINT,
                stop_handler as *const () as libc::sighandler_t,
            );
            libc::signal(
                libc::SIGTERM,
                stop_handler as *const () as libc::sighandler_t,
            );
        }
    }

    pub(crate) fn waker(&self) -> Waker {
        Waker(Arc::clone(&self.write))
    }

    /// Sleep until woken, until one of `exits` (pidfds) is readable, or for
    /// at most `timeout`. Returns whether a stop was requested.
    pub(crate) fn wait(&self, exits: &[RawFd], timeout: Duration) -> bool {
        let mut fds = Vec::with_capacity(1 + exits.len());
        fds.push(libc::pollfd {
            fd: self.read.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        fds.extend(exits.iter().map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        }));
        let timeout_ms = i32::try_from(timeout.as_millis().max(1)).unwrap_or(i32::MAX);
        // SAFETY: `fds` holds valid pollfds for the duration of the call. An
        // interrupted wait (a signal) returns at once, and the pipe is read
        // below either way.
        unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
        let mut stop = false;
        let mut buf = [0u8; 64];
        loop {
            // SAFETY: reading into a valid buffer; the pipe is non-blocking.
            let n =
                unsafe { libc::read(self.read.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            stop |= buf[..n as usize].contains(&STOP);
        }
        stop
    }
}

impl Drop for Wake {
    fn drop(&mut self) {
        let _ = STOP_FD.compare_exchange(
            self.write.as_raw_fd(),
            -1,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }
}

/// A descriptor that becomes readable when process `pid` exits, if the
/// platform has one.
pub(crate) fn exit_watch(pid: u32) -> Option<OwnedFd> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: pidfd_open takes a pid and flags and returns a new
        // descriptor or -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if fd < 0 {
            return None;
        }
        // SAFETY: a new descriptor owned from here on.
        let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
        // SAFETY: a valid descriptor; children must not inherit it.
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
        Some(fd)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}
