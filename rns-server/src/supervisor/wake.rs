//! What the supervisor loop sleeps on between passes.
//!
//! The loop waits until something needs it: a stop signal, a control
//! command, a child exiting, or the next readiness probe. Signals and
//! commands write a byte to a pipe; child exits are watched through pidfds,
//! which become readable when the process exits without reaping it, so the
//! loop's `try_wait` still collects the status.

#![allow(unsafe_code, reason = "poll and pidfd_open through libc")]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use rns_cli::signals::{PipeWriter, SignalPipe, SIGINT, SIGTERM};

/// Written by a stop signal: SIGINT or SIGTERM.
const STOP: u8 = b'S';
/// Written when there is a control command to handle.
const WORK: u8 = b'W';

/// A run's wake pipe.
pub(crate) struct Wake(SignalPipe);

/// Wakes a run's loop from another thread.
#[derive(Clone)]
pub(crate) struct Waker(PipeWriter);

impl Waker {
    pub(crate) fn wake(&self) {
        self.0.write(WORK);
    }
}

/// Ask the latest run to stop, as SIGINT and SIGTERM do.
#[cfg(test)]
pub(crate) fn request_stop() {
    rns_cli::signals::notify_routed_pipe();
}

impl Wake {
    pub(crate) fn new() -> io::Result<Self> {
        SignalPipe::new(true).map(Self)
    }

    /// Route SIGINT and SIGTERM to this run. As with a stop channel, the
    /// latest run is the one stopped.
    pub(crate) fn install_signal_handlers(&self) {
        self.0.route(&[SIGINT, SIGTERM], STOP);
    }

    pub(crate) fn waker(&self) -> Waker {
        Waker(self.0.writer())
    }

    /// Sleep until woken, until one of `exits` (pidfds) is readable, or for
    /// at most `timeout`. Returns whether a stop was requested.
    pub(crate) fn wait(&self, exits: &[RawFd], timeout: Duration) -> bool {
        let mut fds = Vec::with_capacity(1 + exits.len());
        fds.push(libc::pollfd {
            fd: self.0.read_fd(),
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
        self.0.drain_contains(STOP)
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
