//! The compact engine's tick on Linux and Android: a periodic timerfd watched
//! by the driver's poller. The driver then waits without a timeout, as it
//! did with a timer thread; a timed wait would arm and cancel a kernel timer
//! on every wait, which a busy endpoint does thousands of times a second.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::event::{Event, EventSender, LoopContext, LoopSource, SourceStatus};

/// The tick source's key among the driver's loop sources. Interface sources
/// use an interface id shifted left by one, so the top of the range is free.
pub(crate) const TICK_SOURCE_KEY: usize = usize::MAX - 1;

pub(crate) struct TickSource {
    timer: OwnedFd,
    tx: EventSender,
    interval_ms: Arc<AtomicU64>,
    armed_ms: u64,
}

impl TickSource {
    pub(crate) fn new(tx: EventSender, interval_ms: Arc<AtomicU64>) -> std::io::Result<Self> {
        // SAFETY: plain syscall; the descriptor is owned below.
        let fd = unsafe {
            libc::timerfd_create(
                libc::CLOCK_MONOTONIC,
                libc::TFD_NONBLOCK | libc::TFD_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` was just created and is owned by nothing else.
        let timer = unsafe { OwnedFd::from_raw_fd(fd) };
        let ms = interval_ms.load(Ordering::Relaxed).max(1);
        let source = TickSource {
            timer,
            tx,
            interval_ms,
            armed_ms: ms,
        };
        source.arm(ms)?;
        Ok(source)
    }

    /// Fire every `ms` milliseconds from now on.
    fn arm(&self, ms: u64) -> std::io::Result<()> {
        let period = libc::timespec {
            tv_sec: (ms / 1000) as libc::time_t,
            tv_nsec: ((ms % 1000) * 1_000_000) as libc::c_long,
        };
        let spec = libc::itimerspec {
            it_interval: period,
            it_value: period,
        };
        // SAFETY: valid descriptor and specification; the old value is not read.
        let rc = unsafe {
            libc::timerfd_settime(self.timer.as_raw_fd(), 0, &spec, std::ptr::null_mut())
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

impl LoopSource for TickSource {
    fn fd(&self) -> RawFd {
        self.timer.as_raw_fd()
    }

    fn on_ready(&mut self, _cx: &mut LoopContext<'_>) -> SourceStatus {
        // Consume the expiration count; ticks missed while the driver was
        // busy collapse into one, as a sleeping timer thread's would.
        let mut expirations = [0u8; 8];
        // SAFETY: reads at most 8 bytes into a buffer of 8.
        let _ = unsafe {
            libc::read(
                self.timer.as_raw_fd(),
                expirations.as_mut_ptr().cast(),
                expirations.len(),
            )
        };
        let ms = self.interval_ms.load(Ordering::Relaxed).max(1);
        if ms != self.armed_ms && self.arm(ms).is_ok() {
            self.armed_ms = ms;
        }
        match self.tx.push_from_loop([Event::Tick]) {
            Ok(_) => SourceStatus::Rearm,
            Err(_) => SourceStatus::Remove,
        }
    }
}
