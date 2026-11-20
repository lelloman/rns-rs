//! Stop handle for an interface's threads, and waits that honor it.

#[cfg(any(feature = "iface-serial", feature = "iface-kiss"))]
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(any(
    feature = "iface-tcp",
    feature = "iface-serial",
    feature = "iface-kiss",
    feature = "iface-backbone"
))]
use std::thread;
#[cfg(any(
    feature = "iface-tcp",
    feature = "iface-serial",
    feature = "iface-kiss",
    feature = "iface-backbone"
))]
use std::time::{Duration, Instant};

/// Stop handle shared between the driver and an interface's background threads.
#[derive(Clone, Default)]
pub struct ListenerControl {
    stop: Arc<AtomicBool>,
    running: Option<Arc<AtomicBool>>,
    /// Wakes the listener thread blocked waiting for a connection.
    wake: Arc<std::sync::OnceLock<crate::listen::ListenerWake>>,
    /// Run once the interface's last frame is out: on shutdown after the
    /// final flush, or when the interface is detached.
    on_finish: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl ListenerControl {
    /// Create a control with no stop requested.
    pub fn new() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            running: None,
            wake: Arc::default(),
            on_finish: None,
        }
    }

    #[cfg(any(feature = "iface-auto", feature = "iface-rnode"))]
    pub(crate) fn with_running_flag(running: Arc<AtomicBool>) -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            running: Some(running),
            wake: Arc::default(),
            on_finish: None,
        }
    }

    /// Run `finish` from [`Self::finish`].
    #[cfg(feature = "iface-rnode")]
    pub(crate) fn with_on_finish(mut self, finish: impl Fn() + Send + Sync + 'static) -> Self {
        self.on_finish = Some(Arc::new(finish));
        self
    }

    /// The interface has sent its last frame: run its finishing step, such
    /// as telling a device the host is leaving.
    pub(crate) fn finish(&self) {
        if let Some(finish) = &self.on_finish {
            finish();
        }
    }

    /// Ask the interface's threads to stop and wake a waiting listener.
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(running) = &self.running {
            running.store(false, Ordering::Relaxed);
        }
        if let Some(wake) = self.wake.get() {
            wake.wake();
        }
    }

    /// Let [`Self::request_stop`] wake the listener thread's wait.
    #[cfg(feature = "iface-local")]
    pub(crate) fn set_wake(&self, wake: crate::listen::ListenerWake) {
        let _ = self.wake.set(wake);
        // A stop requested before the wake was known is seen by the
        // listener's own check before it first waits.
    }

    /// Whether a stop has been requested.
    pub fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    pub(crate) fn same_instance(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.stop, &other.stop)
    }
}

/// Wait for serial input without keeping a detached reader blocked forever.
#[cfg(any(feature = "iface-serial", feature = "iface-kiss"))]
pub(crate) fn poll_readable(fd: std::os::fd::RawFd, timeout: Duration) -> io::Result<bool> {
    let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    let revents = match crate::sys::poll_in(fd, timeout_ms) {
        Ok(revents) => revents,
        Err(error) if error.kind() == io::ErrorKind::Interrupted => return Ok(false),
        Err(error) => return Err(error),
    };
    if revents & libc::POLLNVAL != 0 {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "serial port closed",
        ));
    }
    Ok(revents != 0)
}

#[cfg(any(
    feature = "iface-tcp",
    feature = "iface-serial",
    feature = "iface-kiss",
    feature = "iface-backbone"
))]
pub(crate) fn wait_while_active(control: &ListenerControl, duration: Duration) -> bool {
    let deadline = Instant::now() + duration;
    while !control.should_stop() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return true;
        }
        thread::sleep(remaining.min(Duration::from_millis(100)));
    }
    false
}

#[cfg(all(test, feature = "iface-rnode"))]
mod tests {
    use super::*;

    #[test]
    fn listener_control_finish_runs_hook_on_every_clone() {
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = Arc::clone(&count);
        let control = ListenerControl::with_running_flag(Arc::new(AtomicBool::new(true)))
            .with_on_finish(move || {
                seen.fetch_add(1, Ordering::Relaxed);
            });
        let registered = control.clone();
        registered.request_stop();
        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "stopping alone must not finish"
        );
        registered.finish();
        assert_eq!(count.load(Ordering::Relaxed), 1);
        ListenerControl::new().finish(); // no hook: nothing to run
    }
}
