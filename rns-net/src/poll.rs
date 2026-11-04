//! The driver's readiness poller.
//!
//! On Linux and Android this is a thin epoll backend with the subset of the
//! `polling` crate's API the driver uses; elsewhere it is `polling` itself.
//!
//! The reason is per-wait cost. `polling` arms a timerfd and re-arms it (two
//! syscalls) before every wait, and after every wait it reads its notify
//! eventfd and re-arms that too, whether or not a timeout or a notification
//! was involved. On a busy endpoint that is about four syscalls per loop
//! iteration on top of the wait itself. Here the timeout goes to
//! `epoll_wait` directly (rounded up to whole milliseconds, which only ever
//! wakes the driver late by less than a millisecond, never early), and the
//! notify eventfd is registered level-triggered and read only when it is
//! reported.
//!
//! Semantics kept from `polling`: `add` is oneshot, `Event::none` keeps a
//! registration without interest, hang-up and error count as both readable
//! and writable, a wait interrupted by a signal is retried, only one thread
//! waits at a time (a concurrent wait returns no events), and `notify` wakes
//! the current or next wait once.

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub use polling::{Event, Events, PollMode, Poller};

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use self::epoll::{Event, Events, PollMode, Poller};

#[cfg(any(target_os = "linux", target_os = "android"))]
mod epoll {
    use std::io;
    use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    /// Key reserved for the notify eventfd; never reported to callers.
    const NOTIFY_KEY: u64 = u64::MAX;
    const DEFAULT_CAPACITY: usize = 1024;

    const READ_FLAGS: u32 =
        (libc::EPOLLIN | libc::EPOLLHUP | libc::EPOLLERR | libc::EPOLLPRI) as u32;
    const WRITE_FLAGS: u32 = (libc::EPOLLOUT | libc::EPOLLHUP | libc::EPOLLERR) as u32;

    /// How a registration reports readiness.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PollMode {
        /// Reported once, then disarmed until modified.
        Oneshot,
        /// Reported on every wait while ready.
        Level,
    }

    /// Interest in, or readiness of, one registered descriptor.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Event {
        pub key: usize,
        pub readable: bool,
        pub writable: bool,
    }

    impl Event {
        pub fn readable(key: usize) -> Self {
            Self {
                key,
                readable: true,
                writable: false,
            }
        }

        pub fn writable(key: usize) -> Self {
            Self {
                key,
                readable: false,
                writable: true,
            }
        }

        pub fn none(key: usize) -> Self {
            Self {
                key,
                readable: false,
                writable: false,
            }
        }
    }

    fn flags(interest: Event, mode: PollMode) -> u32 {
        let mut flags = match mode {
            PollMode::Oneshot => libc::EPOLLONESHOT as u32,
            PollMode::Level => 0,
        };
        if interest.readable {
            flags |= READ_FLAGS;
        }
        if interest.writable {
            flags |= WRITE_FLAGS;
        }
        flags
    }

    /// Events reported by one wait.
    pub struct Events {
        list: Vec<libc::epoll_event>,
    }

    impl Events {
        pub fn new() -> Self {
            Self {
                list: Vec::with_capacity(DEFAULT_CAPACITY),
            }
        }

        pub fn iter(&self) -> impl Iterator<Item = Event> + '_ {
            self.list.iter().map(|ev| {
                let (bits, data) = (ev.events, ev.u64);
                Event {
                    key: data as usize,
                    readable: bits & READ_FLAGS != 0,
                    writable: bits & WRITE_FLAGS != 0,
                }
            })
        }

        pub fn clear(&mut self) {
            self.list.clear();
        }
    }

    impl Default for Events {
        fn default() -> Self {
            Self::new()
        }
    }

    pub struct Poller {
        epoll: OwnedFd,
        notify_fd: OwnedFd,
        /// Set by `notify` before it writes the eventfd, so a burst of
        /// notifications before the next wait costs one write.
        notified: AtomicBool,
        /// Held by the thread inside `wait`.
        waiting: Mutex<()>,
    }

    fn check(result: libc::c_int) -> io::Result<libc::c_int> {
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }

    impl Poller {
        pub fn new() -> io::Result<Self> {
            // SAFETY: plain syscalls; each returned descriptor is owned once.
            let epoll =
                unsafe { OwnedFd::from_raw_fd(check(libc::epoll_create1(libc::EPOLL_CLOEXEC))?) };
            let notify_fd = unsafe {
                OwnedFd::from_raw_fd(check(libc::eventfd(
                    0,
                    libc::EFD_CLOEXEC | libc::EFD_NONBLOCK,
                ))?)
            };
            let poller = Self {
                epoll,
                notify_fd,
                notified: AtomicBool::new(false),
                waiting: Mutex::new(()),
            };
            let mut ev = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: NOTIFY_KEY,
            };
            // SAFETY: both descriptors are open and owned by `poller`.
            check(unsafe {
                libc::epoll_ctl(
                    poller.epoll.as_raw_fd(),
                    libc::EPOLL_CTL_ADD,
                    poller.notify_fd.as_raw_fd(),
                    &mut ev,
                )
            })?;
            Ok(poller)
        }

        pub fn supports_level(&self) -> bool {
            true
        }

        fn ctl(
            &self,
            op: libc::c_int,
            fd: RawFd,
            interest: Event,
            mode: PollMode,
        ) -> io::Result<()> {
            debug_assert_ne!(
                interest.key as u64, NOTIFY_KEY,
                "key reserved for notifications"
            );
            let mut ev = libc::epoll_event {
                events: flags(interest, mode),
                u64: interest.key as u64,
            };
            // SAFETY: `fd` is open (guaranteed by the callers' contracts).
            check(unsafe { libc::epoll_ctl(self.epoll.as_raw_fd(), op, fd, &mut ev) }).map(|_| ())
        }

        /// Register `fd` in oneshot mode.
        ///
        /// # Safety
        ///
        /// `fd` must be open, and must be deleted before it is closed.
        pub unsafe fn add(&self, fd: RawFd, interest: Event) -> io::Result<()> {
            self.ctl(libc::EPOLL_CTL_ADD, fd, interest, PollMode::Oneshot)
        }

        /// Register `fd` in `mode`.
        ///
        /// # Safety
        ///
        /// `fd` must be open, and must be deleted before it is closed.
        pub unsafe fn add_with_mode(
            &self,
            fd: RawFd,
            interest: Event,
            mode: PollMode,
        ) -> io::Result<()> {
            self.ctl(libc::EPOLL_CTL_ADD, fd, interest, mode)
        }

        pub fn modify(&self, fd: BorrowedFd<'_>, interest: Event) -> io::Result<()> {
            self.ctl(
                libc::EPOLL_CTL_MOD,
                fd.as_raw_fd(),
                interest,
                PollMode::Oneshot,
            )
        }

        pub fn modify_with_mode(
            &self,
            fd: BorrowedFd<'_>,
            interest: Event,
            mode: PollMode,
        ) -> io::Result<()> {
            self.ctl(libc::EPOLL_CTL_MOD, fd.as_raw_fd(), interest, mode)
        }

        pub fn delete(&self, fd: BorrowedFd<'_>) -> io::Result<()> {
            // SAFETY: `fd` is open; the event argument is ignored for DEL.
            check(unsafe {
                libc::epoll_ctl(
                    self.epoll.as_raw_fd(),
                    libc::EPOLL_CTL_DEL,
                    fd.as_raw_fd(),
                    std::ptr::null_mut(),
                )
            })
            .map(|_| ())
        }

        /// Wait for readiness or a notification, at most `timeout`. New
        /// events are appended to `events`, as `polling` does (callers clear
        /// it); returns its length.
        pub fn wait(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
            let Ok(_waiting) = self.waiting.try_lock() else {
                return Ok(0);
            };
            let start = events.list.len();
            if events.list.capacity() == start {
                events.list.reserve(DEFAULT_CAPACITY);
            }
            let timeout_ms = match timeout {
                None => -1,
                Some(t) => {
                    // Round up: a wait must not end before its deadline.
                    let ms = t.as_nanos().div_ceil(1_000_000);
                    ms.min(libc::c_int::MAX as u128) as libc::c_int
                }
            };
            let spare = events.list.capacity() - start;
            let count = loop {
                // SAFETY: the spare capacity has room for `spare` events, and
                // the length is extended by what the kernel filled in.
                let result = unsafe {
                    libc::epoll_wait(
                        self.epoll.as_raw_fd(),
                        events.list.as_mut_ptr().add(start),
                        spare.min(libc::c_int::MAX as usize) as libc::c_int,
                        timeout_ms,
                    )
                };
                match check(result) {
                    Ok(n) => break n as usize,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            };
            // SAFETY: `epoll_wait` initialised `count` entries after `start`.
            unsafe { events.list.set_len(start + count) };
            if let Some(index) = events.list[start..]
                .iter()
                .position(|ev| ev.u64 == NOTIFY_KEY)
            {
                events.list.remove(start + index);
                let mut counter = [0u8; 8];
                // SAFETY: reads at most 8 bytes into `counter`. Reported
                // readable, so this drains the counter instead of failing.
                unsafe {
                    libc::read(
                        self.notify_fd.as_raw_fd(),
                        counter.as_mut_ptr().cast(),
                        counter.len(),
                    )
                };
            }
            // A notification after this is not lost: it writes the eventfd
            // again and the next wait returns at once.
            self.notified.store(false, Ordering::SeqCst);
            Ok(events.list.len())
        }

        /// Wake the current or the next `wait`.
        pub fn notify(&self) -> io::Result<()> {
            if self
                .notified
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                let one = 1u64.to_ne_bytes();
                // SAFETY: writes 8 bytes from `one`. Fails only if the counter
                // would overflow, in which case a wake is already pending.
                unsafe { libc::write(self.notify_fd.as_raw_fd(), one.as_ptr().cast(), one.len()) };
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::Write;
        use std::os::fd::AsFd;
        use std::os::unix::net::UnixStream;
        use std::sync::Arc;
        use std::time::Instant;

        fn wait(
            poller: &Poller,
            events: &mut Events,
            timeout: Option<Duration>,
        ) -> io::Result<usize> {
            events.clear();
            poller.wait(events, timeout)
        }

        #[test]
        fn wait_appends_like_polling() {
            let poller = Poller::new().unwrap();
            let (a, mut b) = UnixStream::pair().unwrap();
            b.write_all(b"x").unwrap();
            unsafe {
                poller
                    .add_with_mode(a.as_raw_fd(), Event::readable(1), PollMode::Level)
                    .unwrap()
            };
            let mut events = Events::new();
            assert_eq!(poller.wait(&mut events, Some(Duration::ZERO)).unwrap(), 1);
            poller.notify().unwrap();
            assert_eq!(poller.wait(&mut events, Some(Duration::ZERO)).unwrap(), 2);
            assert!(events.iter().all(|e| e.key == 1));
        }

        #[test]
        fn timeout_elapses_without_events() {
            let poller = Poller::new().unwrap();
            let mut events = Events::new();
            let started = Instant::now();
            assert_eq!(
                wait(&poller, &mut events, Some(Duration::from_millis(20))).unwrap(),
                0
            );
            assert!(started.elapsed() >= Duration::from_millis(20));
        }

        #[test]
        fn sub_millisecond_timeout_does_not_return_early() {
            let poller = Poller::new().unwrap();
            let mut events = Events::new();
            let started = Instant::now();
            wait(&poller, &mut events, Some(Duration::from_micros(300))).unwrap();
            assert!(started.elapsed() >= Duration::from_micros(300));
        }

        #[test]
        fn notify_wakes_a_blocked_wait_once_and_is_not_reported() {
            let poller = Arc::new(Poller::new().unwrap());
            let waker = poller.clone();
            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                waker.notify().unwrap();
                waker.notify().unwrap();
            });
            let mut events = Events::new();
            assert_eq!(wait(&poller, &mut events, None).unwrap(), 0);
            handle.join().unwrap();
            // Both notifications were consumed by the one wake.
            assert_eq!(
                wait(&poller, &mut events, Some(Duration::from_millis(10))).unwrap(),
                0
            );
            assert!(events.iter().next().is_none());
        }

        #[test]
        fn notify_before_wait_is_kept() {
            let poller = Poller::new().unwrap();
            poller.notify().unwrap();
            let mut events = Events::new();
            let started = Instant::now();
            wait(&poller, &mut events, Some(Duration::from_secs(5))).unwrap();
            assert!(started.elapsed() < Duration::from_secs(1));
        }

        #[test]
        fn oneshot_reports_once_until_modified() {
            let poller = Poller::new().unwrap();
            let (a, mut b) = UnixStream::pair().unwrap();
            b.write_all(b"x").unwrap();
            unsafe { poller.add(a.as_raw_fd(), Event::readable(7)).unwrap() };
            let mut events = Events::new();
            wait(&poller, &mut events, Some(Duration::ZERO)).unwrap();
            let got: Vec<_> = events.iter().collect();
            assert_eq!(
                got,
                vec![Event {
                    key: 7,
                    readable: true,
                    writable: false
                }]
            );
            wait(&poller, &mut events, Some(Duration::ZERO)).unwrap();
            assert!(events.iter().next().is_none());
            poller.modify(a.as_fd(), Event::readable(7)).unwrap();
            wait(&poller, &mut events, Some(Duration::ZERO)).unwrap();
            assert_eq!(events.iter().count(), 1);
            poller.delete(a.as_fd()).unwrap();
        }

        #[test]
        fn level_reports_while_ready_and_none_silences() {
            let poller = Poller::new().unwrap();
            let (a, mut b) = UnixStream::pair().unwrap();
            b.write_all(b"x").unwrap();
            unsafe {
                poller
                    .add_with_mode(a.as_raw_fd(), Event::readable(3), PollMode::Level)
                    .unwrap()
            };
            let mut events = Events::new();
            for _ in 0..2 {
                wait(&poller, &mut events, Some(Duration::ZERO)).unwrap();
                assert_eq!(events.iter().next().map(|e| e.key), Some(3));
            }
            poller
                .modify_with_mode(a.as_fd(), Event::none(3), PollMode::Level)
                .unwrap();
            wait(&poller, &mut events, Some(Duration::ZERO)).unwrap();
            assert!(events.iter().next().is_none());
        }

        #[test]
        fn hang_up_counts_as_readable_and_writable() {
            let poller = Poller::new().unwrap();
            let (a, b) = UnixStream::pair().unwrap();
            unsafe { poller.add(a.as_raw_fd(), Event::writable(5)).unwrap() };
            drop(b);
            let mut events = Events::new();
            wait(&poller, &mut events, Some(Duration::from_millis(100))).unwrap();
            let event = events.iter().next().unwrap();
            assert!(event.readable && event.writable);
        }
    }
}
