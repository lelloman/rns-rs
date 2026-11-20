//! Signal handling for the tools and daemons.
//!
//! Every handler here only makes async-signal-safe calls: atomic loads and
//! stores, `write(2)` and `_exit(2)`. What a handler does is set up before
//! it is installed, through statics it reads.
//!
//! - [`SignalPipe`]: a signal writes a byte to a pipe a thread waits on.
//! - [`set_flag_on`]: a signal sets an atomic flag a loop polls.
//! - [`exit_on`]: a signal ends the process at once.

#![allow(unsafe_code, reason = "signal handlers and pipes through libc")]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;

pub use libc::{SIGHUP, SIGINT, SIGTERM, SIGWINCH};

/// Install `handler` for each of `signals`. `handler` must only make
/// async-signal-safe calls; every handler of this module does.
fn install(signals: &[libc::c_int], handler: extern "C" fn(libc::c_int)) {
    for &signal in signals {
        // SAFETY: `handler` is an `extern "C" fn(c_int)`, the shape
        // `sighandler_t` expects, and only makes async-signal-safe calls.
        unsafe { libc::signal(signal, handler as *const () as libc::sighandler_t) };
    }
}

/// Write `byte` to `fd`. Async-signal-safe; a failed write (a closed
/// descriptor, a full non-blocking pipe) is ignored.
fn write_byte(fd: RawFd, byte: u8) {
    // SAFETY: one byte from a valid buffer; `write` is async-signal-safe.
    unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
}

// --- Signal pipe ---

/// The write end of the pipe signals are routed to; -1 when none.
static PIPE_FD: AtomicI32 = AtomicI32::new(-1);
/// The byte a routed signal writes.
static PIPE_BYTE: AtomicU8 = AtomicU8::new(0);

extern "C" fn write_to_pipe(_signal: libc::c_int) {
    notify_routed_pipe();
}

/// Write the routed byte to the pipe signals are routed to, as a signal
/// would; nothing without one. Async-signal-safe.
pub fn notify_routed_pipe() {
    let fd = PIPE_FD.load(Ordering::SeqCst);
    if fd >= 0 {
        write_byte(fd, PIPE_BYTE.load(Ordering::SeqCst));
    }
}

/// A pipe a signal handler writes to and a thread waits on. Writing to a
/// pipe is async-signal-safe, unlike sending on a channel, whose wake can
/// be lost when the handler interrupts the thread waiting on it. Neither
/// end is inherited by children.
pub struct SignalPipe {
    read: OwnedFd,
    write: Arc<OwnedFd>,
}

/// Writes to a [`SignalPipe`] from another thread.
#[derive(Clone)]
pub struct PipeWriter(Arc<OwnedFd>);

impl PipeWriter {
    /// Write `byte` to the pipe; dropped when a non-blocking pipe is full.
    pub fn write(&self, byte: u8) {
        write_byte(self.0.as_raw_fd(), byte);
    }
}

impl SignalPipe {
    /// Open a pipe; with `nonblocking`, both ends are non-blocking.
    pub fn new(nonblocking: bool) -> io::Result<Self> {
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
                if nonblocking {
                    let flags = libc::fcntl(fd, libc::F_GETFL);
                    libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }
        }
        Ok(Self {
            read,
            write: Arc::new(write),
        })
    }

    /// Route `signals` to this pipe: each writes `byte` to it. The latest
    /// pipe routed is the one written to.
    pub fn route(&self, signals: &[libc::c_int], byte: u8) {
        PIPE_BYTE.store(byte, Ordering::SeqCst);
        PIPE_FD.store(self.write.as_raw_fd(), Ordering::SeqCst);
        install(signals, write_to_pipe);
    }

    /// A writer to this pipe, for other threads.
    pub fn writer(&self) -> PipeWriter {
        PipeWriter(Arc::clone(&self.write))
    }

    /// The read end, to poll.
    pub fn read_fd(&self) -> RawFd {
        self.read.as_raw_fd()
    }

    /// Block until a byte arrives on a blocking pipe, and return it.
    pub fn wait(&self) -> io::Result<u8> {
        let mut byte = 0u8;
        loop {
            // SAFETY: one byte into a valid buffer.
            let n = unsafe { libc::read(self.read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) };
            if n > 0 {
                return Ok(byte);
            }
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    /// Read whatever a non-blocking pipe holds; returns whether `byte` was
    /// among it.
    pub fn drain_contains(&self, byte: u8) -> bool {
        let mut found = false;
        let mut buf = [0u8; 64];
        loop {
            // SAFETY: reading into a valid buffer; the pipe is non-blocking.
            let n =
                unsafe { libc::read(self.read.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            found |= buf[..n as usize].contains(&byte);
        }
        found
    }
}

impl Drop for SignalPipe {
    fn drop(&mut self) {
        let _ = PIPE_FD.compare_exchange(
            self.write.as_raw_fd(),
            -1,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }
}

// --- Flags ---

/// Signals up to this number can set a flag.
const MAX_FLAG_SIGNAL: usize = 32;

/// The flag each signal sets; null for none.
static FLAGS: [AtomicPtr<AtomicBool>; MAX_FLAG_SIGNAL] =
    [const { AtomicPtr::new(std::ptr::null_mut()) }; MAX_FLAG_SIGNAL];
/// What a flag signal writes to stderr first, as a pointer and a length.
static FLAG_MESSAGE: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static FLAG_MESSAGE_LEN: AtomicUsize = AtomicUsize::new(0);

extern "C" fn set_flag(signal: libc::c_int) {
    let message = FLAG_MESSAGE.load(Ordering::SeqCst);
    let len = FLAG_MESSAGE_LEN.load(Ordering::SeqCst);
    if !message.is_null() && len > 0 {
        // SAFETY: `message` and `len` describe a `&'static [u8]`; a closed
        // stderr only makes the write fail. `write` is async-signal-safe.
        unsafe { libc::write(2, message.cast_const().cast(), len) };
    }
    let Some(slot) = usize::try_from(signal).ok().and_then(|i| FLAGS.get(i)) else {
        return;
    };
    let flag = slot.load(Ordering::SeqCst);
    // SAFETY: a non-null slot holds a `&'static AtomicBool`.
    if let Some(flag) = unsafe { flag.as_ref() } {
        flag.store(true, Ordering::Relaxed);
    }
}

/// Set `flag` on each of `signals` (numbered below 32).
pub fn set_flag_on(signals: &[libc::c_int], flag: &'static AtomicBool) {
    for &signal in signals {
        if let Some(slot) = usize::try_from(signal).ok().and_then(|i| FLAGS.get(i)) {
            slot.store(std::ptr::from_ref(flag).cast_mut(), Ordering::SeqCst);
        }
    }
    install(signals, set_flag);
}

/// Like [`set_flag_on`], and write `message` to stderr on each of these
/// signals before setting the flag. The message is the process's one:
/// the latest set applies to every flag signal.
pub fn set_flag_on_with_message(
    signals: &[libc::c_int],
    flag: &'static AtomicBool,
    message: &'static [u8],
) {
    FLAG_MESSAGE_LEN.store(message.len(), Ordering::SeqCst);
    FLAG_MESSAGE.store(message.as_ptr().cast_mut(), Ordering::SeqCst);
    set_flag_on(signals, flag);
}

// --- Exit ---

static EXIT_CODE: AtomicI32 = AtomicI32::new(0);
static EXIT_NEWLINE: AtomicBool = AtomicBool::new(false);

extern "C" fn exit_now(_signal: libc::c_int) {
    // `write` and `_exit` are async-signal-safe; stdout is flushed after
    // every write that matters, as upstream's `os._exit` does not flush
    // either.
    if EXIT_NEWLINE.load(Ordering::Relaxed) {
        write_byte(1, b'\n');
    }
    // SAFETY: `_exit` is async-signal-safe, takes no pointers and runs no
    // destructors or atexit handlers.
    unsafe { libc::_exit(EXIT_CODE.load(Ordering::Relaxed)) }
}

/// Exit at once with `code` on each of `signals`, first printing a newline
/// on stdout with `newline`. Runs no destructors.
pub fn exit_on(signals: &[libc::c_int], code: i32, newline: bool) {
    EXIT_NEWLINE.store(newline, Ordering::Relaxed);
    EXIT_CODE.store(code, Ordering::Relaxed);
    install(signals, exit_now);
}
