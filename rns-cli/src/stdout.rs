//! Leaving quietly when stdout is closed or on an interrupt.
//!
//! Rust ignores SIGPIPE, so `println!` to a closed pipe (`rnstatus | head`)
//! panics with "failed printing to stdout: Broken pipe". Restoring SIGPIPE's
//! default action would fix that, but would also kill a tool whose network
//! threads write to a peer that went away; this hook only turns that one
//! panic into the exit status a shell reports for SIGPIPE.

#![allow(unsafe_code, reason = "OS calls through libc and signal handlers")]

/// Exit status of a process ended by SIGPIPE, as shells report it.
pub const CLOSED_STDOUT_EXIT: i32 = 128 + 13;

/// Make a panic from printing to a closed stdout exit quietly with
/// [`CLOSED_STDOUT_EXIT`]; any other panic is reported as before.
pub fn exit_quietly_on_closed_stdout() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if is_closed_stdout(panic_message(info)) {
            std::process::exit(CLOSED_STDOUT_EXIT);
        }
        default(info);
    }));
}

static INTERRUPT_EXIT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
static INTERRUPT_NEWLINE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn exit_now(_: libc::c_int) {
    // `write` and `_exit` are async-signal-safe; stdout is flushed after
    // every write that matters, as upstream's `os._exit` does not flush
    // either.
    if INTERRUPT_NEWLINE.load(std::sync::atomic::Ordering::Relaxed) {
        // SAFETY: `write(2)` is async-signal-safe and reads one byte from a static literal; if fd
        // 1 is closed it only fails with EBADF.
        unsafe { libc::write(1, b"\n".as_ptr().cast(), 1) };
    }
    // SAFETY: `_exit` is async-signal-safe, takes no pointers and runs no destructors or atexit
    // handlers.
    unsafe { libc::_exit(INTERRUPT_EXIT.load(std::sync::atomic::Ordering::Relaxed)) }
}

/// Exit at once with `code` on SIGINT or SIGTERM, printing nothing: what an
/// upstream utility does once it has started Reticulum, whose handlers call
/// `RNS.exit()` (`os._exit(0)`).
pub fn exit_on_interrupt(code: i32) {
    INTERRUPT_NEWLINE.store(false, std::sync::atomic::Ordering::Relaxed);
    INTERRUPT_EXIT.store(code, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: `exit_now` is an `extern "C" fn(c_int)`, the shape `sighandler_t` expects, and only
    // does atomic loads, `write(2)` and `_exit`, all async-signal-safe.
    unsafe {
        libc::signal(libc::SIGINT, exit_now as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, exit_now as *const () as libc::sighandler_t);
    }
}

/// Print a newline and exit with `code` on SIGINT or SIGTERM: a utility's
/// own `except KeyboardInterrupt: print(""); exit(code)`, before it has
/// started Reticulum.
pub fn exit_on_interrupt_after_newline(code: i32) {
    exit_on_interrupt(code);
    INTERRUPT_NEWLINE.store(true, std::sync::atomic::Ordering::Relaxed);
}

fn panic_message<'a>(info: &'a std::panic::PanicHookInfo<'_>) -> &'a str {
    if let Some(message) = info.payload().downcast_ref::<&str>() {
        message
    } else if let Some(message) = info.payload().downcast_ref::<String>() {
        message
    } else {
        ""
    }
}

fn is_closed_stdout(message: &str) -> bool {
    message.starts_with("failed printing to stdout") && message.contains("Broken pipe")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_only_the_closed_stdout_panic() {
        assert!(is_closed_stdout(
            "failed printing to stdout: Broken pipe (os error 32)"
        ));
        assert!(!is_closed_stdout("failed printing to stdout: Other error"));
        assert!(!is_closed_stdout("index out of bounds: Broken pipe"));
    }
}
