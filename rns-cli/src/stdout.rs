//! Leaving quietly when stdout is closed or on an interrupt.
//!
//! Rust ignores SIGPIPE, so `println!` to a closed pipe (`rnstatus | head`)
//! panics with "failed printing to stdout: Broken pipe". Restoring SIGPIPE's
//! default action would fix that, but would also kill a tool whose network
//! threads write to a peer that went away; this hook only turns that one
//! panic into the exit status a shell reports for SIGPIPE.

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

/// Exit at once with `code` on SIGINT or SIGTERM, printing nothing: what an
/// upstream utility does once it has started Reticulum, whose handlers call
/// `RNS.exit()` (`os._exit(0)`).
pub fn exit_on_interrupt(code: i32) {
    crate::signals::exit_on(
        &[crate::signals::SIGINT, crate::signals::SIGTERM],
        code,
        false,
    );
}

/// Print a newline and exit with `code` on SIGINT or SIGTERM: a utility's
/// own `except KeyboardInterrupt: print(""); exit(code)`, before it has
/// started Reticulum.
pub fn exit_on_interrupt_after_newline(code: i32) {
    crate::signals::exit_on(
        &[crate::signals::SIGINT, crate::signals::SIGTERM],
        code,
        true,
    );
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
