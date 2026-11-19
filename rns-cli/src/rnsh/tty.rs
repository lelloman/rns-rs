//! The initiator's terminal: restoring its mode and reading its size.

#![allow(unsafe_code, reason = "OS calls through libc and signal handlers")]

use super::*;

pub(super) struct TtyRestorer {
    pub(super) fd: RawFd,
    pub(super) original: Option<libc::termios>,
}

impl TtyRestorer {
    pub(super) fn new(fd: RawFd) -> Self {
        // SAFETY: `termios` is a plain C struct of integers and arrays; all-zero bytes are a
        // valid value.
        let mut original = unsafe { std::mem::zeroed() };
        // SAFETY: `original` is a live local `termios` that `tcgetattr` writes into; a bad `fd`
        // only makes it fail.
        let original = if unsafe { libc::tcgetattr(fd, &mut original) } == 0 {
            Some(original)
        } else {
            None
        };
        TtyRestorer { fd, original }
    }

    pub(super) fn raw(&self) {
        let Some(mut raw) = self.original else {
            return;
        };
        // SAFETY: `raw` is a live local copy of the saved `termios`; `cfmakeraw` edits it in
        // place and `tcsetattr` only reads it.
        unsafe {
            libc::cfmakeraw(&mut raw);
            libc::tcsetattr(self.fd, libc::TCSANOW, &raw);
        }
    }
}

impl Drop for TtyRestorer {
    fn drop(&mut self) {
        if let Some(original) = self.original {
            // SAFETY: `original` is a live local `termios` that `tcsetattr` only reads; a stale
            // `fd` only makes it fail.
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSADRAIN, &original);
            }
        }
    }
}

pub(super) fn current_winsize(fd: RawFd) -> WindowSize {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `ws` is a live local `winsize` that TIOCGWINSZ writes into; a bad `fd` only makes
    // it fail.
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 {
        WindowSize {
            rows: nonzero_u16(ws.ws_row),
            cols: nonzero_u16(ws.ws_col),
            hpix: nonzero_u16(ws.ws_xpixel),
            vpix: nonzero_u16(ws.ws_ypixel),
        }
    } else {
        WindowSize {
            rows: None,
            cols: None,
            hpix: None,
            vpix: None,
        }
    }
}

pub(super) fn nonzero_u16(value: u16) -> Option<u16> {
    (value != 0).then_some(value)
}
