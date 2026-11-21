//! Logging, prompts and numbers printed as upstream prints them.

use super::*;

/// upstream's `RNS.log` as `rnodeconf` sets it up: `[HH:MM:SS] message`, in
/// local time.
pub(super) fn log(message: &str) {
    println!("[{}] {message}", local_time("%H:%M:%S", now()));
    let _ = std::io::stdout().flush();
}

pub(super) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Format `timestamp` in local time with `strftime`.
#[allow(unsafe_code, reason = "localtime_r")]
pub(super) fn local_time(format: &str, timestamp: i64) -> String {
    // SAFETY: `libc::tm` is a plain C struct of integers plus a nullable `tm_zone` pointer;
    // all-zero bytes are a valid value.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let time: libc::time_t = timestamp as libc::time_t;
    // SAFETY: localtime_r and strftime write only into the buffers given.
    unsafe {
        if libc::localtime_r(&time, &mut tm).is_null() {
            return String::new();
        }
        let format = std::ffi::CString::new(format).unwrap_or_default();
        let mut buf = [0u8; 64];
        let len = libc::strftime(
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            format.as_ptr(),
            &tm,
        );
        String::from_utf8_lossy(buf.get(..len).unwrap_or_default()).into_owned()
    }
}

/// A float as Python's `str()` writes it, for the values `rnodeconf`
/// prints.
pub(super) fn py_float(value: f64) -> String {
    format!("{value:?}")
}

/// Python's `round(value, digits)`.
pub(super) fn py_round(value: f64, digits: usize) -> f64 {
    format!("{value:.digits$}").parse().unwrap_or(value)
}

/// `RNS.hexrep`: lowercase hex bytes, colon-delimited.
pub(super) fn hexrep(bytes: &[u8]) -> String {
    rns_core::encoding::hex_delimited(bytes, ':')
}

/// upstream `graceful_exit`.
pub(super) fn graceful_exit(code: i32) -> ! {
    let _ = std::io::stdout().flush();
    exit(code)
}

/// upstream's `print_donation_block`.
pub(super) fn print_donation_block() {
    println!("  Ethereum  : 0x91C421DdfB8a30a49A71d63447ddb54cEBe3465E");
    println!("  Bitcoin   : bc1pgqgu8h8xvj4jtafslq396v7ju7hkgymyrzyqft4llfslz5vp99psqfk3a6");
    println!("  Monero    : 87HcDx6jRSkMQ9nPRd5K9hGGpZLn2s7vWETjMaVM5KfV4TD36NcYa8J8WSxhTSvBzzFpqDwp2fg5GX2moZ7VAP9QMZCZGET");
    println!("  Ko-Fi     : https://ko-fi.com/markqvist");
    println!("  LiberaPay : https://liberapay.com/reticulum");
    println!();
    println!("  Info      : https://reticulum.network");
    println!("  Code      : https://github.com/markqvist");
}

/// upstream's `input()` where only Enter is awaited.
pub(super) fn wait_for_enter() {
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
}

pub(super) fn prompt_int(prompt: &str) -> i64 {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        graceful_exit(0);
    }
    match line.trim().parse() {
        Ok(v) => v,
        Err(_) => {
            println!("\nInvalid number: {}", line.trim());
            graceful_exit(1);
        }
    }
}

/// Python's `int()` on a string: surrounding whitespace, an optional sign,
/// and digits that single underscores may separate.
pub(super) fn py_int(text: &str) -> Option<i64> {
    let text = text.trim();
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    let valid = !digits.is_empty()
        && !digits.starts_with('_')
        && !digits.ends_with('_')
        && !digits.contains("__")
        && digits.chars().all(|c| c.is_ascii_digit() || c == '_');
    if !valid {
        return None;
    }
    text.replace('_', "").parse().ok()
}

/// Lowercase hex without delimiters.
pub(super) fn hexstr(bytes: &[u8]) -> String {
    rns_core::encoding::hex(bytes)
}

/// A two-digit hex code from `--product` or `--model`.
pub(super) fn hex_code(value: Option<&str>) -> Option<u8> {
    let value = value?;
    if value.len() != 2 {
        return None;
    }
    u8::from_str_radix(value, 16).ok()
}
