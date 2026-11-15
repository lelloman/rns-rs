//! Upstream's `RNS.log` lines and Python's exception texts, for the
//! messages upstream's utilities print to stdout through them.

use std::sync::atomic::{AtomicI32, Ordering};

pub const LOG_NONE: i32 = -1;
pub const LOG_CRITICAL: i32 = 0;
pub const LOG_ERROR: i32 = 1;
pub const LOG_WARNING: i32 = 2;
pub const LOG_NOTICE: i32 = 3;
pub const LOG_INFO: i32 = 4;
pub const LOG_VERBOSE: i32 = 5;
pub const LOG_DEBUG: i32 = 6;

/// `RNS.loglevel`: `LOG_NOTICE` until a Reticulum instance sets it.
static LOGLEVEL: AtomicI32 = AtomicI32::new(LOG_NOTICE);

pub fn set_loglevel(level: i32) {
    LOGLEVEL.store(level, Ordering::Relaxed);
}

pub fn loglevel() -> i32 {
    LOGLEVEL.load(Ordering::Relaxed)
}

/// `RNS.loglevelname`.
fn loglevelname(level: i32) -> &'static str {
    match level {
        LOG_CRITICAL => "[Critical]",
        LOG_ERROR => "[Error]   ",
        LOG_WARNING => "[Warning] ",
        LOG_NOTICE => "[Notice]  ",
        LOG_INFO => "[Info]    ",
        LOG_VERBOSE => "[Verbose] ",
        LOG_DEBUG => "[Debug]   ",
        7 => "[Pathing] ",
        8 => "[Extra]   ",
        _ => "Unknown",
    }
}

/// `RNS.log(msg, level)` to stdout, as upstream's utilities log.
pub fn log(msg: &str, level: i32) {
    let current = loglevel();
    if current == LOG_NONE || current < level {
        return;
    }
    println!("[{}] {} {}", timestamp(), loglevelname(level), msg);
}

/// `time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())`.
fn timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as libc::time_t)
        .unwrap_or(0);
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&now, &mut tm) }.is_null() {
        return String::new();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

/// Python's `str()` of the `OSError` an operation on `path` raised:
/// `[Errno 2] No such file or directory: 'path'`.
pub fn oserror(err: &std::io::Error, path: &str) -> String {
    match err.raw_os_error() {
        Some(code) => format!(
            "[Errno {code}] {}: {}",
            strerror(err),
            crate::argparse::repr(path)
        ),
        None => err.to_string(),
    }
}

/// The C library's message for an OS error, which Python's `OSError` shows.
fn strerror(err: &std::io::Error) -> String {
    let text = err.to_string();
    match text.rfind(" (os error ") {
        Some(at) => text[..at].to_string(),
        None => text,
    }
}

/// `bytes.fromhex(s)`, with Python's error message.
pub fn fromhex(s: &str) -> Result<Vec<u8>, String> {
    let chars: Vec<char> = s.chars().collect();
    let digit = |c: Option<&char>| c.and_then(|c| c.to_digit(16));
    let error =
        |at: usize| format!("non-hexadecimal number found in fromhex() arg at position {at}");
    let is_space = |c: char| matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c');
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if is_space(chars[i]) {
            while i < chars.len() && is_space(chars[i]) {
                i += 1;
            }
            if i >= chars.len() {
                break;
            }
        }
        let top = digit(chars.get(i)).ok_or_else(|| error(i))?;
        let bottom = digit(chars.get(i + 1)).ok_or_else(|| error(i + 1))?;
        out.push((top * 16 + bottom) as u8);
        i += 2;
    }
    Ok(out)
}

/// `base64.b32decode(s)`: strict, as Python's.
pub fn b32decode(s: &str) -> Option<Vec<u8>> {
    if !s.is_ascii() || !s.len().is_multiple_of(8) {
        return None;
    }
    let data = s.trim_end_matches('=');
    let pads = s.len() - data.len();
    if ![0, 1, 3, 4, 6].contains(&pads) {
        return None;
    }
    let mut out = Vec::new();
    let mut bits: u64 = 0;
    let mut count = 0;
    for c in data.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        bits = (bits << 5) | u64::from(v);
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    Some(out)
}

/// `base64.urlsafe_b64decode(s)`: characters outside the alphabet are
/// skipped and decoding stops at completing padding, as Python's
/// non-strict decoder does.
pub fn urlsafe_b64decode(s: &str) -> Option<Vec<u8>> {
    if !s.is_ascii() {
        return None;
    }
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut quad = 0;
    let mut pads = 0;
    for c in s.bytes() {
        if c == b'=' {
            pads += 1;
            if quad >= 2 && quad + pads >= 4 {
                // The partial quad's bytes: 2 characters give one, 3 two.
                let bytes = (acc << (6 * (4 - quad))).to_be_bytes();
                out.extend_from_slice(&bytes[1..quad]);
                quad = 0;
                break;
            }
            continue;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => continue,
        };
        pads = 0;
        acc = (acc << 6) | u32::from(v);
        quad += 1;
        if quad == 4 {
            out.extend_from_slice(&acc.to_be_bytes()[1..]);
            acc = 0;
            quad = 0;
        }
    }
    // A partial quad left without its padding is "Incorrect padding".
    (quad == 0).then_some(out)
}

/// `base64.urlsafe_b64encode(data)`.
pub fn urlsafe_b64encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let mut buf = [0u8; 3];
        buf[..chunk.len()].copy_from_slice(chunk);
        let n = (u32::from(buf[0]) << 16) | (u32::from(buf[1]) << 8) | u32::from(buf[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// `base64.b32encode(data)`.
pub fn b32encode(data: &[u8]) -> String {
    crate::format::base32_encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fromhex_reports_pythons_position() {
        assert_eq!(fromhex("0a ff").unwrap(), vec![0x0a, 0xff]);
        assert_eq!(
            fromhex("zz").unwrap_err(),
            "non-hexadecimal number found in fromhex() arg at position 0"
        );
        assert_eq!(
            fromhex("0g").unwrap_err(),
            "non-hexadecimal number found in fromhex() arg at position 1"
        );
        assert_eq!(
            fromhex("abc").unwrap_err(),
            "non-hexadecimal number found in fromhex() arg at position 3"
        );
        assert_eq!(fromhex("a b").unwrap_err().chars().last(), Some('1'));
    }

    #[test]
    fn base_decoders_follow_python() {
        assert_eq!(b32decode("MZXW6==="), Some(b"foo".to_vec()));
        assert_eq!(b32decode("MZXW6"), None);
        assert_eq!(b32decode("mzxw6==="), None);
        assert_eq!(urlsafe_b64decode("Zm9v"), Some(b"foo".to_vec()));
        assert_eq!(urlsafe_b64decode("Zm8="), Some(b"fo".to_vec()));
        assert_eq!(urlsafe_b64decode("Zm8=trailing"), Some(b"fo".to_vec()));
        assert_eq!(urlsafe_b64decode("Zm!9v"), Some(b"foo".to_vec()));
        assert_eq!(urlsafe_b64decode("garbage"), None);
        assert_eq!(urlsafe_b64encode(&[0xfb, 0xff]), "-_8=");
        assert_eq!(b32encode(b"foo"), "MZXW6===");
    }

    #[test]
    fn oserror_text_is_pythons() {
        let err = std::io::Error::from_raw_os_error(2);
        assert_eq!(
            oserror(&err, "nodir/x.rid"),
            "[Errno 2] No such file or directory: 'nodir/x.rid'"
        );
    }
}
