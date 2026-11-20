//! Upstream's `RNS.log` lines and Python's exception texts, for the
//! messages upstream's utilities print to stdout through them.

use crate::sys::home_of;
use rns_core::encoding::{BASE64_EITHER, BASE64_URL_SAFE};
use std::sync::atomic::{AtomicI32, Ordering};

/// Level that silences all logging.
pub const LOG_NONE: i32 = -1;
/// Upstream's `LOG_CRITICAL`; levels are ordered, higher is more verbose.
pub const LOG_CRITICAL: i32 = 0;
/// Upstream's `LOG_ERROR`.
pub const LOG_ERROR: i32 = 1;
/// Upstream's `LOG_WARNING`.
pub const LOG_WARNING: i32 = 2;
/// Upstream's `LOG_NOTICE`, the default level.
pub const LOG_NOTICE: i32 = 3;
/// Upstream's `LOG_INFO`.
pub const LOG_INFO: i32 = 4;
/// Upstream's `LOG_VERBOSE`.
pub const LOG_VERBOSE: i32 = 5;
/// Upstream's `LOG_DEBUG`.
pub const LOG_DEBUG: i32 = 6;

/// `RNS.loglevel`: `LOG_NOTICE` until a Reticulum instance sets it.
static LOGLEVEL: AtomicI32 = AtomicI32::new(LOG_NOTICE);

/// Sets the process-wide level: [`log()`] prints a message only when its
/// level is at most this one, and nothing at [`LOG_NONE`].
pub fn set_loglevel(level: i32) {
    LOGLEVEL.store(level, Ordering::Relaxed);
}

/// The process-wide level [`set_loglevel`] last set; [`LOG_NOTICE`] before
/// that.
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

/// `RNS.logtimestamps` and `RNS.compact_log_fmt`, as the utility's
/// logging set them.
static TIMESTAMPS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
static COMPACT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `RNS.logfile` while `RNS.logdest` is `LOG_FILE`; stdout otherwise.
static LOGFILE: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);

/// Send `RNS.log` lines to `path` (`RNS.logdest = RNS.LOG_FILE` with
/// `RNS.logfile = path`), or back to stdout with `None`.
pub fn set_logfile(path: Option<std::path::PathBuf>) {
    *LOGFILE.lock().unwrap_or_else(|p| p.into_inner()) = path;
}

/// Write a finished log line where `RNS.log` writes it: appended to the
/// log file, or printed.
fn emit(line: &str) {
    let logfile = LOGFILE.lock().unwrap_or_else(|p| p.into_inner()).clone();
    match logfile {
        Some(path) => {
            use std::io::Write;
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let _ = file.write_all(line.as_bytes());
            }
        }
        None => {
            use std::io::Write;
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(line.as_bytes());
            let _ = out.flush();
        }
    }
}

/// `RNS.log`'s line for `msg` at `level`, with a trailing newline.
fn format_line(level: i32, msg: &dyn std::fmt::Display, timestamps: bool, compact: bool) -> String {
    let stamp = if timestamps {
        format!("[{}] ", timestamp())
    } else {
        String::new()
    };
    if compact {
        format!("{stamp}{msg}\n")
    } else {
        format!("{stamp}{} {}\n", loglevelname(level), msg)
    }
}

/// `RNS.log(msg, level)`, as upstream's utilities log.
pub fn log(msg: &str, level: i32) {
    let current = loglevel();
    if current == LOG_NONE || current < level {
        return;
    }
    emit(&format_line(
        level,
        &msg,
        TIMESTAMPS.load(Ordering::Relaxed),
        COMPACT.load(Ordering::Relaxed),
    ));
}

/// Writes to wherever `RNS.log` currently writes.
struct RnsLogDestination;

impl std::io::Write for RnsLogDestination {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        emit(&String::from_utf8_lossy(buf));
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Log target for messages upstream logs at `LOG_NOTICE`: shown at the
/// default level, where this implementation's `info` messages are not.
pub use rns_net::logging::NOTICE_TARGET;

/// Log target for messages upstream logs at `LOG_INFO`.
pub use rns_net::logging::INFO_TARGET;

/// The RNS level of a `log` record: errors, warnings, notices (by target),
/// pathing (by target); `info` is upstream's Verbose, `debug` its Debug,
/// `trace` its Extreme. Upstream's default level 4 then shows what it
/// shows, not every `info` line.
pub fn rns_level(metadata: &log::Metadata) -> i32 {
    if metadata.target() == NOTICE_TARGET {
        return LOG_NOTICE;
    }
    if metadata.target() == INFO_TARGET {
        return LOG_INFO;
    }
    if metadata.target() == rns_net::logging::PATHING_LOG_TARGET {
        return 7;
    }
    match metadata.level() {
        log::Level::Error => LOG_ERROR,
        log::Level::Warn => LOG_WARNING,
        log::Level::Info => LOG_VERBOSE,
        log::Level::Debug => LOG_DEBUG,
        log::Level::Trace => 8,
    }
}

/// A `log` logger writing `RNS.log`'s lines: `[timestamp] [Level]    msg`
/// (without the timestamp when `logtimestamps` is off), up to `level`.
pub struct RnsLogger {
    level: i32,
    timestamps: bool,
    out: std::sync::Mutex<Box<dyn std::io::Write + Send>>,
    /// `RNS.compact_log_fmt`: no level name.
    compact: bool,
}

/// The `[logging]` section of the Reticulum config in `config_dir`
/// (upstream's default when it has none).
pub fn configured_logging(config_dir: Option<&str>) -> rns_net::config::LoggingSection {
    let config_dir = rns_net::storage::resolve_config_dir(config_dir.map(std::path::Path::new));
    let config_file = config_dir.join("config");
    if !config_file.exists() {
        return rns_net::config::LoggingSection::default();
    }
    match rns_net::config::parse_file(&config_file) {
        Ok(config) => config.logging,
        Err(err) => {
            eprintln!(
                "Could not parse logging config {}: {}",
                config_file.display(),
                err
            );
            rns_net::config::LoggingSection::default()
        }
    }
}

/// Log as a utility's `RNS.Reticulum(configdir, loglevel=...)` makes
/// `RNS.log` log: to stdout, at `loglevel`, or without one at the
/// configured level raised by `verbosity` (upstream's `verbosity=`
/// argument), with timestamps unless the config turns them off. `compact`
/// is `RNS.compact_log_fmt`.
pub fn install_utility_logging(
    config_dir: Option<&str>,
    loglevel: Option<i32>,
    verbosity: i32,
    compact: bool,
) {
    let logging = configured_logging(config_dir);
    let level = loglevel.unwrap_or_else(|| (i32::from(logging.loglevel) + verbosity).clamp(0, 8));
    set_loglevel(level);
    TIMESTAMPS.store(logging.logtimestamps, Ordering::Relaxed);
    COMPACT.store(compact, Ordering::Relaxed);
    let _ = RnsLogger::install_with(
        level,
        logging.logtimestamps,
        compact,
        Box::new(RnsLogDestination),
    );
}

impl RnsLogger {
    /// Install it as the global logger.
    pub fn install(
        level: i32,
        timestamps: bool,
        out: Box<dyn std::io::Write + Send>,
    ) -> Result<(), log::SetLoggerError> {
        Self::install_with(level, timestamps, false, out)
    }

    /// Install it as the global logger, with `RNS.compact_log_fmt`.
    pub fn install_with(
        level: i32,
        timestamps: bool,
        compact: bool,
        out: Box<dyn std::io::Write + Send>,
    ) -> Result<(), log::SetLoggerError> {
        let max = match level {
            i32::MIN..=1 => log::LevelFilter::Error,
            2 => log::LevelFilter::Warn,
            3..=5 => log::LevelFilter::Info,
            6 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        };
        log::set_boxed_logger(Box::new(RnsLogger {
            level,
            timestamps,
            out: std::sync::Mutex::new(out),
            compact,
        }))?;
        log::set_max_level(max);
        Ok(())
    }

    fn line(&self, level: i32, msg: &std::fmt::Arguments) -> String {
        format_line(level, msg, self.timestamps, self.compact)
    }
}

impl log::Log for RnsLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        // `RNS.loglevel = -1` silences it, as rnid --stdout does.
        loglevel() != LOG_NONE && rns_level(metadata) <= self.level
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = self.line(rns_level(record.metadata()), record.args());
        let mut out = self
            .out
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = out.write_all(line.as_bytes());
        let _ = out.flush();
    }

    fn flush(&self) {
        let _ = self
            .out
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .flush();
    }
}

/// `time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())`.
fn timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as libc::time_t)
        .unwrap_or(0);
    let Some(tm) = crate::sys::localtime(now) else {
        return String::new();
    };
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

/// `RNS.Identity()`: a new identity, logged at Verbose as upstream's
/// `Identity.create_keys` logs it.
pub fn new_identity() -> rns_crypto::identity::Identity {
    let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::OsRng);
    log(
        &format!(
            "Identity keys created for {}",
            crate::pyfmt::prettyhexrep(identity.hash())
        ),
        LOG_VERBOSE,
    );
    identity
}

/// `RNS.Identity.from_file`: the identity in a file of private key bytes,
/// or `None`, logged as upstream logs it, when it holds none.
pub fn identity_from_file(path: &str) -> Option<rns_crypto::identity::Identity> {
    match std::fs::read(path) {
        Ok(bytes) => identity_from_bytes(&bytes),
        Err(e) => {
            log(
                &format!("Error while loading identity from {path}"),
                LOG_ERROR,
            );
            log(
                &format!("The contained exception was: {}", oserror(&e, path)),
                LOG_ERROR,
            );
            None
        }
    }
}

/// `RNS.Identity.from_bytes` (`load_private_key`).
pub fn identity_from_bytes(bytes: &[u8]) -> Option<rns_crypto::identity::Identity> {
    match <&[u8; 64]>::try_from(bytes) {
        Ok(key) => Some(rns_crypto::identity::Identity::from_private_key(key)),
        Err(_) => {
            let which = if bytes.len() < 32 {
                "An X25519 private key is 32 bytes long"
            } else {
                "An Ed25519 private key is 32 bytes long"
            };
            log(
                &format!("Failed to load identity key, the contained exception was: {which}"),
                LOG_ERROR,
            );
            None
        }
    }
}

/// `RNS.Identity.to_file` / `pub_to_file`: a failure is logged, not
/// raised.
pub fn key_to_file(key: &[u8], path: &str) {
    if let Err(e) = std::fs::write(path, key) {
        log(&format!("Error while saving identity to {path}"), LOG_ERROR);
        log(
            &format!("The contained exception was: {}", oserror(&e, path)),
            LOG_NOTICE,
        );
    }
}

/// `os.path.expanduser`.
pub fn expanduser(path: &str) -> String {
    if !path.starts_with('~') {
        return path.to_string();
    }
    let end = path[1..].find('/').map_or(path.len(), |i| i + 1);
    let home = if end == 1 {
        match std::env::var("HOME") {
            Ok(home) => home,
            Err(_) => return path.to_string(),
        }
    } else {
        match home_of(&path[1..end]) {
            Some(home) => home,
            None => return path.to_string(),
        }
    };
    let joined = format!("{}{}", home.trim_end_matches('/'), &path[end..]);
    if joined.is_empty() {
        "/".into()
    } else {
        joined
    }
}

/// `os.path.normpath` (POSIX): `.` and `..` resolved by name, not by
/// following links.
pub fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let initial = if path.starts_with("//") && !path.starts_with("///") {
        2
    } else if path.starts_with('/') {
        1
    } else {
        0
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if initial == 0 && (parts.is_empty() || parts.last() == Some(&"..")) {
                    parts.push("..");
                } else if !parts.is_empty() {
                    parts.pop();
                }
            }
            other => parts.push(other),
        }
    }
    let joined = format!("{}{}", "/".repeat(initial), parts.join("/"));
    if joined.is_empty() {
        ".".into()
    } else {
        joined
    }
}

/// `os.path.abspath`.
pub fn abspath(path: &str) -> String {
    if path.starts_with('/') {
        normpath(path)
    } else {
        let cwd = std::env::current_dir()
            .map(|d| d.to_string_lossy().into_owned())
            .unwrap_or_default();
        normpath(&format!("{cwd}/{path}"))
    }
}

/// `os.path.basename`.
pub fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
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
        let Some(v) = BASE64_EITHER.sextet(c) else {
            continue;
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
    BASE64_URL_SAFE.encode(data)
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
    fn paths_as_python_handles_them() {
        assert_eq!(normpath("/a/./b/../c//d/"), "/a/c/d");
        assert_eq!(normpath("a/../../b"), "../b");
        assert_eq!(normpath("/../a"), "/a");
        assert_eq!(normpath(""), ".");
        assert_eq!(normpath("//a"), "//a");
        assert_eq!(basename("/x/y.txt"), "y.txt");
        assert_eq!(basename("y/"), "");
        assert_eq!(expanduser("a/~"), "a/~");
    }

    #[test]
    fn named_users_home_from_the_password_database() {
        let root = home_of("root").expect("root is in the password database");
        assert!(root.starts_with('/'));
        assert_eq!(
            expanduser("~root/x"),
            format!("{}/x", root.trim_end_matches('/'))
        );
        assert_eq!(home_of("no-such-user-rns"), None);
        assert_eq!(expanduser("~no-such-user-rns/x"), "~no-such-user-rns/x");
        let threads: Vec<_> = (0..8)
            .map(|_| std::thread::spawn(|| (0..200).all(|_| home_of("root").is_some())))
            .collect();
        assert!(threads.into_iter().all(|t| t.join().unwrap()));
    }

    #[test]
    fn rns_levels_of_log_records() {
        let meta = |level, target| log::Metadata::builder().level(level).target(target).build();
        assert_eq!(
            rns_level(&meta(log::Level::Info, NOTICE_TARGET)),
            LOG_NOTICE
        );
        assert_eq!(rns_level(&meta(log::Level::Info, INFO_TARGET)), LOG_INFO);
        assert_eq!(
            rns_level(&meta(log::Level::Info, "rns_net::node")),
            LOG_VERBOSE
        );
        assert_eq!(rns_level(&meta(log::Level::Warn, "x")), LOG_WARNING);
        assert_eq!(rns_level(&meta(log::Level::Error, "x")), LOG_ERROR);
        assert_eq!(rns_level(&meta(log::Level::Trace, "x")), 8);
        assert_eq!(loglevelname(LOG_NOTICE), "[Notice]  ");
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
