//! Safe wrappers for the plain operating system queries the utilities make
//! through `libc`. What stays outside is inherently unsafe to wrap: signal
//! handlers (which must be async-signal-safe), rnsh's fork, exec and pty
//! handling, and `pre_exec` hooks.
#![allow(unsafe_code, reason = "libc queries, behind safe wrappers")]

use std::ffi::{CStr, CString};

/// The width of the terminal on stdout, if stdout is a terminal that
/// reports one.
pub(crate) fn stdout_columns() -> Option<usize> {
    // SAFETY: `winsize` is a plain C struct of integers, for which all-zero
    // bytes are a valid value.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ fills the live `winsize` passed; on failure it is
    // left zeroed.
    let ok = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } == 0;
    (ok && size.ws_col > 0).then_some(size.ws_col as usize)
}

/// `secs` since the epoch as local broken-down time (`localtime_r`).
pub(crate) fn localtime(secs: libc::time_t) -> Option<libc::tm> {
    // SAFETY: `libc::tm` is a plain C struct of integers plus a nullable
    // `tm_zone` pointer; all-zero bytes are a valid value.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `secs` and `tm` are live locals; the reentrant `localtime_r`
    // only reads one and writes the other, using no shared static buffer.
    let ok = !unsafe { libc::localtime_r(&secs, &mut tm) }.is_null();
    ok.then_some(tm)
}

/// The home directory of `user` in the password database. Uses the
/// reentrant lookup: other threads may be resolving users too.
pub(crate) fn home_of(user: &str) -> Option<String> {
    let name = CString::new(user).ok()?;
    let mut buf = vec![0 as libc::c_char; 1024];
    loop {
        // SAFETY: an all-zero passwd is a valid value for these plain C
        // fields; getpwnam_r fills it, pointing into `buf`.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call and `buf.len()` is
        // the buffer's real size.
        let rc = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                &mut entry,
                buf.as_mut_ptr(),
                buf.len(),
                &mut found,
            )
        };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || found.is_null() || entry.pw_dir.is_null() {
            return None;
        }
        // SAFETY: on success pw_dir points to a NUL-terminated string in
        // `buf`, which is alive here.
        let dir = unsafe { CStr::from_ptr(entry.pw_dir) };
        return Some(dir.to_string_lossy().into_owned());
    }
}

/// The login shell of the user running this process
/// (`pwd.getpwuid(os.getuid()).pw_shell`).
pub(crate) fn login_shell() -> Option<String> {
    // SAFETY: getpwuid returns null or a pointer into static storage, read
    // at once; this is only called from one thread.
    unsafe {
        let entry = libc::getpwuid(libc::getuid());
        if entry.is_null() || (*entry).pw_shell.is_null() {
            return None;
        }
        Some(
            CStr::from_ptr((*entry).pw_shell)
                .to_string_lossy()
                .into_owned(),
        )
    }
}

/// Whether this process may write to `path` (`access(path, W_OK)`).
pub(crate) fn is_writable(path: &str) -> bool {
    CString::new(path)
        // SAFETY: `c` is a NUL-terminated CString that outlives the call;
        // `access` only reads the path.
        .map(|c| unsafe { libc::access(c.as_ptr(), libc::W_OK) } == 0)
        .unwrap_or(false)
}

/// The process id of the peer of a Unix stream socket (`SO_PEERCRED`).
#[cfg(all(feature = "sidecars", target_os = "linux"))]
pub(crate) fn peer_pid(stream: &std::os::unix::net::UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the stream owns a valid socket descriptor, and credentials and
    // length point to writable storage of the size passed to getsockopt.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return None;
    }
    u32::try_from(credentials.pid).ok().filter(|pid| *pid != 0)
}

/// A system configuration value (`sysconf`), such as `_SC_PAGESIZE`.
#[cfg(feature = "sidecars")]
pub(crate) fn sysconf(name: libc::c_int) -> libc::c_long {
    // SAFETY: `sysconf` takes no pointers and only queries a system constant.
    unsafe { libc::sysconf(name) }
}

/// Send `signal` to the process `pid`, or to the process group `-pid`
/// (`kill`). Failure is ignored, as when the target has already exited.
pub(crate) fn kill(pid: libc::pid_t, signal: libc::c_int) {
    // SAFETY: `kill` takes no pointers.
    unsafe {
        libc::kill(pid, signal);
    }
}
