//! Shared process-local allocation for component-owned test listeners.

use std::sync::atomic::{AtomicU16, Ordering};

static NEXT_PORT: AtomicU16 = AtomicU16::new(0);

pub(crate) fn port() -> u16 {
    let pid = std::process::id() as u16;
    // Stay below Linux's default ephemeral range so client connections created by
    // parallel network tests cannot consume a component-owned listener port.
    let base = 10_000 + (pid % 200) * 100;
    let _ = NEXT_PORT.compare_exchange(0, base, Ordering::SeqCst, Ordering::SeqCst);
    // Skip ports another process already holds, such as a developer's
    // daemon or IDE listening in this range.
    loop {
        let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        if std::net::TcpListener::bind(("0.0.0.0", port)).is_ok()
            && std::net::UdpSocket::bind(("0.0.0.0", port)).is_ok()
        {
            return port;
        }
    }
}

/// A shared-instance name that is unique to this test process.
///
/// Local-interface tests bind abstract Unix sockets by instance name. Each
/// test in a process uses its own prefix, and the process id keeps parallel
/// test processes (nextest, concurrent CI jobs, a developer's running daemon)
/// from binding or connecting to each other's sockets. The same prefix yields
/// the same name within a process, so a test's server and client agree.
pub(crate) fn instance_name(prefix: &str) -> String {
    format!("{prefix}-{}", std::process::id())
}

/// A line the tests' logger captured: the thread that logged it, its level
/// and its message.
#[cfg(any(feature = "iface-tcp", feature = "iface-rnode"))]
pub(crate) type LoggedLine = (std::thread::ThreadId, log::Level, String);

/// Every line logged while this crate's unit tests run. The first call
/// installs the capturing logger, the only one these tests install.
#[cfg(any(feature = "iface-tcp", feature = "iface-rnode"))]
pub(crate) fn logged() -> &'static std::sync::Mutex<Vec<LoggedLine>> {
    use std::sync::{Mutex, Once, OnceLock};
    struct Capture;
    static LINES: OnceLock<Mutex<Vec<LoggedLine>>> = OnceLock::new();
    impl log::Log for Capture {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }
        fn log(&self, record: &log::Record<'_>) {
            if let Some(lines) = LINES.get() {
                lines.lock().unwrap().push((
                    std::thread::current().id(),
                    record.level(),
                    record.args().to_string(),
                ));
            }
        }
        fn flush(&self) {}
    }
    static CAPTURE: Capture = Capture;
    let lines = LINES.get_or_init(|| Mutex::new(Vec::new()));
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        log::set_logger(&CAPTURE).expect("no other logger in these tests");
        log::set_max_level(log::LevelFilter::Trace);
    });
    lines
}
