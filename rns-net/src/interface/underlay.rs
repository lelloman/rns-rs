//! Underlay socket options: VPN protection, device binding and firewall marks.

use std::io;
use std::sync::Arc;
#[cfg(all(target_os = "linux", feature = "iface-tcp"))]
use std::time::Duration;

/// Host callback used where every Reticulum underlay socket must be explicitly
/// excluded from an application VPN, notably Android `VpnService.protect()`.
pub trait SocketProtector: Send + Sync {
    /// Exclude the socket `fd` from the VPN before it is used.
    fn protect(&self, fd: std::os::unix::io::RawFd) -> io::Result<()>;
}

fn socket_protector_slot() -> &'static std::sync::RwLock<Option<Arc<dyn SocketProtector>>> {
    static SLOT: std::sync::OnceLock<std::sync::RwLock<Option<Arc<dyn SocketProtector>>>> =
        std::sync::OnceLock::new();
    SLOT.get_or_init(|| std::sync::RwLock::new(None))
}

/// Exclusive process-scoped socket protection registration.
///
/// Android VPN services should run their private node in a dedicated process.
/// A second registration fails instead of replacing a callback used by live
/// sockets.
pub struct SocketProtectorGuard {
    protector: Arc<dyn SocketProtector>,
}

/// Install `protector` for every underlay socket the process opens from now on.
///
/// Fails with [`io::ErrorKind::AlreadyExists`] while another guard is alive.
/// Dropping the returned guard uninstalls the protector.
pub fn install_socket_protector(
    protector: Arc<dyn SocketProtector>,
) -> io::Result<SocketProtectorGuard> {
    let mut slot = socket_protector_slot()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "an underlay socket protector is already installed",
        ));
    }
    *slot = Some(Arc::clone(&protector));
    Ok(SocketProtectorGuard { protector })
}

impl Drop for SocketProtectorGuard {
    fn drop(&mut self) {
        let mut slot = socket_protector_slot()
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot
            .as_ref()
            .is_some_and(|installed| Arc::ptr_eq(installed, &self.protector))
        {
            *slot = None;
        }
    }
}

fn protect_underlay_socket(fd: std::os::unix::io::RawFd) -> io::Result<()> {
    let protector = socket_protector_slot()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    if let Some(protector) = protector {
        protector.protect(fd)?;
    }
    Ok(())
}

/// Bind a socket to a specific network interface using `SO_BINDTODEVICE`.
///
/// Requires `CAP_NET_RAW` or root on Linux.
#[cfg(target_os = "linux")]
pub(crate) fn bind_to_device(fd: std::os::fd::BorrowedFd<'_>, device: &str) -> io::Result<()> {
    let dev_bytes = device.as_bytes();
    if dev_bytes.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("device name too long: {}", device),
        ));
    }
    socket2::SockRef::from(&fd).bind_device(Some(dev_bytes))
}

/// Apply a Linux firewall mark to an IP underlay socket.
///
/// The mark must be set before `connect()` so policy routing can keep Reticulum
/// underlay traffic outside application-level full tunnels. Configuring a mark
/// is fail-closed: callers must not silently create an unmarked socket when the
/// operation is not permitted.
#[cfg(target_os = "linux")]
pub(crate) fn apply_underlay_mark(
    fd: std::os::fd::BorrowedFd<'_>,
    mark: Option<u32>,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    protect_underlay_socket(fd.as_raw_fd())?;
    let Some(mark) = mark else {
        return Ok(());
    };
    socket2::SockRef::from(&fd).set_mark(mark)
}

#[cfg(not(target_os = "linux"))]
pub fn apply_underlay_mark(fd: std::os::fd::BorrowedFd<'_>, mark: Option<u32>) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    protect_underlay_socket(fd.as_raw_fd())?;
    if mark.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "underlay socket marks are only supported on Linux",
        ));
    }
    Ok(())
}

/// Connect a TCP socket after applying underlay routing options.
#[cfg(all(target_os = "linux", feature = "iface-tcp"))]
pub(crate) fn connect_tcp_with_options(
    addr: &std::net::SocketAddr,
    device: Option<&str>,
    underlay_mark: Option<u32>,
    timeout: Duration,
) -> io::Result<std::net::TcpStream> {
    use std::os::fd::AsFd;

    let socket = socket2::Socket::new(
        socket2::Domain::for_address(*addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    apply_underlay_mark(socket.as_fd(), underlay_mark)?;
    if let Some(device) = device {
        bind_to_device(socket.as_fd(), device)?;
    }
    socket.connect_timeout(&(*addr).into(), timeout)?;
    Ok(socket.into())
}

/// Validate at node startup that the configured mark can actually be applied.
pub(crate) fn validate_underlay_mark(mark: Option<u32>) -> io::Result<()> {
    let Some(_) = mark else {
        return Ok(());
    };
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    use std::os::fd::AsFd;
    apply_underlay_mark(socket.as_fd(), mark)
}

#[cfg(test)]
mod socket_protector_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    struct CountingProtector(Arc<AtomicUsize>);
    impl SocketProtector for CountingProtector {
        fn protect(&self, _fd: std::os::unix::io::RawFd) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn underlay_helper_invokes_installed_protector_without_mark() {
        use std::os::fd::AsFd;
        let _lock = TEST_LOCK.lock().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let _guard =
            install_socket_protector(Arc::new(CountingProtector(Arc::clone(&calls)))).unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        apply_underlay_mark(socket.as_fd(), None).unwrap();
        assert!(calls.load(Ordering::Relaxed) >= 1);
    }
}
