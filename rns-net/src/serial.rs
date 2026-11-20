//! Serial port abstraction using libc termios.
//!
//! Provides raw serial I/O without external crate dependencies.

#![allow(unsafe_code, reason = "OS calls through libc")]

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
#[cfg(any(feature = "iface-serial", feature = "iface-kiss"))]
use std::time::Duration;

/// Serial port parity setting.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Parity {
    /// No parity bit.
    None,
    /// Even parity.
    Even,
    /// Odd parity.
    Odd,
}

/// Configuration for a serial port.
#[derive(Debug, Clone)]
pub struct SerialConfig {
    /// Device path, e.g. `/dev/ttyUSB0`.
    pub path: String,
    /// Baud rate; must be one of the rates the port supports.
    pub baud: u32,
    /// Data bits per character: 5, 6 or 7; any other value means 8.
    pub data_bits: u8,
    /// Parity setting.
    pub parity: Parity,
    /// Stop bits: 2 means two, any other value means one.
    pub stop_bits: u8,
}

impl Default for SerialConfig {
    fn default() -> Self {
        SerialConfig {
            path: String::new(),
            baud: 9600,
            data_bits: 8,
            parity: Parity::None,
            stop_bits: 1,
        }
    }
}

/// A serial port backed by a file descriptor it owns.
pub struct SerialPort {
    fd: OwnedFd,
}

impl SerialPort {
    /// Wrap an already open file descriptor (e.g. from a USB bridge
    /// socketpair), taking ownership of it. No termios configuration is
    /// applied: the fd is used as is.
    pub fn from_owned_fd(fd: OwnedFd) -> Self {
        SerialPort { fd }
    }

    /// Open and configure a serial port.
    pub fn open(config: &SerialConfig) -> io::Result<Self> {
        let c_path = std::ffi::CString::new(config.path.as_str())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid path"))?;

        // SAFETY: `c_path` is a live `CString`, so the pointer is NUL-terminated and
        // valid for the call.
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: open just returned this fd and nothing else owns it. From
        // here on it is closed when `fd` drops, after any error is read.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let raw = fd.as_raw_fd();

        // Configure termios
        // SAFETY: `termios` is a plain C struct of integers and integer arrays, for
        // which all-zero bytes are a valid value.
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `raw` is the fd owned by `fd`, open for this whole function, and
        // `termios` is a live, exclusively borrowed `termios`.
        if unsafe { libc::tcgetattr(raw, &mut termios) } != 0 {
            return Err(io::Error::last_os_error());
        }

        // cfmakeraw equivalent
        termios.c_iflag &= !(libc::IGNBRK
            | libc::BRKINT
            | libc::PARMRK
            | libc::ISTRIP
            | libc::INLCR
            | libc::IGNCR
            | libc::ICRNL
            | libc::IXON);
        termios.c_oflag &= !libc::OPOST;
        termios.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
        termios.c_cflag &= !(libc::CSIZE | libc::PARENB);
        termios.c_cflag |= libc::CS8;

        // Data bits
        termios.c_cflag &= !libc::CSIZE;
        termios.c_cflag |= match config.data_bits {
            5 => libc::CS5,
            6 => libc::CS6,
            7 => libc::CS7,
            _ => libc::CS8,
        };

        // Parity
        match config.parity {
            Parity::None => {
                termios.c_cflag &= !libc::PARENB;
            }
            Parity::Even => {
                termios.c_cflag |= libc::PARENB;
                termios.c_cflag &= !libc::PARODD;
            }
            Parity::Odd => {
                termios.c_cflag |= libc::PARENB;
                termios.c_cflag |= libc::PARODD;
            }
        }

        // Stop bits
        if config.stop_bits == 2 {
            termios.c_cflag |= libc::CSTOPB;
        } else {
            termios.c_cflag &= !libc::CSTOPB;
        }

        // Disable flow control and hangup-on-close (HUPCL drops DTR on
        // close, which resets devices that wire DTR to RST like Heltec V3).
        termios.c_cflag |= libc::CLOCAL | libc::CREAD;
        termios.c_cflag &= !(libc::CRTSCTS | libc::HUPCL);
        termios.c_iflag &= !(libc::IXON | libc::IXOFF | libc::IXANY);

        // Baud rate
        let speed = baud_to_speed(config.baud)?;
        // SAFETY: both calls only write the speed fields of `termios`, a live,
        // exclusively borrowed local.
        unsafe {
            libc::cfsetispeed(&mut termios, speed);
            libc::cfsetospeed(&mut termios, speed);
        }

        // Blocking read with VMIN=1, VTIME=0
        termios.c_cc[libc::VMIN] = 1;
        termios.c_cc[libc::VTIME] = 0;

        // SAFETY: `raw` is the fd owned by `fd`, still open, and `termios` is a live
        // local the call only reads.
        if unsafe { libc::tcsetattr(raw, libc::TCSANOW, &termios) } != 0 {
            return Err(io::Error::last_os_error());
        }

        // Clear O_NONBLOCK for blocking reads
        // SAFETY: F_GETFL takes no pointer argument; `raw` is owned by `fd`, still open.
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: F_SETFL takes an integer argument; `raw` is owned by `fd`, still open.
        if unsafe { libc::fcntl(raw, libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(SerialPort { fd })
    }

    /// Get the raw fd.
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Get a Read handle (File wrapping a duplicate of the fd).
    pub fn reader(&self) -> io::Result<std::fs::File> {
        Ok(self.fd.try_clone()?.into())
    }

    /// Get a Write handle (File wrapping a duplicate of the fd).
    pub fn writer(&self) -> io::Result<std::fs::File> {
        Ok(self.fd.try_clone()?.into())
    }
}

impl AsFd for SerialPort {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for SerialPort {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Duplicate a file descriptor the caller keeps owning, such as one the
/// process inherited. The duplicate is owned by the result; an fd that is
/// not open is reported as an error.
pub fn dup_fd(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC takes an integer argument and does not consume `fd`;
    // a closed `fd` only makes the call fail with EBADF, reported below.
    let new_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if new_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl just created this fd and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
}

/// Map baud rate u32 to libc speed_t constant.
fn baud_to_speed(baud: u32) -> io::Result<libc::speed_t> {
    match baud {
        0 => Ok(libc::B0),
        50 => Ok(libc::B50),
        75 => Ok(libc::B75),
        110 => Ok(libc::B110),
        134 => Ok(libc::B134),
        150 => Ok(libc::B150),
        200 => Ok(libc::B200),
        300 => Ok(libc::B300),
        600 => Ok(libc::B600),
        1200 => Ok(libc::B1200),
        1800 => Ok(libc::B1800),
        2400 => Ok(libc::B2400),
        4800 => Ok(libc::B4800),
        9600 => Ok(libc::B9600),
        19200 => Ok(libc::B19200),
        38400 => Ok(libc::B38400),
        57600 => Ok(libc::B57600),
        115200 => Ok(libc::B115200),
        230400 => Ok(libc::B230400),
        #[cfg(target_os = "linux")]
        460800 => Ok(libc::B460800),
        #[cfg(target_os = "linux")]
        500000 => Ok(libc::B500000),
        #[cfg(target_os = "linux")]
        576000 => Ok(libc::B576000),
        #[cfg(target_os = "linux")]
        921600 => Ok(libc::B921600),
        #[cfg(target_os = "linux")]
        1000000 => Ok(libc::B1000000),
        #[cfg(target_os = "linux")]
        1152000 => Ok(libc::B1152000),
        #[cfg(target_os = "linux")]
        1500000 => Ok(libc::B1500000),
        #[cfg(target_os = "linux")]
        2000000 => Ok(libc::B2000000),
        #[cfg(target_os = "linux")]
        2500000 => Ok(libc::B2500000),
        #[cfg(target_os = "linux")]
        3000000 => Ok(libc::B3000000),
        #[cfg(target_os = "linux")]
        3500000 => Ok(libc::B3500000),
        #[cfg(target_os = "linux")]
        4000000 => Ok(libc::B4000000),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported baud rate: {}", baud),
        )),
    }
}

/// Reopen a serial port the reader thread lost, for the Serial and KISS
/// interfaces (`kind` names it in the log): every 5 seconds, open it,
/// wait `settle`, then `prepare` its writer, until that works or the
/// interface stops. Returns the reader and the writer.
#[cfg(any(feature = "iface-serial", feature = "iface-kiss"))]
pub(crate) fn reopen_serial_port(
    name: &str,
    kind: &str,
    serial_config: &SerialConfig,
    control: &crate::interface::ListenerControl,
    settle: Duration,
    mut prepare: impl FnMut(&mut std::fs::File) -> io::Result<()>,
) -> Option<(std::fs::File, std::fs::File)> {
    loop {
        if !crate::interface::wait_while_active(control, Duration::from_secs(5)) {
            return None;
        }
        log::info!(
            "[{}] attempting to reconnect {} port {}...",
            name,
            kind,
            serial_config.path
        );
        match SerialPort::open(serial_config) {
            Ok(port) => match (port.reader(), port.writer()) {
                (Ok(reader), Ok(mut writer)) => {
                    if !crate::interface::wait_while_active(control, settle) {
                        return None;
                    }
                    if let Err(e) = prepare(&mut writer) {
                        log::warn!("[{}] {} port setup failed: {}", name, kind, e);
                        continue;
                    }
                    return Some((reader, writer));
                }
                _ => log::warn!("[{}] failed to get handles from {} port", name, kind),
            },
            Err(e) => log::warn!("[{}] {} reconnect failed: {}", name, kind, e),
        }
    }
}

/// Create a pseudo-terminal pair for testing. Returns (master_fd, slave_fd).
///
/// The master and slave are configured for raw mode to avoid terminal processing.
#[cfg(test)]
pub fn open_pty_pair() -> io::Result<(RawFd, RawFd)> {
    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;
    let ret = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    // Set both sides to raw mode to avoid terminal character processing
    for fd in [master, slave] {
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        unsafe { libc::tcgetattr(fd, &mut termios) };
        // cfmakeraw equivalent
        termios.c_iflag &= !(libc::IGNBRK
            | libc::BRKINT
            | libc::PARMRK
            | libc::ISTRIP
            | libc::INLCR
            | libc::IGNCR
            | libc::ICRNL
            | libc::IXON);
        termios.c_oflag &= !libc::OPOST;
        termios.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
        termios.c_cflag &= !(libc::CSIZE | libc::PARENB);
        termios.c_cflag |= libc::CS8;
        termios.c_cc[libc::VMIN] = 1;
        termios.c_cc[libc::VTIME] = 0;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) };
    }

    Ok((master, slave))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn open_pty_pair_works() {
        let (master, slave) = open_pty_pair().unwrap();
        assert!(master >= 0);
        assert!(slave >= 0);
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
    }

    #[test]
    fn write_read_roundtrip() {
        let (master, slave) = open_pty_pair().unwrap();

        let mut master_file = unsafe { std::fs::File::from_raw_fd(master) };
        let mut slave_file = unsafe { std::fs::File::from_raw_fd(slave) };

        let data = b"hello serial";
        master_file.write_all(data).unwrap();
        master_file.flush().unwrap();

        // Poll with timeout to avoid blocking forever
        let mut pfd = libc::pollfd {
            fd: slave,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, 2000) };
        assert!(ret > 0, "should have data available on slave");

        let mut buf = [0u8; 64];
        let n = slave_file.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], data);
    }

    #[test]
    fn config_baud_rates() {
        // Verify common baud rates map successfully
        for &baud in &[9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600] {
            let speed = baud_to_speed(baud);
            assert!(speed.is_ok(), "baud {} should be supported", baud);
        }
    }

    #[test]
    fn from_owned_fd_works() {
        let (master, slave) = open_pty_pair().unwrap();

        let port = SerialPort::from_owned_fd(unsafe { OwnedFd::from_raw_fd(slave) });
        let mut writer = port.writer().unwrap();
        let mut reader_file = unsafe { std::fs::File::from_raw_fd(master) };

        let data = b"from_owned_fd test";
        writer.write_all(data).unwrap();
        writer.flush().unwrap();

        let mut pfd = libc::pollfd {
            fd: master,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, 2000) };
        assert!(ret > 0, "should have data available");

        let mut buf = [0u8; 64];
        let n = reader_file.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], data);
    }

    #[test]
    fn dup_fd_leaves_the_original_open() {
        let (master, slave) = open_pty_pair().unwrap();
        let copy = dup_fd(slave).unwrap();
        drop(copy);
        assert!(unsafe { libc::fcntl(slave, libc::F_GETFD) } >= 0);
        assert!(dup_fd(-1).is_err());
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
    }

    #[test]
    fn invalid_path_fails() {
        let config = SerialConfig {
            path: "/dev/nonexistent_serial_port_xyz".into(),
            ..Default::default()
        };
        let result = SerialPort::open(&config);
        assert!(result.is_err());
    }
}
