//! Serial port abstraction using libc termios.
//!
//! Provides raw serial I/O without external crate dependencies.

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

/// Serial port parity setting.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Parity {
    None,
    Even,
    Odd,
}

/// Configuration for a serial port.
#[derive(Debug, Clone)]
pub struct SerialConfig {
    pub path: String,
    pub baud: u32,
    pub data_bits: u8,
    pub parity: Parity,
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

/// A serial port backed by a file descriptor.
pub struct SerialPort {
    fd: RawFd,
}

impl SerialPort {
    /// Open and configure a serial port.
    pub fn open(config: &SerialConfig) -> io::Result<Self> {
        let c_path = std::ffi::CString::new(config.path.as_str())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid path"))?;

        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Configure termios
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut termios) } != 0 {
            unsafe { libc::close(fd) };
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

        // Disable flow control
        termios.c_cflag |= libc::CLOCAL | libc::CREAD;
        termios.c_iflag &= !(libc::IXON | libc::IXOFF | libc::IXANY);
        termios.c_cflag &= !libc::CRTSCTS;

        // Baud rate
        let speed = baud_to_speed(config.baud)?;
        unsafe {
            libc::cfsetispeed(&mut termios, speed);
            libc::cfsetospeed(&mut termios, speed);
        }

        // Blocking read with VMIN=1, VTIME=0
        termios.c_cc[libc::VMIN] = 1;
        termios.c_cc[libc::VTIME] = 0;

        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) } != 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        // Clear O_NONBLOCK for blocking reads
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        Ok(SerialPort { fd })
    }

    /// Get the raw fd.
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Get a Read handle (File wrapping a dup'd fd).
    pub fn reader(&self) -> io::Result<std::fs::File> {
        let new_fd = unsafe { libc::dup(self.fd) };
        if new_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { std::fs::File::from_raw_fd(new_fd) })
    }

    /// Get a Write handle (File wrapping a dup'd fd).
    pub fn writer(&self) -> io::Result<std::fs::File> {
        let new_fd = unsafe { libc::dup(self.fd) };
        if new_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { std::fs::File::from_raw_fd(new_fd) })
    }
}

impl AsRawFd for SerialPort {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for SerialPort {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
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
        460800 => Ok(libc::B460800),
        500000 => Ok(libc::B500000),
        576000 => Ok(libc::B576000),
        921600 => Ok(libc::B921600),
        1000000 => Ok(libc::B1000000),
        1152000 => Ok(libc::B1152000),
        1500000 => Ok(libc::B1500000),
        2000000 => Ok(libc::B2000000),
        2500000 => Ok(libc::B2500000),
        3000000 => Ok(libc::B3000000),
        3500000 => Ok(libc::B3500000),
        4000000 => Ok(libc::B4000000),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported baud rate: {}", baud),
        )),
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
    fn invalid_path_fails() {
        let config = SerialConfig {
            path: "/dev/nonexistent_serial_port_xyz".into(),
            ..Default::default()
        };
        let result = SerialPort::open(&config);
        assert!(result.is_err());
    }
}
