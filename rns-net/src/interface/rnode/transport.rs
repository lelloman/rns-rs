use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::io::AsRawFd;

use crate::serial::SerialConfig;
use crate::serial::SerialPort;

const DEFAULT_PORT: u32 = 7633;

#[derive(Debug)]
pub enum Transport {
    Serial(std::fs::File),
    Tcp(TcpStream),
}

impl Transport {
    pub fn open(
        config: &SerialConfig,
        underlay_mark: Option<u32>,
    ) -> io::Result<(Transport, Transport)> {
        if let Some(addr) = config.path.strip_prefix("tcp:") {
            let addr = if addr.contains(':') {
                addr.to_string()
            } else {
                format!("{}:{}", addr, DEFAULT_PORT)
            };

            let address = addr
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| io::Error::other("RNode TCP address did not resolve"))?;
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(address),
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;
            crate::interface::apply_underlay_mark(socket.as_raw_fd(), underlay_mark)?;
            socket.connect(&address.into())?;
            let stream: TcpStream = socket.into();
            let reader = stream.try_clone()?;
            Ok((Transport::Tcp(reader), Transport::Tcp(stream)))
        } else {
            let port = SerialPort::open(config)?;
            Ok((
                Transport::Serial(port.reader()?),
                Transport::Serial(port.writer()?),
            ))
        }
    }

    pub fn open_from_fd(fd: i32) -> io::Result<(Transport, Transport)> {
        let port = SerialPort::from_raw_fd(fd);
        let reader = port.reader()?;
        let writer = port.writer()?;
        std::mem::forget(port);
        Ok((Transport::Serial(reader), Transport::Serial(writer)))
    }
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Transport::Serial(f) => f.read(buf),
            Transport::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Transport::Serial(f) => f.write(buf),
            Transport::Tcp(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Transport::Serial(f) => f.flush(),
            Transport::Tcp(s) => s.flush(),
        }
    }
}

impl AsRawFd for Transport {
    fn as_raw_fd(&self) -> i32 {
        match self {
            Transport::Serial(f) => f.as_raw_fd(),
            Transport::Tcp(s) => s.as_raw_fd(),
        }
    }
}
