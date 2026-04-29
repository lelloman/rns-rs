use std::io::{self, Read, Write};
use std::net::TcpStream;

use crate::serial::SerialConfig;
use crate::serial::SerialPort;

const DEFAULT_PORT: u32 = 7633;

#[derive(Debug)]
pub enum Transport {
    Serial(std::fs::File),
    Tcp(TcpStream),
}

impl Transport {
    pub fn open(config: &SerialConfig) -> io::Result<(Transport, Transport)> {
        if let Some(addr) = config.path.strip_prefix("tcp:") {
            let addr = if addr.contains(':') {
                addr.to_string()
            } else {
                format!("{}:{}", addr, DEFAULT_PORT)
            };

            let stream = TcpStream::connect(addr)?;
            let reader = stream.try_clone()?;
            Ok((Transport::Tcp(reader), Transport::Tcp(stream)))
        } else {
            let port = SerialPort::open(&config)?;
            Ok((
                Transport::Serial(port.reader()?),
                Transport::Serial(port.writer()?),
            ))
        }
    }

    pub fn open_from_fd(fd: i32) -> io::Result<(Transport, Transport)> {
        let port = SerialPort::from_raw_fd(fd);
        Ok((
            Transport::Serial(port.reader()?),
            Transport::Serial(port.writer()?),
        ))
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
