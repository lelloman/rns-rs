use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::fd::AsFd;
use std::os::unix::io::AsRawFd;

use crate::serial::SerialConfig;
use crate::serial::SerialPort;

const DEFAULT_PORT: u32 = 7633;

#[derive(Debug)]
pub enum Transport {
    Serial(std::fs::File),
    Tcp(TcpStream),
    /// The device's notifications over BLE, read from the descriptor
    /// BlueZ hands over.
    #[cfg(feature = "iface-rnode-ble")]
    BleNotify(std::fs::File, std::sync::Arc<super::ble::Session>),
    /// Writes to the device over BLE.
    #[cfg(feature = "iface-rnode-ble")]
    BleWrite(std::sync::Arc<super::ble::Session>),
    /// No connection: the device could not be opened yet. Reads and
    /// writes fail; its descriptor is -1.
    Offline,
}

fn offline() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "the device is not open")
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
            crate::interface::apply_underlay_mark(socket.as_fd(), underlay_mark)?;
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

    /// Find and connect the RNode `target` names over BLE, for the
    /// interface upstream calls `iface`.
    #[cfg(feature = "iface-rnode-ble")]
    pub(super) fn open_ble(
        target: &super::ble::Target,
        iface: &str,
        state: &super::ble::SharedLinkState,
        budget: std::time::Duration,
    ) -> io::Result<(Transport, Transport)> {
        let (notify, session) = super::ble::open(target, iface, state, budget)?;
        Ok((
            Transport::BleNotify(notify, std::sync::Arc::clone(&session)),
            Transport::BleWrite(session),
        ))
    }

    /// Without BLE support built in, a BLE port cannot be opened.
    #[cfg(not(feature = "iface-rnode-ble"))]
    pub(super) fn open_ble(
        _target: &super::ble::Target,
        _iface: &str,
        _state: &super::ble::SharedLinkState,
        _budget: std::time::Duration,
    ) -> io::Result<(Transport, Transport)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this build has no BLE support (the iface-rnode-ble feature)",
        ))
    }

    /// End the connection as upstream closes it: a BLE device is
    /// disconnected. Other connections close when dropped.
    pub fn close(&self) {
        match self {
            #[cfg(feature = "iface-rnode-ble")]
            Transport::BleNotify(_, session) | Transport::BleWrite(session) => session.close(),
            _ => {}
        }
    }

    /// End the connection as [`Self::close`] does, letting `read` read
    /// what the device answers while a BLE device disconnects. Other
    /// connections are not read: they close when dropped.
    pub fn close_reading(&self, read: impl FnOnce(&mut std::fs::File)) {
        match self {
            #[cfg(feature = "iface-rnode-ble")]
            Transport::BleNotify(_, session) | Transport::BleWrite(session) => {
                session.close_reading(read)
            }
            _ => drop(read),
        }
    }

    /// Note that the device dropped the connection.
    pub fn lost(&self) {
        match self {
            #[cfg(feature = "iface-rnode-ble")]
            Transport::BleNotify(_, session) | Transport::BleWrite(session) => session.lost(),
            _ => {}
        }
    }

    /// Reader and writer on duplicates of `fd`, which stays the caller's:
    /// it is not closed here.
    pub fn open_from_fd(fd: i32) -> io::Result<(Transport, Transport)> {
        let reader = crate::serial::dup_fd(fd)?;
        let writer = crate::serial::dup_fd(fd)?;
        Ok((
            Transport::Serial(reader.into()),
            Transport::Serial(writer.into()),
        ))
    }
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Transport::Serial(f) => f.read(buf),
            Transport::Tcp(s) => s.read(buf),
            #[cfg(feature = "iface-rnode-ble")]
            Transport::BleNotify(f, _) => f.read(buf),
            #[cfg(feature = "iface-rnode-ble")]
            Transport::BleWrite(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the BLE write side is not read",
            )),
            Transport::Offline => Err(offline()),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Transport::Serial(f) => f.write(buf),
            Transport::Tcp(s) => s.write(buf),
            #[cfg(feature = "iface-rnode-ble")]
            Transport::BleNotify(_, session) | Transport::BleWrite(session) => session.write(buf),
            Transport::Offline => Err(offline()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Transport::Serial(f) => f.flush(),
            Transport::Tcp(s) => s.flush(),
            #[cfg(feature = "iface-rnode-ble")]
            Transport::BleNotify(..) | Transport::BleWrite(_) => Ok(()),
            Transport::Offline => Ok(()),
        }
    }
}

impl AsRawFd for Transport {
    fn as_raw_fd(&self) -> i32 {
        match self {
            Transport::Serial(f) => f.as_raw_fd(),
            Transport::Tcp(s) => s.as_raw_fd(),
            #[cfg(feature = "iface-rnode-ble")]
            Transport::BleNotify(f, _) => f.as_raw_fd(),
            #[cfg(feature = "iface-rnode-ble")]
            Transport::BleWrite(session) => session.fd(),
            Transport::Offline => -1,
        }
    }
}
