//! Network interface abstractions.

pub mod tcp;
pub mod tcp_server;
pub mod udp;
pub mod local;
pub mod serial_iface;
pub mod kiss_iface;
pub mod pipe;
pub mod rnode;
pub mod backbone;
pub mod auto;
pub mod i2p;

use std::io;

use rns_core::transport::types::{InterfaceId, InterfaceInfo};
use crate::ifac::IfacState;

/// Bind a socket to a specific network interface using `SO_BINDTODEVICE`.
///
/// Requires `CAP_NET_RAW` or root on Linux.
#[cfg(target_os = "linux")]
pub fn bind_to_device(fd: std::os::unix::io::RawFd, device: &str) -> io::Result<()> {
    let dev_bytes = device.as_bytes();
    if dev_bytes.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("device name too long: {}", device),
        ));
    }
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            dev_bytes.as_ptr() as *const libc::c_void,
            dev_bytes.len() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Writable end of an interface. Held by the driver.
///
/// Each implementation wraps a socket + framing.
pub trait Writer: Send {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()>;
}

pub use crate::common::interface_stats::{InterfaceStats, ANNOUNCE_SAMPLE_MAX};

use crate::common::management::InterfaceStatusView;

/// Everything the driver tracks per interface.
pub struct InterfaceEntry {
    pub id: InterfaceId,
    pub info: InterfaceInfo,
    pub writer: Box<dyn Writer>,
    pub online: bool,
    /// True for dynamically spawned interfaces (e.g. TCP server clients).
    /// These are fully removed on InterfaceDown rather than just marked offline.
    pub dynamic: bool,
    /// IFAC state for this interface, if access codes are enabled.
    pub ifac: Option<IfacState>,
    /// Traffic statistics.
    pub stats: InterfaceStats,
    /// Human-readable interface type string (e.g. "TCPClientInterface").
    pub interface_type: String,
}

impl InterfaceStatusView for InterfaceEntry {
    fn id(&self) -> InterfaceId { self.id }
    fn info(&self) -> &InterfaceInfo { &self.info }
    fn online(&self) -> bool { self.online }
    fn stats(&self) -> &InterfaceStats { &self.stats }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_core::constants;

    struct MockWriter {
        sent: Vec<Vec<u8>>,
    }

    impl MockWriter {
        fn new() -> Self {
            MockWriter { sent: Vec::new() }
        }
    }

    impl Writer for MockWriter {
        fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
            self.sent.push(data.to_vec());
            Ok(())
        }
    }

    #[test]
    fn interface_entry_construction() {
        let entry = InterfaceEntry {
            id: InterfaceId(1),
            info: InterfaceInfo {
                id: InterfaceId(1),
                name: String::new(),
                mode: constants::MODE_FULL,
                out_capable: true,
                in_capable: true,
                bitrate: None,
                announce_rate_target: None,
                announce_rate_grace: 0,
                announce_rate_penalty: 0.0,
                announce_cap: constants::ANNOUNCE_CAP,
                is_local_client: false,
                wants_tunnel: false,
                tunnel_id: None,
                mtu: constants::MTU as u32,
                ia_freq: 0.0,
                started: 0.0,
                ingress_control: false,
            },
            writer: Box::new(MockWriter::new()),
            online: false,
            dynamic: false,
            ifac: None,
            stats: InterfaceStats::default(),
            interface_type: String::new(),
        };
        assert_eq!(entry.id, InterfaceId(1));
        assert!(!entry.online);
        assert!(!entry.dynamic);
    }

    #[test]
    fn mock_writer_captures_bytes() {
        let mut writer = MockWriter::new();
        writer.send_frame(b"hello").unwrap();
        writer.send_frame(b"world").unwrap();
        assert_eq!(writer.sent.len(), 2);
        assert_eq!(writer.sent[0], b"hello");
        assert_eq!(writer.sent[1], b"world");
    }

    #[test]
    fn writer_send_frame_produces_output() {
        let mut writer = MockWriter::new();
        let data = vec![0x01, 0x02, 0x03];
        writer.send_frame(&data).unwrap();
        assert_eq!(writer.sent[0], data);
    }
}
