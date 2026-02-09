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

use std::io;

use rns_core::transport::types::{InterfaceId, InterfaceInfo};
use crate::ifac::IfacState;

/// Writable end of an interface. Held by the driver.
///
/// Each implementation wraps a socket + framing.
pub trait Writer: Send {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()>;
}

/// Traffic statistics for an interface.
#[derive(Debug, Clone, Default)]
pub struct InterfaceStats {
    pub rxb: u64,
    pub txb: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub started: f64,
}

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
            },
            writer: Box::new(MockWriter::new()),
            online: false,
            dynamic: false,
            ifac: None,
            stats: InterfaceStats::default(),
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
