//! Network interface abstractions.

pub mod tcp;
pub mod tcp_server;
pub mod udp;
pub mod local;

use std::io;

use rns_core::transport::types::{InterfaceId, InterfaceInfo};

/// Writable end of an interface. Held by the driver.
///
/// Each implementation wraps a socket + framing.
pub trait Writer: Send {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()>;
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
