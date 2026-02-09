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

use std::io;

use rns_core::transport::types::{InterfaceId, InterfaceInfo};
use crate::ifac::IfacState;

/// Writable end of an interface. Held by the driver.
///
/// Each implementation wraps a socket + framing.
pub trait Writer: Send {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()>;
}

/// Maximum number of announce timestamps to keep per direction.
const ANNOUNCE_SAMPLE_MAX: usize = 6;

/// Traffic statistics for an interface.
#[derive(Debug, Clone, Default)]
pub struct InterfaceStats {
    pub rxb: u64,
    pub txb: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub started: f64,
    /// Recent incoming announce timestamps (bounded).
    pub ia_timestamps: Vec<f64>,
    /// Recent outgoing announce timestamps (bounded).
    pub oa_timestamps: Vec<f64>,
}

impl InterfaceStats {
    /// Record an incoming announce timestamp.
    pub fn record_incoming_announce(&mut self, now: f64) {
        self.ia_timestamps.push(now);
        if self.ia_timestamps.len() > ANNOUNCE_SAMPLE_MAX {
            self.ia_timestamps.remove(0);
        }
    }

    /// Record an outgoing announce timestamp.
    pub fn record_outgoing_announce(&mut self, now: f64) {
        self.oa_timestamps.push(now);
        if self.oa_timestamps.len() > ANNOUNCE_SAMPLE_MAX {
            self.oa_timestamps.remove(0);
        }
    }

    /// Compute announce frequency (per second) from timestamps.
    fn compute_frequency(timestamps: &[f64]) -> f64 {
        if timestamps.len() < 2 {
            return 0.0;
        }
        let span = timestamps[timestamps.len() - 1] - timestamps[0];
        if span <= 0.0 {
            return 0.0;
        }
        (timestamps.len() - 1) as f64 / span
    }

    /// Incoming announce frequency (per second).
    pub fn incoming_announce_freq(&self) -> f64 {
        Self::compute_frequency(&self.ia_timestamps)
    }

    /// Outgoing announce frequency (per second).
    pub fn outgoing_announce_freq(&self) -> f64 {
        Self::compute_frequency(&self.oa_timestamps)
    }
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
                announce_cap: constants::ANNOUNCE_CAP,
                is_local_client: false,
                wants_tunnel: false,
                tunnel_id: None,
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
