//! What the driver tracks per interface.

use std::time::{Duration, Instant};

use super::{AsyncWriterMetrics, InterfaceStats, Writer};
use crate::ifac::IfacState;
use rns_core::transport::types::{InterfaceId, InterfaceInfo};

/// Everything the driver tracks per interface.
pub(crate) struct InterfaceEntry {
    /// Interface ID.
    pub id: InterfaceId,
    /// Transport-level description of the interface.
    pub info: InterfaceInfo,
    /// Writer frames are sent through.
    pub writer: Box<dyn Writer>,
    /// Counters of the async writer wrapping `writer`, when it has one.
    pub async_writer_metrics: Option<AsyncWriterMetrics>,
    /// Administrative enable/disable state.
    pub enabled: bool,
    /// Whether the interface is currently up.
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
    /// Next time a send should be retried after a transient WouldBlock.
    pub send_retry_at: Option<Instant>,
    /// Current retry backoff for transient send failures.
    pub send_retry_backoff: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_core::constants;
    use std::io;

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
                stamp_costs: Default::default(),
                id: InterfaceId(1),
                name: String::new(),
                mode: constants::MODE_FULL,
                gravity: 0,
                recursive_prs: false,
                announces_from_internal: true,
                announces_to_internal: None,
                out_capable: true,
                in_capable: true,
                bitrate: None,
                airtime_profile: None,
                announce_rate_target: None,
                announce_rate_grace: 0,
                announce_rate_penalty: 0.0,
                announce_cap: constants::ANNOUNCE_CAP,
                is_local_client: false,
                wants_tunnel: false,
                shared_medium: false,
                hop_limiter: None,
                tunnel_id: None,
                mtu: constants::MTU as u32,
                mtu_upgradable: false,
                ia_freq: 0.0,
                ia_samples: 0,
                ip_freq: 0.0,
                op_freq: 0.0,
                op_samples: 0,
                started: 0.0,
                ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
            },
            writer: Box::new(MockWriter::new()),
            async_writer_metrics: None,
            enabled: true,
            online: false,
            dynamic: false,
            ifac: None,
            stats: InterfaceStats::default(),
            interface_type: String::new(),
            send_retry_at: None,
            send_retry_backoff: Duration::ZERO,
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
