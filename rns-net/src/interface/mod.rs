//! Network interface abstractions.

#[cfg(feature = "iface-auto")]
pub mod auto;
#[cfg(feature = "iface-backbone")]
pub mod backbone;
#[cfg(feature = "iface-i2p")]
pub mod i2p;
#[cfg(feature = "iface-kiss")]
pub mod kiss_iface;
#[cfg(feature = "iface-local")]
pub mod local;
#[cfg(feature = "iface-pipe")]
pub mod pipe;
pub mod registry;
#[cfg(feature = "iface-rnode")]
pub mod rnode;
#[cfg(feature = "iface-serial")]
pub mod serial_iface;
#[cfg(feature = "iface-tcp")]
pub mod tcp;
#[cfg(feature = "iface-tcp")]
pub mod tcp_server;
#[cfg(feature = "iface-udp")]
pub mod udp;

use std::any::Any;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::event::EventSender;
use crate::ifac::IfacState;
use rns_core::transport::types::{InterfaceId, InterfaceInfo};

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
    /// Administrative enable/disable state.
    pub enabled: bool,
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

/// Result of starting an interface via a factory.
pub enum StartResult {
    /// One writer, registered immediately (TcpClient, Udp, Serial, etc.)
    Simple {
        id: InterfaceId,
        info: InterfaceInfo,
        writer: Box<dyn Writer>,
        interface_type_name: String,
    },
    /// Spawns a listener; dynamic interfaces arrive via Event::InterfaceUp (TcpServer, Auto, I2P, etc.)
    Listener,
    /// Multiple subinterfaces from one config (RNode).
    Multi(Vec<SubInterface>),
}

/// A single subinterface returned from a multi-interface factory.
pub struct SubInterface {
    pub id: InterfaceId,
    pub info: InterfaceInfo,
    pub writer: Box<dyn Writer>,
    pub interface_type_name: String,
}

/// Context passed to [`InterfaceFactory::start()`].
pub struct StartContext {
    pub tx: EventSender,
    pub next_dynamic_id: Arc<AtomicU64>,
    pub mode: u8,
}

/// Opaque interface config data. Each factory downcasts to its concrete type.
pub trait InterfaceConfigData: Send + Any {
    fn as_any(&self) -> &dyn Any;
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

impl<T: Send + 'static> InterfaceConfigData for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Factory that can parse config and start an interface type.
pub trait InterfaceFactory: Send + Sync {
    /// Config-file type name, e.g. "TCPClientInterface".
    fn type_name(&self) -> &str;

    /// Default IFAC size (bytes). 8 for serial/kiss/rnode, 16 for others.
    fn default_ifac_size(&self) -> usize {
        16
    }

    /// Parse from key-value params (config file or external).
    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String>;

    /// Start the interface from parsed config.
    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> io::Result<StartResult>;
}

impl InterfaceStatusView for InterfaceEntry {
    fn id(&self) -> InterfaceId {
        self.id
    }
    fn info(&self) -> &InterfaceInfo {
        &self.info
    }
    fn online(&self) -> bool {
        self.online
    }
    fn stats(&self) -> &InterfaceStats {
        &self.stats
    }
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
