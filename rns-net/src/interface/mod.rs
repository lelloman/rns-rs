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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread;
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

pub const DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY: usize = 256;

#[derive(Clone, Default)]
pub struct ListenerControl {
    stop: Arc<AtomicBool>,
}

impl ListenerControl {
    pub fn new() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Default)]
pub struct AsyncWriterMetrics {
    queued_frames: Arc<AtomicUsize>,
    worker_alive: Arc<AtomicBool>,
}

impl AsyncWriterMetrics {
    pub fn queued_frames(&self) -> usize {
        self.queued_frames.load(Ordering::Relaxed)
    }

    pub fn worker_alive(&self) -> bool {
        self.worker_alive.load(Ordering::Relaxed)
    }
}

struct AsyncWriter {
    tx: SyncSender<Vec<u8>>,
    metrics: AsyncWriterMetrics,
}

impl Writer for AsyncWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        if !self.metrics.worker_alive() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "interface writer worker is offline",
            ));
        }

        match self.tx.try_send(data.to_vec()) {
            Ok(()) => {
                self.metrics.queued_frames.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(TrySendError::Full(_)) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "interface writer queue is full",
            )),
            Err(TrySendError::Disconnected(_)) => {
                self.metrics
                    .worker_alive
                    .store(false, Ordering::Relaxed);
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "interface writer worker disconnected",
                ))
            }
        }
    }
}

pub fn wrap_async_writer(
    writer: Box<dyn Writer>,
    interface_id: InterfaceId,
    interface_name: &str,
    event_tx: EventSender,
    queue_capacity: usize,
) -> (Box<dyn Writer>, AsyncWriterMetrics) {
    let (tx, rx) = sync_channel::<Vec<u8>>(queue_capacity.max(1));
    let metrics = AsyncWriterMetrics {
        queued_frames: Arc::new(AtomicUsize::new(0)),
        worker_alive: Arc::new(AtomicBool::new(true)),
    };
    let metrics_thread = metrics.clone();
    let name = interface_name.to_string();

    thread::Builder::new()
        .name(format!("iface-writer-{}", interface_id.0))
        .spawn(move || {
            async_writer_loop(writer, rx, interface_id, name, event_tx, metrics_thread)
        })
        .expect("failed to spawn interface writer thread");

    (
        Box::new(AsyncWriter {
            tx,
            metrics: metrics.clone(),
        }),
        metrics,
    )
}

fn async_writer_loop(
    mut writer: Box<dyn Writer>,
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
    interface_id: InterfaceId,
    interface_name: String,
    event_tx: EventSender,
    metrics: AsyncWriterMetrics,
) {
    while let Ok(frame) = rx.recv() {
        metrics.queued_frames.fetch_sub(1, Ordering::Relaxed);
        if let Err(err) = writer.send_frame(&frame) {
            metrics.worker_alive.store(false, Ordering::Relaxed);
            log::warn!(
                "[{}:{}] async writer exiting after send failure: {}",
                interface_name,
                interface_id.0,
                err
            );
            let _ = event_tx.send(crate::event::Event::InterfaceDown(interface_id));
            return;
        }
    }

    metrics.worker_alive.store(false, Ordering::Relaxed);
}

pub use crate::common::interface_stats::{InterfaceStats, ANNOUNCE_SAMPLE_MAX};

use crate::common::management::InterfaceStatusView;

/// Everything the driver tracks per interface.
pub struct InterfaceEntry {
    pub id: InterfaceId,
    pub info: InterfaceInfo,
    pub writer: Box<dyn Writer>,
    pub async_writer_metrics: Option<AsyncWriterMetrics>,
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
    Listener { control: Option<ListenerControl> },
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
    use crate::event::Event;
    use rns_core::constants;
    use std::sync::mpsc;

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

    struct BlockingWriter {
        entered_tx: mpsc::Sender<()>,
        release_rx: mpsc::Receiver<()>,
    }

    impl Writer for BlockingWriter {
        fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
            let _ = self.entered_tx.send(());
            let _ = self.release_rx.recv();
            Ok(())
        }
    }

    struct FailingWriter;

    impl Writer for FailingWriter {
        fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "boom"))
        }
    }

    #[test]
    fn async_writer_returns_wouldblock_when_queue_is_full() {
        let (event_tx, _event_rx) = crate::event::channel();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (mut writer, metrics) = wrap_async_writer(
            Box::new(BlockingWriter {
                entered_tx,
                release_rx,
            }),
            InterfaceId(7),
            "test",
            event_tx,
            1,
        );

        writer.send_frame(&[1]).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        writer.send_frame(&[2]).unwrap();
        assert_eq!(metrics.queued_frames(), 1);
        let err = writer.send_frame(&[3]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

        let _ = release_tx.send(());
    }

    #[test]
    fn async_writer_reports_interface_down_after_worker_failure() {
        let (event_tx, event_rx) = crate::event::channel();
        let (mut writer, metrics) =
            wrap_async_writer(Box::new(FailingWriter), InterfaceId(9), "fail", event_tx, 2);

        writer.send_frame(&[1]).unwrap();
        let event = event_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(event, Event::InterfaceDown(InterfaceId(9))));
        assert!(!metrics.worker_alive());
    }
}
