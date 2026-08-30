//! Network interface abstractions.

#[cfg(feature = "iface-auto")]
pub mod auto;
#[cfg(feature = "iface-kiss")]
pub mod ax25_kiss;
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
pub(crate) mod transmit_buffer;
#[cfg(feature = "iface-udp")]
pub mod udp;
#[cfg(all(feature = "iface-weave", target_os = "linux"))]
pub mod weave;

use std::any::Any;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use crate::event::EventSender;
use crate::ifac::IfacState;
use rns_core::transport::types::{InterfaceId, InterfaceInfo};

/// Host callback used where every Reticulum underlay socket must be explicitly
/// excluded from an application VPN, notably Android `VpnService.protect()`.
pub trait SocketProtector: Send + Sync {
    fn protect(&self, fd: std::os::unix::io::RawFd) -> io::Result<()>;
}

fn socket_protector_slot() -> &'static std::sync::RwLock<Option<Arc<dyn SocketProtector>>> {
    static SLOT: std::sync::OnceLock<std::sync::RwLock<Option<Arc<dyn SocketProtector>>>> =
        std::sync::OnceLock::new();
    SLOT.get_or_init(|| std::sync::RwLock::new(None))
}

/// Exclusive process-scoped socket protection registration.
///
/// Android VPN services should run their private node in a dedicated process.
/// A second registration fails instead of replacing a callback used by live
/// sockets.
pub struct SocketProtectorGuard {
    protector: Arc<dyn SocketProtector>,
}

pub fn install_socket_protector(
    protector: Arc<dyn SocketProtector>,
) -> io::Result<SocketProtectorGuard> {
    let mut slot = socket_protector_slot()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "an underlay socket protector is already installed",
        ));
    }
    *slot = Some(Arc::clone(&protector));
    Ok(SocketProtectorGuard { protector })
}

#[cfg(test)]
mod socket_protector_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    struct CountingProtector(Arc<AtomicUsize>);
    impl SocketProtector for CountingProtector {
        fn protect(&self, _fd: std::os::unix::io::RawFd) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn underlay_helper_invokes_installed_protector_without_mark() {
        use std::os::fd::AsRawFd;
        let _lock = TEST_LOCK.lock().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let _guard =
            install_socket_protector(Arc::new(CountingProtector(Arc::clone(&calls)))).unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        apply_underlay_mark(socket.as_raw_fd(), None).unwrap();
        assert!(calls.load(Ordering::Relaxed) >= 1);
    }
}

impl Drop for SocketProtectorGuard {
    fn drop(&mut self) {
        let mut slot = socket_protector_slot()
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot
            .as_ref()
            .is_some_and(|installed| Arc::ptr_eq(installed, &self.protector))
        {
            *slot = None;
        }
    }
}

fn protect_underlay_socket(fd: std::os::unix::io::RawFd) -> io::Result<()> {
    let protector = socket_protector_slot()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    if let Some(protector) = protector {
        protector.protect(fd)?;
    }
    Ok(())
}

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

/// Apply a Linux firewall mark to an IP underlay socket.
///
/// The mark must be set before `connect()` so policy routing can keep Reticulum
/// underlay traffic outside application-level full tunnels. Configuring a mark
/// is fail-closed: callers must not silently create an unmarked socket when the
/// operation is not permitted.
#[cfg(target_os = "linux")]
pub fn apply_underlay_mark(fd: std::os::unix::io::RawFd, mark: Option<u32>) -> io::Result<()> {
    protect_underlay_socket(fd)?;
    let Some(mark) = mark else {
        return Ok(());
    };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply_underlay_mark(fd: std::os::unix::io::RawFd, mark: Option<u32>) -> io::Result<()> {
    protect_underlay_socket(fd)?;
    if mark.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "underlay socket marks are only supported on Linux",
        ));
    }
    Ok(())
}

/// Connect a TCP socket after applying underlay routing options.
#[cfg(target_os = "linux")]
pub fn connect_tcp_with_options(
    addr: &std::net::SocketAddr,
    device: Option<&str>,
    underlay_mark: Option<u32>,
    timeout: Duration,
) -> io::Result<std::net::TcpStream> {
    use std::os::unix::io::AsRawFd;

    let socket = socket2::Socket::new(
        socket2::Domain::for_address(*addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    apply_underlay_mark(socket.as_raw_fd(), underlay_mark)?;
    if let Some(device) = device {
        bind_to_device(socket.as_raw_fd(), device)?;
    }
    socket.connect_timeout(&(*addr).into(), timeout)?;
    Ok(socket.into())
}

/// Validate at node startup that the configured mark can actually be applied.
pub fn validate_underlay_mark(mark: Option<u32>) -> io::Result<()> {
    let Some(_) = mark else {
        return Ok(());
    };
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    use std::os::unix::io::AsRawFd;
    apply_underlay_mark(socket.as_raw_fd(), mark)
}

/// Writable end of an interface. Held by the driver.
///
/// Each implementation wraps a socket + framing.
pub trait Writer: Send {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()>;

    fn send_frames(&mut self, frames: &[Vec<u8>]) -> io::Result<()> {
        for frame in frames {
            self.send_frame(frame)?;
        }
        Ok(())
    }

    /// Resume bytes accepted by a previous call that returned `WouldBlock`.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// Share an exact byte admission budget with the async producer when this
    /// writer uses dataplane egress control.
    fn egress_control(&self) -> Option<EgressControl> {
        None
    }

    fn shutdown(&mut self) {}
}

pub const DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY: usize = 256;

#[derive(Clone)]
#[doc(hidden)]
pub struct EgressControl {
    byte_limit: usize,
    reserved_bytes: Arc<AtomicUsize>,
    stalled: Arc<AtomicBool>,
    dropped_frames: Arc<AtomicU64>,
    dropped_bytes: Arc<AtomicU64>,
}

impl EgressControl {
    pub(crate) fn new(byte_limit: usize) -> Self {
        Self {
            byte_limit,
            reserved_bytes: Arc::new(AtomicUsize::new(0)),
            stalled: Arc::new(AtomicBool::new(false)),
            dropped_frames: Arc::new(AtomicU64::new(0)),
            dropped_bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    fn try_reserve(&self, bytes: usize) -> bool {
        if self.stalled.load(Ordering::Relaxed) {
            return false;
        }
        let mut current = self.reserved_bytes.load(Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(bytes) else {
                return false;
            };
            if next > self.byte_limit {
                return false;
            }
            match self.reserved_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    fn release(&self, bytes: usize) {
        self.reserved_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }

    pub(crate) fn stalled(&self) -> bool {
        self.stalled.load(Ordering::Relaxed)
    }

    pub(crate) fn set_stalled(&self, stalled: bool) {
        self.stalled.store(stalled, Ordering::Relaxed);
    }

    pub(crate) fn record_drop(&self, bytes: usize) {
        self.dropped_frames.fetch_add(1, Ordering::Relaxed);
        self.dropped_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

/// Return whether an interface type normally operates on a shared medium.
///
/// This is a type-level hint: runtime configuration can still describe links
/// with different physical properties. It mirrors Reticulum's interface-class
/// defaults and is suitable for discovery/capability metadata.
pub fn shared_medium_hint(interface_type: &str) -> bool {
    matches!(
        interface_type,
        "AX25KISSInterface"
            | "KISSInterface"
            | "PipeInterface"
            | "RNodeInterface"
            | "RNodeMultiInterface"
            | "SerialInterface"
            | "UDPInterface"
    )
}

pub(crate) fn lock_or_recover<'a, T>(mutex: &'a Mutex<T>, label: &str) -> MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::warn!("recovering poisoned mutex: {}", label);
            poisoned.into_inner()
        }
    }
}

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
    egress_control: Option<EgressControl>,
}

impl AsyncWriterMetrics {
    pub fn queued_frames(&self) -> usize {
        self.queued_frames.load(Ordering::Relaxed)
    }

    pub fn worker_alive(&self) -> bool {
        self.worker_alive.load(Ordering::Relaxed)
    }

    /// Exact encoded bytes waiting in the async queue or concrete writer.
    pub fn tx_buffered(&self) -> usize {
        self.egress_control
            .as_ref()
            .map(|control| control.reserved_bytes.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn tx_drops(&self) -> u64 {
        self.egress_control
            .as_ref()
            .map(|control| control.dropped_frames.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn tx_dropped_bytes(&self) -> u64 {
        self.egress_control
            .as_ref()
            .map(|control| control.dropped_bytes.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn tx_stalled(&self) -> bool {
        self.egress_control
            .as_ref()
            .is_some_and(EgressControl::stalled)
    }
}

struct AsyncWriter {
    tx: SyncSender<QueuedFrame>,
    metrics: AsyncWriterMetrics,
}

struct QueuedFrame {
    data: Vec<u8>,
    reserved_bytes: usize,
}

impl Writer for AsyncWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        if !self.metrics.worker_alive() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "interface writer worker is offline",
            ));
        }

        let reserved_bytes = if let Some(control) = &self.metrics.egress_control {
            let framed_bytes = crate::hdlc::framed_len(data);
            if !control.try_reserve(framed_bytes) {
                control.record_drop(framed_bytes);
                return Ok(());
            }
            framed_bytes
        } else {
            0
        };

        // Publish accounting before the frame becomes visible to the worker.
        self.metrics.queued_frames.fetch_add(1, Ordering::Relaxed);
        match self.tx.try_send(QueuedFrame {
            data: data.to_vec(),
            reserved_bytes,
        }) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(frame)) => {
                self.metrics.queued_frames.fetch_sub(1, Ordering::Relaxed);
                if let Some(control) = &self.metrics.egress_control {
                    control.release(frame.reserved_bytes);
                }
                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "interface writer queue is full",
                ))
            }
            Err(TrySendError::Disconnected(frame)) => {
                self.metrics.queued_frames.fetch_sub(1, Ordering::Relaxed);
                if let Some(control) = &self.metrics.egress_control {
                    control.release(frame.reserved_bytes);
                }
                self.metrics.worker_alive.store(false, Ordering::Relaxed);
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
    let egress_control = writer.egress_control();
    let (tx, rx) = sync_channel::<QueuedFrame>(queue_capacity.max(1));
    let metrics = AsyncWriterMetrics {
        queued_frames: Arc::new(AtomicUsize::new(0)),
        worker_alive: Arc::new(AtomicBool::new(true)),
        egress_control,
    };
    let metrics_thread = metrics.clone();
    let name = interface_name.to_string();

    let spawn_result = thread::Builder::new()
        .name(format!("iface-writer-{}", interface_id.0))
        .spawn(move || async_writer_loop(writer, rx, interface_id, name, event_tx, metrics_thread));

    if let Err(err) = spawn_result {
        metrics.worker_alive.store(false, Ordering::Relaxed);
        log::error!(
            "[{}:{}] failed to spawn async writer thread: {}",
            interface_name,
            interface_id.0,
            err
        );
        return (Box::new(DirectWriterFallback), metrics);
    }

    (
        Box::new(AsyncWriter {
            tx,
            metrics: metrics.clone(),
        }),
        metrics,
    )
}

struct DirectWriterFallback;

impl Writer for DirectWriterFallback {
    fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
        Err(io::Error::other("interface writer worker unavailable"))
    }
}

fn async_writer_loop(
    mut writer: Box<dyn Writer>,
    rx: std::sync::mpsc::Receiver<QueuedFrame>,
    interface_id: InterfaceId,
    interface_name: String,
    event_tx: EventSender,
    metrics: AsyncWriterMetrics,
) {
    while let Ok(first) = rx.recv() {
        let mut queued = vec![first];
        queued.extend(rx.try_iter());
        let reserved_bytes = queued.iter().map(|frame| frame.reserved_bytes).sum();
        let frames: Vec<_> = queued.into_iter().map(|frame| frame.data).collect();
        metrics
            .queued_frames
            .fetch_sub(frames.len(), Ordering::Relaxed);

        let mut result = writer.send_frames(&frames);
        while result
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
        {
            thread::sleep(Duration::from_millis(1));
            result = writer.flush();
        }

        if let Some(control) = &metrics.egress_control {
            control.release(reserved_bytes);
        }

        if let Err(err) = result {
            metrics.worker_alive.store(false, Ordering::Relaxed);
            log::warn!(
                "[{}:{}] async writer exiting after send failure: {}",
                interface_name,
                interface_id.0,
                err
            );
            writer.shutdown();
            let _ = event_tx.send(crate::event::Event::InterfaceDown(interface_id));
            return;
        }
    }

    metrics.worker_alive.store(false, Ordering::Relaxed);
}

pub use crate::common::interface_stats::{InterfaceStats, TrafficRates, ANNOUNCE_SAMPLE_MAX};

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
// Boxing `Simple` would change the published factory result representation.
#[allow(clippy::large_enum_variant)]
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
    pub gravity: i64,
    pub recursive_prs: bool,
    pub announces_from_internal: bool,
    pub announces_to_internal: Option<bool>,
    pub ingress_control: rns_core::transport::types::IngressControlConfig,
    pub ifac: Option<IfacState>,
    /// Linux `SO_MARK` value applied to IP underlay sockets before connect.
    pub underlay_mark: Option<u32>,
}

/// Opaque interface config data. Each factory downcasts to its concrete type.
pub trait InterfaceConfigData: Send + Any {
    fn as_any(&self) -> &dyn Any;
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

/// ConfigObj section passed to factories that need nested `[[[sections]]]`.
pub struct ConfigSection<'a> {
    pub params: &'a HashMap<String, String>,
    pub children: &'a [crate::config::ParsedSubinterface],
}

#[derive(Debug, Clone)]
pub struct DynamicInterfaceTemplate {
    pub parent_id: InterfaceId,
    pub interface_type: String,
    pub ifac: Option<IfacState>,
    pub mode: u8,
    pub gravity: i64,
    pub recursive_prs: bool,
    pub announces_from_internal: bool,
    pub announces_to_internal: Option<bool>,
}

impl DynamicInterfaceTemplate {
    pub fn registration(
        &self,
        mut info: InterfaceInfo,
    ) -> crate::event::DynamicInterfaceRegistration {
        info.mode = self.mode;
        info.gravity = self.gravity;
        info.recursive_prs = self.recursive_prs;
        info.announces_from_internal = self.announces_from_internal;
        info.announces_to_internal = self.announces_to_internal;
        crate::event::DynamicInterfaceRegistration {
            info,
            interface_type: self.interface_type.clone(),
            parent_id: self.parent_id,
            telemetry: crate::event::InterfaceTelemetry::default(),
            ifac: self.ifac.clone(),
        }
    }
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

    /// Parse a complete ConfigObj interface section. Flat factories inherit
    /// the compatibility default; multi-interface factories can inspect children.
    fn parse_config_section(
        &self,
        name: &str,
        id: InterfaceId,
        section: ConfigSection<'_>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        self.parse_config(name, id, section.params)
    }

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
    fn tx_drops(&self) -> u64 {
        self.async_writer_metrics
            .as_ref()
            .map(AsyncWriterMetrics::tx_drops)
            .unwrap_or(0)
    }
    fn tx_dropped_bytes(&self) -> u64 {
        self.async_writer_metrics
            .as_ref()
            .map(AsyncWriterMetrics::tx_dropped_bytes)
            .unwrap_or(0)
    }
    fn tx_stalled(&self) -> bool {
        self.async_writer_metrics
            .as_ref()
            .is_some_and(AsyncWriterMetrics::tx_stalled)
    }
    fn tx_buffered(&self) -> usize {
        self.async_writer_metrics
            .as_ref()
            .map(AsyncWriterMetrics::tx_buffered)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_medium_hint_matches_interface_class_defaults() {
        for interface_type in [
            "AX25KISSInterface",
            "KISSInterface",
            "PipeInterface",
            "RNodeInterface",
            "RNodeMultiInterface",
            "SerialInterface",
            "UDPInterface",
        ] {
            assert!(shared_medium_hint(interface_type), "{interface_type}");
        }
        for interface_type in [
            "AutoInterface",
            "BackboneInterface",
            "I2PInterface",
            "LocalInterface",
            "TCPClientInterface",
            "TCPServerInterface",
        ] {
            assert!(!shared_medium_hint(interface_type), "{interface_type}");
        }
    }
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
                tunnel_id: None,
                mtu: constants::MTU as u32,
                ia_freq: 0.0,
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
    fn dynamic_registration_inherits_announces_to_internal() {
        let template = DynamicInterfaceTemplate {
            parent_id: InterfaceId(7),
            interface_type: "dynamic-test".into(),
            ifac: None,
            mode: constants::MODE_GATEWAY,
            gravity: -3,
            recursive_prs: true,
            announces_from_internal: false,
            announces_to_internal: Some(true),
        };
        let info = InterfaceInfo {
            id: InterfaceId(8),
            name: "child".into(),
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
            tunnel_id: None,
            mtu: constants::MTU as u32,
            ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
            ia_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: 0.0,
        };

        let registration = template.registration(info);

        assert_eq!(registration.info.mode, constants::MODE_GATEWAY);
        assert_eq!(registration.info.gravity, -3);
        assert!(registration.info.recursive_prs);
        assert!(!registration.info.announces_from_internal);
        assert_eq!(registration.info.announces_to_internal, Some(true));
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

    struct EgressControlledBlockingWriter {
        inner: BlockingWriter,
        control: EgressControl,
    }

    impl Writer for EgressControlledBlockingWriter {
        fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
            self.inner.send_frame(data)
        }

        fn egress_control(&self) -> Option<EgressControl> {
            Some(self.control.clone())
        }
    }

    struct FailingWriter {
        shutdown_called: Arc<AtomicBool>,
    }

    struct RecordingWriter {
        sent_tx: mpsc::Sender<Vec<u8>>,
    }

    impl Writer for RecordingWriter {
        fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
            self.sent_tx
                .send(data.to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "test receiver closed"))
        }
    }

    struct BatchRecordingWriter {
        batch_tx: mpsc::Sender<usize>,
        first_release: Option<mpsc::Receiver<()>>,
    }

    impl Writer for BatchRecordingWriter {
        fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
            unreachable!("the async worker must use batch delivery")
        }

        fn send_frames(&mut self, frames: &[Vec<u8>]) -> io::Result<()> {
            self.batch_tx.send(frames.len()).unwrap();
            if let Some(release) = self.first_release.take() {
                release.recv().unwrap();
            }
            Ok(())
        }
    }

    impl Writer for FailingWriter {
        fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "boom"))
        }

        fn shutdown(&mut self) {
            self.shutdown_called.store(true, Ordering::Relaxed);
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

        release_tx.send(()).unwrap();
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("the queued frame must wake the writer without another send trigger");
        assert_eq!(metrics.queued_frames(), 0);
        release_tx.send(()).unwrap();
    }

    #[test]
    fn async_writer_shares_exact_egress_byte_valve_and_stall_gate() {
        let (event_tx, _event_rx) = crate::event::channel();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let control = EgressControl::new(4);
        let (mut writer, metrics) = wrap_async_writer(
            Box::new(EgressControlledBlockingWriter {
                inner: BlockingWriter {
                    entered_tx,
                    release_rx,
                },
                control: control.clone(),
            }),
            InterfaceId(8),
            "egress-test",
            event_tx,
            8,
        );

        // Two ordinary bytes occupy exactly four HDLC bytes on wire.
        writer.send_frame(&[1, 2]).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(control.reserved_bytes.load(Ordering::Relaxed), 4);
        assert_eq!(metrics.tx_buffered(), 4);

        // The hard valve drops instead of retaining another four-byte frame.
        writer.send_frame(&[3, 4]).unwrap();
        assert_eq!(control.reserved_bytes.load(Ordering::Relaxed), 4);
        assert_eq!(control.dropped_frames.load(Ordering::Relaxed), 1);
        assert_eq!(control.dropped_bytes.load(Ordering::Relaxed), 4);
        assert_eq!(metrics.tx_drops(), 1);
        assert_eq!(metrics.tx_dropped_bytes(), 4);

        release_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while control.reserved_bytes.load(Ordering::Relaxed) != 0 {
            assert!(
                Instant::now() < deadline,
                "egress reservation did not drain"
            );
            thread::yield_now();
        }

        control.set_stalled(true);
        assert!(metrics.tx_stalled());
        writer.send_frame(&[5]).unwrap();
        assert_eq!(control.dropped_frames.load(Ordering::Relaxed), 2);
        assert_eq!(control.dropped_bytes.load(Ordering::Relaxed), 7);
        assert_eq!(metrics.queued_frames(), 0);
    }

    #[test]
    fn async_writer_reports_interface_down_after_worker_failure() {
        let (event_tx, event_rx) = crate::event::channel();
        let shutdown_called = Arc::new(AtomicBool::new(false));
        let (mut writer, metrics) = wrap_async_writer(
            Box::new(FailingWriter {
                shutdown_called: Arc::clone(&shutdown_called),
            }),
            InterfaceId(9),
            "fail",
            event_tx,
            2,
        );

        writer.send_frame(&[1]).unwrap();
        let event = event_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(event, Event::InterfaceDown(InterfaceId(9))));
        assert!(!metrics.worker_alive());
        assert!(shutdown_called.load(Ordering::Relaxed));
    }

    #[test]
    fn async_writer_preserves_order_through_fifty_thousand_frame_burst() {
        const FRAME_COUNT: usize = 50_000;
        let (event_tx, _event_rx) = crate::event::channel();
        let (sent_tx, sent_rx) = mpsc::channel();
        let (mut writer, metrics) = wrap_async_writer(
            Box::new(RecordingWriter { sent_tx }),
            InterfaceId(11),
            "burst",
            event_tx,
            FRAME_COUNT,
        );

        for index in 0..FRAME_COUNT {
            let payload = (index as u64).to_be_bytes();
            writer.send_frame(&payload).unwrap();
        }

        for index in 0..FRAME_COUNT {
            let received = sent_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(received, (index as u64).to_be_bytes());
        }
        assert!(metrics.worker_alive());
    }

    #[test]
    fn async_writer_coalesces_frames_waiting_behind_an_active_batch() {
        let (event_tx, _event_rx) = crate::event::channel();
        let (batch_tx, batch_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (mut writer, _) = wrap_async_writer(
            Box::new(BatchRecordingWriter {
                batch_tx,
                first_release: Some(release_rx),
            }),
            InterfaceId(12),
            "batch",
            event_tx,
            16,
        );

        writer.send_frame(&[0]).unwrap();
        assert_eq!(batch_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 1);
        for index in 1..=10 {
            writer.send_frame(&[index]).unwrap();
        }
        release_tx.send(()).unwrap();

        assert_eq!(batch_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 10);
    }
}
