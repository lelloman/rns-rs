//! TCP client interface with HDLC framing.
//!
//! Matches Python `TCPClientInterface` from `TCPInterface.py`.

use std::io::{self, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rns_core::transport::types::InterfaceId;

use crate::event::{Event, EventSender, LoopContext, LoopSource, SourceStatus};
use crate::hdlc;
use crate::interface::{lock_or_recover, wait_while_active, ListenerControl, Writer};

/// Upstream `TCPInterface.HW_MTU`.
const HW_MTU: usize = 262_144;

/// Configuration for a TCP client interface.
#[derive(Debug, Clone)]
pub struct TcpClientConfig {
    pub name: String,
    pub target_host: String,
    pub target_port: u16,
    pub interface_id: InterfaceId,
    pub reconnect_wait: Duration,
    pub max_reconnect_tries: Option<u32>,
    pub connect_timeout: Duration,
    /// Linux network interface to bind the socket to (e.g. "usb0").
    pub device: Option<String>,
    pub runtime: Arc<Mutex<TcpClientRuntime>>,
}

#[derive(Debug, Clone)]
pub struct TcpClientRuntime {
    pub target_host: String,
    pub target_port: u16,
    pub reconnect_wait: Duration,
    pub max_reconnect_tries: Option<u32>,
    pub connect_timeout: Duration,
}

impl TcpClientRuntime {
    pub fn from_config(config: &TcpClientConfig) -> Self {
        Self {
            target_host: config.target_host.clone(),
            target_port: config.target_port,
            reconnect_wait: config.reconnect_wait,
            max_reconnect_tries: config.max_reconnect_tries,
            connect_timeout: config.connect_timeout,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpClientRuntimeConfigHandle {
    pub interface_name: String,
    pub runtime: Arc<Mutex<TcpClientRuntime>>,
    pub startup: TcpClientRuntime,
}

impl Default for TcpClientConfig {
    fn default() -> Self {
        let mut config = TcpClientConfig {
            name: String::new(),
            target_host: "127.0.0.1".into(),
            target_port: 4242,
            interface_id: InterfaceId(0),
            reconnect_wait: Duration::from_secs(5),
            max_reconnect_tries: None,
            connect_timeout: Duration::from_secs(5),
            device: None,
            runtime: Arc::new(Mutex::new(TcpClientRuntime {
                target_host: "127.0.0.1".into(),
                target_port: 4242,
                reconnect_wait: Duration::from_secs(5),
                max_reconnect_tries: None,
                connect_timeout: Duration::from_secs(5),
            })),
        };
        let startup = TcpClientRuntime::from_config(&config);
        config.runtime = Arc::new(Mutex::new(startup));
        config
    }
}

/// Writer that sends HDLC-framed data over a TCP stream.
struct TcpWriter {
    stream: TcpStream,
    /// Reused encoding buffer for coalesced writes.
    scratch: Vec<u8>,
}

impl Writer for TcpWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(&hdlc::frame(data))
    }

    fn send_frames(&mut self, frames: &[crate::interface::FrameBytes]) -> io::Result<()> {
        hdlc::write_frames(&mut self.stream, frames, &mut self.scratch)
    }

    fn loop_socket(&self) -> Option<std::os::fd::RawFd> {
        Some(self.stream.as_raw_fd())
    }
}

/// Set TCP_NODELAY, keepalive and (on Linux) keepalive tuning and user
/// timeout options. Shared by outbound client sockets and sockets accepted
/// by the TCP server.
pub(crate) fn set_socket_options(stream: &TcpStream) -> io::Result<()> {
    let fd = stream.as_raw_fd();
    unsafe {
        // TCP_NODELAY = 1
        let val: libc::c_int = 1;
        if libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }

        // SO_KEEPALIVE = 1
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }

        // Linux-specific keepalive tuning and user timeout
        #[cfg(target_os = "linux")]
        {
            // TCP_KEEPIDLE = 5
            let idle: libc::c_int = 5;
            if libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPIDLE,
                &idle as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }

            // TCP_KEEPINTVL = 2
            let intvl: libc::c_int = 2;
            if libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPINTVL,
                &intvl as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }

            // TCP_KEEPCNT = 12
            let cnt: libc::c_int = 12;
            if libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPCNT,
                &cnt as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }

            // TCP_USER_TIMEOUT = 24000 ms
            let timeout: libc::c_int = 24_000;
            if libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_USER_TIMEOUT,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// Try to connect to the target host:port with timeout.
fn try_connect(config: &TcpClientConfig, underlay_mark: Option<u32>) -> io::Result<TcpStream> {
    let runtime = lock_or_recover(&config.runtime, "tcp client runtime").clone();
    let addr_str = format!("{}:{}", config.target_host, config.target_port);
    let addr = addr_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses resolved"))?;

    #[cfg(target_os = "linux")]
    let stream = if config.device.is_some() || underlay_mark.is_some() {
        super::connect_tcp_with_options(
            &addr,
            config.device.as_deref(),
            underlay_mark,
            runtime.connect_timeout,
        )?
    } else {
        TcpStream::connect_timeout(&addr, runtime.connect_timeout)?
    };
    #[cfg(not(target_os = "linux"))]
    let stream = TcpStream::connect_timeout(&addr, runtime.connect_timeout)?;
    set_socket_options(&stream)?;
    Ok(stream)
}

/// Connect and start the reader thread. Returns the writer for the driver.
pub fn start(config: TcpClientConfig, tx: EventSender) -> io::Result<Box<dyn Writer>> {
    start_with_ifac(config, tx, 0, None)
}

fn start_with_ifac(
    config: TcpClientConfig,
    tx: EventSender,
    ifac_size: usize,
    underlay_mark: Option<u32>,
) -> io::Result<Box<dyn Writer>> {
    start_with_ifac_control(config, tx, ifac_size, underlay_mark).map(|(writer, _)| writer)
}

fn start_with_ifac_control(
    config: TcpClientConfig,
    tx: EventSender,
    ifac_size: usize,
    underlay_mark: Option<u32>,
) -> io::Result<(Box<dyn Writer>, ListenerControl)> {
    let stream = try_connect(&config, underlay_mark)?;
    let writer_stream = stream.try_clone()?;

    let id = config.interface_id;
    // Initial connect: writer is None because it's returned directly to the caller
    let _ = tx.send(Event::InterfaceUp(id, None, None));

    let control = ListenerControl::new();
    let link = Arc::new(ClientLink {
        config,
        tx,
        ifac_size,
        underlay_mark,
        control: control.clone(),
    });
    if let Err(error) = link.serve(stream) {
        let _ = link.tx.send(Event::InterfaceDown(id));
        return Err(error);
    }

    Ok((
        Box::new(TcpWriter {
            stream: writer_stream,
            scratch: Vec::new(),
        }),
        control,
    ))
}

/// Bytes read from one stream socket per readiness before other sources
/// get a turn; the socket is re-armed and served again on the next pass.
pub(crate) const STREAM_READ_BUDGET: usize = 256 * 1024;

/// How a read pass over a stream socket ended.
pub(crate) enum StreamRead {
    /// The socket is drained or the read budget is spent: watch it again.
    Rearm,
    /// Inbound data is full: read again once the driver has drained it, so
    /// TCP flow control slows the sender meanwhile.
    Suspend,
    /// The peer closed the connection.
    Closed,
    Failed(io::Error),
    /// The driver is gone.
    DriverGone,
}

/// Read a readable stream socket on the driver thread until it is empty or
/// [`STREAM_READ_BUDGET`] is spent, and queue the frames decoded from it,
/// reporting the bytes and frames of each read to `on_read`.
/// Reads nothing while inbound data is full, so data queued past capacity
/// is bounded by one read per socket.
pub(crate) fn read_stream_frames(
    fd: std::os::fd::RawFd,
    decoder: &mut hdlc::Decoder,
    cx: &mut LoopContext<'_>,
    tx: &EventSender,
    id: InterfaceId,
    name: &str,
    mut on_read: impl FnMut(usize, usize),
) -> StreamRead {
    if !tx.inbound_data_has_room() {
        return StreamRead::Suspend;
    }
    let mut read = 0;
    while read < STREAM_READ_BUDGET {
        // SAFETY: `cx.buf` is a valid writable buffer for the call.
        // MSG_DONTWAIT keeps the socket's own mode untouched.
        let n = unsafe {
            libc::recv(
                fd,
                cx.buf.as_mut_ptr().cast(),
                cx.buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::WouldBlock => return StreamRead::Rearm,
                io::ErrorKind::Interrupted => continue,
                _ => return StreamRead::Failed(e),
            }
        }
        if n == 0 {
            return StreamRead::Closed;
        }
        let n = n as usize;
        read += n;
        let decoded = decoder.feed_with_diagnostics(&cx.buf[..n]);
        for frame_len in decoded.invalid_frame_lengths {
            log::debug!(
                "[{}] invalid HDLC frame of {} bytes received on interface {}, dropping frame",
                name,
                frame_len,
                id.0,
            );
        }
        on_read(n, decoded.frames.len());
        let frames = decoded.frames.into_iter().map(|frame| Event::Frame {
            interface_id: id,
            data: frame,
            rssi: None,
            snr: None,
        });
        match tx.push_from_loop(frames) {
            Ok(true) => {}
            Ok(false) => return StreamRead::Suspend,
            Err(_) => return StreamRead::DriverGone,
        }
    }
    StreamRead::Rearm
}

/// What a client connection needs across reconnects.
struct ClientLink {
    config: TcpClientConfig,
    tx: EventSender,
    ifac_size: usize,
    underlay_mark: Option<u32>,
    control: ListenerControl,
}

impl ClientLink {
    /// Read `stream` on the driver thread from now on.
    fn serve(self: &Arc<Self>, stream: TcpStream) -> io::Result<()> {
        let source = ReaderSource {
            stream,
            decoder: hdlc::Decoder::reticulum(HW_MTU, self.ifac_size),
            link: Arc::clone(self),
        };
        self.tx.register_source(
            crate::interface::loop_writer::read_key(self.config.interface_id),
            Box::new(source),
        )
    }

    /// Report the connection down and reconnect on a thread of its own,
    /// which exits once the new connection is served on the driver (or
    /// reconnecting gives up or is stopped).
    fn connection_lost(self: &Arc<Self>) {
        let id = self.config.interface_id;
        let _ = self.tx.push_from_loop([Event::InterfaceDown(id)]);
        let link = Arc::clone(self);
        let spawned = thread::Builder::new()
            .name(format!("tcp-reconn-{}", id.0))
            .spawn(move || link.reconnect_loop());
        if let Err(error) = spawned {
            log::error!(
                "[{}] cannot start reconnecting, giving up: {}",
                self.config.name,
                error
            );
        }
    }

    fn reconnect_loop(self: Arc<Self>) {
        loop {
            let Some(stream) = reconnect(&self.config, &self.tx, self.underlay_mark, &self.control)
            else {
                if !self.control.should_stop() {
                    log::error!("[{}] reconnection failed, giving up", self.config.name);
                }
                return;
            };
            match self.serve(stream) {
                Ok(()) => return,
                Err(error) => {
                    log::warn!(
                        "[{}] cannot read the new connection: {}",
                        self.config.name,
                        error
                    );
                    let _ = self.tx.send(Event::InterfaceDown(self.config.interface_id));
                }
            }
        }
    }
}

/// The connected socket, read on the driver thread.
struct ReaderSource {
    stream: TcpStream,
    decoder: hdlc::Decoder,
    link: Arc<ClientLink>,
}

impl LoopSource for ReaderSource {
    fn fd(&self) -> std::os::fd::RawFd {
        self.stream.as_raw_fd()
    }

    fn stopped(&self) -> bool {
        self.link.control.should_stop()
    }

    fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
        let link = &self.link;
        if link.control.should_stop() {
            return SourceStatus::Remove;
        }
        let name = &link.config.name;
        match read_stream_frames(
            self.stream.as_raw_fd(),
            &mut self.decoder,
            cx,
            &link.tx,
            link.config.interface_id,
            name,
            |_, _| {},
        ) {
            StreamRead::Rearm => SourceStatus::Rearm,
            StreamRead::Suspend => SourceStatus::Suspend,
            StreamRead::Closed => {
                log::warn!("[{}] connection closed", name);
                link.connection_lost();
                SourceStatus::Remove
            }
            StreamRead::Failed(error) => {
                log::warn!("[{}] read error: {}", name, error);
                link.connection_lost();
                SourceStatus::Remove
            }
            StreamRead::DriverGone => SourceStatus::Remove,
        }
    }
}

/// Attempt to reconnect with retry logic. Returns the new reader stream on success.
/// Sends the new writer to the driver via InterfaceUp event.
fn reconnect(
    config: &TcpClientConfig,
    tx: &EventSender,
    underlay_mark: Option<u32>,
    control: &ListenerControl,
) -> Option<TcpStream> {
    let mut attempts = 0u32;
    loop {
        let runtime = lock_or_recover(&config.runtime, "tcp client runtime").clone();
        if !wait_while_active(control, runtime.reconnect_wait) {
            return None;
        }
        attempts += 1;

        if let Some(max) = runtime.max_reconnect_tries {
            if attempts > max {
                let _ = tx.send(Event::InterfaceDown(config.interface_id));
                return None;
            }
        }

        log::info!("[{}] reconnect attempt {} ...", config.name, attempts);

        match try_connect(config, underlay_mark) {
            Ok(new_stream) => {
                if control.should_stop() {
                    return None;
                }
                // Clone the stream: one for the reader, one for the writer
                let writer_stream = match new_stream.try_clone() {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("[{}] failed to clone stream: {}", config.name, e);
                        continue;
                    }
                };
                log::info!("[{}] reconnected", config.name);
                // Send new writer to the driver so it can replace the stale one
                let new_writer: Box<dyn Writer> = Box::new(TcpWriter {
                    stream: writer_stream,
                    scratch: Vec::new(),
                });
                let _ = tx.send(Event::InterfaceUp(
                    config.interface_id,
                    Some(new_writer),
                    None,
                ));
                return Some(new_stream);
            }
            Err(e) => {
                log::warn!("[{}] reconnect failed: {}", config.name, e);
            }
        }
    }
}

// --- Factory implementation ---

use super::{InterfaceConfigData, InterfaceFactory, StartContext, StartResult};
use rns_core::transport::types::InterfaceInfo;
use std::collections::HashMap;

/// Factory for `TCPClientInterface`.
pub struct TcpClientFactory;

impl InterfaceFactory for TcpClientFactory {
    fn type_name(&self) -> &str {
        "TCPClientInterface"
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        let target_host = params
            .get("target_host")
            .cloned()
            .unwrap_or_else(|| "127.0.0.1".into());
        let target_port = params
            .get("target_port")
            .and_then(|v| v.parse().ok())
            .unwrap_or(4242);

        Ok(Box::new(TcpClientConfig {
            name: name.to_string(),
            target_host,
            target_port,
            interface_id: id,
            device: params.get("device").cloned(),
            ..TcpClientConfig::default()
        }))
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> io::Result<StartResult> {
        let tcp_config = *config
            .into_any()
            .downcast::<TcpClientConfig>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "wrong config type"))?;

        let id = tcp_config.interface_id;
        let name = tcp_config.name.clone();
        let info = InterfaceInfo {
            id,
            name,
            mode: ctx.mode,
            gravity: ctx.gravity,
            recursive_prs: ctx.recursive_prs,
            announces_from_internal: ctx.announces_from_internal,
            announces_to_internal: ctx.announces_to_internal,
            out_capable: true,
            in_capable: true,
            bitrate: None,
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: rns_core::constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: 65535,
            ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
            ia_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: crate::time::now(),
        };

        let ifac_size = ctx.ifac.as_ref().map(|ifac| ifac.size).unwrap_or(0);
        let (writer, control) =
            start_with_ifac_control(tcp_config, ctx.tx, ifac_size, ctx.underlay_mark)?;

        Ok(StartResult::Simple {
            control: Some(control),
            id,
            info,
            writer,
            interface_type_name: "TCPClientInterface".to_string(),
        })
    }
}

pub(crate) fn tcp_client_runtime_handle_from_config(
    config: &TcpClientConfig,
) -> TcpClientRuntimeConfigHandle {
    TcpClientRuntimeConfigHandle {
        interface_name: config.name.clone(),
        runtime: Arc::clone(&config.runtime),
        startup: TcpClientRuntime::from_config(config),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn detach_stops_idle_tcp_reader_without_reconnect() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let (tx, rx) = crate::event::channel();
        let control = ListenerControl::new();
        let link = Arc::new(ClientLink {
            config: TcpClientConfig {
                name: "detach-test".into(),
                interface_id: InterfaceId(75),
                ..Default::default()
            },
            tx,
            ifac_size: 0,
            underlay_mark: None,
            control: control.clone(),
        });
        link.serve(server).unwrap();
        control.request_stop();
        rx.sweep_stopped_sources();

        // The reader closed its socket and did not report or reconnect.
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(std::io::Read::read(&mut client, &mut buf).unwrap(), 0);
        assert!(rx.try_recv().is_err());
        drop(link);
    }

    #[test]
    fn a_reconnected_client_is_read_on_the_receiving_thread() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        let (tx, rx) = crate::event::channel();
        let config = TcpClientConfig {
            interface_id: InterfaceId(76),
            ..make_config(port)
        };
        let _writer = start(config, tx).unwrap();
        let (first, _) = listener.accept().unwrap();
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            Event::InterfaceUp(InterfaceId(76), None, _)
        ));
        drop(first);
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            Event::InterfaceDown(InterfaceId(76))
        ));
        let (mut second, _) = listener.accept().unwrap();
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            Event::InterfaceUp(InterfaceId(76), Some(_), _)
        ));
        let payload: Vec<u8> = (0..32).collect();
        second.write_all(&hdlc::frame(&payload)).unwrap();
        match rx.recv_timeout(Duration::from_secs(2)).unwrap() {
            Event::Frame { data, .. } => assert_eq!(data, payload),
            other => panic!("expected Frame, got {:?}", other),
        }
        // The reconnect thread exits once the new socket is served here.
        let reconnecting = || {
            std::fs::read_dir("/proc/self/task")
                .unwrap()
                .filter_map(|task| std::fs::read_to_string(task.ok()?.path().join("comm")).ok())
                .any(|name| name.trim_end() == "tcp-reconn-76")
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while reconnecting() && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!reconnecting());
    }

    use std::net::TcpListener;
    use std::time::Duration;

    fn find_free_port() -> u16 {
        crate::test_support::port()
    }

    fn make_config(port: u16) -> TcpClientConfig {
        TcpClientConfig {
            name: format!("test-tcp-{}", port),
            target_host: "127.0.0.1".into(),
            target_port: port,
            interface_id: InterfaceId(1),
            reconnect_wait: Duration::from_millis(100),
            max_reconnect_tries: Some(2),
            connect_timeout: Duration::from_secs(2),
            runtime: Arc::new(Mutex::new(TcpClientRuntime {
                target_host: "127.0.0.1".into(),
                target_port: port,
                reconnect_wait: Duration::from_millis(100),
                max_reconnect_tries: Some(2),
                connect_timeout: Duration::from_secs(2),
            })),
            device: None,
        }
    }

    #[test]
    fn connect_to_listener() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        let (tx, rx) = crate::event::channel();

        let config = make_config(port);
        let _writer = start(config, tx).unwrap();

        // Accept the connection
        let _server_stream = listener.accept().unwrap();

        // Should receive InterfaceUp event
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceUp(InterfaceId(1), _, _)));
    }

    #[test]
    fn receive_frame() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        let (tx, rx) = crate::event::channel();

        let config = make_config(port);
        let _writer = start(config, tx).unwrap();

        let (mut server_stream, _) = listener.accept().unwrap();

        // Drain the InterfaceUp event
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        // Send an HDLC frame from server (>= 19 bytes payload)
        let payload: Vec<u8> = (0..32).collect();
        let framed = hdlc::frame(&payload);
        server_stream.write_all(&framed).unwrap();

        // Should receive Frame event
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame {
                interface_id,
                data,
                rssi: _,
                snr: _,
            } => {
                assert_eq!(interface_id, InterfaceId(1));
                assert_eq!(data, payload);
            }
            other => panic!("expected Frame, got {:?}", other),
        }
    }

    #[test]
    fn reader_enforces_upstream_frame_bounds_and_ifac_allowance() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        let (tx, rx) = crate::event::channel();
        let ifac_size = 8;

        let config = make_config(port);
        let _writer = start_with_ifac(config, tx, ifac_size, None).unwrap();
        let (mut server_stream, _) = listener.accept().unwrap();
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            Event::InterfaceUp(_, _, _)
        ));

        // The exact Reticulum header minimum is invalid; the next valid frame
        // must still be recovered from the same stream.
        server_stream
            .write_all(&hdlc::frame(&[0x11; rns_core::constants::HEADER_MINSIZE]))
            .unwrap();
        let minimum_valid = vec![0x22; rns_core::constants::HEADER_MINSIZE + 1];
        server_stream
            .write_all(&hdlc::frame(&minimum_valid))
            .unwrap();
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            Event::Frame { data, .. } if data == minimum_valid
        ));

        // IFAC bytes are part of the on-wire frame allowance.
        let maximum_valid = vec![0x33; HW_MTU + ifac_size];
        server_stream
            .write_all(&hdlc::frame(&maximum_valid))
            .unwrap();
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            Event::Frame { data, .. } if data == maximum_valid
        ));

        // An oversized frame is discarded and cannot poison the next frame.
        server_stream
            .write_all(&hdlc::frame(&vec![0x44; HW_MTU + ifac_size + 1]))
            .unwrap();
        let recovery = vec![0x55; rns_core::constants::HEADER_MINSIZE + 1];
        server_stream.write_all(&hdlc::frame(&recovery)).unwrap();
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            Event::Frame { data, .. } if data == recovery
        ));
    }

    #[test]
    fn send_frame() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        let (tx, _rx) = crate::event::channel();

        let config = make_config(port);
        let mut writer = start(config, tx).unwrap();

        let (mut server_stream, _) = listener.accept().unwrap();
        server_stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Send a frame via writer
        let payload: Vec<u8> = (0..24).collect();
        writer.send_frame(&payload).unwrap();

        // Read from server side
        let mut buf = [0u8; 256];
        let n = server_stream.read(&mut buf).unwrap();
        let expected = hdlc::frame(&payload);
        assert_eq!(&buf[..n], &expected[..]);
    }

    #[test]
    fn multiple_frames() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        let (tx, rx) = crate::event::channel();

        let config = make_config(port);
        let _writer = start(config, tx).unwrap();

        let (mut server_stream, _) = listener.accept().unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        // Send multiple frames
        let payloads: Vec<Vec<u8>> = (0..3)
            .map(|i| (0..24).map(|j| j + i * 50).collect())
            .collect();
        for p in &payloads {
            server_stream.write_all(&hdlc::frame(p)).unwrap();
        }

        // Should receive all frames
        for expected in &payloads {
            let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
            match event {
                Event::Frame { data, .. } => assert_eq!(&data, expected),
                other => panic!("expected Frame, got {:?}", other),
            }
        }
    }

    #[test]
    fn split_across_reads() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        let (tx, rx) = crate::event::channel();

        let config = make_config(port);
        let _writer = start(config, tx).unwrap();

        let (mut server_stream, _) = listener.accept().unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        // Send frame in two parts
        let payload: Vec<u8> = (0..32).collect();
        let framed = hdlc::frame(&payload);
        let mid = framed.len() / 2;

        server_stream.write_all(&framed[..mid]).unwrap();
        server_stream.flush().unwrap();
        thread::sleep(Duration::from_millis(50));
        server_stream.write_all(&framed[mid..]).unwrap();
        server_stream.flush().unwrap();

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { data, .. } => assert_eq!(data, payload),
            other => panic!("expected Frame, got {:?}", other),
        }
    }

    #[test]
    fn reconnect_on_close() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        listener.set_nonblocking(false).unwrap();
        let (tx, rx) = crate::event::channel();

        let config = make_config(port);
        let _writer = start(config, tx).unwrap();

        // Accept first connection and immediately close it
        let (server_stream, _) = listener.accept().unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        drop(server_stream);

        // Should get InterfaceDown
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceDown(InterfaceId(1))));

        // Accept the reconnection
        let _server_stream2 = listener.accept().unwrap();

        // Should get InterfaceUp again
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceUp(InterfaceId(1), _, _)));
    }

    #[test]
    fn socket_options() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();

        let stream = try_connect(&make_config(port), None).unwrap();
        let _server = listener.accept().unwrap();

        // Verify TCP_NODELAY is set
        let fd = stream.as_raw_fd();
        let mut val: libc::c_int = 0;
        let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                &mut val as *mut _ as *mut libc::c_void,
                &mut len,
            );
        }
        assert_eq!(val, 1, "TCP_NODELAY should be 1");
    }

    #[test]
    fn connect_timeout() {
        // Use a non-routable address to trigger timeout
        let config = TcpClientConfig {
            name: "timeout-test".into(),
            target_host: "192.0.2.1".into(), // TEST-NET, non-routable
            target_port: 12345,
            interface_id: InterfaceId(99),
            reconnect_wait: Duration::from_millis(100),
            max_reconnect_tries: Some(0),
            connect_timeout: Duration::from_millis(500),
            device: None,
            runtime: Arc::new(Mutex::new(TcpClientRuntime {
                target_host: "192.0.2.1".into(),
                target_port: 12345,
                reconnect_wait: Duration::from_millis(100),
                max_reconnect_tries: Some(0),
                connect_timeout: Duration::from_millis(500),
            })),
        };

        let start_time = std::time::Instant::now();
        let result = try_connect(&config, None);
        let elapsed = start_time.elapsed();

        assert!(result.is_err());
        // Should timeout roughly around 500ms, definitely under 5s
        assert!(elapsed < Duration::from_secs(5));
    }
}
