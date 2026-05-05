//! Local shared instance interface.
//!
//! Provides communication between the shared RNS instance and local client
//! programs. Uses Unix abstract sockets on Linux, TCP on other platforms.
//! HDLC framing over the connection (same as TCP interfaces).
//!
//! Two modes:
//! - `LocalServer`: The shared instance binds and accepts client connections.
//! - `LocalClient`: Connects to an existing shared instance.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rns_core::constants;
use rns_core::transport::types::{InterfaceId, InterfaceInfo};

use crate::event::{Event, EventSender};
use crate::hdlc;
use crate::interface::{ListenerControl, Writer};

#[cfg(target_os = "android")]
const CLIENT_SLEEP_PAUSE_TIMEOUT: Duration = Duration::from_secs(12);
#[cfg(target_os = "android")]
const PHY_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// Configuration for a Local server (shared instance).
#[derive(Debug, Clone)]
pub struct LocalServerConfig {
    pub instance_name: String,
    pub port: u16,
    pub interface_id: InterfaceId,
}

impl Default for LocalServerConfig {
    fn default() -> Self {
        LocalServerConfig {
            instance_name: "default".into(),
            port: 37428,
            interface_id: InterfaceId(0),
        }
    }
}

/// Configuration for a Local client (connecting to shared instance).
#[derive(Debug, Clone)]
pub struct LocalClientConfig {
    pub name: String,
    pub instance_name: String,
    pub port: u16,
    pub interface_id: InterfaceId,
    pub reconnect_wait: Duration,
}

impl Default for LocalClientConfig {
    fn default() -> Self {
        LocalClientConfig {
            name: "Local shared instance".into(),
            instance_name: "default".into(),
            port: 37428,
            interface_id: InterfaceId(0),
            reconnect_wait: Duration::from_secs(8),
        }
    }
}

/// HDLC writer over a TCP or Unix stream.
struct LocalWriter {
    stream: TcpStream,
    sleep_hold: Option<ClientSleepHold>,
}

impl Writer for LocalWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        if self
            .sleep_hold
            .as_ref()
            .is_some_and(ClientSleepHold::should_drop_outbound)
        {
            log::debug!("TX paused for LocalInterface client, dropping outbound packet");
            return Ok(());
        }
        self.stream.write_all(&hdlc::frame(data))
    }
}

#[derive(Clone)]
struct ClientSleepHold {
    timeout: Duration,
    deadline: Arc<Mutex<Instant>>,
}

impl ClientSleepHold {
    #[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
    fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            deadline: Arc::new(Mutex::new(Instant::now() + timeout)),
        }
    }

    fn refresh(&self) {
        *lock_or_recover(&self.deadline) = Instant::now() + self.timeout;
    }

    fn should_drop_outbound(&self) -> bool {
        Instant::now() > *lock_or_recover(&self.deadline)
    }
}

fn lock_or_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn android_client_sleep_hold() -> Option<ClientSleepHold> {
    #[cfg(target_os = "android")]
    {
        Some(ClientSleepHold::new(CLIENT_SLEEP_PAUSE_TIMEOUT))
    }
    #[cfg(not(target_os = "android"))]
    {
        None
    }
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
fn spawn_physical_keepalive_loop(
    mut writer: Box<dyn Writer>,
    interface_id: InterfaceId,
    interface_name: String,
    interval: Duration,
) {
    thread::Builder::new()
        .name(format!("local-phy-keepalive-{}", interface_id.0))
        .spawn(move || loop {
            thread::sleep(interval);
            if let Err(err) = writer.send_frame(&[]) {
                log::debug!(
                    "[{}:{}] LocalInterface physical keepalive stopped: {}",
                    interface_name,
                    interface_id.0,
                    err
                );
                return;
            }
        })
        .ok();
}

fn maybe_spawn_local_client_phy_keepalive(
    stream: &LocalClientStream,
    interface_id: InterfaceId,
    interface_name: &str,
) -> io::Result<()> {
    #[cfg(target_os = "android")]
    {
        let writer = local_client_stream_writer(stream)?;
        spawn_physical_keepalive_loop(
            writer,
            interface_id,
            interface_name.to_string(),
            PHY_KEEPALIVE_INTERVAL,
        );
    }

    #[cfg(not(target_os = "android"))]
    {
        let _ = (stream, interface_id, interface_name);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
mod unix_socket {
    use std::io;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};

    fn abstract_addr(instance_name: &str) -> io::Result<SocketAddr> {
        SocketAddr::from_abstract_name(format!("rns/{}", instance_name))
    }

    /// Try to bind a Unix abstract socket with the given instance name.
    pub fn try_bind_unix(instance_name: &str) -> io::Result<UnixListener> {
        let addr = abstract_addr(instance_name)?;
        UnixListener::bind_addr(&addr)
    }

    /// Try to connect to a Unix abstract socket.
    pub fn try_connect_unix(instance_name: &str) -> io::Result<UnixStream> {
        let addr = abstract_addr(instance_name)?;
        UnixStream::connect_addr(&addr)
    }
}

// ==================== LOCAL SERVER ====================

/// Start a local server (shared instance).
/// Tries Unix abstract socket first on Linux, falls back to TCP.
/// Spawns an acceptor thread. Each client gets a dynamically allocated InterfaceId.
pub fn start_server(
    config: LocalServerConfig,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
) -> io::Result<ListenerControl> {
    let control = ListenerControl::new();
    // Try Unix socket first on Linux
    #[cfg(target_os = "linux")]
    {
        match unix_socket::try_bind_unix(&config.instance_name) {
            Ok(listener) => {
                listener.set_nonblocking(true)?;
                log::info!(
                    "Local server using Unix socket: rns/{}",
                    config.instance_name
                );
                let name = format!("rns/{}", config.instance_name);
                let listener_control = control.clone();
                thread::Builder::new()
                    .name("local-server".into())
                    .spawn(move || {
                        unix_server_loop(listener, name, tx, next_id, listener_control);
                    })?;
                return Ok(control);
            }
            Err(e) => {
                log::info!("Unix socket bind failed ({}), falling back to TCP", e);
            }
        }
    }

    // Fallback: TCP on localhost
    let addr = format!("127.0.0.1:{}", config.port);
    let listener = TcpListener::bind(&addr)?;
    listener.set_nonblocking(true)?;

    log::info!("Local server listening on TCP {}", addr);

    let listener_control = control.clone();
    thread::Builder::new()
        .name("local-server".into())
        .spawn(move || {
            tcp_server_loop(listener, tx, next_id, listener_control);
        })?;

    Ok(control)
}

/// TCP server accept loop for local interface.
fn tcp_server_loop(
    listener: TcpListener,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
    control: ListenerControl,
) {
    loop {
        if control.should_stop() {
            log::info!("Local TCP listener stopping");
            return;
        }

        let stream_result = listener.accept().map(|(stream, _)| stream);
        let stream = match stream_result {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(e) => {
                log::warn!("Local server accept failed: {}", e);
                continue;
            }
        };

        if let Err(e) = stream.set_nodelay(true) {
            log::warn!("Local server set_nodelay failed: {}", e);
        }

        let client_id = InterfaceId(next_id.fetch_add(1, Ordering::Relaxed));
        spawn_local_client_handler(stream, client_id, tx.clone());
    }
}

/// Unix socket server accept loop for local interface.
#[cfg(target_os = "linux")]
fn unix_server_loop(
    listener: std::os::unix::net::UnixListener,
    name: String,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
    control: ListenerControl,
) {
    loop {
        if control.should_stop() {
            log::info!("[{}] Local Unix listener stopping", name);
            return;
        }

        let stream_result = listener.accept().map(|(stream, _)| stream);
        let stream = match stream_result {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(e) => {
                log::warn!("[{}] Local server accept failed: {}", name, e);
                continue;
            }
        };

        let client_id = InterfaceId(next_id.fetch_add(1, Ordering::Relaxed));

        // Convert UnixStream to a pair of read/write handles
        let writer_stream = match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                log::warn!("Local server clone failed: {}", e);
                continue;
            }
        };

        let sleep_hold = android_client_sleep_hold();
        let info = make_local_interface_info(client_id);
        let writer: Box<dyn Writer> = Box::new(UnixLocalWriter {
            stream: writer_stream,
            sleep_hold: sleep_hold.clone(),
        });

        if tx
            .send(Event::InterfaceUp(client_id, Some(writer), Some(info)))
            .is_err()
        {
            return;
        }

        let client_tx = tx.clone();
        thread::Builder::new()
            .name(format!("local-unix-reader-{}", client_id.0))
            .spawn(move || {
                unix_reader_loop(stream, client_id, client_tx, sleep_hold);
            })
            .ok();
    }
}

#[cfg(target_os = "linux")]
struct UnixLocalWriter {
    stream: std::os::unix::net::UnixStream,
    sleep_hold: Option<ClientSleepHold>,
}

#[cfg(target_os = "linux")]
impl Writer for UnixLocalWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        use std::io::Write;
        if self
            .sleep_hold
            .as_ref()
            .is_some_and(ClientSleepHold::should_drop_outbound)
        {
            log::debug!("TX paused for LocalInterface client, dropping outbound packet");
            return Ok(());
        }
        self.stream.write_all(&hdlc::frame(data))
    }
}

#[cfg(target_os = "linux")]
fn unix_reader_loop(
    mut stream: std::os::unix::net::UnixStream,
    id: InterfaceId,
    tx: EventSender,
    sleep_hold: Option<ClientSleepHold>,
) {
    use std::io::Read;
    let mut decoder = hdlc::Decoder::new();
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                let _ = tx.send(Event::InterfaceDown(id));
                return;
            }
            Ok(n) => {
                if let Some(ref sleep_hold) = sleep_hold {
                    sleep_hold.refresh();
                }
                for frame in decoder.feed(&buf[..n]) {
                    if tx
                        .send(Event::Frame {
                            interface_id: id,
                            data: frame,
                            rssi: None,
                            snr: None,
                        })
                        .is_err()
                    {
                        return;
                    }
                }
            }
            Err(_) => {
                let _ = tx.send(Event::InterfaceDown(id));
                return;
            }
        }
    }
}

/// Spawn handler threads for a connected TCP local client.
fn spawn_local_client_handler(stream: TcpStream, client_id: InterfaceId, tx: EventSender) {
    let writer_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("Local server clone failed: {}", e);
            return;
        }
    };

    let sleep_hold = android_client_sleep_hold();
    let info = make_local_interface_info(client_id);
    let writer: Box<dyn Writer> = Box::new(LocalWriter {
        stream: writer_stream,
        sleep_hold: sleep_hold.clone(),
    });

    if tx
        .send(Event::InterfaceUp(client_id, Some(writer), Some(info)))
        .is_err()
    {
        return;
    }

    thread::Builder::new()
        .name(format!("local-reader-{}", client_id.0))
        .spawn(move || {
            tcp_reader_loop(stream, client_id, tx, sleep_hold);
        })
        .ok();
}

fn tcp_reader_loop(
    mut stream: TcpStream,
    id: InterfaceId,
    tx: EventSender,
    sleep_hold: Option<ClientSleepHold>,
) {
    let mut decoder = hdlc::Decoder::new();
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                log::info!("Local client {} disconnected", id.0);
                let _ = tx.send(Event::InterfaceDown(id));
                return;
            }
            Ok(n) => {
                if let Some(ref sleep_hold) = sleep_hold {
                    sleep_hold.refresh();
                }
                for frame in decoder.feed(&buf[..n]) {
                    if tx
                        .send(Event::Frame {
                            interface_id: id,
                            data: frame,
                            rssi: None,
                            snr: None,
                        })
                        .is_err()
                    {
                        return;
                    }
                }
            }
            Err(e) => {
                log::warn!("Local client {} read error: {}", id.0, e);
                let _ = tx.send(Event::InterfaceDown(id));
                return;
            }
        }
    }
}

fn make_local_interface_info(id: InterfaceId) -> InterfaceInfo {
    InterfaceInfo {
        id,
        name: String::from("LocalInterface"),
        mode: constants::MODE_FULL,
        out_capable: true,
        in_capable: true,
        bitrate: Some(1_000_000_000), // 1 Gbps
        airtime_profile: None,
        announce_rate_target: None,
        announce_rate_grace: 0,
        announce_rate_penalty: 0.0,
        announce_cap: constants::ANNOUNCE_CAP,
        is_local_client: false,
        wants_tunnel: false,
        tunnel_id: None,
        mtu: 65535,
        ia_freq: 0.0,
        started: 0.0,
        ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
    }
}

// ==================== LOCAL CLIENT ====================

#[cfg(target_os = "linux")]
enum LocalClientStream {
    Unix(std::os::unix::net::UnixStream),
    Tcp(TcpStream),
}

#[cfg(target_os = "linux")]
impl LocalClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            LocalClientStream::Unix(stream) => stream.read(buf),
            LocalClientStream::Tcp(stream) => stream.read(buf),
        }
    }

    fn writer(&self) -> io::Result<Box<dyn Writer>> {
        match self {
            LocalClientStream::Unix(stream) => Ok(Box::new(UnixLocalWriter {
                stream: stream.try_clone()?,
                sleep_hold: None,
            })),
            LocalClientStream::Tcp(stream) => Ok(Box::new(LocalWriter {
                stream: stream.try_clone()?,
                sleep_hold: None,
            })),
        }
    }
}

#[cfg(not(target_os = "linux"))]
type LocalClientStream = TcpStream;

#[cfg(not(target_os = "linux"))]
fn local_client_stream_writer(stream: &LocalClientStream) -> io::Result<Box<dyn Writer>> {
    Ok(Box::new(LocalWriter {
        stream: stream.try_clone()?,
        sleep_hold: None,
    }))
}

#[cfg(target_os = "linux")]
fn local_client_stream_writer(stream: &LocalClientStream) -> io::Result<Box<dyn Writer>> {
    stream.writer()
}

fn try_connect_tcp(config: &LocalClientConfig) -> io::Result<TcpStream> {
    let addr = format!("127.0.0.1:{}", config.port);
    let stream = TcpStream::connect(&addr)?;
    stream.set_nodelay(true)?;
    log::info!(
        "[{}] Connected to shared instance via TCP {}",
        config.name,
        addr
    );
    Ok(stream)
}

#[cfg(target_os = "linux")]
fn try_connect_local_client(config: &LocalClientConfig) -> io::Result<LocalClientStream> {
    match unix_socket::try_connect_unix(&config.instance_name) {
        Ok(stream) => {
            log::info!(
                "[{}] Connected to shared instance via Unix socket: rns/{}",
                config.name,
                config.instance_name
            );
            Ok(LocalClientStream::Unix(stream))
        }
        Err(e) => {
            log::info!(
                "[{}] Unix socket connect failed ({}), trying TCP",
                config.name,
                e
            );
            try_connect_tcp(config).map(LocalClientStream::Tcp)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn try_connect_local_client(config: &LocalClientConfig) -> io::Result<LocalClientStream> {
    try_connect_tcp(config)
}

fn reconnect_local_client(config: &LocalClientConfig, tx: &EventSender) -> LocalClientStream {
    loop {
        thread::sleep(config.reconnect_wait);
        match try_connect_local_client(config) {
            Ok(stream) => match local_client_stream_writer(&stream) {
                Ok(writer) => {
                    let _ = maybe_spawn_local_client_phy_keepalive(
                        &stream,
                        config.interface_id,
                        &config.name,
                    );
                    let _ = tx.send(Event::InterfaceUp(config.interface_id, Some(writer), None));
                    return stream;
                }
                Err(e) => {
                    log::warn!("[{}] failed to clone reconnect writer: {}", config.name, e);
                }
            },
            Err(e) => {
                log::warn!("[{}] reconnect failed: {}", config.name, e);
            }
        }
    }
}

fn local_client_reader_loop(
    mut stream: LocalClientStream,
    config: LocalClientConfig,
    tx: EventSender,
) {
    let id = config.interface_id;
    let mut decoder = hdlc::Decoder::new();
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                log::warn!("[{}] shared connection closed", config.name);
                let _ = tx.send(Event::InterfaceDown(id));
                stream = reconnect_local_client(&config, &tx);
                decoder = hdlc::Decoder::new();
            }
            Ok(n) => {
                for frame in decoder.feed(&buf[..n]) {
                    if tx
                        .send(Event::Frame {
                            interface_id: id,
                            data: frame,
                            rssi: None,
                            snr: None,
                        })
                        .is_err()
                    {
                        return;
                    }
                }
            }
            Err(e) => {
                log::warn!("[{}] shared read error: {}", config.name, e);
                let _ = tx.send(Event::InterfaceDown(id));
                stream = reconnect_local_client(&config, &tx);
                decoder = hdlc::Decoder::new();
            }
        }
    }
}

/// Start a local client (connect to shared instance).
/// Tries Unix socket first on Linux, falls back to TCP.
/// Returns the writer for the driver.
pub fn start_client(config: LocalClientConfig, tx: EventSender) -> io::Result<Box<dyn Writer>> {
    let id = config.interface_id;
    let stream = try_connect_local_client(&config)?;
    let writer = local_client_stream_writer(&stream)?;
    maybe_spawn_local_client_phy_keepalive(&stream, id, &config.name)?;

    let _ = tx.send(Event::InterfaceUp(id, None, None));

    thread::Builder::new()
        .name(format!("local-client-reader-{}", id.0))
        .spawn(move || {
            local_client_reader_loop(stream, config, tx);
        })?;

    Ok(writer)
}

// --- Factory implementations ---

use super::{InterfaceConfigData, InterfaceFactory, StartContext, StartResult};
use std::collections::HashMap;

/// Factory for `LocalServerInterface`.
pub struct LocalServerFactory;

impl InterfaceFactory for LocalServerFactory {
    fn type_name(&self) -> &str {
        "LocalServerInterface"
    }

    fn parse_config(
        &self,
        _name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        let instance_name = params
            .get("instance_name")
            .cloned()
            .unwrap_or_else(|| "default".into());
        let port = params
            .get("port")
            .and_then(|v| v.parse().ok())
            .unwrap_or(37428);

        Ok(Box::new(LocalServerConfig {
            instance_name,
            port,
            interface_id: id,
        }))
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> std::io::Result<StartResult> {
        let server_config = *config
            .into_any()
            .downcast::<LocalServerConfig>()
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "wrong config type")
            })?;

        let control = start_server(server_config, ctx.tx, ctx.next_dynamic_id)?;
        Ok(StartResult::Listener {
            control: Some(control),
        })
    }
}

/// Factory for `LocalClientInterface`.
pub struct LocalClientFactory;

impl InterfaceFactory for LocalClientFactory {
    fn type_name(&self) -> &str {
        "LocalClientInterface"
    }

    fn parse_config(
        &self,
        _name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        let instance_name = params
            .get("instance_name")
            .cloned()
            .unwrap_or_else(|| "default".into());
        let port = params
            .get("port")
            .and_then(|v| v.parse().ok())
            .unwrap_or(37428);

        Ok(Box::new(LocalClientConfig {
            instance_name,
            port,
            interface_id: id,
            ..LocalClientConfig::default()
        }))
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> std::io::Result<StartResult> {
        let client_config = *config
            .into_any()
            .downcast::<LocalClientConfig>()
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "wrong config type")
            })?;

        let id = client_config.interface_id;
        let name = client_config.name.clone();
        let info = InterfaceInfo {
            id,
            name,
            mode: ctx.mode,
            out_capable: true,
            in_capable: true,
            bitrate: Some(1_000_000_000),
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: rns_core::constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: 65535,
            ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
            ia_freq: 0.0,
            started: crate::time::now(),
        };

        let writer = start_client(client_config, ctx.tx)?;

        Ok(StartResult::Simple {
            id,
            info,
            writer,
            interface_type_name: "LocalInterface".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::sync::mpsc::RecvTimeoutError;

    #[cfg(target_os = "linux")]
    type TestClient = std::os::unix::net::UnixStream;

    #[cfg(not(target_os = "linux"))]
    type TestClient = TcpStream;

    fn connect_test_client(instance_name: &str, _port: u16) -> TestClient {
        #[cfg(target_os = "linux")]
        {
            unix_socket::try_connect_unix(instance_name).unwrap()
        }

        #[cfg(not(target_os = "linux"))]
        {
            TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap()
        }
    }

    fn find_free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn server_bind_tcp() {
        let port = find_free_port();
        let instance_name = "test-bind".to_string();
        let (tx, _rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(7000));

        let config = LocalServerConfig {
            instance_name: instance_name.clone(),
            port,
            interface_id: InterfaceId(70),
        };

        // We force TCP by using a unique instance name that won't conflict
        // with any existing Unix socket
        start_server(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        connect_test_client(&instance_name, port);
    }

    #[test]
    fn server_accept_client() {
        let port = find_free_port();
        let instance_name = "test-accept".to_string();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(7100));

        let config = LocalServerConfig {
            instance_name: instance_name.clone(),
            port,
            interface_id: InterfaceId(71),
        };

        start_server(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        connect_test_client(&instance_name, port);

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::InterfaceUp(id, writer, info) => {
                assert_eq!(id, InterfaceId(7100));
                assert!(writer.is_some());
                assert!(info.is_some());
            }
            other => panic!("expected InterfaceUp, got {:?}", other),
        }
    }

    #[test]
    fn server_stop_prevents_new_accepts() {
        let port = find_free_port();
        let instance_name = "test-stop".to_string();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(7150));

        let config = LocalServerConfig {
            instance_name: instance_name.clone(),
            port,
            interface_id: InterfaceId(71),
        };

        let control = start_server(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));
        control.request_stop();
        thread::sleep(Duration::from_millis(120));

        #[cfg(target_os = "linux")]
        let connect_result = unix_socket::try_connect_unix(&instance_name);

        #[cfg(not(target_os = "linux"))]
        let connect_result = TcpStream::connect(format!("127.0.0.1:{}", port));

        if let Ok(stream) = connect_result {
            drop(stream);
        }

        match rx.recv_timeout(Duration::from_millis(200)) {
            Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => {}
            other => panic!("expected no InterfaceUp after server stop, got {:?}", other),
        }
    }

    #[test]
    fn client_send_receive() {
        let port = find_free_port();
        let (server_tx, server_rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(7200));

        let server_config = LocalServerConfig {
            instance_name: "test-sr".into(),
            port,
            interface_id: InterfaceId(72),
        };

        start_server(server_config, server_tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        // Connect client
        let (client_tx, client_rx) = crate::event::channel();
        let client_config = LocalClientConfig {
            name: "test-client".into(),
            instance_name: "test-sr".into(),
            port,
            interface_id: InterfaceId(73),
            reconnect_wait: Duration::from_secs(1),
        };

        let mut client_writer = start_client(client_config, client_tx).unwrap();

        // Get server-side InterfaceUp
        let event = server_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let mut server_writer = match event {
            Event::InterfaceUp(_, Some(w), _) => w,
            other => panic!("expected InterfaceUp with writer, got {:?}", other),
        };

        // Get client-side InterfaceUp
        let event = client_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::InterfaceUp(id, _, _) => assert_eq!(id, InterfaceId(73)),
            other => panic!("expected InterfaceUp, got {:?}", other),
        }

        // Client sends to server
        let payload: Vec<u8> = (0..32).collect();
        client_writer.send_frame(&payload).unwrap();

        let event = server_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { data, .. } => assert_eq!(data, payload),
            other => panic!("expected Frame, got {:?}", other),
        }

        // Server sends to client
        let payload2: Vec<u8> = (100..132).collect();
        server_writer.send_frame(&payload2).unwrap();

        let event = client_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { data, .. } => assert_eq!(data, payload2),
            other => panic!("expected Frame, got {:?}", other),
        }
    }

    #[test]
    fn sleep_hold_drops_outbound_after_timeout_and_refresh_restores() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();

        let sleep_hold = ClientSleepHold::new(Duration::from_millis(30));
        let mut writer = LocalWriter {
            stream: server_stream,
            sleep_hold: Some(sleep_hold.clone()),
        };

        writer.send_frame(b"live").unwrap();
        let mut buf = [0u8; 16];
        let n = client.read(&mut buf).unwrap();
        assert!(n > 0);

        thread::sleep(Duration::from_millis(50));
        writer.send_frame(b"drop").unwrap();
        let err = client.read(&mut buf).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "paused writer should not emit bytes, got {err:?}"
        );

        sleep_hold.refresh();
        writer.send_frame(b"again").unwrap();
        let n = client.read(&mut buf).unwrap();
        assert!(n > 0);
    }

    #[test]
    fn tcp_reader_refreshes_sleep_hold_on_inbound_data() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        let writer_stream = server_stream.try_clone().unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();

        let sleep_hold = ClientSleepHold::new(Duration::from_millis(30));
        let reader_sleep_hold = sleep_hold.clone();
        let (tx, rx) = crate::event::channel();
        thread::spawn(move || {
            tcp_reader_loop(server_stream, InterfaceId(98), tx, Some(reader_sleep_hold));
        });

        let mut writer = LocalWriter {
            stream: writer_stream,
            sleep_hold: Some(sleep_hold),
        };

        thread::sleep(Duration::from_millis(50));
        writer.send_frame(b"drop").unwrap();
        let mut buf = [0u8; 32];
        let err = client.read(&mut buf).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "paused writer should not emit bytes, got {err:?}"
        );

        let inbound = vec![0x42; constants::HEADER_MINSIZE];
        client.write_all(&hdlc::frame(&inbound)).unwrap();
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame {
                interface_id,
                data,
                rssi: _,
                snr: _,
            } => {
                assert_eq!(interface_id, InterfaceId(98));
                assert_eq!(data, inbound);
            }
            other => panic!("expected Frame, got {:?}", other),
        }

        writer.send_frame(b"again").unwrap();
        let n = client.read(&mut buf).unwrap();
        assert!(n > 0);
    }

    #[test]
    fn physical_keepalive_loop_sends_empty_hdlc_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();

        let writer: Box<dyn Writer> = Box::new(LocalWriter {
            stream: server_stream,
            sleep_hold: None,
        });
        spawn_physical_keepalive_loop(
            writer,
            InterfaceId(99),
            "test-local".into(),
            Duration::from_millis(10),
        );

        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0x7E, 0x7E]);
    }

    #[test]
    fn multiple_local_clients() {
        let port = find_free_port();
        let instance_name = "test-multi".to_string();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(7300));

        let config = LocalServerConfig {
            instance_name: instance_name.clone(),
            port,
            interface_id: InterfaceId(74),
        };

        start_server(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let _client1 = connect_test_client(&instance_name, port);
        let _client2 = connect_test_client(&instance_name, port);

        let mut ids = Vec::new();
        for _ in 0..2 {
            let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
            match event {
                Event::InterfaceUp(id, _, _) => ids.push(id),
                other => panic!("expected InterfaceUp, got {:?}", other),
            }
        }

        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
    }

    #[test]
    fn client_disconnect_detected() {
        let port = find_free_port();
        let instance_name = "test-dc".to_string();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(7400));

        let config = LocalServerConfig {
            instance_name: instance_name.clone(),
            port,
            interface_id: InterfaceId(75),
        };

        start_server(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        #[cfg(target_os = "linux")]
        let client = unix_socket::try_connect_unix(&instance_name).unwrap();

        #[cfg(not(target_os = "linux"))]
        let client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        // Disconnect
        drop(client);

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            matches!(event, Event::InterfaceDown(_)),
            "expected InterfaceDown, got {:?}",
            event
        );
    }

    #[test]
    fn client_reconnects_after_tcp_restart() {
        let port = find_free_port();
        let addr = format!("127.0.0.1:{}", port);
        let instance_name = format!("test-reconnect-{}", port);

        let listener1 = TcpListener::bind(&addr).unwrap();
        let (accepted1_tx, accepted1_rx) = mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener1.accept().unwrap();
            accepted1_tx.send(stream).unwrap();
        });

        let (client_tx, client_rx) = crate::event::channel();
        let client_config = LocalClientConfig {
            name: "test-client".into(),
            instance_name,
            port,
            interface_id: InterfaceId(76),
            reconnect_wait: Duration::from_millis(50),
        };

        let _writer = start_client(client_config, client_tx).unwrap();
        let event = client_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            event,
            Event::InterfaceUp(InterfaceId(76), None, None)
        ));

        let stream1 = accepted1_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(stream1);

        let event = client_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceDown(InterfaceId(76))));

        let listener2 = TcpListener::bind(&addr).unwrap();
        let (accepted2_tx, accepted2_rx) = mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener2.accept().unwrap();
            accepted2_tx.send(stream).unwrap();
        });

        let mut reconnected_writer = None;
        for _ in 0..10 {
            let event = client_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            match event {
                Event::InterfaceUp(InterfaceId(76), writer, None) if writer.is_some() => {
                    reconnected_writer = writer;
                    break;
                }
                _ => {}
            }
        }

        let mut reconnected_writer = reconnected_writer.expect("missing reconnect writer");
        let mut stream2 = accepted2_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        reconnected_writer.send_frame(b"client->server").unwrap();
        stream2
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; 64];
        let n = stream2.read(&mut buf).unwrap();
        assert!(n > 0, "expected bytes from refreshed writer");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unix_abstract_socket_helpers_work() {
        let instance_name = format!(
            "test-abstract-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let listener = unix_socket::try_bind_unix(&instance_name).unwrap();
        let accept_thread = thread::spawn(move || listener.accept().unwrap().0);

        let mut client = unix_socket::try_connect_unix(&instance_name).unwrap();
        let mut server = accept_thread.join().unwrap();

        client.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
    }
}
