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
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rns_core::constants;
use rns_core::transport::types::{InterfaceId, InterfaceInfo};

use crate::event::{Event, EventSender};
use crate::hdlc;
use crate::interface::Writer;

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
}

impl Writer for LocalWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(&hdlc::frame(data))
    }
}

#[cfg(target_os = "linux")]
mod unix_socket {
    use std::io;
    use std::os::unix::net::{UnixListener, UnixStream};

    /// Try to bind a Unix abstract socket with the given instance name.
    pub fn try_bind_unix(instance_name: &str) -> io::Result<UnixListener> {
        let path = format!("\0rns/{}", instance_name);
        UnixListener::bind(path)
    }

    /// Try to connect to a Unix abstract socket.
    pub fn try_connect_unix(instance_name: &str) -> io::Result<UnixStream> {
        let path = format!("\0rns/{}", instance_name);
        UnixStream::connect(path)
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
) -> io::Result<()> {
    // Try Unix socket first on Linux
    #[cfg(target_os = "linux")]
    {
        match unix_socket::try_bind_unix(&config.instance_name) {
            Ok(listener) => {
                log::info!(
                    "Local server using Unix socket: rns/{}",
                    config.instance_name
                );
                let name = format!("rns/{}", config.instance_name);
                thread::Builder::new()
                    .name("local-server".into())
                    .spawn(move || {
                        unix_server_loop(listener, name, tx, next_id);
                    })?;
                return Ok(());
            }
            Err(e) => {
                log::info!(
                    "Unix socket bind failed ({}), falling back to TCP",
                    e
                );
            }
        }
    }

    // Fallback: TCP on localhost
    let addr = format!("127.0.0.1:{}", config.port);
    let listener = TcpListener::bind(&addr)?;

    log::info!("Local server listening on TCP {}", addr);

    thread::Builder::new()
        .name("local-server".into())
        .spawn(move || {
            tcp_server_loop(listener, tx, next_id);
        })?;

    Ok(())
}

/// TCP server accept loop for local interface.
fn tcp_server_loop(listener: TcpListener, tx: EventSender, next_id: Arc<AtomicU64>) {
    for stream_result in listener.incoming() {
        let stream = match stream_result {
            Ok(s) => s,
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
) {
    for stream_result in listener.incoming() {
        let stream = match stream_result {
            Ok(s) => s,
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

        let info = make_local_interface_info(client_id);
        let writer: Box<dyn Writer> = Box::new(UnixLocalWriter { stream: writer_stream });

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
                unix_reader_loop(stream, client_id, client_tx);
            })
            .ok();
    }
}

#[cfg(target_os = "linux")]
struct UnixLocalWriter {
    stream: std::os::unix::net::UnixStream,
}

#[cfg(target_os = "linux")]
impl Writer for UnixLocalWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        use std::io::Write;
        self.stream.write_all(&hdlc::frame(data))
    }
}

#[cfg(target_os = "linux")]
fn unix_reader_loop(
    mut stream: std::os::unix::net::UnixStream,
    id: InterfaceId,
    tx: EventSender,
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
                for frame in decoder.feed(&buf[..n]) {
                    if tx
                        .send(Event::Frame {
                            interface_id: id,
                            data: frame,
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

    let info = make_local_interface_info(client_id);
    let writer: Box<dyn Writer> = Box::new(LocalWriter { stream: writer_stream });

    if tx
        .send(Event::InterfaceUp(client_id, Some(writer), Some(info)))
        .is_err()
    {
        return;
    }

    thread::Builder::new()
        .name(format!("local-reader-{}", client_id.0))
        .spawn(move || {
            tcp_reader_loop(stream, client_id, tx);
        })
        .ok();
}

fn tcp_reader_loop(mut stream: TcpStream, id: InterfaceId, tx: EventSender) {
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
                for frame in decoder.feed(&buf[..n]) {
                    if tx
                        .send(Event::Frame {
                            interface_id: id,
                            data: frame,
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
        mode: constants::MODE_FULL,
        out_capable: true,
        in_capable: true,
        bitrate: Some(1_000_000_000), // 1 Gbps
        announce_rate_target: None,
        announce_rate_grace: 0,
        announce_rate_penalty: 0.0,
    }
}

// ==================== LOCAL CLIENT ====================

/// Start a local client (connect to shared instance).
/// Tries Unix socket first on Linux, falls back to TCP.
/// Returns the writer for the driver.
pub fn start_client(config: LocalClientConfig, tx: EventSender) -> io::Result<Box<dyn Writer>> {
    let id = config.interface_id;

    // Try Unix socket first on Linux
    #[cfg(target_os = "linux")]
    {
        match unix_socket::try_connect_unix(&config.instance_name) {
            Ok(stream) => {
                log::info!(
                    "[{}] Connected to shared instance via Unix socket: rns/{}",
                    config.name,
                    config.instance_name
                );

                let writer_stream = stream.try_clone()?;
                let _ = tx.send(Event::InterfaceUp(id, None, None));

                let client_tx = tx;
                thread::Builder::new()
                    .name(format!("local-client-reader-{}", id.0))
                    .spawn(move || {
                        unix_reader_loop(stream, id, client_tx);
                    })?;

                return Ok(Box::new(UnixLocalWriter { stream: writer_stream }));
            }
            Err(e) => {
                log::info!(
                    "[{}] Unix socket connect failed ({}), trying TCP",
                    config.name,
                    e
                );
            }
        }
    }

    // Fallback: TCP
    let addr = format!("127.0.0.1:{}", config.port);
    let stream = TcpStream::connect(&addr)?;
    stream.set_nodelay(true)?;

    log::info!("[{}] Connected to shared instance via TCP {}", config.name, addr);

    let reader_stream = stream.try_clone()?;
    let writer_stream = stream.try_clone()?;

    let _ = tx.send(Event::InterfaceUp(id, None, None));

    thread::Builder::new()
        .name(format!("local-client-reader-{}", id.0))
        .spawn(move || {
            tcp_reader_loop(reader_stream, id, tx);
        })?;

    Ok(Box::new(LocalWriter { stream: writer_stream }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

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
        let (tx, _rx) = mpsc::channel();
        let next_id = Arc::new(AtomicU64::new(7000));

        let config = LocalServerConfig {
            instance_name: "test-bind".into(),
            port,
            interface_id: InterfaceId(70),
        };

        // We force TCP by using a unique instance name that won't conflict
        // with any existing Unix socket
        start_server(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        // Should be able to connect
        let _client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    }

    #[test]
    fn server_accept_client() {
        let port = find_free_port();
        let (tx, rx) = mpsc::channel();
        let next_id = Arc::new(AtomicU64::new(7100));

        let config = LocalServerConfig {
            instance_name: "test-accept".into(),
            port,
            interface_id: InterfaceId(71),
        };

        start_server(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let _client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

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
    fn client_send_receive() {
        let port = find_free_port();
        let (server_tx, server_rx) = mpsc::channel();
        let next_id = Arc::new(AtomicU64::new(7200));

        let server_config = LocalServerConfig {
            instance_name: "test-sr".into(),
            port,
            interface_id: InterfaceId(72),
        };

        start_server(server_config, server_tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        // Connect client
        let (client_tx, client_rx) = mpsc::channel();
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
    fn multiple_local_clients() {
        let port = find_free_port();
        let (tx, rx) = mpsc::channel();
        let next_id = Arc::new(AtomicU64::new(7300));

        let config = LocalServerConfig {
            instance_name: "test-multi".into(),
            port,
            interface_id: InterfaceId(74),
        };

        start_server(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let _c1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let _c2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

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
        let (tx, rx) = mpsc::channel();
        let next_id = Arc::new(AtomicU64::new(7400));

        let config = LocalServerConfig {
            instance_name: "test-dc".into(),
            port,
            interface_id: InterfaceId(75),
        };

        start_server(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

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
}
