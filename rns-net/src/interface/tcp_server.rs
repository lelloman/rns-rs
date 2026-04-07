//! TCP server interface with HDLC framing.
//!
//! Accepts client connections and spawns per-client reader threads.
//! Each client gets a dynamically allocated InterfaceId.
//! Matches Python `TCPServerInterface` from `TCPInterface.py`.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use rns_core::constants;
use rns_core::transport::types::{InterfaceId, InterfaceInfo};

use crate::event::{Event, EventSender};
use crate::hdlc;
use crate::interface::{ListenerControl, Writer};

/// Configuration for a TCP server interface.
#[derive(Debug, Clone)]
pub struct TcpServerConfig {
    pub name: String,
    pub listen_ip: String,
    pub listen_port: u16,
    pub interface_id: InterfaceId,
    pub max_connections: Option<usize>,
    pub runtime: Arc<Mutex<TcpServerRuntime>>,
}

#[derive(Debug, Clone)]
pub struct TcpServerRuntime {
    pub max_connections: Option<usize>,
}

impl TcpServerRuntime {
    pub fn from_config(config: &TcpServerConfig) -> Self {
        Self {
            max_connections: config.max_connections,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpServerRuntimeConfigHandle {
    pub interface_name: String,
    pub runtime: Arc<Mutex<TcpServerRuntime>>,
    pub startup: TcpServerRuntime,
}

impl Default for TcpServerConfig {
    fn default() -> Self {
        let mut config = TcpServerConfig {
            name: String::new(),
            listen_ip: "0.0.0.0".into(),
            listen_port: 4242,
            interface_id: InterfaceId(0),
            max_connections: None,
            runtime: Arc::new(Mutex::new(TcpServerRuntime {
                max_connections: None,
            })),
        };
        let startup = TcpServerRuntime::from_config(&config);
        config.runtime = Arc::new(Mutex::new(startup));
        config
    }
}

/// Writer that sends HDLC-framed data over a TCP stream.
struct TcpServerWriter {
    stream: TcpStream,
}

impl Writer for TcpServerWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(&hdlc::frame(data))
    }
}

/// Start a TCP server. Spawns a listener thread that accepts connections
/// and per-client reader threads. Returns immediately.
///
/// `next_id` is shared with the node for allocating unique InterfaceIds
/// for each connected client.
pub fn start(
    config: TcpServerConfig,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
) -> io::Result<ListenerControl> {
    let addr = format!("{}:{}", config.listen_ip, config.listen_port);
    let listener = TcpListener::bind(&addr)?;
    listener.set_nonblocking(true)?;

    log::info!("[{}] TCP server listening on {}", config.name, addr);

    let name = config.name.clone();
    let runtime = Arc::clone(&config.runtime);
    let active_connections = Arc::new(AtomicUsize::new(0));
    let control = ListenerControl::new();
    let listener_control = control.clone();
    thread::Builder::new()
        .name(format!("tcp-server-{}", config.interface_id.0))
        .spawn(move || {
            listener_loop(
                listener,
                name,
                tx,
                next_id,
                runtime,
                active_connections,
                listener_control,
            );
        })?;

    Ok(control)
}

/// Listener thread: accepts connections and spawns reader threads.
fn listener_loop(
    listener: TcpListener,
    name: String,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
    runtime: Arc<Mutex<TcpServerRuntime>>,
    active_connections: Arc<AtomicUsize>,
    control: ListenerControl,
) {
    loop {
        if control.should_stop() {
            log::info!("[{}] listener stopping", name);
            return;
        }

        let stream_result = listener.accept().map(|(stream, _)| stream);
        let stream = match stream_result {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            Err(e) => {
                log::warn!("[{}] accept failed: {}", name, e);
                continue;
            }
        };

        let max_connections = runtime.lock().unwrap().max_connections;
        if let Some(max) = max_connections {
            if active_connections.load(Ordering::Relaxed) >= max {
                let peer = stream.peer_addr().ok();
                log::warn!(
                    "[{}] max connections ({}) reached, rejecting {:?}",
                    name,
                    max,
                    peer
                );
                drop(stream);
                continue;
            }
        }

        active_connections.fetch_add(1, Ordering::Relaxed);

        let client_id = InterfaceId(next_id.fetch_add(1, Ordering::Relaxed));
        let peer_addr = stream.peer_addr().ok();

        log::info!(
            "[{}] client connected: {:?} → id {}",
            name,
            peer_addr,
            client_id.0
        );

        // Set TCP_NODELAY on the client socket
        if let Err(e) = stream.set_nodelay(true) {
            log::warn!("[{}] set_nodelay failed: {}", name, e);
        }

        // Clone stream for writer
        let writer_stream = match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                log::warn!("[{}] failed to clone stream: {}", name, e);
                continue;
            }
        };

        let writer: Box<dyn Writer> = Box::new(TcpServerWriter {
            stream: writer_stream,
        });

        let info = InterfaceInfo {
            id: client_id,
            name: format!("TCPServerInterface/Client-{}", client_id.0),
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
            mtu: 65535,
            ia_freq: 0.0,
            started: 0.0,
            ingress_control: true,
        };

        // Send InterfaceUp with InterfaceInfo for dynamic registration
        if tx
            .send(Event::InterfaceUp(client_id, Some(writer), Some(info)))
            .is_err()
        {
            // Driver shut down
            return;
        }

        // Spawn reader thread for this client
        let client_tx = tx.clone();
        let client_name = name.clone();
        let client_active = active_connections.clone();
        thread::Builder::new()
            .name(format!("tcp-server-reader-{}", client_id.0))
            .spawn(move || {
                client_reader_loop(stream, client_id, client_name, client_tx, client_active);
            })
            .ok();
    }
}

/// Per-client reader thread: reads HDLC frames, sends to driver.
fn client_reader_loop(
    mut stream: TcpStream,
    id: InterfaceId,
    name: String,
    tx: EventSender,
    active_connections: Arc<AtomicUsize>,
) {
    let mut decoder = hdlc::Decoder::new();
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                log::info!("[{}] client {} disconnected", name, id.0);
                active_connections.fetch_sub(1, Ordering::Relaxed);
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
                        // Driver shut down
                        active_connections.fetch_sub(1, Ordering::Relaxed);
                        return;
                    }
                }
            }
            Err(e) => {
                log::warn!("[{}] client {} read error: {}", name, id.0, e);
                active_connections.fetch_sub(1, Ordering::Relaxed);
                let _ = tx.send(Event::InterfaceDown(id));
                return;
            }
        }
    }
}

// --- Factory implementation ---

use super::{InterfaceConfigData, InterfaceFactory, StartContext, StartResult};
use std::collections::HashMap;

/// Factory for `TCPServerInterface`.
pub struct TcpServerFactory;

impl InterfaceFactory for TcpServerFactory {
    fn type_name(&self) -> &str {
        "TCPServerInterface"
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        let listen_ip = params
            .get("listen_ip")
            .cloned()
            .unwrap_or_else(|| "0.0.0.0".into());
        let listen_port = params
            .get("listen_port")
            .and_then(|v| v.parse().ok())
            .unwrap_or(4242);
        let max_connections = params.get("max_connections").and_then(|v| v.parse().ok());
        let mut config = TcpServerConfig {
            name: name.to_string(),
            listen_ip,
            listen_port,
            interface_id: id,
            max_connections,
            runtime: Arc::new(Mutex::new(TcpServerRuntime {
                max_connections: None,
            })),
        };
        let startup = TcpServerRuntime::from_config(&config);
        config.runtime = Arc::new(Mutex::new(startup));
        Ok(Box::new(config))
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> io::Result<StartResult> {
        let cfg = *config
            .into_any()
            .downcast::<TcpServerConfig>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "wrong config type"))?;
        let control = start(cfg, ctx.tx, ctx.next_dynamic_id)?;
        Ok(StartResult::Listener {
            control: Some(control),
        })
    }
}

pub(crate) fn runtime_handle_from_config(config: &TcpServerConfig) -> TcpServerRuntimeConfigHandle {
    TcpServerRuntimeConfigHandle {
        interface_name: config.name.clone(),
        runtime: Arc::clone(&config.runtime),
        startup: TcpServerRuntime::from_config(config),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use std::time::Duration;

    fn find_free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn make_server_config(
        port: u16,
        interface_id: u64,
        max_connections: Option<usize>,
    ) -> TcpServerConfig {
        let mut config = TcpServerConfig {
            name: "test-server".into(),
            listen_ip: "127.0.0.1".into(),
            listen_port: port,
            interface_id: InterfaceId(interface_id),
            max_connections,
            runtime: Arc::new(Mutex::new(TcpServerRuntime {
                max_connections: None,
            })),
        };
        let startup = TcpServerRuntime::from_config(&config);
        config.runtime = Arc::new(Mutex::new(startup));
        config
    }

    #[test]
    fn accept_connection() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(1000));

        let config = make_server_config(port, 1, None);

        start(config, tx, next_id).unwrap();

        // Give server time to start listening
        thread::sleep(Duration::from_millis(50));

        // Connect a client
        let _client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        // Should receive InterfaceUp with InterfaceInfo (dynamic)
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::InterfaceUp(id, writer, info) => {
                assert_eq!(id, InterfaceId(1000));
                assert!(writer.is_some());
                assert!(info.is_some());
            }
            other => panic!("expected InterfaceUp, got {:?}", other),
        }
    }

    #[test]
    fn receive_frame_from_client() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(2000));

        let config = make_server_config(port, 2, None);

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        // Send an HDLC frame (>= 19 bytes)
        let payload: Vec<u8> = (0..32).collect();
        let framed = hdlc::frame(&payload);
        client.write_all(&framed).unwrap();

        // Should receive Frame event
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { interface_id, data } => {
                assert_eq!(interface_id, InterfaceId(2000));
                assert_eq!(data, payload);
            }
            other => panic!("expected Frame, got {:?}", other),
        }
    }

    #[test]
    fn send_frame_to_client() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(3000));

        let config = make_server_config(port, 3, None);

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Get the writer from InterfaceUp
        let event = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let mut writer = match event {
            Event::InterfaceUp(_, Some(w), _) => w,
            other => panic!("expected InterfaceUp with writer, got {:?}", other),
        };

        // Send a frame via writer
        let payload: Vec<u8> = (0..24).collect();
        writer.send_frame(&payload).unwrap();

        // Read from client side
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).unwrap();
        let expected = hdlc::frame(&payload);
        assert_eq!(&buf[..n], &expected[..]);
    }

    #[test]
    fn multiple_clients() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(4000));

        let config = make_server_config(port, 4, None);

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        // Connect two clients
        let _client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let _client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        // Collect InterfaceUp events
        let mut ids = Vec::new();
        for _ in 0..2 {
            let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
            match event {
                Event::InterfaceUp(id, _, _) => ids.push(id),
                other => panic!("expected InterfaceUp, got {:?}", other),
            }
        }

        // Should have unique IDs
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
    }

    #[test]
    fn client_disconnect() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(5000));

        let config = make_server_config(port, 5, None);

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        // Disconnect
        drop(client);

        // Should receive InterfaceDown
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            matches!(event, Event::InterfaceDown(InterfaceId(5000))),
            "expected InterfaceDown(5000), got {:?}",
            event
        );
    }

    #[test]
    fn server_bind_port() {
        let port = find_free_port();
        let (tx, _rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(6000));

        let config = make_server_config(port, 6, None);

        // Should not error
        start(config, tx, next_id).unwrap();
    }

    #[test]
    fn max_connections_rejects_excess() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(7000));

        let config = make_server_config(port, 7, Some(2));

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        // Connect two clients (at limit)
        let _client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let _client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        // Drain both InterfaceUp events
        for _ in 0..2 {
            let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(matches!(event, Event::InterfaceUp(_, _, _)));
        }

        // Third connection should be accepted at TCP level but immediately dropped by server
        let client3 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        client3
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();

        // Give server time to reject
        thread::sleep(Duration::from_millis(100));

        // Should NOT receive a third InterfaceUp
        let result = rx.recv_timeout(Duration::from_millis(500));
        assert!(
            result.is_err(),
            "expected no InterfaceUp for rejected connection, got {:?}",
            result
        );
    }

    #[test]
    fn max_connections_allows_after_disconnect() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(7100));

        let config = make_server_config(port, 71, Some(1));

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        // Connect first client
        let client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceUp(_, _, _)));

        // Disconnect first client
        drop(client1);

        // Wait for InterfaceDown
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceDown(_)));

        // Now a new connection should be accepted
        let _client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            matches!(event, Event::InterfaceUp(_, _, _)),
            "expected InterfaceUp after slot freed, got {:?}",
            event
        );
    }

    #[test]
    fn runtime_max_connections_updates_live() {
        let port = find_free_port();
        let (tx, rx) = crate::event::channel();
        let next_id = Arc::new(AtomicU64::new(7200));

        let config = make_server_config(port, 72, None);
        let runtime = Arc::clone(&config.runtime);

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let _client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceUp(_, _, _)));

        {
            let mut runtime = runtime.lock().unwrap();
            runtime.max_connections = Some(1);
        }

        let _client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let result = rx.recv_timeout(Duration::from_millis(400));
        assert!(
            result.is_err(),
            "expected no InterfaceUp after lowering max_connections, got {:?}",
            result
        );
    }
}
