//! Backbone TCP mesh interface using Linux epoll.
//!
//! Server mode: listens on a TCP port, accepts peer connections, spawns
//! dynamic per-peer interfaces. Uses a single epoll thread to multiplex
//! all client sockets. HDLC framing for packet boundaries.
//!
//! Client mode: connects to a remote backbone server, single TCP connection
//! with HDLC framing. Reconnects on disconnect.
//!
//! Matches Python `BackboneInterface.py`.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rns_core::constants;
use rns_core::transport::types::{InterfaceId, InterfaceInfo};

use crate::event::{Event, EventSender};
use crate::hdlc;
use crate::interface::Writer;

/// HW_MTU: 1 MB (matches Python BackboneInterface.HW_MTU)
#[allow(dead_code)]
const HW_MTU: usize = 1_048_576;

/// Configuration for a backbone interface.
#[derive(Debug, Clone)]
pub struct BackboneConfig {
    pub name: String,
    pub listen_ip: String,
    pub listen_port: u16,
    pub interface_id: InterfaceId,
}

impl Default for BackboneConfig {
    fn default() -> Self {
        BackboneConfig {
            name: String::new(),
            listen_ip: "0.0.0.0".into(),
            listen_port: 0,
            interface_id: InterfaceId(0),
        }
    }
}

/// Writer that sends HDLC-framed data directly via socket write.
struct BackboneWriter {
    fd: RawFd,
}

impl Writer for BackboneWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        let framed = hdlc::frame(data);
        let mut offset = 0;
        while offset < framed.len() {
            let n = unsafe {
                libc::send(
                    self.fd,
                    framed[offset..].as_ptr() as *const libc::c_void,
                    framed.len() - offset,
                    libc::MSG_NOSIGNAL,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            offset += n as usize;
        }
        Ok(())
    }
}

// BackboneWriter's fd is a dup'd copy — we own it
impl Drop for BackboneWriter {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Safety: the fd is only accessed via send/close which are thread-safe.
unsafe impl Send for BackboneWriter {}

/// Start a backbone interface. Binds TCP listener, spawns epoll thread.
pub fn start(
    config: BackboneConfig,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
) -> io::Result<()> {
    let addr = format!("{}:{}", config.listen_ip, config.listen_port);
    let listener = TcpListener::bind(&addr)?;
    listener.set_nonblocking(true)?;

    log::info!(
        "[{}] backbone server listening on {}",
        config.name,
        listener.local_addr().unwrap_or(addr.parse().unwrap())
    );

    let name = config.name.clone();
    thread::Builder::new()
        .name(format!("backbone-epoll-{}", config.interface_id.0))
        .spawn(move || {
            if let Err(e) = epoll_loop(listener, name, tx, next_id) {
                log::error!("backbone epoll loop error: {}", e);
            }
        })?;

    Ok(())
}

/// Per-client tracking state.
struct ClientState {
    id: InterfaceId,
    decoder: hdlc::Decoder,
}

/// Main epoll event loop.
fn epoll_loop(
    listener: TcpListener,
    name: String,
    tx: EventSender,
    next_id: Arc<AtomicU64>,
) -> io::Result<()> {
    let epfd = unsafe { libc::epoll_create1(0) };
    if epfd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Register listener
    let listener_fd = listener.as_raw_fd();
    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: listener_fd as u64,
    };
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, listener_fd, &mut ev) } < 0 {
        unsafe { libc::close(epfd) };
        return Err(io::Error::last_os_error());
    }

    let mut clients: HashMap<RawFd, ClientState> = HashMap::new();
    let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; 64];

    loop {
        let nfds = unsafe {
            libc::epoll_wait(epfd, events.as_mut_ptr(), events.len() as i32, 1000)
        };

        if nfds < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // Clean up
            for (&fd, _) in &clients {
                unsafe {
                    libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut());
                    libc::close(fd);
                }
            }
            unsafe { libc::close(epfd) };
            return Err(err);
        }

        for i in 0..nfds as usize {
            let ev = &events[i];
            let fd = ev.u64 as RawFd;

            if fd == listener_fd {
                // Accept new connection
                loop {
                    match listener.accept() {
                        Ok((stream, peer_addr)) => {
                            let client_fd = stream.as_raw_fd();

                            // Set non-blocking
                            stream.set_nonblocking(true).ok();
                            stream.set_nodelay(true).ok();

                            // Set SO_KEEPALIVE and TCP options
                            set_tcp_keepalive(client_fd);

                            let client_id =
                                InterfaceId(next_id.fetch_add(1, Ordering::Relaxed));

                            log::info!(
                                "[{}] backbone client connected: {} → id {}",
                                name,
                                peer_addr,
                                client_id.0
                            );

                            // Register client fd with epoll
                            let mut cev = libc::epoll_event {
                                events: libc::EPOLLIN as u32,
                                u64: client_fd as u64,
                            };
                            if unsafe {
                                libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, client_fd, &mut cev)
                            } < 0
                            {
                                log::warn!(
                                    "[{}] failed to add client to epoll: {}",
                                    name,
                                    io::Error::last_os_error()
                                );
                                // stream drops here, closing client_fd — correct
                                continue;
                            }

                            // Prevent TcpStream from closing the fd on drop.
                            // From here on, we own client_fd via epoll.
                            std::mem::forget(stream);

                            // Create writer (dup the fd so writer has independent ownership)
                            let writer_fd = unsafe { libc::dup(client_fd) };
                            if writer_fd < 0 {
                                log::warn!("[{}] failed to dup client fd", name);
                                unsafe {
                                    libc::epoll_ctl(
                                        epfd,
                                        libc::EPOLL_CTL_DEL,
                                        client_fd,
                                        std::ptr::null_mut(),
                                    );
                                    libc::close(client_fd);
                                }
                                continue;
                            }
                            let writer: Box<dyn Writer> =
                                Box::new(BackboneWriter { fd: writer_fd });

                            clients.insert(
                                client_fd,
                                ClientState {
                                    id: client_id,
                                    decoder: hdlc::Decoder::new(),
                                },
                            );

                            let info = InterfaceInfo {
                                id: client_id,
                                name: format!("BackboneInterface/{}", client_fd),
                                mode: constants::MODE_FULL,
                                out_capable: true,
                                in_capable: true,
                                bitrate: Some(1_000_000_000), // 1 Gbps guess
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

                            if tx
                                .send(Event::InterfaceUp(
                                    client_id,
                                    Some(writer),
                                    Some(info),
                                ))
                                .is_err()
                            {
                                // Driver shut down
                                cleanup(epfd, &clients, listener_fd);
                                return Ok(());
                            }

                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            log::warn!("[{}] accept error: {}", name, e);
                            break;
                        }
                    }
                }
            } else if clients.contains_key(&fd) {
                // Client event
                let mut should_remove = false;
                let mut client_id = InterfaceId(0);

                if ev.events & libc::EPOLLIN as u32 != 0 {
                    let mut buf = [0u8; 4096];
                    let n = unsafe {
                        libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
                    };

                    if n <= 0 {
                        if let Some(c) = clients.get(&fd) {
                            client_id = c.id;
                        }
                        should_remove = true;
                    } else if let Some(client) = clients.get_mut(&fd) {
                        client_id = client.id;
                        for frame in client.decoder.feed(&buf[..n as usize]) {
                            if tx
                                .send(Event::Frame {
                                    interface_id: client_id,
                                    data: frame,
                                })
                                .is_err()
                            {
                                cleanup(epfd, &clients, listener_fd);
                                return Ok(());
                            }
                        }
                    }
                }

                if ev.events & (libc::EPOLLHUP | libc::EPOLLERR) as u32 != 0 {
                    if let Some(c) = clients.get(&fd) {
                        client_id = c.id;
                    }
                    should_remove = true;
                }

                if should_remove {
                    log::info!(
                        "[{}] backbone client {} disconnected",
                        name,
                        client_id.0
                    );
                    unsafe {
                        libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut());
                        libc::close(fd);
                    }
                    clients.remove(&fd);
                    let _ = tx.send(Event::InterfaceDown(client_id));
                }
            }
        }
    }
}

fn set_tcp_keepalive(fd: RawFd) {
    unsafe {
        let one: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let idle: libc::c_int = 5;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPIDLE,
            &idle as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let interval: libc::c_int = 2;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPINTVL,
            &interval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let cnt: libc::c_int = 12;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPCNT,
            &cnt as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

fn cleanup(epfd: RawFd, clients: &HashMap<RawFd, ClientState>, listener_fd: RawFd) {
    for (&fd, _) in clients {
        unsafe {
            libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut());
            libc::close(fd);
        }
    }
    unsafe {
        libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, listener_fd, std::ptr::null_mut());
        libc::close(epfd);
    }
}

// ---------------------------------------------------------------------------
// Client mode
// ---------------------------------------------------------------------------

/// Configuration for a backbone client interface.
#[derive(Debug, Clone)]
pub struct BackboneClientConfig {
    pub name: String,
    pub target_host: String,
    pub target_port: u16,
    pub interface_id: InterfaceId,
    pub reconnect_wait: Duration,
    pub max_reconnect_tries: Option<u32>,
    pub connect_timeout: Duration,
    pub transport_identity: Option<String>,
}

impl Default for BackboneClientConfig {
    fn default() -> Self {
        BackboneClientConfig {
            name: String::new(),
            target_host: "127.0.0.1".into(),
            target_port: 4242,
            interface_id: InterfaceId(0),
            reconnect_wait: Duration::from_secs(5),
            max_reconnect_tries: None,
            connect_timeout: Duration::from_secs(5),
            transport_identity: None,
        }
    }
}

/// Writer that sends HDLC-framed data over a TCP stream (client mode).
struct BackboneClientWriter {
    stream: TcpStream,
}

impl Writer for BackboneClientWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(&hdlc::frame(data))
    }
}

/// Try to connect to the target host:port with timeout.
fn try_connect_client(config: &BackboneClientConfig) -> io::Result<TcpStream> {
    let addr_str = format!("{}:{}", config.target_host, config.target_port);
    let addr = addr_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses resolved"))?;

    let stream = TcpStream::connect_timeout(&addr, config.connect_timeout)?;
    stream.set_nodelay(true)?;
    set_tcp_keepalive(stream.as_raw_fd());
    Ok(stream)
}

/// Connect and start the reader thread. Returns the writer for the driver.
pub fn start_client(
    config: BackboneClientConfig,
    tx: EventSender,
) -> io::Result<Box<dyn Writer>> {
    let stream = try_connect_client(&config)?;
    let reader_stream = stream.try_clone()?;
    let writer_stream = stream.try_clone()?;

    let id = config.interface_id;
    log::info!(
        "[{}] backbone client connected to {}:{}",
        config.name,
        config.target_host,
        config.target_port
    );

    // Initial connect: writer is None because it's returned directly to the caller
    let _ = tx.send(Event::InterfaceUp(id, None, None));

    thread::Builder::new()
        .name(format!("backbone-client-{}", id.0))
        .spawn(move || {
            client_reader_loop(reader_stream, config, tx);
        })?;

    Ok(Box::new(BackboneClientWriter { stream: writer_stream }))
}

/// Reader thread: reads from socket, HDLC-decodes, sends frames to driver.
/// On disconnect, attempts reconnection.
fn client_reader_loop(mut stream: TcpStream, config: BackboneClientConfig, tx: EventSender) {
    let id = config.interface_id;
    let mut decoder = hdlc::Decoder::new();
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                log::warn!("[{}] connection closed", config.name);
                let _ = tx.send(Event::InterfaceDown(id));
                match client_reconnect(&config, &tx) {
                    Some(new_stream) => {
                        stream = new_stream;
                        decoder = hdlc::Decoder::new();
                        continue;
                    }
                    None => {
                        log::error!("[{}] reconnection failed, giving up", config.name);
                        return;
                    }
                }
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
                log::warn!("[{}] read error: {}", config.name, e);
                let _ = tx.send(Event::InterfaceDown(id));
                match client_reconnect(&config, &tx) {
                    Some(new_stream) => {
                        stream = new_stream;
                        decoder = hdlc::Decoder::new();
                        continue;
                    }
                    None => {
                        log::error!("[{}] reconnection failed, giving up", config.name);
                        return;
                    }
                }
            }
        }
    }
}

/// Attempt to reconnect with retry logic. Returns the new reader stream on success.
/// Sends the new writer to the driver via InterfaceUp event.
fn client_reconnect(config: &BackboneClientConfig, tx: &EventSender) -> Option<TcpStream> {
    let mut attempts = 0u32;
    loop {
        thread::sleep(config.reconnect_wait);
        attempts += 1;

        if let Some(max) = config.max_reconnect_tries {
            if attempts > max {
                let _ = tx.send(Event::InterfaceDown(config.interface_id));
                return None;
            }
        }

        log::info!(
            "[{}] reconnect attempt {} ...",
            config.name,
            attempts
        );

        match try_connect_client(config) {
            Ok(new_stream) => {
                let writer_stream = match new_stream.try_clone() {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("[{}] failed to clone stream: {}", config.name, e);
                        continue;
                    }
                };
                log::info!("[{}] reconnected", config.name);
                let new_writer: Box<dyn Writer> =
                    Box::new(BackboneClientWriter { stream: writer_stream });
                let _ = tx.send(Event::InterfaceUp(config.interface_id, Some(new_writer), None));
                return Some(new_stream);
            }
            Err(e) => {
                log::warn!("[{}] reconnect failed: {}", config.name, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    fn find_free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn backbone_accept_connection() {
        let port = find_free_port();
        let (tx, rx) = mpsc::channel();
        let next_id = Arc::new(AtomicU64::new(8000));

        let config = BackboneConfig {
            name: "test-backbone".into(),
            listen_ip: "127.0.0.1".into(),
            listen_port: port,
            interface_id: InterfaceId(80),
        };

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let _client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::InterfaceUp(id, writer, info) => {
                assert_eq!(id, InterfaceId(8000));
                assert!(writer.is_some());
                assert!(info.is_some());
                let info = info.unwrap();
                assert!(info.out_capable);
                assert!(info.in_capable);
            }
            other => panic!("expected InterfaceUp, got {:?}", other),
        }
    }

    #[test]
    fn backbone_receive_frame() {
        let port = find_free_port();
        let (tx, rx) = mpsc::channel();
        let next_id = Arc::new(AtomicU64::new(8100));

        let config = BackboneConfig {
            name: "test-backbone".into(),
            listen_ip: "127.0.0.1".into(),
            listen_port: port,
            interface_id: InterfaceId(81),
        };

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        // Send HDLC frame (>= 19 bytes)
        let payload: Vec<u8> = (0..32).collect();
        client.write_all(&hdlc::frame(&payload)).unwrap();

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { interface_id, data } => {
                assert_eq!(interface_id, InterfaceId(8100));
                assert_eq!(data, payload);
            }
            other => panic!("expected Frame, got {:?}", other),
        }
    }

    #[test]
    fn backbone_send_to_client() {
        let port = find_free_port();
        let (tx, rx) = mpsc::channel();
        let next_id = Arc::new(AtomicU64::new(8200));

        let config = BackboneConfig {
            name: "test-backbone".into(),
            listen_ip: "127.0.0.1".into(),
            listen_port: port,
            interface_id: InterfaceId(82),
        };

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

        // Get writer from InterfaceUp
        let event = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let mut writer = match event {
            Event::InterfaceUp(_, Some(w), _) => w,
            other => panic!("expected InterfaceUp with writer, got {:?}", other),
        };

        // Send frame via writer
        let payload: Vec<u8> = (0..24).collect();
        writer.send_frame(&payload).unwrap();

        // Read from client
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).unwrap();
        let expected = hdlc::frame(&payload);
        assert_eq!(&buf[..n], &expected[..]);
    }

    #[test]
    fn backbone_multiple_clients() {
        let port = find_free_port();
        let (tx, rx) = mpsc::channel();
        let next_id = Arc::new(AtomicU64::new(8300));

        let config = BackboneConfig {
            name: "test-backbone".into(),
            listen_ip: "127.0.0.1".into(),
            listen_port: port,
            interface_id: InterfaceId(83),
        };

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let _client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let _client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

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
    fn backbone_client_disconnect() {
        let port = find_free_port();
        let (tx, rx) = mpsc::channel();
        let next_id = Arc::new(AtomicU64::new(8400));

        let config = BackboneConfig {
            name: "test-backbone".into(),
            listen_ip: "127.0.0.1".into(),
            listen_port: port,
            interface_id: InterfaceId(84),
        };

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
            matches!(event, Event::InterfaceDown(InterfaceId(8400))),
            "expected InterfaceDown(8400), got {:?}",
            event
        );
    }

    #[test]
    fn backbone_epoll_multiplexing() {
        let port = find_free_port();
        let (tx, rx) = mpsc::channel();
        let next_id = Arc::new(AtomicU64::new(8500));

        let config = BackboneConfig {
            name: "test-backbone".into(),
            listen_ip: "127.0.0.1".into(),
            listen_port: port,
            interface_id: InterfaceId(85),
        };

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let mut client1 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let mut client2 = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

        // Drain both InterfaceUp events
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        // Both clients send data simultaneously
        let payload1: Vec<u8> = (0..24).collect();
        let payload2: Vec<u8> = (100..130).collect();
        client1.write_all(&hdlc::frame(&payload1)).unwrap();
        client2.write_all(&hdlc::frame(&payload2)).unwrap();

        // Should receive both Frame events
        let mut received = Vec::new();
        for _ in 0..2 {
            let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
            match event {
                Event::Frame { data, .. } => received.push(data),
                other => panic!("expected Frame, got {:?}", other),
            }
        }
        assert!(received.contains(&payload1));
        assert!(received.contains(&payload2));
    }

    #[test]
    fn backbone_bind_port() {
        let port = find_free_port();
        let (tx, _rx) = mpsc::channel();
        let next_id = Arc::new(AtomicU64::new(8600));

        let config = BackboneConfig {
            name: "test-backbone".into(),
            listen_ip: "127.0.0.1".into(),
            listen_port: port,
            interface_id: InterfaceId(86),
        };

        // Should not error
        start(config, tx, next_id).unwrap();
    }

    #[test]
    fn backbone_hdlc_fragmented() {
        let port = find_free_port();
        let (tx, rx) = mpsc::channel();
        let next_id = Arc::new(AtomicU64::new(8700));

        let config = BackboneConfig {
            name: "test-backbone".into(),
            listen_ip: "127.0.0.1".into(),
            listen_port: port,
            interface_id: InterfaceId(87),
        };

        start(config, tx, next_id).unwrap();
        thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        client.set_nodelay(true).unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        // Send HDLC frame in two fragments
        let payload: Vec<u8> = (0..32).collect();
        let framed = hdlc::frame(&payload);
        let mid = framed.len() / 2;

        client.write_all(&framed[..mid]).unwrap();
        thread::sleep(Duration::from_millis(50));
        client.write_all(&framed[mid..]).unwrap();

        // Should receive reassembled frame
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { data, .. } => {
                assert_eq!(data, payload);
            }
            other => panic!("expected Frame, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Client mode tests
    // -----------------------------------------------------------------------

    fn make_client_config(port: u16, id: u64) -> BackboneClientConfig {
        BackboneClientConfig {
            name: format!("test-bb-client-{}", port),
            target_host: "127.0.0.1".into(),
            target_port: port,
            interface_id: InterfaceId(id),
            reconnect_wait: Duration::from_millis(100),
            max_reconnect_tries: Some(2),
            connect_timeout: Duration::from_secs(2),
            transport_identity: None,
        }
    }

    #[test]
    fn backbone_client_connect() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        let (tx, rx) = mpsc::channel();

        let config = make_client_config(port, 9000);
        let _writer = start_client(config, tx).unwrap();

        let _server_stream = listener.accept().unwrap();

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceUp(InterfaceId(9000), _, _)));
    }

    #[test]
    fn backbone_client_receive_frame() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        let (tx, rx) = mpsc::channel();

        let config = make_client_config(port, 9100);
        let _writer = start_client(config, tx).unwrap();

        let (mut server_stream, _) = listener.accept().unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        // Send HDLC frame from server side (>= 19 bytes payload)
        let payload: Vec<u8> = (0..32).collect();
        server_stream.write_all(&hdlc::frame(&payload)).unwrap();

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { interface_id, data } => {
                assert_eq!(interface_id, InterfaceId(9100));
                assert_eq!(data, payload);
            }
            other => panic!("expected Frame, got {:?}", other),
        }
    }

    #[test]
    fn backbone_client_send_frame() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        let (tx, _rx) = mpsc::channel();

        let config = make_client_config(port, 9200);
        let mut writer = start_client(config, tx).unwrap();

        let (mut server_stream, _) = listener.accept().unwrap();
        server_stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let payload: Vec<u8> = (0..24).collect();
        writer.send_frame(&payload).unwrap();

        let mut buf = [0u8; 256];
        let n = server_stream.read(&mut buf).unwrap();
        let expected = hdlc::frame(&payload);
        assert_eq!(&buf[..n], &expected[..]);
    }

    #[test]
    fn backbone_client_reconnect() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        listener.set_nonblocking(false).unwrap();
        let (tx, rx) = mpsc::channel();

        let config = make_client_config(port, 9300);
        let _writer = start_client(config, tx).unwrap();

        // Accept first connection and immediately close it
        let (server_stream, _) = listener.accept().unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        drop(server_stream);

        // Should get InterfaceDown
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceDown(InterfaceId(9300))));

        // Accept the reconnection
        let _server_stream2 = listener.accept().unwrap();

        // Should get InterfaceUp again
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceUp(InterfaceId(9300), _, _)));
    }
}
